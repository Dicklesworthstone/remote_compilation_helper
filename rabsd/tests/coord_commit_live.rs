//! bd-epyez daemon-level acceptance: the H-epic pin/commit/quarantine
//! machinery driven by the LIVE coordinator, under a running daemon.
//!
//! rabs-cas proves `process_offer`'s fences at library fidelity. What was
//! never proven — and until this vertebra was not even reachable — is that
//! the daemon can commit at all: nothing acquired the coordinator
//! authority, so fence #1 (`NotActiveAuthority`) refused every offer.
//!
//! What each test here proves, precisely:
//!
//! 1. `daemon_binary_acquires_and_advances_coordinator_authority` — the
//!    shipped `rabsd` binary acquires a durable authority at boot and
//!    advances the term on the next boot over the same store.
//! 2. `coordinator_commits_then_quarantines_divergence_under_running_daemon`
//!    — with all three regions up under the real `run_daemon` runtime and
//!    the real janitor-mounted store, `CoordLive::commit_offer` commits a
//!    prepared-result offer, and a SECOND offer for the same action key
//!    with a different result is quarantined as `SemanticDivergence`: the
//!    committed pointer survives untouched, an incident row is appended,
//!    the losing candidate is pinned, and serving is switched off.
//! 3. `divergence_is_classified_from_cas_bytes_after_a_restart` — a
//!    coordinator with no memory of the commit still classifies a
//!    same-key candidate correctly, because it reloads the committed
//!    manifest out of its CAS bytes (bd-h8sp5).
//! 4. `committed_state_survives_a_kill_dash_nine_and_reboot` — the
//!    committed pointer, its pin, and its serving state survive SIGKILL
//!    and a reboot that reconciles clean.
//! 5. `a_committed_action_serves_its_real_bytes_into_a_worktree` — the
//!    payoff (bd-iy2e0): `serve_action` materializes the committed
//!    artifact's actual bytes into a fresh worktree, and refuses once a
//!    divergence quarantines the action.
//! 6. `a_hit_whose_outputs_differ_from_the_callers_work_is_refused` —
//!    the interlock (bd-6uuiq): a caller that states what its own work
//!    would produce gets a refusal, and no bytes, whenever the commit
//!    would deliver a different file set.
//! 7. `serving_an_uncommitted_action_is_a_typed_miss_not_an_empty_hit` —
//!    a miss is `NotServable(NoRecord)`, never an empty "hit".
//!
//! NOT proven here (named so nothing is implied): neither the offer nor
//! the serve request arrives over the wire (J024 / bd-1vf05 — these drive
//! the in-process coordinator API a wire handler will call), no wrapper
//! yet skips a compile on the strength of a hit, and the "crash exactly
//! between link and metadata commit" matrix stays at library fidelity in
//! rabs-cas's H015 crash matrix.
#![cfg(unix)]

use std::collections::BTreeSet;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rabs_asupersync::daemon_runtime::{DaemonRunOptions, SubsystemWork, run_daemon};
use rabs_cas::blob_store::{DurabilityPolicy, PutLimits, PutOutcome, put_if_absent};
use rabs_cas::digest_set::{DigestRequest, digest_set};
use rabs_cas::metadata_store::{RabsMetadataStore, RusqliteEngine, SqlMetadataStore, digest_key};
use rabs_cas::publication::{
    AUTHORITY_DIGEST_DOMAIN, DIVERGENCE_EVIDENCE_PIN_CLASS, OfferPreparedActionResult,
    PublicationOutcome,
};
use rabs_cas::serving_state::{ServeDecision, serving_gate};
use rabs_cas::test_support::{
    divergent_offer_with_manifest_bytes, divergent_offer_with_manifest_bytes_with_ids,
    install_admission_world, install_admission_world_with_ids, install_offer_closure,
    offer_serving_object, offer_under, offer_with_manifest_bytes, sample_action_key,
    sample_expected_descriptor,
};
use rabs_protocol::result_identity::DivergenceClass;
use rabs_protocol::result_identity::ObjectId;
use rabsd::coord::live::{CoordLive, ExpectedOutputs, ServeOutcome, cluster_id, load_manifest};
use rabsd::janitor::store::{LiveCas, mount_and_reconcile};

/// Run the real binary over `state_dir` for a short bounded life.
fn boot_binary(state_dir: &std::path::Path, ms: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_rabsd"))
        .args(["--run-for-ms", ms])
        .env("RABS_SOCKET_PATH", state_dir.join("rabsd.sock"))
        .env("RABS_BOOT_MARKER", state_dir.join("rabsd.boot"))
        .env("RABS_STATE_DIR", state_dir)
        .env("RABS_CONFIG", "/nonexistent-rabs-config")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run rabsd")
}

/// Now, in microseconds since the Unix epoch. The commit writes the
/// H040 serving record at its column defaults (clock epoch 0), so the
/// gate is always asked at epoch 0 in these tests.
fn now_micros() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_micros(),
    )
    .expect("micros fit i64")
}

/// The value of a `"field":N` or `"field":"text"` pair in a JSON line.
fn json_field<'a>(line: &'a str, field: &str) -> Option<&'a str> {
    let start = line.find(&format!("\"{field}\":"))? + field.len() + 3;
    let rest = &line[start..];
    let rest = rest.strip_prefix('"').unwrap_or(rest);
    let end = rest.find(['"', ',', '}'])?;
    Some(&rest[..end])
}

/// Open the daemon's on-disk metadata store directly (only ever while no
/// daemon is running over it).
fn open_store(state_dir: &std::path::Path) -> SqlMetadataStore<RusqliteEngine> {
    let engine = RusqliteEngine::open(&state_dir.join("cas").join("meta.sqlite")).expect("engine");
    let mut store = SqlMetadataStore::open(engine).expect("store");
    // This process wrote none of these rows: declare the domains it reads
    // (R121 — an undeclared domain is a fail-closed read, not a re-type).
    store.intern_domain(AUTHORITY_DIGEST_DOMAIN);
    store.intern_domain("rabs.action-key.sha256.v1");
    store
}

#[test]
fn daemon_binary_acquires_and_advances_coordinator_authority() {
    let dir = tempfile::tempdir().unwrap();

    let first = boot_binary(dir.path(), "1200");
    let stdout = String::from_utf8_lossy(&first.stdout);
    assert!(
        first.status.success(),
        "rabsd did not exit clean:\nSTDOUT:{stdout}\nSTDERR:{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let line = stdout
        .lines()
        .find(|l| l.contains("\"kind\":\"coord-authority-acquired\""))
        .unwrap_or_else(|| panic!("no authority acquisition line:\n{stdout}"));
    assert_eq!(json_field(line, "term"), Some("1"), "{line}");
    let first_digest = json_field(line, "digest").expect("digest").to_owned();

    // The row is durable: it is in the store the daemon left behind.
    {
        let mut store = open_store(dir.path());
        let row = store
            .active_authority()
            .expect("active authority")
            .expect("an authority must be held after boot");
        assert_eq!(digest_key(&row.digest), first_digest);
        assert_eq!(row.term, 1);
    }

    // Next boot supersedes the dead incarnation at term + 1 — exactly one
    // authority is ever active.
    let second = boot_binary(dir.path(), "1200");
    let stdout = String::from_utf8_lossy(&second.stdout);
    assert!(second.status.success(), "second boot failed: {stdout}");
    let line = stdout
        .lines()
        .find(|l| l.contains("\"kind\":\"coord-authority-acquired\""))
        .unwrap_or_else(|| panic!("no authority acquisition line on reboot:\n{stdout}"));
    assert_eq!(json_field(line, "term"), Some("2"), "{line}");
    assert_ne!(
        json_field(line, "digest"),
        Some(first_digest.as_str()),
        "a reboot must mint a fresh incarnation, not reuse the dead one"
    );
    {
        let mut store = open_store(dir.path());
        // `active_authority` itself refuses more than one active row.
        let row = store.active_authority().expect("one active").expect("held");
        assert_eq!(row.term, 2);
    }
}

/// What the coord region observed while the daemon was up.
#[derive(Default)]
struct LiveOutcomes {
    commit: Option<Result<PublicationOutcome, String>>,
    divergence: Option<Result<PublicationOutcome, String>>,
}

#[test]
fn coordinator_commits_then_quarantines_divergence_under_running_daemon() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().to_path_buf();
    let cas_root = state_dir.join("cas");

    // Production mount, production coordinator, production runtime: the
    // only thing this test supplies is the offer a worker would send.
    let cas = Arc::new(mount_and_reconcile(&cas_root).expect("mount"));
    let coord = Arc::new(CoordLive::with_cas(Arc::clone(&cas)));
    let outcomes: Arc<Mutex<LiveOutcomes>> = Arc::default();

    let coord_for_region = Arc::clone(&coord);
    let cas_for_region = Arc::clone(&cas);
    let outcomes_for_region = Arc::clone(&outcomes);
    let coord_work: SubsystemWork = Box::new(move |_cx, mut shutdown| {
        Box::pin(async move {
            // The two production boot steps `coord::live::coord_work`
            // performs; the daemon is fully up from here.
            coord_for_region.mark_up();
            let authority = coord_for_region
                .acquire_boot_authority(&cluster_id())
                .map_err(|e| format!("authority: {e}"))?;

            // A worker's world: the action entry, generation, attempt and
            // lease under THIS coordinator's authority, both manifests'
            // real bytes in the blob store (the coordinator reads the
            // committed one back to classify the second offer), and both
            // closures durably located — an offer whose bytes are not
            // durable is refused before any transaction opens.
            let (first, first_bytes) = offer_with_manifest_bytes(&authority);
            let (second, second_bytes) = divergent_offer_with_manifest_bytes(&authority);
            {
                let mut store = cas_for_region.store().lock().expect("store lock");
                install_admission_world(&mut *store, &authority);
            }
            store_manifest_object(&cas_for_region, &first, &first_bytes);
            store_manifest_object(&cas_for_region, &second, &second_bytes);

            let commit = coord_for_region
                .commit_offer(&first, &sample_expected_descriptor())
                .map_err(|e| e.to_string());
            let divergence = coord_for_region
                .commit_offer(&second, &sample_expected_descriptor())
                .map_err(|e| e.to_string());
            {
                let mut recorded = outcomes_for_region.lock().expect("outcomes lock");
                recorded.commit = Some(commit);
                recorded.divergence = Some(divergence);
            }

            shutdown.wait().await;
            coord_for_region.mark_down();
            Ok(())
        })
    });

    let receipt = run_daemon(DaemonRunOptions {
        run_for: Some(Duration::from_millis(1500)),
        boot_marker: Some(state_dir.join("rabsd.boot")),
        edge_work: Some(rabsd::edge::server::edge_work(
            rabsd::edge::server::EdgeServerConfig {
                socket_path: state_dir.join("rabsd.sock"),
                state_dir: state_dir.clone(),
                coord: Arc::clone(&coord),
            },
        )),
        coord_work: Some(coord_work),
        janitor_work: Some(rabsd::janitor::store::janitor_work_holding(Ok(Arc::clone(
            &cas,
        )))),
        ..DaemonRunOptions::default()
    })
    .expect("daemon run");
    assert!(
        receipt.clean(),
        "regions must retire clean: {}",
        receipt.to_json_line()
    );

    let outcomes = outcomes.lock().expect("outcomes");
    // 1. The first offer really committed.
    let commit = outcomes
        .commit
        .as_ref()
        .expect("commit ran")
        .as_ref()
        .unwrap_or_else(|e| panic!("first offer must commit, refused: {e}"));
    let PublicationOutcome::Committed(record) = commit else {
        panic!("expected a commit, got {commit:?}");
    };
    let first_manifest_key = digest_key(&record.canonical_result_manifest_id.0);

    // 2. The same-key, different-result offer was quarantined, not
    //    committed and not silently dropped.
    let divergence = outcomes
        .divergence
        .as_ref()
        .expect("second offer ran")
        .as_ref()
        .unwrap_or_else(|e| panic!("divergent offer must be quarantined, refused: {e}"));
    let PublicationOutcome::Quarantined(quarantine) = divergence else {
        panic!("expected a quarantine, got {divergence:?}");
    };
    assert_eq!(quarantine.class, DivergenceClass::SemanticDivergence);

    // 3. Everything the two calls claim is in the daemon's durable store.
    let mut store = open_store(&state_dir);
    let action_key = sample_action_key();
    assert_eq!(
        store
            .published_manifest_key(&action_key)
            .expect("published key"),
        Some(first_manifest_key),
        "the committed pointer must still name the FIRST manifest"
    );
    let incidents = store
        .list_divergence_incidents(&digest_key(&action_key))
        .expect("incidents");
    assert_eq!(incidents.len(), 1, "one appended incident: {incidents:?}");
    assert_eq!(incidents[0].seq, quarantine.incident_seq);
    let candidate_pin = store
        .pin_row(quarantine.candidate_pin_id)
        .expect("pin row")
        .expect("the losing candidate must be pinned so GC cannot eat it");
    assert_eq!(candidate_pin.class, DIVERGENCE_EVIDENCE_PIN_CLASS);
    assert!(!candidate_pin.released);

    // 4. Serving is off. (The commit writes the H040 record at its column
    //    defaults — clock epoch 0 — so the gate is asked at that epoch.)
    let now = now_micros();
    match serving_gate(&mut store, &digest_key(&action_key), now, 0).expect("gate") {
        ServeDecision::NotServable { disposition } => assert_eq!(disposition, "quarantined"),
        other => panic!("a quarantined action must not serve, gate said {other:?}"),
    }
}

/// Put the manifest's canonical bytes into the REAL blob store, so the
/// coordinator can read the committed manifest back the way production
/// will: object bytes on disk, location row in the store.
fn store_manifest_object(cas: &LiveCas, offer: &OfferPreparedActionResult, bytes: &[u8]) {
    let mut store = cas.store().lock().expect("store lock");
    let mut reader = bytes;
    let outcome = put_if_absent(
        cas.layout(),
        &mut *store,
        &offer.manifest_id.0,
        &mut reader,
        PutLimits::default(),
        DurabilityPolicy::FULL,
    )
    .expect("put manifest bytes");
    assert!(
        matches!(
            outcome,
            PutOutcome::Stored { .. } | PutOutcome::IdempotentDuplicate { .. }
        ),
        "manifest bytes must land in the store: {outcome:?}"
    );
    install_offer_closure(&mut *store, offer);
}

#[test]
fn divergence_is_classified_from_cas_bytes_after_a_restart() {
    // The point of bd-h8sp5: A018 classification needs the COMMITTED
    // manifest, and a restarted coordinator remembers nothing. Reading
    // it back out of its CAS bytes is what keeps a same-key,
    // different-result offer a QUARANTINE instead of degrading into a
    // CommittedManifestUnavailable refusal.
    let dir = tempfile::tempdir().unwrap();
    let cas_root = dir.path().join("cas");

    // Incarnation 1: commit the first result.
    {
        let cas = Arc::new(mount_and_reconcile(&cas_root).expect("mount"));
        let coord = CoordLive::with_cas(Arc::clone(&cas));
        let authority = coord
            .acquire_boot_authority(&cluster_id())
            .expect("authority");
        let (offer, bytes) = offer_with_manifest_bytes(&authority);
        {
            let mut store = cas.store().lock().expect("store lock");
            install_admission_world(&mut *store, &authority);
        }
        store_manifest_object(&cas, &offer, &bytes);
        let outcome = coord
            .commit_offer(&offer, &sample_expected_descriptor())
            .expect("commit");
        assert!(
            matches!(outcome, PublicationOutcome::Committed(_)),
            "expected a commit, got {outcome:?}"
        );
    }

    // Incarnation 2: a brand-new process-level coordinator over the same
    // on-disk store — no memory of incarnation 1 whatsoever. G020/R120:
    // its boot CLOSED incarnation 1's generations, so the divergent
    // candidate reissues in a FRESH generation bound to the new authority
    // (ids above the never-reuse high-water mark; the old attempt id is
    // burned) — prior-authority execution may contribute verified blobs
    // but can never publish under the new term.
    let cas = Arc::new(mount_and_reconcile(&cas_root).expect("re-mount"));
    let coord = CoordLive::with_cas(Arc::clone(&cas));
    let authority = coord
        .acquire_boot_authority(&cluster_id())
        .expect("authority");
    assert_eq!(authority.term, 2, "the reboot must advance the term");
    assert_eq!(
        coord.closed_prior_generations(),
        1,
        "boot must close the single generation the prior term left active"
    );

    let reissue_ids = rabs_cas::test_support::FixtureAttemptIds {
        generation: 12,
        attempt: 21,
        lease: 31,
    };
    {
        let mut store = cas.store().lock().expect("store lock");
        install_admission_world_with_ids(&mut *store, &authority, reissue_ids);
    }
    let (divergent, bytes) =
        divergent_offer_with_manifest_bytes_with_ids(&authority, reissue_ids);
    store_manifest_object(&cas, &divergent, &bytes);
    let outcome = coord
        .commit_offer(&divergent, &sample_expected_descriptor())
        .expect("the divergent offer must be admitted and classified");
    let PublicationOutcome::Quarantined(quarantine) = outcome else {
        panic!("expected a quarantine across the restart, got {outcome:?}");
    };
    assert_eq!(quarantine.class, DivergenceClass::SemanticDivergence);

    // And the committed manifest really was reloaded from bytes, not
    // guessed: it decodes to a manifest whose semantic digest is the one
    // the incident says the candidate diverged from.
    let committed_key = {
        let mut store = cas.store().lock().expect("store lock");
        store
            .published_manifest_key(&sample_action_key())
            .expect("published key")
            .expect("a committed pointer")
    };
    let reloaded = {
        let mut store = cas.store().lock().expect("store lock");
        load_manifest(&mut *store, &committed_key).expect("manifest reloads from its CAS bytes")
    };
    assert_ne!(
        reloaded.semantic_result_digest, divergent.manifest.semantic_result_digest,
        "the two candidates must genuinely differ semantically"
    );
    assert_eq!(
        digest_key(&reloaded.action_key),
        digest_key(&sample_action_key())
    );
}

#[test]
fn committed_state_survives_a_kill_dash_nine_and_reboot() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().to_path_buf();
    let cas_root = state_dir.join("cas");

    // Commit through the live coordinator, exactly as the test above.
    let committed_key = {
        let cas = Arc::new(mount_and_reconcile(&cas_root).expect("mount"));
        let coord = CoordLive::with_cas(Arc::clone(&cas));
        let authority = coord
            .acquire_boot_authority(&cluster_id())
            .expect("authority");
        let offer = offer_under(&authority);
        {
            let mut store = cas.store().lock().expect("store lock");
            install_admission_world(&mut *store, &authority);
            install_offer_closure(&mut *store, &offer);
        }
        let outcome = coord
            .commit_offer(&offer, &sample_expected_descriptor())
            .expect("commit");
        let PublicationOutcome::Committed(record) = outcome else {
            panic!("expected a commit, got {outcome:?}");
        };
        digest_key(&record.canonical_result_manifest_id.0)
    };

    // A daemon dies hard over that store: SIGKILL, no shutdown, no
    // receipt, boot marker left behind.
    let mut child = Command::new(env!("CARGO_BIN_EXE_rabsd"))
        .args(["--run-for-ms", "30000"])
        .env("RABS_SOCKET_PATH", state_dir.join("rabsd.sock"))
        .env("RABS_BOOT_MARKER", state_dir.join("rabsd.boot"))
        .env("RABS_STATE_DIR", &state_dir)
        .env("RABS_CONFIG", "/nonexistent-rabs-config")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn rabsd");
    // Let it get through boot (mount + reconcile + authority) before the
    // kill, so the reboot really is recovering from a live incarnation.
    // Wait for the marker the daemon writes as its first boot act (with a
    // bounded poll — a cold binary on a slow volume can take a moment).
    let marker = state_dir.join("rabsd.boot");
    for _ in 0..100 {
        if marker.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    // Let the rest of boot (mount + reconcile + authority) land too.
    std::thread::sleep(Duration::from_millis(300));
    child.kill().expect("kill rabsd");
    let killed = child.wait_with_output().expect("reap rabsd");
    assert!(
        !killed.status.success(),
        "the daemon was supposed to die by signal"
    );
    assert!(
        state_dir.join("rabsd.boot").exists(),
        "a killed daemon must leave its boot marker behind:\nSTDOUT:{}\nSTDERR:{}",
        String::from_utf8_lossy(&killed.stdout),
        String::from_utf8_lossy(&killed.stderr)
    );

    // Reboot: reconcile must come back clean and see the prior death.
    let out = boot_binary(&state_dir, "1200");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "reboot after SIGKILL failed:\nSTDOUT:{stdout}\nSTDERR:{stderr}"
    );
    assert!(
        stdout.contains("\"serving_refused\":false"),
        "reconcile must not refuse serving after a clean-store kill: {stdout}"
    );
    assert!(
        stderr.contains("\"kind\":\"rabsd-recovery\""),
        "the boot marker must report the unclean prior incarnation: {stderr}"
    );

    // The commit is still there, still pinned, still servable.
    let mut store = open_store(&state_dir);
    let action_key = sample_action_key();
    assert_eq!(
        store
            .published_manifest_key(&action_key)
            .expect("published key"),
        Some(committed_key),
        "the committed pointer must survive SIGKILL + reboot"
    );
    let pin_hex = store
        .list_publications()
        .expect("publications")
        .into_iter()
        .find(|(key, _)| *key == digest_key(&action_key))
        .expect("the publication row")
        .1;
    assert_eq!(
        store.pin_released_by_hex(&pin_hex).expect("pin"),
        Some(false),
        "the publication reachability pin must survive and stay held"
    );
    let now = now_micros();
    assert_eq!(
        serving_gate(&mut store, &digest_key(&action_key), now, 0).expect("gate"),
        ServeDecision::Servable,
        "an undisputed commit must still serve after the crash"
    );
}

#[test]
fn a_committed_action_serves_its_real_bytes_into_a_worktree() {
    // The first path in RABS by which a cache hit becomes files on disk
    // (bd-iy2e0): gate -> reload the committed manifest from CAS bytes
    // -> materialize its outputs into a live worktree.
    let dir = tempfile::tempdir().unwrap();
    let cas = Arc::new(mount_and_reconcile(&dir.path().join("cas")).expect("mount"));
    let coord = CoordLive::with_cas(Arc::clone(&cas));
    let authority = coord
        .acquire_boot_authority(&cluster_id())
        .expect("authority");

    // The artifact a worker produced, really in the byte store.
    let artifact = b"the compiled rlib bytes a worker uploaded".repeat(64);
    let object = {
        let mut store = cas.store().lock().expect("store lock");
        let declared = digest_set(&artifact, DigestRequest::default(), None)
            .expect("digest")
            .atp_content_id;
        let mut reader: &[u8] = &artifact;
        put_if_absent(
            cas.layout(),
            &mut *store,
            &declared,
            &mut reader,
            PutLimits::default(),
            DurabilityPolicy::FULL,
        )
        .expect("put artifact");
        ObjectId(declared)
    };

    let (offer, manifest_bytes) = offer_serving_object(&authority, &object);
    {
        let mut store = cas.store().lock().expect("store lock");
        install_admission_world(&mut *store, &authority);
    }
    store_manifest_object(&cas, &offer, &manifest_bytes);
    let outcome = coord
        .commit_offer(&offer, &sample_expected_descriptor())
        .expect("commit");
    assert!(
        matches!(outcome, PublicationOutcome::Committed(_)),
        "expected a commit, got {outcome:?}"
    );

    // Serve it into a worktree that does not exist yet.
    let worktree = dir.path().join("worktree");
    let now = now_micros();
    let served = coord
        .serve_action(
            &sample_action_key(),
            &worktree,
            // The interlock: this caller states exactly what its own
            // work would have produced, and the commit must match.
            &ExpectedOutputs::Exactly(BTreeSet::from(["out/lib.rlib".to_owned()])),
            now,
            0,
        )
        .expect("serve");
    let ServeOutcome::Served { files } = served else {
        panic!("expected a served hit, got {served:?}");
    };
    assert_eq!(files, vec![worktree.join("out").join("lib.rlib")]);
    assert_eq!(
        std::fs::read(&files[0]).expect("read served artifact"),
        artifact,
        "the served file must be the committed bytes"
    );

    // A quarantine switches serving off: same action, now refused.
    let (divergent, divergent_bytes) = divergent_offer_with_manifest_bytes(&authority);
    store_manifest_object(&cas, &divergent, &divergent_bytes);
    let outcome = coord
        .commit_offer(&divergent, &sample_expected_descriptor())
        .expect("classified");
    assert!(
        matches!(outcome, PublicationOutcome::Quarantined(_)),
        "expected a quarantine, got {outcome:?}"
    );
    let after = coord
        .serve_action(
            &sample_action_key(),
            &dir.path().join("worktree2"),
            &ExpectedOutputs::WhateverWasCommitted,
            now,
            0,
        )
        .expect("serve after quarantine");
    match after {
        ServeOutcome::NotServable(ServeDecision::NotServable { disposition }) => {
            assert_eq!(disposition, "quarantined");
        }
        other => panic!("a quarantined action must not serve, got {other:?}"),
    }
    assert!(
        !dir.path().join("worktree2").exists(),
        "a refused serve must write nothing"
    );
}

#[test]
fn a_hit_whose_outputs_differ_from_the_callers_work_is_refused() {
    // THE interlock (bd-6uuiq). A caller about to skip work states what
    // that work would produce. If the committed result produces anything
    // else, serving it would hand back a build missing files it was
    // promised — so it is not a hit, and not a single byte is written.
    let dir = tempfile::tempdir().unwrap();
    let cas = Arc::new(mount_and_reconcile(&dir.path().join("cas")).expect("mount"));
    let coord = CoordLive::with_cas(Arc::clone(&cas));
    let authority = coord
        .acquire_boot_authority(&cluster_id())
        .expect("authority");

    let artifact = b"a committed rlib".to_vec();
    let object = {
        let mut store = cas.store().lock().expect("store lock");
        let declared = digest_set(&artifact, DigestRequest::default(), None)
            .expect("digest")
            .atp_content_id;
        let mut reader: &[u8] = &artifact;
        put_if_absent(
            cas.layout(),
            &mut *store,
            &declared,
            &mut reader,
            PutLimits::default(),
            DurabilityPolicy::FULL,
        )
        .expect("put artifact");
        ObjectId(declared)
    };
    let (offer, manifest_bytes) = offer_serving_object(&authority, &object);
    {
        let mut store = cas.store().lock().expect("store lock");
        install_admission_world(&mut *store, &authority);
    }
    store_manifest_object(&cas, &offer, &manifest_bytes);
    coord
        .commit_offer(&offer, &sample_expected_descriptor())
        .expect("commit");

    // The caller's work would produce a `.rmeta` too — this commit does
    // not have one.
    let worktree = dir.path().join("worktree");
    let outcome = coord
        .serve_action(
            &sample_action_key(),
            &worktree,
            &ExpectedOutputs::Exactly(BTreeSet::from([
                "out/lib.rlib".to_owned(),
                "out/lib.rmeta".to_owned(),
            ])),
            now_micros(),
            0,
        )
        .expect("serve");
    match outcome {
        ServeOutcome::OutputSetMismatch {
            missing,
            unexpected,
        } => {
            assert_eq!(missing, vec!["out/lib.rmeta".to_owned()]);
            assert!(unexpected.is_empty(), "{unexpected:?}");
        }
        other => panic!("a differing output set must refuse, got {other:?}"),
    }
    assert!(
        !worktree.exists(),
        "a refused serve must not create the worktree, let alone files"
    );

    // The mirror case: the caller expects LESS than the commit produces.
    let outcome = coord
        .serve_action(
            &sample_action_key(),
            &worktree,
            &ExpectedOutputs::Exactly(BTreeSet::new()),
            now_micros(),
            0,
        )
        .expect("serve");
    match outcome {
        ServeOutcome::OutputSetMismatch {
            missing,
            unexpected,
        } => {
            assert!(missing.is_empty(), "{missing:?}");
            assert_eq!(unexpected, vec!["out/lib.rlib".to_owned()]);
        }
        other => panic!("an extra committed output must refuse, got {other:?}"),
    }

    // And the matching set still serves.
    let served = coord
        .serve_action(
            &sample_action_key(),
            &worktree,
            &ExpectedOutputs::Exactly(BTreeSet::from(["out/lib.rlib".to_owned()])),
            now_micros(),
            0,
        )
        .expect("serve");
    assert!(
        matches!(served, ServeOutcome::Served { .. }),
        "an exact match must serve, got {served:?}"
    );
    assert_eq!(
        std::fs::read(worktree.join("out").join("lib.rlib")).expect("served"),
        artifact
    );
}

#[test]
fn serving_an_uncommitted_action_is_a_typed_miss_not_an_empty_hit() {
    let dir = tempfile::tempdir().unwrap();
    let cas = Arc::new(mount_and_reconcile(&dir.path().join("cas")).expect("mount"));
    let coord = CoordLive::with_cas(Arc::clone(&cas));
    coord
        .acquire_boot_authority(&cluster_id())
        .expect("authority");
    let outcome = coord
        .serve_action(
            &sample_action_key(),
            &dir.path().join("worktree"),
            &ExpectedOutputs::WhateverWasCommitted,
            now_micros(),
            0,
        )
        .expect("serve");
    assert_eq!(outcome, ServeOutcome::NotServable(ServeDecision::NoRecord));
    assert!(!dir.path().join("worktree").exists());
}
