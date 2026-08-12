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
//!
//! NOT proven here (named so nothing is implied): the offer does not
//! arrive over the wire from a worker (that protocol is J024 — this drives
//! the in-process coordinator API a wire handler will call), and the
//! "crash exactly between link and metadata commit" matrix stays at
//! library fidelity in rabs-cas's H015 crash matrix.
#![cfg(unix)]

use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rabs_asupersync::daemon_runtime::{DaemonRunOptions, SubsystemWork, run_daemon};
use rabs_cas::blob_store::{DurabilityPolicy, PutLimits, PutOutcome, put_if_absent};
use rabs_cas::metadata_store::{RabsMetadataStore, RusqliteEngine, SqlMetadataStore, digest_key};
use rabs_cas::publication::{
    AUTHORITY_DIGEST_DOMAIN, DIVERGENCE_EVIDENCE_PIN_CLASS, OfferPreparedActionResult,
    PublicationOutcome,
};
use rabs_cas::serving_state::{ServeDecision, serving_gate};
use rabs_cas::test_support::{
    divergent_offer_with_manifest_bytes, install_admission_world, install_offer_closure,
    offer_under, offer_with_manifest_bytes, sample_action_key, sample_expected_descriptor,
};
use rabs_protocol::result_identity::DivergenceClass;
use rabsd::coord::live::{CoordLive, cluster_id, load_manifest};
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
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_micros(),
    )
    .expect("micros fit i64");
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
    // on-disk store — no memory of incarnation 1 whatsoever.
    let cas = Arc::new(mount_and_reconcile(&cas_root).expect("re-mount"));
    let coord = CoordLive::with_cas(Arc::clone(&cas));
    let authority = coord
        .acquire_boot_authority(&cluster_id())
        .expect("authority");
    assert_eq!(authority.term, 2, "the reboot must advance the term");

    let (divergent, bytes) = divergent_offer_with_manifest_bytes(&authority);
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
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_micros(),
    )
    .expect("micros fit i64");
    assert_eq!(
        serving_gate(&mut store, &digest_key(&action_key), now, 0).expect("gate"),
        ServeDecision::Servable,
        "an undisputed commit must still serve after the crash"
    );
}
