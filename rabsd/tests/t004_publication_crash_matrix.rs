//! T004: the publication crash matrix at PROCESS fidelity (bead 38.4;
//! the T-side owner of H015; risks R111/R119).
//!
//! H015 already injects at every SQL mutation boundary of the
//! publication protocol, including inside store transactions, on both
//! engines, and proves restart convergence. Its close reason names what
//! it deliberately left: "matrix runs in-process over the store
//! protocol (process-level kill -9 E2E and worker/edge-side kills are
//! the T004 lab bead, 38.4)". `coord_commit_live.rs`'s own header says
//! the same from the other side — the crash matrix "stays at library
//! fidelity". This file closes that gap, and does not re-drive H015's
//! intra-transaction boundaries.
//!
//! The difference process fidelity actually buys, stated so the value
//! is not assumed:
//!
//! - a real `abort()` kills between the store's fsync and anything the
//!   process was still holding — no `Drop`, no unwind, no flush;
//! - recovery runs in a genuinely NEW incarnation: a fresh boot nonce,
//!   so `next_pin_id` hands out ids from a different space, and a real
//!   authority re-acquisition that advances the term. H015 simulated
//!   this ("fresh pin ids/seqs"); here it is the real thing;
//! - the shipped `rabsd` binary performs the reconcile, so the oracle
//!   is the product's own startup path rather than a library call.
//!
//! HOW A PHASE IS DRIVEN. Nothing in production is modified to support
//! this — no fault seam, no crash env var in the daemon. The test
//! re-executes ITSELF: the parent spawns this same test binary running
//! the `#[ignore]`d child below, tells it which phase to reach, and the
//! child drives the real publication path in-process and then calls
//! `std::process::abort()`. That keeps the injection entirely inside
//! the test binary.
//!
//! WHY THE CHILD WRITES A SENTINEL. A child that died in its own setup
//! would also look "killed by a signal", and the parent would then
//! assert its oracles against a store the phase never touched — a
//! matrix that passes while testing nothing. So the child fsyncs a
//! `reached-<phase>` marker as its last act before aborting, and the
//! parent refuses to evaluate a phase whose marker is absent.
//!
//! NOT COVERED, named so nothing is implied: worker-side kills (no
//! worker process participates in this path yet — the offer is prepared
//! in-process), wire delivery of offers or serve requests, and the
//! intra-transaction boundaries that are H015's.
#![cfg(unix)]

use std::collections::BTreeSet;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;

use rabs_cas::blob_store::{DurabilityPolicy, PutLimits, put_if_absent};
use rabs_cas::digest_set::{DigestRequest, digest_set};
use rabs_cas::metadata_store::{RabsMetadataStore, RusqliteEngine, SqlMetadataStore, digest_key};
use rabs_cas::publication::{
    AUTHORITY_DIGEST_DOMAIN, OfferPreparedActionResult, PublicationOutcome,
};
use rabs_cas::serving_state::{ServeDecision, serving_gate};
use rabs_cas::test_support::{
    divergent_offer_with_manifest_bytes, install_admission_world, install_offer_closure,
    offer_serving_object, sample_action_key, sample_expected_descriptor,
};
use rabs_protocol::result_identity::ObjectId;
use rabsd::coord::live::{CoordLive, ExpectedOutputs, ServeOutcome, cluster_id};
use rabsd::janitor::store::{LiveCas, mount_and_reconcile};

/// The environment the parent uses to steer the child.
const PHASE_ENV: &str = "RABS_T004_CRASH_AT";
const STATE_ENV: &str = "RABS_T004_STATE_DIR";

/// Objects and the offer closure are in the store; nothing is published.
const PHASE_UPLOADED: &str = "uploaded";
/// The publication transaction returned Committed.
const PHASE_COMMITTED: &str = "committed";
/// The commit was materialized into a real worktree.
const PHASE_SERVED: &str = "served";
/// A divergent same-key offer was quarantined over the commit.
const PHASE_QUARANTINED: &str = "quarantined";

const PHASES: [&str; 4] = [
    PHASE_UPLOADED,
    PHASE_COMMITTED,
    PHASE_SERVED,
    PHASE_QUARANTINED,
];

/// The artifact bytes the committed action serves.
fn artifact() -> Vec<u8> {
    b"the compiled rlib bytes a worker uploaded".repeat(64)
}

fn store_manifest_object(cas: &LiveCas, offer: &OfferPreparedActionResult, bytes: &[u8]) {
    let mut store = cas.store().lock().expect("store lock");
    let mut reader = bytes;
    put_if_absent(
        cas.layout(),
        &mut *store,
        &offer.manifest_id.0,
        &mut reader,
        PutLimits::default(),
        DurabilityPolicy::FULL,
    )
    .expect("put manifest bytes");
    install_offer_closure(&mut *store, offer);
}

/// Open the on-disk store directly. Only ever called while no process
/// is running over it.
fn open_store(state_dir: &Path) -> SqlMetadataStore<RusqliteEngine> {
    let engine = RusqliteEngine::open(&state_dir.join("cas").join("meta.sqlite")).expect("engine");
    let mut store = SqlMetadataStore::open(engine).expect("store");
    // This process wrote none of these rows (R121: an undeclared domain
    // is a fail-closed read, not a re-type).
    store.intern_domain(AUTHORITY_DIGEST_DOMAIN);
    store.intern_domain("rabs.action-key.sha256.v1");
    store
}

/// Build the world up to, and including, `phase`, then never return.
///
/// This runs in the CHILD process. Each step is the real coordinator
/// path — the same calls `coord_commit_live.rs` makes — so the store the
/// parent inspects was written by production code, not by a fixture.
fn drive_to(phase: &str, state_dir: &Path) -> ! {
    let cas = Arc::new(mount_and_reconcile(&state_dir.join("cas")).expect("mount"));
    let coord = CoordLive::with_cas(Arc::clone(&cas));
    let authority = coord
        .acquire_boot_authority(&cluster_id())
        .expect("authority");

    let object = {
        let bytes = artifact();
        let mut store = cas.store().lock().expect("store lock");
        let declared = digest_set(&bytes, DigestRequest::default(), None)
            .expect("digest")
            .atp_content_id;
        let mut reader: &[u8] = &bytes;
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
    if phase == PHASE_UPLOADED {
        die_at(phase, state_dir);
    }

    let outcome = coord
        .commit_offer(&offer, &sample_expected_descriptor())
        .expect("commit");
    assert!(
        matches!(outcome, PublicationOutcome::Committed(_)),
        "the child must really have committed, got {outcome:?}"
    );
    if phase == PHASE_COMMITTED {
        die_at(phase, state_dir);
    }

    if phase == PHASE_SERVED {
        let served = coord
            .serve_action(
                &sample_action_key(),
                &state_dir.join("worktree"),
                &ExpectedOutputs::Exactly(BTreeSet::from(["out/lib.rlib".to_owned()])),
                now_micros(),
                0,
            )
            .expect("serve");
        assert!(
            matches!(served, ServeOutcome::Served { .. }),
            "the child must really have served, got {served:?}"
        );
        die_at(phase, state_dir);
    }

    if phase == PHASE_QUARANTINED {
        let (divergent, divergent_bytes) = divergent_offer_with_manifest_bytes(&authority);
        store_manifest_object(&cas, &divergent, &divergent_bytes);
        let outcome = coord
            .commit_offer(&divergent, &sample_expected_descriptor())
            .expect("classified");
        assert!(
            matches!(outcome, PublicationOutcome::Quarantined(_)),
            "the child must really have quarantined, got {outcome:?}"
        );
        die_at(phase, state_dir);
    }

    panic!("unknown phase {phase}");
}

/// Record that the phase was genuinely reached, then die the way a
/// machine losing power dies: no unwinding, no `Drop`, no flush.
fn die_at(phase: &str, state_dir: &Path) -> ! {
    let marker = state_dir.join(format!("reached-{phase}"));
    let file = std::fs::File::create(&marker).expect("create phase marker");
    file.sync_all().expect("fsync phase marker");
    std::process::abort();
}

fn now_micros() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_micros(),
    )
    .expect("micros fit i64")
}

/// The child entry point. Ignored so a normal run never executes it; the
/// parent invokes it explicitly with `--ignored --exact`.
#[test]
#[ignore = "spawned by the T004 matrix parent; aborts by design"]
fn t004_crash_child() {
    let Ok(phase) = std::env::var(PHASE_ENV) else {
        panic!("{PHASE_ENV} must be set: this test is only ever spawned by the matrix");
    };
    let state_dir = PathBuf::from(std::env::var(STATE_ENV).expect("state dir"));
    drive_to(&phase, &state_dir);
}

/// Run the child to `phase` over `state_dir` and require that it died by
/// signal having actually reached the phase.
fn crash_at(phase: &str, state_dir: &Path) {
    let output = Command::new(std::env::current_exe().expect("test binary"))
        .args(["--exact", "t004_crash_child", "--ignored", "--nocapture"])
        .env(PHASE_ENV, phase)
        .env(STATE_ENV, state_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn crash child");

    // Death by signal, not a tidy exit: `abort()` raises SIGABRT, and a
    // process that returned an exit code did not crash, it finished.
    assert!(
        output.status.code().is_none(),
        "phase {phase}: the child must die by signal, got {:?}\nSTDOUT:{}\nSTDERR:{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        output.status.signal(),
        Some(libc_sigabrt()),
        "phase {phase}: expected SIGABRT from abort()"
    );
    // And it died where we meant it to. Without this a child that
    // panicked during setup would still look like a successful
    // injection, and every oracle below would be asserted against a
    // store the phase never reached.
    assert!(
        state_dir.join(format!("reached-{phase}")).exists(),
        "phase {phase}: the child died before reaching the phase\nSTDOUT:{}\nSTDERR:{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// SIGABRT, without pulling in a libc dependency for one constant.
const fn libc_sigabrt() -> i32 {
    6
}

/// Boot the shipped daemon over the store and return its output: the
/// product's own reconcile is the recovery oracle.
fn reboot(state_dir: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_rabsd"))
        .args(["--run-for-ms", "1200"])
        .env("RABS_SOCKET_PATH", state_dir.join("rabsd.sock"))
        .env("RABS_BOOT_MARKER", state_dir.join("rabsd.boot"))
        .env("RABS_STATE_DIR", state_dir)
        .env("RABS_CONFIG", "/nonexistent-rabs-config")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("reboot rabsd")
}

/// Every publication row for the sample action key.
fn publications_for_sample(store: &mut SqlMetadataStore<RusqliteEngine>) -> Vec<String> {
    let key = digest_key(&sample_action_key());
    store
        .list_publications()
        .expect("publications")
        .into_iter()
        .filter(|(action, _)| *action == key)
        .map(|(_, pin_hex)| pin_hex)
        .collect()
}

#[test]
fn t004_every_publication_phase_survives_a_real_process_death() {
    for phase in PHASES {
        let dir = tempfile::tempdir().expect("tempdir");
        let state_dir = dir.path().to_path_buf();

        crash_at(phase, &state_dir);

        // 1. The product's own startup path must come back clean. A
        //    crash is not allowed to leave a store that needs an
        //    operator, and R119's fail-closed refusal is the loudest
        //    signal that something was left torn.
        let out = reboot(&state_dir);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success(),
            "phase {phase}: reboot after the crash failed\nSTDOUT:{stdout}\nSTDERR:{stderr}"
        );
        assert!(
            stdout.contains("\"serving_refused\":false"),
            "phase {phase}: reconcile refused serving after the crash: {stdout}"
        );
        assert!(
            stderr.contains("\"kind\":\"rabsd-recovery\""),
            "phase {phase}: the boot marker must report the unclean prior incarnation: {stderr}"
        );

        // 2. Publication state is exactly what the phase reached — never
        //    partial, never doubled.
        let mut store = open_store(&state_dir);
        let pins = publications_for_sample(&mut store);
        let expect_published = phase != PHASE_UPLOADED;
        if expect_published {
            assert_eq!(
                pins.len(),
                1,
                "phase {phase}: a crash must leave exactly one publication row, found {}",
                pins.len()
            );
            assert_eq!(
                store.pin_released_by_hex(&pins[0]).expect("pin"),
                Some(false),
                "phase {phase}: the publication reachability pin must survive unreleased (R111)"
            );
        } else {
            assert!(
                pins.is_empty(),
                "phase {phase}: nothing was committed, so no publication may exist"
            );
        }

        // 3. Serving reflects the phase, and quarantine survives the
        //    crash rather than being forgotten into a hit.
        let decision =
            serving_gate(&mut store, &digest_key(&sample_action_key()), now_micros(), 0)
                .expect("gate");
        match phase {
            PHASE_UPLOADED => assert!(
                !matches!(decision, ServeDecision::Servable),
                "phase {phase}: an uncommitted action must not serve, got {decision:?}"
            ),
            PHASE_QUARANTINED => assert!(
                matches!(decision, ServeDecision::NotServable { .. }),
                "phase {phase}: a quarantine must survive the crash, got {decision:?}"
            ),
            _ => assert_eq!(
                decision,
                ServeDecision::Servable,
                "phase {phase}: an undisputed commit must still serve after the crash"
            ),
        }

        // 4. Bytes already materialized stay correct. A crash may leave
        //    a partial file SET — that is the documented serve contract —
        //    but never a corrupt file.
        if phase == PHASE_SERVED {
            let served = state_dir.join("worktree").join("out").join("lib.rlib");
            assert!(
                served.exists(),
                "phase {phase}: the served artifact must survive the crash"
            );
            assert_eq!(
                std::fs::read(&served).expect("read served artifact"),
                artifact(),
                "phase {phase}: a crash must not leave a corrupted served artifact"
            );
        }
    }
}

#[test]
fn t004_a_retry_after_a_crash_converges_and_never_double_commits() {
    // The other half of R111. Recovering is not enough: the work has to
    // be REDOABLE. A new incarnation re-offers the same result, and the
    // store must converge on exactly one publication — whether the crash
    // landed before the commit (the retry publishes) or after it (the
    // retry is idempotent, not a second row).
    //
    // This is where process fidelity earns its keep. The retry runs
    // under a fresh boot nonce, so `next_pin_id` draws from a different
    // id space than the dead incarnation used, and the authority is
    // genuinely re-acquired. An implementation that keyed idempotence on
    // a process-local id would pass H015's in-process retry and fail
    // here.
    for phase in [PHASE_UPLOADED, PHASE_COMMITTED] {
        let dir = tempfile::tempdir().expect("tempdir");
        let state_dir = dir.path().to_path_buf();

        crash_at(phase, &state_dir);
        assert!(reboot(&state_dir).status.success(), "phase {phase}: reboot");

        // A brand-new incarnation redoes the offer.
        let cas = Arc::new(mount_and_reconcile(&state_dir.join("cas")).expect("remount"));
        let coord = CoordLive::with_cas(Arc::clone(&cas));
        let authority = coord
            .acquire_boot_authority(&cluster_id())
            .expect("re-acquire authority");
        let object = {
            let bytes = artifact();
            let mut store = cas.store().lock().expect("store lock");
            let declared = digest_set(&bytes, DigestRequest::default(), None)
                .expect("digest")
                .atp_content_id;
            let mut reader: &[u8] = &bytes;
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
            .expect("retry commit");
        assert!(
            matches!(
                outcome,
                PublicationOutcome::Committed(_) | PublicationOutcome::AlreadyPublished { .. }
            ),
            "phase {phase}: a retry of the identical result must publish or be a no-op, \
             got {outcome:?}"
        );

        drop(coord);
        drop(cas);
        let mut store = open_store(&state_dir);
        assert_eq!(
            publications_for_sample(&mut store).len(),
            1,
            "phase {phase}: retry after a crash must converge on exactly ONE publication"
        );
    }
}
