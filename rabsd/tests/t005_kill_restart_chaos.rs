//! T005: daemon kill/restart chaos (bead 38.5; builds on H013's startup
//! reconciliation and G008's TERM/drain/reap).
//!
//! `daemon_lifecycle.rs` already proves the single, tidy cases: SIGTERM
//! exits clean inside its budget, one `kill -9` of a BOOTED daemon
//! leaves crash evidence, and the next boot reports recovery. Those are
//! point checks on a daemon that had finished starting.
//!
//! Chaos is the other question: not "does it recover from THE crash"
//! but "does it recover from a crash ANYWHERE, over and over, without
//! quietly accumulating something". Two properties neither the existing
//! suite nor T004 covers:
//!
//! - **Kill offset is varied**, so kills land before the boot marker
//!   (during mount and reconcile) as well as after it. A daemon that
//!   recovers cleanly from a post-boot kill can still be left torn by
//!   one that dies half-way through reconciling. The suite ASSERTS it
//!   achieved both classes rather than assuming its sleeps hit them —
//!   timing-based injection that silently always landed in one phase
//!   would otherwise report full coverage of one.
//! - **Repetition is the point.** A single crash/restart cycle cannot
//!   show accumulation. Leaks of exactly the shape this bead names —
//!   orphan pins, duplicated publications, a stale socket that blocks
//!   the next start — only become visible when the cycle runs many
//!   times over one store and the invariant is checked at the end.
//!
//! NOT COVERED, named so nothing is implied: `rabs-wkr` is not killed
//! here. T005's text says "kill rabsd/rabs-wkr", but no worker process
//! participates in this path yet — the same gap T004 hit, tracked as
//! bd-nrzas. Killing a process that is not a participant would prove
//! nothing. Mid-compile and mid-transfer kills belong with that worker
//! work for the same reason. What is proven here is the daemon half:
//! mid-reconcile and post-boot kills, repeated, with recovery and
//! no-accumulation checked against the store and the product's own
//! startup path.
#![cfg(unix)]

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use rabs_cas::blob_store::{DurabilityPolicy, PutLimits, put_if_absent};
use rabs_cas::metadata_store::{RabsMetadataStore, RusqliteEngine, SqlMetadataStore, digest_key};
use rabs_cas::publication::{
    AUTHORITY_DIGEST_DOMAIN, OfferPreparedActionResult, PublicationOutcome,
};
use rabs_cas::test_support::{
    install_admission_world, install_offer_closure, offer_with_manifest_bytes, sample_action_key,
    sample_expected_descriptor,
};
use rabsd::coord::live::{CoordLive, cluster_id};
use rabsd::janitor::store::{LiveCas, mount_and_reconcile};

/// How many crash/restart cycles one chaos run performs. Large enough
/// that a per-cycle leak of a single row is unmistakable, small enough
/// that the suite stays a test rather than a soak (T010 owns soak).
const CYCLES: usize = 12;

/// Kill offsets in milliseconds, cycled through. The short ones land
/// during mount/reconcile, before the daemon writes its boot marker;
/// the long ones land after it is up.
const KILL_OFFSETS_MS: [u64; 6] = [0, 5, 20, 60, 200, 400];

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

/// Commit one publication into the store, so the chaos cycles have real
/// authoritative state to preserve rather than an empty database.
fn seed_publication(state_dir: &Path) {
    let cas = Arc::new(mount_and_reconcile(&state_dir.join("cas")).expect("mount"));
    let coord = CoordLive::with_cas(Arc::clone(&cas));
    let authority = coord
        .acquire_boot_authority(&cluster_id())
        .expect("authority");
    let (offer, manifest_bytes) = offer_with_manifest_bytes(&authority);
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
        "the chaos fixture must start from a real commit, got {outcome:?}"
    );
}

fn daemon_env(command: &mut Command, state_dir: &Path) {
    command
        .env("RABS_SOCKET_PATH", state_dir.join("rabsd.sock"))
        .env("RABS_BOOT_MARKER", state_dir.join("rabsd.boot"))
        .env("RABS_STATE_DIR", state_dir)
        .env("RABS_CONFIG", "/nonexistent-rabs-config");
}

fn spawn_daemon(state_dir: &Path) -> Child {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rabsd"));
    command.args(["--run-for-ms", "30000"]);
    daemon_env(&mut command, state_dir);
    command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn rabsd")
}

/// One clean boot of the shipped binary: the product's own startup path,
/// used as the recovery oracle.
fn boot(state_dir: &Path) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rabsd"));
    command.args(["--run-for-ms", "1200"]);
    daemon_env(&mut command, state_dir);
    command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("boot rabsd")
}

fn open_store(state_dir: &Path) -> SqlMetadataStore<RusqliteEngine> {
    let engine = RusqliteEngine::open(&state_dir.join("cas").join("meta.sqlite")).expect("engine");
    let mut store = SqlMetadataStore::open(engine).expect("store");
    store.intern_domain(AUTHORITY_DIGEST_DOMAIN);
    store.intern_domain("rabs.action-key.sha256.v1");
    store
}

/// Publication rows for the fixture's action key.
fn publications(store: &mut SqlMetadataStore<RusqliteEngine>) -> Vec<String> {
    let key = digest_key(&sample_action_key());
    store
        .list_publications()
        .expect("publications")
        .into_iter()
        .filter(|(action, _)| *action == key)
        .map(|(_, pin_hex)| pin_hex)
        .collect()
}

/// Where a kill landed, judged by whether the daemon had reached the
/// point where it publishes its boot marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KillPhase {
    /// Killed during mount/reconcile, before the marker existed.
    BeforeBootMarker,
    /// Killed after the daemon was up.
    AfterBootMarker,
}

/// Spawn, wait `offset`, SIGKILL, reap. Returns where the kill landed.
fn crash_cycle(state_dir: &Path, offset_ms: u64, marker: &Path) -> KillPhase {
    // The phase classification below reads the marker, so a marker left
    // by an earlier cycle would make every kill look post-boot and the
    // coverage assertion would pass while testing one phase twice. A
    // clean boot removes the marker, so its absence here is also a check
    // that the previous cycle's recovery boot really did shut down
    // cleanly.
    assert!(
        !marker.exists(),
        "a stale boot marker would corrupt the kill-phase classification"
    );
    let mut child = spawn_daemon(state_dir);
    std::thread::sleep(Duration::from_millis(offset_ms));
    let phase = if marker.exists() {
        KillPhase::AfterBootMarker
    } else {
        KillPhase::BeforeBootMarker
    };
    child.kill().expect("SIGKILL");
    let reaped = child.wait_with_output().expect("reap rabsd");
    assert!(
        !reaped.status.success(),
        "a SIGKILLed daemon must not report success"
    );
    phase
}

#[test]
fn t005_repeated_kills_across_boot_phases_never_lose_or_duplicate_state() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state_dir = dir.path().to_path_buf();
    let marker = state_dir.join("rabsd.boot");

    seed_publication(&state_dir);
    let baseline = {
        let mut store = open_store(&state_dir);
        let pins = publications(&mut store);
        assert_eq!(pins.len(), 1, "the fixture must start from one publication");
        pins
    };

    let mut phases = Vec::new();
    for cycle in 0..CYCLES {
        let offset = KILL_OFFSETS_MS[cycle % KILL_OFFSETS_MS.len()];
        phases.push(crash_cycle(&state_dir, offset, &marker));

        // Every cycle must leave a store the product can still start
        // over. Checking only at the end would hide a store that was
        // briefly unstartable and then repaired by a later boot.
        let out = boot(&state_dir);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success(),
            "cycle {cycle} (kill at {offset}ms): the daemon could not start after the crash\
             \nSTDOUT:{stdout}\nSTDERR:{stderr}"
        );
        assert!(
            stdout.contains("\"serving_refused\":false"),
            "cycle {cycle} (kill at {offset}ms): reconcile refused serving\
             \nSTDOUT:{stdout}\nSTDERR:{stderr}"
        );
    }

    // Coverage, asserted rather than hoped. Timing-based injection that
    // always landed after boot would still pass every assertion above
    // while proving nothing about a crash during reconciliation.
    assert!(
        phases.contains(&KillPhase::BeforeBootMarker),
        "no kill landed during mount/reconcile: the mid-reconcile arm is untested, \
         not passing (offsets {KILL_OFFSETS_MS:?}, observed {phases:?})"
    );
    assert!(
        phases.contains(&KillPhase::AfterBootMarker),
        "no kill landed after boot: the post-boot arm is untested, not passing \
         (observed {phases:?})"
    );

    // Nothing accumulated. A per-cycle leak of even one row over
    // CYCLES iterations is unmistakable here, and this is the property
    // a single crash/restart test structurally cannot show.
    let mut store = open_store(&state_dir);
    let after = publications(&mut store);
    assert_eq!(
        after, baseline,
        "{CYCLES} crash/restart cycles changed the publication set: a crash must not \
         orphan or duplicate a publication pin"
    );
    assert_eq!(
        store.pin_released_by_hex(&after[0]).expect("pin"),
        Some(false),
        "the publication reachability pin must still be held after {CYCLES} crashes"
    );
}

#[test]
fn t005_a_crashed_daemon_never_blocks_the_next_one_from_starting() {
    // The orphan-resource half of this bead. A SIGKILLed daemon cannot
    // clean up: its socket file and boot marker survive it. The next
    // daemon must take the socket over rather than refuse, or one crash
    // would take the host out until an operator removed a file by hand.
    let dir = tempfile::tempdir().expect("tempdir");
    let state_dir = dir.path().to_path_buf();
    let marker = state_dir.join("rabsd.boot");
    let socket = state_dir.join("rabsd.sock");

    seed_publication(&state_dir);

    let mut child = spawn_daemon(&state_dir);
    for _ in 0..200 {
        if marker.exists() && socket.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(
        marker.exists(),
        "the daemon must reach its boot marker before this scenario means anything"
    );
    let socket_survived = socket.exists();
    child.kill().expect("SIGKILL");
    child.wait().expect("reap");

    assert!(
        marker.exists(),
        "a SIGKILLed daemon must leave its boot marker as crash evidence"
    );
    if socket_survived {
        assert!(
            socket.exists(),
            "a SIGKILLed daemon cannot have removed its own socket"
        );
    }

    // The recovery boot takes the stale socket over and says it found an
    // unclean prior incarnation. Here the marker IS from a real daemon,
    // so unlike T004's matrix the recovery report is meaningful.
    let out = boot(&state_dir);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "a stale socket or marker must not block the next daemon\
         \nSTDOUT:{stdout}\nSTDERR:{stderr}"
    );
    assert!(
        stderr.contains("rabsd-recovery"),
        "the next boot must report the unclean prior incarnation: {stderr}"
    );
    assert!(
        stdout.contains("\"serving_refused\":false"),
        "reconcile after a real daemon crash must not refuse serving: {stdout}"
    );
}
