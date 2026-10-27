//! Exercise the live SPRT-to-installation handoff using real CAS/output bytes.
//!
//! Checkpoints are explicitly synthetic boundary fixtures: these tests prove
//! how qualified policy is CONSUMED, not that 209,286 compiles were compared.
//! The CAS ladder suite separately exercises the evidence reducer. Each mode
//! runs in a fresh process: Rust 2024 environment mutation is never needed.
#![cfg(unix)]

use rabs_cas::blob_store::{DurabilityPolicy, PutLimits, put_if_absent};
use rabs_cas::digest_set::{DigestRequest, digest_set};
use rabs_cas::metadata_store::{RabsMetadataStore, digest_key};
use rabs_cas::publication::{OfferPreparedActionResult, PublicationOutcome};
use rabs_cas::test_support::{
    FixtureAttemptIds, install_admission_world, install_admission_world_with_ids,
    install_offer_closure, offer_serving_object, sample_action_key, sample_expected_descriptor,
};
use rabs_protocol::generation::{ActionGenerationId, AttemptId, ExecutionLeaseId};
use rabs_protocol::result_identity::ObjectId;
use rabsd::coord::live::{CoordLive, ExpectedOutputs, ServeOutcome};
use rabsd::janitor::store::{LiveCas, mount_and_reconcile};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const CHILD: &str = "RABS_SPRT_BUDGET_TEST_CHILD";
const ROOT: &str = "RABS_SPRT_BUDGET_TEST_ROOT";
const CLASS: &str = "rustc-dependency-compile";
const CLUSTER: &str = "sprt-budget-tests";
const BYTES: &[u8] = b"real CAS artifact bytes for the replay budget regression";
const STEP: u64 = 69_762;

fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros(),
    )
    .unwrap()
}

fn run_child(test: &str, mode: &str, root: Option<&Path>) {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", test, "--nocapture"])
        .env(CHILD, test)
        .env("RABS_SPRT_SAMPLING", mode)
        .env_remove(ROOT)
        .stdin(Stdio::null());
    if let Some(root) = root {
        command.env(ROOT, root);
    }
    let mut child = command.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success(), "{test} mode={mode}: {status}");
            return;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{test} mode={mode}: child exceeded the test deadline");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn in_child(test: &str) -> bool {
    std::env::var(CHILD).as_deref() == Ok(test)
}

fn open(root: &Path) -> (Arc<LiveCas>, Arc<CoordLive>) {
    let cas = Arc::new(mount_and_reconcile(&root.join("cas")).unwrap());
    let coord = Arc::new(CoordLive::with_cas(Arc::clone(&cas)));
    coord.acquire_boot_authority(CLUSTER).unwrap();
    coord.mark_up();
    (cas, coord)
}

fn put(cas: &LiveCas, bytes: &[u8]) -> ObjectId {
    let object = digest_set(bytes, DigestRequest::default(), None)
        .unwrap()
        .atp_content_id;
    put_if_absent(
        cas.layout(),
        &mut *cas.store().lock().unwrap(),
        &object,
        &mut &bytes[..],
        PutLimits::default(),
        DurabilityPolicy::FULL,
    )
    .unwrap();
    ObjectId(object)
}

fn compare(cas: &LiveCas, coord: &CoordLive, original: &OfferPreparedActionResult, number: u128) {
    let authority = coord.authority().unwrap();
    let ids = FixtureAttemptIds {
        generation: 11 + number,
        attempt: 20 + number,
        lease: 30 + number,
    };
    install_admission_world_with_ids(&mut *cas.store().lock().unwrap(), &authority, ids);
    let mut offer = original.clone();
    offer.authority.coordinator = authority;
    offer.authority.action_generation.generation_id = ActionGenerationId(ids.generation);
    offer.authority.attempt_id = AttemptId(ids.attempt);
    offer.authority.execution_lease_id = ExecutionLeaseId(ids.lease);
    assert_eq!(
        coord
            .commit_offer(&offer, &sample_expected_descriptor())
            .unwrap(),
        PublicationOutcome::IdempotentEvidenceAppended,
    );
}

fn fixture(stage: u64) -> (tempfile::TempDir, Arc<LiveCas>, Arc<CoordLive>) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let (cas, coord) = open(dir.path());
    let authority = coord.authority().unwrap();
    let artifact = put(&cas, BYTES);
    {
        let mut store = cas.store().lock().unwrap();
        install_admission_world(&mut *store, &authority);
        store
            .record_decision_receipt(
                "rabs-live-action-class-v1",
                &digest_key(&sample_action_key()),
                0,
                CLASS,
                "synthetic descriptor binding",
            )
            .unwrap();
    }
    let (offer, bytes) = offer_serving_object(&authority, &artifact);
    assert_eq!(put(&cas, &bytes), offer.manifest_id);
    install_offer_closure(&mut *cas.store().lock().unwrap(), &offer);
    assert!(matches!(
        coord
            .commit_offer(&offer, &sample_expected_descriptor())
            .unwrap(),
        PublicationOutcome::Committed(_)
    ));
    compare(&cas, &coord, &offer, 1);
    compare(&cas, &coord, &offer, 2);
    // Intentionally inject a qualified boundary, not synthetic trial receipts.
    // This test must exercise the final replay-budget consumer without running
    // hundreds of thousands of fsync-backed fixture transactions per case.
    cas.store()
        .lock()
        .unwrap()
        .record_decision_receipt(
            "rabs-sprt-checkpoint-v1",
            CLASS,
            0,
            &(stage * STEP).to_string(),
            &(3 * STEP).to_string(),
        )
        .unwrap();
    (dir, cas, coord)
}

fn serve_from_edge(coord: &Arc<CoordLive>, destination: &Path) -> ServeOutcome {
    coord
        .edge_subscriber()
        .serve_action(
            &sample_action_key(),
            destination,
            &ExpectedOutputs::Exactly(["out/lib.rlib".to_owned()].into_iter().collect()),
            now(),
            0,
        )
        .unwrap()
}

fn installed(coord: &Arc<CoordLive>, destination: &Path) {
    assert!(matches!(
        serve_from_edge(coord, destination),
        ServeOutcome::Served { .. }
    ));
    assert_eq!(
        std::fs::read(destination.join("out/lib.rlib")).unwrap(),
        BYTES
    );
}

fn exhausted(coord: &Arc<CoordLive>, destination: &Path) {
    assert!(matches!(
        serve_from_edge(coord, destination),
        ServeOutcome::ExecutePrivately(_)
    ));
    assert!(
        !destination.exists(),
        "refused replay must not materialize output"
    );
}

#[test]
fn live_sprt_qualified_limits_survive_coordinator_restarts() {
    const TEST: &str = "live_sprt_qualified_limits_survive_coordinator_restarts";
    if !in_child(TEST) {
        run_child(TEST, "1", None);
        return;
    }
    for (stage, limit) in [(0, 0), (1, 3), (2, 19), (3, 99)] {
        let (dir, mut cas, mut coord) = fixture(stage);
        for index in 0..limit {
            if index == limit / 2 {
                drop(coord);
                drop(cas);
                (cas, coord) = open(dir.path());
            }
            installed(&coord, &dir.path().join(format!("replay-{index}")));
        }
        exhausted(&coord, &dir.path().join("exhausted"));
        assert_eq!(
            cas.store()
                .lock()
                .unwrap()
                .serving_disposition_key(&digest_key(&sample_action_key()))
                .unwrap()
                .as_deref(),
            Some("servable"),
            "exhausted budget is not fabricated quarantine",
        );
    }
}

#[test]
fn live_sprt_mode_switching_does_not_reset_spent_receipts() {
    const TEST: &str = "live_sprt_mode_switching_does_not_reset_spent_receipts";
    if !in_child(TEST) {
        let (dir, cas, coord) = fixture(3);
        drop(coord);
        drop(cas);
        run_child(TEST, "off", Some(dir.path()));
        run_child(TEST, "on", Some(dir.path()));
        run_child(TEST, "0", Some(dir.path()));
        return;
    }
    let root = PathBuf::from(std::env::var_os(ROOT).unwrap());
    let (_cas, coord) = open(&root);
    match std::env::var("RABS_SPRT_SAMPLING").unwrap().as_str() {
        "off" => {
            for index in 0..16 {
                installed(&coord, &root.join(format!("fixed-{index}")));
            }
        }
        "on" => {
            for index in 16..99 {
                installed(&coord, &root.join(format!("qualified-{index}")));
            }
        }
        "0" => {}
        value => panic!("unexpected test mode {value}"),
    }
    exhausted(&coord, &root.join("must-not-reset"));
}

#[test]
fn live_sprt_concurrent_installers_share_one_qualified_budget() {
    const TEST: &str = "live_sprt_concurrent_installers_share_one_qualified_budget";
    if !in_child(TEST) {
        run_child(TEST, "true", None);
        return;
    }
    let (dir, _cas, coord) = fixture(2);
    let outcomes = std::thread::scope(|scope| {
        let barrier = Arc::new(std::sync::Barrier::new(24));
        let threads: Vec<_> = (0..24)
            .map(|index| {
                let coord = Arc::clone(&coord);
                let barrier = Arc::clone(&barrier);
                let destination = dir.path().join(format!("concurrent-{index}"));
                scope.spawn(move || {
                    barrier.wait();
                    let outcome = serve_from_edge(&coord, &destination);
                    (outcome, destination)
                })
            })
            .collect();
        threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>()
    });
    let mut served = 0;
    for (outcome, destination) in outcomes {
        match outcome {
            ServeOutcome::Served { .. } => {
                served += 1;
                assert_eq!(
                    std::fs::read(destination.join("out/lib.rlib")).unwrap(),
                    BYTES
                );
            }
            ServeOutcome::ExecutePrivately(_) => assert!(!destination.exists()),
            other => panic!("unexpected concurrent outcome {other:?}"),
        }
    }
    assert_eq!(
        served, 19,
        "final coordinator ceiling must not truncate SPRT to 16"
    );
    exhausted(&coord, &dir.path().join("no-extra-permit"));
}

#[test]
fn live_sprt_invalid_mode_cannot_silently_enable_fixed_replay() {
    const TEST: &str = "live_sprt_invalid_mode_cannot_silently_enable_fixed_replay";
    if !in_child(TEST) {
        run_child(TEST, "typo", None);
        return;
    }
    let (dir, cas, coord) = fixture(3);
    let before = cas.store().lock().unwrap().differential_snapshot().unwrap();
    let destination = dir.path().join("invalid-mode");
    let result = coord.edge_subscriber().serve_action(
        &sample_action_key(),
        &destination,
        &ExpectedOutputs::WhateverWasCommitted,
        now(),
        0,
    );
    assert!(
        result.is_err(),
        "invalid mode cannot fall back to a 16-install grant"
    );
    assert!(!destination.exists());
    assert_eq!(
        cas.store().lock().unwrap().differential_snapshot().unwrap(),
        before
    );
}
