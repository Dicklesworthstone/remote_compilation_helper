use super::*;
use crate::cancellation::tests::{make_test_context, test_config, test_events};
use crate::history::BuildHistory;
use crate::workers::WorkerPool;
use std::path::Path;

const HOUR: Duration = Duration::from_secs(3600);
const MINUTE: Duration = Duration::from_secs(60);

#[test]
fn forget_thresholds_follow_proof_and_origin() {
    use ForgetOrigin::{Automatic, Operator};
    use RemoteAnswer::{Confirmed, NotAsked, Unconfirmed};

    // A just-exited wrapper is never forgettable, even with a worker receipt.
    for origin in [Operator, Automatic] {
        for answer in [Confirmed, Unconfirmed, NotAsked] {
            let refusal = forget_decision(origin, 14 * MINUTE, answer).unwrap_err();
            assert!(refusal.contains("900s of silence"), "{refusal}");
        }
    }
    assert!(forget_decision(Operator, 15 * MINUTE, Confirmed).is_ok());

    // Without a worker answer the operator waits 24h, the detector 72h.
    let refusal = forget_decision(Operator, 23 * HOUR, Unconfirmed).unwrap_err();
    assert!(refusal.contains("24h of silence (1h remaining)"), "{refusal}");
    assert!(forget_decision(Operator, 24 * HOUR, Unconfirmed).is_ok());
    assert!(forget_decision(Operator, 24 * HOUR, NotAsked).is_ok());
    assert!(forget_decision(Automatic, 71 * HOUR, NotAsked).is_err());
    let proof = forget_decision(Automatic, 72 * HOUR, NotAsked).unwrap();
    assert!(proof.contains("72h automatic limit"), "{proof}");
}

fn rewind(value: &mut serde_json::Value, age: Duration) {
    let then = (chrono::Utc::now() - chrono::Duration::from_std(age).unwrap()).to_rfc3339();
    for field in ["started_at", "last_heartbeat_at", "last_progress_at"] {
        value[field] = serde_json::json!(then);
    }
}

/// Persist two remote builds that heartbeat into `execute`, 20 minutes ago:
/// one whose wrapper was killed (the phantom) and one owned by this live
/// test process. Then restart the "daemon" by reloading durable ownership,
/// exactly what every dispatcher restart did with the real phantoms.
fn persisted_phantom(root: &Path) -> (Arc<BuildHistory>, u64, u64) {
    let path = root.join("history.jsonl");
    let history = BuildHistory::new(20).with_persistence(path.clone());
    let mut wrapper = std::process::Command::new("sleep")
        .arg("60")
        .spawn()
        .unwrap();
    let phantom = history.start_active_build_with_wrapper(
        "phantom-project".into(),
        "w1".into(),
        "cargo test".into(),
        wrapper.id(),
        Some(format!("rchw-{}", uuid::Uuid::new_v4())),
        2,
        rch_common::BuildLocation::Remote,
    );
    assert!(phantom.hook_process_identity.is_some());
    wrapper.kill().unwrap();
    wrapper.wait().unwrap();
    let live = history.start_active_build_with_wrapper(
        "live-project".into(),
        "w1".into(),
        "cargo test".into(),
        std::process::id(),
        Some(format!("rchw-{}", uuid::Uuid::new_v4())),
        1,
        rch_common::BuildLocation::Remote,
    );
    drop(history);

    let ownership_path = path.with_extension("ownership.json");
    let mut ownership: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&ownership_path).unwrap()).unwrap();
    for build in ownership["active"].as_array_mut().unwrap() {
        rewind(build, 20 * MINUTE);
        build["heartbeat_phase"] = serde_json::json!("execute");
        let id = build["id"].as_u64().unwrap();
        build["remote_pgid_file"] = serde_json::json!(format!("/tmp/rch-run/x/{id}.pgid"));
    }
    std::fs::write(&ownership_path, serde_json::to_vec(&ownership).unwrap()).unwrap();
    let restored = Arc::new(BuildHistory::load_from_file(&path, 20).unwrap());
    (restored, phantom.id, live.id)
}

async fn pool_with_reserved_slots(slots: u32) -> WorkerPool {
    let pool = WorkerPool::new();
    let config = rch_common::WorkerConfig {
        id: WorkerId::new("w1"),
        total_slots: 4,
        ..Default::default()
    };
    pool.add_worker(config.clone()).await;
    assert!(pool.get(&config.id).await.unwrap().reserve_slots(slots).await);
    pool
}

#[tokio::test]
async fn persisted_phantom_skips_drains_and_is_forgotten_only_with_proof() {
    let root = tempfile::tempdir().unwrap();
    let (history, phantom, live) = persisted_phantom(root.path());
    let restored = history.active_build(phantom).unwrap();
    assert!(restored.recovered, "ownership came back from disk");
    let now = Instant::now();
    let silence = orphaned_silence(&restored, now).unwrap();
    assert!(silence >= 19 * MINUTE && silence <= 21 * MINUTE, "{silence:?}");
    assert!(is_orphaned_build(&restored, now));
    assert!(!is_orphaned_build(&history.active_build(live).unwrap(), now));

    let pool = pool_with_reserved_slots(3).await;
    let ctx = make_test_context(pool.clone(), Arc::clone(&history));

    // A drain waits only for the live build; the phantom is reported.
    let admission = crate::api::restart_admission_snapshot(&ctx, true).await;
    assert_eq!(admission.active_build_ids, vec![live]);
    assert_eq!(admission.orphaned_build_ids, vec![phantom]);

    let orch = CancellationOrchestrator::new(test_config(), test_events());
    let worker = pool.get(&WorkerId::new("w1")).await.unwrap();

    // No admitted endpoint, so the worker cannot be asked: 20 minutes of
    // silence is not enough for an operator, nor 25h for the detector.
    for (origin, at) in [
        (ForgetOrigin::Operator, now),
        (ForgetOrigin::Automatic, now + 25 * HOUR),
    ] {
        let refused = orch.forget_build_at(&ctx, phantom, origin, at).await;
        assert_eq!(refused.status, "refused", "{refused:?}");
        assert_eq!(refused.slots_released, 0);
        assert!(history.active_build(phantom).is_some());
        assert_eq!(worker.used_slots(), 3);
    }

    // A live wrapper is never forgotten, however old the build looks.
    let refused = orch
        .forget_build_at(&ctx, live, ForgetOrigin::Operator, now + 100 * HOUR)
        .await;
    assert_eq!(refused.status, "refused");
    assert!(
        refused.message.as_deref().unwrap().contains("running or unverified"),
        "{refused:?}"
    );
    assert!(history.active_build(live).is_some());

    let forgotten = orch
        .forget_build_at(&ctx, phantom, ForgetOrigin::Operator, now + 25 * HOUR)
        .await;
    assert_eq!(forgotten.status, "forgotten", "{forgotten:?}");
    assert_eq!(forgotten.slots_released, 2);
    assert_eq!(worker.used_slots(), 1);
    assert!(history.active_build(phantom).is_none());
    assert!(history.active_build(live).is_some());
    let wrapper = restored.local_wrapper_id.as_deref().unwrap();
    let record = history.terminal_build(phantom, wrapper).unwrap();
    assert_eq!(record.exit_code, 130);
    let cancellation = record.cancellation.unwrap();
    assert_eq!(cancellation.reason_code, FORGOTTEN_REASON_CODE);
    assert_eq!(cancellation.origin, "operator");
    assert_eq!(cancellation.final_state, "forgotten");
    assert_eq!(cancellation.operation_id, format!("forget-{phantom}"));

    // Forgetting is idempotent and survives the next restart.
    let again = orch
        .forget_build_at(&ctx, phantom, ForgetOrigin::Operator, now + 25 * HOUR)
        .await;
    assert_eq!(again.status, "error");
    assert_eq!(worker.used_slots(), 1);
    let reloaded =
        BuildHistory::load_from_file(&root.path().join("history.jsonl"), 20).unwrap();
    assert!(reloaded.active_build(phantom).is_none());
    assert!(reloaded.has_terminal_build(phantom));
    assert!(reloaded.active_build(live).is_some());
}

#[tokio::test]
async fn automatic_forget_needs_the_long_limit_and_never_dials() {
    let root = tempfile::tempdir().unwrap();
    let (history, phantom, _live) = persisted_phantom(root.path());
    let pool = pool_with_reserved_slots(3).await;
    let ctx = make_test_context(pool.clone(), Arc::clone(&history));
    let orch = CancellationOrchestrator::new(test_config(), test_events());
    let now = Instant::now();
    let refused = orch
        .forget_build_at(&ctx, phantom, ForgetOrigin::Automatic, now + 71 * HOUR)
        .await;
    assert_eq!(refused.status, "refused");
    let forgotten = orch
        .forget_build_at(&ctx, phantom, ForgetOrigin::Automatic, now + 73 * HOUR)
        .await;
    assert_eq!(forgotten.status, "forgotten", "{forgotten:?}");
    let wrapper = history.terminal_build(phantom, "missing");
    assert!(wrapper.is_none(), "terminal records stay wrapper-bound");
    assert!(history.has_terminal_build(phantom));
    assert_eq!(
        pool.get(&WorkerId::new("w1")).await.unwrap().used_slots(),
        1
    );
}

#[tokio::test]
async fn forget_shares_cancellation_admission() {
    let root = tempfile::tempdir().unwrap();
    let (history, phantom, _live) = persisted_phantom(root.path());
    let ctx = make_test_context(pool_with_reserved_slots(2).await, Arc::clone(&history));
    let orch = CancellationOrchestrator::new(test_config(), test_events());
    let build = history.active_build(phantom).unwrap();
    let claim = CancellationRecord {
        build_id: phantom,
        worker_id: build.worker_id.clone(),
        worker_endpoint: None,
        state: CancellationState::RemoteKillSent,
        reason: CancelReason::User,
        requested_at: Instant::now(),
        completed_at: None,
        escalation_count: 0,
        remote_kill_attempted: true,
        remote_kill_confirmed: false,
        remote_record_absent: false,
        cleanup_ok: true,
        slots: build.slots,
        slots_released: 0,
        hook_pid: build.hook_pid,
        hook_process_identity: build.hook_process_identity.clone(),
        remote_pgid_file: build.remote_pgid_file.clone(),
        abandoned_unlaunched: false,
    };
    orch.active.lock().unwrap().insert(phantom, claim);
    let busy = orch
        .forget_build_at(
            &ctx,
            phantom,
            ForgetOrigin::Operator,
            Instant::now() + 25 * HOUR,
        )
        .await;
    assert_eq!(busy.status, "cancelling");
    assert!(history.active_build(phantom).is_some());
    orch.active.lock().unwrap().remove(&phantom);
    assert!(orch.active_cancellations().await.is_empty());
}
