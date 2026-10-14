//! Scheduling and cancellation-lifetime regressions for the actual flight set.
use super::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Waker};

fn stamp_for(id: u64, worker: &str) -> RetryStamp {
    let now = Instant::now();
    RetryStamp {
        build_id: id,
        worker_id: worker.into(),
        wrapper: None,
        hook_pid: 0,
        hook_identity: None,
        started: now,
        heartbeat: now,
        progress: now,
        remote_pgid_file: None,
        slots: 1,
    }
}

#[test]
fn automatic_operations_are_bounded_globally_per_worker_and_per_build() {
    let mut flights = Remediations::default();
    assert!(flights.push(stamp_for(1, "worker-a"), std::future::pending()));
    assert!(!flights.push(stamp_for(2, "worker-a"), std::future::pending()));
    assert!(!flights.push(stamp_for(1, "worker-b"), std::future::pending()));
    for id in 2..=MAX_AUTOMATIC_CANCELLATIONS as u64 {
        assert!(flights.push(
            stamp_for(id, &format!("worker-{id}")),
            std::future::pending()
        ));
    }
    assert_eq!(flights.running.len(), MAX_AUTOMATIC_CANCELLATIONS);
    assert!(!flights.push(stamp_for(100, "overflow"), std::future::pending()));
}

#[tokio::test]
async fn never_ready_worker_cannot_hold_a_ready_peer_or_lose_a_later_wakeup() {
    let mut flights = Remediations::default();
    let (finish, waiting) = tokio::sync::oneshot::channel();
    assert!(flights.push(stamp_for(1, "stalled"), std::future::pending()));
    assert!(flights.push(stamp_for(2, "wakes-later"), async move {
        waiting.await.expect("complete controlled waiter")
    }));
    assert!(flights.push(stamp_for(3, "ready-peer"), async { Some("failed".into()) }));
    let (peer, result, _) = tokio::time::timeout(Duration::from_secs(2), flights.next_completed())
        .await
        .expect("a ready peer must not await the oldest worker");
    assert_eq!(peer.build_id, 3);
    assert_eq!(result.as_deref(), Some("failed"));
    assert_eq!(flights.running.len(), 2);
    assert!(!flights.can_start(&stamp_for(4, "stalled")));

    finish.send(Some("cancelled".into())).unwrap();
    let (peer, result, _) = tokio::time::timeout(Duration::from_secs(2), flights.next_completed())
        .await
        .expect("a later wakeup must remain registered");
    assert_eq!(peer.build_id, 2);
    assert_eq!(result.as_deref(), Some("cancelled"));
    assert_eq!(flights.running.len(), 1);
    assert!(flights.can_start(&stamp_for(5, "ready-peer")));
}

#[tokio::test]
async fn observer_tick_interrupts_waiting_without_dropping_inflight_work() {
    let mut flights = Remediations::default();
    let (finish, waiting) = tokio::sync::oneshot::channel();
    let entered = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&entered);
    assert!(flights.push(stamp_for(1, "worker"), async move {
        seen.fetch_add(1, Ordering::SeqCst);
        waiting.await.expect("wait survives observer ticks")
    }));
    for _ in 0..10 {
        let mut waiting_for_any = Box::pin(flights.next_completed());
        let mut cx = Context::from_waker(Waker::noop());
        assert!(waiting_for_any.as_mut().poll(&mut cx).is_pending());
        drop(waiting_for_any); // The same interruption as select! taking a tick.
        assert_eq!(flights.running.len(), 1);
    }
    assert_eq!(entered.load(Ordering::SeqCst), 1);
    finish.send(Some("failed".into())).unwrap();
    let (completed, _, _) = flights.next_completed().await;
    assert_eq!(completed.build_id, 1);
    assert!(flights.running.is_empty());
}

#[tokio::test]
async fn stopping_before_first_poll_cannot_admit_an_automatic_cancellation() {
    let mut flights = Remediations::default();
    let entered = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&entered);
    let resource = Arc::new(());
    let weak = Arc::downgrade(&resource);
    assert!(flights.push(stamp_for(1, "worker"), async move {
        let _owned = resource;
        seen.fetch_add(1, Ordering::SeqCst);
        std::future::pending().await
    }));
    drop(flights);
    tokio::task::yield_now().await;
    assert_eq!(entered.load(Ordering::SeqCst), 0);
    assert!(
        weak.upgrade().is_none(),
        "no detached admission task may remain"
    );
}

/// Use the real durable history loader to model old observations. No remote
/// endpoint or hook PID is supplied, so these tests never signal or use SSH.
fn stale_builds(
    workers: &[&str],
) -> (tempfile::TempDir, ActiveBuildCleanup, Vec<ActiveBuildState>) {
    stale_builds_with(workers, false)
}

/// `live_hook` binds each build to this test process and a wrapper id, as a
/// reattached hook would be. A reloaded build accepts heartbeats only then.
fn stale_builds_with(
    workers: &[&str],
    live_hook: bool,
) -> (tempfile::TempDir, ActiveBuildCleanup, Vec<ActiveBuildState>) {
    use crate::history::BuildHistory;

    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("history.jsonl");
    let mut context = crate::test_daemon_context(crate::workers::WorkerPool::new());
    context.history = Arc::new(BuildHistory::new(100).with_persistence(path.clone()));
    for (index, worker) in workers.iter().enumerate() {
        context.history.start_active_build(
            format!("automatic-{index}"),
            (*worker).into(),
            "cargo check".into(),
            0,
            1,
            rch_common::BuildLocation::Remote,
        );
    }
    let ownership = path.with_extension("ownership.json");
    let mut snapshot: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&ownership).unwrap()).unwrap();
    // Below the 15-minute abandoned-before-remote threshold: a zero PID alone
    // cannot release these reservations, and cancellation remains unconfirmed.
    let old = (chrono::Utc::now() - chrono::Duration::seconds(600)).to_rfc3339();
    for (index, row) in snapshot["active"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .enumerate()
    {
        for field in ["started_at", "last_heartbeat_at", "last_progress_at"] {
            row[field] = serde_json::json!(&old);
        }
        row["heartbeat_phase"] = serde_json::json!("sync_up");
        if live_hook {
            let pid = crate::history::observable_test_process_id();
            row["hook_pid"] = serde_json::json!(pid);
            row["hook_process_identity"] =
                serde_json::json!(crate::history::process_identity(pid).unwrap());
            row["local_wrapper_id"] = serde_json::json!(format!("live-hook-fixture-{index}"));
        }
    }
    std::fs::write(&ownership, serde_json::to_vec(&snapshot).unwrap()).unwrap();
    context.history = Arc::new(BuildHistory::load_from_file(&path, 100).unwrap());
    let cleanup = ActiveBuildCleanup::new(context);
    let candidates = cleanup.collect_active_builds_observed(&mut ObservationWindow::default());
    assert_eq!(candidates.len(), workers.len());
    (root, cleanup, candidates)
}

#[tokio::test]
async fn production_admission_skips_busy_workers_and_advances_past_a_failed_prefix() {
    let (_root, cleanup, candidates) =
        stale_builds(&["busy", "busy", "b", "c", "d", "e", "f", "g", "h", "i", "j"]);
    let mut flights = Remediations::default();
    let mut observation = ObservationWindow::default();
    let mut backoff = RetryBackoff::default();
    let mut attempted = HashSet::new();
    // The real cancellations return failures; leave them eligible here to test
    // rotation even without relying on backoff to remove an old prefix.
    for _ in 0..3 {
        let fresh = cleanup.collect_active_builds_observed(&mut observation);
        flights.start_observed(&cleanup, &mut observation, &mut backoff, fresh);
        assert!(flights.running.len() <= MAX_AUTOMATIC_CANCELLATIONS);
        let workers: HashSet<_> = flights.running.iter().map(|f| &f.stamp.worker_id).collect();
        assert_eq!(workers.len(), flights.running.len());
        tokio::time::timeout(Duration::from_secs(30), async {
            while !flights.running.is_empty() {
                let (stamp, status, _) = flights.next_completed().await;
                assert_eq!(status.as_deref(), Some("failed"));
                attempted.insert(stamp.build_id);
            }
        })
        .await
        .expect("no-endpoint cancellation must settle without SSH");
    }
    assert_eq!(
        attempted.len(),
        candidates.len(),
        "a failed prefix starved the tail"
    );
    assert_eq!(
        cleanup.context.history.active_builds().len(),
        candidates.len()
    );
    assert!(cleanup.context.history.recent(100).is_empty());
}

#[tokio::test]
async fn heartbeat_after_queuing_vetoes_cancellation_at_first_poll() {
    let (_root, cleanup, candidates) = stale_builds_with(&["resumes-before-poll"], true);
    let mut flights = Remediations::default();
    let mut observation = ObservationWindow::default();
    flights.start_observed(
        &cleanup,
        &mut observation,
        &mut RetryBackoff::default(),
        candidates.clone(),
    );
    assert_eq!(flights.running.len(), 1);
    let build = &candidates[0];
    cleanup
        .context
        .history
        .record_build_heartbeat(rch_common::BuildHeartbeatRequest {
            build_id: build.id,
            worker_id: rch_common::WorkerId::new(&build.worker_id),
            hook_pid: None,
            local_wrapper_id: build.local_wrapper_id.clone(),
            remote_pgid_file: None,
            phase: rch_common::BuildHeartbeatPhase::SyncUp,
            detail: None,
            progress_counter: None,
            progress_percent: None,
        })
        .unwrap();
    let (_, status, _) = flights.next_completed().await;
    assert!(
        status.is_none(),
        "new evidence must veto admission, not cancel the resumed job"
    );
    assert!(
        cleanup
            .context
            .cancellation
            .active_cancellations()
            .await
            .is_empty()
    );
    assert!(cleanup.context.history.active_build(build.id).is_some());
    assert!(cleanup.context.history.recent(100).is_empty());
}

#[tokio::test]
async fn observer_scans_continue_with_all_cancellation_lanes_stalled() {
    let (_root, cleanup, candidates) = stale_builds(&["observed-peer"]);
    let mut flights = Remediations::default();
    let base = candidates.iter().map(|build| build.id).max().unwrap();
    for offset in 1..=MAX_AUTOMATIC_CANCELLATIONS as u64 {
        let id = base.checked_add(offset).unwrap();
        assert!(flights.push(
            stamp_for(id, &format!("blocked-{id}")),
            std::future::pending()
        ));
    }
    let mut observation = ObservationWindow::default();
    let mut backoff = RetryBackoff::default();
    for _ in 0..3 {
        // Exercise the same observation path used by run's timer branch.
        RecoveredQueueCleanup::default().check(&cleanup.context);
        let fresh = cleanup.collect_active_builds_observed(&mut observation);
        assert_eq!(fresh.len(), 1);
        flights.start_observed(&cleanup, &mut observation, &mut backoff, fresh);
        assert_eq!(flights.running.len(), MAX_AUTOMATIC_CANCELLATIONS);
        assert!(
            cleanup
                .context
                .history
                .active_build(candidates[0].id)
                .unwrap()
                .detector_heartbeat_stale
        );
    }
    assert!(
        cleanup
            .context
            .cancellation
            .active_cancellations()
            .await
            .is_empty()
    );
}

#[tokio::test]
async fn refreshed_queue_drops_obsolete_ids_without_forgetting_running_operations() {
    let (_root, cleanup, candidates) = stale_builds(&["waiting-a", "waiting-b"]);
    let mut flights = Remediations::default();
    let base = candidates.iter().map(|build| build.id).max().unwrap();
    for offset in 1..=MAX_AUTOMATIC_CANCELLATIONS as u64 {
        let id = base.checked_add(offset).unwrap();
        assert!(flights.push(
            stamp_for(id, &format!("blocked-{id}")),
            std::future::pending()
        ));
    }
    let mut observation = ObservationWindow::default();
    let mut backoff = RetryBackoff::default();
    flights.start_observed(&cleanup, &mut observation, &mut backoff, candidates);
    assert_eq!(flights.pending.len(), 2);
    // Empty fresh observations can mean progress, not terminal completion.
    flights.start_observed(&cleanup, &mut observation, &mut backoff, Vec::new());
    assert!(flights.pending.is_empty());
    assert_eq!(flights.running.len(), MAX_AUTOMATIC_CANCELLATIONS);
    assert_eq!(cleanup.context.history.active_builds().len(), 2);
}
