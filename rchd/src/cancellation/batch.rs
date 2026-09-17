//! Daemon-owned, bounded fan-out for fleet-wide cancellation.

use super::{CancelAllBuildsResponse, CancelReason, CancellationOrchestrator, CancelledBuildInfo};
use crate::DaemonContext;
use std::collections::BTreeSet;
use std::sync::Arc;
use tokio::task::JoinSet;
use tracing::warn;

// Shared by clones of one orchestrator, not multiplied by concurrent callers.
pub(super) const MAX_BULK_CANCELLATIONS: usize = 8;

pub(super) async fn cancel_all_builds(
    orchestrator: &CancellationOrchestrator,
    context: &DaemonContext,
    force: bool,
) -> CancelAllBuildsResponse {
    // Freeze the requested set before the first await. Jobs admitted afterward
    // are not part of this request, even if earlier cancellations are slow.
    let build_ids: BTreeSet<u64> = context
        .history
        .active_builds()
        .into_iter()
        .map(|build| build.id)
        .collect();
    if build_ids.is_empty() {
        return CancelAllBuildsResponse {
            status: "ok".to_owned(),
            cancelled_count: 0,
            cancelled: Vec::new(),
            message: Some("No active builds to cancel".to_owned()),
        };
    }

    let requested_count = build_ids.len();
    let owner = orchestrator.clone();
    let context = context.clone();
    // Detaching the caller's JoinHandle does not cancel the batch. In
    // particular, requests beyond the first window must still be attempted.
    // This owns work for the current runtime; it is not restart persistence.
    let operation = tokio::spawn(cancel_batch(owner, context, build_ids, force));
    match operation.await {
        Ok(response) => response,
        Err(error) => {
            warn!(%error, requested_count, "Bulk cancellation task ended unexpectedly");
            CancelAllBuildsResponse {
                status: "failed".to_owned(),
                cancelled_count: 0,
                cancelled: Vec::new(),
                message: Some(format!(
                    "Bulk cancellation of {requested_count} build(s) ended unexpectedly; \
                     inspect active history before retrying (some operations may have completed)"
                )),
            }
        }
    }
}

async fn cancel_batch(
    owner: CancellationOrchestrator,
    context: DaemonContext,
    build_ids: BTreeSet<u64>,
    force: bool,
) -> CancelAllBuildsResponse {
    let requested_count = build_ids.len();
    // Start pessimistic: even a panicked waiter cannot erase a requested ID
    // from the failure denominator or manufacture a successful cancellation.
    let mut unconfirmed = build_ids.clone();
    let mut pending = build_ids.into_iter();
    let mut running = JoinSet::new();
    let mut cancelled = Vec::new();

    loop {
        // Bound waiter tasks as well as SSH work. Do not spawn one task for
        // every build just to have almost all of them wait on a semaphore.
        while running.len() < MAX_BULK_CANCELLATIONS {
            let Some(build_id) = pending.next() else {
                break;
            };
            let owner = owner.clone();
            let context = context.clone();
            running.spawn(async move {
                let Ok(_permit) = Arc::clone(&owner.bulk_permits).acquire_owned().await else {
                    return (build_id, None);
                };
                // Use the production single-build admission, identity refresh,
                // termination confirmation and exactly-once cleanup unchanged.
                let response = owner
                    .cancel_build(&context, build_id, CancelReason::User, force)
                    .await;
                (build_id, Some(response))
            });
        }

        let Some(result) = running.join_next().await else {
            break;
        };
        match result {
            Ok((build_id, Some(response))) if response.status == "cancelled" => {
                unconfirmed.remove(&build_id);
                cancelled.push(CancelledBuildInfo {
                    build_id,
                    worker_id: response.worker_id.unwrap_or_default(),
                    project_id: response.project_id.unwrap_or_default(),
                    slots_released: response.slots_released,
                });
            }
            Ok(_) => {}
            Err(error) => {
                // Other candidates still need processing after one waiter
                // fails. Its ID remains in `unconfirmed` from the snapshot.
                warn!(%error, "Bulk cancellation waiter failed");
            }
        }
    }

    // Completion order is intentionally concurrent, response order is stable.
    cancelled.sort_by_key(|build| build.build_id);
    let unconfirmed: Vec<u64> = unconfirmed.into_iter().collect();
    let cancelled_count = cancelled.len();
    let status = if unconfirmed.is_empty() {
        "ok"
    } else if cancelled.is_empty() {
        "failed"
    } else {
        "partial"
    };
    // A disconnected caller no longer receives the response, so retain an
    // observable batch outcome without declaring unconfirmed work completed.
    owner.events.emit(
        "cancellation_batch_completed",
        &serde_json::json!({
            "requested_count": requested_count,
            "cancelled_count": cancelled_count,
            "unconfirmed_build_ids": &unconfirmed,
            "force": force,
            "status": status,
        }),
    );
    CancelAllBuildsResponse {
        status: status.to_owned(),
        cancelled_count,
        cancelled,
        message: Some(format!(
            "{} build(s) {}; {} cancellation(s) unconfirmed: {:?}",
            cancelled_count,
            if force {
                "forcefully terminated"
            } else {
                "cancelled"
            },
            unconfirmed.len(),
            unconfirmed,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cancellation::CancellationConfig;
    use crate::cancellation::tests::{make_test_context, test_config, test_events};
    use crate::history::BuildHistory;
    use crate::workers::WorkerPool;
    use rch_common::BuildLocation;
    use std::time::Duration;

    async fn wait_for_attempt_count(owner: &CancellationOrchestrator, count: usize) {
        tokio::time::timeout(Duration::from_secs(3), async {
            while owner.active_cancellations().await.len() != count {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("bulk cancellation did not reach its bounded admission window");
    }

    #[tokio::test]
    async fn cancellation_batch_finishes_snapshot_after_caller_abort_without_admitting_later_jobs()
    {
        for force in [false, true] {
            let history = Arc::new(BuildHistory::new(100));
            let requested = MAX_BULK_CANCELLATIONS + 3;
            for index in 0..requested {
                history.start_active_build(
                    format!("bulk-{index}"),
                    format!("missing-{index}"),
                    "cargo test".to_owned(),
                    0,
                    1,
                    BuildLocation::Remote,
                );
            }
            let context = make_test_context(WorkerPool::new(), history.clone());
            let owner = CancellationOrchestrator::new(
                CancellationConfig {
                    cleanup_timeout: Duration::ZERO,
                    ..test_config()
                },
                test_events(),
            );
            // Block the real operations in final accounting. Zero termination
            // budget and zero hook PIDs ensure no process/worker is contacted.
            let stats = owner.worker_stats.write().await;
            let caller_owner = owner.clone();
            let caller_context = context.clone();
            let caller = tokio::spawn(async move {
                caller_owner.cancel_all_builds(&caller_context, force).await
            });
            wait_for_attempt_count(&owner, MAX_BULK_CANCELLATIONS).await;
            assert_eq!(owner.bulk_permits.available_permits(), 0);
            caller.abort();
            assert!(caller.await.unwrap_err().is_cancelled());
            let late = history.start_active_build(
                "arrived-after-snapshot".to_owned(),
                "late-worker".to_owned(),
                "cargo test".to_owned(),
                0,
                1,
                BuildLocation::Remote,
            );
            assert_eq!(
                owner.active_cancellations().await.len(),
                MAX_BULK_CANCELLATIONS
            );
            drop(stats);
            tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    let attempted: usize = owner
                        .worker_stats
                        .read()
                        .await
                        .values()
                        .map(|stats| stats.recent_cancellations.len())
                        .sum();
                    if attempted == requested {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("caller abort abandoned later windows of the requested snapshot");
            wait_for_attempt_count(&owner, 0).await;
            assert_eq!(history.active_builds().len(), requested + 1);
            assert!(history.active_build(late.id).is_some());
            assert!(
                history.recent(100).is_empty(),
                "unconfirmed work must stay active"
            );
            assert!(!owner.worker_stats.read().await.contains_key("late-worker"));
        }
    }

    #[tokio::test]
    async fn cancellation_batch_reports_only_confirmed_builds_in_stable_order() {
        for force in [false, true] {
            let history = Arc::new(BuildHistory::new(100));
            let mut confirmed = Vec::new();
            let mut retained = Vec::new();
            for index in 0..(MAX_BULK_CANCELLATIONS + 5) {
                let slots = if index % 3 == 0 { 1 } else { 0 };
                let build = history.start_active_build(
                    format!("bulk-{index}"),
                    "missing-worker".to_owned(),
                    "fixture".to_owned(),
                    0,
                    slots,
                    BuildLocation::Remote,
                );
                if slots == 0 {
                    confirmed.push(build.id);
                } else {
                    retained.push(build.id);
                }
            }
            let context = make_test_context(WorkerPool::new(), history.clone());
            let owner = CancellationOrchestrator::new(test_config(), test_events());
            let result = owner.cancel_all_builds(&context, force).await;
            assert_eq!(result.status, "partial");
            confirmed.sort_unstable();
            assert_eq!(result.cancelled_count, confirmed.len());
            assert_eq!(
                result
                    .cancelled
                    .iter()
                    .map(|build| build.build_id)
                    .collect::<Vec<_>>(),
                confirmed
            );
            assert!(
                result
                    .cancelled
                    .iter()
                    .all(|build| build.slots_released == 0)
            );
            assert_eq!(history.recent(100).len(), confirmed.len());
            assert_eq!(history.active_builds().len(), retained.len());
            for id in retained {
                assert!(history.active_build(id).is_some());
            }
            let retry = owner.cancel_all_builds(&context, force).await;
            assert_eq!(retry.status, "failed");
            assert_eq!(retry.cancelled_count, 0);
            assert!(retry.cancelled.is_empty());
            assert_eq!(history.recent(100).len(), confirmed.len());
        }
    }

    #[tokio::test]
    async fn cancellation_batch_concurrent_snapshots_share_limit_and_retain_real_reservations() {
        let pool = WorkerPool::new();
        let history = Arc::new(BuildHistory::new(100));
        let per_batch = MAX_BULK_CANCELLATIONS + 3;
        let reserved = u32::try_from(per_batch).unwrap() + 2;
        let mut workers = Vec::new();
        let mut snapshots = [BTreeSet::new(), BTreeSet::new()];
        for (index, snapshot) in snapshots.iter_mut().enumerate() {
            let id = rch_common::WorkerId::new(format!("bulk-worker-{index}"));
            pool.add_worker(rch_common::WorkerConfig {
                id: id.clone(),
                host: "bulk-cancellation.invalid".to_owned(),
                total_slots: reserved + 2,
                ..rch_common::WorkerConfig::default()
            })
            .await;
            let worker = pool.get(&id).await.unwrap();
            assert!(worker.reserve_slots(reserved).await);
            workers.push(worker);
            for build in 0..per_batch {
                let active = history.start_active_build(
                    format!("batch-{index}-build-{build}"),
                    id.to_string(),
                    "cargo test".to_owned(),
                    0,
                    1,
                    BuildLocation::Remote,
                );
                snapshot.insert(active.id);
            }
        }
        let context = make_test_context(pool, history.clone());
        let owner = CancellationOrchestrator::new(
            CancellationConfig {
                cleanup_timeout: Duration::ZERO,
                ..test_config()
            },
            test_events(),
        );
        let stats = owner.worker_stats.write().await;
        let [first_ids, second_ids] = snapshots;
        let first = tokio::spawn(cancel_batch(
            owner.clone(),
            context.clone(),
            first_ids,
            false,
        ));
        wait_for_attempt_count(&owner, MAX_BULK_CANCELLATIONS).await;
        let second = tokio::spawn(cancel_batch(owner.clone(), context, second_ids, true));
        for _ in 0..20 {
            tokio::task::yield_now().await;
            assert_eq!(
                owner.active_cancellations().await.len(),
                MAX_BULK_CANCELLATIONS,
                "a second batch multiplied the shared operation budget"
            );
        }
        drop(stats);
        let (first, second) = tokio::time::timeout(Duration::from_secs(3), async {
            tokio::join!(first, second)
        })
        .await
        .expect("both bounded snapshots must make progress");
        for result in [first.unwrap(), second.unwrap()] {
            assert_eq!(result.status, "failed");
            assert_eq!(result.cancelled_count, 0);
            assert!(result.cancelled.is_empty());
        }
        assert_eq!(history.active_builds().len(), per_batch * 2);
        assert!(history.recent(100).is_empty());
        for worker in workers {
            assert_eq!(
                worker.used_slots(),
                reserved,
                "failed bulk cancellation released live or unrelated reservations"
            );
        }
        assert_eq!(
            owner.bulk_permits.available_permits(),
            MAX_BULK_CANCELLATIONS
        );
        assert!(owner.active_cancellations().await.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn cancellation_batch_aborted_caller_still_terminates_all_owned_hooks() {
        struct OwnedChild(std::process::Child);
        impl Drop for OwnedChild {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        let root = tempfile::tempdir().unwrap().keep();
        let history = Arc::new(BuildHistory::new(100));
        let mut children = Vec::new();
        let mut expected = BTreeSet::new();
        for index in 0..2 {
            let ready = root.join(format!("hook-{index}-ready"));
            let child = OwnedChild(
                std::process::Command::new("/bin/sh")
                    .args([
                        "-c",
                        "trap '' TERM; printf ready > \"$1\"; exec /bin/sleep 60",
                        "bulk-owned-hook",
                    ])
                    .arg(&ready)
                    .spawn()
                    .unwrap(),
            );
            tokio::time::timeout(Duration::from_secs(3), async {
                while std::fs::read(&ready).ok().as_deref() != Some(b"ready") {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap();
            let build = history.start_active_build(
                format!("owned-bulk-hook-{index}"),
                "no-remote-work".to_owned(),
                "fixture".to_owned(),
                child.0.id(),
                0,
                BuildLocation::Remote,
            );
            expected.insert(build.id);
            children.push(child);
        }
        let sentinel = OwnedChild(
            std::process::Command::new("/bin/sleep")
                .arg("60")
                .spawn()
                .unwrap(),
        );
        let context = make_test_context(WorkerPool::new(), history.clone());
        let owner = CancellationOrchestrator::new(
            CancellationConfig {
                grace_period: Duration::from_secs(1),
                kill_timeout: Duration::from_secs(1),
                ..test_config()
            },
            test_events(),
        );
        let caller_owner = owner.clone();
        let caller =
            tokio::spawn(async move { caller_owner.cancel_all_builds(&context, false).await });
        wait_for_attempt_count(&owner, 2).await;
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        let late = history.start_active_build(
            "late-live-sentinel".to_owned(),
            "no-remote-work".to_owned(),
            "fixture".to_owned(),
            sentinel.0.id(),
            0,
            BuildLocation::Remote,
        );
        wait_for_attempt_count(&owner, 0).await;
        for child in &children {
            assert!(
                !crate::cancellation::is_process_alive(child.0.id()),
                "aborting a bulk caller abandoned one of its requested hooks"
            );
        }
        assert!(crate::cancellation::is_process_alive(sentinel.0.id()));
        assert!(history.active_build(late.id).is_some());
        assert_eq!(history.active_builds().len(), 1);
        let completed = history.recent(100);
        assert_eq!(completed.len(), 2);
        assert_eq!(
            completed
                .iter()
                .map(|build| build.id)
                .collect::<BTreeSet<_>>(),
            expected
        );
        assert!(completed.iter().all(|build| {
            build.exit_code == 130
                && build
                    .cancellation
                    .as_ref()
                    .is_some_and(|metadata| metadata.final_state == "completed")
        }));
    }
}
