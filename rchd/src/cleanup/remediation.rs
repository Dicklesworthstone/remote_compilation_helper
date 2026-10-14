//! Automatic cancellation retries; never ownership or termination authority.
//!
//! An unwritable worker registry can make cancellation fail indefinitely
//! (bd-5ojmb). Retrying every observer tick only adds load and warnings. Keep
//! retry state separate from history, and always revalidate current evidence.

use super::{ActiveBuildCleanup, ObservationWindow, RecoveredQueueCleanup, build_stuck_evidence};
use crate::history::ActiveBuildState;
use std::collections::{HashMap, HashSet, VecDeque};
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::task::Poll;
use std::time::{Duration, Instant};
use tokio::time::{MissedTickBehavior, interval};
use tracing::warn;

mod lease_wakeup;

const RETRY_BASE: Duration = Duration::from_secs(30);
const RETRY_MAX: Duration = Duration::from_secs(5 * 60);
/// Bound both accepted automatic operations and new starts per observer tick.
/// A worker may occupy only one of these lanes. User cancellation is separate.
const MAX_AUTOMATIC_CANCELLATIONS: usize = 4;

/// Immutable attempt identity plus the actual progress observed before it.
/// A resumed/replaced wrapper must not inherit a previous observation's delay
/// or cancellation decision. Never manufacture a heartbeat to implement backoff.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RetryStamp {
    build_id: u64,
    worker_id: String,
    wrapper: Option<String>,
    hook_pid: u32,
    hook_identity: Option<String>,
    started: Instant,
    heartbeat: Instant,
    progress: Instant,
    remote_pgid_file: Option<String>,
    slots: u32,
}

impl RetryStamp {
    fn of(build: &ActiveBuildState) -> Self {
        Self {
            build_id: build.id,
            worker_id: build.worker_id.clone(),
            wrapper: build.local_wrapper_id.clone(),
            hook_pid: build.hook_pid,
            hook_identity: build.hook_process_identity.clone(),
            started: build.started_at_mono,
            heartbeat: build.last_heartbeat_mono,
            progress: build.last_progress_mono,
            remote_pgid_file: build.remote_pgid_file.clone(),
            slots: build.slots,
        }
    }
}

struct FailedAttempt {
    stamp: RetryStamp,
    finished: Instant,
    delay: Duration,
    lease: Option<lease_wakeup::LeaseStamp>,
}

#[derive(Default)]
struct RetryBackoff {
    failures: HashMap<u64, FailedAttempt>,
}

impl RetryBackoff {
    fn ready(&mut self, stamp: &RetryStamp, now: Instant) -> bool {
        if !self.failures.contains_key(&stamp.build_id) {
            return true;
        }
        self.ready_after_lease_observation(stamp, now, lease_wakeup::observe(stamp))
    }

    fn ready_after_lease_observation(
        &mut self,
        stamp: &RetryStamp,
        now: Instant,
        lease: Option<lease_wakeup::LeaseStamp>,
    ) -> bool {
        let Some(previous) = self.failures.get(&stamp.build_id) else {
            return true;
        };
        if previous.stamp != *stamp || lease_wakeup::changed(&previous.lease, &lease) {
            self.failures.remove(&stamp.build_id);
            return true;
        }
        now.saturating_duration_since(previous.finished) >= previous.delay
    }

    #[cfg(test)]
    fn failed(&mut self, stamp: RetryStamp, now: Instant) -> Duration {
        let lease = lease_wakeup::observe(&stamp);
        self.failed_with_lease(stamp, now, lease)
    }

    fn failed_with_lease(
        &mut self,
        stamp: RetryStamp,
        now: Instant,
        lease: Option<lease_wakeup::LeaseStamp>,
    ) -> Duration {
        let delay = self
            .failures
            .get(&stamp.build_id)
            .filter(|previous| previous.stamp == stamp)
            .map_or(RETRY_BASE, |previous| {
                previous.delay.saturating_mul(2).min(RETRY_MAX)
            });
        self.failures.insert(
            stamp.build_id,
            FailedAttempt {
                lease,
                stamp,
                finished: now,
                delay,
            },
        );
        delay
    }

    fn retain_active(&mut self, active: &[ActiveBuildState]) {
        let ids: HashSet<u64> = active.iter().map(|build| build.id).collect();
        self.failures.retain(|id, _| ids.contains(id));
    }
}

/// Do not reuse a decision across a queue wait, a peer's cancellation, or a
/// heartbeat. This does not adopt a current worker endpoint or grant any right
/// to signal a PID; the cancellation orchestrator retains those checks.
pub(super) fn fresh_candidate(
    cleanup: &ActiveBuildCleanup,
    planned: &ActiveBuildState,
    observation: &mut ObservationWindow,
) -> Option<ActiveBuildState> {
    if cleanup.context.history.ownership_failed() {
        return None;
    }
    let current = cleanup.context.history.active_build(planned.id)?;
    if RetryStamp::of(&current) != RetryStamp::of(planned) {
        return None;
    }
    let now = Instant::now();
    let recovering = observation.recovering_build(now, current.recovered);
    build_stuck_evidence(&current, now)
        .should_remediate_after_observation(recovering)
        .then_some(current)
}

fn record_outcome(
    cleanup: &ActiveBuildCleanup,
    backoff: &mut RetryBackoff,
    attempted: RetryStamp,
    status: &str,
    lease_before: Option<lease_wakeup::LeaseStamp>,
) {
    // The retry controller never removes a build or releases a slot. Absence
    // only retires our local timer; the orchestrator owns durable completion.
    let current = cleanup.context.history.active_build(attempted.build_id);
    if current.as_ref().map(RetryStamp::of).as_ref() != Some(&attempted) {
        backoff.failures.remove(&attempted.build_id);
        return;
    }
    let id = attempted.build_id;
    let worker = attempted.worker_id.clone();
    let recovery_hint = lease_wakeup::recovery_hint(&attempted);
    // Watch from BEFORE the operation: recovery that races with a failed
    // cancellation must not disappear behind a newly established deadline.
    let delay = backoff.failed_with_lease(attempted, Instant::now(), lease_before);
    warn!(
        build_id = id,
        worker_id = %worker,
        status,
        retry_after_secs = delay.as_secs(),
        recovery_hint = ?recovery_hint,
        "Automatic cancellation unconfirmed; ownership retained and retry deferred"
    );
    cleanup.context.events.emit(
        "stuck_detector_retry_scheduled",
        &serde_json::json!({
            "build_id_text": id.to_string(),
            "worker_id": worker,
            "status": status,
            "retry_after_secs": delay.as_secs(),
            "recovery_hint": recovery_hint,
        }),
    );
}

/// Poll a small bounded set in the observer itself, rather than spawning a
/// second task that could first admit a cancellation AFTER observer shutdown.
/// Dropping this set drops only waiters. The cancellation orchestrator still
/// owns termination/finalization of operations it has already admitted.
struct InFlight {
    stamp: RetryStamp,
    lease_before: Option<lease_wakeup::LeaseStamp>,
    wait: Pin<Box<dyn Future<Output = Option<String>> + Send>>,
}

#[derive(Default)]
struct Remediations {
    running: Vec<InFlight>,
    pending: VecDeque<u64>,
}

impl Remediations {
    fn can_start(&self, stamp: &RetryStamp) -> bool {
        self.running.len() < MAX_AUTOMATIC_CANCELLATIONS
            && !self.running.iter().any(|flight| {
                flight.stamp.build_id == stamp.build_id || flight.stamp.worker_id == stamp.worker_id
            })
    }

    fn push(
        &mut self,
        stamp: RetryStamp,
        wait: impl Future<Output = Option<String>> + Send + 'static,
    ) -> bool {
        if !self.can_start(&stamp) {
            return false;
        }
        self.running.push(InFlight {
            lease_before: lease_wakeup::observe(&stamp),
            stamp,
            wait: Box::pin(wait),
        });
        true
    }

    async fn next_completed(
        &mut self,
    ) -> (RetryStamp, Option<String>, Option<lease_wakeup::LeaseStamp>) {
        // At most four polls; all waits share this task's waker. A ready peer
        // is collected even when the oldest worker never wakes. Cancellation
        // of this poll by a timer tick leaves every owned future in the set.
        poll_fn(|cx| {
            for index in 0..self.running.len() {
                if let Poll::Ready(status) = self.running[index].wait.as_mut().poll(cx) {
                    let flight = self.running.swap_remove(index);
                    return Poll::Ready((flight.stamp, status, flight.lease_before));
                }
            }
            Poll::Pending
        })
        .await
    }

    fn start_observed(
        &mut self,
        cleanup: &ActiveBuildCleanup,
        observation: &mut ObservationWindow,
        backoff: &mut RetryBackoff,
        mut candidates: Vec<ActiveBuildState>,
    ) {
        // Retain only scheduling order, never a stale build snapshot. Waiting
        // IDs precede previously attempted IDs reintroduced by the next scan,
        // so two jobs sharing a worker cannot starve one another behind an
        // always-failing prefix. New IDs enter in deterministic order.
        candidates.sort_by_key(|build| build.id);
        let current_ids: HashSet<u64> = candidates.iter().map(|build| build.id).collect();
        self.pending.retain(|id| current_ids.contains(id));
        let mut queued: HashSet<u64> = self.pending.iter().copied().collect();
        queued.extend(self.running.iter().map(|flight| flight.stamp.build_id));
        for build in &candidates {
            if queued.insert(build.id) {
                self.pending.push_back(build.id);
            }
        }
        let current: HashMap<u64, ActiveBuildState> = candidates
            .into_iter()
            .map(|build| (build.id, build))
            .collect();
        let mut starts = 0;
        // Examine each queued ID at most once. A busy/backed-off worker goes
        // around the queue without spinning or blocking a disjoint peer.
        for _ in 0..self.pending.len() {
            if starts == MAX_AUTOMATIC_CANCELLATIONS
                || self.running.len() == MAX_AUTOMATIC_CANCELLATIONS
            {
                break;
            }
            let id = self.pending.pop_front().expect("bounded pending iteration");
            let planned = &current[&id];
            let stamp = RetryStamp::of(planned);
            if !self.can_start(&stamp) || !backoff.ready(&stamp, Instant::now()) {
                self.pending.push_back(id);
                continue;
            }
            let Some(build) = fresh_candidate(cleanup, planned, observation) else {
                continue;
            };
            let owner = ActiveBuildCleanup::new(cleanup.context.clone());
            let mut admission_observation = ObservationWindow {
                last_observed: observation.last_observed,
                recover_until: observation.recover_until,
                startup_until: observation.startup_until,
            };
            // Recheck when the future is FIRST POLLED too: a heartbeat or an
            // observer pause may have occurred since this future was queued.
            // There is then no await before cancel_build's synchronous admission.
            let wait = async move {
                let current = fresh_candidate(&owner, &build, &mut admission_observation)?;
                let response = owner
                    .context
                    .cancellation
                    .cancel_build(
                        &owner.context,
                        current.id,
                        crate::cancellation::CancelReason::StuckDetector,
                        false,
                    )
                    .await;
                Some(response.status)
            };
            if self.push(stamp, wait) {
                starts += 1;
            }
        }
    }
}

pub(super) async fn run(cleanup: ActiveBuildCleanup) {
    let mut ticker = interval(Duration::from_secs(5));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut observation = ObservationWindow::for_startup(Instant::now());
    let mut recovered_queue = RecoveredQueueCleanup::default();
    let mut backoff = RetryBackoff::default();
    let mut flights = Remediations::default();
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                // Neither remote termination nor another worker's backoff may
                // delay queued-owner retirement or fresh stuck observations.
                recovered_queue.check(&cleanup.context);
                backoff.retain_active(&cleanup.context.history.active_builds());
                let candidates = cleanup.collect_active_builds_observed(&mut observation);
                flights.start_observed(&cleanup, &mut observation, &mut backoff, candidates);
            }
            (attempted, status, lease_before) = flights.next_completed(), if !flights.running.is_empty() => {
                if let Some(status) = status {
                    record_outcome(&cleanup, &mut backoff, attempted, &status, lease_before);
                } else {
                    // Fresh evidence vetoed this decision before any operation
                    // was admitted. It is not a failed cancellation or a receipt.
                    backoff.failures.remove(&attempted.build_id);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stamp(now: Instant, id: u64) -> RetryStamp {
        RetryStamp {
            build_id: id,
            worker_id: "worker".into(),
            wrapper: Some(format!("wrapper-{id}")),
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
    fn retry_delays_start_at_completion_and_double_to_a_finite_cap() {
        let start = Instant::now();
        let observed = stamp(start, 1);
        let mut retry = RetryBackoff::default();
        assert!(retry.ready(&observed, start));
        let mut finished = start + Duration::from_secs(120);
        for seconds in [30, 60, 120, 240, 300, 300, 300] {
            let delay = retry.failed(observed.clone(), finished);
            assert_eq!(delay, Duration::from_secs(seconds));
            assert!(!retry.ready(&observed, finished));
            assert!(!retry.ready(&observed, finished + delay - Duration::from_nanos(1)));
            assert!(retry.ready(&observed, finished + delay));
            finished += delay;
        }
    }

    #[test]
    fn observer_ticks_do_not_extend_the_retry_deadline() {
        let now = Instant::now();
        let observed = stamp(now, 1);
        let mut retry = RetryBackoff::default();
        retry.failed(observed.clone(), now);
        for seconds in [0, 5, 10, 15, 20, 25] {
            assert!(!retry.ready(&observed, now + Duration::from_secs(seconds)));
        }
        assert!(retry.ready(&observed, now + RETRY_BASE));
        assert_eq!(retry.failures[&1].finished, now);
    }

    #[test]
    fn new_progress_or_execution_identity_discards_old_retry_state() {
        let now = Instant::now();
        let original = stamp(now, 1);
        let mut changed = Vec::new();
        let mut next = original.clone();
        next.heartbeat += Duration::from_nanos(1);
        changed.push(next);
        let mut next = original.clone();
        next.progress += Duration::from_nanos(1);
        changed.push(next);
        let mut next = original.clone();
        next.started += Duration::from_nanos(1);
        changed.push(next);
        let mut next = original.clone();
        next.worker_id = "other-worker".into();
        changed.push(next);
        let mut next = original.clone();
        next.wrapper = Some("replacement-wrapper".into());
        changed.push(next);
        let mut next = original.clone();
        next.hook_identity = Some("replacement-birth".into());
        changed.push(next);
        let mut next = original.clone();
        next.hook_pid = 42;
        changed.push(next);
        let mut next = original.clone();
        next.remote_pgid_file = Some("/new-record".into());
        changed.push(next);
        let mut next = original.clone();
        next.slots = 2;
        changed.push(next);
        for next in changed {
            let mut retry = RetryBackoff::default();
            retry.failed(original.clone(), now);
            retry.failed(original.clone(), now);
            assert!(retry.ready(&next, now));
            assert!(retry.failures.is_empty());
            assert_eq!(retry.failed(next, now), RETRY_BASE);
        }
    }

    #[test]
    fn failed_build_does_not_delay_other_builds_or_rewrite_its_observation() {
        let now = Instant::now();
        let original = stamp(now, 1);
        let mut retry = RetryBackoff::default();
        retry.failed(original.clone(), now);
        assert!(retry.ready(&stamp(now, 2), now));
        assert_eq!(retry.failures[&1].stamp, original);
        assert!(!retry.ready(&original, now - Duration::from_secs(1)));
    }

    #[test]
    fn terminal_builds_do_not_leave_unbounded_retry_timers() {
        let now = Instant::now();
        let mut retry = RetryBackoff::default();
        for id in 1..100 {
            retry.failed(stamp(now, id), now);
        }
        retry.retain_active(&[]);
        assert!(retry.failures.is_empty());
    }

    #[tokio::test]
    async fn unconfirmed_response_keeps_real_history_and_slots() {
        let pool = crate::workers::WorkerPool::new();
        let worker_id = rch_common::WorkerId::new("retry-retains-ownership");
        pool.add_worker(rch_common::WorkerConfig {
            id: worker_id.clone(),
            total_slots: 4,
            ..Default::default()
        })
        .await;
        let worker = pool.get(&worker_id).await.unwrap();
        assert!(worker.reserve_slots(3).await);
        let context = crate::test_daemon_context(pool);
        let build = context.history.start_active_build(
            "retry-project".into(),
            worker_id.to_string(),
            "cargo check".into(),
            0,
            2,
            rch_common::BuildLocation::Remote,
        );
        let cleanup = ActiveBuildCleanup::new(context.clone());
        let before = serde_json::to_value(&build).unwrap();
        let mut retry = RetryBackoff::default();
        for status in ["failed", "cancelling", "error", "cancelled"] {
            record_outcome(&cleanup, &mut retry, RetryStamp::of(&build), status, None);
            let retained = context.history.active_build(build.id).unwrap();
            assert_eq!(serde_json::to_value(retained).unwrap(), before);
            assert_eq!(worker.used_slots(), 3);
            assert!(!context.history.has_terminal_build(build.id));
            assert!(!retry.ready(&RetryStamp::of(&build), Instant::now()));
        }
    }

    #[tokio::test]
    async fn fresh_heartbeat_invalidates_a_planned_cancellation() {
        let context = crate::test_daemon_context(crate::workers::WorkerPool::new());
        let build = context.history.start_active_build(
            "resumed-project".into(),
            "resumed-worker".into(),
            "cargo check".into(),
            0,
            1,
            rch_common::BuildLocation::Remote,
        );
        let cleanup = ActiveBuildCleanup::new(context.clone());
        let mut stale = build.clone();
        stale.last_heartbeat_mono -= Duration::from_secs(120);
        stale.last_progress_mono -= Duration::from_secs(120);
        stale.started_at_mono -= Duration::from_secs(120);
        assert!(fresh_candidate(&cleanup, &stale, &mut ObservationWindow::default()).is_none());
        assert!(fresh_candidate(&cleanup, &build, &mut ObservationWindow::default()).is_none());
        assert!(context.history.active_build(build.id).is_some());
        assert!(context.cancellation.active_cancellations().await.is_empty());
    }
}

#[cfg(test)]
mod concurrency_tests;
