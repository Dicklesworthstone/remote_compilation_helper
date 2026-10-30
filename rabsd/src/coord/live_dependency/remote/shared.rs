//! Service-owned remote execution and independent subscriber delivery.
//!
//! An offer claims no physical worker. Its exact wrapper acknowledgment admits
//! bounded FIFO demand; one dispatcher starts a supervised producer when actual
//! capacity becomes available. Other offers may join that open queued or active
//! flight. Losing a subscriber releases only its interest. The service owns and
//! joins the dispatcher and transports after the originating edge exits.

use super::super::shared_work::{
    DeferredLaunch, LaunchStatus, SharedWork, Subscription, WorkError,
};
use super::{
    CoordLive, LiveDependencyRequest, MAX_PENDING_ACTIONS, OperationCancellation, PendingRemote,
    PendingRemoteInstall, RemoteInstallAuthority, RemoteOutput, RemoteResult, RemoteValidation,
    TypedDigest, WorkerProbe,
};
use std::collections::VecDeque;
use std::fmt;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const MAX_SHARED_SUBSCRIBERS: usize = MAX_PENDING_ACTIONS;
const QUEUE_WAIT: Duration = Duration::from_secs(5 * 60);

/// Wakeups carry no queue, supervisor or native thread ownership. A version
/// recorded before probing capacity prevents release/cancel/complete events
/// from being lost between a failed probe and the dispatcher's bounded wait.
#[derive(Debug, Default)]
pub(super) struct QueueSignal {
    version: Mutex<u64>,
    changed: Condvar,
}

impl QueueSignal {
    pub(super) fn notify(&self) {
        let mut version = self
            .version
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        *version = version.wrapping_add(1);
        self.changed.notify_all();
    }

    pub(super) fn version(&self) -> u64 {
        *self
            .version
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }

    pub(super) fn wait(&self, observed: u64, deadline: Option<Instant>) {
        let mut version = self
            .version
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        while *version == observed {
            version = if let Some(deadline) = deadline {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return;
                }
                let (next, timeout) = self
                    .changed
                    .wait_timeout(version, remaining)
                    .unwrap_or_else(|error| error.into_inner());
                if timeout.timed_out() {
                    return;
                }
                next
            } else {
                self.changed
                    .wait(version)
                    .unwrap_or_else(|error| error.into_inner())
            };
        }
    }
}

struct QueuedRemote {
    pending: Option<PendingRemote>,
    launch: DeferredLaunch<TypedDigest, SharedRemoteResult>,
    cancellation: OperationCancellation,
    deadline: Instant,
}

#[derive(Default)]
struct QueueState {
    closed: bool,
    pending: VecDeque<QueuedRemote>,
}

#[derive(Default)]
struct QueueCore {
    state: Mutex<QueueState>,
    signal: Arc<QueueSignal>,
}

#[derive(Default)]
struct Dispatcher {
    worker: Option<JoinHandle<()>>,
    failure: Option<String>,
}

/// The canonical service's bounded owner of all shared remote producer threads.
/// Keep this separate from `RemoteDependencies`: producers retain the worker
/// pool, and must never retain their own thread registry through that pool.
pub struct SharedRemoteExecutions {
    work: Arc<SharedWork<TypedDigest, SharedRemoteResult>>,
    queue: Arc<QueueCore>,
    dispatcher: Mutex<Dispatcher>,
}

impl fmt::Debug for SharedRemoteExecutions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SharedRemoteExecutions")
            .finish_non_exhaustive()
    }
}

impl SharedRemoteExecutions {
    /// One execution owner per configured worker and one service-wide bound on
    /// retained subscribers, including offers awaiting their acknowledgment.
    #[must_use]
    pub fn new(worker_count: usize) -> Arc<Self> {
        let queue = Arc::new(QueueCore::default());
        let signal = Arc::downgrade(&queue.signal);
        Arc::new(Self {
            work: Arc::new(
                SharedWork::new(worker_count, MAX_SHARED_SUBSCRIBERS).with_notify(move || {
                    if let Some(signal) = signal.upgrade() {
                        signal.notify();
                    }
                }),
            ),
            queue,
            dispatcher: Mutex::new(Dispatcher::default()),
        })
    }

    /// Seal new work and membership, cancel active actions, then join every
    /// producer before the service releases coordinator or filesystem custody.
    pub fn shutdown(&self) -> Result<(), String> {
        // This lock serializes admission with close and concurrent shutdowns.
        // The dispatcher never acquires it, so joining cannot deadlock it.
        let mut dispatcher = self
            .dispatcher
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        self.queue
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .closed = true;
        self.queue.signal.notify();
        if let Some(worker) = dispatcher.worker.take()
            && worker.join().is_err()
        {
            dispatcher.failure = Some("shared remote queue dispatcher panicked".into());
        }
        let workers = self
            .work
            .shutdown()
            .map_err(|error| format!("shared remote execution shutdown: {error}"));
        if let Some(failure) = &dispatcher.failure {
            return Err(failure.clone());
        }
        workers
    }

    pub(super) fn try_join(&self, key: &TypedDigest) -> Option<Subscription<SharedRemoteResult>> {
        // Serialize membership with queue closure. This short supervisor call
        // only enrolls interest; it never reaps, prepares, spawns or calls user
        // code while the queue lock is held.
        let queue = self
            .queue
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if queue.closed {
            return None;
        }
        self.work.try_join(key)
    }

    fn enqueue(&self, pending: PendingRemote) -> Result<Subscription<SharedRemoteResult>, String> {
        if pending.reservation.is_some() {
            return Err("queued remote action already owns a worker".into());
        }
        let mut dispatcher = self
            .dispatcher
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if self
            .queue
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .closed
        {
            return Err("shared remote execution queue is closed".into());
        }
        if dispatcher
            .worker
            .as_ref()
            .is_some_and(JoinHandle::is_finished)
        {
            return Err("shared remote queue dispatcher stopped".into());
        }
        if dispatcher.worker.is_none() {
            let work = Arc::clone(&self.work);
            let queue = Arc::clone(&self.queue);
            dispatcher.worker = Some(
                std::thread::Builder::new()
                    .name("rabs-remote-dispatch".into())
                    .spawn(move || dispatch(work, queue))
                    .map_err(|error| format!("start shared remote queue: {error}"))?,
            );
        }
        let deadline = Instant::now()
            .checked_add(QUEUE_WAIT)
            .ok_or("shared remote queue deadline overflow")?;
        pending
            .remote
            .workers
            .availability
            .watch(&self.queue.signal);
        let cancellation = OperationCancellation::new();
        let cancel = cancellation.clone();
        let signal = Arc::downgrade(&self.queue.signal);
        let (subscription, launch) = self
            .work
            .defer(pending.action_key().clone(), move || {
                cancel.cancel();
                if let Some(signal) = signal.upgrade() {
                    signal.notify();
                }
            })
            .map_err(|error| format!("shared remote queue admission: {error}"))?;
        let mut queue = self
            .queue
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if queue.closed {
            return Err("shared remote execution queue closed during admission".into());
        }
        queue.pending.push_back(QueuedRemote {
            pending: Some(pending),
            launch,
            cancellation,
            deadline,
        });
        drop(queue);
        self.queue.signal.notify();
        Ok(subscription)
    }
}

impl Drop for SharedRemoteExecutions {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

fn failed_before_start(reason: impl Into<String>) -> SharedRemoteResult {
    SharedRemoteResult::Failed {
        reason: reason.into(),
        execution_finished: true,
    }
}

/// Even an unexpected dispatcher unwind resolves every dormant flight. Active
/// producers remain owned by SharedWork and are joined by service shutdown.
struct QueueOwner {
    queue: Arc<QueueCore>,
    work: Arc<SharedWork<TypedDigest, SharedRemoteResult>>,
}

impl Drop for QueueOwner {
    fn drop(&mut self) {
        let pending = {
            let mut queue = self
                .queue
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            queue.closed = true;
            std::mem::take(&mut queue.pending)
        };
        for mut queued in pending {
            queued.cancellation.cancel();
            let _ = self.work.finish_deferred(
                &mut queued.launch,
                failed_before_start("shared remote service stopped before worker admission"),
            );
        }
        self.queue.signal.notify();
    }
}

fn dispatch(work: Arc<SharedWork<TypedDigest, SharedRemoteResult>>, queue: Arc<QueueCore>) {
    let owner = QueueOwner { queue, work };
    loop {
        let observed = owner.queue.signal.version();
        let pending = {
            let mut state = owner
                .queue
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if state.closed {
                return;
            }
            std::mem::take(&mut state.pending)
        };
        let mut retained = VecDeque::new();
        let mut blocked = false;
        let mut deadline: Option<Instant> = None;
        for mut queued in pending {
            if owner
                .queue
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .closed
            {
                retained.push_back(queued);
                continue;
            }
            if queued.cancellation.is_cancelled() || !queued.launch.is_pending() {
                continue;
            }
            if Instant::now() >= queued.deadline {
                let _ = owner.work.finish_deferred(
                    &mut queued.launch,
                    failed_before_start(
                        "shared remote worker queue exceeded its five-minute budget",
                    ),
                );
                continue;
            }
            deadline = Some(deadline.map_or(queued.deadline, |at| at.min(queued.deadline)));
            if blocked {
                retained.push_back(queued);
                continue;
            }
            let remote = Arc::clone(&queued.pending.as_ref().expect("queued input owner").remote);
            let mut pool_error = None;
            let mut worker_deadline = None;
            let result = owner.work.try_launch(&mut queued.launch, || {
                if owner
                    .queue
                    .state
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .closed
                {
                    return None;
                }
                match remote.workers.probe_worker() {
                    Ok(WorkerProbe::Reserved(reservation)) => {
                        let mut pending = queued.pending.take().expect("queued input owner");
                        pending.reservation = Some(reservation);
                        let cancellation = queued.cancellation.clone();
                        Some(move || SharedRemoteResult::from_remote(pending.execute(cancellation)))
                    }
                    Ok(WorkerProbe::Waiting(deadline)) => {
                        worker_deadline = deadline;
                        None
                    }
                    Err(error) => {
                        pool_error = Some(error);
                        None
                    }
                }
            });
            match result {
                Ok(LaunchStatus::Started | LaunchStatus::CancelledBeforeStart) => {}
                Ok(LaunchStatus::Blocked) => {
                    if let Some(error) = pool_error {
                        let _ = owner.work.finish_deferred(
                            &mut queued.launch,
                            failed_before_start(format!("shared remote worker admission: {error}")),
                        );
                    } else {
                        if let Some(ready) = worker_deadline {
                            deadline = Some(deadline.map_or(ready, |at| at.min(ready)));
                        }
                        blocked = true;
                        retained.push_back(queued);
                    }
                }
                Err(error) => {
                    let _ = owner.work.finish_deferred(
                        &mut queued.launch,
                        failed_before_start(format!("shared remote dispatch: {error}")),
                    );
                }
            }
        }
        {
            let mut state = owner
                .queue
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            // New arrivals stay behind the retained FIFO cohort. No queue lock
            // is held during preparation, native spawn, reaping or callbacks.
            retained.append(&mut state.pending);
            state.pending = retained;
            if state.closed {
                return;
            }
        }
        owner.queue.signal.wait(observed, deadline);
    }
}

/// This capability can only be constructed from the current producer's
/// successful H011 publication. It contains no arbitrary-key lookup path and
/// cannot contain an affine workspace result. Terminal flights reject joins.
#[derive(Debug)]
pub(super) enum SharedRemoteResult {
    Published(Arc<RemoteOutput>),
    Failed {
        reason: String,
        execution_finished: bool,
    },
}

impl SharedRemoteResult {
    fn from_remote(result: RemoteResult) -> Self {
        match result {
            RemoteResult::Failed {
                reason,
                execution_finished,
            } => Self::Failed {
                reason,
                execution_finished,
            },
            RemoteResult::Ready(ready) => {
                if ready.request.is_execution_only() {
                    return Self::Failed {
                        reason: "fresh workspace execution cannot enter a shared result flight"
                            .into(),
                        execution_finished: true,
                    };
                }
                if let Err(reason) = ready.output.verify_binding(&ready.request) {
                    return Self::Failed {
                        reason,
                        execution_finished: true,
                    };
                }
                match ready.result.into_shared_output(ready.output) {
                    Ok(output) => Self::Published(output),
                    Err(reason) => Self::Failed {
                        reason,
                        execution_finished: true,
                    },
                }
            }
        }
    }
}

#[derive(Debug)]
struct SubscriberRequest {
    coord: Arc<CoordLive>,
    request: LiveDependencyRequest,
    validation: RemoteValidation,
}

impl SubscriberRequest {
    fn ready(self, output: Arc<RemoteOutput>) -> RemoteResult {
        if self.request.is_execution_only() {
            return RemoteResult::Failed {
                reason: "workspace requests require their own fresh remote execution".into(),
                execution_finished: true,
            };
        }
        if let Err(reason) = output.verify_binding(&self.request) {
            return RemoteResult::Failed {
                reason,
                execution_finished: true,
            };
        }
        // No filesystem work or target authority is exercised by this wait.
        // The acknowledged installation thread revalidates THIS request's
        // witnesses and uses THIS request's destination and presentation.
        RemoteResult::Ready(PendingRemoteInstall {
            coord: self.coord,
            request: self.request,
            output,
            validation: self.validation,
            result: RemoteInstallAuthority::Published,
        })
    }
}

enum Offer {
    Start {
        executions: Arc<SharedRemoteExecutions>,
        pending: Box<PendingRemote>,
    },
    Joined(Subscription<SharedRemoteResult>),
}

/// An unaccepted private-execution offer. Dropping a starter releases its key
/// claim without reserving a worker or starting a flight; dropping a follower
/// removes only its enrolled interest. Neither authorizes output writes.
pub struct PendingSharedRemote {
    subscriber: SubscriberRequest,
    offer: Offer,
}

impl fmt::Debug for PendingSharedRemote {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingSharedRemote")
            .field("action_key", self.action_key())
            .finish_non_exhaustive()
    }
}

impl PendingSharedRemote {
    pub(super) fn starter(executions: Arc<SharedRemoteExecutions>, pending: PendingRemote) -> Self {
        let subscriber = SubscriberRequest {
            coord: Arc::clone(&pending.lane.coord),
            request: pending.request.clone(),
            validation: pending.invocation.validation.clone(),
        };
        Self {
            subscriber,
            offer: Offer::Start {
                executions,
                pending: Box::new(pending),
            },
        }
    }

    pub(super) fn joined(
        coord: Arc<CoordLive>,
        request: LiveDependencyRequest,
        validation: RemoteValidation,
        subscription: Subscription<SharedRemoteResult>,
    ) -> Self {
        Self {
            subscriber: SubscriberRequest {
                coord,
                request,
                validation,
            },
            offer: Offer::Joined(subscription),
        }
    }

    #[must_use]
    pub fn action_key(&self) -> &TypedDigest {
        &self.subscriber.request.key.action_key
    }

    /// Consume only after the exact action's `rustc-remote-accept` frame.
    /// A follower uses its already enrolled membership, even if the producer
    /// completed between the offer and this acknowledgment. No new member can
    /// join a terminal flight or reuse its current-producer privilege later.
    pub fn accept(self) -> Result<SharedRemoteSubscription, String> {
        let Self { subscriber, offer } = self;
        if subscriber.request.is_execution_only() {
            return Err("workspace execution cannot accept a shared remote offer".into());
        }
        let (work, disposition) = match offer {
            Offer::Joined(subscription) => (subscription, "joined"),
            Offer::Start {
                executions,
                pending,
            } => (executions.enqueue(*pending)?, "queued"),
        };
        let key = rabs_cas::metadata_store::digest_key(&subscriber.request.key.action_key);
        crate::edge::server::log_line(
            "rabsd-shared-remote-subscribed",
            &[("key", &key), ("disposition", disposition)],
        );
        Ok(SharedRemoteSubscription {
            subscriber: Some(subscriber),
            work,
        })
    }
}

/// One caller's interest and immutable input witnesses. It owns no worker
/// transport and cannot cancel another caller's demand. Drop removes only this
/// membership; the supervisor signals cancellation when the last one leaves.
pub struct SharedRemoteSubscription {
    subscriber: Option<SubscriberRequest>,
    work: Subscription<SharedRemoteResult>,
}

impl fmt::Debug for SharedRemoteSubscription {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SharedRemoteSubscription")
            .field(
                "action_key",
                &self
                    .subscriber
                    .as_ref()
                    .map(|subscriber| &subscriber.request.key.action_key),
            )
            .finish_non_exhaustive()
    }
}

impl SharedRemoteSubscription {
    /// Return at most one private installation offer for this subscriber. A
    /// producer panic retains uncertain execution semantics; it never grants
    /// local retry merely because its native thread has returned.
    pub async fn wait(&mut self) -> RemoteResult {
        let outcome = self.work.wait().await;
        let Some(subscriber) = self.subscriber.take() else {
            return RemoteResult::Failed {
                reason: "shared remote subscriber result already consumed".into(),
                // A prior delivery may still own a writer, or the first
                // result may have reported uncertain remote execution.
                execution_finished: false,
            };
        };
        match outcome {
            Ok(result) => match result.as_ref() {
                SharedRemoteResult::Published(output) => subscriber.ready(Arc::clone(output)),
                SharedRemoteResult::Failed {
                    reason,
                    execution_finished,
                } => RemoteResult::Failed {
                    reason: reason.clone(),
                    execution_finished: *execution_finished,
                },
            },
            Err(error) => RemoteResult::Failed {
                reason: format!("shared remote execution owner failed: {error}"),
                execution_finished: error == WorkError::CancelledBeforeStart,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::request_owned_tests::Fixture;
    use super::*;
    use std::future::Future;
    use std::pin::pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::task::{Context, Poll, Wake, Waker};
    use std::time::{Duration, Instant};

    struct ThreadWake(std::thread::Thread);

    impl Wake for ThreadWake {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }

    fn wait<T>(future: impl Future<Output = T>) -> T {
        let mut future = pin!(future);
        let waker = Waker::from(Arc::new(ThreadWake(std::thread::current())));
        let mut context = Context::from_waker(&waker);
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(result) => return result,
                Poll::Pending => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    assert!(
                        !remaining.is_zero(),
                        "shared remote result did not complete"
                    );
                    std::thread::park_timeout(remaining);
                }
            }
        }
    }

    #[test]
    fn release_between_capacity_probe_and_wait_is_not_lost() {
        let signal = QueueSignal::default();
        let before_probe = signal.version();
        signal.notify();
        // The production wait may have no upcoming cooldown. A versioned wait
        // must observe this already-issued wake instead of sleeping until its
        // fallback deadline without another capacity change.
        let deadline = Instant::now() + Duration::from_secs(5);
        signal.wait(before_probe, Some(deadline));
        assert!(Instant::now() < deadline, "the earlier release was lost");
        assert_ne!(signal.version(), before_probe);
    }

    #[test]
    fn queued_deadline_settles_surviving_members_without_starting_a_producer() {
        let executions = SharedRemoteExecutions::new(1);
        let key = rabs_key::typed_digest::compute("rabs.test.queued-deadline.v1", b"action");
        let cancellation = OperationCancellation::new();
        let cancel = cancellation.clone();
        let (origin, launch) = executions
            .work
            .defer(key.clone(), move || cancel.cancel())
            .unwrap();
        let mut follower = executions.try_join(&key).unwrap();
        drop(origin);
        assert!(!cancellation.is_cancelled());
        executions
            .queue
            .state
            .lock()
            .unwrap()
            .pending
            .push_back(QueuedRemote {
                // This is deliberately a before-start refusal fixture: an expired
                // dormant flight never dereferences or executes a PendingRemote.
                // No compiler, transport, capture or publication is simulated.
                pending: None,
                launch,
                cancellation,
                deadline: Instant::now(),
            });
        let work = Arc::clone(&executions.work);
        let queue = Arc::clone(&executions.queue);
        executions.dispatcher.lock().unwrap().worker =
            Some(std::thread::spawn(move || dispatch(work, queue)));
        let result = wait(follower.wait()).unwrap();
        assert!(matches!(result.as_ref(), SharedRemoteResult::Failed {
            reason,
            execution_finished: true,
        } if reason.contains("five-minute budget")));
        assert!(executions.try_join(&key).is_none());
        executions.shutdown().unwrap();
        assert!(executions.queue.state.lock().unwrap().pending.is_empty());
        assert!(executions.dispatcher.lock().unwrap().worker.is_none());
    }

    #[test]
    fn dispatcher_owner_settles_dormant_flights_before_releasing_queue_custody() {
        let executions = SharedRemoteExecutions::new(1);
        let key = rabs_key::typed_digest::compute("rabs.test.queued-shutdown.v1", b"action");
        let cancellation = OperationCancellation::new();
        let (mut member, launch) = executions.work.defer(key.clone(), || {}).unwrap();
        executions
            .queue
            .state
            .lock()
            .unwrap()
            .pending
            .push_back(QueuedRemote {
                // Exercise only the real queue owner's dormant cleanup path. An
                // absent execution request makes any accidental dispatch fail.
                pending: None,
                launch,
                cancellation: cancellation.clone(),
                deadline: Instant::now() + QUEUE_WAIT,
            });
        drop(QueueOwner {
            queue: Arc::clone(&executions.queue),
            work: Arc::clone(&executions.work),
        });
        let result = wait(member.wait()).unwrap();
        assert!(matches!(result.as_ref(), SharedRemoteResult::Failed {
            reason,
            execution_finished: true,
        } if reason.contains("stopped before worker admission")));
        assert!(cancellation.is_cancelled());
        let queue = executions.queue.state.lock().unwrap();
        assert!(queue.closed);
        assert!(queue.pending.is_empty());
        drop(queue);
        assert!(executions.try_join(&key).is_none());
        executions.shutdown().unwrap();
    }

    #[test]
    fn completed_remote_cohort_rejects_new_producer_result_subscribers() {
        // Real CAS capture supplies immutable manifest custody. The Published
        // tag is explicit fixture input to exercise cohort membership only;
        // this test does not claim H011 admission, rustc execution or TLS.
        let fixture = Fixture::new();
        let captured = fixture.capture();
        let output = Arc::new(RemoteOutput {
            manifest: captured.manifest().clone(),
            manifest_key: captured.captured.manifest_key.clone(),
            canonical_transcript: vec![b'x'; 64 * 1024],
        });
        let key = output.manifest.action_key.clone();
        let executions = SharedRemoteExecutions::new(1);
        let cancelled = Arc::new(AtomicUsize::new(0));
        let cancel = Arc::clone(&cancelled);
        let produced = Arc::clone(&output);
        let (release, released) = mpsc::sync_channel(1);
        let origin = executions
            .work
            .start(
                key.clone(),
                move || {
                    cancel.fetch_add(1, Ordering::AcqRel);
                },
                move || {
                    released.recv().unwrap();
                    SharedRemoteResult::Published(produced)
                },
            )
            .unwrap();
        let mut survivor = executions.try_join(&key).unwrap();
        let mut other = executions.try_join(&key).unwrap();
        drop(origin);
        assert_eq!(cancelled.load(Ordering::Acquire), 0);
        release.send(()).unwrap();
        let first = wait(survivor.wait()).unwrap();
        let second = wait(other.wait()).unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        let SharedRemoteResult::Published(shared) = first.as_ref() else {
            panic!("the surviving cohort lost its published capture");
        };
        assert!(Arc::ptr_eq(shared, &output));
        // Even while existing members retain the exact producer result, a
        // later request must reenter normal replay/verification policy.
        assert!(executions.try_join(&key).is_none());
        executions.shutdown().unwrap();
        assert!(executions.try_join(&key).is_none());
        drop(survivor);
        drop(other);
        assert_eq!(cancelled.load(Ordering::Acquire), 0);
    }
}
