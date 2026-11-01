//! Service-owned remote execution and independent subscriber delivery.
//!
//! An offer claims no physical worker. Its exact wrapper acknowledgment admits
//! bounded FIFO demand; one dispatcher starts a supervised producer when actual
//! capacity becomes available. Other offers may join that open queued or active
//! flight. Losing a subscriber releases only its interest. The service owns and
//! joins the dispatcher and transports after the originating edge exits.
//! Workspace requests use the same FIFO and capacity bounds, but each has a
//! unique private queue identity and exactly one result owner. Matching action
//! keys never join or replay workspace output; every request executes afresh.

use super::super::shared_work::{
    DeferredLaunch, LaunchStatus, SharedWork, Subscription, WorkError,
};
use super::{
    CoordLive, DependencyWorkerPool, LiveDependencyRequest, MAX_PENDING_ACTIONS,
    OperationCancellation, PendingActionClaim, PendingRemote, PendingRemoteInstall,
    RemoteInstallAuthority, RemoteOutput, RemoteResult, RemoteValidation, RequestOwnedResult,
    TypedDigest, WorkerProbe,
};
use std::collections::{HashSet, VecDeque};
use std::fmt;
use std::io;
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
    launch: DeferredLaunch<FlightKey, SharedRemoteResult>,
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

/// Dependency cohorts can be joined by their exact key. A workspace request's
/// queue identity is private to its sole subscription, even when another
/// request has byte-identical compilation inputs and the same action key.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum FlightKey {
    Dependency(TypedDigest),
    RequestOwned(u64),
}

#[derive(Debug, Default)]
struct RequestBudget {
    state: Mutex<RequestBudgetState>,
}

#[derive(Debug, Default)]
struct RequestBudgetState {
    next: u64,
    live: usize,
}

impl RequestBudget {
    fn reserve(self: &Arc<Self>) -> io::Result<RequestPermit> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("remote request budget lock poisoned"))?;
        if state.live >= MAX_SHARED_SUBSCRIBERS {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "remote request offer and subscription capacity exhausted",
            ));
        }
        let id = state
            .next
            .checked_add(1)
            .ok_or_else(|| io::Error::other("remote request identity exhausted"))?;
        state.next = id;
        state.live += 1;
        Ok(RequestPermit {
            budget: Arc::clone(self),
            id,
        })
    }
}

/// A request reserves service-wide demand before its remote offer is sent.
/// Retain this permit through acceptance and independent result delivery;
/// caller disappearance releases only this request's counted interest.
#[derive(Debug)]
struct RequestPermit {
    budget: Arc<RequestBudget>,
    id: u64,
}

impl RequestPermit {
    fn flight_key(&self, action_key: &TypedDigest, request_owned: bool) -> FlightKey {
        if request_owned {
            FlightKey::RequestOwned(self.id)
        } else {
            FlightKey::Dependency(action_key.clone())
        }
    }
}

impl Drop for RequestPermit {
    fn drop(&mut self) {
        self.budget
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .live -= 1;
    }
}

/// The canonical service's bounded owner of queued remote producer threads.
/// Keep this separate from `RemoteDependencies`: producers retain the worker
/// pool, and must never retain their own thread registry through that pool.
pub struct SharedRemoteExecutions {
    work: Arc<SharedWork<FlightKey, SharedRemoteResult>>,
    queue: Arc<QueueCore>,
    dispatcher: Mutex<Dispatcher>,
    requests: Arc<RequestBudget>,
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
            requests: Arc::new(RequestBudget::default()),
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
        self.work.try_join(&FlightKey::Dependency(key.clone()))
    }

    fn enqueue(
        &self,
        pending: PendingRemote,
        permit: &RequestPermit,
    ) -> Result<Subscription<SharedRemoteResult>, String> {
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
        let flight_key =
            permit.flight_key(pending.action_key(), pending.request.is_execution_only());
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
            .defer(flight_key, move || {
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
    work: Arc<SharedWork<FlightKey, SharedRemoteResult>>,
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

/// Once an earlier request waits for an action key, later requests for that
/// key must wait for the next FIFO pass too. A producer may release its claim
/// between two probes in this pass; that release must not let a later caller
/// overtake the earlier waiter. Unrelated keys can still use spare workers.
#[cfg(test)]
fn probe_in_order(
    waiting_keys: &mut HashSet<TypedDigest>,
    workers: &DependencyWorkerPool,
    key: &TypedDigest,
    claim: &mut Option<PendingActionClaim>,
) -> io::Result<WorkerProbe> {
    probe_in_order_for(waiting_keys, workers, key, claim, None)
}

fn probe_in_order_for(
    waiting_keys: &mut HashSet<TypedDigest>,
    workers: &DependencyWorkerPool,
    key: &TypedDigest,
    claim: &mut Option<PendingActionClaim>,
    requirements: Option<&serde_json::Value>,
) -> io::Result<WorkerProbe> {
    if waiting_keys.contains(key) {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "an earlier queued request is waiting for this action key",
        ));
    }
    let result = workers.probe_claimed_worker_for(key, claim, requirements);
    if result
        .as_ref()
        .is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock)
    {
        waiting_keys.insert(key.clone());
    }
    result
}

fn dispatch(work: Arc<SharedWork<FlightKey, SharedRemoteResult>>, queue: Arc<QueueCore>) {
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
        let mut waiting_keys = HashSet::new();
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
            let mut claim_waiting = false;
            let mut request_waiting = false;
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
                // Acquire no worker while an earlier same-key producer still
                // owns its attempt. Claim release has its own availability
                // wake, including the gap after worker reservation release.
                let pending = queued.pending.as_mut().expect("queued input owner");
                match probe_in_order_for(
                    &mut waiting_keys,
                    &remote.workers,
                    &pending.request.key.action_key,
                    &mut pending.action_claim,
                    Some(&pending.invocation.requirements),
                ) {
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
                    Ok(WorkerProbe::RequestWaiting(deadline)) => {
                        worker_deadline = deadline;
                        request_waiting = true;
                        None
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        claim_waiting = true;
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
                        // A prior same-key producer can occupy only one
                        // worker. Keep that key's FIFO order without forcing
                        // unrelated ready actions to leave other workers idle.
                        // A capability-specific wait also leaves capacity
                        // usable by a different request. Preserve FIFO for
                        // the claimed key while scanning those other actions.
                        blocked = !claim_waiting && !request_waiting;
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

/// Immutable bytes may have several dependency subscribers only after H011
/// publication. An unpublished workspace capture instead retains a single
/// affine owner behind a one-shot take; its private flight cannot be joined.
#[derive(Debug)]
pub(super) struct RequestOwnedOutput {
    output: Arc<RemoteOutput>,
    result: Mutex<Option<Box<RequestOwnedResult>>>,
}

impl RequestOwnedOutput {
    fn new(output: Arc<RemoteOutput>, result: Box<RequestOwnedResult>) -> Result<Self, String> {
        result.verify_binding(&output.manifest.action_key, &output.manifest_key)?;
        if result.manifest() != &output.manifest {
            return Err("request-owned queued result differs from its captured manifest".into());
        }
        Ok(Self {
            output,
            result: Mutex::new(Some(result)),
        })
    }

    fn take(&self) -> Result<Box<RequestOwnedResult>, String> {
        self.result
            .lock()
            .map_err(|_| "request-owned remote result lock poisoned")?
            .take()
            .ok_or_else(|| "request-owned remote result already consumed".into())
    }
}

/// A current producer's result, never an arbitrary-key cache lookup. Shared
/// publication and one-shot workspace custody remain separate alternatives.
/// Terminal flights reject joins, and private workspace flights never admit
/// followers even while queued or executing.
#[derive(Debug)]
pub(super) enum SharedRemoteResult {
    Published(Arc<RemoteOutput>),
    RequestOwned(RequestOwnedOutput),
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
                if let Err(reason) = ready.output.verify_binding(&ready.request) {
                    return Self::Failed {
                        reason,
                        execution_finished: true,
                    };
                }
                if ready.request.is_execution_only() {
                    let RemoteInstallAuthority::RequestOwned(result) = ready.result else {
                        return failed_before_start(
                            "queued workspace execution lacks its request-owned result",
                        );
                    };
                    return match RequestOwnedOutput::new(ready.output, result) {
                        Ok(owned) => Self::RequestOwned(owned),
                        Err(reason) => failed_before_start(reason),
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

    fn ready_owned(self, owned: &RequestOwnedOutput) -> RemoteResult {
        if !self.request.is_execution_only() {
            return failed_owned_result(
                "dependency subscribers cannot consume a request-owned workspace result",
            );
        }
        if let Err(reason) = owned.output.verify_binding(&self.request) {
            return failed_owned_result(reason);
        }
        let result = match owned.take() {
            Ok(result) => result,
            Err(reason) => return failed_owned_result(reason),
        };
        // This sole subscriber retains its original request, witnesses and
        // destination. Taking affine custody does not install, publish, index
        // a transcript or add verification evidence. Its independent writer
        // ACK must still pass through the ordinary request-owned installer.
        RemoteResult::Ready(PendingRemoteInstall {
            coord: self.coord,
            request: self.request,
            output: Arc::clone(&owned.output),
            validation: self.validation,
            result: RemoteInstallAuthority::RequestOwned(result),
        })
    }
}

fn failed_owned_result(reason: impl Into<String>) -> RemoteResult {
    RemoteResult::Failed {
        reason: reason.into(),
        execution_finished: true,
    }
}

enum Offer {
    Start {
        executions: Arc<SharedRemoteExecutions>,
        pending: Box<PendingRemote>,
    },
    Joined(Subscription<SharedRemoteResult>),
}

/// An unaccepted private-execution offer. Dropping a dependency starter
/// releases its key claim; a workspace starter owns no key claim yet. Neither
/// has reserved a worker or started a flight. Dropping a dependency follower
/// removes only its enrolled interest. No alternative authorizes output writes.
pub struct PendingSharedRemote {
    subscriber: SubscriberRequest,
    offer: Offer,
    permit: RequestPermit,
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
    pub(super) fn starter(
        executions: Arc<SharedRemoteExecutions>,
        pending: PendingRemote,
    ) -> io::Result<Self> {
        let permit = executions.requests.reserve()?;
        let subscriber = SubscriberRequest {
            coord: Arc::clone(&pending.lane.coord),
            request: pending.request.clone(),
            validation: pending.invocation.validation.clone(),
        };
        Ok(Self {
            subscriber,
            offer: Offer::Start {
                executions,
                pending: Box::new(pending),
            },
            permit,
        })
    }

    pub(super) fn joined(
        coord: Arc<CoordLive>,
        request: LiveDependencyRequest,
        validation: RemoteValidation,
        subscription: Subscription<SharedRemoteResult>,
        executions: &SharedRemoteExecutions,
    ) -> io::Result<Self> {
        let permit = executions.requests.reserve()?;
        Ok(Self {
            subscriber: SubscriberRequest {
                coord,
                request,
                validation,
            },
            offer: Offer::Joined(subscription),
            permit,
        })
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
        let Self {
            subscriber,
            offer,
            permit,
        } = self;
        let (work, disposition) = match offer {
            Offer::Joined(subscription) => {
                if subscriber.request.is_execution_only() {
                    return Err("workspace execution cannot join a shared remote offer".into());
                }
                (subscription, "joined")
            }
            Offer::Start {
                executions,
                pending,
            } => (
                executions.enqueue(*pending, &permit)?,
                if subscriber.request.is_execution_only() {
                    "queued-request-owned"
                } else {
                    "queued"
                },
            ),
        };
        let key = rabs_cas::metadata_store::digest_key(&subscriber.request.key.action_key);
        let queue_request = permit.id.to_string();
        crate::edge::server::log_line(
            "rabsd-shared-remote-subscribed",
            &[
                ("key", &key),
                ("disposition", disposition),
                ("queue_request_id", &queue_request),
            ],
        );
        Ok(SharedRemoteSubscription {
            subscriber: Some(subscriber),
            work,
            _permit: permit,
        })
    }
}

/// One caller's interest and immutable input witnesses. It owns no worker
/// transport and cannot cancel another caller's demand. Drop removes only this
/// membership; the supervisor signals cancellation when the last one leaves.
pub struct SharedRemoteSubscription {
    subscriber: Option<SubscriberRequest>,
    work: Subscription<SharedRemoteResult>,
    _permit: RequestPermit,
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
                SharedRemoteResult::RequestOwned(owned) => subscriber.ready_owned(owned),
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
    fn claim_release_mid_pass_cannot_let_a_later_same_key_request_overtake() {
        let workers = super::super::worker_pool_tests::pool(
            std::path::Path::new("/private/fifo-workspace-pool"),
            2,
        );
        let key = rabs_key::typed_digest::compute("rabs.test.private-fifo.v1", b"shared-key");
        let other = rabs_key::typed_digest::compute("rabs.test.private-fifo.v1", b"unrelated");
        let running = workers.try_reserve(&key).unwrap();
        let mut waiting_keys = HashSet::new();
        let mut earlier = None;
        assert_eq!(
            probe_in_order(&mut waiting_keys, &workers, &key, &mut earlier)
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        let mut unrelated = None;
        let WorkerProbe::Reserved(unrelated_worker) =
            probe_in_order(&mut waiting_keys, &workers, &other, &mut unrelated).unwrap()
        else {
            panic!("an unrelated ready action must use the spare worker");
        };
        // Complete the old producer after the first queued request failed its
        // probe, but before a later same-key request is visited in this pass.
        drop(running);
        let mut later = None;
        assert_eq!(
            probe_in_order(&mut waiting_keys, &workers, &key, &mut later)
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        assert!(earlier.is_none() && later.is_none());
        let mut next_pass = HashSet::new();
        let WorkerProbe::Reserved(earlier_worker) =
            probe_in_order(&mut next_pass, &workers, &key, &mut earlier).unwrap()
        else {
            panic!("the earlier waiter must acquire the newly freed worker first");
        };
        assert_eq!(
            probe_in_order(&mut next_pass, &workers, &key, &mut later)
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        assert!(later.is_none());
        drop((earlier_worker, earlier, unrelated_worker, unrelated));
        assert!(workers.pending.lock().unwrap().is_empty());
    }

    #[test]
    fn capability_wait_keeps_its_action_claim_without_stranding_another_compatible_request() {
        use super::super::worker_pool_tests::{pool, scheduling_hello, scheduling_request};

        let workers = pool(std::path::Path::new("/private/capability-queue"), 1);
        let mut hello = scheduling_hello();
        hello["dependency_execution_modes"] = serde_json::json!(["closed-metadata"]);
        let advertisement = workers.workers[0].advertise_for_test(&hello);
        let archive = scheduling_request(false);
        let metadata = scheduling_request(true);
        let blocked_key =
            rabs_key::typed_digest::compute("rabs.test.capability-queue.v1", b"archive");
        let ready_key =
            rabs_key::typed_digest::compute("rabs.test.capability-queue.v1", b"metadata");
        let mut waiting_keys = HashSet::new();
        let mut earlier = None;
        assert!(matches!(
            probe_in_order_for(
                &mut waiting_keys,
                &workers,
                &blocked_key,
                &mut earlier,
                Some(&archive),
            )
            .unwrap(),
            WorkerProbe::RequestWaiting(None)
        ));
        let mut later = None;
        assert_eq!(
            probe_in_order_for(
                &mut waiting_keys,
                &workers,
                &blocked_key,
                &mut later,
                Some(&archive),
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::WouldBlock
        );
        assert!(earlier.is_some() && later.is_none());
        let mut ready_claim = None;
        let WorkerProbe::Reserved(reserved) = probe_in_order_for(
            &mut waiting_keys,
            &workers,
            &ready_key,
            &mut ready_claim,
            Some(&metadata),
        )
        .unwrap() else {
            panic!("an incompatible queue head must not hide usable worker capacity");
        };
        assert_eq!(reserved.worker(), "worker-1");
        drop((reserved, ready_claim, earlier, advertisement));
        assert!(workers.pending.lock().unwrap().is_empty());
        assert!(workers.try_claim(&blocked_key).is_ok());
    }

    #[test]
    fn unacknowledged_requests_are_bounded_individually_even_for_one_action_key() {
        let executions = SharedRemoteExecutions::new(1);
        let key = rabs_key::typed_digest::compute("rabs.test.private-queue.v1", b"same-action");
        // These are exactly the permits a starter/follower must reserve before
        // returning its offer. No ACK, deferred flight or worker is present.
        let mut offers = (0..MAX_SHARED_SUBSCRIBERS)
            .map(|_| executions.requests.reserve().unwrap())
            .collect::<Vec<_>>();
        let keys = offers
            .iter()
            .map(|permit| permit.flight_key(&key, true))
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(keys.len(), MAX_SHARED_SUBSCRIBERS);
        assert_eq!(
            executions.requests.reserve().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert!(executions.queue.state.lock().unwrap().pending.is_empty());
        assert!(executions.dispatcher.lock().unwrap().worker.is_none());
        assert!(executions.try_join(&key).is_none());

        drop(offers.pop());
        let replacement = executions.requests.reserve().unwrap();
        assert!(!keys.contains(&replacement.flight_key(&key, true)));
        // Dependency callers spend the same request budget. Their join key
        // differs from every private request, regardless of matching content.
        assert!(!keys.contains(&replacement.flight_key(&key, false)));
        assert_eq!(
            executions.requests.reserve().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(offers);
        drop(replacement);
        assert_eq!(executions.requests.state.lock().unwrap().live, 0);
        executions.shutdown().unwrap();
    }

    #[test]
    fn request_identity_exhaustion_never_wraps_or_reuses_a_live_private_flight() {
        let budget = Arc::new(RequestBudget::default());
        budget.state.lock().unwrap().next = u64::MAX - 1;
        let last = budget.reserve().unwrap();
        assert_eq!(last.id, u64::MAX);
        assert!(
            budget
                .reserve()
                .unwrap_err()
                .to_string()
                .contains("identity exhausted")
        );
        drop(last);
        assert_eq!(budget.state.lock().unwrap().live, 0);
        assert!(
            budget.reserve().is_err(),
            "release must not recycle identity"
        );
    }

    #[test]
    fn cancelling_one_same_key_workspace_waiter_cannot_cancel_or_join_another() {
        let executions = SharedRemoteExecutions::new(1);
        let key = rabs_key::typed_digest::compute("rabs.test.private-cancel.v1", b"same-action");
        let first = executions.requests.reserve().unwrap();
        let second = executions.requests.reserve().unwrap();
        let first_cancel = OperationCancellation::new();
        let second_cancel = OperationCancellation::new();
        let cancel = first_cancel.clone();
        let (first_member, mut first_launch) = executions
            .work
            .defer(first.flight_key(&key, true), move || cancel.cancel())
            .unwrap();
        let cancel = second_cancel.clone();
        let (mut second_member, mut second_launch) = executions
            .work
            .defer(second.flight_key(&key, true), move || cancel.cancel())
            .unwrap();
        assert!(executions.try_join(&key).is_none());
        drop(first_member);
        drop(first);
        assert!(first_cancel.is_cancelled());
        assert!(!second_cancel.is_cancelled());
        assert_eq!(
            executions
                .work
                .try_launch(
                    &mut first_launch,
                    || -> Option<fn() -> SharedRemoteResult> {
                        panic!("a cancelled workspace waiter must not even probe a worker");
                    }
                )
                .unwrap(),
            LaunchStatus::CancelledBeforeStart
        );
        assert!(second_launch.is_pending());
        executions
            .work
            .finish_deferred(&mut second_launch, failed_before_start("test refusal"))
            .unwrap();
        assert!(matches!(
            wait(second_member.wait()).unwrap().as_ref(),
            SharedRemoteResult::Failed { reason, execution_finished: true }
                if reason == "test refusal"
        ));
        assert!(!second_cancel.is_cancelled());
        drop(second_member);
        drop(second);
        executions.shutdown().unwrap();
    }

    #[test]
    fn same_key_workspace_results_keep_distinct_one_shot_custody_without_publication() {
        // Exercise real CAS pins and independent filesystem installation with
        // explicit capture fixtures. This is not compiler or TLS evidence.
        let fixture = Fixture::new();
        let first_capture = fixture.capture();
        let second_capture = fixture.capture();
        let key = first_capture.manifest().action_key.clone();
        let first_attempt = first_capture.authority().attempt_id;
        let second_attempt = second_capture.authority().attempt_id;
        assert_ne!(first_attempt, second_attempt);
        let output = |capture: &RequestOwnedResult| {
            Arc::new(RemoteOutput {
                manifest: capture.manifest().clone(),
                manifest_key: capture.captured.manifest_key.clone(),
                canonical_transcript: Vec::new(),
            })
        };
        let first_result =
            RequestOwnedOutput::new(output(&first_capture), Box::new(first_capture)).unwrap();
        let second_result =
            RequestOwnedOutput::new(output(&second_capture), Box::new(second_capture)).unwrap();
        let executions = SharedRemoteExecutions::new(1);
        let first = executions.requests.reserve().unwrap();
        let second = executions.requests.reserve().unwrap();
        let (mut first_member, mut first_launch) = executions
            .work
            .defer(first.flight_key(&key, true), || {})
            .unwrap();
        let (mut second_member, mut second_launch) = executions
            .work
            .defer(second.flight_key(&key, true), || {})
            .unwrap();
        let (release, released) = mpsc::sync_channel(1);
        assert_eq!(
            executions
                .work
                .try_launch(&mut first_launch, || Some(move || {
                    released.recv().unwrap();
                    SharedRemoteResult::RequestOwned(first_result)
                }))
                .unwrap(),
            LaunchStatus::Started
        );
        assert!(executions.try_join(&key).is_none());
        assert_eq!(
            executions
                .work
                .try_launch(
                    &mut second_launch,
                    || -> Option<fn() -> SharedRemoteResult> {
                        panic!("the first private worker still owns capacity");
                    }
                )
                .unwrap(),
            LaunchStatus::Blocked
        );
        release.send(()).unwrap();
        let first_result = wait(first_member.wait()).unwrap();
        assert_eq!(
            executions
                .work
                .try_launch(&mut second_launch, || Some(move || {
                    SharedRemoteResult::RequestOwned(second_result)
                }))
                .unwrap(),
            LaunchStatus::Started
        );
        let second_result = wait(second_member.wait()).unwrap();
        let SharedRemoteResult::RequestOwned(first_result) = first_result.as_ref() else {
            panic!("first workspace request lost affine custody");
        };
        let SharedRemoteResult::RequestOwned(second_result) = second_result.as_ref() else {
            panic!("second workspace request lost affine custody");
        };
        let first_capture = first_result.take().unwrap();
        let second_capture = second_result.take().unwrap();
        assert_eq!(first_capture.authority().attempt_id, first_attempt);
        assert_eq!(second_capture.authority().attempt_id, second_attempt);
        assert!(first_result.take().is_err());
        assert!(second_result.take().is_err());
        let first_files = fixture
            .install(
                *first_capture,
                &fixture.root.path().join("first"),
                || Ok(()),
            )
            .unwrap();
        let second_files = fixture
            .install(*second_capture, &fixture.root.path().join("second"), || {
                Ok(())
            })
            .unwrap();
        assert_eq!(first_files.len(), 1);
        assert_eq!(second_files.len(), 1);
        assert_ne!(first_files, second_files);
        assert_eq!(
            std::fs::read(&first_files[0]).unwrap(),
            std::fs::read(&second_files[0]).unwrap()
        );
        fixture.assert_unpublished();
        assert!(executions.try_join(&key).is_none());
        executions.shutdown().unwrap();
    }

    #[test]
    fn queued_deadline_settles_surviving_members_without_starting_a_producer() {
        let executions = SharedRemoteExecutions::new(1);
        let key = rabs_key::typed_digest::compute("rabs.test.queued-deadline.v1", b"action");
        let cancellation = OperationCancellation::new();
        let cancel = cancellation.clone();
        let (origin, launch) = executions
            .work
            .defer(FlightKey::Dependency(key.clone()), move || cancel.cancel())
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
        let (mut member, launch) = executions
            .work
            .defer(FlightKey::Dependency(key.clone()), || {})
            .unwrap();
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
                FlightKey::Dependency(key.clone()),
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
