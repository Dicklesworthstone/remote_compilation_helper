//! Bounded, authority-owned work with an exact cohort of interested callers.
//!
//! A subscription owns demand and a result notification, never a native worker
//! handle. Losing one connection therefore cannot join or cancel work that
//! another connection still needs. Only the supervisor reaps workers, and its
//! shutdown joins every worker before the authority that admitted it can close.
//!
//! Cohort membership closes atomically with completion or the last departure.
//! A matching key after that point cannot acquire authority to a fresh producer's
//! result: later requests must go through the domain's normal replay gates.
//! This module does not interpret results, publication, or installation consent.
//!
//! Cancellation callbacks must only signal cancellation promptly. Neither they
//! nor work closures may retain or reenter their own supervisor. Actual process
//! cancellation and drain belong to the worker closure; this supervisor retains
//! its handle until that closure has returned, including during shutdown.
//! Deferred flights retain bounded demand without a worker thread. Their opaque
//! launch capability belongs to an independently owned dispatcher, which may
//! acquire real executor capacity before starting exactly that flight.

use std::collections::HashMap;
use std::fmt;
use std::future::poll_fn;
use std::hash::Hash;
use std::io;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};
use std::thread::{self, JoinHandle};

#[derive(Debug)]
pub enum StartError {
    ShuttingDown,
    #[cfg(test)]
    AtCapacity,
    QueueCapacity,
    SubscriberCapacity,
    AlreadyRunning,
    StaleDeferred,
    PreparationPanicked,
    Spawn(io::Error),
}

impl fmt::Display for StartError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShuttingDown => formatter.write_str("shared execution admission is closed"),
            #[cfg(test)]
            Self::AtCapacity => {
                formatter.write_str("shared execution worker capacity is exhausted")
            }
            Self::QueueCapacity => {
                formatter.write_str("shared execution deferred-flight capacity is exhausted")
            }
            Self::SubscriberCapacity => {
                formatter.write_str("shared execution subscriber capacity is exhausted")
            }
            Self::AlreadyRunning => {
                formatter.write_str("this action already has an owned shared execution")
            }
            Self::StaleDeferred => {
                formatter.write_str("deferred launch does not own this unstarted flight")
            }
            Self::PreparationPanicked => {
                formatter.write_str("shared execution readiness preparation panicked")
            }
            Self::Spawn(error) => write!(
                formatter,
                "could not spawn shared execution worker: {error}"
            ),
        }
    }
}

impl std::error::Error for StartError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Spawn(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkError {
    WorkerPanicked,
    /// No worker closure was launched. This is a settled-before-execution
    /// failure, unlike a panic after a producer acquired execution custody.
    CancelledBeforeStart,
}

impl fmt::Display for WorkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WorkerPanicked => formatter.write_str("shared execution worker panicked"),
            Self::CancelledBeforeStart => {
                formatter.write_str("shared execution ended before its worker was started")
            }
        }
    }
}

impl std::error::Error for WorkError {}

/// Failures observed across both earlier reaps and this shutdown. Cancellation
/// callback panics do not skip any remaining cancellations or worker joins.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ShutdownError {
    pub worker_panics: usize,
    pub cancellation_panics: usize,
}

impl fmt::Display for ShutdownError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "worker panics: {}; cancellation callback panics: {}",
            self.worker_panics, self.cancellation_panics
        )
    }
}

impl std::error::Error for ShutdownError {}

impl ShutdownError {
    fn add(&mut self, other: Self) {
        self.worker_panics = self.worker_panics.saturating_add(other.worker_panics);
        self.cancellation_panics = self
            .cancellation_panics
            .saturating_add(other.cancellation_panics);
    }

    fn result(self) -> Result<(), Self> {
        if self == Self::default() {
            Ok(())
        } else {
            Err(self)
        }
    }
}

struct SubscriberBudget {
    maximum: usize,
    registered: AtomicUsize,
}

impl SubscriberBudget {
    fn reserve(self: &Arc<Self>) -> Option<SubscriberSlot> {
        self.registered
            .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < self.maximum).then(|| count + 1)
            })
            .ok()
            .map(|_| SubscriberSlot(Arc::clone(self)))
    }
}

struct SubscriberSlot(Arc<SubscriberBudget>);

impl Drop for SubscriberSlot {
    fn drop(&mut self) {
        self.0.registered.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Clone, Copy)]
enum Cancellation {
    NotRequested,
    Running,
    Finished { panicked: bool },
}

struct FlightState<R> {
    accepting: bool,
    outcome: Option<Result<Arc<R>, WorkError>>,
    subscribers: HashMap<u64, Option<Waker>>,
    next_subscriber: u64,
    cancellation: Cancellation,
}

struct Flight<R> {
    state: Mutex<FlightState<R>>,
    cancellation_changed: Condvar,
    cancel: Box<dyn Fn() + Send + Sync>,
    notify: Arc<dyn Fn() + Send + Sync>,
}

fn notify(callback: &(dyn Fn() + Send + Sync)) {
    let _ = catch_unwind(AssertUnwindSafe(callback));
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl<R: Send + Sync + 'static> Flight<R> {
    fn join(self: &Arc<Self>, budget: &Arc<SubscriberBudget>) -> Option<Subscription<R>> {
        let mut state = lock(&self.state);
        if !state.accepting || state.outcome.is_some() {
            return None;
        }
        let id = state.next_subscriber;
        let next = id.checked_add(1)?;
        let slot = budget.reserve()?;
        state.next_subscriber = next;
        state.subscribers.insert(id, None);
        Some(Subscription {
            flight: Arc::clone(self),
            id,
            _slot: slot,
        })
    }

    /// Called with the flight lock held, then invoked only after releasing it.
    fn select_cancellation(state: &mut FlightState<R>) -> bool {
        state.accepting = false;
        if state.outcome.is_none() && matches!(state.cancellation, Cancellation::NotRequested) {
            state.cancellation = Cancellation::Running;
            true
        } else {
            false
        }
    }

    fn run_cancellation(&self) {
        let panicked = catch_unwind(AssertUnwindSafe(|| (self.cancel)())).is_err();
        lock(&self.state).cancellation = Cancellation::Finished { panicked };
        self.cancellation_changed.notify_all();
    }

    fn seal_and_cancel(&self) {
        let selected = Self::select_cancellation(&mut lock(&self.state));
        if selected {
            self.run_cancellation();
        }
    }

    fn cancel_deferred(&self) {
        self.seal_and_cancel();
        self.complete(Err(WorkError::CancelledBeforeStart));
    }

    fn detach(&self, id: u64) {
        let (waker, cancel) = {
            let mut state = lock(&self.state);
            let waker = state.subscribers.remove(&id);
            let cancel = state.subscribers.is_empty() && Self::select_cancellation(&mut state);
            (waker, cancel)
        };
        if cancel {
            self.run_cancellation();
        }
        // A caller's RawWaker destructor must not run under the flight lock.
        drop(waker);
    }

    fn complete(&self, outcome: Result<Arc<R>, WorkError>) {
        let wakers = {
            let mut state = lock(&self.state);
            state.accepting = false;
            if state.outcome.is_some() {
                return;
            }
            state.outcome = Some(outcome);
            state
                .subscribers
                .values_mut()
                .filter_map(Option::take)
                .collect::<Vec<_>>()
        };
        // Wake every member independently. One ill-behaved waker must not lose
        // another caller's notification or strand supervisor-owned work.
        for waker in wakers {
            let _ = catch_unwind(AssertUnwindSafe(|| waker.wake()));
        }
        // Notification follows result sealing and subscriber wakeups. A
        // dispatcher may immediately join this completed worker's finishing
        // handle, even before JoinHandle::is_finished observes thread exit.
        notify(self.notify.as_ref());
    }

    fn report(&self, join_panicked: bool) -> ShutdownError {
        if join_panicked {
            self.complete(Err(WorkError::WorkerPanicked));
        }
        let mut state = lock(&self.state);
        // A last subscription can be invoking cancellation on another thread.
        // Wait for that already-selected callback; never invoke it a second time.
        while matches!(state.cancellation, Cancellation::Running) {
            state = self
                .cancellation_changed
                .wait(state)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
        ShutdownError {
            worker_panics: usize::from(
                join_panicked || matches!(state.outcome, Some(Err(WorkError::WorkerPanicked))),
            ),
            cancellation_panics: usize::from(matches!(
                state.cancellation,
                Cancellation::Finished { panicked: true }
            )),
        }
    }
}

/// An opaque, non-cloneable membership in one running flight. Repeated waits
/// return the same immutable result; a domain's delivery permit remains affine.
/// Dropping membership never joins a worker, and only the final departure asks
/// its still-running worker to cancel.
pub struct Subscription<R: Send + Sync + 'static> {
    flight: Arc<Flight<R>>,
    id: u64,
    _slot: SubscriberSlot,
}

impl<R: Send + Sync + 'static> fmt::Debug for Subscription<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Subscription")
            .field("member", &self.id)
            .finish_non_exhaustive()
    }
}

impl<R: Send + Sync + 'static> Subscription<R> {
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<Arc<R>, WorkError>> {
        let mut state = lock(&self.flight.state);
        if let Some(outcome) = &state.outcome {
            return Poll::Ready(outcome.clone());
        }
        let waker = state
            .subscribers
            .get_mut(&self.id)
            .expect("a live subscription retains its member slot");
        if !waker
            .as_ref()
            .is_some_and(|stored| stored.will_wake(cx.waker()))
        {
            let replaced = waker.replace(cx.waker().clone());
            drop(state);
            // Replacing a task's waker also relinquishes its old task custody.
            drop(replaced);
        }
        Poll::Pending
    }

    pub async fn wait(&mut self) -> Result<Arc<R>, WorkError> {
        poll_fn(|cx| self.poll(cx)).await
    }
}

impl<R: Send + Sync + 'static> Drop for Subscription<R> {
    fn drop(&mut self) {
        self.flight.detach(self.id);
    }
}

/// Exclusive permission to start one particular deferred generation. Matching
/// keys do not substitute for this capability: a cancelled queued entry may
/// have been replaced by a new flight for the same action.
pub struct DeferredLaunch<K, R: Send + Sync + 'static> {
    key: K,
    flight: Arc<Flight<R>>,
    armed: bool,
    _slot: SubscriberSlot,
}

impl<K, R: Send + Sync + 'static> fmt::Debug for DeferredLaunch<K, R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeferredLaunch")
            .field("armed", &self.armed)
            .finish_non_exhaustive()
    }
}

impl<K, R: Send + Sync + 'static> DeferredLaunch<K, R> {
    /// Whether this unconsumed capability still has live demand. Dispatchers
    /// may discard cancelled entries without acquiring a worker reservation.
    pub fn is_pending(&self) -> bool {
        let state = lock(&self.flight.state);
        self.armed && state.accepting && state.outcome.is_none() && !state.subscribers.is_empty()
    }

    fn cancel(&mut self) {
        if self.armed {
            self.armed = false;
            self.flight.cancel_deferred();
        }
    }
}

impl<K, R: Send + Sync + 'static> Drop for DeferredLaunch<K, R> {
    fn drop(&mut self) {
        self.cancel();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LaunchStatus {
    Started,
    /// Native capacity or the readiness callback is not ready. The capability
    /// remains live, and no worker closure has been consumed by the supervisor.
    Blocked,
    CancelledBeforeStart,
}

struct Job<R> {
    flight: Arc<Flight<R>>,
    worker: Option<JoinHandle<()>>,
    preparing: bool,
}

struct Registry<K, R> {
    jobs: HashMap<K, Job<R>>,
    shutdown_started: bool,
    shutdown_finished: bool,
    reapers: usize,
    native_workers: usize,
    preparing: usize,
    failures: ShutdownError,
}

/// One bounded supervisor per shared execution authority. Worker handles are
/// deliberately stored separately from the per-flight state used by workers and
/// subscribers, avoiding a worker-owned handle, self-join, or internal Arc cycle.
pub struct SharedWork<K: Eq + Hash + Clone + Send, R: Send + Sync + 'static> {
    maximum_work: usize,
    budget: Arc<SubscriberBudget>,
    deferred_budget: Arc<SubscriberBudget>,
    notify: Arc<dyn Fn() + Send + Sync>,
    registry: Mutex<Registry<K, R>>,
    changed: Condvar,
}

impl<K: Eq + Hash + Clone + Send, R: Send + Sync + 'static> SharedWork<K, R> {
    pub fn new(max_work: usize, max_subscribers: usize) -> Self {
        Self {
            maximum_work: max_work,
            budget: Arc::new(SubscriberBudget {
                maximum: max_subscribers,
                registered: AtomicUsize::new(0),
            }),
            deferred_budget: Arc::new(SubscriberBudget {
                maximum: max_subscribers,
                registered: AtomicUsize::new(0),
            }),
            notify: Arc::new(|| {}),
            registry: Mutex::new(Registry {
                jobs: HashMap::new(),
                shutdown_started: false,
                shutdown_finished: false,
                reapers: 0,
                native_workers: 0,
                preparing: 0,
                failures: ShutdownError::default(),
            }),
            changed: Condvar::new(),
        }
    }

    /// Install a notification-only callback before admitting work. It must be
    /// prompt and must not retain or reenter this supervisor. A weak handle to
    /// the domain dispatcher's signal keeps ownership acyclic. Notifications
    /// carry no result or execution authority and always run outside locks.
    pub fn with_notify(mut self, callback: impl Fn() + Send + Sync + 'static) -> Self {
        self.notify = Arc::new(callback);
        self
    }

    fn flight(&self, cancel: impl Fn() + Send + Sync + 'static) -> Arc<Flight<R>> {
        Arc::new(Flight {
            state: Mutex::new(FlightState {
                accepting: true,
                outcome: None,
                subscribers: HashMap::from([(1, None)]),
                next_subscriber: 2,
                cancellation: Cancellation::NotRequested,
            }),
            cancellation_changed: Condvar::new(),
            cancel: Box::new(cancel),
            notify: Arc::clone(&self.notify),
        })
    }

    fn worker(
        flight: &Arc<Flight<R>>,
        work: impl FnOnce() -> R + Send + 'static,
    ) -> io::Result<JoinHandle<()>> {
        let flight = Arc::clone(flight);
        thread::Builder::new()
            .name("rabs-shared-work".to_owned())
            .spawn(move || {
                let outcome = catch_unwind(AssertUnwindSafe(|| Arc::new(work())))
                    .map_err(|_| WorkError::WorkerPanicked);
                flight.complete(outcome);
            })
    }

    /// Join only an existing, still-open cohort. Capacity exhaustion and sealed
    /// cohorts both refuse; neither invents a subscription from a matching key.
    pub fn try_join(&self, key: &K) -> Option<Subscription<R>> {
        let registry = lock(&self.registry);
        if registry.shutdown_started {
            return None;
        }
        registry.jobs.get(key)?.flight.join(&self.budget)
    }

    /// Register demand without spawning or reserving a native worker. Both the
    /// returned membership and the opaque dispatcher capability are bounded;
    /// retaining cancelled capabilities cannot create an unbounded queue.
    pub fn defer(
        &self,
        key: K,
        cancel: impl Fn() + Send + Sync + 'static,
    ) -> Result<(Subscription<R>, DeferredLaunch<K, R>), StartError> {
        self.reap_finished(false);
        let mut registry = lock(&self.registry);
        if registry.shutdown_started {
            return Err(StartError::ShuttingDown);
        }
        if registry.jobs.contains_key(&key) {
            return Err(StartError::AlreadyRunning);
        }
        let queued = self
            .deferred_budget
            .reserve()
            .ok_or(StartError::QueueCapacity)?;
        let slot = self
            .budget
            .reserve()
            .ok_or(StartError::SubscriberCapacity)?;
        let flight = self.flight(cancel);
        registry.jobs.insert(
            key.clone(),
            Job {
                flight: Arc::clone(&flight),
                worker: None,
                preparing: false,
            },
        );
        Ok((
            Subscription {
                flight: Arc::clone(&flight),
                id: 1,
                _slot: slot,
            },
            DeferredLaunch {
                key,
                flight,
                armed: true,
                _slot: queued,
            },
        ))
    }

    /// Try to launch exactly this deferred generation. `prepare` only acquires
    /// bounded external resources and constructs a closure; it must not run the
    /// workload. It runs outside locks and is never called without native
    /// capacity and live demand. `None` retains the queued request in its owner.
    ///
    /// Cancellation and shutdown are rechecked after preparation. Resources in
    /// a rejected closure are dropped before the preparation slot is released,
    /// and shutdown waits for every such owner even though no worker started.
    pub fn try_launch<F>(
        &self,
        permit: &mut DeferredLaunch<K, R>,
        prepare: impl FnOnce() -> Option<F>,
    ) -> Result<LaunchStatus, StartError>
    where
        F: FnOnce() -> R + Send + 'static,
    {
        if !permit.armed {
            return Err(StartError::StaleDeferred);
        }
        // Completion notification precedes native thread exit. Join a sealed
        // result's finishing handle here, outside all state locks, rather than
        // waiting for another notification that will never arrive.
        self.reap_finished(true);
        let mut preparation = Preparation {
            supervisor: self,
            key: permit.key.clone(),
            flight: Arc::clone(&permit.flight),
            active: false,
        };
        {
            let mut registry = lock(&self.registry);
            if registry.shutdown_started {
                drop(registry);
                permit.cancel();
                return Ok(LaunchStatus::CancelledBeforeStart);
            }
            let job = registry
                .jobs
                .get(&permit.key)
                .ok_or(StartError::StaleDeferred)?;
            if !Arc::ptr_eq(&job.flight, &permit.flight) || job.worker.is_some() || job.preparing {
                return Err(StartError::StaleDeferred);
            }
            if !permit.is_pending() {
                drop(registry);
                permit.cancel();
                return Ok(LaunchStatus::CancelledBeforeStart);
            }
            if registry.native_workers + registry.preparing >= self.maximum_work {
                return Ok(LaunchStatus::Blocked);
            }
            registry.jobs.get_mut(&permit.key).unwrap().preparing = true;
            registry.preparing += 1;
            preparation.active = true;
        }

        let work = match catch_unwind(AssertUnwindSafe(prepare)) {
            Ok(Some(work)) => work,
            Ok(None) => {
                drop(preparation);
                if permit.is_pending() {
                    return Ok(LaunchStatus::Blocked);
                }
                permit.cancel();
                return Ok(LaunchStatus::CancelledBeforeStart);
            }
            Err(_) => {
                drop(preparation);
                permit.cancel();
                return Err(StartError::PreparationPanicked);
            }
        };

        let mut registry = lock(&self.registry);
        if registry.shutdown_started {
            drop(registry);
            drop(work);
            drop(preparation);
            permit.cancel();
            return Ok(LaunchStatus::CancelledBeforeStart);
        }
        if !registry.jobs.get(&permit.key).is_some_and(|job| {
            Arc::ptr_eq(&job.flight, &permit.flight) && job.preparing && job.worker.is_none()
        }) {
            drop(registry);
            drop(work);
            drop(preparation);
            permit.cancel();
            return Err(StartError::StaleDeferred);
        }
        // Serialize actual launch with the last departure. A departure before
        // this point starts no worker; a later departure signals the launched
        // worker's retained cancellation token.
        let state = lock(&permit.flight.state);
        if !state.accepting || state.outcome.is_some() || state.subscribers.is_empty() {
            drop(state);
            drop(registry);
            drop(work);
            drop(preparation);
            permit.cancel();
            return Ok(LaunchStatus::CancelledBeforeStart);
        }
        match Self::worker(&permit.flight, work) {
            Ok(worker) => {
                let job = registry.jobs.get_mut(&permit.key).unwrap();
                job.worker = Some(worker);
                job.preparing = false;
                registry.native_workers += 1;
                registry.preparing -= 1;
                preparation.active = false;
                permit.armed = false;
                drop(state);
                drop(registry);
                self.changed.notify_all();
                Ok(LaunchStatus::Started)
            }
            Err(error) => {
                drop(state);
                drop(registry);
                drop(preparation);
                permit.cancel();
                Err(StartError::Spawn(error))
            }
        }
    }

    /// Settle a domain-level refusal without launching any native work. Only
    /// this exact unstarted generation can receive the supplied terminal result.
    pub fn finish_deferred(
        &self,
        permit: &mut DeferredLaunch<K, R>,
        result: R,
    ) -> Result<(), StartError> {
        if !permit.armed {
            return Err(StartError::StaleDeferred);
        }
        let registry = lock(&self.registry);
        if registry.shutdown_started {
            drop(registry);
            permit.cancel();
            return Err(StartError::ShuttingDown);
        }
        if !registry.jobs.get(&permit.key).is_some_and(|job| {
            Arc::ptr_eq(&job.flight, &permit.flight) && job.worker.is_none() && !job.preparing
        }) {
            return Err(StartError::StaleDeferred);
        }
        permit.armed = false;
        drop(registry);
        permit.flight.complete(Ok(Arc::new(result)));
        Ok(())
    }

    /// Immediate admission retained for native ownership regression tests.
    /// Production admission uses deferred capabilities and the fair dispatcher.
    #[cfg(test)]
    pub fn start(
        &self,
        key: K,
        cancel: impl Fn() + Send + Sync + 'static,
        work: impl FnOnce() -> R + Send + 'static,
    ) -> Result<Subscription<R>, StartError> {
        let (subscription, mut launch) = self.defer(key, cancel)?;
        match self.try_launch(&mut launch, || Some(work))? {
            LaunchStatus::Started => Ok(subscription),
            LaunchStatus::Blocked => Err(StartError::AtCapacity),
            LaunchStatus::CancelledBeforeStart => Err(StartError::ShuttingDown),
        }
    }

    fn join_jobs(jobs: &mut [Job<R>]) -> (ShutdownError, usize) {
        let mut failures = ShutdownError::default();
        let mut joined = 0;
        for job in jobs {
            let panicked = match job.worker.take() {
                Some(worker) => {
                    joined += 1;
                    worker.join().is_err()
                }
                None => {
                    job.flight.cancel_deferred();
                    false
                }
            };
            failures.add(job.flight.report(panicked));
        }
        (failures, joined)
    }

    fn reap_finished(&self, join_completed: bool) {
        let mut jobs = {
            let mut registry = lock(&self.registry);
            if registry.shutdown_started {
                return;
            }
            let finished = registry
                .jobs
                .iter()
                .filter(|(_, job)| {
                    if job.preparing {
                        return false;
                    }
                    match &job.worker {
                        Some(worker) => {
                            worker.is_finished()
                                || (join_completed && lock(&job.flight.state).outcome.is_some())
                        }
                        None => {
                            let state = lock(&job.flight.state);
                            state.outcome.is_some()
                                || (!state.accepting && state.subscribers.is_empty())
                        }
                    }
                })
                .map(|(key, _)| key.clone())
                .collect::<Vec<_>>();
            if finished.is_empty() {
                return;
            }
            registry.reapers += 1;
            finished
                .into_iter()
                .filter_map(|key| registry.jobs.remove(&key))
                .collect::<Vec<_>>()
        };
        // Native capacity remains counted while a completed worker's finishing
        // handle is being joined. Concurrent callers cannot exceed the bound
        // simply because a reaper removed that handle from the key registry.
        let (failures, joined) = Self::join_jobs(&mut jobs);
        {
            let mut registry = lock(&self.registry);
            registry.failures.add(failures);
            registry.native_workers -= joined;
            registry.reapers -= 1;
        }
        self.changed.notify_all();
        notify(self.notify.as_ref());
    }

    /// Seal admission, signal every unfinished flight, and join every owned
    /// native worker. Concurrent callers wait for the same complete shutdown.
    /// Results may outlive the supervisor through their original subscriptions.
    pub fn shutdown(&self) -> Result<(), ShutdownError> {
        let mut jobs = {
            let mut registry = lock(&self.registry);
            loop {
                if registry.shutdown_finished {
                    return registry.failures.result();
                }
                if !registry.shutdown_started {
                    registry.shutdown_started = true;
                    break registry
                        .jobs
                        .drain()
                        .map(|(_, job)| job)
                        .collect::<Vec<_>>();
                }
                registry = self
                    .changed
                    .wait(registry)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
            }
        };
        for job in &jobs {
            job.flight.seal_and_cancel();
            if job.worker.is_none() {
                job.flight.complete(Err(WorkError::CancelledBeforeStart));
            }
        }
        let (failures, joined) = Self::join_jobs(&mut jobs);
        let result = {
            let mut registry = lock(&self.registry);
            registry.failures.add(failures);
            registry.native_workers -= joined;
            // A concurrent start can already be joining a completed worker it
            // removed before shutdown sealed admission. Include that ownership
            // before declaring the supervisor drained.
            while registry.reapers != 0 || registry.preparing != 0 {
                registry = self
                    .changed
                    .wait(registry)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
            }
            registry.shutdown_finished = true;
            registry.failures.result()
        };
        self.changed.notify_all();
        result
    }
}

/// Reserved native capacity while a readiness callback runs outside locks.
/// Work/resources returned by that callback must be dropped before this guard.
struct Preparation<'a, K: Eq + Hash + Clone + Send, R: Send + Sync + 'static> {
    supervisor: &'a SharedWork<K, R>,
    key: K,
    flight: Arc<Flight<R>>,
    active: bool,
}

impl<K: Eq + Hash + Clone + Send, R: Send + Sync + 'static> Drop for Preparation<'_, K, R> {
    fn drop(&mut self) {
        if self.active {
            let mut registry = lock(&self.supervisor.registry);
            if let Some(job) = registry.jobs.get_mut(&self.key)
                && Arc::ptr_eq(&job.flight, &self.flight)
            {
                job.preparing = false;
            }
            registry.preparing -= 1;
            drop(registry);
            self.supervisor.changed.notify_all();
            // A readiness miss is not a resource-availability event. Waking
            // the dispatcher for its own unchanged miss would cause a spin.
        }
    }
}

impl<K: Eq + Hash + Clone + Send, R: Send + Sync + 'static> Drop for SharedWork<K, R> {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::sync::mpsc::{self, Receiver, Sender};
    use std::task::Wake;
    use std::time::{Duration, Instant};

    const TEST_TIMEOUT: Duration = Duration::from_secs(5);

    struct ThreadWake(thread::Thread);

    impl Wake for ThreadWake {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.unpark();
        }
    }

    // Poll the real production future on the calling native thread. Each waiter
    // supplies its own native wake target; there is no alternate work registry,
    // simulated cancellation, or modeled result path in these tests.
    fn wait<R: Send + Sync + 'static>(
        subscription: &mut Subscription<R>,
        registered: Option<Sender<()>>,
    ) -> Result<Arc<R>, WorkError> {
        let waker = Waker::from(Arc::new(ThreadWake(thread::current())));
        let mut context = Context::from_waker(&waker);
        let mut future = Box::pin(subscription.wait());
        let mut registered = registered;
        let deadline = Instant::now() + TEST_TIMEOUT;
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(result) => return result,
                Poll::Pending => {
                    if let Some(sender) = registered.take() {
                        sender.send(()).unwrap();
                    }
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    assert!(!remaining.is_zero(), "shared result was not delivered");
                    thread::park_timeout(remaining);
                }
            }
        }
    }

    fn receive<T>(receiver: &Receiver<T>) -> T {
        receiver
            .recv_timeout(TEST_TIMEOUT)
            .expect("native worker timed out")
    }

    #[test]
    fn deferred_members_coalesce_without_a_thread_and_survive_origin_loss() {
        let supervisor = SharedWork::new(1, 3);
        let cancellations = Arc::new(AtomicUsize::new(0));
        let cancelled = Arc::clone(&cancellations);
        let (origin, mut launch) = supervisor
            .defer("queued", move || {
                cancelled.fetch_add(1, Ordering::SeqCst);
            })
            .unwrap();
        let mut follower = supervisor.try_join(&"queued").unwrap();
        assert!(matches!(
            supervisor.defer("queued", || {}),
            Err(StartError::AlreadyRunning)
        ));
        assert_eq!(lock(&supervisor.registry).native_workers, 0);
        assert!(lock(&supervisor.registry).jobs[&"queued"].worker.is_none());
        drop(origin);
        assert!(launch.is_pending());
        assert_eq!(cancellations.load(Ordering::SeqCst), 0);
        let (started, worker) = mpsc::channel();
        let (release, gate) = mpsc::channel();
        assert_eq!(
            supervisor
                .try_launch(&mut launch, || {
                    Some(move || {
                        started.send(thread::current().id()).unwrap();
                        receive(&gate);
                        String::from("one actual queued producer")
                    })
                })
                .unwrap(),
            LaunchStatus::Started
        );
        assert_ne!(receive(&worker), thread::current().id());
        drop(launch);
        assert_eq!(cancellations.load(Ordering::SeqCst), 0);
        release.send(()).unwrap();
        assert_eq!(
            *wait(&mut follower, None).unwrap(),
            "one actual queued producer"
        );
        assert!(supervisor.try_join(&"queued").is_none());
        supervisor.shutdown().unwrap();
    }

    #[test]
    fn deferred_readiness_does_not_consume_the_request_or_spin_on_unavailable_resources() {
        let notifications = Arc::new(AtomicUsize::new(0));
        let notified = Arc::clone(&notifications);
        let supervisor = SharedWork::new(1, 3).with_notify(move || {
            notified.fetch_add(1, Ordering::SeqCst);
        });
        let (release, gate) = mpsc::channel();
        let mut running = supervisor
            .start(
                "running",
                || {},
                move || {
                    receive(&gate);
                    1
                },
            )
            .unwrap();
        let (mut waiting, mut launch) = supervisor.defer("waiting", || {}).unwrap();
        let mut body = Some(|| 2);
        let preparations = AtomicUsize::new(0);
        assert_eq!(
            supervisor
                .try_launch(&mut launch, || {
                    preparations.fetch_add(1, Ordering::SeqCst);
                    body.take()
                })
                .unwrap(),
            LaunchStatus::Blocked
        );
        assert_eq!(preparations.load(Ordering::SeqCst), 0);
        assert!(body.is_some());
        release.send(()).unwrap();
        assert_eq!(*wait(&mut running, None).unwrap(), 1);
        // Native capacity is now available, but the domain's external worker
        // may still be busy. A readiness miss leaves its original body intact.
        assert_eq!(
            supervisor
                .try_launch(&mut launch, || None::<fn() -> u32>)
                .unwrap(),
            LaunchStatus::Blocked
        );
        let before = notifications.load(Ordering::SeqCst);
        assert_eq!(
            supervisor
                .try_launch(&mut launch, || None::<fn() -> u32>)
                .unwrap(),
            LaunchStatus::Blocked
        );
        assert_eq!(notifications.load(Ordering::SeqCst), before);
        assert!(body.is_some());
        assert_eq!(
            supervisor.try_launch(&mut launch, || body.take()).unwrap(),
            LaunchStatus::Started
        );
        assert!(body.is_none());
        assert_eq!(*wait(&mut waiting, None).unwrap(), 2);
        supervisor.shutdown().unwrap();
    }

    #[test]
    fn stale_deferred_capability_cannot_launch_or_finish_a_replacement_generation() {
        let supervisor: SharedWork<u32, &'static str> = SharedWork::new(1, 3);
        let cancellations = Arc::new(AtomicUsize::new(0));
        let cancelled = Arc::clone(&cancellations);
        let (origin, mut old) = supervisor
            .defer(7, move || {
                cancelled.fetch_add(1, Ordering::SeqCst);
            })
            .unwrap();
        drop(origin);
        assert!(!old.is_pending());
        // Reap the cancelled dormant entry while its old capability is still
        // held. Its same-key successor must not inherit that launch authority.
        let (mut current, mut replacement) = supervisor.defer(7, || {}).unwrap();
        let prepared = AtomicUsize::new(0);
        assert!(matches!(
            supervisor.try_launch(&mut old, || {
                prepared.fetch_add(1, Ordering::SeqCst);
                Some(|| "wrong generation")
            }),
            Err(StartError::StaleDeferred)
        ));
        assert!(matches!(
            supervisor.finish_deferred(&mut old, "wrong terminal result"),
            Err(StartError::StaleDeferred)
        ));
        assert_eq!(prepared.load(Ordering::SeqCst), 0);
        drop(old);
        assert!(replacement.is_pending());
        supervisor
            .finish_deferred(&mut replacement, "current generation")
            .unwrap();
        assert_eq!(*wait(&mut current, None).unwrap(), "current generation");
        assert_eq!(cancellations.load(Ordering::SeqCst), 1);
        supervisor.shutdown().unwrap();
    }

    #[test]
    fn retained_deferred_capabilities_and_members_have_independent_finite_bounds() {
        let supervisor: SharedWork<u32, u32> = SharedWork::new(1, 2);
        let (first, first_launch) = supervisor.defer(1, || {}).unwrap();
        let (second, second_launch) = supervisor.defer(2, || {}).unwrap();
        assert!(supervisor.try_join(&1).is_none());
        drop(first);
        drop(second);
        assert!(matches!(
            supervisor.defer(3, || {}),
            Err(StartError::QueueCapacity)
        ));
        assert_eq!(lock(&supervisor.registry).native_workers, 0);
        drop(first_launch);
        let (mut third, mut third_launch) = supervisor.defer(3, || {}).unwrap();
        supervisor.finish_deferred(&mut third_launch, 3).unwrap();
        assert_eq!(*wait(&mut third, None).unwrap(), 3);
        drop(second_launch);
        supervisor.shutdown().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn last_cancellation_during_readiness_releases_real_resources_without_starting_work() {
        use std::io::Read;
        use std::os::unix::net::UnixStream;

        let supervisor = Arc::new(SharedWork::new(1, 2));
        let cancellations = Arc::new(AtomicUsize::new(0));
        let cancelled = Arc::clone(&cancellations);
        let (subscriber, mut launch) = supervisor
            .defer(1, move || {
                cancelled.fetch_add(1, Ordering::SeqCst);
            })
            .unwrap();
        let (prepared, resources) = mpsc::channel();
        let (release, gate) = mpsc::channel();
        let executions = Arc::new(AtomicUsize::new(0));
        let executed = Arc::clone(&executions);
        let owner = Arc::clone(&supervisor);
        let launcher = thread::spawn(move || {
            owner.try_launch(&mut launch, || {
                let (retained, observer) = UnixStream::pair().unwrap();
                prepared.send(observer).unwrap();
                receive(&gate);
                Some(move || {
                    executed.fetch_add(1, Ordering::SeqCst);
                    drop(retained);
                    17
                })
            })
        });
        let mut observer = receive(&resources);
        observer.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
        let before = Instant::now();
        drop(subscriber);
        assert!(before.elapsed() < Duration::from_secs(1));
        assert_eq!(cancellations.load(Ordering::SeqCst), 1);
        // The readiness callback is deliberately paused. Neither membership
        // operations nor cancellation may be waiting on its registry lock.
        assert!(supervisor.try_join(&1).is_none());
        assert!(matches!(
            supervisor.start(2, || {}, || 2),
            Err(StartError::AtCapacity)
        ));
        release.send(()).unwrap();
        assert_eq!(
            launcher.join().unwrap().unwrap(),
            LaunchStatus::CancelledBeforeStart
        );
        assert_eq!(observer.read(&mut [0_u8; 1]).unwrap(), 0);
        assert_eq!(executions.load(Ordering::SeqCst), 0);
        assert_eq!(lock(&supervisor.registry).preparing, 0);
        supervisor.shutdown().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn shutdown_waits_for_prepared_resource_release_without_spawning_a_late_worker() {
        use std::io::Read;
        use std::os::unix::net::UnixStream;

        let supervisor = Arc::new(SharedWork::new(1, 2));
        let (mut subscriber, mut launch) = supervisor.defer(1, || {}).unwrap();
        let (prepared, resources) = mpsc::channel();
        let (release, gate) = mpsc::channel();
        let executions = Arc::new(AtomicUsize::new(0));
        let executed = Arc::clone(&executions);
        let owner = Arc::clone(&supervisor);
        let launcher = thread::spawn(move || {
            owner.try_launch(&mut launch, || {
                let (retained, observer) = UnixStream::pair().unwrap();
                prepared.send(observer).unwrap();
                receive(&gate);
                Some(move || {
                    executed.fetch_add(1, Ordering::SeqCst);
                    drop(retained);
                    17
                })
            })
        });
        let mut observer = receive(&resources);
        observer.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
        let (done, completion) = mpsc::channel();
        let owner = Arc::clone(&supervisor);
        let shutdown = thread::spawn(move || {
            let result = owner.shutdown();
            done.send(()).unwrap();
            result
        });
        assert_eq!(
            wait(&mut subscriber, None),
            Err(WorkError::CancelledBeforeStart)
        );
        assert!(matches!(
            completion.recv_timeout(Duration::from_millis(30)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        assert!(!lock(&supervisor.registry).shutdown_finished);
        release.send(()).unwrap();
        assert_eq!(
            launcher.join().unwrap().unwrap(),
            LaunchStatus::CancelledBeforeStart
        );
        shutdown.join().unwrap().unwrap();
        assert_eq!(observer.read(&mut [0_u8; 1]).unwrap(), 0);
        assert_eq!(executions.load(Ordering::SeqCst), 0);
        assert_eq!(lock(&supervisor.registry).preparing, 0);
    }

    #[test]
    fn completion_notification_reaps_the_real_finishing_thread_without_a_second_wakeup() {
        let notifications = Arc::new(AtomicUsize::new(0));
        let notified = Arc::clone(&notifications);
        let (completing, completion) = mpsc::channel();
        let (release, gate) = mpsc::channel();
        let gate = Mutex::new(gate);
        let supervisor = Arc::new(SharedWork::new(1, 4).with_notify(move || {
            if notified.fetch_add(1, Ordering::SeqCst) == 0 {
                // Hold the actual native thread in its completion tail after
                // result sealing, before is_finished can observe its exit.
                completing.send(()).unwrap();
                receive(&lock(&gate));
            }
        }));
        let mut first = supervisor.start(1, || {}, || 1).unwrap();
        receive(&completion);
        assert_eq!(*wait(&mut first, None).unwrap(), 1);
        let (mut second, mut launch) = supervisor.defer(2, || {}).unwrap();
        let owner = Arc::clone(&supervisor);
        let launcher = thread::spawn(move || owner.try_launch(&mut launch, || Some(|| 2)));
        let deadline = Instant::now() + TEST_TIMEOUT;
        while lock(&supervisor.registry).reapers == 0 {
            assert!(Instant::now() < deadline, "completed worker was not joined");
            thread::yield_now();
        }
        // A live native tail remains counted even after its handle leaves the
        // map. Joining it holds neither the registry nor a flight lock.
        assert!(matches!(
            supervisor.start(3, || {}, || 3),
            Err(StartError::AtCapacity)
        ));
        let another_member = supervisor.try_join(&2).unwrap();
        drop(another_member);
        release.send(()).unwrap();
        assert_eq!(launcher.join().unwrap().unwrap(), LaunchStatus::Started);
        assert_eq!(*wait(&mut second, None).unwrap(), 2);
        supervisor.shutdown().unwrap();
    }

    #[test]
    fn cancellation_racing_deferred_native_launch_never_reports_an_unstarted_running_worker() {
        for _ in 0..24 {
            let supervisor = Arc::new(SharedWork::new(1, 1));
            let (cancelled, cancellation) = mpsc::channel();
            let (subscriber, mut launch) = supervisor
                .defer(1, move || {
                    let _ = cancelled.send(());
                })
                .unwrap();
            let (preparing, preparation) = mpsc::channel();
            let gate = Arc::new(std::sync::Barrier::new(2));
            let worker_gate = Arc::clone(&gate);
            let executions = Arc::new(AtomicUsize::new(0));
            let executed = Arc::clone(&executions);
            let owner = Arc::clone(&supervisor);
            let launcher = thread::spawn(move || {
                owner.try_launch(&mut launch, || {
                    preparing.send(()).unwrap();
                    worker_gate.wait();
                    Some(move || {
                        executed.fetch_add(1, Ordering::SeqCst);
                        receive(&cancellation);
                    })
                })
            });
            receive(&preparation);
            gate.wait();
            drop(subscriber);
            let status = launcher.join().unwrap().unwrap();
            supervisor.shutdown().unwrap();
            match status {
                LaunchStatus::CancelledBeforeStart => {
                    assert_eq!(executions.load(Ordering::SeqCst), 0);
                }
                LaunchStatus::Started => {
                    assert_eq!(executions.load(Ordering::SeqCst), 1);
                }
                LaunchStatus::Blocked => panic!("the only ready flight lost its launch slot"),
            }
        }
    }

    #[test]
    fn dropped_or_panicked_deferred_admission_settles_members_before_execution() {
        let supervisor: SharedWork<u32, u32> = SharedWork::new(1, 4);
        let (mut first, first_launch) = supervisor.defer(1, || {}).unwrap();
        let mut follower = supervisor.try_join(&1).unwrap();
        drop(first_launch);
        assert_eq!(wait(&mut first, None), Err(WorkError::CancelledBeforeStart));
        assert_eq!(
            wait(&mut follower, None),
            Err(WorkError::CancelledBeforeStart)
        );
        let (mut second, mut second_launch) = supervisor.defer(2, || {}).unwrap();
        assert!(matches!(
            supervisor.try_launch(&mut second_launch, || -> Option<fn() -> u32> {
                panic!("actual readiness callback panic");
            }),
            Err(StartError::PreparationPanicked)
        ));
        assert_eq!(
            wait(&mut second, None),
            Err(WorkError::CancelledBeforeStart)
        );
        assert_eq!(lock(&supervisor.registry).preparing, 0);
        let (mut third, _third_launch) = supervisor.defer(3, || {}).unwrap();
        supervisor.shutdown().unwrap();
        assert_eq!(wait(&mut third, None), Err(WorkError::CancelledBeforeStart));
    }

    #[test]
    fn initial_subscriber_can_leave_while_followers_keep_the_actual_worker_alive() {
        let supervisor = SharedWork::new(1, 2);
        let cancellations = Arc::new(AtomicUsize::new(0));
        let cancel_count = Arc::clone(&cancellations);
        let (started, ready) = mpsc::channel();
        let (release, gate) = mpsc::channel();
        let first = supervisor
            .start(
                "action",
                move || {
                    cancel_count.fetch_add(1, Ordering::SeqCst);
                },
                move || {
                    started.send(thread::current().id()).unwrap();
                    receive(&gate);
                    String::from("the compiler's original immutable result")
                },
            )
            .unwrap();
        assert_ne!(receive(&ready), thread::current().id());
        let mut follower = supervisor.try_join(&"action").unwrap();
        drop(first);
        assert_eq!(cancellations.load(Ordering::SeqCst), 0);
        assert!(supervisor.try_join(&"other-action").is_none());
        release.send(()).unwrap();
        let result = wait(&mut follower, None).unwrap();
        assert_eq!(*result, "the compiler's original immutable result");
        assert!(supervisor.try_join(&"action").is_none());
        assert!(Arc::ptr_eq(&result, &wait(&mut follower, None).unwrap()));
        supervisor.shutdown().unwrap();
        drop(supervisor);
        assert_eq!(*wait(&mut follower, None).unwrap(), *result);
        drop(follower);
        assert_eq!(cancellations.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn every_subscriber_has_an_independent_native_waker() {
        let supervisor = SharedWork::new(1, 2);
        let (release, gate) = mpsc::channel();
        let mut first = supervisor
            .start(
                7,
                || {},
                move || {
                    receive(&gate);
                    vec![13_u8; 4096]
                },
            )
            .unwrap();
        let mut second = supervisor.try_join(&7).unwrap();
        let (registered, registrations) = mpsc::channel();
        let first_registered = registered.clone();
        let first_waiter = thread::spawn(move || wait(&mut first, Some(first_registered)).unwrap());
        let second_waiter = thread::spawn(move || wait(&mut second, Some(registered)).unwrap());
        receive(&registrations);
        receive(&registrations);
        release.send(()).unwrap();
        let first_result = first_waiter.join().unwrap();
        let second_result = second_waiter.join().unwrap();
        assert!(Arc::ptr_eq(&first_result, &second_result));
        assert_eq!(first_result.as_slice(), &[13_u8; 4096]);
        assert!(supervisor.try_join(&7).is_none());
        supervisor.shutdown().unwrap();
    }

    #[test]
    fn last_departure_seals_membership_and_signals_once_without_joining() {
        let supervisor = SharedWork::new(1, 2);
        let cancellations = Arc::new(AtomicUsize::new(0));
        let cancel_count = Arc::clone(&cancellations);
        let (cancelled, cancel_signal) = mpsc::channel();
        let (release, gate) = mpsc::channel();
        let first = supervisor
            .start(
                "action",
                move || {
                    cancel_count.fetch_add(1, Ordering::SeqCst);
                    cancelled.send(()).unwrap();
                },
                move || {
                    receive(&cancel_signal);
                    receive(&gate);
                    42
                },
            )
            .unwrap();
        let second = supervisor.try_join(&"action").unwrap();
        drop(first);
        assert_eq!(cancellations.load(Ordering::SeqCst), 0);
        let before = Instant::now();
        drop(second);
        assert!(
            before.elapsed() < Duration::from_secs(1),
            "subscription drop joined live work"
        );
        assert_eq!(cancellations.load(Ordering::SeqCst), 1);
        assert!(supervisor.try_join(&"action").is_none());
        assert!(matches!(
            supervisor.start("action", || {}, || 0),
            Err(StartError::AlreadyRunning)
        ));
        assert!(matches!(
            supervisor.start("different", || {}, || 0),
            Err(StartError::AtCapacity)
        ));
        release.send(()).unwrap();
        supervisor.shutdown().unwrap();
        assert_eq!(cancellations.load(Ordering::SeqCst), 1);
    }

    fn start_after_reap(supervisor: &SharedWork<u32, u32>, key: u32) -> Subscription<u32> {
        let deadline = Instant::now() + TEST_TIMEOUT;
        loop {
            match supervisor.start(key, || {}, move || key) {
                Ok(subscription) => return subscription,
                Err(StartError::AtCapacity | StartError::AlreadyRunning) => {
                    assert!(Instant::now() < deadline, "finished handle was not reaped");
                    thread::yield_now();
                }
                Err(error) => panic!("unexpected start refusal: {error:?}"),
            }
        }
    }

    #[test]
    fn quotas_bound_native_work_and_all_retained_subscriptions() {
        let supervisor = SharedWork::new(1, 2);
        let (release, gate) = mpsc::channel();
        let mut first = supervisor
            .start(
                1,
                || {},
                move || {
                    receive(&gate);
                    1
                },
            )
            .unwrap();
        let second_member = supervisor.try_join(&1).unwrap();
        assert!(supervisor.try_join(&1).is_none());
        assert!(matches!(
            supervisor.start(2, || {}, || 2),
            Err(StartError::SubscriberCapacity)
        ));
        drop(second_member);
        release.send(()).unwrap();
        assert_eq!(*wait(&mut first, None).unwrap(), 1);
        let mut second = start_after_reap(&supervisor, 2);
        assert_eq!(*wait(&mut second, None).unwrap(), 2);
        // Finished jobs can be reaped, but their existing subscriptions still
        // occupy the global bounded cohort budget until their owners release it.
        let deadline = Instant::now() + TEST_TIMEOUT;
        loop {
            match supervisor.start(3, || {}, || 3) {
                Err(StartError::SubscriberCapacity) => break,
                Err(StartError::AtCapacity) => {
                    assert!(Instant::now() < deadline);
                    thread::yield_now();
                }
                other => panic!("retained subscriptions escaped the bound: {other:?}"),
            }
        }
        drop(first);
        let mut third = start_after_reap(&supervisor, 3);
        assert_eq!(*wait(&mut third, None).unwrap(), 3);
        supervisor.shutdown().unwrap();
    }

    #[test]
    fn shutdown_seals_admission_and_all_callers_wait_for_actual_worker_return() {
        let supervisor = Arc::new(SharedWork::new(1, 2));
        let cancellations = Arc::new(AtomicUsize::new(0));
        let cancel_count = Arc::clone(&cancellations);
        let (cancelled, cancel_signal) = mpsc::channel();
        let (release, gate) = mpsc::channel();
        let returned = Arc::new(AtomicUsize::new(0));
        let worker_returned = Arc::clone(&returned);
        let mut subscriber = supervisor
            .start(
                1,
                move || {
                    cancel_count.fetch_add(1, Ordering::SeqCst);
                    cancelled.send(()).unwrap();
                },
                move || {
                    receive(&gate);
                    worker_returned.store(1, Ordering::SeqCst);
                    91
                },
            )
            .unwrap();
        let (completed, completions) = mpsc::channel();
        let first_owner = Arc::clone(&supervisor);
        let first_completed = completed.clone();
        let first_shutdown = thread::spawn(move || {
            let result = first_owner.shutdown();
            first_completed.send(()).unwrap();
            result
        });
        receive(&cancel_signal);
        assert!(supervisor.try_join(&1).is_none());
        assert!(matches!(
            supervisor.start(2, || {}, || 2),
            Err(StartError::ShuttingDown)
        ));
        let second_owner = Arc::clone(&supervisor);
        let second_shutdown = thread::spawn(move || {
            let result = second_owner.shutdown();
            completed.send(()).unwrap();
            result
        });
        assert!(completions.try_recv().is_err());
        assert_eq!(returned.load(Ordering::SeqCst), 0);
        release.send(()).unwrap();
        first_shutdown.join().unwrap().unwrap();
        second_shutdown.join().unwrap().unwrap();
        assert_eq!(returned.load(Ordering::SeqCst), 1);
        assert_eq!(cancellations.load(Ordering::SeqCst), 1);
        assert_eq!(*wait(&mut subscriber, None).unwrap(), 91);
        drop(subscriber);
        assert_eq!(cancellations.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn worker_panic_is_terminal_for_every_member_and_is_joined() {
        let supervisor: SharedWork<u32, ()> = SharedWork::new(1, 2);
        let (release, gate) = mpsc::channel();
        let mut first = supervisor
            .start(
                1,
                || {},
                move || {
                    receive(&gate);
                    panic!("actual shared compiler task panic");
                },
            )
            .unwrap();
        let mut second = supervisor.try_join(&1).unwrap();
        release.send(()).unwrap();
        assert_eq!(wait(&mut first, None), Err(WorkError::WorkerPanicked));
        assert_eq!(wait(&mut second, None), Err(WorkError::WorkerPanicked));
        assert!(supervisor.try_join(&1).is_none());
        let expected = Err(ShutdownError {
            worker_panics: 1,
            cancellation_panics: 0,
        });
        assert_eq!(supervisor.shutdown(), expected);
        assert_eq!(supervisor.shutdown(), expected);
    }

    #[test]
    fn cancellation_panic_does_not_skip_worker_join_or_repeat_cancellation() {
        let supervisor = SharedWork::new(1, 1);
        let cancellations = Arc::new(AtomicUsize::new(0));
        let cancel_count = Arc::clone(&cancellations);
        let (release, gate) = mpsc::channel();
        let returned = Arc::new(AtomicUsize::new(0));
        let worker_returned = Arc::clone(&returned);
        let subscription = supervisor
            .start(
                1,
                move || {
                    cancel_count.fetch_add(1, Ordering::SeqCst);
                    panic!("actual cancellation callback panic");
                },
                move || {
                    receive(&gate);
                    worker_returned.store(1, Ordering::SeqCst);
                },
            )
            .unwrap();
        drop(subscription);
        assert!(supervisor.try_join(&1).is_none());
        release.send(()).unwrap();
        assert_eq!(
            supervisor.shutdown(),
            Err(ShutdownError {
                worker_panics: 0,
                cancellation_panics: 1
            })
        );
        assert_eq!(returned.load(Ordering::SeqCst), 1);
        assert_eq!(cancellations.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn dropping_supervisor_cancels_and_joins_even_with_a_live_subscriber() {
        let supervisor = SharedWork::new(1, 1);
        let (cancelled, cancel_signal) = mpsc::channel();
        let returned = Arc::new(AtomicUsize::new(0));
        let worker_returned = Arc::clone(&returned);
        let mut subscription = supervisor
            .start(
                1,
                move || {
                    cancelled.send(()).unwrap();
                },
                move || {
                    receive(&cancel_signal);
                    worker_returned.store(1, Ordering::SeqCst);
                    "drained"
                },
            )
            .unwrap();
        drop(supervisor);
        assert_eq!(returned.load(Ordering::SeqCst), 1);
        assert_eq!(*wait(&mut subscription, None).unwrap(), "drained");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn shared_native_process_survives_initiator_loss_and_final_cancellation_reaps_it() {
        use std::path::PathBuf;
        use std::process::{Child, Command, Stdio};

        struct OwnedChild(Child);
        impl Drop for OwnedChild {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        let supervisor = SharedWork::new(1, 2);
        let cancellations = Arc::new(AtomicUsize::new(0));
        let cancel_count = Arc::clone(&cancellations);
        let (cancelled, cancel_signal) = mpsc::channel();
        let (started, process) = mpsc::channel();
        let drained = Arc::new(AtomicUsize::new(0));
        let worker_drained = Arc::clone(&drained);
        let first = supervisor
            .start(
                "compiler",
                move || {
                    cancel_count.fetch_add(1, Ordering::SeqCst);
                    cancelled.send(()).unwrap();
                },
                move || {
                    let mut child = OwnedChild(
                        Command::new("/bin/sh")
                            .args(["-c", "exec sleep 60"])
                            .stdin(Stdio::null())
                            .stdout(Stdio::null())
                            .stderr(Stdio::null())
                            .spawn()
                            .unwrap(),
                    );
                    started.send(child.0.id()).unwrap();
                    receive(&cancel_signal);
                    child.0.kill().unwrap();
                    let status = child.0.wait().unwrap();
                    assert!(!status.success());
                    worker_drained.store(1, Ordering::SeqCst);
                },
            )
            .unwrap();
        let pid = receive(&process);
        let process_path = PathBuf::from(format!("/proc/{pid}"));
        let follower = supervisor.try_join(&"compiler").unwrap();
        drop(first);
        assert_eq!(cancellations.load(Ordering::SeqCst), 0);
        assert!(
            process_path.exists(),
            "initiator loss killed the shared compiler"
        );
        assert_eq!(drained.load(Ordering::SeqCst), 0);
        drop(follower);
        supervisor.shutdown().unwrap();
        assert_eq!(cancellations.load(Ordering::SeqCst), 1);
        assert_eq!(drained.load(Ordering::SeqCst), 1);
        assert!(
            !process_path.exists(),
            "shutdown returned before native child reap"
        );
    }
}
