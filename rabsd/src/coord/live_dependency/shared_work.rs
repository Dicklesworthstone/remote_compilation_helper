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
    AtCapacity,
    SubscriberCapacity,
    AlreadyRunning,
    Spawn(io::Error),
}

impl fmt::Display for StartError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShuttingDown => formatter.write_str("shared execution admission is closed"),
            Self::AtCapacity => {
                formatter.write_str("shared execution worker capacity is exhausted")
            }
            Self::SubscriberCapacity => {
                formatter.write_str("shared execution subscriber capacity is exhausted")
            }
            Self::AlreadyRunning => {
                formatter.write_str("this action already has an owned shared execution")
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
}

impl fmt::Display for WorkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WorkerPanicked => formatter.write_str("shared execution worker panicked"),
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

struct Job<R> {
    flight: Arc<Flight<R>>,
    worker: Option<JoinHandle<()>>,
}

struct Registry<K, R> {
    jobs: HashMap<K, Job<R>>,
    shutdown_started: bool,
    shutdown_finished: bool,
    reapers: usize,
    failures: ShutdownError,
}

/// One bounded supervisor per shared execution authority. Worker handles are
/// deliberately stored separately from the per-flight state used by workers and
/// subscribers, avoiding a worker-owned handle, self-join, or internal Arc cycle.
pub struct SharedWork<K: Eq + Hash + Clone + Send, R: Send + Sync + 'static> {
    maximum_work: usize,
    budget: Arc<SubscriberBudget>,
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
            registry: Mutex::new(Registry {
                jobs: HashMap::new(),
                shutdown_started: false,
                shutdown_finished: false,
                reapers: 0,
                failures: ShutdownError::default(),
            }),
            changed: Condvar::new(),
        }
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

    pub fn start(
        &self,
        key: K,
        cancel: impl Fn() + Send + Sync + 'static,
        work: impl FnOnce() -> R + Send + 'static,
    ) -> Result<Subscription<R>, StartError> {
        self.reap_finished();
        let mut registry = lock(&self.registry);
        if registry.shutdown_started {
            return Err(StartError::ShuttingDown);
        }
        if registry.jobs.contains_key(&key) {
            return Err(StartError::AlreadyRunning);
        }
        if registry.jobs.len() >= self.maximum_work {
            return Err(StartError::AtCapacity);
        }
        let slot = self
            .budget
            .reserve()
            .ok_or(StartError::SubscriberCapacity)?;
        let flight = Arc::new(Flight {
            state: Mutex::new(FlightState {
                accepting: true,
                outcome: None,
                subscribers: HashMap::from([(1, None)]),
                next_subscriber: 2,
                cancellation: Cancellation::NotRequested,
            }),
            cancellation_changed: Condvar::new(),
            cancel: Box::new(cancel),
        });
        let worker_flight = Arc::clone(&flight);
        // Registration and handle ownership happen under the registry lock, so
        // shutdown cannot miss a successfully spawned worker. The worker only
        // locks its own flight; it never accesses this registry or supervisor.
        let worker = thread::Builder::new()
            .name("rabs-shared-work".to_owned())
            .spawn(move || {
                let outcome = catch_unwind(AssertUnwindSafe(|| Arc::new(work())))
                    .map_err(|_| WorkError::WorkerPanicked);
                worker_flight.complete(outcome);
            })
            .map_err(StartError::Spawn)?;
        registry.jobs.insert(
            key,
            Job {
                flight: Arc::clone(&flight),
                worker: Some(worker),
            },
        );
        Ok(Subscription {
            flight,
            id: 1,
            _slot: slot,
        })
    }

    fn join_jobs(jobs: &mut [Job<R>]) -> ShutdownError {
        let mut failures = ShutdownError::default();
        for job in jobs {
            let panicked = job
                .worker
                .take()
                .is_some_and(|worker| worker.join().is_err());
            failures.add(job.flight.report(panicked));
        }
        failures
    }

    fn reap_finished(&self) {
        let mut jobs = {
            let mut registry = lock(&self.registry);
            if registry.shutdown_started {
                return;
            }
            let finished = registry
                .jobs
                .iter()
                .filter(|(_, job)| job.worker.as_ref().is_some_and(JoinHandle::is_finished))
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
        // Only handles observed finished are removed here. Even these joins
        // occur outside the registry lock; subscription operations stay prompt.
        let failures = Self::join_jobs(&mut jobs);
        {
            let mut registry = lock(&self.registry);
            registry.failures.add(failures);
            registry.reapers -= 1;
        }
        self.changed.notify_all();
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
        }
        let failures = Self::join_jobs(&mut jobs);
        let result = {
            let mut registry = lock(&self.registry);
            registry.failures.add(failures);
            // A concurrent start can already be joining a completed worker it
            // removed before shutdown sealed admission. Include that ownership
            // before declaring the supervisor drained.
            while registry.reapers != 0 {
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
            Err(StartError::AtCapacity)
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
