//! Bounded, owned blocking work for the live edge.
//!
//! A future cancellation is not cancellation of a filesystem write. The task
//! owns and joins its thread, including on drop. Capacity remains owned until
//! the thread finishes. A non-clone permit can also cross a protocol boundary
//! between joined stages, reserving capacity without retaining a worker thread.
//! Normal waiting yields to the native reactor. Drop may wait for a filesystem
//! operation that the operating system cannot interrupt, rather than detach it.

use std::collections::VecDeque;
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::thread::JoinHandle;

#[derive(Clone)]
pub(super) struct Limit {
    active: Arc<AtomicUsize>,
    maximum: usize,
    waiters: Arc<Mutex<VecDeque<CapacityWaiter>>>,
}

struct CapacityWaiter {
    identity: Arc<()>,
    waker: Waker,
}

impl Limit {
    pub(super) fn new(maximum: usize) -> Self {
        Self {
            active: Arc::new(AtomicUsize::new(0)),
            maximum,
            waiters: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    pub(super) fn acquire(&self) -> Option<Permit> {
        let waiters = self
            .waiters
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if !waiters.is_empty() {
            return None;
        }
        self.acquire_unqueued()
    }

    // The caller owns the waiter lock and has checked queue order.
    fn acquire_unqueued(&self) -> Option<Permit> {
        self.active
            .try_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < self.maximum).then(|| active + 1)
            })
            .ok()?;
        Some(Permit(Arc::clone(&self.active), Arc::clone(&self.waiters)))
    }

    /// Wait cooperatively for a completed remote result's installation slot.
    /// No thread or permit is retained while queued. The edge's connection cap
    /// bounds waiters; caller liveness and a deadline bound their lifetime.
    /// Fresh cache hits cannot overtake results that already finished compiling.
    pub(super) fn wait(&self) -> WaitingPermit {
        WaitingPermit {
            limit: self.clone(),
            identity: Arc::new(()),
            registered: false,
            completed: false,
        }
    }

    /// Admission has no queue and never waits behind another caller. Spawn
    /// failure drops the unstarted closure and its permit without running it.
    pub(super) fn spawn<T, F>(&self, work: F) -> Result<OwnedWork<T>, WorkError>
    where
        T: Send + 'static,
        F: FnOnce() -> T + Send + 'static,
    {
        self.acquire().ok_or(WorkError::Saturated)?.finish(work)
    }
}

pub(super) struct WaitingPermit {
    limit: Limit,
    identity: Arc<()>,
    registered: bool,
    completed: bool,
}

impl Future for WaitingPermit {
    type Output = Permit;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        assert!(!this.completed, "capacity future polled after completion");
        let shared = Arc::clone(&this.limit.waiters);
        let mut waiters = shared.lock().unwrap_or_else(|error| error.into_inner());
        let is_next = waiters
            .front()
            .is_none_or(|waiter| Arc::ptr_eq(&waiter.identity, &this.identity));
        if is_next && let Some(permit) = this.limit.acquire_unqueued() {
            if this.registered {
                waiters.pop_front();
                this.registered = false;
            }
            this.completed = true;
            let next = (this.limit.active.load(Ordering::Acquire) < this.limit.maximum)
                .then(|| waiters.front().map(|waiter| waiter.waker.clone()))
                .flatten();
            drop(waiters);
            if let Some(waker) = next {
                waker.wake();
            }
            return Poll::Ready(permit);
        }
        if let Some(waiter) = waiters
            .iter_mut()
            .find(|waiter| Arc::ptr_eq(&waiter.identity, &this.identity))
        {
            waiter.waker.clone_from(cx.waker());
        } else {
            waiters.push_back(CapacityWaiter {
                identity: Arc::clone(&this.identity),
                waker: cx.waker().clone(),
            });
            this.registered = true;
        }
        Poll::Pending
    }
}

impl Drop for WaitingPermit {
    fn drop(&mut self) {
        if !self.registered {
            return;
        }
        let mut waiters = self
            .limit
            .waiters
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(index) = waiters
            .iter()
            .position(|waiter| Arc::ptr_eq(&waiter.identity, &self.identity))
        {
            waiters.remove(index);
        }
        let next = (self.limit.active.load(Ordering::Acquire) < self.limit.maximum)
            .then(|| waiters.front().map(|waiter| waiter.waker.clone()))
            .flatten();
        drop(waiters);
        if let Some(waker) = next {
            waker.wake();
        }
    }
}

/// Non-clone capacity permit, never execution or publication authority.
/// Moving it into a stage prevents concurrent use of that reservation.
pub(super) struct Permit(Arc<AtomicUsize>, Arc<Mutex<VecDeque<CapacityWaiter>>>);

impl Permit {
    /// Keep this reservation with the result of a joined stage. The receiver
    /// can await a bounded protocol acknowledgment without retaining a thread,
    /// then start the next stage WITHOUT racing for capacity a second time.
    /// Dropping an unconsumed result releases its reservation and payload.
    pub(super) fn stage<T, F>(self, work: F) -> Result<OwnedWork<(T, Self)>, WorkError>
    where
        T: Send + 'static,
        F: FnOnce() -> T + Send + 'static,
    {
        spawn_owned(None, move || {
            let result = work();
            // Tuple fields drop in order: abandoned payload cleanup must run
            // while the reservation is still held, not after another admission.
            (result, self)
        })
    }

    /// The final stage releases capacity after its work finishes, as ordinary
    /// Limit::spawn does. Thread-start errors still refuse; an existing permit
    /// eliminates saturation, not OS resource exhaustion or failed work.
    pub(super) fn finish<T, F>(self, work: F) -> Result<OwnedWork<T>, WorkError>
    where
        T: Send + 'static,
        F: FnOnce() -> T + Send + 'static,
    {
        spawn_owned(Some(self), work)
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
        let next = self
            .1
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .front()
            .map(|waiter| waiter.waker.clone());
        if let Some(waker) = next {
            waker.wake();
        }
    }
}

/// One thread/notification implementation for both ordinary work and staged
/// handoffs. A continuing stage returns its permit INSIDE its result; a final
/// stage drops its permit after publishing the result, before waking the owner.
fn spawn_owned<T, F>(permit: Option<Permit>, work: F) -> Result<OwnedWork<T>, WorkError>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let shared = Arc::new(Mutex::new(Completion {
        result: None,
        waker: None,
    }));
    let worker_state = Arc::clone(&shared);
    let thread = std::thread::Builder::new()
        .name("rabs-edge-io".to_owned())
        .spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(work))
                .map_err(|_| WorkError::Panicked);
            let waker = {
                let mut state = worker_state
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                state.result = Some(result);
                state.waker.take()
            };
            drop(permit);
            if let Some(waker) = waker {
                waker.wake();
            }
        })
        .map_err(|error| WorkError::Spawn(error.to_string()))?;
    Ok(OwnedWork {
        shared,
        thread: Some(thread),
        consumed: false,
    })
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum WorkError {
    Saturated,
    Spawn(String),
    Panicked,
    Consumed,
}
impl std::fmt::Display for WorkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Saturated => write!(f, "edge blocking-work capacity exhausted"),
            Self::Spawn(error) => write!(f, "edge work thread could not start: {error}"),
            Self::Panicked => write!(
                f,
                "edge blocking work panicked; side effects may be partial"
            ),
            Self::Consumed => write!(f, "edge work completion already consumed"),
        }
    }
}

struct Completion<T> {
    result: Option<Result<T, WorkError>>,
    waker: Option<Waker>,
}

pub(super) struct OwnedWork<T> {
    shared: Arc<Mutex<Completion<T>>>,
    thread: Option<JoinHandle<()>>,
    consumed: bool,
}
impl<T> OwnedWork<T> {
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<T, WorkError>> {
        if self.consumed {
            return Poll::Ready(Err(WorkError::Consumed));
        }
        let result = {
            let mut state = self
                .shared
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if let Some(result) = state.result.take() {
                result
            } else {
                // Registration and completion use the same lock: there is no
                // check-then-register window in which a wake can be lost.
                state.waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
        };
        self.consumed = true;
        if let Some(thread) = self.thread.take()
            && thread.join().is_err()
        {
            return Poll::Ready(Err(WorkError::Panicked));
        }
        Poll::Ready(result)
    }

    pub(super) async fn wait(&mut self) -> Result<T, WorkError> {
        poll_fn(|cx| self.poll(cx)).await
    }
}
impl<T> Drop for OwnedWork<T> {
    fn drop(&mut self) {
        if let Some(thread) = self.thread.take() {
            // Do not discard the shared result before joining: it can own a
            // flight guard whose Drop releases coordinator accounting.
            let _ = thread.join();
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "completion_reservation_tests.rs"]
mod completion_reservation_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use std::sync::mpsc;
    use std::task::Wake;
    use std::time::{Duration, Instant};

    struct ThreadWake(std::thread::Thread);
    impl Wake for ThreadWake {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }
    fn wait<T>(work: &mut OwnedWork<T>) -> Result<T, WorkError> {
        let waker = Waker::from(Arc::new(ThreadWake(std::thread::current())));
        let mut cx = Context::from_waker(&waker);
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            match work.poll(&mut cx) {
                Poll::Ready(result) => return result,
                Poll::Pending => {
                    assert!(Instant::now() < until, "owned work did not wake");
                    std::thread::park_timeout(Duration::from_millis(10));
                }
            }
        }
    }

    #[test]
    fn shared_capacity_refuses_before_work_runs_and_releases_exactly_once() {
        let limit = Limit::new(1);
        let (release, blocked) = mpsc::channel();
        let mut task = limit.spawn(move || blocked.recv().unwrap()).unwrap();
        let called = Arc::new(AtomicBool::new(false));
        let other = Arc::clone(&called);
        assert!(matches!(
            limit
                .clone()
                .spawn(move || other.store(true, Ordering::Release)),
            Err(WorkError::Saturated)
        ));
        assert!(!called.load(Ordering::Acquire));
        release.send(7).unwrap();
        assert_eq!(wait(&mut task).unwrap(), 7);
        assert_eq!(wait(&mut task), Err(WorkError::Consumed));
        drop(task);
        let permit = limit.acquire().unwrap();
        assert!(limit.acquire().is_none());
        drop(permit);
        assert!(limit.acquire().is_some());
    }

    #[test]
    fn completed_results_wait_in_order_without_fresh_hits_stealing_capacity() {
        let limit = Limit::new(1);
        let occupied = limit.acquire().unwrap();
        let waker = Waker::from(Arc::new(ThreadWake(std::thread::current())));
        let mut cx = Context::from_waker(&waker);
        let mut first = Box::pin(limit.wait());
        let mut second = Box::pin(limit.wait());
        assert!(first.as_mut().poll(&mut cx).is_pending());
        assert!(second.as_mut().poll(&mut cx).is_pending());
        drop(occupied);
        assert!(
            limit.acquire().is_none(),
            "new hits must respect completed results"
        );
        assert!(second.as_mut().poll(&mut cx).is_pending());
        let Poll::Ready(first_permit) = first.as_mut().poll(&mut cx) else {
            panic!("first completed result did not receive the free slot");
        };
        assert!(second.as_mut().poll(&mut cx).is_pending());
        drop(first_permit);
        let Poll::Ready(second_permit) = second.as_mut().poll(&mut cx) else {
            panic!("second completed result did not receive the free slot");
        };
        drop(second_permit);
        assert!(limit.acquire().is_some());
    }

    #[test]
    fn abandoned_installation_waiters_release_queue_ownership_and_wake_successors() {
        struct CountWake(AtomicUsize);
        impl Wake for CountWake {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let limit = Limit::new(1);
        let occupied = limit.acquire().unwrap();
        let wake = Arc::new(CountWake(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&wake));
        let mut cx = Context::from_waker(&waker);
        let mut abandoned = Box::pin(limit.wait());
        let mut survivor = Box::pin(limit.wait());
        assert!(abandoned.as_mut().poll(&mut cx).is_pending());
        assert!(survivor.as_mut().poll(&mut cx).is_pending());
        drop(occupied);
        let before = wake.0.load(Ordering::SeqCst);
        assert!(before > 0, "permit release must wake a registered waiter");
        drop(abandoned);
        assert!(wake.0.load(Ordering::SeqCst) > before);
        let Poll::Ready(permit) = survivor.as_mut().poll(&mut cx) else {
            panic!("cancelled predecessor stranded free capacity");
        };
        drop(permit);
        assert_eq!(limit.active.load(Ordering::Acquire), 0);
        assert!(limit.waiters.lock().unwrap().is_empty());
    }

    #[test]
    fn cancelling_all_waiters_restores_ordinary_nonblocking_admission() {
        let limit = Limit::new(1);
        let occupied = limit.acquire().unwrap();
        let waker = Waker::from(Arc::new(ThreadWake(std::thread::current())));
        let mut cx = Context::from_waker(&waker);
        let mut waiter = Box::pin(limit.wait());
        for _ in 0..8 {
            assert!(waiter.as_mut().poll(&mut cx).is_pending());
        }
        assert_eq!(limit.waiters.lock().unwrap().len(), 1);
        drop(waiter);
        assert!(limit.waiters.lock().unwrap().is_empty());
        assert!(
            limit.acquire().is_none(),
            "cancellation cannot release another owner"
        );
        drop(occupied);
        assert!(limit.acquire().is_some());
    }

    #[test]
    fn pending_work_yields_and_completion_wakes_the_waiter() {
        let limit = Limit::new(1);
        let (release, blocked) = mpsc::channel();
        let mut task = limit.spawn(move || blocked.recv().unwrap()).unwrap();
        let waker = Waker::from(Arc::new(ThreadWake(std::thread::current())));
        assert!(task.poll(&mut Context::from_waker(&waker)).is_pending());
        release.send("finished").unwrap();
        assert_eq!(wait(&mut task).unwrap(), "finished");
    }

    #[test]
    fn cancelled_owner_joins_writer_and_drops_unconsumed_result() {
        struct Receipt(Arc<AtomicBool>);
        impl Drop for Receipt {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }
        let limit = Limit::new(1);
        let wrote = Arc::new(AtomicBool::new(false));
        let released = Arc::new(AtomicBool::new(false));
        let (start, started) = mpsc::channel();
        let (finish, finishing) = mpsc::channel();
        let writer_done = Arc::clone(&wrote);
        let receipt = Receipt(Arc::clone(&released));
        let task = limit
            .spawn(move || {
                start.send(()).unwrap();
                finishing.recv().unwrap();
                writer_done.store(true, Ordering::Release);
                receipt
            })
            .unwrap();
        started.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(limit.acquire().is_none());
        let dropper = std::thread::spawn(move || drop(task));
        assert!(!wrote.load(Ordering::Acquire));
        assert!(!released.load(Ordering::Acquire));
        assert!(
            limit.acquire().is_none(),
            "cancellation must not free a writer's permit"
        );
        finish.send(()).unwrap();
        dropper.join().unwrap();
        assert!(wrote.load(Ordering::Acquire));
        assert!(released.load(Ordering::Acquire));
        assert!(limit.acquire().is_some());
    }

    #[test]
    fn panics_are_typed_and_do_not_leak_capacity() {
        let limit = Limit::new(1);
        let mut task = limit
            .spawn(|| -> () { panic!("injected blocking work failure") })
            .unwrap();
        assert_eq!(wait(&mut task), Err(WorkError::Panicked));
        assert!(limit.acquire().is_some());
        assert!(matches!(
            Limit::new(0).spawn(|| ()),
            Err(WorkError::Saturated)
        ));
    }

    #[test]
    fn blocked_materializer_does_not_consume_shadow_capacity() {
        let materializers = Limit::new(1);
        let shadow = Limit::new(1);
        let (release, blocked) = mpsc::channel();
        let mut materialization = materializers
            .spawn(move || blocked.recv().unwrap())
            .unwrap();
        let mut consult = shadow.spawn(|| "pass-through").unwrap();
        assert_eq!(wait(&mut consult).unwrap(), "pass-through");
        assert!(materializers.acquire().is_none());
        release.send(()).unwrap();
        wait(&mut materialization).unwrap();
    }

    #[test]
    fn stage_handoff_keeps_capacity_without_a_live_thread_and_finishes_when_full() {
        let limit = Limit::new(2);
        let reservation = limit.acquire().unwrap();
        let mut capture = reservation.stage(|| b"captured bytes".to_vec()).unwrap();
        let (bytes, reservation) = wait(&mut capture).unwrap();
        assert!(capture.thread.is_none(), "capture thread has been joined");
        drop(capture);
        let competitor = limit.acquire().unwrap();
        assert!(limit.acquire().is_none(), "handoff remains admitted");
        let mut publication = reservation.finish(move || bytes).unwrap();
        assert_eq!(wait(&mut publication).unwrap(), b"captured bytes");
        // Publication freed exactly its own slot, not the competitor's.
        let freed = limit.acquire().unwrap();
        assert!(limit.acquire().is_none());
        drop(freed);
        drop(competitor);
        assert_eq!(limit.active.load(Ordering::Acquire), 0);
    }

    #[test]
    fn successive_stages_never_mint_or_double_spend_a_reservation() {
        let limit = Limit::new(1);
        let mut reservation = limit.acquire().unwrap();
        for stage in 0..16 {
            let mut work = reservation.stage(move || stage).unwrap();
            let (result, next) = wait(&mut work).unwrap();
            assert_eq!(result, stage);
            assert!(work.thread.is_none());
            assert!(limit.acquire().is_none());
            assert!(matches!(wait(&mut work), Err(WorkError::Consumed)));
            reservation = next;
        }
        drop(reservation);
        assert_eq!(limit.active.load(Ordering::Acquire), 0);
    }

    #[test]
    fn stage_and_final_panics_release_capacity_once() {
        let limit = Limit::new(1);
        let mut stage = limit
            .acquire()
            .unwrap()
            .stage(|| -> () { panic!("capture failed") })
            .unwrap();
        assert!(matches!(wait(&mut stage), Err(WorkError::Panicked)));
        assert_eq!(limit.active.load(Ordering::Acquire), 0);
        let mut final_stage = limit
            .acquire()
            .unwrap()
            .finish(|| -> () { panic!("publication failed") })
            .unwrap();
        assert_eq!(wait(&mut final_stage), Err(WorkError::Panicked));
        assert_eq!(limit.active.load(Ordering::Acquire), 0);
    }

    #[test]
    fn dropping_an_unconsumed_stage_joins_before_releasing_capacity_and_payload() {
        struct Payload(Arc<AtomicBool>);
        impl Drop for Payload {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }
        let limit = Limit::new(1);
        let dropped = Arc::new(AtomicBool::new(false));
        let payload = Payload(Arc::clone(&dropped));
        let (started, entered) = mpsc::channel();
        let (release, continue_work) = mpsc::channel();
        let work = limit
            .acquire()
            .unwrap()
            .stage(move || {
                started.send(()).unwrap();
                continue_work.recv_timeout(Duration::from_secs(5)).unwrap();
                payload
            })
            .unwrap();
        entered.recv_timeout(Duration::from_secs(5)).unwrap();
        let (dropping, drop_started) = mpsc::channel();
        let dropper = std::thread::spawn(move || {
            dropping.send(()).unwrap();
            drop(work);
        });
        drop_started.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(!dropped.load(Ordering::Acquire));
        assert!(limit.acquire().is_none());
        release.send(()).unwrap();
        dropper.join().unwrap();
        assert!(dropped.load(Ordering::Acquire));
        assert_eq!(limit.active.load(Ordering::Acquire), 0);
    }

    #[test]
    fn abandoning_a_completed_handoff_never_runs_a_final_stage() {
        let limit = Limit::new(1);
        let mut work = limit.acquire().unwrap().stage(|| 17).unwrap();
        let (result, reservation) = wait(&mut work).unwrap();
        assert_eq!(result, 17);
        assert_eq!(limit.active.load(Ordering::Acquire), 1);
        drop(reservation);
        assert_eq!(limit.active.load(Ordering::Acquire), 0);
        let mut ordinary = limit.spawn(|| 23).unwrap();
        assert_eq!(wait(&mut ordinary).unwrap(), 23);
    }

    #[test]
    fn discarded_ready_payload_is_cleaned_before_its_reservation_is_released() {
        struct Payload {
            limit: Limit,
            checked: Arc<AtomicBool>,
        }
        impl Drop for Payload {
            fn drop(&mut self) {
                assert!(self.limit.acquire().is_none());
                self.checked.store(true, Ordering::Release);
            }
        }
        let limit = Limit::new(1);
        let checked = Arc::new(AtomicBool::new(false));
        let payload = Payload {
            limit: limit.clone(),
            checked: Arc::clone(&checked),
        };
        let work = limit.acquire().unwrap().stage(move || payload).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !work.thread.as_ref().unwrap().is_finished() {
            assert!(Instant::now() < deadline, "stage did not finish");
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(limit.acquire().is_none());
        drop(work);
        assert!(checked.load(Ordering::Acquire));
        assert_eq!(limit.active.load(Ordering::Acquire), 0);
    }
}
