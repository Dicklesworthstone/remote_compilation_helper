//! Bounded, owned blocking work for the live edge.
//!
//! A future cancellation is not cancellation of a filesystem write. The task
//! owns and joins its thread, including on drop. The capacity permit belongs to
//! that thread until all work finishes; disconnects cannot create extra writers.
//! Normal waiting yields to the native reactor. Drop may wait for a filesystem
//! operation that the operating system cannot interrupt, rather than detach it.

use std::future::poll_fn;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::thread::JoinHandle;

#[derive(Clone)]
pub(super) struct Limit {
    active: Arc<AtomicUsize>,
    maximum: usize,
}

impl Limit {
    pub(super) fn new(maximum: usize) -> Self {
        Self { active: Arc::new(AtomicUsize::new(0)), maximum }
    }

    pub(super) fn acquire(&self) -> Option<Permit> {
        self.active.fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
            (active < self.maximum).then(|| active + 1)
        }).ok()?;
        Some(Permit(Arc::clone(&self.active)))
    }

    /// Admission has no queue and never waits behind another caller. Spawn
    /// failure drops the unstarted closure and its permit without running it.
    pub(super) fn spawn<T, F>(&self, work: F) -> Result<OwnedWork<T>, WorkError>
    where
        T: Send + 'static,
        F: FnOnce() -> T + Send + 'static,
    {
        let permit = self.acquire().ok_or(WorkError::Saturated)?;
        let shared = Arc::new(Mutex::new(Completion { result: None, waker: None }));
        let worker_state = Arc::clone(&shared);
        let thread = std::thread::Builder::new().name("rabs-edge-io".to_owned())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(work))
                    .map_err(|_| WorkError::Panicked);
                let waker = {
                    let mut state = worker_state.lock().unwrap_or_else(|error| error.into_inner());
                    state.result = Some(result);
                    state.waker.take()
                };
                drop(permit);
                if let Some(waker) = waker { waker.wake(); }
            }).map_err(|error| WorkError::Spawn(error.to_string()))?;
        Ok(OwnedWork { shared, thread: Some(thread), consumed: false })
    }
}

/// Non-clone permit; admission and release cannot be duplicated by a caller.
pub(super) struct Permit(Arc<AtomicUsize>);
impl Drop for Permit {
    fn drop(&mut self) { self.0.fetch_sub(1, Ordering::AcqRel); }
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
            Self::Panicked => write!(f, "edge blocking work panicked; side effects may be partial"),
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
        if self.consumed { return Poll::Ready(Err(WorkError::Consumed)); }
        let result = {
            let mut state = self.shared.lock().unwrap_or_else(|error| error.into_inner());
            if let Some(result) = state.result.take() { result }
            else {
                // Registration and completion use the same lock: there is no
                // check-then-register window in which a wake can be lost.
                state.waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
        };
        self.consumed = true;
        if let Some(thread) = self.thread.take() && thread.join().is_err() {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use std::sync::mpsc;
    use std::task::Wake;
    use std::time::{Duration, Instant};

    struct ThreadWake(std::thread::Thread);
    impl Wake for ThreadWake {
        fn wake(self: Arc<Self>) { self.0.unpark(); }
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
        assert!(matches!(limit.clone().spawn(move || other.store(true, Ordering::Release)),
            Err(WorkError::Saturated)));
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
            fn drop(&mut self) { self.0.store(true, Ordering::Release); }
        }
        let limit = Limit::new(1);
        let wrote = Arc::new(AtomicBool::new(false));
        let released = Arc::new(AtomicBool::new(false));
        let (start, started) = mpsc::channel();
        let (finish, finishing) = mpsc::channel();
        let writer_done = Arc::clone(&wrote);
        let receipt = Receipt(Arc::clone(&released));
        let task = limit.spawn(move || {
            start.send(()).unwrap();
            finishing.recv().unwrap();
            writer_done.store(true, Ordering::Release);
            receipt
        }).unwrap();
        started.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(limit.acquire().is_none());
        let dropper = std::thread::spawn(move || drop(task));
        assert!(!wrote.load(Ordering::Acquire));
        assert!(!released.load(Ordering::Acquire));
        assert!(limit.acquire().is_none(), "cancellation must not free a writer's permit");
        finish.send(()).unwrap();
        dropper.join().unwrap();
        assert!(wrote.load(Ordering::Acquire));
        assert!(released.load(Ordering::Acquire));
        assert!(limit.acquire().is_some());
    }

    #[test]
    fn panics_are_typed_and_do_not_leak_capacity() {
        let limit = Limit::new(1);
        let mut task = limit.spawn(|| -> () { panic!("injected blocking work failure") }).unwrap();
        assert_eq!(wait(&mut task), Err(WorkError::Panicked));
        assert!(limit.acquire().is_some());
        assert!(matches!(Limit::new(0).spawn(|| ()), Err(WorkError::Saturated)));
    }

    #[test]
    fn blocked_materializer_does_not_consume_shadow_capacity() {
        let materializers = Limit::new(1);
        let shadow = Limit::new(1);
        let (release, blocked) = mpsc::channel();
        let mut materialization = materializers.spawn(move || blocked.recv().unwrap()).unwrap();
        let mut consult = shadow.spawn(|| "pass-through").unwrap();
        assert_eq!(wait(&mut consult).unwrap(), "pass-through");
        assert!(materializers.acquire().is_none());
        release.send(()).unwrap();
        wait(&mut materialization).unwrap();
    }
}
