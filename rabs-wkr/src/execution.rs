//! Session-owned blocking execution and monotonic cancellation (S5/G008).
//!
//! The worker's Asupersync reactor must remain available while a compiler
//! runs. One owned thread performs blocking sandbox/process/drain work;
//! completion wakes the reactor. Dropping its owner requests cancellation
//! and JOINS, never detaches a compiler that may still mutate its workspace.
//! The executor must cooperate through `ExecutionControl::reason`.

use std::future::poll_fn;
use std::io;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::session::ExecResult;

/// Default worker-local upper bound; a request may shorten, never extend it.
pub const DEFAULT_EXECUTION_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// Why an execution stopped other than by the compiler's natural exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum StopReason {
    /// Explicit cancellation of this request, not of another request's PID.
    Cancelled = 1,
    /// The worker's monotonic execution budget expired.
    DeadlineExceeded = 2,
    /// The session owner disappeared or the coordinator connection failed.
    SessionLost = 3,
}

impl StopReason {
    /// Stable wire label; these are never deterministic compiler failures.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Cancelled => "cancelled",
            Self::DeadlineExceeded => "deadline-exceeded",
            Self::SessionLost => "session-lost",
        }
    }

    /// Non-success compatibility exit. The typed reason is authoritative;
    /// even a compiler trapping TERM and exiting zero remains interrupted.
    #[must_use]
    pub const fn exit_code(self) -> i32 {
        match self {
            Self::Cancelled => 130,
            Self::DeadlineExceeded => 124,
            Self::SessionLost => 125,
        }
    }

    fn from_state(state: u8) -> Option<Self> {
        match state {
            1 => Some(Self::Cancelled),
            2 => Some(Self::DeadlineExceeded),
            3 => Some(Self::SessionLost),
            _ => None,
        }
    }
}

const RUNNING: u8 = 0;
const FINISHED: u8 = 4;

/// Per-execution control, with no PID or other process-global authority.
/// The first stop reason wins; completion fences all later cancellation.
#[derive(Debug, Clone)]
pub struct ExecutionControl {
    state: Arc<AtomicU8>,
    deadline: Instant,
}

impl ExecutionControl {
    /// Start a finite local budget. Wall-clock jumps cannot extend it.
    pub fn new(timeout: Duration) -> io::Result<Self> {
        if timeout.is_zero() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "zero execution timeout"));
        }
        let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "execution timeout overflow")
        })?;
        Ok(Self {
            state: Arc::new(AtomicU8::new(RUNNING)),
            deadline,
        })
    }

    /// Request a stop. False means another stop or completion already won.
    pub fn cancel(&self, reason: StopReason) -> bool {
        self.state
            .compare_exchange(RUNNING, reason as u8, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// Observe cancellation, recording expiry on the first expired poll.
    #[must_use]
    pub fn reason(&self) -> Option<StopReason> {
        if self.state.load(Ordering::Acquire) == RUNNING && Instant::now() >= self.deadline {
            self.cancel(StopReason::DeadlineExceeded);
        }
        StopReason::from_state(self.state.load(Ordering::Acquire))
    }

    /// Freeze the result frontier. A subsequent cancel cannot relabel a
    /// completed execution or affect the next request on this session.
    pub(crate) fn finish(&self) -> Option<StopReason> {
        let _ = self.reason();
        match self.state.compare_exchange(
            RUNNING,
            FINISHED,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => None,
            Err(state) => StopReason::from_state(state),
        }
    }
}

/// Completion is available only after the executor's process/drain cleanup.
#[derive(Debug)]
pub struct ExecutionCompletion {
    /// The real captured result, with a nonzero exit on interrupted work.
    pub result: ExecResult,
    /// Typed interruption, independent of the compiler's exit-code convention.
    pub stop_reason: Option<StopReason>,
}

#[derive(Default)]
struct CompletionState {
    result: Option<Result<ExecutionCompletion, String>>,
    waker: Option<Waker>,
}

/// One non-clone owner for a running sandbox execution. Session admission
/// permits only one at a time; no unbounded queue or detached work is hidden here.
pub struct ExecutionTask {
    request_id: u64,
    control: ExecutionControl,
    state: Arc<Mutex<CompletionState>>,
    thread: Option<JoinHandle<()>>,
    completed: bool,
}

impl ExecutionTask {
    /// Spawn a cooperating blocking executor. Thread creation failures do not
    /// admit work. Panics become typed execution errors, never successful offers.
    pub fn spawn(
        request_id: u64,
        timeout: Duration,
        execute: impl FnOnce(ExecutionControl) -> ExecResult + Send + 'static,
    ) -> io::Result<Self> {
        let control = ExecutionControl::new(timeout)?;
        let state = Arc::new(Mutex::new(CompletionState::default()));
        let worker_control = control.clone();
        let worker_state = Arc::clone(&state);
        let thread = std::thread::Builder::new()
            .name(format!("rabs-exec-{request_id}"))
            .spawn(move || {
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    execute(worker_control.clone())
                }));
                let stop_reason = worker_control.finish();
                let result = match outcome {
                    Ok(mut result) if result.request_id == request_id => {
                        if let Some(reason) = stop_reason {
                            result.exit_code = reason.exit_code();
                        }
                        Ok(ExecutionCompletion { result, stop_reason })
                    }
                    Ok(_) => Err("executor returned a different request identity".to_owned()),
                    Err(_) => Err("execution thread panicked".to_owned()),
                };
                let waker = {
                    let mut state = worker_state.lock().unwrap_or_else(|e| e.into_inner());
                    state.result = Some(result);
                    state.waker.take()
                };
                if let Some(waker) = waker {
                    waker.wake();
                }
            })?;
        Ok(Self {
            request_id,
            control,
            state,
            thread: Some(thread),
            completed: false,
        })
    }

    /// Session-scoped identity; cancellations must match this exactly.
    #[must_use]
    pub fn request_id(&self) -> u64 {
        self.request_id
    }

    /// Request cancellation without blocking the reactor on process cleanup.
    pub fn cancel(&self, reason: StopReason) -> bool {
        self.control.cancel(reason)
    }

    /// Poll completion alongside incoming control frames. Registers the waker
    /// under the same mutex as publication, so no completion wakeup is lost.
    pub fn poll_completion(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<ExecutionCompletion, String>> {
        if self.completed {
            return Poll::Ready(Err("execution completion already consumed".to_owned()));
        }
        let result = {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(result) = state.result.take() {
                result
            } else {
                state.waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
        };
        self.completed = true;
        if let Some(thread) = self.thread.take()
            && thread.join().is_err()
        {
            return Poll::Ready(Err("execution owner thread failed".to_owned()));
        }
        Poll::Ready(result)
    }

    /// Await cleanup without monopolizing the async runtime thread.
    pub async fn wait(&mut self) -> Result<ExecutionCompletion, String> {
        poll_fn(|cx| self.poll_completion(cx)).await
    }
}

impl Drop for ExecutionTask {
    fn drop(&mut self) {
        if let Some(thread) = self.thread.take() {
            // Exceptional future-drop/shutdown path. Normal disconnect handling
            // calls cancel + wait asynchronously before reaching this guard.
            self.control.cancel(StopReason::SessionLost);
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use std::task::Wake;

    struct ThreadWake(std::thread::Thread);
    impl Wake for ThreadWake {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }

    fn wait(task: &mut ExecutionTask) -> Result<ExecutionCompletion, String> {
        let waker = Waker::from(Arc::new(ThreadWake(std::thread::current())));
        let mut cx = Context::from_waker(&waker);
        loop {
            match task.poll_completion(&mut cx) {
                Poll::Ready(result) => return result,
                Poll::Pending => std::thread::park_timeout(Duration::from_millis(100)),
            }
        }
    }

    fn result(request_id: u64) -> ExecResult {
        ExecResult {
            request_id,
            exit_code: 0,
            stdout_sha256: crate::session::sha256_hex(b"output"),
            stderr_sha256: crate::session::sha256_hex(b""),
            executed: true,
            residual_group_members: 0,
            stdout_spill_bytes: 0,
            stderr_spill_bytes: 0,
            stdout_spill_path: None,
            stderr_spill_path: None,
        }
    }

    #[test]
    fn first_stop_wins_and_completion_fences_late_cancellation() {
        let control = ExecutionControl::new(Duration::from_secs(10)).unwrap();
        assert!(control.cancel(StopReason::Cancelled));
        assert!(!control.cancel(StopReason::SessionLost));
        assert_eq!(control.finish(), Some(StopReason::Cancelled));
        let completed = ExecutionControl::new(Duration::from_secs(10)).unwrap();
        assert_eq!(completed.finish(), None);
        assert!(!completed.cancel(StopReason::Cancelled));
        assert_eq!(completed.reason(), None);
        assert!(ExecutionControl::new(Duration::ZERO).is_err());
    }

    #[test]
    fn deadline_cannot_be_reported_as_success_even_if_executor_exits_zero() {
        let mut task = ExecutionTask::spawn(7, Duration::from_millis(30), |control| {
            while control.reason().is_none() {
                std::thread::sleep(Duration::from_millis(2));
            }
            result(7)
        })
        .unwrap();
        let completed = wait(&mut task).unwrap();
        assert_eq!(completed.stop_reason, Some(StopReason::DeadlineExceeded));
        assert_eq!(completed.result.exit_code, 124);
        assert!(completed.result.executed);
    }

    #[test]
    fn dropping_session_owner_cancels_and_joins_instead_of_detaching() {
        let cleaned = Arc::new(AtomicBool::new(false));
        let worker_cleaned = Arc::clone(&cleaned);
        let task = ExecutionTask::spawn(8, Duration::from_secs(5), move |control| {
            while control.reason().is_none() {
                std::thread::sleep(Duration::from_millis(2));
            }
            worker_cleaned.store(true, Ordering::Release);
            result(8)
        })
        .unwrap();
        drop(task);
        assert!(cleaned.load(Ordering::Acquire));
    }

    #[test]
    fn natural_completion_and_panics_are_distinct() {
        let mut task = ExecutionTask::spawn(9, Duration::from_secs(5), |_| result(9)).unwrap();
        let completion = wait(&mut task).unwrap();
        assert_eq!(completion.stop_reason, None);
        assert_eq!(completion.result.exit_code, 0);
        assert!(!task.cancel(StopReason::Cancelled));
        let mut panicked = ExecutionTask::spawn(10, Duration::from_secs(5), |_| {
            panic!("test executor panic")
        })
        .unwrap();
        assert!(wait(&mut panicked).unwrap_err().contains("panicked"));
        let mut misbound = ExecutionTask::spawn(11, Duration::from_secs(5), |_| result(12)).unwrap();
        assert!(wait(&mut misbound).unwrap_err().contains("identity"));
    }
}
