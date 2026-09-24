//! Session-owned blocking execution and monotonic cancellation (S5/G008).
//!
//! The worker's Asupersync reactor must remain available while a compiler
//! runs. One owned thread performs blocking sandbox/process/drain work;
//! completion wakes the reactor. Dropping its owner requests cancellation
//! and JOINS, never detaches a compiler that may still mutate its workspace.
//! The executor must cooperate through `ExecutionControl::reason`.

mod preview;
pub use preview::{OUTPUT_PREVIEW_VERSION, output_preview_reply};
use rabs_asupersync::stream_drain::preview::LiveOutputPreview;
use rabs_protocol::lease_semantics::{RequestExecutionLease, RequestExecutionLeaseIdentity};
use std::future::poll_fn;
use std::io;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::artifacts::{ArtifactPlan, CapturedArtifacts};
use crate::output::CapturedOutputs;
use crate::result_spool::RetentionTarget;
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
    /// The request's worker-local execution lease expired without renewal.
    LeaseExpired = 4,
}

impl StopReason {
    /// Stable wire label; these are never deterministic compiler failures.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Cancelled => "cancelled",
            Self::DeadlineExceeded => "deadline-exceeded",
            Self::SessionLost => "session-lost",
            Self::LeaseExpired => "lease-expired",
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
            Self::LeaseExpired => 125,
        }
    }

    fn from_state(state: u8) -> Option<Self> {
        match state & !FINISHED {
            1 => Some(Self::Cancelled),
            2 => Some(Self::DeadlineExceeded),
            3 => Some(Self::SessionLost),
            4 => Some(Self::LeaseExpired),
            _ => None,
        }
    }
}

const RUNNING: u8 = 0;
// Completion is independent of the stop reason. A cancelled execution must
// become just as immutable as a naturally completed one, without erasing why
// it stopped. The high bit leaves every typed stop reason independently intact.
const FINISHED: u8 = 0x80;

#[derive(Debug, Default)]
struct OutputCapture {
    requested: bool,
    result: Option<Result<CapturedOutputs, String>>,
}

#[derive(Debug, Default)]
struct ArtifactCapture {
    plan: Option<ArtifactPlan>,
    result: Option<Result<CapturedArtifacts, String>>,
}

#[derive(Debug)]
struct ExecutionLease {
    origin: Instant,
    lease: RequestExecutionLease,
}

impl ExecutionLease {
    fn own_millis(&self, now: Instant) -> Option<u64> {
        u64::try_from(now.checked_duration_since(self.origin)?.as_millis()).ok()
    }

    fn live(&mut self, now: Instant) -> bool {
        self.own_millis(now).is_some_and(|millis| self.lease.live(millis).is_ok())
    }
}

/// Per-execution control, with no PID or other process-global authority.
/// The first stop reason wins; completion fences all later cancellation.
#[derive(Debug, Clone)]
pub struct ExecutionControl {
    state: Arc<AtomicU8>,
    deadline: Instant,
    lease: Arc<Mutex<Option<ExecutionLease>>>,
    output: Arc<Mutex<OutputCapture>>,
    artifacts: Arc<Mutex<ArtifactCapture>>,
    preview: Arc<LiveOutputPreview>,
}

impl ExecutionControl {
    /// Start a finite local budget. Wall-clock jumps cannot extend it.
    pub fn new(timeout: Duration) -> io::Result<Self> {
        Self::new_at(timeout, None, Instant::now())
    }

    /// Arm the exact admitted request's lease before its executor thread starts.
    /// Renewals extend only this lease; the hard execution timeout stays fixed.
    pub fn new_with_lease(
        timeout: Duration,
        identity: RequestExecutionLeaseIdentity,
        ttl_ms: u64,
    ) -> io::Result<Self> {
        Self::new_at(timeout, Some((identity, ttl_ms)), Instant::now())
    }

    fn new_at(
        timeout: Duration,
        lease: Option<(RequestExecutionLeaseIdentity, u64)>,
        now: Instant,
    ) -> io::Result<Self> {
        if timeout.is_zero() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "zero execution timeout"));
        }
        let deadline = now.checked_add(timeout).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "execution timeout overflow")
        })?;
        let lease = lease.map(|(identity, ttl_ms)| {
            RequestExecutionLease::new(identity, ttl_ms, 0)
                .map(|lease| ExecutionLease { origin: now, lease })
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, format!("execution lease: {error:?}")))
        }).transpose()?;
        Ok(Self {
            state: Arc::new(AtomicU8::new(RUNNING)),
            deadline,
            lease: Arc::new(Mutex::new(lease)),
            output: Arc::new(Mutex::new(OutputCapture::default())),
            artifacts: Arc::new(Mutex::new(ArtifactCapture::default())),
            preview: Arc::new(LiveOutputPreview::default()),
        })
    }

    /// Request a stop. False means another stop or completion already won.
    pub fn cancel(&self, reason: StopReason) -> bool {
        let mut lease = self.lease.lock().unwrap_or_else(|e| e.into_inner());
        let accepted = self.state
            .compare_exchange(RUNNING, reason as u8, Ordering::AcqRel, Ordering::Acquire)
            .is_ok();
        if accepted && let Some(lease) = lease.as_mut() {
            let _ = lease.lease.close();
        }
        accepted
    }

    /// Observe cancellation, recording expiry on the first expired poll.
    #[must_use]
    pub fn reason(&self) -> Option<StopReason> {
        let mut lease = self.lease.lock().unwrap_or_else(|e| e.into_inner());
        self.observe_reason(&mut lease, Instant::now())
    }

    fn observe_reason(&self, lease: &mut Option<ExecutionLease>, now: Instant) -> Option<StopReason> {
        if self.state.load(Ordering::Acquire) == RUNNING {
            let reason = if now >= self.deadline {
                Some(StopReason::DeadlineExceeded)
            } else if lease.as_mut().is_some_and(|lease| !lease.live(now)) {
                Some(StopReason::LeaseExpired)
            } else {
                None
            };
            if let Some(reason) = reason {
                self.state.store(reason as u8, Ordering::Release);
                if let Some(lease) = lease.as_mut() {
                    let _ = lease.lease.close();
                }
            }
        }
        StopReason::from_state(self.state.load(Ordering::Acquire))
    }

    /// Renew only the existing request-bound lease. A stale sequence, terminal
    /// execution, expired lease, or elapsed hard timeout can never be revived.
    pub fn renew_execution_lease(&self, sequence: u64) -> bool {
        let mut lease = self.lease.lock().unwrap_or_else(|e| e.into_inner());
        self.renew_lease_at(&mut lease, sequence, Instant::now())
    }

    fn renew_lease_at(&self, lease: &mut Option<ExecutionLease>, sequence: u64, now: Instant) -> bool {
        if self.observe_reason(lease, now).is_some() || self.state.load(Ordering::Acquire) != RUNNING {
            return false;
        }
        let Some(lease) = lease.as_mut() else { return false; };
        let identity = *lease.lease.identity();
        let renewed = lease.own_millis(now)
            .is_some_and(|millis| lease.lease.renew(&identity, sequence, millis).is_ok());
        if !renewed && lease.lease.is_closed() {
            self.state.store(StopReason::LeaseExpired as u8, Ordering::Release);
        }
        renewed
    }

    /// Enable complete output capture before invoking the executor. Digest-only
    /// callers do not pay for the additional disk snapshots. This is local
    /// execution configuration, not authority to open an arbitrary remote path.
    /// Requests after the frozen result frontier have no effect.
    pub fn request_output_capture(&self) {
        let mut output = self.output.lock().unwrap_or_else(|e| e.into_inner());
        if self.state.load(Ordering::Acquire) & FINISHED == 0 {
            output.requested = true;
        }
    }

    /// Whether the owner requested readable output as well as digests.
    #[must_use]
    pub fn output_capture_requested(&self) -> bool {
        self.output.lock().unwrap_or_else(|e| e.into_inner()).requested
    }

    /// Attach a complete capture (or a precise capture failure) exactly once.
    /// Interrupted executions may still attach their pre-kill diagnostics,
    /// but only BEFORE the owner freezes the result frontier.
    /// The task validates the captured digests against its final ExecResult.
    pub fn retain_outputs(&self, capture: Result<CapturedOutputs, String>) -> io::Result<()> {
        let mut output = self.output.lock().unwrap_or_else(|e| e.into_inner());
        if output.result.is_some() || self.state.load(Ordering::Acquire) & FINISHED != 0 {
            return Err(io::Error::other("output capture already completed"));
        }
        output.requested = true;
        output.result = Some(capture);
        Ok(())
    }

    fn take_outputs(&self) -> Option<Result<CapturedOutputs, String>> {
        self.output.lock().unwrap_or_else(|e| e.into_inner()).result.take()
    }

    /// Configure the exact artifact declaration before the executor starts.
    /// A second configuration cannot silently replace the first contract.
    fn request_artifacts(&self, plan: ArtifactPlan) -> io::Result<()> {
        let mut artifacts = self.artifacts.lock().unwrap_or_else(|e| e.into_inner());
        if artifacts.plan.is_some() || self.state.load(Ordering::Acquire) != RUNNING {
            return Err(io::Error::other("artifact declaration already fixed"));
        }
        artifacts.plan = Some(plan);
        Ok(())
    }

    /// The validated contract used to construct the canonical output mount.
    #[must_use]
    pub fn artifact_plan(&self) -> Option<ArtifactPlan> {
        self.artifacts.lock().unwrap_or_else(|e| e.into_inner()).plan.clone()
    }

    /// Retain a complete offer or its capture failure, bound to this execution's
    /// declaration. The result frontier independently rejects missing artifacts.
    pub fn retain_artifacts(&self, capture: Result<CapturedArtifacts, String>) -> io::Result<()> {
        let mut artifacts = self.artifacts.lock().unwrap_or_else(|e| e.into_inner());
        if artifacts.plan.is_none() || artifacts.result.is_some()
            || self.state.load(Ordering::Acquire) & FINISHED != 0
        {
            return Err(io::Error::other("artifact capture not requested or already completed"));
        }
        if capture.as_ref().is_ok_and(|bundle| Some(bundle.plan()) != artifacts.plan.as_ref()) {
            return Err(io::Error::other("artifact capture does not match declaration"));
        }
        artifacts.result = Some(capture);
        Ok(())
    }

    /// Freeze the result frontier, including interrupted executions. Retain
    /// the first stop reason while rejecting all later capture writes. Taking
    /// the capture locks in one fixed order makes the freeze atomic relative
    /// to their check-and-attach operations, not just to cancellation.
    pub(crate) fn finish(&self) -> Option<StopReason> {
        let _output = self.output.lock().unwrap_or_else(|e| e.into_inner());
        let _artifacts = self.artifacts.lock().unwrap_or_else(|e| e.into_inner());
        let mut lease = self.lease.lock().unwrap_or_else(|e| e.into_inner());
        let _ = self.observe_reason(&mut lease, Instant::now());
        if let Some(lease) = lease.as_mut() {
            let _ = lease.lease.close();
        }
        StopReason::from_state(self.state.fetch_or(FINISHED, Ordering::AcqRel))
    }
}

/// Completion is available only after the executor's process/drain cleanup.
#[derive(Debug)]
pub struct ExecutionCompletion {
    /// The real captured result, with a nonzero exit on interrupted work.
    pub result: ExecResult,
    /// Typed interruption, independent of the compiler's exit-code convention.
    pub stop_reason: Option<StopReason>,
    /// Complete readable streams when capture was requested and execution ran.
    /// Ownership transfers to the session, not to process-global path names.
    pub outputs: Option<CapturedOutputs>,
    /// Exact declared artifacts of a successful, uninterrupted, cleaned execution.
    /// Failed/cancelled work never returns partial artifact offers.
    pub artifacts: Option<CapturedArtifacts>,
}

fn complete_result(
    control: &ExecutionControl,
    mut result: ExecResult,
    stop_reason: Option<StopReason>,
) -> Result<ExecutionCompletion, String> {
    // Process cleanup is a prerequisite for EVERY completion, including
    // digest-only requests, compiler failures and interrupted executions.
    // Otherwise a resumable result can outlive children that still mutate
    // the supposedly finished workspace. This check precedes retention.
    if result.residual_group_members != 0 {
        return Err("execution cleanup left residual process-group members".to_owned());
    }
    if result.executed && !(0..=255).contains(&result.exit_code) {
        return Err("executor returned an invalid exit status".to_owned());
    }
    if !result.executed && result.exit_code == 0 {
        return Err("unexecuted request cannot report successful completion".to_owned());
    }
    if let Some(reason) = stop_reason {
        result.exit_code = reason.exit_code();
    }
    let outputs = match control.take_outputs() {
        Some(Ok(outputs)) if outputs.stdout.sha256() == result.stdout_sha256
            && outputs.stderr.sha256() == result.stderr_sha256 => Some(outputs),
        Some(Ok(_)) => return Err("output capture does not match result digests".to_owned()),
        Some(Err(error)) => return Err(format!("output capture failed: {error}")),
        None if control.output_capture_requested() && result.executed => {
            return Err("executor omitted requested output capture".to_owned());
        }
        None => None,
    };
    let mut capture = control.artifacts.lock().unwrap_or_else(|e| e.into_inner());
    let captured = capture.result.take();
    let artifacts = if capture.plan.is_some() && result.executed && result.exit_code == 0
        && stop_reason.is_none()
    {
        match captured {
            Some(Ok(artifacts)) if Some(artifacts.plan()) == capture.plan.as_ref() => Some(artifacts),
            Some(Ok(_)) => return Err("artifact capture does not match declaration".to_owned()),
            Some(Err(error)) => return Err(format!("artifact capture failed: {error}")),
            None => return Err("executor omitted requested artifact capture".to_owned()),
        }
    } else {
        // Do not offer partially compiled objects even if an executor attached
        // them before cancellation won. Diagnostics remain available separately.
        None
    };
    Ok(ExecutionCompletion { result, stop_reason, outputs, artifacts })
}

#[derive(Default)]
struct CompletionState {
    result: Option<Result<ExecutionCompletion, String>>,
    retained_result_digest: Option<String>,
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
        Self::spawn_controlled(request_id, ExecutionControl::new(timeout)?, None, execute)
    }

    /// Fix the artifact contract BEFORE spawning, so even a very fast executor
    /// cannot finish before its output requirements are registered.
    pub fn spawn_with_artifacts(
        request_id: u64,
        timeout: Duration,
        artifacts: ArtifactPlan,
        execute: impl FnOnce(ExecutionControl) -> ExecResult + Send + 'static,
    ) -> io::Result<Self> {
        let control = ExecutionControl::new(timeout)?;
        control.request_artifacts(artifacts)?;
        Self::spawn_controlled(request_id, control, None, execute)
    }

    /// Production delivery with an optional durable result sink. Sealing runs on
    /// the SAME blocking owner after process cleanup, never on the control loop.
    /// A seal failure cannot become a successful or resumable completion.
    pub fn spawn_for_delivery(
        request_id: u64,
        timeout: Duration,
        artifacts: Option<ArtifactPlan>,
        retention: Option<RetentionTarget>,
        execute: impl FnOnce(ExecutionControl) -> ExecResult + Send + 'static,
    ) -> io::Result<Self> {
        Self::spawn_for_delivery_with_lease(request_id, timeout, artifacts, retention, None, execute)
    }

    /// Production delivery with the authenticated session's exact execution
    /// lease. It is validated and armed before any executor thread can run.
    pub fn spawn_for_delivery_with_lease(
        request_id: u64,
        timeout: Duration,
        artifacts: Option<ArtifactPlan>,
        retention: Option<RetentionTarget>,
        lease: Option<(RequestExecutionLeaseIdentity, u64)>,
        execute: impl FnOnce(ExecutionControl) -> ExecResult + Send + 'static,
    ) -> io::Result<Self> {
        let control = match lease {
            Some((identity, ttl_ms)) => {
                if identity.request_id != request_id {
                    return Err(io::Error::new(io::ErrorKind::InvalidInput, "execution lease request differs from task"));
                }
                ExecutionControl::new_with_lease(timeout, identity, ttl_ms)?
            }
            None => ExecutionControl::new(timeout)?,
        };
        if let Some(plan) = artifacts { control.request_artifacts(plan)?; }
        if retention.is_some() { control.request_output_capture(); }
        Self::spawn_controlled(request_id, control, retention, execute)
    }

    fn spawn_controlled(
        request_id: u64,
        control: ExecutionControl,
        retention: Option<RetentionTarget>,
        execute: impl FnOnce(ExecutionControl) -> ExecResult + Send + 'static,
    ) -> io::Result<Self> {
        let state = Arc::new(Mutex::new(CompletionState::default()));
        let worker_control = control.clone();
        let worker_state = Arc::clone(&state);
        let thread = std::thread::Builder::new()
            .name(format!("rabs-exec-{request_id}"))
            .spawn(move || {
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let result = execute(worker_control.clone());
                    let stop_reason = worker_control.finish();
                    if result.request_id != request_id {
                        return Err("executor returned a different request identity".to_owned());
                    }
                    let mut completion = complete_result(&worker_control, result, stop_reason)?;
                    let retained = match retention {
                        Some(target) if completion.result.executed => Some(
                            target.seal(&mut completion).map_err(|error| format!("result retention failed: {error}"))?
                        ),
                        _ => None,
                    };
                    Ok((completion, retained))
                }));
                let _ = worker_control.finish();
                let (result, retained_result_digest) = match outcome {
                    Ok(Ok((completion, retained))) => (Ok(completion), retained),
                    Ok(Err(error)) => (Err(error), None),
                    Err(_) => (Err("execution thread panicked".to_owned()), None),
                };
                let waker = {
                    let mut state = worker_state.lock().unwrap_or_else(|e| e.into_inner());
                    state.result = Some(result);
                    state.retained_result_digest = retained_result_digest;
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
    pub fn request_id(&self) -> u64 { self.request_id }

    /// Present only after complete bytes and their seal are durably stored.
    /// The session must commit this digest to its journal before sending output.
    #[must_use]
    pub fn retained_result_digest(&self) -> Option<String> {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).retained_result_digest.clone()
    }

    /// Request cancellation without blocking the reactor on process cleanup.
    pub fn cancel(&self, reason: StopReason) -> bool { self.control.cancel(reason) }

    /// The session validates the incoming lease identity before calling this
    /// method. The control retains that identity and enforces sequence/expiry.
    pub fn renew_execution_lease(&self, sequence: u64) -> bool {
        self.control.renew_execution_lease(sequence)
    }

    /// Poll completion alongside incoming control frames. Registers the waker
    /// under the same mutex as publication, so no completion wakeup is lost.
    pub fn poll_completion(&mut self, cx: &mut Context<'_>) -> Poll<Result<ExecutionCompletion, String>> {
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
        if let Some(thread) = self.thread.take() && thread.join().is_err() {
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
        fn wake(self: Arc<Self>) { self.0.unpark(); }
    }

    fn wait(task: &mut ExecutionTask) -> Result<ExecutionCompletion, String> {
        let waker = Waker::from(Arc::new(ThreadWake(std::thread::current())));
        let mut cx = Context::from_waker(&waker);
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match task.poll_completion(&mut cx) {
                Poll::Ready(result) => return result,
                Poll::Pending => {
                    assert!(Instant::now() < deadline, "execution test timed out");
                    std::thread::park_timeout(Duration::from_millis(100));
                }
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

    fn lease_identity(request_id: u64) -> RequestExecutionLeaseIdentity {
        RequestExecutionLeaseIdentity {
            session_id: 11,
            lease_id: 12,
            request_id,
            request_sha256: [3; 32],
            boot_generation: 4,
            incarnation: 5,
        }
    }

    fn observe_at(control: &ExecutionControl, now: Instant) -> Option<StopReason> {
        let mut lease = control.lease.lock().unwrap();
        control.observe_reason(&mut lease, now)
    }

    fn renew_at(control: &ExecutionControl, sequence: u64, now: Instant) -> bool {
        let mut lease = control.lease.lock().unwrap();
        control.renew_lease_at(&mut lease, sequence, now)
    }

    #[test]
    fn execution_lease_renews_before_boundary_but_replay_and_expiry_never_rearm() {
        let origin = Instant::now();
        let control = ExecutionControl::new_at(
            Duration::from_secs(10), Some((lease_identity(40), 1_000)), origin,
        ).unwrap();
        assert_eq!(observe_at(&control, origin + Duration::from_millis(999)), None);
        assert!(!renew_at(&control, 0, origin + Duration::from_millis(999)));
        assert!(renew_at(&control, 1, origin + Duration::from_millis(999)));
        assert_eq!(observe_at(&control, origin + Duration::from_millis(1_998)), None);
        assert!(!renew_at(&control, 1, origin + Duration::from_millis(1_998)));
        assert!(!renew_at(&control, 0, origin + Duration::from_millis(1_998)));
        assert!(!renew_at(&control, 2, origin + Duration::from_millis(1_999)));
        assert_eq!(control.reason(), Some(StopReason::LeaseExpired));
        assert!(!renew_at(&control, 3, origin + Duration::from_secs(5)));
        assert_eq!(control.finish(), Some(StopReason::LeaseExpired));
        assert_eq!(control.finish(), Some(StopReason::LeaseExpired));
        assert_eq!(control.state.load(Ordering::Acquire), FINISHED | StopReason::LeaseExpired as u8);
    }

    #[test]
    fn lease_renewals_cannot_extend_the_hard_timeout_or_recover_a_clock_regression() {
        let origin = Instant::now();
        let bounded = ExecutionControl::new_at(
            Duration::from_millis(1_500), Some((lease_identity(41), 1_000)), origin,
        ).unwrap();
        assert!(renew_at(&bounded, 1, origin + Duration::from_millis(900)));
        assert!(!renew_at(&bounded, 2, origin + Duration::from_millis(1_500)));
        assert_eq!(bounded.reason(), Some(StopReason::DeadlineExceeded));

        let regressed = ExecutionControl::new_at(
            Duration::from_secs(10), Some((lease_identity(42), 1_000)), origin,
        ).unwrap();
        assert_eq!(observe_at(&regressed, origin + Duration::from_millis(500)), None);
        assert!(!renew_at(&regressed, 1, origin + Duration::from_millis(499)));
        assert_eq!(regressed.reason(), Some(StopReason::LeaseExpired));
        assert!(!renew_at(&regressed, 2, origin + Duration::from_millis(600)));
    }

    #[test]
    fn completion_and_cancellation_close_the_lease_without_changing_the_outcome() {
        for reason in [None, Some(StopReason::Cancelled), Some(StopReason::SessionLost)] {
            let control = ExecutionControl::new_with_lease(
                Duration::from_secs(10), lease_identity(43), 1_000,
            ).unwrap();
            if let Some(reason) = reason {
                assert!(control.cancel(reason));
                assert!(!control.renew_execution_lease(1));
            }
            assert_eq!(control.finish(), reason);
            assert!(!control.renew_execution_lease(2));
            assert_eq!(observe_at(&control, control.deadline + Duration::from_secs(1)), reason);
            assert_eq!(control.finish(), reason);
            assert!(control.lease.lock().unwrap().as_ref().unwrap().lease.is_closed());
        }
        let unleased = ExecutionControl::new(Duration::from_secs(10)).unwrap();
        assert!(!unleased.renew_execution_lease(1));
        assert_eq!(unleased.reason(), None);
    }

    #[test]
    fn renewal_racing_completion_cannot_reopen_the_frozen_execution() {
        use std::sync::Barrier;
        for _ in 0..32 {
            let control = ExecutionControl::new_with_lease(
                Duration::from_secs(10), lease_identity(44), 1_000,
            ).unwrap();
            let barrier = Arc::new(Barrier::new(2));
            let renew_control = control.clone();
            let renew_barrier = Arc::clone(&barrier);
            let renewal = std::thread::spawn(move || {
                renew_barrier.wait();
                renew_control.renew_execution_lease(1)
            });
            barrier.wait();
            assert_eq!(control.finish(), None);
            let accepted = renewal.join().unwrap();
            let lease = control.lease.lock().unwrap();
            let lease = &lease.as_ref().unwrap().lease;
            assert_eq!(lease.renewal_seq(), u64::from(accepted));
            assert!(lease.is_closed());
            assert_eq!(control.state.load(Ordering::Acquire), FINISHED);
        }
    }

    #[test]
    fn invalid_or_foreign_lease_is_refused_before_the_executor_starts() {
        for (id, ttl) in [(45, 999), (45, 60_001), (46, 1_000)] {
            let started = Arc::new(AtomicBool::new(false));
            let execute_started = Arc::clone(&started);
            let task = ExecutionTask::spawn_for_delivery_with_lease(
                45, Duration::from_secs(10), None, None, Some((lease_identity(id), ttl)),
                move |_| {
                    execute_started.store(true, Ordering::Release);
                    result(45)
                },
            );
            assert!(task.is_err());
            assert!(!started.load(Ordering::Acquire));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn expired_lease_stops_a_real_process_tree_and_preserves_diagnostics() {
        use rabs_asupersync::process_groups::{ManagedProcessGroup, ProcessGroupSpec, members_from_proc};
        use rabs_asupersync::stream_drain::DrainLimits;
        use std::process::Stdio;
        use std::sync::atomic::AtomicU32;

        let root = tempfile::tempdir().unwrap();
        let spill = root.path().join("spill");
        let pgid = Arc::new(AtomicU32::new(0));
        let worker_pgid = Arc::clone(&pgid);
        let mut task = ExecutionTask::spawn_for_delivery_with_lease(
            47, Duration::from_secs(5), None, None, Some((lease_identity(47), 1_000)),
            move |control| {
                assert_eq!(control.reason(), None, "lease must be armed before executor invocation");
                let spec = ProcessGroupSpec::new("sh", [
                    "-c".to_owned(),
                    "printf prefix; printf diagnostic >&2; sleep 30 & wait".to_owned(),
                ]);
                let group = ManagedProcessGroup::spawn_with(&spec, |command| {
                    command.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
                }).unwrap();
                worker_pgid.store(group.pgid(), Ordering::Release);
                let output = group.wait_with_bounded_drain_controlled(
                    &DrainLimits { resident_bound: 64, spill_dir: spill },
                    || control.reason().is_some(),
                ).unwrap();
                let capture = CapturedOutputs::from_lanes(&output.stdout, &output.stderr).unwrap();
                let mut observed = result(47);
                observed.stdout_sha256 = capture.stdout.sha256().to_owned();
                observed.stderr_sha256 = capture.stderr.sha256().to_owned();
                observed.residual_group_members = output.residual_group_members;
                // Even a nominal zero result cannot turn expired ownership into success.
                control.retain_outputs(Ok(capture)).unwrap();
                observed
            },
        ).unwrap();
        let mut completed = wait(&mut task).unwrap();
        assert_eq!(completed.stop_reason, Some(StopReason::LeaseExpired));
        assert_eq!(completed.result.exit_code, 125);
        assert_eq!(completed.result.residual_group_members, 0);
        assert!(completed.artifacts.is_none());
        let outputs = completed.outputs.as_mut().unwrap();
        assert_eq!(outputs.stdout.read_chunk(0, 64).unwrap(), b"prefix");
        assert_eq!(outputs.stderr.read_chunk(0, 64).unwrap(), b"diagnostic");
        let pgid = pgid.load(Ordering::Acquire);
        assert_ne!(pgid, 0);
        assert!(members_from_proc(pgid).is_empty());
        assert!(!std::path::Path::new(&format!("/proc/{pgid}")).exists());
        assert!(!task.renew_execution_lease(1));
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
            while control.reason().is_none() { std::thread::sleep(Duration::from_millis(2)); }
            result(7)
        }).unwrap();
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
            while control.reason().is_none() { std::thread::sleep(Duration::from_millis(2)); }
            worker_cleaned.store(true, Ordering::Release);
            result(8)
        }).unwrap();
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
        }).unwrap();
        assert!(wait(&mut panicked).unwrap_err().contains("panicked"));
        let mut misbound = ExecutionTask::spawn(11, Duration::from_secs(5), |_| result(12)).unwrap();
        assert!(wait(&mut misbound).unwrap_err().contains("identity"));
    }

    fn outputs(bytes: &[u8]) -> CapturedOutputs {
        CapturedOutputs {
            stdout: crate::output::CapturedStream::from_reader(bytes, bytes.len() as u64).unwrap(),
            stderr: crate::output::CapturedStream::from_reader(&b""[..], 0).unwrap(),
        }
    }

    #[test]
    fn completion_owns_full_output_even_after_cancellation() {
        let mut task = ExecutionTask::spawn(12, Duration::from_secs(5), |control| {
            control.cancel(StopReason::Cancelled);
            control.retain_outputs(Ok(outputs(b"output"))).unwrap();
            assert!(control.retain_outputs(Ok(outputs(b"second"))).is_err());
            result(12)
        }).unwrap();
        let mut completion = wait(&mut task).unwrap();
        assert_eq!(completion.stop_reason, Some(StopReason::Cancelled));
        assert_eq!(completion.result.exit_code, 130);
        assert_eq!(completion.outputs.as_mut().unwrap().stdout.read_chunk(0, 64).unwrap(), b"output");
    }

    #[test]
    fn missing_failed_and_misbound_captures_never_produce_successful_completion() {
        for case in 0..3 {
            let mut task = ExecutionTask::spawn(13, Duration::from_secs(5), move |control| {
                control.request_output_capture();
                match case {
                    0 => {}
                    1 => control.retain_outputs(Err("disk full".to_owned())).unwrap(),
                    _ => control.retain_outputs(Ok(outputs(b"wrong bytes"))).unwrap(),
                }
                result(13)
            }).unwrap();
            assert!(wait(&mut task).unwrap_err().contains("output"));
        }
    }

    fn artifact_plan(name: &str) -> ArtifactPlan {
        ArtifactPlan::new("dep".into(), vec![name.into()]).unwrap()
    }

    fn artifacts(plan: ArtifactPlan) -> CapturedArtifacts {
        let prepared = crate::artifacts::PreparedArtifacts::new(plan).unwrap();
        std::fs::write(prepared.backing().join("a"), b"compiled").unwrap();
        prepared.capture(|| false).unwrap()
    }

    #[test]
    fn artifact_success_requires_the_exact_capture_not_just_exit_zero() {
        for case in 0..4 {
            let mut task = ExecutionTask::spawn_with_artifacts(20, Duration::from_secs(5), artifact_plan("a"), move |control| {
                assert!(control.request_artifacts(artifact_plan("b")).is_err());
                match case {
                    0 => {}
                    1 => control.retain_artifacts(Err("missing file".into())).unwrap(),
                    _ => control.retain_artifacts(Ok(artifacts(artifact_plan("a")))).unwrap(),
                }
                let mut result = result(20);
                if case == 2 { result.residual_group_members = 1; }
                result
            }).unwrap();
            let completion = wait(&mut task);
            if case == 3 {
                let mut completion = completion.unwrap();
                assert_eq!(completion.artifacts.as_mut().unwrap().read_chunk("a", 0, 64).unwrap(), b"compiled");
            } else if case == 2 {
                assert!(completion.unwrap_err().contains("residual process-group members"));
            } else {
                assert!(completion.unwrap_err().contains("artifact"));
            }
        }
        let control = ExecutionControl::new(Duration::from_secs(5)).unwrap();
        control.request_artifacts(artifact_plan("b")).unwrap();
        assert!(control.retain_artifacts(Ok(artifacts(artifact_plan("a")))).is_err());
    }

    #[test]
    fn failed_and_interrupted_executions_retain_diagnostics_but_never_artifacts() {
        for cancelled in [false, true] {
            let mut task = ExecutionTask::spawn_with_artifacts(21, Duration::from_secs(5), artifact_plan("a"), move |control| {
                control.retain_outputs(Ok(outputs(b"output"))).unwrap();
                control.retain_artifacts(Ok(artifacts(artifact_plan("a")))).unwrap();
                let mut result = result(21);
                if cancelled { control.cancel(StopReason::Cancelled); }
                else { result.exit_code = 1; }
                result
            }).unwrap();
            let completion = wait(&mut task).unwrap();
            assert!(completion.artifacts.is_none());
            assert!(completion.outputs.is_some());
            assert_ne!(completion.result.exit_code, 0);
        }
    }

    #[test]
    fn every_finished_state_rejects_late_capture_and_keeps_its_stop_reason() {
        for reason in [
            None,
            Some(StopReason::Cancelled),
            Some(StopReason::DeadlineExceeded),
            Some(StopReason::SessionLost),
            Some(StopReason::LeaseExpired),
        ] {
            let control = ExecutionControl::new(Duration::from_secs(5)).unwrap();
            control.request_artifacts(artifact_plan("a")).unwrap();
            if let Some(reason) = reason {
                assert!(control.cancel(reason));
            }
            assert_eq!(control.finish(), reason);
            assert_eq!(control.finish(), reason, "freezing is idempotent");
            assert_eq!(control.reason(), reason);
            assert!(!control.cancel(StopReason::SessionLost));
            assert!(control.retain_outputs(Err("late output".into())).is_err());
            assert!(control.retain_artifacts(Err("late artifact".into())).is_err());
            assert!(control.take_outputs().is_none());
            assert!(control.artifacts.lock().unwrap().result.is_none());
            control.request_output_capture();
            assert!(!control.output_capture_requested());
        }
    }

    #[test]
    fn concurrent_cancel_and_finish_choose_one_immutable_frontier() {
        use std::sync::Barrier;

        for _ in 0..64 {
            let control = ExecutionControl::new(Duration::from_secs(5)).unwrap();
            let barrier = Arc::new(Barrier::new(2));
            let other_control = control.clone();
            let other_barrier = Arc::clone(&barrier);
            let other = std::thread::spawn(move || {
                other_barrier.wait();
                other_control.cancel(StopReason::Cancelled)
            });
            barrier.wait();
            let reason = control.finish();
            let cancellation_won = other.join().unwrap();
            assert_eq!(reason, cancellation_won.then_some(StopReason::Cancelled));
            assert_eq!(control.reason(), reason);
            assert_eq!(control.finish(), reason);
            assert!(control.retain_outputs(Err("late".into())).is_err());
        }
    }

    #[test]
    fn residual_children_refuse_completion_without_an_artifact_contract() {
        for exit_code in [0, 1, 137] {
            for reason in [None, Some(StopReason::Cancelled), Some(StopReason::SessionLost)] {
                let mut task = ExecutionTask::spawn_for_delivery(
                    30,
                    Duration::from_secs(5),
                    None,
                    None,
                    move |control| {
                        if let Some(reason) = reason {
                            control.cancel(reason);
                        }
                        let mut result = result(30);
                        result.exit_code = exit_code;
                        result.residual_group_members = 1;
                        result
                    },
                ).unwrap();
                assert!(wait(&mut task).unwrap_err().contains("residual process-group members"));
                assert!(task.retained_result_digest().is_none());
            }
        }
    }

    #[test]
    fn invalid_status_and_unexecuted_success_never_become_completion() {
        for exit_code in [i32::MIN, -1, 256, i32::MAX] {
            let mut task = ExecutionTask::spawn(31, Duration::from_secs(5), move |_| {
                let mut result = result(31);
                result.exit_code = exit_code;
                result
            }).unwrap();
            assert!(wait(&mut task).unwrap_err().contains("invalid exit status"));
        }
        let mut task = ExecutionTask::spawn(32, Duration::from_secs(5), |_| {
            let mut result = result(32);
            result.executed = false;
            result
        }).unwrap();
        assert!(wait(&mut task).unwrap_err().contains("unexecuted request"));

        // A real pre-execution refusal is not silently relabelled as a
        // compiler failure or forced to supply nonexistent output captures.
        let mut refused = ExecutionTask::spawn(33, Duration::from_secs(5), |control| {
            control.request_output_capture();
            let mut result = result(33);
            result.executed = false;
            result.exit_code = -1;
            result
        }).unwrap();
        let completion = wait(&mut refused).unwrap();
        assert!(!completion.result.executed);
        assert_eq!(completion.result.exit_code, -1);
        assert!(completion.outputs.is_none());
    }
}
