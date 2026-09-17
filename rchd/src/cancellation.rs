//! Build cancellation orchestrator with deterministic state machine (bd-1yt6).
//!
//! Provides bounded escalation (SIGTERM → remote kill → SIGKILL),
//! deterministic cleanup (slots, history, events), and per-worker
//! cancellation debt for reliability integration.

mod batch;

use crate::DaemonContext;
use crate::api::{CancelAllBuildsResponse, CancelBuildResponse, CancelledBuildInfo};
use crate::events::EventBus;
use rch_common::{
    BuildCancellationMetadata, BuildCancellationWorkerHealth, WorkerId, WorkerStatus,
};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, warn};

fn duration_millis_u64(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

// ── Cancel Reason ────────────────────────────────────────────────────────

/// Why a build cancellation was initiated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CancelReason {
    /// Explicit user/agent request.
    User,
    /// Build exceeded its timeout.
    Timeout,
    /// Stuck detector determined build is stuck.
    StuckDetector,
    /// Build was evicted from the queue.
    QueueEviction,
}

impl std::fmt::Display for CancelReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::User => write!(f, "user"),
            Self::Timeout => write!(f, "timeout"),
            Self::StuckDetector => write!(f, "stuck_detector"),
            Self::QueueEviction => write!(f, "queue_eviction"),
        }
    }
}

// ── Cancellation State ───────────────────────────────────────────────────

/// State machine for an individual build cancellation lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CancellationState {
    /// Cancel has been requested but not yet acted on.
    Requested,
    /// SIGTERM sent to local hook process, waiting for grace period.
    TermSent,
    /// SSH kill sent to remote worker process.
    RemoteKillSent,
    /// Escalated to SIGKILL locally after remote kill failed.
    Escalated,
    /// Cancellation completed: slots released, history updated, event emitted.
    Completed,
    /// Termination was not confirmed; active history and reservations are retained.
    Failed,
}

impl std::fmt::Display for CancellationState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Requested => write!(f, "requested"),
            Self::TermSent => write!(f, "term_sent"),
            Self::RemoteKillSent => write!(f, "remote_kill_sent"),
            Self::Escalated => write!(f, "escalated"),
            Self::Completed => write!(f, "completed"),
            Self::Failed => write!(f, "failed"),
        }
    }
}

// ── Cancellation Record ──────────────────────────────────────────────────

/// Tracks the lifecycle of a single build cancellation.
#[derive(Debug, Clone, Serialize)]
pub struct CancellationRecord {
    pub build_id: u64,
    pub worker_id: String,
    pub state: CancellationState,
    pub reason: CancelReason,
    #[serde(skip)]
    pub requested_at: Instant,
    #[serde(skip)]
    pub completed_at: Option<Instant>,
    pub escalation_count: u32,
    pub remote_kill_attempted: bool,
    pub cleanup_ok: bool,
    /// Slots originally held by the build (captured at cancel time).
    pub slots: u32,
    pub slots_released: u32,
    pub hook_pid: u32,
    /// Boot+start evidence binding the recorded PID to its owning wrapper.
    #[serde(skip)]
    pub hook_process_identity: Option<String>,
    pub remote_pgid_file: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct CancellationWorkerHealthSnapshot {
    status: String,
    speed_score: f64,
    used_slots: u32,
    available_slots: u32,
    pressure_state: String,
    pressure_reason_code: String,
}

fn cancellation_operation_id(build_id: u64) -> String {
    format!("cancel-{build_id}")
}

fn worker_status_label(status: WorkerStatus) -> &'static str {
    match status {
        WorkerStatus::Healthy => "healthy",
        WorkerStatus::Degraded => "degraded",
        WorkerStatus::Unreachable => "unreachable",
        WorkerStatus::Draining => "draining",
        WorkerStatus::Drained => "drained",
        WorkerStatus::Disabled => "disabled",
    }
}

fn worker_health_for_history(
    snapshot: &CancellationWorkerHealthSnapshot,
) -> BuildCancellationWorkerHealth {
    BuildCancellationWorkerHealth {
        status: snapshot.status.clone(),
        speed_score: snapshot.speed_score,
        used_slots: snapshot.used_slots,
        available_slots: snapshot.available_slots,
        pressure_state: snapshot.pressure_state.clone(),
        pressure_reason_code: snapshot.pressure_reason_code.clone(),
    }
}

fn push_decision_stage(path: &mut Vec<&'static str>, stage: &'static str) {
    if path.last().copied() != Some(stage) {
        path.push(stage);
    }
}

fn cancellation_decision_path(record: &CancellationRecord) -> Vec<&'static str> {
    let mut path = vec!["requested"];

    let force_path = record.remote_kill_attempted
        && record.escalation_count == 0
        && matches!(
            record.state,
            CancellationState::Completed | CancellationState::Failed | CancellationState::Escalated
        );

    if force_path {
        push_decision_stage(&mut path, "escalated");
        push_decision_stage(&mut path, "remote_kill_sent");
    } else {
        push_decision_stage(&mut path, "term_sent");
        if record.remote_kill_attempted {
            push_decision_stage(&mut path, "remote_kill_sent");
        }
        if record.escalation_count > 1 || matches!(record.state, CancellationState::Escalated) {
            push_decision_stage(&mut path, "escalated");
        }
    }

    let terminal = match record.state {
        CancellationState::Completed => "completed",
        CancellationState::Failed => "failed",
        CancellationState::Requested => "requested",
        CancellationState::TermSent => "term_sent",
        CancellationState::RemoteKillSent => "remote_kill_sent",
        CancellationState::Escalated => "escalated",
    };
    push_decision_stage(&mut path, terminal);

    path
}

fn cancellation_escalation_stage(record: &CancellationRecord) -> &'static str {
    if record.escalation_count > 1 || matches!(record.state, CancellationState::Escalated) {
        "sigkill"
    } else if record.remote_kill_attempted {
        "remote_kill"
    } else {
        "term"
    }
}

/// Sending a signal is not evidence that both sides of a remote build stopped.
fn cancellation_terminal_state(local_stopped: bool, remote_stopped: bool) -> CancellationState {
    if local_stopped && remote_stopped {
        CancellationState::Completed
    } else {
        CancellationState::Failed
    }
}

// ── Configuration ────────────────────────────────────────────────────────

/// Policy knobs for the cancellation orchestrator.
#[derive(Debug, Clone)]
pub struct CancellationConfig {
    /// How long to wait after SIGTERM before escalating.
    pub grace_period: Duration,
    /// How long to wait for SIGKILL to take effect.
    pub kill_timeout: Duration,
    /// Timeout for SSH kill command to remote worker.
    pub remote_kill_timeout: Duration,
    /// Maximum number of non-forced escalation stages attempted.
    pub max_escalations: u32,
    /// Overall timeout for termination stages, including forced cancellation.
    /// Accounting and failure reporting follow without freeing unconfirmed work.
    pub cleanup_timeout: Duration,
}

impl Default for CancellationConfig {
    fn default() -> Self {
        Self {
            grace_period: Duration::from_secs(5),
            kill_timeout: Duration::from_secs(3),
            remote_kill_timeout: Duration::from_secs(10),
            max_escalations: 3,
            cleanup_timeout: Duration::from_secs(15),
        }
    }
}

// ── Per-Worker Debt Tracker ──────────────────────────────────────────────

/// Tracks cancellation frequency per worker for reliability integration.
/// All counters use timestamped vectors pruned to the DEBT_WINDOW so stale
/// events do not permanently inflate a worker's cancellation debt.
#[derive(Debug, Clone, Default)]
struct WorkerCancelStats {
    /// Recent cancellation timestamps (within window).
    recent_cancellations: Vec<Instant>,
    /// Recent escalation timestamps (within window).
    recent_escalations: Vec<Instant>,
    /// Recent cleanup failure timestamps (within window).
    recent_cleanup_failures: Vec<Instant>,
    /// Total builds observed (for rate computation).
    total_builds: u64,
}

const DEBT_WINDOW: Duration = Duration::from_secs(300); // 5 minutes

// ── Orchestrator ─────────────────────────────────────────────────────────

/// Drives build cancellations through a deterministic state machine with
/// bounded escalation and cleanup guarantees. Clones share admission and debt.
#[derive(Clone)]
pub struct CancellationOrchestrator {
    config: CancellationConfig,
    /// Short, synchronous map operations only; never held across an await.
    /// A synchronous lock lets an attempt release its claim in Drop.
    active: Arc<Mutex<HashMap<u64, CancellationRecord>>>,
    /// Per-worker cancellation debt tracking.
    worker_stats: Arc<RwLock<HashMap<String, WorkerCancelStats>>>,
    /// Bound bulk work across concurrent requests and orchestrator clones.
    bulk_permits: Arc<tokio::sync::Semaphore>,
    /// Event bus for structured event emission.
    events: EventBus,
}

/// Owns only the in-flight claim, never the build reservation. Dropping an
/// interrupted operation must permit a retry, not certify remote termination.
struct CancellationAttempt {
    build_id: u64,
    active: Arc<Mutex<HashMap<u64, CancellationRecord>>>,
}

impl Drop for CancellationAttempt {
    fn drop(&mut self) {
        self.active
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .remove(&self.build_id);
    }
}

impl CancellationOrchestrator {
    /// Create a new orchestrator with the given config and event bus.
    pub fn new(config: CancellationConfig, events: EventBus) -> Self {
        Self {
            config,
            active: Arc::new(Mutex::new(HashMap::new())),
            worker_stats: Arc::new(RwLock::new(HashMap::new())),
            bulk_permits: Arc::new(tokio::sync::Semaphore::new(batch::MAX_BULK_CANCELLATIONS)),
            events,
        }
    }

    /// Admit one cancellation and await its result. Once admitted, the daemon
    /// task owns termination AND finalization; cancelling this wait must not
    /// abandon remote cleanup or interrupt a claimed history record's release.
    /// This survives caller cancellation, not shutdown of the daemon runtime.
    pub async fn cancel_build(
        &self,
        ctx: &DaemonContext,
        build_id: u64,
        reason: CancelReason,
        force: bool,
    ) -> CancelBuildResponse {
        let (mut record, project_id, attempt) = {
            let mut active = self
                .active
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if let Some(existing) = active.get(&build_id) {
                return CancelBuildResponse {
                    status: "cancelling".to_string(),
                    build_id,
                    worker_id: Some(existing.worker_id.clone()),
                    project_id: ctx
                        .history
                        .active_build(build_id)
                        .map(|build| build.project_id),
                    message: Some(format!(
                        "Cancellation already in progress (state: {})",
                        existing.state
                    )),
                    slots_released: existing.slots_released,
                };
            }
            // Resolve history after acquiring admission, not before an async
            // lock wait during which a prior cancellation may have finalized it.
            let Some(build) = ctx.history.active_build(build_id) else {
                return CancelBuildResponse {
                    status: "error".to_string(),
                    build_id,
                    worker_id: None,
                    project_id: None,
                    message: Some("Build not found or already completed".to_string()),
                    slots_released: 0,
                };
            };
            let record = CancellationRecord {
                build_id,
                worker_id: build.worker_id,
                state: CancellationState::Requested,
                reason,
                requested_at: Instant::now(),
                completed_at: None,
                escalation_count: 0,
                remote_kill_attempted: false,
                cleanup_ok: true,
                slots: build.slots,
                slots_released: 0,
                hook_pid: build.hook_pid,
                hook_process_identity: build.hook_process_identity.clone(),
                remote_pgid_file: build.remote_pgid_file,
            };
            active.insert(build_id, record.clone());
            (
                record,
                build.project_id,
                CancellationAttempt {
                    build_id,
                    active: Arc::clone(&self.active),
                },
            )
        };

        let owner = self.clone();
        let context = ctx.clone();
        let failed_worker = record.worker_id.clone();
        let failed_project = project_id.clone();
        // There is no await between admission and transferring the guard into
        // the owned task. Dropping a JoinHandle detaches, rather than aborts,
        // the operation. Duplicate requests still share the same admission map.
        let operation = tokio::spawn(async move {
            let _attempt = attempt;
            // A normal completion may have won before this task was scheduled.
            // Do not signal the stale hook from the admission-time snapshot.
            let Some(current) = context.history.active_build(build_id) else {
                return CancelBuildResponse {
                    status: "error".to_string(),
                    build_id,
                    worker_id: Some(record.worker_id),
                    project_id: Some(project_id),
                    message: Some("Build completed before cancellation started".to_string()),
                    slots_released: 0,
                };
            };
            // A persisted PID alone cannot identify its owner after restart.
            // Do not signal it until exact process identity is available.
            if current.hook_pid != 0
                && (current.hook_process_identity.is_none()
                    || crate::history::process_identity(current.hook_pid)
                        != current.hook_process_identity)
            {
                return CancelBuildResponse {
                    status: "failed".into(),
                    build_id,
                    worker_id: Some(record.worker_id),
                    project_id: Some(project_id),
                    message: Some(
                        "Wrapper process identity unverified; reservation retained".into(),
                    ),
                    slots_released: 0,
                };
            }
            record.hook_pid = current.hook_pid;
            record.remote_pgid_file = current.remote_pgid_file;
            record.hook_process_identity = current.hook_process_identity.clone();
            record.slots = current.slots;

            owner.events.emit(
                "cancellation_requested",
                &serde_json::json!({
                    "build_id": build_id,
                    "worker_id": record.worker_id,
                    "project_id": project_id,
                    "reason": reason,
                    "force": force,
                }),
            );
            owner
                .execute_cancellation(&context, &mut record, force)
                .await;
            // Keep finalization in this same task. Caller cancellation after
            // confirmation must not lose its slot-release/history owner.
            owner.run_cleanup(&context, &mut record).await;
            owner.record_cancellation_stats(&record).await;

            CancelBuildResponse {
                status: if record.state == CancellationState::Completed {
                    "cancelled"
                } else {
                    "failed"
                }
                .to_string(),
                build_id,
                worker_id: Some(record.worker_id),
                project_id: Some(project_id),
                message: Some(match (record.state, force) {
                    (CancellationState::Completed, true) => {
                        "Build forcefully terminated".to_string()
                    }
                    (CancellationState::Completed, false) => {
                        "Build cancellation completed".to_string()
                    }
                    _ => {
                        "Cancellation unconfirmed; active build and reservations retained for retry"
                            .to_string()
                    }
                }),
                slots_released: record.slots_released,
            }
        });
        match operation.await {
            Ok(response) => response,
            Err(error) => {
                warn!(build_id, %error, "Cancellation task ended unexpectedly");
                CancelBuildResponse {
                    status: "failed".to_string(),
                    build_id,
                    worker_id: Some(failed_worker),
                    project_id: Some(failed_project),
                    message: Some(
                        "Cancellation task ended unexpectedly; check active history before retrying"
                            .to_string(),
                    ),
                    slots_released: 0,
                }
            }
        }
    }

    /// Cancel the current snapshot with bounded, daemon-owned concurrency.
    /// Caller interruption does not abandon later builds in the snapshot.
    pub async fn cancel_all_builds(
        &self,
        ctx: &DaemonContext,
        force: bool,
    ) -> CancelAllBuildsResponse {
        batch::cancel_all_builds(self, ctx, force).await
    }

    /// One budget bounds all termination stages, including lock waits and force.
    async fn execute_cancellation(
        &self,
        ctx: &DaemonContext,
        record: &mut CancellationRecord,
        force: bool,
    ) {
        let deadline = Instant::now().checked_add(self.config.cleanup_timeout);
        if self.config.cleanup_timeout.is_zero() || deadline.is_none() {
            record.state = CancellationState::Failed;
            record.cleanup_ok = false;
            return;
        }
        let deadline = deadline.expect("checked cancellation deadline");
        let timed_out = tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
            self.execute_cancellation_stages(ctx, record, force, deadline),
        )
        .await
        .is_err();
        if timed_out || record.state != CancellationState::Completed {
            record.state = CancellationState::Failed;
            record.cleanup_ok = false;
            warn!(
                "Cancellation of build {} unconfirmed (timed_out={}); retaining active state",
                record.build_id, timed_out
            );
        }
    }

    /// Only exact boot+start evidence may authorize a local signal; PID reuse
    /// or an uncertain identity fails closed rather than risking a victim.
    fn verified_hook_identity(record: &CancellationRecord) -> Option<u32> {
        if record.hook_pid == 0 {
            return None;
        }
        if crate::history::process_identity(record.hook_pid).as_deref()
            == record
                .hook_process_identity
                .as_deref()
                .filter(|identity| !identity.is_empty())
        {
            Some(record.hook_pid)
        } else {
            None
        }
    }

    async fn send_verified_signal(&self, record: &CancellationRecord, force: bool) -> bool {
        match Self::verified_hook_identity(record) {
            Some(pid) => send_signal_to_process(pid, force),
            None => {
                warn!(
                    "Skipping unverified local signal for build {}",
                    record.build_id
                );
                false
            }
        }
    }

    async fn execute_cancellation_stages(
        &self,
        ctx: &DaemonContext,
        record: &mut CancellationRecord,
        force: bool,
        deadline: Instant,
    ) {
        // Losing the hook does not prove that its remote process group exited.
        // Only builds with no reservation AND no remote identity may skip SSH.
        let remote_required = record.slots > 0 || record.remote_pgid_file.is_some();

        // Force skips grace, not confirmation or the overall termination budget.
        if force {
            record.state = CancellationState::Escalated;
            if record.hook_pid > 0 {
                self.send_verified_signal(record, true).await;
            }
            let remote_stopped = !remote_required || self.try_remote_kill(ctx, record).await;
            let local_stopped =
                wait_for_process_exit(record.hook_pid, self.config.kill_timeout).await;
            record.state = cancellation_terminal_state(local_stopped, remote_stopped);
            return;
        }

        // Step 1: Send SIGTERM.
        record.state = CancellationState::TermSent;
        if record.hook_pid > 0 {
            self.send_verified_signal(record, false).await;
        }

        let local_stopped = wait_for_process_exit(record.hook_pid, self.config.grace_period).await;
        if local_stopped {
            let remote_stopped =
                !remote_required || self.attempt_remote_kill_stage(ctx, record).await;
            record.state = cancellation_terminal_state(true, remote_stopped);
            return;
        }

        if Instant::now() >= deadline {
            record.state = CancellationState::Failed;
            return;
        }

        // Step 2: Terminate remote work, preserving its result through SIGKILL.
        let remote_stopped = !remote_required || self.attempt_remote_kill_stage(ctx, record).await;
        if remote_stopped
            && wait_for_process_exit(record.hook_pid, Duration::from_millis(500)).await
        {
            record.state = CancellationState::Completed;
            return;
        }

        if Instant::now() >= deadline || record.escalation_count >= self.config.max_escalations {
            record.state = CancellationState::Failed;
            return;
        }

        // Step 3: Escalate locally, but never turn a failed SSH kill into success.
        record.escalation_count += 1;
        self.events.emit(
            "cancellation_escalated",
            &serde_json::json!({
                "build_id": record.build_id,
                "worker_id": record.worker_id,
                "stage": "sigkill",
                "escalation_count": record.escalation_count,
            }),
        );

        record.state = CancellationState::Escalated;
        if record.hook_pid > 0 {
            self.send_verified_signal(record, true).await;
        }
        let local_stopped = wait_for_process_exit(record.hook_pid, self.config.kill_timeout).await;
        record.state = cancellation_terminal_state(local_stopped, remote_stopped);
    }

    async fn attempt_remote_kill_stage(
        &self,
        ctx: &DaemonContext,
        record: &mut CancellationRecord,
    ) -> bool {
        if record.escalation_count >= self.config.max_escalations {
            return false;
        }
        record.escalation_count += 1;
        self.events.emit(
            "cancellation_escalated",
            &serde_json::json!({
                "build_id": record.build_id,
                "worker_id": record.worker_id,
                "stage": "remote_kill",
                "escalation_count": record.escalation_count,
            }),
        );

        record.state = CancellationState::RemoteKillSent;
        self.try_remote_kill(ctx, record).await
    }

    /// Attempt to kill the remote process on the worker via SSH.
    async fn try_remote_kill(&self, ctx: &DaemonContext, record: &mut CancellationRecord) -> bool {
        record.remote_kill_attempted = true;

        // Look up worker config for SSH connection details.
        let worker = match ctx.pool.get(&WorkerId::new(&record.worker_id)).await {
            Some(w) => w,
            None => {
                debug!(
                    "Worker {} not found for remote kill of build {}",
                    record.worker_id, record.build_id
                );
                return false;
            }
        };

        let config = worker.config.read().await;
        let host = config.host.clone();
        let user = config.user.clone();
        let identity = config.identity_file.clone();
        drop(config);

        let remote_kill_script =
            build_remote_kill_script(record.remote_pgid_file.as_deref(), record.build_id);
        // `tokio::time::timeout(..., cmd.output())` drops the spawned ssh
        // future when it fires. Without `kill_on_drop`, the local ssh
        // process stays alive holding a socket until its own keepalive
        // gives up — at exactly the moment we're trying to clean up after
        // a stuck build. Force a SIGKILL on cancellation.
        let ssh_result = tokio::time::timeout(
            self.config.remote_kill_timeout,
            tokio::process::Command::new("ssh")
                .args([
                    "-o",
                    "StrictHostKeyChecking=no",
                    "-o",
                    "ConnectTimeout=5",
                    "-o",
                    "BatchMode=yes",
                    "-i",
                    &identity,
                    &format!("{}@{}", user, host),
                    &remote_kill_script,
                ])
                .kill_on_drop(true)
                .output(),
        )
        .await;

        match ssh_result {
            Ok(Ok(output)) => {
                let success = remote_kill_confirmed(&output, record.build_id);
                debug!(
                    "Remote kill for build {} on {}: success={}",
                    record.build_id, record.worker_id, success
                );
                success
            }
            Ok(Err(e)) => {
                warn!(
                    "Remote kill SSH command failed for build {}: {}",
                    record.build_id, e
                );
                false
            }
            Err(_) => {
                warn!(
                    "Remote kill timed out for build {} on {}",
                    record.build_id, record.worker_id
                );
                false
            }
        }
    }

    async fn capture_worker_health_snapshot(
        &self,
        ctx: &DaemonContext,
        worker_id: &str,
    ) -> Option<CancellationWorkerHealthSnapshot> {
        let worker = ctx.pool.get(&WorkerId::new(worker_id)).await?;
        let status = worker.status().await;
        let pressure = worker.pressure_assessment().await;

        Some(CancellationWorkerHealthSnapshot {
            status: worker_status_label(status).to_string(),
            speed_score: worker.get_speed_score(),
            used_slots: worker.used_slots(),
            available_slots: worker.available_slots().await,
            pressure_state: pressure.state.to_string(),
            pressure_reason_code: pressure.reason_code,
        })
    }

    /// Finalize confirmed cancellations; report failures without losing ownership.
    /// Failed attempts must leave the active build available to cleanup/retry.
    async fn run_cleanup(&self, ctx: &DaemonContext, record: &mut CancellationRecord) {
        let worker_id = &record.worker_id;

        // A failed attempt is not a terminal build. Taking it out of history
        // would both release unconfirmed capacity and prevent a later retry.
        let claimed_active = if record.state == CancellationState::Completed {
            ctx.history.active_build(record.build_id)
        } else {
            record.state = CancellationState::Failed;
            record.cleanup_ok = false;
            record.slots_released = 0;
            None
        };
        let mut history_ok = false;

        // 3. Build cancellation metadata and write finalized cancelled record.
        let elapsed = record.requested_at.elapsed();
        record.completed_at = Some(Instant::now());

        let decision_path = cancellation_decision_path(record);
        let escalation_stage = cancellation_escalation_stage(record);
        let operation_id = cancellation_operation_id(record.build_id);
        let cancel_origin = record.reason.to_string();
        let worker_health = self.capture_worker_health_snapshot(ctx, worker_id).await;

        if let Some(state) = claimed_active {
            let cancellation = BuildCancellationMetadata {
                operation_id: operation_id.clone(),
                origin: cancel_origin.clone(),
                reason_code: record.reason.to_string(),
                decision_path: decision_path
                    .iter()
                    .map(|stage| (*stage).to_string())
                    .collect(),
                escalation_stage: escalation_stage.to_string(),
                escalation_count: record.escalation_count,
                remote_kill_attempted: record.remote_kill_attempted,
                cleanup_ok: record.cleanup_ok,
                history_cancelled: true,
                final_state: record.state.to_string(),
                worker_health: worker_health.as_ref().map(worker_health_for_history),
            };
            match ctx.history.complete_durable(
                state.id,
                &state.worker_id,
                state.local_wrapper_id.as_deref(),
                130,
                None,
                None,
                None,
                Some(cancellation),
            ) {
                Ok(Some((state, _))) => {
                    history_ok = true;
                    if let Some(worker) = ctx.pool.get(&WorkerId::new(&state.worker_id)).await {
                        worker.release_slots(state.slots).await;
                        record.slots_released = state.slots;
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    warn!(
                        "Unable to persist cancellation for {}: {error}",
                        record.build_id
                    );
                    record.state = CancellationState::Failed;
                    record.cleanup_ok = false;
                }
            }
            if matches!(
                record.reason,
                CancelReason::Timeout | CancelReason::StuckDetector
            ) && let Some(worker) = ctx.pool.get(&WorkerId::new(worker_id)).await
            {
                worker
                    .record_failure(Some(format!("build cancelled by {}", record.reason)))
                    .await;
            }
            if !cfg!(test) {
                crate::metrics::dec_active_builds("remote");
                crate::metrics::inc_build_total("cancelled", "remote");
            }
        }

        // 4. Emit completion or failure event.
        let event_name = match record.state {
            CancellationState::Completed => "cancellation_completed",
            _ => "cancellation_failed",
        };

        self.events.emit(
            event_name,
            &serde_json::json!({
                "operation_id": operation_id,
                "build_id": record.build_id,
                "worker_id": record.worker_id,
                "reason": record.reason,
                "cancel_origin": cancel_origin,
                "state": record.state,
                "decision_path": decision_path,
                "escalation_stage": escalation_stage,
                "escalation_count": record.escalation_count,
                "remote_kill_attempted": record.remote_kill_attempted,
                "slots_released": record.slots_released,
                "elapsed_ms": duration_millis_u64(elapsed),
                "cleanup_ok": record.cleanup_ok,
                "history_cancelled": history_ok,
                "active_build_retained": ctx.history.active_build(record.build_id).is_some(),
                "worker_health": worker_health,
            }),
        );

        if !history_ok && record.state == CancellationState::Completed {
            // Build was already gone from active — not necessarily an error
            // if another codepath cleaned it up.
            debug!(
                "Build {} was not in active history during cleanup (may have already completed)",
                record.build_id
            );
        }
    }

    /// Record cancellation stats for a worker (for debt computation).
    async fn record_cancellation_stats(&self, record: &CancellationRecord) {
        let mut stats = self.worker_stats.write().await;
        let entry = stats.entry(record.worker_id.clone()).or_default();

        let now = Instant::now();
        entry.recent_cancellations.push(now);

        for _ in 0..record.escalation_count {
            entry.recent_escalations.push(now);
        }
        if !record.cleanup_ok {
            entry.recent_cleanup_failures.push(now);
        }
    }

    /// Compute cancellation debt for a worker (0.0 = clean, 1.0 = saturated).
    ///
    /// Used by the reliability model as a 5th signal.
    pub async fn cancellation_debt(&self, worker_id: &str) -> f64 {
        let mut stats = self.worker_stats.write().await;
        let Some(entry) = stats.get_mut(worker_id) else {
            return 0.0; // No cancellation history → no debt.
        };

        // Prune all counters outside the window. Compare ages rather than
        // constructing a cutoff Instant, because `Instant::now() - Duration`
        // panics if the result would precede the monotonic clock's origin
        // (fresh-boot scenario on Linux where `Instant::now()` < DEBT_WINDOW).
        let now = Instant::now();
        entry
            .recent_cancellations
            .retain(|t| now.saturating_duration_since(*t) < DEBT_WINDOW);
        entry
            .recent_escalations
            .retain(|t| now.saturating_duration_since(*t) < DEBT_WINDOW);
        entry
            .recent_cleanup_failures
            .retain(|t| now.saturating_duration_since(*t) < DEBT_WINDOW);

        let recent_count = entry.recent_cancellations.len() as f64;

        // Rate component: cancellations per 5-minute window, normalized.
        // 5+ cancellations in 5 minutes → full rate debt.
        let rate_debt = (recent_count / 5.0).min(1.0);

        // Escalation component: 0.2 per recent escalation.
        let escalation_debt = (entry.recent_escalations.len() as f64 * 0.2).min(0.6);

        // Cleanup failure component: 0.3 per recent failed cleanup.
        let cleanup_debt = (entry.recent_cleanup_failures.len() as f64 * 0.3).min(0.6);

        // Weighted combination, capped at 1.0.
        (rate_debt * 0.4 + escalation_debt * 0.3 + cleanup_debt * 0.3).clamp(0.0, 1.0)
    }

    /// Get active (in-flight) cancellation records.
    pub async fn active_cancellations(&self) -> Vec<CancellationRecord> {
        self.active
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .values()
            .cloned()
            .collect()
    }

    /// Increment the total builds counter for a worker (for rate computation).
    pub async fn record_build(&self, worker_id: &str) {
        let mut stats = self.worker_stats.write().await;
        let entry = stats.entry(worker_id.to_string()).or_default();
        entry.total_builds += 1;
    }
}

// ── Process signal helpers ───────────────────────────────────────────────

// Keep the executable protocol as a shell source so tests run the exact bytes
// sent to workers, including the process-table verification after signalling.
const REMOTE_CANCELLATION_SCRIPT: &str = include_str!("cancellation_remote.sh");

fn build_remote_kill_script(remote_pgid_file: Option<&str>, build_id: u64) -> String {
    let Some(remote_pgid_file) = remote_pgid_file else {
        // Matching command text cannot prove that a build's descendants exited.
        // Retain the reservation when no process-group identity was recorded.
        return "exit 42".to_owned();
    };
    format!(
        "sh -c {} sh {} {build_id}",
        shell_escape::escape(std::borrow::Cow::Borrowed(REMOTE_CANCELLATION_SCRIPT)),
        shell_escape::escape(std::borrow::Cow::Borrowed(remote_pgid_file)),
    )
}

fn remote_kill_confirmed(output: &std::process::Output, build_id: u64) -> bool {
    // Neither SSH exit zero nor partial/stale output is a termination receipt.
    output.status.success()
        && output.stdout.as_slice() == format!("RCH_REMOTE_CANCELLED_V1:{build_id}\n").as_bytes()
}

/// Use the existing safe syscall wrapper: spawning /bin/kill can block the
/// runtime before an async deadline can be polled, especially under fork load.
fn send_signal_to_process(pid: u32, force: bool) -> bool {
    use nix::sys::signal::{Signal, kill};
    use nix::unistd::Pid;

    let Ok(pid) = i32::try_from(pid) else {
        return false;
    };
    // Never reinterpret an invalid hook PID as a process-group/broadcast signal.
    if pid <= 1 {
        return false;
    }
    let signal = if force {
        Signal::SIGKILL
    } else {
        Signal::SIGTERM
    };
    match kill(Pid::from_raw(pid), signal) {
        Ok(()) => true,
        Err(error) => {
            debug!("Failed to send {signal} to process {pid}: {error}");
            false
        }
    }
}

fn is_process_alive(pid: u32) -> bool {
    use nix::errno::Errno;
    use nix::sys::signal::kill;
    use nix::unistd::Pid;

    if pid == 0 {
        return false;
    }
    let Ok(raw_pid) = i32::try_from(pid) else {
        return false;
    };
    #[cfg(target_os = "linux")]
    if let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat"))
        && let Some((_, fields)) = stat.rsplit_once(") ")
        && matches!(fields.split_whitespace().next(), Some("Z" | "X"))
    {
        // A zombie has already exited; its parent may not have reaped it yet.
        return false;
    }
    // Permission and other probe errors are not evidence of process absence.
    !matches!(kill(Pid::from_raw(raw_pid), None), Err(Errno::ESRCH))
}

async fn wait_for_process_exit(pid: u32, budget: Duration) -> bool {
    if !is_process_alive(pid) {
        return true;
    }
    if budget.is_zero() {
        return false;
    }
    tokio::time::timeout(budget, async {
        while is_process_alive(pid) {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .is_ok()
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::benchmark_queue::BenchmarkQueue;
    use crate::benchmark_scheduler::{BenchmarkScheduler, SchedulerConfig};
    use crate::events::EventBus;
    use crate::history::BuildHistory;
    use crate::selection::WorkerSelector;
    use crate::self_test::{
        DEFAULT_RESULT_CAPACITY, DEFAULT_RUN_CAPACITY, SelfTestHistory, SelfTestService,
    };
    use crate::workers::WorkerPool;
    use chrono::Duration as ChronoDuration;
    use rch_common::SelfTestConfig;
    use std::sync::Arc;
    use std::time::Instant;

    #[test]
    fn test_duration_millis_u64_saturates() {
        assert_eq!(duration_millis_u64(Duration::from_secs(u64::MAX)), u64::MAX);
    }

    pub(super) fn test_events() -> EventBus {
        EventBus::new(64)
    }

    pub(super) fn test_config() -> CancellationConfig {
        CancellationConfig {
            grace_period: Duration::from_millis(100),
            kill_timeout: Duration::from_millis(50),
            remote_kill_timeout: Duration::from_secs(1),
            max_escalations: 3,
            cleanup_timeout: Duration::from_secs(5),
        }
    }

    fn make_test_self_test(pool: WorkerPool) -> Arc<SelfTestService> {
        let history = Arc::new(SelfTestHistory::new(
            DEFAULT_RUN_CAPACITY,
            DEFAULT_RESULT_CAPACITY,
        ));
        Arc::new(SelfTestService::new(
            pool,
            SelfTestConfig::default(),
            history,
        ))
    }

    fn make_test_alert_manager() -> Arc<crate::alerts::AlertManager> {
        Arc::new(crate::alerts::AlertManager::new(
            crate::alerts::AlertConfig::default(),
        ))
    }

    fn make_test_benchmark_trigger(
        pool: WorkerPool,
    ) -> crate::benchmark_scheduler::BenchmarkTriggerHandle {
        let telemetry = Arc::new(crate::telemetry::TelemetryStore::new(
            Duration::from_secs(300),
            None,
        ));
        let (scheduler, trigger) =
            BenchmarkScheduler::new(SchedulerConfig::default(), pool, telemetry, test_events());
        let scheduler = Arc::new(scheduler);
        tokio::spawn(scheduler.run());
        trigger
    }

    pub(super) fn make_test_context(pool: WorkerPool, history: Arc<BuildHistory>) -> DaemonContext {
        let events = test_events();
        DaemonContext {
            pool: pool.clone(),
            worker_selector: Arc::new(WorkerSelector::new()),
            history,
            telemetry: Arc::new(crate::telemetry::TelemetryStore::new(
                Duration::from_secs(300),
                None,
            )),
            benchmark_queue: Arc::new(BenchmarkQueue::new(ChronoDuration::minutes(5))),
            benchmark_trigger: make_test_benchmark_trigger(pool.clone()),
            events: events.clone(),
            self_test: make_test_self_test(pool.clone()),
            alert_manager: make_test_alert_manager(),
            repo_convergence: Arc::new(crate::repo_convergence::RepoConvergenceService::new(
                events.clone(),
            )),
            cancellation: Arc::new(CancellationOrchestrator::new(
                CancellationConfig::default(),
                events.clone(),
            )),
            started_at: Instant::now(),
            socket_path: "/tmp/test-cancel.sock".to_string(),
            version: "0.0.0-test",
            pid: std::process::id(),
            queue_timeout_secs: 300,
            bypass_store: None,
            admin_disable_store: None,
            workers_config_path: None,
            admission_barrier: Arc::new(tokio::sync::RwLock::new(false)),
        }
    }

    fn test_record(
        state: CancellationState,
        escalation_count: u32,
        remote_kill_attempted: bool,
    ) -> CancellationRecord {
        CancellationRecord {
            build_id: 42,
            worker_id: "w1".to_string(),
            state,
            reason: CancelReason::User,
            requested_at: Instant::now(),
            completed_at: None,
            escalation_count,
            remote_kill_attempted,
            cleanup_ok: true,
            slots: 1,
            slots_released: 1,
            hook_pid: 12345,
            hook_process_identity: None,
            remote_pgid_file: None,
        }
    }

    #[test]
    fn test_build_remote_kill_script_prefers_recorded_pgid_file() {
        let script = build_remote_kill_script(Some("/tmp/rch/project/.rch-run/42.pgid"), 42);
        assert!(script.contains("pgid_file="));
        // Group-kill must use `-PGID` (no `--`): dash's kill builtin mishandles
        // `kill -TERM -- -PGID`, silently failing to signal the group.
        assert!(script.contains("kill -TERM -\"$pgid\""));
        assert!(!script.contains("kill -TERM -- -"));
        assert!(script.contains("/tmp/rch/project/.rch-run/42.pgid"));
        assert!(!script.contains("RCH_BUILD_ID=42;"));
    }

    #[test]
    fn test_build_remote_kill_script_handles_shell_special_pgid_file_path() {
        let script =
            build_remote_kill_script(Some("/tmp/rch/project dir/agent's/.rch-run/42.pgid"), 42);
        assert!(script.contains("pgid_file=$1"));
        assert!(script.contains("/tmp/rch/project"));
        assert!(!script.contains("pgid_file='/tmp"));

        let status = std::process::Command::new("sh")
            .arg("-n")
            .arg("-c")
            .arg(&script)
            .status()
            .expect("shell syntax check should run");
        assert!(
            status.success(),
            "remote kill script must be shell-parseable: {script}"
        );
    }

    // 1. Cancel of non-existent build → error response
    #[tokio::test]
    async fn test_cancel_nonexistent_build_returns_error() {
        let pool = WorkerPool::new();
        let history = Arc::new(BuildHistory::new(100));
        let ctx = make_test_context(pool, history);
        let orch = CancellationOrchestrator::new(test_config(), test_events());

        let resp = orch
            .cancel_build(&ctx, 999, CancelReason::User, false)
            .await;
        assert_eq!(resp.status, "error");
        assert_eq!(resp.slots_released, 0);
    }

    #[tokio::test]
    async fn test_cancel_inflight_build_records_metadata() {
        let pool = WorkerPool::new();
        let history = Arc::new(BuildHistory::new(100));
        let active = history.start_active_build(
            "proj".to_string(),
            "worker-a".to_string(),
            "cargo test".to_string(),
            0,
            0,
            rch_common::BuildLocation::Remote,
        );
        let ctx = make_test_context(pool, history.clone());
        let orch = CancellationOrchestrator::new(test_config(), test_events());

        let resp = orch
            .cancel_build(&ctx, active.id, CancelReason::Timeout, false)
            .await;
        assert_eq!(resp.status, "cancelled");
        assert_eq!(resp.build_id, active.id);
        assert!(history.active_build(active.id).is_none());

        let recent = history.recent(5);
        let cancelled = recent
            .iter()
            .find(|record| record.id == active.id)
            .expect("cancelled build record should exist");
        let metadata = cancelled
            .cancellation
            .as_ref()
            .expect("cancellation metadata should be present");
        assert_eq!(metadata.origin, "timeout");
        assert_eq!(metadata.reason_code, "timeout");
        assert_eq!(metadata.operation_id, format!("cancel-{}", active.id));
        assert_eq!(metadata.final_state, "completed");
        assert!(metadata.history_cancelled);
    }

    #[tokio::test]
    async fn test_cancel_after_completion_returns_error_post_completion_race() {
        let pool = WorkerPool::new();
        let history = Arc::new(BuildHistory::new(100));
        let active = history.start_active_build(
            "proj".to_string(),
            "worker-a".to_string(),
            "cargo check".to_string(),
            0,
            0,
            rch_common::BuildLocation::Remote,
        );
        let _ = history.finish_active_build(active.id, 0, None, None, None);

        let ctx = make_test_context(pool, history);
        let orch = CancellationOrchestrator::new(test_config(), test_events());
        let resp = orch
            .cancel_build(&ctx, active.id, CancelReason::User, false)
            .await;
        assert_eq!(resp.status, "error");
        assert!(
            resp.message
                .as_deref()
                .is_some_and(|message| message.contains("not found"))
        );
    }

    #[tokio::test]
    async fn test_repeated_cancel_after_completion_is_deterministic() {
        let pool = WorkerPool::new();
        let history = Arc::new(BuildHistory::new(100));
        let active = history.start_active_build(
            "proj".to_string(),
            "worker-a".to_string(),
            "cargo clippy".to_string(),
            0,
            0,
            rch_common::BuildLocation::Remote,
        );
        let ctx = make_test_context(pool, history);
        let orch = CancellationOrchestrator::new(test_config(), test_events());

        let first = orch
            .cancel_build(&ctx, active.id, CancelReason::User, false)
            .await;
        assert_eq!(first.status, "cancelled");

        let second = orch
            .cancel_build(&ctx, active.id, CancelReason::User, false)
            .await;
        assert_eq!(second.status, "error");
    }

    // 2. Double cancel (idempotent) — simulate by trying to cancel the same
    //    non-existent build twice (since we can't easily create active builds
    //    in unit tests without the full pipeline).
    #[tokio::test]
    async fn test_double_cancel_nonexistent_is_idempotent() {
        let pool = WorkerPool::new();
        let history = Arc::new(BuildHistory::new(100));
        let ctx = make_test_context(pool, history);
        let orch = CancellationOrchestrator::new(test_config(), test_events());

        let r1 = orch.cancel_build(&ctx, 42, CancelReason::User, false).await;
        let r2 = orch.cancel_build(&ctx, 42, CancelReason::User, false).await;
        assert_eq!(r1.status, "error");
        assert_eq!(r2.status, "error");
    }

    // 3. Cancellation debt computation: 0 cancellations = 0.0 debt
    #[tokio::test]
    async fn test_cancellation_debt_zero_for_unknown_worker() {
        let orch = CancellationOrchestrator::new(test_config(), test_events());
        let debt = orch.cancellation_debt("w1").await;
        assert!(debt < f64::EPSILON);
    }

    // 4. Cancellation debt increases with cancellation events
    #[tokio::test]
    async fn test_cancellation_debt_increases_with_events() {
        let orch = CancellationOrchestrator::new(test_config(), test_events());

        // Manually record some cancellation stats.
        {
            let mut stats = orch.worker_stats.write().await;
            let entry = stats.entry("w1".to_string()).or_default();
            let now = Instant::now();
            for _ in 0..5 {
                entry.recent_cancellations.push(now);
            }
            for _ in 0..3 {
                entry.recent_escalations.push(now);
            }
            entry.recent_cleanup_failures.push(now);
        }

        let debt = orch.cancellation_debt("w1").await;
        assert!(debt > 0.0);
        assert!(debt <= 1.0);
    }

    // 5. Cancellation debt is capped at 1.0
    #[tokio::test]
    async fn test_cancellation_debt_capped_at_one() {
        let orch = CancellationOrchestrator::new(test_config(), test_events());

        {
            let mut stats = orch.worker_stats.write().await;
            let entry = stats.entry("w1".to_string()).or_default();
            let now = Instant::now();
            for _ in 0..100 {
                entry.recent_cancellations.push(now);
            }
            for _ in 0..100 {
                entry.recent_escalations.push(now);
            }
            for _ in 0..100 {
                entry.recent_cleanup_failures.push(now);
            }
        }

        let debt = orch.cancellation_debt("w1").await;
        assert!((debt - 1.0).abs() < f64::EPSILON || debt <= 1.0);
    }

    // 6. CancellationConfig defaults are sensible
    #[test]
    fn test_cancellation_config_defaults() {
        let config = CancellationConfig::default();
        assert_eq!(config.grace_period, Duration::from_secs(5));
        assert_eq!(config.kill_timeout, Duration::from_secs(3));
        assert_eq!(config.remote_kill_timeout, Duration::from_secs(10));
        assert_eq!(config.max_escalations, 3);
        assert_eq!(config.cleanup_timeout, Duration::from_secs(15));
    }

    // 7. Cancel all with no active builds
    #[tokio::test]
    async fn test_cancel_all_no_active_builds() {
        let pool = WorkerPool::new();
        let history = Arc::new(BuildHistory::new(100));
        let ctx = make_test_context(pool, history);
        let orch = CancellationOrchestrator::new(test_config(), test_events());

        let resp = orch.cancel_all_builds(&ctx, false).await;
        assert_eq!(resp.status, "ok");
        assert_eq!(resp.cancelled_count, 0);
        assert!(resp.cancelled.is_empty());
    }

    // 8. CancellationState display
    #[test]
    fn test_cancellation_state_display() {
        assert_eq!(CancellationState::Requested.to_string(), "requested");
        assert_eq!(CancellationState::TermSent.to_string(), "term_sent");
        assert_eq!(
            CancellationState::RemoteKillSent.to_string(),
            "remote_kill_sent"
        );
        assert_eq!(CancellationState::Escalated.to_string(), "escalated");
        assert_eq!(CancellationState::Completed.to_string(), "completed");
        assert_eq!(CancellationState::Failed.to_string(), "failed");
    }

    // 9. CancelReason display
    #[test]
    fn test_cancel_reason_display() {
        assert_eq!(CancelReason::User.to_string(), "user");
        assert_eq!(CancelReason::Timeout.to_string(), "timeout");
        assert_eq!(CancelReason::StuckDetector.to_string(), "stuck_detector");
        assert_eq!(CancelReason::QueueEviction.to_string(), "queue_eviction");
    }

    // 10. Active cancellations list is empty by default
    #[tokio::test]
    async fn test_active_cancellations_empty() {
        let orch = CancellationOrchestrator::new(test_config(), test_events());
        let active = orch.active_cancellations().await;
        assert!(active.is_empty());
    }

    // 11. Record build increments total
    #[tokio::test]
    async fn test_record_build_increments_total() {
        let orch = CancellationOrchestrator::new(test_config(), test_events());
        orch.record_build("w1").await;
        orch.record_build("w1").await;

        let stats = orch.worker_stats.read().await;
        assert_eq!(stats["w1"].total_builds, 2);
    }

    // 12. Debt window prunes old entries
    #[tokio::test]
    async fn test_debt_prunes_old_cancellations() {
        let orch = CancellationOrchestrator::new(test_config(), test_events());

        {
            let mut stats = orch.worker_stats.write().await;
            let entry = stats.entry("w1".to_string()).or_default();
            // Add an "old" cancellation far in the past.
            // We can't set Instant directly to the past, but we can verify
            // that fresh entries produce non-zero debt.
            entry.recent_cancellations.push(Instant::now());
        }

        let debt = orch.cancellation_debt("w1").await;
        // One recent cancellation = rate_debt = 1/5 = 0.2, total ~ 0.2 * 0.4 = 0.08
        assert!(debt > 0.0);
        assert!(debt < 0.5); // Single cancel shouldn't be high.
    }

    #[test]
    fn test_cancellation_decision_path_term_only() {
        let record = test_record(CancellationState::Completed, 0, false);
        let path = cancellation_decision_path(&record);
        assert_eq!(path, vec!["requested", "term_sent", "completed"]);
        assert_eq!(cancellation_escalation_stage(&record), "term");
    }

    #[test]
    fn test_cancellation_decision_path_remote_kill() {
        let record = test_record(CancellationState::Completed, 1, true);
        let path = cancellation_decision_path(&record);
        assert_eq!(
            path,
            vec!["requested", "term_sent", "remote_kill_sent", "completed"]
        );
        assert_eq!(cancellation_escalation_stage(&record), "remote_kill");
    }

    #[test]
    fn test_cancellation_decision_path_sigkill_escalation() {
        let record = test_record(CancellationState::Completed, 2, true);
        let path = cancellation_decision_path(&record);
        assert_eq!(
            path,
            vec![
                "requested",
                "term_sent",
                "remote_kill_sent",
                "escalated",
                "completed"
            ]
        );
        assert_eq!(cancellation_escalation_stage(&record), "sigkill");
    }

    #[test]
    fn test_cancellation_decision_path_failed_before_remote_kill() {
        let record = test_record(CancellationState::Failed, 0, false);
        let path = cancellation_decision_path(&record);
        assert_eq!(path, vec!["requested", "term_sent", "failed"]);
        assert_eq!(cancellation_escalation_stage(&record), "term");
    }

    #[test]
    fn test_cancellation_decision_path_force_cancel() {
        let record = test_record(CancellationState::Completed, 0, true);
        let path = cancellation_decision_path(&record);
        assert_eq!(
            path,
            vec!["requested", "escalated", "remote_kill_sent", "completed"]
        );
        assert_eq!(cancellation_escalation_stage(&record), "remote_kill");
    }

    #[tokio::test]
    async fn test_cancellation_attempts_remote_kill_when_local_hook_exits_with_pgid_file() {
        let pool = WorkerPool::new();
        let history = Arc::new(BuildHistory::new(100));
        let ctx = make_test_context(pool, history);
        let orch = CancellationOrchestrator::new(test_config(), test_events());
        let mut record = CancellationRecord {
            build_id: 42,
            worker_id: "missing-worker".to_string(),
            state: CancellationState::Requested,
            reason: CancelReason::User,
            requested_at: Instant::now(),
            completed_at: None,
            escalation_count: 0,
            remote_kill_attempted: false,
            cleanup_ok: true,
            slots: 1,
            slots_released: 0,
            hook_pid: 0,
            hook_process_identity: None,
            remote_pgid_file: None,
        };

        orch.execute_cancellation(&ctx, &mut record, false).await;

        assert_eq!(record.state, CancellationState::Failed);
        assert!(!record.cleanup_ok);
        assert!(record.remote_kill_attempted);
        assert_eq!(record.escalation_count, 1);
        assert_eq!(
            cancellation_decision_path(&record),
            vec!["requested", "term_sent", "remote_kill_sent", "failed"]
        );
        assert_eq!(cancellation_escalation_stage(&record), "remote_kill");
    }

    #[tokio::test]
    async fn test_cancellation_without_remote_work_preserves_term_only_fast_path() {
        let pool = WorkerPool::new();
        let history = Arc::new(BuildHistory::new(100));
        let ctx = make_test_context(pool, history);
        let orch = CancellationOrchestrator::new(test_config(), test_events());
        let mut record = CancellationRecord {
            build_id: 43,
            worker_id: "missing-worker".to_string(),
            state: CancellationState::Requested,
            reason: CancelReason::User,
            requested_at: Instant::now(),
            completed_at: None,
            escalation_count: 0,
            remote_kill_attempted: false,
            cleanup_ok: true,
            slots: 0,
            slots_released: 0,
            hook_pid: 0,
            hook_process_identity: None,
            remote_pgid_file: None,
        };

        orch.execute_cancellation(&ctx, &mut record, false).await;

        assert_eq!(record.state, CancellationState::Completed);
        assert!(!record.remote_kill_attempted);
        assert_eq!(record.escalation_count, 0);
        assert_eq!(
            cancellation_decision_path(&record),
            vec!["requested", "term_sent", "completed"]
        );
        assert_eq!(cancellation_escalation_stage(&record), "term");
    }

    #[test]
    fn test_cancellation_operation_id_format() {
        assert_eq!(cancellation_operation_id(4242), "cancel-4242");
    }

    #[test]
    fn cancellation_safety_requires_both_termination_results() {
        for local in [false, true] {
            for remote in [false, true] {
                assert_eq!(
                    cancellation_terminal_state(local, remote),
                    if local && remote {
                        CancellationState::Completed
                    } else {
                        CancellationState::Failed
                    }
                );
            }
        }
    }

    #[tokio::test]
    async fn cancellation_safety_remote_failure_is_retryable_in_graceful_and_force_modes() {
        for force in [false, true] {
            let history = Arc::new(BuildHistory::new(100));
            let active = history.start_active_build(
                "unconfirmed".to_owned(),
                "missing-worker".to_owned(),
                "cargo test".to_owned(),
                0,
                1,
                rch_common::BuildLocation::Remote,
            );
            let ctx = make_test_context(WorkerPool::new(), history.clone());
            let orch = CancellationOrchestrator::new(test_config(), test_events());
            for _ in 0..2 {
                let response = orch
                    .cancel_build(&ctx, active.id, CancelReason::User, force)
                    .await;
                assert_eq!(response.status, "failed");
                assert_eq!(response.slots_released, 0);
                assert!(history.active_build(active.id).is_some());
                assert!(history.recent(10).is_empty());
                assert!(orch.active_cancellations().await.is_empty());
            }
            assert!(orch.cancellation_debt("missing-worker").await > 0.0);
        }
    }

    #[tokio::test]
    async fn cancellation_safety_deadline_preserves_real_reservations_and_exactly_once_cleanup() {
        let pool = WorkerPool::new();
        let config = rch_common::WorkerConfig::default();
        let id = config.id.clone();
        pool.add_worker(config).await;
        let worker = pool.get(&id).await.unwrap();
        assert!(worker.reserve_slots(3).await);
        let history = Arc::new(BuildHistory::new(100));
        let active = history.start_active_build(
            "reserved".to_owned(),
            id.to_string(),
            "cargo test".to_owned(),
            0,
            1,
            rch_common::BuildLocation::Remote,
        );
        let ctx = make_test_context(pool, history.clone());
        let orch = CancellationOrchestrator::new(
            CancellationConfig {
                cleanup_timeout: Duration::ZERO,
                ..test_config()
            },
            test_events(),
        );
        for force in [false, true] {
            let response = orch
                .cancel_build(&ctx, active.id, CancelReason::Timeout, force)
                .await;
            assert_eq!(response.status, "failed");
            assert_eq!(response.slots_released, 0);
            assert_eq!(worker.used_slots(), 3);
            assert!(!worker.reserve_slots(2).await);
            assert!(history.active_build(active.id).is_some());
            assert!(history.recent(10).is_empty());
        }

        // A later confirmed attempt may finalize once, without freeing the two
        // reservations belonging to other work or double-releasing on a race.
        let mut confirmed = test_record(CancellationState::Completed, 1, true);
        confirmed.build_id = active.id;
        confirmed.worker_id = id.to_string();
        confirmed.slots_released = 0;
        orch.run_cleanup(&ctx, &mut confirmed).await;
        assert_eq!(confirmed.slots_released, 1);
        assert_eq!(worker.used_slots(), 2);
        assert!(history.active_build(active.id).is_none());
        assert_eq!(history.recent(10).len(), 1);
        orch.run_cleanup(&ctx, &mut confirmed).await;
        assert_eq!(worker.used_slots(), 2);
        assert_eq!(history.recent(10).len(), 1);
    }

    #[tokio::test]
    async fn cancellation_safety_overall_deadline_bounds_remote_lock_waits_even_when_forced() {
        let pool = WorkerPool::new();
        let config = rch_common::WorkerConfig::default();
        let id = config.id.clone();
        pool.add_worker(config).await;
        let worker = pool.get(&id).await.unwrap();
        let ctx = make_test_context(pool, Arc::new(BuildHistory::new(100)));
        let orch = CancellationOrchestrator::new(
            CancellationConfig {
                cleanup_timeout: Duration::from_millis(40),
                remote_kill_timeout: Duration::from_secs(60),
                ..test_config()
            },
            test_events(),
        );
        for force in [false, true] {
            // Hold the real worker lock: the remote stage cannot reach spawn.
            let lock = worker.config.write().await;
            let mut record = test_record(CancellationState::Requested, 0, false);
            record.worker_id = id.to_string();
            record.hook_pid = 0;
            record.slots_released = 0;
            tokio::time::timeout(
                Duration::from_secs(1),
                orch.execute_cancellation(&ctx, &mut record, force),
            )
            .await
            .expect("overall deadline must cancel the blocked remote stage");
            assert_eq!(record.state, CancellationState::Failed);
            assert!(!record.cleanup_ok);
            assert!(record.remote_kill_attempted);
            drop(lock);
        }
    }

    #[tokio::test]
    async fn cancellation_safety_bulk_response_excludes_unconfirmed_builds() {
        let history = Arc::new(BuildHistory::new(100));
        let completed = history.start_active_build(
            "no-remote-work".to_owned(),
            "missing".to_owned(),
            "cargo check".to_owned(),
            0,
            0,
            rch_common::BuildLocation::Remote,
        );
        let retained = history.start_active_build(
            "remote-work".to_owned(),
            "missing".to_owned(),
            "cargo test".to_owned(),
            0,
            1,
            rch_common::BuildLocation::Remote,
        );
        let ctx = make_test_context(WorkerPool::new(), history.clone());
        let orch = CancellationOrchestrator::new(test_config(), test_events());
        let response = orch.cancel_all_builds(&ctx, false).await;
        assert_eq!(response.status, "partial");
        assert_eq!(response.cancelled_count, 1);
        assert_eq!(response.cancelled.len(), 1);
        assert_eq!(response.cancelled[0].build_id, completed.id);
        assert!(history.active_build(retained.id).is_some());
        let retry = orch.cancel_all_builds(&ctx, true).await;
        assert_eq!(retry.status, "failed");
        assert_eq!(retry.cancelled_count, 0);
        assert!(retry.cancelled.is_empty());
        assert!(history.active_build(retained.id).is_some());
    }

    #[tokio::test]
    async fn cancellation_safety_escalation_limit_does_not_fake_success() {
        let ctx = make_test_context(WorkerPool::new(), Arc::new(BuildHistory::new(100)));
        let orch = CancellationOrchestrator::new(
            CancellationConfig {
                max_escalations: 0,
                ..test_config()
            },
            test_events(),
        );
        let mut record = test_record(CancellationState::Requested, 0, false);
        record.hook_pid = 0;
        record.slots_released = 0;
        orch.execute_cancellation(&ctx, &mut record, false).await;
        assert_eq!(record.state, CancellationState::Failed);
        assert_eq!(record.escalation_count, 0);
        assert!(!record.remote_kill_attempted);
    }

    #[tokio::test]
    async fn cancellation_safety_local_signal_and_exit_probe_use_only_an_owned_child() {
        struct ChildGuard(std::process::Child);
        impl Drop for ChildGuard {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        assert!(!send_signal_to_process(0, false));
        assert!(!send_signal_to_process(1, true));
        assert!(!send_signal_to_process(u32::MAX, true));
        assert!(!is_process_alive(0));
        assert!(!is_process_alive(u32::MAX));
        assert!(is_process_alive(std::process::id()));
        let mut child = ChildGuard(
            std::process::Command::new("/bin/sleep")
                .arg("60")
                .spawn()
                .unwrap(),
        );
        let pid = child.0.id();
        assert!(is_process_alive(pid));
        assert!(!wait_for_process_exit(pid, Duration::ZERO).await);
        assert!(send_signal_to_process(pid, false));
        child.0.wait().unwrap();
        assert!(wait_for_process_exit(pid, Duration::from_secs(1)).await);
    }

    #[test]
    fn remote_cancel_receipt_requires_success_and_one_complete_matching_record() {
        use std::os::unix::process::ExitStatusExt;

        for (code, stdout, expected) in [
            (0, "RCH_REMOTE_CANCELLED_V1:42\n", true),
            (0, "", false),
            (0, "RCH_REMOTE_CANCELLED_V1:42", false),
            (0, "RCH_REMOTE_CANCELLED_V1:41\n", false),
            (
                0,
                "RCH_REMOTE_CANCELLED_V1:42\nRCH_REMOTE_CANCELLED_V1:42\n",
                false,
            ),
            (255, "RCH_REMOTE_CANCELLED_V1:42\n", false),
        ] {
            let output = std::process::Output {
                status: std::process::ExitStatus::from_raw(code << 8),
                stdout: stdout.as_bytes().to_vec(),
                stderr: Vec::new(),
            };
            assert_eq!(
                remote_kill_confirmed(&output, 42),
                expected,
                "{code}: {stdout:?}"
            );
        }
    }

    async fn remote_cancel_probe_fixture(
        path: &std::path::Path,
        prefix: &str,
    ) -> std::process::Output {
        tokio::time::timeout(
            Duration::from_secs(5),
            tokio::process::Command::new("/bin/sh")
                .arg("-c")
                .arg(format!("{prefix}\n{REMOTE_CANCELLATION_SCRIPT}"))
                .arg("rch-cancel-fixture")
                .arg(path)
                .arg("42")
                .stdin(std::process::Stdio::null())
                .kill_on_drop(true)
                .output(),
        )
        .await
        .expect("remote cancellation probe exceeded its test deadline")
        .unwrap()
    }

    #[tokio::test]
    async fn remote_cancel_rejects_unsafe_and_missing_identity_without_signalling() {
        let root = tempfile::tempdir().unwrap().keep();
        let path = root.join("group with 'quote $dollar;`backtick`.pgid");
        // The spy cannot send a real signal even if validation regresses.
        let spy = "kill() { printf SIGNALLED; return 0; }; sleep() { :; };";
        for value in [
            "",
            "0",
            "1",
            "-1",
            "-42",
            "00",
            "012",
            "2 3",
            "2\n3",
            "2147483648",
            "999999999999999999999",
            "$(false)",
        ] {
            std::fs::write(&path, value).unwrap();
            let output = remote_cancel_probe_fixture(&path, spy).await;
            assert_eq!(output.status.code(), Some(42), "{value:?}");
            assert!(
                output.stdout.is_empty(),
                "invalid ID reached a signal: {value:?}"
            );
        }
        let link = root.join("link.pgid");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        for invalid in [root.join("missing.pgid"), root.clone(), link] {
            let output = remote_cancel_probe_fixture(&invalid, spy).await;
            assert_eq!(output.status.code(), Some(42));
            assert!(output.stdout.is_empty());
        }
        let script = build_remote_kill_script(None, 42);
        assert!(
            !script.contains("pkill"),
            "missing identity must not select processes by text"
        );
        let output = tokio::process::Command::new("/bin/sh")
            .args(["-c", &script])
            .kill_on_drop(true)
            .output()
            .await
            .unwrap();
        assert!(!remote_kill_confirmed(&output, 42));
    }

    #[tokio::test]
    async fn remote_cancel_observation_errors_and_survivors_never_confirm_success() {
        let root = tempfile::tempdir().unwrap().keep();
        let path = root.join("group.pgid");
        std::fs::write(&path, "123\n").unwrap();
        // Execute the production shell source with only OS failures injected.
        // All kill calls are inert; sleep is shortened for deterministic faults.
        for (probe, expected) in [
            ("ps() { return 1; };", 44),
            ("ps() { :; };", 44),
            ("ps() { printf 'not a process table\\n'; };", 44),
            ("ps() { printf '10 10 S\\n'; };", 44),
            ("ps() { printf '%s 123 S\\n' \"$$\"; };", 44),
            ("ps() { printf '%s 99 S\\n100 123 R\\n' \"$$\"; };", 45),
            (
                "ps() { printf '%s 99 S\\n100 123 Z\\n101 123 S\\n' \"$$\"; };",
                45,
            ),
            ("ps() { printf '%s 99 S\\n100 123 Z\\n' \"$$\"; };", 0),
            ("ps() { printf '%s 99 S\\n' \"$$\"; };", 0),
        ] {
            let prefix = format!("kill() {{ return 0; }}; sleep() {{ :; }}; {probe}");
            let output = remote_cancel_probe_fixture(&path, &prefix).await;
            assert_eq!(output.status.code(), Some(expected), "{probe}: {output:?}");
            assert_eq!(remote_kill_confirmed(&output, 42), expected == 0);
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn remote_cancel_real_process_group_is_verified_and_retryable() {
        use std::os::unix::process::CommandExt;

        struct OwnedGroup(std::process::Child);
        impl Drop for OwnedGroup {
            fn drop(&mut self) {
                // Keep the leader unreaped until here, so its PID cannot be
                // reused by another group before this owned cleanup.
                let pid = i32::try_from(self.0.id()).unwrap();
                let _ = nix::sys::signal::killpg(
                    nix::unistd::Pid::from_raw(pid),
                    nix::sys::signal::Signal::SIGKILL,
                );
                let _ = self.0.wait();
            }
        }

        let root = tempfile::tempdir().unwrap().keep();
        let child_pid_path = root.join("child.pid");
        let group = OwnedGroup(
            std::process::Command::new("/bin/sh")
                .args([
                    "-c",
                    "trap '' TERM; sleep 60 & printf '%s\\n' \"$!\" > \"$1\"; wait",
                    "rch-group",
                ])
                .arg(&child_pid_path)
                .process_group(0)
                .spawn()
                .unwrap(),
        );
        let unrelated = OwnedGroup(
            std::process::Command::new("/bin/sleep")
                .arg("60")
                .process_group(0)
                .spawn()
                .unwrap(),
        );
        let child_pid: u32 = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let Ok(text) = std::fs::read_to_string(&child_pid_path)
                    && let Ok(pid) = text.trim().parse::<u32>()
                {
                    break pid;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let path = root.join("group with 'quote $dollar;`backtick`.pgid");
        std::fs::write(&path, format!("{}\n", group.0.id())).unwrap();
        let script = build_remote_kill_script(Some(path.to_str().unwrap()), 42);
        for _ in 0..2 {
            let output = tokio::time::timeout(
                Duration::from_secs(8),
                tokio::process::Command::new("/bin/sh")
                    .args(["-c", &script])
                    .kill_on_drop(true)
                    .output(),
            )
            .await
            .unwrap()
            .unwrap();
            assert!(remote_kill_confirmed(&output, 42), "{output:?}");
            assert!(!is_process_alive(group.0.id()));
            assert!(!is_process_alive(child_pid));
            assert!(is_process_alive(unrelated.0.id()));
        }
    }

    #[tokio::test]
    async fn remote_cancel_transport_requires_receipt_before_releasing_reservations() {
        const CHILD_ROOT: &str = "RCH_REMOTE_CANCEL_TEST_ROOT";
        if let Some(root) = std::env::var_os(CHILD_ROOT).map(std::path::PathBuf::from) {
            let pool = WorkerPool::new();
            let config = rch_common::WorkerConfig::default();
            let id = config.id.clone();
            pool.add_worker(config).await;
            let worker = pool.get(&id).await.unwrap();
            assert!(worker.reserve_slots(3).await);
            let history = Arc::new(BuildHistory::new(100));
            let active = history.start_active_build(
                "receipt".to_owned(),
                id.to_string(),
                "cargo test".to_owned(),
                0,
                1,
                rch_common::BuildLocation::Remote,
            );
            std::fs::write(root.join("build-id"), active.id.to_string()).unwrap();
            let ctx = make_test_context(pool, history.clone());
            let orch = CancellationOrchestrator::new(test_config(), test_events());
            for mode in [
                "empty",
                "truncated",
                "wrong-id",
                "duplicate",
                "failed",
                "confirmed",
            ] {
                std::fs::write(root.join("mode"), mode).unwrap();
                let mut record = test_record(CancellationState::Requested, 0, false);
                record.build_id = active.id;
                record.worker_id = id.to_string();
                record.hook_pid = 0;
                record.slots_released = 0;
                record.remote_pgid_file = Some("/test/owned-group.pgid".to_owned());
                orch.execute_cancellation(&ctx, &mut record, true).await;
                orch.run_cleanup(&ctx, &mut record).await;
                if mode == "confirmed" {
                    assert_eq!(record.state, CancellationState::Completed);
                    assert_eq!(record.slots_released, 1);
                    assert_eq!(worker.used_slots(), 2);
                    assert!(history.active_build(active.id).is_none());
                    orch.run_cleanup(&ctx, &mut record).await;
                    assert_eq!(worker.used_slots(), 2);
                } else {
                    assert_eq!(record.state, CancellationState::Failed, "{mode}");
                    assert_eq!(record.slots_released, 0);
                    assert_eq!(worker.used_slots(), 3);
                    assert!(history.active_build(active.id).is_some());
                    assert!(history.recent(10).is_empty());
                }
            }
            std::fs::write(root.join("child-completed"), "ok").unwrap();
            return;
        }

        // Isolate PATH in a child test process; never change global test env or
        // contact a worker. The fake SSH controls only exit/status receipts.
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap().keep();
        let ssh = root.join("ssh");
        std::fs::write(
            &ssh,
            r#"#!/bin/sh
id=$(/bin/cat "$RCH_REMOTE_CANCEL_TEST_ROOT/build-id") || exit 99
mode=$(/bin/cat "$RCH_REMOTE_CANCEL_TEST_ROOT/mode") || exit 99
case "$mode" in
  empty) exit 0;;
  truncated) printf 'RCH_REMOTE_CANCELLED_V1:%s' "$id";;
  wrong-id) printf 'RCH_REMOTE_CANCELLED_V1:0\n';;
  duplicate) printf 'RCH_REMOTE_CANCELLED_V1:%s\n' "$id" "$id";;
  failed) printf 'RCH_REMOTE_CANCELLED_V1:%s\n' "$id"; exit 255;;
  confirmed) printf 'RCH_REMOTE_CANCELLED_V1:%s\n' "$id";;
  *) exit 99;;
esac
"#,
        )
        .unwrap();
        std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o700)).unwrap();
        let output = tokio::time::timeout(
            Duration::from_secs(15),
            tokio::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "cancellation::tests::remote_cancel_transport_requires_receipt_before_releasing_reservations", "--nocapture"])
                .env(CHILD_ROOT, &root)
                .env("PATH", format!("{}:/usr/bin:/bin", root.display()))
                .kill_on_drop(true)
                .output(),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(
            output.status.success(),
            "isolated SSH fixture failed: {output:?}"
        );
        assert!(
            root.join("child-completed").is_file(),
            "child regression did not execute"
        );
    }

    async fn wait_for_cancellation_attempts(orch: &CancellationOrchestrator, expected: usize) {
        tokio::time::timeout(Duration::from_secs(3), async {
            while orch.active_cancellations().await.len() != expected {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("cancellation attempt ownership did not settle");
    }

    #[tokio::test]
    async fn cancellation_ownership_dropped_waiter_preserves_reservations_and_retryability() {
        for force in [false, true] {
            for budget in [Duration::ZERO, Duration::from_millis(40)] {
                let pool = WorkerPool::new();
                let config = rch_common::WorkerConfig::default();
                let id = config.id.clone();
                pool.add_worker(config).await;
                let worker = pool.get(&id).await.unwrap();
                assert!(worker.reserve_slots(3).await);
                let history = Arc::new(BuildHistory::new(100));
                let build = history.start_active_build(
                    "abandoned-waiter".to_owned(),
                    id.to_string(),
                    "cargo test".to_owned(),
                    0,
                    1,
                    rch_common::BuildLocation::Remote,
                );
                let ctx = make_test_context(pool, history.clone());
                let mut orch = CancellationOrchestrator::new(
                    CancellationConfig {
                        cleanup_timeout: budget,
                        ..test_config()
                    },
                    test_events(),
                );
                // Zero budget blocks in failure reporting; nonzero budget
                // blocks in termination. Neither case can reach a real SSH.
                let lock = worker.config.write().await;
                let caller_owner = orch.clone();
                let caller_context = ctx.clone();
                let caller = tokio::spawn(async move {
                    caller_owner
                        .cancel_build(&caller_context, build.id, CancelReason::User, force)
                        .await
                });
                wait_for_cancellation_attempts(&orch, 1).await;
                caller.abort();
                assert!(caller.await.unwrap_err().is_cancelled());
                let duplicate = orch
                    .cancel_build(&ctx, build.id, CancelReason::User, force)
                    .await;
                assert_eq!(duplicate.status, "cancelling");
                assert_eq!(duplicate.slots_released, 0);
                // Keep the lock past the stage deadline, preventing an SSH
                // spawn even if this test is running on a configured host.
                tokio::time::sleep(budget + Duration::from_millis(30)).await;
                drop(lock);
                wait_for_cancellation_attempts(&orch, 0).await;
                assert_eq!(worker.used_slots(), 3);
                assert!(history.active_build(build.id).is_some());
                assert!(history.recent(10).is_empty());
                // Retry uses the same shared admission map, without SSH.
                orch.config.cleanup_timeout = Duration::ZERO;
                let retry = orch
                    .cancel_build(&ctx, build.id, CancelReason::User, force)
                    .await;
                assert_eq!(retry.status, "failed", "abandoned attempt blocked a retry");
                assert_eq!(worker.used_slots(), 3);
                assert!(orch.active_cancellations().await.is_empty());
                assert_eq!(
                    orch.worker_stats.read().await[id.as_str()]
                        .recent_cancellations
                        .len(),
                    2,
                    "duplicate waits must not create extra cancellation attempts"
                );
            }
        }
    }

    #[tokio::test]
    async fn cancellation_ownership_guard_releases_only_its_claim_on_abort_and_unwind() {
        let orch = CancellationOrchestrator::new(test_config(), test_events());
        for unwind in [false, true] {
            {
                let mut active = orch.active.lock().unwrap();
                active.insert(42, test_record(CancellationState::Requested, 0, false));
                let mut other = test_record(CancellationState::Requested, 0, false);
                other.build_id = 43;
                active.insert(43, other);
            }
            let attempt = CancellationAttempt {
                build_id: 42,
                active: Arc::clone(&orch.active),
            };
            let task = tokio::spawn(async move {
                let _attempt = attempt;
                assert!(!unwind, "injected cancellation task unwind");
                std::future::pending::<()>().await;
            });
            if !unwind {
                task.abort();
            }
            let error = task.await.unwrap_err();
            assert_eq!(error.is_panic(), unwind);
            let active = orch.active_cancellations().await;
            assert_eq!(active.len(), 1);
            assert_eq!(active[0].build_id, 43);
        }
    }

    struct CancellationOwnedChild(std::process::Child);

    impl Drop for CancellationOwnedChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn cancellation_ownership_termination_and_history_finish_after_waiter_abort() {
        let root = tempfile::tempdir().unwrap().keep();
        let ready = root.join("hook-ready");
        let child = CancellationOwnedChild(
            std::process::Command::new("/bin/sh")
                .args([
                    "-c",
                    "trap '' TERM; printf ready > \"$1\"; exec /bin/sleep 60",
                    "owned-cancel-hook",
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
        let history = Arc::new(BuildHistory::new(100));
        let build = history.start_active_build(
            "owned-hook".to_owned(),
            "no-remote-work".to_owned(),
            "fixture".to_owned(),
            child.0.id(),
            0,
            rch_common::BuildLocation::Remote,
        );
        let ctx = make_test_context(WorkerPool::new(), history.clone());
        let orch = CancellationOrchestrator::new(
            CancellationConfig {
                kill_timeout: Duration::from_secs(1),
                ..test_config()
            },
            test_events(),
        );
        let caller_owner = orch.clone();
        let caller = tokio::spawn(async move {
            caller_owner
                .cancel_build(&ctx, build.id, CancelReason::User, false)
                .await
        });
        wait_for_cancellation_attempts(&orch, 1).await;
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        wait_for_cancellation_attempts(&orch, 0).await;
        assert!(
            !is_process_alive(child.0.id()),
            "caller abort abandoned the owned hook"
        );
        assert!(history.active_build(build.id).is_none());
        let recent = history.recent(10);
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].id, build.id);
        assert_eq!(
            recent[0].cancellation.as_ref().unwrap().final_state,
            "completed"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancellation_ownership_completed_before_dispatch_does_not_signal_stale_hook() {
        use std::future::{Future, poll_fn};
        use std::task::Poll;

        let child = CancellationOwnedChild(
            std::process::Command::new("/bin/sleep")
                .arg("60")
                .spawn()
                .unwrap(),
        );
        let history = Arc::new(BuildHistory::new(100));
        let build = history.start_active_build(
            "completion-race".to_owned(),
            "no-remote-work".to_owned(),
            "fixture".to_owned(),
            child.0.id(),
            0,
            rch_common::BuildLocation::Remote,
        );
        let ctx = make_test_context(WorkerPool::new(), history.clone());
        let orch = CancellationOrchestrator::new(test_config(), test_events());
        let mut request = Box::pin(orch.cancel_build(&ctx, build.id, CancelReason::User, true));
        // Poll admission without yielding to the newly spawned owner task.
        poll_fn(|cx| {
            assert!(request.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        assert!(
            history
                .finish_active_build(build.id, 0, None, None, None)
                .is_some()
        );
        let response = request.await;
        assert_eq!(response.status, "error");
        assert_eq!(response.slots_released, 0);
        assert!(
            is_process_alive(child.0.id()),
            "signalled a completed build's stale hook"
        );
        assert!(orch.active_cancellations().await.is_empty());
        assert!(
            history
                .recent(10)
                .iter()
                .all(|record| record.cancellation.is_none())
        );
    }
}
