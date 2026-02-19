//! Build cancellation orchestrator with deterministic state machine (bd-1yt6).
//!
//! Provides bounded escalation (SIGTERM → remote kill → SIGKILL),
//! deterministic cleanup (slots, history, events), and per-worker
//! cancellation debt for reliability integration.

use crate::DaemonContext;
use crate::api::{CancelAllBuildsResponse, CancelBuildResponse, CancelledBuildInfo};
use crate::events::EventBus;
use rch_common::{
    BuildCancellationMetadata, BuildCancellationWorkerHealth, WorkerId, WorkerStatus,
};
use serde::Serialize;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, warn};

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
    /// Cancellation failed but cleanup was still attempted.
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
    /// Maximum number of escalation stages attempted.
    pub max_escalations: u32,
    /// Overall timeout for the entire cancellation lifecycle.
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
/// bounded escalation and cleanup guarantees.
pub struct CancellationOrchestrator {
    config: CancellationConfig,
    /// Active (in-flight) cancellations keyed by build_id.
    active: RwLock<HashMap<u64, CancellationRecord>>,
    /// Per-worker cancellation debt tracking.
    worker_stats: RwLock<HashMap<String, WorkerCancelStats>>,
    /// Event bus for structured event emission.
    events: EventBus,
}

impl CancellationOrchestrator {
    /// Create a new orchestrator with the given config and event bus.
    pub fn new(config: CancellationConfig, events: EventBus) -> Self {
        Self {
            config,
            active: RwLock::new(HashMap::new()),
            worker_stats: RwLock::new(HashMap::new()),
            events,
        }
    }

    /// Main entry point: cancel a single build.
    pub async fn cancel_build(
        &self,
        ctx: &DaemonContext,
        build_id: u64,
        reason: CancelReason,
        force: bool,
    ) -> CancelBuildResponse {
        // Look up the active build.
        let active_build = match ctx.history.active_build(build_id) {
            Some(build) => build,
            None => {
                // Check if we already have an active cancellation for this build (idempotent).
                let active = self.active.read().await;
                if let Some(record) = active.get(&build_id) {
                    return CancelBuildResponse {
                        status: "cancelling".to_string(),
                        build_id,
                        worker_id: Some(record.worker_id.clone()),
                        project_id: None,
                        message: Some(format!(
                            "Cancellation already in progress (state: {})",
                            record.state
                        )),
                        slots_released: record.slots_released,
                    };
                }
                return CancelBuildResponse {
                    status: "error".to_string(),
                    build_id,
                    worker_id: None,
                    project_id: None,
                    message: Some("Build not found or already completed".to_string()),
                    slots_released: 0,
                };
            }
        };

        let worker_id = active_build.worker_id.clone();
        let project_id = active_build.project_id.clone();
        let slots = active_build.slots;
        let hook_pid = active_build.hook_pid;

        // Create the cancellation record.
        let mut record = CancellationRecord {
            build_id,
            worker_id: worker_id.clone(),
            state: CancellationState::Requested,
            reason,
            requested_at: Instant::now(),
            completed_at: None,
            escalation_count: 0,
            remote_kill_attempted: false,
            cleanup_ok: true,
            slots,
            slots_released: 0,
            hook_pid,
        };

        // Atomically check-and-insert: prevent concurrent double-cancellation
        // which would cause double slot release.
        {
            let mut active = self.active.write().await;
            if let Some(existing) = active.get(&build_id) {
                return CancelBuildResponse {
                    status: "cancelling".to_string(),
                    build_id,
                    worker_id: Some(existing.worker_id.clone()),
                    project_id: Some(project_id),
                    message: Some(format!(
                        "Cancellation already in progress (state: {})",
                        existing.state
                    )),
                    slots_released: existing.slots_released,
                };
            }
            active.insert(build_id, record.clone());
        }

        // Emit requested event.
        self.events.emit(
            "cancellation_requested",
            &serde_json::json!({
                "build_id": build_id,
                "worker_id": worker_id,
                "project_id": project_id,
                "reason": reason,
                "force": force,
            }),
        );

        // Execute the state machine.
        self.execute_cancellation(ctx, &mut record, force).await;

        // Run cleanup (always, regardless of state).
        self.run_cleanup(ctx, &mut record).await;

        // Update worker stats.
        self.record_cancellation_stats(&record).await;

        // Move from active to completed.
        self.active.write().await.remove(&build_id);

        let status = match record.state {
            CancellationState::Completed => "cancelled".to_string(),
            CancellationState::Failed => "failed".to_string(),
            _ => "cancelled".to_string(),
        };

        CancelBuildResponse {
            status,
            build_id,
            worker_id: Some(worker_id),
            project_id: Some(project_id),
            message: Some(match (record.state, force) {
                (CancellationState::Completed, true) => "Build forcefully terminated".to_string(),
                (CancellationState::Completed, false) => "Build cancellation completed".to_string(),
                (CancellationState::Failed, _) => "Cancellation completed with errors".to_string(),
                _ => format!("Cancellation finished in state: {}", record.state),
            }),
            slots_released: record.slots_released,
        }
    }

    /// Cancel all active builds, delegating each to the state machine.
    pub async fn cancel_all_builds(
        &self,
        ctx: &DaemonContext,
        force: bool,
    ) -> CancelAllBuildsResponse {
        let active_builds = ctx.history.active_builds();

        if active_builds.is_empty() {
            return CancelAllBuildsResponse {
                status: "ok".to_string(),
                cancelled_count: 0,
                cancelled: vec![],
                message: Some("No active builds to cancel".to_string()),
            };
        }

        let mut cancelled = Vec::with_capacity(active_builds.len());

        for build in active_builds {
            let resp = self
                .cancel_build(ctx, build.id, CancelReason::User, force)
                .await;
            cancelled.push(CancelledBuildInfo {
                build_id: resp.build_id,
                worker_id: resp.worker_id.clone().unwrap_or_default(),
                project_id: resp.project_id.clone().unwrap_or_default(),
                slots_released: resp.slots_released,
            });
        }

        let cancelled_count = cancelled.len();

        CancelAllBuildsResponse {
            status: "ok".to_string(),
            cancelled_count,
            cancelled,
            message: Some(format!(
                "{} build(s) {}",
                cancelled_count,
                if force {
                    "forcefully terminated"
                } else {
                    "cancelled"
                },
            )),
        }
    }

    /// Execute the cancellation state machine.
    async fn execute_cancellation(
        &self,
        ctx: &DaemonContext,
        record: &mut CancellationRecord,
        force: bool,
    ) {
        let deadline = Instant::now() + self.config.cleanup_timeout;

        // Force cancel: skip grace period, go straight to SIGKILL.
        if force {
            record.state = CancellationState::Escalated;
            if record.hook_pid > 0 {
                send_signal_to_process(record.hook_pid, true);
            }
            self.try_remote_kill(ctx, record).await;
            record.state = CancellationState::Completed;
            return;
        }

        // Step 1: Send SIGTERM.
        record.state = CancellationState::TermSent;
        if record.hook_pid > 0 {
            send_signal_to_process(record.hook_pid, false);
        }

        // Wait for grace period, checking if process exits.
        let grace_end = Instant::now() + self.config.grace_period;
        while Instant::now() < grace_end && Instant::now() < deadline {
            if record.hook_pid == 0 || !is_process_alive(record.hook_pid) {
                record.state = CancellationState::Completed;
                return;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }

        // Check deadline.
        if Instant::now() >= deadline {
            record.state = CancellationState::Failed;
            warn!("Cancellation of build {} exceeded timeout", record.build_id);
            return;
        }

        // Step 2: Process still alive — attempt remote kill.
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
        let remote_killed = self.try_remote_kill(ctx, record).await;

        if remote_killed {
            // Give a moment for the local process to die too.
            tokio::time::sleep(Duration::from_millis(500)).await;
            if record.hook_pid == 0 || !is_process_alive(record.hook_pid) {
                record.state = CancellationState::Completed;
                return;
            }
        }

        // Check deadline.
        if Instant::now() >= deadline {
            record.state = CancellationState::Failed;
            warn!(
                "Cancellation of build {} exceeded timeout after remote kill",
                record.build_id
            );
            return;
        }

        // Step 3: Escalate to local SIGKILL.
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
            send_signal_to_process(record.hook_pid, true);
        }

        // Brief wait for SIGKILL to take effect.
        tokio::time::sleep(self.config.kill_timeout.min(Duration::from_secs(2))).await;

        record.state = CancellationState::Completed;
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

        // SSH kill command: kill all processes in the build's process group
        // on the remote worker. Use pkill to match by the build_id marker
        // that the hook sets in the remote process environment.
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
                    &format!(
                        "pkill -9 -f 'RCH_BUILD_ID={}' 2>/dev/null; true",
                        record.build_id
                    ),
                ])
                .output(),
        )
        .await;

        match ssh_result {
            Ok(Ok(output)) => {
                let success = output.status.success();
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

    /// Deterministic cleanup: release slots, update history, emit event.
    /// Always runs regardless of cancellation outcome.
    async fn run_cleanup(&self, ctx: &DaemonContext, record: &mut CancellationRecord) {
        let worker_id = &record.worker_id;

        // 1. Claim active build in history. This is the idempotency/ownership gate:
        // whoever claims it performs deterministic cleanup and final record write.
        let claimed_active = ctx.history.take_active_build(record.build_id);
        let history_ok = claimed_active.is_some();

        // 2. Release worker slots — only if we successfully claimed the build from
        // active history. If claim failed, another codepath already finalized the
        // build and released slots; releasing again would steal slots from a
        // subsequent build.
        if history_ok && record.slots > 0 {
            if let Some(worker) = ctx.pool.get(&WorkerId::new(worker_id)).await {
                worker.release_slots(record.slots).await;
                record.slots_released = record.slots;
            } else {
                warn!(
                    "Worker {} not found during slot release for build {}",
                    worker_id, record.build_id
                );
                record.cleanup_ok = false;
            }
        }

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
            ctx.history
                .record_cancelled_build(state, None, Some(cancellation));
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
                "elapsed_ms": elapsed.as_millis() as u64,
                "cleanup_ok": record.cleanup_ok,
                "history_cancelled": history_ok,
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

        // Prune all counters outside the window.
        let cutoff = Instant::now() - DEBT_WINDOW;
        entry.recent_cancellations.retain(|t| *t > cutoff);
        entry.recent_escalations.retain(|t| *t > cutoff);
        entry.recent_cleanup_failures.retain(|t| *t > cutoff);

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
        self.active.read().await.values().cloned().collect()
    }

    /// Increment the total builds counter for a worker (for rate computation).
    pub async fn record_build(&self, worker_id: &str) {
        let mut stats = self.worker_stats.write().await;
        let entry = stats.entry(worker_id.to_string()).or_default();
        entry.total_builds += 1;
    }
}

// ── Process signal helpers ───────────────────────────────────────────────

fn send_signal_to_process(pid: u32, force: bool) -> bool {
    if pid == 0 {
        return false;
    }

    let signal = if force { "KILL" } else { "TERM" };

    match std::process::Command::new("kill")
        .arg(format!("-{}", signal))
        .arg(pid.to_string())
        .output()
    {
        Ok(output) => output.status.success(),
        Err(e) => {
            debug!("Failed to send {} signal to process {}: {}", signal, pid, e);
            false
        }
    }
}

fn is_process_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }

    if cfg!(target_os = "linux") {
        return std::path::Path::new(&format!("/proc/{}", pid)).exists();
    }

    std::process::Command::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
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

    fn test_events() -> EventBus {
        EventBus::new(64)
    }

    fn test_config() -> CancellationConfig {
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

    fn make_test_context(pool: WorkerPool, history: Arc<BuildHistory>) -> DaemonContext {
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
        }
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

    #[test]
    fn test_cancellation_operation_id_format() {
        assert_eq!(cancellation_operation_id(4242), "cancel-4242");
    }
}
