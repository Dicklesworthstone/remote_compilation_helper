//! Unix socket API for hook-daemon communication.
//!
//! Implements a simple HTTP-like protocol over Unix socket:
//! - Request: `GET /select-worker?project=X&cores=N\n`
//! - Response: JSON `SelectionResponse` or error

use crate::DaemonContext;
use crate::alerts::AlertInfo;
use crate::events::EventBus;
use crate::history::{BuildHistory, QueueSelectionContract, QueuedWaiterClaim};
use crate::metrics;
use crate::metrics::budget::{self, BudgetStatusResponse};
use crate::reload;
use crate::restart_admission::{MaintenanceFence, MaintenancePeer, RestartAdmissionState};
use crate::telemetry::collect_telemetry_from_worker;
use crate::workers::{
    WorkerCapabilitiesResponse, get_workers_capabilities, handle_worker_disable,
    handle_worker_drain, handle_worker_enable,
};
use anyhow::{Context, Result, anyhow};
use chrono::{Duration as ChronoDuration, Utc};
use rch_common::RestartAdmissionResponse;
use rch_common::job_identity::{
    DurableJobLease, LOCAL_WRAPPER_ID_PREFIX, default_job_lease_directory,
};
use rch_common::process_identity::{OwnerPresence, ProcessIdentity, owner_presence};
use rch_common::{
    ApiError, BuildHeartbeatRequest, BuildRecord, BuildStats, BypassRecord, BypassRecordStore,
    CircuitBreakerConfig, CircuitState, CommandPriority, ErrorCode, ReleaseRequest,
    RequiredRuntime, SELECTION_RESPONSE_PROTOCOL_VERSION, SavedTimeStats, SelectedWorker,
    SelectionReason, SelectionRequest, SelectionResponse, WorkerId, WorkerStatus,
    default_bypass_record_path,
};
use rch_telemetry::protocol::{TelemetrySource, TestRunRecord, TestRunStats, WorkerTelemetry};
use rch_telemetry::speedscore::SpeedScore;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tracing::{debug, info, warn};
use uuid::Uuid;

// ============================================================================
// Helper Functions
// ============================================================================

const MAX_LINE_SIZE: usize = 65536; // 64KB

async fn read_line_with_limit<R: AsyncBufReadExt + Unpin>(
    reader: &mut R,
    buf: &mut String,
    limit: usize,
) -> Result<usize> {
    let mut bytes = Vec::new();
    let mut count = 0;
    while count < limit {
        let byte = reader.read_u8().await;
        match byte {
            Ok(b) => {
                count += 1;
                bytes.push(b);
                if b == b'\n' {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                break;
            }
            Err(e) => return Err(e.into()),
        }
    }

    if count >= limit && bytes.last() != Some(&b'\n') {
        return Err(anyhow!("Request line exceeded limit of {} bytes", limit));
    }

    let s = String::from_utf8(bytes).map_err(|e| anyhow!("Invalid UTF-8 in request: {}", e))?;
    buf.push_str(&s);
    Ok(count)
}

/// Format wait time in seconds to a human-readable string.
fn format_wait_time(secs: u64) -> String {
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        let mins = secs / 60;
        let s = secs % 60;
        if s == 0 {
            format!("{}m", mins)
        } else {
            format!("{}m {}s", mins, s)
        }
    } else {
        let hours = secs / 3600;
        let mins = (secs % 3600) / 60;
        if mins == 0 {
            format!("{}h", hours)
        } else {
            format!("{}h {}m", hours, mins)
        }
    }
}

/// Parsed API request variants.
#[derive(Debug)]
enum ApiRequest {
    SelectWorker {
        request: SelectionRequest,
        /// Client-minted identity supplied before daemon contact.
        local_wrapper_id: Option<String>,
        /// If true and all workers are busy, enqueue and wait for a worker.
        wait_for_worker: bool,
        /// Optional client-provided max queue wait timeout (seconds).
        /// Effective wait timeout is min(daemon queue timeout, client timeout).
        wait_timeout_secs: Option<u64>,
        /// Report which worker would be chosen without reserving slots or
        /// opening a durable build (`rch diagnose`).
        dry_run: bool,
        /// Resume only an identity-matched durable queue row from a prior daemon.
        resume_queued: bool,
    },
    ReleaseWorker(ReleaseRequest),
    RecordBuild {
        worker_id: WorkerId,
        project: String,
        is_test: bool,
    },
    BuildHeartbeat,
    IngestTelemetry(TelemetrySource),
    TestRun,
    TelemetryPoll {
        worker_id: WorkerId,
    },
    SpeedScore {
        worker_id: WorkerId,
    },
    SpeedScoreHistory {
        worker_id: WorkerId,
        days: u32,
        limit: usize,
        offset: usize,
    },
    SpeedScores,
    WorkersCapabilities {
        refresh: bool,
    },
    BenchmarkTrigger {
        worker_id: WorkerId,
    },
    Events,
    Status,
    Metrics,
    Health,
    Ready,
    Budget,
    SelfTestStatus,
    SelfTestHistory {
        limit: usize,
    },
    SelfTestRun(SelfTestRunRequest),
    Shutdown {
        fence: MaintenanceFence,
        force: bool,
    },
    /// Atomically mutate fenced daemon maintenance admission.
    RestartAdmission {
        fence: MaintenanceFence,
        action: MaintenanceAction,
    },
    /// Read the restart barrier without changing daemon state.
    RestartAdmissionStatus,
    /// Reload configuration (workers.toml) without restart.
    Reload,
    CancelBuild {
        build_id: u64,
        force: bool,
        local_wrapper_id: Option<String>,
    },
    CancelJob {
        local_wrapper_id: String,
    },
    CancelAllBuilds {
        force: bool,
    },
    BuildRecovery {
        build_id: u64,
        local_wrapper_id: String,
    },
    /// Drain a worker (stop sending new jobs, let existing jobs complete).
    WorkerDrain {
        worker_id: WorkerId,
    },
    /// Enable a previously disabled/draining worker.
    WorkerEnable {
        worker_id: WorkerId,
    },
    /// Disable a worker with optional reason and drain behavior.
    WorkerDisable {
        worker_id: WorkerId,
        reason: Option<String>,
        /// If true, drain existing jobs before fully disabling.
        drain_first: bool,
    },
    /// Get repo convergence status for all or a specific worker.
    RepoConvergenceStatus {
        worker_id: Option<WorkerId>,
    },
    /// Simulate convergence dry-run for a worker.
    RepoConvergenceDryRun {
        worker_id: WorkerId,
    },
    /// Trigger targeted convergence repair for a worker.
    RepoConvergenceRepair {
        worker_id: WorkerId,
    },
}

// ============================================================================
// Status Response Types (per bead remote_compilation_helper-3sy)
// ============================================================================

/// Full status response for GET /status endpoint.
///
/// Named `DaemonFullStatus` to distinguish from CLI's `SystemOverview` type.
#[derive(Debug, Serialize)]
pub struct DaemonFullStatus {
    /// Daemon metadata.
    pub daemon: DaemonStatusInfo,
    /// Effective admission state and the separately fenced maintenance owner.
    pub admission: RestartAdmissionResponse,
    /// Worker states.
    pub workers: Vec<WorkerStatusInfo>,
    /// Currently active builds.
    pub active_builds: Vec<ActiveBuild>,
    /// Queued builds waiting for workers.
    pub queued_builds: Vec<QueuedBuild>,
    /// Recent completed builds.
    pub recent_builds: Vec<BuildRecord>,
    /// Issues and warnings.
    pub issues: Vec<Issue>,
    /// Active alerts from worker health monitoring.
    pub alerts: Vec<AlertInfo>,
    /// Aggregate statistics.
    pub stats: BuildStats,
    /// Aggregate test run statistics.
    pub test_stats: TestRunStats,
    /// Saved time statistics from remote builds.
    pub saved_time: SavedTimeStats,
    /// Operator-facing remediation view: a compact, redacted snapshot of the
    /// remediation posture (desired/live fleet, admissibility, proof queue,
    /// jobs, disk pressure, telemetry freshness, recent incidents) rendered by
    /// the TUI/web dashboards (bd-session-history-remediation-ocv9i.14.4).
    /// Assembled once here so the three surfaces cannot disagree.
    pub remediation: rch_common::remediation_view::RemediationView,
}

/// Daemon metadata.
#[derive(Debug, Serialize)]
pub struct DaemonStatusInfo {
    /// Process ID.
    pub pid: u32,
    /// Uptime in seconds.
    pub uptime_secs: u64,
    /// Daemon version.
    pub version: String,
    /// Unix socket path.
    pub socket_path: String,
    /// When daemon started (ISO 8601).
    pub started_at: String,
    /// Total workers configured.
    pub workers_total: usize,
    /// Healthy workers.
    pub workers_healthy: usize,
    /// Total slots.
    pub slots_total: u32,
    /// Available slots.
    pub slots_available: u32,
}

/// Worker status information.
#[derive(Debug, Serialize)]
pub struct WorkerStatusInfo {
    /// Worker ID.
    pub id: String,
    /// Host address.
    pub host: String,
    /// SSH user.
    pub user: String,
    /// Current status.
    pub status: String,
    /// Circuit breaker state.
    pub circuit_state: String,
    /// Used slots.
    pub used_slots: u32,
    /// Total slots.
    pub total_slots: u32,
    /// Speed score (0-100).
    pub speed_score: f64,
    /// Last error message, if any.
    pub last_error: Option<String>,
    /// Consecutive failure count.
    pub consecutive_failures: u32,
    /// Seconds until circuit auto-recovers (None if not open or cooldown elapsed).
    pub recovery_in_secs: Option<u64>,
    /// Recent health check results (true=success, false=failure).
    /// Most recent result is at the end. Used for history visualization.
    pub failure_history: Vec<bool>,
    /// Normalized storage pressure state.
    pub pressure_state: String,
    /// Confidence level for the pressure decision.
    pub pressure_confidence: String,
    /// Stable pressure reason code.
    pub pressure_reason_code: String,
    /// Policy rule provenance for pressure classification.
    pub pressure_policy_rule: String,
    /// Measured free disk (GB), if available.
    pub pressure_disk_free_gb: Option<f64>,
    /// Measured total disk (GB), if available.
    pub pressure_disk_total_gb: Option<f64>,
    /// Measured free-disk ratio, if available.
    pub pressure_disk_free_ratio: Option<f64>,
    /// Free space (GB) on the filesystem holding build trees, which sizes
    /// slots and the free-space floor (GH #78). Absent when the worker reports
    /// no separate build-disk sample.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pressure_build_disk_free_gb: Option<f64>,
    /// Total size (GB) of the build-disk filesystem, if reported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pressure_build_disk_total_gb: Option<f64>,
    /// Last disk I/O utilization sample, if available.
    pub pressure_disk_io_util_pct: Option<f64>,
    /// Last memory pressure sample, if available.
    pub pressure_memory_pressure: Option<f64>,
    /// Age of latest telemetry sample in seconds, if available.
    pub pressure_telemetry_age_secs: Option<u64>,
    /// Whether the latest telemetry sample is fresh enough for high-confidence policy decisions.
    pub pressure_telemetry_fresh: bool,
    /// Active temporary-bypass record for this worker, if it is currently
    /// quarantined on the transient-eligibility axis. `None` for healthy or
    /// admin-disabled workers. Surfaces the bypass reason, next probe, backoff,
    /// and auto-rejoin criteria (bd-session-history-remediation-ocv9i.1.2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bypass: Option<BypassRecord>,
}

/// Active build information (placeholder).
#[derive(Debug, Serialize)]
pub struct ActiveBuild {
    /// Build ID.
    pub id: u64,
    /// Project identifier.
    pub project_id: String,
    /// Worker executing the build.
    pub worker_id: String,
    /// Command being executed.
    pub command: String,
    /// When build started (ISO 8601).
    pub started_at: String,
    /// Last heartbeat timestamp (ISO 8601).
    pub last_heartbeat_at: String,
    /// Age of the latest heartbeat sample in seconds.
    pub heartbeat_age_secs: u64,
    /// Last progress-evidence timestamp (ISO 8601).
    pub last_progress_at: String,
    /// Age of latest progress evidence in seconds.
    pub progress_age_secs: u64,
    /// Current heartbeat phase.
    pub heartbeat_phase: String,
    /// Progress detail captured from heartbeat samples.
    pub heartbeat_detail: Option<String>,
    /// Monotonic progress counter from the hook.
    pub heartbeat_counter: u64,
    /// Progress estimate in [0,100], when available.
    pub heartbeat_percent: Option<f64>,
    /// Slots currently owned by this build.
    pub slots: u32,
    /// Latest detector check: hook process alive.
    pub detector_hook_alive: bool,
    /// Latest detector check: heartbeat currently stale.
    pub detector_heartbeat_stale: bool,
    /// Latest detector check: progress evidence currently stale.
    pub detector_progress_stale: bool,
    /// Latest detector confidence in [0,1].
    pub detector_confidence: f64,
    /// Build age at last detector evaluation.
    pub detector_build_age_secs: u64,
    /// Slot count considered by detector at last evaluation.
    pub detector_slots_owned: u32,
    /// Last detector evaluation timestamp (ISO 8601), if available.
    pub detector_last_evaluated_at: Option<String>,
}

/// Queued build information.
///
/// Represents a build waiting for an available worker.
#[derive(Debug, Serialize)]
pub struct QueuedBuild {
    /// Queue position ID.
    pub id: u64,
    /// Exact decimal ID for clients whose JSON numbers cannot represent u64.
    pub id_text: String,
    /// Project identifier.
    pub project_id: String,
    /// Command to execute.
    pub command: String,
    /// When build was queued (ISO 8601).
    pub queued_at: String,
    /// Queue position (1-indexed).
    pub position: usize,
    /// Slots needed.
    pub slots_needed: u32,
    /// Estimated start time (ISO 8601), if available.
    pub estimated_start: Option<String>,
    /// Time waiting in queue (formatted string, e.g., "2m 15s").
    pub wait_time: String,
}

/// Issue or warning.
#[derive(Debug, Serialize)]
pub struct Issue {
    /// Severity: info, warning, error.
    pub severity: String,
    /// Short summary.
    pub summary: String,
    /// Suggested remediation command.
    pub remediation: Option<String>,
    /// The worker this issue is about, when it concerns one worker rather than
    /// the daemon. `rch check` rates such an issue as a degraded fleet, not a
    /// daemon that is not ready. Omitted for daemon-level issues.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub worker_id: Option<String>,
}

// ============================================================================
// Health & Ready Response Types (per bead remote_compilation_helper-lia)
// ============================================================================

/// Health check response.
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    /// Health status: "healthy" or "unhealthy".
    pub status: String,
    /// Daemon version.
    pub version: String,
    /// Uptime in seconds.
    pub uptime_seconds: u64,
}

/// Readiness check response.
#[derive(Debug, Serialize)]
pub struct ReadyResponse {
    /// Ready status: "ready" or "not_ready".
    pub status: String,
    /// Whether workers are available.
    pub workers_available: bool,
    /// Reason if not ready.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

// ============================================================================
// Self-Test Response Types (per bead remote_compilation_helper-cs7)
// ============================================================================

/// Request to run a self-test.
#[derive(Debug)]
pub struct SelfTestRunRequest {
    pub worker_ids: Vec<String>,
    pub project: Option<String>,
    pub timeout_secs: Option<u64>,
    pub release_mode: bool,
    pub scheduled: bool,
    /// Optional per-run retry-count override (`retries` query param). A bounded
    /// smoke canary passes `Some(0)` for one fail-fast attempt.
    pub retries: Option<u32>,
}

/// Status response for self-test scheduler.
#[derive(Debug, Serialize)]
pub struct SelfTestStatusResponse {
    pub enabled: bool,
    pub schedule: Option<String>,
    pub interval: Option<String>,
    pub last_run: Option<crate::self_test::SelfTestRunRecord>,
    pub next_run: Option<String>,
}

/// History response for self-tests.
#[derive(Debug, Serialize)]
pub struct SelfTestHistoryResponse {
    pub runs: Vec<crate::self_test::SelfTestRunRecord>,
    pub results: Vec<crate::self_test::SelfTestResultRecord>,
}

/// Run response for self-tests.
#[derive(Debug, Serialize)]
pub struct SelfTestRunResponse {
    pub run: crate::self_test::SelfTestRunRecord,
    pub results: Vec<crate::self_test::SelfTestResultRecord>,
}

/// Build heartbeat ingestion response.
#[derive(Debug, Serialize)]
pub struct BuildHeartbeatResponse {
    pub status: String,
    pub build_id: u64,
    pub worker_id: String,
    pub phase: String,
}

#[derive(Debug)]
enum MaintenanceAction {
    Acquire {
        purpose: String,
        owner_identity: ProcessIdentity,
    },
    Renew,
    Release,
    Recover,
}

// ============================================================================
// Build Cancellation Response Types (per bead remote_compilation_helper-scs)
// ============================================================================

/// Response for a single build cancellation.
#[derive(Debug, Serialize)]
pub struct CancelBuildResponse {
    pub status: String,
    pub build_id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub worker_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    pub slots_released: u32,
}

/// Response for cancelling multiple builds.
#[derive(Debug, Serialize)]
pub struct CancelAllBuildsResponse {
    pub status: String,
    pub cancelled_count: usize,
    pub cancelled: Vec<CancelledBuildInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Info about a cancelled build.
#[derive(Debug, Serialize)]
pub struct CancelledBuildInfo {
    pub build_id: u64,
    pub worker_id: String,
    pub project_id: String,
    pub slots_released: u32,
}

// ============================================================================
// SpeedScore Response Types (per bead remote_compilation_helper-y8n)
// ============================================================================

/// API view of a SpeedScore.
#[derive(Debug, Serialize)]
pub struct SpeedScoreView {
    pub total: f64,
    pub cpu_score: f64,
    pub memory_score: f64,
    pub disk_score: f64,
    pub network_score: f64,
    pub compilation_score: f64,
    pub measured_at: String,
    pub version: u32,
}

/// Latest SpeedScore response.
#[derive(Debug, Serialize)]
pub struct SpeedScoreResponse {
    pub worker_id: String,
    pub speedscore: Option<SpeedScoreView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// History pagination metadata.
#[derive(Debug, Serialize)]
pub struct PaginationInfo {
    pub total: u64,
    pub offset: usize,
    pub limit: usize,
    pub has_more: bool,
}

/// SpeedScore history response.
#[derive(Debug, Serialize)]
pub struct SpeedScoreHistoryResponse {
    pub worker_id: String,
    pub history: Vec<SpeedScoreView>,
    pub pagination: PaginationInfo,
}

/// SpeedScore list response.
#[derive(Debug, Serialize)]
pub struct SpeedScoreListResponse {
    pub workers: Vec<SpeedScoreWorker>,
}

#[derive(Debug, Serialize)]
pub struct SpeedScoreWorker {
    pub worker_id: String,
    pub speedscore: Option<SpeedScoreView>,
    pub status: WorkerStatus,
}

/// Benchmark trigger response.
#[derive(Debug, Serialize)]
pub struct BenchmarkTriggerResponse {
    pub status: String,
    pub worker_id: String,
    pub request_id: String,
}

// ============================================================================
// Repo Convergence Response Types (per bead bd-vvmd.3.5)
// ============================================================================

/// Worker convergence state view for JSON output.
#[derive(Debug, Serialize)]
pub struct ConvergenceWorkerView {
    pub worker_id: String,
    pub drift_state: String,
    pub drift_confidence: f64,
    pub required_repos: Vec<String>,
    pub synced_repos: Vec<String>,
    pub missing_repos: Vec<String>,
    pub attempt_budget_remaining: u32,
    pub time_budget_remaining_ms: u64,
    pub last_status_check_unix_ms: i64,
    pub remediation: Vec<String>,
}

/// Full convergence status response.
#[derive(Debug, Serialize)]
pub struct RepoConvergenceStatusResponse {
    pub status: String,
    pub workers: Vec<ConvergenceWorkerView>,
    pub recent_outcomes: Vec<crate::repo_convergence::ConvergenceOutcome>,
    pub summary: ConvergenceSummary,
}

/// Summary statistics for convergence status.
#[derive(Debug, Serialize)]
pub struct ConvergenceSummary {
    pub total_workers: usize,
    pub ready: usize,
    pub drifting: usize,
    pub converging: usize,
    pub failed: usize,
    pub stale: usize,
}

/// Dry-run response: what convergence would do without actually doing it.
#[derive(Debug, Serialize)]
pub struct RepoConvergenceDryRunResponse {
    pub status: String,
    pub worker_id: String,
    pub current_state: String,
    pub missing_repos: Vec<String>,
    pub has_budget: bool,
    pub attempt_budget_remaining: u32,
    pub time_budget_remaining_ms: u64,
    pub would_attempt: bool,
    pub reason: String,
    pub remediation: Vec<String>,
}

/// Repair response: result of triggering convergence repair.
#[derive(Debug, Serialize)]
pub struct RepoConvergenceRepairResponse {
    pub status: String,
    pub worker_id: String,
    pub action: String,
    pub previous_state: String,
    pub new_state: String,
    pub message: String,
}

/// Local API response enum for daemon endpoints.
///
/// Uses untagged serialization so success cases serialize directly as data,
/// while errors serialize using the unified ApiError format from rch-common.
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub(crate) enum ApiResponse<T: Serialize> {
    Ok(T),
    Error(ApiError),
}

fn selection_response_json(response: &SelectionResponse) -> Result<String> {
    let mut value = serde_json::to_value(response)?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| anyhow!("selection response did not serialize as an object"))?;
    object.insert(
        "selection_protocol_version".to_string(),
        serde_json::json!(SELECTION_RESPONSE_PROTOCOL_VERSION),
    );
    Ok(serde_json::to_string(&value)?)
}

/// Log an operator worker action with its caller, so a drain, enable or disable
/// can be attributed later. On 2026-09-28 hz4 and vmi1152480 were drained twice
/// with no admin record and no log line, and nobody could say which agent did
/// it. `ps` is bounded to one second per lookup and its output is truncated.
async fn log_worker_admin_action(
    action: &str,
    worker_id: &WorkerId,
    outcome: &str,
    peer_pid: Option<i32>,
) {
    let caller = match peer_pid {
        Some(pid) => describe_caller(pid).await,
        None => "unknown caller".to_string(),
    };
    info!(
        action,
        worker = %worker_id,
        outcome,
        caller = %caller,
        "Worker admin action"
    );
}

async fn describe_caller(pid: i32) -> String {
    async fn ps(fields: &str, pid: &str) -> Option<String> {
        let output = tokio::time::timeout(
            Duration::from_secs(1),
            tokio::process::Command::new("ps")
                .args(["-o", fields, "-p", pid])
                .kill_on_drop(true)
                .output(),
        )
        .await
        .ok()?
        .ok()?;
        let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
        (!text.is_empty()).then(|| text.chars().take(160).collect())
    }
    let pid_text = pid.to_string();
    let Some(line) = ps("ppid=,command=", &pid_text).await else {
        return format!("pid={pid}");
    };
    let (ppid, command) = line
        .trim_start()
        .split_once(char::is_whitespace)
        .unwrap_or((line.as_str(), ""));
    let parent = ps("command=", ppid.trim()).await.unwrap_or_default();
    format!(
        "pid={pid} cmd={:?} ppid={} parent={parent:?}",
        command.trim(),
        ppid.trim()
    )
}

/// Handle an incoming connection on the Unix socket.
pub async fn handle_connection(
    stream: UnixStream,
    ctx: DaemonContext,
    shutdown_tx: tokio::sync::mpsc::Sender<()>,
) -> Result<()> {
    handle_connection_with_metrics(
        stream,
        ctx,
        shutdown_tx,
        metrics::tracing::request_metrics(),
    )
    .await
}

async fn handle_connection_with_metrics(
    stream: UnixStream,
    ctx: DaemonContext,
    shutdown_tx: tokio::sync::mpsc::Sender<()>,
    request_metrics: Option<rch_telemetry::metrics::Metrics>,
) -> Result<()> {
    // Bind maintenance, and a pre-2.1 client's release (GH #119), to the
    // connection owner's observed birth before any await. A delayed request
    // may not acquire rights under a recycled PID. Keep the PID separately
    // for operator-action log attribution.
    let peer_pid = stream.peer_cred().ok().and_then(|cred| cred.pid());
    let maintenance_peer = MaintenancePeer::capture(peer_pid);
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    // Read the request line
    let n = read_line_with_limit(&mut reader, &mut line, MAX_LINE_SIZE).await?;
    if n == 0 {
        return Ok(()); // Connection closed
    }

    let line = line.trim();
    debug!("Received request: {}", line);

    // Observe finite request handling, including error returns and cancellation.
    // Event subscriptions live until disconnect, so their lifetime is not a
    // request latency sample. Reading the initial request line is excluded.
    let request = parse_request(line);
    let _request_duration = (!matches!(&request, Ok(ApiRequest::Events)))
        .then(|| metrics::tracing::RequestDuration::start(request_metrics));

    // Parse and handle the request
    let (response_json, content_type) = match request {
        Ok(ApiRequest::SelectWorker {
            request,
            local_wrapper_id,
            wait_for_worker,
            wait_timeout_secs,
            dry_run,
            resume_queued,
        }) => {
            metrics::inc_requests("select-worker");
            let response = if dry_run {
                handle_select_worker_dry_run(&ctx, &request).await
            } else {
                handle_select_worker_mode(
                    &ctx,
                    request,
                    wait_for_worker,
                    wait_timeout_secs,
                    local_wrapper_id,
                    resume_queued,
                )
                .await?
            };
            (selection_response_json(&response)?, "application/json")
        }
        Ok(ApiRequest::ReleaseWorker(mut request)) => {
            metrics::inc_requests("release-worker");
            // Read optional JSON body line for timing breakdown
            // Use a short timeout to avoid blocking when no body is sent
            let mut body_line = String::new();
            if let Ok(Ok(_)) = tokio::time::timeout(
                Duration::from_millis(50),
                read_line_with_limit(&mut reader, &mut body_line, MAX_LINE_SIZE),
            )
            .await
            {
                let body = body_line.trim();
                if !body.is_empty()
                    && let Ok(timing) =
                        serde_json::from_str::<rch_common::CommandTimingBreakdown>(body)
                {
                    request.timing = Some(timing);
                }
            }
            handle_release_worker_from(&ctx, request, maintenance_peer.as_ref()).await?;
            ("{}".to_string(), "application/json")
        }
        Ok(ApiRequest::RecordBuild {
            worker_id,
            project,
            is_test,
        }) => {
            metrics::inc_requests("record-build");
            handle_record_build(&ctx, &worker_id, &project, is_test).await?;
            ("{}".to_string(), "application/json")
        }
        Ok(ApiRequest::BuildHeartbeat) => {
            metrics::inc_requests("build-heartbeat");
            let mut body = String::new();
            match tokio::time::timeout(
                Duration::from_secs(5),
                read_line_with_limit(&mut reader, &mut body, MAX_LINE_SIZE),
            )
            .await
            {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    warn!("Build heartbeat body read timed out");
                    return Ok(());
                }
            }
            let payload = body.trim();
            if payload.is_empty() {
                (
                    "{\"status\":\"error\",\"error\":\"empty build heartbeat payload\"}"
                        .to_string(),
                    "application/json",
                )
            } else {
                match serde_json::from_str::<BuildHeartbeatRequest>(payload) {
                    Ok(request) => {
                        let response = handle_build_heartbeat(&ctx, request).await;
                        (serde_json::to_string(&response)?, "application/json")
                    }
                    Err(e) => {
                        warn!("Failed to parse build heartbeat JSON: {}", e);
                        (
                            "{\"status\":\"error\",\"error\":\"invalid build heartbeat payload\"}"
                                .to_string(),
                            "application/json",
                        )
                    }
                }
            }
        }
        Ok(ApiRequest::IngestTelemetry(source)) => {
            metrics::inc_requests("telemetry");
            let mut body = String::new();
            match tokio::time::timeout(
                Duration::from_secs(5),
                read_line_with_limit(&mut reader, &mut body, MAX_LINE_SIZE),
            )
            .await
            {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    warn!("Telemetry body read timed out");
                    return Ok(());
                }
            }
            let payload = body.trim();

            if payload.is_empty() {
                warn!("Telemetry ingestion received empty body");
                (
                    "{\"status\":\"error\",\"error\":\"empty telemetry payload\"}".to_string(),
                    "application/json",
                )
            } else {
                match WorkerTelemetry::from_json(payload) {
                    Ok(telemetry) => {
                        if !telemetry.is_compatible() {
                            warn!(
                                "Telemetry protocol version mismatch for worker {}",
                                telemetry.worker_id
                            );
                        }
                        ctx.telemetry.ingest(telemetry, source);
                        ("{\"status\":\"ok\"}".to_string(), "application/json")
                    }
                    Err(e) => {
                        warn!("Failed to parse telemetry JSON: {}", e);
                        (
                            "{\"status\":\"error\",\"error\":\"invalid telemetry payload\"}"
                                .to_string(),
                            "application/json",
                        )
                    }
                }
            }
        }
        Ok(ApiRequest::TestRun) => {
            metrics::inc_requests("test-run");
            let mut body = String::new();
            match tokio::time::timeout(
                Duration::from_secs(5),
                read_line_with_limit(&mut reader, &mut body, MAX_LINE_SIZE),
            )
            .await
            {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    warn!("Test run body read timed out");
                    return Ok(());
                }
            }
            let payload = body.trim();

            if payload.is_empty() {
                warn!("Test run ingestion received empty body");
                (
                    "{\"status\":\"error\",\"error\":\"empty test run payload\"}".to_string(),
                    "application/json",
                )
            } else {
                match TestRunRecord::from_json(payload) {
                    Ok(record) => {
                        ctx.telemetry.record_test_run(record);
                        ("{\"status\":\"ok\"}".to_string(), "application/json")
                    }
                    Err(e) => {
                        warn!("Failed to parse test run JSON: {}", e);
                        (
                            "{\"status\":\"error\",\"error\":\"invalid test run payload\"}"
                                .to_string(),
                            "application/json",
                        )
                    }
                }
            }
        }
        Ok(ApiRequest::TelemetryPoll { worker_id }) => {
            metrics::inc_requests("telemetry-poll");
            let response = handle_telemetry_poll(&ctx, &worker_id).await;
            let response_json = serde_json::to_string(&response)?;
            (response_json, "application/json")
        }
        Ok(ApiRequest::SpeedScore { worker_id }) => {
            metrics::inc_requests("speedscore");
            let response = handle_speedscore(&ctx, &worker_id).await;
            (serde_json::to_string(&response)?, "application/json")
        }
        Ok(ApiRequest::SpeedScoreHistory {
            worker_id,
            days,
            limit,
            offset,
        }) => {
            metrics::inc_requests("speedscore-history");
            let response = handle_speedscore_history(&ctx, &worker_id, days, limit, offset).await;
            (serde_json::to_string(&response)?, "application/json")
        }
        Ok(ApiRequest::SpeedScores) => {
            metrics::inc_requests("speedscore-list");
            let response = handle_speedscore_list(&ctx).await;
            (serde_json::to_string(&response)?, "application/json")
        }
        Ok(ApiRequest::WorkersCapabilities { refresh }) => {
            metrics::inc_requests("workers-capabilities");
            let response = handle_workers_capabilities(&ctx, refresh).await;
            (serde_json::to_string(&response)?, "application/json")
        }
        Ok(ApiRequest::BenchmarkTrigger { worker_id }) => {
            metrics::inc_requests("benchmark-trigger");
            let response = handle_benchmark_trigger(&ctx, &worker_id).await;
            (serde_json::to_string(&response)?, "application/json")
        }
        Ok(ApiRequest::Events) => {
            metrics::inc_requests("events");
            handle_event_stream(&mut writer, ctx.events.clone()).await?;
            return Ok(());
        }
        Ok(ApiRequest::Status) => {
            metrics::inc_requests("status");
            let status = handle_status(&ctx).await?;
            (serde_json::to_string(&status)?, "application/json")
        }
        Ok(ApiRequest::Metrics) => {
            metrics::inc_requests("metrics");
            let metrics_text = handle_metrics()?;
            (metrics_text, "text/plain; version=0.0.4")
        }
        Ok(ApiRequest::Health) => {
            metrics::inc_requests("health");
            let health = handle_health(&ctx);
            (serde_json::to_string(&health)?, "application/json")
        }
        Ok(ApiRequest::Ready) => {
            metrics::inc_requests("ready");
            let ready = handle_ready(&ctx).await;
            (serde_json::to_string(&ready)?, "application/json")
        }
        Ok(ApiRequest::Budget) => {
            metrics::inc_requests("budget");
            let budget_status = handle_budget();
            (serde_json::to_string(&budget_status)?, "application/json")
        }
        Ok(ApiRequest::SelfTestStatus) => {
            metrics::inc_requests("self-test-status");
            let status = ctx.self_test.status();
            let response = SelfTestStatusResponse {
                enabled: status.enabled,
                schedule: status.schedule,
                interval: status.interval,
                last_run: status.last_run,
                next_run: status.next_run,
            };
            (serde_json::to_string(&response)?, "application/json")
        }
        Ok(ApiRequest::SelfTestHistory { limit }) => {
            metrics::inc_requests("self-test-history");
            let runs = ctx.self_test.history().recent_runs(limit);
            let run_ids: Vec<u64> = runs.iter().map(|run| run.id).collect();
            let results = ctx.self_test.history().results_for_runs(&run_ids);
            let response = SelfTestHistoryResponse { runs, results };
            (serde_json::to_string(&response)?, "application/json")
        }
        Ok(ApiRequest::SelfTestRun(request)) => {
            metrics::inc_requests("self-test-run");
            let mut options = crate::self_test::SelfTestRunOptions {
                run_type: if request.scheduled {
                    crate::self_test::SelfTestRunType::Scheduled
                } else {
                    crate::self_test::SelfTestRunType::Manual
                },
                ..Default::default()
            };
            if !request.worker_ids.is_empty() {
                options.worker_ids =
                    Some(request.worker_ids.into_iter().map(WorkerId::new).collect());
            }
            if let Some(project) = request.project {
                options.project_path = Some(PathBuf::from(project));
            }
            if let Some(timeout) = request.timeout_secs {
                options.timeout = Duration::from_secs(timeout);
            }
            options.release_mode = request.release_mode;
            options.retry_count_override = request.retries;

            let report = if request.scheduled {
                ctx.self_test.run_scheduled_now().await?
            } else {
                ctx.self_test.run_manual(options).await?
            };
            let response = SelfTestRunResponse {
                run: report.run,
                results: report.results,
            };
            (serde_json::to_string(&response)?, "application/json")
        }
        Ok(ApiRequest::Shutdown { fence, force }) => {
            metrics::inc_requests("shutdown");
            let response =
                handle_shutdown(&ctx, &fence, force, maintenance_peer.as_ref(), &shutdown_tx).await;
            (serde_json::to_string(&response)?, "application/json")
        }
        Ok(ApiRequest::RestartAdmission { fence, action }) => {
            metrics::inc_requests("restart-admission");
            let response =
                handle_restart_admission(&ctx, &fence, action, maintenance_peer.as_ref()).await;
            (serde_json::to_string(&response)?, "application/json")
        }
        Ok(ApiRequest::RestartAdmissionStatus) => {
            metrics::inc_requests("restart-admission-status");
            let response = restart_admission_status(&ctx).await;
            (serde_json::to_string(&response)?, "application/json")
        }
        Ok(ApiRequest::Reload) => {
            metrics::inc_requests("reload");
            // Reload from the file the daemon was launched with, never from a
            // freshly resolved default (bd-xqg58).
            let result =
                reload::reload_workers(&ctx.pool, ctx.workers_config_path.as_deref(), true).await;
            match result {
                Ok(reload_result) => {
                    let response = serde_json::json!({
                        "success": true,
                        "added": reload_result.added,
                        "updated": reload_result.updated,
                        "removed": reload_result.removed,
                        "warnings": reload_result.warnings
                    });
                    (response.to_string(), "application/json")
                }
                Err(e) => {
                    warn!("Configuration reload failed: {}", e);
                    let response = serde_json::json!({
                        "success": false,
                        "error": e.to_string()
                    });
                    (response.to_string(), "application/json")
                }
            }
        }
        Ok(ApiRequest::BuildRecovery {
            build_id,
            local_wrapper_id,
        }) => {
            let response = if let Some(active) = ctx.history.active_build(build_id) {
                if active.local_wrapper_id.as_deref() == Some(local_wrapper_id.as_str()) {
                    serde_json::json!({"status":"active","active":active})
                } else {
                    serde_json::json!({"status":"identity_mismatch"})
                }
            } else if let Some(record) = ctx.history.terminal_build(build_id, &local_wrapper_id) {
                serde_json::json!({"status":"completed","record":record,"local_wrapper_id":local_wrapper_id})
            } else if ctx.history.has_terminal_build(build_id) {
                serde_json::json!({"status":"identity_mismatch"})
            } else {
                serde_json::json!({"status":"not_found"})
            };
            (response.to_string(), "application/json")
        }
        Ok(ApiRequest::CancelJob { local_wrapper_id }) => {
            let response = handle_cancel_job(&ctx, &local_wrapper_id, false).await?;
            (response.to_string(), "application/json")
        }
        Ok(ApiRequest::CancelBuild {
            build_id,
            force,
            local_wrapper_id,
        }) => {
            metrics::inc_requests("cancel-build");
            if let Some(queued) = ctx.history.queued_build(build_id).filter(|_| {
                ctx.history.active_build(build_id).is_none()
                    && !ctx.history.has_terminal_build(build_id)
            }) {
                let response = match queued.local_wrapper_id.as_deref() {
                    Some(wrapper)
                        if local_wrapper_id
                            .as_deref()
                            .is_none_or(|requested| requested == wrapper) =>
                    {
                        let mut response = handle_cancel_job(&ctx, wrapper, force).await?;
                        response["queue_id"] = serde_json::json!(build_id);
                        if response["status"] == "cancelled_before_start" {
                            response["status"] = serde_json::json!("cancelled");
                            response["build_id"] = serde_json::json!(build_id);
                            response["message"] =
                                serde_json::json!("Queued job cancelled before start");
                        }
                        response
                    }
                    _ => {
                        serde_json::json!({"status":"error", "build_id":build_id, "slots_released":0, "message":"Queued job has no matching durable wrapper identity; cancellation refused"})
                    }
                };
                (response.to_string(), "application/json")
            } else if let Some(record) = local_wrapper_id
                .as_deref()
                .and_then(|wrapper| ctx.history.terminal_build(build_id, wrapper))
            {
                (serde_json::json!({"status":"completed","record":record,"local_wrapper_id":local_wrapper_id}).to_string(), "application/json")
            } else {
                let owner = ctx
                    .history
                    .active_build(build_id)
                    .filter(|state| state.local_wrapper_id != local_wrapper_id);
                let response = if owner.is_some() || ctx.history.has_terminal_build(build_id) {
                    CancelBuildResponse {
                        status: "error".to_string(),
                        build_id,
                        worker_id: None,
                        project_id: None,
                        message: Some(ownership_mismatch_message(
                            build_id,
                            owner
                                .as_ref()
                                .map(|state| state.local_wrapper_id.as_deref()),
                        )),
                        slots_released: 0,
                    }
                } else {
                    handle_cancel_build(&ctx, build_id, force).await
                };
                (serde_json::to_string(&response)?, "application/json")
            }
        }
        Ok(ApiRequest::CancelAllBuilds { force }) => {
            metrics::inc_requests("cancel-all-builds");
            let response = handle_cancel_all_builds(&ctx, force).await;
            (serde_json::to_string(&response)?, "application/json")
        }
        Ok(ApiRequest::WorkerDrain { worker_id }) => {
            metrics::inc_requests("worker-drain");
            let response = handle_worker_drain(&ctx, &worker_id).await;
            log_worker_admin_action("drain", &worker_id, &response.status, peer_pid).await;
            (serde_json::to_string(&response)?, "application/json")
        }
        Ok(ApiRequest::WorkerEnable { worker_id }) => {
            metrics::inc_requests("worker-enable");
            let response = handle_worker_enable(&ctx, &worker_id).await;
            log_worker_admin_action("enable", &worker_id, &response.status, peer_pid).await;
            (serde_json::to_string(&response)?, "application/json")
        }
        Ok(ApiRequest::WorkerDisable {
            worker_id,
            reason,
            drain_first,
        }) => {
            metrics::inc_requests("worker-disable");
            let response = handle_worker_disable(&ctx, &worker_id, reason, drain_first).await;
            log_worker_admin_action("disable", &worker_id, &response.status, peer_pid).await;
            (serde_json::to_string(&response)?, "application/json")
        }
        Ok(ApiRequest::RepoConvergenceStatus { worker_id }) => {
            metrics::inc_requests("repo-convergence-status");
            let response = handle_repo_convergence_status(&ctx, worker_id.as_ref()).await;
            (serde_json::to_string(&response)?, "application/json")
        }
        Ok(ApiRequest::RepoConvergenceDryRun { worker_id }) => {
            metrics::inc_requests("repo-convergence-dry-run");
            let response = handle_repo_convergence_dry_run(&ctx, &worker_id).await;
            (serde_json::to_string(&response)?, "application/json")
        }
        Ok(ApiRequest::RepoConvergenceRepair { worker_id }) => {
            metrics::inc_requests("repo-convergence-repair");
            let response = handle_repo_convergence_repair(&ctx, &worker_id).await;
            (serde_json::to_string(&response)?, "application/json")
        }
        Err(e) => return Err(e),
    };

    // Send the response
    let response_bytes = format!(
        "HTTP/1.0 200 OK\r\nContent-Type: {}\r\n\r\n{}\n",
        content_type, response_json
    );

    writer.write_all(response_bytes.as_bytes()).await?;
    writer.flush().await?;

    Ok(())
}

/// Parse a request line into an ApiRequest.
fn parse_request(line: &str) -> Result<ApiRequest> {
    // Expected format: GET /select-worker?project=X&cores=N
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(anyhow!("Invalid request format"));
    }

    let method = parts[0];
    let path = parts[1];

    if method != "GET" && method != "POST" {
        return Err(anyhow!("Only GET and POST methods supported"));
    }

    if path == "/events" && method == "GET" {
        return Ok(ApiRequest::Events);
    }

    if path == "/speedscores" && method == "GET" {
        return Ok(ApiRequest::SpeedScores);
    }

    if path.starts_with("/workers/capabilities") && method == "GET" {
        let (path_only, query) = split_path_query(path);
        if path_only == "/workers/capabilities" {
            let mut refresh = false;
            for param in query.split('&') {
                if param.is_empty() {
                    continue;
                }
                let mut kv = param.splitn(2, '=');
                let key = kv.next().unwrap_or("");
                let value = kv.next().unwrap_or("");
                if key == "refresh" && (value == "1" || value.eq_ignore_ascii_case("true")) {
                    refresh = true;
                }
            }
            return Ok(ApiRequest::WorkersCapabilities { refresh });
        }
    }

    if path.starts_with("/speedscore") && method == "GET" {
        let (path_only, query) = split_path_query(path);

        if path_only == "/speedscore/history" {
            let mut worker_id = None;
            let mut days = 30u32;
            let mut limit = 100usize;
            let mut offset = 0usize;

            for param in query.split('&') {
                if param.is_empty() {
                    continue;
                }
                let mut kv = param.splitn(2, '=');
                let key = kv.next().unwrap_or("");
                let value = kv.next().unwrap_or("");
                match key {
                    "worker" => worker_id = Some(percent_unescape_query_value(value)),
                    "days" => days = value.parse().unwrap_or(days),
                    "limit" => limit = value.parse().unwrap_or(limit).min(10_000),
                    "offset" => offset = value.parse().unwrap_or(offset).min(1_000_000),
                    _ => {}
                }
            }

            if let Some(worker_id) = worker_id {
                return Ok(ApiRequest::SpeedScoreHistory {
                    worker_id: WorkerId::new(worker_id),
                    days,
                    limit,
                    offset,
                });
            }
        }

        if let Some(rest) = path_only.strip_prefix("/speedscore/") {
            let rest = rest.trim_matches('/');
            if rest.is_empty() {
                return Err(anyhow!("Missing worker id"));
            }

            if let Some(worker_part) = rest.strip_suffix("/history") {
                let worker_part = worker_part.trim_end_matches('/');
                let mut days = 30u32;
                let mut limit = 100usize;
                let mut offset = 0usize;

                for param in query.split('&') {
                    if param.is_empty() {
                        continue;
                    }
                    let mut kv = param.splitn(2, '=');
                    let key = kv.next().unwrap_or("");
                    let value = kv.next().unwrap_or("");
                    match key {
                        "days" => days = value.parse().unwrap_or(days),
                        "limit" => limit = value.parse().unwrap_or(limit).min(10_000),
                        "offset" => offset = value.parse().unwrap_or(offset).min(1_000_000),
                        _ => {}
                    }
                }

                return Ok(ApiRequest::SpeedScoreHistory {
                    worker_id: WorkerId::new(percent_unescape_query_value(worker_part)),
                    days,
                    limit,
                    offset,
                });
            }

            return Ok(ApiRequest::SpeedScore {
                worker_id: WorkerId::new(percent_unescape_query_value(rest)),
            });
        }
    }

    if route_matches_exact_or_child(path, "/benchmark/trigger") {
        if method != "POST" {
            return Err(anyhow!("Only POST method supported for benchmark trigger"));
        }
        let (path_only, query) = split_path_query(path);
        let mut worker_id = path_only
            .strip_prefix("/benchmark/trigger/")
            .map(percent_unescape_query_value);

        for param in query.split('&') {
            if param.is_empty() {
                continue;
            }
            let mut kv = param.splitn(2, '=');
            let key = kv.next().unwrap_or("");
            let value = kv.next().unwrap_or("");
            if key == "worker" {
                worker_id = Some(percent_unescape_query_value(value));
            }
        }

        let Some(worker_id) = worker_id.filter(|value| !value.is_empty()) else {
            return Err(anyhow!("Missing worker id"));
        };

        return Ok(ApiRequest::BenchmarkTrigger {
            worker_id: WorkerId::new(worker_id),
        });
    }

    let (maintenance_path, maintenance_query) = split_path_query(path);
    if maintenance_path == "/restart-admission" && method == "GET" {
        return Ok(ApiRequest::RestartAdmissionStatus);
    }
    if method == "POST"
        && matches!(
            maintenance_path,
            "/shutdown"
                | "/restart-admission"
                | "/restart-admission/renew"
                | "/restart-admission/release"
                | "/restart-admission/recover"
        )
    {
        let MaintenanceQuery {
            fence,
            purpose,
            force,
            owner_identity,
        } = parse_maintenance_query(maintenance_query)?;
        anyhow::ensure!(
            maintenance_path == "/restart-admission" || owner_identity.is_none(),
            "owner_identity is only valid for maintenance acquisition"
        );
        if maintenance_path == "/shutdown" {
            return Ok(ApiRequest::Shutdown { fence, force });
        }
        anyhow::ensure!(!force, "force is only valid for shutdown");
        let action = match maintenance_path {
            "/restart-admission" => MaintenanceAction::Acquire {
                purpose,
                owner_identity: owner_identity
                    .ok_or_else(|| anyhow!("maintenance owner_identity is required"))?,
            },
            "/restart-admission/renew" => MaintenanceAction::Renew,
            "/restart-admission/release" => MaintenanceAction::Release,
            _ => MaintenanceAction::Recover,
        };
        return Ok(ApiRequest::RestartAdmission { fence, action });
    }

    if path == "/reload" && method == "POST" {
        return Ok(ApiRequest::Reload);
    }

    // Build cancellation endpoints
    if method == "POST"
        && let Some(wrapper) = path
            .strip_prefix("/jobs/")
            .and_then(|rest| rest.strip_suffix("/cancel"))
    {
        let uuid = wrapper
            .strip_prefix(LOCAL_WRAPPER_ID_PREFIX)
            .ok_or_else(|| anyhow!("Invalid local wrapper id"))?;
        Uuid::parse_str(uuid).map_err(|_| anyhow!("Invalid local wrapper id"))?;
        return Ok(ApiRequest::CancelJob {
            local_wrapper_id: wrapper.to_owned(),
        });
    }
    if method == "GET" && path.starts_with("/builds/") {
        let (route, query) = path.split_once('?').unwrap_or((path, ""));
        let build_id = route
            .trim_start_matches("/builds/")
            .trim_end_matches('/')
            .parse::<u64>()
            .map_err(|_| anyhow!("Invalid build id"))?;
        let local_wrapper_id = query
            .split('&')
            .find_map(|pair| pair.strip_prefix("local_wrapper_id="))
            .map(percent_unescape_query_value)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| anyhow!("Missing local_wrapper_id"))?;
        return Ok(ApiRequest::BuildRecovery {
            build_id,
            local_wrapper_id,
        });
    }
    if method == "POST" && path.starts_with("/builds") {
        let (path_only, query) = split_path_query(path);

        if path_only == "/builds/cancel-all" {
            let mut force = false;
            for param in query.split('&') {
                if param.is_empty() {
                    continue;
                }
                let mut kv = param.splitn(2, '=');
                let key = kv.next().unwrap_or("");
                let value = kv.next().unwrap_or("");
                if key == "force" {
                    force = value == "1" || value.eq_ignore_ascii_case("true");
                }
            }
            return Ok(ApiRequest::CancelAllBuilds { force });
        }

        if let Some(rest) = path_only.strip_prefix("/builds/") {
            let rest = rest.trim_matches('/');
            let parts: Vec<&str> = rest.split('/').collect();
            if parts.len() == 2 && parts[1] == "cancel" {
                let build_id = parts[0]
                    .parse::<u64>()
                    .map_err(|_| anyhow!("Invalid build id: {}", parts[0]))?;

                let mut force = false;
                let mut local_wrapper_id = None;
                for param in query.split('&') {
                    if param.is_empty() {
                        continue;
                    }
                    let mut kv = param.splitn(2, '=');
                    let key = kv.next().unwrap_or("");
                    let value = kv.next().unwrap_or("");
                    if key == "force" {
                        force = value == "1" || value.eq_ignore_ascii_case("true");
                    } else if key == "local_wrapper_id" {
                        local_wrapper_id = Some(percent_unescape_query_value(value));
                    }
                }

                return Ok(ApiRequest::CancelBuild {
                    build_id,
                    force,
                    local_wrapper_id,
                });
            }
        }
    }

    if path == "/status" {
        return Ok(ApiRequest::Status);
    }

    if path == "/metrics" {
        return Ok(ApiRequest::Metrics);
    }

    if path == "/health" {
        return Ok(ApiRequest::Health);
    }

    if path == "/ready" {
        return Ok(ApiRequest::Ready);
    }

    if path == "/budget" {
        return Ok(ApiRequest::Budget);
    }

    if path == "/self-test/status" {
        return Ok(ApiRequest::SelfTestStatus);
    }

    if let Some(query) = query_for_exact_route(path, "/self-test/history") {
        let mut limit = 10usize;
        for param in query.split('&') {
            if param.is_empty() {
                continue;
            }
            let mut kv = param.splitn(2, '=');
            let key = kv.next().unwrap_or("");
            let value = kv.next().unwrap_or("");
            if key == "limit" {
                limit = value.parse().unwrap_or(limit).min(10_000);
            }
        }
        return Ok(ApiRequest::SelfTestHistory { limit });
    }

    if let Some(query) = query_for_exact_route(path, "/self-test/run") {
        if method != "POST" {
            return Err(anyhow!("Only POST method supported for self-test run"));
        }

        let mut worker_ids = Vec::new();
        let mut project = None;
        let mut timeout_secs = None;
        let mut release_mode = true;
        let mut scheduled = false;
        let mut retries = None;

        for param in query.split('&') {
            if param.is_empty() {
                continue;
            }
            let mut kv = param.splitn(2, '=');
            let key = kv.next().unwrap_or("");
            let value = kv.next().unwrap_or("");
            match key {
                "worker" => worker_ids.push(percent_unescape_query_value(value)),
                "project" => project = Some(percent_unescape_query_value(value)),
                "timeout" => timeout_secs = value.parse().ok(),
                "retries" => retries = value.parse().ok(),
                "debug" if value == "1" || value.eq_ignore_ascii_case("true") => {
                    release_mode = false;
                }
                "scheduled" if value == "1" || value.eq_ignore_ascii_case("true") => {
                    scheduled = true;
                }
                "all" if value == "1" || value.eq_ignore_ascii_case("true") => {
                    worker_ids.clear();
                }
                _ => {}
            }
        }

        return Ok(ApiRequest::SelfTestRun(SelfTestRunRequest {
            worker_ids,
            project,
            timeout_secs,
            release_mode,
            scheduled,
            retries,
        }));
    }

    if let Some(query) = query_for_exact_route(path, "/release-worker") {
        if method != "POST" {
            return Err(anyhow!("Only POST method supported for release"));
        }

        let mut worker_id = None;
        let mut slots = None;
        let mut build_id = None;
        let mut exit_code = None;
        let mut duration_ms = None;
        let mut bytes_transferred = None;
        let mut disk_peak_output_bytes = None;
        let mut local_wrapper_id = None;
        let mut worker_fault = false;
        let mut worker_disk_full = false;
        let mut worker_disk_roots = Vec::new();
        let mut worker_live_checkout_refused = false;
        let mut worker_source_busy = false;

        for param in query.split('&') {
            if param.is_empty() {
                continue;
            }
            let mut kv = param.splitn(2, '=');
            let key = kv.next().unwrap_or("");
            let value = kv.next().unwrap_or("");

            match key {
                "worker" => worker_id = Some(percent_unescape_query_value(value)),
                "slots" => slots = value.parse().ok(),
                "build_id" => build_id = value.parse().ok(),
                "exit_code" => {
                    anyhow::ensure!(exit_code.is_none(), "Duplicate release exit code");
                    exit_code = Some(value.parse::<i32>().context("Invalid release exit code")?);
                }
                "duration_ms" => duration_ms = value.parse().ok(),
                "bytes_transferred" => bytes_transferred = value.parse().ok(),
                "disk_peak_output_bytes" => {
                    anyhow::ensure!(
                        disk_peak_output_bytes.is_none(),
                        "Duplicate disk peak output measurement"
                    );
                    disk_peak_output_bytes = Some(
                        value
                            .parse::<u64>()
                            .context("Invalid disk peak output measurement")?,
                    );
                }
                "local_wrapper_id" => local_wrapper_id = Some(percent_unescape_query_value(value)),
                "worker_fault" => worker_fault = matches!(value, "1" | "true"),
                "worker_disk_full" => worker_disk_full = matches!(value, "1" | "true"),
                "worker_live_checkout_refused" => {
                    worker_live_checkout_refused = matches!(value, "1" | "true")
                }
                "worker_source_busy" => worker_source_busy = matches!(value, "1" | "true"),
                "worker_disk_roots" => {
                    worker_disk_roots =
                        serde_json::from_str::<Vec<String>>(&percent_unescape_query_value(value))
                            .context("Invalid worker disk roots")?;
                }
                _ => {} // Ignore unknown parameters
            }
        }

        let worker_id = worker_id.ok_or_else(|| anyhow!("Missing 'worker' parameter"))?;
        let slots = slots.unwrap_or(0);

        anyhow::ensure!(
            disk_peak_output_bytes.is_none() || exit_code.is_some(),
            "Disk output measurement requires an explicit release exit code"
        );
        return Ok(ApiRequest::ReleaseWorker(ReleaseRequest {
            worker_id: rch_common::WorkerId::new(worker_id),
            slots,
            build_id,
            exit_code,
            duration_ms,
            bytes_transferred,
            disk_peak_output_bytes,
            local_wrapper_id,
            timing: None,
            worker_fault,
            worker_disk_full,
            worker_disk_roots,
            worker_live_checkout_refused,
            worker_source_busy,
        }));
    }

    if let Some(query) = query_for_exact_route(path, "/record-build") {
        if method != "POST" {
            return Err(anyhow!("Only POST method supported for record-build"));
        }

        let mut worker_id = None;
        let mut project = None;
        let mut is_test = false;

        for param in query.split('&') {
            if param.is_empty() {
                continue;
            }
            let mut kv = param.splitn(2, '=');
            let key = kv.next().unwrap_or("");
            let value = kv.next().unwrap_or("");

            match key {
                "worker" => worker_id = Some(percent_unescape_query_value(value)),
                "project" => project = Some(percent_unescape_query_value(value)),
                "is_test" => {
                    let query_value = percent_unescape_query_value(value);
                    is_test = matches!(query_value.as_str(), "1" | "true" | "yes" | "y" | "on");
                }
                _ => {}
            }
        }

        let worker_id = worker_id.ok_or_else(|| anyhow!("Missing 'worker' parameter"))?;
        let project = project.ok_or_else(|| anyhow!("Missing 'project' parameter"))?;

        return Ok(ApiRequest::RecordBuild {
            worker_id: WorkerId::new(worker_id),
            project,
            is_test,
        });
    }

    if query_for_exact_route(path, "/build-heartbeat").is_some() {
        if method != "POST" {
            return Err(anyhow!("Only POST method supported for build heartbeat"));
        }
        return Ok(ApiRequest::BuildHeartbeat);
    }

    if query_for_exact_route(path, "/test-run").is_some() {
        if method != "POST" {
            return Err(anyhow!("Only POST method supported for test run"));
        }
        return Ok(ApiRequest::TestRun);
    }

    if path.starts_with("/telemetry") {
        let (path_only, query) = split_path_query(path);

        return match path_only {
            "/telemetry/poll" => {
                if method != "POST" {
                    return Err(anyhow!("Only POST method supported for telemetry polling"));
                }

                let mut worker_id = None;
                for param in query.split('&') {
                    if param.is_empty() {
                        continue;
                    }
                    let mut kv = param.splitn(2, '=');
                    let key = kv.next().unwrap_or("");
                    let value = kv.next().unwrap_or("");
                    if key == "worker" {
                        worker_id = Some(percent_unescape_query_value(value));
                    }
                }

                let worker_id = worker_id.ok_or_else(|| anyhow!("Missing 'worker' parameter"))?;
                Ok(ApiRequest::TelemetryPoll {
                    worker_id: WorkerId::new(worker_id),
                })
            }
            "/telemetry/ingest" => {
                if method != "POST" {
                    return Err(anyhow!(
                        "Only POST method supported for telemetry ingestion"
                    ));
                }

                let mut source = None;
                for param in query.split('&') {
                    if param.is_empty() {
                        continue;
                    }
                    let mut kv = param.splitn(2, '=');
                    let key = kv.next().unwrap_or("");
                    let value = kv.next().unwrap_or("");
                    if key == "source" {
                        source = parse_telemetry_source(&percent_unescape_query_value(value));
                    }
                }

                Ok(ApiRequest::IngestTelemetry(
                    source.unwrap_or(TelemetrySource::Piggyback),
                ))
            }
            _ => Err(anyhow!("Unknown endpoint: {}", path_only)),
        };
    }

    // Worker state management endpoints: POST /workers/{id}/{action}
    if path.starts_with("/workers/") && method == "POST" {
        let rest = path.strip_prefix("/workers/").unwrap_or("");
        let (path_part, query) = split_path_query(rest);
        let parts: Vec<&str> = path_part.split('/').collect();

        if parts.len() == 2 {
            let worker_id = percent_unescape_query_value(parts[0]);
            let action = parts[1];

            match action {
                "drain" => {
                    return Ok(ApiRequest::WorkerDrain {
                        worker_id: WorkerId::new(worker_id),
                    });
                }
                "enable" => {
                    return Ok(ApiRequest::WorkerEnable {
                        worker_id: WorkerId::new(worker_id),
                    });
                }
                "disable" => {
                    let mut reason = None;
                    let mut drain_first = false;

                    for param in query.split('&') {
                        if param.is_empty() {
                            continue;
                        }
                        let mut kv = param.splitn(2, '=');
                        let key = kv.next().unwrap_or("");
                        let value = kv.next().unwrap_or("");

                        match key {
                            "reason" => reason = Some(percent_unescape_query_value(value)),
                            "drain" => {
                                drain_first = value == "1" || value.eq_ignore_ascii_case("true")
                            }
                            _ => {}
                        }
                    }

                    return Ok(ApiRequest::WorkerDisable {
                        worker_id: WorkerId::new(worker_id),
                        reason,
                        drain_first,
                    });
                }
                _ => {}
            }
        }
    }

    // Repo convergence operator endpoints (bd-vvmd.3.5).
    if path.starts_with("/repo-convergence") {
        let (path_only, query) = split_path_query(path);

        match path_only {
            "/repo-convergence/status" => {
                let mut worker_id = None;
                for param in query.split('&') {
                    if param.is_empty() {
                        continue;
                    }
                    let mut kv = param.splitn(2, '=');
                    let key = kv.next().unwrap_or("");
                    let value = kv.next().unwrap_or("");
                    if key == "worker" {
                        worker_id = Some(WorkerId::new(percent_unescape_query_value(value)));
                    }
                }
                return Ok(ApiRequest::RepoConvergenceStatus { worker_id });
            }
            "/repo-convergence/dry-run" => {
                let mut worker_id = None;
                for param in query.split('&') {
                    if param.is_empty() {
                        continue;
                    }
                    let mut kv = param.splitn(2, '=');
                    let key = kv.next().unwrap_or("");
                    let value = kv.next().unwrap_or("");
                    if key == "worker" {
                        worker_id = Some(WorkerId::new(percent_unescape_query_value(value)));
                    }
                }
                return match worker_id {
                    Some(id) => Ok(ApiRequest::RepoConvergenceDryRun { worker_id: id }),
                    None => Err(anyhow!("Missing required 'worker' parameter for dry-run")),
                };
            }
            "/repo-convergence/repair" => {
                if method != "POST" {
                    return Err(anyhow!("Repair endpoint requires POST method"));
                }
                let mut worker_id = None;
                for param in query.split('&') {
                    if param.is_empty() {
                        continue;
                    }
                    let mut kv = param.splitn(2, '=');
                    let key = kv.next().unwrap_or("");
                    let value = kv.next().unwrap_or("");
                    if key == "worker" {
                        worker_id = Some(WorkerId::new(percent_unescape_query_value(value)));
                    }
                }
                return match worker_id {
                    Some(id) => Ok(ApiRequest::RepoConvergenceRepair { worker_id: id }),
                    None => Err(anyhow!("Missing required 'worker' parameter for repair")),
                };
            }
            _ => return Err(anyhow!("Unknown convergence endpoint: {}", path_only)),
        }
    }

    let Some((query, resume_queued, disk_budget_route, tools_route)) = [
        ("/select-worker", false, false, false),
        ("/select-worker/resume-queued", true, false, false),
        ("/select-worker/disk-budget", false, true, false),
        (
            "/select-worker/resume-queued/disk-budget",
            true,
            true,
            false,
        ),
        ("/select-verified-tools", false, false, true),
        ("/select-verified-tools/resume-queued", true, false, true),
        ("/select-verified-tools/disk-budget", false, true, true),
        (
            "/select-verified-tools/resume-queued/disk-budget",
            true,
            true,
            true,
        ),
    ]
    .into_iter()
    .find_map(|(route, resume, disk_budget, tools)| {
        query_for_exact_route(path, route).map(|query| (query, resume, disk_budget, tools))
    }) else {
        return Err(anyhow!("Unknown endpoint: {}", path));
    };

    let mut project = None;
    let mut command = None;
    let mut cores = None;
    let mut disk_headroom_gib = None;
    let mut wait_for_worker = false;
    let mut job_mode = false;
    let mut wait_timeout_secs = None;
    let mut toolchain = None;
    let mut required_runtime = RequiredRuntime::default();
    let mut command_priority = CommandPriority::Normal;
    let mut classification_duration_us = None;
    let mut hook_pid = None;
    let mut local_wrapper_id = None;
    let mut preferred_workers = Vec::new();
    let mut required_tools: Vec<String> = Vec::new();
    let mut dry_run = false;

    for param in query.split('&') {
        if param.is_empty() {
            continue;
        }
        let mut kv = param.splitn(2, '=');
        let key = kv.next().unwrap_or("");
        let value = kv.next().unwrap_or("");

        match key {
            "project" => project = Some(percent_unescape_query_value(value)),
            "command" => command = Some(percent_unescape_query_value(value)),
            "cores" => cores = value.parse::<u32>().ok().filter(|cores| *cores > 0),
            "disk_headroom_gib" => {
                anyhow::ensure!(
                    disk_headroom_gib.is_none(),
                    "Duplicate disk_headroom_gib parameter"
                );
                disk_headroom_gib = Some(
                    value
                        .parse::<u32>()
                        .context("disk_headroom_gib must be an unsigned whole GiB count")?,
                );
            }
            "wait" | "queue" => {
                wait_for_worker = value == "1" || value.eq_ignore_ascii_case("true");
            }
            "wait_timeout_secs" => {
                wait_timeout_secs = value.parse::<u64>().ok().filter(|secs| *secs > 0);
            }
            "toolchain" => {
                let json = percent_unescape_query_value(value);
                toolchain = serde_json::from_str(&json).ok();
            }
            "runtime" => {
                // Parse required runtime (rust, bun, node)
                let rt_str = percent_unescape_query_value(value);
                // Use serde_json to parse the enum variant string (e.g. "bun")
                // We wrap in quotes to make it valid JSON string for the enum
                required_runtime = serde_json::from_str(&format!("\"{}\"", rt_str))
                    .ok()
                    .unwrap_or_default();
            }
            "priority" => {
                let pr_str = percent_unescape_query_value(value);
                command_priority = pr_str.parse().unwrap_or(CommandPriority::Normal);
            }
            "job_mode" => {
                job_mode = value == "1" || value.eq_ignore_ascii_case("true");
            }
            // Repeatable `&require_tool=NAME`. Duplicates are collapsed; the
            // gate itself is order-independent, and an empty value is dropped
            // rather than becoming a requirement no worker can ever satisfy by
            // accident.
            "require_tool" => {
                let name = percent_unescape_query_value(value);
                let name = name.trim();
                if !name.is_empty() && !required_tools.iter().any(|t| t == name) {
                    required_tools.push(name.to_string());
                }
            }
            "classification_us" => {
                // Classification latency from hook (for AGENTS.md compliance tracking)
                classification_duration_us = value.parse().ok();
            }
            "hook_pid" => {
                hook_pid = value.parse().ok();
            }
            "dry_run" => {
                dry_run = value == "1" || value == "true";
            }
            "local_wrapper_id" => {
                let candidate = percent_unescape_query_value(value);
                if candidate.starts_with(LOCAL_WRAPPER_ID_PREFIX) {
                    local_wrapper_id = Some(candidate);
                }
            }
            "worker" | "preferred_worker" | "preferred" => {
                preferred_workers.extend(parse_worker_id_list(value));
            }
            "workers" | "preferred_workers" => {
                preferred_workers.extend(parse_worker_id_list(value));
            }
            _ => {} // Ignore unknown parameters
        }
    }

    let project = project.ok_or_else(|| anyhow!("Missing 'project' parameter"))?;
    let estimated_cores = cores.unwrap_or(1);
    let disk_headroom_gib = disk_headroom_gib.unwrap_or(0);
    anyhow::ensure!(
        disk_budget_route == (disk_headroom_gib > 0),
        "A positive disk_headroom_gib requires the exact disk-budget selection route"
    );
    anyhow::ensure!(
        !tools_route || !required_tools.is_empty(),
        "The verified-tools selection route requires explicit tool requirements"
    );
    if resume_queued
        && (dry_run || !wait_for_worker || local_wrapper_id.is_none() || hook_pid.is_none())
    {
        return Err(anyhow!(
            "queued resume requires the original waiting wrapper and process"
        ));
    }

    Ok(ApiRequest::SelectWorker {
        request: SelectionRequest {
            project,
            command,
            command_priority,
            estimated_cores,
            disk_headroom_gib,
            preferred_workers,
            toolchain,
            required_runtime,
            classification_duration_us,
            hook_pid,
            job_mode,
            required_tools,
        },
        wait_for_worker,
        wait_timeout_secs,
        local_wrapper_id,
        dry_run,
        resume_queued,
    })
}

fn parse_worker_id_list(encoded_value: &str) -> Vec<WorkerId> {
    percent_unescape_query_value(encoded_value)
        .split(',')
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .map(WorkerId::new)
        .collect()
}

fn query_for_exact_route<'a>(path: &'a str, expected_path: &str) -> Option<&'a str> {
    let (path_only, query) = split_path_query(path);
    (path_only == expected_path).then_some(query)
}

fn route_matches_exact_or_child(path: &str, expected_path: &str) -> bool {
    let (path_only, _) = split_path_query(path);
    path_only == expected_path
        || path_only
            .strip_prefix(expected_path)
            .is_some_and(|rest| rest.starts_with('/'))
}

fn parse_telemetry_source(value: &str) -> Option<TelemetrySource> {
    match value.trim().to_lowercase().as_str() {
        "piggyback" => Some(TelemetrySource::Piggyback),
        "ssh-poll" | "ssh_poll" | "ssh" => Some(TelemetrySource::SshPoll),
        "on-demand" | "on_demand" | "ondemand" => Some(TelemetrySource::OnDemand),
        _ => None,
    }
}

fn split_path_query(path: &str) -> (&str, &str) {
    match path.split_once('?') {
        Some((path, query)) => (path, query),
        None => (path, ""),
    }
}

/// URL percent-unescaping for query/path segments.
///
/// Converts %XX hex sequences to their original characters and treats '+'
/// as a query-space marker.
fn percent_unescape_query_value(s: &str) -> String {
    let mut bytes: Vec<u8> = Vec::with_capacity(s.len());
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '%' {
            // Try to read two hex digits
            let hex: String = chars.by_ref().take(2).collect();
            if hex.len() == 2
                && let Ok(byte) = u8::from_str_radix(&hex, 16)
            {
                bytes.push(byte);
                continue;
            }
            // Invalid encoding, keep original
            bytes.push(b'%');
            bytes.extend_from_slice(hex.as_bytes());
        } else if c == '+' {
            // + is space in application/x-www-form-urlencoded
            bytes.push(b' ');
        } else {
            let mut buf = [0; 4];
            let s = c.encode_utf8(&mut buf);
            bytes.extend_from_slice(s.as_bytes());
        }
    }

    String::from_utf8_lossy(&bytes).into_owned()
}

#[derive(Debug, Serialize)]
struct TelemetryPollResponse {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    telemetry: Option<WorkerTelemetry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    worker_id: Option<String>,
}

async fn handle_telemetry_poll(ctx: &DaemonContext, worker_id: &WorkerId) -> TelemetryPollResponse {
    let worker = match ctx.pool.get(worker_id).await {
        Some(worker) => worker,
        None => {
            return TelemetryPollResponse {
                status: "error".to_string(),
                telemetry: None,
                error: Some("worker not found".to_string()),
                worker_id: Some(worker_id.to_string()),
            };
        }
    };

    let status = worker.status().await;
    if matches!(
        status,
        WorkerStatus::Unreachable | WorkerStatus::Drained | WorkerStatus::Disabled
    ) {
        return TelemetryPollResponse {
            status: "error".to_string(),
            telemetry: None,
            error: Some("worker unavailable".to_string()),
            worker_id: Some(worker_id.to_string()),
        };
    }

    // 20s (matching TelemetryPollerConfig): a fresh SSH connect+auth+exec to a
    // trans-continental worker can approach/exceed 5s under load.
    match collect_telemetry_from_worker(&worker, Duration::from_secs(20)).await {
        Ok((endpoint, telemetry)) => {
            let Some(_endpoint_guard) = worker.lock_current_endpoint(&endpoint).await else {
                return TelemetryPollResponse {
                    status: "error".to_string(),
                    telemetry: None,
                    error: Some("worker endpoint changed during telemetry collection".to_string()),
                    worker_id: Some(worker_id.to_string()),
                };
            };
            ctx.telemetry.ingest_for_endpoint(
                telemetry.clone(),
                TelemetrySource::OnDemand,
                &endpoint,
            );
            TelemetryPollResponse {
                status: "ok".to_string(),
                telemetry: Some(telemetry),
                error: None,
                worker_id: None,
            }
        }
        Err(e) => TelemetryPollResponse {
            status: "error".to_string(),
            telemetry: None,
            error: Some(e.to_string()),
            worker_id: Some(worker_id.to_string()),
        },
    }
}

fn speedscore_view(score: SpeedScore) -> SpeedScoreView {
    SpeedScoreView {
        total: score.total,
        cpu_score: score.cpu_score,
        memory_score: score.memory_score,
        disk_score: score.disk_score,
        network_score: score.network_score,
        compilation_score: score.compilation_score,
        measured_at: score.calculated_at.to_rfc3339(),
        version: score.version,
    }
}

/// Create an error response using unified ApiError format.
///
/// Adds worker_id to context and retry_after_secs when provided.
fn error_response(
    code: ErrorCode,
    message: impl Into<String>,
    worker_id: Option<&WorkerId>,
    retry_after: Option<ChronoDuration>,
) -> ApiError {
    let mut error = ApiError::new(code, message);
    if let Some(id) = worker_id {
        error = error.with_context("worker_id", id.as_str());
    }
    if let Some(duration) = retry_after {
        error = error.with_retry_after(duration.num_seconds().max(1) as u64);
    }
    error
}

async fn handle_speedscore(
    ctx: &DaemonContext,
    worker_id: &WorkerId,
) -> ApiResponse<SpeedScoreResponse> {
    if ctx.pool.get(worker_id).await.is_none() {
        return ApiResponse::Error(error_response(
            ErrorCode::ConfigInvalidWorker,
            format!("Worker '{}' not found", worker_id),
            Some(worker_id),
            None,
        ));
    }

    match ctx.telemetry.latest_speedscore(worker_id.as_str()).await {
        Ok(Some(score)) => ApiResponse::Ok(SpeedScoreResponse {
            worker_id: worker_id.to_string(),
            speedscore: Some(speedscore_view(score)),
            message: None,
        }),
        Ok(None) => ApiResponse::Ok(SpeedScoreResponse {
            worker_id: worker_id.to_string(),
            speedscore: None,
            message: Some("Worker has not been benchmarked yet".to_string()),
        }),
        Err(err) => {
            warn!("Failed to load SpeedScore for {}: {}", worker_id, err);
            ApiResponse::Error(error_response(
                ErrorCode::InternalStateError,
                "Failed to retrieve SpeedScore",
                Some(worker_id),
                None,
            ))
        }
    }
}

async fn handle_speedscore_history(
    ctx: &DaemonContext,
    worker_id: &WorkerId,
    days: u32,
    limit: usize,
    offset: usize,
) -> ApiResponse<SpeedScoreHistoryResponse> {
    if ctx.pool.get(worker_id).await.is_none() {
        return ApiResponse::Error(error_response(
            ErrorCode::ConfigInvalidWorker,
            format!("Worker '{}' not found", worker_id),
            Some(worker_id),
            None,
        ));
    }

    let days = days.clamp(1, 365);
    let limit = limit.clamp(1, 1000);
    let since = Utc::now() - ChronoDuration::days(days as i64);

    match ctx
        .telemetry
        .speedscore_history(worker_id.as_str(), since, limit, offset)
        .await
    {
        Ok(page) => {
            let has_more = ((offset + page.entries.len()) as u64) < page.total;
            ApiResponse::Ok(SpeedScoreHistoryResponse {
                worker_id: worker_id.to_string(),
                history: page.entries.into_iter().map(speedscore_view).collect(),
                pagination: PaginationInfo {
                    total: page.total,
                    offset,
                    limit,
                    has_more,
                },
            })
        }
        Err(err) => {
            warn!(
                "Failed to load SpeedScore history for {}: {}",
                worker_id, err
            );
            ApiResponse::Error(error_response(
                ErrorCode::InternalStateError,
                "Failed to retrieve SpeedScore history",
                Some(worker_id),
                None,
            ))
        }
    }
}

async fn handle_speedscore_list(ctx: &DaemonContext) -> ApiResponse<SpeedScoreListResponse> {
    let workers = ctx.pool.all_workers().await;
    let mut entries = Vec::with_capacity(workers.len());

    for worker in workers {
        let status = worker.status().await;
        let worker_id = worker.config.read().await.id.clone();
        let speedscore = match ctx.telemetry.latest_speedscore(worker_id.as_str()).await {
            Ok(score) => score.map(speedscore_view),
            Err(err) => {
                warn!("Failed to load SpeedScore for {}: {}", worker_id, err);
                None
            }
        };

        entries.push(SpeedScoreWorker {
            worker_id: worker_id.to_string(),
            speedscore,
            status,
        });
    }

    ApiResponse::Ok(SpeedScoreListResponse { workers: entries })
}

async fn handle_workers_capabilities(
    ctx: &DaemonContext,
    refresh: bool,
) -> ApiResponse<WorkerCapabilitiesResponse> {
    ApiResponse::Ok(get_workers_capabilities(ctx, refresh).await)
}

async fn handle_benchmark_trigger(
    ctx: &DaemonContext,
    worker_id: &WorkerId,
) -> ApiResponse<BenchmarkTriggerResponse> {
    if ctx.pool.get(worker_id).await.is_none() {
        return ApiResponse::Error(error_response(
            ErrorCode::ConfigInvalidWorker,
            format!("Worker '{}' not found", worker_id),
            Some(worker_id),
            None,
        ));
    }

    let request_id = Uuid::new_v4().to_string();
    match ctx
        .benchmark_queue
        .enqueue(worker_id.clone(), request_id.clone())
    {
        Ok(request) => {
            if let Err(err) = ctx
                .benchmark_trigger
                .trigger(worker_id.clone(), request.request_id.clone(), None)
                .await
            {
                warn!(
                    worker = %worker_id,
                    request_id = %request.request_id,
                    "Benchmark trigger dispatch failed: {}",
                    err
                );
                let _ = ctx.benchmark_queue.pop();
                return ApiResponse::Error(error_response(
                    ErrorCode::InternalStateError,
                    "Benchmark scheduler unavailable",
                    Some(worker_id),
                    None,
                ));
            }

            let _ = ctx.benchmark_queue.pop();
            ctx.events.emit(
                "benchmark_queued",
                &serde_json::json!({
                    "worker_id": worker_id.as_str(),
                    "request_id": request.request_id,
                    "queued_at": request.requested_at.to_rfc3339(),
                }),
            );
            ApiResponse::Ok(BenchmarkTriggerResponse {
                status: "queued".to_string(),
                worker_id: worker_id.to_string(),
                request_id,
            })
        }
        Err(rate) => ApiResponse::Error(error_response(
            ErrorCode::WorkerAtCapacity,
            "Benchmark trigger rate limited",
            Some(worker_id),
            Some(rate.retry_after),
        )),
    }
}

async fn handle_event_stream(
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    events: EventBus,
) -> Result<()> {
    let mut rx = events.subscribe();
    let header = "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n";
    writer.write_all(header.as_bytes()).await?;
    writer.flush().await?;

    loop {
        match rx.recv().await {
            Ok(message) => {
                if let Err(err) = writer.write_all(message.as_bytes()).await {
                    warn!("Event stream write failed: {}", err);
                    break;
                }
                if let Err(err) = writer.write_all(b"\n").await {
                    warn!("Event stream write failed: {}", err);
                    break;
                }
                if let Err(err) = writer.flush().await {
                    warn!("Event stream flush failed: {}", err);
                    break;
                }
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                warn!("Event stream lagged, skipped {} messages", skipped);
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
        }
    }

    Ok(())
}

fn cancelled_selection() -> SelectionResponse {
    SelectionResponse {
        worker: None,
        reason: SelectionReason::SelectionError("job_cancelled_before_start".to_owned()),
        build_id: None,
        diagnostics: None,
    }
}

/// Answer "which worker would this build get?" without admitting it.
///
/// `rch diagnose` used to run a real selection, which reserves slots and opens
/// a durable build, and then release it. Since releases require the durable
/// build_id, that release was refused: every diagnose leaked a ghost build that
/// held its slots (and blocked same-project admission) until a daemon restart.
/// Releasing with the build_id would instead record a phantom successful build.
/// A dry run selects exactly as a real request does and stops before
/// reservation.
async fn handle_select_worker_dry_run(
    ctx: &DaemonContext,
    request: &SelectionRequest,
) -> SelectionResponse {
    // Same exclusions as a real request: a worker already building this
    // project would not be handed a second build of it.
    let exclusions = project_exclusions(ctx, &request.project);
    let excluded_worker_ids: std::collections::HashSet<String> =
        exclusions.keys().cloned().collect();
    // A preview is what `rch diagnose` shows, so it reports every worker's
    // decision even when it selects one (GH #125).
    let mut result = ctx
        .worker_selector
        .preview_with_inventory(&ctx.pool, request, &excluded_worker_ids)
        .await;
    if let Some(diagnostics) = result.diagnostics.as_mut() {
        describe_project_exclusions(diagnostics, &exclusions);
    }
    let worker = match result.worker {
        Some(worker) => {
            // Read slot/score state before taking the config lock: tokio's
            // RwLock is fair, and available_slots() reads the config itself.
            let slots_available = worker.available_slots().await;
            let speed_score = worker.get_speed_score();
            let config = worker.config.read().await;
            Some(SelectedWorker {
                id: config.id.clone(),
                host: config.host.clone(),
                user: config.user.clone(),
                identity_file: config.identity_file.clone(),
                slots_available,
                speed_score,
                declared_os: rch_common::declared_os(&config.tags),
                project_lane: 0,
                disk_budget: ctx.worker_selector.build_disk_budget(request),
            })
        }
        None => None,
    };
    SelectionResponse {
        worker,
        reason: result.reason,
        build_id: None,
        diagnostics: result.diagnostics,
    }
}

/// Handle a select-worker request.
#[cfg(test)]
async fn handle_select_worker(
    ctx: &DaemonContext,
    request: SelectionRequest,
    wait_for_worker: bool,
    wait_timeout_secs: Option<u64>,
) -> Result<SelectionResponse> {
    handle_select_worker_with_wrapper(ctx, request, wait_for_worker, wait_timeout_secs, None).await
}

#[cfg(test)]
async fn handle_select_worker_with_wrapper(
    ctx: &DaemonContext,
    request: SelectionRequest,
    wait_for_worker: bool,
    wait_timeout_secs: Option<u64>,
    local_wrapper_id: Option<String>,
) -> Result<SelectionResponse> {
    handle_select_worker_mode(
        ctx,
        request,
        wait_for_worker,
        wait_timeout_secs,
        local_wrapper_id,
        false,
    )
    .await
}

fn queue_selection_digest(
    request: &SelectionRequest,
    wait_timeout_secs: Option<u64>,
) -> Result<[u8; 32]> {
    let mut digest = Sha256::new();
    digest.update(b"rch-queued-selection-v1\0");
    digest.update(serde_json::to_vec(&(request, wait_timeout_secs))?);
    Ok(digest.finalize().into())
}

async fn handle_select_worker_mode(
    ctx: &DaemonContext,
    request: SelectionRequest,
    wait_for_worker: bool,
    wait_timeout_secs: Option<u64>,
    local_wrapper_id: Option<String>,
    resume_queued: bool,
) -> Result<SelectionResponse> {
    recover_restart_admission(ctx).await;
    // Resume refusal must close the exchange, never look like a confirmed busy
    // response that permits local fallback. No selector runs before this claim.
    let resumed = if resume_queued {
        anyhow::ensure!(wait_for_worker, "queued resume requires waiting selection");
        let admission = ctx.admission_barrier.read().await;
        anyhow::ensure!(!admission.is_closed(), "restart admission barrier active");
        let wrapper = local_wrapper_id
            .as_deref()
            .ok_or_else(|| anyhow!("missing queued owner"))?;
        let resumed = ctx.history.resume_queued_build(
            wrapper,
            request
                .hook_pid
                .ok_or_else(|| anyhow!("missing queued process"))?,
            &queue_selection_digest(&request, wait_timeout_secs)?,
        )?;
        drop(admission);
        // One line per reattached waiter, so a restart can be checked for
        // queued rows that resumed versus refused (bd-w2qrp).
        info!(
            queue_id = resumed.0.id,
            project_id = %resumed.0.project_id,
            wrapper,
            "Queued waiter resumed its recovered row"
        );
        Some(resumed)
    } else {
        anyhow::ensure!(
            !local_wrapper_id
                .as_deref()
                .is_some_and(|id| ctx.history.has_queued_wrapper(id)),
            "wrapper already owns a queued selection; explicit recovery is required"
        );
        None
    };
    if local_wrapper_id
        .as_deref()
        .is_some_and(|id| ctx.history.wrapper_cancelled(id))
    {
        return Ok(cancelled_selection());
    }
    if ctx.admission_barrier.read().await.is_closed() || ctx.history.ownership_failed() {
        anyhow::ensure!(
            !resume_queued,
            "queued resume blocked by restart admission barrier"
        );
        return Ok(SelectionResponse {
            worker: None,
            reason: SelectionReason::SelectionError("restart_admission_barrier_active".to_string()),
            build_id: None,
            diagnostics: None,
        });
    }
    debug!(
        "Selecting worker for project '{}' with {} cores",
        request.project, request.estimated_cores
    );

    // Record classification latency from hook if provided (AGENTS.md compliance)
    if let Some(classification_us) = request.classification_duration_us {
        // Convert microseconds to seconds for the histogram
        let duration_secs = classification_us as f64 / 1_000_000.0;
        metrics::DECISION_LATENCY
            .with_label_values(&["compilation"])
            .observe(duration_secs);

        // Check for budget violations (compilation budget is 5ms = 0.005s)
        let duration_ms = classification_us as f64 / 1000.0;
        if duration_ms > 5.0 {
            metrics::DECISION_BUDGET_VIOLATIONS
                .with_label_values(&["compilation"])
                .inc();
            warn!(
                "Classification latency budget violation: {:.3}ms (budget: 5ms)",
                duration_ms
            );
        }

        if duration_ms > 10.0 {
            metrics::DECISION_PANIC_THRESHOLD_VIOLATIONS
                .with_label_values(&["compilation"])
                .inc();
            tracing::error!(
                "Classification latency exceeded panic threshold: {:.3}ms (threshold: 10ms)",
                duration_ms
            );
        }
    }

    // Mock support: RCH_MOCK_CIRCUIT_OPEN simulates all circuits open
    if std::env::var("RCH_MOCK_CIRCUIT_OPEN").is_ok() {
        anyhow::ensure!(!resume_queued, "queued resume blocked by circuit override");
        debug!("RCH_MOCK_CIRCUIT_OPEN set, returning AllCircuitsOpen");
        return Ok(SelectionResponse {
            worker: None,
            reason: SelectionReason::AllCircuitsOpen,
            build_id: None,
            diagnostics: None,
        });
    }

    async fn attempt_select_and_reserve(
        ctx: &DaemonContext,
        request: &SelectionRequest,
        local_wrapper_id: Option<String>,
        waiter: Option<&QueuedWaiterClaim>,
    ) -> Result<SelectionResponse> {
        if local_wrapper_id
            .as_deref()
            .is_some_and(|id| ctx.history.wrapper_cancelled(id))
        {
            return Ok(cancelled_selection());
        }
        recover_restart_admission(ctx).await;
        let admission = ctx.admission_barrier.read().await;
        if admission.is_closed() || ctx.history.ownership_failed() {
            return Ok(SelectionResponse {
                worker: None,
                reason: SelectionReason::SelectionError(
                    "restart_admission_barrier_active".to_string(),
                ),
                build_id: None,
                diagnostics: None,
            });
        }
        let response = async {
            // Retry loop to handle race conditions where slots are taken between selection and reservation.
            let mut reservation_attempts = 0;
            const MAX_ATTEMPTS: u32 = 3;
            let mut excluded_worker_ids = project_excluded_workers(ctx, &request.project);
            // bd-decdd: a worker held for an older starving waiter is busy for
            // this request. Steer off it only when selection actually picks it,
            // so a request the worker would refuse anyway keeps its own reason.
            let held_worker = ctx.history.queue_hold_against(waiter);
            let mut steered_off_hold = false;

            loop {
                // Use the configured worker selector.
                let result = ctx
                    .worker_selector
                    .select_with_exclusions(&ctx.pool, request, &excluded_worker_ids)
                    .await;
                let selection_reason = result.reason;
                let selection_diagnostics = result.diagnostics;

                let Some(worker) = result.worker else {
                    if local_wrapper_id
                        .as_deref()
                        .is_some_and(|id| ctx.history.wrapper_cancelled(id))
                    {
                        return Ok(cancelled_selection());
                    }
                    debug!("No worker selected: {}", selection_reason);
                    return Ok(SelectionResponse {
                        worker: None,
                        // The held worker would have taken it: busy, so it can queue.
                        reason: if steered_off_hold {
                            SelectionReason::AllWorkersBusy
                        } else {
                            selection_reason
                        },
                        build_id: None,
                        diagnostics: selection_diagnostics,
                    });
                };

                let selected_endpoint = worker.endpoint_snapshot().await;
                let selected_worker_id = selected_endpoint.config.id.clone();
                if held_worker.as_deref() == Some(selected_worker_id.as_str()) {
                    steered_off_hold = true;
                    excluded_worker_ids.insert(selected_worker_id.as_str().to_string());
                    continue;
                }

                // Reserve the slots.
                //
                // Clamp to what this worker can physically hold. `estimated_cores`
                // is an estimate derived from `compilation.build_slots`, and
                // admission may deliberately hand back a worker whose TOTAL slots
                // are below it (see the `capacity_degraded` path in
                // `selection.rs`) rather than let the build fall back to local.
                // Reserving the unclamped estimate on such a worker can never
                // succeed, so without this clamp the selection loop burns all three
                // attempts on "race condition" retries and then reports
                // AllWorkersBusy — a phantom race against a worker that was simply
                // too small. Observed live on ts1 2026-08-26: repeated
                // "Failed to reserve 4 slots on hz2" against a 2-slot worker.
                //
                // An undersized worker is only offered while it has a free slot,
                // so clamp such a request to what is FREE, not to its total: a
                // 2-slot worker with one slot busy can never reserve 2, and the
                // degraded path then failed exactly when it mattered. A worker
                // that can hold the whole estimate still reserves all of it, so
                // a race that shrank its free slots fails and retries instead of
                // under-reserving and oversubscribing the host.
                reservation_attempts += 1;
                let reserve_slots = {
                    let total = worker.effective_total_slots().await;
                    if request.estimated_cores > total {
                        total.min(worker.available_slots().await.max(1))
                    } else {
                        request.estimated_cores
                    }
                };
                if worker.reserve_slots(reserve_slots).await {
                    // Keep the returned endpoint and its disk evidence under
                    // one configuration generation through durable admission.
                    // A retarget between cloning the address and reading disk
                    // capacity must not fund the old host with the new host's
                    // free space. No SSH runs under this short read lock.
                    let Some(config) = worker.lock_current_endpoint(&selected_endpoint).await
                    else {
                        worker.release_slots(reserve_slots).await;
                        excluded_worker_ids.insert(selected_worker_id.as_str().to_string());
                        continue;
                    };
                    let (id, host, user, identity_file, declared_os) = (
                        config.id.clone(),
                        config.host.clone(),
                        config.user.clone(),
                        config.identity_file.clone(),
                        rch_common::declared_os(&config.tags),
                    );

                    let command = request
                        .command
                        .clone()
                        .unwrap_or_else(|| "<unknown>".to_string());

                    let disk_budget = ctx.worker_selector.build_disk_budget(request);
                    let disk = crate::disk_pressure::DiskHeadroomAdmission {
                        requested_gib: disk_budget.map_or(0, |budget| {
                            u32::try_from(
                                budget
                                    .max_growth_bytes
                                    .div_ceil(rch_common::BuildDiskBudget::GIB),
                            )
                            .unwrap_or(u32::MAX)
                        }),
                        floor_gib: disk_budget.map_or(0, |budget| {
                            budget
                                .min_free_bytes
                                .div_ceil(rch_common::BuildDiskBudget::GIB)
                        }),
                        capacity: worker.disk_capacity_observation().await,
                    };

                    let admission = ctx.history.try_start_active_build_in_lanes(
                        request.project.clone(),
                        id.as_str().to_string(),
                        command.clone(),
                        request.hook_pid.unwrap_or(0),
                        local_wrapper_id.clone(),
                        reserve_slots,
                        rch_common::BuildLocation::Remote,
                        waiter,
                        disk,
                        Some(selected_endpoint.clone()),
                        ctx.pool.project_lanes(id.as_str()),
                    );
                    drop(config);
                    let state = match admission {
                        Ok(Some(state)) => state,
                        Ok(None) => {
                            worker.release_slots(reserve_slots).await;
                            if local_wrapper_id
                                .as_deref()
                                .is_some_and(|id| ctx.history.wrapper_cancelled(id))
                            {
                                return Ok(cancelled_selection());
                            }
                            if ctx.history.ownership_failed() {
                                anyhow::bail!(
                                    "durable ownership uncertain; admission closed until restart"
                                );
                            }
                            anyhow::ensure!(
                                waiter.is_none_or(|claim| ctx.history.owns_queued_waiter(claim)),
                                "queued waiter no longer owns admission"
                            );
                            anyhow::ensure!(
                                waiter.is_some()
                                    || !local_wrapper_id
                                        .as_deref()
                                        .is_some_and(|id| ctx.history.has_queued_wrapper(id)),
                                "wrapper already owns a queued selection"
                            );
                            excluded_worker_ids.insert(id.as_str().to_string());
                            continue;
                        }
                        Err(error) => {
                            return Err(error.into());
                        }
                    };
                    let build_id = Some(state.id);
                    if !cfg!(test) {
                        metrics::inc_active_builds("remote");
                    }
                    ctx.events.emit(
                        "build_started",
                        &serde_json::json!({
                            "build_id": state.id, "project_id": request.project.clone(),
                            "worker_id": id.as_str(), "command": command,
                            "local_wrapper_id": local_wrapper_id.clone(), "slots": reserve_slots,
                        }),
                    );

                    let slots_available = worker.available_slots().await;
                    let speed_score = worker.get_speed_score();

                    if request.command_priority != CommandPriority::Normal {
                        ctx.events.emit(
                            "priority_hint",
                            &serde_json::json!({
                                "project": request.project.clone(),
                                "worker_id": id.as_str(),
                                "priority": request.command_priority.to_string(),
                                "estimated_cores": request.estimated_cores,
                                "command": request.command.clone(),
                            }),
                        );
                    }

                    return Ok(SelectionResponse {
                        worker: Some(SelectedWorker {
                            id,
                            host,
                            user,
                            identity_file,
                            slots_available,
                            speed_score,
                            declared_os,
                            project_lane: state.project_lane,
                            disk_budget: if state.disk_headroom_gib != 0 {
                                Some(rch_common::BuildDiskBudget {
                                    max_growth_bytes: u64::from(state.disk_headroom_gib)
                                        * rch_common::BuildDiskBudget::GIB,
                                    min_free_bytes: state
                                        .disk_floor_gib
                                        .saturating_mul(rch_common::BuildDiskBudget::GIB),
                                })
                            } else if state.recovered {
                                // Legacy live rows are charged a cold allowance by
                                // history, and replay must enforce the same charge.
                                Some(rch_common::BuildDiskBudget {
                                    max_growth_bytes: u64::from(
                                        rch_common::BuildDiskBudget::growth_budget_gib(f64::from(
                                            rch_common::BuildDiskBudget::cold_growth_gib(
                                                &state.command,
                                            )
                                            .unwrap_or(16),
                                        )),
                                    ) * rch_common::BuildDiskBudget::GIB,
                                    min_free_bytes: disk_budget
                                        .map_or(0, |budget| budget.min_free_bytes),
                                })
                            } else {
                                None
                            },
                        }),
                        reason: selection_reason,
                        build_id,
                        diagnostics: selection_diagnostics,
                    });
                }

                warn!(
                    "Failed to reserve {} slots on {} (race condition), attempt {}/{}",
                    reserve_slots, selected_worker_id, reservation_attempts, MAX_ATTEMPTS
                );

                if reservation_attempts >= MAX_ATTEMPTS {
                    // Give up after max attempts.
                    return Ok(SelectionResponse {
                        worker: None,
                        reason: SelectionReason::AllWorkersBusy,
                        build_id: None,
                        diagnostics: None,
                    });
                }
                // Loop again - next selection will see reduced slot count.
            }
        }
        .await;
        drop(admission);
        response
    }

    let initial = if resumed.is_some() {
        SelectionResponse {
            worker: None,
            reason: SelectionReason::AllWorkersBusy,
            build_id: None,
            diagnostics: None,
        }
    } else {
        attempt_select_and_reserve(ctx, &request, local_wrapper_id.clone(), None).await?
    };
    if initial.worker.is_some()
        || !wait_for_worker
        || initial.reason != SelectionReason::AllWorkersBusy
    {
        return Ok(initial);
    }

    // All workers are busy. If the hook opted into waiting, enqueue and wait.
    let hook_pid = request.hook_pid.unwrap_or(0);
    let command = request
        .command
        .clone()
        .unwrap_or_else(|| "<unknown>".to_string());

    let effective_queue_timeout_secs =
        queue_wait_secs(request.job_mode, wait_timeout_secs, ctx.queue_timeout_secs);
    let selection_digest = queue_selection_digest(&request, wait_timeout_secs)?;
    recover_restart_admission(ctx).await;
    let admission = ctx.admission_barrier.read().await;
    if admission.is_closed() || ctx.history.ownership_failed() {
        anyhow::ensure!(
            !resume_queued,
            "queued resume blocked by restart admission barrier"
        );
        return Ok(SelectionResponse {
            worker: None,
            reason: SelectionReason::SelectionError("restart_admission_barrier_active".to_string()),
            build_id: None,
            diagnostics: None,
        });
    }
    let queued_result = resumed.or_else(|| {
        ctx.history.enqueue_selection_build(
            request.project.clone(),
            command.clone(),
            hook_pid,
            request.estimated_cores,
            local_wrapper_id.clone(),
            QueueSelectionContract {
                digest: selection_digest,
                timeout_secs: effective_queue_timeout_secs,
            },
        )
    });
    drop(admission);
    let Some((queued, waiter)) = queued_result else {
        if ctx.history.ownership_failed() {
            anyhow::bail!("durable ownership uncertain; queue admission closed until restart");
        }
        if local_wrapper_id
            .as_deref()
            .is_some_and(|id| ctx.history.wrapper_cancelled(id))
        {
            return Ok(cancelled_selection());
        }
        anyhow::ensure!(
            !local_wrapper_id
                .as_deref()
                .is_some_and(|id| ctx.history.has_queued_wrapper(id)),
            "wrapper already owns a queued selection"
        );
        // Queue full - fall back to the normal busy response.
        return Ok(initial);
    };

    ctx.history.update_queue_estimates();
    if !cfg!(test) {
        metrics::set_build_queue_depth(ctx.history.queue_depth());
    }
    ctx.events.emit(
        if resume_queued {
            "build_queue_resumed"
        } else {
            "build_queued"
        },
        &serde_json::json!({
            "queue_id": queued.id,
            "project_id": queued.project_id,
            "command": queued.command,
            "queued_at": queued.queued_at,
            "position": ctx.history.queue_position(queued.id),
            "slots_needed": queued.slots_needed,
        }),
    );

    const QUEUE_POLL_INTERVAL: Duration = Duration::from_secs(1);
    let queue_timeout = Duration::from_secs(
        queued
            .selection_contract
            .as_ref()
            .expect("selection queue has a contract")
            .timeout_secs
            .min(effective_queue_timeout_secs),
    );
    // Every exit from the wait, including errors and a dropped future,
    // releases a hold this waiter took.
    let _hold_release = QueueHoldRelease {
        history: &ctx.history,
        queue_id: queued.id,
    };

    loop {
        if local_wrapper_id
            .as_deref()
            .is_some_and(|id| ctx.history.wrapper_cancelled(id))
        {
            ctx.history
                .finish_queued_build(queued.id, local_wrapper_id.as_deref())?;
            ctx.history.update_queue_estimates();
            if !cfg!(test) {
                metrics::set_build_queue_depth(ctx.history.queue_depth());
            }
            return Ok(cancelled_selection());
        }
        // Check if the queue wait has timed out
        if queued.queued_at_mono.elapsed() > queue_timeout {
            if ctx
                .history
                .finish_queued_build(queued.id, local_wrapper_id.as_deref())?
            {
                return Ok(cancelled_selection());
            }
            ctx.history.update_queue_estimates();
            if !cfg!(test) {
                metrics::set_build_queue_depth(ctx.history.queue_depth());
                metrics::inc_local_fallback_reason("queue_timeout");
            }
            ctx.events.emit(
                "build_queue_removed",
                &serde_json::json!({
                    "queue_id": queued.id,
                    "project_id": queued.project_id,
                    "reason": "timeout",
                    "waited_secs": queued.queued_at_mono.elapsed().as_secs(),
                }),
            );
            warn!(
                "Queue timeout after {}s for project {}, falling back to local",
                queued.queued_at_mono.elapsed().as_secs(),
                queued.project_id
            );
            return Ok(SelectionResponse {
                worker: None,
                reason: SelectionReason::SelectionError("queue_timeout".to_string()),
                build_id: None,
                diagnostics: None,
            });
        }

        // If the hook process exited while waiting, drop the queued build to avoid leaking slots.
        if hook_pid > 0 && !is_process_alive(hook_pid) {
            if ctx
                .history
                .finish_queued_build(queued.id, local_wrapper_id.as_deref())?
            {
                return Ok(cancelled_selection());
            }
            ctx.history.update_queue_estimates();
            if !cfg!(test) {
                metrics::set_build_queue_depth(ctx.history.queue_depth());
            }
            ctx.events.emit(
                "build_queue_removed",
                &serde_json::json!({
                    "queue_id": queued.id,
                    "project_id": queued.project_id,
                    "reason": "hook_exited",
                }),
            );
            return Ok(SelectionResponse {
                worker: None,
                reason: SelectionReason::SelectionError("hook_exited".to_string()),
                build_id: None,
                diagnostics: None,
            });
        }

        anyhow::ensure!(
            ctx.history.owns_queued_waiter(&waiter),
            "queued waiter ownership lost"
        );
        let response =
            attempt_select_and_reserve(ctx, &request, local_wrapper_id.clone(), Some(&waiter))
                .await?;
        if response.worker.is_some() {
            let _ = ctx.history.remove_queued_build(queued.id);
            ctx.history.update_queue_estimates();
            if !cfg!(test) {
                metrics::set_build_queue_depth(ctx.history.queue_depth());
            }
            return Ok(response);
        }

        // If conditions changed (e.g., all circuits open), stop waiting and fail-open.
        if response.reason != SelectionReason::AllWorkersBusy {
            if ctx
                .history
                .finish_queued_build(queued.id, local_wrapper_id.as_deref())?
            {
                return Ok(cancelled_selection());
            }
            ctx.history.update_queue_estimates();
            if !cfg!(test) {
                metrics::set_build_queue_depth(ctx.history.queue_depth());
            }
            ctx.events.emit(
                "build_queue_removed",
                &serde_json::json!({
                    "queue_id": queued.id,
                    "project_id": queued.project_id,
                    "reason": response.reason.to_string(),
                }),
            );
            return Ok(response);
        }

        if request.job_mode
            && queued.slots_needed > 1
            && queued.queued_at_mono.elapsed() >= QUEUE_HOLD_AFTER
        {
            let current = ctx.history.queue_hold_of(queued.id);
            match response
                .diagnostics
                .as_ref()
                .and_then(|diagnostics| queue_hold_candidate(diagnostics, current.as_deref()))
            {
                Some(worker_id) => {
                    if ctx.history.claim_queue_hold(
                        queued.id,
                        queued.queued_at_mono,
                        worker_id.clone(),
                    ) {
                        info!(
                            queue_id = queued.id,
                            project = %queued.project_id,
                            worker = %worker_id,
                            slots = queued.slots_needed,
                            waited_secs = queued.queued_at_mono.elapsed().as_secs(),
                            "Queue hold: draining a worker for a starving multi-slot job"
                        );
                    }
                }
                None => ctx.history.release_queue_hold(queued.id),
            }
        }

        tokio::time::sleep(QUEUE_POLL_INTERVAL).await;
    }
}

/// Longest admission wait the daemon grants a `--job` request (bd-decdd).
const JOB_QUEUE_WAIT_CEILING_SECS: u64 = 24 * 3600;

/// How long a queued request waits: the client's wait, capped at the daemon's
/// queue timeout. A job never falls back to local (bd-decdd), so that cap only
/// turned its wait into a refusal and a resubmission at the back of the queue;
/// a job's longer wait is honoured up to a ceiling. The hook-exit check still
/// drops a dead waiter's row.
fn queue_wait_secs(job_mode: bool, client_secs: Option<u64>, daemon_secs: u64) -> u64 {
    let daemon_secs = daemon_secs.max(1);
    let cap = if job_mode {
        daemon_secs.max(JOB_QUEUE_WAIT_CEILING_SECS)
    } else {
        daemon_secs
    };
    client_secs
        .filter(|secs| *secs > 0)
        .map_or(daemon_secs, |secs| secs.min(cap))
}
/// How long a multi-slot job waits before it may hold a worker (bd-decdd).
const QUEUE_HOLD_AFTER: Duration = Duration::from_secs(120);

struct QueueHoldRelease<'a> {
    history: &'a BuildHistory,
    queue_id: u64,
}

impl Drop for QueueHoldRelease<'_> {
    fn drop(&mut self) {
        self.history.release_queue_hold(self.queue_id);
    }
}

/// A worker that refused this request only for `slots.insufficient`: it
/// passed every other gate and can hold the request once its slots free.
/// Keeps the current hold while it still qualifies; otherwise prefers the
/// worker closest to fitting.
fn queue_hold_candidate(
    diagnostics: &rch_common::SelectionDiagnostics,
    current: Option<&str>,
) -> Option<String> {
    let candidates = diagnostics.workers.iter().filter(|worker| {
        worker.total_slots >= diagnostics.estimated_cores
            && worker
                .reason_codes
                .iter()
                .map(String::as_str)
                .eq(["slots.insufficient"])
    });
    let mut best: Option<&rch_common::WorkerSelectionDiagnostic> = None;
    for worker in candidates {
        if current == Some(worker.worker_id.as_str()) {
            return current.map(str::to_string);
        }
        let rank = |w: &rch_common::WorkerSelectionDiagnostic| {
            (
                w.available_slots,
                w.total_slots,
                std::cmp::Reverse(w.worker_id.as_str().to_string()),
            )
        };
        if best.is_none_or(|b| rank(worker) > rank(b)) {
            best = Some(worker);
        }
    }
    best.map(|worker| worker.worker_id.as_str().to_string())
}

fn maintenance_wall_ms() -> u64 {
    u64::try_from(Utc::now().timestamp_millis()).unwrap_or(0)
}

struct MaintenanceQuery {
    fence: MaintenanceFence,
    purpose: String,
    force: bool,
    owner_identity: Option<ProcessIdentity>,
}

fn parse_maintenance_query(query: &str) -> Result<MaintenanceQuery> {
    let mut values = std::collections::HashMap::new();
    for parameter in query.split('&').filter(|value| !value.is_empty()) {
        let (key, value) = parameter
            .split_once('=')
            .ok_or_else(|| anyhow!("invalid maintenance parameter"))?;
        anyhow::ensure!(
            matches!(
                key,
                "daemon_incarnation" | "token" | "purpose" | "force" | "owner_identity"
            ),
            "unknown maintenance parameter: {key}"
        );
        anyhow::ensure!(
            values
                .insert(key, percent_unescape_query_value(value))
                .is_none(),
            "duplicate maintenance parameter: {key}"
        );
    }
    let daemon_incarnation = values
        .remove("daemon_incarnation")
        .ok_or_else(|| anyhow!("maintenance daemon_incarnation is required"))?;
    let token = values
        .remove("token")
        .ok_or_else(|| anyhow!("maintenance token is required"))?;
    for value in [&daemon_incarnation, &token] {
        anyhow::ensure!(
            Uuid::parse_str(value).is_ok_and(|uuid| uuid.to_string() == *value),
            "maintenance fences require canonical UUIDs"
        );
    }
    let purpose = values
        .remove("purpose")
        .unwrap_or_else(|| "maintenance".into());
    anyhow::ensure!(
        !purpose.is_empty() && purpose.len() <= 96 && !purpose.chars().any(char::is_control),
        "invalid maintenance purpose"
    );
    let force = match values.remove("force").as_deref() {
        None | Some("false" | "0") => false,
        Some("true" | "1") => true,
        _ => return Err(anyhow!("invalid maintenance force flag")),
    };
    let owner_identity = values
        .remove("owner_identity")
        .map(|record| {
            ProcessIdentity::from_record(&record)
                .filter(|identity| identity.to_record().as_deref() == Some(record.as_str()))
                .ok_or_else(|| {
                    anyhow!("maintenance owner_identity must be a canonical process birth record")
                })
        })
        .transpose()?;
    Ok(MaintenanceQuery {
        fence: MaintenanceFence {
            daemon_incarnation,
            token,
        },
        purpose,
        force,
        owner_identity,
    })
}

/// Invoked by worker admission, operator status, and an independent ticker.
/// Taking the write lock fences recovery against any selection still reserving
/// durable work, and against shutdown's final ownership/quiescence check.
pub(crate) async fn recover_restart_admission(ctx: &DaemonContext) {
    let mut admission = ctx.admission_barrier.write().await;
    admission.recover(Instant::now(), maintenance_wall_ms());
    let events = admission.take_events();
    drop(admission);
    for event in events {
        event.emit();
    }
}

async fn bounded_client_lease_scan() -> Result<Vec<String>> {
    // Retain the permit inside the blocking task even if a caller times out.
    // A stuck filesystem therefore cannot create an unbounded pile of scans.
    static SCANS: std::sync::OnceLock<std::sync::Arc<tokio::sync::Semaphore>> =
        std::sync::OnceLock::new();
    let scans = SCANS
        .get_or_init(|| std::sync::Arc::new(tokio::sync::Semaphore::new(1)))
        .clone();
    run_bounded_client_lease_scan(scans, Duration::from_secs(3), nonterminal_client_lease_ids).await
}

async fn run_bounded_client_lease_scan(
    scans: std::sync::Arc<tokio::sync::Semaphore>,
    timeout: Duration,
    scan: impl FnOnce() -> Result<Vec<String>> + Send + 'static,
) -> Result<Vec<String>> {
    let permit = scans
        .try_acquire_owned()
        .map_err(|_| anyhow!("client lease scan already in progress"))?;
    tokio::time::timeout(
        timeout,
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            scan()
        }),
    )
    .await
    .map_err(|_| anyhow!("client lease scan timed out; quiescence is unknown"))?
    .map_err(|error| anyhow!("client lease scan task failed: {error}"))?
}

async fn admission_response(
    ctx: &DaemonContext,
    admission: &mut RestartAdmissionState,
    include_leases: bool,
) -> RestartAdmissionResponse {
    let scan = if include_leases {
        bounded_client_lease_scan().await
    } else {
        Ok(Vec::new())
    };
    // The scan can outlive the operator or its deadline. Never return a stale
    // successful acquisition after recovery has invalidated its fence.
    admission.recover(Instant::now(), maintenance_wall_ms());
    let mut response = admission.snapshot(Instant::now(), ctx.history.ownership_failure_reason());
    response.active_build_ids = ctx
        .history
        .active_builds()
        .into_iter()
        .map(|build| build.id)
        .collect();
    response.queued_build_ids = ctx
        .history
        .queued_builds()
        .into_iter()
        .map(|build| build.id)
        .collect();
    match scan {
        Ok(ids) => response.client_lease_ids = ids,
        Err(error) => response.client_lease_scan_error = Some(error.to_string()),
    }
    response.restart_permitted = include_leases
        && response.maintenance_closed
        && !response.shutdown_committed
        && !response.ownership_failed
        && response.active_build_ids.is_empty()
        && response.queued_build_ids.is_empty()
        && response.client_lease_ids.is_empty()
        && response.client_lease_scan_error.is_none();
    response
}

fn maintenance_failure(
    mut response: RestartAdmissionResponse,
    reason: &str,
) -> RestartAdmissionResponse {
    response.success = false;
    response.status = reason.into();
    response.restart_permitted = false;
    response.message = Some(format!(
        "Maintenance operation refused: {reason}. Inspect `rch daemon admission status --json`; only the current owner can release or stop the daemon, and abandoned operations recover after their deadline."
    ));
    response
}

async fn handle_restart_admission(
    ctx: &DaemonContext,
    fence: &MaintenanceFence,
    action: MaintenanceAction,
    connection_peer: Option<&MaintenancePeer>,
) -> RestartAdmissionResponse {
    let mut admission = ctx.admission_barrier.write().await;
    let response = async {
        admission.recover(Instant::now(), maintenance_wall_ms());
        // Verify the original connection identity under the lock, after any
        // request/lock wait. Do not recapture a replacement process as owner.
        let peer = connection_peer.and_then(MaintenancePeer::revalidate);
        let include_leases = matches!(
            action,
            MaintenanceAction::Acquire { .. } | MaintenanceAction::Renew
        );
        let releasing = matches!(
            action,
            MaintenanceAction::Release | MaintenanceAction::Recover
        );
        let (result, status) = match action {
            MaintenanceAction::Acquire {
                purpose,
                owner_identity,
            } => {
                let result = peer
                    .ok_or("maintenance_peer_identity_unknown")
                    .and_then(|peer| peer.validate_acquisition_identity(&owner_identity))
                    .and_then(|()| {
                        admission.acquire(
                            fence,
                            peer,
                            purpose,
                            Instant::now(),
                            maintenance_wall_ms(),
                        )
                    });
                (result, "acquired")
            }
            MaintenanceAction::Renew => (
                admission.renew(fence, peer, Instant::now(), maintenance_wall_ms()),
                "renewed",
            ),
            MaintenanceAction::Release => (admission.release(fence, peer), "released"),
            MaintenanceAction::Recover => (admission.validate_recovery(fence), "recovered"),
        };
        let mut response =
            admission_response(ctx, &mut admission, include_leases && result.is_ok()).await;
        if let Err(reason) = result {
            return maintenance_failure(response, reason);
        }
        if releasing && response.admission_closed {
            return maintenance_failure(response, "ownership_failed");
        }
        if !releasing
            && admission
                .validate_owner(fence, connection_peer.and_then(MaintenancePeer::revalidate))
                .is_err()
        {
            return maintenance_failure(response, "maintenance_ownership_lost");
        }
        response.status = status.into();
        response
    }
    .await;
    let events = admission.take_events();
    drop(admission);
    for event in events {
        event.emit();
    }
    response
}

async fn handle_shutdown(
    ctx: &DaemonContext,
    fence: &MaintenanceFence,
    force: bool,
    connection_peer: Option<&MaintenancePeer>,
    shutdown_tx: &tokio::sync::mpsc::Sender<()>,
) -> RestartAdmissionResponse {
    let mut admission = ctx.admission_barrier.write().await;
    let response = async {
        admission.recover(Instant::now(), maintenance_wall_ms());
        if let Err(reason) =
            admission.validate_owner(fence, connection_peer.and_then(MaintenancePeer::revalidate))
        {
            return maintenance_failure(
                admission_response(ctx, &mut admission, false).await,
                reason,
            );
        }
        let response = admission_response(ctx, &mut admission, !force).await;
        if !force && !response.restart_permitted {
            return maintenance_failure(response, "shutdown_blocked");
        }
        // Revalidate after the filesystem scan, under the same lock that selection
        // needs. Expiry or owner death during the scan invalidates this operation.
        if let Err(reason) =
            admission.commit_shutdown(fence, connection_peer.and_then(MaintenancePeer::revalidate))
        {
            return maintenance_failure(response, reason);
        }
        match shutdown_tx.try_send(()) {
            Ok(()) | Err(tokio::sync::mpsc::error::TrySendError::Full(())) => {
                // Arm before any logging or subsequent await. An output sink or
                // stalled runtime cannot strand a committed, closed barrier.
                crate::arm_shutdown_watchdog();
                let mut committed = admission_response(ctx, &mut admission, false).await;
                committed.status = "shutting_down".into();
                committed
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(())) => {
                admission.rollback_shutdown_send_failure();
                maintenance_failure(
                    admission_response(ctx, &mut admission, false).await,
                    "shutdown_delivery_failed",
                )
            }
        }
    }
    .await;
    let events = admission.take_events();
    drop(admission);
    for event in events {
        event.emit();
    }
    if response.shutdown_committed && response.success {
        info!(
            daemon_incarnation = %response.daemon_incarnation,
            token = %fence.token,
            deadline_secs = 30,
            "Committed daemon shutdown; admission remains closed until process exit, with a bounded process deadline"
        );
    }
    response
}

async fn restart_admission_snapshot(
    ctx: &DaemonContext,
    include_leases: bool,
) -> RestartAdmissionResponse {
    let mut admission = ctx.admission_barrier.write().await;
    admission.recover(Instant::now(), maintenance_wall_ms());
    let response = admission_response(ctx, &mut admission, include_leases).await;
    let events = admission.take_events();
    drop(admission);
    for event in events {
        event.emit();
    }
    response
}

/// Status may recover a dead/expired operator, but never another live operation.
async fn restart_admission_status(ctx: &DaemonContext) -> RestartAdmissionResponse {
    restart_admission_snapshot(ctx, true).await
}

/// Return every client lease that is not both terminal and explicitly
/// acknowledged by the daemon.  A malformed directory entry fails closed: a
/// restart cannot claim a zero-state snapshot when durable evidence is
/// unreadable.
fn nonterminal_client_lease_ids() -> Result<Vec<String>> {
    scan_client_leases(&default_job_lease_directory())
}

/// The scan behind [`nonterminal_client_lease_ids`], parameterized on the
/// directory so tests exercise it against a temp dir without env games.
fn scan_client_leases(lease_dir: &std::path::Path) -> Result<Vec<String>> {
    let entries = match std::fs::read_dir(lease_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(anyhow!("cannot inspect {}: {error}", lease_dir.display())),
    };

    let now_unix_ms = u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap_or(0);
    let mut blocked = Vec::new();
    for entry in entries {
        let entry =
            entry.map_err(|error| anyhow!("cannot enumerate {}: {error}", lease_dir.display()))?;
        if entry
            .path()
            .extension()
            .is_none_or(|extension| extension != "json")
        {
            continue;
        }
        let bytes = std::fs::read(entry.path())
            .map_err(|error| anyhow!("cannot read {}: {error}", entry.path().display()))?;
        let lease: DurableJobLease = serde_json::from_slice(&bytes)
            .map_err(|error| anyhow!("cannot parse {}: {error}", entry.path().display()))?;
        if lease_blocks_restart(&lease, now_unix_ms, || {
            owner_presence(lease.wrapper_pid, lease.owner_identity().as_ref())
        }) {
            blocked.push(lease.identity.local_wrapper_id);
        } else if now_unix_ms.saturating_sub(lease.heartbeat_unix_ms) >= LEASE_REAP_RETENTION_MS
            && !lease_owns_unretired_source(&lease)
            && (!lease_waits_for_restart_admission(&lease)
                || owner_presence(lease.wrapper_pid, lease.owner_identity().as_ref())
                    == OwnerPresence::Absent)
        {
            // Reap the file: it no longer blocks restart (terminal+acked, or
            // provably dead and stale) and its last heartbeat is over the
            // retention window, so it is pure history. Nothing else ever
            // removed these — 18k of them accumulated in days and made every
            // admission re-scan (and re-probe) all of them (bd-daspu). Best
            // effort: a remove that fails just means we scan it again.
            let _ = std::fs::remove_file(entry.path());
        }
    }
    blocked.sort();
    Ok(blocked)
}

/// How long a non-blocking lease is kept after its last heartbeat before the
/// scan reaps its file. Long enough for post-mortem inspection of a just
/// finished job; short enough that the directory stays bounded.
const LEASE_REAP_RETENTION_MS: u64 = 60 * 60 * 1000;

/// Heartbeat age past which a lease whose wrapper owner is provably absent is
/// treated as abandoned for restart-admission purposes. Wrappers heartbeat
/// every few seconds while alive, so fifteen minutes of silence combined with
/// an absent owner is affirmative evidence the client is gone — not a pause.
const DEAD_WRAPPER_HEARTBEAT_STALE_MS: u64 = 15 * 60 * 1000;

/// Whether one durable client lease blocks the restart-admission barrier.
///
/// A lease only stops blocking on affirmative evidence: either the wrapper
/// acknowledged a terminal state, or the wrapper owner is provably absent
/// AND its heartbeat is stale past [`DEAD_WRAPPER_HEARTBEAT_STALE_MS`]. A
/// recycled PID or a previous boot proves that the recorded owner is absent;
/// the existence of an unrelated process does not keep its lease alive.
/// Fresh heartbeats, live owners, and uncertain ownership stay blocking.
/// Without the absent-wrapper arm, leases
/// orphaned by killed wrappers accumulate forever and permanently wedge
/// `rch daemon restart` (observed live 2026-08-09: ~450 dead `running` leases,
/// heartbeats days old, no restart possible).
///
/// `wrapper_presence` is a thunk so the durable identity probe only
/// runs for leases that already passed the cheap heartbeat-staleness filter.
/// A lease whose recovery recipe is not retired is the only authority that
/// can release its worker-side source claim (`rch jobs recover`). Reaping it
/// after its wrapper died stranded the claim forever and fenced every
/// overlapping build on that worker (bd-dmg2k: 69 such claims fleet-wide).
/// Only a recipe that names worker-side ownership (source roots, a source
/// pair, or a tree to retire) needs keeping.
/// Workers this project must not be placed on: one running build per project
/// per worker, workers whose failed build's client lease still owns worker
/// source (their registry would refuse the same root, bd-jqhno), and workers
/// whose live checkout of the project refused a recent sync (bd-fbtws), and
/// workers where another owner recently kept the project's source (bd-p3kuz).
fn project_excluded_workers(
    ctx: &DaemonContext,
    project: &str,
) -> std::collections::HashSet<String> {
    project_exclusions(ctx, project).into_keys().collect()
}

/// Why selection skips a worker for one project. Selection only needs the
/// set; `rch diagnose` names the cause (GH #125).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProjectExclusion {
    /// Every project lane on the worker holds an active build of it.
    LanesFull,
    /// A failed build's client lease still owns the project's source there.
    SourceFenced,
    /// The worker's live checkout of the project refused a source sync.
    LiveCheckout,
    /// Another owner held the project's source there past the admission wait.
    SourceBusy,
}

impl ProjectExclusion {
    fn reason_code(self) -> &'static str {
        match self {
            Self::LanesFull => "project.lanes_full",
            Self::SourceFenced => "project.source_fenced",
            Self::LiveCheckout => "project.live_checkout_fenced",
            Self::SourceBusy => "project.source_busy_fenced",
        }
    }

    fn reason(self) -> &'static str {
        match self {
            Self::LanesFull => "every project lane on this worker holds an active build",
            Self::SourceFenced => {
                "a failed build's client lease still owns this project's source on this worker"
            }
            Self::LiveCheckout => {
                "this worker's live checkout of the project refused a source sync"
            }
            Self::SourceBusy => "another owner holds this project's source on this worker",
        }
    }
}

/// The workers excluded for `project`, each with the first cause found.
fn project_exclusions(
    ctx: &DaemonContext,
    project: &str,
) -> std::collections::HashMap<String, ProjectExclusion> {
    // A worker is full for this project once every one of its project lanes
    // holds an active build (bd-sgvod; one lane unless daemon.toml says more).
    let mut excluded: std::collections::HashMap<String, ProjectExclusion> = ctx
        .history
        .active_build_counts_for_project(project)
        .into_iter()
        .filter(|(worker, count)| *count >= ctx.pool.project_lanes(worker) as usize)
        .map(|(worker, _)| (worker, ProjectExclusion::LanesFull))
        .collect();
    let fences = [
        (
            ctx.history
                .source_fenced_workers(project, crate::cancellation::client_lease_owns_source),
            ProjectExclusion::SourceFenced,
        ),
        (
            ctx.history.live_checkout_fenced_workers(project),
            ProjectExclusion::LiveCheckout,
        ),
        (
            ctx.history.source_busy_fenced_workers(project),
            ProjectExclusion::SourceBusy,
        ),
    ];
    for (workers, cause) in fences {
        for worker in workers {
            excluded.entry(worker).or_insert(cause);
        }
    }
    excluded
}

/// Name each project exclusion's actual cause in the per-worker diagnostics.
/// The selector reports them all as `active_project_exclusion` because it
/// sees only the excluded set; that code stays for existing consumers.
fn describe_project_exclusions(
    diagnostics: &mut rch_common::SelectionDiagnostics,
    exclusions: &std::collections::HashMap<String, ProjectExclusion>,
) {
    for worker in &mut diagnostics.workers {
        let Some(cause) = exclusions.get(worker.worker_id.as_str()) else {
            continue;
        };
        if worker
            .reason_codes
            .iter()
            .any(|code| code == "active_project_exclusion")
        {
            worker.final_reason = cause.reason().to_string();
            worker.reason_codes.push(cause.reason_code().to_string());
        }
    }
}

pub(crate) fn lease_owns_unretired_source(lease: &DurableJobLease) -> bool {
    lease.recovery.as_ref().is_some_and(|recipe| {
        let owns = recipe
            .get("source_roots")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|roots| !roots.is_empty())
            || recipe.get("pair").is_some_and(|pair| !pair.is_null())
            || recipe
                .get("retire_root")
                .is_some_and(|root| !root.is_null());
        owns && recipe.get("retired").and_then(serde_json::Value::as_bool) != Some(true)
    })
}

pub(crate) fn lease_blocks_restart(
    lease: &DurableJobLease,
    now_unix_ms: u64,
    wrapper_presence: impl FnOnce() -> OwnerPresence,
) -> bool {
    if lease.state.is_terminal() && lease.terminal_acknowledged {
        return false;
    }
    if lease_waits_for_restart_admission(lease) {
        // A new wrapper waiting outside the gate owns no execution, queue row
        // or worker source. Counting it as active makes every new build extend
        // a drain forever. Its live journal is retained separately by the scan.
        return false;
    }
    // A durable timestamp from a future wall clock cannot establish recent
    // liveness. Fall back to identity, keeping live/unknown owners conservative.
    let heartbeat_stale = lease.heartbeat_unix_ms > now_unix_ms
        || now_unix_ms.saturating_sub(lease.heartbeat_unix_ms) >= DEAD_WRAPPER_HEARTBEAT_STALE_MS;
    if !heartbeat_stale {
        return true;
    }
    wrapper_presence() != OwnerPresence::Absent
}

fn lease_waits_for_restart_admission(lease: &DurableJobLease) -> bool {
    lease.phase == "restart_admission_wait"
        && lease.state == rch_common::job_identity::JobLifecycleState::Queued
        && lease.identity.remote_build_id.is_none()
        && lease.worker_id.is_none()
        && lease.recovery.is_none()
        && lease.exit_code.is_none()
        && !lease.terminal_acknowledged
}

/// Handle a release-worker request that has no connection peer.
#[cfg(test)]
async fn handle_release_worker(ctx: &DaemonContext, request: ReleaseRequest) -> Result<()> {
    handle_release_worker_from(ctx, request, None).await
}

/// Handle a release-worker request.
///
/// `peer` is the release connection's kernel-reported process, captured when
/// the connection was accepted. It is consulted only for a release that omits
/// `local_wrapper_id` (GH #119, see [`BuildHistory::legacy_release_wrapper`]).
async fn handle_release_worker_from(
    ctx: &DaemonContext,
    mut request: ReleaseRequest,
    peer: Option<&MaintenancePeer>,
) -> Result<()> {
    anyhow::ensure!(
        request.disk_peak_output_bytes.is_none() || request.exit_code.is_some(),
        "Disk output measurement requires an explicit release exit code"
    );
    let _release_guard = ctx.history.lock_releases().await;
    if request.local_wrapper_id.is_none()
        && let (Some(build_id), Some(peer)) = (request.build_id, peer)
        && let Some(wrapper) = ctx.history.legacy_release_wrapper(
            build_id,
            request.worker_id.as_str(),
            peer.pid,
            &peer.identity,
        )
    {
        info!(
            build_id,
            worker_id = %request.worker_id,
            local_wrapper_id = %wrapper,
            client_pid = peer.pid,
            "Accepting a release without local_wrapper_id from the build's own client \
             process (pre-2.1 client, GH #119)"
        );
        request.local_wrapper_id = Some(wrapper);
    }
    let started = std::time::Instant::now();
    let exit_code = request.exit_code.unwrap_or(0);
    let worker_disk_full = exit_code != 0 && request.worker_disk_full;
    let (release_worker_id, release_slots, record, remote_command_started, worker_endpoint) =
        if let Some(build_id) = request.build_id {
            let completion = ctx
                .history
                .complete_durable_with_disk_fault(
                    build_id,
                    request.worker_id.as_str(),
                    request.local_wrapper_id.as_deref(),
                    crate::history::BuildCompletion {
                        exit_code,
                        duration_ms: request.duration_ms,
                        bytes_transferred: request.bytes_transferred,
                        disk_peak_output_bytes: request.disk_peak_output_bytes,
                        timing: request.timing,
                        cancellation: None,
                    },
                    worker_disk_full.then_some(request.worker_disk_roots),
                )
                .inspect_err(|error| {
                    if error.kind() == std::io::ErrorKind::PermissionDenied {
                        let recorded = ctx.history.active_build(build_id);
                        let recorded = recorded.as_ref();
                        warn!(
                            build_id,
                            worker_id = %request.worker_id,
                            presented_wrapper =
                                request.local_wrapper_id.as_deref().unwrap_or("<none>"),
                            recorded_worker =
                                recorded.map_or("<none>", |state| state.worker_id.as_str()),
                            recorded_wrapper = recorded
                                .and_then(|state| state.local_wrapper_id.as_deref())
                                .unwrap_or("<none>"),
                            "Refusing release: build ownership mismatch"
                        );
                    }
                })?;
            // A retry acknowledges only its original, owner-validated fault.
            // Its newly supplied flags/paths cannot rewrite a terminal build.
            let Some((state, record)) = completion else {
                if let Some(fault) = ctx.history.pending_disk_fault(build_id) {
                    anyhow::ensure!(
                        apply_pending_disk_fault(ctx, &fault).await?,
                        "disk-fault endpoint is absent; durable incident is pending reintroduction"
                    );
                }
                return Ok(());
            };
            let remote_command_started = state.remote_command_started();
            (
                WorkerId::new(state.worker_id),
                state.slots,
                Some(record),
                remote_command_started,
                state.worker_endpoint,
            )
        } else {
            anyhow::bail!("release requires durable build_id; unowned slot release refused")
        };
    let ownership_done = started.elapsed();

    // A completed build's exact owner, not an uncorrelated error string or
    // arbitrary worker id, supplies this signal. Quarantine before returning
    // its slots so another selection cannot reuse them on the exhausted disk.
    // The eligibility axis and its durable recovery record leave admin intent
    // unchanged; ordinary SSH success cannot reopen this worker.
    let quarantine_result = if let Some(fault) = ctx.history.pending_disk_fault(
        request
            .build_id
            .expect("durable build identity checked above"),
    ) {
        apply_pending_disk_fault(ctx, &fault)
            .await
            .and_then(|resolved| {
                anyhow::ensure!(
                    resolved,
                    "disk-fault endpoint is absent; durable incident is pending reintroduction"
                );
                Ok(())
            })
    } else {
        Ok(())
    };

    debug!(
        "Releasing {} slots on worker {}",
        release_slots, release_worker_id
    );
    ctx.pool
        .release_slots(&release_worker_id, release_slots)
        .await;
    let slots_done = started.elapsed();

    if let Some(ref rec) = record {
        // The owner-validated worker refused this project's source because it
        // is a live checkout there; every later sync would be refused too.
        if exit_code != 0 && request.worker_live_checkout_refused {
            ctx.history
                .fence_live_checkout(&rec.project_id, release_worker_id.as_str());
            info!(
                project_id = %rec.project_id,
                worker_id = %release_worker_id,
                hours = crate::history::LIVE_CHECKOUT_FENCE_MAX_AGE.as_secs() / 3600,
                "Keeping project off worker: its live checkout refused the source sync (bd-fbtws)"
            );
        }
        // Another owner, often a stopped client whose build rchd already
        // retired, holds this project's source there; every placement would
        // wait out the admission timeout and be refused (bd-p3kuz).
        if exit_code != 0 && request.worker_source_busy {
            ctx.history
                .fence_source_busy(&rec.project_id, release_worker_id.as_str());
            info!(
                project_id = %rec.project_id,
                worker_id = %release_worker_id,
                minutes = crate::history::SOURCE_BUSY_FENCE_MAX_AGE.as_secs() / 60,
                "Keeping project off worker: another owner holds its source there (bd-p3kuz)"
            );
        }
        if !cfg!(test) {
            metrics::dec_active_builds("remote");
            let outcome = if exit_code == 0 { "success" } else { "failure" };
            metrics::inc_build_total(outcome, "remote");
        }
        ctx.events.emit(
            "build_completed",
            &serde_json::json!({
                "build_id": rec.id,
                "project_id": rec.project_id,
                "worker_id": rec.worker_id,
                "command": rec.command,
                "exit_code": rec.exit_code,
                "duration_ms": rec.duration_ms,
                "location": format!("{:?}", rec.location),
            }),
        );

        // Only successful command completions are positive worker-health
        // signals. A nonzero command exit is a build/test result, not an
        // infrastructure failure for the worker circuit.
        if let Some(endpoint) = worker_endpoint.as_ref()
            && let Some(worker) = ctx.pool.get(&endpoint.config.id).await
        {
            if exit_code == 0
                && let Some(_endpoint_guard) = worker.lock_current_endpoint(endpoint).await
            {
                worker.record_success().await;
            }

            // A failure the hook blamed on the worker (missing toolchain or
            // system library, SIGILL, full disk) says the worker is broken
            // for this project, not that its pool is worth returning to.
            ctx.worker_selector
                .record_bound_remote_completion(
                    &worker,
                    endpoint,
                    &rec.project_id,
                    &rec.command,
                    exit_code,
                    remote_command_started && !request.worker_fault && !worker_disk_full,
                )
                .await;
        }
    }
    // The hook fails a finished build closed when this ack is late, so name
    // the slow stage instead of leaving only the client-side timeout.
    let total = started.elapsed();
    if total >= SLOW_RELEASE_WARN {
        warn!(
            build_id = ?request.build_id,
            worker_id = %release_worker_id,
            ownership_ms = ownership_done.as_millis() as u64,
            slots_ms = (slots_done - ownership_done).as_millis() as u64,
            completion_ms = (total - slots_done).as_millis() as u64,
            "Slow release-worker handling ({} ms)",
            total.as_millis()
        );
    }
    // Ownership is already terminal even if the separate quarantine journal
    // failed. Release its slots exactly once, but refuse acknowledgment until
    // the pending durable fault can be finished by retry or daemon startup.
    quarantine_result
}

async fn apply_pending_disk_fault(
    ctx: &DaemonContext,
    fault: &crate::history::PendingDiskFault,
) -> Result<bool> {
    let worker = ctx.pool.get(&WorkerId::new(&fault.worker_id)).await;
    let Some(store) = &ctx.bypass_store else {
        let Some(endpoint) = fault.worker_endpoint.as_ref() else {
            ctx.history
                .archive_disk_fault(fault.build_id, &fault.incident_id)?;
            return Ok(true);
        };
        let Some(worker) = worker else {
            return Ok(false);
        };
        let Some(_config) = worker
            .lock_disk_fault_endpoint(endpoint, fault.runtime_endpoint.as_ref())
            .await
        else {
            if worker.is_endpoint_retired() {
                return Ok(false);
            }
            ctx.history
                .archive_disk_fault(fault.build_id, &fault.incident_id)?;
            return Ok(true);
        };
        worker
            .enter_bypass(rch_common::BypassFailureClass::DiskInodePressure)
            .await;
        anyhow::bail!("worker disk fault cannot be acknowledged without durable bypass storage");
    };
    crate::bypass_recovery_service::apply_owned_disk_fault(
        store,
        worker.as_ref(),
        &ctx.history,
        fault,
    )
    .await
}

/// Finish completion's durable side effects before startup enables admission
/// or background recovery. Absent workers retain an endpoint-bound pending
/// obligation, retried by the recovery service after inventory changes. Their
/// old filesystem cannot quarantine a different endpoint reusing the ID.
pub(crate) async fn replay_pending_disk_faults(ctx: &DaemonContext) -> Result<()> {
    let _release_guard = ctx.history.lock_releases().await;
    for fault in ctx.history.pending_disk_faults() {
        apply_pending_disk_fault(ctx, &fault).await?;
    }
    Ok(())
}

/// A build-id cancel refused because a durable wrapper owns the build. Name
/// the owner and the paths that do work, so the operator neither retries a
/// refusal nor reaches for a daemon restart (which keeps durable ownership).
/// `owner` is `None` when the build is already terminal, `Some(None)` when an
/// active build has no wrapper identity.
fn ownership_mismatch_message(build_id: u64, owner: Option<Option<&str>>) -> String {
    match owner {
        Some(Some(wrapper)) => format!(
            "build ownership mismatch: build {build_id} is owned by wrapper {wrapper}. \
             Cancel it with `rch jobs cancel {wrapper}`. If that wrapper and its lease are \
             gone, the stuck detector releases the build on its own once it has been silent \
             for 15 min (never started remote work) or 6h (started)"
        ),
        Some(None) => format!(
            "build ownership mismatch: build {build_id} has no wrapper identity; cancel it \
             by build id alone"
        ),
        None => format!("build ownership mismatch: build {build_id} has already completed"),
    }
}

/// Release handling at or above this logs its per-stage breakdown.
const SLOW_RELEASE_WARN: Duration = Duration::from_secs(1);

/// Handle a record-build request.
async fn handle_record_build(
    ctx: &DaemonContext,
    worker_id: &WorkerId,
    project: &str,
    is_test: bool,
) -> Result<()> {
    debug!(
        "Recording build for project '{}' on worker {}",
        project, worker_id
    );
    ctx.worker_selector
        .record_build(worker_id.as_str(), project, is_test)
        .await;
    Ok(())
}

fn heartbeat_phase_to_str(phase: &rch_common::BuildHeartbeatPhase) -> &'static str {
    match phase {
        rch_common::BuildHeartbeatPhase::SyncUp => "sync_up",
        rch_common::BuildHeartbeatPhase::Execute => "execute",
        rch_common::BuildHeartbeatPhase::SyncDown => "sync_down",
        rch_common::BuildHeartbeatPhase::Finalize => "finalize",
    }
}

/// Handle a build-heartbeat request.
async fn handle_build_heartbeat(
    ctx: &DaemonContext,
    request: BuildHeartbeatRequest,
) -> BuildHeartbeatResponse {
    let build_id = request.build_id;
    let worker_id = request.worker_id.as_str().to_string();
    let phase = heartbeat_phase_to_str(&request.phase).to_string();
    let detail = request.detail.clone();
    let progress_counter = request.progress_counter;
    let progress_percent = request.progress_percent;

    if ctx.history.ownership_failed() {
        return BuildHeartbeatResponse {
            status: "error: durable ownership uncertain; restart required".to_string(),
            build_id,
            worker_id,
            phase,
        };
    }
    if let Some(state) = ctx.history.record_build_heartbeat(request) {
        let event_phase = heartbeat_phase_to_str(&state.heartbeat_phase).to_string();
        let event_detail = state.heartbeat_detail.clone();
        let event_counter = state.heartbeat_counter;
        let event_percent = state.heartbeat_percent;
        ctx.events.emit(
            "build_heartbeat",
            &serde_json::json!({
                "build_id": state.id,
                "project_id": state.project_id,
                "worker_id": state.worker_id,
                "phase": event_phase,
                "detail": event_detail,
                "progress_counter": event_counter,
                "progress_percent": event_percent,
            }),
        );
        BuildHeartbeatResponse {
            status: "ok".to_string(),
            build_id,
            worker_id,
            phase,
        }
    } else {
        if ctx.history.ownership_failed() {
            return BuildHeartbeatResponse {
                status: "error: failed to persist heartbeat ownership; restart required"
                    .to_string(),
                build_id,
                worker_id,
                phase,
            };
        }
        warn!(
            "Ignoring heartbeat for unknown build {} on worker {}",
            build_id, worker_id
        );
        ctx.events.emit(
            "build_heartbeat_ignored",
            &serde_json::json!({
                "build_id": build_id,
                "worker_id": worker_id.clone(),
                "phase": phase.clone(),
                "detail": detail,
                "progress_counter": progress_counter,
                "progress_percent": progress_percent,
            }),
        );
        BuildHeartbeatResponse {
            status: "ignored".to_string(),
            build_id,
            worker_id,
            phase,
        }
    }
}

/// Handle a metrics request - returns Prometheus text format.
fn handle_metrics() -> Result<String> {
    metrics::encode_metrics()
}

/// Handle a health check request.
fn handle_health(ctx: &DaemonContext) -> HealthResponse {
    HealthResponse {
        status: "healthy".to_string(),
        version: ctx.version.to_string(),
        uptime_seconds: ctx.started_at.elapsed().as_secs(),
    }
}

/// Whether select-worker could hand this worker a new build.
///
/// Capacity surfaces (`/status` `slots_available`, socket and HTTP `/ready`)
/// must agree with selection: critical pressure is a hard selection exclusion
/// whichever pressure rule fired (disk, ratio, IO, memory), so a critical
/// worker contributes no assignable capacity (issue #75).
pub(crate) fn worker_accepts_new_builds(
    status: WorkerStatus,
    circuit_state: CircuitState,
    pressure_state: crate::disk_pressure::PressureState,
) -> bool {
    matches!(status, WorkerStatus::Healthy | WorkerStatus::Degraded)
        && circuit_state != CircuitState::Open
        && pressure_state != crate::disk_pressure::PressureState::Critical
}

/// Handle a readiness check request.
async fn handle_ready(ctx: &DaemonContext) -> ReadyResponse {
    let workers = ctx.pool.all_workers().await;

    // Check if any assignable workers are available. Raw free slots on drained,
    // disabled, unreachable, open-circuit, or critical-pressure workers cannot
    // accept new builds.
    let mut workers_available = false;
    for w in workers {
        let Some(circuit_state) = w.circuit_state().await else {
            continue;
        };
        let pressure_state = w.pressure_assessment().await.state;
        if !worker_accepts_new_builds(w.status().await, circuit_state, pressure_state) {
            continue;
        }
        if w.available_slots().await > 0 {
            workers_available = true;
            break;
        }
    }

    if workers_available {
        ReadyResponse {
            status: "ready".to_string(),
            workers_available: true,
            reason: None,
        }
    } else {
        ReadyResponse {
            status: "not_ready".to_string(),
            workers_available: false,
            reason: Some("no_workers_available".to_string()),
        }
    }
}

/// Handle a budget status request.
fn handle_budget() -> BudgetStatusResponse {
    budget::get_budget_status()
}

pub(crate) fn is_process_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }

    // Signal 0 performs error checking without sending a signal: the process
    // exists (0) or errors. EPERM still means "exists". This MUST be a direct
    // syscall, not a forked `/bin/kill` — the lease scan calls it once per
    // stale lease, and with thousands of leaked leases the forks monopolized
    // every runtime thread and wedged the daemon socket (bd-daspu).
    #[cfg(unix)]
    {
        let Ok(pid) = i32::try_from(pid) else {
            return false;
        };
        match nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None) {
            Ok(()) => true,
            // EPERM: the process exists but is not ours to signal — alive,
            // which is also the conservative direction for lease blocking.
            Err(nix::errno::Errno::EPERM) => true,
            Err(_) => false,
        }
    }
    #[cfg(not(unix))]
    {
        std::process::Command::new("kill")
            .arg("-0")
            .arg(pid.to_string())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }
}

async fn handle_cancel_job(
    ctx: &DaemonContext,
    wrapper: &str,
    force: bool,
) -> Result<serde_json::Value> {
    use crate::history::WrapperCancellation;
    match ctx.history.cancel_wrapper(wrapper)? {
        WrapperCancellation::BeforeStart => {
            ctx.history.update_queue_estimates();
            if !cfg!(test) {
                metrics::set_build_queue_depth(ctx.history.queue_depth());
            }
            ctx.events.emit(
                "job_cancelled_before_start",
                &serde_json::json!({"local_wrapper_id":wrapper}),
            );
            Ok(
                serde_json::json!({"status":"cancelled_before_start", "local_wrapper_id":wrapper, "exit_code":130, "slots_released":0}),
            )
        }
        WrapperCancellation::Active(build_id) => {
            let response = handle_cancel_build(ctx, build_id, force).await;
            let mut response = serde_json::to_value(response)?;
            response["local_wrapper_id"] = serde_json::json!(wrapper);
            Ok(response)
        }
        WrapperCancellation::Completed(record) => Ok(
            serde_json::json!({"status":"completed", "local_wrapper_id":wrapper, "record":record}),
        ),
        WrapperCancellation::NotQueued => Ok(
            serde_json::json!({"status":"not_queued", "local_wrapper_id":wrapper, "message":"Job is not currently queued; no cancellation-before-start was acknowledged"}),
        ),
    }
}

/// Handle a build cancellation request.
///
/// Delegates to the CancellationOrchestrator for deterministic state machine,
/// bounded escalation (SIGTERM → remote kill → SIGKILL), and cleanup.
async fn handle_cancel_build(
    ctx: &DaemonContext,
    build_id: u64,
    force: bool,
) -> CancelBuildResponse {
    ctx.cancellation
        .cancel_build(
            ctx,
            build_id,
            crate::cancellation::CancelReason::User,
            force,
        )
        .await
}

/// Handle cancellation of all active builds.
///
/// Delegates to the CancellationOrchestrator for each active build.
async fn handle_cancel_all_builds(ctx: &DaemonContext, force: bool) -> CancelAllBuildsResponse {
    ctx.cancellation.cancel_all_builds(ctx, force).await
}

fn cancellation_issues_from_recent_builds(recent_builds: &[BuildRecord]) -> Vec<Issue> {
    let mut cancelled = 0usize;
    let mut cleanup_failures = 0usize;
    let mut sigkill_escalations = 0usize;
    let mut unreachable_workers = 0usize;
    let mut latest_operation: Option<String> = None;

    for build in recent_builds {
        let Some(cancellation) = &build.cancellation else {
            continue;
        };
        cancelled += 1;
        latest_operation = Some(cancellation.operation_id.clone());
        if !cancellation.cleanup_ok {
            cleanup_failures += 1;
        }
        if cancellation.escalation_stage == "sigkill" {
            sigkill_escalations += 1;
        }
        if cancellation
            .worker_health
            .as_ref()
            .is_some_and(|health| health.status == "unreachable")
        {
            unreachable_workers += 1;
        }
    }

    let mut issues = Vec::new();
    if cleanup_failures > 0 {
        let operation_hint = latest_operation
            .map(|op| format!(" Last operation: {op}."))
            .unwrap_or_default();
        issues.push(Issue {
            severity: "error".to_string(),
            summary: format!(
                "{} recent cancellation(s) finished with cleanup failures.{operation_hint}",
                cleanup_failures
            ),
            remediation: Some(
                "Run `rch workers probe --all`, then inspect daemon logs for `cancellation_failed` events before retrying affected builds.".to_string(),
            ),
            worker_id: None,
        });
    }

    if sigkill_escalations > 0 {
        issues.push(Issue {
            severity: "warning".to_string(),
            summary: format!(
                "{} recent cancellation(s) escalated to SIGKILL (stuck or unresponsive process trees).",
                sigkill_escalations
            ),
            remediation: Some(
                "Check for stuck toolchain phases with `rch status --jobs` and investigate long-running remote processes.".to_string(),
            ),
            worker_id: None,
        });
    }

    if unreachable_workers > 0 {
        issues.push(Issue {
            severity: "warning".to_string(),
            summary: format!(
                "{} cancellation(s) ended while worker health reported unreachable.",
                unreachable_workers
            ),
            remediation: Some(
                "Validate worker reachability with `rch workers probe --all` and confirm SSH connectivity before resuming remote builds.".to_string(),
            ),
            worker_id: None,
        });
    }

    if cancelled > 0 && issues.is_empty() {
        issues.push(Issue {
            severity: "info".to_string(),
            summary: format!(
                "{} recent cancellation(s) completed cleanly with deterministic cleanup.",
                cancelled
            ),
            remediation: Some(
                "No action required. Use `rch status --json` to inspect cancellation metadata if debugging build interruptions.".to_string(),
            ),
            worker_id: None,
        });
    }

    issues
}

fn active_build_issues_from_active_builds(
    active_builds: &[crate::history::ActiveBuildState],
) -> Vec<Issue> {
    let stalled_live_hook_builds: Vec<_> = active_builds
        .iter()
        .filter(|build| {
            build.detector_progress_stale
                && build.detector_hook_alive
                && !build.detector_heartbeat_stale
        })
        .collect();

    if stalled_live_hook_builds.is_empty() {
        return Vec::new();
    }

    let representative = stalled_live_hook_builds
        .iter()
        .max_by_key(|build| build.detector_build_age_secs)
        .expect("non-empty stalled live-hook build list");

    // Stale progress with a live hook and fresh heartbeats is the normal shape
    // of one large crate compiling silently, which the stuck detector no longer
    // cancels (9f8692f2). The old remediation told readers to cancel the build
    // and drain the worker; agents followed it literally, cancelling healthy
    // builds and draining a 64-core worker (hz4, 2026-09-28). Keep it
    // informational and point at inspection, not intervention.
    vec![Issue {
        severity: "info".to_string(),
        summary: format!(
            "{} active build(s) have stale progress while hook heartbeats remain fresh (longest: build {} on worker {}); usually a large crate compiling silently.",
            stalled_live_hook_builds.len(),
            representative.id,
            representative.worker_id
        ),
        remediation: Some(format!(
            "No action needed while the hook stays alive. Inspect with `rch queue --json`; cancel build {} only if it is past its build/test timeout budget. Do not drain {} for this: the worker is healthy.",
            representative.id, representative.worker_id
        )),
        worker_id: None,
    }]
}

/// Handle a status request.
/// Assemble the operator-facing remediation view (bd-..14.4) from the live
/// daemon state already gathered for `/status`. Single source of truth: the
/// TUI, CLI, and web all render this struct, so the three surfaces cannot
/// disagree on counts or posture.
///
/// Zero extra I/O on the (TUI-polled) status path: worker rows come from the
/// already-built `worker_infos`, jobs from the already-fetched build history,
/// and recent incidents from the in-memory active alerts. The deferred-proof
/// conveyor is not daemon-resident yet (bd-..5.3 is foundation-only), so the
/// proof-queue census is empty here; the assembler supports a populated census
/// once the conveyor is wired.
fn build_remediation_view(
    worker_infos: &[WorkerStatusInfo],
    active_builds: &[crate::history::ActiveBuildState],
    queued_count: usize,
    alerts: &[AlertInfo],
    now: chrono::DateTime<Utc>,
) -> rch_common::remediation_view::RemediationView {
    use rch_common::bypass_record::BypassState;
    use rch_common::fleet_diff::WorkerObservation;
    use rch_common::fleet_status::DEFAULT_ABSENCE_THRESHOLD_SECS;
    use rch_common::remediation_view::{
        DiskLevel, JobsInput, MAX_VIEW_INCIDENTS, ProofQueueInput, RemediationIncidentLine,
        RemediationWorkerRow, assemble, build_inputs,
    };

    let rows: Vec<RemediationWorkerRow> = worker_infos
        .iter()
        .map(|w| {
            let facts_known = w.pressure_state != "telemetry_gap";
            RemediationWorkerRow {
                observation: WorkerObservation {
                    worker_id: w.id.clone(),
                    configured: true,
                    in_daemon_pool: true,
                    reachable: w.status != "unreachable",
                    admin_disabled: w.status == "disabled",
                    temporarily_bypassed: w.bypass.is_some(),
                    facts_known,
                    // The bare dashboard view is not tied to a specific command.
                    command_admissible: true,
                },
                disk_level: DiskLevel::from_pressure_state(&w.pressure_state),
                // Per-worker reclaim progress is not surfaced in the status row;
                // critical pressure without a reclaim signal reads as operator
                // action, which is the safe default.
                reclaiming: false,
                free_ratio: w.pressure_disk_free_ratio,
                slots_used: w.used_slots,
                slots_total: w.total_slots,
                telemetry_known: facts_known,
                telemetry_fresh: w.pressure_telemetry_fresh,
                telemetry_age_secs: w.pressure_telemetry_age_secs,
                recovered_pending_canary: w
                    .bypass
                    .as_ref()
                    .is_some_and(|b| b.state == BypassState::RecoveredPendingCanary),
                absent_secs: None,
            }
        })
        .collect();

    let stuck = active_builds
        .iter()
        .filter(|b| {
            !b.detector_hook_alive || (b.detector_heartbeat_stale && b.detector_progress_stale)
        })
        .count();
    let jobs = JobsInput {
        active: active_builds.len(),
        queued: queued_count,
        stuck,
    };

    let incidents: Vec<RemediationIncidentLine> = alerts
        .iter()
        .filter(|a| a.state == "active")
        .take(MAX_VIEW_INCIDENTS)
        .map(|a| {
            let age = chrono::DateTime::parse_from_rfc3339(&a.last_seen)
                .ok()
                .map(|t| {
                    u64::try_from((now - t.with_timezone(&Utc)).num_seconds().max(0)).unwrap_or(0)
                })
                .unwrap_or(0);
            RemediationIncidentLine::new(
                a.kind.clone(),
                "alert",
                a.worker_id.clone(),
                age,
                a.message.clone(),
            )
        })
        .collect();

    let inputs = build_inputs(
        &rows,
        jobs,
        ProofQueueInput::default(),
        incidents,
        DEFAULT_ABSENCE_THRESHOLD_SECS,
    );
    let now_ms = u64::try_from(now.timestamp_millis()).unwrap_or(0);
    assemble(&inputs, now_ms)
}

/// The single most actionable issue for one worker, or `None` when it is fine.
///
/// Ordering is by *actionability*, not severity. The administrative axis
/// (`Disabled` / `Drained`) is checked FIRST and deliberately suppresses every
/// downstream signal, because on a worker the operator has taken out of service
/// those signals are both expected and unfixable:
///
/// `TelemetryPoller::should_poll_worker` skips `AdminIntent::Drained |
/// AdminIntent::Disabled` outright, so such a worker's telemetry ALWAYS decays
/// into `PressureState::TelemetryGap`. Reporting that gap here used to mask the
/// real reason and, worse, offered "wait for the next poll, or run `rch daemon
/// restart`" as the fix — two things that provably cannot work: the poller
/// never polls it, and an admin disable is persisted in `AdminDisableStore` and
/// re-applied verbatim on daemon startup, so a restart reinstates it. That is
/// precisely the confident-wrong remediation the TelemetryGap arm warns about
/// (issue #16), reintroduced one branch further down.
///
/// Observed in the field: worker `hz3` was auto-quarantined with reason
/// `e104-timeout-orphan-unverified` and then sat at `0/10` top-priority slots
/// for ~18 h while `rch status` reported only "stale/missing pressure
/// telemetry". The real fix is `rch workers enable <id>`, which also deletes
/// the durable record.
fn worker_issue(
    worker_id: &str,
    status: WorkerStatus,
    circuit_state: CircuitState,
    pressure_state: crate::disk_pressure::PressureState,
    pressure_reason_code: &str,
    disabled_reason: Option<&str>,
) -> Option<Issue> {
    // --- Administrative axis: deliberate, durable, and it silences the rest. ---
    if status == WorkerStatus::Disabled {
        let reason = disabled_reason.unwrap_or("no reason recorded");
        return Some(Issue {
            severity: "warning".to_string(),
            summary: format!(
                "Worker '{worker_id}' is administratively disabled ({reason}); its slots are withheld, it is not polled for telemetry, and the disable is durable — restarting the daemon re-applies it"
            ),
            // Agents act on this line. An operator disable can protect a
            // production host, so name the condition, not just the command.
            remediation: Some(format!(
                "only once the recorded reason no longer applies (an operator decision): rch workers enable {worker_id}"
            )),
            worker_id: Some(worker_id.to_string()),
        });
    }
    if status == WorkerStatus::Drained {
        return Some(Issue {
            severity: "warning".to_string(),
            summary: format!(
                "Worker '{worker_id}' is drained; its slots are withheld and it is not polled for telemetry"
            ),
            remediation: Some(format!("rch workers enable {worker_id}")),
            worker_id: Some(worker_id.to_string()),
        });
    }

    // --- Eligibility axis. ---
    if circuit_state == CircuitState::Open {
        return Some(Issue {
            severity: "error".to_string(),
            summary: format!("Circuit open for worker '{worker_id}'"),
            remediation: Some(format!("rch workers probe {worker_id} --force")),
            worker_id: Some(worker_id.to_string()),
        });
    }
    if pressure_state == crate::disk_pressure::PressureState::Critical {
        return Some(Issue {
            severity: "error".to_string(),
            summary: format!(
                "Worker '{worker_id}' in critical pressure state ({pressure_reason_code})"
            ),
            remediation: Some(
                "rch workers capabilities --refresh (inspect pressure metrics and ballast policy)"
                    .to_string(),
            ),
            worker_id: Some(worker_id.to_string()),
        });
    }
    if pressure_state == crate::disk_pressure::PressureState::TelemetryGap {
        return Some(Issue {
            severity: "warning".to_string(),
            summary: format!(
                "Worker '{worker_id}' has stale/missing pressure telemetry ({pressure_reason_code})"
            ),
            // Telemetry ingest is daemon-driven: only the periodic
            // TelemetryPoller (or worker piggyback) calls
            // TelemetryStore::ingest(). No client-side `rch workers ...`
            // subcommand can move an ACTIVE worker out of TelemetryGap; emitting
            // one as a Fix would train agents to run confident-wrong
            // commands (issue #16). Workers whose telemetry is stale *because*
            // they are out of service are handled by the admin arms above.
            remediation: Some(
                "telemetry ingest is daemon-driven; wait for next poll (~poll-interval) or run `rch daemon restart` to force a fresh poll cycle"
                    .to_string(),
            ),
            worker_id: Some(worker_id.to_string()),
        });
    }
    if status == WorkerStatus::Unreachable {
        return Some(Issue {
            severity: "error".to_string(),
            summary: format!("Worker '{worker_id}' is unreachable"),
            remediation: Some(format!("rch workers probe {worker_id}")),
            worker_id: Some(worker_id.to_string()),
        });
    }
    if status == WorkerStatus::Degraded {
        return Some(Issue {
            severity: "warning".to_string(),
            summary: format!("Worker '{worker_id}' is degraded (slow response)"),
            remediation: None,
            worker_id: Some(worker_id.to_string()),
        });
    }

    None
}

/// Full daemon status — the socket `/status` body. Also served over TCP by the
/// tailnet API (`http_api::create_api_router`), so it is crate-visible.
pub(crate) async fn handle_status(ctx: &DaemonContext) -> Result<DaemonFullStatus> {
    let workers = ctx.pool.all_workers().await;

    // Current temporary-bypass records, persisted across daemon restarts. The
    // store file is the single source of truth; a missing/corrupt file yields an
    // empty store, so status never fails because of bypass state
    // (bd-session-history-remediation-ocv9i.1.2).
    let bypass_store = BypassRecordStore::load(default_bypass_record_path());

    let mut workers_healthy = 0;
    let mut slots_total = 0u32;
    let mut slots_available = 0u32;

    let mut worker_infos = Vec::with_capacity(workers.len());
    let mut issues = Vec::new();

    for worker in &workers {
        let status = worker.status().await;
        let (worker_id, host, user) = {
            let config = worker.config.read().await;
            (
                config.id.to_string(),
                config.host.clone(),
                config.user.clone(),
            )
        };
        let total_slots = worker.effective_total_slots().await;
        let used_slots = worker.used_slots();
        let available_slots = total_slots.saturating_sub(used_slots);
        let circuit_stats = worker.circuit_stats().await;
        let circuit_state = circuit_stats.state();
        let pressure = worker.pressure_assessment().await;
        let assignable_slots = if worker_accepts_new_builds(status, circuit_state, pressure.state) {
            available_slots
        } else {
            0
        };

        // Count healthy workers
        if status == WorkerStatus::Healthy {
            workers_healthy += 1;
        }

        slots_total = slots_total.saturating_add(total_slots);
        slots_available = slots_available.saturating_add(assignable_slots);

        // Build worker status info
        let status_str = match status {
            WorkerStatus::Healthy => "healthy",
            WorkerStatus::Degraded => "degraded",
            WorkerStatus::Unreachable => "unreachable",
            WorkerStatus::Draining => "draining",
            WorkerStatus::Drained => "drained",
            WorkerStatus::Disabled => "disabled",
        };

        let circuit_str = match circuit_state {
            CircuitState::Closed => "closed",
            CircuitState::Open => "open",
            CircuitState::HalfOpen => "half_open",
        };

        // Use default circuit config for recovery time calculation
        let circuit_config = CircuitBreakerConfig::default();
        let recovery_in_secs = circuit_stats.recovery_remaining_secs(&circuit_config);

        worker_infos.push(WorkerStatusInfo {
            id: worker_id.clone(),
            host,
            user,
            status: status_str.to_string(),
            circuit_state: circuit_str.to_string(),
            used_slots,
            total_slots,
            speed_score: worker.get_speed_score(),
            last_error: worker.last_error().await,
            consecutive_failures: circuit_stats.consecutive_failures(),
            recovery_in_secs,
            failure_history: circuit_stats.recent_results().to_vec(),
            pressure_state: pressure.state.to_string(),
            pressure_confidence: pressure.confidence.to_string(),
            pressure_reason_code: pressure.reason_code.clone(),
            pressure_policy_rule: pressure.policy_rule.clone(),
            pressure_disk_free_gb: pressure.disk_free_gb,
            pressure_disk_total_gb: pressure.disk_total_gb,
            pressure_disk_free_ratio: pressure.disk_free_ratio,
            pressure_build_disk_free_gb: pressure.build_disk_free_gb,
            pressure_build_disk_total_gb: pressure.build_disk_total_gb,
            pressure_disk_io_util_pct: pressure.disk_io_util_pct,
            pressure_memory_pressure: pressure.memory_pressure,
            pressure_telemetry_age_secs: pressure.telemetry_age_secs,
            pressure_telemetry_fresh: pressure.telemetry_fresh,
            bypass: bypass_store.get(&worker_id).cloned(),
        });

        // Generate issues based on worker state
        if let Some(issue) = worker_issue(
            &worker_id,
            status,
            circuit_state,
            pressure.state,
            &pressure.reason_code,
            worker.disabled_reason().await.as_deref(),
        ) {
            issues.push(issue);
        }
    }

    // Calculate uptime
    let uptime_secs = ctx.started_at.elapsed().as_secs();

    // Get started_at as ISO 8601 (approximation using current time - uptime)
    let started_at = {
        use std::time::{SystemTime, UNIX_EPOCH};
        // Use unwrap_or_default to handle edge case of system time before UNIX_EPOCH
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        // `saturating_sub` guards against a wall-clock jump backward (NTP
        // step) that would make `uptime_secs > now`. Plain subtraction
        // panics in debug and wraps in release, turning a harmless
        // displayed start time into a crash or a nonsensical date.
        let start = now.saturating_sub(uptime_secs);
        // Format as ISO 8601
        let dt = chrono::DateTime::from_timestamp(start as i64, 0).unwrap_or_else(chrono::Utc::now);
        dt.to_rfc3339()
    };

    // Get recent and active builds from history.
    let recent_builds = ctx.history.recent(20);
    issues.extend(cancellation_issues_from_recent_builds(&recent_builds));
    let active_builds = ctx.history.active_builds();
    issues.extend(active_build_issues_from_active_builds(&active_builds));
    let stats = ctx.history.stats();
    let test_stats = ctx.telemetry.test_run_stats().await;

    // Collect active alerts from the alert manager
    let alerts = ctx.alert_manager.active_alerts();

    // Update queue depth metric
    let queue_depth = ctx.history.queue_depth();
    if !cfg!(test) {
        metrics::set_build_queue_depth(queue_depth);
    }

    // Assemble the operator-facing remediation view from the live state above,
    // before `active_builds`/`worker_infos` are moved into the response.
    let remediation = build_remediation_view(
        &worker_infos,
        &active_builds,
        queue_depth,
        &alerts,
        Utc::now(),
    );

    Ok(DaemonFullStatus {
        daemon: DaemonStatusInfo {
            pid: ctx.pid,
            uptime_secs,
            version: ctx.version.to_string(),
            socket_path: ctx.socket_path.clone(),
            started_at,
            workers_total: workers.len(),
            workers_healthy,
            slots_total,
            slots_available,
        },
        admission: restart_admission_snapshot(ctx, false).await,
        workers: worker_infos,
        active_builds: active_builds
            .into_iter()
            .map(|b| ActiveBuild {
                id: b.id,
                project_id: b.project_id,
                worker_id: b.worker_id,
                command: b.command,
                started_at: b.started_at,
                last_heartbeat_at: b.last_heartbeat_at,
                heartbeat_age_secs: b.last_heartbeat_mono.elapsed().as_secs(),
                last_progress_at: b.last_progress_at,
                progress_age_secs: b.last_progress_mono.elapsed().as_secs(),
                heartbeat_phase: heartbeat_phase_to_str(&b.heartbeat_phase).to_string(),
                heartbeat_detail: b.heartbeat_detail,
                heartbeat_counter: b.heartbeat_counter,
                heartbeat_percent: b.heartbeat_percent,
                slots: b.slots,
                detector_hook_alive: b.detector_hook_alive,
                detector_heartbeat_stale: b.detector_heartbeat_stale,
                detector_progress_stale: b.detector_progress_stale,
                detector_confidence: b.detector_confidence,
                detector_build_age_secs: b.detector_build_age_secs,
                detector_slots_owned: b.detector_slots_owned,
                detector_last_evaluated_at: b.detector_last_evaluated_at,
            })
            .collect(),
        queued_builds: ctx
            .history
            .queued_builds()
            .into_iter()
            .enumerate()
            .map(|(i, b)| {
                let wait_secs = b.queued_at_mono.elapsed().as_secs();
                QueuedBuild {
                    id: b.id,
                    id_text: b.id.to_string(),
                    project_id: b.project_id,
                    command: b.command,
                    queued_at: b.queued_at,
                    position: i + 1,
                    slots_needed: b.slots_needed,
                    estimated_start: b.estimated_start,
                    wait_time: format_wait_time(wait_secs),
                }
            })
            .collect(),
        recent_builds,
        issues,
        alerts,
        stats,
        test_stats,
        saved_time: ctx.history.saved_time_stats(),
        remediation,
    })
}

// ============================================================================
// Repo Convergence Handlers (bd-vvmd.3.5)
// ============================================================================

/// Build remediation suggestions based on worker convergence state.
fn convergence_remediation(state: &crate::repo_convergence::WorkerConvergenceState) -> Vec<String> {
    use crate::repo_convergence::ConvergenceDriftState;

    let mut hints = Vec::new();
    match state.current_state {
        ConvergenceDriftState::Ready => {}
        ConvergenceDriftState::Drifting => {
            if !state.missing_repos.is_empty() {
                hints.push(format!(
                    "Missing {} repo(s): {}",
                    state.missing_repos.len(),
                    state.missing_repos.join(", ")
                ));
            }
            hints.push("Run convergence repair to sync missing repos.".into());
        }
        ConvergenceDriftState::Converging => {
            hints.push("Sync in progress — wait for completion.".into());
        }
        ConvergenceDriftState::Failed => {
            hints.push(format!(
                "Budget exhausted (attempts: {}, time: {}ms remaining).",
                state.attempt_budget_remaining, state.time_budget_remaining_ms
            ));
            hints.push("Reset worker state with a new repo set update or manual repair.".into());
        }
        ConvergenceDriftState::Stale => {
            hints.push("No recent status check — run status refresh.".into());
        }
    }
    hints
}

/// Convert a WorkerConvergenceState into a JSON-safe view with remediation.
fn build_convergence_worker_view(
    state: &crate::repo_convergence::WorkerConvergenceState,
) -> ConvergenceWorkerView {
    let drift_confidence = state.drift_confidence();

    ConvergenceWorkerView {
        worker_id: state.worker_id.clone(),
        drift_state: state.current_state.to_string(),
        drift_confidence,
        required_repos: state.required_repos.clone(),
        synced_repos: state.synced_repos.clone(),
        missing_repos: state.missing_repos.clone(),
        attempt_budget_remaining: state.attempt_budget_remaining,
        time_budget_remaining_ms: state.time_budget_remaining_ms,
        last_status_check_unix_ms: state.last_status_check_unix_ms,
        remediation: convergence_remediation(state),
    }
}

/// Handle GET /repo-convergence/status — full convergence dashboard.
///
/// `pub(crate)` because the tailnet API (`http_api.rs`) serves the same body
/// on `GET /repo-convergence/status`.
pub(crate) async fn handle_repo_convergence_status(
    ctx: &DaemonContext,
    worker_id: Option<&WorkerId>,
) -> ApiResponse<RepoConvergenceStatusResponse> {
    let svc = &ctx.repo_convergence;

    let workers: Vec<ConvergenceWorkerView> = if let Some(wid) = worker_id {
        match svc.get_worker_state(wid).await {
            Some(ws) => vec![build_convergence_worker_view(&ws)],
            None => {
                // Worker not tracked — return Stale view.
                vec![ConvergenceWorkerView {
                    worker_id: wid.as_str().to_string(),
                    drift_state: "stale".into(),
                    drift_confidence: 0.0,
                    required_repos: vec![],
                    synced_repos: vec![],
                    missing_repos: vec![],
                    attempt_budget_remaining: 3,
                    time_budget_remaining_ms: 120_000,
                    last_status_check_unix_ms: 0,
                    remediation: vec!["No convergence data — run status refresh.".into()],
                }]
            }
        }
    } else {
        let all = svc.get_all_worker_states().await;
        all.iter().map(build_convergence_worker_view).collect()
    };

    // Build summary counts.
    let mut summary = ConvergenceSummary {
        total_workers: workers.len(),
        ready: 0,
        drifting: 0,
        converging: 0,
        failed: 0,
        stale: 0,
    };
    for w in &workers {
        match w.drift_state.as_str() {
            "ready" => summary.ready += 1,
            "drifting" => summary.drifting += 1,
            "converging" => summary.converging += 1,
            "failed" => summary.failed += 1,
            _ => summary.stale += 1,
        }
    }

    let recent_outcomes = svc.get_recent_outcomes(20).await;

    let status = if summary.failed > 0 {
        "degraded"
    } else if summary.drifting > 0 || summary.converging > 0 {
        "converging"
    } else if summary.total_workers == 0 || summary.stale == summary.total_workers {
        "unknown"
    } else {
        "healthy"
    };

    ApiResponse::Ok(RepoConvergenceStatusResponse {
        status: status.into(),
        workers,
        recent_outcomes,
        summary,
    })
}

/// Handle GET /repo-convergence/dry-run — simulate what convergence would do.
async fn handle_repo_convergence_dry_run(
    ctx: &DaemonContext,
    worker_id: &WorkerId,
) -> ApiResponse<RepoConvergenceDryRunResponse> {
    use crate::repo_convergence::ConvergenceDriftState;

    let svc = &ctx.repo_convergence;
    let has_budget = svc.has_budget(worker_id).await;

    match svc.get_worker_state(worker_id).await {
        Some(ws) => {
            let (would_attempt, reason) = match ws.current_state {
                ConvergenceDriftState::Ready => (false, "Worker is already converged.".into()),
                ConvergenceDriftState::Drifting => {
                    if has_budget {
                        (true, "Would attempt sync for missing repos.".into())
                    } else {
                        (false, "Budget exhausted — cannot attempt sync.".into())
                    }
                }
                ConvergenceDriftState::Converging => (false, "Sync already in progress.".into()),
                ConvergenceDriftState::Failed => {
                    (false, "Budget exhausted — manual reset required.".into())
                }
                ConvergenceDriftState::Stale => {
                    (true, "Would attempt fresh status check and sync.".into())
                }
            };

            let remediation = convergence_remediation(&ws);

            ApiResponse::Ok(RepoConvergenceDryRunResponse {
                status: "ok".into(),
                worker_id: worker_id.as_str().to_string(),
                current_state: ws.current_state.to_string(),
                missing_repos: ws.missing_repos.clone(),
                has_budget,
                attempt_budget_remaining: ws.attempt_budget_remaining,
                time_budget_remaining_ms: ws.time_budget_remaining_ms,
                would_attempt,
                reason,
                remediation,
            })
        }
        None => ApiResponse::Ok(RepoConvergenceDryRunResponse {
            status: "ok".into(),
            worker_id: worker_id.as_str().to_string(),
            current_state: "stale".into(),
            missing_repos: vec![],
            has_budget: true,
            attempt_budget_remaining: 3,
            time_budget_remaining_ms: 120_000,
            would_attempt: true,
            reason: "No convergence data — would attempt fresh sync.".into(),
            remediation: vec!["No convergence data — run status refresh.".into()],
        }),
    }
}

/// Handle POST /repo-convergence/repair — trigger convergence repair for a worker.
///
/// Resets budget and marks the worker for re-convergence. Bypasses hysteresis
/// since this is a deliberate operator action. Does NOT invoke the actual
/// adapter (that happens in the background convergence loop); this just
/// unblocks the state machine so the next convergence cycle picks it up.
async fn handle_repo_convergence_repair(
    ctx: &DaemonContext,
    worker_id: &WorkerId,
) -> ApiResponse<RepoConvergenceRepairResponse> {
    let svc = &ctx.repo_convergence;

    match svc.repair_worker(worker_id).await {
        Some(previous_state) => {
            let new_state = svc.get_drift_state(worker_id).await;
            ApiResponse::Ok(RepoConvergenceRepairResponse {
                status: "ok".into(),
                worker_id: worker_id.as_str().to_string(),
                action: "reset_convergence".into(),
                previous_state: previous_state.to_string(),
                new_state: new_state.to_string(),
                message: format!(
                    "Worker convergence reset from {} to {}. Next convergence cycle will attempt sync.",
                    previous_state, new_state
                ),
            })
        }
        None => ApiResponse::Ok(RepoConvergenceRepairResponse {
            status: "noop".into(),
            worker_id: worker_id.as_str().to_string(),
            action: "none".into(),
            previous_state: "stale".into(),
            new_state: "stale".into(),
            message: "Worker not tracked — nothing to repair.".into(),
        }),
    }
}

#[cfg(test)]
#[allow(clippy::assertions_on_constants)]
mod tests {
    use super::*;
    use crate::disk_pressure::{PressureAssessment, PressureConfidence, PressureState};
    use crate::history::BuildHistory;
    use crate::selection::WorkerSelector;
    use crate::self_test::{SelfTestHistory, SelfTestService};
    use crate::telemetry::TelemetryStore;
    use crate::workers::{WorkerCapabilitiesInfo, WorkerPool, WorkerStateResponse};
    use crate::{
        benchmark_queue::BenchmarkQueue,
        benchmark_scheduler::{BenchmarkScheduler, BenchmarkTriggerHandle, SchedulerConfig},
        events::EventBus,
    };
    use chrono::Duration as ChronoDuration;
    use rch_common::test_guard;
    use rch_common::{
        BuildCancellationMetadata, BuildCancellationWorkerHealth, SelfTestConfig,
        WorkerCapabilities,
    };
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    fn make_test_context(pool: WorkerPool) -> DaemonContext {
        let history = Arc::new(SelfTestHistory::new(
            crate::self_test::DEFAULT_RUN_CAPACITY,
            crate::self_test::DEFAULT_RESULT_CAPACITY,
        ));
        let self_test = Arc::new(SelfTestService::new(
            pool.clone(),
            SelfTestConfig::default(),
            history,
        ));
        let alert_manager = Arc::new(crate::alerts::AlertManager::new(
            crate::alerts::AlertConfig::default(),
        ));
        let events = EventBus::new(16);
        let history = Arc::new(BuildHistory::new(100));
        let mut selector = WorkerSelector::new();
        selector.set_build_history(history.clone());
        DaemonContext {
            pool,
            worker_selector: Arc::new(selector),
            history,
            telemetry: Arc::new(TelemetryStore::new(Duration::from_secs(300), None)),
            benchmark_queue: Arc::new(BenchmarkQueue::new(ChronoDuration::minutes(5))),
            benchmark_trigger: make_test_benchmark_trigger(),
            repo_convergence: Arc::new(crate::repo_convergence::RepoConvergenceService::new(
                events.clone(),
            )),
            cancellation: Arc::new(crate::cancellation::CancellationOrchestrator::new(
                crate::cancellation::CancellationConfig::default(),
                events.clone(),
            )),
            events,
            self_test,
            alert_manager,
            started_at: Instant::now(),
            socket_path: "/tmp/test.sock".to_string(),
            version: "0.1.0",
            pid: 1234,
            queue_timeout_secs: 300,
            bypass_store: None,
            admin_disable_store: None,
            workers_config_path: None,
            admission_barrier: Arc::new(tokio::sync::RwLock::new(RestartAdmissionState::default())),
        }
    }

    fn make_test_benchmark_trigger() -> BenchmarkTriggerHandle {
        let pool = WorkerPool::new();
        let telemetry = Arc::new(TelemetryStore::new(Duration::from_secs(300), None));
        let (scheduler, handle) = BenchmarkScheduler::new(
            SchedulerConfig::default(),
            pool,
            telemetry,
            EventBus::new(16),
        );
        let scheduler = Arc::new(scheduler);
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(scheduler.run());
        }
        handle
    }

    fn replace_test_history(ctx: &mut DaemonContext, history: BuildHistory) {
        let history = Arc::new(history);
        Arc::make_mut(&mut ctx.worker_selector).set_build_history(Arc::clone(&history));
        ctx.history = history;
    }

    async fn set_test_build_disk(pool: &WorkerPool, worker_id: &str, free_gib: f64) {
        let worker = pool.get(&WorkerId::new(worker_id)).await.unwrap();
        let mut capabilities = worker.capabilities().await;
        capabilities.build_disk_free_gb = Some(free_gib);
        capabilities.build_disk_total_gb = Some(200.0);
        worker.set_capabilities(capabilities).await;
    }

    /// Interrupt the actual waiting handler only after its queue row is durable,
    /// then construct a fresh history manager exactly as daemon startup does.
    async fn queue_resume_fixture(
        queue_timeout_secs: u64,
    ) -> (
        tempfile::TempDir,
        DaemonContext,
        SelectionRequest,
        String,
        u64,
    ) {
        let hook_pid = crate::history::observable_test_process_id();
        assert!(
            crate::history::process_identity(hook_pid).is_some() && is_process_alive(hook_pid),
            "queue resume integration requires one PID namespace for procfs and kill(0): \
             getpid={}, procfs owner={hook_pid}; the live test owner must pass both unchanged production checks",
            std::process::id(),
        );
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("history.jsonl");
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("requested", 4)).await;
        set_test_build_disk(&pool, "requested", 100.0).await;
        assert!(
            pool.get(&WorkerId::new("requested"))
                .await
                .unwrap()
                .reserve_slots(4)
                .await
        );
        let mut ctx = make_test_context(pool);
        ctx.queue_timeout_secs = queue_timeout_secs;
        replace_test_history(
            &mut ctx,
            BuildHistory::new(10).with_persistence(path.clone()),
        );
        let request = SelectionRequest {
            project: "resume-project".into(),
            command: Some("cargo build".into()),
            command_priority: CommandPriority::Normal,
            estimated_cores: 2,
            disk_headroom_gib: 0,
            preferred_workers: vec![WorkerId::new("requested")],
            toolchain: None,
            required_runtime: RequiredRuntime::None,
            classification_duration_us: Some(9),
            job_mode: false,
            required_tools: vec![],
            hook_pid: Some(hook_pid),
        };
        let wrapper = format!("rchw-{}", Uuid::new_v4());
        let old_ctx = ctx.clone();
        let old_request = request.clone();
        let old_wrapper = wrapper.clone();
        let waiter = tokio::spawn(async move {
            handle_select_worker_with_wrapper(
                &old_ctx,
                old_request,
                true,
                Some(30),
                Some(old_wrapper),
            )
            .await
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            while ctx.history.queue_depth() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let queue_id = ctx.history.queued_builds()[0].id;
        waiter.abort();
        assert!(waiter.await.unwrap_err().is_cancelled());
        replace_test_history(&mut ctx, BuildHistory::load_from_file(&path, 10).unwrap());
        assert!(ctx.history.queued_build(queue_id).unwrap().recovered);
        (tmp, ctx, request, wrapper, queue_id)
    }

    #[tokio::test]
    async fn queue_resume_socket_route_continues_the_original_waiter_once() {
        let _guard = test_guard!();
        let (tmp, ctx, request, wrapper, queue_id) = queue_resume_fixture(300).await;
        let original = ctx.history.queued_build(queue_id).unwrap();
        let worker = ctx.pool.get(&WorkerId::new("requested")).await.unwrap();
        worker.release_slots(4).await;
        // An ordinary selection cannot consume a restored row even now that
        // slots are free. Only the distinct recovery route may do so.
        assert!(
            handle_select_worker_with_wrapper(
                &ctx,
                request.clone(),
                true,
                Some(30),
                Some(wrapper.clone())
            )
            .await
            .is_err()
        );
        assert_eq!(worker.available_slots().await, 4);
        let (mut client, server) = UnixStream::pair().unwrap();
        let (shutdown_tx, _) = tokio::sync::mpsc::channel(1);
        let connection = tokio::spawn(handle_connection(server, ctx.clone(), shutdown_tx));
        let line = format!(
            "GET /select-worker/resume-queued?project=resume-project&command=cargo%20build&cores=2&worker=requested&classification_us=9&hook_pid={}&local_wrapper_id={wrapper}&wait=1&wait_timeout_secs=30\n",
            crate::history::observable_test_process_id(),
        );
        client.write_all(line.as_bytes()).await.unwrap();
        let mut response = String::new();
        tokio::time::timeout(Duration::from_secs(2), client.read_to_string(&mut response))
            .await
            .unwrap()
            .unwrap();
        connection.await.unwrap().unwrap();
        assert!(response.starts_with("HTTP/1.0 200"), "{response}");
        let body: serde_json::Value =
            serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap();
        let build_id = body["build_id"].as_u64().unwrap();
        assert_eq!(body["worker"]["id"], "requested");
        assert_eq!(worker.available_slots().await, 2);
        assert_eq!(ctx.history.queue_depth(), 0);
        assert_eq!(ctx.history.active_builds().len(), 1);
        assert_eq!(
            ctx.history
                .active_build(build_id)
                .unwrap()
                .local_wrapper_id
                .as_deref(),
            Some(wrapper.as_str())
        );
        let restored = BuildHistory::load_from_file(&tmp.path().join("history.jsonl"), 10).unwrap();
        assert!(restored.queued_build(original.id).is_none());
        assert!(restored.active_build(build_id).is_some());
        // A lost resumed response cannot authorize another selection.
        assert!(
            handle_select_worker_mode(&ctx, request, true, Some(30), Some(wrapper), true)
                .await
                .is_err()
        );
        assert_eq!(worker.available_slots().await, 2);
    }

    #[tokio::test]
    async fn queue_resume_rejects_changed_selection_constraints_without_claiming() {
        let _guard = test_guard!();
        let (_tmp, ctx, request, wrapper, queue_id) = queue_resume_fixture(300).await;
        let worker = ctx.pool.get(&WorkerId::new("requested")).await.unwrap();
        worker.release_slots(4).await;
        let original = serde_json::to_value(&request).unwrap();
        for (field, value) in [
            ("project", serde_json::json!("different-project")),
            ("command", serde_json::json!("cargo test")),
            ("estimated_cores", serde_json::json!(1)),
            ("disk_headroom_gib", serde_json::json!(64)),
            ("command_priority", serde_json::json!("high")),
            ("preferred_workers", serde_json::json!(["alternate"])),
            (
                "toolchain",
                serde_json::json!({"channel":"nightly", "date":"2026-09-01", "full_version":"different compiler"}),
            ),
            ("required_runtime", serde_json::json!("rust")),
            ("job_mode", serde_json::json!(true)),
            ("required_tools", serde_json::json!(["git"])),
            ("classification_duration_us", serde_json::json!(10)),
            ("hook_pid", serde_json::json!(1)),
        ] {
            let mut changed = original.clone();
            changed[field] = value;
            let changed: SelectionRequest = serde_json::from_value(changed).unwrap();
            assert!(
                handle_select_worker_mode(
                    &ctx,
                    changed,
                    true,
                    Some(30),
                    Some(wrapper.clone()),
                    true
                )
                .await
                .is_err(),
                "accepted changed {field}"
            );
            assert!(ctx.history.queued_build(queue_id).unwrap().recovered);
            assert_eq!(worker.available_slots().await, 4);
        }
        for timeout in [None, Some(29), Some(31)] {
            assert!(
                handle_select_worker_mode(
                    &ctx,
                    request.clone(),
                    true,
                    timeout,
                    Some(wrapper.clone()),
                    true
                )
                .await
                .is_err()
            );
        }
        let response =
            handle_select_worker_mode(&ctx, request, true, Some(30), Some(wrapper), true)
                .await
                .unwrap();
        assert!(response.worker.is_some());
        assert_eq!(worker.available_slots().await, 2);
    }

    #[tokio::test]
    async fn queue_resume_expired_original_timeout_never_reserves_free_worker() {
        let _guard = test_guard!();
        let (tmp, mut ctx, request, wrapper, queue_id) = queue_resume_fixture(1).await;
        let ownership = tmp.path().join("history.ownership.json");
        let mut snapshot: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&ownership).unwrap()).unwrap();
        snapshot["queued"][0]["queued_at"] =
            serde_json::json!((Utc::now() - ChronoDuration::seconds(2)).to_rfc3339());
        std::fs::write(&ownership, serde_json::to_vec(&snapshot).unwrap()).unwrap();
        replace_test_history(
            &mut ctx,
            BuildHistory::load_from_file(&tmp.path().join("history.jsonl"), 10).unwrap(),
        );
        // Increasing daemon configuration cannot extend the persisted deadline.
        ctx.queue_timeout_secs = 600;
        let worker = ctx.pool.get(&WorkerId::new("requested")).await.unwrap();
        worker.release_slots(4).await;
        let response =
            handle_select_worker_mode(&ctx, request, true, Some(30), Some(wrapper), true)
                .await
                .unwrap();
        assert_eq!(
            response.reason,
            SelectionReason::SelectionError("queue_timeout".into())
        );
        assert!(response.worker.is_none());
        assert!(ctx.history.queued_build(queue_id).is_none());
        assert!(ctx.history.active_builds().is_empty());
        assert_eq!(worker.available_slots().await, 4);
        let restored = BuildHistory::load_from_file(&tmp.path().join("history.jsonl"), 10).unwrap();
        assert!(restored.queued_build(queue_id).is_none());
        assert!(restored.active_builds().is_empty());
    }

    #[tokio::test]
    async fn queue_resume_cancelled_owner_and_duplicate_waiter_never_select() {
        let _guard = test_guard!();
        let (_tmp, ctx, request, wrapper, queue_id) = queue_resume_fixture(300).await;
        let waiting_ctx = ctx.clone();
        let waiting_request = request.clone();
        let waiting_wrapper = wrapper.clone();
        let waiter = tokio::spawn(async move {
            handle_select_worker_mode(
                &waiting_ctx,
                waiting_request,
                true,
                Some(30),
                Some(waiting_wrapper),
                true,
            )
            .await
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            while ctx.history.queued_build(queue_id).unwrap().recovered {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(
            handle_select_worker_mode(
                &ctx,
                request.clone(),
                true,
                Some(30),
                Some(wrapper.clone()),
                true
            )
            .await
            .is_err()
        );
        assert!(matches!(
            ctx.history.cancel_wrapper(&wrapper).unwrap(),
            crate::history::WrapperCancellation::BeforeStart
        ));
        let response = tokio::time::timeout(Duration::from_secs(2), waiter)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(
            response.reason,
            SelectionReason::SelectionError("job_cancelled_before_start".into())
        );
        assert!(
            handle_select_worker_mode(&ctx, request, true, Some(30), Some(wrapper), true)
                .await
                .is_err()
        );
        assert!(ctx.history.active_builds().is_empty());
        assert_eq!(ctx.history.queue_depth(), 0);
        assert_eq!(
            ctx.pool
                .get(&WorkerId::new("requested"))
                .await
                .unwrap()
                .available_slots()
                .await,
            0
        );
    }

    #[test]
    fn queue_resume_route_requires_an_identified_waiter_and_never_aliases_selection() {
        let base = "GET /select-worker/resume-queued?project=p&wait=1&local_wrapper_id=rchw-owner&hook_pid=123";
        assert!(matches!(
            parse_request(base).unwrap(),
            ApiRequest::SelectWorker {
                resume_queued: true,
                ..
            }
        ));
        for line in [
            "GET /select-worker/resume-queued?project=p&local_wrapper_id=rchw-owner&hook_pid=123",
            "GET /select-worker/resume-queued?project=p&wait=1&hook_pid=123",
            "GET /select-worker/resume-queued?project=p&wait=1&local_wrapper_id=rchw-owner",
            "GET /select-worker/resume-queued-extra?project=p&wait=1&local_wrapper_id=rchw-owner&hook_pid=123",
        ] {
            assert!(parse_request(line).is_err(), "{line}");
        }
        assert!(parse_request(&format!("{base}&dry_run=1")).is_err());
    }

    #[test]
    fn verified_tools_routes_bind_requirements_to_selection_and_queue_recovery() {
        for (route, resume, budget) in [
            ("/select-verified-tools", false, 0),
            ("/select-verified-tools/resume-queued", true, 0),
            ("/select-verified-tools/disk-budget", false, 64),
            ("/select-verified-tools/resume-queued/disk-budget", true, 64),
        ] {
            let disk = if budget == 0 {
                String::new()
            } else {
                format!("&disk_headroom_gib={budget}")
            };
            let base = format!(
                "GET {route}?project=p&command=cargo%20xwin%20build&wait=1&local_wrapper_id=rchw-owner&hook_pid=123{disk}"
            );
            assert!(parse_request(&base).is_err(), "missing tools: {base}");
            let ApiRequest::SelectWorker {
                mut request,
                resume_queued,
                ..
            } = parse_request(&format!(
                "{base}&require_tool=cargo-xwin&require_tool=llvm-ar&require_tool=cargo-xwin"
            ))
            .expect("explicit verified tool requirements")
            else {
                panic!("expected selection")
            };
            assert_eq!(request.required_tools, vec!["cargo-xwin", "llvm-ar"]);
            assert_eq!(request.command.as_deref(), Some("cargo xwin build"));
            assert_eq!(request.disk_headroom_gib, budget);
            assert_eq!(resume_queued, resume);
            assert!(!request.job_mode);
            let constrained = queue_selection_digest(&request, Some(30)).unwrap();
            request.required_tools.pop();
            assert_ne!(
                constrained,
                queue_selection_digest(&request, Some(30)).unwrap()
            );
        }
        for line in [
            "GET /select-verified-tools-extra?project=p&require_tool=cargo-xwin",
            "GET /select-verified-tools?project=p&require_tool=&require_tool=%20",
            "GET /select-verified-tools?project=p&require_tool=cargo-xwin&disk_headroom_gib=64",
            "GET /select-verified-tools/disk-budget?project=p&require_tool=cargo-xwin",
            "GET /select-verified-tools/resume-queued?project=p&require_tool=cargo-xwin",
        ] {
            assert!(parse_request(line).is_err(), "accepted {line}");
        }
    }

    #[test]
    fn disk_headroom_routes_require_explicit_valid_budget_and_preserve_resume() {
        for (route, resume) in [
            ("/select-worker/disk-budget", false),
            ("/select-worker/resume-queued/disk-budget", true),
        ] {
            let line = format!(
                "GET {route}?project=p&disk_headroom_gib=64&wait=1&local_wrapper_id=rchw-owner&hook_pid=123"
            );
            let ApiRequest::SelectWorker {
                request,
                resume_queued,
                ..
            } = parse_request(&line).expect("budgeted selection")
            else {
                panic!("expected selection")
            };
            assert_eq!(request.disk_headroom_gib, 64);
            assert_eq!(resume_queued, resume);
        }
        for invalid in ["", "0", "-1", "1.5", "4294967296", "no"] {
            let line =
                format!("GET /select-worker/disk-budget?project=p&disk_headroom_gib={invalid}");
            assert!(parse_request(&line).is_err(), "accepted {line}");
        }
        for line in [
            "GET /select-worker/disk-budget?project=p",
            "GET /select-worker?project=p&disk_headroom_gib=64",
            "GET /select-worker/disk-budget?project=p&disk_headroom_gib=64&disk_headroom_gib=1",
            "GET /select-worker/disk-budget-extra?project=p&disk_headroom_gib=64",
            "GET /select-worker/resume-queued/disk-budget?project=p&disk_headroom_gib=64",
            "GET /select-worker/resume-queued?project=p&disk_headroom_gib=64&wait=1&local_wrapper_id=rchw-owner&hook_pid=123",
        ] {
            assert!(parse_request(line).is_err(), "accepted {line}");
        }
    }

    #[test]
    fn disk_headroom_is_bound_to_queue_identity_without_changing_legacy_requests() {
        let ApiRequest::SelectWorker { mut request, .. } =
            parse_request("GET /select-worker?project=p&cores=4").unwrap()
        else {
            panic!("expected selection")
        };
        let old = queue_selection_digest(&request, Some(30)).unwrap();
        assert_eq!(request.disk_headroom_gib, 0);
        let json = serde_json::to_value(&request).unwrap();
        assert!(json.get("disk_headroom_gib").is_none());
        let restored = serde_json::from_value(json).unwrap();
        assert_eq!(old, queue_selection_digest(&restored, Some(30)).unwrap());
        request.disk_headroom_gib = 64;
        let budgeted = queue_selection_digest(&request, Some(30)).unwrap();
        assert_ne!(old, budgeted);
        request.disk_headroom_gib = 63;
        assert_ne!(
            budgeted,
            queue_selection_digest(&request, Some(30)).unwrap()
        );
    }

    #[tokio::test]
    async fn disk_headroom_api_selects_capacity_and_releases_only_owned_budget() {
        let _guard = test_guard!();
        let tmp = tempfile::tempdir().unwrap();
        let history_path = tmp.path().join("history.jsonl");
        let pool = WorkerPool::new();
        for (id, free) in [("small", 51.0), ("large", 100.0)] {
            pool.add_worker(make_test_worker(id, 8)).await;
            pool.get(&WorkerId::new(id))
                .await
                .unwrap()
                .set_capabilities(WorkerCapabilities {
                    rustc_version: Some("1.97.0-nightly".into()),
                    projects_root_ok: Some(true),
                    disk_free_gb: Some(free),
                    disk_total_gb: Some(200.0),
                    build_disk_free_gb: Some(free),
                    build_disk_total_gb: Some(200.0),
                    ..Default::default()
                })
                .await;
        }
        let mut ctx = make_test_context(pool);
        replace_test_history(
            &mut ctx,
            BuildHistory::new(100).with_persistence(history_path.clone()),
        );
        ctx.worker_selector = Arc::new(crate::daemon_worker_selector(
            &rch_common::RchConfig::default(),
            Arc::clone(&ctx.history),
            None,
        ));
        let ApiRequest::SelectWorker { request, .. } = parse_request(
            "GET /select-worker/disk-budget?project=large-build&command=cargo%20test&cores=1&disk_headroom_gib=64&runtime=none"
        ).unwrap() else { panic!("expected selection") };
        let preview = handle_select_worker_dry_run(&ctx, &request).await;
        assert_eq!(
            preview.worker.as_ref().map(|worker| worker.id.as_str()),
            Some("large")
        );
        assert!(preview.build_id.is_none());
        assert_eq!(ctx.history.reserved_disk_headroom_gib("large"), 0);

        let response = handle_select_worker_with_wrapper(
            &ctx,
            request.clone(),
            false,
            None,
            Some("rchw-disk-owner".into()),
        )
        .await
        .unwrap();
        assert_eq!(response.worker.unwrap().id.as_str(), "large");
        let build_id = response.build_id.unwrap();
        assert_eq!(ctx.history.reserved_disk_headroom_gib("large"), 64);
        assert_eq!(ctx.history.reserved_disk_headroom_gib("small"), 0);
        let restored = BuildHistory::load_from_file(&history_path, 100).unwrap();
        assert_eq!(restored.reserved_disk_headroom_gib("large"), 64);

        let mut second = request.clone();
        second.project = "another-large-build".into();
        let refused = handle_select_worker_with_wrapper(
            &ctx,
            second.clone(),
            false,
            None,
            Some("rchw-second-disk-owner".into()),
        )
        .await
        .unwrap();
        assert!(refused.worker.is_none());
        assert!(
            refused.reason.to_string().contains("disk_headroom"),
            "{:?}",
            refused.reason
        );
        assert_eq!(ctx.history.active_builds().len(), 1);
        let worker = ctx.pool.get(&WorkerId::new("large")).await.unwrap();
        assert_eq!(worker.used_slots(), 1);

        let release = |owner: &str| ReleaseRequest {
            disk_peak_output_bytes: None,
            local_wrapper_id: Some(owner.into()),
            worker_id: WorkerId::new("large"),
            slots: 99,
            build_id: Some(build_id),
            exit_code: Some(0),
            duration_ms: None,
            bytes_transferred: None,
            timing: None,
            worker_fault: false,
            worker_disk_full: false,
            worker_live_checkout_refused: false,
            worker_source_busy: false,
            worker_disk_roots: Vec::new(),
        };
        assert!(
            handle_release_worker(&ctx, release("rchw-wrong-owner"))
                .await
                .is_err()
        );
        assert_eq!(ctx.history.reserved_disk_headroom_gib("large"), 64);
        assert_eq!(worker.used_slots(), 1);
        handle_release_worker(&ctx, release("rchw-disk-owner"))
            .await
            .unwrap();
        assert_eq!(ctx.history.reserved_disk_headroom_gib("large"), 0);
        assert_eq!(worker.used_slots(), 0);
        let stale = handle_select_worker_with_wrapper(
            &ctx,
            second.clone(),
            false,
            None,
            Some("rchw-second-disk-owner".into()),
        )
        .await
        .unwrap();
        assert!(stale.worker.is_none());
        assert!(stale.build_id.is_none());
        let diagnostic = stale
            .diagnostics
            .unwrap()
            .workers
            .into_iter()
            .find(|entry| entry.worker_id.as_str() == "large")
            .unwrap();
        assert!(
            diagnostic
                .reason_codes
                .iter()
                .any(|reason| reason == "disk_headroom_stale")
        );
        assert!(ctx.history.active_builds().is_empty());
        assert_eq!(worker.used_slots(), 0);
        // Only a capacity probe started after completion can fund the next
        // reservation. Keep the old positive and duplicate-release checks.
        let refreshed = worker.capabilities().await;
        worker.set_capabilities(refreshed).await;
        let next = handle_select_worker_with_wrapper(
            &ctx,
            second,
            false,
            None,
            Some("rchw-second-disk-owner".into()),
        )
        .await
        .unwrap();
        assert_eq!(next.worker.unwrap().id.as_str(), "large");
        assert_eq!(ctx.history.reserved_disk_headroom_gib("large"), 64);
        handle_release_worker(&ctx, release("rchw-disk-owner"))
            .await
            .unwrap();
        assert_eq!(
            ctx.history.reserved_disk_headroom_gib("large"),
            64,
            "duplicate completion must not release the new build's budget"
        );
        assert_eq!(worker.used_slots(), 1);
    }

    #[tokio::test]
    async fn automatic_disk_budget_api_relocates_reported_21_gib_test_and_admits_small_control() {
        let _guard = test_guard!();
        let directory = tempfile::tempdir().unwrap().keep();
        let history_path = directory.join("history.jsonl");
        let pool = WorkerPool::new();
        for (id, free_gib) in [("hz3", 33.0), ("spare", 100.0)] {
            pool.add_worker(make_test_worker(id, 8)).await;
            set_test_build_disk(&pool, id, free_gib).await;
        }
        let mut ctx = make_test_context(pool);
        replace_test_history(
            &mut ctx,
            BuildHistory::new(100).with_persistence(history_path.clone()),
        );
        let gib = rch_common::BuildDiskBudget::GIB;

        // Feed attributed measurements through admitted, owner-checked API
        // completions. The reported failed 21 GiB build stays a lower bound;
        // it must never be treated as evidence of a successful small build.
        for (project, peak_gib, exit_code) in [("frankennumpy", 21, 101), ("small-control", 2, 0)] {
            set_test_build_disk(&ctx.pool, "spare", 100.0).await;
            let ApiRequest::SelectWorker { request, .. } = parse_request(&format!(
                "GET /select-worker?project={project}&command=cargo%20test%20--workspace&cores=1&worker=spare&runtime=none",
            ))
            .unwrap() else {
                panic!("expected ordinary selection request")
            };
            assert_eq!(request.disk_headroom_gib, 0);
            let owner = format!("rchw-measured-{project}");
            let response =
                handle_select_worker_with_wrapper(&ctx, request, false, None, Some(owner.clone()))
                    .await
                    .unwrap();
            let selected = response.worker.expect("cold build fits the spare worker");
            assert_eq!(selected.id.as_str(), "spare");
            let budget = selected.disk_budget.expect("automatic command budget");
            assert_eq!(budget.max_growth_bytes, 40 * gib);
            let build_id = response.build_id.unwrap();
            assert_eq!(ctx.history.reserved_disk_headroom_gib("spare"), 40);
            let heartbeat = handle_build_heartbeat(
                &ctx,
                BuildHeartbeatRequest {
                    build_id,
                    worker_id: WorkerId::new("spare"),
                    hook_pid: None,
                    local_wrapper_id: Some(owner.clone()),
                    remote_pgid_file: None,
                    phase: rch_common::BuildHeartbeatPhase::Execute,
                    detail: None,
                    progress_counter: Some(1),
                    progress_percent: None,
                },
            )
            .await;
            assert_eq!(heartbeat.status, "ok");

            let ApiRequest::ReleaseWorker(receipt) = parse_request(&format!(
                "POST /release-worker?worker=spare&build_id={build_id}&local_wrapper_id={owner}&exit_code={exit_code}&disk_peak_output_bytes={}",
                peak_gib * gib,
            ))
            .unwrap() else {
                panic!("expected measured release receipt")
            };
            let mut wrong_owner = receipt.clone();
            wrong_owner.local_wrapper_id = Some("rchw-other-owner".into());
            assert!(handle_release_worker(&ctx, wrong_owner).await.is_err());
            assert_eq!(
                ctx.history
                    .learned_footprint_gib(project, "cargo test --workspace"),
                None,
            );
            assert_eq!(ctx.history.reserved_disk_headroom_gib("spare"), 40);
            handle_release_worker(&ctx, receipt).await.unwrap();
            assert_eq!(ctx.history.reserved_disk_headroom_gib("spare"), 0);
            assert_eq!(
                ctx.history
                    .terminal_build(build_id, &owner)
                    .unwrap()
                    .exit_code,
                exit_code,
            );
        }

        // Startup must bind placement and admission to the same persisted
        // measurements, including the failed build's conservative cold floor.
        replace_test_history(
            &mut ctx,
            BuildHistory::load_from_file(&history_path, 100).unwrap(),
        );
        assert_eq!(
            ctx.history
                .learned_footprint_gib("frankennumpy", "cargo test --workspace"),
            Some(32.0),
        );
        assert_eq!(
            ctx.history
                .learned_footprint_gib("small-control", "cargo test --workspace"),
            Some(2.0),
        );
        for (id, free_gib) in [("hz3", 33.0), ("spare", 100.0)] {
            set_test_build_disk(&ctx.pool, id, free_gib).await;
        }
        let ApiRequest::SelectWorker { request, .. } = parse_request(
            "GET /select-worker?project=frankennumpy&command=cargo%20test%20--workspace&cores=1&runtime=none",
        )
        .unwrap() else {
            panic!("expected automatic admission request")
        };
        let preview = handle_select_worker_dry_run(&ctx, &request).await;
        let preview_worker = preview.worker.expect("preview finds the safe spare");
        assert_eq!(preview_worker.id.as_str(), "spare");
        let expected_budget = preview_worker.disk_budget.unwrap();
        assert_eq!(expected_budget.max_growth_bytes, 40 * gib);
        assert_eq!(expected_budget.min_free_bytes, 10 * gib);
        assert!(preview.build_id.is_none());
        assert!(ctx.history.active_builds().is_empty());

        let mut forced = request.clone();
        forced.preferred_workers = vec![WorkerId::new("hz3")];
        let refused = handle_select_worker_with_wrapper(
            &ctx,
            forced,
            false,
            None,
            Some("rchw-forced-incident-retry".into()),
        )
        .await
        .unwrap();
        assert!(refused.worker.is_none());
        assert!(refused.build_id.is_none());
        assert!(refused.diagnostics.unwrap().workers.iter().any(|worker| {
            worker.worker_id.as_str() == "hz3"
                && worker
                    .reason_codes
                    .iter()
                    .any(|code| code.starts_with("disk_headroom"))
        }),);
        assert_eq!(ctx.history.reserved_disk_headroom_gib("hz3"), 0);

        let relocated = handle_select_worker_with_wrapper(
            &ctx,
            request.clone(),
            false,
            None,
            Some("rchw-safe-incident-retry".into()),
        )
        .await
        .unwrap();
        let selected = relocated.worker.unwrap();
        assert_eq!(selected.id.as_str(), "spare");
        assert_eq!(selected.disk_budget, Some(expected_budget));
        let active = ctx
            .history
            .active_build(relocated.build_id.unwrap())
            .unwrap();
        assert_eq!(active.disk_headroom_gib, 40);
        assert_eq!(active.disk_floor_gib, 10);

        let mut small = request;
        small.project = "small-control".into();
        small.preferred_workers = vec![WorkerId::new("hz3")];
        let admitted = handle_select_worker_with_wrapper(
            &ctx,
            small,
            false,
            None,
            Some("rchw-small-control".into()),
        )
        .await
        .unwrap();
        let selected = admitted.worker.expect("measured small build fits hz3");
        assert_eq!(selected.id.as_str(), "hz3");
        assert_eq!(selected.disk_budget.unwrap().max_growth_bytes, 4 * gib);
        assert_eq!(ctx.history.reserved_disk_headroom_gib("hz3"), 4);
        assert_eq!(ctx.history.reserved_disk_headroom_gib("spare"), 40);
        assert_eq!(ctx.history.active_builds().len(), 2);
    }

    #[test]
    fn test_parse_request_basic() {
        let _guard = test_guard!();
        let req = parse_request("GET /select-worker?project=myproject&cores=4").unwrap();
        assert!(matches!(req, ApiRequest::SelectWorker { .. }));
        let ApiRequest::SelectWorker { request: req, .. } = req else {
            return;
        };
        assert_eq!(req.project, "myproject");
        assert_eq!(req.estimated_cores, 4);
    }

    #[test]
    fn test_parse_request_project_only() {
        let _guard = test_guard!();
        let req = parse_request("GET /select-worker?project=test").unwrap();
        let ApiRequest::SelectWorker { request: req, .. } = req else {
            assert!(false, "expected select-worker request");
            return;
        };
        assert_eq!(req.project, "test");
        assert_eq!(req.estimated_cores, 1); // Default
    }

    #[test]
    fn test_parse_request_dry_run_flag() {
        let _guard = test_guard!();
        for (line, expected) in [
            ("GET /select-worker?project=p&cores=2&dry_run=1", true),
            ("GET /select-worker?project=p&cores=2&dry_run=true", true),
            ("GET /select-worker?project=p&cores=2&dry_run=0", false),
            ("GET /select-worker?project=p&cores=2", false),
        ] {
            let ApiRequest::SelectWorker { dry_run, .. } = parse_request(line).unwrap() else {
                panic!("expected select-worker request for {line}");
            };
            assert_eq!(dry_run, expected, "{line}");
        }
    }

    /// `rch diagnose` must be able to ask which worker a build would get
    /// without reserving slots or opening a durable build it cannot release.
    #[tokio::test]
    async fn test_dry_run_selection_reserves_nothing() {
        let _guard = test_guard!();
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("dry-worker", 8)).await;
        set_test_build_disk(&pool, "dry-worker", 100.0).await;
        let worker = pool.get(&WorkerId::new("dry-worker")).await.unwrap();
        let ctx = make_test_context(pool);
        let request = SelectionRequest {
            job_mode: false,
            project: "dry-run-project".to_string(),
            command: Some("cargo build".to_string()),
            command_priority: CommandPriority::Normal,
            estimated_cores: 4,
            disk_headroom_gib: 0,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::None,
            classification_duration_us: None,
            required_tools: Vec::new(),
            hook_pid: None,
        };
        let response = handle_select_worker_dry_run(&ctx, &request).await;
        let selected = response.worker.expect("dry run should report a worker");
        assert_eq!(selected.id.as_str(), "dry-worker");
        assert_eq!(selected.slots_available, 8);
        assert!(response.build_id.is_none());
        assert_eq!(worker.used_slots(), 0);
        assert!(
            ctx.history
                .active_workers_for_project("dry-run-project")
                .is_empty()
        );
    }

    /// GH #125: the dry run behind `rch diagnose` reports every configured
    /// worker's decision even when it selects one, names a project
    /// exclusion's actual cause, and marks workers outside a requested set.
    #[tokio::test]
    async fn dry_run_selection_inventories_every_worker_with_its_reason() {
        use rch_common::WorkerSelectionDiagnosticDecision as Decision;
        let _guard = test_guard!();
        let pool = WorkerPool::new();
        for id in ["chosen", "busy", "fenced"] {
            pool.add_worker(make_test_worker(id, 8)).await;
            set_test_build_disk(&pool, id, 100.0).await;
        }
        let busy = pool.get(&WorkerId::new("busy")).await.unwrap();
        assert!(busy.reserve_slots(6).await);
        let ctx = make_test_context(pool);
        ctx.history
            .fence_live_checkout("inventory-project", "fenced");
        let mut request = SelectionRequest {
            job_mode: false,
            project: "inventory-project".to_string(),
            command: Some("cargo build".to_string()),
            command_priority: CommandPriority::Normal,
            estimated_cores: 4,
            disk_headroom_gib: 0,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::None,
            classification_duration_us: None,
            required_tools: Vec::new(),
            hook_pid: None,
        };
        let entry = |response: &SelectionResponse, id: &str| {
            response
                .diagnostics
                .as_ref()
                .expect("a dry run always reports per-worker diagnostics")
                .workers
                .iter()
                .find(|worker| worker.worker_id.as_str() == id)
                .unwrap_or_else(|| panic!("no diagnostic for {id}"))
                .clone()
        };

        let response = handle_select_worker_dry_run(&ctx, &request).await;
        assert_eq!(response.worker.as_ref().unwrap().id.as_str(), "chosen");
        assert_eq!(response.diagnostics.as_ref().unwrap().workers.len(), 3);
        let chosen = entry(&response, "chosen");
        assert_eq!(chosen.final_decision, Decision::Allow, "{chosen:?}");
        let busy_entry = entry(&response, "busy");
        assert_eq!(busy_entry.final_decision, Decision::Deny);
        assert_eq!(busy_entry.reason_codes, vec!["slots.insufficient"]);
        let fenced = entry(&response, "fenced");
        assert_eq!(fenced.final_decision, Decision::Deny);
        assert!(fenced.active_project_excluded);
        assert_eq!(
            fenced.reason_codes,
            vec!["active_project_exclusion", "project.live_checkout_fenced"]
        );
        assert_eq!(fenced.final_reason, ProjectExclusion::LiveCheckout.reason());
        // A preview reserves nothing, and the plain preview other callers use
        // still attaches diagnostics only to a failed selection.
        assert_eq!(busy.used_slots(), 6);
        assert!(ctx.history.active_builds().is_empty());
        let plain = ctx
            .worker_selector
            .preview_with_exclusions(&ctx.pool, &request, &std::collections::HashSet::new())
            .await;
        assert!(plain.worker.is_some() && plain.diagnostics.is_none());

        request.preferred_workers = vec![WorkerId::new("chosen")];
        let response = handle_select_worker_dry_run(&ctx, &request).await;
        assert_eq!(response.worker.as_ref().unwrap().id.as_str(), "chosen");
        assert_eq!(entry(&response, "chosen").final_decision, Decision::Allow);
        for id in ["busy", "fenced"] {
            let other = entry(&response, id);
            assert_eq!(other.final_decision, Decision::Deny, "{id}");
            assert_eq!(other.reason_codes, vec!["selection.not_requested"], "{id}");
            assert_eq!(
                other.final_reason, "not in the requested worker set",
                "{id}"
            );
        }
    }

    #[test]
    fn test_parse_request_zero_cores_defaults_to_one() {
        let _guard = test_guard!();
        let req = parse_request("GET /select-worker?project=test&cores=0").unwrap();
        let ApiRequest::SelectWorker { request: req, .. } = req else {
            assert!(false, "expected select-worker request");
            return;
        };
        assert_eq!(req.estimated_cores, 1);
    }

    #[test]
    fn test_parse_request_with_spaces() {
        let _guard = test_guard!();
        let req = parse_request("GET /select-worker?project=my%20project&cores=2").unwrap();
        let ApiRequest::SelectWorker { request: req, .. } = req else {
            assert!(false, "expected select-worker request");
            return;
        };
        assert_eq!(req.project, "my project");
        assert_eq!(req.estimated_cores, 2);
    }

    #[test]
    fn test_parse_request_carries_valid_local_wrapper_id_separately_from_command() {
        let _guard = test_guard!();
        let request = parse_request(
            "GET /select-worker?project=test&command=cargo%20build&local_wrapper_id=rchw-lease-1",
        )
        .unwrap();
        let ApiRequest::SelectWorker {
            request,
            local_wrapper_id,
            ..
        } = request
        else {
            panic!("expected select-worker request");
        };
        assert_eq!(request.command.as_deref(), Some("cargo build"));
        assert_eq!(local_wrapper_id.as_deref(), Some("rchw-lease-1"));
    }

    #[test]
    fn test_parse_request_with_priority_hint() {
        let _guard = test_guard!();
        let req = parse_request("GET /select-worker?project=test&cores=2&priority=high").unwrap();
        let ApiRequest::SelectWorker { request: req, .. } = req else {
            assert!(false, "expected select-worker request");
            return;
        };
        assert_eq!(req.command_priority, rch_common::CommandPriority::High);
    }

    #[test]
    fn test_parse_request_with_preferred_workers() {
        let _guard = test_guard!();
        let req = parse_request(
            "GET /select-worker?project=test&worker=ts2&workers=vmi1%2Cvmi2&preferred=fast",
        )
        .unwrap();
        assert!(matches!(req, ApiRequest::SelectWorker { .. }));
        let ApiRequest::SelectWorker { request: req, .. } = req else {
            return;
        };
        let ids: Vec<&str> = req
            .preferred_workers
            .iter()
            .map(|worker| worker.as_str())
            .collect();
        assert_eq!(ids, vec!["ts2", "vmi1", "vmi2", "fast"]);
    }

    #[test]
    fn test_parse_request_invalid_priority_defaults_to_normal() {
        let _guard = test_guard!();
        let req = parse_request("GET /select-worker?project=test&cores=2&priority=urgent").unwrap();
        let ApiRequest::SelectWorker { request: req, .. } = req else {
            assert!(false, "expected select-worker request");
            return;
        };
        assert_eq!(req.command_priority, rch_common::CommandPriority::Normal);
    }

    #[test]
    fn test_parse_request_status() {
        let _guard = test_guard!();
        let req = parse_request("GET /status").unwrap();
        assert!(matches!(req, ApiRequest::Status), "expected status request");
    }

    #[test]
    fn test_parse_request_test_run() {
        let _guard = test_guard!();
        let req = parse_request("POST /test-run").unwrap();
        assert!(
            matches!(req, ApiRequest::TestRun),
            "expected test run request"
        );
    }

    #[test]
    fn test_parse_request_build_heartbeat() {
        let _guard = test_guard!();
        let req = parse_request("POST /build-heartbeat").unwrap();
        assert!(
            matches!(req, ApiRequest::BuildHeartbeat),
            "expected build-heartbeat request"
        );
    }

    #[test]
    fn test_parse_request_speedscore() {
        let _guard = test_guard!();
        let req = parse_request("GET /speedscore/css").unwrap();
        match req {
            ApiRequest::SpeedScore { worker_id } => {
                assert_eq!(worker_id.as_str(), "css");
            }
            _ => assert!(false, "expected speedscore request"),
        }
    }

    #[test]
    fn test_parse_request_speedscore_history() {
        let _guard = test_guard!();
        let req = parse_request("GET /speedscore/css/history?days=7&limit=25&offset=5").unwrap();
        match req {
            ApiRequest::SpeedScoreHistory {
                worker_id,
                days,
                limit,
                offset,
            } => {
                assert_eq!(worker_id.as_str(), "css");
                assert_eq!(days, 7);
                assert_eq!(limit, 25);
                assert_eq!(offset, 5);
            }
            _ => assert!(false, "expected speedscore history request"),
        }
    }

    #[test]
    fn test_parse_request_speedscores() {
        let _guard = test_guard!();
        let req = parse_request("GET /speedscores").unwrap();
        assert!(
            matches!(req, ApiRequest::SpeedScores),
            "expected speedscores request"
        );
    }

    #[test]
    fn test_parse_request_workers_capabilities() {
        let _guard = test_guard!();
        let req = parse_request("GET /workers/capabilities").unwrap();
        match req {
            ApiRequest::WorkersCapabilities { refresh } => {
                assert!(!refresh);
            }
            _ => assert!(false, "expected workers capabilities request"),
        }

        let req = parse_request("GET /workers/capabilities?refresh=true").unwrap();
        match req {
            ApiRequest::WorkersCapabilities { refresh } => {
                assert!(refresh);
            }
            _ => assert!(false, "expected workers capabilities request"),
        }
    }

    #[test]
    fn test_parse_request_benchmark_trigger() {
        let _guard = test_guard!();
        let req = parse_request("POST /benchmark/trigger/css").unwrap();
        match req {
            ApiRequest::BenchmarkTrigger { worker_id } => {
                assert_eq!(worker_id.as_str(), "css");
            }
            _ => assert!(false, "expected benchmark trigger request"),
        }

        let req = parse_request("POST /benchmark/trigger?worker=css").unwrap();
        match req {
            ApiRequest::BenchmarkTrigger { worker_id } => {
                assert_eq!(worker_id.as_str(), "css");
            }
            _ => assert!(false, "expected benchmark trigger query request"),
        }
    }

    #[test]
    fn test_parse_request_events() {
        let _guard = test_guard!();
        let req = parse_request("GET /events").unwrap();
        assert!(matches!(req, ApiRequest::Events), "expected events request");
    }

    #[tokio::test]
    async fn socket_request_duration_records_real_responses_and_errors() {
        use prometheus::Encoder;

        let _guard = test_guard!();
        let registry = prometheus::Registry::new();
        let observations = rch_telemetry::metrics::Metrics::new().expect("metrics");
        observations.register(&registry).expect("register metrics");
        let histogram = observations
            .request_duration_seconds
            .with_label_values(&["rchd_api"]);

        for request in ["GET /health\n", "GET /unknown-endpoint\n"] {
            let (mut client, server) = UnixStream::pair().expect("socket pair");
            let (shutdown_tx, _shutdown_rx) = tokio::sync::mpsc::channel(1);
            let task = tokio::spawn(handle_connection_with_metrics(
                server,
                make_test_context(WorkerPool::new()),
                shutdown_tx,
                Some(observations.clone()),
            ));
            client.write_all(request.as_bytes()).await.expect("request");
            let mut response = String::new();
            tokio::time::timeout(Duration::from_secs(2), client.read_to_string(&mut response))
                .await
                .expect("response deadline")
                .expect("response bytes");
            let result = task.await.expect("join handler");
            if request.contains("/health") {
                result.expect("write health response");
                assert!(response.starts_with("HTTP/1.0"), "{response}");
                let body = response.split_once("\r\n\r\n").expect("HTTP body").1;
                let body: serde_json::Value = serde_json::from_str(body).expect("JSON response");
                assert!(body.get("status").is_some(), "{body}");
            } else {
                let error = result.expect_err("unknown route returns early");
                assert!(error.to_string().contains("Unknown endpoint"), "{error}");
                assert!(response.is_empty(), "no response was written: {response}");
            }
        }
        assert_eq!(histogram.get_sample_count(), 2);
        let mut text = Vec::new();
        prometheus::TextEncoder::new()
            .encode(&registry.gather(), &mut text)
            .expect("encode registered collector");
        assert!(
            String::from_utf8(text)
                .unwrap()
                .contains("rch_request_duration_seconds_count{entrypoint=\"rchd_api\"} 2\n")
        );
    }

    #[tokio::test]
    async fn socket_request_duration_observes_cancellation_but_excludes_event_streams() {
        let _guard = test_guard!();
        let observations = rch_telemetry::metrics::Metrics::new().expect("metrics");
        let histogram = observations
            .request_duration_seconds
            .with_label_values(&["rchd_api"]);
        let (mut client, server) = UnixStream::pair().expect("socket pair");
        let (shutdown_tx, _shutdown_rx) = tokio::sync::mpsc::channel(1);
        client
            .write_all(b"POST /build-heartbeat\n")
            .await
            .expect("request without body");
        let request = handle_connection_with_metrics(
            server,
            make_test_context(WorkerPool::new()),
            shutdown_tx,
            Some(observations.clone()),
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(20), request)
                .await
                .is_err(),
            "cancel the handler while it waits for the heartbeat body"
        );
        assert_eq!(histogram.get_sample_count(), 1, "cancelled finite request");

        let (mut client, server) = UnixStream::pair().expect("socket pair");
        let (shutdown_tx, _shutdown_rx) = tokio::sync::mpsc::channel(1);
        let task = tokio::spawn(handle_connection_with_metrics(
            server,
            make_test_context(WorkerPool::new()),
            shutdown_tx,
            Some(observations),
        ));
        client.write_all(b"GET /events\n").await.expect("subscribe");
        let mut reader = BufReader::new(client);
        let mut header = String::new();
        tokio::time::timeout(Duration::from_secs(2), reader.read_line(&mut header))
            .await
            .expect("stream header deadline")
            .expect("stream header");
        assert_eq!(header, "HTTP/1.0 200 OK\r\n");
        task.abort();
        assert!(task.await.expect_err("stream cancelled").is_cancelled());
        assert_eq!(histogram.get_sample_count(), 1, "stream lifetime excluded");
    }

    /// Regression for bd-xqg58: the socket `reload` must read the file the
    /// daemon was launched with (`--workers-config`), not whatever the
    /// default config-dir resolution picks at reload time. On macOS those
    /// can be two different files, and edits to the running one were
    /// silently ignored.
    #[tokio::test]
    async fn test_reload_uses_launch_time_workers_config_path() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let _guard = test_guard!();
        let dir = tempfile::tempdir().expect("tempdir");
        let workers_path = dir.path().join("launch-workers.toml");
        std::fs::write(
            &workers_path,
            "[[workers]]\nid = \"reload-launch-path-w1\"\nhost = \"127.0.0.1\"\ntotal_slots = 2\n",
        )
        .expect("write workers.toml");

        let pool = WorkerPool::new();
        let mut ctx = make_test_context(pool.clone());
        ctx.workers_config_path = Some(workers_path);

        let (client, server) = tokio::net::UnixStream::pair().expect("socket pair");
        let (shutdown_tx, _shutdown_rx) = tokio::sync::mpsc::channel(1);
        let server_task = tokio::spawn(handle_connection(server, ctx, shutdown_tx));

        let (mut reader, mut writer) = client.into_split();
        writer
            .write_all(b"POST /reload\n")
            .await
            .expect("send reload");
        let mut raw = String::new();
        reader
            .read_to_string(&mut raw)
            .await
            .expect("read response");
        server_task.await.expect("join").expect("handle_connection");

        // Replies are framed as HTTP/1.0: status line, headers, blank line, body.
        let body = raw
            .split_once("\r\n\r\n")
            .map(|(_, body)| body)
            .unwrap_or(&raw);
        let response: serde_json::Value =
            serde_json::from_str(body.trim()).expect("reload response body is JSON");
        assert_eq!(response["success"], true, "response: {response}");
        assert_eq!(response["added"], 1, "response: {response}");
        assert!(
            pool.get(&WorkerId::new("reload-launch-path-w1"))
                .await
                .is_some(),
            "worker from the launch-time workers.toml must be in the pool"
        );
    }

    #[test]
    fn test_parse_request_reload() {
        let _guard = test_guard!();
        let req = parse_request("POST /reload").unwrap();
        assert!(matches!(req, ApiRequest::Reload), "expected reload request");
    }

    #[test]
    fn test_parse_request_reload_get_fails() {
        let _guard = test_guard!();
        // GET method should not work for reload
        let result = parse_request("GET /reload");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_request_telemetry_poll() {
        let _guard = test_guard!();
        let req = parse_request("POST /telemetry/poll?worker=css").unwrap();
        match req {
            ApiRequest::TelemetryPoll { worker_id } => {
                assert_eq!(worker_id.as_str(), "css");
            }
            _ => assert!(false, "expected telemetry poll request"),
        }
    }

    #[test]
    fn test_parse_request_self_test_status() {
        let _guard = test_guard!();
        let req = parse_request("GET /self-test/status").unwrap();
        assert!(
            matches!(req, ApiRequest::SelfTestStatus),
            "expected self-test status request"
        );
    }

    #[test]
    fn test_parse_request_self_test_history() {
        let _guard = test_guard!();
        let req = parse_request("GET /self-test/history?limit=5").unwrap();
        match req {
            ApiRequest::SelfTestHistory { limit } => assert_eq!(limit, 5),
            _ => assert!(false, "expected self-test history request"),
        }
    }

    #[test]
    fn test_parse_request_self_test_run() {
        let _guard = test_guard!();
        let req =
            parse_request("POST /self-test/run?worker=css&timeout=120&debug=1&scheduled=false")
                .unwrap();
        let ApiRequest::SelfTestRun(req) = req else {
            assert!(false, "expected self-test run request");
            return;
        };
        assert_eq!(req.worker_ids, vec!["css".to_string()]);
        assert_eq!(req.timeout_secs, Some(120));
        assert!(!req.release_mode);
        assert!(!req.scheduled);
    }

    #[test]
    fn test_parse_request_with_toolchain() {
        let _guard = test_guard!();
        // Create a toolchain JSON and URL encode it
        let toolchain_json = r###"{"channel":"nightly","date":"2024-01-01","full_version":"rustc 1.76.0-nightly"}"###;
        let encoded = urlencoding_encode(toolchain_json);
        let query = format!(
            "GET /select-worker?project=test&cores=4&toolchain={}",
            encoded
        );

        let req = parse_request(&query).unwrap();
        let ApiRequest::SelectWorker { request: req, .. } = req else {
            assert!(false, "expected select-worker request");
            return;
        };

        assert_eq!(req.project, "test");
        assert_eq!(req.estimated_cores, 4);
        assert!(req.toolchain.is_some());

        let tc = req.toolchain.unwrap();
        assert_eq!(tc.channel, "nightly");
        assert_eq!(tc.date, Some("2024-01-01".to_string()));
    }

    #[test]
    fn test_parse_request_with_runtime() {
        let _guard = test_guard!();
        let query = "GET /select-worker?project=test&runtime=bun";
        let req = parse_request(query).unwrap();
        let ApiRequest::SelectWorker { request: req, .. } = req else {
            assert!(false, "expected select-worker request");
            return;
        };
        assert_eq!(req.required_runtime, RequiredRuntime::Bun);

        let query = "GET /select-worker?project=test&runtime=rust";
        let req = parse_request(query).unwrap();
        let ApiRequest::SelectWorker { request: req, .. } = req else {
            assert!(false, "expected select-worker request");
            return;
        };
        assert_eq!(req.required_runtime, RequiredRuntime::Rust);

        // Invalid runtime should default to None
        let query = "GET /select-worker?project=test&runtime=invalid";
        let req = parse_request(query).unwrap();
        let ApiRequest::SelectWorker { request: req, .. } = req else {
            assert!(false, "expected select-worker request");
            return;
        };
        assert_eq!(req.required_runtime, RequiredRuntime::None);
    }

    #[test]
    fn test_parse_request_missing_project() {
        let _guard = test_guard!();
        let result = parse_request("GET /select-worker?cores=4");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_request_invalid_method() {
        let _guard = test_guard!();
        let result = parse_request("PUT /select-worker?project=test");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_request_unknown_endpoint() {
        let _guard = test_guard!();
        let result = parse_request("GET /unknown?project=test");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_request_rejects_route_prefix_typos() {
        let _guard = test_guard!();
        let cases = [
            "POST /benchmark/trigger-extra?worker=css",
            "GET /self-test/history-extra?limit=5",
            "POST /self-test/run-extra?worker=css",
            "POST /release-worker-extra?worker=css&slots=4",
            "POST /record-build-extra?worker=css&project=myproject",
            "POST /build-heartbeat-extra",
            "POST /test-run-extra",
            "GET /select-worker-extra?project=test",
        ];

        for request in cases {
            assert!(
                parse_request(request).is_err(),
                "route typo should be rejected: {request}"
            );
        }
    }

    #[test]
    fn test_percent_unescape_query_value_basic() {
        let _guard = test_guard!();
        assert_eq!(percent_unescape_query_value("hello%20world"), "hello world");
        assert_eq!(
            percent_unescape_query_value("path%2Fto%2Ffile"),
            "path/to/file"
        );
        assert_eq!(percent_unescape_query_value("foo%3Abar"), "foo:bar");
    }

    #[test]
    fn test_percent_unescape_query_value_special_chars() {
        let _guard = test_guard!();
        assert_eq!(percent_unescape_query_value("a%26b%3Dc"), "a&b=c");
        assert_eq!(percent_unescape_query_value("100%25"), "100%");
        assert_eq!(percent_unescape_query_value("hello%2Bworld"), "hello+world");
    }

    #[test]
    fn test_percent_unescape_query_value_plus_as_space() {
        let _guard = test_guard!();
        assert_eq!(percent_unescape_query_value("hello+world"), "hello world");
    }

    #[test]
    fn test_percent_unescape_query_value_no_escapes() {
        let _guard = test_guard!();
        assert_eq!(percent_unescape_query_value("simple"), "simple");
        assert_eq!(
            percent_unescape_query_value("with-dash_underscore"),
            "with-dash_underscore"
        );
    }

    #[test]
    fn test_percent_unescape_query_value_invalid() {
        let _guard = test_guard!();
        // Invalid hex should be preserved
        assert_eq!(percent_unescape_query_value("foo%GGbar"), "foo%GGbar");
        // Incomplete sequence at end
        assert_eq!(percent_unescape_query_value("foo%"), "foo%");
    }

    #[test]
    fn test_percent_unescape_query_value_utf8() {
        let _guard = test_guard!();
        // "é" is %C3%A9 in UTF-8
        assert_eq!(percent_unescape_query_value("%C3%A9"), "é");
        // "こんにちは" (Konnichiwa)
        // こ: %E3%81%93
        // ん: %E3%82%93
        // に: %E3%81%AB
        // ち: %E3%81%A1
        // は: %E3%81%AF
        assert_eq!(
            percent_unescape_query_value("%E3%81%93%E3%82%93%E3%81%AB%E3%81%A1%E3%81%AF"),
            "こんにちは"
        );
        // Mixed
        assert_eq!(
            percent_unescape_query_value("hello%20%F0%9F%8C%8D"),
            "hello 🌍"
        );
    }

    // Helper for test_parse_request_with_toolchain
    fn urlencoding_encode(s: &str) -> String {
        let mut result = String::with_capacity(s.len() * 3);
        for c in s.chars() {
            match c {
                'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => result.push(c),
                _ => {
                    for byte in c.to_string().as_bytes() {
                        result.push('%');
                        result.push_str(&format!("{:02X}", byte));
                    }
                }
            }
        }
        result
    }

    // =========================================================================
    // Selection response tests - reason field scenarios
    // =========================================================================

    use rch_common::{CommandPriority, RequiredRuntime, WorkerConfig, WorkerId, WorkerStatus};

    fn make_test_worker(id: &str, total_slots: u32) -> WorkerConfig {
        WorkerConfig {
            id: WorkerId::new(id),
            host: "localhost".to_string(),
            user: "user".to_string(),
            identity_file: "~/.ssh/id_rsa".to_string(),
            total_slots,
            priority: 100,
            tags: vec![],
            tools: Vec::new(),
        }
    }

    #[tokio::test]
    async fn test_handle_select_worker_no_workers_configured() {
        let pool = WorkerPool::new();
        let ctx = make_test_context(pool);
        let request = SelectionRequest {
            job_mode: false,
            project: "test".to_string(),
            command: None,
            command_priority: CommandPriority::Normal,
            estimated_cores: 4,
            disk_headroom_gib: 0,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
            hook_pid: None,
            required_tools: Vec::new(),
        };

        let response = handle_select_worker(&ctx, request, false, None)
            .await
            .unwrap();
        assert!(response.worker.is_none());
        assert_eq!(response.reason, SelectionReason::NoWorkersConfigured);
    }

    #[tokio::test]
    async fn test_handle_select_worker_all_unreachable() {
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("worker1", 8)).await;
        pool.add_worker(make_test_worker("worker2", 8)).await;

        // Mark all workers as unreachable
        pool.set_status(&WorkerId::new("worker1"), WorkerStatus::Unreachable)
            .await;
        pool.set_status(&WorkerId::new("worker2"), WorkerStatus::Unreachable)
            .await;

        let ctx = make_test_context(pool);
        let request = SelectionRequest {
            job_mode: false,
            project: "test".to_string(),
            command: None,
            command_priority: CommandPriority::Normal,
            estimated_cores: 2,
            disk_headroom_gib: 0,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
            hook_pid: None,
            required_tools: Vec::new(),
        };

        let response = handle_select_worker(&ctx, request, false, None)
            .await
            .unwrap();
        assert!(response.worker.is_none());
        assert_eq!(response.reason, SelectionReason::AllWorkersUnreachable);
    }

    #[tokio::test]
    async fn test_handle_select_worker_all_busy() {
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("worker1", 4)).await;

        // Reserve all slots
        let worker = pool.get(&WorkerId::new("worker1")).await.unwrap();
        worker.reserve_slots(4).await;

        let ctx = make_test_context(pool);
        let request = SelectionRequest {
            job_mode: false,
            project: "test".to_string(),
            command: None,
            command_priority: CommandPriority::Normal,
            estimated_cores: 2,
            disk_headroom_gib: 0,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
            hook_pid: None,
            required_tools: Vec::new(),
        };

        let response = handle_select_worker(&ctx, request, false, None)
            .await
            .unwrap();
        assert!(response.worker.is_none());
        assert_eq!(response.reason, SelectionReason::AllWorkersBusy);
    }

    #[tokio::test]
    async fn test_handle_select_worker_requested_busy_does_not_use_available_alternate() {
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("requested", 4)).await;
        pool.add_worker(make_test_worker("alternate", 8)).await;

        let requested = pool.get(&WorkerId::new("requested")).await.unwrap();
        assert!(requested.reserve_slots(4).await);

        let ctx = make_test_context(pool);
        let request = SelectionRequest {
            job_mode: false,
            project: "test".to_string(),
            command: None,
            command_priority: CommandPriority::Normal,
            estimated_cores: 2,
            disk_headroom_gib: 0,
            preferred_workers: vec![WorkerId::new("requested")],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
            hook_pid: None,
            required_tools: Vec::new(),
        };

        let response = handle_select_worker(&ctx, request, false, None)
            .await
            .unwrap();
        assert!(response.worker.is_none());
        assert_eq!(response.reason, SelectionReason::AllWorkersBusy);
        assert!(response.diagnostics.is_some());
    }

    #[tokio::test]
    async fn queued_job_cancellation_reaches_waiter_without_reserving_slots() {
        let _guard = test_guard!();
        for by_queue_id in [false, true] {
            let pool = WorkerPool::new();
            pool.add_worker(make_test_worker("requested", 4)).await;
            set_test_build_disk(&pool, "requested", 100.0).await;
            let worker = pool.get(&WorkerId::new("requested")).await.unwrap();
            assert!(worker.reserve_slots(4).await);
            let tmp = tempfile::TempDir::new().unwrap();
            let path = tmp.path().join("history.jsonl");
            let mut ctx = make_test_context(pool);
            replace_test_history(
                &mut ctx,
                BuildHistory::new(10).with_persistence(path.clone()),
            );
            let wrapper = format!("rchw-{}", Uuid::new_v4());
            let request = SelectionRequest {
                job_mode: false,
                project: "cancel-queued".into(),
                command: Some("cargo build".into()),
                command_priority: CommandPriority::Normal,
                estimated_cores: 2,
                disk_headroom_gib: 0,
                preferred_workers: vec![WorkerId::new("requested")],
                toolchain: None,
                required_runtime: RequiredRuntime::default(),
                classification_duration_us: None,
                hook_pid: Some(std::process::id()),
                required_tools: Vec::new(),
            };
            let waiting_ctx = ctx.clone();
            let waiting_request = request.clone();
            let waiting_wrapper = wrapper.clone();
            let waiter = tokio::spawn(async move {
                handle_select_worker_with_wrapper(
                    &waiting_ctx,
                    waiting_request,
                    true,
                    Some(5),
                    Some(waiting_wrapper),
                )
                .await
            });
            tokio::time::timeout(Duration::from_secs(2), async {
                while ctx.history.queue_depth() == 0 {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap();
            let queue_id = ctx.history.queued_builds()[0].id;
            let route = if by_queue_id {
                format!("POST /builds/{queue_id}/cancel\n")
            } else {
                format!("POST /jobs/{wrapper}/cancel\n")
            };
            let (mut client, server) = UnixStream::pair().unwrap();
            let (shutdown_tx, _shutdown_rx) = tokio::sync::mpsc::channel(1);
            let cancellation = tokio::spawn(handle_connection(server, ctx.clone(), shutdown_tx));
            client.write_all(route.as_bytes()).await.unwrap();
            let mut response = String::new();
            tokio::time::timeout(Duration::from_secs(2), client.read_to_string(&mut response))
                .await
                .unwrap()
                .unwrap();
            cancellation.await.unwrap().unwrap();
            let body: serde_json::Value =
                serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap();
            assert_eq!(
                body["status"],
                if by_queue_id {
                    "cancelled"
                } else {
                    "cancelled_before_start"
                }
            );
            assert_eq!(body["local_wrapper_id"], wrapper);
            assert_eq!(body["slots_released"], 0);
            worker.release_slots(4).await;
            let response = tokio::time::timeout(Duration::from_secs(3), waiter)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(response.reason, cancelled_selection().reason);
            assert!(response.worker.is_none());
            assert!(response.build_id.is_none());
            assert!(ctx.history.active_builds().is_empty());
            assert_eq!(ctx.history.queue_depth(), 0);
            assert_eq!(worker.available_slots().await, 4);

            replace_test_history(&mut ctx, BuildHistory::load_from_file(&path, 10).unwrap());
            let retry = handle_select_worker_with_wrapper(
                &ctx,
                request,
                false,
                None,
                Some(wrapper.clone()),
            )
            .await
            .unwrap();
            assert_eq!(retry.reason, cancelled_selection().reason);
            assert_eq!(worker.available_slots().await, 4);
            assert_eq!(
                handle_cancel_job(&ctx, &wrapper, false).await.unwrap()["status"],
                "cancelled_before_start"
            );
            assert_eq!(
                handle_cancel_job(&ctx, "unknown-wrapper", false)
                    .await
                    .unwrap()["status"],
                "not_queued"
            );
        }
    }

    #[test]
    fn queued_job_cancel_route_requires_complete_wrapper_identity() {
        let wrapper = format!("rchw-{}", Uuid::new_v4());
        assert!(
            matches!(parse_request(&format!("POST /jobs/{wrapper}/cancel")).unwrap(), ApiRequest::CancelJob { local_wrapper_id } if local_wrapper_id == wrapper)
        );
        for route in [
            "POST /jobs/rchw-invalid/cancel",
            "POST /jobs/1/cancel",
            "POST /jobs/../cancel",
        ] {
            assert!(parse_request(route).is_err());
        }
    }

    #[tokio::test]
    async fn test_handle_select_worker_requested_busy_queue_waits_for_requested_worker() {
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("requested", 4)).await;
        pool.add_worker(make_test_worker("alternate", 8)).await;

        let requested = pool.get(&WorkerId::new("requested")).await.unwrap();
        assert!(requested.reserve_slots(4).await);
        let release_target = requested.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            release_target.release_slots(4).await;
        });

        let ctx = make_test_context(pool);
        let request = SelectionRequest {
            job_mode: false,
            project: "test".to_string(),
            command: None,
            command_priority: CommandPriority::Normal,
            estimated_cores: 2,
            disk_headroom_gib: 0,
            preferred_workers: vec![WorkerId::new("requested")],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
            hook_pid: None,
            required_tools: Vec::new(),
        };

        let response = handle_select_worker(&ctx, request, true, Some(2))
            .await
            .unwrap();
        let selected = response
            .worker
            .expect("requested worker should become available");
        assert_eq!(selected.id.as_str(), "requested");
    }

    #[tokio::test]
    async fn test_handle_select_worker_impossible_requested_capacity_never_queues() {
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("requested", 1)).await;
        pool.add_worker(make_test_worker("alternate", 8)).await;
        let ctx = make_test_context(pool);
        let request = SelectionRequest {
            job_mode: false,
            project: "test".to_string(),
            command: None,
            command_priority: CommandPriority::Normal,
            estimated_cores: 2,
            disk_headroom_gib: 0,
            preferred_workers: vec![WorkerId::new("requested")],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
            hook_pid: None,
            required_tools: Vec::new(),
        };

        let response = tokio::time::timeout(
            Duration::from_millis(200),
            handle_select_worker(&ctx, request, true, Some(2)),
        )
        .await
        .expect("impossible capacity must return without entering the queue")
        .unwrap();
        assert!(response.worker.is_none());
        assert!(matches!(
            response.reason,
            SelectionReason::NoAdmissibleWorkers(ref summary)
                if summary.contains("insufficient_total_slots=1")
        ));
    }

    #[tokio::test]
    async fn test_handle_select_worker_success() {
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("worker1", 8)).await;

        let ctx = make_test_context(pool);
        let request = SelectionRequest {
            job_mode: false,
            project: "test".to_string(),
            command: None,
            command_priority: CommandPriority::Normal,
            estimated_cores: 2,
            disk_headroom_gib: 0,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
            hook_pid: None,
            required_tools: Vec::new(),
        };

        let response = handle_select_worker(&ctx, request, false, None)
            .await
            .unwrap();
        assert!(response.worker.is_some());
        assert_eq!(response.reason, SelectionReason::Success);

        let worker = response.worker.unwrap();
        assert_eq!(worker.id.as_str(), "worker1");
        // Should have reserved 2 slots
        assert_eq!(worker.slots_available, 6);
    }

    #[tokio::test]
    async fn test_admission_barrier_refuses_new_worker_selection() {
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("worker1", 8)).await;
        let ctx = make_test_context(pool);
        ctx.admission_barrier.write().await.begin_shutdown();
        let request = SelectionRequest {
            job_mode: false,
            project: "restart-guard".to_string(),
            command: Some("cargo test".to_string()),
            command_priority: CommandPriority::Normal,
            estimated_cores: 1,
            disk_headroom_gib: 0,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
            required_tools: Vec::new(),
            hook_pid: Some(1234),
        };

        let response = handle_select_worker(&ctx, request, false, None)
            .await
            .expect("barrier returns a structured refusal");

        assert!(response.worker.is_none());
        assert_eq!(
            response.reason,
            SelectionReason::SelectionError("restart_admission_barrier_active".to_string())
        );
        assert!(ctx.history.active_builds().is_empty());
    }

    fn make_test_lease(heartbeat_unix_ms: u64, wrapper_pid: u32) -> DurableJobLease {
        let mut identity = rch_common::job_identity::JobIdentity::new_local();
        identity.admit(42);
        let mut lease = DurableJobLease::new(
            identity,
            wrapper_pid,
            None,
            None,
            heartbeat_unix_ms,
            false,
            true,
            "blake3:test".to_string(),
        );
        lease.admit(42, "worker1".to_string(), heartbeat_unix_ms);
        lease
    }

    #[test]
    fn scan_reaps_only_nonblocking_stale_leases_and_reports_blockers() {
        let dir = std::env::temp_dir().join(format!("rch-lease-scan-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let now = u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap();
        let write = |name: &str, lease: &DurableJobLease| {
            std::fs::write(dir.join(name), serde_json::to_vec(lease).unwrap()).unwrap();
        };

        // Blocking: fresh heartbeat — must be reported, never reaped.
        let fresh = make_test_lease(now, 1);
        write("fresh.json", &fresh);
        // Non-blocking and past retention: terminal + acknowledged, ancient
        // heartbeat — must be reaped.
        let mut done = make_test_lease(now - LEASE_REAP_RETENTION_MS - 1, 1);
        done.acknowledge_terminal(now - LEASE_REAP_RETENTION_MS - 1);
        write("done-old.json", &done);
        // Non-blocking but INSIDE retention: terminal + acknowledged, recent
        // heartbeat — kept for post-mortem, not reaped, not reported.
        let mut recent = make_test_lease(now - 1000, 1);
        recent.acknowledge_terminal(now - 1000);
        write("done-recent.json", &recent);
        // Not a lease: never touched.
        std::fs::write(dir.join("README.txt"), b"not a lease").unwrap();

        let blocked = scan_client_leases(&dir).unwrap();
        assert_eq!(blocked.len(), 1, "only the fresh lease blocks: {blocked:?}");
        assert!(
            !dir.join("done-old.json").exists(),
            "stale non-blocker reaped"
        );
        assert!(
            dir.join("done-recent.json").exists(),
            "recent non-blocker kept"
        );
        assert!(dir.join("fresh.json").exists(), "blocker kept");
        assert!(dir.join("README.txt").exists(), "non-json untouched");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn scan_never_reaps_a_dead_lease_that_still_owns_worker_source() {
        let dir = tempfile::tempdir().unwrap();
        let now = u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap();
        let stale = now - LEASE_REAP_RETENTION_MS - 1;
        // A PID beyond pid_max: provably dead.
        let dead_pid = 4_194_304 * 2;
        let write = |name: &str, pid: u32, recipe: serde_json::Value| {
            let mut lease = make_test_lease(stale, pid);
            lease.recovery = Some(recipe);
            std::fs::write(dir.path().join(name), serde_json::to_vec(&lease).unwrap()).unwrap();
        };
        let owning = |retired: bool| serde_json::json!({ "source_roots": ["/p"], "pair": null, "retire_root": null, "retired": retired });
        write("owns-source.json", dead_pid, owning(false));
        write("retired.json", dead_pid, owning(true));
        write(
            "owns-nothing.json",
            dead_pid,
            serde_json::json!({ "source_roots": [], "pair": null, "retire_root": null, "retired": false }),
        );

        let blocked = scan_client_leases(dir.path()).unwrap();

        assert!(blocked.is_empty(), "{blocked:?}");
        assert!(
            dir.path().join("owns-source.json").exists(),
            "the only authority able to release a worker claim was reaped"
        );
        assert!(
            !dir.path().join("retired.json").exists(),
            "retired history is reaped"
        );
        assert!(
            !dir.path().join("owns-nothing.json").exists(),
            "a recipe owning nothing on the worker is plain history"
        );
    }

    #[test]
    fn is_process_alive_uses_the_syscall_truthfully() {
        // This transient liveness helper remains useful to queue waiters;
        // durable restart leases separately require process birth identity.
        assert!(is_process_alive(std::process::id()));
        assert!(!is_process_alive(0));
    }

    #[test]
    fn test_lease_blocks_restart_acknowledged_terminal_never_blocks() {
        let now = 10 * DEAD_WRAPPER_HEARTBEAT_STALE_MS;
        let mut lease = make_test_lease(1, 1);
        lease.acknowledge_terminal(now);
        assert!(!lease_blocks_restart(&lease, now, || unreachable!(
            "terminal+acknowledged must not probe liveness"
        )));
    }

    #[test]
    fn test_lease_blocks_restart_refused_before_admission_never_blocks() {
        // A wrapper refused before admission keeps running the command
        // locally under the same PID; its retired lease must not hold a drain.
        let now = 10 * DEAD_WRAPPER_HEARTBEAT_STALE_MS;
        let mut lease = DurableJobLease::new(
            rch_common::job_identity::JobIdentity::new_local(),
            1,
            None,
            None,
            now,
            false,
            true,
            "blake3:test".to_string(),
        );
        lease.state = rch_common::job_identity::JobLifecycleState::FailedBeforeAdmission;
        lease.heartbeat("failed_before_admission", now);
        lease.terminal_acknowledged = true;
        assert!(!lease_blocks_restart(&lease, now, || unreachable!(
            "a retired refusal must not probe liveness"
        )));
    }

    #[test]
    fn test_lease_blocks_restart_fresh_heartbeat_blocks_without_liveness_probe() {
        let now = 10 * DEAD_WRAPPER_HEARTBEAT_STALE_MS;
        let lease = make_test_lease(now - DEAD_WRAPPER_HEARTBEAT_STALE_MS + 1, 1);
        assert!(lease_blocks_restart(&lease, now, || unreachable!(
            "a fresh heartbeat must not probe liveness"
        )));
    }

    #[test]
    fn restart_admission_waiter_only_stops_blocking_without_execution_ownership() {
        let now = 10 * DEAD_WRAPPER_HEARTBEAT_STALE_MS;
        let mut waiting = make_test_lease(now, std::process::id());
        waiting.state = rch_common::job_identity::JobLifecycleState::Queued;
        waiting.identity.remote_build_id = None;
        waiting.worker_id = None;
        waiting.phase = "restart_admission_wait".into();
        assert!(!lease_blocks_restart(&waiting, now, || unreachable!()));
        let mut admitted = waiting.clone();
        admitted.identity.remote_build_id = Some(42);
        assert!(lease_blocks_restart(&admitted, now, || unreachable!()));
        let mut worker = waiting.clone();
        worker.worker_id = Some("worker-a".into());
        assert!(lease_blocks_restart(&worker, now, || unreachable!()));
        let mut source_owner = waiting.clone();
        source_owner.recovery = Some(serde_json::json!({"source_roots":["/source"]}));
        assert!(lease_blocks_restart(&source_owner, now, || unreachable!()));
        let mut running = waiting;
        running.state = rch_common::job_identity::JobLifecycleState::Running;
        assert!(lease_blocks_restart(&running, now, || unreachable!()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn restart_admission_scan_retains_live_waiting_journal_even_with_stale_heartbeat() {
        let directory = tempfile::tempdir().unwrap();
        let mut waiting = make_test_lease(1, std::process::id());
        waiting.process_birth = rch_common::process_identity::current_process_identity();
        waiting.state = rch_common::job_identity::JobLifecycleState::Queued;
        waiting.identity.remote_build_id = None;
        waiting.worker_id = None;
        waiting.phase = "restart_admission_wait".into();
        let path = directory.path().join("waiting.json");
        std::fs::write(&path, serde_json::to_vec(&waiting).unwrap()).unwrap();
        assert!(scan_client_leases(directory.path()).unwrap().is_empty());
        assert!(path.exists(), "live waiting lease must remain observable");
    }

    #[test]
    fn test_lease_blocks_restart_stale_heartbeat_alive_pid_blocks() {
        let now = 10 * DEAD_WRAPPER_HEARTBEAT_STALE_MS;
        let lease = make_test_lease(now - DEAD_WRAPPER_HEARTBEAT_STALE_MS, 1);
        assert!(lease_blocks_restart(&lease, now, || OwnerPresence::Live));
    }

    #[test]
    fn test_lease_blocks_restart_stale_heartbeat_dead_pid_unblocks() {
        let now = 10 * DEAD_WRAPPER_HEARTBEAT_STALE_MS;
        let lease = make_test_lease(now - DEAD_WRAPPER_HEARTBEAT_STALE_MS, 1);
        assert!(!lease_blocks_restart(&lease, now, || OwnerPresence::Absent));
    }

    #[test]
    fn test_lease_blocks_restart_zero_pid_stays_blocking_even_when_stale() {
        let now = 10 * DEAD_WRAPPER_HEARTBEAT_STALE_MS;
        let lease = make_test_lease(1, 0);
        assert!(lease_blocks_restart(&lease, now, || {
            owner_presence(lease.wrapper_pid, lease.owner_identity().as_ref())
        }));
    }

    #[test]
    fn test_lease_blocks_restart_stale_unknown_ownership_stays_blocking() {
        let now = 10 * DEAD_WRAPPER_HEARTBEAT_STALE_MS;
        let lease = make_test_lease(1, 4242);
        assert!(lease_blocks_restart(&lease, now, || OwnerPresence::Unknown));
    }

    #[test]
    fn test_lease_blocks_restart_future_heartbeat_requires_owner_evidence() {
        let now = 10 * DEAD_WRAPPER_HEARTBEAT_STALE_MS;
        let lease = make_test_lease(u64::MAX, 4242);
        assert!(!lease_blocks_restart(&lease, now, || OwnerPresence::Absent));
        assert!(lease_blocks_restart(&lease, now, || OwnerPresence::Live));
        assert!(lease_blocks_restart(&lease, now, || OwnerPresence::Unknown));
    }

    #[test]
    fn test_lease_blocks_restart_recycled_pid_and_old_boot_do_not_block() {
        use rch_common::process_identity::{ProcessIdentity, ProcessObservation, ProcessStart};
        let now = 10 * DEAD_WRAPPER_HEARTBEAT_STALE_MS;
        let mut lease = make_test_lease(1, 4242);
        let original = ProcessIdentity {
            boot_id: "6a5a0649-d23a-4d74-b542-85f5e69de721".into(),
            start: ProcessStart::Linux { ticks: 10 },
        };
        lease.process_birth = Some(original.clone());
        for replacement in [
            ProcessIdentity {
                start: ProcessStart::Linux { ticks: 11 },
                ..original.clone()
            },
            ProcessIdentity {
                boot_id: "0e9306b2-57d4-42c2-85b7-ec00aa52fe86".into(),
                ..original.clone()
            },
        ] {
            assert!(!lease_blocks_restart(&lease, now, || {
                lease
                    .owner_identity()
                    .unwrap()
                    .presence(&ProcessObservation::Present(replacement))
            }));
        }
        assert!(lease_blocks_restart(&lease, now, || {
            original.presence(&ProcessObservation::Unknown)
        }));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_lease_blocks_restart_linux_live_identity_and_recycled_start() {
        use rch_common::process_identity::{ProcessStart, current_process_identity};
        let now = 10 * DEAD_WRAPPER_HEARTBEAT_STALE_MS;
        let mut lease = make_test_lease(1, std::process::id());
        lease.process_birth = Some(current_process_identity().expect("Linux process identity"));
        assert!(lease_blocks_restart(&lease, now, || {
            owner_presence(lease.wrapper_pid, lease.owner_identity().as_ref())
        }));
        let ProcessStart::Linux { ticks } = &mut lease.process_birth.as_mut().unwrap().start else {
            panic!("Linux birth marker expected");
        };
        *ticks = ticks.saturating_add(1);
        assert!(!lease_blocks_restart(&lease, now, || {
            owner_presence(lease.wrapper_pid, lease.owner_identity().as_ref())
        }));
    }

    #[test]
    fn test_lease_blocks_restart_unacknowledged_terminal_dead_wrapper_unblocks() {
        // A wrapper that died after reaching a terminal state but before the
        // daemon acknowledged it: same dead-wrapper evidence rule applies.
        let now = 10 * DEAD_WRAPPER_HEARTBEAT_STALE_MS;
        let mut lease = make_test_lease(1, 1);
        lease.state = rch_common::job_identity::JobLifecycleState::Finished;
        assert!(!lease.terminal_acknowledged);
        assert!(!lease_blocks_restart(&lease, now, || OwnerPresence::Absent));
        assert!(lease_blocks_restart(&lease, now, || OwnerPresence::Live));
    }

    #[tokio::test]
    async fn test_restart_admission_reports_active_build_and_keeps_barrier_closed() {
        let ctx = make_test_context(WorkerPool::new());
        let active = ctx.history.start_active_build(
            "restart-proof".to_string(),
            "worker-a".to_string(),
            "cargo test -p rchd".to_string(),
            4242,
            1,
            rch_common::BuildLocation::Remote,
        );

        let fence = MaintenanceFence {
            daemon_incarnation: restart_admission_snapshot(&ctx, false)
                .await
                .daemon_incarnation,
            token: Uuid::new_v4().to_string(),
        };
        let response = handle_restart_admission(
            &ctx,
            &fence,
            MaintenanceAction::Acquire {
                purpose: "restart".into(),
                owner_identity: rch_common::process_identity::current_process_identity().unwrap(),
            },
            MaintenancePeer::capture(i32::try_from(std::process::id()).ok()).as_ref(),
        )
        .await;

        assert!(!response.restart_permitted);
        assert_eq!(response.active_build_ids, vec![active.id]);
        assert!(response.queued_build_ids.is_empty());
        assert!(ctx.admission_barrier.read().await.is_closed());
    }

    async fn acquire_test_maintenance(ctx: &DaemonContext) -> MaintenanceFence {
        let fence = MaintenanceFence {
            daemon_incarnation: restart_admission_snapshot(ctx, false)
                .await
                .daemon_incarnation,
            token: Uuid::new_v4().to_string(),
        };
        let peer = MaintenancePeer::capture(i32::try_from(std::process::id()).ok())
            .expect("the test process must have a durable kernel identity");
        ctx.admission_barrier
            .write()
            .await
            .acquire(
                &fence,
                Some(&peer),
                "test-maintenance".into(),
                Instant::now(),
                maintenance_wall_ms(),
            )
            .unwrap();
        fence
    }

    #[tokio::test]
    async fn restart_admission_scan_timeout_and_cancellation_retain_scan_budget() {
        for cancel in [false, true] {
            let scans = Arc::new(tokio::sync::Semaphore::new(1));
            let (started_tx, started_rx) = tokio::sync::oneshot::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            let timeout = if cancel {
                Duration::from_secs(60)
            } else {
                Duration::ZERO
            };
            let caller = tokio::spawn(run_bounded_client_lease_scan(
                scans.clone(),
                timeout,
                move || {
                    let _ = started_tx.send(());
                    // The sender is owned by this test, so unwinding also
                    // releases this simulated stuck filesystem operation.
                    let _ = release_rx.recv();
                    Ok(Vec::new())
                },
            ));
            tokio::time::timeout(Duration::from_secs(5), started_rx)
                .await
                .expect("blocking scanner started")
                .unwrap();
            if cancel {
                caller.abort();
                assert!(caller.await.unwrap_err().is_cancelled());
            } else {
                let error = caller.await.unwrap().unwrap_err();
                assert!(error.to_string().contains("quiescence is unknown"));
            }
            assert_eq!(scans.available_permits(), 0);
            let refused =
                run_bounded_client_lease_scan(scans.clone(), Duration::from_secs(5), || {
                    panic!("a pending scan must not start another blocking task")
                })
                .await
                .unwrap_err();
            assert!(refused.to_string().contains("already in progress"));

            release_tx.send(()).unwrap();
            let permit = tokio::time::timeout(Duration::from_secs(5), scans.acquire())
                .await
                .expect("completed scanner returns its budget")
                .unwrap();
            drop(permit);
            assert_eq!(
                run_bounded_client_lease_scan(scans, Duration::from_secs(5), || {
                    Ok(vec!["live-wrapper".into()])
                })
                .await
                .unwrap(),
                vec!["live-wrapper"]
            );
        }
    }

    #[tokio::test]
    async fn restart_admission_lifecycle_logging_releases_lock_before_output() {
        use tracing::instrument::WithSubscriber;
        use tracing_subscriber::prelude::*;

        // Other daemon tests install subscribers while exercising the same
        // callsites. Isolate their process-global interest-cache changes from
        // this test's exact event counts, while retaining the real log sink and
        // its assertion that lifecycle output never holds the admission lock.
        const CHILD_ROOT: &str = "RCH_RESTART_ADMISSION_LOG_TEST_ROOT";
        const TEST: &str =
            "api::tests::restart_admission_lifecycle_logging_releases_lock_before_output";
        let child_root = if let Some(root) = std::env::var_os(CHILD_ROOT) {
            std::path::PathBuf::from(root)
        } else {
            let root = tempfile::tempdir().unwrap();
            let output = tokio::time::timeout(
                Duration::from_secs(30),
                tokio::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", TEST, "--nocapture", "--test-threads=1"])
                    .env(CHILD_ROOT, root.path())
                    .kill_on_drop(true)
                    .output(),
            )
            .await
            .expect("isolated admission lifecycle logging test timed out")
            .unwrap();
            assert!(
                output.status.success(),
                "isolated admission lifecycle logging failed: {output:?}"
            );
            assert!(
                root.path().join("completed").is_file(),
                "isolated admission lifecycle logging did not run all assertions: {output:?}"
            );
            return;
        };

        struct CheckUnlocked {
            admission: Arc<tokio::sync::RwLock<RestartAdmissionState>>,
            events: Arc<std::sync::Mutex<Vec<String>>>,
        }

        #[derive(Default)]
        struct Message(String);

        impl tracing::field::Visit for Message {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" {
                    self.0 = format!("{value:?}");
                }
            }
        }

        impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CheckUnlocked {
            fn on_event(
                &self,
                event: &tracing::Event<'_>,
                _context: tracing_subscriber::layer::Context<'_, S>,
            ) {
                if event
                    .metadata()
                    .fields()
                    .field("daemon_incarnation")
                    .is_some()
                {
                    assert!(
                        self.admission.try_write().is_ok(),
                        "a blocked lifecycle log sink must not hold the admission lock"
                    );
                    let mut message = Message::default();
                    event.record(&mut message);
                    self.events.lock().unwrap().push(message.0);
                }
            }
        }

        let ctx = make_test_context(WorkerPool::new());
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::registry().with(CheckUnlocked {
            admission: ctx.admission_barrier.clone(),
            events: events.clone(),
        });
        let assert_events = |count, stage| {
            let observed = events.lock().unwrap();
            assert_eq!(observed.len(), count, "{stage}: {observed:?}");
        };
        async {
            let first = acquire_test_maintenance(&ctx).await;
            // A cancelled request may leave an acquired event for the independent
            // recovery task; emitting it must also happen after releasing the lock.
            recover_restart_admission(&ctx).await;
            assert_events(1, "first acquisition");
            let peer_pid = i32::try_from(std::process::id()).ok();
            let peer = MaintenancePeer::capture(peer_pid).unwrap();
            let released =
                handle_restart_admission(&ctx, &first, MaintenanceAction::Release, Some(&peer))
                    .await;
            assert!(released.success);
            assert_events(2, "explicit release");

            let expired = MaintenanceFence {
                token: Uuid::new_v4().to_string(),
                ..first
            };
            ctx.admission_barrier
                .write()
                .await
                .acquire(
                    &expired,
                    Some(&peer),
                    "expired request".into(),
                    Instant::now() - crate::restart_admission::MAINTENANCE_TTL,
                    maintenance_wall_ms(),
                )
                .unwrap();
            recover_restart_admission(&ctx).await;
            assert_events(4, "expired acquisition and recovery");
            assert!(
                !restart_admission_snapshot(&ctx, false)
                    .await
                    .admission_closed
            );

            let shutting_down = acquire_test_maintenance(&ctx).await;
            recover_restart_admission(&ctx).await;
            assert_events(5, "shutdown acquisition");
            let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
            let committed = handle_shutdown(&ctx, &shutting_down, true, Some(&peer), &sender).await;
            assert!(committed.success && committed.shutdown_committed);
            receiver.try_recv().unwrap();
        }
        .with_subscriber(subscriber)
        .await;
        assert_events(6, "committed shutdown");
        std::fs::write(
            child_root.join("completed"),
            "six lifecycle events checked\n",
        )
        .unwrap();
    }

    #[tokio::test]
    async fn restart_admission_api_unknown_peer_cannot_close_admission() {
        let ctx = make_test_context(WorkerPool::new());
        let fence = MaintenanceFence {
            daemon_incarnation: restart_admission_snapshot(&ctx, false)
                .await
                .daemon_incarnation,
            token: Uuid::new_v4().to_string(),
        };
        let response = handle_restart_admission(
            &ctx,
            &fence,
            MaintenanceAction::Acquire {
                purpose: "restart".into(),
                owner_identity: rch_common::process_identity::current_process_identity().unwrap(),
            },
            None,
        )
        .await;
        assert!(!response.success);
        assert_eq!(response.status, "maintenance_peer_identity_unknown");
        assert!(!response.admission_closed);
        assert!(response.maintenance_owner.is_none());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn restart_admission_recycled_connection_identity_cannot_mutate_barrier() {
        use rch_common::process_identity::ProcessStart;

        let ctx = make_test_context(WorkerPool::new());
        let mut recycled =
            MaintenancePeer::capture(i32::try_from(std::process::id()).ok()).unwrap();
        let ProcessStart::Linux { ticks } = &mut recycled.identity.start else {
            panic!("Linux birth marker expected");
        };
        *ticks = ticks.saturating_add(1);
        let candidate = MaintenanceFence {
            daemon_incarnation: restart_admission_snapshot(&ctx, false)
                .await
                .daemon_incarnation,
            token: Uuid::new_v4().to_string(),
        };
        let refused = handle_restart_admission(
            &ctx,
            &candidate,
            MaintenanceAction::Acquire {
                purpose: "delayed connection".into(),
                owner_identity: recycled.identity.clone(),
            },
            Some(&recycled),
        )
        .await;
        assert!(!refused.success && !refused.admission_closed);
        assert_eq!(refused.status, "maintenance_peer_identity_unknown");

        // A socket may already have waited in the accept backlog when the
        // original PID was recycled. Even a currently live peer observation
        // cannot replace the caller's pre-connect birth witness.
        let live_peer = MaintenancePeer::capture(i32::try_from(std::process::id()).ok()).unwrap();
        for (owner_identity, reason) in [
            (
                recycled.identity.clone(),
                "maintenance_owner_identity_mismatch",
            ),
            (
                ProcessIdentity {
                    boot_id: "0e9306b2-57d4-42c2-85b7-ec00aa52fe86".into(),
                    ..live_peer.identity.clone()
                },
                "maintenance_owner_identity_mismatch",
            ),
            (
                ProcessIdentity {
                    boot_id: String::new(),
                    ..live_peer.identity.clone()
                },
                "maintenance_owner_identity_unknown",
            ),
        ] {
            let refused = handle_restart_admission(
                &ctx,
                &candidate,
                MaintenanceAction::Acquire {
                    purpose: "backlogged connection".into(),
                    owner_identity,
                },
                Some(&live_peer),
            )
            .await;
            assert!(!refused.success && !refused.admission_closed, "{refused:?}");
            assert_eq!(refused.status, reason);
        }

        let owner = acquire_test_maintenance(&ctx).await;
        for action in [MaintenanceAction::Renew, MaintenanceAction::Release] {
            let refused = handle_restart_admission(&ctx, &owner, action, Some(&recycled)).await;
            assert!(!refused.success && refused.admission_closed);
            assert_eq!(refused.status, "maintenance_peer_identity_unknown");
            assert_eq!(refused.maintenance_owner.unwrap().token, owner.token);
        }
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
        let refused = handle_shutdown(&ctx, &owner, true, Some(&recycled), &sender).await;
        assert!(!refused.success && !refused.shutdown_committed);
        assert!(matches!(
            receiver.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn restart_admission_api_concurrent_release_and_recovery_leave_live_owner_closed() {
        let ctx = make_test_context(WorkerPool::new());
        let first = acquire_test_maintenance(&ctx).await;
        let second = MaintenanceFence {
            token: Uuid::new_v4().to_string(),
            ..first.clone()
        };
        let peer = MaintenancePeer::capture(i32::try_from(std::process::id()).ok());
        for (fence, action) in [
            (&second, MaintenanceAction::Release),
            (&second, MaintenanceAction::Renew),
            (&first, MaintenanceAction::Recover),
        ] {
            let refused = handle_restart_admission(&ctx, fence, action, peer.as_ref()).await;
            assert!(!refused.success);
            assert!(refused.admission_closed);
            assert_eq!(refused.maintenance_owner.unwrap().token, first.token);
        }
        let released =
            handle_restart_admission(&ctx, &first, MaintenanceAction::Release, peer.as_ref()).await;
        assert!(released.success && !released.admission_closed);
        let verified = restart_admission_snapshot(&ctx, false).await;
        assert!(!verified.admission_closed && verified.maintenance_owner.is_none());
    }

    #[tokio::test]
    async fn restart_admission_shutdown_delivery_error_can_be_released_and_verified() {
        let ctx = make_test_context(WorkerPool::new());
        let fence = acquire_test_maintenance(&ctx).await;
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        drop(receiver);
        let peer = MaintenancePeer::capture(i32::try_from(std::process::id()).ok());
        let failed = handle_shutdown(&ctx, &fence, true, peer.as_ref(), &sender).await;
        assert!(!failed.success);
        assert_eq!(failed.status, "shutdown_delivery_failed");
        assert!(failed.admission_closed && !failed.shutdown_committed);
        let released =
            handle_restart_admission(&ctx, &fence, MaintenanceAction::Release, peer.as_ref()).await;
        assert!(released.success && !released.admission_closed);
        assert!(
            !restart_admission_snapshot(&ctx, false)
                .await
                .admission_closed
        );
    }

    #[tokio::test]
    async fn restart_admission_shutdown_commits_before_notify_and_rejects_late_release() {
        let ctx = make_test_context(WorkerPool::new());
        let fence = acquire_test_maintenance(&ctx).await;
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
        let peer = MaintenancePeer::capture(i32::try_from(std::process::id()).ok());
        let committed = handle_shutdown(&ctx, &fence, true, peer.as_ref(), &sender).await;
        assert!(committed.success && committed.shutdown_committed && committed.admission_closed);
        assert_eq!(committed.status, "shutting_down");
        receiver
            .try_recv()
            .expect("shutdown notification was delivered");
        let refused =
            handle_restart_admission(&ctx, &fence, MaintenanceAction::Release, peer.as_ref()).await;
        assert!(!refused.success);
        assert_eq!(refused.status, "shutdown_committed");
        assert!(refused.admission_closed && refused.shutdown_committed);
    }

    #[tokio::test]
    async fn restart_admission_release_does_not_report_open_after_history_write_failure() {
        let directory = tempfile::tempdir().unwrap();
        let non_directory = directory.path().join("not-a-directory");
        std::fs::write(&non_directory, "a regular file").unwrap();
        let mut ctx = make_test_context(WorkerPool::new());
        replace_test_history(
            &mut ctx,
            BuildHistory::new(10).with_persistence(non_directory.join("history.jsonl")),
        );
        let failure = ctx
            .history
            .try_start_active_build_with_wrapper(
                "test-project".into(),
                "test-worker".into(),
                "cargo test".into(),
                std::process::id(),
                Some("rchw-test".into()),
                1,
                rch_common::BuildLocation::Remote,
            )
            .unwrap_err();
        let fence = acquire_test_maintenance(&ctx).await;
        let response = handle_restart_admission(
            &ctx,
            &fence,
            MaintenanceAction::Release,
            MaintenancePeer::capture(i32::try_from(std::process::id()).ok()).as_ref(),
        )
        .await;
        assert!(!response.success && response.admission_closed && response.ownership_failed);
        assert_eq!(response.status, "ownership_failed");
        assert!(!response.maintenance_closed && response.maintenance_owner.is_none());
        assert_eq!(
            response.ownership_error.as_deref(),
            Some(failure.to_string().as_str())
        );
        let verified = restart_admission_snapshot(&ctx, false).await;
        assert!(verified.ownership_failed && verified.admission_closed);
        assert_eq!(verified.ownership_error, response.ownership_error);
    }

    #[tokio::test]
    async fn test_handle_select_worker_preserves_affinity_pin_reason() {
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("worker1", 8)).await;
        pool.add_worker(make_test_worker("worker2", 8)).await;

        let ctx = make_test_context(pool);
        ctx.worker_selector
            .record_success("worker2", "test-project")
            .await;
        let request = SelectionRequest {
            job_mode: false,
            project: "test-project".to_string(),
            command: None,
            command_priority: CommandPriority::Normal,
            estimated_cores: 2,
            disk_headroom_gib: 0,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
            hook_pid: None,
            required_tools: Vec::new(),
        };

        let response = handle_select_worker(&ctx, request, false, None)
            .await
            .unwrap();

        assert_eq!(response.reason, SelectionReason::AffinityPinned);
        let worker = response.worker.expect("affinity-pinned worker");
        assert_eq!(worker.id.as_str(), "worker2");
        assert_eq!(worker.slots_available, 6);
    }

    #[tokio::test]
    async fn test_handle_select_worker_tracks_active_build_when_hook_pid_present() {
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("worker1", 8)).await;
        set_test_build_disk(&pool, "worker1", 100.0).await;

        let ctx = make_test_context(pool);
        let request = SelectionRequest {
            job_mode: false,
            project: "test-project".to_string(),
            command: Some("cargo build --release".to_string()),
            command_priority: CommandPriority::Normal,
            estimated_cores: 2,
            disk_headroom_gib: 0,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
            required_tools: Vec::new(),
            hook_pid: Some(4242),
        };

        let response = handle_select_worker_with_wrapper(
            &ctx,
            request,
            false,
            None,
            Some("rchw-daemon-correlation".to_string()),
        )
        .await
        .unwrap();
        assert_eq!(response.reason, SelectionReason::Success);
        let build_id = response.build_id.expect("build_id should be assigned");

        let active = ctx.history.active_build(build_id).expect("active build");
        assert_eq!(active.project_id, "test-project");
        assert_eq!(active.worker_id, "worker1");
        assert_eq!(active.command, "cargo build --release");
        assert_eq!(active.hook_pid, 4242);
        assert_eq!(
            active.local_wrapper_id.as_deref(),
            Some("rchw-daemon-correlation")
        );
        assert_eq!(active.slots, 2);

        // Release should finalize the active build and move it into history
        handle_release_worker(
            &ctx,
            ReleaseRequest {
                local_wrapper_id: Some("rchw-daemon-correlation".to_string()),
                disk_peak_output_bytes: None,
                worker_id: WorkerId::new("worker1"),
                slots: 2,
                build_id: Some(build_id),
                exit_code: Some(0),
                duration_ms: None,
                bytes_transferred: None,
                timing: None,
                worker_fault: false,
                worker_disk_full: false,
                worker_live_checkout_refused: false,
                worker_source_busy: false,
                worker_disk_roots: Vec::new(),
            },
        )
        .await
        .unwrap();

        assert!(ctx.history.active_build(build_id).is_none());
        let recent = ctx.history.recent(10);
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].id, build_id);
        assert_eq!(recent[0].project_id, "test-project");
        assert_eq!(recent[0].worker_id.as_deref(), Some("worker1"));
        assert_eq!(recent[0].exit_code, 0);
        assert_eq!(recent[0].location, rch_common::BuildLocation::Remote);
    }

    #[test]
    fn queue_wait_honours_a_jobs_long_wait_but_caps_compilations() {
        assert_eq!(queue_wait_secs(false, Some(329), 300), 300);
        assert_eq!(queue_wait_secs(false, Some(60), 300), 60);
        assert_eq!(queue_wait_secs(false, None, 300), 300);
        assert_eq!(queue_wait_secs(true, Some(21_599), 300), 21_599);
        assert_eq!(
            queue_wait_secs(true, Some(u64::MAX), 300),
            JOB_QUEUE_WAIT_CEILING_SECS
        );
        assert_eq!(queue_wait_secs(true, None, 300), 300);
        assert_eq!(queue_wait_secs(true, Some(0), 0), 1);
    }

    fn hold_diagnostic(
        id: &str,
        available: u32,
        total: u32,
        codes: &[&str],
    ) -> rch_common::WorkerSelectionDiagnostic {
        rch_common::WorkerSelectionDiagnostic {
            worker_id: WorkerId::new(id),
            status: "healthy".into(),
            circuit_state: "closed".into(),
            pressure_state: "healthy".into(),
            pressure_reason_code: "none".into(),
            success_rate: None,
            min_success_rate: 0.0,
            fallback_min_success_rate: 0.0,
            required_runtime: RequiredRuntime::default(),
            runtime_available: true,
            available_slots: available,
            total_slots: total,
            estimated_cores: 3,
            active_project_excluded: false,
            final_decision: rch_common::WorkerSelectionDiagnosticDecision::Deny,
            final_reason: String::new(),
            reason_codes: codes.iter().map(|code| (*code).to_string()).collect(),
        }
    }

    #[test]
    fn queue_hold_candidate_is_a_worker_short_only_of_slots() {
        let diagnostics = rch_common::SelectionDiagnostics {
            required_runtime: RequiredRuntime::default(),
            estimated_cores: 3,
            min_success_rate: 0.0,
            fallback_min_success_rate: 0.0,
            active_project_exclusion_count: 1,
            workers: vec![
                hold_diagnostic("busy-a", 1, 3, &["slots.insufficient"]),
                hold_diagnostic("busy-b", 2, 3, &["slots.insufficient"]),
                hold_diagnostic("small", 2, 2, &["slots.request_exceeds_capacity"]),
                hold_diagnostic("excluded", 3, 3, &["active_project_exclusion"]),
                hold_diagnostic("critical", 3, 8, &["pressure.critical"]),
            ],
        };
        // Closest to fitting first; an existing hold is kept while it qualifies.
        assert_eq!(
            queue_hold_candidate(&diagnostics, None).as_deref(),
            Some("busy-b")
        );
        assert_eq!(
            queue_hold_candidate(&diagnostics, Some("busy-a")).as_deref(),
            Some("busy-a")
        );
        assert_eq!(
            queue_hold_candidate(&diagnostics, Some("excluded")).as_deref(),
            Some("busy-b")
        );
        let mut none_fit = diagnostics.clone();
        none_fit
            .workers
            .retain(|w| !w.worker_id.as_str().starts_with("busy"));
        assert_eq!(queue_hold_candidate(&none_fit, None), None);
    }

    #[tokio::test]
    async fn queue_hold_steers_younger_requests_off_the_held_worker() {
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("held", 3)).await;
        set_test_build_disk(&pool, "held", 100.0).await;
        let ctx = make_test_context(pool);
        let request = |hook_pid| SelectionRequest {
            job_mode: false,
            project: "other-project".to_string(),
            command: Some("cargo build".to_string()),
            command_priority: CommandPriority::Normal,
            estimated_cores: 1,
            disk_headroom_gib: 0,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
            required_tools: Vec::new(),
            hook_pid: Some(hook_pid),
        };

        // An older 3-slot job waiter holds the only worker.
        let (queued, _claim) = ctx
            .history
            .enqueue_selection_build(
                "gate-project".into(),
                "bash job.sh -j 3".into(),
                std::process::id(),
                3,
                None,
                QueueSelectionContract {
                    digest: [1; 32],
                    timeout_secs: 3600,
                },
            )
            .unwrap();
        assert!(
            ctx.history
                .claim_queue_hold(queued.id, queued.queued_at_mono, "held".to_string())
        );

        // A request the held worker would take is busy, so it can queue.
        let blocked = handle_select_worker(&ctx, request(2001), false, None)
            .await
            .unwrap();
        assert!(blocked.worker.is_none());
        assert_eq!(blocked.reason, SelectionReason::AllWorkersBusy);
        assert!(ctx.history.active_builds().is_empty());

        // Once the waiter leaves the queue, the worker is selectable again.
        ctx.history.release_queue_hold(queued.id);
        let admitted = handle_select_worker(&ctx, request(2002), false, None)
            .await
            .unwrap();
        assert_eq!(
            admitted.worker.as_ref().map(|w| w.id.as_str()),
            Some("held")
        );
    }

    #[tokio::test]
    async fn test_handle_select_worker_blocks_same_project_on_same_worker() {
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("worker1", 8)).await;
        set_test_build_disk(&pool, "worker1", 100.0).await;

        let ctx = make_test_context(pool);
        let first_request = SelectionRequest {
            job_mode: false,
            project: "shared-project".to_string(),
            command: Some("cargo test".to_string()),
            command_priority: CommandPriority::Normal,
            estimated_cores: 2,
            disk_headroom_gib: 0,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
            required_tools: Vec::new(),
            hook_pid: Some(1001),
        };

        let first_response = handle_select_worker(&ctx, first_request, false, None)
            .await
            .unwrap();
        assert_eq!(first_response.reason, SelectionReason::Success);
        assert_eq!(
            first_response.worker.as_ref().map(|w| w.id.as_str()),
            Some("worker1")
        );

        let second_request = SelectionRequest {
            job_mode: false,
            project: "shared-project".to_string(),
            command: Some("cargo test".to_string()),
            command_priority: CommandPriority::Normal,
            estimated_cores: 2,
            disk_headroom_gib: 0,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
            required_tools: Vec::new(),
            hook_pid: Some(1002),
        };

        let second_response = handle_select_worker(&ctx, second_request, false, None)
            .await
            .unwrap();
        assert!(second_response.worker.is_none());
        assert_eq!(
            second_response.reason,
            SelectionReason::NoAdmissibleWorkers("active_project_exclusion=1".to_string())
        );
        let diagnostics = second_response
            .diagnostics
            .expect("daemon response should surface selector diagnostics");
        assert_eq!(diagnostics.active_project_exclusion_count, 1);
        assert_eq!(diagnostics.workers.len(), 1);
        assert!(
            diagnostics.workers[0]
                .reason_codes
                .iter()
                .any(|code| code == "active_project_exclusion")
        );
    }

    #[tokio::test]
    async fn test_handle_select_worker_routes_same_project_to_different_worker() {
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("worker1", 8)).await;
        pool.add_worker(make_test_worker("worker2", 8)).await;
        set_test_build_disk(&pool, "worker1", 100.0).await;
        set_test_build_disk(&pool, "worker2", 100.0).await;

        let ctx = make_test_context(pool);
        let first_request = SelectionRequest {
            job_mode: false,
            project: "shared-project".to_string(),
            command: Some("cargo build".to_string()),
            command_priority: CommandPriority::Normal,
            estimated_cores: 2,
            disk_headroom_gib: 0,
            preferred_workers: vec![WorkerId::new("worker1")],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
            required_tools: Vec::new(),
            hook_pid: Some(2001),
        };

        let first_response = handle_select_worker(&ctx, first_request, false, None)
            .await
            .unwrap();
        assert_eq!(first_response.reason, SelectionReason::Success);
        assert_eq!(
            first_response.worker.as_ref().map(|w| w.id.as_str()),
            Some("worker1")
        );

        let second_request = SelectionRequest {
            job_mode: false,
            project: "shared-project".to_string(),
            command: Some("cargo build".to_string()),
            command_priority: CommandPriority::Normal,
            estimated_cores: 2,
            disk_headroom_gib: 0,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
            required_tools: Vec::new(),
            hook_pid: Some(2002),
        };

        let second_response = handle_select_worker(&ctx, second_request, false, None)
            .await
            .unwrap();
        assert_eq!(second_response.reason, SelectionReason::Success);
        assert_eq!(
            second_response.worker.as_ref().map(|w| w.id.as_str()),
            Some("worker2")
        );
    }

    #[tokio::test]
    async fn test_handle_select_worker_job_mode_burst_spreads_then_queues() {
        // bd-g7rpy: a job burst larger than the worker count spreads one shard
        // per worker (one-active-job-per-project-per-worker guard), then excess
        // shards QUEUE (AllWorkersBusy) instead of failing to local. The same
        // state for a compilation request still returns NoAdmissibleWorkers.
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("worker1", 8)).await;
        pool.add_worker(make_test_worker("worker2", 8)).await;
        set_test_build_disk(&pool, "worker1", 100.0).await;
        set_test_build_disk(&pool, "worker2", 100.0).await;

        let ctx = make_test_context(pool);
        let shard = |pid: u32, job_mode: bool| SelectionRequest {
            job_mode,
            project: "burst-project".to_string(),
            command: Some("./run_shard.sh".to_string()),
            command_priority: CommandPriority::Normal,
            estimated_cores: 2,
            disk_headroom_gib: 0,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
            required_tools: Vec::new(),
            hook_pid: Some(pid),
        };

        let s1 = handle_select_worker(&ctx, shard(101, true), false, None)
            .await
            .unwrap();
        assert_eq!(s1.reason, SelectionReason::Success);

        let s2 = handle_select_worker(&ctx, shard(102, true), false, None)
            .await
            .unwrap();
        assert_eq!(s2.reason, SelectionReason::Success);
        // Spread: the guard forces shard 2 onto the OTHER worker.
        let w1 = s1.worker.as_ref().map(|w| w.id.as_str()).unwrap();
        let w2 = s2.worker.as_ref().map(|w| w.id.as_str()).unwrap();
        assert_ne!(w1, w2);

        let s3 = handle_select_worker(&ctx, shard(103, true), false, None)
            .await
            .unwrap();
        assert!(s3.worker.is_none());
        assert_eq!(s3.reason, SelectionReason::AllWorkersBusy);

        // Compilation request in the identical state: unchanged verdict.
        let compile = handle_select_worker(&ctx, shard(104, false), false, None)
            .await
            .unwrap();
        assert!(matches!(
            compile.reason,
            SelectionReason::NoAdmissibleWorkers(_)
        ));
    }
    #[tokio::test]
    async fn test_handle_select_worker_allows_different_projects_on_same_worker() {
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("worker1", 8)).await;
        set_test_build_disk(&pool, "worker1", 100.0).await;

        let ctx = make_test_context(pool);
        let first_request = SelectionRequest {
            job_mode: false,
            project: "project-a".to_string(),
            command: Some("cargo check".to_string()),
            command_priority: CommandPriority::Normal,
            estimated_cores: 2,
            disk_headroom_gib: 0,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
            required_tools: Vec::new(),
            hook_pid: Some(3001),
        };

        let first_response = handle_select_worker(&ctx, first_request, false, None)
            .await
            .unwrap();
        assert_eq!(first_response.reason, SelectionReason::Success);

        let second_request = SelectionRequest {
            job_mode: false,
            project: "project-b".to_string(),
            command: Some("cargo check".to_string()),
            command_priority: CommandPriority::Normal,
            estimated_cores: 2,
            disk_headroom_gib: 0,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
            required_tools: Vec::new(),
            hook_pid: Some(3002),
        };

        let second_response = handle_select_worker(&ctx, second_request, false, None)
            .await
            .unwrap();
        assert_eq!(second_response.reason, SelectionReason::Success);
        assert_eq!(
            second_response.worker.as_ref().map(|w| w.id.as_str()),
            Some("worker1")
        );
    }

    #[tokio::test]
    async fn test_handle_select_worker_preferred() {
        // An explicit `preferred_workers` request is an allow-set (d174384):
        // a requested worker that exists is selected over any other candidate,
        // and a requested worker absent from the pool is refused rather than
        // silently replaced by an unrelated worker.
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("worker1", 8)).await;
        pool.add_worker(make_test_worker("worker2", 8)).await;

        let ctx = make_test_context(pool);
        let request = SelectionRequest {
            job_mode: false,
            project: "test".to_string(),
            command: None,
            command_priority: CommandPriority::Normal,
            estimated_cores: 2,
            disk_headroom_gib: 0,
            preferred_workers: vec![WorkerId::new("worker2")],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
            hook_pid: None,
            required_tools: Vec::new(),
        };

        let response = handle_select_worker(&ctx, request, false, None)
            .await
            .unwrap();
        let worker = response.worker.unwrap();
        assert_eq!(worker.id.as_str(), "worker2");

        // A requested worker that is not in the pool never escapes the
        // allow-set: the selection refuses with NoMatchingWorkers instead of
        // handing back worker1.
        let absent_request = SelectionRequest {
            job_mode: false,
            project: "test-absent".to_string(),
            command: None,
            command_priority: CommandPriority::Normal,
            estimated_cores: 2,
            disk_headroom_gib: 0,
            preferred_workers: vec![WorkerId::new("no-such-worker")],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
            hook_pid: None,
            required_tools: Vec::new(),
        };
        let refusal = handle_select_worker(&ctx, absent_request, false, None)
            .await
            .unwrap();
        assert!(refusal.worker.is_none());
        assert_eq!(refusal.reason, SelectionReason::NoMatchingWorkers);
    }

    // =========================================================================
    // Reload API tests
    // =========================================================================

    #[test]
    fn test_parse_request_reload_requires_post() {
        let _guard = test_guard!();
        // Only POST should work for reload
        let result = parse_request("POST /reload");
        assert!(result.is_ok());
        assert!(
            matches!(result.unwrap(), ApiRequest::Reload),
            "expected reload request"
        );

        // GET should fail
        let result = parse_request("GET /reload");
        assert!(result.is_err());
    }

    // =========================================================================
    // format_wait_time tests
    // =========================================================================

    #[test]
    fn test_format_wait_time_seconds_only() {
        let _guard = test_guard!();
        assert_eq!(format_wait_time(0), "0s");
        assert_eq!(format_wait_time(1), "1s");
        assert_eq!(format_wait_time(30), "30s");
        assert_eq!(format_wait_time(59), "59s");
    }

    #[test]
    fn test_format_wait_time_minutes() {
        let _guard = test_guard!();
        assert_eq!(format_wait_time(60), "1m");
        assert_eq!(format_wait_time(61), "1m 1s");
        assert_eq!(format_wait_time(90), "1m 30s");
        assert_eq!(format_wait_time(120), "2m");
        assert_eq!(format_wait_time(3599), "59m 59s");
    }

    #[test]
    fn test_format_wait_time_hours() {
        let _guard = test_guard!();
        assert_eq!(format_wait_time(3600), "1h");
        assert_eq!(format_wait_time(3660), "1h 1m");
        assert_eq!(format_wait_time(7200), "2h");
        assert_eq!(format_wait_time(7260), "2h 1m");
        assert_eq!(format_wait_time(9000), "2h 30m");
    }

    // =========================================================================
    // Response type serialization tests
    // =========================================================================

    #[test]
    fn test_daemon_status_info_serialization() {
        let _guard = test_guard!();
        let info = DaemonStatusInfo {
            pid: 1234,
            uptime_secs: 3600,
            version: "1.0.0".to_string(),
            socket_path: "/tmp/test.sock".to_string(),
            started_at: "2025-01-01T00:00:00Z".to_string(),
            workers_total: 4,
            workers_healthy: 3,
            slots_total: 32,
            slots_available: 24,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"pid\":1234"));
        assert!(json.contains("\"uptime_secs\":3600"));
        assert!(json.contains("\"workers_total\":4"));
    }

    #[test]
    fn test_worker_status_info_serialization() {
        let _guard = test_guard!();
        let info = WorkerStatusInfo {
            id: "worker1".to_string(),
            host: "localhost".to_string(),
            user: "user".to_string(),
            status: "healthy".to_string(),
            circuit_state: "closed".to_string(),
            used_slots: 2,
            total_slots: 8,
            speed_score: 95.5,
            last_error: None,
            consecutive_failures: 0,
            recovery_in_secs: None,
            failure_history: vec![true, true, true],
            pressure_state: "healthy".to_string(),
            pressure_confidence: "high".to_string(),
            pressure_reason_code: "pressure_healthy".to_string(),
            pressure_policy_rule: "all_pressure_rules_within_threshold".to_string(),
            pressure_disk_free_gb: Some(42.0),
            pressure_disk_total_gb: Some(128.0),
            pressure_disk_free_ratio: Some(0.328),
            pressure_build_disk_free_gb: None,
            pressure_build_disk_total_gb: None,
            pressure_disk_io_util_pct: Some(18.0),
            pressure_memory_pressure: Some(44.0),
            pressure_telemetry_age_secs: Some(7),
            pressure_telemetry_fresh: true,
            bypass: None,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"id\":\"worker1\""));
        assert!(json.contains("\"used_slots\":2"));
        assert!(json.contains("\"speed_score\":95.5"));
    }

    #[test]
    fn test_health_response_serialization() {
        let _guard = test_guard!();
        let response = HealthResponse {
            status: "healthy".to_string(),
            version: "1.0.0".to_string(),
            uptime_seconds: 3600,
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"status\":\"healthy\""));
        assert!(json.contains("\"version\":\"1.0.0\""));
    }

    #[test]
    fn test_ready_response_serialization_ready() {
        let _guard = test_guard!();
        let response = ReadyResponse {
            status: "ready".to_string(),
            workers_available: true,
            reason: None,
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"status\":\"ready\""));
        assert!(json.contains("\"workers_available\":true"));
        // reason should be skipped when None
        assert!(!json.contains("reason"));
    }

    #[test]
    fn test_ready_response_serialization_not_ready() {
        let _guard = test_guard!();
        let response = ReadyResponse {
            status: "not_ready".to_string(),
            workers_available: false,
            reason: Some("no_workers_available".to_string()),
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"status\":\"not_ready\""));
        assert!(json.contains("\"reason\":\"no_workers_available\""));
    }

    #[test]
    fn test_active_build_serialization() {
        let _guard = test_guard!();
        let build = ActiveBuild {
            id: 42,
            project_id: "my-project".to_string(),
            worker_id: "worker1".to_string(),
            command: "cargo build".to_string(),
            started_at: "2025-01-01T00:00:00Z".to_string(),
            last_heartbeat_at: "2025-01-01T00:00:03Z".to_string(),
            heartbeat_age_secs: 2,
            last_progress_at: "2025-01-01T00:00:02Z".to_string(),
            progress_age_secs: 3,
            heartbeat_phase: "execute".to_string(),
            heartbeat_detail: Some("Compiling crates".to_string()),
            heartbeat_counter: 9,
            heartbeat_percent: Some(42.0),
            slots: 4,
            detector_hook_alive: false,
            detector_heartbeat_stale: true,
            detector_progress_stale: true,
            detector_confidence: 0.91,
            detector_build_age_secs: 120,
            detector_slots_owned: 4,
            detector_last_evaluated_at: Some("2025-01-01T00:00:04Z".to_string()),
        };
        let json = serde_json::to_string(&build).unwrap();
        assert!(json.contains("\"id\":42"));
        assert!(json.contains("\"project_id\":\"my-project\""));
        assert!(json.contains("\"command\":\"cargo build\""));
        assert!(json.contains("\"heartbeat_phase\":\"execute\""));
        assert!(json.contains("\"heartbeat_counter\":9"));
        assert!(json.contains("\"detector_confidence\":0.91"));
    }

    #[test]
    fn test_queued_build_serialization() {
        let _guard = test_guard!();
        let build = QueuedBuild {
            id: (1_u64 << 63) + 1,
            id_text: "9223372036854775809".to_string(),
            project_id: "test".to_string(),
            command: "cargo test".to_string(),
            queued_at: "2025-01-01T00:00:00Z".to_string(),
            position: 1,
            slots_needed: 4,
            estimated_start: Some("2025-01-01T00:01:00Z".to_string()),
            wait_time: "1m 30s".to_string(),
        };
        let json = serde_json::to_string(&build).unwrap();
        assert!(json.contains("\"id\":9223372036854775809"));
        assert!(json.contains("\"id_text\":\"9223372036854775809\""));
        assert!(json.contains("\"position\":1"));
        assert!(json.contains("\"slots_needed\":4"));
        assert!(json.contains("\"wait_time\":\"1m 30s\""));
    }

    #[test]
    fn test_issue_serialization() {
        let _guard = test_guard!();
        let issue = Issue {
            severity: "warning".to_string(),
            summary: "Worker w1 is unreachable".to_string(),
            remediation: Some("rch doctor".to_string()),
            worker_id: None,
        };
        let json = serde_json::to_string(&issue).unwrap();
        assert!(json.contains("\"severity\":\"warning\""));
        assert!(json.contains("\"remediation\":\"rch doctor\""));
        // Daemon-level issues keep their pre-existing wire shape.
        assert!(!json.contains("worker_id"));

        let worker_scoped = Issue {
            worker_id: Some("w1".to_string()),
            ..issue
        };
        let json = serde_json::to_string(&worker_scoped).unwrap();
        assert!(json.contains("\"worker_id\":\"w1\""));
    }

    #[test]
    fn test_cancel_build_response_serialization() {
        let _guard = test_guard!();
        let response = CancelBuildResponse {
            status: "cancelled".to_string(),
            build_id: 123,
            worker_id: Some("worker1".to_string()),
            project_id: Some("test".to_string()),
            message: Some("Build cancelled".to_string()),
            slots_released: 4,
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"build_id\":123"));
        assert!(json.contains("\"slots_released\":4"));
    }

    #[test]
    fn test_cancel_all_builds_response_serialization() {
        let _guard = test_guard!();
        let response = CancelAllBuildsResponse {
            status: "ok".to_string(),
            cancelled_count: 2,
            cancelled: vec![CancelledBuildInfo {
                build_id: 1,
                worker_id: "w1".to_string(),
                project_id: "p1".to_string(),
                slots_released: 4,
            }],
            message: None,
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"cancelled_count\":2"));
    }

    #[test]
    fn test_worker_state_response_serialization() {
        let _guard = test_guard!();
        let response = WorkerStateResponse {
            status: "ok".to_string(),
            worker_id: "worker1".to_string(),
            action: "drain".to_string(),
            new_status: Some("draining".to_string()),
            reason: None,
            message: Some("Worker draining started".to_string()),
            active_slots: Some(4),
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"action\":\"drain\""));
        assert!(json.contains("\"new_status\":\"draining\""));
    }

    #[test]
    fn test_speedscore_view_serialization() {
        let _guard = test_guard!();
        let view = SpeedScoreView {
            total: 85.5,
            cpu_score: 90.0,
            memory_score: 80.0,
            disk_score: 85.0,
            network_score: 88.0,
            compilation_score: 82.0,
            measured_at: "2025-01-01T00:00:00Z".to_string(),
            version: 1,
        };
        let json = serde_json::to_string(&view).unwrap();
        assert!(json.contains("\"total\":85.5"));
        assert!(json.contains("\"cpu_score\":90"));
    }

    #[test]
    fn test_speedscore_response_serialization() {
        let _guard = test_guard!();
        let response = SpeedScoreResponse {
            worker_id: "worker1".to_string(),
            speedscore: None,
            message: Some("No speedscore available".to_string()),
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"worker_id\":\"worker1\""));
    }

    #[test]
    fn test_pagination_info_serialization() {
        let _guard = test_guard!();
        let info = PaginationInfo {
            total: 100,
            offset: 10,
            limit: 20,
            has_more: true,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"total\":100"));
        assert!(json.contains("\"has_more\":true"));
    }

    #[test]
    fn test_benchmark_trigger_response_serialization() {
        let _guard = test_guard!();
        let response = BenchmarkTriggerResponse {
            status: "queued".to_string(),
            worker_id: "worker1".to_string(),
            request_id: "abc-123".to_string(),
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"status\":\"queued\""));
        assert!(json.contains("\"request_id\":\"abc-123\""));
    }

    // =========================================================================
    // API request parsing tests (additional endpoints)
    // =========================================================================

    #[test]
    fn test_parse_request_health() {
        let _guard = test_guard!();
        let req = parse_request("GET /health").unwrap();
        assert!(matches!(req, ApiRequest::Health));
    }

    #[test]
    fn test_parse_request_ready() {
        let _guard = test_guard!();
        let req = parse_request("GET /ready").unwrap();
        assert!(matches!(req, ApiRequest::Ready));
    }

    #[test]
    fn test_parse_request_metrics() {
        let _guard = test_guard!();
        let req = parse_request("GET /metrics").unwrap();
        assert!(matches!(req, ApiRequest::Metrics));
    }

    #[test]
    fn test_parse_request_budget() {
        let _guard = test_guard!();
        let req = parse_request("GET /budget").unwrap();
        assert!(matches!(req, ApiRequest::Budget));
    }

    #[test]
    fn test_parse_request_shutdown() {
        let _guard = test_guard!();
        assert!(parse_request("POST /shutdown").is_err());
        let query = format!(
            "daemon_incarnation={}&token={}",
            Uuid::new_v4(),
            Uuid::new_v4()
        );
        let req = parse_request(&format!("POST /shutdown?{query}")).unwrap();
        assert!(matches!(req, ApiRequest::Shutdown { force: false, .. }));
        let req = parse_request(&format!("POST /shutdown?{query}&force=true")).unwrap();
        assert!(matches!(req, ApiRequest::Shutdown { force: true, .. }));
    }

    #[test]
    fn test_parse_request_restart_admission_routes() {
        let _guard = test_guard!();
        let query = format!(
            "daemon_incarnation={}&token={}",
            Uuid::new_v4(),
            Uuid::new_v4()
        );
        let owner_record = "6a5a0649-d23a-4d74-b542-85f5e69de721:42";
        assert!(parse_request("POST /restart-admission").is_err());
        assert!(parse_request("POST /restart-admission/release").is_err());
        assert!(parse_request(&format!("POST /restart-admission?{query}")).is_err());
        assert!(matches!(
            parse_request(&format!(
                "POST /restart-admission?{query}&owner_identity={owner_record}"
            ))
            .unwrap(),
            ApiRequest::RestartAdmission {
                action: MaintenanceAction::Acquire { owner_identity, .. },
                ..
            } if owner_identity.to_record().as_deref() == Some(owner_record)
        ));
        assert!(matches!(
            parse_request(&format!("POST /restart-admission/release?{query}")).unwrap(),
            ApiRequest::RestartAdmission {
                action: MaintenanceAction::Release,
                ..
            }
        ));
        assert!(matches!(
            parse_request(&format!("POST /restart-admission/renew?{query}")).unwrap(),
            ApiRequest::RestartAdmission {
                action: MaintenanceAction::Renew,
                ..
            }
        ));
        assert!(matches!(
            parse_request(&format!("POST /restart-admission/recover?{query}")).unwrap(),
            ApiRequest::RestartAdmission {
                action: MaintenanceAction::Recover,
                ..
            }
        ));
        assert!(matches!(
            parse_request("GET /restart-admission").unwrap(),
            ApiRequest::RestartAdmissionStatus
        ));
        assert!(
            parse_request(&format!(
                "POST /restart-admission?{query}&token={}",
                Uuid::new_v4()
            ))
            .is_err()
        );
        assert!(parse_request("POST /restart-admission?daemon_incarnation=bad&token=bad").is_err());
        for record in [
            "",
            "unknown",
            "6a5a0649-d23a-4d74-b542-85f5e69de721:042",
            "6a5a0649-d23a-4d74-b542-85f5e69de721:darwin:100:1000000",
        ] {
            assert!(
                parse_request(&format!(
                    "POST /restart-admission?{query}&owner_identity={record}"
                ))
                .is_err()
            );
        }
        assert!(
            parse_request(&format!(
                "POST /restart-admission?{query}&owner_identity={owner_record}&owner_identity={owner_record}"
            ))
            .is_err()
        );
        for endpoint in [
            "/shutdown",
            "/restart-admission/renew",
            "/restart-admission/release",
            "/restart-admission/recover",
        ] {
            assert!(
                parse_request(&format!(
                    "POST {endpoint}?{query}&owner_identity={owner_record}"
                ))
                .is_err()
            );
        }
    }

    #[test]
    fn test_parse_request_cancel_build() {
        let _guard = test_guard!();
        let req = parse_request("POST /builds/123/cancel").unwrap();
        match req {
            ApiRequest::CancelBuild {
                build_id, force, ..
            } => {
                assert_eq!(build_id, 123);
                assert!(!force);
            }
            _ => assert!(false, "expected cancel build request"),
        }

        let req = parse_request("POST /builds/456/cancel?force=true").unwrap();
        match req {
            ApiRequest::CancelBuild {
                build_id, force, ..
            } => {
                assert_eq!(build_id, 456);
                assert!(force);
            }
            _ => assert!(false, "expected cancel build request with force"),
        }
    }

    #[test]
    fn test_parse_request_cancel_all_builds() {
        let _guard = test_guard!();
        let req = parse_request("POST /builds/cancel-all").unwrap();
        match req {
            ApiRequest::CancelAllBuilds { force } => {
                assert!(!force);
            }
            _ => assert!(false, "expected cancel all builds request"),
        }

        let req = parse_request("POST /builds/cancel-all?force=true").unwrap();
        match req {
            ApiRequest::CancelAllBuilds { force } => {
                assert!(force);
            }
            _ => assert!(false, "expected cancel all builds with force"),
        }
    }

    #[test]
    fn test_parse_request_worker_drain() {
        let _guard = test_guard!();
        let req = parse_request("POST /workers/css/drain").unwrap();
        match req {
            ApiRequest::WorkerDrain { worker_id } => {
                assert_eq!(worker_id.as_str(), "css");
            }
            _ => assert!(false, "expected worker drain request"),
        }
    }

    #[test]
    fn test_parse_request_worker_enable() {
        let _guard = test_guard!();
        let req = parse_request("POST /workers/css/enable").unwrap();
        match req {
            ApiRequest::WorkerEnable { worker_id } => {
                assert_eq!(worker_id.as_str(), "css");
            }
            _ => assert!(false, "expected worker enable request"),
        }
    }

    #[test]
    fn test_parse_request_worker_disable() {
        let _guard = test_guard!();
        let req = parse_request("POST /workers/css/disable").unwrap();
        match req {
            ApiRequest::WorkerDisable {
                worker_id,
                reason,
                drain_first,
            } => {
                assert_eq!(worker_id.as_str(), "css");
                assert!(reason.is_none());
                assert!(!drain_first);
            }
            _ => assert!(false, "expected worker disable request"),
        }

        let req = parse_request("POST /workers/css/disable?reason=maintenance&drain=true").unwrap();
        match req {
            ApiRequest::WorkerDisable {
                worker_id,
                reason,
                drain_first,
            } => {
                assert_eq!(worker_id.as_str(), "css");
                assert_eq!(reason, Some("maintenance".to_string()));
                assert!(drain_first);
            }
            _ => assert!(false, "expected worker disable request with options"),
        }
    }

    #[test]
    fn test_parse_request_release_worker() {
        let _guard = test_guard!();
        let req = parse_request("POST /release-worker?worker=css&slots=4").unwrap();
        match req {
            ApiRequest::ReleaseWorker(req) => {
                assert_eq!(req.worker_id.as_str(), "css");
                assert_eq!(req.slots, 4);
            }
            _ => assert!(false, "expected release worker request"),
        }
    }

    #[test]
    fn test_parse_request_release_worker_with_build_id() {
        let _guard = test_guard!();
        let req = parse_request("POST /release-worker?worker=css&slots=4&build_id=123").unwrap();
        match req {
            ApiRequest::ReleaseWorker(req) => {
                assert_eq!(req.worker_id.as_str(), "css");
                assert_eq!(req.slots, 4);
                assert_eq!(req.build_id, Some(123));
            }
            _ => assert!(false, "expected release worker request with build_id"),
        }
    }

    #[test]
    fn test_parse_request_release_worker_with_exit_code() {
        let _guard = test_guard!();
        let req = parse_request("POST /release-worker?worker=css&slots=4&exit_code=0").unwrap();
        match req {
            ApiRequest::ReleaseWorker(req) => {
                assert_eq!(req.exit_code, Some(0));
            }
            _ => assert!(false, "expected release worker request with exit_code"),
        }
    }

    #[test]
    fn test_parse_request_release_worker_fault_flag() {
        let _guard = test_guard!();
        for (query, expected) in [
            ("&exit_code=101&worker_fault=1", true),
            ("&exit_code=101&worker_fault=true", true),
            ("&exit_code=101&worker_fault=0", false),
            ("&exit_code=101", false),
        ] {
            let req =
                parse_request(&format!("POST /release-worker?worker=css&slots=4{query}")).unwrap();
            let ApiRequest::ReleaseWorker(req) = req else {
                unreachable!("expected release worker request for {query}");
            };
            assert_eq!(req.worker_fault, expected, "{query}");
        }
    }

    #[test]
    fn test_parse_release_disk_peak_requires_one_unsigned_measurement() {
        let ApiRequest::ReleaseWorker(request) = parse_request(
            "POST /release-worker?worker=hz3&exit_code=0&disk_peak_output_bytes=22548578304",
        )
        .unwrap() else {
            panic!("expected release")
        };
        assert_eq!(
            request.disk_peak_output_bytes,
            Some(21 * rch_common::BuildDiskBudget::GIB),
        );
        for suffix in [
            "-1",
            "NaN",
            "18446744073709551616",
            "1&disk_peak_output_bytes=2",
        ] {
            assert!(
                parse_request(&format!(
                    "POST /release-worker?worker=hz3&exit_code=0&disk_peak_output_bytes={suffix}",
                ))
                .is_err(),
            );
        }
    }

    #[test]
    fn disk_peak_requires_an_explicit_unambiguous_terminal_status() {
        for status in ["", "&exit_code=bad", "&exit_code=1&exit_code=0"] {
            assert!(
                parse_request(&format!(
                    "POST /release-worker?worker=hz3{status}&disk_peak_output_bytes=2147483648",
                ))
                .is_err()
            );
        }
    }

    #[test]
    fn test_parse_request_record_build() {
        let _guard = test_guard!();
        let req =
            parse_request("POST /record-build?worker=css&project=myproject&is_test=true").unwrap();
        match req {
            ApiRequest::RecordBuild {
                worker_id,
                project,
                is_test,
            } => {
                assert_eq!(worker_id.as_str(), "css");
                assert_eq!(project, "myproject");
                assert!(is_test);
            }
            _ => assert!(false, "expected record build request"),
        }
    }

    #[test]
    fn test_parse_request_ingest_telemetry() {
        let _guard = test_guard!();
        let req = parse_request("POST /telemetry/ingest?source=piggyback").unwrap();
        match req {
            ApiRequest::IngestTelemetry(source) => {
                assert_eq!(source, TelemetrySource::Piggyback);
            }
            _ => assert!(false, "expected ingest telemetry request"),
        }

        let req = parse_request("POST /telemetry/ingest?source=ssh_poll").unwrap();
        match req {
            ApiRequest::IngestTelemetry(source) => {
                assert_eq!(source, TelemetrySource::SshPoll);
            }
            _ => assert!(false, "expected ingest telemetry request"),
        }
    }

    #[test]
    fn test_parse_request_wait_for_worker() {
        let _guard = test_guard!();
        let req = parse_request("GET /select-worker?project=test&wait=true&wait_timeout_secs=45")
            .unwrap();
        match req {
            ApiRequest::SelectWorker {
                wait_for_worker,
                wait_timeout_secs,
                ..
            } => {
                assert!(wait_for_worker);
                assert_eq!(wait_timeout_secs, Some(45));
            }
            _ => assert!(false, "expected select worker request"),
        }

        let req = parse_request("GET /select-worker?project=test&wait=false").unwrap();
        match req {
            ApiRequest::SelectWorker {
                wait_for_worker,
                wait_timeout_secs,
                ..
            } => {
                assert!(!wait_for_worker);
                assert_eq!(wait_timeout_secs, None);
            }
            _ => assert!(false, "expected select worker request"),
        }

        let req = parse_request("GET /select-worker?project=test&wait_timeout_secs=0").unwrap();
        match req {
            ApiRequest::SelectWorker {
                wait_timeout_secs, ..
            } => {
                assert_eq!(wait_timeout_secs, None);
            }
            _ => assert!(false, "expected select worker request"),
        }
    }

    // =========================================================================
    // Handler tests
    // =========================================================================

    #[tokio::test]
    async fn test_handle_ready_with_available_workers() {
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("worker1", 8)).await;
        let ctx = make_test_context(pool);

        let response = handle_ready(&ctx).await;
        assert_eq!(response.status, "ready");
        assert!(response.workers_available);
        assert!(response.reason.is_none());
    }

    #[tokio::test]
    async fn test_handle_ready_no_workers() {
        let pool = WorkerPool::new();
        let ctx = make_test_context(pool);

        let response = handle_ready(&ctx).await;
        assert_eq!(response.status, "not_ready");
        assert!(!response.workers_available);
        assert!(response.reason.is_some());
    }

    #[tokio::test]
    async fn test_handle_ready_all_slots_used() {
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("worker1", 4)).await;

        // Reserve all slots
        let worker = pool.get(&WorkerId::new("worker1")).await.unwrap();
        worker.reserve_slots(4).await;

        let ctx = make_test_context(pool);
        let response = handle_ready(&ctx).await;
        assert_eq!(response.status, "not_ready");
        assert!(!response.workers_available);
    }

    #[tokio::test]
    async fn test_handle_ready_ignores_non_assignable_workers_with_free_slots() {
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("drained", 4)).await;
        pool.add_worker(make_test_worker("disabled", 4)).await;
        pool.add_worker(make_test_worker("unreachable", 4)).await;
        pool.set_status(&WorkerId::new("drained"), WorkerStatus::Drained)
            .await;
        pool.set_status(&WorkerId::new("disabled"), WorkerStatus::Disabled)
            .await;
        pool.set_status(&WorkerId::new("unreachable"), WorkerStatus::Unreachable)
            .await;
        let ctx = make_test_context(pool);

        let response = handle_ready(&ctx).await;
        assert_eq!(response.status, "not_ready");
        assert!(!response.workers_available);
        assert_eq!(response.reason.as_deref(), Some("no_workers_available"));
    }

    #[tokio::test]
    async fn test_handle_ready_ignores_open_circuit_workers_with_free_slots() {
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("worker1", 4)).await;
        let worker = pool
            .get(&WorkerId::new("worker1"))
            .await
            .expect("worker should exist");
        worker.open_circuit().await;
        let ctx = make_test_context(pool);

        let response = handle_ready(&ctx).await;
        assert_eq!(response.status, "not_ready");
        assert!(!response.workers_available);
        assert_eq!(response.reason.as_deref(), Some("no_workers_available"));
    }

    #[tokio::test]
    async fn test_handle_cancel_build_not_found() {
        let pool = WorkerPool::new();
        let ctx = make_test_context(pool);

        let response = handle_cancel_build(&ctx, 9999, false).await;
        assert_eq!(response.status, "error");
        assert_eq!(response.build_id, 9999);
        assert!(response.message.unwrap().contains("not found"));
        assert_eq!(response.slots_released, 0);
    }

    #[tokio::test]
    async fn test_handle_cancel_all_builds_empty() {
        let pool = WorkerPool::new();
        let ctx = make_test_context(pool);

        let response = handle_cancel_all_builds(&ctx, false).await;
        assert_eq!(response.status, "ok");
        assert_eq!(response.cancelled_count, 0);
        assert!(response.cancelled.is_empty());
    }

    #[test]
    fn ownership_mismatch_names_the_owner_and_what_works() {
        let owned = ownership_mismatch_message(7, Some(Some("rchw-abc")));
        assert!(owned.contains("rchw-abc"), "{owned}");
        assert!(owned.contains("rch jobs cancel rchw-abc"), "{owned}");
        assert!(owned.contains("6h"), "{owned}");
        let anonymous = ownership_mismatch_message(7, Some(None));
        assert!(anonymous.contains("no wrapper identity"), "{anonymous}");
        let done = ownership_mismatch_message(7, None);
        assert!(done.contains("already completed"), "{done}");
        for message in [owned, anonymous, done] {
            assert!(message.starts_with("build ownership mismatch"), "{message}");
        }
    }

    #[tokio::test]
    async fn describe_caller_names_the_calling_process() {
        let pid = std::process::id();
        let described = describe_caller(pid as i32).await;
        assert!(described.starts_with(&format!("pid={pid} ")), "{described}");
        assert!(
            described.contains("cmd=") && described.contains("parent="),
            "{described}"
        );
        // A pid that cannot exist still yields an attributable line, not a hang.
        assert_eq!(describe_caller(i32::MAX).await, format!("pid={}", i32::MAX));
    }

    #[tokio::test]
    async fn test_handle_worker_drain_not_found() {
        let pool = WorkerPool::new();
        let ctx = make_test_context(pool);

        let response = handle_worker_drain(&ctx, &WorkerId::new("nonexistent")).await;
        assert_eq!(response.status, "error");
        assert!(response.message.unwrap().contains("not found"));
    }

    #[tokio::test]
    async fn test_handle_worker_drain_success() {
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("worker1", 8)).await;
        let ctx = make_test_context(pool);

        let response = handle_worker_drain(&ctx, &WorkerId::new("worker1")).await;
        assert_eq!(response.status, "ok");
        assert_eq!(response.worker_id, "worker1");
        assert_eq!(response.action, "drain");
        assert_eq!(response.new_status, Some("drained".to_string()));
    }

    #[tokio::test]
    async fn test_handle_worker_enable_not_found() {
        let pool = WorkerPool::new();
        let ctx = make_test_context(pool);

        let response = handle_worker_enable(&ctx, &WorkerId::new("nonexistent")).await;
        assert_eq!(response.status, "error");
        assert!(response.message.unwrap().contains("not found"));
    }

    #[tokio::test]
    async fn test_handle_worker_enable_success() {
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("worker1", 8)).await;
        // Set to draining first
        pool.set_status(&WorkerId::new("worker1"), WorkerStatus::Draining)
            .await;
        let ctx = make_test_context(pool);

        let response = handle_worker_enable(&ctx, &WorkerId::new("worker1")).await;
        assert_eq!(response.status, "ok");
        assert_eq!(response.worker_id, "worker1");
        assert_eq!(response.action, "enable");
        assert_eq!(response.new_status, Some("healthy".to_string()));
    }

    #[tokio::test]
    async fn test_handle_worker_disable_not_found() {
        let pool = WorkerPool::new();
        let ctx = make_test_context(pool);

        let response =
            handle_worker_disable(&ctx, &WorkerId::new("nonexistent"), None, false).await;
        assert_eq!(response.status, "error");
        assert!(response.message.unwrap().contains("not found"));
    }

    #[tokio::test]
    async fn test_handle_worker_disable_success() {
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("worker1", 8)).await;
        let ctx = make_test_context(pool);

        let response = handle_worker_disable(
            &ctx,
            &WorkerId::new("worker1"),
            Some("maintenance".to_string()),
            false,
        )
        .await;
        assert_eq!(response.status, "ok");
        assert_eq!(response.worker_id, "worker1");
        assert_eq!(response.action, "disable");
        assert_eq!(response.new_status, Some("disabled".to_string()));
    }

    #[tokio::test]
    async fn test_handle_worker_disable_with_drain() {
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("worker1", 8)).await;
        let ctx = make_test_context(pool);

        // Simulate an active build so drain_first takes the draining branch.
        let worker = ctx.pool.get(&WorkerId::new("worker1")).await.unwrap();
        assert!(worker.reserve_slots(1).await);

        let response = handle_worker_disable(&ctx, &WorkerId::new("worker1"), None, true).await;
        assert_eq!(response.status, "ok");
        assert_eq!(response.action, "disable");
        // When drain_first is true, should set to draining first
        assert_eq!(response.new_status, Some("draining".to_string()));
    }

    #[tokio::test]
    async fn test_worker_disable_persists_durable_record_and_enable_removes_it() {
        use rch_common::bypass_record::AdminDisableStore;

        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("worker1", 8)).await;
        let mut ctx = make_test_context(pool);
        let dir = tempfile::tempdir().unwrap();
        let store_path = dir.path().join("admin_disables.json");
        ctx.admin_disable_store = Some(Arc::new(tokio::sync::Mutex::new(
            AdminDisableStore::with_path(&store_path),
        )));

        let response = handle_worker_disable(
            &ctx,
            &WorkerId::new("worker1"),
            Some("cpu-capability-fault (SIGILL)".to_string()),
            false,
        )
        .await;
        assert_eq!(response.status, "ok");

        // A fresh load from disk is the restart-survival property under test.
        let reloaded = AdminDisableStore::load(&store_path);
        assert_eq!(
            reloaded
                .get("worker1")
                .expect("record persisted")
                .reason
                .as_deref(),
            Some("cpu-capability-fault (SIGILL)"),
        );

        let response = handle_worker_enable(&ctx, &WorkerId::new("worker1")).await;
        assert_eq!(response.status, "ok");
        assert!(
            AdminDisableStore::load(&store_path)
                .get("worker1")
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_worker_disable_with_drain_also_persists_durable_record() {
        use rch_common::bypass_record::AdminDisableStore;

        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("worker1", 8)).await;
        let mut ctx = make_test_context(pool);
        let dir = tempfile::tempdir().unwrap();
        let store_path = dir.path().join("admin_disables.json");
        ctx.admin_disable_store = Some(Arc::new(tokio::sync::Mutex::new(
            AdminDisableStore::with_path(&store_path),
        )));

        let worker = ctx.pool.get(&WorkerId::new("worker1")).await.unwrap();
        assert!(worker.reserve_slots(1).await);
        let response = handle_worker_disable(&ctx, &WorkerId::new("worker1"), None, true).await;
        assert_eq!(response.new_status, Some("draining".to_string()));

        // The intent is durable even while the worker is still draining.
        assert!(
            AdminDisableStore::load(&store_path)
                .get("worker1")
                .is_some()
        );
    }

    // =========================================================================
    // Worker capabilities info tests
    // =========================================================================

    #[test]
    fn test_worker_capabilities_info_serialization() {
        let _guard = test_guard!();
        let info = WorkerCapabilitiesInfo {
            id: "worker1".to_string(),
            host: "localhost".to_string(),
            user: "test".to_string(),
            capabilities: WorkerCapabilities::default(),
            pressure_assessment: crate::disk_pressure::PressureAssessment::default(),
            refresh: None,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"id\":\"worker1\""));
    }

    #[test]
    fn test_worker_capabilities_response_serialization() {
        let _guard = test_guard!();
        let response = WorkerCapabilitiesResponse { workers: vec![] };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"workers\":[]"));
    }

    // =========================================================================
    // Self-test response types tests
    // =========================================================================

    #[test]
    fn test_self_test_status_response_serialization() {
        let _guard = test_guard!();
        let response = SelfTestStatusResponse {
            enabled: true,
            schedule: Some("daily".to_string()),
            interval: Some("24h".to_string()),
            last_run: None,
            next_run: Some("2025-01-02T00:00:00Z".to_string()),
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"enabled\":true"));
        assert!(json.contains("\"schedule\":\"daily\""));
    }

    // =========================================================================
    // SpeedScore list response tests
    // =========================================================================

    #[test]
    fn test_speedscore_list_response_serialization() {
        let _guard = test_guard!();
        let response = SpeedScoreListResponse {
            workers: vec![SpeedScoreWorker {
                worker_id: "worker1".to_string(),
                speedscore: None,
                status: WorkerStatus::Healthy,
            }],
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"worker_id\":\"worker1\""));
    }

    #[test]
    fn test_speedscore_history_response_serialization() {
        let _guard = test_guard!();
        let response = SpeedScoreHistoryResponse {
            worker_id: "worker1".to_string(),
            history: vec![],
            pagination: PaginationInfo {
                total: 0,
                offset: 0,
                limit: 20,
                has_more: false,
            },
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"worker_id\":\"worker1\""));
        assert!(json.contains("\"has_more\":false"));
    }

    #[test]
    fn test_selection_response_json_includes_protocol_version() {
        let _guard = test_guard!();
        let response = SelectionResponse {
            worker: None,
            reason: SelectionReason::AllWorkersBusy,
            build_id: None,
            diagnostics: None,
        };

        let json = selection_response_json(&response).expect("selection response serializes");
        let value: serde_json::Value = serde_json::from_str(&json).expect("valid json");

        assert_eq!(
            value["selection_protocol_version"],
            rch_common::SELECTION_RESPONSE_PROTOCOL_VERSION
        );
        assert_eq!(value["reason"], "all_workers_busy");
    }

    // =========================================================================
    // ApiResponse tests
    // =========================================================================

    #[test]
    fn test_api_response_ok_serialization() {
        let _guard = test_guard!();
        let response: ApiResponse<HealthResponse> = ApiResponse::Ok(HealthResponse {
            status: "healthy".to_string(),
            version: "1.0.0".to_string(),
            uptime_seconds: 100,
        });
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"status\":\"healthy\""));
    }

    #[test]
    fn test_api_response_error_serialization() {
        let _guard = test_guard!();
        let response: ApiResponse<HealthResponse> =
            ApiResponse::Error(ApiError::new(ErrorCode::ConfigNotFound, "Not found"));
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"details\":\"Not found\""));
    }

    // =========================================================================
    // Telemetry poll tests
    // =========================================================================

    #[tokio::test]
    async fn test_handle_telemetry_poll_worker_not_found() {
        let pool = WorkerPool::new();
        let ctx = make_test_context(pool);

        let response = handle_telemetry_poll(&ctx, &WorkerId::new("nonexistent")).await;
        assert!(response.error.is_some());
        assert!(response.error.unwrap().contains("not found"));
    }

    #[tokio::test]
    async fn test_handle_speedscore_worker_not_found() {
        let pool = WorkerPool::new();
        let ctx = make_test_context(pool);

        let response = handle_speedscore(&ctx, &WorkerId::new("nonexistent")).await;
        match response {
            ApiResponse::Error(e) => {
                assert!(
                    e.details
                        .as_deref()
                        .unwrap_or_default()
                        .contains("not found")
                );
            }
            _ => assert!(false, "expected error response"),
        }
    }

    #[tokio::test]
    async fn test_handle_speedscore_success() {
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("worker1", 8)).await;
        let ctx = make_test_context(pool);

        let response = handle_speedscore(&ctx, &WorkerId::new("worker1")).await;
        match response {
            ApiResponse::Ok(r) => {
                assert_eq!(r.worker_id, "worker1");
                // No speedscore initially
                assert!(r.speedscore.is_none());
            }
            _ => assert!(false, "expected ok response"),
        }
    }

    #[tokio::test]
    async fn test_handle_speedscore_list() {
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("worker1", 8)).await;
        pool.add_worker(make_test_worker("worker2", 4)).await;
        let ctx = make_test_context(pool);

        let response = handle_speedscore_list(&ctx).await;
        match response {
            ApiResponse::Ok(r) => {
                assert_eq!(r.workers.len(), 2);
            }
            _ => assert!(false, "expected ok response"),
        }
    }

    #[tokio::test]
    async fn test_handle_benchmark_trigger_worker_not_found() {
        let pool = WorkerPool::new();
        let ctx = make_test_context(pool);

        let response = handle_benchmark_trigger(&ctx, &WorkerId::new("nonexistent")).await;
        match response {
            ApiResponse::Error(e) => {
                assert!(
                    e.details
                        .as_deref()
                        .unwrap_or_default()
                        .contains("not found")
                );
            }
            _ => assert!(false, "expected error response"),
        }
    }

    #[tokio::test]
    async fn test_handle_benchmark_trigger_success() {
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("worker1", 8)).await;
        let ctx = make_test_context(pool);

        let response = handle_benchmark_trigger(&ctx, &WorkerId::new("worker1")).await;
        match response {
            ApiResponse::Ok(r) => {
                assert_eq!(r.status, "queued");
                assert_eq!(r.worker_id, "worker1");
                assert!(!r.request_id.is_empty());
            }
            _ => assert!(false, "expected ok response"),
        }
    }

    #[tokio::test]
    async fn test_handle_benchmark_trigger_rate_limited() {
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("worker1", 8)).await;
        let ctx = make_test_context(pool);

        let first = handle_benchmark_trigger(&ctx, &WorkerId::new("worker1")).await;
        assert!(matches!(first, ApiResponse::Ok(_)));

        let second = handle_benchmark_trigger(&ctx, &WorkerId::new("worker1")).await;
        match second {
            ApiResponse::Error(err) => {
                assert!(
                    err.details
                        .as_deref()
                        .unwrap_or_default()
                        .contains("rate limited")
                );
                assert!(err.retry_after_secs.is_some());
            }
            _ => assert!(false, "expected rate-limited error response"),
        }
    }

    // =========================================================================
    // SpeedScore history tests
    // =========================================================================

    #[tokio::test]
    async fn test_handle_speedscore_history_worker_not_found() {
        let _guard = test_guard!();
        let pool = WorkerPool::new();
        let ctx = make_test_context(pool);

        let response =
            handle_speedscore_history(&ctx, &WorkerId::new("nonexistent"), 7, 20, 0).await;
        match response {
            ApiResponse::Error(e) => {
                assert!(
                    e.details
                        .as_deref()
                        .unwrap_or_default()
                        .contains("not found")
                );
            }
            _ => assert!(false, "expected error response"),
        }
    }

    #[tokio::test]
    async fn test_handle_speedscore_history_success_empty() {
        let _guard = test_guard!();
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("worker1", 8)).await;
        let ctx = make_test_context(pool);

        let response = handle_speedscore_history(&ctx, &WorkerId::new("worker1"), 7, 20, 0).await;
        match response {
            ApiResponse::Ok(r) => {
                assert_eq!(r.worker_id, "worker1");
                assert!(r.history.is_empty()); // No history entries yet
                assert!(!r.pagination.has_more);
            }
            _ => assert!(false, "expected ok response"),
        }
    }

    #[tokio::test]
    async fn test_handle_speedscore_history_clamps_days() {
        let _guard = test_guard!();
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("worker1", 8)).await;
        let ctx = make_test_context(pool);

        // Request 0 days - should be clamped to 1
        let response = handle_speedscore_history(&ctx, &WorkerId::new("worker1"), 0, 20, 0).await;
        match response {
            ApiResponse::Ok(r) => {
                assert_eq!(r.worker_id, "worker1");
            }
            _ => assert!(false, "expected ok response"),
        }

        // Request 1000 days - should be clamped to 365
        let response =
            handle_speedscore_history(&ctx, &WorkerId::new("worker1"), 1000, 20, 0).await;
        match response {
            ApiResponse::Ok(r) => {
                assert_eq!(r.worker_id, "worker1");
            }
            _ => assert!(false, "expected ok response"),
        }
    }

    #[tokio::test]
    async fn test_handle_speedscore_history_clamps_limit() {
        let _guard = test_guard!();
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("worker1", 8)).await;
        let ctx = make_test_context(pool);

        // Request limit of 0 - should be clamped to 1
        let response = handle_speedscore_history(&ctx, &WorkerId::new("worker1"), 7, 0, 0).await;
        match response {
            ApiResponse::Ok(r) => {
                assert_eq!(r.pagination.limit, 1);
            }
            _ => assert!(false, "expected ok response"),
        }

        // Request limit of 5000 - should be clamped to 1000
        let response = handle_speedscore_history(&ctx, &WorkerId::new("worker1"), 7, 5000, 0).await;
        match response {
            ApiResponse::Ok(r) => {
                assert_eq!(r.pagination.limit, 1000);
            }
            _ => assert!(false, "expected ok response"),
        }
    }

    // =========================================================================
    // Workers capabilities tests
    // =========================================================================

    #[tokio::test]
    async fn test_handle_workers_capabilities_empty_pool() {
        let _guard = test_guard!();
        let pool = WorkerPool::new();
        let ctx = make_test_context(pool);

        let response = handle_workers_capabilities(&ctx, false).await;
        match response {
            ApiResponse::Ok(r) => {
                assert!(r.workers.is_empty());
            }
            _ => assert!(false, "expected ok response"),
        }
    }

    #[tokio::test]
    async fn test_handle_workers_capabilities_with_workers() {
        let _guard = test_guard!();
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("worker1", 8)).await;
        pool.add_worker(make_test_worker("worker2", 4)).await;
        let ctx = make_test_context(pool);

        let response = handle_workers_capabilities(&ctx, false).await;
        match response {
            ApiResponse::Ok(r) => {
                assert_eq!(r.workers.len(), 2);
                // Check worker info is populated
                let w1 = r.workers.iter().find(|w| w.id == "worker1").unwrap();
                assert_eq!(w1.host, "localhost");
                assert_eq!(w1.user, "user");
            }
            _ => assert!(false, "expected ok response"),
        }
    }

    // =========================================================================
    // Release worker tests
    // =========================================================================

    #[tokio::test]
    async fn disk_full_release_quarantines_only_the_completed_build_owner() {
        let _guard = test_guard!();
        for (exit, flag, request_worker, wrapper, quarantine) in [
            (101, true, "worker1", "owner", true),
            (0, true, "worker1", "owner", false),
            (101, false, "worker1", "owner", false),
            (101, true, "worker2", "owner", false),
            (101, true, "worker1", "wrong-owner", false),
        ] {
            let pool = WorkerPool::new();
            pool.add_worker(make_test_worker("worker1", 8)).await;
            pool.add_worker(make_test_worker("worker2", 8)).await;
            let mut ctx = make_test_context(pool.clone());
            let directory = tempfile::tempdir().unwrap();
            let store_path = directory.path().join("bypasses.json");
            let store = Arc::new(tokio::sync::Mutex::new(BypassRecordStore::with_path(
                &store_path,
            )));
            ctx.bypass_store = Some(store.clone());
            let worker = pool.get(&WorkerId::new("worker1")).await.unwrap();
            let build = ctx
                .history
                .try_start_active_build_with_waiter(
                    "disk-project".into(),
                    "worker1".into(),
                    "cargo build".into(),
                    12345,
                    Some("owner".into()),
                    2,
                    rch_common::BuildLocation::Remote,
                    None,
                    crate::disk_pressure::DiskHeadroomAdmission::default(),
                    Some(worker.endpoint_snapshot().await),
                )
                .unwrap()
                .unwrap();
            assert!(worker.reserve_slots(2).await);
            ctx.history
                .record_build_heartbeat(BuildHeartbeatRequest {
                    build_id: build.id,
                    worker_id: WorkerId::new("worker1"),
                    hook_pid: None,
                    local_wrapper_id: Some("owner".into()),
                    remote_pgid_file: None,
                    phase: rch_common::BuildHeartbeatPhase::Execute,
                    detail: None,
                    progress_counter: Some(1),
                    progress_percent: None,
                })
                .unwrap();
            let request = parse_request(&format!(
                "POST /release-worker?worker={request_worker}&build_id={}&local_wrapper_id={wrapper}&exit_code={exit}&worker_disk_full={flag}&worker_disk_roots=%5B%22%2Fbuild-volume%2Frch%22%5D", build.id
            )).unwrap();
            let ApiRequest::ReleaseWorker(request) = request else {
                panic!("release request expected")
            };
            assert_eq!(request.worker_disk_full, flag);
            assert_eq!(request.worker_disk_roots, ["/build-volume/rch"]);
            let result = handle_release_worker(&ctx, request.clone()).await;
            let owned = request_worker == "worker1" && wrapper == "owner";
            assert_eq!(result.is_ok(), owned, "{request:?}: {result:?}");
            assert_eq!(worker.used_slots(), if owned { 0 } else { 2 });
            assert_eq!(
                worker.lifecycle().await.admin,
                crate::workers::AdminIntent::Active
            );
            assert_eq!(store.lock().await.contains("worker1"), quarantine);
            assert!(!store.lock().await.contains("worker2"));
            if quarantine {
                let persisted = BypassRecordStore::load(&store_path);
                let before = persisted.get("worker1").unwrap().clone();
                assert_eq!(
                    before.failure_class,
                    rch_common::BypassFailureClass::DiskInodePressure
                );
                assert_eq!(before.disk_roots, ["/build-volume/rch"]);
                assert_eq!(
                    worker.eligibility().await,
                    crate::workers::EligibilityState::TemporaryBypass
                );
                worker.apply_health_status(WorkerStatus::Healthy).await;
                assert_eq!(worker.status().await, WorkerStatus::Unreachable);
                pool.get(&WorkerId::new("worker2"))
                    .await
                    .unwrap()
                    .disable(Some("test maintenance".into()))
                    .await;
                assert!(
                    !handle_ready(&ctx).await.workers_available,
                    "quarantined free slots must not advertise ready capacity"
                );
                handle_release_worker(&ctx, request).await.unwrap();
                assert_eq!(
                    store.lock().await.get("worker1"),
                    Some(&before),
                    "duplicate completion must not advance failure backoff"
                );
                assert_eq!(
                    ctx.worker_selector
                        .cache_warmth("worker1", "disk-project", crate::selection::CacheUse::Build)
                        .await,
                    0.0
                );
            } else {
                assert!(worker.lifecycle().await.is_schedulable());
                if owned {
                    assert_eq!(
                        ctx.worker_selector
                            .cache_warmth(
                                "worker1",
                                "disk-project",
                                crate::selection::CacheUse::Build
                            )
                            .await,
                        1.0,
                        "successful builds and ordinary project failures retain useful cache warmth"
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn live_checkout_refusal_keeps_the_project_off_the_owner_worker() {
        // bd-fbtws: (exit, flag, owner, fenced)
        for (exit, flag, wrapper, fenced) in [
            (101, true, "owner", true),
            (0, true, "owner", false),
            (101, false, "owner", false),
            (101, true, "wrong-owner", false),
        ] {
            let pool = WorkerPool::new();
            pool.add_worker(make_test_worker("worker1", 8)).await;
            let ctx = make_test_context(pool.clone());
            let worker = pool.get(&WorkerId::new("worker1")).await.unwrap();
            let build = ctx
                .history
                .try_start_active_build_with_waiter(
                    "live-project".into(),
                    "worker1".into(),
                    "cargo build".into(),
                    12345,
                    Some("owner".into()),
                    2,
                    rch_common::BuildLocation::Remote,
                    None,
                    crate::disk_pressure::DiskHeadroomAdmission::default(),
                    Some(worker.endpoint_snapshot().await),
                )
                .unwrap()
                .unwrap();
            assert!(worker.reserve_slots(2).await);
            let request = parse_request(&format!(
                "POST /release-worker?worker=worker1&build_id={}&local_wrapper_id={wrapper}&exit_code={exit}&worker_live_checkout_refused={}",
                build.id,
                u8::from(flag)
            ))
            .unwrap();
            let ApiRequest::ReleaseWorker(request) = request else {
                panic!("release request expected")
            };
            assert_eq!(request.worker_live_checkout_refused, flag);
            let result = handle_release_worker(&ctx, request).await;
            assert_eq!(result.is_ok(), wrapper == "owner", "{result:?}");
            // A refused release keeps the build active, which excludes the
            // worker on its own; the fence is what outlives completion.
            assert_eq!(
                ctx.history
                    .live_checkout_fenced_workers("live-project")
                    .contains("worker1"),
                fenced
            );
            if fenced {
                assert!(project_excluded_workers(&ctx, "live-project").contains("worker1"));
            }
            assert!(project_excluded_workers(&ctx, "other-project").is_empty());
        }
    }

    #[tokio::test]
    async fn source_busy_release_keeps_the_project_off_that_worker() {
        // bd-p3kuz: (exit, flag, fenced)
        for (exit, flag, fenced) in [(101, true, true), (0, true, false), (101, false, false)] {
            let pool = WorkerPool::new();
            pool.add_worker(make_test_worker("worker1", 8)).await;
            let ctx = make_test_context(pool.clone());
            let worker = pool.get(&WorkerId::new("worker1")).await.unwrap();
            let build = ctx
                .history
                .try_start_active_build_with_waiter(
                    "held-project".into(),
                    "worker1".into(),
                    "cargo test".into(),
                    12345,
                    Some("owner".into()),
                    1,
                    rch_common::BuildLocation::Remote,
                    None,
                    crate::disk_pressure::DiskHeadroomAdmission::default(),
                    Some(worker.endpoint_snapshot().await),
                )
                .unwrap()
                .unwrap();
            assert!(worker.reserve_slots(1).await);
            let request = parse_request(&format!(
                "POST /release-worker?worker=worker1&build_id={}&local_wrapper_id=owner&exit_code={exit}&worker_source_busy={}",
                build.id,
                u8::from(flag)
            ))
            .unwrap();
            let ApiRequest::ReleaseWorker(request) = request else {
                panic!("release request expected")
            };
            assert_eq!(request.worker_source_busy, flag);
            assert!(!request.worker_live_checkout_refused);
            handle_release_worker(&ctx, request).await.unwrap();
            assert_eq!(
                project_excluded_workers(&ctx, "held-project").contains("worker1"),
                fenced
            );
            assert!(
                ctx.history
                    .live_checkout_fenced_workers("held-project")
                    .is_empty()
            );
            assert!(project_excluded_workers(&ctx, "other-project").is_empty());
        }
    }

    #[tokio::test]
    async fn project_lanes_keep_a_worker_eligible_until_every_lane_is_busy() {
        // bd-sgvod
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("worker1", 8)).await;
        let ctx = make_test_context(pool.clone());
        let start = |wrapper: &str| {
            ctx.history
                .try_start_active_build_in_lanes(
                    "lane-project".into(),
                    "worker1".into(),
                    "cargo test".into(),
                    12345,
                    Some(wrapper.into()),
                    1,
                    rch_common::BuildLocation::Remote,
                    None,
                    crate::disk_pressure::DiskHeadroomAdmission::default(),
                    None,
                    ctx.pool.project_lanes("worker1"),
                )
                .unwrap()
        };
        assert!(start("one").is_some());
        // One lane (the default): a second build of the project is excluded.
        assert!(project_excluded_workers(&ctx, "lane-project").contains("worker1"));
        pool.set_project_lanes(std::collections::HashMap::from([(
            "worker1".to_string(),
            2,
        )]));
        assert!(!project_excluded_workers(&ctx, "lane-project").contains("worker1"));
        assert_eq!(start("two").unwrap().project_lane, 1);
        assert!(project_excluded_workers(&ctx, "lane-project").contains("worker1"));
        assert!(project_excluded_workers(&ctx, "other-project").is_empty());
        // Out-of-range settings are clamped.
        pool.set_project_lanes(std::collections::HashMap::from([(
            "worker1".to_string(),
            0,
        )]));
        assert_eq!(pool.project_lanes("worker1"), 1);
        pool.set_project_lanes(std::collections::HashMap::from([(
            "worker1".to_string(),
            99,
        )]));
        assert_eq!(
            pool.project_lanes("worker1"),
            crate::workers::MAX_PROJECT_LANES
        );
    }

    fn disk_fault_release_request(build_id: u64) -> ReleaseRequest {
        ReleaseRequest {
            disk_peak_output_bytes: None,
            local_wrapper_id: Some("disk-owner".into()),
            worker_id: WorkerId::new("worker1"),
            slots: 2,
            build_id: Some(build_id),
            exit_code: Some(101),
            duration_ms: Some(50),
            bytes_transferred: None,
            timing: None,
            worker_fault: true,
            worker_disk_full: true,
            worker_live_checkout_refused: false,
            worker_source_busy: false,
            worker_disk_roots: vec!["/build-volume/rch".into()],
        }
    }

    #[tokio::test]
    async fn disk_fault_restart_replays_either_commit_boundary_without_duplicate_quarantine() {
        let _guard = test_guard!();
        for bypass_was_committed in [false, true] {
            let temporary = tempfile::tempdir().unwrap();
            let history_path = temporary.path().join("history.jsonl");
            let store_path = temporary.path().join("bypasses.json");
            let pool = WorkerPool::new();
            pool.add_worker(make_test_worker("worker1", 8)).await;
            let mut ctx = make_test_context(pool);
            replace_test_history(
                &mut ctx,
                BuildHistory::new(10).with_persistence(history_path.clone()),
            );
            ctx.bypass_store = Some(Arc::new(tokio::sync::Mutex::new(
                BypassRecordStore::with_path(&store_path),
            )));
            let worker = ctx.pool.get(&WorkerId::new("worker1")).await.unwrap();
            let build = ctx
                .history
                .try_start_active_build_with_waiter(
                    "disk-project".into(),
                    "worker1".into(),
                    "cargo build".into(),
                    12345,
                    Some("disk-owner".into()),
                    2,
                    rch_common::BuildLocation::Remote,
                    None,
                    crate::disk_pressure::DiskHeadroomAdmission::default(),
                    Some(worker.endpoint_snapshot().await),
                )
                .unwrap()
                .unwrap();
            // Crash frontier one: the real ownership transaction completed,
            // but no worker quarantine has yet been written.
            ctx.history
                .complete_durable_with_disk_fault(
                    build.id,
                    "worker1",
                    Some("disk-owner"),
                    crate::history::BuildCompletion {
                        exit_code: 101,
                        duration_ms: Some(50),
                        disk_peak_output_bytes: None,
                        bytes_transferred: None,
                        timing: None,
                        cancellation: None,
                    },
                    Some(vec!["/build-volume/rch".into()]),
                )
                .unwrap()
                .unwrap();
            let fault = ctx.history.pending_disk_fault(build.id).unwrap();
            let before = if bypass_was_committed {
                let worker = ctx.pool.get(&WorkerId::new("worker1")).await.unwrap();
                // Crash frontier two: the real bypass producer fsynced its
                // record, then completion acknowledgment was interrupted.
                assert!(
                    crate::bypass_recovery_service::record_worker_disk_bypass(
                        ctx.bypass_store.as_ref().unwrap(),
                        Some(&worker),
                        "worker1",
                        &fault.incident_id,
                        &fault.roots,
                        "disk exhausted",
                        fault.reported_unix_ms,
                        || Err(std::io::Error::other("interrupted before acknowledgment")),
                    )
                    .await
                    .is_err()
                );
                Some(
                    BypassRecordStore::load(&store_path)
                        .get("worker1")
                        .unwrap()
                        .clone(),
                )
            } else {
                None
            };
            drop(ctx);

            let pool = WorkerPool::new();
            pool.add_worker(make_test_worker("worker1", 8)).await;
            let worker = pool.get(&WorkerId::new("worker1")).await.unwrap();
            // An unrelated recovered build still owns this capacity. Fault
            // replay must never release it on behalf of the terminal build.
            assert!(worker.reserve_slots(3).await);
            let mut restored = make_test_context(pool);
            replace_test_history(
                &mut restored,
                BuildHistory::load_from_file(&history_path, 10).unwrap(),
            );
            let store = Arc::new(tokio::sync::Mutex::new(BypassRecordStore::load(
                &store_path,
            )));
            restored.bypass_store = Some(store.clone());
            assert!(restored.history.active_builds().is_empty());
            replay_pending_disk_faults(&restored).await.unwrap();
            assert_eq!(worker.used_slots(), 3);
            assert!(!worker.lifecycle().await.is_schedulable());
            let after = store.lock().await.get("worker1").unwrap().clone();
            assert_eq!(after.disk_roots, ["/build-volume/rch"]);
            if let Some(before) = before {
                assert_eq!(
                    after, before,
                    "replay must not advance failure/backoff or replace evidence"
                );
            }
            assert!(!restored.history.has_pending_disk_fault("worker1"));
            assert!(
                BuildHistory::load_from_file(&history_path, 10)
                    .unwrap()
                    .pending_disk_faults()
                    .is_empty()
            );

            let mut duplicate = disk_fault_release_request(build.id);
            duplicate.worker_disk_roots = vec!["../invalid-new-retry-root".into()];
            handle_release_worker(&restored, duplicate.clone())
                .await
                .unwrap();
            assert_eq!(store.lock().await.get("worker1"), Some(&after));
            // Once newer recovery has removed the bypass, old completion
            // retries and another restart cannot put the worker back into it.
            store.lock().await.remove("worker1").unwrap();
            worker.recover_to_canary().await.unwrap();
            worker.promote_from_canary().await.unwrap();
            replace_test_history(
                &mut restored,
                BuildHistory::load_from_file(&history_path, 10).unwrap(),
            );
            replay_pending_disk_faults(&restored).await.unwrap();
            handle_release_worker(&restored, duplicate).await.unwrap();
            assert!(!store.lock().await.contains("worker1"));
            assert!(worker.lifecycle().await.is_schedulable());
            assert_eq!(worker.used_slots(), 3);
        }
    }

    #[tokio::test]
    async fn disk_fault_failed_bypass_write_retains_intent_and_retry_releases_no_other_slots() {
        let _guard = test_guard!();
        let temporary = tempfile::tempdir().unwrap();
        let history_path = temporary.path().join("history.jsonl");
        let store_path = temporary.path().join("bypasses.json");
        // A real rename failure, with no mocked persistence success.
        std::fs::create_dir(&store_path).unwrap();
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("worker1", 8)).await;
        let worker = pool.get(&WorkerId::new("worker1")).await.unwrap();
        assert!(worker.reserve_slots(5).await);
        let mut ctx = make_test_context(pool);
        replace_test_history(
            &mut ctx,
            BuildHistory::new(10).with_persistence(history_path.clone()),
        );
        let store = Arc::new(tokio::sync::Mutex::new(BypassRecordStore::with_path(
            &store_path,
        )));
        ctx.bypass_store = Some(store.clone());
        let build = ctx
            .history
            .try_start_active_build_with_waiter(
                "disk-project".into(),
                "worker1".into(),
                "cargo build".into(),
                12345,
                Some("disk-owner".into()),
                2,
                rch_common::BuildLocation::Remote,
                None,
                crate::disk_pressure::DiskHeadroomAdmission::default(),
                Some(worker.endpoint_snapshot().await),
            )
            .unwrap()
            .unwrap();
        let mut request = disk_fault_release_request(build.id);
        request.worker_disk_roots = vec!["../bad".into()];
        assert!(handle_release_worker(&ctx, request).await.is_err());
        assert!(ctx.history.active_build(build.id).is_some());
        assert_eq!(worker.used_slots(), 5);

        let request = disk_fault_release_request(build.id);
        assert!(handle_release_worker(&ctx, request.clone()).await.is_err());
        assert_eq!(worker.used_slots(), 3);
        assert!(ctx.history.active_build(build.id).is_none());
        assert!(ctx.history.has_pending_disk_fault("worker1"));
        assert!(
            BuildHistory::load_from_file(&history_path, 10)
                .unwrap()
                .has_pending_disk_fault("worker1")
        );
        assert!(!worker.lifecycle().await.is_schedulable());
        let recorded = store.lock().await.get("worker1").unwrap().clone();
        std::fs::rename(
            &store_path,
            temporary.path().join("preserved-rename-obstacle"),
        )
        .unwrap();
        handle_release_worker(&ctx, request).await.unwrap();
        assert_eq!(worker.used_slots(), 3);
        assert!(!ctx.history.has_pending_disk_fault("worker1"));
        assert_eq!(
            BypassRecordStore::load(&store_path).get("worker1"),
            Some(&recorded)
        );
    }

    #[tokio::test]
    async fn late_disk_faults_archive_exact_incidents_without_quarantining_replacements() {
        for change in [
            "retarget",
            "aba",
            "restart",
            "legacy",
            "retarget_then_remove",
        ] {
            for durable_store in [false, true] {
                let temporary = tempfile::tempdir().unwrap();
                let history_path = temporary.path().join("history.jsonl");
                let store_path = temporary.path().join("bypasses.json");
                let original = make_test_worker("worker1", 8);
                let pool = WorkerPool::new();
                pool.add_worker(original.clone()).await;
                let mut worker = pool.get(&original.id).await.unwrap();
                let mut ctx = make_test_context(pool);
                replace_test_history(
                    &mut ctx,
                    BuildHistory::new(100).with_persistence(history_path.clone()),
                );
                if durable_store {
                    ctx.bypass_store = Some(Arc::new(tokio::sync::Mutex::new(
                        BypassRecordStore::with_path(&store_path),
                    )));
                }
                let build = ctx
                    .history
                    .try_start_active_build_with_waiter(
                        "old-volume".into(),
                        original.id.to_string(),
                        "cargo build".into(),
                        0,
                        Some("disk-owner".into()),
                        2,
                        rch_common::BuildLocation::Remote,
                        None,
                        crate::disk_pressure::DiskHeadroomAdmission::default(),
                        if change == "legacy" {
                            None
                        } else {
                            Some(worker.endpoint_snapshot().await)
                        },
                    )
                    .unwrap()
                    .unwrap();
                let other = ctx.history.start_active_build(
                    "other-build".into(),
                    original.id.to_string(),
                    "cargo check".into(),
                    0,
                    1,
                    rch_common::BuildLocation::Remote,
                );
                assert!(worker.reserve_slots(3).await);
                let mut replacement = original.clone();
                replacement.host = "replacement.example".into();
                if change == "restart" {
                    ctx.history
                        .complete_durable_with_disk_fault(
                            build.id,
                            "worker1",
                            Some("disk-owner"),
                            crate::history::BuildCompletion {
                                exit_code: 101,
                                duration_ms: None,
                                disk_peak_output_bytes: None,
                                bytes_transferred: None,
                                timing: None,
                                cancellation: None,
                            },
                            Some(vec!["/build-volume/rch".into()]),
                        )
                        .unwrap()
                        .unwrap();
                    replace_test_history(
                        &mut ctx,
                        BuildHistory::load_from_file(&history_path, 100).unwrap(),
                    );
                    ctx.pool = WorkerPool::new();
                    ctx.pool.add_worker(replacement).await;
                    worker = ctx.pool.get(&original.id).await.unwrap();
                    for active in ctx.history.active_builds() {
                        ctx.pool
                            .restore_recovered_slots(&original.id, active.slots)
                            .await
                            .unwrap();
                    }
                    replay_pending_disk_faults(&ctx).await.unwrap();
                } else {
                    ctx.pool.add_worker(replacement).await;
                    if change == "aba" {
                        ctx.pool.add_worker(original.clone()).await;
                    } else if change == "retarget_then_remove" {
                        // Retirement may preserve an unchanged endpoint's
                        // obligation, but must not erase a known retarget.
                        assert!(ctx.pool.remove_worker(&original.id).await);
                        ctx.pool.add_worker(original.clone()).await;
                        worker = ctx.pool.get(&original.id).await.unwrap();
                        for active in ctx.history.active_builds() {
                            ctx.pool
                                .restore_recovered_slots(&original.id, active.slots)
                                .await
                                .unwrap();
                        }
                    }
                    worker.apply_health_status(WorkerStatus::Healthy).await;
                    handle_release_worker(&ctx, disk_fault_release_request(build.id))
                        .await
                        .unwrap();
                }
                assert!(
                    worker.lifecycle().await.is_schedulable(),
                    "{change}/{durable_store}"
                );
                assert_eq!(worker.used_slots(), 1);
                assert!(ctx.history.active_build(other.id).is_some());
                assert!(ctx.history.active_build(build.id).is_none());
                assert!(ctx.history.pending_disk_fault(build.id).is_none());
                let archived = ctx.history.unapplied_disk_fault(build.id).unwrap();
                assert_eq!(archived.roots, ["/build-volume/rch"]);
                assert_eq!(archived.worker_endpoint.is_none(), change == "legacy");
                if let Some(endpoint) = archived.worker_endpoint.as_ref() {
                    assert!(endpoint.matches_config(&original));
                }
                assert!(!BypassRecordStore::load(&store_path).contains("worker1"));

                // An archived stale fault remains evidence when the old
                // coordinates return in a later daemon; it never replays.
                replace_test_history(
                    &mut ctx,
                    BuildHistory::load_from_file(&history_path, 100).unwrap(),
                );
                ctx.pool = WorkerPool::new();
                ctx.pool.add_worker(original.clone()).await;
                worker = ctx.pool.get(&original.id).await.unwrap();
                for active in ctx.history.active_builds() {
                    ctx.pool
                        .restore_recovered_slots(&original.id, active.slots)
                        .await
                        .unwrap();
                }
                replay_pending_disk_faults(&ctx).await.unwrap();
                let mut duplicate = disk_fault_release_request(build.id);
                duplicate.worker_disk_roots = vec!["../injected-retry-root".into()];
                handle_release_worker(&ctx, duplicate).await.unwrap();
                assert!(worker.lifecycle().await.is_schedulable());
                assert_eq!(worker.used_slots(), 1);
                assert_eq!(ctx.history.unapplied_disk_fault(build.id), Some(archived));
                assert!(!BypassRecordStore::load(&store_path).contains("worker1"));
            }
        }
    }

    #[tokio::test]
    async fn test_handle_release_worker_basic() {
        let _guard = test_guard!();
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("worker1", 8)).await;

        // Reserve some slots first
        let worker = pool.get(&WorkerId::new("worker1")).await.unwrap();
        let reserved = worker.reserve_slots(4).await;
        assert!(reserved);

        let ctx = make_test_context(pool.clone());

        let request = ReleaseRequest {
            local_wrapper_id: None,
            worker_id: WorkerId::new("worker1"),
            slots: 4,
            build_id: None,
            disk_peak_output_bytes: None,
            exit_code: None,
            duration_ms: None,
            bytes_transferred: None,
            timing: None,
            worker_fault: false,
            worker_disk_full: false,
            worker_live_checkout_refused: false,
            worker_source_busy: false,
            worker_disk_roots: Vec::new(),
        };

        let result = handle_release_worker(&ctx, request).await;
        assert!(result.is_err());
        // An unowned legacy request cannot free another build's reservation.
        assert_eq!(worker.available_slots().await, 4);
    }

    /// Select a build the way every client since v1.0.56 does: with a wrapper
    /// identity and this test process as its hook process.
    async fn select_wrapper_owned_build(ctx: &DaemonContext, worker_id: &str) -> (u64, String) {
        let wrapper = format!("rchw-{}", Uuid::new_v4());
        let request = SelectionRequest {
            job_mode: false,
            project: "legacy-client-project".to_string(),
            command: Some("cargo build".to_string()),
            command_priority: CommandPriority::Normal,
            estimated_cores: 4,
            disk_headroom_gib: 0,
            preferred_workers: vec![WorkerId::new(worker_id)],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
            required_tools: Vec::new(),
            hook_pid: Some(crate::history::observable_test_process_id()),
        };
        let response =
            handle_select_worker_with_wrapper(ctx, request, false, None, Some(wrapper.clone()))
                .await
                .unwrap();
        assert_eq!(response.worker.unwrap().id.as_str(), worker_id);
        (response.build_id.unwrap(), wrapper)
    }

    /// Serve one request over a real socket pair, so the daemon reads its peer
    /// from the kernel exactly as it does in production.
    async fn serve_socket_request(ctx: &DaemonContext, line: &str) -> (Result<()>, String) {
        let (mut client, server) = UnixStream::pair().unwrap();
        let peer_pid = server.peer_cred().unwrap().pid().unwrap();
        assert_eq!(
            u32::try_from(peer_pid).unwrap(),
            crate::history::observable_test_process_id(),
            "the socket peer and the procfs identity must name this test process"
        );
        let (shutdown_tx, _) = tokio::sync::mpsc::channel(1);
        let connection = tokio::spawn(handle_connection(server, ctx.clone(), shutdown_tx));
        client.write_all(line.as_bytes()).await.unwrap();
        let mut response = String::new();
        tokio::time::timeout(Duration::from_secs(5), client.read_to_string(&mut response))
            .await
            .unwrap()
            .unwrap();
        (connection.await.unwrap(), response)
    }

    /// GH #119: v1.0.56-v2.0.x clients select with `local_wrapper_id` but
    /// release without it. The build's own client process must still be able
    /// to release it, over the real socket route and with the v2.0.x request
    /// line byte for byte.
    #[tokio::test]
    async fn legacy_client_release_without_wrapper_frees_its_own_build() {
        let _guard = test_guard!();
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("legacy", 8)).await;
        set_test_build_disk(&pool, "legacy", 100.0).await;
        let ctx = make_test_context(pool.clone());
        let worker = pool.get(&WorkerId::new("legacy")).await.unwrap();
        let (build_id, wrapper) = select_wrapper_owned_build(&ctx, "legacy").await;
        assert_eq!(worker.used_slots(), 4);

        let (result, response) = serve_socket_request(
            &ctx,
            &format!(
                "POST /release-worker?worker=legacy&slots=4&build_id={build_id}&exit_code=0\n"
            ),
        )
        .await;
        result.unwrap();
        assert!(response.starts_with("HTTP/1.0 200"), "{response}");
        assert_eq!(worker.used_slots(), 0);
        assert!(ctx.history.active_build(build_id).is_none());
        // The terminal receipt keeps the recorded owner: the same release
        // presented by that owner is an acknowledged repeat.
        assert!(
            ctx.history
                .complete_durable(
                    build_id,
                    "legacy",
                    Some(&wrapper),
                    crate::history::BuildCompletion {
                        exit_code: 0,
                        duration_ms: None,
                        bytes_transferred: None,
                        disk_peak_output_bytes: None,
                        timing: None,
                        cancellation: None,
                    },
                )
                .unwrap()
                .is_none()
        );
    }

    /// GH #119: the legacy acceptance is no ownership bypass. A wrapper-less
    /// release from any process but the build's client, one naming another
    /// worker, and a current client's wrong wrapper (even from the owner
    /// process) are all still refused, and the slots stay reserved.
    #[tokio::test]
    async fn release_without_wrapper_is_refused_unless_the_builds_own_client_sends_it() {
        use rch_common::process_identity::ProcessStart;
        let _guard = test_guard!();
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("legacy", 8)).await;
        pool.add_worker(make_test_worker("other", 8)).await;
        set_test_build_disk(&pool, "legacy", 100.0).await;
        let ctx = make_test_context(pool.clone());
        let worker = pool.get(&WorkerId::new("legacy")).await.unwrap();
        let (build_id, wrapper) = select_wrapper_owned_build(&ctx, "legacy").await;
        let owner = MaintenancePeer::capture(
            i32::try_from(crate::history::observable_test_process_id()).ok(),
        )
        .unwrap();
        let mut recycled = owner.clone();
        recycled.identity.start = match recycled.identity.start {
            ProcessStart::Linux { ticks } => ProcessStart::Linux { ticks: ticks + 1 },
            ProcessStart::Darwin {
                seconds,
                microseconds,
            } => ProcessStart::Darwin {
                seconds: seconds + 1,
                microseconds,
            },
        };
        let mut other_pid = owner.clone();
        other_pid.pid += 1;
        let release = |worker_id: &str, local_wrapper_id: Option<&str>| ReleaseRequest {
            local_wrapper_id: local_wrapper_id.map(str::to_owned),
            worker_id: WorkerId::new(worker_id),
            slots: 4,
            build_id: Some(build_id),
            disk_peak_output_bytes: None,
            exit_code: Some(0),
            duration_ms: None,
            bytes_transferred: None,
            timing: None,
            worker_fault: false,
            worker_disk_full: false,
            worker_live_checkout_refused: false,
            worker_source_busy: false,
            worker_disk_roots: Vec::new(),
        };

        for (case, request, peer) in [
            ("no peer", release("legacy", None), None),
            ("recycled PID", release("legacy", None), Some(&recycled)),
            ("another process", release("legacy", None), Some(&other_pid)),
            ("another worker", release("other", None), Some(&owner)),
            (
                "wrong wrapper from the owner",
                release("legacy", Some("rchw-not-the-owner")),
                Some(&owner),
            ),
        ] {
            assert!(
                handle_release_worker_from(&ctx, request, peer)
                    .await
                    .is_err(),
                "{case}: release must be refused"
            );
            assert_eq!(worker.used_slots(), 4, "{case}: slots must stay reserved");
            assert!(ctx.history.active_build(build_id).is_some(), "{case}");
        }

        // The current protocol is unchanged: the owner's wrapper releases it.
        handle_release_worker_from(&ctx, release("legacy", Some(&wrapper)), Some(&recycled))
            .await
            .unwrap();
        assert_eq!(worker.used_slots(), 0);
        assert!(ctx.history.active_build(build_id).is_none());
    }

    #[tokio::test]
    async fn test_handle_release_worker_with_build_completion() {
        let _guard = test_guard!();
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("worker1", 8)).await;

        let ctx = make_test_context(pool.clone());

        // Start a build first using the correct API
        let worker = pool.get(&WorkerId::new("worker1")).await.unwrap();
        let build = ctx
            .history
            .try_start_active_build_with_waiter(
                "test-project".to_string(),
                "worker1".to_string(),
                "cargo build".to_string(),
                12345,
                None,
                4,
                rch_common::BuildLocation::Remote,
                None,
                crate::disk_pressure::DiskHeadroomAdmission::default(),
                Some(worker.endpoint_snapshot().await),
            )
            .unwrap()
            .unwrap();
        let build_id = build.id;

        // Reserve slots
        worker.reserve_slots(4).await;

        let request = ReleaseRequest {
            local_wrapper_id: None,
            worker_id: WorkerId::new("worker1"),
            slots: 4,
            build_id: Some(build_id),
            exit_code: Some(0),
            disk_peak_output_bytes: None,
            duration_ms: Some(5000),
            bytes_transferred: Some(1024 * 1024),
            timing: None,
            worker_fault: false,
            worker_disk_full: false,
            worker_live_checkout_refused: false,
            worker_source_busy: false,
            worker_disk_roots: Vec::new(),
        };

        let result = handle_release_worker(&ctx, request).await;
        assert!(result.is_ok());

        // Verify build was completed in history
        let recent = ctx.history.recent(10);
        let completed = recent.iter().find(|b| b.id == build_id);
        assert!(completed.is_some());
        assert_eq!(completed.unwrap().exit_code, 0);

        let stats = worker.circuit_stats().await;
        assert_eq!(stats.error_rate(), 0.0);
        assert_eq!(stats.recent_results(), &[true]);
        assert_eq!(
            ctx.worker_selector
                .get_fallback_worker("test-project")
                .await,
            Some("worker1".to_string())
        );
    }

    #[tokio::test]
    async fn completed_build_feedback_is_bound_but_slot_release_survives_retarget_and_restart() {
        for change in ["unchanged", "retarget", "aba", "restart", "legacy"] {
            let directory = tempfile::tempdir().unwrap();
            let history_path = directory.path().join("history.jsonl");
            let original = make_test_worker("bound-completion", 8);
            let pool = WorkerPool::new();
            pool.add_worker(original.clone()).await;
            set_test_build_disk(&pool, original.id.as_str(), 100.0).await;
            let mut worker = pool.get(&original.id).await.unwrap();
            let mut ctx = make_test_context(pool.clone());
            replace_test_history(
                &mut ctx,
                BuildHistory::new(100).with_persistence(history_path.clone()),
            );
            let other = ctx.history.start_active_build(
                "other-build".into(),
                original.id.to_string(),
                "cargo check".into(),
                0,
                1,
                rch_common::BuildLocation::Remote,
            );
            assert!(worker.reserve_slots(1).await);

            let build_id = if change == "legacy" {
                assert!(worker.reserve_slots(2).await);
                ctx.history
                    .start_active_build(
                        "finished-build".into(),
                        original.id.to_string(),
                        "cargo build".into(),
                        0,
                        2,
                        rch_common::BuildLocation::Remote,
                    )
                    .id
            } else {
                let response = handle_select_worker(
                    &ctx,
                    SelectionRequest {
                        job_mode: false,
                        project: "finished-build".into(),
                        command: Some("cargo build".into()),
                        command_priority: CommandPriority::Normal,
                        estimated_cores: 2,
                        disk_headroom_gib: 0,
                        preferred_workers: vec![],
                        toolchain: None,
                        required_runtime: RequiredRuntime::default(),
                        classification_duration_us: None,
                        hook_pid: None,
                        required_tools: Vec::new(),
                    },
                    false,
                    None,
                )
                .await
                .unwrap();
                let selected = response.worker.unwrap();
                let id = response.build_id.unwrap();
                let active = ctx.history.active_build(id).unwrap();
                let endpoint = active.worker_endpoint.as_ref().unwrap();
                assert_eq!(endpoint.config.id, selected.id);
                assert_eq!(endpoint.config.host, selected.host);
                assert_eq!(endpoint.config.user, selected.user);
                assert_eq!(endpoint.config.identity_file, selected.identity_file);
                assert_eq!(
                    rch_common::declared_os(&endpoint.config.tags),
                    selected.declared_os
                );
                id
            };
            assert_eq!(worker.used_slots(), 3);
            if matches!(change, "retarget" | "aba") {
                let mut replacement = original.clone();
                replacement.host = "replacement.host".into();
                pool.add_worker(replacement).await;
                if change == "aba" {
                    pool.add_worker(original.clone()).await;
                }
            } else if change == "restart" {
                replace_test_history(
                    &mut ctx,
                    BuildHistory::load_from_file(&history_path, 100).unwrap(),
                );
                ctx.pool = WorkerPool::new();
                ctx.pool.add_worker(original.clone()).await;
                worker = ctx.pool.get(&original.id).await.unwrap();
                for active in ctx.history.active_builds() {
                    worker.restore_slots(active.slots).unwrap();
                }
            }
            worker
                .record_failure(Some("current endpoint evidence".into()))
                .await;
            let release = ReleaseRequest {
                local_wrapper_id: None,
                worker_id: original.id.clone(),
                disk_peak_output_bytes: None,
                slots: 999,
                build_id: Some(build_id),
                exit_code: Some(0),
                duration_ms: None,
                bytes_transferred: None,
                timing: None,
                worker_fault: false,
                worker_disk_full: false,
                worker_live_checkout_refused: false,
                worker_source_busy: false,
                worker_disk_roots: Vec::new(),
            };
            handle_release_worker(&ctx, release.clone()).await.unwrap();
            assert_eq!(
                worker.used_slots(),
                1,
                "{change}: release follows exact ownership"
            );
            let stats = worker.circuit_stats().await;
            assert_eq!(
                stats.consecutive_failures(),
                u32::from(change != "unchanged"),
                "{change}"
            );
            assert_eq!(
                ctx.worker_selector
                    .get_fallback_worker("finished-build")
                    .await,
                (change == "unchanged").then(|| original.id.to_string()),
                "{change}: old ownership cannot pin the current worker"
            );
            handle_release_worker(&ctx, release).await.unwrap();
            assert_eq!(
                worker.used_slots(),
                1,
                "{change}: duplicate completion released another build"
            );
            assert!(ctx.history.active_build(other.id).is_some());
            assert!(ctx.history.active_build(build_id).is_none());
            assert_eq!(ctx.history.recent(10).len(), 1);
        }
    }

    #[tokio::test]
    async fn test_handle_release_worker_uses_active_build_slots() {
        let _guard = test_guard!();
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("worker1", 8)).await;

        let ctx = make_test_context(pool.clone());
        let build = ctx.history.start_active_build(
            "test-project".to_string(),
            "worker1".to_string(),
            "cargo build".to_string(),
            12345,
            4,
            rch_common::BuildLocation::Remote,
        );
        let build_id = build.id;

        let worker = pool.get(&WorkerId::new("worker1")).await.unwrap();
        assert!(worker.reserve_slots(4).await);

        let request = ReleaseRequest {
            local_wrapper_id: None,
            worker_id: WorkerId::new("worker1"),
            slots: 0,
            disk_peak_output_bytes: None,
            build_id: Some(build_id),
            exit_code: Some(0),
            duration_ms: Some(5000),
            bytes_transferred: Some(1024 * 1024),
            timing: None,
            worker_fault: false,
            worker_disk_full: false,
            worker_live_checkout_refused: false,
            worker_source_busy: false,
            worker_disk_roots: Vec::new(),
        };

        handle_release_worker(&ctx, request).await.unwrap();

        assert_eq!(worker.available_slots().await, 8);
        assert!(ctx.history.active_build(build_id).is_none());
    }

    #[tokio::test]
    async fn test_handle_release_worker_build_id_is_idempotent() {
        let _guard = test_guard!();
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("worker1", 8)).await;

        let ctx = make_test_context(pool.clone());
        let build = ctx.history.start_active_build(
            "test-project".to_string(),
            "worker1".to_string(),
            "cargo build".to_string(),
            12345,
            4,
            rch_common::BuildLocation::Remote,
        );
        let build_id = build.id;
        let worker = pool.get(&WorkerId::new("worker1")).await.unwrap();
        assert!(worker.reserve_slots(4).await);

        let release = || ReleaseRequest {
            disk_peak_output_bytes: None,
            local_wrapper_id: None,
            worker_id: WorkerId::new("worker1"),
            slots: 4,
            build_id: Some(build_id),
            exit_code: Some(1),
            duration_ms: None,
            bytes_transferred: None,
            timing: None,
            worker_fault: false,
            worker_disk_full: false,
            worker_live_checkout_refused: false,
            worker_source_busy: false,
            worker_disk_roots: Vec::new(),
        };
        handle_release_worker(&ctx, release()).await.unwrap();
        assert_eq!(worker.available_slots().await, 8);

        // Simulate a later build reserving capacity before a duplicate/late
        // release for the completed build arrives.
        assert!(worker.reserve_slots(2).await);
        handle_release_worker(&ctx, release()).await.unwrap();
        assert_eq!(worker.available_slots().await, 6);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_handle_release_worker_concurrent_duplicates_claim_build_once() {
        let _guard = test_guard!();
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("worker1", 8)).await;
        let ctx = make_test_context(pool.clone());
        let build = ctx.history.start_active_build(
            "test-project".to_string(),
            "worker1".to_string(),
            "cargo build".to_string(),
            12345,
            4,
            rch_common::BuildLocation::Remote,
        );
        let build_id = build.id;
        let worker = pool.get(&WorkerId::new("worker1")).await.unwrap();
        assert!(worker.reserve_slots(4).await);

        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let spawn_release = |ctx: DaemonContext, barrier: Arc<tokio::sync::Barrier>| {
            tokio::spawn(async move {
                barrier.wait().await;
                handle_release_worker(
                    &ctx,
                    ReleaseRequest {
                        local_wrapper_id: None,
                        disk_peak_output_bytes: None,
                        worker_id: WorkerId::new("worker1"),
                        slots: 4,
                        build_id: Some(build_id),
                        exit_code: Some(1),
                        duration_ms: None,
                        bytes_transferred: None,
                        timing: None,
                        worker_fault: false,
                        worker_disk_full: false,
                        worker_live_checkout_refused: false,
                        worker_source_busy: false,
                        worker_disk_roots: Vec::new(),
                    },
                )
                .await
            })
        };
        let first = spawn_release(ctx.clone(), barrier.clone());
        let second = spawn_release(ctx.clone(), barrier.clone());
        barrier.wait().await;
        first.await.unwrap().unwrap();
        second.await.unwrap().unwrap();

        assert_eq!(worker.available_slots().await, 8);
        assert!(ctx.history.active_build(build_id).is_none());
        assert_eq!(
            ctx.history
                .recent(10)
                .iter()
                .filter(|record| record.id == build_id)
                .count(),
            1
        );

        // A later duplicate remains a no-op after new capacity is reserved.
        assert!(worker.reserve_slots(2).await);
        handle_release_worker(
            &ctx,
            ReleaseRequest {
                local_wrapper_id: None,
                worker_id: WorkerId::new("worker1"),
                slots: 4,
                disk_peak_output_bytes: None,
                build_id: Some(build_id),
                exit_code: Some(1),
                duration_ms: None,
                bytes_transferred: None,
                timing: None,
                worker_fault: false,
                worker_disk_full: false,
                worker_live_checkout_refused: false,
                worker_source_busy: false,
                worker_disk_roots: Vec::new(),
            },
        )
        .await
        .unwrap();
        assert_eq!(worker.available_slots().await, 6);
    }

    #[tokio::test]
    async fn test_release_after_remote_failure_warms_cache_without_health_or_pin() {
        let _guard = test_guard!();
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("worker1", 8)).await;
        let ctx = make_test_context(pool.clone());
        let worker = pool.get(&WorkerId::new("worker1")).await.unwrap();

        let endpoint = worker.endpoint_snapshot().await;
        let start = |project: &str| {
            let build = ctx
                .history
                .try_start_active_build_with_waiter(
                    project.to_string(),
                    "worker1".to_string(),
                    "cargo build".to_string(),
                    12345,
                    None,
                    2,
                    rch_common::BuildLocation::Remote,
                    None,
                    crate::disk_pressure::DiskHeadroomAdmission::default(),
                    Some(endpoint.clone()),
                )
                .unwrap()
                .unwrap();
            build.id
        };
        let release = |build_id| ReleaseRequest {
            disk_peak_output_bytes: None,
            local_wrapper_id: None,
            worker_id: WorkerId::new("worker1"),
            slots: 2,
            build_id: Some(build_id),
            exit_code: Some(101),
            duration_ms: Some(5000),
            bytes_transferred: None,
            timing: None,
            worker_fault: false,
            worker_disk_full: false,
            worker_live_checkout_refused: false,
            worker_source_busy: false,
            worker_disk_roots: Vec::new(),
        };

        // GH #81: the remote command ran (Execute heartbeat), then exited 101.
        let ran = start("ran-project");
        assert!(worker.reserve_slots(2).await);
        ctx.history
            .record_build_heartbeat(rch_common::BuildHeartbeatRequest {
                build_id: ran,
                worker_id: WorkerId::new("worker1"),
                hook_pid: None,
                local_wrapper_id: None,
                remote_pgid_file: None,
                phase: rch_common::BuildHeartbeatPhase::Execute,
                detail: None,
                progress_counter: Some(1),
                progress_percent: None,
            })
            .expect("heartbeat accepted");
        handle_release_worker(&ctx, release(ran)).await.unwrap();
        assert_eq!(
            ctx.worker_selector
                .cache_warmth("worker1", "ran-project", crate::selection::CacheUse::Build)
                .await,
            1.0
        );
        assert_eq!(
            ctx.worker_selector.get_pinned_worker("ran-project").await,
            None
        );
        assert!(worker.circuit_stats().await.recent_results().is_empty());

        // Never got past sync-up: the worker's cache learned nothing.
        let unsynced = start("unsynced-project");
        assert!(worker.reserve_slots(2).await);
        handle_release_worker(&ctx, release(unsynced))
            .await
            .unwrap();
        assert_eq!(
            ctx.worker_selector
                .cache_warmth(
                    "worker1",
                    "unsynced-project",
                    crate::selection::CacheUse::Build
                )
                .await,
            0.0
        );
        assert_eq!(worker.available_slots().await, 8);

        // The command ran, but the hook blamed the worker (e.g. its toolchain
        // or a system library is missing): warming it would route the next
        // build of the project straight back to the broken worker.
        let broken = start("broken-worker-project");
        assert!(worker.reserve_slots(2).await);
        ctx.history
            .record_build_heartbeat(rch_common::BuildHeartbeatRequest {
                build_id: broken,
                worker_id: WorkerId::new("worker1"),
                hook_pid: None,
                local_wrapper_id: None,
                remote_pgid_file: None,
                phase: rch_common::BuildHeartbeatPhase::Execute,
                detail: None,
                progress_counter: Some(1),
                progress_percent: None,
            })
            .expect("heartbeat accepted");
        let mut faulted = release(broken);
        faulted.worker_fault = true;
        handle_release_worker(&ctx, faulted).await.unwrap();
        assert_eq!(
            ctx.worker_selector
                .cache_warmth(
                    "worker1",
                    "broken-worker-project",
                    crate::selection::CacheUse::Build
                )
                .await,
            0.0
        );
        assert_eq!(worker.available_slots().await, 8);
    }

    #[tokio::test]
    async fn test_handle_release_worker_nonzero_exit_preserves_worker_health() {
        let _guard = test_guard!();
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("worker1", 8)).await;

        let ctx = make_test_context(pool.clone());
        let build = ctx.history.start_active_build(
            "test-project".to_string(),
            "worker1".to_string(),
            "cargo test".to_string(),
            12345,
            4,
            rch_common::BuildLocation::Remote,
        );
        let build_id = build.id;

        let worker = pool.get(&WorkerId::new("worker1")).await.unwrap();
        worker.reserve_slots(4).await;

        let request = ReleaseRequest {
            local_wrapper_id: None,
            worker_id: WorkerId::new("worker1"),
            slots: 4,
            build_id: Some(build_id),
            exit_code: Some(101),
            disk_peak_output_bytes: None,
            duration_ms: Some(5000),
            bytes_transferred: Some(1024 * 1024),
            timing: None,
            worker_fault: false,
            worker_disk_full: false,
            worker_live_checkout_refused: false,
            worker_source_busy: false,
            worker_disk_roots: Vec::new(),
        };

        let result = handle_release_worker(&ctx, request).await;
        assert!(result.is_ok());

        let recent = ctx.history.recent(10);
        let completed = recent
            .iter()
            .find(|b| b.id == build_id)
            .expect("build should be completed");
        assert_eq!(completed.exit_code, 101);

        let stats = worker.circuit_stats().await;
        assert_eq!(stats.error_rate(), 0.0);
        assert!(stats.recent_results().is_empty());
        assert_eq!(
            ctx.worker_selector
                .get_fallback_worker("test-project")
                .await,
            None
        );
    }

    #[tokio::test]
    async fn test_handle_build_heartbeat_updates_active_build_state() {
        let _guard = test_guard!();
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("worker1", 8)).await;
        let ctx = make_test_context(pool);

        let build = ctx.history.start_active_build(
            "test-project".to_string(),
            "worker1".to_string(),
            "cargo build".to_string(),
            43210,
            4,
            rch_common::BuildLocation::Remote,
        );

        let response = handle_build_heartbeat(
            &ctx,
            BuildHeartbeatRequest {
                build_id: build.id,
                worker_id: WorkerId::new("worker1"),
                hook_pid: Some(43210),
                local_wrapper_id: Some("rchw-test".to_string()),
                remote_pgid_file: Some("/tmp/rch/test-project/hash/.rch-run/99.pgid".to_string()),
                phase: rch_common::BuildHeartbeatPhase::Execute,
                detail: Some("Compiling".to_string()),
                progress_counter: Some(4),
                progress_percent: Some(18.0),
            },
        )
        .await;

        assert_eq!(response.status, "ok");
        let active = ctx.history.active_build(build.id).expect("active build");
        assert_eq!(
            active.heartbeat_phase,
            rch_common::BuildHeartbeatPhase::Execute
        );
        assert_eq!(
            active.remote_pgid_file.as_deref(),
            Some("/tmp/rch/test-project/hash/.rch-run/99.pgid")
        );
        assert_eq!(active.heartbeat_counter, 4);
        assert_eq!(active.heartbeat_percent, Some(18.0));
    }

    #[tokio::test]
    async fn test_handle_build_heartbeat_rejects_worker_mismatch() {
        let _guard = test_guard!();
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("worker1", 8)).await;
        let ctx = make_test_context(pool);

        let build = ctx.history.start_active_build(
            "test-project".to_string(),
            "worker1".to_string(),
            "cargo build".to_string(),
            5555,
            2,
            rch_common::BuildLocation::Remote,
        );

        let response = handle_build_heartbeat(
            &ctx,
            BuildHeartbeatRequest {
                build_id: build.id,
                worker_id: WorkerId::new("worker-x"),
                hook_pid: Some(5555),
                local_wrapper_id: None,
                remote_pgid_file: None,
                phase: rch_common::BuildHeartbeatPhase::Execute,
                detail: Some("Mismatch".to_string()),
                progress_counter: Some(2),
                progress_percent: None,
            },
        )
        .await;

        assert_eq!(response.status, "ignored");
    }

    // =========================================================================
    // Record build tests
    // =========================================================================

    #[tokio::test]
    async fn test_handle_record_build_basic() {
        let _guard = test_guard!();
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("worker1", 8)).await;
        let ctx = make_test_context(pool);

        let result =
            handle_record_build(&ctx, &WorkerId::new("worker1"), "my-project", false).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_record_build_test_flag() {
        let _guard = test_guard!();
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("worker1", 8)).await;
        let ctx = make_test_context(pool);

        // Record a test build
        let result = handle_record_build(&ctx, &WorkerId::new("worker1"), "my-project", true).await;
        assert!(result.is_ok());
    }

    // =========================================================================
    // Status handler tests
    // =========================================================================

    #[tokio::test]
    async fn test_handle_status_empty_pool() {
        let _guard = test_guard!();
        let pool = WorkerPool::new();
        let ctx = make_test_context(pool);

        let result = handle_status(&ctx).await;
        assert!(result.is_ok());

        let status = result.unwrap();
        assert!(status.workers.is_empty());
        assert!(status.active_builds.is_empty());
        assert!(status.queued_builds.is_empty());
        assert_eq!(status.daemon.workers_total, 0);
        assert_eq!(status.daemon.workers_healthy, 0);
    }

    #[tokio::test]
    async fn test_handle_status_with_workers() {
        let _guard = test_guard!();
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("worker1", 8)).await;
        pool.add_worker(make_test_worker("worker2", 4)).await;
        let ctx = make_test_context(pool);

        let result = handle_status(&ctx).await;
        assert!(result.is_ok());

        let status = result.unwrap();
        assert_eq!(status.workers.len(), 2);
        assert_eq!(status.daemon.workers_total, 2);
        assert_eq!(status.daemon.slots_total, 12); // 8 + 4
        assert_eq!(status.daemon.version, "0.1.0");
        assert_eq!(status.daemon.pid, 1234);
    }

    #[tokio::test]
    async fn test_handle_status_slots_available_counts_only_assignable_capacity() {
        let _guard = test_guard!();
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("healthy", 8)).await;
        pool.add_worker(make_test_worker("degraded", 4)).await;
        pool.add_worker(make_test_worker("drained", 6)).await;
        pool.add_worker(make_test_worker("disabled", 10)).await;
        pool.add_worker(make_test_worker("open-circuit", 5)).await;

        let healthy = pool
            .get(&WorkerId::new("healthy"))
            .await
            .expect("healthy worker should exist");
        assert!(healthy.reserve_slots(2).await);

        let degraded = pool
            .get(&WorkerId::new("degraded"))
            .await
            .expect("degraded worker should exist");
        degraded.set_status(WorkerStatus::Degraded).await;
        assert!(degraded.reserve_slots(1).await);

        pool.set_status(&WorkerId::new("drained"), WorkerStatus::Drained)
            .await;
        pool.set_status(&WorkerId::new("disabled"), WorkerStatus::Disabled)
            .await;

        let open_circuit = pool
            .get(&WorkerId::new("open-circuit"))
            .await
            .expect("open-circuit worker should exist");
        open_circuit.open_circuit().await;

        let ctx = make_test_context(pool);
        let status = handle_status(&ctx).await.expect("status should succeed");

        assert_eq!(status.daemon.slots_total, 33);
        assert_eq!(
            status.daemon.slots_available, 9,
            "only healthy/degraded, non-open-circuit capacity should be assignable"
        );
    }

    /// Issue #75: `/status` slots_available, socket `/ready` and HTTP `/ready`
    /// must agree with select-worker, which hard-excludes critical pressure
    /// whichever rule fired (disk floor via the capabilities probe, memory).
    #[tokio::test]
    async fn test_capacity_surfaces_exclude_critical_pressure_workers() {
        use tower::ServiceExt;
        let _guard = test_guard!();

        async fn http_ready_status(pool: &WorkerPool) -> axum::http::StatusCode {
            crate::http_api::create_router(crate::http_api::HttpState {
                pool: pool.clone(),
                version: "test",
                started_at: Instant::now(),
                pid: 1,
            })
            .oneshot(
                axum::http::Request::builder()
                    .uri("/ready")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
        }

        for case in ["disk_critical", "memory_critical"] {
            let pool = WorkerPool::new();
            pool.add_worker(make_test_worker("w1", 8)).await;
            let worker = pool.get(&WorkerId::new("w1")).await.unwrap();
            if case == "disk_critical" {
                // 45 GB of 926 GB (4.9%): below the 5% critical ratio, via the
                // same policy path the capabilities probe takes.
                worker
                    .set_capabilities(WorkerCapabilities {
                        disk_free_gb: Some(45.0),
                        disk_total_gb: Some(926.0),
                        ..Default::default()
                    })
                    .await;
            } else {
                worker
                    .set_pressure_assessment(PressureAssessment {
                        state: PressureState::Critical,
                        confidence: PressureConfidence::High,
                        reason_code: "memory_pressure_critical".to_string(),
                        policy_rule: "memory_pressure>=critical_memory_pressure".to_string(),
                        disk_free_gb: Some(500.0),
                        disk_total_gb: Some(926.0),
                        memory_pressure: Some(95.0),
                        telemetry_fresh: true,
                        ..Default::default()
                    })
                    .await;
            }
            assert_eq!(
                worker.pressure_assessment().await.state,
                PressureState::Critical,
                "{case}"
            );

            let ctx = make_test_context(pool.clone());
            let status = handle_status(&ctx).await.unwrap();
            assert_eq!(status.daemon.slots_available, 0, "{case}");
            assert!(status.daemon.slots_total > 0, "{case}");
            let ready = handle_ready(&ctx).await;
            assert_eq!(ready.status, "not_ready", "{case}");
            assert!(!ready.workers_available, "{case}");
            assert_eq!(
                http_ready_status(&pool).await,
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                "{case}"
            );

            // A second, unpressured worker restores readiness and contributes
            // exactly its own slots.
            pool.add_worker(make_test_worker("w2", 4)).await;
            let ctx = make_test_context(pool.clone());
            let status = handle_status(&ctx).await.unwrap();
            assert_eq!(status.daemon.slots_available, 4, "{case}");
            assert!(handle_ready(&ctx).await.workers_available, "{case}");
            assert_eq!(
                http_ready_status(&pool).await,
                axum::http::StatusCode::OK,
                "{case}"
            );
        }
    }

    #[tokio::test]
    async fn test_disk_slots_status_preserves_usage_after_derating() {
        let _guard = test_guard!();
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("disk-worker", 8)).await;
        let worker = pool.get(&WorkerId::new("disk-worker")).await.unwrap();
        assert!(worker.reserve_slots(4).await);
        worker
            .set_pressure_assessment(crate::disk_pressure::PressureAssessment {
                disk_free_gb: Some(20.0),
                ..Default::default()
            })
            .await;
        let ctx = make_test_context(pool);
        let status = handle_status(&ctx).await.unwrap();
        assert_eq!(status.workers[0].total_slots, 1);
        assert_eq!(status.workers[0].used_slots, 4);
        assert_eq!(status.daemon.slots_total, 1);
        assert_eq!(status.daemon.slots_available, 0);
        let snapshots = crate::ui::workers::WorkerStatusPanel::collect_snapshot(&ctx.pool).await;
        assert_eq!(snapshots[0].total_slots, 1);
        assert_eq!(snapshots[0].used_slots, 4);
    }

    #[tokio::test]
    async fn test_disk_slots_selection_clamps_reservation_to_effective_capacity() {
        let _guard = test_guard!();
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("disk-worker", 8)).await;
        let worker = pool.get(&WorkerId::new("disk-worker")).await.unwrap();
        worker
            .set_pressure_assessment(crate::disk_pressure::PressureAssessment {
                disk_free_gb: Some(40.0),
                ..Default::default()
            })
            .await;
        let ctx = make_test_context(pool);
        let request = SelectionRequest {
            job_mode: false,
            project: "disk-capacity".to_string(),
            command: None,
            command_priority: CommandPriority::Normal,
            estimated_cores: 4,
            disk_headroom_gib: 0,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::None,
            classification_duration_us: None,
            required_tools: Vec::new(),
            hook_pid: Some(98765),
        };
        let response = handle_select_worker(&ctx, request, false, None)
            .await
            .unwrap();
        assert_eq!(response.worker.unwrap().slots_available, 0);
        assert_eq!(worker.used_slots(), 3);
        let build_id = response.build_id.unwrap();
        assert_eq!(ctx.history.active_build(build_id).unwrap().slots, 3);
        worker
            .set_pressure_assessment(crate::disk_pressure::PressureAssessment {
                disk_free_gb: Some(70.0),
                ..Default::default()
            })
            .await;
        assert!(worker.reserve_slots(1).await);
        handle_release_worker(
            &ctx,
            ReleaseRequest {
                local_wrapper_id: None,
                worker_id: WorkerId::new("disk-worker"),
                disk_peak_output_bytes: None,
                slots: 4,
                build_id: Some(build_id),
                exit_code: Some(0),
                duration_ms: None,
                bytes_transferred: None,
                timing: None,
                worker_fault: false,
                worker_disk_full: false,
                worker_live_checkout_refused: false,
                worker_source_busy: false,
                worker_disk_roots: Vec::new(),
            },
        )
        .await
        .unwrap();
        assert_eq!(worker.used_slots(), 1);
        assert_eq!(worker.available_slots().await, 5);
    }

    /// A worker too small for the estimate is offered while it has ANY free
    /// slot. Clamping the reservation to its total (3) when one slot is already
    /// busy can never succeed, so the capacity-degraded path must reserve what
    /// is free instead of reporting a phantom race and falling back to local.
    #[tokio::test]
    async fn test_degraded_selection_reserves_free_slots_on_partly_busy_worker() {
        let _guard = test_guard!();
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("small-worker", 8)).await;
        let worker = pool.get(&WorkerId::new("small-worker")).await.unwrap();
        worker
            .set_pressure_assessment(crate::disk_pressure::PressureAssessment {
                disk_free_gb: Some(40.0),
                ..Default::default()
            })
            .await;
        assert_eq!(worker.effective_total_slots().await, 3);
        assert!(worker.reserve_slots(1).await);
        let ctx = make_test_context(pool);
        let request = SelectionRequest {
            job_mode: false,
            project: "degraded-busy".to_string(),
            command: None,
            command_priority: CommandPriority::Normal,
            estimated_cores: 4,
            disk_headroom_gib: 0,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::None,
            classification_duration_us: None,
            required_tools: Vec::new(),
            hook_pid: Some(98766),
        };
        let response = handle_select_worker(&ctx, request, false, None)
            .await
            .unwrap();
        assert!(
            response.worker.is_some(),
            "degraded worker with free slots must be admitted: {}",
            response.reason
        );
        assert_eq!(worker.used_slots(), 3);
        let build_id = response.build_id.unwrap();
        assert_eq!(ctx.history.active_build(build_id).unwrap().slots, 2);
    }

    #[tokio::test]
    async fn test_handle_status_includes_pressure_metadata() {
        let _guard = test_guard!();
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("worker1", 8)).await;

        let worker = pool
            .get(&WorkerId::new("worker1"))
            .await
            .expect("worker should exist");
        worker
            .set_pressure_assessment(PressureAssessment {
                state: PressureState::Warning,
                confidence: PressureConfidence::High,
                reason_code: "disk_free_below_warning_gb".to_string(),
                policy_rule: "disk_free_gb<=warning_free_gb".to_string(),
                disk_free_gb: Some(18.0),
                disk_total_gb: Some(120.0),
                disk_free_ratio: Some(0.15),
                build_disk_free_gb: None,
                build_disk_total_gb: None,
                disk_io_util_pct: Some(72.0),
                memory_pressure: Some(44.0),
                telemetry_age_secs: Some(8),
                telemetry_fresh: true,
                evaluated_at_unix_ms: 1_700_000_000_000,
            })
            .await;

        let ctx = make_test_context(pool);
        let status = handle_status(&ctx).await.expect("status should succeed");
        let worker = status
            .workers
            .iter()
            .find(|entry| entry.id == "worker1")
            .expect("worker1 status entry should exist");

        assert_eq!(worker.pressure_state, "warning");
        assert_eq!(worker.pressure_confidence, "high");
        assert_eq!(worker.pressure_reason_code, "disk_free_below_warning_gb");
        assert_eq!(worker.pressure_policy_rule, "disk_free_gb<=warning_free_gb");
        assert_eq!(worker.pressure_disk_free_gb, Some(18.0));
        assert_eq!(worker.pressure_disk_total_gb, Some(120.0));
        assert_eq!(worker.pressure_disk_free_ratio, Some(0.15));
        assert_eq!(worker.pressure_disk_io_util_pct, Some(72.0));
        assert_eq!(worker.pressure_memory_pressure, Some(44.0));
        assert_eq!(worker.pressure_telemetry_age_secs, Some(8));
        assert!(worker.pressure_telemetry_fresh);
    }

    #[tokio::test]
    async fn test_handle_status_emits_critical_pressure_issue() {
        let _guard = test_guard!();
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("worker1", 8)).await;

        let worker = pool
            .get(&WorkerId::new("worker1"))
            .await
            .expect("worker should exist");
        worker
            .set_pressure_assessment(PressureAssessment {
                state: PressureState::Critical,
                confidence: PressureConfidence::High,
                reason_code: "disk_free_below_critical_gb".to_string(),
                policy_rule: "disk_free_gb<=critical_free_gb".to_string(),
                disk_free_gb: Some(4.0),
                disk_total_gb: Some(120.0),
                disk_free_ratio: Some(0.033),
                build_disk_free_gb: None,
                build_disk_total_gb: None,
                disk_io_util_pct: Some(91.0),
                memory_pressure: Some(82.0),
                telemetry_age_secs: Some(7),
                telemetry_fresh: true,
                evaluated_at_unix_ms: 1_700_000_000_000,
            })
            .await;

        let ctx = make_test_context(pool);
        let status = handle_status(&ctx).await.expect("status should succeed");
        assert!(
            status
                .issues
                .iter()
                .any(|issue| issue.summary.contains("critical pressure state")),
            "status issues should include critical pressure signal"
        );
    }

    #[tokio::test]
    async fn test_handle_status_emits_cancellation_cleanup_issue() {
        let _guard = test_guard!();
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("worker1", 8)).await;
        let ctx = make_test_context(pool);

        let active = ctx.history.start_active_build(
            "test-project".to_string(),
            "worker1".to_string(),
            "cargo test".to_string(),
            0,
            4,
            rch_common::BuildLocation::Remote,
        );
        let cancellation = BuildCancellationMetadata {
            operation_id: "cancel-1".to_string(),
            origin: "timeout".to_string(),
            reason_code: "timeout".to_string(),
            decision_path: vec![
                "requested".to_string(),
                "term_sent".to_string(),
                "remote_kill_sent".to_string(),
                "escalated".to_string(),
                "completed".to_string(),
            ],
            escalation_stage: "sigkill".to_string(),
            escalation_count: 2,
            remote_kill_attempted: true,
            cleanup_ok: false,
            history_cancelled: true,
            final_state: "completed".to_string(),
            worker_health: Some(BuildCancellationWorkerHealth {
                status: "unreachable".to_string(),
                speed_score: 0.0,
                used_slots: 4,
                available_slots: 0,
                pressure_state: "critical".to_string(),
                pressure_reason_code: "disk_free_below_critical_gb".to_string(),
            }),
        };
        let _ = ctx
            .history
            .cancel_active_build(active.id, None, Some(cancellation));

        let status = handle_status(&ctx).await.expect("status should succeed");
        assert!(
            status
                .issues
                .iter()
                .any(|issue| issue.summary.contains("cleanup failures")),
            "status issues should include cancellation cleanup failures"
        );
        assert!(
            status
                .issues
                .iter()
                .any(|issue| issue.summary.contains("SIGKILL")),
            "status issues should include cancellation escalation warnings"
        );
    }

    #[tokio::test]
    async fn test_handle_status_emits_live_hook_progress_stall_issue() {
        let _guard = test_guard!();
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("worker1", 8)).await;
        let ctx = make_test_context(pool);

        let active = ctx.history.start_active_build(
            "test-project".to_string(),
            "worker1".to_string(),
            "cargo test".to_string(),
            0,
            4,
            rch_common::BuildLocation::Remote,
        );
        let updated = ctx.history.record_stuck_detector_snapshot(
            active.id,
            crate::history::StuckDetectorSnapshot {
                hook_alive: true,
                heartbeat_stale: false,
                progress_stale: true,
                confidence: 0.25,
                build_age_secs: 240,
                slots_owned: 4,
            },
        );
        assert!(updated.is_some());

        let status = handle_status(&ctx).await.expect("status should succeed");
        let issue = status
            .issues
            .iter()
            .find(|issue| issue.summary.contains("stale progress"))
            .expect("status issues should include live-hook progress stall");

        assert_eq!(issue.severity, "info");
        assert!(issue.summary.contains(&active.id.to_string()));
        assert!(issue.summary.contains("worker1"));
        let remediation = issue
            .remediation
            .as_ref()
            .expect("stall issue should include remediation");
        // A live, heartbeating build is healthy: the advice must never tell an
        // agent to drain the worker or cancel unconditionally.
        assert!(!remediation.contains("rch workers drain"));
        assert!(!remediation.contains("rch cancel"));
        assert!(remediation.contains("rch queue --json"));
    }

    #[tokio::test]
    async fn test_handle_status_with_active_build() {
        let _guard = test_guard!();
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("worker1", 8)).await;
        let ctx = make_test_context(pool);

        // Start a build using the correct API
        ctx.history.start_active_build(
            "test-project".to_string(),
            "worker1".to_string(),
            "cargo build".to_string(),
            12345,
            4,
            rch_common::BuildLocation::Remote,
        );

        let result = handle_status(&ctx).await;
        assert!(result.is_ok());

        let status = result.unwrap();
        assert_eq!(status.active_builds.len(), 1);
        assert_eq!(status.active_builds[0].project_id, "test-project");
        assert_eq!(status.active_builds[0].command, "cargo build");
        assert_eq!(status.active_builds[0].heartbeat_phase, "sync_up");
        assert_eq!(status.active_builds[0].heartbeat_counter, 0);
        assert_eq!(status.active_builds[0].slots, 4);
        assert_eq!(status.active_builds[0].detector_confidence, 0.0);
    }

    // =========================================================================
    // Format wait time tests
    // =========================================================================

    #[test]
    fn test_format_wait_time_edge_cases() {
        let _guard = test_guard!();

        // Exactly 60 seconds
        assert_eq!(format_wait_time(60), "1m");

        // Exactly 1 hour
        assert_eq!(format_wait_time(3600), "1h");

        // 1 hour and 30 minutes
        assert_eq!(format_wait_time(5400), "1h 30m");

        // 2 hours exactly
        assert_eq!(format_wait_time(7200), "2h");

        // Zero seconds
        assert_eq!(format_wait_time(0), "0s");

        // 59 seconds
        assert_eq!(format_wait_time(59), "59s");

        // 61 seconds
        assert_eq!(format_wait_time(61), "1m 1s");
    }

    // =========================================================================
    // Health handler test
    // =========================================================================

    #[test]
    fn test_handle_health() {
        let _guard = test_guard!();
        let pool = WorkerPool::new();
        let ctx = make_test_context(pool);

        let response = handle_health(&ctx);
        assert_eq!(response.status, "healthy");
        assert_eq!(response.version, "0.1.0");
        // Uptime should be small since we just created the context
        assert!(response.uptime_seconds < 10);
    }

    // =========================================================================
    // Budget handler test
    // =========================================================================

    #[test]
    fn test_handle_budget() {
        let _guard = test_guard!();
        let response = handle_budget();
        // Just verify it returns without panic and has expected structure
        // Response has status, budgets, and computed_at fields
        assert!(!response.computed_at.is_empty());
    }

    // =========================================================================
    // Repo Convergence API Tests (bd-vvmd.3.5)
    // =========================================================================

    #[tokio::test]
    async fn test_convergence_status_empty() {
        let _guard = test_guard!();
        let pool = WorkerPool::new();
        let ctx = make_test_context(pool);

        let response = handle_repo_convergence_status(&ctx, None).await;
        match response {
            ApiResponse::Ok(status) => {
                assert_eq!(status.workers.len(), 0);
                assert_eq!(status.summary.total_workers, 0);
                assert_eq!(status.status, "unknown");
            }
            ApiResponse::Error(e) => assert!(false, "Expected Ok, got error: {}", e.message),
        }
    }

    #[tokio::test]
    async fn test_convergence_status_with_workers() {
        let _guard = test_guard!();
        let pool = WorkerPool::new();
        let ctx = make_test_context(pool);

        // Set up convergence state.
        let wid = WorkerId::new("w1");
        ctx.repo_convergence
            .update_required_repos(&wid, vec!["repo-a".into()], vec!["repo-a".into()])
            .await;

        let response = handle_repo_convergence_status(&ctx, None).await;
        match response {
            ApiResponse::Ok(status) => {
                assert_eq!(status.workers.len(), 1);
                assert_eq!(status.workers[0].worker_id, "w1");
                assert_eq!(status.workers[0].drift_state, "ready");
                assert_eq!(status.summary.ready, 1);
                assert_eq!(status.status, "healthy");
            }
            ApiResponse::Error(e) => assert!(false, "Expected Ok, got error: {}", e.message),
        }
    }

    #[tokio::test]
    async fn test_convergence_status_filtered_by_worker() {
        let _guard = test_guard!();
        let pool = WorkerPool::new();
        let ctx = make_test_context(pool);

        let wid1 = WorkerId::new("w1");
        let wid2 = WorkerId::new("w2");
        ctx.repo_convergence
            .update_required_repos(&wid1, vec!["repo-a".into()], vec!["repo-a".into()])
            .await;
        ctx.repo_convergence
            .update_required_repos(&wid2, vec!["repo-b".into()], vec![])
            .await;

        // Filter to w1 only.
        let response = handle_repo_convergence_status(&ctx, Some(&wid1)).await;
        match response {
            ApiResponse::Ok(status) => {
                assert_eq!(status.workers.len(), 1);
                assert_eq!(status.workers[0].worker_id, "w1");
            }
            ApiResponse::Error(e) => assert!(false, "Expected Ok, got error: {}", e.message),
        }
    }

    #[tokio::test]
    async fn test_convergence_status_unknown_worker() {
        let _guard = test_guard!();
        let pool = WorkerPool::new();
        let ctx = make_test_context(pool);

        let wid = WorkerId::new("nonexistent");
        let response = handle_repo_convergence_status(&ctx, Some(&wid)).await;
        match response {
            ApiResponse::Ok(status) => {
                assert_eq!(status.workers.len(), 1);
                assert_eq!(status.workers[0].drift_state, "stale");
                assert!(!status.workers[0].remediation.is_empty());
            }
            ApiResponse::Error(e) => assert!(false, "Expected Ok, got error: {}", e.message),
        }
    }

    #[tokio::test]
    async fn test_convergence_dry_run_ready_worker() {
        let _guard = test_guard!();
        let pool = WorkerPool::new();
        let ctx = make_test_context(pool);

        let wid = WorkerId::new("w1");
        ctx.repo_convergence
            .update_required_repos(&wid, vec!["repo-a".into()], vec!["repo-a".into()])
            .await;

        let response = handle_repo_convergence_dry_run(&ctx, &wid).await;
        match response {
            ApiResponse::Ok(dr) => {
                assert!(!dr.would_attempt, "Ready worker should not attempt sync");
                assert_eq!(dr.current_state, "ready");
            }
            ApiResponse::Error(e) => assert!(false, "Expected Ok, got error: {}", e.message),
        }
    }

    #[tokio::test]
    async fn test_convergence_dry_run_drifting_worker() {
        let _guard = test_guard!();
        let pool = WorkerPool::new();
        let ctx = make_test_context(pool);

        let wid = WorkerId::new("w1");
        ctx.repo_convergence
            .update_required_repos(&wid, vec!["repo-a".into()], vec![])
            .await;

        let response = handle_repo_convergence_dry_run(&ctx, &wid).await;
        match response {
            ApiResponse::Ok(dr) => {
                assert!(
                    dr.would_attempt,
                    "Drifting worker with budget should attempt"
                );
                assert_eq!(dr.current_state, "drifting");
                assert!(!dr.missing_repos.is_empty());
                assert!(dr.has_budget);
            }
            ApiResponse::Error(e) => assert!(false, "Expected Ok, got error: {}", e.message),
        }
    }

    #[tokio::test]
    async fn test_convergence_dry_run_unknown_worker() {
        let _guard = test_guard!();
        let pool = WorkerPool::new();
        let ctx = make_test_context(pool);

        let wid = WorkerId::new("nonexistent");
        let response = handle_repo_convergence_dry_run(&ctx, &wid).await;
        match response {
            ApiResponse::Ok(dr) => {
                assert!(dr.would_attempt);
                assert_eq!(dr.current_state, "stale");
            }
            ApiResponse::Error(e) => assert!(false, "Expected Ok, got error: {}", e.message),
        }
    }

    #[tokio::test]
    async fn test_convergence_repair_resets_to_drifting() {
        let _guard = test_guard!();
        let pool = WorkerPool::new();
        let ctx = make_test_context(pool);

        let wid = WorkerId::new("w1");
        // Set to Ready.
        ctx.repo_convergence
            .update_required_repos(&wid, vec!["repo-a".into()], vec!["repo-a".into()])
            .await;

        let response = handle_repo_convergence_repair(&ctx, &wid).await;
        match response {
            ApiResponse::Ok(repair) => {
                assert_eq!(repair.status, "ok");
                assert_eq!(repair.previous_state, "ready");
                assert_eq!(repair.new_state, "drifting");
                assert_eq!(repair.action, "reset_convergence");
            }
            ApiResponse::Error(e) => assert!(false, "Expected Ok, got error: {}", e.message),
        }
    }

    #[tokio::test]
    async fn test_convergence_repair_no_repos_noop() {
        let _guard = test_guard!();
        let pool = WorkerPool::new();
        let ctx = make_test_context(pool);

        let wid = WorkerId::new("unknown");
        let response = handle_repo_convergence_repair(&ctx, &wid).await;
        match response {
            ApiResponse::Ok(repair) => {
                assert_eq!(repair.status, "noop");
                assert_eq!(repair.action, "none");
            }
            ApiResponse::Error(e) => assert!(false, "Expected Ok, got error: {}", e.message),
        }
    }

    #[tokio::test]
    async fn test_convergence_status_json_serializable() {
        let _guard = test_guard!();
        let pool = WorkerPool::new();
        let ctx = make_test_context(pool);

        let wid = WorkerId::new("w1");
        ctx.repo_convergence
            .update_required_repos(&wid, vec!["repo-a".into()], vec![])
            .await;

        let response = handle_repo_convergence_status(&ctx, None).await;
        // Must serialize without error for the API to work.
        let json = serde_json::to_string(&response).expect("Should serialize to JSON");
        assert!(json.contains("drifting"));
        assert!(json.contains("w1"));
    }

    #[test]
    fn test_parse_convergence_status_route() {
        let _guard = test_guard!();
        let req = parse_request("GET /repo-convergence/status").unwrap();
        assert!(
            matches!(req, ApiRequest::RepoConvergenceStatus { worker_id: None }),
            "Should parse status route without worker filter"
        );
    }

    #[test]
    fn test_parse_convergence_status_with_worker() {
        let _guard = test_guard!();
        let req = parse_request("GET /repo-convergence/status?worker=w1").unwrap();
        match req {
            ApiRequest::RepoConvergenceStatus {
                worker_id: Some(wid),
            } => {
                assert_eq!(wid.as_str(), "w1");
            }
            _ => assert!(false, "Expected RepoConvergenceStatus with worker_id"),
        }
    }

    #[test]
    fn test_parse_convergence_dry_run_route() {
        let _guard = test_guard!();
        let req = parse_request("GET /repo-convergence/dry-run?worker=w1").unwrap();
        match req {
            ApiRequest::RepoConvergenceDryRun { worker_id } => {
                assert_eq!(worker_id.as_str(), "w1");
            }
            _ => assert!(false, "Expected RepoConvergenceDryRun"),
        }
    }

    #[test]
    fn test_parse_convergence_dry_run_missing_worker() {
        let _guard = test_guard!();
        let result = parse_request("GET /repo-convergence/dry-run");
        assert!(result.is_err(), "Should fail without worker parameter");
    }

    #[test]
    fn test_parse_convergence_repair_route() {
        let _guard = test_guard!();
        let req = parse_request("POST /repo-convergence/repair?worker=w1").unwrap();
        match req {
            ApiRequest::RepoConvergenceRepair { worker_id } => {
                assert_eq!(worker_id.as_str(), "w1");
            }
            _ => assert!(false, "Expected RepoConvergenceRepair"),
        }
    }

    #[test]
    fn test_parse_convergence_repair_requires_post() {
        let _guard = test_guard!();
        let result = parse_request("GET /repo-convergence/repair?worker=w1");
        assert!(result.is_err(), "Repair should require POST method");
    }

    #[test]
    fn test_parse_convergence_unknown_subpath() {
        let _guard = test_guard!();
        let result = parse_request("GET /repo-convergence/unknown");
        assert!(result.is_err(), "Unknown subpath should error");
    }

    // ------------------------------------------------------------------
    // worker_issue: the admin axis must win over the telemetry gap it causes.
    //
    // Regression for the field incident where `hz3` sat at 0/10 top-priority
    // slots for ~18 h while `rch status` reported only "stale/missing pressure
    // telemetry" with a remediation ("wait for the next poll, or
    // `rch daemon restart`") that could never work: the poller skips
    // Drained/Disabled workers, and an admin disable is persisted and
    // re-applied on startup.
    // ------------------------------------------------------------------

    /// A disabled worker whose telemetry has (inevitably) gone stale must
    /// report the DISABLE, name its reason, and point at `rch workers enable` —
    /// never the unreachable "wait for the next poll" advice.
    #[test]
    fn worker_issue_disabled_beats_the_telemetry_gap_it_causes() {
        let _guard = test_guard!();
        let issue = worker_issue(
            "hz3",
            WorkerStatus::Disabled,
            CircuitState::Closed,
            PressureState::TelemetryGap,
            "telemetry_unavailable",
            Some("e104-timeout-orphan-unverified: remote build process group not verified dead"),
        )
        .expect("a disabled worker must surface an issue");

        assert_eq!(issue.severity, "warning");
        assert!(
            issue.summary.contains("administratively disabled"),
            "summary must name the real cause, got: {}",
            issue.summary
        );
        assert!(
            issue.summary.contains("e104-timeout-orphan-unverified"),
            "summary must carry the recorded disable reason, got: {}",
            issue.summary
        );
        assert!(
            !issue.summary.contains("stale/missing pressure telemetry"),
            "the telemetry gap must not mask the disable, got: {}",
            issue.summary
        );

        let fix = issue.remediation.expect("a disable is actionable");
        assert!(
            fix.contains("rch workers enable hz3"),
            "must point at the only command that clears it, got: {fix}"
        );
        assert!(
            !fix.contains("daemon restart"),
            "a restart re-applies the durable disable; never suggest it here, got: {fix}"
        );
    }

    /// Same bug class on the sibling admin state: `should_poll_worker` skips
    /// `Drained` too, so it would have grown the identical phantom gap.
    #[test]
    fn worker_issue_drained_beats_the_telemetry_gap_it_causes() {
        let _guard = test_guard!();
        let issue = worker_issue(
            "hz4",
            WorkerStatus::Drained,
            CircuitState::Closed,
            PressureState::TelemetryGap,
            "telemetry_unavailable",
            None,
        )
        .expect("a drained worker must surface an issue");

        assert_eq!(issue.severity, "warning");
        assert!(issue.summary.contains("drained"), "got: {}", issue.summary);
        assert!(
            !issue.summary.contains("stale/missing pressure telemetry"),
            "got: {}",
            issue.summary
        );
        assert!(
            issue
                .remediation
                .expect("drain is actionable")
                .contains("rch workers enable hz4")
        );
    }

    /// A disable with no recorded reason must still be reported, and must not
    /// print an empty parenthetical.
    #[test]
    fn worker_issue_disabled_without_a_recorded_reason_is_still_explicit() {
        let _guard = test_guard!();
        let issue = worker_issue(
            "omarchy",
            WorkerStatus::Disabled,
            CircuitState::Closed,
            PressureState::Healthy,
            "pressure_healthy",
            None,
        )
        .expect("a disabled worker must surface an issue");
        assert!(
            issue.summary.contains("no reason recorded"),
            "got: {}",
            issue.summary
        );
    }

    /// The admin axis also dominates an open circuit: probing a worker the
    /// operator disabled cannot bring it back, so `--force` would be the same
    /// confident-wrong advice.
    #[test]
    fn worker_issue_disabled_beats_an_open_circuit() {
        let _guard = test_guard!();
        let issue = worker_issue(
            "wsurf",
            WorkerStatus::Disabled,
            CircuitState::Open,
            PressureState::TelemetryGap,
            "telemetry_unavailable",
            Some("maintenance"),
        )
        .expect("issue expected");
        assert!(
            issue.summary.contains("administratively disabled"),
            "got: {}",
            issue.summary
        );
        assert!(
            !issue.summary.contains("Circuit open"),
            "got: {}",
            issue.summary
        );
    }

    /// The fix must NOT silence real telemetry gaps on workers that are still
    /// in service — those keep the daemon-driven advice, which is correct there.
    #[test]
    fn worker_issue_active_worker_keeps_the_telemetry_gap_warning() {
        let _guard = test_guard!();
        let issue = worker_issue(
            "vmi1264463",
            WorkerStatus::Healthy,
            CircuitState::Closed,
            PressureState::TelemetryGap,
            "disk_metrics_unavailable",
            None,
        )
        .expect("an active worker in a telemetry gap must still warn");
        assert!(
            issue.summary.contains("stale/missing pressure telemetry"),
            "got: {}",
            issue.summary
        );
        assert!(
            issue
                .remediation
                .expect("gap advice retained")
                .contains("daemon-driven")
        );
    }

    /// Untouched arms still behave: an open circuit and a critical-pressure
    /// worker keep their original error-severity issues, and a healthy worker
    /// reports nothing at all.
    #[test]
    fn worker_issue_preserves_the_pre_existing_arms() {
        let _guard = test_guard!();
        let circuit = worker_issue(
            "w1",
            WorkerStatus::Healthy,
            CircuitState::Open,
            PressureState::Healthy,
            "pressure_healthy",
            None,
        )
        .expect("issue expected");
        assert_eq!(circuit.severity, "error");
        assert!(circuit.summary.contains("Circuit open"));
        // Worker-scoped, so `rch check` rates it degraded rather than not ready.
        assert_eq!(circuit.worker_id.as_deref(), Some("w1"));

        let critical = worker_issue(
            "w2",
            WorkerStatus::Healthy,
            CircuitState::Closed,
            PressureState::Critical,
            "disk_ratio_below_critical",
            None,
        )
        .expect("issue expected");
        assert_eq!(critical.severity, "error");
        assert!(critical.summary.contains("critical pressure state"));
        assert_eq!(critical.worker_id.as_deref(), Some("w2"));

        let unreachable = worker_issue(
            "w3",
            WorkerStatus::Unreachable,
            CircuitState::Closed,
            PressureState::Healthy,
            "pressure_healthy",
            None,
        )
        .expect("issue expected");
        assert_eq!(unreachable.severity, "error");
        assert!(unreachable.summary.contains("is unreachable"));

        let degraded = worker_issue(
            "w4",
            WorkerStatus::Degraded,
            CircuitState::Closed,
            PressureState::Healthy,
            "pressure_healthy",
            None,
        )
        .expect("issue expected");
        assert_eq!(degraded.severity, "warning");
        assert!(degraded.remediation.is_none());

        assert!(
            worker_issue(
                "w5",
                WorkerStatus::Healthy,
                CircuitState::Closed,
                PressureState::Healthy,
                "pressure_healthy",
                None,
            )
            .is_none(),
            "a healthy worker must report no issue"
        );
    }
}
