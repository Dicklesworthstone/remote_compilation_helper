//! Unix socket API for hook-daemon communication.
//!
//! Implements a simple HTTP-like protocol over Unix socket:
//! - Request: `GET /select-worker?project=X&cores=N\n`
//! - Response: JSON `SelectionResponse` or error

use crate::DaemonContext;
use crate::alerts::AlertInfo;
use crate::events::EventBus;
use crate::metrics;
use crate::metrics::budget::{self, BudgetStatusResponse};
use crate::reload;
use crate::telemetry::collect_telemetry_from_worker;
use crate::workers::{
    WorkerCapabilitiesResponse, get_workers_capabilities, handle_worker_disable,
    handle_worker_drain, handle_worker_enable,
};
use anyhow::{Result, anyhow};
use chrono::{Duration as ChronoDuration, Utc};
use rch_common::{
    ApiError, BuildHeartbeatRequest, BuildRecord, BuildStats, CircuitBreakerConfig, CircuitState,
    CommandPriority, ErrorCode, ReleaseRequest, RequiredRuntime, SavedTimeStats, SelectedWorker,
    SelectionReason, SelectionRequest, SelectionResponse, WorkerId, WorkerStatus,
};
use rch_telemetry::protocol::{TelemetrySource, TestRunRecord, TestRunStats, WorkerTelemetry};
use rch_telemetry::speedscore::SpeedScore;
use serde::Serialize;
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tracing::{debug, warn};
use uuid::Uuid;

// ============================================================================
// Helper Functions
// ============================================================================

const MAX_LINE_SIZE: usize = 65536; // 64KB
const MAX_BODY_SIZE: u64 = 10 * 1024 * 1024; // 10MB

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
        /// If true and all workers are busy, enqueue and wait for a worker.
        wait_for_worker: bool,
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
    Shutdown,
    /// Reload configuration (workers.toml) without restart.
    Reload,
    CancelBuild {
        build_id: u64,
        force: bool,
    },
    CancelAllBuilds {
        force: bool,
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
    /// Last disk I/O utilization sample, if available.
    pub pressure_disk_io_util_pct: Option<f64>,
    /// Last memory pressure sample, if available.
    pub pressure_memory_pressure: Option<f64>,
    /// Age of latest telemetry sample in seconds, if available.
    pub pressure_telemetry_age_secs: Option<u64>,
    /// Whether the latest telemetry sample is fresh enough for high-confidence policy decisions.
    pub pressure_telemetry_fresh: bool,
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

/// Local API response enum for daemon endpoints.
///
/// Uses untagged serialization so success cases serialize directly as data,
/// while errors serialize using the unified ApiError format from rch-common.
#[derive(Debug, Serialize)]
#[serde(untagged)]
enum ApiResponse<T: Serialize> {
    Ok(T),
    Error(ApiError),
}

/// Handle an incoming connection on the Unix socket.
pub async fn handle_connection(
    stream: UnixStream,
    ctx: DaemonContext,
    shutdown_tx: tokio::sync::mpsc::Sender<()>,
) -> Result<()> {
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

    // Parse and handle the request
    let (response_json, content_type) = match parse_request(line) {
        Ok(ApiRequest::SelectWorker {
            request,
            wait_for_worker,
        }) => {
            metrics::inc_requests("select-worker");
            let response = handle_select_worker(&ctx, request, wait_for_worker).await?;
            (serde_json::to_string(&response)?, "application/json")
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
            handle_release_worker(&ctx, request).await?;
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
                Duration::from_secs(10),
                reader.take(MAX_BODY_SIZE).read_to_string(&mut body),
            )
            .await
            {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => return Err(e.into()),
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
                Duration::from_secs(10),
                reader.take(MAX_BODY_SIZE).read_to_string(&mut body),
            )
            .await
            {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => return Err(e.into()),
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
                Duration::from_secs(10),
                reader.take(MAX_BODY_SIZE).read_to_string(&mut body),
            )
            .await
            {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => return Err(e.into()),
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
        Ok(ApiRequest::Shutdown) => {
            metrics::inc_requests("shutdown");
            let _ = shutdown_tx.send(()).await;
            (
                "{\"status\":\"shutting_down\"}".to_string(),
                "application/json",
            )
        }
        Ok(ApiRequest::Reload) => {
            metrics::inc_requests("reload");
            // Perform reload using the reload module
            let result = reload::reload_workers(&ctx.pool, None, true).await;
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
        Ok(ApiRequest::CancelBuild { build_id, force }) => {
            metrics::inc_requests("cancel-build");
            let response = handle_cancel_build(&ctx, build_id, force).await;
            (serde_json::to_string(&response)?, "application/json")
        }
        Ok(ApiRequest::CancelAllBuilds { force }) => {
            metrics::inc_requests("cancel-all-builds");
            let response = handle_cancel_all_builds(&ctx, force).await;
            (serde_json::to_string(&response)?, "application/json")
        }
        Ok(ApiRequest::WorkerDrain { worker_id }) => {
            metrics::inc_requests("worker-drain");
            let response = handle_worker_drain(&ctx, &worker_id).await;
            (serde_json::to_string(&response)?, "application/json")
        }
        Ok(ApiRequest::WorkerEnable { worker_id }) => {
            metrics::inc_requests("worker-enable");
            let response = handle_worker_enable(&ctx, &worker_id).await;
            (serde_json::to_string(&response)?, "application/json")
        }
        Ok(ApiRequest::WorkerDisable {
            worker_id,
            reason,
            drain_first,
        }) => {
            metrics::inc_requests("worker-disable");
            let response = handle_worker_disable(&ctx, &worker_id, reason, drain_first).await;
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
                    "worker" => worker_id = Some(urlencoding_decode(value)),
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
                    worker_id: WorkerId::new(urlencoding_decode(worker_part)),
                    days,
                    limit,
                    offset,
                });
            }

            return Ok(ApiRequest::SpeedScore {
                worker_id: WorkerId::new(urlencoding_decode(rest)),
            });
        }
    }

    if path.starts_with("/benchmark/trigger") {
        if method != "POST" {
            return Err(anyhow!("Only POST method supported for benchmark trigger"));
        }
        let (path_only, query) = split_path_query(path);
        let mut worker_id = path_only
            .strip_prefix("/benchmark/trigger/")
            .map(urlencoding_decode);

        for param in query.split('&') {
            if param.is_empty() {
                continue;
            }
            let mut kv = param.splitn(2, '=');
            let key = kv.next().unwrap_or("");
            let value = kv.next().unwrap_or("");
            if key == "worker" {
                worker_id = Some(urlencoding_decode(value));
            }
        }

        let Some(worker_id) = worker_id.filter(|value| !value.is_empty()) else {
            return Err(anyhow!("Missing worker id"));
        };

        return Ok(ApiRequest::BenchmarkTrigger {
            worker_id: WorkerId::new(worker_id),
        });
    }

    if path == "/shutdown" && method == "POST" {
        return Ok(ApiRequest::Shutdown);
    }

    if path == "/reload" && method == "POST" {
        return Ok(ApiRequest::Reload);
    }

    // Build cancellation endpoints
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

                return Ok(ApiRequest::CancelBuild { build_id, force });
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

    if path.starts_with("/self-test/history") {
        let query = path.strip_prefix("/self-test/history").unwrap_or("");
        let query = query.strip_prefix('?').unwrap_or("");
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

    if path.starts_with("/self-test/run") {
        if method != "POST" {
            return Err(anyhow!("Only POST method supported for self-test run"));
        }
        let query = path.strip_prefix("/self-test/run").unwrap_or("");
        let query = query.strip_prefix('?').unwrap_or("");

        let mut worker_ids = Vec::new();
        let mut project = None;
        let mut timeout_secs = None;
        let mut release_mode = true;
        let mut scheduled = false;

        for param in query.split('&') {
            if param.is_empty() {
                continue;
            }
            let mut kv = param.splitn(2, '=');
            let key = kv.next().unwrap_or("");
            let value = kv.next().unwrap_or("");
            match key {
                "worker" => worker_ids.push(urlencoding_decode(value)),
                "project" => project = Some(urlencoding_decode(value)),
                "timeout" => timeout_secs = value.parse().ok(),
                "debug" => {
                    if value == "1" || value.eq_ignore_ascii_case("true") {
                        release_mode = false;
                    }
                }
                "scheduled" => {
                    if value == "1" || value.eq_ignore_ascii_case("true") {
                        scheduled = true;
                    }
                }
                "all" => {
                    if value == "1" || value.eq_ignore_ascii_case("true") {
                        worker_ids.clear();
                    }
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
        }));
    }

    if path.starts_with("/release-worker") {
        if method != "POST" {
            return Err(anyhow!("Only POST method supported for release"));
        }

        let query = path.strip_prefix("/release-worker").unwrap_or("");
        let query = query.strip_prefix('?').unwrap_or("");

        let mut worker_id = None;
        let mut slots = None;
        let mut build_id = None;
        let mut exit_code = None;
        let mut duration_ms = None;
        let mut bytes_transferred = None;

        for param in query.split('&') {
            if param.is_empty() {
                continue;
            }
            let mut kv = param.splitn(2, '=');
            let key = kv.next().unwrap_or("");
            let value = kv.next().unwrap_or("");

            match key {
                "worker" => worker_id = Some(urlencoding_decode(value)),
                "slots" => slots = value.parse().ok(),
                "build_id" => build_id = value.parse().ok(),
                "exit_code" => exit_code = value.parse().ok(),
                "duration_ms" => duration_ms = value.parse().ok(),
                "bytes_transferred" => bytes_transferred = value.parse().ok(),
                _ => {} // Ignore unknown parameters
            }
        }

        let worker_id = worker_id.ok_or_else(|| anyhow!("Missing 'worker' parameter"))?;
        let slots = slots.unwrap_or(0);

        return Ok(ApiRequest::ReleaseWorker(ReleaseRequest {
            worker_id: rch_common::WorkerId::new(worker_id),
            slots,
            build_id,
            exit_code,
            duration_ms,
            bytes_transferred,
            timing: None, // Parsed from body in handle_connection
        }));
    }

    if path.starts_with("/record-build") {
        if method != "POST" {
            return Err(anyhow!("Only POST method supported for record-build"));
        }

        let query = path.strip_prefix("/record-build").unwrap_or("");
        let query = query.strip_prefix('?').unwrap_or("");

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
                "worker" => worker_id = Some(urlencoding_decode(value)),
                "project" => project = Some(urlencoding_decode(value)),
                "is_test" => {
                    let decoded = urlencoding_decode(value);
                    is_test = matches!(decoded.as_str(), "1" | "true" | "yes" | "y" | "on");
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

    if path.starts_with("/build-heartbeat") {
        if method != "POST" {
            return Err(anyhow!("Only POST method supported for build heartbeat"));
        }
        return Ok(ApiRequest::BuildHeartbeat);
    }

    if path.starts_with("/test-run") {
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
                        worker_id = Some(urlencoding_decode(value));
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
                        source = parse_telemetry_source(&urlencoding_decode(value));
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
            let worker_id = urlencoding_decode(parts[0]);
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
                            "reason" => reason = Some(urlencoding_decode(value)),
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

    if !path.starts_with("/select-worker") {
        return Err(anyhow!("Unknown endpoint: {}", path));
    }

    // Parse query parameters for select-worker
    let query = path.strip_prefix("/select-worker").unwrap_or("");
    let query = query.strip_prefix('?').unwrap_or("");

    let mut project = None;
    let mut command = None;
    let mut cores = None;
    let mut wait_for_worker = false;
    let mut toolchain = None;
    let mut required_runtime = RequiredRuntime::default();
    let mut command_priority = CommandPriority::Normal;
    let mut classification_duration_us = None;
    let mut hook_pid = None;

    for param in query.split('&') {
        if param.is_empty() {
            continue;
        }
        let mut kv = param.splitn(2, '=');
        let key = kv.next().unwrap_or("");
        let value = kv.next().unwrap_or("");

        match key {
            "project" => project = Some(urlencoding_decode(value)),
            "command" => command = Some(urlencoding_decode(value)),
            "cores" => cores = value.parse().ok(),
            "wait" | "queue" => {
                wait_for_worker = value == "1" || value.eq_ignore_ascii_case("true");
            }
            "toolchain" => {
                let json = urlencoding_decode(value);
                toolchain = serde_json::from_str(&json).ok();
            }
            "runtime" => {
                // Parse required runtime (rust, bun, node)
                let rt_str = urlencoding_decode(value);
                // Use serde_json to parse the enum variant string (e.g. "bun")
                // We wrap in quotes to make it valid JSON string for the enum
                required_runtime = serde_json::from_str(&format!("\"{}\"", rt_str))
                    .ok()
                    .unwrap_or_default();
            }
            "priority" => {
                let pr_str = urlencoding_decode(value);
                command_priority = pr_str.parse().unwrap_or(CommandPriority::Normal);
            }
            "classification_us" => {
                // Classification latency from hook (for AGENTS.md compliance tracking)
                classification_duration_us = value.parse().ok();
            }
            "hook_pid" => {
                hook_pid = value.parse().ok();
            }
            _ => {} // Ignore unknown parameters
        }
    }

    let project = project.ok_or_else(|| anyhow!("Missing 'project' parameter"))?;
    let estimated_cores = cores.unwrap_or(1);

    Ok(ApiRequest::SelectWorker {
        request: SelectionRequest {
            project,
            command,
            command_priority,
            estimated_cores,
            preferred_workers: vec![],
            toolchain,
            required_runtime,
            classification_duration_us,
            hook_pid,
        },
        wait_for_worker,
    })
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

/// URL percent-decoding.
///
/// Decodes %XX hex sequences to their original characters.
/// Handles UTF-8 multi-byte sequences correctly (e.g. %C3%A9 -> é).
fn urlencoding_decode(s: &str) -> String {
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

    match collect_telemetry_from_worker(&worker, Duration::from_secs(5)).await {
        Ok(telemetry) => {
            ctx.telemetry
                .ingest(telemetry.clone(), TelemetrySource::OnDemand);
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

/// Handle a select-worker request.
async fn handle_select_worker(
    ctx: &DaemonContext,
    request: SelectionRequest,
    wait_for_worker: bool,
) -> Result<SelectionResponse> {
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
    }

    // Mock support: RCH_MOCK_CIRCUIT_OPEN simulates all circuits open
    if std::env::var("RCH_MOCK_CIRCUIT_OPEN").is_ok() {
        debug!("RCH_MOCK_CIRCUIT_OPEN set, returning AllCircuitsOpen");
        return Ok(SelectionResponse {
            worker: None,
            reason: SelectionReason::AllCircuitsOpen,
            build_id: None,
        });
    }

    async fn attempt_select_and_reserve(
        ctx: &DaemonContext,
        request: &SelectionRequest,
    ) -> Result<SelectionResponse> {
        // Retry loop to handle race conditions where slots are taken between selection and reservation.
        let mut attempts = 0;
        const MAX_ATTEMPTS: u32 = 3;

        loop {
            attempts += 1;

            // Use the configured worker selector.
            let result = ctx.worker_selector.select(&ctx.pool, request).await;

            let Some(worker) = result.worker else {
                debug!("No worker selected: {}", result.reason);
                return Ok(SelectionResponse {
                    worker: None,
                    reason: result.reason,
                    build_id: None,
                });
            };

            // Reserve the slots.
            if worker.reserve_slots(request.estimated_cores).await {
                let (id, host, user, identity_file) = {
                    let config = worker.config.read().await;
                    (
                        config.id.clone(),
                        config.host.clone(),
                        config.user.clone(),
                        config.identity_file.clone(),
                    )
                };

                let command = request
                    .command
                    .clone()
                    .unwrap_or_else(|| "<unknown>".to_string());

                let build_id = if let Some(hook_pid) = request.hook_pid.filter(|pid| *pid > 0) {
                    let state = ctx.history.start_active_build(
                        request.project.clone(),
                        id.as_str().to_string(),
                        command.clone(),
                        hook_pid,
                        request.estimated_cores,
                        rch_common::BuildLocation::Remote,
                    );
                    if !cfg!(test) {
                        metrics::inc_active_builds("remote");
                    }
                    ctx.events.emit(
                        "build_started",
                        &serde_json::json!({
                            "build_id": state.id,
                            "project_id": request.project.clone(),
                            "worker_id": id.as_str(),
                            "command": command,
                            "slots": request.estimated_cores,
                        }),
                    );
                    Some(state.id)
                } else {
                    None
                };

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
                    }),
                    reason: SelectionReason::Success,
                    build_id,
                });
            }

            warn!(
                "Failed to reserve {} slots on {} (race condition), attempt {}/{}",
                request.estimated_cores,
                worker.config.read().await.id,
                attempts,
                MAX_ATTEMPTS
            );

            if attempts >= MAX_ATTEMPTS {
                // Give up after max attempts.
                return Ok(SelectionResponse {
                    worker: None,
                    reason: SelectionReason::AllWorkersBusy,
                    build_id: None,
                });
            }
            // Loop again - next selection will see reduced slot count.
        }
    }

    let initial = attempt_select_and_reserve(ctx, &request).await?;
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

    let Some(queued) = ctx.history.enqueue_build(
        request.project.clone(),
        command.clone(),
        hook_pid,
        request.estimated_cores,
    ) else {
        // Queue full - fall back to the normal busy response.
        return Ok(initial);
    };

    ctx.history.update_queue_estimates();
    if !cfg!(test) {
        metrics::set_build_queue_depth(ctx.history.queue_depth());
    }
    ctx.events.emit(
        "build_queued",
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
    let queue_timeout = Duration::from_secs(ctx.queue_timeout_secs);

    loop {
        // Check if the queue wait has timed out
        if queued.queued_at_mono.elapsed() > queue_timeout {
            let _ = ctx.history.remove_queued_build(queued.id);
            ctx.history.update_queue_estimates();
            if !cfg!(test) {
                metrics::set_build_queue_depth(ctx.history.queue_depth());
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
            });
        }

        // Only the head-of-line build attempts selection (simple FIFO).
        if ctx.history.queue_position(queued.id) != Some(1) {
            tokio::time::sleep(QUEUE_POLL_INTERVAL).await;
            continue;
        }

        // If the hook process exited while waiting, drop the queued build to avoid leaking slots.
        if hook_pid > 0 && !is_process_alive(hook_pid) {
            let _ = ctx.history.remove_queued_build(queued.id);
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
            });
        }

        let response = attempt_select_and_reserve(ctx, &request).await?;
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
            let _ = ctx.history.remove_queued_build(queued.id);
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

        tokio::time::sleep(QUEUE_POLL_INTERVAL).await;
    }
}

/// Handle a release-worker request.
async fn handle_release_worker(ctx: &DaemonContext, request: ReleaseRequest) -> Result<()> {
    debug!(
        "Releasing {} slots on worker {}",
        request.slots, request.worker_id
    );
    ctx.pool
        .release_slots(&request.worker_id, request.slots)
        .await;

    if let Some(build_id) = request.build_id {
        let exit_code = request.exit_code.unwrap_or(0);
        let record = ctx.history.finish_active_build(
            build_id,
            exit_code,
            request.duration_ms,
            request.bytes_transferred,
            request.timing,
        );
        if let Some(ref rec) = record {
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

            // Record successful builds for affinity pinning
            if exit_code == 0
                && let Some(ref worker_id) = rec.worker_id
            {
                ctx.worker_selector
                    .record_success(worker_id, &rec.project_id)
                    .await;
            }
        }
    }
    Ok(())
}

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

/// Handle a readiness check request.
async fn handle_ready(ctx: &DaemonContext) -> ReadyResponse {
    let workers = ctx.pool.all_workers().await;

    // Check if any workers are available
    let mut workers_available = false;
    for w in workers {
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

/// Send a signal to a process using the kill command.
///
/// Returns true if the signal was sent successfully, false otherwise.
fn send_signal_to_process(pid: u32, force: bool) -> bool {
    if pid == 0 {
        return false;
    }

    let signal = if force { "KILL" } else { "TERM" };

    // Use kill command which is available on all Unix systems
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

    // `kill -0` performs error checking without sending a signal.
    // Exit status 0 means the process exists and is signalable.
    std::process::Command::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// Handle a build cancellation request.
///
/// Cancels an active build by:
/// 1. Sending SIGTERM to the hook process (which propagates to remote)
/// 2. Marking the build as cancelled in history
/// 3. Releasing worker slots
async fn handle_cancel_build(
    ctx: &DaemonContext,
    build_id: u64,
    force: bool,
) -> CancelBuildResponse {
    // Look up the active build
    let active_build = match ctx.history.active_build(build_id) {
        Some(build) => build,
        None => {
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

    // Send signal to the hook process
    // SIGTERM for graceful, SIGKILL for force
    if hook_pid > 0 && !send_signal_to_process(hook_pid, force) {
        debug!("Failed to send signal to hook process {}", hook_pid);
        // Process might have already exited, continue with cleanup
    }

    // Cancel the build in history (marks as cancelled with exit code 130)
    if ctx.history.cancel_active_build(build_id, None).is_some() && !cfg!(test) {
        metrics::dec_active_builds("remote");
        metrics::inc_build_total("cancelled", "remote");
    }

    // Release worker slots
    if let Some(worker) = ctx.pool.get(&WorkerId::new(&worker_id)).await {
        worker.release_slots(slots).await;
    }

    CancelBuildResponse {
        status: "cancelled".to_string(),
        build_id,
        worker_id: Some(worker_id),
        project_id: Some(project_id),
        message: Some(if force {
            "Build forcefully terminated".to_string()
        } else {
            "Build cancellation signal sent".to_string()
        }),
        slots_released: slots,
    }
}

/// Handle cancellation of all active builds.
async fn handle_cancel_all_builds(ctx: &DaemonContext, force: bool) -> CancelAllBuildsResponse {
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
        let build_id = build.id;
        let worker_id = build.worker_id.clone();
        let project_id = build.project_id.clone();
        let slots = build.slots;
        let hook_pid = build.hook_pid;

        // Send signal to hook process
        if hook_pid > 0 {
            send_signal_to_process(hook_pid, force);
        }

        // Cancel in history
        if ctx.history.cancel_active_build(build_id, None).is_some() && !cfg!(test) {
            metrics::dec_active_builds("remote");
            metrics::inc_build_total("cancelled", "remote");
        }

        // Release worker slots
        if let Some(worker) = ctx.pool.get(&WorkerId::new(&worker_id)).await {
            worker.release_slots(slots).await;
        }

        cancelled.push(CancelledBuildInfo {
            build_id,
            worker_id,
            project_id,
            slots_released: slots,
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
            }
        )),
    }
}

/// Handle a status request.
async fn handle_status(ctx: &DaemonContext) -> Result<DaemonFullStatus> {
    let workers = ctx.pool.all_workers().await;

    let mut workers_healthy = 0;
    let mut slots_total = 0u32;
    let mut slots_available = 0u32;

    let mut worker_infos = Vec::with_capacity(workers.len());
    let mut issues = Vec::new();

    for worker in &workers {
        let status = worker.status().await;
        let (worker_id, host, user, total_slots) = {
            let config = worker.config.read().await;
            (
                config.id.to_string(),
                config.host.clone(),
                config.user.clone(),
                config.total_slots,
            )
        };
        let available_slots = worker.available_slots().await;
        let used_slots = total_slots - available_slots;

        // Count healthy workers
        if status == WorkerStatus::Healthy {
            workers_healthy += 1;
        }

        slots_total = slots_total.saturating_add(total_slots);
        slots_available = slots_available.saturating_add(available_slots);

        // Build worker status info
        let status_str = match status {
            WorkerStatus::Healthy => "healthy",
            WorkerStatus::Degraded => "degraded",
            WorkerStatus::Unreachable => "unreachable",
            WorkerStatus::Draining => "draining",
            WorkerStatus::Drained => "drained",
            WorkerStatus::Disabled => "disabled",
        };

        // Get circuit state and stats from worker
        let circuit_stats = worker.circuit_stats().await;
        let circuit_state = circuit_stats.state();
        let circuit_str = match circuit_state {
            CircuitState::Closed => "closed",
            CircuitState::Open => "open",
            CircuitState::HalfOpen => "half_open",
        };
        let pressure = worker.pressure_assessment().await;

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
            pressure_disk_io_util_pct: pressure.disk_io_util_pct,
            pressure_memory_pressure: pressure.memory_pressure,
            pressure_telemetry_age_secs: pressure.telemetry_age_secs,
            pressure_telemetry_fresh: pressure.telemetry_fresh,
        });

        // Generate issues based on worker state
        if circuit_state == CircuitState::Open {
            issues.push(Issue {
                severity: "error".to_string(),
                summary: format!("Circuit open for worker '{}'", worker_id),
                remediation: Some(format!("rch workers probe {} --force", worker_id)),
            });
        } else if pressure.state == crate::disk_pressure::PressureState::Critical {
            issues.push(Issue {
                severity: "error".to_string(),
                summary: format!(
                    "Worker '{}' in critical pressure state ({})",
                    worker_id, pressure.reason_code
                ),
                remediation: Some(
                    "rch workers capabilities --refresh (inspect pressure metrics and ballast policy)"
                        .to_string(),
                ),
            });
        } else if pressure.state == crate::disk_pressure::PressureState::TelemetryGap {
            issues.push(Issue {
                severity: "warning".to_string(),
                summary: format!(
                    "Worker '{}' has stale/missing pressure telemetry ({})",
                    worker_id, pressure.reason_code
                ),
                remediation: Some(
                    "rch workers capabilities --refresh (re-probe worker metrics)".to_string(),
                ),
            });
        } else if status == WorkerStatus::Unreachable {
            issues.push(Issue {
                severity: "error".to_string(),
                summary: format!("Worker '{}' is unreachable", worker_id),
                remediation: Some(format!("rch workers probe {}", worker_id)),
            });
        } else if status == WorkerStatus::Degraded {
            issues.push(Issue {
                severity: "warning".to_string(),
                summary: format!("Worker '{}' is degraded (slow response)", worker_id),
                remediation: None,
            });
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
        let start = now - uptime_secs;
        // Format as ISO 8601
        let dt = chrono::DateTime::from_timestamp(start as i64, 0).unwrap_or_else(chrono::Utc::now);
        dt.to_rfc3339()
    };

    // Get recent builds from history
    let recent_builds = ctx.history.recent(20);
    let stats = ctx.history.stats();
    let test_stats = ctx.telemetry.test_run_stats().await;

    // Collect active alerts from the alert manager
    let alerts = ctx.alert_manager.active_alerts();

    // Update queue depth metric
    let queue_depth = ctx.history.queue_depth();
    if !cfg!(test) {
        metrics::set_build_queue_depth(queue_depth);
    }

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
        workers: worker_infos,
        active_builds: ctx
            .history
            .active_builds()
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
    })
}

#[cfg(test)]
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
    use rch_common::{SelfTestConfig, WorkerCapabilities};
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
        DaemonContext {
            pool,
            worker_selector: Arc::new(WorkerSelector::new()),
            history: Arc::new(BuildHistory::new(100)),
            telemetry: Arc::new(TelemetryStore::new(Duration::from_secs(300), None)),
            benchmark_queue: Arc::new(BenchmarkQueue::new(ChronoDuration::minutes(5))),
            benchmark_trigger: make_test_benchmark_trigger(),
            events: EventBus::new(16),
            self_test,
            alert_manager,
            started_at: Instant::now(),
            socket_path: "/tmp/test.sock".to_string(),
            version: "0.1.0",
            pid: 1234,
            queue_timeout_secs: 300,
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

    #[test]
    fn test_parse_request_basic() {
        let _guard = test_guard!();
        let req = parse_request("GET /select-worker?project=myproject&cores=4").unwrap();
        let ApiRequest::SelectWorker { request: req, .. } = req else {
            panic!("expected select-worker request");
        };
        assert_eq!(req.project, "myproject");
        assert_eq!(req.estimated_cores, 4);
    }

    #[test]
    fn test_parse_request_project_only() {
        let _guard = test_guard!();
        let req = parse_request("GET /select-worker?project=test").unwrap();
        let ApiRequest::SelectWorker { request: req, .. } = req else {
            panic!("expected select-worker request");
        };
        assert_eq!(req.project, "test");
        assert_eq!(req.estimated_cores, 1); // Default
    }

    #[test]
    fn test_parse_request_with_spaces() {
        let _guard = test_guard!();
        let req = parse_request("GET /select-worker?project=my%20project&cores=2").unwrap();
        let ApiRequest::SelectWorker { request: req, .. } = req else {
            panic!("expected select-worker request");
        };
        assert_eq!(req.project, "my project");
        assert_eq!(req.estimated_cores, 2);
    }

    #[test]
    fn test_parse_request_with_priority_hint() {
        let _guard = test_guard!();
        let req = parse_request("GET /select-worker?project=test&cores=2&priority=high").unwrap();
        let ApiRequest::SelectWorker { request: req, .. } = req else {
            panic!("expected select-worker request");
        };
        assert_eq!(req.command_priority, rch_common::CommandPriority::High);
    }

    #[test]
    fn test_parse_request_invalid_priority_defaults_to_normal() {
        let _guard = test_guard!();
        let req = parse_request("GET /select-worker?project=test&cores=2&priority=urgent").unwrap();
        let ApiRequest::SelectWorker { request: req, .. } = req else {
            panic!("expected select-worker request");
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
            _ => panic!("expected speedscore request"),
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
            _ => panic!("expected speedscore history request"),
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
            _ => panic!("expected workers capabilities request"),
        }

        let req = parse_request("GET /workers/capabilities?refresh=true").unwrap();
        match req {
            ApiRequest::WorkersCapabilities { refresh } => {
                assert!(refresh);
            }
            _ => panic!("expected workers capabilities request"),
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
            _ => panic!("expected benchmark trigger request"),
        }
    }

    #[test]
    fn test_parse_request_events() {
        let _guard = test_guard!();
        let req = parse_request("GET /events").unwrap();
        assert!(matches!(req, ApiRequest::Events), "expected events request");
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
            _ => panic!("expected telemetry poll request"),
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
            _ => panic!("expected self-test history request"),
        }
    }

    #[test]
    fn test_parse_request_self_test_run() {
        let _guard = test_guard!();
        let req =
            parse_request("POST /self-test/run?worker=css&timeout=120&debug=1&scheduled=false")
                .unwrap();
        let ApiRequest::SelfTestRun(req) = req else {
            panic!("expected self-test run request");
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
            panic!("expected select-worker request");
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
            panic!("expected select-worker request");
        };
        assert_eq!(req.required_runtime, RequiredRuntime::Bun);

        let query = "GET /select-worker?project=test&runtime=rust";
        let req = parse_request(query).unwrap();
        let ApiRequest::SelectWorker { request: req, .. } = req else {
            panic!("expected select-worker request");
        };
        assert_eq!(req.required_runtime, RequiredRuntime::Rust);

        // Invalid runtime should default to None
        let query = "GET /select-worker?project=test&runtime=invalid";
        let req = parse_request(query).unwrap();
        let ApiRequest::SelectWorker { request: req, .. } = req else {
            panic!("expected select-worker request");
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
    fn test_urlencoding_decode_basic() {
        let _guard = test_guard!();
        assert_eq!(urlencoding_decode("hello%20world"), "hello world");
        assert_eq!(urlencoding_decode("path%2Fto%2Ffile"), "path/to/file");
        assert_eq!(urlencoding_decode("foo%3Abar"), "foo:bar");
    }

    #[test]
    fn test_urlencoding_decode_special_chars() {
        let _guard = test_guard!();
        assert_eq!(urlencoding_decode("a%26b%3Dc"), "a&b=c");
        assert_eq!(urlencoding_decode("100%25"), "100%");
        assert_eq!(urlencoding_decode("hello%2Bworld"), "hello+world");
    }

    #[test]
    fn test_urlencoding_decode_plus_as_space() {
        let _guard = test_guard!();
        assert_eq!(urlencoding_decode("hello+world"), "hello world");
    }

    #[test]
    fn test_urlencoding_decode_no_encoding() {
        let _guard = test_guard!();
        assert_eq!(urlencoding_decode("simple"), "simple");
        assert_eq!(
            urlencoding_decode("with-dash_underscore"),
            "with-dash_underscore"
        );
    }

    #[test]
    fn test_urlencoding_decode_invalid() {
        let _guard = test_guard!();
        // Invalid hex should be preserved
        assert_eq!(urlencoding_decode("foo%GGbar"), "foo%GGbar");
        // Incomplete sequence at end
        assert_eq!(urlencoding_decode("foo%"), "foo%");
    }

    #[test]
    fn test_urlencoding_decode_utf8() {
        let _guard = test_guard!();
        // "é" is %C3%A9 in UTF-8
        assert_eq!(urlencoding_decode("%C3%A9"), "é");
        // "こんにちは" (Konnichiwa)
        // こ: %E3%81%93
        // ん: %E3%82%93
        // に: %E3%81%AB
        // ち: %E3%81%A1
        // は: %E3%81%AF
        assert_eq!(
            urlencoding_decode("%E3%81%93%E3%82%93%E3%81%AB%E3%81%A1%E3%81%AF"),
            "こんにちは"
        );
        // Mixed
        assert_eq!(urlencoding_decode("hello%20%F0%9F%8C%8D"), "hello 🌍");
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
        }
    }

    #[tokio::test]
    async fn test_handle_select_worker_no_workers_configured() {
        let pool = WorkerPool::new();
        let ctx = make_test_context(pool);
        let request = SelectionRequest {
            project: "test".to_string(),
            command: None,
            command_priority: CommandPriority::Normal,
            estimated_cores: 4,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
            hook_pid: None,
        };

        let response = handle_select_worker(&ctx, request, false).await.unwrap();
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
            project: "test".to_string(),
            command: None,
            command_priority: CommandPriority::Normal,
            estimated_cores: 2,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
            hook_pid: None,
        };

        let response = handle_select_worker(&ctx, request, false).await.unwrap();
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
            project: "test".to_string(),
            command: None,
            command_priority: CommandPriority::Normal,
            estimated_cores: 8, // Request more than total slots
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
            hook_pid: None,
        };

        let response = handle_select_worker(&ctx, request, false).await.unwrap();
        assert!(response.worker.is_none());
        assert_eq!(response.reason, SelectionReason::AllWorkersBusy);
    }

    #[tokio::test]
    async fn test_handle_select_worker_success() {
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("worker1", 8)).await;

        let ctx = make_test_context(pool);
        let request = SelectionRequest {
            project: "test".to_string(),
            command: None,
            command_priority: CommandPriority::Normal,
            estimated_cores: 2,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
            hook_pid: None,
        };

        let response = handle_select_worker(&ctx, request, false).await.unwrap();
        assert!(response.worker.is_some());
        assert_eq!(response.reason, SelectionReason::Success);

        let worker = response.worker.unwrap();
        assert_eq!(worker.id.as_str(), "worker1");
        // Should have reserved 2 slots
        assert_eq!(worker.slots_available, 6);
    }

    #[tokio::test]
    async fn test_handle_select_worker_tracks_active_build_when_hook_pid_present() {
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("worker1", 8)).await;

        let ctx = make_test_context(pool);
        let request = SelectionRequest {
            project: "test-project".to_string(),
            command: Some("cargo build --release".to_string()),
            command_priority: CommandPriority::Normal,
            estimated_cores: 2,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
            hook_pid: Some(4242),
        };

        let response = handle_select_worker(&ctx, request, false).await.unwrap();
        assert_eq!(response.reason, SelectionReason::Success);
        let build_id = response.build_id.expect("build_id should be assigned");

        let active = ctx.history.active_build(build_id).expect("active build");
        assert_eq!(active.project_id, "test-project");
        assert_eq!(active.worker_id, "worker1");
        assert_eq!(active.command, "cargo build --release");
        assert_eq!(active.hook_pid, 4242);
        assert_eq!(active.slots, 2);

        // Release should finalize the active build and move it into history
        handle_release_worker(
            &ctx,
            ReleaseRequest {
                worker_id: WorkerId::new("worker1"),
                slots: 2,
                build_id: Some(build_id),
                exit_code: Some(0),
                duration_ms: None,
                bytes_transferred: None,
                timing: None,
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

    #[tokio::test]
    async fn test_handle_select_worker_preferred() {
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("worker1", 8)).await;
        pool.add_worker(make_test_worker("worker2", 8)).await;

        let ctx = make_test_context(pool);
        let request = SelectionRequest {
            project: "test".to_string(),
            command: None,
            command_priority: CommandPriority::Normal,
            estimated_cores: 2,
            preferred_workers: vec![WorkerId::new("worker2")],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
            hook_pid: None,
        };

        let response = handle_select_worker(&ctx, request, false).await.unwrap();
        let worker = response.worker.unwrap();
        assert_eq!(worker.id.as_str(), "worker2");
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
            pressure_disk_io_util_pct: Some(18.0),
            pressure_memory_pressure: Some(44.0),
            pressure_telemetry_age_secs: Some(7),
            pressure_telemetry_fresh: true,
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
            id: 1,
            project_id: "test".to_string(),
            command: "cargo test".to_string(),
            queued_at: "2025-01-01T00:00:00Z".to_string(),
            position: 1,
            slots_needed: 4,
            estimated_start: Some("2025-01-01T00:01:00Z".to_string()),
            wait_time: "1m 30s".to_string(),
        };
        let json = serde_json::to_string(&build).unwrap();
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
        };
        let json = serde_json::to_string(&issue).unwrap();
        assert!(json.contains("\"severity\":\"warning\""));
        assert!(json.contains("\"remediation\":\"rch doctor\""));
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
        let req = parse_request("POST /shutdown").unwrap();
        assert!(matches!(req, ApiRequest::Shutdown));
    }

    #[test]
    fn test_parse_request_cancel_build() {
        let _guard = test_guard!();
        let req = parse_request("POST /builds/123/cancel").unwrap();
        match req {
            ApiRequest::CancelBuild { build_id, force } => {
                assert_eq!(build_id, 123);
                assert!(!force);
            }
            _ => panic!("expected cancel build request"),
        }

        let req = parse_request("POST /builds/456/cancel?force=true").unwrap();
        match req {
            ApiRequest::CancelBuild { build_id, force } => {
                assert_eq!(build_id, 456);
                assert!(force);
            }
            _ => panic!("expected cancel build request with force"),
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
            _ => panic!("expected cancel all builds request"),
        }

        let req = parse_request("POST /builds/cancel-all?force=true").unwrap();
        match req {
            ApiRequest::CancelAllBuilds { force } => {
                assert!(force);
            }
            _ => panic!("expected cancel all builds with force"),
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
            _ => panic!("expected worker drain request"),
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
            _ => panic!("expected worker enable request"),
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
            _ => panic!("expected worker disable request"),
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
            _ => panic!("expected worker disable request with options"),
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
            _ => panic!("expected release worker request"),
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
            _ => panic!("expected release worker request with build_id"),
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
            _ => panic!("expected release worker request with exit_code"),
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
            _ => panic!("expected record build request"),
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
            _ => panic!("expected ingest telemetry request"),
        }

        let req = parse_request("POST /telemetry/ingest?source=ssh_poll").unwrap();
        match req {
            ApiRequest::IngestTelemetry(source) => {
                assert_eq!(source, TelemetrySource::SshPoll);
            }
            _ => panic!("expected ingest telemetry request"),
        }
    }

    #[test]
    fn test_parse_request_wait_for_worker() {
        let _guard = test_guard!();
        let req = parse_request("GET /select-worker?project=test&wait=true").unwrap();
        match req {
            ApiRequest::SelectWorker {
                wait_for_worker, ..
            } => {
                assert!(wait_for_worker);
            }
            _ => panic!("expected select worker request"),
        }

        let req = parse_request("GET /select-worker?project=test&wait=false").unwrap();
        match req {
            ApiRequest::SelectWorker {
                wait_for_worker, ..
            } => {
                assert!(!wait_for_worker);
            }
            _ => panic!("expected select worker request"),
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
        assert_eq!(response.new_status, Some("draining".to_string()));
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
            _ => panic!("expected error response"),
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
            _ => panic!("expected ok response"),
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
            _ => panic!("expected ok response"),
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
            _ => panic!("expected error response"),
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
            _ => panic!("expected ok response"),
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
            _ => panic!("expected rate-limited error response"),
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
            _ => panic!("expected error response"),
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
            _ => panic!("expected ok response"),
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
            _ => panic!("expected ok response"),
        }

        // Request 1000 days - should be clamped to 365
        let response =
            handle_speedscore_history(&ctx, &WorkerId::new("worker1"), 1000, 20, 0).await;
        match response {
            ApiResponse::Ok(r) => {
                assert_eq!(r.worker_id, "worker1");
            }
            _ => panic!("expected ok response"),
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
            _ => panic!("expected ok response"),
        }

        // Request limit of 5000 - should be clamped to 1000
        let response = handle_speedscore_history(&ctx, &WorkerId::new("worker1"), 7, 5000, 0).await;
        match response {
            ApiResponse::Ok(r) => {
                assert_eq!(r.pagination.limit, 1000);
            }
            _ => panic!("expected ok response"),
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
            _ => panic!("expected ok response"),
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
            _ => panic!("expected ok response"),
        }
    }

    // =========================================================================
    // Release worker tests
    // =========================================================================

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
            worker_id: WorkerId::new("worker1"),
            slots: 4,
            build_id: None,
            exit_code: None,
            duration_ms: None,
            bytes_transferred: None,
            timing: None,
        };

        let result = handle_release_worker(&ctx, request).await;
        assert!(result.is_ok());

        // Verify slots were released
        let available = worker.available_slots().await;
        assert_eq!(available, 8);
    }

    #[tokio::test]
    async fn test_handle_release_worker_with_build_completion() {
        let _guard = test_guard!();
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("worker1", 8)).await;

        let ctx = make_test_context(pool.clone());

        // Start a build first using the correct API
        let build = ctx.history.start_active_build(
            "test-project".to_string(),
            "worker1".to_string(),
            "cargo build".to_string(),
            12345,
            4,
            rch_common::BuildLocation::Remote,
        );
        let build_id = build.id;

        // Reserve slots
        let worker = pool.get(&WorkerId::new("worker1")).await.unwrap();
        worker.reserve_slots(4).await;

        let request = ReleaseRequest {
            worker_id: WorkerId::new("worker1"),
            slots: 4,
            build_id: Some(build_id),
            exit_code: Some(0),
            duration_ms: Some(5000),
            bytes_transferred: Some(1024 * 1024),
            timing: None,
        };

        let result = handle_release_worker(&ctx, request).await;
        assert!(result.is_ok());

        // Verify build was completed in history
        let recent = ctx.history.recent(10);
        let completed = recent.iter().find(|b| b.id == build_id);
        assert!(completed.is_some());
        assert_eq!(completed.unwrap().exit_code, 0);
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
}
