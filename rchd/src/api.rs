//! Unix socket API for hook-daemon communication.
//!
//! Implements a simple HTTP-like protocol over Unix socket:
//! - Request: `GET /select-worker?project=X&cores=N\n`
//! - Response: JSON `SelectionResponse` or error

use crate::DaemonContext;
use crate::alerts::AlertInfo;
use crate::events::EventBus;
use crate::health::{HealthConfig, probe_worker_capabilities};
use crate::metrics;
use crate::metrics::budget::{self, BudgetStatusResponse};
use crate::reload;
use crate::telemetry::collect_telemetry_from_worker;
use anyhow::{Result, anyhow};
use chrono::{Duration as ChronoDuration, Utc};
use rch_common::{
    ApiError, BuildRecord, BuildStats, CircuitBreakerConfig, CircuitState, CommandPriority,
    ErrorCode, ReleaseRequest, RequiredRuntime, SelectedWorker, SelectionReason, SelectionRequest,
    SelectionResponse, WorkerCapabilities, WorkerId, WorkerStatus,
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

/// Parsed API request variants.
#[derive(Debug)]
enum ApiRequest {
    SelectWorker(SelectionRequest),
    ReleaseWorker(ReleaseRequest),
    RecordBuild {
        worker_id: WorkerId,
        project: String,
        is_test: bool,
    },
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
    /// Currently active builds (placeholder for future).
    pub active_builds: Vec<ActiveBuild>,
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
}

/// Worker capabilities information.
#[derive(Debug, Serialize)]
pub struct WorkerCapabilitiesInfo {
    pub id: String,
    pub host: String,
    pub user: String,
    pub capabilities: WorkerCapabilities,
}

/// Worker capabilities response.
#[derive(Debug, Serialize)]
pub struct WorkerCapabilitiesResponse {
    pub workers: Vec<WorkerCapabilitiesInfo>,
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

/// Response for worker state changes (drain/enable/disable).
#[derive(Debug, Serialize)]
pub struct WorkerStateResponse {
    pub status: String,
    pub worker_id: String,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_slots: Option<u32>,
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
    let n = reader.read_line(&mut line).await?;
    if n == 0 {
        return Ok(()); // Connection closed
    }

    let line = line.trim();
    debug!("Received request: {}", line);

    // Parse and handle the request
    let (response_json, content_type) = match parse_request(line) {
        Ok(ApiRequest::SelectWorker(request)) => {
            metrics::inc_requests("select-worker");
            let response = handle_select_worker(&ctx, request).await?;
            (serde_json::to_string(&response)?, "application/json")
        }
        Ok(ApiRequest::ReleaseWorker(request)) => {
            metrics::inc_requests("release-worker");
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
        Ok(ApiRequest::IngestTelemetry(source)) => {
            metrics::inc_requests("telemetry");
            let mut body = String::new();
            reader.read_to_string(&mut body).await?;
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
            reader.read_to_string(&mut body).await?;
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
                    "limit" => limit = value.parse().unwrap_or(limit),
                    "offset" => offset = value.parse().unwrap_or(offset),
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
                        "limit" => limit = value.parse().unwrap_or(limit),
                        "offset" => offset = value.parse().unwrap_or(offset),
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
    if path.starts_with("/cancel-build") && method == "POST" {
        let query = path.strip_prefix("/cancel-build").unwrap_or("");
        let query = query.strip_prefix('?').unwrap_or("");

        let mut build_id = None;
        let mut force = false;

        for param in query.split('&') {
            if param.is_empty() {
                continue;
            }
            let mut kv = param.splitn(2, '=');
            let key = kv.next().unwrap_or("");
            let value = kv.next().unwrap_or("");

            match key {
                "build_id" | "id" => build_id = value.parse().ok(),
                "force" => force = value == "1" || value.eq_ignore_ascii_case("true"),
                _ => {}
            }
        }

        let build_id = build_id.ok_or_else(|| anyhow!("Missing 'build_id' parameter"))?;
        return Ok(ApiRequest::CancelBuild { build_id, force });
    }

    if path.starts_with("/cancel-all-builds") && method == "POST" {
        let query = path.strip_prefix("/cancel-all-builds").unwrap_or("");
        let query = query.strip_prefix('?').unwrap_or("");

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
                limit = value.parse().unwrap_or(limit);
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
                "test" => {
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

    if path.starts_with("/test-run") {
        if method != "POST" {
            return Err(anyhow!("Only POST method supported for test run"));
        }
        return Ok(ApiRequest::TestRun);
    }

    if path.starts_with("/telemetry") {
        if path.starts_with("/telemetry/poll") {
            if method != "POST" {
                return Err(anyhow!("Only POST method supported for telemetry polling"));
            }

            let query = path.strip_prefix("/telemetry/poll").unwrap_or("");
            let query = query.strip_prefix('?').unwrap_or("");
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
            return Ok(ApiRequest::TelemetryPoll {
                worker_id: WorkerId::new(worker_id),
            });
        }

        if method != "POST" {
            return Err(anyhow!(
                "Only POST method supported for telemetry ingestion"
            ));
        }

        let query = path.strip_prefix("/telemetry").unwrap_or("");
        let query = query.strip_prefix('?').unwrap_or("");

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

        let source = source.unwrap_or(TelemetrySource::Piggyback);
        return Ok(ApiRequest::IngestTelemetry(source));
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

    Ok(ApiRequest::SelectWorker(SelectionRequest {
        project,
        command,
        command_priority,
        estimated_cores,
        preferred_workers: vec![],
        toolchain,
        required_runtime,
        classification_duration_us,
        hook_pid,
    }))
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
                error: Some("worker_not_found".to_string()),
                worker_id: Some(worker_id.to_string()),
            };
        }
    };

    let status = worker.status().await;
    if matches!(status, WorkerStatus::Unreachable | WorkerStatus::Disabled) {
        return TelemetryPollResponse {
            status: "error".to_string(),
            telemetry: None,
            error: Some("worker_unreachable".to_string()),
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
            format!("Worker '{}' does not exist", worker_id),
            Some(worker_id),
            None,
        ));
    }

    match ctx.telemetry.latest_speedscore(worker_id.as_str()) {
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
            format!("Worker '{}' does not exist", worker_id),
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
        let speedscore = match ctx.telemetry.latest_speedscore(worker_id.as_str()) {
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
    let workers = ctx.pool.all_workers().await;
    let mut entries = Vec::with_capacity(workers.len());
    let timeout = HealthConfig::default().check_timeout;

    for worker in workers {
        if refresh && let Some(capabilities) = probe_worker_capabilities(&worker, timeout).await {
            worker.set_capabilities(capabilities).await;
        }

        let (id, host, user) = {
            let config = worker.config.read().await;
            (
                config.id.to_string(),
                config.host.clone(),
                config.user.clone(),
            )
        };
        let capabilities = worker.capabilities().await;

        entries.push(WorkerCapabilitiesInfo {
            id,
            host,
            user,
            capabilities,
        });
    }

    ApiResponse::Ok(WorkerCapabilitiesResponse { workers: entries })
}

async fn handle_benchmark_trigger(
    ctx: &DaemonContext,
    worker_id: &WorkerId,
) -> ApiResponse<BenchmarkTriggerResponse> {
    if ctx.pool.get(worker_id).await.is_none() {
        return ApiResponse::Error(error_response(
            ErrorCode::ConfigInvalidWorker,
            format!("Worker '{}' does not exist", worker_id),
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

    // Retry loop to handle race conditions where slots are taken between selection and reservation
    let mut attempts = 0;
    const MAX_ATTEMPTS: u32 = 3;

    loop {
        attempts += 1;

        // Use the configured worker selector
        let result = ctx.worker_selector.select(&ctx.pool, &request).await;

        let Some(worker) = result.worker else {
            debug!("No worker selected: {}", result.reason);
            return Ok(SelectionResponse {
                worker: None,
                reason: result.reason,
                build_id: None,
            });
        };

        // Reserve the slots
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
            let build_id = if let Some(hook_pid) = request.hook_pid.filter(|pid| *pid > 0) {
                let command = request
                    .command
                    .clone()
                    .unwrap_or_else(|| "<unknown>".to_string());
                let state = ctx.history.start_active_build(
                    request.project.clone(),
                    id.as_str().to_string(),
                    command,
                    hook_pid,
                    request.estimated_cores,
                    rch_common::BuildLocation::Remote,
                );
                if !cfg!(test) {
                    metrics::inc_active_builds("remote");
                }
                Some(state.id)
            } else {
                None
            };

            let slots_available = worker.available_slots().await;
            let speed_score = worker.get_speed_score().await;

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
            // Give up after max attempts
            return Ok(SelectionResponse {
                worker: None,
                reason: SelectionReason::AllWorkersBusy,
                build_id: None,
            });
        }
        // Loop again - next selection will see reduced slot count
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
        );
        if let Some(ref rec) = record {
            if !cfg!(test) {
                metrics::dec_active_builds("remote");
                let outcome = if exit_code == 0 { "success" } else { "failure" };
                metrics::inc_build_total(outcome, "remote");
            }

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

/// Handle a worker drain request.
async fn handle_worker_drain(ctx: &DaemonContext, worker_id: &WorkerId) -> WorkerStateResponse {
    match ctx.pool.get(worker_id).await {
        Some(worker) => {
            let active_slots = worker.used_slots();
            worker.drain().await;
            WorkerStateResponse {
                status: "ok".to_string(),
                worker_id: worker_id.to_string(),
                action: "drain".to_string(),
                new_status: Some("draining".to_string()),
                reason: None,
                message: Some(format!(
                    "Worker is draining. {} slot(s) currently in use.",
                    active_slots
                )),
                active_slots: Some(active_slots),
            }
        }
        None => WorkerStateResponse {
            status: "error".to_string(),
            worker_id: worker_id.to_string(),
            action: "drain".to_string(),
            new_status: None,
            reason: None,
            message: Some(format!("Worker '{}' not found", worker_id)),
            active_slots: None,
        },
    }
}

/// Handle a worker enable request.
async fn handle_worker_enable(ctx: &DaemonContext, worker_id: &WorkerId) -> WorkerStateResponse {
    match ctx.pool.get(worker_id).await {
        Some(worker) => {
            let old_status = worker.status().await;
            worker.enable().await;
            WorkerStateResponse {
                status: "ok".to_string(),
                worker_id: worker_id.to_string(),
                action: "enable".to_string(),
                new_status: Some("healthy".to_string()),
                reason: None,
                message: Some(format!("Worker enabled (was {:?})", old_status)),
                active_slots: None,
            }
        }
        None => WorkerStateResponse {
            status: "error".to_string(),
            worker_id: worker_id.to_string(),
            action: "enable".to_string(),
            new_status: None,
            reason: None,
            message: Some(format!("Worker '{}' not found", worker_id)),
            active_slots: None,
        },
    }
}

/// Handle a worker disable request.
async fn handle_worker_disable(
    ctx: &DaemonContext,
    worker_id: &WorkerId,
    reason: Option<String>,
    drain_first: bool,
) -> WorkerStateResponse {
    match ctx.pool.get(worker_id).await {
        Some(worker) => {
            let active_slots = worker.used_slots();

            if drain_first && active_slots > 0 {
                // Start draining - will be fully disabled when slots reach 0
                worker.drain().await;
                WorkerStateResponse {
                    status: "ok".to_string(),
                    worker_id: worker_id.to_string(),
                    action: "disable".to_string(),
                    new_status: Some("draining".to_string()),
                    reason: reason.clone(),
                    message: Some(format!(
                        "Worker is draining before disable. {} slot(s) in use. Reason: {}",
                        active_slots,
                        reason.as_deref().unwrap_or("none provided")
                    )),
                    active_slots: Some(active_slots),
                }
            } else {
                // Disable immediately
                worker.disable(reason.clone()).await;
                WorkerStateResponse {
                    status: "ok".to_string(),
                    worker_id: worker_id.to_string(),
                    action: "disable".to_string(),
                    new_status: Some("disabled".to_string()),
                    reason: reason.clone(),
                    message: Some(format!(
                        "Worker disabled. Reason: {}",
                        reason.as_deref().unwrap_or("none provided")
                    )),
                    active_slots: Some(active_slots),
                }
            }
        }
        None => WorkerStateResponse {
            status: "error".to_string(),
            worker_id: worker_id.to_string(),
            action: "disable".to_string(),
            new_status: None,
            reason,
            message: Some(format!("Worker '{}' not found", worker_id)),
            active_slots: None,
        },
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
            speed_score: worker.get_speed_score().await,
            last_error: worker.last_error().await,
            consecutive_failures: circuit_stats.consecutive_failures(),
            recovery_in_secs,
            failure_history: circuit_stats.recent_results().to_vec(),
        });

        // Generate issues based on worker state
        if circuit_state == CircuitState::Open {
            issues.push(Issue {
                severity: "error".to_string(),
                summary: format!("Circuit open for worker '{}'", worker_id),
                remediation: Some(format!("rch workers probe {} --force", worker_id)),
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
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let start = now - uptime_secs;
        // Format as ISO 8601
        let dt = chrono::DateTime::from_timestamp(start as i64, 0).unwrap_or_else(chrono::Utc::now);
        dt.to_rfc3339()
    };

    // Get recent builds from history
    let recent_builds = ctx.history.recent(20);
    let stats = ctx.history.stats();
    let test_stats = ctx.telemetry.test_run_stats();

    // Collect active alerts from the alert manager
    let alerts = ctx.alert_manager.active_alerts();

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
            })
            .collect(),
        recent_builds,
        issues,
        alerts,
        stats,
        test_stats,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::BuildHistory;
    use crate::selection::WorkerSelector;
    use crate::self_test::{SelfTestHistory, SelfTestService};
    use crate::telemetry::TelemetryStore;
    use crate::workers::WorkerPool;
    use crate::{benchmark_queue::BenchmarkQueue, events::EventBus};
    use chrono::Duration as ChronoDuration;
    use rch_common::SelfTestConfig;
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
            events: EventBus::new(16),
            self_test,
            alert_manager,
            started_at: Instant::now(),
            socket_path: "/tmp/test.sock".to_string(),
            version: "0.1.0",
            pid: 1234,
        }
    }

    #[test]
    fn test_parse_request_basic() {
        let req = parse_request("GET /select-worker?project=myproject&cores=4").unwrap();
        let ApiRequest::SelectWorker(req) = req else {
            panic!("expected select-worker request");
        };
        assert_eq!(req.project, "myproject");
        assert_eq!(req.estimated_cores, 4);
    }

    #[test]
    fn test_parse_request_project_only() {
        let req = parse_request("GET /select-worker?project=test").unwrap();
        let ApiRequest::SelectWorker(req) = req else {
            panic!("expected select-worker request");
        };
        assert_eq!(req.project, "test");
        assert_eq!(req.estimated_cores, 1); // Default
    }

    #[test]
    fn test_parse_request_with_spaces() {
        let req = parse_request("GET /select-worker?project=my%20project&cores=2").unwrap();
        let ApiRequest::SelectWorker(req) = req else {
            panic!("expected select-worker request");
        };
        assert_eq!(req.project, "my project");
        assert_eq!(req.estimated_cores, 2);
    }

    #[test]
    fn test_parse_request_with_priority_hint() {
        let req = parse_request("GET /select-worker?project=test&cores=2&priority=high").unwrap();
        let ApiRequest::SelectWorker(req) = req else {
            panic!("expected select-worker request");
        };
        assert_eq!(req.command_priority, rch_common::CommandPriority::High);
    }

    #[test]
    fn test_parse_request_invalid_priority_defaults_to_normal() {
        let req = parse_request("GET /select-worker?project=test&cores=2&priority=urgent").unwrap();
        let ApiRequest::SelectWorker(req) = req else {
            panic!("expected select-worker request");
        };
        assert_eq!(req.command_priority, rch_common::CommandPriority::Normal);
    }

    #[test]
    fn test_parse_request_status() {
        let req = parse_request("GET /status").unwrap();
        assert!(matches!(req, ApiRequest::Status), "expected status request");
    }

    #[test]
    fn test_parse_request_test_run() {
        let req = parse_request("POST /test-run").unwrap();
        assert!(
            matches!(req, ApiRequest::TestRun),
            "expected test run request"
        );
    }

    #[test]
    fn test_parse_request_speedscore() {
        let req = parse_request("GET /speedscore/css").unwrap();
        match req {
            ApiRequest::SpeedScore { worker_id } => {
                assert_eq!(worker_id.as_str(), "css");
            }
            _ => panic!( "expected speedscore request"),
        }
    }

    #[test]
    fn test_parse_request_speedscore_history() {
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
            _ => panic!( "expected speedscore history request"),
        }
    }

    #[test]
    fn test_parse_request_speedscores() {
        let req = parse_request("GET /speedscores").unwrap();
        assert!(
            matches!(req, ApiRequest::SpeedScores),
            "expected speedscores request"
        );
    }

    #[test]
    fn test_parse_request_workers_capabilities() {
        let req = parse_request("GET /workers/capabilities").unwrap();
        match req {
            ApiRequest::WorkersCapabilities { refresh } => {
                assert!(!refresh);
            }
            _ => panic!( "expected workers capabilities request"),
        }

        let req = parse_request("GET /workers/capabilities?refresh=true").unwrap();
        match req {
            ApiRequest::WorkersCapabilities { refresh } => {
                assert!(refresh);
            }
            _ => panic!( "expected workers capabilities request"),
        }
    }

    #[test]
    fn test_parse_request_benchmark_trigger() {
        let req = parse_request("POST /benchmark/trigger/css").unwrap();
        match req {
            ApiRequest::BenchmarkTrigger { worker_id } => {
                assert_eq!(worker_id.as_str(), "css");
            }
            _ => panic!( "expected benchmark trigger request"),
        }
    }

    #[test]
    fn test_parse_request_events() {
        let req = parse_request("GET /events").unwrap();
        assert!(matches!(req, ApiRequest::Events), "expected events request");
    }

    #[test]
    fn test_parse_request_reload() {
        let req = parse_request("POST /reload").unwrap();
        assert!(matches!(req, ApiRequest::Reload), "expected reload request");
    }

    #[test]
    fn test_parse_request_reload_get_fails() {
        // GET method should not work for reload
        let result = parse_request("GET /reload");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_request_telemetry_poll() {
        let req = parse_request("POST /telemetry/poll?worker=css").unwrap();
        match req {
            ApiRequest::TelemetryPoll { worker_id } => {
                assert_eq!(worker_id.as_str(), "css");
            }
            _ => panic!( "expected telemetry poll request"),
        }
    }

    #[test]
    fn test_parse_request_self_test_status() {
        let req = parse_request("GET /self-test/status").unwrap();
        assert!(
            matches!(req, ApiRequest::SelfTestStatus),
            "expected self-test status request"
        );
    }

    #[test]
    fn test_parse_request_self_test_history() {
        let req = parse_request("GET /self-test/history?limit=5").unwrap();
        match req {
            ApiRequest::SelfTestHistory { limit } => assert_eq!(limit, 5),
            _ => panic!( "expected self-test history request"),
        }
    }

    #[test]
    fn test_parse_request_self_test_run() {
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
        // Create a toolchain JSON and URL encode it
        let toolchain_json = r###"{"channel":"nightly","date":"2024-01-01","full_version":"rustc 1.76.0-nightly"}"###;
        let encoded = urlencoding_encode(toolchain_json);
        let query = format!(
            "GET /select-worker?project=test&cores=4&toolchain={}",
            encoded
        );

        let req = parse_request(&query).unwrap();
        let ApiRequest::SelectWorker(req) = req else {
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
        let query = "GET /select-worker?project=test&runtime=bun";
        let req = parse_request(query).unwrap();
        let ApiRequest::SelectWorker(req) = req else {
            panic!("expected select-worker request");
        };
        assert_eq!(req.required_runtime, RequiredRuntime::Bun);

        let query = "GET /select-worker?project=test&runtime=rust";
        let req = parse_request(query).unwrap();
        let ApiRequest::SelectWorker(req) = req else {
            panic!("expected select-worker request");
        };
        assert_eq!(req.required_runtime, RequiredRuntime::Rust);

        // Invalid runtime should default to None
        let query = "GET /select-worker?project=test&runtime=invalid";
        let req = parse_request(query).unwrap();
        let ApiRequest::SelectWorker(req) = req else {
            panic!("expected select-worker request");
        };
        assert_eq!(req.required_runtime, RequiredRuntime::None);
    }

    #[test]
    fn test_parse_request_missing_project() {
        let result = parse_request("GET /select-worker?cores=4");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_request_invalid_method() {
        let result = parse_request("PUT /select-worker?project=test");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_request_unknown_endpoint() {
        let result = parse_request("GET /unknown?project=test");
        assert!(result.is_err());
    }

    #[test]
    fn test_urlencoding_decode_basic() {
        assert_eq!(urlencoding_decode("hello%20world"), "hello world");
        assert_eq!(urlencoding_decode("path%2Fto%2Ffile"), "path/to/file");
        assert_eq!(urlencoding_decode("foo%3Abar"), "foo:bar");
    }

    #[test]
    fn test_urlencoding_decode_special_chars() {
        assert_eq!(urlencoding_decode("a%26b%3Dc"), "a&b=c");
        assert_eq!(urlencoding_decode("100%25"), "100%");
        assert_eq!(urlencoding_decode("hello%2Bworld"), "hello+world");
    }

    #[test]
    fn test_urlencoding_decode_plus_as_space() {
        assert_eq!(urlencoding_decode("hello+world"), "hello world");
    }

    #[test]
    fn test_urlencoding_decode_no_encoding() {
        assert_eq!(urlencoding_decode("simple"), "simple");
        assert_eq!(
            urlencoding_decode("with-dash_underscore"),
            "with-dash_underscore"
        );
    }

    #[test]
    fn test_urlencoding_decode_invalid() {
        // Invalid hex should be preserved
        assert_eq!(urlencoding_decode("foo%GGbar"), "foo%GGbar");
        // Incomplete sequence at end
        assert_eq!(urlencoding_decode("foo%"), "foo%");
    }

    #[test]
    fn test_urlencoding_decode_utf8() {
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

        let response = handle_select_worker(&ctx, request).await.unwrap();
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

        let response = handle_select_worker(&ctx, request).await.unwrap();
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

        let response = handle_select_worker(&ctx, request).await.unwrap();
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

        let response = handle_select_worker(&ctx, request).await.unwrap();
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

        let response = handle_select_worker(&ctx, request).await.unwrap();
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

        let response = handle_select_worker(&ctx, request).await.unwrap();
        let worker = response.worker.unwrap();
        assert_eq!(worker.id.as_str(), "worker2");
    }

    // =========================================================================
    // Reload API tests
    // =========================================================================

    #[test]
    fn test_parse_request_reload_requires_post() {
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
}
