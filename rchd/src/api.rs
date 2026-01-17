//! Unix socket API for hook-daemon communication.
//!
//! Implements a simple HTTP-like protocol over Unix socket:
//! - Request: `GET /select-worker?project=X&cores=N\n`
//! - Response: JSON `SelectionResponse` or error

use crate::DaemonContext;
use crate::metrics;
use crate::metrics::budget::{self, BudgetStatusResponse};
use crate::selection::{SelectionWeights, select_worker_with_config};
use crate::workers::WorkerPool;
use anyhow::{Result, anyhow};
use rch_common::{
    BuildRecord, BuildStats, CircuitBreakerConfig, CircuitState, ReleaseRequest, RequiredRuntime,
    SelectedWorker, SelectionReason, SelectionRequest, SelectionResponse, WorkerStatus,
};
use serde::Serialize;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tracing::{debug, warn};

/// Parsed API request variants.
#[derive(Debug)]
enum ApiRequest {
    SelectWorker(SelectionRequest),
    ReleaseWorker(ReleaseRequest),
    Status,
    Metrics,
    Health,
    Ready,
    Budget,
    Shutdown,
}

// ============================================================================
// Status Response Types (per bead remote_compilation_helper-3sy)
// ============================================================================

/// Full status response for GET /status.
#[derive(Debug, Serialize)]
pub struct StatusResponse {
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
    /// Aggregate statistics.
    pub stats: BuildStats,
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
            let response = handle_select_worker(&ctx.pool, request).await?;
            (serde_json::to_string(&response)?, "application/json")
        }
        Ok(ApiRequest::ReleaseWorker(request)) => {
            metrics::inc_requests("release-worker");
            handle_release_worker(&ctx.pool, request).await?;
            ("{}".to_string(), "application/json")
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
        Ok(ApiRequest::Shutdown) => {
            metrics::inc_requests("shutdown");
            let _ = shutdown_tx.send(()).await;
            (
                "{\"status\":\"shutting_down\"}".to_string(),
                "application/json",
            )
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

    if path == "/shutdown" && method == "POST" {
        return Ok(ApiRequest::Shutdown);
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

    if path.starts_with("/release-worker") {
        if method != "POST" {
            return Err(anyhow!("Only POST method supported for release"));
        }

        let query = path.strip_prefix("/release-worker").unwrap_or("");
        let query = query.strip_prefix('?').unwrap_or("");

        let mut worker_id = None;
        let mut slots = None;

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
                _ => {} // Ignore unknown parameters
            }
        }

        let worker_id = worker_id.ok_or_else(|| anyhow!("Missing 'worker' parameter"))?;
        let slots = slots.unwrap_or(0);

        return Ok(ApiRequest::ReleaseWorker(ReleaseRequest {
            worker_id: rch_common::WorkerId::new(worker_id),
            slots,
        }));
    }

    if !path.starts_with("/select-worker") {
        return Err(anyhow!("Unknown endpoint: {}", path));
    }

    // Parse query parameters for select-worker
    let query = path.strip_prefix("/select-worker").unwrap_or("");
    let query = query.strip_prefix('?').unwrap_or("");

    let mut project = None;
    let mut cores = None;
    let mut toolchain = None;
    let mut required_runtime = RequiredRuntime::default();
    let mut classification_duration_us = None;

    for param in query.split('&') {
        if param.is_empty() {
            continue;
        }
        let mut kv = param.splitn(2, '=');
        let key = kv.next().unwrap_or("");
        let value = kv.next().unwrap_or("");

        match key {
            "project" => project = Some(urlencoding_decode(value)),
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
            "classification_us" => {
                // Classification latency from hook (for AGENTS.md compliance tracking)
                classification_duration_us = value.parse().ok();
            }
            _ => {} // Ignore unknown parameters
        }
    }

    let project = project.ok_or_else(|| anyhow!("Missing 'project' parameter"))?;
    let estimated_cores = cores.unwrap_or(1);

    Ok(ApiRequest::SelectWorker(SelectionRequest {
        project,
        estimated_cores,
        preferred_workers: vec![],
        toolchain,
        required_runtime,
        classification_duration_us,
    }))
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
            if hex.len() == 2 {
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    bytes.push(byte);
                    continue;
                }
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

/// Handle a select-worker request.
async fn handle_select_worker(
    pool: &WorkerPool,
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
        });
    }

    let weights = SelectionWeights::default();
    let circuit_config = CircuitBreakerConfig::default();
    let result = select_worker_with_config(pool, &request, &weights, &circuit_config).await;

    let Some(worker) = result.worker else {
        debug!("No worker selected: {}", result.reason);
        return Ok(SelectionResponse {
            worker: None,
            reason: result.reason,
        });
    };

    // Reserve the slots
    if !worker.reserve_slots(request.estimated_cores) {
        warn!(
            "Failed to reserve {} slots on {} (race condition)",
            request.estimated_cores, worker.config.id
        );
        // This can happen if another request reserved the slots between
        // selection and reservation. Treat as all workers busy.
        return Ok(SelectionResponse {
            worker: None,
            reason: SelectionReason::AllWorkersBusy,
        });
    }

    Ok(SelectionResponse {
        worker: Some(SelectedWorker {
            id: worker.config.id.clone(),
            host: worker.config.host.clone(),
            user: worker.config.user.clone(),
            identity_file: worker.config.identity_file.clone(),
            slots_available: worker.available_slots(),
            speed_score: worker.speed_score,
        }),
        reason: SelectionReason::Success,
    })
}

/// Handle a release-worker request.
async fn handle_release_worker(pool: &WorkerPool, request: ReleaseRequest) -> Result<()> {
    debug!(
        "Releasing {} slots on worker {}",
        request.slots, request.worker_id
    );
    pool.release_slots(&request.worker_id, request.slots).await;
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
    let workers_available = workers.iter().any(|w| {
        // A worker is available if it's healthy and has slots
        w.available_slots() > 0
    });

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

/// Handle a status request.
async fn handle_status(ctx: &DaemonContext) -> Result<StatusResponse> {
    let workers = ctx.pool.all_workers().await;

    let mut workers_healthy = 0;
    let mut slots_total = 0u32;
    let mut slots_available = 0u32;

    let mut worker_infos = Vec::with_capacity(workers.len());
    let mut issues = Vec::new();

    for worker in &workers {
        let status = worker.status().await;
        let used_slots = worker.config.total_slots - worker.available_slots();

        // Count healthy workers
        if status == WorkerStatus::Healthy {
            workers_healthy += 1;
        }

        slots_total = slots_total.saturating_add(worker.config.total_slots);
        slots_available = slots_available.saturating_add(worker.available_slots());

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
            id: worker.config.id.to_string(),
            host: worker.config.host.clone(),
            user: worker.config.user.clone(),
            status: status_str.to_string(),
            circuit_state: circuit_str.to_string(),
            used_slots,
            total_slots: worker.config.total_slots,
            speed_score: worker.speed_score,
            last_error: worker.last_error().await,
            consecutive_failures: circuit_stats.consecutive_failures(),
            recovery_in_secs,
            failure_history: circuit_stats.recent_results().to_vec(),
        });

        // Generate issues based on worker state
        if circuit_state == CircuitState::Open {
            issues.push(Issue {
                severity: "error".to_string(),
                summary: format!("Circuit open for worker '{}'", worker.config.id),
                remediation: Some(format!("rch workers probe {} --force", worker.config.id)),
            });
        } else if status == WorkerStatus::Unreachable {
            issues.push(Issue {
                severity: "error".to_string(),
                summary: format!("Worker '{}' is unreachable", worker.config.id),
                remediation: Some(format!("rch workers probe {}", worker.config.id)),
            });
        } else if status == WorkerStatus::Degraded {
            issues.push(Issue {
                severity: "warning".to_string(),
                summary: format!("Worker '{}' is degraded (slow response)", worker.config.id),
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

    Ok(StatusResponse {
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
        active_builds: vec![], // TODO: Implement active build tracking
        recent_builds,
        issues,
        stats,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::BuildHistory;
    use std::sync::Arc;
    use std::time::Instant;

    fn make_test_context(pool: WorkerPool) -> DaemonContext {
        DaemonContext {
            pool,
            history: Arc::new(BuildHistory::new(100)),
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
    fn test_parse_request_status() {
        let req = parse_request("GET /status").unwrap();
        match req {
            ApiRequest::Status => {} // Correct
            _ => panic!("expected status request"),
        }
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
        assert_eq!(urlencoding_decode("foo%2"), "foo%2");
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

    use rch_common::{RequiredRuntime, WorkerConfig, WorkerId, WorkerStatus};

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
        let request = SelectionRequest {
            project: "test".to_string(),
            estimated_cores: 4,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
        };

        let response = handle_select_worker(&pool, request).await.unwrap();
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

        let request = SelectionRequest {
            project: "test".to_string(),
            estimated_cores: 2,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
        };

        let response = handle_select_worker(&pool, request).await.unwrap();
        assert!(response.worker.is_none());
        assert_eq!(response.reason, SelectionReason::AllWorkersUnreachable);
    }

    #[tokio::test]
    async fn test_handle_select_worker_all_busy() {
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("worker1", 4)).await;

        // Reserve all slots
        let worker = pool.get(&WorkerId::new("worker1")).await.unwrap();
        worker.reserve_slots(4);

        let request = SelectionRequest {
            project: "test".to_string(),
            estimated_cores: 2, // Request more than available
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
        };

        let response = handle_select_worker(&pool, request).await.unwrap();
        assert!(response.worker.is_none());
        assert_eq!(response.reason, SelectionReason::AllWorkersBusy);
    }

    #[tokio::test]
    async fn test_handle_select_worker_success() {
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("worker1", 16)).await;

        let request = SelectionRequest {
            project: "test".to_string(),
            estimated_cores: 4,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
        };

        let response = handle_select_worker(&pool, request).await.unwrap();
        assert!(response.worker.is_some());
        assert_eq!(response.reason, SelectionReason::Success);

        let worker = response.worker.unwrap();
        assert_eq!(worker.id.as_str(), "worker1");
        // 16 total - 4 reserved = 12 available after reservation
        assert_eq!(worker.slots_available, 12);
    }

    #[tokio::test]
    async fn test_handle_select_worker_not_enough_slots() {
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("worker1", 4)).await;

        let request = SelectionRequest {
            project: "test".to_string(),
            estimated_cores: 8, // Request more than total slots
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
        };

        let response = handle_select_worker(&pool, request).await.unwrap();
        assert!(response.worker.is_none());
        assert_eq!(response.reason, SelectionReason::AllWorkersBusy);
    }

    #[tokio::test]
    async fn test_handle_status_summary() {
        let pool = WorkerPool::new();
        pool.add_worker(make_test_worker("worker1", 4)).await;
        pool.add_worker(make_test_worker("worker2", 8)).await;

        // Set worker2 to degraded to verify status counts
        pool.set_status(&WorkerId::new("worker2"), WorkerStatus::Degraded)
            .await;

        // Reserve some slots
        let worker1 = pool.get(&WorkerId::new("worker1")).await.unwrap();
        let worker2 = pool.get(&WorkerId::new("worker2")).await.unwrap();
        assert!(worker1.reserve_slots(2));
        assert!(worker2.reserve_slots(3));

        let ctx = make_test_context(pool);
        let status = handle_status(&ctx).await.unwrap();

        assert_eq!(status.daemon.workers_total, 2);
        assert_eq!(status.daemon.workers_healthy, 1);
        assert_eq!(status.daemon.slots_total, 12);
        assert_eq!(status.daemon.slots_available, 7);
        assert_eq!(status.workers.len(), 2);
    }
}
