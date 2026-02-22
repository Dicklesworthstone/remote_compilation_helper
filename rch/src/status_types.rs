//! Types for the enhanced status command.
//!
//! These types mirror the response structures from rchd's /status API endpoint.

use rch_common::{
    BuildCancellationMetadata, CommandTimingBreakdown, SavedTimeStats, WorkerCapabilities,
};
use serde::{Deserialize, Serialize};

/// Full status response from daemon's GET /status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonFullStatusResponse {
    pub daemon: DaemonInfoFromApi,
    pub workers: Vec<WorkerStatusFromApi>,
    pub active_builds: Vec<ActiveBuildFromApi>,
    #[serde(default)]
    pub queued_builds: Vec<QueuedBuildFromApi>,
    pub recent_builds: Vec<BuildRecordFromApi>,
    pub issues: Vec<IssueFromApi>,
    /// Active alerts from the daemon (worker health, circuits, etc.).
    #[serde(default)]
    pub alerts: Vec<AlertInfoFromApi>,
    pub stats: BuildStatsFromApi,
    #[serde(default)]
    pub test_stats: Option<TestRunStatsFromApi>,
    /// Saved time statistics from remote builds.
    #[serde(default)]
    pub saved_time: Option<SavedTimeStats>,
}

/// Daemon metadata from API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonInfoFromApi {
    pub pid: u32,
    pub uptime_secs: u64,
    pub version: String,
    pub socket_path: String,
    pub started_at: String,
    pub workers_total: usize,
    pub workers_healthy: usize,
    pub slots_total: u32,
    pub slots_available: u32,
}

/// Worker status information from API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerStatusFromApi {
    pub id: String,
    pub host: String,
    pub user: String,
    pub status: String,
    pub circuit_state: String,
    pub used_slots: u32,
    pub total_slots: u32,
    pub speed_score: f64,
    pub last_error: Option<String>,
    /// Consecutive failure count.
    #[serde(default)]
    pub consecutive_failures: u32,
    /// Seconds until circuit auto-recovers (None if not open or cooldown elapsed).
    #[serde(default)]
    pub recovery_in_secs: Option<u64>,
    /// Recent health check results (true=success, false=failure).
    #[serde(default)]
    pub failure_history: Vec<bool>,
    /// Normalized storage pressure state (healthy, warning, critical, telemetry_gap).
    #[serde(default)]
    pub pressure_state: Option<String>,
    /// Confidence level for the pressure decision (high, medium, low).
    #[serde(default)]
    pub pressure_confidence: Option<String>,
    /// Stable pressure reason code for diagnostics.
    #[serde(default)]
    pub pressure_reason_code: Option<String>,
    /// Policy rule provenance for pressure classification.
    #[serde(default)]
    pub pressure_policy_rule: Option<String>,
    /// Measured free disk (GB), if available.
    #[serde(default)]
    pub pressure_disk_free_gb: Option<f64>,
    /// Measured total disk (GB), if available.
    #[serde(default)]
    pub pressure_disk_total_gb: Option<f64>,
    /// Measured free-disk ratio, if available.
    #[serde(default)]
    pub pressure_disk_free_ratio: Option<f64>,
    /// Last disk I/O utilization sample, if available.
    #[serde(default)]
    pub pressure_disk_io_util_pct: Option<f64>,
    /// Last memory pressure sample, if available.
    #[serde(default)]
    pub pressure_memory_pressure: Option<f64>,
    /// Age of latest telemetry sample in seconds, if available.
    #[serde(default)]
    pub pressure_telemetry_age_secs: Option<u64>,
    /// Whether the latest telemetry sample is fresh enough for high-confidence decisions.
    #[serde(default)]
    pub pressure_telemetry_fresh: Option<bool>,
}

/// Worker capabilities information from API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerCapabilitiesFromApi {
    pub id: String,
    pub host: String,
    pub user: String,
    pub capabilities: WorkerCapabilities,
}

/// Worker capabilities response from API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerCapabilitiesResponseFromApi {
    pub workers: Vec<WorkerCapabilitiesFromApi>,
}

/// Active build information from API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveBuildFromApi {
    pub id: u64,
    pub project_id: String,
    pub worker_id: String,
    pub command: String,
    pub started_at: String,
    #[serde(default)]
    pub last_heartbeat_at: Option<String>,
    #[serde(default)]
    pub heartbeat_age_secs: Option<u64>,
    #[serde(default)]
    pub last_progress_at: Option<String>,
    #[serde(default)]
    pub progress_age_secs: Option<u64>,
    #[serde(default)]
    pub heartbeat_phase: Option<String>,
    #[serde(default)]
    pub heartbeat_detail: Option<String>,
    #[serde(default)]
    pub heartbeat_counter: Option<u64>,
    #[serde(default)]
    pub heartbeat_percent: Option<f64>,
    #[serde(default)]
    pub slots: Option<u32>,
    #[serde(default)]
    pub detector_hook_alive: Option<bool>,
    #[serde(default)]
    pub detector_heartbeat_stale: Option<bool>,
    #[serde(default)]
    pub detector_progress_stale: Option<bool>,
    #[serde(default)]
    pub detector_confidence: Option<f64>,
    #[serde(default)]
    pub detector_build_age_secs: Option<u64>,
    #[serde(default)]
    pub detector_slots_owned: Option<u32>,
    #[serde(default)]
    pub detector_last_evaluated_at: Option<String>,
}

/// Queued build information from API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueuedBuildFromApi {
    pub id: u64,
    pub project_id: String,
    pub command: String,
    pub queued_at: String,
    pub position: usize,
    pub slots_needed: u32,
    pub estimated_start: Option<String>,
    pub wait_time: String,
}

/// Build record from API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildRecordFromApi {
    pub id: u64,
    pub started_at: String,
    pub completed_at: String,
    pub project_id: String,
    pub worker_id: Option<String>,
    pub command: String,
    pub exit_code: i32,
    pub duration_ms: u64,
    pub location: String,
    pub bytes_transferred: Option<u64>,
    #[serde(default)]
    pub timing: Option<CommandTimingBreakdown>,
    #[serde(default)]
    pub cancellation: Option<BuildCancellationMetadata>,
}

/// Issue from API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueFromApi {
    pub severity: String,
    pub summary: String,
    pub remediation: Option<String>,
}

/// Alert information from API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertInfoFromApi {
    pub id: String,
    pub kind: String,
    pub severity: String,
    pub message: String,
    #[serde(default)]
    pub worker_id: Option<String>,
    pub created_at: String,
}

/// Build statistics from API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildStatsFromApi {
    pub total_builds: usize,
    pub success_count: usize,
    pub failure_count: usize,
    pub remote_count: usize,
    pub local_count: usize,
    pub avg_duration_ms: u64,
}

/// Test execution statistics from API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestRunStatsFromApi {
    pub total_runs: u64,
    pub passed_runs: u64,
    pub failed_runs: u64,
    pub build_error_runs: u64,
    pub avg_duration_ms: u64,
    #[serde(default)]
    pub runs_by_kind: std::collections::HashMap<String, u64>,
}

// ============================================================================
// Convergence API Types
// ============================================================================

/// Worker convergence view from the /repo-convergence/status endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConvergenceWorkerViewFromApi {
    pub worker_id: String,
    pub drift_state: String,
    #[serde(default)]
    pub drift_confidence: f64,
    #[serde(default)]
    pub required_repos: Vec<String>,
    #[serde(default)]
    pub synced_repos: Vec<String>,
    #[serde(default)]
    pub missing_repos: Vec<String>,
    #[serde(default)]
    pub attempt_budget_remaining: u32,
    #[serde(default)]
    pub time_budget_remaining_ms: u64,
    #[serde(default)]
    pub last_status_check_unix_ms: i64,
    #[serde(default)]
    pub remediation: Vec<String>,
}

/// Summary statistics for convergence status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConvergenceSummaryFromApi {
    pub total_workers: usize,
    pub ready: usize,
    pub drifting: usize,
    pub converging: usize,
    pub failed: usize,
    pub stale: usize,
}

/// Full convergence status response from /repo-convergence/status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoConvergenceStatusFromApi {
    pub status: String,
    pub workers: Vec<ConvergenceWorkerViewFromApi>,
    pub summary: ConvergenceSummaryFromApi,
}

// ============================================================================
// Unified Status Surface Types (bd-vvmd.6.3)
// ============================================================================

/// Schema version for the unified status JSON envelope.
pub const STATUS_SCHEMA_VERSION: &str = "1.0.0";

/// System-level posture summarizing whether builds go remote or fall back local.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SystemPosture {
    /// All workers healthy, remote compilation fully available.
    RemoteReady,
    /// Some workers degraded; partial remote capability.
    Degraded,
    /// No workers available; all builds run locally (fail-open).
    LocalOnly,
}

impl SystemPosture {
    /// Compute posture from daemon status response.
    pub fn from_status(status: &DaemonFullStatusResponse) -> Self {
        if status.daemon.workers_total == 0 || status.daemon.workers_healthy == 0 {
            Self::LocalOnly
        } else if status.daemon.workers_healthy < status.daemon.workers_total {
            Self::Degraded
        } else {
            Self::RemoteReady
        }
    }

    #[allow(dead_code)]
    pub fn label(&self) -> &'static str {
        match self {
            Self::RemoteReady => "remote-ready",
            Self::Degraded => "degraded",
            Self::LocalOnly => "local-only",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::RemoteReady => "All workers healthy, remote compilation available",
            Self::Degraded => "Some workers unhealthy, partial remote capability",
            Self::LocalOnly => "No workers available, builds run locally (fail-open)",
        }
    }
}

/// Structured remediation hint with reason code and actionable guidance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationHint {
    /// Stable reason code for programmatic matching (e.g., "circuit_open", "pressure_critical").
    pub reason_code: String,
    /// Severity: "critical", "warning", "info".
    pub severity: String,
    /// Human-readable explanation of the issue.
    pub message: String,
    /// Actionable command or step to resolve the issue.
    pub suggested_action: String,
    /// Optional worker ID this hint applies to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub worker_id: Option<String>,
}

/// Generate remediation hints for workers with non-healthy states.
pub fn generate_worker_remediations(workers: &[WorkerStatusFromApi]) -> Vec<RemediationHint> {
    let mut hints = Vec::new();

    for w in workers {
        // Circuit breaker issues
        match w.circuit_state.as_str() {
            "open" => {
                let msg = if w.consecutive_failures > 0 {
                    format!(
                        "Worker {} circuit open after {} consecutive failures",
                        w.id, w.consecutive_failures
                    )
                } else {
                    format!("Worker {} circuit open due to repeated failures", w.id)
                };
                hints.push(RemediationHint {
                    reason_code: "circuit_open".into(),
                    severity: "critical".into(),
                    message: msg,
                    suggested_action: format!("rch workers probe {} --force", w.id),
                    worker_id: Some(w.id.clone()),
                });
            }
            "half_open" => {
                hints.push(RemediationHint {
                    reason_code: "circuit_half_open".into(),
                    severity: "warning".into(),
                    message: format!("Worker {} circuit is testing recovery", w.id),
                    suggested_action: format!("rch workers probe {}", w.id),
                    worker_id: Some(w.id.clone()),
                });
            }
            _ => {}
        }

        // Pressure issues
        if let Some(ref pressure) = w.pressure_state {
            match pressure.as_str() {
                "critical" => {
                    let disk_info = w
                        .pressure_disk_free_gb
                        .map(|gb| format!(" ({:.1} GB free)", gb))
                        .unwrap_or_default();
                    hints.push(RemediationHint {
                        reason_code: "pressure_critical".into(),
                        severity: "critical".into(),
                        message: format!(
                            "Worker {} under critical storage pressure{}",
                            w.id, disk_info
                        ),
                        suggested_action: format!(
                            "ssh {}@{} 'cargo clean' or free disk space",
                            w.user, w.host
                        ),
                        worker_id: Some(w.id.clone()),
                    });
                }
                "warning" => {
                    let disk_info = w
                        .pressure_disk_free_gb
                        .map(|gb| format!(" ({:.1} GB free)", gb))
                        .unwrap_or_default();
                    hints.push(RemediationHint {
                        reason_code: "pressure_warning".into(),
                        severity: "warning".into(),
                        message: format!("Worker {} storage pressure elevated{}", w.id, disk_info),
                        suggested_action: format!(
                            "ssh {}@{} 'du -sh /tmp/rch-*' to check cache sizes",
                            w.user, w.host
                        ),
                        worker_id: Some(w.id.clone()),
                    });
                }
                "telemetry_gap" => {
                    hints.push(RemediationHint {
                        reason_code: "pressure_telemetry_gap".into(),
                        severity: "warning".into(),
                        message: format!("Worker {} storage telemetry stale or missing", w.id),
                        suggested_action: format!("rch workers probe {}", w.id),
                        worker_id: Some(w.id.clone()),
                    });
                }
                _ => {}
            }
        }

        // Unreachable workers
        if (w.status == "unreachable" || w.status == "unhealthy") && w.circuit_state != "open" {
            // Only add if not already covered by circuit_open hint
            hints.push(RemediationHint {
                reason_code: "worker_unreachable".into(),
                severity: "critical".into(),
                message: format!(
                    "Worker {} is unreachable{}",
                    w.id,
                    w.last_error
                        .as_ref()
                        .map(|e| format!(": {}", e))
                        .unwrap_or_default()
                ),
                suggested_action: format!(
                    "ssh {}@{} 'echo ok' to verify connectivity",
                    w.user, w.host
                ),
                worker_id: Some(w.id.clone()),
            });
        }
    }

    hints
}

/// Generate convergence remediation hints.
pub fn generate_convergence_remediations(
    convergence: &RepoConvergenceStatusFromApi,
) -> Vec<RemediationHint> {
    let mut hints = Vec::new();

    for w in &convergence.workers {
        match w.drift_state.as_str() {
            "drifting" => {
                let missing = if w.missing_repos.is_empty() {
                    String::new()
                } else {
                    format!(" (missing: {})", w.missing_repos.join(", "))
                };
                hints.push(RemediationHint {
                    reason_code: "convergence_drifting".into(),
                    severity: "warning".into(),
                    message: format!("Worker {} repos drifting{}", w.worker_id, missing),
                    suggested_action: format!(
                        "rch repo-convergence repair --worker {}",
                        w.worker_id
                    ),
                    worker_id: Some(w.worker_id.clone()),
                });
            }
            "failed" => {
                hints.push(RemediationHint {
                    reason_code: "convergence_failed".into(),
                    severity: "critical".into(),
                    message: format!(
                        "Worker {} convergence failed (budget: {} attempts, {}ms remaining)",
                        w.worker_id, w.attempt_budget_remaining, w.time_budget_remaining_ms
                    ),
                    suggested_action: format!(
                        "rch repo-convergence repair --worker {} --force",
                        w.worker_id
                    ),
                    worker_id: Some(w.worker_id.clone()),
                });
            }
            "stale" => {
                hints.push(RemediationHint {
                    reason_code: "convergence_stale".into(),
                    severity: "info".into(),
                    message: format!("Worker {} convergence data stale", w.worker_id),
                    suggested_action: format!(
                        "rch repo-convergence dry-run --worker {}",
                        w.worker_id
                    ),
                    worker_id: Some(w.worker_id.clone()),
                });
            }
            _ => {} // "ready" and "converging" are fine
        }

        // Include per-worker remediation from the convergence endpoint
        for rem in &w.remediation {
            if !rem.is_empty() {
                hints.push(RemediationHint {
                    reason_code: "convergence_hint".into(),
                    severity: "info".into(),
                    message: rem.clone(),
                    suggested_action: String::new(),
                    worker_id: Some(w.worker_id.clone()),
                });
            }
        }
    }

    hints
}

/// Unified status surface response for JSON output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedStatusResponse {
    /// Schema version for forward compatibility.
    pub schema_version: String,
    /// System-level posture.
    pub posture: SystemPosture,
    /// Posture description.
    pub posture_description: String,
    /// Core daemon and worker status.
    pub daemon: DaemonFullStatusResponse,
    /// Convergence status (None if endpoint unreachable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub convergence: Option<RepoConvergenceStatusFromApi>,
    /// Aggregated remediation hints across all signals.
    pub remediation_hints: Vec<RemediationHint>,
}

// ============================================================================
// Self-Test API Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfTestRunRecordFromApi {
    pub id: u64,
    pub run_type: String,
    pub started_at: String,
    pub completed_at: String,
    pub workers_tested: usize,
    pub workers_passed: usize,
    pub workers_failed: usize,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfTestResultRecordFromApi {
    pub run_id: u64,
    pub worker_id: String,
    pub passed: bool,
    pub local_hash: Option<String>,
    pub remote_hash: Option<String>,
    pub local_time_ms: Option<u64>,
    pub remote_time_ms: Option<u64>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfTestStatusResponse {
    pub enabled: bool,
    pub schedule: Option<String>,
    pub interval: Option<String>,
    pub last_run: Option<SelfTestRunRecordFromApi>,
    pub next_run: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfTestHistoryResponse {
    pub runs: Vec<SelfTestRunRecordFromApi>,
    pub results: Vec<SelfTestResultRecordFromApi>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfTestRunResponse {
    pub run: SelfTestRunRecordFromApi,
    pub results: Vec<SelfTestResultRecordFromApi>,
}

// ============================================================================
// SpeedScore API Types
// ============================================================================

/// SpeedScore view from API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpeedScoreViewFromApi {
    pub total: f64,
    pub cpu_score: f64,
    pub memory_score: f64,
    pub disk_score: f64,
    pub network_score: f64,
    pub compilation_score: f64,
    pub measured_at: String,
    pub version: u32,
}

impl SpeedScoreViewFromApi {
    /// Get rating based on total score.
    pub fn rating(&self) -> &'static str {
        match self.total {
            x if x >= 90.0 => "Excellent",
            x if x >= 75.0 => "Very Good",
            x if x >= 60.0 => "Good",
            x if x >= 45.0 => "Average",
            x if x >= 30.0 => "Below Average",
            _ => "Poor",
        }
    }
}

/// SpeedScore response for single worker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpeedScoreResponseFromApi {
    pub worker_id: String,
    pub speedscore: Option<SpeedScoreViewFromApi>,
    pub message: Option<String>,
}

/// Pagination info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginationInfoFromApi {
    pub total: u64,
    pub offset: usize,
    pub limit: usize,
    pub has_more: bool,
}

/// SpeedScore history response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpeedScoreHistoryResponseFromApi {
    pub worker_id: String,
    pub history: Vec<SpeedScoreViewFromApi>,
    pub pagination: PaginationInfoFromApi,
}

/// Worker status for SpeedScore list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerStatusFromSpeedScoreApi {
    pub status: String,
    pub circuit_state: String,
}

/// SpeedScore list entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpeedScoreWorkerFromApi {
    pub worker_id: String,
    pub speedscore: Option<SpeedScoreViewFromApi>,
    pub status: WorkerStatusFromSpeedScoreApi,
}

/// SpeedScore list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpeedScoreListResponseFromApi {
    pub workers: Vec<SpeedScoreWorkerFromApi>,
}

/// Helper to format duration in human-readable form.
pub fn format_duration(secs: u64) -> String {
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        let hours = secs / 3600;
        let mins = (secs % 3600) / 60;
        format!("{}h {}m", hours, mins)
    }
}

/// Helper to format bytes in human-readable form.
#[allow(dead_code)]
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * 1024;
    const GB: u64 = 1024 * 1024 * 1024;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Extract JSON body from HTTP response.
pub fn extract_json_body(response: &str) -> Option<&str> {
    // Find the blank line that separates headers from body
    if let Some(pos) = response.find("\r\n\r\n") {
        Some(&response[pos + 4..])
    } else if let Some(pos) = response.find("\n\n") {
        Some(&response[pos + 2..])
    } else {
        // No headers, assume raw JSON
        Some(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rch_common::test_guard;

    #[test]
    fn test_format_duration() {
        let _guard = test_guard!();
        assert_eq!(format_duration(30), "30s");
        assert_eq!(format_duration(90), "1m 30s");
        assert_eq!(format_duration(3661), "1h 1m");
    }

    #[test]
    fn test_format_bytes() {
        let _guard = test_guard!();
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1500), "1.5 KB");
        assert_eq!(format_bytes(1_500_000), "1.4 MB");
        assert_eq!(format_bytes(1_500_000_000), "1.4 GB");
    }

    #[test]
    fn test_extract_json_body() {
        let _guard = test_guard!();
        let response = "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{\"test\": 1}";
        assert_eq!(extract_json_body(response), Some("{\"test\": 1}"));
    }

    #[test]
    fn test_deserialize_daemon_status() {
        let _guard = test_guard!();
        let socket_path = rch_common::default_socket_path();
        let json = serde_json::json!({
            "daemon": {
                "pid": 1234,
                "uptime_secs": 3600,
                "version": "0.1.0",
                "socket_path": socket_path,
                "started_at": "2026-01-16T12:00:00Z",
                "workers_total": 2,
                "workers_healthy": 2,
                "slots_total": 32,
                "slots_available": 28
            },
            "workers": [],
            "active_builds": [],
            "recent_builds": [],
            "issues": [],
            "stats": {
                "total_builds": 10,
                "success_count": 9,
                "failure_count": 1,
                "remote_count": 10,
                "local_count": 0,
                "avg_duration_ms": 45000
            }
        });

        let status: DaemonFullStatusResponse = serde_json::from_value(json).unwrap();
        assert_eq!(status.daemon.pid, 1234);
        assert_eq!(status.stats.total_builds, 10);
    }

    // ==================== Additional Coverage Tests ====================

    #[test]
    fn test_format_duration_zero() {
        let _guard = test_guard!();
        assert_eq!(format_duration(0), "0s");
    }

    #[test]
    fn test_format_duration_exactly_one_minute() {
        let _guard = test_guard!();
        assert_eq!(format_duration(60), "1m 0s");
    }

    #[test]
    fn test_format_duration_exactly_one_hour() {
        let _guard = test_guard!();
        assert_eq!(format_duration(3600), "1h 0m");
    }

    #[test]
    fn test_format_duration_multiple_hours() {
        let _guard = test_guard!();
        assert_eq!(format_duration(7200), "2h 0m");
        assert_eq!(format_duration(7320), "2h 2m"); // 2h 2m
        assert_eq!(format_duration(86400), "24h 0m"); // 24 hours
    }

    #[test]
    fn test_format_bytes_zero() {
        let _guard = test_guard!();
        assert_eq!(format_bytes(0), "0 B");
    }

    #[test]
    fn test_format_bytes_exact_boundaries() {
        let _guard = test_guard!();
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1024 * 1024), "1.0 MB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.0 GB");
    }

    #[test]
    fn test_format_bytes_just_under_kb() {
        let _guard = test_guard!();
        assert_eq!(format_bytes(1023), "1023 B");
    }

    #[test]
    fn test_extract_json_body_unix_newlines() {
        let _guard = test_guard!();
        let response = "HTTP/1.0 200 OK\nContent-Type: application/json\n\n{\"test\": 2}";
        assert_eq!(extract_json_body(response), Some("{\"test\": 2}"));
    }

    #[test]
    fn test_extract_json_body_no_headers() {
        let _guard = test_guard!();
        let response = "{\"direct\": \"json\"}";
        assert_eq!(extract_json_body(response), Some("{\"direct\": \"json\"}"));
    }

    #[test]
    fn test_extract_json_body_empty() {
        let _guard = test_guard!();
        assert_eq!(extract_json_body(""), Some(""));
    }

    #[test]
    fn test_speed_score_rating_excellent() {
        let _guard = test_guard!();
        let score = SpeedScoreViewFromApi {
            total: 95.0,
            cpu_score: 95.0,
            memory_score: 95.0,
            disk_score: 95.0,
            network_score: 95.0,
            compilation_score: 95.0,
            measured_at: "2026-01-16T12:00:00Z".to_string(),
            version: 1,
        };
        assert_eq!(score.rating(), "Excellent");
    }

    #[test]
    fn test_speed_score_rating_very_good() {
        let _guard = test_guard!();
        let score = SpeedScoreViewFromApi {
            total: 80.0,
            cpu_score: 80.0,
            memory_score: 80.0,
            disk_score: 80.0,
            network_score: 80.0,
            compilation_score: 80.0,
            measured_at: "2026-01-16T12:00:00Z".to_string(),
            version: 1,
        };
        assert_eq!(score.rating(), "Very Good");
    }

    #[test]
    fn test_speed_score_rating_good() {
        let _guard = test_guard!();
        let score = SpeedScoreViewFromApi {
            total: 65.0,
            cpu_score: 65.0,
            memory_score: 65.0,
            disk_score: 65.0,
            network_score: 65.0,
            compilation_score: 65.0,
            measured_at: "2026-01-16T12:00:00Z".to_string(),
            version: 1,
        };
        assert_eq!(score.rating(), "Good");
    }

    #[test]
    fn test_speed_score_rating_average() {
        let _guard = test_guard!();
        let score = SpeedScoreViewFromApi {
            total: 50.0,
            cpu_score: 50.0,
            memory_score: 50.0,
            disk_score: 50.0,
            network_score: 50.0,
            compilation_score: 50.0,
            measured_at: "2026-01-16T12:00:00Z".to_string(),
            version: 1,
        };
        assert_eq!(score.rating(), "Average");
    }

    #[test]
    fn test_speed_score_rating_below_average() {
        let _guard = test_guard!();
        let score = SpeedScoreViewFromApi {
            total: 35.0,
            cpu_score: 35.0,
            memory_score: 35.0,
            disk_score: 35.0,
            network_score: 35.0,
            compilation_score: 35.0,
            measured_at: "2026-01-16T12:00:00Z".to_string(),
            version: 1,
        };
        assert_eq!(score.rating(), "Below Average");
    }

    #[test]
    fn test_speed_score_rating_poor() {
        let _guard = test_guard!();
        let score = SpeedScoreViewFromApi {
            total: 20.0,
            cpu_score: 20.0,
            memory_score: 20.0,
            disk_score: 20.0,
            network_score: 20.0,
            compilation_score: 20.0,
            measured_at: "2026-01-16T12:00:00Z".to_string(),
            version: 1,
        };
        assert_eq!(score.rating(), "Poor");
    }

    #[test]
    fn test_speed_score_rating_boundaries() {
        let _guard = test_guard!();
        // Exactly at boundary values
        let mut score = SpeedScoreViewFromApi {
            total: 90.0,
            cpu_score: 90.0,
            memory_score: 90.0,
            disk_score: 90.0,
            network_score: 90.0,
            compilation_score: 90.0,
            measured_at: "2026-01-16T12:00:00Z".to_string(),
            version: 1,
        };
        assert_eq!(score.rating(), "Excellent");

        score.total = 89.99;
        assert_eq!(score.rating(), "Very Good");

        score.total = 75.0;
        assert_eq!(score.rating(), "Very Good");

        score.total = 74.99;
        assert_eq!(score.rating(), "Good");

        score.total = 60.0;
        assert_eq!(score.rating(), "Good");

        score.total = 59.99;
        assert_eq!(score.rating(), "Average");

        score.total = 45.0;
        assert_eq!(score.rating(), "Average");

        score.total = 44.99;
        assert_eq!(score.rating(), "Below Average");

        score.total = 30.0;
        assert_eq!(score.rating(), "Below Average");

        score.total = 29.99;
        assert_eq!(score.rating(), "Poor");
    }

    #[test]
    fn test_deserialize_worker_status() {
        let _guard = test_guard!();
        let json = serde_json::json!({
            "id": "worker-1",
            "host": "192.168.1.100",
            "user": "ubuntu",
            "status": "Healthy",
            "circuit_state": "Closed",
            "used_slots": 4,
            "total_slots": 16,
            "speed_score": 85.5,
            "last_error": null
        });

        let worker: WorkerStatusFromApi = serde_json::from_value(json).unwrap();
        assert_eq!(worker.id, "worker-1");
        assert_eq!(worker.total_slots, 16);
        assert_eq!(worker.speed_score, 85.5);
        assert!(worker.last_error.is_none());
    }

    #[test]
    fn test_deserialize_worker_status_with_error() {
        let _guard = test_guard!();
        let json = serde_json::json!({
            "id": "worker-2",
            "host": "192.168.1.101",
            "user": "ubuntu",
            "status": "Unreachable",
            "circuit_state": "Open",
            "used_slots": 0,
            "total_slots": 8,
            "speed_score": 0.0,
            "last_error": "Connection refused",
            "consecutive_failures": 5,
            "recovery_in_secs": 300
        });

        let worker: WorkerStatusFromApi = serde_json::from_value(json).unwrap();
        assert_eq!(worker.last_error, Some("Connection refused".to_string()));
        assert_eq!(worker.consecutive_failures, 5);
        assert_eq!(worker.recovery_in_secs, Some(300));
    }

    #[test]
    fn test_deserialize_active_build() {
        let _guard = test_guard!();
        let json = serde_json::json!({
            "id": 12345,
            "project_id": "rch",
            "worker_id": "worker-1",
            "command": "cargo build --release",
            "started_at": "2026-01-16T12:00:00Z",
            "last_heartbeat_at": "2026-01-16T12:00:04Z",
            "heartbeat_age_secs": 3,
            "last_progress_at": "2026-01-16T12:00:03Z",
            "progress_age_secs": 4,
            "heartbeat_phase": "execute",
            "heartbeat_detail": "Compiling",
            "heartbeat_counter": 12,
            "heartbeat_percent": 66.0,
            "slots": 4,
            "detector_hook_alive": false,
            "detector_heartbeat_stale": true,
            "detector_progress_stale": true,
            "detector_confidence": 0.91,
            "detector_build_age_secs": 120,
            "detector_slots_owned": 4,
            "detector_last_evaluated_at": "2026-01-16T12:00:05Z"
        });

        let build: ActiveBuildFromApi = serde_json::from_value(json).unwrap();
        assert_eq!(build.id, 12345);
        assert_eq!(build.project_id, "rch");
        assert_eq!(build.command, "cargo build --release");
        assert_eq!(build.heartbeat_phase, Some("execute".to_string()));
        assert_eq!(build.heartbeat_counter, Some(12));
        assert_eq!(build.heartbeat_percent, Some(66.0));
        assert_eq!(build.slots, Some(4));
        assert_eq!(build.detector_confidence, Some(0.91));
        assert_eq!(build.detector_hook_alive, Some(false));
    }

    #[test]
    fn test_deserialize_queued_build() {
        let _guard = test_guard!();
        let json = serde_json::json!({
            "id": 12346,
            "project_id": "rch",
            "command": "cargo test",
            "queued_at": "2026-01-16T12:01:00Z",
            "position": 3,
            "slots_needed": 4,
            "estimated_start": "2026-01-16T12:05:00Z",
            "wait_time": "4m"
        });

        let build: QueuedBuildFromApi = serde_json::from_value(json).unwrap();
        assert_eq!(build.position, 3);
        assert_eq!(build.slots_needed, 4);
        assert_eq!(
            build.estimated_start,
            Some("2026-01-16T12:05:00Z".to_string())
        );
    }

    #[test]
    fn test_deserialize_build_record() {
        let _guard = test_guard!();
        let json = serde_json::json!({
            "id": 100,
            "started_at": "2026-01-16T12:00:00Z",
            "completed_at": "2026-01-16T12:01:30Z",
            "project_id": "rch",
            "worker_id": "worker-1",
            "command": "cargo build",
            "exit_code": 0,
            "duration_ms": 90000,
            "location": "remote",
            "bytes_transferred": 1024000
        });

        let build: BuildRecordFromApi = serde_json::from_value(json).unwrap();
        assert_eq!(build.exit_code, 0);
        assert_eq!(build.duration_ms, 90000);
        assert_eq!(build.bytes_transferred, Some(1024000));
    }

    #[test]
    fn test_deserialize_issue() {
        let _guard = test_guard!();
        let json = serde_json::json!({
            "severity": "warning",
            "summary": "Worker worker-1 has high latency",
            "remediation": "Check network connection"
        });

        let issue: IssueFromApi = serde_json::from_value(json).unwrap();
        assert_eq!(issue.severity, "warning");
        assert_eq!(
            issue.remediation,
            Some("Check network connection".to_string())
        );
    }

    #[test]
    fn test_deserialize_alert_info() {
        let _guard = test_guard!();
        let json = serde_json::json!({
            "id": "alert-123",
            "kind": "worker_degraded",
            "severity": "warning",
            "message": "Worker performance degraded",
            "worker_id": "worker-1",
            "created_at": "2026-01-16T12:00:00Z"
        });

        let alert: AlertInfoFromApi = serde_json::from_value(json).unwrap();
        assert_eq!(alert.kind, "worker_degraded");
        assert_eq!(alert.worker_id, Some("worker-1".to_string()));
    }

    #[test]
    fn test_deserialize_build_stats() {
        let _guard = test_guard!();
        let json = serde_json::json!({
            "total_builds": 100,
            "success_count": 95,
            "failure_count": 5,
            "remote_count": 80,
            "local_count": 20,
            "avg_duration_ms": 45000
        });

        let stats: BuildStatsFromApi = serde_json::from_value(json).unwrap();
        assert_eq!(stats.total_builds, 100);
        assert_eq!(stats.success_count, 95);
        assert_eq!(stats.avg_duration_ms, 45000);
    }

    #[test]
    fn test_deserialize_test_run_stats() {
        let _guard = test_guard!();
        let json = serde_json::json!({
            "total_runs": 50,
            "passed_runs": 45,
            "failed_runs": 3,
            "build_error_runs": 2,
            "avg_duration_ms": 30000,
            "runs_by_kind": {
                "unit": 30,
                "integration": 20
            }
        });

        let stats: TestRunStatsFromApi = serde_json::from_value(json).unwrap();
        assert_eq!(stats.total_runs, 50);
        assert_eq!(stats.passed_runs, 45);
        assert_eq!(stats.runs_by_kind.get("unit"), Some(&30));
    }

    #[test]
    fn test_deserialize_self_test_status() {
        let _guard = test_guard!();
        let json = serde_json::json!({
            "enabled": true,
            "schedule": "0 */6 * * *",
            "interval": "6h",
            "last_run": null,
            "next_run": "2026-01-16T18:00:00Z"
        });

        let status: SelfTestStatusResponse = serde_json::from_value(json).unwrap();
        assert!(status.enabled);
        assert_eq!(status.schedule, Some("0 */6 * * *".to_string()));
        assert!(status.last_run.is_none());
    }

    #[test]
    fn test_deserialize_pagination_info() {
        let _guard = test_guard!();
        let json = serde_json::json!({
            "total": 100,
            "offset": 20,
            "limit": 10,
            "has_more": true
        });

        let pagination: PaginationInfoFromApi = serde_json::from_value(json).unwrap();
        assert_eq!(pagination.total, 100);
        assert!(pagination.has_more);
    }

    // ── SystemPosture tests ──

    fn make_daemon_status(
        workers_total: usize,
        workers_healthy: usize,
    ) -> DaemonFullStatusResponse {
        DaemonFullStatusResponse {
            daemon: DaemonInfoFromApi {
                pid: 1,
                uptime_secs: 100,
                version: "test".to_string(),
                socket_path: "/tmp/test.sock".to_string(),
                started_at: "2026-01-01T00:00:00Z".to_string(),
                workers_total,
                workers_healthy,
                slots_total: 16,
                slots_available: 8,
            },
            workers: vec![],
            active_builds: vec![],
            queued_builds: vec![],
            recent_builds: vec![],
            issues: vec![],
            alerts: vec![],
            stats: BuildStatsFromApi {
                total_builds: 0,
                success_count: 0,
                failure_count: 0,
                remote_count: 0,
                local_count: 0,
                avg_duration_ms: 0,
            },
            test_stats: None,
            saved_time: None,
        }
    }

    #[test]
    fn test_system_posture_remote_ready() {
        let _guard = test_guard!();
        let status = make_daemon_status(2, 2);
        assert_eq!(
            SystemPosture::from_status(&status),
            SystemPosture::RemoteReady
        );
    }

    #[test]
    fn test_system_posture_degraded() {
        let _guard = test_guard!();
        let status = make_daemon_status(3, 1);
        assert_eq!(SystemPosture::from_status(&status), SystemPosture::Degraded);
    }

    #[test]
    fn test_system_posture_local_only_no_workers() {
        let _guard = test_guard!();
        let status = make_daemon_status(0, 0);
        assert_eq!(
            SystemPosture::from_status(&status),
            SystemPosture::LocalOnly
        );
    }

    #[test]
    fn test_system_posture_local_only_no_healthy() {
        let _guard = test_guard!();
        let status = make_daemon_status(2, 0);
        assert_eq!(
            SystemPosture::from_status(&status),
            SystemPosture::LocalOnly
        );
    }

    #[test]
    fn test_system_posture_label_and_description() {
        let _guard = test_guard!();
        assert_eq!(SystemPosture::RemoteReady.label(), "remote-ready");
        assert_eq!(SystemPosture::Degraded.label(), "degraded");
        assert_eq!(SystemPosture::LocalOnly.label(), "local-only");

        assert!(!SystemPosture::RemoteReady.description().is_empty());
        assert!(!SystemPosture::Degraded.description().is_empty());
        assert!(!SystemPosture::LocalOnly.description().is_empty());
    }

    #[test]
    fn test_system_posture_serialization_round_trip() {
        let _guard = test_guard!();
        for posture in [
            SystemPosture::RemoteReady,
            SystemPosture::Degraded,
            SystemPosture::LocalOnly,
        ] {
            let json = serde_json::to_string(&posture).unwrap();
            let deserialized: SystemPosture = serde_json::from_str(&json).unwrap();
            assert_eq!(posture, deserialized);
        }
    }

    // ── Worker remediation tests ──

    fn make_worker(id: &str, status: &str, circuit: &str) -> WorkerStatusFromApi {
        WorkerStatusFromApi {
            id: id.to_string(),
            host: "10.0.0.1".to_string(),
            user: "ubuntu".to_string(),
            status: status.to_string(),
            circuit_state: circuit.to_string(),
            used_slots: 0,
            total_slots: 8,
            speed_score: 50.0,
            last_error: None,
            consecutive_failures: 0,
            recovery_in_secs: None,
            failure_history: vec![],
            pressure_state: None,
            pressure_confidence: None,
            pressure_reason_code: None,
            pressure_policy_rule: None,
            pressure_disk_free_gb: None,
            pressure_disk_total_gb: None,
            pressure_disk_free_ratio: None,
            pressure_disk_io_util_pct: None,
            pressure_memory_pressure: None,
            pressure_telemetry_age_secs: None,
            pressure_telemetry_fresh: None,
        }
    }

    #[test]
    fn test_remediation_circuit_open() {
        let _guard = test_guard!();
        let mut w = make_worker("w1", "unhealthy", "open");
        w.consecutive_failures = 5;
        let hints = generate_worker_remediations(&[w]);

        let circuit_hints: Vec<_> = hints
            .iter()
            .filter(|h| h.reason_code == "circuit_open")
            .collect();
        assert_eq!(circuit_hints.len(), 1);
        assert_eq!(circuit_hints[0].severity, "critical");
        assert!(circuit_hints[0].message.contains("5 consecutive failures"));
        assert!(circuit_hints[0].suggested_action.contains("probe"));
        assert_eq!(circuit_hints[0].worker_id.as_deref(), Some("w1"));
    }

    #[test]
    fn test_remediation_circuit_half_open() {
        let _guard = test_guard!();
        let w = make_worker("w2", "healthy", "half_open");
        let hints = generate_worker_remediations(&[w]);

        let half_open: Vec<_> = hints
            .iter()
            .filter(|h| h.reason_code == "circuit_half_open")
            .collect();
        assert_eq!(half_open.len(), 1);
        assert_eq!(half_open[0].severity, "warning");
    }

    #[test]
    fn test_remediation_pressure_critical() {
        let _guard = test_guard!();
        let mut w = make_worker("w3", "healthy", "closed");
        w.pressure_state = Some("critical".to_string());
        w.pressure_disk_free_gb = Some(1.2);
        let hints = generate_worker_remediations(&[w]);

        let pressure: Vec<_> = hints
            .iter()
            .filter(|h| h.reason_code == "pressure_critical")
            .collect();
        assert_eq!(pressure.len(), 1);
        assert_eq!(pressure[0].severity, "critical");
        assert!(pressure[0].message.contains("1.2 GB free"));
        assert!(pressure[0].suggested_action.contains("cargo clean"));
    }

    #[test]
    fn test_remediation_pressure_warning() {
        let _guard = test_guard!();
        let mut w = make_worker("w4", "healthy", "closed");
        w.pressure_state = Some("warning".to_string());
        let hints = generate_worker_remediations(&[w]);

        let pressure: Vec<_> = hints
            .iter()
            .filter(|h| h.reason_code == "pressure_warning")
            .collect();
        assert_eq!(pressure.len(), 1);
        assert_eq!(pressure[0].severity, "warning");
    }

    #[test]
    fn test_remediation_pressure_telemetry_gap() {
        let _guard = test_guard!();
        let mut w = make_worker("w5", "healthy", "closed");
        w.pressure_state = Some("telemetry_gap".to_string());
        let hints = generate_worker_remediations(&[w]);

        let gap: Vec<_> = hints
            .iter()
            .filter(|h| h.reason_code == "pressure_telemetry_gap")
            .collect();
        assert_eq!(gap.len(), 1);
        assert_eq!(gap[0].severity, "warning");
    }

    #[test]
    fn test_remediation_worker_unreachable() {
        let _guard = test_guard!();
        let mut w = make_worker("w6", "unreachable", "closed");
        w.last_error = Some("Connection refused".to_string());
        let hints = generate_worker_remediations(&[w]);

        let unreach: Vec<_> = hints
            .iter()
            .filter(|h| h.reason_code == "worker_unreachable")
            .collect();
        assert_eq!(unreach.len(), 1);
        assert_eq!(unreach[0].severity, "critical");
        assert!(unreach[0].message.contains("Connection refused"));
        assert!(unreach[0].suggested_action.contains("ssh"));
    }

    #[test]
    fn test_remediation_healthy_workers_no_hints() {
        let _guard = test_guard!();
        let w = make_worker("w7", "healthy", "closed");
        let hints = generate_worker_remediations(&[w]);
        assert!(hints.is_empty(), "healthy worker should produce no hints");
    }

    #[test]
    fn test_remediation_open_circuit_does_not_duplicate_unreachable() {
        let _guard = test_guard!();
        // Worker with open circuit + unreachable should NOT get worker_unreachable hint
        // (the circuit_open hint covers it)
        let w = make_worker("w8", "unreachable", "open");
        let hints = generate_worker_remediations(&[w]);

        let circuit: Vec<_> = hints
            .iter()
            .filter(|h| h.reason_code == "circuit_open")
            .collect();
        let unreach: Vec<_> = hints
            .iter()
            .filter(|h| h.reason_code == "worker_unreachable")
            .collect();
        assert_eq!(circuit.len(), 1);
        assert_eq!(
            unreach.len(),
            0,
            "open circuit should suppress worker_unreachable"
        );
    }

    // ── Convergence remediation tests ──

    #[test]
    fn test_convergence_remediation_drifting() {
        let _guard = test_guard!();
        let conv = RepoConvergenceStatusFromApi {
            status: "degraded".to_string(),
            workers: vec![ConvergenceWorkerViewFromApi {
                worker_id: "w1".to_string(),
                drift_state: "drifting".to_string(),
                drift_confidence: 0.8,
                required_repos: vec!["repo-a".to_string()],
                synced_repos: vec![],
                missing_repos: vec!["repo-a".to_string()],
                attempt_budget_remaining: 3,
                time_budget_remaining_ms: 60000,
                last_status_check_unix_ms: 0,
                remediation: vec![],
            }],
            summary: ConvergenceSummaryFromApi {
                total_workers: 1,
                ready: 0,
                drifting: 1,
                converging: 0,
                failed: 0,
                stale: 0,
            },
        };
        let hints = generate_convergence_remediations(&conv);

        let drift: Vec<_> = hints
            .iter()
            .filter(|h| h.reason_code == "convergence_drifting")
            .collect();
        assert_eq!(drift.len(), 1);
        assert_eq!(drift[0].severity, "warning");
        assert!(drift[0].message.contains("repo-a"));
        assert!(drift[0].suggested_action.contains("repair"));
    }

    #[test]
    fn test_convergence_remediation_failed() {
        let _guard = test_guard!();
        let conv = RepoConvergenceStatusFromApi {
            status: "failed".to_string(),
            workers: vec![ConvergenceWorkerViewFromApi {
                worker_id: "w2".to_string(),
                drift_state: "failed".to_string(),
                drift_confidence: 0.0,
                required_repos: vec![],
                synced_repos: vec![],
                missing_repos: vec![],
                attempt_budget_remaining: 0,
                time_budget_remaining_ms: 0,
                last_status_check_unix_ms: 0,
                remediation: vec![],
            }],
            summary: ConvergenceSummaryFromApi {
                total_workers: 1,
                ready: 0,
                drifting: 0,
                converging: 0,
                failed: 1,
                stale: 0,
            },
        };
        let hints = generate_convergence_remediations(&conv);

        let failed: Vec<_> = hints
            .iter()
            .filter(|h| h.reason_code == "convergence_failed")
            .collect();
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].severity, "critical");
        assert!(failed[0].suggested_action.contains("--force"));
    }

    #[test]
    fn test_convergence_remediation_stale() {
        let _guard = test_guard!();
        let conv = RepoConvergenceStatusFromApi {
            status: "stale".to_string(),
            workers: vec![ConvergenceWorkerViewFromApi {
                worker_id: "w3".to_string(),
                drift_state: "stale".to_string(),
                drift_confidence: 0.0,
                required_repos: vec![],
                synced_repos: vec![],
                missing_repos: vec![],
                attempt_budget_remaining: 5,
                time_budget_remaining_ms: 30000,
                last_status_check_unix_ms: 0,
                remediation: vec![],
            }],
            summary: ConvergenceSummaryFromApi {
                total_workers: 1,
                ready: 0,
                drifting: 0,
                converging: 0,
                failed: 0,
                stale: 1,
            },
        };
        let hints = generate_convergence_remediations(&conv);

        let stale: Vec<_> = hints
            .iter()
            .filter(|h| h.reason_code == "convergence_stale")
            .collect();
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].severity, "info");
        assert!(stale[0].suggested_action.contains("dry-run"));
    }

    #[test]
    fn test_convergence_remediation_ready_produces_no_hints() {
        let _guard = test_guard!();
        let conv = RepoConvergenceStatusFromApi {
            status: "ready".to_string(),
            workers: vec![ConvergenceWorkerViewFromApi {
                worker_id: "w4".to_string(),
                drift_state: "ready".to_string(),
                drift_confidence: 1.0,
                required_repos: vec![],
                synced_repos: vec![],
                missing_repos: vec![],
                attempt_budget_remaining: 5,
                time_budget_remaining_ms: 30000,
                last_status_check_unix_ms: 0,
                remediation: vec![],
            }],
            summary: ConvergenceSummaryFromApi {
                total_workers: 1,
                ready: 1,
                drifting: 0,
                converging: 0,
                failed: 0,
                stale: 0,
            },
        };
        let hints = generate_convergence_remediations(&conv);
        assert!(
            hints.is_empty(),
            "ready convergence should produce no hints"
        );
    }

    #[test]
    fn test_convergence_per_worker_remediation_forwarded() {
        let _guard = test_guard!();
        let conv = RepoConvergenceStatusFromApi {
            status: "degraded".to_string(),
            workers: vec![ConvergenceWorkerViewFromApi {
                worker_id: "w5".to_string(),
                drift_state: "drifting".to_string(),
                drift_confidence: 0.5,
                required_repos: vec![],
                synced_repos: vec![],
                missing_repos: vec![],
                attempt_budget_remaining: 3,
                time_budget_remaining_ms: 60000,
                last_status_check_unix_ms: 0,
                remediation: vec!["run git fetch on worker".to_string()],
            }],
            summary: ConvergenceSummaryFromApi {
                total_workers: 1,
                ready: 0,
                drifting: 1,
                converging: 0,
                failed: 0,
                stale: 0,
            },
        };
        let hints = generate_convergence_remediations(&conv);

        let forwarded: Vec<_> = hints
            .iter()
            .filter(|h| h.reason_code == "convergence_hint")
            .collect();
        assert_eq!(forwarded.len(), 1);
        assert!(forwarded[0].message.contains("git fetch"));
    }

    // ── UnifiedStatusResponse tests ──

    #[test]
    fn test_unified_status_response_serialization() {
        let _guard = test_guard!();
        let status = make_daemon_status(2, 2);
        let unified = UnifiedStatusResponse {
            schema_version: STATUS_SCHEMA_VERSION.to_string(),
            posture: SystemPosture::RemoteReady,
            posture_description: SystemPosture::RemoteReady.description().to_string(),
            daemon: status,
            convergence: None,
            remediation_hints: vec![RemediationHint {
                reason_code: "test_hint".to_string(),
                severity: "info".to_string(),
                message: "test message".to_string(),
                suggested_action: "do something".to_string(),
                worker_id: None,
            }],
        };

        let json = serde_json::to_string(&unified).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["schema_version"], STATUS_SCHEMA_VERSION);
        assert_eq!(parsed["posture"], "remote_ready");
        assert_eq!(parsed["remediation_hints"].as_array().unwrap().len(), 1);
        assert_eq!(parsed["remediation_hints"][0]["reason_code"], "test_hint");
    }

    #[test]
    fn test_unified_status_schema_version_constant() {
        let _guard = test_guard!();
        assert_eq!(STATUS_SCHEMA_VERSION, "1.0.0");
    }

    #[test]
    fn test_remediation_hint_serialization_skips_none_worker() {
        let _guard = test_guard!();
        let hint = RemediationHint {
            reason_code: "test".to_string(),
            severity: "info".to_string(),
            message: "msg".to_string(),
            suggested_action: "act".to_string(),
            worker_id: None,
        };
        let json = serde_json::to_string(&hint).unwrap();
        assert!(
            !json.contains("worker_id"),
            "None worker_id should be skipped"
        );

        let hint_with_worker = RemediationHint {
            worker_id: Some("w1".to_string()),
            ..hint
        };
        let json2 = serde_json::to_string(&hint_with_worker).unwrap();
        assert!(
            json2.contains("worker_id"),
            "Some worker_id should be included"
        );
    }
}
