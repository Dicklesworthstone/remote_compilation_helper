//! Types for the enhanced status command.
//!
//! These types mirror the response structures from rchd's /status API endpoint.

use rch_common::{CommandTimingBreakdown, SavedTimeStats, WorkerCapabilities};
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
}
