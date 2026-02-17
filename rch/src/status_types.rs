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
}
