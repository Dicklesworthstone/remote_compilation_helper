//! Types for the enhanced status command.
//!
//! These types mirror the response structures from rchd's /status API endpoint.

use serde::{Deserialize, Serialize};

/// Full status response from daemon's GET /status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonFullStatusResponse {
    pub daemon: DaemonInfoFromApi,
    pub workers: Vec<WorkerStatusFromApi>,
    pub active_builds: Vec<ActiveBuildFromApi>,
    pub recent_builds: Vec<BuildRecordFromApi>,
    pub issues: Vec<IssueFromApi>,
    pub stats: BuildStatsFromApi,
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
}

/// Issue from API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueFromApi {
    pub severity: String,
    pub summary: String,
    pub remediation: Option<String>,
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

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(30), "30s");
        assert_eq!(format_duration(90), "1m 30s");
        assert_eq!(format_duration(3661), "1h 1m");
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1500), "1.5 KB");
        assert_eq!(format_bytes(1_500_000), "1.4 MB");
        assert_eq!(format_bytes(1_500_000_000), "1.4 GB");
    }

    #[test]
    fn test_extract_json_body() {
        let response = "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{\"test\": 1}";
        assert_eq!(extract_json_body(response), Some("{\"test\": 1}"));
    }

    #[test]
    fn test_deserialize_daemon_status() {
        let json = r#"{
            "daemon": {
                "pid": 1234,
                "uptime_secs": 3600,
                "version": "0.1.0",
                "socket_path": "/tmp/rch.sock",
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
        }"#;

        let status: DaemonFullStatusResponse = serde_json::from_str(json).unwrap();
        assert_eq!(status.daemon.pid, 1234);
        assert_eq!(status.stats.total_builds, 10);
    }
}
