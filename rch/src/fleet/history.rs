//! Deployment history management.
//!
//! Tracks past deployments for auditing and rollback purposes.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// A deployment history entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentHistoryEntry {
    /// When the deployment occurred.
    pub timestamp: String,
    /// Worker that was deployed to.
    pub worker_id: String,
    /// Version that was deployed.
    pub version: String,
    /// Previous version (for rollback).
    pub previous_version: Option<String>,
    /// Whether deployment succeeded.
    pub success: bool,
    /// Duration in milliseconds.
    pub duration_ms: u64,
    /// Error message if failed.
    pub error: Option<String>,
}

/// Manages deployment history storage and retrieval.
pub struct HistoryManager {
    history_dir: PathBuf,
}

impl HistoryManager {
    /// Create a new history manager.
    pub fn new() -> Result<Self> {
        let history_dir = dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("rch")
            .join("fleet_history");

        fs::create_dir_all(&history_dir)?;

        Ok(Self { history_dir })
    }

    /// Get deployment history, optionally filtered by worker.
    pub fn get_history(
        &self,
        limit: usize,
        worker: Option<&str>,
    ) -> Result<Vec<DeploymentHistoryEntry>> {
        let history_file = self.history_dir.join("deployments.jsonl");

        if !history_file.exists() {
            return Ok(Vec::new());
        }

        let content = fs::read_to_string(&history_file)?;
        let mut entries: Vec<DeploymentHistoryEntry> = content
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect();

        // Filter by worker if specified
        if let Some(worker_id) = worker {
            entries.retain(|e| e.worker_id == worker_id);
        }

        // Sort by timestamp descending (most recent first)
        entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        // Limit results
        entries.truncate(limit);

        Ok(entries)
    }

    /// Record a new deployment.
    pub fn record_deployment(&self, entry: &DeploymentHistoryEntry) -> Result<()> {
        let history_file = self.history_dir.join("deployments.jsonl");

        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&history_file)?;

        use std::io::Write;
        writeln!(file, "{}", serde_json::to_string(entry)?)?;

        Ok(())
    }

    /// Get the last successful deployment for a worker.
    pub fn get_last_successful(&self, worker_id: &str) -> Result<Option<DeploymentHistoryEntry>> {
        let history = self.get_history(100, Some(worker_id))?;
        Ok(history.into_iter().find(|e| e.success))
    }

    /// Get the previous version for a worker (for rollback).
    pub fn get_previous_version(&self, worker_id: &str) -> Result<Option<String>> {
        let history = self.get_history(10, Some(worker_id))?;

        // Find the first successful deployment that's different from current
        let mut seen_current = false;
        for entry in history {
            if entry.success {
                if seen_current {
                    return Ok(Some(entry.version));
                }
                seen_current = true;
            }
        }

        Ok(None)
    }

    /// Create a history manager with a custom directory (for testing).
    #[cfg(test)]
    pub fn with_dir(history_dir: PathBuf) -> Result<Self> {
        fs::create_dir_all(&history_dir)?;
        Ok(Self { history_dir })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // ========================
    // DeploymentHistoryEntry tests
    // ========================

    #[test]
    fn deployment_history_entry_serializes() {
        let entry = DeploymentHistoryEntry {
            timestamp: "2024-01-15T10:30:00Z".to_string(),
            worker_id: "worker-1".to_string(),
            version: "1.0.0".to_string(),
            previous_version: Some("0.9.0".to_string()),
            success: true,
            duration_ms: 5000,
            error: None,
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("2024-01-15T10:30:00Z"));
        assert!(json.contains("worker-1"));
        assert!(json.contains("1.0.0"));
        assert!(json.contains("0.9.0"));
        assert!(json.contains("\"success\":true"));
        assert!(json.contains("5000"));
    }

    #[test]
    fn deployment_history_entry_failed_serializes() {
        let entry = DeploymentHistoryEntry {
            timestamp: "2024-01-15T10:35:00Z".to_string(),
            worker_id: "worker-2".to_string(),
            version: "1.0.0".to_string(),
            previous_version: None,
            success: false,
            duration_ms: 1000,
            error: Some("Connection timeout".to_string()),
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("worker-2"));
        assert!(json.contains("\"success\":false"));
        assert!(json.contains("Connection timeout"));
    }

    #[test]
    fn deployment_history_entry_deserializes_roundtrip() {
        let entry = DeploymentHistoryEntry {
            timestamp: "2024-01-15T11:00:00Z".to_string(),
            worker_id: "test-worker".to_string(),
            version: "2.0.0".to_string(),
            previous_version: Some("1.5.0".to_string()),
            success: true,
            duration_ms: 3500,
            error: None,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let restored: DeploymentHistoryEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.timestamp, "2024-01-15T11:00:00Z");
        assert_eq!(restored.worker_id, "test-worker");
        assert_eq!(restored.version, "2.0.0");
        assert_eq!(restored.previous_version, Some("1.5.0".to_string()));
        assert!(restored.success);
        assert_eq!(restored.duration_ms, 3500);
        assert!(restored.error.is_none());
    }

    // ========================
    // HistoryManager tests
    // ========================

    #[test]
    fn history_manager_with_dir_creates_directory() {
        let temp_dir = TempDir::new().unwrap();
        let history_dir = temp_dir.path().join("test_history");
        let _manager = HistoryManager::with_dir(history_dir.clone()).unwrap();
        assert!(history_dir.exists());
    }

    #[test]
    fn history_manager_get_history_empty() {
        let temp_dir = TempDir::new().unwrap();
        let manager = HistoryManager::with_dir(temp_dir.path().join("history")).unwrap();
        let history = manager.get_history(10, None).unwrap();
        assert!(history.is_empty());
    }

    #[test]
    fn history_manager_record_and_get_deployment() {
        let temp_dir = TempDir::new().unwrap();
        let manager = HistoryManager::with_dir(temp_dir.path().join("history")).unwrap();

        let entry = DeploymentHistoryEntry {
            timestamp: "2024-01-15T12:00:00Z".to_string(),
            worker_id: "worker-1".to_string(),
            version: "1.0.0".to_string(),
            previous_version: None,
            success: true,
            duration_ms: 2000,
            error: None,
        };

        manager.record_deployment(&entry).unwrap();

        let history = manager.get_history(10, None).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].worker_id, "worker-1");
        assert_eq!(history[0].version, "1.0.0");
    }

    #[test]
    fn history_manager_get_history_filtered_by_worker() {
        let temp_dir = TempDir::new().unwrap();
        let manager = HistoryManager::with_dir(temp_dir.path().join("history")).unwrap();

        // Record deployments for different workers
        for (worker, version) in [("worker-1", "1.0.0"), ("worker-2", "1.0.0"), ("worker-1", "1.1.0")] {
            manager
                .record_deployment(&DeploymentHistoryEntry {
                    timestamp: format!("2024-01-15T12:0{}:00Z", version.chars().nth(2).unwrap()),
                    worker_id: worker.to_string(),
                    version: version.to_string(),
                    previous_version: None,
                    success: true,
                    duration_ms: 1000,
                    error: None,
                })
                .unwrap();
        }

        let history_w1 = manager.get_history(10, Some("worker-1")).unwrap();
        assert_eq!(history_w1.len(), 2);
        for entry in &history_w1 {
            assert_eq!(entry.worker_id, "worker-1");
        }

        let history_w2 = manager.get_history(10, Some("worker-2")).unwrap();
        assert_eq!(history_w2.len(), 1);
        assert_eq!(history_w2[0].worker_id, "worker-2");
    }

    #[test]
    fn history_manager_get_history_respects_limit() {
        let temp_dir = TempDir::new().unwrap();
        let manager = HistoryManager::with_dir(temp_dir.path().join("history")).unwrap();

        // Record many deployments
        for i in 0..10 {
            manager
                .record_deployment(&DeploymentHistoryEntry {
                    timestamp: format!("2024-01-15T12:{:02}:00Z", i),
                    worker_id: "worker-1".to_string(),
                    version: format!("1.0.{}", i),
                    previous_version: None,
                    success: true,
                    duration_ms: 1000,
                    error: None,
                })
                .unwrap();
        }

        let history = manager.get_history(3, None).unwrap();
        assert_eq!(history.len(), 3);
    }

    #[test]
    fn history_manager_get_history_sorted_descending() {
        let temp_dir = TempDir::new().unwrap();
        let manager = HistoryManager::with_dir(temp_dir.path().join("history")).unwrap();

        // Record deployments with different timestamps
        for i in 0..5 {
            manager
                .record_deployment(&DeploymentHistoryEntry {
                    timestamp: format!("2024-01-15T12:{:02}:00Z", i),
                    worker_id: "worker-1".to_string(),
                    version: format!("1.0.{}", i),
                    previous_version: None,
                    success: true,
                    duration_ms: 1000,
                    error: None,
                })
                .unwrap();
        }

        let history = manager.get_history(10, None).unwrap();
        // Most recent (04) should be first
        assert!(history[0].timestamp > history[1].timestamp);
        assert!(history[1].timestamp > history[2].timestamp);
    }

    #[test]
    fn history_manager_get_last_successful() {
        let temp_dir = TempDir::new().unwrap();
        let manager = HistoryManager::with_dir(temp_dir.path().join("history")).unwrap();

        // Record failed then successful
        manager
            .record_deployment(&DeploymentHistoryEntry {
                timestamp: "2024-01-15T12:00:00Z".to_string(),
                worker_id: "worker-1".to_string(),
                version: "1.0.0".to_string(),
                previous_version: None,
                success: true,
                duration_ms: 1000,
                error: None,
            })
            .unwrap();

        manager
            .record_deployment(&DeploymentHistoryEntry {
                timestamp: "2024-01-15T12:01:00Z".to_string(),
                worker_id: "worker-1".to_string(),
                version: "1.1.0".to_string(),
                previous_version: Some("1.0.0".to_string()),
                success: false,
                duration_ms: 500,
                error: Some("Failed".to_string()),
            })
            .unwrap();

        let last = manager.get_last_successful("worker-1").unwrap();
        assert!(last.is_some());
        assert_eq!(last.unwrap().version, "1.0.0");
    }

    #[test]
    fn history_manager_get_last_successful_none() {
        let temp_dir = TempDir::new().unwrap();
        let manager = HistoryManager::with_dir(temp_dir.path().join("history")).unwrap();

        // Only failed deployments
        manager
            .record_deployment(&DeploymentHistoryEntry {
                timestamp: "2024-01-15T12:00:00Z".to_string(),
                worker_id: "worker-1".to_string(),
                version: "1.0.0".to_string(),
                previous_version: None,
                success: false,
                duration_ms: 500,
                error: Some("Failed".to_string()),
            })
            .unwrap();

        let last = manager.get_last_successful("worker-1").unwrap();
        assert!(last.is_none());
    }

    #[test]
    fn history_manager_get_previous_version() {
        let temp_dir = TempDir::new().unwrap();
        let manager = HistoryManager::with_dir(temp_dir.path().join("history")).unwrap();

        // Record two successful deployments
        manager
            .record_deployment(&DeploymentHistoryEntry {
                timestamp: "2024-01-15T12:00:00Z".to_string(),
                worker_id: "worker-1".to_string(),
                version: "1.0.0".to_string(),
                previous_version: None,
                success: true,
                duration_ms: 1000,
                error: None,
            })
            .unwrap();

        manager
            .record_deployment(&DeploymentHistoryEntry {
                timestamp: "2024-01-15T12:01:00Z".to_string(),
                worker_id: "worker-1".to_string(),
                version: "1.1.0".to_string(),
                previous_version: Some("1.0.0".to_string()),
                success: true,
                duration_ms: 1000,
                error: None,
            })
            .unwrap();

        let prev = manager.get_previous_version("worker-1").unwrap();
        assert!(prev.is_some());
        assert_eq!(prev.unwrap(), "1.0.0");
    }

    #[test]
    fn history_manager_get_previous_version_none_with_single_deployment() {
        let temp_dir = TempDir::new().unwrap();
        let manager = HistoryManager::with_dir(temp_dir.path().join("history")).unwrap();

        // Only one successful deployment
        manager
            .record_deployment(&DeploymentHistoryEntry {
                timestamp: "2024-01-15T12:00:00Z".to_string(),
                worker_id: "worker-1".to_string(),
                version: "1.0.0".to_string(),
                previous_version: None,
                success: true,
                duration_ms: 1000,
                error: None,
            })
            .unwrap();

        let prev = manager.get_previous_version("worker-1").unwrap();
        assert!(prev.is_none());
    }

    #[test]
    fn history_manager_get_previous_version_skips_failures() {
        let temp_dir = TempDir::new().unwrap();
        let manager = HistoryManager::with_dir(temp_dir.path().join("history")).unwrap();

        // Record: success, fail, success
        manager
            .record_deployment(&DeploymentHistoryEntry {
                timestamp: "2024-01-15T12:00:00Z".to_string(),
                worker_id: "worker-1".to_string(),
                version: "1.0.0".to_string(),
                previous_version: None,
                success: true,
                duration_ms: 1000,
                error: None,
            })
            .unwrap();

        manager
            .record_deployment(&DeploymentHistoryEntry {
                timestamp: "2024-01-15T12:01:00Z".to_string(),
                worker_id: "worker-1".to_string(),
                version: "1.1.0".to_string(),
                previous_version: Some("1.0.0".to_string()),
                success: false,
                duration_ms: 500,
                error: Some("Failed".to_string()),
            })
            .unwrap();

        manager
            .record_deployment(&DeploymentHistoryEntry {
                timestamp: "2024-01-15T12:02:00Z".to_string(),
                worker_id: "worker-1".to_string(),
                version: "1.2.0".to_string(),
                previous_version: Some("1.0.0".to_string()),
                success: true,
                duration_ms: 1000,
                error: None,
            })
            .unwrap();

        let prev = manager.get_previous_version("worker-1").unwrap();
        assert!(prev.is_some());
        // Should skip the failed 1.1.0 and return 1.0.0
        assert_eq!(prev.unwrap(), "1.0.0");
    }
}
