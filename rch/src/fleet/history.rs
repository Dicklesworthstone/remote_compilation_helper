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
}
