//! Deployment history management.
//!
//! Tracks past deployments for auditing and rollback purposes.

use anyhow::Result;
use rch_common::fleet_provenance::FleetDeployAuditRecord;
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

        // Fleet deployments run workers in parallel via tokio::spawn, so
        // multiple threads hit this function simultaneously. `writeln!` on
        // `std::fs::File` compiles to *two* `write_all` calls (JSON bytes,
        // then `\n`). Even with O_APPEND — which only makes a single
        // `write()` syscall atomic at EOF — those two writes can
        // interleave between threads and produce `{a}{b}\n\n`, which
        // invalidates the JSONL stream that `get_history` reads back.
        // Build one buffer and hand it to a single `write_all` so each
        // line lands intact (typical entry is well under PIPE_BUF).
        use std::io::Write;
        let mut line = serde_json::to_vec(entry)?;
        line.push(b'\n');
        file.write_all(&line)?;

        Ok(())
    }

    /// Append a fleet-deploy provenance audit record to the audit trail
    /// (bd-session-history-remediation-ocv9i.7.4).
    ///
    /// Stored in `provenance_audit.jsonl`, separate from `deployments.jsonl`,
    /// so the verification/rollback audit trail keeps its own stable schema and
    /// does not perturb the existing deployment-history reader. Uses the same
    /// single-`write_all` atomicity as [`Self::record_deployment`] because fleet
    /// deploys write from parallel `tokio::spawn` tasks.
    pub fn record_provenance_audit(&self, record: &FleetDeployAuditRecord) -> Result<()> {
        let audit_file = self.history_dir.join("provenance_audit.jsonl");

        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&audit_file)?;

        use std::io::Write;
        let mut line = serde_json::to_vec(record)?;
        line.push(b'\n');
        file.write_all(&line)?;

        Ok(())
    }

    /// Read fleet-deploy provenance audit records, newest first, optionally
    /// filtered by worker and capped at `limit`. The audit reader for the fleet
    /// history surface; consumed by tests and (follow-up) a `rch fleet history`
    /// provenance view.
    pub fn get_provenance_audit(
        &self,
        limit: usize,
        worker: Option<&str>,
    ) -> Result<Vec<FleetDeployAuditRecord>> {
        let audit_file = self.history_dir.join("provenance_audit.jsonl");

        if !audit_file.exists() {
            return Ok(Vec::new());
        }

        let content = fs::read_to_string(&audit_file)?;
        let mut entries: Vec<FleetDeployAuditRecord> = content
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect();

        if let Some(worker_id) = worker {
            entries.retain(|e| e.worker_id == worker_id);
        }

        // Newest first by deploy timestamp.
        entries.sort_by_key(|e| std::cmp::Reverse(e.deployed_at_unix_ms));
        entries.truncate(limit);

        Ok(entries)
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
        for (worker, version) in [
            ("worker-1", "1.0.0"),
            ("worker-2", "1.0.0"),
            ("worker-1", "1.1.0"),
        ] {
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

    // ========================
    // Provenance audit trail tests (bd-...-ocv9i.7.4)
    // ========================

    use rch_common::fleet_provenance::{
        ArtifactProvenance, FleetDeployAuditRecord, ProvenancePolicy, ProvenanceVerdict,
        SignatureCheck, rollback_status, verify_artifact_provenance,
    };

    fn audit_record(worker: &str, deployed_at: u64) -> FleetDeployAuditRecord {
        let triple = "x86_64-unknown-linux-musl";
        let p = ArtifactProvenance::dev_artifact("rch-wkr", triple);
        let verdict = verify_artifact_provenance(
            &p,
            triple,
            None,
            SignatureCheck::Absent,
            &ProvenancePolicy::dev_friendly(),
        );
        FleetDeployAuditRecord::from_verdict(
            "run-1",
            "bd-session-history-remediation-ocv9i.7.4",
            worker,
            "ubuntu",
            "/home/ubuntu/.local/bin/rch-wkr",
            &p,
            None,
            deployed_at,
            &verdict,
            "operator",
            "deploy",
        )
    }

    #[test]
    fn provenance_audit_empty_when_no_file() {
        let temp_dir = TempDir::new().unwrap();
        let manager = HistoryManager::with_dir(temp_dir.path().join("history")).unwrap();
        let entries = manager.get_provenance_audit(10, None).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn provenance_audit_record_and_read_back() {
        let temp_dir = TempDir::new().unwrap();
        let manager = HistoryManager::with_dir(temp_dir.path().join("history")).unwrap();

        let mut rec = audit_record("css", 1_700_000_000_000);
        rec.set_duration_ms(1234);
        manager.record_provenance_audit(&rec).unwrap();

        let entries = manager.get_provenance_audit(10, None).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].worker_id, "css");
        assert_eq!(entries[0].verification_status, "dev_allowed");
        assert_eq!(entries[0].rollback_status, rollback_status::NONE);
        assert_eq!(entries[0].duration_ms, 1234);
    }

    #[test]
    fn provenance_audit_filters_by_worker_and_orders_newest_first() {
        let temp_dir = TempDir::new().unwrap();
        let manager = HistoryManager::with_dir(temp_dir.path().join("history")).unwrap();

        manager
            .record_provenance_audit(&audit_record("css", 100))
            .unwrap();
        manager
            .record_provenance_audit(&audit_record("hz1", 200))
            .unwrap();
        manager
            .record_provenance_audit(&audit_record("css", 300))
            .unwrap();

        let css = manager.get_provenance_audit(10, Some("css")).unwrap();
        assert_eq!(css.len(), 2);
        // Newest first.
        assert_eq!(css[0].deployed_at_unix_ms, 300);
        assert_eq!(css[1].deployed_at_unix_ms, 100);

        let all = manager.get_provenance_audit(10, None).unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].deployed_at_unix_ms, 300);
    }

    #[test]
    fn provenance_audit_does_not_pollute_deployment_history() {
        let temp_dir = TempDir::new().unwrap();
        let manager = HistoryManager::with_dir(temp_dir.path().join("history")).unwrap();

        // A provenance audit write must not appear in the deployment-history
        // reader (separate JSONL files, separate schemas).
        manager
            .record_provenance_audit(&audit_record("css", 1))
            .unwrap();
        let deployments = manager.get_history(10, None).unwrap();
        assert!(deployments.is_empty());
    }

    // A rejected verdict is recorded for audit even though the deploy is refused.
    #[test]
    fn provenance_audit_records_rejected_verdict() {
        let temp_dir = TempDir::new().unwrap();
        let manager = HistoryManager::with_dir(temp_dir.path().join("history")).unwrap();

        let triple = "x86_64-unknown-linux-musl";
        let mut p = ArtifactProvenance::dev_artifact("rch-wkr", triple);
        p.target_triple = "aarch64-apple-darwin".to_string();
        let verdict = verify_artifact_provenance(
            &p,
            triple,
            None,
            SignatureCheck::Absent,
            &ProvenancePolicy::dev_friendly(),
        );
        assert!(matches!(verdict, ProvenanceVerdict::Rejected { .. }));
        let rec = FleetDeployAuditRecord::from_verdict(
            "run-x",
            "bd-x",
            "css",
            "ubuntu",
            "/home/ubuntu/.local/bin/rch-wkr",
            &p,
            None,
            7,
            &verdict,
            "operator",
            "refused: wrong triple",
        );
        manager.record_provenance_audit(&rec).unwrap();
        let entries = manager.get_provenance_audit(10, None).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].verification_status, "rejected");
        assert_eq!(
            entries[0].reason_code.as_deref(),
            Some("provenance_wrong_target_triple")
        );
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
