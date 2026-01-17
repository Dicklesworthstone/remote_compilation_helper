//! Deployment audit logging.
//!
//! Provides comprehensive audit trail for all deployment operations
//! for compliance and debugging purposes.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use uuid::Uuid;

/// A single audit log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentAuditEntry {
    /// When this event occurred.
    pub timestamp: DateTime<Utc>,
    /// The deployment this event belongs to.
    pub deployment_id: Uuid,
    /// Type of event.
    pub event_type: AuditEventType,
    /// Worker this event relates to (if any).
    pub worker_id: Option<String>,
    /// Additional event details.
    pub details: serde_json::Value,
    /// User who triggered the deployment.
    pub user: String,
    /// Machine the deployment was run from.
    pub machine: String,
}

impl Default for DeploymentAuditEntry {
    fn default() -> Self {
        Self {
            timestamp: Utc::now(),
            deployment_id: Uuid::nil(),
            event_type: AuditEventType::DeploymentStarted,
            worker_id: None,
            details: serde_json::json!({}),
            user: String::new(),
            machine: String::new(),
        }
    }
}

/// Types of auditable events during deployment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditEventType {
    DeploymentStarted,
    DeploymentCompleted,
    DeploymentFailed,
    WorkerPreflight,
    WorkerDrainStarted,
    WorkerDrainCompleted,
    WorkerTransferStarted,
    WorkerTransferCompleted,
    WorkerInstallStarted,
    WorkerInstallCompleted,
    WorkerVerifyStarted,
    WorkerVerifyCompleted,
    WorkerFailed,
    WorkerRolledBack,
    CanaryStarted,
    CanaryPassed,
    CanaryFailed,
}

/// Summary statistics from the audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditSummary {
    pub total_events: usize,
    pub workers_deployed: usize,
    pub workers_failed: usize,
    pub duration_ms: u64,
}

/// Audit logger for deployment operations.
pub struct AuditLogger {
    file: Option<BufWriter<File>>,
    entries: Vec<DeploymentAuditEntry>,
    started_at: Option<DateTime<Utc>>,
}

impl AuditLogger {
    pub fn new(path: Option<&Path>) -> anyhow::Result<Self> {
        let file = if let Some(p) = path {
            Some(BufWriter::new(File::create(p)?))
        } else {
            None
        };
        Ok(Self {
            file,
            entries: Vec::new(),
            started_at: None,
        })
    }

    pub fn log(&mut self, entry: DeploymentAuditEntry) -> anyhow::Result<()> {
        if self.started_at.is_none() {
            self.started_at = Some(entry.timestamp);
        }
        if let Some(ref mut file) = self.file {
            let line = serde_json::to_string(&entry)?;
            writeln!(file, "{}", line)?;
            file.flush()?;
        }
        self.entries.push(entry);
        Ok(())
    }

    pub fn log_deployment_started(
        &mut self,
        deployment_id: Uuid,
        target_version: &str,
        worker_count: usize,
        strategy: &str,
    ) -> anyhow::Result<()> {
        self.log(DeploymentAuditEntry {
            timestamp: Utc::now(),
            deployment_id,
            event_type: AuditEventType::DeploymentStarted,
            worker_id: None,
            details: serde_json::json!({"target_version": target_version, "worker_count": worker_count, "strategy": strategy}),
            user: whoami(),
            machine: hostname(),
        })
    }

    pub fn log_worker_event(
        &mut self,
        deployment_id: Uuid,
        worker_id: &str,
        event_type: AuditEventType,
        details: serde_json::Value,
    ) -> anyhow::Result<()> {
        self.log(DeploymentAuditEntry {
            timestamp: Utc::now(),
            deployment_id,
            event_type,
            worker_id: Some(worker_id.to_string()),
            details,
            user: whoami(),
            machine: hostname(),
        })
    }

    pub fn summary(&self) -> AuditSummary {
        let duration_ms = if let (Some(start), Some(last)) =
            (self.started_at, self.entries.last().map(|e| e.timestamp))
        {
            (last - start).num_milliseconds().unsigned_abs()
        } else {
            0
        };
        AuditSummary {
            total_events: self.entries.len(),
            workers_deployed: self
                .entries
                .iter()
                .filter(|e| matches!(e.event_type, AuditEventType::WorkerInstallCompleted))
                .count(),
            workers_failed: self
                .entries
                .iter()
                .filter(|e| matches!(e.event_type, AuditEventType::WorkerFailed))
                .count(),
            duration_ms,
        }
    }

    pub fn entries(&self) -> &[DeploymentAuditEntry] {
        &self.entries
    }
}

fn whoami() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| {
            std::fs::read_to_string("/etc/hostname")
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|_| "unknown".to_string())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================
    // DeploymentAuditEntry tests
    // ========================

    #[test]
    fn deployment_audit_entry_default_has_nil_deployment_id() {
        let entry = DeploymentAuditEntry::default();
        assert_eq!(entry.deployment_id, Uuid::nil());
    }

    #[test]
    fn deployment_audit_entry_default_has_deployment_started_event() {
        let entry = DeploymentAuditEntry::default();
        assert_eq!(entry.event_type, AuditEventType::DeploymentStarted);
    }

    #[test]
    fn deployment_audit_entry_default_has_no_worker() {
        let entry = DeploymentAuditEntry::default();
        assert!(entry.worker_id.is_none());
    }

    #[test]
    fn deployment_audit_entry_default_has_empty_details() {
        let entry = DeploymentAuditEntry::default();
        assert_eq!(entry.details, serde_json::json!({}));
    }

    #[test]
    fn deployment_audit_entry_default_has_empty_user_and_machine() {
        let entry = DeploymentAuditEntry::default();
        assert_eq!(entry.user, "");
        assert_eq!(entry.machine, "");
    }

    #[test]
    fn deployment_audit_entry_serializes_roundtrip() {
        let entry = DeploymentAuditEntry {
            timestamp: Utc::now(),
            deployment_id: Uuid::new_v4(),
            event_type: AuditEventType::WorkerInstallCompleted,
            worker_id: Some("worker-1".to_string()),
            details: serde_json::json!({"version": "1.0.0"}),
            user: "test-user".to_string(),
            machine: "test-machine".to_string(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let restored: DeploymentAuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.deployment_id, entry.deployment_id);
        assert_eq!(restored.event_type, AuditEventType::WorkerInstallCompleted);
        assert_eq!(restored.worker_id, Some("worker-1".to_string()));
        assert_eq!(restored.user, "test-user");
        assert_eq!(restored.machine, "test-machine");
    }

    // ========================
    // AuditEventType tests
    // ========================

    #[test]
    fn audit_event_type_deployment_started_serializes() {
        let event = AuditEventType::DeploymentStarted;
        let json = serde_json::to_string(&event).unwrap();
        assert_eq!(json, "\"DeploymentStarted\"");
    }

    #[test]
    fn audit_event_type_deployment_completed_serializes() {
        let event = AuditEventType::DeploymentCompleted;
        let json = serde_json::to_string(&event).unwrap();
        assert_eq!(json, "\"DeploymentCompleted\"");
    }

    #[test]
    fn audit_event_type_deployment_failed_serializes() {
        let event = AuditEventType::DeploymentFailed;
        let json = serde_json::to_string(&event).unwrap();
        assert_eq!(json, "\"DeploymentFailed\"");
    }

    #[test]
    fn audit_event_type_worker_events_serialize() {
        let events = [
            (AuditEventType::WorkerPreflight, "WorkerPreflight"),
            (AuditEventType::WorkerDrainStarted, "WorkerDrainStarted"),
            (AuditEventType::WorkerDrainCompleted, "WorkerDrainCompleted"),
            (AuditEventType::WorkerTransferStarted, "WorkerTransferStarted"),
            (
                AuditEventType::WorkerTransferCompleted,
                "WorkerTransferCompleted",
            ),
            (AuditEventType::WorkerInstallStarted, "WorkerInstallStarted"),
            (
                AuditEventType::WorkerInstallCompleted,
                "WorkerInstallCompleted",
            ),
            (AuditEventType::WorkerVerifyStarted, "WorkerVerifyStarted"),
            (
                AuditEventType::WorkerVerifyCompleted,
                "WorkerVerifyCompleted",
            ),
            (AuditEventType::WorkerFailed, "WorkerFailed"),
            (AuditEventType::WorkerRolledBack, "WorkerRolledBack"),
        ];
        for (event, expected) in events {
            let json = serde_json::to_string(&event).unwrap();
            assert_eq!(json, format!("\"{}\"", expected));
        }
    }

    #[test]
    fn audit_event_type_canary_events_serialize() {
        let events = [
            (AuditEventType::CanaryStarted, "CanaryStarted"),
            (AuditEventType::CanaryPassed, "CanaryPassed"),
            (AuditEventType::CanaryFailed, "CanaryFailed"),
        ];
        for (event, expected) in events {
            let json = serde_json::to_string(&event).unwrap();
            assert_eq!(json, format!("\"{}\"", expected));
        }
    }

    #[test]
    fn audit_event_type_equality() {
        assert_eq!(AuditEventType::DeploymentStarted, AuditEventType::DeploymentStarted);
        assert_ne!(AuditEventType::DeploymentStarted, AuditEventType::DeploymentCompleted);
    }

    // ========================
    // AuditSummary tests
    // ========================

    #[test]
    fn audit_summary_serializes_roundtrip() {
        let summary = AuditSummary {
            total_events: 10,
            workers_deployed: 5,
            workers_failed: 2,
            duration_ms: 12345,
        };
        let json = serde_json::to_string(&summary).unwrap();
        let restored: AuditSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.total_events, 10);
        assert_eq!(restored.workers_deployed, 5);
        assert_eq!(restored.workers_failed, 2);
        assert_eq!(restored.duration_ms, 12345);
    }

    // ========================
    // AuditLogger tests
    // ========================

    #[test]
    fn audit_logger_new_without_path_creates_memory_only_logger() {
        let logger = AuditLogger::new(None).unwrap();
        assert!(logger.entries().is_empty());
    }

    #[test]
    fn audit_logger_log_stores_entry() {
        let mut logger = AuditLogger::new(None).unwrap();
        let entry = DeploymentAuditEntry::default();
        logger.log(entry).unwrap();
        assert_eq!(logger.entries().len(), 1);
    }

    #[test]
    fn audit_logger_log_multiple_entries() {
        let mut logger = AuditLogger::new(None).unwrap();
        for i in 0..5 {
            let mut entry = DeploymentAuditEntry::default();
            entry.user = format!("user-{}", i);
            logger.log(entry).unwrap();
        }
        assert_eq!(logger.entries().len(), 5);
    }

    #[test]
    fn audit_logger_summary_empty_logger() {
        let logger = AuditLogger::new(None).unwrap();
        let summary = logger.summary();
        assert_eq!(summary.total_events, 0);
        assert_eq!(summary.workers_deployed, 0);
        assert_eq!(summary.workers_failed, 0);
        assert_eq!(summary.duration_ms, 0);
    }

    #[test]
    fn audit_logger_summary_counts_deployed_workers() {
        let mut logger = AuditLogger::new(None).unwrap();

        // Log some worker install completed events
        for i in 0..3 {
            logger
                .log(DeploymentAuditEntry {
                    event_type: AuditEventType::WorkerInstallCompleted,
                    worker_id: Some(format!("worker-{}", i)),
                    ..Default::default()
                })
                .unwrap();
        }

        let summary = logger.summary();
        assert_eq!(summary.workers_deployed, 3);
    }

    #[test]
    fn audit_logger_summary_counts_failed_workers() {
        let mut logger = AuditLogger::new(None).unwrap();

        // Log some worker failed events
        for i in 0..2 {
            logger
                .log(DeploymentAuditEntry {
                    event_type: AuditEventType::WorkerFailed,
                    worker_id: Some(format!("worker-{}", i)),
                    ..Default::default()
                })
                .unwrap();
        }

        let summary = logger.summary();
        assert_eq!(summary.workers_failed, 2);
    }

    #[test]
    fn audit_logger_log_deployment_started_logs_correct_event() {
        let mut logger = AuditLogger::new(None).unwrap();
        let deployment_id = Uuid::new_v4();

        logger
            .log_deployment_started(deployment_id, "1.0.0", 5, "all-at-once")
            .unwrap();

        let entries = logger.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].deployment_id, deployment_id);
        assert_eq!(entries[0].event_type, AuditEventType::DeploymentStarted);
        assert!(entries[0].worker_id.is_none());
        assert!(entries[0].details["target_version"] == "1.0.0");
        assert!(entries[0].details["worker_count"] == 5);
        assert!(entries[0].details["strategy"] == "all-at-once");
    }

    #[test]
    fn audit_logger_log_worker_event_logs_correct_event() {
        let mut logger = AuditLogger::new(None).unwrap();
        let deployment_id = Uuid::new_v4();

        logger
            .log_worker_event(
                deployment_id,
                "worker-1",
                AuditEventType::WorkerTransferStarted,
                serde_json::json!({"bytes": 1024}),
            )
            .unwrap();

        let entries = logger.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].deployment_id, deployment_id);
        assert_eq!(
            entries[0].event_type,
            AuditEventType::WorkerTransferStarted
        );
        assert_eq!(entries[0].worker_id, Some("worker-1".to_string()));
        assert!(entries[0].details["bytes"] == 1024);
    }

    #[test]
    fn audit_logger_entries_returns_all_logged_entries() {
        let mut logger = AuditLogger::new(None).unwrap();

        logger.log(DeploymentAuditEntry::default()).unwrap();
        logger
            .log(DeploymentAuditEntry {
                event_type: AuditEventType::DeploymentCompleted,
                ..Default::default()
            })
            .unwrap();

        let entries = logger.entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].event_type, AuditEventType::DeploymentStarted);
        assert_eq!(entries[1].event_type, AuditEventType::DeploymentCompleted);
    }

    // ========================
    // whoami/hostname helper tests
    // ========================

    #[test]
    fn whoami_returns_string() {
        let user = whoami();
        // Should return something (either env var or "unknown")
        assert!(!user.is_empty() || user == "unknown");
    }

    #[test]
    fn hostname_returns_string() {
        let host = hostname();
        // Should return something (either env var or "unknown")
        assert!(!host.is_empty() || host == "unknown");
    }
}
