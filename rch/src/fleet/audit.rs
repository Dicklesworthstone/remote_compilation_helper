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
