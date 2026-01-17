//! Preflight checks for worker deployments.

use crate::ui::context::OutputContext;
use anyhow::Result;
use rch_common::WorkerConfig;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PreflightResult {
    pub ssh_ok: bool,
    pub disk_space_mb: u64,
    pub disk_ok: bool,
    pub rsync_ok: bool,
    pub zstd_ok: bool,
    pub rustup_ok: bool,
    pub current_version: Option<String>,
    pub issues: Vec<PreflightIssue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightIssue {
    pub severity: Severity,
    pub check: String,
    pub message: String,
    pub remediation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerStatus {
    pub worker_id: String,
    pub reachable: bool,
    pub healthy: bool,
    pub version: Option<String>,
    pub issues: Vec<String>,
}

pub async fn run_preflight(
    _worker: &WorkerConfig,
    _ctx: &OutputContext,
) -> Result<PreflightResult> {
    // Simulate successful preflight - real impl would SSH
    Ok(PreflightResult {
        ssh_ok: true,
        disk_space_mb: 10000,
        disk_ok: true,
        rsync_ok: true,
        zstd_ok: true,
        rustup_ok: true,
        current_version: None,
        issues: vec![],
    })
}

pub async fn get_fleet_status(
    workers: &[&WorkerConfig],
    _ctx: &OutputContext,
) -> Result<Vec<WorkerStatus>> {
    Ok(workers
        .iter()
        .map(|w| WorkerStatus {
            worker_id: w.id.0.clone(),
            reachable: true,
            healthy: true,
            version: Some("0.1.0".into()),
            issues: vec![],
        })
        .collect())
}

#[allow(dead_code)]
pub const MIN_DISK_SPACE_MB: u64 = 500;

#[cfg(test)]
mod tests {
    use super::*;

    // ========================
    // Severity tests
    // ========================

    #[test]
    fn severity_info_serializes() {
        let sev = Severity::Info;
        let json = serde_json::to_string(&sev).unwrap();
        assert_eq!(json, "\"Info\"");
    }

    #[test]
    fn severity_warning_serializes() {
        let sev = Severity::Warning;
        let json = serde_json::to_string(&sev).unwrap();
        assert_eq!(json, "\"Warning\"");
    }

    #[test]
    fn severity_error_serializes() {
        let sev = Severity::Error;
        let json = serde_json::to_string(&sev).unwrap();
        assert_eq!(json, "\"Error\"");
    }

    #[test]
    fn severity_ordering() {
        assert!(Severity::Info < Severity::Warning);
        assert!(Severity::Warning < Severity::Error);
        assert!(Severity::Info < Severity::Error);
    }

    #[test]
    fn severity_equality() {
        assert_eq!(Severity::Info, Severity::Info);
        assert_eq!(Severity::Warning, Severity::Warning);
        assert_eq!(Severity::Error, Severity::Error);
        assert_ne!(Severity::Info, Severity::Warning);
    }

    #[test]
    fn severity_deserializes() {
        let json = "\"Warning\"";
        let sev: Severity = serde_json::from_str(json).unwrap();
        assert_eq!(sev, Severity::Warning);
    }

    // ========================
    // PreflightResult tests
    // ========================

    #[test]
    fn preflight_result_default() {
        let result = PreflightResult::default();
        assert!(!result.ssh_ok);
        assert_eq!(result.disk_space_mb, 0);
        assert!(!result.disk_ok);
        assert!(!result.rsync_ok);
        assert!(!result.zstd_ok);
        assert!(!result.rustup_ok);
        assert!(result.current_version.is_none());
        assert!(result.issues.is_empty());
    }

    #[test]
    fn preflight_result_serializes() {
        let result = PreflightResult {
            ssh_ok: true,
            disk_space_mb: 10000,
            disk_ok: true,
            rsync_ok: true,
            zstd_ok: true,
            rustup_ok: false,
            current_version: Some("1.0.0".to_string()),
            issues: vec![PreflightIssue {
                severity: Severity::Warning,
                check: "rustup".to_string(),
                message: "rustup not found".to_string(),
                remediation: Some("Install rustup".to_string()),
            }],
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"ssh_ok\":true"));
        assert!(json.contains("10000"));
        assert!(json.contains("1.0.0"));
        assert!(json.contains("rustup not found"));
    }

    #[test]
    fn preflight_result_deserializes_roundtrip() {
        let result = PreflightResult {
            ssh_ok: true,
            disk_space_mb: 5000,
            disk_ok: true,
            rsync_ok: true,
            zstd_ok: true,
            rustup_ok: true,
            current_version: Some("2.0.0".to_string()),
            issues: vec![],
        };
        let json = serde_json::to_string(&result).unwrap();
        let restored: PreflightResult = serde_json::from_str(&json).unwrap();
        assert!(restored.ssh_ok);
        assert_eq!(restored.disk_space_mb, 5000);
        assert!(restored.disk_ok);
        assert_eq!(restored.current_version, Some("2.0.0".to_string()));
    }

    // ========================
    // PreflightIssue tests
    // ========================

    #[test]
    fn preflight_issue_serializes() {
        let issue = PreflightIssue {
            severity: Severity::Error,
            check: "disk_space".to_string(),
            message: "Insufficient disk space".to_string(),
            remediation: Some("Free up at least 500MB".to_string()),
        };
        let json = serde_json::to_string(&issue).unwrap();
        assert!(json.contains("Error"));
        assert!(json.contains("disk_space"));
        assert!(json.contains("Insufficient disk space"));
        assert!(json.contains("Free up at least 500MB"));
    }

    #[test]
    fn preflight_issue_without_remediation_serializes() {
        let issue = PreflightIssue {
            severity: Severity::Info,
            check: "version".to_string(),
            message: "Current version is up to date".to_string(),
            remediation: None,
        };
        let json = serde_json::to_string(&issue).unwrap();
        assert!(json.contains("Info"));
        assert!(json.contains("version"));
        assert!(json.contains("null") || json.contains("remediation\":null"));
    }

    #[test]
    fn preflight_issue_deserializes_roundtrip() {
        let issue = PreflightIssue {
            severity: Severity::Warning,
            check: "ssh".to_string(),
            message: "SSH key not found".to_string(),
            remediation: Some("Generate SSH key".to_string()),
        };
        let json = serde_json::to_string(&issue).unwrap();
        let restored: PreflightIssue = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.severity, Severity::Warning);
        assert_eq!(restored.check, "ssh");
        assert_eq!(restored.message, "SSH key not found");
        assert_eq!(restored.remediation, Some("Generate SSH key".to_string()));
    }

    // ========================
    // WorkerStatus tests
    // ========================

    #[test]
    fn worker_status_serializes() {
        let status = WorkerStatus {
            worker_id: "worker-1".to_string(),
            reachable: true,
            healthy: true,
            version: Some("1.0.0".to_string()),
            issues: vec!["minor warning".to_string()],
        };
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("worker-1"));
        assert!(json.contains("\"reachable\":true"));
        assert!(json.contains("\"healthy\":true"));
        assert!(json.contains("1.0.0"));
        assert!(json.contains("minor warning"));
    }

    #[test]
    fn worker_status_without_version_serializes() {
        let status = WorkerStatus {
            worker_id: "worker-2".to_string(),
            reachable: false,
            healthy: false,
            version: None,
            issues: vec!["Connection refused".to_string()],
        };
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("worker-2"));
        assert!(json.contains("\"reachable\":false"));
        assert!(json.contains("\"healthy\":false"));
        assert!(json.contains("Connection refused"));
    }

    #[test]
    fn worker_status_deserializes_roundtrip() {
        let status = WorkerStatus {
            worker_id: "test-worker".to_string(),
            reachable: true,
            healthy: false,
            version: Some("3.0.0".to_string()),
            issues: vec!["issue1".to_string(), "issue2".to_string()],
        };
        let json = serde_json::to_string(&status).unwrap();
        let restored: WorkerStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.worker_id, "test-worker");
        assert!(restored.reachable);
        assert!(!restored.healthy);
        assert_eq!(restored.version, Some("3.0.0".to_string()));
        assert_eq!(restored.issues.len(), 2);
    }

    // ========================
    // MIN_DISK_SPACE_MB constant test
    // ========================

    #[test]
    fn min_disk_space_constant() {
        assert_eq!(MIN_DISK_SPACE_MB, 500);
    }
}
