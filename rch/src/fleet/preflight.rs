//! Preflight checks for worker deployments.

use crate::ui::context::OutputContext;
use anyhow::Result;
use rch_common::{SshClient, SshOptions, WorkerConfig};
use serde::{Deserialize, Serialize};

/// Result of preflight checks on a worker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightResult {
    /// Worker identifier.
    pub worker_id: String,
    /// SSH connectivity check passed.
    pub ssh_ok: bool,
    /// Available disk space in MB.
    pub disk_space_mb: u64,
    /// Disk space check passed (>= 500MB).
    pub disk_ok: bool,
    /// rsync is available.
    pub rsync_ok: bool,
    /// zstd is available.
    pub zstd_ok: bool,
    /// rustup is available.
    pub rustup_ok: bool,
    /// Current installed version (if any).
    pub current_version: Option<String>,
    /// Issues found during preflight.
    pub issues: Vec<PreflightIssue>,
}

impl Default for PreflightResult {
    fn default() -> Self {
        Self {
            worker_id: String::new(),
            ssh_ok: false,
            disk_space_mb: 0,
            disk_ok: false,
            rsync_ok: false,
            zstd_ok: false,
            rustup_ok: false,
            current_version: None,
            issues: Vec::new(),
        }
    }
}

/// An issue found during preflight checks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightIssue {
    /// Severity of the issue.
    pub severity: Severity,
    /// Which check found the issue.
    pub check: String,
    /// Human-readable message.
    pub message: String,
    /// Suggested remediation.
    pub remediation: Option<String>,
}

/// Severity level for issues.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    /// Informational only.
    Info,
    /// Warning - may cause problems.
    Warning,
    /// Error - will cause deployment failure.
    Error,
}

/// Run preflight checks on a worker.
pub async fn run_preflight(worker: &WorkerConfig, _ctx: &OutputContext) -> Result<PreflightResult> {
    let mut result = PreflightResult {
        worker_id: worker.id.0.clone(),
        ..Default::default()
    };

    // Create SSH client
    let ssh_options = SshOptions {
        connect_timeout: std::time::Duration::from_secs(10),
        ..Default::default()
    };

    let mut ssh = SshClient::new(worker.clone(), ssh_options);
    if let Err(e) = ssh.connect().await {
        result.issues.push(PreflightIssue {
            severity: Severity::Error,
            check: "ssh".into(),
            message: format!("Cannot connect via SSH: {}", e),
            remediation: Some("Verify SSH key and host configuration".into()),
        });
        return Ok(result);
    }
    result.ssh_ok = true;

    // Check disk space
    match ssh
        .execute("df -m /home | tail -1 | awk '{print $4}'")
        .await
    {
        Ok(cmd_result) => {
            result.disk_space_mb = cmd_result.stdout.trim().parse().unwrap_or(0);
            result.disk_ok = result.disk_space_mb >= 500;
            if !result.disk_ok {
                result.issues.push(PreflightIssue {
                    severity: Severity::Warning,
                    check: "disk_space".into(),
                    message: format!("Low disk space: {}MB (need 500MB)", result.disk_space_mb),
                    remediation: Some("Free up disk space on worker".into()),
                });
            }
        }
        Err(e) => {
            result.issues.push(PreflightIssue {
                severity: Severity::Warning,
                check: "disk_space".into(),
                message: format!("Could not check disk space: {}", e),
                remediation: None,
            });
        }
    }

    // Check required tools
    result.rsync_ok = ssh
        .execute("which rsync")
        .await
        .map(|r| r.success())
        .unwrap_or(false);
    if !result.rsync_ok {
        result.issues.push(PreflightIssue {
            severity: Severity::Error,
            check: "rsync".into(),
            message: "rsync not found".into(),
            remediation: Some("Install rsync: apt install rsync".into()),
        });
    }

    result.zstd_ok = ssh
        .execute("which zstd")
        .await
        .map(|r| r.success())
        .unwrap_or(false);
    if !result.zstd_ok {
        result.issues.push(PreflightIssue {
            severity: Severity::Warning,
            check: "zstd".into(),
            message: "zstd not found (optional, for faster compression)".into(),
            remediation: Some("Install zstd: apt install zstd".into()),
        });
    }

    result.rustup_ok = ssh
        .execute("which rustup")
        .await
        .map(|r| r.success())
        .unwrap_or(false);
    if !result.rustup_ok {
        result.issues.push(PreflightIssue {
            severity: Severity::Warning,
            check: "rustup".into(),
            message: "rustup not found (needed for toolchain sync)".into(),
            remediation: Some(
                "Install rustup: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
                    .into(),
            ),
        });
    }

    // Check current version
    match ssh
        .execute("~/.rch/bin/rch-wkr --version 2>/dev/null || echo 'not installed'")
        .await
    {
        Ok(cmd_result) => {
            let output = cmd_result.stdout.trim();
            if output != "not installed" {
                // Parse version from output like "rch-wkr 0.1.0"
                if let Some(ver) = output.split_whitespace().last() {
                    result.current_version = Some(ver.to_string());
                }
            }
        }
        Err(_) => {
            // Not installed or error - that's fine
        }
    }

    Ok(result)
}

/// Fleet status entry for a worker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetStatusEntry {
    /// Worker identifier.
    pub worker_id: String,
    /// Whether worker is reachable.
    pub reachable: bool,
    /// Whether worker is healthy.
    pub healthy: bool,
    /// Installed version.
    pub version: Option<String>,
    /// Status issues.
    pub issues: Vec<String>,
}

/// Get fleet status for multiple workers.
pub async fn get_fleet_status(
    workers: &[&WorkerConfig],
    ctx: &OutputContext,
) -> Result<Vec<FleetStatusEntry>> {
    let mut results = Vec::new();

    for worker in workers {
        let preflight = run_preflight(worker, ctx).await?;

        let healthy = preflight.ssh_ok
            && preflight.disk_ok
            && preflight.rsync_ok
            && preflight
                .issues
                .iter()
                .all(|i| i.severity < Severity::Error);

        results.push(FleetStatusEntry {
            worker_id: worker.id.0.clone(),
            reachable: preflight.ssh_ok,
            healthy,
            version: preflight.current_version,
            issues: preflight
                .issues
                .iter()
                .filter(|i| i.severity >= Severity::Warning)
                .map(|i| i.message.clone())
                .collect(),
        });
    }

    Ok(results)
}
