//! Preflight checks for worker deployments.

use crate::fleet::ssh::SshExecutor;
use crate::ui::context::OutputContext;
use anyhow::Result;
use futures::stream::{self, StreamExt};
use rch_common::{FleetConfig, WorkerConfig};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, info, warn};

/// Maximum concurrent SSH queries to workers (prevents overwhelming network/SSH agent).
const MAX_CONCURRENT_QUERIES: usize = 10;

/// Default timeout for individual worker queries in seconds.
const DEFAULT_QUERY_TIMEOUT_SECS: u64 = 30;

/// Retry an async operation with configurable retry count and delay.
///
/// Uses exponential backoff between retries. Returns the last error if all attempts fail.
pub async fn with_retry<T, E, F, Fut>(
    config: &FleetConfig,
    operation: F,
) -> std::result::Result<T, E>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = std::result::Result<T, E>>,
    E: std::fmt::Display,
{
    let mut last_error = None;

    for attempt in 0..=config.retry_count {
        match operation().await {
            Ok(result) => return Ok(result),
            Err(e) => {
                if attempt < config.retry_count {
                    debug!(
                        attempt = %attempt,
                        max_retries = %config.retry_count,
                        error = %e,
                        delay_ms = %config.retry_delay_ms,
                        "Retrying after transient error"
                    );
                    tokio::time::sleep(config.retry_delay()).await;
                }
                last_error = Some(e);
            }
        }
    }

    Err(last_error.unwrap())
}

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
    worker: &WorkerConfig,
    _ctx: &OutputContext,
    config: &FleetConfig,
) -> Result<PreflightResult> {
    let mut issues = Vec::new();

    // Log config values being used
    debug!(
        ssh_connect_timeout = config.ssh_connect_timeout_secs,
        ssh_command_timeout = config.ssh_command_timeout_secs,
        min_disk_space_mb = config.min_disk_space_mb,
        "Using fleet configuration for preflight"
    );

    // =========================================================================
    // SSH Connectivity Check
    // =========================================================================
    debug!(
        worker = %worker.id,
        host = %worker.host,
        "Checking SSH connectivity"
    );

    let ssh_executor = SshExecutor::new(worker).connect_timeout(config.ssh_connect_timeout());

    let ssh_result = ssh_executor.check_connectivity().await;

    let ssh_ok = match &ssh_result {
        Ok(connected) => {
            if *connected {
                info!(
                    worker = %worker.id,
                    ssh_ok = true,
                    "SSH connectivity check passed"
                );
                true
            } else {
                warn!(
                    worker = %worker.id,
                    host = %worker.host,
                    "SSH connectivity check returned false"
                );
                issues.push(PreflightIssue {
                    severity: Severity::Error,
                    check: "ssh".to_string(),
                    message: format!("SSH connection to {} failed", worker.host),
                    remediation: Some(format!(
                        "Check: 1) Host is reachable: ping {} 2) SSH service running 3) Key auth: ssh -i {} {}@{}",
                        worker.host, worker.identity_file, worker.user, worker.host
                    )),
                });
                false
            }
        }
        Err(e) => {
            warn!(
                worker = %worker.id,
                host = %worker.host,
                error = %e,
                "SSH connectivity check failed"
            );
            issues.push(PreflightIssue {
                severity: Severity::Error,
                check: "ssh".to_string(),
                message: format!("SSH connection to {} failed: {}", worker.host, e),
                remediation: Some(format!(
                    "Check: 1) Host is reachable: ping {} 2) SSH service running 3) Key auth: ssh -i {} {}@{}",
                    worker.host, worker.identity_file, worker.user, worker.host
                )),
            });
            false
        }
    };

    info!(
        worker = %worker.id,
        ssh_ok = %ssh_ok,
        "SSH connectivity check complete"
    );

    // =========================================================================
    // Disk Space Check
    // =========================================================================
    let (disk_space_mb, disk_ok) = if ssh_ok {
        debug!(worker = %worker.id, "Checking disk space");

        // Portable df command that works on Linux and macOS
        // -P: POSIX format (consistent columns)
        // -m: 1MB blocks
        // awk extracts available space (4th column)
        let disk_cmd = "df -Pm /tmp 2>/dev/null | tail -1 | awk '{print $4}'";

        match ssh_executor.run_command(disk_cmd).await {
            Ok(output) => {
                if output.success() {
                    match output.stdout.trim().parse::<u64>() {
                        Ok(mb) => {
                            let ok = mb >= config.min_disk_space_mb;
                            if !ok {
                                warn!(
                                    worker = %worker.id,
                                    disk_mb = %mb,
                                    threshold_mb = %config.min_disk_space_mb,
                                    "Low disk space warning"
                                );
                                issues.push(PreflightIssue {
                                    severity: Severity::Warning,
                                    check: "disk_space".to_string(),
                                    message: format!(
                                        "Low disk space: {}MB available, {}MB required",
                                        mb, config.min_disk_space_mb
                                    ),
                                    remediation: Some(format!(
                                        "Free up disk space on {}: rm -rf /tmp/rch-* or expand volume",
                                        worker.host
                                    )),
                                });
                            }
                            info!(
                                worker = %worker.id,
                                disk_mb = %mb,
                                threshold_mb = %config.min_disk_space_mb,
                                ok = %ok,
                                "Disk space check complete"
                            );
                            (mb, ok)
                        }
                        Err(e) => {
                            warn!(
                                worker = %worker.id,
                                error = %e,
                                raw = %output.stdout.trim(),
                                "Failed to parse disk space output"
                            );
                            issues.push(PreflightIssue {
                                severity: Severity::Warning,
                                check: "disk_space".to_string(),
                                message: format!("Could not parse disk space: {}", e),
                                remediation: None,
                            });
                            (0, false)
                        }
                    }
                } else {
                    warn!(
                        worker = %worker.id,
                        exit_code = %output.exit_code,
                        stderr = %output.stderr.trim(),
                        "Disk space command failed"
                    );
                    issues.push(PreflightIssue {
                        severity: Severity::Warning,
                        check: "disk_space".to_string(),
                        message: format!(
                            "Disk space check failed with exit code {}",
                            output.exit_code
                        ),
                        remediation: None,
                    });
                    (0, false)
                }
            }
            Err(e) => {
                warn!(
                    worker = %worker.id,
                    error = %e,
                    "Disk space check failed"
                );
                issues.push(PreflightIssue {
                    severity: Severity::Warning,
                    check: "disk_space".to_string(),
                    message: format!("Disk space check failed: {}", e),
                    remediation: None,
                });
                (0, false)
            }
        }
    } else {
        // SSH failed, can't check disk
        debug!(worker = %worker.id, "Skipping disk space check - SSH not available");
        (0, false)
    };

    // =========================================================================
    // rsync/zstd Availability Check
    // =========================================================================
    let (rsync_ok, zstd_ok) = if ssh_ok {
        debug!(worker = %worker.id, "Checking rsync availability");

        // Check rsync using POSIX-compliant `command -v`
        let rsync_result = ssh_executor.run_command("command -v rsync").await;
        let rsync_ok = rsync_result.as_ref().map(|o| o.success()).unwrap_or(false);

        if !rsync_ok {
            warn!(worker = %worker.id, tool = "rsync", "Required tool not found");
            issues.push(PreflightIssue {
                severity: Severity::Error,
                check: "rsync".to_string(),
                message: "rsync is not installed or not in PATH".to_string(),
                remediation: Some(format!(
                    "Install rsync on {}: sudo apt install rsync (Debian/Ubuntu) or sudo yum install rsync (RHEL/CentOS)",
                    worker.host
                )),
            });
        } else {
            debug!(worker = %worker.id, "rsync found");
            // Optionally collect version for diagnostics
            if let Ok(output) = ssh_executor
                .run_command("rsync --version 2>/dev/null | head -1")
                .await
                && output.success()
                && !output.stdout.trim().is_empty()
            {
                debug!(
                    worker = %worker.id,
                    version = %output.stdout.trim(),
                    "rsync version"
                );
            }
        }

        debug!(worker = %worker.id, "Checking zstd availability");

        // Check zstd using POSIX-compliant `command -v`
        let zstd_result = ssh_executor.run_command("command -v zstd").await;
        let zstd_ok = zstd_result.as_ref().map(|o| o.success()).unwrap_or(false);

        if !zstd_ok {
            warn!(worker = %worker.id, tool = "zstd", "Required tool not found");
            issues.push(PreflightIssue {
                severity: Severity::Error,
                check: "zstd".to_string(),
                message: "zstd is not installed or not in PATH".to_string(),
                remediation: Some(format!(
                    "Install zstd on {}: sudo apt install zstd (Debian/Ubuntu) or sudo yum install zstd (RHEL/CentOS)",
                    worker.host
                )),
            });
        } else {
            debug!(worker = %worker.id, "zstd found");
            // Optionally collect version for diagnostics
            if let Ok(output) = ssh_executor.run_command("zstd --version 2>/dev/null").await
                && output.success()
                && !output.stdout.trim().is_empty()
            {
                debug!(
                    worker = %worker.id,
                    version = %output.stdout.trim(),
                    "zstd version"
                );
            }
        }

        info!(
            worker = %worker.id,
            rsync = %rsync_ok,
            zstd = %zstd_ok,
            "Tool availability check complete"
        );

        (rsync_ok, zstd_ok)
    } else {
        // SSH failed, can't check tools
        debug!(
            worker = %worker.id,
            "Skipping rsync/zstd check - SSH not available"
        );
        (false, false)
    };

    // =========================================================================
    // rustup Check and Version Detection
    // =========================================================================
    let (rustup_ok, current_version) = if ssh_ok {
        debug!(worker = %worker.id, "Checking rustup availability");

        // Check rustup using POSIX-compliant `command -v`
        let rustup_result = ssh_executor.run_command("command -v rustup").await;
        let rustup_ok = rustup_result.as_ref().map(|o| o.success()).unwrap_or(false);

        if !rustup_ok {
            warn!(worker = %worker.id, tool = "rustup", "Required tool not found");
            issues.push(PreflightIssue {
                severity: Severity::Error,
                check: "rustup".to_string(),
                message: "rustup is not installed or not in PATH".to_string(),
                remediation: Some(format!(
                    "Install rustup on {}: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh",
                    worker.host
                )),
            });
        } else {
            debug!(worker = %worker.id, "rustup found");
            // Check rustc version for diagnostics
            if let Ok(output) = ssh_executor
                .run_command("rustc --version 2>/dev/null")
                .await
                && output.success()
                && !output.stdout.trim().is_empty()
            {
                debug!(
                    worker = %worker.id,
                    version = %output.stdout.trim(),
                    "rustc version"
                );
            }
        }

        // Check rch-wkr version if rustup is available (worker can compile)
        debug!(worker = %worker.id, "Checking rch-wkr version");
        let version = if let Ok(output) = ssh_executor
            .run_command(
                "~/.local/bin/rch-wkr --version 2>/dev/null || rch-wkr --version 2>/dev/null",
            )
            .await
        {
            if output.success() && !output.stdout.trim().is_empty() {
                let version_str = output.stdout.trim();
                // Extract version number (e.g., "rch-wkr 1.0.0" -> "1.0.0")
                let version = version_str.split_whitespace().last().map(|s| s.to_string());
                info!(
                    worker = %worker.id,
                    version = ?version,
                    "rch-wkr version detected"
                );
                version
            } else {
                debug!(worker = %worker.id, "rch-wkr not installed (will be deployed)");
                None
            }
        } else {
            debug!(worker = %worker.id, "rch-wkr not installed (will be deployed)");
            None
        };

        info!(
            worker = %worker.id,
            rustup = %rustup_ok,
            rch_wkr_version = ?version,
            "rustup and rch-wkr check complete"
        );

        (rustup_ok, version)
    } else {
        // SSH failed, can't check rustup
        debug!(
            worker = %worker.id,
            "Skipping rustup/rch-wkr check - SSH not available"
        );
        (false, None)
    };

    Ok(PreflightResult {
        ssh_ok,
        disk_space_mb,
        disk_ok,
        rsync_ok,
        zstd_ok,
        rustup_ok,
        current_version,
        issues,
    })
}

/// Query a single worker's status with timeout handling.
///
/// This function is designed to be called concurrently for multiple workers.
/// It handles individual worker timeouts gracefully, returning a WorkerStatus
/// with reachable=false if the query times out.
async fn query_single_worker(
    worker: &WorkerConfig,
    config: &FleetConfig,
    timeout: Duration,
) -> WorkerStatus {
    debug!(
        worker = %worker.id,
        host = %worker.host,
        timeout_ms = %timeout.as_millis(),
        "Querying worker status"
    );

    // Wrap the entire query in a timeout
    match tokio::time::timeout(timeout, query_worker_inner(worker, config)).await {
        Ok(status) => {
            debug!(
                worker = %worker.id,
                reachable = %status.reachable,
                healthy = %status.healthy,
                version = ?status.version,
                issues = ?status.issues,
                "Worker query completed"
            );
            status
        }
        Err(_) => {
            warn!(
                worker = %worker.id,
                host = %worker.host,
                timeout_ms = %timeout.as_millis(),
                "Worker query timed out"
            );
            WorkerStatus {
                worker_id: worker.id.0.clone(),
                reachable: false,
                healthy: false,
                version: None,
                issues: vec![format!("Query timed out after {}s", timeout.as_secs())],
            }
        }
    }
}

/// Inner worker query logic (without timeout wrapper).
async fn query_worker_inner(worker: &WorkerConfig, config: &FleetConfig) -> WorkerStatus {
    let ssh_executor = SshExecutor::new(worker).connect_timeout(config.ssh_connect_timeout());

    // Check SSH connectivity
    let reachable = ssh_executor.check_connectivity().await.unwrap_or(false);

    let mut issues = Vec::new();
    let mut version = None;
    let mut healthy = reachable;

    if reachable {
        // Check rch-wkr version
        if let Ok(output) = ssh_executor
            .run_command(
                "~/.local/bin/rch-wkr --version 2>/dev/null || rch-wkr --version 2>/dev/null",
            )
            .await
            && output.success()
            && !output.stdout.trim().is_empty()
        {
            // split_whitespace() already handles leading/trailing whitespace
            version = output
                .stdout
                .split_whitespace()
                .last()
                .map(|s| s.to_string());
        }

        // Check disk space
        let disk_cmd = "df -Pm /tmp 2>/dev/null | tail -1 | awk '{print $4}'";
        if let Ok(output) = ssh_executor.run_command(disk_cmd).await
            && output.success()
            && let Ok(mb) = output.stdout.trim().parse::<u64>()
            && mb < config.min_disk_space_mb
        {
            issues.push(format!("Low disk space: {}MB", mb));
            healthy = false;
        }
    } else {
        issues.push("Unreachable".to_string());
    }

    WorkerStatus {
        worker_id: worker.id.0.clone(),
        reachable,
        healthy,
        version,
        issues,
    }
}

/// Query fleet status for all workers with parallel execution.
///
/// Queries all workers concurrently with bounded parallelism to prevent
/// overwhelming the network or SSH agent. Each worker query has an individual
/// timeout to ensure fast overall completion even if some workers are slow.
///
/// # Arguments
///
/// * `workers` - Slice of worker configurations to query
/// * `ctx` - Output context for progress display
/// * `config` - Fleet configuration with timeouts and thresholds
///
/// # Returns
///
/// A vector of `WorkerStatus` for each worker, in the same order as input.
/// Workers that timeout or fail are marked as unreachable with appropriate issues.
pub async fn get_fleet_status(
    workers: &[&WorkerConfig],
    ctx: &OutputContext,
    config: &FleetConfig,
) -> Result<Vec<WorkerStatus>> {
    use indicatif::{ProgressBar, ProgressStyle};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // Handle empty workers case
    if workers.is_empty() {
        debug!("No workers to query");
        return Ok(vec![]);
    }

    // Determine concurrency limit (use config or default)
    let max_concurrent = config.max_concurrent_workers.min(MAX_CONCURRENT_QUERIES);
    let query_timeout = Duration::from_secs(
        config
            .ssh_command_timeout_secs
            .min(DEFAULT_QUERY_TIMEOUT_SECS),
    );

    // Log config values being used
    info!(
        workers = %workers.len(),
        max_concurrent = %max_concurrent,
        ssh_timeout = %config.ssh_connect_timeout_secs,
        query_timeout_secs = %query_timeout.as_secs(),
        "Starting parallel fleet status check"
    );

    // Human-readable progress output (non-JSON/non-quiet mode)
    if !ctx.is_json() && !ctx.is_quiet() {
        eprintln!("Querying {} workers...", workers.len());
    }

    // Create progress bar for multi-worker operations (non-JSON/non-quiet mode only)
    let progress_bar = if !ctx.is_json() && !ctx.is_quiet() && workers.len() > 1 {
        let pb = ProgressBar::new(workers.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{bar:40}] {pos}/{len} workers ({eta})")
                .unwrap_or_else(|_| ProgressStyle::default_bar())
                .progress_chars("=>-"),
        );
        Some(Arc::new(pb))
    } else {
        None
    };

    // Capture verbose flag for worker-level output
    let show_per_worker = ctx.is_verbose() && !ctx.is_json() && !ctx.is_quiet();

    let start = std::time::Instant::now();
    let completed = Arc::new(AtomicUsize::new(0));

    // Clone config for use in async closures
    let config = config.clone();

    // Query all workers in parallel with bounded concurrency
    // Note: We collect into Vec<(usize, WorkerStatus)> to preserve order
    let results: Vec<(usize, WorkerStatus)> = stream::iter(workers.iter().enumerate())
        .map(|(idx, worker)| {
            let config = config.clone();
            let pb = progress_bar.clone();
            let completed = completed.clone();

            async move {
                let status = query_single_worker(worker, &config, query_timeout).await;

                // Update progress
                let done = completed.fetch_add(1, Ordering::Relaxed) + 1;
                if let Some(ref pb) = pb {
                    pb.set_position(done as u64);
                }

                (idx, status)
            }
        })
        .buffer_unordered(max_concurrent)
        .collect()
        .await;

    // Sort by original index to preserve order
    let results: Vec<WorkerStatus> = {
        let mut sorted = results;
        sorted.sort_by_key(|(idx, _)| *idx);
        sorted.into_iter().map(|(_, status)| status).collect()
    };

    // Finish progress bar
    if let Some(pb) = progress_bar {
        pb.finish_with_message("Done");
    }

    // Log summary
    let duration = start.elapsed();
    let reachable_count = results.iter().filter(|r| r.reachable).count();
    let healthy_count = results.iter().filter(|r| r.healthy).count();
    let unreachable_count = results.len() - reachable_count;

    info!(
        total = %results.len(),
        reachable = %reachable_count,
        healthy = %healthy_count,
        unreachable = %unreachable_count,
        duration_ms = %duration.as_millis(),
        "Fleet status query complete"
    );

    // Verbose per-worker status output
    if show_per_worker {
        eprintln!("\nPer-worker status:");
        for r in &results {
            let icon = if r.healthy {
                "✓"
            } else if r.reachable {
                "⚠"
            } else {
                "✗"
            };
            let status_text = if r.healthy {
                "healthy"
            } else if r.reachable {
                "issues found"
            } else {
                "unreachable"
            };
            eprintln!(
                "  {} {} - {}{}",
                icon,
                r.worker_id,
                status_text,
                r.version
                    .as_ref()
                    .map(|v| format!(" (v{})", v))
                    .unwrap_or_default()
            );
            if !r.issues.is_empty() {
                for issue in &r.issues {
                    eprintln!("      → {}", issue);
                }
            }
        }
    }

    // Human-readable summary (non-JSON mode)
    if !ctx.is_json() && !ctx.is_quiet() && unreachable_count > 0 {
        eprintln!("Warning: {} worker(s) unreachable", unreachable_count);
    }

    Ok(results)
}

/// Minimum disk space required in MB.
#[allow(dead_code)] // Reserved for bd-3029.2 preflight disk check
pub const MIN_DISK_SPACE_MB: u64 = 500;

/// SSH connectivity check timeout in seconds (fast fail for preflight).
#[allow(dead_code)] // Available as fallback default
pub const SSH_CONNECT_TIMEOUT_SECS: u64 = 5;

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
