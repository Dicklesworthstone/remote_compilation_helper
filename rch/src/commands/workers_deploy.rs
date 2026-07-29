//! Worker binary deployment commands.
//!
//! This module contains commands for deploying the rch-wkr binary to
//! remote workers via SCP.

use crate::ui::context::OutputContext;
use crate::ui::theme::StatusIndicator;
use anyhow::{Context, Result};
use rch_common::ssh_utils::shell_escape_path_with_home;
use rch_common::{ApiError, ApiResponse, ErrorCode, WorkerConfig};
use serde::Serialize;
use std::path::{Path, PathBuf};
use tokio::process::Command;

use super::helpers::{
    classify_ssh_error_message, major_version_mismatch, ssh_key_path_from_identity,
};
use super::load_workers_from_config;

// =============================================================================
// Workers Deploy Binary Command
// =============================================================================

/// Deploy rch-wkr binary to workers.
///
/// Finds the local rch-wkr binary, checks version on remote workers,
/// and deploys if needed using scp. Falls back to user directories
/// if /usr/local/bin requires sudo.
pub async fn workers_deploy_binary(
    worker_id: Option<String>,
    all: bool,
    force: bool,
    dry_run: bool,
    ctx: &OutputContext,
) -> Result<()> {
    let style = ctx.theme();

    if worker_id.is_none() && !all {
        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::<()>::err(
                "workers deploy-binary",
                ApiError::new(
                    ErrorCode::ConfigValidationError,
                    "Specify either a worker ID or --all",
                ),
            ));
        } else {
            println!(
                "{} Specify either {} or {}",
                StatusIndicator::Error.display(style),
                style.highlight("<worker-id>"),
                style.highlight("--all")
            );
        }
        return Ok(());
    }

    // Load workers configuration
    let workers = load_workers_from_config()?;
    if workers.is_empty() {
        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::<()>::err(
                "workers deploy-binary",
                ApiError::new(
                    ErrorCode::ConfigNotFound,
                    "No workers configured. Run 'rch workers discover --add' first.",
                ),
            ));
        } else {
            println!(
                "{} No workers configured.",
                StatusIndicator::Error.display(style)
            );
            println!(
                "  {} Run '{}' first.",
                style.muted("→"),
                style.highlight("rch workers discover --add")
            );
        }
        return Ok(());
    }

    // Filter to target workers
    let target_workers: Vec<&WorkerConfig> = if all {
        workers.iter().collect()
    } else {
        let wid = worker_id.as_ref().unwrap();
        workers.iter().filter(|w| w.id.as_str() == wid).collect()
    };

    if target_workers.is_empty() {
        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::<()>::err(
                "workers deploy-binary",
                ApiError::new(
                    ErrorCode::ConfigInvalidWorker,
                    format!("Worker '{}' not found in configuration", worker_id.unwrap()),
                ),
            ));
        } else {
            println!(
                "{} Worker '{}' not found in configuration.",
                StatusIndicator::Error.display(style),
                worker_id.unwrap()
            );
        }
        return Ok(());
    }

    // Find local binary
    let local_binary = find_local_binary("rch-wkr")?;
    let local_version = get_binary_version(&local_binary).await?;

    if !ctx.is_json() {
        println!(
            "{} Found local rch-wkr {} at {}",
            StatusIndicator::Success.display(style),
            style.highlight(&local_version),
            style.muted(&local_binary.display().to_string())
        );
        println!();
    }

    // Deploy to each worker
    let mut results: Vec<DeployResult> = Vec::new();

    for worker in target_workers {
        let result =
            deploy_binary_to_worker(worker, &local_binary, &local_version, force, dry_run, ctx)
                .await;
        results.push(result);
    }

    // Output JSON response if needed
    if ctx.is_json() {
        let _ = ctx.json(&ApiResponse::ok(
            "workers deploy-binary",
            serde_json::json!({
                "local_version": local_version,
                "results": results
            }),
        ));
    }

    Ok(())
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Find local binary path.
pub(super) fn find_local_binary(name: &str) -> Result<PathBuf> {
    // Check if running from cargo target directory
    let exe = std::env::current_exe()?;
    let exe_dir = exe
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Cannot get exe directory"))?;

    // Check same directory as current executable
    let same_dir = exe_dir.join(name);
    if same_dir.exists() {
        return Ok(same_dir);
    }

    // Check if it's in PATH
    if let Ok(output) = std::process::Command::new("which").arg(name).output()
        && output.status.success()
    {
        let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !path.is_empty() {
            return Ok(PathBuf::from(path));
        }
    }

    // Check common locations
    let common_paths = ["/usr/local/bin", "/usr/bin", "~/.cargo/bin", "~/.local/bin"];

    for base in common_paths {
        let expanded = shellexpand::tilde(base);
        let path = PathBuf::from(expanded.as_ref()).join(name);
        if path.exists() {
            return Ok(path);
        }
    }

    Err(anyhow::anyhow!(
        "Could not find '{}' binary. Make sure it's built and in PATH.",
        name
    ))
}

/// Get version string from binary.
pub(super) async fn get_binary_version(path: &Path) -> Result<String> {
    let output = Command::new(path)
        .arg("--version")
        .output()
        .await
        .context("Failed to run binary")?;

    if !output.status.success() {
        return Err(anyhow::anyhow!("Binary returned non-zero exit code"));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Extract version from "rch-wkr 1.0.0" or similar
    let version = stdout
        .split_whitespace()
        .nth(1)
        .unwrap_or("unknown")
        .to_string();

    Ok(version)
}

/// Deploy binary to a single worker.
async fn deploy_binary_to_worker(
    worker: &WorkerConfig,
    local_binary: &Path,
    local_version: &str,
    force: bool,
    dry_run: bool,
    ctx: &OutputContext,
) -> DeployResult {
    let style = ctx.theme();

    if !ctx.is_json() {
        print!(
            "  {} {}@{} ... ",
            StatusIndicator::Info.display(style),
            style.highlight(&worker.user),
            style.highlight(&worker.host)
        );
    }

    // Check remote version
    let remote_version = get_remote_version(worker).await.ok();

    // Determine if we need to deploy
    let needs_deploy = if force {
        true
    } else if let Some(ref rv) = remote_version {
        major_version_mismatch(local_version, rv) || rv != local_version
    } else {
        true // Not installed
    };

    if !needs_deploy {
        if !ctx.is_json() {
            println!(
                "{} (already at {})",
                style.success("OK"),
                style.muted(remote_version.as_deref().unwrap_or("?"))
            );
        }
        return DeployResult {
            worker_id: worker.id.to_string(),
            success: true,
            deployed: false,
            local_version: local_version.to_string(),
            remote_version,
            error: None,
        };
    }

    if dry_run {
        if !ctx.is_json() {
            println!(
                "{} (would deploy {} → {})",
                style.info("DRY-RUN"),
                style.muted(remote_version.as_deref().unwrap_or("none")),
                style.highlight(local_version)
            );
        }
        return DeployResult {
            worker_id: worker.id.to_string(),
            success: true,
            deployed: false,
            local_version: local_version.to_string(),
            remote_version,
            error: Some("dry-run".to_string()),
        };
    }

    // Deploy via SCP
    match deploy_via_scp(worker, local_binary).await {
        Ok(remote_path) => {
            if !ctx.is_json() {
                println!(
                    "{} (deployed to {})",
                    style.success("OK"),
                    style.muted(remote_path)
                );
            }
            DeployResult {
                worker_id: worker.id.to_string(),
                success: true,
                deployed: true,
                local_version: local_version.to_string(),
                remote_version: Some(local_version.to_string()),
                error: None,
            }
        }
        Err(e) => {
            if !ctx.is_json() {
                println!("{}", style.error(&format!("FAILED: {}", e)));
            }
            DeployResult {
                worker_id: worker.id.to_string(),
                success: false,
                deployed: false,
                local_version: local_version.to_string(),
                remote_version,
                error: Some(e.to_string()),
            }
        }
    }
}

/// Get remote rch-wkr version via SSH.
pub(super) async fn get_remote_version(worker: &WorkerConfig) -> Result<String> {
    let mut cmd = Command::new("ssh");
    cmd.arg("-o").arg("BatchMode=yes");
    cmd.arg("-o").arg("ConnectTimeout=10");
    cmd.arg("-i").arg(&worker.identity_file);

    let target = format!("{}@{}", worker.user, worker.host);
    cmd.arg(&target);
    cmd.arg("rch-wkr --version 2>/dev/null || ~/.local/bin/rch-wkr --version 2>/dev/null || echo 'NOT_INSTALLED'");

    let output = cmd.output().await.context("SSH command failed")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let key_path = ssh_key_path_from_identity(Some(&worker.identity_file));
        let ssh_error = classify_ssh_error_message(
            &worker.host,
            &worker.user,
            key_path,
            &stderr,
            std::time::Duration::from_secs(10),
        );
        return Err(ssh_error.into());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.contains("NOT_INSTALLED") {
        return Err(anyhow::anyhow!("rch-wkr not installed"));
    }

    // Extract version from "rch-wkr 1.0.0" or similar
    let version = stdout
        .split_whitespace()
        .nth(1)
        .unwrap_or("unknown")
        .trim()
        .to_string();

    Ok(version)
}

/// Deploy binary via SCP to remote worker.
pub(super) async fn deploy_via_scp(
    worker: &WorkerConfig,
    local_binary: &Path,
) -> Result<&'static str> {
    // Try /usr/local/bin first, then fall back to ~/.local/bin
    let remote_paths = [
        ("/usr/local/bin/rch-wkr", "/usr/local/bin"),
        ("~/.local/bin/rch-wkr", "~/.local/bin"),
    ];
    let mut failures = Vec::new();
    let target = format!("{}@{}", worker.user, worker.host);

    for (remote_path, dir) in remote_paths {
        // Ensure target directory exists
        let mut mkdir_cmd = Command::new("ssh");
        mkdir_cmd.arg("-o").arg("BatchMode=yes");
        mkdir_cmd.arg("-o").arg("ConnectTimeout=10");
        mkdir_cmd.arg("-i").arg(&worker.identity_file);

        mkdir_cmd.arg(&target);
        mkdir_cmd.arg(remote_mkdir_command(dir)?);

        let mkdir_output = mkdir_cmd.output().await?;
        if !mkdir_output.status.success() {
            failures.push(deploy_failure(remote_path, "mkdir", &mkdir_output));
            continue;
        }

        // SCP the binary
        let mut scp_cmd = Command::new("scp");
        scp_cmd.arg("-o").arg("BatchMode=yes");
        scp_cmd.arg("-o").arg("ConnectTimeout=30");
        scp_cmd.arg("-i").arg(&worker.identity_file);
        scp_cmd.arg(local_binary);

        let remote_target = scp_remote_target(worker, remote_path);
        scp_cmd.arg(&remote_target);

        let output = scp_cmd.output().await?;

        if output.status.success() {
            // Make executable
            let mut chmod_cmd = Command::new("ssh");
            chmod_cmd.arg("-o").arg("BatchMode=yes");
            chmod_cmd.arg("-o").arg("ConnectTimeout=10");
            chmod_cmd.arg("-i").arg(&worker.identity_file);
            chmod_cmd.arg(&target);
            chmod_cmd.arg(remote_chmod_command(remote_path)?);

            let chmod_output = chmod_cmd.output().await?;
            if !chmod_output.status.success() {
                failures.push(deploy_failure(remote_path, "chmod", &chmod_output));
                continue;
            }

            return Ok(remote_path);
        } else {
            failures.push(deploy_failure(remote_path, "scp", &output));
        }
    }

    if failures.is_empty() {
        Err(anyhow::anyhow!(
            "Failed to deploy to any location on {}",
            worker.host
        ))
    } else {
        Err(anyhow::anyhow!(
            "Failed to deploy to any location on {} ({})",
            worker.host,
            failures.join("; ")
        ))
    }
}

fn remote_mkdir_command(dir: &str) -> Result<String> {
    let escaped_dir = remote_shell_path(dir)?;
    Ok(format!("mkdir -p -- {escaped_dir}"))
}

fn remote_chmod_command(remote_path: &str) -> Result<String> {
    let escaped_path = remote_shell_path(remote_path)?;
    Ok(format!("chmod +x -- {escaped_path}"))
}

fn scp_remote_target(worker: &WorkerConfig, remote_path: &str) -> String {
    format!("{}@{}:{remote_path}", worker.user, worker.host)
}

fn remote_shell_path(path: &str) -> Result<String> {
    shell_escape_path_with_home(path)
        .ok_or_else(|| anyhow::anyhow!("Remote path contains unsupported control characters"))
}

fn deploy_failure(remote_path: &str, stage: &str, output: &std::process::Output) -> String {
    format!(
        "{remote_path}: {stage} failed: {}",
        command_failure_summary(output)
    )
}

fn command_failure_summary(output: &std::process::Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let detail = stderr.trim();
    let detail = if detail.is_empty() {
        stdout.trim()
    } else {
        detail
    };

    match output.status.code() {
        Some(code) if detail.is_empty() => format!("exit {code}"),
        Some(code) => format!("exit {code}: {detail}"),
        None if detail.is_empty() => "terminated by signal".to_string(),
        None => format!("terminated by signal: {detail}"),
    }
}

// =============================================================================
// Response Types
// =============================================================================

/// Result of deploying to a single worker.
#[derive(Debug, Clone, Serialize)]
struct DeployResult {
    worker_id: String,
    success: bool,
    deployed: bool,
    local_version: String,
    remote_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_deploy_shell_commands_quote_paths() {
        assert_eq!(
            remote_mkdir_command("/usr/local/bin").expect("mkdir command"),
            "mkdir -p -- '/usr/local/bin'"
        );
        assert_eq!(
            remote_mkdir_command("~/.local/bin").expect("mkdir command"),
            "mkdir -p -- \"$HOME/.local/bin\""
        );
        assert_eq!(
            remote_chmod_command("~/.local/bin/rch-wkr").expect("chmod command"),
            "chmod +x -- \"$HOME/.local/bin/rch-wkr\""
        );
        assert_eq!(
            remote_chmod_command("dir with spaces/rch-wkr").expect("chmod command"),
            "chmod +x -- 'dir with spaces/rch-wkr'"
        );
    }

    #[test]
    fn remote_deploy_shell_commands_reject_control_characters() {
        let err = remote_chmod_command("bad\npath")
            .expect_err("control characters should be rejected")
            .to_string();
        assert!(err.contains("control characters"));
    }
}
