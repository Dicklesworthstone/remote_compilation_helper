//! CLI command handler implementations.
//!
//! This module contains the actual business logic for each CLI subcommand.
//!
//! ## Module Organization
//!
//! - `types` - Response types for JSON output (WorkerInfo, etc.)
//! - Command handlers are implemented directly in this module

// Sub-modules
mod agents;
mod config;
mod daemon;
mod helpers;
mod hook;
mod queue;
mod speedscore;
mod status;
pub mod types;
mod workers;
mod workers_deploy;
mod workers_init;

// Re-export daemon commands for backward compatibility
pub use daemon::{
    daemon_logs, daemon_reload, daemon_restart, daemon_start, daemon_status, daemon_stop,
};

// Re-export hook commands for backward compatibility
pub use hook::{hook_install, hook_status, hook_test, hook_uninstall};

// Re-export status/diagnostics commands for backward compatibility
pub use status::{check, diagnose, self_test, status_overview};

// Re-export queue/cancel commands for backward compatibility
pub use queue::{cancel_build, queue_status};

// Re-export workers commands for backward compatibility
pub use workers::{
    workers_benchmark, workers_capabilities, workers_disable, workers_drain, workers_enable,
    workers_list, workers_probe,
};

// Re-export agents commands for backward compatibility
pub use agents::{agents_install_hook, agents_list, agents_status, agents_uninstall_hook};

// Re-export config commands for backward compatibility
pub use config::{
    config_diff, config_export, config_get, config_init, config_lint, config_reset, config_set,
    config_show, config_validate,
};

// Re-export speedscore command for backward compatibility
pub use speedscore::speedscore;

// Re-export workers init/discover commands for backward compatibility
pub use workers_init::{workers_discover, workers_init};

// Re-export workers deploy command for backward compatibility
pub use workers_deploy::workers_deploy_binary;

// Re-export types for backward compatibility
pub use types::*;

// Re-export config helpers from helpers module (single source of truth)
#[cfg(test)]
pub(crate) use helpers::set_test_config_dir_override;
pub use helpers::{config_dir, load_workers_from_config};

// Re-export commonly used helpers
#[cfg(not(unix))]
use crate::error::PlatformError;
use crate::error::{DaemonError, SshError};
use crate::status_types::{
    WorkerCapabilitiesFromApi, WorkerCapabilitiesResponseFromApi, extract_json_body,
};
use crate::ui::context::OutputContext;
use crate::ui::progress::Spinner;
use crate::ui::theme::StatusIndicator;
use anyhow::{Context, Result, bail};
use helpers::{major_version_mismatch, rust_version_mismatch};
use rch_common::{ApiError, ApiResponse, ErrorCode, WorkerCapabilities, WorkerConfig};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::process::Command;
use tracing::debug;

use crate::hook::{query_daemon, release_worker};
use crate::transfer::project_id_from_path;

// Note: Response types (WorkerInfo, WorkersListResponse, etc.) are now in types.rs
// and re-exported via `pub use types::*` at the top of this module.
// Helper functions (runtime_label, version helpers, SSH helpers, etc.) are in helpers.rs.

fn has_any_capabilities(capabilities: &WorkerCapabilities) -> bool {
    capabilities.rustc_version.is_some()
        || capabilities.bun_version.is_some()
        || capabilities.node_version.is_some()
        || capabilities.npm_version.is_some()
}

/// Probe local runtime capabilities by running version commands in parallel.
/// Uses tokio async to spawn all 4 version checks concurrently, reducing total
/// latency from ~200ms (sequential) to ~50ms (parallel).
async fn probe_local_capabilities() -> WorkerCapabilities {
    async fn run_version(cmd: &str, args: &[&str]) -> Option<String> {
        let output = tokio::process::Command::new(cmd)
            .args(args)
            .output()
            .await
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let trimmed = stdout.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    }

    // Run all version checks in parallel
    let (rustc, bun, node, npm) = tokio::join!(
        run_version("rustc", &["--version"]),
        run_version("bun", &["--version"]),
        run_version("node", &["--version"]),
        run_version("npm", &["--version"]),
    );

    let mut caps = WorkerCapabilities::new();
    caps.rustc_version = rustc;
    caps.bun_version = bun;
    caps.node_version = node;
    caps.npm_version = npm;
    caps
}

fn collect_local_capability_warnings(
    workers: &[WorkerCapabilitiesFromApi],
    local: &WorkerCapabilities,
) -> Vec<String> {
    let mut warnings = Vec::new();

    if let Some(local_rust) = local.rustc_version.as_ref() {
        let missing: Vec<String> = workers
            .iter()
            .filter(|worker| !worker.capabilities.has_rust())
            .map(|worker| worker.id.clone())
            .collect();
        if !missing.is_empty() {
            warnings.push(format!(
                "Workers missing Rust runtime (local: {}): {}",
                local_rust,
                missing.join(", ")
            ));
        }

        let mismatched: Vec<String> = workers
            .iter()
            .filter_map(|worker| {
                let remote = worker.capabilities.rustc_version.as_ref()?;
                if rust_version_mismatch(local_rust, remote) {
                    Some(format!("{} ({})", worker.id, remote))
                } else {
                    None
                }
            })
            .collect();
        if !mismatched.is_empty() {
            warnings.push(format!(
                "Rust version mismatch vs local {}: {}",
                local_rust,
                mismatched.join(", ")
            ));
        }
    }

    if let Some(local_bun) = local.bun_version.as_ref() {
        let missing: Vec<String> = workers
            .iter()
            .filter(|worker| !worker.capabilities.has_bun())
            .map(|worker| worker.id.clone())
            .collect();
        if !missing.is_empty() {
            warnings.push(format!(
                "Workers missing Bun runtime (local: {}): {}",
                local_bun,
                missing.join(", ")
            ));
        }

        let mismatched: Vec<String> = workers
            .iter()
            .filter_map(|worker| {
                let remote = worker.capabilities.bun_version.as_ref()?;
                if major_version_mismatch(local_bun, remote) {
                    Some(format!("{} ({})", worker.id, remote))
                } else {
                    None
                }
            })
            .collect();
        if !mismatched.is_empty() {
            warnings.push(format!(
                "Bun major version mismatch vs local {}: {}",
                local_bun,
                mismatched.join(", ")
            ));
        }
    }

    if let Some(local_node) = local.node_version.as_ref() {
        let missing: Vec<String> = workers
            .iter()
            .filter(|worker| !worker.capabilities.has_node())
            .map(|worker| worker.id.clone())
            .collect();
        if !missing.is_empty() {
            warnings.push(format!(
                "Workers missing Node runtime (local: {}): {}",
                local_node,
                missing.join(", ")
            ));
        }

        let mismatched: Vec<String> = workers
            .iter()
            .filter_map(|worker| {
                let remote = worker.capabilities.node_version.as_ref()?;
                if major_version_mismatch(local_node, remote) {
                    Some(format!("{} ({})", worker.id, remote))
                } else {
                    None
                }
            })
            .collect();
        if !mismatched.is_empty() {
            warnings.push(format!(
                "Node major version mismatch vs local {}: {}",
                local_node,
                mismatched.join(", ")
            ));
        }
    }

    if let Some(local_npm) = local.npm_version.as_ref() {
        let missing: Vec<String> = workers
            .iter()
            .filter(|worker| worker.capabilities.npm_version.is_none())
            .map(|worker| worker.id.clone())
            .collect();
        if !missing.is_empty() {
            warnings.push(format!(
                "Workers missing npm runtime (local: {}): {}",
                local_npm,
                missing.join(", ")
            ));
        }

        let mismatched: Vec<String> = workers
            .iter()
            .filter_map(|worker| {
                let remote = worker.capabilities.npm_version.as_ref()?;
                if major_version_mismatch(local_npm, remote) {
                    Some(format!("{} ({})", worker.id, remote))
                } else {
                    None
                }
            })
            .collect();
        if !mismatched.is_empty() {
            warnings.push(format!(
                "npm major version mismatch vs local {}: {}",
                local_npm,
                mismatched.join(", ")
            ));
        }
    }

    warnings
}

#[cfg(test)]
fn summarize_capabilities(capabilities: &WorkerCapabilities) -> String {
    let mut parts = Vec::new();
    if let Some(rustc) = capabilities.rustc_version.as_ref() {
        parts.push(format!("rustc {}", rustc));
    }
    if let Some(bun) = capabilities.bun_version.as_ref() {
        parts.push(format!("bun {}", bun));
    }
    if let Some(node) = capabilities.node_version.as_ref() {
        parts.push(format!("node {}", node));
    }
    if let Some(npm) = capabilities.npm_version.as_ref() {
        parts.push(format!("npm {}", npm));
    }

    if parts.is_empty() {
        "unknown".to_string()
    } else {
        parts.join(", ")
    }
}

// Note: All response types (DiagnoseResponse, HookActionResponse, etc.) are defined
// in types.rs and re-exported via `pub use types::*` above.

// Note: config_dir, load_workers_from_config, and test config overrides are defined
// in helpers.rs and re-exported via `pub use helpers::*` above.


// NOTE: workers_deploy_binary and helpers moved to workers_deploy.rs


/// Synchronize Rust toolchain to workers.
///
/// Detects the project's required toolchain from rust-toolchain.toml,
/// checks each worker's installed toolchains, and installs if missing.
pub async fn workers_sync_toolchain(
    worker_id: Option<String>,
    all: bool,
    dry_run: bool,
    ctx: &OutputContext,
) -> Result<()> {
    let style = ctx.theme();

    if worker_id.is_none() && !all {
        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::<()>::err(
                "workers sync-toolchain",
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

    // Detect project toolchain
    let toolchain = detect_project_toolchain()?;

    // Load workers configuration
    let workers = load_workers_from_config()?;
    if workers.is_empty() {
        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::<()>::err(
                "workers sync-toolchain",
                ApiError::new(ErrorCode::ConfigNotFound, "No workers configured"),
            ));
        } else {
            println!(
                "{} No workers configured.",
                StatusIndicator::Error.display(style)
            );
        }
        return Ok(());
    }

    // Filter to target workers
    let target_workers: Vec<&WorkerConfig> = if all {
        workers.iter().collect()
    } else if let Some(ref id) = worker_id {
        workers.iter().filter(|w| w.id.0 == *id).collect()
    } else {
        vec![]
    };

    if target_workers.is_empty() {
        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::<()>::err(
                "workers sync-toolchain",
                ApiError::new(
                    ErrorCode::ConfigInvalidWorker,
                    format!("Worker '{}' not found", worker_id.unwrap_or_default()),
                ),
            ));
        } else {
            println!(
                "{} Worker not found: {}",
                StatusIndicator::Error.display(style),
                worker_id.unwrap_or_default()
            );
        }
        return Ok(());
    }

    if !ctx.is_json() {
        println!("{}", style.format_header("Sync Rust Toolchain"));
        println!();
        println!(
            "  {} Required toolchain: {}",
            style.muted("→"),
            style.highlight(&toolchain)
        );
        if dry_run {
            println!(
                "  {} {}",
                style.muted("→"),
                style.warning("DRY RUN - no changes will be made")
            );
        }
        println!();
    }

    // Sync to each target worker
    let mut results: Vec<ToolchainSyncResult> = Vec::new();

    for worker in &target_workers {
        let result = sync_toolchain_to_worker(worker, &toolchain, dry_run, ctx).await;
        results.push(result);
    }

    // JSON output
    if ctx.is_json() {
        let _ = ctx.json(&ApiResponse::ok(
            "workers sync-toolchain",
            serde_json::json!({
                "toolchain": toolchain,
                "results": results,
            }),
        ));
    } else {
        // Summary
        let success_count = results.iter().filter(|r| r.success).count();
        let already_count = results.iter().filter(|r| r.already_installed).count();
        let fail_count = results.len() - success_count;

        println!();
        println!(
            "  {} Installed: {}, Already present: {}, Failed: {}",
            style.muted("Summary:"),
            style.success(&(success_count - already_count).to_string()),
            style.muted(&already_count.to_string()),
            if fail_count > 0 {
                style.error(&fail_count.to_string())
            } else {
                style.muted("0")
            }
        );
    }

    Ok(())
}

/// Complete worker setup: deploy binary and sync toolchain.
///
/// This is the recommended command for setting up new workers.
/// It combines `rch workers deploy-binary` and `rch workers sync-toolchain`.
pub async fn workers_setup(
    worker_id: Option<String>,
    all: bool,
    dry_run: bool,
    skip_binary: bool,
    skip_toolchain: bool,
    ctx: &OutputContext,
) -> Result<()> {
    let style = ctx.theme();

    if worker_id.is_none() && !all {
        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::<()>::err(
                "workers setup",
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
                "workers setup",
                ApiError::new(ErrorCode::ConfigNotFound, "No workers configured"),
            ));
        } else {
            println!(
                "{} No workers configured. Run {}",
                StatusIndicator::Error.display(style),
                style.highlight("rch workers discover --add")
            );
        }
        return Ok(());
    }

    // Filter to target workers
    let target_workers: Vec<&WorkerConfig> = if all {
        workers.iter().collect()
    } else if let Some(ref id) = worker_id {
        workers.iter().filter(|w| w.id.0 == *id).collect()
    } else {
        vec![]
    };

    if target_workers.is_empty() {
        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::<()>::err(
                "workers setup",
                ApiError::new(
                    ErrorCode::ConfigInvalidWorker,
                    format!("Worker '{}' not found", worker_id.unwrap_or_default()),
                ),
            ));
        } else {
            println!(
                "{} Worker not found: {}",
                StatusIndicator::Error.display(style),
                worker_id.unwrap_or_default()
            );
        }
        return Ok(());
    }

    // Detect project toolchain for sync
    let toolchain = if skip_toolchain {
        None
    } else {
        Some(detect_project_toolchain()?)
    };

    if !ctx.is_json() {
        println!("{}", style.format_header("Worker Setup"));
        println!();
        println!(
            "  {} Workers: {} ({})",
            style.muted("→"),
            target_workers.len(),
            if all {
                "all"
            } else {
                worker_id.as_deref().unwrap_or("?")
            }
        );
        if let Some(ref tc) = toolchain {
            println!("  {} Toolchain: {}", style.muted("→"), style.highlight(tc));
        }
        if dry_run {
            println!(
                "  {} {}",
                style.muted("→"),
                style.warning("DRY RUN - no changes will be made")
            );
        }
        println!();
    }

    // Track overall results
    let mut all_results: Vec<SetupResult> = Vec::new();

    // Setup each worker
    for worker in &target_workers {
        let result = setup_single_worker(
            worker,
            toolchain.as_deref(),
            dry_run,
            skip_binary,
            skip_toolchain,
            ctx,
        )
        .await;
        all_results.push(result);
    }

    // JSON output
    if ctx.is_json() {
        let _ = ctx.json(&ApiResponse::ok(
            "workers setup",
            serde_json::json!({
                "toolchain": toolchain,
                "results": all_results,
            }),
        ));
    } else {
        // Summary
        println!();
        let success_count = all_results.iter().filter(|r| r.success).count();
        let fail_count = all_results.len() - success_count;

        println!(
            "  {} Successful: {}, Failed: {}",
            style.muted("Summary:"),
            style.success(&success_count.to_string()),
            if fail_count > 0 {
                style.error(&fail_count.to_string())
            } else {
                style.muted("0")
            }
        );
    }

    Ok(())
}

/// Result of setting up a single worker.
#[derive(Debug, Clone, Serialize)]
struct SetupResult {
    worker_id: String,
    success: bool,
    binary_deployed: bool,
    toolchain_synced: bool,
    errors: Vec<String>,
}

/// Setup a single worker: deploy binary and sync toolchain.
async fn setup_single_worker(
    worker: &WorkerConfig,
    toolchain: Option<&str>,
    dry_run: bool,
    skip_binary: bool,
    skip_toolchain: bool,
    ctx: &OutputContext,
) -> SetupResult {
    let style = ctx.theme();
    let worker_id = &worker.id.0;

    if !ctx.is_json() {
        println!(
            "  {} Setting up {}...",
            StatusIndicator::Info.display(style),
            style.highlight(worker_id)
        );
    }

    let mut result = SetupResult {
        worker_id: worker_id.clone(),
        success: true,
        binary_deployed: false,
        toolchain_synced: false,
        errors: Vec::new(),
    };

    // Step 1: Deploy binary
    if !skip_binary {
        if !ctx.is_json() {
            print!("      {} Binary: ", style.muted("→"));
            use std::io::Write;
            let _ = std::io::stdout().flush();
        }

        // Find local binary and get version
        let binary_result: Result<bool> = async {
            let local_binary = find_local_binary("rch-wkr")?;
            let local_version = get_binary_version(&local_binary).await?;

            // Check remote version
            let remote_version = get_remote_version(worker).await.ok();

            // Skip if versions match
            if remote_version.as_ref() == Some(&local_version) {
                return Ok(false); // No deployment needed
            }

            if dry_run {
                return Ok(true); // Would deploy (for dry-run reporting)
            }

            // Deploy the binary
            deploy_via_scp(worker, &local_binary).await?;
            Ok(true)
        }
        .await;

        match binary_result {
            Ok(true) if dry_run => {
                if !ctx.is_json() {
                    println!("{}", style.muted("would deploy"));
                }
            }
            Ok(true) => {
                result.binary_deployed = true;
                if !ctx.is_json() {
                    println!("{}", style.success("deployed"));
                }
            }
            Ok(false) => {
                if !ctx.is_json() {
                    println!("{}", style.muted("already up to date"));
                }
            }
            Err(e) => {
                result.success = false;
                result.errors.push(format!("Binary deployment: {}", e));
                if !ctx.is_json() {
                    println!("{} ({})", style.error("FAILED"), e);
                }
            }
        }
    }

    // Step 2: Sync toolchain
    if !skip_toolchain && let Some(tc) = toolchain {
        if !ctx.is_json() {
            print!("      {} Toolchain: ", style.muted("→"));
            use std::io::Write;
            let _ = std::io::stdout().flush();
        }

        if dry_run {
            // Check if already installed for dry-run reporting
            match check_remote_toolchain(worker, tc).await {
                Ok(true) => {
                    if !ctx.is_json() {
                        println!("{}", style.muted("already installed"));
                    }
                    result.toolchain_synced = true;
                }
                Ok(false) => {
                    if !ctx.is_json() {
                        println!("{}", style.muted("would install"));
                    }
                }
                Err(e) => {
                    if !ctx.is_json() {
                        println!("{} ({})", style.warning("check failed"), e);
                    }
                }
            }
        } else {
            // Check and install
            match check_remote_toolchain(worker, tc).await {
                Ok(true) => {
                    result.toolchain_synced = true;
                    if !ctx.is_json() {
                        println!("{}", style.muted("already installed"));
                    }
                }
                Ok(false) => {
                    // Install
                    match install_remote_toolchain(worker, tc).await {
                        Ok(()) => {
                            result.toolchain_synced = true;
                            if !ctx.is_json() {
                                println!("{}", style.success("installed"));
                            }
                        }
                        Err(e) => {
                            result.success = false;
                            result.errors.push(format!("Toolchain install: {}", e));
                            if !ctx.is_json() {
                                println!("{} ({})", style.error("FAILED"), e);
                            }
                        }
                    }
                }
                Err(e) => {
                    result.success = false;
                    result.errors.push(format!("Toolchain check: {}", e));
                    if !ctx.is_json() {
                        println!("{} ({})", style.error("FAILED"), e);
                    }
                }
            }
        }
    }

    // Step 3: Verify worker health (quick SSH ping)
    if !dry_run && result.success {
        if !ctx.is_json() {
            print!("      {} Health: ", style.muted("→"));
            use std::io::Write;
            let _ = std::io::stdout().flush();
        }

        match verify_worker_health(worker).await {
            Ok(true) => {
                if !ctx.is_json() {
                    println!("{}", style.success("OK"));
                }
            }
            Ok(false) => {
                if !ctx.is_json() {
                    println!("{}", style.warning("degraded"));
                }
            }
            Err(e) => {
                result.errors.push(format!("Health check: {}", e));
                if !ctx.is_json() {
                    println!("{} ({})", style.error("FAILED"), e);
                }
            }
        }
    }

    result
}

/// Quick health check: verify SSH works and rch-wkr responds.
async fn verify_worker_health(worker: &WorkerConfig) -> Result<bool> {
    let mut cmd = Command::new("ssh");
    cmd.arg("-o").arg("BatchMode=yes");
    cmd.arg("-o").arg("ConnectTimeout=10");
    cmd.arg("-o").arg("StrictHostKeyChecking=accept-new");
    cmd.arg("-i").arg(&worker.identity_file);
    cmd.arg(format!("{}@{}", worker.user, worker.host));
    cmd.arg("rch-wkr capabilities >/dev/null 2>&1 && echo OK || echo DEGRADED");

    let output = cmd.output().await.context("Health check failed")?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();

    Ok(stdout == "OK")
}

/// Detect the project's required toolchain from rust-toolchain.toml or rust-toolchain.
fn detect_project_toolchain() -> Result<String> {
    use std::fs;

    // Check for rust-toolchain.toml first
    let toml_path = std::env::current_dir()?.join("rust-toolchain.toml");
    if toml_path.exists() {
        let content = fs::read_to_string(&toml_path)?;
        // Parse TOML to find channel
        // Format: [toolchain]\nchannel = "nightly-2025-01-01"
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with("channel")
                && let Some(value) = line.split('=').nth(1)
            {
                let channel = value.trim().trim_matches('"').trim_matches('\'');
                return Ok(channel.to_string());
            }
        }
    }

    // Check for rust-toolchain (plain text)
    let plain_path = std::env::current_dir()?.join("rust-toolchain");
    if plain_path.exists() {
        let content = fs::read_to_string(&plain_path)?;
        return Ok(content.trim().to_string());
    }

    // Default to stable if no toolchain file
    Ok("stable".to_string())
}

/// Sync toolchain to a single worker.
async fn sync_toolchain_to_worker(
    worker: &WorkerConfig,
    toolchain: &str,
    dry_run: bool,
    ctx: &OutputContext,
) -> ToolchainSyncResult {
    let worker_id = &worker.id.0;

    // Use a spinner for progress indication during toolchain sync
    let spinner = if !ctx.is_json() {
        let s = Spinner::new(ctx, &format!("{}: Checking toolchain...", worker_id));
        Some(s)
    } else {
        None
    };

    // Check if toolchain is already installed
    match check_remote_toolchain(worker, toolchain).await {
        Ok(true) => {
            if let Some(s) = spinner {
                s.finish_success(&format!("{}: Already installed", worker_id));
            }
            return ToolchainSyncResult {
                worker_id: worker_id.clone(),
                success: true,
                already_installed: true,
                installed_toolchain: Some(toolchain.to_string()),
                error: None,
            };
        }
        Ok(false) => {
            // Need to install - update spinner message
            if let Some(ref s) = spinner {
                s.set_message(&format!("{}: Installing {}...", worker_id, toolchain));
            }
        }
        Err(e) => {
            if let Some(s) = spinner {
                s.finish_error(&format!("{}: {}", worker_id, e));
            }
            return ToolchainSyncResult {
                worker_id: worker_id.clone(),
                success: false,
                already_installed: false,
                installed_toolchain: None,
                error: Some(e.to_string()),
            };
        }
    }

    if dry_run {
        if let Some(s) = spinner {
            s.finish_warning(&format!("{}: Would install {}", worker_id, toolchain));
        }
        return ToolchainSyncResult {
            worker_id: worker_id.clone(),
            success: true,
            already_installed: false,
            installed_toolchain: None,
            error: None,
        };
    }

    // Install the toolchain
    match install_remote_toolchain(worker, toolchain).await {
        Ok(()) => {
            if let Some(s) = spinner {
                s.finish_success(&format!("{}: Installed {}", worker_id, toolchain));
            }
            ToolchainSyncResult {
                worker_id: worker_id.clone(),
                success: true,
                already_installed: false,
                installed_toolchain: Some(toolchain.to_string()),
                error: None,
            }
        }
        Err(e) => {
            if let Some(s) = spinner {
                s.finish_error(&format!("{}: {}", worker_id, e));
            }
            ToolchainSyncResult {
                worker_id: worker_id.clone(),
                success: false,
                already_installed: false,
                installed_toolchain: None,
                error: Some(e.to_string()),
            }
        }
    }
}

/// Check if a toolchain is installed on a remote worker.
async fn check_remote_toolchain(worker: &WorkerConfig, toolchain: &str) -> Result<bool> {
    let mut cmd = Command::new("ssh");
    cmd.arg("-o").arg("BatchMode=yes");
    cmd.arg("-o").arg("ConnectTimeout=10");
    cmd.arg("-o").arg("StrictHostKeyChecking=accept-new");
    cmd.arg("-i").arg(&worker.identity_file);
    cmd.arg(format!("{}@{}", worker.user, worker.host));
    cmd.arg(format!(
        "rustup show | grep -q '{}' && echo FOUND || echo NOTFOUND",
        toolchain
    ));

    let output = cmd.output().await.context("Failed to SSH to worker")?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    Ok(stdout.trim() == "FOUND")
}

/// Install a toolchain on a remote worker.
async fn install_remote_toolchain(worker: &WorkerConfig, toolchain: &str) -> Result<()> {
    let mut cmd = Command::new("ssh");
    cmd.arg("-o").arg("BatchMode=yes");
    cmd.arg("-o").arg("ConnectTimeout=60"); // Toolchain install can take a while
    cmd.arg("-i").arg(&worker.identity_file);
    cmd.arg(format!("{}@{}", worker.user, worker.host));
    cmd.arg(format!(
        "rustup install {} && rustup component add rust-src --toolchain {}",
        toolchain, toolchain
    ));

    let output = cmd.output().await.context("Failed to install toolchain")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(SshError::ToolchainInstallFailed {
            host: worker.host.clone(),
            toolchain: toolchain.to_string(),
            message: stderr.trim().to_string(),
        }
        .into());
    }

    Ok(())
}

/// Result of syncing toolchain to a single worker.
#[derive(Debug, Clone, Serialize)]
struct ToolchainSyncResult {
    worker_id: String,
    success: bool,
    already_installed: bool,
    installed_toolchain: Option<String>,
    error: Option<String>,
}

// NOTE: workers_init and workers_discover moved to workers_init.rs

// =============================================================================
// Config Commands
// =============================================================================
// NOTE: Config commands moved to config.rs
// =============================================================================
// Diagnose Command
// =============================================================================

#[derive(Debug, Clone, Deserialize)]
struct DaemonHealthResponse {
    status: String,
    version: String,
    uptime_seconds: u64,
}

#[cfg(not(unix))]
async fn query_daemon_health(_socket_path: &str) -> Result<DaemonHealthResponse> {
    Err(PlatformError::UnixOnly {
        feature: "daemon health check".to_string(),
    })?
}

#[cfg(unix)]
async fn query_daemon_health(socket_path: &str) -> Result<DaemonHealthResponse> {
    let stream = UnixStream::connect(socket_path).await?;
    let (reader, mut writer) = stream.into_split();

    let request = "GET /health\n";
    writer.write_all(request.as_bytes()).await?;
    writer.flush().await?;

    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    let mut body = String::new();
    let mut in_body = false;

    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            break;
        }
        if in_body {
            body.push_str(&line);
        } else if line.trim().is_empty() {
            in_body = true;
        }
    }

    let health: DaemonHealthResponse = serde_json::from_str(body.trim())?;
    Ok(health)
}

// NOTE: build_dry_run_summary and diagnose moved to status.rs

/// Helper to send command to daemon socket.
#[cfg(not(unix))]
pub(crate) async fn send_daemon_command(_command: &str) -> Result<String> {
    Err(PlatformError::UnixOnly {
        feature: "daemon commands".to_string(),
    })?
}

#[cfg(unix)]
pub(crate) async fn send_daemon_command(command: &str) -> Result<String> {
    let config = crate::config::load_config()?;
    let expanded = shellexpand::tilde(&config.general.socket_path);
    let socket_path = Path::new(expanded.as_ref());
    if !socket_path.exists() {
        return Err(DaemonError::SocketNotFound {
            socket_path: socket_path.display().to_string(),
        }
        .into());
    }

    let stream = UnixStream::connect(socket_path).await?;
    let (reader, mut writer) = stream.into_split();

    writer.write_all(command.as_bytes()).await?;
    writer.flush().await?;

    let mut reader = BufReader::new(reader);
    let mut response = String::new();
    reader.read_to_string(&mut response).await?;

    Ok(response)
}

// NOTE: self_test, status_overview, and check moved to status.rs
// NOTE: agents_list, agents_status, agents_install_hook, agents_uninstall_hook moved to agents.rs

// =============================================================================
// SpeedScore Commands
// =============================================================================

/// Query the daemon for worker capabilities.
async fn query_workers_capabilities(refresh: bool) -> Result<WorkerCapabilitiesResponseFromApi> {
    let command = if refresh {
        "GET /workers/capabilities?refresh=true\n"
    } else {
        "GET /workers/capabilities\n"
    };
    let response = send_daemon_command(command).await?;
    let json = extract_json_body(&response)
        .ok_or_else(|| anyhow::anyhow!("Invalid response format from daemon"))?;
    let capabilities: WorkerCapabilitiesResponseFromApi =
        serde_json::from_str(json).context("Failed to parse worker capabilities response")?;
    Ok(capabilities)
}

// NOTE: SpeedScore commands moved to speedscore.rs

/// Interactive first-run setup wizard.
///
/// Guides the user through:
/// 1. Detecting potential workers from SSH config
/// 2. Selecting which hosts to use as workers
/// 3. Probing hosts for connectivity
/// 4. Deploying rch-wkr binary to workers
/// 5. Synchronizing Rust toolchain
/// 6. Starting the daemon
/// 7. Installing the Claude Code hook
/// 8. Running a test compilation
pub async fn init_wizard(yes: bool, skip_test: bool, ctx: &OutputContext) -> Result<()> {
    use dialoguer::Confirm;

    let style = ctx.theme();

    println!();
    println!("{}", style.format_header("RCH First-Run Setup Wizard"));
    println!();
    println!(
        "  {} This wizard will help you set up RCH for remote compilation.",
        style.muted("→")
    );
    println!();

    // Step 1: Initialize configuration
    println!("{}", style.highlight("Step 1/8: Initialize configuration"));
    config_init(ctx, false, yes)?;
    println!();

    // Step 2: Discover workers
    println!(
        "{}",
        style.highlight("Step 2/8: Discover potential workers")
    );
    workers_discover(true, false, yes, ctx).await?;
    println!();

    // Step 3: Add discovered workers
    if !yes {
        let add_workers = Confirm::new()
            .with_prompt("Add discovered workers to configuration?")
            .default(true)
            .interact()
            .unwrap_or(false);

        if add_workers {
            workers_discover(false, true, false, ctx).await?;
        }
    } else {
        workers_discover(false, true, true, ctx).await?;
    }
    println!();

    // Step 4: Probe worker connectivity
    println!("{}", style.highlight("Step 4/8: Probe worker connectivity"));
    workers_probe(None, true, ctx).await?;
    println!();

    // Step 5: Deploy worker binary
    println!("{}", style.highlight("Step 5/8: Deploy worker binary"));
    let deploy = if yes {
        true
    } else {
        Confirm::new()
            .with_prompt("Deploy rch-wkr binary to workers?")
            .default(true)
            .interact()
            .unwrap_or(false)
    };
    if deploy {
        workers_deploy_binary(None, true, false, false, ctx).await?;
    }
    println!();

    // Step 6: Sync toolchain
    println!(
        "{}",
        style.highlight("Step 6/8: Synchronize Rust toolchain")
    );
    let sync_toolchain = if yes {
        true
    } else {
        Confirm::new()
            .with_prompt("Synchronize Rust toolchain to workers?")
            .default(true)
            .interact()
            .unwrap_or(false)
    };
    if sync_toolchain {
        workers_sync_toolchain(None, true, false, ctx).await?;
    }
    println!();

    // Step 7: Start daemon
    println!("{}", style.highlight("Step 7/8: Start daemon"));
    daemon_start(ctx).await?;
    println!();

    // Step 8: Install hook
    println!("{}", style.highlight("Step 8/8: Install Claude Code hook"));
    hook::hook_install(ctx)?;
    println!();

    // Optional: Test compilation
    if !skip_test {
        println!("{}", style.highlight("Bonus: Test compilation"));
        let run_test = if yes {
            true
        } else {
            Confirm::new()
                .with_prompt("Run a test compilation?")
                .default(true)
                .interact()
                .unwrap_or(false)
        };
        if run_test {
            hook::hook_test(ctx).await?;
        }
        println!();
    }

    // Summary
    println!("{}", style.format_success("Setup complete!"));
    println!();
    println!("{}", style.highlight("What's next:"));
    println!(
        "  {} Use Claude Code normally - compilation will be offloaded",
        style.muted("•")
    );
    println!(
        "  {} Monitor with: {}",
        style.muted("•"),
        style.info("rch status --workers --jobs")
    );
    println!(
        "  {} Check health with: {}",
        style.muted("•"),
        style.info("rch doctor")
    );

    Ok(())
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::helpers::{
        default_socket_path, extract_version_numbers, indent_lines, major_minor_version,
        major_version, major_version_mismatch, runtime_label, rust_version_mismatch,
        urlencoding_encode,
    };
    use super::status::{build_diagnose_decision, build_dry_run_summary};
    use super::*;
    use crate::status_types::format_bytes;
    use crate::ui::context::{OutputConfig, OutputMode};
    use crate::ui::writer::SharedOutputBuffer;
    use rch_common::test_guard;
    use rch_common::{Classification, CompilationKind, RequiredRuntime, WorkerId};
    use rch_common::{SelectedWorker, SelectionReason};

    struct TestConfigDirGuard;

    impl TestConfigDirGuard {
        fn new(path: PathBuf) -> Self {
            set_test_config_dir_override(Some(path));
            Self
        }
    }

    impl Drop for TestConfigDirGuard {
        fn drop(&mut self) {
            set_test_config_dir_override(None);
        }
    }

    fn json_test_context() -> (OutputContext, SharedOutputBuffer) {
        let stdout_buf = SharedOutputBuffer::new();
        let stderr_buf = SharedOutputBuffer::new();
        let ctx = OutputContext::with_writers(
            OutputConfig {
                force_mode: Some(OutputMode::Json),
                ..Default::default()
            },
            stdout_buf.as_writer(false),
            stderr_buf.as_writer(false),
        );
        (ctx, stdout_buf)
    }

    // -------------------------------------------------------------------------
    // ApiResponse Tests
    // -------------------------------------------------------------------------

    #[test]
    fn api_response_ok_creates_success_response() {
        let _guard = test_guard!();
        let response = ApiResponse::ok("test cmd", "test data".to_string());
        assert!(response.success);
        assert_eq!(response.command, Some("test cmd".to_string()));
        assert_eq!(response.api_version, "1.0");
        assert!(response.data.is_some());
        assert_eq!(response.data.unwrap(), "test data");
        assert!(response.error.is_none());
    }

    #[test]
    fn api_response_err_creates_error_response() {
        let _guard = test_guard!();
        let response: ApiResponse<()> =
            ApiResponse::err("failed cmd", ApiError::internal("error message"));
        assert!(!response.success);
        assert_eq!(response.command, Some("failed cmd".to_string()));
        assert!(response.data.is_none());
        assert!(response.error.is_some());
        let error = response.error.unwrap();
        assert_eq!(error.code, "RCH-E504"); // InternalStateError
    }

    #[test]
    fn api_response_err_with_specific_error_code() {
        let _guard = test_guard!();
        let response: ApiResponse<()> = ApiResponse::err(
            "cmd",
            ApiError::new(ErrorCode::SshConnectionFailed, "Worker not available"),
        );
        assert!(!response.success);
        assert!(response.error.is_some());
        let error = response.error.unwrap();
        assert_eq!(error.code, "RCH-E100"); // SshConnectionFailed
    }

    #[test]
    fn api_response_ok_serializes_without_error_field() {
        let _guard = test_guard!();
        let response = ApiResponse::ok("test", "data".to_string());
        let json = serde_json::to_value(&response).unwrap();
        assert!(json.get("error").is_none());
        assert_eq!(json["data"], "data");
        assert!(json["success"].as_bool().unwrap());
    }

    #[test]
    fn api_response_err_serializes_without_data_field() {
        let _guard = test_guard!();
        let response: ApiResponse<String> =
            ApiResponse::err("test", ApiError::internal("error msg"));
        let json = serde_json::to_value(&response).unwrap();
        assert!(json.get("data").is_none());
        assert!(json.get("error").is_some());
        assert!(!json["success"].as_bool().unwrap());
    }

    #[test]
    fn api_response_with_complex_data_serializes() {
        let _guard = test_guard!();
        #[derive(Serialize)]
        struct ComplexData {
            name: String,
            count: u32,
            items: Vec<String>,
        }
        let data = ComplexData {
            name: "test".to_string(),
            count: 3,
            items: vec!["a".to_string(), "b".to_string()],
        };
        let response = ApiResponse::ok("complex", data);
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["data"]["name"], "test");
        assert_eq!(json["data"]["count"], 3);
        assert_eq!(json["data"]["items"].as_array().unwrap().len(), 2);
    }

    // -------------------------------------------------------------------------
    // Config / Workers IO Tests (coverage)
    // -------------------------------------------------------------------------

    #[test]
    fn config_init_simple_json_creates_files() {
        let _guard = test_guard!();
        let temp_dir = tempfile::tempdir().expect("temp dir should be creatable");
        let _cfg_guard = TestConfigDirGuard::new(temp_dir.path().to_path_buf());

        let (ctx, stdout_buf) = json_test_context();
        config_init(&ctx, false, true).expect("config init should succeed");

        assert!(temp_dir.path().join("config.toml").exists());
        assert!(temp_dir.path().join("workers.toml").exists());

        let value: serde_json::Value =
            serde_json::from_str(&stdout_buf.to_string_lossy()).expect("json output");
        assert_eq!(value["success"], true);
        assert_eq!(value["command"], "config init");
        assert_eq!(value["data"]["created"].as_array().unwrap().len(), 2);
        assert_eq!(
            value["data"]["already_existed"].as_array().unwrap().len(),
            0
        );
    }

    #[test]
    fn config_init_simple_json_reports_existing_files() {
        let _guard = test_guard!();
        let temp_dir = tempfile::tempdir().expect("temp dir should be creatable");
        let _cfg_guard = TestConfigDirGuard::new(temp_dir.path().to_path_buf());

        let (ctx1, _stdout_buf1) = json_test_context();
        config_init(&ctx1, false, true).expect("first config init should succeed");

        let (ctx2, stdout_buf2) = json_test_context();
        config_init(&ctx2, false, true).expect("second config init should succeed");

        let value: serde_json::Value =
            serde_json::from_str(&stdout_buf2.to_string_lossy()).expect("json output");
        assert_eq!(value["success"], true);
        assert_eq!(value["command"], "config init");
        assert_eq!(value["data"]["created"].as_array().unwrap().len(), 0);
        assert_eq!(
            value["data"]["already_existed"].as_array().unwrap().len(),
            2
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn workers_list_json_uses_config_override() {
        let _guard = test_guard!();
        let temp_dir = tempfile::tempdir().expect("temp dir should be creatable");
        let _cfg_guard = TestConfigDirGuard::new(temp_dir.path().to_path_buf());

        // Seed example config files (includes one enabled worker)
        let (ctx, _stdout_buf) = json_test_context();
        config_init(&ctx, false, true).expect("config init should succeed");

        let (ctx2, stdout_buf2) = json_test_context();
        workers_list(false, &ctx2)
            .await
            .expect("workers list should succeed");

        let value: serde_json::Value =
            serde_json::from_str(&stdout_buf2.to_string_lossy()).expect("json output");
        assert_eq!(value["success"], true);
        assert_eq!(value["command"], "workers list");
        assert_eq!(value["data"]["count"], 1);
        assert_eq!(value["data"]["workers"][0]["id"], "worker1");
    }

    #[test]
    fn config_validate_json_success_with_example_files() {
        let _guard = test_guard!();
        let temp_dir = tempfile::tempdir().expect("temp dir should be creatable");
        let _cfg_guard = TestConfigDirGuard::new(temp_dir.path().to_path_buf());

        let (ctx1, _stdout_buf1) = json_test_context();
        config_init(&ctx1, false, true).expect("config init should succeed");

        let (ctx2, stdout_buf2) = json_test_context();
        config_validate(&ctx2).expect("config validate should succeed");

        let value: serde_json::Value =
            serde_json::from_str(&stdout_buf2.to_string_lossy()).expect("json output");
        assert_eq!(value["success"], true);
        assert_eq!(value["command"], "config validate");
        assert_eq!(value["data"]["valid"], true);
        assert_eq!(value["data"]["errors"].as_array().unwrap().len(), 0);
    }

    // -------------------------------------------------------------------------
    // WorkerInfo Tests
    // -------------------------------------------------------------------------

    #[test]
    fn worker_info_from_worker_config_converts_all_fields() {
        let _guard = test_guard!();
        let config = WorkerConfig {
            id: WorkerId::new("test-worker"),
            host: "192.168.1.100".to_string(),
            user: "admin".to_string(),
            identity_file: "~/.ssh/key.pem".to_string(),
            total_slots: 16,
            priority: 50,
            tags: vec!["fast".to_string(), "ssd".to_string()],
        };
        let info = WorkerInfo::from(&config);
        assert_eq!(info.id, "test-worker");
        assert_eq!(info.host, "192.168.1.100");
        assert_eq!(info.user, "admin");
        assert_eq!(info.total_slots, 16);
        assert_eq!(info.priority, 50);
        assert_eq!(info.tags, vec!["fast", "ssd"]);
    }

    #[test]
    fn worker_info_from_worker_config_with_empty_tags() {
        let _guard = test_guard!();
        let config = WorkerConfig {
            id: WorkerId::new("minimal"),
            host: "host.example.com".to_string(),
            user: "ubuntu".to_string(),
            identity_file: "~/.ssh/id_rsa".to_string(),
            total_slots: 8,
            priority: 100,
            tags: vec![],
        };
        let info = WorkerInfo::from(&config);
        assert!(info.tags.is_empty());
    }

    #[test]
    fn worker_info_serializes_correctly() {
        let _guard = test_guard!();
        let config = WorkerConfig {
            id: WorkerId::new("w1"),
            host: "host".to_string(),
            user: "user".to_string(),
            identity_file: "key".to_string(),
            total_slots: 4,
            priority: 75,
            tags: vec!["gpu".to_string()],
        };
        let info = WorkerInfo::from(&config);
        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(json["id"], "w1");
        assert_eq!(json["host"], "host");
        assert_eq!(json["total_slots"], 4);
        assert_eq!(json["tags"].as_array().unwrap().len(), 1);
    }

    // -------------------------------------------------------------------------
    // Response Types Tests
    // -------------------------------------------------------------------------

    #[test]
    fn workers_list_response_serializes() {
        let _guard = test_guard!();
        let response = WorkersListResponse {
            workers: vec![],
            count: 0,
        };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["count"], 0);
        assert!(json["workers"].as_array().unwrap().is_empty());
    }

    #[test]
    fn workers_list_response_with_workers_serializes() {
        let _guard = test_guard!();
        let workers = vec![
            WorkerInfo {
                id: "w1".to_string(),
                host: "host1".to_string(),
                user: "u1".to_string(),
                total_slots: 8,
                priority: 100,
                tags: vec![],
                speedscore: None,
            },
            WorkerInfo {
                id: "w2".to_string(),
                host: "host2".to_string(),
                user: "u2".to_string(),
                total_slots: 16,
                priority: 50,
                tags: vec!["fast".to_string()],
                speedscore: Some(85.5),
            },
        ];
        let response = WorkersListResponse { workers, count: 2 };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["count"], 2);
        let workers_arr = json["workers"].as_array().unwrap();
        assert_eq!(workers_arr.len(), 2);
        assert_eq!(workers_arr[0]["id"], "w1");
        assert_eq!(workers_arr[1]["id"], "w2");
    }

    #[test]
    fn worker_probe_result_success_serializes() {
        let _guard = test_guard!();
        let result = WorkerProbeResult {
            id: "worker1".to_string(),
            host: "192.168.1.1".to_string(),
            status: "healthy".to_string(),
            latency_ms: Some(42),
            error: None,
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["id"], "worker1");
        assert_eq!(json["status"], "healthy");
        assert_eq!(json["latency_ms"], 42);
        assert!(json.get("error").is_none()); // skipped when None
    }

    #[test]
    fn worker_probe_result_failure_serializes() {
        let _guard = test_guard!();
        let result = WorkerProbeResult {
            id: "worker2".to_string(),
            host: "192.168.1.2".to_string(),
            status: "unreachable".to_string(),
            latency_ms: None,
            error: Some("Connection refused".to_string()),
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["status"], "unreachable");
        assert!(json.get("latency_ms").is_none()); // skipped when None
        assert_eq!(json["error"], "Connection refused");
    }

    #[test]
    fn daemon_status_response_running_serializes() {
        let _guard = test_guard!();
        let response = DaemonStatusResponse {
            running: true,
            socket_path: "/tmp/rch.sock".to_string(),
            uptime_seconds: Some(3600),
        };
        let json = serde_json::to_value(&response).unwrap();
        assert!(json["running"].as_bool().unwrap());
        assert_eq!(json["socket_path"], "/tmp/rch.sock");
        assert_eq!(json["uptime_seconds"], 3600);
    }

    #[test]
    fn daemon_status_response_not_running_serializes() {
        let _guard = test_guard!();
        let response = DaemonStatusResponse {
            running: false,
            socket_path: "/tmp/rch.sock".to_string(),
            uptime_seconds: None,
        };
        let json = serde_json::to_value(&response).unwrap();
        assert!(!json["running"].as_bool().unwrap());
        assert!(json.get("uptime_seconds").is_none());
    }

    #[test]
    fn system_overview_serializes() {
        let _guard = test_guard!();
        let response = SystemOverview {
            daemon_running: true,
            hook_installed: true,
            workers_count: 3,
            workers: None,
        };
        let json = serde_json::to_value(&response).unwrap();
        assert!(json["daemon_running"].as_bool().unwrap());
        assert!(json["hook_installed"].as_bool().unwrap());
        assert_eq!(json["workers_count"], 3);
        assert!(json.get("workers").is_none());
    }

    #[test]
    fn config_show_response_serializes() {
        let _guard = test_guard!();
        let response = ConfigShowResponse {
            general: ConfigGeneralSection {
                enabled: true,
                force_local: false,
                force_remote: false,
                log_level: "info".to_string(),
                socket_path: "/tmp/rch.sock".to_string(),
            },
            compilation: ConfigCompilationSection {
                confidence_threshold: 0.85,
                min_local_time_ms: 2000,
            },
            transfer: ConfigTransferSection {
                compression_level: 3,
                exclude_patterns: vec!["target/".to_string()],
                remote_base: "/tmp/rch".to_string(),
                max_transfer_mb: None,
                max_transfer_time_ms: None,
                bwlimit_kbps: None,
                estimated_bandwidth_bps: None,
                adaptive_compression: false,
                min_compression_level: 1,
                max_compression_level: 19,
                verify_artifacts: false,
                verify_max_size_bytes: 100 * 1024 * 1024,
            },
            environment: ConfigEnvironmentSection {
                allowlist: vec!["RUSTFLAGS".to_string()],
            },
            circuit: ConfigCircuitSection {
                failure_threshold: 3,
                success_threshold: 2,
                error_rate_threshold: 0.5,
                window_secs: 60,
                open_cooldown_secs: 30,
                half_open_max_probes: 2,
            },
            output: ConfigOutputSection {
                visibility: rch_common::OutputVisibility::None,
                first_run_complete: false,
            },
            self_healing: ConfigSelfHealingSection {
                hook_starts_daemon: true,
                daemon_installs_hooks: true,
                auto_start_cooldown_secs: 30,
                auto_start_timeout_secs: 3,
            },
            sources: vec!["~/.config/rch/config.toml".to_string()],
            value_sources: None,
        };
        let json = serde_json::to_value(&response).unwrap();
        assert!(json["general"]["enabled"].as_bool().unwrap());
        assert_eq!(json["compilation"]["confidence_threshold"], 0.85);
        assert_eq!(json["transfer"]["compression_level"], 3);
        assert_eq!(json["circuit"]["failure_threshold"], 3);
    }

    #[test]
    fn config_init_response_serializes() {
        let _guard = test_guard!();
        let response = ConfigInitResponse {
            created: vec!["config.toml".to_string()],
            already_existed: vec!["workers.toml".to_string()],
        };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["created"].as_array().unwrap().len(), 1);
        assert_eq!(json["already_existed"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn config_validation_response_valid_serializes() {
        let _guard = test_guard!();
        let response = ConfigValidationResponse {
            errors: vec![],
            warnings: vec![],
            valid: true,
        };
        let json = serde_json::to_value(&response).unwrap();
        assert!(json["valid"].as_bool().unwrap());
        assert!(json["errors"].as_array().unwrap().is_empty());
    }

    #[test]
    fn config_validation_response_with_issues_serializes() {
        let _guard = test_guard!();
        let response = ConfigValidationResponse {
            errors: vec![ConfigValidationIssue {
                file: "config.toml".to_string(),
                message: "Invalid syntax".to_string(),
            }],
            warnings: vec![ConfigValidationIssue {
                file: "workers.toml".to_string(),
                message: "Deprecated field".to_string(),
            }],
            valid: false,
        };
        let json = serde_json::to_value(&response).unwrap();
        assert!(!json["valid"].as_bool().unwrap());
        assert_eq!(json["errors"][0]["message"], "Invalid syntax");
        assert_eq!(json["warnings"][0]["file"], "workers.toml");
    }

    #[test]
    fn config_set_response_serializes() {
        let _guard = test_guard!();
        let response = ConfigSetResponse {
            key: "general.log_level".to_string(),
            value: "debug".to_string(),
            config_path: "/home/user/.config/rch/config.toml".to_string(),
        };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["key"], "general.log_level");
        assert_eq!(json["value"], "debug");
    }

    #[test]
    fn config_export_response_serializes() {
        let _guard = test_guard!();
        let response = ConfigExportResponse {
            format: "toml".to_string(),
            content: "[general]\nenabled = true".to_string(),
        };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["format"], "toml");
        assert!(json["content"].as_str().unwrap().contains("enabled"));
    }

    #[test]
    fn diagnose_decision_intercepts_when_confident() {
        let _guard = test_guard!();
        let classification =
            Classification::compilation(CompilationKind::CargoBuild, 0.95, "cargo build");
        let decision = build_diagnose_decision(&classification, 0.85);
        assert!(decision.would_intercept);
        // New format: "Compilation command with confidence 0.95 >= threshold 0.85"
        assert!(decision.reason.contains(">=") || decision.reason.contains("threshold"));
    }

    #[test]
    fn diagnose_decision_rejects_when_below_threshold() {
        let _guard = test_guard!();
        let classification =
            Classification::compilation(CompilationKind::CargoCheck, 0.80, "cargo check");
        let decision = build_diagnose_decision(&classification, 0.85);
        assert!(!decision.would_intercept);
        assert!(decision.reason.contains("below threshold"));
    }

    #[test]
    fn diagnose_response_serializes() {
        let _guard = test_guard!();
        let classification =
            Classification::compilation(CompilationKind::CargoBuild, 0.95, "cargo build");
        let response = DiagnoseResponse {
            classification,
            tiers: Vec::new(),
            command: "cargo build".to_string(),
            normalized_command: "cargo build".to_string(),
            decision: DiagnoseDecision {
                would_intercept: true,
                reason: "meets confidence threshold".to_string(),
            },
            threshold: DiagnoseThreshold {
                value: 0.85,
                source: "default".to_string(),
            },
            daemon: DiagnoseDaemonStatus {
                socket_path: "/tmp/rch.sock".to_string(),
                socket_exists: false,
                reachable: false,
                status: None,
                version: None,
                uptime_seconds: None,
                error: Some("daemon socket not found".to_string()),
            },
            required_runtime: RequiredRuntime::Rust,
            local_capabilities: None,
            capabilities_warnings: Vec::new(),
            worker_selection: None,
            dry_run: None,
        };

        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["command"], "cargo build");
        assert_eq!(json["classification"]["confidence"], 0.95);
        assert_eq!(json["threshold"]["value"], 0.85);
    }

    #[test]
    fn workers_capabilities_report_serializes_with_local() {
        let _guard = test_guard!();
        let report = WorkersCapabilitiesReport {
            workers: vec![],
            local: Some(WorkerCapabilities {
                rustc_version: Some("rustc 1.87.0-nightly".to_string()),
                bun_version: None,
                node_version: None,
                npm_version: None,
                ..Default::default()
            }),
            required_runtime: Some(RequiredRuntime::Rust),
            warnings: vec!["warn".to_string()],
        };
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["local"]["rustc_version"], "rustc 1.87.0-nightly");
        assert_eq!(json["required_runtime"], "rust");
        assert!(json["warnings"].is_array());
    }

    #[test]
    fn local_capability_warnings_include_missing_and_mismatch() {
        let _guard = test_guard!();
        let local = WorkerCapabilities {
            rustc_version: Some("rustc 1.87.0-nightly".to_string()),
            bun_version: None,
            node_version: None,
            npm_version: None,
            ..Default::default()
        };
        let workers = vec![
            WorkerCapabilitiesFromApi {
                id: "w-missing".to_string(),
                host: "host".to_string(),
                user: "user".to_string(),
                capabilities: WorkerCapabilities::new(),
            },
            WorkerCapabilitiesFromApi {
                id: "w-old".to_string(),
                host: "host".to_string(),
                user: "user".to_string(),
                capabilities: WorkerCapabilities {
                    rustc_version: Some("rustc 1.86.0-nightly".to_string()),
                    bun_version: None,
                    node_version: None,
                    npm_version: None,
                    ..Default::default()
                },
            },
        ];
        let warnings = collect_local_capability_warnings(&workers, &local);
        assert!(warnings.iter().any(|w| w.contains("missing Rust runtime")));
        assert!(warnings.iter().any(|w| w.contains("Rust version mismatch")));
    }

    #[test]
    fn hook_action_response_success_serializes() {
        let _guard = test_guard!();
        let response = HookActionResponse {
            action: "install".to_string(),
            success: true,
            settings_path: "~/.config/claude-code/settings.json".to_string(),
            message: Some("Hook installed successfully".to_string()),
        };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["action"], "install");
        assert!(json["success"].as_bool().unwrap());
        assert_eq!(json["message"], "Hook installed successfully");
    }

    #[test]
    fn hook_action_response_without_message_serializes() {
        let _guard = test_guard!();
        let response = HookActionResponse {
            action: "uninstall".to_string(),
            success: true,
            settings_path: "path".to_string(),
            message: None,
        };
        let json = serde_json::to_value(&response).unwrap();
        assert!(json.get("message").is_none());
    }

    #[test]
    fn hook_test_response_serializes() {
        let _guard = test_guard!();
        let response = HookTestResponse {
            classification_tests: vec![ClassificationTestResult {
                command: "cargo build".to_string(),
                is_compilation: true,
                confidence: 0.95,
                expected_intercept: true,
                passed: true,
            }],
            daemon_connected: true,
            daemon_response: Some("OK".to_string()),
            workers_configured: 2,
            workers: vec![],
        };
        let json = serde_json::to_value(&response).unwrap();
        assert!(json["daemon_connected"].as_bool().unwrap());
        assert_eq!(json["workers_configured"], 2);
        let tests = json["classification_tests"].as_array().unwrap();
        assert_eq!(tests[0]["command"], "cargo build");
        assert!(tests[0]["passed"].as_bool().unwrap());
    }

    #[test]
    fn classification_test_result_serializes() {
        let _guard = test_guard!();
        let result = ClassificationTestResult {
            command: "bun test".to_string(),
            is_compilation: true,
            confidence: 0.92,
            expected_intercept: true,
            passed: true,
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["command"], "bun test");
        assert!(json["is_compilation"].as_bool().unwrap());
        assert_eq!(json["confidence"], 0.92);
    }

    // -------------------------------------------------------------------------
    // ErrorCode Tests
    // -------------------------------------------------------------------------

    #[test]
    fn error_code_codes_have_rch_prefix() {
        let _guard = test_guard!();
        // Verify error codes follow RCH-Exxx format
        assert_eq!(ErrorCode::ConfigNotFound.code_string(), "RCH-E001");
        assert_eq!(ErrorCode::ConfigValidationError.code_string(), "RCH-E004");
        assert_eq!(ErrorCode::ConfigInvalidWorker.code_string(), "RCH-E008");
        assert_eq!(ErrorCode::SshConnectionFailed.code_string(), "RCH-E100");
        assert_eq!(
            ErrorCode::InternalDaemonNotRunning.code_string(),
            "RCH-E502"
        );
        assert_eq!(ErrorCode::InternalStateError.code_string(), "RCH-E504");
    }

    // -------------------------------------------------------------------------
    // config_dir Tests
    // -------------------------------------------------------------------------

    #[test]
    fn config_dir_returns_some() {
        let _guard = test_guard!();
        // config_dir should return a path on most systems
        let dir = config_dir();
        // We can't guarantee it returns Some on all systems, but if it does,
        // it should be a valid path that ends with "rch"
        if let Some(path) = dir {
            assert!(path.to_string_lossy().contains("rch"));
        }
    }

    // -------------------------------------------------------------------------
    // API_VERSION Tests
    // -------------------------------------------------------------------------

    #[test]
    fn api_version_is_expected_value() {
        let _guard = test_guard!();
        assert_eq!(rch_common::API_VERSION, "1.0");
    }

    // -------------------------------------------------------------------------
    // default_socket_path Tests
    // -------------------------------------------------------------------------

    #[test]
    fn default_socket_path_returns_valid_path() {
        let _guard = test_guard!();
        let path = default_socket_path();
        // Should end with rch.sock regardless of prefix
        assert!(
            path.ends_with("rch.sock"),
            "Socket path should end with rch.sock, got: {}",
            path
        );
        // Should be an absolute path
        assert!(
            path.starts_with('/'),
            "Socket path should be absolute, got: {}",
            path
        );
    }

    // -------------------------------------------------------------------------
    // Dry Run Summary Tests
    // -------------------------------------------------------------------------

    #[test]
    fn dry_run_summary_not_intercepted() {
        let _guard = test_guard!();
        let summary = build_dry_run_summary(false, "not a compilation command", &None, false);
        assert!(!summary.would_offload);
        assert_eq!(summary.reason, "not a compilation command");
        // Non-intercepted commands get single "Local execution" step
        assert_eq!(summary.pipeline_steps.len(), 1);
        assert_eq!(summary.pipeline_steps[0].name, "Local execution");
        assert!(!summary.pipeline_steps[0].skipped);
    }

    #[test]
    fn dry_run_summary_intercepted_no_daemon() {
        let _guard = test_guard!();
        let summary = build_dry_run_summary(
            true,
            "meets confidence threshold",
            &None,
            false, // daemon not reachable
        );
        // With no worker selection and daemon not reachable, would_offload is still true
        // because the function returns optimistic summary
        assert!(summary.would_offload);
        assert!(summary.reason.contains("worker available"));
        // Intercepted commands have 6 pipeline steps
        assert_eq!(summary.pipeline_steps.len(), 6);
        // Classification step should run
        assert!(!summary.pipeline_steps[0].skipped);
        assert_eq!(summary.pipeline_steps[0].name, "Classification");
        // Daemon query should be skipped (daemon not reachable)
        assert!(summary.pipeline_steps[1].skipped);
        assert_eq!(summary.pipeline_steps[1].name, "Daemon query");
    }

    #[test]
    fn dry_run_summary_intercepted_with_worker() {
        let _guard = test_guard!();
        let worker = SelectedWorker {
            id: WorkerId::new("test-worker"),
            host: "worker.example.com".to_string(),
            user: "rch".to_string(),
            identity_file: "~/.ssh/id_rsa".to_string(),
            slots_available: 4,
            speed_score: 1.5,
        };
        let worker_selection = DiagnoseWorkerSelection {
            estimated_cores: 4,
            worker: Some(worker),
            reason: SelectionReason::Success,
        };
        let summary = build_dry_run_summary(
            true,
            "meets confidence threshold",
            &Some(worker_selection),
            true, // daemon reachable
        );
        assert!(summary.would_offload);
        assert!(summary.reason.contains("worker available"));
        // Intercepted commands have 6 pipeline steps
        assert_eq!(summary.pipeline_steps.len(), 6);
        // All steps should run (not skipped) when worker is selected
        for step in &summary.pipeline_steps {
            assert!(!step.skipped, "Step {} should not be skipped", step.name);
        }
    }

    #[test]
    fn dry_run_pipeline_step_serializes() {
        let _guard = test_guard!();
        let step = DryRunPipelineStep {
            step: 1,
            name: "classify".to_string(),
            description: "Analyze command".to_string(),
            skipped: false,
            skip_reason: None,
            estimated_duration_ms: Some(2),
        };
        let json = serde_json::to_value(&step).unwrap();
        assert_eq!(json["step"], 1);
        assert_eq!(json["name"], "classify");
        assert_eq!(json["skipped"], false);
        assert_eq!(json["estimated_duration_ms"], 2);
        assert!(json.get("skip_reason").is_none());
    }

    #[test]
    fn dry_run_pipeline_step_skipped_serializes() {
        let _guard = test_guard!();
        let step = DryRunPipelineStep {
            step: 2,
            name: "select".to_string(),
            description: "Select worker".to_string(),
            skipped: true,
            skip_reason: Some("daemon not reachable".to_string()),
            estimated_duration_ms: None,
        };
        let json = serde_json::to_value(&step).unwrap();
        assert_eq!(json["skipped"], true);
        assert_eq!(json["skip_reason"], "daemon not reachable");
        assert!(json.get("estimated_duration_ms").is_none());
    }

    #[test]
    fn dry_run_transfer_estimate_serializes() {
        let _guard = test_guard!();
        let estimate = DryRunTransferEstimate {
            bytes: 1024 * 1024 * 10, // 10 MB
            human_size: "10.00 MB".to_string(),
            files: 150,
            estimated_time_ms: 2500,
            would_skip: false,
            skip_reason: None,
        };
        let json = serde_json::to_value(&estimate).unwrap();
        assert_eq!(json["bytes"], 10485760);
        assert_eq!(json["human_size"], "10.00 MB");
        assert_eq!(json["files"], 150);
        assert_eq!(json["estimated_time_ms"], 2500);
        assert_eq!(json["would_skip"], false);
    }

    #[test]
    fn dry_run_transfer_estimate_would_skip_serializes() {
        let _guard = test_guard!();
        let estimate = DryRunTransferEstimate {
            bytes: 1024 * 1024 * 500, // 500 MB
            human_size: "500.00 MB".to_string(),
            files: 5000,
            estimated_time_ms: 60000,
            would_skip: true,
            skip_reason: Some("exceeds max_transfer_mb threshold".to_string()),
        };
        let json = serde_json::to_value(&estimate).unwrap();
        assert_eq!(json["would_skip"], true);
        assert_eq!(json["skip_reason"], "exceeds max_transfer_mb threshold");
    }

    #[test]
    fn dry_run_summary_serializes() {
        let _guard = test_guard!();
        let summary = DryRunSummary {
            would_offload: true,
            reason: "compilation command meets threshold".to_string(),
            pipeline_steps: vec![DryRunPipelineStep {
                step: 1,
                name: "classify".to_string(),
                description: "Analyze command".to_string(),
                skipped: false,
                skip_reason: None,
                estimated_duration_ms: Some(2),
            }],
            transfer_estimate: None,
            total_estimated_ms: Some(100),
        };
        let json = serde_json::to_value(&summary).unwrap();
        assert_eq!(json["would_offload"], true);
        assert_eq!(json["reason"], "compilation command meets threshold");
        assert_eq!(json["pipeline_steps"].as_array().unwrap().len(), 1);
        assert_eq!(json["total_estimated_ms"], 100);
    }

    #[test]
    fn format_bytes_basic() {
        let _guard = test_guard!();
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1024 * 1024), "1.0 MB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.0 GB");
    }

    #[test]
    fn format_bytes_fractional() {
        let _guard = test_guard!();
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(1024 * 1024 + 512 * 1024), "1.5 MB");
    }

    // -------------------------------------------------------------------------
    // runtime_label Tests
    // -------------------------------------------------------------------------

    #[test]
    fn runtime_label_rust() {
        let _guard = test_guard!();
        assert_eq!(runtime_label(&RequiredRuntime::Rust), "rust");
    }

    #[test]
    fn runtime_label_bun() {
        let _guard = test_guard!();
        assert_eq!(runtime_label(&RequiredRuntime::Bun), "bun");
    }

    #[test]
    fn runtime_label_node() {
        let _guard = test_guard!();
        assert_eq!(runtime_label(&RequiredRuntime::Node), "node");
    }

    #[test]
    fn runtime_label_none() {
        let _guard = test_guard!();
        assert_eq!(runtime_label(&RequiredRuntime::None), "none");
    }

    // -------------------------------------------------------------------------
    // has_any_capabilities Tests
    // -------------------------------------------------------------------------

    #[test]
    fn has_any_capabilities_empty() {
        let _guard = test_guard!();
        let caps = WorkerCapabilities::new();
        assert!(!has_any_capabilities(&caps));
    }

    #[test]
    fn has_any_capabilities_with_rust() {
        let _guard = test_guard!();
        let caps = WorkerCapabilities {
            rustc_version: Some("rustc 1.87.0".to_string()),
            ..Default::default()
        };
        assert!(has_any_capabilities(&caps));
    }

    #[test]
    fn has_any_capabilities_with_bun() {
        let _guard = test_guard!();
        let caps = WorkerCapabilities {
            bun_version: Some("1.2.3".to_string()),
            ..Default::default()
        };
        assert!(has_any_capabilities(&caps));
    }

    #[test]
    fn has_any_capabilities_with_node() {
        let _guard = test_guard!();
        let caps = WorkerCapabilities {
            node_version: Some("v20.0.0".to_string()),
            ..Default::default()
        };
        assert!(has_any_capabilities(&caps));
    }

    #[test]
    fn has_any_capabilities_with_npm() {
        let _guard = test_guard!();
        let caps = WorkerCapabilities {
            npm_version: Some("10.0.0".to_string()),
            ..Default::default()
        };
        assert!(has_any_capabilities(&caps));
    }

    #[test]
    fn has_any_capabilities_with_all() {
        let _guard = test_guard!();
        let caps = WorkerCapabilities {
            rustc_version: Some("rustc 1.87.0".to_string()),
            bun_version: Some("1.2.3".to_string()),
            node_version: Some("v20.0.0".to_string()),
            npm_version: Some("10.0.0".to_string()),
            ..Default::default()
        };
        assert!(has_any_capabilities(&caps));
    }

    // -------------------------------------------------------------------------
    // extract_version_numbers Tests
    // -------------------------------------------------------------------------

    #[test]
    fn extract_version_numbers_simple() {
        let _guard = test_guard!();
        assert_eq!(extract_version_numbers("1.2.3"), vec![1, 2, 3]);
    }

    #[test]
    fn extract_version_numbers_with_prefix() {
        let _guard = test_guard!();
        assert_eq!(
            extract_version_numbers("rustc 1.87.0-nightly"),
            vec![1, 87, 0]
        );
    }

    #[test]
    fn extract_version_numbers_node_format() {
        let _guard = test_guard!();
        assert_eq!(extract_version_numbers("v20.11.1"), vec![20, 11, 1]);
    }

    #[test]
    fn extract_version_numbers_empty() {
        let _guard = test_guard!();
        assert_eq!(extract_version_numbers(""), Vec::<u64>::new());
    }

    #[test]
    fn extract_version_numbers_no_numbers() {
        let _guard = test_guard!();
        assert_eq!(
            extract_version_numbers("no numbers here"),
            Vec::<u64>::new()
        );
    }

    #[test]
    fn extract_version_numbers_single() {
        let _guard = test_guard!();
        assert_eq!(extract_version_numbers("version 42"), vec![42]);
    }

    #[test]
    fn extract_version_numbers_large() {
        let _guard = test_guard!();
        assert_eq!(extract_version_numbers("2024.01.15"), vec![2024, 1, 15]);
    }

    // -------------------------------------------------------------------------
    // major_version Tests
    // -------------------------------------------------------------------------

    #[test]
    fn major_version_extracts_first() {
        let _guard = test_guard!();
        assert_eq!(major_version("rustc 1.87.0-nightly"), Some(1));
    }

    #[test]
    fn major_version_node() {
        let _guard = test_guard!();
        assert_eq!(major_version("v20.11.1"), Some(20));
    }

    #[test]
    fn major_version_empty() {
        let _guard = test_guard!();
        assert_eq!(major_version(""), None);
    }

    #[test]
    fn major_version_no_numbers() {
        let _guard = test_guard!();
        assert_eq!(major_version("no version"), None);
    }

    // -------------------------------------------------------------------------
    // major_minor_version Tests
    // -------------------------------------------------------------------------

    #[test]
    fn major_minor_version_extracts_both() {
        let _guard = test_guard!();
        assert_eq!(major_minor_version("rustc 1.87.0-nightly"), Some((1, 87)));
    }

    #[test]
    fn major_minor_version_node() {
        let _guard = test_guard!();
        assert_eq!(major_minor_version("v20.11.1"), Some((20, 11)));
    }

    #[test]
    fn major_minor_version_single_number() {
        let _guard = test_guard!();
        assert_eq!(major_minor_version("version 42"), None);
    }

    #[test]
    fn major_minor_version_empty() {
        let _guard = test_guard!();
        assert_eq!(major_minor_version(""), None);
    }

    // -------------------------------------------------------------------------
    // rust_version_mismatch Tests
    // -------------------------------------------------------------------------

    #[test]
    fn rust_version_mismatch_same_version() {
        let _guard = test_guard!();
        assert!(!rust_version_mismatch(
            "rustc 1.87.0-nightly",
            "rustc 1.87.0-nightly"
        ));
    }

    #[test]
    fn rust_version_mismatch_different_patch() {
        let _guard = test_guard!();
        // Same major.minor, different patch - should NOT be a mismatch
        assert!(!rust_version_mismatch("rustc 1.87.0", "rustc 1.87.1"));
    }

    #[test]
    fn rust_version_mismatch_different_minor() {
        let _guard = test_guard!();
        assert!(rust_version_mismatch("rustc 1.87.0", "rustc 1.86.0"));
    }

    #[test]
    fn rust_version_mismatch_different_major() {
        let _guard = test_guard!();
        assert!(rust_version_mismatch("rustc 1.87.0", "rustc 2.0.0"));
    }

    #[test]
    fn rust_version_mismatch_invalid_local() {
        let _guard = test_guard!();
        // If local can't be parsed, returns false (no mismatch detectable)
        assert!(!rust_version_mismatch("invalid", "rustc 1.87.0"));
    }

    #[test]
    fn rust_version_mismatch_invalid_remote() {
        let _guard = test_guard!();
        assert!(!rust_version_mismatch("rustc 1.87.0", "invalid"));
    }

    // -------------------------------------------------------------------------
    // major_version_mismatch Tests
    // -------------------------------------------------------------------------

    #[test]
    fn major_version_mismatch_same() {
        let _guard = test_guard!();
        assert!(!major_version_mismatch("bun 1.2.3", "bun 1.5.0"));
    }

    #[test]
    fn major_version_mismatch_different() {
        let _guard = test_guard!();
        assert!(major_version_mismatch("bun 1.2.3", "bun 2.0.0"));
    }

    #[test]
    fn major_version_mismatch_invalid_local() {
        let _guard = test_guard!();
        assert!(!major_version_mismatch("no version", "bun 1.2.3"));
    }

    #[test]
    fn major_version_mismatch_invalid_remote() {
        let _guard = test_guard!();
        assert!(!major_version_mismatch("bun 1.2.3", "no version"));
    }

    // -------------------------------------------------------------------------
    // summarize_capabilities Tests
    // -------------------------------------------------------------------------

    #[test]
    fn summarize_capabilities_empty() {
        let _guard = test_guard!();
        let caps = WorkerCapabilities::new();
        assert_eq!(summarize_capabilities(&caps), "unknown");
    }

    #[test]
    fn summarize_capabilities_rust_only() {
        let _guard = test_guard!();
        let caps = WorkerCapabilities {
            rustc_version: Some("rustc 1.87.0".to_string()),
            ..Default::default()
        };
        assert_eq!(summarize_capabilities(&caps), "rustc rustc 1.87.0");
    }

    #[test]
    fn summarize_capabilities_all() {
        let _guard = test_guard!();
        let caps = WorkerCapabilities {
            rustc_version: Some("1.87".to_string()),
            bun_version: Some("1.2".to_string()),
            node_version: Some("20.0".to_string()),
            npm_version: Some("10.0".to_string()),
            ..Default::default()
        };
        let result = summarize_capabilities(&caps);
        assert!(result.contains("rustc 1.87"));
        assert!(result.contains("bun 1.2"));
        assert!(result.contains("node 20.0"));
        assert!(result.contains("npm 10.0"));
    }

    // -------------------------------------------------------------------------
    // indent_lines Tests
    // -------------------------------------------------------------------------

    #[test]
    fn indent_lines_single() {
        let _guard = test_guard!();
        assert_eq!(indent_lines("hello", "  "), "  hello");
    }

    #[test]
    fn indent_lines_multiple() {
        let _guard = test_guard!();
        assert_eq!(indent_lines("a\nb\nc", ">> "), ">> a\n>> b\n>> c");
    }

    #[test]
    fn indent_lines_empty() {
        let _guard = test_guard!();
        // Empty string has no lines, so output is also empty
        assert_eq!(indent_lines("", "  "), "");
    }

    #[test]
    fn indent_lines_empty_prefix() {
        let _guard = test_guard!();
        assert_eq!(indent_lines("a\nb", ""), "a\nb");
    }

    // -------------------------------------------------------------------------
    // urlencoding_encode Tests
    // -------------------------------------------------------------------------

    #[test]
    fn urlencoding_encode_alphanumeric() {
        let _guard = test_guard!();
        assert_eq!(urlencoding_encode("abc123"), "abc123");
    }

    #[test]
    fn urlencoding_encode_safe_chars() {
        let _guard = test_guard!();
        assert_eq!(urlencoding_encode("a-b_c.d~e"), "a-b_c.d~e");
    }

    #[test]
    fn urlencoding_encode_spaces() {
        let _guard = test_guard!();
        assert_eq!(urlencoding_encode("hello world"), "hello%20world");
    }

    #[test]
    fn urlencoding_encode_special() {
        let _guard = test_guard!();
        assert_eq!(urlencoding_encode("a=b&c"), "a%3Db%26c");
    }

    #[test]
    fn urlencoding_encode_unicode() {
        let _guard = test_guard!();
        // Multi-byte UTF-8 characters should be percent-encoded
        let result = urlencoding_encode("hello\u{00E9}"); // é
        assert!(result.starts_with("hello%"));
        assert!(result.len() > 6); // Should be longer due to encoding
    }

    #[test]
    fn urlencoding_encode_empty() {
        let _guard = test_guard!();
        assert_eq!(urlencoding_encode(""), "");
    }

    // -------------------------------------------------------------------------
    // is_default_verify_size Tests
    // -------------------------------------------------------------------------

    #[test]
    fn is_default_verify_size_true() {
        let _guard = test_guard!();
        assert!(is_default_verify_size(&(100 * 1024 * 1024)));
    }

    #[test]
    fn is_default_verify_size_false() {
        let _guard = test_guard!();
        assert!(!is_default_verify_size(&0));
        assert!(!is_default_verify_size(&(50 * 1024 * 1024)));
    }
}
