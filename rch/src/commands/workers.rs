//! Worker management commands.
//!
//! This module contains commands for listing, probing, benchmarking, and managing
//! the worker fleet.

#[cfg(not(unix))]
use crate::error::PlatformError;
use anyhow::{Context, Result};
use rch_common::{
    ApiError, ApiResponse, ErrorCode, RequiredRuntime, WorkerCapabilities, WorkerConfig,
    classify_command_detailed,
};
#[cfg(unix)]
use rch_common::{SshClient, SshOptions};
use std::path::{Path, PathBuf};

use crate::status_types::{
    DaemonFullStatusResponse, SpeedScoreListResponseFromApi, WorkerCapabilitiesFromApi,
    WorkerCapabilitiesResponseFromApi, extract_json_body,
};
use crate::ui::context::OutputContext;
use crate::ui::progress::MultiProgressManager;
use crate::ui::theme::{StatusIndicator, Theme};
use tracing::debug;

use super::helpers::{
    classify_ssh_error, configured_socket_path, format_ssh_report, indent_lines,
    major_version_mismatch, runtime_label, rust_version_mismatch, send_daemon_command,
    ssh_error_code, urlencoding_encode,
};
use super::helpers::{config_dir, load_workers_from_config};
use super::types::{
    WorkerActionResponse, WorkerBenchmarkResult, WorkerInfo, WorkerProbeResult, WorkerProbeSummary,
    WorkersCapabilitiesReport, WorkersListResponse, WorkersProbeResponse,
};

use crate::hook::required_runtime_for_kind;

// =============================================================================
// Workers-Specific Helper Functions
// =============================================================================

pub(super) fn has_any_capabilities(capabilities: &WorkerCapabilities) -> bool {
    capabilities.rustc_version.is_some()
        || capabilities.bun_version.is_some()
        || capabilities.node_version.is_some()
        || capabilities.npm_version.is_some()
}

/// Probe local runtime capabilities by running version commands in parallel.
/// Uses tokio async to spawn all 4 version checks concurrently, reducing total
/// latency from ~200ms (sequential) to ~50ms (parallel).
pub(super) async fn probe_local_capabilities() -> WorkerCapabilities {
    fn rustc_version_command() -> tokio::process::Command {
        let mut command = tokio::process::Command::new("rustc");
        command.arg("--version");
        command
    }

    fn bun_version_command() -> tokio::process::Command {
        let mut command = tokio::process::Command::new("bun");
        command.arg("--version");
        command
    }

    fn node_version_command() -> tokio::process::Command {
        let mut command = tokio::process::Command::new("node");
        command.arg("--version");
        command
    }

    fn npm_version_command() -> tokio::process::Command {
        let mut command = tokio::process::Command::new("npm");
        command.arg("--version");
        command
    }

    async fn run_version(mut command: tokio::process::Command) -> Option<String> {
        let output = command.output().await.ok()?;
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
        run_version(rustc_version_command()),
        run_version(bun_version_command()),
        run_version(node_version_command()),
        run_version(npm_version_command()),
    );

    let mut caps = WorkerCapabilities::new();
    caps.rustc_version = rustc;
    caps.bun_version = bun;
    caps.node_version = node;
    caps.npm_version = npm;
    caps
}

pub(super) fn collect_local_capability_warnings(
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

fn workers_list_verbose_enabled(ctx: &OutputContext) -> bool {
    ctx.is_verbose() && !ctx.is_json()
}

fn render_worker_verbose_lines(
    worker: &WorkerConfig,
    daemon_status: Option<&DaemonFullStatusResponse>,
    style: &Theme,
) -> Vec<String> {
    let mut lines = Vec::new();

    if let Some(status) = daemon_status {
        if let Some(worker_status) = status.workers.iter().find(|w| w.id == worker.id.as_str()) {
            let circuit_display = match worker_status.circuit_state.as_str() {
                "closed" => style.success("Closed"),
                "half_open" => style.warning("HalfOpen"),
                "open" => style.error("Open"),
                other => style.muted(other),
            };
            lines.push(format!(
                "    {} {} {}",
                style.key("Circuit"),
                style.muted(":"),
                circuit_display
            ));

            let slots_display = if worker_status.used_slots > 0 {
                style.warning(&format!(
                    "{}/{}",
                    worker_status.used_slots, worker_status.total_slots
                ))
            } else {
                style.success(&format!(
                    "{}/{}",
                    worker_status.used_slots, worker_status.total_slots
                ))
            };
            lines.push(format!(
                "    {} {} {}",
                style.key("In Use"),
                style.muted(":"),
                slots_display
            ));

            let status_display = match worker_status.status.as_str() {
                "healthy" => style.success("Healthy"),
                "degraded" => style.warning("Degraded"),
                "unreachable" => style.error("Unreachable"),
                "draining" => style.warning("Draining"),
                "drained" => style.info("Drained"),
                "disabled" => style.muted("Disabled"),
                other => style.muted(other),
            };
            lines.push(format!(
                "    {} {} {}",
                style.key("Status"),
                style.muted(":"),
                status_display
            ));

            if let Some(ref last_error) = worker_status.last_error {
                lines.push(format!(
                    "    {} {} {}",
                    style.key("LastErr"),
                    style.muted(":"),
                    style.error(last_error)
                ));
            }

            if let Some(recovery_secs) = worker_status.recovery_in_secs {
                lines.push(format!(
                    "    {} {} {}s",
                    style.key("Recover"),
                    style.muted(":"),
                    style.info(&recovery_secs.to_string())
                ));
            }
        } else {
            lines.push(format!(
                "    {} {}",
                style.muted("Live status:"),
                style.muted("(not in daemon)")
            ));
        }
    } else {
        lines.push(format!(
            "    {} {}",
            style.muted("Live status:"),
            style.muted("(daemon not running)")
        ));
    }

    lines.push(format!(
        "    {} {} {}",
        style.key("SSH Key"),
        style.muted(":"),
        style.muted(&worker.identity_file)
    ));

    lines
}

#[cfg(test)]
pub(super) fn summarize_capabilities(capabilities: &WorkerCapabilities) -> String {
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

/// Query the daemon for worker capabilities.
pub(super) async fn query_workers_capabilities(
    refresh: bool,
) -> Result<WorkerCapabilitiesResponseFromApi> {
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

/// Query the daemon for all worker SpeedScores.
async fn query_speedscore_list() -> Result<SpeedScoreListResponseFromApi> {
    let response = send_daemon_command("GET /speedscores\n").await?;
    let json = extract_json_body(&response)
        .ok_or_else(|| anyhow::anyhow!("Invalid response format from daemon"))?;
    let scores: SpeedScoreListResponseFromApi =
        serde_json::from_str(json).context("Failed to parse SpeedScore list response")?;
    Ok(scores)
}

// =============================================================================
// Workers Commands
// =============================================================================

/// List all configured workers.
pub async fn workers_list(show_speedscore: bool, ctx: &OutputContext) -> Result<()> {
    let workers = load_workers_from_config()?;
    let style = ctx.theme();

    // Fetch speedscores if requested
    let speedscores = if show_speedscore {
        query_speedscore_list().await.ok()
    } else {
        None
    };

    // In verbose mode, fetch live daemon status for circuit breaker state, slot usage, etc.
    let daemon_status = if workers_list_verbose_enabled(ctx) {
        debug!(target: "rch::verbose", "fetching daemon status for verbose workers list");
        match send_daemon_command("GET /status\n").await {
            Ok(response) => extract_json_body(&response)
                .and_then(|json| serde_json::from_str::<DaemonFullStatusResponse>(json).ok()),
            Err(_) => None,
        }
    } else {
        None
    };

    // JSON output mode
    if ctx.is_json() {
        let mut worker_infos: Vec<WorkerInfo> = workers.iter().map(WorkerInfo::from).collect();
        // Enrich with speedscore data if available
        if let Some(ref scores) = speedscores {
            for info in &mut worker_infos {
                if let Some(score_entry) = scores.workers.iter().find(|s| s.worker_id == info.id)
                    && let Some(ref score) = score_entry.speedscore
                {
                    info.speedscore = Some(score.total);
                }
            }
        }
        let response = WorkersListResponse {
            count: workers.len(),
            workers: worker_infos,
        };
        let _ = ctx.json(&ApiResponse::ok("workers list", response));
        return Ok(());
    }

    if workers.is_empty() {
        let config_path = config_dir()
            .map(|d| d.join("workers.toml"))
            .unwrap_or_else(|| PathBuf::from("~/.config/rch/workers.toml"));
        println!("  {} No workers configured.", style.symbols.info);
        println!();
        println!(
            "  Create a workers config at: {}",
            style.value(&config_path.display().to_string())
        );
        println!();
        println!(
            "  Run {} to generate example configuration.",
            style.highlight("rch config init")
        );
        return Ok(());
    }

    println!("{}", style.format_header("Configured Workers"));
    println!();

    for worker in &workers {
        println!(
            "  {} {} {}@{}",
            style.symbols.bullet_filled,
            style.highlight(worker.id.as_str()),
            style.muted(&worker.user),
            style.info(&worker.host)
        );

        // Base stats line
        let mut stats_line = format!(
            "    {} {} {}  {} {} {}",
            style.key("Slots"),
            style.muted(":"),
            style.value(&worker.total_slots.to_string()),
            style.key("Priority"),
            style.muted(":"),
            style.value(&worker.priority.to_string())
        );

        // Add SpeedScore if available
        if let Some(ref scores) = speedscores
            && let Some(score_entry) = scores
                .workers
                .iter()
                .find(|s| s.worker_id == worker.id.as_str())
            && let Some(ref score) = score_entry.speedscore
        {
            let score_color = match score.total {
                x if x >= 75.0 => style.success(&format!("{:.0}", x)),
                x if x >= 45.0 => style.warning(&format!("{:.0}", x)),
                x => style.error(&format!("{:.0}", x)),
            };
            stats_line.push_str(&format!(
                "  {} {} {}",
                style.key("Score"),
                style.muted(":"),
                score_color
            ));
        }

        println!("{}", stats_line);

        if !worker.tags.is_empty() {
            println!(
                "    {} {} {}",
                style.key("Tags"),
                style.muted(":"),
                style.muted(&worker.tags.join(", "))
            );
        }

        if workers_list_verbose_enabled(ctx) {
            debug!(target: "rch::verbose", worker = %worker.id, "rendering verbose worker details");
            for line in render_worker_verbose_lines(worker, daemon_status.as_ref(), style) {
                println!("{line}");
            }
        }

        println!();
    }

    println!(
        "{} {} worker(s)",
        style.muted("Total:"),
        style.highlight(&workers.len().to_string())
    );
    Ok(())
}

/// Show worker runtime capabilities.
pub async fn workers_capabilities(
    command: Option<String>,
    refresh: bool,
    ctx: &OutputContext,
) -> Result<()> {
    let style = ctx.theme();
    let response = query_workers_capabilities(refresh).await?;
    let workers = response.workers;
    let local_capabilities = probe_local_capabilities().await;
    let local_has_any = has_any_capabilities(&local_capabilities);

    let mut warnings = Vec::new();
    let mut required_runtime = None;

    if let Some(command) = command.as_deref() {
        let details = classify_command_detailed(command);
        if !details.classification.is_compilation {
            warnings.push(format!(
                "Command '{}' is not a compilation command: {}",
                command, details.classification.reason
            ));
        }
        let runtime = required_runtime_for_kind(details.classification.kind);
        if runtime != RequiredRuntime::None {
            required_runtime = Some(runtime);
        }
    }

    if let Some(runtime) = required_runtime {
        let missing: Vec<String> = workers
            .iter()
            .filter(|worker| {
                let caps = &worker.capabilities;
                match runtime {
                    RequiredRuntime::Rust => !caps.has_rust(),
                    RequiredRuntime::Bun => !caps.has_bun(),
                    RequiredRuntime::Node => !caps.has_node(),
                    RequiredRuntime::None => false,
                }
            })
            .map(|worker| worker.id.clone())
            .collect();

        if !missing.is_empty() {
            warnings.push(format!(
                "Workers missing required runtime {}: {}",
                runtime_label(&runtime),
                missing.join(", ")
            ));
        }
    }

    if local_has_any {
        warnings.extend(collect_local_capability_warnings(
            &workers,
            &local_capabilities,
        ));
    }

    if ctx.is_json() {
        let report = WorkersCapabilitiesReport {
            workers,
            local: Some(local_capabilities),
            required_runtime,
            warnings,
        };
        let _ = ctx.json(&ApiResponse::ok("workers capabilities", report));
        return Ok(());
    }

    if workers.is_empty() {
        println!(
            "{} {}",
            StatusIndicator::Warning.display(style),
            style.warning("No workers configured")
        );
        return Ok(());
    }

    println!("{}", style.format_header("Worker Capabilities"));
    println!();

    let key_width = ["Rust", "Bun", "Node", "npm"]
        .iter()
        .map(|label| label.len())
        .max()
        .unwrap_or(4);

    println!("{}", style.highlight("Local Capabilities"));
    let render = |label: &str, value: Option<&String>| {
        let (indicator, display) = if let Some(ver) = value {
            (StatusIndicator::Success, style.value(ver))
        } else {
            (StatusIndicator::Warning, style.warning("unknown"))
        };
        let padded_label = format!("{label:width$}", width = key_width);
        println!(
            "    {} {} {} {}",
            indicator.display(style),
            style.key(&padded_label),
            style.muted(":"),
            display
        );
    };
    render("Rust", local_capabilities.rustc_version.as_ref());
    render("Bun", local_capabilities.bun_version.as_ref());
    render("Node", local_capabilities.node_version.as_ref());
    render("npm", local_capabilities.npm_version.as_ref());
    if !local_has_any {
        println!(
            "    {} {}",
            StatusIndicator::Warning.display(style),
            style.warning("No local runtimes detected")
        );
    }
    println!();

    if let Some(runtime) = required_runtime.as_ref() {
        println!(
            "{} {}",
            style.key("Required runtime:"),
            style.value(runtime_label(runtime))
        );
        println!();
    }

    for worker in &workers {
        println!(
            "  {} {} {}@{}",
            style.symbols.bullet_filled,
            style.highlight(&worker.id),
            style.muted(&worker.user),
            style.info(&worker.host)
        );

        let caps = &worker.capabilities;
        render("Rust", caps.rustc_version.as_ref());
        render("Bun", caps.bun_version.as_ref());
        render("Node", caps.node_version.as_ref());
        render("npm", caps.npm_version.as_ref());
        println!();
    }

    if !warnings.is_empty() {
        println!("{}", style.format_header("Warnings"));
        for warning in warnings {
            println!(
                "  {} {}",
                StatusIndicator::Warning.display(style),
                style.warning(&warning)
            );
        }
    }

    Ok(())
}

/// Probe worker connectivity (not available on non-Unix platforms).
#[cfg(not(unix))]
pub async fn workers_probe(
    _worker_id: Option<String>,
    _all: bool,
    _ctx: &OutputContext,
) -> Result<()> {
    Err(PlatformError::UnixOnly {
        feature: "worker probe".to_string(),
    })?
}

/// Probe worker connectivity.
#[cfg(unix)]
pub async fn workers_probe(
    worker_id: Option<String>,
    all: bool,
    ctx: &OutputContext,
) -> Result<()> {
    let workers = load_workers_from_config()?;
    let style = ctx.theme();

    if workers.is_empty() {
        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::<WorkersProbeResponse>::ok(
                "workers probe",
                WorkersProbeResponse {
                    results: vec![],
                    summary: WorkerProbeSummary::default(),
                },
            ));
        }
        return Ok(());
    }

    let targets: Vec<&WorkerConfig> = if all {
        workers.iter().collect()
    } else if let Some(id) = &worker_id {
        workers.iter().filter(|w| w.id.as_str() == id).collect()
    } else {
        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::<()>::err(
                "workers probe",
                ApiError::new(
                    ErrorCode::ConfigValidationError,
                    "Specify a worker ID or use --all",
                ),
            ));
        } else {
            println!(
                "{} Specify a worker ID or use {} to probe all workers.",
                StatusIndicator::Info.display(style),
                style.highlight("--all")
            );
        }
        return Ok(());
    };

    if targets.is_empty() {
        if let Some(id) = worker_id {
            if ctx.is_json() {
                let _ = ctx.json(&ApiResponse::<()>::err(
                    "workers probe",
                    ApiError::new(
                        ErrorCode::ConfigInvalidWorker,
                        format!("Worker '{}' not found", id),
                    ),
                ));
            } else {
                println!(
                    "{} Worker '{}' not found in configuration.",
                    StatusIndicator::Warning.display(style),
                    style.highlight(&id)
                );
            }
        }
        return Ok(());
    }

    let mut results = Vec::new();

    if !ctx.is_json() {
        println!(
            "Probing {} worker(s)...\n",
            style.highlight(&targets.len().to_string())
        );
    }

    for worker in targets {
        if !ctx.is_json() {
            print!(
                "  {} {}@{}... ",
                style.highlight(worker.id.as_str()),
                style.muted(&worker.user),
                style.info(&worker.host)
            );
        }

        let ssh_options = SshOptions::default();
        let mut client = SshClient::new(worker.clone(), ssh_options.clone());

        match client.connect().await {
            Ok(()) => {
                let start = std::time::Instant::now();
                match client.health_check().await {
                    Ok(true) => {
                        let latency = start.elapsed().as_millis() as u64;
                        results.push(WorkerProbeResult {
                            id: worker.id.as_str().to_string(),
                            host: worker.host.clone(),
                            status: "ok".to_string(),
                            latency_ms: Some(latency),
                            error: None,
                            error_code: None,
                        });
                        if !ctx.is_json() {
                            println!(
                                "{} ({}ms)",
                                StatusIndicator::Success.with_label(style, "OK"),
                                style.muted(&latency.to_string())
                            );
                        }
                    }
                    Ok(false) => {
                        // Reachable over SSH but the worker didn't confirm
                        // readiness. Distinguish this from connect-layer
                        // failures with WorkerHealthCheckFailed (E202).
                        let code = rch_common::ErrorCode::WorkerHealthCheckFailed.code_string();
                        results.push(WorkerProbeResult {
                            id: worker.id.as_str().to_string(),
                            host: worker.host.clone(),
                            status: "unhealthy".to_string(),
                            latency_ms: None,
                            error: Some("Health check failed".to_string()),
                            error_code: Some(code),
                        });
                        if !ctx.is_json() {
                            println!(
                                "{}",
                                StatusIndicator::Error.with_label(style, "Health check failed")
                            );
                        }
                    }
                    Err(e) => {
                        let ssh_error = classify_ssh_error(worker, &e, ssh_options.connect_timeout);
                        let code = ssh_error_code(&ssh_error).code_string();
                        let report = format_ssh_report(ssh_error);
                        results.push(WorkerProbeResult {
                            id: worker.id.as_str().to_string(),
                            host: worker.host.clone(),
                            status: "error".to_string(),
                            latency_ms: None,
                            error: Some(report.clone()),
                            error_code: Some(code.clone()),
                        });
                        if !ctx.is_json() {
                            println!(
                                "{} Health check failed [{}]:\n{}",
                                StatusIndicator::Error.display(style),
                                style.highlight(&code),
                                indent_lines(&report, "    ")
                            );
                        }
                    }
                }
                let _ = client.disconnect().await;
            }
            Err(e) => {
                let ssh_error = classify_ssh_error(worker, &e, ssh_options.connect_timeout);
                let code = ssh_error_code(&ssh_error).code_string();
                let report = format_ssh_report(ssh_error);
                results.push(WorkerProbeResult {
                    id: worker.id.as_str().to_string(),
                    host: worker.host.clone(),
                    status: "connection_failed".to_string(),
                    latency_ms: None,
                    error: Some(report.clone()),
                    error_code: Some(code.clone()),
                });
                if !ctx.is_json() {
                    println!(
                        "{} Connection failed [{}]:\n{}",
                        StatusIndicator::Error.display(style),
                        style.highlight(&code),
                        indent_lines(&report, "    ")
                    );
                }
            }
        }
    }

    let summary = summarize_probe_results(&results);

    if ctx.is_json() {
        let _ = ctx.json(&ApiResponse::ok(
            "workers probe",
            WorkersProbeResponse { results, summary },
        ));
    } else {
        println!("\n{}", format_probe_summary_line(&summary, style));
    }

    Ok(())
}

/// Tally a batch of probe results into a `WorkerProbeSummary`.
pub(crate) fn summarize_probe_results(results: &[WorkerProbeResult]) -> WorkerProbeSummary {
    let mut summary = WorkerProbeSummary {
        total: results.len(),
        ..WorkerProbeSummary::default()
    };
    for result in results {
        match result.status.as_str() {
            "ok" | "healthy" => summary.healthy += 1,
            "unhealthy" => summary.unhealthy += 1,
            _ => summary.failed += 1,
        }
        if let Some(code) = &result.error_code {
            *summary.by_error_code.entry(code.clone()).or_insert(0) += 1;
        } else if result.error.is_some() {
            *summary
                .by_error_code
                .entry("other".to_string())
                .or_insert(0) += 1;
        }
    }
    summary
}

/// Render a one-line human summary such as
/// `"9 worker(s) probed: 0 healthy, 6 RCH-E100, 3 RCH-E108."`
///
/// Unhealthy workers are reported via their `RCH-E202` bucket in
/// `by_error_code` rather than as a separate "unhealthy" entry to avoid
/// double-counting the same worker.
fn format_probe_summary_line(
    summary: &WorkerProbeSummary,
    style: &crate::ui::theme::Theme,
) -> String {
    let mut parts: Vec<String> = Vec::new();
    parts.push(format!("{} healthy", summary.healthy));
    // BTreeMap iteration is sorted by key, so output order is deterministic.
    for (code, count) in &summary.by_error_code {
        parts.push(format!("{} {}", count, code));
    }
    format!(
        "{} worker(s) probed: {}.",
        style.highlight(&summary.total.to_string()),
        parts.join(", ")
    )
}

/// Run worker benchmarks (not available on non-Unix platforms).
#[cfg(not(unix))]
pub async fn workers_benchmark(_ctx: &OutputContext) -> Result<()> {
    Err(PlatformError::UnixOnly {
        feature: "worker benchmark".to_string(),
    })?
}

/// Run worker benchmarks.
#[cfg(unix)]
pub async fn workers_benchmark(ctx: &OutputContext) -> Result<()> {
    let workers = load_workers_from_config()?;
    let style = ctx.theme();

    if workers.is_empty() {
        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::<Vec<WorkerBenchmarkResult>>::ok(
                "workers benchmark",
                vec![],
            ));
        }
        return Ok(());
    }

    let mut results = Vec::new();

    // Use MultiProgressManager for animated spinners per worker
    let mp = MultiProgressManager::new(ctx);

    if !ctx.is_json() && !mp.is_visible() {
        // Fallback for non-TTY: print static header
        println!(
            "Running benchmarks on {} worker(s)...\n",
            style.highlight(&workers.len().to_string())
        );
    }

    for worker in &workers {
        let spinner = if !ctx.is_json() {
            let pb = mp.add_spinner(worker.id.as_str(), "Connecting...");
            Some(pb)
        } else {
            None
        };

        let ssh_options = SshOptions::default();
        let mut client = SshClient::new(worker.clone(), ssh_options.clone());

        match client.connect().await {
            Ok(()) => {
                if let Some(ref pb) = spinner {
                    pb.set_message("Running benchmark...");
                }

                let bench_id = uuid::Uuid::new_v4();
                let bench_dir = format!("rch_bench_{}", bench_id);

                // Run a simple benchmark: compile a hello world Rust program
                // Uses a unique directory and cleans up afterwards
                let benchmark_cmd = format!(
                    r###"#
                    cd /tmp && \
                    mkdir -p {0} && \
                    cd {0} && \
                    echo 'fn main() {{ println!("hello"); }}' > main.rs && \
                    (time rustc main.rs -o hello) 2>&1 | grep real || echo 'rustc not found'; \
                    cd .. && rm -rf {0}
                "###,
                    bench_dir
                );

                let start = std::time::Instant::now();
                let result = client.execute(&benchmark_cmd).await;
                let duration = start.elapsed();

                match result {
                    Ok(r) if r.success() => {
                        let duration_ms = duration.as_millis() as u64;
                        results.push(WorkerBenchmarkResult {
                            id: worker.id.as_str().to_string(),
                            host: worker.host.clone(),
                            status: "ok".to_string(),
                            duration_ms: Some(duration_ms),
                            error: None,
                        });
                        if let Some(ref pb) = spinner {
                            pb.finish_with_message(format!("✓ {}ms", duration_ms));
                        }
                    }
                    Ok(r) => {
                        results.push(WorkerBenchmarkResult {
                            id: worker.id.as_str().to_string(),
                            host: worker.host.clone(),
                            status: "failed".to_string(),
                            duration_ms: None,
                            error: Some(format!("exit code {}", r.exit_code)),
                        });
                        if let Some(ref pb) = spinner {
                            pb.finish_with_message(format!("✗ Failed (exit={})", r.exit_code));
                        }
                    }
                    Err(e) => {
                        let ssh_error = classify_ssh_error(worker, &e, ssh_options.command_timeout);
                        let report = format_ssh_report(ssh_error);
                        results.push(WorkerBenchmarkResult {
                            id: worker.id.as_str().to_string(),
                            host: worker.host.clone(),
                            status: "error".to_string(),
                            duration_ms: None,
                            error: Some(report.clone()),
                        });
                        if let Some(ref pb) = spinner {
                            pb.finish_with_message(format!(
                                "✗ {}",
                                report.lines().next().unwrap_or("Error")
                            ));
                        }
                    }
                }
                let _ = client.disconnect().await;
            }
            Err(e) => {
                let ssh_error = classify_ssh_error(worker, &e, ssh_options.connect_timeout);
                let report = format_ssh_report(ssh_error);
                results.push(WorkerBenchmarkResult {
                    id: worker.id.as_str().to_string(),
                    host: worker.host.clone(),
                    status: "connection_failed".to_string(),
                    duration_ms: None,
                    error: Some(report.clone()),
                });
                if let Some(ref pb) = spinner {
                    pb.finish_with_message(format!(
                        "✗ Connection failed: {}",
                        report.lines().next().unwrap_or("Error")
                    ));
                }
            }
        }
    }

    if ctx.is_json() {
        let _ = ctx.json(&ApiResponse::ok("workers benchmark", results));
    } else {
        println!(
            "\n{} For accurate speed scores, use longer benchmark runs.",
            StatusIndicator::Info.display(style)
        );
    }
    Ok(())
}

/// Drain a worker (requires daemon).
///
/// If `skip_confirm` is false, prompts for confirmation before draining.
pub async fn workers_drain(worker_id: &str, skip_confirm: bool, ctx: &OutputContext) -> Result<()> {
    use dialoguer::Confirm;

    let style = ctx.theme();

    // Check if daemon is running
    let socket_path_str = configured_socket_path()?;
    if !Path::new(&socket_path_str).exists() {
        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::<()>::err(
                "workers drain",
                ApiError::new(ErrorCode::InternalDaemonNotRunning, "Daemon is not running"),
            ));
        } else {
            println!(
                "{} Daemon is not running. Start it with {}",
                StatusIndicator::Error.display(style),
                style.highlight("rch daemon start")
            );
            println!(
                "\n{} Draining requires the daemon to track worker state.",
                StatusIndicator::Info.display(style)
            );
        }
        return Ok(());
    }

    // Prompt for confirmation unless skipped or in JSON mode
    if !skip_confirm && !ctx.is_json() {
        println!(
            "{} This will stop routing new jobs to worker {}.",
            StatusIndicator::Warning.display(style),
            style.highlight(worker_id)
        );
        println!(
            "  {} Active builds will be allowed to complete.",
            StatusIndicator::Info.display(style)
        );
        let confirmed = Confirm::new()
            .with_prompt("Drain this worker?")
            .default(false)
            .interact()?;
        if !confirmed {
            println!("{} Aborted.", StatusIndicator::Info.display(style));
            return Ok(());
        }
    }

    // Send drain command to daemon
    match send_daemon_command(&format!(
        "POST /workers/{}/drain\n",
        urlencoding_encode(worker_id)
    ))
    .await
    {
        Ok(response) => {
            if response.contains("error") || response.contains("Error") {
                if ctx.is_json() {
                    let _ = ctx.json(&ApiResponse::ok(
                        "workers drain",
                        WorkerActionResponse {
                            worker_id: worker_id.to_string(),
                            action: "drain".to_string(),
                            success: false,
                            message: Some(response),
                        },
                    ));
                } else {
                    println!(
                        "{} Failed to drain worker: {}",
                        StatusIndicator::Error.display(style),
                        style.muted(&response)
                    );
                }
            } else if ctx.is_json() {
                let _ = ctx.json(&ApiResponse::ok(
                    "workers drain",
                    WorkerActionResponse {
                        worker_id: worker_id.to_string(),
                        action: "drain".to_string(),
                        success: true,
                        message: Some("Worker is now draining".to_string()),
                    },
                ));
            } else {
                println!(
                    "{} Worker {} is now draining.",
                    StatusIndicator::Success.display(style),
                    style.highlight(worker_id)
                );
                println!(
                    "  {} No new jobs will be sent. Existing jobs will complete.",
                    StatusIndicator::Info.display(style)
                );
            }
        }
        Err(e) => {
            if ctx.is_json() {
                let _ = ctx.json(&ApiResponse::<()>::err(
                    "workers drain",
                    ApiError::new(ErrorCode::InternalStateError, e.to_string()),
                ));
            } else {
                println!(
                    "{} Failed to communicate with daemon: {}",
                    StatusIndicator::Error.display(style),
                    style.muted(&e.to_string())
                );
                println!(
                    "\n{} Drain/enable commands require the daemon to be running.",
                    StatusIndicator::Info.display(style)
                );
            }
        }
    }

    Ok(())
}

/// Enable a worker (requires daemon).
pub async fn workers_enable(worker_id: &str, ctx: &OutputContext) -> Result<()> {
    let style = ctx.theme();

    let socket_path_str = configured_socket_path()?;
    if !Path::new(&socket_path_str).exists() {
        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::<()>::err(
                "workers enable",
                ApiError::new(ErrorCode::InternalDaemonNotRunning, "Daemon is not running"),
            ));
        } else {
            println!(
                "{} Daemon is not running. Start it with {}",
                StatusIndicator::Error.display(style),
                style.highlight("rch daemon start")
            );
        }
        return Ok(());
    }

    match send_daemon_command(&format!(
        "POST /workers/{}/enable\n",
        urlencoding_encode(worker_id)
    ))
    .await
    {
        Ok(response) => {
            if response.contains("error") || response.contains("Error") {
                if ctx.is_json() {
                    let _ = ctx.json(&ApiResponse::ok(
                        "workers enable",
                        WorkerActionResponse {
                            worker_id: worker_id.to_string(),
                            action: "enable".to_string(),
                            success: false,
                            message: Some(response),
                        },
                    ));
                } else {
                    println!(
                        "{} Failed to enable worker: {}",
                        StatusIndicator::Error.display(style),
                        style.muted(&response)
                    );
                }
            } else if ctx.is_json() {
                let _ = ctx.json(&ApiResponse::ok(
                    "workers enable",
                    WorkerActionResponse {
                        worker_id: worker_id.to_string(),
                        action: "enable".to_string(),
                        success: true,
                        message: Some("Worker is now enabled".to_string()),
                    },
                ));
            } else {
                println!(
                    "{} Worker {} is now enabled.",
                    StatusIndicator::Success.display(style),
                    style.highlight(worker_id)
                );
            }
        }
        Err(e) => {
            if ctx.is_json() {
                let _ = ctx.json(&ApiResponse::<()>::err(
                    "workers enable",
                    ApiError::new(ErrorCode::InternalStateError, e.to_string()),
                ));
            } else {
                println!(
                    "{} Failed to communicate with daemon: {}",
                    StatusIndicator::Error.display(style),
                    style.muted(&e.to_string())
                );
            }
        }
    }

    Ok(())
}

/// Disable a worker (requires daemon).
///
/// If `skip_confirm` is false, prompts for confirmation before disabling.
pub async fn workers_disable(
    worker_id: &str,
    reason: Option<String>,
    drain_first: bool,
    skip_confirm: bool,
    ctx: &OutputContext,
) -> Result<()> {
    use dialoguer::Confirm;

    let style = ctx.theme();

    let socket_path_str = configured_socket_path()?;
    if !Path::new(&socket_path_str).exists() {
        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::<()>::err(
                "workers disable",
                ApiError::new(ErrorCode::InternalDaemonNotRunning, "Daemon is not running"),
            ));
        } else {
            println!(
                "{} Daemon is not running. Start it with {}",
                StatusIndicator::Error.display(style),
                style.highlight("rch daemon start")
            );
        }
        return Ok(());
    }

    // Prompt for confirmation unless skipped or in JSON mode
    if !skip_confirm && !ctx.is_json() {
        println!(
            "{} This will mark worker {} as offline.",
            StatusIndicator::Warning.display(style),
            style.highlight(worker_id)
        );
        if drain_first {
            println!(
                "  {} Active builds will complete before disabling.",
                StatusIndicator::Info.display(style)
            );
        } else {
            println!(
                "  {} The worker will be immediately excluded from job assignment.",
                StatusIndicator::Info.display(style)
            );
        }
        let confirmed = Confirm::new()
            .with_prompt("Disable this worker?")
            .default(false)
            .interact()?;
        if !confirmed {
            println!("{} Aborted.", StatusIndicator::Info.display(style));
            return Ok(());
        }
    }

    // Build the request URL with optional reason and drain flag
    let mut url = format!("POST /workers/{}/disable", urlencoding_encode(worker_id));
    let mut query_parts = Vec::new();
    if let Some(ref r) = reason {
        query_parts.push(format!("reason={}", urlencoding_encode(r)));
    }
    if drain_first {
        query_parts.push("drain=true".to_string());
    }
    if !query_parts.is_empty() {
        url = format!("{}?{}", url, query_parts.join("&"));
    }
    url.push('\n');

    match send_daemon_command(&url).await {
        Ok(response) => {
            if response.contains("error") || response.contains("Error") {
                if ctx.is_json() {
                    let _ = ctx.json(&ApiResponse::ok(
                        "workers disable",
                        WorkerActionResponse {
                            worker_id: worker_id.to_string(),
                            action: "disable".to_string(),
                            success: false,
                            message: Some(response),
                        },
                    ));
                } else {
                    println!(
                        "{} Failed to disable worker: {}",
                        StatusIndicator::Error.display(style),
                        style.muted(&response)
                    );
                }
            } else if ctx.is_json() {
                let _ = ctx.json(&ApiResponse::ok(
                    "workers disable",
                    WorkerActionResponse {
                        worker_id: worker_id.to_string(),
                        action: "disable".to_string(),
                        success: true,
                        message: Some(if drain_first {
                            "Worker is draining before disable".to_string()
                        } else {
                            "Worker is now disabled".to_string()
                        }),
                    },
                ));
            } else if drain_first {
                println!(
                    "{} Worker {} is draining before disable.",
                    StatusIndicator::Success.display(style),
                    style.highlight(worker_id)
                );
                println!(
                    "  {} Existing jobs will complete, then worker will be disabled.",
                    StatusIndicator::Info.display(style)
                );
                if let Some(ref r) = reason {
                    println!(
                        "  {} Reason: {}",
                        StatusIndicator::Info.display(style),
                        style.muted(r)
                    );
                }
            } else {
                println!(
                    "{} Worker {} is now disabled.",
                    StatusIndicator::Success.display(style),
                    style.highlight(worker_id)
                );
                println!(
                    "  {} No jobs will be sent to this worker.",
                    StatusIndicator::Info.display(style)
                );
                if let Some(ref r) = reason {
                    println!(
                        "  {} Reason: {}",
                        StatusIndicator::Info.display(style),
                        style.muted(r)
                    );
                }
            }
        }
        Err(e) => {
            if ctx.is_json() {
                let _ = ctx.json(&ApiResponse::<()>::err(
                    "workers disable",
                    ApiError::new(ErrorCode::InternalStateError, e.to_string()),
                ));
            } else {
                println!(
                    "{} Failed to communicate with daemon: {}",
                    StatusIndicator::Error.display(style),
                    style.muted(&e.to_string())
                );
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod probe_summary_tests {
    use super::*;
    use crate::ui::context::OutputConfig;
    use crate::ui::writer::SharedOutputBuffer;
    use rch_common::WorkerId;

    fn mk(status: &str, error_code: Option<&str>, error: Option<&str>) -> WorkerProbeResult {
        WorkerProbeResult {
            id: "w".to_string(),
            host: "h".to_string(),
            status: status.to_string(),
            latency_ms: None,
            error: error.map(String::from),
            error_code: error_code.map(String::from),
        }
    }

    #[test]
    fn summarize_counts_healthy_and_error_codes() {
        let results = vec![
            mk("ok", None, None),
            mk("ok", None, None),
            mk("connection_failed", Some("RCH-E100"), Some("...")),
            mk("connection_failed", Some("RCH-E108"), Some("...")),
            mk("connection_failed", Some("RCH-E108"), Some("...")),
            mk("unhealthy", Some("RCH-E202"), Some("Health check failed")),
        ];
        let s = summarize_probe_results(&results);
        assert_eq!(s.total, 6);
        assert_eq!(s.healthy, 2);
        assert_eq!(s.unhealthy, 1);
        assert_eq!(s.failed, 3);
        assert_eq!(s.by_error_code.get("RCH-E100"), Some(&1));
        assert_eq!(s.by_error_code.get("RCH-E108"), Some(&2));
        assert_eq!(s.by_error_code.get("RCH-E202"), Some(&1));
    }

    #[test]
    fn summarize_buckets_uncategorized_errors_as_other() {
        let results = vec![mk("error", None, Some("something weird"))];
        let s = summarize_probe_results(&results);
        assert_eq!(s.by_error_code.get("other"), Some(&1));
    }

    #[test]
    fn summarize_empty_input() {
        let s = summarize_probe_results(&[]);
        assert_eq!(s.total, 0);
        assert_eq!(s.healthy, 0);
        assert!(s.by_error_code.is_empty());
    }

    fn make_worker() -> WorkerConfig {
        WorkerConfig {
            id: WorkerId::new("builder-1"),
            host: "127.0.0.1".to_string(),
            user: "ubuntu".to_string(),
            identity_file: "~/.ssh/rch_test".to_string(),
            total_slots: 8,
            priority: 100,
            tags: vec!["rust".to_string()],
        }
    }

    fn make_daemon_status() -> DaemonFullStatusResponse {
        serde_json::from_value(serde_json::json!({
            "daemon": {
                "pid": 123,
                "uptime_secs": 45,
                "version": "test",
                "socket_path": "/tmp/rch.sock",
                "started_at": "2026-01-01T00:00:00Z",
                "workers_total": 1,
                "workers_healthy": 1,
                "slots_total": 8,
                "slots_available": 6
            },
            "workers": [{
                "id": "builder-1",
                "host": "127.0.0.1",
                "user": "ubuntu",
                "status": "degraded",
                "circuit_state": "open",
                "used_slots": 2,
                "total_slots": 8,
                "speed_score": 90.0,
                "last_error": "ssh timeout",
                "recovery_in_secs": 30
            }],
            "active_builds": [],
            "recent_builds": [],
            "issues": [],
            "alerts": [],
            "stats": {
                "total_builds": 0,
                "success_count": 0,
                "failure_count": 0,
                "remote_count": 0,
                "local_count": 0,
                "avg_duration_ms": 0
            }
        }))
        .unwrap()
    }

    fn make_context(config: OutputConfig) -> OutputContext {
        let stdout = SharedOutputBuffer::new().as_writer(true);
        let stderr = SharedOutputBuffer::new().as_writer(true);
        OutputContext::with_writers(config, stdout, stderr)
    }

    #[test]
    fn test_workers_list_verbose_shows_extra_columns() {
        let worker = make_worker();
        let status = make_daemon_status();
        let style = crate::ui::theme::Style::new(false, true, false);
        let output = render_worker_verbose_lines(&worker, Some(&status), &style).join("\n");

        assert!(output.contains("Circuit"));
        assert!(output.contains("In Use"));
        assert!(output.contains("Status"));
        assert!(output.contains("LastErr"));
        assert!(output.contains("Recover"));
        assert!(output.contains("SSH Key"));
        assert!(output.contains("ssh timeout"));
        assert!(output.contains("~/.ssh/rch_test"));
    }

    #[test]
    fn test_workers_list_normal_hides_extra_columns() {
        let normal_ctx = make_context(OutputConfig::default());
        assert!(!workers_list_verbose_enabled(&normal_ctx));

        let verbose_ctx = make_context(OutputConfig {
            verbose: true,
            ..Default::default()
        });
        assert!(workers_list_verbose_enabled(&verbose_ctx));

        let verbose_json_ctx = make_context(OutputConfig {
            json: true,
            verbose: true,
            ..Default::default()
        });
        assert!(!workers_list_verbose_enabled(&verbose_json_ctx));
    }
}
