//! Status and diagnostics commands.
//!
//! This module contains commands for diagnosing RCH behavior, running self-tests,
//! and checking overall system status.

use crate::hook::{extract_project_name, query_daemon, release_worker, required_runtime_for_kind};
use crate::status_types::{
    DaemonFullStatusResponse, SelfTestHistoryResponse, SelfTestRunResponse, SelfTestStatusResponse,
    extract_json_body,
};
use crate::toolchain::detect_toolchain;
use crate::ui::context::OutputContext;
use crate::ui::progress::Spinner;
use crate::ui::theme::StatusIndicator;
use anyhow::{Context, Result};
use rch_common::{ApiResponse, CommandPriority, RequiredRuntime, normalize_project_path};
use std::path::Path;
use tracing::debug;

use super::config::collect_value_sources;
use super::helpers::{humanize_duration, runtime_label, urlencoding_encode};
use super::types::{
    DiagnoseDaemonStatus, DiagnoseDecision, DiagnoseResponse, DiagnoseThreshold,
    DiagnoseWorkerSelection, DryRunPipelineStep, DryRunSummary,
};
use super::workers::{
    collect_local_capability_warnings, has_any_capabilities, probe_local_capabilities,
    query_workers_capabilities,
};
use super::{load_workers_from_config, query_daemon_health, send_daemon_command};

// =============================================================================
// Diagnose Command
// =============================================================================

/// Build intercept decision based on classification and threshold.
pub(super) fn build_diagnose_decision(
    classification: &rch_common::Classification,
    threshold: f64,
) -> DiagnoseDecision {
    let would_intercept = classification.is_compilation && classification.confidence >= threshold;
    let reason = if !classification.is_compilation {
        "Command not classified as compilation".to_string()
    } else if classification.confidence < threshold {
        format!(
            "Confidence {:.2} below threshold {:.2}",
            classification.confidence, threshold
        )
    } else {
        format!(
            "Compilation command with confidence {:.2} >= threshold {:.2}",
            classification.confidence, threshold
        )
    };
    DiagnoseDecision {
        would_intercept,
        reason,
    }
}

/// Build dry-run summary showing what would happen.
pub(super) fn build_dry_run_summary(
    would_intercept: bool,
    reason: &str,
    worker_selection: &Option<DiagnoseWorkerSelection>,
    daemon_reachable: bool,
) -> DryRunSummary {
    if !would_intercept {
        return DryRunSummary {
            would_offload: false,
            reason: reason.to_string(),
            pipeline_steps: vec![DryRunPipelineStep {
                step: 1,
                name: "Local execution".to_string(),
                description: "Command would run locally (not offloaded)".to_string(),
                skipped: false,
                skip_reason: None,
                estimated_duration_ms: None,
            }],
            transfer_estimate: None,
            total_estimated_ms: None,
        };
    }

    let mut steps = Vec::new();

    // Step 1: Classification (already done)
    steps.push(DryRunPipelineStep {
        step: 1,
        name: "Classification".to_string(),
        description: "Command classified as compilation".to_string(),
        skipped: false,
        skip_reason: None,
        estimated_duration_ms: Some(1),
    });

    // Step 2: Daemon query
    steps.push(DryRunPipelineStep {
        step: 2,
        name: "Daemon query".to_string(),
        description: "Request worker selection from daemon".to_string(),
        skipped: !daemon_reachable,
        skip_reason: if !daemon_reachable {
            Some("Daemon not reachable".to_string())
        } else {
            None
        },
        estimated_duration_ms: Some(5),
    });

    // Step 3: Worker selection
    let worker_selected = worker_selection
        .as_ref()
        .is_some_and(|s| s.worker.is_some());
    steps.push(DryRunPipelineStep {
        step: 3,
        name: "Worker selection".to_string(),
        description: if worker_selected {
            format!(
                "Worker {} selected",
                worker_selection
                    .as_ref()
                    .and_then(|s| s.worker.as_ref())
                    .map(|w| w.id.as_str())
                    .unwrap_or("unknown")
            )
        } else {
            "Select best available worker".to_string()
        },
        skipped: !worker_selected,
        skip_reason: if !worker_selected {
            Some(
                worker_selection
                    .as_ref()
                    .map(|s| s.reason.to_string())
                    .unwrap_or_else(|| "No worker available".to_string()),
            )
        } else {
            None
        },
        estimated_duration_ms: Some(2),
    });

    // Step 4: Transfer
    steps.push(DryRunPipelineStep {
        step: 4,
        name: "Transfer".to_string(),
        description: "Sync project files to worker via rsync+zstd".to_string(),
        skipped: !worker_selected,
        skip_reason: None,
        estimated_duration_ms: None, // Depends on project size
    });

    // Step 5: Remote execution
    steps.push(DryRunPipelineStep {
        step: 5,
        name: "Remote execution".to_string(),
        description: "Execute compilation command on worker".to_string(),
        skipped: !worker_selected,
        skip_reason: None,
        estimated_duration_ms: None, // Depends on build
    });

    // Step 6: Artifact retrieval
    steps.push(DryRunPipelineStep {
        step: 6,
        name: "Artifact retrieval".to_string(),
        description: "Retrieve build artifacts from remote worker".to_string(),
        skipped: false,
        skip_reason: None,
        estimated_duration_ms: None, // Would need rsync dry-run
    });

    DryRunSummary {
        would_offload: true,
        reason: "compilation command meets threshold, worker available".to_string(),
        pipeline_steps: steps,
        transfer_estimate: None,  // Would need actual rsync dry-run
        total_estimated_ms: None, // Total unknown without transfer estimates
    }
}

/// Summarize local capabilities as a string.
fn summarize_capabilities(caps: &rch_common::WorkerCapabilities) -> String {
    let mut parts = Vec::new();
    if caps.has_rust() {
        parts.push(format!(
            "rust {}",
            caps.rustc_version.as_deref().unwrap_or("?")
        ));
    }
    if caps.has_bun() {
        parts.push(format!(
            "bun {}",
            caps.bun_version.as_deref().unwrap_or("?")
        ));
    }
    if caps.has_node() {
        parts.push(format!(
            "node {}",
            caps.node_version.as_deref().unwrap_or("?")
        ));
    }
    if parts.is_empty() {
        "none detected".to_string()
    } else {
        parts.join(", ")
    }
}

/// Diagnose command classification and selection decisions.
pub async fn diagnose(command: &str, dry_run: bool, ctx: &OutputContext) -> Result<()> {
    use rch_common::classify_command_detailed;

    let style = ctx.theme();
    let loaded = crate::config::load_config_with_sources()?;
    let config = loaded.config;

    let details = classify_command_detailed(command);
    let threshold = config.compilation.confidence_threshold;

    let value_sources = collect_value_sources(&config, &loaded.sources);
    let threshold_source = value_sources
        .iter()
        .find(|s| s.key == "compilation.confidence_threshold")
        .map(|s| s.source.clone())
        .unwrap_or_else(|| "default".to_string());

    let decision = build_diagnose_decision(&details.classification, threshold);
    let would_intercept = decision.would_intercept;

    debug!(
        "Diagnose input='{}' normalized='{}'",
        details.original, details.normalized
    );
    debug!(
        "Classification confidence={:.2} reason='{}'",
        details.classification.confidence, details.classification.reason
    );
    debug!(
        "Confidence threshold={:.2} source='{}'",
        threshold, threshold_source
    );
    for tier in &details.tiers {
        debug!(
            "Tier {} {} decision={:?} reason='{}'",
            tier.tier, tier.name, tier.decision, tier.reason
        );
    }

    let required_runtime = required_runtime_for_kind(details.classification.kind);
    let socket_path = config.general.socket_path.clone();
    let socket_exists = Path::new(&socket_path).exists();

    // Run capabilities probe and daemon health check in parallel
    let capabilities_future = probe_local_capabilities();
    let daemon_health_future = async {
        if socket_exists {
            query_daemon_health(&socket_path).await.ok()
        } else {
            None
        }
    };

    let (local_capabilities, daemon_health) =
        tokio::join!(capabilities_future, daemon_health_future);

    let local_has_any = has_any_capabilities(&local_capabilities);
    let mut capabilities_warnings = Vec::new();

    let mut daemon_status = DiagnoseDaemonStatus {
        socket_path: socket_path.clone(),
        socket_exists,
        reachable: false,
        status: None,
        version: None,
        uptime_seconds: None,
        error: None,
    };

    if let Some(health) = daemon_health {
        daemon_status.reachable = true;
        daemon_status.status = Some(health.status);
        daemon_status.version = Some(health.version);
        daemon_status.uptime_seconds = Some(health.uptime_seconds);
        debug!(
            "Daemon health ok status='{}' version='{}' uptime={}s",
            daemon_status.status.as_deref().unwrap_or("unknown"),
            daemon_status.version.as_deref().unwrap_or("unknown"),
            daemon_status.uptime_seconds.unwrap_or(0)
        );
    } else if socket_exists {
        daemon_status.error = Some("health check failed".to_string());
        debug!("Daemon health check failed");
    } else {
        daemon_status.error = Some("daemon socket not found".to_string());
        debug!("Daemon socket not found: {}", socket_path);
    }

    let mut worker_selection = None;
    if would_intercept && daemon_status.reachable {
        let estimated_cores = 4;
        let project_root = std::env::current_dir().ok();
        let normalized_project_root = project_root.as_ref().and_then(|path| {
            normalize_project_path(path)
                .map(|normalized| normalized.canonical_path().to_path_buf())
                .ok()
        });
        let project = extract_project_name();
        let toolchain = normalized_project_root
            .as_ref()
            .or(project_root.as_ref())
            .and_then(|root| detect_toolchain(root).ok());

        match query_daemon(
            &socket_path,
            &project,
            estimated_cores,
            command,
            toolchain.as_ref(),
            required_runtime,
            CommandPriority::Normal,
            0,
            None,
            false,
        )
        .await
        {
            Ok(response) => {
                if let Some(worker) = response.worker.as_ref()
                    && let Err(err) = release_worker(
                        &socket_path,
                        &worker.id,
                        estimated_cores,
                        None,
                        None,
                        None,
                        None,
                        None, // timing
                    )
                    .await
                {
                    debug!("Failed to release worker slots: {}", err);
                }
                worker_selection = Some(DiagnoseWorkerSelection {
                    estimated_cores,
                    worker: response.worker.clone(),
                    reason: response.reason.clone(),
                });
                if let Some(worker) = response.worker.as_ref() {
                    debug!(
                        "Worker selected id='{}' slots_available={} speed_score={:.2} reason={:?}",
                        worker.id, worker.slots_available, worker.speed_score, response.reason
                    );
                } else {
                    debug!("No worker selected reason={:?}", response.reason);
                }
            }
            Err(err) => {
                daemon_status.error = Some(format!("selection request failed: {}", err));
                debug!("Worker selection request failed: {}", err);
            }
        }
    }

    if details.classification.is_compilation {
        if daemon_status.reachable {
            match query_workers_capabilities(false).await {
                Ok(response) => {
                    if required_runtime != RequiredRuntime::None {
                        let missing: Vec<String> = response
                            .workers
                            .iter()
                            .filter(|worker| {
                                let caps = &worker.capabilities;
                                match &required_runtime {
                                    RequiredRuntime::Rust => !caps.has_rust(),
                                    RequiredRuntime::Bun => !caps.has_bun(),
                                    RequiredRuntime::Node => !caps.has_node(),
                                    RequiredRuntime::None => false,
                                }
                            })
                            .map(|worker| worker.id.clone())
                            .collect();

                        if !missing.is_empty() {
                            capabilities_warnings.push(format!(
                                "Workers missing required runtime {}: {}",
                                runtime_label(&required_runtime),
                                missing.join(", ")
                            ));
                        }
                    }

                    if local_has_any {
                        capabilities_warnings.extend(collect_local_capability_warnings(
                            &response.workers,
                            &local_capabilities,
                        ));
                    }
                }
                Err(err) => {
                    capabilities_warnings.push(format!("Worker capabilities unavailable: {}", err));
                }
            }
        } else if required_runtime != RequiredRuntime::None {
            capabilities_warnings
                .push("Worker capabilities unavailable (daemon not reachable)".to_string());
        }
    }

    // Build dry-run summary if requested
    let dry_run_summary = if dry_run {
        Some(build_dry_run_summary(
            would_intercept,
            &decision.reason,
            &worker_selection,
            daemon_status.reachable,
        ))
    } else {
        None
    };

    if ctx.is_json() {
        let response = DiagnoseResponse {
            classification: details.classification.clone(),
            tiers: details.tiers.clone(),
            command: details.original.clone(),
            normalized_command: details.normalized.clone(),
            decision: DiagnoseDecision {
                would_intercept: decision.would_intercept,
                reason: decision.reason.clone(),
            },
            threshold: DiagnoseThreshold {
                value: threshold,
                source: threshold_source.clone(),
            },
            daemon: daemon_status,
            required_runtime,
            local_capabilities: local_has_any.then(|| local_capabilities.clone()),
            capabilities_warnings: capabilities_warnings.clone(),
            worker_selection,
            dry_run: dry_run_summary.clone(),
        };
        let _ = ctx.json(&ApiResponse::ok("diagnose", response));
        return Ok(());
    }

    // Display dry-run pipeline if requested
    if dry_run {
        println!("{}", style.format_header("RCH Dry Run"));
        println!();
        if let Some(ref summary) = dry_run_summary {
            let offload_label = if summary.would_offload {
                style.format_success("YES")
            } else {
                style.format_warning("NO")
            };
            println!(
                "{} {} {}",
                style.key("Would offload:"),
                offload_label,
                style.muted(&format!("({})", summary.reason))
            );
            println!();
            println!("{}", style.highlight("Pipeline Steps"));
            for step in &summary.pipeline_steps {
                let status = if step.skipped {
                    style.muted("[SKIP]")
                } else {
                    style.success("[RUN]")
                };
                println!(
                    "  {} {} {}",
                    status,
                    style.value(&format!("{}.", step.step)),
                    style.highlight(&step.name)
                );
                println!("     {}", style.muted(&step.description));
                if let Some(ref reason) = step.skip_reason {
                    println!("     {} {}", style.warning("Skip:"), style.muted(reason));
                }
                if let Some(ms) = step.estimated_duration_ms {
                    println!("     {} ~{}ms", style.muted("Est:"), ms);
                }
            }
            if let Some(ref transfer) = summary.transfer_estimate {
                println!();
                println!("{}", style.highlight("Transfer Estimate"));
                println!(
                    "  {} {} ({} files)",
                    style.key("Size:"),
                    style.value(&transfer.human_size),
                    transfer.files
                );
                println!("  {} ~{}ms", style.key("Time:"), transfer.estimated_time_ms);
                if transfer.would_skip {
                    println!(
                        "  {} {}",
                        style.warning("Would skip:"),
                        transfer
                            .skip_reason
                            .as_deref()
                            .unwrap_or("threshold exceeded")
                    );
                }
            }
            if let Some(total_ms) = summary.total_estimated_ms {
                println!();
                println!("{} ~{}ms", style.key("Total estimated:"), total_ms);
            }
        }
        println!();
        println!(
            "  {} This is a dry run. No network calls were made.",
            style.muted("ℹ")
        );
        return Ok(());
    }

    println!("{}", style.format_header("RCH Diagnose"));
    println!();

    println!("{}", style.highlight("Command Analysis"));
    println!(
        "  {} {}",
        style.key("Input:"),
        style.value(details.original.trim())
    );
    if details.normalized != details.original.trim() {
        println!(
            "  {} {}",
            style.key("Normalized:"),
            style.value(details.normalized.trim())
        );
    }
    println!("  {} {}", style.key("Tool:"), style.value("Bash"));
    println!();

    println!("{}", style.highlight("Classification"));
    let kind_label = details
        .classification
        .kind
        .map(|k| format!("{:?}", k))
        .unwrap_or_else(|| "none".to_string());
    println!("  {} {}", style.key("Kind:"), style.value(&kind_label));
    println!(
        "  {} {} {}",
        style.key("Confidence:"),
        style.value(&format!("{:.2}", details.classification.confidence)),
        style.muted(&format!("({})", details.classification.reason))
    );
    println!(
        "  {} {} {}",
        style.key("Threshold:"),
        style.value(&format!("{:.2}", threshold)),
        style.muted(&format!("# from {}", threshold_source))
    );

    let decision_label = if would_intercept {
        style.format_success("WOULD INTERCEPT")
    } else {
        style.format_warning("WOULD NOT INTERCEPT")
    };
    println!("  {} {}", style.key("Decision:"), decision_label);
    println!(
        "  {} {}",
        style.key("Reason:"),
        style.value(&decision.reason)
    );
    println!();

    println!("{}", style.highlight("Runtime Capabilities"));
    println!(
        "  {} {}",
        style.key("Required runtime:"),
        style.value(runtime_label(&required_runtime))
    );
    println!(
        "  {} {}",
        style.key("Local runtimes:"),
        style.value(&summarize_capabilities(&local_capabilities))
    );
    if capabilities_warnings.is_empty() {
        println!("  {} {}", style.key("Warnings:"), style.value("none"));
    } else {
        for warning in &capabilities_warnings {
            println!(
                "  {} {}",
                StatusIndicator::Warning.display(style),
                style.warning(warning)
            );
        }
    }
    println!();

    println!("{}", style.highlight("Tier Decisions"));
    for tier in &details.tiers {
        let decision = match tier.decision {
            rch_common::TierDecision::Pass => style.format_success("PASS"),
            rch_common::TierDecision::Reject => style.format_warning("REJECT"),
        };
        println!(
            "  {} {} {} {}",
            style.key(&format!("Tier {}:", tier.tier)),
            style.value(&tier.name),
            style.muted("→"),
            decision
        );
        println!("    {} {}", style.muted("reason:"), tier.reason);
    }
    println!();

    println!("{}", style.highlight("Daemon Status"));
    println!(
        "  {} {}",
        style.key("Socket:"),
        style.value(&daemon_status.socket_path)
    );
    println!(
        "  {} {}",
        style.key("Socket exists:"),
        style.value(&daemon_status.socket_exists.to_string())
    );
    println!(
        "  {} {}",
        style.key("Reachable:"),
        style.value(&daemon_status.reachable.to_string())
    );
    if let Some(status) = &daemon_status.status {
        println!("  {} {}", style.key("Status:"), style.value(status));
    }
    if let Some(version) = &daemon_status.version {
        println!("  {} {}", style.key("Version:"), style.value(version));
    }
    if let Some(uptime) = daemon_status.uptime_seconds {
        println!(
            "  {} {}s",
            style.key("Uptime:"),
            style.value(&uptime.to_string())
        );
    }
    if let Some(error) = &daemon_status.error {
        println!("  {} {}", style.key("Error:"), style.value(error));
    }
    println!();

    // Show transfer exclude info including .rchignore
    println!("{}", style.highlight("Transfer Configuration"));
    let config_exclude_count = config.transfer.exclude_patterns.len();
    let project_root = std::env::current_dir().ok();
    let rchignore_count = project_root
        .as_ref()
        .and_then(|root| crate::transfer::parse_rchignore(&root.join(".rchignore")).ok())
        .map(|patterns| patterns.len())
        .unwrap_or(0);
    let effective_count = config_exclude_count + rchignore_count;

    println!(
        "  {} {} {}",
        style.key("Exclude patterns:"),
        style.value(&effective_count.to_string()),
        style.muted(&format!(
            "({} from config, {} from .rchignore)",
            config_exclude_count, rchignore_count
        ))
    );
    if rchignore_count > 0 {
        println!(
            "  {} {}",
            style.key(".rchignore:"),
            style.format_success("detected")
        );
    } else {
        println!(
            "  {} {}",
            style.key(".rchignore:"),
            style.muted("not found")
        );
    }
    println!(
        "  {} {}",
        style.key("Compression:"),
        style.value(&format!("zstd level {}", config.transfer.compression_level))
    );
    println!(
        "  {} {}",
        style.key("Remote base:"),
        style.value(&config.transfer.remote_base)
    );
    println!();

    println!("{}", style.highlight("Worker Selection (simulated)"));
    if let Some(selection) = &worker_selection {
        match &selection.worker {
            Some(worker) => {
                println!(
                    "  {} {}",
                    style.key("Selected:"),
                    style.value(&worker.id.to_string())
                );
                println!(
                    "  {} {}@{}",
                    style.key("Host:"),
                    style.value(&worker.user),
                    style.value(&worker.host)
                );
                println!(
                    "  {} {}",
                    style.key("Slots available:"),
                    style.value(&worker.slots_available.to_string())
                );
                println!("  {} {:.1}", style.key("Speed score:"), worker.speed_score);
                println!(
                    "  {} {}",
                    style.key("Reason:"),
                    style.value(&selection.reason.to_string())
                );
            }
            None => {
                println!(
                    "  {} {}",
                    style.key("Result:"),
                    style.value("No worker selected")
                );
                println!(
                    "  {} {}",
                    style.key("Reason:"),
                    style.value(&selection.reason.to_string())
                );
            }
        }
    } else if !would_intercept {
        println!(
            "  {} {}",
            style.key("Skipped:"),
            style.value("Command would not be intercepted")
        );
    } else if !daemon_status.reachable {
        println!(
            "  {} {}",
            style.key("Skipped:"),
            style.value("Daemon not reachable")
        );
    } else {
        println!(
            "  {} {}",
            style.key("Skipped:"),
            style.value("Selection unavailable")
        );
    }

    Ok(())
}

// =============================================================================
// Self-Test Command
// =============================================================================

#[allow(clippy::too_many_arguments)]
pub async fn self_test(
    action: Option<crate::SelfTestAction>,
    worker: Option<String>,
    all: bool,
    project: Option<std::path::PathBuf>,
    timeout: u64,
    debug: bool,
    scheduled: bool,
    ctx: &OutputContext,
) -> Result<()> {
    match action {
        Some(crate::SelfTestAction::Status) => self_test_status(ctx).await,
        Some(crate::SelfTestAction::History { limit }) => self_test_history(limit, ctx).await,
        None => self_test_run(worker, all, project, timeout, debug, scheduled, ctx).await,
    }
}

async fn self_test_status(ctx: &OutputContext) -> Result<()> {
    let response = send_daemon_command("GET /self-test/status\n").await?;
    let json = extract_json_body(&response).ok_or_else(|| anyhow::anyhow!("Invalid response"))?;
    let status: SelfTestStatusResponse = serde_json::from_str(json)?;

    let _ = ctx.json(&status);
    if ctx.is_json() {
        return Ok(());
    }

    let style = ctx.style();
    println!("{}", style.format_header("Self-Test Status"));
    println!(
        "  {} {} {}",
        style.key("Scheduled"),
        style.muted(":"),
        if status.enabled {
            style.success("Enabled")
        } else {
            style.warning("Disabled")
        }
    );

    if let Some(schedule) = status.schedule.as_ref() {
        println!(
            "  {} {} {}",
            style.key("Schedule"),
            style.muted(":"),
            style.info(schedule)
        );
    }
    if let Some(interval) = status.interval.as_ref() {
        println!(
            "  {} {} {}",
            style.key("Interval"),
            style.muted(":"),
            style.info(interval)
        );
    }
    if let Some(last) = status.last_run.as_ref() {
        println!(
            "  {} {} {} ({} passed, {} failed)",
            style.key("Last run"),
            style.muted(":"),
            style.info(&last.completed_at),
            last.workers_passed,
            last.workers_failed
        );
    }
    if let Some(next) = status.next_run.as_ref() {
        println!(
            "  {} {} {}",
            style.key("Next run"),
            style.muted(":"),
            style.info(next)
        );
    }

    Ok(())
}

async fn self_test_history(limit: usize, ctx: &OutputContext) -> Result<()> {
    let command = format!("GET /self-test/history?limit={}\n", limit);
    let response = send_daemon_command(&command).await?;
    let json = extract_json_body(&response).ok_or_else(|| anyhow::anyhow!("Invalid response"))?;
    let history: SelfTestHistoryResponse = serde_json::from_str(json)?;

    let _ = ctx.json(&history);
    if ctx.is_json() {
        return Ok(());
    }

    let style = ctx.style();
    println!("{}", style.format_header("Self-Test History"));
    if history.runs.is_empty() {
        println!("  {}", style.muted("No self-test runs recorded."));
        return Ok(());
    }

    let rows: Vec<Vec<String>> = history
        .runs
        .iter()
        .map(|run| {
            vec![
                run.id.to_string(),
                run.run_type.clone(),
                run.completed_at.clone(),
                format!("{}ms", run.duration_ms),
                run.workers_passed.to_string(),
                run.workers_failed.to_string(),
            ]
        })
        .collect();

    ctx.table(
        &["ID", "Type", "Completed", "Duration", "Passed", "Failed"],
        &rows,
    );

    for run in &history.runs {
        if run.workers_failed == 0 {
            continue;
        }
        println!(
            "\n  {} {}",
            style.key("Failures for run"),
            style.highlight(&run.id.to_string())
        );
        for result in history
            .results
            .iter()
            .filter(|r| r.run_id == run.id && !r.passed)
        {
            let error = result
                .error
                .clone()
                .unwrap_or_else(|| "unknown".to_string());
            println!(
                "    {} {}: {}",
                StatusIndicator::Error.display(style),
                style.highlight(&result.worker_id),
                style.error(&error)
            );
        }
    }

    Ok(())
}

async fn self_test_run(
    worker: Option<String>,
    all: bool,
    project: Option<std::path::PathBuf>,
    timeout: u64,
    debug: bool,
    scheduled: bool,
    ctx: &OutputContext,
) -> Result<()> {
    let mut worker_ids = Vec::new();

    if scheduled {
        // Scheduled run uses daemon config (ignore worker selection).
    } else if all {
        // Empty worker list signals "all" to daemon.
    } else if let Some(worker) = worker {
        worker_ids.push(worker);
    } else {
        let workers = load_workers_from_config()?;
        let first = workers
            .first()
            .ok_or_else(|| anyhow::anyhow!("No workers configured"))?;
        worker_ids.push(first.id.to_string());
    }

    let mut query = Vec::new();
    for id in &worker_ids {
        query.push(format!("worker={}", urlencoding_encode(id)));
    }
    if all {
        query.push("all=true".to_string());
    }
    if scheduled {
        query.push("scheduled=true".to_string());
    }
    if let Some(path) = project.as_ref() {
        query.push(format!(
            "project={}",
            urlencoding_encode(&path.display().to_string())
        ));
    }
    if timeout > 0 {
        query.push(format!("timeout={}", timeout));
    }
    if debug {
        query.push("debug=true".to_string());
    }

    let command = if query.is_empty() {
        "POST /self-test/run\n".to_string()
    } else {
        format!("POST /self-test/run?{}\n", query.join("&"))
    };

    // Use a spinner while waiting for the daemon to complete self-tests
    let spinner = if !ctx.is_json() {
        let target_desc = if all {
            "all workers".to_string()
        } else if worker_ids.is_empty() {
            "default worker".to_string()
        } else {
            worker_ids.join(", ")
        };
        Some(Spinner::new(
            ctx,
            &format!("Running self-test on {}...", target_desc),
        ))
    } else {
        None
    };

    let response = send_daemon_command(&command).await;

    // Handle response with spinner
    let response = match response {
        Ok(r) => {
            if let Some(ref s) = spinner {
                s.finish_and_clear();
            }
            r
        }
        Err(e) => {
            if let Some(s) = spinner {
                s.finish_error(&format!("Failed: {}", e));
            }
            return Err(e);
        }
    };

    let json = extract_json_body(&response).ok_or_else(|| anyhow::anyhow!("Invalid response"))?;
    let run: SelfTestRunResponse = serde_json::from_str(json)?;

    let _ = ctx.json(&run);
    if ctx.is_json() {
        return Ok(());
    }

    let style = ctx.style();
    println!("{}", style.format_header("Self-Test Result"));
    println!(
        "  {} {} {}",
        style.key("Run"),
        style.muted(":"),
        style.info(&run.run.completed_at)
    );
    println!(
        "  {} {} {} passed, {} failed",
        style.key("Workers"),
        style.muted(":"),
        style.success(&run.run.workers_passed.to_string()),
        style.error(&run.run.workers_failed.to_string())
    );

    for result in &run.results {
        let status = if result.passed {
            StatusIndicator::Success.display(style)
        } else {
            StatusIndicator::Error.display(style)
        };
        let detail = if result.passed {
            format!(
                "remote={}ms local={}ms",
                result.remote_time_ms.unwrap_or(0),
                result.local_time_ms.unwrap_or(0)
            )
        } else {
            result
                .error
                .clone()
                .unwrap_or_else(|| "unknown error".to_string())
        };
        println!(
            "  {} {}: {}",
            status,
            style.highlight(&result.worker_id),
            detail
        );

        // Verbose mode: show timing breakdown and additional info
        if ctx.is_verbose() {
            if result.passed {
                // Calculate speedup
                if let (Some(remote), Some(local)) = (result.remote_time_ms, result.local_time_ms) {
                    let speedup = if remote > 0 {
                        local as f64 / remote as f64
                    } else {
                        1.0
                    };
                    println!("      {} {:.1}x speedup", style.muted("→"), speedup);
                    // Show hash comparison in verbose mode
                    if let (Some(local_hash), Some(remote_hash)) =
                        (&result.local_hash, &result.remote_hash)
                    {
                        let hash_match = if local_hash == remote_hash {
                            style.success("match")
                        } else {
                            style.error("MISMATCH")
                        };
                        println!("      {} hash {}", style.muted("→"), hash_match);
                    }
                }
            } else {
                // For failed tests, show more error context
                if let Some(ref err) = result.error
                    && err.len() > 50
                {
                    println!("      {} {}", style.muted("error:"), style.error(err));
                }
            }
        }
    }

    Ok(())
}

// =============================================================================
// Status Overview Command
// =============================================================================

pub async fn status_overview(workers: bool, jobs: bool, ctx: &OutputContext) -> Result<()> {
    use crate::status_types::{
        RemediationHint, RepoConvergenceStatusFromApi, STATUS_SCHEMA_VERSION, SystemPosture,
        UnifiedStatusResponse, generate_convergence_remediations, generate_worker_remediations,
    };

    // Query daemon for full status.
    let response = send_daemon_command("GET /status\n").await?;
    let json = extract_json_body(&response)
        .ok_or_else(|| anyhow::anyhow!("Invalid response format from daemon"))?;
    let status: DaemonFullStatusResponse =
        serde_json::from_str(json).context("Failed to parse daemon status response")?;

    // Query convergence status (best-effort; don't fail if endpoint unreachable).
    let convergence = match send_daemon_command("GET /repo-convergence/status\n").await {
        Ok(conv_response) => extract_json_body(&conv_response)
            .and_then(|j| serde_json::from_str::<RepoConvergenceStatusFromApi>(j).ok()),
        Err(_) => None,
    };

    // Compute system posture.
    let posture = SystemPosture::from_status(&status);

    // Generate remediation hints from all signals.
    let mut remediation_hints: Vec<RemediationHint> = generate_worker_remediations(&status.workers);
    if let Some(ref conv) = convergence {
        remediation_hints.extend(generate_convergence_remediations(conv));
    }

    // Posture-level hints.
    match &posture {
        SystemPosture::LocalOnly => {
            if status.daemon.workers_total == 0 {
                remediation_hints.push(RemediationHint {
                    reason_code: "no_workers_configured".into(),
                    severity: "critical".into(),
                    message: "No workers configured; all builds run locally".into(),
                    suggested_action: "rch workers add <host> or edit ~/.config/rch/workers.toml"
                        .into(),
                    worker_id: None,
                });
            } else {
                remediation_hints.push(RemediationHint {
                    reason_code: "all_workers_down".into(),
                    severity: "critical".into(),
                    message: "All workers unreachable; builds falling back to local".into(),
                    suggested_action: "rch doctor --fix".into(),
                    worker_id: None,
                });
            }
        }
        SystemPosture::Degraded => {
            remediation_hints.push(RemediationHint {
                reason_code: "partial_capacity".into(),
                severity: "warning".into(),
                message: format!(
                    "Operating at reduced capacity: {}/{} workers healthy",
                    status.daemon.workers_healthy, status.daemon.workers_total
                ),
                suggested_action: "rch workers probe --all".into(),
                worker_id: None,
            });
        }
        SystemPosture::RemoteReady => {}
    }

    if ctx.is_json() {
        let unified = UnifiedStatusResponse {
            schema_version: STATUS_SCHEMA_VERSION.to_string(),
            posture_description: posture.description().to_string(),
            posture,
            daemon: status,
            convergence,
            remediation_hints,
        };
        let _ = ctx.json(&ApiResponse::ok("status", &unified));
        return Ok(());
    }

    // In verbose mode, always show all sections (workers and jobs)
    let show_workers = workers || ctx.is_verbose();
    let show_jobs = jobs || ctx.is_verbose();

    crate::status_display::render_full_status(
        &status,
        show_workers,
        show_jobs,
        convergence.as_ref(),
        &remediation_hints,
        &posture,
        ctx.style(),
    );

    // Verbose mode: show additional details not in standard display
    if ctx.is_verbose() {
        let style = ctx.theme();
        println!();
        println!("{}", style.format_header("Verbose Details"));
        println!();

        // Config source info
        println!(
            "  {} {} {}",
            style.key("Socket"),
            style.muted(":"),
            style.value(&status.daemon.socket_path)
        );
        println!(
            "  {} {} {}",
            style.key("Started"),
            style.muted(":"),
            style.value(&status.daemon.started_at)
        );

        // Show alerts if any
        if !status.alerts.is_empty() {
            println!();
            println!("  {}", style.key("Active Alerts:"));
            for alert in &status.alerts {
                let severity_style = match alert.severity.as_str() {
                    "critical" | "error" => style.error(&alert.severity),
                    "warning" => style.warning(&alert.severity),
                    _ => style.info(&alert.severity),
                };
                println!(
                    "    {} [{}] {}",
                    severity_style,
                    style.muted(&alert.created_at),
                    style.value(&alert.message)
                );
            }
        }

        // Show issues if any
        if !status.issues.is_empty() {
            println!();
            println!("  {}", style.key("Known Issues:"));
            for issue in &status.issues {
                println!(
                    "    {} {} - {}",
                    style.warning("⚠"),
                    style.key(&issue.summary),
                    style.muted(issue.remediation.as_deref().unwrap_or(""))
                );
            }
        }
    }

    Ok(())
}

// =============================================================================
// Check Command
// =============================================================================

/// Quick health check: "Is RCH working right now?"
///
/// Returns exit codes:
/// - 0: Ready (daemon running, all workers healthy)
/// - 1: Degraded (daemon running, some workers unreachable)
/// - 2: Not ready (daemon not running or fatal issues)
pub async fn check(ctx: &OutputContext) -> Result<()> {
    #[derive(Debug, Clone, serde::Serialize, schemars::JsonSchema)]
    struct CheckResponse {
        status: String,
        exit_code: i32,
        daemon: Option<DaemonCheckInfo>,
        workers: WorkersCheckInfo,
        hook: HookCheckInfo,
        issues: Vec<String>,
    }

    #[derive(Debug, Clone, serde::Serialize, schemars::JsonSchema)]
    struct DaemonCheckInfo {
        running: bool,
        pid: Option<u32>,
        uptime_secs: Option<u64>,
    }

    #[derive(Debug, Clone, serde::Serialize, schemars::JsonSchema)]
    struct WorkersCheckInfo {
        total: usize,
        healthy: usize,
        unhealthy: Vec<String>,
    }

    #[derive(Debug, Clone, serde::Serialize, schemars::JsonSchema)]
    struct HookCheckInfo {
        installed: bool,
    }

    // Try to query daemon status
    let daemon_result = send_daemon_command("GET /status\n").await;

    let (status, exit_code, daemon_info, workers_info, issues) = match daemon_result {
        Ok(response) => {
            match extract_json_body(&response) {
                Some(json) => {
                    match serde_json::from_str::<DaemonFullStatusResponse>(json) {
                        Ok(status) => {
                            // Daemon is running - determine health
                            let healthy_count = status.daemon.workers_healthy;
                            let total_count = status.daemon.workers_total;
                            let unhealthy: Vec<String> = status
                                .workers
                                .iter()
                                .filter(|w| {
                                    w.status != "healthy"
                                        && w.status != "draining"
                                        && w.status != "drained"
                                })
                                .map(|w| w.id.clone())
                                .collect();

                            let daemon_info = DaemonCheckInfo {
                                running: true,
                                pid: Some(status.daemon.pid),
                                uptime_secs: Some(status.daemon.uptime_secs),
                            };

                            let workers_info = WorkersCheckInfo {
                                total: total_count,
                                healthy: healthy_count,
                                unhealthy: unhealthy.clone(),
                            };

                            let mut issues_list: Vec<String> = unhealthy
                                .iter()
                                .map(|w| format!("Worker {} is unreachable", w))
                                .collect();

                            // Add daemon-reported issues
                            for issue in &status.issues {
                                issues_list.push(issue.summary.clone());
                            }

                            if total_count == 0 {
                                (
                                    "not_ready".to_string(),
                                    2,
                                    daemon_info,
                                    workers_info,
                                    vec!["No workers configured".to_string()],
                                )
                            } else if healthy_count == total_count {
                                (
                                    "ready".to_string(),
                                    0,
                                    daemon_info,
                                    workers_info,
                                    issues_list,
                                )
                            } else if healthy_count > 0 {
                                (
                                    "degraded".to_string(),
                                    1,
                                    daemon_info,
                                    workers_info,
                                    issues_list,
                                )
                            } else {
                                issues_list.insert(0, "All workers are unreachable".to_string());
                                (
                                    "not_ready".to_string(),
                                    2,
                                    daemon_info,
                                    workers_info,
                                    issues_list,
                                )
                            }
                        }
                        Err(_) => {
                            let daemon_info = DaemonCheckInfo {
                                running: true,
                                pid: None,
                                uptime_secs: None,
                            };
                            let workers_info = WorkersCheckInfo {
                                total: 0,
                                healthy: 0,
                                unhealthy: vec![],
                            };
                            (
                                "not_ready".to_string(),
                                2,
                                daemon_info,
                                workers_info,
                                vec!["Daemon returned invalid response".to_string()],
                            )
                        }
                    }
                }
                None => {
                    let daemon_info = DaemonCheckInfo {
                        running: true,
                        pid: None,
                        uptime_secs: None,
                    };
                    let workers_info = WorkersCheckInfo {
                        total: 0,
                        healthy: 0,
                        unhealthy: vec![],
                    };
                    (
                        "not_ready".to_string(),
                        2,
                        daemon_info,
                        workers_info,
                        vec!["Daemon returned invalid response format".to_string()],
                    )
                }
            }
        }
        Err(_) => {
            // Daemon not running or socket not found
            let daemon_info = DaemonCheckInfo {
                running: false,
                pid: None,
                uptime_secs: None,
            };
            let workers_info = WorkersCheckInfo {
                total: 0,
                healthy: 0,
                unhealthy: vec![],
            };
            (
                "not_ready".to_string(),
                2,
                daemon_info,
                workers_info,
                vec!["Daemon not running".to_string()],
            )
        }
    };

    // Check if hook is installed
    let hook_installed = {
        use crate::agent::{AgentKind, HookStatus, check_hook_status};
        matches!(
            check_hook_status(AgentKind::ClaudeCode),
            Ok(HookStatus::Installed)
        )
    };

    let hook_info = HookCheckInfo {
        installed: hook_installed,
    };

    let response = CheckResponse {
        status: status.clone(),
        exit_code,
        daemon: Some(daemon_info),
        workers: workers_info.clone(),
        hook: hook_info.clone(),
        issues: issues.clone(),
    };

    // JSON output
    if ctx.is_json() {
        let _ = ctx.json(&ApiResponse::ok("check", &response));
        if exit_code != 0 {
            std::process::exit(exit_code);
        }
        return Ok(());
    }

    // Human-readable output
    let style = ctx.style();

    match status.as_str() {
        "ready" => {
            println!(
                "{} RCH is ready ({}/{} workers healthy)",
                style.success("\u{2713}"),
                workers_info.healthy,
                workers_info.total
            );
        }
        "degraded" => {
            println!(
                "{} RCH degraded: {}/{} workers unreachable ({})",
                style.warning("\u{26A0}"),
                workers_info.unhealthy.len(),
                workers_info.total,
                workers_info.unhealthy.join(", ")
            );
        }
        "not_ready" => {
            let issue = issues
                .first()
                .map(|s| s.as_str())
                .unwrap_or("unknown error");
            println!("{} RCH not ready: {}", style.error("\u{2717}"), issue);
        }
        _ => {}
    }

    // Verbose mode: show detailed breakdown
    if ctx.is_verbose() {
        println!();
        println!("{}", style.format_header("Health Check Details"));
        println!();

        // Daemon status
        if let Some(ref d) = response.daemon {
            let daemon_status = if d.running {
                format!(
                    "{} running (pid {}, uptime {})",
                    style.success("\u{2713}"),
                    d.pid.unwrap_or(0),
                    humanize_duration(d.uptime_secs.unwrap_or(0))
                )
            } else {
                format!("{} not running", style.error("\u{2717}"))
            };
            println!(
                "  {} {} {}",
                style.key("Daemon"),
                style.muted(":"),
                daemon_status
            );
        }

        // Workers status
        let workers_status = if workers_info.total == 0 {
            format!("{} no workers configured", style.warning("\u{26A0}"))
        } else if workers_info.healthy == workers_info.total {
            format!(
                "{} all healthy ({}/{})",
                style.success("\u{2713}"),
                workers_info.healthy,
                workers_info.total
            )
        } else {
            format!(
                "{} {}/{} healthy",
                style.warning("\u{26A0}"),
                workers_info.healthy,
                workers_info.total
            )
        };
        println!(
            "  {} {} {}",
            style.key("Workers"),
            style.muted(":"),
            workers_status
        );

        // Hook status
        let hook_status = if hook_info.installed {
            format!("{} installed", style.success("\u{2713}"))
        } else {
            format!("{} not installed", style.warning("\u{26A0}"))
        };
        println!(
            "  {} {} {}",
            style.key("Hook"),
            style.muted(":"),
            hook_status
        );

        // Issues
        if !issues.is_empty() {
            println!();
            println!("  {}", style.key("Issues:"));
            for issue in &issues {
                println!("    {} {}", style.warning("\u{26A0}"), issue);
            }
        }

        println!();
        println!(
            "  {} {} {}",
            style.key("Overall"),
            style.muted(":"),
            match status.as_str() {
                "ready" => style.success("RCH is ready").to_string(),
                "degraded" => style.warning("RCH is degraded").to_string(),
                _ => style.error("RCH is not ready").to_string(),
            }
        );
    }

    // Exit with appropriate code
    if exit_code != 0 {
        std::process::exit(exit_code);
    }

    Ok(())
}
