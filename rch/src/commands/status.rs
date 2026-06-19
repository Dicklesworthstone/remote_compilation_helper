//! Status and diagnostics commands.
//!
//! This module contains commands for diagnosing RCH behavior, running self-tests,
//! and checking overall system status.

use crate::hook::{
    cargo_job_count_for_command, estimate_cores_for_command, extract_project_name_with_policy,
    preferred_workers_from_env, query_daemon, release_worker, required_runtime_for_kind,
};
use crate::status_types::{
    DaemonFullStatusResponse, IssueFromApi, SelfTestHistoryResponseFromApi,
    SelfTestResultRecordFromApi, SelfTestRunResponseFromApi, SelfTestStatusResponseFromApi,
    extract_json_body,
};
use crate::toolchain::detect_toolchain;
use crate::ui::context::OutputContext;
use crate::ui::progress::Spinner;
use crate::ui::theme::{StatusIndicator, Theme};
use anyhow::{Context, Result};
use rch_common::fleet_smoke_profile::{
    ProfileMode, ScenarioAction, SmokeProfileEvent, SmokeProfileInputs, SmokeProfilePlan,
    SmokeScenario, plan_smoke_profile,
};
use rch_common::{
    ApiResponse, CommandPriority, PlacementPlan, RequestedWorkerFacts, RequestedWorkerOutcome,
    RequiredRuntime, WorkerConfig, evaluate_requested_worker, normalize_project_path_with_policy,
    resolve_placement,
};
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

pub(super) fn build_diagnose_slot_estimate(
    kind: Option<rch_common::CompilationKind>,
    command: &str,
    config: &rch_common::CompilationConfig,
) -> (u32, Option<u32>) {
    (
        estimate_cores_for_command(kind, command, config),
        cargo_job_count_for_command(command),
    )
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
    let no_worker_reason = if daemon_reachable {
        worker_selection
            .as_ref()
            .map(|s| s.reason.to_string())
            .unwrap_or_else(|| "No worker available".to_string())
    } else {
        "Daemon not reachable".to_string()
    };
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
            Some(no_worker_reason.clone())
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
        skip_reason: if !worker_selected {
            Some(no_worker_reason.clone())
        } else {
            None
        },
        estimated_duration_ms: None, // Depends on project size
    });

    // Step 5: Remote execution
    steps.push(DryRunPipelineStep {
        step: 5,
        name: "Remote execution".to_string(),
        description: "Execute compilation command on worker".to_string(),
        skipped: !worker_selected,
        skip_reason: if !worker_selected {
            Some(no_worker_reason.clone())
        } else {
            None
        },
        estimated_duration_ms: None, // Depends on build
    });

    // Step 6: Artifact retrieval
    steps.push(DryRunPipelineStep {
        step: 6,
        name: "Artifact retrieval".to_string(),
        description: "Retrieve build artifacts from remote worker".to_string(),
        skipped: !worker_selected,
        skip_reason: if !worker_selected {
            Some(no_worker_reason.clone())
        } else {
            None
        },
        estimated_duration_ms: None, // Would need rsync dry-run
    });

    let reason = if worker_selected {
        "compilation command meets threshold, worker available".to_string()
    } else if !daemon_reachable {
        "compilation command meets threshold, but daemon is not reachable".to_string()
    } else {
        format!("compilation command meets threshold, but no worker selected: {no_worker_reason}")
    };

    DryRunSummary {
        would_offload: worker_selected,
        reason,
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
/// Resolve the canonical placement plan from the environment and refine it with
/// the simulated worker-selection result. When a worker was explicitly
/// requested, the requested-worker outcome is evaluated against the daemon's
/// per-worker selection diagnostics so an inadmissible requested worker yields a
/// structured refusal instead of a silent swap
/// (bd-...remediation-ocv9i.13.5).
fn build_diagnose_placement(worker_selection: &Option<DiagnoseWorkerSelection>) -> PlacementPlan {
    let mut plan = resolve_placement(|key| std::env::var(key).ok());

    let effective_worker = worker_selection
        .as_ref()
        .and_then(|s| s.worker.as_ref())
        .map(|w| w.id.to_string());
    plan = plan.with_effective_worker(effective_worker.clone());

    // Refine the requested-worker outcome from the live selection diagnostics.
    if let Some(requested) = plan.requested_worker.clone() {
        // A comma list requests several; evaluate the primary (first) entry.
        let primary = requested
            .split(',')
            .map(str::trim)
            .find(|s| !s.is_empty())
            .unwrap_or("");
        let outcome = match worker_selection
            .as_ref()
            .and_then(|s| s.diagnostics.as_ref())
        {
            Some(diag) => {
                match diag
                    .workers
                    .iter()
                    .find(|w| w.worker_id.as_str() == primary)
                {
                    Some(wd) => {
                        let facts = RequestedWorkerFacts {
                            requested: Some(primary.to_string()),
                            exists: true,
                            admin_disabled: wd.status.eq_ignore_ascii_case("disabled"),
                            draining_or_drained: wd.status.to_ascii_lowercase().contains("drain"),
                            reachable: !wd.status.eq_ignore_ascii_case("unreachable"),
                            temporarily_bypassed: wd.circuit_state.eq_ignore_ascii_case("open")
                                || wd.status.to_ascii_lowercase().contains("bypass"),
                            platform_matches: !wd
                                .reason_codes
                                .iter()
                                .any(|c| c.contains("os_arch") || c.contains("platform")),
                            has_required_runtime: wd.runtime_available,
                            project_excluded: wd.active_project_excluded,
                            has_free_slots: wd.available_slots >= wd.estimated_cores,
                        };
                        evaluate_requested_worker(&facts)
                    }
                    // Requested worker is not among the configured workers.
                    None => evaluate_requested_worker(&RequestedWorkerFacts {
                        requested: Some(primary.to_string()),
                        exists: false,
                        ..RequestedWorkerFacts::none()
                    }),
                }
            }
            // No diagnostics (daemon unreachable / not intercepted): leave the
            // outcome as "requested, pending fleet evaluation" but record honor
            // when the effective worker matches the request.
            None => {
                if effective_worker.as_deref() == Some(primary) {
                    evaluate_requested_worker(&RequestedWorkerFacts::admissible(primary))
                } else {
                    RequestedWorkerOutcome::requested()
                }
            }
        };
        plan = plan.with_requested_worker_outcome(outcome);
    }

    plan
}

pub async fn diagnose(command: &str, dry_run: bool, ctx: &OutputContext) -> Result<()> {
    use rch_common::classify_command_detailed;

    let style = ctx.theme();
    let loaded = crate::config::load_config_with_sources()?;
    let config = loaded.config;
    // Build the path topology policy from the loaded config so that any
    // normalization diagnostics reference the configured roots rather than
    // the compiled-in `/data/projects` + `/dp` defaults. See GitHub #9.
    let topology_policy = config.path_topology.to_policy();

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
        let (estimated_cores, cargo_jobs) =
            build_diagnose_slot_estimate(details.classification.kind, command, &config.compilation);
        let project_root = std::env::current_dir().ok();
        let normalized_project_root = project_root.as_ref().and_then(|path| {
            normalize_project_path_with_policy(path, &topology_policy)
                .map(|normalized| normalized.canonical_path().to_path_buf())
                .ok()
        });
        let project = extract_project_name_with_policy(&topology_policy);
        let toolchain = project_root
            .as_ref()
            .or(normalized_project_root.as_ref())
            .and_then(|root| detect_toolchain(root).ok());
        let preferred_workers = preferred_workers_from_env();

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
            &preferred_workers,
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
                    cargo_jobs,
                    worker: response.worker.clone(),
                    reason: response.reason.clone(),
                    diagnostics: response.diagnostics.clone(),
                });
                if let Some(worker) = response.worker.as_ref() {
                    debug!(
                        "Worker selected id='{}' slots_remaining_after_reservation={} speed_score={:.2} reason={:?}",
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

    // Resolve the canonical placement plan (env controls + requested-worker
    // admissibility against the simulated selection).
    let placement = build_diagnose_placement(&worker_selection);

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
            placement: placement.clone(),
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
                    style.key("Slots remaining after reservation:"),
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
    println!();

    println!("{}", style.highlight("Placement Controls"));
    println!(
        "  {} {}",
        style.key("Requested worker:"),
        style.value(placement.requested_worker.as_deref().unwrap_or("(none)"))
    );
    println!(
        "  {} {}",
        style.key("Effective worker:"),
        style.value(placement.effective_worker.as_deref().unwrap_or("(none)"))
    );
    if let Some(profile) = placement.requested_profile.as_deref() {
        println!(
            "  {} {}",
            style.key("Requested profile:"),
            style.value(profile)
        );
    }
    println!(
        "  {} {}",
        style.key("Strict remote:"),
        style.value(placement.strict_remote_policy.as_str())
    );
    println!(
        "  {} {}",
        style.key("Queue policy:"),
        style.value(placement.queue_policy.as_str())
    );
    println!(
        "  {} {}",
        style.key("Visibility:"),
        style.value(placement.visibility_mode.as_str())
    );
    if let Some(ms) = placement.wait_timeout_ms {
        println!(
            "  {} {}ms",
            style.key("Wait timeout:"),
            style.value(&ms.to_string())
        );
    }
    println!(
        "  {} {}",
        style.key("Target dir:"),
        style.value(placement.target_dir_policy.as_str())
    );
    // Requested-worker outcome: honored, refused (with reason + next action),
    // or not-requested.
    let outcome = &placement.requested_worker_outcome;
    if outcome.status.is_refusal() {
        println!(
            "  {} {} {}",
            style.key("Requested worker:"),
            style.format_warning(&format!("REFUSED ({})", outcome.status.as_str())),
            style.muted(
                &outcome
                    .reason_code
                    .as_deref()
                    .map(|c| format!("[{c}]"))
                    .unwrap_or_default()
            )
        );
        if let Some(action) = outcome.next_action.as_deref() {
            println!("    {} {}", style.muted("next:"), style.value(action));
        }
    } else {
        println!(
            "  {} {}",
            style.key("Requested-worker outcome:"),
            style.value(outcome.status.as_str())
        );
    }
    for diag in &placement.diagnostics {
        println!(
            "  {} {} {}",
            StatusIndicator::Warning.display(style),
            style.muted(&format!("[{}]", diag.control)),
            style.warning(&diag.message)
        );
    }

    Ok(())
}

/// `rch admit -- <command>`: a fast, read-only admission preflight. Classifies
/// the command, derives the capabilities a worker must have, and returns a
/// decisive Offload / Local / Queue / Defer recommendation before any expensive
/// work starts. Pure classification — no network side effects; the daemon
/// candidate/rejection query that further refines the recommendation lands with
/// the selection-RPC work (bd-...12.3).
pub async fn admit(command: &str, ctx: &OutputContext) -> Result<()> {
    use rch_common::admit_preflight::preflight;

    // Proof/strict-remote policy mirrors the ControlState surface
    // (RCH_REQUIRE_REMOTE / RCH_FORCE_REMOTE).
    let proof_policy = ["RCH_REQUIRE_REMOTE", "RCH_FORCE_REMOTE"]
        .iter()
        .any(|key| {
            std::env::var(key).is_ok_and(|v| {
                matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
        });

    let pf = preflight(command, proof_policy);

    if ctx.is_json() {
        let _ = ctx.json(&ApiResponse::ok("admit", &pf));
        return Ok(());
    }

    let style = ctx.theme();
    println!("{}", style.format_header("RCH Admit"));
    println!();
    println!("{} {}", style.key("Recommendation:"), {
        let r = pf.base_recommendation.as_str();
        match pf.base_recommendation {
            rch_common::admit_preflight::AdmitRecommendation::Offload => style.format_success(r),
            rch_common::admit_preflight::AdmitRecommendation::Local => style.format_warning(r),
            _ => style.value(r).to_string(),
        }
    });
    println!("{} {}", style.key("Compilation:"), pf.is_compilation);
    if let Some(family) = &pf.family {
        println!("{} {}", style.key("Family:"), style.value(family));
    }
    if pf.compound.len() > 1 {
        println!(
            "{} {} parts",
            style.key("Compound:"),
            style.value(&pf.compound.len().to_string())
        );
    }
    let req = &pf.required;
    let mut needs: Vec<String> = Vec::new();
    if req.needs_cargo {
        needs.push("cargo".to_string());
    }
    if req.needs_bun {
        needs.push("bun".to_string());
    }
    for t in &req.needs_targets {
        needs.push(format!("target:{t}"));
    }
    for tc in &req.needs_toolchains {
        needs.push(format!("toolchain:{tc}"));
    }
    println!(
        "{} {}",
        style.key("Required capabilities:"),
        if needs.is_empty() {
            style.muted("none").to_string()
        } else {
            style.value(&needs.join(", ")).to_string()
        }
    );
    if pf.proof_policy {
        println!("{} {}", style.key("Proof policy:"), style.value("strict"));
    }
    println!();
    println!("{}", style.muted(&pf.detail));
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
    smoke: bool,
    soak: bool,
    dry_run: bool,
    ctx: &OutputContext,
) -> Result<()> {
    // The real-fleet smoke/soak profile is a distinct mode from the per-worker
    // canary self-test (bd-session-history-remediation-ocv9i.16.6).
    if smoke {
        return self_test_smoke(worker, all, dry_run, soak, ctx).await;
    }
    match action {
        Some(crate::SelfTestAction::Status) => self_test_status(ctx).await,
        Some(crate::SelfTestAction::History { limit }) => self_test_history(limit, ctx).await,
        None => self_test_run(worker, all, project, timeout, debug, scheduled, ctx).await,
    }
}

async fn self_test_status(ctx: &OutputContext) -> Result<()> {
    let response = send_daemon_command("GET /self-test/status\n").await?;
    let json = extract_json_body(&response).ok_or_else(|| anyhow::anyhow!("Invalid response"))?;
    let status: SelfTestStatusResponseFromApi = serde_json::from_str(json)?;

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
    let history: SelfTestHistoryResponseFromApi = serde_json::from_str(json)?;

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
    let run: SelfTestRunResponseFromApi = serde_json::from_str(json)?;

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

    let mut timed_out = 0usize;
    for result in &run.results {
        let status = if result.passed {
            StatusIndicator::Success.display(style)
        } else {
            StatusIndicator::Error.display(style)
        };
        // A timeout is a distinct failure class; count it separately so the
        // end-of-run summary can tell the agent whether it was a wedged
        // worker versus a real regression (bd-nuuqt).
        let is_timeout = result
            .error
            .as_deref()
            .is_some_and(|e| e.contains("[RCH-E203]") || e.to_lowercase().contains("timed out"));
        if is_timeout {
            timed_out += 1;
        }
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

        if ctx.is_verbose() {
            debug!(target: "rch::verbose", worker_id = %result.worker_id, "rendering verbose self-test result details");
            for line in render_self_test_result_verbose_lines(result, style) {
                println!("{line}");
            }
        }
    }

    // Final one-line summary so agents watching --all runs can tell at a
    // glance whether a failure is a timeout (likely transient/wedged worker)
    // or a real self-test failure (bd-nuuqt).
    let ok = run.run.workers_passed;
    let failed_other = run.run.workers_failed.saturating_sub(timed_out);
    println!(
        "\n{} {} ok, {} timed out, {} failed.",
        style.muted("Summary:"),
        style.success(&ok.to_string()),
        if timed_out > 0 {
            style.warning(&timed_out.to_string())
        } else {
            style.muted("0")
        },
        if failed_other > 0 {
            style.error(&failed_other.to_string())
        } else {
            style.muted("0")
        }
    );

    Ok(())
}

// =============================================================================
// Real-fleet smoke/soak validation profile
// (bd-session-history-remediation-ocv9i.16.6)
// =============================================================================
//
// `rch self-test --smoke` plans the bounded real-fleet validation profile from
// observed environment (config + daemon reachability) and emits the structured
// `SmokeProfileEvent` JSONL trace operators attach to Beads close reasons. The
// scenario set, skip/refusal logic, and JSONL schema are owned by the pure
// `rch_common::fleet_smoke_profile` foundation (single source of truth) — this
// consumer gathers inputs, runs the planner, performs the client-side daemon
// reachability scenario for real, drives the live per-worker SSH probe scenarios
// (capabilities + disk/inode admission, via the mock-SSH-tested executor
// orchestrator), and renders/persists the trace. The remaining daemon/pipeline
// scenarios (cargo canary, artifact retrieval, queue attach/cancel, desired-vs-
// live fleet) and the client-side proof-mode refusal stay `planned` for now.

/// Owning bead id for the smoke-profile JSONL trace.
const SMOKE_BEAD_ID: &str = "bd-session-history-remediation-ocv9i.16.6";

/// Number of repeated per-worker probe passes a `--soak` run performs. Soak is a
/// bounded endurance check that the cheap, idempotent per-worker probes (exact
/// user/path capabilities + disk/inode headroom) stay green across repeated
/// passes; a single smoke run does exactly one pass. Full load/endurance soak
/// (repeated cargo canaries over time) belongs to the daemon-pipeline scenarios.
const SOAK_PASSES: usize = 3;

/// The build-root path(s) the disk/inode admission scenario probes for headroom.
/// Derived from the effective `transfer.remote_base` (where offloaded builds
/// land), falling back to the documented default when config is unavailable.
///
/// The build root itself may not exist yet on a freshly-provisioned worker (it
/// is created on the first offloaded build), so we ALSO probe its parent mount,
/// which always exists and shares the relevant filesystem. The disk executor
/// skips non-existent roots and reports the worst pressure across those present,
/// so a fresh worker still yields a real reading instead of `Unknown`. Mirrors
/// the daemon recovery prober, which probes both the base and its parent.
fn smoke_disk_roots() -> Vec<String> {
    let base = crate::config::load_config_with_sources()
        .ok()
        .map(|loaded| loaded.config.transfer.remote_base)
        .unwrap_or_else(rch_common::types::default_remote_base);
    let mut roots = vec![base.clone()];
    if let Some(parent) = std::path::Path::new(&base)
        .parent()
        .and_then(std::path::Path::to_str)
        && !parent.is_empty()
        && parent != "/"
        && parent != base
    {
        roots.push(parent.to_string());
    }
    roots
}

/// Decide the DesiredVsLiveFleet smoke outcome from the fleet status report.
///
/// The inventory is "consistent" when no desired worker is sustained-absent from
/// live eligibility (no [`absence_alerts`](rch_common::fleet_status::FleetStatusReport::absence_alerts))
/// and the fleet has not collapsed to zero usable workers. Present-but-degraded
/// workers (busy, disk pressure, stale telemetry) are NOT inventory drift — they
/// are in the pool, just not ready — so this deliberately does not key off the
/// general `problem_class`. Pure so it is unit-testable without a daemon.
fn smoke_fleet_consistency(
    report: &rch_common::fleet_status::FleetStatusReport,
) -> (bool, Option<String>) {
    if report.capacity_collapsed() {
        return (false, Some("fleet_capacity_collapsed".to_string()));
    }
    if !report.absence_alerts.is_empty() {
        return (false, Some("fleet_workers_absent".to_string()));
    }
    (true, None)
}

/// Fetch the daemon full status and fold it into a fleet status report (reuses
/// the same `GET /status` + [`build_fleet_status_report`] path as `rch status
/// --fleet`). Used by the DesiredVsLiveFleet smoke scenario.
async fn fetch_fleet_status_report() -> Result<rch_common::fleet_status::FleetStatusReport> {
    let response = send_daemon_command("GET /status\n").await?;
    let json = extract_json_body(&response)
        .ok_or_else(|| anyhow::anyhow!("Invalid response format from daemon"))?;
    let status: DaemonFullStatusResponse =
        serde_json::from_str(json).context("Failed to parse daemon status response")?;
    Ok(build_fleet_status_report(&status))
}

/// Build the smoke-profile inputs from observed environment + flags. Pure so the
/// input-derivation is unit-testable without a daemon or workers.
fn build_smoke_inputs(
    workers_configured: bool,
    daemon_reachable: bool,
    dry_run: bool,
    soak: bool,
    selected_worker: Option<String>,
) -> SmokeProfileInputs {
    SmokeProfileInputs {
        workers_configured,
        // Remote execution can proceed only if the daemon is up AND at least one
        // worker is configured — a bounded, honest proxy for full admission that
        // drives the proof-mode-refusal scenario decision.
        remote_execution_available: daemon_reachable && workers_configured,
        dry_run,
        mode: if soak {
            ProfileMode::Soak
        } else {
            ProfileMode::Smoke
        },
        selected_worker,
    }
}

/// Generate one `planned` JSONL event per scenario, in run order. Pure so the
/// trace shape is unit-testable. A complete planned trace is emitted even for a
/// dry-run (the foundation's design), so the JSONL is always auditable.
fn smoke_planned_events(
    plan: &SmokeProfilePlan,
    run_id: &str,
    representative_worker: Option<&str>,
) -> Vec<SmokeProfileEvent> {
    plan.scenarios
        .iter()
        .map(|planned| {
            SmokeProfileEvent::planned(
                run_id,
                SMOKE_BEAD_ID,
                representative_worker.map(str::to_string),
                planned,
            )
        })
        .collect()
}

/// Persist the JSONL trace under the cache dir (best-effort). Returns the path so
/// operators can attach it to a Beads close reason and CI can self-validate it.
fn write_smoke_jsonl(run_id: &str, events: &[SmokeProfileEvent]) -> Option<String> {
    let dir = dirs::cache_dir()?.join("rch").join("smoke");
    std::fs::create_dir_all(&dir).ok()?;
    let path = dir.join(format!("{run_id}.jsonl"));
    let mut buf = String::new();
    for event in events {
        let line = serde_json::to_string(event).ok()?;
        buf.push_str(&line);
        buf.push('\n');
    }
    std::fs::write(&path, buf).ok()?;
    Some(path.display().to_string())
}

async fn self_test_smoke(
    worker: Option<String>,
    all: bool,
    dry_run: bool,
    soak: bool,
    ctx: &OutputContext,
) -> Result<()> {
    let workers = load_workers_from_config().unwrap_or_default();
    let workers_configured = !workers.is_empty();

    // Probe daemon reachability — this both feeds the plan and IS the real result
    // of the daemon-reachability scenario.
    let probe_start = std::time::Instant::now();
    let daemon_reachable = send_daemon_command("GET /health\n").await.is_ok();
    let probe_ms = u64::try_from(probe_start.elapsed().as_millis()).unwrap_or(u64::MAX);

    // A single --worker selects that worker; --all (or neither) is fleet-wide.
    let selected_worker = if all { None } else { worker };
    let inputs = build_smoke_inputs(
        workers_configured,
        daemon_reachable,
        dry_run,
        soak,
        selected_worker.clone(),
    );
    let plan = plan_smoke_profile(&inputs);

    let run_id = uuid::Uuid::new_v4().to_string();

    // For a single `--worker` the planned per-worker events are scoped to that
    // worker; a fleet-wide run (`--all` or the default) leaves worker_id unset,
    // because the plan is not tied to one worker — per-worker execution is the
    // live runner's job and would emit one event per worker. Attributing a
    // fleet-wide plan to an arbitrary `workers.first()` would mislead.
    let mut events = smoke_planned_events(&plan, &run_id, selected_worker.as_deref());

    // Execute the one fully client-side scenario for real: daemon reachability.
    // The per-worker SSH scenarios then execute live (below); proof-mode refusal
    // and the daemon/pipeline scenarios remain `planned`. Skipped under --dry-run
    // (which executes nothing by definition).
    if !dry_run
        && let Some(planned) = plan
            .scenarios
            .iter()
            .find(|p| p.scenario == SmokeScenario::DaemonReachable)
        && planned.action.is_executed()
    {
        events.push(SmokeProfileEvent::outcome(
            run_id.clone(),
            SMOKE_BEAD_ID,
            None,
            SmokeScenario::DaemonReachable,
            daemon_reachable,
            Some(
                rch_common::IncidentReasonCode::DaemonSocketRefused
                    .code()
                    .to_string(),
            ),
            Some("GET /health".to_string()),
            probe_ms,
        ));
    }

    // DesiredVsLiveFleet (daemon-view, no SSH): when planned to run, query the
    // daemon's full status, build the fleet report, and assert inventory
    // consistency — no desired worker sustained-absent and the fleet not
    // collapsed. A failed daemon fetch is a failed outcome (cannot verify).
    if !dry_run
        && let Some(planned) = plan
            .scenarios
            .iter()
            .find(|p| p.scenario == SmokeScenario::DesiredVsLiveFleet)
        && planned.action.is_executed()
    {
        let started = std::time::Instant::now();
        let (passed, reason) = match fetch_fleet_status_report().await {
            Ok(report) => smoke_fleet_consistency(&report),
            Err(_) => (false, Some("fleet_status_unavailable".to_string())),
        };
        let ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        events.push(SmokeProfileEvent::outcome(
            run_id.clone(),
            SMOKE_BEAD_ID,
            None,
            SmokeScenario::DesiredVsLiveFleet,
            passed,
            reason,
            Some("GET /status".to_string()),
            ms,
        ));
    }

    // Live per-worker SSH scenarios: when not a dry-run and the capabilities
    // scenario is planned to execute, probe each target worker for real. The
    // executor orchestrator (mock-SSH tested) runs the WorkerCapabilitiesExactUserPath
    // and DiskInodeAdmission scenarios and returns started/passed/failed events.
    // The other five scenarios are daemon/pipeline-level (composed elsewhere) or
    // client-side (proof-mode refusal); they remain `planned` here.
    if !dry_run
        && plan.scenarios.iter().any(|p| {
            p.scenario == SmokeScenario::WorkerCapabilitiesExactUserPath && p.action.is_executed()
        })
    {
        let disk_roots = smoke_disk_roots();
        // A single `--worker` scopes to that worker; otherwise every configured
        // worker is exercised. Soak repeats each pass `soak_passes()` times.
        let targets: Vec<&WorkerConfig> = match selected_worker.as_deref() {
            Some(id) => workers.iter().filter(|w| w.id.0 == id).collect(),
            None => workers.iter().collect(),
        };
        let passes = if soak { SOAK_PASSES } else { 1 };
        for _ in 0..passes {
            for worker in &targets {
                let worker_events = crate::fleet::run_smoke_worker_scenarios(
                    &run_id,
                    SMOKE_BEAD_ID,
                    worker,
                    &disk_roots,
                )
                .await;
                events.extend(worker_events);
            }
        }
    }

    // Proof-mode refusal (client-side, no SSH): when the plan expects a refusal
    // (remote execution unavailable), confirm the proof-mode control actually
    // resolves to a fail-closed policy — `RCH_REQUIRE_REMOTE` must refuse local
    // fallback rather than silently building locally. Exercising the real 13.5
    // `resolve_placement` path catches a fail-open regression in that mapping.
    if !dry_run
        && let Some(planned) = plan
            .scenarios
            .iter()
            .find(|p| p.scenario == SmokeScenario::ProofModeRefusal)
        && matches!(planned.action, ScenarioAction::ExpectRefusal { .. })
    {
        let policy = resolve_placement(|k| (k == "RCH_REQUIRE_REMOTE").then(|| "1".to_string()))
            .strict_remote_policy;
        let held = policy.fail_closed();
        events.push(SmokeProfileEvent::refused(
            run_id.clone(),
            SMOKE_BEAD_ID,
            held,
            Some(
                rch_common::IncidentReasonCode::ProofRefusal
                    .code()
                    .to_string(),
            ),
            0,
        ));
    }

    let log_path = write_smoke_jsonl(&run_id, &events);

    let payload = serde_json::json!({
        "run_id": run_id,
        "bead_id": SMOKE_BEAD_ID,
        "mode": plan.mode,
        "dry_run": dry_run,
        "workers_configured": workers_configured,
        "remote_execution_available": inputs.remote_execution_available,
        "daemon_reachable": daemon_reachable,
        "overall_skipped": plan.overall_skipped,
        "plan": plan,
        "events": events,
        "log_path": log_path,
    });
    let _ = ctx.json(&payload);
    if ctx.is_json() {
        return Ok(());
    }

    render_smoke_plan(&plan, daemon_reachable, log_path.as_deref(), ctx);
    Ok(())
}

fn render_smoke_plan(
    plan: &SmokeProfilePlan,
    daemon_reachable: bool,
    log_path: Option<&str>,
    ctx: &OutputContext,
) {
    let style = ctx.style();
    println!("{}", style.format_header("Real-Fleet Smoke Profile (plan)"));

    let rows: Vec<Vec<String>> = plan
        .scenarios
        .iter()
        .map(|p| {
            vec![
                p.scenario.as_str().to_string(),
                p.action.status_token().to_string(),
                p.action.reason_code().unwrap_or("").to_string(),
            ]
        })
        .collect();
    ctx.table(&["Scenario", "Action", "Reason"], &rows);

    let count = |pred: fn(&ScenarioAction) -> bool| -> usize {
        plan.scenarios.iter().filter(|p| pred(&p.action)).count()
    };
    let run = count(|a| matches!(a, ScenarioAction::Run));
    let dry = count(|a| matches!(a, ScenarioAction::DryRun));
    let skip = count(|a| matches!(a, ScenarioAction::Skip { .. }));
    let refuse = count(|a| matches!(a, ScenarioAction::ExpectRefusal { .. }));

    println!(
        "\n{} {} run, {} dry-run, {} skip, {} expect-refusal{}.",
        style.muted("Summary:"),
        style.success(&run.to_string()),
        dry,
        skip,
        refuse,
        if plan.overall_skipped {
            format!(" ({})", style.warning("real-fleet validation skipped"))
        } else {
            String::new()
        }
    );
    println!(
        "  {} {}",
        style.key("Daemon reachable"),
        if daemon_reachable {
            style.success("yes")
        } else {
            style.warning("no")
        }
    );
    if let Some(path) = log_path {
        println!("  {} {}", style.key("JSONL trace"), style.info(path));
    }
    println!(
        "  {}",
        style.muted(
            "Per-worker scenario execution is the operator real-fleet procedure; see docs/runbooks."
        )
    );
}

fn render_self_test_result_verbose_lines(
    result: &SelfTestResultRecordFromApi,
    style: &Theme,
) -> Vec<String> {
    let mut lines = Vec::new();

    if result.passed {
        if let (Some(remote), Some(local)) = (result.remote_time_ms, result.local_time_ms) {
            let speedup = if remote > 0 {
                local as f64 / remote as f64
            } else {
                1.0
            };
            lines.push(format!(
                "      {} {:.1}x speedup",
                style.muted("→"),
                speedup
            ));

            if let (Some(local_hash), Some(remote_hash)) = (&result.local_hash, &result.remote_hash)
            {
                let hash_match = if local_hash == remote_hash {
                    style.success("match")
                } else {
                    style.error("MISMATCH")
                };
                lines.push(format!("      {} hash {}", style.muted("→"), hash_match));
            }
        }
    } else if let Some(ref err) = result.error
        && err.len() > 50
    {
        lines.push(format!(
            "      {} {}",
            style.muted("error:"),
            style.error(err)
        ));
    }

    lines
}

// =============================================================================
// Status Overview Command
// =============================================================================

pub async fn status_overview(
    workers: bool,
    jobs: bool,
    fleet: bool,
    remediation: bool,
    ctx: &OutputContext,
) -> Result<()> {
    use crate::status_types::{
        CliStatusResponse, RemediationHint, RepoConvergenceStatusFromApi, STATUS_SCHEMA_VERSION,
        SystemPosture, generate_convergence_remediations, generate_worker_remediations,
    };

    // Query daemon for full status.
    let response = send_daemon_command("GET /status\n").await?;
    let json = extract_json_body(&response)
        .ok_or_else(|| anyhow::anyhow!("Invalid response format from daemon"))?;
    let status: DaemonFullStatusResponse =
        serde_json::from_str(json).context("Failed to parse daemon status response")?;

    // `--fleet`: a focused desired/live grouping + dominant-problem summary +
    // absence alerts (bd-session-history-remediation-ocv9i.2.2). Short-circuits
    // the normal status render with its own JSON/human output.
    if fleet {
        let report = build_fleet_status_report(&status);
        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::ok("status-fleet", &report));
        } else {
            crate::status_display::render_fleet_status(&report, ctx.style());
        }
        return Ok(());
    }

    // `--remediation`: the operator-facing remediation view assembled by the
    // daemon (single source of truth). Falls back to a CLI-side assembly only
    // when talking to a daemon that predates the field
    // (bd-session-history-remediation-ocv9i.14.4).
    if remediation {
        let view = status
            .remediation
            .clone()
            .unwrap_or_else(|| build_remediation_view_from_status(&status));
        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::ok("status-remediation", &view));
        } else {
            crate::status_display::render_remediation_view(&view, ctx.style());
        }
        return Ok(());
    }

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
        let cli_status = CliStatusResponse {
            schema_version: STATUS_SCHEMA_VERSION.to_string(),
            posture_description: posture.description().to_string(),
            posture,
            daemon: status,
            convergence,
            remediation_hints,
        };
        let _ = ctx.json(&ApiResponse::ok("status", &cli_status));
        return Ok(());
    }

    let (show_workers, show_jobs) = status_overview_section_flags(workers, jobs, ctx);

    crate::status_display::render_full_status(
        &status,
        show_workers,
        show_jobs,
        convergence.as_ref(),
        &remediation_hints,
        &posture,
        ctx.style(),
    );

    if ctx.is_verbose() {
        debug!(target: "rch::verbose", "rendering verbose status details");
        for line in render_status_verbose_detail_lines(&status, ctx.theme()) {
            println!("{line}");
        }
    }

    Ok(())
}

/// Map daemon status + desired config + the bypass store into the fleet-wide
/// status report (bd-session-history-remediation-ocv9i.2.2). Each worker becomes
/// a [`rch_common::fleet_status::FleetWorkerSignal`]; absence durations come from
/// the age of a worker's active offline alert.
fn build_fleet_status_report(
    status: &DaemonFullStatusResponse,
) -> rch_common::fleet_status::FleetStatusReport {
    use chrono::{DateTime, Utc};
    use rch_common::fleet_diff::WorkerObservation;
    use rch_common::fleet_status::{
        DEFAULT_ABSENCE_THRESHOLD_SECS, FleetWorkerSignal, compute_fleet_status,
    };
    use std::collections::BTreeSet;

    let desired = super::helpers::load_workers_from_config().unwrap_or_default();
    let desired_ids: BTreeSet<String> = desired.iter().map(|w| w.id.to_string()).collect();
    let live_ids: BTreeSet<String> = status.workers.iter().map(|w| w.id.clone()).collect();
    let now = Utc::now();

    // A worker's absence duration is the age of its longest-standing active
    // offline alert, if any.
    let absent_secs_for = |id: &str| -> Option<u64> {
        status
            .alerts
            .iter()
            .filter(|a| a.worker_id.as_deref() == Some(id) && a.kind.contains("offline"))
            .filter_map(|a| DateTime::parse_from_rfc3339(&a.first_seen).ok())
            .map(|fs| {
                u64::try_from((now - fs.with_timezone(&Utc)).num_seconds().max(0)).unwrap_or(0)
            })
            .max()
    };

    let mut signals: Vec<FleetWorkerSignal> =
        Vec::with_capacity(desired.len() + status.workers.len());

    for w in &status.workers {
        let reachable = w.status != "unreachable";
        let admin_disabled = w.status == "disabled";
        let temporarily_bypassed = w.bypass.is_some();
        let observation = WorkerObservation {
            worker_id: w.id.clone(),
            configured: desired_ids.contains(&w.id),
            in_daemon_pool: true,
            reachable,
            admin_disabled,
            temporarily_bypassed,
            facts_known: w.pressure_state.as_deref() != Some("telemetry_gap"),
            // The bare fleet view is not tied to a specific command.
            command_admissible: true,
        };
        let disk_pressure = matches!(
            w.pressure_state.as_deref(),
            Some("critical") | Some("warning")
        );
        let slots_saturated = w.total_slots > 0 && w.used_slots >= w.total_slots;
        signals.push(FleetWorkerSignal {
            observation,
            disk_pressure,
            slots_saturated,
            absent_secs: absent_secs_for(&w.id),
        });
    }

    // Desired workers entirely missing from the live pool.
    for cfg in &desired {
        let id = cfg.id.to_string();
        if live_ids.contains(&id) {
            continue;
        }
        let observation = WorkerObservation {
            worker_id: id.clone(),
            configured: true,
            in_daemon_pool: false,
            reachable: false,
            admin_disabled: false,
            temporarily_bypassed: false,
            facts_known: true,
            command_admissible: true,
        };
        signals.push(FleetWorkerSignal {
            observation,
            disk_pressure: false,
            slots_saturated: false,
            absent_secs: absent_secs_for(&id),
        });
    }

    compute_fleet_status(&signals, DEFAULT_ABSENCE_THRESHOLD_SECS)
}

/// Assemble the operator-facing remediation view (bd-..14.4) from the daemon
/// status response. This is only the CLI-side fallback for a daemon that
/// predates the `remediation` status field — the daemon is the authoritative
/// source; both call the same pure `rch_common` assembler so the result is
/// identical regardless of where the inputs are gathered.
fn build_remediation_view_from_status(
    status: &DaemonFullStatusResponse,
) -> rch_common::remediation_view::RemediationView {
    use rch_common::bypass_record::BypassState;
    use rch_common::fleet_diff::WorkerObservation;
    use rch_common::fleet_status::DEFAULT_ABSENCE_THRESHOLD_SECS;
    use rch_common::remediation_view::{
        DiskLevel, JobsInput, MAX_VIEW_INCIDENTS, ProofQueueInput, RemediationIncidentLine,
        RemediationWorkerRow, assemble, build_inputs,
    };

    let rows: Vec<RemediationWorkerRow> = status
        .workers
        .iter()
        .map(|w| {
            let facts_known = w.pressure_state.as_deref() != Some("telemetry_gap");
            RemediationWorkerRow {
                observation: WorkerObservation {
                    worker_id: w.id.clone(),
                    configured: true,
                    in_daemon_pool: true,
                    reachable: w.status != "unreachable",
                    admin_disabled: w.status == "disabled",
                    temporarily_bypassed: w.bypass.is_some(),
                    facts_known,
                    command_admissible: true,
                },
                disk_level: DiskLevel::from_pressure_state(
                    w.pressure_state.as_deref().unwrap_or(""),
                ),
                reclaiming: false,
                free_ratio: w.pressure_disk_free_ratio,
                slots_used: w.used_slots,
                slots_total: w.total_slots,
                telemetry_known: facts_known,
                telemetry_fresh: w.pressure_telemetry_fresh.unwrap_or(false),
                telemetry_age_secs: w.pressure_telemetry_age_secs,
                recovered_pending_canary: w
                    .bypass
                    .as_ref()
                    .is_some_and(|b| b.state == BypassState::RecoveredPendingCanary),
                absent_secs: None,
            }
        })
        .collect();

    let jobs = JobsInput {
        active: status.active_builds.len(),
        queued: status.queued_builds.len(),
        stuck: 0,
    };

    let incidents: Vec<RemediationIncidentLine> = status
        .alerts
        .iter()
        .filter(|a| a.state == "active")
        .take(MAX_VIEW_INCIDENTS)
        .map(|a| {
            RemediationIncidentLine::new(
                a.kind.clone(),
                "alert",
                a.worker_id.clone(),
                0,
                &a.message,
            )
        })
        .collect();

    let inputs = build_inputs(
        &rows,
        jobs,
        ProofQueueInput::default(),
        incidents,
        DEFAULT_ABSENCE_THRESHOLD_SECS,
    );
    assemble(&inputs, 0)
}

fn status_overview_section_flags(workers: bool, jobs: bool, ctx: &OutputContext) -> (bool, bool) {
    (workers || ctx.is_verbose(), jobs || ctx.is_verbose())
}

fn render_status_verbose_detail_lines(
    status: &DaemonFullStatusResponse,
    style: &Theme,
) -> Vec<String> {
    let mut lines = vec![
        style.format_header("Verbose Details"),
        String::new(),
        format!(
            "  {} {} {}",
            style.key("Socket"),
            style.muted(":"),
            style.value(&status.daemon.socket_path)
        ),
        format!(
            "  {} {} {}",
            style.key("Started"),
            style.muted(":"),
            style.value(&status.daemon.started_at)
        ),
    ];

    if !status.alerts.is_empty() {
        lines.push(String::new());
        lines.push(format!("  {}", style.key("Active Alerts:")));
        for alert in &status.alerts {
            let severity_style = match alert.severity.as_str() {
                "critical" | "error" => style.error(&alert.severity),
                "warning" => style.warning(&alert.severity),
                _ => style.info(&alert.severity),
            };
            lines.push(format!(
                "    {} [{}] {}",
                severity_style,
                style.muted(&alert.created_at),
                style.value(&alert.message)
            ));
        }
    }

    if !status.issues.is_empty() {
        lines.push(String::new());
        lines.push(format!("  {}", style.key("Known Issues:")));
        for issue in &status.issues {
            lines.push(format!(
                "    {} {} - {}",
                style.warning("⚠"),
                style.key(&issue.summary),
                style.muted(issue.remediation.as_deref().unwrap_or(""))
            ));
        }
    }

    lines
}

// =============================================================================
// Check Command
// =============================================================================

const CHECK_HOOK_NOT_INSTALLED_ISSUE: &str = "Claude Code hook not installed";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum CheckIssueSeverity {
    Info,
    Warning,
    Error,
}

fn check_issue_severity(severity: &str) -> CheckIssueSeverity {
    if severity.eq_ignore_ascii_case("error") || severity.eq_ignore_ascii_case("critical") {
        CheckIssueSeverity::Error
    } else if severity.eq_ignore_ascii_case("info") {
        CheckIssueSeverity::Info
    } else {
        CheckIssueSeverity::Warning
    }
}

fn derive_check_outcome(
    total_count: usize,
    healthy_count: usize,
    unhealthy: &[String],
    daemon_issues: &[IssueFromApi],
    hook_installed: bool,
) -> (String, i32, Vec<String>) {
    let mut issues_list: Vec<String> = unhealthy
        .iter()
        .map(|w| format!("Worker {} is unreachable", w))
        .collect();
    issues_list.extend(daemon_issues.iter().map(|issue| issue.summary.clone()));

    let daemon_issue_severity = daemon_issues
        .iter()
        .map(|issue| check_issue_severity(&issue.severity))
        .max();

    let (mut status, mut exit_code, mut issues) = if total_count == 0 {
        issues_list.insert(0, "No workers configured".to_string());
        ("not_ready".to_string(), 2, issues_list)
    } else if healthy_count == total_count {
        ("ready".to_string(), 0, issues_list)
    } else if healthy_count > 0 {
        if issues_list.is_empty() {
            let not_healthy = total_count.saturating_sub(healthy_count);
            let worker_word = if not_healthy == 1 {
                "worker"
            } else {
                "workers"
            };
            let verb = if not_healthy == 1 { "is" } else { "are" };
            issues_list.push(format!(
                "{not_healthy} configured {worker_word} {verb} not healthy ({healthy_count}/{total_count} healthy)"
            ));
        }
        ("degraded".to_string(), 1, issues_list)
    } else {
        issues_list.insert(0, "All workers are unreachable".to_string());
        ("not_ready".to_string(), 2, issues_list)
    };

    match daemon_issue_severity {
        Some(CheckIssueSeverity::Error) => {
            status = "not_ready".to_string();
            exit_code = 2;
        }
        Some(CheckIssueSeverity::Warning) if status == "ready" => {
            status = "degraded".to_string();
            exit_code = 1;
        }
        _ => {}
    }

    if !hook_installed {
        if status == "ready" || status == "degraded" {
            issues.insert(0, CHECK_HOOK_NOT_INSTALLED_ISSUE.to_string());
        } else {
            issues.push(CHECK_HOOK_NOT_INSTALLED_ISSUE.to_string());
        }
        status = "not_ready".to_string();
        exit_code = 2;
    }

    (status, exit_code, issues)
}

/// Quick health check: "Is RCH working right now?"
///
/// Returns exit codes:
/// - 0: Ready (daemon running, hook installed, all workers healthy)
/// - 1: Degraded (daemon running, some workers unreachable)
/// - 2: Not ready (daemon/hook missing or fatal issues)
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

    // Check if hook is installed. RCH is not "ready" for transparent
    // Claude Code offload unless the hook is actually present.
    let hook_installed = {
        use crate::agent::{AgentKind, HookStatus, check_hook_status};
        matches!(
            check_hook_status(AgentKind::ClaudeCode),
            Ok(HookStatus::Installed)
        )
    };

    let (status, exit_code, daemon_info, workers_info, issues) = match daemon_result {
        Ok(response) => {
            match extract_json_body(&response) {
                Some(json) => {
                    match serde_json::from_str::<DaemonFullStatusResponse>(json) {
                        Ok(daemon_status) => {
                            // Daemon is running - determine health
                            let healthy_count = daemon_status.daemon.workers_healthy;
                            let total_count = daemon_status.daemon.workers_total;
                            let unhealthy: Vec<String> = daemon_status
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
                                pid: Some(daemon_status.daemon.pid),
                                uptime_secs: Some(daemon_status.daemon.uptime_secs),
                            };

                            let workers_info = WorkersCheckInfo {
                                total: total_count,
                                healthy: healthy_count,
                                unhealthy: unhealthy.clone(),
                            };

                            let (status, exit_code, issues) = derive_check_outcome(
                                total_count,
                                healthy_count,
                                &unhealthy,
                                &daemon_status.issues,
                                hook_installed,
                            );
                            (status, exit_code, daemon_info, workers_info, issues)
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
            if workers_info.unhealthy.is_empty() {
                let issue = issues
                    .first()
                    .map(String::as_str)
                    .unwrap_or("some workers are not fully healthy");
                println!("{} RCH degraded: {}", style.warning("\u{26A0}"), issue);
            } else {
                println!(
                    "{} RCH degraded: {}/{} workers unreachable ({})",
                    style.warning("\u{26A0}"),
                    workers_info.unhealthy.len(),
                    workers_info.total,
                    workers_info.unhealthy.join(", ")
                );
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::context::OutputConfig;
    use crate::ui::writer::SharedOutputBuffer;

    fn make_context(config: OutputConfig) -> OutputContext {
        let stdout = SharedOutputBuffer::new().as_writer(true);
        let stderr = SharedOutputBuffer::new().as_writer(true);
        OutputContext::with_writers(config, stdout, stderr)
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
            "workers": [],
            "active_builds": [],
            "recent_builds": [],
            "issues": [{
                "severity": "warning",
                "summary": "worker pressure",
                "remediation": "run rch workers probe --all"
            }],
            "alerts": [{
                "id": "alert-1",
                "kind": "worker",
                "severity": "warning",
                "message": "worker degraded",
                "worker_id": "builder-1",
                "created_at": "2026-01-01T00:00:30Z"
            }],
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

    fn check_issue(severity: &str, summary: &str) -> IssueFromApi {
        IssueFromApi {
            severity: severity.to_string(),
            summary: summary.to_string(),
            remediation: None,
        }
    }

    #[test]
    fn test_status_verbose_includes_worker_details() {
        let normal_ctx = make_context(OutputConfig::default());
        assert_eq!(
            status_overview_section_flags(false, false, &normal_ctx),
            (false, false)
        );

        let verbose_ctx = make_context(OutputConfig {
            verbose: true,
            ..Default::default()
        });
        assert_eq!(
            status_overview_section_flags(false, false, &verbose_ctx),
            (true, true)
        );

        let style = crate::ui::theme::Style::new(false, true, false);
        let verbose_lines = render_status_verbose_detail_lines(&make_daemon_status(), &style);
        assert_ne!(verbose_lines.first().map(String::as_str), Some(""));

        let output = verbose_lines.join("\n");
        assert!(output.contains("Verbose Details"));
        assert!(output.contains("Socket"));
        assert!(output.contains("/tmp/rch.sock"));
        assert!(output.contains("Started"));
        assert!(output.contains("Active Alerts"));
        assert!(output.contains("Known Issues"));
    }

    #[test]
    fn test_check_outcome_ready_requires_hook() {
        let unhealthy = Vec::new();
        let daemon_issues = Vec::new();
        let (status, exit_code, issues) =
            derive_check_outcome(2, 2, &unhealthy, &daemon_issues, false);

        assert_eq!(status, "not_ready");
        assert_eq!(exit_code, 2);
        assert_eq!(
            issues.first().map(String::as_str),
            Some(CHECK_HOOK_NOT_INSTALLED_ISSUE)
        );
    }

    #[test]
    fn test_check_outcome_ready_when_hook_installed() {
        let unhealthy = Vec::new();
        let daemon_issues = Vec::new();
        let (status, exit_code, issues) =
            derive_check_outcome(2, 2, &unhealthy, &daemon_issues, true);

        assert_eq!(status, "ready");
        assert_eq!(exit_code, 0);
        assert!(issues.is_empty());
    }

    #[test]
    fn test_check_outcome_degraded_missing_hook_promotes_not_ready() {
        let unhealthy = vec!["builder-2".to_string()];
        let daemon_issues = vec![check_issue("warning", "worker pressure")];
        let (status, exit_code, issues) =
            derive_check_outcome(2, 1, &unhealthy, &daemon_issues, false);

        assert_eq!(status, "not_ready");
        assert_eq!(exit_code, 2);
        assert_eq!(
            issues.first().map(String::as_str),
            Some(CHECK_HOOK_NOT_INSTALLED_ISSUE)
        );
        assert!(
            issues
                .iter()
                .any(|issue| issue == "Worker builder-2 is unreachable")
        );
        assert!(issues.iter().any(|issue| issue == "worker pressure"));
    }

    #[test]
    fn test_check_outcome_ready_with_daemon_warning_is_degraded() {
        let unhealthy = Vec::new();
        let daemon_issues = vec![check_issue("warning", "worker pressure")];
        let (status, exit_code, issues) =
            derive_check_outcome(2, 2, &unhealthy, &daemon_issues, true);

        assert_eq!(status, "degraded");
        assert_eq!(exit_code, 1);
        assert_eq!(issues, vec!["worker pressure"]);
    }

    #[test]
    fn test_check_outcome_daemon_error_is_not_ready() {
        let unhealthy = Vec::new();
        let daemon_issues = vec![check_issue("error", "daemon failed to clean up a build")];
        let (status, exit_code, issues) =
            derive_check_outcome(2, 2, &unhealthy, &daemon_issues, true);

        assert_eq!(status, "not_ready");
        assert_eq!(exit_code, 2);
        assert_eq!(issues, vec!["daemon failed to clean up a build"]);
    }

    #[test]
    fn test_check_outcome_zero_workers_preserves_daemon_issues() {
        let unhealthy = Vec::new();
        let daemon_issues = vec![check_issue("warning", "stale pressure telemetry")];
        let (status, exit_code, issues) =
            derive_check_outcome(0, 0, &unhealthy, &daemon_issues, true);

        assert_eq!(status, "not_ready");
        assert_eq!(exit_code, 2);
        assert_eq!(
            issues.first().map(String::as_str),
            Some("No workers configured")
        );
        assert!(
            issues
                .iter()
                .any(|issue| issue == "stale pressure telemetry")
        );
    }

    #[test]
    fn test_check_outcome_partial_health_without_named_unhealthy_worker_explains_degraded() {
        let unhealthy = Vec::new();
        let daemon_issues = Vec::new();
        let (status, exit_code, issues) =
            derive_check_outcome(3, 2, &unhealthy, &daemon_issues, true);

        assert_eq!(status, "degraded");
        assert_eq!(exit_code, 1);
        assert_eq!(
            issues,
            vec!["1 configured worker is not healthy (2/3 healthy)".to_string()]
        );
    }

    #[test]
    fn test_self_test_verbose_shows_each_step() {
        let style = crate::ui::theme::Style::new(false, true, false);
        let passed: SelfTestResultRecordFromApi = serde_json::from_value(serde_json::json!({
            "run_id": 1,
            "worker_id": "builder-1",
            "passed": true,
            "local_hash": "abc",
            "remote_hash": "abc",
            "local_time_ms": 4000,
            "remote_time_ms": 1000,
            "error": null
        }))
        .unwrap();
        let failed: SelfTestResultRecordFromApi = serde_json::from_value(serde_json::json!({
            "run_id": 1,
            "worker_id": "builder-2",
            "passed": false,
            "local_hash": null,
            "remote_hash": null,
            "local_time_ms": null,
            "remote_time_ms": null,
            "error": "this is a deliberately long worker self-test error message for verbose context"
        }))
        .unwrap();

        let passed_output = render_self_test_result_verbose_lines(&passed, &style).join("\n");
        assert!(passed_output.contains("4.0x speedup"));
        assert!(passed_output.contains("hash match"));

        let failed_output = render_self_test_result_verbose_lines(&failed, &style).join("\n");
        assert!(failed_output.contains("error:"));
        assert!(failed_output.contains("deliberately long"));
    }

    // ========================
    // Smoke-profile consumer tests (bd-...-ocv9i.16.6)
    // ========================

    #[test]
    fn build_smoke_inputs_maps_environment_and_flags() {
        // Workers + daemon up => remote execution available.
        let i = build_smoke_inputs(true, true, false, false, None);
        assert!(i.workers_configured);
        assert!(i.remote_execution_available);
        assert_eq!(i.mode, ProfileMode::Smoke);
        assert!(!i.dry_run);

        // No workers => remote unavailable even if the daemon is up.
        assert!(!build_smoke_inputs(false, true, false, false, None).remote_execution_available);
        // Daemon down => remote unavailable even with workers.
        assert!(!build_smoke_inputs(true, false, false, false, None).remote_execution_available);

        // soak + dry_run + a selected worker are carried through.
        let i = build_smoke_inputs(true, true, true, true, Some("css".to_string()));
        assert_eq!(i.mode, ProfileMode::Soak);
        assert!(i.dry_run);
        assert_eq!(i.selected_worker.as_deref(), Some("css"));
    }

    #[test]
    fn smoke_planned_events_cover_every_scenario_with_reasons() {
        // No-workers plan: real-worker scenarios skip with a reason, the daemon
        // scenario runs, and proof-mode refusal is expected.
        let inputs = build_smoke_inputs(false, false, false, false, None);
        let plan = plan_smoke_profile(&inputs);
        let events = smoke_planned_events(&plan, "run-1", Some("css"));

        assert_eq!(events.len(), SmokeScenario::ALL.len());
        assert!(
            events
                .iter()
                .all(|e| e.run_id == "run-1" && e.event == "planned" && e.bead_id == SMOKE_BEAD_ID)
        );

        // The daemon scenario is not worker-scoped, so its worker id is dropped.
        let daemon = events
            .iter()
            .find(|e| e.scenario == "daemon_reachable")
            .unwrap();
        assert_eq!(daemon.worker_id, None);
        assert_eq!(daemon.status, "run");

        // A real-worker scenario keeps the worker and carries the skip reason.
        let canary = events
            .iter()
            .find(|e| e.scenario == "cargo_canary")
            .unwrap();
        assert_eq!(canary.worker_id.as_deref(), Some("css"));
        assert_eq!(canary.status, "skip");
        assert_eq!(canary.reason_code.as_deref(), Some("smoke_no_real_workers"));

        // Remote unavailable => proof-mode refusal is expected.
        let proof = events
            .iter()
            .find(|e| e.scenario == "proof_mode_refusal")
            .unwrap();
        assert_eq!(proof.status, "expect_refusal");
    }

    #[test]
    fn smoke_planned_events_full_fleet_runs_per_worker_scenarios() {
        let inputs = build_smoke_inputs(true, true, false, false, None);
        let plan = plan_smoke_profile(&inputs);
        let events = smoke_planned_events(&plan, "run-2", Some("hz1"));
        let canary = events
            .iter()
            .find(|e| e.scenario == "cargo_canary")
            .unwrap();
        assert_eq!(canary.status, "run");
        assert_eq!(canary.reason_code, None);
        // Remote available => proof-mode refusal cannot be exercised (skipped).
        let proof = events
            .iter()
            .find(|e| e.scenario == "proof_mode_refusal")
            .unwrap();
        assert_eq!(proof.status, "skip");
        assert_eq!(proof.reason_code.as_deref(), Some("smoke_remote_available"));
    }

    #[test]
    fn smoke_fleet_consistency_pass_and_fail_paths() {
        use rch_common::fleet_diff::WorkerObservation;
        use rch_common::fleet_status::{
            DEFAULT_ABSENCE_THRESHOLD_SECS, FleetWorkerSignal, compute_fleet_status,
        };
        let ready = |id: &str| FleetWorkerSignal {
            observation: WorkerObservation {
                worker_id: id.to_string(),
                configured: true,
                in_daemon_pool: true,
                reachable: true,
                admin_disabled: false,
                temporarily_bypassed: false,
                facts_known: true,
                command_admissible: true,
            },
            disk_pressure: false,
            slots_saturated: false,
            absent_secs: None,
        };

        // Ready workers, no absences -> inventory consistent.
        let healthy =
            compute_fleet_status(&[ready("a"), ready("b")], DEFAULT_ABSENCE_THRESHOLD_SECS);
        assert_eq!(smoke_fleet_consistency(&healthy), (true, None));

        // Workers present but none ready -> capacity collapsed -> inconsistent.
        let mut down1 = ready("a");
        down1.observation.reachable = false;
        let mut down2 = ready("b");
        down2.observation.reachable = false;
        let collapsed = compute_fleet_status(&[down1, down2], DEFAULT_ABSENCE_THRESHOLD_SECS);
        let (ok, reason) = smoke_fleet_consistency(&collapsed);
        assert!(!ok);
        assert_eq!(reason.as_deref(), Some("fleet_capacity_collapsed"));

        // A configured worker sustained-absent from live -> inventory drift.
        let mut absent = ready("c");
        absent.observation.reachable = false;
        absent.observation.in_daemon_pool = false;
        absent.absent_secs = Some(DEFAULT_ABSENCE_THRESHOLD_SECS + 10);
        let drifted = compute_fleet_status(&[ready("a"), absent], DEFAULT_ABSENCE_THRESHOLD_SECS);
        let (ok2, reason2) = smoke_fleet_consistency(&drifted);
        assert!(!ok2);
        assert_eq!(reason2.as_deref(), Some("fleet_workers_absent"));
    }
}
