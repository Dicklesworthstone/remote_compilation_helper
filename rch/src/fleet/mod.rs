//! Fleet management for worker deployments.
//!
//! This module provides centralized deployment, rollback, and monitoring
//! capabilities for the rch-wkr worker agent across all configured remote workers.

mod audit;
pub mod doctor;
mod dry_run;
mod executor;
mod history;
mod lock;
mod plan;
mod preflight;
mod progress;
mod rollback;
pub mod ssh;

pub use lock::{FleetLockGuard, RCH_FLEET_WAIT_SECS_ENV};

use crate::commands::load_workers_from_config;
use crate::config::load_config;
use crate::ui::context::OutputContext;
use crate::ui::theme::StatusIndicator;
use anyhow::Result;

use crate::error::BinaryError;
use rch_common::{ApiError, ApiResponse, ErrorCode};
use std::path::{Path, PathBuf};

pub use audit::{AuditEventType, AuditLogger, DeploymentAuditEntry};
pub use dry_run::{DryRunResult, PotentialIssue, PredictedAction, WorkerPrediction};
pub(crate) use executor::run_smoke_worker_scenarios;
pub use executor::{FleetExecutor, FleetResult};
pub use history::{DeploymentHistoryEntry, HistoryManager};
pub use plan::{
    DeployOptions, DeployStep, DeploymentPlan, DeploymentStatus, DeploymentStrategy,
    WorkerDeployment,
};
pub use preflight::{PreflightIssue, PreflightResult, Severity, with_retry};
pub use progress::{DeployPhase, FleetProgress};
pub use rollback::{RollbackManager, WorkerBackup};
pub use ssh::{
    CommandOutput, FleetSshError, MockCommandResult, MockConnectivity, MockSshExecutor,
    SshExecutor, parse_disk_space, parse_version_string,
};

/// Deploy rch-wkr to workers.
///
/// If `skip_confirm` is false, prompts for confirmation before deploying.
#[allow(clippy::too_many_arguments)]
pub async fn deploy(
    ctx: &OutputContext,
    worker: Option<String>,
    parallel: usize,
    canary: Option<u8>,
    canary_wait: u64,
    no_toolchain: bool,
    force: bool,
    verify: bool,
    drain_first: bool,
    drain_timeout: u64,
    dry_run: bool,
    resume: bool,
    version: Option<String>,
    audit_log: Option<PathBuf>,
    skip_confirm: bool,
) -> Result<()> {
    use dialoguer::Confirm;
    let style = ctx.theme();

    // Load workers configuration
    let workers = load_workers_from_config()?;
    if workers.is_empty() {
        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::<()>::err(
                "fleet deploy",
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
            println!("  {} Run: rch workers discover --add", style.muted("→"));
        }
        return Ok(());
    }

    // Filter to target workers
    let target_workers: Vec<_> = if let Some(ref ids) = worker {
        let ids: Vec<&str> = ids.split(',').map(|s| s.trim()).collect();
        workers
            .iter()
            .filter(|w| ids.iter().any(|id| w.id.0 == *id))
            .collect()
    } else {
        workers.iter().collect()
    };

    if target_workers.is_empty() {
        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::<()>::err(
                "fleet deploy",
                ApiError::new(
                    ErrorCode::ConfigInvalidWorker,
                    format!("Worker(s) '{}' not found", worker.unwrap_or_default()),
                ),
            ));
        } else {
            println!(
                "{} Worker(s) not found: {}",
                StatusIndicator::Error.display(style),
                worker.unwrap_or_default()
            );
        }
        return Ok(());
    }

    // Determine deployment strategy
    let strategy = if let Some(percent) = canary {
        DeploymentStrategy::Canary {
            percent,
            wait_secs: canary_wait,
            auto_promote: true,
        }
    } else {
        DeploymentStrategy::AllAtOnce {
            parallelism: parallel,
        }
    };

    // Build deployment options
    let options = DeployOptions {
        force,
        verify,
        drain_first,
        drain_timeout,
        no_toolchain,
        resume,
        target_version: version,
    };

    // Create deployment plan
    let plan = DeploymentPlan::new(&target_workers, strategy, options)?;

    if !ctx.is_json() {
        println!("{}", style.format_header("Fleet Deployment"));
        println!();
        println!(
            "  {} Workers: {}",
            style.muted("→"),
            style.value(&target_workers.len().to_string())
        );
        println!(
            "  {} Strategy: {}",
            style.muted("→"),
            style.value(&format!("{:?}", plan.strategy))
        );
        println!(
            "  {} Parallel: {}",
            style.muted("→"),
            style.value(&parallel.to_string())
        );
        if drain_first {
            println!("  {} Drain first: {}", style.muted("→"), style.value("yes"));
        }
        println!();
    }

    // Handle dry run
    if dry_run {
        // Dry-run is read-only; skip the cooperative lock so it can be
        // exercised while another agent holds a deploy.
        let dry_run_result = dry_run::compute_dry_run(&plan, ctx).await?;
        dry_run::display_dry_run(&dry_run_result, ctx, "fleet deploy")?;
        return Ok(());
    }

    // Per-fleet cooperative lock — prevents two concurrent deploys from
    // racing on worker state (bd-5z2wa). Held for the rest of this function
    // via RAII; drop removes only the lock body this process wrote.
    let _fleet_lock = match lock::acquire("fleet-deploy") {
        Ok(guard) => guard,
        Err(err) => {
            if ctx.is_json() {
                let _ = ctx.json(&ApiResponse::<()>::err(
                    "fleet deploy",
                    ApiError::new(ErrorCode::InternalStateError, err.to_string()),
                ));
            } else {
                println!("{} {}", StatusIndicator::Error.display(style), err);
            }
            return Ok(());
        }
    };

    // Prompt for confirmation unless skipped or in JSON mode
    if !skip_confirm && !ctx.is_json() {
        println!(
            "{} This will deploy rch-wkr to {} worker(s).",
            StatusIndicator::Warning.display(style),
            target_workers.len()
        );
        if drain_first {
            println!(
                "  {} Active builds will be drained first.",
                StatusIndicator::Info.display(style)
            );
        }
        let confirmed = Confirm::new()
            .with_prompt("Proceed with deployment?")
            .default(false)
            .interact()?;
        if !confirmed {
            println!("{} Aborted.", StatusIndicator::Info.display(style));
            return Ok(());
        }
        println!();
    }

    // Create audit logger if requested
    let audit_logger = if let Some(ref path) = audit_log {
        Some(AuditLogger::new(Some(path))?)
    } else {
        None
    };

    // Find local rch-wkr binary to deploy
    let local_binary = find_local_binary("rch-wkr")?;

    if !ctx.is_json() {
        println!(
            "  {} Binary: {}",
            style.muted("→"),
            style.value(&local_binary.display().to_string())
        );
        println!();
    }

    // --drain-first: stop routing to the targets and wait for their in-flight
    // builds before replacing rch-wkr underneath them. A deploy that cannot
    // confirm the targets are idle is refused rather than run over live builds.
    let drained_for_deploy: Vec<String> = if drain_first {
        let ids: Vec<String> = target_workers.iter().map(|w| w.id.0.clone()).collect();
        let mut drained = Vec::new();
        let mut refusal = None;
        for id in &ids {
            match crate::status_display::drain_worker(id).await {
                Ok(()) => drained.push(id.clone()),
                Err(error) => {
                    refusal = Some(format!("could not drain {id}: {error:#}"));
                    break;
                }
            }
        }
        if refusal.is_none() {
            match wait_for_drained_idle(&drained, drain_timeout).await {
                Ok(busy) if busy.is_empty() => {}
                Ok(busy) => {
                    let names: Vec<String> = busy
                        .iter()
                        .map(|(id, slots)| format!("{id} ({slots} slot(s))"))
                        .collect();
                    refusal = Some(format!(
                        "workers still busy after {drain_timeout}s: {}",
                        names.join(", ")
                    ));
                }
                Err(error) => {
                    refusal = Some(format!("could not confirm workers are idle: {error:#}"));
                }
            }
        }
        if let Some(reason) = refusal {
            re_enable_workers(&drained).await;
            anyhow::bail!(
                "deploy refused (--drain-first): {reason}; drained workers were re-enabled"
            );
        }
        drained
    } else {
        Vec::new()
    };

    // Execute deployment
    let executor = FleetExecutor::new(parallel, audit_logger, &target_workers, local_binary)?;
    let result = executor.execute(plan, ctx).await;
    re_enable_workers(&drained_for_deploy).await;
    let result = result?;

    // Output results
    if ctx.is_json() {
        let _ = ctx.json(&ApiResponse::ok("fleet deploy", &result));
    } else {
        match result {
            FleetResult::Success {
                deployed,
                skipped,
                failed,
            } => {
                println!();
                println!(
                    "  {} Deployed: {}, Skipped: {}, Failed: {}",
                    style.muted("Summary:"),
                    style.success(&deployed.to_string()),
                    style.muted(&skipped.to_string()),
                    if failed > 0 {
                        style.error(&failed.to_string())
                    } else {
                        style.muted("0")
                    }
                );
            }
            FleetResult::CanaryPending {
                promoted,
                remaining,
                skipped,
                failed,
            } => {
                println!();
                println!(
                    "  {} Canary deployed to {} worker(s); {} still on the previous version \
                    (auto_promote off — fleet NOT fully rolled out). Skipped: {}, Failed: {}",
                    StatusIndicator::Warning.display(style),
                    style.success(&promoted.to_string()),
                    style.highlight(&remaining.to_string()),
                    style.muted(&skipped.to_string()),
                    if failed > 0 {
                        style.error(&failed.to_string())
                    } else {
                        style.muted("0")
                    }
                );
                println!(
                    "  {} Promote the rest with a full `rch fleet deploy` (or re-run with \
                    auto-promote).",
                    style.muted("→")
                );
            }
            FleetResult::CanaryFailed { reason } => {
                println!();
                println!(
                    "{} Canary deployment failed: {}",
                    StatusIndicator::Error.display(style),
                    reason
                );
            }
            FleetResult::Aborted { reason } => {
                println!();
                println!(
                    "{} Deployment aborted: {}",
                    StatusIndicator::Warning.display(style),
                    reason
                );
            }
        }
    }

    Ok(())
}

/// Rollback workers to a previous version.
/// Rollback rch-wkr on workers to a previous version.
///
/// If `skip_confirm` is false, prompts for confirmation before rolling back.
pub async fn rollback(
    ctx: &OutputContext,
    worker: Option<String>,
    to_version: Option<String>,
    parallel: usize,
    verify: bool,
    dry_run: bool,
    skip_confirm: bool,
) -> Result<()> {
    use dialoguer::Confirm;

    let style = ctx.theme();

    // Load workers configuration
    let workers = load_workers_from_config()?;
    if workers.is_empty() {
        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::<()>::err(
                "fleet rollback",
                ApiError::new(ErrorCode::ConfigNotFound, "No workers configured."),
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
    let target_workers: Vec<_> = if let Some(ref ids) = worker {
        let ids: Vec<&str> = ids.split(',').map(|s| s.trim()).collect();
        workers
            .iter()
            .filter(|w| ids.iter().any(|id| w.id.0 == *id))
            .collect()
    } else {
        workers.iter().collect()
    };

    if !ctx.is_json() {
        println!("{}", style.format_header("Fleet Rollback"));
        println!();
        println!(
            "  {} Workers: {}",
            style.muted("→"),
            style.value(&target_workers.len().to_string())
        );
        if let Some(ref ver) = to_version {
            println!(
                "  {} Target version: {}",
                style.muted("→"),
                style.value(ver)
            );
        } else {
            println!("  {} Target: previous version", style.muted("→"),);
        }
        println!();
    }

    if dry_run {
        if ctx.is_json() {
            #[derive(serde::Serialize)]
            struct RollbackDryRun<'a> {
                dry_run: bool,
                worker_count: usize,
                workers: Vec<&'a str>,
                target_version: Option<&'a str>,
            }
            let dry_run_result = RollbackDryRun {
                dry_run: true,
                worker_count: target_workers.len(),
                workers: target_workers.iter().map(|w| w.id.0.as_str()).collect(),
                target_version: to_version.as_deref(),
            };
            let _ = ctx.json(&ApiResponse::ok("fleet rollback", &dry_run_result));
        } else {
            println!(
                "  {} Would rollback {} worker(s)",
                style.muted("DRY RUN:"),
                target_workers.len()
            );
            for w in &target_workers {
                println!("    {} {}", style.muted("→"), w.id.0);
            }
        }
        return Ok(());
    }

    // Per-fleet cooperative lock — shared across deploy/rollback/drain so a
    // rollback cannot race with an in-progress deploy (bd-5z2wa).
    let _fleet_lock = match lock::acquire("fleet-rollback") {
        Ok(guard) => guard,
        Err(err) => {
            if ctx.is_json() {
                let _ = ctx.json(&ApiResponse::<()>::err(
                    "fleet rollback",
                    ApiError::new(ErrorCode::InternalStateError, err.to_string()),
                ));
            } else {
                println!("{} {}", StatusIndicator::Error.display(style), err);
            }
            return Ok(());
        }
    };

    // Prompt for confirmation unless skipped or in JSON mode
    if !skip_confirm && !ctx.is_json() {
        println!(
            "{} This will rollback rch-wkr on {} worker(s).",
            StatusIndicator::Warning.display(style),
            target_workers.len()
        );
        if let Some(ref ver) = to_version {
            println!(
                "  {} Rolling back to version {}.",
                StatusIndicator::Info.display(style),
                ver
            );
        }
        let confirmed = Confirm::new()
            .with_prompt("Proceed with rollback?")
            .default(false)
            .interact()?;
        if !confirmed {
            println!("{} Aborted.", StatusIndicator::Info.display(style));
            return Ok(());
        }
        println!();
    }

    // Execute rollback
    let manager = RollbackManager::new()?;
    let results = manager
        .rollback_workers(
            &target_workers,
            to_version.as_deref(),
            parallel,
            verify,
            ctx,
        )
        .await?;

    if ctx.is_json() {
        let _ = ctx.json(&ApiResponse::ok("fleet rollback", &results));
    } else {
        let success_count = results.iter().filter(|r| r.success).count();
        let fail_count = results.len() - success_count;
        println!();
        println!(
            "  {} Rolled back: {}, Failed: {}",
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

/// Show fleet deployment status.
pub async fn status(ctx: &OutputContext, worker: Option<String>, watch: bool) -> Result<()> {
    let style = ctx.theme();

    // Load configuration for fleet operations
    let config = load_config().unwrap_or_default();
    let fleet_config = &config.fleet;

    // Load workers configuration
    let workers = load_workers_from_config()?;
    if workers.is_empty() {
        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::<()>::err(
                "fleet status",
                ApiError::new(ErrorCode::ConfigNotFound, "No workers configured."),
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
    let target_workers: Vec<_> = if let Some(ref ids) = worker {
        let ids: Vec<&str> = ids.split(',').map(|s| s.trim()).collect();
        workers
            .iter()
            .filter(|w| ids.iter().any(|id| w.id.0 == *id))
            .collect()
    } else {
        workers.iter().collect()
    };

    // Get status for each worker
    let status_results = preflight::get_fleet_status(&target_workers, ctx, fleet_config).await?;

    if ctx.is_json() {
        let _ = ctx.json(&ApiResponse::ok("fleet status", &status_results));
        return Ok(());
    }

    println!("{}", style.format_header("Fleet Status"));
    println!();

    for result in &status_results {
        let status_icon = if result.healthy {
            StatusIndicator::Success.display(style)
        } else if result.reachable {
            StatusIndicator::Warning.display(style)
        } else {
            StatusIndicator::Error.display(style)
        };

        println!(
            "  {} {} {}",
            status_icon,
            style.highlight(&result.worker_id),
            if let Some(ref ver) = result.version {
                style.muted(&format!("({})", ver))
            } else {
                style.muted("(unknown)")
            }
        );

        if !result.issues.is_empty() {
            for issue in &result.issues {
                println!("      {} {}", style.muted("⚠"), issue);
            }
        }
    }

    if watch {
        // Re-query every worker on each refresh; a stale screen that merely
        // sleeps would claim a live view it does not have.
        loop {
            println!();
            println!(
                "  {} refreshing every {}s, Ctrl+C to exit",
                style.muted("Watching..."),
                FLEET_STATUS_WATCH_INTERVAL.as_secs()
            );
            tokio::time::sleep(FLEET_STATUS_WATCH_INTERVAL).await;
            println!();
            println!(
                "{}",
                style.muted(&format!(
                    "── {} ──",
                    chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
                ))
            );
            Box::pin(status(ctx, worker.clone(), false)).await?;
        }
    }

    Ok(())
}

const FLEET_STATUS_WATCH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

/// Verify worker installations.
pub async fn verify(ctx: &OutputContext, worker: Option<String>) -> Result<()> {
    let style = ctx.theme();

    // Load configuration for fleet operations
    let config = load_config().unwrap_or_default();
    let fleet_config = &config.fleet;

    // Load workers configuration
    let workers = load_workers_from_config()?;
    if workers.is_empty() {
        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::<()>::err(
                "fleet verify",
                ApiError::new(ErrorCode::ConfigNotFound, "No workers configured."),
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
    let target_workers: Vec<_> = if let Some(ref ids) = worker {
        let ids: Vec<&str> = ids.split(',').map(|s| s.trim()).collect();
        workers
            .iter()
            .filter(|w| ids.iter().any(|id| w.id.0 == *id))
            .collect()
    } else {
        workers.iter().collect()
    };

    if !ctx.is_json() {
        println!("{}", style.format_header("Fleet Verification"));
        println!();
    }

    // Run preflight checks on each worker
    let mut all_ok = true;
    let mut results = Vec::new();

    for w in &target_workers {
        let result = preflight::run_preflight(w, ctx, fleet_config).await?;
        let ok = result.ssh_ok && result.disk_ok && result.rsync_ok && result.issues.is_empty();

        if !ctx.is_json() {
            let status_icon = if ok {
                StatusIndicator::Success.display(style)
            } else {
                StatusIndicator::Error.display(style)
            };

            println!(
                "  {} {} {}",
                status_icon,
                style.highlight(&w.id.0),
                if let Some(ref ver) = result.current_version {
                    style.muted(&format!("v{}", ver))
                } else {
                    style.muted("(not installed)")
                }
            );

            if !result.issues.is_empty() {
                for issue in &result.issues {
                    println!(
                        "      {} [{:?}] {}",
                        style.muted("→"),
                        issue.severity,
                        issue.message
                    );
                }
            }
        }

        if !ok {
            all_ok = false;
        }
        results.push(result);
    }

    if ctx.is_json() {
        let _ = ctx.json(&ApiResponse::ok("fleet verify", &results));
    } else {
        println!();
        if all_ok {
            println!(
                "  {} All {} workers verified successfully",
                StatusIndicator::Success.display(style),
                target_workers.len()
            );
        } else {
            println!(
                "  {} Some workers have issues",
                StatusIndicator::Warning.display(style)
            );
        }
    }

    Ok(())
}

/// Drain workers before maintenance.
/// Drain workers before maintenance.
///
/// If `skip_confirm` is false, prompts for confirmation before draining.
pub async fn drain(
    ctx: &OutputContext,
    worker: Option<String>,
    all: bool,
    timeout: u64,
    skip_confirm: bool,
) -> Result<()> {
    use dialoguer::Confirm;

    let style = ctx.theme();

    if worker.is_none() && !all {
        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::<()>::err(
                "fleet drain",
                ApiError::new(
                    ErrorCode::ConfigValidationError,
                    "Specify either a worker ID or --all",
                ),
            ));
        } else {
            println!(
                "{} Specify either {} or {}",
                StatusIndicator::Error.display(style),
                style.highlight("<worker>"),
                style.highlight("--all")
            );
        }
        return Ok(());
    }

    // Load workers configuration
    let workers = load_workers_from_config()?;

    // Filter to target workers
    let target_workers: Vec<_> = if all {
        workers.iter().collect()
    } else if let Some(ref ids) = worker {
        let ids: Vec<&str> = ids.split(',').map(|s| s.trim()).collect();
        workers
            .iter()
            .filter(|w| ids.iter().any(|id| w.id.0 == *id))
            .collect()
    } else {
        vec![]
    };

    if !ctx.is_json() {
        println!("{}", style.format_header("Fleet Drain"));
        println!();
        println!(
            "  {} Draining {} worker(s) with timeout {}s",
            style.muted("→"),
            target_workers.len(),
            timeout
        );
        println!();
    }

    // Per-fleet cooperative lock — drain mutates routing state so concurrent
    // drains would race (bd-5z2wa).
    let _fleet_lock = match lock::acquire("fleet-drain") {
        Ok(guard) => guard,
        Err(err) => {
            if ctx.is_json() {
                let _ = ctx.json(&ApiResponse::<()>::err(
                    "fleet drain",
                    ApiError::new(ErrorCode::InternalStateError, err.to_string()),
                ));
            } else {
                println!("{} {}", StatusIndicator::Error.display(style), err);
            }
            return Ok(());
        }
    };

    // Prompt for confirmation unless skipped or in JSON mode
    if !skip_confirm && !ctx.is_json() {
        println!(
            "{} This will drain {} worker(s), stopping new job routing.",
            StatusIndicator::Warning.display(style),
            target_workers.len()
        );
        if all {
            println!(
                "  {} ALL workers will be drained!",
                StatusIndicator::Warning.display(style)
            );
        }
        let confirmed = Confirm::new()
            .with_prompt("Proceed with drain?")
            .default(false)
            .interact()?;
        if !confirmed {
            println!("{} Aborted.", StatusIndicator::Info.display(style));
            return Ok(());
        }
        println!();
    }

    // Drain each worker through the daemon. A worker counts as drained only
    // when the daemon acknowledged it; anything else is reported as failed.
    let mut drained: Vec<String> = Vec::new();
    let mut failed: Vec<(String, String)> = Vec::new();
    for w in &target_workers {
        if !ctx.is_json() {
            println!(
                "  {} Draining {}...",
                StatusIndicator::Pending.display(style),
                style.highlight(&w.id.0)
            );
        }
        match crate::status_display::drain_worker(&w.id.0).await {
            Ok(()) => {
                if !ctx.is_json() {
                    println!(
                        "  {} {} drained (no new builds will be routed to it)",
                        StatusIndicator::Success.display(style),
                        style.highlight(&w.id.0)
                    );
                }
                drained.push(w.id.0.clone());
            }
            Err(error) => {
                if !ctx.is_json() {
                    println!(
                        "  {} {} not drained: {error:#}",
                        StatusIndicator::Error.display(style),
                        style.highlight(&w.id.0)
                    );
                }
                failed.push((w.id.0.clone(), format!("{error:#}")));
            }
        }
    }

    // Draining stops new routing; in-flight builds keep running. Wait up to
    // `timeout` seconds for them so a caller can safely take workers down.
    let still_busy = wait_for_drained_idle(&drained, timeout).await;
    if !ctx.is_json() {
        match &still_busy {
            Ok(busy) if busy.is_empty() => {}
            Ok(busy) => {
                for (id, slots) in busy {
                    println!(
                        "  {} {} still has {} slot(s) in use after {}s",
                        StatusIndicator::Warning.display(style),
                        style.highlight(id),
                        slots,
                        timeout
                    );
                }
            }
            Err(error) => println!(
                "  {} Could not confirm in-flight builds finished: {error:#}",
                StatusIndicator::Warning.display(style)
            ),
        }
    }

    if ctx.is_json() {
        let busy_json = match &still_busy {
            Ok(busy) => serde_json::json!(
                busy.iter()
                    .map(|(id, slots)| serde_json::json!({"worker_id": id, "used_slots": slots}))
                    .collect::<Vec<_>>()
            ),
            Err(_) => serde_json::Value::Null,
        };
        if failed.is_empty() {
            let _ = ctx.json(&ApiResponse::ok(
                "fleet drain",
                serde_json::json!({
                    "workers_drained": drained,
                    "still_busy": busy_json,
                    "idle_confirmed": matches!(&still_busy, Ok(busy) if busy.is_empty()),
                    "timeout": timeout,
                }),
            ));
        } else {
            let failed_ids: Vec<&str> = failed.iter().map(|(id, _)| id.as_str()).collect();
            let details: Vec<String> = failed
                .iter()
                .map(|(id, error)| format!("{id}: {error}"))
                .collect();
            let _ = ctx.json(&ApiResponse::<()>::err(
                "fleet drain",
                ApiError::new(
                    ErrorCode::WorkerStateError,
                    format!(
                        "{} of {} worker(s) were not drained",
                        failed.len(),
                        target_workers.len()
                    ),
                )
                .with_details(details.join("; "))
                .with_context("failed_workers", failed_ids.join(","))
                .with_context("drained_workers", drained.join(",")),
            ));
        }
    }

    if failed.is_empty() {
        Ok(())
    } else {
        Err(crate::doctor::DoctorExit(1).into())
    }
}

/// Return workers drained for a deploy to routing. Best-effort: a failure is
/// logged, because the deploy outcome is already decided and the operator can
/// re-run `rch workers enable`.
async fn re_enable_workers(workers: &[String]) {
    for id in workers {
        if let Err(error) = crate::status_display::enable_worker(id).await {
            tracing::warn!(
                "could not re-enable {id} after deploy: {error:#}; run `rch workers enable {id}`"
            );
        }
    }
}

/// Poll the daemon until none of `workers` has slots in use, or `timeout_secs`
/// elapses. Returns the workers still busy (empty when all went idle).
async fn wait_for_drained_idle(
    workers: &[String],
    timeout_secs: u64,
) -> Result<Vec<(String, u32)>> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    loop {
        let status = crate::status_display::query_daemon_full_status().await?;
        let busy: Vec<(String, u32)> = status
            .workers
            .iter()
            .filter(|worker| workers.contains(&worker.id) && worker.used_slots > 0)
            .map(|worker| (worker.id.clone(), worker.used_slots))
            .collect();
        if busy.is_empty() || std::time::Instant::now() >= deadline {
            return Ok(busy);
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

/// Show deployment history.
pub async fn history(ctx: &OutputContext, limit: usize, worker: Option<String>) -> Result<()> {
    let style = ctx.theme();

    let manager = HistoryManager::new()?;
    let entries = manager.get_history(limit, worker.as_deref())?;

    if ctx.is_json() {
        let _ = ctx.json(&ApiResponse::ok("fleet history", &entries));
        return Ok(());
    }

    println!("{}", style.format_header("Deployment History"));
    println!();

    if entries.is_empty() {
        println!("  {} No deployment history found", style.muted("→"));
        return Ok(());
    }

    for entry in &entries {
        let status_icon = if entry.success {
            StatusIndicator::Success.display(style)
        } else {
            StatusIndicator::Error.display(style)
        };

        println!(
            "  {} {} {} → {} ({})",
            status_icon,
            style.muted(&entry.timestamp),
            style.highlight(&entry.worker_id),
            style.value(&entry.version),
            style.muted(&format!("{}ms", entry.duration_ms))
        );
    }

    Ok(())
}

/// Find a local binary in common locations.
fn find_local_binary(name: &str) -> Result<PathBuf> {
    let current_exe_dir = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf));
    let home_dir = dirs::home_dir();
    let path_binary = which::which(name).ok();
    let cargo_target_dir = std::env::var_os("CARGO_TARGET_DIR").map(PathBuf::from);
    let cwd = std::env::current_dir().ok();

    for loc in local_binary_candidate_locations(
        name,
        current_exe_dir.as_deref(),
        home_dir.as_deref(),
        path_binary.as_deref(),
        cargo_target_dir.as_deref(),
        cwd.as_deref(),
    ) {
        if loc.exists() && loc.is_file() {
            return Ok(loc);
        }
    }

    Err(BinaryError::NotFound {
        name: name.to_string(),
    }
    .into())
}

fn local_binary_candidate_locations(
    name: &str,
    current_exe_dir: Option<&Path>,
    home_dir: Option<&Path>,
    path_binary: Option<&Path>,
    cargo_target_dir: Option<&Path>,
    cwd: Option<&Path>,
) -> Vec<PathBuf> {
    let mut locations = Vec::new();

    if let Some(dir) = current_exe_dir {
        locations.push(dir.join(name));
    }

    if let Some(home) = home_dir {
        locations.push(home.join(".local/bin").join(name));
        locations.push(home.join(".cargo/bin").join(name));
    }

    locations.push(PathBuf::from("/usr/local/bin").join(name));
    locations.push(PathBuf::from("/usr/bin").join(name));

    if let Some(path) = path_binary {
        locations.push(path.to_path_buf());
    }

    if let Some(target_dir) = cargo_target_dir {
        locations.push(target_dir.join("release").join(name));
        locations.push(target_dir.join("debug").join(name));
    }

    if let Some(cwd) = cwd {
        locations.push(cwd.join("target/release").join(name));
        locations.push(cwd.join("target/debug").join(name));
    }

    locations
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::context::{ColorChoice, OutputConfig, OutputContext, OutputFormat, OutputMode};
    use crate::ui::writer::SharedOutputBuffer;

    fn json_ctx() -> (OutputContext, SharedOutputBuffer) {
        let stdout = SharedOutputBuffer::new();
        let stderr = SharedOutputBuffer::new();

        let ctx = OutputContext::with_writers(
            OutputConfig {
                force_mode: Some(OutputMode::Json),
                color: ColorChoice::Never,
                format: OutputFormat::Json,
                ..OutputConfig::default()
            },
            stdout.as_writer(false),
            stderr.as_writer(false),
        );

        (ctx, stdout)
    }

    fn plain_ctx() -> OutputContext {
        let stdout = SharedOutputBuffer::new();
        let stderr = SharedOutputBuffer::new();

        OutputContext::with_writers(
            OutputConfig {
                force_mode: Some(OutputMode::Plain),
                color: ColorChoice::Never,
                ..OutputConfig::default()
            },
            stdout.as_writer(false),
            stderr.as_writer(false),
        )
    }

    fn parse_json_output(stdout: &SharedOutputBuffer) -> serde_json::Value {
        let raw = stdout.to_string_lossy();
        let trimmed = raw.trim();
        assert!(!trimmed.is_empty(), "expected JSON output, got empty");
        serde_json::from_str(trimmed).expect("output should be valid JSON")
    }

    fn assert_is_api_response(value: &serde_json::Value) {
        assert!(
            value.get("success").is_some(),
            "expected ApiResponse-like JSON with 'success' field"
        );
        assert!(
            value.get("command").is_some(),
            "expected ApiResponse-like JSON with 'command' field"
        );
    }

    #[test]
    fn binary_candidates_prefer_installed_sibling_over_stale_cargo_target() {
        let candidates = local_binary_candidate_locations(
            "rch-wkr",
            Some(Path::new("/home/ubuntu/.local/bin")),
            Some(Path::new("/home/ubuntu")),
            Some(Path::new("/data/tmp/cargo-target/release/rch-wkr")),
            Some(Path::new("/data/tmp/cargo-target")),
            Some(Path::new("/data/projects/remote_compilation_helper")),
        );

        let installed_sibling = PathBuf::from("/home/ubuntu/.local/bin/rch-wkr");
        let stale_target = PathBuf::from("/data/tmp/cargo-target/release/rch-wkr");

        assert_eq!(candidates.first(), Some(&installed_sibling));

        let installed_position = candidates
            .iter()
            .position(|path| path == &installed_sibling)
            .expect("installed sibling should be considered");
        let stale_target_position = candidates
            .iter()
            .position(|path| path == &stale_target)
            .expect("cargo target fallback should still be considered");

        assert!(
            installed_position < stale_target_position,
            "installed binary must win over stale CARGO_TARGET_DIR fallback"
        );
    }

    #[tokio::test]
    async fn deploy_dry_run_emits_json_response() {
        let (ctx, stdout) = json_ctx();
        deploy(
            &ctx, None, 2, None, 0, false, false, true, false, 0, true, false, None, None, true,
        )
        .await
        .unwrap();

        let value = parse_json_output(&stdout);
        assert_is_api_response(&value);
    }

    #[tokio::test]
    async fn rollback_dry_run_emits_json_response() {
        let (ctx, stdout) = json_ctx();
        rollback(&ctx, None, None, 2, false, true, true)
            .await
            .unwrap();

        let value = parse_json_output(&stdout);
        assert_is_api_response(&value);
    }

    #[tokio::test]
    async fn status_emits_json_response() {
        let (ctx, stdout) = json_ctx();
        status(&ctx, Some("definitely-missing-worker".to_string()), false)
            .await
            .unwrap();

        let value = parse_json_output(&stdout);
        assert_is_api_response(&value);
    }

    #[tokio::test]
    async fn verify_emits_json_response() {
        let (ctx, stdout) = json_ctx();
        verify(&ctx, Some("definitely-missing-worker".to_string()))
            .await
            .unwrap();

        let value = parse_json_output(&stdout);
        assert_is_api_response(&value);
    }

    #[tokio::test]
    async fn drain_requires_worker_or_all_in_json_mode() {
        let (ctx, stdout) = json_ctx();
        drain(&ctx, None, false, 10, true).await.unwrap();

        let value = parse_json_output(&stdout);
        assert_is_api_response(&value);
        assert!(
            !value
                .get("success")
                .and_then(|v| v.as_bool())
                .unwrap_or(true),
            "expected validation error"
        );
    }

    #[tokio::test]
    async fn drain_all_ok_even_when_no_workers_configured() {
        let (ctx, stdout) = json_ctx();
        drain(&ctx, None, true, 10, true).await.unwrap();

        let value = parse_json_output(&stdout);
        assert_is_api_response(&value);
    }

    #[tokio::test]
    async fn history_emits_json_response() {
        let (ctx, stdout) = json_ctx();
        history(&ctx, 5, None).await.unwrap();

        let value = parse_json_output(&stdout);
        assert_is_api_response(&value);
    }

    #[tokio::test]
    async fn non_json_modes_do_not_panic() {
        let ctx = plain_ctx();

        deploy(
            &ctx, None, 2, None, 0, false, false, true, false, 0, true, false, None, None, true,
        )
        .await
        .unwrap();

        rollback(&ctx, None, None, 2, false, true, true)
            .await
            .unwrap();
        status(&ctx, Some("definitely-missing-worker".to_string()), false)
            .await
            .unwrap();
        verify(&ctx, Some("definitely-missing-worker".to_string()))
            .await
            .unwrap();
        drain(&ctx, None, false, 10, true).await.unwrap();
        drain(&ctx, None, true, 10, true).await.unwrap();
        history(&ctx, 5, None).await.unwrap();
    }
}
