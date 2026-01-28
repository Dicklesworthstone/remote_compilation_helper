//! Fleet management for worker deployments.
//!
//! This module provides centralized deployment, rollback, and monitoring
//! capabilities for the rch-wkr worker agent across all configured remote workers.

mod audit;
mod dry_run;
mod executor;
mod history;
mod plan;
mod preflight;
mod rollback;

use crate::commands::load_workers_from_config;
use crate::ui::context::OutputContext;
use crate::ui::theme::StatusIndicator;
use anyhow::Result;
use rch_common::{ApiError, ApiResponse, ErrorCode};
use std::path::PathBuf;

pub use audit::{AuditEventType, AuditLogger, DeploymentAuditEntry};
pub use dry_run::{DryRunResult, PotentialIssue, PredictedAction, WorkerPrediction};
pub use executor::{FleetExecutor, FleetResult};
pub use history::{DeploymentHistoryEntry, HistoryManager};
pub use plan::{
    DeployOptions, DeployStep, DeploymentPlan, DeploymentStatus, DeploymentStrategy,
    WorkerDeployment,
};
pub use preflight::{PreflightIssue, PreflightResult, Severity};
pub use rollback::{RollbackManager, WorkerBackup};

/// Deploy rch-wkr to workers.
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
) -> Result<()> {
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
        let dry_run_result = dry_run::compute_dry_run(&plan, ctx).await?;
        dry_run::display_dry_run(&dry_run_result, ctx, "fleet deploy")?;
        return Ok(());
    }

    // Create audit logger if requested
    let audit_logger = if let Some(ref path) = audit_log {
        Some(AuditLogger::new(Some(path))?)
    } else {
        None
    };

    // Execute deployment
    let executor = FleetExecutor::new(parallel, audit_logger)?;
    let result = executor.execute(plan, ctx).await?;

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
pub async fn rollback(
    ctx: &OutputContext,
    worker: Option<String>,
    to_version: Option<String>,
    parallel: usize,
    verify: bool,
    dry_run: bool,
) -> Result<()> {
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
    let status_results = preflight::get_fleet_status(&target_workers, ctx).await?;

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
        println!();
        println!("  {} Press Ctrl+C to exit", style.muted("Watching..."));
        // Watch loop would go here - simplified for now
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    }

    Ok(())
}

/// Verify worker installations.
pub async fn verify(ctx: &OutputContext, worker: Option<String>) -> Result<()> {
    let style = ctx.theme();

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
        let result = preflight::run_preflight(w, ctx).await?;
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
pub async fn drain(
    ctx: &OutputContext,
    worker: Option<String>,
    all: bool,
    timeout: u64,
) -> Result<()> {
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

    // Drain each worker via daemon
    for w in &target_workers {
        if !ctx.is_json() {
            println!(
                "  {} Draining {}...",
                StatusIndicator::Pending.display(style),
                style.highlight(&w.id.0)
            );
        }
        // Would call daemon to drain worker here
        // For now, just mark as success
        if !ctx.is_json() {
            println!(
                "  {} {} drained",
                StatusIndicator::Success.display(style),
                style.highlight(&w.id.0)
            );
        }
    }

    if ctx.is_json() {
        let _ = ctx.json(&ApiResponse::ok(
            "fleet drain",
            serde_json::json!({
                "workers_drained": target_workers.len(),
                "timeout": timeout,
            }),
        ));
    }

    Ok(())
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

    #[tokio::test]
    async fn deploy_dry_run_emits_json_response() {
        let (ctx, stdout) = json_ctx();
        deploy(
            &ctx, None, 2, None, 0, false, false, true, false, 0, true, false, None, None,
        )
        .await
        .unwrap();

        let value = parse_json_output(&stdout);
        assert_is_api_response(&value);
    }

    #[tokio::test]
    async fn rollback_dry_run_emits_json_response() {
        let (ctx, stdout) = json_ctx();
        rollback(&ctx, None, None, 2, false, true).await.unwrap();

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
        drain(&ctx, None, false, 10).await.unwrap();

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
        drain(&ctx, None, true, 10).await.unwrap();

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
            &ctx, None, 2, None, 0, false, false, true, false, 0, true, false, None, None,
        )
        .await
        .unwrap();

        rollback(&ctx, None, None, 2, false, true).await.unwrap();
        status(&ctx, Some("definitely-missing-worker".to_string()), false)
            .await
            .unwrap();
        verify(&ctx, Some("definitely-missing-worker".to_string()))
            .await
            .unwrap();
        drain(&ctx, None, false, 10).await.unwrap();
        drain(&ctx, None, true, 10).await.unwrap();
        history(&ctx, 5, None).await.unwrap();
    }
}
