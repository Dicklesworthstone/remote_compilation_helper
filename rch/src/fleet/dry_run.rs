//! Enhanced dry run with predicted outcomes.

use crate::fleet::plan::{DeploymentPlan, DeploymentStrategy};
use crate::fleet::preflight::Severity;
use crate::ui::context::OutputContext;
use crate::ui::theme::StatusIndicator;
use anyhow::Result;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct DryRunResult {
    pub plan_id: String,
    pub predictions: Vec<WorkerPrediction>,
    pub estimated_duration_secs: u64,
    pub potential_issues: Vec<PotentialIssue>,
    pub resource_requirements: ResourceRequirements,
}

#[derive(Debug, Clone, Serialize)]
pub struct WorkerPrediction {
    pub worker_id: String,
    pub current_version: Option<String>,
    pub target_version: String,
    pub action: PredictedAction,
    pub estimated_transfer_mb: f64,
    pub estimated_time_secs: u64,
    pub preflight_issues: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum PredictedAction {
    Install,
    Upgrade,
    Downgrade,
    Reinstall,
    Skip,
}

#[derive(Debug, Clone, Serialize)]
pub struct PotentialIssue {
    pub severity: Severity,
    pub worker_id: Option<String>,
    pub issue: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResourceRequirements {
    pub total_transfer_mb: f64,
    pub peak_parallelism: usize,
    pub estimated_bandwidth_mbps: f64,
}

pub async fn compute_dry_run(plan: &DeploymentPlan, _ctx: &OutputContext) -> Result<DryRunResult> {
    const BINARY_SIZE_MB: f64 = 5.0;
    const BASE_DEPLOY_TIME_SECS: u64 = 30;

    let mut predictions = Vec::new();
    let mut issues = Vec::new();

    for worker in &plan.workers {
        let action = match &worker.current_version {
            None => PredictedAction::Install,
            Some(c) if c < &worker.target_version => PredictedAction::Upgrade,
            Some(c) if c > &worker.target_version => PredictedAction::Downgrade,
            Some(c) if c == &worker.target_version && plan.options.force => {
                PredictedAction::Reinstall
            }
            Some(_) => PredictedAction::Skip,
        };
        let (transfer, time) = if action == PredictedAction::Skip {
            (0.0, 0)
        } else {
            (BINARY_SIZE_MB, BASE_DEPLOY_TIME_SECS)
        };
        predictions.push(WorkerPrediction {
            worker_id: worker.worker_id.clone(),
            current_version: worker.current_version.clone(),
            target_version: worker.target_version.clone(),
            action,
            estimated_transfer_mb: transfer,
            estimated_time_secs: time,
            preflight_issues: vec![],
        });
    }

    let estimated_duration_secs = estimate_total_duration(&predictions, &plan.strategy);
    let total_transfer_mb: f64 = predictions.iter().map(|p| p.estimated_transfer_mb).sum();
    let peak_parallelism = match &plan.strategy {
        DeploymentStrategy::AllAtOnce { parallelism } => (*parallelism).min(predictions.len()),
        DeploymentStrategy::Canary { percent, .. } => {
            (predictions.len() * (*percent as usize) / 100).max(1)
        }
        DeploymentStrategy::Rolling { batch_size, .. } => *batch_size,
    };

    if predictions
        .iter()
        .all(|p| p.action == PredictedAction::Skip)
    {
        issues.push(PotentialIssue {
            severity: Severity::Info,
            worker_id: None,
            issue: "All workers already at target version".into(),
            recommendation: "Use --force to reinstall".into(),
        });
    }

    Ok(DryRunResult {
        plan_id: plan.id.to_string(),
        predictions,
        estimated_duration_secs,
        potential_issues: issues,
        resource_requirements: ResourceRequirements {
            total_transfer_mb,
            peak_parallelism,
            estimated_bandwidth_mbps: total_transfer_mb / (estimated_duration_secs as f64 + 1.0),
        },
    })
}

fn estimate_total_duration(predictions: &[WorkerPrediction], strategy: &DeploymentStrategy) -> u64 {
    let active: Vec<_> = predictions
        .iter()
        .filter(|p| p.action != PredictedAction::Skip)
        .collect();
    if active.is_empty() {
        return 0;
    }
    let max_time = active
        .iter()
        .map(|p| p.estimated_time_secs)
        .max()
        .unwrap_or(0);
    match strategy {
        DeploymentStrategy::AllAtOnce { parallelism } => {
            active.len().div_ceil(*parallelism) as u64 * max_time
        }
        DeploymentStrategy::Canary { wait_secs, .. } => max_time + wait_secs + max_time,
        DeploymentStrategy::Rolling {
            batch_size,
            wait_between,
        } => {
            let batches = active.len().div_ceil(*batch_size);
            batches as u64 * max_time + (batches.saturating_sub(1) as u64) * wait_between
        }
    }
}

pub fn display_dry_run(result: &DryRunResult, ctx: &OutputContext) -> Result<()> {
    let style = ctx.theme();
    if ctx.is_json() {
        let _ = ctx.json(&serde_json::json!({"dry_run": true, "result": result}));
        return Ok(());
    }

    println!("{}", style.format_header("Deployment Dry Run"));
    println!();
    let active_count = result
        .predictions
        .iter()
        .filter(|p| p.action != PredictedAction::Skip)
        .count();
    let skip_count = result.predictions.len() - active_count;
    println!(
        "  {} Workers: {} total, {} to deploy, {} to skip",
        style.muted("→"),
        style.value(&result.predictions.len().to_string()),
        style.success(&active_count.to_string()),
        style.muted(&skip_count.to_string())
    );
    println!(
        "  {} Estimated duration: {}s",
        style.muted("→"),
        style.value(&result.estimated_duration_secs.to_string())
    );
    println!(
        "  {} Total transfer: {:.1} MB",
        style.muted("→"),
        result.resource_requirements.total_transfer_mb
    );
    println!();
    println!("  {}", style.muted("Worker Actions:"));
    for pred in &result.predictions {
        let action_str = match pred.action {
            PredictedAction::Install => style.success("[INSTALL]"),
            PredictedAction::Upgrade => style.success("[UPGRADE]"),
            PredictedAction::Downgrade => style.warning("[DOWNGRADE]"),
            PredictedAction::Reinstall => style.muted("[REINSTALL]"),
            PredictedAction::Skip => style.muted("[SKIP]"),
        };
        println!(
            "    {} {} {} → {} (~{:.1}MB, ~{}s)",
            action_str,
            style.highlight(&pred.worker_id),
            style.muted(pred.current_version.as_deref().unwrap_or("none")),
            pred.target_version,
            pred.estimated_transfer_mb,
            pred.estimated_time_secs
        );
    }
    if !result.potential_issues.is_empty() {
        println!();
        println!("  {}", style.muted("Potential Issues:"));
        for issue in &result.potential_issues {
            let icon = match issue.severity {
                Severity::Error => StatusIndicator::Error.display(style),
                Severity::Warning => StatusIndicator::Warning.display(style),
                Severity::Info => StatusIndicator::Info.display(style),
            };
            println!(
                "    {} [{}] {}",
                icon,
                issue.worker_id.as_deref().unwrap_or("global"),
                issue.issue
            );
        }
    }
    println!();
    println!(
        "  {} This is a dry run. No changes were made.",
        style.muted("ℹ")
    );
    Ok(())
}
