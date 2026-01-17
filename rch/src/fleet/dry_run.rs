//! Dry-run simulation for fleet deployments.
//!
//! Predicts outcomes without making actual changes.

use super::plan::DeploymentPlan;
use crate::ui::context::OutputContext;
use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Result of a dry-run simulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DryRunResult {
    pub predictions: Vec<WorkerPrediction>,
    pub issues: Vec<PotentialIssue>,
}

/// Prediction for a single worker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerPrediction {
    pub worker_id: String,
    pub actions: Vec<PredictedAction>,
    pub would_succeed: bool,
}

/// A predicted action that would be taken.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PredictedAction {
    Transfer { bytes: u64, files: usize },
    Execute { command: String },
    Verify { checks: Vec<String> },
}

/// A potential issue detected during dry-run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PotentialIssue {
    pub severity: String,
    pub message: String,
    pub worker_id: Option<String>,
}

/// Compute dry-run results for a deployment plan.
pub async fn compute_dry_run(plan: &DeploymentPlan, _ctx: &OutputContext) -> Result<DryRunResult> {
    let predictions: Vec<WorkerPrediction> = plan
        .workers
        .iter()
        .map(|w| WorkerPrediction {
            worker_id: w.worker_id.clone(),
            actions: vec![PredictedAction::Transfer { bytes: 0, files: 0 }],
            would_succeed: true,
        })
        .collect();

    Ok(DryRunResult {
        predictions,
        issues: vec![],
    })
}

/// Display dry-run results to the user.
pub fn display_dry_run(result: &DryRunResult, ctx: &OutputContext) -> Result<()> {
    let style = ctx.theme();
    println!("{}", style.format_header("Dry Run Results"));
    println!();
    for pred in &result.predictions {
        println!("  {} {}", style.muted("→"), pred.worker_id);
    }
    Ok(())
}
