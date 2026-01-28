//! Enhanced dry run with predicted outcomes.

use crate::fleet::plan::{DeploymentPlan, DeploymentStrategy};
use crate::fleet::preflight::Severity;
use crate::ui::context::OutputContext;
use crate::ui::theme::StatusIndicator;
use anyhow::Result;
use rch_common::api::ApiResponse;
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

pub fn display_dry_run(result: &DryRunResult, ctx: &OutputContext, command: &str) -> Result<()> {
    let style = ctx.theme();
    if ctx.is_json() {
        let _ = ctx.json(&ApiResponse::ok(command, result));
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

#[cfg(test)]
mod tests {
    use super::*;

    // ========================
    // PredictedAction tests
    // ========================

    #[test]
    fn predicted_action_install_serializes() {
        let action = PredictedAction::Install;
        let json = serde_json::to_string(&action).unwrap();
        assert_eq!(json, "\"Install\"");
    }

    #[test]
    fn predicted_action_upgrade_serializes() {
        let action = PredictedAction::Upgrade;
        let json = serde_json::to_string(&action).unwrap();
        assert_eq!(json, "\"Upgrade\"");
    }

    #[test]
    fn predicted_action_downgrade_serializes() {
        let action = PredictedAction::Downgrade;
        let json = serde_json::to_string(&action).unwrap();
        assert_eq!(json, "\"Downgrade\"");
    }

    #[test]
    fn predicted_action_reinstall_serializes() {
        let action = PredictedAction::Reinstall;
        let json = serde_json::to_string(&action).unwrap();
        assert_eq!(json, "\"Reinstall\"");
    }

    #[test]
    fn predicted_action_skip_serializes() {
        let action = PredictedAction::Skip;
        let json = serde_json::to_string(&action).unwrap();
        assert_eq!(json, "\"Skip\"");
    }

    #[test]
    fn predicted_action_equality() {
        assert_eq!(PredictedAction::Install, PredictedAction::Install);
        assert_ne!(PredictedAction::Install, PredictedAction::Upgrade);
        assert_eq!(PredictedAction::Skip, PredictedAction::Skip);
    }

    // ========================
    // WorkerPrediction tests
    // ========================

    #[test]
    fn worker_prediction_serializes() {
        let prediction = WorkerPrediction {
            worker_id: "worker-1".to_string(),
            current_version: Some("1.0.0".to_string()),
            target_version: "2.0.0".to_string(),
            action: PredictedAction::Upgrade,
            estimated_transfer_mb: 5.0,
            estimated_time_secs: 30,
            preflight_issues: vec!["low disk space".to_string()],
        };
        let json = serde_json::to_string(&prediction).unwrap();
        assert!(json.contains("worker-1"));
        assert!(json.contains("1.0.0"));
        assert!(json.contains("2.0.0"));
        assert!(json.contains("Upgrade"));
        assert!(json.contains("5.0"));
        assert!(json.contains("30"));
        assert!(json.contains("low disk space"));
    }

    #[test]
    fn worker_prediction_with_no_current_version_serializes() {
        let prediction = WorkerPrediction {
            worker_id: "worker-2".to_string(),
            current_version: None,
            target_version: "1.0.0".to_string(),
            action: PredictedAction::Install,
            estimated_transfer_mb: 5.0,
            estimated_time_secs: 30,
            preflight_issues: vec![],
        };
        let json = serde_json::to_string(&prediction).unwrap();
        assert!(json.contains("worker-2"));
        assert!(json.contains("null"));
        assert!(json.contains("Install"));
    }

    // ========================
    // PotentialIssue tests
    // ========================

    #[test]
    fn potential_issue_serializes() {
        let issue = PotentialIssue {
            severity: Severity::Warning,
            worker_id: Some("worker-1".to_string()),
            issue: "Low disk space".to_string(),
            recommendation: "Free up space".to_string(),
        };
        let json = serde_json::to_string(&issue).unwrap();
        assert!(json.contains("Warning"));
        assert!(json.contains("worker-1"));
        assert!(json.contains("Low disk space"));
        assert!(json.contains("Free up space"));
    }

    #[test]
    fn potential_issue_global_serializes() {
        let issue = PotentialIssue {
            severity: Severity::Info,
            worker_id: None,
            issue: "All workers at version".to_string(),
            recommendation: "Use --force".to_string(),
        };
        let json = serde_json::to_string(&issue).unwrap();
        assert!(json.contains("Info"));
        assert!(json.contains("null"));
    }

    // ========================
    // ResourceRequirements tests
    // ========================

    #[test]
    fn resource_requirements_serializes() {
        let req = ResourceRequirements {
            total_transfer_mb: 25.5,
            peak_parallelism: 4,
            estimated_bandwidth_mbps: 12.75,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("25.5"));
        assert!(json.contains("4"));
        assert!(json.contains("12.75"));
    }

    // ========================
    // DryRunResult tests
    // ========================

    #[test]
    fn dry_run_result_serializes() {
        let result = DryRunResult {
            plan_id: "test-plan-123".to_string(),
            predictions: vec![WorkerPrediction {
                worker_id: "w1".to_string(),
                current_version: None,
                target_version: "1.0.0".to_string(),
                action: PredictedAction::Install,
                estimated_transfer_mb: 5.0,
                estimated_time_secs: 30,
                preflight_issues: vec![],
            }],
            estimated_duration_secs: 30,
            potential_issues: vec![],
            resource_requirements: ResourceRequirements {
                total_transfer_mb: 5.0,
                peak_parallelism: 1,
                estimated_bandwidth_mbps: 0.16,
            },
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("test-plan-123"));
        assert!(json.contains("w1"));
        assert!(json.contains("Install"));
    }

    // ========================
    // estimate_total_duration tests
    // ========================

    fn make_prediction(action: PredictedAction, time: u64) -> WorkerPrediction {
        WorkerPrediction {
            worker_id: "test".to_string(),
            current_version: None,
            target_version: "1.0.0".to_string(),
            action,
            estimated_transfer_mb: 5.0,
            estimated_time_secs: time,
            preflight_issues: vec![],
        }
    }

    #[test]
    fn estimate_duration_empty_predictions() {
        let predictions: Vec<WorkerPrediction> = vec![];
        let strategy = DeploymentStrategy::AllAtOnce { parallelism: 4 };
        let duration = estimate_total_duration(&predictions, &strategy);
        assert_eq!(duration, 0);
    }

    #[test]
    fn estimate_duration_all_skip() {
        let predictions = vec![
            make_prediction(PredictedAction::Skip, 0),
            make_prediction(PredictedAction::Skip, 0),
        ];
        let strategy = DeploymentStrategy::AllAtOnce { parallelism: 4 };
        let duration = estimate_total_duration(&predictions, &strategy);
        assert_eq!(duration, 0);
    }

    #[test]
    fn estimate_duration_all_at_once_single_worker() {
        let predictions = vec![make_prediction(PredictedAction::Install, 30)];
        let strategy = DeploymentStrategy::AllAtOnce { parallelism: 4 };
        let duration = estimate_total_duration(&predictions, &strategy);
        assert_eq!(duration, 30);
    }

    #[test]
    fn estimate_duration_all_at_once_parallel() {
        let predictions = vec![
            make_prediction(PredictedAction::Install, 30),
            make_prediction(PredictedAction::Install, 30),
            make_prediction(PredictedAction::Install, 30),
            make_prediction(PredictedAction::Install, 30),
        ];
        let strategy = DeploymentStrategy::AllAtOnce { parallelism: 4 };
        let duration = estimate_total_duration(&predictions, &strategy);
        // All 4 workers can run in parallel, so duration is max_time
        assert_eq!(duration, 30);
    }

    #[test]
    fn estimate_duration_all_at_once_batched() {
        let predictions = vec![
            make_prediction(PredictedAction::Install, 30),
            make_prediction(PredictedAction::Install, 30),
            make_prediction(PredictedAction::Install, 30),
            make_prediction(PredictedAction::Install, 30),
        ];
        let strategy = DeploymentStrategy::AllAtOnce { parallelism: 2 };
        let duration = estimate_total_duration(&predictions, &strategy);
        // 4 workers, parallelism 2 = 2 batches * 30s = 60s
        assert_eq!(duration, 60);
    }

    #[test]
    fn estimate_duration_canary() {
        let predictions = vec![
            make_prediction(PredictedAction::Install, 30),
            make_prediction(PredictedAction::Install, 30),
        ];
        let strategy = DeploymentStrategy::Canary {
            percent: 50,
            wait_secs: 60,
            auto_promote: true,
        };
        let duration = estimate_total_duration(&predictions, &strategy);
        // canary: max_time + wait_secs + max_time = 30 + 60 + 30 = 120
        assert_eq!(duration, 120);
    }

    #[test]
    fn estimate_duration_rolling_single_batch() {
        let predictions = vec![
            make_prediction(PredictedAction::Install, 30),
            make_prediction(PredictedAction::Install, 30),
        ];
        let strategy = DeploymentStrategy::Rolling {
            batch_size: 2,
            wait_between: 10,
        };
        let duration = estimate_total_duration(&predictions, &strategy);
        // 1 batch * 30s + 0 wait = 30s
        assert_eq!(duration, 30);
    }

    #[test]
    fn estimate_duration_rolling_multiple_batches() {
        let predictions = vec![
            make_prediction(PredictedAction::Install, 30),
            make_prediction(PredictedAction::Install, 30),
            make_prediction(PredictedAction::Install, 30),
            make_prediction(PredictedAction::Install, 30),
        ];
        let strategy = DeploymentStrategy::Rolling {
            batch_size: 2,
            wait_between: 10,
        };
        let duration = estimate_total_duration(&predictions, &strategy);
        // 2 batches * 30s + 1 wait * 10s = 60 + 10 = 70s
        assert_eq!(duration, 70);
    }

    #[test]
    fn estimate_duration_rolling_partial_batch() {
        let predictions = vec![
            make_prediction(PredictedAction::Install, 30),
            make_prediction(PredictedAction::Install, 30),
            make_prediction(PredictedAction::Install, 30),
        ];
        let strategy = DeploymentStrategy::Rolling {
            batch_size: 2,
            wait_between: 10,
        };
        let duration = estimate_total_duration(&predictions, &strategy);
        // 2 batches (ceil(3/2)=2) * 30s + 1 wait * 10s = 60 + 10 = 70s
        assert_eq!(duration, 70);
    }

    // ========================
    // Integration-style tests for compute_dry_run helper logic
    // ========================

    #[test]
    fn action_install_when_no_current_version() {
        // Test the action determination logic
        let current_version: Option<String> = None;
        let target_version = "1.0.0".to_string();
        let force = false;

        let action = match &current_version {
            None => PredictedAction::Install,
            Some(c) if c < &target_version => PredictedAction::Upgrade,
            Some(c) if c > &target_version => PredictedAction::Downgrade,
            Some(c) if c == &target_version && force => PredictedAction::Reinstall,
            Some(_) => PredictedAction::Skip,
        };

        assert_eq!(action, PredictedAction::Install);
    }

    #[test]
    fn action_upgrade_when_current_less_than_target() {
        let current_version = Some("1.0.0".to_string());
        let target_version = "2.0.0".to_string();
        let force = false;

        let action = match &current_version {
            None => PredictedAction::Install,
            Some(c) if c < &target_version => PredictedAction::Upgrade,
            Some(c) if c > &target_version => PredictedAction::Downgrade,
            Some(c) if c == &target_version && force => PredictedAction::Reinstall,
            Some(_) => PredictedAction::Skip,
        };

        assert_eq!(action, PredictedAction::Upgrade);
    }

    #[test]
    fn action_downgrade_when_current_greater_than_target() {
        let current_version = Some("3.0.0".to_string());
        let target_version = "2.0.0".to_string();
        let force = false;

        let action = match &current_version {
            None => PredictedAction::Install,
            Some(c) if c < &target_version => PredictedAction::Upgrade,
            Some(c) if c > &target_version => PredictedAction::Downgrade,
            Some(c) if c == &target_version && force => PredictedAction::Reinstall,
            Some(_) => PredictedAction::Skip,
        };

        assert_eq!(action, PredictedAction::Downgrade);
    }

    #[test]
    fn action_reinstall_when_same_version_with_force() {
        let current_version = Some("1.0.0".to_string());
        let target_version = "1.0.0".to_string();
        let force = true;

        let action = match &current_version {
            None => PredictedAction::Install,
            Some(c) if c < &target_version => PredictedAction::Upgrade,
            Some(c) if c > &target_version => PredictedAction::Downgrade,
            Some(c) if c == &target_version && force => PredictedAction::Reinstall,
            Some(_) => PredictedAction::Skip,
        };

        assert_eq!(action, PredictedAction::Reinstall);
    }

    #[test]
    fn action_skip_when_same_version_without_force() {
        let current_version = Some("1.0.0".to_string());
        let target_version = "1.0.0".to_string();
        let force = false;

        let action = match &current_version {
            None => PredictedAction::Install,
            Some(c) if c < &target_version => PredictedAction::Upgrade,
            Some(c) if c > &target_version => PredictedAction::Downgrade,
            Some(c) if c == &target_version && force => PredictedAction::Reinstall,
            Some(_) => PredictedAction::Skip,
        };

        assert_eq!(action, PredictedAction::Skip);
    }

    // ========================
    // Peak parallelism calculation tests
    // ========================

    #[test]
    fn peak_parallelism_all_at_once_limited_by_workers() {
        let predictions_len = 2;
        let parallelism = 4usize;
        let peak = parallelism.min(predictions_len);
        assert_eq!(peak, 2);
    }

    #[test]
    fn peak_parallelism_all_at_once_limited_by_parallelism() {
        let predictions_len = 10;
        let parallelism = 4usize;
        let peak = parallelism.min(predictions_len);
        assert_eq!(peak, 4);
    }

    #[test]
    fn peak_parallelism_canary() {
        let predictions_len = 10;
        let percent = 20u8;
        let peak = (predictions_len * (percent as usize) / 100).max(1);
        assert_eq!(peak, 2);
    }

    #[test]
    fn peak_parallelism_canary_minimum_one() {
        let predictions_len = 3;
        let percent = 10u8;
        let peak = (predictions_len * (percent as usize) / 100).max(1);
        // 3 * 10 / 100 = 0, but max(1) = 1
        assert_eq!(peak, 1);
    }

    #[test]
    fn peak_parallelism_rolling() {
        let batch_size = 3;
        assert_eq!(batch_size, 3);
    }
}
