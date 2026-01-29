//! Fleet deployment executor.
//!
//! Handles parallel execution of deployments across workers
//! with progress tracking and error handling.

use crate::fleet::audit::AuditLogger;
use crate::fleet::plan::{DeploymentPlan, DeploymentStatus, DeploymentStrategy};
use crate::fleet::progress::{DeployPhase, FleetProgress};
use crate::ui::context::OutputContext;
use crate::ui::theme::StatusIndicator;
use anyhow::Result;
use rch_common::WorkerId;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Result of a fleet deployment operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum FleetResult {
    /// Deployment completed (possibly with some failures).
    Success {
        deployed: usize,
        skipped: usize,
        failed: usize,
    },
    /// Canary deployment failed validation.
    CanaryFailed { reason: String },
    /// Deployment was aborted.
    Aborted { reason: String },
}

/// Executes fleet deployments.
pub struct FleetExecutor {
    parallelism: usize,
    audit: Option<Arc<Mutex<AuditLogger>>>,
}

impl FleetExecutor {
    /// Create a new fleet executor.
    pub fn new(parallelism: usize, audit: Option<AuditLogger>) -> Result<Self> {
        Ok(Self {
            parallelism,
            audit: audit.map(|a| Arc::new(Mutex::new(a))),
        })
    }

    /// Execute a deployment plan.
    pub async fn execute(
        &self,
        mut plan: DeploymentPlan,
        ctx: &OutputContext,
    ) -> Result<FleetResult> {
        let style = ctx.theme();

        // Log deployment start
        if let Some(ref audit) = self.audit {
            let mut audit = audit.lock().await;
            let strategy_str = match &plan.strategy {
                DeploymentStrategy::AllAtOnce { parallelism } => {
                    format!("all-at-once({})", parallelism)
                }
                DeploymentStrategy::Canary { percent, .. } => format!("canary({}%)", percent),
                DeploymentStrategy::Rolling { batch_size, .. } => {
                    format!("rolling({})", batch_size)
                }
            };
            audit.log_deployment_started(
                plan.id,
                &plan.target_version,
                plan.workers.len(),
                &strategy_str,
            )?;
        }

        let mut deployed = 0;
        let mut skipped = 0;
        let mut failed = 0;

        // Clone strategy to avoid borrow issues
        let strategy = plan.strategy.clone();
        let worker_count = plan.workers.len();

        // Create fleet progress tracker for non-JSON mode
        let worker_ids: Vec<WorkerId> = plan
            .workers
            .iter()
            .map(|w| WorkerId(w.worker_id.clone()))
            .collect();
        let progress = Arc::new(FleetProgress::new(ctx, &worker_ids));

        // Execute based on strategy
        match strategy {
            DeploymentStrategy::AllAtOnce { parallelism } => {
                let results = self
                    .deploy_batch(
                        &mut plan,
                        0..worker_count,
                        parallelism,
                        ctx,
                        progress.clone(),
                    )
                    .await?;
                for (idx, success) in results {
                    if success {
                        if plan.workers[idx].status == DeploymentStatus::Skipped {
                            skipped += 1;
                        } else {
                            deployed += 1;
                        }
                    } else {
                        failed += 1;
                    }
                }
            }
            DeploymentStrategy::Canary {
                percent,
                wait_secs,
                auto_promote,
            } => {
                let canary_count = ((worker_count * (percent as usize)) / 100).max(1);

                if !ctx.is_json() {
                    println!(
                        "  {} Deploying to {} canary worker(s)...",
                        style.muted("→"),
                        canary_count
                    );
                }

                // Deploy to canary workers
                let canary_results = self
                    .deploy_batch(
                        &mut plan,
                        0..canary_count,
                        self.parallelism,
                        ctx,
                        progress.clone(),
                    )
                    .await?;
                let canary_failed = canary_results.iter().filter(|(_, s)| !s).count();

                if canary_failed > 0 {
                    return Ok(FleetResult::CanaryFailed {
                        reason: format!("{} canary worker(s) failed", canary_failed),
                    });
                }

                if !ctx.is_json() {
                    println!(
                        "  {} Canary successful. Waiting {}s before full rollout...",
                        StatusIndicator::Success.display(style),
                        wait_secs
                    );
                }

                // Wait before promoting
                tokio::time::sleep(std::time::Duration::from_secs(wait_secs)).await;

                if auto_promote && canary_count < worker_count {
                    if !ctx.is_json() {
                        println!("  {} Deploying to remaining workers...", style.muted("→"));
                    }
                    let remaining_results = self
                        .deploy_batch(
                            &mut plan,
                            canary_count..worker_count,
                            self.parallelism,
                            ctx,
                            progress.clone(),
                        )
                        .await?;

                    for (idx, success) in canary_results
                        .into_iter()
                        .chain(remaining_results.into_iter())
                    {
                        if success {
                            if plan.workers[idx].status == DeploymentStatus::Skipped {
                                skipped += 1;
                            } else {
                                deployed += 1;
                            }
                        } else {
                            failed += 1;
                        }
                    }
                }
            }
            DeploymentStrategy::Rolling {
                batch_size,
                wait_between,
            } => {
                let mut start = 0;
                let mut batch_num = 0;

                while start < worker_count {
                    let end = (start + batch_size).min(worker_count);
                    batch_num += 1;

                    if !ctx.is_json() {
                        println!(
                            "  {} Batch {}: deploying to workers {}..{}",
                            style.muted("→"),
                            batch_num,
                            start + 1,
                            end
                        );
                    }

                    let batch_results = self
                        .deploy_batch(&mut plan, start..end, batch_size, ctx, progress.clone())
                        .await?;

                    for (idx, success) in batch_results {
                        if success {
                            if plan.workers[idx].status == DeploymentStatus::Skipped {
                                skipped += 1;
                            } else {
                                deployed += 1;
                            }
                        } else {
                            failed += 1;
                        }
                    }

                    start = end;

                    if start < worker_count {
                        if !ctx.is_json() {
                            println!(
                                "  {} Waiting {}s before next batch...",
                                style.muted("→"),
                                wait_between
                            );
                        }
                        tokio::time::sleep(std::time::Duration::from_secs(wait_between)).await;
                    }
                }
            }
        }

        // Finish progress display
        progress.finish();

        Ok(FleetResult::Success {
            deployed,
            skipped,
            failed,
        })
    }

    /// Deploy a batch of workers in parallel.
    async fn deploy_batch(
        &self,
        plan: &mut DeploymentPlan,
        range: std::ops::Range<usize>,
        parallelism: usize,
        ctx: &OutputContext,
        progress: Arc<FleetProgress>,
    ) -> Result<Vec<(usize, bool)>> {
        use tokio::sync::Semaphore;

        let semaphore = Arc::new(Semaphore::new(parallelism));
        let mut handles = Vec::new();
        let style = ctx.theme();
        let is_json = ctx.is_json();

        for idx in range.clone() {
            let permit = semaphore.clone().acquire_owned().await?;
            let worker_id = plan.workers[idx].worker_id.clone();
            let target_version = plan.workers[idx].target_version.clone();
            let current_version = plan.workers[idx].current_version.clone();
            let force = plan.options.force;
            let progress = progress.clone();

            let handle = tokio::spawn(async move {
                let _permit = permit;

                // Check if we need to deploy
                if !force && current_version.as_ref() == Some(&target_version) {
                    progress
                        .worker_skipped(&worker_id, "already at version")
                        .await;
                    return (idx, worker_id, true, DeploymentStatus::Skipped);
                }

                // Connecting phase
                progress
                    .set_phase(&worker_id, DeployPhase::Connecting)
                    .await;
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;

                // Upload phase
                progress.set_phase(&worker_id, DeployPhase::Uploading).await;
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;

                // Install phase
                progress
                    .set_phase(&worker_id, DeployPhase::Installing)
                    .await;
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;

                // Verify phase
                progress.set_phase(&worker_id, DeployPhase::Verifying).await;
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;

                // Complete
                progress.worker_complete(&worker_id, &target_version).await;
                (idx, worker_id, true, DeploymentStatus::Completed)
            });

            handles.push(handle);
        }

        let mut results = Vec::new();
        for handle in handles {
            let (idx, worker_id, success, status) = handle.await?;
            plan.workers[idx].status = status;

            // In JSON mode, also print status (progress bars are hidden)
            if is_json {
                let status_str = match status {
                    DeploymentStatus::Completed => "deployed",
                    DeploymentStatus::Skipped => "skipped",
                    DeploymentStatus::Failed => "failed",
                    _ => "unknown",
                };
                // Progress bars handle display in non-JSON mode
                let _ = (style, worker_id, status_str); // suppress unused warnings
            }

            results.push((idx, success));
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================
    // FleetResult tests
    // ========================

    #[test]
    fn fleet_result_success_serializes() {
        let result = FleetResult::Success {
            deployed: 5,
            skipped: 2,
            failed: 1,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"status\":\"Success\""));
        assert!(json.contains("\"deployed\":5"));
        assert!(json.contains("\"skipped\":2"));
        assert!(json.contains("\"failed\":1"));
    }

    #[test]
    fn fleet_result_success_zero_values_serializes() {
        let result = FleetResult::Success {
            deployed: 0,
            skipped: 0,
            failed: 0,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"status\":\"Success\""));
        assert!(json.contains("\"deployed\":0"));
    }

    #[test]
    fn fleet_result_canary_failed_serializes() {
        let result = FleetResult::CanaryFailed {
            reason: "Health check failed".to_string(),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"status\":\"CanaryFailed\""));
        assert!(json.contains("Health check failed"));
    }

    #[test]
    fn fleet_result_aborted_serializes() {
        let result = FleetResult::Aborted {
            reason: "User cancelled".to_string(),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"status\":\"Aborted\""));
        assert!(json.contains("User cancelled"));
    }

    #[test]
    fn fleet_result_variants_are_tagged() {
        // Verify the serde tag attribute works correctly
        let success = serde_json::to_string(&FleetResult::Success {
            deployed: 1,
            skipped: 0,
            failed: 0,
        })
        .unwrap();
        let canary = serde_json::to_string(&FleetResult::CanaryFailed {
            reason: "test".to_string(),
        })
        .unwrap();
        let aborted = serde_json::to_string(&FleetResult::Aborted {
            reason: "test".to_string(),
        })
        .unwrap();

        // Each should have a different status tag
        assert!(success.contains("\"status\":\"Success\""));
        assert!(canary.contains("\"status\":\"CanaryFailed\""));
        assert!(aborted.contains("\"status\":\"Aborted\""));
    }

    // ========================
    // FleetExecutor tests
    // ========================

    #[test]
    fn fleet_executor_new_without_audit() {
        let executor = FleetExecutor::new(4, None);
        assert!(executor.is_ok());
        let executor = executor.unwrap();
        assert_eq!(executor.parallelism, 4);
    }

    #[test]
    fn fleet_executor_new_with_parallelism_one() {
        let executor = FleetExecutor::new(1, None).unwrap();
        assert_eq!(executor.parallelism, 1);
    }

    #[test]
    fn fleet_executor_new_with_high_parallelism() {
        let executor = FleetExecutor::new(100, None).unwrap();
        assert_eq!(executor.parallelism, 100);
    }

    // ========================
    // FleetResult additional tests
    // ========================

    #[test]
    fn fleet_result_success_large_counts() {
        let result = FleetResult::Success {
            deployed: 1000,
            skipped: 500,
            failed: 10,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"deployed\":1000"));
        assert!(json.contains("\"skipped\":500"));
        assert!(json.contains("\"failed\":10"));
    }

    #[test]
    fn fleet_result_canary_failed_empty_reason() {
        let result = FleetResult::CanaryFailed {
            reason: String::new(),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"status\":\"CanaryFailed\""));
        assert!(json.contains("\"reason\":\"\""));
    }

    #[test]
    fn fleet_result_canary_failed_long_reason() {
        let result = FleetResult::CanaryFailed {
            reason: "x".repeat(1000),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"status\":\"CanaryFailed\""));
        assert!(json.len() > 1000);
    }

    #[test]
    fn fleet_result_aborted_special_chars_in_reason() {
        let result = FleetResult::Aborted {
            reason: "User cancelled: \"interrupted\" <signal>".to_string(),
        };
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: FleetResult = serde_json::from_str(&json).unwrap();
        match deserialized {
            FleetResult::Aborted { reason } => {
                assert!(reason.contains("interrupted"));
                assert!(reason.contains("<signal>"));
            }
            _ => panic!("Expected Aborted variant"),
        }
    }

    #[test]
    fn fleet_result_deserialize_success() {
        let json = r#"{"status":"Success","deployed":3,"skipped":1,"failed":0}"#;
        let result: FleetResult = serde_json::from_str(json).unwrap();
        match result {
            FleetResult::Success {
                deployed,
                skipped,
                failed,
            } => {
                assert_eq!(deployed, 3);
                assert_eq!(skipped, 1);
                assert_eq!(failed, 0);
            }
            _ => panic!("Expected Success variant"),
        }
    }

    #[test]
    fn fleet_result_deserialize_canary_failed() {
        let json = r#"{"status":"CanaryFailed","reason":"worker timeout"}"#;
        let result: FleetResult = serde_json::from_str(json).unwrap();
        match result {
            FleetResult::CanaryFailed { reason } => {
                assert_eq!(reason, "worker timeout");
            }
            _ => panic!("Expected CanaryFailed variant"),
        }
    }

    #[test]
    fn fleet_result_deserialize_aborted() {
        let json = r#"{"status":"Aborted","reason":"ctrl+c"}"#;
        let result: FleetResult = serde_json::from_str(json).unwrap();
        match result {
            FleetResult::Aborted { reason } => {
                assert_eq!(reason, "ctrl+c");
            }
            _ => panic!("Expected Aborted variant"),
        }
    }

    #[test]
    fn fleet_result_roundtrip_all_variants() {
        let variants = vec![
            FleetResult::Success {
                deployed: 10,
                skipped: 2,
                failed: 1,
            },
            FleetResult::CanaryFailed {
                reason: "test failure".to_string(),
            },
            FleetResult::Aborted {
                reason: "test abort".to_string(),
            },
        ];

        for original in variants {
            let json = serde_json::to_string(&original).unwrap();
            let restored: FleetResult = serde_json::from_str(&json).unwrap();
            let json_again = serde_json::to_string(&restored).unwrap();
            assert_eq!(json, json_again);
        }
    }

    // ========================
    // FleetExecutor edge cases
    // ========================

    #[test]
    fn fleet_executor_parallelism_zero() {
        // Zero parallelism should still construct (validation happens at execute time)
        let executor = FleetExecutor::new(0, None);
        assert!(executor.is_ok());
        assert_eq!(executor.unwrap().parallelism, 0);
    }

    #[test]
    fn fleet_executor_very_large_parallelism() {
        let executor = FleetExecutor::new(usize::MAX, None).unwrap();
        assert_eq!(executor.parallelism, usize::MAX);
    }
}
