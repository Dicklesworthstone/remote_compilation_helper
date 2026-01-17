//! Fleet deployment executor.
//!
//! Handles parallel execution of deployments across workers
//! with progress tracking and error handling.

use crate::fleet::audit::AuditLogger;
use crate::fleet::plan::{DeploymentPlan, DeploymentStatus, DeploymentStrategy};
use crate::ui::context::OutputContext;
use crate::ui::theme::StatusIndicator;
use anyhow::Result;
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Result of a fleet deployment operation.
#[derive(Debug, Clone, Serialize)]
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

        // Execute based on strategy
        match strategy {
            DeploymentStrategy::AllAtOnce { parallelism } => {
                let results = self
                    .deploy_batch(&mut plan, 0..worker_count, parallelism, ctx)
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
                    .deploy_batch(&mut plan, 0..canary_count, self.parallelism, ctx)
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
                        .deploy_batch(&mut plan, canary_count..worker_count, self.parallelism, ctx)
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
                        .deploy_batch(&mut plan, start..end, batch_size, ctx)
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
    ) -> Result<Vec<(usize, bool)>> {
        use tokio::sync::Semaphore;

        let semaphore = Arc::new(Semaphore::new(parallelism));
        let mut handles = Vec::new();
        let style = ctx.theme();

        for idx in range {
            let permit = semaphore.clone().acquire_owned().await?;
            let _worker_id = plan.workers[idx].worker_id.clone();
            let target_version = plan.workers[idx].target_version.clone();
            let current_version = plan.workers[idx].current_version.clone();
            let force = plan.options.force;
            let _is_json = ctx.is_json();

            let handle = tokio::spawn(async move {
                let _permit = permit;

                // Check if we need to deploy
                if !force && current_version.as_ref() == Some(&target_version) {
                    return (idx, true, DeploymentStatus::Skipped);
                }

                // Simulate deployment steps (real implementation would SSH to worker)
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;

                // Return success
                (idx, true, DeploymentStatus::Completed)
            });

            handles.push(handle);
        }

        let mut results = Vec::new();
        for handle in handles {
            let (idx, success, status) = handle.await?;
            plan.workers[idx].status = status;

            if !ctx.is_json() {
                let icon = if success {
                    if status == DeploymentStatus::Skipped {
                        StatusIndicator::Info.display(style)
                    } else {
                        StatusIndicator::Success.display(style)
                    }
                } else {
                    StatusIndicator::Error.display(style)
                };
                let status_str = match status {
                    DeploymentStatus::Completed => "deployed",
                    DeploymentStatus::Skipped => "skipped (already at version)",
                    DeploymentStatus::Failed => "failed",
                    _ => "unknown",
                };
                println!(
                    "    {} {} {}",
                    icon,
                    style.highlight(&plan.workers[idx].worker_id),
                    style.muted(status_str)
                );
            }

            results.push((idx, success));
        }

        Ok(results)
    }
}
