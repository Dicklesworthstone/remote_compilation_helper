//! Fleet deployment executor.
//!
//! Handles parallel execution of deployments across workers
//! with progress tracking and error handling.
//!
//! ## Backup During Deploy
//!
//! Before deploying a new binary, the executor creates a backup of the current
//! binary on the worker. This enables rollback if the new version fails.
//! Backup failures are non-fatal and never block deployment.

use crate::fleet::audit::AuditLogger;
use crate::fleet::plan::{DeploymentPlan, DeploymentStatus, DeploymentStrategy};
use crate::fleet::progress::{DeployPhase, FleetProgress};
use crate::fleet::rollback::{
    MAX_BACKUPS_PER_WORKER, REMOTE_BACKUP_DIR, REMOTE_RCH_PATH, RollbackManager, WorkerBackup,
};
use crate::fleet::ssh::{CommandOutput, FleetSshError, SshExecutor};
use crate::ui::context::OutputContext;
use crate::ui::theme::StatusIndicator;
use anyhow::Result;

use crate::error::{FleetError, SshError};
use futures::future::BoxFuture;
use rch_common::{WorkerConfig, WorkerId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

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
    /// Worker configurations indexed by worker ID.
    worker_configs: Arc<HashMap<String, WorkerConfig>>,
    /// Path to the local binary to deploy.
    local_binary: PathBuf,
}

impl FleetExecutor {
    /// Create a new fleet executor.
    ///
    /// # Arguments
    /// * `parallelism` - Maximum number of concurrent deployments
    /// * `audit` - Optional audit logger for deployment events
    /// * `workers` - Worker configurations to deploy to
    /// * `local_binary` - Path to the local rch-wkr binary to deploy
    pub fn new(
        parallelism: usize,
        audit: Option<AuditLogger>,
        workers: &[&WorkerConfig],
        local_binary: PathBuf,
    ) -> Result<Self> {
        let worker_configs: HashMap<String, WorkerConfig> = workers
            .iter()
            .map(|w| (w.id.0.clone(), (*w).clone()))
            .collect();

        Ok(Self {
            parallelism,
            audit: audit.map(|a| Arc::new(Mutex::new(a))),
            worker_configs: Arc::new(worker_configs),
            local_binary,
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
                    progress.finish();
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

                // Count canary results
                for (idx, success) in &canary_results {
                    if *success {
                        if plan.workers[*idx].status == DeploymentStatus::Skipped {
                            skipped += 1;
                        } else {
                            deployed += 1;
                        }
                    } else {
                        failed += 1;
                    }
                }

                // Deploy to remaining workers if auto_promote is enabled
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

                    for (idx, success) in remaining_results {
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

        // Ensure parallelism is at least 1 to avoid deadlock
        let effective_parallelism = parallelism.max(1);
        let semaphore = Arc::new(Semaphore::new(effective_parallelism));
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
            let worker_configs = self.worker_configs.clone();
            let local_binary = self.local_binary.clone();

            let handle = tokio::spawn(async move {
                let _permit = permit;

                // Get worker config
                let worker_config = match worker_configs.get(&worker_id) {
                    Some(cfg) => cfg.clone(),
                    None => {
                        progress
                            .worker_failed(&worker_id, "worker config not found")
                            .await;
                        return (idx, worker_id, false, DeploymentStatus::Failed);
                    }
                };

                // Check if we need to deploy
                if !force && current_version.as_ref() == Some(&target_version) {
                    progress
                        .worker_skipped(&worker_id, "already at version")
                        .await;
                    return (idx, worker_id, true, DeploymentStatus::Skipped);
                }

                // Connecting phase - test SSH connectivity
                progress
                    .set_phase(&worker_id, DeployPhase::Connecting)
                    .await;

                if let Err(e) = test_ssh_connectivity(&worker_config).await {
                    progress
                        .worker_failed(&worker_id, &format!("SSH failed: {}", e))
                        .await;
                    return (idx, worker_id, false, DeploymentStatus::Failed);
                }

                // Backup phase - create backup of current binary (best-effort, non-fatal)
                // This runs before upload to capture the existing version
                if let Ok(mut rollback_manager) = RollbackManager::new() {
                    match backup_before_deploy(&worker_config, &mut rollback_manager).await {
                        Ok(Some(backup)) => {
                            debug!(
                                worker = %worker_id,
                                version = %backup.version,
                                "Backup created, proceeding with deploy"
                            );
                        }
                        Ok(None) => {
                            debug!(worker = %worker_id, "No backup created (no existing version or skipped)");
                        }
                        Err(e) => {
                            warn!(worker = %worker_id, error = %e, "Backup failed (continuing deploy)");
                        }
                    }
                }

                // Upload phase - create remote directory and copy binary
                progress.set_phase(&worker_id, DeployPhase::Uploading).await;

                if let Err(e) = create_remote_directory(&worker_config).await {
                    progress
                        .worker_failed(&worker_id, &format!("mkdir failed: {}", e))
                        .await;
                    return (idx, worker_id, false, DeploymentStatus::Failed);
                }

                if let Err(e) = copy_binary_via_scp(&worker_config, &local_binary).await {
                    progress
                        .worker_failed(&worker_id, &format!("scp failed: {}", e))
                        .await;
                    return (idx, worker_id, false, DeploymentStatus::Failed);
                }

                // Install phase - set permissions
                progress
                    .set_phase(&worker_id, DeployPhase::Installing)
                    .await;

                if let Err(e) = set_executable_permissions(&worker_config).await {
                    progress
                        .worker_failed(&worker_id, &format!("chmod failed: {}", e))
                        .await;
                    return (idx, worker_id, false, DeploymentStatus::Failed);
                }

                // Verify phase - run health check
                progress.set_phase(&worker_id, DeployPhase::Verifying).await;

                if let Err(e) = verify_installation(&worker_config).await {
                    progress
                        .worker_failed(&worker_id, &format!("verify failed: {}", e))
                        .await;
                    return (idx, worker_id, false, DeploymentStatus::Failed);
                }

                // Complete
                progress.worker_complete(&worker_id, &target_version).await;
                debug!(
                    "Successfully deployed {} to worker {}",
                    target_version, worker_id
                );
                (idx, worker_id, true, DeploymentStatus::Completed)
            });

            handles.push(handle);
        }

        let mut results = Vec::new();
        for handle in handles {
            let (idx, _worker_id, success, status) = handle.await?;
            plan.workers[idx].status = status;
            results.push((idx, success));
        }

        // Suppress unused variable warnings (style is used for JSON mode output in caller)
        let _ = (style, is_json);

        Ok(results)
    }
}

// =============================================================================
// SSH/SCP deployment helper functions (using SshExecutor)
// =============================================================================

/// Test SSH connectivity to a worker.
///
/// Uses `SshExecutor::check_connectivity()` for consistent behavior and logging.
async fn test_ssh_connectivity(worker: &WorkerConfig) -> Result<()> {
    let ssh = SshExecutor::new(worker);

    if ssh.check_connectivity().await? {
        Ok(())
    } else {
        Err(SshError::ConnectionFailed {
            host: worker.host.clone(),
            user: worker.user.clone(),
            key_path: worker.identity_file.clone().into(),
            message: "connectivity check returned false".to_string(),
        }
        .into())
    }
}

/// Create the remote directory for rch-wkr binary.
///
/// Uses `SshExecutor::create_directory()` for consistent behavior and logging.
async fn create_remote_directory(worker: &WorkerConfig) -> Result<()> {
    let ssh = SshExecutor::new(worker);
    ssh.create_directory("~/.local/bin")
        .await
        .map_err(|e| anyhow::anyhow!("mkdir failed: {}", e))
}

/// Copy the binary to the worker via SCP.
///
/// Uses `SshExecutor::copy_file()` for consistent behavior and logging.
async fn copy_binary_via_scp(worker: &WorkerConfig, local_binary: &Path) -> Result<()> {
    let ssh = SshExecutor::new(worker);
    let remote_path = "~/.local/bin/rch-wkr";

    debug!(
        "SCP: {} -> {}@{}:{}",
        local_binary.display(),
        worker.user,
        worker.host,
        remote_path
    );

    ssh.copy_file(local_binary, remote_path)
        .await
        .map_err(|e| anyhow::anyhow!("scp failed: {}", e))
}

/// Set executable permissions on the remote binary.
///
/// Uses `SshExecutor::set_executable()` for consistent behavior and logging.
async fn set_executable_permissions(worker: &WorkerConfig) -> Result<()> {
    let ssh = SshExecutor::new(worker);
    ssh.set_executable("~/.local/bin/rch-wkr")
        .await
        .map_err(|e| anyhow::anyhow!("chmod failed: {}", e))
}

/// Verify the installation by running health check.
///
/// Uses `SshExecutor::run_command()` for consistent behavior and logging.
async fn verify_installation(worker: &WorkerConfig) -> Result<()> {
    let ssh = SshExecutor::new(worker);
    let output = ssh
        .run_command("~/.local/bin/rch-wkr health")
        .await
        .map_err(|e| anyhow::anyhow!("health check failed: {}", e))?;

    if !output.success() {
        return Err(FleetError::HealthCheckFailed {
            reason: output.stderr.trim().to_string(),
        }
        .into());
    }

    Ok(())
}

// =============================================================================
// Backup during deploy
// =============================================================================

/// Create backup of current binary before deploying new version.
///
/// This function is best-effort and non-fatal:
/// - Returns `Ok(None)` if there's no existing binary to backup
/// - Returns `Ok(None)` on any error (logged at WARN level)
/// - Returns `Ok(Some(backup))` on success
///
/// The backup is registered in the local rollback registry for later rollback.
/// Old backups exceeding MAX_BACKUPS_PER_WORKER are automatically pruned.
pub async fn backup_before_deploy(
    worker: &WorkerConfig,
    rollback_manager: &mut RollbackManager,
) -> Result<Option<WorkerBackup>> {
    let ssh = SshExecutor::new(worker);
    backup_before_deploy_with_runner(worker, rollback_manager, &ssh).await
}

trait CommandRunner {
    fn run_command<'a>(
        &'a self,
        cmd: &'a str,
    ) -> BoxFuture<'a, Result<CommandOutput, FleetSshError>>;
}

impl<'a> CommandRunner for SshExecutor<'a> {
    fn run_command<'b>(
        &'b self,
        cmd: &'b str,
    ) -> BoxFuture<'b, Result<CommandOutput, FleetSshError>> {
        Box::pin(SshExecutor::run_command(self, cmd))
    }
}

#[cfg(test)]
impl CommandRunner for crate::fleet::ssh::MockSshExecutor {
    fn run_command<'a>(
        &'a self,
        cmd: &'a str,
    ) -> BoxFuture<'a, Result<CommandOutput, FleetSshError>> {
        Box::pin(crate::fleet::ssh::MockSshExecutor::run_command(self, cmd))
    }
}

async fn backup_before_deploy_with_runner<R: CommandRunner>(
    worker: &WorkerConfig,
    rollback_manager: &mut RollbackManager,
    runner: &R,
) -> Result<Option<WorkerBackup>> {
    // 1. Get current version before deploying
    debug!(worker = %worker.id, "Checking for existing version to backup");
    let version_cmd = format!("{} --version 2>/dev/null", REMOTE_RCH_PATH);
    let current_version = match runner.run_command(&version_cmd).await {
        Ok(output) if output.success() => output.stdout.split_whitespace().nth(1).map(String::from),
        Ok(_) => None,
        Err(e) => {
            debug!(worker = %worker.id, error = %e, "No existing rch-wkr found");
            None
        }
    };

    let version = match current_version {
        Some(v) => v,
        None => {
            debug!(worker = %worker.id, "No existing version to backup");
            return Ok(None);
        }
    };

    info!(worker = %worker.id, version = %version, "Creating backup before deploy");

    // 2. Create backup directory
    let mkdir_cmd = format!("mkdir -p {}", REMOTE_BACKUP_DIR);
    match runner.run_command(&mkdir_cmd).await {
        Ok(output) if output.success() => {}
        Ok(output) => {
            warn!(
                worker = %worker.id,
                stderr = %output.stderr.trim(),
                "Failed to create backup directory"
            );
            return Ok(None);
        }
        Err(e) => {
            warn!(worker = %worker.id, error = %e, "Failed to create backup directory");
            return Ok(None); // Non-fatal
        }
    }

    // 3. Check disk space before backup (prevent silent failures)
    // Use portable df command that works on both Linux and macOS
    let df_output = runner
        .run_command("df -Pm ~/.rch 2>/dev/null | tail -1 | awk '{print $4}'")
        .await;
    if let Ok(output) = df_output
        && let Ok(mb) = output.stdout.trim().parse::<u64>()
        && mb < 50
    {
        // Less than 50MB available
        warn!(
            worker = %worker.id,
            available_mb = %mb,
            "Low disk space, skipping backup"
        );
        return Ok(None);
    }
    // Ignore disk check errors - proceed with backup

    // 4. Copy current binary to backup location
    let remote_backup_path = format!("{}/rch-wkr-{}", REMOTE_BACKUP_DIR, version);
    let copy_cmd = format!("cp {} {}", REMOTE_RCH_PATH, remote_backup_path);
    match runner.run_command(&copy_cmd).await {
        Ok(output) if output.success() => {}
        Ok(output) => {
            warn!(
                worker = %worker.id,
                stderr = %output.stderr.trim(),
                "Failed to copy binary to backup"
            );
            return Ok(None);
        }
        Err(e) => {
            warn!(worker = %worker.id, error = %e, "Failed to copy binary to backup");
            return Ok(None); // Non-fatal
        }
    }

    // 5. Calculate hash for verification
    let hash_cmd = format!(
        "sha256sum {} 2>/dev/null | cut -d' ' -f1",
        remote_backup_path
    );
    let binary_hash = match runner.run_command(&hash_cmd).await {
        Ok(output) if output.success() => {
            let hash = output.stdout.trim().to_string();
            if hash.len() == 64 {
                hash
            } else {
                "unknown".to_string()
            }
        }
        Ok(_) | Err(_) => {
            warn!(worker = %worker.id, "Failed to calculate backup hash");
            "unknown".to_string()
        }
    };

    // 6. Create and register backup entry
    let backup = rollback_manager.create_backup_entry(
        &worker.id.0,
        &version,
        &remote_backup_path,
        &binary_hash,
    );

    if let Err(e) = rollback_manager.save_backup_entry(&backup) {
        warn!(worker = %worker.id, error = %e, "Failed to save backup entry to registry");
        return Ok(None); // Non-fatal
    }

    // 7. Prune old backups (keep only MAX_BACKUPS_PER_WORKER)
    // This is best-effort - failures don't affect the deploy
    match rollback_manager.prune_old_backups(MAX_BACKUPS_PER_WORKER) {
        Ok(removed) => {
            for old_backup in removed {
                debug!(
                    worker = %worker.id,
                    version = %old_backup.version,
                    "Cleaning up old backup"
                );
                // Best-effort cleanup of remote file
                let rm_cmd = format!("rm -f {}", old_backup.remote_path.display());
                let _ = runner.run_command(&rm_cmd).await;
            }
        }
        Err(e) => {
            warn!(worker = %worker.id, error = %e, "Failed to prune old backups");
        }
    }

    info!(
        worker = %worker.id,
        version = %version,
        hash = %binary_hash,
        "Backup created successfully"
    );

    Ok(Some(backup))
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

    fn test_worker_config() -> WorkerConfig {
        WorkerConfig {
            id: WorkerId("test-worker".to_string()),
            host: "localhost".to_string(),
            user: "test".to_string(),
            identity_file: "/tmp/test_key".to_string(),
            total_slots: 4,
            priority: 1,
            tags: vec![],
        }
    }

    fn test_binary_path() -> PathBuf {
        PathBuf::from("/tmp/rch-wkr")
    }

    #[test]
    fn fleet_executor_new_without_audit() {
        let worker = test_worker_config();
        let executor = FleetExecutor::new(4, None, &[&worker], test_binary_path());
        assert!(executor.is_ok());
        let executor = executor.unwrap();
        assert_eq!(executor.parallelism, 4);
    }

    #[test]
    fn fleet_executor_new_with_parallelism_one() {
        let worker = test_worker_config();
        let executor = FleetExecutor::new(1, None, &[&worker], test_binary_path()).unwrap();
        assert_eq!(executor.parallelism, 1);
    }

    #[test]
    fn fleet_executor_new_with_high_parallelism() {
        let worker = test_worker_config();
        let executor = FleetExecutor::new(100, None, &[&worker], test_binary_path()).unwrap();
        assert_eq!(executor.parallelism, 100);
    }

    #[test]
    fn fleet_executor_stores_worker_configs() {
        let worker = test_worker_config();
        let executor = FleetExecutor::new(4, None, &[&worker], test_binary_path()).unwrap();
        assert!(executor.worker_configs.contains_key("test-worker"));
    }

    #[test]
    fn fleet_executor_stores_binary_path() {
        let worker = test_worker_config();
        let binary_path = PathBuf::from("/custom/path/rch-wkr");
        let executor = FleetExecutor::new(4, None, &[&worker], binary_path.clone()).unwrap();
        assert_eq!(executor.local_binary, binary_path);
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
        let worker = test_worker_config();
        let executor = FleetExecutor::new(0, None, &[&worker], test_binary_path());
        assert!(executor.is_ok());
        assert_eq!(executor.unwrap().parallelism, 0);
    }

    #[test]
    fn fleet_executor_very_large_parallelism() {
        let worker = test_worker_config();
        let executor =
            FleetExecutor::new(usize::MAX, None, &[&worker], test_binary_path()).unwrap();
        assert_eq!(executor.parallelism, usize::MAX);
    }

    #[test]
    fn fleet_executor_empty_workers() {
        let executor = FleetExecutor::new(4, None, &[], test_binary_path()).unwrap();
        assert!(executor.worker_configs.is_empty());
    }

    #[test]
    fn fleet_executor_multiple_workers() {
        let mut worker1 = test_worker_config();
        worker1.id = WorkerId("worker-1".to_string());
        let mut worker2 = test_worker_config();
        worker2.id = WorkerId("worker-2".to_string());

        let executor =
            FleetExecutor::new(4, None, &[&worker1, &worker2], test_binary_path()).unwrap();
        assert_eq!(executor.worker_configs.len(), 2);
        assert!(executor.worker_configs.contains_key("worker-1"));
        assert!(executor.worker_configs.contains_key("worker-2"));
    }

    // ========================
    // Backup Before Deploy tests
    // ========================

    #[tokio::test]
    async fn backup_before_deploy_skips_on_low_disk() {
        use crate::fleet::ssh::{MockCommandResult, MockSshExecutor};

        let worker = test_worker_config();
        let temp_dir = tempfile::tempdir().unwrap();
        let mut manager = RollbackManager::with_path(temp_dir.path()).unwrap();

        let mock = MockSshExecutor::new()
            .with_command("--version", MockCommandResult::ok("rch-wkr 1.0.0"))
            .with_command("mkdir -p", MockCommandResult::ok(""))
            .with_command("df -Pm", MockCommandResult::ok("49"));

        let result = backup_before_deploy_with_runner(&worker, &mut manager, &mock)
            .await
            .unwrap();

        assert!(result.is_none());
        assert!(manager.get_latest_backup(&worker.id.0).is_none());
    }

    #[tokio::test]
    async fn backup_before_deploy_copy_failure_is_non_fatal() {
        use crate::fleet::ssh::{MockCommandResult, MockSshExecutor};

        let worker = test_worker_config();
        let temp_dir = tempfile::tempdir().unwrap();
        let mut manager = RollbackManager::with_path(temp_dir.path()).unwrap();

        let mock = MockSshExecutor::new()
            .with_command("--version", MockCommandResult::ok("rch-wkr 1.0.0"))
            .with_command("mkdir -p", MockCommandResult::ok(""))
            .with_command("df -Pm", MockCommandResult::ok("500"))
            .with_command("cp ", MockCommandResult::err(1, "Permission denied"));

        let result = backup_before_deploy_with_runner(&worker, &mut manager, &mock)
            .await
            .unwrap();

        assert!(result.is_none());
        assert!(manager.get_latest_backup(&worker.id.0).is_none());
    }
}
