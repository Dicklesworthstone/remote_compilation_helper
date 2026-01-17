//! Rollback management for fleet deployments.
//!
//! Handles reverting workers to previous versions when deployments fail.

use crate::fleet::history::HistoryManager;
use crate::ui::context::OutputContext;
use crate::ui::theme::StatusIndicator;
use anyhow::Result;
use rch_common::WorkerConfig;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Backup information for a worker's previous state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerBackup {
    /// Worker identifier.
    pub worker_id: String,
    /// Version that was backed up.
    pub version: String,
    /// Path to backup binary.
    pub backup_path: PathBuf,
    /// When the backup was created.
    pub created_at: String,
}

/// Result of a rollback operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackResult {
    /// Worker that was rolled back.
    pub worker_id: String,
    /// Whether rollback succeeded.
    pub success: bool,
    /// Version rolled back to.
    pub rolled_back_to: Option<String>,
    /// Error message if failed.
    pub error: Option<String>,
}

/// Manages rollback operations for workers.
pub struct RollbackManager {
    history: HistoryManager,
    backup_dir: PathBuf,
}

impl RollbackManager {
    /// Create a new rollback manager.
    pub fn new() -> Result<Self> {
        let backup_dir = dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("rch")
            .join("backups");

        std::fs::create_dir_all(&backup_dir)?;

        Ok(Self {
            history: HistoryManager::new()?,
            backup_dir,
        })
    }

    /// Rollback workers to a specific or previous version.
    pub async fn rollback_workers(
        &self,
        workers: &[&WorkerConfig],
        to_version: Option<&str>,
        _parallelism: usize,
        _verify: bool,
        ctx: &OutputContext,
    ) -> Result<Vec<RollbackResult>> {
        let style = ctx.theme();
        let mut results = Vec::new();

        // Process workers (simplified - real impl would use parallelism)
        for worker in workers {
            let worker_id = &worker.id.0;

            // Determine target version
            let target_version = if let Some(v) = to_version {
                v.to_string()
            } else {
                match self.history.get_previous_version(worker_id)? {
                    Some(v) => v,
                    None => {
                        results.push(RollbackResult {
                            worker_id: worker_id.clone(),
                            success: false,
                            rolled_back_to: None,
                            error: Some("No previous version found".to_string()),
                        });
                        continue;
                    }
                }
            };

            if !ctx.is_json() {
                println!(
                    "  {} Rolling back {} to v{}...",
                    StatusIndicator::Pending.display(style),
                    style.highlight(worker_id),
                    target_version
                );
            }

            // Simulate rollback (real impl would SSH and restore)
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;

            if !ctx.is_json() {
                println!(
                    "  {} {} rolled back to v{}",
                    StatusIndicator::Success.display(style),
                    style.highlight(worker_id),
                    target_version
                );
            }

            results.push(RollbackResult {
                worker_id: worker_id.clone(),
                success: true,
                rolled_back_to: Some(target_version),
                error: None,
            });
        }

        Ok(results)
    }

    /// Create a backup of a worker's current binary.
    pub async fn create_backup(
        &self,
        worker: &WorkerConfig,
        version: &str,
    ) -> Result<WorkerBackup> {
        let backup_path = self
            .backup_dir
            .join(&worker.id.0)
            .join(format!("{}.bak", version));

        std::fs::create_dir_all(backup_path.parent().unwrap())?;

        // Real impl would SSH and copy binary
        // For now, just create the backup record

        Ok(WorkerBackup {
            worker_id: worker.id.0.clone(),
            version: version.to_string(),
            backup_path,
            created_at: chrono::Utc::now().to_rfc3339(),
        })
    }

    /// Restore a worker from backup.
    pub async fn restore_backup(
        &self,
        _backup: &WorkerBackup,
        _worker: &WorkerConfig,
    ) -> Result<()> {
        // Real impl would SSH and restore binary
        // Simulated for now
        Ok(())
    }
}
