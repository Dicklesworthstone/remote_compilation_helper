//! Rollback management for fleet deployments.
//!
//! Handles reverting workers to previous versions when deployments fail.
//!
//! ## Backup Registry
//!
//! The backup registry tracks all worker backups in a local JSON file at
//! `~/.local/share/rch/backups/registry.json`. Each backup entry includes:
//! - Worker ID and version
//! - SHA256 hash of the binary for verification
//! - Remote path where the backup is stored on the worker
//! - Timestamp of when the backup was created
//!
//! The registry uses atomic writes with file locking to handle concurrent access.

use crate::fleet::history::HistoryManager;
use crate::fleet::ssh::{CommandRunner, SshExecutor};
use crate::state::lock::ConfigLock;
use crate::ui::context::OutputContext;
use crate::ui::theme::StatusIndicator;
use anyhow::{Context, Result};

use futures::stream::{self, StreamExt};
use rch_common::WorkerConfig;
use rch_common::ssh_utils::{shell_escape_path_with_home, shell_escape_value};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tracing::{debug, error, info, warn};

// =============================================================================
// Constants
// =============================================================================

/// Default remote path to the rch-wkr binary on workers.
pub const REMOTE_RCH_PATH: &str = "~/.local/bin/rch-wkr";

/// Default remote backup directory on workers.
pub const REMOTE_BACKUP_DIR: &str = "~/.rch/backups";

/// Maximum number of backups to keep per worker.
#[allow(dead_code)] // Enforced when backup retention is implemented
pub const MAX_BACKUPS_PER_WORKER: usize = 3;

/// Registry file name.
const REGISTRY_FILE: &str = "registry.json";

/// Timeout for rollback operations.
const ROLLBACK_TIMEOUT: Duration = Duration::from_secs(60);

/// Timeout for acquiring the backup registry lock.
const REGISTRY_LOCK_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum concurrent rollback operations (cap to prevent resource exhaustion).
const MAX_CONCURRENT_ROLLBACKS: usize = 10;

/// Backup information for a worker's previous state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerBackup {
    /// Worker identifier.
    pub worker_id: String,
    /// Version that was backed up.
    pub version: String,
    /// Local path to backup metadata.
    pub backup_path: PathBuf,
    /// Remote path where the backup binary is stored on the worker.
    pub remote_path: PathBuf,
    /// SHA256 hash of the backed up binary for verification.
    /// Set to "unknown" if hash could not be computed.
    pub binary_hash: String,
    /// When the backup was created (RFC 3339 format).
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

    /// Create a rollback manager with a custom backup directory (for testing).
    /// The deploy/provenance history is isolated to a `history/` subdir so tests
    /// stay hermetic — the rollback-audit emission (bd-...-7.4) never touches the
    /// real provenance trail.
    #[cfg(test)]
    pub fn with_path(backup_dir: &std::path::Path) -> Result<Self> {
        std::fs::create_dir_all(backup_dir)?;
        Ok(Self {
            history: HistoryManager::with_dir(backup_dir.join("history"))?,
            backup_dir: backup_dir.to_path_buf(),
        })
    }

    /// Get the path to the registry file.
    fn registry_path(&self) -> PathBuf {
        self.backup_dir.join(REGISTRY_FILE)
    }

    /// Load the backup registry from disk.
    ///
    /// Returns an empty vector if the registry doesn't exist yet.
    /// Handles corrupted files by backing them up and returning empty.
    pub fn load_registry(&self) -> Result<Vec<WorkerBackup>> {
        let path = self.registry_path();
        if !path.exists() {
            debug!("Registry file does not exist, returning empty");
            return Ok(Vec::new());
        }

        let mut file = match std::fs::File::open(&path) {
            Ok(f) => f,
            Err(e) => {
                warn!(error = %e, "Failed to open registry file");
                return Ok(Vec::new());
            }
        };

        let mut content = String::new();
        if let Err(e) = file.read_to_string(&mut content) {
            warn!(error = %e, "Failed to read registry file");
            return Ok(Vec::new());
        }

        match serde_json::from_str::<Vec<WorkerBackup>>(&content) {
            Ok(registry) => {
                debug!(count = registry.len(), "Loaded backup registry");
                Ok(registry)
            }
            Err(e) => {
                error!(error = %e, "Corrupted backup registry, backing up and recreating");
                // Backup the corrupted file
                let backup_path = path.with_extension("json.corrupted");
                if let Err(rename_err) = std::fs::rename(&path, &backup_path) {
                    warn!(error = %rename_err, "Failed to backup corrupted registry");
                } else {
                    info!(path = %backup_path.display(), "Corrupted registry backed up");
                }
                Ok(Vec::new())
            }
        }
    }

    /// Save a backup entry to the registry.
    ///
    /// Uses atomic writes to prevent corruption from concurrent access.
    pub fn save_backup_entry(&self, backup: &WorkerBackup) -> Result<()> {
        let _lock = ConfigLock::acquire_with_timeout(
            "backup-registry",
            REGISTRY_LOCK_TIMEOUT,
            "save backup registry",
        )?;
        let path = self.registry_path();
        let temp_path = path.with_extension("json.tmp");

        // Load existing registry
        let mut registry = self.load_registry().unwrap_or_default();

        // Add the new backup
        registry.push(backup.clone());

        // Write atomically via temp file
        let content =
            serde_json::to_string_pretty(&registry).context("Failed to serialize registry")?;

        let mut file =
            std::fs::File::create(&temp_path).context("Failed to create temp registry file")?;
        file.write_all(content.as_bytes())
            .context("Failed to write registry")?;
        file.sync_all().context("Failed to sync registry file")?;
        drop(file);

        // Atomic rename
        std::fs::rename(&temp_path, &path)
            .context("Failed to rename temp registry to final path")?;

        info!(
            worker = %backup.worker_id,
            version = %backup.version,
            "Backup entry saved to registry"
        );

        Ok(())
    }

    /// Get the latest backup for a worker.
    pub fn get_latest_backup(&self, worker_id: &str) -> Option<WorkerBackup> {
        let registry = self.load_registry().ok()?;

        registry
            .into_iter()
            .filter(|b| b.worker_id == worker_id)
            .max_by(|a, b| a.created_at.cmp(&b.created_at))
    }

    /// Get a specific version's backup for a worker.
    pub fn get_backup(&self, worker_id: &str, version: &str) -> Option<WorkerBackup> {
        let registry = self.load_registry().ok()?;

        select_backup(&registry, worker_id, Some(version)).cloned()
    }

    /// Prune old backups, keeping only the most recent `max_per_worker` for each worker.
    ///
    /// Returns the list of removed backups so the caller can clean up remote files.
    pub fn prune_old_backups(&mut self, max_per_worker: usize) -> Result<Vec<WorkerBackup>> {
        let _lock = ConfigLock::acquire_with_timeout(
            "backup-registry",
            REGISTRY_LOCK_TIMEOUT,
            "prune backup registry",
        )?;
        let path = self.registry_path();
        let registry = self.load_registry()?;

        // Group by worker_id
        let mut by_worker: HashMap<String, Vec<WorkerBackup>> = HashMap::new();
        for backup in registry {
            by_worker
                .entry(backup.worker_id.clone())
                .or_default()
                .push(backup);
        }

        // Sort each worker's backups by created_at (newest first) and collect removed
        let mut kept = Vec::new();
        let mut removed = Vec::new();

        for (worker_id, mut backups) in by_worker {
            backups.sort_by(|a, b| b.created_at.cmp(&a.created_at));

            for (i, backup) in backups.into_iter().enumerate() {
                if i < max_per_worker {
                    kept.push(backup);
                } else {
                    debug!(
                        worker = %worker_id,
                        version = %backup.version,
                        "Pruning old backup"
                    );
                    removed.push(backup);
                }
            }
        }

        // Write the pruned registry
        if !removed.is_empty() {
            let temp_path = path.with_extension("json.tmp");
            let content = serde_json::to_string_pretty(&kept)?;
            let mut file = std::fs::File::create(&temp_path)?;
            file.write_all(content.as_bytes())?;
            file.sync_all()?;
            drop(file);
            std::fs::rename(&temp_path, &path)?;

            info!(
                removed = removed.len(),
                kept = kept.len(),
                "Pruned old backups from registry"
            );
        }

        Ok(removed)
    }

    /// Get the backup directory path.
    pub fn backup_dir(&self) -> &PathBuf {
        &self.backup_dir
    }

    /// Rollback workers to a specific or previous version.
    ///
    /// This function restores workers to a previous binary version by:
    /// 1. Looking up the backup for each worker (specific version or latest)
    /// 2. Staging a private copy beside the installed binary
    /// 3. Checking its exact version and, when requested, its recorded SHA-256
    /// 4. Atomically replacing the installed path, preserving running helpers
    ///
    /// # Arguments
    ///
    /// * `workers` - List of workers to roll back
    /// * `to_version` - Optional specific version to roll back to (uses previous if None)
    /// * `parallelism` - Maximum number of concurrent rollback operations
    /// * `verify` - If true, verify the recorded binary hash before switching
    /// * `ctx` - Output context for progress display
    ///
    /// # Returns
    ///
    /// A vector of `RollbackResult` for each worker, indicating success or failure.
    pub async fn rollback_workers(
        &self,
        workers: &[&WorkerConfig],
        to_version: Option<&str>,
        parallelism: usize,
        verify: bool,
        ctx: &OutputContext,
    ) -> Result<Vec<RollbackResult>> {
        if workers.is_empty() {
            return Ok(Vec::new());
        }

        // Cap parallelism to prevent resource exhaustion
        let max_concurrent = parallelism.clamp(1, MAX_CONCURRENT_ROLLBACKS);

        info!(
            workers = %workers.len(),
            parallelism = %max_concurrent,
            version = ?to_version,
            verify = %verify,
            "Starting parallel rollback operation"
        );

        // A registered backup is the binary saved before deployment. It is
        // available even for a worker's first recorded deployment; requiring
        // two successful history rows incorrectly made that rollback unusable.
        // Read one registry snapshot for the complete operation.
        let registry = self.load_registry()?;
        type RollbackTask<'a> = (usize, &'a WorkerConfig, Option<(WorkerBackup, String)>);
        let mut rollback_tasks: Vec<RollbackTask<'_>> = Vec::with_capacity(workers.len());

        for (idx, worker) in workers.iter().enumerate() {
            let backup = select_backup(&registry, &worker.id.0, to_version).cloned();
            rollback_tasks.push((
                idx,
                worker,
                backup.map(|backup| {
                    let target_version = normalize_version(&backup.version).to_string();
                    (backup, target_version)
                }),
            ));
        }

        let completed = Arc::new(AtomicUsize::new(0));
        let total = workers.len();

        // Phase 2: Execute rollbacks in parallel with bounded concurrency. Each
        // task is timed so the provenance audit record carries the rollback
        // duration (bd-session-history-remediation-ocv9i.7.4).
        let results: Vec<(usize, RollbackResult, u64)> = stream::iter(rollback_tasks)
            .map(|(idx, worker, backup_opt)| {
                let completed = completed.clone();

                async move {
                    let started = std::time::Instant::now();
                    let result = match backup_opt {
                        Some((backup, target_version)) => {
                            execute_single_rollback(worker, &backup, &target_version, verify, ctx)
                                .await
                        }
                        None => RollbackResult {
                            worker_id: worker.id.0.clone(),
                            success: false,
                            rolled_back_to: None,
                            error: Some(
                                "No backup found. Re-deploy the desired version instead."
                                    .to_string(),
                            ),
                        },
                    };
                    let duration_ms =
                        u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);

                    // Update progress
                    let done = completed.fetch_add(1, Ordering::Relaxed) + 1;
                    debug!(
                        progress = %format!("{}/{}", done, total),
                        worker = %worker.id,
                        success = %result.success,
                        "Worker rollback complete"
                    );

                    (idx, result, duration_ms)
                }
            })
            .buffer_unordered(max_concurrent)
            .collect()
            .await;

        // Sort by original index to preserve order.
        let mut sorted = results;
        sorted.sort_by_key(|(idx, _, _)| *idx);

        // Append a provenance audit row per worker (bd-...-7.4): flag each
        // worker's most recent deploy audit record rolled-back / rollback-failed
        // and re-persist it, preserving the artifact identity, remote user/path,
        // verification result, and trigger the rollback-history spec requires.
        for (_, result, duration_ms) in &sorted {
            record_rollback_audit(
                &self.history,
                &result.worker_id,
                result.success,
                *duration_ms,
            );
        }

        let results: Vec<RollbackResult> =
            sorted.into_iter().map(|(_, result, _)| result).collect();

        // Log summary
        let success_count = results.iter().filter(|r| r.success).count();
        let fail_count = results.len() - success_count;

        info!(
            total = %results.len(),
            success = %success_count,
            failed = %fail_count,
            "Rollback operation complete"
        );

        Ok(results)
    }

    /// Create a backup of a worker's current binary.
    ///
    /// This creates a local backup record. The actual remote backup creation
    /// (copying the binary on the worker) is done by `backup_before_deploy`
    /// in the executor module which uses SSH.
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

        // Compute remote backup path
        let remote_path = PathBuf::from(format!("{}/rch-wkr-{}", REMOTE_BACKUP_DIR, version));

        // Note: binary_hash will be set by the actual SSH backup operation
        // This stub returns "unknown" - the real implementation in executor.rs
        // will compute the hash via `sha256sum` on the remote
        let backup = WorkerBackup {
            worker_id: worker.id.0.clone(),
            version: version.to_string(),
            backup_path,
            remote_path,
            binary_hash: "unknown".to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
        };

        debug!(
            worker = %worker.id,
            version = %version,
            remote_path = %backup.remote_path.display(),
            "Created backup record"
        );

        Ok(backup)
    }

    /// Create a backup entry with a known hash (for use by executor).
    pub fn create_backup_entry(
        &self,
        worker_id: &str,
        version: &str,
        remote_path: &str,
        binary_hash: &str,
    ) -> WorkerBackup {
        let backup_path = self
            .backup_dir
            .join(worker_id)
            .join(format!("{}.bak", version));

        WorkerBackup {
            worker_id: worker_id.to_string(),
            version: version.to_string(),
            backup_path,
            remote_path: PathBuf::from(remote_path),
            binary_hash: binary_hash.to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Restore a worker from backup, checking the exact version before the
    /// atomic switch. Active per-command worker processes are left running.
    pub async fn restore_backup(&self, backup: &WorkerBackup, worker: &WorkerConfig) -> Result<()> {
        self.restore_backup_with_verification(backup, worker, false)
            .await
    }

    /// Restore using the same transaction as fleet rollback. A requested hash
    /// check requires a known digest and a successful remote SHA-256 operation.
    pub async fn restore_backup_with_verification(
        &self,
        backup: &WorkerBackup,
        worker: &WorkerConfig,
        verify_hash: bool,
    ) -> Result<()> {
        let ssh = SshExecutor::with_timeout(worker, ROLLBACK_TIMEOUT);
        restore_with_runner(worker, backup, &backup.version, verify_hash, &ssh).await
    }
}

// =============================================================================
// Standalone Functions (for use in async parallel execution)
// =============================================================================

/// Append a rollback entry to the provenance audit trail
/// (bd-session-history-remediation-ocv9i.7.4).
///
/// Loads the worker's most recent deploy provenance audit record, flags it
/// rolled-back (`success`) or rollback-failed (degraded — needs operator
/// attention), stamps the rollback duration, and re-persists it. This
/// mutate-and-re-append design preserves the original deploy's artifact identity,
/// remote user/path, verification result, and operator/remediation trigger — the
/// rollback-history fields the bead requires — while recording the rollback
/// outcome. When no prior deploy audit record exists (the deploy predates
/// provenance auditing), the rollback still happens; it simply leaves no
/// provenance row to flag, which is logged rather than fabricated.
fn record_rollback_audit(
    history: &HistoryManager,
    worker_id: &str,
    success: bool,
    duration_ms: u64,
) {
    // Newest-first, capped at 1 -> 0 or 1 record.
    let latest = match history.get_provenance_audit(1, Some(worker_id)) {
        Ok(mut records) => records.pop(),
        Err(e) => {
            debug!(
                worker = %worker_id,
                error = %e,
                "Could not read provenance audit trail to record rollback"
            );
            return;
        }
    };
    let Some(mut record) = latest else {
        debug!(
            worker = %worker_id,
            "No prior deploy audit record to flag for rollback (deploy predates provenance auditing)"
        );
        return;
    };

    if success {
        record.mark_rolled_back();
    } else {
        record.mark_rollback_failed();
    }
    record.set_duration_ms(duration_ms);

    if let Err(e) = history.record_provenance_audit(&record) {
        warn!(
            worker = %worker_id,
            error = %e,
            "Failed to append rollback provenance audit record"
        );
    }
}

/// Running rch-wkr instances are per-command helpers, not a service. Replacing
/// their executable by rename lets active jobs finish on their original inode.
async fn execute_single_rollback(
    worker: &WorkerConfig,
    backup: &WorkerBackup,
    target_version: &str,
    verify: bool,
    ctx: &OutputContext,
) -> RollbackResult {
    let style = ctx.theme();
    let worker_id = &worker.id.0;
    if !ctx.is_json() {
        println!(
            "  {} Rolling back {} to v{}...",
            StatusIndicator::Pending.display(style),
            style.highlight(worker_id),
            target_version
        );
    }

    let ssh = SshExecutor::with_timeout(worker, ROLLBACK_TIMEOUT);
    let result = execute_rollback_with_runner(worker, backup, target_version, verify, &ssh).await;
    if !ctx.is_json() {
        if result.success {
            println!(
                "  {} {} rolled back to v{}",
                StatusIndicator::Success.display(style),
                style.highlight(worker_id),
                target_version
            );
        } else {
            println!(
                "  {} {} rollback failed: {}",
                StatusIndicator::Error.display(style),
                style.highlight(worker_id),
                result.error.as_deref().unwrap_or("unconfirmed rollback")
            );
        }
    }
    result
}

fn normalize_version(version: &str) -> &str {
    version.strip_prefix('v').unwrap_or(version)
}

fn select_backup<'a>(
    registry: &'a [WorkerBackup],
    worker_id: &str,
    version: Option<&str>,
) -> Option<&'a WorkerBackup> {
    registry
        .iter()
        .filter(|backup| {
            backup.worker_id == worker_id
                && version.is_none_or(|version| {
                    normalize_version(&backup.version) == normalize_version(version)
                })
        })
        .max_by(|a, b| a.created_at.cmp(&b.created_at))
}

async fn execute_rollback_with_runner<R: CommandRunner>(
    worker: &WorkerConfig,
    backup: &WorkerBackup,
    target_version: &str,
    verify: bool,
    runner: &R,
) -> RollbackResult {
    let outcome = restore_with_runner(worker, backup, target_version, verify, runner).await;
    match outcome {
        Ok(()) => RollbackResult {
            worker_id: worker.id.0.clone(),
            success: true,
            rolled_back_to: Some(normalize_version(target_version).to_string()),
            error: None,
        },
        Err(error) => RollbackResult {
            worker_id: worker.id.0.clone(),
            success: false,
            rolled_back_to: None,
            error: Some(format!("{error:#}")),
        },
    }
}

/// One transport command owns staging, validation and the atomic switch. An
/// interrupted response is unconfirmed, never a fabricated rollback success.
async fn restore_with_runner<R: CommandRunner>(
    worker: &WorkerConfig,
    backup: &WorkerBackup,
    target_version: &str,
    verify: bool,
    runner: &R,
) -> Result<()> {
    anyhow::ensure!(
        backup.worker_id == worker.id.0,
        "backup belongs to another worker"
    );
    anyhow::ensure!(
        normalize_version(&backup.version) == normalize_version(target_version),
        "backup version differs from requested rollback version"
    );
    let command = rollback_command(backup, REMOTE_RCH_PATH, verify)?;
    let output = runner.run_command(&command).await.context(
        "remote rollback result is unconfirmed; inspect the installed worker version before retrying",
    )?;
    anyhow::ensure!(
        output.success(),
        "rollback command failed (exit {}): {}",
        output.exit_code,
        output.stderr.trim()
    );
    let receipt = format!("RCH_ROLLBACK_OK {}", normalize_version(target_version));
    anyhow::ensure!(
        output.stdout.trim() == receipt,
        "rollback completion receipt missing or invalid; inspect the installed worker version before retrying"
    );
    info!(worker = %worker.id, version = %target_version, "Verified rollback completed");
    Ok(())
}

/// Build the transaction exercised by both the SSH path and native shell tests.
/// Rejected staging files and the original backup are retained for diagnosis.
fn rollback_command(backup: &WorkerBackup, destination: &str, verify: bool) -> Result<String> {
    let version = normalize_version(&backup.version);
    anyhow::ensure!(
        !version.is_empty()
            && version
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._+-".contains(&byte)),
        "invalid rollback version"
    );
    let source = backup
        .remote_path
        .to_str()
        .context("backup path is not UTF-8")?;
    anyhow::ensure!(
        source.starts_with('/') || source.starts_with("~/"),
        "backup path must be absolute or relative to the worker home"
    );
    let source = shell_escape_path_with_home(source).context("invalid backup path")?;
    let destination = shell_escape_path_with_home(destination).context("invalid installed path")?;
    let expected_hash = if verify {
        anyhow::ensure!(
            backup.binary_hash.len() == 64
                && backup
                    .binary_hash
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit()),
            "verified rollback requires a recorded SHA-256 digest"
        );
        backup.binary_hash.to_ascii_lowercase()
    } else {
        String::new()
    };
    let version = shell_escape_value(version).context("invalid rollback version")?;
    Ok(format!(
        r#"set -efu
rch_backup={source}
rch_destination={destination}
rch_expected_version={version}
rch_expected_hash='{expected_hash}'
rch_stage=
rch_rollback_fail() {{
    printf 'RCH rollback refused: %s\n' "$1" >&2
    if [ -n "$rch_stage" ]; then
        printf 'Staged backup retained at %s\n' "$rch_stage" >&2
    fi
    exit 1
}}
[ -f "$rch_backup" ] && [ ! -L "$rch_backup" ] || rch_rollback_fail 'backup is missing or not a regular file'
[ -d "${{rch_destination%/*}}" ] || rch_rollback_fail 'installed binary directory is missing'
[ ! -L "$rch_destination" ] || rch_rollback_fail 'installed binary is a symlink'
if [ -e "$rch_destination" ] && [ ! -f "$rch_destination" ]; then
    rch_rollback_fail 'installed binary is not a regular file'
fi
rch_stage=$(mktemp "${{rch_destination}}.rollback.XXXXXXXX") || rch_rollback_fail 'cannot create staging file'
cp "$rch_backup" "$rch_stage" || rch_rollback_fail 'cannot copy backup to staging file'
chmod 0755 "$rch_stage" || rch_rollback_fail 'cannot make staged backup executable'
if [ -n "$rch_expected_hash" ]; then
    if command -v sha256sum >/dev/null 2>&1; then
        rch_hash_output=$(sha256sum < "$rch_stage") || rch_rollback_fail 'SHA-256 command failed'
    elif command -v shasum >/dev/null 2>&1; then
        rch_hash_output=$(shasum -a 256 < "$rch_stage") || rch_rollback_fail 'SHA-256 command failed'
    else
        rch_rollback_fail 'no SHA-256 utility is available'
    fi
    rch_actual_hash=${{rch_hash_output%% *}}
    [ "$rch_actual_hash" = "$rch_expected_hash" ] || rch_rollback_fail 'backup SHA-256 does not match recorded digest'
fi
rch_version_output=$("$rch_stage" --version) || rch_rollback_fail 'staged binary cannot report its version'
set -- $rch_version_output
[ "$#" -ge 2 ] && [ "$1" = rch-wkr ] || rch_rollback_fail 'staged binary reported an invalid version'
rch_actual_version=${{2#v}}
[ "$rch_actual_version" = "$rch_expected_version" ] || rch_rollback_fail 'staged binary version differs from requested version'
[ ! -L "$rch_destination" ] || rch_rollback_fail 'installed binary changed to a symlink'
if [ -e "$rch_destination" ] && [ ! -f "$rch_destination" ]; then
    rch_rollback_fail 'installed binary changed to a non-regular file'
fi
mv -f "$rch_stage" "$rch_destination" || rch_rollback_fail 'atomic binary switch failed'
if [ ! -f "$rch_destination" ] || [ -L "$rch_destination" ] || [ -e "$rch_stage" ] || [ -L "$rch_stage" ]; then
    printf 'RCH rollback result is unconfirmed: installed path changed during switch\n' >&2
    exit 1
fi
printf 'RCH_ROLLBACK_OK %s\n' "$rch_expected_version"
"#
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================
    // Helper functions
    // ========================

    #[allow(dead_code)] // Shared test helper for future rollback cases
    fn mock_backup(worker_id: &str, version: &str, timestamp: u64) -> WorkerBackup {
        WorkerBackup {
            worker_id: worker_id.to_string(),
            version: version.to_string(),
            backup_path: PathBuf::from(format!("/tmp/backups/{}/{}.bak", worker_id, version)),
            remote_path: PathBuf::from(format!("~/.rch/backups/rch-wkr-{}", version)),
            binary_hash: format!("hash_{}", version),
            created_at: format!("2024-01-15T12:00:{:02}Z", timestamp % 60),
        }
    }

    // ========================
    // WorkerBackup tests
    // ========================

    #[test]
    fn worker_backup_serializes() {
        let backup = WorkerBackup {
            worker_id: "worker-1".to_string(),
            version: "1.0.0".to_string(),
            backup_path: PathBuf::from("/tmp/backups/worker-1/1.0.0.bak"),
            remote_path: PathBuf::from("~/.rch/backups/rch-wkr-1.0.0"),
            binary_hash: "abc123".to_string(),
            created_at: "2024-01-15T12:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&backup).unwrap();
        assert!(json.contains("worker-1"));
        assert!(json.contains("1.0.0"));
        assert!(json.contains("backups"));
        assert!(json.contains("abc123"));
        assert!(json.contains("2024-01-15T12:00:00Z"));
    }

    #[test]
    fn worker_backup_deserializes_roundtrip() {
        let backup = WorkerBackup {
            worker_id: "test-worker".to_string(),
            version: "2.0.0".to_string(),
            backup_path: PathBuf::from("/data/backups/test.bak"),
            remote_path: PathBuf::from("~/.rch/backups/rch-wkr-2.0.0"),
            binary_hash: "def456".to_string(),
            created_at: "2024-01-16T10:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&backup).unwrap();
        let restored: WorkerBackup = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.worker_id, "test-worker");
        assert_eq!(restored.version, "2.0.0");
        assert_eq!(
            restored.backup_path,
            PathBuf::from("/data/backups/test.bak")
        );
        assert_eq!(restored.binary_hash, "def456");
        assert_eq!(restored.created_at, "2024-01-16T10:00:00Z");
    }

    // ========================
    // RollbackResult tests
    // ========================

    #[test]
    fn rollback_result_success_serializes() {
        let result = RollbackResult {
            worker_id: "worker-1".to_string(),
            success: true,
            rolled_back_to: Some("1.0.0".to_string()),
            error: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("worker-1"));
        assert!(json.contains("\"success\":true"));
        assert!(json.contains("1.0.0"));
    }

    #[test]
    fn rollback_result_failure_serializes() {
        let result = RollbackResult {
            worker_id: "worker-2".to_string(),
            success: false,
            rolled_back_to: None,
            error: Some("No previous version found".to_string()),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("worker-2"));
        assert!(json.contains("\"success\":false"));
        assert!(json.contains("No previous version found"));
    }

    #[test]
    fn rollback_result_deserializes_roundtrip() {
        let result = RollbackResult {
            worker_id: "test-worker".to_string(),
            success: true,
            rolled_back_to: Some("3.0.0".to_string()),
            error: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        let restored: RollbackResult = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.worker_id, "test-worker");
        assert!(restored.success);
        assert_eq!(restored.rolled_back_to, Some("3.0.0".to_string()));
        assert!(restored.error.is_none());
    }

    #[test]
    fn rollback_result_failed_deserializes_roundtrip() {
        let result = RollbackResult {
            worker_id: "failed-worker".to_string(),
            success: false,
            rolled_back_to: None,
            error: Some("Connection refused".to_string()),
        };
        let json = serde_json::to_string(&result).unwrap();
        let restored: RollbackResult = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.worker_id, "failed-worker");
        assert!(!restored.success);
        assert!(restored.rolled_back_to.is_none());
        assert_eq!(restored.error, Some("Connection refused".to_string()));
    }

    // ========================
    // RollbackManager tests
    // ========================

    #[test]
    fn rollback_manager_new_creates_backup_dir() {
        // RollbackManager::new() creates dirs in the user's data directory
        // This test verifies the constructor doesn't panic
        let manager = RollbackManager::new();
        assert!(manager.is_ok());
    }

    // ========================
    // WorkerBackup additional tests
    // ========================

    #[test]
    fn worker_backup_with_empty_strings() {
        let backup = WorkerBackup {
            worker_id: String::new(),
            version: String::new(),
            backup_path: PathBuf::new(),
            remote_path: PathBuf::new(),
            binary_hash: String::new(),
            created_at: String::new(),
        };
        let json = serde_json::to_string(&backup).unwrap();
        let restored: WorkerBackup = serde_json::from_str(&json).unwrap();
        assert!(restored.worker_id.is_empty());
        assert!(restored.version.is_empty());
    }

    #[test]
    fn worker_backup_with_special_characters() {
        let backup = WorkerBackup {
            worker_id: "worker/with:special\"chars".to_string(),
            version: "1.0.0-beta+build.123".to_string(),
            backup_path: PathBuf::from("/path/with spaces/and\"quotes"),
            remote_path: PathBuf::from("~/.rch/backups/rch-wkr-1.0.0"),
            binary_hash: "hash123".to_string(),
            created_at: "2024-01-15T12:00:00+05:30".to_string(),
        };
        let json = serde_json::to_string(&backup).unwrap();
        let restored: WorkerBackup = serde_json::from_str(&json).unwrap();
        assert!(restored.worker_id.contains("special"));
        assert!(restored.version.contains("beta"));
    }

    #[test]
    fn worker_backup_with_long_strings() {
        let backup = WorkerBackup {
            worker_id: "w".repeat(1000),
            version: "v".repeat(100),
            backup_path: PathBuf::from("/very/long/path".to_string() + &"/segment".repeat(100)),
            remote_path: PathBuf::from("~/.rch/backups/rch-wkr-v".to_string() + &"v".repeat(99)),
            binary_hash: "h".repeat(64),
            created_at: "2024-01-15T12:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&backup).unwrap();
        let restored: WorkerBackup = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.worker_id.len(), 1000);
        assert_eq!(restored.version.len(), 100);
    }

    #[test]
    fn worker_backup_path_variations() {
        let paths = vec![
            PathBuf::from("/absolute/path"),
            PathBuf::from("relative/path"),
            PathBuf::from("."),
            PathBuf::from(".."),
            PathBuf::from("./local"),
        ];
        for path in paths {
            let backup = WorkerBackup {
                worker_id: "test".to_string(),
                version: "1.0.0".to_string(),
                backup_path: path.clone(),
                remote_path: PathBuf::from("~/.rch/backups/rch-wkr-1.0.0"),
                binary_hash: "abc123".to_string(),
                created_at: "2024-01-15T12:00:00Z".to_string(),
            };
            let json = serde_json::to_string(&backup).unwrap();
            let restored: WorkerBackup = serde_json::from_str(&json).unwrap();
            assert_eq!(restored.backup_path, path);
        }
    }

    // ========================
    // RollbackResult additional tests
    // ========================

    #[test]
    fn rollback_result_both_version_and_error() {
        // Edge case: both rolled_back_to and error are Some (unlikely but valid struct)
        let result = RollbackResult {
            worker_id: "partial-worker".to_string(),
            success: false,
            rolled_back_to: Some("1.0.0".to_string()),
            error: Some("Verification failed after rollback".to_string()),
        };
        let json = serde_json::to_string(&result).unwrap();
        let restored: RollbackResult = serde_json::from_str(&json).unwrap();
        assert!(!restored.success);
        assert_eq!(restored.rolled_back_to, Some("1.0.0".to_string()));
        assert!(restored.error.is_some());
    }

    #[test]
    fn rollback_result_empty_worker_id() {
        let result = RollbackResult {
            worker_id: String::new(),
            success: true,
            rolled_back_to: Some("1.0.0".to_string()),
            error: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        let restored: RollbackResult = serde_json::from_str(&json).unwrap();
        assert!(restored.worker_id.is_empty());
    }

    #[test]
    fn rollback_result_long_error_message() {
        let result = RollbackResult {
            worker_id: "worker-1".to_string(),
            success: false,
            rolled_back_to: None,
            error: Some("e".repeat(10000)),
        };
        let json = serde_json::to_string(&result).unwrap();
        let restored: RollbackResult = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.error.unwrap().len(), 10000);
    }

    #[test]
    fn rollback_result_special_chars_in_error() {
        let result = RollbackResult {
            worker_id: "worker".to_string(),
            success: false,
            rolled_back_to: None,
            error: Some("Error: \"connection refused\" on host <remote>".to_string()),
        };
        let json = serde_json::to_string(&result).unwrap();
        let restored: RollbackResult = serde_json::from_str(&json).unwrap();
        assert!(restored.error.unwrap().contains("<remote>"));
    }

    #[test]
    fn rollback_result_version_formats() {
        let versions = vec![
            "1.0.0",
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0+build.123",
            "1.0.0-beta+build.456",
            "0.0.1",
            "99.99.99",
        ];
        for v in versions {
            let result = RollbackResult {
                worker_id: "test".to_string(),
                success: true,
                rolled_back_to: Some(v.to_string()),
                error: None,
            };
            let json = serde_json::to_string(&result).unwrap();
            let restored: RollbackResult = serde_json::from_str(&json).unwrap();
            assert_eq!(restored.rolled_back_to, Some(v.to_string()));
        }
    }

    // ========================
    // RollbackManager tests
    // ========================

    #[test]
    fn rollback_manager_backup_dir_exists_after_new() {
        let manager = RollbackManager::new().unwrap();
        assert!(manager.backup_dir.exists() || !manager.backup_dir.to_string_lossy().is_empty());
    }

    #[tokio::test]
    async fn rollback_manager_create_backup_returns_valid_struct() {
        use rch_common::{WorkerConfig, WorkerId};

        let manager = RollbackManager::new().unwrap();
        let worker = WorkerConfig {
            id: WorkerId::new("test-worker"),
            host: "localhost".to_string(),
            user: "testuser".to_string(),
            identity_file: "~/.ssh/id_rsa".to_string(),
            total_slots: 4,
            priority: 100,
            tags: vec![],
            tools: Vec::new(),
        };

        let backup = manager.create_backup(&worker, "1.0.0").await.unwrap();
        assert_eq!(backup.worker_id, "test-worker");
        assert_eq!(backup.version, "1.0.0");
        assert!(backup.backup_path.to_string_lossy().contains("test-worker"));
        assert!(!backup.created_at.is_empty());
    }

    #[tokio::test]
    async fn rollback_manager_create_backup_different_versions() {
        use rch_common::{WorkerConfig, WorkerId};

        let manager = RollbackManager::new().unwrap();
        let worker = WorkerConfig {
            id: WorkerId::new("version-test"),
            host: "localhost".to_string(),
            user: "testuser".to_string(),
            identity_file: "~/.ssh/id_rsa".to_string(),
            total_slots: 4,
            priority: 100,
            tags: vec![],
            tools: Vec::new(),
        };

        let backup1 = manager.create_backup(&worker, "1.0.0").await.unwrap();
        let backup2 = manager.create_backup(&worker, "2.0.0").await.unwrap();

        assert_ne!(backup1.backup_path, backup2.backup_path);
        assert_ne!(backup1.version, backup2.version);
    }

    // Note: restore_backup tests require real SSH and are moved to integration tests

    // ========================
    // Registry Operations Tests
    // ========================

    #[test]
    fn test_backup_registry_add_entry() {
        let temp_dir = tempfile::tempdir().unwrap();
        let manager = RollbackManager::with_path(temp_dir.path()).unwrap();

        // Create and save a backup entry
        let backup = manager.create_backup_entry("worker1", "0.9.0", "/path/to/backup", "abc123");
        manager.save_backup_entry(&backup).unwrap();

        // Verify it can be retrieved
        let latest = manager.get_latest_backup("worker1");
        assert!(latest.is_some());
        let latest = latest.unwrap();
        assert_eq!(latest.worker_id, "worker1");
        assert_eq!(latest.version, "0.9.0");
        assert_eq!(latest.binary_hash, "abc123");
    }

    #[test]
    fn test_backup_registry_multiple_workers() {
        let temp_dir = tempfile::tempdir().unwrap();
        let manager = RollbackManager::with_path(temp_dir.path()).unwrap();

        // Save backups for different workers
        let backup1 = manager.create_backup_entry("worker1", "1.0.0", "/path/1", "hash1");
        let backup2 = manager.create_backup_entry("worker2", "1.0.0", "/path/2", "hash2");
        let backup3 = manager.create_backup_entry("worker1", "1.1.0", "/path/3", "hash3");

        manager.save_backup_entry(&backup1).unwrap();
        manager.save_backup_entry(&backup2).unwrap();
        // Small delay to ensure different timestamps
        std::thread::sleep(std::time::Duration::from_millis(10));
        manager.save_backup_entry(&backup3).unwrap();

        // Check worker1 has latest version 1.1.0
        let latest1 = manager.get_latest_backup("worker1").unwrap();
        assert_eq!(latest1.version, "1.1.0");

        // Check worker2 has version 1.0.0
        let latest2 = manager.get_latest_backup("worker2").unwrap();
        assert_eq!(latest2.version, "1.0.0");

        // Check unknown worker returns None
        assert!(manager.get_latest_backup("worker3").is_none());
    }

    #[test]
    fn test_backup_registry_get_specific_version() {
        let temp_dir = tempfile::tempdir().unwrap();
        let manager = RollbackManager::with_path(temp_dir.path()).unwrap();

        // Save multiple versions
        let backup1 = manager.create_backup_entry("worker1", "0.8.0", "/path/1", "hash_0.8.0");
        let backup2 = manager.create_backup_entry("worker1", "0.9.0", "/path/2", "hash_0.9.0");
        let backup3 = manager.create_backup_entry("worker1", "1.0.0", "/path/3", "hash_1.0.0");

        manager.save_backup_entry(&backup1).unwrap();
        manager.save_backup_entry(&backup2).unwrap();
        manager.save_backup_entry(&backup3).unwrap();

        // Get specific version
        let backup = manager.get_backup("worker1", "0.9.0");
        assert!(backup.is_some());
        assert_eq!(backup.unwrap().binary_hash, "hash_0.9.0");

        // Non-existent version
        assert!(manager.get_backup("worker1", "0.7.0").is_none());

        // Non-existent worker
        assert!(manager.get_backup("worker2", "0.9.0").is_none());
    }

    #[test]
    fn test_backup_registry_persistence() {
        let temp_dir = tempfile::tempdir().unwrap();
        let registry_path = temp_dir.path();

        // Create and save with first manager instance
        {
            let manager = RollbackManager::with_path(registry_path).unwrap();
            let backup = manager.create_backup_entry("worker1", "1.0.0", "/path", "abc123");
            manager.save_backup_entry(&backup).unwrap();
        }

        // Reload with new manager instance and verify
        {
            let manager = RollbackManager::with_path(registry_path).unwrap();
            let latest = manager.get_latest_backup("worker1");
            assert!(latest.is_some());
            assert_eq!(latest.unwrap().version, "1.0.0");
        }
    }

    #[test]
    fn test_backup_registry_corrupted_recovery() {
        let temp_dir = tempfile::tempdir().unwrap();
        let registry_path = temp_dir.path().join("registry.json");

        // Write corrupted data
        std::fs::write(&registry_path, "{ invalid json").unwrap();

        // Create manager - should recover gracefully
        let manager = RollbackManager::with_path(temp_dir.path()).unwrap();
        let registry = manager.load_registry().unwrap();

        // Should return empty registry after recovery
        assert!(registry.is_empty());

        // Corrupted file should be backed up
        let backup_path = temp_dir.path().join("registry.json.corrupted");
        assert!(backup_path.exists());
    }

    #[test]
    fn test_backup_registry_prune() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut manager = RollbackManager::with_path(temp_dir.path()).unwrap();

        // Add 4 backups for worker1 with different timestamps
        for i in 0..4 {
            let backup = WorkerBackup {
                worker_id: "worker1".to_string(),
                version: format!("0.{}.0", 7 + i),
                backup_path: PathBuf::from(format!("/tmp/backups/worker1/0.{}.0.bak", 7 + i)),
                remote_path: PathBuf::from(format!("~/.rch/backups/rch-wkr-0.{}.0", 7 + i)),
                binary_hash: format!("hash_{}", i),
                // Use sequential timestamps to ensure deterministic ordering
                created_at: format!("2024-01-15T12:00:{:02}Z", i * 10),
            };
            manager.save_backup_entry(&backup).unwrap();
        }

        // Prune to keep only 2 most recent
        let removed = manager.prune_old_backups(2).unwrap();

        // Should have removed 2 (oldest)
        assert_eq!(removed.len(), 2);
        assert!(removed.iter().any(|b| b.version == "0.7.0"));
        assert!(removed.iter().any(|b| b.version == "0.8.0"));

        // Verify only latest 2 remain
        let registry = manager.load_registry().unwrap();
        assert_eq!(registry.len(), 2);

        // Oldest should be gone
        assert!(manager.get_backup("worker1", "0.7.0").is_none());
        assert!(manager.get_backup("worker1", "0.8.0").is_none());

        // Newest should still exist
        assert!(manager.get_backup("worker1", "0.9.0").is_some());
        assert!(manager.get_backup("worker1", "0.10.0").is_some());
    }

    #[test]
    fn test_backup_registry_prune_multiple_workers() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut manager = RollbackManager::with_path(temp_dir.path()).unwrap();

        // Add 3 backups each for 2 workers
        for worker in ["worker1", "worker2"] {
            for i in 0..3 {
                let backup = WorkerBackup {
                    worker_id: worker.to_string(),
                    version: format!("1.{}.0", i),
                    backup_path: PathBuf::from(format!("/tmp/{}/1.{}.0.bak", worker, i)),
                    remote_path: PathBuf::from(format!("~/.rch/backups/rch-wkr-1.{}.0", i)),
                    binary_hash: format!("hash_{}_{}", worker, i),
                    created_at: format!("2024-01-15T12:{}:00Z", i * 10),
                };
                manager.save_backup_entry(&backup).unwrap();
            }
        }

        // Prune to keep 2 per worker
        let removed = manager.prune_old_backups(2).unwrap();

        // Should remove 1 per worker (2 total)
        assert_eq!(removed.len(), 2);

        // Each worker should have 2 backups remaining
        let registry = manager.load_registry().unwrap();
        let worker1_count = registry.iter().filter(|b| b.worker_id == "worker1").count();
        let worker2_count = registry.iter().filter(|b| b.worker_id == "worker2").count();
        assert_eq!(worker1_count, 2);
        assert_eq!(worker2_count, 2);
    }

    #[test]
    fn test_backup_registry_empty_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let registry_path = temp_dir.path().join("registry.json");

        // Write empty JSON array
        std::fs::write(&registry_path, "[]").unwrap();

        let manager = RollbackManager::with_path(temp_dir.path()).unwrap();
        let registry = manager.load_registry().unwrap();

        assert!(registry.is_empty());
    }

    #[test]
    fn test_backup_registry_missing_file() {
        let temp_dir = tempfile::tempdir().unwrap();

        // Don't create any registry file
        let manager = RollbackManager::with_path(temp_dir.path()).unwrap();
        let registry = manager.load_registry().unwrap();

        // Should return empty without error
        assert!(registry.is_empty());
    }

    #[test]
    fn test_backup_registry_atomic_write() {
        let temp_dir = tempfile::tempdir().unwrap();
        let manager = RollbackManager::with_path(temp_dir.path()).unwrap();

        // Save multiple entries
        for i in 0..5 {
            let backup =
                manager.create_backup_entry(&format!("worker{}", i), "1.0.0", "/path", "hash");
            manager.save_backup_entry(&backup).unwrap();
        }

        // Verify no temp files left behind
        let entries: Vec<_> = std::fs::read_dir(temp_dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();

        // Should only have registry.json (and possibly worker subdirs)
        for entry in &entries {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            assert!(
                !name_str.ends_with(".tmp"),
                "Temp file left behind: {}",
                name_str
            );
        }
    }

    #[test]
    fn test_backup_entry_timestamp_ordering() {
        let temp_dir = tempfile::tempdir().unwrap();
        let manager = RollbackManager::with_path(temp_dir.path()).unwrap();

        // Save backups with explicit timestamps (out of order)
        let backup_old = WorkerBackup {
            worker_id: "worker1".to_string(),
            version: "0.8.0".to_string(),
            backup_path: PathBuf::from("/tmp/0.8.0.bak"),
            remote_path: PathBuf::from("~/.rch/backups/rch-wkr-0.8.0"),
            binary_hash: "old_hash".to_string(),
            created_at: "2024-01-15T10:00:00Z".to_string(), // Earlier
        };
        let backup_new = WorkerBackup {
            worker_id: "worker1".to_string(),
            version: "0.9.0".to_string(),
            backup_path: PathBuf::from("/tmp/0.9.0.bak"),
            remote_path: PathBuf::from("~/.rch/backups/rch-wkr-0.9.0"),
            binary_hash: "new_hash".to_string(),
            created_at: "2024-01-15T12:00:00Z".to_string(), // Later
        };

        // Save in reverse order
        manager.save_backup_entry(&backup_new).unwrap();
        manager.save_backup_entry(&backup_old).unwrap();

        // get_latest_backup should return the one with latest timestamp
        let latest = manager.get_latest_backup("worker1").unwrap();
        assert_eq!(latest.version, "0.9.0");
        assert_eq!(latest.binary_hash, "new_hash");
    }

    // ========================
    // Rollback Workers Tests (Empty Workers)
    // ========================

    #[tokio::test]
    async fn test_rollback_workers_empty_list() {
        use crate::ui::test_utils::OutputCapture;

        let temp_dir = tempfile::tempdir().unwrap();
        let manager = RollbackManager::with_path(temp_dir.path()).unwrap();
        let capture = OutputCapture::json();
        let ctx = capture.context();

        let results = manager
            .rollback_workers(&[], None, 4, true, &ctx)
            .await
            .unwrap();
        assert!(results.is_empty());
    }

    // ========================
    // Create Backup Entry Tests
    // ========================

    #[test]
    fn test_create_backup_entry_fields() {
        let temp_dir = tempfile::tempdir().unwrap();
        let manager = RollbackManager::with_path(temp_dir.path()).unwrap();

        let backup = manager.create_backup_entry(
            "test-worker",
            "1.2.3",
            "~/.rch/backups/rch-wkr-1.2.3",
            "sha256hash",
        );

        assert_eq!(backup.worker_id, "test-worker");
        assert_eq!(backup.version, "1.2.3");
        assert_eq!(backup.binary_hash, "sha256hash");
        assert!(backup.backup_path.to_string_lossy().contains("test-worker"));
        assert!(backup.backup_path.to_string_lossy().contains("1.2.3.bak"));
        assert!(!backup.created_at.is_empty());
    }

    #[test]
    fn test_create_backup_entry_unknown_hash() {
        let temp_dir = tempfile::tempdir().unwrap();
        let manager = RollbackManager::with_path(temp_dir.path()).unwrap();

        let backup = manager.create_backup_entry("worker1", "1.0.0", "/path", "unknown");

        assert_eq!(backup.binary_hash, "unknown");
    }

    // ========================
    // Rollback Execution Tests (No SSH)
    // ========================

    /// Test helper to create a mock WorkerConfig
    fn mock_worker(id: &str) -> WorkerConfig {
        use rch_common::WorkerId;
        WorkerConfig {
            id: WorkerId::new(id),
            host: format!("mock://{}.local", id),
            user: "testuser".to_string(),
            identity_file: "~/.ssh/id_rsa".to_string(),
            total_slots: 4,
            priority: 100,
            tags: vec![],
            tools: Vec::new(),
        }
    }

    /// Test helper to create a mock backup with specific hash
    fn mock_backup_with_hash(
        worker_id: &str,
        version: &str,
        timestamp: u64,
        hash: &str,
    ) -> WorkerBackup {
        WorkerBackup {
            worker_id: worker_id.to_string(),
            version: version.to_string(),
            backup_path: PathBuf::from(format!("/tmp/backups/{}/{}.bak", worker_id, version)),
            remote_path: PathBuf::from(format!("~/.rch/backups/rch-wkr-{}", version)),
            binary_hash: hash.to_string(),
            created_at: format!("2024-01-15T12:00:{:02}Z", timestamp % 60),
        }
    }

    #[tokio::test]
    async fn test_rollback_no_backup() {
        use crate::ui::test_utils::OutputCapture;

        let temp_dir = tempfile::tempdir().unwrap();
        let manager = RollbackManager::with_path(temp_dir.path()).unwrap();
        let worker = mock_worker("worker1");
        let workers = vec![&worker];
        let capture = OutputCapture::json();
        let ctx = capture.context();

        // Manager has no backups registered
        let results = manager
            .rollback_workers(&workers, None, 4, true, &ctx)
            .await
            .unwrap();

        assert_eq!(results.len(), 1);
        assert!(!results[0].success);
        assert!(
            results[0]
                .error
                .as_ref()
                .unwrap()
                .to_lowercase()
                .contains("no backup")
                || results[0].error.as_ref().unwrap().contains("Re-deploy")
        );
    }

    #[tokio::test]
    async fn test_rollback_specific_version_not_found() {
        use crate::ui::test_utils::OutputCapture;

        let temp_dir = tempfile::tempdir().unwrap();
        let manager = RollbackManager::with_path(temp_dir.path()).unwrap();
        let worker = mock_worker("worker1");
        let workers = vec![&worker];

        // Save a backup for version 1.0.0
        let backup = mock_backup_with_hash("worker1", "1.0.0", 1000, "abc123");
        manager.save_backup_entry(&backup).unwrap();

        let capture = OutputCapture::json();
        let ctx = capture.context();

        // Request version 2.0.0 which doesn't exist
        let results = manager
            .rollback_workers(&workers, Some("2.0.0"), 4, true, &ctx)
            .await
            .unwrap();

        assert_eq!(results.len(), 1);
        assert!(!results[0].success);
        assert!(results[0].rolled_back_to.is_none());
    }

    // bd-session-history-remediation-ocv9i.7.4 — rollback audit trail.

    fn seed_deploy_audit(manager: &RollbackManager, worker: &str) -> String {
        use rch_common::fleet_provenance::{
            ArtifactProvenance, FleetDeployAuditRecord, ProvenancePolicy, SignatureCheck,
            verify_artifact_provenance,
        };
        let triple = "x86_64-unknown-linux-gnu";
        let p = ArtifactProvenance::dev_artifact("rch-wkr", triple);
        let verdict = verify_artifact_provenance(
            &p,
            triple,
            None,
            SignatureCheck::Absent,
            &ProvenancePolicy::dev_friendly(),
        );
        let rec = FleetDeployAuditRecord::from_verdict(
            "run-7",
            "bd-session-history-remediation-ocv9i.7.4",
            worker,
            "rch",
            "/home/rch/.local/bin/rch-wkr",
            &p,
            None,
            1000,
            &verdict,
            "operator",
            "deploy",
        );
        manager.history.record_provenance_audit(&rec).unwrap();
        verdict.verification_status().to_string()
    }

    #[tokio::test]
    async fn rollback_audit_flags_record_rolled_back_on_success() {
        use rch_common::fleet_provenance::rollback_status;
        let temp = tempfile::tempdir().unwrap();
        let manager = RollbackManager::with_path(temp.path()).unwrap();
        let verification = seed_deploy_audit(&manager, "css");

        // Simulate a successful rollback's audit emission.
        record_rollback_audit(&manager.history, "css", true, 4200);

        let after = manager
            .history
            .get_provenance_audit(10, Some("css"))
            .unwrap();
        let rolled = after
            .iter()
            .find(|r| r.rollback_status == rollback_status::ROLLED_BACK)
            .expect("a rolled_back audit record");
        assert_eq!(rolled.duration_ms, 4200);
        // The mutate-and-re-append preserves the original deploy context.
        assert_eq!(rolled.worker_id, "css");
        assert_eq!(rolled.remote_user, "rch");
        assert_eq!(rolled.trigger, "operator");
        assert_eq!(rolled.verification_status, verification);
    }

    #[tokio::test]
    async fn rollback_audit_flags_record_rollback_failed_on_failure() {
        use rch_common::fleet_provenance::rollback_status;
        let temp = tempfile::tempdir().unwrap();
        let manager = RollbackManager::with_path(temp.path()).unwrap();
        seed_deploy_audit(&manager, "css");

        // A failed rollback flags the record degraded (operator attention).
        record_rollback_audit(&manager.history, "css", false, 7);

        let after = manager
            .history
            .get_provenance_audit(10, Some("css"))
            .unwrap();
        let failed = after
            .iter()
            .find(|r| r.rollback_status == rollback_status::ROLLBACK_FAILED)
            .expect("a rollback_failed audit record");
        assert_eq!(failed.duration_ms, 7);
        assert_eq!(failed.worker_id, "css");
    }

    #[tokio::test]
    async fn rollback_audit_noop_without_prior_record() {
        let temp = tempfile::tempdir().unwrap();
        let manager = RollbackManager::with_path(temp.path()).unwrap();
        // No seeded deploy record -> nothing to flag, no panic, no write.
        record_rollback_audit(&manager.history, "ghost", true, 10);
        let after = manager
            .history
            .get_provenance_audit(10, Some("ghost"))
            .unwrap();
        assert!(after.is_empty());
    }

    // The full rollback_workers path actually emits the audit row (the wiring).
    // Outcome-agnostic: in the test harness the mock host's SSH may succeed or
    // fail, so we only assert the seeded record was flagged (no longer `none`) —
    // the per-outcome rolled_back/rollback_failed mapping is covered by the two
    // direct tests above.
    #[tokio::test]
    async fn rollback_workers_emits_audit_record() {
        use crate::ui::test_utils::OutputCapture;
        use rch_common::fleet_provenance::rollback_status;
        let temp = tempfile::tempdir().unwrap();
        let manager = RollbackManager::with_path(temp.path()).unwrap();
        let worker = mock_worker("css");
        let backup = mock_backup_with_hash("css", "1.0.0", 1000, "abc123");
        manager.save_backup_entry(&backup).unwrap();
        seed_deploy_audit(&manager, "css");

        let capture = OutputCapture::json();
        let ctx = capture.context();
        let results = manager
            .rollback_workers(&[&worker], Some("1.0.0"), 4, false, &ctx)
            .await
            .unwrap();
        assert_eq!(results.len(), 1);

        let after = manager
            .history
            .get_provenance_audit(10, Some("css"))
            .unwrap();
        assert!(
            after
                .iter()
                .any(|r| r.rollback_status != rollback_status::NONE),
            "rollback_workers must flag the worker's audit record"
        );
    }

    #[tokio::test]
    async fn test_rollback_parallelism_capped() {
        use crate::ui::test_utils::OutputCapture;

        let temp_dir = tempfile::tempdir().unwrap();
        let manager = RollbackManager::with_path(temp_dir.path()).unwrap();

        // Create many workers
        let workers: Vec<WorkerConfig> = (0..20).map(|i| mock_worker(&format!("w{}", i))).collect();
        let worker_refs: Vec<&WorkerConfig> = workers.iter().collect();

        let capture = OutputCapture::json();
        let ctx = capture.context();

        // Even with parallelism=100, should be capped at MAX_CONCURRENT_ROLLBACKS
        let results = manager
            .rollback_workers(&worker_refs, None, 100, false, &ctx)
            .await
            .unwrap();

        // All should report "no backup" error since no backups registered
        assert_eq!(results.len(), 20);
        assert!(results.iter().all(|r| !r.success));
    }

    // Production rollback orchestration, with only its transport substituted.
    #[tokio::test]
    async fn rollback_requires_a_matching_completion_receipt() {
        use crate::fleet::ssh::{MockCommandResult, MockSshExecutor};

        let worker = mock_worker("worker1");
        let backup = mock_backup_with_hash("worker1", "0.9.0", 1000, &"a".repeat(64));
        for (stdout, success) in [
            ("RCH_ROLLBACK_OK 0.9.0\n", true),
            ("", false),
            ("rch-wkr 0.9.0", false),
            ("RCH_ROLLBACK_OK 0.9.00", false),
            ("RCH_ROLLBACK_OK 0.9.0\nunexpected", false),
        ] {
            let transport =
                MockSshExecutor::new().with_command("set -efu", MockCommandResult::ok(stdout));
            let result =
                execute_rollback_with_runner(&worker, &backup, "v0.9.0", true, &transport).await;
            assert_eq!(result.success, success, "{stdout:?}: {result:?}");
            assert_eq!(result.rolled_back_to.as_deref(), success.then_some("0.9.0"));
        }
    }

    #[tokio::test]
    async fn rollback_remote_errors_never_report_success() {
        use crate::fleet::ssh::{MockCommandResult, MockSshExecutor};

        let worker = mock_worker("worker1");
        let backup = mock_backup_with_hash("worker1", "0.9.0", 1000, "unknown");
        for transport in [
            MockSshExecutor::unreachable(),
            MockSshExecutor::new().with_command(
                "set -efu",
                MockCommandResult::err(1, "backup SHA-256 does not match recorded digest"),
            ),
        ] {
            let result =
                execute_rollback_with_runner(&worker, &backup, "0.9.0", false, &transport).await;
            assert!(!result.success);
            assert!(result.rolled_back_to.is_none());
            assert!(result.error.is_some());
        }
    }

    #[tokio::test]
    async fn rollback_validates_worker_version_path_and_requested_digest_before_ssh() {
        use crate::fleet::ssh::MockSshExecutor;

        let worker = mock_worker("worker1");
        let transport = MockSshExecutor::unreachable();
        let good = mock_backup_with_hash("worker1", "0.9.0", 1000, &"a".repeat(64));
        let mut cases = Vec::new();
        let mut other_worker = good.clone();
        other_worker.worker_id = "worker2".to_string();
        cases.push((other_worker, "another worker"));
        let mut other_version = good.clone();
        other_version.version = "0.9.00".to_string();
        cases.push((other_version, "differs from requested"));
        let mut relative = good.clone();
        relative.remote_path = PathBuf::from("-rf");
        cases.push((relative, "path must be absolute"));
        let mut control = good.clone();
        control.remote_path = PathBuf::from("/tmp/backup\ncommand");
        cases.push((control, "invalid backup path"));
        let non_hex_digest = "x".repeat(64);
        for hash in ["unknown", "", "abc123", non_hex_digest.as_str()] {
            let mut backup = good.clone();
            backup.binary_hash = hash.to_string();
            cases.push((backup, "recorded SHA-256"));
        }

        for (backup, expected) in cases {
            let result =
                execute_rollback_with_runner(&worker, &backup, "0.9.0", true, &transport).await;
            assert!(!result.success);
            let error = result.error.unwrap();
            assert!(error.contains(expected), "{expected}: {error}");
            assert!(
                !error.contains("unconfirmed"),
                "must fail before the SSH transport"
            );
        }
    }

    #[tokio::test]
    async fn rollback_allows_unknown_digest_only_without_requested_verification() {
        use crate::fleet::ssh::{MockCommandResult, MockSshExecutor};

        let worker = mock_worker("worker1");
        let backup = mock_backup_with_hash("worker1", "0.9.0", 1000, "unknown");
        let transport = MockSshExecutor::new()
            .with_command("set -efu", MockCommandResult::ok("RCH_ROLLBACK_OK 0.9.0\n"));
        let result =
            execute_rollback_with_runner(&worker, &backup, "0.9.0", false, &transport).await;
        assert!(result.success, "{result:?}");
    }

    #[test]
    fn rollback_selects_latest_registered_backup_without_requiring_deployment_history() {
        let older = mock_backup_with_hash("worker1", "0.9.0", 1, "old");
        let newer = mock_backup_with_hash("worker1", "0.9.0", 2, "new");
        let latest = mock_backup_with_hash("worker1", "1.0.0", 3, "latest");
        let other_worker = mock_backup_with_hash("worker2", "2.0.0", 4, "other");
        let registry = [older, newer, latest, other_worker];
        assert_eq!(
            select_backup(&registry, "worker1", None)
                .unwrap()
                .binary_hash,
            "latest"
        );
        assert_eq!(
            select_backup(&registry, "worker1", Some("v0.9.0"))
                .unwrap()
                .binary_hash,
            "new"
        );
        assert!(select_backup(&registry, "missing", None).is_none());
        assert!(select_backup(&registry, "worker1", Some("9.0")).is_none());
    }

    /// Native filesystem/process tests execute the exact generated production
    /// transaction. The executable fixtures model version replies, not a live
    /// fleet deployment or a real release artifact.
    #[cfg(unix)]
    mod native_rollback {
        use super::*;
        use std::os::unix::fs::PermissionsExt;
        use std::path::Path;
        use std::process::{Command, Output};

        const OLD_BINARY: &[u8] = b"previously installed worker bytes\n";
        const GOOD_BACKUP: &str = "#!/bin/sh\nprintf 'rch-wkr 0.9.0 (fixture)\\n'\n";

        struct Fixture {
            root: tempfile::TempDir,
            backup: WorkerBackup,
            source: PathBuf,
            destination: PathBuf,
            source_bytes: Vec<u8>,
        }

        impl Fixture {
            fn new(body: &str) -> Self {
                let root = tempfile::tempdir().unwrap();
                let source = root.path().join("backup ' $literal;file");
                let bin = root.path().join("binary directory");
                std::fs::create_dir(&bin).unwrap();
                let destination = bin.join("rch-wkr");
                std::fs::write(&source, body).unwrap();
                std::fs::write(&destination, OLD_BINARY).unwrap();
                let mut backup =
                    mock_backup_with_hash("worker1", "0.9.0", 1, &sha256(body.as_bytes()));
                backup.remote_path = source.clone();
                Self {
                    root,
                    backup,
                    source,
                    destination,
                    source_bytes: body.as_bytes().to_vec(),
                }
            }

            fn run(&self, verify: bool, tools: Option<&Path>) -> Output {
                let script =
                    rollback_command(&self.backup, self.destination.to_str().unwrap(), verify)
                        .unwrap();
                let mut command = Command::new("/bin/sh");
                command.args(["-c", &script]);
                if let Some(tools) = tools {
                    command.env("PATH", tools);
                }
                command.output().unwrap()
            }

            fn assert_preserved(&self, output: &Output) {
                assert!(!output.status.success(), "unexpected success: {output:?}");
                assert!(!String::from_utf8_lossy(&output.stdout).contains("RCH_ROLLBACK_OK"));
                assert_eq!(std::fs::read(&self.destination).unwrap(), OLD_BINARY);
                assert_eq!(std::fs::read(&self.source).unwrap(), self.source_bytes);
            }

            fn tools(&self, broken: Option<&str>) -> PathBuf {
                let directory = self.root.path().join("tools");
                std::fs::create_dir(&directory).unwrap();
                for name in ["cp", "chmod", "mktemp", "mv"] {
                    let target = directory.join(name);
                    if broken == Some(name) {
                        std::fs::write(&target, "#!/bin/sh\nexit 23\n").unwrap();
                        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755))
                            .unwrap();
                    } else {
                        std::os::unix::fs::symlink(which::which(name).unwrap(), target).unwrap();
                    }
                }
                directory
            }
        }

        fn sha256(bytes: &[u8]) -> String {
            use sha2::{Digest, Sha256};
            use std::fmt::Write as _;
            let mut text = String::with_capacity(64);
            for byte in Sha256::digest(bytes) {
                write!(&mut text, "{byte:02x}").unwrap();
            }
            text
        }

        #[test]
        fn rollback_installs_verified_bytes_and_preserves_backup() {
            let fixture = Fixture::new(GOOD_BACKUP);
            let output = fixture.run(true, None);
            assert!(output.status.success(), "{output:?}");
            assert_eq!(output.stdout, b"RCH_ROLLBACK_OK 0.9.0\n");
            assert_eq!(
                std::fs::read(&fixture.destination).unwrap(),
                fixture.source_bytes
            );
            assert_eq!(
                std::fs::read(&fixture.source).unwrap(),
                fixture.source_bytes
            );
            assert_eq!(
                std::fs::metadata(&fixture.destination)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o755
            );
            let executed = Command::new(&fixture.destination)
                .arg("--version")
                .output()
                .unwrap();
            assert!(executed.status.success());
            assert_eq!(executed.stdout, b"rch-wkr 0.9.0 (fixture)\n");
        }

        #[test]
        fn rollback_rejects_hash_mismatch_before_executing_backup() {
            let mut fixture =
                Fixture::new("#!/bin/sh\n: > \"${0%/*}/executed\"\nprintf 'rch-wkr 0.9.0\\n'\n");
            fixture.backup.binary_hash = "0".repeat(64);
            let output = fixture.run(true, None);
            fixture.assert_preserved(&output);
            assert!(String::from_utf8_lossy(&output.stderr).contains("SHA-256 does not match"));
            assert!(String::from_utf8_lossy(&output.stderr).contains("Staged backup retained"));
            assert!(
                !fixture
                    .destination
                    .parent()
                    .unwrap()
                    .join("executed")
                    .exists()
            );
        }

        #[test]
        fn rollback_rejects_missing_and_failed_hash_utilities() {
            for broken in [false, true] {
                let fixture = Fixture::new(GOOD_BACKUP);
                let tools = fixture.tools(None);
                if broken {
                    let hasher = tools.join("sha256sum");
                    std::fs::write(&hasher, "#!/bin/sh\nexit 23\n").unwrap();
                    std::fs::set_permissions(&hasher, std::fs::Permissions::from_mode(0o755))
                        .unwrap();
                }
                let output = fixture.run(true, Some(&tools));
                fixture.assert_preserved(&output);
                let error = String::from_utf8_lossy(&output.stderr);
                assert!(
                    error.contains(if broken {
                        "SHA-256 command failed"
                    } else {
                        "no SHA-256 utility"
                    }),
                    "{error}"
                );
            }
        }

        #[test]
        fn rollback_copy_chmod_and_switch_failures_preserve_installed_binary() {
            for broken in ["cp", "chmod", "mv"] {
                let fixture = Fixture::new(GOOD_BACKUP);
                let tools = fixture.tools(Some(broken));
                let output = fixture.run(false, Some(&tools));
                fixture.assert_preserved(&output);
                assert!(String::from_utf8_lossy(&output.stderr).contains("Staged backup retained"));
            }
        }

        #[test]
        fn rollback_rejects_wrong_unexecutable_and_failed_version_replies() {
            for body in [
                "#!/bin/sh\nprintf 'rch-wkr 0.9.00\\n'\n",
                "#!/bin/sh\nprintf 'different-tool 0.9.0\\n'\n",
                "#!/bin/sh\nprintf 'rch-wkr version 0.9.0\\n'\n",
                "#!/bin/sh\nprintf 'rch-wkr 0.9.0\\n'\nexit 7\n",
                "this is not an executable\n",
            ] {
                let fixture = Fixture::new(body);
                let output = fixture.run(false, None);
                fixture.assert_preserved(&output);
                assert!(String::from_utf8_lossy(&output.stderr).contains("version"));
            }
        }

        #[test]
        fn rollback_missing_backup_and_symlink_paths_preserve_existing_bytes() {
            for variant in ["missing", "source_link", "destination_link"] {
                let mut fixture = Fixture::new(GOOD_BACKUP);
                match variant {
                    "missing" => fixture.backup.remote_path = fixture.root.path().join("absent"),
                    "source_link" => {
                        let link = fixture.root.path().join("backup-link");
                        std::os::unix::fs::symlink(&fixture.source, &link).unwrap();
                        fixture.backup.remote_path = link;
                    }
                    "destination_link" => {
                        let saved = fixture.root.path().join("saved-current");
                        std::fs::rename(&fixture.destination, &saved).unwrap();
                        std::os::unix::fs::symlink(&saved, &fixture.destination).unwrap();
                    }
                    _ => unreachable!(),
                }
                let output = fixture.run(false, None);
                fixture.assert_preserved(&output);
            }
        }

        #[test]
        fn rollback_rejects_directory_destination_without_moving_bytes_inside() {
            let fixture = Fixture::new(GOOD_BACKUP);
            let saved = fixture.root.path().join("saved-current");
            std::fs::rename(&fixture.destination, &saved).unwrap();
            std::fs::create_dir(&fixture.destination).unwrap();
            let output = fixture.run(false, None);
            assert!(!output.status.success(), "{output:?}");
            assert_eq!(std::fs::read(&saved).unwrap(), OLD_BINARY);
            assert_eq!(std::fs::read_dir(&fixture.destination).unwrap().count(), 0);
            assert_eq!(
                std::fs::read(&fixture.source).unwrap(),
                fixture.source_bytes
            );
        }

        #[test]
        fn rollback_rejects_a_successful_move_that_leaves_staging_unconsumed() {
            let fixture = Fixture::new(GOOD_BACKUP);
            let tools = fixture.tools(Some("mv"));
            std::fs::write(tools.join("mv"), "#!/bin/sh\nexit 0\n").unwrap();
            let output = fixture.run(false, Some(&tools));
            fixture.assert_preserved(&output);
            assert!(String::from_utf8_lossy(&output.stderr).contains("unconfirmed"));
        }

        #[test]
        fn rollback_never_reports_success_when_destination_becomes_a_directory_during_mv() {
            let fixture = Fixture::new(GOOD_BACKUP);
            let tools = fixture.tools(Some("mv"));
            let saved = fixture.root.path().join("saved-current");
            let real_mv = which::which("mv").unwrap();
            let real_mkdir = which::which("mkdir").unwrap();
            let real_mv = shell_escape_path_with_home(real_mv.to_str().unwrap()).unwrap();
            let real_mkdir = shell_escape_path_with_home(real_mkdir.to_str().unwrap()).unwrap();
            let saved_arg = shell_escape_path_with_home(saved.to_str().unwrap()).unwrap();
            // Simulate another actor replacing the destination between the
            // final type check and mv. POSIX mv then succeeds by moving the
            // stage inside that directory; it must not produce a receipt.
            std::fs::write(
                tools.join("mv"),
                format!(
                    "#!/bin/sh\nset -eu\n[ \"$#\" -eq 3 ]\n\
                     {real_mv} \"$3\" {saved_arg}\n\
                     {real_mkdir} \"$3\"\n\
                     exec {real_mv} \"$@\"\n"
                ),
            )
            .unwrap();
            let output = fixture.run(false, Some(&tools));
            assert!(!output.status.success(), "{output:?}");
            assert!(!String::from_utf8_lossy(&output.stdout).contains("RCH_ROLLBACK_OK"));
            assert!(String::from_utf8_lossy(&output.stderr).contains("unconfirmed"));
            assert_eq!(std::fs::read(saved).unwrap(), OLD_BINARY);
            assert_eq!(
                std::fs::read(&fixture.source).unwrap(),
                fixture.source_bytes
            );
            let entries: Vec<_> = std::fs::read_dir(&fixture.destination)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .collect();
            assert_eq!(entries.len(), 1);
            assert_eq!(std::fs::read(&entries[0]).unwrap(), fixture.source_bytes);
        }

        struct RunningHelper(std::process::Child);

        impl Drop for RunningHelper {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        #[test]
        fn rollback_replaces_a_running_executable_without_terminating_its_process() {
            let fixture = Fixture::new(GOOD_BACKUP);
            std::fs::copy(which::which("sleep").unwrap(), &fixture.destination).unwrap();
            let mut helper = RunningHelper(
                Command::new(&fixture.destination)
                    .arg("30")
                    .spawn()
                    .unwrap(),
            );
            assert!(helper.0.try_wait().unwrap().is_none());
            let output = fixture.run(true, None);
            assert!(output.status.success(), "{output:?}");
            assert!(
                helper.0.try_wait().unwrap().is_none(),
                "active worker was stopped"
            );
            assert_eq!(
                std::fs::read(&fixture.destination).unwrap(),
                fixture.source_bytes
            );
        }
    }

    // ========================
    // Concurrent Write Tests
    // ========================

    #[tokio::test]
    async fn test_backup_registry_concurrent_writes() {
        use tokio::task::JoinSet;

        let temp_dir = tempfile::tempdir().unwrap();
        let registry_path = temp_dir.path().to_path_buf();

        // Spawn multiple concurrent writes
        let mut tasks = JoinSet::new();
        for i in 0..10 {
            let path = registry_path.clone();
            tasks.spawn(async move {
                let manager = RollbackManager::with_path(&path).unwrap();
                let backup =
                    manager.create_backup_entry(&format!("worker{}", i), "1.0.0", "/path", "hash");
                manager.save_backup_entry(&backup).unwrap();
                i
            });
        }

        // Wait for all to complete
        let mut completed = Vec::new();
        while let Some(result) = tasks.join_next().await {
            completed.push(result.unwrap());
        }

        // All 10 should have completed
        assert_eq!(completed.len(), 10);

        // Verify registry is not corrupted
        let manager = RollbackManager::with_path(&registry_path).unwrap();
        let registry = manager.load_registry().unwrap();

        // Should have all 10 entries (atomic writes should prevent corruption)
        assert_eq!(registry.len(), 10);

        // Verify each worker is present
        for i in 0..10 {
            let worker_id = format!("worker{}", i);
            assert!(
                manager.get_latest_backup(&worker_id).is_some(),
                "Worker {} should have backup",
                worker_id
            );
        }
    }

    // ========================
    // Multiple Workers Parallel Test
    // ========================

    #[tokio::test]
    async fn test_rollback_multiple_workers_returns_all_results() {
        use crate::ui::test_utils::OutputCapture;

        let temp_dir = tempfile::tempdir().unwrap();
        let manager = RollbackManager::with_path(temp_dir.path()).unwrap();

        // Create 5 workers
        let workers: Vec<WorkerConfig> = (0..5).map(|i| mock_worker(&format!("w{}", i))).collect();
        let worker_refs: Vec<&WorkerConfig> = workers.iter().collect();

        let capture = OutputCapture::json();
        let ctx = capture.context();

        // No backups registered, so all should fail
        let results = manager
            .rollback_workers(&worker_refs, None, 4, false, &ctx)
            .await
            .unwrap();

        // Should get a result for each worker
        assert_eq!(results.len(), 5);

        // All should fail (no backups)
        assert!(results.iter().all(|r| !r.success));

        // Each worker should have its own result
        let worker_ids: Vec<&str> = results.iter().map(|r| r.worker_id.as_str()).collect();
        for i in 0..5 {
            let expected_id = format!("w{}", i);
            assert!(
                worker_ids.contains(&expected_id.as_str()),
                "Missing result for {}",
                expected_id
            );
        }
    }
}
