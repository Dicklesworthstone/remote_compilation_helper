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
use rch_common::ssh_utils::shell_escape_path_with_home;
use rch_common::{WorkerConfig, WorkerId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

const REMOTE_WORKER_BINARY: &str = "~/.local/bin/rch-wkr";
static STAGED_BINARY_COUNTER: AtomicU64 = AtomicU64::new(0);

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
    /// Canary succeeded but `auto_promote` is off, so the rest of the fleet is
    /// intentionally NOT yet deployed. Distinct from `Success` so operators and
    /// JSON consumers never read a partial canary rollout as a finished one.
    CanaryPending {
        /// Workers deployed in the canary batch.
        promoted: usize,
        /// Workers still running the previous version, awaiting promotion.
        remaining: usize,
        skipped: usize,
        failed: usize,
    },
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
        // Set when a canary succeeds but auto_promote is off: the count of
        // workers intentionally left on the previous version.
        let mut canary_pending_remaining: Option<usize> = None;

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

                // Deploy to remaining workers if auto_promote is enabled;
                // otherwise leave them on the previous version and record the
                // pending count so the caller doesn't report a finished rollout.
                if canary_count < worker_count {
                    if auto_promote {
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
                    } else {
                        canary_pending_remaining = Some(worker_count - canary_count);
                    }
                }
            }
            DeploymentStrategy::Rolling {
                batch_size,
                wait_between,
            } => {
                // Clamp batch_size to at least 1. A 0 here would make
                // `end = start + 0 = start`, so `start = end` wouldn't
                // advance and the loop would spin forever. The strategy
                // value comes from user config/JSON, so we must not trust
                // it — mirror the `parallelism.max(1)` clamp used inside
                // `deploy_batch` and by dry-run's estimator.
                let batch_size = batch_size.max(1);
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

        if let Some(remaining) = canary_pending_remaining {
            Ok(FleetResult::CanaryPending {
                promoted: deployed,
                remaining,
                skipped,
                failed,
            })
        } else {
            Ok(FleetResult::Success {
                deployed,
                skipped,
                failed,
            })
        }
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

                // Guard against clobbering a worker's good binary with one built
                // for the wrong OS/arch (e.g. pushing a macOS binary onto a
                // linux/amd64 worker => `Exec format error`). Runs before SCP so
                // a mismatch never overwrites the existing binary.
                if let Err(e) = ensure_binary_matches_worker(&worker_config, &local_binary).await {
                    progress.worker_failed(&worker_id, &format!("{}", e)).await;
                    return (idx, worker_id, false, DeploymentStatus::Failed);
                }

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

// =============================================================================
// Binary / worker platform compatibility guard
// =============================================================================
//
// A controller must never overwrite a worker's good binary with one built for
// the wrong OS/arch. Pushing a macOS Mach-O onto a linux/amd64 worker leaves
// every invocation failing with `Exec format error` (exit 126). We detect the
// local binary's executable format from its magic bytes and the worker's
// platform from `uname`, and refuse the deploy on mismatch *before* the
// existing binary is replaced.

/// Operating-system family of an executable or a remote worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BinaryOs {
    Linux,
    MacOs,
    Windows,
}

impl BinaryOs {
    fn as_str(self) -> &'static str {
        match self {
            BinaryOs::Linux => "linux",
            BinaryOs::MacOs => "macos",
            BinaryOs::Windows => "windows",
        }
    }
}

/// CPU architecture of an executable or a remote worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BinaryArch {
    X86_64,
    Aarch64,
    X86,
    Arm,
}

impl BinaryArch {
    fn as_str(self) -> &'static str {
        match self {
            BinaryArch::X86_64 => "x86_64",
            BinaryArch::Aarch64 => "aarch64",
            BinaryArch::X86 => "x86",
            BinaryArch::Arm => "arm",
        }
    }
}

/// OS + arch of an executable or worker. `arch == None` means the arch could
/// not be determined (e.g. a universal/fat Mach-O, or an unrecognised
/// `uname -m`); in that case we only enforce the OS match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BinaryPlatform {
    os: BinaryOs,
    arch: Option<BinaryArch>,
}

impl std::fmt::Display for BinaryPlatform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.arch {
            Some(arch) => write!(f, "{}/{}", self.os.as_str(), arch.as_str()),
            None => write!(f, "{}/unknown", self.os.as_str()),
        }
    }
}

/// Number of header bytes that are sufficient to classify ELF, Mach-O and PE
/// executables (magic + machine/cputype fields all live in the first 20 bytes).
const BINARY_MAGIC_PROBE_LEN: usize = 20;

/// Classify a local executable from its leading magic bytes.
///
/// Returns `None` when the format is unrecognised, in which case the guard
/// fails open (the post-deploy health check remains the backstop).
fn detect_binary_platform(header: &[u8]) -> Option<BinaryPlatform> {
    // PE / Windows ("MZ").
    if header.len() >= 2 && &header[0..2] == b"MZ" {
        return Some(BinaryPlatform {
            os: BinaryOs::Windows,
            arch: None,
        });
    }

    // ELF: 0x7F 'E' 'L' 'F'.
    if header.len() >= 20 && header[0..4] == [0x7F, b'E', b'L', b'F'] {
        // EI_DATA at offset 5: 1 = little-endian, 2 = big-endian.
        let little_endian = header[5] != 2;
        // e_machine: 2-byte field at offset 18.
        let machine = if little_endian {
            u16::from_le_bytes([header[18], header[19]])
        } else {
            u16::from_be_bytes([header[18], header[19]])
        };
        let arch = match machine {
            0x3E => Some(BinaryArch::X86_64),  // EM_X86_64
            0xB7 => Some(BinaryArch::Aarch64), // EM_AARCH64
            0x03 => Some(BinaryArch::X86),     // EM_386
            0x28 => Some(BinaryArch::Arm),     // EM_ARM
            _ => None,
        };
        return Some(BinaryPlatform {
            os: BinaryOs::Linux,
            arch,
        });
    }

    // Mach-O (single-arch). Magic stored in native endianness:
    //   little-endian on disk: CF FA ED FE (64-bit) / CE FA ED FE (32-bit)
    //   cross-endian:          FE ED FA CF / FE ED FA CE
    if header.len() >= 8 {
        let magic = &header[0..4];
        let is_macho_le = magic == [0xCF, 0xFA, 0xED, 0xFE] || magic == [0xCE, 0xFA, 0xED, 0xFE];
        let is_macho_be = magic == [0xFE, 0xED, 0xFA, 0xCF] || magic == [0xFE, 0xED, 0xFA, 0xCE];
        if is_macho_le || is_macho_be {
            // cputype: 4-byte field at offset 4, in the same endianness as magic.
            let cputype = if is_macho_le {
                u32::from_le_bytes([header[4], header[5], header[6], header[7]])
            } else {
                u32::from_be_bytes([header[4], header[5], header[6], header[7]])
            };
            let arch = match cputype {
                0x0100_0007 => Some(BinaryArch::X86_64),  // CPU_TYPE_X86_64
                0x0100_000C => Some(BinaryArch::Aarch64), // CPU_TYPE_ARM64
                0x0000_0007 => Some(BinaryArch::X86),     // CPU_TYPE_X86
                0x0000_000C => Some(BinaryArch::Arm),     // CPU_TYPE_ARM
                _ => None,
            };
            return Some(BinaryPlatform {
                os: BinaryOs::MacOs,
                arch,
            });
        }

        // Universal / fat Mach-O: FAT_MAGIC 0xCAFEBABE (and byte-swapped). Such
        // a binary contains multiple slices, so we only assert the macOS OS.
        if magic == [0xCA, 0xFE, 0xBA, 0xBE] || magic == [0xBE, 0xBA, 0xFE, 0xCA] {
            return Some(BinaryPlatform {
                os: BinaryOs::MacOs,
                arch: None,
            });
        }
    }

    None
}

/// Parse `uname -s` / `uname -m` output into a worker platform.
///
/// `uname_s` is the kernel name (`Linux`, `Darwin`, ...) and `uname_m` is the
/// machine hardware name (`x86_64`, `aarch64`, `arm64`, ...). Returns `None`
/// when the OS is unrecognised so the guard fails open.
fn parse_worker_platform(uname_s: &str, uname_m: &str) -> Option<BinaryPlatform> {
    let os = match uname_s.trim().to_ascii_lowercase().as_str() {
        "linux" => BinaryOs::Linux,
        "darwin" => BinaryOs::MacOs,
        s if s.contains("mingw") || s.contains("msys") || s.contains("cygwin") => BinaryOs::Windows,
        _ => return None,
    };

    let arch = match uname_m.trim().to_ascii_lowercase().as_str() {
        "x86_64" | "amd64" => Some(BinaryArch::X86_64),
        "aarch64" | "arm64" => Some(BinaryArch::Aarch64),
        "i386" | "i486" | "i586" | "i686" | "x86" => Some(BinaryArch::X86),
        m if m.starts_with("armv") || m == "arm" => Some(BinaryArch::Arm),
        _ => None,
    };

    Some(BinaryPlatform { os, arch })
}

/// Whether a binary built for `local` can execute on a `worker` platform.
///
/// The OS must match exactly. The arch must match when both are known; an
/// unknown arch on either side (universal binary, unrecognised `uname -m`)
/// degrades to an OS-only check rather than a false rejection.
fn platforms_compatible(local: BinaryPlatform, worker: BinaryPlatform) -> bool {
    if local.os != worker.os {
        return false;
    }
    match (local.arch, worker.arch) {
        (Some(a), Some(b)) => a == b,
        _ => true,
    }
}

/// Read the leading magic bytes of a local binary.
fn read_binary_header(path: &Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut buf = vec![0u8; BINARY_MAGIC_PROBE_LEN];
    let mut read = 0;
    while read < buf.len() {
        match file.read(&mut buf[read..])? {
            0 => break,
            n => read += n,
        }
    }
    buf.truncate(read);
    Ok(buf)
}

/// Detect a worker's platform via `uname`.
async fn detect_worker_platform(worker: &WorkerConfig) -> Option<BinaryPlatform> {
    let ssh = SshExecutor::new(worker);
    let output = ssh
        .run_command("uname -s; uname -m")
        .await
        .ok()
        .filter(CommandOutput::success)?;
    let mut lines = output.stdout.lines();
    let uname_s = lines.next()?;
    let uname_m = lines.next().unwrap_or("");
    parse_worker_platform(uname_s, uname_m)
}

// =============================================================================
// Per-worker target-triple discovery and artifact resolution
// (bd-session-history-remediation-ocv9i.7.1, elaborating P0 6h54q)
// =============================================================================
//
// `rch update --fleet` must select the rch-wkr artifact matching each WORKER's
// target triple, never assume the controller's own OS/arch. The 6h54q guard
// refuses a proven mismatch *at deploy time*; this adds the upstream half:
// discover each worker's triple and resolve the compatible artifact ahead of
// time, failing closed when none exists.

/// C runtime flavor for linux targets. RCH ships linux binaries as static
/// `musl` builds, so `musl` is the default expectation; `gnu` is recorded when
/// a worker clearly lacks musl, and `unknown` when undetermined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // wired into the deploy flow by bead 7.2
enum LinuxLibc {
    Musl,
    Gnu,
    Unknown,
}

/// Facts discovered about a worker needed to pick its fleet-update artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)] // fields consumed by the deploy-flow integration (bead 7.2)
struct WorkerTargetFacts {
    /// OS + CPU arch (from `uname`).
    platform: BinaryPlatform,
    /// libc flavor (linux only; ignored for macOS).
    libc: LinuxLibc,
    /// The SSH user the controller connects as.
    remote_user: String,
    /// The currently-installed `rch-wkr` path on the worker, if found.
    rch_wkr_path: Option<String>,
}

/// Map a worker's discovered facts to its Rust target triple. Returns `None`
/// when the OS/arch could not be classified (caller must fail closed).
///
/// Linux defaults to `musl` (RCH's static release flavor) unless a worker was
/// positively detected as `gnu`-only. Mirrors the os/arch→triple mapping used
/// by the self-update path so fleet and self artifacts name workers
/// identically.
#[allow(dead_code)] // consumed by the deploy-flow integration (bead 7.2)
fn worker_target_triple(facts: &WorkerTargetFacts) -> Option<String> {
    let arch = facts.platform.arch?;
    let arch_str = match arch {
        BinaryArch::X86_64 => "x86_64",
        BinaryArch::Aarch64 => "aarch64",
        // 32-bit targets are not part of the fleet release matrix.
        BinaryArch::X86 | BinaryArch::Arm => return None,
    };
    match facts.platform.os {
        BinaryOs::Linux => {
            let libc = match facts.libc {
                LinuxLibc::Gnu => "gnu",
                // musl is the default static release flavor.
                LinuxLibc::Musl | LinuxLibc::Unknown => "musl",
            };
            Some(format!("{arch_str}-unknown-linux-{libc}"))
        }
        BinaryOs::MacOs => Some(format!("{arch_str}-apple-darwin")),
        // Windows workers are not part of the fleet.
        BinaryOs::Windows => None,
    }
}

/// A fleet-update artifact available to deploy, identified by the target triple
/// it was built for.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)] // consumed by the deploy-flow integration (bead 7.2)
struct FleetArtifact {
    /// Artifact file name (e.g. `rch-wkr-v1.0.27-x86_64-unknown-linux-musl`).
    name: String,
    /// The Rust target triple this artifact targets.
    target_triple: String,
}

/// Failure to resolve a compatible artifact for a worker.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)] // consumed by the deploy-flow integration (bead 7.2)
enum ArtifactResolveError {
    /// The worker's target triple could not be determined.
    UnknownTriple { worker_id: String },
    /// No available artifact matches the worker's triple.
    NoCompatibleArtifact {
        worker_id: String,
        triple: String,
        available: Vec<String>,
    },
}

impl std::fmt::Display for ArtifactResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArtifactResolveError::UnknownTriple { worker_id } => write!(
                f,
                "cannot resolve fleet artifact for {worker_id}: worker target triple is unknown"
            ),
            ArtifactResolveError::NoCompatibleArtifact {
                worker_id,
                triple,
                available,
            } => write!(
                f,
                "no fleet artifact for {worker_id} (target {triple}); available: [{}]",
                available.join(", ")
            ),
        }
    }
}

/// Resolve the artifact matching a worker's target triple, failing **closed**
/// when none is compatible. An artifact matches when its `target_triple` equals
/// the worker triple or its `name` contains the triple as a substring (release
/// asset names embed the triple).
#[allow(dead_code)] // consumed by the deploy-flow integration (bead 7.2)
fn resolve_worker_artifact<'a>(
    worker_id: &str,
    triple: &str,
    artifacts: &'a [FleetArtifact],
) -> Result<&'a FleetArtifact, ArtifactResolveError> {
    artifacts
        .iter()
        .find(|a| a.target_triple == triple || a.name.contains(triple))
        .ok_or_else(|| ArtifactResolveError::NoCompatibleArtifact {
            worker_id: worker_id.to_string(),
            triple: triple.to_string(),
            available: artifacts.iter().map(|a| a.target_triple.clone()).collect(),
        })
}

/// Discover a worker's target facts over SSH: `uname`, libc flavor, the SSH
/// user, and the current `rch-wkr` path. Returns `None` when the platform
/// cannot be classified (caller fails closed).
#[allow(dead_code)] // invoked by the deploy-flow integration (bead 7.2)
async fn discover_worker_target_facts(worker: &WorkerConfig) -> Option<WorkerTargetFacts> {
    let platform = detect_worker_platform(worker).await?;
    let ssh = SshExecutor::new(worker);

    // libc detection (linux only): a musl loader under /lib indicates musl;
    // `ldd --version` mentioning GNU indicates gnu. Best-effort.
    let libc = if platform.os == BinaryOs::Linux {
        match ssh
            .run_command(
                "ls /lib/ld-musl-* >/dev/null 2>&1 && echo musl || (ldd --version 2>&1 | head -1)",
            )
            .await
        {
            Ok(out) if out.success() => {
                let lower = out.stdout.to_ascii_lowercase();
                if lower.contains("musl") {
                    LinuxLibc::Musl
                } else if lower.contains("gnu") || lower.contains("glibc") {
                    LinuxLibc::Gnu
                } else {
                    LinuxLibc::Unknown
                }
            }
            _ => LinuxLibc::Unknown,
        }
    } else {
        LinuxLibc::Unknown
    };

    let rch_wkr_path = match ssh
        .run_command("command -v rch-wkr 2>/dev/null || echo ~/.local/bin/rch-wkr")
        .await
    {
        Ok(out) if out.success() => out.stdout.lines().next().map(str::to_string),
        _ => None,
    };

    Some(WorkerTargetFacts {
        platform,
        libc,
        remote_user: worker.user.clone(),
        rch_wkr_path,
    })
}

/// Refuse to deploy a binary whose OS/arch is incompatible with the worker.
///
/// Fails open (returns `Ok`) when either side cannot be classified — the
/// post-deploy health check stays as the final backstop — but fails loudly on a
/// *proven* mismatch so a controller never clobbers a worker's good binary with
/// an `Exec format error` time bomb.
async fn ensure_binary_matches_worker(worker: &WorkerConfig, local_binary: &Path) -> Result<()> {
    let header = match read_binary_header(local_binary) {
        Ok(header) => header,
        Err(e) => {
            warn!(
                worker = %worker.id,
                path = %local_binary.display(),
                error = %e,
                "Could not read local binary header for platform check; proceeding"
            );
            return Ok(());
        }
    };

    let local_platform = match detect_binary_platform(&header) {
        Some(platform) => platform,
        None => {
            warn!(
                worker = %worker.id,
                path = %local_binary.display(),
                "Unrecognised local binary format; skipping platform pre-check"
            );
            return Ok(());
        }
    };

    let worker_platform = match detect_worker_platform(worker).await {
        Some(platform) => platform,
        None => {
            warn!(
                worker = %worker.id,
                "Could not determine worker platform via uname; skipping platform pre-check"
            );
            return Ok(());
        }
    };

    if platforms_compatible(local_platform, worker_platform) {
        debug!(
            worker = %worker.id,
            local = %local_platform,
            remote = %worker_platform,
            "Binary platform matches worker"
        );
        return Ok(());
    }

    Err(FleetError::BinaryPlatformMismatch {
        worker_id: worker.id.0.clone(),
        local: local_platform.to_string(),
        worker: worker_platform.to_string(),
    }
    .into())
}

/// Copy the binary to the worker via SCP.
///
/// Uploads to a temporary file in the target directory, then atomically renames
/// it into place. Directly scp'ing onto `rch-wkr` can fail when the worker
/// binary is currently executing.
async fn copy_binary_via_scp(worker: &WorkerConfig, local_binary: &Path) -> Result<()> {
    let ssh = SshExecutor::new(worker);
    let remote_path = REMOTE_WORKER_BINARY;
    let staging_path = remote_worker_binary_staging_path();

    debug!(
        "SCP: {} -> {}@{}:{}",
        local_binary.display(),
        worker.user,
        worker.host,
        staging_path
    );

    ssh.copy_file(local_binary, &staging_path)
        .await
        .map_err(|e| anyhow::anyhow!("scp failed: {}", e))?;

    // Atomic, rollback-safe switch (bd-...-7.2): chmod + checksum-verify +
    // startup-validate the staged temp binary, and only `mv` it into place if
    // all of that succeeds. `set -e` aborts BEFORE the rename on any failure
    // (truncated/corrupt transfer => checksum mismatch; wrong arch/bad binary
    // => `--version` exec error), so the previously working binary stays live.
    let expected_sha256 = local_file_sha256_hex(local_binary)
        .map_err(|e| anyhow::anyhow!("hash local binary {}: {}", local_binary.display(), e))?;
    let finalize_cmd = staged_install_command(&staging_path, remote_path, &expected_sha256)?;
    let output = ssh
        .run_command(&finalize_cmd)
        .await
        .map_err(|e| anyhow::anyhow!("staged install failed: {}", e))?;

    if output.success() {
        return Ok(());
    }

    // Validation/checksum failed (or an interrupted transfer): the rename never
    // ran, so the old binary is intact. Best-effort remove the staged temp.
    if let Ok(staging_path) = remote_shell_path(&staging_path) {
        let cleanup_cmd = format!("rm -f {staging_path}");
        let _ = ssh.run_command(&cleanup_cmd).await;
    }

    Err(anyhow::anyhow!(
        "staged install rejected before switch (exit {}: {}); previous binary left active",
        output.exit_code,
        output.stderr.trim()
    ))
}

/// Streaming SHA-256 of a local file as a lowercase hex string. Matches the
/// worker's `sha256sum` so a corrupt/truncated transfer is caught before the
/// atomic switch.
fn local_file_sha256_hex(path: &Path) -> std::io::Result<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex_lower(&hasher.finalize()))
}

/// Lowercase hex encoding of a byte slice.
fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Set executable permissions on the remote binary.
///
/// Uses `SshExecutor::set_executable()` for consistent behavior and logging.
async fn set_executable_permissions(worker: &WorkerConfig) -> Result<()> {
    let ssh = SshExecutor::new(worker);
    ssh.set_executable(REMOTE_WORKER_BINARY)
        .await
        .map_err(|e| anyhow::anyhow!("chmod failed: {}", e))
}

/// Verify the installation by running health check.
///
/// Uses `SshExecutor::run_command()` for consistent behavior and logging.
// =============================================================================
// Post-deploy exact user/path validation
// (bd-session-history-remediation-ocv9i.7.3)
// =============================================================================

/// Eligibility verdict from validating the deployed binary at the EXACT path
/// (and as the user) RCH will actually invoke it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PostDeployEligibility {
    Eligible,
    /// The deployed binary cannot run on this worker (most commonly an
    /// `Exec format error` from an OS/arch mismatch). The worker must be marked
    /// not eligible; `reason_code` is a stable token for incident/proof/
    /// admission surfaces.
    NotEligible {
        reason_code: &'static str,
        detail: String,
    },
}

/// Build the post-deploy validation command. Runs against the EXACT remote
/// path RCH invokes (shell-escaped, never the bare PATH-resolved `rch-wkr`
/// which could be a different binary), as the connecting worker user (the SSH
/// session is already that user — NOT root, NOT a login-default path). Probes
/// `uname`, `file`, and `<path> --version` so a wrong-OS/arch binary surfaces
/// as a non-zero exit / `Exec format error`.
fn post_deploy_validation_command(remote_path: &str) -> Result<String> {
    let p = remote_shell_path(remote_path)?;
    Ok(format!(
        "uname -s -m; file {p} 2>/dev/null || true; {p} --version"
    ))
}

/// Classify the exact-path validation result. `Exec format error` (exit 126 or
/// the kernel message) means the binary is built for the wrong OS/arch and the
/// worker is not eligible; any other non-zero exit is a generic validation
/// failure.
fn classify_post_deploy(exit_code: i32, stderr: &str) -> PostDeployEligibility {
    let trimmed = stderr.trim();
    if exit_code == 126 || trimmed.contains("Exec format error") {
        return PostDeployEligibility::NotEligible {
            reason_code: "os_arch_mismatch",
            detail: format!(
                "deployed rch-wkr is not executable on this worker (exit {exit_code}: {trimmed}); \
                the binary architecture does not match the worker"
            ),
        };
    }
    if exit_code != 0 {
        return PostDeployEligibility::NotEligible {
            reason_code: "post_deploy_validation_failed",
            detail: format!("post-deploy validation failed (exit {exit_code}: {trimmed})"),
        };
    }
    PostDeployEligibility::Eligible
}

async fn verify_installation(worker: &WorkerConfig) -> Result<()> {
    let ssh = SshExecutor::new(worker);

    // 1. Exact user/path validation (bd-...-7.3): run `<exact path> --version`
    //    (+ uname/file) as the worker user. An Exec format error here marks the
    //    worker not eligible with a stable reason code — the post-deploy
    //    backstop for the pre-deploy/staged arch guards.
    let validation_cmd = post_deploy_validation_command(REMOTE_WORKER_BINARY)?;
    let validation = ssh
        .run_command(&validation_cmd)
        .await
        .map_err(|e| anyhow::anyhow!("post-deploy validation failed: {}", e))?;
    if let PostDeployEligibility::NotEligible {
        reason_code,
        detail,
    } = classify_post_deploy(validation.exit_code, &validation.stderr)
    {
        return Err(FleetError::HealthCheckFailed {
            reason: format!("[{reason_code}] {detail}"),
        }
        .into());
    }

    // 2. Protocol handshake via the same exact path.
    let output = ssh
        .run_command("~/.local/bin/rch-wkr health")
        .await
        .map_err(|e| anyhow::anyhow!("health check failed: {}", e))?;

    if !output.success() {
        let stderr = output.stderr.trim();
        if let PostDeployEligibility::NotEligible {
            reason_code,
            detail,
        } = classify_post_deploy(output.exit_code, stderr)
        {
            return Err(FleetError::HealthCheckFailed {
                reason: format!("[{reason_code}] {detail}"),
            }
            .into());
        }
        return Err(FleetError::HealthCheckFailed {
            reason: stderr.to_string(),
        }
        .into());
    }

    Ok(())
}

fn remote_worker_binary_staging_path() -> String {
    let counter = STAGED_BINARY_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    format!(
        "~/.local/bin/.rch-wkr.tmp.{}.{}.{}",
        std::process::id(),
        nonce,
        counter
    )
}

fn remote_shell_path(remote_path: &str) -> Result<String> {
    shell_escape_path_with_home(remote_path)
        .ok_or_else(|| anyhow::anyhow!("invalid remote path contains control characters"))
}

/// Build the atomic, rollback-safe install script for a staged worker binary
/// (bd-...-7.2).
///
/// Under `set -e`, in order: make the staged temp executable, verify its
/// SHA-256 against `expected_sha256` (catches a truncated/corrupt transfer),
/// run `--version` FROM THE TEMP PATH (catches a wrong-arch/broken binary via
/// an `Exec format error`), and only then `mv -f` it over the live binary. Any
/// earlier failure exits non-zero before the rename, so the previously working
/// binary is never replaced by a bad one.
fn staged_install_command(
    staging_path: &str,
    final_path: &str,
    expected_sha256: &str,
) -> Result<String> {
    let staged = remote_shell_path(staging_path)?;
    let final_path = remote_shell_path(final_path)?;
    // expected_sha256 is our own lowercase hex (64 chars, [0-9a-f]); guard
    // anyway so a non-hex value can never inject shell.
    if expected_sha256.len() != 64 || !expected_sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(anyhow::anyhow!("invalid expected sha256 digest"));
    }
    Ok(format!(
        "set -e; \
         chmod +x {staged}; \
         actual=$(sha256sum {staged} | cut -d' ' -f1); \
         [ \"$actual\" = \"{expected_sha256}\" ] || {{ echo \"checksum mismatch: $actual != {expected_sha256}\" >&2; exit 1; }}; \
         {staged} --version >/dev/null 2>&1 || {{ echo \"staged binary failed --version (wrong arch or corrupt)\" >&2; exit 1; }}; \
         mv -f {staged} {final_path}"
    ))
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
    fn fleet_result_canary_pending_serializes_distinctly_from_success() {
        // Regression (bd-review-canary-success-misreport): a canary with
        // auto_promote off must NOT serialize as Success — a JSON consumer
        // would otherwise read a partial rollout as finished.
        let pending = FleetResult::CanaryPending {
            promoted: 5,
            remaining: 95,
            skipped: 0,
            failed: 0,
        };
        let json = serde_json::to_string(&pending).unwrap();
        assert!(json.contains("\"status\":\"CanaryPending\""));
        assert!(json.contains("\"promoted\":5"));
        assert!(json.contains("\"remaining\":95"));
        // Must be distinguishable from Success with the same deployed count.
        let success = serde_json::to_string(&FleetResult::Success {
            deployed: 5,
            skipped: 0,
            failed: 0,
        })
        .unwrap();
        assert_ne!(json, success);
        assert!(!json.contains("\"status\":\"Success\""));
    }

    #[test]
    fn fleet_result_canary_pending_round_trips() {
        let pending = FleetResult::CanaryPending {
            promoted: 2,
            remaining: 6,
            skipped: 1,
            failed: 0,
        };
        let json = serde_json::to_string(&pending).unwrap();
        let back: FleetResult = serde_json::from_str(&json).unwrap();
        match back {
            FleetResult::CanaryPending {
                promoted,
                remaining,
                skipped,
                failed,
            } => {
                assert_eq!((promoted, remaining, skipped, failed), (2, 6, 1, 0));
            }
            other => panic!("expected CanaryPending, got {other:?}"),
        }
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
    fn fleet_result_aborted_special_chars_in_reason() -> Result<()> {
        let result = FleetResult::Aborted {
            reason: "User cancelled: \"interrupted\" <signal>".to_string(),
        };
        let json = serde_json::to_string(&result)?;
        let deserialized: FleetResult = serde_json::from_str(&json)?;
        let FleetResult::Aborted { reason } = deserialized else {
            return Err(anyhow::anyhow!("expected Aborted variant"));
        };

        assert!(reason.contains("interrupted"));
        assert!(reason.contains("<signal>"));
        Ok(())
    }

    #[test]
    fn fleet_result_deserialize_success() -> Result<()> {
        let json = r#"{"status":"Success","deployed":3,"skipped":1,"failed":0}"#;
        let result: FleetResult = serde_json::from_str(json)?;
        let FleetResult::Success {
            deployed,
            skipped,
            failed,
        } = result
        else {
            return Err(anyhow::anyhow!("expected Success variant"));
        };

        assert_eq!(deployed, 3);
        assert_eq!(skipped, 1);
        assert_eq!(failed, 0);
        Ok(())
    }

    #[test]
    fn fleet_result_deserialize_canary_failed() -> Result<()> {
        let json = r#"{"status":"CanaryFailed","reason":"worker timeout"}"#;
        let result: FleetResult = serde_json::from_str(json)?;
        let FleetResult::CanaryFailed { reason } = result else {
            return Err(anyhow::anyhow!("expected CanaryFailed variant"));
        };

        assert_eq!(reason, "worker timeout");
        Ok(())
    }

    #[test]
    fn fleet_result_deserialize_aborted() -> Result<()> {
        let json = r#"{"status":"Aborted","reason":"ctrl+c"}"#;
        let result: FleetResult = serde_json::from_str(json)?;
        let FleetResult::Aborted { reason } = result else {
            return Err(anyhow::anyhow!("expected Aborted variant"));
        };

        assert_eq!(reason, "ctrl+c");
        Ok(())
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

    #[test]
    fn staged_install_command_validates_then_renames_in_order() -> Result<()> {
        let sha = "a".repeat(64);
        let command = staged_install_command(
            "~/.local/bin/.rch-wkr.tmp.123.456",
            REMOTE_WORKER_BINARY,
            &sha,
        )?;

        // chmod, checksum, --version, then mv — with mv strictly last.
        assert!(command.contains("set -e"));
        assert!(command.contains("chmod +x \"$HOME/.local/bin/.rch-wkr.tmp.123.456\""));
        assert!(command.contains("sha256sum \"$HOME/.local/bin/.rch-wkr.tmp.123.456\""));
        assert!(
            command.contains(&sha),
            "expected digest embedded for comparison"
        );
        assert!(command.contains("\"$HOME/.local/bin/.rch-wkr.tmp.123.456\" --version"));
        assert!(command.contains(
            "mv -f \"$HOME/.local/bin/.rch-wkr.tmp.123.456\" \"$HOME/.local/bin/rch-wkr\""
        ));
        // Rollback-safety: the rename must be the LAST step (after both guards),
        // so a failed checksum/version (set -e) never reaches it.
        let mv_pos = command.find("mv -f").expect("mv present");
        let sha_pos = command.find("sha256sum").expect("checksum present");
        let ver_pos = command.find("--version").expect("version present");
        assert!(
            mv_pos > sha_pos && mv_pos > ver_pos,
            "mv must come after both guards"
        );
        Ok(())
    }

    #[test]
    fn staged_install_command_rejects_non_hex_digest() {
        // A non-hex/short digest must never be embedded into the shell script.
        assert!(
            staged_install_command("~/.local/bin/.rch-wkr.tmp.1", REMOTE_WORKER_BINARY, "nope")
                .is_err()
        );
        assert!(
            staged_install_command(
                "~/.local/bin/.rch-wkr.tmp.1",
                REMOTE_WORKER_BINARY,
                "abc; rm -rf /"
            )
            .is_err()
        );
    }

    #[test]
    fn local_file_sha256_matches_known_vector() {
        // SHA-256("") = e3b0c442...; SHA-256("abc") = ba7816bf...
        let dir = tempfile::tempdir().unwrap();
        let empty = dir.path().join("empty");
        std::fs::write(&empty, b"").unwrap();
        assert_eq!(
            local_file_sha256_hex(&empty).unwrap(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let abc = dir.path().join("abc");
        std::fs::write(&abc, b"abc").unwrap();
        assert_eq!(
            local_file_sha256_hex(&abc).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn post_deploy_validation_runs_the_exact_quoted_path() -> Result<()> {
        // Must invoke the EXACT path (shell-escaped to $HOME), never the bare
        // PATH-resolved `rch-wkr`.
        let cmd = post_deploy_validation_command(REMOTE_WORKER_BINARY)?;
        assert!(cmd.contains("\"$HOME/.local/bin/rch-wkr\" --version"));
        assert!(cmd.contains("uname -s -m"));
        // Never a bare `rch-wkr --version` (would PATH-resolve to a different
        // binary than the one RCH invokes).
        assert!(!cmd.contains(" rch-wkr --version"));
        Ok(())
    }

    #[test]
    fn classify_post_deploy_marks_exec_format_ineligible() {
        // The exact 6h54q Darwin-controller -> Linux-worker regression: the
        // pushed binary triggers `Exec format error` (exit 126).
        match classify_post_deploy(126, "sh: 1: rch-wkr: Exec format error") {
            PostDeployEligibility::NotEligible { reason_code, .. } => {
                assert_eq!(reason_code, "os_arch_mismatch");
            }
            other => panic!("expected NotEligible(os_arch_mismatch), got {other:?}"),
        }
        // Message without the 126 exit code is still caught.
        assert!(matches!(
            classify_post_deploy(1, "Exec format error"),
            PostDeployEligibility::NotEligible {
                reason_code: "os_arch_mismatch",
                ..
            }
        ));
    }

    #[test]
    fn classify_post_deploy_generic_failure_and_success() {
        assert!(matches!(
            classify_post_deploy(2, "some other error"),
            PostDeployEligibility::NotEligible {
                reason_code: "post_deploy_validation_failed",
                ..
            }
        ));
        assert_eq!(classify_post_deploy(0, ""), PostDeployEligibility::Eligible);
    }

    #[test]
    fn remote_worker_binary_staging_path_never_targets_live_binary() {
        let staging_path = remote_worker_binary_staging_path();

        assert!(staging_path.starts_with("~/.local/bin/.rch-wkr.tmp."));
        assert_ne!(staging_path, REMOTE_WORKER_BINARY);
    }

    // ========================
    // Binary / worker platform guard tests
    // ========================

    fn elf_header(machine: u16, little_endian: bool) -> Vec<u8> {
        let mut h = vec![0u8; BINARY_MAGIC_PROBE_LEN];
        h[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
        h[4] = 2; // EI_CLASS = 64-bit
        h[5] = if little_endian { 1 } else { 2 };
        let bytes = if little_endian {
            machine.to_le_bytes()
        } else {
            machine.to_be_bytes()
        };
        h[18] = bytes[0];
        h[19] = bytes[1];
        h
    }

    fn macho_header(magic: [u8; 4], cputype: u32, little_endian: bool) -> Vec<u8> {
        let mut h = vec![0u8; BINARY_MAGIC_PROBE_LEN];
        h[0..4].copy_from_slice(&magic);
        let bytes = if little_endian {
            cputype.to_le_bytes()
        } else {
            cputype.to_be_bytes()
        };
        h[4..8].copy_from_slice(&bytes);
        h
    }

    #[test]
    fn detect_binary_platform_recognises_linux_elf() {
        let platform = detect_binary_platform(&elf_header(0x3E, true)).unwrap();
        assert_eq!(platform.os, BinaryOs::Linux);
        assert_eq!(platform.arch, Some(BinaryArch::X86_64));

        let aarch = detect_binary_platform(&elf_header(0xB7, true)).unwrap();
        assert_eq!(aarch.arch, Some(BinaryArch::Aarch64));
    }

    #[test]
    fn detect_binary_platform_recognises_macho() {
        // 64-bit little-endian arm64 Mach-O (CF FA ED FE).
        let arm =
            detect_binary_platform(&macho_header([0xCF, 0xFA, 0xED, 0xFE], 0x0100_000C, true))
                .unwrap();
        assert_eq!(arm.os, BinaryOs::MacOs);
        assert_eq!(arm.arch, Some(BinaryArch::Aarch64));

        // 64-bit little-endian x86_64 Mach-O.
        let x86 =
            detect_binary_platform(&macho_header([0xCF, 0xFA, 0xED, 0xFE], 0x0100_0007, true))
                .unwrap();
        assert_eq!(x86.arch, Some(BinaryArch::X86_64));
    }

    #[test]
    fn detect_binary_platform_recognises_fat_macho_as_unknown_arch() {
        let fat = detect_binary_platform(&[0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 2]).unwrap();
        assert_eq!(fat.os, BinaryOs::MacOs);
        assert_eq!(fat.arch, None);
    }

    #[test]
    fn detect_binary_platform_returns_none_for_garbage() {
        assert!(detect_binary_platform(&[0x00, 0x01, 0x02, 0x03]).is_none());
        assert!(detect_binary_platform(&[]).is_none());
    }

    // ========================
    // Target-triple discovery + artifact resolution (bd-...-7.1)
    // ========================

    fn facts(os: BinaryOs, arch: Option<BinaryArch>, libc: LinuxLibc) -> WorkerTargetFacts {
        WorkerTargetFacts {
            platform: BinaryPlatform { os, arch },
            libc,
            remote_user: "ubuntu".to_string(),
            rch_wkr_path: Some("~/.local/bin/rch-wkr".to_string()),
        }
    }

    #[test]
    fn worker_target_triple_linux_defaults_to_musl() {
        // Linux x86_64 with unknown libc => musl (RCH's static release flavor).
        assert_eq!(
            worker_target_triple(&facts(
                BinaryOs::Linux,
                Some(BinaryArch::X86_64),
                LinuxLibc::Unknown
            ))
            .as_deref(),
            Some("x86_64-unknown-linux-musl")
        );
        // Explicit musl.
        assert_eq!(
            worker_target_triple(&facts(
                BinaryOs::Linux,
                Some(BinaryArch::X86_64),
                LinuxLibc::Musl
            ))
            .as_deref(),
            Some("x86_64-unknown-linux-musl")
        );
        // gnu detected.
        assert_eq!(
            worker_target_triple(&facts(
                BinaryOs::Linux,
                Some(BinaryArch::X86_64),
                LinuxLibc::Gnu
            ))
            .as_deref(),
            Some("x86_64-unknown-linux-gnu")
        );
        // aarch64 linux.
        assert_eq!(
            worker_target_triple(&facts(
                BinaryOs::Linux,
                Some(BinaryArch::Aarch64),
                LinuxLibc::Musl
            ))
            .as_deref(),
            Some("aarch64-unknown-linux-musl")
        );
    }

    #[test]
    fn worker_target_triple_macos_and_unsupported() {
        assert_eq!(
            worker_target_triple(&facts(
                BinaryOs::MacOs,
                Some(BinaryArch::Aarch64),
                LinuxLibc::Unknown
            ))
            .as_deref(),
            Some("aarch64-apple-darwin")
        );
        assert_eq!(
            worker_target_triple(&facts(
                BinaryOs::MacOs,
                Some(BinaryArch::X86_64),
                LinuxLibc::Unknown
            ))
            .as_deref(),
            Some("x86_64-apple-darwin")
        );
        // Unknown arch, 32-bit, and Windows are not in the fleet matrix.
        assert!(worker_target_triple(&facts(BinaryOs::Linux, None, LinuxLibc::Musl)).is_none());
        assert!(
            worker_target_triple(&facts(
                BinaryOs::Linux,
                Some(BinaryArch::X86),
                LinuxLibc::Musl
            ))
            .is_none()
        );
        assert!(
            worker_target_triple(&facts(
                BinaryOs::Windows,
                Some(BinaryArch::X86_64),
                LinuxLibc::Unknown
            ))
            .is_none()
        );
    }

    #[test]
    fn resolve_worker_artifact_matches_by_triple_and_name() {
        let artifacts = vec![
            FleetArtifact {
                name: "rch-wkr-v1-x86_64-unknown-linux-musl".to_string(),
                target_triple: "x86_64-unknown-linux-musl".to_string(),
            },
            FleetArtifact {
                name: "rch-wkr-v1-aarch64-apple-darwin".to_string(),
                target_triple: "aarch64-apple-darwin".to_string(),
            },
        ];
        // Exact triple match.
        let got = resolve_worker_artifact("w1", "x86_64-unknown-linux-musl", &artifacts).unwrap();
        assert_eq!(got.target_triple, "x86_64-unknown-linux-musl");
        // Match by name substring when target_triple field differs.
        let by_name = vec![FleetArtifact {
            name: "rch-wkr-aarch64-apple-darwin.tar.gz".to_string(),
            target_triple: "darwin-aarch64".to_string(),
        }];
        assert!(resolve_worker_artifact("w2", "aarch64-apple-darwin", &by_name).is_ok());
    }

    #[test]
    fn resolve_worker_artifact_fails_closed_with_no_match() {
        // The exact 6h54q failure mode: a darwin controller's artifacts only,
        // resolving for a linux worker => fail closed, never reuse a darwin one.
        let darwin_only = vec![FleetArtifact {
            name: "rch-wkr-aarch64-apple-darwin".to_string(),
            target_triple: "aarch64-apple-darwin".to_string(),
        }];
        let err =
            resolve_worker_artifact("linux-worker", "x86_64-unknown-linux-musl", &darwin_only)
                .unwrap_err();
        match err {
            ArtifactResolveError::NoCompatibleArtifact {
                worker_id,
                triple,
                available,
            } => {
                assert_eq!(worker_id, "linux-worker");
                assert_eq!(triple, "x86_64-unknown-linux-musl");
                assert_eq!(available, vec!["aarch64-apple-darwin".to_string()]);
            }
            other => panic!("expected NoCompatibleArtifact, got {other:?}"),
        }
        // Empty artifact set also fails closed.
        assert!(resolve_worker_artifact("w", "x86_64-unknown-linux-musl", &[]).is_err());
    }

    #[test]
    fn parse_worker_platform_normalises_uname() {
        let linux = parse_worker_platform("Linux", "x86_64").unwrap();
        assert_eq!(linux.os, BinaryOs::Linux);
        assert_eq!(linux.arch, Some(BinaryArch::X86_64));

        let mac = parse_worker_platform("Darwin", "arm64").unwrap();
        assert_eq!(mac.os, BinaryOs::MacOs);
        assert_eq!(mac.arch, Some(BinaryArch::Aarch64));

        // amd64 alias and unknown arch degrade gracefully.
        assert_eq!(
            parse_worker_platform("Linux", "amd64").unwrap().arch,
            Some(BinaryArch::X86_64)
        );
        assert_eq!(
            parse_worker_platform("Linux", "riscv64").unwrap().arch,
            None
        );
        assert!(parse_worker_platform("Plan9", "x86_64").is_none());
    }

    #[test]
    fn platforms_compatible_rejects_the_p0_failure_mode() {
        // The exact bug: a macOS/arm64 controller binary pushed onto a
        // linux/amd64 worker.
        let mac_binary = BinaryPlatform {
            os: BinaryOs::MacOs,
            arch: Some(BinaryArch::Aarch64),
        };
        let linux_worker = BinaryPlatform {
            os: BinaryOs::Linux,
            arch: Some(BinaryArch::X86_64),
        };
        assert!(!platforms_compatible(mac_binary, linux_worker));
    }

    #[test]
    fn platforms_compatible_rejects_arch_mismatch_same_os() {
        let arm_linux = BinaryPlatform {
            os: BinaryOs::Linux,
            arch: Some(BinaryArch::Aarch64),
        };
        let x86_linux = BinaryPlatform {
            os: BinaryOs::Linux,
            arch: Some(BinaryArch::X86_64),
        };
        assert!(!platforms_compatible(arm_linux, x86_linux));
    }

    #[test]
    fn platforms_compatible_accepts_exact_match_and_unknown_arch() {
        let x86_linux = BinaryPlatform {
            os: BinaryOs::Linux,
            arch: Some(BinaryArch::X86_64),
        };
        assert!(platforms_compatible(x86_linux, x86_linux));

        // Unknown arch on either side degrades to an OS-only match.
        let unknown_linux = BinaryPlatform {
            os: BinaryOs::Linux,
            arch: None,
        };
        assert!(platforms_compatible(unknown_linux, x86_linux));
        assert!(platforms_compatible(x86_linux, unknown_linux));
    }

    #[test]
    fn read_binary_header_reads_leading_magic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fake-elf");
        std::fs::write(&path, elf_header(0x3E, true)).unwrap();
        let header = read_binary_header(&path).unwrap();
        let platform = detect_binary_platform(&header).unwrap();
        assert_eq!(platform.os, BinaryOs::Linux);
        assert_eq!(platform.arch, Some(BinaryArch::X86_64));
    }

    #[tokio::test]
    async fn ensure_binary_matches_worker_fails_open_on_unreadable_binary() {
        let worker = test_worker_config();
        let missing = PathBuf::from("/nonexistent/path/rch-wkr");
        // Unreadable local binary => fail open (Ok), backstopped by health check.
        assert!(
            ensure_binary_matches_worker(&worker, &missing)
                .await
                .is_ok()
        );
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
