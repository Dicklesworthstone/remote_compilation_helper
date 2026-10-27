//! Worker cache cleanup scheduler.
//!
//! Periodically cleans up old project caches on workers to prevent disk exhaustion.
//! Respects worker busy state and configurable thresholds.

#![allow(dead_code)] // Scaffold code - will be wired into main.rs

use crate::config::CacheCleanupConfig;
use crate::workers::{WorkerPool, WorkerState};
use rch_common::{SshClient, SshOptions, WorkerId, WorkerStatus};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::time::interval;
use tracing::{debug, info, warn};

/// Result of a cleanup operation on a single worker.
#[derive(Debug, Clone)]
pub struct CleanupResult {
    /// Worker that was cleaned.
    pub worker_id: WorkerId,
    /// Whether cleanup was successful.
    pub success: bool,
    /// Number of directories removed (if known).
    pub dirs_removed: Option<u64>,
    /// Bytes freed (if known).
    pub bytes_freed: Option<u64>,
    /// Duration of cleanup operation.
    pub duration: Duration,
    /// Error message if cleanup failed.
    pub error: Option<String>,
}

/// Stats for a cleanup run across all workers.
#[derive(Debug, Default)]
pub struct CleanupStats {
    /// Number of workers checked.
    pub workers_checked: u32,
    /// Number of workers cleaned.
    pub workers_cleaned: u32,
    /// Number of workers skipped (busy or unhealthy).
    pub workers_skipped: u32,
    /// Number of cleanup errors.
    pub errors: u32,
    /// Total bytes freed across all workers.
    pub total_bytes_freed: u64,
    /// Total directories removed.
    pub total_dirs_removed: u64,
}

#[derive(Debug, Clone)]
struct CleanupMetrics {
    removed_dirs: u64,
    freed_bytes: u64,
    free_before_gb: f64,
    free_after_gb: f64,
    low_disk_mode: bool,
    remove_errors: u64,
}

fn cleanup_threshold_kb(min_free_gb: u64) -> u64 {
    min_free_gb.saturating_mul(1024).saturating_mul(1024)
}

/// Where the remote launcher publishes process records (`transfer.rs`).
const REMOTE_RUN_ROOT: &str = "/tmp/rch-run";

#[cfg(test)]
use rch_common::stale_target_reap::RETAINED_SOURCE_GC_GUARD;

/// Refresh real activity after source admission, never using the pre-wait CWD
/// snapshot as authority. Return 0 only for known idle, 1 for observed activity,
/// and 2 for unknown inspection. No scratch file or filesystem mutation here.
const CLEANUP_SOURCE_ACTIVITY_GUARD: &str = r#"
rch_cleanup_process_cwd() {
    # stdin holds this exact proc directory; PID reuse cannot retarget it.
    if rch_process_cwd=$(readlink /proc/self/fd/0/cwd); then
        case "$rch_process_cwd" in "$2"|"$2"/*) return 1;; esac
        return 0
    fi
    if rch_process_state=$(awk '/^State:[[:space:]]/ { print $2; n++ } END { exit n != 1 }' /proc/self/fd/0/status); then
        case "$rch_process_state" in Z|X) return 0;; esac
    else
        if rch_process_identity=$(readlink /proc/self/fd/0) &&
           [ "$rch_process_identity" = "$1 (deleted)" ]; then
            return 0
        fi
    fi
    return 2
}
rch_cleanup_bound_process_cwd() {
    rch_process_opened=0
    if {
        rch_process_opened=1
        rch_cleanup_process_cwd "$1" "$2"
    } < "$1"; then
        return 0
    else
        rch_process_status=$?
    fi
    # A failed directory open never entered the group. Its shell status is
    # not the helper's typed result and cannot prove observed CWD activity.
    if [ "$rch_process_opened" -eq 1 ]; then return "$rch_process_status"; fi
    return 2
}
rch_cleanup_source_activity() {
    if rch_recent_active=$(find "$1" -type f -mmin -"$2" -print -quit); then
        if [ -n "$rch_recent_active" ]; then
            printf 'RCH_CLEANUP_ACTIVITY_HOLD dir=%s reason=recent\n' "$1" >&2
            return 1
        fi
    else
        printf 'RCH_CLEANUP_ACTIVITY_UNKNOWN dir=%s reason=recent\n' "$1" >&2
        return 2
    fi
    if [ ! -d /proc/self/fd ] || [ ! -L /proc/self/cwd ]; then
        printf 'RCH_CLEANUP_ACTIVITY_UNKNOWN dir=%s reason=proc\n' "$1" >&2
        return 2
    fi
    rch_seen_process=0
    for rch_proc_dir in /proc/[0-9]*; do
        [ -d "$rch_proc_dir" ] || continue
        rch_seen_process=1
        if rch_cleanup_bound_process_cwd "$rch_proc_dir" "$1"; then
            :
        else
            rch_process_status=$?
            if [ "$rch_process_status" -eq 1 ]; then
                printf 'RCH_CLEANUP_ACTIVITY_HOLD dir=%s reason=cwd\n' "$1" >&2
                return 1
            fi
            [ -d "$rch_proc_dir" ] || continue
            printf 'RCH_CLEANUP_ACTIVITY_UNKNOWN dir=%s reason=cwds\n' "$1" >&2
            return 2
        fi
    done
    if [ "$rch_seen_process" -eq 0 ]; then
        printf 'RCH_CLEANUP_ACTIVITY_UNKNOWN dir=%s reason=empty-cwds\n' "$1" >&2
        return 2
    fi
    return 0
}
"#;

/// Admit a cleanup candidate under the same durable registry transaction as
/// source admission, then recheck retention before any mutation. Return 0 with
/// the transaction held, 1 for a retained or active candidate, 2 for unavailable
/// ownership or inspection, and 3 if retirement failed (the caller must stop
/// the sweep).
/// Every successful admission requires a checked end after the mutation.
const CLEANUP_SOURCE_TRANSACTION: &str = r#"
rch_cleanup_source_candidate_end() {
    if __gc_source_end; then return 0; fi;
    printf 'RCH_CLEANUP_SOURCE_RETIREMENT_FAILED dir=%s\n' "$1" >&2
    return 1
}
rch_cleanup_source_candidate_begin() {
    if __gc_source_begin "$1"; then
        :
    else
        rch_source_admission_status=$?
        if [ "$rch_source_admission_status" -eq 3 ]; then
            printf 'RCH_CLEANUP_RETENTION_HOLD dir=%s\n' "$1" >&2
            return 1
        fi
        # Removed by someone else while this sweep waited for the registry lock.
        if [ "$rch_source_admission_status" -eq 4 ]; then return 1; fi
        printf 'RCH_CLEANUP_SOURCE_OWNERSHIP_UNAVAILABLE dir=%s\n' "$1" >&2
        return 2
    fi
    if rch_retained_source_gc_hold "$__gc_candidate"; then
        rch_retention_status=0
    else
        rch_retention_status=$?
    fi
    if [ "$rch_retention_status" -eq 1 ]; then
        if rch_cleanup_source_activity "$__gc_candidate" "${2:-5}"; then
            return 0
        else
            rch_activity_status=$?
        fi
        if ! rch_cleanup_source_candidate_end "$1"; then return 3; fi
        if [ "$rch_activity_status" -eq 1 ]; then return 1; fi
        return 2
    fi
    if ! rch_cleanup_source_candidate_end "$1"; then return 3; fi
    if [ "$rch_retention_status" -eq 0 ]; then
        printf 'RCH_CLEANUP_RETENTION_HOLD dir=%s\n' "$1" >&2
        return 1
    fi
    return 2
}
"#;

fn build_cleanup_command(
    escaped_base: &str,
    escaped_run_root: &str,
    max_cache_age_hours: u64,
    min_free_gb: u64,
) -> String {
    build_cleanup_command_with_source_guard(
        escaped_base,
        escaped_run_root,
        max_cache_age_hours,
        min_free_gb,
        placement_low_disk_permille(),
        &rch_common::stale_target_reap::source_claim_gc_guard_fragment(),
    )
}

/// rchd gives a worker zero slots once its free ratio falls to the placement
/// policy's `critical_free_ratio`. Below that line no new build replaces these
/// caches, so an age-only prune can leave a large worker starved with tens of
/// GB free (bd-xxck3: css queue-timed-out ~466 builds/h on 2026-10-13). Low-disk
/// eviction therefore also runs until the filesystem is back above that line
/// with two percentage points of headroom.
pub(crate) fn placement_low_disk_permille() -> u64 {
    let critical = crate::disk_pressure::DiskPressurePolicyConfig::configured().critical_free_ratio;
    ((critical * 1000.0).ceil() as u64).saturating_add(20)
}

/// Whether placement has zeroed this worker for lack of free space. Only the
/// two free-space verdicts count: a saturated-I/O or stale-telemetry critical
/// must not attract a sweep.
fn disk_starved(pressure: &crate::disk_pressure::PressureAssessment) -> bool {
    pressure.state == crate::disk_pressure::PressureState::Critical
        && matches!(
            pressure.reason_code.as_str(),
            "disk_free_below_critical_gb" | "disk_ratio_below_critical"
        )
}

fn build_cleanup_command_with_source_guard(
    escaped_base: &str,
    escaped_run_root: &str,
    max_cache_age_hours: u64,
    min_free_gb: u64,
    low_disk_permille: u64,
    source_guard: &str,
) -> String {
    let max_age_minutes = max_cache_age_hours.saturating_mul(60);
    let threshold_kb = cleanup_threshold_kb(min_free_gb);
    let active_grace_minutes = 5_u64;
    // Worker-side orphan watchdog: a job whose process record is older than
    // this and whose recorded leader is still alive escaped the in-session
    // watchdog (ssh drop or daemon restart). 240 min is far above any
    // legitimate test cap (default 30 min). The shared identity helpers bind
    // the group to worker boot and leader start time, so a reused pgid never
    // matches. A record whose group is gone, whose leader no longer matches,
    // or which is malformed can authorize nothing and is deleted; a failed
    // process observation keeps it for the next cycle.
    let orphan_after_minutes = 240_u64;
    // Run directories hold only records; an empty one untouched for a day is
    // garbage. A launch racing its removal fails typed setup and fails over.
    let empty_run_dir_minutes = 1440_u64;
    format!(
        "set -u; \
         base={base}; \
         max_age_minutes={max_age_minutes}; \
         threshold_kb={threshold_kb}; \
         low_disk_permille={low_disk_permille}; \
         active_grace_minutes={active_grace_minutes}; \
         orphan_after_minutes={orphan_after_minutes}; \
         if [ ! -d \"$base\" ]; then mkdir -p \"$base\"; fi; \
         if physical=$(cd \"$base\" 2>/dev/null && pwd -P); then base=$physical; fi; \
         total_kb=$(df -Pk \"$base\" 2>/dev/null | awk 'NR==2 {{print $2}}'); \
         case \"$total_kb\" in ''|*[!0-9]*) total_kb=0 ;; esac; \
         ratio_kb=$((total_kb / 1000 * low_disk_permille)); \
         if [ \"$ratio_kb\" -gt \"$threshold_kb\" ]; then threshold_kb=$ratio_kb; fi; \
         before_kb=$(df -Pk \"$base\" 2>/dev/null | awk 'NR==2 {{print $4}}'); \
         if [ -z \"$before_kb\" ]; then before_kb=0; fi; \
         removed=0; freed_kb=0; low_disk=0; remove_errors=0; orphans_killed=0; \
         if [ \"$before_kb\" -lt \"$threshold_kb\" ]; then low_disk=1; fi; \
         run_root={run_root}; \
         if [ -d \"$run_root\" ]; then \
           tally=$(mktemp /tmp/rch-cleanup.XXXXXX); \
           (set -- \"$run_root\"/*/*.pgid\n{identity}\n killed=0; \
             for pgf in \"$@\"; do \
               [ -f \"$pgf\" ] && [ ! -L \"$pgf\" ] || continue; \
               [ -n \"$(find \"$pgf\" -mmin +\"$orphan_after_minutes\" -print 2>/dev/null)\" ] || continue; \
               build=${{pgf##*/}}; build=${{build%.pgid}}; verdict=stale; \
               if rch_read_record \"$pgf\" \"$build\"; then \
                 rch_group_state; \
                 case $? in \
                   0) ;; \
                   1) if rch_signal_group KILL; then verdict=killed; fi ;; \
                   *) verdict=unknown ;; \
                 esac; \
               fi; \
               case $verdict in \
                 stale) rm -f -- \"$pgf\" 2>/dev/null ;; \
                 killed) killed=$((killed + 1)) ;; \
               esac; \
             done; \
             echo \"$killed\") > \"$tally\" 2>/dev/null; \
           orphans_killed=$(cat \"$tally\" 2>/dev/null); rm -f \"$tally\"; \
           case \"$orphans_killed\" in ''|*[!0-9]*) orphans_killed=0 ;; esac; \
           find \"$run_root\" -mindepth 1 -maxdepth 1 -type d -empty -mmin +{empty_run_dir_minutes} -exec rmdir -- {{}} + 2>/dev/null || :; \
         fi; \
         {source_guard}\n\
         {activity_guard}\n\
         {source_transaction}\n\
         candidates=$(mktemp /tmp/rch-cleanup.XXXXXX); \
         if [ \"$low_disk\" -eq 1 ]; then \
           {{ \
             if find \"$base\" -maxdepth 0 -printf '' >/dev/null 2>&1; then \
               find \"$base\" -mindepth 2 -maxdepth 2 -type d ! -path \"$base/offroot/*\" -printf '%T@ %p\\n' 2>/dev/null; \
               if [ -d \"$base/offroot\" ]; then \
                 find \"$base/offroot\" -mindepth 2 -maxdepth 2 -type d -printf '%T@ %p\\n' 2>/dev/null; \
               fi; \
             else \
               find \"$base\" -mindepth 2 -maxdepth 2 -type d ! -path \"$base/offroot/*\" -exec stat -f '%m %N' {{}} + 2>/dev/null; \
               if [ -d \"$base/offroot\" ]; then \
                 find \"$base/offroot\" -mindepth 2 -maxdepth 2 -type d -exec stat -f '%m %N' {{}} + 2>/dev/null; \
               fi; \
             fi; \
           }} | sort -n | sed 's/^[^ ]* //' > \"$candidates\"; \
         else \
           find \"$base\" -mindepth 2 -maxdepth 2 -type d ! -path \"$base/offroot/*\" -mmin +\"$max_age_minutes\" -print 2>/dev/null > \"$candidates\"; \
           if [ -d \"$base/offroot\" ]; then \
             find \"$base/offroot\" -mindepth 2 -maxdepth 2 -type d -mmin +\"$max_age_minutes\" -print 2>/dev/null >> \"$candidates\"; \
           fi; \
         fi; \
         while IFS= read -r dir; do \
           [ -z \"$dir\" ] && continue; \
           [ ! -d \"$dir\" ] && continue; \
           case \"$dir\" in \"$base\"/*) ;; *) continue ;; esac; \
           if rch_retained_source_gc_hold \"$dir\"; then \
             printf 'RCH_CLEANUP_RETENTION_HOLD dir=%s\\n' \"$dir\" >&2; continue; \
           else \
             rch_retention_status=$?; \
           fi; \
           if [ \"$rch_retention_status\" -ne 1 ]; then \
             remove_errors=$((remove_errors + 1)); continue; \
           fi; \
           if recent_active=$(find \"$dir\" -type f -mmin -\"$active_grace_minutes\" -print -quit); then \
             :; \
           else \
             remove_errors=$((remove_errors + 1)); \
             printf 'RCH_CLEANUP_ACTIVITY_UNKNOWN dir=%s reason=recent\\n' \"$dir\" >&2; continue; \
           fi; \
           if [ -n \"$recent_active\" ]; then continue; fi; \
           if rch_cleanup_source_candidate_begin \"$dir\" \"$active_grace_minutes\"; then \
             :; \
           else \
             rch_source_status=$?; \
             if [ \"$rch_source_status\" -eq 1 ]; then continue; fi; \
             remove_errors=$((remove_errors + 1)); \
             if [ \"$rch_source_status\" -eq 3 ]; then break; fi; \
             continue; \
           fi; \
           dir=$__gc_candidate; \
           size_kb=$(du -sk \"$dir\" 2>/dev/null | awk '{{print $1}}'); \
           if [ -z \"$size_kb\" ]; then size_kb=0; fi; \
         if rm -rf \"$dir\" 2>/dev/null; then \
           removed=$((removed + 1)); \
           freed_kb=$((freed_kb + size_kb)); \
         elif [ ! -d \"$dir\" ]; then \
           removed=$((removed + 1)); \
           freed_kb=$((freed_kb + size_kb)); \
         elif [ -z \"$(find \"$dir\" -mindepth 1 -print -quit 2>/dev/null)\" ]; then \
           if rmdir \"$dir\" 2>/dev/null; then \
             removed=$((removed + 1)); \
             freed_kb=$((freed_kb + size_kb)); \
             printf 'RCH_CLEANUP_HUSK_REAPED dir=%s\\n' \"$dir\" >&2; \
           else \
             remove_errors=$((remove_errors + 1)); \
             printf 'RCH_CLEANUP_RM_FAILURE dir=%s kb=%s\\n' \"$dir\" \"$size_kb\" >&2; \
           fi; \
         else \
           remove_errors=$((remove_errors + 1)); \
           printf 'RCH_CLEANUP_RM_FAILURE dir=%s kb=%s\\n' \"$dir\" \"$size_kb\" >&2; \
         fi; \
           if ! rch_cleanup_source_candidate_end \"$dir\"; then \
             remove_errors=$((remove_errors + 1)); break; \
           fi; \
           if [ \"$low_disk\" -eq 1 ]; then \
             current_kb=$(df -Pk \"$base\" 2>/dev/null | awk 'NR==2 {{print $4}}'); \
             if [ -n \"$current_kb\" ] && [ \"$current_kb\" -ge \"$threshold_kb\" ]; then break; fi; \
           fi; \
         done < \"$candidates\"; \
         rm -f \"$candidates\"; \
         if [ -d \"$base/offroot\" ]; then \
           find \"$base/offroot\" -mindepth 1 -maxdepth 1 -type d -empty -exec rmdir -- {{}} + 2>/dev/null || :; \
         fi; \
         after_kb=$(df -Pk \"$base\" 2>/dev/null | awk 'NR==2 {{print $4}}'); \
         if [ -z \"$after_kb\" ]; then after_kb=0; fi; \
         printf 'RCH_CLEANUP_METRICS removed=%s freed_kb=%s before_kb=%s after_kb=%s low_disk=%s remove_errors=%s orphans_killed=%s\\n' \"$removed\" \"$freed_kb\" \"$before_kb\" \"$after_kb\" \"$low_disk\" \"$remove_errors\" \"$orphans_killed\"; \
         if [ \"$remove_errors\" -gt 0 ]; then exit 1; fi",
        base = escaped_base,
        run_root = escaped_run_root,
        max_age_minutes = max_age_minutes,
        threshold_kb = threshold_kb,
        low_disk_permille = low_disk_permille,
        active_grace_minutes = active_grace_minutes,
        orphan_after_minutes = orphan_after_minutes,
        empty_run_dir_minutes = empty_run_dir_minutes,
        identity = rch_common::REMOTE_PROCESS_IDENTITY_SCRIPT,
        activity_guard = CLEANUP_SOURCE_ACTIVITY_GUARD,
        source_guard = source_guard,
        source_transaction = CLEANUP_SOURCE_TRANSACTION,
    )
}

fn parse_cleanup_metrics(stdout: &str) -> Option<CleanupMetrics> {
    let line = stdout
        .lines()
        .find(|line| line.contains("RCH_CLEANUP_METRICS"))?;

    let mut removed_dirs = None;
    let mut freed_kb = None;
    let mut before_kb = None;
    let mut after_kb = None;
    let mut low_disk = None;
    let mut remove_errors = None;

    for token in line.split_whitespace().skip(1) {
        let Some((key, value)) = token.split_once('=') else {
            continue;
        };
        match key {
            "removed" => removed_dirs = value.parse::<u64>().ok(),
            "freed_kb" => freed_kb = value.parse::<u64>().ok(),
            "before_kb" => before_kb = value.parse::<u64>().ok(),
            "after_kb" => after_kb = value.parse::<u64>().ok(),
            "low_disk" => low_disk = Some(value == "1"),
            "remove_errors" => remove_errors = value.parse::<u64>().ok(),
            _ => {}
        }
    }

    Some(CleanupMetrics {
        removed_dirs: removed_dirs.unwrap_or(0),
        freed_bytes: freed_kb.unwrap_or(0).saturating_mul(1024),
        free_before_gb: before_kb.unwrap_or(0) as f64 / (1024.0 * 1024.0),
        free_after_gb: after_kb.unwrap_or(0) as f64 / (1024.0 * 1024.0),
        low_disk_mode: low_disk.unwrap_or(false),
        remove_errors: remove_errors.unwrap_or(0),
    })
}

/// Cache cleanup scheduler service.
pub struct CacheCleanupScheduler {
    /// Worker pool reference.
    pool: WorkerPool,
    /// Configuration.
    config: CacheCleanupConfig,
    /// Last cleanup time per worker.
    last_cleanup: Arc<RwLock<HashMap<WorkerId, Instant>>>,
    /// First observed idle instant per worker (used for idle-threshold gating).
    idle_since: Arc<RwLock<HashMap<WorkerId, Instant>>>,
    /// SSH options for cleanup commands (throwaway fallback path).
    ssh_options: SshOptions,
    /// Shared SSH connection pool. When `Some`, cleanup commands run over a warm
    /// reused ControlMaster; when `None`, the legacy throwaway path is used.
    ssh_pool: Option<Arc<rch_common::SshPool>>,
}

impl CacheCleanupScheduler {
    /// Create a new cache cleanup scheduler.
    pub fn new(pool: WorkerPool, config: CacheCleanupConfig) -> Self {
        Self {
            pool,
            config,
            last_cleanup: Arc::new(RwLock::new(HashMap::new())),
            idle_since: Arc::new(RwLock::new(HashMap::new())),
            ssh_options: SshOptions::default(),
            ssh_pool: None,
        }
    }

    /// Attach a shared SSH connection pool for warm ControlMaster reuse.
    #[must_use]
    pub fn with_ssh_pool(mut self, pool: Option<Arc<rch_common::SshPool>>) -> Self {
        self.ssh_pool = pool;
        self
    }

    /// Run one remote command against a worker, using the shared pool (warm
    /// master reuse) when configured, otherwise a throwaway SSH session.
    async fn run_remote(
        &self,
        config: &rch_common::WorkerConfig,
        command: &str,
    ) -> anyhow::Result<rch_common::CommandResult> {
        if let Some(pool) = &self.ssh_pool {
            return pool
                .run_with_timeout(config, command, self.ssh_options.command_timeout)
                .await;
        }
        let mut ssh_client = SshClient::new(config.clone(), self.ssh_options.clone());
        ssh_client.connect().await?;
        let result = ssh_client.execute(command).await;
        let _ = ssh_client.disconnect().await;
        result
    }

    /// Start the cleanup scheduler.
    ///
    /// Returns a handle to the spawned task.
    pub fn start(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        let scheduler = self;
        tokio::spawn(async move {
            if !scheduler.config.enabled {
                info!("Cache cleanup scheduler disabled");
                return;
            }

            info!(
                "Cache cleanup scheduler started (interval={}s, max_age={}h, min_free={}GB)",
                scheduler.config.interval_secs,
                scheduler.config.max_cache_age_hours,
                scheduler.config.min_free_gb
            );

            let mut ticker = interval(Duration::from_secs(scheduler.config.interval_secs));
            loop {
                ticker.tick().await;
                let stats = scheduler.run_cleanup_cycle().await;
                if stats.workers_cleaned > 0 || stats.errors > 0 {
                    info!(
                        "Cache cleanup cycle: checked={}, cleaned={}, skipped={}, errors={}, freed={}MB",
                        stats.workers_checked,
                        stats.workers_cleaned,
                        stats.workers_skipped,
                        stats.errors,
                        stats.total_bytes_freed / (1024 * 1024)
                    );
                } else {
                    debug!("Cache cleanup cycle: no action needed");
                }
            }
        })
    }

    /// Run a single cleanup cycle across all workers.
    async fn run_cleanup_cycle(&self) -> CleanupStats {
        let mut stats = CleanupStats::default();
        let workers = self.pool.all_workers().await;

        for worker_state in workers {
            stats.workers_checked += 1;
            let worker_id = worker_state.config.read().await.id.clone();

            // Check if worker is eligible for cleanup
            if !self.is_worker_eligible(&worker_state).await {
                debug!("Worker {} not eligible for cleanup", worker_id);
                stats.workers_skipped += 1;
                continue;
            }

            // Perform cleanup
            match self.cleanup_worker(&worker_state).await {
                Ok(result) => {
                    if result.success {
                        stats.workers_cleaned += 1;
                        if let Some(bytes) = result.bytes_freed {
                            stats.total_bytes_freed += bytes;
                        }
                        if let Some(dirs) = result.dirs_removed {
                            stats.total_dirs_removed += dirs;
                        }
                    } else {
                        stats.errors += 1;
                    }
                }
                Err(e) => {
                    warn!("Failed to cleanup worker {}: {}", worker_id, e);
                    stats.errors += 1;
                }
            }
        }

        stats
    }

    /// Check if a worker is eligible for cleanup.
    async fn is_worker_eligible(&self, worker_state: &WorkerState) -> bool {
        let worker_id = worker_state.config.read().await.id.clone();

        // Check worker status
        let status = worker_state.status().await;
        if status != WorkerStatus::Healthy {
            debug!(
                "Worker {:?} not healthy (status={:?}), skipping cleanup",
                worker_id, status
            );
            self.idle_since.write().await.remove(&worker_id);
            return false;
        }

        // Placement gives a worker no new builds once it is critically short
        // of free space, but the builds it already runs can hold slots for
        // hours, and a ghost reservation holds one indefinitely. Requiring an
        // idle worker then keeps the sweep away from exactly the workers
        // that need it (2026-10-13: css swept three idle workers and skipped
        // every starved one). The script protects live trees itself (recent
        // activity, retention holds, the source registry), so a starved
        // worker is swept while it drains.
        let disk_starved = disk_starved(&worker_state.pressure_assessment().await);

        // Check if worker is busy (has active slots)
        let used_slots = worker_state.used_slots();
        if used_slots != 0 && !disk_starved {
            debug!(
                "Worker {} is busy ({} slots reserved), skipping cleanup",
                worker_id, used_slots
            );
            self.idle_since.write().await.remove(&worker_id);
            return false;
        }

        // Enforce idle threshold before cleanup.
        let idle_threshold = Duration::from_secs(self.config.idle_threshold_secs);
        if !idle_threshold.is_zero() && !disk_starved {
            let now = Instant::now();
            let idle_for = {
                let mut idle_since = self.idle_since.write().await;
                let first_idle = idle_since.entry(worker_id.clone()).or_insert(now);
                now.saturating_duration_since(*first_idle)
            };
            if idle_for < idle_threshold {
                debug!(
                    "Worker {} idle for {:?} (threshold {:?}), skipping cleanup",
                    worker_id, idle_for, idle_threshold
                );
                return false;
            }
        }

        // Check circuit breaker state
        let circuit_state = worker_state.circuit_state().await;
        if circuit_state != Some(rch_common::CircuitState::Closed) {
            debug!(
                "Worker {} circuit not closed ({:?}), skipping cleanup",
                worker_id, circuit_state
            );
            return false;
        }

        true
    }

    /// Perform cleanup on a single worker.
    async fn cleanup_worker(&self, worker_state: &WorkerState) -> anyhow::Result<CleanupResult> {
        let start = Instant::now();
        let config = worker_state.config.read().await.clone();

        info!(
            "Starting cache cleanup on worker {} (max_age={}h, min_free={}GB)",
            config.id, self.config.max_cache_age_hours, self.config.min_free_gb
        );

        // Build cleanup command:
        // - baseline prune by age
        // - when below disk threshold, escalate and prune oldest caches until threshold is met
        let remote_base = &self.config.remote_base;
        let escaped_base = rch_common::ssh_utils::shell_escape_path_with_home(remote_base)
            .ok_or_else(|| anyhow::anyhow!("Invalid remote_base: contains control characters"))?;
        let cleanup_script = build_cleanup_command(
            escaped_base.as_ref(),
            REMOTE_RUN_ROOT,
            self.config.max_cache_age_hours,
            self.config.min_free_gb,
        );
        // The worker's login shell may be zsh, which neither word-splits nor
        // tolerates unmatched globs the way the POSIX script expects.
        let cleanup_cmd = format!("sh -c {}", shell_escape::escape(cleanup_script.into()));

        // Execute cleanup via SSH (pooled warm master when available).
        let result = self.run_remote(&config, &cleanup_cmd).await?;

        // Update last cleanup time
        {
            let mut last_cleanup = self.last_cleanup.write().await;
            last_cleanup.insert(config.id.clone(), Instant::now());
        }

        let duration = start.elapsed();
        let metrics = parse_cleanup_metrics(&result.stdout);
        let metrics_summary = metrics
            .as_ref()
            .map(|m| {
                format!(
                    "removed={}, freed_mb={}, before_free_gb={:.2}, after_free_gb={:.2}, low_disk={}, remove_errors={}",
                    m.removed_dirs,
                    m.freed_bytes / (1024 * 1024),
                    m.free_before_gb,
                    m.free_after_gb,
                    m.low_disk_mode,
                    m.remove_errors
                )
            })
            .unwrap_or_else(|| "metrics=unavailable".to_string());

        if result.exit_code == 0 {
            info!(
                "Cache cleanup completed on worker {} in {:?} ({})",
                config.id, duration, metrics_summary
            );
            if let Some(ref parsed) = metrics
                && parsed.free_after_gb < self.config.min_free_gb as f64
            {
                warn!(
                    "Worker {} still below free-space threshold after cleanup: {:.2}GB < {}GB",
                    config.id, parsed.free_after_gb, self.config.min_free_gb
                );
            }
            Ok(CleanupResult {
                worker_id: config.id,
                success: true,
                dirs_removed: metrics.as_ref().map(|m| m.removed_dirs),
                bytes_freed: metrics.as_ref().map(|m| m.freed_bytes),
                duration,
                error: None,
            })
        } else {
            let error_msg = format!(
                "Cleanup command failed with exit code {} ({}, stderr: {})",
                result.exit_code,
                metrics_summary,
                result.stderr.trim()
            );
            warn!(
                "Cache cleanup failed on worker {}: {}",
                config.id, error_msg
            );
            Ok(CleanupResult {
                worker_id: config.id,
                success: false,
                dirs_removed: None,
                bytes_freed: None,
                duration,
                error: Some(error_msg),
            })
        }
    }

    /// Trigger immediate cleanup on a specific worker.
    pub async fn cleanup_worker_now(&self, worker_id: &WorkerId) -> anyhow::Result<CleanupResult> {
        let worker_state = self
            .pool
            .get(worker_id)
            .await
            .ok_or_else(|| anyhow::anyhow!("Worker {} not found", worker_id))?;

        self.cleanup_worker(&worker_state).await
    }

    /// Get cleanup status for all workers.
    pub async fn get_status(&self) -> HashMap<WorkerId, Option<Instant>> {
        let last_cleanup = self.last_cleanup.read().await;
        let workers = self.pool.all_workers().await;

        let mut status = HashMap::new();
        for worker in workers {
            let id = worker.config.read().await.id.clone();
            let last = last_cleanup.get(&id).copied();
            status.insert(id, last);
        }
        status
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rch_common::test_guard;
    use rch_common::{CircuitState, WorkerConfig};

    #[test]
    fn test_cleanup_config_defaults() {
        let _guard = test_guard!();
        let config = CacheCleanupConfig::default();
        assert!(config.enabled);
        assert_eq!(config.interval_secs, 3600);
        assert_eq!(config.max_cache_age_hours, 72);
        assert_eq!(config.min_free_gb, 10);
        assert_eq!(config.idle_threshold_secs, 60);
        assert_eq!(config.remote_base, "/data/tmp/rch");
    }

    #[test]
    fn test_cleanup_stats_default() {
        let _guard = test_guard!();
        let stats = CleanupStats::default();
        assert_eq!(stats.workers_checked, 0);
        assert_eq!(stats.workers_cleaned, 0);
        assert_eq!(stats.workers_skipped, 0);
        assert_eq!(stats.errors, 0);
        assert_eq!(stats.total_bytes_freed, 0);
    }

    #[test]
    fn test_cleanup_result_creation() {
        let _guard = test_guard!();
        let result = CleanupResult {
            worker_id: WorkerId::new("test-worker"),
            success: true,
            dirs_removed: Some(5),
            bytes_freed: Some(1024 * 1024 * 100),
            duration: Duration::from_secs(2),
            error: None,
        };

        assert!(result.success);
        assert_eq!(result.dirs_removed, Some(5));
        assert_eq!(result.bytes_freed, Some(104857600));
    }

    #[test]
    fn test_cleanup_result_failure() {
        let _guard = test_guard!();
        let result = CleanupResult {
            worker_id: WorkerId::new("failing-worker"),
            success: false,
            dirs_removed: None,
            bytes_freed: None,
            duration: Duration::from_millis(500),
            error: Some("SSH connection failed".to_string()),
        };

        assert!(!result.success);
        assert!(result.dirs_removed.is_none());
        assert!(result.bytes_freed.is_none());
        assert_eq!(result.error, Some("SSH connection failed".to_string()));
        assert_eq!(result.duration.as_millis(), 500);
    }

    #[test]
    fn test_cleanup_result_partial_info() {
        let _guard = test_guard!();
        // Result where we got some info but not all
        let result = CleanupResult {
            worker_id: WorkerId::new("partial-worker"),
            success: true,
            dirs_removed: Some(10),
            bytes_freed: None, // couldn't determine bytes
            duration: Duration::from_secs(5),
            error: None,
        };

        assert!(result.success);
        assert_eq!(result.dirs_removed, Some(10));
        assert!(result.bytes_freed.is_none());
    }

    #[test]
    fn test_cleanup_result_debug_format() {
        let _guard = test_guard!();
        let result = CleanupResult {
            worker_id: WorkerId::new("debug-worker"),
            success: true,
            dirs_removed: Some(3),
            bytes_freed: Some(1024),
            duration: Duration::from_millis(100),
            error: None,
        };

        let debug_str = format!("{:?}", result);
        assert!(debug_str.contains("debug-worker"));
        assert!(debug_str.contains("success: true"));
    }

    #[test]
    fn test_cleanup_result_clone() {
        let _guard = test_guard!();
        let result = CleanupResult {
            worker_id: WorkerId::new("clone-worker"),
            success: true,
            dirs_removed: Some(7),
            bytes_freed: Some(2048),
            duration: Duration::from_secs(1),
            error: None,
        };

        let cloned = result.clone();
        assert_eq!(cloned.worker_id, result.worker_id);
        assert_eq!(cloned.success, result.success);
        assert_eq!(cloned.dirs_removed, result.dirs_removed);
        assert_eq!(cloned.bytes_freed, result.bytes_freed);
    }

    #[test]
    fn test_cleanup_stats_accumulation() {
        let _guard = test_guard!();
        let mut stats = CleanupStats::default();

        // Simulate checking workers
        stats.workers_checked += 3;
        stats.workers_cleaned += 2;
        stats.workers_skipped += 1;
        stats.total_bytes_freed = 1024 * 1024 * 500; // 500MB
        stats.total_dirs_removed = 15;

        assert_eq!(stats.workers_checked, 3);
        assert_eq!(stats.workers_cleaned, 2);
        assert_eq!(stats.workers_skipped, 1);
        assert_eq!(stats.total_bytes_freed, 524288000);
        assert_eq!(stats.total_dirs_removed, 15);
    }

    #[test]
    fn test_cleanup_stats_with_errors() {
        let _guard = test_guard!();
        let stats = CleanupStats {
            workers_checked: 5,
            workers_cleaned: 2,
            workers_skipped: 1,
            errors: 2,
            ..Default::default()
        };

        assert_eq!(
            stats.workers_checked,
            stats.workers_cleaned + stats.workers_skipped + stats.errors
        );
    }

    #[test]
    fn test_cleanup_stats_debug_format() {
        let _guard = test_guard!();
        let stats = CleanupStats {
            workers_checked: 10,
            workers_cleaned: 8,
            workers_skipped: 1,
            errors: 1,
            total_bytes_freed: 1_000_000_000,
            total_dirs_removed: 50,
        };

        let debug_str = format!("{:?}", stats);
        assert!(debug_str.contains("workers_checked: 10"));
        assert!(debug_str.contains("workers_cleaned: 8"));
    }

    fn create_test_worker_config(id: &str) -> WorkerConfig {
        WorkerConfig {
            id: WorkerId::new(id),
            host: "test.example.com".to_string(),
            user: "testuser".to_string(),
            identity_file: "/home/test/.ssh/id_rsa".to_string(),
            total_slots: 8,
            priority: 50,
            tags: vec![],
            tools: Vec::new(),
        }
    }

    #[tokio::test]
    async fn test_worker_state_status_healthy() {
        let config = create_test_worker_config("healthy-worker");
        let worker_state = WorkerState::new(config);

        let status = worker_state.status().await;
        assert_eq!(status, WorkerStatus::Healthy);
    }

    #[tokio::test]
    async fn test_worker_state_status_changes() {
        let config = create_test_worker_config("status-worker");
        let worker_state = WorkerState::new(config);

        // Initially healthy
        assert_eq!(worker_state.status().await, WorkerStatus::Healthy);

        // Set to draining
        worker_state.set_status(WorkerStatus::Draining).await;
        assert_eq!(worker_state.status().await, WorkerStatus::Draining);

        // Set to unreachable
        worker_state.set_status(WorkerStatus::Unreachable).await;
        assert_eq!(worker_state.status().await, WorkerStatus::Unreachable);
    }

    #[tokio::test]
    async fn test_worker_state_slots_availability() {
        let config = create_test_worker_config("slots-worker");
        let worker_state = WorkerState::new(config);

        // All slots available initially
        assert_eq!(worker_state.available_slots().await, 8);

        // Reserve some slots
        let reserved = worker_state.reserve_slots(3).await;
        assert!(reserved);
        assert_eq!(worker_state.available_slots().await, 5);

        // Release slots
        worker_state.release_slots(2).await;
        assert_eq!(worker_state.available_slots().await, 7);
    }

    #[tokio::test]
    async fn test_worker_state_circuit_state() {
        let config = create_test_worker_config("circuit-worker");
        let worker_state = WorkerState::new(config);

        // Circuit starts closed
        let circuit = worker_state.circuit_state().await;
        assert_eq!(circuit, Some(CircuitState::Closed));

        // Open circuit
        worker_state.open_circuit().await;
        assert_eq!(worker_state.circuit_state().await, Some(CircuitState::Open));

        // Half-open
        worker_state.half_open_circuit().await;
        assert_eq!(
            worker_state.circuit_state().await,
            Some(CircuitState::HalfOpen)
        );

        // Close again
        worker_state.close_circuit().await;
        assert_eq!(
            worker_state.circuit_state().await,
            Some(CircuitState::Closed)
        );
    }

    #[tokio::test]
    async fn test_cleanup_scheduler_creation() {
        let pool = WorkerPool::new();
        let config = CacheCleanupConfig::default();

        let scheduler = CacheCleanupScheduler::new(pool, config);

        // Verify config is stored
        assert!(scheduler.config.enabled);
        assert_eq!(scheduler.config.interval_secs, 3600);
    }

    #[tokio::test]
    async fn test_cleanup_scheduler_disabled_config() {
        let pool = WorkerPool::new();
        let config = CacheCleanupConfig {
            enabled: false,
            ..Default::default()
        };

        let scheduler = CacheCleanupScheduler::new(pool, config);
        assert!(!scheduler.config.enabled);
    }

    #[tokio::test]
    async fn test_cleanup_scheduler_custom_config() {
        let pool = WorkerPool::new();
        let config = CacheCleanupConfig {
            enabled: true,
            interval_secs: 1800, // 30 minutes
            max_cache_age_hours: 24,
            min_free_gb: 20,
            idle_threshold_secs: 120,
            remote_base: "/var/rch/cache".to_string(),
        };

        let scheduler = CacheCleanupScheduler::new(pool, config);

        assert!(scheduler.config.enabled);
        assert_eq!(scheduler.config.interval_secs, 1800);
        assert_eq!(scheduler.config.max_cache_age_hours, 24);
        assert_eq!(scheduler.config.min_free_gb, 20);
        assert_eq!(scheduler.config.remote_base, "/var/rch/cache");
    }

    #[tokio::test]
    async fn test_cleanup_scheduler_get_status_empty() {
        let pool = WorkerPool::new();
        let config = CacheCleanupConfig::default();

        let scheduler = CacheCleanupScheduler::new(pool, config);
        let status = scheduler.get_status().await;

        assert!(status.is_empty());
    }

    #[tokio::test]
    async fn test_cleanup_scheduler_get_status_with_workers() {
        let pool = WorkerPool::new();
        let config1 = create_test_worker_config("worker1");
        let config2 = create_test_worker_config("worker2");

        pool.add_worker(config1).await;
        pool.add_worker(config2).await;

        let cleanup_config = CacheCleanupConfig::default();
        let scheduler = CacheCleanupScheduler::new(pool, cleanup_config);
        let status = scheduler.get_status().await;

        assert_eq!(status.len(), 2);
        // No cleanups yet, so all values should be None
        for (_, last_cleanup) in status {
            assert!(last_cleanup.is_none());
        }
    }

    #[tokio::test]
    async fn test_is_worker_eligible_healthy_idle() {
        let pool = WorkerPool::new();
        let config = create_test_worker_config("eligible-worker");
        pool.add_worker(config).await;

        let cleanup_config = CacheCleanupConfig {
            idle_threshold_secs: 0,
            ..Default::default()
        };
        let scheduler = CacheCleanupScheduler::new(pool.clone(), cleanup_config);

        let worker_state = pool.get(&WorkerId::new("eligible-worker")).await.unwrap();

        // Worker is healthy, all slots available, circuit closed
        let eligible = scheduler.is_worker_eligible(&worker_state).await;
        assert!(eligible);
    }

    #[tokio::test]
    async fn test_is_worker_eligible_respects_idle_threshold() {
        let pool = WorkerPool::new();
        let config = create_test_worker_config("idle-threshold-worker");
        pool.add_worker(config).await;

        let cleanup_config = CacheCleanupConfig {
            idle_threshold_secs: 60,
            ..Default::default()
        };
        let scheduler = CacheCleanupScheduler::new(pool.clone(), cleanup_config);
        let worker_state = pool
            .get(&WorkerId::new("idle-threshold-worker"))
            .await
            .unwrap();

        let eligible_first = scheduler.is_worker_eligible(&worker_state).await;
        assert!(!eligible_first);

        {
            let mut idle_since = scheduler.idle_since.write().await;
            idle_since.insert(
                WorkerId::new("idle-threshold-worker"),
                Instant::now() - Duration::from_secs(120),
            );
        }

        let eligible_after_threshold = scheduler.is_worker_eligible(&worker_state).await;
        assert!(eligible_after_threshold);
    }

    #[tokio::test]
    async fn test_disk_slots_idle_worker_remains_eligible_for_cleanup() {
        let pool = WorkerPool::new();
        pool.add_worker(create_test_worker_config("disk-cleanup"))
            .await;
        let worker = pool.get(&WorkerId::new("disk-cleanup")).await.unwrap();
        let scheduler = CacheCleanupScheduler::new(
            pool,
            CacheCleanupConfig {
                idle_threshold_secs: 0,
                ..Default::default()
            },
        );
        assert!(worker.reserve_slots(2).await);
        for free_gb in [40.0, 10.0] {
            worker
                .set_pressure_assessment(crate::disk_pressure::PressureAssessment {
                    disk_free_gb: Some(free_gb),
                    ..Default::default()
                })
                .await;
            assert!(!scheduler.is_worker_eligible(&worker).await);
        }
        worker.release_slots(2).await;
        assert_eq!(worker.available_slots().await, 0);
        assert!(scheduler.is_worker_eligible(&worker).await);
        worker
            .set_pressure_assessment(crate::disk_pressure::PressureAssessment {
                disk_free_gb: Some(40.0),
                ..Default::default()
            })
            .await;
        assert_eq!(worker.available_slots().await, 3);
        assert!(scheduler.is_worker_eligible(&worker).await);
    }

    #[tokio::test]
    async fn test_disk_starved_worker_is_swept_while_its_builds_drain() {
        use crate::disk_pressure::{PressureAssessment, PressureState};
        let pool = WorkerPool::new();
        pool.add_worker(create_test_worker_config("starved")).await;
        let worker = pool.get(&WorkerId::new("starved")).await.unwrap();
        // The default idle threshold: a busy worker never satisfies it.
        let scheduler = CacheCleanupScheduler::new(pool, CacheCleanupConfig::default());
        assert!(worker.reserve_slots(1).await);
        let critical = |reason: &str| PressureAssessment {
            state: PressureState::Critical,
            reason_code: reason.to_string(),
            ..Default::default()
        };
        for reason in ["disk_ratio_below_critical", "disk_free_below_critical_gb"] {
            worker.set_pressure_assessment(critical(reason)).await;
            assert!(scheduler.is_worker_eligible(&worker).await, "{reason}");
        }
        // Critical for another reason, or merely tight, still waits for idle.
        for other in [
            critical("memory_pressure_critical"),
            critical("disk_io_saturated_with_low_headroom"),
            critical("disk_critical_without_fresh_telemetry"),
            PressureAssessment {
                state: PressureState::Warning,
                reason_code: "disk_ratio_below_warning".to_string(),
                ..Default::default()
            },
        ] {
            let reason = other.reason_code.clone();
            worker.set_pressure_assessment(other).await;
            assert!(!scheduler.is_worker_eligible(&worker).await, "{reason}");
        }
    }

    #[tokio::test]
    async fn test_is_worker_eligible_unhealthy() {
        let pool = WorkerPool::new();
        let config = create_test_worker_config("unhealthy-worker");
        pool.add_worker(config).await;

        let cleanup_config = CacheCleanupConfig::default();
        let scheduler = CacheCleanupScheduler::new(pool.clone(), cleanup_config);

        let worker_state = pool.get(&WorkerId::new("unhealthy-worker")).await.unwrap();

        // Set worker to unreachable
        worker_state.set_status(WorkerStatus::Unreachable).await;

        let eligible = scheduler.is_worker_eligible(&worker_state).await;
        assert!(!eligible);
    }

    #[tokio::test]
    async fn test_is_worker_eligible_busy() {
        let pool = WorkerPool::new();
        let config = create_test_worker_config("busy-worker");
        pool.add_worker(config).await;

        let cleanup_config = CacheCleanupConfig::default();
        let scheduler = CacheCleanupScheduler::new(pool.clone(), cleanup_config);

        let worker_state = pool.get(&WorkerId::new("busy-worker")).await.unwrap();

        // Reserve some slots (worker is now busy)
        worker_state.reserve_slots(4).await;

        let eligible = scheduler.is_worker_eligible(&worker_state).await;
        assert!(!eligible);
    }

    #[tokio::test]
    async fn test_is_worker_eligible_circuit_open() {
        let pool = WorkerPool::new();
        let config = create_test_worker_config("circuit-open-worker");
        pool.add_worker(config).await;

        let cleanup_config = CacheCleanupConfig::default();
        let scheduler = CacheCleanupScheduler::new(pool.clone(), cleanup_config);

        let worker_state = pool
            .get(&WorkerId::new("circuit-open-worker"))
            .await
            .unwrap();

        // Open the circuit
        worker_state.open_circuit().await;

        let eligible = scheduler.is_worker_eligible(&worker_state).await;
        assert!(!eligible);
    }

    #[tokio::test]
    async fn test_is_worker_eligible_draining() {
        let pool = WorkerPool::new();
        let config = create_test_worker_config("draining-worker");
        pool.add_worker(config).await;

        let cleanup_config = CacheCleanupConfig::default();
        let scheduler = CacheCleanupScheduler::new(pool.clone(), cleanup_config);

        let worker_state = pool.get(&WorkerId::new("draining-worker")).await.unwrap();

        // Set to draining
        worker_state.set_status(WorkerStatus::Draining).await;

        let eligible = scheduler.is_worker_eligible(&worker_state).await;
        assert!(!eligible);
    }

    #[tokio::test]
    async fn test_cleanup_worker_now_not_found() {
        let pool = WorkerPool::new();
        let config = CacheCleanupConfig::default();
        let scheduler = CacheCleanupScheduler::new(pool, config);

        let result = scheduler
            .cleanup_worker_now(&WorkerId::new("nonexistent"))
            .await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Worker nonexistent not found")
        );
    }

    #[tokio::test]
    async fn test_run_cleanup_cycle_empty_pool() {
        let pool = WorkerPool::new();
        let config = CacheCleanupConfig::default();
        let scheduler = CacheCleanupScheduler::new(pool, config);

        let stats = scheduler.run_cleanup_cycle().await;

        assert_eq!(stats.workers_checked, 0);
        assert_eq!(stats.workers_cleaned, 0);
        assert_eq!(stats.workers_skipped, 0);
        assert_eq!(stats.errors, 0);
    }

    #[tokio::test]
    async fn test_run_cleanup_cycle_all_skipped() {
        let pool = WorkerPool::new();
        // Add workers that will be skipped (busy)
        let config1 = create_test_worker_config("busy-worker1");
        let config2 = create_test_worker_config("busy-worker2");
        pool.add_worker(config1).await;
        pool.add_worker(config2).await;

        // Make workers busy
        let worker1 = pool.get(&WorkerId::new("busy-worker1")).await.unwrap();
        let worker2 = pool.get(&WorkerId::new("busy-worker2")).await.unwrap();
        worker1.reserve_slots(4).await;
        worker2.reserve_slots(4).await;

        let cleanup_config = CacheCleanupConfig::default();
        let scheduler = CacheCleanupScheduler::new(pool, cleanup_config);

        let stats = scheduler.run_cleanup_cycle().await;

        assert_eq!(stats.workers_checked, 2);
        assert_eq!(stats.workers_cleaned, 0);
        assert_eq!(stats.workers_skipped, 2);
        assert_eq!(stats.errors, 0);
    }

    #[test]
    fn test_cleanup_config_custom_values() {
        let _guard = test_guard!();
        let config = CacheCleanupConfig {
            enabled: false,
            interval_secs: 7200,
            max_cache_age_hours: 168, // 1 week
            min_free_gb: 50,
            idle_threshold_secs: 300,
            remote_base: "/custom/path".to_string(),
        };

        assert!(!config.enabled);
        assert_eq!(config.interval_secs, 7200);
        assert_eq!(config.max_cache_age_hours, 168);
        assert_eq!(config.min_free_gb, 50);
        assert_eq!(config.idle_threshold_secs, 300);
        assert_eq!(config.remote_base, "/custom/path");
    }

    #[test]
    fn test_cleanup_result_with_large_values() {
        let _guard = test_guard!();
        let result = CleanupResult {
            worker_id: WorkerId::new("large-cleanup"),
            success: true,
            dirs_removed: Some(1000),
            bytes_freed: Some(1024 * 1024 * 1024 * 10), // 10GB
            duration: Duration::from_secs(120),         // 2 minutes
            error: None,
        };

        assert!(result.success);
        assert_eq!(result.dirs_removed, Some(1000));
        assert_eq!(result.bytes_freed, Some(10737418240));
        assert_eq!(result.duration.as_secs(), 120);
    }

    #[test]
    fn test_cleanup_stats_large_accumulation() {
        let _guard = test_guard!();
        // Simulate large-scale cleanup
        let stats = CleanupStats {
            workers_checked: 100,
            workers_cleaned: 95,
            workers_skipped: 3,
            errors: 2,
            total_bytes_freed: 1024 * 1024 * 1024 * 500, // 500GB
            total_dirs_removed: 5000,
        };

        assert_eq!(stats.workers_checked, 100);
        assert_eq!(stats.total_bytes_freed, 536870912000);
        assert_eq!(stats.total_dirs_removed, 5000);
    }

    #[test]
    fn test_parse_cleanup_metrics_parses_emitted_line() {
        let _guard = test_guard!();
        let stdout = "noise\nRCH_CLEANUP_METRICS removed=4 freed_kb=2048 before_kb=4096 after_kb=6144 low_disk=1 remove_errors=2\n";
        let metrics = parse_cleanup_metrics(stdout).expect("expected parse result");
        assert_eq!(metrics.removed_dirs, 4);
        assert_eq!(metrics.freed_bytes, 2 * 1024 * 1024);
        assert!((metrics.free_before_gb - (4096.0 / (1024.0 * 1024.0))).abs() < f64::EPSILON);
        assert!((metrics.free_after_gb - (6144.0 / (1024.0 * 1024.0))).abs() < f64::EPSILON);
        assert!(metrics.low_disk_mode);
        assert_eq!(metrics.remove_errors, 2);
    }

    #[cfg(unix)]
    #[test]
    fn retained_source_gc_guard_holds_markers_and_ancestors_without_erasure() {
        use std::io::Write;
        use std::os::unix::fs::symlink;

        let directory = tempfile::Builder::new()
            .prefix("retained-source-gc-")
            .disable_cleanup(true)
            .tempdir()
            .unwrap();
        let directory = directory.keep();
        let ancestor = directory.join("parent with ' quoted name");
        let retained = ancestor.join("retained source");
        let malformed = directory.join("malformed-marker");
        let ordinary = directory.join("ordinary-unmarked");
        for path in [&retained, &malformed, &ordinary] {
            std::fs::create_dir_all(path).unwrap();
        }
        let sentinel = retained.join("original-input");
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&sentinel)
            .unwrap()
            .write_all(b"original retained bytes")
            .unwrap();
        // A dangling metadata symlink is a hold without following its target.
        // Marker contents are not asserted as a valid source seal by this gate.
        symlink("metadata-not-a-path", retained.join(".rch-retention-v1")).unwrap();
        let beneath_retained = retained.join("nested/target");
        std::fs::create_dir_all(&beneath_retained).unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(malformed.join(".rch-retention-v1"))
            .unwrap();
        let script = format!("{RETAINED_SOURCE_GC_GUARD}\nrch_retained_source_gc_hold \"$1\"");
        for (path, held) in [
            (&retained, true),
            (&beneath_retained, true),
            (&ancestor, true),
            (&malformed, true),
            (&ordinary, false),
        ] {
            // Execute the actual production predicate, not the deleting sweep.
            // This is local filesystem policy coverage, not worker GC proof.
            let output = std::process::Command::new("sh")
                .args(["-c", &script, "retention-guard"])
                .arg(path)
                .output()
                .unwrap();
            assert_eq!(output.status.code(), Some(if held { 0 } else { 1 }));
            assert_eq!(
                std::fs::read(&sentinel).unwrap(),
                b"original retained bytes"
            );
        }
        let absent = directory.join("absent-probe-root");
        let unknown = std::process::Command::new("sh")
            .args(["-c", &script, "retention-guard"])
            .arg(absent)
            .output()
            .unwrap();
        assert_eq!(unknown.status.code(), Some(2));
        assert!(
            String::from_utf8(unknown.stderr)
                .unwrap()
                .contains("RCH_CLEANUP_RETENTION_UNKNOWN")
        );
        assert_eq!(
            std::fs::read(&sentinel).unwrap(),
            b"original retained bytes"
        );
    }

    #[cfg(target_os = "linux")]
    fn source_transaction_fixture(body: &str) -> (std::process::Output, std::path::PathBuf) {
        use std::io::Write;

        let directory = tempfile::Builder::new()
            .prefix("cleanup-source-transaction-")
            .disable_cleanup(true)
            .tempdir()
            .unwrap()
            .keep();
        let directory = directory.canonicalize().unwrap();
        let candidate = directory.join("parent with ' quote/candidate");
        std::fs::create_dir_all(&candidate).unwrap();
        let mut original = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(candidate.join("original-input"))
            .unwrap();
        original.write_all(b"preserved cleanup input").unwrap();
        original
            .set_modified(std::time::SystemTime::now() - Duration::from_secs(10 * 60))
            .unwrap();
        // Execute the real GNU/Linux transaction with an owned fixture registry,
        // never the deleting sweep or
        // the production registry. This is local policy coverage, not a worker
        // lifecycle, SDK, transport, crash recovery or performance assertion.
        let script = format!(
            "{}\n{CLEANUP_SOURCE_ACTIVITY_GUARD}\n{CLEANUP_SOURCE_TRANSACTION}\n\
             set -eu; candidate=$1;\n{body}",
            rch_common::stale_target_reap::source_claim_gc_guard_fragment_with_registry(
                directory.join("claims").to_str().unwrap(),
            ),
        );
        let output = std::process::Command::new("sh")
            .args(["-c", &script, "cleanup-source-transaction"])
            .arg(&candidate)
            .arg(&directory)
            .output()
            .unwrap();
        assert_eq!(
            std::fs::read(candidate.join("original-input")).unwrap(),
            b"preserved cleanup input"
        );
        (output, directory)
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cleanup_source_transaction_holds_real_lock_until_checked_retirement() {
        let _guard = test_guard!();
        let (output, directory) = source_transaction_fixture(
            r#"
rch_cleanup_source_candidate_begin "$candidate";
claim=$__gc_reservation;
rch_claim_record_valid "$claim";
[ "$(cat "$claim")" = "$candidate" ];
if flock -n -E 73 "$__gc_source_registry/metadata.lock" true; then exit 10;
else [ "$?" -eq 73 ]; fi;
rch_cleanup_source_candidate_end "$candidate";
[ ! -e "$claim" ];
rch_claim_record_valid "$__gc_source_registry/released/${claim##*/}";
[ "$(cat "$__gc_source_registry/released/${claim##*/}")" = "$candidate" ];
flock -n "$__gc_source_registry/metadata.lock" true;
"#,
        );
        assert!(output.status.success(), "{output:?}");
        assert_eq!(
            std::fs::read_dir(directory.join("claims/released"))
                .unwrap()
                .count(),
            1
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cleanup_source_transaction_late_marker_prevents_a_gc_claim() {
        let _guard = test_guard!();
        let (output, directory) = source_transaction_fixture(
            r#"
if rch_retained_source_gc_hold "$candidate"; then exit 10; else [ "$?" -eq 1 ]; fi;
ln -s 'retention-metadata-not-a-path' "$candidate/.rch-retention-v1";
if rch_cleanup_source_candidate_begin "$candidate"; then exit 11; else [ "$?" -eq 1 ]; fi;
[ -z "$__gc_reservation" ];
[ ! -e "$__gc_source_registry/released" ];
for record in "$__gc_source_registry"/*.claim "$__gc_source_registry"/*.pending; do
    [ ! -e "$record" ] && [ ! -L "$record" ];
done;
flock -n "$__gc_source_registry/metadata.lock" true;
"#,
        );
        assert!(output.status.success(), "{output:?}");
        assert!(String::from_utf8_lossy(&output.stderr).contains("RCH_CLEANUP_RETENTION_HOLD"));
        assert!(!directory.join("claims/released").exists());
        assert!(
            std::fs::symlink_metadata(
                directory.join("parent with ' quote/candidate/.rch-retention-v1")
            )
            .unwrap()
            .file_type()
            .is_symlink()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cleanup_source_transaction_preserves_active_ancestor_claim() {
        let _guard = test_guard!();
        let (output, directory) = source_transaction_fixture(
            r#"
mkdir "$__gc_source_registry";
root=$(cd "$candidate/.." && pwd -P);
actual=$(printf '%s\n' "$root" | sha256sum); digest=${actual%% *};
claim="$__gc_source_registry/ca01.$digest.claim";
exec 9>"$__gc_source_registry/metadata.lock"; flock -x 9;
rch_claim_write_atomic "$__gc_source_registry" "$claim" "$digest" "$root";
exec 9>&-;
if rch_cleanup_source_candidate_begin "$candidate"; then exit 10; else [ "$?" -eq 2 ]; fi;
rch_claim_record_valid "$claim";
[ "$(cat "$claim")" = "$root" ];
[ ! -e "$__gc_source_registry/released" ];
flock -n "$__gc_source_registry/metadata.lock" true;
"#,
        );
        assert!(output.status.success(), "{output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("RCH_CLEANUP_SOURCE_OWNERSHIP_UNAVAILABLE")
        );
        assert_eq!(
            std::fs::read_dir(directory.join("claims")).unwrap().count(),
            2
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cleanup_source_transaction_rechecks_writes_during_metadata_admission() {
        let _guard = test_guard!();
        let (output, directory) = source_transaction_fixture(
            r#"
early=$(find "$candidate" -type f -mmin -5 -print -quit);
[ -z "$early" ];
mkdir "$__gc_source_registry";
exec 9>"$__gc_source_registry/metadata.lock"; flock -x 9;
(
    exec 9>&-;
    if rch_cleanup_source_candidate_begin "$candidate"; then exit 10;
    else [ "$?" -eq 1 ]; fi;
    [ -z "$__gc_reservation" ];
) &
child=$!;
attempt=0;
waiter_seen=0;
while [ "$waiter_seen" -eq 0 ]; do
    children=$(cat "/proc/$child/task/$child/children");
    for waiter in $children; do
        if name=$(cat "/proc/$waiter/comm") && [ "$name" = flock ] &&
           descriptor=$(readlink "/proc/$waiter/fd/8") &&
           [ "$descriptor" = "$__gc_source_registry/metadata.lock" ]; then
            waiter_seen=1; break;
        fi;
    done;
    [ "$waiter_seen" -eq 0 ] || break;
    [ "$attempt" -lt 200 ] || exit 11;
    attempt=$((attempt + 1)); sleep 0.01;
done;
(set -C; printf 'late input' > "$candidate/late-input");
exec 9>&-;
wait "$child";
flock -n "$__gc_source_registry/metadata.lock" true;
"#,
        );
        assert!(output.status.success(), "{output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("reason=recent"),
            "{output:?}"
        );
        assert_eq!(
            std::fs::read(directory.join("parent with ' quote/candidate/late-input")).unwrap(),
            b"late input"
        );
        assert_eq!(
            std::fs::read_dir(directory.join("claims/released"))
                .unwrap()
                .count(),
            1
        );
    }

    #[cfg(unix)]
    #[test]
    fn cleanup_source_activity_keeps_recent_inputs_and_reports_missing_inspection() {
        use std::io::Write;

        let directory = tempfile::Builder::new()
            .prefix("cleanup-source-activity-")
            .disable_cleanup(true)
            .tempdir()
            .unwrap()
            .keep();
        let directory = directory.canonicalize().unwrap();
        let original = directory.join("original-input");
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&original)
            .unwrap()
            .write_all(b"recent original bytes")
            .unwrap();
        let script =
            format!("{CLEANUP_SOURCE_ACTIVITY_GUARD}\nrch_cleanup_source_activity \"$1\" 5");
        for (candidate, expected) in [(&directory, 1), (&directory.join("absent-probe"), 2)] {
            let output = std::process::Command::new("sh")
                .args(["-c", &script, "activity-guard"])
                .arg(candidate)
                .output()
                .unwrap();
            assert_eq!(output.status.code(), Some(expected), "{output:?}");
            assert_eq!(std::fs::read(&original).unwrap(), b"recent original bytes");
            let diagnostics = String::from_utf8_lossy(&output.stderr);
            assert!(diagnostics.contains(if expected == 1 {
                "RCH_CLEANUP_ACTIVITY_HOLD"
            } else {
                "RCH_CLEANUP_ACTIVITY_UNKNOWN"
            }));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cleanup_source_activity_keeps_live_cwd_and_classifies_a_real_zombie() {
        use std::io::{BufRead, Write};
        use std::process::{Command, Stdio};

        let directory = tempfile::Builder::new()
            .prefix("cleanup-process-cwd-")
            .disable_cleanup(true)
            .tempdir()
            .unwrap()
            .keep();
        let directory = directory.canonicalize().unwrap();
        let original = directory.join("original-input");
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&original)
            .unwrap()
            .write_all(b"original process input")
            .unwrap();
        let script =
            format!("{CLEANUP_SOURCE_ACTIVITY_GUARD}\nrch_cleanup_bound_process_cwd \"$1\" \"$2\"");

        // Actual redirection failure must remain unknown under both shells,
        // independent of the shell's own redirection-error exit code.
        for shell in ["sh", "bash"] {
            let output = Command::new(shell)
                .args(["-c", &script, "missing-process-directory"])
                .arg(directory.join("missing-process-directory"))
                .arg(&directory)
                .output()
                .unwrap();
            assert_eq!(output.status.code(), Some(2), "{shell}: {output:?}");
            assert!(!output.stderr.is_empty());
        }

        // Do not reap before inspection: the kernel must actually report Z.
        let mut zombie = Command::new("sh").args(["-c", "exit 0"]).spawn().unwrap();
        let proc = std::path::PathBuf::from(format!("/proc/{}", zombie.id()));
        let mut observed_zombie = false;
        for _ in 0..200 {
            let status = std::fs::read_to_string(proc.join("status")).unwrap();
            observed_zombie = status.lines().any(|line| {
                line.starts_with("State:") && line.split_whitespace().nth(1) == Some("Z")
            });
            if observed_zombie {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let output = Command::new("sh")
            .args(["-c", &script, "zombie-cwd"])
            .arg(&proc)
            .arg(&directory)
            .output()
            .unwrap();
        assert!(zombie.wait().unwrap().success());
        assert!(observed_zombie, "the real kernel zombie was not observed");
        assert_eq!(output.status.code(), Some(0), "{output:?}");

        let mut live = Command::new("sh")
            .args([
                "-c",
                "cd \"$1\"; printf 'ready\\n'; read release",
                "live-cwd",
            ])
            .arg(&directory)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut ready = String::new();
        std::io::BufReader::new(live.stdout.take().unwrap())
            .read_line(&mut ready)
            .unwrap();
        let proc = std::path::PathBuf::from(format!("/proc/{}", live.id()));
        let output = Command::new("sh")
            .args(["-c", &script, "live-cwd"])
            .arg(&proc)
            .arg(&directory)
            .output()
            .unwrap();
        live.stdin
            .as_mut()
            .unwrap()
            .write_all(b"release\n")
            .unwrap();
        assert!(live.wait().unwrap().success());
        assert_eq!(ready, "ready\n");
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        assert_eq!(std::fs::read(&original).unwrap(), b"original process input");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cleanup_source_transaction_failed_retirement_keeps_durable_claim() {
        let _guard = test_guard!();
        let (output, directory) = source_transaction_fixture(
            r#"
mkdir "$__gc_source_registry";
ln -s "$2" "$__gc_source_registry/released";
printf '%s\n' 'real recent input' > "$candidate/late-input";
if rch_cleanup_source_candidate_begin "$candidate"; then exit 10; else [ "$?" -eq 3 ]; fi;
rch_claim_record_valid "$__gc_reservation";
[ "$(cat "$__gc_reservation")" = "$candidate" ];
flock -n "$__gc_source_registry/metadata.lock" true;
"#,
        );
        assert!(output.status.success(), "{output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("RCH_CLEANUP_SOURCE_RETIREMENT_FAILED")
        );
        assert!(
            std::fs::symlink_metadata(directory.join("claims/released"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            std::fs::read_dir(directory.join("claims")).unwrap().count(),
            3
        );
    }

    #[test]
    fn test_build_cleanup_command_contains_threshold_and_marker() {
        let _guard = test_guard!();
        let command = build_cleanup_command("'/tmp/rch'", REMOTE_RUN_ROOT, 72, 10);
        assert!(command.contains("threshold_kb=10485760"));
        assert!(command.contains("low_disk_permille=70"));
        assert!(command.contains("ratio_kb=$((total_kb / 1000 * low_disk_permille))"));
        assert!(command.contains("active_grace_minutes=5"));
        assert!(command.contains("-mmin -\"$active_grace_minutes\""));
        assert!(command.contains("case \"$dir\" in \"$base\"/*)"));
        assert!(command.contains("if rm -rf \"$dir\""));
        assert!(command.contains("remove_errors=$((remove_errors + 1))"));
        assert!(command.contains("if [ \"$remove_errors\" -gt 0 ]; then exit 1; fi"));
        assert!(command.contains("RCH_CLEANUP_METRICS"));
        assert!(command.contains("low_disk"));
        assert!(command.contains("remove_errors"));
    }

    /// Backdate a file far past the 240-minute orphan threshold.
    fn age_record(path: &std::path::Path) {
        let backdated = std::time::SystemTime::now() - std::time::Duration::from_secs(5 * 3600);
        std::fs::File::options()
            .write(true)
            .open(path)
            .expect("open record")
            .set_modified(backdated)
            .expect("backdate record");
    }

    /// Stale records (malformed, or naming a group with no members) are
    /// deleted; fresh ones are kept; an empty run dir is removed only once
    /// it is a day old.
    #[test]
    fn cleanup_command_deletes_stale_process_records_only() {
        let _guard = test_guard!();
        let base = tempfile::tempdir().expect("base");
        let runs = tempfile::tempdir().expect("run root");
        let run = runs.path().join("project-0123456789abcdef");
        std::fs::create_dir(&run).expect("run dir");
        let malformed = run.join("41.pgid");
        std::fs::write(&malformed, "garbage\n").expect("malformed");
        age_record(&malformed);
        // Legacy bare pgid of a group that cannot exist (above pid_max).
        let vanished = run.join("42.pgid");
        std::fs::write(&vanished, "2147483000\n").expect("vanished");
        age_record(&vanished);
        let fresh = run.join("43.pgid");
        std::fs::write(&fresh, "garbage\n").expect("fresh");
        let empty_old = runs.path().join("empty-old");
        std::fs::create_dir(&empty_old).expect("empty old");
        std::fs::File::open(&empty_old)
            .unwrap()
            .set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(2 * 86400))
            .unwrap();
        let empty_new = runs.path().join("empty-new");
        std::fs::create_dir(&empty_new).expect("empty new");

        let (stdout, stderr, code) = run_sweep_with_runs(base.path(), runs.path(), &[]);
        assert_eq!(code, Some(0), "{stdout}{stderr}");
        assert!(stdout.contains("orphans_killed=0"), "{stdout}");
        assert!(
            !malformed.exists() && !vanished.exists(),
            "stale records remain"
        );
        assert!(
            fresh.exists(),
            "a record younger than the threshold was touched"
        );
        assert!(!empty_old.exists(), "day-old empty run dir must go");
        assert!(
            empty_new.exists() && run.exists(),
            "live run dirs must stay"
        );
    }

    /// A live group whose recorded leader matches is killed; the identity
    /// check comes from the launcher's own record format.
    #[cfg(target_os = "linux")]
    #[test]
    fn cleanup_command_kills_identified_orphan_group() {
        use std::os::unix::process::ExitStatusExt;
        let _guard = test_guard!();
        let base = tempfile::tempdir().expect("base");
        let runs = tempfile::tempdir().expect("run root");
        let run = runs.path().join("project-0123456789abcdef");
        std::fs::create_dir(&run).expect("run dir");
        let record = run.join("77.pgid");
        let launcher = format!(
            "{}\nrch_remote_record \"$1\" 77 || exit 9\nexec sleep 600",
            rch_common::REMOTE_PROCESS_IDENTITY_SCRIPT
        );
        let mut leader = std::process::Command::new("setsid")
            .args(["sh", "-c", &launcher, "rch-test"])
            .arg(&record)
            .spawn()
            .expect("spawn orphan");
        let deadline = Instant::now() + Duration::from_secs(10);
        while !record.exists() {
            assert!(Instant::now() < deadline, "launcher never published");
            std::thread::sleep(Duration::from_millis(20));
        }
        age_record(&record);

        let (stdout, stderr, code) = run_sweep_with_runs(base.path(), runs.path(), &[]);
        let status = leader.wait().expect("reap leader");
        assert_eq!(code, Some(0), "{stdout}{stderr}");
        assert!(stdout.contains("orphans_killed=1"), "{stdout}{stderr}");
        assert_eq!(status.signal(), Some(9));
    }

    /// The sweep (both modes share the loop) must not delete a directory a
    /// live process works in, even when nothing in it was written recently.
    #[cfg(target_os = "linux")]
    #[test]
    fn cleanup_command_keeps_directory_used_as_process_cwd() {
        let _guard = test_guard!();
        let base = tempfile::tempdir().expect("base");
        let pool = base.path().join("repo").join(".rch-target-pool-busy");
        std::fs::create_dir_all(pool.join("deps")).expect("pool tree");
        age_dir(&pool);
        let mut worker = std::process::Command::new("sleep")
            .arg("600")
            .current_dir(pool.join("deps"))
            .spawn()
            .expect("spawn cwd holder");
        let (stdout, _stderr, code) = run_sweep(base.path(), &[]);
        worker.kill().expect("kill cwd holder");
        worker.wait().expect("reap cwd holder");
        assert_eq!(code, Some(0));
        assert!(stdout.contains("removed=0"), "{stdout}");
        assert!(pool.is_dir(), "in-use pool was deleted");
    }

    #[test]
    fn test_build_cleanup_command_reconciles_failed_rm_and_reports_diagnostics() {
        let _guard = test_guard!();
        let command = build_cleanup_command("'/tmp/rch'", REMOTE_RUN_ROOT, 72, 10);
        // bd-kwvy8: a nonzero rm does NOT mean nothing was reaped. A
        // candidate that is already gone was reaped by another writer —
        // count it.
        assert!(command.contains("elif [ ! -d \"$dir\" ]; then"));
        // An empty husk left by a raced/partial removal gets exactly one
        // rmdir retry; success counts as removed and says so on stderr.
        assert!(command.contains("RCH_CLEANUP_HUSK_REAPED dir=%s"));
        // A surviving candidate or an unreapable husk produces a per-dir
        // diagnostic instead of being silently swallowed by 2>/dev/null.
        assert!(command.contains("RCH_CLEANUP_RM_FAILURE dir=%s kb=%s"));
    }

    /// Backdate a fixture directory so the sweep's `-mmin +max_age` filter
    /// (max_age 0 in these tests) deterministically selects it.
    ///
    /// A directory created moments before the sweep has age 0, which is
    /// NOT "older than 0 minutes" under either `find`: BSD rounds
    /// `(age + 59) / 60` and so needs the entry to be at least one second
    /// old, GNU truncates and needs a full minute. Fresh fixtures therefore
    /// only became candidates when the test process happened to be slow,
    /// which made the tests pass under a loaded full gate and fail when
    /// run alone.
    fn age_dir(path: &std::path::Path) {
        let backdated = std::time::SystemTime::now() - std::time::Duration::from_secs(10 * 60);
        std::fs::File::open(path)
            .expect("open fixture dir")
            .set_modified(backdated)
            .expect("backdate fixture dir");
    }

    /// Write an executable `name` into `dir` so `dir` can be prepended to
    /// the sweep's PATH (see `run_sweep`).
    fn write_shim(dir: &std::path::Path, name: &str, body: &str) {
        use std::os::unix::fs::PermissionsExt;
        let shim = dir.join(name);
        std::fs::write(&shim, body).expect("write shim");
        std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755))
            .expect("chmod shim");
    }

    /// Runs the generated sweep against a scratch tree, optionally with
    /// directories prepended to PATH (for command shims), capturing
    /// stdout, stderr, and exit status.
    fn run_sweep(
        base: &std::path::Path,
        prepend_path: &[std::path::PathBuf],
    ) -> (String, String, Option<i32>) {
        // Never let a test sweep the host's real process records.
        let runs = tempfile::tempdir().expect("run root");
        run_sweep_with_runs(base, runs.path(), prepend_path)
    }

    fn run_sweep_with_runs(
        base: &std::path::Path,
        runs: &std::path::Path,
        prepend_path: &[std::path::PathBuf],
    ) -> (String, String, Option<i32>) {
        // A zero ratio keeps low-disk mode independent of the test host's disk.
        run_sweep_with(base, runs, prepend_path, 0, 0)
    }

    fn run_sweep_with(
        base: &std::path::Path,
        runs: &std::path::Path,
        prepend_path: &[std::path::PathBuf],
        max_cache_age_hours: u64,
        low_disk_permille: u64,
    ) -> (String, String, Option<i32>) {
        use std::env::{join_paths, split_paths};
        let escaped = format!("'{}'", base.display());
        // Registry records are protocol state, not a host-wide test fixture.
        // Preserve this private registry even if a test panics; the real worker
        // registry must never be used by a sweep against an owned scratch tree.
        let registry = tempfile::Builder::new()
            .prefix("cleanup-sweep-claims-")
            .disable_cleanup(true)
            .tempdir()
            .expect("private source registry")
            .keep();
        let source_guard =
            rch_common::stale_target_reap::source_claim_gc_guard_fragment_with_registry(
                registry.to_str().unwrap(),
            );
        let command = build_cleanup_command_with_source_guard(
            &escaped,
            &format!("'{}'", runs.display()),
            max_cache_age_hours,
            0,
            low_disk_permille,
            &source_guard,
        );
        let mut full_path: Vec<std::path::PathBuf> = prepend_path.to_vec();
        full_path.extend(split_paths(&std::env::var_os("PATH").unwrap_or_default()));
        let output = std::process::Command::new("sh")
            .arg("-c")
            .arg(&command)
            .env("PATH", join_paths(full_path.iter()).expect("join PATH"))
            .output()
            .expect("run sweep");
        (
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
            output.status.code(),
        )
    }

    /// A worker at or below the placement policy's critical free ratio gets no
    /// slots, so the sweep must evict inactive caches there even when they are
    /// younger than max_age (bd-xxck3). `find -printf` makes this Linux-only.
    #[cfg(target_os = "linux")]
    #[test]
    fn cleanup_command_evicts_young_inactive_caches_below_the_placement_ratio() {
        let _guard = test_guard!();
        assert_eq!(placement_low_disk_permille(), 70);
        let base = tempfile::tempdir().expect("base");
        let runs = tempfile::tempdir().expect("run root");
        let pool = base
            .path()
            .join("busy_repo")
            .join(".rch-target-pool-0123abcd");
        std::fs::create_dir_all(pool.join("deps")).expect("pool tree");
        // Past the 5-minute activity grace, far younger than 72 h.
        age_dir(&pool);
        let (stdout, stderr, code) = run_sweep_with(base.path(), runs.path(), &[], 72, 0);
        assert_eq!(code, Some(0), "{stdout}{stderr}");
        assert!(
            stdout.contains("removed=0") && stdout.contains("low_disk=0"),
            "{stdout}"
        );
        assert!(pool.exists());
        // No filesystem has 100% free, so this ratio always demands eviction.
        let (stdout, stderr, code) = run_sweep_with(base.path(), runs.path(), &[], 72, 1000);
        assert_eq!(code, Some(0), "{stdout}{stderr}");
        assert!(
            stdout.contains("removed=1") && stdout.contains("low_disk=1"),
            "{stdout}"
        );
        assert!(!pool.exists());
    }

    /// Without procfs the sweep cannot prove a pool idle, so it keeps it and
    /// reports why; the reap tests are Linux-only for that reason.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn cleanup_command_keeps_aged_pool_when_activity_is_unprovable() {
        let _guard = test_guard!();
        let base = tempfile::tempdir().expect("base");
        let pool = base
            .path()
            .join("gcverify_pool_repo")
            .join(".rch-target-pool-deadbeefcafe");
        std::fs::create_dir_all(pool.join("deps")).expect("pool tree");
        age_dir(&pool);
        let (stdout, stderr, _) = run_sweep(base.path(), &[]);
        assert!(stdout.contains("removed=0"), "{stdout}");
        assert!(
            stderr.contains("RCH_CLEANUP_ACTIVITY_UNKNOWN") && stderr.contains("reason=proc"),
            "{stderr}"
        );
        assert!(pool.join("deps").is_dir());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cleanup_command_reaps_aged_pool_normally() {
        let _guard = test_guard!();
        let base = tempfile::tempdir().expect("base");
        let pool = base
            .path()
            .join("gcverify_pool_repo")
            .join(".rch-target-pool-deadbeefcafe");
        std::fs::create_dir_all(pool.join("deps")).expect("pool tree");
        age_dir(&pool);
        let (stdout, stderr, code) = run_sweep(base.path(), &[]);
        assert_eq!(code, Some(0), "{stdout}{stderr}");
        assert!(stdout.contains("removed=1"), "{stdout}");
        assert!(stdout.contains("remove_errors=0"), "{stdout}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cleanup_command_reaps_empty_husk_when_rmdir_succeeds() {
        let _guard = test_guard!();
        let base = tempfile::tempdir().expect("base");
        // Empty husk: contents were removed by an interfering writer,
        // the directory itself remains (bd-kwvy8's hz2 observation).
        let husk = base
            .path()
            .join("gcverify_pool_repo")
            .join(".rch-target-pool-deadbeefcafe");
        std::fs::create_dir_all(&husk).expect("husk");
        age_dir(&husk);
        // A shim `rm` that refuses -rf models rm failing mid-removal;
        // the sweep must reconcile via rmdir and count the reap.
        let shim_dir = tempfile::tempdir().expect("shim dir");
        write_shim(
            shim_dir.path(),
            "rm",
            "#!/bin/sh\n[ \"$1\" = \"-rf\" ] && exit 42\nfor real in /usr/bin/rm /bin/rm; do [ -x \"$real\" ] && exec \"$real\" \"$@\"; done\nexit 127\n",
        );
        let (stdout, stderr, code) = run_sweep(base.path(), &[shim_dir.path().to_path_buf()]);
        assert_eq!(code, Some(0));
        assert!(stdout.contains("removed=1"), "{stdout}");
        assert!(stdout.contains("remove_errors=0"), "{stdout}");
        assert!(
            stderr.contains("RCH_CLEANUP_HUSK_REAPED")
                && stderr.contains(".rch-target-pool-deadbeefcafe"),
            "{stderr}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cleanup_command_reports_survivor_and_unreapable_husk_as_errors() {
        let _guard = test_guard!();
        let base = tempfile::tempdir().expect("base");
        let survivor = base.path().join("repo_a").join(".rch-target-pool-survivor");
        std::fs::create_dir_all(survivor.join("nested")).expect("survivor tree");
        age_dir(&survivor);
        let husk = base.path().join("repo_b").join(".rch-target-pool-husk");
        std::fs::create_dir_all(&husk).expect("husk");
        age_dir(&husk);
        // Inject the failures through command shims rather than read-only
        // parents: root ignores directory permissions, so an EACCES-based
        // fixture reports the wrong verdict on the root-run workers the
        // gate actually executes on. `rm -rf` refusing leaves the survivor
        // non-empty (RM_FAILURE via the final branch); `rmdir` refusing
        // leaves the husk an unreapable empty shell (RM_FAILURE via the
        // rmdir-retry branch). Both directories must still exist after.
        let shim_dir = tempfile::tempdir().expect("shim dir");
        write_shim(
            shim_dir.path(),
            "rm",
            "#!/bin/sh\n[ \"$1\" = \"-rf\" ] && exit 1\nfor real in /usr/bin/rm /bin/rm; do [ -x \"$real\" ] && exec \"$real\" \"$@\"; done\nexit 127\n",
        );
        write_shim(shim_dir.path(), "rmdir", "#!/bin/sh\nexit 1\n");
        let (stdout, stderr, code) = run_sweep(base.path(), &[shim_dir.path().to_path_buf()]);
        assert!(survivor.join("nested").is_dir(), "survivor must be intact");
        assert!(husk.is_dir(), "husk must be intact");
        assert_eq!(code, Some(1));
        assert!(stdout.contains("removed=0"), "{stdout}");
        assert!(stdout.contains("remove_errors=2"), "{stdout}");
        assert!(
            stderr.matches("RCH_CLEANUP_RM_FAILURE").count() == 2,
            "{stderr}"
        );
        assert!(stderr.contains(".rch-target-pool-survivor"), "{stderr}");
        assert!(stderr.contains(".rch-target-pool-husk"), "{stderr}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cleanup_command_reaps_idle_offroot_mirror_and_keeps_active_or_protected_offroot_mirror() {
        let _guard = test_guard!();
        let base = tempfile::tempdir().expect("base");
        let idle_parent = base.path().join("offroot").join("0123456789abcdef");
        let idle_mirror = idle_parent.join("idle-clone");
        std::fs::create_dir_all(idle_mirror.join("src")).expect("idle mirror");
        let old_file = idle_mirror.join("src/lib.rs");
        std::fs::write(&old_file, "pub fn old() {}\n").expect("write old file");
        age_record(&old_file);
        age_dir(&idle_mirror);

        let kept_parent = base.path().join("offroot").join("fedcba9876543210");
        let active_mirror = kept_parent.join("active-clone");
        std::fs::create_dir_all(active_mirror.join("src")).expect("active mirror");
        std::fs::write(active_mirror.join("src/lib.rs"), "pub fn active() {}\n")
            .expect("write recent file");
        age_dir(&active_mirror);

        let protected_mirror = kept_parent.join("protected-clone");
        std::fs::create_dir_all(protected_mirror.join("src")).expect("protected mirror");
        let protected_file = protected_mirror.join("src/lib.rs");
        std::fs::write(&protected_file, "pub fn protected() {}\n").expect("write protected file");
        age_record(&protected_file);
        std::fs::write(protected_mirror.join(".sbh-protect"), "hold\n").expect("write sbh protect");
        age_dir(&protected_mirror);

        let (stdout, stderr, code) = run_sweep(base.path(), &[]);
        assert_eq!(code, Some(0), "{stdout}{stderr}");
        assert!(stdout.contains("removed=1"), "{stdout}{stderr}");
        assert!(!idle_mirror.exists(), "idle offroot mirror must be reaped");
        assert!(
            !idle_parent.exists(),
            "empty offroot hash parent must be pruned"
        );
        assert!(
            active_mirror.exists(),
            "offroot mirror with recent activity must be kept"
        );
        assert!(
            protected_mirror.exists(),
            "offroot mirror with .sbh-protect must be kept"
        );
    }
}
