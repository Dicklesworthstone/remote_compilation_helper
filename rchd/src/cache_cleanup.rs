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
}

fn cleanup_threshold_kb(min_free_gb: u64) -> u64 {
    min_free_gb.saturating_mul(1024).saturating_mul(1024)
}

fn build_cleanup_command(escaped_base: &str, max_cache_age_hours: u64, min_free_gb: u64) -> String {
    let max_age_minutes = max_cache_age_hours.saturating_mul(60);
    let threshold_kb = cleanup_threshold_kb(min_free_gb);
    let active_grace_minutes = 5_u64;
    format!(
        "set -u; \
         base={base}; \
         max_age_minutes={max_age_minutes}; \
         threshold_kb={threshold_kb}; \
         active_grace_minutes={active_grace_minutes}; \
         if [ ! -d \"$base\" ]; then mkdir -p \"$base\"; fi; \
         before_kb=$(df -Pk \"$base\" 2>/dev/null | awk 'NR==2 {{print $4}}'); \
         if [ -z \"$before_kb\" ]; then before_kb=0; fi; \
         removed=0; freed_kb=0; low_disk=0; \
         if [ \"$before_kb\" -lt \"$threshold_kb\" ]; then low_disk=1; fi; \
         candidates=$(mktemp /tmp/rch-cleanup.XXXXXX); \
         if [ \"$low_disk\" -eq 1 ]; then \
           find \"$base\" -mindepth 2 -maxdepth 2 -type d -printf '%T@ %p\\n' 2>/dev/null \
             | sort -n | sed 's/^[^ ]* //' > \"$candidates\"; \
         else \
           find \"$base\" -mindepth 2 -maxdepth 2 -type d -mmin +\"$max_age_minutes\" -print 2>/dev/null > \"$candidates\"; \
         fi; \
         while IFS= read -r dir; do \
           [ -z \"$dir\" ] && continue; \
           [ ! -d \"$dir\" ] && continue; \
           case \"$dir\" in \"$base\"/*) ;; *) continue ;; esac; \
           recent_active=$(find \"$dir\" -type f -mmin -\"$active_grace_minutes\" -print -quit 2>/dev/null || true); \
           if [ -n \"$recent_active\" ]; then continue; fi; \
           size_kb=$(du -sk \"$dir\" 2>/dev/null | awk '{{print $1}}'); \
           rm -rf \"$dir\" 2>/dev/null || true; \
           removed=$((removed + 1)); \
           if [ -n \"$size_kb\" ]; then freed_kb=$((freed_kb + size_kb)); fi; \
           if [ \"$low_disk\" -eq 1 ]; then \
             current_kb=$(df -Pk \"$base\" 2>/dev/null | awk 'NR==2 {{print $4}}'); \
             if [ -n \"$current_kb\" ] && [ \"$current_kb\" -ge \"$threshold_kb\" ]; then break; fi; \
           fi; \
         done < \"$candidates\"; \
         rm -f \"$candidates\"; \
         after_kb=$(df -Pk \"$base\" 2>/dev/null | awk 'NR==2 {{print $4}}'); \
         if [ -z \"$after_kb\" ]; then after_kb=0; fi; \
         printf 'RCH_CLEANUP_METRICS removed=%s freed_kb=%s before_kb=%s after_kb=%s low_disk=%s\\n' \"$removed\" \"$freed_kb\" \"$before_kb\" \"$after_kb\" \"$low_disk\"",
        base = escaped_base,
        max_age_minutes = max_age_minutes,
        threshold_kb = threshold_kb,
        active_grace_minutes = active_grace_minutes,
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
            _ => {}
        }
    }

    Some(CleanupMetrics {
        removed_dirs: removed_dirs.unwrap_or(0),
        freed_bytes: freed_kb.unwrap_or(0).saturating_mul(1024),
        free_before_gb: before_kb.unwrap_or(0) as f64 / (1024.0 * 1024.0),
        free_after_gb: after_kb.unwrap_or(0) as f64 / (1024.0 * 1024.0),
        low_disk_mode: low_disk.unwrap_or(false),
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
    /// SSH options for cleanup commands.
    ssh_options: SshOptions,
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
        }
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
        let (worker_id, total_slots) = {
            let config = worker_state.config.read().await;
            (config.id.clone(), config.total_slots)
        };

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

        // Check if worker is busy (has active slots)
        let available = worker_state.available_slots().await;
        if available < total_slots {
            debug!(
                "Worker {} is busy ({}/{} slots available), skipping cleanup",
                worker_id, available, total_slots
            );
            self.idle_since.write().await.remove(&worker_id);
            return false;
        }

        // Enforce idle threshold before cleanup.
        let idle_threshold = Duration::from_secs(self.config.idle_threshold_secs);
        if !idle_threshold.is_zero() {
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
        let cleanup_cmd = build_cleanup_command(
            escaped_base.as_ref(),
            self.config.max_cache_age_hours,
            self.config.min_free_gb,
        );

        // Execute cleanup via SSH
        let mut ssh_client = SshClient::new(config.clone(), self.ssh_options.clone());
        ssh_client.connect().await?;

        let result = ssh_client.execute(&cleanup_cmd).await?;

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
                    "removed={}, freed_mb={}, before_free_gb={:.2}, after_free_gb={:.2}, low_disk={}",
                    m.removed_dirs,
                    m.freed_bytes / (1024 * 1024),
                    m.free_before_gb,
                    m.free_after_gb,
                    m.low_disk_mode
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
                "Cleanup command failed with exit code {} (stderr: {})",
                result.exit_code,
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
        assert_eq!(config.remote_base, "/tmp/rch");
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
        let stdout = "noise\nRCH_CLEANUP_METRICS removed=4 freed_kb=2048 before_kb=4096 after_kb=6144 low_disk=1\n";
        let metrics = parse_cleanup_metrics(stdout).expect("expected parse result");
        assert_eq!(metrics.removed_dirs, 4);
        assert_eq!(metrics.freed_bytes, 2 * 1024 * 1024);
        assert!((metrics.free_before_gb - (4096.0 / (1024.0 * 1024.0))).abs() < f64::EPSILON);
        assert!((metrics.free_after_gb - (6144.0 / (1024.0 * 1024.0))).abs() < f64::EPSILON);
        assert!(metrics.low_disk_mode);
    }

    #[test]
    fn test_build_cleanup_command_contains_threshold_and_marker() {
        let _guard = test_guard!();
        let command = build_cleanup_command("'/tmp/rch'", 72, 10);
        assert!(command.contains("threshold_kb=10485760"));
        assert!(command.contains("active_grace_minutes=5"));
        assert!(command.contains("-mmin -\"$active_grace_minutes\""));
        assert!(command.contains("case \"$dir\" in \"$base\"/*)"));
        assert!(command.contains("RCH_CLEANUP_METRICS"));
        assert!(command.contains("low_disk"));
    }
}
