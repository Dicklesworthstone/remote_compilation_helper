//! Worker health monitoring with heartbeats.
//!
//! Periodically checks worker availability and updates their status.

use crate::workers::{WorkerPool, WorkerState};
use rch_common::{SshClient, SshOptions, WorkerStatus};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::time::interval;
use tracing::{debug, info, warn};

/// Default health check interval.
const DEFAULT_CHECK_INTERVAL: Duration = Duration::from_secs(30);

/// Default timeout for health check SSH connection.
const DEFAULT_CHECK_TIMEOUT: Duration = Duration::from_secs(10);

/// Threshold for degraded status (slow response).
const DEGRADED_THRESHOLD_MS: u64 = 5000;

/// Health monitor configuration.
#[derive(Debug, Clone)]
pub struct HealthConfig {
    /// Interval between health checks.
    pub check_interval: Duration,
    /// Timeout for each health check.
    pub check_timeout: Duration,
    /// Threshold for marking worker as degraded (ms).
    pub degraded_threshold_ms: u64,
    /// Number of consecutive failures before marking unreachable.
    pub failure_threshold: u32,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            check_interval: DEFAULT_CHECK_INTERVAL,
            check_timeout: DEFAULT_CHECK_TIMEOUT,
            degraded_threshold_ms: DEGRADED_THRESHOLD_MS,
            failure_threshold: 3,
        }
    }
}

/// Result of a single health check.
#[derive(Debug, Clone)]
pub struct HealthCheckResult {
    /// Whether the check succeeded.
    pub healthy: bool,
    /// Response time in milliseconds.
    pub response_time_ms: u64,
    /// Error message if failed.
    pub error: Option<String>,
    /// Timestamp of the check.
    #[allow(dead_code)] // May be used for monitoring metrics
    pub checked_at: Instant,
}

impl HealthCheckResult {
    fn success(response_time_ms: u64) -> Self {
        Self {
            healthy: true,
            response_time_ms,
            error: None,
            checked_at: Instant::now(),
        }
    }

    fn failure(error: String) -> Self {
        Self {
            healthy: false,
            response_time_ms: 0,
            error: Some(error),
            checked_at: Instant::now(),
        }
    }
}

/// Worker health state tracking.
#[derive(Debug)]
pub struct WorkerHealth {
    /// Consecutive failure count.
    consecutive_failures: u32,
    /// Last health check result.
    last_result: Option<HealthCheckResult>,
    /// Current status.
    current_status: WorkerStatus,
}

impl Default for WorkerHealth {
    fn default() -> Self {
        Self {
            consecutive_failures: 0,
            last_result: None,
            current_status: WorkerStatus::Healthy,
        }
    }
}

impl WorkerHealth {
    /// Update health state based on check result.
    pub fn update(&mut self, result: HealthCheckResult, config: &HealthConfig) {
        if result.healthy {
            self.consecutive_failures = 0;

            // Check if response is slow (degraded)
            if result.response_time_ms > config.degraded_threshold_ms {
                self.current_status = WorkerStatus::Degraded;
            } else {
                self.current_status = WorkerStatus::Healthy;
            }
        } else {
            self.consecutive_failures += 1;

            if self.consecutive_failures >= config.failure_threshold {
                self.current_status = WorkerStatus::Unreachable;
            } else {
                // Still trying, keep current status unless already unreachable
                if self.current_status != WorkerStatus::Unreachable {
                    self.current_status = WorkerStatus::Degraded;
                }
            }
        }

        self.last_result = Some(result);
    }

    /// Get current status.
    pub fn status(&self) -> WorkerStatus {
        self.current_status
    }

    /// Get last check result.
    #[allow(dead_code)] // Will be used by status API
    pub fn last_result(&self) -> Option<&HealthCheckResult> {
        self.last_result.as_ref()
    }
}

/// Health monitor that periodically checks all workers.
pub struct HealthMonitor {
    /// Worker pool to monitor.
    pool: WorkerPool,
    /// Configuration.
    config: HealthConfig,
    /// Health state per worker.
    health_states: Arc<RwLock<std::collections::HashMap<String, WorkerHealth>>>,
    /// Whether monitor is running.
    running: Arc<RwLock<bool>>,
}

impl HealthMonitor {
    /// Create a new health monitor.
    pub fn new(pool: WorkerPool, config: HealthConfig) -> Self {
        Self {
            pool,
            config,
            health_states: Arc::new(RwLock::new(std::collections::HashMap::new())),
            running: Arc::new(RwLock::new(false)),
        }
    }

    /// Start the health monitoring background task.
    pub fn start(&self) -> tokio::task::JoinHandle<()> {
        let pool = self.pool.clone();
        let config = self.config.clone();
        let health_states = self.health_states.clone();
        let running = self.running.clone();

        tokio::spawn(async move {
            *running.write().await = true;
            let mut ticker = interval(config.check_interval);

            info!(
                "Health monitor started (interval: {:?})",
                config.check_interval
            );

            loop {
                ticker.tick().await;

                if !*running.read().await {
                    info!("Health monitor stopping");
                    break;
                }

                // Check ALL workers (not just healthy) so unreachable workers can recover
                let workers = pool.all_workers().await;
                debug!("Checking health of {} workers", workers.len());

                for worker in workers {
                    let worker_id = worker.config.id.as_str().to_string();
                    let result = check_worker_health(&worker, &config).await;

                    // Update health state
                    let mut states = health_states.write().await;
                    let health = states.entry(worker_id.clone()).or_default();
                    health.update(result.clone(), &config);

                    // Log status changes
                    let new_status = health.status();
                    if result.healthy {
                        debug!(
                            "Worker {} healthy ({}ms)",
                            worker_id, result.response_time_ms
                        );
                    } else {
                        warn!(
                            "Worker {} check failed: {:?} (failures: {})",
                            worker_id, result.error, health.consecutive_failures
                        );
                    }

                    // Update worker pool status
                    pool.set_status(&worker.config.id, new_status).await;
                }
            }
        })
    }

    /// Stop the health monitor.
    #[allow(dead_code)] // Will be used for graceful shutdown
    pub async fn stop(&self) {
        *self.running.write().await = false;
    }

    /// Get health state for a worker.
    #[allow(dead_code)] // Will be used by status API
    pub async fn get_health(&self, worker_id: &str) -> Option<WorkerStatus> {
        let states = self.health_states.read().await;
        states.get(worker_id).map(|h| h.status())
    }

    /// Get all health states.
    #[allow(dead_code)] // Will be used by status API
    pub async fn all_health_states(&self) -> Vec<(String, WorkerStatus)> {
        let states = self.health_states.read().await;
        states
            .iter()
            .map(|(id, h)| (id.clone(), h.status()))
            .collect()
    }
}

/// Check health of a single worker.
async fn check_worker_health(
    worker: &Arc<WorkerState>,
    config: &HealthConfig,
) -> HealthCheckResult {
    let start = Instant::now();

    // Create SSH connection with timeout
    let ssh_options = SshOptions {
        connect_timeout: config.check_timeout,
        command_timeout: config.check_timeout,
        control_master: false, // Don't use control master for health checks
        ..Default::default()
    };

    let mut client = SshClient::new(worker.config.clone(), ssh_options);

    // Try to connect and run a simple command
    match client.connect().await {
        Ok(()) => {
            // Run a simple echo command
            match client.execute("echo health_check").await {
                Ok(result) => {
                    let duration = start.elapsed();
                    let _ = client.disconnect().await;

                    if result.success() && result.stdout.trim() == "health_check" {
                        HealthCheckResult::success(duration.as_millis() as u64)
                    } else {
                        HealthCheckResult::failure(format!(
                            "Unexpected response: exit={}, stdout={}",
                            result.exit_code,
                            result.stdout.trim()
                        ))
                    }
                }
                Err(e) => {
                    let _ = client.disconnect().await;
                    HealthCheckResult::failure(format!("Command failed: {}", e))
                }
            }
        }
        Err(e) => HealthCheckResult::failure(format!("Connection failed: {}", e)),
    }
}

/// Perform a one-time health check on a worker.
#[allow(dead_code)] // Will be used by workers probe command
pub async fn probe_worker(worker: &WorkerState) -> HealthCheckResult {
    let config = HealthConfig::default();
    let worker_arc = Arc::new(WorkerState::new(worker.config.clone()));
    check_worker_health(&worker_arc, &config).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_config_default() {
        let config = HealthConfig::default();
        assert_eq!(config.check_interval, Duration::from_secs(30));
        assert_eq!(config.failure_threshold, 3);
    }

    #[test]
    fn test_health_check_result_success() {
        let result = HealthCheckResult::success(100);
        assert!(result.healthy);
        assert_eq!(result.response_time_ms, 100);
        assert!(result.error.is_none());
    }

    #[test]
    fn test_health_check_result_failure() {
        let result = HealthCheckResult::failure("Connection timeout".to_string());
        assert!(!result.healthy);
        assert!(result.error.is_some());
    }

    #[test]
    fn test_worker_health_update_success() {
        let config = HealthConfig::default();
        let mut health = WorkerHealth::default();

        // Successful check
        let result = HealthCheckResult::success(100);
        health.update(result, &config);
        assert_eq!(health.status(), WorkerStatus::Healthy);
        assert_eq!(health.consecutive_failures, 0);
    }

    #[test]
    fn test_worker_health_update_degraded() {
        let config = HealthConfig::default();
        let mut health = WorkerHealth::default();

        // Slow response (degraded)
        let result = HealthCheckResult::success(6000); // Over threshold
        health.update(result, &config);
        assert_eq!(health.status(), WorkerStatus::Degraded);
    }

    #[test]
    fn test_worker_health_update_unreachable() {
        let config = HealthConfig {
            failure_threshold: 3,
            ..Default::default()
        };
        let mut health = WorkerHealth::default();

        // Multiple failures
        for _ in 0..3 {
            let result = HealthCheckResult::failure("Connection failed".to_string());
            health.update(result, &config);
        }

        assert_eq!(health.status(), WorkerStatus::Unreachable);
        assert_eq!(health.consecutive_failures, 3);
    }

    #[test]
    fn test_worker_health_recovery() {
        let config = HealthConfig::default();
        let mut health = WorkerHealth::default();

        // Fail twice
        for _ in 0..2 {
            let result = HealthCheckResult::failure("Error".to_string());
            health.update(result, &config);
        }
        assert_eq!(health.consecutive_failures, 2);

        // Then succeed
        let result = HealthCheckResult::success(100);
        health.update(result, &config);
        assert_eq!(health.status(), WorkerStatus::Healthy);
        assert_eq!(health.consecutive_failures, 0);
    }
}
