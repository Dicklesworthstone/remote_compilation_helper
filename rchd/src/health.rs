//! Worker health monitoring with heartbeats.
//!
//! Periodically checks worker availability and updates their status.

#![allow(dead_code)] // Scaffold code - methods will be used in future beads

use crate::alerts::AlertManager;
use crate::metrics;
use crate::ui::workers::WorkerStatusPanel;
use crate::workers::{WorkerPool, WorkerState};
use rch_common::mock::{self, MockConfig, MockSshClient};
use rch_common::{
    CircuitBreakerConfig, CircuitState, CircuitStats, SshClient, SshOptions, WorkerStatus,
};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, RwLock};
use tokio::time::interval;
use tracing::{debug, info, warn};

fn is_mock_transport(_worker: &WorkerState) -> bool {
    // In mock mode, we assume mock config is active
    // We can't easily check worker.config without async lock here,
    // but if mock is enabled globally that's enough
    mock::is_mock_enabled()
}

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
    /// Circuit breaker configuration.
    pub circuit: CircuitBreakerConfig,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            check_interval: DEFAULT_CHECK_INTERVAL,
            check_timeout: DEFAULT_CHECK_TIMEOUT,
            degraded_threshold_ms: DEGRADED_THRESHOLD_MS,
            failure_threshold: 3,
            circuit: CircuitBreakerConfig::default(),
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

    /// Record metrics for this health check result.
    fn record_metrics(&self, worker_id: &str) {
        if self.healthy {
            // Record latency histogram
            metrics::observe_worker_latency(worker_id, self.response_time_ms as f64);
            // Update last seen timestamp
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs_f64())
                .unwrap_or(0.0);
            metrics::set_worker_last_seen(worker_id, now);
        }
    }
}

/// Worker health state tracking with circuit breaker integration.
#[derive(Debug)]
pub struct WorkerHealth {
    /// Last health check result.
    last_result: Option<HealthCheckResult>,
    /// Current worker status.
    current_status: WorkerStatus,
    /// Circuit breaker statistics for this worker.
    circuit: CircuitStats,
    /// Last error message (for diagnostics).
    last_error: Option<String>,
}

impl Default for WorkerHealth {
    fn default() -> Self {
        Self {
            last_result: None,
            current_status: WorkerStatus::Healthy,
            circuit: CircuitStats::new(),
            last_error: None,
        }
    }
}

impl WorkerHealth {
    /// Create a new WorkerHealth with default state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Update health state based on check result.
    ///
    /// This drives circuit breaker state transitions based on health check outcomes:
    /// - On success: records success, may close half-open circuit
    /// - On failure: records failure, may open circuit
    pub fn update(&mut self, result: HealthCheckResult, config: &HealthConfig, worker_id: &str) {
        let prior_circuit_state = self.circuit.state();

        if result.healthy {
            // Record success in circuit stats
            self.circuit.record_success();
            self.last_error = None;

            // Check if circuit should close (half-open -> closed)
            if self.circuit.should_close(&config.circuit) {
                info!(
                    "Worker {} circuit closing: {} consecutive successes",
                    worker_id, config.circuit.success_threshold
                );
                self.circuit.close();
            }
        } else {
            // Record failure in circuit stats
            self.circuit.record_failure();
            self.last_error = result.error.clone();

            // Check if circuit should open (closed -> open)
            if self.circuit.should_open(&config.circuit) {
                info!(
                    "Worker {} circuit opening: {} consecutive failures",
                    worker_id,
                    self.circuit.consecutive_failures()
                );
                self.circuit.open();
            } else if self.circuit.state() == CircuitState::HalfOpen {
                // Failure in half-open means reopen circuit
                info!(
                    "Worker {} circuit reopening: probe failed in half-open state",
                    worker_id
                );
                self.circuit.open();
            }
        }

        // Check if circuit should transition to half-open (open -> half-open)
        if self.circuit.state() == CircuitState::Open
            && self.circuit.should_half_open(&config.circuit)
        {
            info!(
                "Worker {} circuit transitioning to half-open: cooldown elapsed",
                worker_id
            );
            self.circuit.half_open();
        }

        // Determine status based on circuit state and check result
        self.current_status = match self.circuit.state() {
            CircuitState::Open => WorkerStatus::Unreachable,
            CircuitState::HalfOpen => WorkerStatus::Degraded,
            CircuitState::Closed => {
                if !result.healthy {
                    // Failed but circuit not open yet -> Degraded
                    WorkerStatus::Degraded
                } else if result.response_time_ms > config.degraded_threshold_ms {
                    // Slow response -> Degraded
                    WorkerStatus::Degraded
                } else {
                    // Healthy and fast
                    WorkerStatus::Healthy
                }
            }
        };

        // Log state transitions
        let new_circuit_state = self.circuit.state();
        if prior_circuit_state != new_circuit_state {
            info!(
                "Worker {} circuit state: {:?} -> {:?}",
                worker_id, prior_circuit_state, new_circuit_state
            );
        }

        self.last_result = Some(result);
    }

    /// Get current worker status.
    pub fn status(&self) -> WorkerStatus {
        self.current_status
    }

    /// Get current circuit state.
    pub fn circuit_state(&self) -> CircuitState {
        self.circuit.state()
    }

    /// Get circuit statistics.
    pub fn circuit_stats(&self) -> &CircuitStats {
        &self.circuit
    }

    /// Get last check result.
    #[allow(dead_code)] // Will be used by status API
    pub fn last_result(&self) -> Option<&HealthCheckResult> {
        self.last_result.as_ref()
    }

    /// Get last error message.
    pub fn last_error(&self) -> Option<&str> {
        self.last_error.as_deref()
    }

    /// Check if this worker can be used for a probe in half-open state.
    pub fn can_probe(&self, config: &HealthConfig) -> bool {
        self.circuit.can_probe(&config.circuit)
    }

    /// Start a probe request (call when sending a request to half-open circuit).
    pub fn start_probe(&mut self, config: &HealthConfig) -> bool {
        self.circuit.start_probe(&config.circuit)
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
    /// Optional worker status panel for log output.
    status_panel: Option<Arc<Mutex<WorkerStatusPanel>>>,
    /// Optional alert manager for worker health alerting.
    alert_manager: Option<Arc<AlertManager>>,
}

impl HealthMonitor {
    /// Create a new health monitor.
    pub fn new(pool: WorkerPool, config: HealthConfig) -> Self {
        Self {
            pool,
            config,
            health_states: Arc::new(RwLock::new(std::collections::HashMap::new())),
            running: Arc::new(RwLock::new(false)),
            status_panel: None,
            alert_manager: None,
        }
    }

    /// Attach a worker status panel for periodic output.
    #[must_use]
    pub fn with_status_panel(mut self, panel: Arc<Mutex<WorkerStatusPanel>>) -> Self {
        self.status_panel = Some(panel);
        self
    }

    /// Attach an alert manager for worker health alerting.
    #[must_use]
    pub fn with_alert_manager(mut self, alert_manager: Arc<AlertManager>) -> Self {
        self.alert_manager = Some(alert_manager);
        self
    }

    /// Start the health monitoring background task.
    pub fn start(&self) -> tokio::task::JoinHandle<()> {
        let pool = self.pool.clone();
        let config = self.config.clone();
        let health_states = self.health_states.clone();
        let running = self.running.clone();
        let status_panel = self.status_panel.clone();
        let alert_manager = self.alert_manager.clone();

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

                // Track unreachable count for all-workers-offline alert
                let total_workers = workers.len();
                let mut unreachable_count = 0;

                for worker in workers {
                    let worker_config_guard = worker.config.read().await;
                    let worker_id = worker_config_guard.id.as_str().to_string();
                    let total_slots = worker_config_guard.total_slots;
                    // Drop lock before check_worker_health to avoid holding it during IO
                    drop(worker_config_guard);

                    let result = check_worker_health(&worker, &config).await;

                    // Record health check latency metric
                    if result.healthy {
                        metrics::observe_worker_latency(&worker_id, result.response_time_ms as f64);
                        // Update last seen timestamp
                        let now = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .map(|d| d.as_secs_f64())
                            .unwrap_or(0.0);
                        metrics::set_worker_last_seen(&worker_id, now);
                    }

                    // Update health state, tracking previous status for alerting
                    let mut states = health_states.write().await;
                    let health = states.entry(worker_id.clone()).or_default();
                    let previous_status = health.status();
                    let previous_circuit_state = health.circuit_state();
                    health.update(result.clone(), &config, &worker_id);

                    if result.healthy {
                        worker
                            .set_last_latency_ms(Some(result.response_time_ms))
                            .await;
                    } else {
                        worker.set_last_latency_ms(None).await;
                    }

                    // Log status changes
                    let new_status = health.status();
                    let new_circuit_state = health.circuit_state();

                    // Track unreachable workers for all-workers-offline alert
                    if new_status == WorkerStatus::Unreachable {
                        unreachable_count += 1;
                    }

                    // Notify alert manager of status changes and circuit state changes
                    if let Some(ref alert_mgr) = alert_manager {
                        // Status change notification
                        if previous_status != new_status {
                            alert_mgr.handle_worker_status_change(
                                &worker_id,
                                previous_status,
                                new_status,
                                health.last_error(),
                            );
                        }

                        // Circuit breaker opened notification
                        if previous_circuit_state != CircuitState::Open
                            && new_circuit_state == CircuitState::Open
                        {
                            alert_mgr.handle_circuit_open(&worker_id);
                        }
                    }

                    // Record worker status metric
                    let status_value = match new_status {
                        WorkerStatus::Healthy => 1.0,
                        WorkerStatus::Degraded => 2.0,
                        WorkerStatus::Draining => 2.0,
                        WorkerStatus::Unreachable => 0.0,
                        WorkerStatus::Disabled => 0.0,
                    };
                    metrics::set_worker_status(&worker_id, "current", status_value);

                    // Record circuit breaker state
                    let circuit_value = match new_circuit_state {
                        CircuitState::Closed => 0,
                        CircuitState::HalfOpen => 1,
                        CircuitState::Open => 2,
                    };
                    metrics::set_circuit_state(&worker_id, circuit_value);

                    // Record slot metrics
                    metrics::set_worker_slots_total(&worker_id, total_slots);
                    metrics::set_worker_slots_available(&worker_id, worker.available_slots().await);
                    if result.healthy {
                        debug!(
                            "Worker {} healthy ({}ms)",
                            worker_id, result.response_time_ms
                        );

                        // Probe capabilities after successful health check
                        // This runs in the background to avoid slowing down health checks
                        let worker_clone = worker.clone();
                        let timeout = config.check_timeout;
                        tokio::spawn(async move {
                            if let Some(capabilities) =
                                probe_worker_capabilities(&worker_clone, timeout).await
                            {
                                worker_clone.set_capabilities(capabilities).await;
                            }
                        });
                    } else {
                        warn!(
                            "Worker {} check failed: {:?} (failures: {})",
                            worker_id,
                            result.error,
                            health.circuit_stats().consecutive_failures()
                        );
                    }

                    // Update worker pool status
                    let worker_config = worker.config.read().await;
                    pool.set_status(&worker_config.id, new_status).await;
                }

                // Check for all-workers-offline condition
                if let Some(ref alert_mgr) = alert_manager {
                    alert_mgr.handle_all_workers_offline(total_workers, unreachable_count);
                }

                if let Some(panel) = &status_panel {
                    let snapshot = WorkerStatusPanel::collect_snapshot(&pool).await;
                    let mut panel = panel.lock().await;
                    panel.emit_update(&snapshot, 0);
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

    // Debug: log mock mode status and env var
    let mock_env = std::env::var("RCH_MOCK_SSH").unwrap_or_default();
    let mock_enabled = is_mock_transport(worker);
    let worker_config = worker.config.read().await;

    debug!(
        "Health check for {}: mock_enabled={}, RCH_MOCK_SSH='{}', host='{}'",
        worker_config.id, mock_enabled, mock_env, worker_config.host
    );

    if mock_enabled {
        let mut client = MockSshClient::new(worker_config.clone(), MockConfig::from_env());
        match client.connect().await {
            Ok(()) => match client.execute("echo health_check").await {
                Ok(result) => {
                    let duration = start.elapsed();
                    let _ = client.disconnect().await;
                    if result.success() && result.stdout.trim() == "health_check" {
                        return HealthCheckResult::success(duration.as_millis() as u64);
                    }
                    return HealthCheckResult::failure(format!(
                        "Unexpected response: exit={}, stdout={}",
                        result.exit_code,
                        result.stdout.trim()
                    ));
                }
                Err(e) => {
                    let _ = client.disconnect().await;
                    return HealthCheckResult::failure(format!("Command failed: {}", e));
                }
            },
            Err(e) => return HealthCheckResult::failure(format!("Connection failed: {}", e)),
        }
    }

    // Create SSH connection with timeout
    let ssh_options = SshOptions {
        connect_timeout: config.check_timeout,
        command_timeout: config.check_timeout,
        control_master: false, // Don't use control master for health checks
        ..Default::default()
    };

    let mut client = SshClient::new(worker_config.clone(), ssh_options);

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
    // Wrap in Arc for compatibility
    let config_clone = worker.config.read().await.clone();
    let worker_arc = Arc::new(WorkerState::new(config_clone));
    check_worker_health(&worker_arc, &config).await
}

/// Probe worker capabilities (Bun, Node, Rust versions).
///
/// Runs `rch-wkr capabilities` on the worker and parses the JSON output.
/// Returns None if probing fails (worker continues without capability info).
pub async fn probe_worker_capabilities(
    worker: &Arc<WorkerState>,
    timeout: Duration,
) -> Option<rch_common::WorkerCapabilities> {
    use rch_common::{SshClient, SshOptions, WorkerCapabilities};

    let worker_config = worker.config.read().await;

    // Check if mock mode is enabled
    if is_mock_transport(worker) {
        // In mock mode, return mock capabilities that include Rust
        // (so mock workers can be selected for Rust compilation)
        debug!(
            "Worker {} capabilities probe: mock mode, returning mock capabilities",
            worker_config.id
        );
        return Some(WorkerCapabilities::mock_with_rust());
    }

    let ssh_options = SshOptions {
        connect_timeout: timeout,
        command_timeout: timeout,
        control_master: false,
        ..Default::default()
    };

    let mut client = SshClient::new(worker_config.clone(), ssh_options);

    match client.connect().await {
        Ok(()) => {
            // Try to run rch-wkr capabilities command
            match client.execute("rch-wkr capabilities 2>/dev/null").await {
                Ok(result) => {
                    let _ = client.disconnect().await;

                    if result.success() {
                        // Parse JSON output
                        match serde_json::from_str::<WorkerCapabilities>(&result.stdout) {
                            Ok(capabilities) => {
                                debug!(
                                    "Worker {} capabilities: rustc={:?}, bun={:?}, node={:?}",
                                    worker_config.id,
                                    capabilities.rustc_version,
                                    capabilities.bun_version,
                                    capabilities.node_version
                                );
                                return Some(capabilities);
                            }
                            Err(e) => {
                                debug!(
                                    "Worker {} capabilities JSON parse failed: {} (output: {})",
                                    worker_config.id,
                                    e,
                                    result.stdout.trim()
                                );
                            }
                        }
                    } else {
                        // rch-wkr might not be installed yet, that's OK
                        debug!(
                            "Worker {} capabilities probe failed (rch-wkr may not be installed): exit={}",
                            worker_config.id, result.exit_code
                        );
                    }
                }
                Err(e) => {
                    let _ = client.disconnect().await;
                    debug!(
                        "Worker {} capabilities probe command failed: {}",
                        worker_config.id, e
                    );
                }
            }
        }
        Err(e) => {
            debug!(
                "Worker {} capabilities probe connection failed: {}",
                worker_config.id, e
            );
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use rch_common::mock::{
        clear_mock_overrides, set_mock_enabled_override, set_mock_ssh_config_override,
    };
    use rch_common::test_guard;
    use rch_common::{WorkerConfig, WorkerId};
    use std::sync::OnceLock;

    fn test_lock() -> &'static Mutex<()> {
        static ENV_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();
        ENV_MUTEX.get_or_init(|| Mutex::new(()))
    }

    struct MockOverrideGuard;

    impl MockOverrideGuard {
        fn set_failure() -> Self {
            set_mock_enabled_override(Some(true));
            set_mock_ssh_config_override(Some(MockConfig::connection_failure()));
            Self
        }
    }

    impl Drop for MockOverrideGuard {
        fn drop(&mut self) {
            clear_mock_overrides();
        }
    }

    #[test]
    fn test_health_config_default() {
        let _guard = test_guard!();
        let config = HealthConfig::default();
        assert_eq!(config.check_interval, Duration::from_secs(30));
        assert_eq!(config.failure_threshold, 3);
    }

    #[test]
    fn test_health_check_result_success() {
        let _guard = test_guard!();
        let result = HealthCheckResult::success(100);
        assert!(result.healthy);
        assert_eq!(result.response_time_ms, 100);
        assert!(result.error.is_none());
    }

    #[test]
    fn test_health_check_result_failure() {
        let _guard = test_guard!();
        let result = HealthCheckResult::failure("Connection timeout".to_string());
        assert!(!result.healthy);
        assert!(result.error.is_some());
    }

    #[test]
    fn test_worker_health_update_success() {
        let _guard = test_guard!();
        let config = HealthConfig::default();
        let mut health = WorkerHealth::default();

        // Successful check
        let result = HealthCheckResult::success(100);
        health.update(result, &config, "test-worker");
        assert_eq!(health.status(), WorkerStatus::Healthy);
        assert_eq!(health.circuit_stats().consecutive_failures(), 0);
    }

    #[test]
    fn test_worker_health_update_degraded() {
        let _guard = test_guard!();
        let config = HealthConfig::default();
        let mut health = WorkerHealth::default();

        // Slow response (degraded)
        let result = HealthCheckResult::success(6000); // Over threshold
        health.update(result, &config, "test-worker");
        assert_eq!(health.status(), WorkerStatus::Degraded);
    }

    #[test]
    fn test_worker_health_update_unreachable() {
        let _guard = test_guard!();
        let config = HealthConfig {
            failure_threshold: 3,
            ..Default::default()
        };
        let mut health = WorkerHealth::default();

        // Multiple failures
        for _ in 0..3 {
            let result = HealthCheckResult::failure("Connection failed".to_string());
            health.update(result, &config, "test-worker");
        }

        assert_eq!(health.status(), WorkerStatus::Unreachable);
        assert_eq!(health.circuit_stats().consecutive_failures(), 3);
    }

    #[test]
    fn test_worker_health_recovery() {
        let _guard = test_guard!();
        let config = HealthConfig::default();
        let mut health = WorkerHealth::default();

        // Fail twice
        for _ in 0..2 {
            let result = HealthCheckResult::failure("Error".to_string());
            health.update(result, &config, "test-worker");
        }
        assert_eq!(health.circuit_stats().consecutive_failures(), 2);

        // Then succeed
        let result = HealthCheckResult::success(100);
        health.update(result, &config, "test-worker");
        assert_eq!(health.status(), WorkerStatus::Healthy);
        assert_eq!(health.circuit_stats().consecutive_failures(), 0);
    }

    #[test]
    fn test_circuit_opens_on_failure_threshold() {
        let _guard = test_guard!();
        let config = HealthConfig {
            circuit: CircuitBreakerConfig {
                failure_threshold: 3,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut health = WorkerHealth::default();

        // Initial state is closed
        assert_eq!(health.circuit_state(), CircuitState::Closed);

        // Fail up to threshold
        for i in 0..3 {
            let result = HealthCheckResult::failure("Connection failed".to_string());
            health.update(result, &config, "test-worker");
            if i < 2 {
                // Circuit still closed before threshold
                assert_eq!(health.circuit_state(), CircuitState::Closed);
            }
        }

        // Circuit should now be open
        assert_eq!(health.circuit_state(), CircuitState::Open);
        assert_eq!(health.status(), WorkerStatus::Unreachable);
    }

    #[test]
    fn test_circuit_transitions_to_half_open() {
        let _guard = test_guard!();
        let config = HealthConfig {
            circuit: CircuitBreakerConfig {
                failure_threshold: 2,
                open_cooldown_secs: 0, // Instant cooldown for testing
                ..Default::default()
            },
            ..Default::default()
        };
        let mut health = WorkerHealth::default();

        // With open_cooldown_secs=0, the circuit opens then immediately transitions
        // to half-open in the same update() call when should_half_open() is checked.
        for _ in 0..2 {
            let result = HealthCheckResult::failure("Error".to_string());
            health.update(result, &config, "test-worker");
        }
        // With cooldown=0, we go straight to HalfOpen after opening
        assert_eq!(health.circuit_state(), CircuitState::HalfOpen);
    }

    #[test]
    fn test_circuit_closes_after_success_in_half_open() {
        let _guard = test_guard!();
        let config = HealthConfig {
            circuit: CircuitBreakerConfig {
                failure_threshold: 2,
                success_threshold: 2,
                open_cooldown_secs: 0,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut health = WorkerHealth::default();

        // Open and transition to half-open
        for _ in 0..2 {
            let result = HealthCheckResult::failure("Error".to_string());
            health.update(result, &config, "test-worker");
        }
        // Trigger half-open transition
        let result = HealthCheckResult::success(50);
        health.update(result, &config, "test-worker");
        assert_eq!(health.circuit_state(), CircuitState::HalfOpen);

        // One more success should close circuit (success_threshold=2)
        let result = HealthCheckResult::success(50);
        health.update(result, &config, "test-worker");
        assert_eq!(health.circuit_state(), CircuitState::Closed);
        assert_eq!(health.status(), WorkerStatus::Healthy);
    }

    #[test]
    fn test_circuit_reopens_on_failure_in_half_open() {
        let _guard = test_guard!();
        // Use two configs: one with cooldown=0 to quickly get to half-open,
        // then one with longer cooldown to verify reopen stays open
        let config_fast = HealthConfig {
            circuit: CircuitBreakerConfig {
                failure_threshold: 2,
                open_cooldown_secs: 0,
                ..Default::default()
            },
            ..Default::default()
        };
        let config_slow = HealthConfig {
            circuit: CircuitBreakerConfig {
                failure_threshold: 2,
                open_cooldown_secs: 60, // Long cooldown so circuit stays open
                ..Default::default()
            },
            ..Default::default()
        };
        let mut health = WorkerHealth::default();

        // Open and transition to half-open (with fast cooldown)
        for _ in 0..2 {
            let result = HealthCheckResult::failure("Error".to_string());
            health.update(result, &config_fast, "test-worker");
        }
        // With cooldown=0, we're now in HalfOpen
        assert_eq!(health.circuit_state(), CircuitState::HalfOpen);

        // Failure in half-open should reopen circuit (use slow config so it stays open)
        let result = HealthCheckResult::failure("Failed again".to_string());
        health.update(result, &config_slow, "test-worker");
        assert_eq!(health.circuit_state(), CircuitState::Open);
        assert_eq!(health.status(), WorkerStatus::Unreachable);
    }

    #[test]
    fn test_circuit_stats_accessors() {
        let _guard = test_guard!();
        let config = HealthConfig::default();
        let mut health = WorkerHealth::default();

        // Initially no error
        assert!(health.last_error().is_none());

        // After failure, error is stored
        let result = HealthCheckResult::failure("Test error message".to_string());
        health.update(result, &config, "test-worker");
        assert_eq!(health.last_error(), Some("Test error message"));

        // After success, error is cleared
        let result = HealthCheckResult::success(50);
        health.update(result, &config, "test-worker");
        assert!(health.last_error().is_none());
    }

    #[tokio::test]
    async fn test_check_worker_health_mock_failure() {
        let _lock = test_lock().lock().await;
        let _overrides = MockOverrideGuard::set_failure();

        let worker = WorkerState::new(WorkerConfig {
            id: WorkerId::new("mock-fail"),
            host: "mock.host".to_string(),
            user: "mockuser".to_string(),
            identity_file: "~/.ssh/mock".to_string(),
            total_slots: 4,
            priority: 100,
            tags: vec![],
        });

        let result = check_worker_health(&Arc::new(worker), &HealthConfig::default()).await;
        assert!(!result.healthy);
    }

    // ============================================================================
    // Integration tests: Health monitoring -> Circuit breaker -> Worker selection
    // ============================================================================

    mod integration_tests {
        use super::*;
        use crate::selection::{SelectionWeights, select_worker_with_config};
        use crate::workers::WorkerPool;
        use rch_common::{CommandPriority, RequiredRuntime, SelectionRequest};

        fn make_worker_config(id: &str) -> WorkerConfig {
            WorkerConfig {
                id: WorkerId::new(id),
                host: format!("{}.host", id),
                user: "testuser".to_string(),
                identity_file: "~/.ssh/test".to_string(),
                total_slots: 8,
                priority: 100,
                tags: vec![],
            }
        }

        fn make_request(project: &str, cores: u32) -> SelectionRequest {
            SelectionRequest {
                project: project.to_string(),
                command: None,
                command_priority: CommandPriority::Normal,
                estimated_cores: cores,
                preferred_workers: vec![],
                toolchain: None,
                required_runtime: RequiredRuntime::default(),
                classification_duration_us: None,
                hook_pid: None,
            }
        }

        #[tokio::test]
        async fn test_integration_health_failures_cause_selection_exclusion() {
            // Test that health failures leading to open circuit cause worker to be
            // excluded from selection, and when all workers are in open state,
            // selection returns AllCircuitsOpen.

            let pool = WorkerPool::new();
            pool.add_worker(make_worker_config("worker-1")).await;
            pool.add_worker(make_worker_config("worker-2")).await;

            let health_config = HealthConfig {
                circuit: CircuitBreakerConfig {
                    failure_threshold: 3,
                    ..Default::default()
                },
                ..Default::default()
            };
            let weights = SelectionWeights::default();
            let request = make_request("test-project", 2);

            // Initially, selection should succeed
            let result =
                select_worker_with_config(&pool, &request, &weights, &health_config.circuit).await;
            assert!(result.worker.is_some());
            assert_eq!(result.reason, rch_common::SelectionReason::Success);

            // Simulate consecutive failures on worker-1 to open its circuit
            let worker1 = pool.get(&WorkerId::new("worker-1")).await.unwrap();
            for _ in 0..3 {
                worker1
                    .record_failure(Some("Connection timeout".to_string()))
                    .await;
            }
            // Manually check if circuit should open and transition
            if worker1.should_open_circuit(&health_config.circuit).await {
                worker1.open_circuit().await;
            }

            // Selection should still work (worker-2 is available)
            let result =
                select_worker_with_config(&pool, &request, &weights, &health_config.circuit).await;
            assert!(result.worker.is_some());
            let selected = result.worker.unwrap();
            assert_eq!(selected.config.read().await.id.as_str(), "worker-2");

            // Now fail worker-2 as well
            let worker2 = pool.get(&WorkerId::new("worker-2")).await.unwrap();
            for _ in 0..3 {
                worker2
                    .record_failure(Some("Connection timeout".to_string()))
                    .await;
            }
            if worker2.should_open_circuit(&health_config.circuit).await {
                worker2.open_circuit().await;
            }

            // Both circuits open - selection should return AllCircuitsOpen
            let result =
                select_worker_with_config(&pool, &request, &weights, &health_config.circuit).await;
            assert!(result.worker.is_none());
            assert_eq!(result.reason, rch_common::SelectionReason::AllCircuitsOpen);
        }

        #[tokio::test]
        async fn test_integration_circuit_recovery_path() {
            // Test full recovery: Open -> HalfOpen -> Closed
            // Verify selection behavior at each stage.

            let pool = WorkerPool::new();
            pool.add_worker(make_worker_config("recovery-worker")).await;

            let health_config = HealthConfig {
                circuit: CircuitBreakerConfig {
                    failure_threshold: 2,
                    success_threshold: 2,
                    open_cooldown_secs: 0, // Immediate transition to half-open
                    half_open_max_probes: 1,
                    ..Default::default()
                },
                ..Default::default()
            };
            let weights = SelectionWeights::default();
            let request = make_request("test-project", 2);

            let worker = pool.get(&WorkerId::new("recovery-worker")).await.unwrap();

            // Stage 1: Circuit is Closed
            assert_eq!(worker.circuit_state().await.unwrap(), CircuitState::Closed);
            let result =
                select_worker_with_config(&pool, &request, &weights, &health_config.circuit).await;
            assert!(result.worker.is_some());

            // Stage 2: Cause failures to open circuit
            for _ in 0..2 {
                worker.record_failure(Some("Error".to_string())).await;
            }
            if worker.should_open_circuit(&health_config.circuit).await {
                worker.open_circuit().await;
            }
            assert_eq!(worker.circuit_state().await.unwrap(), CircuitState::Open);

            // Stage 3: Transition to half-open (cooldown=0)
            if worker.should_half_open(&health_config.circuit).await {
                worker.half_open_circuit().await;
            }
            assert_eq!(
                worker.circuit_state().await.unwrap(),
                CircuitState::HalfOpen
            );

            // Stage 4: Selection should work in half-open with probe budget
            let result =
                select_worker_with_config(&pool, &request, &weights, &health_config.circuit).await;
            assert!(result.worker.is_some());

            // Stage 5: Record successes to close circuit
            worker.record_success().await;
            worker.record_success().await;
            if worker.should_close_circuit(&health_config.circuit).await {
                worker.close_circuit().await;
            }
            assert_eq!(worker.circuit_state().await.unwrap(), CircuitState::Closed);

            // Stage 6: Selection works normally again
            let result =
                select_worker_with_config(&pool, &request, &weights, &health_config.circuit).await;
            assert!(result.worker.is_some());
            assert_eq!(result.reason, rch_common::SelectionReason::Success);
        }

        #[tokio::test]
        async fn test_integration_half_open_probe_exhaustion() {
            // Test that when a half-open worker exhausts its probe budget,
            // it's excluded until the probe completes.

            let pool = WorkerPool::new();
            pool.add_worker(make_worker_config("probe-worker")).await;

            let circuit_config = CircuitBreakerConfig {
                failure_threshold: 2,
                open_cooldown_secs: 0,
                half_open_max_probes: 1,
                ..Default::default()
            };
            let weights = SelectionWeights::default();
            let request = make_request("test-project", 2);

            let worker = pool.get(&WorkerId::new("probe-worker")).await.unwrap();

            // Open and transition to half-open
            for _ in 0..2 {
                worker.record_failure(None).await;
            }
            worker.open_circuit().await;
            worker.half_open_circuit().await;

            // First selection should succeed and start probe
            let result1 =
                select_worker_with_config(&pool, &request, &weights, &circuit_config).await;
            assert!(result1.worker.is_some());

            // Second selection should fail (probe budget exhausted)
            let result2 =
                select_worker_with_config(&pool, &request, &weights, &circuit_config).await;
            // With only one worker and probe exhausted, should return busy/circuits open
            assert!(result2.worker.is_none());
        }

        #[tokio::test]
        async fn test_integration_mixed_circuit_states() {
            // Test selection behavior with workers in different circuit states:
            // - Worker A: Closed (healthy)
            // - Worker B: Open (excluded)
            // - Worker C: HalfOpen (available with penalty)
            // Verify that closed is preferred over half-open due to penalty.

            let pool = WorkerPool::new();
            pool.add_worker(WorkerConfig {
                id: WorkerId::new("closed-worker"),
                host: "closed.host".to_string(),
                user: "testuser".to_string(),
                identity_file: "~/.ssh/test".to_string(),
                total_slots: 8,
                priority: 100,
                tags: vec![],
            })
            .await;
            pool.add_worker(WorkerConfig {
                id: WorkerId::new("open-worker"),
                host: "open.host".to_string(),
                user: "testuser".to_string(),
                identity_file: "~/.ssh/test".to_string(),
                total_slots: 16, // More slots - would normally be preferred
                priority: 100,
                tags: vec![],
            })
            .await;
            pool.add_worker(WorkerConfig {
                id: WorkerId::new("half-open-worker"),
                host: "half-open.host".to_string(),
                user: "testuser".to_string(),
                identity_file: "~/.ssh/test".to_string(),
                total_slots: 12, // More slots than closed
                priority: 100,
                tags: vec![],
            })
            .await;

            let circuit_config = CircuitBreakerConfig {
                failure_threshold: 2,
                open_cooldown_secs: 0,
                half_open_max_probes: 10, // High limit to avoid probe exhaustion
                ..Default::default()
            };
            let weights = SelectionWeights::default();
            let request = make_request("test-project", 2);

            // Set up circuit states
            let open_worker = pool.get(&WorkerId::new("open-worker")).await.unwrap();
            open_worker.open_circuit().await;

            let half_open_worker = pool.get(&WorkerId::new("half-open-worker")).await.unwrap();
            half_open_worker.open_circuit().await;
            half_open_worker.half_open_circuit().await;

            // Selection should prefer closed-worker despite having fewer slots
            // because half-open has penalty and open is excluded
            let result =
                select_worker_with_config(&pool, &request, &weights, &circuit_config).await;
            assert!(result.worker.is_some());
            let selected = result.worker.unwrap();
            assert_eq!(selected.config.read().await.id.as_str(), "closed-worker");
        }

        #[tokio::test]
        async fn test_integration_failure_in_half_open_reopens() {
            // Test that a failure during half-open probe causes circuit to reopen.

            let pool = WorkerPool::new();
            pool.add_worker(make_worker_config("reopen-worker")).await;

            let circuit_config = CircuitBreakerConfig {
                failure_threshold: 2,
                open_cooldown_secs: 0,
                half_open_max_probes: 1,
                ..Default::default()
            };

            let worker = pool.get(&WorkerId::new("reopen-worker")).await.unwrap();

            // Transition to half-open
            worker.record_failure(None).await;
            worker.record_failure(None).await;
            worker.open_circuit().await;
            worker.half_open_circuit().await;
            assert_eq!(
                worker.circuit_state().await.unwrap(),
                CircuitState::HalfOpen
            );

            // Start a probe
            worker.start_probe(&circuit_config).await;

            // Simulate failure during probe - record failure and reopen
            worker
                .record_failure(Some("Probe failed".to_string()))
                .await;
            worker.open_circuit().await; // Failure in half-open should reopen

            assert_eq!(worker.circuit_state().await.unwrap(), CircuitState::Open);
            assert_eq!(worker.last_error().await, Some("Probe failed".to_string()));
        }

        #[tokio::test]
        async fn test_integration_health_update_drives_circuit_transitions() {
            // Test that WorkerHealth.update() correctly drives all circuit
            // state transitions based on health check results.

            let config = HealthConfig {
                circuit: CircuitBreakerConfig {
                    failure_threshold: 3,
                    success_threshold: 2,
                    open_cooldown_secs: 0, // Immediate half-open
                    ..Default::default()
                },
                ..Default::default()
            };
            let mut health = WorkerHealth::default();

            // Initial state: Closed
            assert_eq!(health.circuit_state(), CircuitState::Closed);
            assert_eq!(health.status(), WorkerStatus::Healthy);

            // Failures 1 & 2: Still closed, status degrades
            health.update(
                HealthCheckResult::failure("Error 1".to_string()),
                &config,
                "test-worker",
            );
            assert_eq!(health.circuit_state(), CircuitState::Closed);
            assert_eq!(health.status(), WorkerStatus::Degraded);

            health.update(
                HealthCheckResult::failure("Error 2".to_string()),
                &config,
                "test-worker",
            );
            assert_eq!(health.circuit_state(), CircuitState::Closed);

            // Failure 3: Circuit opens, then immediately goes to half-open
            // (since open_cooldown_secs = 0)
            health.update(
                HealthCheckResult::failure("Error 3".to_string()),
                &config,
                "test-worker",
            );
            // With cooldown=0, after opening it checks should_half_open which is true
            assert_eq!(health.circuit_state(), CircuitState::HalfOpen);
            assert_eq!(health.status(), WorkerStatus::Degraded);

            // Success 1: Still half-open
            health.update(HealthCheckResult::success(50), &config, "test-worker");
            assert_eq!(health.circuit_state(), CircuitState::HalfOpen);

            // Success 2: Circuit closes (success_threshold = 2)
            health.update(HealthCheckResult::success(50), &config, "test-worker");
            assert_eq!(health.circuit_state(), CircuitState::Closed);
            assert_eq!(health.status(), WorkerStatus::Healthy);
        }
    }
}
