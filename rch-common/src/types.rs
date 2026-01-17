//! Common types used across RCH components.

use crate::toolchain::ToolchainInfo;
use serde::{Deserialize, Serialize};

/// Unique identifier for a worker in the fleet.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WorkerId(pub String);

impl WorkerId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for WorkerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Status of a worker in the fleet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerStatus {
    /// Worker is healthy and accepting jobs.
    Healthy,
    /// Worker is responding slowly.
    Degraded,
    /// Worker failed to respond to heartbeat.
    Unreachable,
    /// Worker is not accepting new jobs (finishing current).
    Draining,
    /// Worker is manually disabled.
    Disabled,
}

/// Circuit breaker state for a worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CircuitState {
    /// Normal operation.
    Closed,
    /// Circuit is open (short-circuit).
    Open,
    /// Circuit is half-open (probing).
    HalfOpen,
}

impl Default for CircuitState {
    fn default() -> Self {
        Self::Closed
    }
}

impl Default for WorkerStatus {
    fn default() -> Self {
        Self::Healthy
    }
}

/// Worker selection request sent from hook to daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectionRequest {
    /// Project identifier (usually directory name or hash).
    pub project: String,
    /// Estimated CPU cores needed for this compilation.
    pub estimated_cores: u32,
    /// Preferred worker IDs (e.g., from project config).
    #[serde(default)]
    pub preferred_workers: Vec<WorkerId>,
    /// Rust toolchain information for the project.
    #[serde(default)]
    pub toolchain: Option<ToolchainInfo>,
}

/// Reason for worker selection result.
///
/// Provides context when no worker is available, enabling informative
/// fallback messages in the hook.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectionReason {
    /// Worker assigned successfully.
    Success,
    /// No workers configured in workers.toml.
    NoWorkersConfigured,
    /// All workers are unreachable (failed health checks).
    AllWorkersUnreachable,
    /// All workers have circuits open (after repeated failures).
    AllCircuitsOpen,
    /// All workers are at capacity (no available slots).
    AllWorkersBusy,
    /// No workers match required tags or preferences.
    NoMatchingWorkers,
    /// Internal error during selection.
    SelectionError(String),
}

impl std::fmt::Display for SelectionReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Success => write!(f, "worker assigned successfully"),
            Self::NoWorkersConfigured => write!(f, "no workers configured"),
            Self::AllWorkersUnreachable => write!(f, "all workers unreachable"),
            Self::AllCircuitsOpen => write!(f, "all worker circuits open"),
            Self::AllWorkersBusy => write!(f, "all workers at capacity"),
            Self::NoMatchingWorkers => write!(f, "no matching workers found"),
            Self::SelectionError(e) => write!(f, "selection error: {}", e),
        }
    }
}

/// Details about a selected worker for remote compilation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectedWorker {
    /// Selected worker ID.
    pub id: WorkerId,
    /// Host address for SSH.
    pub host: String,
    /// SSH user.
    pub user: String,
    /// Path to SSH identity file.
    pub identity_file: String,
    /// Number of slots available on this worker after reservation.
    pub slots_available: u32,
    /// Worker's speed score (0-100).
    pub speed_score: f64,
}

/// Worker selection response from daemon to hook.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectionResponse {
    /// Selected worker details, if available.
    pub worker: Option<SelectedWorker>,
    /// Reason for the selection result.
    pub reason: SelectionReason,
}

/// Request to release reserved worker slots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseRequest {
    /// ID of the worker to release slots on.
    pub worker_id: WorkerId,
    /// Number of slots to release.
    pub slots: u32,
}

/// Configuration for a remote worker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerConfig {
    /// Unique identifier for this worker.
    pub id: WorkerId,
    /// SSH hostname or IP address.
    pub host: String,
    /// SSH username.
    pub user: String,
    /// Path to SSH private key.
    pub identity_file: String,
    /// Total CPU slots available on this worker.
    pub total_slots: u32,
    /// Priority for worker selection (higher = preferred).
    #[serde(default = "default_priority")]
    pub priority: u32,
    /// Optional tags for filtering.
    #[serde(default)]
    pub tags: Vec<String>,
}

fn default_priority() -> u32 {
    100
}

/// RCH configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RchConfig {
    #[serde(default)]
    pub general: GeneralConfig,
    #[serde(default)]
    pub compilation: CompilationConfig,
    #[serde(default)]
    pub transfer: TransferConfig,
    #[serde(default)]
    pub circuit: CircuitBreakerConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    /// Whether RCH is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Log level (trace, debug, info, warn, error).
    #[serde(default = "default_log_level")]
    pub log_level: String,
    /// Path to Unix socket for daemon communication.
    #[serde(default = "default_socket_path")]
    pub socket_path: String,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            log_level: "info".to_string(),
            socket_path: "/tmp/rch.sock".to_string(),
        }
    }
}

/// Circuit breaker configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    /// Consecutive failures to open circuit.
    #[serde(default = "default_circuit_failure_threshold")]
    pub failure_threshold: u32,
    /// Consecutive successes to close circuit.
    #[serde(default = "default_circuit_success_threshold")]
    pub success_threshold: u32,
    /// Error rate threshold (0.0-1.0) to open circuit.
    #[serde(default = "default_circuit_error_rate_threshold")]
    pub error_rate_threshold: f64,
    /// Rolling window size in seconds.
    #[serde(default = "default_circuit_window_secs")]
    pub window_secs: u64,
    /// Cooldown duration before half-open (seconds).
    #[serde(default = "default_circuit_open_cooldown_secs")]
    pub open_cooldown_secs: u64,
    /// Max concurrent probes in half-open.
    #[serde(default = "default_circuit_half_open_max_probes")]
    pub half_open_max_probes: u32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: default_circuit_failure_threshold(),
            success_threshold: default_circuit_success_threshold(),
            error_rate_threshold: default_circuit_error_rate_threshold(),
            window_secs: default_circuit_window_secs(),
            open_cooldown_secs: default_circuit_open_cooldown_secs(),
            half_open_max_probes: default_circuit_half_open_max_probes(),
        }
    }
}

/// Circuit breaker statistics for tracking state transitions.
///
/// Maintains a rolling window of successes and failures to determine
/// when the circuit should open, close, or enter half-open state.
#[derive(Debug, Clone, Default)]
pub struct CircuitStats {
    /// Current circuit state.
    state: CircuitState,
    /// Consecutive failure count (reset on success).
    consecutive_failures: u32,
    /// Consecutive success count in half-open state (reset on failure).
    consecutive_successes: u32,
    /// Total successes in the current rolling window.
    window_successes: u32,
    /// Total failures in the current rolling window.
    window_failures: u32,
    /// Timestamp when circuit entered Open state (epoch millis).
    opened_at: Option<u64>,
    /// Timestamp of last state change (epoch millis).
    last_state_change: u64,
    /// Current active probes in half-open state.
    active_probes: u32,
}

impl CircuitStats {
    /// Create new circuit stats in the closed state.
    pub fn new() -> Self {
        Self {
            state: CircuitState::Closed,
            consecutive_failures: 0,
            consecutive_successes: 0,
            window_successes: 0,
            window_failures: 0,
            opened_at: None,
            last_state_change: Self::now_millis(),
            active_probes: 0,
        }
    }

    /// Get the current circuit state.
    pub fn state(&self) -> CircuitState {
        self.state
    }

    /// Get the timestamp when the circuit opened (if open).
    pub fn opened_at(&self) -> Option<u64> {
        self.opened_at
    }

    /// Get the timestamp of the last state change.
    pub fn last_state_change(&self) -> u64 {
        self.last_state_change
    }

    /// Get the consecutive failure count.
    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }

    /// Get the error rate in the current window (0.0-1.0).
    pub fn error_rate(&self) -> f64 {
        let total = self.window_successes + self.window_failures;
        if total == 0 {
            return 0.0;
        }
        self.window_failures as f64 / total as f64
    }

    /// Record a successful operation.
    ///
    /// In closed state: resets consecutive failures, increments window successes.
    /// In half-open state: increments consecutive successes.
    pub fn record_success(&mut self) {
        self.window_successes += 1;
        self.consecutive_failures = 0;

        if self.state == CircuitState::HalfOpen {
            self.consecutive_successes += 1;
            if self.active_probes > 0 {
                self.active_probes -= 1;
            }
        }
    }

    /// Record a failed operation.
    ///
    /// Increments consecutive failures and window failures.
    /// In half-open state, resets consecutive successes.
    pub fn record_failure(&mut self) {
        self.window_failures += 1;
        self.consecutive_failures += 1;

        if self.state == CircuitState::HalfOpen {
            self.consecutive_successes = 0;
            if self.active_probes > 0 {
                self.active_probes -= 1;
            }
        }
    }

    /// Check if the circuit should open based on config thresholds.
    ///
    /// Returns true if:
    /// - Consecutive failures exceed threshold, OR
    /// - Error rate exceeds threshold (with minimum sample size)
    pub fn should_open(&self, config: &CircuitBreakerConfig) -> bool {
        if self.state != CircuitState::Closed {
            return false;
        }

        // Open if consecutive failures exceed threshold
        if self.consecutive_failures >= config.failure_threshold {
            return true;
        }

        // Open if error rate exceeds threshold (with minimum 5 samples)
        let total = self.window_successes + self.window_failures;
        if total >= 5 && self.error_rate() >= config.error_rate_threshold {
            return true;
        }

        false
    }

    /// Check if the circuit should transition to half-open.
    ///
    /// Returns true if the circuit is open and the cooldown period has elapsed.
    pub fn should_half_open(&self, config: &CircuitBreakerConfig) -> bool {
        if self.state != CircuitState::Open {
            return false;
        }

        let now = Self::now_millis();
        let cooldown_ms = config.open_cooldown_secs * 1000;

        if let Some(opened_at) = self.opened_at {
            now.saturating_sub(opened_at) >= cooldown_ms
        } else {
            false
        }
    }

    /// Check if the circuit should close.
    ///
    /// Returns true if in half-open state and consecutive successes
    /// meet or exceed the success threshold.
    pub fn should_close(&self, config: &CircuitBreakerConfig) -> bool {
        if self.state != CircuitState::HalfOpen {
            return false;
        }

        self.consecutive_successes >= config.success_threshold
    }

    /// Check if a probe request can be made in half-open state.
    ///
    /// Returns true if active probes are below the maximum allowed.
    pub fn can_probe(&self, config: &CircuitBreakerConfig) -> bool {
        if self.state != CircuitState::HalfOpen {
            return false;
        }

        self.active_probes < config.half_open_max_probes
    }

    /// Start a probe request in half-open state.
    ///
    /// Returns true if the probe was started, false if already at max probes.
    pub fn start_probe(&mut self, config: &CircuitBreakerConfig) -> bool {
        if !self.can_probe(config) {
            return false;
        }
        self.active_probes += 1;
        true
    }

    /// Transition the circuit to open state.
    pub fn open(&mut self) {
        if self.state != CircuitState::Open {
            self.state = CircuitState::Open;
            self.opened_at = Some(Self::now_millis());
            self.last_state_change = Self::now_millis();
            self.consecutive_successes = 0;
            self.active_probes = 0;
        }
    }

    /// Transition the circuit to half-open state.
    pub fn half_open(&mut self) {
        if self.state != CircuitState::HalfOpen {
            self.state = CircuitState::HalfOpen;
            self.last_state_change = Self::now_millis();
            self.consecutive_successes = 0;
            self.active_probes = 0;
        }
    }

    /// Transition the circuit to closed state.
    pub fn close(&mut self) {
        if self.state != CircuitState::Closed {
            self.state = CircuitState::Closed;
            self.last_state_change = Self::now_millis();
            self.opened_at = None;
            self.consecutive_failures = 0;
            self.consecutive_successes = 0;
            self.active_probes = 0;
            // Reset the window on close
            self.window_successes = 0;
            self.window_failures = 0;
        }
    }

    /// Reset the rolling window counters.
    ///
    /// Called periodically to ensure the window reflects recent activity.
    pub fn reset_window(&mut self) {
        self.window_successes = 0;
        self.window_failures = 0;
    }

    fn now_millis() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompilationConfig {
    /// Minimum confidence score to intercept (0.0-1.0).
    #[serde(default = "default_confidence")]
    pub confidence_threshold: f64,
    /// Skip interception if estimated local time < this (ms).
    #[serde(default = "default_min_local_time")]
    pub min_local_time_ms: u64,
}

impl Default for CompilationConfig {
    fn default() -> Self {
        Self {
            confidence_threshold: 0.85,
            min_local_time_ms: 2000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferConfig {
    /// zstd compression level (1-19).
    #[serde(default = "default_compression")]
    pub compression_level: u32,
    /// Patterns to exclude from transfer.
    #[serde(default = "default_excludes")]
    pub exclude_patterns: Vec<String>,
}

impl Default for TransferConfig {
    fn default() -> Self {
        Self {
            compression_level: 3,
            exclude_patterns: default_excludes(),
        }
    }
}

fn default_circuit_failure_threshold() -> u32 {
    3
}

fn default_circuit_success_threshold() -> u32 {
    2
}

fn default_circuit_error_rate_threshold() -> f64 {
    0.5
}

fn default_circuit_window_secs() -> u64 {
    60
}

fn default_circuit_open_cooldown_secs() -> u64 {
    30
}

fn default_circuit_half_open_max_probes() -> u32 {
    1
}

fn default_true() -> bool {
    true
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_socket_path() -> String {
    "/tmp/rch.sock".to_string()
}

fn default_confidence() -> f64 {
    0.85
}

fn default_min_local_time() -> u64 {
    2000
}

fn default_compression() -> u32 {
    3
}

fn default_excludes() -> Vec<String> {
    vec![
        "target/".to_string(),
        ".git/objects/".to_string(),
        "node_modules/".to_string(),
        "*.rlib".to_string(),
        "*.rmeta".to_string(),
    ]
}

// ============================================================================
// Build History Types
// ============================================================================

/// Location where a build was executed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildLocation {
    /// Build executed locally.
    Local,
    /// Build executed on a remote worker.
    Remote,
}

impl Default for BuildLocation {
    fn default() -> Self {
        Self::Local
    }
}

/// Record of a completed build.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildRecord {
    /// Unique build identifier.
    pub id: u64,
    /// When the build started (ISO 8601 timestamp).
    pub started_at: String,
    /// When the build completed (ISO 8601 timestamp).
    pub completed_at: String,
    /// Project identifier (usually directory name or hash).
    pub project_id: String,
    /// Worker that executed the build (None if local).
    pub worker_id: Option<String>,
    /// Full command executed.
    pub command: String,
    /// Exit code (0 = success).
    pub exit_code: i32,
    /// Duration in milliseconds.
    pub duration_ms: u64,
    /// Build location (local or remote).
    pub location: BuildLocation,
    /// Bytes transferred (if remote).
    pub bytes_transferred: Option<u64>,
}

/// Aggregate statistics for build history.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BuildStats {
    /// Total number of builds in history.
    pub total_builds: usize,
    /// Number of successful builds (exit_code == 0).
    pub success_count: usize,
    /// Number of failed builds (exit_code != 0).
    pub failure_count: usize,
    /// Number of remote builds.
    pub remote_count: usize,
    /// Number of local builds.
    pub local_count: usize,
    /// Average build duration in milliseconds.
    pub avg_duration_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_state_default() {
        assert_eq!(CircuitState::default(), CircuitState::Closed);
    }

    #[test]
    fn test_circuit_config_defaults() {
        let config = CircuitBreakerConfig::default();
        assert_eq!(config.failure_threshold, 3);
        assert_eq!(config.success_threshold, 2);
        assert_eq!(config.error_rate_threshold, 0.5);
        assert_eq!(config.window_secs, 60);
        assert_eq!(config.open_cooldown_secs, 30);
        assert_eq!(config.half_open_max_probes, 1);
    }

    #[test]
    fn test_rch_config_has_circuit_defaults() {
        let config = RchConfig::default();
        assert_eq!(config.circuit.failure_threshold, 3);
    }

    #[test]
    fn test_circuit_config_serde_roundtrip() {
        let config = CircuitBreakerConfig {
            failure_threshold: 5,
            success_threshold: 3,
            error_rate_threshold: 0.75,
            window_secs: 120,
            open_cooldown_secs: 45,
            half_open_max_probes: 2,
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: CircuitBreakerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.failure_threshold, 5);
        assert_eq!(parsed.success_threshold, 3);
        assert_eq!(parsed.error_rate_threshold, 0.75);
        assert_eq!(parsed.window_secs, 120);
        assert_eq!(parsed.open_cooldown_secs, 45);
        assert_eq!(parsed.half_open_max_probes, 2);
    }

    #[test]
    fn test_selection_reason_serialization() {
        // Test that all variants serialize to snake_case
        assert_eq!(
            serde_json::to_string(&SelectionReason::Success).unwrap(),
            "\"success\""
        );
        assert_eq!(
            serde_json::to_string(&SelectionReason::NoWorkersConfigured).unwrap(),
            "\"no_workers_configured\""
        );
        assert_eq!(
            serde_json::to_string(&SelectionReason::AllWorkersUnreachable).unwrap(),
            "\"all_workers_unreachable\""
        );
        assert_eq!(
            serde_json::to_string(&SelectionReason::AllCircuitsOpen).unwrap(),
            "\"all_circuits_open\""
        );
        assert_eq!(
            serde_json::to_string(&SelectionReason::AllWorkersBusy).unwrap(),
            "\"all_workers_busy\""
        );
        assert_eq!(
            serde_json::to_string(&SelectionReason::NoMatchingWorkers).unwrap(),
            "\"no_matching_workers\""
        );
    }

    #[test]
    fn test_selection_reason_with_error() {
        let reason = SelectionReason::SelectionError("test error".to_string());
        let json = serde_json::to_string(&reason).unwrap();
        assert!(json.contains("selection_error"));
        assert!(json.contains("test error"));
    }

    #[test]
    fn test_selection_reason_deserialization() {
        assert_eq!(
            serde_json::from_str::<SelectionReason>("\"success\"").unwrap(),
            SelectionReason::Success
        );
        assert_eq!(
            serde_json::from_str::<SelectionReason>("\"all_workers_busy\"").unwrap(),
            SelectionReason::AllWorkersBusy
        );
    }

    #[test]
    fn test_selection_reason_display() {
        assert_eq!(
            SelectionReason::Success.to_string(),
            "worker assigned successfully"
        );
        assert_eq!(
            SelectionReason::NoWorkersConfigured.to_string(),
            "no workers configured"
        );
        assert_eq!(
            SelectionReason::AllWorkersUnreachable.to_string(),
            "all workers unreachable"
        );
        assert_eq!(
            SelectionReason::AllWorkersBusy.to_string(),
            "all workers at capacity"
        );
        assert_eq!(
            SelectionReason::SelectionError("oops".to_string()).to_string(),
            "selection error: oops"
        );
    }

    #[test]
    fn test_selection_response_with_worker() {
        let response = SelectionResponse {
            worker: Some(SelectedWorker {
                id: WorkerId::new("test"),
                host: "localhost".to_string(),
                user: "user".to_string(),
                identity_file: "~/.ssh/id_rsa".to_string(),
                slots_available: 8,
                speed_score: 75.0,
            }),
            reason: SelectionReason::Success,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"reason\":\"success\""));
        assert!(json.contains("\"id\":\"test\""));
    }

    #[test]
    fn test_selection_response_without_worker() {
        let response = SelectionResponse {
            worker: None,
            reason: SelectionReason::AllWorkersBusy,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"worker\":null"));
        assert!(json.contains("\"reason\":\"all_workers_busy\""));
    }

    #[test]
    fn test_selection_response_roundtrip() {
        let original = SelectionResponse {
            worker: Some(SelectedWorker {
                id: WorkerId::new("worker-1"),
                host: "192.168.1.100".to_string(),
                user: "ubuntu".to_string(),
                identity_file: "/path/to/key".to_string(),
                slots_available: 16,
                speed_score: 90.5,
            }),
            reason: SelectionReason::Success,
        };

        let json = serde_json::to_string(&original).unwrap();
        let parsed: SelectionResponse = serde_json::from_str(&json).unwrap();

        assert!(parsed.worker.is_some());
        let worker = parsed.worker.unwrap();
        assert_eq!(worker.id.as_str(), "worker-1");
        assert_eq!(worker.host, "192.168.1.100");
        assert_eq!(worker.slots_available, 16);
        assert_eq!(parsed.reason, SelectionReason::Success);
    }

    // CircuitStats tests

    #[test]
    fn test_circuit_stats_new() {
        let stats = CircuitStats::new();
        assert_eq!(stats.state(), CircuitState::Closed);
        assert_eq!(stats.consecutive_failures(), 0);
        assert_eq!(stats.error_rate(), 0.0);
        assert!(stats.opened_at().is_none());
    }

    #[test]
    fn test_circuit_stats_record_success() {
        let mut stats = CircuitStats::new();
        stats.record_success();
        stats.record_success();
        assert_eq!(stats.error_rate(), 0.0);
        assert_eq!(stats.consecutive_failures(), 0);
    }

    #[test]
    fn test_circuit_stats_record_failure() {
        let mut stats = CircuitStats::new();
        stats.record_failure();
        stats.record_failure();
        assert_eq!(stats.consecutive_failures(), 2);
        assert_eq!(stats.error_rate(), 1.0); // 2 failures, 0 successes
    }

    #[test]
    fn test_circuit_stats_error_rate() {
        let mut stats = CircuitStats::new();
        stats.record_success();
        stats.record_success();
        stats.record_failure();
        // 1 failure / 3 total = 0.333...
        assert!((stats.error_rate() - 0.333).abs() < 0.01);
    }

    #[test]
    fn test_circuit_stats_should_open_consecutive_failures() {
        let mut stats = CircuitStats::new();
        let config = CircuitBreakerConfig::default(); // threshold = 3

        stats.record_failure();
        assert!(!stats.should_open(&config));

        stats.record_failure();
        assert!(!stats.should_open(&config));

        stats.record_failure();
        assert!(stats.should_open(&config)); // 3 consecutive failures
    }

    #[test]
    fn test_circuit_stats_should_open_error_rate() {
        let mut stats = CircuitStats::new();
        let config = CircuitBreakerConfig {
            error_rate_threshold: 0.5,
            ..Default::default()
        };

        // Need at least 5 samples
        stats.record_success();
        stats.record_success();
        stats.record_failure();
        stats.record_failure();
        assert!(!stats.should_open(&config)); // Only 4 samples

        stats.record_failure(); // 5 samples: 2 success, 3 failures = 60% error rate
        assert!(stats.should_open(&config));
    }

    #[test]
    fn test_circuit_stats_success_resets_consecutive_failures() {
        let mut stats = CircuitStats::new();
        stats.record_failure();
        stats.record_failure();
        assert_eq!(stats.consecutive_failures(), 2);

        stats.record_success();
        assert_eq!(stats.consecutive_failures(), 0);
    }

    #[test]
    fn test_circuit_stats_open_transition() {
        let mut stats = CircuitStats::new();
        stats.open();

        assert_eq!(stats.state(), CircuitState::Open);
        assert!(stats.opened_at().is_some());
    }

    #[test]
    fn test_circuit_stats_half_open_transition() {
        let mut stats = CircuitStats::new();
        stats.open();
        stats.half_open();

        assert_eq!(stats.state(), CircuitState::HalfOpen);
    }

    #[test]
    fn test_circuit_stats_close_transition() {
        let mut stats = CircuitStats::new();
        stats.open();
        stats.half_open();
        stats.close();

        assert_eq!(stats.state(), CircuitState::Closed);
        assert!(stats.opened_at().is_none());
        assert_eq!(stats.consecutive_failures(), 0);
    }

    #[test]
    fn test_circuit_stats_should_close() {
        let mut stats = CircuitStats::new();
        let config = CircuitBreakerConfig {
            success_threshold: 2,
            ..Default::default()
        };

        stats.open();
        stats.half_open();

        assert!(!stats.should_close(&config)); // 0 successes

        stats.record_success();
        assert!(!stats.should_close(&config)); // 1 success

        stats.record_success();
        assert!(stats.should_close(&config)); // 2 successes
    }

    #[test]
    fn test_circuit_stats_can_probe() {
        let mut stats = CircuitStats::new();
        let config = CircuitBreakerConfig {
            half_open_max_probes: 1,
            ..Default::default()
        };

        // Can't probe when closed
        assert!(!stats.can_probe(&config));

        stats.open();
        // Can't probe when open
        assert!(!stats.can_probe(&config));

        stats.half_open();
        // Can probe when half-open
        assert!(stats.can_probe(&config));

        // Start a probe
        assert!(stats.start_probe(&config));
        // Can't start another probe
        assert!(!stats.can_probe(&config));
        assert!(!stats.start_probe(&config));
    }

    #[test]
    fn test_circuit_stats_probe_completion() {
        let mut stats = CircuitStats::new();
        let config = CircuitBreakerConfig {
            half_open_max_probes: 1,
            ..Default::default()
        };

        stats.open();
        stats.half_open();
        stats.start_probe(&config);

        // Probe completes with success
        stats.record_success();

        // Can start another probe
        assert!(stats.can_probe(&config));
    }

    #[test]
    fn test_circuit_stats_failure_in_half_open() {
        let mut stats = CircuitStats::new();
        let config = CircuitBreakerConfig {
            success_threshold: 2,
            ..Default::default()
        };

        stats.open();
        stats.half_open();

        stats.record_success();
        assert_eq!(stats.consecutive_failures(), 0);

        // Failure resets consecutive successes
        stats.record_failure();
        assert!(!stats.should_close(&config));

        // Need 2 more successes
        stats.record_success();
        stats.record_success();
        assert!(stats.should_close(&config));
    }

    #[test]
    fn test_circuit_stats_reset_window() {
        let mut stats = CircuitStats::new();
        stats.record_success();
        stats.record_failure();

        assert!(stats.error_rate() > 0.0);

        stats.reset_window();
        assert_eq!(stats.error_rate(), 0.0);
    }

    #[test]
    fn test_circuit_state_transitions_are_deterministic() {
        let config = CircuitBreakerConfig::default();
        let mut stats = CircuitStats::new();

        // Start closed
        assert_eq!(stats.state(), CircuitState::Closed);

        // Cause failures to open
        for _ in 0..3 {
            stats.record_failure();
        }
        assert!(stats.should_open(&config));
        stats.open();
        assert_eq!(stats.state(), CircuitState::Open);

        // Transition to half-open after cooldown would be checked
        stats.half_open();
        assert_eq!(stats.state(), CircuitState::HalfOpen);

        // Successes to close
        for _ in 0..2 {
            stats.record_success();
        }
        assert!(stats.should_close(&config));
        stats.close();
        assert_eq!(stats.state(), CircuitState::Closed);
    }
}
