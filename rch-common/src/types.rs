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
}
