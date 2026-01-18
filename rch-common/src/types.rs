//! Common types used across RCH components.

use crate::toolchain::ToolchainInfo;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

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

/// Required runtime for command execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RequiredRuntime {
    /// No specific runtime required (default).
    None,
    /// Requires Rust toolchain.
    Rust,
    /// Requires Bun runtime.
    Bun,
    /// Requires Node.js runtime.
    Node,
}

impl Default for RequiredRuntime {
    fn default() -> Self {
        Self::None
    }
}

/// Worker selection request sent from hook to daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectionRequest {
    /// Project identifier (usually directory name or hash).
    pub project: String,
    /// Full command being executed (optional, for active build tracking).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// Estimated CPU cores needed for this compilation.
    pub estimated_cores: u32,
    /// Preferred worker IDs (e.g., from project config).
    #[serde(default)]
    pub preferred_workers: Vec<WorkerId>,
    /// Rust toolchain information for the project.
    #[serde(default)]
    pub toolchain: Option<ToolchainInfo>,
    /// Required runtime for command execution.
    #[serde(default)]
    pub required_runtime: RequiredRuntime,
    /// Classification decision latency in microseconds (for AGENTS.md compliance).
    /// This tracks how long the 5-tier classification took on the hook side.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classification_duration_us: Option<u64>,
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
    /// No workers have the required runtime (e.g., Bun, Node).
    NoWorkersWithRuntime(String),
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
            Self::NoWorkersWithRuntime(rt) => write!(f, "no workers with {} installed", rt),
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
    /// Optional build ID assigned by the daemon (for active build tracking).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_id: Option<u64>,
}

/// Request to release reserved worker slots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseRequest {
    /// ID of the worker to release slots on.
    pub worker_id: WorkerId,
    /// Number of slots to release.
    pub slots: u32,
    /// Optional build ID to mark complete.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_id: Option<u64>,
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

impl Default for WorkerConfig {
    fn default() -> Self {
        Self {
            id: WorkerId::new("default-worker"),
            host: "localhost".to_string(),
            user: "user".to_string(),
            identity_file: "~/.ssh/id_rsa".to_string(),
            total_slots: 4,
            priority: default_priority(),
            tags: Vec::new(),
        }
    }
}

/// Runtime capabilities detected on a worker.
///
/// These are probed during health checks and cached for routing decisions.
/// Commands requiring specific runtimes (e.g., `bun test`) can be routed
/// only to workers with the corresponding capability.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WorkerCapabilities {
    /// Rust compiler version (from `rustc --version`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rustc_version: Option<String>,
    /// Bun runtime version (from `bun --version`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bun_version: Option<String>,
    /// Node.js version (from `node --version`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_version: Option<String>,
    /// npm version (from `npm --version`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub npm_version: Option<String>,
}

impl WorkerCapabilities {
    /// Create new empty capabilities.
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if this worker has Bun installed.
    pub fn has_bun(&self) -> bool {
        self.bun_version.is_some()
    }

    /// Check if this worker has Node.js installed.
    pub fn has_node(&self) -> bool {
        self.node_version.is_some()
    }

    /// Check if this worker has Rust installed.
    pub fn has_rust(&self) -> bool {
        self.rustc_version.is_some()
    }
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
    #[serde(default)]
    pub output: OutputConfig,
    #[serde(default)]
    pub self_test: SelfTestConfig,
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
            socket_path: default_socket_path(),
        }
    }
}

/// Visibility level for hook output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputVisibility {
    None,
    Summary,
    Verbose,
}

impl Default for OutputVisibility {
    fn default() -> Self {
        Self::None
    }
}

impl std::fmt::Display for OutputVisibility {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            OutputVisibility::None => "none",
            OutputVisibility::Summary => "summary",
            OutputVisibility::Verbose => "verbose",
        };
        write!(f, "{}", value)
    }
}

impl std::str::FromStr for OutputVisibility {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "none" | "silent" | "quiet" => Ok(Self::None),
            "summary" | "short" => Ok(Self::Summary),
            "verbose" | "debug" => Ok(Self::Verbose),
            _ => Err(()),
        }
    }
}

/// Hook output configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    /// Output visibility level for hook messages.
    #[serde(default = "default_output_visibility")]
    pub visibility: OutputVisibility,
    /// Whether the first-run success message has been shown.
    #[serde(default)]
    pub first_run_complete: bool,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            visibility: OutputVisibility::None,
            first_run_complete: false,
        }
    }
}

// ============================================================================
// Self-Test Configuration
// ============================================================================

/// Action to take when a scheduled self-test fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelfTestFailureAction {
    /// Only emit an alert/log entry.
    Alert,
    /// Disable the failing worker automatically.
    DisableWorker,
    /// Alert and disable the worker.
    AlertAndDisable,
}

impl Default for SelfTestFailureAction {
    fn default() -> Self {
        Self::Alert
    }
}

/// Which workers to include in self-test runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SelfTestWorkers {
    /// Special value "all" (or a single worker id string).
    All(String),
    /// Explicit worker list.
    List(Vec<WorkerId>),
}

impl Default for SelfTestWorkers {
    fn default() -> Self {
        Self::All("all".to_string())
    }
}

impl SelfTestWorkers {
    /// Resolve to an explicit list if configured, or None to indicate "all".
    pub fn resolve(&self) -> Option<Vec<WorkerId>> {
        match self {
            SelfTestWorkers::All(value) => {
                if value.eq_ignore_ascii_case("all") {
                    None
                } else {
                    Some(vec![WorkerId::new(value.clone())])
                }
            }
            SelfTestWorkers::List(list) => Some(list.clone()),
        }
    }
}

fn default_self_test_retry_count() -> u32 {
    3
}

fn default_self_test_retry_delay() -> String {
    "5m".to_string()
}

fn default_self_test_enabled() -> bool {
    false
}

/// Self-test scheduling and behavior configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfTestConfig {
    /// Enable scheduled self-tests.
    #[serde(default = "default_self_test_enabled")]
    pub enabled: bool,
    /// Cron schedule (e.g., "0 3 * * *").
    #[serde(default)]
    pub schedule: Option<String>,
    /// Interval duration (e.g., "24h").
    #[serde(default)]
    pub interval: Option<String>,
    /// Which workers to test (default: "all").
    #[serde(default)]
    pub workers: SelfTestWorkers,
    /// Action on failure.
    #[serde(default)]
    pub on_failure: SelfTestFailureAction,
    /// Retry count for failed tests.
    #[serde(default = "default_self_test_retry_count")]
    pub retry_count: u32,
    /// Delay between retries.
    #[serde(default = "default_self_test_retry_delay")]
    pub retry_delay: String,
}

impl Default for SelfTestConfig {
    fn default() -> Self {
        Self {
            enabled: default_self_test_enabled(),
            schedule: None,
            interval: None,
            workers: SelfTestWorkers::default(),
            on_failure: SelfTestFailureAction::default(),
            retry_count: default_self_test_retry_count(),
            retry_delay: default_self_test_retry_delay(),
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
    /// Recent health check results (true=success, false=failure).
    /// Used for history visualization in status display.
    recent_results: Vec<bool>,
}

/// Maximum number of recent results to keep for history visualization.
const CIRCUIT_HISTORY_SIZE: usize = 10;

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
            recent_results: Vec::with_capacity(CIRCUIT_HISTORY_SIZE),
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
        self.push_result(true);

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
        self.push_result(false);

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

    /// Get recent health check results for history visualization.
    ///
    /// Returns a slice of recent results (true=success, false=failure),
    /// with the most recent result at the end.
    pub fn recent_results(&self) -> &[bool] {
        &self.recent_results
    }

    /// Calculate seconds remaining until circuit auto-transitions to half-open.
    ///
    /// Returns None if circuit is not open or cooldown has already elapsed.
    pub fn recovery_remaining_secs(&self, config: &CircuitBreakerConfig) -> Option<u64> {
        if self.state != CircuitState::Open {
            return None;
        }

        let now = Self::now_millis();
        let cooldown_ms = config.open_cooldown_secs * 1000;

        if let Some(opened_at) = self.opened_at {
            let elapsed_ms = now.saturating_sub(opened_at);
            if elapsed_ms < cooldown_ms {
                return Some((cooldown_ms - elapsed_ms) / 1000);
            }
        }
        None
    }

    /// Push a result to the history, maintaining the maximum size.
    fn push_result(&mut self, success: bool) {
        if self.recent_results.len() >= CIRCUIT_HISTORY_SIZE {
            self.recent_results.remove(0);
        }
        self.recent_results.push(success);
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

pub fn default_socket_path() -> String {
    // Prefer XDG_RUNTIME_DIR if available (per-user runtime directory).
    if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
        if !runtime_dir.trim().is_empty() {
            let path = PathBuf::from(runtime_dir).join("rch.sock");
            return path.to_string_lossy().to_string();
        }
    }

    // Fallback to ~/.cache/rch/rch.sock (persistent across reboots).
    if let Some(cache_dir) = dirs::cache_dir() {
        let rch_cache = cache_dir.join("rch");
        let _ = std::fs::create_dir_all(&rch_cache);
        return rch_cache.join("rch.sock").to_string_lossy().to_string();
    }

    // Last resort: /tmp/rch.sock
    "/tmp/rch.sock".to_string()
}

#[allow(dead_code)]
fn default_output_visibility() -> OutputVisibility {
    OutputVisibility::None
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
        // Rust build artifacts
        "target/".to_string(),
        "*.rlib".to_string(),
        "*.rmeta".to_string(),
        // Git objects (large, regenerated on clone)
        ".git/objects/".to_string(),
        // Node.js / Bun dependencies (massive, reinstalled on worker)
        "node_modules/".to_string(),
        // Bun cache and runtime files
        ".bun/".to_string(),
        // npm / pnpm caches
        ".npm/".to_string(),
        ".pnpm-store/".to_string(),
        // Common build output directories
        "dist/".to_string(),
        "build/".to_string(),
        // Framework-specific caches
        ".next/".to_string(),
        ".nuxt/".to_string(),
        ".turbo/".to_string(),
        ".parcel-cache/".to_string(),
        // Coverage reports (generated during tests)
        "coverage/".to_string(),
        ".nyc_output/".to_string(),
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

// ============================================================================
// Compilation Timing and Metrics
// ============================================================================

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Breakdown of timing for each compilation phase.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CompilationTimingBreakdown {
    /// Time to sync source files to worker.
    #[serde(with = "duration_millis")]
    pub rsync_up: Duration,
    /// Time for cargo build on worker.
    #[serde(with = "duration_millis")]
    pub remote_build: Duration,
    /// Time to sync artifacts back.
    #[serde(with = "duration_millis")]
    pub rsync_down: Duration,
    /// Total end-to-end latency.
    #[serde(with = "duration_millis")]
    pub total: Duration,
}

mod duration_millis {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        duration.as_millis().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let millis = u64::deserialize(deserializer)?;
        Ok(Duration::from_millis(millis))
    }
}

/// Comprehensive metrics for a single compilation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompilationMetrics {
    /// Project identifier (usually directory name or hash).
    pub project_id: String,
    /// Worker that performed the compilation.
    pub worker_id: String,
    /// When the compilation occurred.
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Timing breakdown for each phase.
    pub timing: CompilationTimingBreakdown,
    /// Local build time for comparison (if available).
    #[serde(with = "option_duration_millis")]
    pub local_build_time: Option<Duration>,
    /// Speedup ratio (local_time / remote_time).
    pub speedup: Option<f64>,
    /// Number of files synced to worker.
    pub files_synced: u64,
    /// Total bytes transferred.
    pub bytes_transferred: u64,
    /// Exit code from compilation.
    pub exit_code: i32,
    /// Whether compilation succeeded.
    pub success: bool,
}

mod option_duration_millis {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Option<Duration>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match duration {
            Some(d) => Some(d.as_millis() as u64).serialize(serializer),
            None => Option::<u64>::None.serialize(serializer),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<u64> = Option::deserialize(deserializer)?;
        Ok(opt.map(Duration::from_millis))
    }
}

impl CompilationMetrics {
    /// Calculate speedup based on local vs remote build time.
    pub fn calculate_speedup(&mut self) {
        if let Some(local) = self.local_build_time {
            if self.timing.total.as_millis() > 0 {
                self.speedup = Some(local.as_secs_f64() / self.timing.total.as_secs_f64());
            }
        }
    }

    /// Check if remote compilation was beneficial (faster than local).
    pub fn is_beneficial(&self) -> bool {
        self.speedup.map(|s| s > 1.0).unwrap_or(false)
    }
}

impl Default for CompilationMetrics {
    fn default() -> Self {
        Self {
            project_id: String::new(),
            worker_id: String::new(),
            timestamp: chrono::Utc::now(),
            timing: CompilationTimingBreakdown::default(),
            local_build_time: None,
            speedup: None,
            files_synced: 0,
            bytes_transferred: 0,
            exit_code: 0,
            success: true,
        }
    }
}

/// Timer for tracking compilation phases.
///
/// Use this to measure the duration of each phase of remote compilation.
///
/// # Example
/// ```ignore
/// let mut timer = CompilationTimer::new("my-project", "worker-1");
/// // ... rsync source files ...
/// timer.end_rsync_up();
/// // ... run cargo build ...
/// timer.end_remote_build();
/// // ... rsync artifacts back ...
/// timer.end_rsync_down();
/// let metrics = timer.finish(0, 100, 1_000_000);
/// ```
#[derive(Debug)]
pub struct CompilationTimer {
    project_id: String,
    worker_id: String,
    start: Instant,
    phase_start: Instant,
    rsync_up: Option<Duration>,
    remote_build: Option<Duration>,
    rsync_down: Option<Duration>,
}

impl CompilationTimer {
    /// Create a new timer for a compilation.
    pub fn new(project_id: &str, worker_id: &str) -> Self {
        let now = Instant::now();
        Self {
            project_id: project_id.to_string(),
            worker_id: worker_id.to_string(),
            start: now,
            phase_start: now,
            rsync_up: None,
            remote_build: None,
            rsync_down: None,
        }
    }

    /// Mark the end of the rsync upload phase.
    pub fn end_rsync_up(&mut self) {
        self.rsync_up = Some(self.phase_start.elapsed());
        self.phase_start = Instant::now();
        tracing::info!(
            rsync_up_ms = %self.rsync_up.unwrap().as_millis(),
            "TIMING: rsync_up completed"
        );
    }

    /// Mark the end of the remote build phase.
    pub fn end_remote_build(&mut self) {
        self.remote_build = Some(self.phase_start.elapsed());
        self.phase_start = Instant::now();
        tracing::info!(
            remote_build_ms = %self.remote_build.unwrap().as_millis(),
            "TIMING: remote_build completed"
        );
    }

    /// Mark the end of the rsync download phase.
    pub fn end_rsync_down(&mut self) {
        self.rsync_down = Some(self.phase_start.elapsed());
        tracing::info!(
            rsync_down_ms = %self.rsync_down.unwrap().as_millis(),
            "TIMING: rsync_down completed"
        );
    }

    /// Finish timing and produce metrics.
    pub fn finish(self, exit_code: i32, files: u64, bytes: u64) -> CompilationMetrics {
        let total = self.start.elapsed();
        tracing::info!(
            total_ms = %total.as_millis(),
            exit_code = %exit_code,
            "TIMING: compilation completed"
        );

        CompilationMetrics {
            project_id: self.project_id,
            worker_id: self.worker_id,
            timestamp: chrono::Utc::now(),
            timing: CompilationTimingBreakdown {
                rsync_up: self.rsync_up.unwrap_or_default(),
                remote_build: self.remote_build.unwrap_or_default(),
                rsync_down: self.rsync_down.unwrap_or_default(),
                total,
            },
            local_build_time: None,
            speedup: None,
            files_synced: files,
            bytes_transferred: bytes,
            exit_code,
            success: exit_code == 0,
        }
    }
}

/// Aggregator for compilation metrics with statistics.
#[derive(Debug)]
pub struct MetricsAggregator {
    history: VecDeque<CompilationMetrics>,
    max_history: usize,
}

impl MetricsAggregator {
    /// Create a new aggregator with a maximum history size.
    pub fn new(max_history: usize) -> Self {
        Self {
            history: VecDeque::with_capacity(max_history),
            max_history,
        }
    }

    /// Record a new compilation's metrics.
    pub fn record(&mut self, metrics: CompilationMetrics) {
        if self.history.len() >= self.max_history {
            self.history.pop_front();
        }
        self.history.push_back(metrics);
    }

    /// Get the average speedup across all recorded compilations.
    pub fn average_speedup(&self) -> Option<f64> {
        let speedups: Vec<f64> = self.history.iter().filter_map(|m| m.speedup).collect();

        if speedups.is_empty() {
            None
        } else {
            Some(speedups.iter().sum::<f64>() / speedups.len() as f64)
        }
    }

    /// Get the p50 (median) total compilation time.
    pub fn p50_total_time(&self) -> Option<Duration> {
        self.percentile_total_time(0.50)
    }

    /// Get the p95 total compilation time.
    pub fn p95_total_time(&self) -> Option<Duration> {
        self.percentile_total_time(0.95)
    }

    /// Get the p99 total compilation time.
    pub fn p99_total_time(&self) -> Option<Duration> {
        self.percentile_total_time(0.99)
    }

    /// Get a percentile of total compilation times.
    fn percentile_total_time(&self, percentile: f64) -> Option<Duration> {
        let mut times: Vec<_> = self.history.iter().map(|m| m.timing.total).collect();

        if times.is_empty() {
            return None;
        }

        times.sort();
        let idx = ((times.len() as f64 * percentile) as usize).min(times.len() - 1);
        Some(times[idx])
    }

    /// Get the success rate as a percentage.
    pub fn success_rate(&self) -> f64 {
        if self.history.is_empty() {
            return 100.0;
        }
        let successes = self.history.iter().filter(|m| m.success).count();
        (successes as f64 / self.history.len() as f64) * 100.0
    }

    /// Get the number of recorded compilations.
    pub fn count(&self) -> usize {
        self.history.len()
    }

    /// Get all recorded metrics.
    pub fn metrics(&self) -> &VecDeque<CompilationMetrics> {
        &self.history
    }

    /// Clear all recorded metrics.
    pub fn clear(&mut self) {
        self.history.clear();
    }
}

impl Default for MetricsAggregator {
    fn default() -> Self {
        Self::new(1000)
    }
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
            build_id: None,
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
            build_id: None,
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
            build_id: None,
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

    // ========================================================================
    // Compilation Timing Tests
    // ========================================================================

    fn make_test_metrics(
        speedup: Option<f64>,
        total_secs: u64,
        success: bool,
    ) -> CompilationMetrics {
        CompilationMetrics {
            project_id: "test-project".to_string(),
            worker_id: "worker-1".to_string(),
            timestamp: chrono::Utc::now(),
            timing: CompilationTimingBreakdown {
                rsync_up: Duration::from_millis(100),
                remote_build: Duration::from_millis(800),
                rsync_down: Duration::from_millis(100),
                total: Duration::from_secs(total_secs),
            },
            local_build_time: speedup.map(|s| Duration::from_secs_f64(total_secs as f64 * s)),
            speedup,
            files_synced: 100,
            bytes_transferred: 1_000_000,
            exit_code: if success { 0 } else { 1 },
            success,
        }
    }

    #[test]
    fn test_compilation_timing_breakdown_default() {
        let timing = CompilationTimingBreakdown::default();
        assert_eq!(timing.rsync_up, Duration::ZERO);
        assert_eq!(timing.remote_build, Duration::ZERO);
        assert_eq!(timing.rsync_down, Duration::ZERO);
        assert_eq!(timing.total, Duration::ZERO);
    }

    #[test]
    fn test_compilation_timing_breakdown_serialization() {
        let timing = CompilationTimingBreakdown {
            rsync_up: Duration::from_millis(100),
            remote_build: Duration::from_millis(2000),
            rsync_down: Duration::from_millis(50),
            total: Duration::from_millis(2150),
        };

        let json = serde_json::to_string(&timing).unwrap();
        assert!(json.contains("100")); // rsync_up
        assert!(json.contains("2000")); // remote_build
        assert!(json.contains("50")); // rsync_down
        assert!(json.contains("2150")); // total

        let parsed: CompilationTimingBreakdown = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.rsync_up, timing.rsync_up);
        assert_eq!(parsed.remote_build, timing.remote_build);
        assert_eq!(parsed.rsync_down, timing.rsync_down);
        assert_eq!(parsed.total, timing.total);
    }

    #[test]
    fn test_compilation_metrics_calculate_speedup() {
        let mut metrics = CompilationMetrics {
            timing: CompilationTimingBreakdown {
                total: Duration::from_secs(10),
                ..Default::default()
            },
            local_build_time: Some(Duration::from_secs(30)),
            ..Default::default()
        };

        metrics.calculate_speedup();

        assert!(metrics.speedup.is_some());
        let speedup = metrics.speedup.unwrap();
        assert!(
            (speedup - 3.0).abs() < 0.01,
            "Expected 3.0x speedup, got {}",
            speedup
        );
    }

    #[test]
    fn test_compilation_metrics_is_beneficial() {
        let mut metrics = CompilationMetrics::default();

        // No speedup calculated
        assert!(!metrics.is_beneficial());

        // Speedup > 1 is beneficial
        metrics.speedup = Some(1.5);
        assert!(metrics.is_beneficial());

        // Speedup < 1 is not beneficial
        metrics.speedup = Some(0.8);
        assert!(!metrics.is_beneficial());

        // Speedup = 1 is not beneficial (exactly same speed)
        metrics.speedup = Some(1.0);
        assert!(!metrics.is_beneficial());
    }

    #[test]
    fn test_compilation_metrics_serialization() {
        let metrics = make_test_metrics(Some(2.5), 10, true);
        let json = serde_json::to_string(&metrics).unwrap();

        assert!(json.contains("test-project"));
        assert!(json.contains("worker-1"));
        assert!(json.contains("2.5")); // speedup

        let parsed: CompilationMetrics = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.project_id, "test-project");
        assert_eq!(parsed.worker_id, "worker-1");
        assert!(parsed.success);
    }

    #[test]
    fn test_compilation_timer_new() {
        let timer = CompilationTimer::new("my-project", "my-worker");
        assert_eq!(timer.project_id, "my-project");
        assert_eq!(timer.worker_id, "my-worker");
        assert!(timer.rsync_up.is_none());
        assert!(timer.remote_build.is_none());
        assert!(timer.rsync_down.is_none());
    }

    #[test]
    fn test_compilation_timer_phases() {
        let mut timer = CompilationTimer::new("test", "worker");

        // Simulate rsync up
        std::thread::sleep(Duration::from_millis(5));
        timer.end_rsync_up();
        assert!(timer.rsync_up.is_some());
        assert!(timer.rsync_up.unwrap() >= Duration::from_millis(5));

        // Simulate remote build
        std::thread::sleep(Duration::from_millis(10));
        timer.end_remote_build();
        assert!(timer.remote_build.is_some());
        assert!(timer.remote_build.unwrap() >= Duration::from_millis(10));

        // Simulate rsync down
        std::thread::sleep(Duration::from_millis(5));
        timer.end_rsync_down();
        assert!(timer.rsync_down.is_some());
        assert!(timer.rsync_down.unwrap() >= Duration::from_millis(5));

        // Finish
        let metrics = timer.finish(0, 50, 500_000);
        assert_eq!(metrics.project_id, "test");
        assert_eq!(metrics.worker_id, "worker");
        assert!(metrics.success);
        assert!(metrics.timing.total >= Duration::from_millis(20));
        assert_eq!(metrics.files_synced, 50);
        assert_eq!(metrics.bytes_transferred, 500_000);
    }

    #[test]
    fn test_metrics_aggregator_new() {
        let agg = MetricsAggregator::new(100);
        assert_eq!(agg.count(), 0);
        assert!(agg.average_speedup().is_none());
    }

    #[test]
    fn test_metrics_aggregator_record() {
        let mut agg = MetricsAggregator::new(3);

        // Record first metric
        agg.record(make_test_metrics(Some(2.0), 10, true));
        assert_eq!(agg.count(), 1);

        // Record up to max
        agg.record(make_test_metrics(Some(3.0), 20, true));
        agg.record(make_test_metrics(Some(4.0), 30, true));
        assert_eq!(agg.count(), 3);

        // Exceed max should drop oldest
        agg.record(make_test_metrics(Some(5.0), 40, true));
        assert_eq!(agg.count(), 3);
    }

    #[test]
    fn test_metrics_aggregator_average_speedup() {
        let mut agg = MetricsAggregator::new(100);

        // Empty case
        assert!(agg.average_speedup().is_none());

        // Add metrics with speedups 1, 2, 3, 4, 5 -> average = 3
        for i in 1..=5 {
            agg.record(make_test_metrics(Some(i as f64), 10, true));
        }

        let avg = agg.average_speedup().unwrap();
        assert!((avg - 3.0).abs() < 0.01, "Expected 3.0, got {}", avg);
    }

    #[test]
    fn test_metrics_aggregator_average_speedup_with_none() {
        let mut agg = MetricsAggregator::new(100);

        // Mix of Some and None speedups
        agg.record(make_test_metrics(Some(2.0), 10, true));
        agg.record(make_test_metrics(None, 10, true)); // No speedup
        agg.record(make_test_metrics(Some(4.0), 10, true));

        // Average should only consider metrics with speedup
        let avg = agg.average_speedup().unwrap();
        assert!((avg - 3.0).abs() < 0.01, "Expected 3.0, got {}", avg);
    }

    #[test]
    fn test_metrics_aggregator_percentiles() {
        let mut agg = MetricsAggregator::new(100);

        // Add metrics with total times 1s, 2s, 3s, ..., 10s
        for i in 1..=10 {
            agg.record(make_test_metrics(Some(1.0), i, true));
        }

        // p50 (median) should be around 5s
        let p50 = agg.p50_total_time().unwrap();
        assert!(p50 >= Duration::from_secs(5) && p50 <= Duration::from_secs(6));

        // p95 should be around 9s or 10s
        let p95 = agg.p95_total_time().unwrap();
        assert!(p95 >= Duration::from_secs(9) && p95 <= Duration::from_secs(10));

        // p99 should be 10s
        let p99 = agg.p99_total_time().unwrap();
        assert!(p99 >= Duration::from_secs(9));
    }

    #[test]
    fn test_metrics_aggregator_success_rate() {
        let mut agg = MetricsAggregator::new(100);

        // Empty case
        assert_eq!(agg.success_rate(), 100.0);

        // All successful
        agg.record(make_test_metrics(Some(1.0), 10, true));
        agg.record(make_test_metrics(Some(1.0), 10, true));
        assert_eq!(agg.success_rate(), 100.0);

        // Add a failure (2 success, 1 failure = 66.67%)
        agg.record(make_test_metrics(Some(1.0), 10, false));
        let rate = agg.success_rate();
        assert!((rate - 66.67).abs() < 1.0, "Expected ~66.67%, got {}", rate);
    }

    #[test]
    fn test_metrics_aggregator_clear() {
        let mut agg = MetricsAggregator::new(100);
        agg.record(make_test_metrics(Some(1.0), 10, true));
        agg.record(make_test_metrics(Some(2.0), 20, true));

        assert_eq!(agg.count(), 2);

        agg.clear();
        assert_eq!(agg.count(), 0);
        assert!(agg.average_speedup().is_none());
    }
}
