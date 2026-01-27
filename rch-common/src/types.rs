//! Common types used across RCH components.

use crate::{CompilationKind, toolchain::ToolchainInfo};
use rand::Rng;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Unique identifier for a worker in the fleet.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum WorkerStatus {
    /// Worker is healthy and accepting jobs.
    #[default]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CircuitState {
    /// Normal operation.
    #[default]
    Closed,
    /// Circuit is open (short-circuit).
    Open,
    /// Circuit is half-open (probing).
    HalfOpen,
}

/// Required runtime for command execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum RequiredRuntime {
    /// No specific runtime required (default).
    #[default]
    None,
    /// Requires Rust toolchain.
    Rust,
    /// Requires Bun runtime.
    Bun,
    /// Requires Node.js runtime.
    Node,
}

/// Per-command priority hint for worker selection.
///
/// This is an *input hint* from the caller (typically the hook) and should not
/// change default behavior when omitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum CommandPriority {
    Low,
    #[default]
    Normal,
    High,
}

impl std::fmt::Display for CommandPriority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::Low => "low",
            Self::Normal => "normal",
            Self::High => "high",
        };
        write!(f, "{}", value)
    }
}

impl std::str::FromStr for CommandPriority {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "low" => Ok(Self::Low),
            "normal" => Ok(Self::Normal),
            "high" => Ok(Self::High),
            _ => Err(()),
        }
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
    /// Priority hint for this request.
    #[serde(default)]
    pub command_priority: CommandPriority,
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
    /// Process ID of the hook (for active build tracking).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hook_pid: Option<u32>,
}

/// Reason for worker selection result.
///
/// Provides context when no worker is available, enabling informative
/// fallback messages in the hook.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
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
    /// Worker assigned via affinity pinning (recent successful build).
    AffinityPinned,
    /// Worker assigned via last-success fallback (all others unavailable).
    AffinityFallback,
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
            Self::AffinityPinned => write!(f, "worker assigned via affinity pinning"),
            Self::AffinityFallback => write!(f, "worker assigned via last-success fallback"),
        }
    }
}

// ============================================================================
// Worker Selection Strategy
// ============================================================================

/// Worker selection strategy determining how workers are chosen for jobs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SelectionStrategy {
    /// Original behavior: sort by priority, select first available.
    /// Use for backwards compatibility or manual control.
    #[default]
    Priority,
    /// Select worker with highest SpeedScore.
    /// Best for performance-critical builds with homogeneous workers.
    Fastest,
    /// Balance all factors: SpeedScore, load, health, cache affinity.
    /// Default recommendation for diverse worker pools.
    Balanced,
    /// Prefer workers with warm caches for the project.
    /// Best for incremental builds on large codebases.
    CacheAffinity,
    /// Weighted random selection favoring fast workers but ensuring fairness.
    /// Prevents hot-spotting when many workers are available.
    FairFastest,
}

impl std::fmt::Display for SelectionStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Priority => "priority",
            Self::Fastest => "fastest",
            Self::Balanced => "balanced",
            Self::CacheAffinity => "cache_affinity",
            Self::FairFastest => "fair_fastest",
        };
        write!(f, "{}", name)
    }
}

impl std::str::FromStr for SelectionStrategy {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "priority" => Ok(Self::Priority),
            "fastest" => Ok(Self::Fastest),
            "balanced" => Ok(Self::Balanced),
            "cache_affinity" | "cache-affinity" | "cacheaffinity" => Ok(Self::CacheAffinity),
            "fair_fastest" | "fair-fastest" | "fairfastest" => Ok(Self::FairFastest),
            _ => Err(format!(
                "unknown selection strategy '{}', expected one of: priority, fastest, balanced, cache_affinity, fair_fastest",
                s
            )),
        }
    }
}

/// Configuration for the worker selection algorithm.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectionConfig {
    /// Selection strategy to use.
    #[serde(default)]
    pub strategy: SelectionStrategy,
    /// Minimum success rate (0.0-1.0) for a worker to be considered.
    #[serde(default = "default_min_success_rate")]
    pub min_success_rate: f64,
    /// Factor weights for the balanced strategy.
    #[serde(default)]
    pub weights: SelectionWeightConfig,
    /// Fairness settings for fair_fastest strategy.
    #[serde(default)]
    pub fairness: FairnessConfig,
    /// Cache affinity settings for project-to-worker pinning.
    #[serde(default)]
    pub affinity: AffinityConfig,

    // Preflight health guards (bd-3eaa)
    /// Maximum load-per-core threshold. Workers exceeding this are skipped.
    /// Set to None to disable load-based filtering.
    #[serde(default = "default_max_load_per_core")]
    pub max_load_per_core: Option<f64>,
    /// Minimum free disk space in GB. Workers below this are skipped.
    /// Set to None to disable disk-based filtering.
    #[serde(default = "default_min_free_gb")]
    pub min_free_gb: Option<f64>,
}

impl Default for SelectionConfig {
    fn default() -> Self {
        Self {
            strategy: SelectionStrategy::default(),
            min_success_rate: default_min_success_rate(),
            weights: SelectionWeightConfig::default(),
            fairness: FairnessConfig::default(),
            affinity: AffinityConfig::default(),
            max_load_per_core: default_max_load_per_core(),
            min_free_gb: default_min_free_gb(),
        }
    }
}

fn default_min_success_rate() -> f64 {
    0.8
}

fn default_max_load_per_core() -> Option<f64> {
    Some(2.0) // Skip workers with load/core > 2.0
}

fn default_min_free_gb() -> Option<f64> {
    Some(10.0) // Skip workers with < 10 GB free
}

/// Weight configuration for the balanced selection strategy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectionWeightConfig {
    /// Weight for SpeedScore (0.0-1.0).
    #[serde(default = "default_weight_speedscore")]
    pub speedscore: f64,
    /// Weight for available slots (0.0-1.0).
    #[serde(default = "default_weight_slots")]
    pub slots: f64,
    /// Weight for health/success rate (0.0-1.0).
    #[serde(default = "default_weight_health")]
    pub health: f64,
    /// Weight for cache affinity (0.0-1.0).
    #[serde(default = "default_weight_cache")]
    pub cache: f64,
    /// Weight for network latency (0.0-1.0).
    #[serde(default = "default_weight_network")]
    pub network: f64,
    /// Weight for worker priority (0.0-1.0).
    #[serde(default = "default_weight_priority")]
    pub priority: f64,
    /// Penalty multiplier for half-open circuit workers (0.0-1.0).
    #[serde(default = "default_half_open_penalty")]
    pub half_open_penalty: f64,
}

impl Default for SelectionWeightConfig {
    fn default() -> Self {
        Self {
            speedscore: default_weight_speedscore(),
            slots: default_weight_slots(),
            health: default_weight_health(),
            cache: default_weight_cache(),
            network: default_weight_network(),
            priority: default_weight_priority(),
            half_open_penalty: default_half_open_penalty(),
        }
    }
}

fn default_weight_speedscore() -> f64 {
    0.5
}
fn default_weight_slots() -> f64 {
    0.4
}
fn default_weight_health() -> f64 {
    0.3
}
fn default_weight_cache() -> f64 {
    0.2
}
fn default_weight_network() -> f64 {
    0.1
}
fn default_weight_priority() -> f64 {
    0.1
}
fn default_half_open_penalty() -> f64 {
    0.5
}

/// Fairness settings for the fair_fastest selection strategy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FairnessConfig {
    /// Lookback window in seconds for tracking recent selections.
    #[serde(default = "default_fairness_lookback_secs")]
    pub lookback_secs: u64,
    /// Maximum consecutive selections for a single worker before penalty.
    #[serde(default = "default_max_consecutive_selections")]
    pub max_consecutive_selections: u32,
}

impl Default for FairnessConfig {
    fn default() -> Self {
        Self {
            lookback_secs: default_fairness_lookback_secs(),
            max_consecutive_selections: default_max_consecutive_selections(),
        }
    }
}

fn default_fairness_lookback_secs() -> u64 {
    300 // 5 minutes
}

fn default_max_consecutive_selections() -> u32 {
    3
}

/// Cache affinity settings for project-to-worker pinning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AffinityConfig {
    /// Enable affinity pinning (pin projects to last successful worker).
    #[serde(default = "default_affinity_enabled")]
    pub enabled: bool,
    /// Time window in minutes to pin a project to its last successful worker.
    /// After this window expires, normal selection resumes.
    #[serde(default = "default_affinity_pin_minutes")]
    pub pin_minutes: u64,
    /// Enable last-success fallback when no workers match selection criteria.
    /// If enabled, the daemon will attempt the last successful worker for a project
    /// when all other workers are unavailable or fail selection.
    #[serde(default = "default_last_success_fallback")]
    pub enable_last_success_fallback: bool,
    /// Minimum success rate for the last-success worker to be used as fallback.
    /// Must be lower than min_success_rate to be meaningful as a fallback.
    #[serde(default = "default_fallback_min_success_rate")]
    pub fallback_min_success_rate: f64,
}

impl Default for AffinityConfig {
    fn default() -> Self {
        Self {
            enabled: default_affinity_enabled(),
            pin_minutes: default_affinity_pin_minutes(),
            enable_last_success_fallback: default_last_success_fallback(),
            fallback_min_success_rate: default_fallback_min_success_rate(),
        }
    }
}

fn default_affinity_enabled() -> bool {
    true
}

fn default_affinity_pin_minutes() -> u64 {
    60 // 1 hour default
}

fn default_last_success_fallback() -> bool {
    true
}

fn default_fallback_min_success_rate() -> f64 {
    0.5 // More lenient than normal min_success_rate (0.8)
}

/// Details about a selected worker for remote compilation.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
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
    /// Optional exit code for the build (used to finalize active build tracking).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// Optional total duration in milliseconds (pipeline or execution).
    ///
    /// If omitted, the daemon will compute duration from the active build's start time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    /// Optional bytes transferred during the pipeline (upload + artifact download).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_transferred: Option<u64>,
    /// Optional per-phase timing breakdown for the build pipeline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timing: Option<CommandTimingBreakdown>,
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
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
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

    // Health metrics (bd-3eaa)
    /// Number of CPU cores on the worker.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub num_cpus: Option<u32>,
    /// 1-minute load average.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load_avg_1: Option<f64>,
    /// 5-minute load average.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load_avg_5: Option<f64>,
    /// 15-minute load average.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load_avg_15: Option<f64>,
    /// Free disk space in GB (on /tmp or build directory).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_free_gb: Option<f64>,
    /// Total disk space in GB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_total_gb: Option<f64>,
}

impl WorkerCapabilities {
    /// Create new empty capabilities.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create mock capabilities with Rust installed.
    ///
    /// Used by mock transport to simulate a worker with Rust toolchain.
    pub fn mock_with_rust() -> Self {
        Self {
            rustc_version: Some("1.85.0-nightly (mock)".to_string()),
            ..Self::default()
        }
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

    /// Calculate load per core (1-minute load average / num_cpus).
    /// Returns None if metrics are unavailable.
    pub fn load_per_core(&self) -> Option<f64> {
        match (self.load_avg_1, self.num_cpus) {
            (Some(load), Some(cpus)) if cpus > 0 => Some(load / cpus as f64),
            _ => None,
        }
    }

    /// Check if worker has high load (exceeds threshold).
    /// Returns None if metrics unavailable (fail-open).
    pub fn is_high_load(&self, max_load_per_core: f64) -> Option<bool> {
        self.load_per_core().map(|lpc| lpc > max_load_per_core)
    }

    /// Check if worker has low disk space (below threshold).
    /// Returns None if metrics unavailable (fail-open).
    pub fn is_low_disk(&self, min_free_gb: f64) -> Option<bool> {
        self.disk_free_gb.map(|free| free < min_free_gb)
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
    pub environment: EnvironmentConfig,
    #[serde(default)]
    pub circuit: CircuitBreakerConfig,
    #[serde(default)]
    pub output: OutputConfig,
    #[serde(default)]
    pub self_healing: SelfHealingConfig,
    #[serde(default)]
    pub self_test: SelfTestConfig,
    /// Worker selection algorithm configuration.
    #[serde(default)]
    pub selection: SelectionConfig,
    /// Execution allowlist configuration (bd-785w).
    #[serde(default)]
    pub execution: ExecutionConfig,
    /// Worker health alerting configuration (daemon).
    #[serde(default)]
    pub alerts: AlertsConfig,
}

/// Worker health alerting configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertsConfig {
    /// Enable or disable alert generation in the daemon.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Suppress duplicate alerts for this many seconds.
    #[serde(default = "default_alert_suppress_duplicates_secs")]
    pub suppress_duplicates_secs: u64,
    /// Webhook configuration for external notifications.
    #[serde(default)]
    pub webhook: Option<WebhookConfig>,
}

/// Webhook configuration for alert dispatch.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WebhookConfig {
    /// Webhook endpoint URL (e.g., Slack/Discord webhook URL).
    pub url: Option<String>,
    /// Secret for HMAC-SHA256 signing (optional).
    #[serde(default)]
    pub secret: Option<String>,
    /// Timeout in seconds for webhook requests.
    #[serde(default = "default_webhook_timeout_secs")]
    pub timeout_secs: u64,
    /// Number of retries on failure.
    #[serde(default = "default_webhook_retry_count")]
    pub retry_count: u32,
    /// Events to send (empty = all events).
    /// Supported: worker_offline, worker_degraded, circuit_open, all_workers_offline
    #[serde(default)]
    pub events: Vec<String>,
}

fn default_webhook_timeout_secs() -> u64 {
    5
}

fn default_webhook_retry_count() -> u32 {
    3
}

fn default_alert_suppress_duplicates_secs() -> u64 {
    300
}

impl Default for AlertsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            suppress_duplicates_secs: default_alert_suppress_duplicates_secs(),
            webhook: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    /// Whether RCH is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Force local execution for this project (never offload), even if the command is classified.
    ///
    /// Intended for sensitive projects or cases where local state must be authoritative.
    #[serde(default)]
    pub force_local: bool,
    /// Force remote execution for this project (always attempt offload) when safe.
    ///
    /// This bypasses heuristic gating (e.g. confidence threshold overrides) but still respects
    /// structural safety checks and NEVER_INTERCEPT patterns.
    #[serde(default)]
    pub force_remote: bool,
    /// Log level (trace, debug, info, warn, error).
    #[serde(default = "default_log_level")]
    pub log_level: String,
    /// Path to Unix socket for daemon communication.
    #[serde(default = "default_socket_path")]
    pub socket_path: String,
}

/// Environment variable passthrough configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnvironmentConfig {
    /// Allowlist of environment variables to forward to remote workers.
    #[serde(default)]
    pub allowlist: Vec<String>,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            force_local: false,
            force_remote: false,
            log_level: "info".to_string(),
            socket_path: default_socket_path(),
        }
    }
}

/// Visibility level for hook output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum OutputVisibility {
    #[default]
    None,
    Summary,
    Verbose,
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

/// Color mode for remote command output.
///
/// Controls whether ANSI color codes are preserved when streaming
/// output from remote compilation commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ColorMode {
    /// Force color output regardless of terminal detection.
    /// Sets CARGO_TERM_COLOR=always and similar environment variables.
    #[default]
    Always,
    /// Let the remote command detect terminal capabilities (may lose colors).
    Auto,
    /// Disable color output entirely.
    Never,
}

impl std::fmt::Display for ColorMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            ColorMode::Always => "always",
            ColorMode::Auto => "auto",
            ColorMode::Never => "never",
        };
        write!(f, "{}", value)
    }
}

impl std::str::FromStr for ColorMode {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "always" | "force" | "yes" | "true" => Ok(Self::Always),
            "auto" | "detect" => Ok(Self::Auto),
            "never" | "none" | "no" | "false" => Ok(Self::Never),
            _ => Err(()),
        }
    }
}

fn default_color_mode() -> ColorMode {
    ColorMode::default()
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
    /// Color mode for remote command output.
    /// Controls whether ANSI color codes are preserved in remote output.
    #[serde(default = "default_color_mode")]
    pub color_mode: ColorMode,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            visibility: OutputVisibility::None,
            first_run_complete: false,
            color_mode: ColorMode::default(),
        }
    }
}

// ============================================================================
// Self-Healing Configuration
// ============================================================================

fn default_autostart_cooldown_secs() -> u64 {
    30
}

fn default_autostart_timeout_secs() -> u64 {
    3
}

/// Self-healing behaviors for the hook and daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfHealingConfig {
    /// Whether the hook should attempt to auto-start the daemon.
    #[serde(default = "default_true")]
    pub hook_starts_daemon: bool,
    /// Whether the daemon should auto-install Claude Code hooks on startup.
    #[serde(default = "default_true")]
    pub daemon_installs_hooks: bool,
    /// Cooldown between auto-start attempts in seconds.
    #[serde(default = "default_autostart_cooldown_secs")]
    pub auto_start_cooldown_secs: u64,
    /// Time to wait for the daemon socket after spawning in seconds.
    /// Also aliased as `daemon_start_timeout` for backwards compatibility.
    #[serde(
        default = "default_autostart_timeout_secs",
        alias = "daemon_start_timeout"
    )]
    pub auto_start_timeout_secs: u64,
}

impl Default for SelfHealingConfig {
    fn default() -> Self {
        Self {
            hook_starts_daemon: default_true(),
            daemon_installs_hooks: default_true(),
            auto_start_cooldown_secs: default_autostart_cooldown_secs(),
            auto_start_timeout_secs: default_autostart_timeout_secs(),
        }
    }
}

impl SelfHealingConfig {
    /// Apply environment variable overrides to this config.
    ///
    /// Supported environment variables:
    /// - `RCH_NO_SELF_HEALING=1` - Master switch to disable all self-healing
    /// - `RCH_HOOK_STARTS_DAEMON=0|1` - Control hook auto-starting daemon
    /// - `RCH_DAEMON_INSTALLS_HOOKS=0|1` - Control daemon auto-installing hooks
    /// - `RCH_AUTO_START_TIMEOUT_SECS=<seconds>` - Max wait for daemon start
    /// - `RCH_AUTO_START_COOLDOWN_SECS=<seconds>` - Min time between auto-starts
    pub fn with_env_overrides(mut self) -> Self {
        // Master disable switch
        if let Ok(val) = std::env::var("RCH_NO_SELF_HEALING")
            && (val == "1" || val.eq_ignore_ascii_case("true"))
        {
            self.hook_starts_daemon = false;
            self.daemon_installs_hooks = false;
            return self;
        }

        // Individual toggles
        if let Ok(val) = std::env::var("RCH_HOOK_STARTS_DAEMON") {
            self.hook_starts_daemon = val != "0" && !val.eq_ignore_ascii_case("false");
        }
        if let Ok(val) = std::env::var("RCH_DAEMON_INSTALLS_HOOKS") {
            self.daemon_installs_hooks = val != "0" && !val.eq_ignore_ascii_case("false");
        }

        // Numeric settings
        if let Ok(val) = std::env::var("RCH_AUTO_START_TIMEOUT_SECS")
            && let Ok(secs) = val.parse()
        {
            self.auto_start_timeout_secs = secs;
        }
        if let Ok(val) = std::env::var("RCH_AUTO_START_COOLDOWN_SECS")
            && let Ok(secs) = val.parse()
        {
            self.auto_start_cooldown_secs = secs;
        }

        self
    }
}

// ============================================================================
// Self-Test Configuration
// ============================================================================

/// Action to take when a scheduled self-test fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SelfTestFailureAction {
    /// Only emit an alert/log entry.
    #[default]
    Alert,
    /// Disable the failing worker automatically.
    DisableWorker,
    /// Alert and disable the worker.
    AlertAndDisable,
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
    /// Minimum expected speedup ratio (local_time / remote_time) to offload.
    /// If predicted speedup < threshold, run locally. Default: 1.2 (20% faster).
    /// Set to 1.0 to always offload when other criteria are met.
    #[serde(default = "default_speedup_threshold")]
    pub remote_speedup_threshold: f64,
    /// Default slot estimate for build commands (cargo build, gcc, etc.).
    #[serde(default = "default_build_slots")]
    pub build_slots: u32,
    /// Default slot estimate for test commands (cargo test, nextest).
    /// Tests typically use more parallelism than builds.
    #[serde(default = "default_test_slots")]
    pub test_slots: u32,
    /// Default slot estimate for check/lint commands (cargo check, clippy).
    /// These are typically faster and use fewer resources.
    #[serde(default = "default_check_slots")]
    pub check_slots: u32,
    /// Timeout in seconds for build commands.
    /// Build commands (cargo build, gcc, etc.) typically complete faster than tests.
    #[serde(default = "default_build_timeout")]
    pub build_timeout_sec: u64,
    /// Timeout in seconds for test commands.
    /// Test commands often need longer timeouts due to test suite execution time.
    #[serde(default = "default_test_timeout")]
    pub test_timeout_sec: u64,
}

impl Default for CompilationConfig {
    fn default() -> Self {
        Self {
            confidence_threshold: 0.85,
            min_local_time_ms: 2000,
            remote_speedup_threshold: default_speedup_threshold(),
            build_slots: default_build_slots(),
            test_slots: default_test_slots(),
            check_slots: default_check_slots(),
            build_timeout_sec: default_build_timeout(),
            test_timeout_sec: default_test_timeout(),
        }
    }
}

fn default_build_slots() -> u32 {
    4
}

fn default_test_slots() -> u32 {
    8
}

fn default_check_slots() -> u32 {
    2
}

/// Default build timeout: 5 minutes (300 seconds).
/// Most builds complete well within this time.
fn default_build_timeout() -> u64 {
    300
}

/// Default test timeout: 30 minutes (1800 seconds).
/// Test suites often take significantly longer than builds.
fn default_test_timeout() -> u64 {
    1800
}

impl CompilationConfig {
    /// Returns the appropriate timeout for the given compilation kind.
    ///
    /// Test commands get the longer test timeout, while all other commands
    /// (builds, checks, clippy, etc.) use the build timeout.
    pub fn timeout_for_kind(&self, kind: Option<CompilationKind>) -> std::time::Duration {
        let secs = match kind {
            Some(CompilationKind::CargoTest)
            | Some(CompilationKind::CargoNextest)
            | Some(CompilationKind::BunTest) => self.test_timeout_sec,
            _ => self.build_timeout_sec,
        };
        std::time::Duration::from_secs(secs)
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
    /// SSH keepalive interval in seconds (`ssh -o ServerAliveInterval=<N>`).
    ///
    /// When unset, OpenSSH defaults apply (keepalive disabled).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_server_alive_interval_secs: Option<u64>,
    /// SSH ControlPersist idle timeout in seconds (`ssh -o ControlPersist=<N>s`).
    ///
    /// - Unset preserves OpenSSH defaults (ControlPersist enabled by default via mux).
    /// - `0` disables persistence (`ControlPersist=no`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_control_persist_secs: Option<u64>,
    /// Remote base directory for project sync and build execution.
    /// Must be an absolute path. Defaults to /tmp/rch.
    #[serde(default = "default_remote_base")]
    pub remote_base: String,
    /// Retry policy for transient network errors during transfer.
    #[serde(default)]
    pub retry: RetryConfig,
    /// Verify artifact integrity using blake3 hashes after transfer (bd-377q).
    ///
    /// When enabled, computes blake3 hashes of key artifacts (binaries, test outputs)
    /// on the worker after build, then verifies them locally after download.
    /// Disabled by default to avoid extra overhead.
    #[serde(default)]
    pub verify_artifacts: bool,
    /// Maximum file size (bytes) for artifact verification (bd-377q).
    ///
    /// Files larger than this limit are skipped during verification to avoid
    /// excessive I/O. Defaults to 100MB.
    #[serde(default = "default_verify_max_size")]
    pub verify_max_size_bytes: u64,

    // =========================================================================
    // Transfer Optimization (bd-3hho)
    // =========================================================================
    /// Maximum transfer size in MB before skipping remote execution.
    ///
    /// When set, runs `rsync --dry-run --stats` to estimate transfer size.
    /// If the estimated size exceeds this threshold, remote offload is skipped
    /// and the command runs locally. Set to `None` (default) to disable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_transfer_mb: Option<u64>,

    /// Maximum estimated transfer time in milliseconds before skipping remote.
    ///
    /// Uses `estimated_bandwidth_bps` (or measured link speed) to calculate
    /// expected transfer time. If it exceeds this threshold, remote offload
    /// is skipped. Set to `None` (default) to disable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_transfer_time_ms: Option<u64>,

    /// Bandwidth limit for rsync in KB/s.
    ///
    /// Passed as `rsync --bwlimit=<N>` to limit transfer speed and prevent
    /// network saturation. Set to `None` or `0` (default) for unlimited.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bwlimit_kbps: Option<u64>,

    /// Estimated link bandwidth in bytes per second.
    ///
    /// Used for transfer time estimation when `max_transfer_time_ms` is set.
    /// If not provided, defaults to 10 MB/s (10485760 bytes/sec).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub estimated_bandwidth_bps: Option<u64>,

    // =========================================================================
    // Adaptive Compression (bd-243w)
    // =========================================================================
    /// Enable adaptive zstd compression based on transfer size (bd-243w).
    ///
    /// When enabled, automatically selects compression level based on estimated
    /// payload size:
    /// - < 10MB: level 1 (fast, minimal compression)
    /// - 10-200MB: level 3 (balanced, default)
    /// - > 200MB: level 7 (slower, better compression)
    ///
    /// When disabled (default), uses the fixed `compression_level` setting.
    #[serde(default)]
    pub adaptive_compression: bool,

    /// Minimum compression level for adaptive mode (bd-243w).
    ///
    /// Even in adaptive mode, compression level won't go below this.
    /// Defaults to 1.
    #[serde(default = "default_min_compression")]
    pub min_compression_level: u32,

    /// Maximum compression level for adaptive mode (bd-243w).
    ///
    /// Even in adaptive mode, compression level won't exceed this.
    /// Defaults to 9 (avoids CPU-intensive levels 10+).
    #[serde(default = "default_max_compression")]
    pub max_compression_level: u32,
}

impl Default for TransferConfig {
    fn default() -> Self {
        Self {
            compression_level: 3,
            exclude_patterns: default_excludes(),
            ssh_server_alive_interval_secs: None,
            ssh_control_persist_secs: None,
            remote_base: default_remote_base(),
            retry: RetryConfig::default(),
            verify_artifacts: false,
            verify_max_size_bytes: default_verify_max_size(),
            // Transfer optimization (bd-3hho)
            max_transfer_mb: None,
            max_transfer_time_ms: None,
            bwlimit_kbps: None,
            estimated_bandwidth_bps: None,
            // Adaptive compression (bd-243w)
            adaptive_compression: false,
            min_compression_level: default_min_compression(),
            max_compression_level: default_max_compression(),
        }
    }
}

impl TransferConfig {
    /// Select compression level based on estimated transfer size (bd-243w).
    ///
    /// When adaptive compression is enabled, selects an appropriate level
    /// based on payload size:
    /// - < 10MB: level 1 (fast, minimal compression)
    /// - 10-200MB: level 3 (balanced)
    /// - > 200MB: level 7 (better compression)
    ///
    /// The result is clamped between `min_compression_level` and `max_compression_level`.
    ///
    /// When adaptive compression is disabled, returns the fixed `compression_level`.
    pub fn select_compression_level(&self, estimated_bytes: Option<u64>) -> u32 {
        if !self.adaptive_compression {
            return self.compression_level;
        }

        let Some(bytes) = estimated_bytes else {
            // No estimate available, use default
            return self.compression_level;
        };

        // Size thresholds
        const SMALL_THRESHOLD: u64 = 10_000_000; // 10 MB (decimal)
        const LARGE_THRESHOLD: u64 = 200_000_000; // 200 MB (decimal)

        let level = if bytes < SMALL_THRESHOLD {
            1 // Fast compression for small payloads
        } else if bytes < LARGE_THRESHOLD {
            3 // Balanced for medium payloads
        } else {
            7 // Better compression for large payloads
        };

        // Clamp to configured bounds
        level.clamp(self.min_compression_level, self.max_compression_level)
    }
}

// =============================================================================
// Execution Configuration (bd-785w)
// =============================================================================

/// Default allowlist of commands that can be executed remotely.
/// Aligned with the classifier's supported CompilationKind values.
fn default_execution_allowlist() -> Vec<String> {
    vec![
        // Rust
        "cargo".to_string(),
        "rustc".to_string(),
        // cargo-nextest
        "nextest".to_string(),
        // C/C++
        "gcc".to_string(),
        "g++".to_string(),
        "clang".to_string(),
        "clang++".to_string(),
        "cc".to_string(),
        "c++".to_string(),
        // Build systems
        "make".to_string(),
        "cmake".to_string(),
        "ninja".to_string(),
        "meson".to_string(),
        // Bun
        "bun".to_string(),
    ]
}

/// Execution allowlist configuration for remote builds (bd-785w).
///
/// Controls which command base names are permitted for remote execution.
/// Commands not in the allowlist will fail-open to local execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionConfig {
    /// Allowlist of command base names permitted for remote execution.
    ///
    /// Examples: "cargo", "rustc", "gcc", "bun"
    ///
    /// If a classified compilation command's base name is not in this list,
    /// RCH will fail-open to local execution with a clear reason.
    ///
    /// An empty allowlist disables all remote execution (local only).
    #[serde(default = "default_execution_allowlist")]
    pub allowlist: Vec<String>,
}

impl Default for ExecutionConfig {
    fn default() -> Self {
        Self {
            allowlist: default_execution_allowlist(),
        }
    }
}

impl ExecutionConfig {
    /// Check if a command base name is allowed for remote execution.
    pub fn is_allowed(&self, command_base: &str) -> bool {
        self.allowlist
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(command_base))
    }
}

// =============================================================================
// Retry Configuration (bd-x1ek)
// =============================================================================

fn default_retry_max_attempts() -> u32 {
    3
}

fn default_retry_base_delay_ms() -> u64 {
    100
}

fn default_retry_max_delay_ms() -> u64 {
    5000
}

fn default_retry_jitter_factor() -> f64 {
    0.1
}

fn default_retry_total_timeout_ms() -> u64 {
    30000
}

/// Configuration for retry behavior on transient errors.
///
/// Used by rsync and SSH operations to recover from transient network failures
/// without blocking too long or retrying non-recoverable errors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum number of retry attempts (1 = no retries, just initial attempt).
    #[serde(default = "default_retry_max_attempts")]
    pub max_attempts: u32,

    /// Initial delay between retries in milliseconds.
    #[serde(default = "default_retry_base_delay_ms")]
    pub base_delay_ms: u64,

    /// Maximum delay between retries in milliseconds (caps exponential backoff).
    #[serde(default = "default_retry_max_delay_ms")]
    pub max_delay_ms: u64,

    /// Jitter factor (0.0 - 1.0) to randomize delay.
    /// A value of 0.1 means ±10% randomization.
    #[serde(default = "default_retry_jitter_factor")]
    pub jitter_factor: f64,

    /// Total timeout for all retry attempts in milliseconds.
    /// After this, retries stop even if max_attempts not reached.
    #[serde(default = "default_retry_total_timeout_ms")]
    pub total_timeout_ms: u64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: default_retry_max_attempts(),
            base_delay_ms: default_retry_base_delay_ms(),
            max_delay_ms: default_retry_max_delay_ms(),
            jitter_factor: default_retry_jitter_factor(),
            total_timeout_ms: default_retry_total_timeout_ms(),
        }
    }
}

impl RetryConfig {
    /// Create a config that disables retries (single attempt only).
    pub fn no_retry() -> Self {
        Self {
            max_attempts: 1,
            ..Default::default()
        }
    }

    /// Calculate delay for a given attempt number (0-indexed).
    ///
    /// Uses exponential backoff with optional jitter.
    pub fn delay_for_attempt(&self, attempt: u32) -> std::time::Duration {
        if attempt == 0 {
            return std::time::Duration::ZERO;
        }

        // Exponential backoff: base * 2^attempt
        let base = self.base_delay_ms as f64;
        let delay = base * (2.0_f64.powi(attempt as i32 - 1));
        let capped = delay.min(self.max_delay_ms as f64);

        // Apply jitter: delay ± (delay * jitter_factor)
        let jittered = if self.jitter_factor > 0.0 {
            let jitter_range = capped * self.jitter_factor;
            let jitter = (rand::rng().random::<f64>() * 2.0 - 1.0) * jitter_range;
            (capped + jitter).max(0.0)
        } else {
            capped
        };

        std::time::Duration::from_millis(jittered as u64)
    }

    /// Check if we should retry given elapsed time since start.
    pub fn should_retry(&self, attempt: u32, elapsed: std::time::Duration) -> bool {
        if attempt >= self.max_attempts {
            return false;
        }
        elapsed.as_millis() < self.total_timeout_ms as u128
    }
}

/// Default remote base path for project transfers.
pub fn default_remote_base() -> String {
    "/tmp/rch".to_string()
}

/// Validate and normalize a remote base path.
/// Returns an error if the path is not absolute or contains traversal sequences.
pub fn validate_remote_base(path: &str) -> Result<String, String> {
    // Expand tilde for user convenience
    let expanded = shellexpand::tilde(path).into_owned();

    // Check for absolute path
    if !expanded.starts_with('/') {
        return Err(format!(
            "remote_base must be an absolute path, got: {}",
            path
        ));
    }

    // Check for path traversal attempts
    if expanded.contains("..") {
        return Err(format!(
            "remote_base must not contain path traversal (..): {}",
            path
        ));
    }

    // Normalize: remove trailing slashes
    let normalized = expanded.trim_end_matches('/').to_string();

    // Safety checks
    if normalized.is_empty() || normalized == "/" {
        return Err("remote_base cannot be the root directory (safety restriction)".to_string());
    }

    // Enforce at least 2 levels deep (e.g. /tmp/rch, /home/user/rch)
    // /tmp -> depth 1 (unsafe for recursive delete)
    // /tmp/rch -> depth 2 (safe)
    let components: Vec<&str> = normalized.split('/').filter(|c| !c.is_empty()).collect();
    if components.len() < 2 {
        return Err(format!(
            "remote_base must be at least 2 levels deep (e.g. /tmp/rch), got: {}",
            normalized
        ));
    }

    Ok(normalized)
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
    if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR")
        && !runtime_dir.trim().is_empty()
    {
        let path = PathBuf::from(runtime_dir).join("rch.sock");
        return path.to_string_lossy().to_string();
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

/// Default speedup threshold: 1.2 (require 20% speedup to offload).
/// This is conservative to avoid offloading builds that would be only
/// marginally faster remotely when accounting for transfer overhead.
fn default_speedup_threshold() -> f64 {
    1.2
}

fn default_compression() -> u32 {
    3
}

/// Default maximum file size for artifact verification (100MB).
fn default_verify_max_size() -> u64 {
    100 * 1024 * 1024 // 100MB
}

/// Default minimum compression level for adaptive mode.
fn default_min_compression() -> u32 {
    1
}

/// Default maximum compression level for adaptive mode.
fn default_max_compression() -> u32 {
    9
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BuildLocation {
    /// Build executed locally.
    #[default]
    Local,
    /// Build executed on a remote worker.
    Remote,
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
    /// Optional timing breakdown for the pipeline.
    #[serde(default)]
    pub timing: Option<CommandTimingBreakdown>,
}

/// Input payload for recording a completed build.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildRecordInput {
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
    /// Optional timing breakdown for the pipeline.
    #[serde(default)]
    pub timing: Option<CommandTimingBreakdown>,
}

impl BuildRecordInput {
    /// Convert input payload into a build record with a supplied ID.
    pub fn into_record(self, id: u64) -> BuildRecord {
        BuildRecord {
            id,
            started_at: self.started_at,
            completed_at: self.completed_at,
            project_id: self.project_id,
            worker_id: self.worker_id,
            command: self.command,
            exit_code: self.exit_code,
            duration_ms: self.duration_ms,
            location: self.location,
            bytes_transferred: self.bytes_transferred,
            timing: self.timing,
        }
    }
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

/// Saved time statistics from remote builds.
///
/// Tracks estimated time savings from offloading builds to remote workers.
/// Uses local build history to estimate what remote builds would have taken locally.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SavedTimeStats {
    /// Total time spent on remote builds (milliseconds).
    pub total_remote_duration_ms: u64,
    /// Estimated total time if those builds ran locally (milliseconds).
    pub estimated_local_duration_ms: u64,
    /// Time saved by offloading (milliseconds).
    /// Computed as max(0, estimated_local - remote).
    pub time_saved_ms: u64,
    /// Number of remote builds included in calculation.
    pub builds_counted: usize,
    /// Average speedup factor (local_estimate / remote_duration).
    /// A value of 2.0 means remote builds are ~2x faster than local.
    pub avg_speedup: f64,
    /// Total time saved today (milliseconds).
    pub today_saved_ms: u64,
    /// Total time saved this week (milliseconds).
    pub week_saved_ms: u64,
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

/// Timing breakdown for a single command pipeline.
///
/// Uses optional durations so missing phases serialize as `null`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CommandTimingBreakdown {
    /// Time spent classifying the command.
    #[serde(with = "option_duration_millis")]
    pub classify: Option<Duration>,
    /// Time spent selecting a worker.
    #[serde(with = "option_duration_millis")]
    pub select: Option<Duration>,
    /// Time spent syncing source files to the worker.
    #[serde(with = "option_duration_millis")]
    pub sync_up: Option<Duration>,
    /// Time spent executing the remote command.
    #[serde(with = "option_duration_millis")]
    pub exec: Option<Duration>,
    /// Time spent syncing artifacts back.
    #[serde(with = "option_duration_millis")]
    pub sync_down: Option<Duration>,
    /// Time spent on cleanup (slot release, bookkeeping).
    #[serde(with = "option_duration_millis")]
    pub cleanup: Option<Duration>,
    /// Total end-to-end time for the pipeline.
    #[serde(with = "option_duration_millis")]
    pub total: Option<Duration>,
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
        if let Some(local) = self.local_build_time
            && self.timing.total.as_millis() > 0
        {
            self.speedup = Some(local.as_secs_f64() / self.timing.total.as_secs_f64());
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
    use crate::test_guard;

    #[test]
    fn test_circuit_state_default() {
        let _guard = test_guard!();
        assert_eq!(CircuitState::default(), CircuitState::Closed);
    }

    #[test]
    fn test_circuit_config_defaults() {
        let _guard = test_guard!();
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
        let _guard = test_guard!();
        let config = RchConfig::default();
        assert_eq!(config.circuit.failure_threshold, 3);
    }

    #[test]
    fn test_circuit_config_serde_roundtrip() {
        let _guard = test_guard!();
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

    // ========================================================================
    // WorkerCapabilities Tests
    // ========================================================================

    #[test]
    fn test_worker_capabilities_default() {
        let _guard = test_guard!();
        let caps = WorkerCapabilities::default();
        assert!(caps.rustc_version.is_none());
        assert!(caps.bun_version.is_none());
        assert!(caps.node_version.is_none());
        assert!(caps.npm_version.is_none());
    }

    #[test]
    fn test_worker_capabilities_new() {
        let _guard = test_guard!();
        let caps = WorkerCapabilities::new();
        assert!(caps.rustc_version.is_none());
        assert!(!caps.has_rust());
        assert!(!caps.has_bun());
        assert!(!caps.has_node());
    }

    #[test]
    fn test_worker_capabilities_has_rust() {
        let _guard = test_guard!();
        let mut caps = WorkerCapabilities::new();
        assert!(!caps.has_rust());

        caps.rustc_version = Some("rustc 1.76.0 (07dca489a 2024-02-04)".to_string());
        assert!(caps.has_rust());
    }

    #[test]
    fn test_worker_capabilities_has_bun() {
        let _guard = test_guard!();
        let mut caps = WorkerCapabilities::new();
        assert!(!caps.has_bun());

        caps.bun_version = Some("1.0.25".to_string());
        assert!(caps.has_bun());
    }

    #[test]
    fn test_worker_capabilities_has_node() {
        let _guard = test_guard!();
        let mut caps = WorkerCapabilities::new();
        assert!(!caps.has_node());

        caps.node_version = Some("v20.11.0".to_string());
        assert!(caps.has_node());
    }

    #[test]
    fn test_worker_capabilities_multiple_runtimes() {
        let _guard = test_guard!();
        let caps = WorkerCapabilities {
            rustc_version: Some("rustc 1.76.0".to_string()),
            bun_version: Some("1.0.25".to_string()),
            node_version: Some("v20.11.0".to_string()),
            npm_version: Some("10.2.4".to_string()),
            ..Default::default()
        };

        assert!(caps.has_rust());
        assert!(caps.has_bun());
        assert!(caps.has_node());
    }

    #[test]
    fn test_worker_capabilities_serialization_empty() {
        let _guard = test_guard!();
        let caps = WorkerCapabilities::new();
        let json = serde_json::to_string(&caps).unwrap();
        // Empty capabilities should serialize to {}
        assert_eq!(json, "{}");

        // And deserialize back correctly
        let parsed: WorkerCapabilities = serde_json::from_str(&json).unwrap();
        assert!(!parsed.has_rust());
        assert!(!parsed.has_bun());
        assert!(!parsed.has_node());
    }

    #[test]
    fn test_worker_capabilities_serialization_with_versions() {
        let _guard = test_guard!();
        let caps = WorkerCapabilities {
            rustc_version: Some("rustc 1.76.0-nightly".to_string()),
            bun_version: Some("1.0.25".to_string()),
            node_version: None,
            npm_version: None,
            ..Default::default()
        };

        let json = serde_json::to_string(&caps).unwrap();
        assert!(json.contains("rustc_version"));
        assert!(json.contains("rustc 1.76.0-nightly"));
        assert!(json.contains("bun_version"));
        assert!(json.contains("1.0.25"));
        // None fields should be skipped
        assert!(!json.contains("node_version"));
        assert!(!json.contains("npm_version"));

        let parsed: WorkerCapabilities = serde_json::from_str(&json).unwrap();
        assert!(parsed.has_rust());
        assert!(parsed.has_bun());
        assert!(!parsed.has_node());
    }

    #[test]
    fn test_worker_capabilities_deserialization_partial() {
        let _guard = test_guard!();
        // Deserialize JSON with only some fields
        let json = r#"{"bun_version": "1.0.0"}"#;
        let caps: WorkerCapabilities = serde_json::from_str(json).unwrap();

        assert!(!caps.has_rust());
        assert!(caps.has_bun());
        assert!(!caps.has_node());
        assert_eq!(caps.bun_version, Some("1.0.0".to_string()));
    }

    #[test]
    fn test_worker_capabilities_clone() {
        let _guard = test_guard!();
        let caps = WorkerCapabilities {
            rustc_version: Some("1.76.0".to_string()),
            bun_version: None,
            node_version: Some("v20".to_string()),
            npm_version: None,
            ..Default::default()
        };

        let cloned = caps.clone();
        assert_eq!(cloned.rustc_version, caps.rustc_version);
        assert_eq!(cloned.bun_version, caps.bun_version);
        assert_eq!(cloned.node_version, caps.node_version);
        assert_eq!(cloned.npm_version, caps.npm_version);
    }

    #[test]
    fn test_selection_reason_serialization() {
        let _guard = test_guard!();
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
        let _guard = test_guard!();
        let reason = SelectionReason::SelectionError("test error".to_string());
        let json = serde_json::to_string(&reason).unwrap();
        assert!(json.contains("selection_error"));
        assert!(json.contains("test error"));
    }

    #[test]
    fn test_selection_reason_deserialization() {
        let _guard = test_guard!();
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
        let _guard = test_guard!();
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
        let _guard = test_guard!();
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
        let _guard = test_guard!();
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
        let _guard = test_guard!();
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
        let _guard = test_guard!();
        let stats = CircuitStats::new();
        assert_eq!(stats.state(), CircuitState::Closed);
        assert_eq!(stats.consecutive_failures(), 0);
        assert_eq!(stats.error_rate(), 0.0);
        assert!(stats.opened_at().is_none());
    }

    #[test]
    fn test_circuit_stats_record_success() {
        let _guard = test_guard!();
        let mut stats = CircuitStats::new();
        stats.record_success();
        stats.record_success();
        assert_eq!(stats.error_rate(), 0.0);
        assert_eq!(stats.consecutive_failures(), 0);
    }

    #[test]
    fn test_circuit_stats_record_failure() {
        let _guard = test_guard!();
        let mut stats = CircuitStats::new();
        stats.record_failure();
        stats.record_failure();
        assert_eq!(stats.consecutive_failures(), 2);
        assert_eq!(stats.error_rate(), 1.0); // 2 failures, 0 successes
    }

    #[test]
    fn test_circuit_stats_error_rate() {
        let _guard = test_guard!();
        let mut stats = CircuitStats::new();
        stats.record_success();
        stats.record_success();
        stats.record_failure();
        // 1 failure / 3 total = 0.333...
        assert!((stats.error_rate() - 0.333).abs() < 0.01);
    }

    #[test]
    fn test_circuit_stats_should_open_consecutive_failures() {
        let _guard = test_guard!();
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
        let _guard = test_guard!();
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
        let _guard = test_guard!();
        let mut stats = CircuitStats::new();
        stats.record_failure();
        stats.record_failure();
        assert_eq!(stats.consecutive_failures(), 2);

        stats.record_success();
        assert_eq!(stats.consecutive_failures(), 0);
    }

    #[test]
    fn test_circuit_stats_open_transition() {
        let _guard = test_guard!();
        let mut stats = CircuitStats::new();
        stats.open();

        assert_eq!(stats.state(), CircuitState::Open);
        assert!(stats.opened_at().is_some());
    }

    #[test]
    fn test_circuit_stats_half_open_transition() {
        let _guard = test_guard!();
        let mut stats = CircuitStats::new();
        stats.open();
        stats.half_open();

        assert_eq!(stats.state(), CircuitState::HalfOpen);
    }

    #[test]
    fn test_circuit_stats_close_transition() {
        let _guard = test_guard!();
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
        let _guard = test_guard!();
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
        let _guard = test_guard!();
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
        let _guard = test_guard!();
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
        let _guard = test_guard!();
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
        let _guard = test_guard!();
        let mut stats = CircuitStats::new();
        stats.record_success();
        stats.record_failure();

        assert!(stats.error_rate() > 0.0);

        stats.reset_window();
        assert_eq!(stats.error_rate(), 0.0);
    }

    #[test]
    fn test_circuit_state_transitions_are_deterministic() {
        let _guard = test_guard!();
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
        let _guard = test_guard!();
        let timing = CompilationTimingBreakdown::default();
        assert_eq!(timing.rsync_up, Duration::ZERO);
        assert_eq!(timing.remote_build, Duration::ZERO);
        assert_eq!(timing.rsync_down, Duration::ZERO);
        assert_eq!(timing.total, Duration::ZERO);
    }

    #[test]
    fn test_compilation_timing_breakdown_serialization() {
        let _guard = test_guard!();
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
    fn test_command_timing_breakdown_serialization() {
        let _guard = test_guard!();
        let timing = CommandTimingBreakdown {
            classify: Some(Duration::from_millis(2)),
            select: None,
            sync_up: Some(Duration::from_millis(120)),
            exec: Some(Duration::from_millis(900)),
            sync_down: None,
            cleanup: Some(Duration::from_millis(5)),
            total: Some(Duration::from_millis(1027)),
        };

        let json = serde_json::to_string(&timing).unwrap();
        assert!(json.contains("\"classify\":2"));
        assert!(json.contains("\"select\":null"));
        assert!(json.contains("\"sync_up\":120"));
        assert!(json.contains("\"exec\":900"));
        assert!(json.contains("\"sync_down\":null"));
        assert!(json.contains("\"cleanup\":5"));
        assert!(json.contains("\"total\":1027"));

        let parsed: CommandTimingBreakdown = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.classify, timing.classify);
        assert_eq!(parsed.select, timing.select);
        assert_eq!(parsed.sync_up, timing.sync_up);
        assert_eq!(parsed.exec, timing.exec);
        assert_eq!(parsed.sync_down, timing.sync_down);
        assert_eq!(parsed.cleanup, timing.cleanup);
        assert_eq!(parsed.total, timing.total);
    }

    #[test]
    fn test_compilation_metrics_calculate_speedup() {
        let _guard = test_guard!();
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
        let _guard = test_guard!();
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
        let _guard = test_guard!();
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
        let _guard = test_guard!();
        let timer = CompilationTimer::new("my-project", "my-worker");
        assert_eq!(timer.project_id, "my-project");
        assert_eq!(timer.worker_id, "my-worker");
        assert!(timer.rsync_up.is_none());
        assert!(timer.remote_build.is_none());
        assert!(timer.rsync_down.is_none());
    }

    #[test]
    fn test_compilation_timer_phases() {
        let _guard = test_guard!();
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
        let _guard = test_guard!();
        let agg = MetricsAggregator::new(100);
        assert_eq!(agg.count(), 0);
        assert!(agg.average_speedup().is_none());
    }

    #[test]
    fn test_metrics_aggregator_record() {
        let _guard = test_guard!();
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
        let _guard = test_guard!();
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
        let _guard = test_guard!();
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
        let _guard = test_guard!();
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
        let _guard = test_guard!();
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
        let _guard = test_guard!();
        let mut agg = MetricsAggregator::new(100);
        agg.record(make_test_metrics(Some(1.0), 10, true));
        agg.record(make_test_metrics(Some(2.0), 20, true));

        assert_eq!(agg.count(), 2);

        agg.clear();
        assert_eq!(agg.count(), 0);
        assert!(agg.average_speedup().is_none());
    }

    // CompilationConfig timeout tests

    #[test]
    fn test_compilation_config_default_timeouts() {
        let _guard = test_guard!();
        let config = CompilationConfig::default();
        // Default build timeout: 5 minutes
        assert_eq!(config.build_timeout_sec, 300);
        // Default test timeout: 30 minutes
        assert_eq!(config.test_timeout_sec, 1800);
    }

    #[test]
    fn test_compilation_config_timeout_for_test_kinds() {
        let _guard = test_guard!();
        let config = CompilationConfig::default();

        // Test commands should get test_timeout_sec
        assert_eq!(
            config.timeout_for_kind(Some(crate::CompilationKind::CargoTest)),
            std::time::Duration::from_secs(1800)
        );
        assert_eq!(
            config.timeout_for_kind(Some(crate::CompilationKind::CargoNextest)),
            std::time::Duration::from_secs(1800)
        );
        assert_eq!(
            config.timeout_for_kind(Some(crate::CompilationKind::BunTest)),
            std::time::Duration::from_secs(1800)
        );
    }

    #[test]
    fn test_compilation_config_timeout_for_build_kinds() {
        let _guard = test_guard!();
        let config = CompilationConfig::default();

        // Build/check commands should get build_timeout_sec
        assert_eq!(
            config.timeout_for_kind(Some(crate::CompilationKind::CargoBuild)),
            std::time::Duration::from_secs(300)
        );
        assert_eq!(
            config.timeout_for_kind(Some(crate::CompilationKind::CargoCheck)),
            std::time::Duration::from_secs(300)
        );
        assert_eq!(
            config.timeout_for_kind(Some(crate::CompilationKind::CargoClippy)),
            std::time::Duration::from_secs(300)
        );
        assert_eq!(
            config.timeout_for_kind(None),
            std::time::Duration::from_secs(300)
        );
    }

    #[test]
    fn test_compilation_config_custom_timeouts() {
        let _guard = test_guard!();
        let config = CompilationConfig {
            build_timeout_sec: 600, // 10 minutes
            test_timeout_sec: 3600, // 1 hour
            ..Default::default()
        };

        assert_eq!(
            config.timeout_for_kind(Some(crate::CompilationKind::CargoBuild)),
            std::time::Duration::from_secs(600)
        );
        assert_eq!(
            config.timeout_for_kind(Some(crate::CompilationKind::CargoTest)),
            std::time::Duration::from_secs(3600)
        );
    }

    #[test]
    fn test_compilation_config_speedup_threshold_default() {
        let _guard = test_guard!();
        let config = CompilationConfig::default();
        // Default speedup threshold: 1.2 (20% faster required)
        assert!((config.remote_speedup_threshold - 1.2).abs() < 0.001);
    }

    #[test]
    fn test_compilation_config_speedup_threshold_custom() {
        let _guard = test_guard!();
        let config = CompilationConfig {
            remote_speedup_threshold: 1.5, // Require 50% faster
            ..Default::default()
        };
        assert!((config.remote_speedup_threshold - 1.5).abs() < 0.001);
    }

    #[test]
    fn test_compilation_config_speedup_threshold_no_minimum() {
        let _guard = test_guard!();
        // Setting to 1.0 means "always offload when other criteria met"
        let config = CompilationConfig {
            remote_speedup_threshold: 1.0,
            ..Default::default()
        };
        assert!((config.remote_speedup_threshold - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_compilation_config_min_local_time_ms_default() {
        let _guard = test_guard!();
        let config = CompilationConfig::default();
        // Default min_local_time_ms: 2000ms
        assert_eq!(config.min_local_time_ms, 2000);
    }

    #[test]
    fn test_compilation_config_serde_roundtrip_speedup_threshold() {
        let _guard = test_guard!();
        let config = CompilationConfig {
            remote_speedup_threshold: 2.5,
            min_local_time_ms: 5000,
            ..Default::default()
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: CompilationConfig = serde_json::from_str(&json).unwrap();
        assert!((parsed.remote_speedup_threshold - 2.5).abs() < 0.001);
        assert_eq!(parsed.min_local_time_ms, 5000);
    }

    // ========================================================================
    // validate_remote_base Tests
    // ========================================================================

    #[test]
    fn test_validate_remote_base_absolute_path() {
        let _guard = test_guard!();
        assert_eq!(validate_remote_base("/tmp/rch").unwrap(), "/tmp/rch");
        assert_eq!(
            validate_remote_base("/var/rch-builds").unwrap(),
            "/var/rch-builds"
        );
        assert_eq!(
            validate_remote_base("/home/builder/.rch").unwrap(),
            "/home/builder/.rch"
        );
    }

    #[test]
    fn test_validate_remote_base_tilde_expansion() {
        let _guard = test_guard!();
        // Tilde expansion should work
        let result = validate_remote_base("~/rch");
        assert!(result.is_ok());
        let path = result.unwrap();
        assert!(
            path.starts_with('/'),
            "Path should be absolute after expansion: {}",
            path
        );
        assert!(!path.contains('~'), "Tilde should be expanded: {}", path);
    }

    #[test]
    fn test_validate_remote_base_rejects_relative_path() {
        let _guard = test_guard!();
        let result = validate_remote_base("tmp/rch");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("absolute path"));
    }

    #[test]
    fn test_validate_remote_base_rejects_path_traversal() {
        let _guard = test_guard!();
        let result = validate_remote_base("/tmp/../etc/rch");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("path traversal"));

        let result = validate_remote_base("/tmp/rch/../other");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("path traversal"));
    }

    #[test]
    fn test_validate_remote_base_normalizes_trailing_slash() {
        let _guard = test_guard!();
        assert_eq!(validate_remote_base("/tmp/rch/").unwrap(), "/tmp/rch");
        assert_eq!(validate_remote_base("/tmp/rch///").unwrap(), "/tmp/rch");
    }

    #[test]
    fn test_validate_remote_base_root_path() {
        let _guard = test_guard!();
        // Root path should be rejected
        let result = validate_remote_base("/");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("root directory"));
    }

    #[test]
    fn test_validate_remote_base_rejects_top_level() {
        let _guard = test_guard!();
        // Top-level directories should be rejected (depth 1)
        let result = validate_remote_base("/tmp");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("at least 2 levels deep"));

        let result = validate_remote_base("/home");
        assert!(result.is_err());

        // Depth 2 should be allowed
        assert_eq!(validate_remote_base("/tmp/rch").unwrap(), "/tmp/rch");
    }

    #[test]
    fn test_default_remote_base() {
        let _guard = test_guard!();
        assert_eq!(default_remote_base(), "/tmp/rch");
    }

    #[test]
    fn test_transfer_config_default_has_remote_base() {
        let _guard = test_guard!();
        let config = TransferConfig::default();
        assert_eq!(config.remote_base, "/tmp/rch");
    }

    // ========================================================================
    // RetryConfig Tests (bd-x1ek)
    // ========================================================================

    #[test]
    fn test_retry_config_default() {
        let _guard = test_guard!();
        let config = RetryConfig::default();
        assert_eq!(config.max_attempts, 3);
        assert_eq!(config.base_delay_ms, 100);
        assert_eq!(config.max_delay_ms, 5000);
        assert_eq!(config.jitter_factor, 0.1);
        assert_eq!(config.total_timeout_ms, 30000);
    }

    #[test]
    fn test_retry_config_no_retry() {
        let _guard = test_guard!();
        let config = RetryConfig::no_retry();
        assert_eq!(config.max_attempts, 1);
    }

    #[test]
    fn test_retry_config_delay_for_attempt_zero() {
        let _guard = test_guard!();
        let config = RetryConfig::default();
        assert_eq!(config.delay_for_attempt(0), std::time::Duration::ZERO);
    }

    #[test]
    fn test_retry_config_delay_for_attempt_exponential() {
        let _guard = test_guard!();
        let config = RetryConfig {
            base_delay_ms: 100,
            max_delay_ms: 10000,
            jitter_factor: 0.0, // No jitter for deterministic test
            ..Default::default()
        };

        // attempt 1: 100 * 2^0 = 100ms
        assert_eq!(
            config.delay_for_attempt(1),
            std::time::Duration::from_millis(100)
        );
        // attempt 2: 100 * 2^1 = 200ms
        assert_eq!(
            config.delay_for_attempt(2),
            std::time::Duration::from_millis(200)
        );
        // attempt 3: 100 * 2^2 = 400ms
        assert_eq!(
            config.delay_for_attempt(3),
            std::time::Duration::from_millis(400)
        );
    }

    #[test]
    fn test_retry_config_delay_capped_at_max() {
        let _guard = test_guard!();
        let config = RetryConfig {
            base_delay_ms: 1000,
            max_delay_ms: 2000,
            jitter_factor: 0.0,
            ..Default::default()
        };

        // attempt 2: 1000 * 2^1 = 2000ms (at cap)
        assert_eq!(
            config.delay_for_attempt(2),
            std::time::Duration::from_millis(2000)
        );
        // attempt 3: 1000 * 2^2 = 4000ms, capped to 2000ms
        assert_eq!(
            config.delay_for_attempt(3),
            std::time::Duration::from_millis(2000)
        );
    }

    #[test]
    fn test_retry_config_should_retry() {
        let _guard = test_guard!();
        let config = RetryConfig {
            max_attempts: 3,
            total_timeout_ms: 1000,
            ..Default::default()
        };

        // Before max attempts and within timeout
        assert!(config.should_retry(0, std::time::Duration::from_millis(0)));
        assert!(config.should_retry(1, std::time::Duration::from_millis(500)));
        assert!(config.should_retry(2, std::time::Duration::from_millis(900)));

        // At max attempts
        assert!(!config.should_retry(3, std::time::Duration::from_millis(0)));

        // Past timeout
        assert!(!config.should_retry(1, std::time::Duration::from_millis(1001)));
    }

    #[test]
    fn test_retry_config_serde_roundtrip() {
        let _guard = test_guard!();
        let config = RetryConfig {
            max_attempts: 5,
            base_delay_ms: 200,
            max_delay_ms: 8000,
            jitter_factor: 0.2,
            total_timeout_ms: 60000,
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: RetryConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.max_attempts, 5);
        assert_eq!(parsed.base_delay_ms, 200);
        assert_eq!(parsed.max_delay_ms, 8000);
        assert_eq!(parsed.jitter_factor, 0.2);
        assert_eq!(parsed.total_timeout_ms, 60000);
    }

    #[test]
    fn test_transfer_config_includes_retry() {
        let _guard = test_guard!();
        let config = TransferConfig::default();
        assert_eq!(config.retry.max_attempts, 3);
    }

    // =========================================================================
    // ExecutionConfig Tests (bd-785w)
    // =========================================================================

    #[test]
    fn test_execution_config_default_allowlist() {
        let _guard = test_guard!();
        let config = ExecutionConfig::default();
        // All supported compilers should be in the default allowlist
        assert!(config.is_allowed("cargo"));
        assert!(config.is_allowed("rustc"));
        assert!(config.is_allowed("gcc"));
        assert!(config.is_allowed("g++"));
        assert!(config.is_allowed("clang"));
        assert!(config.is_allowed("clang++"));
        assert!(config.is_allowed("make"));
        assert!(config.is_allowed("cmake"));
        assert!(config.is_allowed("ninja"));
        assert!(config.is_allowed("meson"));
        assert!(config.is_allowed("bun"));
        assert!(config.is_allowed("nextest"));
        assert!(config.is_allowed("cc"));
        assert!(config.is_allowed("c++"));
    }

    #[test]
    fn test_execution_config_is_allowed_case_insensitive() {
        let _guard = test_guard!();
        let config = ExecutionConfig::default();
        // Should be case-insensitive
        assert!(config.is_allowed("CARGO"));
        assert!(config.is_allowed("Cargo"));
        assert!(config.is_allowed("GCC"));
        assert!(config.is_allowed("Gcc"));
    }

    #[test]
    fn test_execution_config_is_not_allowed() {
        let _guard = test_guard!();
        let config = ExecutionConfig::default();
        // Unknown commands should not be allowed
        assert!(!config.is_allowed("python"));
        assert!(!config.is_allowed("npm"));
        assert!(!config.is_allowed("go"));
        assert!(!config.is_allowed(""));
    }

    #[test]
    fn test_execution_config_empty_allowlist() {
        let _guard = test_guard!();
        let config = ExecutionConfig { allowlist: vec![] };
        // Empty allowlist should block everything
        assert!(!config.is_allowed("cargo"));
        assert!(!config.is_allowed("gcc"));
    }

    #[test]
    fn test_execution_config_custom_allowlist() {
        let _guard = test_guard!();
        let config = ExecutionConfig {
            allowlist: vec!["cargo".to_string(), "custom_tool".to_string()],
        };
        assert!(config.is_allowed("cargo"));
        assert!(config.is_allowed("custom_tool"));
        assert!(!config.is_allowed("gcc"));
    }

    #[test]
    fn test_execution_config_serde() {
        let _guard = test_guard!();
        let config = ExecutionConfig {
            allowlist: vec!["cargo".to_string(), "rustc".to_string()],
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: ExecutionConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.allowlist, config.allowlist);
    }

    #[test]
    fn test_rch_config_includes_execution() {
        let _guard = test_guard!();
        let config = RchConfig::default();
        // RchConfig should include ExecutionConfig with default allowlist
        assert!(config.execution.is_allowed("cargo"));
    }

    // ========================================================================
    // Adaptive Compression Tests (bd-243w)
    // ========================================================================

    #[test]
    fn test_adaptive_compression_disabled_by_default() {
        let _guard = test_guard!();
        let config = TransferConfig::default();
        assert!(!config.adaptive_compression);
        // Should use fixed level when disabled
        assert_eq!(config.select_compression_level(Some(1_000_000)), 3);
        assert_eq!(config.select_compression_level(Some(500_000_000)), 3);
    }

    #[test]
    fn test_adaptive_compression_small_payload() {
        let _guard = test_guard!();
        let config = TransferConfig {
            adaptive_compression: true,
            ..Default::default()
        };
        // < 10MB should use level 1
        assert_eq!(config.select_compression_level(Some(0)), 1);
        assert_eq!(config.select_compression_level(Some(1_000_000)), 1); // 1MB
        assert_eq!(config.select_compression_level(Some(9_999_999)), 1); // ~10MB
    }

    #[test]
    fn test_adaptive_compression_medium_payload() {
        let _guard = test_guard!();
        let config = TransferConfig {
            adaptive_compression: true,
            ..Default::default()
        };
        // 10-200MB should use level 3
        assert_eq!(config.select_compression_level(Some(10_000_000)), 3); // 10MB
        assert_eq!(config.select_compression_level(Some(100_000_000)), 3); // 100MB
        assert_eq!(config.select_compression_level(Some(199_999_999)), 3); // ~200MB
    }

    #[test]
    fn test_adaptive_compression_large_payload() {
        let _guard = test_guard!();
        let config = TransferConfig {
            adaptive_compression: true,
            ..Default::default()
        };
        // > 200MB should use level 7
        assert_eq!(config.select_compression_level(Some(200_000_000)), 7); // 200MB
        assert_eq!(config.select_compression_level(Some(500_000_000)), 7); // 500MB
        assert_eq!(config.select_compression_level(Some(1_000_000_000)), 7); // 1GB
    }

    #[test]
    fn test_adaptive_compression_no_estimate() {
        let _guard = test_guard!();
        let config = TransferConfig {
            adaptive_compression: true,
            compression_level: 5,
            ..Default::default()
        };
        // No estimate should fallback to default level
        assert_eq!(config.select_compression_level(None), 5);
    }

    #[test]
    fn test_adaptive_compression_respects_min_level() {
        let _guard = test_guard!();
        let config = TransferConfig {
            adaptive_compression: true,
            min_compression_level: 3,
            ..Default::default()
        };
        // Small payload would want level 1, but min is 3
        assert_eq!(config.select_compression_level(Some(1_000_000)), 3);
    }

    #[test]
    fn test_adaptive_compression_respects_max_level() {
        let _guard = test_guard!();
        let config = TransferConfig {
            adaptive_compression: true,
            max_compression_level: 5,
            ..Default::default()
        };
        // Large payload would want level 7, but max is 5
        assert_eq!(config.select_compression_level(Some(500_000_000)), 5);
    }

    #[test]
    fn test_adaptive_compression_serde_roundtrip() {
        let _guard = test_guard!();
        let config = TransferConfig {
            adaptive_compression: true,
            min_compression_level: 2,
            max_compression_level: 8,
            ..Default::default()
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: TransferConfig = serde_json::from_str(&json).unwrap();
        assert!(parsed.adaptive_compression);
        assert_eq!(parsed.min_compression_level, 2);
        assert_eq!(parsed.max_compression_level, 8);
    }

    // -------------------------------------------------------------------------
    // Self-Healing Config Tests (bd-59kg)
    // -------------------------------------------------------------------------

    #[test]
    fn test_self_healing_config_defaults() {
        let _guard = test_guard!();
        // TEST START: SelfHealingConfig::default() returns expected values
        let config = SelfHealingConfig::default();

        // Both self-healing behaviors enabled by default
        assert!(
            config.hook_starts_daemon,
            "hook_starts_daemon should be true by default"
        );
        assert!(
            config.daemon_installs_hooks,
            "daemon_installs_hooks should be true by default"
        );

        // Timing defaults
        assert_eq!(
            config.auto_start_cooldown_secs, 30,
            "auto_start_cooldown_secs should default to 30"
        );
        assert_eq!(
            config.auto_start_timeout_secs, 3,
            "auto_start_timeout_secs should default to 3"
        );
        // TEST PASS: SelfHealingConfig defaults
    }

    #[test]
    fn test_self_healing_config_serde_full() {
        let _guard = test_guard!();
        // TEST START: Full SelfHealingConfig serialization/deserialization
        let config = SelfHealingConfig {
            hook_starts_daemon: false,
            daemon_installs_hooks: false,
            auto_start_cooldown_secs: 60,
            auto_start_timeout_secs: 10,
        };

        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("\"hook_starts_daemon\":false"));
        assert!(json.contains("\"daemon_installs_hooks\":false"));
        assert!(json.contains("\"auto_start_cooldown_secs\":60"));
        assert!(json.contains("\"auto_start_timeout_secs\":10"));

        let parsed: SelfHealingConfig = serde_json::from_str(&json).unwrap();
        assert!(!parsed.hook_starts_daemon);
        assert!(!parsed.daemon_installs_hooks);
        assert_eq!(parsed.auto_start_cooldown_secs, 60);
        assert_eq!(parsed.auto_start_timeout_secs, 10);
        // TEST PASS: Full SelfHealingConfig serde
    }

    #[test]
    fn test_self_healing_config_serde_partial_uses_defaults() {
        let _guard = test_guard!();
        // TEST START: Partial TOML/JSON uses defaults for missing fields
        let json = r#"{"hook_starts_daemon": false}"#;
        let config: SelfHealingConfig = serde_json::from_str(json).unwrap();

        assert!(
            !config.hook_starts_daemon,
            "Explicit false should be parsed"
        );
        assert!(
            config.daemon_installs_hooks,
            "Missing field should use default (true)"
        );
        assert_eq!(
            config.auto_start_cooldown_secs, 30,
            "Missing field should use default (30)"
        );
        assert_eq!(
            config.auto_start_timeout_secs, 3,
            "Missing field should use default (3)"
        );
        // TEST PASS: Partial SelfHealingConfig uses defaults
    }

    #[test]
    fn test_self_healing_config_toml_with_alias() {
        let _guard = test_guard!();
        // TEST START: daemon_start_timeout alias works for auto_start_timeout_secs
        let toml_str = r#"
            hook_starts_daemon = true
            daemon_installs_hooks = false
            auto_start_cooldown_secs = 45
            daemon_start_timeout = 7
        "#;

        let config: SelfHealingConfig = toml::from_str(toml_str).unwrap();
        assert!(config.hook_starts_daemon);
        assert!(!config.daemon_installs_hooks);
        assert_eq!(config.auto_start_cooldown_secs, 45);
        assert_eq!(
            config.auto_start_timeout_secs, 7,
            "daemon_start_timeout alias should set auto_start_timeout_secs"
        );
        // TEST PASS: TOML alias works
    }

    #[allow(unsafe_code)]
    mod self_healing_env_override_tests {
        use super::*;
        use crate::config::env_test_lock;

        fn env_guard() -> std::sync::MutexGuard<'static, ()> {
            env_test_lock()
        }

        fn set_env(key: &str, value: &str) {
            // SAFETY: Tests are serialized with env_guard().
            unsafe { std::env::set_var(key, value) };
        }

        fn remove_env(key: &str) {
            // SAFETY: Tests are serialized with env_guard().
            unsafe { std::env::remove_var(key) };
        }

        struct EnvVarGuard {
            key: &'static str,
            old: Option<String>,
        }

        impl EnvVarGuard {
            fn set(key: &'static str, value: &str) -> Self {
                let old = std::env::var(key).ok();
                set_env(key, value);
                Self { key, old }
            }
        }

        impl Drop for EnvVarGuard {
            fn drop(&mut self) {
                if let Some(old) = &self.old {
                    set_env(self.key, old);
                } else {
                    remove_env(self.key);
                }
            }
        }

        #[test]
        fn test_self_healing_config_with_env_overrides_master_disable() {
            let _guard = test_guard!();
            let _guard = env_guard();

            let _no_self_healing = EnvVarGuard::set("RCH_NO_SELF_HEALING", "1");
            let _hook_starts_daemon = EnvVarGuard::set("RCH_HOOK_STARTS_DAEMON", "1");
            let _daemon_installs_hooks = EnvVarGuard::set("RCH_DAEMON_INSTALLS_HOOKS", "1");
            let _cooldown = EnvVarGuard::set("RCH_AUTO_START_COOLDOWN_SECS", "99");
            let _timeout = EnvVarGuard::set("RCH_AUTO_START_TIMEOUT_SECS", "99");

            let config = SelfHealingConfig::default().with_env_overrides();
            assert!(
                !config.hook_starts_daemon,
                "RCH_NO_SELF_HEALING should disable hook auto-start"
            );
            assert!(
                !config.daemon_installs_hooks,
                "RCH_NO_SELF_HEALING should disable daemon hook installation"
            );

            // Master disable returns early; numeric overrides should not apply.
            assert_eq!(config.auto_start_cooldown_secs, 30);
            assert_eq!(config.auto_start_timeout_secs, 3);
        }

        #[test]
        fn test_self_healing_config_with_env_overrides_toggles_and_numbers() {
            let _guard = test_guard!();
            let _guard = env_guard();

            let _hook_starts_daemon = EnvVarGuard::set("RCH_HOOK_STARTS_DAEMON", "0");
            let _daemon_installs_hooks = EnvVarGuard::set("RCH_DAEMON_INSTALLS_HOOKS", "false");
            let _cooldown = EnvVarGuard::set("RCH_AUTO_START_COOLDOWN_SECS", "45");
            let _timeout = EnvVarGuard::set("RCH_AUTO_START_TIMEOUT_SECS", "7");

            let config = SelfHealingConfig::default().with_env_overrides();
            assert!(!config.hook_starts_daemon);
            assert!(!config.daemon_installs_hooks);
            assert_eq!(config.auto_start_cooldown_secs, 45);
            assert_eq!(config.auto_start_timeout_secs, 7);
        }

        #[test]
        fn test_self_healing_config_with_env_overrides_invalid_numbers_ignored() {
            let _guard = test_guard!();
            let _guard = env_guard();

            let _cooldown = EnvVarGuard::set("RCH_AUTO_START_COOLDOWN_SECS", "not-a-number");
            let _timeout = EnvVarGuard::set("RCH_AUTO_START_TIMEOUT_SECS", "nope");

            let config = SelfHealingConfig::default().with_env_overrides();
            assert_eq!(config.auto_start_cooldown_secs, 30);
            assert_eq!(config.auto_start_timeout_secs, 3);
        }
    }

    // -------------------------------------------------------------------------
    // Preflight Health Guard Tests (bd-3eaa)
    // -------------------------------------------------------------------------

    #[test]
    fn test_load_per_core_calculation() {
        let _guard = test_guard!();
        let mut caps = WorkerCapabilities::new();
        // No metrics -> None
        assert!(caps.load_per_core().is_none());

        // Only load, no cpus -> None
        caps.load_avg_1 = Some(4.0);
        assert!(caps.load_per_core().is_none());

        // Both available
        caps.num_cpus = Some(4);
        assert_eq!(caps.load_per_core(), Some(1.0)); // 4.0 / 4 = 1.0

        // High load
        caps.load_avg_1 = Some(16.0);
        assert_eq!(caps.load_per_core(), Some(4.0)); // 16.0 / 4 = 4.0
    }

    #[test]
    fn test_is_high_load() {
        let _guard = test_guard!();
        let mut caps = WorkerCapabilities::new();
        caps.load_avg_1 = Some(8.0);
        caps.num_cpus = Some(4);
        // load_per_core = 2.0

        // Below threshold
        assert_eq!(caps.is_high_load(3.0), Some(false));
        // At threshold
        assert_eq!(caps.is_high_load(2.0), Some(false)); // equal is OK
        // Above threshold
        assert_eq!(caps.is_high_load(1.5), Some(true));

        // No metrics -> None (fail-open)
        caps.load_avg_1 = None;
        assert!(caps.is_high_load(1.0).is_none());
    }

    #[test]
    fn test_is_low_disk() {
        let _guard = test_guard!();
        let mut caps = WorkerCapabilities::new();
        caps.disk_free_gb = Some(15.0);

        // Above threshold
        assert_eq!(caps.is_low_disk(10.0), Some(false));
        // At threshold
        assert_eq!(caps.is_low_disk(15.0), Some(false)); // equal is OK
        // Below threshold
        assert_eq!(caps.is_low_disk(20.0), Some(true));

        // No metrics -> None (fail-open)
        caps.disk_free_gb = None;
        assert!(caps.is_low_disk(10.0).is_none());
    }

    #[test]
    fn test_selection_config_preflight_defaults() {
        let _guard = test_guard!();
        let config = SelectionConfig::default();
        // Default thresholds
        assert_eq!(config.max_load_per_core, Some(2.0));
        assert_eq!(config.min_free_gb, Some(10.0));
    }

    #[test]
    fn test_selection_config_preflight_serde() {
        let _guard = test_guard!();
        let config = SelectionConfig {
            max_load_per_core: Some(3.5),
            min_free_gb: Some(25.0),
            ..Default::default()
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: SelectionConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.max_load_per_core, Some(3.5));
        assert_eq!(parsed.min_free_gb, Some(25.0));
    }

    #[test]
    fn test_worker_capabilities_health_metrics_serde() {
        let _guard = test_guard!();
        let caps = WorkerCapabilities {
            num_cpus: Some(8),
            load_avg_1: Some(1.5),
            load_avg_5: Some(2.0),
            load_avg_15: Some(1.8),
            disk_free_gb: Some(50.5),
            disk_total_gb: Some(100.0),
            ..Default::default()
        };
        let json = serde_json::to_string(&caps).unwrap();
        let parsed: WorkerCapabilities = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.num_cpus, Some(8));
        assert_eq!(parsed.load_avg_1, Some(1.5));
        assert_eq!(parsed.disk_free_gb, Some(50.5));
    }
}
