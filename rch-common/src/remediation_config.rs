//! Central config schema and default policy for the session-history remediation
//! features (bd-session-history-remediation-ocv9i.17.1).
//!
//! This module is the **design center** for what every remediation feature means
//! when the user has not customized anything. It declares one serde- and
//! `schemars`-friendly [`RemediationConfig`] that aggregates every remediation
//! knob with a documented default, the fail-open / fail-closed policy, value
//! validation, path safety, and redaction of sensitive (path-like) fields.
//!
//! ## Why a separate config layer
//!
//! The runtime subsystems keep their own runtime structs, which use types that
//! are awkward to serialize (`std::time::Duration`, `PathBuf`) or that live in
//! the `rchd` binary crate and so cannot be referenced from shared code. This
//! module holds the **serializable** declaration of the same knobs (seconds,
//! bytes, plain strings) plus `From` conversions into the rch-common runtime
//! structs. Drift-guard tests assert that the central defaults reproduce each
//! runtime struct's own `::default()`, so the documented schema can never
//! silently diverge from the code that runs.
//!
//! ## Default policy
//!
//! - Ordinary hook / `rch exec` paths stay **fail-open**: any error falls back
//!   to local execution rather than blocking the agent.
//! - Explicit **proof mode fails closed** — it refuses local fallback before it
//!   would run locally, so a requested proof is never silently downgraded.
//! - Path-like defaults resolve under RCH-managed roots (`/tmp/rch`, the XDG
//!   state/cache dirs, `/data/projects`). Operator-supplied paths must be
//!   absolute; [`RemediationConfig::validate`] flags any path outside the
//!   managed roots as an operator override rather than silently trusting it.

use serde::{Deserialize, Serialize};

use schemars::{JsonSchema, schema_for};

use crate::incident_ledger::{IncidentLedgerConfig, default_ledger_path};
use crate::proof_intent::{ReplayConstraints, StaleSourcePolicy};

// ── Canonical default constants ──────────────────────────────────────────────
//
// Each constant is the single documented default for one knob. The values are
// copied from (and drift-guarded against, where the runtime struct lives in
// rch-common) the subsystems that consume them:
//   - temporary bypass backoff  → `bypass_record::BypassBackoff`
//   - auto-rejoin criteria       → `bypass_record::AutoRejoinCriteria`
//   - auto-rejoin probe thresholds → `rchd::bypass_recovery_service::BypassRecoveryConfig`
//   - reconciliation windows     → `rchd::repo_convergence` module constants
//   - incident ledger retention  → `incident_ledger::IncidentLedgerConfig`
//   - build-root safety          → `rchd::build_root_policy` module constants
//   - pooled target / reaper     → `rchd::config::StaleTargetReapConfig`
//   - log retention              → `log_retention::LogRetentionPolicy`
//   - disk pressure              → `disk_pressure_report::PressureThresholds`

/// Default temporary-bypass backoff window (30s; mirrors `BypassBackoff`).
pub const DEFAULT_BACKOFF_INITIAL_SECS: u64 = 30;
/// Default temporary-bypass backoff ceiling (15min; mirrors `BypassBackoff`).
pub const DEFAULT_BACKOFF_MAX_SECS: u64 = 900;

/// Default consecutive passes required before a worker may auto-rejoin.
pub const DEFAULT_REQUIRED_CONSECUTIVE_PASSES: u32 = 2;
/// Default cadence at which the recovery service scans for due probes (30s).
pub const DEFAULT_CHECK_INTERVAL_SECS: u64 = 30;
/// Default SSH/probe timeout for a single capability probe or canary (10s).
pub const DEFAULT_PROBE_TIMEOUT_SECS: u64 = 10;
/// Default minimum free disk (GB) a probed root must report.
pub const DEFAULT_MIN_DISK_FREE_GB: f64 = 5.0;
/// Default minimum free inodes a probed root must report.
pub const DEFAULT_MIN_DISK_INODES: u64 = 10_000;
/// Default maximum load-per-core a recovered worker may report.
pub const DEFAULT_MAX_LOAD_PER_CORE: f64 = 4.0;
/// Default minimum worker wire protocol (held at 0 until rch-wkr exposes one).
pub const DEFAULT_MIN_PROTOCOL: u32 = 0;
/// Default canary command run over the SSH path before a full rejoin.
pub const DEFAULT_CANARY_COMMAND: &str = "rustc --version";

/// Default maximum convergence attempts before a worker enters `Failed`.
pub const DEFAULT_RECONCILE_MAX_ATTEMPTS: u32 = 3;
/// Default wall-clock budget per convergence cycle (seconds).
pub const DEFAULT_RECONCILE_TIME_BUDGET_SECS: u64 = 120;
/// Default minimum dwell time before a state transition (hysteresis, ms).
pub const DEFAULT_RECONCILE_HYSTERESIS_MS: u64 = 5_000;
/// Default retained per-worker transition-history entries.
pub const DEFAULT_RECONCILE_MAX_TRANSITION_HISTORY: usize = 64;
/// Default retained global convergence-outcome entries.
pub const DEFAULT_RECONCILE_MAX_OUTCOME_HISTORY: usize = 256;
/// Default staleness threshold for a worker's last status check (seconds).
pub const DEFAULT_RECONCILE_STALENESS_SECS: u64 = 300;

/// Default retained-event count for the incident ledger after compaction.
pub const DEFAULT_INCIDENT_MAX_ENTRIES: usize = 5_000;
/// Default incident-ledger size that triggers compaction (4 MiB).
pub const DEFAULT_INCIDENT_MAX_BYTES: u64 = 4 * 1024 * 1024;

/// Default minimum free bytes a build root must have (2 GiB).
pub const DEFAULT_BUILD_ROOT_MIN_FREE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// Default minimum free inodes a build root must have.
pub const DEFAULT_BUILD_ROOT_MIN_FREE_INODES: u64 = 50_000;

/// Default idle window before a pooled target dir is reaped (hours).
pub const DEFAULT_POOLED_REAPER_IDLE_HOURS: u32 = 12;
/// Default sweep cadence for the pooled-target stale reaper (minutes).
pub const DEFAULT_POOLED_REAPER_INTERVAL_MINS: u64 = 120;
/// Default remote base under which pooled target dirs live.
pub const DEFAULT_POOLED_REMOTE_BASE: &str = "/data/projects";

/// Default maximum telemetry age that still counts as "fresh" (seconds).
pub const DEFAULT_TELEMETRY_MAX_AGE_SECS: u64 = 120;

/// Default rotation trigger for an active managed log (16 MiB).
pub const DEFAULT_LOG_MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;
/// Default rotated generations retained per managed log.
pub const DEFAULT_LOG_KEEP_ROTATED: usize = 3;
/// Default managed-log total at/above which pressure is `Warning` (64 MiB).
pub const DEFAULT_LOG_WARN_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
/// Default managed-log total at/above which pressure is `Critical` (256 MiB).
pub const DEFAULT_LOG_CRITICAL_TOTAL_BYTES: u64 = 256 * 1024 * 1024;

/// Default available-percent below which disk pressure is `Warning`.
pub const DEFAULT_PRESSURE_WARNING_AVAIL_PCT: f64 = 15.0;
/// Default available-percent below which disk pressure is `Critical`.
pub const DEFAULT_PRESSURE_CRITICAL_AVAIL_PCT: f64 = 5.0;
/// Default available-inodes below which disk pressure is `Warning`.
pub const DEFAULT_PRESSURE_WARNING_AVAIL_INODES: u64 = 100_000;
/// Default available-inodes below which disk pressure is `Critical`.
pub const DEFAULT_PRESSURE_CRITICAL_AVAIL_INODES: u64 = 10_000;

/// Default real-fleet smoke/soak iteration count.
pub const DEFAULT_SMOKE_ITERATIONS: usize = 20;
/// Default deterministic seed for the soak workload.
pub const DEFAULT_SMOKE_SEED: u64 = 42;

/// Absolute path prefixes RCH treats as managed/standard (no operator warning).
const RCH_MANAGED_ROOT_PREFIXES: &[&str] = &["/tmp/rch", "/tmp", "/data/projects", "/dp"];

/// Default disk roots whose capacity/inodes the recovery probe reports.
#[must_use]
fn default_disk_roots() -> Vec<String> {
    vec!["/tmp".to_string(), "/tmp/rch".to_string()]
}

// ── Top-level policy ─────────────────────────────────────────────────────────

/// The failure-mode policy: what RCH does when a remediation path errors.
///
/// The defaults encode the project's core invariant — ordinary command paths
/// fail open (run locally) while explicit proof mode fails closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct RemediationPolicy {
    /// Ordinary hook / `rch exec` paths fall back to local execution on error.
    pub hook_exec_fail_open: bool,
    /// Explicit proof mode refuses local fallback before running locally.
    pub proof_mode_fail_closed: bool,
}

impl Default for RemediationPolicy {
    fn default() -> Self {
        Self {
            hook_exec_fail_open: true,
            proof_mode_fail_closed: true,
        }
    }
}

// ── Temporary bypass ─────────────────────────────────────────────────────────

/// Temporary-bypass retention and probe backoff knobs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct TemporaryBypassConfig {
    /// Initial backoff window before the first recovery probe (seconds).
    pub backoff_initial_secs: u64,
    /// Ceiling for the exponential backoff window (seconds).
    pub backoff_max_secs: u64,
}

impl Default for TemporaryBypassConfig {
    fn default() -> Self {
        Self {
            backoff_initial_secs: DEFAULT_BACKOFF_INITIAL_SECS,
            backoff_max_secs: DEFAULT_BACKOFF_MAX_SECS,
        }
    }
}

// ── Auto-rejoin ──────────────────────────────────────────────────────────────

/// Auto-rejoin canary thresholds and recovery-probe dimensions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct AutoRejoinConfig {
    /// Consecutive successful recovery probes required before a canary build.
    pub required_consecutive_passes: u32,
    /// Whether one canary build is required before full rejoin.
    pub canary_required: bool,
    /// How often the recovery service scans for due probes (seconds).
    pub check_interval_secs: u64,
    /// SSH/probe timeout for a single capability probe or canary (seconds).
    pub probe_timeout_secs: u64,
    /// Minimum free disk (GB) a worker must report on every probed root.
    pub min_disk_free_gb: f64,
    /// Minimum free inodes a worker must report on every probed root.
    pub min_disk_inodes: u64,
    /// Disk roots whose capacity/inodes the probe reports.
    pub disk_roots: Vec<String>,
    /// Maximum load-per-core a worker may report to pass the load dimension.
    pub max_load_per_core: f64,
    /// Minimum worker wire protocol required to pass the protocol dimension.
    pub min_protocol: u32,
    /// rustup targets a recovered worker must have (empty = cargo/rustc only).
    pub required_targets: Vec<String>,
    /// rustup toolchains a recovered worker must have (prefix-matched).
    pub required_toolchains: Vec<String>,
    /// The canary command run over the SSH path before full rejoin.
    pub canary_command: String,
}

impl Default for AutoRejoinConfig {
    fn default() -> Self {
        Self {
            required_consecutive_passes: DEFAULT_REQUIRED_CONSECUTIVE_PASSES,
            canary_required: true,
            check_interval_secs: DEFAULT_CHECK_INTERVAL_SECS,
            probe_timeout_secs: DEFAULT_PROBE_TIMEOUT_SECS,
            min_disk_free_gb: DEFAULT_MIN_DISK_FREE_GB,
            min_disk_inodes: DEFAULT_MIN_DISK_INODES,
            disk_roots: default_disk_roots(),
            max_load_per_core: DEFAULT_MAX_LOAD_PER_CORE,
            min_protocol: DEFAULT_MIN_PROTOCOL,
            required_targets: Vec::new(),
            required_toolchains: Vec::new(),
            canary_command: DEFAULT_CANARY_COMMAND.to_string(),
        }
    }
}

// ── Desired-state reconciliation ─────────────────────────────────────────────

/// Desired-state fleet reconciliation windows and history bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct ReconciliationConfig {
    /// Maximum convergence attempts before a worker enters `Failed`.
    pub max_attempts: u32,
    /// Wall-clock budget per convergence cycle (seconds).
    pub time_budget_secs: u64,
    /// Minimum dwell time before a state transition (hysteresis, ms).
    pub state_hysteresis_ms: u64,
    /// Retained per-worker transition-history entries.
    pub max_transition_history: usize,
    /// Retained global convergence-outcome entries.
    pub max_outcome_history: usize,
    /// Staleness threshold for a worker's last status check (seconds).
    pub staleness_threshold_secs: u64,
}

impl Default for ReconciliationConfig {
    fn default() -> Self {
        Self {
            max_attempts: DEFAULT_RECONCILE_MAX_ATTEMPTS,
            time_budget_secs: DEFAULT_RECONCILE_TIME_BUDGET_SECS,
            state_hysteresis_ms: DEFAULT_RECONCILE_HYSTERESIS_MS,
            max_transition_history: DEFAULT_RECONCILE_MAX_TRANSITION_HISTORY,
            max_outcome_history: DEFAULT_RECONCILE_MAX_OUTCOME_HISTORY,
            staleness_threshold_secs: DEFAULT_RECONCILE_STALENESS_SECS,
        }
    }
}

// ── Proof mode / deferred proof queue ────────────────────────────────────────

/// Proof intent store location and default replay policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct ProofConfig {
    /// Override path for the proof-intent JSONL store. `None` resolves under the
    /// RCH-managed state dir (alongside the incident ledger).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store_path: Option<String>,
    /// Default stale-source policy when an intent does not specify one.
    pub default_stale_source_policy: StaleSourcePolicy,
    // Note: this nested table must be serialized last so the scalar keys above
    // precede it (TOML requires scalar keys before sub-tables).
    /// Default constraints applied to a stored intent at replay time.
    pub default_replay_constraints: ReplayConstraints,
}

impl Default for ProofConfig {
    fn default() -> Self {
        Self {
            store_path: None,
            default_replay_constraints: ReplayConstraints::default(),
            // Conservative default: only replay byte-identical sources.
            default_stale_source_policy: StaleSourcePolicy::RejectIfChanged,
        }
    }
}

// ── Incident ledger ──────────────────────────────────────────────────────────

/// Incident-ledger retention bounds and optional path override.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct IncidentLedgerPolicy {
    /// Override path for the ledger JSONL file. `None` uses the RCH state dir.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Events retained after a compaction (most-recent wins).
    pub max_entries: usize,
    /// File size that triggers a compaction, in bytes.
    pub max_bytes: u64,
}

impl Default for IncidentLedgerPolicy {
    fn default() -> Self {
        Self {
            path: None,
            max_entries: DEFAULT_INCIDENT_MAX_ENTRIES,
            max_bytes: DEFAULT_INCIDENT_MAX_BYTES,
        }
    }
}

// ── Mount-aware build root ───────────────────────────────────────────────────

/// Mount-aware build-root / cargo-home safety thresholds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct BuildRootConfig {
    /// Minimum free bytes a build root must have to be considered safe.
    pub min_free_bytes: u64,
    /// Minimum free inodes a build root must have to be considered safe.
    pub min_free_inodes: u64,
}

impl Default for BuildRootConfig {
    fn default() -> Self {
        Self {
            min_free_bytes: DEFAULT_BUILD_ROOT_MIN_FREE_BYTES,
            min_free_inodes: DEFAULT_BUILD_ROOT_MIN_FREE_INODES,
        }
    }
}

// ── Pooled target dirs ───────────────────────────────────────────────────────

/// Pooled target-dir policy and conservative stale reaper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct PooledTargetConfig {
    /// Whether per-key pooled target dirs are used for remote builds.
    pub pooling_enabled: bool,
    /// Whether the stale-target reaper runs (ships off pending canary soak).
    pub reaper_enabled: bool,
    /// Idle window before a pooled target dir is reaped (hours).
    pub reaper_idle_hours: u32,
    /// Sweep cadence for the stale reaper (minutes).
    pub reaper_interval_mins: u64,
    /// Remote base under which pooled target dirs live.
    pub remote_base: String,
}

impl Default for PooledTargetConfig {
    fn default() -> Self {
        Self {
            pooling_enabled: true,
            reaper_enabled: false,
            reaper_idle_hours: DEFAULT_POOLED_REAPER_IDLE_HOURS,
            reaper_interval_mins: DEFAULT_POOLED_REAPER_INTERVAL_MINS,
            remote_base: DEFAULT_POOLED_REMOTE_BASE.to_string(),
        }
    }
}

// ── Telemetry freshness ──────────────────────────────────────────────────────

/// Telemetry freshness tolerance.
///
/// The freshness model itself ([`crate::telemetry_freshness`]) is adaptive and
/// pure; this knob is the base maximum age the recovery path treats as "fresh"
/// when it cannot derive a tighter, observer-aware tolerance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct TelemetryFreshnessConfig {
    /// Maximum telemetry age that still counts as fresh (seconds).
    pub max_age_secs: u64,
}

impl Default for TelemetryFreshnessConfig {
    fn default() -> Self {
        Self {
            max_age_secs: DEFAULT_TELEMETRY_MAX_AGE_SECS,
        }
    }
}

// ── Log retention ────────────────────────────────────────────────────────────

/// Daemon log rotation/retention policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct LogRetentionConfig {
    /// Rotate an active log once it exceeds this many bytes.
    pub max_file_bytes: u64,
    /// Rotated generations to retain per log.
    pub keep_rotated: usize,
    /// Managed total at/above which pressure is `Warning`.
    pub warn_total_bytes: u64,
    /// Managed total at/above which pressure is `Critical`.
    pub critical_total_bytes: u64,
}

impl Default for LogRetentionConfig {
    fn default() -> Self {
        Self {
            max_file_bytes: DEFAULT_LOG_MAX_FILE_BYTES,
            keep_rotated: DEFAULT_LOG_KEEP_ROTATED,
            warn_total_bytes: DEFAULT_LOG_WARN_TOTAL_BYTES,
            critical_total_bytes: DEFAULT_LOG_CRITICAL_TOTAL_BYTES,
        }
    }
}

// ── Disk pressure ────────────────────────────────────────────────────────────

/// Disk-pressure classification thresholds.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct DiskPressureConfig {
    /// Available-percent at/below which pressure is `Warning`.
    pub warning_avail_pct: f64,
    /// Available-percent at/below which pressure is `Critical`.
    pub critical_avail_pct: f64,
    /// Available-inodes at/below which pressure is `Warning`.
    pub warning_avail_inodes: u64,
    /// Available-inodes at/below which pressure is `Critical`.
    pub critical_avail_inodes: u64,
}

impl Default for DiskPressureConfig {
    fn default() -> Self {
        Self {
            warning_avail_pct: DEFAULT_PRESSURE_WARNING_AVAIL_PCT,
            critical_avail_pct: DEFAULT_PRESSURE_CRITICAL_AVAIL_PCT,
            warning_avail_inodes: DEFAULT_PRESSURE_WARNING_AVAIL_INODES,
            critical_avail_inodes: DEFAULT_PRESSURE_CRITICAL_AVAIL_INODES,
        }
    }
}

// ── Real-fleet smoke/soak ────────────────────────────────────────────────────

/// Real-fleet smoke and soak validation defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct SmokeConfig {
    /// Iteration count for the soak workload.
    pub iterations: usize,
    /// Deterministic seed for the soak workload.
    pub seed: u64,
}

impl Default for SmokeConfig {
    fn default() -> Self {
        Self {
            iterations: DEFAULT_SMOKE_ITERATIONS,
            seed: DEFAULT_SMOKE_SEED,
        }
    }
}

// ── Aggregate ────────────────────────────────────────────────────────────────

/// The complete remediation config schema: one section per subsystem plus the
/// top-level failure-mode policy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(default)]
pub struct RemediationConfig {
    /// Failure-mode policy (fail-open hook/exec, fail-closed proof mode).
    pub policy: RemediationPolicy,
    /// Temporary-bypass retention and backoff.
    pub temporary_bypass: TemporaryBypassConfig,
    /// Auto-rejoin canary thresholds and recovery-probe dimensions.
    pub auto_rejoin: AutoRejoinConfig,
    /// Desired-state reconciliation windows.
    pub reconciliation: ReconciliationConfig,
    /// Proof intent store and default replay policy.
    pub proof: ProofConfig,
    /// Incident ledger retention.
    pub incident_ledger: IncidentLedgerPolicy,
    /// Mount-aware build-root safety thresholds.
    pub build_root: BuildRootConfig,
    /// Pooled target-dir policy and stale reaper.
    pub pooled_target: PooledTargetConfig,
    /// Telemetry freshness tolerance.
    pub telemetry_freshness: TelemetryFreshnessConfig,
    /// Daemon log rotation/retention.
    pub log_retention: LogRetentionConfig,
    /// Disk-pressure classification thresholds.
    pub disk_pressure: DiskPressureConfig,
    /// Real-fleet smoke/soak defaults.
    pub smoke: SmokeConfig,
}

/// Severity of a [`RemediationIssue`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssueSeverity {
    /// A value that makes the config invalid and must be corrected.
    Error,
    /// A value that is accepted but worth flagging (e.g. an operator path
    /// outside the RCH-managed roots).
    Warning,
}

/// A single validation finding for a remediation knob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemediationIssue {
    /// Dotted field path, e.g. `remediation.auto_rejoin.check_interval_secs`.
    pub field: String,
    /// Whether the finding is an error or an advisory warning.
    pub severity: IssueSeverity,
    /// Human-readable explanation.
    pub message: String,
}

impl RemediationIssue {
    fn error(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            severity: IssueSeverity::Error,
            message: message.into(),
        }
    }

    fn warning(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            severity: IssueSeverity::Warning,
            message: message.into(),
        }
    }
}

impl RemediationConfig {
    /// Whether ordinary hook / `rch exec` paths fall back to local on error.
    #[must_use]
    pub fn hook_exec_is_fail_open(&self) -> bool {
        self.policy.hook_exec_fail_open
    }

    /// Whether explicit proof mode refuses local fallback before running.
    #[must_use]
    pub fn proof_mode_is_fail_closed(&self) -> bool {
        self.policy.proof_mode_fail_closed
    }

    /// Validate every knob, returning any errors and advisory warnings.
    ///
    /// Range/ordering checks reject impossible values; path checks require
    /// operator paths to be absolute and flag any path outside the RCH-managed
    /// roots as an operator override (warning, not error).
    #[must_use]
    pub fn validate(&self) -> Vec<RemediationIssue> {
        let mut issues = Vec::new();

        // Temporary bypass backoff.
        if self.temporary_bypass.backoff_initial_secs == 0 {
            issues.push(RemediationIssue::error(
                "remediation.temporary_bypass.backoff_initial_secs",
                "backoff_initial_secs must be greater than 0",
            ));
        }
        if self.temporary_bypass.backoff_max_secs < self.temporary_bypass.backoff_initial_secs {
            issues.push(RemediationIssue::error(
                "remediation.temporary_bypass.backoff_max_secs",
                "backoff_max_secs must be >= backoff_initial_secs",
            ));
        }

        // Auto-rejoin.
        if self.auto_rejoin.required_consecutive_passes == 0 {
            issues.push(RemediationIssue::error(
                "remediation.auto_rejoin.required_consecutive_passes",
                "required_consecutive_passes must be at least 1",
            ));
        }
        if self.auto_rejoin.check_interval_secs == 0 {
            issues.push(RemediationIssue::error(
                "remediation.auto_rejoin.check_interval_secs",
                "check_interval_secs must be greater than 0",
            ));
        }
        if self.auto_rejoin.probe_timeout_secs == 0 {
            issues.push(RemediationIssue::error(
                "remediation.auto_rejoin.probe_timeout_secs",
                "probe_timeout_secs must be greater than 0",
            ));
        }
        if !self.auto_rejoin.min_disk_free_gb.is_finite() || self.auto_rejoin.min_disk_free_gb < 0.0
        {
            issues.push(RemediationIssue::error(
                "remediation.auto_rejoin.min_disk_free_gb",
                "min_disk_free_gb must be finite and >= 0",
            ));
        }
        if !self.auto_rejoin.max_load_per_core.is_finite()
            || self.auto_rejoin.max_load_per_core <= 0.0
        {
            issues.push(RemediationIssue::error(
                "remediation.auto_rejoin.max_load_per_core",
                "max_load_per_core must be finite and > 0",
            ));
        }
        if self.auto_rejoin.canary_command.trim().is_empty() {
            issues.push(RemediationIssue::error(
                "remediation.auto_rejoin.canary_command",
                "canary_command must not be empty",
            ));
        }
        for root in &self.auto_rejoin.disk_roots {
            check_managed_path("remediation.auto_rejoin.disk_roots", root, &mut issues);
        }

        // Reconciliation.
        if self.reconciliation.max_attempts == 0 {
            issues.push(RemediationIssue::error(
                "remediation.reconciliation.max_attempts",
                "max_attempts must be at least 1",
            ));
        }
        if self.reconciliation.time_budget_secs == 0 {
            issues.push(RemediationIssue::error(
                "remediation.reconciliation.time_budget_secs",
                "time_budget_secs must be greater than 0",
            ));
        }

        // Proof store path.
        if let Some(path) = &self.proof.store_path {
            check_managed_path("remediation.proof.store_path", path, &mut issues);
        }

        // Incident ledger.
        if self.incident_ledger.max_entries == 0 {
            issues.push(RemediationIssue::error(
                "remediation.incident_ledger.max_entries",
                "max_entries must be at least 1",
            ));
        }
        if self.incident_ledger.max_bytes == 0 {
            issues.push(RemediationIssue::error(
                "remediation.incident_ledger.max_bytes",
                "max_bytes must be greater than 0",
            ));
        }
        if let Some(path) = &self.incident_ledger.path {
            check_managed_path("remediation.incident_ledger.path", path, &mut issues);
        }

        // Build root.
        if self.build_root.min_free_bytes == 0 {
            issues.push(RemediationIssue::error(
                "remediation.build_root.min_free_bytes",
                "min_free_bytes must be greater than 0",
            ));
        }

        // Pooled target.
        if self.pooled_target.reaper_enabled && self.pooled_target.reaper_interval_mins == 0 {
            issues.push(RemediationIssue::error(
                "remediation.pooled_target.reaper_interval_mins",
                "reaper_interval_mins must be > 0 when the reaper is enabled",
            ));
        }
        check_managed_path(
            "remediation.pooled_target.remote_base",
            &self.pooled_target.remote_base,
            &mut issues,
        );

        // Telemetry freshness.
        if self.telemetry_freshness.max_age_secs == 0 {
            issues.push(RemediationIssue::error(
                "remediation.telemetry_freshness.max_age_secs",
                "max_age_secs must be greater than 0",
            ));
        }

        // Log retention.
        if self.log_retention.max_file_bytes == 0 {
            issues.push(RemediationIssue::error(
                "remediation.log_retention.max_file_bytes",
                "max_file_bytes must be greater than 0",
            ));
        }
        if self.log_retention.critical_total_bytes < self.log_retention.warn_total_bytes {
            issues.push(RemediationIssue::error(
                "remediation.log_retention.critical_total_bytes",
                "critical_total_bytes must be >= warn_total_bytes",
            ));
        }

        // Disk pressure ordering and range.
        let dp = &self.disk_pressure;
        for (field, pct) in [
            (
                "remediation.disk_pressure.warning_avail_pct",
                dp.warning_avail_pct,
            ),
            (
                "remediation.disk_pressure.critical_avail_pct",
                dp.critical_avail_pct,
            ),
        ] {
            if !pct.is_finite() || !(0.0..=100.0).contains(&pct) {
                issues.push(RemediationIssue::error(
                    field,
                    "available-percent thresholds must be within [0.0, 100.0]",
                ));
            }
        }
        if dp.critical_avail_pct > dp.warning_avail_pct {
            issues.push(RemediationIssue::error(
                "remediation.disk_pressure.critical_avail_pct",
                "critical_avail_pct must be <= warning_avail_pct",
            ));
        }
        if dp.critical_avail_inodes > dp.warning_avail_inodes {
            issues.push(RemediationIssue::error(
                "remediation.disk_pressure.critical_avail_inodes",
                "critical_avail_inodes must be <= warning_avail_inodes",
            ));
        }

        // Smoke.
        if self.smoke.iterations == 0 {
            issues.push(RemediationIssue::error(
                "remediation.smoke.iterations",
                "iterations must be at least 1",
            ));
        }

        issues
    }

    /// A redacted clone: every path-like field has its home/user segment masked
    /// so the config is safe to print in status output, logs, and proof JSON.
    #[must_use]
    pub fn redacted(&self) -> Self {
        let mut out = self.clone();
        out.auto_rejoin.disk_roots = out
            .auto_rejoin
            .disk_roots
            .iter()
            .map(|p| redact_path(p))
            .collect();
        out.proof.store_path = out.proof.store_path.as_deref().map(redact_path);
        out.incident_ledger.path = out.incident_ledger.path.as_deref().map(redact_path);
        out.pooled_target.remote_base = redact_path(&out.pooled_target.remote_base);
        out
    }

    /// The machine-readable JSON Schema for the remediation config.
    ///
    /// This is the "machine-readable schema" half of the documented-defaults
    /// acceptance criterion; [`RemediationConfig::human_help`] is the human half.
    #[must_use]
    pub fn schema_json() -> serde_json::Value {
        serde_json::to_value(schema_for!(RemediationConfig))
            .expect("RemediationConfig schema serializes")
    }

    /// A human-readable summary of every knob and its default value.
    #[must_use]
    pub fn human_help() -> String {
        let d = RemediationConfig::default();
        let mut s = String::new();
        s.push_str("[remediation] — session-history remediation defaults\n");
        s.push_str("  policy.hook_exec_fail_open      = ");
        s.push_str(&d.policy.hook_exec_fail_open.to_string());
        s.push_str("  (ordinary hook/exec falls back to local on error)\n");
        s.push_str("  policy.proof_mode_fail_closed   = ");
        s.push_str(&d.policy.proof_mode_fail_closed.to_string());
        s.push_str("  (proof mode refuses local fallback)\n");
        s.push_str(&format!(
            "  temporary_bypass.backoff_initial_secs = {}\n",
            d.temporary_bypass.backoff_initial_secs
        ));
        s.push_str(&format!(
            "  temporary_bypass.backoff_max_secs     = {}\n",
            d.temporary_bypass.backoff_max_secs
        ));
        s.push_str(&format!(
            "  auto_rejoin.required_consecutive_passes = {}\n",
            d.auto_rejoin.required_consecutive_passes
        ));
        s.push_str(&format!(
            "  auto_rejoin.canary_required           = {}\n",
            d.auto_rejoin.canary_required
        ));
        s.push_str(&format!(
            "  auto_rejoin.check_interval_secs       = {}\n",
            d.auto_rejoin.check_interval_secs
        ));
        s.push_str(&format!(
            "  auto_rejoin.probe_timeout_secs        = {}\n",
            d.auto_rejoin.probe_timeout_secs
        ));
        s.push_str(&format!(
            "  reconciliation.max_attempts           = {}\n",
            d.reconciliation.max_attempts
        ));
        s.push_str(&format!(
            "  reconciliation.time_budget_secs       = {}\n",
            d.reconciliation.time_budget_secs
        ));
        s.push_str(&format!(
            "  proof.default_stale_source_policy     = {:?}\n",
            d.proof.default_stale_source_policy
        ));
        s.push_str(&format!(
            "  incident_ledger.max_entries           = {}\n",
            d.incident_ledger.max_entries
        ));
        s.push_str(&format!(
            "  incident_ledger.max_bytes             = {}\n",
            d.incident_ledger.max_bytes
        ));
        s.push_str(&format!(
            "  build_root.min_free_bytes             = {}\n",
            d.build_root.min_free_bytes
        ));
        s.push_str(&format!(
            "  build_root.min_free_inodes            = {}\n",
            d.build_root.min_free_inodes
        ));
        s.push_str(&format!(
            "  pooled_target.pooling_enabled         = {}\n",
            d.pooled_target.pooling_enabled
        ));
        s.push_str(&format!(
            "  pooled_target.reaper_enabled          = {}\n",
            d.pooled_target.reaper_enabled
        ));
        s.push_str(&format!(
            "  telemetry_freshness.max_age_secs      = {}\n",
            d.telemetry_freshness.max_age_secs
        ));
        s.push_str(&format!(
            "  log_retention.max_file_bytes          = {}\n",
            d.log_retention.max_file_bytes
        ));
        s.push_str(&format!(
            "  disk_pressure.warning_avail_pct       = {}\n",
            d.disk_pressure.warning_avail_pct
        ));
        s.push_str(&format!(
            "  disk_pressure.critical_avail_pct      = {}\n",
            d.disk_pressure.critical_avail_pct
        ));
        s.push_str(&format!(
            "  smoke.iterations                      = {}\n",
            d.smoke.iterations
        ));
        s.push_str(&format!(
            "  smoke.seed                            = {}\n",
            d.smoke.seed
        ));
        s
    }
}

/// Whether `path` resolves under a known RCH-managed/standard root.
#[must_use]
fn is_managed_path(path: &str) -> bool {
    if path.contains("/rch") {
        return true;
    }
    RCH_MANAGED_ROOT_PREFIXES
        .iter()
        .any(|prefix| path == *prefix || path.starts_with(&format!("{prefix}/")))
}

/// Push an error for a relative path or a warning for an operator path outside
/// the RCH-managed roots. Empty strings are ignored (treated as "unset").
fn check_managed_path(field: &str, path: &str, issues: &mut Vec<RemediationIssue>) {
    if path.trim().is_empty() {
        return;
    }
    // A leading `~` expands to an absolute home path at use time.
    let absolute = path.starts_with('/') || path.starts_with('~');
    if !absolute {
        issues.push(RemediationIssue::error(
            field,
            format!("path must be absolute, got {path:?}"),
        ));
        return;
    }
    if !is_managed_path(path) {
        issues.push(RemediationIssue::warning(
            field,
            format!(
                "{path:?} is outside the RCH-managed roots; ensure it is an intended operator path"
            ),
        ));
    }
}

/// Mask the home/user segment of a path so it is safe to print.
///
/// Pure and env-independent for stable golden output: `/home/<user>/x` →
/// `/home/<redacted>/x`, `/Users/<user>/x` → `/Users/<redacted>/x`, and a
/// leading `~` is preserved.
#[must_use]
fn redact_path(path: &str) -> String {
    for marker in ["/home/", "/Users/"] {
        if let Some(rest_start) = path.find(marker) {
            let (head, tail) = path.split_at(rest_start + marker.len());
            // `tail` begins with the username segment; mask up to the next `/`.
            let masked_tail = match tail.find('/') {
                Some(slash) => format!("<redacted>{}", &tail[slash..]),
                None => "<redacted>".to_string(),
            };
            return format!("{head}{masked_tail}");
        }
    }
    path.to_string()
}

// ── Conversions into rch-common runtime structs ──────────────────────────────
//
// These let runtime consumers build their existing structs from the central
// config; drift-guard tests assert each conversion of the *default* config
// reproduces the runtime struct's own `::default()`.

impl From<&TemporaryBypassConfig> for crate::bypass_record::BypassBackoff {
    fn from(cfg: &TemporaryBypassConfig) -> Self {
        Self {
            current_ms: cfg.backoff_initial_secs.saturating_mul(1000),
            attempts: 0,
            max_ms: cfg.backoff_max_secs.saturating_mul(1000),
        }
    }
}

impl From<&AutoRejoinConfig> for crate::bypass_record::AutoRejoinCriteria {
    fn from(cfg: &AutoRejoinConfig) -> Self {
        Self {
            required_consecutive_passes: cfg.required_consecutive_passes,
            canary_required: cfg.canary_required,
        }
    }
}

impl From<&IncidentLedgerPolicy> for IncidentLedgerConfig {
    fn from(cfg: &IncidentLedgerPolicy) -> Self {
        Self {
            path: cfg
                .path
                .as_ref()
                .map_or_else(default_ledger_path, std::path::PathBuf::from),
            max_entries: cfg.max_entries,
            max_bytes: cfg.max_bytes,
        }
    }
}

impl From<&LogRetentionConfig> for crate::log_retention::LogRetentionPolicy {
    fn from(cfg: &LogRetentionConfig) -> Self {
        Self {
            max_file_bytes: cfg.max_file_bytes,
            keep_rotated: cfg.keep_rotated,
            warn_total_bytes: cfg.warn_total_bytes,
            critical_total_bytes: cfg.critical_total_bytes,
        }
    }
}

impl From<&DiskPressureConfig> for crate::disk_pressure_report::PressureThresholds {
    fn from(cfg: &DiskPressureConfig) -> Self {
        Self {
            warning_avail_pct: cfg.warning_avail_pct,
            critical_avail_pct: cfg.critical_avail_pct,
            warning_avail_inodes: cfg.warning_avail_inodes,
            critical_avail_inodes: cfg.critical_avail_inodes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bypass_record::{AutoRejoinCriteria, BypassBackoff};
    use crate::disk_pressure_report::PressureThresholds;
    use crate::log_retention::LogRetentionPolicy;

    #[test]
    fn default_construction_matches_documented_values() {
        let c = RemediationConfig::default();
        assert!(c.policy.hook_exec_fail_open);
        assert!(c.policy.proof_mode_fail_closed);
        assert_eq!(c.temporary_bypass.backoff_initial_secs, 30);
        assert_eq!(c.temporary_bypass.backoff_max_secs, 900);
        assert_eq!(c.auto_rejoin.required_consecutive_passes, 2);
        assert!(c.auto_rejoin.canary_required);
        assert_eq!(c.auto_rejoin.canary_command, "rustc --version");
        assert_eq!(c.reconciliation.max_attempts, 3);
        assert_eq!(c.incident_ledger.max_entries, 5_000);
        assert_eq!(c.incident_ledger.max_bytes, 4 * 1024 * 1024);
        assert_eq!(c.build_root.min_free_bytes, 2 * 1024 * 1024 * 1024);
        assert_eq!(c.telemetry_freshness.max_age_secs, 120);
        assert_eq!(c.smoke.iterations, 20);
    }

    #[test]
    fn default_is_valid() {
        let issues = RemediationConfig::default().validate();
        assert!(issues.is_empty(), "default must be valid, got {issues:?}");
    }

    #[test]
    fn serde_round_trip_via_toml() {
        let c = RemediationConfig::default();
        let toml_str = toml::to_string(&c).expect("serialize toml");
        let back: RemediationConfig = toml::from_str(&toml_str).expect("deserialize toml");
        assert_eq!(c, back);
    }

    #[test]
    fn serde_round_trip_via_json() {
        let c = RemediationConfig::default();
        let json = serde_json::to_string(&c).expect("serialize json");
        let back: RemediationConfig = serde_json::from_str(&json).expect("deserialize json");
        assert_eq!(c, back);
    }

    #[test]
    fn partial_toml_fills_missing_fields_from_default() {
        // Container-level #[serde(default)] must fill every omitted field.
        let partial = r#"
            [policy]
            hook_exec_fail_open = false

            [auto_rejoin]
            check_interval_secs = 99
        "#;
        let c: RemediationConfig = toml::from_str(partial).expect("parse partial");
        // Overridden:
        assert!(!c.policy.hook_exec_fail_open);
        assert_eq!(c.auto_rejoin.check_interval_secs, 99);
        // Untouched → defaults:
        assert!(c.policy.proof_mode_fail_closed);
        assert_eq!(c.auto_rejoin.required_consecutive_passes, 2);
        assert_eq!(c.incident_ledger.max_entries, 5_000);
    }

    #[test]
    fn malformed_values_are_rejected_by_validate() {
        let mut c = RemediationConfig::default();
        c.temporary_bypass.backoff_initial_secs = 0;
        c.auto_rejoin.check_interval_secs = 0;
        c.auto_rejoin.canary_command = "  ".to_string();
        c.disk_pressure_force_invalid();
        c.incident_ledger.max_entries = 0;
        let issues = c.validate();
        let fields: Vec<&str> = issues.iter().map(|i| i.field.as_str()).collect();
        assert!(fields.contains(&"remediation.temporary_bypass.backoff_initial_secs"));
        assert!(fields.contains(&"remediation.auto_rejoin.check_interval_secs"));
        assert!(fields.contains(&"remediation.auto_rejoin.canary_command"));
        assert!(fields.contains(&"remediation.incident_ledger.max_entries"));
        assert!(issues.iter().any(|i| i.severity == IssueSeverity::Error
            && i.field.starts_with("remediation.disk_pressure")));
    }

    #[test]
    fn malformed_toml_value_type_fails_to_parse() {
        // backoff_initial_secs must be an integer, not a string.
        let bad = r#"
            [temporary_bypass]
            backoff_initial_secs = "thirty"
        "#;
        assert!(toml::from_str::<RemediationConfig>(bad).is_err());
    }

    #[test]
    fn relative_path_is_an_error_managed_path_is_clean() {
        let mut c = RemediationConfig::default();
        c.incident_ledger.path = Some("relative/incidents.jsonl".to_string());
        let issues = c.validate();
        assert!(issues.iter().any(|i| {
            i.field == "remediation.incident_ledger.path" && i.severity == IssueSeverity::Error
        }));

        // A managed path under /tmp/rch is clean (no issue for that field).
        c.incident_ledger.path = Some("/tmp/rch/incidents.jsonl".to_string());
        let issues = c.validate();
        assert!(
            !issues
                .iter()
                .any(|i| i.field == "remediation.incident_ledger.path")
        );
    }

    #[test]
    fn operator_path_outside_managed_roots_warns() {
        let mut c = RemediationConfig::default();
        c.incident_ledger.path = Some("/var/lib/custom/incidents.jsonl".to_string());
        let issues = c.validate();
        let issue = issues
            .iter()
            .find(|i| i.field == "remediation.incident_ledger.path")
            .expect("operator path produces an issue");
        assert_eq!(issue.severity, IssueSeverity::Warning);
    }

    #[test]
    fn redaction_masks_home_and_user_segments() {
        let mut c = RemediationConfig::default();
        c.incident_ledger.path = Some("/home/alice/.local/state/rch/incidents.jsonl".to_string());
        c.proof.store_path = Some("/Users/bob/proofs.jsonl".to_string());
        c.auto_rejoin.disk_roots = vec!["/home/carol/builds".to_string(), "/tmp/rch".to_string()];
        let r = c.redacted();
        assert_eq!(
            r.incident_ledger.path.as_deref(),
            Some("/home/<redacted>/.local/state/rch/incidents.jsonl")
        );
        assert_eq!(
            r.proof.store_path.as_deref(),
            Some("/Users/<redacted>/proofs.jsonl")
        );
        assert_eq!(
            r.auto_rejoin.disk_roots,
            vec![
                "/home/<redacted>/builds".to_string(),
                "/tmp/rch".to_string()
            ]
        );
        // Non-sensitive paths are untouched.
        assert_eq!(redact_path("/tmp/rch"), "/tmp/rch");
        assert_eq!(redact_path("/data/projects"), "/data/projects");
    }

    #[test]
    fn schema_json_describes_the_struct() {
        let schema = RemediationConfig::schema_json();
        // Top-level object with our sections present.
        let props = schema
            .get("properties")
            .and_then(serde_json::Value::as_object)
            .expect("schema has properties");
        for section in [
            "policy",
            "temporary_bypass",
            "auto_rejoin",
            "reconciliation",
            "proof",
            "incident_ledger",
            "build_root",
            "pooled_target",
            "telemetry_freshness",
            "log_retention",
            "disk_pressure",
            "smoke",
        ] {
            assert!(
                props.contains_key(section),
                "schema missing section {section}"
            );
        }
    }

    #[test]
    fn human_help_lists_key_defaults() {
        let help = RemediationConfig::human_help();
        assert!(help.contains("hook_exec_fail_open"));
        assert!(help.contains("proof_mode_fail_closed"));
        assert!(help.contains("backoff_initial_secs"));
        assert!(help.contains("incident_ledger.max_entries"));
    }

    // ── Drift guards: central defaults reproduce runtime struct defaults ──

    #[test]
    fn drift_guard_bypass_backoff() {
        let from_cfg = BypassBackoff::from(&TemporaryBypassConfig::default());
        assert_eq!(from_cfg, BypassBackoff::default());
    }

    #[test]
    fn drift_guard_auto_rejoin_criteria() {
        let from_cfg = AutoRejoinCriteria::from(&AutoRejoinConfig::default());
        assert_eq!(from_cfg, AutoRejoinCriteria::default());
    }

    #[test]
    fn drift_guard_log_retention() {
        let from_cfg = LogRetentionPolicy::from(&LogRetentionConfig::default());
        assert_eq!(from_cfg, LogRetentionPolicy::default());
    }

    #[test]
    fn drift_guard_disk_pressure() {
        let from_cfg = PressureThresholds::from(&DiskPressureConfig::default());
        assert_eq!(from_cfg, PressureThresholds::default());
    }

    #[test]
    fn drift_guard_incident_ledger() {
        let from_cfg = IncidentLedgerConfig::from(&IncidentLedgerPolicy::default());
        let runtime = IncidentLedgerConfig::default();
        // IncidentLedgerConfig has no PartialEq; compare field-by-field.
        assert_eq!(from_cfg.max_entries, runtime.max_entries);
        assert_eq!(from_cfg.max_bytes, runtime.max_bytes);
        assert_eq!(from_cfg.path, runtime.path);
    }

    // Test-only helper to force an invalid disk-pressure ordering.
    impl RemediationConfig {
        fn disk_pressure_force_invalid(&mut self) {
            self.disk_pressure.critical_avail_pct = 90.0;
            self.disk_pressure.warning_avail_pct = 10.0;
        }
    }
}
