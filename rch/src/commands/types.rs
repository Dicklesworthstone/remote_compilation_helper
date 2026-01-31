//! Response types for CLI command outputs.
//!
//! This module contains all JSON-serializable response types used by CLI commands.
//! These types are separated from the command implementations to improve code organization
//! and enable easier testing.

use rch_common::{
    Classification, ClassificationTier, RequiredRuntime, SelectedWorker, SelectionReason,
    WorkerCapabilities, WorkerConfig,
};
use schemars::JsonSchema;
use serde::Serialize;

use crate::status_types::WorkerCapabilitiesFromApi;

// =============================================================================
// Worker Response Types
// =============================================================================

/// Worker information for JSON output.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct WorkerInfo {
    pub id: String,
    pub host: String,
    pub user: String,
    pub total_slots: u32,
    pub priority: u32,
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub speedscore: Option<f64>,
}

impl From<&WorkerConfig> for WorkerInfo {
    fn from(w: &WorkerConfig) -> Self {
        Self {
            id: w.id.as_str().to_string(),
            host: w.host.clone(),
            user: w.user.clone(),
            total_slots: w.total_slots,
            priority: w.priority,
            tags: w.tags.clone(),
            speedscore: None,
        }
    }
}

/// Workers list response.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct WorkersListResponse {
    pub workers: Vec<WorkerInfo>,
    pub count: usize,
}

/// Worker probe result.
#[derive(Debug, Clone, Serialize)]
pub struct WorkerProbeResult {
    pub id: String,
    pub host: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Worker capabilities report for JSON output.
#[derive(Debug, Clone, Serialize)]
pub struct WorkersCapabilitiesReport {
    pub workers: Vec<WorkerCapabilitiesFromApi>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local: Option<WorkerCapabilities>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_runtime: Option<RequiredRuntime>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub warnings: Vec<String>,
}

/// Worker benchmark result for JSON output.
#[derive(Debug, Clone, Serialize)]
pub struct WorkerBenchmarkResult {
    pub id: String,
    pub host: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Worker action response for JSON output.
#[derive(Debug, Clone, Serialize)]
pub struct WorkerActionResponse {
    pub worker_id: String,
    pub action: String,
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

// =============================================================================
// Daemon Response Types
// =============================================================================

/// Daemon status response.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct DaemonStatusResponse {
    pub running: bool,
    pub socket_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uptime_seconds: Option<u64>,
}

/// System overview response.
///
/// Named `SystemOverview` to distinguish from daemon's `DaemonFullStatus` type.
#[derive(Debug, Clone, Serialize)]
#[allow(dead_code)]
pub struct SystemOverview {
    pub daemon_running: bool,
    pub hook_installed: bool,
    pub workers_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workers: Option<Vec<WorkerInfo>>,
}

/// Daemon action response for JSON output.
#[derive(Debug, Clone, Serialize)]
pub struct DaemonActionResponse {
    pub action: String,
    pub success: bool,
    pub socket_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Daemon reload response for JSON output.
#[derive(Debug, Clone, Serialize)]
pub struct DaemonReloadResponse {
    pub success: bool,
    pub added: usize,
    pub updated: usize,
    pub removed: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Daemon logs response for JSON output.
#[derive(Debug, Clone, Serialize)]
pub struct DaemonLogsResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_file: Option<String>,
    pub lines: Vec<String>,
    pub found: bool,
}

// =============================================================================
// Configuration Response Types
// =============================================================================

/// Configuration show response for JSON output.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct ConfigShowResponse {
    pub general: ConfigGeneralSection,
    pub compilation: ConfigCompilationSection,
    pub transfer: ConfigTransferSection,
    pub environment: ConfigEnvironmentSection,
    pub circuit: ConfigCircuitSection,
    pub output: ConfigOutputSection,
    pub self_healing: ConfigSelfHealingSection,
    pub sources: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_sources: Option<Vec<ConfigValueSourceInfo>>,
}

/// Source information for a single configuration value.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct ConfigValueSourceInfo {
    pub key: String,
    pub value: String,
    pub source: String,
}

/// Configuration get response for JSON output.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct ConfigGetResponse {
    pub key: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

/// Configuration export response for JSON output.
#[derive(Debug, Clone, Serialize)]
#[allow(dead_code)]
pub struct ConfigExportResponse {
    pub format: String,
    pub content: String,
}

/// General configuration section.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct ConfigGeneralSection {
    pub enabled: bool,
    pub force_local: bool,
    pub force_remote: bool,
    pub log_level: String,
    pub socket_path: String,
}

/// Compilation configuration section.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct ConfigCompilationSection {
    pub confidence_threshold: f64,
    pub min_local_time_ms: u64,
}

/// Transfer configuration section.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct ConfigTransferSection {
    pub compression_level: u32,
    pub exclude_patterns: Vec<String>,
    pub remote_base: String,
    // Transfer optimization (bd-3hho)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_transfer_mb: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_transfer_time_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bwlimit_kbps: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub estimated_bandwidth_bps: Option<u64>,
    // Adaptive compression (bd-243w)
    pub adaptive_compression: bool,
    pub min_compression_level: u32,
    pub max_compression_level: u32,
    // Artifact verification (bd-377q)
    pub verify_artifacts: bool,
    #[serde(skip_serializing_if = "is_default_verify_size")]
    pub verify_max_size_bytes: u64,
}

/// Helper function for serialization: returns true if value is the default verify size (100 MB).
pub fn is_default_verify_size(val: &u64) -> bool {
    *val == 100 * 1024 * 1024 // 100 MB default
}

/// Environment configuration section.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct ConfigEnvironmentSection {
    pub allowlist: Vec<String>,
}

/// Circuit breaker configuration section.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct ConfigCircuitSection {
    pub failure_threshold: u32,
    pub success_threshold: u32,
    pub error_rate_threshold: f64,
    pub window_secs: u64,
    pub open_cooldown_secs: u64,
    pub half_open_max_probes: u32,
}

/// Output configuration section.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct ConfigOutputSection {
    pub visibility: rch_common::OutputVisibility,
    pub first_run_complete: bool,
}

/// Self-healing configuration section.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct ConfigSelfHealingSection {
    pub hook_starts_daemon: bool,
    pub daemon_installs_hooks: bool,
    pub auto_start_cooldown_secs: u64,
    pub auto_start_timeout_secs: u64,
}

/// Configuration init response for JSON output.
#[derive(Debug, Clone, Serialize)]
pub struct ConfigInitResponse {
    pub created: Vec<String>,
    pub already_existed: Vec<String>,
}

/// Configuration validation response for JSON output.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct ConfigValidationResponse {
    pub errors: Vec<ConfigValidationIssue>,
    pub warnings: Vec<ConfigValidationIssue>,
    pub valid: bool,
}

/// A single validation issue.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct ConfigValidationIssue {
    pub file: String,
    pub message: String,
}

/// Configuration set response for JSON output.
#[derive(Debug, Clone, Serialize)]
pub struct ConfigSetResponse {
    pub key: String,
    pub value: String,
    pub config_path: String,
}

/// Configuration reset response for JSON output.
#[derive(Debug, Clone, Serialize)]
pub struct ConfigResetResponse {
    pub key: String,
    pub value: String,
    pub config_path: String,
}

/// Issue severity for config lint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum LintSeverity {
    Error,
    Warning,
    Info,
}

/// A single lint issue.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct LintIssue {
    pub severity: LintSeverity,
    pub code: String,
    pub message: String,
    pub remediation: String,
}

/// Response for config lint command.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct ConfigLintResponse {
    pub issues: Vec<LintIssue>,
    pub error_count: usize,
    pub warning_count: usize,
    pub info_count: usize,
}

/// A single diff entry showing a non-default value.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct ConfigDiffEntry {
    pub key: String,
    pub current: String,
    pub default: String,
    pub source: String,
}

/// Response for config diff command.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct ConfigDiffResponse {
    pub entries: Vec<ConfigDiffEntry>,
    pub total_changes: usize,
}

// =============================================================================
// Diagnose Response Types
// =============================================================================

/// Diagnose command response for JSON output.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct DiagnoseResponse {
    pub classification: Classification,
    pub tiers: Vec<ClassificationTier>,
    pub command: String,
    pub normalized_command: String,
    pub decision: DiagnoseDecision,
    pub threshold: DiagnoseThreshold,
    pub daemon: DiagnoseDaemonStatus,
    pub required_runtime: RequiredRuntime,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_capabilities: Option<WorkerCapabilities>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub capabilities_warnings: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub worker_selection: Option<DiagnoseWorkerSelection>,
    /// Dry-run summary showing the full pipeline (only present when --dry-run is used).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dry_run: Option<DryRunSummary>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct DiagnoseDecision {
    pub would_intercept: bool,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct DiagnoseThreshold {
    pub value: f64,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct DiagnoseDaemonStatus {
    pub socket_path: String,
    pub socket_exists: bool,
    pub reachable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uptime_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct DiagnoseWorkerSelection {
    pub estimated_cores: u32,
    pub worker: Option<SelectedWorker>,
    pub reason: SelectionReason,
}

/// Pipeline step for dry-run output.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct DryRunPipelineStep {
    /// Step number (1-based).
    pub step: u32,
    /// Step name (e.g., "classify", "select", "sync_up", "exec", "sync_down").
    pub name: String,
    /// Human-readable description of what would happen.
    pub description: String,
    /// Whether this step would be skipped.
    pub skipped: bool,
    /// Reason for skipping (if skipped).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<String>,
    /// Estimated duration in milliseconds (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub estimated_duration_ms: Option<u64>,
}

/// Transfer size estimation for dry-run.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct DryRunTransferEstimate {
    /// Estimated bytes to transfer.
    pub bytes: u64,
    /// Human-readable size (e.g., "12.5 MB").
    pub human_size: String,
    /// Estimated number of files.
    pub files: u32,
    /// Estimated transfer time in milliseconds.
    pub estimated_time_ms: u64,
    /// Whether transfer would be skipped due to size limits.
    pub would_skip: bool,
    /// Reason for skipping (if would_skip is true).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<String>,
}

/// Dry-run summary showing the full pipeline.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct DryRunSummary {
    /// Whether the command would be offloaded remotely.
    pub would_offload: bool,
    /// Reason for the offload decision.
    pub reason: String,
    /// Pipeline steps that would be executed.
    pub pipeline_steps: Vec<DryRunPipelineStep>,
    /// Transfer size estimation (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transfer_estimate: Option<DryRunTransferEstimate>,
    /// Total estimated time in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_estimated_ms: Option<u64>,
}

// =============================================================================
// Hook Response Types
// =============================================================================

/// Hook install/uninstall response for JSON output.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct HookActionResponse {
    pub action: String,
    pub success: bool,
    pub settings_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Hook test response for JSON output.
#[derive(Debug, Clone, Serialize)]
#[allow(dead_code)]
pub struct HookTestResponse {
    pub classification_tests: Vec<ClassificationTestResult>,
    pub daemon_connected: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub daemon_response: Option<String>,
    pub workers_configured: usize,
    pub workers: Vec<WorkerInfo>,
}

/// Classification test result.
#[derive(Debug, Clone, Serialize)]
#[allow(dead_code)]
pub struct ClassificationTestResult {
    pub command: String,
    pub is_compilation: bool,
    pub confidence: f64,
    pub expected_intercept: bool,
    pub passed: bool,
}

// =============================================================================
// Doctor Command Response Types
// =============================================================================

/// Status of a diagnostic check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum DoctorCheckStatus {
    Pass,
    Warning,
    Fail,
    Skipped,
}

/// Result of a single diagnostic check.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct DoctorCheck {
    pub category: String,
    pub name: String,
    pub status: DoctorCheckStatus,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggestion: Option<String>,
    /// Whether this issue can be auto-fixed.
    #[serde(default)]
    pub fixable: bool,
    /// Whether a fix was applied during this run.
    #[serde(default)]
    pub fix_applied: bool,
    /// Message about the fix that was applied (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix_message: Option<String>,
}

/// Summary of all doctor checks.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct DoctorSummary {
    pub total: usize,
    pub passed: usize,
    pub warnings: usize,
    pub failed: usize,
    pub fixed: usize,
    pub would_fix: usize,
}

/// A fix that was applied during doctor run.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct DoctorFixApplied {
    pub check_name: String,
    pub action: String,
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Overall doctor command response for JSON output.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct DoctorResponse {
    pub checks: Vec<DoctorCheck>,
    pub summary: DoctorSummary,
    pub fixes_applied: Vec<DoctorFixApplied>,
}
