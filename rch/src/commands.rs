//! CLI command handler implementations.
//!
//! This module contains the actual business logic for each CLI subcommand.

use crate::error::{ConfigError, SshError};
use crate::status_types::{
    DaemonFullStatusResponse, SelfTestHistoryResponse, SelfTestRunResponse, SelfTestStatusResponse,
    SpeedScoreHistoryResponseFromApi, SpeedScoreListResponseFromApi, SpeedScoreResponseFromApi,
    SpeedScoreViewFromApi, WorkerCapabilitiesFromApi, WorkerCapabilitiesResponseFromApi,
    extract_json_body,
};
use crate::ui::context::OutputContext;
use crate::ui::theme::StatusIndicator;
use anyhow::{Context, Result, bail};
use directories::ProjectDirs;
use rch_common::{
    ApiError, ApiResponse, Classification, ClassificationDetails, ClassificationTier,
    CommandPriority, ConfigValueSource, DiscoveredHost, ErrorCode, RchConfig, RequiredRuntime,
    SelectedWorker, SelectionReason, SshClient, SshOptions, WorkerCapabilities, WorkerConfig,
    WorkerId, classify_command_detailed, discover_all,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::process::Command;
use tracing::debug;

use crate::hook::{query_daemon, release_worker, required_runtime_for_kind};
use crate::toolchain::detect_toolchain;
use crate::transfer::project_id_from_path;

/// Default socket path.
const DEFAULT_SOCKET_PATH: &str = "/tmp/rch.sock";

fn print_file_validation(
    label: &str,
    validations: &[crate::config::FileValidation],
    style: &crate::ui::theme::Theme,
    path: &Path,
) {
    let Some(validation) = validations.iter().find(|v| v.file == path) else {
        return;
    };

    if validation.errors.is_empty() && validation.warnings.is_empty() {
        println!(
            "{} {}: {}",
            StatusIndicator::Success.display(style),
            style.highlight(label),
            style.success("Valid")
        );
        return;
    }

    if validation.errors.is_empty() {
        println!(
            "{} {}: {}",
            StatusIndicator::Warning.display(style),
            style.highlight(label),
            style.warning("Valid (warnings)")
        );
    } else {
        println!(
            "{} {}: {}",
            StatusIndicator::Error.display(style),
            style.highlight(label),
            style.error("Invalid")
        );
    }

    for warning in &validation.warnings {
        println!(
            "  {} {}",
            StatusIndicator::Warning.display(style),
            style.muted(warning)
        );
    }

    for error in &validation.errors {
        println!(
            "  {} {}",
            StatusIndicator::Error.display(style),
            style.error(error)
        );
    }
}
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

fn runtime_label(runtime: &RequiredRuntime) -> &'static str {
    match runtime {
        RequiredRuntime::Rust => "rust",
        RequiredRuntime::Bun => "bun",
        RequiredRuntime::Node => "node",
        RequiredRuntime::None => "none",
    }
}

fn has_any_capabilities(capabilities: &WorkerCapabilities) -> bool {
    capabilities.rustc_version.is_some()
        || capabilities.bun_version.is_some()
        || capabilities.node_version.is_some()
        || capabilities.npm_version.is_some()
}

/// Probe local runtime capabilities by running version commands in parallel.
/// Uses tokio async to spawn all 4 version checks concurrently, reducing total
/// latency from ~200ms (sequential) to ~50ms (parallel).
async fn probe_local_capabilities() -> WorkerCapabilities {
    async fn run_version(cmd: &str, args: &[&str]) -> Option<String> {
        let output = tokio::process::Command::new(cmd)
            .args(args)
            .output()
            .await
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let trimmed = stdout.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    }

    // Run all version checks in parallel
    let (rustc, bun, node, npm) = tokio::join!(
        run_version("rustc", &["--version"]),
        run_version("bun", &["--version"]),
        run_version("node", &["--version"]),
        run_version("npm", &["--version"]),
    );

    let mut caps = WorkerCapabilities::new();
    caps.rustc_version = rustc;
    caps.bun_version = bun;
    caps.node_version = node;
    caps.npm_version = npm;
    caps
}

fn extract_version_numbers(version: &str) -> Vec<u64> {
    let mut numbers = Vec::new();
    let mut current: Option<u64> = None;
    for ch in version.chars() {
        if let Some(digit) = ch.to_digit(10) {
            let next = current
                .unwrap_or(0)
                .saturating_mul(10)
                .saturating_add(digit as u64);
            current = Some(next);
        } else if let Some(value) = current.take() {
            numbers.push(value);
        }
    }
    if let Some(value) = current {
        numbers.push(value);
    }
    numbers
}

fn major_version(version: &str) -> Option<u64> {
    extract_version_numbers(version).into_iter().next()
}

fn major_minor_version(version: &str) -> Option<(u64, u64)> {
    let numbers = extract_version_numbers(version);
    if numbers.len() >= 2 {
        Some((numbers[0], numbers[1]))
    } else {
        None
    }
}

fn rust_version_mismatch(local: &str, remote: &str) -> bool {
    match (major_minor_version(local), major_minor_version(remote)) {
        (Some((lmaj, lmin)), Some((rmaj, rmin))) => lmaj != rmaj || lmin != rmin,
        _ => false,
    }
}

fn major_version_mismatch(local: &str, remote: &str) -> bool {
    match (major_version(local), major_version(remote)) {
        (Some(lmaj), Some(rmaj)) => lmaj != rmaj,
        _ => false,
    }
}

fn collect_local_capability_warnings(
    workers: &[WorkerCapabilitiesFromApi],
    local: &WorkerCapabilities,
) -> Vec<String> {
    let mut warnings = Vec::new();

    if let Some(local_rust) = local.rustc_version.as_ref() {
        let missing: Vec<String> = workers
            .iter()
            .filter(|worker| !worker.capabilities.has_rust())
            .map(|worker| worker.id.clone())
            .collect();
        if !missing.is_empty() {
            warnings.push(format!(
                "Workers missing Rust runtime (local: {}): {}",
                local_rust,
                missing.join(", ")
            ));
        }

        let mismatched: Vec<String> = workers
            .iter()
            .filter_map(|worker| {
                let remote = worker.capabilities.rustc_version.as_ref()?;
                if rust_version_mismatch(local_rust, remote) {
                    Some(format!("{} ({})", worker.id, remote))
                } else {
                    None
                }
            })
            .collect();
        if !mismatched.is_empty() {
            warnings.push(format!(
                "Rust version mismatch vs local {}: {}",
                local_rust,
                mismatched.join(", ")
            ));
        }
    }

    if let Some(local_bun) = local.bun_version.as_ref() {
        let missing: Vec<String> = workers
            .iter()
            .filter(|worker| !worker.capabilities.has_bun())
            .map(|worker| worker.id.clone())
            .collect();
        if !missing.is_empty() {
            warnings.push(format!(
                "Workers missing Bun runtime (local: {}): {}",
                local_bun,
                missing.join(", ")
            ));
        }

        let mismatched: Vec<String> = workers
            .iter()
            .filter_map(|worker| {
                let remote = worker.capabilities.bun_version.as_ref()?;
                if major_version_mismatch(local_bun, remote) {
                    Some(format!("{} ({})", worker.id, remote))
                } else {
                    None
                }
            })
            .collect();
        if !mismatched.is_empty() {
            warnings.push(format!(
                "Bun major version mismatch vs local {}: {}",
                local_bun,
                mismatched.join(", ")
            ));
        }
    }

    if let Some(local_node) = local.node_version.as_ref() {
        let missing: Vec<String> = workers
            .iter()
            .filter(|worker| !worker.capabilities.has_node())
            .map(|worker| worker.id.clone())
            .collect();
        if !missing.is_empty() {
            warnings.push(format!(
                "Workers missing Node runtime (local: {}): {}",
                local_node,
                missing.join(", ")
            ));
        }

        let mismatched: Vec<String> = workers
            .iter()
            .filter_map(|worker| {
                let remote = worker.capabilities.node_version.as_ref()?;
                if major_version_mismatch(local_node, remote) {
                    Some(format!("{} ({})", worker.id, remote))
                } else {
                    None
                }
            })
            .collect();
        if !mismatched.is_empty() {
            warnings.push(format!(
                "Node major version mismatch vs local {}: {}",
                local_node,
                mismatched.join(", ")
            ));
        }
    }

    if let Some(local_npm) = local.npm_version.as_ref() {
        let missing: Vec<String> = workers
            .iter()
            .filter(|worker| worker.capabilities.npm_version.is_none())
            .map(|worker| worker.id.clone())
            .collect();
        if !missing.is_empty() {
            warnings.push(format!(
                "Workers missing npm runtime (local: {}): {}",
                local_npm,
                missing.join(", ")
            ));
        }

        let mismatched: Vec<String> = workers
            .iter()
            .filter_map(|worker| {
                let remote = worker.capabilities.npm_version.as_ref()?;
                if major_version_mismatch(local_npm, remote) {
                    Some(format!("{} ({})", worker.id, remote))
                } else {
                    None
                }
            })
            .collect();
        if !mismatched.is_empty() {
            warnings.push(format!(
                "npm major version mismatch vs local {}: {}",
                local_npm,
                mismatched.join(", ")
            ));
        }
    }

    warnings
}

fn summarize_capabilities(capabilities: &WorkerCapabilities) -> String {
    let mut parts = Vec::new();
    if let Some(rustc) = capabilities.rustc_version.as_ref() {
        parts.push(format!("rustc {}", rustc));
    }
    if let Some(bun) = capabilities.bun_version.as_ref() {
        parts.push(format!("bun {}", bun));
    }
    if let Some(node) = capabilities.node_version.as_ref() {
        parts.push(format!("node {}", node));
    }
    if let Some(npm) = capabilities.npm_version.as_ref() {
        parts.push(format!("npm {}", npm));
    }

    if parts.is_empty() {
        "unknown".to_string()
    } else {
        parts.join(", ")
    }
}

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

fn is_default_verify_size(val: &u64) -> bool {
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

/// Get the RCH config directory path.
pub fn config_dir() -> Option<PathBuf> {
    #[cfg(test)]
    if let Some(dir) = test_config_dir_override() {
        return Some(dir);
    }
    ProjectDirs::from("com", "rch", "rch").map(|dirs| dirs.config_dir().to_path_buf())
}

#[cfg(test)]
thread_local! {
    static TEST_CONFIG_DIR_OVERRIDE: std::cell::RefCell<Option<PathBuf>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn test_config_dir_override() -> Option<PathBuf> {
    TEST_CONFIG_DIR_OVERRIDE.with(|override_path| override_path.borrow().clone())
}

#[cfg(test)]
pub(crate) fn set_test_config_dir_override(path: Option<PathBuf>) {
    TEST_CONFIG_DIR_OVERRIDE.with(|override_path| *override_path.borrow_mut() = path);
}

// =============================================================================
// Workers Commands
// =============================================================================

/// Load workers from configuration file.
///
/// Returns an empty vector if no workers are configured. Does not print
/// any messages - callers should handle the empty case appropriately.
pub fn load_workers_from_config() -> Result<Vec<WorkerConfig>> {
    let config_path = config_dir()
        .map(|d| d.join("workers.toml"))
        .context("Could not determine config directory")?;

    if !config_path.exists() {
        return Ok(vec![]);
    }

    let contents = std::fs::read_to_string(&config_path)
        .with_context(|| format!("Failed to read {:?}", config_path))?;

    // Parse the TOML - expect [[workers]] array
    let parsed: toml::Value =
        toml::from_str(&contents).with_context(|| format!("Failed to parse {:?}", config_path))?;

    let empty_array = vec![];
    let workers_array = parsed
        .get("workers")
        .and_then(|w| w.as_array())
        .unwrap_or(&empty_array);

    let mut workers = Vec::new();
    for entry in workers_array {
        let enabled = entry
            .get("enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        if !enabled {
            continue;
        }

        let id = entry
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let host = entry
            .get("host")
            .and_then(|v| v.as_str())
            .unwrap_or("localhost");
        let user = entry
            .get("user")
            .and_then(|v| v.as_str())
            .unwrap_or("ubuntu");
        let identity_file = entry
            .get("identity_file")
            .and_then(|v| v.as_str())
            .unwrap_or("~/.ssh/id_rsa");
        let total_slots = entry
            .get("total_slots")
            .and_then(|v| v.as_integer())
            .unwrap_or(8) as u32;
        let priority = entry
            .get("priority")
            .and_then(|v| v.as_integer())
            .unwrap_or(100) as u32;
        let tags: Vec<String> = entry
            .get("tags")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|t| t.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        workers.push(WorkerConfig {
            id: WorkerId::new(id),
            host: host.to_string(),
            user: user.to_string(),
            identity_file: identity_file.to_string(),
            total_slots,
            priority,
            tags,
        });
    }

    Ok(workers)
}

/// List all configured workers.
pub async fn workers_list(show_speedscore: bool, ctx: &OutputContext) -> Result<()> {
    let workers = load_workers_from_config()?;
    let style = ctx.theme();

    // Fetch speedscores if requested
    let speedscores = if show_speedscore {
        query_speedscore_list().await.ok()
    } else {
        None
    };

    // JSON output mode
    if ctx.is_json() {
        let mut worker_infos: Vec<WorkerInfo> = workers.iter().map(WorkerInfo::from).collect();
        // Enrich with speedscore data if available
        if let Some(ref scores) = speedscores {
            for info in &mut worker_infos {
                if let Some(score_entry) = scores.workers.iter().find(|s| s.worker_id == info.id)
                    && let Some(ref score) = score_entry.speedscore
                {
                    info.speedscore = Some(score.total);
                }
            }
        }
        let response = WorkersListResponse {
            count: workers.len(),
            workers: worker_infos,
        };
        let _ = ctx.json(&ApiResponse::ok("workers list", response));
        return Ok(());
    }

    if workers.is_empty() {
        let config_path = config_dir()
            .map(|d| d.join("workers.toml"))
            .unwrap_or_else(|| PathBuf::from("~/.config/rch/workers.toml"));
        println!("  {} No workers configured.", style.symbols.info);
        println!();
        println!(
            "  Create a workers config at: {}",
            style.value(&config_path.display().to_string())
        );
        println!();
        println!(
            "  Run {} to generate example configuration.",
            style.highlight("rch config init")
        );
        return Ok(());
    }

    println!("{}", style.format_header("Configured Workers"));
    println!();

    for worker in &workers {
        println!(
            "  {} {} {}@{}",
            style.symbols.bullet_filled,
            style.highlight(worker.id.as_str()),
            style.muted(&worker.user),
            style.info(&worker.host)
        );

        // Base stats line
        let mut stats_line = format!(
            "    {} {} {}  {} {} {}",
            style.key("Slots"),
            style.muted(":"),
            style.value(&worker.total_slots.to_string()),
            style.key("Priority"),
            style.muted(":"),
            style.value(&worker.priority.to_string())
        );

        // Add SpeedScore if available
        if let Some(ref scores) = speedscores
            && let Some(score_entry) = scores
                .workers
                .iter()
                .find(|s| s.worker_id == worker.id.as_str())
            && let Some(ref score) = score_entry.speedscore
        {
            let score_color = match score.total {
                x if x >= 75.0 => style.success(&format!("{:.0}", x)),
                x if x >= 45.0 => style.warning(&format!("{:.0}", x)),
                x => style.error(&format!("{:.0}", x)),
            };
            stats_line.push_str(&format!(
                "  {} {} {}",
                style.key("Score"),
                style.muted(":"),
                score_color
            ));
        }

        println!("{}", stats_line);

        if !worker.tags.is_empty() {
            println!(
                "    {} {} {}",
                style.key("Tags"),
                style.muted(":"),
                style.muted(&worker.tags.join(", "))
            );
        }
        println!();
    }

    println!(
        "{} {} worker(s)",
        style.muted("Total:"),
        style.highlight(&workers.len().to_string())
    );
    Ok(())
}

/// Show worker runtime capabilities.
pub async fn workers_capabilities(
    command: Option<String>,
    refresh: bool,
    ctx: &OutputContext,
) -> Result<()> {
    let style = ctx.theme();
    let response = query_workers_capabilities(refresh).await?;
    let workers = response.workers;
    let local_capabilities = probe_local_capabilities().await;
    let local_has_any = has_any_capabilities(&local_capabilities);

    let mut warnings = Vec::new();
    let mut required_runtime = None;

    if let Some(command) = command.as_deref() {
        let details = classify_command_detailed(command);
        if !details.classification.is_compilation {
            warnings.push(format!(
                "Command '{}' is not a compilation command: {}",
                command, details.classification.reason
            ));
        }
        let runtime = required_runtime_for_kind(details.classification.kind);
        if runtime != RequiredRuntime::None {
            required_runtime = Some(runtime);
        }
    }

    if let Some(runtime) = required_runtime {
        let missing: Vec<String> = workers
            .iter()
            .filter(|worker| {
                let caps = &worker.capabilities;
                match runtime {
                    RequiredRuntime::Rust => !caps.has_rust(),
                    RequiredRuntime::Bun => !caps.has_bun(),
                    RequiredRuntime::Node => !caps.has_node(),
                    RequiredRuntime::None => false,
                }
            })
            .map(|worker| worker.id.clone())
            .collect();

        if !missing.is_empty() {
            warnings.push(format!(
                "Workers missing required runtime {}: {}",
                runtime_label(&runtime),
                missing.join(", ")
            ));
        }
    }

    if local_has_any {
        warnings.extend(collect_local_capability_warnings(
            &workers,
            &local_capabilities,
        ));
    }

    if ctx.is_json() {
        let report = WorkersCapabilitiesReport {
            workers,
            local: Some(local_capabilities),
            required_runtime,
            warnings,
        };
        let _ = ctx.json(&ApiResponse::ok("workers capabilities", report));
        return Ok(());
    }

    if workers.is_empty() {
        println!(
            "{} {}",
            StatusIndicator::Warning.display(style),
            style.warning("No workers configured")
        );
        return Ok(());
    }

    println!("{}", style.format_header("Worker Capabilities"));
    println!();

    let key_width = ["Rust", "Bun", "Node", "npm"]
        .iter()
        .map(|label| label.len())
        .max()
        .unwrap_or(4);

    println!("{}", style.highlight("Local Capabilities"));
    let render = |label: &str, value: Option<&String>| {
        let (indicator, display) = if let Some(ver) = value {
            (StatusIndicator::Success, style.value(ver))
        } else {
            (StatusIndicator::Warning, style.warning("unknown"))
        };
        let padded_label = format!("{label:width$}", width = key_width);
        println!(
            "    {} {} {} {}",
            indicator.display(style),
            style.key(&padded_label),
            style.muted(":"),
            display
        );
    };
    render("Rust", local_capabilities.rustc_version.as_ref());
    render("Bun", local_capabilities.bun_version.as_ref());
    render("Node", local_capabilities.node_version.as_ref());
    render("npm", local_capabilities.npm_version.as_ref());
    if !local_has_any {
        println!(
            "    {} {}",
            StatusIndicator::Warning.display(style),
            style.warning("No local runtimes detected")
        );
    }
    println!();

    if let Some(runtime) = required_runtime.as_ref() {
        println!(
            "{} {}",
            style.key("Required runtime:"),
            style.value(runtime_label(runtime))
        );
        println!();
    }

    for worker in &workers {
        println!(
            "  {} {} {}@{}",
            style.symbols.bullet_filled,
            style.highlight(&worker.id),
            style.muted(&worker.user),
            style.info(&worker.host)
        );

        let caps = &worker.capabilities;
        render("Rust", caps.rustc_version.as_ref());
        render("Bun", caps.bun_version.as_ref());
        render("Node", caps.node_version.as_ref());
        render("npm", caps.npm_version.as_ref());
        println!();
    }

    if !warnings.is_empty() {
        println!("{}", style.format_header("Warnings"));
        for warning in warnings {
            println!(
                "  {} {}",
                StatusIndicator::Warning.display(style),
                style.warning(&warning)
            );
        }
    }

    Ok(())
}

/// Probe worker connectivity.
pub async fn workers_probe(
    worker_id: Option<String>,
    all: bool,
    ctx: &OutputContext,
) -> Result<()> {
    let workers = load_workers_from_config()?;
    let style = ctx.theme();

    if workers.is_empty() {
        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::<Vec<WorkerProbeResult>>::ok(
                "workers probe",
                vec![],
            ));
        }
        return Ok(());
    }

    let targets: Vec<&WorkerConfig> = if all {
        workers.iter().collect()
    } else if let Some(id) = &worker_id {
        workers.iter().filter(|w| w.id.as_str() == id).collect()
    } else {
        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::<()>::err(
                "workers probe",
                ApiError::new(
                    ErrorCode::ConfigValidationError,
                    "Specify a worker ID or use --all",
                ),
            ));
        } else {
            println!(
                "{} Specify a worker ID or use {} to probe all workers.",
                StatusIndicator::Info.display(style),
                style.highlight("--all")
            );
        }
        return Ok(());
    };

    if targets.is_empty() {
        if let Some(id) = worker_id {
            if ctx.is_json() {
                let _ = ctx.json(&ApiResponse::<()>::err(
                    "workers probe",
                    ApiError::new(
                        ErrorCode::ConfigInvalidWorker,
                        format!("Worker '{}' not found", id),
                    ),
                ));
            } else {
                println!(
                    "{} Worker '{}' not found in configuration.",
                    StatusIndicator::Warning.display(style),
                    style.highlight(&id)
                );
            }
        }
        return Ok(());
    }

    let mut results = Vec::new();

    if !ctx.is_json() {
        println!(
            "Probing {} worker(s)...\n",
            style.highlight(&targets.len().to_string())
        );
    }

    for worker in targets {
        if !ctx.is_json() {
            print!(
                "  {} {}@{}... ",
                style.highlight(worker.id.as_str()),
                style.muted(&worker.user),
                style.info(&worker.host)
            );
        }

        let ssh_options = SshOptions::default();
        let mut client = SshClient::new(worker.clone(), ssh_options.clone());

        match client.connect().await {
            Ok(()) => {
                let start = std::time::Instant::now();
                match client.health_check().await {
                    Ok(true) => {
                        let latency = start.elapsed().as_millis() as u64;
                        if ctx.is_json() {
                            results.push(WorkerProbeResult {
                                id: worker.id.as_str().to_string(),
                                host: worker.host.clone(),
                                status: "ok".to_string(),
                                latency_ms: Some(latency),
                                error: None,
                            });
                        } else {
                            println!(
                                "{} ({}ms)",
                                StatusIndicator::Success.with_label(style, "OK"),
                                style.muted(&latency.to_string())
                            );
                        }
                    }
                    Ok(false) => {
                        if ctx.is_json() {
                            results.push(WorkerProbeResult {
                                id: worker.id.as_str().to_string(),
                                host: worker.host.clone(),
                                status: "unhealthy".to_string(),
                                latency_ms: None,
                                error: Some("Health check failed".to_string()),
                            });
                        } else {
                            println!(
                                "{}",
                                StatusIndicator::Error.with_label(style, "Health check failed")
                            );
                        }
                    }
                    Err(e) => {
                        let ssh_error = classify_ssh_error(worker, &e, ssh_options.connect_timeout);
                        let report = format_ssh_report(ssh_error);
                        if ctx.is_json() {
                            results.push(WorkerProbeResult {
                                id: worker.id.as_str().to_string(),
                                host: worker.host.clone(),
                                status: "error".to_string(),
                                latency_ms: None,
                                error: Some(report),
                            });
                        } else {
                            println!(
                                "{} Health check failed:\n{}",
                                StatusIndicator::Error.display(style),
                                indent_lines(&report, "    ")
                            );
                        }
                    }
                }
                let _ = client.disconnect().await;
            }
            Err(e) => {
                let ssh_error = classify_ssh_error(worker, &e, ssh_options.connect_timeout);
                let report = format_ssh_report(ssh_error);
                if ctx.is_json() {
                    results.push(WorkerProbeResult {
                        id: worker.id.as_str().to_string(),
                        host: worker.host.clone(),
                        status: "connection_failed".to_string(),
                        latency_ms: None,
                        error: Some(report),
                    });
                } else {
                    println!(
                        "{} Connection failed:\n{}",
                        StatusIndicator::Error.display(style),
                        indent_lines(&report, "    ")
                    );
                }
            }
        }
    }

    if ctx.is_json() {
        let _ = ctx.json(&ApiResponse::ok("workers probe", results));
    }

    Ok(())
}

fn classify_ssh_error(worker: &WorkerConfig, err: &anyhow::Error, timeout: Duration) -> SshError {
    let key_path = ssh_key_path(worker);
    classify_ssh_error_message(
        &worker.host,
        &worker.user,
        key_path,
        &err.to_string(),
        timeout,
    )
}

fn classify_ssh_error_message(
    host: &str,
    user: &str,
    key_path: PathBuf,
    message: &str,
    timeout: Duration,
) -> SshError {
    let message_lower = message.to_lowercase();

    if message_lower.contains("permission denied") || message_lower.contains("publickey") {
        return SshError::PermissionDenied {
            host: host.to_string(),
            user: user.to_string(),
            key_path: key_path.clone(),
        };
    }

    if message_lower.contains("connection refused") {
        return SshError::ConnectionRefused {
            host: host.to_string(),
            user: user.to_string(),
            key_path: key_path.clone(),
        };
    }

    if message_lower.contains("timed out") || message_lower.contains("timeout") {
        return SshError::ConnectionTimeout {
            host: host.to_string(),
            user: user.to_string(),
            key_path: key_path.clone(),
            timeout_secs: timeout.as_secs().max(1),
        };
    }

    if message_lower.contains("host key verification failed")
        || message_lower.contains("known_hosts")
    {
        return SshError::HostKeyVerificationFailed {
            host: host.to_string(),
            user: user.to_string(),
            key_path: key_path.clone(),
        };
    }

    if message_lower.contains("authentication agent")
        || (message_lower.contains("agent") && message_lower.contains("no identities"))
    {
        return SshError::AgentUnavailable {
            host: host.to_string(),
            user: user.to_string(),
            key_path: key_path.clone(),
        };
    }

    SshError::ConnectionFailed {
        host: host.to_string(),
        user: user.to_string(),
        key_path,
        message: message.to_string(),
    }
}

fn ssh_key_path(worker: &WorkerConfig) -> PathBuf {
    ssh_key_path_from_identity(Some(worker.identity_file.as_str()))
}

fn ssh_key_path_from_identity(identity_file: Option<&str>) -> PathBuf {
    let path = identity_file.unwrap_or("~/.ssh/id_rsa");
    PathBuf::from(shellexpand::tilde(path).to_string())
}

fn format_ssh_report(error: SshError) -> String {
    format!("{:?}", miette::Report::new(error))
}

fn indent_lines(text: &str, prefix: &str) -> String {
    let mut out = String::new();
    for (idx, line) in text.lines().enumerate() {
        if idx > 0 {
            out.push('\n');
        }
        out.push_str(prefix);
        out.push_str(line);
    }
    out
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

/// Run worker benchmarks.
pub async fn workers_benchmark(ctx: &OutputContext) -> Result<()> {
    let workers = load_workers_from_config()?;
    let style = ctx.theme();

    if workers.is_empty() {
        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::<Vec<WorkerBenchmarkResult>>::ok(
                "workers benchmark",
                vec![],
            ));
        }
        return Ok(());
    }

    let mut results = Vec::new();

    if !ctx.is_json() {
        println!(
            "Running benchmarks on {} worker(s)...\n",
            style.highlight(&workers.len().to_string())
        );
    }

    for worker in &workers {
        if !ctx.is_json() {
            print!(
                "  {} {}@{}... ",
                style.highlight(worker.id.as_str()),
                style.muted(&worker.user),
                style.info(&worker.host)
            );
        }

        let ssh_options = SshOptions::default();
        let mut client = SshClient::new(worker.clone(), ssh_options.clone());

        match client.connect().await {
            Ok(()) => {
                let bench_id = uuid::Uuid::new_v4();
                let bench_dir = format!("rch_bench_{}", bench_id);

                // Run a simple benchmark: compile a hello world Rust program
                // Uses a unique directory and cleans up afterwards
                let benchmark_cmd = format!(
                    r###"#
                    cd /tmp && \
                    mkdir -p {0} && \
                    cd {0} && \
                    echo 'fn main() {{ println!("hello"); }}' > main.rs && \
                    (time rustc main.rs -o hello) 2>&1 | grep real || echo 'rustc not found'; \
                    cd .. && rm -rf {0}
                "###,
                    bench_dir
                );

                let start = std::time::Instant::now();
                let result = client.execute(&benchmark_cmd).await;
                let duration = start.elapsed();

                match result {
                    Ok(r) if r.success() => {
                        let duration_ms = duration.as_millis() as u64;
                        if ctx.is_json() {
                            results.push(WorkerBenchmarkResult {
                                id: worker.id.as_str().to_string(),
                                host: worker.host.clone(),
                                status: "ok".to_string(),
                                duration_ms: Some(duration_ms),
                                error: None,
                            });
                        } else {
                            println!(
                                "{} {}ms {}",
                                StatusIndicator::Success.display(style),
                                style.highlight(&duration_ms.to_string()),
                                style.muted("total")
                            );
                        }
                    }
                    Ok(r) => {
                        if ctx.is_json() {
                            results.push(WorkerBenchmarkResult {
                                id: worker.id.as_str().to_string(),
                                host: worker.host.clone(),
                                status: "failed".to_string(),
                                duration_ms: None,
                                error: Some(format!("exit code {}", r.exit_code)),
                            });
                        } else {
                            println!(
                                "{} (exit={})",
                                StatusIndicator::Error.with_label(style, "Failed"),
                                style.muted(&r.exit_code.to_string())
                            );
                        }
                    }
                    Err(e) => {
                        let ssh_error = classify_ssh_error(worker, &e, ssh_options.command_timeout);
                        let report = format_ssh_report(ssh_error);
                        if ctx.is_json() {
                            results.push(WorkerBenchmarkResult {
                                id: worker.id.as_str().to_string(),
                                host: worker.host.clone(),
                                status: "error".to_string(),
                                duration_ms: None,
                                error: Some(report),
                            });
                        } else {
                            println!(
                                "{}\n{}",
                                StatusIndicator::Error.display(style),
                                indent_lines(&report, "    ")
                            );
                        }
                    }
                }
                let _ = client.disconnect().await;
            }
            Err(e) => {
                let ssh_error = classify_ssh_error(worker, &e, ssh_options.connect_timeout);
                let report = format_ssh_report(ssh_error);
                if ctx.is_json() {
                    results.push(WorkerBenchmarkResult {
                        id: worker.id.as_str().to_string(),
                        host: worker.host.clone(),
                        status: "connection_failed".to_string(),
                        duration_ms: None,
                        error: Some(report),
                    });
                } else {
                    println!(
                        "{}\n{}",
                        StatusIndicator::Error.with_label(style, "Connection failed:"),
                        indent_lines(&report, "    ")
                    );
                }
            }
        }
    }

    if ctx.is_json() {
        let _ = ctx.json(&ApiResponse::ok("workers benchmark", results));
    } else {
        println!(
            "\n{} For accurate speed scores, use longer benchmark runs.",
            StatusIndicator::Info.display(style)
        );
    }
    Ok(())
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

/// Drain a worker (requires daemon).
pub async fn workers_drain(worker_id: &str, ctx: &OutputContext) -> Result<()> {
    let style = ctx.theme();

    // Check if daemon is running
    if !Path::new(DEFAULT_SOCKET_PATH).exists() {
        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::<()>::err(
                "workers drain",
                ApiError::new(ErrorCode::InternalDaemonNotRunning, "Daemon is not running"),
            ));
        } else {
            println!(
                "{} Daemon is not running. Start it with {}",
                StatusIndicator::Error.display(style),
                style.highlight("rch daemon start")
            );
            println!(
                "\n{} Draining requires the daemon to track worker state.",
                StatusIndicator::Info.display(style)
            );
        }
        return Ok(());
    }

    // Send drain command to daemon
    match send_daemon_command(&format!("POST /workers/{}/drain\n", worker_id)).await {
        Ok(response) => {
            if response.contains("error") || response.contains("Error") {
                if ctx.is_json() {
                    let _ = ctx.json(&ApiResponse::ok(
                        "workers drain",
                        WorkerActionResponse {
                            worker_id: worker_id.to_string(),
                            action: "drain".to_string(),
                            success: false,
                            message: Some(response),
                        },
                    ));
                } else {
                    println!(
                        "{} Failed to drain worker: {}",
                        StatusIndicator::Error.display(style),
                        style.muted(&response)
                    );
                }
            } else if ctx.is_json() {
                let _ = ctx.json(&ApiResponse::ok(
                    "workers drain",
                    WorkerActionResponse {
                        worker_id: worker_id.to_string(),
                        action: "drain".to_string(),
                        success: true,
                        message: Some("Worker is now draining".to_string()),
                    },
                ));
            } else {
                println!(
                    "{} Worker {} is now draining.",
                    StatusIndicator::Success.display(style),
                    style.highlight(worker_id)
                );
                println!(
                    "  {} No new jobs will be sent. Existing jobs will complete.",
                    StatusIndicator::Info.display(style)
                );
            }
        }
        Err(e) => {
            if ctx.is_json() {
                let _ = ctx.json(&ApiResponse::<()>::err(
                    "workers drain",
                    ApiError::new(ErrorCode::InternalStateError, e.to_string()),
                ));
            } else {
                println!(
                    "{} Failed to communicate with daemon: {}",
                    StatusIndicator::Error.display(style),
                    style.muted(&e.to_string())
                );
                println!(
                    "\n{} Drain/enable commands require the daemon to be running.",
                    StatusIndicator::Info.display(style)
                );
            }
        }
    }

    Ok(())
}

/// Enable a worker (requires daemon).
pub async fn workers_enable(worker_id: &str, ctx: &OutputContext) -> Result<()> {
    let style = ctx.theme();

    if !Path::new(DEFAULT_SOCKET_PATH).exists() {
        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::<()>::err(
                "workers enable",
                ApiError::new(ErrorCode::InternalDaemonNotRunning, "Daemon is not running"),
            ));
        } else {
            println!(
                "{} Daemon is not running. Start it with {}",
                StatusIndicator::Error.display(style),
                style.highlight("rch daemon start")
            );
        }
        return Ok(());
    }

    match send_daemon_command(&format!("POST /workers/{}/enable\n", worker_id)).await {
        Ok(response) => {
            if response.contains("error") || response.contains("Error") {
                if ctx.is_json() {
                    let _ = ctx.json(&ApiResponse::ok(
                        "workers enable",
                        WorkerActionResponse {
                            worker_id: worker_id.to_string(),
                            action: "enable".to_string(),
                            success: false,
                            message: Some(response),
                        },
                    ));
                } else {
                    println!(
                        "{} Failed to enable worker: {}",
                        StatusIndicator::Error.display(style),
                        style.muted(&response)
                    );
                }
            } else if ctx.is_json() {
                let _ = ctx.json(&ApiResponse::ok(
                    "workers enable",
                    WorkerActionResponse {
                        worker_id: worker_id.to_string(),
                        action: "enable".to_string(),
                        success: true,
                        message: Some("Worker is now enabled".to_string()),
                    },
                ));
            } else {
                println!(
                    "{} Worker {} is now enabled.",
                    StatusIndicator::Success.display(style),
                    style.highlight(worker_id)
                );
            }
        }
        Err(e) => {
            if ctx.is_json() {
                let _ = ctx.json(&ApiResponse::<()>::err(
                    "workers enable",
                    ApiError::new(ErrorCode::InternalStateError, e.to_string()),
                ));
            } else {
                println!(
                    "{} Failed to communicate with daemon: {}",
                    StatusIndicator::Error.display(style),
                    style.muted(&e.to_string())
                );
            }
        }
    }

    Ok(())
}

/// Disable a worker (requires daemon).
pub async fn workers_disable(
    worker_id: &str,
    reason: Option<String>,
    drain_first: bool,
    ctx: &OutputContext,
) -> Result<()> {
    let style = ctx.theme();

    if !Path::new(DEFAULT_SOCKET_PATH).exists() {
        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::<()>::err(
                "workers disable",
                ApiError::new(ErrorCode::InternalDaemonNotRunning, "Daemon is not running"),
            ));
        } else {
            println!(
                "{} Daemon is not running. Start it with {}",
                StatusIndicator::Error.display(style),
                style.highlight("rch daemon start")
            );
        }
        return Ok(());
    }

    // Build the request URL with optional reason and drain flag
    let mut url = format!("POST /workers/{}/disable", worker_id);
    let mut query_parts = Vec::new();
    if let Some(ref r) = reason {
        query_parts.push(format!("reason={}", urlencoding_encode(r)));
    }
    if drain_first {
        query_parts.push("drain=true".to_string());
    }
    if !query_parts.is_empty() {
        url = format!("{}?{}", url, query_parts.join("&"));
    }
    url.push('\n');

    match send_daemon_command(&url).await {
        Ok(response) => {
            if response.contains("error") || response.contains("Error") {
                if ctx.is_json() {
                    let _ = ctx.json(&ApiResponse::ok(
                        "workers disable",
                        WorkerActionResponse {
                            worker_id: worker_id.to_string(),
                            action: "disable".to_string(),
                            success: false,
                            message: Some(response),
                        },
                    ));
                } else {
                    println!(
                        "{} Failed to disable worker: {}",
                        StatusIndicator::Error.display(style),
                        style.muted(&response)
                    );
                }
            } else if ctx.is_json() {
                let _ = ctx.json(&ApiResponse::ok(
                    "workers disable",
                    WorkerActionResponse {
                        worker_id: worker_id.to_string(),
                        action: "disable".to_string(),
                        success: true,
                        message: Some(if drain_first {
                            "Worker is draining before disable".to_string()
                        } else {
                            "Worker is now disabled".to_string()
                        }),
                    },
                ));
            } else if drain_first {
                println!(
                    "{} Worker {} is draining before disable.",
                    StatusIndicator::Success.display(style),
                    style.highlight(worker_id)
                );
                println!(
                    "  {} Existing jobs will complete, then worker will be disabled.",
                    StatusIndicator::Info.display(style)
                );
                if let Some(ref r) = reason {
                    println!(
                        "  {} Reason: {}",
                        StatusIndicator::Info.display(style),
                        style.muted(r)
                    );
                }
            } else {
                println!(
                    "{} Worker {} is now disabled.",
                    StatusIndicator::Success.display(style),
                    style.highlight(worker_id)
                );
                println!(
                    "  {} No jobs will be sent to this worker.",
                    StatusIndicator::Info.display(style)
                );
                if let Some(ref r) = reason {
                    println!(
                        "  {} Reason: {}",
                        StatusIndicator::Info.display(style),
                        style.muted(r)
                    );
                }
            }
        }
        Err(e) => {
            if ctx.is_json() {
                let _ = ctx.json(&ApiResponse::<()>::err(
                    "workers disable",
                    ApiError::new(ErrorCode::InternalStateError, e.to_string()),
                ));
            } else {
                println!(
                    "{} Failed to communicate with daemon: {}",
                    StatusIndicator::Error.display(style),
                    style.muted(&e.to_string())
                );
            }
        }
    }

    Ok(())
}

/// Deploy rch-wkr binary to workers.
///
/// Finds the local rch-wkr binary, checks version on remote workers,
/// and deploys if needed using scp. Falls back to user directories
/// if /usr/local/bin requires sudo.
pub async fn workers_deploy_binary(
    worker_id: Option<String>,
    all: bool,
    force: bool,
    dry_run: bool,
    ctx: &OutputContext,
) -> Result<()> {
    let style = ctx.theme();

    if worker_id.is_none() && !all {
        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::<()>::err(
                "workers deploy-binary",
                ApiError::new(
                    ErrorCode::ConfigValidationError,
                    "Specify either a worker ID or --all",
                ),
            ));
        } else {
            println!(
                "{} Specify either {} or {}",
                StatusIndicator::Error.display(style),
                style.highlight("<worker-id>"),
                style.highlight("--all")
            );
        }
        return Ok(());
    }

    // Load workers configuration
    let workers = load_workers_from_config()?;
    if workers.is_empty() {
        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::<()>::err(
                "workers deploy-binary",
                ApiError::new(
                    ErrorCode::ConfigNotFound,
                    "No workers configured. Run 'rch workers discover --add' first.",
                ),
            ));
        } else {
            println!(
                "{} No workers configured.",
                StatusIndicator::Error.display(style)
            );
            println!(
                "  {} Run: rch workers discover --add --yes",
                style.muted("→")
            );
        }
        return Ok(());
    }

    // Filter to target workers
    let target_workers: Vec<&WorkerConfig> = if all {
        workers.iter().collect()
    } else if let Some(ref id) = worker_id {
        workers.iter().filter(|w| w.id.0 == *id).collect()
    } else {
        vec![]
    };

    if target_workers.is_empty() {
        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::<()>::err(
                "workers deploy-binary",
                ApiError::new(
                    ErrorCode::ConfigInvalidWorker,
                    format!("Worker '{}' not found", worker_id.unwrap_or_default()),
                ),
            ));
        } else {
            println!(
                "{} Worker not found: {}",
                StatusIndicator::Error.display(style),
                worker_id.unwrap_or_default()
            );
        }
        return Ok(());
    }

    // Find local rch-wkr binary
    let local_binary = find_local_binary("rch-wkr")?;
    let local_version = get_binary_version(&local_binary).await?;

    if !ctx.is_json() {
        println!("{}", style.format_header("Deploy rch-wkr Binary"));
        println!();
        println!(
            "  {} Local binary: {}",
            style.muted("→"),
            style.value(&local_binary.display().to_string())
        );
        println!(
            "  {} Local version: {}",
            style.muted("→"),
            style.value(&local_version)
        );
        println!();
    }

    // Deploy to each target worker
    let mut results: Vec<DeployResult> = Vec::new();

    for worker in &target_workers {
        let result =
            deploy_binary_to_worker(worker, &local_binary, &local_version, force, dry_run, ctx)
                .await;
        results.push(result);
    }

    // JSON output
    if ctx.is_json() {
        let _ = ctx.json(&ApiResponse::ok(
            "workers deploy-binary",
            serde_json::json!({
                "local_binary": local_binary.display().to_string(),
                "local_version": local_version,
                "results": results,
            }),
        ));
    } else {
        // Summary
        let success_count = results.iter().filter(|r| r.success).count();
        let skip_count = results.iter().filter(|r| r.skipped).count();
        let fail_count = results.len() - success_count - skip_count;

        println!();
        println!(
            "  {} Deployed: {}, Skipped: {}, Failed: {}",
            style.muted("Summary:"),
            style.success(&success_count.to_string()),
            style.muted(&skip_count.to_string()),
            if fail_count > 0 {
                style.error(&fail_count.to_string())
            } else {
                style.muted("0")
            }
        );
    }

    Ok(())
}

/// Find a local binary in common locations.
fn find_local_binary(name: &str) -> Result<PathBuf> {
    let locations = [
        // Target directory (development)
        std::env::current_dir()
            .ok()
            .map(|p| p.join("target/release").join(name)),
        std::env::current_dir()
            .ok()
            .map(|p| p.join("target/debug").join(name)),
        // Cargo install location
        dirs::home_dir().map(|h| h.join(".cargo/bin").join(name)),
        // User local bin
        dirs::home_dir().map(|h| h.join(".local/bin").join(name)),
        // System paths
        Some(PathBuf::from("/usr/local/bin").join(name)),
        Some(PathBuf::from("/usr/bin").join(name)),
    ];

    for loc in locations.into_iter().flatten() {
        if loc.exists() && loc.is_file() {
            return Ok(loc);
        }
    }

    bail!(
        "Could not find {} binary. Build with 'cargo build --release -p rch-wkr'",
        name
    )
}

/// Get version string from a local binary.
async fn get_binary_version(path: &Path) -> Result<String> {
    let output = Command::new(path)
        .arg("--version")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .context("Failed to execute binary for version check")?;

    if !output.status.success() {
        bail!("Binary returned non-zero exit code for --version");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout.trim().to_string())
}

/// Deploy binary to a single worker.
async fn deploy_binary_to_worker(
    worker: &WorkerConfig,
    local_binary: &Path,
    local_version: &str,
    force: bool,
    dry_run: bool,
    ctx: &OutputContext,
) -> DeployResult {
    let style = ctx.theme();
    let worker_id = &worker.id.0;

    if !ctx.is_json() {
        print!(
            "  {} {}... ",
            StatusIndicator::Info.display(style),
            style.highlight(worker_id)
        );
        use std::io::Write;
        let _ = std::io::stdout().flush();
    }

    // Check remote version
    let remote_version = get_remote_version(worker).await;

    // Decide whether to deploy
    match &remote_version {
        Ok(ver) if ver == local_version && !force => {
            if !ctx.is_json() {
                println!("{} (already at {})", style.muted("skipped"), local_version);
            }
            return DeployResult {
                worker_id: worker_id.clone(),
                success: true,
                skipped: true,
                remote_version: Some(ver.clone()),
                install_path: None,
                error: None,
            };
        }
        Ok(ver) => {
            debug!(
                "Remote version {} differs from local {}",
                ver, local_version
            );
        }
        Err(_) => {
            debug!("rch-wkr not installed on {}", worker_id);
        }
    };

    if dry_run {
        if !ctx.is_json() {
            println!(
                "{} (would deploy {})",
                style.muted("dry-run"),
                local_version
            );
        }
        return DeployResult {
            worker_id: worker_id.clone(),
            success: true,
            skipped: false,
            remote_version: remote_version.ok(),
            install_path: None,
            error: None,
        };
    }

    // Deploy the binary
    match deploy_via_scp(worker, local_binary).await {
        Ok(install_path) => {
            if !ctx.is_json() {
                println!(
                    "{} (installed to {})",
                    StatusIndicator::Success.display(style),
                    install_path
                );
            }
            DeployResult {
                worker_id: worker_id.clone(),
                success: true,
                skipped: false,
                remote_version: Some(local_version.to_string()),
                install_path: Some(install_path),
                error: None,
            }
        }
        Err(e) => {
            if !ctx.is_json() {
                println!("{} ({})", StatusIndicator::Error.display(style), e);
            }
            DeployResult {
                worker_id: worker_id.clone(),
                success: false,
                skipped: false,
                remote_version: remote_version.ok(),
                install_path: None,
                error: Some(e.to_string()),
            }
        }
    }
}

/// Get rch-wkr version from remote worker.
async fn get_remote_version(worker: &WorkerConfig) -> Result<String> {
    let mut cmd = Command::new("ssh");
    cmd.arg("-o").arg("BatchMode=yes");
    cmd.arg("-o").arg("ConnectTimeout=10");
    cmd.arg("-o").arg("StrictHostKeyChecking=accept-new");
    cmd.arg("-i").arg(&worker.identity_file);
    cmd.arg(format!("{}@{}", worker.user, worker.host));
    cmd.arg("rch-wkr --version 2>/dev/null || ~/.local/bin/rch-wkr --version 2>/dev/null");

    let output = cmd.output().await.context("Failed to SSH to worker")?;

    if !output.status.success() {
        bail!("rch-wkr not found on remote");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout.trim().to_string())
}

/// Deploy binary to worker via scp.
async fn deploy_via_scp(worker: &WorkerConfig, local_binary: &Path) -> Result<String> {
    let target = format!("{}@{}", worker.user, worker.host);
    let remote_dir = ".local/bin";
    let remote_path = format!("{}/rch-wkr", remote_dir);

    // Ensure directory exists
    let mut mkdir_cmd = Command::new("ssh");
    mkdir_cmd
        .arg("-o")
        .arg("BatchMode=yes")
        .arg("-o")
        .arg("ConnectTimeout=10")
        .arg("-i")
        .arg(&worker.identity_file)
        .arg(&target)
        .arg(format!("mkdir -p ~/{}", remote_dir));

    let mkdir_output = mkdir_cmd
        .output()
        .await
        .context("Failed to create remote directory")?;
    if !mkdir_output.status.success() {
        bail!(
            "Failed to create remote directory: {}",
            String::from_utf8_lossy(&mkdir_output.stderr)
        );
    }

    // Copy binary
    let mut scp_cmd = Command::new("scp");
    scp_cmd
        .arg("-o")
        .arg("BatchMode=yes")
        .arg("-o")
        .arg("ConnectTimeout=30")
        .arg("-i")
        .arg(&worker.identity_file)
        .arg(local_binary)
        .arg(format!("{}:~/{}", target, remote_path));

    let scp_output = scp_cmd.output().await.context("Failed to scp binary")?;
    if !scp_output.status.success() {
        bail!(
            "scp failed: {}",
            String::from_utf8_lossy(&scp_output.stderr)
        );
    }

    // Make executable
    let mut chmod_cmd = Command::new("ssh");
    chmod_cmd
        .arg("-o")
        .arg("BatchMode=yes")
        .arg("-i")
        .arg(&worker.identity_file)
        .arg(&target)
        .arg(format!("chmod +x ~/{}", remote_path));

    let chmod_output = chmod_cmd.output().await.context("Failed to chmod binary")?;
    if !chmod_output.status.success() {
        bail!(
            "chmod failed: {}",
            String::from_utf8_lossy(&chmod_output.stderr)
        );
    }

    // Verify installation
    let mut verify_cmd = Command::new("ssh");
    verify_cmd
        .arg("-o")
        .arg("BatchMode=yes")
        .arg("-i")
        .arg(&worker.identity_file)
        .arg(&target)
        .arg(format!("~/{} health", remote_path));

    let verify_output = verify_cmd
        .output()
        .await
        .context("Failed to verify installation")?;
    if !verify_output.status.success() {
        bail!(
            "Health check failed: {}",
            String::from_utf8_lossy(&verify_output.stderr)
        );
    }

    Ok(format!("~/{}", remote_path))
}

/// Result of deploying to a single worker.
#[derive(Debug, Clone, Serialize)]
struct DeployResult {
    worker_id: String,
    success: bool,
    skipped: bool,
    remote_version: Option<String>,
    install_path: Option<String>,
    error: Option<String>,
}

/// Synchronize Rust toolchain to workers.
///
/// Detects the project's required toolchain from rust-toolchain.toml,
/// checks each worker's installed toolchains, and installs if missing.
pub async fn workers_sync_toolchain(
    worker_id: Option<String>,
    all: bool,
    dry_run: bool,
    ctx: &OutputContext,
) -> Result<()> {
    let style = ctx.theme();

    if worker_id.is_none() && !all {
        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::<()>::err(
                "workers sync-toolchain",
                ApiError::new(
                    ErrorCode::ConfigValidationError,
                    "Specify either a worker ID or --all",
                ),
            ));
        } else {
            println!(
                "{} Specify either {} or {}",
                StatusIndicator::Error.display(style),
                style.highlight("<worker-id>"),
                style.highlight("--all")
            );
        }
        return Ok(());
    }

    // Detect project toolchain
    let toolchain = detect_project_toolchain()?;

    // Load workers configuration
    let workers = load_workers_from_config()?;
    if workers.is_empty() {
        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::<()>::err(
                "workers sync-toolchain",
                ApiError::new(ErrorCode::ConfigNotFound, "No workers configured"),
            ));
        } else {
            println!(
                "{} No workers configured.",
                StatusIndicator::Error.display(style)
            );
        }
        return Ok(());
    }

    // Filter to target workers
    let target_workers: Vec<&WorkerConfig> = if all {
        workers.iter().collect()
    } else if let Some(ref id) = worker_id {
        workers.iter().filter(|w| w.id.0 == *id).collect()
    } else {
        vec![]
    };

    if target_workers.is_empty() {
        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::<()>::err(
                "workers sync-toolchain",
                ApiError::new(
                    ErrorCode::ConfigInvalidWorker,
                    format!("Worker '{}' not found", worker_id.unwrap_or_default()),
                ),
            ));
        } else {
            println!(
                "{} Worker not found: {}",
                StatusIndicator::Error.display(style),
                worker_id.unwrap_or_default()
            );
        }
        return Ok(());
    }

    if !ctx.is_json() {
        println!("{}", style.format_header("Sync Rust Toolchain"));
        println!();
        println!(
            "  {} Required toolchain: {}",
            style.muted("→"),
            style.highlight(&toolchain)
        );
        if dry_run {
            println!(
                "  {} {}",
                style.muted("→"),
                style.warning("DRY RUN - no changes will be made")
            );
        }
        println!();
    }

    // Sync to each target worker
    let mut results: Vec<ToolchainSyncResult> = Vec::new();

    for worker in &target_workers {
        let result = sync_toolchain_to_worker(worker, &toolchain, dry_run, ctx).await;
        results.push(result);
    }

    // JSON output
    if ctx.is_json() {
        let _ = ctx.json(&ApiResponse::ok(
            "workers sync-toolchain",
            serde_json::json!({
                "toolchain": toolchain,
                "results": results,
            }),
        ));
    } else {
        // Summary
        let success_count = results.iter().filter(|r| r.success).count();
        let already_count = results.iter().filter(|r| r.already_installed).count();
        let fail_count = results.len() - success_count;

        println!();
        println!(
            "  {} Installed: {}, Already present: {}, Failed: {}",
            style.muted("Summary:"),
            style.success(&(success_count - already_count).to_string()),
            style.muted(&already_count.to_string()),
            if fail_count > 0 {
                style.error(&fail_count.to_string())
            } else {
                style.muted("0")
            }
        );
    }

    Ok(())
}

/// Complete worker setup: deploy binary and sync toolchain.
///
/// This is the recommended command for setting up new workers.
/// It combines `rch workers deploy-binary` and `rch workers sync-toolchain`.
pub async fn workers_setup(
    worker_id: Option<String>,
    all: bool,
    dry_run: bool,
    skip_binary: bool,
    skip_toolchain: bool,
    ctx: &OutputContext,
) -> Result<()> {
    let style = ctx.theme();

    if worker_id.is_none() && !all {
        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::<()>::err(
                "workers setup",
                ApiError::new(
                    ErrorCode::ConfigValidationError,
                    "Specify either a worker ID or --all",
                ),
            ));
        } else {
            println!(
                "{} Specify either {} or {}",
                StatusIndicator::Error.display(style),
                style.highlight("<worker-id>"),
                style.highlight("--all")
            );
        }
        return Ok(());
    }

    // Load workers configuration
    let workers = load_workers_from_config()?;
    if workers.is_empty() {
        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::<()>::err(
                "workers setup",
                ApiError::new(ErrorCode::ConfigNotFound, "No workers configured"),
            ));
        } else {
            println!(
                "{} No workers configured. Run {}",
                StatusIndicator::Error.display(style),
                style.highlight("rch workers discover --add")
            );
        }
        return Ok(());
    }

    // Filter to target workers
    let target_workers: Vec<&WorkerConfig> = if all {
        workers.iter().collect()
    } else if let Some(ref id) = worker_id {
        workers.iter().filter(|w| w.id.0 == *id).collect()
    } else {
        vec![]
    };

    if target_workers.is_empty() {
        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::<()>::err(
                "workers setup",
                ApiError::new(
                    ErrorCode::ConfigInvalidWorker,
                    format!("Worker '{}' not found", worker_id.unwrap_or_default()),
                ),
            ));
        } else {
            println!(
                "{} Worker not found: {}",
                StatusIndicator::Error.display(style),
                worker_id.unwrap_or_default()
            );
        }
        return Ok(());
    }

    // Detect project toolchain for sync
    let toolchain = if skip_toolchain {
        None
    } else {
        Some(detect_project_toolchain()?)
    };

    if !ctx.is_json() {
        println!("{}", style.format_header("Worker Setup"));
        println!();
        println!(
            "  {} Workers: {} ({})",
            style.muted("→"),
            target_workers.len(),
            if all {
                "all"
            } else {
                worker_id.as_deref().unwrap_or("?")
            }
        );
        if let Some(ref tc) = toolchain {
            println!("  {} Toolchain: {}", style.muted("→"), style.highlight(tc));
        }
        if dry_run {
            println!(
                "  {} {}",
                style.muted("→"),
                style.warning("DRY RUN - no changes will be made")
            );
        }
        println!();
    }

    // Track overall results
    let mut all_results: Vec<SetupResult> = Vec::new();

    // Setup each worker
    for worker in &target_workers {
        let result = setup_single_worker(
            worker,
            toolchain.as_deref(),
            dry_run,
            skip_binary,
            skip_toolchain,
            ctx,
        )
        .await;
        all_results.push(result);
    }

    // JSON output
    if ctx.is_json() {
        let _ = ctx.json(&ApiResponse::ok(
            "workers setup",
            serde_json::json!({
                "toolchain": toolchain,
                "results": all_results,
            }),
        ));
    } else {
        // Summary
        println!();
        let success_count = all_results.iter().filter(|r| r.success).count();
        let fail_count = all_results.len() - success_count;

        println!(
            "  {} Successful: {}, Failed: {}",
            style.muted("Summary:"),
            style.success(&success_count.to_string()),
            if fail_count > 0 {
                style.error(&fail_count.to_string())
            } else {
                style.muted("0")
            }
        );
    }

    Ok(())
}

/// Result of setting up a single worker.
#[derive(Debug, Clone, Serialize)]
struct SetupResult {
    worker_id: String,
    success: bool,
    binary_deployed: bool,
    toolchain_synced: bool,
    errors: Vec<String>,
}

/// Setup a single worker: deploy binary and sync toolchain.
async fn setup_single_worker(
    worker: &WorkerConfig,
    toolchain: Option<&str>,
    dry_run: bool,
    skip_binary: bool,
    skip_toolchain: bool,
    ctx: &OutputContext,
) -> SetupResult {
    let style = ctx.theme();
    let worker_id = &worker.id.0;

    if !ctx.is_json() {
        println!(
            "  {} Setting up {}...",
            StatusIndicator::Info.display(style),
            style.highlight(worker_id)
        );
    }

    let mut result = SetupResult {
        worker_id: worker_id.clone(),
        success: true,
        binary_deployed: false,
        toolchain_synced: false,
        errors: Vec::new(),
    };

    // Step 1: Deploy binary
    if !skip_binary {
        if !ctx.is_json() {
            print!("      {} Binary: ", style.muted("→"));
            use std::io::Write;
            let _ = std::io::stdout().flush();
        }

        // Find local binary and get version
        let binary_result: Result<bool> = async {
            let local_binary = find_local_binary("rch-wkr")?;
            let local_version = get_binary_version(&local_binary).await?;

            // Check remote version
            let remote_version = get_remote_version(worker).await.ok();

            // Skip if versions match
            if remote_version.as_ref() == Some(&local_version) {
                return Ok(false); // No deployment needed
            }

            if dry_run {
                return Ok(true); // Would deploy (for dry-run reporting)
            }

            // Deploy the binary
            deploy_via_scp(worker, &local_binary).await?;
            Ok(true)
        }
        .await;

        match binary_result {
            Ok(true) if dry_run => {
                if !ctx.is_json() {
                    println!("{}", style.muted("would deploy"));
                }
            }
            Ok(true) => {
                result.binary_deployed = true;
                if !ctx.is_json() {
                    println!("{}", style.success("deployed"));
                }
            }
            Ok(false) => {
                if !ctx.is_json() {
                    println!("{}", style.muted("already up to date"));
                }
            }
            Err(e) => {
                result.success = false;
                result.errors.push(format!("Binary deployment: {}", e));
                if !ctx.is_json() {
                    println!("{} ({})", style.error("FAILED"), e);
                }
            }
        }
    }

    // Step 2: Sync toolchain
    if !skip_toolchain && let Some(tc) = toolchain {
        if !ctx.is_json() {
            print!("      {} Toolchain: ", style.muted("→"));
            use std::io::Write;
            let _ = std::io::stdout().flush();
        }

        if dry_run {
            // Check if already installed for dry-run reporting
            match check_remote_toolchain(worker, tc).await {
                Ok(true) => {
                    if !ctx.is_json() {
                        println!("{}", style.muted("already installed"));
                    }
                    result.toolchain_synced = true;
                }
                Ok(false) => {
                    if !ctx.is_json() {
                        println!("{}", style.muted("would install"));
                    }
                }
                Err(e) => {
                    if !ctx.is_json() {
                        println!("{} ({})", style.warning("check failed"), e);
                    }
                }
            }
        } else {
            // Check and install
            match check_remote_toolchain(worker, tc).await {
                Ok(true) => {
                    result.toolchain_synced = true;
                    if !ctx.is_json() {
                        println!("{}", style.muted("already installed"));
                    }
                }
                Ok(false) => {
                    // Install
                    match install_remote_toolchain(worker, tc).await {
                        Ok(()) => {
                            result.toolchain_synced = true;
                            if !ctx.is_json() {
                                println!("{}", style.success("installed"));
                            }
                        }
                        Err(e) => {
                            result.success = false;
                            result.errors.push(format!("Toolchain install: {}", e));
                            if !ctx.is_json() {
                                println!("{} ({})", style.error("FAILED"), e);
                            }
                        }
                    }
                }
                Err(e) => {
                    result.success = false;
                    result.errors.push(format!("Toolchain check: {}", e));
                    if !ctx.is_json() {
                        println!("{} ({})", style.error("FAILED"), e);
                    }
                }
            }
        }
    }

    // Step 3: Verify worker health (quick SSH ping)
    if !dry_run && result.success {
        if !ctx.is_json() {
            print!("      {} Health: ", style.muted("→"));
            use std::io::Write;
            let _ = std::io::stdout().flush();
        }

        match verify_worker_health(worker).await {
            Ok(true) => {
                if !ctx.is_json() {
                    println!("{}", style.success("OK"));
                }
            }
            Ok(false) => {
                if !ctx.is_json() {
                    println!("{}", style.warning("degraded"));
                }
            }
            Err(e) => {
                result.errors.push(format!("Health check: {}", e));
                if !ctx.is_json() {
                    println!("{} ({})", style.error("FAILED"), e);
                }
            }
        }
    }

    result
}

/// Quick health check: verify SSH works and rch-wkr responds.
async fn verify_worker_health(worker: &WorkerConfig) -> Result<bool> {
    let mut cmd = Command::new("ssh");
    cmd.arg("-o").arg("BatchMode=yes");
    cmd.arg("-o").arg("ConnectTimeout=10");
    cmd.arg("-o").arg("StrictHostKeyChecking=accept-new");
    cmd.arg("-i").arg(&worker.identity_file);
    cmd.arg(format!("{}@{}", worker.user, worker.host));
    cmd.arg("rch-wkr capabilities >/dev/null 2>&1 && echo OK || echo DEGRADED");

    let output = cmd.output().await.context("Health check failed")?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();

    Ok(stdout == "OK")
}

/// Detect the project's required toolchain from rust-toolchain.toml or rust-toolchain.
fn detect_project_toolchain() -> Result<String> {
    use std::fs;

    // Check for rust-toolchain.toml first
    let toml_path = std::env::current_dir()?.join("rust-toolchain.toml");
    if toml_path.exists() {
        let content = fs::read_to_string(&toml_path)?;
        // Parse TOML to find channel
        // Format: [toolchain]\nchannel = "nightly-2025-01-01"
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with("channel")
                && let Some(value) = line.split('=').nth(1)
            {
                let channel = value.trim().trim_matches('"').trim_matches('\'');
                return Ok(channel.to_string());
            }
        }
    }

    // Check for rust-toolchain (plain text)
    let plain_path = std::env::current_dir()?.join("rust-toolchain");
    if plain_path.exists() {
        let content = fs::read_to_string(&plain_path)?;
        return Ok(content.trim().to_string());
    }

    // Default to stable if no toolchain file
    Ok("stable".to_string())
}

/// Sync toolchain to a single worker.
async fn sync_toolchain_to_worker(
    worker: &WorkerConfig,
    toolchain: &str,
    dry_run: bool,
    ctx: &OutputContext,
) -> ToolchainSyncResult {
    let style = ctx.theme();
    let worker_id = &worker.id.0;

    if !ctx.is_json() {
        print!(
            "  {} {}... ",
            StatusIndicator::Info.display(style),
            style.highlight(worker_id)
        );
        use std::io::Write;
        let _ = std::io::stdout().flush();
    }

    // Check if toolchain is already installed
    match check_remote_toolchain(worker, toolchain).await {
        Ok(true) => {
            if !ctx.is_json() {
                println!("{} (already installed)", style.muted("skipped"));
            }
            return ToolchainSyncResult {
                worker_id: worker_id.clone(),
                success: true,
                already_installed: true,
                installed_toolchain: Some(toolchain.to_string()),
                error: None,
            };
        }
        Ok(false) => {
            // Need to install
        }
        Err(e) => {
            if !ctx.is_json() {
                println!("{} ({})", style.error("FAILED"), e);
            }
            return ToolchainSyncResult {
                worker_id: worker_id.clone(),
                success: false,
                already_installed: false,
                installed_toolchain: None,
                error: Some(e.to_string()),
            };
        }
    }

    if dry_run {
        if !ctx.is_json() {
            println!("{} (would install {})", style.muted("dry-run"), toolchain);
        }
        return ToolchainSyncResult {
            worker_id: worker_id.clone(),
            success: true,
            already_installed: false,
            installed_toolchain: None,
            error: None,
        };
    }

    // Install the toolchain
    match install_remote_toolchain(worker, toolchain).await {
        Ok(()) => {
            if !ctx.is_json() {
                println!("{} (installed)", StatusIndicator::Success.display(style));
            }
            ToolchainSyncResult {
                worker_id: worker_id.clone(),
                success: true,
                already_installed: false,
                installed_toolchain: Some(toolchain.to_string()),
                error: None,
            }
        }
        Err(e) => {
            if !ctx.is_json() {
                println!("{} ({})", style.error("FAILED"), e);
            }
            ToolchainSyncResult {
                worker_id: worker_id.clone(),
                success: false,
                already_installed: false,
                installed_toolchain: None,
                error: Some(e.to_string()),
            }
        }
    }
}

/// Check if a toolchain is installed on a remote worker.
async fn check_remote_toolchain(worker: &WorkerConfig, toolchain: &str) -> Result<bool> {
    let mut cmd = Command::new("ssh");
    cmd.arg("-o").arg("BatchMode=yes");
    cmd.arg("-o").arg("ConnectTimeout=10");
    cmd.arg("-o").arg("StrictHostKeyChecking=accept-new");
    cmd.arg("-i").arg(&worker.identity_file);
    cmd.arg(format!("{}@{}", worker.user, worker.host));
    cmd.arg(format!(
        "rustup show | grep -q '{}' && echo FOUND || echo NOTFOUND",
        toolchain
    ));

    let output = cmd.output().await.context("Failed to SSH to worker")?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    Ok(stdout.trim() == "FOUND")
}

/// Install a toolchain on a remote worker.
async fn install_remote_toolchain(worker: &WorkerConfig, toolchain: &str) -> Result<()> {
    let mut cmd = Command::new("ssh");
    cmd.arg("-o").arg("BatchMode=yes");
    cmd.arg("-o").arg("ConnectTimeout=60"); // Toolchain install can take a while
    cmd.arg("-i").arg(&worker.identity_file);
    cmd.arg(format!("{}@{}", worker.user, worker.host));
    cmd.arg(format!(
        "rustup install {} && rustup component add rust-src --toolchain {}",
        toolchain, toolchain
    ));

    let output = cmd.output().await.context("Failed to install toolchain")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("rustup install failed: {}", stderr.trim());
    }

    Ok(())
}

/// Result of syncing toolchain to a single worker.
#[derive(Debug, Clone, Serialize)]
struct ToolchainSyncResult {
    worker_id: String,
    success: bool,
    already_installed: bool,
    installed_toolchain: Option<String>,
    error: Option<String>,
}

/// Interactive wizard to add a new worker.
pub async fn workers_init(yes: bool, ctx: &OutputContext) -> Result<()> {
    use dialoguer::{Confirm, Input};
    use tokio::process::Command;

    let style = ctx.theme();

    println!();
    println!("{}", style.format_header("Add New Worker"));
    println!();
    println!(
        "  {} This wizard will guide you through adding a remote compilation worker.",
        style.muted("→")
    );
    println!();

    // Step 1: Get hostname
    println!("{}", style.highlight("Step 1/5: Connection Details"));
    let hostname: String = if yes {
        bail!("--yes flag requires hostname via environment variable RCH_INIT_HOST");
    } else {
        Input::new()
            .with_prompt("Hostname or IP address")
            .interact_text()?
    };

    // Get username with default
    let default_user = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "ubuntu".to_string());
    let username: String = if yes {
        default_user
    } else {
        Input::new()
            .with_prompt("SSH Username")
            .default(default_user)
            .interact_text()?
    };

    // Get SSH key path with default
    let default_key = dirs::home_dir()
        .map(|h| h.join(".ssh/id_rsa").display().to_string())
        .unwrap_or_else(|| "~/.ssh/id_rsa".to_string());
    let identity_file: String = if yes {
        default_key
    } else {
        Input::new()
            .with_prompt("SSH Key Path")
            .default(default_key)
            .interact_text()?
    };

    // Get worker ID with default based on hostname
    let default_id = hostname
        .split('.')
        .next()
        .unwrap_or(&hostname)
        .replace(|c: char| !c.is_alphanumeric() && c != '-', "-");
    let worker_id: String = if yes {
        default_id
    } else {
        Input::new()
            .with_prompt("Worker ID (short name)")
            .default(default_id)
            .interact_text()?
    };
    println!();

    // Step 2: Test SSH connection
    println!("{}", style.highlight("Step 2/5: Testing SSH Connection"));
    print!(
        "  {} Connecting to {}@{}... ",
        StatusIndicator::Info.display(style),
        style.highlight(&username),
        style.highlight(&hostname)
    );

    // Build SSH test command
    let mut cmd = Command::new("ssh");
    cmd.arg("-o").arg("BatchMode=yes");
    cmd.arg("-o").arg("ConnectTimeout=10");
    cmd.arg("-o").arg("StrictHostKeyChecking=accept-new");
    cmd.arg("-i").arg(&identity_file);

    let target = format!("{}@{}", username, hostname);
    cmd.arg(&target);
    cmd.arg("echo 'RCH_TEST_OK'");

    let output = cmd.output().await;
    match output {
        Ok(out) if out.status.success() => {
            println!("{}", style.success("OK"));
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            println!("{}", style.error("FAILED"));
            println!();
            println!(
                "  {} SSH connection failed: {}",
                StatusIndicator::Error.display(style),
                stderr.trim()
            );
            println!();
            println!("  {} Troubleshooting tips:", style.muted("→"));
            println!("      • Check that the hostname is correct");
            println!("      • Verify the SSH key exists and has correct permissions");
            println!(
                "      • Try: ssh -i {} {}@{}",
                identity_file, username, hostname
            );
            return Ok(());
        }
        Err(e) => {
            println!("{}", style.error("FAILED"));
            println!();
            println!(
                "  {} Could not execute SSH: {}",
                StatusIndicator::Error.display(style),
                e
            );
            return Ok(());
        }
    }
    println!();

    // Step 3: Auto-detect system info
    println!(
        "{}",
        style.highlight("Step 3/5: Detecting System Capabilities")
    );

    let mut cmd = Command::new("ssh");
    cmd.arg("-o").arg("BatchMode=yes");
    cmd.arg("-o").arg("ConnectTimeout=10");
    cmd.arg("-i").arg(&identity_file);
    cmd.arg(&target);

    // Probe script to get cores and Rust version
    let probe_script = r#"echo "CORES:$(nproc 2>/dev/null || echo 0)"; \
echo "RUST:$(rustc --version 2>/dev/null || echo none)""#;
    cmd.arg(probe_script);

    let output = cmd.output().await.context("Failed to probe worker")?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    let mut detected_cores: u32 = 8; // default
    let mut rust_version: Option<String> = None;

    for line in stdout.lines() {
        if let Some((key, value)) = line.split_once(':') {
            match key {
                "CORES" => detected_cores = value.trim().parse().unwrap_or(8),
                "RUST" => {
                    let v = value.trim();
                    rust_version = if v == "none" {
                        None
                    } else {
                        Some(v.to_string())
                    };
                }
                _ => {}
            }
        }
    }

    println!(
        "  {} {} CPU cores",
        StatusIndicator::Success.display(style),
        style.highlight(&detected_cores.to_string())
    );
    if let Some(ref rust) = rust_version {
        println!(
            "  {} {}",
            StatusIndicator::Success.display(style),
            style.highlight(rust)
        );
    } else {
        println!(
            "  {} Rust {}",
            StatusIndicator::Warning.display(style),
            style.warning("not installed")
        );
        println!(
            "      {} Will be installed during toolchain sync",
            style.muted("→")
        );
    }
    println!();

    // Step 4: Configure slots and priority
    println!("{}", style.highlight("Step 4/5: Worker Configuration"));

    let total_slots: u32 = if yes {
        detected_cores
    } else {
        let use_recommended = Confirm::new()
            .with_prompt(format!(
                "Use recommended {} slots (based on {} CPU cores)?",
                detected_cores, detected_cores
            ))
            .default(true)
            .interact()
            .unwrap_or(true);

        if use_recommended {
            detected_cores
        } else {
            Input::new()
                .with_prompt("Total slots")
                .default(detected_cores)
                .interact_text()?
        }
    };

    let priority: u32 = if yes {
        100
    } else {
        Input::new()
            .with_prompt("Priority (100 = normal, higher = preferred)")
            .default(100u32)
            .interact_text()?
    };
    println!();

    // Step 5: Save to workers.toml
    println!("{}", style.highlight("Step 5/5: Saving Configuration"));

    let config_dir = directories::ProjectDirs::from("com", "rch", "rch")
        .map(|p| p.config_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from("~/.config/rch"));

    std::fs::create_dir_all(&config_dir)?;
    let workers_path = config_dir.join("workers.toml");

    // Read existing content if any
    let existing_content = std::fs::read_to_string(&workers_path).unwrap_or_default();

    // Check if this worker ID already exists
    if existing_content.contains(&format!("id = \"{}\"", worker_id)) {
        println!(
            "  {} Worker '{}' already exists in {}",
            StatusIndicator::Warning.display(style),
            style.highlight(&worker_id),
            workers_path.display()
        );
        if !yes {
            let overwrite = Confirm::new()
                .with_prompt("Update existing worker configuration?")
                .default(false)
                .interact()
                .unwrap_or(false);
            if !overwrite {
                println!(
                    "  {} Aborted. No changes made.",
                    StatusIndicator::Info.display(style)
                );
                return Ok(());
            }
            // For simplicity, we'll append a new entry. User can manually clean up duplicates.
        }
    }

    // Build new worker entry
    let mut new_entry = String::new();
    if !existing_content.is_empty() && !existing_content.ends_with('\n') {
        new_entry.push('\n');
    }
    if !existing_content.is_empty() {
        new_entry.push('\n');
    }
    new_entry.push_str(&format!(
        "# Added by: rch workers init ({})\n",
        chrono::Local::now().format("%Y-%m-%d %H:%M")
    ));
    new_entry.push_str("[[workers]]\n");
    new_entry.push_str(&format!("id = \"{}\"\n", worker_id));
    new_entry.push_str(&format!("host = \"{}\"\n", hostname));
    new_entry.push_str(&format!("user = \"{}\"\n", username));
    new_entry.push_str(&format!("identity_file = \"{}\"\n", identity_file));
    new_entry.push_str(&format!("total_slots = {}\n", total_slots));
    new_entry.push_str(&format!("priority = {}\n", priority));

    // Append to file
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&workers_path)?;
    std::io::Write::write_all(&mut file, new_entry.as_bytes())?;

    println!(
        "  {} Added worker '{}' to {}",
        StatusIndicator::Success.display(style),
        style.highlight(&worker_id),
        workers_path.display()
    );
    println!();

    // Summary and next steps
    println!("{}", style.format_success("Worker added successfully!"));
    println!();
    println!("  {} Next steps:", style.muted("→"));
    println!(
        "      {} {} {} Deploy rch-wkr binary",
        style.highlight("rch workers deploy-binary"),
        style.muted(&worker_id),
        style.muted("#")
    );
    println!(
        "      {} {} {} Sync Rust toolchain",
        style.highlight("rch workers sync-toolchain"),
        style.muted(&worker_id),
        style.muted("#")
    );
    println!(
        "      {} {} {} Complete setup in one command",
        style.highlight("rch workers setup"),
        style.muted(&worker_id),
        style.muted("#")
    );
    println!();
    println!(
        "  {} Or run '{}' to list all workers.",
        style.muted("→"),
        style.highlight("rch workers list")
    );

    Ok(())
}

/// Discover potential workers from SSH config and shell aliases.
pub async fn workers_discover(
    probe: bool,
    add: bool,
    yes: bool,
    ctx: &OutputContext,
) -> Result<()> {
    let style = ctx.theme();

    // Discover hosts from SSH config and shell aliases
    let hosts = discover_all().context("Failed to discover hosts")?;

    if hosts.is_empty() {
        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::ok(
                "workers discover",
                serde_json::json!({
                    "discovered": [],
                    "message": "No potential workers found"
                }),
            ));
        } else {
            println!(
                "{} No potential workers found in SSH config or shell aliases.",
                StatusIndicator::Warning.display(style)
            );
            println!();
            println!("  {} Checked:", style.muted("→"));
            println!("      ~/.ssh/config");
            println!("      ~/.bashrc, ~/.zshrc");
            println!("      ~/.bash_aliases, ~/.zsh_aliases");
        }
        return Ok(());
    }

    // JSON output
    if ctx.is_json() {
        let hosts_json: Vec<_> = hosts
            .iter()
            .map(|h| {
                serde_json::json!({
                    "alias": h.alias,
                    "hostname": h.hostname,
                    "user": h.user,
                    "identity_file": h.identity_file,
                    "port": h.port,
                    "source": format!("{}", h.source),
                })
            })
            .collect();

        let _ = ctx.json(&ApiResponse::ok(
            "workers discover",
            serde_json::json!({
                "discovered": hosts_json,
                "count": hosts.len(),
            }),
        ));
        return Ok(());
    }

    // Human-readable output
    println!("{}", style.format_header("Discovered Potential Workers"));
    println!();
    println!(
        "  Found {} potential worker(s):",
        style.highlight(&hosts.len().to_string())
    );
    println!();

    for host in &hosts {
        println!(
            "  {} {} {} {}@{}",
            StatusIndicator::Info.display(style),
            style.highlight(&host.alias),
            style.muted("→"),
            host.user,
            host.hostname
        );
        if let Some(ref identity) = host.identity_file {
            // Shorten path for display
            let short_path = identity.replace(
                &dirs::home_dir()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default(),
                "~",
            );
            println!("      {} Key: {}", style.muted("└"), short_path);
        }
        println!("      {} Source: {}", style.muted("└"), host.source);
    }
    println!();

    // Probe hosts if requested
    if probe {
        println!("{}", style.format_header("Probing Hosts"));
        println!();

        for host in &hosts {
            print!(
                "  {} Probing {}... ",
                StatusIndicator::Info.display(style),
                style.highlight(&host.alias)
            );

            // Try to connect and get capabilities
            let result = probe_host(host).await;

            match result {
                Ok(info) => {
                    let status = if info.is_suitable() {
                        style.success("OK")
                    } else {
                        style.warning("BELOW MINIMUM")
                    };
                    println!("{}", status);
                    println!("      {}", info.summary());
                    if !info.is_suitable() {
                        println!(
                            "      {} Minimum: 4 cores, 4GB RAM, 10GB disk",
                            style.muted("⚠")
                        );
                    }
                }
                Err(e) => {
                    println!("{} ({})", style.error("FAILED"), e);
                }
            }
        }
        println!();
    }

    // Add to workers.toml if requested
    if add {
        if !yes {
            println!(
                "{} The --add flag requires --yes for non-interactive mode.",
                StatusIndicator::Warning.display(style)
            );
            println!(
                "  {} Use: rch workers discover --add --yes",
                style.muted("→")
            );
            return Ok(());
        }

        // Write to workers.toml
        let config_dir = directories::ProjectDirs::from("com", "rch", "rch")
            .map(|p| p.config_dir().to_path_buf())
            .unwrap_or_else(|| PathBuf::from("~/.config/rch"));

        std::fs::create_dir_all(&config_dir)?;
        let workers_path = config_dir.join("workers.toml");

        let mut content = String::new();
        content.push_str("# Auto-discovered workers\n");
        content.push_str("# Generated by: rch workers discover --add\n\n");

        for host in &hosts {
            content.push_str("[[workers]]\n");
            content.push_str(&format!("id = \"{}\"\n", host.alias));
            content.push_str(&format!("host = \"{}\"\n", host.hostname));
            content.push_str(&format!("user = \"{}\"\n", host.user));
            if let Some(ref identity) = host.identity_file {
                content.push_str(&format!("identity_file = \"{}\"\n", identity));
            }
            content.push_str("total_slots = 16  # Adjust based on CPU cores\n");
            content.push_str("priority = 100\n");
            content.push('\n');
        }

        std::fs::write(&workers_path, content)?;
        println!(
            "{} Wrote {} worker(s) to {}",
            StatusIndicator::Success.display(style),
            hosts.len(),
            workers_path.display()
        );
    }

    // Hint about next steps
    if !add && !probe {
        println!("  {} Next steps:", style.muted("Hint"));
        println!("      rch workers discover --probe   # Test SSH connectivity");
        println!("      rch workers discover --add --yes  # Add to workers.toml");
    }

    Ok(())
}

/// Probe a discovered host to check connectivity and get comprehensive system info.
async fn probe_host(host: &DiscoveredHost) -> Result<ProbeInfo> {
    use tokio::process::Command;

    // Build SSH command with a comprehensive probe script
    let mut cmd = Command::new("ssh");
    cmd.arg("-o").arg("BatchMode=yes");
    cmd.arg("-o").arg("ConnectTimeout=10");
    cmd.arg("-o").arg("StrictHostKeyChecking=accept-new");

    if let Some(ref identity) = host.identity_file {
        cmd.arg("-i").arg(identity);
    }

    let target = format!("{}@{}", host.user, host.hostname);
    cmd.arg(&target);

    // Single command that gathers all info in a parseable format
    let probe_script = r#"echo "CORES:$(nproc 2>/dev/null || echo 0)"; \
echo "MEM:$(free -g 2>/dev/null | awk '/Mem:/{print $2}' || echo 0)"; \
echo "DISK:$(df -BG /tmp 2>/dev/null | awk 'NR==2{gsub("G","",$4); print $4}' || echo 0)"; \
echo "RUST:$(rustc --version 2>/dev/null || echo none)"; \
echo "ARCH:$(uname -m 2>/dev/null || echo unknown)""#;

    cmd.arg(probe_script);

    let output = cmd.output().await.context("Failed to execute SSH")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let message = if stderr.trim().is_empty() {
            stdout.trim()
        } else {
            stderr.trim()
        };
        let key_path = ssh_key_path_from_identity(host.identity_file.as_deref());
        let ssh_error = classify_ssh_error_message(
            &host.hostname,
            &host.user,
            key_path,
            message,
            Duration::from_secs(10),
        );
        let report = format_ssh_report(ssh_error);
        bail!(report);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut info = ProbeInfo::default();

    // Parse the output
    for line in stdout.lines() {
        if let Some((key, value)) = line.split_once(':') {
            match key {
                "CORES" => info.cores = value.trim().parse().unwrap_or(0),
                "MEM" => info.memory_gb = value.trim().parse().unwrap_or(0),
                "DISK" => info.disk_gb = value.trim().parse().unwrap_or(0),
                "RUST" => {
                    let v = value.trim();
                    info.rust_version = if v == "none" {
                        None
                    } else {
                        Some(v.to_string())
                    };
                }
                "ARCH" => info.arch = value.trim().to_string(),
                _ => {}
            }
        }
    }

    Ok(info)
}

/// Information gathered from probing a host.
#[derive(Default)]
struct ProbeInfo {
    cores: u32,
    memory_gb: u32,
    disk_gb: u32,
    rust_version: Option<String>,
    arch: String,
}

impl ProbeInfo {
    /// Check if host meets minimum requirements for a worker.
    fn is_suitable(&self) -> bool {
        self.cores >= 4 && self.memory_gb >= 4 && self.disk_gb >= 10
    }

    /// Get a short summary string.
    fn summary(&self) -> String {
        let rust = self.rust_version.as_deref().unwrap_or("not installed");
        format!(
            "{} cores, {}GB RAM, {}GB free, {} ({})",
            self.cores, self.memory_gb, self.disk_gb, self.arch, rust
        )
    }
}

// =============================================================================
// Daemon Commands
// =============================================================================

/// Check daemon status.
pub fn daemon_status(ctx: &OutputContext) -> Result<()> {
    let socket_path = Path::new(DEFAULT_SOCKET_PATH);
    let style = ctx.theme();

    let running = socket_path.exists();
    let uptime_seconds = if running {
        std::fs::metadata(socket_path)
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.elapsed().ok())
            .map(|d| d.as_secs())
    } else {
        None
    };

    if ctx.is_json() {
        let _ = ctx.json(&ApiResponse::ok(
            "daemon status",
            DaemonStatusResponse {
                running,
                socket_path: DEFAULT_SOCKET_PATH.to_string(),
                uptime_seconds,
            },
        ));
        return Ok(());
    }

    println!("{}", style.format_header("RCH Daemon Status"));
    println!();

    if running {
        println!(
            "  {} {} {}",
            style.key("Status"),
            style.muted(":"),
            StatusIndicator::Success.with_label(style, "Running")
        );
        println!(
            "  {} {} {}",
            style.key("Socket"),
            style.muted(":"),
            style.value(DEFAULT_SOCKET_PATH)
        );

        if let Some(secs) = uptime_seconds {
            let hours = secs / 3600;
            let mins = (secs % 3600) / 60;
            println!(
                "  {} {} ~{}h {}m",
                style.key("Uptime"),
                style.muted(":"),
                hours,
                mins
            );
        }
    } else {
        println!(
            "  {} {} {}",
            style.key("Status"),
            style.muted(":"),
            StatusIndicator::Error.with_label(style, "Not running")
        );
        println!(
            "  {} {} {} {}",
            style.key("Socket"),
            style.muted(":"),
            style.muted(DEFAULT_SOCKET_PATH),
            style.muted("(not found)")
        );
        println!();
        println!(
            "  {} Start with: {}",
            StatusIndicator::Info.display(style),
            style.highlight("rch daemon start")
        );
    }

    Ok(())
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

/// Start the daemon.
pub async fn daemon_start(ctx: &OutputContext) -> Result<()> {
    let style = ctx.theme();
    let socket_path = Path::new(DEFAULT_SOCKET_PATH);

    if socket_path.exists() {
        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::ok(
                "daemon start",
                DaemonActionResponse {
                    action: "start".to_string(),
                    success: false,
                    socket_path: DEFAULT_SOCKET_PATH.to_string(),
                    message: Some("Daemon already running".to_string()),
                },
            ));
        } else {
            println!(
                "{} Daemon appears to already be running.",
                StatusIndicator::Warning.display(style)
            );
            println!(
                "  {} {} {}",
                style.key("Socket"),
                style.muted(":"),
                style.value(DEFAULT_SOCKET_PATH)
            );
            println!(
                "\n{} Use {} to restart it.",
                StatusIndicator::Info.display(style),
                style.highlight("rch daemon restart")
            );
        }
        return Ok(());
    }

    // Check if rchd binary exists
    let rchd_path = which_rchd();

    if !ctx.is_json() {
        println!("Starting RCH daemon...");
    }
    debug!("Using rchd binary: {:?}", rchd_path);

    // Spawn rchd in background using nohup to detach from terminal
    // This avoids needing unsafe code for setsid()
    let mut cmd = Command::new("nohup");
    cmd.arg(&rchd_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .kill_on_drop(false);

    match cmd.spawn() {
        Ok(_child) => {
            // Wait a moment for the socket to appear
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;

            if socket_path.exists() {
                if ctx.is_json() {
                    let _ = ctx.json(&ApiResponse::ok(
                        "daemon start",
                        DaemonActionResponse {
                            action: "start".to_string(),
                            success: true,
                            socket_path: DEFAULT_SOCKET_PATH.to_string(),
                            message: Some("Daemon started successfully".to_string()),
                        },
                    ));
                } else {
                    println!(
                        "{}",
                        StatusIndicator::Success.with_label(style, "Daemon started successfully.")
                    );
                    println!(
                        "  {} {} {}",
                        style.key("Socket"),
                        style.muted(":"),
                        style.value(DEFAULT_SOCKET_PATH)
                    );
                }
            } else if ctx.is_json() {
                let _ = ctx.json(&ApiResponse::ok(
                    "daemon start",
                    DaemonActionResponse {
                        action: "start".to_string(),
                        success: false,
                        socket_path: DEFAULT_SOCKET_PATH.to_string(),
                        message: Some("Process started but socket not found".to_string()),
                    },
                ));
            } else {
                println!(
                    "{} Daemon process started but socket not found.",
                    StatusIndicator::Warning.display(style)
                );
                println!(
                    "  {} Check logs with: {}",
                    StatusIndicator::Info.display(style),
                    style.highlight("rch daemon logs")
                );
            }
        }
        Err(e) => {
            if ctx.is_json() {
                let _ = ctx.json(&ApiResponse::<()>::err(
                    "daemon start",
                    ApiError::internal(e.to_string()),
                ));
            } else {
                println!(
                    "{} Failed to start daemon: {}",
                    StatusIndicator::Error.display(style),
                    style.muted(&e.to_string())
                );
                println!(
                    "\n{} Make sure {} is in your PATH or installed.",
                    StatusIndicator::Info.display(style),
                    style.highlight("rchd")
                );
            }
        }
    }

    Ok(())
}

/// Stop the daemon.
pub async fn daemon_stop(ctx: &OutputContext) -> Result<()> {
    let style = ctx.theme();
    let socket_path = Path::new(DEFAULT_SOCKET_PATH);

    if !socket_path.exists() {
        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::ok(
                "daemon stop",
                DaemonActionResponse {
                    action: "stop".to_string(),
                    success: true,
                    socket_path: DEFAULT_SOCKET_PATH.to_string(),
                    message: Some("Daemon was not running".to_string()),
                },
            ));
        } else {
            println!(
                "{} Daemon is not running {}",
                StatusIndicator::Pending.display(style),
                style.muted("(socket not found)")
            );
        }
        return Ok(());
    }

    if !ctx.is_json() {
        println!("Stopping RCH daemon...");
    }

    // Try graceful shutdown via socket
    match send_daemon_command("POST /shutdown\n").await {
        Ok(_) => {
            // Wait for socket to disappear
            for _ in 0..10 {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                if !socket_path.exists() {
                    if ctx.is_json() {
                        let _ = ctx.json(&ApiResponse::ok(
                            "daemon stop",
                            DaemonActionResponse {
                                action: "stop".to_string(),
                                success: true,
                                socket_path: DEFAULT_SOCKET_PATH.to_string(),
                                message: Some("Daemon stopped".to_string()),
                            },
                        ));
                    } else {
                        println!(
                            "{}",
                            StatusIndicator::Success.with_label(style, "Daemon stopped.")
                        );
                    }
                    return Ok(());
                }
            }
            if ctx.is_json() {
                let _ = ctx.json(&ApiResponse::ok(
                    "daemon stop",
                    DaemonActionResponse {
                        action: "stop".to_string(),
                        success: false,
                        socket_path: DEFAULT_SOCKET_PATH.to_string(),
                        message: Some("Daemon may still be shutting down".to_string()),
                    },
                ));
            } else {
                println!(
                    "{} Daemon may still be shutting down...",
                    StatusIndicator::Warning.display(style)
                );
            }
        }
        Err(_) => {
            if ctx.is_json() {
                let _ = ctx.json(&ApiResponse::<()>::err(
                    "daemon stop",
                    ApiError::internal("Could not send shutdown command"),
                ));
            } else {
                println!(
                    "{} Could not send shutdown command.",
                    StatusIndicator::Warning.display(style)
                );
                println!("Attempting to find and kill daemon process...");
            }

            // Try pkill
            let output = Command::new("pkill").arg("-f").arg("rchd").output().await;

            match output {
                Ok(o) if o.status.success() => {
                    // Remove stale socket
                    let _ = std::fs::remove_file(socket_path);
                    if ctx.is_json() {
                        let _ = ctx.json(&ApiResponse::ok(
                            "daemon stop",
                            DaemonActionResponse {
                                action: "stop".to_string(),
                                success: true,
                                socket_path: DEFAULT_SOCKET_PATH.to_string(),
                                message: Some("Daemon stopped via pkill".to_string()),
                            },
                        ));
                    } else {
                        println!(
                            "{}",
                            StatusIndicator::Success.with_label(style, "Daemon stopped.")
                        );
                    }
                }
                _ => {
                    if ctx.is_json() {
                        let _ = ctx.json(&ApiResponse::<()>::err(
                            "daemon stop",
                            ApiError::internal("Could not stop daemon"),
                        ));
                    } else {
                        println!(
                            "{} Could not stop daemon. You may need to kill it manually.",
                            StatusIndicator::Error.display(style)
                        );
                        println!(
                            "  {} Try: {}",
                            StatusIndicator::Info.display(style),
                            style.highlight("pkill -9 rchd")
                        );
                    }
                }
            }
        }
    }

    Ok(())
}

/// Restart the daemon.
pub async fn daemon_restart(ctx: &OutputContext) -> Result<()> {
    let style = ctx.theme();
    if !ctx.is_json() {
        println!(
            "{} Restarting RCH daemon...\n",
            StatusIndicator::Info.display(style)
        );
    }
    daemon_stop(ctx).await?;
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    daemon_start(ctx).await?;
    Ok(())
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

/// Reload daemon configuration without restart.
pub async fn daemon_reload(ctx: &OutputContext) -> Result<()> {
    let style = ctx.theme();

    // Check if daemon is running
    if !Path::new(DEFAULT_SOCKET_PATH).exists() {
        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::<()>::err(
                "daemon reload",
                ApiError::new(ErrorCode::InternalDaemonNotRunning, "Daemon is not running"),
            ));
        } else {
            println!(
                "{} Daemon is not running. Start it with {}",
                StatusIndicator::Error.display(style),
                style.highlight("rch daemon start")
            );
        }
        return Ok(());
    }

    if !ctx.is_json() {
        println!(
            "{} Reloading daemon configuration...",
            StatusIndicator::Info.display(style)
        );
    }

    // Send reload command to daemon
    match send_daemon_command("POST /reload\n").await {
        Ok(response) => {
            // Parse response JSON
            if let Some(json) = response.strip_prefix("HTTP/1.1 200 OK\n\n") {
                match serde_json::from_str::<serde_json::Value>(json) {
                    Ok(value) => {
                        let added = value["added"].as_u64().unwrap_or(0) as usize;
                        let updated = value["updated"].as_u64().unwrap_or(0) as usize;
                        let removed = value["removed"].as_u64().unwrap_or(0) as usize;
                        let warnings: Vec<String> = value["warnings"]
                            .as_array()
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|v| v.as_str().map(String::from))
                                    .collect()
                            })
                            .unwrap_or_default();

                        let has_changes = added > 0 || updated > 0 || removed > 0;

                        if ctx.is_json() {
                            let _ = ctx.json(&ApiResponse::ok(
                                "daemon reload",
                                DaemonReloadResponse {
                                    success: true,
                                    added,
                                    updated,
                                    removed,
                                    warnings: warnings.clone(),
                                    message: if has_changes {
                                        Some(format!(
                                            "Configuration reloaded: {} added, {} updated, {} removed",
                                            added, updated, removed
                                        ))
                                    } else {
                                        Some("No configuration changes detected".to_string())
                                    },
                                },
                            ));
                        } else {
                            if has_changes {
                                println!(
                                    "{} Configuration reloaded",
                                    StatusIndicator::Success.display(style)
                                );
                                println!(
                                    "  {} workers added, {} updated, {} removed",
                                    added, updated, removed
                                );
                            } else {
                                println!(
                                    "{} No configuration changes detected",
                                    StatusIndicator::Info.display(style)
                                );
                            }

                            for warning in &warnings {
                                println!("{} {}", StatusIndicator::Warning.display(style), warning);
                            }
                        }
                    }
                    Err(e) => {
                        if ctx.is_json() {
                            let _ = ctx.json(&ApiResponse::<()>::err(
                                "daemon reload",
                                ApiError::internal(format!(
                                    "Failed to parse reload response: {}",
                                    e
                                )),
                            ));
                        } else {
                            println!(
                                "{} Failed to parse reload response: {}",
                                StatusIndicator::Error.display(style),
                                e
                            );
                        }
                    }
                }
            } else if response.contains("HTTP/1.1 500") {
                let error_msg = response.lines().skip(2).collect::<Vec<_>>().join("\n");
                if ctx.is_json() {
                    let _ = ctx.json(&ApiResponse::<()>::err(
                        "daemon reload",
                        ApiError::internal(format!("Reload failed: {}", error_msg)),
                    ));
                } else {
                    println!(
                        "{} Reload failed: {}",
                        StatusIndicator::Error.display(style),
                        error_msg
                    );
                }
            } else if ctx.is_json() {
                let _ = ctx.json(&ApiResponse::<()>::err(
                    "daemon reload",
                    ApiError::internal("Unexpected response from daemon"),
                ));
            } else {
                println!(
                    "{} Unexpected response from daemon",
                    StatusIndicator::Error.display(style)
                );
            }
        }
        Err(e) => {
            if ctx.is_json() {
                let _ = ctx.json(&ApiResponse::<()>::err(
                    "daemon reload",
                    ApiError::internal(format!("Failed to communicate with daemon: {}", e)),
                ));
            } else {
                println!(
                    "{} Failed to communicate with daemon: {}",
                    StatusIndicator::Error.display(style),
                    e
                );
            }
        }
    }

    Ok(())
}

/// Daemon logs response for JSON output.
#[derive(Debug, Clone, Serialize)]
pub struct DaemonLogsResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_file: Option<String>,
    pub lines: Vec<String>,
    pub found: bool,
}

/// Show daemon logs.
pub fn daemon_logs(lines: usize, ctx: &OutputContext) -> Result<()> {
    let style = ctx.theme();

    // Try common log locations
    let log_paths = vec![
        PathBuf::from("/tmp/rchd.log"),
        config_dir()
            .map(|d| d.join("daemon.log"))
            .unwrap_or_default(),
        dirs::cache_dir()
            .map(|d| d.join("rch").join("daemon.log"))
            .unwrap_or_default(),
    ];

    for path in &log_paths {
        if path.exists() {
            let content = std::fs::read_to_string(path)?;
            let all_lines: Vec<&str> = content.lines().collect();
            let start = all_lines.len().saturating_sub(lines);
            let log_lines: Vec<String> = all_lines[start..].iter().map(|s| s.to_string()).collect();

            if ctx.is_json() {
                let _ = ctx.json(&ApiResponse::ok(
                    "daemon logs",
                    DaemonLogsResponse {
                        log_file: Some(path.display().to_string()),
                        lines: log_lines,
                        found: true,
                    },
                ));
            } else {
                println!(
                    "{} {} {}\n",
                    style.key("Log file"),
                    style.muted(":"),
                    style.value(&path.display().to_string())
                );

                for line in &all_lines[start..] {
                    println!("{}", line);
                }
            }

            return Ok(());
        }
    }

    if ctx.is_json() {
        let _ = ctx.json(&ApiResponse::ok(
            "daemon logs",
            DaemonLogsResponse {
                log_file: None,
                lines: vec![],
                found: false,
            },
        ));
    } else {
        println!(
            "{} No log file found.",
            StatusIndicator::Warning.display(style)
        );
        println!("\n{}", style.key("Checked locations:"));
        println!(
            "{}",
            style.muted("# Configuration sources (in priority order):")
        );
        println!("{}", style.muted("# 1. Environment variables (RCH_*)"));
        println!("{}", style.muted("# 2. Project config: .rch/config.toml"));
        if let Some(dir) = config_dir() {
            println!(
                "{}",
                style.muted(&format!(
                    "# 3. User config: {}",
                    dir.join("config.toml").display()
                ))
            );
        }
        println!("{}", style.muted("# 4. Built-in defaults"));
    }

    Ok(())
}

// =============================================================================
// Config Commands
// =============================================================================

/// Show effective configuration.
pub fn config_show(show_sources: bool, ctx: &OutputContext) -> Result<()> {
    let style = ctx.theme();

    // Load config (with source tracking when requested)
    let loaded = if show_sources {
        Some(crate::config::load_config_with_sources()?)
    } else {
        None
    };
    let config = if let Some(loaded) = &loaded {
        loaded.config.clone()
    } else {
        crate::config::load_config()?
    };

    // Build sources list
    let mut sources = vec![
        "Environment variables (RCH_*)".to_string(),
        "Project config: .rch/config.toml".to_string(),
    ];
    if let Some(dir) = config_dir() {
        sources.push(format!(
            "User config: {}",
            dir.join("config.toml").display()
        ));
    }
    sources.push("Built-in defaults".to_string());

    // Determine source for each value
    let value_sources = if show_sources {
        let sources = loaded
            .as_ref()
            .map(|loaded| &loaded.sources)
            .expect("sources available when show_sources is true");
        Some(collect_value_sources(&config, sources))
    } else {
        None
    };

    // JSON output mode
    if ctx.is_json() {
        let response = ConfigShowResponse {
            general: ConfigGeneralSection {
                enabled: config.general.enabled,
                force_local: config.general.force_local,
                force_remote: config.general.force_remote,
                log_level: config.general.log_level.clone(),
                socket_path: config.general.socket_path.clone(),
            },
            compilation: ConfigCompilationSection {
                confidence_threshold: config.compilation.confidence_threshold,
                min_local_time_ms: config.compilation.min_local_time_ms,
            },
            transfer: ConfigTransferSection {
                compression_level: config.transfer.compression_level,
                exclude_patterns: config.transfer.exclude_patterns.clone(),
                remote_base: config.transfer.remote_base.clone(),
                // Transfer optimization (bd-3hho)
                max_transfer_mb: config.transfer.max_transfer_mb,
                max_transfer_time_ms: config.transfer.max_transfer_time_ms,
                bwlimit_kbps: config.transfer.bwlimit_kbps,
                estimated_bandwidth_bps: config.transfer.estimated_bandwidth_bps,
                // Adaptive compression (bd-243w)
                adaptive_compression: config.transfer.adaptive_compression,
                min_compression_level: config.transfer.min_compression_level,
                max_compression_level: config.transfer.max_compression_level,
                // Artifact verification (bd-377q)
                verify_artifacts: config.transfer.verify_artifacts,
                verify_max_size_bytes: config.transfer.verify_max_size_bytes,
            },
            environment: ConfigEnvironmentSection {
                allowlist: config.environment.allowlist.clone(),
            },
            circuit: ConfigCircuitSection {
                failure_threshold: config.circuit.failure_threshold,
                success_threshold: config.circuit.success_threshold,
                error_rate_threshold: config.circuit.error_rate_threshold,
                window_secs: config.circuit.window_secs,
                open_cooldown_secs: config.circuit.open_cooldown_secs,
                half_open_max_probes: config.circuit.half_open_max_probes,
            },
            output: ConfigOutputSection {
                visibility: config.output.visibility,
                first_run_complete: config.output.first_run_complete,
            },
            self_healing: ConfigSelfHealingSection {
                hook_starts_daemon: config.self_healing.hook_starts_daemon,
                daemon_installs_hooks: config.self_healing.daemon_installs_hooks,
                auto_start_cooldown_secs: config.self_healing.auto_start_cooldown_secs,
                auto_start_timeout_secs: config.self_healing.auto_start_timeout_secs,
            },
            sources,
            value_sources,
        };
        let _ = ctx.json(&ApiResponse::ok("config show", response));
        return Ok(());
    }

    println!("{}", style.format_header("Effective RCH Configuration"));
    println!();

    // Helper closure to format value with source
    let format_with_source =
        |key: &str, value: &str, sources: &Option<Vec<ConfigValueSourceInfo>>| -> String {
            if let Some(vs) = sources
                && let Some(s) = vs.iter().find(|v| v.key == key)
            {
                return format!("{} {}", value, style.muted(&format!("# from {}", s.source)));
            }
            value.to_string()
        };

    println!("{}", style.highlight("[general]"));
    println!(
        "  {} = {}",
        style.key("enabled"),
        format_with_source(
            "general.enabled",
            &style.value(&config.general.enabled.to_string()),
            &value_sources
        )
    );
    println!(
        "  {} = {}",
        style.key("force_local"),
        format_with_source(
            "general.force_local",
            &style.value(&config.general.force_local.to_string()),
            &value_sources
        )
    );
    println!(
        "  {} = {}",
        style.key("force_remote"),
        format_with_source(
            "general.force_remote",
            &style.value(&config.general.force_remote.to_string()),
            &value_sources
        )
    );
    println!(
        "  {} = {}",
        style.key("log_level"),
        format_with_source(
            "general.log_level",
            &style.value(&format!("\"{}\"", config.general.log_level)),
            &value_sources
        )
    );
    println!(
        "  {} = {}",
        style.key("socket_path"),
        format_with_source(
            "general.socket_path",
            &style.value(&format!("\"{}\"", config.general.socket_path)),
            &value_sources
        )
    );

    println!("\n{}", style.highlight("[compilation]"));
    println!(
        "  {} = {}",
        style.key("confidence_threshold"),
        format_with_source(
            "compilation.confidence_threshold",
            &style.value(&config.compilation.confidence_threshold.to_string()),
            &value_sources
        )
    );
    println!(
        "  {} = {}",
        style.key("min_local_time_ms"),
        format_with_source(
            "compilation.min_local_time_ms",
            &style.value(&config.compilation.min_local_time_ms.to_string()),
            &value_sources
        )
    );

    println!("\n{}", style.highlight("[transfer]"));
    println!(
        "  {} = {}",
        style.key("compression_level"),
        format_with_source(
            "transfer.compression_level",
            &style.value(&config.transfer.compression_level.to_string()),
            &value_sources
        )
    );
    let exclude_source = source_label("transfer.exclude_patterns", &value_sources);
    if let Some(source) = exclude_source {
        println!(
            "  {} = [ {}",
            style.key("exclude_patterns"),
            style.muted(&format!("# from {}", source))
        );
    } else {
        println!("  {} = [", style.key("exclude_patterns"));
    }
    for pattern in &config.transfer.exclude_patterns {
        println!("    {},", style.value(&format!("\"{}\"", pattern)));
    }
    println!("  ]");
    println!(
        "  {} = {}",
        style.key("remote_base"),
        format_with_source(
            "transfer.remote_base",
            &style.value(&format!("\"{}\"", config.transfer.remote_base)),
            &value_sources
        )
    );

    println!("\n{}", style.highlight("[environment]"));
    let allowlist_source = source_label("environment.allowlist", &value_sources);
    if let Some(source) = allowlist_source {
        println!(
            "  {} = [ {}",
            style.key("allowlist"),
            style.muted(&format!("# from {}", source))
        );
    } else {
        println!("  {} = [", style.key("allowlist"));
    }
    for key in &config.environment.allowlist {
        println!("    {},", style.value(&format!("\"{}\"", key)));
    }
    println!("  ]");

    println!("\n{}", style.highlight("[circuit]"));
    println!(
        "  {} = {}",
        style.key("failure_threshold"),
        format_with_source(
            "circuit.failure_threshold",
            &style.value(&config.circuit.failure_threshold.to_string()),
            &value_sources
        )
    );
    println!(
        "  {} = {}",
        style.key("success_threshold"),
        format_with_source(
            "circuit.success_threshold",
            &style.value(&config.circuit.success_threshold.to_string()),
            &value_sources
        )
    );
    println!(
        "  {} = {}",
        style.key("error_rate_threshold"),
        format_with_source(
            "circuit.error_rate_threshold",
            &style.value(&config.circuit.error_rate_threshold.to_string()),
            &value_sources
        )
    );
    println!(
        "  {} = {}",
        style.key("window_secs"),
        format_with_source(
            "circuit.window_secs",
            &style.value(&config.circuit.window_secs.to_string()),
            &value_sources
        )
    );
    println!(
        "  {} = {}",
        style.key("open_cooldown_secs"),
        format_with_source(
            "circuit.open_cooldown_secs",
            &style.value(&config.circuit.open_cooldown_secs.to_string()),
            &value_sources
        )
    );
    println!(
        "  {} = {}",
        style.key("half_open_max_probes"),
        format_with_source(
            "circuit.half_open_max_probes",
            &style.value(&config.circuit.half_open_max_probes.to_string()),
            &value_sources
        )
    );

    println!("\n{}", style.highlight("[output]"));
    println!(
        "  {} = {}",
        style.key("visibility"),
        format_with_source(
            "output.visibility",
            &style.value(&config.output.visibility.to_string()),
            &value_sources
        )
    );
    println!(
        "  {} = {}",
        style.key("first_run_complete"),
        format_with_source(
            "output.first_run_complete",
            &style.value(&config.output.first_run_complete.to_string()),
            &value_sources
        )
    );

    println!("\n{}", style.highlight("[self_healing]"));
    println!(
        "  {} = {}",
        style.key("hook_starts_daemon"),
        format_with_source(
            "self_healing.hook_starts_daemon",
            &style.value(&config.self_healing.hook_starts_daemon.to_string()),
            &value_sources
        )
    );
    println!(
        "  {} = {}",
        style.key("daemon_installs_hooks"),
        format_with_source(
            "self_healing.daemon_installs_hooks",
            &style.value(&config.self_healing.daemon_installs_hooks.to_string()),
            &value_sources
        )
    );
    println!(
        "  {} = {}",
        style.key("auto_start_cooldown_secs"),
        format_with_source(
            "self_healing.auto_start_cooldown_secs",
            &style.value(&config.self_healing.auto_start_cooldown_secs.to_string()),
            &value_sources
        )
    );
    println!(
        "  {} = {}",
        style.key("auto_start_timeout_secs"),
        format_with_source(
            "self_healing.auto_start_timeout_secs",
            &style.value(&config.self_healing.auto_start_timeout_secs.to_string()),
            &value_sources
        )
    );

    // Show config file locations
    println!(
        "\n{}",
        style.muted("# Configuration sources (in priority order):")
    );
    println!("{}", style.muted("# 1. Environment variables (RCH_*)"));
    println!("{}", style.muted("# 2. Project config: .rch/config.toml"));
    if let Some(dir) = config_dir() {
        println!(
            "{}",
            style.muted(&format!(
                "# 3. User config: {}",
                dir.join("config.toml").display()
            ))
        );
    }
    println!("{}", style.muted("# 4. Built-in defaults"));

    Ok(())
}

/// Determine the source of each configuration value using tracked sources.
fn collect_value_sources(
    config: &RchConfig,
    sources: &crate::config::ConfigSourceMap,
) -> Vec<ConfigValueSourceInfo> {
    let mut values = Vec::new();

    push_value_source(
        &mut values,
        "general.enabled",
        config.general.enabled.to_string(),
        sources,
    );
    push_value_source(
        &mut values,
        "general.force_local",
        config.general.force_local.to_string(),
        sources,
    );
    push_value_source(
        &mut values,
        "general.force_remote",
        config.general.force_remote.to_string(),
        sources,
    );
    push_value_source(
        &mut values,
        "general.log_level",
        config.general.log_level.clone(),
        sources,
    );
    push_value_source(
        &mut values,
        "general.socket_path",
        config.general.socket_path.clone(),
        sources,
    );
    push_value_source(
        &mut values,
        "compilation.confidence_threshold",
        config.compilation.confidence_threshold.to_string(),
        sources,
    );
    push_value_source(
        &mut values,
        "compilation.min_local_time_ms",
        config.compilation.min_local_time_ms.to_string(),
        sources,
    );
    push_value_source(
        &mut values,
        "transfer.compression_level",
        config.transfer.compression_level.to_string(),
        sources,
    );
    push_value_source(
        &mut values,
        "transfer.exclude_patterns",
        format!("{:?}", config.transfer.exclude_patterns),
        sources,
    );
    push_value_source(
        &mut values,
        "environment.allowlist",
        format!("{:?}", config.environment.allowlist),
        sources,
    );
    push_value_source(
        &mut values,
        "circuit.failure_threshold",
        config.circuit.failure_threshold.to_string(),
        sources,
    );
    push_value_source(
        &mut values,
        "circuit.success_threshold",
        config.circuit.success_threshold.to_string(),
        sources,
    );
    push_value_source(
        &mut values,
        "circuit.error_rate_threshold",
        config.circuit.error_rate_threshold.to_string(),
        sources,
    );
    push_value_source(
        &mut values,
        "circuit.window_secs",
        config.circuit.window_secs.to_string(),
        sources,
    );
    push_value_source(
        &mut values,
        "circuit.open_cooldown_secs",
        config.circuit.open_cooldown_secs.to_string(),
        sources,
    );
    push_value_source(
        &mut values,
        "circuit.half_open_max_probes",
        config.circuit.half_open_max_probes.to_string(),
        sources,
    );
    push_value_source(
        &mut values,
        "output.visibility",
        config.output.visibility.to_string(),
        sources,
    );
    push_value_source(
        &mut values,
        "output.first_run_complete",
        config.output.first_run_complete.to_string(),
        sources,
    );
    push_value_source(
        &mut values,
        "self_healing.hook_starts_daemon",
        config.self_healing.hook_starts_daemon.to_string(),
        sources,
    );
    push_value_source(
        &mut values,
        "self_healing.daemon_installs_hooks",
        config.self_healing.daemon_installs_hooks.to_string(),
        sources,
    );
    push_value_source(
        &mut values,
        "self_healing.auto_start_cooldown_secs",
        config.self_healing.auto_start_cooldown_secs.to_string(),
        sources,
    );
    push_value_source(
        &mut values,
        "self_healing.auto_start_timeout_secs",
        config.self_healing.auto_start_timeout_secs.to_string(),
        sources,
    );

    values
}

fn push_value_source(
    values: &mut Vec<ConfigValueSourceInfo>,
    key: &str,
    value: String,
    sources: &crate::config::ConfigSourceMap,
) {
    let source = sources
        .get(key)
        .map(|s| s.label())
        .unwrap_or_else(|| ConfigValueSource::Default.label());
    values.push(ConfigValueSourceInfo {
        key: key.to_string(),
        value,
        source,
    });
}

fn source_label(key: &str, sources: &Option<Vec<ConfigValueSourceInfo>>) -> Option<String> {
    sources.as_ref().and_then(|values| {
        values
            .iter()
            .find(|v| v.key == key)
            .map(|v| v.source.clone())
    })
}

/// Initialize configuration files with optional interactive wizard.
///
/// When `wizard` is true and `use_defaults` is false, prompts the user interactively
/// for configuration values. When `use_defaults` is true, uses sensible defaults
/// without prompting.
pub fn config_init(ctx: &OutputContext, wizard: bool, use_defaults: bool) -> Result<()> {
    use dialoguer::Confirm;

    let style = ctx.theme();
    let config_dir = config_dir().context("Could not determine config directory")?;

    // Create config directory
    std::fs::create_dir_all(&config_dir)
        .with_context(|| format!("Failed to create config directory: {:?}", config_dir))?;

    let config_path = config_dir.join("config.toml");
    let workers_path = config_dir.join("workers.toml");

    let mut created = Vec::new();
    let mut already_existed = Vec::new();

    // Check if files exist and handle accordingly
    let config_exists = config_path.exists();
    let workers_exists = workers_path.exists();

    // If not using wizard, use simple template mode
    if !wizard {
        return config_init_simple(ctx, &config_dir, &config_path, &workers_path);
    }

    // Wizard mode
    if !ctx.is_json() {
        println!("{}", style.format_header("RCH Configuration Wizard"));
        println!();
        if use_defaults {
            println!(
                "  {} Using default values (non-interactive mode)",
                style.muted("→")
            );
        } else {
            println!(
                "  {} Interactive configuration - press Enter to accept defaults",
                style.muted("→")
            );
        }
        println!();
    }

    // Handle existing config.toml
    let should_write_config = if config_exists {
        if use_defaults {
            false // Don't overwrite in non-interactive mode
        } else {
            Confirm::new()
                .with_prompt(format!(
                    "{} already exists. Overwrite?",
                    config_path.display()
                ))
                .default(false)
                .interact()
                .unwrap_or(false)
        }
    } else {
        true
    };

    // Collect config values
    let config_values = if should_write_config {
        Some(collect_config_values(use_defaults, style)?)
    } else {
        None
    };

    // Handle existing workers.toml
    let should_write_workers = if workers_exists {
        if use_defaults {
            false // Don't overwrite in non-interactive mode
        } else {
            Confirm::new()
                .with_prompt(format!(
                    "{} already exists. Overwrite?",
                    workers_path.display()
                ))
                .default(false)
                .interact()
                .unwrap_or(false)
        }
    } else {
        true
    };

    // Collect worker values
    let workers = if should_write_workers {
        Some(collect_worker_values(use_defaults, style)?)
    } else {
        None
    };

    // Write config.toml
    if let Some(values) = config_values {
        let config_content = generate_config_toml(&values);
        std::fs::write(&config_path, config_content)?;
        created.push(config_path.display().to_string());
        if !ctx.is_json() {
            println!(
                "{} {} {}",
                StatusIndicator::Success.display(style),
                style.muted("Created:"),
                style.value(&config_path.display().to_string())
            );
        }
    } else if config_exists {
        already_existed.push(config_path.display().to_string());
        if !ctx.is_json() {
            println!(
                "{} {} {}",
                style.muted("-"),
                style.muted("Kept existing:"),
                style.muted(&config_path.display().to_string())
            );
        }
    }

    // Write workers.toml
    if let Some(ref workers_list) = workers {
        let workers_content = generate_workers_toml(workers_list);
        std::fs::write(&workers_path, workers_content)?;
        created.push(workers_path.display().to_string());
        if !ctx.is_json() {
            println!(
                "{} {} {}",
                StatusIndicator::Success.display(style),
                style.muted("Created:"),
                style.value(&workers_path.display().to_string())
            );
        }
    } else if workers_exists {
        already_existed.push(workers_path.display().to_string());
        if !ctx.is_json() {
            println!(
                "{} {} {}",
                style.muted("-"),
                style.muted("Kept existing:"),
                style.muted(&workers_path.display().to_string())
            );
        }
    }

    // JSON output
    if ctx.is_json() {
        let _ = ctx.json(&ApiResponse::ok(
            "config init",
            ConfigInitResponse {
                created,
                already_existed,
            },
        ));
        return Ok(());
    }

    // Success message and next steps
    println!("\n{}", style.format_success("Configuration initialized!"));
    println!("\n{}", style.highlight("Next steps:"));

    if workers.is_some() || !workers_exists {
        println!(
            "  {}. Edit {} with your actual worker details",
            style.muted("1"),
            style.info(&workers_path.display().to_string())
        );
        println!(
            "  {}. Or auto-discover workers: {}",
            style.muted("2"),
            style.highlight("rch workers discover --add")
        );
    }

    println!(
        "  {}. Test connectivity: {}",
        style.muted("3"),
        style.highlight("rch workers probe --all")
    );
    println!(
        "  {}. Start the daemon: {}",
        style.muted("4"),
        style.highlight("rch daemon start")
    );

    Ok(())
}

/// Simple config init without wizard (original behavior).
fn config_init_simple(
    ctx: &OutputContext,
    _config_dir: &Path,
    config_path: &Path,
    workers_path: &Path,
) -> Result<()> {
    let style = ctx.theme();
    let mut created = Vec::new();
    let mut already_existed = Vec::new();

    // Write example config.toml
    if !config_path.exists() {
        let config_content = r###"# RCH Configuration
# See documentation for all options

[general]
enabled = true
log_level = "info"
socket_path = "/tmp/rch.sock"

[compilation]
confidence_threshold = 0.85
min_local_time_ms = 2000

[transfer]
compression_level = 3
exclude_patterns = [
    "target/",
    ".git/objects/",
    "node_modules/",
    "*.rlib",
    "*.rmeta",
]
"###;
        std::fs::write(config_path, config_content)?;
        created.push(config_path.display().to_string());
        if !ctx.is_json() {
            println!(
                "{} {} {}",
                StatusIndicator::Success.display(style),
                style.muted("Created:"),
                style.value(&config_path.display().to_string())
            );
        }
    } else {
        already_existed.push(config_path.display().to_string());
        if !ctx.is_json() {
            println!(
                "{} {} {}",
                style.muted("-"),
                style.muted("Exists:"),
                style.muted(&config_path.display().to_string())
            );
        }
    }

    // Write example workers.toml
    if !workers_path.exists() {
        let workers_content = r###"# RCH Workers Configuration
# Define your remote compilation workers here

# Example worker definition
[[workers]]
id = "worker1"
host = "192.168.1.100"
user = "ubuntu"
identity_file = "~/.ssh/id_rsa"
total_slots = 16
priority = 100
tags = ["rust", "fast"]
enabled = true

# Add more workers as needed:
# [[workers]]
# id = "worker2"
# host = "192.168.1.101"
# ...
"###;
        std::fs::write(workers_path, workers_content)?;
        created.push(workers_path.display().to_string());
        if !ctx.is_json() {
            println!(
                "{} {} {}",
                StatusIndicator::Success.display(style),
                style.muted("Created:"),
                style.value(&workers_path.display().to_string())
            );
        }
    } else {
        already_existed.push(workers_path.display().to_string());
        if !ctx.is_json() {
            println!(
                "{} {} {}",
                style.muted("-"),
                style.muted("Exists:"),
                style.muted(&workers_path.display().to_string())
            );
        }
    }

    if ctx.is_json() {
        let _ = ctx.json(&ApiResponse::ok(
            "config init",
            ConfigInitResponse {
                created,
                already_existed,
            },
        ));
        return Ok(());
    }

    println!("\n{}", style.format_success("Configuration initialized!"));
    println!("\n{}", style.highlight("Next steps:"));
    println!(
        "  {}. Edit {} with your worker details",
        style.muted("1"),
        style.info(&workers_path.display().to_string())
    );
    println!(
        "  {}. Test connectivity: {}",
        style.muted("2"),
        style.highlight("rch workers probe --all")
    );
    println!(
        "  {}. Start the daemon: {}",
        style.muted("3"),
        style.highlight("rch daemon start")
    );

    Ok(())
}

/// Configuration values collected from wizard.
struct ConfigValues {
    log_level: String,
    socket_path: String,
    confidence_threshold: f64,
    min_local_time_ms: u32,
    compression_level: u8,
}

/// Worker definition collected from wizard.
struct WizardWorker {
    id: String,
    host: String,
    user: String,
    identity_file: String,
    total_slots: u16,
    priority: u16,
}

/// Collect configuration values interactively or with defaults.
fn collect_config_values(
    use_defaults: bool,
    style: &crate::ui::theme::Theme,
) -> Result<ConfigValues> {
    use dialoguer::{Input, Select};

    if use_defaults {
        return Ok(ConfigValues {
            log_level: "info".to_string(),
            socket_path: "/tmp/rch.sock".to_string(),
            confidence_threshold: 0.85,
            min_local_time_ms: 2000,
            compression_level: 3,
        });
    }

    println!("\n{}", style.highlight("General Settings"));
    println!();

    // Log level
    let log_levels = vec!["error", "warn", "info", "debug", "trace"];
    let log_level_idx = Select::new()
        .with_prompt("Log level")
        .items(&log_levels)
        .default(2) // info
        .interact()
        .unwrap_or(2);
    let log_level = log_levels[log_level_idx].to_string();

    // Socket path
    let socket_path: String = Input::new()
        .with_prompt("Unix socket path")
        .default("/tmp/rch.sock".to_string())
        .interact_text()
        .unwrap_or_else(|_| "/tmp/rch.sock".to_string());

    println!("\n{}", style.highlight("Compilation Settings"));
    println!();

    // Confidence threshold
    let confidence_threshold: f64 = Input::new()
        .with_prompt("Classification confidence threshold (0.0-1.0)")
        .default(0.85)
        .validate_with(|input: &f64| {
            if *input >= 0.0 && *input <= 1.0 {
                Ok(())
            } else {
                Err("Must be between 0.0 and 1.0")
            }
        })
        .interact_text()
        .unwrap_or(0.85);

    // Min local time
    let min_local_time_ms: u32 = Input::new()
        .with_prompt("Minimum estimated local time (ms) to offload")
        .default(2000u32)
        .interact_text()
        .unwrap_or(2000);

    println!("\n{}", style.highlight("Transfer Settings"));
    println!();

    // Compression level
    let compression_level: u8 = Input::new()
        .with_prompt("Zstd compression level (1-19, lower=faster)")
        .default(3u8)
        .validate_with(|input: &u8| {
            if *input >= 1 && *input <= 19 {
                Ok(())
            } else {
                Err("Must be between 1 and 19")
            }
        })
        .interact_text()
        .unwrap_or(3);

    Ok(ConfigValues {
        log_level,
        socket_path,
        confidence_threshold,
        min_local_time_ms,
        compression_level,
    })
}

/// Collect worker definitions interactively or with defaults.
fn collect_worker_values(
    use_defaults: bool,
    style: &crate::ui::theme::Theme,
) -> Result<Vec<WizardWorker>> {
    use dialoguer::{Confirm, Input};

    if use_defaults {
        return Ok(vec![WizardWorker {
            id: "worker1".to_string(),
            host: "192.168.1.100".to_string(),
            user: "ubuntu".to_string(),
            identity_file: "~/.ssh/id_rsa".to_string(),
            total_slots: 16,
            priority: 100,
        }]);
    }

    println!("\n{}", style.highlight("Worker Configuration"));
    println!();
    println!(
        "  {} Define your remote compilation workers.",
        style.muted("→")
    );
    println!(
        "  {} You can also auto-discover workers later with: {}",
        style.muted("→"),
        style.info("rch workers discover --add")
    );
    println!();

    let mut workers = Vec::new();
    let mut worker_num = 1;

    loop {
        println!("\n{} Worker #{}", style.muted("─────────────"), worker_num);

        let id: String = Input::new()
            .with_prompt("Worker ID (short name)")
            .default(format!("worker{}", worker_num))
            .interact_text()
            .unwrap_or_else(|_| format!("worker{}", worker_num));

        let host: String = Input::new()
            .with_prompt("Hostname or IP address")
            .interact_text()
            .context("Host is required")?;

        let user: String = Input::new()
            .with_prompt("SSH username")
            .default("ubuntu".to_string())
            .interact_text()
            .unwrap_or_else(|_| "ubuntu".to_string());

        let identity_file: String = Input::new()
            .with_prompt("SSH identity file path")
            .default("~/.ssh/id_rsa".to_string())
            .interact_text()
            .unwrap_or_else(|_| "~/.ssh/id_rsa".to_string());

        let total_slots: u16 = Input::new()
            .with_prompt("Total CPU slots (cores) available")
            .default(16u16)
            .interact_text()
            .unwrap_or(16);

        let priority: u16 = Input::new()
            .with_prompt("Priority (higher = preferred)")
            .default(100u16)
            .interact_text()
            .unwrap_or(100);

        workers.push(WizardWorker {
            id,
            host,
            user,
            identity_file,
            total_slots,
            priority,
        });

        worker_num += 1;

        let add_another = Confirm::new()
            .with_prompt("Add another worker?")
            .default(false)
            .interact()
            .unwrap_or(false);

        if !add_another {
            break;
        }
    }

    if workers.is_empty() {
        // Add a placeholder if no workers were defined
        workers.push(WizardWorker {
            id: "worker1".to_string(),
            host: "192.168.1.100".to_string(),
            user: "ubuntu".to_string(),
            identity_file: "~/.ssh/id_rsa".to_string(),
            total_slots: 16,
            priority: 100,
        });
    }

    Ok(workers)
}

/// Generate config.toml content from wizard values.
fn generate_config_toml(values: &ConfigValues) -> String {
    format!(
        r###"# RCH Configuration
# Generated by rch config init --wizard
# See documentation for all options

[general]
enabled = true
log_level = "{}"
socket_path = "{}"

[compilation]
# Minimum classification confidence to intercept (0.0-1.0)
confidence_threshold = {}
# Skip offloading if estimated local time is below this (milliseconds)
min_local_time_ms = {}

[transfer]
# Zstd compression level (1-19, lower=faster)
compression_level = {}
exclude_patterns = [
    "target/",
    ".git/objects/",
    "node_modules/",
    "*.rlib",
    "*.rmeta",
]
"###,
        values.log_level,
        values.socket_path,
        values.confidence_threshold,
        values.min_local_time_ms,
        values.compression_level
    )
}

/// Generate workers.toml content from wizard values.
fn generate_workers_toml(workers: &[WizardWorker]) -> String {
    let mut content = String::from(
        "# RCH Workers Configuration\n\
         # Generated by rch config init --wizard\n\
         # Define your remote compilation workers here\n\n",
    );

    for worker in workers {
        content.push_str(&format!(
            r#"[[workers]]
id = "{}"
host = "{}"
user = "{}"
identity_file = "{}"
total_slots = {}
priority = {}
enabled = true

"#,
            worker.id,
            worker.host,
            worker.user,
            worker.identity_file,
            worker.total_slots,
            worker.priority
        ));
    }

    content
}

/// Validate configuration files.
pub fn config_validate(ctx: &OutputContext) -> Result<()> {
    let style = ctx.theme();

    let mut validations: Vec<crate::config::FileValidation> = Vec::new();

    let config_dir = match config_dir() {
        Some(d) => d,
        None => {
            if ctx.is_json() {
                let response = ConfigValidationResponse {
                    errors: vec![ConfigValidationIssue {
                        file: "config".to_string(),
                        message: "Could not determine config directory".to_string(),
                    }],
                    warnings: vec![],
                    valid: false,
                };
                let _ = ctx.json(&ApiResponse::ok("config validate", response));
                std::process::exit(1);
            }
            println!(
                "{} Could not determine config directory",
                StatusIndicator::Error.display(style)
            );
            std::process::exit(1);
        }
    };

    // config.toml
    let config_path = config_dir.join("config.toml");
    if config_path.exists() {
        validations.push(crate::config::validate_rch_config_file(&config_path));
    }

    // workers.toml
    let workers_path = config_dir.join("workers.toml");
    if workers_path.exists() {
        validations.push(crate::config::validate_workers_config_file(&workers_path));
    } else {
        let mut missing = crate::config::FileValidation::new(&workers_path);
        missing.error("workers.toml not found (run `rch config init`)".to_string());
        validations.push(missing);
    }

    // project config
    let project_config = PathBuf::from(".rch/config.toml");
    if project_config.exists() {
        validations.push(crate::config::validate_rch_config_file(&project_config));
    }

    let mut error_items = Vec::new();
    let mut warning_items = Vec::new();
    for validation in &validations {
        for error in &validation.errors {
            error_items.push(ConfigValidationIssue {
                file: validation.file.display().to_string(),
                message: error.clone(),
            });
        }
        for warning in &validation.warnings {
            warning_items.push(ConfigValidationIssue {
                file: validation.file.display().to_string(),
                message: warning.clone(),
            });
        }
    }

    let valid = error_items.is_empty();

    if ctx.is_json() {
        let response = ConfigValidationResponse {
            errors: error_items,
            warnings: warning_items,
            valid,
        };
        let _ = ctx.json(&ApiResponse::ok("config validate", response));
        if !valid {
            std::process::exit(1);
        }
        return Ok(());
    }

    println!("Validating RCH configuration...\n");

    if config_path.exists() {
        print_file_validation("config.toml", &validations, style, &config_path);
    } else {
        println!(
            "{} {}: {} {}",
            style.muted("-"),
            style.highlight("config.toml"),
            style.muted("Not found"),
            style.muted("(using defaults)")
        );
    }

    print_file_validation("workers.toml", &validations, style, &workers_path);

    if project_config.exists() {
        print_file_validation(".rch/config.toml", &validations, style, &project_config);
    }

    println!();
    if !valid {
        println!(
            "{} {} error(s), {} warning(s)",
            style.format_error("Validation failed:"),
            error_items.len(),
            warning_items.len()
        );
        std::process::exit(1);
    } else if !warning_items.is_empty() {
        println!(
            "{} with {} warning(s)",
            style.format_warning("Validation passed"),
            warning_items.len()
        );
    } else {
        println!("{}", style.format_success("Validation passed!"));
    }

    Ok(())
}

/// Set a configuration value.
pub fn config_set(key: &str, value: &str, ctx: &OutputContext) -> Result<()> {
    let config_dir = config_dir().context("Could not determine config directory")?;
    std::fs::create_dir_all(&config_dir)
        .with_context(|| format!("Failed to create config directory: {:?}", config_dir))?;
    let config_path = config_dir.join("config.toml");
    config_set_at(&config_path, key, value, ctx)
}

fn config_set_at(config_path: &Path, key: &str, value: &str, ctx: &OutputContext) -> Result<()> {
    let mut config = if config_path.exists() {
        let contents = std::fs::read_to_string(config_path)
            .with_context(|| format!("Failed to read {:?}", config_path))?;
        toml::from_str::<RchConfig>(&contents)
            .with_context(|| format!("Failed to parse {:?}", config_path))?
    } else {
        RchConfig::default()
    };

    match key {
        "general.enabled" => {
            config.general.enabled = parse_bool(value, key)?;
        }
        "general.force_local" => {
            config.general.force_local = parse_bool(value, key)?;
        }
        "general.force_remote" => {
            config.general.force_remote = parse_bool(value, key)?;
        }
        "general.log_level" => {
            config.general.log_level = value.trim().trim_matches(|c| c == '"').to_string();
        }
        "general.socket_path" => {
            config.general.socket_path = value.trim().trim_matches(|c| c == '"').to_string();
        }
        "compilation.confidence_threshold" => {
            let threshold = parse_f64(value, key)?;
            if !(0.0..=1.0).contains(&threshold) {
                bail!("compilation.confidence_threshold must be between 0.0 and 1.0");
            }
            config.compilation.confidence_threshold = threshold;
        }
        "compilation.min_local_time_ms" => {
            config.compilation.min_local_time_ms = parse_u64(value, key)?;
        }
        "transfer.compression_level" => {
            let level = parse_u32(value, key)?;
            if level > 19 {
                bail!("transfer.compression_level must be between 0 and 19");
            }
            config.transfer.compression_level = level;
        }
        "transfer.exclude_patterns" => {
            config.transfer.exclude_patterns = parse_string_list(value, key)?;
        }
        "environment.allowlist" => {
            config.environment.allowlist = parse_string_list(value, key)?;
        }
        "output.visibility" => {
            let trimmed = value.trim().trim_matches(|c| c == '"');
            let visibility = trimmed
                .parse::<rch_common::OutputVisibility>()
                .map_err(|_| {
                    anyhow::anyhow!("output.visibility must be one of: none, summary, verbose")
                })?;
            config.output.visibility = visibility;
        }
        "output.first_run_complete" | "first_run_complete" => {
            config.output.first_run_complete = parse_bool(value, key)?;
        }
        _ => {
            bail!(
                "Unknown config key: {}. Supported keys: general.enabled, general.force_local, general.force_remote, general.log_level, general.socket_path, compilation.confidence_threshold, compilation.min_local_time_ms, transfer.compression_level, transfer.exclude_patterns, environment.allowlist, output.visibility, output.first_run_complete, first_run_complete",
                key
            );
        }
    }

    if config.general.force_local && config.general.force_remote {
        bail!("general.force_local and general.force_remote cannot both be true");
    }

    let contents = toml::to_string_pretty(&config)?;
    std::fs::write(config_path, format!("{}\n", contents))
        .with_context(|| format!("Failed to write {:?}", config_path))?;

    if ctx.is_json() {
        let _ = ctx.json(&ApiResponse::ok(
            "config set",
            ConfigSetResponse {
                key: key.to_string(),
                value: value.to_string(),
                config_path: config_path.display().to_string(),
            },
        ));
    } else {
        println!("Updated {:?}: {} = {}", config_path, key, value);
    }
    Ok(())
}

/// Export configuration as shell environment variables or .env format.
pub fn config_export(format: &str, ctx: &OutputContext) -> Result<()> {
    let config = crate::config::load_config()?;

    match format {
        "shell" => {
            // Shell export format (for sourcing)
            println!("# RCH configuration export");
            println!("# Source this file: source <(rch config export)");
            println!();
            println!("export RCH_ENABLED={}", config.general.enabled);
            println!("export RCH_LOG_LEVEL=\"{}\"", config.general.log_level);
            println!("export RCH_VISIBILITY=\"{}\"", config.output.visibility);
            println!(
                "export RCH_DAEMON_SOCKET=\"{}\"",
                config.general.socket_path
            );
            println!(
                "export RCH_CONFIDENCE_THRESHOLD={}",
                config.compilation.confidence_threshold
            );
            println!(
                "export RCH_MIN_LOCAL_TIME_MS={}",
                config.compilation.min_local_time_ms
            );
            println!(
                "export RCH_TRANSFER_ZSTD_LEVEL={}",
                config.transfer.compression_level
            );
            println!(
                "export RCH_ENV_ALLOWLIST=\"{}\"",
                config.environment.allowlist.join(",")
            );
        }
        "env" => {
            // .env file format
            println!("# RCH configuration");
            println!("# Save to .rch.env in your project");
            println!();
            println!("RCH_ENABLED={}", config.general.enabled);
            println!("RCH_LOG_LEVEL={}", config.general.log_level);
            println!("RCH_VISIBILITY={}", config.output.visibility);
            println!("RCH_DAEMON_SOCKET={}", config.general.socket_path);
            println!(
                "RCH_CONFIDENCE_THRESHOLD={}",
                config.compilation.confidence_threshold
            );
            println!(
                "RCH_MIN_LOCAL_TIME_MS={}",
                config.compilation.min_local_time_ms
            );
            println!(
                "RCH_TRANSFER_ZSTD_LEVEL={}",
                config.transfer.compression_level
            );
            println!(
                "RCH_ENV_ALLOWLIST={}",
                config.environment.allowlist.join(",")
            );
        }
        "json" => {
            // JSON format (ignore ctx.is_json() since user explicitly requested JSON)
            let _ = ctx.json_force(&ApiResponse::ok(
                "config export",
                serde_json::json!({
                    "general": {
                        "enabled": config.general.enabled,
                        "log_level": config.general.log_level,
                        "socket_path": config.general.socket_path,
                    },
                    "output": {
                        "visibility": config.output.visibility.to_string(),
                    },
                    "compilation": {
                        "confidence_threshold": config.compilation.confidence_threshold,
                        "min_local_time_ms": config.compilation.min_local_time_ms,
                    },
                    "transfer": {
                        "compression_level": config.transfer.compression_level,
                        "exclude_patterns": config.transfer.exclude_patterns,
                    },
                    "environment": {
                        "allowlist": config.environment.allowlist,
                    }
                }),
            ));
        }
        _ => {
            bail!(
                "Unknown export format '{}'. Supported: shell, env, json",
                format
            );
        }
    }
    Ok(())
}

// =============================================================================
// Config Lint & Diff
// =============================================================================

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

/// Lint configuration for potential issues.
pub fn config_lint(ctx: &OutputContext) -> Result<()> {
    let style = ctx.theme();
    let config = crate::config::load_config()?;
    let mut issues = Vec::new();

    // Check 1: Missing workers configuration
    let workers_path = config_dir()
        .map(|d| d.join("workers.toml"))
        .unwrap_or_else(|| PathBuf::from("~/.config/rch/workers.toml"));
    if !workers_path.exists() {
        issues.push(LintIssue {
            severity: LintSeverity::Error,
            code: "LINT-E001".to_string(),
            message: "No workers.toml configuration found".to_string(),
            remediation: "Run 'rch config init --wizard' to create workers configuration"
                .to_string(),
        });
    } else {
        // Check if workers.toml has any workers defined
        match load_workers_from_config() {
            Ok(workers) if workers.is_empty() => {
                issues.push(LintIssue {
                    severity: LintSeverity::Error,
                    code: "LINT-E002".to_string(),
                    message: "workers.toml exists but no workers are defined".to_string(),
                    remediation: "Add at least one [[workers]] section to workers.toml".to_string(),
                });
            }
            Err(e) => {
                issues.push(LintIssue {
                    severity: LintSeverity::Error,
                    code: "LINT-E003".to_string(),
                    message: format!("Failed to parse workers.toml: {}", e),
                    remediation:
                        "Fix the workers.toml file syntax or run 'rch config init --wizard'"
                            .to_string(),
                });
            }
            _ => {}
        }
    }

    // Check 2: Compression level warnings
    if config.transfer.compression_level == 0 {
        issues.push(LintIssue {
            severity: LintSeverity::Warning,
            code: "LINT-W001".to_string(),
            message: "Compression is disabled (level=0)".to_string(),
            remediation: "Consider setting compression_level to 3-6 for better transfer performance on slow networks".to_string(),
        });
    } else if config.transfer.compression_level > 19 {
        issues.push(LintIssue {
            severity: LintSeverity::Warning,
            code: "LINT-W002".to_string(),
            message: format!("Compression level {} is very high", config.transfer.compression_level),
            remediation: "High compression levels (>10) significantly slow down transfers. Consider 3-6 for balanced performance".to_string(),
        });
    }

    // Check 3: Risky exclude patterns
    let risky_excludes = ["src/", "Cargo.toml", "Cargo.lock", "package.json", "go.mod"];
    for pattern in &config.transfer.exclude_patterns {
        for risky in &risky_excludes {
            if pattern == *risky || pattern.ends_with(risky) {
                issues.push(LintIssue {
                    severity: LintSeverity::Warning,
                    code: "LINT-W003".to_string(),
                    message: format!(
                        "Exclude pattern '{}' may prevent builds from working",
                        pattern
                    ),
                    remediation: format!(
                        "Remove '{}' from exclude_patterns unless intentional",
                        pattern
                    ),
                });
            }
        }
    }

    // Check 4: Confidence threshold too low
    if config.compilation.confidence_threshold < 0.5 {
        issues.push(LintIssue {
            severity: LintSeverity::Warning,
            code: "LINT-W004".to_string(),
            message: format!(
                "Confidence threshold {} is very low",
                config.compilation.confidence_threshold
            ),
            remediation:
                "Low thresholds may intercept non-compilation commands. Consider 0.8 or higher"
                    .to_string(),
        });
    }

    // Check 5: RCH disabled
    if !config.general.enabled {
        issues.push(LintIssue {
            severity: LintSeverity::Info,
            code: "LINT-I001".to_string(),
            message: "RCH is disabled (general.enabled = false)".to_string(),
            remediation:
                "Set general.enabled = true or RCH_ENABLED=true to enable remote compilation"
                    .to_string(),
        });
    }

    // Check 6: Very short timeouts
    if config.compilation.build_timeout_sec < 60 {
        issues.push(LintIssue {
            severity: LintSeverity::Warning,
            code: "LINT-W005".to_string(),
            message: format!(
                "Build timeout {}s is very short",
                config.compilation.build_timeout_sec
            ),
            remediation:
                "Short timeouts may cause builds to fail prematurely. Consider at least 300s"
                    .to_string(),
        });
    }

    // Count by severity
    let error_count = issues
        .iter()
        .filter(|i| i.severity == LintSeverity::Error)
        .count();
    let warning_count = issues
        .iter()
        .filter(|i| i.severity == LintSeverity::Warning)
        .count();
    let info_count = issues
        .iter()
        .filter(|i| i.severity == LintSeverity::Info)
        .count();

    // Output
    if ctx.is_json() {
        let response = ConfigLintResponse {
            issues,
            error_count,
            warning_count,
            info_count,
        };
        ctx.json(&ApiResponse::ok("config lint", response))?;
    } else if issues.is_empty() {
        println!(
            "{} Configuration looks good!",
            StatusIndicator::Success.display(style)
        );
    } else {
        println!("{} Configuration Lint Results", style.highlight("RCH"));
        println!();

        for issue in &issues {
            let indicator = match issue.severity {
                LintSeverity::Error => StatusIndicator::Error,
                LintSeverity::Warning => StatusIndicator::Warning,
                LintSeverity::Info => StatusIndicator::Info,
            };
            println!(
                "{} [{}] {}",
                indicator.display(style),
                issue.code,
                issue.message
            );
            println!("   {}", style.muted(&format!("→ {}", issue.remediation)));
            println!();
        }

        // Summary
        let mut summary_parts = Vec::new();
        if error_count > 0 {
            summary_parts.push(format!("{} error(s)", error_count));
        }
        if warning_count > 0 {
            summary_parts.push(format!("{} warning(s)", warning_count));
        }
        if info_count > 0 {
            summary_parts.push(format!("{} info", info_count));
        }
        println!("Summary: {}", summary_parts.join(", "));
    }

    // Exit with non-zero if errors found
    if error_count > 0 {
        std::process::exit(1);
    }

    Ok(())
}

/// Show configuration values that differ from defaults.
pub fn config_diff(ctx: &OutputContext) -> Result<()> {
    use rch_common::RchConfig;

    let style = ctx.theme();
    let loaded = crate::config::load_config_with_sources()?;
    let config = &loaded.config;
    let defaults = RchConfig::default();
    let sources = &loaded.sources;

    let mut entries = Vec::new();

    // Helper to add entry if different
    macro_rules! diff_field {
        ($key:expr, $current:expr, $default:expr, $source_key:expr) => {
            let current_str = format!("{}", $current);
            let default_str = format!("{}", $default);
            if current_str != default_str {
                let source = sources
                    .get($source_key)
                    .map(|s| format!("{:?}", s))
                    .unwrap_or_else(|| "unknown".to_string());
                entries.push(ConfigDiffEntry {
                    key: $key.to_string(),
                    current: current_str,
                    default: default_str,
                    source,
                });
            }
        };
    }

    // General section
    diff_field!(
        "general.enabled",
        config.general.enabled,
        defaults.general.enabled,
        "general.enabled"
    );
    diff_field!(
        "general.log_level",
        &config.general.log_level,
        &defaults.general.log_level,
        "general.log_level"
    );
    diff_field!(
        "general.socket_path",
        &config.general.socket_path,
        &defaults.general.socket_path,
        "general.socket_path"
    );

    // Compilation section
    diff_field!(
        "compilation.confidence_threshold",
        config.compilation.confidence_threshold,
        defaults.compilation.confidence_threshold,
        "compilation.confidence_threshold"
    );
    diff_field!(
        "compilation.min_local_time_ms",
        config.compilation.min_local_time_ms,
        defaults.compilation.min_local_time_ms,
        "compilation.min_local_time_ms"
    );
    diff_field!(
        "compilation.build_slots",
        config.compilation.build_slots,
        defaults.compilation.build_slots,
        "compilation.build_slots"
    );
    diff_field!(
        "compilation.test_slots",
        config.compilation.test_slots,
        defaults.compilation.test_slots,
        "compilation.test_slots"
    );
    diff_field!(
        "compilation.check_slots",
        config.compilation.check_slots,
        defaults.compilation.check_slots,
        "compilation.check_slots"
    );
    diff_field!(
        "compilation.build_timeout_sec",
        config.compilation.build_timeout_sec,
        defaults.compilation.build_timeout_sec,
        "compilation.build_timeout_sec"
    );
    diff_field!(
        "compilation.test_timeout_sec",
        config.compilation.test_timeout_sec,
        defaults.compilation.test_timeout_sec,
        "compilation.test_timeout_sec"
    );

    // Transfer section
    diff_field!(
        "transfer.compression_level",
        config.transfer.compression_level,
        defaults.transfer.compression_level,
        "transfer.compression_level"
    );

    // Compare exclude patterns
    let current_excludes = config.transfer.exclude_patterns.join(",");
    let default_excludes = defaults.transfer.exclude_patterns.join(",");
    if current_excludes != default_excludes {
        let source = sources
            .get("transfer.exclude_patterns")
            .map(|s| format!("{:?}", s))
            .unwrap_or_else(|| "unknown".to_string());
        entries.push(ConfigDiffEntry {
            key: "transfer.exclude_patterns".to_string(),
            current: format!("[{}]", current_excludes),
            default: format!("[{}]", default_excludes),
            source,
        });
    }

    // Circuit breaker section
    diff_field!(
        "circuit.failure_threshold",
        config.circuit.failure_threshold,
        defaults.circuit.failure_threshold,
        "circuit.failure_threshold"
    );
    diff_field!(
        "circuit.success_threshold",
        config.circuit.success_threshold,
        defaults.circuit.success_threshold,
        "circuit.success_threshold"
    );
    diff_field!(
        "circuit.error_rate_threshold",
        config.circuit.error_rate_threshold,
        defaults.circuit.error_rate_threshold,
        "circuit.error_rate_threshold"
    );
    diff_field!(
        "circuit.window_secs",
        config.circuit.window_secs,
        defaults.circuit.window_secs,
        "circuit.window_secs"
    );
    diff_field!(
        "circuit.open_cooldown_secs",
        config.circuit.open_cooldown_secs,
        defaults.circuit.open_cooldown_secs,
        "circuit.open_cooldown_secs"
    );
    diff_field!(
        "circuit.half_open_max_probes",
        config.circuit.half_open_max_probes,
        defaults.circuit.half_open_max_probes,
        "circuit.half_open_max_probes"
    );

    // Output section
    diff_field!(
        "output.visibility",
        config.output.visibility,
        defaults.output.visibility,
        "output.visibility"
    );
    diff_field!(
        "output.first_run_complete",
        config.output.first_run_complete,
        defaults.output.first_run_complete,
        "output.first_run_complete"
    );

    // Self-healing section
    diff_field!(
        "self_healing.hook_starts_daemon",
        config.self_healing.hook_starts_daemon,
        defaults.self_healing.hook_starts_daemon,
        "self_healing.hook_starts_daemon"
    );
    diff_field!(
        "self_healing.daemon_installs_hooks",
        config.self_healing.daemon_installs_hooks,
        defaults.self_healing.daemon_installs_hooks,
        "self_healing.daemon_installs_hooks"
    );
    diff_field!(
        "self_healing.auto_start_cooldown_secs",
        config.self_healing.auto_start_cooldown_secs,
        defaults.self_healing.auto_start_cooldown_secs,
        "self_healing.auto_start_cooldown_secs"
    );
    diff_field!(
        "self_healing.auto_start_timeout_secs",
        config.self_healing.auto_start_timeout_secs,
        defaults.self_healing.auto_start_timeout_secs,
        "self_healing.auto_start_timeout_secs"
    );

    // Environment allowlist (compare as sets)
    if !config.environment.allowlist.is_empty()
        && config.environment.allowlist != defaults.environment.allowlist
    {
        let source = sources
            .get("environment.allowlist")
            .map(|s| format!("{:?}", s))
            .unwrap_or_else(|| "unknown".to_string());
        entries.push(ConfigDiffEntry {
            key: "environment.allowlist".to_string(),
            current: format!("[{}]", config.environment.allowlist.join(", ")),
            default: format!("[{}]", defaults.environment.allowlist.join(", ")),
            source,
        });
    }

    let total_changes = entries.len();

    // Output
    if ctx.is_json() {
        let response = ConfigDiffResponse {
            entries,
            total_changes,
        };
        ctx.json(&ApiResponse::ok("config diff", response))?;
    } else if entries.is_empty() {
        println!(
            "{} All configuration values are at defaults",
            StatusIndicator::Success.display(style)
        );
    } else {
        println!(
            "{} Configuration Diff (non-default values)",
            style.highlight("RCH")
        );
        println!();

        // Print header
        println!(
            "{:<40} {:<20} {:<20} {}",
            style.highlight("Key"),
            style.highlight("Current"),
            style.highlight("Default"),
            style.highlight("Source")
        );
        println!("{}", "-".repeat(95));

        for entry in &entries {
            // Truncate long values
            let current = if entry.current.len() > 18 {
                format!("{}...", &entry.current[..15])
            } else {
                entry.current.clone()
            };
            let default = if entry.default.len() > 18 {
                format!("{}...", &entry.default[..15])
            } else {
                entry.default.clone()
            };

            println!(
                "{:<40} {:<20} {:<20} {}",
                entry.key,
                current,
                style.muted(&default),
                entry.source
            );
        }

        println!();
        println!("Total: {} non-default value(s)", total_changes);
    }

    Ok(())
}

fn parse_bool(value: &str, key: &str) -> Result<bool> {
    value.trim().parse::<bool>().map_err(|_| {
        ConfigError::InvalidValue {
            field: key.to_string(),
            reason: format!("'{}' is not a valid boolean", value.trim()),
            suggestion: "Use 'true' or 'false'".to_string(),
        }
        .into()
    })
}

fn parse_u32(value: &str, key: &str) -> Result<u32> {
    value.trim().parse::<u32>().map_err(|_| {
        ConfigError::InvalidValue {
            field: key.to_string(),
            reason: format!("'{}' is not a valid unsigned integer", value.trim()),
            suggestion: "Use a positive whole number (e.g., 0, 1, 42, 1000)".to_string(),
        }
        .into()
    })
}

fn parse_u64(value: &str, key: &str) -> Result<u64> {
    value.trim().parse::<u64>().map_err(|_| {
        ConfigError::InvalidValue {
            field: key.to_string(),
            reason: format!("'{}' is not a valid unsigned integer", value.trim()),
            suggestion: "Use a positive whole number (e.g., 0, 1, 42, 1000)".to_string(),
        }
        .into()
    })
}

fn parse_f64(value: &str, key: &str) -> Result<f64> {
    value.trim().parse::<f64>().map_err(|_| {
        ConfigError::InvalidValue {
            field: key.to_string(),
            reason: format!("'{}' is not a valid number", value.trim()),
            suggestion: "Use a decimal number (e.g., 0.5, 1.0, 3.14)".to_string(),
        }
        .into()
    })
}

fn parse_string_list(value: &str, key: &str) -> Result<Vec<String>> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    if trimmed.starts_with('[') {
        let wrapped = format!("value = {}", trimmed);
        let parsed: toml::Value =
            toml::from_str(&wrapped).with_context(|| format!("Invalid array for {}", key))?;
        let array = parsed
            .get("value")
            .and_then(|v| v.as_array())
            .ok_or_else(|| ConfigError::InvalidValue {
                field: key.to_string(),
                reason: format!("'{}' is not a valid array", trimmed),
                suggestion: "Use TOML array syntax: [\"item1\", \"item2\"]".to_string(),
            })?;
        let mut result = Vec::with_capacity(array.len());
        for item in array {
            let item_str = item.as_str().ok_or_else(|| ConfigError::InvalidValue {
                field: key.to_string(),
                reason: "Array contains non-string items".to_string(),
                suggestion: "All array items must be strings: [\"item1\", \"item2\"]".to_string(),
            })?;
            result.push(item_str.to_string());
        }
        return Ok(result);
    }

    if trimmed.contains(',') {
        let parts: Vec<String> = trimmed
            .split(',')
            .map(|part| part.trim())
            .filter(|part| !part.is_empty())
            .map(String::from)
            .collect();
        if !parts.is_empty() {
            return Ok(parts);
        }
    }

    Ok(vec![trimmed.to_string()])
}

// =============================================================================
// Diagnose Command
// =============================================================================

#[derive(Debug, Clone, Deserialize)]
struct DaemonHealthResponse {
    status: String,
    version: String,
    uptime_seconds: u64,
}

#[cfg(not(unix))]
async fn query_daemon_health(_socket_path: &str) -> Result<DaemonHealthResponse> {
    bail!("daemon health check is only supported on Unix-like platforms");
}

#[cfg(unix)]
async fn query_daemon_health(socket_path: &str) -> Result<DaemonHealthResponse> {
    let stream = UnixStream::connect(socket_path).await?;
    let (reader, mut writer) = stream.into_split();

    let request = "GET /health\n";
    writer.write_all(request.as_bytes()).await?;
    writer.flush().await?;

    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    let mut body = String::new();
    let mut in_body = false;

    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            break;
        }
        if in_body {
            body.push_str(&line);
        } else if line.trim().is_empty() {
            in_body = true;
        }
    }

    let health: DaemonHealthResponse = serde_json::from_str(body.trim())?;
    Ok(health)
}

fn build_diagnose_decision(classification: &Classification, threshold: f64) -> DiagnoseDecision {
    let would_intercept = classification.is_compilation && classification.confidence >= threshold;
    let reason = if !classification.is_compilation {
        format!("not a compilation command ({})", classification.reason)
    } else if classification.confidence < threshold {
        format!(
            "confidence {:.2} below threshold {:.2}",
            classification.confidence, threshold
        )
    } else {
        "meets confidence threshold".to_string()
    };

    DiagnoseDecision {
        would_intercept,
        reason,
    }
}

/// Build a dry-run summary showing the full offload pipeline.
fn build_dry_run_summary(
    would_intercept: bool,
    reason: &str,
    worker_selection: &Option<DiagnoseWorkerSelection>,
    daemon_reachable: bool,
) -> DryRunSummary {
    let mut steps = Vec::new();
    let mut total_estimated_ms: u64 = 0;

    // Step 1: Classification (always happens)
    steps.push(DryRunPipelineStep {
        step: 1,
        name: "classify".to_string(),
        description: "Analyze command to determine if it's a compilation".to_string(),
        skipped: false,
        skip_reason: None,
        estimated_duration_ms: Some(2), // Classification is fast (<5ms budget)
    });
    total_estimated_ms += 2;

    if !would_intercept {
        // Command won't be offloaded - remaining steps are skipped
        steps.push(DryRunPipelineStep {
            step: 2,
            name: "select".to_string(),
            description: "Select optimal worker for remote execution".to_string(),
            skipped: true,
            skip_reason: Some(reason.to_string()),
            estimated_duration_ms: None,
        });
        steps.push(DryRunPipelineStep {
            step: 3,
            name: "sync_up".to_string(),
            description: "Sync project files to remote worker via rsync".to_string(),
            skipped: true,
            skip_reason: Some("command not offloaded".to_string()),
            estimated_duration_ms: None,
        });
        steps.push(DryRunPipelineStep {
            step: 4,
            name: "exec".to_string(),
            description: "Execute compilation command on remote worker".to_string(),
            skipped: true,
            skip_reason: Some("command not offloaded".to_string()),
            estimated_duration_ms: None,
        });
        steps.push(DryRunPipelineStep {
            step: 5,
            name: "sync_down".to_string(),
            description: "Retrieve build artifacts from remote worker".to_string(),
            skipped: true,
            skip_reason: Some("command not offloaded".to_string()),
            estimated_duration_ms: None,
        });

        return DryRunSummary {
            would_offload: false,
            reason: reason.to_string(),
            pipeline_steps: steps,
            transfer_estimate: None,
            total_estimated_ms: Some(total_estimated_ms),
        };
    }

    // Step 2: Worker selection
    let (worker_selected, selection_reason) = if !daemon_reachable {
        (false, "daemon not reachable".to_string())
    } else if let Some(ws) = worker_selection {
        if ws.worker.is_some() {
            (true, format!("{:?}", ws.reason))
        } else {
            (false, format!("{:?}", ws.reason))
        }
    } else {
        (false, "selection not performed".to_string())
    };

    steps.push(DryRunPipelineStep {
        step: 2,
        name: "select".to_string(),
        description: if worker_selected {
            format!(
                "Worker selected: {}",
                worker_selection
                    .as_ref()
                    .and_then(|ws| ws.worker.as_ref())
                    .map(|w| w.id.as_str())
                    .unwrap_or("unknown")
            )
        } else {
            "Select optimal worker for remote execution".to_string()
        },
        skipped: !worker_selected,
        skip_reason: if worker_selected {
            None
        } else {
            Some(selection_reason.clone())
        },
        estimated_duration_ms: Some(5),
    });
    total_estimated_ms += 5;

    if !worker_selected {
        // No worker available - remaining steps are skipped
        steps.push(DryRunPipelineStep {
            step: 3,
            name: "sync_up".to_string(),
            description: "Sync project files to remote worker via rsync".to_string(),
            skipped: true,
            skip_reason: Some("no worker available".to_string()),
            estimated_duration_ms: None,
        });
        steps.push(DryRunPipelineStep {
            step: 4,
            name: "exec".to_string(),
            description: "Execute compilation command on remote worker".to_string(),
            skipped: true,
            skip_reason: Some("no worker available".to_string()),
            estimated_duration_ms: None,
        });
        steps.push(DryRunPipelineStep {
            step: 5,
            name: "sync_down".to_string(),
            description: "Retrieve build artifacts from remote worker".to_string(),
            skipped: true,
            skip_reason: Some("no worker available".to_string()),
            estimated_duration_ms: None,
        });

        return DryRunSummary {
            would_offload: false,
            reason: format!("no worker available: {}", selection_reason),
            pipeline_steps: steps,
            transfer_estimate: None,
            total_estimated_ms: Some(total_estimated_ms),
        };
    }

    // Step 3: Sync up (transfer estimate not available in diagnose mode)
    steps.push(DryRunPipelineStep {
        step: 3,
        name: "sync_up".to_string(),
        description: "Sync project files to remote worker via rsync".to_string(),
        skipped: false,
        skip_reason: None,
        estimated_duration_ms: None, // Would need rsync dry-run
    });

    // Step 4: Execute
    steps.push(DryRunPipelineStep {
        step: 4,
        name: "exec".to_string(),
        description: "Execute compilation command on remote worker".to_string(),
        skipped: false,
        skip_reason: None,
        estimated_duration_ms: None, // Depends on build complexity
    });

    // Step 5: Sync down
    steps.push(DryRunPipelineStep {
        step: 5,
        name: "sync_down".to_string(),
        description: "Retrieve build artifacts from remote worker".to_string(),
        skipped: false,
        skip_reason: None,
        estimated_duration_ms: None, // Would need rsync dry-run
    });

    DryRunSummary {
        would_offload: true,
        reason: "compilation command meets threshold, worker available".to_string(),
        pipeline_steps: steps,
        transfer_estimate: None,  // Would need actual rsync dry-run
        total_estimated_ms: None, // Total unknown without transfer estimates
    }
}

/// Diagnose command classification and selection decisions.
pub async fn diagnose(command: &str, dry_run: bool, ctx: &OutputContext) -> Result<()> {
    let style = ctx.theme();
    let loaded = crate::config::load_config_with_sources()?;
    let config = loaded.config;

    let details: ClassificationDetails = classify_command_detailed(command);
    let threshold = config.compilation.confidence_threshold;

    let value_sources = collect_value_sources(&config, &loaded.sources);
    let threshold_source = value_sources
        .iter()
        .find(|s| s.key == "compilation.confidence_threshold")
        .map(|s| s.source.clone())
        .unwrap_or_else(|| "default".to_string());

    let decision = build_diagnose_decision(&details.classification, threshold);
    let would_intercept = decision.would_intercept;

    debug!(
        "Diagnose input='{}' normalized='{}'",
        details.original, details.normalized
    );
    debug!(
        "Classification confidence={:.2} reason='{}'",
        details.classification.confidence, details.classification.reason
    );
    debug!(
        "Confidence threshold={:.2} source='{}'",
        threshold, threshold_source
    );
    for tier in &details.tiers {
        debug!(
            "Tier {} {} decision={:?} reason='{}'",
            tier.tier, tier.name, tier.decision, tier.reason
        );
    }

    let required_runtime = required_runtime_for_kind(details.classification.kind);
    let socket_path = config.general.socket_path.clone();
    let socket_exists = Path::new(&socket_path).exists();

    // Run capabilities probe and daemon health check in parallel
    let capabilities_future = probe_local_capabilities();
    let daemon_health_future = async {
        if socket_exists {
            query_daemon_health(&socket_path).await.ok()
        } else {
            None
        }
    };

    let (local_capabilities, daemon_health) =
        tokio::join!(capabilities_future, daemon_health_future);

    let local_has_any = has_any_capabilities(&local_capabilities);
    let mut capabilities_warnings = Vec::new();

    let mut daemon_status = DiagnoseDaemonStatus {
        socket_path: socket_path.clone(),
        socket_exists,
        reachable: false,
        status: None,
        version: None,
        uptime_seconds: None,
        error: None,
    };

    if let Some(health) = daemon_health {
        daemon_status.reachable = true;
        daemon_status.status = Some(health.status);
        daemon_status.version = Some(health.version);
        daemon_status.uptime_seconds = Some(health.uptime_seconds);
        debug!(
            "Daemon health ok status='{}' version='{}' uptime={}s",
            daemon_status.status.as_deref().unwrap_or("unknown"),
            daemon_status.version.as_deref().unwrap_or("unknown"),
            daemon_status.uptime_seconds.unwrap_or(0)
        );
    } else if socket_exists {
        daemon_status.error = Some("health check failed".to_string());
        debug!("Daemon health check failed");
    } else {
        daemon_status.error = Some("daemon socket not found".to_string());
        debug!("Daemon socket not found: {}", socket_path);
    }

    let mut worker_selection = None;
    if would_intercept && daemon_status.reachable {
        let estimated_cores = 4;
        let project_root = std::env::current_dir().ok();
        let project = project_root
            .as_ref()
            .map(|path| project_id_from_path(path))
            .unwrap_or_else(|| "unknown".to_string());
        let toolchain = project_root
            .as_ref()
            .and_then(|root| detect_toolchain(root).ok());

        match query_daemon(
            &socket_path,
            &project,
            estimated_cores,
            command,
            toolchain.as_ref(),
            required_runtime,
            CommandPriority::Normal,
            0,
            None,
        )
        .await
        {
            Ok(response) => {
                if let Some(worker) = response.worker.as_ref()
                    && let Err(err) = release_worker(
                        &socket_path,
                        &worker.id,
                        estimated_cores,
                        None,
                        None,
                        None,
                        None,
                        None, // timing
                    )
                    .await
                {
                    debug!("Failed to release worker slots: {}", err);
                }
                worker_selection = Some(DiagnoseWorkerSelection {
                    estimated_cores,
                    worker: response.worker.clone(),
                    reason: response.reason.clone(),
                });
                if let Some(worker) = response.worker.as_ref() {
                    debug!(
                        "Worker selected id='{}' slots_available={} speed_score={:.2} reason={:?}",
                        worker.id, worker.slots_available, worker.speed_score, response.reason
                    );
                } else {
                    debug!("No worker selected reason={:?}", response.reason);
                }
            }
            Err(err) => {
                daemon_status.error = Some(format!("selection request failed: {}", err));
                debug!("Worker selection request failed: {}", err);
            }
        }
    }

    if details.classification.is_compilation {
        if daemon_status.reachable {
            match query_workers_capabilities(false).await {
                Ok(response) => {
                    if required_runtime != RequiredRuntime::None {
                        let missing: Vec<String> = response
                            .workers
                            .iter()
                            .filter(|worker| {
                                let caps = &worker.capabilities;
                                match &required_runtime {
                                    RequiredRuntime::Rust => !caps.has_rust(),
                                    RequiredRuntime::Bun => !caps.has_bun(),
                                    RequiredRuntime::Node => !caps.has_node(),
                                    RequiredRuntime::None => false,
                                }
                            })
                            .map(|worker| worker.id.clone())
                            .collect();

                        if !missing.is_empty() {
                            capabilities_warnings.push(format!(
                                "Workers missing required runtime {}: {}",
                                runtime_label(&required_runtime),
                                missing.join(", ")
                            ));
                        }
                    }

                    if local_has_any {
                        capabilities_warnings.extend(collect_local_capability_warnings(
                            &response.workers,
                            &local_capabilities,
                        ));
                    }
                }
                Err(err) => {
                    capabilities_warnings.push(format!("Worker capabilities unavailable: {}", err));
                }
            }
        } else if required_runtime != RequiredRuntime::None {
            capabilities_warnings
                .push("Worker capabilities unavailable (daemon not reachable)".to_string());
        }
    }

    // Build dry-run summary if requested
    let dry_run_summary = if dry_run {
        Some(build_dry_run_summary(
            would_intercept,
            &decision.reason,
            &worker_selection,
            daemon_status.reachable,
        ))
    } else {
        None
    };

    if ctx.is_json() {
        let response = DiagnoseResponse {
            classification: details.classification.clone(),
            tiers: details.tiers.clone(),
            command: details.original.clone(),
            normalized_command: details.normalized.clone(),
            decision: DiagnoseDecision {
                would_intercept: decision.would_intercept,
                reason: decision.reason.clone(),
            },
            threshold: DiagnoseThreshold {
                value: threshold,
                source: threshold_source.clone(),
            },
            daemon: daemon_status,
            required_runtime,
            local_capabilities: local_has_any.then(|| local_capabilities.clone()),
            capabilities_warnings: capabilities_warnings.clone(),
            worker_selection,
            dry_run: dry_run_summary.clone(),
        };
        let _ = ctx.json(&ApiResponse::ok("diagnose", response));
        return Ok(());
    }

    // Display dry-run pipeline if requested
    if dry_run {
        println!("{}", style.format_header("RCH Dry Run"));
        println!();
        if let Some(ref summary) = dry_run_summary {
            let offload_label = if summary.would_offload {
                style.format_success("YES")
            } else {
                style.format_warning("NO")
            };
            println!(
                "{} {} {}",
                style.key("Would offload:"),
                offload_label,
                style.muted(&format!("({})", summary.reason))
            );
            println!();
            println!("{}", style.highlight("Pipeline Steps"));
            for step in &summary.pipeline_steps {
                let status = if step.skipped {
                    style.muted("[SKIP]")
                } else {
                    style.success("[RUN]")
                };
                println!(
                    "  {} {} {}",
                    status,
                    style.value(&format!("{}.", step.step)),
                    style.highlight(&step.name)
                );
                println!("     {}", style.muted(&step.description));
                if let Some(ref reason) = step.skip_reason {
                    println!("     {} {}", style.warning("Skip:"), style.muted(reason));
                }
                if let Some(ms) = step.estimated_duration_ms {
                    println!("     {} ~{}ms", style.muted("Est:"), ms);
                }
            }
            if let Some(ref transfer) = summary.transfer_estimate {
                println!();
                println!("{}", style.highlight("Transfer Estimate"));
                println!(
                    "  {} {} ({} files)",
                    style.key("Size:"),
                    style.value(&transfer.human_size),
                    transfer.files
                );
                println!("  {} ~{}ms", style.key("Time:"), transfer.estimated_time_ms);
                if transfer.would_skip {
                    println!(
                        "  {} {}",
                        style.warning("Would skip:"),
                        transfer
                            .skip_reason
                            .as_deref()
                            .unwrap_or("threshold exceeded")
                    );
                }
            }
            if let Some(total_ms) = summary.total_estimated_ms {
                println!();
                println!("{} ~{}ms", style.key("Total estimated:"), total_ms);
            }
        }
        println!();
        println!(
            "  {} This is a dry run. No network calls were made.",
            style.muted("ℹ")
        );
        return Ok(());
    }

    println!("{}", style.format_header("RCH Diagnose"));
    println!();

    println!("{}", style.highlight("Command Analysis"));
    println!(
        "  {} {}",
        style.key("Input:"),
        style.value(details.original.trim())
    );
    if details.normalized != details.original.trim() {
        println!(
            "  {} {}",
            style.key("Normalized:"),
            style.value(details.normalized.trim())
        );
    }
    println!("  {} {}", style.key("Tool:"), style.value("Bash"));
    println!();

    println!("{}", style.highlight("Classification"));
    let kind_label = details
        .classification
        .kind
        .map(|k| format!("{:?}", k))
        .unwrap_or_else(|| "none".to_string());
    println!("  {} {}", style.key("Kind:"), style.value(&kind_label));
    println!(
        "  {} {} {}",
        style.key("Confidence:"),
        style.value(&format!("{:.2}", details.classification.confidence)),
        style.muted(&format!("({})", details.classification.reason))
    );
    println!(
        "  {} {} {}",
        style.key("Threshold:"),
        style.value(&format!("{:.2}", threshold)),
        style.muted(&format!("# from {}", threshold_source))
    );

    let decision_label = if would_intercept {
        style.format_success("WOULD INTERCEPT")
    } else {
        style.format_warning("WOULD NOT INTERCEPT")
    };
    println!("  {} {}", style.key("Decision:"), decision_label);
    println!(
        "  {} {}",
        style.key("Reason:"),
        style.value(&decision.reason)
    );
    println!();

    println!("{}", style.highlight("Runtime Capabilities"));
    println!(
        "  {} {}",
        style.key("Required runtime:"),
        style.value(runtime_label(&required_runtime))
    );
    println!(
        "  {} {}",
        style.key("Local runtimes:"),
        style.value(&summarize_capabilities(&local_capabilities))
    );
    if capabilities_warnings.is_empty() {
        println!("  {} {}", style.key("Warnings:"), style.value("none"));
    } else {
        for warning in &capabilities_warnings {
            println!(
                "  {} {}",
                StatusIndicator::Warning.display(style),
                style.warning(warning)
            );
        }
    }
    println!();

    println!("{}", style.highlight("Tier Decisions"));
    for tier in &details.tiers {
        let decision = match tier.decision {
            rch_common::TierDecision::Pass => style.format_success("PASS"),
            rch_common::TierDecision::Reject => style.format_warning("REJECT"),
        };
        println!(
            "  {} {} {} {}",
            style.key(&format!("Tier {}:", tier.tier)),
            style.value(&tier.name),
            style.muted("→"),
            decision
        );
        println!("    {} {}", style.muted("reason:"), tier.reason);
    }
    println!();

    println!("{}", style.highlight("Daemon Status"));
    println!(
        "  {} {}",
        style.key("Socket:"),
        style.value(&daemon_status.socket_path)
    );
    println!(
        "  {} {}",
        style.key("Socket exists:"),
        style.value(&daemon_status.socket_exists.to_string())
    );
    println!(
        "  {} {}",
        style.key("Reachable:"),
        style.value(&daemon_status.reachable.to_string())
    );
    if let Some(status) = &daemon_status.status {
        println!("  {} {}", style.key("Status:"), style.value(status));
    }
    if let Some(version) = &daemon_status.version {
        println!("  {} {}", style.key("Version:"), style.value(version));
    }
    if let Some(uptime) = daemon_status.uptime_seconds {
        println!(
            "  {} {}s",
            style.key("Uptime:"),
            style.value(&uptime.to_string())
        );
    }
    if let Some(error) = &daemon_status.error {
        println!("  {} {}", style.key("Error:"), style.value(error));
    }
    println!();

    // Show transfer exclude info including .rchignore
    println!("{}", style.highlight("Transfer Configuration"));
    let config_exclude_count = config.transfer.exclude_patterns.len();
    let project_root = std::env::current_dir().ok();
    let rchignore_count = project_root
        .as_ref()
        .and_then(|root| crate::transfer::parse_rchignore(&root.join(".rchignore")).ok())
        .map(|patterns| patterns.len())
        .unwrap_or(0);
    let effective_count = config_exclude_count + rchignore_count;

    println!(
        "  {} {} {}",
        style.key("Exclude patterns:"),
        style.value(&effective_count.to_string()),
        style.muted(&format!(
            "({} from config, {} from .rchignore)",
            config_exclude_count, rchignore_count
        ))
    );
    if rchignore_count > 0 {
        println!(
            "  {} {}",
            style.key(".rchignore:"),
            style.format_success("detected")
        );
    } else {
        println!(
            "  {} {}",
            style.key(".rchignore:"),
            style.muted("not found")
        );
    }
    println!(
        "  {} {}",
        style.key("Compression:"),
        style.value(&format!("zstd level {}", config.transfer.compression_level))
    );
    println!(
        "  {} {}",
        style.key("Remote base:"),
        style.value(&config.transfer.remote_base)
    );
    println!();

    println!("{}", style.highlight("Worker Selection (simulated)"));
    if let Some(selection) = &worker_selection {
        match &selection.worker {
            Some(worker) => {
                println!(
                    "  {} {}",
                    style.key("Selected:"),
                    style.value(&worker.id.to_string())
                );
                println!(
                    "  {} {}@{}",
                    style.key("Host:"),
                    style.value(&worker.user),
                    style.value(&worker.host)
                );
                println!(
                    "  {} {}",
                    style.key("Slots available:"),
                    style.value(&worker.slots_available.to_string())
                );
                println!("  {} {:.1}", style.key("Speed score:"), worker.speed_score);
                println!(
                    "  {} {}",
                    style.key("Reason:"),
                    style.value(&selection.reason.to_string())
                );
            }
            None => {
                println!(
                    "  {} {}",
                    style.key("Result:"),
                    style.value("No worker selected")
                );
                println!(
                    "  {} {}",
                    style.key("Reason:"),
                    style.value(&selection.reason.to_string())
                );
            }
        }
    } else if !would_intercept {
        println!(
            "  {} {}",
            style.key("Skipped:"),
            style.value("Command would not be intercepted")
        );
    } else if !daemon_status.reachable {
        println!(
            "  {} {}",
            style.key("Skipped:"),
            style.value("Daemon not reachable")
        );
    } else {
        println!(
            "  {} {}",
            style.key("Skipped:"),
            style.value("Selection unavailable")
        );
    }

    Ok(())
}

// =============================================================================
// Hook Commands
// =============================================================================

/// Install the Claude Code hook.
pub fn hook_install(ctx: &OutputContext) -> Result<()> {
    let style = ctx.theme();

    // Claude Code hooks are configured in ~/.claude/settings.json
    let claude_config_dir = dirs::home_dir()
        .map(|h| h.join(".claude"))
        .context("Could not find home directory")?;

    let settings_path = claude_config_dir.join("settings.json");

    if !ctx.is_json() {
        println!("Installing RCH hook for Claude Code...\n");
    }

    // Find the rch binary path
    let rch_path = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("rch"));

    // Create or update settings.json
    let mut settings: serde_json::Value = if settings_path.exists() {
        let content = std::fs::read_to_string(&settings_path)?;
        serde_json::from_str(&content).unwrap_or(serde_json::json!({}))
    } else {
        std::fs::create_dir_all(&claude_config_dir)?;
        serde_json::json!({})
    };

    // Add or update the hooks section
    let hooks = settings
        .as_object_mut()
        .context("Settings must be an object")?
        .entry("hooks")
        .or_insert(serde_json::json!({}));

    let hooks_obj = hooks.as_object_mut().context("Hooks must be an object")?;

    // Add PreToolUse hook for Bash (new array format with matchers)
    // Note: rch runs as hook when invoked without a subcommand, so no args needed
    // matcher: "Bash" matches the Bash tool name
    hooks_obj.insert(
        "PreToolUse".to_string(),
        serde_json::json!([
            {
                "matcher": "Bash",
                "hooks": [{"type": "command", "command": rch_path.to_string_lossy()}]
            }
        ]),
    );

    // Write back to file
    let new_content = serde_json::to_string_pretty(&settings)?;
    std::fs::write(&settings_path, new_content)?;

    if ctx.is_json() {
        let _ = ctx.json(&ApiResponse::ok(
            "hook install",
            HookActionResponse {
                action: "install".to_string(),
                success: true,
                settings_path: settings_path.display().to_string(),
                message: Some("Hook installed successfully".to_string()),
            },
        ));
    } else {
        println!(
            "{} Hook installed in {}",
            StatusIndicator::Success.display(style),
            style.highlight(&settings_path.display().to_string())
        );
        println!(
            "  {} Claude Code will now use RCH for Bash commands.",
            StatusIndicator::Info.display(style)
        );

        // Run quick health check
        let quick_result = crate::doctor::run_quick_check();
        crate::doctor::print_quick_check_summary(&quick_result, ctx);
    }

    Ok(())
}

/// Uninstall the Claude Code hook.
pub fn hook_uninstall(ctx: &OutputContext) -> Result<()> {
    let style = ctx.theme();

    let claude_config_dir = dirs::home_dir()
        .map(|h| h.join(".claude"))
        .context("Could not find home directory")?;

    let settings_path = claude_config_dir.join("settings.json");

    if !settings_path.exists() {
        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::<()>::err(
                "hook uninstall",
                ApiError::new(
                    ErrorCode::ConfigNotFound,
                    "Claude Code settings file not found",
                ),
            ));
        } else {
            println!(
                "{} Settings file not found: {}",
                StatusIndicator::Warning.display(style),
                settings_path.display()
            );
        }
        return Ok(());
    }

    let content = std::fs::read_to_string(&settings_path)?;
    let mut settings: serde_json::Value = serde_json::from_str(&content)?;

    let removed = if let Some(hooks) = settings.get_mut("hooks") {
        if let Some(hooks_obj) = hooks.as_object_mut() {
            hooks_obj.remove("PreToolUse").is_some()
        } else {
            false
        }
    } else {
        false
    };

    if removed {
        let new_content = serde_json::to_string_pretty(&settings)?;
        std::fs::write(&settings_path, new_content)?;

        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::ok(
                "hook uninstall",
                HookActionResponse {
                    action: "uninstall".to_string(),
                    success: true,
                    settings_path: settings_path.display().to_string(),
                    message: Some("Hook removed successfully".to_string()),
                },
            ));
        } else {
            println!(
                "{} Hook removed from {}",
                StatusIndicator::Success.display(style),
                style.highlight(&settings_path.display().to_string())
            );
        }
    } else if ctx.is_json() {
        let _ = ctx.json(&ApiResponse::ok(
            "hook uninstall",
            HookActionResponse {
                action: "uninstall".to_string(),
                success: false,
                settings_path: settings_path.display().to_string(),
                message: Some("Hook was not found".to_string()),
            },
        ));
    } else {
        println!(
            "{} Hook not found in settings.",
            StatusIndicator::Info.display(style)
        );
    }

    Ok(())
}

/// Display hook installation status.
pub fn hook_status(ctx: &OutputContext) -> Result<()> {
    use crate::agent::{AgentKind, HookStatus, check_hook_status};

    let style = ctx.theme();

    if !ctx.is_json() {
        println!("{}", style.format_header("Hook Status"));
        println!();
    }

    // Check status for supported agents
    let supported_agents = [
        AgentKind::ClaudeCode,
        AgentKind::GeminiCli,
        AgentKind::CodexCli,
        AgentKind::ContinueDev,
    ];

    let mut statuses = Vec::new();
    for kind in &supported_agents {
        let status = check_hook_status(*kind).unwrap_or(HookStatus::NotSupported);
        if !ctx.is_json() {
            let indicator = match status {
                HookStatus::Installed => StatusIndicator::Success,
                HookStatus::NeedsUpdate => StatusIndicator::Warning,
                HookStatus::NotInstalled => StatusIndicator::Info,
                HookStatus::NotSupported => StatusIndicator::Pending,
            };
            println!(
                "  {} {}: {}",
                indicator.display(style),
                style.key(&format!("{:?}", kind)),
                status
            );
        }
        statuses.push(serde_json::json!({
            "agent": format!("{:?}", kind),
            "status": status.to_string(),
        }));
    }

    if ctx.is_json() {
        let _ = ctx.json(&ApiResponse::ok(
            "hook status",
            serde_json::json!({
                "agents": statuses,
            }),
        ));
    }

    Ok(())
}

/// Helper to get rchd path.
fn which_rchd() -> PathBuf {
    // Try to find rchd in same directory as current executable
    if let Ok(exe_path) = std::env::current_exe()
        && let Some(dir) = exe_path.parent()
    {
        let rchd = dir.join("rchd");
        if rchd.exists() {
            return rchd;
        }
    }

    // Fallback to path lookup
    which::which("rchd").unwrap_or_else(|_| PathBuf::from("rchd"))
}

/// Helper to send command to daemon socket.
#[cfg(not(unix))]
async fn send_daemon_command(_command: &str) -> Result<String> {
    bail!("daemon commands are only supported on Unix-like platforms");
}

#[cfg(unix)]
async fn send_daemon_command(command: &str) -> Result<String> {
    let config = crate::config::load_config()?;
    let expanded = shellexpand::tilde(&config.general.socket_path);
    let socket_path = Path::new(expanded.as_ref());
    if !socket_path.exists() {
        bail!("Daemon socket not found at {:?}", socket_path);
    }

    let stream = UnixStream::connect(socket_path).await?;
    let (reader, mut writer) = stream.into_split();

    writer.write_all(command.as_bytes()).await?;
    writer.flush().await?;

    let mut reader = BufReader::new(reader);
    let mut response = String::new();
    reader.read_to_string(&mut response).await?;

    Ok(response)
}

// =============================================================================
// Self-Test Command
// =============================================================================

#[allow(clippy::too_many_arguments)]
pub async fn self_test(
    action: Option<crate::SelfTestAction>,
    worker: Option<String>,
    all: bool,
    project: Option<PathBuf>,
    timeout: u64,
    debug: bool,
    scheduled: bool,
    ctx: &OutputContext,
) -> Result<()> {
    match action {
        Some(crate::SelfTestAction::Status) => self_test_status(ctx).await,
        Some(crate::SelfTestAction::History { limit }) => self_test_history(limit, ctx).await,
        None => self_test_run(worker, all, project, timeout, debug, scheduled, ctx).await,
    }
}

async fn self_test_status(ctx: &OutputContext) -> Result<()> {
    let response = send_daemon_command("GET /self-test/status\n").await?;
    let json = extract_json_body(&response).ok_or_else(|| anyhow::anyhow!("Invalid response"))?;
    let status: SelfTestStatusResponse = serde_json::from_str(json)?;

    let _ = ctx.json(&status);
    if ctx.is_json() {
        return Ok(());
    }

    let style = ctx.style();
    println!("{}", style.format_header("Self-Test Status"));
    println!(
        "  {} {} {}",
        style.key("Scheduled"),
        style.muted(":"),
        if status.enabled {
            style.success("Enabled")
        } else {
            style.warning("Disabled")
        }
    );

    if let Some(schedule) = status.schedule.as_ref() {
        println!(
            "  {} {} {}",
            style.key("Schedule"),
            style.muted(":"),
            style.info(schedule)
        );
    }
    if let Some(interval) = status.interval.as_ref() {
        println!(
            "  {} {} {}",
            style.key("Interval"),
            style.muted(":"),
            style.info(interval)
        );
    }
    if let Some(last) = status.last_run.as_ref() {
        println!(
            "  {} {} {} ({} passed, {} failed)",
            style.key("Last run"),
            style.muted(":"),
            style.info(&last.completed_at),
            last.workers_passed,
            last.workers_failed
        );
    }
    if let Some(next) = status.next_run.as_ref() {
        println!(
            "  {} {} {}",
            style.key("Next run"),
            style.muted(":"),
            style.info(next)
        );
    }

    Ok(())
}

async fn self_test_history(limit: usize, ctx: &OutputContext) -> Result<()> {
    let command = format!("GET /self-test/history?limit={}\n", limit);
    let response = send_daemon_command(&command).await?;
    let json = extract_json_body(&response).ok_or_else(|| anyhow::anyhow!("Invalid response"))?;
    let history: SelfTestHistoryResponse = serde_json::from_str(json)?;

    let _ = ctx.json(&history);
    if ctx.is_json() {
        return Ok(());
    }

    let style = ctx.style();
    println!("{}", style.format_header("Self-Test History"));
    if history.runs.is_empty() {
        println!("  {}", style.muted("No self-test runs recorded."));
        return Ok(());
    }

    let rows: Vec<Vec<String>> = history
        .runs
        .iter()
        .map(|run| {
            vec![
                run.id.to_string(),
                run.run_type.clone(),
                run.completed_at.clone(),
                format!("{}ms", run.duration_ms),
                run.workers_passed.to_string(),
                run.workers_failed.to_string(),
            ]
        })
        .collect();

    ctx.table(
        &["ID", "Type", "Completed", "Duration", "Passed", "Failed"],
        &rows,
    );

    for run in &history.runs {
        if run.workers_failed == 0 {
            continue;
        }
        println!(
            "\n  {} {}",
            style.key("Failures for run"),
            style.highlight(&run.id.to_string())
        );
        for result in history
            .results
            .iter()
            .filter(|r| r.run_id == run.id && !r.passed)
        {
            let error = result
                .error
                .clone()
                .unwrap_or_else(|| "unknown".to_string());
            println!(
                "    {} {}: {}",
                StatusIndicator::Error.display(style),
                style.highlight(&result.worker_id),
                style.error(&error)
            );
        }
    }

    Ok(())
}

async fn self_test_run(
    worker: Option<String>,
    all: bool,
    project: Option<PathBuf>,
    timeout: u64,
    debug: bool,
    scheduled: bool,
    ctx: &OutputContext,
) -> Result<()> {
    let mut worker_ids = Vec::new();

    if scheduled {
        // Scheduled run uses daemon config (ignore worker selection).
    } else if all {
        // Empty worker list signals "all" to daemon.
    } else if let Some(worker) = worker {
        worker_ids.push(worker);
    } else {
        let workers = load_workers_from_config()?;
        let first = workers
            .first()
            .ok_or_else(|| anyhow::anyhow!("No workers configured"))?;
        worker_ids.push(first.id.to_string());
    }

    let mut query = Vec::new();
    for id in &worker_ids {
        query.push(format!("worker={}", urlencoding_encode(id)));
    }
    if all {
        query.push("all=true".to_string());
    }
    if scheduled {
        query.push("scheduled=true".to_string());
    }
    if let Some(path) = project.as_ref() {
        query.push(format!(
            "project={}",
            urlencoding_encode(&path.display().to_string())
        ));
    }
    if timeout > 0 {
        query.push(format!("timeout={}", timeout));
    }
    if debug {
        query.push("debug=true".to_string());
    }

    let command = if query.is_empty() {
        "POST /self-test/run\n".to_string()
    } else {
        format!("POST /self-test/run?{}\n", query.join("&"))
    };

    let response = send_daemon_command(&command).await?;
    let json = extract_json_body(&response).ok_or_else(|| anyhow::anyhow!("Invalid response"))?;
    let run: SelfTestRunResponse = serde_json::from_str(json)?;

    let _ = ctx.json(&run);
    if ctx.is_json() {
        return Ok(());
    }

    let style = ctx.style();
    println!("{}", style.format_header("Self-Test Result"));
    println!(
        "  {} {} {}",
        style.key("Run"),
        style.muted(":"),
        style.info(&run.run.completed_at)
    );
    println!(
        "  {} {} {} passed, {} failed",
        style.key("Workers"),
        style.muted(":"),
        style.success(&run.run.workers_passed.to_string()),
        style.error(&run.run.workers_failed.to_string())
    );

    for result in &run.results {
        let status = if result.passed {
            StatusIndicator::Success.display(style)
        } else {
            StatusIndicator::Error.display(style)
        };
        let detail = if result.passed {
            format!(
                "remote={}ms local={}ms",
                result.remote_time_ms.unwrap_or(0),
                result.local_time_ms.unwrap_or(0)
            )
        } else {
            result
                .error
                .clone()
                .unwrap_or_else(|| "unknown error".to_string())
        };
        println!(
            "  {} {}: {}",
            status,
            style.highlight(&result.worker_id),
            detail
        );
    }

    Ok(())
}

/// URL percent-encoding for query parameters.
/// Optimized to avoid allocations by using direct hex conversion.
fn urlencoding_encode(s: &str) -> String {
    // Hex digits lookup table for zero-allocation encoding
    const HEX_DIGITS: &[u8; 16] = b"0123456789ABCDEF";

    let mut result = String::with_capacity(s.len() * 3);
    for byte in s.as_bytes() {
        match *byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(*byte as char);
            }
            _ => {
                result.push('%');
                result.push(HEX_DIGITS[(byte >> 4) as usize] as char);
                result.push(HEX_DIGITS[(byte & 0x0F) as usize] as char);
            }
        }
    }
    result
}

pub async fn status_overview(workers: bool, jobs: bool, ctx: &OutputContext) -> Result<()> {
    // Query daemon for full status.
    let response = send_daemon_command("GET /status\n").await?;
    let json = extract_json_body(&response)
        .ok_or_else(|| anyhow::anyhow!("Invalid response format from daemon"))?;
    let status: DaemonFullStatusResponse =
        serde_json::from_str(json).context("Failed to parse daemon status response")?;

    if ctx.is_json() {
        let _ = ctx.json(&ApiResponse::ok("status", &status));
        return Ok(());
    }

    crate::status_display::render_full_status(&status, workers, jobs, ctx.style());
    Ok(())
}

/// Display build queue - active builds and worker availability.
pub async fn queue_status(watch: bool, ctx: &OutputContext) -> Result<()> {
    loop {
        // Query daemon for full status
        let response = send_daemon_command("GET /status\n").await?;
        let json = extract_json_body(&response)
            .ok_or_else(|| anyhow::anyhow!("Invalid response format from daemon"))?;
        let status: DaemonFullStatusResponse =
            serde_json::from_str(json).context("Failed to parse daemon status response")?;

        // JSON output for scripting (pure JSON on stdout; no other output).
        if ctx.is_json() {
            let mut workers_available = 0;
            let mut workers_busy = 0;
            let mut workers_offline = 0;

            for worker in &status.workers {
                match worker.status.as_str() {
                    "healthy" | "degraded" | "draining" => {
                        if worker.used_slots >= worker.total_slots {
                            workers_busy += 1;
                        } else {
                            workers_available += 1;
                        }
                    }
                    "unreachable" | "disabled" => workers_offline += 1,
                    _ => {}
                }
            }

            let queue_data = serde_json::json!({
                "active_builds": status.active_builds,
                "queued_builds": status.queued_builds,
                "queue_depth": status.queued_builds.len(),
                "workers_available": workers_available,
                "workers_busy": workers_busy,
                "workers_offline": workers_offline,
                "workers_total": status.daemon.workers_total,
                "workers_healthy": status.daemon.workers_healthy,
                "slots_available": status.daemon.slots_available,
                "slots_total": status.daemon.slots_total,
                "timestamp": chrono::Utc::now().to_rfc3339()
            });
            let _ = ctx.json(&ApiResponse::ok("queue", queue_data));
            return Ok(());
        }

        // In watch mode, clear screen
        if watch {
            print!("\x1B[2J\x1B[H"); // ANSI clear screen and move cursor to top
        }

        let style = ctx.style();

        // Header
        println!(
            "{} {}",
            style.highlight("Build Queue"),
            style.muted(&format!("({})", chrono::Local::now().format("%H:%M:%S")))
        );
        println!("{}", style.muted(&"─".repeat(40)));
        println!();

        // Active builds section
        if status.active_builds.is_empty() {
            println!("{}", style.muted("  No active builds"));
        } else {
            println!(
                "  {} {}",
                style.success("●"),
                style.key(&format!("{} Active Build(s)", status.active_builds.len()))
            );
            println!();

            for build in &status.active_builds {
                // Calculate elapsed time
                let elapsed =
                    if let Ok(started) = chrono::DateTime::parse_from_rfc3339(&build.started_at) {
                        let duration = chrono::Utc::now().signed_duration_since(started);
                        format_build_duration(duration.num_seconds().max(0) as u64)
                    } else {
                        "?".to_string()
                    };

                // Truncate command for display
                let cmd_display = if build.command.len() > 50 {
                    format!("{}...", &build.command[..47])
                } else {
                    build.command.clone()
                };

                println!(
                    "  {} {} {} {} {} {}",
                    style.info(&format!("#{}", build.id)),
                    style.muted("on"),
                    style.key(&build.worker_id),
                    style.muted("|"),
                    style.value(&cmd_display),
                    style.warning(&format!("[{}]", elapsed))
                );

                // Show project
                let project_display = if build.project_id.len() > 30 {
                    format!("...{}", &build.project_id[build.project_id.len() - 27..])
                } else {
                    build.project_id.clone()
                };
                println!(
                    "      {} {}",
                    style.muted("project:"),
                    style.value(&project_display)
                );
            }
        }
        println!();

        // Queued builds section
        if !status.queued_builds.is_empty() {
            println!(
                "  {} {}",
                style.warning("◌"),
                style.key(&format!("{} Queued Build(s)", status.queued_builds.len()))
            );
            println!();

            for build in &status.queued_builds {
                // Truncate command for display
                let cmd_display = if build.command.len() > 50 {
                    format!("{}...", &build.command[..47])
                } else {
                    build.command.clone()
                };

                // Show position and estimated wait
                let estimate_display = build
                    .estimated_start
                    .as_ref()
                    .map(|_| format!("~{}", build.wait_time))
                    .unwrap_or_else(|| build.wait_time.clone());

                println!(
                    "  {} {} {} {} {}",
                    style.info(&format!("#{}", build.id)),
                    style.muted("|"),
                    style.value(&cmd_display),
                    style.muted("waiting"),
                    style.warning(&format!("[{}]", estimate_display))
                );

                // Show project
                let project_display = if build.project_id.len() > 30 {
                    format!("...{}", &build.project_id[build.project_id.len() - 27..])
                } else {
                    build.project_id.clone()
                };
                println!(
                    "      {} {}  {} {}",
                    style.muted("project:"),
                    style.value(&project_display),
                    style.muted("position:"),
                    style.value(&build.position.to_string())
                );
            }
            println!();
        }

        // Worker availability summary
        println!("{}", style.key("Worker Availability"));
        println!();

        let mut healthy_count = 0;
        let mut busy_count = 0;
        let mut offline_count = 0;

        for worker in &status.workers {
            match worker.status.as_str() {
                "healthy" | "degraded" | "draining" => {
                    if worker.used_slots >= worker.total_slots {
                        busy_count += 1;
                    } else {
                        healthy_count += 1;
                    }
                }
                "unreachable" | "disabled" => offline_count += 1,
                _ => {}
            }
        }

        println!(
            "  {} {} available  {} {} busy  {} {} offline",
            style.success("●"),
            healthy_count,
            style.warning("●"),
            busy_count,
            style.error("●"),
            offline_count
        );
        println!();

        // Slot summary
        println!(
            "  {} {} / {} slots free",
            style.info("→"),
            status.daemon.slots_available,
            status.daemon.slots_total
        );

        if !watch {
            break;
        }

        // Wait 1 second before refresh
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }

    Ok(())
}

/// Cancel an active build (or all builds) via the daemon API.
pub async fn cancel_build(
    build_id: Option<u64>,
    all: bool,
    force: bool,
    yes: bool,
    ctx: &OutputContext,
) -> Result<()> {
    use dialoguer::Confirm;

    if all && build_id.is_some() {
        tracing::debug!("Ignoring build_id since --all was provided");
    }

    if all && !yes && !ctx.is_json() {
        let confirmed = Confirm::new()
            .with_prompt("Cancel all active builds?")
            .default(false)
            .interact()
            .unwrap_or(false);
        if !confirmed {
            println!("{}", ctx.style().muted("No builds cancelled."));
            return Ok(());
        }
    }

    let command = if all {
        format!(
            "POST /builds/cancel-all?force={}\n",
            if force { "true" } else { "false" }
        )
    } else {
        let build_id =
            build_id.ok_or_else(|| anyhow::anyhow!("Missing build id (or use --all)"))?;
        format!(
            "POST /builds/{}/cancel?force={}\n",
            build_id,
            if force { "true" } else { "false" }
        )
    };

    let response = send_daemon_command(&command).await?;
    let json = extract_json_body(&response)
        .ok_or_else(|| anyhow::anyhow!("Invalid response format from daemon"))?;
    let payload: serde_json::Value =
        serde_json::from_str(json).context("Failed to parse cancellation response")?;

    let _ = ctx.json(&payload);
    if ctx.is_json() {
        return Ok(());
    }

    let style = ctx.style();
    let status = payload
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    match status {
        "cancelled" => {
            let id = payload.get("build_id").and_then(|v| v.as_u64());
            let msg = payload
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if let Some(id) = id {
                println!(
                    "{} {} {}",
                    style.success("Cancelled"),
                    style.muted("build"),
                    style.value(&id.to_string())
                );
            } else {
                println!("{}", style.success("Cancelled build"));
            }
            if !msg.is_empty() {
                println!("  {}", style.muted(msg));
            }
        }
        "ok" => {
            // cancel-all response when nothing to do, or generic success
            if let Some(msg) = payload.get("message").and_then(|v| v.as_str()) {
                println!("{}", style.info(msg));
            } else {
                println!("{}", style.success("OK"));
            }
        }
        "error" => {
            let msg = payload
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("error");
            println!("{} {}", style.error("Error:"), style.value(msg));
        }
        other => {
            println!("{} {}", style.key("Status:"), style.value(other));
            if let Some(msg) = payload.get("message").and_then(|v| v.as_str()) {
                println!("  {}", style.muted(msg));
            }
        }
    }

    Ok(())
}

/// Format build duration in human-readable form.
fn format_build_duration(secs: u64) -> String {
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        let hours = secs / 3600;
        let mins = (secs % 3600) / 60;
        format!("{}h {}m", hours, mins)
    }
}

// Stub for hook_test
pub async fn hook_test(_ctx: &OutputContext) -> Result<()> {
    // Implementation placeholder
    Ok(())
}

/// List detected AI coding agents and their RCH hook status.
pub fn agents_list(all: bool, ctx: &OutputContext) -> Result<()> {
    use crate::agent::{AgentKind, HookStatus, check_hook_status, detect_agents};

    let style = ctx.theme();

    // Detect all installed agents
    let detected = detect_agents()?;

    // Build agent info list
    let mut agent_infos: Vec<serde_json::Value> = Vec::new();

    // If --all flag, show all known agents; otherwise only detected ones
    let agents_to_show: Vec<AgentKind> = if all {
        AgentKind::ALL.to_vec()
    } else {
        detected.iter().map(|a| a.kind).collect()
    };

    for kind in &agents_to_show {
        let detected_info = detected.iter().find(|a| a.kind == *kind);
        let is_detected = detected_info.is_some();
        let hook_status = check_hook_status(*kind).unwrap_or(HookStatus::NotSupported);

        let info = serde_json::json!({
            "name": kind.name(),
            "kind": format!("{:?}", kind),
            "detected": is_detected,
            "version": detected_info.and_then(|d| d.version.clone()),
            "config_path": detected_info.and_then(|d| d.config_path.as_ref().map(|p| p.display().to_string())),
            "hook_support": format!("{}", kind.hook_support()),
            "hook_status": hook_status.to_string(),
            "can_install_hook": kind.hook_support().can_install_hook(),
        });
        agent_infos.push(info);
    }

    if ctx.is_json() {
        let _ = ctx.json(&ApiResponse::ok(
            "agents list",
            serde_json::json!({
                "agents": agent_infos,
                "total": agent_infos.len(),
                "detected": detected.len(),
            }),
        ));
        return Ok(());
    }

    // Human-readable output
    println!("{}", style.format_header("Detected AI Coding Agents"));
    println!();

    if agents_to_show.is_empty() {
        println!("  {} No AI coding agents detected.", style.muted("ℹ"));
        println!();
        println!("  Run with --all to see all known agents.");
        return Ok(());
    }

    for kind in &agents_to_show {
        let detected_info = detected.iter().find(|a| a.kind == *kind);
        let is_detected = detected_info.is_some();
        let hook_status = check_hook_status(*kind).unwrap_or(HookStatus::NotSupported);

        let status_indicator = if is_detected {
            match hook_status {
                HookStatus::Installed => StatusIndicator::Success,
                HookStatus::NeedsUpdate => StatusIndicator::Warning,
                HookStatus::NotInstalled => StatusIndicator::Info,
                HookStatus::NotSupported => StatusIndicator::Pending,
            }
        } else {
            StatusIndicator::Pending
        };

        let detected_label = if is_detected {
            style.success("detected")
        } else {
            style.muted("not found")
        };

        println!(
            "  {} {} {}",
            status_indicator.display(style),
            style.key(kind.name()),
            detected_label
        );

        if let Some(info) = detected_info {
            if let Some(ref version) = info.version {
                println!("      {} {}", style.muted("Version:"), style.value(version));
            }
            if let Some(ref path) = info.config_path {
                println!(
                    "      {} {}",
                    style.muted("Config:"),
                    style.value(&path.display().to_string())
                );
            }
        }

        println!(
            "      {} {}",
            style.muted("Hook:"),
            match hook_status {
                HookStatus::Installed => style.success(&hook_status.to_string()),
                HookStatus::NeedsUpdate => style.warning(&hook_status.to_string()),
                HookStatus::NotInstalled => style.value(&hook_status.to_string()),
                HookStatus::NotSupported => style.muted(&hook_status.to_string()),
            }
        );
        println!();
    }

    Ok(())
}

/// Show detailed status for a specific agent or all detected agents.
pub fn agents_status(agent: Option<String>, ctx: &OutputContext) -> Result<()> {
    use crate::agent::{AgentKind, HookStatus, check_hook_status, detect_single_agent};

    let style = ctx.theme();

    // If specific agent requested, show only that one
    if let Some(ref agent_name) = agent {
        let kind = AgentKind::from_id(agent_name).ok_or_else(|| {
            anyhow::anyhow!(
                "Unknown agent: {}. Valid agents: {:?}",
                agent_name,
                AgentKind::ALL.iter().map(|k| k.id()).collect::<Vec<_>>()
            )
        })?;

        let detected = detect_single_agent(kind)?;
        let hook_status = check_hook_status(kind).unwrap_or(HookStatus::NotSupported);

        let info = serde_json::json!({
            "name": kind.name(),
            "kind": format!("{:?}", kind),
            "detected": detected.is_some(),
            "version": detected.as_ref().and_then(|d| d.version.clone()),
            "config_path": detected.as_ref().and_then(|d| d.config_path.as_ref().map(|p| p.display().to_string())),
            "detection_method": detected.as_ref().map(|d| format!("{:?}", d.detection_method)),
            "hook_support": format!("{}", kind.hook_support()),
            "hook_status": hook_status.to_string(),
            "can_install_hook": kind.hook_support().can_install_hook(),
        });

        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::ok("agents status", info));
            return Ok(());
        }

        println!(
            "{}",
            style.format_header(&format!("Agent: {}", kind.name()))
        );
        println!();
        println!(
            "  {} {}",
            style.key("Detected:"),
            if detected.is_some() {
                style.success("Yes")
            } else {
                style.warning("No")
            }
        );
        if let Some(ref d) = detected {
            if let Some(ref version) = d.version {
                println!("  {} {}", style.key("Version:"), style.value(version));
            }
            if let Some(ref path) = d.config_path {
                println!(
                    "  {} {}",
                    style.key("Config:"),
                    style.value(&path.display().to_string())
                );
            }
            println!("  {} {:?}", style.key("Detection:"), d.detection_method);
        }
        println!(
            "  {} {}",
            style.key("Hook Support:"),
            style.value(&format!("{}", kind.hook_support()))
        );
        println!(
            "  {} {}",
            style.key("Hook Status:"),
            match hook_status {
                HookStatus::Installed => style.success(&hook_status.to_string()),
                HookStatus::NeedsUpdate => style.warning(&hook_status.to_string()),
                HookStatus::NotInstalled => style.value(&hook_status.to_string()),
                HookStatus::NotSupported => style.muted(&hook_status.to_string()),
            }
        );

        return Ok(());
    }

    // No specific agent - show all detected agents
    agents_list(false, ctx)
}

// Stub for agents_install_hook
pub fn agents_install_hook(_agent: &str, _dry_run: bool, _ctx: &OutputContext) -> Result<()> {
    // Implementation placeholder
    Ok(())
}

// Stub for agents_uninstall_hook
pub fn agents_uninstall_hook(_agent: &str, _dry_run: bool, _ctx: &OutputContext) -> Result<()> {
    // Implementation placeholder
    Ok(())
}

// =============================================================================
// SpeedScore Commands
// =============================================================================

/// Query the daemon for worker capabilities.
async fn query_workers_capabilities(refresh: bool) -> Result<WorkerCapabilitiesResponseFromApi> {
    let command = if refresh {
        "GET /workers/capabilities?refresh=true\n"
    } else {
        "GET /workers/capabilities\n"
    };
    let response = send_daemon_command(command).await?;
    let json = extract_json_body(&response)
        .ok_or_else(|| anyhow::anyhow!("Invalid response format from daemon"))?;
    let capabilities: WorkerCapabilitiesResponseFromApi =
        serde_json::from_str(json).context("Failed to parse worker capabilities response")?;
    Ok(capabilities)
}

/// Query the daemon for all worker SpeedScores.
async fn query_speedscore_list() -> Result<SpeedScoreListResponseFromApi> {
    let response = send_daemon_command("GET /speedscores\n").await?;
    let json = extract_json_body(&response)
        .ok_or_else(|| anyhow::anyhow!("Invalid response format from daemon"))?;
    let scores: SpeedScoreListResponseFromApi =
        serde_json::from_str(json).context("Failed to parse SpeedScore list response")?;
    Ok(scores)
}

/// Query the daemon for a single worker's SpeedScore.
async fn query_speedscore(worker_id: &str) -> Result<SpeedScoreResponseFromApi> {
    let command = format!("GET /speedscore/{}\n", worker_id);
    let response = send_daemon_command(&command).await?;
    let json = extract_json_body(&response)
        .ok_or_else(|| anyhow::anyhow!("Invalid response format from daemon"))?;
    let score: SpeedScoreResponseFromApi =
        serde_json::from_str(json).context("Failed to parse SpeedScore response")?;
    Ok(score)
}

/// Query the daemon for a worker's SpeedScore history.
async fn query_speedscore_history(
    worker_id: &str,
    days: u32,
    limit: usize,
) -> Result<SpeedScoreHistoryResponseFromApi> {
    let command = format!(
        "GET /speedscore/{}/history?days={}&limit={}\n",
        worker_id, days, limit
    );
    let response = send_daemon_command(&command).await?;
    let json = extract_json_body(&response)
        .ok_or_else(|| anyhow::anyhow!("Invalid response format from daemon"))?;
    let history: SpeedScoreHistoryResponseFromApi =
        serde_json::from_str(json).context("Failed to parse SpeedScore history response")?;
    Ok(history)
}

/// Format a SpeedScore value with color based on rating.
fn format_score(score: f64, style: &crate::ui::theme::Theme) -> String {
    match score {
        x if x >= 90.0 => style.success(&format!("{:.1}", x)).to_string(),
        x if x >= 75.0 => style.success(&format!("{:.1}", x)).to_string(),
        x if x >= 60.0 => style.info(&format!("{:.1}", x)).to_string(),
        x if x >= 45.0 => style.warning(&format!("{:.1}", x)).to_string(),
        x => style.error(&format!("{:.1}", x)).to_string(),
    }
}

/// Display SpeedScore details in verbose mode.
fn display_speedscore_verbose(score: &SpeedScoreViewFromApi, style: &crate::ui::theme::Theme) {
    println!(
        "    {} {} {}",
        style.key("CPU"),
        style.muted(":"),
        format_score(score.cpu_score, style)
    );
    println!(
        "    {} {} {}",
        style.key("Memory"),
        style.muted(":"),
        format_score(score.memory_score, style)
    );
    println!(
        "    {} {} {}",
        style.key("Disk"),
        style.muted(":"),
        format_score(score.disk_score, style)
    );
    println!(
        "    {} {} {}",
        style.key("Network"),
        style.muted(":"),
        format_score(score.network_score, style)
    );
    println!(
        "    {} {} {}",
        style.key("Compilation"),
        style.muted(":"),
        format_score(score.compilation_score, style)
    );
}

/// SpeedScore CLI command entry point.
#[allow(clippy::too_many_arguments)]
pub async fn speedscore(
    worker: Option<String>,
    all: bool,
    verbose: bool,
    history: bool,
    days: u32,
    limit: usize,
    ctx: &OutputContext,
) -> Result<()> {
    let style = ctx.theme();

    // Validate arguments
    if all && worker.is_some() {
        bail!("Cannot specify both --all and a worker ID");
    }
    if history && worker.is_none() && !all {
        bail!("--history requires a worker ID or --all");
    }
    if !all && worker.is_none() {
        bail!("Specify a worker ID or use --all to show all workers");
    }

    // Handle history mode
    if history {
        if all {
            // Show brief history for all workers
            let workers = load_workers_from_config()?;
            if ctx.is_json() {
                let mut all_history = Vec::new();
                for w in &workers {
                    if let Ok(h) = query_speedscore_history(w.id.as_str(), days, limit).await {
                        all_history.push(h);
                    }
                }
                let _ = ctx.json(&ApiResponse::ok("speedscore history", all_history));
                return Ok(());
            }

            println!(
                "{}",
                style.format_header("SpeedScore History (All Workers)")
            );
            println!();

            for w in &workers {
                match query_speedscore_history(w.id.as_str(), days, limit).await {
                    Ok(history_resp) => {
                        println!(
                            "  {} {} ({} entries)",
                            style.symbols.bullet_filled,
                            style.highlight(w.id.as_str()),
                            history_resp.history.len()
                        );
                        if let Some(latest) = history_resp.history.first() {
                            println!(
                                "    {} {} → {}",
                                style.muted("Latest:"),
                                format_score(latest.total, style),
                                style.muted(&latest.measured_at)
                            );
                        }
                        if history_resp.history.len() > 1 {
                            let oldest = history_resp.history.last().unwrap();
                            let newest = history_resp.history.first().unwrap();
                            let trend = newest.total - oldest.total;
                            let trend_str = if trend > 0.0 {
                                style.success(&format!("+{:.1}", trend))
                            } else if trend < 0.0 {
                                style.error(&format!("{:.1}", trend))
                            } else {
                                style.muted("±0.0")
                            };
                            println!(
                                "    {} {} (over {} entries)",
                                style.muted("Trend:"),
                                trend_str,
                                history_resp.history.len()
                            );
                        }
                        println!();
                    }
                    Err(e) => {
                        println!(
                            "  {} {} - {}",
                            StatusIndicator::Error.display(style),
                            style.highlight(w.id.as_str()),
                            style.error(&format!("Failed: {}", e))
                        );
                        println!();
                    }
                }
            }
            return Ok(());
        }

        // Show detailed history for single worker
        let worker_id = worker.as_ref().unwrap();
        let history_resp = query_speedscore_history(worker_id, days, limit).await?;

        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::ok("speedscore history", history_resp));
            return Ok(());
        }

        println!(
            "{}",
            style.format_header(&format!("SpeedScore History: {}", worker_id))
        );
        println!();

        if history_resp.history.is_empty() {
            println!(
                "  {} No history available for worker '{}'",
                StatusIndicator::Info.display(style),
                worker_id
            );
            return Ok(());
        }

        println!(
            "  {} {} entries (last {} days)",
            style.muted("Showing"),
            history_resp.history.len(),
            days
        );
        println!();

        for entry in &history_resp.history {
            println!(
                "  {} {} {} {}",
                style.symbols.bullet_filled,
                format_score(entry.total, style),
                style.muted(entry.rating()),
                style.muted(&format!("({})", entry.measured_at))
            );
            if verbose {
                display_speedscore_verbose(entry, style);
            }
        }

        // Show trend if multiple entries
        if history_resp.history.len() > 1 {
            let oldest = history_resp.history.last().unwrap();
            let newest = history_resp.history.first().unwrap();
            let trend = newest.total - oldest.total;
            let trend_str = if trend > 0.0 {
                style.success(&format!("+{:.1}", trend)).to_string()
            } else if trend < 0.0 {
                style.error(&format!("{:.1}", trend)).to_string()
            } else {
                style.muted("±0.0").to_string()
            };
            println!();
            println!(
                "  {} {} over {} entries",
                style.muted("Trend:"),
                trend_str,
                history_resp.history.len()
            );
        }

        return Ok(());
    }

    // Handle --all mode (show all workers)
    if all {
        let scores = query_speedscore_list().await?;

        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::ok("speedscore list", scores));
            return Ok(());
        }

        println!("{}", style.format_header("Worker SpeedScores"));
        println!();

        if scores.workers.is_empty() {
            println!(
                "  {} No workers found",
                StatusIndicator::Info.display(style)
            );
            return Ok(());
        }

        for entry in &scores.workers {
            let status_indicator = match entry.status.status.as_str() {
                "healthy" => StatusIndicator::Success.display(style),
                "degraded" => StatusIndicator::Warning.display(style),
                _ => StatusIndicator::Error.display(style),
            };

            let score_display = if let Some(ref score) = entry.speedscore {
                format!(
                    "{} {}",
                    format_score(score.total, style),
                    style.muted(&format!("({})", score.rating()))
                )
            } else {
                style.muted("N/A").to_string()
            };

            println!(
                "  {} {} {} {}",
                status_indicator,
                style.highlight(&entry.worker_id),
                style.muted(":"),
                score_display
            );

            if verbose && let Some(ref score) = entry.speedscore {
                display_speedscore_verbose(score, style);
            }
        }

        println!();
        println!(
            "{} {} worker(s)",
            style.muted("Total:"),
            style.highlight(&scores.workers.len().to_string())
        );

        return Ok(());
    }

    // Show single worker SpeedScore
    let worker_id = worker.as_ref().unwrap();
    let score_resp = query_speedscore(worker_id).await?;

    if ctx.is_json() {
        let _ = ctx.json(&ApiResponse::ok("speedscore", score_resp));
        return Ok(());
    }

    println!(
        "{}",
        style.format_header(&format!("SpeedScore: {}", worker_id))
    );
    println!();

    match score_resp.speedscore {
        Some(score) => {
            println!(
                "  {} {} {} {}",
                style.key("Total"),
                style.muted(":"),
                format_score(score.total, style),
                style.muted(&format!("({})", score.rating()))
            );
            println!(
                "  {} {} {}",
                style.key("Measured"),
                style.muted(":"),
                style.muted(&score.measured_at)
            );
            println!();

            if verbose {
                println!("{}", style.highlight("  Component Breakdown:"));
                println!(
                    "    {} {} {} {}",
                    style.key("CPU (30%)"),
                    style.muted(":"),
                    format_score(score.cpu_score, style),
                    style.muted("- processor benchmark")
                );
                println!(
                    "    {} {} {} {}",
                    style.key("Memory (15%)"),
                    style.muted(":"),
                    format_score(score.memory_score, style),
                    style.muted("- memory bandwidth")
                );
                println!(
                    "    {} {} {} {}",
                    style.key("Disk (20%)"),
                    style.muted(":"),
                    format_score(score.disk_score, style),
                    style.muted("- I/O throughput")
                );
                println!(
                    "    {} {} {} {}",
                    style.key("Network (15%)"),
                    style.muted(":"),
                    format_score(score.network_score, style),
                    style.muted("- latency & bandwidth")
                );
                println!(
                    "    {} {} {} {}",
                    style.key("Compile (20%)"),
                    style.muted(":"),
                    format_score(score.compilation_score, style),
                    style.muted("- build performance")
                );
            } else {
                println!(
                    "  {} Use {} for component breakdown",
                    style.muted("Tip:"),
                    style.highlight("--verbose")
                );
            }
        }
        None => {
            let msg = score_resp
                .message
                .unwrap_or_else(|| "No SpeedScore available".to_string());
            println!(
                "  {} {}",
                StatusIndicator::Info.display(style),
                style.muted(&msg)
            );
            println!();
            println!(
                "  {} Run {} to generate a score",
                style.muted("Tip:"),
                style.highlight("rch workers benchmark")
            );
        }
    }

    Ok(())
}

/// Interactive first-run setup wizard.
///
/// Guides the user through:
/// 1. Detecting potential workers from SSH config
/// 2. Selecting which hosts to use as workers
/// 3. Probing hosts for connectivity
/// 4. Deploying rch-wkr binary to workers
/// 5. Synchronizing Rust toolchain
/// 6. Starting the daemon
/// 7. Installing the Claude Code hook
/// 8. Running a test compilation
pub async fn init_wizard(yes: bool, skip_test: bool, ctx: &OutputContext) -> Result<()> {
    use dialoguer::Confirm;

    let style = ctx.theme();

    println!();
    println!("{}", style.format_header("RCH First-Run Setup Wizard"));
    println!();
    println!(
        "  {} This wizard will help you set up RCH for remote compilation.",
        style.muted("→")
    );
    println!();

    // Step 1: Initialize configuration
    println!("{}", style.highlight("Step 1/8: Initialize configuration"));
    config_init(ctx, false, yes)?;
    println!();

    // Step 2: Discover workers
    println!(
        "{}",
        style.highlight("Step 2/8: Discover potential workers")
    );
    workers_discover(true, false, yes, ctx).await?;
    println!();

    // Step 3: Add discovered workers
    if !yes {
        let add_workers = Confirm::new()
            .with_prompt("Add discovered workers to configuration?")
            .default(true)
            .interact()
            .unwrap_or(false);

        if add_workers {
            workers_discover(false, true, false, ctx).await?;
        }
    } else {
        workers_discover(false, true, true, ctx).await?;
    }
    println!();

    // Step 4: Probe worker connectivity
    println!("{}", style.highlight("Step 4/8: Probe worker connectivity"));
    workers_probe(None, true, ctx).await?;
    println!();

    // Step 5: Deploy worker binary
    println!("{}", style.highlight("Step 5/8: Deploy worker binary"));
    let deploy = if yes {
        true
    } else {
        Confirm::new()
            .with_prompt("Deploy rch-wkr binary to workers?")
            .default(true)
            .interact()
            .unwrap_or(false)
    };
    if deploy {
        workers_deploy_binary(None, true, false, false, ctx).await?;
    }
    println!();

    // Step 6: Sync toolchain
    println!(
        "{}",
        style.highlight("Step 6/8: Synchronize Rust toolchain")
    );
    let sync_toolchain = if yes {
        true
    } else {
        Confirm::new()
            .with_prompt("Synchronize Rust toolchain to workers?")
            .default(true)
            .interact()
            .unwrap_or(false)
    };
    if sync_toolchain {
        workers_sync_toolchain(None, true, false, ctx).await?;
    }
    println!();

    // Step 7: Start daemon
    println!("{}", style.highlight("Step 7/8: Start daemon"));
    daemon_start(ctx).await?;
    println!();

    // Step 8: Install hook
    println!("{}", style.highlight("Step 8/8: Install Claude Code hook"));
    hook_install(ctx)?;
    println!();

    // Optional: Test compilation
    if !skip_test {
        println!("{}", style.highlight("Bonus: Test compilation"));
        let run_test = if yes {
            true
        } else {
            Confirm::new()
                .with_prompt("Run a test compilation?")
                .default(true)
                .interact()
                .unwrap_or(false)
        };
        if run_test {
            hook_test(ctx).await?;
        }
        println!();
    }

    // Summary
    println!("{}", style.format_success("Setup complete!"));
    println!();
    println!("{}", style.highlight("What's next:"));
    println!(
        "  {} Use Claude Code normally - compilation will be offloaded",
        style.muted("•")
    );
    println!(
        "  {} Monitor with: {}",
        style.muted("•"),
        style.info("rch status --workers --jobs")
    );
    println!(
        "  {} Check health with: {}",
        style.muted("•"),
        style.info("rch doctor")
    );

    Ok(())
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status_types::format_bytes;
    use crate::ui::context::{OutputConfig, OutputMode};
    use crate::ui::writer::SharedOutputBuffer;
    use rch_common::CompilationKind;
    use rch_common::test_guard;

    struct TestConfigDirGuard;

    impl TestConfigDirGuard {
        fn new(path: PathBuf) -> Self {
            set_test_config_dir_override(Some(path));
            Self
        }
    }

    impl Drop for TestConfigDirGuard {
        fn drop(&mut self) {
            set_test_config_dir_override(None);
        }
    }

    fn json_test_context() -> (OutputContext, SharedOutputBuffer) {
        let stdout_buf = SharedOutputBuffer::new();
        let stderr_buf = SharedOutputBuffer::new();
        let ctx = OutputContext::with_writers(
            OutputConfig {
                force_mode: Some(OutputMode::Json),
                ..Default::default()
            },
            stdout_buf.as_writer(false),
            stderr_buf.as_writer(false),
        );
        (ctx, stdout_buf)
    }

    // -------------------------------------------------------------------------
    // ApiResponse Tests
    // -------------------------------------------------------------------------

    #[test]
    fn api_response_ok_creates_success_response() {
        let _guard = test_guard!();
        let response = ApiResponse::ok("test cmd", "test data".to_string());
        assert!(response.success);
        assert_eq!(response.command, Some("test cmd".to_string()));
        assert_eq!(response.api_version, "1.0");
        assert!(response.data.is_some());
        assert_eq!(response.data.unwrap(), "test data");
        assert!(response.error.is_none());
    }

    #[test]
    fn api_response_err_creates_error_response() {
        let _guard = test_guard!();
        let response: ApiResponse<()> =
            ApiResponse::err("failed cmd", ApiError::internal("error message"));
        assert!(!response.success);
        assert_eq!(response.command, Some("failed cmd".to_string()));
        assert!(response.data.is_none());
        assert!(response.error.is_some());
        let error = response.error.unwrap();
        assert_eq!(error.code, "RCH-E504"); // InternalStateError
    }

    #[test]
    fn api_response_err_with_specific_error_code() {
        let _guard = test_guard!();
        let response: ApiResponse<()> = ApiResponse::err(
            "cmd",
            ApiError::new(ErrorCode::SshConnectionFailed, "Worker not available"),
        );
        assert!(!response.success);
        assert!(response.error.is_some());
        let error = response.error.unwrap();
        assert_eq!(error.code, "RCH-E100"); // SshConnectionFailed
    }

    #[test]
    fn api_response_ok_serializes_without_error_field() {
        let _guard = test_guard!();
        let response = ApiResponse::ok("test", "data".to_string());
        let json = serde_json::to_value(&response).unwrap();
        assert!(json.get("error").is_none());
        assert_eq!(json["data"], "data");
        assert!(json["success"].as_bool().unwrap());
    }

    #[test]
    fn api_response_err_serializes_without_data_field() {
        let _guard = test_guard!();
        let response: ApiResponse<String> =
            ApiResponse::err("test", ApiError::internal("error msg"));
        let json = serde_json::to_value(&response).unwrap();
        assert!(json.get("data").is_none());
        assert!(json.get("error").is_some());
        assert!(!json["success"].as_bool().unwrap());
    }

    #[test]
    fn api_response_with_complex_data_serializes() {
        let _guard = test_guard!();
        #[derive(Serialize)]
        struct ComplexData {
            name: String,
            count: u32,
            items: Vec<String>,
        }
        let data = ComplexData {
            name: "test".to_string(),
            count: 3,
            items: vec!["a".to_string(), "b".to_string()],
        };
        let response = ApiResponse::ok("complex", data);
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["data"]["name"], "test");
        assert_eq!(json["data"]["count"], 3);
        assert_eq!(json["data"]["items"].as_array().unwrap().len(), 2);
    }

    // -------------------------------------------------------------------------
    // Config / Workers IO Tests (coverage)
    // -------------------------------------------------------------------------

    #[test]
    fn config_init_simple_json_creates_files() {
        let _guard = test_guard!();
        let temp_dir = tempfile::tempdir().expect("temp dir should be creatable");
        let _cfg_guard = TestConfigDirGuard::new(temp_dir.path().to_path_buf());

        let (ctx, stdout_buf) = json_test_context();
        config_init(&ctx, false, true).expect("config init should succeed");

        assert!(temp_dir.path().join("config.toml").exists());
        assert!(temp_dir.path().join("workers.toml").exists());

        let value: serde_json::Value =
            serde_json::from_str(&stdout_buf.to_string_lossy()).expect("json output");
        assert_eq!(value["success"], true);
        assert_eq!(value["command"], "config init");
        assert_eq!(value["data"]["created"].as_array().unwrap().len(), 2);
        assert_eq!(
            value["data"]["already_existed"].as_array().unwrap().len(),
            0
        );
    }

    #[test]
    fn config_init_simple_json_reports_existing_files() {
        let _guard = test_guard!();
        let temp_dir = tempfile::tempdir().expect("temp dir should be creatable");
        let _cfg_guard = TestConfigDirGuard::new(temp_dir.path().to_path_buf());

        let (ctx1, _stdout_buf1) = json_test_context();
        config_init(&ctx1, false, true).expect("first config init should succeed");

        let (ctx2, stdout_buf2) = json_test_context();
        config_init(&ctx2, false, true).expect("second config init should succeed");

        let value: serde_json::Value =
            serde_json::from_str(&stdout_buf2.to_string_lossy()).expect("json output");
        assert_eq!(value["success"], true);
        assert_eq!(value["command"], "config init");
        assert_eq!(value["data"]["created"].as_array().unwrap().len(), 0);
        assert_eq!(
            value["data"]["already_existed"].as_array().unwrap().len(),
            2
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn workers_list_json_uses_config_override() {
        let _guard = test_guard!();
        let temp_dir = tempfile::tempdir().expect("temp dir should be creatable");
        let _cfg_guard = TestConfigDirGuard::new(temp_dir.path().to_path_buf());

        // Seed example config files (includes one enabled worker)
        let (ctx, _stdout_buf) = json_test_context();
        config_init(&ctx, false, true).expect("config init should succeed");

        let (ctx2, stdout_buf2) = json_test_context();
        workers_list(false, &ctx2)
            .await
            .expect("workers list should succeed");

        let value: serde_json::Value =
            serde_json::from_str(&stdout_buf2.to_string_lossy()).expect("json output");
        assert_eq!(value["success"], true);
        assert_eq!(value["command"], "workers list");
        assert_eq!(value["data"]["count"], 1);
        assert_eq!(value["data"]["workers"][0]["id"], "worker1");
    }

    #[test]
    fn config_validate_json_success_with_example_files() {
        let _guard = test_guard!();
        let temp_dir = tempfile::tempdir().expect("temp dir should be creatable");
        let _cfg_guard = TestConfigDirGuard::new(temp_dir.path().to_path_buf());

        let (ctx1, _stdout_buf1) = json_test_context();
        config_init(&ctx1, false, true).expect("config init should succeed");

        let (ctx2, stdout_buf2) = json_test_context();
        config_validate(&ctx2).expect("config validate should succeed");

        let value: serde_json::Value =
            serde_json::from_str(&stdout_buf2.to_string_lossy()).expect("json output");
        assert_eq!(value["success"], true);
        assert_eq!(value["command"], "config validate");
        assert_eq!(value["data"]["valid"], true);
        assert_eq!(value["data"]["errors"].as_array().unwrap().len(), 0);
    }

    // -------------------------------------------------------------------------
    // WorkerInfo Tests
    // -------------------------------------------------------------------------

    #[test]
    fn worker_info_from_worker_config_converts_all_fields() {
        let _guard = test_guard!();
        let config = WorkerConfig {
            id: WorkerId::new("test-worker"),
            host: "192.168.1.100".to_string(),
            user: "admin".to_string(),
            identity_file: "~/.ssh/key.pem".to_string(),
            total_slots: 16,
            priority: 50,
            tags: vec!["fast".to_string(), "ssd".to_string()],
        };
        let info = WorkerInfo::from(&config);
        assert_eq!(info.id, "test-worker");
        assert_eq!(info.host, "192.168.1.100");
        assert_eq!(info.user, "admin");
        assert_eq!(info.total_slots, 16);
        assert_eq!(info.priority, 50);
        assert_eq!(info.tags, vec!["fast", "ssd"]);
    }

    #[test]
    fn worker_info_from_worker_config_with_empty_tags() {
        let _guard = test_guard!();
        let config = WorkerConfig {
            id: WorkerId::new("minimal"),
            host: "host.example.com".to_string(),
            user: "ubuntu".to_string(),
            identity_file: "~/.ssh/id_rsa".to_string(),
            total_slots: 8,
            priority: 100,
            tags: vec![],
        };
        let info = WorkerInfo::from(&config);
        assert!(info.tags.is_empty());
    }

    #[test]
    fn worker_info_serializes_correctly() {
        let _guard = test_guard!();
        let config = WorkerConfig {
            id: WorkerId::new("w1"),
            host: "host".to_string(),
            user: "user".to_string(),
            identity_file: "key".to_string(),
            total_slots: 4,
            priority: 75,
            tags: vec!["gpu".to_string()],
        };
        let info = WorkerInfo::from(&config);
        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(json["id"], "w1");
        assert_eq!(json["host"], "host");
        assert_eq!(json["total_slots"], 4);
        assert_eq!(json["tags"].as_array().unwrap().len(), 1);
    }

    // -------------------------------------------------------------------------
    // Response Types Tests
    // -------------------------------------------------------------------------

    #[test]
    fn workers_list_response_serializes() {
        let _guard = test_guard!();
        let response = WorkersListResponse {
            workers: vec![],
            count: 0,
        };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["count"], 0);
        assert!(json["workers"].as_array().unwrap().is_empty());
    }

    #[test]
    fn workers_list_response_with_workers_serializes() {
        let _guard = test_guard!();
        let workers = vec![
            WorkerInfo {
                id: "w1".to_string(),
                host: "host1".to_string(),
                user: "u1".to_string(),
                total_slots: 8,
                priority: 100,
                tags: vec![],
                speedscore: None,
            },
            WorkerInfo {
                id: "w2".to_string(),
                host: "host2".to_string(),
                user: "u2".to_string(),
                total_slots: 16,
                priority: 50,
                tags: vec!["fast".to_string()],
                speedscore: Some(85.5),
            },
        ];
        let response = WorkersListResponse { workers, count: 2 };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["count"], 2);
        let workers_arr = json["workers"].as_array().unwrap();
        assert_eq!(workers_arr.len(), 2);
        assert_eq!(workers_arr[0]["id"], "w1");
        assert_eq!(workers_arr[1]["id"], "w2");
    }

    #[test]
    fn worker_probe_result_success_serializes() {
        let _guard = test_guard!();
        let result = WorkerProbeResult {
            id: "worker1".to_string(),
            host: "192.168.1.1".to_string(),
            status: "healthy".to_string(),
            latency_ms: Some(42),
            error: None,
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["id"], "worker1");
        assert_eq!(json["status"], "healthy");
        assert_eq!(json["latency_ms"], 42);
        assert!(json.get("error").is_none()); // skipped when None
    }

    #[test]
    fn worker_probe_result_failure_serializes() {
        let _guard = test_guard!();
        let result = WorkerProbeResult {
            id: "worker2".to_string(),
            host: "192.168.1.2".to_string(),
            status: "unreachable".to_string(),
            latency_ms: None,
            error: Some("Connection refused".to_string()),
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["status"], "unreachable");
        assert!(json.get("latency_ms").is_none()); // skipped when None
        assert_eq!(json["error"], "Connection refused");
    }

    #[test]
    fn daemon_status_response_running_serializes() {
        let _guard = test_guard!();
        let response = DaemonStatusResponse {
            running: true,
            socket_path: "/tmp/rch.sock".to_string(),
            uptime_seconds: Some(3600),
        };
        let json = serde_json::to_value(&response).unwrap();
        assert!(json["running"].as_bool().unwrap());
        assert_eq!(json["socket_path"], "/tmp/rch.sock");
        assert_eq!(json["uptime_seconds"], 3600);
    }

    #[test]
    fn daemon_status_response_not_running_serializes() {
        let _guard = test_guard!();
        let response = DaemonStatusResponse {
            running: false,
            socket_path: "/tmp/rch.sock".to_string(),
            uptime_seconds: None,
        };
        let json = serde_json::to_value(&response).unwrap();
        assert!(!json["running"].as_bool().unwrap());
        assert!(json.get("uptime_seconds").is_none());
    }

    #[test]
    fn system_overview_serializes() {
        let _guard = test_guard!();
        let response = SystemOverview {
            daemon_running: true,
            hook_installed: true,
            workers_count: 3,
            workers: None,
        };
        let json = serde_json::to_value(&response).unwrap();
        assert!(json["daemon_running"].as_bool().unwrap());
        assert!(json["hook_installed"].as_bool().unwrap());
        assert_eq!(json["workers_count"], 3);
        assert!(json.get("workers").is_none());
    }

    #[test]
    fn config_show_response_serializes() {
        let _guard = test_guard!();
        let response = ConfigShowResponse {
            general: ConfigGeneralSection {
                enabled: true,
                force_local: false,
                force_remote: false,
                log_level: "info".to_string(),
                socket_path: "/tmp/rch.sock".to_string(),
            },
            compilation: ConfigCompilationSection {
                confidence_threshold: 0.85,
                min_local_time_ms: 2000,
            },
            transfer: ConfigTransferSection {
                compression_level: 3,
                exclude_patterns: vec!["target/".to_string()],
                remote_base: "/tmp/rch".to_string(),
                max_transfer_mb: None,
                max_transfer_time_ms: None,
                bwlimit_kbps: None,
                estimated_bandwidth_bps: None,
                adaptive_compression: false,
                min_compression_level: 1,
                max_compression_level: 19,
                verify_artifacts: false,
                verify_max_size_bytes: 100 * 1024 * 1024,
            },
            environment: ConfigEnvironmentSection {
                allowlist: vec!["RUSTFLAGS".to_string()],
            },
            circuit: ConfigCircuitSection {
                failure_threshold: 3,
                success_threshold: 2,
                error_rate_threshold: 0.5,
                window_secs: 60,
                open_cooldown_secs: 30,
                half_open_max_probes: 2,
            },
            output: ConfigOutputSection {
                visibility: rch_common::OutputVisibility::None,
                first_run_complete: false,
            },
            self_healing: ConfigSelfHealingSection {
                hook_starts_daemon: true,
                daemon_installs_hooks: true,
                auto_start_cooldown_secs: 30,
                auto_start_timeout_secs: 3,
            },
            sources: vec!["~/.config/rch/config.toml".to_string()],
            value_sources: None,
        };
        let json = serde_json::to_value(&response).unwrap();
        assert!(json["general"]["enabled"].as_bool().unwrap());
        assert_eq!(json["compilation"]["confidence_threshold"], 0.85);
        assert_eq!(json["transfer"]["compression_level"], 3);
        assert_eq!(json["circuit"]["failure_threshold"], 3);
    }

    #[test]
    fn config_init_response_serializes() {
        let _guard = test_guard!();
        let response = ConfigInitResponse {
            created: vec!["config.toml".to_string()],
            already_existed: vec!["workers.toml".to_string()],
        };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["created"].as_array().unwrap().len(), 1);
        assert_eq!(json["already_existed"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn config_validation_response_valid_serializes() {
        let _guard = test_guard!();
        let response = ConfigValidationResponse {
            errors: vec![],
            warnings: vec![],
            valid: true,
        };
        let json = serde_json::to_value(&response).unwrap();
        assert!(json["valid"].as_bool().unwrap());
        assert!(json["errors"].as_array().unwrap().is_empty());
    }

    #[test]
    fn config_validation_response_with_issues_serializes() {
        let _guard = test_guard!();
        let response = ConfigValidationResponse {
            errors: vec![ConfigValidationIssue {
                file: "config.toml".to_string(),
                message: "Invalid syntax".to_string(),
            }],
            warnings: vec![ConfigValidationIssue {
                file: "workers.toml".to_string(),
                message: "Deprecated field".to_string(),
            }],
            valid: false,
        };
        let json = serde_json::to_value(&response).unwrap();
        assert!(!json["valid"].as_bool().unwrap());
        assert_eq!(json["errors"][0]["message"], "Invalid syntax");
        assert_eq!(json["warnings"][0]["file"], "workers.toml");
    }

    #[test]
    fn config_set_response_serializes() {
        let _guard = test_guard!();
        let response = ConfigSetResponse {
            key: "general.log_level".to_string(),
            value: "debug".to_string(),
            config_path: "/home/user/.config/rch/config.toml".to_string(),
        };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["key"], "general.log_level");
        assert_eq!(json["value"], "debug");
    }

    #[test]
    fn config_export_response_serializes() {
        let _guard = test_guard!();
        let response = ConfigExportResponse {
            format: "toml".to_string(),
            content: "[general]\nenabled = true".to_string(),
        };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["format"], "toml");
        assert!(json["content"].as_str().unwrap().contains("enabled"));
    }

    #[test]
    fn diagnose_decision_intercepts_when_confident() {
        let _guard = test_guard!();
        let classification =
            Classification::compilation(CompilationKind::CargoBuild, 0.95, "cargo build");
        let decision = build_diagnose_decision(&classification, 0.85);
        assert!(decision.would_intercept);
        assert!(decision.reason.contains("meets"));
    }

    #[test]
    fn diagnose_decision_rejects_when_below_threshold() {
        let _guard = test_guard!();
        let classification =
            Classification::compilation(CompilationKind::CargoCheck, 0.80, "cargo check");
        let decision = build_diagnose_decision(&classification, 0.85);
        assert!(!decision.would_intercept);
        assert!(decision.reason.contains("below threshold"));
    }

    #[test]
    fn diagnose_response_serializes() {
        let _guard = test_guard!();
        let classification =
            Classification::compilation(CompilationKind::CargoBuild, 0.95, "cargo build");
        let response = DiagnoseResponse {
            classification,
            tiers: Vec::new(),
            command: "cargo build".to_string(),
            normalized_command: "cargo build".to_string(),
            decision: DiagnoseDecision {
                would_intercept: true,
                reason: "meets confidence threshold".to_string(),
            },
            threshold: DiagnoseThreshold {
                value: 0.85,
                source: "default".to_string(),
            },
            daemon: DiagnoseDaemonStatus {
                socket_path: "/tmp/rch.sock".to_string(),
                socket_exists: false,
                reachable: false,
                status: None,
                version: None,
                uptime_seconds: None,
                error: Some("daemon socket not found".to_string()),
            },
            required_runtime: RequiredRuntime::Rust,
            local_capabilities: None,
            capabilities_warnings: Vec::new(),
            worker_selection: None,
            dry_run: None,
        };

        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["command"], "cargo build");
        assert_eq!(json["classification"]["confidence"], 0.95);
        assert_eq!(json["threshold"]["value"], 0.85);
    }

    #[test]
    fn workers_capabilities_report_serializes_with_local() {
        let _guard = test_guard!();
        let report = WorkersCapabilitiesReport {
            workers: vec![],
            local: Some(WorkerCapabilities {
                rustc_version: Some("rustc 1.87.0-nightly".to_string()),
                bun_version: None,
                node_version: None,
                npm_version: None,
                ..Default::default()
            }),
            required_runtime: Some(RequiredRuntime::Rust),
            warnings: vec!["warn".to_string()],
        };
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["local"]["rustc_version"], "rustc 1.87.0-nightly");
        assert_eq!(json["required_runtime"], "rust");
        assert!(json["warnings"].is_array());
    }

    #[test]
    fn local_capability_warnings_include_missing_and_mismatch() {
        let _guard = test_guard!();
        let local = WorkerCapabilities {
            rustc_version: Some("rustc 1.87.0-nightly".to_string()),
            bun_version: None,
            node_version: None,
            npm_version: None,
            ..Default::default()
        };
        let workers = vec![
            WorkerCapabilitiesFromApi {
                id: "w-missing".to_string(),
                host: "host".to_string(),
                user: "user".to_string(),
                capabilities: WorkerCapabilities::new(),
            },
            WorkerCapabilitiesFromApi {
                id: "w-old".to_string(),
                host: "host".to_string(),
                user: "user".to_string(),
                capabilities: WorkerCapabilities {
                    rustc_version: Some("rustc 1.86.0-nightly".to_string()),
                    bun_version: None,
                    node_version: None,
                    npm_version: None,
                    ..Default::default()
                },
            },
        ];
        let warnings = collect_local_capability_warnings(&workers, &local);
        assert!(warnings.iter().any(|w| w.contains("missing Rust runtime")));
        assert!(warnings.iter().any(|w| w.contains("Rust version mismatch")));
    }

    #[test]
    fn hook_action_response_success_serializes() {
        let _guard = test_guard!();
        let response = HookActionResponse {
            action: "install".to_string(),
            success: true,
            settings_path: "~/.config/claude-code/settings.json".to_string(),
            message: Some("Hook installed successfully".to_string()),
        };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["action"], "install");
        assert!(json["success"].as_bool().unwrap());
        assert_eq!(json["message"], "Hook installed successfully");
    }

    #[test]
    fn hook_action_response_without_message_serializes() {
        let _guard = test_guard!();
        let response = HookActionResponse {
            action: "uninstall".to_string(),
            success: true,
            settings_path: "path".to_string(),
            message: None,
        };
        let json = serde_json::to_value(&response).unwrap();
        assert!(json.get("message").is_none());
    }

    #[test]
    fn hook_test_response_serializes() {
        let _guard = test_guard!();
        let response = HookTestResponse {
            classification_tests: vec![ClassificationTestResult {
                command: "cargo build".to_string(),
                is_compilation: true,
                confidence: 0.95,
                expected_intercept: true,
                passed: true,
            }],
            daemon_connected: true,
            daemon_response: Some("OK".to_string()),
            workers_configured: 2,
            workers: vec![],
        };
        let json = serde_json::to_value(&response).unwrap();
        assert!(json["daemon_connected"].as_bool().unwrap());
        assert_eq!(json["workers_configured"], 2);
        let tests = json["classification_tests"].as_array().unwrap();
        assert_eq!(tests[0]["command"], "cargo build");
        assert!(tests[0]["passed"].as_bool().unwrap());
    }

    #[test]
    fn classification_test_result_serializes() {
        let _guard = test_guard!();
        let result = ClassificationTestResult {
            command: "bun test".to_string(),
            is_compilation: true,
            confidence: 0.92,
            expected_intercept: true,
            passed: true,
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["command"], "bun test");
        assert!(json["is_compilation"].as_bool().unwrap());
        assert_eq!(json["confidence"], 0.92);
    }

    // -------------------------------------------------------------------------
    // ErrorCode Tests
    // -------------------------------------------------------------------------

    #[test]
    fn error_code_codes_have_rch_prefix() {
        let _guard = test_guard!();
        // Verify error codes follow RCH-Exxx format
        assert_eq!(ErrorCode::ConfigNotFound.code_string(), "RCH-E001");
        assert_eq!(ErrorCode::ConfigValidationError.code_string(), "RCH-E004");
        assert_eq!(ErrorCode::ConfigInvalidWorker.code_string(), "RCH-E008");
        assert_eq!(ErrorCode::SshConnectionFailed.code_string(), "RCH-E100");
        assert_eq!(
            ErrorCode::InternalDaemonNotRunning.code_string(),
            "RCH-E502"
        );
        assert_eq!(ErrorCode::InternalStateError.code_string(), "RCH-E504");
    }

    // -------------------------------------------------------------------------
    // config_dir Tests
    // -------------------------------------------------------------------------

    #[test]
    fn config_dir_returns_some() {
        let _guard = test_guard!();
        // config_dir should return a path on most systems
        let dir = config_dir();
        // We can't guarantee it returns Some on all systems, but if it does,
        // it should be a valid path that ends with "rch"
        if let Some(path) = dir {
            assert!(path.to_string_lossy().contains("rch"));
        }
    }

    // -------------------------------------------------------------------------
    // API_VERSION Tests
    // -------------------------------------------------------------------------

    #[test]
    fn api_version_is_expected_value() {
        let _guard = test_guard!();
        assert_eq!(rch_common::API_VERSION, "1.0");
    }

    // -------------------------------------------------------------------------
    // DEFAULT_SOCKET_PATH Tests
    // -------------------------------------------------------------------------

    #[test]
    fn default_socket_path_is_expected() {
        let _guard = test_guard!();
        assert_eq!(DEFAULT_SOCKET_PATH, "/tmp/rch.sock");
    }

    // -------------------------------------------------------------------------
    // Dry Run Summary Tests
    // -------------------------------------------------------------------------

    #[test]
    fn dry_run_summary_not_intercepted() {
        let _guard = test_guard!();
        let summary = build_dry_run_summary(false, "not a compilation command", &None, false);
        assert!(!summary.would_offload);
        assert_eq!(summary.reason, "not a compilation command");
        assert_eq!(summary.pipeline_steps.len(), 5);
        // First step (classify) should not be skipped
        assert!(!summary.pipeline_steps[0].skipped);
        // Remaining steps should be skipped
        for step in &summary.pipeline_steps[1..] {
            assert!(step.skipped);
        }
    }

    #[test]
    fn dry_run_summary_intercepted_no_daemon() {
        let _guard = test_guard!();
        let summary = build_dry_run_summary(
            true,
            "meets confidence threshold",
            &None,
            false, // daemon not reachable
        );
        assert!(!summary.would_offload);
        assert!(summary.reason.contains("no worker available"));
        assert_eq!(summary.pipeline_steps.len(), 5);
        // Classify should run
        assert!(!summary.pipeline_steps[0].skipped);
        // Select should be skipped (no daemon)
        assert!(summary.pipeline_steps[1].skipped);
        assert_eq!(summary.pipeline_steps[1].name, "select");
    }

    #[test]
    fn dry_run_summary_intercepted_with_worker() {
        let _guard = test_guard!();
        let worker = SelectedWorker {
            id: WorkerId::new("test-worker"),
            host: "worker.example.com".to_string(),
            user: "rch".to_string(),
            identity_file: "~/.ssh/id_rsa".to_string(),
            slots_available: 4,
            speed_score: 1.5,
        };
        let worker_selection = DiagnoseWorkerSelection {
            estimated_cores: 4,
            worker: Some(worker),
            reason: SelectionReason::Success,
        };
        let summary = build_dry_run_summary(
            true,
            "meets confidence threshold",
            &Some(worker_selection),
            true, // daemon reachable
        );
        assert!(summary.would_offload);
        assert!(summary.reason.contains("worker available"));
        assert_eq!(summary.pipeline_steps.len(), 5);
        // All steps should run (not skipped)
        for step in &summary.pipeline_steps {
            assert!(!step.skipped, "Step {} should not be skipped", step.name);
        }
    }

    #[test]
    fn dry_run_pipeline_step_serializes() {
        let _guard = test_guard!();
        let step = DryRunPipelineStep {
            step: 1,
            name: "classify".to_string(),
            description: "Analyze command".to_string(),
            skipped: false,
            skip_reason: None,
            estimated_duration_ms: Some(2),
        };
        let json = serde_json::to_value(&step).unwrap();
        assert_eq!(json["step"], 1);
        assert_eq!(json["name"], "classify");
        assert_eq!(json["skipped"], false);
        assert_eq!(json["estimated_duration_ms"], 2);
        assert!(json.get("skip_reason").is_none());
    }

    #[test]
    fn dry_run_pipeline_step_skipped_serializes() {
        let _guard = test_guard!();
        let step = DryRunPipelineStep {
            step: 2,
            name: "select".to_string(),
            description: "Select worker".to_string(),
            skipped: true,
            skip_reason: Some("daemon not reachable".to_string()),
            estimated_duration_ms: None,
        };
        let json = serde_json::to_value(&step).unwrap();
        assert_eq!(json["skipped"], true);
        assert_eq!(json["skip_reason"], "daemon not reachable");
        assert!(json.get("estimated_duration_ms").is_none());
    }

    #[test]
    fn dry_run_transfer_estimate_serializes() {
        let _guard = test_guard!();
        let estimate = DryRunTransferEstimate {
            bytes: 1024 * 1024 * 10, // 10 MB
            human_size: "10.00 MB".to_string(),
            files: 150,
            estimated_time_ms: 2500,
            would_skip: false,
            skip_reason: None,
        };
        let json = serde_json::to_value(&estimate).unwrap();
        assert_eq!(json["bytes"], 10485760);
        assert_eq!(json["human_size"], "10.00 MB");
        assert_eq!(json["files"], 150);
        assert_eq!(json["estimated_time_ms"], 2500);
        assert_eq!(json["would_skip"], false);
    }

    #[test]
    fn dry_run_transfer_estimate_would_skip_serializes() {
        let _guard = test_guard!();
        let estimate = DryRunTransferEstimate {
            bytes: 1024 * 1024 * 500, // 500 MB
            human_size: "500.00 MB".to_string(),
            files: 5000,
            estimated_time_ms: 60000,
            would_skip: true,
            skip_reason: Some("exceeds max_transfer_mb threshold".to_string()),
        };
        let json = serde_json::to_value(&estimate).unwrap();
        assert_eq!(json["would_skip"], true);
        assert_eq!(json["skip_reason"], "exceeds max_transfer_mb threshold");
    }

    #[test]
    fn dry_run_summary_serializes() {
        let _guard = test_guard!();
        let summary = DryRunSummary {
            would_offload: true,
            reason: "compilation command meets threshold".to_string(),
            pipeline_steps: vec![DryRunPipelineStep {
                step: 1,
                name: "classify".to_string(),
                description: "Analyze command".to_string(),
                skipped: false,
                skip_reason: None,
                estimated_duration_ms: Some(2),
            }],
            transfer_estimate: None,
            total_estimated_ms: Some(100),
        };
        let json = serde_json::to_value(&summary).unwrap();
        assert_eq!(json["would_offload"], true);
        assert_eq!(json["reason"], "compilation command meets threshold");
        assert_eq!(json["pipeline_steps"].as_array().unwrap().len(), 1);
        assert_eq!(json["total_estimated_ms"], 100);
    }

    #[test]
    fn format_bytes_basic() {
        let _guard = test_guard!();
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1024 * 1024), "1.0 MB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.0 GB");
    }

    #[test]
    fn format_bytes_fractional() {
        let _guard = test_guard!();
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(1024 * 1024 + 512 * 1024), "1.5 MB");
    }

    // -------------------------------------------------------------------------
    // runtime_label Tests
    // -------------------------------------------------------------------------

    #[test]
    fn runtime_label_rust() {
        let _guard = test_guard!();
        assert_eq!(runtime_label(&RequiredRuntime::Rust), "rust");
    }

    #[test]
    fn runtime_label_bun() {
        let _guard = test_guard!();
        assert_eq!(runtime_label(&RequiredRuntime::Bun), "bun");
    }

    #[test]
    fn runtime_label_node() {
        let _guard = test_guard!();
        assert_eq!(runtime_label(&RequiredRuntime::Node), "node");
    }

    #[test]
    fn runtime_label_none() {
        let _guard = test_guard!();
        assert_eq!(runtime_label(&RequiredRuntime::None), "none");
    }

    // -------------------------------------------------------------------------
    // has_any_capabilities Tests
    // -------------------------------------------------------------------------

    #[test]
    fn has_any_capabilities_empty() {
        let _guard = test_guard!();
        let caps = WorkerCapabilities::new();
        assert!(!has_any_capabilities(&caps));
    }

    #[test]
    fn has_any_capabilities_with_rust() {
        let _guard = test_guard!();
        let caps = WorkerCapabilities {
            rustc_version: Some("rustc 1.87.0".to_string()),
            ..Default::default()
        };
        assert!(has_any_capabilities(&caps));
    }

    #[test]
    fn has_any_capabilities_with_bun() {
        let _guard = test_guard!();
        let caps = WorkerCapabilities {
            bun_version: Some("1.2.3".to_string()),
            ..Default::default()
        };
        assert!(has_any_capabilities(&caps));
    }

    #[test]
    fn has_any_capabilities_with_node() {
        let _guard = test_guard!();
        let caps = WorkerCapabilities {
            node_version: Some("v20.0.0".to_string()),
            ..Default::default()
        };
        assert!(has_any_capabilities(&caps));
    }

    #[test]
    fn has_any_capabilities_with_npm() {
        let _guard = test_guard!();
        let caps = WorkerCapabilities {
            npm_version: Some("10.0.0".to_string()),
            ..Default::default()
        };
        assert!(has_any_capabilities(&caps));
    }

    #[test]
    fn has_any_capabilities_with_all() {
        let _guard = test_guard!();
        let caps = WorkerCapabilities {
            rustc_version: Some("rustc 1.87.0".to_string()),
            bun_version: Some("1.2.3".to_string()),
            node_version: Some("v20.0.0".to_string()),
            npm_version: Some("10.0.0".to_string()),
            ..Default::default()
        };
        assert!(has_any_capabilities(&caps));
    }

    // -------------------------------------------------------------------------
    // extract_version_numbers Tests
    // -------------------------------------------------------------------------

    #[test]
    fn extract_version_numbers_simple() {
        let _guard = test_guard!();
        assert_eq!(extract_version_numbers("1.2.3"), vec![1, 2, 3]);
    }

    #[test]
    fn extract_version_numbers_with_prefix() {
        let _guard = test_guard!();
        assert_eq!(
            extract_version_numbers("rustc 1.87.0-nightly"),
            vec![1, 87, 0]
        );
    }

    #[test]
    fn extract_version_numbers_node_format() {
        let _guard = test_guard!();
        assert_eq!(extract_version_numbers("v20.11.1"), vec![20, 11, 1]);
    }

    #[test]
    fn extract_version_numbers_empty() {
        let _guard = test_guard!();
        assert_eq!(extract_version_numbers(""), Vec::<u64>::new());
    }

    #[test]
    fn extract_version_numbers_no_numbers() {
        let _guard = test_guard!();
        assert_eq!(
            extract_version_numbers("no numbers here"),
            Vec::<u64>::new()
        );
    }

    #[test]
    fn extract_version_numbers_single() {
        let _guard = test_guard!();
        assert_eq!(extract_version_numbers("version 42"), vec![42]);
    }

    #[test]
    fn extract_version_numbers_large() {
        let _guard = test_guard!();
        assert_eq!(extract_version_numbers("2024.01.15"), vec![2024, 1, 15]);
    }

    // -------------------------------------------------------------------------
    // major_version Tests
    // -------------------------------------------------------------------------

    #[test]
    fn major_version_extracts_first() {
        let _guard = test_guard!();
        assert_eq!(major_version("rustc 1.87.0-nightly"), Some(1));
    }

    #[test]
    fn major_version_node() {
        let _guard = test_guard!();
        assert_eq!(major_version("v20.11.1"), Some(20));
    }

    #[test]
    fn major_version_empty() {
        let _guard = test_guard!();
        assert_eq!(major_version(""), None);
    }

    #[test]
    fn major_version_no_numbers() {
        let _guard = test_guard!();
        assert_eq!(major_version("no version"), None);
    }

    // -------------------------------------------------------------------------
    // major_minor_version Tests
    // -------------------------------------------------------------------------

    #[test]
    fn major_minor_version_extracts_both() {
        let _guard = test_guard!();
        assert_eq!(major_minor_version("rustc 1.87.0-nightly"), Some((1, 87)));
    }

    #[test]
    fn major_minor_version_node() {
        let _guard = test_guard!();
        assert_eq!(major_minor_version("v20.11.1"), Some((20, 11)));
    }

    #[test]
    fn major_minor_version_single_number() {
        let _guard = test_guard!();
        assert_eq!(major_minor_version("version 42"), None);
    }

    #[test]
    fn major_minor_version_empty() {
        let _guard = test_guard!();
        assert_eq!(major_minor_version(""), None);
    }

    // -------------------------------------------------------------------------
    // rust_version_mismatch Tests
    // -------------------------------------------------------------------------

    #[test]
    fn rust_version_mismatch_same_version() {
        let _guard = test_guard!();
        assert!(!rust_version_mismatch(
            "rustc 1.87.0-nightly",
            "rustc 1.87.0-nightly"
        ));
    }

    #[test]
    fn rust_version_mismatch_different_patch() {
        let _guard = test_guard!();
        // Same major.minor, different patch - should NOT be a mismatch
        assert!(!rust_version_mismatch("rustc 1.87.0", "rustc 1.87.1"));
    }

    #[test]
    fn rust_version_mismatch_different_minor() {
        let _guard = test_guard!();
        assert!(rust_version_mismatch("rustc 1.87.0", "rustc 1.86.0"));
    }

    #[test]
    fn rust_version_mismatch_different_major() {
        let _guard = test_guard!();
        assert!(rust_version_mismatch("rustc 1.87.0", "rustc 2.0.0"));
    }

    #[test]
    fn rust_version_mismatch_invalid_local() {
        let _guard = test_guard!();
        // If local can't be parsed, returns false (no mismatch detectable)
        assert!(!rust_version_mismatch("invalid", "rustc 1.87.0"));
    }

    #[test]
    fn rust_version_mismatch_invalid_remote() {
        let _guard = test_guard!();
        assert!(!rust_version_mismatch("rustc 1.87.0", "invalid"));
    }

    // -------------------------------------------------------------------------
    // major_version_mismatch Tests
    // -------------------------------------------------------------------------

    #[test]
    fn major_version_mismatch_same() {
        let _guard = test_guard!();
        assert!(!major_version_mismatch("bun 1.2.3", "bun 1.5.0"));
    }

    #[test]
    fn major_version_mismatch_different() {
        let _guard = test_guard!();
        assert!(major_version_mismatch("bun 1.2.3", "bun 2.0.0"));
    }

    #[test]
    fn major_version_mismatch_invalid_local() {
        let _guard = test_guard!();
        assert!(!major_version_mismatch("no version", "bun 1.2.3"));
    }

    #[test]
    fn major_version_mismatch_invalid_remote() {
        let _guard = test_guard!();
        assert!(!major_version_mismatch("bun 1.2.3", "no version"));
    }

    // -------------------------------------------------------------------------
    // summarize_capabilities Tests
    // -------------------------------------------------------------------------

    #[test]
    fn summarize_capabilities_empty() {
        let _guard = test_guard!();
        let caps = WorkerCapabilities::new();
        assert_eq!(summarize_capabilities(&caps), "unknown");
    }

    #[test]
    fn summarize_capabilities_rust_only() {
        let _guard = test_guard!();
        let caps = WorkerCapabilities {
            rustc_version: Some("rustc 1.87.0".to_string()),
            ..Default::default()
        };
        assert_eq!(summarize_capabilities(&caps), "rustc rustc 1.87.0");
    }

    #[test]
    fn summarize_capabilities_all() {
        let _guard = test_guard!();
        let caps = WorkerCapabilities {
            rustc_version: Some("1.87".to_string()),
            bun_version: Some("1.2".to_string()),
            node_version: Some("20.0".to_string()),
            npm_version: Some("10.0".to_string()),
            ..Default::default()
        };
        let result = summarize_capabilities(&caps);
        assert!(result.contains("rustc 1.87"));
        assert!(result.contains("bun 1.2"));
        assert!(result.contains("node 20.0"));
        assert!(result.contains("npm 10.0"));
    }

    // -------------------------------------------------------------------------
    // parse_bool Tests
    // -------------------------------------------------------------------------

    #[test]
    fn parse_bool_true() {
        let _guard = test_guard!();
        assert!(parse_bool("true", "test_key").unwrap());
    }

    #[test]
    fn parse_bool_false() {
        let _guard = test_guard!();
        assert!(!parse_bool("false", "test_key").unwrap());
    }

    #[test]
    fn parse_bool_with_whitespace() {
        let _guard = test_guard!();
        assert!(parse_bool("  true  ", "test_key").unwrap());
    }

    #[test]
    fn parse_bool_invalid() {
        let _guard = test_guard!();
        let result = parse_bool("yes", "test_key");
        assert!(result.is_err());
    }

    // -------------------------------------------------------------------------
    // parse_u32 Tests
    // -------------------------------------------------------------------------

    #[test]
    fn parse_u32_valid() {
        let _guard = test_guard!();
        assert_eq!(parse_u32("42", "test_key").unwrap(), 42);
    }

    #[test]
    fn parse_u32_zero() {
        let _guard = test_guard!();
        assert_eq!(parse_u32("0", "test_key").unwrap(), 0);
    }

    #[test]
    fn parse_u32_with_whitespace() {
        let _guard = test_guard!();
        assert_eq!(parse_u32("  123  ", "test_key").unwrap(), 123);
    }

    #[test]
    fn parse_u32_negative() {
        let _guard = test_guard!();
        let result = parse_u32("-1", "test_key");
        assert!(result.is_err());
    }

    #[test]
    fn parse_u32_non_numeric() {
        let _guard = test_guard!();
        let result = parse_u32("abc", "test_key");
        assert!(result.is_err());
    }

    #[test]
    fn parse_u32_overflow() {
        let _guard = test_guard!();
        let result = parse_u32("4294967296", "test_key"); // u32::MAX + 1
        assert!(result.is_err());
    }

    // -------------------------------------------------------------------------
    // parse_u64 Tests
    // -------------------------------------------------------------------------

    #[test]
    fn parse_u64_valid() {
        let _guard = test_guard!();
        assert_eq!(parse_u64("9999999999", "test_key").unwrap(), 9999999999);
    }

    #[test]
    fn parse_u64_zero() {
        let _guard = test_guard!();
        assert_eq!(parse_u64("0", "test_key").unwrap(), 0);
    }

    #[test]
    fn parse_u64_with_whitespace() {
        let _guard = test_guard!();
        assert_eq!(parse_u64("  456  ", "test_key").unwrap(), 456);
    }

    #[test]
    fn parse_u64_negative() {
        let _guard = test_guard!();
        let result = parse_u64("-1", "test_key");
        assert!(result.is_err());
    }

    // -------------------------------------------------------------------------
    // parse_f64 Tests
    // -------------------------------------------------------------------------

    #[test]
    fn parse_f64_integer() {
        let _guard = test_guard!();
        let result = parse_f64("42", "test_key").unwrap();
        assert!((result - 42.0).abs() < f64::EPSILON);
    }

    #[test]
    fn parse_f64_decimal() {
        let _guard = test_guard!();
        let result = parse_f64("2.71", "test_key").unwrap();
        assert!((result - 2.71).abs() < 0.001);
    }

    #[test]
    fn parse_f64_with_whitespace() {
        let _guard = test_guard!();
        let result = parse_f64("  0.5  ", "test_key").unwrap();
        assert!((result - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn parse_f64_negative() {
        let _guard = test_guard!();
        let result = parse_f64("-1.5", "test_key").unwrap();
        assert!((result - (-1.5)).abs() < f64::EPSILON);
    }

    #[test]
    fn parse_f64_invalid() {
        let _guard = test_guard!();
        let result = parse_f64("not a number", "test_key");
        assert!(result.is_err());
    }

    // -------------------------------------------------------------------------
    // parse_string_list Tests
    // -------------------------------------------------------------------------

    #[test]
    fn parse_string_list_empty() {
        let _guard = test_guard!();
        let result = parse_string_list("", "test_key").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn parse_string_list_single() {
        let _guard = test_guard!();
        let result = parse_string_list("item", "test_key").unwrap();
        assert_eq!(result, vec!["item"]);
    }

    #[test]
    fn parse_string_list_comma_separated() {
        let _guard = test_guard!();
        let result = parse_string_list("a, b, c", "test_key").unwrap();
        assert_eq!(result, vec!["a", "b", "c"]);
    }

    #[test]
    fn parse_string_list_toml_array() {
        let _guard = test_guard!();
        let result = parse_string_list(r#"["foo", "bar"]"#, "test_key").unwrap();
        assert_eq!(result, vec!["foo", "bar"]);
    }

    #[test]
    fn parse_string_list_toml_array_empty() {
        let _guard = test_guard!();
        let result = parse_string_list("[]", "test_key").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn parse_string_list_with_whitespace() {
        let _guard = test_guard!();
        let result = parse_string_list("  a  ,  b  ", "test_key").unwrap();
        assert_eq!(result, vec!["a", "b"]);
    }

    // -------------------------------------------------------------------------
    // indent_lines Tests
    // -------------------------------------------------------------------------

    #[test]
    fn indent_lines_single() {
        let _guard = test_guard!();
        assert_eq!(indent_lines("hello", "  "), "  hello");
    }

    #[test]
    fn indent_lines_multiple() {
        let _guard = test_guard!();
        assert_eq!(indent_lines("a\nb\nc", ">> "), ">> a\n>> b\n>> c");
    }

    #[test]
    fn indent_lines_empty() {
        let _guard = test_guard!();
        // Empty string has no lines, so output is also empty
        assert_eq!(indent_lines("", "  "), "");
    }

    #[test]
    fn indent_lines_empty_prefix() {
        let _guard = test_guard!();
        assert_eq!(indent_lines("a\nb", ""), "a\nb");
    }

    // -------------------------------------------------------------------------
    // format_build_duration Tests
    // -------------------------------------------------------------------------

    #[test]
    fn format_build_duration_seconds() {
        let _guard = test_guard!();
        assert_eq!(format_build_duration(45), "45s");
    }

    #[test]
    fn format_build_duration_zero() {
        let _guard = test_guard!();
        assert_eq!(format_build_duration(0), "0s");
    }

    #[test]
    fn format_build_duration_minutes() {
        let _guard = test_guard!();
        assert_eq!(format_build_duration(90), "1m 30s");
    }

    #[test]
    fn format_build_duration_exact_minute() {
        let _guard = test_guard!();
        assert_eq!(format_build_duration(60), "1m 0s");
    }

    #[test]
    fn format_build_duration_hours() {
        let _guard = test_guard!();
        assert_eq!(format_build_duration(3661), "1h 1m");
    }

    #[test]
    fn format_build_duration_exact_hour() {
        let _guard = test_guard!();
        assert_eq!(format_build_duration(3600), "1h 0m");
    }

    #[test]
    fn format_build_duration_multiple_hours() {
        let _guard = test_guard!();
        assert_eq!(format_build_duration(7380), "2h 3m"); // 2h 3m
    }

    // -------------------------------------------------------------------------
    // urlencoding_encode Tests
    // -------------------------------------------------------------------------

    #[test]
    fn urlencoding_encode_alphanumeric() {
        let _guard = test_guard!();
        assert_eq!(urlencoding_encode("abc123"), "abc123");
    }

    #[test]
    fn urlencoding_encode_safe_chars() {
        let _guard = test_guard!();
        assert_eq!(urlencoding_encode("a-b_c.d~e"), "a-b_c.d~e");
    }

    #[test]
    fn urlencoding_encode_spaces() {
        let _guard = test_guard!();
        assert_eq!(urlencoding_encode("hello world"), "hello%20world");
    }

    #[test]
    fn urlencoding_encode_special() {
        let _guard = test_guard!();
        assert_eq!(urlencoding_encode("a=b&c"), "a%3Db%26c");
    }

    #[test]
    fn urlencoding_encode_unicode() {
        let _guard = test_guard!();
        // Multi-byte UTF-8 characters should be percent-encoded
        let result = urlencoding_encode("hello\u{00E9}"); // é
        assert!(result.starts_with("hello%"));
        assert!(result.len() > 6); // Should be longer due to encoding
    }

    #[test]
    fn urlencoding_encode_empty() {
        let _guard = test_guard!();
        assert_eq!(urlencoding_encode(""), "");
    }

    // -------------------------------------------------------------------------
    // generate_config_toml Tests
    // -------------------------------------------------------------------------

    #[test]
    fn generate_config_toml_contains_all_sections() {
        let _guard = test_guard!();
        let values = ConfigValues {
            log_level: "info".to_string(),
            socket_path: "/tmp/rch.sock".to_string(),
            confidence_threshold: 0.85,
            min_local_time_ms: 2000,
            compression_level: 3,
        };
        let toml = generate_config_toml(&values);
        assert!(toml.contains("[general]"));
        assert!(toml.contains("[compilation]"));
        assert!(toml.contains("[transfer]"));
        assert!(toml.contains("enabled = true"));
        assert!(toml.contains("log_level = \"info\""));
        assert!(toml.contains("confidence_threshold = 0.85"));
        assert!(toml.contains("min_local_time_ms = 2000"));
        assert!(toml.contains("compression_level = 3"));
    }

    // -------------------------------------------------------------------------
    // generate_workers_toml Tests
    // -------------------------------------------------------------------------

    #[test]
    fn generate_workers_toml_single_worker() {
        let _guard = test_guard!();
        let workers = vec![WizardWorker {
            id: "worker-1".to_string(),
            host: "192.168.1.100".to_string(),
            user: "ubuntu".to_string(),
            identity_file: "~/.ssh/id_rsa".to_string(),
            total_slots: 8,
            priority: 100,
        }];
        let toml = generate_workers_toml(&workers);
        assert!(toml.contains("[[workers]]"));
        assert!(toml.contains("id = \"worker-1\""));
        assert!(toml.contains("host = \"192.168.1.100\""));
        assert!(toml.contains("user = \"ubuntu\""));
        assert!(toml.contains("total_slots = 8"));
        assert!(toml.contains("priority = 100"));
    }

    #[test]
    fn generate_workers_toml_multiple_workers() {
        let _guard = test_guard!();
        let workers = vec![
            WizardWorker {
                id: "w1".to_string(),
                host: "host1".to_string(),
                user: "user1".to_string(),
                identity_file: "key1".to_string(),
                total_slots: 4,
                priority: 100,
            },
            WizardWorker {
                id: "w2".to_string(),
                host: "host2".to_string(),
                user: "user2".to_string(),
                identity_file: "key2".to_string(),
                total_slots: 8,
                priority: 50,
            },
        ];
        let toml = generate_workers_toml(&workers);
        // Should contain two [[workers]] blocks
        let worker_count = toml.matches("[[workers]]").count();
        assert_eq!(worker_count, 2);
        assert!(toml.contains("id = \"w1\""));
        assert!(toml.contains("id = \"w2\""));
    }

    #[test]
    fn generate_workers_toml_empty() {
        let _guard = test_guard!();
        let workers: Vec<WizardWorker> = vec![];
        let toml = generate_workers_toml(&workers);
        // Should have header but no [[workers]] blocks
        assert!(toml.contains("RCH Workers Configuration"));
        assert!(!toml.contains("[[workers]]"));
    }

    // -------------------------------------------------------------------------
    // is_default_verify_size Tests
    // -------------------------------------------------------------------------

    #[test]
    fn is_default_verify_size_true() {
        let _guard = test_guard!();
        assert!(is_default_verify_size(&(100 * 1024 * 1024)));
    }

    #[test]
    fn is_default_verify_size_false() {
        let _guard = test_guard!();
        assert!(!is_default_verify_size(&0));
        assert!(!is_default_verify_size(&(50 * 1024 * 1024)));
    }
}
