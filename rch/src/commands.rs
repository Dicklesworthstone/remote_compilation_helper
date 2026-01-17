//! CLI command handler implementations.
//!
//! This module contains the actual business logic for each CLI subcommand.

use crate::ui::context::OutputContext;
use crate::ui::theme::StatusIndicator;
use anyhow::{Context, Result, bail};
use directories::ProjectDirs;
use rch_common::{
    DiscoveredHost, RchConfig, SshClient, SshOptions, WorkerConfig, WorkerId, discover_all,
};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::process::Command;
use tracing::debug;

/// Default socket path.
const DEFAULT_SOCKET_PATH: &str = "/tmp/rch.sock";

// =============================================================================
// JSON Response Types
// =============================================================================

/// JSON envelope version for API compatibility detection.
pub const JSON_ENVELOPE_VERSION: &str = "1";

/// Standard error codes for JSON responses.
#[allow(dead_code)]
pub mod error_codes {
    pub const WORKER_UNREACHABLE: &str = "WORKER_UNREACHABLE";
    pub const WORKER_NOT_FOUND: &str = "WORKER_NOT_FOUND";
    pub const CONFIG_INVALID: &str = "CONFIG_INVALID";
    pub const CONFIG_NOT_FOUND: &str = "CONFIG_NOT_FOUND";
    pub const DAEMON_NOT_RUNNING: &str = "DAEMON_NOT_RUNNING";
    pub const DAEMON_CONNECTION_FAILED: &str = "DAEMON_CONNECTION_FAILED";
    pub const SSH_CONNECTION_FAILED: &str = "SSH_CONNECTION_FAILED";
    pub const BENCHMARK_FAILED: &str = "BENCHMARK_FAILED";
    pub const HOOK_INSTALL_FAILED: &str = "HOOK_INSTALL_FAILED";
    pub const INTERNAL_ERROR: &str = "INTERNAL_ERROR";
}

/// Structured error information for JSON responses.
#[derive(Debug, Clone, Serialize)]
pub struct JsonError {
    /// Machine-readable error code (e.g., "WORKER_UNREACHABLE").
    pub code: String,
    /// Human-readable error message.
    pub message: String,
    /// Optional structured details about the error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
    /// Optional suggestions for resolving the error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggestions: Option<Vec<String>>,
}

#[allow(dead_code)]
impl JsonError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            details: None,
            suggestions: None,
        }
    }

    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }

    pub fn with_suggestions(mut self, suggestions: Vec<String>) -> Self {
        self.suggestions = Some(suggestions);
        self
    }

    /// Create a JsonError from a miette Diagnostic.
    pub fn from_diagnostic(diag: &dyn miette::Diagnostic) -> Self {
        let code = diag
            .code()
            .map(|c| c.to_string())
            .unwrap_or_else(|| error_codes::INTERNAL_ERROR.to_string());
        let message = diag.to_string();
        let suggestions = diag.help().map(|h| vec![h.to_string()]);
        Self {
            code,
            message,
            details: None,
            suggestions,
        }
    }
}

/// Standard JSON envelope for all command responses.
#[derive(Debug, Clone, Serialize)]
pub struct JsonResponse<T: Serialize> {
    /// Envelope version for API compatibility.
    pub version: &'static str,
    /// Command that produced this response (e.g., "workers list").
    pub command: String,
    /// Whether the command succeeded.
    pub success: bool,
    /// Response data on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    /// Structured error on failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonError>,
}

impl<T: Serialize> JsonResponse<T> {
    /// Create a successful response.
    pub fn ok(command: impl Into<String>, data: T) -> Self {
        Self {
            version: JSON_ENVELOPE_VERSION,
            command: command.into(),
            success: true,
            data: Some(data),
            error: None,
        }
    }

    /// Create a successful response with explicit command name (alias for ok).
    pub fn ok_cmd(command: impl Into<String>, data: T) -> Self {
        Self::ok(command, data)
    }

    /// Create an error response.
    pub fn err(command: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            version: JSON_ENVELOPE_VERSION,
            command: command.into(),
            success: false,
            data: None,
            error: Some(JsonError::new(error_codes::INTERNAL_ERROR, message)),
        }
    }

    /// Create an error response with explicit command name and error code.
    pub fn err_cmd(
        command: impl Into<String>,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            version: JSON_ENVELOPE_VERSION,
            command: command.into(),
            success: false,
            data: None,
            error: Some(JsonError::new(code, message)),
        }
    }
}

/// Worker information for JSON output.
#[derive(Debug, Clone, Serialize)]
pub struct WorkerInfo {
    pub id: String,
    pub host: String,
    pub user: String,
    pub total_slots: u32,
    pub priority: u32,
    pub tags: Vec<String>,
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
        }
    }
}

/// Workers list response.
#[derive(Debug, Clone, Serialize)]
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

/// Daemon status response.
#[derive(Debug, Clone, Serialize)]
pub struct DaemonStatusResponse {
    pub running: bool,
    pub socket_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uptime_seconds: Option<u64>,
}

/// System status response.
#[derive(Debug, Clone, Serialize)]
pub struct StatusResponse {
    pub daemon_running: bool,
    pub hook_installed: bool,
    pub workers_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workers: Option<Vec<WorkerInfo>>,
}

/// Configuration show response for JSON output.
#[derive(Debug, Clone, Serialize)]
pub struct ConfigShowResponse {
    pub general: ConfigGeneralSection,
    pub compilation: ConfigCompilationSection,
    pub transfer: ConfigTransferSection,
    pub sources: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_sources: Option<Vec<ConfigValueSource>>,
}

/// Source information for a single configuration value.
#[derive(Debug, Clone, Serialize)]
pub struct ConfigValueSource {
    pub key: String,
    pub value: String,
    pub source: String,
}

/// Configuration export response for JSON output.
#[derive(Debug, Clone, Serialize)]
pub struct ConfigExportResponse {
    pub format: String,
    pub content: String,
}

/// General configuration section.
#[derive(Debug, Clone, Serialize)]
pub struct ConfigGeneralSection {
    pub enabled: bool,
    pub log_level: String,
    pub socket_path: String,
}

/// Compilation configuration section.
#[derive(Debug, Clone, Serialize)]
pub struct ConfigCompilationSection {
    pub confidence_threshold: f64,
    pub min_local_time_ms: u64,
}

/// Transfer configuration section.
#[derive(Debug, Clone, Serialize)]
pub struct ConfigTransferSection {
    pub compression_level: u32,
    pub exclude_patterns: Vec<String>,
}

/// Configuration init response for JSON output.
#[derive(Debug, Clone, Serialize)]
pub struct ConfigInitResponse {
    pub created: Vec<String>,
    pub already_existed: Vec<String>,
}

/// Configuration validation response for JSON output.
#[derive(Debug, Clone, Serialize)]
pub struct ConfigValidationResponse {
    pub errors: Vec<ConfigValidationIssue>,
    pub warnings: Vec<ConfigValidationIssue>,
    pub valid: bool,
}

/// A single validation issue.
#[derive(Debug, Clone, Serialize)]
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

/// Hook install/uninstall response for JSON output.
#[derive(Debug, Clone, Serialize)]
pub struct HookActionResponse {
    pub action: String,
    pub success: bool,
    pub settings_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Hook test response for JSON output.
#[derive(Debug, Clone, Serialize)]
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
pub struct ClassificationTestResult {
    pub command: String,
    pub is_compilation: bool,
    pub confidence: f64,
    pub expected_intercept: bool,
    pub passed: bool,
}

/// Get the RCH config directory path.
pub fn config_dir() -> Option<PathBuf> {
    ProjectDirs::from("com", "rch", "rch").map(|dirs| dirs.config_dir().to_path_buf())
}

// =============================================================================
// Workers Commands
// =============================================================================

/// Load workers from configuration file.
pub fn load_workers_from_config() -> Result<Vec<WorkerConfig>> {
    let config_path = config_dir()
        .map(|d| d.join("workers.toml"))
        .context("Could not determine config directory")?;

    if !config_path.exists() {
        println!("No workers configured.");
        println!("Create a workers config at: {:?}", config_path);
        println!("\nRun `rch config init` to generate example configuration.");
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
pub fn workers_list(ctx: &OutputContext) -> Result<()> {
    let workers = load_workers_from_config()?;
    let style = ctx.theme();

    // JSON output mode
    if ctx.is_json() {
        let response = WorkersListResponse {
            count: workers.len(),
            workers: workers.iter().map(WorkerInfo::from).collect(),
        };
        let _ = ctx.json(&JsonResponse::ok("workers list", response));
        return Ok(());
    }

    if workers.is_empty() {
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
        println!(
            "    {} {} {}  {} {} {}",
            style.key("Slots"),
            style.muted(":"),
            style.value(&worker.total_slots.to_string()),
            style.key("Priority"),
            style.muted(":"),
            style.value(&worker.priority.to_string())
        );
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
            let _ = ctx.json(&JsonResponse::<Vec<WorkerProbeResult>>::ok(
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
            let _ = ctx.json(&JsonResponse::<()>::err_cmd(
                "workers probe",
                error_codes::CONFIG_INVALID,
                "Specify a worker ID or use --all",
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
                let _ = ctx.json(&JsonResponse::<()>::err_cmd(
                    "workers probe",
                    error_codes::WORKER_NOT_FOUND,
                    format!("Worker '{}' not found", id),
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

        let mut client = SshClient::new(worker.clone(), SshOptions::default());

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
                        if ctx.is_json() {
                            results.push(WorkerProbeResult {
                                id: worker.id.as_str().to_string(),
                                host: worker.host.clone(),
                                status: "error".to_string(),
                                latency_ms: None,
                                error: Some(e.to_string()),
                            });
                        } else {
                            println!(
                                "{} {}",
                                StatusIndicator::Error.display(style),
                                style.error(&e.to_string())
                            );
                        }
                    }
                }
                let _ = client.disconnect().await;
            }
            Err(e) => {
                if ctx.is_json() {
                    results.push(WorkerProbeResult {
                        id: worker.id.as_str().to_string(),
                        host: worker.host.clone(),
                        status: "connection_failed".to_string(),
                        latency_ms: None,
                        error: Some(e.to_string()),
                    });
                } else {
                    println!(
                        "{} Connection failed: {}",
                        StatusIndicator::Error.display(style),
                        style.muted(&e.to_string())
                    );
                }
            }
        }
    }

    if ctx.is_json() {
        let _ = ctx.json(&JsonResponse::ok("workers probe", results));
    }

    Ok(())
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
            let _ = ctx.json(&JsonResponse::<Vec<WorkerBenchmarkResult>>::ok(
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

        let mut client = SshClient::new(worker.clone(), SshOptions::default());

        match client.connect().await {
            Ok(()) => {
                // Run a simple benchmark: compile a hello world Rust program
                let benchmark_cmd = r###"#
                    cd /tmp && \
                    mkdir -p rch_bench && \
                    cd rch_bench && \
                    echo 'fn main() { println!("hello"); }' > main.rs && \
                    time rustc main.rs -o hello 2>&1 | grep real || echo 'rustc not found'
                "###;

                let start = std::time::Instant::now();
                let result = client.execute(benchmark_cmd).await;
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
                        if ctx.is_json() {
                            results.push(WorkerBenchmarkResult {
                                id: worker.id.as_str().to_string(),
                                host: worker.host.clone(),
                                status: "error".to_string(),
                                duration_ms: None,
                                error: Some(e.to_string()),
                            });
                        } else {
                            println!(
                                "{} {}",
                                StatusIndicator::Error.display(style),
                                style.error(&e.to_string())
                            );
                        }
                    }
                }
                let _ = client.disconnect().await;
            }
            Err(e) => {
                if ctx.is_json() {
                    results.push(WorkerBenchmarkResult {
                        id: worker.id.as_str().to_string(),
                        host: worker.host.clone(),
                        status: "connection_failed".to_string(),
                        duration_ms: None,
                        error: Some(e.to_string()),
                    });
                } else {
                    println!(
                        "{} {}",
                        StatusIndicator::Error.with_label(style, "Connection failed:"),
                        style.muted(&e.to_string())
                    );
                }
            }
        }
    }

    if ctx.is_json() {
        let _ = ctx.json(&JsonResponse::ok("workers benchmark", results));
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
            let _ = ctx.json(&JsonResponse::<()>::err_cmd(
                "workers drain",
                error_codes::DAEMON_NOT_RUNNING,
                "Daemon is not running",
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
                    let _ = ctx.json(&JsonResponse::ok("workers drain", WorkerActionResponse {
                        worker_id: worker_id.to_string(),
                        action: "drain".to_string(),
                        success: false,
                        message: Some(response),
                    }));
                } else {
                    println!(
                        "{} Failed to drain worker: {}",
                        StatusIndicator::Error.display(style),
                        style.muted(&response)
                    );
                }
            } else if ctx.is_json() {
                let _ = ctx.json(&JsonResponse::ok("workers drain", WorkerActionResponse {
                    worker_id: worker_id.to_string(),
                    action: "drain".to_string(),
                    success: true,
                    message: Some("Worker is now draining".to_string()),
                }));
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
                let _ = ctx.json(&JsonResponse::<()>::err_cmd(
                    "workers drain",
                    error_codes::INTERNAL_ERROR,
                    e.to_string(),
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
            let _ = ctx.json(&JsonResponse::<()>::err_cmd(
                "workers enable",
                error_codes::DAEMON_NOT_RUNNING,
                "Daemon is not running",
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
                    let _ = ctx.json(&JsonResponse::ok("workers enable", WorkerActionResponse {
                        worker_id: worker_id.to_string(),
                        action: "enable".to_string(),
                        success: false,
                        message: Some(response),
                    }));
                } else {
                    println!(
                        "{} Failed to enable worker: {}",
                        StatusIndicator::Error.display(style),
                        style.muted(&response)
                    );
                }
            } else if ctx.is_json() {
                let _ = ctx.json(&JsonResponse::ok("workers enable", WorkerActionResponse {
                    worker_id: worker_id.to_string(),
                    action: "enable".to_string(),
                    success: true,
                    message: Some("Worker is now enabled".to_string()),
                }));
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
                let _ = ctx.json(&JsonResponse::<()>::err_cmd(
                    "workers enable",
                    error_codes::INTERNAL_ERROR,
                    e.to_string(),
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
            let _ = ctx.json(&JsonResponse::<()>::err_cmd(
                "workers deploy-binary",
                error_codes::CONFIG_INVALID,
                "Specify either a worker ID or --all",
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
            let _ = ctx.json(&JsonResponse::<()>::err_cmd(
                "workers deploy-binary",
                error_codes::CONFIG_NOT_FOUND,
                "No workers configured. Run 'rch workers discover --add' first.",
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
            let _ = ctx.json(&JsonResponse::<()>::err_cmd(
                "workers deploy-binary",
                error_codes::WORKER_NOT_FOUND,
                format!("Worker '{}' not found", worker_id.unwrap_or_default()),
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
        let result = deploy_binary_to_worker(
            worker,
            &local_binary,
            &local_version,
            force,
            dry_run,
            ctx,
        )
        .await;
        results.push(result);
    }

    // JSON output
    if ctx.is_json() {
        let _ = ctx.json(&JsonResponse::ok(
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
            debug!("Remote version {} differs from local {}", ver, local_version);
        }
        Err(_) => {
            debug!("rch-wkr not installed on {}", worker_id);
        }
    };

    if dry_run {
        if !ctx.is_json() {
            println!("{} (would deploy {})", style.muted("dry-run"), local_version);
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
        .arg("-o").arg("BatchMode=yes")
        .arg("-o").arg("ConnectTimeout=10")
        .arg("-i").arg(&worker.identity_file)
        .arg(&target)
        .arg(format!("mkdir -p ~/{}", remote_dir));

    let mkdir_output = mkdir_cmd.output().await.context("Failed to create remote directory")?;
    if !mkdir_output.status.success() {
        bail!(
            "Failed to create remote directory: {}",
            String::from_utf8_lossy(&mkdir_output.stderr)
        );
    }

    // Copy binary
    let mut scp_cmd = Command::new("scp");
    scp_cmd
        .arg("-o").arg("BatchMode=yes")
        .arg("-o").arg("ConnectTimeout=30")
        .arg("-i").arg(&worker.identity_file)
        .arg(local_binary)
        .arg(format!("{}:~/{}", target, remote_path));

    let scp_output = scp_cmd.output().await.context("Failed to scp binary")?;
    if !scp_output.status.success() {
        bail!("scp failed: {}", String::from_utf8_lossy(&scp_output.stderr));
    }

    // Make executable
    let mut chmod_cmd = Command::new("ssh");
    chmod_cmd
        .arg("-o").arg("BatchMode=yes")
        .arg("-i").arg(&worker.identity_file)
        .arg(&target)
        .arg(format!("chmod +x ~/{}", remote_path));

    let chmod_output = chmod_cmd.output().await.context("Failed to chmod binary")?;
    if !chmod_output.status.success() {
        bail!("chmod failed: {}", String::from_utf8_lossy(&chmod_output.stderr));
    }

    // Verify installation
    let mut verify_cmd = Command::new("ssh");
    verify_cmd
        .arg("-o").arg("BatchMode=yes")
        .arg("-i").arg(&worker.identity_file)
        .arg(&target)
        .arg(format!("~/{} health", remote_path));

    let verify_output = verify_cmd.output().await.context("Failed to verify installation")?;
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
            let _ = ctx.json(&JsonResponse::<()>::err_cmd(
                "workers sync-toolchain",
                error_codes::CONFIG_INVALID,
                "Specify either a worker ID or --all",
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
            let _ = ctx.json(&JsonResponse::<()>::err_cmd(
                "workers sync-toolchain",
                error_codes::CONFIG_NOT_FOUND,
                "No workers configured",
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
            let _ = ctx.json(&JsonResponse::<()>::err_cmd(
                "workers sync-toolchain",
                error_codes::WORKER_NOT_FOUND,
                format!("Worker '{}' not found", worker_id.unwrap_or_default()),
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
        let _ = ctx.json(&JsonResponse::ok(
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
            if line.starts_with("channel") {
                if let Some(value) = line.split('=').nth(1) {
                    let channel = value.trim().trim_matches('"').trim_matches('\'');
                    return Ok(channel.to_string());
                }
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
    cmd.arg(format!("rustup show | grep -q '{}' && echo FOUND || echo NOTFOUND", toolchain));

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
    cmd.arg(format!("rustup install {} && rustup component add rust-src --toolchain {}", toolchain, toolchain));

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
            let _ = ctx.json(&JsonResponse::ok(
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

        let _ = ctx.json(&JsonResponse::ok(
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
            let short_path = identity
                .replace(&dirs::home_dir().map(|p| p.display().to_string()).unwrap_or_default(), "~");
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
        bail!("SSH failed: {}", stderr.trim());
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
                    info.rust_version = if v == "none" { None } else { Some(v.to_string()) };
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
        let _ = ctx.json(&JsonResponse::ok("daemon status", DaemonStatusResponse {
            running,
            socket_path: DEFAULT_SOCKET_PATH.to_string(),
            uptime_seconds,
        }));
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
            let _ = ctx.json(&JsonResponse::ok("daemon start", DaemonActionResponse {
                action: "start".to_string(),
                success: false,
                socket_path: DEFAULT_SOCKET_PATH.to_string(),
                message: Some("Daemon already running".to_string()),
            }));
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
                    let _ = ctx.json(&JsonResponse::ok("daemon start", DaemonActionResponse {
                        action: "start".to_string(),
                        success: true,
                        socket_path: DEFAULT_SOCKET_PATH.to_string(),
                        message: Some("Daemon started successfully".to_string()),
                    }));
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
                let _ = ctx.json(&JsonResponse::ok("daemon start", DaemonActionResponse {
                    action: "start".to_string(),
                    success: false,
                    socket_path: DEFAULT_SOCKET_PATH.to_string(),
                    message: Some("Process started but socket not found".to_string()),
                }));
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
                let _ = ctx.json(&JsonResponse::<()>::err("daemon start", e.to_string()));
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
            let _ = ctx.json(&JsonResponse::ok("daemon stop", DaemonActionResponse {
                action: "stop".to_string(),
                success: true,
                socket_path: DEFAULT_SOCKET_PATH.to_string(),
                message: Some("Daemon was not running".to_string()),
            }));
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
                        let _ = ctx.json(&JsonResponse::ok("daemon stop", DaemonActionResponse {
                            action: "stop".to_string(),
                            success: true,
                            socket_path: DEFAULT_SOCKET_PATH.to_string(),
                            message: Some("Daemon stopped".to_string()),
                        }));
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
                let _ = ctx.json(&JsonResponse::ok("daemon stop", DaemonActionResponse {
                    action: "stop".to_string(),
                    success: false,
                    socket_path: DEFAULT_SOCKET_PATH.to_string(),
                    message: Some("Daemon may still be shutting down".to_string()),
                }));
            } else {
                println!(
                    "{} Daemon may still be shutting down...",
                    StatusIndicator::Warning.display(style)
                );
            }
        }
        Err(_) => {
            if ctx.is_json() {
                let _ = ctx.json(&JsonResponse::<()>::err(
                    "daemon stop",
                    "Could not send shutdown command",
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
                        let _ = ctx.json(&JsonResponse::ok("daemon stop", DaemonActionResponse {
                            action: "stop".to_string(),
                            success: true,
                            socket_path: DEFAULT_SOCKET_PATH.to_string(),
                            message: Some("Daemon stopped via pkill".to_string()),
                        }));
                    } else {
                        println!(
                            "{}",
                            StatusIndicator::Success.with_label(style, "Daemon stopped.")
                        );
                    }
                }
                _ => {
                    if ctx.is_json() {
                        let _ = ctx.json(&JsonResponse::<()>::err(
                            "daemon stop",
                            "Could not stop daemon",
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
                let _ = ctx.json(&JsonResponse::ok("daemon logs", DaemonLogsResponse {
                    log_file: Some(path.display().to_string()),
                    lines: log_lines,
                    found: true,
                }));
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
        let _ = ctx.json(&JsonResponse::ok("daemon logs", DaemonLogsResponse {
            log_file: None,
            lines: vec![],
            found: false,
        }));
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

    // Load user config
    let config = crate::config::load_config()?;
    let defaults = RchConfig::default();

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
        Some(determine_value_sources(&config, &defaults))
    } else {
        None
    };

    // JSON output mode
    if ctx.is_json() {
        let response = ConfigShowResponse {
            general: ConfigGeneralSection {
                enabled: config.general.enabled,
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
            },
            sources,
            value_sources,
        };
        let _ = ctx.json(&JsonResponse::ok("config show", response));
        return Ok(());
    }

    println!("{}", style.format_header("Effective RCH Configuration"));
    println!();

    // Helper closure to format value with source
    let format_with_source =
        |key: &str, value: &str, sources: &Option<Vec<ConfigValueSource>>| -> String {
            if let Some(vs) = sources {
                if let Some(s) = vs.iter().find(|v| v.key == key) {
                    return format!("{} {}", value, style.muted(&format!("# from {}", s.source)));
                }
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
    println!("  {} = [", style.key("exclude_patterns"));
    for pattern in &config.transfer.exclude_patterns {
        println!("    {},", style.value(&format!("\"{}\"", pattern)));
    }
    println!("  ]");

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

/// Determine the source of each configuration value.
fn determine_value_sources(config: &RchConfig, defaults: &RchConfig) -> Vec<ConfigValueSource> {
    let mut sources = Vec::new();
    let project_config_exists = PathBuf::from(".rch/config.toml").exists();
    let user_config_exists = config_dir()
        .map(|d| d.join("config.toml").exists())
        .unwrap_or(false);

    // Check each value and determine its source
    // Priority: env > project > user > default

    // general.enabled
    let enabled_source = if std::env::var("RCH_ENABLED").is_ok() {
        "env:RCH_ENABLED"
    } else if project_config_exists && config.general.enabled != defaults.general.enabled {
        "project:.rch/config.toml"
    } else if user_config_exists && config.general.enabled != defaults.general.enabled {
        "user:~/.config/rch/config.toml"
    } else {
        "default"
    };
    sources.push(ConfigValueSource {
        key: "general.enabled".to_string(),
        value: config.general.enabled.to_string(),
        source: enabled_source.to_string(),
    });

    // general.log_level
    let log_level_source = if std::env::var("RCH_LOG_LEVEL").is_ok() {
        "env:RCH_LOG_LEVEL"
    } else if project_config_exists && config.general.log_level != defaults.general.log_level {
        "project:.rch/config.toml"
    } else if user_config_exists && config.general.log_level != defaults.general.log_level {
        "user:~/.config/rch/config.toml"
    } else {
        "default"
    };
    sources.push(ConfigValueSource {
        key: "general.log_level".to_string(),
        value: config.general.log_level.clone(),
        source: log_level_source.to_string(),
    });

    // general.socket_path
    let socket_source = if std::env::var("RCH_SOCKET_PATH").is_ok() {
        "env:RCH_SOCKET_PATH"
    } else if project_config_exists && config.general.socket_path != defaults.general.socket_path {
        "project:.rch/config.toml"
    } else if user_config_exists && config.general.socket_path != defaults.general.socket_path {
        "user:~/.config/rch/config.toml"
    } else {
        "default"
    };
    sources.push(ConfigValueSource {
        key: "general.socket_path".to_string(),
        value: config.general.socket_path.clone(),
        source: socket_source.to_string(),
    });

    // compilation.confidence_threshold
    let threshold_source = if std::env::var("RCH_CONFIDENCE_THRESHOLD").is_ok() {
        "env:RCH_CONFIDENCE_THRESHOLD"
    } else if project_config_exists
        && (config.compilation.confidence_threshold - defaults.compilation.confidence_threshold)
            .abs()
            > f64::EPSILON
    {
        "project:.rch/config.toml"
    } else if user_config_exists
        && (config.compilation.confidence_threshold - defaults.compilation.confidence_threshold)
            .abs()
            > f64::EPSILON
    {
        "user:~/.config/rch/config.toml"
    } else {
        "default"
    };
    sources.push(ConfigValueSource {
        key: "compilation.confidence_threshold".to_string(),
        value: config.compilation.confidence_threshold.to_string(),
        source: threshold_source.to_string(),
    });

    // compilation.min_local_time_ms
    let min_local_source = if project_config_exists
        && config.compilation.min_local_time_ms != defaults.compilation.min_local_time_ms
    {
        "project:.rch/config.toml"
    } else if user_config_exists
        && config.compilation.min_local_time_ms != defaults.compilation.min_local_time_ms
    {
        "user:~/.config/rch/config.toml"
    } else {
        "default"
    };
    sources.push(ConfigValueSource {
        key: "compilation.min_local_time_ms".to_string(),
        value: config.compilation.min_local_time_ms.to_string(),
        source: min_local_source.to_string(),
    });

    // transfer.compression_level
    let compression_source = if std::env::var("RCH_COMPRESSION").is_ok() {
        "env:RCH_COMPRESSION"
    } else if project_config_exists
        && config.transfer.compression_level != defaults.transfer.compression_level
    {
        "project:.rch/config.toml"
    } else if user_config_exists
        && config.transfer.compression_level != defaults.transfer.compression_level
    {
        "user:~/.config/rch/config.toml"
    } else {
        "default"
    };
    sources.push(ConfigValueSource {
        key: "transfer.compression_level".to_string(),
        value: config.transfer.compression_level.to_string(),
        source: compression_source.to_string(),
    });

    sources
}

/// Initialize configuration files.
pub fn config_init(ctx: &OutputContext) -> Result<()> {
    let style = ctx.theme();
    let config_dir = config_dir().context("Could not determine config directory")?;

    // Create config directory
    std::fs::create_dir_all(&config_dir)
        .with_context(|| format!("Failed to create config directory: {:?}", config_dir))?;

    let config_path = config_dir.join("config.toml");
    let workers_path = config_dir.join("workers.toml");

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
        let _ = ctx.json(&JsonResponse::ok_cmd("config init", ConfigInitResponse {
            created,
            already_existed,
        }));
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

/// Validate configuration files.
pub fn config_validate(ctx: &OutputContext) -> Result<()> {
    let style = ctx.theme();

    println!("Validating RCH configuration...\n");

    let mut errors = 0;
    let mut warnings = 0;

    // Check config directory
    let config_dir = match config_dir() {
        Some(d) => d,
        None => {
            println!(
                "{} Could not determine config directory",
                StatusIndicator::Error.display(style)
            );
            return Ok(());
        }
    };

    // Check config.toml
    let config_path = config_dir.join("config.toml");
    if config_path.exists() {
        match std::fs::read_to_string(&config_path) {
            Ok(content) => match toml::from_str::<RchConfig>(&content) {
                Ok(config) => {
                    println!(
                        "{} {}: {}",
                        StatusIndicator::Success.display(style),
                        style.highlight("config.toml"),
                        style.success("Valid")
                    );

                    // Validate values
                    if config.compilation.confidence_threshold < 0.0
                        || config.compilation.confidence_threshold > 1.0
                    {
                        println!(
                            "  {} {} should be between 0.0 and 1.0",
                            StatusIndicator::Warning.display(style),
                            style.key("confidence_threshold")
                        );
                        warnings += 1;
                    }
                    if config.transfer.compression_level > 19 {
                        println!(
                            "  {} {} should be 1-19",
                            StatusIndicator::Warning.display(style),
                            style.key("compression_level")
                        );
                        warnings += 1;
                    }
                }
                Err(e) => {
                    println!(
                        "{} {}: {} - {}",
                        StatusIndicator::Error.display(style),
                        style.highlight("config.toml"),
                        style.error("Parse error"),
                        style.muted(&e.to_string())
                    );
                    errors += 1;
                }
            },
            Err(e) => {
                println!(
                    "{} {}: {} - {}",
                    StatusIndicator::Error.display(style),
                    style.highlight("config.toml"),
                    style.error("Read error"),
                    style.muted(&e.to_string())
                );
                errors += 1;
            }
        }
    } else {
        println!(
            "{} {}: {} {}",
            style.muted("-"),
            style.highlight("config.toml"),
            style.muted("Not found"),
            style.muted("(using defaults)")
        );
    }

    // Check workers.toml
    let workers_path = config_dir.join("workers.toml");
    if workers_path.exists() {
        match std::fs::read_to_string(&workers_path) {
            Ok(content) => match toml::from_str::<toml::Value>(&content) {
                Ok(parsed) => {
                    let workers = parsed
                        .get("workers")
                        .and_then(|w| w.as_array())
                        .map(|a| a.len())
                        .unwrap_or(0);
                    println!(
                        "{} {}: {} ({} workers)",
                        StatusIndicator::Success.display(style),
                        style.highlight("workers.toml"),
                        style.success("Valid"),
                        workers
                    );

                    if workers == 0 {
                        println!(
                            "  {} No workers defined",
                            StatusIndicator::Warning.display(style)
                        );
                        warnings += 1;
                    }
                }
                Err(e) => {
                    println!(
                        "{} {}: {} - {}",
                        StatusIndicator::Error.display(style),
                        style.highlight("workers.toml"),
                        style.error("Parse error"),
                        style.muted(&e.to_string())
                    );
                    errors += 1;
                }
            },
            Err(e) => {
                println!(
                    "{} {}: {} - {}",
                    StatusIndicator::Error.display(style),
                    style.highlight("workers.toml"),
                    style.error("Read error"),
                    style.muted(&e.to_string())
                );
                errors += 1;
            }
        }
    } else {
        println!(
            "{} {}: {}",
            StatusIndicator::Error.display(style),
            style.highlight("workers.toml"),
            style.error("Not found")
        );
        println!(
            "  {} Run {} to create it",
            StatusIndicator::Info.display(style),
            style.highlight("rch config init")
        );
        errors += 1;
    }

    // Check project config
    let project_config = PathBuf::from(".rch/config.toml");
    if project_config.exists() {
        match std::fs::read_to_string(&project_config) {
            Ok(content) => match toml::from_str::<RchConfig>(&content) {
                Ok(_) => println!(
                    "{} {}: {}",
                    StatusIndicator::Success.display(style),
                    style.highlight(".rch/config.toml"),
                    style.success("Valid")
                ),
                Err(e) => {
                    println!(
                        "{} {}: {} - {}",
                        StatusIndicator::Error.display(style),
                        style.highlight(".rch/config.toml"),
                        style.error("Parse error"),
                        style.muted(&e.to_string())
                    );
                    errors += 1;
                }
            },
            Err(e) => {
                println!(
                    "{} {}: {} - {}",
                    StatusIndicator::Error.display(style),
                    style.highlight(".rch/config.toml"),
                    style.error("Read error"),
                    style.muted(&e.to_string())
                );
                errors += 1;
            }
        }
    }

    println!();
    if errors > 0 {
        println!(
            "{} {} error(s), {} warning(s)",
            style.format_error("Validation failed:"),
            errors,
            warnings
        );
    } else if warnings > 0 {
        println!(
            "{} with {} warning(s)",
            style.format_warning("Validation passed"),
            warnings
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
        _ => {
            bail!(
                "Unknown config key: {}. Supported keys: general.enabled, general.log_level, general.socket_path, compilation.confidence_threshold, compilation.min_local_time_ms, transfer.compression_level, transfer.exclude_patterns",
                key
            );
        }
    }

    let contents = toml::to_string_pretty(&config)?;
    std::fs::write(config_path, format!("{}\n", contents))
        .with_context(|| format!("Failed to write {:?}", config_path))?;

    if ctx.is_json() {
        let _ = ctx.json(&JsonResponse::ok_cmd("config set", ConfigSetResponse {
            key: key.to_string(),
            value: value.to_string(),
            config_path: config_path.display().to_string(),
        }));
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
        }
        "env" => {
            // .env file format
            println!("# RCH configuration");
            println!("# Save to .rch.env in your project");
            println!();
            println!("RCH_ENABLED={}", config.general.enabled);
            println!("RCH_LOG_LEVEL={}", config.general.log_level);
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
        }
        "json" => {
            // JSON format (ignore ctx.is_json() since user explicitly requested JSON)
            let _ = ctx.json(&JsonResponse::ok_cmd(
                "config export",
                serde_json::json!({
                    "general": {
                        "enabled": config.general.enabled,
                        "log_level": config.general.log_level,
                        "socket_path": config.general.socket_path,
                    },
                    "compilation": {
                        "confidence_threshold": config.compilation.confidence_threshold,
                        "min_local_time_ms": config.compilation.min_local_time_ms,
                    },
                    "transfer": {
                        "compression_level": config.transfer.compression_level,
                        "exclude_patterns": config.transfer.exclude_patterns,
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

fn parse_bool(value: &str, key: &str) -> Result<bool> {
    value
        .trim()
        .parse::<bool>()
        .map_err(|_| anyhow::anyhow!("Invalid boolean for {}: {}", key, value))
}

fn parse_u32(value: &str, key: &str) -> Result<u32> {
    value
        .trim()
        .parse::<u32>()
        .map_err(|_| anyhow::anyhow!("Invalid u32 for {}: {}", key, value))
}

fn parse_u64(value: &str, key: &str) -> Result<u64> {
    value
        .trim()
        .parse::<u64>()
        .map_err(|_| anyhow::anyhow!("Invalid u64 for {}: {}", key, value))
}

fn parse_f64(value: &str, key: &str) -> Result<f64> {
    value
        .trim()
        .parse::<f64>()
        .map_err(|_| anyhow::anyhow!("Invalid float for {}: {}", key, value))
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
            .ok_or_else(|| anyhow::anyhow!("Invalid array for {}", key))?;
        let mut result = Vec::with_capacity(array.len());
        for item in array {
            let item_str = item
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("Array items must be strings for {}", key))?;
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
        let _ = ctx.json(&JsonResponse::ok("hook install", HookActionResponse {
            action: "install".to_string(),
            success: true,
            settings_path: settings_path.display().to_string(),
            message: Some("Hook installed successfully".to_string()),
        }));
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
            let _ = ctx.json(&JsonResponse::<()>::err_cmd(
                "hook uninstall",
                error_codes::CONFIG_NOT_FOUND,
                "Claude Code settings file not found",
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
            let _ = ctx.json(&JsonResponse::ok("hook uninstall", HookActionResponse {
                action: "uninstall".to_string(),
                success: true,
                settings_path: settings_path.display().to_string(),
                message: Some("Hook removed successfully".to_string()),
            }));
        } else {
            println!(
                "{} Hook removed from {}",
                StatusIndicator::Success.display(style),
                style.highlight(&settings_path.display().to_string())
            );
        }
    } else if ctx.is_json() {
        let _ = ctx.json(&JsonResponse::ok("hook uninstall", HookActionResponse {
            action: "uninstall".to_string(),
            success: false,
            settings_path: settings_path.display().to_string(),
            message: Some("Hook was not found".to_string()),
        }));
    } else {
        println!(
            "{} Hook not found in settings.",
            StatusIndicator::Info.display(style)
        );
    }

    Ok(())
}

/// Helper to get rchd path.
fn which_rchd() -> PathBuf {
    // Try to find rchd in same directory as current executable
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(dir) = exe_path.parent() {
            let rchd = dir.join("rchd");
            if rchd.exists() {
                return rchd;
            }
        }
    }

    // Fallback to path lookup
    which::which("rchd").unwrap_or_else(|_| PathBuf::from("rchd"))
}

/// Helper to send command to daemon socket.
async fn send_daemon_command(command: &str) -> Result<String> {
    let socket_path = Path::new(DEFAULT_SOCKET_PATH);
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

// Stub for status_overview
pub async fn status_overview(_workers: bool, _jobs: bool) -> Result<()> {
    // Implementation placeholder
    Ok(())
}

// Stub for hook_test
pub async fn hook_test(_ctx: &OutputContext) -> Result<()> {
    // Implementation placeholder
    Ok(())
}

// Stub for agents_list
pub fn agents_list(_all: bool, _ctx: &OutputContext) -> Result<()> {
    // Implementation placeholder
    Ok(())
}

// Stub for agents_status
pub fn agents_status(_agent: Option<String>, _ctx: &OutputContext) -> Result<()> {
    // Implementation placeholder
    Ok(())
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
