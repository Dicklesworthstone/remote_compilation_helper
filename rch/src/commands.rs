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
        let result =
            deploy_binary_to_worker(worker, &local_binary, &local_version, force, dry_run, ctx)
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
            let _ = ctx.json(&JsonResponse::<()>::err_cmd(
                "workers setup",
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
                "workers setup",
                error_codes::CONFIG_NOT_FOUND,
                "No workers configured",
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
            let _ = ctx.json(&JsonResponse::<()>::err_cmd(
                "workers setup",
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
        let _ = ctx.json(&JsonResponse::ok(
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
    if !skip_toolchain {
        if let Some(tc) = toolchain {
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
            println!("      • Try: ssh -i {} {}@{}", identity_file, username, hostname);
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
    println!("{}", style.highlight("Step 3/5: Detecting System Capabilities"));

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
                    rust_version = if v == "none" { None } else { Some(v.to_string()) };
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
    new_entry.push_str(&format!("# Added by: rch workers init ({})\n",
        chrono::Local::now().format("%Y-%m-%d %H:%M")));
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
        let _ = ctx.json(&JsonResponse::ok_cmd("config init", ConfigInitResponse {
            created,
            already_existed,
        }));
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
    use serde_json::json;

    // -------------------------------------------------------------------------
    // JsonError Tests
    // -------------------------------------------------------------------------

    #[test]
    fn json_error_new_creates_error_with_code_and_message() {
        let error = JsonError::new("TEST_CODE", "Test message");
        assert_eq!(error.code, "TEST_CODE");
        assert_eq!(error.message, "Test message");
        assert!(error.details.is_none());
        assert!(error.suggestions.is_none());
    }

    #[test]
    fn json_error_with_details_adds_details() {
        let details = json!({"key": "value", "count": 42});
        let error = JsonError::new("CODE", "msg").with_details(details.clone());
        assert!(error.details.is_some());
        assert_eq!(error.details.unwrap(), details);
    }

    #[test]
    fn json_error_with_suggestions_adds_suggestions() {
        let suggestions = vec!["Try this".to_string(), "Or that".to_string()];
        let error = JsonError::new("CODE", "msg").with_suggestions(suggestions.clone());
        assert!(error.suggestions.is_some());
        assert_eq!(error.suggestions.unwrap(), suggestions);
    }

    #[test]
    fn json_error_chained_builders_work() {
        let error = JsonError::new("CODE", "msg")
            .with_details(json!({"info": "test"}))
            .with_suggestions(vec!["suggestion".to_string()]);
        assert_eq!(error.code, "CODE");
        assert!(error.details.is_some());
        assert!(error.suggestions.is_some());
    }

    #[test]
    fn json_error_serializes_correctly() {
        let error = JsonError::new("TEST_ERROR", "Something went wrong");
        let json = serde_json::to_value(&error).unwrap();
        assert_eq!(json["code"], "TEST_ERROR");
        assert_eq!(json["message"], "Something went wrong");
        // details and suggestions should be omitted when None
        assert!(json.get("details").is_none());
        assert!(json.get("suggestions").is_none());
    }

    #[test]
    fn json_error_with_details_serializes_details() {
        let error = JsonError::new("CODE", "msg").with_details(json!({"count": 5}));
        let json = serde_json::to_value(&error).unwrap();
        assert_eq!(json["details"]["count"], 5);
    }

    // -------------------------------------------------------------------------
    // JsonResponse Tests
    // -------------------------------------------------------------------------

    #[test]
    fn json_response_ok_creates_success_response() {
        let response: JsonResponse<String> = JsonResponse::ok("test cmd", "test data".to_string());
        assert!(response.success);
        assert_eq!(response.command, "test cmd");
        assert_eq!(response.version, JSON_ENVELOPE_VERSION);
        assert!(response.data.is_some());
        assert_eq!(response.data.unwrap(), "test data");
        assert!(response.error.is_none());
    }

    #[test]
    fn json_response_ok_cmd_is_alias_for_ok() {
        let response1: JsonResponse<i32> = JsonResponse::ok("cmd", 42);
        let response2: JsonResponse<i32> = JsonResponse::ok_cmd("cmd", 42);
        assert_eq!(response1.command, response2.command);
        assert_eq!(response1.success, response2.success);
        assert_eq!(response1.data, response2.data);
    }

    #[test]
    fn json_response_err_creates_error_response() {
        let response: JsonResponse<()> = JsonResponse::err("failed cmd", "error message");
        assert!(!response.success);
        assert_eq!(response.command, "failed cmd");
        assert!(response.data.is_none());
        assert!(response.error.is_some());
        let error = response.error.unwrap();
        assert_eq!(error.code, error_codes::INTERNAL_ERROR);
        assert_eq!(error.message, "error message");
    }

    #[test]
    fn json_response_err_cmd_creates_error_with_custom_code() {
        let response: JsonResponse<()> = JsonResponse::err_cmd(
            "cmd",
            error_codes::WORKER_UNREACHABLE,
            "Worker not available",
        );
        assert!(!response.success);
        assert!(response.error.is_some());
        let error = response.error.unwrap();
        assert_eq!(error.code, error_codes::WORKER_UNREACHABLE);
        assert_eq!(error.message, "Worker not available");
    }

    #[test]
    fn json_response_ok_serializes_without_error_field() {
        let response: JsonResponse<String> = JsonResponse::ok("test", "data".to_string());
        let json = serde_json::to_value(&response).unwrap();
        assert!(json.get("error").is_none());
        assert_eq!(json["data"], "data");
        assert_eq!(json["success"], true);
    }

    #[test]
    fn json_response_err_serializes_without_data_field() {
        let response: JsonResponse<String> = JsonResponse::err("test", "error msg");
        let json = serde_json::to_value(&response).unwrap();
        assert!(json.get("data").is_none());
        assert!(json.get("error").is_some());
        assert_eq!(json["success"], false);
    }

    #[test]
    fn json_response_with_complex_data_serializes() {
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
        let response = JsonResponse::ok("complex", data);
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["data"]["name"], "test");
        assert_eq!(json["data"]["count"], 3);
        assert_eq!(json["data"]["items"].as_array().unwrap().len(), 2);
    }

    // -------------------------------------------------------------------------
    // WorkerInfo Tests
    // -------------------------------------------------------------------------

    #[test]
    fn worker_info_from_worker_config_converts_all_fields() {
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
        let workers = vec![
            WorkerInfo {
                id: "w1".to_string(),
                host: "host1".to_string(),
                user: "u1".to_string(),
                total_slots: 8,
                priority: 100,
                tags: vec![],
            },
            WorkerInfo {
                id: "w2".to_string(),
                host: "host2".to_string(),
                user: "u2".to_string(),
                total_slots: 16,
                priority: 50,
                tags: vec!["fast".to_string()],
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
        let response = DaemonStatusResponse {
            running: true,
            socket_path: "/tmp/rch.sock".to_string(),
            uptime_seconds: Some(3600),
        };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["running"], true);
        assert_eq!(json["socket_path"], "/tmp/rch.sock");
        assert_eq!(json["uptime_seconds"], 3600);
    }

    #[test]
    fn daemon_status_response_not_running_serializes() {
        let response = DaemonStatusResponse {
            running: false,
            socket_path: "/tmp/rch.sock".to_string(),
            uptime_seconds: None,
        };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["running"], false);
        assert!(json.get("uptime_seconds").is_none());
    }

    #[test]
    fn status_response_serializes() {
        let response = StatusResponse {
            daemon_running: true,
            hook_installed: true,
            workers_count: 3,
            workers: None,
        };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["daemon_running"], true);
        assert_eq!(json["hook_installed"], true);
        assert_eq!(json["workers_count"], 3);
        assert!(json.get("workers").is_none());
    }

    #[test]
    fn config_show_response_serializes() {
        let response = ConfigShowResponse {
            general: ConfigGeneralSection {
                enabled: true,
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
            },
            sources: vec!["~/.config/rch/config.toml".to_string()],
            value_sources: None,
        };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["general"]["enabled"], true);
        assert_eq!(json["compilation"]["confidence_threshold"], 0.85);
        assert_eq!(json["transfer"]["compression_level"], 3);
    }

    #[test]
    fn config_init_response_serializes() {
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
        let response = ConfigValidationResponse {
            errors: vec![],
            warnings: vec![],
            valid: true,
        };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["valid"], true);
        assert!(json["errors"].as_array().unwrap().is_empty());
    }

    #[test]
    fn config_validation_response_with_issues_serializes() {
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
        assert_eq!(json["valid"], false);
        assert_eq!(json["errors"][0]["message"], "Invalid syntax");
        assert_eq!(json["warnings"][0]["file"], "workers.toml");
    }

    #[test]
    fn config_set_response_serializes() {
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
        let response = ConfigExportResponse {
            format: "toml".to_string(),
            content: "[general]\nenabled = true".to_string(),
        };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["format"], "toml");
        assert!(json["content"].as_str().unwrap().contains("enabled"));
    }

    #[test]
    fn hook_action_response_success_serializes() {
        let response = HookActionResponse {
            action: "install".to_string(),
            success: true,
            settings_path: "~/.config/claude-code/settings.json".to_string(),
            message: Some("Hook installed successfully".to_string()),
        };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["action"], "install");
        assert_eq!(json["success"], true);
        assert_eq!(json["message"], "Hook installed successfully");
    }

    #[test]
    fn hook_action_response_without_message_serializes() {
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
        assert_eq!(json["daemon_connected"], true);
        assert_eq!(json["workers_configured"], 2);
        let tests = json["classification_tests"].as_array().unwrap();
        assert_eq!(tests[0]["command"], "cargo build");
        assert_eq!(tests[0]["passed"], true);
    }

    #[test]
    fn classification_test_result_serializes() {
        let result = ClassificationTestResult {
            command: "bun test".to_string(),
            is_compilation: true,
            confidence: 0.92,
            expected_intercept: true,
            passed: true,
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["command"], "bun test");
        assert_eq!(json["is_compilation"], true);
        assert_eq!(json["confidence"], 0.92);
    }

    // -------------------------------------------------------------------------
    // Error Codes Tests
    // -------------------------------------------------------------------------

    #[test]
    fn error_codes_are_strings() {
        assert_eq!(error_codes::WORKER_UNREACHABLE, "WORKER_UNREACHABLE");
        assert_eq!(error_codes::WORKER_NOT_FOUND, "WORKER_NOT_FOUND");
        assert_eq!(error_codes::CONFIG_INVALID, "CONFIG_INVALID");
        assert_eq!(error_codes::CONFIG_NOT_FOUND, "CONFIG_NOT_FOUND");
        assert_eq!(error_codes::DAEMON_NOT_RUNNING, "DAEMON_NOT_RUNNING");
        assert_eq!(
            error_codes::DAEMON_CONNECTION_FAILED,
            "DAEMON_CONNECTION_FAILED"
        );
        assert_eq!(error_codes::SSH_CONNECTION_FAILED, "SSH_CONNECTION_FAILED");
        assert_eq!(error_codes::BENCHMARK_FAILED, "BENCHMARK_FAILED");
        assert_eq!(error_codes::HOOK_INSTALL_FAILED, "HOOK_INSTALL_FAILED");
        assert_eq!(error_codes::INTERNAL_ERROR, "INTERNAL_ERROR");
    }

    // -------------------------------------------------------------------------
    // config_dir Tests
    // -------------------------------------------------------------------------

    #[test]
    fn config_dir_returns_some() {
        // config_dir should return a path on most systems
        let dir = config_dir();
        // We can't guarantee it returns Some on all systems, but if it does,
        // it should be a valid path that ends with "rch"
        if let Some(path) = dir {
            assert!(path.to_string_lossy().contains("rch"));
        }
    }

    // -------------------------------------------------------------------------
    // JSON_ENVELOPE_VERSION Tests
    // -------------------------------------------------------------------------

    #[test]
    fn json_envelope_version_is_expected_value() {
        assert_eq!(JSON_ENVELOPE_VERSION, "1");
    }

    // -------------------------------------------------------------------------
    // DEFAULT_SOCKET_PATH Tests
    // -------------------------------------------------------------------------

    #[test]
    fn default_socket_path_is_expected() {
        assert_eq!(DEFAULT_SOCKET_PATH, "/tmp/rch.sock");
    }
}
