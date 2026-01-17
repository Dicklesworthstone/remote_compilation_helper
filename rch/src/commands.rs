//! CLI command handler implementations.
//!
//! This module contains the actual business logic for each CLI subcommand.

use crate::ui::context::OutputContext;
use crate::ui::style::{StatusIndicator, Style};
use anyhow::{Context, Result, bail};
use directories::ProjectDirs;
use rch_common::{RchConfig, SshClient, SshOptions, WorkerConfig, WorkerId};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::process::Command;
use tracing::debug;

// =============================================================================
// JSON Response Types
// =============================================================================

/// Standard JSON envelope for all command responses.
#[derive(Debug, Clone, Serialize)]
pub struct JsonResponse<T: Serialize> {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl<T: Serialize> JsonResponse<T> {
    pub fn ok(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    pub fn err(message: impl Into<String>) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message.into()),
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

/// Create a style for terminal output.
///
/// Detects terminal capabilities and creates appropriate styling.
fn terminal_style() -> Style {
    let is_tty = is_terminal::is_terminal(std::io::stdout());
    let supports_unicode = is_tty
        && std::env::var("LANG")
            .map(|l| l.contains("UTF"))
            .unwrap_or(true);
    Style::new(is_tty, supports_unicode)
}

/// Get the RCH config directory path.
pub fn config_dir() -> Option<PathBuf> {
    ProjectDirs::from("com", "rch", "rch").map(|dirs| dirs.config_dir().to_path_buf())
}

/// Default socket path.
const DEFAULT_SOCKET_PATH: &str = "/tmp/rch.sock";

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
    let style = ctx.style();

    // JSON output mode
    if ctx.is_json() {
        let response = WorkersListResponse {
            count: workers.len(),
            workers: workers.iter().map(WorkerInfo::from).collect(),
        };
        let _ = ctx.json(&JsonResponse::ok(response));
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
pub async fn workers_probe(worker_id: Option<String>, all: bool, ctx: &OutputContext) -> Result<()> {
    let workers = load_workers_from_config()?;
    let style = ctx.style();

    if workers.is_empty() {
        if ctx.is_json() {
            let _ = ctx.json(&JsonResponse::<Vec<WorkerProbeResult>>::ok(vec![]));
        }
        return Ok(());
    }

    let targets: Vec<&WorkerConfig> = if all {
        workers.iter().collect()
    } else if let Some(id) = &worker_id {
        workers.iter().filter(|w| w.id.as_str() == id).collect()
    } else {
        if ctx.is_json() {
            let _ = ctx.json(&JsonResponse::<()>::err("Specify a worker ID or use --all"));
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
                let _ = ctx.json(&JsonResponse::<()>::err(format!("Worker '{}' not found", id)));
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
        let _ = ctx.json(&JsonResponse::ok(results));
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
    let style = ctx.style();

    if workers.is_empty() {
        if ctx.is_json() {
            let _ = ctx.json(&JsonResponse::<Vec<WorkerBenchmarkResult>>::ok(vec![]));
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
                let benchmark_cmd = r#"
                    cd /tmp && \
                    mkdir -p rch_bench && \
                    cd rch_bench && \
                    echo 'fn main() { println!("hello"); }' > main.rs && \
                    time rustc main.rs -o hello 2>&1 | grep real || echo 'rustc not found'
                "#;

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
                                style.muted(&e.to_string())
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
        let _ = ctx.json(&JsonResponse::ok(results));
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
    let style = ctx.style();

    // Check if daemon is running
    if !Path::new(DEFAULT_SOCKET_PATH).exists() {
        if ctx.is_json() {
            let _ = ctx.json(&JsonResponse::<()>::err("Daemon is not running"));
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
                    let _ = ctx.json(&JsonResponse::ok(WorkerActionResponse {
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
            } else {
                if ctx.is_json() {
                    let _ = ctx.json(&JsonResponse::ok(WorkerActionResponse {
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
        }
        Err(e) => {
            if ctx.is_json() {
                let _ = ctx.json(&JsonResponse::<()>::err(e.to_string()));
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
    let style = ctx.style();

    if !Path::new(DEFAULT_SOCKET_PATH).exists() {
        if ctx.is_json() {
            let _ = ctx.json(&JsonResponse::<()>::err("Daemon is not running"));
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
                    let _ = ctx.json(&JsonResponse::ok(WorkerActionResponse {
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
            } else {
                if ctx.is_json() {
                    let _ = ctx.json(&JsonResponse::ok(WorkerActionResponse {
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
        }
        Err(e) => {
            if ctx.is_json() {
                let _ = ctx.json(&JsonResponse::<()>::err(e.to_string()));
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

// =============================================================================
// Daemon Commands
// =============================================================================

/// Check daemon status.
pub fn daemon_status(ctx: &OutputContext) -> Result<()> {
    let socket_path = Path::new(DEFAULT_SOCKET_PATH);
    let style = ctx.style();

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
        let _ = ctx.json(&JsonResponse::ok(DaemonStatusResponse {
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
    let style = ctx.style();
    let socket_path = Path::new(DEFAULT_SOCKET_PATH);

    if socket_path.exists() {
        if ctx.is_json() {
            let _ = ctx.json(&JsonResponse::ok(DaemonActionResponse {
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
                    let _ = ctx.json(&JsonResponse::ok(DaemonActionResponse {
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
            } else {
                if ctx.is_json() {
                    let _ = ctx.json(&JsonResponse::ok(DaemonActionResponse {
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
        }
        Err(e) => {
            if ctx.is_json() {
                let _ = ctx.json(&JsonResponse::<()>::err(e.to_string()));
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
    let style = ctx.style();
    let socket_path = Path::new(DEFAULT_SOCKET_PATH);

    if !socket_path.exists() {
        if ctx.is_json() {
            let _ = ctx.json(&JsonResponse::ok(DaemonActionResponse {
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
                        let _ = ctx.json(&JsonResponse::ok(DaemonActionResponse {
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
                let _ = ctx.json(&JsonResponse::ok(DaemonActionResponse {
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
            if !ctx.is_json() {
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
                        let _ = ctx.json(&JsonResponse::ok(DaemonActionResponse {
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
                        let _ = ctx.json(&JsonResponse::<()>::err("Could not stop daemon"));
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
    let style = ctx.style();
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
    let style = ctx.style();

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
                let _ = ctx.json(&JsonResponse::ok(DaemonLogsResponse {
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
        let _ = ctx.json(&JsonResponse::ok(DaemonLogsResponse {
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
        for path in &log_paths {
            println!(
                "  {} {}",
                style.muted("-"),
                style.muted(&path.display().to_string())
            );
        }
        println!(
            "\n{} The daemon may log to stderr. Try running in foreground: {}",
            StatusIndicator::Info.display(style),
            style.highlight("rchd")
        );
    }

    Ok(())
}

// =============================================================================
// Config Commands
// =============================================================================

/// Show effective configuration.
pub fn config_show() -> Result<()> {
    let style = terminal_style();

    // Load user config
    let config = crate::config::load_config()?;

    println!("{}", style.format_header("Effective RCH Configuration"));
    println!();

    println!("{}", style.highlight("[general]"));
    println!(
        "  {} = {}",
        style.key("enabled"),
        style.value(&config.general.enabled.to_string())
    );
    println!(
        "  {} = {}",
        style.key("log_level"),
        style.value(&format!("\"{}\"", config.general.log_level))
    );
    println!(
        "  {} = {}",
        style.key("socket_path"),
        style.value(&format!("\"{}\"", config.general.socket_path))
    );

    println!("\n{}", style.highlight("[compilation]"));
    println!(
        "  {} = {}",
        style.key("confidence_threshold"),
        style.value(&config.compilation.confidence_threshold.to_string())
    );
    println!(
        "  {} = {}",
        style.key("min_local_time_ms"),
        style.value(&config.compilation.min_local_time_ms.to_string())
    );

    println!("\n{}", style.highlight("[transfer]"));
    println!(
        "  {} = {}",
        style.key("compression_level"),
        style.value(&config.transfer.compression_level.to_string())
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

/// Initialize configuration files.
pub fn config_init() -> Result<()> {
    let style = terminal_style();
    let config_dir = config_dir().context("Could not determine config directory")?;

    // Create config directory
    std::fs::create_dir_all(&config_dir)
        .with_context(|| format!("Failed to create config directory: {:?}", config_dir))?;

    let config_path = config_dir.join("config.toml");
    let workers_path = config_dir.join("workers.toml");

    // Write example config.toml
    if !config_path.exists() {
        let config_content = r#"# RCH Configuration
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
"#;
        std::fs::write(&config_path, config_content)?;
        println!(
            "{} {} {}",
            StatusIndicator::Success.display(&style),
            style.muted("Created:"),
            style.value(&config_path.display().to_string())
        );
    } else {
        println!(
            "{} {} {}",
            style.muted("-"),
            style.muted("Exists:"),
            style.muted(&config_path.display().to_string())
        );
    }

    // Write example workers.toml
    if !workers_path.exists() {
        let workers_content = r#"# RCH Workers Configuration
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
"#;
        std::fs::write(&workers_path, workers_content)?;
        println!(
            "{} {} {}",
            StatusIndicator::Success.display(&style),
            style.muted("Created:"),
            style.value(&workers_path.display().to_string())
        );
    } else {
        println!(
            "{} {} {}",
            style.muted("-"),
            style.muted("Exists:"),
            style.muted(&workers_path.display().to_string())
        );
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
pub fn config_validate() -> Result<()> {
    let style = terminal_style();

    println!("Validating RCH configuration...\n");

    let mut errors = 0;
    let mut warnings = 0;

    // Check config directory
    let config_dir = match config_dir() {
        Some(d) => d,
        None => {
            println!(
                "{} Could not determine config directory",
                StatusIndicator::Error.display(&style)
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
                        StatusIndicator::Success.display(&style),
                        style.highlight("config.toml"),
                        style.success("Valid")
                    );

                    // Validate values
                    if config.compilation.confidence_threshold < 0.0
                        || config.compilation.confidence_threshold > 1.0
                    {
                        println!(
                            "  {} {} should be between 0.0 and 1.0",
                            StatusIndicator::Warning.display(&style),
                            style.key("confidence_threshold")
                        );
                        warnings += 1;
                    }
                    if config.transfer.compression_level > 19 {
                        println!(
                            "  {} {} should be 1-19",
                            StatusIndicator::Warning.display(&style),
                            style.key("compression_level")
                        );
                        warnings += 1;
                    }
                }
                Err(e) => {
                    println!(
                        "{} {}: {} - {}",
                        StatusIndicator::Error.display(&style),
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
                    StatusIndicator::Error.display(&style),
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
                        StatusIndicator::Success.display(&style),
                        style.highlight("workers.toml"),
                        style.success("Valid"),
                        workers
                    );

                    if workers == 0 {
                        println!(
                            "  {} No workers defined",
                            StatusIndicator::Warning.display(&style)
                        );
                        warnings += 1;
                    }
                }
                Err(e) => {
                    println!(
                        "{} {}: {} - {}",
                        StatusIndicator::Error.display(&style),
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
                    StatusIndicator::Error.display(&style),
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
            StatusIndicator::Error.display(&style),
            style.highlight("workers.toml"),
            style.error("Not found")
        );
        println!(
            "  {} Run {} to create it",
            StatusIndicator::Info.display(&style),
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
                    StatusIndicator::Success.display(&style),
                    style.highlight(".rch/config.toml"),
                    style.success("Valid")
                ),
                Err(e) => {
                    println!(
                        "{} {}: {} - {}",
                        StatusIndicator::Error.display(&style),
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
                    StatusIndicator::Error.display(&style),
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
pub fn config_set(key: &str, value: &str) -> Result<()> {
    let config_dir = config_dir().context("Could not determine config directory")?;
    std::fs::create_dir_all(&config_dir)
        .with_context(|| format!("Failed to create config directory: {:?}", config_dir))?;
    let config_path = config_dir.join("config.toml");
    config_set_at(&config_path, key, value)
}

fn config_set_at(config_path: &Path, key: &str, value: &str) -> Result<()> {
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
            config.general.log_level = value.trim().trim_matches('"').to_string();
        }
        "general.socket_path" => {
            config.general.socket_path = value.trim().trim_matches('"').to_string();
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
    std::fs::write(config_path, format!("{contents}\n"))
        .with_context(|| format!("Failed to write {:?}", config_path))?;

    println!("Updated {:?}: {} = {}", config_path, key, value);
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
pub fn hook_install() -> Result<()> {
    let style = terminal_style();

    // Claude Code hooks are configured in ~/.claude/settings.json
    let claude_config_dir = dirs::home_dir()
        .map(|h| h.join(".claude"))
        .context("Could not find home directory")?;

    let settings_path = claude_config_dir.join("settings.json");

    println!("Installing RCH hook for Claude Code...\n");

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

    // Add PreToolUse hook for Bash
    hooks_obj.insert(
        "PreToolUse".to_string(),
        serde_json::json!([{
            "matcher": "Bash",
            "hooks": [{
                "type": "command",
                "command": rch_path.to_string_lossy()
            }]
        }]),
    );

    // Write back
    let formatted = serde_json::to_string_pretty(&settings)?;
    std::fs::write(&settings_path, formatted)?;

    println!("{}", style.format_success("Hook installed!"));
    println!(
        "\n{} {} {:?}",
        style.key("Configuration written to"),
        style.muted(":"),
        settings_path
    );
    println!("\nThe hook will intercept Bash commands and route compilations");
    println!("to remote workers when the daemon is running.");
    println!("\n{}", style.highlight("Next steps:"));
    println!(
        "  {}. Configure workers: {} && edit workers.toml",
        style.muted("1"),
        style.info("rch config init")
    );
    println!(
        "  {}. Start daemon: {}",
        style.muted("2"),
        style.info("rch daemon start")
    );
    println!(
        "  {}. Use Claude Code normally - compilations will be offloaded",
        style.muted("3")
    );

    Ok(())
}

/// Uninstall the Claude Code hook.
pub fn hook_uninstall() -> Result<()> {
    let style = terminal_style();
    let settings_path = dirs::home_dir()
        .map(|h| h.join(".claude").join("settings.json"))
        .context("Could not find home directory")?;

    if !settings_path.exists() {
        println!(
            "{} No Claude Code settings found.",
            StatusIndicator::Info.display(&style)
        );
        return Ok(());
    }

    let content = std::fs::read_to_string(&settings_path)?;
    let mut settings: serde_json::Value = serde_json::from_str(&content)?;

    // Remove the PreToolUse hook
    if let Some(hooks) = settings.get_mut("hooks") {
        if let Some(hooks_obj) = hooks.as_object_mut() {
            hooks_obj.remove("PreToolUse");
            println!(
                "{}",
                StatusIndicator::Success.with_label(&style, "Hook removed!")
            );
        }
    }

    // Write back
    let formatted = serde_json::to_string_pretty(&settings)?;
    std::fs::write(&settings_path, formatted)?;

    println!(
        "\n{}",
        StatusIndicator::Success.with_label(&style, "RCH hook has been uninstalled.")
    );
    println!(
        "  {} Claude Code will now run all commands locally.",
        style.muted(style.symbols.arrow_right)
    );

    Ok(())
}

/// Test the hook with a sample command.
pub async fn hook_test() -> Result<()> {
    use rch_common::classify_command;

    let style = terminal_style();

    println!("Testing RCH hook functionality...\n");

    // Test 1: Classification
    println!(
        "{}. {}",
        style.highlight("1"),
        style.highlight("Command Classification")
    );
    println!("   {}", style.muted(&"─".repeat(22)));

    let test_commands = vec![
        ("cargo build --release", true),
        ("cargo test", true),
        ("cargo fmt", false),
        ("ls -la", false),
        ("gcc -o main main.c", true),
        ("make clean", false),
        ("make all", true),
    ];

    for (cmd, expect_intercept) in &test_commands {
        let class = classify_command(cmd);
        let status = if class.is_compilation == *expect_intercept {
            StatusIndicator::Success.display(&style)
        } else {
            StatusIndicator::Error.display(&style)
        };
        let action = if class.is_compilation {
            style.warning("INTERCEPT")
        } else {
            style.success("ALLOW")
        };
        println!(
            "   {} {} {} {} (confidence: {})",
            status,
            style.muted("\""),
            style.value(cmd),
            style.muted("\""),
            action
        );
        println!("      {}", style.muted(&format!("{:.2}", class.confidence)));
    }

    // Test 2: Daemon connectivity
    println!(
        "\n{}. {}",
        style.highlight("2"),
        style.highlight("Daemon Connectivity")
    );
    println!("   {}", style.muted(&"─".repeat(19)));

    if Path::new(DEFAULT_SOCKET_PATH).exists() {
        match send_daemon_command("GET /status\n").await {
            Ok(response) => {
                println!(
                    "   {} Daemon responding",
                    StatusIndicator::Success.display(&style)
                );
                if !response.is_empty() {
                    println!(
                        "   {} {}",
                        style.key("Response"),
                        style.muted(response.trim())
                    );
                }
            }
            Err(e) => {
                println!(
                    "   {} Daemon not responding: {}",
                    StatusIndicator::Error.display(&style),
                    style.muted(&e.to_string())
                );
            }
        }
    } else {
        println!(
            "   {} Daemon not running {}",
            style.muted("-"),
            style.muted("(socket not found)")
        );
        println!(
            "     {} Start with: {}",
            StatusIndicator::Info.display(&style),
            style.highlight("rch daemon start")
        );
    }

    // Test 3: Worker configuration
    println!(
        "\n{}. {}",
        style.highlight("3"),
        style.highlight("Worker Configuration")
    );
    println!("   {}", style.muted(&"─".repeat(20)));

    match load_workers_from_config() {
        Ok(workers) if !workers.is_empty() => {
            println!(
                "   {} {} worker(s) configured",
                StatusIndicator::Success.display(&style),
                style.highlight(&workers.len().to_string())
            );
            for w in &workers {
                println!(
                    "     {} {} {}@{}",
                    style.muted("-"),
                    style.highlight(w.id.as_str()),
                    style.muted(&w.user),
                    style.info(&w.host)
                );
            }
        }
        Ok(_) => {
            println!("   {} No workers configured", style.muted("-"));
            println!(
                "     {} Run: {}",
                StatusIndicator::Info.display(&style),
                style.highlight("rch config init")
            );
        }
        Err(e) => {
            println!(
                "   {} Error loading workers: {}",
                StatusIndicator::Error.display(&style),
                style.muted(&e.to_string())
            );
        }
    }

    println!("\n{}", style.format_success("Hook test complete!"));
    Ok(())
}

// =============================================================================
// Status Command
// =============================================================================

/// Show overall system status.
pub async fn status_overview(show_workers: bool, show_jobs: bool) -> Result<()> {
    let style = terminal_style();

    println!("{}", style.format_header("RCH Status"));
    println!();

    // Daemon status
    let daemon_running = Path::new(DEFAULT_SOCKET_PATH).exists();
    println!(
        "  {} {} {}",
        style.key("Daemon"),
        style.muted(":"),
        if daemon_running {
            style.success("Running")
        } else {
            style.error("Stopped")
        }
    );

    // Worker count
    match load_workers_from_config() {
        Ok(workers) => {
            println!(
                "  {} {} {} configured",
                style.key("Workers"),
                style.muted(":"),
                style.highlight(&workers.len().to_string())
            );
        }
        Err(_) => {
            println!(
                "  {} {} {}",
                style.key("Workers"),
                style.muted(":"),
                style.warning("Not configured")
            );
        }
    }

    // Hook status
    let hook_installed = dirs::home_dir()
        .map(|h| h.join(".claude").join("settings.json"))
        .map(|p| {
            if p.exists() {
                std::fs::read_to_string(&p)
                    .ok()
                    .map(|c| c.contains("PreToolUse"))
                    .unwrap_or(false)
            } else {
                false
            }
        })
        .unwrap_or(false);

    println!(
        "  {} {} {}",
        style.key("Hook"),
        style.muted(":"),
        if hook_installed {
            style.success("Installed")
        } else {
            style.warning("Not installed")
        }
    );

    if show_workers {
        println!("\n{}", style.format_header("Workers"));
        let workers = load_workers_from_config().unwrap_or_default();
        if workers.is_empty() {
            println!("  {}", style.muted("(none configured)"));
        } else {
            for worker in &workers {
                // Try to get status from daemon if running
                let status = if daemon_running {
                    style.muted("unknown")
                } else {
                    style.warning("daemon-offline")
                };
                println!(
                    "  {} {} {}@{} [{}]",
                    style.symbols.bullet_filled,
                    style.highlight(worker.id.as_str()),
                    style.muted(&worker.user),
                    style.info(&worker.host),
                    status
                );
            }
        }
    }

    if show_jobs {
        println!("\n{}", style.format_header("Active Jobs"));
        if daemon_running {
            match send_daemon_command("GET /jobs\n").await {
                Ok(response) if !response.trim().is_empty() => {
                    println!("{}", response);
                }
                _ => {
                    println!("  {}", style.muted("(no active jobs)"));
                }
            }
        } else {
            println!("  {}", style.muted("(daemon not running)"));
        }
    }

    Ok(())
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Find the rchd binary.
fn which_rchd() -> PathBuf {
    // Check same directory as rch
    if let Ok(exe) = std::env::current_exe() {
        let rchd = exe.parent().map(|p| p.join("rchd")).unwrap_or_default();
        if rchd.exists() {
            return rchd;
        }
    }

    // Check PATH
    if let Ok(output) = std::process::Command::new("which").arg("rchd").output() {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout);
            return PathBuf::from(path.trim());
        }
    }

    // Fallback
    PathBuf::from("rchd")
}

/// Send a command to the daemon via Unix socket.
async fn send_daemon_command(command: &str) -> Result<String> {
    let stream = UnixStream::connect(DEFAULT_SOCKET_PATH)
        .await
        .context("Failed to connect to daemon socket")?;

    let (reader, mut writer) = stream.into_split();

    writer.write_all(command.as_bytes()).await?;
    writer.flush().await?;

    let mut reader = BufReader::new(reader);
    let mut response = String::new();

    // Read response with timeout
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line).await {
                Ok(0) => break, // EOF
                Ok(_) => response.push_str(&line),
                Err(_) => break,
            }
        }
    })
    .await
    .ok();

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_parse_workers_toml_single_worker() {
        let toml_content = r#"
[[workers]]
id = "test-worker"
host = "192.168.1.100"
user = "testuser"
identity_file = "~/.ssh/test_key"
total_slots = 8
priority = 100
tags = ["rust", "test"]
enabled = true
"#;

        let parsed: toml::Value = toml::from_str(toml_content).expect("Failed to parse TOML");
        let workers_array = parsed
            .get("workers")
            .and_then(|w| w.as_array())
            .expect("Expected workers array");

        assert_eq!(workers_array.len(), 1);

        let entry = &workers_array[0];
        assert_eq!(entry.get("id").unwrap().as_str().unwrap(), "test-worker");
        assert_eq!(
            entry.get("host").unwrap().as_str().unwrap(),
            "192.168.1.100"
        );
        assert_eq!(entry.get("total_slots").unwrap().as_integer().unwrap(), 8);
    }

    #[test]
    fn test_parse_workers_toml_multiple_workers() {
        let toml_content = r#"
[[workers]]
id = "worker1"
host = "192.168.1.100"
total_slots = 16

[[workers]]
id = "worker2"
host = "192.168.1.101"
total_slots = 8
enabled = false

[[workers]]
id = "worker3"
host = "192.168.1.102"
total_slots = 32
"#;

        let parsed: toml::Value = toml::from_str(toml_content).expect("Failed to parse TOML");
        let workers_array = parsed
            .get("workers")
            .and_then(|w| w.as_array())
            .expect("Expected workers array");

        assert_eq!(workers_array.len(), 3);

        // Check that worker2 is disabled
        let worker2 = &workers_array[1];
        assert!(!worker2.get("enabled").unwrap().as_bool().unwrap());
    }

    #[test]
    fn test_parse_workers_toml_defaults() {
        let toml_content = r#"
[[workers]]
id = "minimal"
host = "example.com"
"#;

        let parsed: toml::Value = toml::from_str(toml_content).expect("Failed to parse TOML");
        let workers_array = parsed
            .get("workers")
            .and_then(|w| w.as_array())
            .expect("Expected workers array");

        let entry = &workers_array[0];

        // These should be None (using defaults)
        assert!(entry.get("user").is_none());
        assert!(entry.get("identity_file").is_none());
        assert!(entry.get("total_slots").is_none());
        assert!(entry.get("priority").is_none());
        assert!(entry.get("enabled").is_none());
    }

    #[test]
    fn test_parse_workers_toml_empty() {
        let toml_content = "# Empty workers file";

        let parsed: toml::Value = toml::from_str(toml_content).expect("Failed to parse TOML");
        let workers_array = parsed.get("workers").and_then(|w| w.as_array());

        assert!(workers_array.is_none());
    }

    #[test]
    fn test_config_set_writes_new_file() {
        let temp_dir = TempDir::new().expect("temp dir");
        let config_path = temp_dir.path().join("config.toml");

        config_set_at(&config_path, "general.enabled", "false").expect("config set failed");

        let contents = std::fs::read_to_string(&config_path).expect("read config");
        let parsed: RchConfig = toml::from_str(&contents).expect("parse config");
        assert!(!parsed.general.enabled);
    }

    #[test]
    fn test_config_set_updates_existing_file() {
        let temp_dir = TempDir::new().expect("temp dir");
        let config_path = temp_dir.path().join("config.toml");

        let initial = RchConfig::default();
        let initial_contents = toml::to_string_pretty(&initial).expect("serialize");
        std::fs::write(&config_path, initial_contents).expect("write initial");

        config_set_at(&config_path, "compilation.confidence_threshold", "0.9")
            .expect("config set failed");

        let contents = std::fs::read_to_string(&config_path).expect("read config");
        let parsed: RchConfig = toml::from_str(&contents).expect("parse config");
        assert!(
            (parsed.compilation.confidence_threshold - 0.9).abs() < f64::EPSILON,
            "confidence_threshold not updated"
        );
        assert_eq!(parsed.general.enabled, initial.general.enabled);
    }

    #[test]
    fn test_config_set_exclude_patterns_array() {
        let temp_dir = TempDir::new().expect("temp dir");
        let config_path = temp_dir.path().join("config.toml");

        config_set_at(
            &config_path,
            "transfer.exclude_patterns",
            "[\"target/\", \"node_modules/\"]",
        )
        .expect("config set failed");

        let contents = std::fs::read_to_string(&config_path).expect("read config");
        let parsed: RchConfig = toml::from_str(&contents).expect("parse config");
        assert_eq!(parsed.transfer.exclude_patterns, vec![
            "target/".to_string(),
            "node_modules/".to_string()
        ]);
    }

    #[test]
    fn test_default_socket_path() {
        assert_eq!(DEFAULT_SOCKET_PATH, "/tmp/rch.sock");
    }

    #[test]
    fn test_which_rchd_fallback() {
        // When rchd is not found, it should fall back to just "rchd"
        let path = which_rchd();
        // The path should either be a valid path or just "rchd"
        assert!(
            path.exists() || path == PathBuf::from("rchd"),
            "Expected either a valid path or 'rchd' fallback"
        );
    }

    #[tokio::test]
    async fn test_daemon_socket_not_found() {
        // Test that commands handle missing daemon gracefully
        let result = send_daemon_command("GET /status\n").await;

        // Should fail because socket doesn't exist
        assert!(result.is_err());
    }

    #[test]
    fn test_config_dir_returns_some() {
        // config_dir should return Some on most systems
        let dir = config_dir();
        // Can be None in some CI environments, but usually Some
        if let Some(d) = dir {
            assert!(d.ends_with("rch") || d.to_string_lossy().contains("rch"));
        }
    }

    #[test]
    fn test_worker_config_conversion() {
        // Test that TOML values convert correctly to WorkerConfig fields
        let toml_content = r#"
[[workers]]
id = "conversion-test"
host = "10.0.0.1"
user = "admin"
identity_file = "/path/to/key"
total_slots = 24
priority = 150
tags = ["gpu", "fast"]
enabled = true
"#;

        let parsed: toml::Value = toml::from_str(toml_content).expect("Failed to parse TOML");
        let entry = &parsed.get("workers").unwrap().as_array().unwrap()[0];

        // Simulate the conversion logic from load_workers_from_config
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

        assert_eq!(id, "conversion-test");
        assert_eq!(host, "10.0.0.1");
        assert_eq!(user, "admin");
        assert_eq!(identity_file, "/path/to/key");
        assert_eq!(total_slots, 24);
        assert_eq!(priority, 150);
    }

    #[test]
    fn test_hook_classification_in_test_command() {
        use rch_common::classify_command;

        // These should be classified as compilation commands
        let compilation_commands = vec![
            "cargo build --release",
            "cargo test",
            "cargo check",
            "rustc main.rs",
            "gcc -o main main.c",
            "make all",
        ];

        for cmd in compilation_commands {
            let class = classify_command(cmd);
            assert!(
                class.is_compilation,
                "Expected '{}' to be classified as compilation",
                cmd
            );
        }

        // These should NOT be classified as compilation commands
        let non_compilation_commands = vec![
            "cargo fmt",
            "cargo clean",
            "cargo --version",
            "ls -la",
            "cd /tmp",
            "echo hello",
        ];

        for cmd in non_compilation_commands {
            let class = classify_command(cmd);
            assert!(
                !class.is_compilation,
                "Expected '{}' to NOT be classified as compilation",
                cmd
            );
        }
    }
}
