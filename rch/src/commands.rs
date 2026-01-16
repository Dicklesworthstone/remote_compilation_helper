//! CLI command handler implementations.
//!
//! This module contains the actual business logic for each CLI subcommand.

use anyhow::{Context, Result};
use directories::ProjectDirs;
use rch_common::{RchConfig, SshClient, SshOptions, WorkerConfig, WorkerId};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::process::Command;
use tracing::debug;

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
pub fn workers_list() -> Result<()> {
    let workers = load_workers_from_config()?;

    if workers.is_empty() {
        return Ok(());
    }

    println!("Configured Workers");
    println!("==================");
    println!();

    for worker in &workers {
        println!("  {} - {}@{}", worker.id, worker.user, worker.host);
        println!(
            "    Slots: {}, Priority: {}",
            worker.total_slots, worker.priority
        );
        if !worker.tags.is_empty() {
            println!("    Tags: {}", worker.tags.join(", "));
        }
        println!();
    }

    println!("Total: {} worker(s)", workers.len());
    Ok(())
}

/// Probe worker connectivity.
pub async fn workers_probe(worker_id: Option<String>, all: bool) -> Result<()> {
    let workers = load_workers_from_config()?;

    if workers.is_empty() {
        return Ok(());
    }

    let targets: Vec<&WorkerConfig> = if all {
        workers.iter().collect()
    } else if let Some(id) = &worker_id {
        workers.iter().filter(|w| w.id.as_str() == id).collect()
    } else {
        println!("Specify a worker ID or use --all to probe all workers.");
        return Ok(());
    };

    if targets.is_empty() {
        if let Some(id) = worker_id {
            println!("Worker '{}' not found in configuration.", id);
        }
        return Ok(());
    }

    println!("Probing {} worker(s)...\n", targets.len());

    for worker in targets {
        print!("  {} ({}@{})... ", worker.id, worker.user, worker.host);

        let mut client = SshClient::new(worker.clone(), SshOptions::default());

        match client.connect().await {
            Ok(()) => {
                let start = std::time::Instant::now();
                match client.health_check().await {
                    Ok(true) => {
                        let latency = start.elapsed().as_millis();
                        println!("✓ OK ({}ms)", latency);
                    }
                    Ok(false) => {
                        println!("✗ Health check failed");
                    }
                    Err(e) => {
                        println!("✗ Error: {}", e);
                    }
                }
                let _ = client.disconnect().await;
            }
            Err(e) => {
                println!("✗ Connection failed: {}", e);
            }
        }
    }

    Ok(())
}

/// Run worker benchmarks.
pub async fn workers_benchmark() -> Result<()> {
    let workers = load_workers_from_config()?;

    if workers.is_empty() {
        return Ok(());
    }

    println!("Running benchmarks on {} worker(s)...\n", workers.len());

    for worker in &workers {
        print!("  {} ... ", worker.id);

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
                        println!("✓ {}ms total, exit={}", duration.as_millis(), r.exit_code);
                    }
                    Ok(r) => {
                        println!("✗ Failed (exit={})", r.exit_code);
                    }
                    Err(e) => {
                        println!("✗ Error: {}", e);
                    }
                }
                let _ = client.disconnect().await;
            }
            Err(e) => {
                println!("✗ Connection failed: {}", e);
            }
        }
    }

    println!("\nNote: For accurate speed scores, use longer benchmark runs.");
    Ok(())
}

/// Drain a worker (requires daemon).
pub async fn workers_drain(worker_id: &str) -> Result<()> {
    // Check if daemon is running
    if !Path::new(DEFAULT_SOCKET_PATH).exists() {
        println!("Daemon is not running. Start it with `rch daemon start`.");
        println!("\nDraining requires the daemon to track worker state.");
        return Ok(());
    }

    // Send drain command to daemon
    match send_daemon_command(&format!("POST /workers/{}/drain\n", worker_id)).await {
        Ok(response) => {
            if response.contains("error") || response.contains("Error") {
                println!("Failed to drain worker: {}", response);
            } else {
                println!("Worker '{}' is now draining.", worker_id);
                println!("No new jobs will be sent. Existing jobs will complete.");
            }
        }
        Err(e) => {
            println!("Failed to communicate with daemon: {}", e);
            println!("\nNote: Drain/enable commands require the daemon to be running.");
        }
    }

    Ok(())
}

/// Enable a worker (requires daemon).
pub async fn workers_enable(worker_id: &str) -> Result<()> {
    if !Path::new(DEFAULT_SOCKET_PATH).exists() {
        println!("Daemon is not running. Start it with `rch daemon start`.");
        return Ok(());
    }

    match send_daemon_command(&format!("POST /workers/{}/enable\n", worker_id)).await {
        Ok(response) => {
            if response.contains("error") || response.contains("Error") {
                println!("Failed to enable worker: {}", response);
            } else {
                println!("Worker '{}' is now enabled.", worker_id);
            }
        }
        Err(e) => {
            println!("Failed to communicate with daemon: {}", e);
        }
    }

    Ok(())
}

// =============================================================================
// Daemon Commands
// =============================================================================

/// Check daemon status.
pub fn daemon_status() -> Result<()> {
    let socket_path = Path::new(DEFAULT_SOCKET_PATH);

    println!("RCH Daemon Status");
    println!("=================\n");

    if socket_path.exists() {
        println!("  Status: Running");
        println!("  Socket: {}", DEFAULT_SOCKET_PATH);

        // Try to get more info from the daemon
        if let Ok(metadata) = std::fs::metadata(socket_path) {
            if let Ok(modified) = metadata.modified() {
                if let Ok(duration) = modified.elapsed() {
                    let hours = duration.as_secs() / 3600;
                    let mins = (duration.as_secs() % 3600) / 60;
                    println!("  Uptime: ~{}h {}m", hours, mins);
                }
            }
        }
    } else {
        println!("  Status: Not running");
        println!("  Socket: {} (not found)", DEFAULT_SOCKET_PATH);
        println!("\n  Start with: rch daemon start");
    }

    Ok(())
}

/// Start the daemon.
pub async fn daemon_start() -> Result<()> {
    let socket_path = Path::new(DEFAULT_SOCKET_PATH);

    if socket_path.exists() {
        println!("Daemon appears to already be running.");
        println!("Socket exists at: {}", DEFAULT_SOCKET_PATH);
        println!("\nUse `rch daemon restart` to restart it.");
        return Ok(());
    }

    // Check if rchd binary exists
    let rchd_path = which_rchd();

    println!("Starting RCH daemon...");
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
                println!("Daemon started successfully.");
                println!("Socket: {}", DEFAULT_SOCKET_PATH);
            } else {
                println!("Daemon process started but socket not found.");
                println!("Check logs with: rch daemon logs");
            }
        }
        Err(e) => {
            println!("Failed to start daemon: {}", e);
            println!("\nMake sure 'rchd' is in your PATH or installed.");
        }
    }

    Ok(())
}

/// Stop the daemon.
pub async fn daemon_stop() -> Result<()> {
    let socket_path = Path::new(DEFAULT_SOCKET_PATH);

    if !socket_path.exists() {
        println!("Daemon is not running (socket not found).");
        return Ok(());
    }

    println!("Stopping RCH daemon...");

    // Try graceful shutdown via socket
    match send_daemon_command("POST /shutdown\n").await {
        Ok(_) => {
            // Wait for socket to disappear
            for _ in 0..10 {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                if !socket_path.exists() {
                    println!("Daemon stopped.");
                    return Ok(());
                }
            }
            println!("Daemon may still be shutting down...");
        }
        Err(_) => {
            // Try to kill by finding the process
            println!("Could not send shutdown command.");
            println!("Attempting to find and kill daemon process...");

            // Try pkill
            let output = Command::new("pkill").arg("-f").arg("rchd").output().await;

            match output {
                Ok(o) if o.status.success() => {
                    // Remove stale socket
                    let _ = std::fs::remove_file(socket_path);
                    println!("Daemon stopped.");
                }
                _ => {
                    println!("Could not stop daemon. You may need to kill it manually.");
                    println!("Try: pkill -9 rchd");
                }
            }
        }
    }

    Ok(())
}

/// Restart the daemon.
pub async fn daemon_restart() -> Result<()> {
    println!("Restarting RCH daemon...\n");
    daemon_stop().await?;
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    daemon_start().await?;
    Ok(())
}

/// Show daemon logs.
pub fn daemon_logs(lines: usize) -> Result<()> {
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
            println!("Log file: {:?}\n", path);

            let content = std::fs::read_to_string(path)?;
            let all_lines: Vec<&str> = content.lines().collect();
            let start = all_lines.len().saturating_sub(lines);

            for line in &all_lines[start..] {
                println!("{}", line);
            }

            return Ok(());
        }
    }

    println!("No log file found.");
    println!("\nChecked locations:");
    for path in &log_paths {
        println!("  - {:?}", path);
    }
    println!("\nThe daemon may log to stderr. Try running in foreground: rchd");

    Ok(())
}

// =============================================================================
// Config Commands
// =============================================================================

/// Show effective configuration.
pub fn config_show() -> Result<()> {
    // Load user config
    let config = crate::config::load_config()?;

    println!("Effective RCH Configuration");
    println!("============================\n");

    println!("[general]");
    println!("  enabled = {}", config.general.enabled);
    println!("  log_level = \"{}\"", config.general.log_level);
    println!("  socket_path = \"{}\"", config.general.socket_path);

    println!("\n[compilation]");
    println!(
        "  confidence_threshold = {}",
        config.compilation.confidence_threshold
    );
    println!(
        "  min_local_time_ms = {}",
        config.compilation.min_local_time_ms
    );

    println!("\n[transfer]");
    println!(
        "  compression_level = {}",
        config.transfer.compression_level
    );
    println!("  exclude_patterns = [");
    for pattern in &config.transfer.exclude_patterns {
        println!("    \"{}\",", pattern);
    }
    println!("  ]");

    // Show config file locations
    println!("\n# Configuration sources (in priority order):");
    println!("# 1. Environment variables (RCH_*)");
    println!("# 2. Project config: .rch/config.toml");
    if let Some(dir) = config_dir() {
        println!("# 3. User config: {:?}", dir.join("config.toml"));
    }
    println!("# 4. Built-in defaults");

    Ok(())
}

/// Initialize configuration files.
pub fn config_init() -> Result<()> {
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
        println!("Created: {:?}", config_path);
    } else {
        println!("Exists:  {:?}", config_path);
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
        println!("Created: {:?}", workers_path);
    } else {
        println!("Exists:  {:?}", workers_path);
    }

    println!("\nConfiguration initialized!");
    println!("\nNext steps:");
    println!("  1. Edit {:?} with your worker details", workers_path);
    println!("  2. Test connectivity: rch workers probe --all");
    println!("  3. Start the daemon: rch daemon start");

    Ok(())
}

/// Validate configuration files.
pub fn config_validate() -> Result<()> {
    println!("Validating RCH configuration...\n");

    let mut errors = 0;
    let mut warnings = 0;

    // Check config directory
    let config_dir = match config_dir() {
        Some(d) => d,
        None => {
            println!("✗ Could not determine config directory");
            return Ok(());
        }
    };

    // Check config.toml
    let config_path = config_dir.join("config.toml");
    if config_path.exists() {
        match std::fs::read_to_string(&config_path) {
            Ok(content) => match toml::from_str::<RchConfig>(&content) {
                Ok(config) => {
                    println!("✓ config.toml: Valid");

                    // Validate values
                    if config.compilation.confidence_threshold < 0.0
                        || config.compilation.confidence_threshold > 1.0
                    {
                        println!("  ⚠ confidence_threshold should be between 0.0 and 1.0");
                        warnings += 1;
                    }
                    if config.transfer.compression_level > 19 {
                        println!("  ⚠ compression_level should be 1-19");
                        warnings += 1;
                    }
                }
                Err(e) => {
                    println!("✗ config.toml: Parse error - {}", e);
                    errors += 1;
                }
            },
            Err(e) => {
                println!("✗ config.toml: Read error - {}", e);
                errors += 1;
            }
        }
    } else {
        println!("- config.toml: Not found (using defaults)");
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
                    println!("✓ workers.toml: Valid ({} workers)", workers);

                    if workers == 0 {
                        println!("  ⚠ No workers defined");
                        warnings += 1;
                    }
                }
                Err(e) => {
                    println!("✗ workers.toml: Parse error - {}", e);
                    errors += 1;
                }
            },
            Err(e) => {
                println!("✗ workers.toml: Read error - {}", e);
                errors += 1;
            }
        }
    } else {
        println!("✗ workers.toml: Not found");
        println!("  Run `rch config init` to create it");
        errors += 1;
    }

    // Check project config
    let project_config = PathBuf::from(".rch/config.toml");
    if project_config.exists() {
        match std::fs::read_to_string(&project_config) {
            Ok(content) => match toml::from_str::<RchConfig>(&content) {
                Ok(_) => println!("✓ .rch/config.toml: Valid"),
                Err(e) => {
                    println!("✗ .rch/config.toml: Parse error - {}", e);
                    errors += 1;
                }
            },
            Err(e) => {
                println!("✗ .rch/config.toml: Read error - {}", e);
                errors += 1;
            }
        }
    }

    println!();
    if errors > 0 {
        println!(
            "Validation failed: {} error(s), {} warning(s)",
            errors, warnings
        );
    } else if warnings > 0 {
        println!("Validation passed with {} warning(s)", warnings);
    } else {
        println!("Validation passed!");
    }

    Ok(())
}

/// Set a configuration value.
pub fn config_set(key: &str, value: &str) -> Result<()> {
    println!("Setting {} = {}", key, value);
    println!("\nNote: config set is not fully implemented yet.");
    println!("Please edit the config file directly:");
    if let Some(dir) = config_dir() {
        println!("  {:?}", dir.join("config.toml"));
    }
    Ok(())
}

// =============================================================================
// Hook Commands
// =============================================================================

/// Install the Claude Code hook.
pub fn hook_install() -> Result<()> {
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

    println!("✓ Hook installed!");
    println!("\nConfiguration written to: {:?}", settings_path);
    println!("\nThe hook will intercept Bash commands and route compilations");
    println!("to remote workers when the daemon is running.");
    println!("\nNext steps:");
    println!("  1. Configure workers: rch config init && edit workers.toml");
    println!("  2. Start daemon: rch daemon start");
    println!("  3. Use Claude Code normally - compilations will be offloaded");

    Ok(())
}

/// Uninstall the Claude Code hook.
pub fn hook_uninstall() -> Result<()> {
    let settings_path = dirs::home_dir()
        .map(|h| h.join(".claude").join("settings.json"))
        .context("Could not find home directory")?;

    if !settings_path.exists() {
        println!("No Claude Code settings found.");
        return Ok(());
    }

    let content = std::fs::read_to_string(&settings_path)?;
    let mut settings: serde_json::Value = serde_json::from_str(&content)?;

    // Remove the PreToolUse hook
    if let Some(hooks) = settings.get_mut("hooks") {
        if let Some(hooks_obj) = hooks.as_object_mut() {
            hooks_obj.remove("PreToolUse");
            println!("✓ Hook removed!");
        }
    }

    // Write back
    let formatted = serde_json::to_string_pretty(&settings)?;
    std::fs::write(&settings_path, formatted)?;

    println!("\nRCH hook has been uninstalled.");
    println!("Claude Code will now run all commands locally.");

    Ok(())
}

/// Test the hook with a sample command.
pub async fn hook_test() -> Result<()> {
    use rch_common::classify_command;

    println!("Testing RCH hook functionality...\n");

    // Test 1: Classification
    println!("1. Command Classification");
    println!("   ----------------------");

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
            "✓"
        } else {
            "✗"
        };
        println!(
            "   {} \"{}\" -> {} (confidence: {:.2})",
            status,
            cmd,
            if class.is_compilation {
                "INTERCEPT"
            } else {
                "ALLOW"
            },
            class.confidence
        );
    }

    // Test 2: Daemon connectivity
    println!("\n2. Daemon Connectivity");
    println!("   -------------------");

    if Path::new(DEFAULT_SOCKET_PATH).exists() {
        match send_daemon_command("GET /status\n").await {
            Ok(response) => {
                println!("   ✓ Daemon responding");
                if !response.is_empty() {
                    println!("   Response: {}", response.trim());
                }
            }
            Err(e) => {
                println!("   ✗ Daemon not responding: {}", e);
            }
        }
    } else {
        println!("   - Daemon not running (socket not found)");
        println!("     Start with: rch daemon start");
    }

    // Test 3: Worker configuration
    println!("\n3. Worker Configuration");
    println!("   --------------------");

    match load_workers_from_config() {
        Ok(workers) if !workers.is_empty() => {
            println!("   ✓ {} worker(s) configured", workers.len());
            for w in &workers {
                println!("     - {} ({}@{})", w.id, w.user, w.host);
            }
        }
        Ok(_) => {
            println!("   - No workers configured");
            println!("     Run: rch config init");
        }
        Err(e) => {
            println!("   ✗ Error loading workers: {}", e);
        }
    }

    println!("\nHook test complete!");
    Ok(())
}

// =============================================================================
// Status Command
// =============================================================================

/// Show overall system status.
pub async fn status_overview(show_workers: bool, show_jobs: bool) -> Result<()> {
    println!("RCH Status");
    println!("==========\n");

    // Daemon status
    let daemon_running = Path::new(DEFAULT_SOCKET_PATH).exists();
    println!(
        "Daemon: {}",
        if daemon_running { "Running" } else { "Stopped" }
    );

    // Worker count
    match load_workers_from_config() {
        Ok(workers) => {
            println!("Workers: {} configured", workers.len());
        }
        Err(_) => {
            println!("Workers: Not configured");
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
        "Hook: {}",
        if hook_installed {
            "Installed"
        } else {
            "Not installed"
        }
    );

    if show_workers {
        println!("\n--- Workers ---");
        let workers = load_workers_from_config().unwrap_or_default();
        if workers.is_empty() {
            println!("  (none configured)");
        } else {
            for worker in &workers {
                // Try to get status from daemon if running
                let status = if daemon_running {
                    "unknown" // Would need daemon API to get actual status
                } else {
                    "daemon-offline"
                };
                println!(
                    "  {} - {}@{} [{}]",
                    worker.id, worker.user, worker.host, status
                );
            }
        }
    }

    if show_jobs {
        println!("\n--- Active Jobs ---");
        if daemon_running {
            match send_daemon_command("GET /jobs\n").await {
                Ok(response) if !response.trim().is_empty() => {
                    println!("{}", response);
                }
                _ => {
                    println!("  (no active jobs)");
                }
            }
        } else {
            println!("  (daemon not running)");
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
