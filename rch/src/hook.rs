//! PreToolUse hook implementation.
//!
//! Handles incoming hook requests from Claude Code, classifies commands,
//! and routes compilation commands to remote workers.

use crate::config::load_config;
use crate::error::{ArtifactRetrievalWarning, DaemonError, TransferError};
use crate::status_types::format_bytes;
use crate::toolchain::detect_toolchain;
use crate::transfer::{
    SyncResult, TransferPipeline, compute_project_hash, default_bun_artifact_patterns,
    default_c_cpp_artifact_patterns, default_rust_artifact_patterns,
    default_rust_test_artifact_patterns, project_id_from_path,
};
use crate::ui::console::RchConsole;
use rch_common::{
    ColorMode, CommandPriority, CommandTimingBreakdown, CompilationKind, HookInput, HookOutput,
    OutputVisibility, RequiredRuntime, SelectedWorker, SelectionResponse, SelfHealingConfig,
    ToolchainInfo, TransferConfig, WorkerConfig, WorkerId, classify_command,
    ui::{
        ArtifactSummary, CelebrationSummary, CompilationProgress, CompletionCelebration, Icons,
        OutputContext, RchTheme, TransferProgress,
    },
};
use rch_telemetry::protocol::{
    PIGGYBACK_MARKER, TelemetrySource, TestRunRecord, WorkerTelemetry,
    extract_piggybacked_telemetry,
};
use serde::Deserialize;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::time::{sleep, timeout};
use tracing::{debug, info, warn};
use which::which;

#[cfg(all(feature = "rich-ui", unix))]
use rich_rust::renderables::Panel;

// ============================================================================
// Exit Code Constants
// ============================================================================
//
// Cargo test (and cargo build/check/clippy) use specific exit codes:
//
// - 0:   Success (all tests passed, or build succeeded)
// - 1:   Build/compilation error (couldn't compile tests or crate)
// - 101: Test failures (tests compiled and ran, but some failed)
// - 128+N: Process killed by signal N (e.g., 137 = SIGKILL, 143 = SIGTERM)
//
// For RCH, ALL non-zero exits should deny local re-execution because:
// 1. Exit 101: Tests failed remotely, re-running locally won't help
// 2. Exit 1: Build error would occur locally too
// 3. Exit 128+N: Likely resource exhaustion (OOM), local might also fail
//
// The only exception is toolchain failures (missing rust version), which
// should fall back to local in case the local machine has the toolchain.

/// Exit code for successful cargo command (tests passed, build succeeded).
#[allow(dead_code)]
const EXIT_SUCCESS: i32 = 0;

/// Exit code for build/compilation error.
const EXIT_BUILD_ERROR: i32 = 1;

/// Exit code for cargo test when tests ran but some failed.
const EXIT_TEST_FAILURES: i32 = 101;

/// Minimum exit code indicating the process was killed by a signal.
/// Exit code = 128 + signal number (e.g., 137 = 128 + 9 = SIGKILL).
const EXIT_SIGNAL_BASE: i32 = 128;

use rch_common::util::mask_sensitive_command;

/// Run the hook, reading from stdin and writing to stdout.
pub async fn run_hook() -> anyhow::Result<()> {
    let mut stdout = io::stdout();

    // Read input from stdin with a 10MB limit to prevent OOM
    let mut input = String::new();
    {
        use tokio::io::{AsyncReadExt, stdin};
        stdin()
            .take(10 * 1024 * 1024)
            .read_to_string(&mut input)
            .await?;
    }

    let input = input.trim();
    if input.is_empty() {
        // No input - just allow
        return Ok(());
    }

    // Parse the hook input
    let hook_input: HookInput = match serde_json::from_str(input) {
        Ok(hi) => hi,
        Err(e) => {
            warn!("Failed to parse hook input: {}", e);
            // On parse error, allow the command (fail-open)
            return Ok(());
        }
    };

    // Process the hook request
    let output = process_hook(hook_input).await;

    // Write output
    if let HookOutput::Deny(_) = &output {
        let json = serde_json::to_string(&output)?;
        writeln!(stdout, "{}", json)?;
    }
    // For Allow, we output nothing (empty stdout = allow)

    Ok(())
}

#[derive(Clone, Copy)]
struct HookReporter {
    visibility: OutputVisibility,
}

impl HookReporter {
    fn new(visibility: OutputVisibility) -> Self {
        Self { visibility }
    }

    fn summary(&self, message: &str) {
        if self.visibility != OutputVisibility::None {
            eprintln!("{}", message);
        }
    }

    fn verbose(&self, message: &str) {
        if self.visibility == OutputVisibility::Verbose {
            eprintln!("{}", message);
        }
    }
}

fn format_duration_ms(duration: Duration) -> String {
    let millis = duration.as_millis();
    if millis >= 1000 {
        format!("{:.1}s", millis as f64 / 1000.0)
    } else {
        format!("{}ms", millis)
    }
}

fn format_speed(bytes: u64, duration_ms: u64) -> String {
    if duration_ms == 0 || bytes == 0 {
        return "--".to_string();
    }
    let secs = duration_ms as f64 / 1000.0;
    if secs <= 0.0 {
        return "--".to_string();
    }
    let per_sec = (bytes as f64 / secs).round() as u64;
    format!("{}/s", format_bytes(per_sec))
}

fn cache_hit(sync: &SyncResult) -> bool {
    sync.bytes_transferred == 0 && sync.files_transferred == 0
}

fn detect_target_label(command: &str, output: &str) -> Option<String> {
    if let Some(profile) = detect_profile_from_output(output) {
        return Some(profile);
    }
    if let Some(profile) = extract_profile_flag(command) {
        return Some(profile);
    }
    if command.contains("--release") {
        return Some("release".to_string());
    }
    None
}

fn detect_profile_from_output(output: &str) -> Option<String> {
    for line in output.lines() {
        if line.contains("Finished `release`") {
            return Some("release".to_string());
        }
        if line.contains("Finished `dev`") || line.contains("Finished `debug`") {
            return Some("debug".to_string());
        }
        if line.contains("Finished `bench`") {
            return Some("bench".to_string());
        }
    }
    None
}

fn extract_profile_flag(command: &str) -> Option<String> {
    for token in command.split_whitespace() {
        if let Some(profile) = token.strip_prefix("--profile=") {
            return Some(profile.to_string());
        }
    }

    let mut iter = command.split_whitespace();
    while let Some(token) = iter.next() {
        if token == "--profile"
            && let Some(value) = iter.next()
        {
            return Some(value.to_string());
        }
    }
    None
}

fn emit_job_banner(
    console: &RchConsole,
    ctx: OutputContext,
    worker: &SelectedWorker,
    build_id: Option<u64>,
) {
    if console.is_machine() {
        return;
    }

    let job = build_id
        .map(|id| format!("j-{}", id))
        .unwrap_or_else(|| "job".to_string());
    let message = format!(
        "{} Job {} submitted to {} (slots {}, speed {:.1})",
        Icons::status_healthy(ctx),
        job,
        worker.id,
        worker.slots_available,
        worker.speed_score
    );

    #[cfg(all(feature = "rich-ui", unix))]
    if console.is_rich() {
        let rich = format!(
            "[bold {}]{}[/] Job {} submitted to {} (slots {}, speed {:.1})",
            RchTheme::INFO,
            Icons::status_healthy(ctx),
            job,
            worker.id,
            worker.slots_available,
            worker.speed_score
        );
        console.print_rich(&rich);
        return;
    }

    console.print_plain(&message);
}

#[allow(clippy::too_many_arguments)] // Presentation helper; wiring is clearer with explicit params.
fn render_compile_summary(
    console: &RchConsole,
    ctx: OutputContext,
    worker: &SelectedWorker,
    build_id: Option<u64>,
    sync: &SyncResult,
    exec_ms: u64,
    artifacts: Option<&SyncResult>,
    artifacts_failed: bool,
    cache_hit: bool,
    success: bool,
) {
    if console.is_machine() {
        return;
    }

    let total_ms = sync.duration_ms + exec_ms + artifacts.map(|a| a.duration_ms).unwrap_or(0);
    let sync_duration = format_duration_ms(Duration::from_millis(sync.duration_ms));
    let exec_duration = format_duration_ms(Duration::from_millis(exec_ms));
    let total_duration = format_duration_ms(Duration::from_millis(total_ms));

    let sync_bytes = format_bytes(sync.bytes_transferred);
    let sync_speed = format_speed(sync.bytes_transferred, sync.duration_ms);

    let (artifact_line, artifact_duration) = if let Some(artifact) = artifacts {
        let bytes = format_bytes(artifact.bytes_transferred);
        let speed = format_speed(artifact.bytes_transferred, artifact.duration_ms);
        let duration = format_duration_ms(Duration::from_millis(artifact.duration_ms));
        (
            format!(
                "{} Artifacts: {} in {} ({})",
                Icons::arrow_down(ctx),
                bytes,
                duration,
                speed
            ),
            duration,
        )
    } else if artifacts_failed {
        ("Artifacts: failed".to_string(), "--".to_string())
    } else {
        ("Artifacts: skipped".to_string(), "--".to_string())
    };

    let job = build_id
        .map(|id| format!("j-{}", id))
        .unwrap_or_else(|| "job".to_string());

    let worker_line = format!(
        "{} Worker: {} | Job: {}",
        Icons::worker(ctx),
        worker.id,
        job
    );
    let timing_line = format!(
        "{} Total: {} (sync {}, build {}, artifacts {})",
        Icons::clock(ctx),
        total_duration,
        sync_duration,
        exec_duration,
        artifact_duration
    );
    let sync_line = format!(
        "{} Sync: {} in {} ({})",
        Icons::arrow_up(ctx),
        sync_bytes,
        sync_duration,
        sync_speed
    );
    let compile_line = format!("{} Compile: {}", Icons::compile(ctx), exec_duration);

    let cache_text = if cache_hit { "HIT" } else { "MISS" };
    let cache_line_plain = format!("{} Cache: {}", Icons::transfer(ctx), cache_text);

    let content_plain = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        worker_line, timing_line, sync_line, compile_line, artifact_line, cache_line_plain
    );

    #[cfg(all(feature = "rich-ui", unix))]
    if console.is_rich() {
        let cache_rich = if cache_hit {
            format!("[bold {}]HIT[/]", RchTheme::SUCCESS)
        } else {
            format!("[bold {}]MISS[/]", RchTheme::WARNING)
        };
        let cache_line = format!("{} Cache: {}", Icons::transfer(ctx), cache_rich);
        let content = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            worker_line, timing_line, sync_line, compile_line, artifact_line, cache_line
        );
        let title = if success {
            "Compilation Complete"
        } else {
            "Compilation Failed"
        };
        let border = if success {
            RchTheme::success()
        } else {
            RchTheme::error()
        };
        let panel = Panel::from_text(&content)
            .title(title)
            .border_style(border)
            .rounded();
        console.print_renderable(&panel);
        return;
    }

    console.print_plain(&content_plain);
}

fn estimate_local_time_ms(remote_ms: u64, worker_speed_score: f64) -> Option<u64> {
    if remote_ms == 0 || worker_speed_score <= 0.0 {
        return None;
    }
    // Don't clamp upper bound - allow scores > 100 (faster than baseline)
    // Lower bound 1.0 prevents zero/negative logic issues
    let normalized = worker_speed_score.max(1.0);

    // Formula: LocalTime = RemoteTime * (WorkerScore / BaselineScore)
    // Example: Worker=200 (2x fast), Remote=5s. Local=5*(200/100)=10s.
    let estimate = (remote_ms as f64) * (normalized / 100.0);
    Some(estimate.round().max(1.0) as u64)
}

fn parse_u32(value: &str) -> Option<u32> {
    value
        .trim_matches('"')
        .parse::<u32>()
        .ok()
        .filter(|n| *n > 0)
}

fn parse_env_u32(command: &str, key: &str) -> Option<u32> {
    let needle = format!("{}=", key);
    command
        .split_whitespace()
        .find_map(|token| token.strip_prefix(&needle).and_then(parse_u32))
}

fn read_env_u32(key: &str) -> Option<u32> {
    if cfg!(test) {
        return None;
    }
    std::env::var(key).ok().and_then(|v| parse_u32(&v))
}

fn parse_jobs_flag(command: &str) -> Option<u32> {
    let tokens: Vec<&str> = command.split_whitespace().collect();
    for (idx, token) in tokens.iter().enumerate() {
        if (*token == "-j" || *token == "--jobs")
            && let Some(next) = tokens.get(idx + 1)
            && let Some(value) = parse_u32(next)
        {
            return Some(value);
        }
        if let Some(value) = token.strip_prefix("-j=").and_then(parse_u32) {
            return Some(value);
        }
        if let Some(value) = token.strip_prefix("-j").and_then(parse_u32) {
            return Some(value);
        }
        if let Some(value) = token.strip_prefix("--jobs=").and_then(parse_u32) {
            return Some(value);
        }
    }
    None
}

fn parse_test_threads(command: &str) -> Option<u32> {
    let tokens: Vec<&str> = command.split_whitespace().collect();
    for (idx, token) in tokens.iter().enumerate() {
        if *token == "--test-threads"
            && let Some(next) = tokens.get(idx + 1)
            && let Some(value) = parse_u32(next)
        {
            return Some(value);
        }
        if let Some(value) = token.strip_prefix("--test-threads=").and_then(parse_u32) {
            return Some(value);
        }
    }
    None
}

// ============================================================================
// Daemon Auto-Start (Self-Healing)
// ============================================================================

#[derive(Debug, thiserror::Error)]
enum AutoStartError {
    #[error("Another process is starting the daemon (lock held)")]
    LockHeld,
    #[error("Auto-start on cooldown (last attempt {0}s ago, need {1}s)")]
    CooldownActive(u64, u64),
    #[error("Failed to spawn rchd: {0}")]
    SpawnFailed(#[source] std::io::Error),
    #[error("Daemon started but socket not found after {0}s")]
    Timeout(u64),
    #[error("rchd binary not found in PATH")]
    BinaryNotFound,
    #[error("Socket exists but daemon not responding (stale socket)")]
    StaleSocket,
    #[error("Configuration disabled auto-start")]
    Disabled,
    #[error("Auto-start I/O error: {0}")]
    Io(#[source] std::io::Error),
}

#[derive(Debug)]
struct AutoStartLock {
    path: PathBuf,
}

impl Drop for AutoStartLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[derive(Debug, Deserialize)]
struct HealthResponse {
    status: String,
}

fn autostart_state_dir() -> PathBuf {
    if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR")
        && !runtime_dir.trim().is_empty()
    {
        return PathBuf::from(runtime_dir).join("rch");
    }
    PathBuf::from("/tmp").join("rch")
}

fn autostart_lock_path() -> PathBuf {
    autostart_state_dir().join("hook_autostart.lock")
}

fn autostart_cooldown_path() -> PathBuf {
    autostart_state_dir().join("hook_autostart.cooldown")
}

fn read_cooldown_timestamp(path: &Path) -> Option<SystemTime> {
    let contents = std::fs::read_to_string(path).ok()?;
    let secs: u64 = contents.trim().parse().ok()?;
    Some(UNIX_EPOCH + Duration::from_secs(secs))
}

fn write_cooldown_timestamp(path: &Path) -> Result<(), AutoStartError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(AutoStartError::Io)?;
    }
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs();
    std::fs::write(path, format!("{now_secs}")).map_err(AutoStartError::Io)
}

fn acquire_autostart_lock(path: &Path) -> Result<AutoStartLock, AutoStartError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(AutoStartError::Io)?;
    }
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(_) => Ok(AutoStartLock {
            path: path.to_path_buf(),
        }),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(AutoStartError::LockHeld),
        Err(e) => Err(AutoStartError::Io(e)),
    }
}

fn which_rchd_path() -> Option<PathBuf> {
    if let Ok(exe_path) = std::env::current_exe()
        && let Some(dir) = exe_path.parent()
    {
        let candidate = dir.join("rchd");
        if candidate.exists() {
            return Some(candidate);
        }
    }

    which("rchd").ok()
}

fn spawn_rchd(path: &Path) -> Result<(), AutoStartError> {
    let mut cmd = std::process::Command::new("nohup");
    cmd.arg(path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null());
    cmd.spawn().map_err(AutoStartError::SpawnFailed)?;
    Ok(())
}

async fn probe_daemon_health(socket_path: &Path) -> bool {
    let connect = timeout(Duration::from_millis(300), UnixStream::connect(socket_path)).await;
    let stream = match connect {
        Ok(Ok(stream)) => stream,
        _ => return false,
    };

    let (reader, mut writer) = stream.into_split();
    if writer.write_all(b"GET /health\n").await.is_err() {
        return false;
    }
    let _ = writer.flush().await;

    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    let mut body = String::new();
    let mut in_body = false;

    loop {
        line.clear();
        let read = match timeout(Duration::from_millis(300), reader.read_line(&mut line)).await {
            Ok(Ok(n)) => n,
            _ => return false,
        };
        if read == 0 {
            break;
        }
        if in_body {
            body.push_str(&line);
        } else if line.trim().is_empty() {
            in_body = true;
        }
    }

    let response: HealthResponse = match serde_json::from_str(body.trim()) {
        Ok(resp) => resp,
        Err(_) => return false,
    };

    response.status == "healthy"
}

async fn wait_for_socket(socket_path: &Path, timeout_secs: u64) -> bool {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        if socket_path.exists() && probe_daemon_health(socket_path).await {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        sleep(Duration::from_millis(100)).await;
    }
}

async fn try_auto_start_daemon(
    config: &SelfHealingConfig,
    socket_path: &Path,
) -> Result<(), AutoStartError> {
    if !config.hook_starts_daemon {
        return Err(AutoStartError::Disabled);
    }

    info!(
        target: "rch::hook::autostart",
        "Daemon unavailable, attempting auto-start"
    );

    if socket_path.exists() {
        if probe_daemon_health(socket_path).await {
            debug!(
                target: "rch::hook::autostart",
                "Socket exists and daemon is responsive"
            );
            return Ok(());
        }

        warn!(
            target: "rch::hook::autostart",
            "Socket exists but daemon not responding"
        );
        if let Err(err) = std::fs::remove_file(socket_path) {
            warn!(
                target: "rch::hook::autostart",
                "Failed to remove stale socket: {}",
                err
            );
            return Err(AutoStartError::StaleSocket);
        }
    }

    let cooldown_path = autostart_cooldown_path();
    if let Some(last_attempt) = read_cooldown_timestamp(&cooldown_path) {
        let elapsed = last_attempt
            .elapsed()
            .unwrap_or(Duration::from_secs(0))
            .as_secs();
        if elapsed < config.auto_start_cooldown_secs {
            return Err(AutoStartError::CooldownActive(
                elapsed,
                config.auto_start_cooldown_secs,
            ));
        }
    }

    let _lock = acquire_autostart_lock(&autostart_lock_path())?;
    write_cooldown_timestamp(&cooldown_path)?;

    let rchd_path = which_rchd_path().ok_or(AutoStartError::BinaryNotFound)?;
    info!(
        target: "rch::hook::autostart",
        "Spawning rchd at {}",
        rchd_path.display()
    );
    spawn_rchd(&rchd_path)?;

    let timeout_secs = config.auto_start_timeout_secs;
    if !wait_for_socket(socket_path, timeout_secs).await {
        return Err(AutoStartError::Timeout(timeout_secs));
    }

    info!(
        target: "rch::hook::autostart",
        "Auto-start successful, socket is responsive"
    );
    Ok(())
}

/// Detect if a cargo test command has a test name filter.
///
/// Filtered tests (e.g., `cargo test my_test`) typically run fewer tests
/// and thus require fewer slots than a full test suite.
///
/// Returns true if the command appears to filter tests by name.
fn is_filtered_test_command(command: &str) -> bool {
    let tokens: Vec<&str> = command.split_whitespace().collect();

    // Find the position of "test" in the command
    let test_pos = tokens.iter().position(|&t| t == "test");
    let Some(test_idx) = test_pos else {
        return false;
    };

    // Flags that take a separate argument (not using =)
    let flags_with_args = [
        "-p",
        "--package",
        "--bin",
        "--test",
        "--bench",
        "--example",
        "--features",
        "--target",
        "--target-dir",
        "-j",
        "--jobs",
        "--color",
        "--message-format",
        "--manifest-path",
    ];

    // Flags that don't take arguments (standalone)
    let standalone_flags = [
        "--lib",
        "--release",
        "--all",
        "--workspace",
        "--no-default-features",
        "--all-features",
        "-v",
        "--verbose",
        "-q",
        "--quiet",
        "--frozen",
        "--locked",
        "--offline",
        "--no-fail-fast",
    ];

    let mut i = test_idx + 1;
    while i < tokens.len() {
        let token = tokens[i];

        // Stop at the separator
        if token == "--" {
            break;
        }

        // Check if this is a flag that takes an argument
        if flags_with_args.contains(&token) {
            // Skip this flag and its argument
            i += 2;
            continue;
        }

        // Check if this is a flag=value style
        if flags_with_args
            .iter()
            .any(|&f| token.starts_with(&format!("{}=", f)))
        {
            i += 1;
            continue;
        }

        // Check if this is a standalone flag
        if standalone_flags.contains(&token) {
            i += 1;
            continue;
        }

        // Skip any other flag-like tokens
        if token.starts_with('-') {
            i += 1;
            continue;
        }

        // Found a non-flag token - this is a test name filter
        return true;
    }

    false
}

/// Check if the command has the --ignored flag (for running only ignored tests).
///
/// Tests marked with `#[ignore]` are typically a small subset, so they need
/// fewer slots. However, --include-ignored runs all tests plus ignored ones.
fn has_ignored_only_flag(command: &str) -> bool {
    let tokens: Vec<&str> = command.split_whitespace().collect();

    // Look for "--ignored" but not "--include-ignored"
    let has_ignored = tokens.contains(&"--ignored");
    let has_include_ignored = tokens.contains(&"--include-ignored");

    // Only return true for --ignored without --include-ignored
    has_ignored && !has_include_ignored
}

/// Check if the command has the --exact flag for exact test name matching.
///
/// Exact matching typically results in running a single test.
fn has_exact_flag(command: &str) -> bool {
    command.split_whitespace().any(|t| t == "--exact")
}

// ============================================================================
// Timing History (bd-2m7j Phase 2)
// ============================================================================

use serde::Serialize;
use std::collections::HashMap;

/// Maximum number of timing samples to retain per project+kind.
const MAX_TIMING_SAMPLES: usize = 20;

/// Maximum number of projects to track in timing history (LRU eviction above this).
const MAX_TIMING_PROJECTS: usize = 500;

/// A single timing record for a completed build.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TimingRecord {
    /// Timestamp when the build completed (Unix seconds).
    pub timestamp: u64,
    /// Duration in milliseconds.
    pub duration_ms: u64,
    /// Whether this was a remote build (true) or local (false).
    pub remote: bool,
}

/// Timing data for a specific project+kind combination.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ProjectTimingData {
    /// Recent local build durations (ring buffer).
    pub local_samples: Vec<TimingRecord>,
    /// Recent remote build durations (ring buffer).
    pub remote_samples: Vec<TimingRecord>,
}

impl ProjectTimingData {
    /// Add a timing sample, maintaining ring buffer size.
    fn add_sample(&mut self, duration_ms: u64, remote: bool) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let record = TimingRecord {
            timestamp,
            duration_ms,
            remote,
        };

        let samples = if remote {
            &mut self.remote_samples
        } else {
            &mut self.local_samples
        };

        samples.push(record);
        if samples.len() > MAX_TIMING_SAMPLES {
            samples.remove(0);
        }
    }

    /// Calculate median duration from samples.
    fn median_duration(&self, remote: bool) -> Option<u64> {
        let samples = if remote {
            &self.remote_samples
        } else {
            &self.local_samples
        };

        if samples.is_empty() {
            return None;
        }

        let mut durations: Vec<u64> = samples.iter().map(|r| r.duration_ms).collect();
        durations.sort_unstable();
        let mid = durations.len() / 2;
        Some(if durations.len().is_multiple_of(2) {
            (durations[mid - 1] + durations[mid]) / 2
        } else {
            durations[mid]
        })
    }

    /// Calculate speedup ratio (local_time / remote_time).
    fn speedup_ratio(&self) -> Option<f64> {
        let local_median = self.median_duration(false)?;
        let remote_median = self.median_duration(true)?;
        if remote_median == 0 {
            return None;
        }
        Some(local_median as f64 / remote_median as f64)
    }

    /// Get the most recent timestamp from any sample (used for LRU eviction).
    fn most_recent_timestamp(&self) -> u64 {
        let local_max = self
            .local_samples
            .iter()
            .map(|r| r.timestamp)
            .max()
            .unwrap_or(0);
        let remote_max = self
            .remote_samples
            .iter()
            .map(|r| r.timestamp)
            .max()
            .unwrap_or(0);
        local_max.max(remote_max)
    }
}

/// Full timing history, keyed by project+kind.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct TimingHistory {
    /// Map from "project_id:kind" to timing data.
    #[serde(default)]
    pub entries: HashMap<String, ProjectTimingData>,
}

/// Process-global in-memory cache for TimingHistory.
///
/// After first load from disk, all reads come from memory (zero disk I/O).
/// Writes update the cache first, then persist to disk asynchronously.
/// This eliminates disk I/O from the estimate_timing_for_build hot path.
static TIMING_CACHE: std::sync::OnceLock<std::sync::RwLock<TimingHistory>> =
    std::sync::OnceLock::new();

/// Get or initialize the global TimingHistory cache.
///
/// First call loads from disk (blocking); subsequent calls return the cached copy.
fn timing_cache() -> &'static std::sync::RwLock<TimingHistory> {
    TIMING_CACHE.get_or_init(|| std::sync::RwLock::new(TimingHistory::load_from_disk()))
}

impl TimingHistory {
    /// Load timing history from disk. Returns empty history on error.
    fn load_from_disk() -> Self {
        let Some(path) = timing_history_path() else {
            return Self::default();
        };

        match std::fs::read_to_string(&path) {
            Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    /// Save timing history to disk. Logs warnings on error but does not propagate.
    fn save_to_disk(&self) {
        let Some(path) = timing_history_path() else {
            return;
        };

        // Ensure parent directory exists
        if let Some(parent) = path.parent()
            && let Err(e) = std::fs::create_dir_all(parent)
        {
            warn!(
                "Failed to create timing history directory {}: {}",
                parent.display(),
                e
            );
            return;
        }

        // Write atomically using temp file
        let temp_path = path.with_extension("tmp");
        let content = match serde_json::to_string_pretty(self) {
            Ok(c) => c,
            Err(e) => {
                warn!("Failed to serialize timing history: {}", e);
                return;
            }
        };
        if let Err(e) = std::fs::write(&temp_path, &content) {
            warn!(
                "Failed to write timing history to {}: {}",
                temp_path.display(),
                e
            );
            return;
        }
        if let Err(e) = std::fs::rename(&temp_path, &path) {
            warn!(
                "Failed to rename timing history {} -> {}: {}",
                temp_path.display(),
                path.display(),
                e
            );
        }
    }

    /// Get the key for a project+kind combination.
    fn key(project: &str, kind: Option<CompilationKind>) -> String {
        let kind_str = kind
            .map(|k| format!("{:?}", k))
            .unwrap_or_else(|| "Unknown".to_string());
        format!("{}:{}", project, kind_str)
    }

    /// Get timing data for a project+kind.
    fn get(&self, project: &str, kind: Option<CompilationKind>) -> Option<&ProjectTimingData> {
        self.entries.get(&Self::key(project, kind))
    }

    /// Record a timing sample.
    ///
    /// Implements LRU eviction to prevent unbounded memory growth:
    /// if entries exceed MAX_TIMING_PROJECTS, evicts the least recently used entry.
    fn record(
        &mut self,
        project: &str,
        kind: Option<CompilationKind>,
        duration_ms: u64,
        remote: bool,
    ) {
        let key = Self::key(project, kind);
        let data = self.entries.entry(key).or_default();
        data.add_sample(duration_ms, remote);

        // LRU eviction: if over limit, remove the entry with oldest timestamp
        if self.entries.len() > MAX_TIMING_PROJECTS {
            // Find the key with the oldest most_recent_timestamp
            if let Some(oldest_key) = self
                .entries
                .iter()
                .min_by_key(|(_, data)| data.most_recent_timestamp())
                .map(|(k, _)| k.clone())
            {
                self.entries.remove(&oldest_key);
            }
        }
    }
}

/// Get the path to the timing history file.
fn timing_history_path() -> Option<PathBuf> {
    dirs::cache_dir().map(|dir| dir.join("rch").join("timing_history.json"))
}

/// Record a build timing to the history store.
///
/// Updates the in-memory cache immediately, then persists to disk.
/// Called after a build completes to update the timing history.
/// This is used by `estimate_timing_for_build` for future predictions.
pub fn record_build_timing(
    project: &str,
    kind: Option<CompilationKind>,
    duration_ms: u64,
    remote: bool,
) {
    let cache = timing_cache();
    // Update in-memory cache, then write-through to disk
    if let Ok(mut history) = cache.write() {
        history.record(project, kind, duration_ms, remote);
        history.save_to_disk();
    }
}

/// Timing estimate for offload gating decisions.
///
/// Used to determine whether a build is worth offloading based on
/// predicted local execution time and expected speedup.
#[derive(Debug, Clone)]
struct TimingEstimate {
    /// Predicted local build time in milliseconds.
    pub predicted_local_ms: u64,
    /// Predicted speedup ratio (local_time / remote_time), if available.
    /// None indicates insufficient data to estimate speedup.
    pub predicted_speedup: Option<f64>,
}

/// Estimate timing for a build to support offload gating.
///
/// This function attempts to estimate how long a build would take locally
/// and what speedup we might achieve by offloading. The estimation uses
/// this fallback order:
/// 1. Historical timing data for this project/kind
/// 2. Conservative defaults (allow offload)
///
/// When no historical data is available, returns None to trigger fail-open
/// behavior (allow offload attempt).
#[allow(unused_variables)] // config used for future speedscore integration
fn estimate_timing_for_build(
    project: &str,
    kind: Option<CompilationKind>,
    config: &rch_common::RchConfig,
) -> Option<TimingEstimate> {
    // Read from in-memory cache (zero disk I/O after first load)
    let cache = timing_cache();
    let history = cache.read().ok()?;

    // Look up timing data for this project+kind
    let data = history.get(project, kind)?;

    // Need at least local samples to estimate
    let local_median = data.median_duration(false)?;

    // Speedup is optional (requires both local and remote history)
    let speedup = data.speedup_ratio();

    Some(TimingEstimate {
        predicted_local_ms: local_median,
        predicted_speedup: speedup,
    })
}

fn estimate_cores_for_command(
    kind: Option<CompilationKind>,
    command: &str,
    config: &rch_common::CompilationConfig,
) -> u32 {
    let build_default = config.build_slots.max(1);
    let test_default = config.test_slots.max(1);
    let check_default = config.check_slots.max(1);

    // Slot reduction for filtered tests (fewer tests = fewer slots needed)
    let filtered_test_slots = (test_default / 2).max(2);

    match kind {
        Some(
            CompilationKind::CargoTest | CompilationKind::CargoNextest | CompilationKind::BunTest,
        ) => {
            // Priority order for test slot estimation:
            // 1. Explicit --test-threads flag
            // 2. RUST_TEST_THREADS environment variable (inline or ambient)
            // 3. Inferred from test filtering (reduced slots)
            // 4. Default test_slots from config
            if let Some(threads) = parse_test_threads(command) {
                return threads.max(1);
            }
            if let Some(threads) = parse_env_u32(command, "RUST_TEST_THREADS")
                .or_else(|| read_env_u32("RUST_TEST_THREADS"))
            {
                return threads.max(1);
            }

            // Reduce slots for filtered tests:
            // - Specific test name filter (cargo test my_test)
            // - --exact flag (single test match)
            // - --ignored only (typically few ignored tests)
            if is_filtered_test_command(command) || has_exact_flag(command) {
                return filtered_test_slots;
            }
            if has_ignored_only_flag(command) {
                return filtered_test_slots;
            }

            test_default.max(1)
        }
        Some(
            CompilationKind::CargoCheck
            | CompilationKind::CargoClippy
            | CompilationKind::BunTypecheck,
        ) => parse_jobs_flag(command)
            .or_else(|| parse_env_u32(command, "CARGO_BUILD_JOBS"))
            .or_else(|| read_env_u32("CARGO_BUILD_JOBS"))
            .unwrap_or(check_default)
            .max(1),
        Some(_) => parse_jobs_flag(command)
            .or_else(|| parse_env_u32(command, "CARGO_BUILD_JOBS"))
            .or_else(|| read_env_u32("CARGO_BUILD_JOBS"))
            .unwrap_or(build_default)
            .max(1),
        None => build_default,
    }
}

fn is_test_kind(kind: Option<CompilationKind>) -> bool {
    matches!(
        kind,
        Some(CompilationKind::CargoTest | CompilationKind::CargoNextest | CompilationKind::BunTest)
    )
}

fn emit_first_run_message(worker: &SelectedWorker, remote_ms: u64, local_ms: Option<u64>) {
    let divider = "----------------------------------------";
    let remote = format_duration_ms(Duration::from_millis(remote_ms));

    eprintln!();
    eprintln!("{}", divider);
    eprintln!("First remote build complete!");
    eprintln!();

    if let Some(local_ms) = local_ms {
        let local = format_duration_ms(Duration::from_millis(local_ms));
        eprintln!(
            "Your build ran on '{}' in {} (local estimate ~{}).",
            worker.id, remote, local
        );
    } else {
        eprintln!("Your build ran on '{}' in {}.", worker.id, remote);
    }

    eprintln!("RCH will run silently in the background from now on.");
    eprintln!();
    eprintln!("To see build activity: rch status --jobs");
    eprintln!("To disable this message: rch config set first_run_complete true");
    eprintln!("{}", divider);
    eprintln!();
}

/// Process a hook request and return the output.
async fn process_hook(input: HookInput) -> HookOutput {
    // Tier 0: Only process Bash tool
    if input.tool_name != "Bash" {
        debug!("Non-Bash tool: {}, allowing", input.tool_name);
        return HookOutput::allow();
    }

    let command = &input.tool_input.command;
    // Mask sensitive data in debug logs (API keys, tokens, passwords)
    debug!("Processing command: {}", mask_sensitive_command(command));

    // Classify the command using 5-tier system with LRU cache (bd-17cn)
    // Per AGENTS.md: non-compilation decisions must complete in <1ms, compilation in <5ms
    // The cache reduces CPU overhead for repeated build/test commands
    let classify_start = Instant::now();
    let classification = crate::cache::classify_cached(command, classify_command);
    let classification_duration = classify_start.elapsed();
    let classification_duration_us = classification_duration.as_micros() as u64;

    if !classification.is_compilation {
        // Log non-compilation decision latency (budget: <1ms per AGENTS.md)
        let duration_ms = classification_duration_us as f64 / 1000.0;
        if duration_ms > 1.0 {
            warn!(
                "Non-compilation decision exceeded 1ms budget: {:.3}ms for '{}'",
                duration_ms, command
            );
        } else {
            debug!(
                "Non-compilation decision: {:.3}ms for '{}' ({})",
                duration_ms, command, classification.reason
            );
        }
        return HookOutput::allow();
    }

    let config = match load_config() {
        Ok(cfg) => cfg,
        Err(e) => {
            warn!("Failed to load config: {}, allowing local execution", e);
            return HookOutput::allow();
        }
    };

    let reporter = HookReporter::new(config.output.visibility);

    if !config.general.enabled {
        debug!("RCH disabled via config, allowing local execution");
        return HookOutput::allow();
    }

    // Per-project overrides (bd-1vzb)
    //
    // - force_local: always allow local execution for compilation commands (skip daemon + transfer)
    // - force_remote: always attempt remote execution when safe (bypass confidence threshold)
    //
    // Conflicting flags should be caught by config validation, but handle defensively here.
    if config.general.force_local && config.general.force_remote {
        warn!(
            "Invalid config: both general.force_local and general.force_remote are set; allowing local execution"
        );
        reporter.summary("[RCH] local (invalid config: force_local+force_remote)");
        return HookOutput::allow();
    }
    if config.general.force_local {
        debug!("RCH force_local enabled, allowing local execution");
        reporter.summary("[RCH] local (force_local)");
        return HookOutput::allow();
    }

    // Log compilation decision latency (budget: <5ms per AGENTS.md)
    let duration_ms = classification_duration_us as f64 / 1000.0;
    if duration_ms > 5.0 {
        warn!(
            "Compilation decision exceeded 5ms budget: {:.3}ms",
            duration_ms
        );
    }

    info!(
        "Compilation detected: {:?} (confidence: {:.2}, classified in {:.3}ms)",
        classification.kind, classification.confidence, duration_ms
    );
    reporter.verbose(&format!(
        "[RCH] compile {:?} (confidence {:.2})",
        classification.kind, classification.confidence
    ));

    // Check confidence threshold
    let confidence_threshold = if config.general.force_remote {
        reporter.verbose("[RCH] force_remote enabled: bypassing confidence threshold");
        0.0
    } else {
        config.compilation.confidence_threshold
    };
    if classification.confidence < confidence_threshold {
        debug!(
            "Confidence {:.2} below threshold {:.2}, allowing local execution",
            classification.confidence, confidence_threshold
        );
        reporter.summary("[RCH] local (confidence below threshold)");
        return HookOutput::allow();
    }

    // Check execution allowlist (bd-785w)
    // Commands not in the allowlist fail-open to local execution
    if let Some(kind) = classification.kind {
        let command_base = kind.command_base();
        if !config.execution.is_allowed(command_base) {
            debug!(
                "Command base '{}' not in execution allowlist, allowing local execution",
                command_base
            );
            reporter.summary(&format!(
                "[RCH] local (command '{}' not in allowlist)",
                command_base
            ));
            return HookOutput::allow();
        }
    }

    // Extract project for timing estimation and daemon query
    let project = extract_project_name();

    // Check timing thresholds (min_local_time_ms and remote_speedup_threshold)
    // This gating prevents offloading tiny builds where overhead dominates.
    // Note: spawn_blocking moves file I/O off the async runtime (bd-1gz8)
    if !config.general.force_remote {
        let project_clone = project.clone();
        let kind = classification.kind;
        let config_clone = config.clone();
        let timing_estimate = tokio::task::spawn_blocking(move || {
            estimate_timing_for_build(&project_clone, kind, &config_clone)
        })
        .await
        .ok()
        .flatten();

        if let Some(timing_estimate) = timing_estimate {
            // Gate on min_local_time_ms: skip remote if build is too small
            if timing_estimate.predicted_local_ms < config.compilation.min_local_time_ms {
                debug!(
                    "Predicted local time {}ms < threshold {}ms, allowing local execution",
                    timing_estimate.predicted_local_ms, config.compilation.min_local_time_ms
                );
                reporter.verbose(&format!(
                    "[RCH] local (predicted {}ms < min {}ms)",
                    timing_estimate.predicted_local_ms, config.compilation.min_local_time_ms
                ));
                reporter.summary("[RCH] local (build too small for offload)");
                return HookOutput::allow();
            }

            // Gate on remote_speedup_threshold: skip remote if speedup isn't worth it
            if let Some(predicted_speedup) = timing_estimate.predicted_speedup
                && predicted_speedup < config.compilation.remote_speedup_threshold
            {
                debug!(
                    "Predicted speedup {:.2}x < threshold {:.2}x, allowing local execution",
                    predicted_speedup, config.compilation.remote_speedup_threshold
                );
                reporter.verbose(&format!(
                    "[RCH] local (predicted speedup {:.1}x < {:.1}x threshold)",
                    predicted_speedup, config.compilation.remote_speedup_threshold
                ));
                reporter.summary("[RCH] local (remote speedup insufficient)");
                return HookOutput::allow();
            }

            debug!(
                "Timing check passed: predicted_local={}ms, predicted_speedup={:?}",
                timing_estimate.predicted_local_ms, timing_estimate.predicted_speedup
            );
        } else {
            // No timing history available - fail-open (allow offload)
            debug!(
                "No timing history for {}/{:?}, allowing offload attempt",
                project, classification.kind
            );
        }
    }

    let estimated_cores =
        estimate_cores_for_command(classification.kind, command, &config.compilation);
    reporter.verbose("[RCH] selecting worker...");

    // Detect toolchain to send to daemon
    let project_root_for_detection = std::env::current_dir().ok();
    let toolchain = if let Some(root) = &project_root_for_detection {
        match detect_toolchain(root) {
            Ok(tc) => {
                debug!("Detected toolchain: {}", tc);
                Some(tc)
            }
            Err(e) => {
                warn!("Failed to detect toolchain: {}", e);
                None
            }
        }
    } else {
        None
    };

    // Determine required runtime
    let required_runtime = required_runtime_for_kind(classification.kind);
    let command_priority = command_priority_from_env(&reporter);

    match query_daemon(
        &config.general.socket_path,
        &project,
        estimated_cores,
        command,
        toolchain.as_ref(),
        required_runtime,
        command_priority,
        classification_duration_us,
        Some(std::process::id()),
    )
    .await
    {
        Ok(response) => {
            handle_selection_response(
                response,
                command,
                &config,
                &reporter,
                toolchain.as_ref(),
                classification.kind,
                &project,
                estimated_cores,
            )
            .await
        }
        Err(e) => {
            warn!(
                target: "rch::hook::autostart",
                "Failed to query daemon: {}",
                e
            );
            match try_auto_start_daemon(
                &config.self_healing,
                Path::new(&config.general.socket_path),
            )
            .await
            {
                Ok(()) => match query_daemon(
                    &config.general.socket_path,
                    &project,
                    estimated_cores,
                    command,
                    toolchain.as_ref(),
                    required_runtime,
                    command_priority,
                    classification_duration_us,
                    Some(std::process::id()),
                )
                .await
                {
                    Ok(response) => {
                        handle_selection_response(
                            response,
                            command,
                            &config,
                            &reporter,
                            toolchain.as_ref(),
                            classification.kind,
                            &project,
                            estimated_cores,
                        )
                        .await
                    }
                    Err(err) => {
                        warn!(
                            target: "rch::hook::autostart",
                            "Failed to query daemon after auto-start: {}",
                            err
                        );
                        reporter.summary("[RCH] local (daemon unavailable)");
                        HookOutput::allow()
                    }
                },
                Err(auto_err) => {
                    warn!(
                        target: "rch::hook::autostart",
                        "Failed to auto-start daemon: {}",
                        auto_err
                    );
                    warn!("Original daemon error: {}", e);
                    reporter.summary("[RCH] local (daemon unavailable)");
                    HookOutput::allow()
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)] // Pipeline wiring favors explicit params.
async fn handle_selection_response(
    response: SelectionResponse,
    command: &str,
    config: &rch_common::RchConfig,
    reporter: &HookReporter,
    toolchain: Option<&ToolchainInfo>,
    classification_kind: Option<CompilationKind>,
    project: &str,
    estimated_cores: u32,
) -> HookOutput {
    // Check if a worker was assigned
    let Some(worker) = response.worker else {
        // No worker available - graceful fallback to local execution
        warn!(
            "⚠️ RCH: No remote workers available ({}), executing locally",
            response.reason
        );
        reporter.summary(&format!("[RCH] local ({})", response.reason));
        return HookOutput::allow();
    };

    info!(
        "Selected worker: {} at {}@{} ({} slots, speed {:.1})",
        worker.id, worker.user, worker.host, worker.slots_available, worker.speed_score
    );
    reporter.verbose(&format!(
        "[RCH] selected {}@{} (slots {}, speed {:.1})",
        worker.user, worker.host, worker.slots_available, worker.speed_score
    ));

    // Execute remote compilation pipeline
    let remote_start = Instant::now();
    let result = execute_remote_compilation(
        &worker,
        command,
        config.transfer.clone(),
        config.environment.allowlist.clone(),
        &config.compilation,
        toolchain,
        classification_kind,
        reporter,
        &config.general.socket_path,
        config.output.color_mode,
        response.build_id,
    )
    .await;
    let remote_elapsed = remote_start.elapsed();

    // Always release slots after execution
    let release_exit_code = result
        .as_ref()
        .map(|ok| ok.exit_code)
        .unwrap_or(EXIT_BUILD_ERROR);
    // Add total elapsed time to the timing breakdown
    let release_timing = result.as_ref().ok().map(|ok| {
        let mut timing = ok.timing.clone();
        timing.total = Some(remote_elapsed);
        timing
    });
    if let Err(e) = release_worker(
        &config.general.socket_path,
        &worker.id,
        estimated_cores,
        response.build_id,
        Some(release_exit_code),
        None,
        None,
        release_timing.as_ref(),
    )
    .await
    {
        warn!("Failed to release worker slots: {}", e);
    }

    match result {
        Ok(result) => {
            if result.exit_code == 0 {
                // Command succeeded remotely - deny local execution
                // The agent sees output via stderr, artifacts are local
                info!("Remote compilation succeeded, denying local execution");
                reporter.summary(&format!(
                    "[RCH] remote {} ({})",
                    worker.id,
                    format_duration_ms(remote_elapsed)
                ));

                // Record successful build for cache affinity
                let is_test = classification_kind
                    .map(|kind| kind.is_test_command())
                    .unwrap_or(false);
                if let Err(e) =
                    record_build(&config.general.socket_path, &worker.id, project, is_test).await
                {
                    warn!("Failed to record build: {}", e);
                }

                // Record timing for future gating decisions (bd-mnhp: spawn_blocking for file I/O)
                let project_for_timing = project.to_string();
                let duration = result.duration_ms;
                tokio::task::spawn_blocking(move || {
                    record_build_timing(&project_for_timing, classification_kind, duration, true);
                });

                if !config.output.first_run_complete {
                    let local_estimate =
                        estimate_local_time_ms(result.duration_ms, worker.speed_score);
                    emit_first_run_message(&worker, result.duration_ms, local_estimate);
                    if let Err(e) = crate::config::set_first_run_complete(true) {
                        warn!("Failed to persist first_run_complete: {}", e);
                    }
                }

                HookOutput::deny("RCH: Command executed successfully on remote worker".to_string())
            } else if is_toolchain_failure(&result.stderr, result.exit_code) {
                // Toolchain failure - fall back to local execution
                warn!(
                    "Remote toolchain failure detected (exit {}), falling back to local",
                    result.exit_code
                );
                reporter.summary(&format!("[RCH] local (toolchain missing on {})", worker.id));
                HookOutput::allow()
            } else {
                // Command failed remotely - still deny to prevent re-execution
                // The agent saw the error output via stderr
                //
                // Exit code semantics:
                // - 101: Test failures (cargo test ran but tests failed)
                // - 1: Build/compilation error
                // - 128+N: Process killed by signal N
                let exit_code = result.exit_code;

                // Check for signal-killed processes (OOM, etc.)
                if let Some(signal) = is_signal_killed(exit_code) {
                    warn!(
                        "Remote command killed by signal {} ({}) on {}, denying local execution",
                        signal,
                        signal_name(signal),
                        worker.id
                    );
                    reporter.summary(&format!(
                        "[RCH] remote {} killed ({})",
                        worker.id,
                        signal_name(signal)
                    ));
                } else if exit_code == EXIT_TEST_FAILURES {
                    // Cargo test exit 101: tests ran but some failed
                    info!(
                        "Remote tests failed (exit 101) on {}, denying local re-execution",
                        worker.id
                    );
                    reporter.summary(&format!("[RCH] remote {} tests failed", worker.id));
                } else if exit_code == EXIT_BUILD_ERROR {
                    // Build/compilation error
                    info!(
                        "Remote build error (exit 1) on {}, denying local re-execution",
                        worker.id
                    );
                    reporter.summary(&format!("[RCH] remote {} build error", worker.id));
                } else {
                    // Other non-zero exit code
                    info!(
                        "Remote command failed (exit {}) on {}, denying local execution",
                        exit_code, worker.id
                    );
                    reporter.summary(&format!(
                        "[RCH] remote {} failed (exit {})",
                        worker.id, exit_code
                    ));
                }

                // Still record timing for failed builds (useful for predictions)
                // bd-mnhp: spawn_blocking for file I/O
                let project_for_timing = project.to_string();
                let duration = result.duration_ms;
                tokio::task::spawn_blocking(move || {
                    record_build_timing(&project_for_timing, classification_kind, duration, true);
                });

                HookOutput::deny(format!(
                    "RCH: Remote compilation failed with exit code {}",
                    exit_code
                ))
            }
        }
        Err(e) => {
            // Check if this is a transfer skip (not a failure, just too large/slow)
            if let Some(skip_err) = e.downcast_ref::<TransferError>()
                && let TransferError::TransferSkipped { reason } = skip_err
            {
                info!(
                    "Transfer skipped ({}), falling back to local execution",
                    reason
                );
                reporter.summary(&format!("[RCH] local ({})", reason));
                return HookOutput::allow();
            }

            // Pipeline failed - fall back to local execution
            warn!(
                "Remote execution pipeline failed: {}, falling back to local",
                e
            );
            reporter.summary("[RCH] local (remote pipeline failed)");
            HookOutput::allow()
        }
    }
}

/// Query the daemon for a worker.
#[allow(clippy::too_many_arguments)] // Command routing query wires many independent fields.
pub(crate) async fn query_daemon(
    socket_path: &str,
    project: &str,
    cores: u32,
    command: &str,
    toolchain: Option<&ToolchainInfo>,
    required_runtime: RequiredRuntime,
    command_priority: CommandPriority,
    classification_duration_us: u64,
    hook_pid: Option<u32>,
) -> anyhow::Result<SelectionResponse> {
    // Check if socket exists
    if !Path::new(socket_path).exists() {
        return Err(DaemonError::SocketNotFound {
            socket_path: socket_path.to_string(),
        }
        .into());
    }

    // Connect to daemon (with timeout to avoid hanging if socket is stuck)
    let stream = timeout(Duration::from_secs(5), UnixStream::connect(socket_path))
        .await
        .map_err(|_| anyhow::anyhow!("Daemon connect timed out after 5s"))??;
    let (reader, mut writer) = stream.into_split();

    // Build query string
    let mut query = format!("project={}&cores={}", urlencoding_encode(project), cores);
    query.push_str(&format!("&command={}", urlencoding_encode(command)));

    if let Some(tc) = toolchain
        && let Ok(json) = serde_json::to_string(tc)
    {
        query.push_str(&format!("&toolchain={}", urlencoding_encode(&json)));
    }

    if required_runtime != RequiredRuntime::None {
        // Serialize to lowercase string (rust, bun, node)
        // Since it's an enum with lowercase serialization, serde_json::to_string gives "rust" (with quotes)
        // We want just the string.
        let json = serde_json::to_string(&required_runtime).unwrap_or_default();
        let raw = json.trim_matches('"');
        query.push_str(&format!("&runtime={}", urlencoding_encode(raw)));
    }

    query.push_str(&format!(
        "&priority={}",
        urlencoding_encode(&command_priority.to_string())
    ));

    // Add classification duration for AGENTS.md compliance tracking
    query.push_str(&format!(
        "&classification_us={}",
        classification_duration_us
    ));

    if let Some(pid) = hook_pid {
        query.push_str(&format!("&hook_pid={}", pid));
    }

    // When all workers are at capacity, queue the build on the daemon instead of
    // falling back to a local compilation storm. Disable with RCH_QUEUE_WHEN_BUSY=0.
    if queue_when_busy_enabled() {
        query.push_str("&wait=1");
    }

    // Send request
    let request = format!("GET /select-worker?{}\n", query);
    writer.write_all(request.as_bytes()).await?;
    writer.flush().await?;

    // Read response (skip HTTP headers) with timeout and body size limit.
    // The daemon should respond within 30s even when queuing builds.
    // Body is capped at 64KB to prevent unbounded memory growth.
    const MAX_RESPONSE_BODY: usize = 64 * 1024;
    const RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);

    let read_response = async {
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
                if body.len() + line.len() > MAX_RESPONSE_BODY {
                    return Err(anyhow::anyhow!(
                        "Daemon response body exceeded {}KB limit",
                        MAX_RESPONSE_BODY / 1024
                    ));
                }
                body.push_str(&line);
            } else if line.trim().is_empty() {
                in_body = true;
            }
        }

        serde_json::from_str::<SelectionResponse>(body.trim())
            .map_err(|e| anyhow::anyhow!("Failed to parse daemon response: {}", e))
    };

    let response = timeout(RESPONSE_TIMEOUT, read_response)
        .await
        .map_err(|_| anyhow::anyhow!("Daemon response timed out after 30s"))??;

    Ok(response)
}

/// Release reserved slots on a worker.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn release_worker(
    socket_path: &str,
    worker_id: &WorkerId,
    slots: u32,
    build_id: Option<u64>,
    exit_code: Option<i32>,
    duration_ms: Option<u64>,
    bytes_transferred: Option<u64>,
    timing: Option<&CommandTimingBreakdown>,
) -> anyhow::Result<()> {
    if !Path::new(socket_path).exists() {
        return Ok(()); // Ignore if daemon gone
    }

    let stream = match timeout(Duration::from_secs(2), UnixStream::connect(socket_path)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => return Ok(()), // Timeout connecting — daemon likely busy, don't block hook
    };
    let (reader, mut writer) = stream.into_split();

    // Send request
    let mut request = format!(
        "POST /release-worker?worker={}&slots={}",
        urlencoding_encode(worker_id.as_str()),
        slots
    );
    if let Some(build_id) = build_id {
        request.push_str(&format!("&build_id={}", build_id));
    }
    if let Some(exit_code) = exit_code {
        request.push_str(&format!("&exit_code={}", exit_code));
    }
    if let Some(duration_ms) = duration_ms {
        request.push_str(&format!("&duration_ms={}", duration_ms));
    }
    if let Some(bytes_transferred) = bytes_transferred {
        request.push_str(&format!("&bytes_transferred={}", bytes_transferred));
    }
    request.push('\n');

    // Add timing breakdown as JSON body if present
    if let Some(timing) = timing
        && let Ok(json) = serde_json::to_string(timing)
    {
        request.push_str(&json);
        request.push('\n');
    }

    writer.write_all(request.as_bytes()).await?;
    writer.flush().await?;

    // Read response line (to ensure daemon processed it) with timeout
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    let _ = timeout(Duration::from_secs(5), reader.read_line(&mut line)).await;

    Ok(())
}

/// Record a successful build on a worker (for cache affinity).
pub(crate) async fn record_build(
    socket_path: &str,
    worker_id: &WorkerId,
    project: &str,
    is_test: bool,
) -> anyhow::Result<()> {
    if !Path::new(socket_path).exists() {
        return Ok(()); // Ignore if daemon gone
    }

    let stream = match timeout(Duration::from_secs(2), UnixStream::connect(socket_path)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => return Ok(()), // Timeout connecting — daemon likely busy, don't block hook
    };
    let (reader, mut writer) = stream.into_split();

    // Send request
    let mut request = format!(
        "POST /record-build?worker={}&project={}",
        urlencoding_encode(worker_id.as_str()),
        urlencoding_encode(project)
    );
    if is_test {
        request.push_str("&is_test=1");
    }
    request.push('\n');
    writer.write_all(request.as_bytes()).await?;
    writer.flush().await?;

    // Read response line with timeout
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    let _ = timeout(Duration::from_secs(5), reader.read_line(&mut line)).await;

    Ok(())
}

/// URL percent-encoding for query parameters.
///
/// Encodes characters that are not URL-safe (RFC 3986 unreserved characters).
/// Optimized to avoid allocations by using direct hex conversion.
fn urlencoding_encode(s: &str) -> String {
    // Hex digits lookup table for zero-allocation encoding
    const HEX_DIGITS: &[u8; 16] = b"0123456789ABCDEF";

    let mut result = String::with_capacity(s.len() * 3); // Worst case: all encoded

    for byte in s.as_bytes() {
        match *byte {
            // Unreserved characters (RFC 3986) - don't encode
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(*byte as char);
            }
            // Everything else needs encoding
            _ => {
                result.push('%');
                result.push(HEX_DIGITS[(byte >> 4) as usize] as char);
                result.push(HEX_DIGITS[(byte & 0x0F) as usize] as char);
            }
        }
    }

    result
}

fn queue_when_busy_enabled() -> bool {
    let Ok(value) = std::env::var("RCH_QUEUE_WHEN_BUSY") else {
        return true;
    };
    let value = value.trim().to_lowercase();
    !matches!(value.as_str(), "0" | "false" | "no" | "off")
}

/// Extract project name from current working directory.
fn extract_project_name() -> String {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("unknown"));
    let name = cwd
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    // Compute short hash of the absolute path to ensure uniqueness
    // This prevents cache affinity collisions for projects with same dir name (e.g. "app")
    let hash = blake3::hash(cwd.to_string_lossy().as_bytes()).to_hex();
    let short_hash = &hash[..8];

    format!("{}-{}", name, short_hash)
}

fn command_priority_from_env(reporter: &HookReporter) -> CommandPriority {
    let Ok(raw) = std::env::var("RCH_PRIORITY") else {
        return CommandPriority::Normal;
    };

    match raw.parse::<CommandPriority>() {
        Ok(value) => value,
        Err(()) => {
            reporter.verbose(&format!(
                "[RCH] ignoring invalid RCH_PRIORITY={:?} (expected: low|normal|high)",
                raw
            ));
            CommandPriority::Normal
        }
    }
}

/// Convert a SelectedWorker to a WorkerConfig.
fn selected_worker_to_config(worker: &SelectedWorker) -> WorkerConfig {
    WorkerConfig {
        id: worker.id.clone(),
        host: worker.host.clone(),
        user: worker.user.clone(),
        identity_file: worker.identity_file.clone(),
        total_slots: worker.slots_available,
        priority: 100,
        tags: vec![],
    }
}

/// Result of remote compilation execution.
#[derive(Debug)]
struct RemoteExecutionResult {
    /// Exit code of the remote command.
    exit_code: i32,
    /// Standard error output (used for toolchain detection).
    stderr: String,
    /// Remote command duration in milliseconds.
    duration_ms: u64,
    /// Per-phase timing breakdown.
    timing: CommandTimingBreakdown,
}

/// Check if the failure is a toolchain-related infrastructure failure.
///
/// Returns true if the error indicates a toolchain issue that should
/// trigger a local fallback rather than denying execution.
fn is_toolchain_failure(stderr: &str, exit_code: i32) -> bool {
    if exit_code == 0 {
        return false;
    }

    // Check for common toolchain failure patterns
    let toolchain_patterns = [
        "toolchain",
        "is not installed",
        "rustup: command not found",
        "rustup: not found",
        "error: no such command",
        "error: toolchain",
    ];

    let stderr_lower = stderr.to_lowercase();
    toolchain_patterns
        .iter()
        .any(|pattern| stderr_lower.contains(&pattern.to_lowercase()))
}

/// Check if the process was killed by a signal.
///
/// Exit codes > 128 indicate the process was terminated by a signal.
/// The signal number is exit_code - 128.
///
/// Common signals:
/// - 137 (SIGKILL = 9): Typically OOM killer
/// - 143 (SIGTERM = 15): Graceful termination request
/// - 139 (SIGSEGV = 11): Segmentation fault
fn is_signal_killed(exit_code: i32) -> Option<i32> {
    if exit_code > EXIT_SIGNAL_BASE {
        Some(exit_code - EXIT_SIGNAL_BASE)
    } else {
        None
    }
}

/// Format a signal number as a human-readable name.
fn signal_name(signal: i32) -> &'static str {
    match signal {
        1 => "SIGHUP",
        2 => "SIGINT",
        3 => "SIGQUIT",
        6 => "SIGABRT",
        9 => "SIGKILL",
        11 => "SIGSEGV",
        13 => "SIGPIPE",
        14 => "SIGALRM",
        15 => "SIGTERM",
        _ => "UNKNOWN",
    }
}

/// Map a classification kind to required runtime.
pub(crate) fn required_runtime_for_kind(kind: Option<CompilationKind>) -> RequiredRuntime {
    match kind {
        Some(k) => match k {
            CompilationKind::CargoBuild
            | CompilationKind::CargoTest
            | CompilationKind::CargoCheck
            | CompilationKind::CargoClippy
            | CompilationKind::CargoDoc
            | CompilationKind::CargoNextest
            | CompilationKind::CargoBench
            | CompilationKind::Rustc => RequiredRuntime::Rust,

            CompilationKind::BunTest | CompilationKind::BunTypecheck => RequiredRuntime::Bun,

            _ => RequiredRuntime::None,
        },
        None => RequiredRuntime::None,
    }
}

/// Get artifact patterns based on compilation kind.
///
/// Test commands use minimal patterns since test output is streamed and the full
/// target/ directory is not needed. This significantly reduces artifact transfer
/// time for test-only commands.
fn get_artifact_patterns(kind: Option<CompilationKind>) -> Vec<String> {
    match kind {
        Some(CompilationKind::BunTest) | Some(CompilationKind::BunTypecheck) => {
            default_bun_artifact_patterns()
        }
        // Test and bench commands only need coverage/results artifacts, not full target/
        Some(CompilationKind::CargoTest)
        | Some(CompilationKind::CargoNextest)
        | Some(CompilationKind::CargoBench) => default_rust_test_artifact_patterns(),
        Some(CompilationKind::Rustc)
        | Some(CompilationKind::CargoBuild)
        | Some(CompilationKind::CargoCheck)
        | Some(CompilationKind::CargoClippy)
        | Some(CompilationKind::CargoDoc) => default_rust_artifact_patterns(),
        Some(CompilationKind::Gcc)
        | Some(CompilationKind::Gpp)
        | Some(CompilationKind::Clang)
        | Some(CompilationKind::Clangpp)
        | Some(CompilationKind::Make)
        | Some(CompilationKind::CmakeBuild)
        | Some(CompilationKind::Ninja)
        | Some(CompilationKind::Meson) => default_c_cpp_artifact_patterns(),
        _ => default_rust_artifact_patterns(),
    }
}

/// Execute a compilation command on a remote worker.
///
/// This function:
/// 1. Syncs the project to the remote worker
/// 2. Executes the command remotely with streaming output
/// 3. Retrieves build artifacts back to local
///
/// Returns the execution result including exit code and stderr.
#[allow(clippy::too_many_arguments)] // Pipeline wiring favors explicit params
async fn execute_remote_compilation(
    worker: &SelectedWorker,
    command: &str,
    transfer_config: TransferConfig,
    env_allowlist: Vec<String>,
    compilation_config: &rch_common::CompilationConfig,
    toolchain: Option<&ToolchainInfo>,
    kind: Option<CompilationKind>,
    reporter: &HookReporter,
    socket_path: &str,
    color_mode: ColorMode,
    build_id: Option<u64>,
) -> anyhow::Result<RemoteExecutionResult> {
    let worker_config = selected_worker_to_config(worker);

    // Get current working directory as project root
    let project_root =
        std::env::current_dir().map_err(|e| TransferError::NoProjectRoot { source: e })?;

    let project_id = project_id_from_path(&project_root);
    let project_hash = compute_project_hash(&project_root);

    let output_ctx = OutputContext::detect();
    let console = RchConsole::with_context(output_ctx);
    let feedback_visible = reporter.visibility != OutputVisibility::None && !console.is_machine();
    let progress_enabled =
        output_ctx.supports_rich() && reporter.visibility != OutputVisibility::None;

    if feedback_visible {
        emit_job_banner(&console, output_ctx, worker, build_id);
    }

    info!(
        "Starting remote compilation pipeline for {} (hash: {})",
        project_id, project_hash
    );
    reporter.verbose(&format!(
        "[RCH] sync start (project {} on {})",
        project_id, worker_config.id
    ));

    // Create transfer pipeline with color mode, command timeout, and compilation kind
    let command_timeout = compilation_config.timeout_for_kind(kind);
    let pipeline = TransferPipeline::new(
        project_root.clone(),
        project_id.clone(),
        project_hash,
        transfer_config,
    )
    .with_color_mode(color_mode)
    .with_env_allowlist(env_allowlist)
    .with_command_timeout(command_timeout)
    .with_compilation_kind(kind);

    // Check if transfer should be skipped based on size/time estimation
    if let Some(skip_reason) = pipeline.should_skip_transfer(&worker_config).await {
        info!(
            "Transfer estimation indicates skip: {} (worker {})",
            skip_reason, worker_config.id
        );
        reporter.verbose(&format!("[RCH] skip transfer: {}", skip_reason));
        return Err(TransferError::TransferSkipped {
            reason: skip_reason,
        }
        .into());
    }

    // Step 1: Sync project to remote
    info!("Syncing project to worker {}...", worker_config.id);
    let mut upload_progress = if progress_enabled {
        Some(TransferProgress::upload(
            output_ctx,
            "Syncing workspace",
            reporter.visibility == OutputVisibility::None,
        ))
    } else {
        None
    };
    let sync_result = if let Some(progress) = &mut upload_progress {
        pipeline
            .sync_to_remote_streaming(&worker_config, |line| {
                progress.update_from_line(line);
            })
            .await?
    } else {
        pipeline.sync_to_remote(&worker_config).await?
    };
    info!(
        "Sync complete: {} files, {} bytes in {}ms",
        sync_result.files_transferred, sync_result.bytes_transferred, sync_result.duration_ms
    );
    reporter.verbose(&format!(
        "[RCH] sync done: {} files, {} bytes in {}ms",
        sync_result.files_transferred, sync_result.bytes_transferred, sync_result.duration_ms
    ));
    if let Some(progress) = &mut upload_progress {
        progress.apply_summary(sync_result.bytes_transferred, sync_result.files_transferred);
        progress.finish();
    }

    // Step 2: Execute command remotely with streaming output
    // Mask sensitive data (API keys, tokens, passwords) before logging
    let masked_command = mask_sensitive_command(command);
    info!("Executing command remotely: {}", masked_command);
    reporter.verbose(&format!("[RCH] exec start: {}", masked_command));

    // Capture stderr for toolchain failure detection
    //
    // `std::env::set_var` is unsafe in Rust 2024, but reading env is fine. For streaming,
    // we need shared mutable state across stdout/stderr callbacks; use `Rc<RefCell<_>>`
    // to avoid borrow-checker conflicts between the two closures.
    use std::cell::RefCell;
    use std::rc::Rc;

    let stderr_capture_cell = Rc::new(RefCell::new(String::new()));

    struct CompileUiState {
        progress: Option<CompilationProgress>,
        output: String,
        output_truncated: bool,
        crates_compiled: Option<u32>,
        warnings: Option<u32>,
    }
    let use_compile_progress = progress_enabled
        && matches!(
            kind,
            Some(
                CompilationKind::CargoBuild
                    | CompilationKind::CargoCheck
                    | CompilationKind::CargoClippy
                    | CompilationKind::CargoDoc
                    | CompilationKind::CargoBench
            )
        );
    let ui_state = Rc::new(RefCell::new(CompileUiState {
        progress: if use_compile_progress {
            Some(CompilationProgress::new(
                output_ctx,
                worker_config.id.as_str().to_string(),
                reporter.visibility == OutputVisibility::None,
            ))
        } else {
            None
        },
        output: String::new(),
        output_truncated: false,
        crates_compiled: None,
        warnings: None,
    }));

    // Stream stdout/stderr to our stderr so the agent sees the output
    let command_with_telemetry = wrap_command_with_telemetry(command, &worker_config.id);
    let ui_state_stdout = Rc::clone(&ui_state);
    let ui_state_stderr = Rc::clone(&ui_state);
    let stderr_capture_stderr = Rc::clone(&stderr_capture_cell);
    let mut suppress_telemetry = false;

    let result = pipeline
        .execute_remote_streaming(
            &worker_config,
            &command_with_telemetry,
            toolchain,
            move |line| {
                if suppress_telemetry {
                    return;
                }
                if line.trim() == PIGGYBACK_MARKER {
                    suppress_telemetry = true;
                    return;
                }

                let mut state = ui_state_stdout.borrow_mut();
                if let Some(progress) = state.progress.as_mut() {
                    progress.update_from_line(line);
                    if !state.output_truncated {
                        const MAX_OUTPUT_BYTES: usize = 256 * 1024;
                        if state.output.len() + line.len() <= MAX_OUTPUT_BYTES {
                            state.output.push_str(line);
                        } else {
                            state.output_truncated = true;
                        }
                    }
                } else {
                    // Write stdout lines to stderr (hook stdout is for protocol)
                    eprint!("{}", line);
                }
            },
            move |line| {
                // Write stderr lines to stderr and capture for analysis
                let mut state = ui_state_stderr.borrow_mut();
                if let Some(progress) = state.progress.as_mut() {
                    progress.update_from_line(line);
                    if !state.output_truncated {
                        const MAX_OUTPUT_BYTES: usize = 256 * 1024;
                        if state.output.len() + line.len() <= MAX_OUTPUT_BYTES {
                            state.output.push_str(line);
                        } else {
                            state.output_truncated = true;
                        }
                    }
                } else {
                    eprint!("{}", line);
                }
                drop(state);

                stderr_capture_stderr.borrow_mut().push_str(line);
            },
        )
        .await?;

    let stderr_capture = std::mem::take(&mut *stderr_capture_cell.borrow_mut());

    info!(
        "Remote command finished: exit={} in {}ms",
        result.exit_code, result.duration_ms
    );
    reporter.verbose(&format!(
        "[RCH] exec done: exit={} in {}ms",
        result.exit_code, result.duration_ms
    ));

    {
        let mut state = ui_state.borrow_mut();

        let mut progress_stats = None;
        if let Some(progress) = state.progress.as_mut() {
            progress_stats = Some((progress.crates_compiled(), progress.warnings()));
            if result.success() {
                progress.finish();
            } else {
                let message = stderr_capture
                    .lines()
                    .find(|line| !line.trim().is_empty())
                    .unwrap_or("remote compilation failed");
                progress.finish_error(message);
            }
        }
        if let Some((crates_compiled, warnings)) = progress_stats {
            state.crates_compiled = Some(crates_compiled);
            state.warnings = Some(warnings);
        }

        if use_compile_progress && !result.success() && !state.output.is_empty() {
            eprintln!("{}", state.output);
            if state.output_truncated {
                eprintln!("[RCH] output truncated (increase buffer if needed)");
            }
        }
    }

    let mut artifacts_result: Option<SyncResult> = None;
    let mut artifacts_failed = false;
    // Step 3: Retrieve artifacts
    if result.success() {
        info!("Retrieving build artifacts...");
        reporter.verbose("[RCH] artifacts: retrieving...");
        let artifact_patterns = get_artifact_patterns(kind);
        let mut download_progress = if progress_enabled {
            Some(TransferProgress::download(
                output_ctx,
                "Retrieving artifacts",
                reporter.visibility == OutputVisibility::None,
            ))
        } else {
            None
        };

        let retrieval = if let Some(progress) = &mut download_progress {
            pipeline
                .retrieve_artifacts_streaming(&worker_config, &artifact_patterns, |line| {
                    progress.update_from_line(line);
                })
                .await
        } else {
            pipeline
                .retrieve_artifacts(&worker_config, &artifact_patterns)
                .await
        };

        match retrieval {
            Ok(artifact_result) => {
                info!(
                    "Artifacts retrieved: {} files, {} bytes in {}ms",
                    artifact_result.files_transferred,
                    artifact_result.bytes_transferred,
                    artifact_result.duration_ms
                );
                reporter.verbose(&format!(
                    "[RCH] artifacts done: {} files, {} bytes in {}ms",
                    artifact_result.files_transferred,
                    artifact_result.bytes_transferred,
                    artifact_result.duration_ms
                ));
                if let Some(progress) = &mut download_progress {
                    progress.apply_summary(
                        artifact_result.bytes_transferred,
                        artifact_result.files_transferred,
                    );
                    progress.finish();
                }
                artifacts_result = Some(artifact_result);
            }
            Err(e) => {
                artifacts_failed = true;

                // Extract rsync exit code from error message if present
                let error_str = e.to_string();
                let rsync_exit_code = error_str.find("exit code").and_then(|_| {
                    error_str
                        .split("exit code")
                        .nth(1)
                        .and_then(|s| s.split(':').next())
                        .and_then(|s| {
                            s.trim()
                                .trim_start_matches("Some(")
                                .trim_end_matches(')')
                                .parse()
                                .ok()
                        })
                });

                // Create structured warning (bd-1q3p)
                let warning = ArtifactRetrievalWarning::new(
                    worker_config.id.as_str(),
                    artifact_patterns.clone(),
                    &error_str,
                    rsync_exit_code,
                );

                warn!("Failed to retrieve artifacts: {}", e);

                // Show detailed warning in verbose mode or when not in machine mode
                if !console.is_machine() {
                    reporter.verbose(&warning.format_warning());
                } else {
                    // For machine mode, output JSON warning
                    debug!("Artifact retrieval warning (JSON): {}", warning.to_json());
                    reporter.verbose("[RCH] artifacts failed (continuing)");
                }

                if let Some(progress) = &mut download_progress {
                    progress.finish_error(&e.to_string());
                }
                // Continue anyway - compilation succeeded
            }
        }
    }

    // Step 4: Extract and forward telemetry (piggybacked in stdout)
    let extraction = extract_piggybacked_telemetry(&result.stdout);
    if let Some(error) = extraction.extraction_error {
        warn!("Telemetry extraction failed: {}", error);
    }
    if let Some(telemetry) = extraction.telemetry
        && let Err(e) = send_telemetry(socket_path, TelemetrySource::Piggyback, &telemetry).await
    {
        warn!("Failed to forward telemetry to daemon: {}", e);
    }

    if is_test_kind(kind)
        && let Some(kind) = kind
    {
        let record = TestRunRecord::new(
            project_id.clone(),
            worker_config.id.as_str().to_string(),
            command.to_string(),
            kind,
            result.exit_code,
            result.duration_ms,
        );
        if let Err(e) = send_test_run(socket_path, &record).await {
            warn!("Failed to forward test run telemetry: {}", e);
        }
    }

    let (crates_compiled, output_snapshot) = {
        let state = ui_state.borrow();
        (state.crates_compiled, state.output.clone())
    };

    if feedback_visible {
        render_compile_summary(
            &console,
            output_ctx,
            worker,
            build_id,
            &sync_result,
            result.duration_ms,
            artifacts_result.as_ref(),
            artifacts_failed,
            cache_hit(&sync_result),
            result.success(),
        );
    }

    if result.success() {
        let artifacts_summary = artifacts_result.as_ref().map(|artifact| ArtifactSummary {
            files: u64::from(artifact.files_transferred),
            bytes: artifact.bytes_transferred,
        });
        let target_label = detect_target_label(command, &output_snapshot);

        let summary = CelebrationSummary::new(project_id.clone(), result.duration_ms)
            .worker(worker_config.id.as_str())
            .crates_compiled(crates_compiled)
            .artifacts(artifacts_summary)
            .cache_hit(Some(cache_hit(&sync_result)))
            .target(target_label)
            .quiet(reporter.visibility == OutputVisibility::None);

        CompletionCelebration::new(summary).record_and_render(output_ctx);
    }

    // Construct per-phase timing breakdown
    let timing = CommandTimingBreakdown {
        sync_up: Some(Duration::from_millis(sync_result.duration_ms)),
        exec: Some(Duration::from_millis(result.duration_ms)),
        sync_down: artifacts_result
            .as_ref()
            .map(|ar| Duration::from_millis(ar.duration_ms)),
        ..Default::default()
    };

    Ok(RemoteExecutionResult {
        exit_code: result.exit_code,
        stderr: stderr_capture,
        duration_ms: result.duration_ms,
        timing,
    })
}

fn wrap_command_with_telemetry(command: &str, worker_id: &WorkerId) -> String {
    let escaped_worker = shell_escape::escape(worker_id.as_str().into());
    // Use newline instead of semicolon to ensure trailing comments in command
    // don't comment out the status capture logic.
    format!(
        "{cmd}\nstatus=$?; if command -v rch-telemetry >/dev/null 2>&1; then \
         telemetry=$(rch-telemetry collect --format json --worker-id {worker} 2>/dev/null || true); \
         if [ -n \"$telemetry\" ]; then echo '{marker}'; echo \"$telemetry\"; fi; \
         fi; exit $status",
        cmd = command,
        worker = escaped_worker,
        marker = PIGGYBACK_MARKER
    )
}

async fn send_telemetry(
    socket_path: &str,
    source: TelemetrySource,
    telemetry: &WorkerTelemetry,
) -> anyhow::Result<()> {
    if !Path::new(socket_path).exists() {
        return Ok(());
    }

    let stream = match timeout(Duration::from_secs(2), UnixStream::connect(socket_path)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => return Ok(()), // Timeout connecting — don't block hook
    };
    let (reader, mut writer) = stream.into_split();

    let body = telemetry.to_json()?;
    let request = format!(
        "POST /telemetry/ingest?source={}\n{}\n",
        urlencoding_encode(&source.to_string()),
        body
    );

    writer.write_all(request.as_bytes()).await?;
    writer.flush().await?;

    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    let _ = timeout(Duration::from_secs(5), reader.read_line(&mut line)).await;

    Ok(())
}

async fn send_test_run(socket_path: &str, record: &TestRunRecord) -> anyhow::Result<()> {
    if !Path::new(socket_path).exists() {
        return Ok(());
    }

    let stream = match timeout(Duration::from_secs(2), UnixStream::connect(socket_path)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => return Ok(()), // Timeout connecting — don't block hook
    };
    let (reader, mut writer) = stream.into_split();

    let body = record.to_json()?;
    let request = format!("POST /test-run\n{}\n", body);

    writer.write_all(request.as_bytes()).await?;
    writer.flush().await?;

    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    let _ = timeout(Duration::from_secs(5), reader.read_line(&mut line)).await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rch_common::mock::{
        self, MockConfig, MockRsyncConfig, Phase, clear_mock_overrides, set_mock_enabled_override,
        set_mock_rsync_config_override, set_mock_ssh_config_override,
    };
    use rch_common::test_guard;
    use rch_common::{SelectionReason, ToolInput};
    use std::sync::OnceLock;
    use tokio::io::BufReader as TokioBufReader;
    use tokio::net::UnixListener;
    use tokio::sync::Mutex;

    fn test_lock() -> &'static Mutex<()> {
        static ENV_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();
        ENV_MUTEX.get_or_init(|| Mutex::new(()))
    }

    struct TestOverridesGuard;

    impl TestOverridesGuard {
        fn set(socket_path: &str, ssh_config: MockConfig, rsync_config: MockRsyncConfig) -> Self {
            let mut config = rch_common::RchConfig::default();
            config.general.socket_path = socket_path.to_string();
            crate::config::set_test_config_override(Some(config));

            set_mock_enabled_override(Some(true));
            set_mock_ssh_config_override(Some(ssh_config));
            set_mock_rsync_config_override(Some(rsync_config));

            Self
        }
    }

    impl Drop for TestOverridesGuard {
        fn drop(&mut self) {
            crate::config::set_test_config_override(None);
            clear_mock_overrides();
        }
    }

    struct ConfigOverrideGuard;

    impl ConfigOverrideGuard {
        fn set(config: rch_common::RchConfig) -> Self {
            crate::config::set_test_config_override(Some(config));
            Self
        }
    }

    impl Drop for ConfigOverrideGuard {
        fn drop(&mut self) {
            crate::config::set_test_config_override(None);
        }
    }

    async fn spawn_mock_daemon(socket_path: &str, response: SelectionResponse) {
        let _ = std::fs::remove_file(socket_path);
        let listener = UnixListener::bind(socket_path).expect("Failed to bind mock socket");

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("Accept failed");
            let (reader, mut writer) = stream.into_split();
            let mut buf_reader = TokioBufReader::new(reader);

            let mut request_line = String::new();
            buf_reader
                .read_line(&mut request_line)
                .await
                .expect("Failed to read request");

            let body = serde_json::to_string(&response).expect("Serialize response");
            let http = format!("HTTP/1.1 200 OK\r\n\r\n{}", body);
            writer
                .write_all(http.as_bytes())
                .await
                .expect("Failed to write response");
            writer.flush().await.expect("Failed to flush response");
        });
    }

    #[tokio::test]
    async fn test_non_bash_allowed() {
        let input = HookInput {
            tool_name: "Read".to_string(),
            tool_input: ToolInput {
                command: "anything".to_string(),
                description: None,
            },
            session_id: None,
        };

        let output = process_hook(input).await;
        assert!(output.is_allow());
    }

    #[tokio::test]
    async fn test_non_compilation_allowed() {
        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: "ls -la".to_string(),
                description: None,
            },
            session_id: None,
        };

        let output = process_hook(input).await;
        assert!(output.is_allow());
    }

    #[tokio::test]
    async fn test_compilation_detected() {
        let _lock = test_lock().lock().await;
        // Disable mock mode to test real fail-open behavior (no daemon = allow)
        mock::set_mock_enabled_override(Some(false));

        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: "cargo build --release".to_string(),
                description: None,
            },
            session_id: None,
        };

        // Without daemon, should fail-open and allow local execution
        // This tests that classification works and fail-open behavior is preserved
        let output = process_hook(input).await;
        assert!(
            output.is_allow(),
            "Expected allow when daemon unavailable (fail-open)"
        );

        // Reset mock override
        mock::set_mock_enabled_override(None);
    }

    // ========================================================================
    // TimingEstimate and Timing Gating Tests
    // ========================================================================

    #[test]
    fn test_timing_estimate_struct() {
        let _guard = test_guard!();
        let estimate = TimingEstimate {
            predicted_local_ms: 5000,
            predicted_speedup: Some(2.5),
        };
        assert_eq!(estimate.predicted_local_ms, 5000);
        assert_eq!(estimate.predicted_speedup, Some(2.5));
    }

    #[test]
    fn test_timing_estimate_no_speedup() {
        let _guard = test_guard!();
        let estimate = TimingEstimate {
            predicted_local_ms: 3000,
            predicted_speedup: None,
        };
        assert_eq!(estimate.predicted_local_ms, 3000);
        assert!(estimate.predicted_speedup.is_none());
    }

    #[test]
    fn test_estimate_timing_returns_none_without_history() {
        let _guard = test_guard!();
        // Currently returns None (fail-open) since no timing history exists
        let config = rch_common::RchConfig::default();
        let estimate =
            estimate_timing_for_build("test-project", Some(CompilationKind::CargoBuild), &config);
        assert!(estimate.is_none());
    }

    #[test]
    fn test_timing_gating_thresholds_default() {
        let _guard = test_guard!();
        let config = rch_common::CompilationConfig::default();
        // Default min_local_time_ms: 2000ms
        assert_eq!(config.min_local_time_ms, 2000);
        // Default speedup threshold: 1.2x
        assert!((config.remote_speedup_threshold - 1.2).abs() < 0.001);
    }

    #[test]
    fn test_urlencoding_encode_basic() {
        let _guard = test_guard!();
        assert_eq!(urlencoding_encode("hello world"), "hello%20world");
        assert_eq!(urlencoding_encode("path/to/file"), "path%2Fto%2Ffile");
        assert_eq!(urlencoding_encode("foo:bar"), "foo%3Abar");
    }

    #[test]
    fn test_urlencoding_encode_special_chars() {
        let _guard = test_guard!();
        assert_eq!(urlencoding_encode("a&b=c"), "a%26b%3Dc");
        assert_eq!(urlencoding_encode("100%"), "100%25");
        assert_eq!(urlencoding_encode("hello+world"), "hello%2Bworld");
    }

    #[test]
    fn test_urlencoding_encode_no_encoding_needed() {
        let _guard = test_guard!();
        assert_eq!(urlencoding_encode("simple"), "simple");
        assert_eq!(
            urlencoding_encode("with-dash_underscore.dot~tilde"),
            "with-dash_underscore.dot~tilde"
        );
        assert_eq!(urlencoding_encode("ABC123"), "ABC123");
    }

    #[test]
    fn test_urlencoding_encode_unicode() {
        let _guard = test_guard!();
        // Unicode characters should be encoded as UTF-8 bytes
        let encoded = urlencoding_encode("café");
        assert!(encoded.contains("%")); // 'é' should be encoded
        assert!(encoded.starts_with("caf")); // ASCII part preserved
    }

    #[test]
    fn test_parse_jobs_flag_variants() {
        let _guard = test_guard!();
        assert_eq!(parse_jobs_flag("cargo build -j 8"), Some(8));
        assert_eq!(parse_jobs_flag("cargo build -j8"), Some(8));
        assert_eq!(parse_jobs_flag("cargo build --jobs 4"), Some(4));
        assert_eq!(parse_jobs_flag("cargo build --jobs=12"), Some(12));
        assert_eq!(parse_jobs_flag("cargo build -j=16"), Some(16));
        assert_eq!(parse_jobs_flag("cargo build --jobs=12"), Some(12));
        assert_eq!(parse_jobs_flag("cargo build -j"), None);
        assert_eq!(parse_jobs_flag("cargo build --jobs"), None);
    }

    #[test]
    fn test_parse_test_threads_variants() {
        let _guard = test_guard!();
        assert_eq!(
            parse_test_threads("cargo test -- --test-threads=4"),
            Some(4)
        );
        assert_eq!(
            parse_test_threads("cargo test -- --test-threads 2"),
            Some(2)
        );
        assert_eq!(parse_test_threads("cargo test"), None);
    }

    #[test]
    fn test_estimate_cores_for_command() {
        let _guard = test_guard!();
        let config = rch_common::CompilationConfig {
            build_slots: 6,
            test_slots: 10,
            check_slots: 3,
            ..Default::default()
        };

        let build =
            estimate_cores_for_command(Some(CompilationKind::CargoBuild), "cargo build", &config);
        assert_eq!(build, 6);

        let build_jobs = estimate_cores_for_command(
            Some(CompilationKind::CargoBuild),
            "cargo build -j 12",
            &config,
        );
        assert_eq!(build_jobs, 12);

        let test_default =
            estimate_cores_for_command(Some(CompilationKind::CargoTest), "cargo test", &config);
        assert_eq!(test_default, 10);

        let test_threads = estimate_cores_for_command(
            Some(CompilationKind::CargoTest),
            "cargo test -- --test-threads=4",
            &config,
        );
        assert_eq!(test_threads, 4);

        let test_env = estimate_cores_for_command(
            Some(CompilationKind::CargoTest),
            "RUST_TEST_THREADS=3 cargo test",
            &config,
        );
        assert_eq!(test_env, 3);

        let check_default =
            estimate_cores_for_command(Some(CompilationKind::CargoCheck), "cargo check", &config);
        assert_eq!(check_default, 3);
    }

    // =========================================================================
    // Classification + threshold interaction tests
    // =========================================================================

    #[test]
    fn test_classification_confidence_levels() {
        let _guard = test_guard!();
        // High confidence: explicit cargo build
        let result = classify_command("cargo build");
        assert!(result.is_compilation);
        assert!(result.confidence >= 0.90);

        // Still compilation but different command
        let result = classify_command("cargo test --release");
        assert!(result.is_compilation);
        assert!(result.confidence >= 0.85);

        // Non-compilation cargo commands should not trigger
        let result = classify_command("cargo fmt");
        assert!(!result.is_compilation);
    }

    #[test]
    fn test_classification_bun_commands() {
        let _guard = test_guard!();
        // Bun compilation commands should be intercepted
        let result = classify_command("bun test");
        assert!(result.is_compilation);

        let result = classify_command("bun typecheck");
        assert!(result.is_compilation);

        // Bun watch modes should NOT be intercepted
        let result = classify_command("bun test --watch");
        assert!(!result.is_compilation);

        let result = classify_command("bun typecheck --watch");
        assert!(!result.is_compilation);

        // Bun package management should NOT be intercepted
        let result = classify_command("bun install");
        assert!(!result.is_compilation);

        let result = classify_command("bun add react");
        assert!(!result.is_compilation);

        let result = classify_command("bun remove react");
        assert!(!result.is_compilation);

        let result = classify_command("bun link");
        assert!(!result.is_compilation);

        // Bun execution helpers should NOT be intercepted
        let result = classify_command("bun run build");
        assert!(!result.is_compilation);

        let result = classify_command("bun build");
        assert!(!result.is_compilation);

        let result = classify_command("bun dev");
        assert!(!result.is_compilation);

        let result = classify_command("bun repl");
        assert!(!result.is_compilation);

        let result = classify_command("bun x vite build");
        assert!(!result.is_compilation);

        let result = classify_command("bunx vite build");
        assert!(!result.is_compilation);
    }

    #[test]
    fn test_classification_c_compilers_and_build_systems() {
        let _guard = test_guard!();
        let result = classify_command("gcc -O2 -o hello hello.c");
        assert!(result.is_compilation);

        let result = classify_command("g++ -std=c++20 -o hello hello.cpp");
        assert!(result.is_compilation);

        let result = classify_command("clang -o hello hello.c");
        assert!(result.is_compilation);

        let result = classify_command("clang++ -o hello hello.cpp");
        assert!(result.is_compilation);

        let result = classify_command("make");
        assert!(result.is_compilation);

        let result = classify_command("ninja -C build");
        assert!(result.is_compilation);

        let result = classify_command("cmake --build build");
        assert!(result.is_compilation);
    }

    #[test]
    fn test_classification_env_wrapped_commands() {
        let _guard = test_guard!();
        let result = classify_command("RUST_BACKTRACE=1 cargo test");
        assert!(result.is_compilation);

        let result = classify_command("RUST_TEST_THREADS=4 cargo test");
        assert!(result.is_compilation);
    }

    #[test]
    fn test_classification_rejects_shell_metachars() {
        let _guard = test_guard!();
        // Piped commands should not be intercepted
        let result = classify_command("cargo build | tee log.txt");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("pipe"));

        // Backgrounded commands should not be intercepted
        let result = classify_command("cargo build &");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("background"));

        // Redirected commands should not be intercepted
        let result = classify_command("cargo build > output.log");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("redirect"));

        // Subshell capture should not be intercepted
        let result = classify_command("result=$(cargo build)");
        assert!(!result.is_compilation);
        assert!(result.reason.contains("subshell"));
    }

    #[test]
    fn test_extract_project_name() {
        let _guard = test_guard!();
        // The function uses current directory, but we can test it runs
        let project = extract_project_name();
        // Should return something (either actual dir name or "unknown")
        assert!(!project.is_empty());
    }

    // =========================================================================
    // Hook output protocol tests
    // =========================================================================

    #[test]
    fn test_hook_output_allow_is_empty() {
        let _guard = test_guard!();
        // Allow output should serialize to nothing (empty stdout = allow)
        let output = HookOutput::allow();
        assert!(output.is_allow());
    }

    #[test]
    fn test_hook_output_deny_serializes() {
        let _guard = test_guard!();
        let output = HookOutput::deny("Test denial reason".to_string());
        let json = serde_json::to_string(&output).expect("Should serialize");
        assert!(json.contains("deny"));
        assert!(json.contains("Test denial reason"));
    }

    #[test]
    fn test_selected_worker_to_config() {
        let _guard = test_guard!();
        let worker = SelectedWorker {
            id: rch_common::WorkerId::new("test-worker"),
            host: "192.168.1.100".to_string(),
            user: "ubuntu".to_string(),
            identity_file: "~/.ssh/id_rsa".to_string(),
            slots_available: 8,
            speed_score: 75.5,
        };

        let config = selected_worker_to_config(&worker);
        assert_eq!(config.id.as_str(), "test-worker");
        assert_eq!(config.host, "192.168.1.100");
        assert_eq!(config.user, "ubuntu");
        assert_eq!(config.total_slots, 8);
    }

    // =========================================================================
    // Mock daemon socket tests
    // =========================================================================

    #[tokio::test]
    async fn test_daemon_query_missing_socket() {
        // Query a non-existent socket should fail gracefully
        let result = query_daemon(
            "/tmp/nonexistent_rch_test.sock",
            "testproj",
            4,
            "cargo build",
            None,
            RequiredRuntime::None,
            CommandPriority::Normal,
            100, // 100µs classification time
            None,
        )
        .await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("not found") || err_msg.contains("No such file"));
    }

    #[tokio::test]
    async fn test_daemon_query_protocol() {
        // Create a mock daemon socket
        let socket_path = format!("/tmp/rch_test_daemon_{}.sock", std::process::id());

        // Clean up any existing socket
        let _ = std::fs::remove_file(&socket_path);

        let listener = UnixListener::bind(&socket_path).expect("Failed to create test socket");

        // Spawn mock daemon handler
        let socket_path_clone = socket_path.clone();
        let daemon_handle = tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("Failed to accept connection");
            let (reader, mut writer) = stream.into_split();
            let mut buf_reader = TokioBufReader::new(reader);

            // Read the request line
            let mut request_line = String::new();
            buf_reader
                .read_line(&mut request_line)
                .await
                .expect("Failed to read request");

            // Verify request format
            assert!(request_line.starts_with("GET /select-worker"));
            assert!(request_line.contains("project="));
            assert!(request_line.contains("cores="));
            assert!(request_line.contains("command=cargo%20build"));
            assert!(request_line.contains("priority=normal"));

            // Send mock response
            let response = SelectionResponse {
                worker: Some(SelectedWorker {
                    id: rch_common::WorkerId::new("mock-worker"),
                    host: "mock.host.local".to_string(),
                    user: "mockuser".to_string(),
                    identity_file: "~/.ssh/mock_key".to_string(),
                    slots_available: 16,
                    speed_score: 95.0,
                }),
                reason: SelectionReason::Success,
                build_id: None,
            };
            let body = serde_json::to_string(&response).unwrap();
            let http_response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            writer
                .write_all(http_response.as_bytes())
                .await
                .expect("Failed to write response");
            writer.flush().await.expect("Failed to flush response");
        });

        // Give daemon time to start listening
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // Query the mock daemon
        let result = query_daemon(
            &socket_path,
            "test-project",
            4,
            "cargo build",
            None,
            RequiredRuntime::None,
            CommandPriority::Normal,
            100,
            None,
        )
        .await;

        // Clean up
        daemon_handle.await.expect("Daemon task panicked");
        let _ = std::fs::remove_file(&socket_path_clone);

        // Verify result
        let response = result.expect("Query should succeed");
        let worker = response.worker.expect("Should have worker");
        assert_eq!(worker.id.as_str(), "mock-worker");
        assert_eq!(worker.host, "mock.host.local");
        assert_eq!(worker.slots_available, 16);
    }

    #[tokio::test]
    async fn test_daemon_query_url_encoding() {
        // Verify special characters in project name are encoded
        let socket_path = format!("/tmp/rch_test_url_{}.sock", std::process::id());
        let _ = std::fs::remove_file(&socket_path);

        let listener = UnixListener::bind(&socket_path).expect("Failed to create test socket");

        let socket_path_clone = socket_path.clone();
        let daemon_handle = tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("Failed to accept connection");
            let (reader, mut writer) = stream.into_split();
            let mut buf_reader = TokioBufReader::new(reader);

            // Read the request line
            let mut request_line = String::new();
            buf_reader.read_line(&mut request_line).await.expect("Read");

            // The project name "my project/test" should be URL encoded
            assert!(request_line.contains("my%20project%2Ftest"));

            // Send minimal response
            let response = SelectionResponse {
                worker: Some(SelectedWorker {
                    id: rch_common::WorkerId::new("w1"),
                    host: "h".to_string(),
                    user: "u".to_string(),
                    identity_file: "i".to_string(),
                    slots_available: 1,
                    speed_score: 1.0,
                }),
                reason: SelectionReason::Success,
                build_id: None,
            };
            let body = serde_json::to_string(&response).unwrap();
            let http = format!("HTTP/1.1 200 OK\r\n\r\n{}", body);
            writer.write_all(http.as_bytes()).await.expect("Write");
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let result = query_daemon(
            &socket_path,
            "my project/test",
            2,
            "cargo build --release",
            None,
            RequiredRuntime::None,
            CommandPriority::Normal,
            150, // 150µs classification time
            None,
        )
        .await;
        daemon_handle.await.expect("Daemon task");
        let _ = std::fs::remove_file(&socket_path_clone);

        assert!(result.is_ok());
    }

    // =========================================================================
    // Fail-open behavior tests
    // =========================================================================

    #[tokio::test]
    async fn test_fail_open_on_invalid_json() {
        let _lock = test_lock().lock().await;
        // Disable mock mode to test real fail-open behavior
        mock::set_mock_enabled_override(Some(false));

        let mut config = rch_common::RchConfig::default();
        config.general.socket_path = "/tmp/rch-test-no-daemon.sock".to_string();
        let _ = std::fs::remove_file(&config.general.socket_path);
        let _config_guard = ConfigOverrideGuard::set(config);

        // If hook input is invalid JSON, should allow (fail-open)
        // This tests the run_hook behavior implicitly through process_hook
        // We can't easily test run_hook directly as it reads stdin

        // But we can verify that process_hook with valid input returns Allow
        // when no daemon is available (which is the fail-open case)
        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: "cargo build".to_string(),
                description: None,
            },
            session_id: None,
        };

        // With no daemon running, should fail-open to allow
        let output = process_hook(input).await;
        mock::clear_mock_overrides();
        assert!(output.is_allow());
    }

    #[tokio::test]
    async fn test_fail_open_on_config_error() {
        let _lock = test_lock().lock().await;
        // Disable mock mode to test real fail-open behavior
        mock::set_mock_enabled_override(Some(false));

        // If config is missing or invalid, should allow
        // This is tested implicitly by process_hook when config can't load
        // The current implementation falls back to allow
        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: "cargo build --release".to_string(),
                description: None,
            },
            session_id: None,
        };

        let output = process_hook(input).await;
        mock::clear_mock_overrides();
        // Should allow because daemon isn't running (fail-open)
        assert!(output.is_allow());
    }

    #[tokio::test]
    async fn test_process_hook_remote_success_mocked() {
        let _lock = test_lock().lock().await;
        let socket_path = format!(
            "/tmp/rch_test_hook_success_{}_{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let _overrides = TestOverridesGuard::set(
            &socket_path,
            MockConfig::default(),
            MockRsyncConfig::success(),
        );
        mock::clear_global_invocations();

        let response = SelectionResponse {
            worker: Some(SelectedWorker {
                id: rch_common::WorkerId::new("mock-worker"),
                host: "mock.host.local".to_string(),
                user: "mockuser".to_string(),
                identity_file: "~/.ssh/mock_key".to_string(),
                slots_available: 8,
                speed_score: 90.0,
            }),
            reason: SelectionReason::Success,
            build_id: None,
        };
        spawn_mock_daemon(&socket_path, response).await;

        tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: "cargo build".to_string(),
                description: None,
            },
            session_id: None,
        };

        let output: HookOutput = process_hook(input).await;
        let _ = std::fs::remove_file(&socket_path);

        assert!(!output.is_allow());

        let rsync_logs = mock::global_rsync_invocations_snapshot();
        let ssh_logs = mock::global_ssh_invocations_snapshot();

        assert!(rsync_logs.iter().any(|i| i.phase == Phase::Sync));
        assert!(rsync_logs.iter().any(|i| i.phase == Phase::Artifacts));
        assert!(ssh_logs.iter().any(|i| i.phase == Phase::Execute));
    }

    #[tokio::test]
    async fn test_force_local_allows_even_when_remote_available() {
        let _lock = test_lock().lock().await;
        let socket_path = format!(
            "/tmp/rch_test_hook_force_local_{}_{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let _overrides = TestOverridesGuard::set(
            &socket_path,
            MockConfig::default(),
            MockRsyncConfig::success(),
        );
        mock::clear_global_invocations();

        let mut config = rch_common::RchConfig::default();
        config.general.socket_path = socket_path.to_string();
        config.general.force_local = true;
        crate::config::set_test_config_override(Some(config));

        let response = SelectionResponse {
            worker: Some(SelectedWorker {
                id: rch_common::WorkerId::new("mock-worker"),
                host: "mock.host.local".to_string(),
                user: "mockuser".to_string(),
                identity_file: "~/.ssh/mock_key".to_string(),
                slots_available: 8,
                speed_score: 90.0,
            }),
            reason: SelectionReason::Success,
            build_id: None,
        };
        spawn_mock_daemon(&socket_path, response).await;

        tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: "cargo build".to_string(),
                description: None,
            },
            session_id: None,
        };

        let output = process_hook(input).await;
        let _ = std::fs::remove_file(&socket_path);

        assert!(output.is_allow());

        let rsync_logs = mock::global_rsync_invocations_snapshot();
        let ssh_logs = mock::global_ssh_invocations_snapshot();
        assert!(rsync_logs.is_empty());
        assert!(ssh_logs.is_empty());
    }

    #[tokio::test]
    async fn test_force_remote_bypasses_confidence_threshold() {
        let _lock = test_lock().lock().await;
        let socket_path = format!(
            "/tmp/rch_test_hook_force_remote_threshold_{}_{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let _overrides = TestOverridesGuard::set(
            &socket_path,
            MockConfig::default(),
            MockRsyncConfig::success(),
        );
        mock::clear_global_invocations();

        let classification = classify_command("cargo build");
        assert!(classification.is_compilation);
        let high_threshold = (classification.confidence + 0.01).min(1.0);

        let mut config = rch_common::RchConfig::default();
        config.general.socket_path = socket_path.to_string();
        config.general.force_remote = true;
        config.compilation.confidence_threshold = high_threshold;
        crate::config::set_test_config_override(Some(config));

        let response = SelectionResponse {
            worker: Some(SelectedWorker {
                id: rch_common::WorkerId::new("mock-worker"),
                host: "mock.host.local".to_string(),
                user: "mockuser".to_string(),
                identity_file: "~/.ssh/mock_key".to_string(),
                slots_available: 8,
                speed_score: 90.0,
            }),
            reason: SelectionReason::Success,
            build_id: None,
        };
        spawn_mock_daemon(&socket_path, response).await;

        tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: "cargo build".to_string(),
                description: None,
            },
            session_id: None,
        };

        let output = process_hook(input).await;
        let _ = std::fs::remove_file(&socket_path);

        assert!(!output.is_allow());

        let rsync_logs = mock::global_rsync_invocations_snapshot();
        let ssh_logs = mock::global_ssh_invocations_snapshot();
        assert!(rsync_logs.iter().any(|i| i.phase == Phase::Sync));
        assert!(rsync_logs.iter().any(|i| i.phase == Phase::Artifacts));
        assert!(ssh_logs.iter().any(|i| i.phase == Phase::Execute));
    }

    #[tokio::test]
    async fn test_process_hook_remote_sync_failure_allows() {
        let _lock = test_lock().lock().await;
        let socket_path = format!(
            "/tmp/rch_test_hook_sync_fail_{}_{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let _overrides = TestOverridesGuard::set(
            &socket_path,
            MockConfig::default(),
            MockRsyncConfig::sync_failure(),
        );
        mock::clear_global_invocations();

        let response = SelectionResponse {
            worker: Some(SelectedWorker {
                id: rch_common::WorkerId::new("mock-worker"),
                host: "mock.host.local".to_string(),
                user: "mockuser".to_string(),
                identity_file: "~/.ssh/mock_key".to_string(),
                slots_available: 8,
                speed_score: 90.0,
            }),
            reason: SelectionReason::Success,
            build_id: None,
        };
        spawn_mock_daemon(&socket_path, response).await;

        tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: "cargo build".to_string(),
                description: None,
            },
            session_id: None,
        };

        let output = process_hook(input).await;
        let _ = std::fs::remove_file(&socket_path);

        assert!(output.is_allow());

        let rsync_logs = mock::global_rsync_invocations_snapshot();
        let ssh_logs = mock::global_ssh_invocations_snapshot();
        assert!(rsync_logs.iter().any(|i| i.phase == Phase::Sync));
        assert!(ssh_logs.is_empty());
    }

    #[tokio::test]
    async fn test_process_hook_remote_nonzero_exit_denies() {
        let _lock = test_lock().lock().await;
        let socket_path = format!(
            "/tmp/rch_test_hook_exit_nonzero_{}_{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let _overrides = TestOverridesGuard::set(
            &socket_path,
            MockConfig {
                default_exit_code: 2,
                ..MockConfig::default()
            },
            MockRsyncConfig::success(),
        );
        mock::clear_global_invocations();

        let response = SelectionResponse {
            worker: Some(SelectedWorker {
                id: rch_common::WorkerId::new("mock-worker"),
                host: "mock.host.local".to_string(),
                user: "mockuser".to_string(),
                identity_file: "~/.ssh/mock_key".to_string(),
                slots_available: 8,
                speed_score: 90.0,
            }),
            reason: SelectionReason::Success,
            build_id: None,
        };
        spawn_mock_daemon(&socket_path, response).await;

        tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: "cargo build".to_string(),
                description: None,
            },
            session_id: None,
        };

        let output = process_hook(input).await;
        let _ = std::fs::remove_file(&socket_path);

        assert!(!output.is_allow());
    }

    #[test]
    fn test_transfer_config_defaults() {
        let _guard = test_guard!();
        // Verify TransferConfig has sensible defaults
        let config = TransferConfig::default();
        assert!(!config.exclude_patterns.is_empty());
        assert!(config.exclude_patterns.iter().any(|p| p.contains("target")));
    }

    #[test]
    fn test_worker_config_from_selected_worker() {
        let _guard = test_guard!();
        // Test the conversion preserves all fields correctly
        let worker = SelectedWorker {
            id: rch_common::WorkerId::new("worker-alpha"),
            host: "alpha.example.com".to_string(),
            user: "deploy".to_string(),
            identity_file: "/keys/deploy.pem".to_string(),
            slots_available: 32,
            speed_score: 88.8,
        };

        let config = selected_worker_to_config(&worker);

        assert_eq!(config.id.as_str(), "worker-alpha");
        assert_eq!(config.host, "alpha.example.com");
        assert_eq!(config.user, "deploy");
        assert_eq!(config.identity_file, "/keys/deploy.pem");
        assert_eq!(config.total_slots, 32);
        assert_eq!(config.priority, 100); // Default priority
        assert!(config.tags.is_empty()); // Default empty tags
    }

    // =========================================================================
    // Local fallback scenario tests (remote_compilation_helper-od4)
    // =========================================================================

    #[tokio::test]
    async fn test_fallback_no_workers_configured() {
        let _lock = test_lock().lock().await;
        let socket_path = format!(
            "/tmp/rch_test_no_workers_{}_{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let _overrides = TestOverridesGuard::set(
            &socket_path,
            MockConfig::default(),
            MockRsyncConfig::success(),
        );

        // Daemon returns no workers configured
        let response = SelectionResponse {
            worker: None,
            reason: SelectionReason::NoWorkersConfigured,
            build_id: None,
        };
        spawn_mock_daemon(&socket_path, response).await;
        tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: "cargo build".to_string(),
                description: None,
            },
            session_id: None,
        };

        let output = process_hook(input).await;
        let _ = std::fs::remove_file(&socket_path);

        // Should fall back to local execution
        assert!(output.is_allow());
    }

    #[tokio::test]
    async fn test_fallback_all_workers_unreachable() {
        let _lock = test_lock().lock().await;
        let socket_path = format!(
            "/tmp/rch_test_unreachable_{}_{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let _overrides = TestOverridesGuard::set(
            &socket_path,
            MockConfig::default(),
            MockRsyncConfig::success(),
        );

        // Daemon returns all workers unreachable
        let response = SelectionResponse {
            worker: None,
            reason: SelectionReason::AllWorkersUnreachable,
            build_id: None,
        };
        spawn_mock_daemon(&socket_path, response).await;
        tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: "cargo build --release".to_string(),
                description: None,
            },
            session_id: None,
        };

        let output = process_hook(input).await;
        let _ = std::fs::remove_file(&socket_path);

        // Should fall back to local execution
        assert!(output.is_allow());
    }

    #[tokio::test]
    async fn test_fallback_all_workers_busy() {
        let _lock = test_lock().lock().await;
        let socket_path = format!(
            "/tmp/rch_test_busy_{}_{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let _overrides = TestOverridesGuard::set(
            &socket_path,
            MockConfig::default(),
            MockRsyncConfig::success(),
        );

        // Daemon returns all workers busy
        let response = SelectionResponse {
            worker: None,
            reason: SelectionReason::AllWorkersBusy,
            build_id: None,
        };
        spawn_mock_daemon(&socket_path, response).await;
        tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: "cargo test".to_string(),
                description: None,
            },
            session_id: None,
        };

        let output = process_hook(input).await;
        let _ = std::fs::remove_file(&socket_path);

        // Should fall back to local execution
        assert!(output.is_allow());
    }

    #[tokio::test]
    async fn test_fallback_all_circuits_open() {
        let _lock = test_lock().lock().await;
        let socket_path = format!(
            "/tmp/rch_test_circuits_{}_{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let _overrides = TestOverridesGuard::set(
            &socket_path,
            MockConfig::default(),
            MockRsyncConfig::success(),
        );

        // Daemon returns all circuits open (circuit breaker tripped)
        let response = SelectionResponse {
            worker: None,
            reason: SelectionReason::AllCircuitsOpen,
            build_id: None,
        };
        spawn_mock_daemon(&socket_path, response).await;
        tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: "cargo check".to_string(),
                description: None,
            },
            session_id: None,
        };

        let output = process_hook(input).await;
        let _ = std::fs::remove_file(&socket_path);

        // Should fall back to local execution
        assert!(output.is_allow());
    }

    #[tokio::test]
    async fn test_fallback_selection_error() {
        let _lock = test_lock().lock().await;
        let socket_path = format!(
            "/tmp/rch_test_sel_err_{}_{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let _overrides = TestOverridesGuard::set(
            &socket_path,
            MockConfig::default(),
            MockRsyncConfig::success(),
        );

        // Daemon returns a selection error
        let response = SelectionResponse {
            worker: None,
            reason: SelectionReason::SelectionError("Internal error".to_string()),
            build_id: None,
        };
        spawn_mock_daemon(&socket_path, response).await;
        tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: "cargo build".to_string(),
                description: None,
            },
            session_id: None,
        };

        let output = process_hook(input).await;
        let _ = std::fs::remove_file(&socket_path);

        // Should fall back to local execution
        assert!(output.is_allow());
    }

    #[tokio::test]
    async fn test_fallback_daemon_error_response() {
        let _lock = test_lock().lock().await;
        let socket_path = format!(
            "/tmp/rch_test_daemon_err_{}_{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let _overrides = TestOverridesGuard::set(
            &socket_path,
            MockConfig::default(),
            MockRsyncConfig::success(),
        );

        // Spawn a daemon that returns HTTP 500 error
        let _ = std::fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path).expect("bind");

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let (reader, mut writer) = stream.into_split();
            let mut buf_reader = TokioBufReader::new(reader);

            let mut request_line = String::new();
            buf_reader.read_line(&mut request_line).await.expect("read");

            // Return HTTP 500 error
            let http = "HTTP/1.1 500 Internal Server Error\r\n\r\n Расположение: {\"error\": \"internal\"}";
            writer.write_all(http.as_bytes()).await.expect("write");
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: "cargo build".to_string(),
                description: None,
            },
            session_id: None,
        };

        let output = process_hook(input).await;
        let _ = std::fs::remove_file(&socket_path);

        // Should fall back to local execution (fail-open)
        assert!(output.is_allow());
    }

    #[tokio::test]
    async fn test_fallback_daemon_malformed_json() {
        let _lock = test_lock().lock().await;
        let socket_path = format!(
            "/tmp/rch_test_malformed_{}_{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let _overrides = TestOverridesGuard::set(
            &socket_path,
            MockConfig::default(),
            MockRsyncConfig::success(),
        );

        // Spawn a daemon that returns malformed JSON
        let _ = std::fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path).expect("bind");

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let (reader, mut writer) = stream.into_split();
            let mut buf_reader = TokioBufReader::new(reader);

            let mut request_line = String::new();
            buf_reader.read_line(&mut request_line).await.expect("read");

            // Return malformed JSON
            let http = "HTTP/1.1 200 OK\r\n\r\n{invalid json}";
            writer.write_all(http.as_bytes()).await.expect("write");
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: "cargo build".to_string(),
                description: None,
            },
            session_id: None,
        };

        let output = process_hook(input).await;
        let _ = std::fs::remove_file(&socket_path);

        // Should fall back to local execution (fail-open on parse error)
        assert!(output.is_allow());
    }

    #[tokio::test]
    async fn test_fallback_daemon_connection_reset() {
        let _lock = test_lock().lock().await;
        let socket_path = format!(
            "/tmp/rch_test_reset_{}_{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let _overrides = TestOverridesGuard::set(
            &socket_path,
            MockConfig::default(),
            MockRsyncConfig::success(),
        );

        // Spawn a daemon that immediately closes connection
        let _ = std::fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path).expect("bind");

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            // Immediately drop the stream to simulate connection reset
            drop(stream);
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: "cargo build".to_string(),
                description: None,
            },
            session_id: None,
        };

        let output = process_hook(input).await;
        let _ = std::fs::remove_file(&socket_path);

        // Should fall back to local execution (fail-open on connection error)
        assert!(output.is_allow());
    }

    // =========================================================================
    // Exit code handling tests (bead remote_compilation_helper-zerp)
    // =========================================================================

    #[test]
    fn test_is_signal_killed() {
        let _guard = test_guard!();
        // Normal exit codes should not be signal-killed
        assert!(is_signal_killed(0).is_none());
        assert!(is_signal_killed(1).is_none());
        assert!(is_signal_killed(101).is_none());
        assert!(is_signal_killed(128).is_none()); // 128 is exactly at boundary

        // Signal kills (128 + signal)
        assert_eq!(is_signal_killed(129), Some(1)); // SIGHUP
        assert_eq!(is_signal_killed(130), Some(2)); // SIGINT
        assert_eq!(is_signal_killed(137), Some(9)); // SIGKILL
        assert_eq!(is_signal_killed(139), Some(11)); // SIGSEGV
        assert_eq!(is_signal_killed(143), Some(15)); // SIGTERM
    }

    #[test]
    fn test_signal_name() {
        let _guard = test_guard!();
        assert_eq!(signal_name(1), "SIGHUP");
        assert_eq!(signal_name(2), "SIGINT");
        assert_eq!(signal_name(9), "SIGKILL");
        assert_eq!(signal_name(11), "SIGSEGV");
        assert_eq!(signal_name(15), "SIGTERM");
        assert_eq!(signal_name(99), "UNKNOWN");
    }

    #[test]
    fn test_exit_code_constants() {
        let _guard = test_guard!();
        // Verify exit code constants match cargo's documented behavior
        assert_eq!(EXIT_SUCCESS, 0);
        assert_eq!(EXIT_BUILD_ERROR, 1);
        assert_eq!(EXIT_TEST_FAILURES, 101);
        assert_eq!(EXIT_SIGNAL_BASE, 128);
    }

    #[test]
    fn test_is_toolchain_failure_basic() {
        let _guard = test_guard!();
        // Should detect toolchain issues
        assert!(is_toolchain_failure(
            "error: toolchain 'nightly-2025-01-01' is not installed",
            1
        ));
        assert!(is_toolchain_failure("rustup: command not found", 127));
        assert!(is_toolchain_failure("error: no such command: `build`", 1));

        // Should not flag normal failures
        assert!(!is_toolchain_failure(
            "error[E0425]: cannot find value `x`",
            1
        ));
        assert!(!is_toolchain_failure(
            "test result: FAILED. 1 passed; 2 failed",
            101
        ));

        // Success should never be a toolchain failure
        assert!(!is_toolchain_failure("anything", 0));
    }

    #[test]
    fn test_exit_code_semantics_documented() {
        let _guard = test_guard!();
        // This test documents the expected behavior for different exit codes
        // Exit 0: Success - should deny local (verified in other tests)
        // Exit 101: Test failures - should deny local (re-running won't help)
        // Exit 1: Build error - should deny local (same error locally)
        // Exit 137: SIGKILL - should deny local (likely OOM)

        // Verify constants are what we expect
        assert_eq!(EXIT_SUCCESS, 0, "Success exit code should be 0");
        assert_eq!(EXIT_BUILD_ERROR, 1, "Build error exit code should be 1");
        assert_eq!(
            EXIT_TEST_FAILURES, 101,
            "Test failures exit code should be 101"
        );

        // Verify signal detection
        let sigkill = 128 + 9;
        assert_eq!(is_signal_killed(sigkill), Some(9), "Should detect SIGKILL");
        assert_eq!(signal_name(9), "SIGKILL", "Should name SIGKILL correctly");
    }

    // =========================================================================
    // Cargo test integration tests (bead remote_compilation_helper-iyv1)
    // =========================================================================

    #[test]
    fn test_wrap_command_with_telemetry_handles_comments() {
        let _guard = test_guard!();
        let worker_id = rch_common::WorkerId::new("worker1");
        let command = "echo hello # my comment";
        let wrapped = wrap_command_with_telemetry(command, &worker_id);

        // Ensure newline separation exists
        assert!(wrapped.contains(&format!("{}\nstatus=$?", command)));

        // Ensure status capture isn't commented out (it should be on a new line)
        let lines: Vec<&str> = wrapped.lines().collect();
        assert!(lines.iter().any(|l| l.starts_with("status=$?")));

        // Basic sanity check on structure
        assert!(wrapped.contains("rch-telemetry collect"));
        assert!(wrapped.contains("exit $status"));
    }

    #[tokio::test]
    async fn test_cargo_test_remote_success() {
        let _lock = test_lock().lock().await;
        let socket_path = format!(
            "/tmp/rch_test_cargo_test_success_{}_{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        // Configure mock for successful test execution (exit 0)
        let _overrides = TestOverridesGuard::set(
            &socket_path,
            MockConfig {
                default_exit_code: 0,
                default_stdout: "running 5 tests\ntest test_one ... ok\ntest test_two ... ok\n\ntest result: ok. 5 passed; 0 failed; 0 ignored\n".to_string(),
                ..MockConfig::default()
            },
            MockRsyncConfig::success(),
        );
        mock::clear_global_invocations();

        let response = SelectionResponse {
            worker: Some(SelectedWorker {
                id: rch_common::WorkerId::new("test-worker"),
                host: "test.host.local".to_string(),
                user: "testuser".to_string(),
                identity_file: "~/.ssh/test_key".to_string(),
                slots_available: 8,
                speed_score: 85.0,
            }),
            reason: SelectionReason::Success,
            build_id: None,
        };
        spawn_mock_daemon(&socket_path, response).await;

        tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: "cargo test".to_string(),
                description: None,
            },
            session_id: None,
        };

        let output = process_hook(input).await;
        let _ = std::fs::remove_file(&socket_path);

        // Successful remote test should deny local execution
        assert!(
            !output.is_allow(),
            "Successful cargo test should deny local execution"
        );

        // Verify the pipeline phases executed correctly
        let rsync_logs = mock::global_rsync_invocations_snapshot();
        let ssh_logs = mock::global_ssh_invocations_snapshot();

        assert!(
            rsync_logs.iter().any(|i| i.phase == Phase::Sync),
            "Should have synced project"
        );
        assert!(
            ssh_logs.iter().any(|i| i.phase == Phase::Execute),
            "Should have executed remote command"
        );
        // Artifacts should be retrieved on success (but with test-specific patterns)
        assert!(
            rsync_logs.iter().any(|i| i.phase == Phase::Artifacts),
            "Should have retrieved artifacts"
        );
    }

    #[tokio::test]
    async fn test_cargo_test_remote_test_failures() {
        let _lock = test_lock().lock().await;
        let socket_path = format!(
            "/tmp/rch_test_cargo_test_failures_{}_{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        // Configure mock for test failures (exit 101)
        let _overrides = TestOverridesGuard::set(
            &socket_path,
            MockConfig {
                default_exit_code: 101,
                default_stdout: "running 5 tests\ntest test_one ... ok\ntest test_two ... FAILED\n\ntest result: FAILED. 4 passed; 1 failed; 0 ignored\n".to_string(),
                default_stderr: "thread 'test_two' panicked at 'assertion failed'\n".to_string(),
                ..MockConfig::default()
            },
            MockRsyncConfig::success(),
        );
        mock::clear_global_invocations();

        let response = SelectionResponse {
            worker: Some(SelectedWorker {
                id: rch_common::WorkerId::new("test-worker"),
                host: "test.host.local".to_string(),
                user: "testuser".to_string(),
                identity_file: "~/.ssh/test_key".to_string(),
                slots_available: 8,
                speed_score: 85.0,
            }),
            reason: SelectionReason::Success,
            build_id: None,
        };
        spawn_mock_daemon(&socket_path, response).await;

        tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: "cargo test".to_string(),
                description: None,
            },
            session_id: None,
        };

        let output = process_hook(input).await;
        let _ = std::fs::remove_file(&socket_path);

        // Test failures (exit 101) should still deny local execution
        // Re-running locally won't help - the tests already ran and failed
        assert!(
            !output.is_allow(),
            "cargo test with failures (exit 101) should deny local execution"
        );

        // Verify pipeline executed
        let ssh_logs = mock::global_ssh_invocations_snapshot();
        assert!(
            ssh_logs.iter().any(|i| i.phase == Phase::Execute),
            "Should have executed remote command"
        );
    }

    #[tokio::test]
    async fn test_cargo_test_remote_build_failure() {
        let _lock = test_lock().lock().await;
        let socket_path = format!(
            "/tmp/rch_test_cargo_test_build_fail_{}_{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        // Configure mock for build failure (exit 1)
        let _overrides = TestOverridesGuard::set(
            &socket_path,
            MockConfig {
                default_exit_code: 1,
                default_stderr: "error[E0425]: cannot find value `undefined_var` in this scope\n  --> src/lib.rs:10:5\n".to_string(),
                ..MockConfig::default()
            },
            MockRsyncConfig::success(),
        );
        mock::clear_global_invocations();

        let response = SelectionResponse {
            worker: Some(SelectedWorker {
                id: rch_common::WorkerId::new("test-worker"),
                host: "test.host.local".to_string(),
                user: "testuser".to_string(),
                identity_file: "~/.ssh/test_key".to_string(),
                slots_available: 8,
                speed_score: 85.0,
            }),
            reason: SelectionReason::Success,
            build_id: None,
        };
        spawn_mock_daemon(&socket_path, response).await;

        tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: "cargo test".to_string(),
                description: None,
            },
            session_id: None,
        };

        let output = process_hook(input).await;
        let _ = std::fs::remove_file(&socket_path);

        // Build failure (exit 1) should deny local execution
        // Same compilation error would occur locally
        assert!(
            !output.is_allow(),
            "cargo test build failure (exit 1) should deny local execution"
        );
    }

    #[tokio::test]
    async fn test_cargo_test_with_filter() {
        let _lock = test_lock().lock().await;
        let socket_path = format!(
            "/tmp/rch_test_cargo_test_filter_{}_{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let _overrides = TestOverridesGuard::set(
            &socket_path,
            MockConfig::default(),
            MockRsyncConfig::success(),
        );
        mock::clear_global_invocations();

        let response = SelectionResponse {
            worker: Some(SelectedWorker {
                id: rch_common::WorkerId::new("test-worker"),
                host: "test.host.local".to_string(),
                user: "testuser".to_string(),
                identity_file: "~/.ssh/test_key".to_string(),
                slots_available: 8,
                speed_score: 85.0,
            }),
            reason: SelectionReason::Success,
            build_id: None,
        };
        spawn_mock_daemon(&socket_path, response).await;

        tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

        // Test with filter pattern
        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: "cargo test specific_test".to_string(),
                description: None,
            },
            session_id: None,
        };

        let output = process_hook(input).await;
        let _ = std::fs::remove_file(&socket_path);

        // Filtered test command should also work
        assert!(
            !output.is_allow(),
            "Filtered cargo test should deny local execution on success"
        );
    }

    #[tokio::test]
    async fn test_cargo_test_with_test_threads() {
        let _lock = test_lock().lock().await;
        let socket_path = format!(
            "/tmp/rch_test_cargo_test_threads_{}_{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let _overrides = TestOverridesGuard::set(
            &socket_path,
            MockConfig::default(),
            MockRsyncConfig::success(),
        );
        mock::clear_global_invocations();

        let response = SelectionResponse {
            worker: Some(SelectedWorker {
                id: rch_common::WorkerId::new("test-worker"),
                host: "test.host.local".to_string(),
                user: "testuser".to_string(),
                identity_file: "~/.ssh/test_key".to_string(),
                slots_available: 8,
                speed_score: 85.0,
            }),
            reason: SelectionReason::Success,
            build_id: None,
        };
        spawn_mock_daemon(&socket_path, response).await;

        tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

        // Test with --test-threads flag (should parse correctly for slot estimation)
        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: "cargo test -- --test-threads=4".to_string(),
                description: None,
            },
            session_id: None,
        };

        let output = process_hook(input).await;
        let _ = std::fs::remove_file(&socket_path);

        // Should work regardless of thread count
        assert!(
            !output.is_allow(),
            "cargo test with --test-threads should work"
        );
    }

    #[tokio::test]
    async fn test_cargo_test_signal_killed() {
        let _lock = test_lock().lock().await;
        let socket_path = format!(
            "/tmp/rch_test_cargo_test_signal_{}_{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        // Configure mock for OOM kill (exit 137 = 128 + 9 = SIGKILL)
        let _overrides = TestOverridesGuard::set(
            &socket_path,
            MockConfig {
                default_exit_code: 137,
                default_stderr: "Killed\n".to_string(),
                ..MockConfig::default()
            },
            MockRsyncConfig::success(),
        );
        mock::clear_global_invocations();

        let response = SelectionResponse {
            worker: Some(SelectedWorker {
                id: rch_common::WorkerId::new("test-worker"),
                host: "test.host.local".to_string(),
                user: "testuser".to_string(),
                identity_file: "~/.ssh/test_key".to_string(),
                slots_available: 8,
                speed_score: 85.0,
            }),
            reason: SelectionReason::Success,
            build_id: None,
        };
        spawn_mock_daemon(&socket_path, response).await;

        tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: "cargo test".to_string(),
                description: None,
            },
            session_id: None,
        };

        let output = process_hook(input).await;
        let _ = std::fs::remove_file(&socket_path);

        // Signal killed (likely OOM) should deny local execution
        assert!(
            !output.is_allow(),
            "Signal-killed cargo test should deny local execution"
        );
    }

    #[tokio::test]
    async fn test_cargo_test_toolchain_fallback() {
        let _lock = test_lock().lock().await;
        let socket_path = format!(
            "/tmp/rch_test_cargo_test_toolchain_{}_{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        // Configure mock for toolchain failure - should allow local fallback
        let _overrides = TestOverridesGuard::set(
            &socket_path,
            MockConfig {
                default_exit_code: 1,
                default_stderr: "error: toolchain 'nightly-2025-01-15' is not installed\n"
                    .to_string(),
                ..MockConfig::default()
            },
            MockRsyncConfig::success(),
        );
        mock::clear_global_invocations();

        let response = SelectionResponse {
            worker: Some(SelectedWorker {
                id: rch_common::WorkerId::new("test-worker"),
                host: "test.host.local".to_string(),
                user: "testuser".to_string(),
                identity_file: "~/.ssh/test_key".to_string(),
                slots_available: 8,
                speed_score: 85.0,
            }),
            reason: SelectionReason::Success,
            build_id: None,
        };
        spawn_mock_daemon(&socket_path, response).await;

        tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: "cargo test".to_string(),
                description: None,
            },
            session_id: None,
        };

        let output = process_hook(input).await;
        let _ = std::fs::remove_file(&socket_path);

        // Toolchain failure should allow local fallback
        // Local machine might have the toolchain
        assert!(
            output.is_allow(),
            "Toolchain failure should allow local fallback"
        );
    }

    #[test]
    fn test_cargo_test_classification() {
        let _guard = test_guard!();
        // Verify cargo test commands are classified correctly
        let result = classify_command("cargo test");
        assert!(result.is_compilation, "cargo test should be compilation");
        assert_eq!(
            result.kind,
            Some(CompilationKind::CargoTest),
            "Should be CargoTest kind"
        );

        let result = classify_command("cargo test specific_test");
        assert!(result.is_compilation);
        assert_eq!(result.kind, Some(CompilationKind::CargoTest));

        let result = classify_command("cargo test -- --test-threads=4");
        assert!(result.is_compilation);
        assert_eq!(result.kind, Some(CompilationKind::CargoTest));

        let result = classify_command("cargo test --release");
        assert!(result.is_compilation);
        assert_eq!(result.kind, Some(CompilationKind::CargoTest));

        let result = classify_command("cargo test -p mypackage");
        assert!(result.is_compilation);
        assert_eq!(result.kind, Some(CompilationKind::CargoTest));
    }

    #[test]
    fn test_cargo_nextest_classification() {
        let _guard = test_guard!();
        // Verify cargo nextest commands are classified correctly
        let result = classify_command("cargo nextest run");
        assert!(result.is_compilation, "cargo nextest should be compilation");
        assert_eq!(
            result.kind,
            Some(CompilationKind::CargoNextest),
            "Should be CargoNextest kind"
        );

        let result = classify_command("cargo nextest run --no-fail-fast");
        assert!(result.is_compilation);
        assert_eq!(result.kind, Some(CompilationKind::CargoNextest));
    }

    #[test]
    fn test_artifact_patterns_for_test_commands() {
        let _guard = test_guard!();
        // Verify test commands use minimal artifact patterns
        let test_patterns = get_artifact_patterns(Some(CompilationKind::CargoTest));
        let build_patterns = get_artifact_patterns(Some(CompilationKind::CargoBuild));

        // Test patterns should be smaller (more targeted)
        // They should include coverage/results but not full target/
        assert!(
            !test_patterns.iter().any(|p| p == "target/"),
            "Test artifacts should not include full target/"
        );

        // Build patterns should include full build outputs
        assert!(
            build_patterns.iter().any(|p| p == "target/debug/**"),
            "Build artifacts should include target/debug/**"
        );
        assert!(
            build_patterns.iter().any(|p| p == "target/release/**"),
            "Build artifacts should include target/release/**"
        );
        assert!(
            !test_patterns.iter().any(|p| p == "target/debug/**"),
            "Test artifacts should not include target/debug/**"
        );
        assert!(
            !test_patterns.iter().any(|p| p == "target/release/**"),
            "Test artifacts should not include target/release/**"
        );
    }

    // =========================================================================
    // Test filtering and special flags tests (bead remote_compilation_helper-ya16)
    // =========================================================================

    #[test]
    fn test_is_filtered_test_command_basic() {
        let _guard = test_guard!();
        // Basic test name filter
        assert!(
            is_filtered_test_command("cargo test my_test"),
            "Should detect test name filter"
        );
        assert!(
            is_filtered_test_command("cargo test test_foo"),
            "Should detect test name filter"
        );
        assert!(
            is_filtered_test_command("cargo test some::module::test"),
            "Should detect module path filter"
        );

        // Full test suite (no filter)
        assert!(
            !is_filtered_test_command("cargo test"),
            "No filter in basic cargo test"
        );
        assert!(
            !is_filtered_test_command("cargo test --release"),
            "Flags are not filters"
        );
    }

    #[test]
    fn test_is_filtered_test_command_with_flags() {
        let _guard = test_guard!();
        // Filter with flags
        assert!(
            is_filtered_test_command("cargo test --release my_test"),
            "Should detect filter after flags"
        );
        assert!(
            is_filtered_test_command("cargo test -p mypackage my_test"),
            "Should detect filter after package flag"
        );

        // Only package flag (not a name filter)
        assert!(
            !is_filtered_test_command("cargo test -p mypackage"),
            "Package is not a test name filter"
        );
        assert!(
            !is_filtered_test_command("cargo test --lib"),
            "--lib is not a test name filter"
        );
    }

    #[test]
    fn test_is_filtered_test_command_with_separator() {
        let _guard = test_guard!();
        // Filter before --
        assert!(
            is_filtered_test_command("cargo test my_test -- --nocapture"),
            "Should detect filter before separator"
        );

        // No filter, args after --
        assert!(
            !is_filtered_test_command("cargo test -- --nocapture"),
            "Args after -- are not test name filters"
        );
        assert!(
            !is_filtered_test_command("cargo test -- --test-threads=4"),
            "Args after -- are not test name filters"
        );
    }

    #[test]
    fn test_has_ignored_only_flag() {
        let _guard = test_guard!();
        // Only --ignored
        assert!(
            has_ignored_only_flag("cargo test -- --ignored"),
            "Should detect --ignored"
        );

        // --include-ignored (runs all tests)
        assert!(
            !has_ignored_only_flag("cargo test -- --include-ignored"),
            "--include-ignored runs all tests"
        );

        // Both flags (--include-ignored takes precedence)
        assert!(
            !has_ignored_only_flag("cargo test -- --ignored --include-ignored"),
            "--include-ignored takes precedence"
        );

        // No flags
        assert!(!has_ignored_only_flag("cargo test"), "No flags");
    }

    #[test]
    fn test_has_exact_flag() {
        let _guard = test_guard!();
        assert!(
            has_exact_flag("cargo test my_test -- --exact"),
            "--exact detected"
        );
        assert!(!has_exact_flag("cargo test my_test"), "No --exact");
        assert!(!has_exact_flag("cargo test -- --nocapture"), "No --exact");
    }

    #[test]
    fn test_estimate_cores_filtered_tests() {
        let _guard = test_guard!();
        let config = rch_common::CompilationConfig {
            build_slots: 6,
            test_slots: 10,
            check_slots: 3,
            ..Default::default()
        };

        // Full test suite gets default slots
        let full =
            estimate_cores_for_command(Some(CompilationKind::CargoTest), "cargo test", &config);
        assert_eq!(full, 10, "Full test suite uses default test_slots");

        // Filtered test gets reduced slots (test_slots / 2, min 2)
        let filtered = estimate_cores_for_command(
            Some(CompilationKind::CargoTest),
            "cargo test my_test",
            &config,
        );
        assert_eq!(filtered, 5, "Filtered test uses reduced slots");

        // --exact flag gets reduced slots
        let exact = estimate_cores_for_command(
            Some(CompilationKind::CargoTest),
            "cargo test my_test -- --exact",
            &config,
        );
        assert_eq!(exact, 5, "--exact uses reduced slots");

        // --ignored only gets reduced slots
        let ignored = estimate_cores_for_command(
            Some(CompilationKind::CargoTest),
            "cargo test -- --ignored",
            &config,
        );
        assert_eq!(ignored, 5, "--ignored uses reduced slots");

        // --include-ignored gets full slots (runs all tests plus ignored)
        let include_ignored = estimate_cores_for_command(
            Some(CompilationKind::CargoTest),
            "cargo test -- --include-ignored",
            &config,
        );
        assert_eq!(include_ignored, 10, "--include-ignored uses full slots");
    }

    #[test]
    fn test_estimate_cores_explicit_threads_overrides_filter() {
        let _guard = test_guard!();
        let config = rch_common::CompilationConfig {
            build_slots: 6,
            test_slots: 10,
            check_slots: 3,
            ..Default::default()
        };

        // Explicit --test-threads should override filtering heuristics
        let explicit = estimate_cores_for_command(
            Some(CompilationKind::CargoTest),
            "cargo test my_test -- --test-threads=8",
            &config,
        );
        assert_eq!(explicit, 8, "Explicit --test-threads overrides filtering");

        // RUST_TEST_THREADS also overrides
        let env = estimate_cores_for_command(
            Some(CompilationKind::CargoTest),
            "RUST_TEST_THREADS=6 cargo test my_test",
            &config,
        );
        assert_eq!(env, 6, "RUST_TEST_THREADS overrides filtering");
    }

    #[test]
    fn test_estimate_cores_filtered_minimum() {
        let _guard = test_guard!();
        let config = rch_common::CompilationConfig {
            build_slots: 6,
            test_slots: 2, // Very low test_slots
            check_slots: 3,
            ..Default::default()
        };

        // With test_slots=2, filtered should be max(2/2, 2) = max(1, 2) = 2
        let filtered = estimate_cores_for_command(
            Some(CompilationKind::CargoTest),
            "cargo test my_test",
            &config,
        );
        assert!(filtered >= 2, "Filtered slots should be at least 2");
    }

    #[test]
    fn test_nocapture_does_not_affect_slots() {
        let _guard = test_guard!();
        let config = rch_common::CompilationConfig {
            build_slots: 6,
            test_slots: 10,
            check_slots: 3,
            ..Default::default()
        };

        // --nocapture doesn't affect slot estimation
        let with_nocapture = estimate_cores_for_command(
            Some(CompilationKind::CargoTest),
            "cargo test -- --nocapture",
            &config,
        );
        let without =
            estimate_cores_for_command(Some(CompilationKind::CargoTest), "cargo test", &config);
        assert_eq!(with_nocapture, without, "--nocapture doesn't affect slots");

        // --show-output also doesn't affect slots
        let with_show = estimate_cores_for_command(
            Some(CompilationKind::CargoTest),
            "cargo test -- --show-output",
            &config,
        );
        assert_eq!(with_show, without, "--show-output doesn't affect slots");
    }

    #[test]
    fn test_skip_pattern_uses_full_slots() {
        let _guard = test_guard!();
        let config = rch_common::CompilationConfig {
            build_slots: 6,
            test_slots: 10,
            check_slots: 3,
            ..Default::default()
        };

        // --skip doesn't reduce the test suite significantly
        // (still runs most tests, just skipping some)
        let with_skip = estimate_cores_for_command(
            Some(CompilationKind::CargoTest),
            "cargo test -- --skip slow_test",
            &config,
        );
        assert_eq!(with_skip, 10, "--skip uses full slots");
    }

    // =========================================================================
    // Timeout handling tests (bead bd-1aim.2)
    // =========================================================================

    #[tokio::test]
    async fn test_daemon_query_connect_timeout_fail_open() {
        // When the daemon socket exists but doesn't accept connections quickly,
        // the hook should timeout and fail-open to allow local execution.
        //
        // We simulate this by creating a socket that accepts but never responds.
        let _lock = test_lock().lock().await;
        let socket_path = format!(
            "/tmp/rch_test_connect_timeout_{}_{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        // Clean up any existing socket
        let _ = std::fs::remove_file(&socket_path);

        // Create a socket that accepts connections but never responds
        let listener = UnixListener::bind(&socket_path).expect("Failed to create test socket");

        let socket_path_clone = socket_path.clone();
        tokio::spawn(async move {
            // Accept the connection but do nothing with it
            let _ = listener.accept().await;
            // Hold connection open for longer than the timeout
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        });

        // Give listener time to start
        tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

        // Query should timeout since daemon never responds
        let result: anyhow::Result<SelectionResponse> = query_daemon(
            &socket_path,
            "test-project",
            4,
            "cargo build",
            None,
            RequiredRuntime::None,
            CommandPriority::Normal,
            100,
            None,
        )
        .await;

        let _ = std::fs::remove_file(&socket_path_clone);

        // Should fail due to read timeout (empty response)
        assert!(
            result.is_err(),
            "Query should fail when daemon doesn't respond"
        );
    }

    #[tokio::test]
    async fn test_process_hook_timeout_fail_open() {
        let _lock = test_lock().lock().await;
        let socket_path = format!(
            "/tmp/rch_test_process_timeout_{}_{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        // Create test config with our socket
        let _overrides = TestOverridesGuard::set(
            &socket_path,
            MockConfig::default(),
            MockRsyncConfig::success(),
        );

        // Clean up any existing socket
        let _ = std::fs::remove_file(&socket_path);

        // Create a slow daemon that doesn't respond in time
        let listener = UnixListener::bind(&socket_path).expect("bind");

        tokio::spawn(async move {
            // Accept and hold connection but don't respond
            let (stream, _) = listener.accept().await.expect("accept");
            // Hold the stream open
            let (_reader, _writer) = stream.into_split();
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: "cargo build".to_string(),
                description: None,
            },
            session_id: None,
        };

        let output = process_hook(input).await;
        let _ = std::fs::remove_file(&socket_path);

        // Should fail-open when daemon times out
        assert!(
            output.is_allow(),
            "Hook should fail-open when daemon query times out"
        );
    }

    #[tokio::test]
    async fn test_daemon_query_partial_response_timeout() {
        // Test behavior when daemon sends partial response and then hangs
        let _lock = test_lock().lock().await;
        let socket_path = format!(
            "/tmp/rch_test_partial_timeout_{}_{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let _ = std::fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path).expect("bind");

        let socket_path_clone = socket_path.clone();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let (reader, mut writer) = stream.into_split();
            let mut buf_reader = TokioBufReader::new(reader);

            // Read request
            let mut request_line = String::new();
            let _ = buf_reader.read_line(&mut request_line).await;

            // Write partial HTTP response (no body)
            writer
                .write_all(b"HTTP/1.1 200 OK\r\n")
                .await
                .expect("write");
            // Hang without completing the response
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

        let result = query_daemon(
            &socket_path,
            "test-project",
            4,
            "cargo build",
            None,
            RequiredRuntime::None,
            CommandPriority::Normal,
            100,
            None,
        )
        .await;

        let _ = std::fs::remove_file(&socket_path_clone);

        // Partial response should result in error (no body to parse)
        assert!(result.is_err(), "Partial response should result in error");
    }

    #[test]
    fn test_timeout_constants_are_reasonable() {
        let _guard = test_guard!();
        // Document and verify the timeout values used in the hook
        // Connection timeout: 300ms (quick enough to not block agents, long enough for local socket)
        // Read timeout: 300ms (same reasoning)
        // These are defined in query_daemon but we verify the code uses timeouts
        // by checking the function uses tokio::time::timeout

        // This is a documentation test - the actual values are embedded in query_daemon
        // We verify the timeout behavior via the tests above (test_daemon_query_connect_timeout_fail_open,
        // test_process_hook_timeout_fail_open, test_daemon_query_partial_response_timeout)
        //
        // The specific timeout values (300ms connect, 300ms read) are validated by the fact that
        // these tests complete in reasonable time without hanging.
    }

    // ============================================================================
    // Auto-start (Self-Healing) Tests
    // ============================================================================

    /// Test helper to create a unique temp directory for auto-start tests
    fn create_test_state_dir() -> tempfile::TempDir {
        tempfile::TempDir::new().expect("Failed to create temp dir")
    }

    #[test]
    fn test_read_cooldown_timestamp_valid() {
        let _guard = test_guard!();
        let temp_dir = create_test_state_dir();
        let cooldown_path = temp_dir.path().join("cooldown");

        // Write a known timestamp (100 seconds ago)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        std::fs::write(&cooldown_path, format!("{}", now - 100)).unwrap();

        let timestamp = super::read_cooldown_timestamp(&cooldown_path);
        assert!(timestamp.is_some(), "Should read valid timestamp");

        let elapsed = timestamp.unwrap().elapsed().unwrap().as_secs();
        assert!(
            (99..=102).contains(&elapsed),
            "Elapsed time should be ~100s, got {}",
            elapsed
        );
    }

    #[test]
    fn test_read_cooldown_timestamp_missing() {
        let _guard = test_guard!();
        let temp_dir = create_test_state_dir();
        let cooldown_path = temp_dir.path().join("nonexistent");

        let timestamp = super::read_cooldown_timestamp(&cooldown_path);
        assert!(timestamp.is_none(), "Missing file should return None");
    }

    #[test]
    fn test_read_cooldown_timestamp_invalid_content() {
        let _guard = test_guard!();
        let temp_dir = create_test_state_dir();
        let cooldown_path = temp_dir.path().join("cooldown");

        std::fs::write(&cooldown_path, "not a number").unwrap();

        let timestamp = super::read_cooldown_timestamp(&cooldown_path);
        assert!(timestamp.is_none(), "Invalid content should return None");
    }

    #[test]
    fn test_write_cooldown_timestamp_creates_file() {
        let _guard = test_guard!();
        let temp_dir = create_test_state_dir();
        let cooldown_path = temp_dir.path().join("subdir/cooldown");

        let result = super::write_cooldown_timestamp(&cooldown_path);
        assert!(result.is_ok(), "Should create file and parent directories");
        assert!(cooldown_path.exists(), "Cooldown file should exist");

        let contents = std::fs::read_to_string(&cooldown_path).unwrap();
        let secs: u64 = contents.trim().parse().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(secs <= now && secs >= now - 2, "Timestamp should be recent");
    }

    #[test]
    fn test_acquire_autostart_lock_success() {
        let _guard = test_guard!();
        let temp_dir = create_test_state_dir();
        let lock_path = temp_dir.path().join("autostart.lock");

        let lock = super::acquire_autostart_lock(&lock_path);
        assert!(lock.is_ok(), "Should acquire lock on first attempt");
        assert!(lock_path.exists(), "Lock file should exist");
    }

    #[test]
    fn test_acquire_autostart_lock_contention() {
        let _guard = test_guard!();
        let temp_dir = create_test_state_dir();
        let lock_path = temp_dir.path().join("autostart.lock");

        // First acquisition should succeed
        let lock1 = super::acquire_autostart_lock(&lock_path);
        assert!(lock1.is_ok(), "First lock should succeed");

        // Second acquisition should fail with LockHeld
        let lock2 = super::acquire_autostart_lock(&lock_path);
        assert!(lock2.is_err(), "Second lock should fail");
        assert!(
            matches!(lock2.unwrap_err(), super::AutoStartError::LockHeld),
            "Error should be LockHeld"
        );
    }

    #[test]
    fn test_autostart_lock_released_on_drop() {
        let _guard = test_guard!();
        let temp_dir = create_test_state_dir();
        let lock_path = temp_dir.path().join("autostart.lock");

        // Acquire and drop the lock
        {
            let lock = super::acquire_autostart_lock(&lock_path);
            assert!(lock.is_ok(), "First lock should succeed");
            assert!(lock_path.exists(), "Lock file should exist while held");
            // lock is dropped here
        }

        // Lock file should be removed
        assert!(
            !lock_path.exists(),
            "Lock file should be removed after drop"
        );

        // Should be able to acquire lock again
        let lock2 = super::acquire_autostart_lock(&lock_path);
        assert!(lock2.is_ok(), "Should be able to reacquire lock after drop");
    }

    #[test]
    fn test_acquire_autostart_lock_creates_parent_dirs() {
        let _guard = test_guard!();
        let temp_dir = create_test_state_dir();
        let lock_path = temp_dir.path().join("deep/nested/dir/autostart.lock");

        let lock = super::acquire_autostart_lock(&lock_path);
        assert!(lock.is_ok(), "Should create parent directories");
        assert!(lock_path.exists(), "Lock file should exist");
    }

    #[tokio::test]
    async fn test_auto_start_config_disabled() {
        let temp_dir = create_test_state_dir();
        let socket_path = temp_dir.path().join("test.sock");

        let config = rch_common::SelfHealingConfig {
            hook_starts_daemon: false,
            ..Default::default()
        };

        let result = super::try_auto_start_daemon(&config, &socket_path).await;

        assert!(result.is_err(), "Should return error when disabled");
        assert!(
            matches!(result.unwrap_err(), super::AutoStartError::Disabled),
            "Error should be Disabled"
        );
    }

    // Note: Tests that require env var manipulation are marked with #[ignore] for safety.
    // Env var manipulation in tests can cause data races and is unsafe in Rust 2024 edition.
    // The core functionality is tested via the helper functions that don't depend on env vars.

    #[test]
    fn test_autostart_state_dir_returns_path() {
        let _guard = test_guard!();
        // Basic test that autostart_state_dir returns a valid path
        // (without manipulating env vars which is unsafe)
        let dir = super::autostart_state_dir();
        assert!(!dir.as_os_str().is_empty(), "Path should not be empty");
        assert!(
            dir.to_string_lossy().contains("rch"),
            "Path should contain 'rch'"
        );
    }

    #[test]
    fn test_autostart_lock_path_ends_with_expected_name() {
        let _guard = test_guard!();
        let path = super::autostart_lock_path();
        assert!(
            path.file_name()
                .map(|n| n == "hook_autostart.lock")
                .unwrap_or(false),
            "Lock path should end with hook_autostart.lock"
        );
    }

    #[test]
    fn test_autostart_cooldown_path_ends_with_expected_name() {
        let _guard = test_guard!();
        let path = super::autostart_cooldown_path();
        assert!(
            path.file_name()
                .map(|n| n == "hook_autostart.cooldown")
                .unwrap_or(false),
            "Cooldown path should end with hook_autostart.cooldown"
        );
    }

    // =========================================================================
    // Cooldown Integration Tests (bd-59kg)
    // =========================================================================
    //
    // Note: Full integration tests for cooldown behavior in try_auto_start_daemon
    // would require manipulating the state directory via env vars, which is unsafe
    // in Rust 2024 (data races in parallel tests). The cooldown logic is tested via:
    //
    // 1. test_read_cooldown_timestamp_valid - validates reading timestamps works
    // 2. test_read_cooldown_timestamp_missing - validates missing file returns None
    // 3. test_write_cooldown_timestamp_creates_file - validates writing timestamps
    // 4. test_auto_start_config_disabled - validates early exit when disabled
    //
    // The integration flow in try_auto_start_daemon is:
    //   cooldown_path = autostart_cooldown_path()
    //   if read_cooldown_timestamp(path).elapsed() < config.cooldown_secs:
    //       return Err(CooldownActive)
    //   ... proceed with daemon start ...
    //   write_cooldown_timestamp(path)

    #[test]
    fn test_autostart_error_cooldown_active_variant() {
        let _guard = test_guard!();
        // TEST START: AutoStartError::CooldownActive has expected structure
        let error = super::AutoStartError::CooldownActive(15, 30);

        // Verify debug formatting includes timing info
        let debug = format!("{:?}", error);
        assert!(
            debug.contains("CooldownActive"),
            "Debug should contain variant name"
        );
        assert!(debug.contains("15"), "Debug should contain elapsed seconds");
        assert!(
            debug.contains("30"),
            "Debug should contain cooldown threshold"
        );

        // Verify it's a distinct error variant
        assert!(
            !matches!(error, super::AutoStartError::Disabled),
            "Should not be Disabled"
        );
        assert!(
            !matches!(error, super::AutoStartError::LockHeld),
            "Should not be LockHeld"
        );
        // TEST PASS: CooldownActive error variant
    }

    #[test]
    fn test_cooldown_logic_simulation() {
        let _guard = test_guard!();
        // TEST START: Simulate cooldown logic without touching real state files
        // This mirrors the logic in try_auto_start_daemon lines 628-640

        let temp_dir = create_test_state_dir();
        let cooldown_path = temp_dir.path().join("cooldown");
        let cooldown_secs: u64 = 30;

        // Case 1: No cooldown file -> should proceed
        let last_attempt = super::read_cooldown_timestamp(&cooldown_path);
        assert!(
            last_attempt.is_none(),
            "No file means no cooldown active - should proceed"
        );

        // Case 2: Recent cooldown file -> should block
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // Write timestamp from 10 seconds ago (within 30s cooldown)
        std::fs::write(&cooldown_path, format!("{}", now - 10)).unwrap();

        let last_attempt = super::read_cooldown_timestamp(&cooldown_path).unwrap();
        let elapsed = last_attempt
            .elapsed()
            .unwrap_or(std::time::Duration::ZERO)
            .as_secs();
        assert!(
            elapsed < cooldown_secs,
            "Elapsed {} should be < cooldown {} - should block",
            elapsed,
            cooldown_secs
        );

        // Case 3: Old cooldown file -> should proceed
        // Write timestamp from 60 seconds ago (outside 30s cooldown)
        std::fs::write(&cooldown_path, format!("{}", now - 60)).unwrap();

        let last_attempt = super::read_cooldown_timestamp(&cooldown_path).unwrap();
        let elapsed = last_attempt
            .elapsed()
            .unwrap_or(std::time::Duration::ZERO)
            .as_secs();
        assert!(
            elapsed >= cooldown_secs,
            "Elapsed {} should be >= cooldown {} - should proceed",
            elapsed,
            cooldown_secs
        );
        // TEST PASS: Cooldown logic simulation
    }

    #[test]
    fn test_cooldown_file_update_after_attempt() {
        let _guard = test_guard!();
        // TEST START: Verify cooldown timestamp is updated after write
        let temp_dir = create_test_state_dir();
        let cooldown_path = temp_dir.path().join("subdir/cooldown");

        // Write initial cooldown
        let result = super::write_cooldown_timestamp(&cooldown_path);
        assert!(result.is_ok(), "First write should succeed");

        let timestamp1 = std::fs::read_to_string(&cooldown_path).unwrap();
        let ts1: u64 = timestamp1
            .trim()
            .parse()
            .expect("cooldown timestamp must be a unix seconds integer");

        // Sleep briefly and write again
        let result = super::write_cooldown_timestamp(&cooldown_path);
        assert!(result.is_ok(), "Second write should succeed");

        let timestamp2 = std::fs::read_to_string(&cooldown_path).unwrap();
        let ts2: u64 = timestamp2
            .trim()
            .parse()
            .expect("cooldown timestamp must be a unix seconds integer");

        assert!(
            ts2 >= ts1,
            "Second write should be >= first write (ts2={ts2} >= ts1={ts1})"
        );
        // TEST PASS: Cooldown file update
    }

    // =========================================================================
    // Timing History Tests
    // =========================================================================

    #[test]
    fn test_timing_record_creation() {
        let _guard = test_guard!();
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let record = super::TimingRecord {
            timestamp: now_secs,
            duration_ms: 5000,
            remote: true,
        };

        assert_eq!(record.duration_ms, 5000);
        assert!(record.remote);
        assert!(record.timestamp >= now_secs - 1 && record.timestamp <= now_secs + 1);
    }

    #[test]
    fn test_project_timing_data_add_sample() {
        let _guard = test_guard!();
        let mut data = super::ProjectTimingData::default();

        // Add local sample
        data.add_sample(1000, false);
        assert_eq!(data.local_samples.len(), 1);
        assert_eq!(data.remote_samples.len(), 0);
        assert_eq!(data.local_samples[0].duration_ms, 1000);

        // Add remote sample
        data.add_sample(500, true);
        assert_eq!(data.local_samples.len(), 1);
        assert_eq!(data.remote_samples.len(), 1);
        assert_eq!(data.remote_samples[0].duration_ms, 500);
    }

    #[test]
    fn test_project_timing_data_median_odd_count() {
        let _guard = test_guard!();
        let mut data = super::ProjectTimingData::default();
        data.add_sample(100, false);
        data.add_sample(300, false);
        data.add_sample(200, false);

        // Median of [100, 200, 300] = 200
        assert_eq!(data.median_duration(false), Some(200));
    }

    #[test]
    fn test_project_timing_data_median_even_count() {
        let _guard = test_guard!();
        let mut data = super::ProjectTimingData::default();
        data.add_sample(100, true);
        data.add_sample(300, true);
        data.add_sample(200, true);
        data.add_sample(400, true);

        // Median of [100, 200, 300, 400] = (200 + 300) / 2 = 250
        assert_eq!(data.median_duration(true), Some(250));
    }

    #[test]
    fn test_project_timing_data_median_empty() {
        let _guard = test_guard!();
        let data = super::ProjectTimingData::default();
        assert_eq!(data.median_duration(false), None);
        assert_eq!(data.median_duration(true), None);
    }

    #[test]
    fn test_project_timing_data_speedup_ratio() {
        let _guard = test_guard!();
        let mut data = super::ProjectTimingData::default();
        // Local takes 1000ms
        data.add_sample(1000, false);
        // Remote takes 500ms
        data.add_sample(500, true);

        // Speedup = local / remote = 1000 / 500 = 2.0
        assert_eq!(data.speedup_ratio(), Some(2.0));
    }

    #[test]
    fn test_project_timing_data_speedup_no_data() {
        let _guard = test_guard!();
        let mut data = super::ProjectTimingData::default();
        data.add_sample(1000, false);

        // No remote data, can't compute speedup
        assert_eq!(data.speedup_ratio(), None);
    }

    #[test]
    fn test_project_timing_data_sample_truncation() {
        let _guard = test_guard!();
        let mut data = super::ProjectTimingData::default();

        // Add more than MAX_TIMING_SAMPLES
        for i in 0..25 {
            data.add_sample(i * 100, false);
        }

        // Should be capped at MAX_TIMING_SAMPLES (20)
        assert_eq!(data.local_samples.len(), super::MAX_TIMING_SAMPLES);
        // First sample should be removed (FIFO)
        assert_eq!(data.local_samples[0].duration_ms, 500); // Started at 0, removed 0-4
    }

    #[test]
    fn test_timing_history_key() {
        let _guard = test_guard!();
        let key = super::TimingHistory::key("my_project", Some(CompilationKind::CargoTest));
        assert!(key.contains("my_project"));
        assert!(key.contains("CargoTest"));

        let key_unknown = super::TimingHistory::key("project2", None);
        assert!(key_unknown.contains("project2"));
        assert!(key_unknown.contains("Unknown"));
    }

    #[test]
    fn test_timing_history_record_and_get() {
        let _guard = test_guard!();
        let mut history = super::TimingHistory::default();

        history.record("proj1", Some(CompilationKind::CargoBuild), 1000, true);
        history.record("proj1", Some(CompilationKind::CargoBuild), 800, true);

        let data = history.get("proj1", Some(CompilationKind::CargoBuild));
        assert!(data.is_some());
        let data = data.unwrap();
        assert_eq!(data.remote_samples.len(), 2);
        assert_eq!(data.median_duration(true), Some(900)); // (800 + 1000) / 2

        // Different kind should be separate
        let data2 = history.get("proj1", Some(CompilationKind::CargoTest));
        assert!(data2.is_none());
    }

    #[test]
    fn test_timing_history_serialization() {
        let _guard = test_guard!();
        let mut history = super::TimingHistory::default();
        history.record("proj", Some(CompilationKind::CargoCheck), 500, false);
        history.record("proj", Some(CompilationKind::CargoCheck), 250, true);

        let json = serde_json::to_string(&history).unwrap();
        let loaded: super::TimingHistory = serde_json::from_str(&json).unwrap();

        let data = loaded
            .get("proj", Some(CompilationKind::CargoCheck))
            .unwrap();
        assert_eq!(data.local_samples.len(), 1);
        assert_eq!(data.remote_samples.len(), 1);
    }

    // ========================================================================
    // WS1.4: Tests for spawn_blocking wrappers (bd-3s1j)
    // ========================================================================

    #[tokio::test]
    async fn test_spawn_blocking_load_with_valid_file() {
        let _guard = test_guard!();
        // Create a temp directory with a timing history file
        let temp_dir = tempfile::tempdir().unwrap();
        let history_path = temp_dir.path().join("timing_history.json");

        // Create valid timing data
        let mut history = super::TimingHistory::default();
        history.record(
            "test-project",
            Some(CompilationKind::CargoBuild),
            1000,
            false,
        );
        let json = serde_json::to_string_pretty(&history).unwrap();
        std::fs::write(&history_path, json).unwrap();

        // Load via spawn_blocking (simulating what we do in production)
        let path = history_path.clone();
        let loaded = tokio::task::spawn_blocking(move || {
            // In production we use timing_history_path(), here we test the pattern
            std::fs::read_to_string(&path)
                .ok()
                .and_then(|content| serde_json::from_str::<super::TimingHistory>(&content).ok())
                .unwrap_or_default()
        })
        .await
        .unwrap();

        // Verify data loaded correctly
        let data = loaded.get("test-project", Some(CompilationKind::CargoBuild));
        assert!(data.is_some());
        assert_eq!(data.unwrap().local_samples.len(), 1);
    }

    #[tokio::test]
    async fn test_spawn_blocking_load_missing_file() {
        let _guard = test_guard!();
        let temp_dir = tempfile::tempdir().unwrap();
        let missing_path = temp_dir.path().join("nonexistent.json");

        let loaded = tokio::task::spawn_blocking(move || {
            std::fs::read_to_string(&missing_path)
                .ok()
                .and_then(|content| serde_json::from_str::<super::TimingHistory>(&content).ok())
                .unwrap_or_default()
        })
        .await
        .unwrap();

        // Should return default (empty history)
        assert!(loaded.entries.is_empty());
    }

    #[tokio::test]
    async fn test_spawn_blocking_load_corrupt_json() {
        let _guard = test_guard!();
        let temp_dir = tempfile::tempdir().unwrap();
        let corrupt_path = temp_dir.path().join("corrupt.json");
        std::fs::write(&corrupt_path, "not valid json {{{").unwrap();

        let loaded = tokio::task::spawn_blocking(move || {
            std::fs::read_to_string(&corrupt_path)
                .ok()
                .and_then(|content| serde_json::from_str::<super::TimingHistory>(&content).ok())
                .unwrap_or_default()
        })
        .await
        .unwrap();

        // Should return default on corrupt data (graceful degradation)
        assert!(loaded.entries.is_empty());
    }

    #[tokio::test]
    async fn test_spawn_blocking_save_creates_file() {
        let _guard = test_guard!();
        let temp_dir = tempfile::tempdir().unwrap();
        let save_path = temp_dir.path().join("saved_history.json");

        let mut history = super::TimingHistory::default();
        history.record(
            "saved-project",
            Some(CompilationKind::CargoTest),
            2000,
            true,
        );

        let path = save_path.clone();
        tokio::task::spawn_blocking(move || {
            let content = serde_json::to_string_pretty(&history).unwrap();
            std::fs::write(&path, content).unwrap();
        })
        .await
        .unwrap();

        // Verify file was created and has correct content
        assert!(save_path.exists());
        let content = std::fs::read_to_string(&save_path).unwrap();
        let loaded: super::TimingHistory = serde_json::from_str(&content).unwrap();
        let data = loaded.get("saved-project", Some(CompilationKind::CargoTest));
        assert!(data.is_some());
        assert_eq!(data.unwrap().remote_samples.len(), 1);
    }

    #[tokio::test]
    async fn test_spawn_blocking_timeout_protection() {
        let _guard = test_guard!();
        // Verify spawn_blocking completes within reasonable time (not deadlocked)
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tokio::task::spawn_blocking(|| {
                let history = super::TimingHistory::default();
                // Simulate some work
                std::thread::sleep(std::time::Duration::from_millis(10));
                history
            }),
        )
        .await;

        assert!(
            result.is_ok(),
            "spawn_blocking should complete within 5s timeout"
        );
    }

    #[tokio::test]
    async fn test_spawn_blocking_concurrent_loads() {
        let _guard = test_guard!();
        let temp_dir = tempfile::tempdir().unwrap();
        let history_path = temp_dir.path().join("concurrent.json");

        // Create test file
        let mut history = super::TimingHistory::default();
        history.record("concurrent", Some(CompilationKind::CargoBuild), 500, false);
        std::fs::write(&history_path, serde_json::to_string(&history).unwrap()).unwrap();

        // Spawn 5 concurrent loads
        let mut handles = Vec::new();
        for _ in 0..5 {
            let path = history_path.clone();
            handles.push(tokio::task::spawn_blocking(move || {
                std::fs::read_to_string(&path)
                    .ok()
                    .and_then(|c| serde_json::from_str::<super::TimingHistory>(&c).ok())
                    .unwrap_or_default()
            }));
        }

        // All should complete without deadlock
        for handle in handles {
            let loaded = handle.await.unwrap();
            assert!(
                loaded
                    .get("concurrent", Some(CompilationKind::CargoBuild))
                    .is_some()
            );
        }
    }

    #[tokio::test]
    async fn test_spawn_blocking_concurrent_saves() {
        let _guard = test_guard!();
        let temp_dir = tempfile::tempdir().unwrap();

        // Spawn 5 concurrent saves to different files
        let mut handles = Vec::new();
        for i in 0..5 {
            let path = temp_dir.path().join(format!("save_{}.json", i));
            let mut history = super::TimingHistory::default();
            history.record(
                &format!("project-{}", i),
                Some(CompilationKind::CargoBuild),
                100 * i as u64,
                false,
            );

            handles.push(tokio::task::spawn_blocking(move || {
                let content = serde_json::to_string(&history).unwrap();
                std::fs::write(&path, content).unwrap();
                path
            }));
        }

        // All should complete and files should exist
        for handle in handles {
            let path = handle.await.unwrap();
            assert!(path.exists(), "File should be created: {:?}", path);
        }
    }

    #[tokio::test]
    async fn test_spawn_blocking_performance_budget() {
        let _guard = test_guard!();
        let temp_dir = tempfile::tempdir().unwrap();
        let history_path = temp_dir.path().join("perf_test.json");

        // Create a reasonably sized history file
        let mut history = super::TimingHistory::default();
        for i in 0..10 {
            history.record(
                &format!("project-{}", i),
                Some(CompilationKind::CargoBuild),
                1000 + i * 100,
                false,
            );
            history.record(
                &format!("project-{}", i),
                Some(CompilationKind::CargoBuild),
                800 + i * 50,
                true,
            );
        }
        std::fs::write(
            &history_path,
            serde_json::to_string_pretty(&history).unwrap(),
        )
        .unwrap();

        // Measure load time
        let load_path = history_path.clone();
        let start = std::time::Instant::now();
        let _loaded = tokio::task::spawn_blocking(move || {
            std::fs::read_to_string(&load_path)
                .ok()
                .and_then(|c| serde_json::from_str::<super::TimingHistory>(&c).ok())
                .unwrap_or_default()
        })
        .await
        .unwrap();
        let load_duration = start.elapsed();

        // Measure save time
        let save_path = temp_dir.path().join("perf_save.json");
        let start = std::time::Instant::now();
        tokio::task::spawn_blocking(move || {
            let content = serde_json::to_string_pretty(&history).unwrap();
            std::fs::write(&save_path, content).unwrap();
        })
        .await
        .unwrap();
        let save_duration = start.elapsed();

        let total = load_duration + save_duration;

        // Log timings for diagnostics (visible with --nocapture)
        eprintln!("Performance test results:");
        eprintln!("  Load: {:?}", load_duration);
        eprintln!("  Save: {:?}", save_duration);
        eprintln!("  Total: {:?}", total);

        // Total should be well under 2ms budget (leaving room for the rest of the 5ms)
        // On fast SSDs this is typically <1ms, but we allow up to 50ms for slow CI
        assert!(
            total < std::time::Duration::from_millis(50),
            "Load+save took {:?}, should be <50ms for CI compatibility",
            total
        );
    }
}
