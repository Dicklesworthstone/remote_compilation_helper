//! PreToolUse hook implementation.
//!
//! Handles incoming hook requests from Claude Code, classifies commands,
//! and routes compilation commands to remote workers.

use crate::config::load_config;
use crate::error::{ArtifactRetrievalWarning, DaemonError, TransferError};
use crate::status_types::format_bytes;
use crate::toolchain::detect_toolchain;
use crate::transfer::{
    SyncResult, TransferPipeline, compute_project_hash, compute_project_hash_with_dependency_roots,
    default_bun_artifact_patterns, default_c_cpp_artifact_patterns, default_rust_artifact_patterns,
    default_rust_test_artifact_patterns, project_id_from_path,
};
use crate::ui::console::RchConsole;
use rch_common::repo_updater_contract::{
    REPO_UPDATER_ALLOW_OVERRIDE_ENV, REPO_UPDATER_ALLOWED_HOSTS_ENV, REPO_UPDATER_ALLOWLIST_ENV,
    REPO_UPDATER_AUTH_CREDENTIAL_ID_ENV, REPO_UPDATER_AUTH_EXPIRES_AT_MS_ENV,
    REPO_UPDATER_AUTH_ISSUED_AT_MS_ENV, REPO_UPDATER_AUTH_MODE_ENV, REPO_UPDATER_AUTH_REVOKED_ENV,
    REPO_UPDATER_AUTH_SCOPES_ENV, REPO_UPDATER_AUTH_SOURCE_ENV,
    REPO_UPDATER_AUTH_VERIFIED_HOSTS_ENV, REPO_UPDATER_OVERRIDE_APPROVED_AT_MS_ENV,
    REPO_UPDATER_OVERRIDE_AUDIT_EVENT_ID_ENV, REPO_UPDATER_OVERRIDE_JUSTIFICATION_ENV,
    REPO_UPDATER_OVERRIDE_OPERATOR_ID_ENV, REPO_UPDATER_OVERRIDE_TICKET_REF_ENV,
    REPO_UPDATER_REQUIRE_HOST_IDENTITY_ENV, REPO_UPDATER_REQUIRED_SCOPES_ENV,
    REPO_UPDATER_ROTATION_MAX_AGE_SECS_ENV, REPO_UPDATER_TRUSTED_HOST_IDENTITIES_ENV,
    RepoUpdaterAuthContext, RepoUpdaterAuthMode, RepoUpdaterCredentialSource,
    RepoUpdaterOperatorOverride, RepoUpdaterTrustedHostIdentity, RepoUpdaterVerifiedHostIdentity,
};
use rch_common::{
    BuildHeartbeatPhase, BuildHeartbeatRequest, ColorMode, CommandPriority, CommandTimingBreakdown,
    CompilationKind, DependencyClosurePlan, HookInput, HookOutput, OutputVisibility,
    REPO_UPDATER_CANONICAL_PROJECTS_ROOT, RepoUpdaterAdapterCommand, RepoUpdaterAdapterContract,
    RepoUpdaterAdapterRequest, RepoUpdaterOutputFormat, RequiredRuntime, SelectedWorker,
    SelectionReason, SelectionResponse, SelfHealingConfig, ToolchainInfo, TransferConfig,
    WorkerConfig, WorkerId, build_dependency_closure_plan_with_policy, build_invocation,
    classify_command, mock, normalize_project_path, normalize_project_path_with_policy,
    path_topology::{
        DEFAULT_ALIAS_PROJECT_ROOT, DEFAULT_CANONICAL_PROJECT_ROOT, PathTopologyPolicy,
    },
    ui::{
        ArtifactSummary, CelebrationSummary, CompilationProgress, CompletionCelebration, Icons,
        OutputContext, RchTheme, TransferProgress,
    },
};
use rch_telemetry::protocol::{
    PIGGYBACK_MARKER, TelemetrySource, TestRunRecord, WorkerTelemetry,
    extract_piggybacked_telemetry,
};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::process::Command;
use tokio::sync::oneshot;
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
#[allow(dead_code)] // Used in run_exec
const EXIT_TEST_FAILURES: i32 = 101;

/// Minimum exit code indicating the process was killed by a signal.
/// Exit code = 128 + signal number (e.g., 137 = 128 + 9 = SIGKILL).
#[allow(dead_code)] // Used in run_exec
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
    // - Deny: write JSON to block the command
    // - AllowWithModifiedCommand: write JSON to replace the command (transparent interception)
    // - Allow: output nothing (empty stdout = allow unchanged)
    match &output {
        HookOutput::Deny(_) | HookOutput::AllowWithModifiedCommand(_) => {
            let json = serde_json::to_string(&output)?;
            writeln!(stdout, "{}", json)?;
        }
        HookOutput::Allow(_) => {
            // Empty stdout = allow command unchanged
        }
    }

    Ok(())
}

/// Execute a compilation command on a remote worker.
///
/// This is called by `rch exec -- <command>` which is invoked after the hook
/// rewrites the original compilation command. This separation allows the hook
/// to return immediately (<50ms) while the actual compilation runs as a
/// normal command invocation.
pub async fn run_exec(command_parts: Vec<String>) -> anyhow::Result<()> {
    let command = command_parts.join(" ");
    if command.is_empty() {
        anyhow::bail!("No command provided to exec");
    }

    // Classify the command
    let classification = classify_command(&command);
    if !classification.is_compilation {
        // Not a compilation command - just run locally
        // This shouldn't normally happen since the hook only rewrites compilations
        warn!("exec called with non-compilation command: {}", command);
        let status = std::process::Command::new("sh")
            .arg("-c")
            .arg(&command)
            .status()?;
        std::process::exit(status.code().unwrap_or(1));
    }

    let config = match load_config() {
        Ok(cfg) => cfg,
        Err(e) => {
            warn!("Failed to load config: {}, running locally", e);
            let status = std::process::Command::new("sh")
                .arg("-c")
                .arg(&command)
                .status()?;
            std::process::exit(status.code().unwrap_or(1));
        }
    };

    let reporter = HookReporter::new(config.output.visibility);

    // Extract project name
    let project = extract_project_name();

    // Estimate cores needed
    let estimated_cores =
        estimate_cores_for_command(classification.kind, &command, &config.compilation);

    // Detect toolchain
    let project_root = std::env::current_dir().ok();
    let toolchain = if let Some(root) = &project_root {
        detect_toolchain(root).ok()
    } else {
        None
    };
    let forwarded_cargo_target_dir = resolve_forwarded_cargo_target_dir(
        &config.environment.allowlist,
        project_root.as_deref().unwrap_or_else(|| Path::new(".")),
        &reporter,
    );

    // Determine required runtime
    let required_runtime = required_runtime_for_kind(classification.kind);
    let command_priority = command_priority_from_env(&reporter);
    let wait_for_worker = queue_when_busy_enabled();

    // Query daemon for worker selection
    let response = match query_daemon(
        &config.general.socket_path,
        &project,
        estimated_cores,
        &command,
        toolchain.as_ref(),
        required_runtime,
        command_priority,
        0, // classification duration not relevant here
        Some(std::process::id()),
        wait_for_worker,
    )
    .await
    {
        Ok(resp) => resp,
        Err(e) => {
            warn!("Failed to query daemon: {}, running locally", e);
            // Try auto-start daemon
            if let Ok(()) =
                try_auto_start_daemon(&config.self_healing, Path::new(&config.general.socket_path))
                    .await
            {
                // Retry query
                match query_daemon(
                    &config.general.socket_path,
                    &project,
                    estimated_cores,
                    &command,
                    toolchain.as_ref(),
                    required_runtime,
                    command_priority,
                    0,
                    Some(std::process::id()),
                    wait_for_worker,
                )
                .await
                {
                    Ok(resp) => resp,
                    Err(_) => {
                        reporter.summary("[RCH] local (daemon unavailable)");
                        let status = std::process::Command::new("sh")
                            .arg("-c")
                            .arg(&command)
                            .status()?;
                        std::process::exit(status.code().unwrap_or(1));
                    }
                }
            } else {
                reporter.summary("[RCH] local (daemon unavailable)");
                let status = std::process::Command::new("sh")
                    .arg("-c")
                    .arg(&command)
                    .status()?;
                std::process::exit(status.code().unwrap_or(1));
            }
        }
    };

    // Check if a worker was assigned
    let Some(worker) = response.worker else {
        reporter.summary(&format!("[RCH] local ({})", response.reason));
        let status = std::process::Command::new("sh")
            .arg("-c")
            .arg(&command)
            .status()?;
        std::process::exit(status.code().unwrap_or(1));
    };

    info!(
        "Selected worker: {} at {}@{} ({} slots, speed {:.1})",
        worker.id, worker.user, worker.host, worker.slots_available, worker.speed_score
    );

    // Execute remote compilation pipeline
    let remote_start = Instant::now();
    let result = execute_remote_compilation(
        &worker,
        &command,
        config.transfer.clone(),
        config.environment.allowlist.clone(),
        forwarded_cargo_target_dir,
        &config.compilation,
        toolchain.as_ref(),
        classification.kind,
        &reporter,
        &config.general.socket_path,
        config.output.color_mode,
        response.build_id,
    )
    .await;
    let remote_elapsed = remote_start.elapsed();

    // Release worker slots
    let release_exit_code = result
        .as_ref()
        .map(|ok| ok.exit_code)
        .unwrap_or(EXIT_BUILD_ERROR);
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

    // Handle result and exit with appropriate code
    match result {
        Ok(result) => {
            if result.exit_code == 0 {
                reporter.summary(&format!(
                    "[RCH] remote {} ({})",
                    worker.id,
                    format_duration_ms(remote_elapsed)
                ));
                // Record successful build
                let is_test = classification
                    .kind
                    .map(|kind| kind.is_test_command())
                    .unwrap_or(false);
                if let Err(e) =
                    record_build(&config.general.socket_path, &worker.id, &project, is_test).await
                {
                    warn!("Failed to record build: {}", e);
                }
                std::process::exit(0);
            } else if is_toolchain_failure(&result.stderr, result.exit_code) {
                // Toolchain failure - fall back to local
                warn!("Remote toolchain failure, falling back to local");
                reporter.summary(&format!("[RCH] local (toolchain missing on {})", worker.id));
                let status = std::process::Command::new("sh")
                    .arg("-c")
                    .arg(&command)
                    .status()?;
                std::process::exit(status.code().unwrap_or(1));
            } else {
                // Command failed remotely - exit with the same code
                reporter.summary(&format!(
                    "[RCH] remote {} failed (exit {})",
                    worker.id, result.exit_code
                ));
                std::process::exit(result.exit_code);
            }
        }
        Err(e) => {
            if let Some(preflight_err) = e.downcast_ref::<DependencyPreflightFailure>() {
                warn!(
                    "Dependency preflight blocked remote execution [{}]: {}",
                    preflight_err.reason_code, preflight_err.remediation
                );
                reporter.summary(&format!(
                    "[RCH] local (dependency preflight {}: {})",
                    preflight_err.reason_code, preflight_err.remediation
                ));
                reporter.verbose(&format!(
                    "[RCH] dependency preflight report: {}",
                    preflight_err.report_json()
                ));
                let status = std::process::Command::new("sh")
                    .arg("-c")
                    .arg(&command)
                    .status()?;
                std::process::exit(status.code().unwrap_or(1));
            }

            // Check for transfer skip (not a failure)
            if let Some(skip_err) = e.downcast_ref::<TransferError>()
                && let TransferError::TransferSkipped { reason } = skip_err
            {
                reporter.summary(&format!("[RCH] local ({})", reason));
                let status = std::process::Command::new("sh")
                    .arg("-c")
                    .arg(&command)
                    .status()?;
                std::process::exit(status.code().unwrap_or(1));
            }

            // Other errors - run locally
            warn!("Remote execution failed: {}, running locally", e);
            reporter.summary("[RCH] local (remote execution failed)");
            let status = std::process::Command::new("sh")
                .arg("-c")
                .arg(&command)
                .status()?;
            std::process::exit(status.code().unwrap_or(1));
        }
    }
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

#[allow(dead_code)] // May be used for timing estimates in run_exec
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

fn tokenize_command(command: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;

    for c in command.chars() {
        if escaped {
            current.push(c);
            escaped = false;
            continue;
        }
        if c == '\\' {
            escaped = true;
            continue;
        }
        if c == '\'' && !in_double {
            in_single = !in_single;
            continue;
        }
        if c == '"' && !in_single {
            in_double = !in_double;
            continue;
        }
        if c.is_whitespace() && !in_single && !in_double {
            if !current.is_empty() {
                tokens.push(current.clone());
                current.clear();
            }
            continue;
        }
        current.push(c);
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

/// Detect if a cargo test command has a test name filter.
///
/// Filtered tests (e.g., `cargo test my_test`) typically run fewer tests
/// and thus require fewer slots than a full test suite.
///
/// Returns true if the command appears to filter tests by name.
fn is_filtered_test_command(command: &str) -> bool {
    let tokens = tokenize_command(command);

    // Find the position of "test" or "run" (for nextest) in the command
    let test_pos = tokens
        .iter()
        .position(|t| t == "test" || t == "t" || t == "run");
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
        "--profile",
        "--config",
        "-Z",
    ];

    let mut i = test_idx + 1;
    while i < tokens.len() {
        let token = &tokens[i];

        // Stop at the separator
        if token == "--" {
            // Check if there is a positional argument after --
            if i + 1 < tokens.len() {
                let next = &tokens[i + 1];
                if !next.starts_with('-') {
                    return true;
                }
            }
            break;
        }

        // Check if this is a flag that takes an argument
        if flags_with_args.contains(&token.as_str()) {
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
    let tokens = tokenize_command(command);

    let has_ignored = tokens.iter().any(|t| t == "--ignored");
    let has_include_ignored = tokens.iter().any(|t| t == "--include-ignored");

    has_ignored && !has_include_ignored
}

/// Check if the command has the --exact flag for exact test name matching.
///
/// Exact matching typically results in running a single test.
fn has_exact_flag(command: &str) -> bool {
    tokenize_command(command).iter().any(|t| t == "--exact")
}

// ============================================================================
// Timing History (bd-2m7j Phase 2)
// ============================================================================

use std::collections::HashMap;

// Timing infrastructure - currently used only for metrics collection and future
// timing-based build gating. Allow dead_code until timing estimates are wired
// into run_exec for smarter offload decisions.
#[allow(dead_code)]
const MAX_TIMING_SAMPLES: usize = 20;

#[allow(dead_code)]
const MAX_TIMING_PROJECTS: usize = 500;

/// A single timing record for a completed build.
#[allow(dead_code)]
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
#[allow(dead_code)]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ProjectTimingData {
    /// Recent local build durations (ring buffer).
    pub local_samples: Vec<TimingRecord>,
    /// Recent remote build durations (ring buffer).
    pub remote_samples: Vec<TimingRecord>,
}

#[allow(dead_code)]
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
#[allow(dead_code)]
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
#[allow(dead_code)]
static TIMING_CACHE: std::sync::OnceLock<std::sync::RwLock<TimingHistory>> =
    std::sync::OnceLock::new();

/// Get or initialize the global TimingHistory cache.
///
/// First call loads from disk (blocking); subsequent calls return the cached copy.
#[allow(dead_code)]
fn timing_cache() -> &'static std::sync::RwLock<TimingHistory> {
    TIMING_CACHE.get_or_init(|| std::sync::RwLock::new(TimingHistory::load_from_disk()))
}

#[allow(dead_code)]
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
#[allow(dead_code)]
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
#[allow(dead_code)]
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
#[allow(dead_code)]
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
    let filtered_test_slots = (test_default / 2).max(2).min(test_default);

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

#[allow(dead_code)]
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

    // CRITICAL: Return immediately with delegated command to avoid hook timeout.
    //
    // Claude Code hooks have a tight timeout budget (~50-100ms). The full remote
    // compilation pipeline (daemon query + rsync + SSH + rsync back) takes 3+ seconds.
    // If we do that work here, the hook times out and Claude Code ignores our response.
    //
    // Solution: Return immediately with `rch exec -- <command>`. The hook completes
    // in <10ms, and the actual remote compilation happens when Claude Code executes
    // the modified command.
    //
    // For compound commands like "cd /path && cargo build", we preserve the prefix
    // and only wrap the compilation part: "cd /path && rch exec -- cargo build"
    info!(
        "Delegating compilation to rch exec (classification: {:?}, compound: {})",
        classification.kind,
        classification.command_prefix.is_some()
    );
    reporter.verbose("[RCH] delegating to rch exec...");

    let modified_command = if let (Some(prefix), Some(extracted)) = (
        &classification.command_prefix,
        &classification.extracted_command,
    ) {
        // Compound command: preserve prefix, wrap only the compilation part
        format!("{}rch exec -- {}", prefix, extracted)
    } else {
        // Simple command: wrap the entire command
        format!("rch exec -- {}", command)
    };

    HookOutput::allow_with_modified_command(modified_command)
}

#[allow(dead_code)]
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
    let invocation_cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let forwarded_cargo_target_dir = resolve_forwarded_cargo_target_dir(
        &config.environment.allowlist,
        &invocation_cwd,
        reporter,
    );

    // Execute remote compilation pipeline
    let remote_start = Instant::now();
    let result = execute_remote_compilation(
        &worker,
        command,
        config.transfer.clone(),
        config.environment.allowlist.clone(),
        forwarded_cargo_target_dir,
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
                // Command succeeded remotely - replace with no-op for transparency
                // The agent already saw output via stderr, artifacts are local
                // Using allow+modified_command makes this completely transparent to the agent
                info!("Remote compilation succeeded, replacing with no-op for transparency");
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

                // Replace original command with a no-op - agent thinks command ran locally
                HookOutput::allow_with_modified_command("true")
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
                        "Remote command killed by signal {} ({}) on {}, replacing with exit code for transparency",
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
                        "Remote tests failed (exit 101) on {}, replacing with exit code for transparency",
                        worker.id
                    );
                    reporter.summary(&format!("[RCH] remote {} tests failed", worker.id));
                } else if exit_code == EXIT_BUILD_ERROR {
                    // Build/compilation error
                    info!(
                        "Remote build error (exit 1) on {}, replacing with exit code for transparency",
                        worker.id
                    );
                    reporter.summary(&format!("[RCH] remote {} build error", worker.id));
                } else {
                    // Other non-zero exit code
                    info!(
                        "Remote command failed (exit {}) on {}, replacing with exit code for transparency",
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

                // Replace with exit command to preserve the exit code transparently
                // Agent already saw the error output, now they see the correct exit code
                HookOutput::allow_with_modified_command(format!("exit {}", exit_code))
            }
        }
        Err(e) => {
            if let Some(preflight_err) = e.downcast_ref::<DependencyPreflightFailure>() {
                info!(
                    "Dependency preflight blocked remote execution [{}], falling back to local",
                    preflight_err.reason_code
                );
                reporter.summary(&format!(
                    "[RCH] local (dependency preflight {}: {})",
                    preflight_err.reason_code, preflight_err.remediation
                ));
                reporter.verbose(&format!(
                    "[RCH] dependency preflight report: {}",
                    preflight_err.report_json()
                ));
                return HookOutput::allow();
            }

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
    wait_for_worker: bool,
) -> anyhow::Result<SelectionResponse> {
    // Mock support: RCH_MOCK_CIRCUIT_OPEN simulates all circuits open
    // This needs to be checked in the hook since the daemon may be started
    // before this environment variable is set for the test scenario.
    if std::env::var("RCH_MOCK_CIRCUIT_OPEN").is_ok() {
        debug!("RCH_MOCK_CIRCUIT_OPEN set, returning AllCircuitsOpen");
        return Ok(SelectionResponse {
            worker: None,
            reason: SelectionReason::AllCircuitsOpen,
            build_id: None,
        });
    }

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
    if wait_for_worker {
        query.push_str("&wait=1");
        // Keep daemon queue timeout aligned with the client-side socket timeout
        // so queued requests return a structured SelectionReason instead of
        // triggering a client communication timeout.
        let wait_timeout_secs = daemon_response_timeout(wait_for_worker)
            .as_secs()
            .saturating_sub(1)
            .max(1);
        query.push_str(&format!("&wait_timeout_secs={}", wait_timeout_secs));
    }

    // Send request
    let request = format!("GET /select-worker?{}\n", query);
    writer.write_all(request.as_bytes()).await?;
    writer.flush().await?;

    // Read response (skip HTTP headers) with timeout and body size limit.
    // Body is capped at 64KB to prevent unbounded memory growth.
    const MAX_RESPONSE_BODY: usize = 64 * 1024;
    let response_timeout = daemon_response_timeout(wait_for_worker);

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

    let response = timeout(response_timeout, read_response)
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "Daemon response timed out after {}s",
                response_timeout.as_secs()
            )
        })??;

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

const DEFAULT_DAEMON_RESPONSE_TIMEOUT_SECS: u64 = 30;
const DEFAULT_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS: u64 = 330;

fn queue_when_busy_enabled_from(value: Option<&str>) -> bool {
    let Some(value) = value else {
        return true;
    };
    let value = value.trim().to_lowercase();
    !matches!(value.as_str(), "0" | "false" | "no" | "off")
}

fn queue_when_busy_enabled() -> bool {
    let value = std::env::var("RCH_QUEUE_WHEN_BUSY").ok();
    queue_when_busy_enabled_from(value.as_deref())
}

fn parse_timeout_secs(raw: &str) -> Option<u64> {
    raw.trim().parse::<u64>().ok().filter(|secs| *secs > 0)
}

fn daemon_response_timeout_for(
    wait_for_worker: bool,
    global_override: Option<&str>,
    wait_override: Option<&str>,
) -> Duration {
    if let Some(secs) = global_override.and_then(parse_timeout_secs) {
        return Duration::from_secs(secs);
    }

    if wait_for_worker {
        let secs = wait_override
            .and_then(parse_timeout_secs)
            .unwrap_or(DEFAULT_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS);
        return Duration::from_secs(secs);
    }

    Duration::from_secs(DEFAULT_DAEMON_RESPONSE_TIMEOUT_SECS)
}

fn daemon_response_timeout(wait_for_worker: bool) -> Duration {
    let global_override = std::env::var("RCH_DAEMON_RESPONSE_TIMEOUT_SECS").ok();
    let wait_override = std::env::var("RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS").ok();
    daemon_response_timeout_for(
        wait_for_worker,
        global_override.as_deref(),
        wait_override.as_deref(),
    )
}

/// Extract project name from current working directory.
pub(crate) fn extract_project_name() -> String {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("unknown"));
    let normalized_cwd = match normalize_project_path(&cwd) {
        Ok(normalized) => {
            for decision in normalized.decision_trace() {
                debug!("[RCH] project identity normalization: {}", decision);
            }
            normalized.canonical_path().to_path_buf()
        }
        Err(err) => {
            warn!(
                "Project path normalization failed for {}: {}",
                cwd.display(),
                err
            );
            for decision in err.decision_trace() {
                debug!(
                    "[RCH] project identity normalization failed at: {}",
                    decision
                );
            }
            cwd.clone()
        }
    };

    let name = normalized_cwd
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    // Compute short hash of the canonical project path to ensure stable identity
    // across equivalent aliases (for example /dp/repo and /data/projects/repo).
    // This prevents cache affinity collisions for projects with same dir name (e.g. "app")
    let hash = blake3::hash(normalized_cwd.to_string_lossy().as_bytes()).to_hex();
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

#[derive(Debug, Clone)]
struct DependencyRuntimePlan {
    sync_roots: Vec<PathBuf>,
    fail_open_decision: Option<DependencyRuntimeFailOpenDecision>,
}

#[derive(Debug, Clone)]
struct DependencyRuntimeFailOpenDecision {
    reason_code: &'static str,
    remediation: &'static str,
    detail: String,
}

fn text_indicates_timeout(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("timeout") || lower.contains("timed out")
}

fn classify_dependency_runtime_fail_open(
    plan: &DependencyClosurePlan,
) -> DependencyRuntimeFailOpenDecision {
    let has_policy_violation = plan
        .issues
        .iter()
        .any(|issue| issue.code == "path-policy-violation");
    let has_timeout = plan
        .fail_open_reason
        .as_deref()
        .is_some_and(text_indicates_timeout)
        || plan.issues.iter().any(|issue| {
            text_indicates_timeout(&issue.message)
                || issue
                    .diagnostics
                    .iter()
                    .any(|diag| text_indicates_timeout(diag))
        });

    let (reason_code, remediation) = if has_policy_violation {
        (
            DEPENDENCY_PREFLIGHT_CODE_POLICY,
            DEPENDENCY_PREFLIGHT_REMEDIATION_POLICY,
        )
    } else if has_timeout {
        (
            DEPENDENCY_PREFLIGHT_CODE_TIMEOUT,
            DEPENDENCY_PREFLIGHT_REMEDIATION_TIMEOUT,
        )
    } else {
        (
            DEPENDENCY_PREFLIGHT_CODE_UNKNOWN,
            DEPENDENCY_PREFLIGHT_REMEDIATION_UNKNOWN,
        )
    };

    let issue_codes = if plan.issues.is_empty() {
        "none".to_string()
    } else {
        plan.issues
            .iter()
            .map(|issue| issue.code.clone())
            .collect::<Vec<_>>()
            .join(",")
    };
    let fail_open_reason = plan
        .fail_open_reason
        .as_deref()
        .unwrap_or("no planner fail-open reason supplied");
    let detail = format!("planner fail-open reason={fail_open_reason}; issue_codes={issue_codes}");

    DependencyRuntimeFailOpenDecision {
        reason_code,
        remediation,
        detail,
    }
}

fn build_dependency_runtime_fail_open_report(
    worker: &WorkerConfig,
    normalized_project_root: &Path,
    decision: &DependencyRuntimeFailOpenDecision,
) -> DependencyPreflightReport {
    let status = if decision.reason_code == DEPENDENCY_PREFLIGHT_CODE_POLICY {
        DependencyPreflightStatus::PolicyViolation
    } else if decision.reason_code == DEPENDENCY_PREFLIGHT_CODE_TIMEOUT {
        DependencyPreflightStatus::Timeout
    } else {
        DependencyPreflightStatus::Unknown
    };

    DependencyPreflightReport {
        schema_version: DEPENDENCY_PREFLIGHT_SCHEMA_VERSION,
        worker: worker.id.as_str().to_string(),
        verified: false,
        reason_code: Some(decision.reason_code),
        remediation: Some(decision.remediation),
        evidence: vec![DependencyPreflightEvidence {
            root: normalized_project_root.to_string_lossy().to_string(),
            manifest: normalized_project_root
                .join("Cargo.toml")
                .to_string_lossy()
                .to_string(),
            status,
            reason_code: decision.reason_code,
            detail: decision.detail.clone(),
            is_primary: true,
        }],
    }
}

fn command_uses_cargo_dependency_graph(kind: Option<CompilationKind>) -> bool {
    matches!(
        kind,
        Some(
            CompilationKind::CargoBuild
                | CompilationKind::CargoCheck
                | CompilationKind::CargoClippy
                | CompilationKind::CargoDoc
                | CompilationKind::CargoTest
                | CompilationKind::CargoNextest
                | CompilationKind::CargoBench
        )
    )
}

fn normalize_dependency_root_for_runtime(root: &Path) -> Option<PathBuf> {
    normalize_project_path_with_policy(root, &PathTopologyPolicy::default())
        .ok()
        .map(|normalized| normalized.canonical_path().to_path_buf())
}

fn build_dependency_runtime_plan(
    normalized_project_root: &Path,
    kind: Option<CompilationKind>,
    reporter: &HookReporter,
) -> DependencyRuntimePlan {
    if !command_uses_cargo_dependency_graph(kind) {
        return DependencyRuntimePlan {
            sync_roots: vec![normalized_project_root.to_path_buf()],
            fail_open_decision: None,
        };
    }

    let plan = build_dependency_closure_plan_with_policy(
        normalized_project_root,
        &PathTopologyPolicy::default(),
    );
    if !plan.is_ready() {
        if let Some(reason) = &plan.fail_open_reason {
            reporter.verbose(&format!(
                "[RCH] dependency closure planner fail-open: {}",
                reason
            ));
        }
        for issue in &plan.issues {
            reporter.verbose(&format!(
                "[RCH] dependency closure issue {} ({:?}): {}",
                issue.code, issue.risk, issue.message
            ));
        }
        let decision = classify_dependency_runtime_fail_open(&plan);
        reporter.verbose(&format!(
            "[RCH] dependency planner fail-open decision [{}]: {}",
            decision.reason_code, decision.remediation
        ));
        return DependencyRuntimePlan {
            sync_roots: vec![normalized_project_root.to_path_buf()],
            fail_open_decision: Some(decision),
        };
    }

    let mut seen = std::collections::BTreeSet::<PathBuf>::new();
    let mut ordered = Vec::<PathBuf>::new();
    for action in &plan.sync_order {
        if let Some(root) = normalize_dependency_root_for_runtime(&action.package_root)
            && seen.insert(root.clone())
        {
            reporter.verbose(&format!(
                "[RCH] dependency root {} ({:?})",
                root.display(),
                action.metadata.reason
            ));
            ordered.push(root);
        }
    }

    if ordered.is_empty() {
        ordered.push(normalized_project_root.to_path_buf());
    }
    if !ordered.iter().any(|root| root == normalized_project_root) {
        ordered.push(normalized_project_root.to_path_buf());
    }

    DependencyRuntimePlan {
        sync_roots: ordered,
        fail_open_decision: None,
    }
}

fn env_allowlist_contains(env_allowlist: &[String], key: &str) -> bool {
    env_allowlist
        .iter()
        .map(|item| item.trim())
        .any(|item| item == key)
}

fn resolve_forwarded_cargo_target_dir_with_lookup<F>(
    env_allowlist: &[String],
    invocation_cwd: &Path,
    reporter: &HookReporter,
    mut lookup_env: F,
) -> Option<PathBuf>
where
    F: FnMut(&str) -> Option<String>,
{
    if !env_allowlist_contains(env_allowlist, "CARGO_TARGET_DIR") {
        return None;
    }

    let raw = match lookup_env("CARGO_TARGET_DIR") {
        Some(value) => value,
        None => {
            reporter.verbose("[RCH] CARGO_TARGET_DIR is allowlisted but unset locally");
            return None;
        }
    };

    let trimmed = raw.trim();
    if trimmed.is_empty() {
        reporter.verbose("[RCH] CARGO_TARGET_DIR is allowlisted but empty");
        return None;
    }

    let requested = PathBuf::from(trimmed);
    let resolved = if requested.is_absolute() {
        requested
    } else {
        invocation_cwd.join(requested)
    };

    reporter.verbose(&format!(
        "[RCH] CARGO_TARGET_DIR forwarding detected; syncing worker .rch-target to {}",
        resolved.display()
    ));
    Some(resolved)
}

fn resolve_forwarded_cargo_target_dir(
    env_allowlist: &[String],
    invocation_cwd: &Path,
    reporter: &HookReporter,
) -> Option<PathBuf> {
    resolve_forwarded_cargo_target_dir_with_lookup(env_allowlist, invocation_cwd, reporter, |key| {
        std::env::var(key).ok()
    })
}

fn should_skip_remote_preflight(worker: &WorkerConfig) -> bool {
    mock::is_mock_enabled() || mock::is_mock_worker(worker)
}

async fn run_worker_ssh_command(
    worker: &WorkerConfig,
    remote_cmd: &str,
    timeout_duration: Duration,
) -> anyhow::Result<Output> {
    let identity_file = shellexpand::tilde(&worker.identity_file);
    let destination = format!("{}@{}", worker.user, worker.host);

    let mut cmd = Command::new("ssh");
    cmd.arg("-o").arg("BatchMode=yes");
    cmd.arg("-o").arg("StrictHostKeyChecking=accept-new");
    cmd.arg("-o").arg(format!(
        "ConnectTimeout={}",
        timeout_duration.as_secs().max(1)
    ));
    cmd.arg("-i").arg(identity_file.as_ref());
    cmd.arg(destination);
    cmd.arg(build_remote_shell_command(remote_cmd));
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    let output = timeout(timeout_duration, cmd.output())
        .await
        .map_err(|_| anyhow::anyhow!("SSH command timed out after {:?}", timeout_duration))??;
    Ok(output)
}

fn build_remote_shell_command(remote_cmd: &str) -> String {
    format!("sh -lc {}", shell_escape::escape(remote_cmd.into()))
}

async fn ensure_worker_projects_topology(
    worker: &WorkerConfig,
    reporter: &HookReporter,
) -> anyhow::Result<()> {
    if should_skip_remote_preflight(worker) {
        reporter.verbose("[RCH] topology preflight skipped in mock mode");
        return Ok(());
    }

    let topology_cmd = format!(
        "set -e; \
         if [ ! -e {canonical} ] && [ ! -L {canonical} ]; then mkdir -p {canonical}; fi; \
         if [ -e {canonical} ] && [ ! -d {canonical} ]; then echo 'RCH_TOPOLOGY_ERR_CANONICAL_NOT_DIRECTORY' >&2; exit 41; fi; \
         if [ -L {alias} ]; then \
           target=$(readlink {alias} 2>/dev/null || true); \
           if [ \"$target\" != {canonical} ] && [ \"$target\" != {canonical_slash} ]; then ln -sfn {canonical} {alias}; fi; \
         elif [ -e {alias} ]; then \
           echo 'RCH_TOPOLOGY_ERR_ALIAS_NOT_SYMLINK' >&2; exit 42; \
         else \
           ln -s {canonical} {alias}; \
         fi; \
         echo RCH_TOPOLOGY_OK",
        canonical = shell_escape::escape(DEFAULT_CANONICAL_PROJECT_ROOT.into()),
        canonical_slash =
            shell_escape::escape(format!("{}/", DEFAULT_CANONICAL_PROJECT_ROOT).into()),
        alias = shell_escape::escape(DEFAULT_ALIAS_PROJECT_ROOT.into())
    );

    let output = run_worker_ssh_command(worker, &topology_cmd, Duration::from_secs(20)).await?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        anyhow::bail!(
            "remote topology preflight failed on {} (status {:?}): stdout='{}' stderr='{}'",
            worker.id,
            output.status.code(),
            stdout,
            stderr
        );
    }
    reporter.verbose(&format!(
        "[RCH] topology preflight ok on {} (/dp -> /data/projects enforced)",
        worker.id
    ));
    Ok(())
}

async fn collect_repo_updater_specs(sync_roots: &[PathBuf]) -> Vec<String> {
    let mut specs = std::collections::BTreeSet::new();

    for root in sync_roots {
        let output = Command::new("git")
            .arg("-C")
            .arg(root)
            .arg("remote")
            .arg("get-url")
            .arg("origin")
            .output()
            .await;

        let Ok(output) = output else {
            continue;
        };
        if !output.status.success() {
            continue;
        }
        let remote = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !remote.is_empty() {
            specs.insert(remote);
        }
    }

    specs.into_iter().collect()
}

fn repo_updater_timeout_for(
    contract: &RepoUpdaterAdapterContract,
    command: RepoUpdaterAdapterCommand,
) -> u64 {
    contract
        .command_budgets
        .iter()
        .find(|budget| budget.command == command)
        .map(|budget| budget.timeout_secs)
        .unwrap_or(contract.timeout_policy.sync_timeout_secs)
        .max(1)
}

fn build_repo_updater_remote_command(
    invocation: &rch_common::repo_updater_contract::RepoUpdaterInvocation,
) -> String {
    let env_prefix = invocation
        .env
        .iter()
        .map(|(k, v)| format!("{k}={}", shell_escape::escape(v.as_str().into())))
        .collect::<Vec<_>>()
        .join(" ");
    let escaped_binary = shell_escape::escape(invocation.binary.as_str().into()).to_string();
    let escaped_args = invocation
        .args
        .iter()
        .map(|arg| shell_escape::escape(arg.as_str().into()).to_string())
        .collect::<Vec<_>>()
        .join(" ");
    if env_prefix.is_empty() {
        format!("{escaped_binary} {escaped_args}")
    } else {
        format!("{env_prefix} {escaped_binary} {escaped_args}")
    }
}

fn build_repo_sync_idempotency_key(worker_id: &WorkerId, sync_roots: &[PathBuf]) -> String {
    build_repo_sync_idempotency_key_for_command(
        worker_id,
        sync_roots,
        RepoUpdaterAdapterCommand::SyncApply,
    )
}

fn repo_updater_command_name(command: RepoUpdaterAdapterCommand) -> &'static str {
    match command {
        RepoUpdaterAdapterCommand::ListPaths => "list-paths",
        RepoUpdaterAdapterCommand::StatusNoFetch => "status-no-fetch",
        RepoUpdaterAdapterCommand::SyncDryRun => "sync-dry-run",
        RepoUpdaterAdapterCommand::SyncApply => "sync-apply",
        RepoUpdaterAdapterCommand::RobotDocsSchemas => "robot-docs-schemas",
        RepoUpdaterAdapterCommand::Version => "version",
    }
}

fn build_repo_sync_idempotency_key_for_command(
    worker_id: &WorkerId,
    sync_roots: &[PathBuf],
    command: RepoUpdaterAdapterCommand,
) -> String {
    let mut material = worker_id.as_str().to_string();
    material.push('|');
    material.push_str(repo_updater_command_name(command));
    for root in sync_roots {
        material.push('|');
        material.push_str(&root.to_string_lossy());
    }
    let hash = blake3::hash(material.as_bytes()).to_hex();
    format!("rch-repo-sync-{}", &hash[..16])
}

async fn execute_repo_updater_command(
    worker: &WorkerConfig,
    contract: &RepoUpdaterAdapterContract,
    base_request: &RepoUpdaterAdapterRequest,
    sync_roots: &[PathBuf],
    command: RepoUpdaterAdapterCommand,
    reporter: &HookReporter,
) -> bool {
    let mut request = base_request.clone();
    let timeout_secs = repo_updater_timeout_for(contract, command);
    request.command = command;
    request.timeout_secs = timeout_secs;
    request.idempotency_key =
        build_repo_sync_idempotency_key_for_command(&worker.id, sync_roots, command);

    if let Err(err) = request.validate(contract) {
        let failure_kind = err.failure_kind();
        warn!(
            "repo_updater {} validation failed for {} [{} {:?}]: {}",
            repo_updater_command_name(command),
            worker.id,
            err.reason_code(),
            failure_kind,
            err
        );
        reporter.verbose(&format!(
            "[RCH] repo_updater {} skipped (validation failed [{} {:?}]): {} | remediation: {}",
            repo_updater_command_name(command),
            err.reason_code(),
            failure_kind,
            err,
            err.remediation()
        ));
        return false;
    }

    let invocation = build_invocation(&request, contract);
    let remote_cmd = build_repo_updater_remote_command(&invocation);
    let retry_policy = &contract.retry_policy;
    let max_attempts = retry_policy.max_attempts.max(1);
    let mut backoff_ms = retry_policy.initial_backoff_ms;

    for attempt in 0..max_attempts {
        if attempt > 0 {
            reporter.verbose(&format!(
                "[RCH] repo_updater {} retry {}/{} on {} (backoff {}ms)",
                repo_updater_command_name(command),
                attempt + 1,
                max_attempts,
                worker.id,
                backoff_ms
            ));
            tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
            backoff_ms = backoff_ms
                .saturating_mul(u64::from(retry_policy.backoff_multiplier_percent))
                .saturating_div(100)
                .min(retry_policy.max_backoff_ms);
        }

        match run_worker_ssh_command(worker, &remote_cmd, Duration::from_secs(timeout_secs)).await {
            Ok(output) if output.status.success() => {
                if attempt > 0 {
                    reporter.verbose(&format!(
                        "[RCH] repo_updater {} succeeded on attempt {}/{} for {} repositories on {}",
                        repo_updater_command_name(command),
                        attempt + 1,
                        max_attempts,
                        request.repo_specs.len(),
                        worker.id
                    ));
                } else {
                    reporter.verbose(&format!(
                        "[RCH] repo_updater {} succeeded for {} repositories on {}",
                        repo_updater_command_name(command),
                        request.repo_specs.len(),
                        worker.id
                    ));
                }
                return true;
            }
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                warn!(
                    "repo_updater {} failed on {} attempt {}/{} (status {:?}): {}",
                    repo_updater_command_name(command),
                    worker.id,
                    attempt + 1,
                    max_attempts,
                    output.status.code(),
                    stderr
                );
                // Last attempt — give up
                if attempt + 1 >= max_attempts {
                    reporter.verbose(&format!(
                        "[RCH] repo_updater {} exhausted {} attempts on {} (continuing with direct sync)",
                        repo_updater_command_name(command),
                        max_attempts,
                        worker.id
                    ));
                    return false;
                }
            }
            Err(err) => {
                warn!(
                    "repo_updater {} transport failure on {} attempt {}/{}: {}",
                    repo_updater_command_name(command),
                    worker.id,
                    attempt + 1,
                    max_attempts,
                    err
                );
                // Last attempt — give up
                if attempt + 1 >= max_attempts {
                    reporter.verbose(&format!(
                        "[RCH] repo_updater {} unavailable on {} after {} attempts (continuing with direct sync)",
                        repo_updater_command_name(command),
                        max_attempts,
                        worker.id
                    ));
                    return false;
                }
            }
        }
    }

    false
}

fn parse_csv_env_var(var_name: &str) -> Option<Vec<String>> {
    let raw = std::env::var(var_name).ok()?;
    let entries = raw
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>();
    (!entries.is_empty()).then_some(entries)
}

fn parse_host_identity_pairs(raw: &str) -> Vec<(String, String)> {
    raw.split(',')
        .filter_map(|entry| {
            let trimmed = entry.trim();
            let (host, fingerprint) = trimmed.split_once('=')?;
            let host = host.trim();
            let fingerprint = fingerprint.trim();
            if host.is_empty() || fingerprint.is_empty() {
                return None;
            }
            Some((host.to_string(), fingerprint.to_string()))
        })
        .collect()
}

fn parse_auth_source(raw: &str) -> Option<RepoUpdaterCredentialSource> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "gh_cli" | "gh" => Some(RepoUpdaterCredentialSource::GhCli),
        "token_env" | "token" => Some(RepoUpdaterCredentialSource::TokenEnv),
        "ssh_agent" | "ssh" => Some(RepoUpdaterCredentialSource::SshAgent),
        _ => None,
    }
}

fn parse_auth_mode(raw: &str) -> Option<RepoUpdaterAuthMode> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "inherit_environment" | "inherit" => Some(RepoUpdaterAuthMode::InheritEnvironment),
        "require_gh_auth" | "gh" | "gh_cli" => Some(RepoUpdaterAuthMode::RequireGhAuth),
        "require_token_env" | "token_env" | "token" => Some(RepoUpdaterAuthMode::RequireTokenEnv),
        _ => None,
    }
}

fn env_flag_is_truthy(var_name: &str) -> bool {
    std::env::var(var_name)
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn env_var_present(var_name: &str) -> bool {
    std::env::var(var_name)
        .ok()
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
}

fn apply_repo_updater_contract_env_policy(contract: &mut RepoUpdaterAdapterContract) {
    if let Some(hosts) = parse_csv_env_var(REPO_UPDATER_ALLOWED_HOSTS_ENV) {
        contract.trust_policy.allowed_repo_hosts = hosts;
    }
    if let Some(spec_allowlist) = parse_csv_env_var(REPO_UPDATER_ALLOWLIST_ENV) {
        contract.trust_policy.allowlisted_repo_specs = spec_allowlist;
    }
    if let Ok(raw_mode) = std::env::var(REPO_UPDATER_AUTH_MODE_ENV)
        && let Some(mode) = parse_auth_mode(&raw_mode)
    {
        contract.auth_policy.mode = mode;
    }
    if env_flag_is_truthy(REPO_UPDATER_ALLOW_OVERRIDE_ENV) {
        contract.trust_policy.allow_operator_override = true;
    }
    if let Some(required_scopes) = parse_csv_env_var(REPO_UPDATER_REQUIRED_SCOPES_ENV) {
        contract.auth_policy.required_scopes = required_scopes;
    }
    if let Ok(rotation_max_age_secs) = std::env::var(REPO_UPDATER_ROTATION_MAX_AGE_SECS_ENV)
        && let Ok(parsed) = rotation_max_age_secs.trim().parse::<u64>()
    {
        contract.auth_policy.rotation_max_age_secs = parsed.max(1);
    }
    if env_flag_is_truthy(REPO_UPDATER_REQUIRE_HOST_IDENTITY_ENV) {
        contract.auth_policy.require_host_identity_verification = true;
    }
    if let Ok(raw_identities) = std::env::var(REPO_UPDATER_TRUSTED_HOST_IDENTITIES_ENV) {
        let trusted = parse_host_identity_pairs(&raw_identities)
            .into_iter()
            .map(|(host, key_fingerprint)| RepoUpdaterTrustedHostIdentity {
                host,
                key_fingerprint,
            })
            .collect::<Vec<_>>();
        if !trusted.is_empty() {
            contract.auth_policy.trusted_host_identities = trusted;
        }
    }
}

fn repo_updater_auth_context_env_supplied() -> bool {
    [
        REPO_UPDATER_AUTH_SOURCE_ENV,
        REPO_UPDATER_AUTH_CREDENTIAL_ID_ENV,
        REPO_UPDATER_AUTH_ISSUED_AT_MS_ENV,
        REPO_UPDATER_AUTH_EXPIRES_AT_MS_ENV,
        REPO_UPDATER_AUTH_SCOPES_ENV,
        REPO_UPDATER_AUTH_REVOKED_ENV,
        REPO_UPDATER_AUTH_VERIFIED_HOSTS_ENV,
    ]
    .iter()
    .any(|var_name| std::env::var(var_name).is_ok())
}

fn infer_repo_updater_auth_context(requested_at_unix_ms: i64) -> RepoUpdaterAuthContext {
    let (source, credential_id, granted_scopes) = if env_var_present("GH_TOKEN") {
        (
            RepoUpdaterCredentialSource::TokenEnv,
            "env:GH_TOKEN".to_string(),
            vec!["repo:read".to_string()],
        )
    } else if env_var_present("GITHUB_TOKEN") {
        (
            RepoUpdaterCredentialSource::TokenEnv,
            "env:GITHUB_TOKEN".to_string(),
            vec!["repo:read".to_string()],
        )
    } else if env_var_present("SSH_AUTH_SOCK") {
        (
            RepoUpdaterCredentialSource::SshAgent,
            "ssh-agent".to_string(),
            Vec::new(),
        )
    } else {
        (
            RepoUpdaterCredentialSource::SshAgent,
            "implicit-no-auth".to_string(),
            Vec::new(),
        )
    };

    let issued_at_unix_ms = if requested_at_unix_ms > 1_000 {
        requested_at_unix_ms - 1_000
    } else {
        1
    };
    let expires_at_unix_ms = requested_at_unix_ms.saturating_add(86_400_000);

    RepoUpdaterAuthContext {
        source,
        credential_id,
        issued_at_unix_ms,
        expires_at_unix_ms,
        granted_scopes,
        revoked: false,
        verified_hosts: Vec::new(),
    }
}

fn auto_tune_repo_updater_contract(
    contract: &mut RepoUpdaterAdapterContract,
    repo_specs: &[String],
    auth_context: Option<&RepoUpdaterAuthContext>,
    has_explicit_allowlist: bool,
    has_explicit_auth_mode: bool,
    reporter: &HookReporter,
) {
    if !has_explicit_allowlist
        && contract.trust_policy.enforce_repo_spec_allowlist
        && contract.trust_policy.allowlisted_repo_specs.is_empty()
    {
        contract.trust_policy.allowlisted_repo_specs = repo_specs.to_vec();
        reporter.verbose(&format!(
            "[RCH] repo_updater allowlist auto-seeded from dependency closure ({} repos)",
            contract.trust_policy.allowlisted_repo_specs.len()
        ));
    }

    if !has_explicit_auth_mode {
        contract.auth_policy.mode = match auth_context.map(|ctx| ctx.source) {
            Some(RepoUpdaterCredentialSource::TokenEnv) => RepoUpdaterAuthMode::RequireTokenEnv,
            Some(RepoUpdaterCredentialSource::GhCli) => RepoUpdaterAuthMode::RequireGhAuth,
            Some(RepoUpdaterCredentialSource::SshAgent) | None => {
                RepoUpdaterAuthMode::InheritEnvironment
            }
        };
        reporter.verbose(&format!(
            "[RCH] repo_updater auth mode auto-selected: {:?}",
            contract.auth_policy.mode
        ));
    }
}

fn hydrate_repo_updater_auth_context_defaults(
    auth_context: &mut RepoUpdaterAuthContext,
    requested_at_unix_ms: i64,
    contract: &RepoUpdaterAdapterContract,
) {
    if auth_context.credential_id.trim().is_empty() {
        auth_context.credential_id = match auth_context.source {
            RepoUpdaterCredentialSource::GhCli => "gh-cli",
            RepoUpdaterCredentialSource::TokenEnv => "token-env",
            RepoUpdaterCredentialSource::SshAgent => "ssh-agent",
        }
        .to_string();
    }

    if auth_context.issued_at_unix_ms <= 0 || auth_context.issued_at_unix_ms > requested_at_unix_ms
    {
        auth_context.issued_at_unix_ms = if requested_at_unix_ms > 1_000 {
            requested_at_unix_ms - 1_000
        } else {
            1
        };
    }

    if auth_context.expires_at_unix_ms <= requested_at_unix_ms {
        let ttl_ms_u64 = contract
            .auth_policy
            .rotation_max_age_secs
            .saturating_mul(1_000)
            .max(60_000);
        let ttl_ms = i64::try_from(ttl_ms_u64).unwrap_or(i64::MAX / 2);
        auth_context.expires_at_unix_ms = requested_at_unix_ms.saturating_add(ttl_ms);
    }

    if auth_context.granted_scopes.is_empty() && !contract.auth_policy.required_scopes.is_empty() {
        auth_context.granted_scopes = contract.auth_policy.required_scopes.clone();
    }

    if auth_context.verified_hosts.is_empty()
        && contract.auth_policy.require_host_identity_verification
    {
        auth_context.verified_hosts = contract
            .auth_policy
            .trusted_host_identities
            .iter()
            .map(|identity| RepoUpdaterVerifiedHostIdentity {
                host: identity.host.clone(),
                key_fingerprint: identity.key_fingerprint.clone(),
                verified_at_unix_ms: requested_at_unix_ms,
            })
            .collect();
    }
}

fn repo_updater_operator_override_from_env() -> Option<RepoUpdaterOperatorOverride> {
    let operator_id = std::env::var(REPO_UPDATER_OVERRIDE_OPERATOR_ID_ENV).ok();
    let justification = std::env::var(REPO_UPDATER_OVERRIDE_JUSTIFICATION_ENV).ok();
    let ticket_ref = std::env::var(REPO_UPDATER_OVERRIDE_TICKET_REF_ENV).ok();
    let audit_event_id = std::env::var(REPO_UPDATER_OVERRIDE_AUDIT_EVENT_ID_ENV).ok();
    let approved_at_unix_ms = std::env::var(REPO_UPDATER_OVERRIDE_APPROVED_AT_MS_ENV)
        .ok()
        .and_then(|value| value.trim().parse::<i64>().ok())
        .unwrap_or_default();

    if operator_id.is_none()
        && justification.is_none()
        && ticket_ref.is_none()
        && audit_event_id.is_none()
        && approved_at_unix_ms == 0
    {
        return None;
    }

    Some(RepoUpdaterOperatorOverride {
        operator_id: operator_id.unwrap_or_default(),
        justification: justification.unwrap_or_default(),
        ticket_ref: ticket_ref.unwrap_or_default(),
        audit_event_id: audit_event_id.unwrap_or_default(),
        approved_at_unix_ms,
    })
}

fn repo_updater_auth_context_from_env(requested_at_unix_ms: i64) -> Option<RepoUpdaterAuthContext> {
    let source = std::env::var(REPO_UPDATER_AUTH_SOURCE_ENV)
        .ok()
        .and_then(|raw| parse_auth_source(&raw));
    let credential_id = std::env::var(REPO_UPDATER_AUTH_CREDENTIAL_ID_ENV).ok();
    let issued_at_unix_ms = std::env::var(REPO_UPDATER_AUTH_ISSUED_AT_MS_ENV)
        .ok()
        .and_then(|value| value.trim().parse::<i64>().ok());
    let expires_at_unix_ms = std::env::var(REPO_UPDATER_AUTH_EXPIRES_AT_MS_ENV)
        .ok()
        .and_then(|value| value.trim().parse::<i64>().ok());
    let scopes = parse_csv_env_var(REPO_UPDATER_AUTH_SCOPES_ENV).unwrap_or_default();
    let revoked = env_flag_is_truthy(REPO_UPDATER_AUTH_REVOKED_ENV);
    let verified_hosts = std::env::var(REPO_UPDATER_AUTH_VERIFIED_HOSTS_ENV)
        .ok()
        .map(|raw| {
            parse_host_identity_pairs(&raw)
                .into_iter()
                .map(|(host, key_fingerprint)| RepoUpdaterVerifiedHostIdentity {
                    host,
                    key_fingerprint,
                    verified_at_unix_ms: requested_at_unix_ms,
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    if source.is_none()
        && credential_id.is_none()
        && issued_at_unix_ms.is_none()
        && expires_at_unix_ms.is_none()
        && scopes.is_empty()
        && !revoked
        && verified_hosts.is_empty()
    {
        return None;
    }

    Some(RepoUpdaterAuthContext {
        source: source.unwrap_or(RepoUpdaterCredentialSource::TokenEnv),
        credential_id: credential_id.unwrap_or_default(),
        issued_at_unix_ms: issued_at_unix_ms.unwrap_or_default(),
        expires_at_unix_ms: expires_at_unix_ms.unwrap_or_default(),
        granted_scopes: scopes,
        revoked,
        verified_hosts,
    })
}

async fn maybe_sync_repo_set_with_repo_updater(
    worker: &WorkerConfig,
    sync_roots: &[PathBuf],
    reporter: &HookReporter,
) {
    if sync_roots.len() <= 1 {
        return;
    }
    if should_skip_remote_preflight(worker) {
        reporter.verbose("[RCH] repo_updater pre-sync skipped in mock mode");
        return;
    }

    let repo_specs = collect_repo_updater_specs(sync_roots).await;
    if repo_specs.is_empty() {
        reporter.verbose("[RCH] repo_updater pre-sync skipped (no git origin remotes found)");
        return;
    }

    let mut contract = RepoUpdaterAdapterContract::default();
    apply_repo_updater_contract_env_policy(&mut contract);
    let has_explicit_allowlist = env_var_present(REPO_UPDATER_ALLOWLIST_ENV);
    let has_explicit_auth_mode = env_var_present(REPO_UPDATER_AUTH_MODE_ENV);

    let command = RepoUpdaterAdapterCommand::SyncApply;
    let timeout_secs = repo_updater_timeout_for(&contract, command);
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or_default();

    let mut auth_context = if repo_updater_auth_context_env_supplied() {
        repo_updater_auth_context_from_env(now_ms)
    } else {
        None
    };
    if auth_context.is_none() {
        auth_context = Some(infer_repo_updater_auth_context(now_ms));
        reporter.verbose("[RCH] repo_updater auth context inferred from runtime environment");
    }

    auto_tune_repo_updater_contract(
        &mut contract,
        &repo_specs,
        auth_context.as_ref(),
        has_explicit_allowlist,
        has_explicit_auth_mode,
        reporter,
    );
    if let Some(context) = auth_context.as_mut() {
        hydrate_repo_updater_auth_context_defaults(context, now_ms, &contract);
    }

    let request = RepoUpdaterAdapterRequest {
        schema_version: rch_common::REPO_UPDATER_CONTRACT_SCHEMA_VERSION.to_string(),
        correlation_id: format!("rch-{}-{}", worker.id, now_ms),
        worker_id: worker.id.to_string(),
        command,
        requested_at_unix_ms: now_ms,
        projects_root: PathBuf::from(REPO_UPDATER_CANONICAL_PROJECTS_ROOT),
        repo_specs,
        idempotency_key: build_repo_sync_idempotency_key(&worker.id, sync_roots),
        retry_attempt: 0,
        timeout_secs,
        expected_output_format: RepoUpdaterOutputFormat::Json,
        auth_context,
        operator_override: repo_updater_operator_override_from_env(),
    };

    if let Err(err) = request.validate(&contract) {
        let failure_kind = err.failure_kind();
        warn!(
            "repo_updater request validation failed for {} [{} {:?}]: {}",
            worker.id,
            err.reason_code(),
            failure_kind,
            err
        );
        reporter.verbose(&format!(
            "[RCH] repo_updater pre-sync skipped (validation failed [{} {:?}]): {} | remediation: {}",
            err.reason_code(),
            failure_kind,
            err,
            err.remediation()
        ));
        return;
    }

    // Read-only convergence preflight to surface policy/auth/drift issues before mutation.
    let dry_run_ok = execute_repo_updater_command(
        worker,
        &contract,
        &request,
        sync_roots,
        RepoUpdaterAdapterCommand::SyncDryRun,
        reporter,
    )
    .await;
    if !dry_run_ok {
        reporter.verbose(
            "[RCH] repo_updater dry-run did not complete cleanly; attempting sync apply anyway",
        );
    }

    let sync_apply_ok = execute_repo_updater_command(
        worker,
        &contract,
        &request,
        sync_roots,
        RepoUpdaterAdapterCommand::SyncApply,
        reporter,
    )
    .await;
    if sync_apply_ok {
        // Post-apply non-mutating snapshot for diagnostics and observability.
        let _ = execute_repo_updater_command(
            worker,
            &contract,
            &request,
            sync_roots,
            RepoUpdaterAdapterCommand::StatusNoFetch,
            reporter,
        )
        .await;
    }
}

fn merge_sync_result(base: &SyncResult, extra: &SyncResult) -> SyncResult {
    SyncResult {
        bytes_transferred: base
            .bytes_transferred
            .saturating_add(extra.bytes_transferred),
        files_transferred: base
            .files_transferred
            .saturating_add(extra.files_transferred),
        duration_ms: base.duration_ms.saturating_add(extra.duration_ms),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SyncClosurePlanEntry {
    local_root: PathBuf,
    remote_root: String,
    project_id: String,
    root_hash: String,
    is_primary: bool,
}

/// Outcome of syncing a single closure root during multi-root transfer.
///
/// Used to collect per-root results and enable partial failure diagnostics
/// instead of aborting the entire sync on the first dependency root failure.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SyncRootOutcome {
    /// Root synced successfully.
    Synced,
    /// Dependency root sync was skipped (transfer estimation indicated skip).
    Skipped { reason: String },
    /// Dependency root sync failed (non-fatal for non-primary roots).
    Failed { error: String },
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct SyncClosureManifest {
    schema_version: &'static str,
    generated_at_unix_ms: i64,
    project_root: String,
    entries: Vec<SyncClosureManifestEntry>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct SyncClosureManifestEntry {
    order: usize,
    local_root: String,
    remote_root: String,
    project_id: String,
    root_hash: String,
    is_primary: bool,
}

const DEPENDENCY_PREFLIGHT_SCHEMA_VERSION: &str = "rch.dependency_preflight.v1";
const DEPENDENCY_PREFLIGHT_CODE_PRESENT: &str = "RCH-I324";
const DEPENDENCY_PREFLIGHT_CODE_MISSING: &str = "RCH-E324";
const DEPENDENCY_PREFLIGHT_CODE_STALE: &str = "RCH-E325";
const DEPENDENCY_PREFLIGHT_CODE_UNKNOWN: &str = "RCH-E326";
const DEPENDENCY_PREFLIGHT_CODE_POLICY: &str = "RCH-E327";
const DEPENDENCY_PREFLIGHT_CODE_TIMEOUT: &str = "RCH-E328";
const DEPENDENCY_PREFLIGHT_REMEDIATION_MISSING: &str =
    "Ensure every dependency root in the closure is synced and Cargo.toml exists remotely.";
const DEPENDENCY_PREFLIGHT_REMEDIATION_STALE: &str = "One or more dependency roots were not refreshed; rerun after successful sync of skipped roots.";
const DEPENDENCY_PREFLIGHT_REMEDIATION_UNKNOWN: &str =
    "Dependency verification could not determine remote state; inspect sync/SSH logs and retry.";
const DEPENDENCY_PREFLIGHT_REMEDIATION_POLICY: &str = "Path dependency topology policy failed; move dependencies under /data/projects (or /dp) and retry.";
const DEPENDENCY_PREFLIGHT_REMEDIATION_TIMEOUT: &str = "Dependency planner timed out; rerun after system load decreases or investigate cargo metadata latency.";

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum DependencyPreflightStatus {
    Present,
    Missing,
    Stale,
    PolicyViolation,
    Timeout,
    Unknown,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct DependencyPreflightEvidence {
    root: String,
    manifest: String,
    status: DependencyPreflightStatus,
    reason_code: &'static str,
    detail: String,
    is_primary: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct DependencyPreflightReport {
    schema_version: &'static str,
    worker: String,
    verified: bool,
    reason_code: Option<&'static str>,
    remediation: Option<&'static str>,
    evidence: Vec<DependencyPreflightEvidence>,
}

#[derive(Debug, thiserror::Error)]
#[error("dependency preflight verification failed [{reason_code}]")]
struct DependencyPreflightFailure {
    reason_code: &'static str,
    remediation: &'static str,
    report: DependencyPreflightReport,
}

impl DependencyPreflightFailure {
    fn from_report(report: DependencyPreflightReport) -> Self {
        let reason_code = report
            .reason_code
            .unwrap_or(DEPENDENCY_PREFLIGHT_CODE_UNKNOWN);
        let remediation = report
            .remediation
            .unwrap_or(DEPENDENCY_PREFLIGHT_REMEDIATION_UNKNOWN);
        Self {
            reason_code,
            remediation,
            report,
        }
    }

    fn report_json(&self) -> String {
        serde_json::to_string(&self.report).unwrap_or_else(|err| {
            format!(
                "{{\"schema_version\":\"{}\",\"verified\":false,\"reason_code\":\"{}\",\"serialization_error\":\"{}\"}}",
                DEPENDENCY_PREFLIGHT_SCHEMA_VERSION, self.reason_code, err
            )
        })
    }
}

fn parse_dependency_preflight_probe_output(
    stdout: &str,
) -> (
    std::collections::BTreeSet<String>,
    std::collections::BTreeSet<String>,
) {
    let mut present = std::collections::BTreeSet::new();
    let mut missing = std::collections::BTreeSet::new();

    for line in stdout.lines() {
        if let Some(path) = line.strip_prefix("RCH_DEP_PRESENT:") {
            present.insert(path.trim().to_string());
        } else if let Some(path) = line.strip_prefix("RCH_DEP_MISSING:") {
            missing.insert(path.trim().to_string());
        }
    }

    (present, missing)
}

fn dependency_preflight_failure_reason(
    evidence: &[DependencyPreflightEvidence],
) -> Option<(&'static str, &'static str)> {
    // Only block on primary root failures. Non-primary dependency roots with
    // Missing/Stale/Unknown status are logged as warnings but do not abort the
    // build — cargo will surface clear errors if a dep is truly unavailable,
    // and this avoids false-positive blocking from intermittent verification
    // issues on sibling repos that may already be cached on the worker.
    if evidence
        .iter()
        .any(|item| item.is_primary && item.status == DependencyPreflightStatus::Missing)
    {
        return Some((
            DEPENDENCY_PREFLIGHT_CODE_MISSING,
            DEPENDENCY_PREFLIGHT_REMEDIATION_MISSING,
        ));
    }
    if evidence
        .iter()
        .any(|item| item.is_primary && item.status == DependencyPreflightStatus::Stale)
    {
        return Some((
            DEPENDENCY_PREFLIGHT_CODE_STALE,
            DEPENDENCY_PREFLIGHT_REMEDIATION_STALE,
        ));
    }
    if evidence
        .iter()
        .any(|item| item.is_primary && item.status == DependencyPreflightStatus::Unknown)
    {
        return Some((
            DEPENDENCY_PREFLIGHT_CODE_UNKNOWN,
            DEPENDENCY_PREFLIGHT_REMEDIATION_UNKNOWN,
        ));
    }
    // Log warnings for non-primary roots with issues (informational, non-blocking).
    for item in evidence {
        if !item.is_primary && item.status != DependencyPreflightStatus::Present {
            warn!(
                "Non-primary dependency root {} has status {:?} (non-blocking): {}",
                item.root, item.status, item.detail
            );
        }
    }
    None
}

fn build_dependency_preflight_report(
    worker: &WorkerConfig,
    root_outcomes: &[(SyncClosurePlanEntry, SyncRootOutcome)],
    present_manifests: &std::collections::BTreeSet<String>,
    missing_manifests: &std::collections::BTreeSet<String>,
    probe_failure: Option<&str>,
) -> DependencyPreflightReport {
    let mut evidence = Vec::with_capacity(root_outcomes.len());

    for (entry, outcome) in root_outcomes {
        let manifest_path = entry.local_root.join("Cargo.toml");
        let manifest = manifest_path.to_string_lossy().to_string();
        let root = entry.local_root.to_string_lossy().to_string();

        let (status, reason_code, detail) = match outcome {
            SyncRootOutcome::Synced => {
                if missing_manifests.contains(&manifest) {
                    (
                        DependencyPreflightStatus::Missing,
                        DEPENDENCY_PREFLIGHT_CODE_MISSING,
                        "required Cargo.toml is missing on remote worker".to_string(),
                    )
                } else if present_manifests.contains(&manifest) {
                    (
                        DependencyPreflightStatus::Present,
                        DEPENDENCY_PREFLIGHT_CODE_PRESENT,
                        "manifest present and refreshed in current sync".to_string(),
                    )
                } else {
                    let detail = probe_failure
                        .map(|failure| format!("manifest probe unavailable: {}", failure))
                        .unwrap_or_else(|| {
                            "probe output omitted status for synced manifest".to_string()
                        });
                    (
                        DependencyPreflightStatus::Unknown,
                        DEPENDENCY_PREFLIGHT_CODE_UNKNOWN,
                        detail,
                    )
                }
            }
            SyncRootOutcome::Skipped { reason } => (
                DependencyPreflightStatus::Stale,
                DEPENDENCY_PREFLIGHT_CODE_STALE,
                format!("dependency root skipped before verification: {}", reason),
            ),
            SyncRootOutcome::Failed { error } => (
                DependencyPreflightStatus::Unknown,
                DEPENDENCY_PREFLIGHT_CODE_UNKNOWN,
                format!("dependency root sync failed before verification: {}", error),
            ),
        };

        evidence.push(DependencyPreflightEvidence {
            root,
            manifest,
            status,
            reason_code,
            detail,
            is_primary: entry.is_primary,
        });
    }

    let (verified, reason_code, remediation) = match dependency_preflight_failure_reason(&evidence)
    {
        Some((reason_code, remediation)) => (false, Some(reason_code), Some(remediation)),
        None => (true, None, None),
    };

    DependencyPreflightReport {
        schema_version: DEPENDENCY_PREFLIGHT_SCHEMA_VERSION,
        worker: worker.id.as_str().to_string(),
        verified,
        reason_code,
        remediation,
        evidence,
    }
}

fn canonicalize_sync_root_for_plan(root: &Path) -> PathBuf {
    normalize_dependency_root_for_runtime(root)
        .or_else(|| std::fs::canonicalize(root).ok())
        .unwrap_or_else(|| root.to_path_buf())
}

/// Returns `true` if `path` is within the allowed topology roots.
fn is_within_sync_topology(path: &Path, policy: &PathTopologyPolicy) -> bool {
    path.starts_with(policy.canonical_root()) || path.starts_with(policy.alias_root())
}

fn build_sync_closure_plan(
    sync_roots: &[PathBuf],
    normalized_project_root: &Path,
    project_hash: &str,
) -> Vec<SyncClosurePlanEntry> {
    let policy = PathTopologyPolicy::default();
    let mut ordered_roots = std::collections::BTreeSet::<PathBuf>::new();
    for root in sync_roots {
        let canonicalized = canonicalize_sync_root_for_plan(root);
        if !is_within_sync_topology(&canonicalized, &policy) {
            warn!(
                "Dependency root {} (canonicalized: {}) is outside allowed topology ({} / {}); skipping from sync closure",
                root.display(),
                canonicalized.display(),
                policy.canonical_root().display(),
                policy.alias_root().display(),
            );
            continue;
        }
        ordered_roots.insert(canonicalized);
    }

    let primary_root = canonicalize_sync_root_for_plan(normalized_project_root);
    ordered_roots.insert(primary_root.clone());

    ordered_roots
        .into_iter()
        .map(|root| {
            let is_primary = root == primary_root;
            let root_hash = if is_primary {
                project_hash.to_string()
            } else {
                compute_project_hash(&root)
            };
            SyncClosurePlanEntry {
                remote_root: root.to_string_lossy().to_string(),
                project_id: project_id_from_path(&root),
                root_hash,
                is_primary,
                local_root: root,
            }
        })
        .collect()
}

fn build_sync_closure_manifest(
    plan: &[SyncClosurePlanEntry],
    normalized_project_root: &Path,
) -> SyncClosureManifest {
    let generated_at_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or_default();
    let entries = plan
        .iter()
        .enumerate()
        .map(|(idx, entry)| SyncClosureManifestEntry {
            order: idx + 1,
            local_root: entry.local_root.to_string_lossy().to_string(),
            remote_root: entry.remote_root.clone(),
            project_id: entry.project_id.clone(),
            root_hash: entry.root_hash.clone(),
            is_primary: entry.is_primary,
        })
        .collect();
    SyncClosureManifest {
        schema_version: "rch.sync_closure_manifest.v1",
        generated_at_unix_ms,
        project_root: normalized_project_root.to_string_lossy().to_string(),
        entries,
    }
}

async fn verify_remote_dependency_manifests(
    worker: &WorkerConfig,
    root_outcomes: &[(SyncClosurePlanEntry, SyncRootOutcome)],
    reporter: &HookReporter,
) -> anyhow::Result<()> {
    if should_skip_remote_preflight(worker) {
        reporter.verbose("[RCH] remote dependency preflight skipped in mock mode");
        return Ok(());
    }
    if root_outcomes.is_empty() {
        return Ok(());
    }

    let synced_roots = root_outcomes
        .iter()
        .filter_map(|(entry, outcome)| match outcome {
            SyncRootOutcome::Synced => Some(entry.local_root.clone()),
            SyncRootOutcome::Skipped { .. } | SyncRootOutcome::Failed { .. } => None,
        })
        .collect::<Vec<_>>();

    let mut present_manifests = std::collections::BTreeSet::new();
    let mut missing_manifests = std::collections::BTreeSet::new();
    let mut probe_failure: Option<String> = None;

    if let Some(verify_cmd) = build_remote_dependency_preflight_command(&synced_roots) {
        match run_worker_ssh_command(worker, &verify_cmd, Duration::from_secs(20)).await {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                let (present, missing) = parse_dependency_preflight_probe_output(&stdout);
                present_manifests = present;
                missing_manifests = missing;
                if !output.status.success() && missing_manifests.is_empty() {
                    probe_failure = Some(format!(
                        "probe exited with status {:?}; stdout='{}'; stderr='{}'",
                        output.status.code(),
                        stdout,
                        stderr
                    ));
                }
            }
            Err(err) => {
                probe_failure = Some(err.to_string());
            }
        }
    }

    let report = build_dependency_preflight_report(
        worker,
        root_outcomes,
        &present_manifests,
        &missing_manifests,
        probe_failure.as_deref(),
    );
    let report_json = serde_json::to_string(&report).unwrap_or_else(|err| {
        format!(
            "{{\"schema_version\":\"{}\",\"verified\":false,\"reason_code\":\"{}\",\"serialization_error\":\"{}\"}}",
            DEPENDENCY_PREFLIGHT_SCHEMA_VERSION, DEPENDENCY_PREFLIGHT_CODE_UNKNOWN, err
        )
    });
    reporter.verbose(&format!(
        "[RCH] dependency preflight report: {}",
        report_json
    ));
    if report.verified {
        reporter.verbose(&format!(
            "[RCH] remote dependency preflight verified {} roots on {}",
            report.evidence.len(),
            worker.id
        ));
        return Ok(());
    }

    let failure = DependencyPreflightFailure::from_report(report);
    warn!(
        "Remote dependency preflight blocked remote execution on {} [{}] remediation='{}'",
        worker.id, failure.reason_code, failure.remediation
    );
    reporter.verbose(&format!(
        "[RCH] dependency preflight remediation [{}]: {}",
        failure.reason_code, failure.remediation
    ));
    Err(failure.into())
}

fn build_remote_dependency_preflight_command(sync_roots: &[PathBuf]) -> Option<String> {
    if sync_roots.is_empty() {
        return None;
    }

    let checks = sync_roots
        .iter()
        .map(|root| root.join("Cargo.toml"))
        .map(|manifest| {
            let escaped = shell_escape::escape(manifest.to_string_lossy().to_string().into());
            format!(
                "manifest={manifest}; if [ -f \"$manifest\" ]; then printf 'RCH_DEP_PRESENT:%s\\n' \"$manifest\"; else printf 'RCH_DEP_MISSING:%s\\n' \"$manifest\"; missing=1; fi",
                manifest = escaped
            )
        })
        .collect::<Vec<_>>()
        .join("; ");

    Some(format!(
        "missing=0; {checks}; if [ \"$missing\" -ne 0 ]; then exit 43; fi; echo RCH_REMOTE_DEPENDENCIES_OK"
    ))
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
#[allow(dead_code)]
fn is_signal_killed(exit_code: i32) -> Option<i32> {
    if exit_code > EXIT_SIGNAL_BASE {
        Some(exit_code - EXIT_SIGNAL_BASE)
    } else {
        None
    }
}

/// Format a signal number as a human-readable name.
#[allow(dead_code)]
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

const BUILD_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Debug, Clone)]
struct BuildHeartbeatSnapshot {
    phase: BuildHeartbeatPhase,
    detail: Option<String>,
    progress_counter: u64,
    progress_percent: Option<f64>,
}

impl BuildHeartbeatSnapshot {
    fn new() -> Self {
        Self {
            phase: BuildHeartbeatPhase::SyncUp,
            detail: Some("build_started".to_string()),
            progress_counter: 0,
            progress_percent: None,
        }
    }

    fn update_phase(&mut self, phase: BuildHeartbeatPhase, detail: Option<String>) {
        self.phase = phase;
        self.detail = detail;
        self.progress_counter = self.progress_counter.saturating_add(1);
    }

    fn note_progress(&mut self) {
        self.progress_counter = self.progress_counter.saturating_add(1);
    }
}

struct BuildHeartbeatLoop {
    socket_path: String,
    build_id: u64,
    worker_id: WorkerId,
    hook_pid: u32,
    state: Arc<Mutex<BuildHeartbeatSnapshot>>,
    stop_tx: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl BuildHeartbeatLoop {
    fn start(socket_path: &str, build_id: u64, worker_id: &WorkerId) -> Self {
        let state = Arc::new(Mutex::new(BuildHeartbeatSnapshot::new()));
        let (stop_tx, mut stop_rx) = oneshot::channel::<()>();

        let socket_path_owned = socket_path.to_string();
        let worker_id_owned = worker_id.clone();
        let state_for_task = Arc::clone(&state);
        let hook_pid = std::process::id();

        let task = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(BUILD_HEARTBEAT_INTERVAL);
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        let snapshot = {
                            state_for_task
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .clone()
                        };
                        let heartbeat = BuildHeartbeatRequest {
                            build_id,
                            worker_id: worker_id_owned.clone(),
                            hook_pid: Some(hook_pid),
                            phase: snapshot.phase,
                            detail: snapshot.detail,
                            progress_counter: Some(snapshot.progress_counter),
                            progress_percent: snapshot.progress_percent,
                        };
                        if let Err(e) = send_build_heartbeat(&socket_path_owned, &heartbeat).await {
                            debug!("build heartbeat send failed for build {}: {}", build_id, e);
                        }
                    }
                    _ = &mut stop_rx => break,
                }
            }
        });

        Self {
            socket_path: socket_path.to_string(),
            build_id,
            worker_id: worker_id.clone(),
            hook_pid,
            state,
            stop_tx: Some(stop_tx),
            task: Some(task),
        }
    }

    fn shared_state(&self) -> Arc<Mutex<BuildHeartbeatSnapshot>> {
        Arc::clone(&self.state)
    }

    fn update_phase(&self, phase: BuildHeartbeatPhase, detail: Option<String>) {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .update_phase(phase, detail);
    }

    async fn flush(&self) {
        let snapshot = { self.state.lock().unwrap_or_else(|e| e.into_inner()).clone() };
        let heartbeat = BuildHeartbeatRequest {
            build_id: self.build_id,
            worker_id: self.worker_id.clone(),
            hook_pid: Some(self.hook_pid),
            phase: snapshot.phase,
            detail: snapshot.detail,
            progress_counter: Some(snapshot.progress_counter),
            progress_percent: snapshot.progress_percent,
        };
        if let Err(e) = send_build_heartbeat(&self.socket_path, &heartbeat).await {
            debug!(
                "build heartbeat flush failed for build {}: {}",
                self.build_id, e
            );
        }
    }

    async fn finish(mut self, phase: BuildHeartbeatPhase, detail: Option<String>) {
        self.update_phase(phase, detail);
        self.flush().await;
        if let Some(stop_tx) = self.stop_tx.take() {
            let _ = stop_tx.send(());
        }
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for BuildHeartbeatLoop {
    fn drop(&mut self) {
        if let Some(stop_tx) = self.stop_tx.take() {
            let _ = stop_tx.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

fn mark_heartbeat_progress(state: &Arc<Mutex<BuildHeartbeatSnapshot>>) {
    state
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .note_progress();
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
    forwarded_cargo_target_dir: Option<PathBuf>,
    compilation_config: &rch_common::CompilationConfig,
    toolchain: Option<&ToolchainInfo>,
    kind: Option<CompilationKind>,
    reporter: &HookReporter,
    socket_path: &str,
    color_mode: ColorMode,
    build_id: Option<u64>,
) -> anyhow::Result<RemoteExecutionResult> {
    let worker_config = selected_worker_to_config(worker);

    // Get current working directory and normalize it to the canonical project root.
    let project_root =
        std::env::current_dir().map_err(|e| TransferError::NoProjectRoot { source: e })?;
    let normalized_project = normalize_project_path(&project_root).map_err(|e| {
        anyhow::anyhow!(
            "Project path normalization failed for {}: {}",
            project_root.display(),
            e
        )
    })?;
    for decision in normalized_project.decision_trace() {
        reporter.verbose(&format!("[RCH] project path normalized: {}", decision));
    }
    let normalized_project_root = normalized_project.canonical_path().to_path_buf();

    let dependency_plan = build_dependency_runtime_plan(&normalized_project_root, kind, reporter);
    if let Some(decision) = dependency_plan.fail_open_decision.as_ref() {
        let report = build_dependency_runtime_fail_open_report(
            &worker_config,
            &normalized_project_root,
            decision,
        );
        if let Ok(report_json) = serde_json::to_string(&report) {
            reporter.verbose(&format!(
                "[RCH] dependency planner fail-open report: {}",
                report_json
            ));
        }
        // Proceed with primary-root-only sync instead of aborting.
        // The planner already set sync_roots = [primary_root] as a safe fallback.
        // Running remotely with just the primary root is better than falling back
        // to local execution (which defeats rch's purpose). Cargo will surface
        // clear errors if any path dependency is truly missing on the worker.
        warn!(
            "Dependency planner fail-open on {} [{}]: proceeding with primary-root-only sync ({})",
            worker_config.id, decision.reason_code, decision.remediation
        );
        reporter.verbose(&format!(
            "[RCH] dependency planner fail-open [{}]: proceeding with primary root only — {}",
            decision.reason_code, decision.remediation
        ));
    }
    let raw_sync_roots = dependency_plan.sync_roots;
    let project_id = project_id_from_path(&normalized_project_root);
    let project_hash =
        compute_project_hash_with_dependency_roots(&normalized_project_root, &raw_sync_roots);
    let sync_plan =
        build_sync_closure_plan(&raw_sync_roots, &normalized_project_root, &project_hash);
    let sync_roots = sync_plan
        .iter()
        .map(|entry| entry.local_root.clone())
        .collect::<Vec<_>>();
    let sync_manifest = build_sync_closure_manifest(&sync_plan, &normalized_project_root);

    let output_ctx = OutputContext::detect();
    let console = RchConsole::with_context(output_ctx);
    let feedback_visible = reporter.visibility != OutputVisibility::None && !console.is_machine();
    let progress_enabled =
        output_ctx.supports_rich() && reporter.visibility != OutputVisibility::None;
    let mut heartbeat_loop =
        build_id.map(|id| BuildHeartbeatLoop::start(socket_path, id, &worker_config.id));
    if let Some(loop_ref) = heartbeat_loop.as_ref() {
        loop_ref.update_phase(BuildHeartbeatPhase::SyncUp, Some("sync_start".to_string()));
        loop_ref.flush().await;
    }

    if feedback_visible {
        emit_job_banner(&console, output_ctx, worker, build_id);
    }

    info!(
        "Starting remote compilation pipeline for {} (hash: {})",
        project_id, project_hash
    );
    reporter.verbose(&format!(
        "[RCH] dependency sync roots planned: {}",
        sync_plan.len()
    ));
    for (idx, entry) in sync_plan.iter().enumerate() {
        reporter.verbose(&format!(
            "[RCH] dependency sync root {}/{}: {}",
            idx + 1,
            sync_plan.len(),
            entry.local_root.display()
        ));
    }
    match serde_json::to_string(&sync_manifest) {
        Ok(manifest_json) => {
            reporter.verbose(&format!(
                "[RCH] dependency sync manifest: {}",
                manifest_json
            ));
            info!(
                "Prepared dependency sync manifest for {} roots",
                sync_manifest.entries.len()
            );
        }
        Err(err) => warn!("Failed to serialize dependency sync manifest: {}", err),
    }
    reporter.verbose(&format!(
        "[RCH] sync start (project {} on {})",
        project_id, worker_config.id
    ));

    // Ensure deterministic remote topology before any repo synchronization.
    ensure_worker_projects_topology(&worker_config, reporter).await?;

    // Best-effort repo convergence for multi-repo dependency graphs.
    maybe_sync_repo_set_with_repo_updater(&worker_config, &sync_roots, reporter).await;

    // Build transfer pipelines with color mode, command timeout, and compilation kind.
    let command_timeout = compilation_config.timeout_for_kind(kind);
    let mut primary_pipeline: Option<TransferPipeline> = None;
    let mut aggregate_sync_result: Option<SyncResult> = None;

    // Step 1: Sync project to remote
    info!("Syncing project to worker {}...", worker_config.id);
    let mut upload_progress = if progress_enabled {
        Some(TransferProgress::upload(
            output_ctx,
            "Syncing workspace closure",
            reporter.visibility == OutputVisibility::None,
        ))
    } else {
        None
    };
    let mut root_outcomes: Vec<(SyncClosurePlanEntry, SyncRootOutcome)> = Vec::new();
    for entry in &sync_plan {
        let mut root_pipeline = TransferPipeline::new(
            entry.local_root.clone(),
            entry.project_id.clone(),
            entry.root_hash.clone(),
            transfer_config.clone(),
        )
        .with_color_mode(color_mode)
        .with_command_timeout(command_timeout)
        .with_compilation_kind(kind)
        .with_remote_path_override(entry.remote_root.clone())
        .with_build_id(build_id);
        if entry.is_primary {
            root_pipeline = root_pipeline.with_env_allowlist(env_allowlist.clone());
        }

        // Check if transfer should be skipped based on size/time estimation.
        if let Some(skip_reason) = root_pipeline.should_skip_transfer(&worker_config).await {
            info!(
                "Transfer estimation indicates skip for {}: {} (worker {})",
                entry.local_root.display(),
                skip_reason,
                worker_config.id
            );
            reporter.verbose(&format!(
                "[RCH] skip transfer for {}: {}",
                entry.local_root.display(),
                skip_reason
            ));
            if entry.is_primary {
                // Primary root skip is fatal — cannot build without the main project.
                return Err(TransferError::TransferSkipped {
                    reason: skip_reason,
                }
                .into());
            }
            root_outcomes.push((
                entry.clone(),
                SyncRootOutcome::Skipped {
                    reason: skip_reason,
                },
            ));
            continue;
        }

        reporter.verbose(&format!(
            "[RCH] syncing dependency root {} to remote {}",
            entry.local_root.display(),
            entry.remote_root.as_str()
        ));
        let sync_attempt = if let Some(progress) = &mut upload_progress {
            root_pipeline
                .sync_to_remote_streaming(&worker_config, |line| {
                    progress.update_from_line(line);
                })
                .await
        } else {
            root_pipeline.sync_to_remote(&worker_config).await
        };
        match sync_attempt {
            Ok(root_sync_result) => {
                aggregate_sync_result = Some(match &aggregate_sync_result {
                    Some(existing) => merge_sync_result(existing, &root_sync_result),
                    None => root_sync_result,
                });
                if entry.is_primary {
                    primary_pipeline = Some(root_pipeline);
                }
                root_outcomes.push((entry.clone(), SyncRootOutcome::Synced));
            }
            Err(e) => {
                if entry.is_primary {
                    // Primary root failure is fatal — cannot build without the main project.
                    return Err(e);
                }
                // Dependency root failure is non-fatal (fail-open for deps).
                warn!(
                    "Dependency root sync failed for {} (non-fatal): {}",
                    entry.local_root.display(),
                    e
                );
                reporter.verbose(&format!(
                    "[RCH] dependency root sync failed (fail-open): {} — {}",
                    entry.local_root.display(),
                    e
                ));
                root_outcomes.push((
                    entry.clone(),
                    SyncRootOutcome::Failed {
                        error: e.to_string(),
                    },
                ));
            }
        }
    }

    // Emit structured partial-sync diagnostics when any dependency roots had issues.
    let failed_count = root_outcomes
        .iter()
        .filter(|(_, o)| !matches!(o, SyncRootOutcome::Synced))
        .count();
    if failed_count > 0 {
        warn!(
            "Partial sync: {}/{} closure roots had issues (build continues with available roots)",
            failed_count,
            sync_plan.len()
        );
        for (entry, outcome) in &root_outcomes {
            match outcome {
                SyncRootOutcome::Synced => {}
                SyncRootOutcome::Skipped { reason } => {
                    info!(
                        "  dependency root skipped: {} — {}",
                        entry.local_root.display(),
                        reason
                    );
                }
                SyncRootOutcome::Failed { error } => {
                    info!(
                        "  dependency root failed: {} — {}",
                        entry.local_root.display(),
                        error
                    );
                }
            }
        }
    }
    let sync_result = aggregate_sync_result
        .ok_or_else(|| anyhow::anyhow!("dependency sync produced no transfer result"))?;
    let pipeline = primary_pipeline.ok_or_else(|| {
        anyhow::anyhow!(
            "dependency sync did not include primary project root {}",
            normalized_project_root.display()
        )
    })?;
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
    if let Some(loop_ref) = heartbeat_loop.as_ref() {
        loop_ref.update_phase(
            BuildHeartbeatPhase::Execute,
            Some("remote_exec_start".to_string()),
        );
        loop_ref.flush().await;
    }

    if command_uses_cargo_dependency_graph(kind) {
        verify_remote_dependency_manifests(&worker_config, &root_outcomes, reporter).await?;
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
    let heartbeat_state_stdout = heartbeat_loop
        .as_ref()
        .map(BuildHeartbeatLoop::shared_state);
    let heartbeat_state_stderr = heartbeat_loop
        .as_ref()
        .map(BuildHeartbeatLoop::shared_state);
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
                if let Some(state) = heartbeat_state_stdout.as_ref() {
                    mark_heartbeat_progress(state);
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
                if let Some(state) = heartbeat_state_stderr.as_ref() {
                    mark_heartbeat_progress(state);
                }
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
        if let Some(loop_ref) = heartbeat_loop.as_ref() {
            loop_ref.update_phase(
                BuildHeartbeatPhase::SyncDown,
                Some("artifact_sync_start".to_string()),
            );
            loop_ref.flush().await;
        }
        info!("Retrieving build artifacts...");
        reporter.verbose("[RCH] artifacts: retrieving...");
        let artifact_patterns = get_artifact_patterns(kind);
        let heartbeat_state_download = heartbeat_loop
            .as_ref()
            .map(BuildHeartbeatLoop::shared_state);
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
                    if let Some(state) = heartbeat_state_download.as_ref() {
                        mark_heartbeat_progress(state);
                    }
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
                artifacts_result = Some(match artifacts_result.take() {
                    Some(existing) => merge_sync_result(&existing, &artifact_result),
                    None => artifact_result,
                });
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

        if let Some(local_target_dir) = forwarded_cargo_target_dir.as_ref() {
            let remote_target_path = format!("{}/.rch-target", pipeline.remote_path());
            let custom_patterns = vec!["**".to_string()];
            let target_pipeline = TransferPipeline::new(
                local_target_dir.clone(),
                project_id_from_path(local_target_dir),
                compute_project_hash(local_target_dir),
                transfer_config.clone(),
            )
            .with_color_mode(color_mode)
            .with_command_timeout(command_timeout)
            .with_compilation_kind(kind)
            .with_remote_path_override(remote_target_path.clone());

            let mut target_progress = if progress_enabled {
                Some(TransferProgress::download(
                    output_ctx,
                    "Syncing custom CARGO_TARGET_DIR artifacts",
                    reporter.visibility == OutputVisibility::None,
                ))
            } else {
                None
            };

            let target_retrieval = if let Some(progress) = &mut target_progress {
                let heartbeat_state_target = heartbeat_loop
                    .as_ref()
                    .map(BuildHeartbeatLoop::shared_state);
                target_pipeline
                    .retrieve_artifacts_streaming(&worker_config, &custom_patterns, |line| {
                        progress.update_from_line(line);
                        if let Some(state) = heartbeat_state_target.as_ref() {
                            mark_heartbeat_progress(state);
                        }
                    })
                    .await
            } else {
                target_pipeline
                    .retrieve_artifacts(&worker_config, &custom_patterns)
                    .await
            };

            match target_retrieval {
                Ok(target_result) => {
                    info!(
                        "Custom CARGO_TARGET_DIR artifacts retrieved: {} files, {} bytes in {}ms",
                        target_result.files_transferred,
                        target_result.bytes_transferred,
                        target_result.duration_ms
                    );
                    reporter.verbose(&format!(
                        "[RCH] custom target dir sync done: {} -> {} ({} files, {} bytes in {}ms)",
                        remote_target_path,
                        local_target_dir.display(),
                        target_result.files_transferred,
                        target_result.bytes_transferred,
                        target_result.duration_ms
                    ));
                    if let Some(progress) = &mut target_progress {
                        progress.apply_summary(
                            target_result.bytes_transferred,
                            target_result.files_transferred,
                        );
                        progress.finish();
                    }
                    artifacts_result = Some(match artifacts_result.take() {
                        Some(existing) => merge_sync_result(&existing, &target_result),
                        None => target_result,
                    });
                }
                Err(e) => {
                    artifacts_failed = true;
                    warn!("Failed to sync custom CARGO_TARGET_DIR artifacts: {}", e);
                    reporter.verbose(&format!(
                        "[RCH] custom target dir sync failed for {}: {}",
                        local_target_dir.display(),
                        e
                    ));
                    if let Some(progress) = &mut target_progress {
                        progress.finish_error(&e.to_string());
                    }
                }
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

    if let Some(loop_ref) = heartbeat_loop.take() {
        let detail = if result.success() {
            Some("build_complete".to_string())
        } else {
            Some(format!("build_exit_{}", result.exit_code))
        };
        loop_ref.finish(BuildHeartbeatPhase::Finalize, detail).await;
    }

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

async fn send_build_heartbeat(
    socket_path: &str,
    heartbeat: &BuildHeartbeatRequest,
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

    let body = serde_json::to_string(heartbeat)?;
    let request = format!("POST /build-heartbeat\n{}\n", body);
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
        self, MockConfig, MockRsyncConfig, clear_mock_overrides, set_mock_enabled_override,
        set_mock_rsync_config_override, set_mock_ssh_config_override,
    };
    use rch_common::test_guard;
    use rch_common::{SelectionReason, TierDecision, ToolInput, classify_command_detailed};
    use serial_test::serial;
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
            false,
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
            false,
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
    async fn test_daemon_query_wait_parameters() {
        let socket_path = format!("/tmp/rch_test_wait_{}.sock", std::process::id());
        let _ = std::fs::remove_file(&socket_path);

        let listener = UnixListener::bind(&socket_path).expect("Failed to create test socket");
        let expected_wait_timeout_secs = daemon_response_timeout_for(true, None, None)
            .as_secs()
            .saturating_sub(1)
            .max(1);

        let socket_path_clone = socket_path.clone();
        let daemon_handle = tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("Failed to accept connection");
            let (reader, mut writer) = stream.into_split();
            let mut buf_reader = TokioBufReader::new(reader);

            let mut request_line = String::new();
            buf_reader
                .read_line(&mut request_line)
                .await
                .expect("Failed to read request");

            assert!(request_line.starts_with("GET /select-worker"));
            assert!(request_line.contains("wait=1"));
            assert!(
                request_line.contains(&format!("wait_timeout_secs={expected_wait_timeout_secs}"))
            );

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

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

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
            true,
        )
        .await;

        daemon_handle.await.expect("Daemon task panicked");
        let _ = std::fs::remove_file(&socket_path_clone);

        let response = result.expect("Query should succeed");
        let worker = response.worker.expect("Should have worker");
        assert_eq!(worker.id.as_str(), "mock-worker");
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
            false,
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
    #[serial(mock_global)]
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

        // Hook should return AllowWithModifiedCommand delegating to `rch exec`
        // The actual remote compilation happens when `rch exec` runs, not in the hook
        assert!(output.is_allow());
        match &output {
            HookOutput::AllowWithModifiedCommand(modified) => {
                let cmd = &modified.hook_specific_output.updated_input.command;
                assert!(
                    cmd.starts_with("rch exec -- "),
                    "Modified command should delegate to rch exec: {}",
                    cmd
                );
                assert!(
                    cmd.contains("cargo build"),
                    "Modified command should contain original command: {}",
                    cmd
                );
            }
            _ => panic!("Expected AllowWithModifiedCommand"),
        }

        // No rsync/SSH should be invoked during the hook - that happens in run_exec
        let rsync_logs = mock::global_rsync_invocations_snapshot();
        let ssh_logs = mock::global_ssh_invocations_snapshot();
        assert!(
            rsync_logs.is_empty(),
            "Hook should not invoke rsync directly"
        );
        assert!(ssh_logs.is_empty(), "Hook should not invoke SSH directly");
    }

    #[tokio::test]
    #[serial(mock_global)]
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
    #[serial(mock_global)]
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

        // force_remote should result in transparent interception (AllowWithModifiedCommand)
        // with delegation to `rch exec`
        assert!(output.is_allow());
        match &output {
            HookOutput::AllowWithModifiedCommand(modified) => {
                let cmd = &modified.hook_specific_output.updated_input.command;
                assert!(
                    cmd.starts_with("rch exec -- "),
                    "Should delegate to rch exec: {}",
                    cmd
                );
            }
            _ => panic!("force_remote should use transparent interception"),
        }

        // No rsync/SSH should be invoked during the hook - that happens in run_exec
        let rsync_logs = mock::global_rsync_invocations_snapshot();
        let ssh_logs = mock::global_ssh_invocations_snapshot();
        assert!(
            rsync_logs.is_empty(),
            "Hook should not invoke rsync directly"
        );
        assert!(ssh_logs.is_empty(), "Hook should not invoke SSH directly");
    }

    #[tokio::test]
    #[serial(mock_global)]
    async fn test_process_hook_delegates_to_rch_exec() {
        // Test that process_hook always delegates to `rch exec` without doing
        // any remote operations itself. Sync failures (if any) would happen
        // in run_exec, not in process_hook.
        let _lock = test_lock().lock().await;
        let socket_path = format!(
            "/tmp/rch_test_hook_delegate_{}_{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        // Even with sync_failure mock config, the hook should succeed
        // because it doesn't do sync - it just delegates to rch exec
        let _overrides = TestOverridesGuard::set(
            &socket_path,
            MockConfig::default(),
            MockRsyncConfig::sync_failure(),
        );
        mock::clear_global_invocations();

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

        // Hook should return AllowWithModifiedCommand delegating to rch exec
        assert!(output.is_allow());
        match &output {
            HookOutput::AllowWithModifiedCommand(modified) => {
                let cmd = &modified.hook_specific_output.updated_input.command;
                assert!(
                    cmd.starts_with("rch exec -- "),
                    "Should delegate to rch exec: {}",
                    cmd
                );
            }
            _ => panic!("Expected AllowWithModifiedCommand"),
        }

        // No rsync/SSH should be invoked during the hook
        let rsync_logs = mock::global_rsync_invocations_snapshot();
        let ssh_logs = mock::global_ssh_invocations_snapshot();
        assert!(
            rsync_logs.is_empty(),
            "Hook should not invoke rsync directly"
        );
        assert!(ssh_logs.is_empty(), "Hook should not invoke SSH directly");
    }

    #[tokio::test]
    #[serial(mock_global)]
    async fn test_process_hook_remote_nonzero_exit_uses_transparent_interception() {
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

        // Remote failure should still use transparent interception (AllowWithModifiedCommand)
        // with "exit <code>" to preserve the exit code for the agent
        assert!(output.is_allow());
        assert!(
            matches!(output, HookOutput::AllowWithModifiedCommand(_)),
            "Expected AllowWithModifiedCommand for remote execution with non-zero exit"
        );
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

    #[test]
    fn test_resolve_forwarded_cargo_target_dir_requires_allowlist() {
        let _guard = test_guard!();
        let reporter = HookReporter::new(OutputVisibility::Verbose);
        let resolved = resolve_forwarded_cargo_target_dir_with_lookup(
            &[],
            Path::new("/tmp/rch"),
            &reporter,
            |_| Some("/tmp/rch-target-no-allowlist".to_string()),
        );

        assert!(resolved.is_none());
    }

    #[test]
    fn test_resolve_forwarded_cargo_target_dir_resolves_relative_path() {
        let _guard = test_guard!();
        let reporter = HookReporter::new(OutputVisibility::Verbose);
        let resolved = resolve_forwarded_cargo_target_dir_with_lookup(
            &[String::from(" CARGO_TARGET_DIR ")],
            Path::new("/data/projects/remote_compilation_helper"),
            &reporter,
            |_| Some("tmp/custom-target".to_string()),
        );

        assert_eq!(
            resolved,
            Some(PathBuf::from(
                "/data/projects/remote_compilation_helper/tmp/custom-target"
            ))
        );
    }

    #[test]
    fn test_auto_tune_repo_updater_contract_autoseeds_allowlist_and_mode() {
        let _guard = test_guard!();
        let mut contract = RepoUpdaterAdapterContract::default();
        let repo_specs = vec!["github.com/example/repo".to_string()];
        let auth_context = RepoUpdaterAuthContext {
            source: RepoUpdaterCredentialSource::SshAgent,
            credential_id: "ssh-agent".to_string(),
            issued_at_unix_ms: 1_700_000_000_000,
            expires_at_unix_ms: 1_700_000_060_000,
            granted_scopes: vec![],
            revoked: false,
            verified_hosts: vec![],
        };
        let reporter = HookReporter::new(OutputVisibility::None);

        auto_tune_repo_updater_contract(
            &mut contract,
            &repo_specs,
            Some(&auth_context),
            false,
            false,
            &reporter,
        );

        assert_eq!(contract.trust_policy.allowlisted_repo_specs, repo_specs);
        assert_eq!(
            contract.auth_policy.mode,
            RepoUpdaterAuthMode::InheritEnvironment
        );
    }

    #[test]
    fn test_hydrate_repo_updater_auth_context_defaults_populates_required_fields() {
        let _guard = test_guard!();
        let contract = RepoUpdaterAdapterContract::default();
        let now_ms = 1_700_000_000_000_i64;
        let mut auth_context = RepoUpdaterAuthContext {
            source: RepoUpdaterCredentialSource::TokenEnv,
            credential_id: String::new(),
            issued_at_unix_ms: 0,
            expires_at_unix_ms: 0,
            granted_scopes: vec![],
            revoked: false,
            verified_hosts: vec![],
        };

        hydrate_repo_updater_auth_context_defaults(&mut auth_context, now_ms, &contract);

        assert_eq!(auth_context.credential_id, "token-env");
        assert!(auth_context.issued_at_unix_ms > 0);
        assert!(auth_context.issued_at_unix_ms <= now_ms);
        assert!(auth_context.expires_at_unix_ms > now_ms);
        assert_eq!(
            auth_context.granted_scopes,
            contract.auth_policy.required_scopes
        );
        assert_eq!(
            auth_context.verified_hosts.len(),
            contract.auth_policy.trusted_host_identities.len()
        );
    }

    #[test]
    fn test_repo_updater_command_name_is_stable() {
        let _guard = test_guard!();
        assert_eq!(
            repo_updater_command_name(RepoUpdaterAdapterCommand::SyncApply),
            "sync-apply"
        );
        assert_eq!(
            repo_updater_command_name(RepoUpdaterAdapterCommand::SyncDryRun),
            "sync-dry-run"
        );
        assert_eq!(
            repo_updater_command_name(RepoUpdaterAdapterCommand::StatusNoFetch),
            "status-no-fetch"
        );
    }

    #[test]
    fn test_build_repo_sync_idempotency_key_for_command_distinguishes_commands() {
        let _guard = test_guard!();
        let worker_id = WorkerId::new("worker-a");
        let sync_roots = vec![
            PathBuf::from("/data/projects/repo-a"),
            PathBuf::from("/data/projects/repo-b"),
        ];

        let apply_key = build_repo_sync_idempotency_key_for_command(
            &worker_id,
            &sync_roots,
            RepoUpdaterAdapterCommand::SyncApply,
        );
        let dry_run_key = build_repo_sync_idempotency_key_for_command(
            &worker_id,
            &sync_roots,
            RepoUpdaterAdapterCommand::SyncDryRun,
        );
        let status_key = build_repo_sync_idempotency_key_for_command(
            &worker_id,
            &sync_roots,
            RepoUpdaterAdapterCommand::StatusNoFetch,
        );

        assert_ne!(apply_key, dry_run_key);
        assert_ne!(dry_run_key, status_key);
        assert_ne!(apply_key, status_key);
        assert!(apply_key.starts_with("rch-repo-sync-"));
    }

    #[test]
    fn test_build_remote_dependency_preflight_command_empty_roots() {
        let _guard = test_guard!();
        assert!(build_remote_dependency_preflight_command(&[]).is_none());
    }

    #[test]
    fn test_build_remote_dependency_preflight_command_separates_checks() {
        let _guard = test_guard!();
        let sync_roots = vec![
            PathBuf::from("/data/projects/repo-a"),
            PathBuf::from("/data/projects/repo-b"),
        ];

        let command = build_remote_dependency_preflight_command(&sync_roots)
            .expect("command should be constructed");

        assert!(
            command.contains("fi; manifest="),
            "generated command must separate consecutive if/fi checks with ';'"
        );
        assert!(
            !command.contains("fi if ["),
            "generated command must not concatenate checks without separator"
        );
        assert!(
            command.contains("RCH_DEP_PRESENT:"),
            "generated command must emit structured present marker"
        );
        assert!(
            command.contains("RCH_DEP_MISSING:"),
            "generated command must emit structured missing marker"
        );
    }

    #[test]
    fn test_parse_dependency_preflight_probe_output_extracts_markers() {
        let _guard = test_guard!();
        let stdout = "\
RCH_DEP_PRESENT:/data/projects/a/Cargo.toml
noise
RCH_DEP_MISSING:/data/projects/b/Cargo.toml
RCH_DEP_PRESENT:/data/projects/c/Cargo.toml
";

        let (present, missing) = parse_dependency_preflight_probe_output(stdout);

        assert_eq!(present.len(), 2);
        assert_eq!(missing.len(), 1);
        assert!(present.contains("/data/projects/a/Cargo.toml"));
        assert!(present.contains("/data/projects/c/Cargo.toml"));
        assert!(missing.contains("/data/projects/b/Cargo.toml"));
    }

    fn make_sync_entry(root: &str, is_primary: bool) -> SyncClosurePlanEntry {
        SyncClosurePlanEntry {
            local_root: PathBuf::from(root),
            remote_root: root.to_string(),
            project_id: format!("id-{}", root.replace('/', "_")),
            root_hash: format!("hash-{}", root.replace('/', "_")),
            is_primary,
        }
    }

    fn make_test_worker_config(id: &str) -> WorkerConfig {
        WorkerConfig {
            id: WorkerId::new(id),
            host: "worker.host".to_string(),
            user: "ubuntu".to_string(),
            identity_file: "~/.ssh/id_ed25519".to_string(),
            total_slots: 8,
            priority: 100,
            tags: Vec::new(),
        }
    }

    fn make_fail_open_plan(
        fail_open_reason: Option<&str>,
        issues: Vec<rch_common::DependencyPlanIssue>,
    ) -> DependencyClosurePlan {
        DependencyClosurePlan {
            state: rch_common::DependencyClosurePlanState::FailOpen,
            entry_manifest_path: PathBuf::from("/data/projects/example/Cargo.toml"),
            workspace_root: Some(PathBuf::from("/data/projects/example")),
            canonical_roots: Vec::new(),
            sync_order: Vec::new(),
            fail_open: true,
            fail_open_reason: fail_open_reason.map(ToString::to_string),
            issues,
        }
    }

    #[test]
    fn test_classify_dependency_runtime_fail_open_policy_violation() {
        let _guard = test_guard!();
        let plan = make_fail_open_plan(
            Some("resolver produced path policy violation"),
            vec![rch_common::DependencyPlanIssue {
                code: "path-policy-violation".to_string(),
                message: "dependency path escapes canonical root".to_string(),
                risk: rch_common::DependencyRiskClass::High,
                diagnostics: vec!["dependency_path=/tmp/off-policy".to_string()],
            }],
        );

        let decision = classify_dependency_runtime_fail_open(&plan);
        assert_eq!(decision.reason_code, DEPENDENCY_PREFLIGHT_CODE_POLICY);
        assert_eq!(
            decision.remediation,
            DEPENDENCY_PREFLIGHT_REMEDIATION_POLICY
        );
    }

    #[test]
    fn test_classify_dependency_runtime_fail_open_timeout_signal() {
        let _guard = test_guard!();
        let plan = make_fail_open_plan(
            Some("cargo metadata timed out after 10s"),
            vec![rch_common::DependencyPlanIssue {
                code: "metadata-invocation-failure".to_string(),
                message: "metadata invocation timed out".to_string(),
                risk: rch_common::DependencyRiskClass::Critical,
                diagnostics: vec!["timeout=10s".to_string()],
            }],
        );

        let decision = classify_dependency_runtime_fail_open(&plan);
        assert_eq!(decision.reason_code, DEPENDENCY_PREFLIGHT_CODE_TIMEOUT);
        assert_eq!(
            decision.remediation,
            DEPENDENCY_PREFLIGHT_REMEDIATION_TIMEOUT
        );
    }

    #[test]
    fn test_classify_dependency_runtime_fail_open_defaults_unknown() {
        let _guard = test_guard!();
        let plan = make_fail_open_plan(
            Some("resolver returned unverifiable graph ordering"),
            vec![rch_common::DependencyPlanIssue {
                code: "non-deterministic-order".to_string(),
                message: "graph order could not be proven".to_string(),
                risk: rch_common::DependencyRiskClass::Critical,
                diagnostics: vec!["planner_state=fail_open".to_string()],
            }],
        );

        let decision = classify_dependency_runtime_fail_open(&plan);
        assert_eq!(decision.reason_code, DEPENDENCY_PREFLIGHT_CODE_UNKNOWN);
        assert_eq!(
            decision.remediation,
            DEPENDENCY_PREFLIGHT_REMEDIATION_UNKNOWN
        );
    }

    #[test]
    fn test_build_dependency_runtime_fail_open_report_uses_status_mapping() {
        let _guard = test_guard!();
        let worker = make_test_worker_config("worker-runtime-report");
        let project_root = PathBuf::from("/data/projects/runtime-policy");
        let decision = DependencyRuntimeFailOpenDecision {
            reason_code: DEPENDENCY_PREFLIGHT_CODE_POLICY,
            remediation: DEPENDENCY_PREFLIGHT_REMEDIATION_POLICY,
            detail: "policy violation detail".to_string(),
        };

        let report = build_dependency_runtime_fail_open_report(&worker, &project_root, &decision);
        assert!(!report.verified);
        assert_eq!(report.reason_code, Some(DEPENDENCY_PREFLIGHT_CODE_POLICY));
        assert_eq!(
            report.remediation,
            Some(DEPENDENCY_PREFLIGHT_REMEDIATION_POLICY)
        );
        assert_eq!(report.evidence.len(), 1);
        assert_eq!(
            report.evidence[0].status,
            DependencyPreflightStatus::PolicyViolation
        );
    }

    #[test]
    fn test_e2e_dependency_preflight_verified_success_path() {
        let _guard = test_guard!();
        let worker = make_test_worker_config("worker-success");
        let entry = make_sync_entry("/data/projects/repo-success", true);
        let manifest = entry
            .local_root
            .join("Cargo.toml")
            .to_string_lossy()
            .to_string();
        let outcomes = vec![(entry, SyncRootOutcome::Synced)];
        let present = std::collections::BTreeSet::from([manifest]);
        let missing = std::collections::BTreeSet::new();

        let report =
            build_dependency_preflight_report(&worker, &outcomes, &present, &missing, None);

        assert!(report.verified, "all-present manifests should verify");
        assert!(report.reason_code.is_none());
        assert!(report.remediation.is_none());
        assert_eq!(report.evidence.len(), 1);
        assert_eq!(
            report.evidence[0].status,
            DependencyPreflightStatus::Present,
            "evidence must mark synced+present roots as present"
        );
    }

    #[test]
    fn test_build_dependency_preflight_report_missing_stale_and_unknown_paths() {
        let _guard = test_guard!();
        let worker = make_test_worker_config("worker-mixed");
        // Use is_primary: true so the missing status triggers blocking.
        let synced_missing = make_sync_entry("/data/projects/repo-missing", true);
        let skipped_stale = make_sync_entry("/data/projects/repo-stale", false);
        let failed_unknown = make_sync_entry("/data/projects/repo-unknown", false);
        let missing_manifest = synced_missing
            .local_root
            .join("Cargo.toml")
            .to_string_lossy()
            .to_string();
        let outcomes = vec![
            (synced_missing, SyncRootOutcome::Synced),
            (
                skipped_stale,
                SyncRootOutcome::Skipped {
                    reason: "transfer skipped by estimator".to_string(),
                },
            ),
            (
                failed_unknown,
                SyncRootOutcome::Failed {
                    error: "rsync timeout".to_string(),
                },
            ),
        ];
        let present = std::collections::BTreeSet::new();
        let missing = std::collections::BTreeSet::from([missing_manifest]);

        let report = build_dependency_preflight_report(
            &worker,
            &outcomes,
            &present,
            &missing,
            Some("probe returned missing markers"),
        );

        assert!(
            !report.verified,
            "missing primary root evidence must block remote execution"
        );
        assert_eq!(
            report.reason_code,
            Some(DEPENDENCY_PREFLIGHT_CODE_MISSING),
            "missing primary should dominate failure reason"
        );
        assert_eq!(
            report.remediation,
            Some(DEPENDENCY_PREFLIGHT_REMEDIATION_MISSING)
        );
        assert!(
            report
                .evidence
                .iter()
                .any(|item| item.status == DependencyPreflightStatus::Missing)
        );
        assert!(
            report
                .evidence
                .iter()
                .any(|item| item.status == DependencyPreflightStatus::Stale)
        );
        assert!(
            report
                .evidence
                .iter()
                .any(|item| item.status == DependencyPreflightStatus::Unknown)
        );
    }

    #[test]
    fn test_e2e_dependency_preflight_stale_fallback_path_maps_reason_code() {
        let _guard = test_guard!();
        let worker = make_test_worker_config("worker-stale");
        // Use is_primary: true so stale status triggers blocking.
        let stale_entry = make_sync_entry("/data/projects/repo-stale-only", true);
        let outcomes = vec![(
            stale_entry,
            SyncRootOutcome::Skipped {
                reason: "bandwidth guard skip".to_string(),
            },
        )];
        let present = std::collections::BTreeSet::new();
        let missing = std::collections::BTreeSet::new();

        let report =
            build_dependency_preflight_report(&worker, &outcomes, &present, &missing, None);

        assert!(!report.verified);
        assert_eq!(report.reason_code, Some(DEPENDENCY_PREFLIGHT_CODE_STALE));
        assert_eq!(
            report.remediation,
            Some(DEPENDENCY_PREFLIGHT_REMEDIATION_STALE)
        );
    }

    #[test]
    fn test_e2e_dependency_preflight_missing_fallback_path_maps_reason_code() {
        let _guard = test_guard!();
        let worker = make_test_worker_config("worker-missing");
        // Use is_primary: true so missing status triggers blocking.
        let entry = make_sync_entry("/data/projects/repo-missing-only", true);
        let manifest = entry
            .local_root
            .join("Cargo.toml")
            .to_string_lossy()
            .to_string();
        let outcomes = vec![(entry, SyncRootOutcome::Synced)];
        let present = std::collections::BTreeSet::new();
        let missing = std::collections::BTreeSet::from([manifest]);

        let report =
            build_dependency_preflight_report(&worker, &outcomes, &present, &missing, None);

        assert!(!report.verified);
        assert_eq!(report.reason_code, Some(DEPENDENCY_PREFLIGHT_CODE_MISSING));
        assert_eq!(
            report.remediation,
            Some(DEPENDENCY_PREFLIGHT_REMEDIATION_MISSING)
        );
    }

    #[tokio::test]
    async fn test_verify_remote_dependency_manifests_blocks_stale_outcomes_deterministically() {
        let _guard = test_guard!();
        // Disable mock mode so verify_remote_dependency_manifests reaches
        // the preflight report logic instead of short-circuiting.
        mock::set_thread_mock_override(Some(false));
        let worker = make_test_worker_config("worker-stale-verify");
        // Use is_primary: true so stale status triggers blocking.
        let outcomes = vec![(
            make_sync_entry("/data/projects/repo-stale-verify", true),
            SyncRootOutcome::Skipped {
                reason: "transfer budget skip".to_string(),
            },
        )];
        let reporter = HookReporter::new(OutputVisibility::Verbose);

        let err = verify_remote_dependency_manifests(&worker, &outcomes, &reporter)
            .await
            .expect_err("stale dependency evidence should block remote execution");
        let preflight = err
            .downcast_ref::<DependencyPreflightFailure>()
            .expect("error should preserve DependencyPreflightFailure type");
        assert_eq!(preflight.reason_code, DEPENDENCY_PREFLIGHT_CODE_STALE);
        assert_eq!(
            preflight.remediation,
            DEPENDENCY_PREFLIGHT_REMEDIATION_STALE
        );
        mock::set_thread_mock_override(None);
    }

    #[test]
    fn test_non_primary_missing_deps_do_not_block_preflight() {
        let _guard = test_guard!();
        let worker = make_test_worker_config("worker-non-primary");
        let primary = make_sync_entry("/data/projects/main-project", true);
        let dep = make_sync_entry("/data/projects/sibling-dep", false);
        let primary_manifest = primary
            .local_root
            .join("Cargo.toml")
            .to_string_lossy()
            .to_string();
        let dep_manifest = dep
            .local_root
            .join("Cargo.toml")
            .to_string_lossy()
            .to_string();

        let outcomes = vec![
            (primary, SyncRootOutcome::Synced),
            (dep, SyncRootOutcome::Synced),
        ];
        let present = std::collections::BTreeSet::from([primary_manifest]);
        let missing = std::collections::BTreeSet::from([dep_manifest]);

        let report =
            build_dependency_preflight_report(&worker, &outcomes, &present, &missing, None);

        assert!(
            report.verified,
            "non-primary missing dep should not block preflight"
        );
        assert!(
            report
                .evidence
                .iter()
                .any(|e| !e.is_primary && e.status == DependencyPreflightStatus::Missing),
            "evidence should still record the non-primary missing status"
        );
    }

    #[test]
    fn test_non_primary_stale_deps_do_not_block_preflight() {
        let _guard = test_guard!();
        let worker = make_test_worker_config("worker-non-primary-stale");
        let primary = make_sync_entry("/data/projects/main-project", true);
        let dep = make_sync_entry("/data/projects/sibling-dep-stale", false);
        let primary_manifest = primary
            .local_root
            .join("Cargo.toml")
            .to_string_lossy()
            .to_string();

        let outcomes = vec![
            (primary, SyncRootOutcome::Synced),
            (
                dep,
                SyncRootOutcome::Skipped {
                    reason: "estimator skip".to_string(),
                },
            ),
        ];
        let present = std::collections::BTreeSet::from([primary_manifest]);
        let missing = std::collections::BTreeSet::new();

        let report =
            build_dependency_preflight_report(&worker, &outcomes, &present, &missing, None);

        assert!(
            report.verified,
            "non-primary stale dep should not block preflight"
        );
    }

    #[test]
    fn test_build_remote_shell_command_wraps_and_escapes_script() {
        let _guard = test_guard!();
        let command = "missing=0; if [ \"$missing\" -ne 0 ]; then echo 'bad'; fi";

        let wrapped = build_remote_shell_command(command);

        assert!(wrapped.starts_with("sh -lc "));
        assert!(
            wrapped.starts_with("sh -lc '"),
            "shell wrapper must quote the script as a single argument"
        );
        assert!(
            !wrapped.starts_with("sh -lc missing=0"),
            "script must not be passed unquoted"
        );
        assert!(
            wrapped.contains("if ["),
            "wrapped command should preserve the full script"
        );
    }

    #[test]
    fn test_build_sync_closure_plan_deterministic_under_permutation() {
        let _guard = test_guard!();
        let temp_dir = tempfile::tempdir_in("/data/projects").expect("create tempdir");
        let project_root = temp_dir.path().join("project");
        let dep_a = temp_dir.path().join("dep_a");
        let dep_b = temp_dir.path().join("dep_b");
        std::fs::create_dir_all(&project_root).expect("create project root");
        std::fs::create_dir_all(&dep_a).expect("create dep_a");
        std::fs::create_dir_all(&dep_b).expect("create dep_b");

        let project_hash = "1234abcd";
        let plan_a = build_sync_closure_plan(
            &[dep_b.clone(), project_root.clone(), dep_a.clone()],
            &project_root,
            project_hash,
        );
        let plan_b = build_sync_closure_plan(
            &[dep_a.clone(), dep_b.clone(), project_root.clone()],
            &project_root,
            project_hash,
        );

        assert_eq!(plan_a, plan_b, "sync closure plan should be deterministic");
        assert!(
            plan_a
                .iter()
                .any(|entry| entry.is_primary && entry.root_hash == project_hash),
            "primary root must retain the closure hash"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_build_sync_closure_plan_dedupes_alias_entries() {
        let _guard = test_guard!();
        use std::os::unix::fs::symlink;

        let temp_dir = tempfile::tempdir_in("/data/projects").expect("create tempdir");
        let project_root = temp_dir.path().join("project");
        let dep = temp_dir.path().join("dep");
        let dep_alias = temp_dir.path().join("dep_alias");
        std::fs::create_dir_all(&project_root).expect("create project root");
        std::fs::create_dir_all(&dep).expect("create dep root");
        symlink(&dep, &dep_alias).expect("create dep alias symlink");

        let dep_canonical = std::fs::canonicalize(&dep).expect("canonicalize dep");
        let plan = build_sync_closure_plan(
            &[dep_alias.clone(), dep.clone(), project_root.clone()],
            &project_root,
            "beefcafe",
        );

        let dep_entries = plan
            .iter()
            .filter(|entry| {
                std::fs::canonicalize(&entry.local_root)
                    .map(|canonical| canonical == dep_canonical)
                    .unwrap_or(false)
            })
            .count();
        assert_eq!(dep_entries, 1, "alias/canonical roots should deduplicate");
    }

    #[tokio::test]
    #[serial(mock_global)]
    async fn test_execute_remote_compilation_syncs_custom_cargo_target_dir_artifacts() {
        let _lock = test_lock().lock().await;
        let _guard = test_guard!();

        let socket_path = format!(
            "/tmp/rch_test_custom_target_artifacts_{}_{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos()
        );

        let _overrides = TestOverridesGuard::set(
            &socket_path,
            MockConfig::default(),
            MockRsyncConfig::success(),
        );
        mock::clear_global_invocations();

        let custom_target_dir = "/data/projects/remote_compilation_helper/.rch-test-target-cache";

        let worker = SelectedWorker {
            id: rch_common::WorkerId::new("mock-worker"),
            host: "mock.host.local".to_string(),
            user: "mockuser".to_string(),
            identity_file: "~/.ssh/mock_key".to_string(),
            slots_available: 8,
            speed_score: 90.0,
        };

        let reporter = HookReporter::new(OutputVisibility::None);
        let result = execute_remote_compilation(
            &worker,
            "cargo build",
            TransferConfig::default(),
            Vec::new(),
            Some(PathBuf::from(custom_target_dir)),
            &rch_common::CompilationConfig::default(),
            None,
            Some(CompilationKind::CargoBuild),
            &reporter,
            &socket_path,
            ColorMode::Auto,
            None,
        )
        .await;

        let execution = result.expect("remote execution should succeed in mock mode");
        assert_eq!(execution.exit_code, 0);

        let rsync_logs = mock::global_rsync_invocations_snapshot();
        let has_custom_target_artifact_sync = rsync_logs.iter().any(|entry| {
            entry.phase == mock::Phase::Artifacts
                && entry.destination == custom_target_dir
                && entry.source.contains(".rch-target")
        });
        assert!(
            has_custom_target_artifact_sync,
            "expected artifact retrieval into custom CARGO_TARGET_DIR from worker .rch-target path"
        );
    }

    #[tokio::test]
    #[serial(mock_global)]
    async fn test_cargo_test_delegates_to_rch_exec() {
        // Test that cargo test commands are delegated to rch exec
        let _lock = test_lock().lock().await;
        let _guard = test_guard!();
        mock::clear_global_invocations();
        crate::config::set_test_config_override(Some(rch_common::RchConfig::default()));

        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: "cargo test".to_string(),
                description: None,
            },
            session_id: None,
        };

        let output = process_hook(input).await;
        crate::config::set_test_config_override(None);

        // Hook should delegate to rch exec
        assert!(
            output.is_allow(),
            "cargo test should be allowed via delegation"
        );
        match &output {
            HookOutput::AllowWithModifiedCommand(modified) => {
                let cmd = &modified.hook_specific_output.updated_input.command;
                assert_eq!(cmd, "rch exec -- cargo test");
            }
            _ => panic!("Expected AllowWithModifiedCommand"),
        }

        // No rsync/SSH during hook - that happens in run_exec
        let rsync_logs = mock::global_rsync_invocations_snapshot();
        let ssh_logs = mock::global_ssh_invocations_snapshot();
        assert!(rsync_logs.is_empty(), "Hook should not invoke rsync");
        assert!(ssh_logs.is_empty(), "Hook should not invoke SSH");
    }

    #[tokio::test]
    #[serial(mock_global)]
    async fn test_cargo_test_with_args_delegates_correctly() {
        // Test that cargo test with arguments is delegated correctly
        let _lock = test_lock().lock().await;
        let _guard = test_guard!();
        mock::clear_global_invocations();
        crate::config::set_test_config_override(Some(rch_common::RchConfig::default()));

        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: "cargo test --release -- --nocapture".to_string(),
                description: None,
            },
            session_id: None,
        };

        let output = process_hook(input).await;
        crate::config::set_test_config_override(None);

        // Hook should delegate with all arguments preserved
        assert!(output.is_allow());
        match &output {
            HookOutput::AllowWithModifiedCommand(modified) => {
                let cmd = &modified.hook_specific_output.updated_input.command;
                assert_eq!(cmd, "rch exec -- cargo test --release -- --nocapture");
            }
            _ => panic!("Expected AllowWithModifiedCommand"),
        }

        // No rsync/SSH during hook
        let rsync_logs = mock::global_rsync_invocations_snapshot();
        let ssh_logs = mock::global_ssh_invocations_snapshot();
        assert!(rsync_logs.is_empty(), "Hook should not invoke rsync");
        assert!(ssh_logs.is_empty(), "Hook should not invoke SSH");
    }

    #[tokio::test]
    #[serial(mock_global)]
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

        // Build failure (exit 1) should use transparent interception with exit code
        // Agent sees the error output and gets correct exit code
        assert!(
            output.is_allow(),
            "cargo test build failure should use transparent interception"
        );
        assert!(
            matches!(output, HookOutput::AllowWithModifiedCommand(_)),
            "cargo test build failure should return AllowWithModifiedCommand"
        );
    }

    #[tokio::test]
    #[serial(mock_global)]
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

        // Filtered test command should use transparent interception
        assert!(
            output.is_allow(),
            "Filtered cargo test should use transparent interception"
        );
        assert!(
            matches!(output, HookOutput::AllowWithModifiedCommand(_)),
            "Filtered cargo test should return AllowWithModifiedCommand"
        );
    }

    #[tokio::test]
    #[serial(mock_global)]
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

        // Should use transparent interception regardless of thread count
        assert!(
            output.is_allow(),
            "cargo test with --test-threads should use transparent interception"
        );
        assert!(
            matches!(output, HookOutput::AllowWithModifiedCommand(_)),
            "cargo test with --test-threads should return AllowWithModifiedCommand"
        );
    }

    #[tokio::test]
    #[serial(mock_global)]
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

        // Signal killed (likely OOM) should use transparent interception with exit code
        assert!(
            output.is_allow(),
            "Signal-killed cargo test should use transparent interception"
        );
        assert!(
            matches!(output, HookOutput::AllowWithModifiedCommand(_)),
            "Signal-killed cargo test should return AllowWithModifiedCommand"
        );
    }

    #[tokio::test]
    #[serial(mock_global)]
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
    fn test_estimate_cores_filtered_never_exceeds_default() {
        let _guard = test_guard!();
        let config = rch_common::CompilationConfig {
            build_slots: 6,
            test_slots: 1, // Single-slot environment
            check_slots: 3,
            ..Default::default()
        };

        let filtered = estimate_cores_for_command(
            Some(CompilationKind::CargoTest),
            "cargo test my_test",
            &config,
        );
        assert_eq!(
            filtered, 1,
            "Filtered tests should not request more slots than test_slots"
        );
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
            false,
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
            false,
        )
        .await;

        let _ = std::fs::remove_file(&socket_path_clone);

        // Partial response should result in error (no body to parse)
        assert!(result.is_err(), "Partial response should result in error");
    }

    #[test]
    fn test_queue_when_busy_enabled_parser() {
        let _guard = test_guard!();
        assert!(queue_when_busy_enabled_from(None));
        assert!(queue_when_busy_enabled_from(Some("1")));
        assert!(queue_when_busy_enabled_from(Some("true")));
        assert!(queue_when_busy_enabled_from(Some("yes")));
        assert!(!queue_when_busy_enabled_from(Some("0")));
        assert!(!queue_when_busy_enabled_from(Some("false")));
        assert!(!queue_when_busy_enabled_from(Some("off")));
    }

    #[test]
    fn test_daemon_response_timeout_defaults_and_overrides() {
        let _guard = test_guard!();
        assert_eq!(
            daemon_response_timeout_for(false, None, None),
            Duration::from_secs(DEFAULT_DAEMON_RESPONSE_TIMEOUT_SECS)
        );
        assert_eq!(
            daemon_response_timeout_for(true, None, None),
            Duration::from_secs(DEFAULT_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS)
        );
        assert_eq!(
            daemon_response_timeout_for(true, None, Some("900")),
            Duration::from_secs(900)
        );
        assert_eq!(
            daemon_response_timeout_for(true, Some("45"), Some("900")),
            Duration::from_secs(45)
        );
        assert_eq!(
            daemon_response_timeout_for(true, Some("invalid"), Some("invalid")),
            Duration::from_secs(DEFAULT_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS)
        );
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

    // ── Multi-root sync manifest & partial failure tests (bd-vvmd.2.3 AC5) ──

    #[test]
    fn test_build_sync_closure_manifest_deterministic_entries() {
        let _guard = test_guard!();
        let temp_dir = tempfile::tempdir_in("/data/projects").expect("create tempdir");
        let project_root = temp_dir.path().join("project");
        let dep_a = temp_dir.path().join("dep_a");
        let dep_b = temp_dir.path().join("dep_b");
        std::fs::create_dir_all(&project_root).expect("create project root");
        std::fs::create_dir_all(&dep_a).expect("create dep_a");
        std::fs::create_dir_all(&dep_b).expect("create dep_b");

        let plan = build_sync_closure_plan(
            &[dep_b.clone(), dep_a.clone(), project_root.clone()],
            &project_root,
            "abc123",
        );
        let manifest_a = build_sync_closure_manifest(&plan, &project_root);
        let manifest_b = build_sync_closure_manifest(&plan, &project_root);

        // Entries must be identical (order, roots, hashes, primary flag).
        assert_eq!(
            manifest_a.entries, manifest_b.entries,
            "manifest entries should be deterministic for the same plan"
        );
        assert_eq!(
            manifest_a.schema_version, manifest_b.schema_version,
            "schema version must be stable"
        );
        assert_eq!(
            manifest_a.project_root, manifest_b.project_root,
            "project root must be stable"
        );
    }

    #[test]
    fn test_build_sync_closure_manifest_schema_version_stable() {
        let _guard = test_guard!();
        let temp_dir = tempfile::tempdir_in("/data/projects").expect("create tempdir");
        let project_root = temp_dir.path().join("project");
        std::fs::create_dir_all(&project_root).expect("create project root");

        let plan = build_sync_closure_plan(
            std::slice::from_ref(&project_root),
            &project_root,
            "deadbeef",
        );
        let manifest = build_sync_closure_manifest(&plan, &project_root);

        assert_eq!(
            manifest.schema_version, "rch.sync_closure_manifest.v1",
            "schema version must match the documented v1 contract"
        );
    }

    #[test]
    fn test_build_sync_closure_manifest_entries_faithfully_represent_plan() {
        let _guard = test_guard!();
        let temp_dir = tempfile::tempdir_in("/data/projects").expect("create tempdir");
        let project_root = temp_dir.path().join("project");
        let dep = temp_dir.path().join("dep");
        std::fs::create_dir_all(&project_root).expect("create project root");
        std::fs::create_dir_all(&dep).expect("create dep");

        let plan = build_sync_closure_plan(
            &[dep.clone(), project_root.clone()],
            &project_root,
            "cafe0001",
        );
        let manifest = build_sync_closure_manifest(&plan, &project_root);

        assert_eq!(
            manifest.entries.len(),
            plan.len(),
            "manifest must have one entry per plan entry"
        );
        for (idx, (plan_entry, manifest_entry)) in
            plan.iter().zip(manifest.entries.iter()).enumerate()
        {
            assert_eq!(manifest_entry.order, idx + 1, "order must be 1-indexed");
            assert_eq!(
                manifest_entry.local_root,
                plan_entry.local_root.to_string_lossy().to_string()
            );
            assert_eq!(manifest_entry.remote_root, plan_entry.remote_root);
            assert_eq!(manifest_entry.project_id, plan_entry.project_id);
            assert_eq!(manifest_entry.root_hash, plan_entry.root_hash);
            assert_eq!(manifest_entry.is_primary, plan_entry.is_primary);
        }
    }

    #[test]
    fn test_build_sync_closure_manifest_primary_root_present() {
        let _guard = test_guard!();
        let temp_dir = tempfile::tempdir_in("/data/projects").expect("create tempdir");
        let project_root = temp_dir.path().join("project");
        let dep = temp_dir.path().join("dep");
        std::fs::create_dir_all(&project_root).expect("create project root");
        std::fs::create_dir_all(&dep).expect("create dep");

        let plan = build_sync_closure_plan(
            &[dep.clone(), project_root.clone()],
            &project_root,
            "primary_hash",
        );
        let manifest = build_sync_closure_manifest(&plan, &project_root);

        let primary_entries: Vec<_> = manifest.entries.iter().filter(|e| e.is_primary).collect();
        assert_eq!(
            primary_entries.len(),
            1,
            "exactly one manifest entry should be the primary root"
        );
        assert_eq!(
            primary_entries[0].root_hash, "primary_hash",
            "primary entry must carry the project-level hash"
        );
    }

    #[test]
    fn test_build_sync_closure_plan_adds_primary_even_when_absent_from_roots() {
        let _guard = test_guard!();
        let temp_dir = tempfile::tempdir_in("/data/projects").expect("create tempdir");
        let project_root = temp_dir.path().join("project");
        let dep = temp_dir.path().join("dep");
        std::fs::create_dir_all(&project_root).expect("create project root");
        std::fs::create_dir_all(&dep).expect("create dep");

        // Deliberately omit project_root from sync_roots list.
        let plan =
            build_sync_closure_plan(std::slice::from_ref(&dep), &project_root, "hash_auto_add");
        let has_primary = plan.iter().any(|e| e.is_primary);
        assert!(
            has_primary,
            "primary root must be auto-added to plan even when not in sync_roots"
        );
        let primary = plan.iter().find(|e| e.is_primary).unwrap();
        assert_eq!(primary.root_hash, "hash_auto_add");
    }

    #[test]
    fn test_sync_root_outcome_diagnostic_counting() {
        let _guard = test_guard!();
        let temp_dir = tempfile::tempdir_in("/data/projects").expect("create tempdir");
        let project_root = temp_dir.path().join("project");
        let dep_a = temp_dir.path().join("dep_a");
        let dep_b = temp_dir.path().join("dep_b");
        let dep_c = temp_dir.path().join("dep_c");
        std::fs::create_dir_all(&project_root).expect("create project root");
        std::fs::create_dir_all(&dep_a).expect("create dep_a");
        std::fs::create_dir_all(&dep_b).expect("create dep_b");
        std::fs::create_dir_all(&dep_c).expect("create dep_c");

        let plan = build_sync_closure_plan(
            &[
                dep_a.clone(),
                dep_b.clone(),
                dep_c.clone(),
                project_root.clone(),
            ],
            &project_root,
            "diag_hash",
        );

        // Simulate outcomes: primary synced, one dep synced, one skipped, one failed.
        let outcomes: Vec<(&SyncClosurePlanEntry, SyncRootOutcome)> = plan
            .iter()
            .map(|entry| {
                let outcome = if entry.is_primary || entry.local_root.ends_with("dep_a") {
                    SyncRootOutcome::Synced
                } else if entry.local_root.ends_with("dep_b") {
                    SyncRootOutcome::Skipped {
                        reason: "size too small".to_string(),
                    }
                } else {
                    SyncRootOutcome::Failed {
                        error: "rsync timeout".to_string(),
                    }
                };
                (entry, outcome)
            })
            .collect();

        let failed_count = outcomes
            .iter()
            .filter(|(_, o)| !matches!(o, SyncRootOutcome::Synced))
            .count();
        assert_eq!(
            failed_count, 2,
            "skipped + failed should count as non-synced"
        );

        let synced_count = outcomes
            .iter()
            .filter(|(_, o)| matches!(o, SyncRootOutcome::Synced))
            .count();
        assert_eq!(synced_count, 2, "primary + dep_a should be synced");
    }

    #[test]
    fn test_build_sync_closure_manifest_serializes_to_json() {
        let _guard = test_guard!();
        let temp_dir = tempfile::tempdir_in("/data/projects").expect("create tempdir");
        let project_root = temp_dir.path().join("project");
        let dep = temp_dir.path().join("dep");
        std::fs::create_dir_all(&project_root).expect("create project root");
        std::fs::create_dir_all(&dep).expect("create dep");

        let plan = build_sync_closure_plan(
            &[dep.clone(), project_root.clone()],
            &project_root,
            "serial_hash",
        );
        let manifest = build_sync_closure_manifest(&plan, &project_root);

        let json =
            serde_json::to_string_pretty(&manifest).expect("manifest should serialize to JSON");
        assert!(
            json.contains("rch.sync_closure_manifest.v1"),
            "JSON must contain schema_version"
        );
        assert!(
            json.contains("serial_hash"),
            "JSON must contain the primary root hash"
        );
        assert!(
            json.contains("\"is_primary\": true"),
            "JSON must contain primary flag"
        );

        // Roundtrip: deserialize should also work for consumers.
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("manifest JSON should be valid");
        let entries = parsed["entries"]
            .as_array()
            .expect("entries should be an array");
        assert_eq!(entries.len(), plan.len());
    }

    // ── Closure topology validation tests (bd-vvmd.2.3 AC3) ──

    #[test]
    fn test_is_within_sync_topology_accepts_canonical_root() {
        let _guard = test_guard!();
        let policy = rch_common::path_topology::PathTopologyPolicy::default();
        let path = PathBuf::from("/data/projects/my_project");
        assert!(
            is_within_sync_topology(&path, &policy),
            "paths under /data/projects should be accepted"
        );
    }

    #[test]
    fn test_is_within_sync_topology_accepts_alias_root() {
        let _guard = test_guard!();
        let policy = rch_common::path_topology::PathTopologyPolicy::default();
        let path = PathBuf::from("/dp/my_project");
        assert!(
            is_within_sync_topology(&path, &policy),
            "paths under /dp alias should be accepted"
        );
    }

    #[test]
    fn test_is_within_sync_topology_rejects_outside_paths() {
        let _guard = test_guard!();
        let policy = rch_common::path_topology::PathTopologyPolicy::default();
        assert!(
            !is_within_sync_topology(Path::new("/tmp/evil"), &policy),
            "/tmp paths should be rejected"
        );
        assert!(
            !is_within_sync_topology(Path::new("/home/user/project"), &policy),
            "/home paths should be rejected"
        );
        assert!(
            !is_within_sync_topology(Path::new("/var/lib/data"), &policy),
            "/var paths should be rejected"
        );
    }

    #[test]
    fn test_build_sync_closure_plan_excludes_out_of_topology_roots() {
        let _guard = test_guard!();
        // Use paths under /data/projects (canonical root) for valid paths,
        // and a /tmp path for the invalid one. Since these dirs may not exist
        // on the test runner, the canonicalization will fall back to the raw
        // path, which is exactly what we want to test.
        let project_root = PathBuf::from("/data/projects/test_proj");
        let valid_dep = PathBuf::from("/data/projects/valid_dep");
        let invalid_dep = PathBuf::from("/tmp/not_allowed");

        let plan = build_sync_closure_plan(
            &[valid_dep.clone(), invalid_dep.clone(), project_root.clone()],
            &project_root,
            "topo_hash",
        );

        // The plan should contain the primary root and valid dep, but NOT the invalid dep.
        let plan_paths: Vec<_> = plan.iter().map(|e| &e.local_root).collect();
        assert!(
            plan_paths
                .iter()
                .any(|p| p.starts_with("/data/projects/test_proj")),
            "primary root must be in plan"
        );
        assert!(
            plan_paths
                .iter()
                .any(|p| p.starts_with("/data/projects/valid_dep")),
            "valid dependency root must be in plan"
        );
        assert!(
            !plan_paths.iter().any(|p| p.starts_with("/tmp")),
            "out-of-topology dependency must be excluded from plan"
        );
    }

    #[test]
    fn test_build_sync_closure_plan_topology_filter_preserves_primary() {
        let _guard = test_guard!();
        // Even with all deps invalid, the primary root must survive.
        let project_root = PathBuf::from("/data/projects/primary_proj");
        let bad_dep_a = PathBuf::from("/home/user/dep_a");
        let bad_dep_b = PathBuf::from("/var/lib/dep_b");

        let plan = build_sync_closure_plan(&[bad_dep_a, bad_dep_b], &project_root, "lonely_hash");

        assert_eq!(plan.len(), 1, "only the primary root should remain");
        assert!(
            plan[0].is_primary,
            "surviving entry must be the primary root"
        );
    }

    // ── bd-3jjc.6: canonicalize_sync_root_for_plan() edge cases ─────────

    #[test]
    fn test_canonicalize_existing_path() {
        let _guard = test_guard!();
        let temp_dir = tempfile::tempdir_in("/data/projects").expect("create tempdir");
        let dir = temp_dir.path().join("real_dir");
        std::fs::create_dir_all(&dir).expect("create dir");

        let result = canonicalize_sync_root_for_plan(&dir);
        // Should be a canonical absolute path containing the dir name.
        assert!(result.is_absolute());
        assert!(
            result.to_string_lossy().contains("real_dir"),
            "canonicalized path should contain dir name: {}",
            result.display()
        );
    }

    #[test]
    fn test_canonicalize_nonexistent_path() {
        let _guard = test_guard!();
        let path = PathBuf::from("/data/projects/does_not_exist_xyz_12345");
        let result = canonicalize_sync_root_for_plan(&path);
        // Fallback: should return original path since normalize and canonicalize both fail.
        assert_eq!(result, path);
    }

    #[test]
    fn test_canonicalize_trailing_slash() {
        let _guard = test_guard!();
        let temp_dir = tempfile::tempdir_in("/data/projects").expect("create tempdir");
        let dir = temp_dir.path().join("trail");
        std::fs::create_dir_all(&dir).expect("create dir");

        let with_trailing = PathBuf::from(format!("{}/", dir.display()));
        let without_trailing = canonicalize_sync_root_for_plan(&dir);
        let with_result = canonicalize_sync_root_for_plan(&with_trailing);
        // Both should resolve to the same canonical path.
        assert_eq!(with_result, without_trailing);
    }

    #[cfg(unix)]
    #[test]
    fn test_canonicalize_symlink() {
        let _guard = test_guard!();
        use std::os::unix::fs::symlink;

        let temp_dir = tempfile::tempdir_in("/data/projects").expect("create tempdir");
        let real_dir = temp_dir.path().join("real");
        let link_dir = temp_dir.path().join("link");
        std::fs::create_dir_all(&real_dir).expect("create real dir");
        symlink(&real_dir, &link_dir).expect("create symlink");

        let from_real = canonicalize_sync_root_for_plan(&real_dir);
        let from_link = canonicalize_sync_root_for_plan(&link_dir);
        assert_eq!(
            from_real, from_link,
            "symlink and real path should canonicalize to the same path"
        );
    }

    #[test]
    fn test_canonicalize_dp_alias() {
        let _guard = test_guard!();
        // /dp is an alias for /data/projects. If /dp symlink exists,
        // canonicalization should resolve through it.
        if Path::new("/dp").exists() {
            let dp_path = PathBuf::from("/dp/remote_compilation_helper");
            let canonical = PathBuf::from("/data/projects/remote_compilation_helper");
            let result = canonicalize_sync_root_for_plan(&dp_path);
            assert_eq!(
                result, canonical,
                "/dp alias should resolve to /data/projects"
            );
        }
        // If /dp doesn't exist, test is effectively a no-op. That's OK —
        // this is an environment-dependent test.
    }

    // ── bd-3jjc.7: is_within_sync_topology() edge cases ─────────────────

    #[test]
    fn test_topology_deeply_nested_accepted() {
        let _guard = test_guard!();
        let policy = rch_common::path_topology::PathTopologyPolicy::default();
        let path = PathBuf::from("/data/projects/a/b/c/d/e/f/g");
        assert!(
            is_within_sync_topology(&path, &policy),
            "deeply nested /data/projects subpaths should be accepted"
        );
    }

    #[test]
    fn test_topology_exact_root_match() {
        let _guard = test_guard!();
        let policy = rch_common::path_topology::PathTopologyPolicy::default();
        // The exact root (/data/projects itself) should be accepted.
        assert!(
            is_within_sync_topology(Path::new("/data/projects"), &policy),
            "/data/projects itself should be accepted"
        );
        assert!(
            is_within_sync_topology(Path::new("/dp"), &policy),
            "/dp itself should be accepted"
        );
    }

    #[test]
    fn test_topology_parent_of_root_rejected() {
        let _guard = test_guard!();
        let policy = rch_common::path_topology::PathTopologyPolicy::default();
        assert!(
            !is_within_sync_topology(Path::new("/data"), &policy),
            "/data (parent of root) should be rejected"
        );
    }

    #[test]
    fn test_topology_prefix_collision_rejected() {
        let _guard = test_guard!();
        let policy = rch_common::path_topology::PathTopologyPolicy::default();
        // /data/projects_extra starts with /data/projects as a string prefix
        // but is NOT a child path. Path::starts_with uses component-based matching.
        assert!(
            !is_within_sync_topology(Path::new("/data/projects_extra"), &policy),
            "/data/projects_extra should be rejected (not a child path)"
        );
    }

    #[test]
    fn test_topology_empty_path_rejected() {
        let _guard = test_guard!();
        let policy = rch_common::path_topology::PathTopologyPolicy::default();
        assert!(
            !is_within_sync_topology(Path::new(""), &policy),
            "empty path should be rejected"
        );
    }

    #[test]
    fn test_topology_root_slash_rejected() {
        let _guard = test_guard!();
        let policy = rch_common::path_topology::PathTopologyPolicy::default();
        assert!(
            !is_within_sync_topology(Path::new("/"), &policy),
            "root path (/) should be rejected"
        );
    }

    // ── bd-3jjc.8: build_sync_closure_plan() edge cases ─────────────────

    #[test]
    fn test_plan_empty_sync_roots() {
        let _guard = test_guard!();
        let project_root = PathBuf::from("/data/projects/solo_project");
        let plan = build_sync_closure_plan(&[], &project_root, "solo_hash");
        assert_eq!(
            plan.len(),
            1,
            "empty sync_roots should produce single primary entry"
        );
        assert!(plan[0].is_primary);
        assert_eq!(plan[0].root_hash, "solo_hash");
    }

    #[test]
    fn test_plan_primary_is_only_root() {
        let _guard = test_guard!();
        let temp_dir = tempfile::tempdir_in("/data/projects").expect("create tempdir");
        let project_root = temp_dir.path().join("only");
        std::fs::create_dir_all(&project_root).expect("create dir");

        let plan = build_sync_closure_plan(
            std::slice::from_ref(&project_root),
            &project_root,
            "only_hash",
        );
        assert_eq!(plan.len(), 1);
        assert!(plan[0].is_primary);
        assert_eq!(plan[0].root_hash, "only_hash");
    }

    #[test]
    fn test_plan_large_root_set() {
        let _guard = test_guard!();
        let temp_dir = tempfile::tempdir_in("/data/projects").expect("create tempdir");
        let project_root = temp_dir.path().join("main_proj");
        std::fs::create_dir_all(&project_root).expect("create main");

        let mut roots = Vec::new();
        for i in 0..100u32 {
            let dep = temp_dir.path().join(format!("dep_{i:04}"));
            std::fs::create_dir_all(&dep).expect("create dep");
            roots.push(dep);
        }
        roots.push(project_root.clone());

        let start = std::time::Instant::now();
        let plan = build_sync_closure_plan(&roots, &project_root, "large_hash");
        let elapsed = start.elapsed();

        // 100 deps + 1 primary (deduped) = 101 entries.
        assert_eq!(plan.len(), 101);
        assert!(
            elapsed.as_millis() < 500,
            "plan build took too long: {elapsed:?}"
        );

        // Verify lexicographic ordering.
        for window in plan.windows(2) {
            assert!(
                window[0].local_root <= window[1].local_root,
                "plan should be lexicographically ordered: {} > {}",
                window[0].local_root.display(),
                window[1].local_root.display(),
            );
        }
    }

    #[test]
    fn test_plan_duplicate_roots_deduped() {
        let _guard = test_guard!();
        let temp_dir = tempfile::tempdir_in("/data/projects").expect("create tempdir");
        let project_root = temp_dir.path().join("proj");
        let dep = temp_dir.path().join("dep");
        std::fs::create_dir_all(&project_root).expect("create proj");
        std::fs::create_dir_all(&dep).expect("create dep");

        let plan = build_sync_closure_plan(
            &[dep.clone(), dep.clone(), dep.clone(), project_root.clone()],
            &project_root,
            "dup_hash",
        );

        // dep appears 3 times in input but should be deduped to 1 entry + primary = 2.
        assert_eq!(plan.len(), 2, "duplicate roots should be deduped");
    }

    #[test]
    fn test_plan_primary_via_dp_alias_canonical() {
        let _guard = test_guard!();
        // If /dp symlink exists, verify /dp/X resolves to /data/projects/X.
        if Path::new("/dp").exists() {
            let dp_path = PathBuf::from("/dp/remote_compilation_helper");
            let canonical = PathBuf::from("/data/projects/remote_compilation_helper");
            let plan = build_sync_closure_plan(&[], &dp_path, "dp_hash");
            assert_eq!(plan.len(), 1);
            assert!(plan[0].is_primary);
            assert_eq!(
                plan[0].local_root, canonical,
                "primary via /dp alias should canonicalize"
            );
        }
    }

    #[test]
    fn test_plan_entry_ordering_is_lexicographic() {
        let _guard = test_guard!();
        let temp_dir = tempfile::tempdir_in("/data/projects").expect("create tempdir");
        let project_root = temp_dir.path().join("proj");
        let dep_z = temp_dir.path().join("z_dep");
        let dep_a = temp_dir.path().join("a_dep");
        let dep_m = temp_dir.path().join("m_dep");
        std::fs::create_dir_all(&project_root).expect("create proj");
        std::fs::create_dir_all(&dep_z).expect("create dep_z");
        std::fs::create_dir_all(&dep_a).expect("create dep_a");
        std::fs::create_dir_all(&dep_m).expect("create dep_m");

        let plan = build_sync_closure_plan(
            &[dep_z, dep_a, dep_m, project_root.clone()],
            &project_root,
            "order_hash",
        );

        for window in plan.windows(2) {
            assert!(
                window[0].local_root <= window[1].local_root,
                "entries must be lexicographically sorted"
            );
        }
    }

    // ── bd-3jjc.9: build_sync_closure_manifest() edge cases ─────────────

    #[test]
    fn test_manifest_empty_plan() {
        let _guard = test_guard!();
        let project_root = PathBuf::from("/data/projects/empty_proj");
        let manifest = build_sync_closure_manifest(&[], &project_root);
        assert_eq!(manifest.entries.len(), 0);
        assert_eq!(manifest.project_root, "/data/projects/empty_proj");
        assert_eq!(manifest.schema_version, "rch.sync_closure_manifest.v1");
    }

    #[test]
    fn test_manifest_generated_at_is_recent() {
        let _guard = test_guard!();
        let temp_dir = tempfile::tempdir_in("/data/projects").expect("create tempdir");
        let project_root = temp_dir.path().join("proj");
        std::fs::create_dir_all(&project_root).expect("create proj");

        let before_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        let plan = build_sync_closure_plan(
            std::slice::from_ref(&project_root),
            &project_root,
            "ts_hash",
        );
        let manifest = build_sync_closure_manifest(&plan, &project_root);
        let after_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        assert!(
            manifest.generated_at_unix_ms >= before_ms,
            "generated_at should be >= start time"
        );
        assert!(
            manifest.generated_at_unix_ms <= after_ms,
            "generated_at should be <= end time"
        );
    }

    #[test]
    fn test_manifest_order_field_sequential() {
        let _guard = test_guard!();
        let temp_dir = tempfile::tempdir_in("/data/projects").expect("create tempdir");
        let project_root = temp_dir.path().join("proj");
        std::fs::create_dir_all(&project_root).expect("create proj");

        let mut roots = Vec::new();
        for i in 0..10u32 {
            let dep = temp_dir.path().join(format!("dep_{i:02}"));
            std::fs::create_dir_all(&dep).expect("create dep");
            roots.push(dep);
        }
        roots.push(project_root.clone());

        let plan = build_sync_closure_plan(&roots, &project_root, "seq_hash");
        let manifest = build_sync_closure_manifest(&plan, &project_root);

        // Order field should be 1-indexed and sequential.
        for (idx, entry) in manifest.entries.iter().enumerate() {
            assert_eq!(
                entry.order,
                idx + 1,
                "order should be 1-indexed sequential, got {} at position {}",
                entry.order,
                idx
            );
        }
    }

    #[test]
    fn test_manifest_unicode_paths() {
        let _guard = test_guard!();
        // Use synthetic plan entries with unicode paths.
        let entries = vec![SyncClosurePlanEntry {
            local_root: PathBuf::from("/data/projects/日本語プロジェクト"),
            remote_root: "/data/projects/日本語プロジェクト".to_string(),
            project_id: "日本語".to_string(),
            root_hash: "unicode_hash".to_string(),
            is_primary: true,
        }];
        let manifest =
            build_sync_closure_manifest(&entries, Path::new("/data/projects/日本語プロジェクト"));
        assert_eq!(manifest.entries.len(), 1);
        assert!(manifest.entries[0].local_root.contains("日本語"));

        // Verify JSON serialization handles unicode.
        let json = serde_json::to_string(&manifest).expect("should serialize unicode");
        assert!(json.contains("日本語"));
    }

    #[test]
    fn test_manifest_long_strings() {
        let _guard = test_guard!();
        let long_id = "x".repeat(10_000);
        let long_hash = "h".repeat(10_000);
        let entries = vec![SyncClosurePlanEntry {
            local_root: PathBuf::from("/data/projects/long_test"),
            remote_root: "/data/projects/long_test".to_string(),
            project_id: long_id.clone(),
            root_hash: long_hash.clone(),
            is_primary: true,
        }];
        let manifest = build_sync_closure_manifest(&entries, Path::new("/data/projects/long_test"));
        assert_eq!(
            manifest.entries[0].project_id, long_id,
            "project_id should not be truncated"
        );
        assert_eq!(
            manifest.entries[0].root_hash, long_hash,
            "root_hash should not be truncated"
        );
    }

    // ── bd-3jjc.10: SyncRootOutcome variant coverage ────────────────────

    #[test]
    fn test_sync_root_outcome_all_synced() {
        let _guard = test_guard!();
        let outcomes: Vec<SyncRootOutcome> = (0..5).map(|_| SyncRootOutcome::Synced).collect();
        let non_synced = outcomes
            .iter()
            .filter(|o| !matches!(o, SyncRootOutcome::Synced))
            .count();
        assert_eq!(non_synced, 0);
    }

    #[test]
    fn test_sync_root_outcome_all_failed() {
        let _guard = test_guard!();
        let outcomes: Vec<SyncRootOutcome> = (0..3)
            .map(|i| SyncRootOutcome::Failed {
                error: format!("error_{i}"),
            })
            .collect();
        let failed_count = outcomes
            .iter()
            .filter(|o| matches!(o, SyncRootOutcome::Failed { .. }))
            .count();
        assert_eq!(failed_count, 3);

        // Verify error messages are preserved.
        let errors: Vec<&str> = outcomes
            .iter()
            .filter_map(|o| match o {
                SyncRootOutcome::Failed { error } => Some(error.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(errors, vec!["error_0", "error_1", "error_2"]);
    }

    #[test]
    fn test_sync_root_outcome_all_skipped() {
        let _guard = test_guard!();
        let outcomes: Vec<SyncRootOutcome> = (0..4)
            .map(|i| SyncRootOutcome::Skipped {
                reason: format!("reason_{i}"),
            })
            .collect();
        let skipped_count = outcomes
            .iter()
            .filter(|o| matches!(o, SyncRootOutcome::Skipped { .. }))
            .count();
        assert_eq!(skipped_count, 4);
    }

    #[test]
    fn test_sync_root_outcome_empty_collection() {
        let _guard = test_guard!();
        let outcomes: Vec<SyncRootOutcome> = vec![];
        let synced = outcomes
            .iter()
            .filter(|o| matches!(o, SyncRootOutcome::Synced))
            .count();
        let failed = outcomes
            .iter()
            .filter(|o| matches!(o, SyncRootOutcome::Failed { .. }))
            .count();
        let skipped = outcomes
            .iter()
            .filter(|o| matches!(o, SyncRootOutcome::Skipped { .. }))
            .count();
        assert_eq!(synced, 0);
        assert_eq!(failed, 0);
        assert_eq!(skipped, 0);
    }

    #[test]
    fn test_sync_root_outcome_mixed_with_reasons() {
        let _guard = test_guard!();
        let outcomes = [
            SyncRootOutcome::Synced,
            SyncRootOutcome::Synced,
            SyncRootOutcome::Skipped {
                reason: "stale".to_string(),
            },
            SyncRootOutcome::Failed {
                error: "timeout".to_string(),
            },
            SyncRootOutcome::Skipped {
                reason: "denied".to_string(),
            },
        ];

        let synced = outcomes
            .iter()
            .filter(|o| matches!(o, SyncRootOutcome::Synced))
            .count();
        let failed = outcomes
            .iter()
            .filter(|o| matches!(o, SyncRootOutcome::Failed { .. }))
            .count();
        let skipped = outcomes
            .iter()
            .filter(|o| matches!(o, SyncRootOutcome::Skipped { .. }))
            .count();

        assert_eq!(synced, 2);
        assert_eq!(failed, 1);
        assert_eq!(skipped, 2);

        // Verify reason extraction.
        let skip_reasons: Vec<&str> = outcomes
            .iter()
            .filter_map(|o| match o {
                SyncRootOutcome::Skipped { reason } => Some(reason.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(skip_reasons, vec!["stale", "denied"]);

        let error_msgs: Vec<&str> = outcomes
            .iter()
            .filter_map(|o| match o {
                SyncRootOutcome::Failed { error } => Some(error.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(error_msgs, vec!["timeout"]);
    }

    // ── bd-3jjc.13: E2E sync closure plan + manifest generation ─────────

    #[test]
    fn test_e2e_sync_closure_plan_and_manifest() {
        let _guard = test_guard!();
        let temp_dir = tempfile::tempdir_in("/data/projects").expect("create tempdir");
        let primary = temp_dir.path().join("primary_project");
        let dep_a = temp_dir.path().join("dep_a");
        let dep_b = temp_dir.path().join("dep_b");
        std::fs::create_dir_all(&primary).expect("create primary");
        std::fs::create_dir_all(&dep_a).expect("create dep_a");
        std::fs::create_dir_all(&dep_b).expect("create dep_b");

        // Step 2: Build plan with valid deps + invalid /tmp dep.
        let plan = build_sync_closure_plan(
            &[
                primary.clone(),
                dep_a.clone(),
                dep_b.clone(),
                PathBuf::from("/tmp/invalid_dep"),
            ],
            &primary,
            "e2e_hash",
        );

        // Step 3: 3 entries (primary, dep_a, dep_b), /tmp excluded.
        assert_eq!(
            plan.len(),
            3,
            "plan should have 3 entries (primary + 2 deps), got {}",
            plan.len()
        );
        assert!(
            !plan
                .iter()
                .any(|e| e.local_root.to_string_lossy().contains("/tmp")),
            "/tmp dep should be excluded by topology filter"
        );

        // Step 4: Verify lexicographic ordering.
        for window in plan.windows(2) {
            assert!(
                window[0].local_root <= window[1].local_root,
                "plan entries should be lexicographically sorted"
            );
        }

        // Step 5: Primary entry has is_primary=true with correct hash.
        let primary_entry = plan
            .iter()
            .find(|e| e.is_primary)
            .expect("primary must exist");
        assert_eq!(primary_entry.root_hash, "e2e_hash");
        let non_primary: Vec<_> = plan.iter().filter(|e| !e.is_primary).collect();
        assert_eq!(non_primary.len(), 2, "should have 2 non-primary entries");

        // Step 6-7: Generate manifest.
        let before_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        let manifest = build_sync_closure_manifest(&plan, &primary);
        let after_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        assert_eq!(manifest.schema_version, "rch.sync_closure_manifest.v1");
        assert_eq!(manifest.entries.len(), 3);
        assert!(manifest.generated_at_unix_ms >= before_ms);
        assert!(manifest.generated_at_unix_ms <= after_ms);

        // Step 8-9: JSON roundtrip.
        let json = serde_json::to_string_pretty(&manifest).expect("serialize");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse");
        let entries = parsed["entries"].as_array().expect("entries array");
        assert_eq!(entries.len(), 3);

        // Step 10: Verify order fields are 1-indexed sequential.
        for (idx, entry) in manifest.entries.iter().enumerate() {
            assert_eq!(entry.order, idx + 1, "order should be 1-indexed sequential");
            assert_eq!(entry.is_primary, plan[idx].is_primary);
            assert_eq!(entry.root_hash, plan[idx].root_hash);
        }
    }

    // ── bd-3jjc.15: E2E topology validation with symlinks ───────────────

    #[cfg(unix)]
    #[test]
    fn test_e2e_topology_validation_with_symlinks() {
        let _guard = test_guard!();
        use std::os::unix::fs::symlink;

        let temp_dir = tempfile::tempdir_in("/data/projects").expect("create tempdir");
        let valid_root = temp_dir.path().join("valid_root");
        let valid_sub = valid_root.join("sub");
        std::fs::create_dir_all(&valid_sub).expect("create valid_root/sub");

        let primary = temp_dir.path().join("primary");
        std::fs::create_dir_all(&primary).expect("create primary");

        // Create symlink alias within the same tempdir.
        let alias_link = temp_dir.path().join("alias_for_valid");
        symlink(&valid_root, &alias_link).expect("create symlink");

        // Build plan with mixed valid/invalid/alias paths.
        let plan = build_sync_closure_plan(
            &[
                valid_root.clone(),
                alias_link.clone(), // should dedup with valid_root
                PathBuf::from("/tmp/should_reject"),
                PathBuf::from("/home/fake/project"),
                PathBuf::from("/var/lib/something"),
                primary.clone(),
            ],
            &primary,
            "topo_e2e_hash",
        );

        // Should contain primary + valid_root (deduped with alias) = 2 entries.
        assert_eq!(
            plan.len(),
            2,
            "plan should have 2 entries (primary + deduped valid_root), got {}",
            plan.len()
        );

        // Verify /tmp, /home, /var paths were excluded.
        for entry in &plan {
            let path_str = entry.local_root.to_string_lossy();
            assert!(
                !path_str.starts_with("/tmp")
                    && !path_str.starts_with("/home")
                    && !path_str.starts_with("/var"),
                "out-of-topology path should not appear in plan: {}",
                path_str
            );
        }

        // Verify alias was deduplicated (only one entry for valid_root).
        let valid_canonical = std::fs::canonicalize(&valid_root).expect("canonicalize");
        let matching_entries = plan
            .iter()
            .filter(|e| {
                std::fs::canonicalize(&e.local_root)
                    .map(|c| c == valid_canonical)
                    .unwrap_or(false)
            })
            .count();
        assert_eq!(
            matching_entries, 1,
            "symlink alias should be deduplicated with canonical path"
        );

        // Verify primary is present.
        assert!(
            plan.iter().any(|e| e.is_primary),
            "primary root must always be in plan"
        );
    }

    // =========================================================================
    // Regression suite: Classification timing budget & edge cases (bd-vvmd.2.9)
    // =========================================================================

    /// Verify classification completes well within the 5ms panic threshold for
    /// compilation commands, and within 1ms for non-compilation commands.
    /// This acts as a regression gate: if any code change blows the budget,
    /// this test catches it.
    #[test]
    fn test_classification_timing_budget_non_compilation() {
        let _guard = test_guard!();
        let non_compilation_cmds = [
            "ls -la",
            "pwd",
            "git status",
            "echo hello world",
            "cat Cargo.toml",
            "npm install",
            "python main.py",
            "docker build -t myapp .",
            "mkdir -p build",
            "rm -rf target/",
        ];

        for cmd in non_compilation_cmds {
            let start = std::time::Instant::now();
            for _ in 0..100 {
                let _ = classify_command(cmd);
            }
            let elapsed = start.elapsed();
            let per_call_us = elapsed.as_micros() / 100;
            // Non-compilation: budget <1ms, panic at 5ms
            // We check the median is under 1ms (1000us)
            assert!(
                per_call_us < 1000,
                "Non-compilation command {:?} exceeded 1ms budget: {}us per call",
                cmd,
                per_call_us
            );
        }
    }

    #[test]
    fn test_classification_timing_budget_compilation() {
        let _guard = test_guard!();
        let compilation_cmds = [
            "cargo build --release",
            "cargo test --workspace",
            "cargo clippy --all-targets",
            "gcc -c main.c -o main.o",
            "make -j8",
            "bun test",
            "rustc main.rs",
            "ninja -j4",
        ];

        for cmd in compilation_cmds {
            let start = std::time::Instant::now();
            for _ in 0..100 {
                let _ = classify_command(cmd);
            }
            let elapsed = start.elapsed();
            let per_call_us = elapsed.as_micros() / 100;
            // Compilation: budget <5ms, panic at 10ms
            assert!(
                per_call_us < 5000,
                "Compilation command {:?} exceeded 5ms budget: {}us per call",
                cmd,
                per_call_us
            );
        }
    }

    /// Verify that process_hook handles compilation commands correctly when
    /// daemon is absent — the classification MUST work, and the hook MUST
    /// fail-open to allow local execution.
    #[tokio::test]
    async fn test_hook_classification_fail_open_all_compilation_kinds() {
        let _lock = test_lock().lock().await;
        mock::set_mock_enabled_override(Some(false));

        let compilation_commands = [
            ("cargo build --release", "CargoBuild"),
            ("cargo test --workspace", "CargoTest"),
            ("cargo check --all-targets", "CargoCheck"),
            ("cargo clippy", "CargoClippy"),
            ("cargo doc --no-deps", "CargoDoc"),
            ("cargo run", "CargoRun"),
            ("cargo bench", "CargoBench"),
            ("cargo nextest run", "CargoNextest"),
            ("bun test", "BunTest"),
            ("bun typecheck", "BunTypecheck"),
        ];

        for (cmd, label) in compilation_commands {
            let input = HookInput {
                tool_name: "Bash".to_string(),
                tool_input: ToolInput {
                    command: cmd.to_string(),
                    description: None,
                },
                session_id: None,
            };

            let output = process_hook(input).await;
            assert!(
                output.is_allow(),
                "Hook should fail-open for {} ({}) when daemon absent",
                label,
                cmd
            );
        }

        mock::set_mock_enabled_override(None);
    }

    /// Verify that non-compilation commands pass through the hook immediately
    /// (are allowed without daemon interaction).
    #[tokio::test]
    async fn test_hook_non_compilation_passthrough() {
        let non_compilation = [
            "ls -la",
            "git status",
            "cargo fmt --check",
            "cargo install ripgrep",
            "bun install",
            "bun run dev",
            "echo hello",
            "cat Cargo.toml",
        ];

        for cmd in non_compilation {
            let input = HookInput {
                tool_name: "Bash".to_string(),
                tool_input: ToolInput {
                    command: cmd.to_string(),
                    description: None,
                },
                session_id: None,
            };

            let output = process_hook(input).await;
            assert!(
                output.is_allow(),
                "Non-compilation command {:?} should pass through the hook (Allow)",
                cmd
            );
        }
    }

    /// Verify that non-Bash tool invocations are always allowed.
    #[tokio::test]
    async fn test_hook_non_bash_tools_always_allowed() {
        let tools = ["Read", "Write", "Edit", "Glob", "Grep", "WebSearch"];

        for tool in tools {
            let input = HookInput {
                tool_name: tool.to_string(),
                tool_input: ToolInput {
                    command: "cargo build".to_string(), // Even compilation keyword
                    description: None,
                },
                session_id: None,
            };

            let output = process_hook(input).await;
            assert!(
                output.is_allow(),
                "Non-Bash tool {:?} should always be allowed, even with compilation keyword",
                tool
            );
        }
    }

    /// Verify that classify_command_detailed produces valid structured output
    /// for every tier decision path, enabling structured logging.
    #[test]
    fn test_structured_log_output_per_tier() {
        let _guard = test_guard!();

        // Tier 0 reject: empty command
        let d = classify_command_detailed("");
        assert_eq!(d.tiers.len(), 1);
        assert_eq!(d.tiers[0].tier, 0);
        assert_eq!(d.tiers[0].decision, TierDecision::Reject);
        assert!(!d.tiers[0].reason.is_empty());

        // Tier 1 reject: piped command
        let d = classify_command_detailed("cargo build | tee log");
        assert!(
            d.tiers
                .iter()
                .any(|t| t.tier == 1 && t.decision == TierDecision::Reject)
        );

        // Tier 2 reject: no keyword
        let d = classify_command_detailed("ls -la");
        assert!(
            d.tiers
                .iter()
                .any(|t| t.tier == 2 && t.decision == TierDecision::Reject)
        );

        // Tier 3 reject: never-intercept
        let d = classify_command_detailed("cargo install serde");
        assert!(
            d.tiers
                .iter()
                .any(|t| t.tier == 3 && t.decision == TierDecision::Reject)
        );

        // Tier 4 pass: full classification
        let d = classify_command_detailed("cargo build --release");
        assert!(
            d.tiers
                .iter()
                .any(|t| t.tier == 4 && t.decision == TierDecision::Pass)
        );
        assert!(d.classification.is_compilation);
        assert!(d.classification.confidence > 0.0);
        assert!(d.classification.kind.is_some());

        // Tier 4 reject: keyword present but no matching pattern
        let d = classify_command_detailed("cargo tree");
        assert!(
            d.tiers
                .iter()
                .any(|t| t.tier == 4 && t.decision == TierDecision::Reject)
        );
    }
}
