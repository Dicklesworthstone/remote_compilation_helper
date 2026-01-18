//! PreToolUse hook implementation.
//!
//! Handles incoming hook requests from Claude Code, classifies commands,
//! and routes compilation commands to remote workers.

use crate::config::load_config;
use crate::error::{DaemonError, TransferError};
use crate::toolchain::detect_toolchain;
use crate::transfer::{
    TransferPipeline, compute_project_hash, default_bun_artifact_patterns,
    default_c_cpp_artifact_patterns, default_rust_artifact_patterns,
    default_rust_test_artifact_patterns, project_id_from_path,
};
use rch_common::{
    ColorMode, CompilationKind, HookInput, HookOutput, OutputVisibility, RequiredRuntime,
    SelectedWorker, SelectionResponse, ToolchainInfo, TransferConfig, WorkerConfig, WorkerId,
    classify_command,
};
use rch_telemetry::protocol::{
    PIGGYBACK_MARKER, TelemetrySource, TestRunRecord, WorkerTelemetry,
    extract_piggybacked_telemetry,
};
use std::io::{self, BufRead, Write};
use std::path::Path;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tracing::{debug, info, warn};

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

/// Run the hook, reading from stdin and writing to stdout.
pub async fn run_hook() -> anyhow::Result<()> {
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    // Read all input from stdin
    let mut input = String::new();
    for line in stdin.lock().lines() {
        input.push_str(&line?);
        input.push('\n');
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

fn estimate_local_time_ms(remote_ms: u64, worker_speed_score: f64) -> Option<u64> {
    if remote_ms == 0 || worker_speed_score <= 0.0 {
        return None;
    }
    let normalized = worker_speed_score.clamp(1.0, 100.0);
    let estimate = (remote_ms as f64) * (100.0 / normalized);
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

fn parse_jobs_flag(command: &str) -> Option<u32> {
    let tokens: Vec<&str> = command.split_whitespace().collect();
    for (idx, token) in tokens.iter().enumerate() {
        if *token == "-j" || *token == "--jobs" {
            if let Some(next) = tokens.get(idx + 1) {
                if let Some(value) = parse_u32(next) {
                    return Some(value);
                }
            }
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
        if *token == "--test-threads" {
            if let Some(next) = tokens.get(idx + 1) {
                if let Some(value) = parse_u32(next) {
                    return Some(value);
                }
            }
        }
        if let Some(value) = token.strip_prefix("--test-threads=").and_then(parse_u32) {
            return Some(value);
        }
    }
    None
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
        if flags_with_args.iter().any(|&f| token == f) {
            // Skip this flag and its argument
            i += 2;
            continue;
        }

        // Check if this is a flag=value style
        if flags_with_args.iter().any(|&f| token.starts_with(&format!("{}=", f))) {
            i += 1;
            continue;
        }

        // Check if this is a standalone flag
        if standalone_flags.iter().any(|&f| token == f) {
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
/// Tests marked with #[ignore] are typically a small subset, so they need
/// fewer slots. However, --include-ignored runs all tests plus ignored ones.
fn has_ignored_only_flag(command: &str) -> bool {
    let tokens: Vec<&str> = command.split_whitespace().collect();

    // Look for "--ignored" but not "--include-ignored"
    let has_ignored = tokens.iter().any(|&t| t == "--ignored");
    let has_include_ignored = tokens.iter().any(|&t| t == "--include-ignored");

    // Only return true for --ignored without --include-ignored
    has_ignored && !has_include_ignored
}

/// Check if the command has the --exact flag for exact test name matching.
///
/// Exact matching typically results in running a single test.
fn has_exact_flag(command: &str) -> bool {
    command.split_whitespace().any(|t| t == "--exact")
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
            // 2. RUST_TEST_THREADS environment variable
            // 3. Inferred from test filtering (reduced slots)
            // 4. Default test_slots from config
            if let Some(threads) = parse_test_threads(command) {
                return threads.max(1);
            }
            if let Some(threads) = parse_env_u32(command, "RUST_TEST_THREADS") {
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
            .unwrap_or(check_default)
            .max(1),
        Some(_) => parse_jobs_flag(command)
            .or_else(|| parse_env_u32(command, "CARGO_BUILD_JOBS"))
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

    let command = &input.tool_input.command;
    debug!("Processing command: {}", command);

    // Classify the command using 5-tier system
    // Per AGENTS.md: non-compilation decisions must complete in <1ms, compilation in <5ms
    let classify_start = Instant::now();
    let classification = classify_command(command);
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
    let confidence_threshold = config.compilation.confidence_threshold;
    if classification.confidence < confidence_threshold {
        debug!(
            "Confidence {:.2} below threshold {:.2}, allowing local execution",
            classification.confidence, confidence_threshold
        );
        reporter.summary("[RCH] local (confidence below threshold)");
        return HookOutput::allow();
    }

    // Query daemon for a worker
    let project = extract_project_name();
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

    match query_daemon(
        &config.general.socket_path,
        &project,
        estimated_cores,
        toolchain.as_ref(),
        required_runtime,
        classification_duration_us,
    )
    .await
    {
        Ok(response) => {
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
                &config.compilation,
                toolchain.as_ref(),
                classification.kind,
                &reporter,
                &config.general.socket_path,
                config.output.color_mode,
            )
            .await;
            let remote_elapsed = remote_start.elapsed();

            // Always release slots after execution
            if let Err(e) =
                release_worker(&config.general.socket_path, &worker.id, estimated_cores).await
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

                        if !config.output.first_run_complete {
                            let local_estimate =
                                estimate_local_time_ms(result.duration_ms, worker.speed_score);
                            emit_first_run_message(&worker, result.duration_ms, local_estimate);
                            if let Err(e) = crate::config::set_first_run_complete(true) {
                                warn!("Failed to persist first_run_complete: {}", e);
                            }
                        }

                        HookOutput::deny(
                            "RCH: Command executed successfully on remote worker".to_string(),
                        )
                    } else if is_toolchain_failure(&result.stderr, result.exit_code) {
                        // Toolchain failure - fall back to local execution
                        warn!(
                            "Remote toolchain failure detected (exit {}), falling back to local",
                            result.exit_code
                        );
                        reporter
                            .summary(&format!("[RCH] local (toolchain missing on {})", worker.id));
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
                            reporter.summary(&format!(
                                "[RCH] remote {} build error",
                                worker.id
                            ));
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

                        HookOutput::deny(format!(
                            "RCH: Remote compilation failed with exit code {}",
                            exit_code
                        ))
                    }
                }
                Err(e) => {
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
        Err(e) => {
            warn!("Failed to query daemon: {}, allowing local execution", e);
            reporter.summary("[RCH] local (daemon unavailable)");
            HookOutput::allow()
        }
    }
}

/// Query the daemon for a worker.
pub(crate) async fn query_daemon(
    socket_path: &str,
    project: &str,
    cores: u32,
    toolchain: Option<&ToolchainInfo>,
    required_runtime: RequiredRuntime,
    classification_duration_us: u64,
) -> anyhow::Result<SelectionResponse> {
    // Check if socket exists
    if !Path::new(socket_path).exists() {
        return Err(DaemonError::SocketNotFound {
            socket_path: socket_path.to_string(),
        }
        .into());
    }

    // Connect to daemon
    let stream = UnixStream::connect(socket_path).await?;
    let (reader, mut writer) = stream.into_split();

    // Build query string
    let mut query = format!("project={}&cores={}", urlencoding_encode(project), cores);

    if let Some(tc) = toolchain {
        if let Ok(json) = serde_json::to_string(tc) {
            query.push_str(&format!("&toolchain={}", urlencoding_encode(&json)));
        }
    }

    if required_runtime != RequiredRuntime::None {
        // Serialize to lowercase string (rust, bun, node)
        // Since it's an enum with lowercase serialization, serde_json::to_string gives "rust" (with quotes)
        // We want just the string.
        let json = serde_json::to_string(&required_runtime).unwrap_or_default();
        let raw = json.trim_matches('"');
        query.push_str(&format!("&runtime={}", urlencoding_encode(raw)));
    }

    // Add classification duration for AGENTS.md compliance tracking
    query.push_str(&format!(
        "&classification_us={}",
        classification_duration_us
    ));

    // Send request
    let request = format!("GET /select-worker?{}\n", query);
    writer.write_all(request.as_bytes()).await?;
    writer.flush().await?;

    // Read response (skip HTTP headers)
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

    // Parse response
    let response: SelectionResponse = serde_json::from_str(body.trim())?;
    Ok(response)
}

/// Release reserved slots on a worker.
pub(crate) async fn release_worker(
    socket_path: &str,
    worker_id: &WorkerId,
    slots: u32,
) -> anyhow::Result<()> {
    if !Path::new(socket_path).exists() {
        return Ok(()); // Ignore if daemon gone
    }

    let stream = UnixStream::connect(socket_path).await?;
    let (reader, mut writer) = stream.into_split();

    // Send request
    let request = format!(
        "POST /release-worker?worker={}&slots={}\n",
        urlencoding_encode(worker_id.as_str()),
        slots
    );
    writer.write_all(request.as_bytes()).await?;
    writer.flush().await?;

    // Read response line (to ensure daemon processed it)
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    reader.read_line(&mut line).await?;

    Ok(())
}

/// URL percent-encoding for query parameters.
///
/// Encodes characters that are not URL-safe (RFC 3986 unreserved characters).
fn urlencoding_encode(s: &str) -> String {
    let mut result = String::with_capacity(s.len() * 3); // Worst case: all encoded

    for c in s.chars() {
        match c {
            // Unreserved characters (RFC 3986) - don't encode
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => {
                result.push(c);
            }
            // Everything else needs encoding
            _ => {
                // Encode as UTF-8 bytes
                for byte in c.to_string().as_bytes() {
                    result.push('%');
                    result.push_str(&format!("{:02X}", byte));
                }
            }
        }
    }

    result
}

/// Extract project name from current working directory.
fn extract_project_name() -> String {
    std::env::current_dir()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
        .unwrap_or_else(|| "unknown".to_string())
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
    compilation_config: &rch_common::CompilationConfig,
    toolchain: Option<&ToolchainInfo>,
    kind: Option<CompilationKind>,
    reporter: &HookReporter,
    socket_path: &str,
    color_mode: ColorMode,
) -> anyhow::Result<RemoteExecutionResult> {
    let worker_config = selected_worker_to_config(worker);

    // Get current working directory as project root
    let project_root =
        std::env::current_dir().map_err(|e| TransferError::NoProjectRoot { source: e })?;

    let project_id = project_id_from_path(&project_root);
    let project_hash = compute_project_hash(&project_root);

    info!(
        "Starting remote compilation pipeline for {} (hash: {})",
        project_id, project_hash
    );
    reporter.verbose(&format!(
        "[RCH] sync start (project {} on {})",
        project_id, worker_config.id
    ));

    // Create transfer pipeline with color mode and command timeout
    let command_timeout = compilation_config.timeout_for_kind(kind);
    let pipeline = TransferPipeline::new(
        project_root.clone(),
        project_id.clone(),
        project_hash,
        transfer_config,
    )
    .with_color_mode(color_mode)
    .with_command_timeout(command_timeout);

    // Step 1: Sync project to remote
    info!("Syncing project to worker {}...", worker_config.id);
    let sync_result = pipeline.sync_to_remote(&worker_config).await?;
    info!(
        "Sync complete: {} files, {} bytes in {}ms",
        sync_result.files_transferred, sync_result.bytes_transferred, sync_result.duration_ms
    );
    reporter.verbose(&format!(
        "[RCH] sync done: {} files, {} bytes in {}ms",
        sync_result.files_transferred, sync_result.bytes_transferred, sync_result.duration_ms
    ));

    // Step 2: Execute command remotely with streaming output
    info!("Executing command remotely: {}", command);
    reporter.verbose(&format!("[RCH] exec start: {}", command));

    // Capture stderr for toolchain failure detection
    let mut stderr_capture = String::new();

    // Stream stdout/stderr to our stderr so the agent sees the output
    let command_with_telemetry = wrap_command_with_telemetry(command, &worker_config.id);
    let mut suppress_telemetry = false;

    let result = pipeline
        .execute_remote_streaming(
            &worker_config,
            &command_with_telemetry,
            toolchain,
            |line| {
                if suppress_telemetry {
                    return;
                }
                if line.trim() == PIGGYBACK_MARKER {
                    suppress_telemetry = true;
                    return;
                }
                // Write stdout lines to stderr (hook stdout is for protocol)
                eprint!("{}", line);
            },
            |line| {
                // Write stderr lines to stderr and capture for analysis
                eprint!("{}", line);
                stderr_capture.push_str(line);
            },
        )
        .await?;

    info!(
        "Remote command finished: exit={} in {}ms",
        result.exit_code, result.duration_ms
    );
    reporter.verbose(&format!(
        "[RCH] exec done: exit={} in {}ms",
        result.exit_code, result.duration_ms
    ));

    // Step 3: Retrieve artifacts
    if result.success() {
        info!("Retrieving build artifacts...");
        reporter.verbose("[RCH] artifacts: retrieving...");
        let artifact_patterns = get_artifact_patterns(kind);
        match pipeline
            .retrieve_artifacts(&worker_config, &artifact_patterns)
            .await
        {
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
            }
            Err(e) => {
                warn!("Failed to retrieve artifacts: {}", e);
                reporter.verbose("[RCH] artifacts failed (continuing)");
                // Continue anyway - compilation succeeded
            }
        }
    }

    // Step 4: Extract and forward telemetry (piggybacked in stdout)
    let extraction = extract_piggybacked_telemetry(&result.stdout);
    if let Some(error) = extraction.extraction_error {
        warn!("Telemetry extraction failed: {}", error);
    }
    if let Some(telemetry) = extraction.telemetry {
        if let Err(e) = send_telemetry(socket_path, TelemetrySource::Piggyback, &telemetry).await {
            warn!("Failed to forward telemetry to daemon: {}", e);
        }
    }

    if is_test_kind(kind) {
        if let Some(kind) = kind {
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
    }

    Ok(RemoteExecutionResult {
        exit_code: result.exit_code,
        stderr: stderr_capture,
        duration_ms: result.duration_ms,
    })
}

fn wrap_command_with_telemetry(command: &str, worker_id: &WorkerId) -> String {
    let escaped_worker = shell_escape::escape(worker_id.as_str().into());
    format!(
        "{cmd}; status=$?; if command -v rch-telemetry >/dev/null 2>&1; then \
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

    let stream = UnixStream::connect(socket_path).await?;
    let (reader, mut writer) = stream.into_split();

    let body = telemetry.to_json()?;
    let request = format!(
        "POST /telemetry?source={}\n{}\n",
        urlencoding_encode(&source.to_string()),
        body
    );

    writer.write_all(request.as_bytes()).await?;
    writer.flush().await?;

    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    reader.read_line(&mut line).await?;

    Ok(())
}

async fn send_test_run(socket_path: &str, record: &TestRunRecord) -> anyhow::Result<()> {
    if !Path::new(socket_path).exists() {
        return Ok(());
    }

    let stream = UnixStream::connect(socket_path).await?;
    let (reader, mut writer) = stream.into_split();

    let body = record.to_json()?;
    let request = format!("POST /test-run\n{}\n", body);

    writer.write_all(request.as_bytes()).await?;
    writer.flush().await?;

    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    reader.read_line(&mut line).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rch_common::mock::{
        self, MockConfig, MockRsyncConfig, Phase, clear_mock_overrides, set_mock_enabled_override,
        set_mock_rsync_config_override, set_mock_ssh_config_override,
    };
    use rch_common::{SelectionReason, ToolInput};
    use std::sync::OnceLock;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};
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
        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: "cargo build --release".to_string(),
                description: None,
            },
            session_id: None,
        };

        // Currently allows because remote execution not implemented
        let output = process_hook(input).await;
        assert!(output.is_allow());
    }

    #[test]
    fn test_urlencoding_encode_basic() {
        assert_eq!(urlencoding_encode("hello world"), "hello%20world");
        assert_eq!(urlencoding_encode("path/to/file"), "path%2Fto%2Ffile");
        assert_eq!(urlencoding_encode("foo:bar"), "foo%3Abar");
    }

    #[test]
    fn test_urlencoding_encode_special_chars() {
        assert_eq!(urlencoding_encode("a&b=c"), "a%26b%3Dc");
        assert_eq!(urlencoding_encode("100%"), "100%25");
        assert_eq!(urlencoding_encode("hello+world"), "hello%2Bworld");
    }

    #[test]
    fn test_urlencoding_encode_no_encoding_needed() {
        assert_eq!(urlencoding_encode("simple"), "simple");
        assert_eq!(
            urlencoding_encode("with-dash_underscore.dot~tilde"),
            "with-dash_underscore.dot~tilde"
        );
        assert_eq!(urlencoding_encode("ABC123"), "ABC123");
    }

    #[test]
    fn test_urlencoding_encode_unicode() {
        // Unicode characters should be encoded as UTF-8 bytes
        let encoded = urlencoding_encode("café");
        assert!(encoded.contains("%")); // 'é' should be encoded
        assert!(encoded.starts_with("caf")); // ASCII part preserved
    }

    #[test]
    fn test_parse_jobs_flag_variants() {
        assert_eq!(parse_jobs_flag("cargo build -j 8"), Some(8));
        assert_eq!(parse_jobs_flag("cargo build -j8"), Some(8));
        assert_eq!(parse_jobs_flag("cargo build -j=16"), Some(16));
        assert_eq!(parse_jobs_flag("cargo build --jobs 4"), Some(4));
        assert_eq!(parse_jobs_flag("cargo build --jobs=12"), Some(12));
        assert_eq!(parse_jobs_flag("cargo build"), None);
    }

    #[test]
    fn test_parse_test_threads_variants() {
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
        let config = rch_common::CompilationConfig {
            build_slots: 6,
            test_slots: 10,
            check_slots: 3,
            ..Default::default()
        };

        let build = estimate_cores_for_command(Some(CompilationKind::CargoBuild), "cargo build", &config);
        assert_eq!(build, 6);

        let build_jobs =
            estimate_cores_for_command(Some(CompilationKind::CargoBuild), "cargo build -j 12", &config);
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
    fn test_classification_rejects_shell_metachars() {
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
        // Allow output should serialize to nothing (empty stdout = allow)
        let output = HookOutput::allow();
        assert!(output.is_allow());
    }

    #[test]
    fn test_hook_output_deny_serializes() {
        let output = HookOutput::deny("Test denial reason".to_string());
        let json = serde_json::to_string(&output).expect("Should serialize");
        assert!(json.contains("deny"));
        assert!(json.contains("Test denial reason"));
    }

    #[test]
    fn test_selected_worker_to_config() {
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
            None,
            RequiredRuntime::None,
            100, // 100µs classification time
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
            None,
            RequiredRuntime::None,
            100,
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
            None,
            RequiredRuntime::None,
            150, // 150µs classification time
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
        assert!(output.is_allow());
    }

    #[tokio::test]
    async fn test_fail_open_on_config_error() {
        let _lock = test_lock().lock().await;
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
        // Verify TransferConfig has sensible defaults
        let config = TransferConfig::default();
        assert!(!config.exclude_patterns.is_empty());
        assert!(config.exclude_patterns.iter().any(|p| p.contains("target")));
    }

    #[test]
    fn test_worker_config_from_selected_worker() {
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
        assert_eq!(signal_name(1), "SIGHUP");
        assert_eq!(signal_name(2), "SIGINT");
        assert_eq!(signal_name(9), "SIGKILL");
        assert_eq!(signal_name(11), "SIGSEGV");
        assert_eq!(signal_name(15), "SIGTERM");
        assert_eq!(signal_name(99), "UNKNOWN");
    }

    #[test]
    fn test_exit_code_constants() {
        // Verify exit code constants match cargo's documented behavior
        assert_eq!(EXIT_SUCCESS, 0);
        assert_eq!(EXIT_BUILD_ERROR, 1);
        assert_eq!(EXIT_TEST_FAILURES, 101);
        assert_eq!(EXIT_SIGNAL_BASE, 128);
    }

    #[test]
    fn test_is_toolchain_failure_basic() {
        // Should detect toolchain issues
        assert!(is_toolchain_failure("error: toolchain 'nightly-2025-01-01' is not installed", 1));
        assert!(is_toolchain_failure("rustup: command not found", 127));
        assert!(is_toolchain_failure("error: no such command: `build`", 1));

        // Should not flag normal failures
        assert!(!is_toolchain_failure("error[E0425]: cannot find value `x`", 1));
        assert!(!is_toolchain_failure("test result: FAILED. 1 passed; 2 failed", 101));

        // Success should never be a toolchain failure
        assert!(!is_toolchain_failure("anything", 0));
    }

    #[test]
    fn test_exit_code_semantics_documented() {
        // This test documents the expected behavior for different exit codes
        // Exit 0: Success - should deny local (verified in other tests)
        // Exit 101: Test failures - should deny local (re-running won't help)
        // Exit 1: Build error - should deny local (same error locally)
        // Exit 137: SIGKILL - should deny local (likely OOM)

        // Verify constants are what we expect
        assert_eq!(EXIT_SUCCESS, 0, "Success exit code should be 0");
        assert_eq!(EXIT_BUILD_ERROR, 1, "Build error exit code should be 1");
        assert_eq!(EXIT_TEST_FAILURES, 101, "Test failures exit code should be 101");

        // Verify signal detection
        let sigkill = 128 + 9;
        assert_eq!(is_signal_killed(sigkill), Some(9), "Should detect SIGKILL");
        assert_eq!(signal_name(9), "SIGKILL", "Should name SIGKILL correctly");
    }

    // =========================================================================
    // Cargo test integration tests (bead remote_compilation_helper-iyv1)
    // =========================================================================

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
            MockConfig {
                default_exit_code: 0,
                default_stdout: "running 1 test\ntest specific_test ... ok\n\ntest result: ok. 1 passed\n".to_string(),
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
                default_stderr: "error: toolchain 'nightly-2025-01-15' is not installed\n".to_string(),
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

        let result = classify_command("cargo test -p rch-common");
        assert!(result.is_compilation);
        assert_eq!(result.kind, Some(CompilationKind::CargoTest));
    }

    #[test]
    fn test_cargo_nextest_classification() {
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
        assert!(
            !has_ignored_only_flag("cargo test"),
            "No flags"
        );
    }

    #[test]
    fn test_has_exact_flag() {
        assert!(has_exact_flag("cargo test my_test -- --exact"), "--exact detected");
        assert!(!has_exact_flag("cargo test my_test"), "No --exact");
        assert!(!has_exact_flag("cargo test -- --nocapture"), "No --exact");
    }

    #[test]
    fn test_estimate_cores_filtered_tests() {
        let config = rch_common::CompilationConfig {
            build_slots: 6,
            test_slots: 10,
            check_slots: 3,
            ..Default::default()
        };

        // Full test suite gets default slots
        let full = estimate_cores_for_command(
            Some(CompilationKind::CargoTest),
            "cargo test",
            &config,
        );
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
        let without = estimate_cores_for_command(
            Some(CompilationKind::CargoTest),
            "cargo test",
            &config,
        );
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
}
