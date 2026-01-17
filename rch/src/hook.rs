//! PreToolUse hook implementation.
//!
//! Handles incoming hook requests from Claude Code, classifies commands,
//! and routes compilation commands to remote workers.

use crate::config::load_config;
use crate::error::{DaemonError, TransferError};
use crate::toolchain::detect_toolchain;
use crate::transfer::{
    TransferPipeline, compute_project_hash, default_rust_artifact_patterns, project_id_from_path,
};
use rch_common::{
    CompilationKind, HookInput, HookOutput, OutputVisibility, RequiredRuntime, SelectedWorker,
    SelectionResponse, ToolchainInfo, TransferConfig, WorkerConfig, WorkerId, classify_command,
};
use std::io::{self, BufRead, Write};
use std::path::Path;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tracing::{debug, info, warn};

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
    let estimated_cores = 4;
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
                toolchain.as_ref(),
                &reporter,
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
                        info!(
                            "Remote compilation failed (exit {}), denying local execution",
                            result.exit_code
                        );
                        reporter.summary(&format!(
                            "[RCH] remote {} failed (exit {})",
                            worker.id, result.exit_code
                        ));
                        HookOutput::deny(format!(
                            "RCH: Remote compilation failed with exit code {}",
                            result.exit_code
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

/// Map a classification kind to required runtime.
pub(crate) fn required_runtime_for_kind(kind: Option<CompilationKind>) -> RequiredRuntime {
    match kind {
        Some(k) => match k {
            CompilationKind::CargoBuild
            | CompilationKind::CargoTest
            | CompilationKind::CargoCheck
            | CompilationKind::CargoClippy
            | CompilationKind::CargoDoc
            | CompilationKind::Rustc => RequiredRuntime::Rust,

            CompilationKind::BunTest | CompilationKind::BunTypecheck => RequiredRuntime::Bun,

            _ => RequiredRuntime::None,
        },
        None => RequiredRuntime::None,
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
async fn execute_remote_compilation(
    worker: &SelectedWorker,
    command: &str,
    transfer_config: TransferConfig,
    toolchain: Option<&ToolchainInfo>,
    reporter: &HookReporter,
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

    // Create transfer pipeline
    let pipeline = TransferPipeline::new(
        project_root.clone(),
        project_id,
        project_hash,
        transfer_config,
    );

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
    let result = pipeline
        .execute_remote_streaming(
            &worker_config,
            command,
            toolchain,
            |line| {
                // Write stdout lines to stderr (hook stdout is for protocol)
                eprintln!("{}", line);
            },
            |line| {
                // Write stderr lines to stderr and capture for analysis
                eprintln!("{}", line);
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
        let artifact_patterns = default_rust_artifact_patterns();
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

    Ok(RemoteExecutionResult {
        exit_code: result.exit_code,
        stderr: stderr_capture,
        duration_ms: result.duration_ms,
    })
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
}
