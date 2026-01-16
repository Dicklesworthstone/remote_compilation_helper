//! PreToolUse hook implementation.
//!
//! Handles incoming hook requests from Claude Code, classifies commands,
//! and routes compilation commands to remote workers.

use crate::config::load_config;
use crate::transfer::{
    TransferPipeline, compute_project_hash, default_rust_artifact_patterns, project_id_from_path,
};
use anyhow::Result;
use rch_common::{
    HookInput, HookOutput, SelectionResponse, TransferConfig, WorkerConfig, classify_command,
};
use std::io::{self, BufRead, Write};
use std::path::Path;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tracing::{debug, info, warn};

/// Run the hook, reading from stdin and writing to stdout.
pub async fn run_hook() -> Result<()> {
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

    if !config.general.enabled {
        debug!("RCH disabled via config, allowing local execution");
        return HookOutput::allow();
    }

    let command = &input.tool_input.command;
    debug!("Processing command: {}", command);

    // Classify the command using 5-tier system
    let classification = classify_command(command);

    if !classification.is_compilation {
        debug!(
            "Not a compilation command: {} ({})",
            command, classification.reason
        );
        return HookOutput::allow();
    }

    info!(
        "Compilation detected: {:?} (confidence: {:.2})",
        classification.kind, classification.confidence
    );

    // Check confidence threshold
    let confidence_threshold = config.compilation.confidence_threshold;
    if classification.confidence < confidence_threshold {
        debug!(
            "Confidence {:.2} below threshold {:.2}, allowing local execution",
            classification.confidence, confidence_threshold
        );
        return HookOutput::allow();
    }

    // Query daemon for a worker
    let project = extract_project_name();

    match query_daemon(&config.general.socket_path, &project, 4).await {
        Ok(worker) => {
            info!(
                "Selected worker: {} at {}@{} ({} slots, speed {:.1})",
                worker.worker, worker.user, worker.host, worker.slots_available, worker.speed_score
            );

            // Execute remote compilation pipeline
            match execute_remote_compilation(&worker, command, config.transfer.clone()).await {
                Ok(exit_code) => {
                    if exit_code == 0 {
                        // Command succeeded remotely - deny local execution
                        // The agent sees output via stderr, artifacts are local
                        info!("Remote compilation succeeded, denying local execution");
                        HookOutput::deny(
                            "RCH: Command executed successfully on remote worker".to_string(),
                        )
                    } else {
                        // Command failed remotely - still deny to prevent re-execution
                        // The agent saw the error output via stderr
                        info!(
                            "Remote compilation failed (exit {}), denying local execution",
                            exit_code
                        );
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
                    HookOutput::allow()
                }
            }
        }
        Err(e) => {
            warn!("Failed to query daemon: {}, allowing local execution", e);
            HookOutput::allow()
        }
    }
}

/// Query the daemon for a worker.
async fn query_daemon(socket_path: &str, project: &str, cores: u32) -> Result<SelectionResponse> {
    // Check if socket exists
    if !Path::new(socket_path).exists() {
        return Err(anyhow::anyhow!("Daemon socket not found: {}", socket_path));
    }

    // Connect to daemon
    let stream = UnixStream::connect(socket_path).await?;
    let (reader, mut writer) = stream.into_split();

    // Send request
    let request = format!(
        "GET /select-worker?project={}&cores={}\n",
        urlencoding_encode(project),
        cores
    );
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

/// Convert a SelectionResponse to a WorkerConfig.
fn selection_to_worker_config(response: &SelectionResponse) -> WorkerConfig {
    WorkerConfig {
        id: response.worker.clone(),
        host: response.host.clone(),
        user: response.user.clone(),
        identity_file: response.identity_file.clone(),
        total_slots: response.slots_available,
        priority: 100,
        tags: vec![],
    }
}

/// Execute a compilation command on a remote worker.
///
/// This function:
/// 1. Syncs the project to the remote worker
/// 2. Executes the command remotely with streaming output
/// 3. Retrieves build artifacts back to local
///
/// Returns the exit code of the remote command.
async fn execute_remote_compilation(
    worker_response: &SelectionResponse,
    command: &str,
    transfer_config: TransferConfig,
) -> Result<i32> {
    let worker_config = selection_to_worker_config(worker_response);

    // Get current working directory as project root
    let project_root = std::env::current_dir()
        .map_err(|e| anyhow::anyhow!("Failed to get current directory: {}", e))?;

    let project_id = project_id_from_path(&project_root);
    let project_hash = compute_project_hash(&project_root);

    info!(
        "Starting remote compilation pipeline for {} (hash: {})",
        project_id, project_hash
    );

    // Create transfer pipeline
    let pipeline = TransferPipeline::new(project_root, project_id, project_hash, transfer_config);

    // Step 1: Sync project to remote
    info!("Syncing project to worker {}...", worker_config.id);
    let sync_result = pipeline.sync_to_remote(&worker_config).await?;
    info!(
        "Sync complete: {} files, {} bytes in {}ms",
        sync_result.files_transferred, sync_result.bytes_transferred, sync_result.duration_ms
    );

    // Step 2: Execute command remotely with streaming output
    info!("Executing command remotely: {}", command);

    // Stream stdout/stderr to our stderr so the agent sees the output
    let result = pipeline
        .execute_remote_streaming(
            &worker_config,
            command,
            |line| {
                // Write stdout lines to stderr (hook stdout is for protocol)
                eprintln!("{}", line);
            },
            |line| {
                // Write stderr lines to stderr
                eprintln!("{}", line);
            },
        )
        .await?;

    info!(
        "Remote command finished: exit={} in {}ms",
        result.exit_code, result.duration_ms
    );

    // Step 3: Retrieve artifacts
    if result.success() {
        info!("Retrieving build artifacts...");
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
            }
            Err(e) => {
                warn!("Failed to retrieve artifacts: {}", e);
                // Continue anyway - compilation succeeded
            }
        }
    }

    Ok(result.exit_code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rch_common::ToolInput;

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
}
