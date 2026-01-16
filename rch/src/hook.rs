//! PreToolUse hook implementation.
//!
//! Handles incoming hook requests from Claude Code, classifies commands,
//! and routes compilation commands to remote workers.

use anyhow::Result;
use rch_common::{HookInput, HookOutput, classify_command};
use std::io::{self, BufRead, Write};
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
    // TODO: Load from config
    let confidence_threshold = 0.85;
    if classification.confidence < confidence_threshold {
        debug!(
            "Confidence {:.2} below threshold {:.2}, allowing local execution",
            classification.confidence, confidence_threshold
        );
        return HookOutput::allow();
    }

    // TODO: Execute remote compilation pipeline
    // For now, just allow local execution
    info!("Remote execution not yet implemented, allowing local");
    HookOutput::allow()
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
}
