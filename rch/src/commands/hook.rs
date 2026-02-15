//! Hook management commands.
//!
//! This module contains commands for installing, uninstalling, and testing
//! the RCH hook for AI coding agents like Claude Code.

use anyhow::{Context, Result};
use chrono::Utc;
use rch_common::{ApiError, ApiResponse, ErrorCode};
use std::path::PathBuf;
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::ui::context::OutputContext;
use crate::ui::theme::StatusIndicator;

use super::types::HookActionResponse;

// =============================================================================
// Hook Commands
// =============================================================================

/// Install the Claude Code hook.
///
/// This function is idempotent and safe - it merges the rch hook with existing
/// hooks rather than replacing them. It also creates a backup before modifying.
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
    let rch_path_str = rch_path.to_string_lossy().to_string();

    // Create backup before modifying (if file exists)
    if settings_path.exists() {
        let backup_path = claude_config_dir.join(format!(
            "settings.json.bak.{}",
            Utc::now().format("%Y%m%d%H%M%S")
        ));
        if let Err(e) = std::fs::copy(&settings_path, &backup_path) {
            if !ctx.is_json() {
                println!(
                    "  {} Could not create backup: {}",
                    StatusIndicator::Warning.display(style),
                    e
                );
            }
        } else if !ctx.is_json() {
            println!(
                "  {} Backup created: {}",
                StatusIndicator::Info.display(style),
                backup_path.display()
            );
        }
    }

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

    // SAFE MERGE: Get existing PreToolUse hooks or create empty array
    let pre_tool_use = hooks_obj
        .entry("PreToolUse")
        .or_insert(serde_json::json!([]));

    let pre_tool_use_arr = pre_tool_use
        .as_array_mut()
        .context("PreToolUse must be an array")?;

    // Find existing Bash matcher or create one
    let bash_matcher_idx = pre_tool_use_arr
        .iter()
        .position(|entry| entry.get("matcher").and_then(|m| m.as_str()) == Some("Bash"));

    let rch_hook = serde_json::json!({"type": "command", "command": rch_path_str});

    if let Some(idx) = bash_matcher_idx {
        // Bash matcher exists - add rch to its hooks if not already present
        let bash_entry = &mut pre_tool_use_arr[idx];
        let hooks_arr = bash_entry.get_mut("hooks").and_then(|h| h.as_array_mut());

        if let Some(hooks) = hooks_arr {
            // Check if rch is already in the hooks
            let rch_exists = hooks.iter().any(|h| {
                h.get("command")
                    .and_then(|c| c.as_str())
                    .map(|c| c.contains("rch"))
                    .unwrap_or(false)
            });

            if rch_exists {
                // Already installed - return early without modifying the file
                if ctx.is_json() {
                    let _ = ctx.json(&ApiResponse::ok(
                        "hook install",
                        HookActionResponse {
                            action: "install".to_string(),
                            success: true,
                            settings_path: settings_path.display().to_string(),
                            message: Some("Hook already installed".to_string()),
                        },
                    ));
                } else {
                    println!(
                        "{} RCH hook already installed in {}",
                        StatusIndicator::Success.display(style),
                        style.highlight(&settings_path.display().to_string())
                    );
                }
                return Ok(());
            } else {
                // Add rch at the END (after other hooks like dcg for safety)
                hooks.push(rch_hook);
            }
        } else {
            // No hooks array - create one with rch
            bash_entry["hooks"] = serde_json::json!([rch_hook]);
        }
    } else {
        // No Bash matcher - create one with rch
        pre_tool_use_arr.push(serde_json::json!({
            "matcher": "Bash",
            "hooks": [rch_hook]
        }));
    }

    // Write back to file
    let new_content = serde_json::to_string_pretty(&settings)?;
    std::fs::write(&settings_path, new_content)?;

    if ctx.is_json() {
        let _ = ctx.json(&ApiResponse::ok(
            "hook install",
            HookActionResponse {
                action: "install".to_string(),
                success: true,
                settings_path: settings_path.display().to_string(),
                message: Some("Hook installed successfully".to_string()),
            },
        ));
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

        // Run quick health check
        let quick_result = crate::doctor::run_quick_check();
        crate::doctor::print_quick_check_summary(&quick_result, ctx);
    }

    Ok(())
}

/// Uninstall the Claude Code hook.
///
/// This function is safe - it only removes the rch hook while preserving other
/// hooks like dcg. It creates a backup before modifying.
///
/// If `skip_confirm` is false, prompts for confirmation before uninstalling.
pub fn hook_uninstall(skip_confirm: bool, ctx: &OutputContext) -> Result<()> {
    use dialoguer::Confirm;

    let style = ctx.theme();

    let claude_config_dir = dirs::home_dir()
        .map(|h| h.join(".claude"))
        .context("Could not find home directory")?;

    let settings_path = claude_config_dir.join("settings.json");

    if !settings_path.exists() {
        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::<()>::err(
                "hook uninstall",
                ApiError::new(
                    ErrorCode::ConfigNotFound,
                    "Claude Code settings file not found",
                ),
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

    // Prompt for confirmation unless skipped or in JSON mode
    if !skip_confirm && !ctx.is_json() {
        println!(
            "{} This will remove the RCH hook from Claude Code settings.",
            StatusIndicator::Warning.display(style)
        );
        println!(
            "  {} Compilation commands will no longer be offloaded to remote workers.",
            StatusIndicator::Info.display(style)
        );
        let confirmed = Confirm::new()
            .with_prompt("Remove RCH hook?")
            .default(false)
            .interact()?;
        if !confirmed {
            println!("{} Aborted.", StatusIndicator::Info.display(style));
            return Ok(());
        }
    }

    // Create backup before modifying
    let backup_path = claude_config_dir.join(format!(
        "settings.json.bak.{}",
        Utc::now().format("%Y%m%d%H%M%S")
    ));
    if let Err(e) = std::fs::copy(&settings_path, &backup_path)
        && !ctx.is_json()
    {
        println!(
            "  {} Could not create backup: {}",
            StatusIndicator::Warning.display(style),
            e
        );
    }

    let content = std::fs::read_to_string(&settings_path)?;
    let mut settings: serde_json::Value = serde_json::from_str(&content)?;

    // SAFE REMOVAL: Only remove rch hook, preserve other hooks (like dcg)
    let mut removed = false;

    if let Some(hooks) = settings.get_mut("hooks")
        && let Some(hooks_obj) = hooks.as_object_mut()
        && let Some(pre_tool_use) = hooks_obj.get_mut("PreToolUse")
        && let Some(pre_tool_use_arr) = pre_tool_use.as_array_mut()
    {
        // Find the Bash matcher
        for entry in pre_tool_use_arr.iter_mut() {
            if entry.get("matcher").and_then(|m| m.as_str()) == Some("Bash")
                && let Some(hooks_arr) = entry.get_mut("hooks").and_then(|h| h.as_array_mut())
            {
                // Remove rch from hooks
                let original_len = hooks_arr.len();
                hooks_arr.retain(|h| {
                    !h.get("command")
                        .and_then(|c| c.as_str())
                        .map(|c| c.contains("rch"))
                        .unwrap_or(false)
                });
                removed = hooks_arr.len() < original_len;
            }
        }

        // Clean up: remove empty Bash matchers
        pre_tool_use_arr.retain(|entry| {
            if entry.get("matcher").and_then(|m| m.as_str()) == Some("Bash") {
                entry
                    .get("hooks")
                    .and_then(|h| h.as_array())
                    .map(|a| !a.is_empty())
                    .unwrap_or(false)
            } else {
                true // Keep non-Bash matchers
            }
        });

        // Clean up: remove PreToolUse if completely empty
        if pre_tool_use_arr.is_empty() {
            hooks_obj.remove("PreToolUse");
        }
    }

    if removed {
        let new_content = serde_json::to_string_pretty(&settings)?;
        std::fs::write(&settings_path, new_content)?;

        if ctx.is_json() {
            let _ = ctx.json(&ApiResponse::ok(
                "hook uninstall",
                HookActionResponse {
                    action: "uninstall".to_string(),
                    success: true,
                    settings_path: settings_path.display().to_string(),
                    message: Some("Hook removed successfully".to_string()),
                },
            ));
        } else {
            println!(
                "{} Hook removed from {}",
                StatusIndicator::Success.display(style),
                style.highlight(&settings_path.display().to_string())
            );
        }
    } else if ctx.is_json() {
        let _ = ctx.json(&ApiResponse::ok(
            "hook uninstall",
            HookActionResponse {
                action: "uninstall".to_string(),
                success: false,
                settings_path: settings_path.display().to_string(),
                message: Some("Hook was not found".to_string()),
            },
        ));
    } else {
        println!(
            "{} Hook not found in settings.",
            StatusIndicator::Info.display(style)
        );
    }

    Ok(())
}

/// Display hook installation status.
pub fn hook_status(ctx: &OutputContext) -> Result<()> {
    use crate::agent::{AgentKind, HookStatus, check_hook_status};

    let style = ctx.theme();

    if !ctx.is_json() {
        println!("{}", style.format_header("Hook Status"));
        println!();
    }

    // Check status for supported agents
    let supported_agents = [
        AgentKind::ClaudeCode,
        AgentKind::GeminiCli,
        AgentKind::CodexCli,
        AgentKind::ContinueDev,
    ];

    let mut statuses = Vec::new();
    for kind in &supported_agents {
        let status = check_hook_status(*kind).unwrap_or(HookStatus::NotSupported);
        if !ctx.is_json() {
            let indicator = match status {
                HookStatus::Installed => StatusIndicator::Success,
                HookStatus::NeedsUpdate => StatusIndicator::Warning,
                HookStatus::NotInstalled => StatusIndicator::Info,
                HookStatus::NotSupported => StatusIndicator::Pending,
            };
            println!(
                "  {} {}: {}",
                indicator.display(style),
                style.key(&format!("{:?}", kind)),
                status
            );
        }
        statuses.push(serde_json::json!({
            "agent": format!("{:?}", kind),
            "status": status.to_string(),
        }));
    }

    if ctx.is_json() {
        let _ = ctx.json(&ApiResponse::ok(
            "hook status",
            serde_json::json!({
                "agents": statuses,
            }),
        ));
    }

    Ok(())
}

/// Test the hook with a sample 'cargo build' command.
///
/// This spawns `rch` in hook mode (no arguments) and passes a sample
/// PreToolUse hook input, showing what the hook would do in response.
pub async fn hook_test(ctx: &OutputContext) -> Result<()> {
    let style = ctx.theme();

    if !ctx.is_json() {
        println!("Testing RCH hook with sample 'cargo build' command...\n");
    }

    // Create a sample hook input as JSON directly
    // (HookInput doesn't derive Serialize, so we build JSON manually)
    let input_json = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": {
            "command": "cargo build",
            "description": "Build the Rust project"
        },
        "session_id": "hook-test-session"
    });
    let input_json_str = serde_json::to_string_pretty(&input_json)?;

    if !ctx.is_json() {
        println!("Input (sent to hook):");
        println!("{}\n", input_json_str);
    }

    // Find the rch binary
    let rch_path = std::env::current_exe()?;

    // Spawn rch in hook mode (no arguments = hook mode)
    let mut child = Command::new(&rch_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Failed to spawn rch in hook mode")?;

    // Write input to stdin
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(input_json_str.as_bytes()).await?;
        stdin.shutdown().await?;
    }

    // Wait for completion with timeout
    let timeout = tokio::time::Duration::from_secs(30);
    let output = tokio::time::timeout(timeout, child.wait_with_output())
        .await
        .context("Hook test timed out after 30 seconds")?
        .context("Failed to wait for hook process")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if ctx.is_json() {
        let output_json: Option<serde_json::Value> = if stdout.is_empty() {
            None
        } else {
            serde_json::from_str(stdout.trim()).ok()
        };

        let decision = if stdout.is_empty() {
            "allow"
        } else if output_json
            .as_ref()
            .map(|v| v.get("hookSpecificOutput").is_some())
            .unwrap_or(false)
        {
            "deny"
        } else {
            "allow"
        };

        let result = serde_json::json!({
            "input": input_json,
            "decision": decision,
            "output": output_json,
            "exit_code": output.status.code(),
            "stderr": if stderr.is_empty() { None::<&str> } else { Some(stderr.trim()) }
        });
        let _ = ctx.json(&result);
        return Ok(());
    }

    // Display results in human-readable format
    if stdout.is_empty() {
        // Empty stdout = allow (local execution)
        println!(
            "{} Hook decision: ALLOW (local execution)",
            StatusIndicator::Success.display(style)
        );
        println!("\nThis means the command would run locally (not offloaded).");
        println!("Reasons this might happen:");
        println!("  - RCH is disabled in config");
        println!("  - No daemon is running");
        println!("  - No workers are available");
        println!("  - The command wasn't classified as a compilation command");
    } else {
        // Parse the hook output as JSON
        match serde_json::from_str::<serde_json::Value>(stdout.trim()) {
            Ok(output_json) => {
                // Check if it's a deny response (has hookSpecificOutput)
                if let Some(hook_output) = output_json.get("hookSpecificOutput") {
                    println!(
                        "{} Hook decision: DENY (intercepted)",
                        StatusIndicator::Success.display(style)
                    );
                    println!("\nThe hook intercepted the command.");

                    if let Some(reason) = hook_output
                        .get("permissionDecisionReason")
                        .and_then(|r| r.as_str())
                    {
                        println!("Reason: {}", reason);
                    }
                } else {
                    // Empty object {} = allow
                    println!(
                        "{} Hook decision: ALLOW (local execution)",
                        StatusIndicator::Success.display(style)
                    );
                    println!("\nThe command would run locally.");
                }
            }
            Err(e) => {
                println!(
                    "{} Failed to parse hook output: {}",
                    StatusIndicator::Warning.display(style),
                    e
                );
                println!("Raw output: {}", stdout);
            }
        }
    }

    if !stderr.is_empty() {
        println!("\nHook stderr:");
        for line in stderr.lines() {
            println!("  {}", line);
        }
    }

    if !output.status.success() {
        println!(
            "\n{} Hook process exited with code: {:?}",
            StatusIndicator::Warning.display(style),
            output.status.code()
        );
    }

    Ok(())
}
