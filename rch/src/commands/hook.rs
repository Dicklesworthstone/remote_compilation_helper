//! Hook management commands.
//!
//! This module contains commands for installing, uninstalling, and testing
//! the RCH hook for AI coding agents like Claude Code.

use anyhow::{Context, Result};
use chrono::Utc;
use rch_common::{ApiError, ApiResponse, ErrorCode};
use serde_json::Value;
use std::path::PathBuf;
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::state::primitives::atomic_write;
use crate::ui::context::OutputContext;
use crate::ui::theme::StatusIndicator;

use super::types::HookActionResponse;

fn is_rch_hook_command(command: &str) -> bool {
    let first_token = shell_words::split(command)
        .ok()
        .and_then(|tokens| tokens.into_iter().next())
        .unwrap_or_else(|| {
            command
                .split_whitespace()
                .next()
                .unwrap_or(command)
                .to_string()
        });

    let basename = std::path::Path::new(&first_token)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(&first_token);

    matches!(basename, "rch")
}

fn hook_command_is_rch(hook: &Value) -> bool {
    hook.get("command")
        .and_then(|command| command.as_str())
        .is_some_and(is_rch_hook_command)
}

fn entry_has_nested_rch_hook(entry: &Value) -> bool {
    entry
        .get("hooks")
        .and_then(|hooks| hooks.as_array())
        .is_some_and(|hooks| hooks.iter().any(hook_command_is_rch))
}

fn entry_is_bash_matcher(entry: &Value) -> bool {
    entry.get("matcher").and_then(|matcher| matcher.as_str()) == Some("Bash")
}

fn entry_has_current_rch_hook(entry: &Value) -> bool {
    entry_is_bash_matcher(entry) && entry_has_nested_rch_hook(entry)
}

fn is_standalone_rch_hook_entry(entry: &Value) -> bool {
    entry.as_str().is_some_and(is_rch_hook_command)
        || (hook_command_is_rch(entry) && entry.get("hooks").is_none())
}

fn install_rch_hook_in_settings(settings: &mut Value, rch_hook: Value) -> Result<bool> {
    let hooks = settings
        .as_object_mut()
        .context("Settings must be an object")?
        .entry("hooks")
        .or_insert(serde_json::json!({}));

    let hooks_obj = hooks.as_object_mut().context("Hooks must be an object")?;

    let pre_tool_use = hooks_obj
        .entry("PreToolUse")
        .or_insert(serde_json::json!([]));

    let pre_tool_use_arr = pre_tool_use
        .as_array_mut()
        .context("PreToolUse must be an array")?;

    let already_has_current_hook = pre_tool_use_arr.iter().any(entry_has_current_rch_hook);
    let original_len = pre_tool_use_arr.len();
    pre_tool_use_arr.retain(|entry| !is_standalone_rch_hook_entry(entry));
    let removed_obsolete_hook = pre_tool_use_arr.len() != original_len;

    if already_has_current_hook {
        return Ok(removed_obsolete_hook);
    }

    if let Some(bash_entry) = pre_tool_use_arr
        .iter_mut()
        .find(|entry| entry_is_bash_matcher(entry))
    {
        match bash_entry
            .get_mut("hooks")
            .and_then(|hooks| hooks.as_array_mut())
        {
            Some(hooks) => hooks.push(rch_hook),
            None => {
                bash_entry
                    .as_object_mut()
                    .context("Bash matcher entry must be an object")?
                    .insert("hooks".to_string(), serde_json::json!([rch_hook]));
            }
        }
    } else {
        pre_tool_use_arr.push(serde_json::json!({
            "matcher": "Bash",
            "hooks": [rch_hook]
        }));
    }

    Ok(true)
}

fn uninstall_rch_hook_from_settings(settings: &mut Value) -> bool {
    let Some(hooks_obj) = settings
        .get_mut("hooks")
        .and_then(|hooks| hooks.as_object_mut())
    else {
        return false;
    };

    let mut removed = false;
    let remove_pre_tool_use = if let Some(pre_tool_use_arr) = hooks_obj
        .get_mut("PreToolUse")
        .and_then(|pre_tool_use| pre_tool_use.as_array_mut())
    {
        let original_len = pre_tool_use_arr.len();
        pre_tool_use_arr.retain(|entry| !is_standalone_rch_hook_entry(entry));
        removed |= pre_tool_use_arr.len() != original_len;

        for entry in pre_tool_use_arr.iter_mut() {
            if let Some(hooks_arr) = entry
                .get_mut("hooks")
                .and_then(|hooks| hooks.as_array_mut())
            {
                let original_len = hooks_arr.len();
                hooks_arr.retain(|hook| !hook_command_is_rch(hook));
                removed |= hooks_arr.len() != original_len;
            }
        }

        pre_tool_use_arr.retain(|entry| {
            if entry_is_bash_matcher(entry) {
                entry
                    .get("hooks")
                    .and_then(|hooks| hooks.as_array())
                    .is_some_and(|hooks| !hooks.is_empty())
            } else {
                true
            }
        });

        pre_tool_use_arr.is_empty()
    } else {
        false
    };

    if remove_pre_tool_use {
        hooks_obj.remove("PreToolUse");
    }

    removed
}

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

    // Create or update settings.json
    let settings_existed = settings_path.exists();
    let mut settings: serde_json::Value = if settings_existed {
        let content = std::fs::read_to_string(&settings_path)?;
        serde_json::from_str(&content).unwrap_or(serde_json::json!({}))
    } else {
        std::fs::create_dir_all(&claude_config_dir)?;
        serde_json::json!({})
    };

    let rch_hook = serde_json::json!({"type": "command", "command": rch_path_str});

    if !install_rch_hook_in_settings(&mut settings, rch_hook)? {
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
    }

    // Create backup before modifying (if file exists)
    if settings_existed {
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

    // Write back to file
    let new_content = serde_json::to_string_pretty(&settings)?;
    atomic_write(&settings_path, new_content.as_bytes())?;

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

    let content = std::fs::read_to_string(&settings_path)?;
    let mut settings: serde_json::Value = serde_json::from_str(&content)?;

    // SAFE REMOVAL: Only remove rch hook, preserve other hooks (like dcg)
    let removed = uninstall_rch_hook_from_settings(&mut settings);

    if removed {
        // Create backup before modifying.
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

        let new_content = serde_json::to_string_pretty(&settings)?;
        atomic_write(&settings_path, new_content.as_bytes())?;

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

    // Spawn rch in hook mode (no arguments = hook mode).
    //
    // `kill_on_drop` is essential here because the call below wraps
    // `child.wait_with_output()` in `tokio::time::timeout(30s, ...)`. On
    // timeout, the future is dropped — without this flag the child rch
    // process keeps running detached, which for a hook test means leaking
    // a process that may also have taken its own slot reservation on the
    // daemon. Force a SIGKILL when the future drops.
    let mut child = Command::new("rch")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
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

        let decision = output_json
            .as_ref()
            .and_then(|json| json.get("hookSpecificOutput"))
            .and_then(|hook_output| hook_output.get("permissionDecision"))
            .and_then(|decision| decision.as_str())
            .unwrap_or("allow");

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
                if let Some(hook_output) = output_json.get("hookSpecificOutput") {
                    let permission_decision = hook_output
                        .get("permissionDecision")
                        .and_then(|decision| decision.as_str())
                        .unwrap_or("unknown");
                    println!(
                        "{} Hook decision: {} (intercepted)",
                        StatusIndicator::Success.display(style),
                        permission_decision.to_uppercase()
                    );
                    println!("\nThe hook intercepted the command.");

                    if let Some(reason) = hook_output
                        .get("permissionDecisionReason")
                        .and_then(|reason| reason.as_str())
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn pre_tool_use(settings: &Value) -> &[Value] {
        settings["hooks"]["PreToolUse"].as_array().unwrap()
    }

    fn nested_rch_hook_count(settings: &Value) -> usize {
        pre_tool_use(settings)
            .iter()
            .filter_map(|entry| entry.get("hooks").and_then(|hooks| hooks.as_array()))
            .flatten()
            .filter(|hook| hook_command_is_rch(hook))
            .count()
    }

    #[test]
    fn rch_hook_command_detection_rejects_substring_false_positives() {
        assert!(is_rch_hook_command("rch"));
        assert!(is_rch_hook_command("/usr/local/bin/rch --hook"));
        assert!(is_rch_hook_command("'/Applications/RCH Tools/rch'"));

        assert!(!is_rch_hook_command("search"));
        assert!(!is_rch_hook_command("/usr/local/bin/archive"));
        assert!(!is_rch_hook_command("rearchive"));
        assert!(!is_rch_hook_command("rch-wkr"));
        assert!(!is_rch_hook_command("myrchwrapper"));
    }

    #[test]
    fn install_preserves_substring_hooks_and_adds_exact_rch_hook() {
        let mut settings = json!({
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [
                            {"type": "command", "command": "search"},
                            {"type": "command", "command": "archive"}
                        ]
                    }
                ]
            }
        });

        let changed = install_rch_hook_in_settings(
            &mut settings,
            json!({"type": "command", "command": "/usr/local/bin/rch"}),
        )
        .unwrap();

        assert!(changed);
        assert_eq!(nested_rch_hook_count(&settings), 1);
        let hooks = pre_tool_use(&settings)[0]["hooks"].as_array().unwrap();
        assert!(
            hooks
                .iter()
                .any(|hook| hook["command"].as_str() == Some("search"))
        );
        assert!(
            hooks
                .iter()
                .any(|hook| hook["command"].as_str() == Some("archive"))
        );
    }

    #[test]
    fn install_does_not_duplicate_existing_nested_rch_hook() {
        let mut settings = json!({
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [{"type": "command", "command": "search"}]
                    },
                    {
                        "matcher": "Bash",
                        "hooks": [{"type": "command", "command": "/usr/local/bin/rch"}]
                    }
                ]
            }
        });
        let before = settings.clone();

        let changed = install_rch_hook_in_settings(
            &mut settings,
            json!({"type": "command", "command": "rch"}),
        )
        .unwrap();

        assert!(!changed);
        assert_eq!(settings, before);
    }

    #[test]
    fn install_does_not_treat_non_bash_rch_hook_as_current() {
        let mut settings = json!({
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Edit",
                        "hooks": [{"type": "command", "command": "rch"}]
                    }
                ]
            }
        });

        let changed = install_rch_hook_in_settings(
            &mut settings,
            json!({"type": "command", "command": "/usr/local/bin/rch"}),
        )
        .unwrap();

        assert!(changed);
        assert_eq!(
            pre_tool_use(&settings)
                .iter()
                .filter(|entry| entry_is_bash_matcher(entry))
                .count(),
            1
        );
    }

    #[test]
    fn install_migrates_obsolete_standalone_rch_hook() {
        let mut settings = json!({
            "hooks": {
                "PreToolUse": [
                    {"command": "rch"},
                    {
                        "matcher": "Bash",
                        "hooks": [{"type": "command", "command": "search"}]
                    }
                ]
            }
        });

        let changed = install_rch_hook_in_settings(
            &mut settings,
            json!({"type": "command", "command": "/usr/local/bin/rch"}),
        )
        .unwrap();

        assert!(changed);
        assert_eq!(nested_rch_hook_count(&settings), 1);
        assert!(
            pre_tool_use(&settings)
                .iter()
                .all(|entry| !is_standalone_rch_hook_entry(entry))
        );
    }

    #[test]
    fn uninstall_removes_only_exact_rch_hooks() {
        let mut settings = json!({
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [
                            {"type": "command", "command": "search"},
                            {"type": "command", "command": "/usr/local/bin/rch"},
                            {"type": "command", "command": "archive"}
                        ]
                    },
                    {"command": "rch"},
                    "rch",
                    {"command": "rch-wkr"}
                ],
                "PostToolUse": [
                    {"type": "command", "command": "rch"}
                ]
            }
        });

        assert!(uninstall_rch_hook_from_settings(&mut settings));

        let pre_hooks = pre_tool_use(&settings);
        assert_eq!(nested_rch_hook_count(&settings), 0);
        assert!(
            pre_hooks
                .iter()
                .filter_map(|entry| entry.get("hooks").and_then(|hooks| hooks.as_array()))
                .flatten()
                .any(|hook| hook["command"].as_str() == Some("search"))
        );
        assert!(
            pre_hooks
                .iter()
                .filter_map(|entry| entry.get("hooks").and_then(|hooks| hooks.as_array()))
                .flatten()
                .any(|hook| hook["command"].as_str() == Some("archive"))
        );
        assert!(
            pre_hooks
                .iter()
                .any(|entry| entry["command"].as_str() == Some("rch-wkr"))
        );
        assert_eq!(settings["hooks"]["PostToolUse"][0]["command"], "rch");
    }
}
