//! Hook management for AI coding agents.
//!
//! Provides idempotent hook installation and management for supported agents.

use super::types::AgentKind;
use crate::state::primitives::{IdempotentResult, atomic_write, create_backup};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;

/// Status of RCH hook for an agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookStatus {
    /// Hook is installed and configured correctly.
    Installed,
    /// Hook is installed but outdated or misconfigured.
    NeedsUpdate,
    /// Hook is not installed.
    NotInstalled,
    /// Agent doesn't support hooks.
    NotSupported,
}

impl std::fmt::Display for HookStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HookStatus::Installed => write!(f, "Installed"),
            HookStatus::NeedsUpdate => write!(f, "Needs update"),
            HookStatus::NotInstalled => write!(f, "Not installed"),
            HookStatus::NotSupported => write!(f, "Not supported"),
        }
    }
}

/// Check the hook status for an agent.
pub fn check_hook_status(kind: AgentKind) -> Result<HookStatus> {
    if !kind.hook_support().can_install_hook() {
        return Ok(HookStatus::NotSupported);
    }

    match kind {
        AgentKind::ClaudeCode => check_claude_code_hook(),
        AgentKind::GeminiCli => check_gemini_cli_hook(),
        AgentKind::CodexCli => check_codex_cli_hook(),
        AgentKind::ContinueDev => check_continue_dev_hook(),
        _ => Ok(HookStatus::NotSupported),
    }
}

/// Install the RCH hook for an agent.
pub fn install_hook(kind: AgentKind, dry_run: bool) -> Result<IdempotentResult> {
    if !kind.hook_support().can_install_hook() {
        anyhow::bail!(
            "{} does not support hook installation ({})",
            kind.name(),
            kind.hook_support()
        );
    }

    match kind {
        AgentKind::ClaudeCode => install_claude_code_hook(dry_run),
        AgentKind::GeminiCli => install_gemini_cli_hook(dry_run),
        AgentKind::CodexCli => install_codex_cli_hook(dry_run),
        AgentKind::ContinueDev => install_continue_dev_hook(dry_run),
        _ => anyhow::bail!("{} hook installation not implemented", kind.name()),
    }
}

/// Uninstall the RCH hook from an agent.
pub fn uninstall_hook(kind: AgentKind, dry_run: bool) -> Result<IdempotentResult> {
    if !kind.hook_support().can_install_hook() {
        anyhow::bail!(
            "{} does not support hook uninstallation ({})",
            kind.name(),
            kind.hook_support()
        );
    }

    match kind {
        AgentKind::ClaudeCode => uninstall_claude_code_hook(dry_run),
        AgentKind::GeminiCli => uninstall_gemini_cli_hook(dry_run),
        AgentKind::CodexCli => uninstall_codex_cli_hook(dry_run),
        AgentKind::ContinueDev => uninstall_continue_dev_hook(dry_run),
        _ => anyhow::bail!("{} hook uninstallation not implemented", kind.name()),
    }
}

// === Claude Code Hook ===

fn claude_code_settings_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".claude").join("settings.json"))
}

fn check_claude_code_hook() -> Result<HookStatus> {
    let settings_path = match claude_code_settings_path() {
        Some(p) => p,
        None => return Ok(HookStatus::NotInstalled),
    };

    if !settings_path.exists() {
        return Ok(HookStatus::NotInstalled);
    }

    let content =
        std::fs::read_to_string(&settings_path).context("Failed to read Claude Code settings")?;

    let settings: Value =
        serde_json::from_str(&content).context("Failed to parse Claude Code settings")?;

    // Check for PreToolUse hook with rch
    if let Some(hooks) = settings.get("hooks")
        && let Some(pre_tool_use) = hooks.get("PreToolUse")
        && let Some(arr) = pre_tool_use.as_array()
    {
        for hook in arr {
            if let Some(cmd) = hook.get("command").and_then(|c| c.as_str())
                && cmd.contains("rch")
            {
                return Ok(HookStatus::Installed);
            }
            // Also check for string hooks
            if let Some(cmd) = hook.as_str() && cmd.contains("rch") {
                return Ok(HookStatus::Installed);
            }
        }
    }

    Ok(HookStatus::NotInstalled)
}

fn install_claude_code_hook(dry_run: bool) -> Result<IdempotentResult> {
    let settings_path = claude_code_settings_path()
        .ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?;

    if dry_run {
        return Ok(IdempotentResult::WouldChange(format!(
            "Would add RCH hook to {}",
            settings_path.display()
        )));
    }

    // Ensure .claude directory exists
    if let Some(parent) = settings_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Read existing settings or create new
    let mut settings: Value = if settings_path.exists() {
        let content = std::fs::read_to_string(&settings_path)?;
        serde_json::from_str(&content).unwrap_or_else(|_| serde_json::json!({}))
    } else {
        serde_json::json!({})
    };

    // Check if already installed
    if check_claude_code_hook()? == HookStatus::Installed {
        return Ok(IdempotentResult::Unchanged);
    }

    // Create backup
    if settings_path.exists() {
        create_backup(&settings_path)?;
    }

    // Add the hook
    let hook_entry = serde_json::json!({
        "command": "rch",
        "description": "Remote Compilation Helper - routes builds to remote workers"
    });

    let hooks = settings
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("Settings is not an object"))?
        .entry("hooks")
        .or_insert_with(|| serde_json::json!({}));

    let hooks_obj = hooks
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("Hooks is not an object"))?;

    let pre_tool_use = hooks_obj
        .entry("PreToolUse")
        .or_insert_with(|| serde_json::json!([]));

    if let Some(arr) = pre_tool_use.as_array_mut() {
        arr.push(hook_entry);
    }

    // Write settings atomically
    let content = serde_json::to_string_pretty(&settings)?;
    atomic_write(&settings_path, content.as_bytes())?;

    Ok(IdempotentResult::Changed)
}

fn uninstall_claude_code_hook(dry_run: bool) -> Result<IdempotentResult> {
    let settings_path = claude_code_settings_path()
        .ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?;

    if !settings_path.exists() {
        return Ok(IdempotentResult::Unchanged);
    }

    if dry_run {
        return Ok(IdempotentResult::WouldChange(format!(
            "Would remove RCH hook from {}",
            settings_path.display()
        )));
    }

    let content = std::fs::read_to_string(&settings_path)?;
    let mut settings: Value = serde_json::from_str(&content)?;

    // Check if hook exists
    if check_claude_code_hook()? == HookStatus::NotInstalled {
        return Ok(IdempotentResult::Unchanged);
    }

    // Create backup
    create_backup(&settings_path)?;

    // Remove the hook
    if let Some(hooks) = settings.get_mut("hooks")
        && let Some(pre_tool_use) = hooks.get_mut("PreToolUse")
        && let Some(arr) = pre_tool_use.as_array_mut()
    {
        arr.retain(|hook| {
            let cmd = hook
                .get("command")
                .and_then(|c| c.as_str())
                .or_else(|| hook.as_str());
            !cmd.map(|c| c.contains("rch")).unwrap_or(false)
        });
    }

    // Write settings atomically
    let content = serde_json::to_string_pretty(&settings)?;
    atomic_write(&settings_path, content.as_bytes())?;

    Ok(IdempotentResult::Changed)
}

// === Gemini CLI Hook ===

fn gemini_cli_settings_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".gemini").join("settings.json"))
}

fn check_gemini_cli_hook() -> Result<HookStatus> {
    let settings_path = match gemini_cli_settings_path() {
        Some(p) => p,
        None => return Ok(HookStatus::NotInstalled),
    };

    if !settings_path.exists() {
        return Ok(HookStatus::NotInstalled);
    }

    let content = std::fs::read_to_string(&settings_path)?;
    let settings: Value = serde_json::from_str(&content)?;

    // Check for pre_tool_use hook with rch
    if let Some(hooks) = settings.get("hooks")
        && let Some(pre_tool_use) = hooks.get("pre_tool_use")
        && let Some(arr) = pre_tool_use.as_array()
    {
        for hook in arr {
            if let Some(cmd) = hook.get("command").and_then(|c| c.as_str())
                && cmd.contains("rch")
            {
                return Ok(HookStatus::Installed);
            }
        }
    }

    Ok(HookStatus::NotInstalled)
}

fn install_gemini_cli_hook(dry_run: bool) -> Result<IdempotentResult> {
    let settings_path = gemini_cli_settings_path()
        .ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?;

    if dry_run {
        return Ok(IdempotentResult::WouldChange(format!(
            "Would add RCH hook to {}",
            settings_path.display()
        )));
    }

    // Similar structure to Claude Code
    if let Some(parent) = settings_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut settings: Value = if settings_path.exists() {
        let content = std::fs::read_to_string(&settings_path)?;
        serde_json::from_str(&content).unwrap_or_else(|_| serde_json::json!({}))
    } else {
        serde_json::json!({})
    };

    if check_gemini_cli_hook()? == HookStatus::Installed {
        return Ok(IdempotentResult::Unchanged);
    }

    if settings_path.exists() {
        create_backup(&settings_path)?;
    }

    let hook_entry = serde_json::json!({
        "command": "rch",
        "description": "Remote Compilation Helper"
    });

    let hooks = settings
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("Settings is not an object"))?
        .entry("hooks")
        .or_insert_with(|| serde_json::json!({}));

    let hooks_obj = hooks
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("Hooks is not an object"))?;

    let pre_tool_use = hooks_obj
        .entry("pre_tool_use")
        .or_insert_with(|| serde_json::json!([]));

    if let Some(arr) = pre_tool_use.as_array_mut() {
        arr.push(hook_entry);
    }

    let content = serde_json::to_string_pretty(&settings)?;
    atomic_write(&settings_path, content.as_bytes())?;

    Ok(IdempotentResult::Changed)
}

fn uninstall_gemini_cli_hook(dry_run: bool) -> Result<IdempotentResult> {
    let settings_path = gemini_cli_settings_path()
        .ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?;

    if !settings_path.exists() {
        return Ok(IdempotentResult::Unchanged);
    }

    if dry_run {
        return Ok(IdempotentResult::WouldChange(format!(
            "Would remove RCH hook from {}",
            settings_path.display()
        )));
    }

    let content = std::fs::read_to_string(&settings_path)?;
    let mut settings: Value = serde_json::from_str(&content)?;

    if check_gemini_cli_hook()? == HookStatus::NotInstalled {
        return Ok(IdempotentResult::Unchanged);
    }

    create_backup(&settings_path)?;

    if let Some(hooks) = settings.get_mut("hooks")
        && let Some(pre_tool_use) = hooks.get_mut("pre_tool_use")
        && let Some(arr) = pre_tool_use.as_array_mut()
    {
        arr.retain(|hook| {
            !hook
                .get("command")
                .and_then(|c| c.as_str())
                .map(|c| c.contains("rch"))
                .unwrap_or(false)
        });
    }

    let content = serde_json::to_string_pretty(&settings)?;
    atomic_write(&settings_path, content.as_bytes())?;

    Ok(IdempotentResult::Changed)
}

// === Codex CLI Hook ===

fn codex_cli_config_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".codex").join("config.toml"))
}

fn check_codex_cli_hook() -> Result<HookStatus> {
    let config_path = match codex_cli_config_path() {
        Some(p) => p,
        None => return Ok(HookStatus::NotInstalled),
    };

    if !config_path.exists() {
        return Ok(HookStatus::NotInstalled);
    }

    let content = std::fs::read_to_string(&config_path)?;

    // Check for rch in hooks section
    if content.contains("[hooks]") && content.contains("rch") {
        return Ok(HookStatus::Installed);
    }

    Ok(HookStatus::NotInstalled)
}

fn install_codex_cli_hook(dry_run: bool) -> Result<IdempotentResult> {
    let config_path = codex_cli_config_path()
        .ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?;

    if dry_run {
        return Ok(IdempotentResult::WouldChange(format!(
            "Would add RCH hook to {}",
            config_path.display()
        )));
    }

    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    if check_codex_cli_hook()? == HookStatus::Installed {
        return Ok(IdempotentResult::Unchanged);
    }

    let mut content = if config_path.exists() {
        create_backup(&config_path)?;
        std::fs::read_to_string(&config_path)?
    } else {
        String::new()
    };

    // Add hooks section if not present
    if !content.contains("[hooks]") {
        content.push_str("\n[hooks]\n");
    }

    // Add pre_tool_use hook
    content.push_str("pre_tool_use = \"rch\"\n");

    atomic_write(&config_path, content.as_bytes())?;

    Ok(IdempotentResult::Changed)
}

fn uninstall_codex_cli_hook(dry_run: bool) -> Result<IdempotentResult> {
    let config_path = codex_cli_config_path()
        .ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?;

    if !config_path.exists() {
        return Ok(IdempotentResult::Unchanged);
    }

    if dry_run {
        return Ok(IdempotentResult::WouldChange(format!(
            "Would remove RCH hook from {}",
            config_path.display()
        )));
    }

    if check_codex_cli_hook()? == HookStatus::NotInstalled {
        return Ok(IdempotentResult::Unchanged);
    }

    create_backup(&config_path)?;

    let content = std::fs::read_to_string(&config_path)?;
    let new_content: String = content
        .lines()
        .filter(|line| !line.contains("rch"))
        .collect::<Vec<_>>()
        .join("\n");

    atomic_write(&config_path, new_content.as_bytes())?;

    Ok(IdempotentResult::Changed)
}

// === Continue.dev Hook ===

fn continue_dev_config_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".continue").join("config.json"))
}

fn check_continue_dev_hook() -> Result<HookStatus> {
    let config_path = match continue_dev_config_path() {
        Some(p) => p,
        None => return Ok(HookStatus::NotInstalled),
    };

    if !config_path.exists() {
        return Ok(HookStatus::NotInstalled);
    }

    let content = std::fs::read_to_string(&config_path)?;
    let config: Value = serde_json::from_str(&content)?;

    // Check for rch in experimental features or custom commands
    if let Some(experimental) = config.get("experimental")
        && let Some(pre_cmd) = experimental.get("preCompileCommand")
        && pre_cmd.as_str().map(|s| s.contains("rch")).unwrap_or(false)
    {
        return Ok(HookStatus::Installed);
    }

    Ok(HookStatus::NotInstalled)
}

fn install_continue_dev_hook(dry_run: bool) -> Result<IdempotentResult> {
    let config_path = continue_dev_config_path()
        .ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?;

    if dry_run {
        return Ok(IdempotentResult::WouldChange(format!(
            "Would add RCH hook to {}",
            config_path.display()
        )));
    }

    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut config: Value = if config_path.exists() {
        let content = std::fs::read_to_string(&config_path)?;
        serde_json::from_str(&content).unwrap_or_else(|_| serde_json::json!({}))
    } else {
        serde_json::json!({})
    };

    if check_continue_dev_hook()? == HookStatus::Installed {
        return Ok(IdempotentResult::Unchanged);
    }

    if config_path.exists() {
        create_backup(&config_path)?;
    }

    let experimental = config
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("Config is not an object"))?
        .entry("experimental")
        .or_insert_with(|| serde_json::json!({}));

    if let Some(exp_obj) = experimental.as_object_mut() {
        exp_obj.insert("preCompileCommand".to_string(), serde_json::json!("rch"));
    }

    let content = serde_json::to_string_pretty(&config)?;
    atomic_write(&config_path, content.as_bytes())?;

    Ok(IdempotentResult::Changed)
}

fn uninstall_continue_dev_hook(dry_run: bool) -> Result<IdempotentResult> {
    let config_path = continue_dev_config_path()
        .ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?;

    if !config_path.exists() {
        return Ok(IdempotentResult::Unchanged);
    }

    if dry_run {
        return Ok(IdempotentResult::WouldChange(format!(
            "Would remove RCH hook from {}",
            config_path.display()
        )));
    }

    if check_continue_dev_hook()? == HookStatus::NotInstalled {
        return Ok(IdempotentResult::Unchanged);
    }

    create_backup(&config_path)?;

    let content = std::fs::read_to_string(&config_path)?;
    let mut config: Value = serde_json::from_str(&content)?;

    if let Some(experimental) = config.get_mut("experimental")
        && let Some(exp_obj) = experimental.as_object_mut()
    {
        exp_obj.remove("preCompileCommand");
    }

    let content = serde_json::to_string_pretty(&config)?;
    atomic_write(&config_path, content.as_bytes())?;

    Ok(IdempotentResult::Changed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hook_status_display() {
        assert_eq!(HookStatus::Installed.to_string(), "Installed");
        assert_eq!(HookStatus::NotInstalled.to_string(), "Not installed");
        assert_eq!(HookStatus::NotSupported.to_string(), "Not supported");
    }

    #[test]
    fn test_check_unsupported_agents() {
        // Agents without hook support should return NotSupported
        assert_eq!(
            check_hook_status(AgentKind::Cursor).unwrap(),
            HookStatus::NotSupported
        );
        assert_eq!(
            check_hook_status(AgentKind::Aider).unwrap(),
            HookStatus::NotSupported
        );
    }
}
