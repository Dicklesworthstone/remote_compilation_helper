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
    check_claude_code_hook_at_path(&settings_path)
}

/// Internal implementation that accepts a path for testability.
fn check_claude_code_hook_at_path(settings_path: &std::path::Path) -> Result<HookStatus> {
    if !settings_path.exists() {
        return Ok(HookStatus::NotInstalled);
    }

    let content =
        std::fs::read_to_string(settings_path).context("Failed to read Claude Code settings")?;

    let settings: Value = match serde_json::from_str(&content) {
        Ok(settings) => settings,
        Err(_) => {
            // Malformed JSON should not crash status checks. Treat as misconfigured.
            return Ok(HookStatus::NeedsUpdate);
        }
    };

    // Check for PreToolUse hook with rch
    if let Some(hooks) = settings.get("hooks")
        && let Some(pre_tool_use) = hooks.get("PreToolUse")
        && let Some(arr) = pre_tool_use.as_array()
    {
        for hook in arr {
            // Check correct format: { "matcher": "Bash", "hooks": [{ "command": "rch" }] }
            if let Some(inner_hooks) = hook.get("hooks").and_then(|h| h.as_array()) {
                for inner in inner_hooks {
                    if let Some(cmd) = inner.get("command").and_then(|c| c.as_str())
                        && cmd.contains("rch")
                    {
                        return Ok(HookStatus::Installed);
                    }
                }
            }
            // Also check obsolete format for backwards compatibility detection:
            // { "command": "rch", "description": "..." }
            if let Some(cmd) = hook.get("command").and_then(|c| c.as_str())
                && cmd.contains("rch")
                && hook.get("matcher").is_none()
            {
                // Obsolete format detected - needs update
                return Ok(HookStatus::NeedsUpdate);
            }
        }
    }

    Ok(HookStatus::NotInstalled)
}

fn install_claude_code_hook(dry_run: bool) -> Result<IdempotentResult> {
    let settings_path = claude_code_settings_path()
        .ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?;
    install_claude_code_hook_at_path(&settings_path, dry_run)
}

/// Internal implementation that accepts a path for testability.
fn install_claude_code_hook_at_path(
    settings_path: &std::path::Path,
    dry_run: bool,
) -> Result<IdempotentResult> {
    // Check if the .claude directory exists - if not, user doesn't use Claude Code
    // We should NOT create the directory for them
    let claude_dir = settings_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Could not determine .claude directory"))?;

    if !claude_dir.exists() {
        return Ok(IdempotentResult::NotApplicable(
            "~/.claude directory does not exist (user does not use Claude Code)".to_string(),
        ));
    }

    if dry_run {
        return Ok(IdempotentResult::WouldChange(format!(
            "Would add RCH hook to {}",
            settings_path.display()
        )));
    }

    // Read existing settings or create new
    let mut settings: Value = if settings_path.exists() {
        let content = std::fs::read_to_string(settings_path)?;
        serde_json::from_str(&content).unwrap_or_else(|_| serde_json::json!({}))
    } else {
        serde_json::json!({})
    };

    // Check if already installed (correctly)
    let current_status = check_claude_code_hook_at_path(settings_path)?;
    if current_status == HookStatus::Installed {
        return Ok(IdempotentResult::Unchanged);
    }

    // Create backup
    if settings_path.exists() {
        create_backup(settings_path)?;
    }

    // If obsolete format exists, we need to remove it first
    if current_status == HookStatus::NeedsUpdate {
        // Remove obsolete entries before adding correct one
        if let Some(hooks) = settings.get_mut("hooks")
            && let Some(pre_tool_use) = hooks.get_mut("PreToolUse")
            && let Some(arr) = pre_tool_use.as_array_mut()
        {
            arr.retain(|hook| {
                // Keep entries that don't have obsolete rch format
                let is_obsolete_rch = hook
                    .get("command")
                    .and_then(|c| c.as_str())
                    .map(|c| c.contains("rch"))
                    .unwrap_or(false)
                    && hook.get("matcher").is_none();
                !is_obsolete_rch
            });
        }
    }

    // Get the rch binary path (prefer full path if available)
    let hook_path = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("rch")))
        .filter(|p| p.exists())
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|| "rch".to_string());

    // Add the hook in the correct format
    let hook_entry = serde_json::json!({
        "matcher": "Bash",
        "hooks": [
            {
                "type": "command",
                "command": hook_path
            }
        ]
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
    atomic_write(settings_path, content.as_bytes())?;

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

    // Check if hook exists (either correct or obsolete format)
    let status = check_claude_code_hook()?;
    if status == HookStatus::NotInstalled || status == HookStatus::NotSupported {
        return Ok(IdempotentResult::Unchanged);
    }

    // Create backup
    create_backup(&settings_path)?;

    // Remove the hook (handle both old and new formats)
    if let Some(hooks) = settings.get_mut("hooks")
        && let Some(pre_tool_use) = hooks.get_mut("PreToolUse")
        && let Some(arr) = pre_tool_use.as_array_mut()
    {
        arr.retain(|hook| {
            // Check correct format: { "matcher": "Bash", "hooks": [{ "command": "rch" }] }
            if let Some(inner_hooks) = hook.get("hooks").and_then(|h| h.as_array()) {
                for inner in inner_hooks {
                    if let Some(cmd) = inner.get("command").and_then(|c| c.as_str())
                        && cmd.contains("rch")
                    {
                        return false; // Remove this entry
                    }
                }
            }
            // Check obsolete format: { "command": "rch", ... }
            if let Some(cmd) = hook.get("command").and_then(|c| c.as_str())
                && cmd.contains("rch")
                && hook.get("matcher").is_none()
            {
                return false; // Remove this entry
            }
            true // Keep other entries
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
    let lines: Vec<&str> = content.lines().collect();

    if let Some((start, end)) = find_toml_section_range(&lines, "hooks") {
        for line in &lines[start + 1..end] {
            if is_pre_tool_use_rch(line) {
                return Ok(HookStatus::Installed);
            }
        }
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

    let content = if config_path.exists() {
        create_backup(&config_path)?;
        std::fs::read_to_string(&config_path)?
    } else {
        String::new()
    };
    let mut lines: Vec<String> = content.lines().map(|line| line.to_string()).collect();

    let mut changed = false;
    if let Some((start, end)) = find_toml_section_range(
        &lines.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
        "hooks",
    ) {
        // Update existing pre_tool_use line or insert if missing
        let mut found = false;
        for line in &mut lines[start + 1..end] {
            if is_pre_tool_use_line(line) {
                if !is_pre_tool_use_rch(line) {
                    *line = "pre_tool_use = \"rch\"".to_string();
                    changed = true;
                }
                found = true;
                break;
            }
        }

        if !found {
            lines.insert(end, "pre_tool_use = \"rch\"".to_string());
            changed = true;
        }
    } else {
        if !lines.is_empty() && !lines.last().map(|l| l.trim().is_empty()).unwrap_or(false) {
            lines.push(String::new());
        }
        lines.push("[hooks]".to_string());
        lines.push("pre_tool_use = \"rch\"".to_string());
        changed = true;
    }

    if !changed {
        return Ok(IdempotentResult::Unchanged);
    }

    let updated = ensure_trailing_newline(lines.join("\n"));
    atomic_write(&config_path, updated.as_bytes())?;

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
    let mut lines: Vec<String> = content.lines().map(|line| line.to_string()).collect();

    let mut changed = false;
    if let Some((start, end)) = find_toml_section_range(
        &lines.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
        "hooks",
    ) {
        let mut idx = start + 1;
        while idx < end {
            if is_pre_tool_use_rch(&lines[idx]) {
                lines.remove(idx);
                changed = true;
                break;
            }
            idx += 1;
        }
    }

    if !changed {
        return Ok(IdempotentResult::Unchanged);
    }

    let updated = ensure_trailing_newline(lines.join("\n"));
    atomic_write(&config_path, updated.as_bytes())?;

    Ok(IdempotentResult::Changed)
}

fn find_toml_section_range(lines: &[&str], section: &str) -> Option<(usize, usize)> {
    let header = format!("[{}]", section);
    let mut start = None;

    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed == header {
            start = Some(idx);
            continue;
        }

        if start.is_some() && trimmed.starts_with('[') && trimmed.ends_with(']') {
            return start.map(|s| (s, idx));
        }
    }

    start.map(|s| (s, lines.len()))
}

fn has_pre_tool_use_key(line: &str) -> bool {
    let trimmed = line.trim_start();
    let Some(rest) = trimmed.strip_prefix("pre_tool_use") else {
        return false;
    };

    match rest.chars().next() {
        None => true,
        Some(c) => c.is_whitespace() || c == '=',
    }
}

fn is_pre_tool_use_line(line: &str) -> bool {
    has_pre_tool_use_key(line)
}

fn is_pre_tool_use_rch(line: &str) -> bool {
    let stripped = line.split('#').next().unwrap_or("").trim();
    if !has_pre_tool_use_key(stripped) {
        return false;
    }

    let Some((_, value)) = stripped.split_once('=') else {
        return false;
    };

    let value = value.trim();

    // Handle string format: pre_tool_use = "rch"
    if value.starts_with('"') || value.starts_with('\'') {
        let unquoted = value.trim_matches('"').trim_matches('\'');
        return unquoted == "rch";
    }

    // Handle array format: pre_tool_use = ["rch", "other"]
    if value.starts_with('[') && value.ends_with(']') {
        let inner = &value[1..value.len() - 1];
        return inner.split(',').any(|item| {
            let item = item.trim().trim_matches('"').trim_matches('\'');
            item == "rch"
        });
    }

    // Bare word (unlikely but handle it)
    value == "rch"
}

fn ensure_trailing_newline(content: String) -> String {
    if content.ends_with('\n') {
        content
    } else {
        format!("{}\n", content)
    }
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

    // ===== TEST: HookStatus =====

    #[test]
    fn test_hook_status_display() {
        eprintln!("TEST START: test_hook_status_display");
        assert_eq!(HookStatus::Installed.to_string(), "Installed");
        assert_eq!(HookStatus::NeedsUpdate.to_string(), "Needs update");
        assert_eq!(HookStatus::NotInstalled.to_string(), "Not installed");
        assert_eq!(HookStatus::NotSupported.to_string(), "Not supported");
        eprintln!("TEST PASS: test_hook_status_display");
    }

    #[test]
    fn test_hook_status_equality() {
        eprintln!("TEST START: test_hook_status_equality");
        assert_eq!(HookStatus::Installed, HookStatus::Installed);
        assert_ne!(HookStatus::Installed, HookStatus::NotInstalled);
        assert_ne!(HookStatus::NeedsUpdate, HookStatus::NotSupported);
        eprintln!("TEST PASS: test_hook_status_equality");
    }

    #[test]
    fn test_hook_status_serde_roundtrip() {
        eprintln!("TEST START: test_hook_status_serde_roundtrip");
        let statuses = [
            HookStatus::Installed,
            HookStatus::NeedsUpdate,
            HookStatus::NotInstalled,
            HookStatus::NotSupported,
        ];
        for status in statuses {
            let json = serde_json::to_string(&status).expect("serialize");
            let parsed: HookStatus = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(status, parsed);
            eprintln!("  {:?} <-> {}", status, json);
        }
        eprintln!("TEST PASS: test_hook_status_serde_roundtrip");
    }

    // ===== TEST: check_hook_status =====

    #[test]
    fn test_check_unsupported_agents() {
        eprintln!("TEST START: test_check_unsupported_agents");
        // Agents without hook support should return NotSupported
        assert_eq!(
            check_hook_status(AgentKind::Cursor).unwrap(),
            HookStatus::NotSupported
        );
        assert_eq!(
            check_hook_status(AgentKind::Aider).unwrap(),
            HookStatus::NotSupported
        );
        assert_eq!(
            check_hook_status(AgentKind::Windsurf).unwrap(),
            HookStatus::NotSupported
        );
        assert_eq!(
            check_hook_status(AgentKind::Cline).unwrap(),
            HookStatus::NotSupported
        );
        eprintln!("TEST PASS: test_check_unsupported_agents");
    }

    #[test]
    fn test_check_hook_status_all_agents_no_panic() {
        eprintln!("TEST START: test_check_hook_status_all_agents_no_panic");
        for kind in AgentKind::ALL {
            let result = check_hook_status(*kind);
            assert!(
                result.is_ok(),
                "check_hook_status({:?}) should not error",
                kind
            );
            let status = result.unwrap();
            eprintln!("  {:?}: {:?}", kind, status);

            // Verify consistency with hook_support
            if !kind.hook_support().can_install_hook() {
                assert_eq!(
                    status,
                    HookStatus::NotSupported,
                    "Agent {:?} should be NotSupported",
                    kind
                );
            }
        }
        eprintln!("TEST PASS: test_check_hook_status_all_agents_no_panic");
    }

    #[test]
    fn test_check_hook_status_supported_agents() {
        eprintln!("TEST START: test_check_hook_status_supported_agents");
        // Supported agents: ClaudeCode, GeminiCli, CodexCli, ContinueDev
        let supported = [
            AgentKind::ClaudeCode,
            AgentKind::GeminiCli,
            AgentKind::CodexCli,
            AgentKind::ContinueDev,
        ];

        for kind in supported {
            let status = check_hook_status(kind).expect("should not error");
            // Status should be one of Installed, NeedsUpdate, or NotInstalled
            assert!(
                matches!(
                    status,
                    HookStatus::Installed | HookStatus::NeedsUpdate | HookStatus::NotInstalled
                ),
                "Unexpected status for {:?}: {:?}",
                kind,
                status
            );
            eprintln!("  {:?}: {:?}", kind, status);
        }
        eprintln!("TEST PASS: test_check_hook_status_supported_agents");
    }

    // ===== TEST: install_hook / uninstall_hook =====

    #[test]
    fn test_install_hook_unsupported_agents_error() {
        eprintln!("TEST START: test_install_hook_unsupported_agents_error");
        let unsupported = [
            AgentKind::Cursor,
            AgentKind::Windsurf,
            AgentKind::Aider,
            AgentKind::Cline,
        ];

        for kind in unsupported {
            let result = install_hook(kind, true); // dry_run = true
            assert!(
                result.is_err(),
                "install_hook({:?}) should error for unsupported agent",
                kind
            );
            eprintln!("  {:?}: correctly rejected", kind);
        }
        eprintln!("TEST PASS: test_install_hook_unsupported_agents_error");
    }

    #[test]
    fn test_uninstall_hook_unsupported_agents_error() {
        eprintln!("TEST START: test_uninstall_hook_unsupported_agents_error");
        let unsupported = [
            AgentKind::Cursor,
            AgentKind::Windsurf,
            AgentKind::Aider,
            AgentKind::Cline,
        ];

        for kind in unsupported {
            let result = uninstall_hook(kind, true); // dry_run = true
            assert!(
                result.is_err(),
                "uninstall_hook({:?}) should error for unsupported agent",
                kind
            );
            eprintln!("  {:?}: correctly rejected", kind);
        }
        eprintln!("TEST PASS: test_uninstall_hook_unsupported_agents_error");
    }

    #[test]
    fn test_install_hook_dry_run_supported_agents() {
        eprintln!("TEST START: test_install_hook_dry_run_supported_agents");
        let supported = [
            AgentKind::ClaudeCode,
            AgentKind::GeminiCli,
            AgentKind::CodexCli,
            AgentKind::ContinueDev,
        ];

        for kind in supported {
            let result = install_hook(kind, true); // dry_run = true
            assert!(
                result.is_ok(),
                "install_hook({:?}, dry_run=true) should not error: {:?}",
                kind,
                result
            );
            let outcome = result.unwrap();
            eprintln!("  {:?}: {:?}", kind, outcome);
        }
        eprintln!("TEST PASS: test_install_hook_dry_run_supported_agents");
    }

    #[test]
    fn test_uninstall_hook_dry_run_supported_agents() {
        eprintln!("TEST START: test_uninstall_hook_dry_run_supported_agents");
        let supported = [
            AgentKind::ClaudeCode,
            AgentKind::GeminiCli,
            AgentKind::CodexCli,
            AgentKind::ContinueDev,
        ];

        for kind in supported {
            let result = uninstall_hook(kind, true); // dry_run = true
            assert!(
                result.is_ok(),
                "uninstall_hook({:?}, dry_run=true) should not error: {:?}",
                kind,
                result
            );
            let outcome = result.unwrap();
            eprintln!("  {:?}: {:?}", kind, outcome);
        }
        eprintln!("TEST PASS: test_uninstall_hook_dry_run_supported_agents");
    }

    // ===== TEST: TOML parsing helpers =====

    #[test]
    fn test_is_pre_tool_use_rch_string_format() {
        eprintln!("TEST START: test_is_pre_tool_use_rch_string_format");
        // Double quotes
        assert!(is_pre_tool_use_rch("pre_tool_use = \"rch\""));
        assert!(is_pre_tool_use_rch("  pre_tool_use = \"rch\"  "));
        assert!(is_pre_tool_use_rch("pre_tool_use=\"rch\""));

        // Single quotes
        assert!(is_pre_tool_use_rch("pre_tool_use = 'rch'"));

        // With comments
        assert!(is_pre_tool_use_rch("pre_tool_use = \"rch\" # comment"));

        // Not rch
        assert!(!is_pre_tool_use_rch("pre_tool_use = \"other\""));
        assert!(!is_pre_tool_use_rch("pre_tool_use = \"rch-extended\""));
        eprintln!("TEST PASS: test_is_pre_tool_use_rch_string_format");
    }

    #[test]
    fn test_is_pre_tool_use_rch_array_format() {
        eprintln!("TEST START: test_is_pre_tool_use_rch_array_format");
        // Array with rch
        assert!(is_pre_tool_use_rch("pre_tool_use = [\"rch\"]"));
        assert!(is_pre_tool_use_rch("pre_tool_use = [\"rch\", \"other\"]"));
        assert!(is_pre_tool_use_rch("pre_tool_use = [\"other\", \"rch\"]"));
        assert!(is_pre_tool_use_rch("pre_tool_use = ['rch', 'other']"));

        // Array without rch
        assert!(!is_pre_tool_use_rch("pre_tool_use = [\"other\"]"));
        assert!(!is_pre_tool_use_rch("pre_tool_use = [\"foo\", \"bar\"]"));
        eprintln!("TEST PASS: test_is_pre_tool_use_rch_array_format");
    }

    #[test]
    fn test_is_pre_tool_use_rch_edge_cases() {
        eprintln!("TEST START: test_is_pre_tool_use_rch_edge_cases");

        // Empty line
        assert!(!is_pre_tool_use_rch(""));

        // Comment line
        assert!(!is_pre_tool_use_rch("# pre_tool_use = \"rch\""));

        // Different key
        assert!(!is_pre_tool_use_rch("post_tool_use = \"rch\""));

        // No value
        assert!(!is_pre_tool_use_rch("pre_tool_use"));
        assert!(!is_pre_tool_use_rch("pre_tool_use ="));

        // rch as substring (should not match)
        assert!(!is_pre_tool_use_rch("pre_tool_use = \"rch_extended\""));
        assert!(!is_pre_tool_use_rch("pre_tool_use = \"my_rch\""));

        // Mixed quotes in array
        assert!(is_pre_tool_use_rch("pre_tool_use = [\"rch\", 'other']"));

        eprintln!("TEST PASS: test_is_pre_tool_use_rch_edge_cases");
    }

    #[test]
    fn test_is_pre_tool_use_line() {
        eprintln!("TEST START: test_is_pre_tool_use_line");
        assert!(is_pre_tool_use_line("pre_tool_use = \"rch\""));
        assert!(is_pre_tool_use_line("  pre_tool_use = \"rch\""));
        assert!(is_pre_tool_use_line("\tpre_tool_use = \"rch\""));
        assert!(is_pre_tool_use_line("pre_tool_use"));
        assert!(is_pre_tool_use_line("pre_tool_use ="));
        assert!(!is_pre_tool_use_line("# pre_tool_use = \"rch\""));
        assert!(!is_pre_tool_use_line("other_key = \"value\""));
        assert!(!is_pre_tool_use_line(""));
        assert!(!is_pre_tool_use_line("pre_tool_uses = \"rch\""));
        assert!(!is_pre_tool_use_line("pre_tool_useful = \"rch\""));
        eprintln!("TEST PASS: test_is_pre_tool_use_line");
    }

    #[test]
    fn test_find_toml_section_range() {
        eprintln!("TEST START: test_find_toml_section_range");
        let lines = vec![
            "# comment",
            "[hooks]",
            "pre_tool_use = \"rch\"",
            "",
            "[other]",
            "key = \"value\"",
        ];

        let range = find_toml_section_range(&lines, "hooks");
        assert_eq!(range, Some((1, 4)));

        let range = find_toml_section_range(&lines, "other");
        assert_eq!(range, Some((4, 6)));

        let range = find_toml_section_range(&lines, "missing");
        assert_eq!(range, None);
        eprintln!("TEST PASS: test_find_toml_section_range");
    }

    #[test]
    fn test_find_toml_section_range_at_end() {
        eprintln!("TEST START: test_find_toml_section_range_at_end");
        let lines = vec!["[hooks]", "pre_tool_use = \"rch\""];

        let range = find_toml_section_range(&lines, "hooks");
        assert_eq!(range, Some((0, 2)));
        eprintln!("TEST PASS: test_find_toml_section_range_at_end");
    }

    #[test]
    fn test_find_toml_section_range_empty() {
        eprintln!("TEST START: test_find_toml_section_range_empty");
        let lines: Vec<&str> = vec![];
        assert_eq!(find_toml_section_range(&lines, "hooks"), None);

        let lines = vec!["# just a comment"];
        assert_eq!(find_toml_section_range(&lines, "hooks"), None);
        eprintln!("TEST PASS: test_find_toml_section_range_empty");
    }

    #[test]
    fn test_find_toml_section_range_nested_brackets() {
        eprintln!("TEST START: test_find_toml_section_range_nested_brackets");
        let lines = vec![
            "[parent]",
            "key = \"value\"",
            "[parent.child]", // Not a top-level section
            "nested = true",
            "[sibling]",
            "other = 1",
        ];

        // Should find [parent] from line 0 to line 2 (before [parent.child])
        // Actually, the current implementation treats [parent.child] as a new section
        let range = find_toml_section_range(&lines, "parent");
        assert!(range.is_some());
        let (start, end) = range.unwrap();
        assert_eq!(start, 0);
        // End should be before the next section header
        assert!(end <= 2 || end <= 4, "Expected end <= 4, got {}", end);
        eprintln!("TEST PASS: test_find_toml_section_range_nested_brackets");
    }

    #[test]
    fn test_find_toml_section_range_whitespace() {
        eprintln!("TEST START: test_find_toml_section_range_whitespace");
        let lines = vec![
            "  [hooks]  ", // Note: current impl uses trim()
            "pre_tool_use = \"rch\"",
        ];

        // Should still find it because we trim
        let range = find_toml_section_range(&lines, "hooks");
        assert_eq!(range, Some((0, 2)));
        eprintln!("TEST PASS: test_find_toml_section_range_whitespace");
    }

    #[test]
    fn test_ensure_trailing_newline() {
        eprintln!("TEST START: test_ensure_trailing_newline");
        assert_eq!(ensure_trailing_newline("foo".to_string()), "foo\n");
        assert_eq!(ensure_trailing_newline("foo\n".to_string()), "foo\n");
        assert_eq!(ensure_trailing_newline("".to_string()), "\n");
        assert_eq!(
            ensure_trailing_newline("multi\nline".to_string()),
            "multi\nline\n"
        );
        assert_eq!(
            ensure_trailing_newline("multi\nline\n".to_string()),
            "multi\nline\n"
        );
        eprintln!("TEST PASS: test_ensure_trailing_newline");
    }

    // ===== TEST: Config path helpers =====

    #[test]
    fn test_claude_code_settings_path() {
        eprintln!("TEST START: test_claude_code_settings_path");
        let path = claude_code_settings_path();
        if let Some(p) = &path {
            assert!(p.to_string_lossy().contains(".claude"));
            assert!(p.to_string_lossy().contains("settings.json"));
            eprintln!("  Path: {:?}", p);
        } else {
            eprintln!("  Path: None (HOME not set)");
        }
        eprintln!("TEST PASS: test_claude_code_settings_path");
    }

    #[test]
    fn test_gemini_cli_settings_path() {
        eprintln!("TEST START: test_gemini_cli_settings_path");
        let path = gemini_cli_settings_path();
        if let Some(p) = &path {
            assert!(p.to_string_lossy().contains(".gemini"));
            assert!(p.to_string_lossy().contains("settings.json"));
            eprintln!("  Path: {:?}", p);
        } else {
            eprintln!("  Path: None (HOME not set)");
        }
        eprintln!("TEST PASS: test_gemini_cli_settings_path");
    }

    #[test]
    fn test_codex_cli_config_path() {
        eprintln!("TEST START: test_codex_cli_config_path");
        let path = codex_cli_config_path();
        if let Some(p) = &path {
            assert!(p.to_string_lossy().contains(".codex"));
            assert!(p.to_string_lossy().contains("config.toml"));
            eprintln!("  Path: {:?}", p);
        } else {
            eprintln!("  Path: None (HOME not set)");
        }
        eprintln!("TEST PASS: test_codex_cli_config_path");
    }

    #[test]
    fn test_continue_dev_config_path() {
        eprintln!("TEST START: test_continue_dev_config_path");
        let path = continue_dev_config_path();
        if let Some(p) = &path {
            assert!(p.to_string_lossy().contains(".continue"));
            assert!(p.to_string_lossy().contains("config.json"));
            eprintln!("  Path: {:?}", p);
        } else {
            eprintln!("  Path: None (HOME not set)");
        }
        eprintln!("TEST PASS: test_continue_dev_config_path");
    }

    // ===== TEST: Self-Healing Hook Installation (bd-59kg) =====
    //
    // These tests use the internal `_at_path` functions directly to avoid
    // needing to manipulate HOME env var (which requires unsafe in Rust 2024).

    /// Test environment helper for isolated hook tests.
    struct TestEnv {
        temp_dir: tempfile::TempDir,
    }

    impl TestEnv {
        fn new() -> Self {
            Self {
                temp_dir: tempfile::TempDir::new().expect("Failed to create temp dir"),
            }
        }

        fn claude_dir(&self) -> std::path::PathBuf {
            self.temp_dir.path().join(".claude")
        }

        fn settings_path(&self) -> std::path::PathBuf {
            self.claude_dir().join("settings.json")
        }

        fn create_claude_dir(&self) {
            std::fs::create_dir_all(self.claude_dir()).expect("Failed to create .claude dir");
        }

        fn write_settings_json(&self, value: &serde_json::Value) {
            std::fs::write(
                self.settings_path(),
                serde_json::to_string_pretty(value).unwrap(),
            )
            .expect("Failed to write settings.json");
        }

        fn read_settings_json(&self) -> serde_json::Value {
            let content = std::fs::read_to_string(self.settings_path())
                .expect("Failed to read settings.json");
            serde_json::from_str(&content).expect("Failed to parse settings.json")
        }
    }

    /// CRITICAL TEST: When ~/.claude directory doesn't exist, return NotApplicable
    /// and do NOT create the directory.
    #[test]
    fn test_install_hook_at_path_no_claude_dir_returns_not_applicable() {
        eprintln!("TEST START: test_install_hook_at_path_no_claude_dir_returns_not_applicable");
        let test_env = TestEnv::new();

        // Verify .claude doesn't exist
        assert!(
            !test_env.claude_dir().exists(),
            ".claude should not exist initially"
        );

        // Action: call install_claude_code_hook_at_path
        let result = install_claude_code_hook_at_path(&test_env.settings_path(), false);
        eprintln!("  Result: {:?}", result);

        // Assert: returns NotApplicable (not error)
        assert!(result.is_ok(), "Should not error");
        let outcome = result.unwrap();
        assert!(
            matches!(outcome, IdempotentResult::NotApplicable(_)),
            "Expected NotApplicable, got: {:?}",
            outcome
        );

        // Assert: ~/.claude was NOT created
        assert!(
            !test_env.claude_dir().exists(),
            ".claude should NOT be created"
        );

        eprintln!("TEST PASS: test_install_hook_at_path_no_claude_dir_returns_not_applicable");
    }

    /// When .claude exists but settings.json doesn't, hook should be installed.
    #[test]
    fn test_install_hook_at_path_claude_dir_exists_no_settings() {
        eprintln!("TEST START: test_install_hook_at_path_claude_dir_exists_no_settings");
        let test_env = TestEnv::new();

        // Setup: create .claude directory (user uses Claude Code)
        test_env.create_claude_dir();
        assert!(!test_env.settings_path().exists());

        // Action: install hook
        let result = install_claude_code_hook_at_path(&test_env.settings_path(), false);
        eprintln!("  Result: {:?}", result);

        // Assert: returns Changed
        assert!(result.is_ok());
        let outcome = result.unwrap();
        assert!(
            matches!(outcome, IdempotentResult::Changed),
            "Expected Changed, got: {:?}",
            outcome
        );

        // Assert: settings.json created with hook
        assert!(test_env.settings_path().exists());
        let settings = test_env.read_settings_json();
        let hooks = settings["hooks"]["PreToolUse"].as_array();
        assert!(hooks.is_some(), "PreToolUse should exist");
        let has_rch = hooks.unwrap().iter().any(|h| {
            h.get("hooks")
                .and_then(|h| h.as_array())
                .map(|arr| {
                    arr.iter().any(|entry| {
                        entry
                            .get("command")
                            .and_then(|c| c.as_str())
                            .map(|s| s.contains("rch"))
                            .unwrap_or(false)
                    })
                })
                .unwrap_or(false)
        });
        assert!(has_rch, "RCH hook should be present");

        eprintln!("TEST PASS: test_install_hook_at_path_claude_dir_exists_no_settings");
    }

    /// When hook is already installed, return Unchanged.
    #[test]
    fn test_install_hook_at_path_already_installed() {
        eprintln!("TEST START: test_install_hook_at_path_already_installed");
        let test_env = TestEnv::new();

        // Setup: create .claude directory and settings with RCH hook
        test_env.create_claude_dir();
        test_env.write_settings_json(&serde_json::json!({
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [
                            {
                                "type": "command",
                                "command": "rch"
                            }
                        ]
                    }
                ]
            }
        }));

        // Action: install hook (should detect already installed)
        let result = install_claude_code_hook_at_path(&test_env.settings_path(), false);
        eprintln!("  Result: {:?}", result);

        // Assert: returns Unchanged
        assert!(result.is_ok());
        let outcome = result.unwrap();
        assert!(
            matches!(outcome, IdempotentResult::Unchanged),
            "Expected Unchanged, got: {:?}",
            outcome
        );

        // Assert: file unchanged (still only one hook)
        let settings = test_env.read_settings_json();
        let hooks = settings["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(hooks.len(), 1, "Should still have exactly one hook");

        eprintln!("TEST PASS: test_install_hook_at_path_already_installed");
    }

    /// When other hooks exist, RCH hook should be added while preserving others.
    #[test]
    fn test_install_hook_at_path_preserves_existing_hooks() {
        eprintln!("TEST START: test_install_hook_at_path_preserves_existing_hooks");
        let test_env = TestEnv::new();

        // Setup: settings.json with other hooks (e.g., DCG)
        test_env.create_claude_dir();
        test_env.write_settings_json(&serde_json::json!({
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [
                            {
                                "type": "command",
                                "command": "dcg"
                            }
                        ]
                    }
                ]
            },
            "other_setting": "preserved"
        }));

        // Action: install RCH hook
        let result = install_claude_code_hook_at_path(&test_env.settings_path(), false);
        eprintln!("  Result: {:?}", result);

        // Assert: returns Changed
        assert!(result.is_ok());
        let outcome = result.unwrap();
        assert!(
            matches!(outcome, IdempotentResult::Changed),
            "Expected Changed, got: {:?}",
            outcome
        );

        // Assert: DCG hook still present
        let settings = test_env.read_settings_json();
        let hooks = settings["hooks"]["PreToolUse"].as_array().unwrap();
        let has_dcg = hooks.iter().any(|h| {
            h.get("hooks")
                .and_then(|arr| arr.as_array())
                .map(|arr| {
                    arr.iter()
                        .any(|e| e.get("command").and_then(|c| c.as_str()) == Some("dcg"))
                })
                .unwrap_or(false)
        });
        assert!(has_dcg, "DCG hook should still be present");

        // Assert: RCH hook added
        let has_rch = hooks.iter().any(|h| {
            h.get("hooks")
                .and_then(|arr| arr.as_array())
                .map(|arr| {
                    arr.iter().any(|e| {
                        e.get("command")
                            .and_then(|c| c.as_str())
                            .map(|s| s.contains("rch"))
                            .unwrap_or(false)
                    })
                })
                .unwrap_or(false)
        });
        assert!(has_rch, "RCH hook should be added");

        // Assert: other settings preserved
        assert_eq!(
            settings["other_setting"], "preserved",
            "Other settings should be preserved"
        );

        eprintln!("TEST PASS: test_install_hook_at_path_preserves_existing_hooks");
    }

    /// When settings.json has malformed JSON, silently replace with valid JSON.
    #[test]
    fn test_install_hook_at_path_malformed_json_recovers() {
        eprintln!("TEST START: test_install_hook_at_path_malformed_json_recovers");
        let test_env = TestEnv::new();

        // Setup: settings.json with invalid JSON
        test_env.create_claude_dir();
        std::fs::write(test_env.settings_path(), "{ invalid json }").unwrap();

        // Action: install hook
        let result = install_claude_code_hook_at_path(&test_env.settings_path(), false);
        eprintln!("  Result: {:?}", result);

        // The current implementation silently replaces invalid JSON with {}
        // This is reasonable behavior - verify it doesn't crash and file ends up valid
        assert!(result.is_ok(), "Should not error on malformed JSON");
        let content = std::fs::read_to_string(test_env.settings_path()).unwrap();
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&content);
        assert!(parsed.is_ok(), "File should be valid JSON after install");

        eprintln!("TEST PASS: test_install_hook_at_path_malformed_json_recovers");
    }

    /// Dry run should return WouldChange without modifying anything.
    #[test]
    fn test_install_hook_at_path_dry_run_no_changes() {
        eprintln!("TEST START: test_install_hook_at_path_dry_run_no_changes");
        let test_env = TestEnv::new();

        // Setup: .claude directory exists but no settings
        test_env.create_claude_dir();
        assert!(!test_env.settings_path().exists());

        // Action: install hook with dry_run = true
        let result = install_claude_code_hook_at_path(&test_env.settings_path(), true);
        eprintln!("  Result: {:?}", result);

        // Assert: returns WouldChange
        assert!(result.is_ok());
        let outcome = result.unwrap();
        assert!(
            matches!(outcome, IdempotentResult::WouldChange(_)),
            "Expected WouldChange, got: {:?}",
            outcome
        );

        // Assert: settings.json NOT created
        assert!(
            !test_env.settings_path().exists(),
            "settings.json should NOT be created in dry run"
        );

        eprintln!("TEST PASS: test_install_hook_at_path_dry_run_no_changes");
    }

    /// Check hook status on non-existent settings file returns NotInstalled.
    #[test]
    fn test_check_hook_at_path_not_exists() {
        eprintln!("TEST START: test_check_hook_at_path_not_exists");
        let test_env = TestEnv::new();
        test_env.create_claude_dir();

        let result = check_claude_code_hook_at_path(&test_env.settings_path());
        eprintln!("  Result: {:?}", result);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), HookStatus::NotInstalled);

        eprintln!("TEST PASS: test_check_hook_at_path_not_exists");
    }

    /// Check hook status when installed returns Installed.
    #[test]
    fn test_check_hook_at_path_installed() {
        eprintln!("TEST START: test_check_hook_at_path_installed");
        let test_env = TestEnv::new();
        test_env.create_claude_dir();
        test_env.write_settings_json(&serde_json::json!({
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [
                            { "type": "command", "command": "rch" }
                        ]
                    }
                ]
            }
        }));

        let result = check_claude_code_hook_at_path(&test_env.settings_path());
        eprintln!("  Result: {:?}", result);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), HookStatus::Installed);

        eprintln!("TEST PASS: test_check_hook_at_path_installed");
    }

    /// Check hook status with obsolete format returns NeedsUpdate.
    #[test]
    fn test_check_hook_at_path_needs_update() {
        eprintln!("TEST START: test_check_hook_at_path_needs_update");
        let test_env = TestEnv::new();
        test_env.create_claude_dir();
        // Obsolete format: command at top level without matcher
        test_env.write_settings_json(&serde_json::json!({
            "hooks": {
                "PreToolUse": [
                    { "command": "rch", "description": "Old format" }
                ]
            }
        }));

        let result = check_claude_code_hook_at_path(&test_env.settings_path());
        eprintln!("  Result: {:?}", result);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), HookStatus::NeedsUpdate);

        eprintln!("TEST PASS: test_check_hook_at_path_needs_update");
    }
}
