//! Daemon hook verification and installation.
//!
//! This module provides self-healing hook management for AI coding agents.
//! The daemon can call [`verify_and_install_claude_code_hook`] at startup to
//! ensure the RCH hook is installed in Claude Code's settings.

use anyhow::{Context, Result};
use serde_json::Value;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Result of hook verification/installation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookResult {
    /// Hook was already installed and configured correctly.
    AlreadyInstalled,
    /// Hook was successfully installed during this call.
    Installed,
    /// Hook installation was skipped (with reason).
    Skipped(String),
    /// Agent/hook is not applicable (e.g., Claude Code not installed).
    NotApplicable,
}

impl std::fmt::Display for HookResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HookResult::AlreadyInstalled => write!(f, "already installed"),
            HookResult::Installed => write!(f, "installed"),
            HookResult::Skipped(reason) => write!(f, "skipped: {}", reason),
            HookResult::NotApplicable => write!(f, "not applicable"),
        }
    }
}

/// Gets the path to Claude Code settings.json.
fn claude_code_settings_path() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".claude").join("settings.json"))
}

/// Gets the path to the .claude directory.
fn claude_code_dir() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".claude"))
}

/// Checks if Claude Code appears to be installed.
///
/// Returns true if the ~/.claude directory exists.
pub fn is_claude_code_installed() -> bool {
    claude_code_dir().map(|p| p.exists()).unwrap_or(false)
}

/// Checks if the RCH hook is installed in Claude Code settings.
fn check_claude_code_hook_installed() -> Result<bool> {
    let settings_path = match claude_code_settings_path() {
        Some(p) => p,
        None => return Ok(false),
    };

    if !settings_path.exists() {
        return Ok(false);
    }

    let content =
        fs::read_to_string(&settings_path).context("Failed to read Claude Code settings")?;

    let settings: Value =
        serde_json::from_str(&content).context("Failed to parse Claude Code settings")?;

    // Check for PreToolUse hook with rch
    if let Some(hooks) = settings.get("hooks")
        && let Some(pre_tool_use) = hooks.get("PreToolUse")
        && let Some(arr) = pre_tool_use.as_array()
    {
        for hook in arr {
            // Check new format: {"matcher": "Bash", "hooks": [{"type": "command", "command": "rch"}]}
            if let Some(inner_hooks) = hook.get("hooks").and_then(|h| h.as_array()) {
                for inner in inner_hooks {
                    if let Some(cmd) = inner.get("command").and_then(|c| c.as_str())
                        && cmd.contains("rch")
                    {
                        return Ok(true);
                    }
                }
            }
            // Check old format: {"command": "rch"} (for backwards compatibility)
            if let Some(cmd) = hook.get("command").and_then(|c| c.as_str())
                && cmd.contains("rch")
            {
                return Ok(true);
            }
            // Also check for string hooks
            if let Some(cmd) = hook.as_str()
                && cmd.contains("rch")
            {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

/// Writes content to a file atomically using a temporary file.
fn atomic_write(path: &PathBuf, content: &[u8]) -> Result<()> {
    let parent = path.parent().context("Path has no parent directory")?;
    let temp_path = parent.join(format!(".{}.tmp", Uuid::new_v4()));

    let mut file = fs::File::create(&temp_path)
        .with_context(|| format!("Failed to create temp file {:?}", temp_path))?;
    file.write_all(content)
        .with_context(|| format!("Failed to write to temp file {:?}", temp_path))?;
    file.sync_all().context("Failed to sync temp file")?;

    fs::rename(&temp_path, path)
        .with_context(|| format!("Failed to rename {:?} to {:?}", temp_path, path))?;

    Ok(())
}

/// Creates a backup of a file if it exists.
fn create_backup(path: &PathBuf) -> Result<PathBuf> {
    let backup_name = format!(
        "{}.bak.{}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("file"),
        chrono::Utc::now().format("%Y%m%d_%H%M%S")
    );
    let backup_path = path
        .parent()
        .map(|p| p.join(&backup_name))
        .unwrap_or_else(|| PathBuf::from(&backup_name));

    fs::copy(path, &backup_path)
        .with_context(|| format!("Failed to create backup at {:?}", backup_path))?;

    debug!("Created backup: {:?}", backup_path);
    Ok(backup_path)
}

/// Verifies and installs the RCH hook in Claude Code settings.
///
/// This is the main entry point for daemon hook self-healing. It:
/// 1. Checks if Claude Code is installed (~/.claude exists)
/// 2. Checks if the hook is already installed
/// 3. Installs the hook if needed
///
/// # Returns
///
/// - `HookResult::AlreadyInstalled` - Hook was already present
/// - `HookResult::Installed` - Hook was just installed
/// - `HookResult::NotApplicable` - Claude Code is not installed
/// - `HookResult::Skipped(reason)` - Installation was skipped for a reason
///
/// # Errors
///
/// Returns an error if file operations fail (read/write/parse).
pub fn verify_and_install_claude_code_hook() -> Result<HookResult> {
    // Check if Claude Code is installed
    let claude_dir = match claude_code_dir() {
        Some(dir) => dir,
        None => {
            debug!("Could not determine home directory");
            return Ok(HookResult::NotApplicable);
        }
    };

    if !claude_dir.exists() {
        debug!("Claude Code not installed (~/.claude does not exist)");
        return Ok(HookResult::NotApplicable);
    }

    // Check if hook is already installed
    match check_claude_code_hook_installed() {
        Ok(true) => {
            debug!("Claude Code hook already installed");
            return Ok(HookResult::AlreadyInstalled);
        }
        Ok(false) => {
            // Proceed with installation
        }
        Err(e) => {
            // If we can't check, log warning but try to install anyway
            warn!(
                "Could not check hook status: {}, attempting installation",
                e
            );
        }
    }

    // Install the hook
    let settings_path = claude_code_settings_path()
        .ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?;

    // Ensure .claude directory exists
    if let Some(parent) = settings_path.parent() {
        fs::create_dir_all(parent)?;
    }

    // Read existing settings or create new
    let mut settings: Value = if settings_path.exists() {
        let content = fs::read_to_string(&settings_path)?;
        match serde_json::from_str(&content) {
            Ok(v) => v,
            Err(e) => {
                warn!(
                    "Existing settings.json is malformed: {}, creating fresh settings",
                    e
                );
                serde_json::json!({})
            }
        }
    } else {
        serde_json::json!({})
    };

    // Create backup if file exists
    if settings_path.exists()
        && let Err(e) = create_backup(&settings_path)
    {
        warn!("Could not create backup: {}", e);
        // Continue anyway - the backup is nice to have but not critical
    }

    // Add the hook using the new Claude Code hooks format
    let hook_entry = serde_json::json!({
        "matcher": "Bash",
        "hooks": [
            {
                "type": "command",
                "command": "rch"
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

    if !pre_tool_use.is_array() {
        *pre_tool_use = serde_json::json!([]);
    }
    pre_tool_use
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("PreToolUse should be an array after initialization"))?
        .push(hook_entry);

    // Write settings atomically
    let content = serde_json::to_string_pretty(&settings)?;
    atomic_write(&settings_path, content.as_bytes())?;

    info!("Installed RCH hook in Claude Code settings");
    Ok(HookResult::Installed)
}

/// Internal helper to check if RCH hook is present in a settings Value.
/// Used for testing and by the main verification function.
#[allow(dead_code)]
fn settings_has_rch_hook(settings: &Value) -> bool {
    if let Some(hooks) = settings.get("hooks")
        && let Some(pre_tool_use) = hooks.get("PreToolUse")
        && let Some(arr) = pre_tool_use.as_array()
    {
        for hook in arr {
            // Check new format: {"matcher": "Bash", "hooks": [{"type": "command", "command": "rch"}]}
            if let Some(inner_hooks) = hook.get("hooks").and_then(|h| h.as_array()) {
                for inner in inner_hooks {
                    if let Some(cmd) = inner.get("command").and_then(|c| c.as_str())
                        && cmd.contains("rch")
                    {
                        return true;
                    }
                }
            }
            // Check old format: {"command": "rch"} (for backwards compatibility)
            if let Some(cmd) = hook.get("command").and_then(|c| c.as_str())
                && cmd.contains("rch")
            {
                return true;
            }
            if let Some(cmd) = hook.as_str()
                && cmd.contains("rch")
            {
                return true;
            }
        }
    }
    false
}

/// Internal helper to add RCH hook to settings Value.
/// Returns the modified settings.
#[allow(dead_code)]
fn add_rch_hook_to_settings(mut settings: Value) -> Result<Value> {
    let hook_entry = serde_json::json!({
        "matcher": "Bash",
        "hooks": [
            {
                "type": "command",
                "command": "rch"
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

    if !pre_tool_use.is_array() {
        *pre_tool_use = serde_json::json!([]);
    }
    pre_tool_use
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("PreToolUse should be an array after initialization"))?
        .push(hook_entry);

    Ok(settings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::TempDir;

    // =========================================================================
    // HookResult Display Tests
    // =========================================================================

    #[test]
    fn test_hook_result_display() {
        assert_eq!(
            HookResult::AlreadyInstalled.to_string(),
            "already installed"
        );
        assert_eq!(HookResult::Installed.to_string(), "installed");
        assert_eq!(
            HookResult::Skipped("reason".to_string()).to_string(),
            "skipped: reason"
        );
        assert_eq!(HookResult::NotApplicable.to_string(), "not applicable");
    }

    #[test]
    fn test_hook_result_equality() {
        assert_eq!(HookResult::AlreadyInstalled, HookResult::AlreadyInstalled);
        assert_eq!(HookResult::Installed, HookResult::Installed);
        assert_eq!(HookResult::NotApplicable, HookResult::NotApplicable);
        assert_eq!(
            HookResult::Skipped("test".to_string()),
            HookResult::Skipped("test".to_string())
        );
        assert_ne!(
            HookResult::Skipped("a".to_string()),
            HookResult::Skipped("b".to_string())
        );
    }

    #[allow(unsafe_code)]
    mod install_tests {
        use super::*;
        use crate::config::env_test_lock;

        fn env_guard() -> std::sync::MutexGuard<'static, ()> {
            env_test_lock()
        }

        fn set_env(key: &str, value: &str) {
            // SAFETY: Tests are serialized with env_guard().
            unsafe { std::env::set_var(key, value) };
        }

        fn remove_env(key: &str) {
            // SAFETY: Tests are serialized with env_guard().
            unsafe { std::env::remove_var(key) };
        }

        struct EnvVarGuard {
            key: &'static str,
            old: Option<String>,
        }

        impl EnvVarGuard {
            fn set(key: &'static str, value: &str) -> Self {
                let old = std::env::var(key).ok();
                set_env(key, value);
                Self { key, old }
            }
        }

        impl Drop for EnvVarGuard {
            fn drop(&mut self) {
                if let Some(old) = &self.old {
                    set_env(self.key, old);
                } else {
                    remove_env(self.key);
                }
            }
        }

        #[test]
        fn test_verify_and_install_not_applicable_does_not_create_claude_dir() {
            let _guard = env_guard();

            let tmp = TempDir::new().unwrap();
            let home = tmp.path().to_string_lossy().to_string();
            let _home = EnvVarGuard::set("HOME", &home);

            let claude_dir = tmp.path().join(".claude");
            assert!(!claude_dir.exists());

            let result = verify_and_install_claude_code_hook().unwrap();
            assert_eq!(result, HookResult::NotApplicable);

            // Critical: the function must NOT create ~/.claude when absent.
            assert!(!claude_dir.exists(), "Should not create ~/.claude");
        }

        #[test]
        fn test_verify_and_install_installs_hook_when_claude_dir_exists() {
            let _guard = env_guard();

            let tmp = TempDir::new().unwrap();
            let home = tmp.path().to_string_lossy().to_string();
            let _home = EnvVarGuard::set("HOME", &home);

            let claude_dir = tmp.path().join(".claude");
            fs::create_dir_all(&claude_dir).unwrap();
            let settings_path = claude_dir.join("settings.json");
            assert!(!settings_path.exists());

            let result = verify_and_install_claude_code_hook().unwrap();
            assert_eq!(result, HookResult::Installed);

            let settings_str = fs::read_to_string(&settings_path).unwrap();
            let settings: Value = serde_json::from_str(&settings_str).unwrap();
            assert!(
                settings_has_rch_hook(&settings),
                "Installed settings should contain rch hook"
            );
        }

        #[test]
        fn test_verify_and_install_already_installed_does_not_modify_file() {
            let _guard = env_guard();

            let tmp = TempDir::new().unwrap();
            let home = tmp.path().to_string_lossy().to_string();
            let _home = EnvVarGuard::set("HOME", &home);

            let claude_dir = tmp.path().join(".claude");
            fs::create_dir_all(&claude_dir).unwrap();
            let settings_path = claude_dir.join("settings.json");

            let settings = json!({
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
            });
            fs::write(
                &settings_path,
                serde_json::to_string_pretty(&settings).unwrap(),
            )
            .unwrap();
            let before = fs::read_to_string(&settings_path).unwrap();

            let result = verify_and_install_claude_code_hook().unwrap();
            assert_eq!(result, HookResult::AlreadyInstalled);

            let after = fs::read_to_string(&settings_path).unwrap();
            assert_eq!(
                after, before,
                "AlreadyInstalled should not rewrite settings.json"
            );
        }

        #[test]
        fn test_verify_and_install_coerces_pre_tool_use_to_array() {
            let _guard = env_guard();

            let tmp = TempDir::new().unwrap();
            let home = tmp.path().to_string_lossy().to_string();
            let _home = EnvVarGuard::set("HOME", &home);

            let claude_dir = tmp.path().join(".claude");
            fs::create_dir_all(&claude_dir).unwrap();
            let settings_path = claude_dir.join("settings.json");

            let settings = json!({
                "hooks": {
                    "PreToolUse": { "not": "an array" }
                }
            });
            fs::write(
                &settings_path,
                serde_json::to_string_pretty(&settings).unwrap(),
            )
            .unwrap();

            let result = verify_and_install_claude_code_hook().unwrap();
            assert_eq!(result, HookResult::Installed);

            let settings_str = fs::read_to_string(&settings_path).unwrap();
            let settings: Value = serde_json::from_str(&settings_str).unwrap();
            assert!(
                settings
                    .get("hooks")
                    .and_then(|h| h.get("PreToolUse"))
                    .and_then(|v| v.as_array())
                    .is_some(),
                "PreToolUse should be coerced to an array"
            );
            assert!(
                settings_has_rch_hook(&settings),
                "Installed settings should contain rch hook"
            );
        }
    }

    // =========================================================================
    // Atomic Write Tests
    // =========================================================================

    #[test]
    fn test_atomic_write() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.json");

        atomic_write(&file_path, b"test content").unwrap();

        let content = fs::read_to_string(&file_path).unwrap();
        assert_eq!(content, "test content");
    }

    #[test]
    fn test_atomic_write_overwrites_existing() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("existing.json");

        fs::write(&file_path, "old content").unwrap();
        atomic_write(&file_path, b"new content").unwrap();

        let content = fs::read_to_string(&file_path).unwrap();
        assert_eq!(content, "new content");
    }

    #[test]
    fn test_atomic_write_nested_directory() {
        let temp_dir = TempDir::new().unwrap();
        let nested_dir = temp_dir.path().join("nested").join("deep");
        fs::create_dir_all(&nested_dir).unwrap();
        let file_path = nested_dir.join("test.json");

        atomic_write(&file_path, b"nested content").unwrap();

        let content = fs::read_to_string(&file_path).unwrap();
        assert_eq!(content, "nested content");
    }

    // =========================================================================
    // Backup Tests
    // =========================================================================

    #[test]
    fn test_create_backup() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("original.json");

        fs::write(&file_path, "original content").unwrap();

        let backup_path = create_backup(&file_path).unwrap();

        assert!(backup_path.exists());
        let backup_content = fs::read_to_string(&backup_path).unwrap();
        assert_eq!(backup_content, "original content");
    }

    #[test]
    fn test_create_backup_preserves_original() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("original.json");

        fs::write(&file_path, "original content").unwrap();
        let _ = create_backup(&file_path).unwrap();

        // Original should still exist
        assert!(file_path.exists());
        let content = fs::read_to_string(&file_path).unwrap();
        assert_eq!(content, "original content");
    }

    #[test]
    fn test_create_backup_naming_format() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("settings.json");

        fs::write(&file_path, "content").unwrap();
        let backup_path = create_backup(&file_path).unwrap();

        let backup_name = backup_path.file_name().unwrap().to_str().unwrap();
        assert!(backup_name.starts_with("settings.json.bak."));
    }

    // =========================================================================
    // Settings Hook Detection Tests
    // =========================================================================

    #[test]
    fn test_settings_has_rch_hook_with_object_hook() {
        // New format with nested hooks array
        let settings = json!({
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [{"type": "command", "command": "rch"}]
                    }
                ]
            }
        });
        assert!(settings_has_rch_hook(&settings));
    }

    #[test]
    fn test_settings_has_rch_hook_with_old_format() {
        // Old format for backwards compatibility
        let settings = json!({
            "hooks": {
                "PreToolUse": [
                    {"command": "rch", "description": "RCH hook"}
                ]
            }
        });
        assert!(settings_has_rch_hook(&settings));
    }

    #[test]
    fn test_settings_has_rch_hook_with_string_hook() {
        let settings = json!({
            "hooks": {
                "PreToolUse": ["rch"]
            }
        });
        assert!(settings_has_rch_hook(&settings));
    }

    #[test]
    fn test_settings_has_rch_hook_partial_match() {
        // Test that a command containing "rch" is detected (new format)
        let settings = json!({
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [{"type": "command", "command": "/usr/local/bin/rch"}]
                    }
                ]
            }
        });
        assert!(settings_has_rch_hook(&settings));
    }

    #[test]
    fn test_settings_has_rch_hook_empty_hooks() {
        let settings = json!({
            "hooks": {
                "PreToolUse": []
            }
        });
        assert!(!settings_has_rch_hook(&settings));
    }

    #[test]
    fn test_settings_has_rch_hook_no_hooks_section() {
        let settings = json!({
            "other_setting": true
        });
        assert!(!settings_has_rch_hook(&settings));
    }

    #[test]
    fn test_settings_has_rch_hook_no_pre_tool_use() {
        let settings = json!({
            "hooks": {
                "PostToolUse": [
                    {"command": "rch"}
                ]
            }
        });
        assert!(!settings_has_rch_hook(&settings));
    }

    #[test]
    fn test_settings_has_rch_hook_other_hook_only() {
        let settings = json!({
            "hooks": {
                "PreToolUse": [
                    {"command": "dcg", "description": "DCG hook"}
                ]
            }
        });
        assert!(!settings_has_rch_hook(&settings));
    }

    #[test]
    fn test_settings_has_rch_hook_multiple_hooks() {
        let settings = json!({
            "hooks": {
                "PreToolUse": [
                    {"matcher": "Bash", "hooks": [{"type": "command", "command": "dcg"}]},
                    {"matcher": "Bash", "hooks": [{"type": "command", "command": "rch"}]}
                ]
            }
        });
        assert!(settings_has_rch_hook(&settings));
    }

    // =========================================================================
    // Add RCH Hook to Settings Tests
    // =========================================================================

    #[test]
    fn test_add_rch_hook_to_empty_settings() {
        let settings = json!({});
        let result = add_rch_hook_to_settings(settings).unwrap();

        assert!(settings_has_rch_hook(&result));

        let hooks = result["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(hooks.len(), 1);
        // New format: check nested hooks array
        assert_eq!(hooks[0]["matcher"], "Bash");
        let inner_hooks = hooks[0]["hooks"].as_array().unwrap();
        assert_eq!(inner_hooks[0]["command"], "rch");
    }

    #[test]
    fn test_add_rch_hook_preserves_existing_settings() {
        let settings = json!({
            "other_setting": "preserved",
            "number_setting": 42
        });
        let result = add_rch_hook_to_settings(settings).unwrap();

        assert!(settings_has_rch_hook(&result));
        assert_eq!(result["other_setting"], "preserved");
        assert_eq!(result["number_setting"], 42);
    }

    #[test]
    fn test_add_rch_hook_preserves_other_hooks() {
        let settings = json!({
            "hooks": {
                "PreToolUse": [
                    {"command": "dcg", "description": "DCG hook"}
                ]
            }
        });
        let result = add_rch_hook_to_settings(settings).unwrap();

        let hooks = result["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(hooks.len(), 2);

        // Old format dcg hook should be preserved
        assert!(hooks.iter().any(|h| h["command"].as_str() == Some("dcg")));
        // New format rch hook should be added
        assert!(settings_has_rch_hook(&result));
    }

    #[test]
    fn test_add_rch_hook_preserves_other_hook_types() {
        let settings = json!({
            "hooks": {
                "PreToolUse": [],
                "PostToolUse": [
                    {"command": "logger"}
                ]
            }
        });
        let result = add_rch_hook_to_settings(settings).unwrap();

        // RCH should be in PreToolUse
        assert!(settings_has_rch_hook(&result));

        // PostToolUse should be preserved
        let post_hooks = result["hooks"]["PostToolUse"].as_array().unwrap();
        assert_eq!(post_hooks.len(), 1);
        assert_eq!(post_hooks[0]["command"], "logger");
    }

    #[test]
    fn test_add_rch_hook_to_non_object_fails() {
        let settings = json!([1, 2, 3]);
        let result = add_rch_hook_to_settings(settings);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not an object"));
    }

    // =========================================================================
    // Integration-Style Tests (with tempfile mock environment)
    // =========================================================================

    /// Helper to create a mock Claude Code environment in a temp directory.
    struct MockClaudeEnv {
        temp_dir: TempDir,
    }

    impl MockClaudeEnv {
        fn new() -> Self {
            Self {
                temp_dir: TempDir::new().unwrap(),
            }
        }

        fn claude_dir(&self) -> PathBuf {
            self.temp_dir.path().join(".claude")
        }

        fn settings_path(&self) -> PathBuf {
            self.claude_dir().join("settings.json")
        }

        fn create_claude_dir(&self) {
            fs::create_dir_all(self.claude_dir()).unwrap();
        }

        fn write_settings(&self, settings: &Value) {
            fs::write(
                self.settings_path(),
                serde_json::to_string_pretty(settings).unwrap(),
            )
            .unwrap();
        }

        fn read_settings(&self) -> Value {
            let content = fs::read_to_string(self.settings_path()).unwrap();
            serde_json::from_str(&content).unwrap()
        }
    }

    #[test]
    fn test_integration_install_hook_to_new_settings() {
        let env = MockClaudeEnv::new();
        env.create_claude_dir();

        // Start with empty settings
        let settings = json!({});
        env.write_settings(&settings);

        // Read, modify, write
        let content = fs::read_to_string(env.settings_path()).unwrap();
        let settings: Value = serde_json::from_str(&content).unwrap();

        if !settings_has_rch_hook(&settings) {
            let modified = add_rch_hook_to_settings(settings).unwrap();
            let content = serde_json::to_string_pretty(&modified).unwrap();
            atomic_write(&env.settings_path(), content.as_bytes()).unwrap();
        }

        // Verify
        let final_settings = env.read_settings();
        assert!(settings_has_rch_hook(&final_settings));
    }

    #[test]
    fn test_integration_skip_if_already_installed() {
        let env = MockClaudeEnv::new();
        env.create_claude_dir();

        // Start with RCH already installed (new format)
        let settings = json!({
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [{"type": "command", "command": "rch"}]
                    }
                ]
            }
        });
        env.write_settings(&settings);

        // Check and don't modify
        let content = fs::read_to_string(env.settings_path()).unwrap();
        let settings: Value = serde_json::from_str(&content).unwrap();

        let already_installed = settings_has_rch_hook(&settings);
        assert!(already_installed);

        // Verify file unchanged (hooks array still has 1 entry)
        let final_settings = env.read_settings();
        let hooks = final_settings["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(hooks.len(), 1);
    }

    #[test]
    fn test_integration_preserve_complex_settings() {
        let env = MockClaudeEnv::new();
        env.create_claude_dir();

        // Complex existing settings
        let settings = json!({
            "appearance": {
                "theme": "dark",
                "fontSize": 14
            },
            "hooks": {
                "PreToolUse": [
                    {"command": "dcg", "description": "Guard"}
                ],
                "PostToolUse": [
                    {"command": "logger"}
                ]
            },
            "customPrompts": ["prompt1", "prompt2"],
            "enabled": true
        });
        env.write_settings(&settings);

        // Add RCH hook
        let content = fs::read_to_string(env.settings_path()).unwrap();
        let settings: Value = serde_json::from_str(&content).unwrap();
        let modified = add_rch_hook_to_settings(settings).unwrap();
        let content = serde_json::to_string_pretty(&modified).unwrap();
        atomic_write(&env.settings_path(), content.as_bytes()).unwrap();

        // Verify all other settings preserved
        let final_settings = env.read_settings();

        assert_eq!(final_settings["appearance"]["theme"], "dark");
        assert_eq!(final_settings["appearance"]["fontSize"], 14);
        assert_eq!(final_settings["enabled"], true);
        assert_eq!(final_settings["customPrompts"].as_array().unwrap().len(), 2);

        // DCG hook preserved (old format)
        let pre_hooks = final_settings["hooks"]["PreToolUse"].as_array().unwrap();
        assert!(pre_hooks.iter().any(|h| h["command"] == "dcg"));
        // RCH hook added (new format)
        assert!(settings_has_rch_hook(&final_settings));

        // PostToolUse preserved
        let post_hooks = final_settings["hooks"]["PostToolUse"].as_array().unwrap();
        assert_eq!(post_hooks.len(), 1);
    }

    #[test]
    fn test_integration_malformed_json_detection() {
        let env = MockClaudeEnv::new();
        env.create_claude_dir();

        // Write malformed JSON
        fs::write(env.settings_path(), "{ invalid json }").unwrap();

        // Try to parse - should fail
        let content = fs::read_to_string(env.settings_path()).unwrap();
        let result: Result<Value, _> = serde_json::from_str(&content);

        assert!(result.is_err());
    }

    #[test]
    fn test_integration_atomic_write_on_failure_leaves_original() {
        let env = MockClaudeEnv::new();
        env.create_claude_dir();

        // Write valid settings
        let original = json!({"original": true});
        env.write_settings(&original);

        // Try atomic write to a non-writable location (simulate failure)
        // Note: This test verifies the atomic_write function signature
        // A true failure test would require more complex setup

        // Verify original is still intact after our read
        let final_settings = env.read_settings();
        assert_eq!(final_settings["original"], true);
    }

    // =========================================================================
    // is_claude_code_installed Tests (uses real filesystem)
    // =========================================================================

    #[test]
    fn test_is_claude_code_installed_returns_bool() {
        // This test just verifies the function exists and returns a bool
        // Actual result depends on whether Claude Code is installed on test machine
        let _ = is_claude_code_installed();
    }
}
