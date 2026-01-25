//! Agent detection functions.
//!
//! Provides functions to detect installed AI coding agents on the system.

use super::types::{AgentKind, DetectedAgent, DetectionMethod};
use anyhow::Result;
use std::path::Path;
use std::process::Command;

/// Detect all installed AI coding agents.
///
/// Returns a list of detected agents with their version and configuration info.
pub fn detect_agents() -> Result<Vec<DetectedAgent>> {
    let mut agents = Vec::new();

    for kind in AgentKind::ALL {
        if let Some(agent) = detect_single_agent(*kind)? {
            agents.push(agent);
        }
    }

    Ok(agents)
}

/// Detect a specific agent by kind.
///
/// Returns `Some(DetectedAgent)` if the agent is installed, `None` otherwise.
pub fn detect_single_agent(kind: AgentKind) -> Result<Option<DetectedAgent>> {
    match kind {
        AgentKind::ClaudeCode => detect_claude_code(),
        AgentKind::GeminiCli => detect_gemini_cli(),
        AgentKind::CodexCli => detect_codex_cli(),
        AgentKind::Cursor => detect_cursor(),
        AgentKind::ContinueDev => detect_continue_dev(),
        AgentKind::Windsurf => detect_windsurf(),
        AgentKind::Aider => detect_aider(),
        AgentKind::Cline => detect_cline(),
    }
}

/// Detect Claude Code installation.
fn detect_claude_code() -> Result<Option<DetectedAgent>> {
    // Try to find claude in PATH
    if let Some(version) = get_command_version("claude", &["--version"]) {
        let agent = DetectedAgent::new(AgentKind::ClaudeCode)
            .with_version(version)
            .with_detection_method(DetectionMethod::PathLookup);
        return Ok(Some(agent));
    }

    // Check for config directory
    if let Some(config_path) = AgentKind::ClaudeCode.default_config_path()
        && config_path.parent().map(|p| p.exists()).unwrap_or(false)
    {
        let agent = DetectedAgent::new(AgentKind::ClaudeCode)
            .with_detection_method(DetectionMethod::ConfigFile);
        return Ok(Some(agent));
    }

    Ok(None)
}

/// Detect Gemini CLI installation.
fn detect_gemini_cli() -> Result<Option<DetectedAgent>> {
    // Try to find gemini in PATH
    if let Some(version) = get_command_version("gemini", &["--version"]) {
        let agent = DetectedAgent::new(AgentKind::GeminiCli)
            .with_version(version)
            .with_detection_method(DetectionMethod::PathLookup);
        return Ok(Some(agent));
    }

    // Check for config directory
    if let Some(config_path) = AgentKind::GeminiCli.default_config_path()
        && config_path.parent().map(|p| p.exists()).unwrap_or(false)
    {
        let agent = DetectedAgent::new(AgentKind::GeminiCli)
            .with_detection_method(DetectionMethod::ConfigFile);
        return Ok(Some(agent));
    }

    Ok(None)
}

/// Detect Codex CLI installation.
fn detect_codex_cli() -> Result<Option<DetectedAgent>> {
    // Try to find codex in PATH
    if let Some(version) = get_command_version("codex", &["--version"]) {
        let agent = DetectedAgent::new(AgentKind::CodexCli)
            .with_version(version)
            .with_detection_method(DetectionMethod::PathLookup);
        return Ok(Some(agent));
    }

    // Check for config directory
    if let Some(config_path) = AgentKind::CodexCli.default_config_path()
        && config_path.parent().map(|p| p.exists()).unwrap_or(false)
    {
        let agent = DetectedAgent::new(AgentKind::CodexCli)
            .with_detection_method(DetectionMethod::ConfigFile);
        return Ok(Some(agent));
    }

    Ok(None)
}

/// Detect Cursor installation.
fn detect_cursor() -> Result<Option<DetectedAgent>> {
    // Check for Cursor config directory
    if let Some(config_path) = AgentKind::Cursor.default_config_path() && config_path.exists() {
        let agent = DetectedAgent::new(AgentKind::Cursor)
            .with_detection_method(DetectionMethod::ConfigFile);
        return Ok(Some(agent));
    }

    // Check common installation paths
    let cursor_paths = [
        "/usr/share/applications/cursor.desktop",
        "/opt/Cursor/cursor",
    ];

    for path in cursor_paths {
        if Path::new(path).exists() {
            let agent = DetectedAgent::new(AgentKind::Cursor)
                .with_detection_method(DetectionMethod::ConfigFile);
            return Ok(Some(agent));
        }
    }

    Ok(None)
}

/// Detect Continue.dev installation.
fn detect_continue_dev() -> Result<Option<DetectedAgent>> {
    // Check for Continue config directory
    if let Some(config_path) = AgentKind::ContinueDev.default_config_path() && config_path.exists()
    {
        let agent = DetectedAgent::new(AgentKind::ContinueDev)
            .with_detection_method(DetectionMethod::ConfigFile);
        return Ok(Some(agent));
    }

    Ok(None)
}

/// Detect Windsurf installation.
fn detect_windsurf() -> Result<Option<DetectedAgent>> {
    // Check for Windsurf config directory
    if let Some(config_path) = AgentKind::Windsurf.default_config_path() && config_path.exists() {
        let agent = DetectedAgent::new(AgentKind::Windsurf)
            .with_detection_method(DetectionMethod::ConfigFile);
        return Ok(Some(agent));
    }

    Ok(None)
}

/// Detect Aider installation.
fn detect_aider() -> Result<Option<DetectedAgent>> {
    // Try to find aider in PATH
    if let Some(version) = get_command_version("aider", &["--version"]) {
        let agent = DetectedAgent::new(AgentKind::Aider)
            .with_version(version)
            .with_detection_method(DetectionMethod::PathLookup);
        return Ok(Some(agent));
    }

    // Check for config file
    if let Some(config_path) = AgentKind::Aider.default_config_path() && config_path.exists() {
        let agent = DetectedAgent::new(AgentKind::Aider)
            .with_detection_method(DetectionMethod::ConfigFile);
        return Ok(Some(agent));
    }

    Ok(None)
}

/// Detect Cline installation.
fn detect_cline() -> Result<Option<DetectedAgent>> {
    // Cline is a VS Code extension, check for its data directory
    if let Some(home) = dirs::home_dir() {
        let cline_path = home.join(".vscode").join("extensions");
        if cline_path.exists() {
            // Look for cline extension
            if let Ok(entries) = std::fs::read_dir(&cline_path) {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let name_str = name.to_string_lossy();
                    if name_str.starts_with("saoudrizwan.claude-dev")
                        || name_str.starts_with("cline.")
                    {
                        let agent = DetectedAgent::new(AgentKind::Cline)
                            .with_detection_method(DetectionMethod::ConfigFile);
                        return Ok(Some(agent));
                    }
                }
            }
        }
    }

    Ok(None)
}

/// Get version from a command.
fn get_command_version(cmd: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(cmd).args(args).output().ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Try stdout first, then stderr (some tools output version to stderr)
    let version_str = if !stdout.trim().is_empty() {
        stdout
    } else {
        stderr
    };

    // Extract version number from output
    extract_version(&version_str)
}

/// Extract version number from a version string.
fn extract_version(s: &str) -> Option<String> {
    // Common patterns:
    // "claude 1.0.0"
    // "v1.0.0"
    // "1.0.0"
    // "tool version 1.0.0"

    let s = s.trim();

    // Try to find a semver-like pattern
    for word in s.split_whitespace() {
        let word = word.trim_start_matches('v');
        if word
            .chars()
            .next()
            .map(|c| c.is_ascii_digit())
            .unwrap_or(false)
        {
            // Check if it looks like a version number
            if word.contains('.') || word.chars().all(|c| c.is_ascii_digit()) {
                return Some(word.to_string());
            }
        }
    }

    // Fallback: return the first line
    s.lines().next().map(|s| s.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_version_semver() {
        assert_eq!(extract_version("1.0.0"), Some("1.0.0".to_string()));
        assert_eq!(extract_version("v1.0.0"), Some("1.0.0".to_string()));
    }

    #[test]
    fn test_extract_version_with_prefix() {
        assert_eq!(extract_version("claude 1.2.3"), Some("1.2.3".to_string()));
        assert_eq!(
            extract_version("tool version 2.0.0"),
            Some("2.0.0".to_string())
        );
    }

    #[test]
    fn test_extract_version_fallback() {
        assert_eq!(
            extract_version("unknown format"),
            Some("unknown format".to_string())
        );
    }

    #[test]
    fn test_detect_agents_returns_vec() {
        // This test just ensures the function runs without panicking
        let result = detect_agents();
        assert!(result.is_ok());
    }
}
