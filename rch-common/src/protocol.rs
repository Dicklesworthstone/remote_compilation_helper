//! Claude Code hook protocol definitions.
//!
//! Defines the JSON structures for PreToolUse hook input/output.

use serde::{Deserialize, Serialize};

/// Input received from Claude Code PreToolUse hook.
#[derive(Debug, Clone, Deserialize)]
pub struct HookInput {
    /// The tool being invoked (e.g., "Bash", "Read", "Write").
    pub tool_name: String,
    /// Tool-specific input.
    pub tool_input: ToolInput,
    /// Optional session ID.
    #[serde(default)]
    pub session_id: Option<String>,
}

/// Tool-specific input for Bash commands.
#[derive(Debug, Clone, Deserialize)]
pub struct ToolInput {
    /// The command to execute.
    pub command: String,
    /// Optional description of what the command does.
    #[serde(default)]
    pub description: Option<String>,
}

/// Output sent back to Claude Code from PreToolUse hook.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum HookOutput {
    /// Allow the command to proceed (empty object or no output).
    Allow(AllowOutput),
    /// Deny the command with a reason.
    Deny(DenyOutput),
}

/// Empty output to allow command execution.
#[derive(Debug, Clone, Default, Serialize)]
pub struct AllowOutput {}

/// Output to deny/block command execution.
#[derive(Debug, Clone, Serialize)]
pub struct DenyOutput {
    #[serde(rename = "hookSpecificOutput")]
    pub hook_specific_output: HookSpecificOutput,
}

#[derive(Debug, Clone, Serialize)]
pub struct HookSpecificOutput {
    #[serde(rename = "hookEventName")]
    pub hook_event_name: String,
    #[serde(rename = "permissionDecision")]
    pub permission_decision: String,
    #[serde(rename = "permissionDecisionReason")]
    pub permission_decision_reason: String,
}

impl HookOutput {
    /// Create an allow output (command proceeds normally).
    pub fn allow() -> Self {
        Self::Allow(AllowOutput {})
    }

    /// Create a deny output with a reason.
    pub fn deny(reason: impl Into<String>) -> Self {
        Self::Deny(DenyOutput {
            hook_specific_output: HookSpecificOutput {
                hook_event_name: "PreToolUse".to_string(),
                permission_decision: "deny".to_string(),
                permission_decision_reason: reason.into(),
            },
        })
    }

    /// Check if this output allows the command.
    pub fn is_allow(&self) -> bool {
        matches!(self, Self::Allow(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hook_input() {
        let json = r#"{
            "tool_name": "Bash",
            "tool_input": {
                "command": "cargo build --release",
                "description": "Build the project"
            },
            "session_id": "abc123"
        }"#;

        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.tool_name, "Bash");
        assert_eq!(input.tool_input.command, "cargo build --release");
        assert_eq!(input.session_id, Some("abc123".to_string()));
    }

    #[test]
    fn test_allow_output() {
        let output = HookOutput::allow();
        let json = serde_json::to_string(&output).unwrap();
        assert_eq!(json, "{}");
    }

    #[test]
    fn test_deny_output() {
        let output = HookOutput::deny("Remote execution failed");
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("permissionDecision"));
        assert!(json.contains("deny"));
    }
}
