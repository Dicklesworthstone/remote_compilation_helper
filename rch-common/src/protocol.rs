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
    /// Allow with a modified/replaced command (for transparent interception).
    /// Used when RCH has already executed the command remotely and wants to
    /// replace the original command with a no-op for transparency.
    AllowWithModifiedCommand(AllowWithModifiedCommandOutput),
    /// Deny the command with a reason.
    Deny(DenyOutput),
}

/// Empty output to allow command execution.
#[derive(Debug, Clone, Default, Serialize)]
pub struct AllowOutput {}

/// Output to allow with a modified command (for transparent interception).
/// This tells Claude Code "allow this tool, but replace the command with this one".
/// Used when RCH has already executed remotely and wants to substitute a no-op.
#[derive(Debug, Clone, Serialize)]
pub struct AllowWithModifiedCommandOutput {
    #[serde(rename = "hookSpecificOutput")]
    pub hook_specific_output: AllowWithModifiedHookSpecificOutput,
}

/// Hook-specific output for allow-with-modification responses.
#[derive(Debug, Clone, Serialize)]
pub struct AllowWithModifiedHookSpecificOutput {
    #[serde(rename = "hookEventName")]
    pub hook_event_name: String,
    #[serde(rename = "permissionDecision")]
    pub permission_decision: String,
    #[serde(rename = "updatedInput")]
    pub updated_input: UpdatedInput,
}

/// The modified input to substitute.
#[derive(Debug, Clone, Serialize)]
pub struct UpdatedInput {
    /// The replacement command (typically a no-op like "true" or "exit 0").
    pub command: String,
}

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

    /// Create an allow output with a modified/replaced command.
    ///
    /// This is used for transparent interception: RCH has already executed the
    /// command remotely, so we replace it with a no-op to prevent double execution.
    /// The agent sees the remote output but thinks the command ran locally.
    ///
    /// # Arguments
    /// * `replacement_command` - The command to substitute (typically "true" for a no-op)
    pub fn allow_with_modified_command(replacement_command: impl Into<String>) -> Self {
        Self::AllowWithModifiedCommand(AllowWithModifiedCommandOutput {
            hook_specific_output: AllowWithModifiedHookSpecificOutput {
                hook_event_name: "PreToolUse".to_string(),
                permission_decision: "allow".to_string(),
                updated_input: UpdatedInput {
                    command: replacement_command.into(),
                },
            },
        })
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
        matches!(self, Self::Allow(_) | Self::AllowWithModifiedCommand(_))
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

    #[test]
    fn test_parse_hook_input_minimal() {
        // Parse without optional fields
        let json = r#"{
            "tool_name": "Bash",
            "tool_input": {
                "command": "ls -la"
            }
        }"#;

        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.tool_name, "Bash");
        assert_eq!(input.tool_input.command, "ls -la");
        assert!(input.tool_input.description.is_none());
        assert!(input.session_id.is_none());
    }

    #[test]
    fn test_parse_hook_input_with_empty_description() {
        let json = r#"{
            "tool_name": "Read",
            "tool_input": {
                "command": "cat file.txt",
                "description": ""
            }
        }"#;

        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.tool_name, "Read");
        assert_eq!(input.tool_input.description, Some("".to_string()));
    }

    #[test]
    fn test_hook_output_is_allow_true() {
        let output = HookOutput::allow();
        assert!(output.is_allow());
    }

    #[test]
    fn test_hook_output_is_allow_false_for_deny() {
        let output = HookOutput::deny("blocked");
        assert!(!output.is_allow());
    }

    #[test]
    fn test_deny_output_preserves_reason() {
        let reason = "Command not allowed: security violation";
        let output = HookOutput::deny(reason);

        if let HookOutput::Deny(deny) = output {
            assert_eq!(deny.hook_specific_output.permission_decision_reason, reason);
            assert_eq!(deny.hook_specific_output.permission_decision, "deny");
            assert_eq!(deny.hook_specific_output.hook_event_name, "PreToolUse");
        } else {
            panic!("Expected Deny variant");
        }
    }

    #[test]
    fn test_deny_output_with_empty_reason() {
        let output = HookOutput::deny("");
        if let HookOutput::Deny(deny) = output {
            assert_eq!(deny.hook_specific_output.permission_decision_reason, "");
        } else {
            panic!("Expected Deny variant");
        }
    }

    #[test]
    fn test_allow_output_default() {
        let output = AllowOutput::default();
        let json = serde_json::to_string(&output).unwrap();
        assert_eq!(json, "{}");
    }

    #[test]
    fn test_deny_output_json_structure() {
        let output = HookOutput::deny("test reason");
        let json = serde_json::to_string(&output).unwrap();

        // Verify the exact JSON structure expected by Claude Code
        assert!(json.contains("hookSpecificOutput"));
        assert!(json.contains("hookEventName"));
        assert!(json.contains("PreToolUse"));
        assert!(json.contains("permissionDecision"));
        assert!(json.contains("\"deny\""));
        assert!(json.contains("permissionDecisionReason"));
        assert!(json.contains("test reason"));
    }

    #[test]
    fn test_hook_input_clone() {
        let original = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: "cargo test".to_string(),
                description: Some("Run tests".to_string()),
            },
            session_id: Some("session-123".to_string()),
        };

        let cloned = original.clone();
        assert_eq!(original.tool_name, cloned.tool_name);
        assert_eq!(original.tool_input.command, cloned.tool_input.command);
        assert_eq!(original.session_id, cloned.session_id);
    }

    #[test]
    fn test_tool_input_clone() {
        let original = ToolInput {
            command: "make build".to_string(),
            description: None,
        };

        let cloned = original.clone();
        assert_eq!(original.command, cloned.command);
        assert_eq!(original.description, cloned.description);
    }

    #[test]
    fn test_hook_output_clone_allow() {
        let original = HookOutput::allow();
        let cloned = original.clone();
        assert!(cloned.is_allow());
    }

    #[test]
    fn test_hook_output_clone_deny() {
        let original = HookOutput::deny("cloned reason");
        let cloned = original.clone();
        assert!(!cloned.is_allow());
    }

    #[test]
    fn test_deny_output_from_string() {
        // Test the Into<String> conversion
        let output = HookOutput::deny(String::from("owned reason"));
        if let HookOutput::Deny(deny) = output {
            assert_eq!(
                deny.hook_specific_output.permission_decision_reason,
                "owned reason"
            );
        } else {
            panic!("Expected Deny variant");
        }
    }

    #[test]
    fn test_parse_hook_input_different_tools() {
        let tools = ["Bash", "Read", "Write", "Edit", "Glob", "Grep"];

        for tool in tools {
            let json = format!(
                r#"{{"tool_name": "{}", "tool_input": {{"command": "test"}}}}"#,
                tool
            );
            let input: HookInput = serde_json::from_str(&json).unwrap();
            assert_eq!(input.tool_name, tool);
        }
    }

    #[test]
    fn test_parse_hook_input_unicode_command() {
        let json = r#"{
            "tool_name": "Bash",
            "tool_input": {
                "command": "echo '日本語 测试 émojis 🦀'"
            }
        }"#;

        let input: HookInput = serde_json::from_str(json).unwrap();
        assert!(input.tool_input.command.contains("日本語"));
        assert!(input.tool_input.command.contains("🦀"));
    }

    #[test]
    fn test_parse_hook_input_special_characters() {
        let json = r#"{
            "tool_name": "Bash",
            "tool_input": {
                "command": "echo \"hello\\nworld\" | grep 'pattern'"
            }
        }"#;

        let input: HookInput = serde_json::from_str(json).unwrap();
        assert!(input.tool_input.command.contains("echo"));
        assert!(input.tool_input.command.contains("grep"));
    }

    #[test]
    fn test_hook_specific_output_debug() {
        let output = HookSpecificOutput {
            hook_event_name: "PreToolUse".to_string(),
            permission_decision: "deny".to_string(),
            permission_decision_reason: "test".to_string(),
        };

        // Verify Debug trait works
        let debug_str = format!("{:?}", output);
        assert!(debug_str.contains("HookSpecificOutput"));
        assert!(debug_str.contains("PreToolUse"));
    }

    #[test]
    fn test_deny_output_debug() {
        let output = DenyOutput {
            hook_specific_output: HookSpecificOutput {
                hook_event_name: "PreToolUse".to_string(),
                permission_decision: "deny".to_string(),
                permission_decision_reason: "test".to_string(),
            },
        };

        let debug_str = format!("{:?}", output);
        assert!(debug_str.contains("DenyOutput"));
    }

    #[test]
    fn test_allow_output_debug() {
        let output = AllowOutput {};
        let debug_str = format!("{:?}", output);
        assert!(debug_str.contains("AllowOutput"));
    }

    // Tests for AllowWithModifiedCommand (transparent interception)

    #[test]
    fn test_allow_with_modified_command_serializes() {
        let output = HookOutput::allow_with_modified_command("true");
        let json = serde_json::to_string(&output).unwrap();

        // Verify the JSON structure expected by Claude Code
        assert!(json.contains("hookSpecificOutput"));
        assert!(json.contains("hookEventName"));
        assert!(json.contains("PreToolUse"));
        assert!(json.contains("permissionDecision"));
        assert!(json.contains("\"allow\""));
        assert!(json.contains("updatedInput"));
        assert!(json.contains("\"command\""));
        assert!(json.contains("\"true\""));
    }

    #[test]
    fn test_allow_with_modified_command_is_allow() {
        let output = HookOutput::allow_with_modified_command("true");
        assert!(output.is_allow());
    }

    #[test]
    fn test_allow_with_modified_command_preserves_replacement() {
        let output = HookOutput::allow_with_modified_command("exit 101");
        if let HookOutput::AllowWithModifiedCommand(allow_mod) = output {
            assert_eq!(
                allow_mod.hook_specific_output.updated_input.command,
                "exit 101"
            );
            assert_eq!(allow_mod.hook_specific_output.permission_decision, "allow");
        } else {
            panic!("Expected AllowWithModifiedCommand variant");
        }
    }

    #[test]
    fn test_allow_with_modified_command_from_string() {
        let output = HookOutput::allow_with_modified_command(String::from("echo done"));
        if let HookOutput::AllowWithModifiedCommand(allow_mod) = output {
            assert_eq!(
                allow_mod.hook_specific_output.updated_input.command,
                "echo done"
            );
        } else {
            panic!("Expected AllowWithModifiedCommand variant");
        }
    }

    #[test]
    fn test_allow_with_modified_command_clone() {
        let original = HookOutput::allow_with_modified_command("true");
        let cloned = original.clone();
        assert!(cloned.is_allow());
        if let HookOutput::AllowWithModifiedCommand(allow_mod) = cloned {
            assert_eq!(allow_mod.hook_specific_output.updated_input.command, "true");
        } else {
            panic!("Expected AllowWithModifiedCommand variant");
        }
    }

    #[test]
    fn test_allow_with_modified_command_json_structure() {
        // Verify exact JSON format expected by Claude Code
        let output = HookOutput::allow_with_modified_command("true");
        let json = serde_json::to_string(&output).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert!(parsed.get("hookSpecificOutput").is_some());
        let hook_output = parsed.get("hookSpecificOutput").unwrap();
        assert_eq!(hook_output.get("hookEventName").unwrap(), "PreToolUse");
        assert_eq!(hook_output.get("permissionDecision").unwrap(), "allow");
        assert!(hook_output.get("updatedInput").is_some());
        let updated_input = hook_output.get("updatedInput").unwrap();
        assert_eq!(updated_input.get("command").unwrap(), "true");
    }
}
