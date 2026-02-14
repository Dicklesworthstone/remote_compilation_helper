//! Platform-independent SSH utilities.
//!
//! These utilities work on all platforms and don't depend on openssh.

use serde::{Deserialize, Serialize};
use tracing::info;

// ============================================================================
// Retry Classification
// ============================================================================

/// True if an SSH/transport error looks retryable (transient network / transport).
///
/// This is intentionally conservative: false negatives are acceptable (fail-open
/// to local execution), false positives can cause needless retries.
pub fn is_retryable_transport_error(err: &anyhow::Error) -> bool {
    let mut parts = Vec::new();
    for cause in err.chain() {
        parts.push(cause.to_string());
    }
    is_retryable_transport_error_text(&parts.join(": "))
}

/// Message-only variant of [`is_retryable_transport_error`] (useful for tests).
pub fn is_retryable_transport_error_text(message: &str) -> bool {
    let message = message.to_lowercase();

    // Fail-fast: non-retryable authentication / host trust issues.
    if message.contains("permission denied")
        || message.contains("host key verification failed")
        || message.contains("could not resolve hostname")
        || message.contains("no such file or directory")
        || message.contains("identity file")
        || message.contains("keyfile")
        || message.contains("invalid format")
        || message.contains("unknown option")
    {
        return false;
    }

    // Common transient transport failures.
    message.contains("connection timed out")
        || message.contains("timed out")
        || message.contains("connection reset")
        || message.contains("broken pipe")
        || message.contains("connection refused")
        || message.contains("network is unreachable")
        || message.contains("no route to host")
        || message.contains("connection closed")
        || message.contains("connection lost")
        || message.contains("ssh_exchange_identification")
        || message.contains("kex_exchange_identification")
        || message.contains("temporary failure in name resolution")
}

/// Result of a remote command execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResult {
    /// Exit code of the command.
    pub exit_code: i32,
    /// Standard output.
    pub stdout: String,
    /// Standard error.
    pub stderr: String,
    /// Execution duration in milliseconds.
    pub duration_ms: u64,
}

impl CommandResult {
    /// Check if the command succeeded (exit code 0).
    pub fn success(&self) -> bool {
        self.exit_code == 0
    }
}

/// Environment variable prefix for remote command execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvPrefix {
    /// Shell-safe prefix (includes trailing space when non-empty).
    pub prefix: String,
    /// Keys applied to the command.
    pub applied: Vec<String>,
    /// Keys rejected due to invalid name or unsafe value.
    pub rejected: Vec<String>,
}

/// Build a shell-safe environment variable prefix from an allowlist.
///
/// - Missing variables are ignored silently.
/// - Unsafe values (newline, carriage return, NUL) are rejected.
/// - Invalid keys are rejected.
pub fn build_env_prefix<F>(allowlist: &[String], mut get_env: F) -> EnvPrefix
where
    F: FnMut(&str) -> Option<String>,
{
    let mut parts = Vec::new();
    let mut applied = Vec::new();
    let mut rejected = Vec::new();

    for raw_key in allowlist {
        let key = raw_key.trim();
        if key.is_empty() {
            continue;
        }
        if !is_valid_env_key(key) {
            info!(
                "Rejecting env var '{}': invalid key name (must start with letter/underscore, contain only alphanumeric/underscore)",
                key
            );
            rejected.push(key.to_string());
            continue;
        }
        let Some(value) = get_env(key) else {
            // Variable not set - this is normal, don't log
            continue;
        };
        let Some(escaped) = shell_escape_value(&value) else {
            info!(
                "Rejecting env var '{}': value contains unsafe characters (newline, carriage return, or NUL)",
                key
            );
            rejected.push(key.to_string());
            continue;
        };
        parts.push(format!("{}={}", key, escaped));
        applied.push(key.to_string());
    }

    let prefix = if parts.is_empty() {
        String::new()
    } else {
        format!("{} ", parts.join(" "))
    };

    EnvPrefix {
        prefix,
        applied,
        rejected,
    }
}

/// Check if a string is a valid environment variable key.
pub fn is_valid_env_key(key: &str) -> bool {
    let mut chars = key.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first == '_' || first.is_ascii_alphabetic()) {
        return false;
    }
    chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

/// Escape a string for use in a shell command.
///
/// Wraps the string in single quotes and escapes internal single quotes.
/// Returns None if the string contains unsafe control characters (newline, carriage return, NUL).
pub fn shell_escape_value(value: &str) -> Option<String> {
    // Reject values with control characters that could break shell parsing
    // Note: These are logged at the call site with the variable name for debugging
    if value.contains('\n') || value.contains('\r') || value.contains('\0') {
        return None;
    }

    if value.is_empty() {
        return Some("''".to_string());
    }

    let needs_quotes = value
        .chars()
        .any(|c| !c.is_ascii_alphanumeric() && c != '_');
    if !needs_quotes {
        return Some(value.to_string());
    }

    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('\'');
    for ch in value.chars() {
        if ch == '\'' {
            escaped.push_str("'\\''");
        } else {
            escaped.push(ch);
        }
    }
    escaped.push('\'');
    Some(escaped)
}

/// Escape a path for use in a shell command, allowing `~` to expand to `$HOME`.
///
/// For paths that start with `~/` or are exactly `~`, this returns a double-quoted
/// string that expands `$HOME` while escaping special characters inside the suffix.
/// For all other paths, this defers to `shell_escape_value`.
pub fn shell_escape_path_with_home(path: &str) -> Option<String> {
    if path.contains('\n') || path.contains('\r') || path.contains('\0') {
        return None;
    }

    if path == "~" {
        return Some("\"$HOME\"".to_string());
    }

    if let Some(suffix) = path.strip_prefix("~/") {
        let escaped_suffix = escape_for_double_quotes(suffix);
        return Some(format!("\"$HOME/{}\"", escaped_suffix));
    }

    shell_escape_value(path)
}

fn escape_for_double_quotes(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '$' => escaped.push_str("\\$"),
            '`' => escaped.push_str("\\`"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_guard;

    #[test]
    fn test_retryable_transport_error_text() {
        let _guard = test_guard!();
        assert!(is_retryable_transport_error_text(
            "ssh: connect to host 1.2.3.4 port 22: Connection timed out"
        ));
        assert!(is_retryable_transport_error_text(
            "kex_exchange_identification: Connection reset by peer"
        ));
        assert!(is_retryable_transport_error_text("Broken pipe"));
        assert!(is_retryable_transport_error_text("Network is unreachable"));
    }

    #[test]
    fn test_non_retryable_transport_error_text() {
        let _guard = test_guard!();
        assert!(!is_retryable_transport_error_text(
            "Permission denied (publickey)."
        ));
        assert!(!is_retryable_transport_error_text(
            "Host key verification failed."
        ));
        assert!(!is_retryable_transport_error_text(
            "Could not resolve hostname worker.example.com: Name or service not known"
        ));
        assert!(!is_retryable_transport_error_text(
            "Identity file /nope/id_rsa not accessible: No such file or directory"
        ));
    }

    #[test]
    fn test_command_result_success() {
        let _guard = test_guard!();
        let result = CommandResult {
            exit_code: 0,
            stdout: "output".to_string(),
            stderr: String::new(),
            duration_ms: 100,
        };
        assert!(result.success());

        let failed = CommandResult {
            exit_code: 1,
            stdout: String::new(),
            stderr: "error".to_string(),
            duration_ms: 50,
        };
        assert!(!failed.success());
    }

    #[test]
    fn test_shell_escape_value() {
        let _guard = test_guard!();
        // Simple value
        assert_eq!(shell_escape_value("simple"), Some("simple".to_string()));

        // Empty string
        assert_eq!(shell_escape_value(""), Some("''".to_string()));

        // With spaces
        assert_eq!(
            shell_escape_value("with spaces"),
            Some("'with spaces'".to_string())
        );

        // With single quote
        assert_eq!(shell_escape_value("it's"), Some("'it'\\''s'".to_string()));

        // Unsafe values
        assert!(shell_escape_value("line1\nline2").is_none());
        assert!(shell_escape_value("line1\rline2").is_none());
        assert!(shell_escape_value("line1\0line2").is_none());
    }

    #[test]
    fn test_shell_escape_path_with_home() {
        let _guard = test_guard!();
        assert_eq!(
            shell_escape_path_with_home("~/.local/bin"),
            Some("\"$HOME/.local/bin\"".to_string())
        );
        assert_eq!(
            shell_escape_path_with_home("~"),
            Some("\"$HOME\"".to_string())
        );
        assert_eq!(
            shell_escape_path_with_home("/usr/local/bin"),
            Some("'/usr/local/bin'".to_string())
        );
    }

    #[test]
    fn test_is_valid_env_key() {
        let _guard = test_guard!();
        assert!(is_valid_env_key("PATH"));
        assert!(is_valid_env_key("_PRIVATE"));
        assert!(is_valid_env_key("MY_VAR_123"));
        assert!(!is_valid_env_key("123VAR"));
        assert!(!is_valid_env_key("MY-VAR"));
        assert!(!is_valid_env_key(""));
    }

    #[test]
    fn test_build_env_prefix() {
        let _guard = test_guard!();
        use std::collections::HashMap;

        let mut env = HashMap::new();
        env.insert("RUSTFLAGS".to_string(), "-C target-cpu=native".to_string());
        env.insert("QUOTED".to_string(), "a'b".to_string());
        env.insert("BADVAL".to_string(), "line1\nline2".to_string());

        let allowlist = vec![
            "RUSTFLAGS".to_string(),
            "QUOTED".to_string(),
            "MISSING".to_string(),
            "BADVAL".to_string(),
            "BAD=KEY".to_string(),
        ];

        let prefix = build_env_prefix(&allowlist, |key| env.get(key).cloned());

        assert!(prefix.prefix.contains("RUSTFLAGS='-C target-cpu=native'"));
        assert!(prefix.prefix.contains("QUOTED='a'\\''b'"));
        assert!(!prefix.prefix.contains("MISSING="));
        assert!(!prefix.prefix.contains("BADVAL="));
        assert!(prefix.rejected.contains(&"BADVAL".to_string()));
        assert!(prefix.rejected.contains(&"BAD=KEY".to_string()));
    }
}
