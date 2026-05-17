//! Rust toolchain information types.
//!
//! Types for representing Rust toolchain information used in the RCH protocol
//! for toolchain synchronization between local and remote workers.

use serde::{Deserialize, Serialize};
use std::borrow::Cow;

use crate::ssh_utils::is_valid_env_key;
use crate::types::ColorMode;

/// Detected Rust toolchain information.
///
/// Contains the channel, optional date, and full version string needed
/// to ensure worker uses the same toolchain as the local project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolchainInfo {
    /// The channel: "stable", "beta", "nightly", or specific version like "1.75.0".
    pub channel: String,
    /// Optional date for nightly/beta: "2024-01-15".
    pub date: Option<String>,
    /// Full version string from rustc --version.
    pub full_version: String,
}

impl ToolchainInfo {
    /// Create a new ToolchainInfo.
    pub fn new(
        channel: impl Into<String>,
        date: Option<String>,
        full_version: impl Into<String>,
    ) -> Self {
        Self {
            channel: channel.into(),
            date,
            full_version: full_version.into(),
        }
    }

    /// Format for rustup run command.
    ///
    /// Returns the toolchain identifier suitable for `rustup run <toolchain>`.
    pub fn rustup_toolchain(&self) -> String {
        match &self.date {
            Some(date) => format!("{}-{}", self.channel, date),
            None => self.channel.clone(),
        }
    }

    /// Check if this is a nightly toolchain.
    pub fn is_nightly(&self) -> bool {
        self.channel == "nightly"
    }

    /// Check if this is a beta toolchain.
    pub fn is_beta(&self) -> bool {
        self.channel == "beta"
    }

    /// Check if this is a stable toolchain.
    pub fn is_stable(&self) -> bool {
        self.channel == "stable"
    }
}

impl std::fmt::Display for ToolchainInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.rustup_toolchain())
    }
}

/// Wrap a command to run with a specific toolchain.
///
/// If toolchain is provided, wraps the command with `rustup run <toolchain>`.
/// Otherwise returns the original command unchanged.
pub fn wrap_command_with_toolchain(command: &str, toolchain: Option<&ToolchainInfo>) -> String {
    match toolchain {
        Some(tc) => insert_toolchain_runner(
            command,
            &format!(
                "rustup run {}",
                shell_escape::escape(Cow::Owned(tc.rustup_toolchain()))
            ),
        ),
        None => command.to_string(),
    }
}

fn insert_toolchain_runner(command: &str, runner: &str) -> String {
    if command.is_empty() {
        return format!("{runner} ");
    }

    let insert_at = toolchain_runner_insert_index(command);
    if insert_at == 0 {
        format!("{runner} {command}")
    } else if insert_at >= command.len() {
        format!("{command} {runner} ")
    } else {
        let Some(prefix) = command.get(..insert_at) else {
            return format!("{runner} {command}");
        };
        let Some(suffix) = command.get(insert_at..) else {
            return format!("{command} {runner} ");
        };
        format!("{prefix}{runner} {suffix}")
    }
}

fn toolchain_runner_insert_index(command: &str) -> usize {
    let Some((start, end)) = next_shell_token_span(command, 0) else {
        return command.len();
    };

    let Some(first) = command.get(start..end) else {
        return start;
    };
    if matches!(first, "env") {
        return env_command_insert_index(command, skip_shell_whitespace(command, end));
    }

    let mut index = start;
    let mut cursor = start;
    while let Some((token_start, token_end)) = next_shell_token_span(command, cursor) {
        let Some(token) = command.get(token_start..token_end) else {
            return token_start;
        };
        if !is_env_assignment_token(token) {
            return token_start;
        }
        index = skip_shell_whitespace(command, token_end);
        cursor = index;
    }

    index
}

fn env_command_insert_index(command: &str, mut cursor: usize) -> usize {
    while let Some((token_start, token_end)) = next_shell_token_span(command, cursor) {
        let Some(token) = command.get(token_start..token_end) else {
            return token_start;
        };
        if matches!(token, "--") {
            return skip_shell_whitespace(command, token_end);
        }
        if env_option_takes_next_token(token) {
            cursor = skip_shell_whitespace(command, token_end);
            if let Some((_, value_end)) = next_shell_token_span(command, cursor) {
                cursor = skip_shell_whitespace(command, value_end);
            }
            continue;
        }
        match token {
            "-u" | "--unset" => {
                cursor = skip_shell_whitespace(command, token_end);
                if let Some((_, unset_end)) = next_shell_token_span(command, cursor) {
                    cursor = skip_shell_whitespace(command, unset_end);
                }
            }
            _ if token.starts_with("--unset=") => {
                cursor = skip_shell_whitespace(command, token_end);
            }
            _ if env_option_has_inline_value(token) => {
                cursor = skip_shell_whitespace(command, token_end);
            }
            _ if token.starts_with('-') && !token.contains('=') => {
                cursor = skip_shell_whitespace(command, token_end);
            }
            _ if is_env_assignment_token(token) => {
                cursor = skip_shell_whitespace(command, token_end);
            }
            _ => return token_start,
        }
    }

    command.len()
}

fn env_option_takes_next_token(token: &str) -> bool {
    matches!(
        token,
        "-C" | "--chdir"
            | "-f"
            | "--file"
            | "-S"
            | "--split-string"
            | "-a"
            | "--argv0"
            | "--ignore-signal"
    )
}

fn env_option_has_inline_value(token: &str) -> bool {
    token.starts_with("--chdir=")
        || token.starts_with("--file=")
        || token.starts_with("--split-string=")
        || token.starts_with("--argv0=")
        || token.starts_with("--ignore-signal=")
        || token.starts_with("-C")
        || token.starts_with("-f")
        || token.starts_with("-S")
        || token.starts_with("-a")
        || token.starts_with("-u")
}

fn is_env_assignment_token(token: &str) -> bool {
    token
        .split_once('=')
        .is_some_and(|(key, _)| is_valid_env_key(key))
}

fn next_shell_token_span(command: &str, offset: usize) -> Option<(usize, usize)> {
    let start = skip_shell_whitespace(command, offset);
    if start >= command.len() {
        return None;
    }

    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;

    let rest = command.get(start..)?;
    for (relative_index, ch) in rest.char_indices() {
        let index = start + relative_index;

        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' && !in_single {
            escaped = true;
            continue;
        }
        if ch == '\'' && !in_double {
            in_single = !in_single;
            continue;
        }
        if ch == '"' && !in_single {
            in_double = !in_double;
            continue;
        }
        if ch.is_whitespace() && !in_single && !in_double {
            return Some((start, index));
        }
    }

    Some((start, command.len()))
}

fn skip_shell_whitespace(command: &str, mut offset: usize) -> usize {
    while offset < command.len() {
        let Some(rest) = command.get(offset..) else {
            break;
        };
        let Some(ch) = rest.chars().next() else {
            break;
        };
        if !ch.is_whitespace() {
            break;
        }
        offset += ch.len_utf8();
    }
    offset
}

/// Wrap a command with environment variables to force color output.
///
/// Remote SSH connections typically don't allocate a PTY, which causes tools
/// like cargo, rustc, and bun to detect a non-TTY and disable color output.
/// This function adds environment variables that force color output regardless
/// of terminal detection.
///
/// # Environment Variables Set
///
/// - `CARGO_TERM_COLOR=always` - Forces cargo to output ANSI colors
/// - `RUST_LOG_STYLE=always` - Forces env_logger/tracing to use colors
/// - `CLICOLOR_FORCE=1` - Standard env var for forcing color output
/// - `FORCE_COLOR=1` - Used by many Node.js/JS tools including Bun
///
/// # Arguments
///
/// * `command` - The command to wrap
/// * `color_mode` - The color mode configuration
///
/// # Returns
///
/// The command prefixed with color-forcing environment variables,
/// or the original command if color mode is Auto or Never.
pub fn wrap_command_with_color(command: &str, color_mode: ColorMode) -> String {
    match color_mode {
        ColorMode::Always => {
            // Environment variables that force color output across different tools:
            // - CARGO_TERM_COLOR: cargo's native color setting
            // - RUST_LOG_STYLE: env_logger and tracing-subscriber color setting
            // - CLICOLOR_FORCE: de facto standard for forcing colors (clicolors.org)
            // - FORCE_COLOR: Node.js/JS ecosystem standard (used by Bun, chalk, etc.)
            // - NO_COLOR: Ensure it's unset (some tools check this first)
            format!(
                "env -u NO_COLOR CARGO_TERM_COLOR=always RUST_LOG_STYLE=always CLICOLOR_FORCE=1 FORCE_COLOR=1 {}",
                command
            )
        }
        ColorMode::Auto => {
            // Let the remote command auto-detect (default behavior)
            command.to_string()
        }
        ColorMode::Never => {
            // Explicitly disable colors
            format!("env NO_COLOR=1 CARGO_TERM_COLOR=never {}", command)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_toolchain_info_new() {
        let tc = ToolchainInfo::new(
            "nightly",
            Some("2024-01-15".to_string()),
            "rustc 1.76.0-nightly",
        );
        assert_eq!(tc.channel, "nightly");
        assert_eq!(tc.date, Some("2024-01-15".to_string()));
    }

    #[test]
    fn test_rustup_toolchain_with_date() {
        let tc = ToolchainInfo {
            channel: "nightly".to_string(),
            date: Some("2024-01-15".to_string()),
            full_version: "".to_string(),
        };
        assert_eq!(tc.rustup_toolchain(), "nightly-2024-01-15");
    }

    #[test]
    fn test_rustup_toolchain_without_date() {
        let tc = ToolchainInfo {
            channel: "stable".to_string(),
            date: None,
            full_version: "".to_string(),
        };
        assert_eq!(tc.rustup_toolchain(), "stable");
    }

    #[test]
    fn test_toolchain_info_display() {
        let tc = ToolchainInfo {
            channel: "nightly".to_string(),
            date: Some("2024-01-15".to_string()),
            full_version: "".to_string(),
        };
        assert_eq!(tc.to_string(), "nightly-2024-01-15");
    }

    #[test]
    fn test_is_nightly() {
        let tc = ToolchainInfo::new("nightly", None, "");
        assert!(tc.is_nightly());
        assert!(!tc.is_stable());
        assert!(!tc.is_beta());
    }

    #[test]
    fn test_is_stable() {
        let tc = ToolchainInfo::new("stable", None, "");
        assert!(tc.is_stable());
        assert!(!tc.is_nightly());
        assert!(!tc.is_beta());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let tc = ToolchainInfo {
            channel: "nightly".to_string(),
            date: Some("2024-01-15".to_string()),
            full_version: "rustc 1.76.0-nightly (abc123 2024-01-15)".to_string(),
        };
        let json = serde_json::to_string(&tc).unwrap();
        let parsed: ToolchainInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(tc, parsed);
    }

    #[test]
    fn test_wrap_command_with_toolchain() {
        let tc = ToolchainInfo::new("nightly", Some("2024-01-15".to_string()), "");
        let wrapped = wrap_command_with_toolchain("cargo build", Some(&tc));
        assert_eq!(wrapped, "rustup run nightly-2024-01-15 cargo build");
    }

    #[test]
    fn test_wrap_command_with_toolchain_preserves_inline_env_assignment() {
        let tc = ToolchainInfo::new("nightly", None, "");
        let wrapped = wrap_command_with_toolchain(
            "RUSTFLAGS=\"-C target-cpu=native\" cargo build",
            Some(&tc),
        );
        assert_eq!(
            wrapped,
            "RUSTFLAGS=\"-C target-cpu=native\" rustup run nightly cargo build"
        );
    }

    #[test]
    fn test_wrap_command_with_toolchain_preserves_env_wrapper() {
        let tc = ToolchainInfo::new("stable", None, "");
        let wrapped = wrap_command_with_toolchain(
            "env -u RUST_LOG RUSTFLAGS=\"-C target-cpu=native\" cargo test",
            Some(&tc),
        );
        assert_eq!(
            wrapped,
            "env -u RUST_LOG RUSTFLAGS=\"-C target-cpu=native\" rustup run stable cargo test"
        );
    }

    #[test]
    fn test_wrap_command_with_toolchain_preserves_env_options_with_operands() {
        let tc = ToolchainInfo::new("stable", None, "");
        let wrapped = wrap_command_with_toolchain(
            "env -C \"/tmp/project dir\" -f .env RUSTFLAGS=-Awarnings cargo test",
            Some(&tc),
        );
        assert_eq!(
            wrapped,
            "env -C \"/tmp/project dir\" -f .env RUSTFLAGS=-Awarnings rustup run stable cargo test"
        );
    }

    #[test]
    fn test_wrap_command_with_toolchain_preserves_env_options_with_inline_operands() {
        let tc = ToolchainInfo::new("stable", None, "");
        let wrapped = wrap_command_with_toolchain(
            "env --chdir=\"/tmp/project dir\" --file=.env RUSTFLAGS=-Awarnings cargo test",
            Some(&tc),
        );
        assert_eq!(
            wrapped,
            "env --chdir=\"/tmp/project dir\" --file=.env RUSTFLAGS=-Awarnings rustup run stable cargo test"
        );
    }

    #[test]
    fn test_wrap_command_with_toolchain_quotes_toolchain_name() {
        let tc = ToolchainInfo::new("nightly;echo injected", None, "");
        let wrapped = wrap_command_with_toolchain("cargo build", Some(&tc));
        assert_eq!(wrapped, "rustup run 'nightly;echo injected' cargo build");
    }

    #[test]
    fn test_wrap_command_no_toolchain() {
        let wrapped = wrap_command_with_toolchain("cargo build", None);
        assert_eq!(wrapped, "cargo build");
    }

    #[test]
    fn test_wrap_command_stable_toolchain() {
        let tc = ToolchainInfo::new("stable", None, "");
        let wrapped = wrap_command_with_toolchain("cargo test", Some(&tc));
        assert_eq!(wrapped, "rustup run stable cargo test");
    }

    // === Additional command wrapping tests for toolchain synchronization ===

    #[test]
    fn test_is_beta() {
        let tc = ToolchainInfo::new("beta", None, "");
        assert!(tc.is_beta());
        assert!(!tc.is_stable());
        assert!(!tc.is_nightly());
    }

    #[test]
    fn test_wrap_command_beta_with_date() {
        let tc = ToolchainInfo::new("beta", Some("2024-02-01".to_string()), "");
        let wrapped = wrap_command_with_toolchain("cargo check", Some(&tc));
        assert_eq!(wrapped, "rustup run beta-2024-02-01 cargo check");
    }

    #[test]
    fn test_wrap_command_specific_version() {
        // Specific version like "1.75.0" without date
        let tc = ToolchainInfo::new("1.75.0", None, "rustc 1.75.0");
        let wrapped = wrap_command_with_toolchain("cargo build --release", Some(&tc));
        assert_eq!(wrapped, "rustup run 1.75.0 cargo build --release");
    }

    #[test]
    fn test_wrap_command_with_complex_args() {
        let tc = ToolchainInfo::new("nightly", None, "");
        let cmd = "cargo build --features \"feature1,feature2\" --target x86_64-unknown-linux-gnu";
        let wrapped = wrap_command_with_toolchain(cmd, Some(&tc));
        assert_eq!(
            wrapped,
            "rustup run nightly cargo build --features \"feature1,feature2\" --target x86_64-unknown-linux-gnu"
        );
    }

    #[test]
    fn test_wrap_command_with_path_spaces() {
        let tc = ToolchainInfo::new("stable", None, "");
        let cmd = "cargo build --manifest-path \"/path/with spaces/Cargo.toml\"";
        let wrapped = wrap_command_with_toolchain(cmd, Some(&tc));
        assert_eq!(
            wrapped,
            "rustup run stable cargo build --manifest-path \"/path/with spaces/Cargo.toml\""
        );
    }

    #[test]
    fn test_wrap_command_empty_string() {
        let tc = ToolchainInfo::new("stable", None, "");
        let wrapped = wrap_command_with_toolchain("", Some(&tc));
        assert_eq!(wrapped, "rustup run stable ");
    }

    #[test]
    fn test_wrap_command_empty_string_no_toolchain() {
        let wrapped = wrap_command_with_toolchain("", None);
        assert_eq!(wrapped, "");
    }

    #[test]
    fn test_wrap_command_clippy() {
        let tc = ToolchainInfo::new("nightly", Some("2024-03-15".to_string()), "");
        let wrapped = wrap_command_with_toolchain("cargo clippy -- -D warnings", Some(&tc));
        assert_eq!(
            wrapped,
            "rustup run nightly-2024-03-15 cargo clippy -- -D warnings"
        );
    }

    #[test]
    fn test_wrap_command_rustfmt() {
        let tc = ToolchainInfo::new("nightly", None, "");
        let wrapped = wrap_command_with_toolchain("cargo fmt --check", Some(&tc));
        assert_eq!(wrapped, "rustup run nightly cargo fmt --check");
    }

    #[test]
    fn test_wrap_command_test_with_filter() {
        let tc = ToolchainInfo::new("stable", None, "");
        let wrapped = wrap_command_with_toolchain("cargo test test_name -- --nocapture", Some(&tc));
        assert_eq!(
            wrapped,
            "rustup run stable cargo test test_name -- --nocapture"
        );
    }

    #[test]
    fn test_rustup_toolchain_beta_with_date() {
        let tc = ToolchainInfo {
            channel: "beta".to_string(),
            date: Some("2024-02-01".to_string()),
            full_version: "".to_string(),
        };
        assert_eq!(tc.rustup_toolchain(), "beta-2024-02-01");
    }

    #[test]
    fn test_rustup_toolchain_specific_version() {
        let tc = ToolchainInfo {
            channel: "1.75.0".to_string(),
            date: None,
            full_version: "rustc 1.75.0".to_string(),
        };
        assert_eq!(tc.rustup_toolchain(), "1.75.0");
    }

    #[test]
    fn test_display_stable() {
        let tc = ToolchainInfo::new("stable", None, "");
        assert_eq!(tc.to_string(), "stable");
    }

    #[test]
    fn test_display_beta_with_date() {
        let tc = ToolchainInfo::new("beta", Some("2024-02-01".to_string()), "");
        assert_eq!(tc.to_string(), "beta-2024-02-01");
    }

    #[test]
    fn test_serialization_stable() {
        let tc = ToolchainInfo::new("stable", None, "rustc 1.75.0 (hash 2024-01-01)");
        let json = serde_json::to_string(&tc).unwrap();
        assert!(json.contains("\"channel\":\"stable\""));
        assert!(json.contains("\"date\":null"));
        let parsed: ToolchainInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(tc, parsed);
    }

    #[test]
    fn test_serialization_beta_with_date() {
        let tc = ToolchainInfo::new("beta", Some("2024-02-01".to_string()), "rustc 1.76.0-beta");
        let json = serde_json::to_string(&tc).unwrap();
        let parsed: ToolchainInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(tc, parsed);
        assert_eq!(parsed.date, Some("2024-02-01".to_string()));
    }

    #[test]
    fn test_toolchain_info_clone() {
        let tc = ToolchainInfo::new("nightly", Some("2024-01-15".to_string()), "rustc 1.76.0");
        let cloned = tc.clone();
        assert_eq!(tc, cloned);
        assert_eq!(tc.channel, cloned.channel);
        assert_eq!(tc.date, cloned.date);
        assert_eq!(tc.full_version, cloned.full_version);
    }

    #[test]
    fn test_toolchain_info_equality() {
        let tc1 = ToolchainInfo::new("nightly", Some("2024-01-15".to_string()), "rustc 1.76.0");
        let tc2 = ToolchainInfo::new("nightly", Some("2024-01-15".to_string()), "rustc 1.76.0");
        let tc3 = ToolchainInfo::new("nightly", Some("2024-01-16".to_string()), "rustc 1.76.0");
        assert_eq!(tc1, tc2);
        assert_ne!(tc1, tc3);
    }

    #[test]
    fn test_channel_detection_methods_consistency() {
        // Only one of the is_* methods should return true for a given toolchain
        for channel in &["stable", "beta", "nightly", "1.75.0", "custom"] {
            let tc = ToolchainInfo::new(*channel, None, "");
            let count = [tc.is_stable(), tc.is_beta(), tc.is_nightly()]
                .iter()
                .filter(|&&b| b)
                .count();
            // Should have at most one true (custom channels have none)
            assert!(count <= 1, "Multiple channel types for: {}", channel);
        }
    }

    // === Color wrapping tests ===

    #[test]
    fn test_wrap_command_with_color_always() {
        let wrapped = wrap_command_with_color("cargo test", ColorMode::Always);
        assert!(wrapped.contains("CARGO_TERM_COLOR=always"));
        assert!(wrapped.contains("RUST_LOG_STYLE=always"));
        assert!(wrapped.contains("CLICOLOR_FORCE=1"));
        assert!(wrapped.contains("FORCE_COLOR=1"));
        assert!(wrapped.contains("env -u NO_COLOR"));
        assert!(wrapped.contains("cargo test"));
    }

    #[test]
    fn test_wrap_command_with_color_auto() {
        let wrapped = wrap_command_with_color("cargo test", ColorMode::Auto);
        // Auto mode should not modify the command
        assert_eq!(wrapped, "cargo test");
    }

    #[test]
    fn test_wrap_command_with_color_never() {
        let wrapped = wrap_command_with_color("cargo test", ColorMode::Never);
        assert!(wrapped.starts_with("env "));
        assert!(wrapped.contains("NO_COLOR=1"));
        assert!(wrapped.contains("CARGO_TERM_COLOR=never"));
        assert!(wrapped.contains("cargo test"));
    }

    #[test]
    fn test_wrap_command_with_color_never_is_timeout_safe() {
        let wrapped = wrap_command_with_color("sh -c 'exit 43'", ColorMode::Never);
        let status = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!(
                "timeout --foreground --preserve-status 5 {}",
                wrapped
            ))
            .status()
            .expect("timeout-wrapped color-disabled command should execute");

        assert_eq!(
            status.code(),
            Some(43),
            "timeout must execute env, not an environment assignment argv"
        );
    }

    #[test]
    fn test_wrap_command_with_color_preserves_complex_command() {
        let cmd = "cargo test --release -- --test-threads=4";
        let wrapped = wrap_command_with_color(cmd, ColorMode::Always);
        assert!(wrapped.contains(cmd));
    }

    #[test]
    fn test_wrap_command_with_color_bun_commands() {
        // Verify Bun commands work with color wrapping (uses FORCE_COLOR)
        let wrapped = wrap_command_with_color("bun test", ColorMode::Always);
        assert!(wrapped.contains("FORCE_COLOR=1"));
        assert!(wrapped.contains("bun test"));
    }

    #[test]
    fn test_color_mode_display() {
        assert_eq!(ColorMode::Always.to_string(), "always");
        assert_eq!(ColorMode::Auto.to_string(), "auto");
        assert_eq!(ColorMode::Never.to_string(), "never");
    }

    #[test]
    fn test_color_mode_from_str() {
        assert_eq!("always".parse::<ColorMode>(), Ok(ColorMode::Always));
        assert_eq!("force".parse::<ColorMode>(), Ok(ColorMode::Always));
        assert_eq!("auto".parse::<ColorMode>(), Ok(ColorMode::Auto));
        assert_eq!("never".parse::<ColorMode>(), Ok(ColorMode::Never));
        assert_eq!("no".parse::<ColorMode>(), Ok(ColorMode::Never));
        assert!("invalid".parse::<ColorMode>().is_err());
    }

    #[test]
    fn test_color_mode_default() {
        // Default should be Always to preserve colors in remote SSH
        assert_eq!(ColorMode::default(), ColorMode::Always);
    }
}
