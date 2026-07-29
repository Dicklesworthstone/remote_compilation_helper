//! Detect quoted single-command misuse in `rch exec`
//! (bd-session-history-remediation-ocv9i.13.1).
//!
//! Agents repeatedly ran `rch exec "cargo check --all-targets"` — the whole
//! command as one quoted string, with no `--` separator. Clap then treats
//! `cargo check --all-targets` as a single program name and RCH tries to exec a
//! bogus binary. This module detects that shape and, instead of running
//! anything, returns a clear correction: `rch exec -- cargo check --all-targets`.
//!
//! [`detect_exec_misuse`] is pure: given the argv after `exec` and whether a
//! `--` separator was present, it decides misuse and builds the suggestion. The
//! [`ExecMisuseReport`] carries `reason_code = exec_quoted_command_misuse`, the
//! parsed suggestion, and the original argv for a machine-readable error.

use serde::{Deserialize, Serialize};

/// The stable reason code string for this misuse (not an `RCH-Innn` incident
/// code — it is a CLI-usage error, surfaced verbatim in the JSON error).
pub const QUOTED_MISUSE_REASON: &str = "exec_quoted_command_misuse";

/// The result of checking `rch exec` argv for quoted-command misuse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecMisuseReport {
    /// Whether the argv is the single-quoted-command misuse shape.
    pub misuse: bool,
    /// Stable reason code, present only on misuse.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    /// The original argv after `exec`, echoed for diagnostics.
    pub original_argv: Vec<String>,
    /// The suggested corrected command line, present only on misuse.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggestion: Option<String>,
    /// Best-effort whitespace split of the quoted command (present on misuse).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parsed_command: Vec<String>,
}

/// Detect quoted single-command misuse. Pure.
///
/// Misuse is exactly: no `--` separator was given **and** the argv after `exec`
/// is a single element that contains whitespace (i.e. a whole command line was
/// passed as one quoted string). A single bare executable name, a properly
/// `--`-separated command, or multiple argv tokens are all legitimate.
#[must_use]
pub fn detect_exec_misuse(argv: &[String], had_separator: bool) -> ExecMisuseReport {
    let is_single_quoted =
        !had_separator && argv.len() == 1 && argv[0].split_whitespace().count() > 1;

    if is_single_quoted {
        let raw = argv[0].trim();
        let parsed_command = raw.split_whitespace().map(str::to_string).collect();
        ExecMisuseReport {
            misuse: true,
            reason_code: Some(QUOTED_MISUSE_REASON.to_string()),
            original_argv: argv.to_vec(),
            suggestion: Some(format!("rch exec -- {raw}")),
            parsed_command,
        }
    } else {
        ExecMisuseReport {
            misuse: false,
            reason_code: None,
            original_argv: argv.to_vec(),
            suggestion: None,
            parsed_command: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn cargo_quoted_command_is_misuse() {
        let report = detect_exec_misuse(&argv(&["cargo check --all-targets"]), false);
        assert!(report.misuse);
        assert_eq!(report.reason_code.as_deref(), Some(QUOTED_MISUSE_REASON));
        assert_eq!(
            report.suggestion.as_deref(),
            Some("rch exec -- cargo check --all-targets")
        );
        assert_eq!(
            report.parsed_command,
            argv(&["cargo", "check", "--all-targets"])
        );
    }

    #[test]
    fn bun_quoted_command_is_misuse() {
        let report = detect_exec_misuse(&argv(&["bun test --coverage"]), false);
        assert!(report.misuse);
        assert_eq!(
            report.suggestion.as_deref(),
            Some("rch exec -- bun test --coverage")
        );
    }

    #[test]
    fn env_prefixed_quoted_command_is_misuse() {
        let report = detect_exec_misuse(&argv(&["env CARGO_TARGET_DIR=/tmp/t cargo build"]), false);
        assert!(report.misuse);
        assert_eq!(
            report.suggestion.as_deref(),
            Some("rch exec -- env CARGO_TARGET_DIR=/tmp/t cargo build")
        );
    }

    #[test]
    fn shell_quoted_command_is_misuse() {
        let report = detect_exec_misuse(&argv(&["bash -lc 'cargo build'"]), false);
        assert!(report.misuse);
        assert!(
            report
                .suggestion
                .as_deref()
                .unwrap()
                .contains("bash -lc 'cargo build'")
        );
    }

    #[test]
    fn legitimate_single_executable_is_not_misuse() {
        // A bare program name with no whitespace is a legitimate exec target.
        let report = detect_exec_misuse(&argv(&["mybinary"]), false);
        assert!(!report.misuse);
        assert!(report.suggestion.is_none());
        assert!(report.reason_code.is_none());
    }

    #[test]
    fn properly_separated_command_is_not_misuse() {
        // `rch exec -- cargo build` arrives as multi-token argv WITH a separator.
        let report = detect_exec_misuse(&argv(&["cargo", "build"]), true);
        assert!(!report.misuse);
        // Even a single token with a separator is fine.
        assert!(!detect_exec_misuse(&argv(&["cargo build"]), true).misuse);
    }

    #[test]
    fn multi_token_argv_without_separator_is_not_this_misuse() {
        // Multiple argv tokens are clap's trailing-var-arg form, not the single
        // quoted-string mistake this detector targets.
        let report = detect_exec_misuse(&argv(&["cargo", "check", "--all-targets"]), false);
        assert!(!report.misuse);
    }

    #[test]
    fn empty_argv_is_not_misuse() {
        let report = detect_exec_misuse(&[], false);
        assert!(!report.misuse);
    }

    #[test]
    fn report_serializes_with_reason_and_original_argv() {
        let report = detect_exec_misuse(&argv(&["cargo check --all-targets"]), false);
        let value = serde_json::to_value(&report).unwrap();
        assert_eq!(value["misuse"], true);
        assert_eq!(value["reason_code"], "exec_quoted_command_misuse");
        assert_eq!(value["original_argv"][0], "cargo check --all-targets");
        assert_eq!(value["suggestion"], "rch exec -- cargo check --all-targets");
        let back: ExecMisuseReport = serde_json::from_value(value).unwrap();
        assert_eq!(back, report);
    }

    #[test]
    fn non_misuse_omits_reason_and_suggestion_on_the_wire() {
        let report = detect_exec_misuse(&argv(&["mybinary"]), false);
        let value = serde_json::to_value(&report).unwrap();
        assert!(value.get("reason_code").is_none());
        assert!(value.get("suggestion").is_none());
        assert!(value.get("parsed_command").is_none());
    }
}
