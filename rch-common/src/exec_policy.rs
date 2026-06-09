//! Explicit-exec policy for non-compilation commands
//! (bd-session-history-remediation-ocv9i.13.2).
//!
//! There are two execution contexts and they must behave differently:
//!
//! - **Hook mode** (the PreToolUse hook): a non-compilation command stays
//!   local and fail-open — RCH must never get in the way of a command the agent
//!   didn't ask it to offload.
//! - **Explicit `rch exec`**: the user explicitly asked RCH to participate, so
//!   silence is wrong. The output must say clearly whether RCH will **reject**
//!   the command, **run it remotely** by explicit override, or **run it locally**
//!   as a fallback — and the policy is deliberately conservative for commands
//!   that mutate local state (formatting, installs), which must never be
//!   shipped to a worker where the mutation would land on the wrong filesystem.
//!
//! [`decide_exec_policy`] is the pure decision; [`ExecDecision`] carries the
//! disposition and the operator/agent-facing message.

use serde::{Deserialize, Serialize};

use crate::patterns::classify_command;

/// What RCH will do with the command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecDisposition {
    /// Run on a remote worker (a compilation, or an explicit safe override).
    RunRemote,
    /// Run locally as a fallback (non-compilation, or a state-mutating command
    /// that must stay local).
    RunLocalFallback,
    /// Refuse to run (proof mode cannot prove a non-compilation command).
    Reject,
}

impl ExecDisposition {
    /// Stable lowercase token.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ExecDisposition::RunRemote => "run_remote",
            ExecDisposition::RunLocalFallback => "run_local_fallback",
            ExecDisposition::Reject => "reject",
        }
    }
}

/// The execution context + explicit overrides for the policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecContext {
    /// True for explicit `rch exec`; false for the PreToolUse hook.
    pub explicit_exec: bool,
    /// Proof/strict-remote mode is in force.
    pub proof_mode: bool,
    /// An explicit force-remote override (`RCH_FORCE_REMOTE`).
    pub force_remote: bool,
}

impl ExecContext {
    /// The hook context (non-explicit), fail-open by default.
    #[must_use]
    pub fn hook() -> Self {
        Self {
            explicit_exec: false,
            proof_mode: false,
            force_remote: false,
        }
    }

    /// A plain explicit `rch exec` context.
    #[must_use]
    pub fn explicit() -> Self {
        Self {
            explicit_exec: true,
            proof_mode: false,
            force_remote: false,
        }
    }
}

/// The policy decision plus its message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecDecision {
    pub disposition: ExecDisposition,
    pub is_compilation: bool,
    /// Whether the command mutates local state (formatting, installs, …).
    pub mutates_local_state: bool,
    /// Clear operator/agent-facing message.
    pub message: String,
}

/// Known commands that mutate the local working tree (so they must never be
/// shipped to a worker). Matched as a normalized `<tool> <subcommand>` pair, so
/// an `env VAR=… ` prefix or extra flags do not hide them.
const LOCAL_MUTATING: &[(&str, &str)] = &[
    ("cargo", "fmt"),
    ("cargo", "fix"),
    ("cargo", "add"),
    ("cargo", "remove"),
    ("cargo", "update"),
    ("bun", "install"),
    ("bun", "add"),
    ("bun", "remove"),
    ("npm", "install"),
    ("npm", "ci"),
    ("pnpm", "install"),
    ("yarn", "install"),
];

/// Whether `command` is a known local-state-mutating command. Skips leading
/// `env VAR=value` assignments and any flags between the tool and subcommand.
#[must_use]
pub fn mutates_local_state(command: &str) -> bool {
    let mut tokens = command.split_whitespace().peekable();
    // Skip a leading `env` and its `VAR=value` assignments.
    if tokens.peek() == Some(&"env") {
        tokens.next();
        while tokens.peek().is_some_and(|t| t.contains('=') && !t.starts_with('-')) {
            tokens.next();
        }
    }
    // Skip any remaining leading `VAR=value` assignments (env-style without `env`).
    while tokens.peek().is_some_and(|t| {
        t.contains('=') && !t.starts_with('-') && !t.contains('/')
    }) {
        tokens.next();
    }
    let Some(tool) = tokens.next() else {
        return false;
    };
    // First non-flag token after the tool is the subcommand.
    let subcommand = tokens.find(|t| !t.starts_with('-'));
    let Some(subcommand) = subcommand else {
        return false;
    };
    LOCAL_MUTATING
        .iter()
        .any(|(t, s)| *t == tool && *s == subcommand)
}

/// Decide the explicit-exec policy for a command. Pure and total.
#[must_use]
pub fn decide_exec_policy(command: &str, ctx: &ExecContext) -> ExecDecision {
    let is_compilation = classify_command(command).is_compilation;
    let mutates = mutates_local_state(command);

    let (disposition, message): (ExecDisposition, String) = if is_compilation {
        // Compilation offloads in both contexts (the normal path).
        (
            ExecDisposition::RunRemote,
            "compilation command — running on a remote worker".to_string(),
        )
    } else if !ctx.explicit_exec {
        // Hook mode: non-compilation stays local, fail-open, silently.
        (
            ExecDisposition::RunLocalFallback,
            "non-compilation in hook mode — running locally (fail-open)".to_string(),
        )
    } else if ctx.proof_mode {
        // Explicit proof mode can't prove a non-compilation command.
        (
            ExecDisposition::Reject,
            "proof mode requires a provable remote compilation; this command cannot be proven — rejected".to_string(),
        )
    } else if mutates {
        // Conservative: a state-mutating command must run where the state lives.
        (
            ExecDisposition::RunLocalFallback,
            "non-compilation that mutates local state — running locally (never shipped to a worker)".to_string(),
        )
    } else if ctx.force_remote {
        // Explicit override for a safe, non-mutating command.
        (
            ExecDisposition::RunRemote,
            "non-compilation, but RCH_FORCE_REMOTE set and command is side-effect-safe — running remotely by explicit override".to_string(),
        )
    } else {
        // Default explicit-exec fallback.
        (
            ExecDisposition::RunLocalFallback,
            "non-compilation under explicit rch exec — running locally as fallback".to_string(),
        )
    };

    ExecDecision {
        disposition,
        is_compilation,
        mutates_local_state: mutates,
        message,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cargo_fmt_runs_local_and_is_flagged_mutating() {
        assert!(mutates_local_state("cargo fmt"));
        let d = decide_exec_policy("cargo fmt", &ExecContext::explicit());
        assert_eq!(d.disposition, ExecDisposition::RunLocalFallback);
        assert!(d.mutates_local_state);
        assert!(!d.is_compilation);
        assert!(d.message.contains("locally"));
    }

    #[test]
    fn cargo_fmt_stays_local_even_with_force_remote() {
        // Conservative: force-remote must NOT ship a state-mutating command.
        let ctx = ExecContext {
            explicit_exec: true,
            proof_mode: false,
            force_remote: true,
        };
        let d = decide_exec_policy("cargo fmt", &ctx);
        assert_eq!(d.disposition, ExecDisposition::RunLocalFallback);
    }

    #[test]
    fn env_prefixed_cargo_fmt_is_still_detected() {
        // `env CARGO_TARGET_DIR=... cargo fmt` must not hide the mutation.
        assert!(mutates_local_state("env CARGO_TARGET_DIR=/tmp/t cargo fmt"));
        let d = decide_exec_policy(
            "env CARGO_TARGET_DIR=/tmp/t cargo fmt",
            &ExecContext::explicit(),
        );
        assert_eq!(d.disposition, ExecDisposition::RunLocalFallback);
        assert!(d.mutates_local_state);
    }

    #[test]
    fn bun_install_runs_local() {
        assert!(mutates_local_state("bun install"));
        let d = decide_exec_policy("bun install", &ExecContext::explicit());
        assert_eq!(d.disposition, ExecDisposition::RunLocalFallback);
        assert!(d.mutates_local_state);
    }

    #[test]
    fn explicit_proof_mode_rejects_non_compilation() {
        let ctx = ExecContext {
            explicit_exec: true,
            proof_mode: true,
            force_remote: false,
        };
        let d = decide_exec_policy("ls -la", &ctx);
        assert_eq!(d.disposition, ExecDisposition::Reject);
        assert!(d.message.contains("rejected"));
    }

    #[test]
    fn proof_mode_rejects_even_state_mutating() {
        // Proof mode is the strongest: it rejects rather than silently running
        // a non-compilation locally.
        let ctx = ExecContext {
            explicit_exec: true,
            proof_mode: true,
            force_remote: false,
        };
        assert_eq!(
            decide_exec_policy("cargo fmt", &ctx).disposition,
            ExecDisposition::Reject
        );
    }

    #[test]
    fn hook_mode_non_compilation_is_local_failopen() {
        let d = decide_exec_policy("ls -la", &ExecContext::hook());
        assert_eq!(d.disposition, ExecDisposition::RunLocalFallback);
        assert!(d.message.contains("fail-open"));
    }

    #[test]
    fn compilation_runs_remote() {
        let d = decide_exec_policy("cargo build --release", &ExecContext::explicit());
        assert_eq!(d.disposition, ExecDisposition::RunRemote);
        assert!(d.is_compilation);
    }

    #[test]
    fn safe_non_compilation_with_force_remote_runs_remote() {
        let ctx = ExecContext {
            explicit_exec: true,
            proof_mode: false,
            force_remote: true,
        };
        // A side-effect-safe non-compilation honored by explicit override.
        let d = decide_exec_policy("echo hello", &ctx);
        assert_eq!(d.disposition, ExecDisposition::RunRemote);
        assert!(!d.mutates_local_state);
        assert!(d.message.contains("override"));
    }

    #[test]
    fn plain_explicit_non_compilation_falls_back_local() {
        let d = decide_exec_policy("echo hi", &ExecContext::explicit());
        assert_eq!(d.disposition, ExecDisposition::RunLocalFallback);
    }

    #[test]
    fn non_mutating_tool_is_not_flagged() {
        assert!(!mutates_local_state("cargo build"));
        assert!(!mutates_local_state("ls -la"));
        assert!(!mutates_local_state("bun test"));
    }

    #[test]
    fn decision_serializes_with_stable_tokens() {
        let d = decide_exec_policy("cargo fmt", &ExecContext::explicit());
        let v = serde_json::to_value(&d).unwrap();
        assert_eq!(v["disposition"], "run_local_fallback");
        assert_eq!(v["mutates_local_state"], true);
        let back: ExecDecision = serde_json::from_value(v).unwrap();
        assert_eq!(back, d);
    }
}
