//! Remote-execution result type and outcome classification for the hook.
//!
//! This submodule owns the data that describes the outcome of a remote build and
//! the predicates that interpret it, extracted from `hook.rs` per bead
//! `remote_compilation_helper-zcecy.14`:
//!
//! - [`RemoteExecutionResult`] — the exit code / stderr / duration / per-phase
//!   timing produced by `transfer_orchestration::execute_remote_compilation` and
//!   consumed by `run_hook` / `run_exec`.
//! - **Toolchain-failure detection** — [`is_toolchain_failure`] recognizes the
//!   stderr signatures of a missing/misconfigured rustup toolchain so the hook can
//!   fall back to local execution rather than deny.
//! - **Worker system-dependency detection** — [`detect_worker_system_dependency_failure`]
//!   parses pkg-config / system-library errors into a
//!   [`WorkerSystemDependencyFailure`] carrying an operator-facing summary,
//!   remediation, and log detail.
//! - **Signal classification** — [`is_signal_killed`] / [`signal_name`] decode the
//!   `128 + N` signal-exit convention.
//!
//! It reaches its inputs from the parent via `use super::*` (the `EXIT_*`
//! exit-code consts and `CommandTimingBreakdown`). Items consumed by the parent
//! (`run_hook` / `run_exec`) and by the sibling `transfer_orchestration`
//! (`RemoteExecutionResult`, which it constructs and returns) are `pub(super)`;
//! `extract_tick_quoted_value` (a detection-only helper) stays private. The
//! cluster's unit tests remain in `hook::tests` and reach the classifier fns via
//! the test module's `use super::*` (the parent re-exports them).

use super::*;

/// Result of remote compilation execution.
#[derive(Debug)]
pub(super) struct RemoteExecutionResult {
    /// Exit code of the remote command.
    pub(super) exit_code: i32,
    /// Standard error output (used for toolchain detection).
    pub(super) stderr: String,
    /// Remote command duration in milliseconds.
    pub(super) duration_ms: u64,
    /// Per-phase timing breakdown.
    pub(super) timing: CommandTimingBreakdown,
}

/// Check if the failure is a toolchain-related infrastructure failure.
///
/// Returns true if the error indicates a toolchain issue that should
/// trigger a local fallback rather than denying execution.
pub(super) fn is_toolchain_failure(stderr: &str, exit_code: i32) -> bool {
    if exit_code == 0 || exit_code == EXIT_TEST_FAILURES || is_signal_killed(exit_code).is_some() {
        return false;
    }

    stderr
        .lines()
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .any(|line| {
            line.starts_with("rustup: command not found")
                || line.starts_with("rustup: not found")
                || line.contains("error: no default toolchain configured")
                || line.contains("error: no active toolchain")
                || (line.contains("error: toolchain ")
                    && (line.contains(" is not installed")
                        || line.contains(" is unavailable")
                        || line.contains(" does not have the binary ")))
                || (line.contains("error: override toolchain ")
                    && line.contains(" is not installed"))
        })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct WorkerSystemDependencyFailure {
    pub(super) system_library: Option<String>,
    pub(super) crate_name: Option<String>,
    pub(super) pkg_config_file: Option<String>,
}

impl WorkerSystemDependencyFailure {
    pub(super) fn summary(&self) -> String {
        if let Some(pkg_config_file) = &self.pkg_config_file {
            return format!("missing worker system package {}", pkg_config_file);
        }
        if let Some(system_library) = &self.system_library {
            return format!("missing worker system library {}", system_library);
        }
        "worker build environment is missing a required system package".to_string()
    }

    pub(super) fn remediation(&self) -> String {
        match (&self.pkg_config_file, &self.system_library) {
            (Some(pkg_config_file), Some(system_library)) => format!(
                "Install the worker-side development package that provides {} (system library {}) and ensure pkg-config can resolve it on the worker.",
                pkg_config_file, system_library
            ),
            (Some(pkg_config_file), None) => format!(
                "Install the worker-side development package that provides {} and ensure PKG_CONFIG_PATH includes its parent directory on the worker.",
                pkg_config_file
            ),
            (None, Some(system_library)) => format!(
                "Install the worker-side development package for system library {} and ensure pkg-config is configured on the worker.",
                system_library
            ),
            (None, None) => "Install the missing worker-side development package and ensure pkg-config can find it on the worker.".to_string(),
        }
    }

    pub(super) fn log_detail(&self) -> String {
        let mut parts = Vec::new();
        if let Some(crate_name) = &self.crate_name {
            parts.push(format!("crate={}", crate_name));
        }
        if let Some(system_library) = &self.system_library {
            parts.push(format!("system_library={}", system_library));
        }
        if let Some(pkg_config_file) = &self.pkg_config_file {
            parts.push(format!("pkg_config_file={}", pkg_config_file));
        }
        if parts.is_empty() {
            "pkg-config/system dependency detection matched".to_string()
        } else {
            parts.join(" ")
        }
    }
}

pub(super) fn detect_worker_system_dependency_failure(
    stderr: &str,
    exit_code: i32,
) -> Option<WorkerSystemDependencyFailure> {
    if exit_code == 0 {
        return None;
    }

    let mut system_library = None;
    let mut crate_name = None;
    let mut pkg_config_file = None;
    let mut pkg_config_signal = false;

    for raw_line in stderr.lines() {
        let line = raw_line.trim();
        let lower = line.to_ascii_lowercase();

        if lower.contains("pkg-config exited with status code")
            || lower.contains("pkg_config_path")
            || lower.contains("the system library `")
            || lower.contains(".pc` needs to be installed")
        {
            pkg_config_signal = true;
        }

        if let Some(value) = extract_tick_quoted_value(line, "The system library `") {
            system_library = Some(value);
        }
        if let Some(value) = extract_tick_quoted_value(line, "required by crate `") {
            crate_name = Some(value);
        }
        if let Some(value) = extract_tick_quoted_value(line, "The file `")
            && value.ends_with(".pc")
        {
            pkg_config_file = Some(value);
        }
    }

    if !pkg_config_signal || (system_library.is_none() && pkg_config_file.is_none()) {
        return None;
    }

    Some(WorkerSystemDependencyFailure {
        system_library,
        crate_name,
        pkg_config_file,
    })
}

fn extract_tick_quoted_value(line: &str, prefix: &str) -> Option<String> {
    let remainder = line.split_once(prefix)?.1;
    let value = remainder.split('`').next()?.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

/// Check if the process was killed by a signal.
///
/// Exit codes > 128 indicate the process was terminated by a signal.
/// The signal number is exit_code - 128.
///
/// Common signals:
/// - 137 (SIGKILL = 9): Typically OOM killer
/// - 143 (SIGTERM = 15): Graceful termination request
/// - 139 (SIGSEGV = 11): Segmentation fault
#[allow(dead_code)]
pub(super) fn is_signal_killed(exit_code: i32) -> Option<i32> {
    if exit_code > EXIT_SIGNAL_BASE {
        Some(exit_code - EXIT_SIGNAL_BASE)
    } else {
        None
    }
}

/// Format a signal number as a human-readable name.
#[allow(dead_code)]
pub(super) fn signal_name(signal: i32) -> &'static str {
    match signal {
        1 => "SIGHUP",
        2 => "SIGINT",
        3 => "SIGQUIT",
        6 => "SIGABRT",
        9 => "SIGKILL",
        11 => "SIGSEGV",
        13 => "SIGPIPE",
        14 => "SIGALRM",
        15 => "SIGTERM",
        _ => "UNKNOWN",
    }
}
