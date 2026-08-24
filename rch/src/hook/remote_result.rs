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
    /// Per declared-result-dir collection outcome (bd-p0yoo), for the
    /// machine-readable envelope (bd-uoh4x). Empty when no dirs declared.
    pub(super) result_dirs: Vec<ExecResultDirStat>,
}

/// Collection outcome of one declared job result directory (bd-uoh4x).
#[derive(Debug, Clone, serde::Serialize)]
pub(super) struct ExecResultDirStat {
    pub path: String,
    pub files: u64,
    pub bytes: u64,
    /// "ok" or a short failure classification ("missing", "transfer_failed").
    pub status: String,
}

/// Machine-readable execution envelope emitted on stdout when the exec
/// invocation requested machine output (`--json` / `--format`) — bd-uoh4x.
///
/// `outcome` describes DELIVERY, not build success: `completed` means the
/// remote command ran and its outputs were handled (whatever the exit code),
/// `transport_error` / `collection_error` mean RCH itself failed to deliver.
#[derive(Debug, serde::Serialize)]
pub(crate) struct ExecResultEnvelope<'a> {
    pub api_version: &'static str,
    pub command: &'a str,
    pub outcome: &'a str,
    pub location: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback_reason: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub worker_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timing: Option<&'a CommandTimingBreakdown>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_dirs: Option<&'a [ExecResultDirStat]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<&'a str>,
}

/// Whether THIS invocation requested machine output on stdout (bd-uoh4x).
/// Set once by `run_exec` from its OutputContext; the PreToolUse hook path
/// never sets it, so hook protocol stdout stays pristine.
static MACHINE_OUTPUT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub(super) fn set_machine_output(on: bool) {
    MACHINE_OUTPUT.store(on, std::sync::atomic::Ordering::Relaxed);
}

pub(super) fn machine_output() -> bool {
    MACHINE_OUTPUT.load(std::sync::atomic::Ordering::Relaxed)
}

/// Print the execution envelope to stdout when machine output is active.
/// Never prints otherwise and never touches stderr (diagnostics stream).
pub(super) fn emit_exec_envelope(env: &ExecResultEnvelope<'_>) {
    if !machine_output() {
        return;
    }
    if let Ok(line) = serde_json::to_string(env) {
        println!("{line}");
    }
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
        // 4/7: CPU-capability faults (bd-68hon) — an Ivy-Bridge-class
        // worker executing x86-64-v3 codegen dies by SIGILL; logging
        // it as UNKNOWN hid the real cause behind "exit 132".
        4 => "SIGILL",
        6 => "SIGABRT",
        7 => "SIGBUS",
        9 => "SIGKILL",
        11 => "SIGSEGV",
        13 => "SIGPIPE",
        14 => "SIGALRM",
        15 => "SIGTERM",
        _ => "UNKNOWN",
    }
}

/// Whether a signal indicates a WORKER CPU-CAPABILITY fault rather than
/// resource exhaustion (bd-68hon): SIGILL means the worker's CPU cannot
/// execute the build's codegen (e.g. AVX2 on a pre-v3 microarch). The
/// build is fine; the WORKER is incompatible — quarantine it and retry
/// on any other worker, instead of the OOM heuristic of "retry bigger".
pub(super) const fn is_cpu_capability_signal(signal: i32) -> bool {
    signal == 4
}

/// Detect a build-tool-WRAPPED CPU-capability signal death.
///
/// Live verification against ovh-b (2026-08-09) showed the incident-class
/// fault never reaches the exit-code arm: when a build script or proc-macro
/// dies by SIGILL, cargo does NOT propagate 128+N — it prints
/// `process didn't exit successfully: `…` (signal: 4, SIGILL: illegal
/// instruction)` and exits 101, so the CPU-capability fault masquerades as
/// an ordinary build failure and the worker is never quarantined.
///
/// Sniff cargo's diagnostic line instead. Both markers must appear on the
/// SAME line so incidental strings in test output cannot spoof a quarantine,
/// and a zero exit never classifies.
pub(super) fn wrapped_cpu_capability_signal(exit_code: i32, output: &str) -> Option<i32> {
    if exit_code == 0 {
        return None;
    }
    for line in output.lines() {
        if !line.contains("didn't exit successfully") {
            continue;
        }
        if line.contains("(signal: 4, SIGILL") {
            return Some(4);
        }
        if line.contains("(signal: 7, SIGBUS") {
            return Some(7);
        }
    }
    None
}

/// Topology-specific Cargo workspace inheritance failure under remote roots.
#[derive(Debug, Clone)]
pub(super) struct CargoWorkspaceInheritanceFailure {
    inherited_field: Option<String>,
}

impl CargoWorkspaceInheritanceFailure {
    pub(super) fn summary(&self) -> String {
        match &self.inherited_field {
            Some(field) => format!("cargo workspace inheritance blocked for {field}"),
            None => "cargo workspace inheritance blocked by remote topology".to_string(),
        }
    }

    pub(super) fn remediation(&self) -> &'static str {
        "Sync dependency workspace metadata roots or isolate remote sync roots from unrelated outer Cargo workspaces before retrying."
    }

    pub(super) fn log_detail(&self) -> String {
        match &self.inherited_field {
            Some(field) => format!("workspace_package_field={field}"),
            None => "workspace package inheritance failure matched".to_string(),
        }
    }
}

/// Detect Cargo workspace-inheritance failures caused by remote topology isolation.
pub(super) fn detect_cargo_workspace_inheritance_failure(
    stderr: &str,
    exit_code: i32,
) -> Option<CargoWorkspaceInheritanceFailure> {
    if exit_code == 0 {
        return None;
    }

    let lower = stderr.to_ascii_lowercase();
    let inherits_from_workspace =
        lower.contains("error inheriting") && lower.contains("from workspace root manifest");
    let missing_workspace_package =
        lower.contains("workspace.package.") && lower.contains("was not defined");
    if !inherits_from_workspace || !missing_workspace_package {
        return None;
    }

    let inherited_field = stderr.lines().find_map(extract_workspace_package_field);
    Some(CargoWorkspaceInheritanceFailure { inherited_field })
}

fn extract_workspace_package_field(line: &str) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    let prefix = "workspace.package.";
    let start = lower.find(prefix)? + prefix.len();
    let original_tail = line.get(start..)?.trim_start();
    let field = original_tail
        .split_whitespace()
        .next()?
        .trim_matches(|ch: char| !ch.is_ascii_alphanumeric() && ch != '-' && ch != '_');
    (!field.is_empty()).then(|| field.to_string())
}

#[cfg(test)]
mod wrapped_signal_tests {
    use super::wrapped_cpu_capability_signal;

    const CARGO_SIGILL_LINE: &str = "  process didn't exit successfully: `/data/projects/avx2probe/.rch-target-ovh-b-pool-75509f/debug/build/avx2probe/b03d/out/build_script_build` (signal: 4, SIGILL: illegal instruction)";

    #[test]
    fn detects_cargo_wrapped_build_script_sigill_at_exit_101() {
        assert_eq!(
            wrapped_cpu_capability_signal(101, CARGO_SIGILL_LINE),
            Some(4)
        );
    }

    #[test]
    fn detects_cargo_wrapped_sigbus() {
        let line = "process didn't exit successfully: `rustc …` (signal: 7, SIGBUS: access to undefined memory)";
        assert_eq!(wrapped_cpu_capability_signal(101, line), Some(7));
    }

    #[test]
    fn zero_exit_never_classifies_even_with_marker() {
        assert_eq!(wrapped_cpu_capability_signal(0, CARGO_SIGILL_LINE), None);
    }

    #[test]
    fn markers_on_separate_lines_do_not_classify() {
        // e.g. test output that PRINTS a sample cargo error across lines, or
        // mentions the signal marker without cargo's process-death prefix.
        let output =
            "left: `didn't exit successfully`\nright: `(signal: 4, SIGILL: illegal instruction)`";
        assert_eq!(wrapped_cpu_capability_signal(101, output), None);
    }

    #[test]
    fn other_signals_in_marker_do_not_classify() {
        // SIGKILL (OOM) stays with the resource-exhaustion handling.
        let line = "process didn't exit successfully: `rustc …` (signal: 9, SIGKILL: kill)";
        assert_eq!(wrapped_cpu_capability_signal(101, line), None);
    }

    #[test]
    fn ordinary_build_error_output_does_not_classify() {
        let output = "error[E0308]: mismatched types\n --> src/main.rs:1:1";
        assert_eq!(wrapped_cpu_capability_signal(101, output), None);
    }
}
