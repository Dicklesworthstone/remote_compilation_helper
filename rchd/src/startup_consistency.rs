//! Daemon startup self-consistency verification
//! (bd-session-history-remediation-ocv9i.3.2).
//!
//! Session history showed silent drift between the *three* places a socket
//! path and hook command live — the daemon's bound socket, the `rch`
//! config/CLI socket the hook uses to reach it, and the actual installed
//! Claude Code PreToolUse hook. When these disagree the hook fails to reach a
//! live daemon and every build silently falls back to local with no obvious
//! cause.
//!
//! On startup `rchd` runs a read-only consistency probe over these surfaces and
//! reports drift as structured `rch::daemon::startup_consistency` tracing
//! events (the surface doctor diagnostics and log shipping consume). It
//! **never** rewrites operator-owned config — detection and reporting only;
//! any repair is gated behind explicit doctor/`--fix` policy in a sibling bead.
//!
//! The check is split into a pure [`check_startup_consistency`] over gathered
//! [`ConsistencyInputs`] (unit-tested against fixtures, no filesystem or real
//! `~/.claude` access) and a thin [`gather_and_log`] wrapper called from
//! `main`.

use std::path::PathBuf;

use serde::Serialize;
use tracing::{info, warn};

/// Outcome of a single consistency check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsistencyStatus {
    /// Surfaces agree / coherent.
    Ok,
    /// Surfaces disagree — operator action likely needed.
    Drift,
    /// Could not be determined (e.g. unresolved `$HOME`); not a failure.
    Unknown,
}

impl ConsistencyStatus {
    fn as_str(self) -> &'static str {
        match self {
            ConsistencyStatus::Ok => "ok",
            ConsistencyStatus::Drift => "drift",
            ConsistencyStatus::Unknown => "unknown",
        }
    }
}

/// One named consistency finding, shaped to the validation-contract log fields
/// (`check`, `status`, `reason_code`, `detail`).
#[derive(Debug, Clone, Serialize)]
pub struct ConsistencyFinding {
    /// Stable check name.
    pub check: &'static str,
    /// Outcome.
    pub status: ConsistencyStatus,
    /// Stable reason code for machine consumers.
    pub reason_code: &'static str,
    /// Human-readable detail.
    pub detail: String,
}

impl ConsistencyFinding {
    fn ok(check: &'static str, reason_code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            check,
            status: ConsistencyStatus::Ok,
            reason_code,
            detail: detail.into(),
        }
    }

    fn drift(check: &'static str, reason_code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            check,
            status: ConsistencyStatus::Drift,
            reason_code,
            detail: detail.into(),
        }
    }

    fn unknown(check: &'static str, reason_code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            check,
            status: ConsistencyStatus::Unknown,
            reason_code,
            detail: detail.into(),
        }
    }
}

/// Full startup consistency report.
#[derive(Debug, Clone, Serialize)]
pub struct StartupConsistencyReport {
    pub findings: Vec<ConsistencyFinding>,
}

impl StartupConsistencyReport {
    /// Number of findings that indicate genuine drift.
    pub fn drift_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.status == ConsistencyStatus::Drift)
            .count()
    }

    /// Whether any surface drifted.
    pub fn has_drift(&self) -> bool {
        self.drift_count() > 0
    }
}

/// Inputs gathered at startup. Kept as a plain struct so the pure check can be
/// exercised against fixtures with no filesystem or `~/.claude` access.
#[derive(Debug, Clone)]
pub struct ConsistencyInputs {
    /// The socket the daemon is binding (`--socket`).
    pub daemon_socket: PathBuf,
    /// The socket the hook/CLI will use to reach the daemon
    /// (`rch` config `general.socket_path`), if configured.
    pub hook_config_socket: Option<PathBuf>,
    /// The canonical default socket path.
    pub canonical_socket: PathBuf,
    /// The installed Claude Code PreToolUse `rch` hook command, if any.
    pub installed_hook_command: Option<String>,
    /// Path of the currently running daemon executable, if known.
    pub current_exe: Option<PathBuf>,
    /// The current user's home directory, if resolvable.
    pub home_dir: Option<PathBuf>,
}

/// First whitespace-separated token of a command line (the program path).
fn command_program(cmd: &str) -> &str {
    cmd.split_whitespace().next().unwrap_or(cmd)
}

/// Pure startup consistency check. No filesystem access — operates entirely on
/// the gathered [`ConsistencyInputs`].
pub fn check_startup_consistency(inputs: &ConsistencyInputs) -> StartupConsistencyReport {
    let mut findings = Vec::new();

    // 1. Is the PreToolUse hook installed at all?
    match &inputs.installed_hook_command {
        None => {
            findings.push(ConsistencyFinding::drift(
                "hook_installed",
                "hook_not_installed",
                "no rch PreToolUse hook found in Claude Code settings; builds will not offload",
            ));
        }
        Some(cmd) => {
            findings.push(ConsistencyFinding::ok(
                "hook_installed",
                "hook_present",
                format!("rch PreToolUse hook present: {cmd}"),
            ));

            // 2. Does the hook point at the same rch install as this daemon's
            //    sibling? Only meaningful when the hook uses an absolute path
            //    and we know our own exe location.
            let program = command_program(cmd);
            let program_path = PathBuf::from(program);
            if program_path.is_absolute() {
                match inputs
                    .current_exe
                    .as_ref()
                    .and_then(|exe| exe.parent())
                    .map(|dir| dir.join("rch"))
                {
                    Some(expected) if expected == program_path => {
                        findings.push(ConsistencyFinding::ok(
                            "hook_binary",
                            "hook_binary_coherent",
                            format!("hook rch matches daemon sibling: {}", expected.display()),
                        ));
                    }
                    Some(expected) => {
                        findings.push(ConsistencyFinding::drift(
                            "hook_binary",
                            "hook_binary_mismatch",
                            format!(
                                "hook invokes {} but the running daemon's sibling rch is {}",
                                program_path.display(),
                                expected.display()
                            ),
                        ));
                    }
                    None => {
                        findings.push(ConsistencyFinding::unknown(
                            "hook_binary",
                            "daemon_exe_unknown",
                            format!(
                                "cannot compare hook rch {} — daemon executable path unknown",
                                program_path.display()
                            ),
                        ));
                    }
                }
            } else {
                findings.push(ConsistencyFinding::ok(
                    "hook_binary",
                    "hook_binary_path_resolved",
                    format!("hook invokes PATH-resolved rch ({program})"),
                ));
            }
        }
    }

    // 3. Do the daemon and the hook/CLI agree on the socket path? This is the
    //    cardinal "hook can't reach the daemon" drift.
    match &inputs.hook_config_socket {
        Some(hook_socket) if *hook_socket == inputs.daemon_socket => {
            findings.push(ConsistencyFinding::ok(
                "socket_consistency",
                "socket_consistent",
                format!("daemon and hook agree on socket {}", hook_socket.display()),
            ));
        }
        Some(hook_socket) => {
            findings.push(ConsistencyFinding::drift(
                "socket_consistency",
                "socket_mismatch",
                format!(
                    "daemon binds {} but hook/config expects {}; hook cannot reach the daemon",
                    inputs.daemon_socket.display(),
                    hook_socket.display()
                ),
            ));
        }
        None => {
            // No explicit hook socket: it will use the canonical default. Drift
            // only if the daemon bound something other than canonical.
            if inputs.daemon_socket == inputs.canonical_socket {
                findings.push(ConsistencyFinding::ok(
                    "socket_consistency",
                    "socket_canonical",
                    format!(
                        "daemon binds the canonical socket {}",
                        inputs.canonical_socket.display()
                    ),
                ));
            } else {
                findings.push(ConsistencyFinding::drift(
                    "socket_consistency",
                    "socket_noncanonical_no_config",
                    format!(
                        "daemon binds {} but no hook socket is configured; the hook will use the \
                        canonical default {} and miss the daemon",
                        inputs.daemon_socket.display(),
                        inputs.canonical_socket.display()
                    ),
                ));
            }
        }
    }

    // 4. User/path coherence: can we resolve the current user's home, and is
    //    the daemon socket an absolute path?
    match &inputs.home_dir {
        None => findings.push(ConsistencyFinding::unknown(
            "user_path",
            "home_unresolved",
            "current user's home directory could not be resolved",
        )),
        Some(home) if !inputs.daemon_socket.is_absolute() => {
            findings.push(ConsistencyFinding::drift(
                "user_path",
                "socket_not_absolute",
                format!(
                    "daemon socket {} is not an absolute path (home={})",
                    inputs.daemon_socket.display(),
                    home.display()
                ),
            ))
        }
        Some(home) => findings.push(ConsistencyFinding::ok(
            "user_path",
            "user_path_coherent",
            format!(
                "home resolved ({}) and socket path is absolute",
                home.display()
            ),
        )),
    }

    StartupConsistencyReport { findings }
}

/// Emit the report as structured tracing events and a drift summary. Reporting
/// only — never mutates operator config.
pub fn log_startup_consistency(report: &StartupConsistencyReport) {
    for f in &report.findings {
        info!(
            target: "rch::daemon::startup_consistency",
            event = "daemon.startup.consistency",
            check = f.check,
            status = f.status.as_str(),
            reason_code = f.reason_code,
            detail = %f.detail,
            "daemon.startup.consistency",
        );
    }
    if report.has_drift() {
        warn!(
            target: "rch::daemon::startup_consistency",
            event = "daemon.startup.consistency.drift",
            drift_count = report.drift_count(),
            "daemon startup detected hook/socket/path drift; not rewriting operator-owned config \
            (run `rch doctor` to inspect, `--fix` to remediate)",
        );
    }
}

/// Gather live inputs and emit the startup consistency report. Read-only.
pub fn gather_and_log(
    daemon_socket: PathBuf,
    hook_config_socket: Option<PathBuf>,
) -> StartupConsistencyReport {
    let inputs = ConsistencyInputs {
        daemon_socket,
        hook_config_socket,
        canonical_socket: PathBuf::from(rch_common::default_socket_path()),
        installed_hook_command: rch_common::hooks::installed_rch_hook_command(),
        current_exe: std::env::current_exe().ok(),
        home_dir: std::env::var_os("HOME").map(PathBuf::from),
    };
    let report = check_startup_consistency(&inputs);
    log_startup_consistency(&report);
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_inputs() -> ConsistencyInputs {
        ConsistencyInputs {
            daemon_socket: PathBuf::from("/home/u/.cache/rch/rch.sock"),
            hook_config_socket: Some(PathBuf::from("/home/u/.cache/rch/rch.sock")),
            canonical_socket: PathBuf::from("/home/u/.cache/rch/rch.sock"),
            installed_hook_command: Some("/home/u/.local/bin/rch".to_string()),
            current_exe: Some(PathBuf::from("/home/u/.local/bin/rchd")),
            home_dir: Some(PathBuf::from("/home/u")),
        }
    }

    fn finding<'a>(report: &'a StartupConsistencyReport, check: &str) -> &'a ConsistencyFinding {
        report
            .findings
            .iter()
            .find(|f| f.check == check)
            .unwrap_or_else(|| panic!("missing finding for check {check}"))
    }

    #[test]
    fn coherent_setup_has_no_drift() {
        let report = check_startup_consistency(&base_inputs());
        assert!(
            !report.has_drift(),
            "coherent setup must not drift: {report:?}"
        );
        assert_eq!(
            finding(&report, "hook_installed").status,
            ConsistencyStatus::Ok
        );
        assert_eq!(
            finding(&report, "hook_binary").status,
            ConsistencyStatus::Ok
        );
        assert_eq!(
            finding(&report, "socket_consistency").status,
            ConsistencyStatus::Ok
        );
        assert_eq!(finding(&report, "user_path").status, ConsistencyStatus::Ok);
    }

    #[test]
    fn missing_hook_is_drift() {
        let mut inputs = base_inputs();
        inputs.installed_hook_command = None;
        let report = check_startup_consistency(&inputs);
        let f = finding(&report, "hook_installed");
        assert_eq!(f.status, ConsistencyStatus::Drift);
        assert_eq!(f.reason_code, "hook_not_installed");
        assert!(report.has_drift());
    }

    #[test]
    fn hook_pointing_at_a_different_rch_install_is_drift() {
        let mut inputs = base_inputs();
        inputs.installed_hook_command = Some("/opt/other/bin/rch".to_string());
        let report = check_startup_consistency(&inputs);
        let f = finding(&report, "hook_binary");
        assert_eq!(f.status, ConsistencyStatus::Drift);
        assert_eq!(f.reason_code, "hook_binary_mismatch");
    }

    #[test]
    fn path_resolved_hook_is_ok_not_drift() {
        let mut inputs = base_inputs();
        inputs.installed_hook_command = Some("rch".to_string());
        let report = check_startup_consistency(&inputs);
        let f = finding(&report, "hook_binary");
        assert_eq!(f.status, ConsistencyStatus::Ok);
        assert_eq!(f.reason_code, "hook_binary_path_resolved");
    }

    #[test]
    fn daemon_and_hook_socket_mismatch_is_drift() {
        let mut inputs = base_inputs();
        inputs.hook_config_socket = Some(PathBuf::from("/tmp/other.sock"));
        let report = check_startup_consistency(&inputs);
        let f = finding(&report, "socket_consistency");
        assert_eq!(f.status, ConsistencyStatus::Drift);
        assert_eq!(f.reason_code, "socket_mismatch");
    }

    #[test]
    fn noncanonical_socket_without_hook_config_is_drift() {
        let mut inputs = base_inputs();
        inputs.hook_config_socket = None;
        inputs.daemon_socket = PathBuf::from("/run/custom/rch.sock");
        // canonical stays at the base home path => mismatch.
        let report = check_startup_consistency(&inputs);
        let f = finding(&report, "socket_consistency");
        assert_eq!(f.status, ConsistencyStatus::Drift);
        assert_eq!(f.reason_code, "socket_noncanonical_no_config");
    }

    #[test]
    fn canonical_socket_without_hook_config_is_ok() {
        let mut inputs = base_inputs();
        inputs.hook_config_socket = None;
        // daemon_socket == canonical_socket in base_inputs.
        let report = check_startup_consistency(&inputs);
        assert_eq!(
            finding(&report, "socket_consistency").reason_code,
            "socket_canonical"
        );
        assert!(!report.has_drift());
    }

    #[test]
    fn unresolved_home_is_unknown_not_drift() {
        let mut inputs = base_inputs();
        inputs.home_dir = None;
        let report = check_startup_consistency(&inputs);
        let f = finding(&report, "user_path");
        assert_eq!(f.status, ConsistencyStatus::Unknown);
        // Unknown must not count as drift.
        assert!(!report.has_drift());
    }

    #[test]
    fn relative_socket_path_is_drift() {
        let mut inputs = base_inputs();
        inputs.daemon_socket = PathBuf::from("rch.sock");
        inputs.hook_config_socket = Some(PathBuf::from("rch.sock"));
        let report = check_startup_consistency(&inputs);
        let f = finding(&report, "user_path");
        assert_eq!(f.status, ConsistencyStatus::Drift);
        assert_eq!(f.reason_code, "socket_not_absolute");
    }

    #[test]
    fn drift_count_aggregates_multiple_findings() {
        let mut inputs = base_inputs();
        inputs.installed_hook_command = None; // drift 1
        inputs.hook_config_socket = Some(PathBuf::from("/tmp/x.sock")); // drift 2
        let report = check_startup_consistency(&inputs);
        assert!(report.drift_count() >= 2, "expected >=2 drifts: {report:?}");
    }
}
