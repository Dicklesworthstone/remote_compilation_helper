//! `rabsd doctor` (bead S7): a pure, testable health assessment of a
//! RABS installation. Every check is a function from OBSERVED FACTS to
//! a typed verdict — the CLI gathers the facts (socket stat, breaker
//! file, state dir, worker capability) and this module decides. That
//! split keeps the doctor unit-testable without a live daemon and keeps
//! remediation advice honest: a check reports what it saw and what to
//! do, never a bare red X.

/// One check's severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// All good.
    Ok,
    /// Degraded but functional (fail-open still holds).
    Warn,
    /// Broken; RABS will not function (but builds still pass locally —
    /// RABS is fail-open by construction).
    Fail,
}

/// One check result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    /// Stable check id.
    pub id: &'static str,
    /// Severity.
    pub severity: Severity,
    /// What was observed.
    pub detail: String,
    /// What to do (empty when Ok).
    pub remediation: String,
}

impl Check {
    fn ok(id: &'static str, detail: impl Into<String>) -> Self {
        Self {
            id,
            severity: Severity::Ok,
            detail: detail.into(),
            remediation: String::new(),
        }
    }
    fn warn(id: &'static str, detail: impl Into<String>, fix: impl Into<String>) -> Self {
        Self {
            id,
            severity: Severity::Warn,
            detail: detail.into(),
            remediation: fix.into(),
        }
    }
    fn fail(id: &'static str, detail: impl Into<String>, fix: impl Into<String>) -> Self {
        Self {
            id,
            severity: Severity::Fail,
            detail: detail.into(),
            remediation: fix.into(),
        }
    }
}

/// Observed facts about the installation (the CLI gathers these).
#[derive(Debug, Clone)]
pub struct DoctorFacts {
    /// Socket path exists.
    pub socket_present: bool,
    /// Socket mode (0o777-masked) if present.
    pub socket_mode: Option<u32>,
    /// A live daemon answered a status probe on the socket.
    pub daemon_responsive: bool,
    /// Breaker state file present.
    pub breaker_present: bool,
    /// Breaker parsed as OPEN (edge believed dead).
    pub breaker_open: bool,
    /// State dir (shadow index/receipts) exists and is writable.
    pub state_dir_writable: bool,
    /// This host can run the canonical namespace (bwrap probe).
    pub canonical_capable: bool,
    /// Missing isolation facets (empty when capable).
    pub missing_facets: Vec<String>,
}

/// Run the doctor over observed facts.
#[must_use]
pub fn diagnose(facts: &DoctorFacts) -> Vec<Check> {
    let mut checks = Vec::new();

    // Socket + daemon liveness.
    match (facts.socket_present, facts.daemon_responsive) {
        (true, true) => checks.push(Check::ok("daemon", "rabsd responsive on its socket")),
        (true, false) => checks.push(Check::warn(
            "daemon",
            "socket present but no daemon answered",
            "start rabsd (a stale socket is taken over via liveness probe on next boot)",
        )),
        (false, _) => checks.push(Check::warn(
            "daemon",
            "no socket — daemon not running",
            "start rabsd; builds pass through locally until it is up (fail-open)",
        )),
    }

    // Socket permissions (only when present).
    if let Some(mode) = facts.socket_mode {
        if mode == 0o600 {
            checks.push(Check::ok("socket-perms", "socket is 0600"));
        } else {
            checks.push(Check::fail(
                "socket-perms",
                format!("socket mode is {mode:o}, expected 0600"),
                "remove the socket and restart rabsd (it re-creates it 0600)",
            ));
        }
    }

    // Breaker file.
    match (facts.breaker_present, facts.breaker_open) {
        (false, _) => checks.push(Check::ok("breaker", "no breaker file (fresh/closed)")),
        (true, false) => checks.push(Check::ok("breaker", "breaker closed")),
        (true, true) => checks.push(Check::warn(
            "breaker",
            "breaker OPEN — wrappers are skipping the daemon",
            "confirm rabsd is healthy; the breaker self-heals on the next successful probe",
        )),
    }

    // State dir.
    if facts.state_dir_writable {
        checks.push(Check::ok("state-dir", "shadow state dir writable"));
    } else {
        checks.push(Check::fail(
            "state-dir",
            "shadow state dir missing or not writable",
            "create the state dir (RABS_STATE_DIR) and ensure the daemon user owns it",
        ));
    }

    // Worker capability (advisory: an edge-only host needs no bwrap).
    if facts.canonical_capable {
        checks.push(Check::ok(
            "canonical",
            "host can run the canonical namespace",
        ));
    } else {
        checks.push(Check::warn(
            "canonical",
            format!(
                "canonical namespace unavailable (missing: {})",
                facts.missing_facets.join(", ")
            ),
            "edge-only hosts need no bwrap; WORKER hosts must install it (rabs-wkr refuses non-canonical hosts)",
        ));
    }

    checks
}

/// The overall verdict (worst severity present).
#[must_use]
pub fn overall(checks: &[Check]) -> Severity {
    if checks.iter().any(|c| c.severity == Severity::Fail) {
        Severity::Fail
    } else if checks.iter().any(|c| c.severity == Severity::Warn) {
        Severity::Warn
    } else {
        Severity::Ok
    }
}

/// Render the report as NDJSON (one check per line + a summary line).
#[must_use]
pub fn to_ndjson(checks: &[Check]) -> String {
    let severity_str = |s: Severity| match s {
        Severity::Ok => "ok",
        Severity::Warn => "warn",
        Severity::Fail => "fail",
    };
    let mut lines: Vec<String> = checks
        .iter()
        .map(|c| {
            format!(
                "{{\"kind\":\"doctor-check\",\"id\":\"{}\",\"severity\":\"{}\",\"detail\":\"{}\",\"remediation\":\"{}\"}}",
                c.id,
                severity_str(c.severity),
                c.detail.replace('"', "'"),
                c.remediation.replace('"', "'"),
            )
        })
        .collect();
    lines.push(format!(
        "{{\"kind\":\"doctor-summary\",\"overall\":\"{}\",\"checks\":{}}}",
        severity_str(overall(checks)),
        checks.len(),
    ));
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy() -> DoctorFacts {
        DoctorFacts {
            socket_present: true,
            socket_mode: Some(0o600),
            daemon_responsive: true,
            breaker_present: false,
            breaker_open: false,
            state_dir_writable: true,
            canonical_capable: true,
            missing_facets: vec![],
        }
    }

    #[test]
    fn a_healthy_install_is_all_ok() {
        let checks = diagnose(&healthy());
        assert_eq!(overall(&checks), Severity::Ok);
        assert!(checks.iter().all(|c| c.severity == Severity::Ok));
        assert!(checks.iter().any(|c| c.id == "daemon"));
    }

    #[test]
    fn no_daemon_is_a_warn_not_a_fail_fail_open() {
        // RABS is fail-open: a dead daemon degrades, it does not break.
        let mut facts = healthy();
        facts.socket_present = false;
        facts.daemon_responsive = false;
        facts.socket_mode = None;
        let checks = diagnose(&facts);
        assert_eq!(overall(&checks), Severity::Warn);
        let daemon = checks.iter().find(|c| c.id == "daemon").unwrap();
        assert_eq!(daemon.severity, Severity::Warn);
        assert!(daemon.remediation.contains("fail-open"));
    }

    #[test]
    fn wrong_socket_perms_and_bad_state_dir_are_fails() {
        let mut facts = healthy();
        facts.socket_mode = Some(0o666);
        facts.state_dir_writable = false;
        let checks = diagnose(&facts);
        assert_eq!(overall(&checks), Severity::Fail);
        assert_eq!(
            checks
                .iter()
                .find(|c| c.id == "socket-perms")
                .unwrap()
                .severity,
            Severity::Fail
        );
        assert_eq!(
            checks
                .iter()
                .find(|c| c.id == "state-dir")
                .unwrap()
                .severity,
            Severity::Fail
        );
    }

    #[test]
    fn open_breaker_and_missing_canonical_are_warns_with_advice() {
        let mut facts = healthy();
        facts.breaker_present = true;
        facts.breaker_open = true;
        facts.canonical_capable = false;
        facts.missing_facets = vec!["bubblewrap".into()];
        let checks = diagnose(&facts);
        assert_eq!(overall(&checks), Severity::Warn);
        let canonical = checks.iter().find(|c| c.id == "canonical").unwrap();
        assert!(canonical.detail.contains("bubblewrap"));
        assert!(canonical.remediation.contains("rabs-wkr refuses"));
    }

    #[test]
    fn ndjson_is_line_per_check_plus_summary() {
        let checks = diagnose(&healthy());
        let ndjson = to_ndjson(&checks);
        assert_eq!(ndjson.lines().count(), checks.len() + 1);
        assert!(ndjson.lines().last().unwrap().contains("doctor-summary"));
        assert!(ndjson.contains("\"overall\":\"ok\""));
    }
}
