//! UX regression suite for human-facing reliability diagnostics (bd-1qhj)
//!
//! Golden-snapshot-style tests covering human-readable outputs for:
//!   - healthy, degraded, quarantined, fail-open, compatibility-mismatch,
//!     and rollback/canary-gate scenarios
//!   - Each non-healthy output must contain: clear diagnosis summary,
//!     reason code(s), concrete remediation command(s), and explicit
//!     risk/safety note when destructive actions are involved
//!   - Deterministic ordering and wording constraints
//!   - Redaction checks (no secrets/PII in outputs)
//!   - Parity between worker-specific and cross-worker narratives

use rch_common::e2e::logging::{LogLevel, LogSource, TestLoggerBuilder};
use rch_common::util::mask_sensitive_command;
use serde::{Deserialize, Serialize};

// ===========================================================================
// UX output model types (mirrors the status surface contract)
// ===========================================================================

const UX_REGRESSION_SCHEMA_VERSION: &str = "1.0.0";

/// System posture labels used in human-facing output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PostureLabel {
    RemoteReady,
    Degraded,
    LocalOnly,
}

impl PostureLabel {
    fn description(&self) -> &'static str {
        match self {
            Self::RemoteReady => "All workers healthy, remote compilation available",
            Self::Degraded => "Some workers unhealthy, partial remote capability",
            Self::LocalOnly => "No workers available, builds run locally (fail-open)",
        }
    }

    fn is_healthy(&self) -> bool {
        matches!(self, Self::RemoteReady)
    }
}

/// Severity level for remediation hints.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum HintSeverity {
    Critical,
    Warning,
    Info,
}

impl HintSeverity {
    fn icon(&self) -> &'static str {
        match self {
            Self::Critical => "!!",
            Self::Warning => "!",
            Self::Info => "i",
        }
    }
}

/// A structured remediation hint for human-facing output.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct UxRemediationHint {
    reason_code: String,
    severity: HintSeverity,
    message: String,
    suggested_action: String,
    worker_id: Option<String>,
    /// Whether this hint involves a destructive/unsafe action.
    involves_destructive_action: bool,
    /// Risk note shown when destructive action is involved.
    risk_note: Option<String>,
}

/// Simulated worker state for building test scenarios.
#[derive(Debug, Clone)]
struct SimWorker {
    id: String,
    host: String,
    user: String,
    status: String,
    circuit_state: String,
    consecutive_failures: u32,
    recovery_in_secs: Option<u64>,
    pressure_state: Option<String>,
    pressure_disk_free_gb: Option<f64>,
    convergence_drift_state: String,
    missing_repos: Vec<String>,
    #[allow(dead_code)]
    failure_history: Vec<bool>,
}

/// A rollout flag snapshot for posture checks.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RolloutFlag {
    name: String,
    state: String,
    subsystem: String,
}

/// A full UX scenario with rendered narrative.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct UxScenario {
    name: String,
    posture: PostureLabel,
    posture_description: String,
    worker_summary: String,
    hints: Vec<UxRemediationHint>,
    convergence_summary: Option<String>,
    narrative_lines: Vec<String>,
}

/// Golden snapshot of a UX scenario output.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct UxGoldenSnapshot {
    schema_version: String,
    scenario_name: String,
    posture: PostureLabel,
    hint_count: usize,
    critical_count: usize,
    warning_count: usize,
    info_count: usize,
    has_destructive_hints: bool,
    all_destructive_have_risk_notes: bool,
    all_non_healthy_have_reason_codes: bool,
    all_non_healthy_have_remediation: bool,
    narrative_deterministic: bool,
    narrative_line_count: usize,
    redaction_clean: bool,
}

// ===========================================================================
// Scenario builders
// ===========================================================================

fn healthy_workers() -> Vec<SimWorker> {
    vec![
        SimWorker {
            id: "w1".into(),
            host: "worker1.example.com".into(),
            user: "rch".into(),
            status: "healthy".into(),
            circuit_state: "closed".into(),
            consecutive_failures: 0,
            recovery_in_secs: None,
            pressure_state: Some("healthy".into()),
            pressure_disk_free_gb: Some(100.0),
            convergence_drift_state: "ready".into(),
            missing_repos: vec![],
            failure_history: vec![true, true, true, true, true],
        },
        SimWorker {
            id: "w2".into(),
            host: "worker2.example.com".into(),
            user: "rch".into(),
            status: "healthy".into(),
            circuit_state: "closed".into(),
            consecutive_failures: 0,
            recovery_in_secs: None,
            pressure_state: Some("healthy".into()),
            pressure_disk_free_gb: Some(200.0),
            convergence_drift_state: "ready".into(),
            missing_repos: vec![],
            failure_history: vec![true, true, true, true, true],
        },
    ]
}

fn degraded_workers() -> Vec<SimWorker> {
    vec![
        SimWorker {
            id: "w1".into(),
            host: "worker1.example.com".into(),
            user: "rch".into(),
            status: "healthy".into(),
            circuit_state: "closed".into(),
            consecutive_failures: 0,
            recovery_in_secs: None,
            pressure_state: Some("warning".into()),
            pressure_disk_free_gb: Some(18.0),
            convergence_drift_state: "drifting".into(),
            missing_repos: vec!["projectA".into()],
            failure_history: vec![true, true, false, true, true],
        },
        SimWorker {
            id: "w2".into(),
            host: "worker2.example.com".into(),
            user: "rch".into(),
            status: "unhealthy".into(),
            circuit_state: "half_open".into(),
            consecutive_failures: 2,
            recovery_in_secs: Some(15),
            pressure_state: Some("healthy".into()),
            pressure_disk_free_gb: Some(80.0),
            convergence_drift_state: "ready".into(),
            missing_repos: vec![],
            failure_history: vec![false, false, true, true, true],
        },
    ]
}

fn quarantined_workers() -> Vec<SimWorker> {
    vec![
        SimWorker {
            id: "w1".into(),
            host: "worker1.example.com".into(),
            user: "rch".into(),
            status: "unhealthy".into(),
            circuit_state: "open".into(),
            consecutive_failures: 5,
            recovery_in_secs: Some(30),
            pressure_state: Some("critical".into()),
            pressure_disk_free_gb: Some(2.5),
            convergence_drift_state: "failed".into(),
            missing_repos: vec!["projectA".into(), "projectB".into()],
            failure_history: vec![false, false, false, false, false],
        },
        SimWorker {
            id: "w2".into(),
            host: "worker2.example.com".into(),
            user: "rch".into(),
            status: "unreachable".into(),
            circuit_state: "open".into(),
            consecutive_failures: 3,
            recovery_in_secs: Some(60),
            pressure_state: None,
            pressure_disk_free_gb: None,
            convergence_drift_state: "stale".into(),
            missing_repos: vec![],
            failure_history: vec![false, false, false, true, true],
        },
    ]
}

fn fail_open_workers() -> Vec<SimWorker> {
    // All workers down → LocalOnly
    vec![]
}

fn compatibility_mismatch_workers() -> Vec<SimWorker> {
    vec![SimWorker {
        id: "w1".into(),
        host: "worker1.example.com".into(),
        user: "rch".into(),
        status: "healthy".into(),
        circuit_state: "closed".into(),
        consecutive_failures: 0,
        recovery_in_secs: None,
        pressure_state: Some("healthy".into()),
        pressure_disk_free_gb: Some(120.0),
        convergence_drift_state: "ready".into(),
        missing_repos: vec![],
        failure_history: vec![true, true, true, true, true],
    }]
}

// ===========================================================================
// Engine: generate human-facing narrative from scenario state
// ===========================================================================

fn compute_posture(workers: &[SimWorker]) -> PostureLabel {
    if workers.is_empty() {
        return PostureLabel::LocalOnly;
    }
    let healthy = workers.iter().filter(|w| w.status == "healthy").count();
    if healthy == 0 {
        PostureLabel::LocalOnly
    } else if healthy < workers.len() {
        PostureLabel::Degraded
    } else {
        PostureLabel::RemoteReady
    }
}

fn generate_worker_hints(workers: &[SimWorker]) -> Vec<UxRemediationHint> {
    let mut hints = Vec::new();

    for w in workers {
        // Circuit breaker issues
        match w.circuit_state.as_str() {
            "open" => {
                let msg = if w.consecutive_failures > 0 {
                    format!(
                        "Worker {} circuit open after {} consecutive failures",
                        w.id, w.consecutive_failures
                    )
                } else {
                    format!("Worker {} circuit open due to repeated failures", w.id)
                };
                let risk = w.recovery_in_secs.map(|s| {
                    format!(
                        "Circuit will auto-retry in {}s. Force-probing resets the cooldown timer.",
                        s
                    )
                });
                hints.push(UxRemediationHint {
                    reason_code: "circuit_open".into(),
                    severity: HintSeverity::Critical,
                    message: msg,
                    suggested_action: format!("rch workers probe {} --force", w.id),
                    worker_id: Some(w.id.clone()),
                    involves_destructive_action: false,
                    risk_note: risk,
                });
            }
            "half_open" => {
                hints.push(UxRemediationHint {
                    reason_code: "circuit_half_open".into(),
                    severity: HintSeverity::Warning,
                    message: format!("Worker {} circuit is testing recovery", w.id),
                    suggested_action: format!("rch workers probe {}", w.id),
                    worker_id: Some(w.id.clone()),
                    involves_destructive_action: false,
                    risk_note: None,
                });
            }
            _ => {}
        }

        // Pressure issues
        if let Some(ref pressure) = w.pressure_state {
            match pressure.as_str() {
                "critical" => {
                    let disk_info = w
                        .pressure_disk_free_gb
                        .map(|gb| format!(" ({:.1} GB free)", gb))
                        .unwrap_or_default();
                    hints.push(UxRemediationHint {
                        reason_code: "pressure_critical".into(),
                        severity: HintSeverity::Critical,
                        message: format!(
                            "Worker {} under critical storage pressure{}",
                            w.id, disk_info
                        ),
                        suggested_action: format!(
                            "ssh {}@{} 'cargo clean' or free disk space",
                            w.user, w.host
                        ),
                        worker_id: Some(w.id.clone()),
                        involves_destructive_action: true,
                        risk_note: Some(
                            "Disk cleanup will remove cached build artifacts. Subsequent builds may be slower."
                                .into(),
                        ),
                    });
                }
                "warning" => {
                    let disk_info = w
                        .pressure_disk_free_gb
                        .map(|gb| format!(" ({:.1} GB free)", gb))
                        .unwrap_or_default();
                    hints.push(UxRemediationHint {
                        reason_code: "pressure_warning".into(),
                        severity: HintSeverity::Warning,
                        message: format!("Worker {} storage pressure elevated{}", w.id, disk_info),
                        suggested_action: format!(
                            "ssh {}@{} 'du -sh /tmp/rch-*' to check cache sizes",
                            w.user, w.host
                        ),
                        worker_id: Some(w.id.clone()),
                        involves_destructive_action: false,
                        risk_note: None,
                    });
                }
                "telemetry_gap" => {
                    hints.push(UxRemediationHint {
                        reason_code: "pressure_telemetry_gap".into(),
                        severity: HintSeverity::Warning,
                        message: format!("Worker {} storage telemetry stale or missing", w.id),
                        suggested_action: format!("rch workers probe {}", w.id),
                        worker_id: Some(w.id.clone()),
                        involves_destructive_action: false,
                        risk_note: None,
                    });
                }
                _ => {}
            }
        }

        // Unreachable workers
        if (w.status == "unreachable" || w.status == "unhealthy") && w.circuit_state != "open" {
            hints.push(UxRemediationHint {
                reason_code: "worker_unreachable".into(),
                severity: HintSeverity::Critical,
                message: format!("Worker {} is {}", w.id, w.status),
                suggested_action: format!(
                    "ssh {}@{} 'echo ok' to verify connectivity",
                    w.user, w.host
                ),
                worker_id: Some(w.id.clone()),
                involves_destructive_action: false,
                risk_note: None,
            });
        }
    }

    hints
}

fn generate_convergence_hints(workers: &[SimWorker]) -> Vec<UxRemediationHint> {
    let mut hints = Vec::new();

    for w in workers {
        match w.convergence_drift_state.as_str() {
            "drifting" => {
                let missing = if w.missing_repos.is_empty() {
                    String::new()
                } else {
                    format!(" (missing: {})", w.missing_repos.join(", "))
                };
                hints.push(UxRemediationHint {
                    reason_code: "convergence_drifting".into(),
                    severity: HintSeverity::Warning,
                    message: format!("Worker {} repos drifting{}", w.id, missing),
                    suggested_action: format!("rch repo-convergence repair --worker {}", w.id),
                    worker_id: Some(w.id.clone()),
                    involves_destructive_action: false,
                    risk_note: None,
                });
            }
            "failed" => {
                hints.push(UxRemediationHint {
                    reason_code: "convergence_failed".into(),
                    severity: HintSeverity::Critical,
                    message: format!("Worker {} convergence failed", w.id),
                    suggested_action: format!(
                        "rch repo-convergence repair --worker {} --force",
                        w.id
                    ),
                    worker_id: Some(w.id.clone()),
                    involves_destructive_action: true,
                    risk_note: Some(
                        "Force repair may re-clone repositories, discarding local worker changes."
                            .into(),
                    ),
                });
            }
            "stale" => {
                hints.push(UxRemediationHint {
                    reason_code: "convergence_stale".into(),
                    severity: HintSeverity::Info,
                    message: format!("Worker {} convergence data stale", w.id),
                    suggested_action: format!("rch repo-convergence dry-run --worker {}", w.id),
                    worker_id: Some(w.id.clone()),
                    involves_destructive_action: false,
                    risk_note: None,
                });
            }
            _ => {} // "ready" and "converging" are fine
        }
    }

    hints
}

fn generate_compatibility_hints(
    expected_schema: &str,
    actual_schema: &str,
    component: &str,
) -> Vec<UxRemediationHint> {
    let mut hints = Vec::new();

    if expected_schema != actual_schema {
        let expected_major: u32 = expected_schema
            .split('.')
            .next()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let actual_major: u32 = actual_schema
            .split('.')
            .next()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let (severity, risk) = if expected_major != actual_major {
            (
                HintSeverity::Critical,
                Some(format!(
                    "Major version mismatch for {}. Update may require migration steps.",
                    component
                )),
            )
        } else {
            (HintSeverity::Warning, None)
        };

        hints.push(UxRemediationHint {
            reason_code: "schema_mismatch".into(),
            severity,
            message: format!(
                "{} schema version mismatch: expected {} but found {}",
                component, expected_schema, actual_schema
            ),
            suggested_action: format!(
                "Update {} adapter to match schema v{}",
                component, expected_schema
            ),
            worker_id: None,
            involves_destructive_action: expected_major != actual_major,
            risk_note: risk,
        });
    }

    hints
}

fn generate_rollout_hints(flags: &[RolloutFlag]) -> Vec<UxRemediationHint> {
    let mut hints = Vec::new();

    let all_disabled = flags.iter().all(|f| f.state == "disabled");
    if all_disabled && !flags.is_empty() {
        hints.push(UxRemediationHint {
            reason_code: "rollout_all_disabled".into(),
            severity: HintSeverity::Warning,
            message: "All reliability feature flags are disabled".into(),
            suggested_action: "Review rollout plan and enable flags incrementally".into(),
            worker_id: None,
            involves_destructive_action: false,
            risk_note: None,
        });
    }

    for f in flags {
        match f.state.as_str() {
            "canary" => {
                hints.push(UxRemediationHint {
                    reason_code: "rollout_canary_active".into(),
                    severity: HintSeverity::Info,
                    message: format!("Flag '{}' is in canary mode for {}", f.name, f.subsystem),
                    suggested_action: format!(
                        "Monitor canary metrics before promoting '{}'",
                        f.name
                    ),
                    worker_id: None,
                    involves_destructive_action: false,
                    risk_note: None,
                });
            }
            "dry_run" => {
                hints.push(UxRemediationHint {
                    reason_code: "rollout_dry_run".into(),
                    severity: HintSeverity::Info,
                    message: format!(
                        "Flag '{}' running in dry-run mode for {}",
                        f.name, f.subsystem
                    ),
                    suggested_action: format!(
                        "Check dry-run logs for '{}' before enabling",
                        f.name
                    ),
                    worker_id: None,
                    involves_destructive_action: false,
                    risk_note: None,
                });
            }
            _ => {}
        }
    }

    hints
}

fn render_narrative(scenario: &UxScenario) -> Vec<String> {
    let mut lines = Vec::new();

    // Posture line
    lines.push(format!(
        "System Posture: {} — {}",
        match &scenario.posture {
            PostureLabel::RemoteReady => "REMOTE-READY",
            PostureLabel::Degraded => "DEGRADED",
            PostureLabel::LocalOnly => "LOCAL-ONLY",
        },
        scenario.posture_description
    ));

    // Worker summary
    lines.push(scenario.worker_summary.clone());

    // Convergence summary
    if let Some(ref cs) = scenario.convergence_summary {
        lines.push(cs.clone());
    }

    // Remediation section
    if !scenario.hints.is_empty() {
        lines.push(String::new()); // blank separator
        lines.push("Remediation Hints:".into());

        // Sort by severity (critical first), then by reason_code for determinism
        let mut sorted_hints = scenario.hints.clone();
        sorted_hints.sort_by(|a, b| {
            a.severity
                .cmp(&b.severity)
                .then_with(|| a.reason_code.cmp(&b.reason_code))
        });

        for hint in &sorted_hints {
            lines.push(format!(
                "  [{}] [{}] {}",
                hint.severity.icon(),
                hint.reason_code,
                hint.message
            ));
            lines.push(format!("       Fix: {}", hint.suggested_action));
            if let Some(ref note) = hint.risk_note {
                lines.push(format!("       Risk: {}", note));
            }
        }
    }

    lines
}

fn build_scenario(
    name: &str,
    workers: &[SimWorker],
    extra_hints: Vec<UxRemediationHint>,
) -> UxScenario {
    let posture = compute_posture(workers);
    let posture_description = posture.description().to_string();

    let healthy_count = workers.iter().filter(|w| w.status == "healthy").count();
    let worker_summary = if workers.is_empty() {
        "Workers: none configured".into()
    } else {
        format!("Workers: {}/{} healthy", healthy_count, workers.len())
    };

    let conv_ready = workers
        .iter()
        .filter(|w| w.convergence_drift_state == "ready")
        .count();
    let convergence_summary = if workers.is_empty() {
        None
    } else {
        Some(format!(
            "Convergence: {}/{} ready",
            conv_ready,
            workers.len()
        ))
    };

    let mut hints = generate_worker_hints(workers);
    hints.extend(generate_convergence_hints(workers));
    hints.extend(extra_hints);

    let mut scenario = UxScenario {
        name: name.into(),
        posture,
        posture_description,
        worker_summary,
        hints,
        convergence_summary,
        narrative_lines: vec![],
    };
    scenario.narrative_lines = render_narrative(&scenario);
    scenario
}

fn build_golden_snapshot(scenario: &UxScenario) -> UxGoldenSnapshot {
    let critical_count = scenario
        .hints
        .iter()
        .filter(|h| h.severity == HintSeverity::Critical)
        .count();
    let warning_count = scenario
        .hints
        .iter()
        .filter(|h| h.severity == HintSeverity::Warning)
        .count();
    let info_count = scenario
        .hints
        .iter()
        .filter(|h| h.severity == HintSeverity::Info)
        .count();

    let has_destructive = scenario.hints.iter().any(|h| h.involves_destructive_action);
    let all_destructive_noted = scenario
        .hints
        .iter()
        .filter(|h| h.involves_destructive_action)
        .all(|h| h.risk_note.is_some());

    let all_have_reason = scenario.hints.iter().all(|h| !h.reason_code.is_empty());
    let all_have_action = scenario
        .hints
        .iter()
        .all(|h| !h.suggested_action.is_empty());

    // Check for redaction issues (no raw secrets in narrative)
    let narrative_text = scenario.narrative_lines.join("\n");
    let redaction_clean = !narrative_text.contains("PRIVATE_KEY=")
        && !narrative_text.contains("SECRET=")
        && !narrative_text.contains("PASSWORD=")
        && !narrative_text.contains("TOKEN=sk-")
        && !narrative_text.contains("API_KEY=")
        && !narrative_text.contains("Bearer ");

    // Verify determinism: render twice, compare
    let second_render = render_narrative(scenario);
    let narrative_deterministic = scenario.narrative_lines == second_render;

    UxGoldenSnapshot {
        schema_version: UX_REGRESSION_SCHEMA_VERSION.into(),
        scenario_name: scenario.name.clone(),
        posture: scenario.posture.clone(),
        hint_count: scenario.hints.len(),
        critical_count,
        warning_count,
        info_count,
        has_destructive_hints: has_destructive,
        all_destructive_have_risk_notes: all_destructive_noted,
        all_non_healthy_have_reason_codes: all_have_reason,
        all_non_healthy_have_remediation: all_have_action,
        narrative_deterministic,
        narrative_line_count: scenario.narrative_lines.len(),
        redaction_clean,
    }
}

// ===========================================================================
// Tests: schema stability
// ===========================================================================

#[test]
fn e2e_ux_golden_snapshot_schema_version() {
    let scenario = build_scenario("healthy", &healthy_workers(), vec![]);
    let snapshot = build_golden_snapshot(&scenario);
    assert_eq!(snapshot.schema_version, UX_REGRESSION_SCHEMA_VERSION);
}

#[test]
fn e2e_ux_golden_snapshot_serialization_roundtrip() {
    let scenario = build_scenario("healthy", &healthy_workers(), vec![]);
    let snapshot = build_golden_snapshot(&scenario);
    let json = serde_json::to_string(&snapshot).unwrap();
    let parsed: UxGoldenSnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.scenario_name, "healthy");
    assert_eq!(parsed.posture, PostureLabel::RemoteReady);
}

#[test]
fn e2e_ux_scenario_serialization_roundtrip() {
    let scenario = build_scenario("degraded", &degraded_workers(), vec![]);
    let json = serde_json::to_string(&scenario).unwrap();
    let parsed: UxScenario = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.name, "degraded");
    assert!(!parsed.hints.is_empty());
}

// ===========================================================================
// Tests: healthy scenario
// ===========================================================================

#[test]
fn e2e_ux_healthy_posture_is_remote_ready() {
    let scenario = build_scenario("healthy", &healthy_workers(), vec![]);
    assert_eq!(scenario.posture, PostureLabel::RemoteReady);
    assert!(scenario.posture.is_healthy());
}

#[test]
fn e2e_ux_healthy_no_hints() {
    let scenario = build_scenario("healthy", &healthy_workers(), vec![]);
    assert!(
        scenario.hints.is_empty(),
        "healthy scenario should have no remediation hints"
    );
}

#[test]
fn e2e_ux_healthy_narrative_clean() {
    let scenario = build_scenario("healthy", &healthy_workers(), vec![]);
    let snapshot = build_golden_snapshot(&scenario);
    assert!(snapshot.narrative_deterministic);
    assert!(snapshot.redaction_clean);
    assert!(
        !scenario
            .narrative_lines
            .iter()
            .any(|l| l.contains("Remediation"))
    );
}

#[test]
fn e2e_ux_healthy_worker_summary() {
    let scenario = build_scenario("healthy", &healthy_workers(), vec![]);
    assert!(scenario.worker_summary.contains("2/2 healthy"));
}

// ===========================================================================
// Tests: degraded scenario
// ===========================================================================

#[test]
fn e2e_ux_degraded_posture() {
    let scenario = build_scenario("degraded", &degraded_workers(), vec![]);
    assert_eq!(scenario.posture, PostureLabel::Degraded);
}

#[test]
fn e2e_ux_degraded_has_hints() {
    let scenario = build_scenario("degraded", &degraded_workers(), vec![]);
    assert!(
        !scenario.hints.is_empty(),
        "degraded scenario must have remediation hints"
    );
}

#[test]
fn e2e_ux_degraded_all_hints_have_reason_and_action() {
    let scenario = build_scenario("degraded", &degraded_workers(), vec![]);
    let snapshot = build_golden_snapshot(&scenario);
    assert!(snapshot.all_non_healthy_have_reason_codes);
    assert!(snapshot.all_non_healthy_have_remediation);
}

#[test]
fn e2e_ux_degraded_narrative_contains_remediation_section() {
    let scenario = build_scenario("degraded", &degraded_workers(), vec![]);
    assert!(
        scenario
            .narrative_lines
            .iter()
            .any(|l| l.contains("Remediation")),
        "degraded narrative must include remediation section"
    );
}

#[test]
fn e2e_ux_degraded_narrative_deterministic() {
    let scenario = build_scenario("degraded", &degraded_workers(), vec![]);
    let snapshot = build_golden_snapshot(&scenario);
    assert!(snapshot.narrative_deterministic);
}

#[test]
fn e2e_ux_degraded_convergence_drifting_mentioned() {
    let scenario = build_scenario("degraded", &degraded_workers(), vec![]);
    let has_drift = scenario
        .hints
        .iter()
        .any(|h| h.reason_code == "convergence_drifting");
    assert!(
        has_drift,
        "degraded scenario should report convergence drifting"
    );
}

// ===========================================================================
// Tests: quarantined scenario
// ===========================================================================

#[test]
fn e2e_ux_quarantined_posture_local_only() {
    let scenario = build_scenario("quarantined", &quarantined_workers(), vec![]);
    assert_eq!(scenario.posture, PostureLabel::LocalOnly);
}

#[test]
fn e2e_ux_quarantined_has_critical_hints() {
    let scenario = build_scenario("quarantined", &quarantined_workers(), vec![]);
    let snapshot = build_golden_snapshot(&scenario);
    assert!(
        snapshot.critical_count > 0,
        "quarantined scenario must have critical-level hints"
    );
}

#[test]
fn e2e_ux_quarantined_destructive_actions_have_risk_notes() {
    let scenario = build_scenario("quarantined", &quarantined_workers(), vec![]);
    let snapshot = build_golden_snapshot(&scenario);
    assert!(
        snapshot.all_destructive_have_risk_notes,
        "all destructive remediation hints must include a risk note"
    );
}

#[test]
fn e2e_ux_quarantined_circuit_open_in_narrative() {
    let scenario = build_scenario("quarantined", &quarantined_workers(), vec![]);
    let text = scenario.narrative_lines.join("\n");
    assert!(
        text.contains("circuit_open"),
        "quarantined narrative must mention circuit_open"
    );
}

#[test]
fn e2e_ux_quarantined_pressure_critical_in_narrative() {
    let scenario = build_scenario("quarantined", &quarantined_workers(), vec![]);
    let text = scenario.narrative_lines.join("\n");
    assert!(
        text.contains("pressure_critical"),
        "quarantined narrative must mention pressure_critical"
    );
}

#[test]
fn e2e_ux_quarantined_convergence_failed_in_narrative() {
    let scenario = build_scenario("quarantined", &quarantined_workers(), vec![]);
    let text = scenario.narrative_lines.join("\n");
    assert!(
        text.contains("convergence_failed"),
        "quarantined narrative must mention convergence_failed"
    );
}

#[test]
fn e2e_ux_quarantined_risk_in_narrative() {
    let scenario = build_scenario("quarantined", &quarantined_workers(), vec![]);
    let text = scenario.narrative_lines.join("\n");
    assert!(
        text.contains("Risk:"),
        "quarantined narrative must contain Risk: notes for destructive actions"
    );
}

// ===========================================================================
// Tests: fail-open scenario
// ===========================================================================

#[test]
fn e2e_ux_fail_open_posture() {
    let scenario = build_scenario("fail-open", &fail_open_workers(), vec![]);
    assert_eq!(scenario.posture, PostureLabel::LocalOnly);
}

#[test]
fn e2e_ux_fail_open_description_mentions_local() {
    let scenario = build_scenario("fail-open", &fail_open_workers(), vec![]);
    assert!(
        scenario.posture_description.contains("locally"),
        "fail-open description should mention local builds"
    );
}

#[test]
fn e2e_ux_fail_open_worker_summary_none() {
    let scenario = build_scenario("fail-open", &fail_open_workers(), vec![]);
    assert!(scenario.worker_summary.contains("none"));
}

#[test]
fn e2e_ux_fail_open_no_convergence() {
    let scenario = build_scenario("fail-open", &fail_open_workers(), vec![]);
    assert!(scenario.convergence_summary.is_none());
}

// ===========================================================================
// Tests: compatibility mismatch scenario
// ===========================================================================

#[test]
fn e2e_ux_compat_mismatch_generates_hint() {
    let mismatch_hints = generate_compatibility_hints("2.0.0", "1.0.0", "repo_updater");
    let scenario = build_scenario(
        "compatibility-mismatch",
        &compatibility_mismatch_workers(),
        mismatch_hints,
    );
    let has_mismatch = scenario
        .hints
        .iter()
        .any(|h| h.reason_code == "schema_mismatch");
    assert!(
        has_mismatch,
        "compatibility mismatch must generate schema_mismatch hint"
    );
}

#[test]
fn e2e_ux_compat_major_mismatch_is_critical() {
    let hints = generate_compatibility_hints("2.0.0", "1.0.0", "repo_updater");
    assert!(!hints.is_empty());
    assert_eq!(hints[0].severity, HintSeverity::Critical);
    assert!(hints[0].involves_destructive_action);
    assert!(hints[0].risk_note.is_some());
}

#[test]
fn e2e_ux_compat_minor_mismatch_is_warning() {
    let hints = generate_compatibility_hints("1.1.0", "1.0.0", "repo_updater");
    assert!(!hints.is_empty());
    assert_eq!(hints[0].severity, HintSeverity::Warning);
    assert!(!hints[0].involves_destructive_action);
}

#[test]
fn e2e_ux_compat_match_no_hints() {
    let hints = generate_compatibility_hints("1.0.0", "1.0.0", "repo_updater");
    assert!(hints.is_empty());
}

// ===========================================================================
// Tests: rollback/canary-gate scenario
// ===========================================================================

#[test]
fn e2e_ux_rollout_all_disabled_warns() {
    let flags = vec![
        RolloutFlag {
            name: "disk_pressure_v2".into(),
            state: "disabled".into(),
            subsystem: "disk_pressure".into(),
        },
        RolloutFlag {
            name: "convergence_v2".into(),
            state: "disabled".into(),
            subsystem: "convergence".into(),
        },
    ];
    let hints = generate_rollout_hints(&flags);
    assert!(
        hints
            .iter()
            .any(|h| h.reason_code == "rollout_all_disabled"),
        "all-disabled should warn"
    );
}

#[test]
fn e2e_ux_rollout_canary_is_info() {
    let flags = vec![RolloutFlag {
        name: "disk_pressure_v2".into(),
        state: "canary".into(),
        subsystem: "disk_pressure".into(),
    }];
    let hints = generate_rollout_hints(&flags);
    assert!(
        hints.iter().any(|h| {
            h.reason_code == "rollout_canary_active" && h.severity == HintSeverity::Info
        })
    );
}

#[test]
fn e2e_ux_rollout_dry_run_is_info() {
    let flags = vec![RolloutFlag {
        name: "triage_v2".into(),
        state: "dry_run".into(),
        subsystem: "process_triage".into(),
    }];
    let hints = generate_rollout_hints(&flags);
    assert!(
        hints
            .iter()
            .any(|h| h.reason_code == "rollout_dry_run" && h.severity == HintSeverity::Info)
    );
}

#[test]
fn e2e_ux_rollout_enabled_no_hints() {
    let flags = vec![RolloutFlag {
        name: "convergence_v2".into(),
        state: "enabled".into(),
        subsystem: "convergence".into(),
    }];
    let hints = generate_rollout_hints(&flags);
    assert!(hints.is_empty());
}

#[test]
fn e2e_ux_rollout_canary_gate_in_narrative() {
    let flags = vec![
        RolloutFlag {
            name: "disk_pressure_v2".into(),
            state: "canary".into(),
            subsystem: "disk_pressure".into(),
        },
        RolloutFlag {
            name: "triage_v2".into(),
            state: "dry_run".into(),
            subsystem: "process_triage".into(),
        },
    ];
    let rollout_hints = generate_rollout_hints(&flags);
    let scenario = build_scenario("rollback-canary-gate", &healthy_workers(), rollout_hints);
    let text = scenario.narrative_lines.join("\n");
    assert!(
        text.contains("canary"),
        "canary flags should appear in narrative"
    );
    assert!(
        text.contains("dry_run"),
        "dry-run flags should appear in narrative"
    );
}

// ===========================================================================
// Tests: narrative quality constraints
// ===========================================================================

#[test]
fn e2e_ux_narrative_ordering_posture_first() {
    let scenario = build_scenario("degraded", &degraded_workers(), vec![]);
    assert!(
        scenario.narrative_lines[0].starts_with("System Posture:"),
        "first narrative line must be the system posture"
    );
}

#[test]
fn e2e_ux_narrative_ordering_workers_second() {
    let scenario = build_scenario("degraded", &degraded_workers(), vec![]);
    assert!(
        scenario.narrative_lines[1].starts_with("Workers:"),
        "second narrative line must be worker summary"
    );
}

#[test]
fn e2e_ux_narrative_critical_before_warning() {
    let scenario = build_scenario("quarantined", &quarantined_workers(), vec![]);
    let text = scenario.narrative_lines.join("\n");

    // Find first occurrence of each severity
    let first_critical = text.find("[!!]");
    let first_warning = text.find("[!]");

    if let (Some(c), Some(w)) = (first_critical, first_warning) {
        assert!(
            c < w,
            "critical hints must appear before warning hints in narrative"
        );
    }
}

#[test]
fn e2e_ux_narrative_deterministic_across_runs() {
    let scenario1 = build_scenario("quarantined", &quarantined_workers(), vec![]);
    let scenario2 = build_scenario("quarantined", &quarantined_workers(), vec![]);
    assert_eq!(
        scenario1.narrative_lines, scenario2.narrative_lines,
        "narrative output must be deterministic"
    );
}

#[test]
fn e2e_ux_narrative_no_ambiguous_wording() {
    // Ensure no contradictory phrases like "might be" next to "definitely"
    let scenario = build_scenario("quarantined", &quarantined_workers(), vec![]);
    let text = scenario.narrative_lines.join("\n");
    let ambiguous_phrases = [
        "might be definitely",
        "possibly certainly",
        "may be certain",
    ];
    for phrase in &ambiguous_phrases {
        assert!(
            !text.contains(phrase),
            "narrative should not contain ambiguous phrase: {}",
            phrase
        );
    }
}

// ===========================================================================
// Tests: redaction checks
// ===========================================================================

#[test]
fn e2e_ux_redaction_mask_sensitive_command_works() {
    let cmd = "GITHUB_TOKEN=ghp_abc123 cargo build";
    let masked = mask_sensitive_command(cmd);
    assert!(
        !masked.contains("ghp_abc123"),
        "sensitive token must be masked"
    );
    assert!(masked.contains("GITHUB_TOKEN=***"));
}

#[test]
fn e2e_ux_redaction_narrative_never_leaks_secrets() {
    // Inject a hint that references a secret in its suggested action
    let hints = vec![UxRemediationHint {
        reason_code: "test_redaction".into(),
        severity: HintSeverity::Info,
        message: "test diagnostic".into(),
        suggested_action: mask_sensitive_command(
            "GITHUB_TOKEN=ghp_secret123 ssh user@host 'echo ok'",
        ),
        worker_id: None,
        involves_destructive_action: false,
        risk_note: None,
    }];
    let scenario = build_scenario("redaction-test", &healthy_workers(), hints);
    let text = scenario.narrative_lines.join("\n");
    assert!(
        !text.contains("ghp_secret123"),
        "narrative must never contain raw secrets"
    );
}

#[test]
fn e2e_ux_redaction_golden_snapshot_clean() {
    // All standard scenarios must be redaction-clean
    let scenarios = [
        build_scenario("healthy", &healthy_workers(), vec![]),
        build_scenario("degraded", &degraded_workers(), vec![]),
        build_scenario("quarantined", &quarantined_workers(), vec![]),
        build_scenario("fail-open", &fail_open_workers(), vec![]),
    ];
    for s in &scenarios {
        let snapshot = build_golden_snapshot(s);
        assert!(
            snapshot.redaction_clean,
            "scenario '{}' must be redaction-clean",
            s.name
        );
    }
}

// ===========================================================================
// Tests: cross-worker parity
// ===========================================================================

#[test]
fn e2e_ux_parity_same_failure_same_narrative() {
    // Two workers with identical failure states should produce equivalent hint structures
    let workers = vec![
        SimWorker {
            id: "w1".into(),
            host: "host1.example.com".into(),
            user: "rch".into(),
            status: "unhealthy".into(),
            circuit_state: "open".into(),
            consecutive_failures: 3,
            recovery_in_secs: Some(30),
            pressure_state: Some("critical".into()),
            pressure_disk_free_gb: Some(5.0),
            convergence_drift_state: "failed".into(),
            missing_repos: vec!["proj".into()],
            failure_history: vec![false, false, false],
        },
        SimWorker {
            id: "w2".into(),
            host: "host2.example.com".into(),
            user: "rch".into(),
            status: "unhealthy".into(),
            circuit_state: "open".into(),
            consecutive_failures: 3,
            recovery_in_secs: Some(30),
            pressure_state: Some("critical".into()),
            pressure_disk_free_gb: Some(5.0),
            convergence_drift_state: "failed".into(),
            missing_repos: vec!["proj".into()],
            failure_history: vec![false, false, false],
        },
    ];

    let scenario = build_scenario("parity-test", &workers, vec![]);

    // Both workers should generate same number and type of hints
    let w1_hints: Vec<_> = scenario
        .hints
        .iter()
        .filter(|h| h.worker_id.as_deref() == Some("w1"))
        .collect();
    let w2_hints: Vec<_> = scenario
        .hints
        .iter()
        .filter(|h| h.worker_id.as_deref() == Some("w2"))
        .collect();

    assert_eq!(
        w1_hints.len(),
        w2_hints.len(),
        "workers with identical states must produce identical hint counts"
    );

    // Same reason codes
    let w1_codes: Vec<_> = w1_hints.iter().map(|h| &h.reason_code).collect();
    let w2_codes: Vec<_> = w2_hints.iter().map(|h| &h.reason_code).collect();
    assert_eq!(
        w1_codes, w2_codes,
        "workers with identical states must produce identical reason codes"
    );

    // Same severities
    let w1_sev: Vec<_> = w1_hints.iter().map(|h| &h.severity).collect();
    let w2_sev: Vec<_> = w2_hints.iter().map(|h| &h.severity).collect();
    assert_eq!(
        w1_sev, w2_sev,
        "workers with identical states must produce identical severities"
    );
}

#[test]
fn e2e_ux_parity_local_vs_remote_equivalent_narrative() {
    // A worker running locally (fail-open) and one that was remote but failed should
    // produce narratives that are structurally consistent
    let local_scenario = build_scenario("local-only", &[], vec![]);
    let remote_fail = build_scenario("remote-failed", &quarantined_workers(), vec![]);

    // Both should be LocalOnly posture
    assert_eq!(local_scenario.posture, PostureLabel::LocalOnly);
    assert_eq!(remote_fail.posture, PostureLabel::LocalOnly);

    // Both should start with posture line
    assert!(local_scenario.narrative_lines[0].contains("LOCAL-ONLY"));
    assert!(remote_fail.narrative_lines[0].contains("LOCAL-ONLY"));
}

// ===========================================================================
// Tests: mixed-failure workflow
// ===========================================================================

#[test]
fn e2e_ux_mixed_failure_workflow_comprehensive() {
    // Build a complex scenario with multiple failure modes
    let workers = vec![
        SimWorker {
            id: "w1".into(),
            host: "fast.example.com".into(),
            user: "rch".into(),
            status: "healthy".into(),
            circuit_state: "closed".into(),
            consecutive_failures: 0,
            recovery_in_secs: None,
            pressure_state: Some("warning".into()),
            pressure_disk_free_gb: Some(22.0),
            convergence_drift_state: "drifting".into(),
            missing_repos: vec!["core".into()],
            failure_history: vec![true, true, false, true, true],
        },
        SimWorker {
            id: "w2".into(),
            host: "slow.example.com".into(),
            user: "rch".into(),
            status: "unhealthy".into(),
            circuit_state: "open".into(),
            consecutive_failures: 4,
            recovery_in_secs: Some(45),
            pressure_state: Some("critical".into()),
            pressure_disk_free_gb: Some(3.0),
            convergence_drift_state: "failed".into(),
            missing_repos: vec!["core".into(), "utils".into()],
            failure_history: vec![false, false, false, false, true],
        },
        SimWorker {
            id: "w3".into(),
            host: "new.example.com".into(),
            user: "rch".into(),
            status: "healthy".into(),
            circuit_state: "closed".into(),
            consecutive_failures: 0,
            recovery_in_secs: None,
            pressure_state: Some("healthy".into()),
            pressure_disk_free_gb: Some(150.0),
            convergence_drift_state: "ready".into(),
            missing_repos: vec![],
            failure_history: vec![true, true, true, true, true],
        },
    ];

    let compat_hints = generate_compatibility_hints("1.1.0", "1.0.0", "process_triage");
    let rollout_hints = generate_rollout_hints(&[RolloutFlag {
        name: "triage_v2".into(),
        state: "canary".into(),
        subsystem: "process_triage".into(),
    }]);

    let mut extra = compat_hints;
    extra.extend(rollout_hints);

    let scenario = build_scenario("mixed-failure", &workers, extra);
    let snapshot = build_golden_snapshot(&scenario);

    // Posture should be degraded (some workers healthy)
    assert_eq!(scenario.posture, PostureLabel::Degraded);

    // Should have multiple severity levels
    assert!(snapshot.critical_count > 0, "must have critical hints");
    assert!(snapshot.warning_count > 0, "must have warning hints");
    assert!(snapshot.info_count > 0, "must have info hints");

    // All quality constraints
    assert!(snapshot.all_non_healthy_have_reason_codes);
    assert!(snapshot.all_non_healthy_have_remediation);
    assert!(snapshot.all_destructive_have_risk_notes);
    assert!(snapshot.narrative_deterministic);
    assert!(snapshot.redaction_clean);

    // Narrative should mention all failure domains
    let text = scenario.narrative_lines.join("\n");
    assert!(text.contains("circuit_open"));
    assert!(text.contains("pressure_critical"));
    assert!(text.contains("convergence_failed"));
    assert!(text.contains("schema_mismatch"));
    assert!(text.contains("canary"));
}

// ===========================================================================
// Tests: golden snapshot stability
// ===========================================================================

#[test]
fn e2e_ux_golden_snapshot_healthy_stable() {
    let scenario = build_scenario("healthy", &healthy_workers(), vec![]);
    let snapshot = build_golden_snapshot(&scenario);

    assert_eq!(snapshot.posture, PostureLabel::RemoteReady);
    assert_eq!(snapshot.hint_count, 0);
    assert_eq!(snapshot.critical_count, 0);
    assert_eq!(snapshot.warning_count, 0);
    assert_eq!(snapshot.info_count, 0);
    assert!(!snapshot.has_destructive_hints);
    assert!(snapshot.narrative_deterministic);
    assert!(snapshot.redaction_clean);
}

#[test]
fn e2e_ux_golden_snapshot_fail_open_stable() {
    let scenario = build_scenario("fail-open", &fail_open_workers(), vec![]);
    let snapshot = build_golden_snapshot(&scenario);

    assert_eq!(snapshot.posture, PostureLabel::LocalOnly);
    assert_eq!(snapshot.hint_count, 0);
    assert!(snapshot.narrative_deterministic);
}

#[test]
fn e2e_ux_golden_snapshot_quarantined_stable() {
    let scenario = build_scenario("quarantined", &quarantined_workers(), vec![]);
    let snapshot = build_golden_snapshot(&scenario);

    assert_eq!(snapshot.posture, PostureLabel::LocalOnly);
    assert!(
        snapshot.hint_count >= 4,
        "quarantined should have many hints"
    );
    assert!(snapshot.critical_count >= 2);
    assert!(snapshot.has_destructive_hints);
    assert!(snapshot.all_destructive_have_risk_notes);
    assert!(snapshot.narrative_deterministic);
}

// ===========================================================================
// Tests: severity icon rendering
// ===========================================================================

#[test]
fn e2e_ux_severity_icons_correct() {
    assert_eq!(HintSeverity::Critical.icon(), "!!");
    assert_eq!(HintSeverity::Warning.icon(), "!");
    assert_eq!(HintSeverity::Info.icon(), "i");
}

#[test]
fn e2e_ux_severity_ordering() {
    assert!(HintSeverity::Critical < HintSeverity::Warning);
    assert!(HintSeverity::Warning < HintSeverity::Info);
}

// ===========================================================================
// Tests: logging integration
// ===========================================================================

#[test]
fn e2e_ux_logging_integration() {
    let logger = TestLoggerBuilder::new("ux_regression").build();

    let scenarios = ["healthy", "degraded", "quarantined", "fail-open"];
    let workers_list: [Vec<SimWorker>; 4] = [
        healthy_workers(),
        degraded_workers(),
        quarantined_workers(),
        fail_open_workers(),
    ];

    for (name, workers) in scenarios.iter().zip(workers_list.iter()) {
        let scenario = build_scenario(name, workers, vec![]);
        let snapshot = build_golden_snapshot(&scenario);

        let level = if snapshot.critical_count > 0 {
            LogLevel::Error
        } else if snapshot.warning_count > 0 {
            LogLevel::Warn
        } else {
            LogLevel::Info
        };

        logger.log(
            level,
            LogSource::Custom("ux_regression".into()),
            format!(
                "UX scenario '{}': posture={:?} hints={} critical={} deterministic={}",
                name,
                scenario.posture,
                snapshot.hint_count,
                snapshot.critical_count,
                snapshot.narrative_deterministic,
            ),
        );
    }

    let entries = logger.entries();
    assert_eq!(entries.len(), 4, "should log one entry per scenario");
    assert!(
        entries
            .iter()
            .all(|e| e.source.to_string() == "ux_regression")
    );
}

// ===========================================================================
// Tests: failure history rendering
// ===========================================================================

#[test]
fn e2e_ux_failure_history_visual_pattern() {
    // The rendering convention: true=success (✓), false=failure (✗)
    fn format_failure_history(history: &[bool]) -> String {
        history
            .iter()
            .map(|&ok| if ok { '✓' } else { '✗' })
            .collect()
    }

    assert_eq!(format_failure_history(&[true, true, true]), "✓✓✓");
    assert_eq!(format_failure_history(&[false, false, true]), "✗✗✓");
    assert_eq!(
        format_failure_history(&[false, false, false, false, false]),
        "✗✗✗✗✗"
    );
}

// ===========================================================================
// Tests: full scenario sweep (all scenarios pass quality checks)
// ===========================================================================

#[test]
fn e2e_ux_full_scenario_sweep() {
    let scenarios = vec![
        build_scenario("healthy", &healthy_workers(), vec![]),
        build_scenario("degraded", &degraded_workers(), vec![]),
        build_scenario("quarantined", &quarantined_workers(), vec![]),
        build_scenario("fail-open", &fail_open_workers(), vec![]),
        build_scenario(
            "compat-mismatch",
            &compatibility_mismatch_workers(),
            generate_compatibility_hints("2.0.0", "1.0.0", "repo_updater"),
        ),
        build_scenario(
            "canary-gate",
            &healthy_workers(),
            generate_rollout_hints(&[RolloutFlag {
                name: "feature_x".into(),
                state: "canary".into(),
                subsystem: "convergence".into(),
            }]),
        ),
    ];

    for scenario in &scenarios {
        let snapshot = build_golden_snapshot(scenario);

        // Universal quality checks
        assert!(
            snapshot.narrative_deterministic,
            "scenario '{}' must be deterministic",
            scenario.name
        );
        assert!(
            snapshot.redaction_clean,
            "scenario '{}' must be redaction-clean",
            scenario.name
        );
        assert!(
            snapshot.all_non_healthy_have_reason_codes,
            "scenario '{}': all hints must have reason codes",
            scenario.name
        );
        assert!(
            snapshot.all_non_healthy_have_remediation,
            "scenario '{}': all hints must have suggested actions",
            scenario.name
        );
        assert!(
            snapshot.all_destructive_have_risk_notes,
            "scenario '{}': all destructive hints must have risk notes",
            scenario.name
        );

        // Non-healthy scenarios with hints must have remediation section in narrative
        if !scenario.hints.is_empty() {
            assert!(
                scenario
                    .narrative_lines
                    .iter()
                    .any(|l| l.contains("Remediation")),
                "scenario '{}' with hints must have remediation section",
                scenario.name
            );
        }
    }
}
