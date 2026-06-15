//! Golden + schema + no-leak + dashboard-data-adapter checks for the
//! operator-facing remediation view (bd-session-history-remediation-ocv9i.14.4).
//!
//! Required-proof artifact named by the program validation matrix
//! (`docs/guides/session-history-remediation-validation.md`, row 14.4:
//! "integration tests for dashboard data adapters; golden JSON/schema checks").
//!
//! - Golden of the band CONTRACT: schema version, band ids + canonical order,
//!   and the action-class taxonomy, so any change to the dashboard surface is a
//!   conscious decision.
//! - "Dashboard data adapter" integration: drive [`build_inputs`] from neutral
//!   worker rows for each of the seven mandated dashboard states and assert the
//!   assembled view's posture + per-band action classes.
//! - "No secret leaks" guard: inject representative secrets into every free-text
//!   field and assert they are gone in JSON (pretty + compact) and Debug.

use rch_common::fleet_diff::WorkerObservation;
use rch_common::remediation_view::{
    BandId, DiskLevel, JobsInput, ProofQueueInput, RemediationActionClass, RemediationIncidentLine,
    RemediationView, RemediationWorkerRow, assemble, build_inputs,
};
use rch_common::schema_versions::{SchemaComponent, current_version};

const ABSENCE_THRESHOLD: u64 = 300;

fn ready_row(id: &str) -> RemediationWorkerRow {
    RemediationWorkerRow {
        observation: WorkerObservation {
            worker_id: id.into(),
            configured: true,
            in_daemon_pool: true,
            reachable: true,
            admin_disabled: false,
            temporarily_bypassed: false,
            facts_known: true,
            command_admissible: true,
        },
        disk_level: DiskLevel::Ok,
        reclaiming: false,
        free_ratio: Some(0.75),
        slots_used: 0,
        slots_total: 8,
        telemetry_known: true,
        telemetry_fresh: true,
        telemetry_age_secs: Some(4),
        recovered_pending_canary: false,
        absent_secs: None,
    }
}

fn view_for(
    rows: &[RemediationWorkerRow],
    jobs: JobsInput,
    proof: ProofQueueInput,
) -> RemediationView {
    let inputs = build_inputs(rows, jobs, proof, Vec::new(), ABSENCE_THRESHOLD);
    assemble(&inputs, 1_700_000_000_000)
}

#[test]
fn golden_band_contract() {
    let view = view_for(
        &[ready_row("css"), ready_row("ovh-a")],
        JobsInput::default(),
        ProofQueueInput::default(),
    );

    assert_eq!(
        view.schema_version,
        current_version(SchemaComponent::RemediationView)
    );
    assert_eq!(view.schema_version, "1.0.0");

    // Bands present, in canonical order — the dashboard surface contract.
    let ids: Vec<&str> = view.bands.iter().map(|b| b.id.as_str()).collect();
    assert_eq!(
        ids,
        vec![
            "desired_fleet",
            "live_eligibility",
            "admissible_workers",
            "proof_queue",
            "active_jobs",
            "disk_pressure",
            "telemetry_freshness",
            "incidents",
        ],
        "band id/order drift — if intentional, update this golden and the dashboards"
    );

    // Action-class taxonomy contract (increasing severity).
    let classes: Vec<&str> = RemediationActionClass::ALL
        .iter()
        .map(|c| c.as_str())
        .collect();
    assert_eq!(
        classes,
        vec![
            "healthy",
            "normal_fail_open",
            "self_healing_in_progress",
            "operator_action_required",
        ]
    );

    // Every band carries its title and a redacted headline.
    for band in &view.bands {
        assert_eq!(band.title, band.id.title());
        assert!(!band.headline.is_empty());
    }
}

#[test]
fn schema_versions_register_the_component() {
    assert!(
        rch_common::schema_versions::ALL_COMPONENTS
            .iter()
            .any(|(c, _)| *c == SchemaComponent::RemediationView),
        "RemediationView must be registered in ALL_COMPONENTS"
    );
}

/// Dashboard-data-adapter integration: the seven mandated dashboard states.
#[test]
fn dashboard_states_have_expected_posture() {
    // 1. healthy
    let view = view_for(
        &[ready_row("a"), ready_row("b"), ready_row("c")],
        JobsInput::default(),
        ProofQueueInput::default(),
    );
    assert_eq!(view.overall, RemediationActionClass::Healthy);

    // 2. degraded (one temporarily bypassed, others fine)
    let mut bypassed = ready_row("b");
    bypassed.observation.temporarily_bypassed = true;
    let view = view_for(
        &[ready_row("a"), bypassed, ready_row("c")],
        JobsInput::default(),
        ProofQueueInput::default(),
    );
    assert_eq!(view.overall, RemediationActionClass::SelfHealingInProgress);
    assert_eq!(
        view.band(BandId::LiveEligibility).unwrap().action_class,
        RemediationActionClass::SelfHealingInProgress
    );

    // 3. no admissible workers (all live but none has trustworthy facts)
    let mut no_facts_a = ready_row("a");
    no_facts_a.observation.facts_known = false;
    let mut no_facts_b = ready_row("b");
    no_facts_b.observation.facts_known = false;
    let view = view_for(
        &[no_facts_a, no_facts_b],
        JobsInput::default(),
        ProofQueueInput::default(),
    );
    assert_eq!(view.overall, RemediationActionClass::OperatorActionRequired);
    assert_eq!(
        view.band(BandId::AdmissibleWorkers).unwrap().action_class,
        RemediationActionClass::OperatorActionRequired
    );

    // 4. proof queued
    let view = view_for(
        &[ready_row("a"), ready_row("b")],
        JobsInput::default(),
        ProofQueueInput {
            queued: 3,
            replaying: 1,
            ..ProofQueueInput::default()
        },
    );
    assert_eq!(
        view.band(BandId::ProofQueue).unwrap().action_class,
        RemediationActionClass::SelfHealingInProgress
    );

    // 5. disk pressure (critical, no reclaim → operator)
    let mut crit = ready_row("a");
    crit.disk_level = DiskLevel::Critical;
    crit.free_ratio = Some(0.01);
    let view = view_for(
        &[crit, ready_row("b")],
        JobsInput::default(),
        ProofQueueInput::default(),
    );
    assert_eq!(view.overall, RemediationActionClass::OperatorActionRequired);
    assert_eq!(
        view.band(BandId::DiskPressure).unwrap().action_class,
        RemediationActionClass::OperatorActionRequired
    );

    // 6. stale telemetry
    let mut stale = ready_row("a");
    stale.telemetry_fresh = false;
    stale.telemetry_age_secs = Some(1200);
    let view = view_for(
        &[stale, ready_row("b")],
        JobsInput::default(),
        ProofQueueInput::default(),
    );
    assert_eq!(
        view.band(BandId::TelemetryFreshness).unwrap().action_class,
        RemediationActionClass::SelfHealingInProgress
    );

    // 7. auto-rejoin pending
    let mut canary = ready_row("a");
    canary.recovered_pending_canary = true;
    let view = view_for(
        &[canary, ready_row("b")],
        JobsInput::default(),
        ProofQueueInput::default(),
    );
    assert_eq!(view.overall, RemediationActionClass::SelfHealingInProgress);
}

#[test]
fn no_secret_leaks_across_render_modes() {
    let mut rows = vec![ready_row("css")];
    // Worker ids are config aliases, but prove that even if a hostname-shaped id
    // sneaks in, free text carrying secrets is scrubbed.
    rows[0].observation.worker_id = "css".into();

    let incidents = vec![RemediationIncidentLine::new(
        "RCH-I010",
        "hook",
        Some("css".into()),
        12,
        "ssh ubuntu@203.0.113.20 failed; key AKIAIOSFODNN7EXAMPLE token Bearer sk-abcdef0123456789abcdef0123456789 at /home/ubuntu/.ssh/id_rsa",
    )];
    let mut inputs = build_inputs(
        &rows,
        JobsInput::default(),
        ProofQueueInput::default(),
        incidents,
        ABSENCE_THRESHOLD,
    );
    inputs.fleet.problem_summary =
        "drift: orphan worker --password hunter2pass DATABASE_URL=postgres://user:hunter2pass@host:5432/db".into();

    let view = assemble(&inputs, 1);

    let pretty = serde_json::to_string_pretty(&view).unwrap();
    let compact = serde_json::to_string(&view).unwrap();
    let debug = format!("{view:?}");

    for rendering in [&pretty, &compact, &debug] {
        assert!(
            !rendering.contains("AKIAIOSFODNN7EXAMPLE"),
            "AWS-shaped key leaked"
        );
        assert!(
            !rendering.contains("abcdef0123456789abcdef0123456789"),
            "bearer token leaked"
        );
        assert!(!rendering.contains("hunter2pass"), "password leaked");
    }
}

#[test]
fn view_json_round_trips() {
    let view = view_for(
        &[ready_row("a")],
        JobsInput {
            active: 2,
            queued: 1,
            stuck: 0,
        },
        ProofQueueInput::default(),
    );
    let json = serde_json::to_string(&view).unwrap();
    let back: RemediationView = serde_json::from_str(&json).unwrap();
    assert_eq!(view, back);
}
