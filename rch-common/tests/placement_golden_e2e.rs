//! Golden / schema-regression tests for the canonical placement control plan
//! (bd-session-history-remediation-ocv9i.13.5).
//!
//! These pin the agent-facing wire form of [`PlacementPlan`] and the
//! requested-worker admissibility outcomes. A field/value/vocabulary change
//! here is intentional only with a schema-version bump — exactly the
//! code-review trigger the program's validation contract requires.

use std::collections::HashMap;

use rch_common::placement::{
    PlacementPlan, RequestedWorkerFacts, RequestedWorkerStatus, StrictRemotePolicy,
    evaluate_requested_worker, resolve_placement,
};
use rch_common::schema_versions::{SchemaComponent, current_version};
use serde_json::{Value, json};

/// Assert a value serializes to exactly `expected`, with a self-describing
/// drift message.
fn assert_golden<T: serde::Serialize>(name: &str, value: &T, expected: Value) {
    let actual = serde_json::to_value(value).expect("value serializes");
    assert_eq!(
        actual,
        expected,
        "golden drift in {name}: a field/value/vocabulary changed. If intentional, \
         bump SchemaComponent::PlacementPlan and update the json! block.\nactual:\n{}",
        serde_json::to_string_pretty(&actual).unwrap()
    );
}

/// Env getter over a fixed map — deterministic, no process-env mutation.
fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
    let map: HashMap<String, String> = pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect();
    move |k: &str| map.get(k).cloned()
}

const VERSION: &str = "1.0.0";

#[test]
fn golden_schema_version_is_pinned() {
    // The plan stamps the registry version, and the registry version is what
    // these goldens assume.
    assert_eq!(current_version(SchemaComponent::PlacementPlan), VERSION);
    assert_eq!(PlacementPlan::schema_version(), VERSION);
}

#[test]
fn golden_default_plan_no_controls() {
    // No env controls: the safe defaults, fully explicit so an agent can read
    // the posture without inferring it.
    let plan = resolve_placement(env(&[]));
    assert_golden(
        "default_plan",
        &plan,
        json!({
            "schema_version": VERSION,
            "strict_remote_policy": "off",
            "queue_policy": "queue_when_busy",
            "visibility_mode": "default",
            "target_dir_policy": "pooled",
            "requested_worker_outcome": { "status": "not_requested" },
        }),
    );
}

#[test]
fn golden_force_remote_is_fail_open_distinct_from_require() {
    let force = resolve_placement(env(&[("RCH_FORCE_REMOTE", "1")]));
    assert_eq!(force.strict_remote_policy, StrictRemotePolicy::ForceRemote);
    let v = serde_json::to_value(&force).unwrap();
    assert_eq!(v["strict_remote_policy"], "force_remote");

    let require = resolve_placement(env(&[("RCH_REQUIRE_REMOTE", "1")]));
    assert_eq!(
        require.strict_remote_policy,
        StrictRemotePolicy::RequireRemote
    );
    let v = serde_json::to_value(&require).unwrap();
    assert_eq!(v["strict_remote_policy"], "require_remote");
}

#[test]
fn golden_full_control_surface() {
    // Every explicit control set at once, plus a honored requested worker and
    // the effective worker — the complete agent-facing surface.
    let plan = resolve_placement(env(&[
        ("RCH_WORKER", "css"),
        ("RCH_PRESET", "fast"),
        ("RCH_REQUIRE_REMOTE", "1"),
        ("RCH_QUEUE_WHEN_BUSY", "0"),
        ("RCH_VISIBILITY", "summary"),
        ("RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS", "90"),
        ("RCH_DISABLE_TARGET_REUSE", "1"),
    ]))
    .with_effective_worker(Some("css".to_string()))
    .with_requested_worker_outcome(evaluate_requested_worker(
        &RequestedWorkerFacts::admissible("css"),
    ));
    assert_golden(
        "full_control_surface",
        &plan,
        json!({
            "schema_version": VERSION,
            "requested_worker": "css",
            "requested_profile": "fast",
            "effective_worker": "css",
            "strict_remote_policy": "require_remote",
            "queue_policy": "no_queue",
            "visibility_mode": "summary",
            "wait_timeout_ms": 90_000,
            "target_dir_policy": "per_job",
            "requested_worker_outcome": { "status": "honored" },
        }),
    );
}

#[test]
fn golden_requested_worker_refusals() {
    // Each refusal class pins its stable status + RCH-Innn reason code. These
    // are the structured handoffs an agent branches on instead of a silent swap.
    let cases = [
        (
            RequestedWorkerFacts {
                requested: Some("ghost".into()),
                exists: false,
                ..RequestedWorkerFacts::none()
            },
            "unavailable",
            "RCH-I001",
        ),
        (
            RequestedWorkerFacts {
                admin_disabled: true,
                ..RequestedWorkerFacts::admissible("css")
            },
            "admin_disabled",
            "RCH-I001",
        ),
        (
            RequestedWorkerFacts {
                temporarily_bypassed: true,
                ..RequestedWorkerFacts::admissible("css")
            },
            "temporarily_bypassed",
            "RCH-I009",
        ),
        (
            RequestedWorkerFacts {
                platform_matches: false,
                ..RequestedWorkerFacts::admissible("css")
            },
            "wrong_platform",
            "RCH-I007",
        ),
        (
            RequestedWorkerFacts {
                has_required_runtime: false,
                ..RequestedWorkerFacts::admissible("css")
            },
            "missing_runtime",
            "RCH-I006",
        ),
        (
            RequestedWorkerFacts {
                project_excluded: true,
                ..RequestedWorkerFacts::admissible("css")
            },
            "project_excluded",
            "RCH-I005",
        ),
        (
            RequestedWorkerFacts {
                has_free_slots: false,
                ..RequestedWorkerFacts::admissible("css")
            },
            "no_free_slots",
            "RCH-I003",
        ),
    ];
    for (facts, status, code) in cases {
        let out = evaluate_requested_worker(&facts);
        let v = serde_json::to_value(&out).unwrap();
        assert_eq!(v["status"], status, "status mismatch for {status}");
        assert_eq!(v["reason_code"], code, "reason_code mismatch for {status}");
        assert!(
            out.next_action.is_some(),
            "refusal {status} must carry a next action"
        );
        assert!(out.status.is_refusal());
    }
}

#[test]
fn golden_honored_outcome_has_no_reason_code() {
    let out = evaluate_requested_worker(&RequestedWorkerFacts::admissible("css"));
    assert_golden("honored_outcome", &out, json!({ "status": "honored" }));
}

#[test]
fn golden_diagnostics_surface_superseded_and_bad_values() {
    // Both a superseded-alias info and a bad-value warning must appear — nothing
    // is silently dropped.
    let plan = resolve_placement(env(&[
        ("RCH_REQUIRE_REMOTE", "1"),
        ("RCH_FORCE_REMOTE", "1"),
        ("RCH_QUEUE_WHEN_BUSY", "perhaps"),
    ]));
    let v = serde_json::to_value(&plan).unwrap();
    let diags = v["diagnostics"].as_array().expect("diagnostics present");
    assert!(
        diags
            .iter()
            .any(|d| d["control"] == "RCH_REQUIRE_REMOTE" && d["level"] == "info"),
        "expected precedence info diagnostic"
    );
    assert!(
        diags
            .iter()
            .any(|d| d["control"] == "RCH_QUEUE_WHEN_BUSY" && d["level"] == "warning"),
        "expected unrecognized-value warning diagnostic"
    );
}

#[test]
fn golden_status_vocabulary_is_complete_and_stable() {
    // The full requested-worker status vocabulary, pinned. Adding a variant is a
    // schema change.
    for (status, token) in [
        (RequestedWorkerStatus::NotRequested, "not_requested"),
        (RequestedWorkerStatus::Requested, "requested"),
        (RequestedWorkerStatus::Honored, "honored"),
        (RequestedWorkerStatus::Unavailable, "unavailable"),
        (RequestedWorkerStatus::AdminDisabled, "admin_disabled"),
        (
            RequestedWorkerStatus::TemporarilyBypassed,
            "temporarily_bypassed",
        ),
        (RequestedWorkerStatus::WrongPlatform, "wrong_platform"),
        (RequestedWorkerStatus::MissingRuntime, "missing_runtime"),
        (RequestedWorkerStatus::ProjectExcluded, "project_excluded"),
        (RequestedWorkerStatus::NoFreeSlots, "no_free_slots"),
    ] {
        assert_eq!(status.as_str(), token);
        assert_eq!(serde_json::to_value(status).unwrap(), json!(token));
    }
}
