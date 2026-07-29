//! Leak-guard E2E for the redaction *consumer wiring* (bd-53ga7).
//!
//! `redaction_policy_golden_e2e.rs` proves the redaction *engine* removes
//! secrets from free text. This suite proves the wiring at each output surface
//! that emits free text actually routes through that engine, by injecting
//! representative secrets and asserting they never survive into the surface's
//! output:
//!
//! - the incident ledger JSONL (`IncidentLedger::append` → `IncidentEvent::redacted`),
//! - artifact-verify diagnostics (`VerificationResult::format_failures`).
//!
//! Every secret literal is assembled from split parts at runtime so no
//! secret-shaped string appears in source (keeps GitHub push-protection /
//! secret-scanning quiet, and is honest: the bytes only exist at test time).

use rch_common::redaction::REDACTION_SENTINEL;
use rch_common::{
    IncidentEvent, IncidentEventType, IncidentLedger, IncidentReasonCode, IncidentSource,
    SelectedMode, VerificationFailure, VerificationResult,
};

/// Representative secrets, assembled at runtime (never present as a literal).
struct InjectedSecrets {
    aws: String,
    github: String,
    bearer_value: String,
}

impl InjectedSecrets {
    fn new() -> Self {
        Self {
            // Shapes that `redact_secrets` recognizes (see redaction.rs
            // SHAPED_PATTERNS): AWS `AKIA…`, GitHub `ghp_…`, Bearer token.
            aws: format!("AKIA{}", "IOSFODNN7EXAMPLE"),
            github: format!("ghp_{}", "abcdefghijklmnopqrstuvwx012345"),
            bearer_value: format!("ghs_{}", "zyxwvutsrq0987654321abcdef"),
        }
    }
}

#[test]
fn incident_ledger_append_redacts_detail_values() {
    let secrets = InjectedSecrets::new();
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("incidents.jsonl");
    let ledger = IncidentLedger::with_path(&path);

    let event = IncidentEvent::new(
        IncidentEventType::Admission,
        IncidentReasonCode::NoAdmissibleWorkers,
        IncidentSource::Daemon,
        "proj-leakguard",
        "cargo build --release",
        SelectedMode::Local,
        true,
        1_700_000_000_000,
    )
    .with_worker_id("css")
    .with_detail("aws_key", &secrets.aws)
    .with_detail("gh_token", &secrets.github)
    .with_detail(
        "auth_header",
        format!("Authorization: Bearer {}", secrets.bearer_value),
    );

    ledger.append(&event).expect("append");

    let persisted = std::fs::read_to_string(&path).expect("read ledger");

    assert!(
        !persisted.contains(&secrets.aws),
        "AWS key leaked into the incident ledger:\n{persisted}"
    );
    assert!(
        !persisted.contains(&secrets.github),
        "GitHub token leaked into the incident ledger:\n{persisted}"
    );
    assert!(
        !persisted.contains(&secrets.bearer_value),
        "Bearer token leaked into the incident ledger:\n{persisted}"
    );
    assert!(
        persisted.contains(REDACTION_SENTINEL),
        "expected the redaction sentinel in the ledger, got:\n{persisted}"
    );

    // The read-back path returns the same redacted view (no raw secret revival).
    let events = ledger.read_all();
    assert_eq!(events.len(), 1);
    let roundtrip = serde_json::to_string(&events[0]).expect("serialize");
    assert!(!roundtrip.contains(&secrets.aws));
    assert!(!roundtrip.contains(&secrets.github));
    assert!(!roundtrip.contains(&secrets.bearer_value));
}

#[test]
fn incident_event_redacted_preserves_structured_fields() {
    // Redaction must touch only free-form `details` values, never the
    // structured identity of the event.
    let secrets = InjectedSecrets::new();
    let event = IncidentEvent::new(
        IncidentEventType::Admission,
        IncidentReasonCode::NoAdmissibleWorkers,
        IncidentSource::Daemon,
        "proj-keep",
        "cargo test",
        SelectedMode::Remote,
        false,
        1_700_000_000_001,
    )
    .with_worker_id("worker-7")
    .with_detail("token", &secrets.github)
    .with_detail("count", "3");

    let redacted = event.redacted();
    assert_eq!(redacted.project_id, "proj-keep");
    assert_eq!(redacted.worker_id.as_deref(), Some("worker-7"));
    assert_eq!(redacted.command_fingerprint, "cargo test");
    assert_eq!(redacted.occurred_at_unix_ms, 1_700_000_000_001);
    // Non-secret detail values pass through untouched.
    assert_eq!(redacted.details.get("count").map(String::as_str), Some("3"));
    // Secret-shaped detail value is masked.
    let token = redacted.details.get("token").expect("token detail");
    assert!(
        !token.contains(&secrets.github),
        "token not redacted: {token}"
    );
}

#[test]
fn artifact_diagnostics_redact_home_path_segments() {
    let secrets = InjectedSecrets::new();
    // A home segment that embeds an injected secret (e.g. a path under a
    // home dir whose name carries a token).
    let leaky_user = format!("alice-{}", secrets.github);
    let result = VerificationResult {
        passed: vec![],
        failed: vec![VerificationFailure {
            path: format!("/home/{leaky_user}/proj/target/debug/app"),
            expected_hash: "a".repeat(64),
            actual_hash: "b".repeat(64),
            expected_size: 1024,
            actual_size: 2048,
        }],
        skipped: vec![],
    };

    let rendered = result.format_failures();

    assert!(
        !rendered.contains(&leaky_user),
        "home/user segment (with secret) leaked into artifact diagnostics:\n{rendered}"
    );
    assert!(
        !rendered.contains(&secrets.github),
        "GitHub token leaked into artifact diagnostics:\n{rendered}"
    );
    assert!(
        rendered.contains("/home/<redacted>/"),
        "expected the home segment to be masked, got:\n{rendered}"
    );
    // The non-sensitive remainder of the path is preserved for usefulness.
    assert!(
        rendered.contains("/proj/target/debug/app"),
        "the non-sensitive path tail should survive, got:\n{rendered}"
    );
}

#[test]
fn artifact_diagnostics_leave_relative_paths_intact() {
    // Relative artifact paths carry no home segment; redaction is a no-op so
    // the diagnostic stays useful.
    let result = VerificationResult {
        passed: vec![],
        failed: vec![VerificationFailure {
            path: "target/debug/app".to_string(),
            expected_hash: "a".repeat(64),
            actual_hash: "b".repeat(64),
            expected_size: 1,
            actual_size: 2,
        }],
        skipped: vec![],
    };
    let rendered = result.format_failures();
    assert!(rendered.contains("target/debug/app"), "{rendered}");
}
