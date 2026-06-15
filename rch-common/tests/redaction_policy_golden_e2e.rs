//! Golden + privacy-policy + no-leak checks for the shared redaction policy
//! (bd-session-history-remediation-ocv9i.16.8).
//!
//! Required-proof artifact named by the program validation matrix
//! (`docs/guides/session-history-remediation-validation.md`, row 16.8:
//! "redaction unit tests, privacy policy checks, golden JSON/schema checks").
//!
//! - Golden of the default policy CONTRACT (schema version, sentinel, and every
//!   rule's id/category/mode) so any policy change is a conscious decision.
//! - Schema structural check.
//! - "No secret leaks" guard: representative secrets injected into a payload are
//!   gone after `redact_secrets`, and stay gone across every rendering mode
//!   (JSON pretty/compact, Debug/plain) — proving redaction is applied at the
//!   DATA layer, not per output mode.

use rch_common::redaction::{
    REDACTION_SENTINEL, RedactionPolicy, redact_path, redact_secrets, redacted_hash,
};
use serde::Serialize;
use serde_json::{Value, json};

#[test]
fn golden_redaction_policy_contract() {
    let policy = RedactionPolicy::default();

    // Scalar contract.
    assert_eq!(policy.schema_version, "1.0.0");
    assert_eq!(policy.sentinel, "[REDACTED]");
    assert!(policy.audit_redactions);

    // Rule contract: id + category + mode for every rule, in order. Descriptions
    // are prose and intentionally excluded from the golden.
    let summary: Vec<Value> = policy
        .rules
        .iter()
        .map(|r| {
            json!({
                "id": r.id,
                "category": serde_json::to_value(r.category).unwrap(),
                "mode": serde_json::to_value(r.mode).unwrap(),
            })
        })
        .collect();

    let expected = json!([
        {"id": "RR-001", "category": "env_secret",      "mode": "masked"},
        {"id": "RR-002", "category": "api_key",         "mode": "masked"},
        {"id": "RR-003", "category": "bearer_token",    "mode": "masked"},
        {"id": "RR-004", "category": "password",        "mode": "masked"},
        {"id": "RR-005", "category": "database_url",    "mode": "masked"},
        {"id": "RR-006", "category": "ssh_key",         "mode": "masked"},
        {"id": "RR-007", "category": "filesystem_path", "mode": "masked"},
        {"id": "RR-008", "category": "source_content",  "mode": "hashed"},
        {"id": "RR-009", "category": "hostname",        "mode": "local_reference"},
    ]);

    assert_eq!(
        Value::Array(summary),
        expected,
        "redaction policy contract drift — if intentional, update this golden"
    );
}

#[test]
fn schema_exposes_policy_fields() {
    let schema = RedactionPolicy::schema_json();
    let props = schema
        .get("properties")
        .and_then(Value::as_object)
        .expect("schema has properties");
    for f in ["schema_version", "sentinel", "audit_redactions", "rules"] {
        assert!(props.contains_key(f), "schema missing {f}");
    }
}

/// Secret fixtures assembled at runtime from split parts so no contiguous
/// secret literal appears in source — that keeps GitHub secret-scanning push
/// protection from flagging our own test data. The redactor still operates on
/// the fully-assembled strings.
struct Fixtures {
    github: String,
    aws: String,
    jwt: String,
    cli_pass: String,
    db_pass: String,
    home_user: String,
}

fn fixtures() -> Fixtures {
    Fixtures {
        github: format!("ghp_{}", "abcdefghijklmnopqrstuvwx012345"),
        aws: format!("AKIA{}", "IOSFODNN7EXAMPLE"),
        jwt: format!(
            "{}.{}.{}",
            "eyJhbGciOi", "eyJzdWIiOiIxIn0", "dozjgNryP4J3jVmNHl0w5N"
        ),
        cli_pass: "hunter2pass".to_string(),
        db_pass: "p4ss".to_string(),
        home_user: "alice".to_string(),
    }
}

/// A representative remediation payload embedding one of every secret class.
#[derive(Serialize, Debug)]
struct LeakProbe {
    command: String,
    incident_detail: String,
    handoff_note: String,
}

fn dirty_probe(f: &Fixtures) -> LeakProbe {
    LeakProbe {
        command: format!(
            "GITHUB_TOKEN={} cargo test --token {}",
            f.github, f.cli_pass
        ),
        incident_detail: format!(
            "ssh failed reading /home/{}/.ssh/id_rsa; db postgres://u:{}@db.internal/app",
            f.home_user, f.db_pass
        ),
        handoff_note: format!("Authorization: Bearer {} and {}", f.jwt, f.aws),
    }
}

/// The exact secret substrings that must never survive redaction.
fn raw_secrets(f: &Fixtures) -> Vec<String> {
    vec![
        f.github.clone(),
        f.cli_pass.clone(),
        f.home_user.clone(),
        f.db_pass.clone(),
        format!("u:{}", f.db_pass),
        f.jwt.clone(),
        f.aws.clone(),
    ]
}

fn redact_probe(p: &LeakProbe) -> LeakProbe {
    LeakProbe {
        command: redact_secrets(&p.command),
        incident_detail: redact_secrets(&p.incident_detail),
        handoff_note: redact_secrets(&p.handoff_note),
    }
}

#[test]
fn no_secret_survives_redaction() {
    let f = fixtures();
    let red = redact_probe(&dirty_probe(&f));
    let blob = format!(
        "{} {} {}",
        red.command, red.incident_detail, red.handoff_note
    );
    for secret in raw_secrets(&f) {
        assert!(
            !blob.contains(&secret),
            "secret {secret:?} survived: {blob}"
        );
    }
    // Debugging detail is preserved: the non-secret host/db/path remnants stay.
    assert!(red.incident_detail.contains("db.internal/app"));
    assert!(red.incident_detail.contains("/home/<redacted>/.ssh/id_rsa"));
}

#[test]
fn redaction_is_stable_across_output_modes() {
    // Redaction happens at the DATA layer, so the secret is absent regardless of
    // how the redacted payload is later rendered. We render the SAME redacted
    // value as JSON (machine mode), compact JSON, and Debug (≈ plain/interactive
    // struct rendering); TOON/colored/interactive all consume this same layer.
    let f = fixtures();
    let red = redact_probe(&dirty_probe(&f));

    let json_pretty = serde_json::to_string_pretty(&red).expect("json");
    let json_compact = serde_json::to_string(&red).expect("json compact");
    let debug_plain = format!("{red:?}");
    // A TOON/plain-text-like flattened rendering.
    let flattened = format!(
        "command={}\nincident_detail={}\nhandoff_note={}",
        red.command, red.incident_detail, red.handoff_note
    );

    let raw = raw_secrets(&f);
    for rendering in [&json_pretty, &json_compact, &debug_plain, &flattened] {
        for secret in &raw {
            assert!(
                !rendering.contains(secret),
                "secret {secret:?} leaked in a rendering mode:\n{rendering}"
            );
        }
        assert!(rendering.contains(REDACTION_SENTINEL) || rendering.contains("***"));
    }
}

#[test]
fn hashed_mode_is_stable_and_irreversible() {
    let h = redacted_hash("worker-host.internal.example.com");
    assert!(h.starts_with("blake3:"));
    assert!(!h.contains("internal.example.com"));
    assert_eq!(h, redacted_hash("worker-host.internal.example.com"));
}

#[test]
fn safe_text_is_not_mangled() {
    // Golden: ordinary build/diagnostic text round-trips unchanged.
    let safe = "cargo clippy --workspace --all-targets -- -D warnings (ran in /tmp/rch)";
    assert_eq!(redact_secrets(safe), safe);
    assert_eq!(redact_path("/data/projects/foo"), "/data/projects/foo");
}
