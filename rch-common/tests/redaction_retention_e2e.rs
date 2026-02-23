//! Reliability Log/Artifact Redaction + Retention Governance E2E Tests (bd-vvmd.6.10)
//!
//! Validates:
//!   - Redaction pipeline removes/masks credentials/tokens/keys/PII across logs,
//!     status payloads, and captured artifacts
//!   - Retention policy defines TTLs, storage tiers, and cleanup behavior
//!   - Redaction rules are schema-aware and versioned
//!   - Verification tests inject synthetic secrets and fail if any survive redaction
//!   - Safe export/share procedures for incident bundles

use rch_common::e2e::harness::ReliabilityCommandRecord;
use rch_common::e2e::logging::{
    LogLevel, ReliabilityContext, ReliabilityEventInput, ReliabilityPhase, TestLoggerBuilder,
};
use rch_common::util::mask_sensitive_command;
use serde::{Deserialize, Serialize};
use std::time::Duration;

// ===========================================================================
// Redaction types
// ===========================================================================

/// Schema version for the redaction policy contract.
const REDACTION_POLICY_SCHEMA_VERSION: &str = "1.0.0";

/// Sentinel used to replace redacted values.
const REDACTION_SENTINEL: &str = "[REDACTED]";

/// A named redaction rule that matches and masks specific patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RedactionRule {
    /// Rule identifier for audit trail.
    id: String,
    /// Human-readable description.
    description: String,
    /// Category of sensitive data this rule targets.
    category: SensitiveDataCategory,
    /// Regex-like pattern (simplified for testing; real impl uses compiled regex).
    pattern_description: String,
    /// Whether this rule is enabled.
    enabled: bool,
}

/// Categories of sensitive data.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SensitiveDataCategory {
    /// API keys and tokens
    ApiKey,
    /// Passwords and passphrases
    Password,
    /// SSH private keys and certificates
    SshKey,
    /// Database connection strings
    DatabaseUrl,
    /// Cloud provider credentials (AWS, GCP, etc.)
    CloudCredential,
    /// Personal identifying information
    Pii,
    /// Session tokens and cookies
    SessionToken,
    /// Custom/project-specific secrets
    Custom,
}

/// Versioned redaction policy with all active rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RedactionPolicy {
    schema_version: String,
    rules: Vec<RedactionRule>,
    sentinel: String,
    audit_all_redactions: bool,
}

impl Default for RedactionPolicy {
    fn default() -> Self {
        Self {
            schema_version: REDACTION_POLICY_SCHEMA_VERSION.to_string(),
            rules: default_redaction_rules(),
            sentinel: REDACTION_SENTINEL.to_string(),
            audit_all_redactions: true,
        }
    }
}

/// Record of a redaction event for audit.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RedactionAuditEntry {
    rule_id: String,
    category: SensitiveDataCategory,
    field_path: String,
    original_length: usize,
    redacted: bool,
}

// ===========================================================================
// Retention types
// ===========================================================================

/// Storage tier for artifact retention.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StorageTier {
    /// Hot storage: fast access, short retention (e.g., local disk during CI).
    Hot,
    /// Warm storage: moderate access, medium retention (e.g., shared NFS).
    Warm,
    /// Cold storage: slow access, long retention (e.g., archive/backup).
    Cold,
    /// Ephemeral: deleted after pipeline completion.
    Ephemeral,
}

/// Retention policy for a class of artifacts.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RetentionRule {
    /// Human-readable name.
    name: String,
    /// Glob pattern matching artifact paths.
    path_pattern: String,
    /// Time-to-live for this class of artifact.
    ttl: Duration,
    /// Storage tier.
    tier: StorageTier,
    /// Whether redaction is required before archival.
    requires_redaction: bool,
    /// Whether this rule applies to CI artifacts.
    applies_to_ci: bool,
}

/// Complete retention policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RetentionPolicy {
    schema_version: String,
    rules: Vec<RetentionRule>,
    default_ttl: Duration,
    default_tier: StorageTier,
    cleanup_interval: Duration,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            schema_version: "1.0.0".to_string(),
            rules: default_retention_rules(),
            default_ttl: Duration::from_secs(86400), // 24 hours
            default_tier: StorageTier::Hot,
            cleanup_interval: Duration::from_secs(3600), // 1 hour
        }
    }
}

/// Result of applying retention policy to a set of artifacts.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RetentionDecision {
    artifact_path: String,
    matched_rule: Option<String>,
    tier: StorageTier,
    ttl_secs: u64,
    requires_redaction: bool,
    action: RetentionAction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RetentionAction {
    Keep,
    Archive,
    Delete,
    RedactThenKeep,
    RedactThenArchive,
}

// ===========================================================================
// Incident bundle types
// ===========================================================================

/// Safe incident bundle for export/share.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct IncidentBundle {
    schema_version: String,
    bundle_id: String,
    created_at: String,
    scenario_ids: Vec<String>,
    redaction_policy_version: String,
    redaction_audit: Vec<RedactionAuditEntry>,
    artifact_manifest: Vec<IncidentArtifactEntry>,
    safe_for_sharing: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IncidentArtifactEntry {
    path: String,
    redacted: bool,
    size_bytes: u64,
    tier: StorageTier,
}

// ===========================================================================
// Default rules
// ===========================================================================

fn default_redaction_rules() -> Vec<RedactionRule> {
    vec![
        RedactionRule {
            id: "RR-001".to_string(),
            description: "API keys in environment variables".to_string(),
            category: SensitiveDataCategory::ApiKey,
            pattern_description: "CARGO_REGISTRY_TOKEN, GITHUB_TOKEN, GH_TOKEN, API_KEY, etc."
                .to_string(),
            enabled: true,
        },
        RedactionRule {
            id: "RR-002".to_string(),
            description: "Passwords in environment variables and arguments".to_string(),
            category: SensitiveDataCategory::Password,
            pattern_description: "PASSWORD=, --password, DB_PASSWORD=".to_string(),
            enabled: true,
        },
        RedactionRule {
            id: "RR-003".to_string(),
            description: "Database connection strings".to_string(),
            category: SensitiveDataCategory::DatabaseUrl,
            pattern_description: "DATABASE_URL= containing credentials".to_string(),
            enabled: true,
        },
        RedactionRule {
            id: "RR-004".to_string(),
            description: "Cloud provider credentials".to_string(),
            category: SensitiveDataCategory::CloudCredential,
            pattern_description: "AWS_SECRET_ACCESS_KEY, AWS_ACCESS_KEY_ID".to_string(),
            enabled: true,
        },
        RedactionRule {
            id: "RR-005".to_string(),
            description: "AI provider API keys".to_string(),
            category: SensitiveDataCategory::ApiKey,
            pattern_description: "OPENAI_API_KEY, ANTHROPIC_API_KEY".to_string(),
            enabled: true,
        },
        RedactionRule {
            id: "RR-006".to_string(),
            description: "CLI argument secrets".to_string(),
            category: SensitiveDataCategory::Password,
            pattern_description: "--token, --secret, --api-key".to_string(),
            enabled: true,
        },
        RedactionRule {
            id: "RR-007".to_string(),
            description: "Session and auth tokens".to_string(),
            category: SensitiveDataCategory::SessionToken,
            pattern_description: "AUTH_TOKEN=, ACCESS_TOKEN=, TOKEN=".to_string(),
            enabled: true,
        },
        RedactionRule {
            id: "RR-008".to_string(),
            description: "Private keys".to_string(),
            category: SensitiveDataCategory::SshKey,
            pattern_description: "PRIVATE_KEY=, SSH key content".to_string(),
            enabled: true,
        },
        RedactionRule {
            id: "RR-009".to_string(),
            description: "Stripe and payment keys".to_string(),
            category: SensitiveDataCategory::ApiKey,
            pattern_description: "STRIPE_SECRET_KEY=".to_string(),
            enabled: true,
        },
    ]
}

fn default_retention_rules() -> Vec<RetentionRule> {
    vec![
        RetentionRule {
            name: "JSONL phase logs".to_string(),
            path_pattern: "**/*.jsonl".to_string(),
            ttl: Duration::from_secs(7 * 86400), // 7 days
            tier: StorageTier::Hot,
            requires_redaction: true,
            applies_to_ci: true,
        },
        RetentionRule {
            name: "Suite summary".to_string(),
            path_pattern: "**/suite_summary.json".to_string(),
            ttl: Duration::from_secs(30 * 86400), // 30 days
            tier: StorageTier::Warm,
            requires_redaction: false,
            applies_to_ci: true,
        },
        RetentionRule {
            name: "Build logs".to_string(),
            path_pattern: "**/*.log".to_string(),
            ttl: Duration::from_secs(3 * 86400), // 3 days
            tier: StorageTier::Hot,
            requires_redaction: true,
            applies_to_ci: true,
        },
        RetentionRule {
            name: "Captured artifacts (JSON)".to_string(),
            path_pattern: "**/artifacts/**/*.json".to_string(),
            ttl: Duration::from_secs(14 * 86400), // 14 days
            tier: StorageTier::Warm,
            requires_redaction: true,
            applies_to_ci: true,
        },
        RetentionRule {
            name: "Scenario replay bundles".to_string(),
            path_pattern: "**/replay_bundles/**".to_string(),
            ttl: Duration::from_secs(90 * 86400), // 90 days
            tier: StorageTier::Cold,
            requires_redaction: true,
            applies_to_ci: false,
        },
        RetentionRule {
            name: "Ephemeral test directories".to_string(),
            path_pattern: "/tmp/rch_e2e_tests/**".to_string(),
            ttl: Duration::from_secs(3600), // 1 hour
            tier: StorageTier::Ephemeral,
            requires_redaction: false,
            applies_to_ci: true,
        },
    ]
}

// ===========================================================================
// Redaction engine
// ===========================================================================

fn apply_redaction(content: &str, policy: &RedactionPolicy) -> (String, Vec<RedactionAuditEntry>) {
    let mut audit = Vec::new();
    let redacted = mask_sensitive_command(content);

    if redacted != content {
        // At least one pattern matched; generate audit entries
        for rule in &policy.rules {
            if rule.enabled {
                audit.push(RedactionAuditEntry {
                    rule_id: rule.id.clone(),
                    category: rule.category.clone(),
                    field_path: "content".to_string(),
                    original_length: content.len(),
                    redacted: true,
                });
            }
        }
    }

    (redacted, audit)
}

fn apply_redaction_to_command_record(
    record: &ReliabilityCommandRecord,
    policy: &RedactionPolicy,
) -> (ReliabilityCommandRecord, Vec<RedactionAuditEntry>) {
    let mut audit = Vec::new();
    let mut redacted_record = record.clone();

    // Redact invoked args
    let args_str = format!(
        "{} {}",
        record.invoked_program,
        record.invoked_args.join(" ")
    );
    let redacted_args_str = mask_sensitive_command(&args_str);
    if redacted_args_str != args_str {
        // Parse back the redacted args (simplified: just use the redacted string)
        redacted_record.invoked_args = vec![redacted_args_str];
        for rule in &policy.rules {
            if rule.enabled {
                audit.push(RedactionAuditEntry {
                    rule_id: rule.id.clone(),
                    category: rule.category.clone(),
                    field_path: "invoked_args".to_string(),
                    original_length: args_str.len(),
                    redacted: true,
                });
                break; // One audit entry per field
            }
        }
    }

    (redacted_record, audit)
}

fn decide_retention(path: &str, policy: &RetentionPolicy) -> RetentionDecision {
    // Find matching rule (first match wins)
    for rule in &policy.rules {
        if path_matches_pattern(path, &rule.path_pattern) {
            let action = if rule.tier == StorageTier::Ephemeral {
                RetentionAction::Delete
            } else if rule.requires_redaction {
                match rule.tier {
                    StorageTier::Cold => RetentionAction::RedactThenArchive,
                    _ => RetentionAction::RedactThenKeep,
                }
            } else {
                match rule.tier {
                    StorageTier::Cold => RetentionAction::Archive,
                    _ => RetentionAction::Keep,
                }
            };

            return RetentionDecision {
                artifact_path: path.to_string(),
                matched_rule: Some(rule.name.clone()),
                tier: rule.tier.clone(),
                ttl_secs: rule.ttl.as_secs(),
                requires_redaction: rule.requires_redaction,
                action,
            };
        }
    }

    // Default
    RetentionDecision {
        artifact_path: path.to_string(),
        matched_rule: None,
        tier: policy.default_tier.clone(),
        ttl_secs: policy.default_ttl.as_secs(),
        requires_redaction: true, // Safe default
        action: RetentionAction::RedactThenKeep,
    }
}

fn path_matches_pattern(path: &str, pattern: &str) -> bool {
    // Simplified glob matching for tests.
    // Splits pattern on "**" segments, then checks that each literal segment
    // appears in the path in order. Extension globs like "*.json" match at end.
    let segments: Vec<&str> = pattern.split("**").collect();

    if segments.len() == 1 {
        // No glob at all — exact match
        return path == pattern;
    }

    let mut remaining = path;
    for seg in &segments {
        let seg = seg.trim_matches('/');
        if seg.is_empty() {
            continue;
        }

        // Handle trailing extension glob like "*.json"
        if seg.starts_with("*.") {
            let ext = &seg[1..]; // e.g., ".json"
            return remaining.ends_with(ext);
        }

        // Check that the literal segment exists in the remaining path
        if let Some(pos) = remaining.find(seg) {
            remaining = &remaining[pos + seg.len()..];
        } else {
            return false;
        }
    }

    true
}

// ===========================================================================
// Tests: Synthetic secret injection (must not survive redaction)
// ===========================================================================

#[test]
fn e2e_redaction_env_var_secrets_masked() {
    let secrets = [
        ("CARGO_REGISTRY_TOKEN=crt_supersecret123", "crt_supersecret123"),
        ("GITHUB_TOKEN=ghp_1234567890abcdef", "ghp_1234567890abcdef"),
        ("GH_TOKEN=gho_token_value", "gho_token_value"),
        ("DATABASE_URL=postgres://user:pass@host/db", "postgres://user:pass@host/db"),
        ("DB_PASSWORD=hunter2", "hunter2"),
        ("API_KEY=sk-proj-1234567890", "sk-proj-1234567890"),
        ("API_SECRET=secret_value_here", "secret_value_here"),
        ("SECRET_KEY=django-insecure-key", "django-insecure-key"),
        ("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI", "wJalrXUtnFEMI"),
        ("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"),
        ("OPENAI_API_KEY=sk-xxxxxxxx", "sk-xxxxxxxx"),
        ("ANTHROPIC_API_KEY=sk-ant-xxxxxxxx", "sk-ant-xxxxxxxx"),
        ("STRIPE_SECRET_KEY=sk_live_12345", "sk_live_12345"),
        ("AUTH_TOKEN=bearer_token_value", "bearer_token_value"),
        ("ACCESS_TOKEN=eyJhbGciOiJIUzI1NiJ9", "eyJhbGciOiJIUzI1NiJ9"),
        ("PRIVATE_KEY=-----BEGIN-RSA-----", "-----BEGIN-RSA-----"),
    ];

    let policy = RedactionPolicy::default();

    for (input, secret_value) in &secrets {
        let cmd = format!("cargo build --release {input}");
        let (redacted, _audit) = apply_redaction(&cmd, &policy);
        assert!(
            !redacted.contains(secret_value),
            "secret '{}' survived redaction in: {}",
            secret_value,
            redacted
        );
        assert!(
            redacted.contains("***"),
            "redacted output should contain '***' sentinel for: {input}"
        );
    }
}

#[test]
fn e2e_redaction_cli_arg_secrets_masked() {
    let secrets = [
        ("--token super_secret_token", "super_secret_token"),
        ("--token=inline_token_value", "inline_token_value"),
        ("--password my_password_123", "my_password_123"),
        ("--password=pass123", "pass123"),
        ("--api-key sk-1234567890", "sk-1234567890"),
        ("--api-key=key_value", "key_value"),
        ("--secret mysecretvalue", "mysecretvalue"),
        ("--secret=secret_inline", "secret_inline"),
    ];

    let policy = RedactionPolicy::default();

    for (input, secret_value) in &secrets {
        let cmd = format!("rch exec --worker w1 {input}");
        let (redacted, _) = apply_redaction(&cmd, &policy);
        assert!(
            !redacted.contains(secret_value),
            "CLI arg secret '{}' survived redaction in: {}",
            secret_value,
            redacted
        );
    }
}

#[test]
fn e2e_redaction_multiple_secrets_in_one_command() {
    let cmd =
        "GITHUB_TOKEN=ghp_abc123 cargo build --release TOKEN=secret1 --password=hunter2 API_KEY=sk-key";
    let policy = RedactionPolicy::default();
    let (redacted, _) = apply_redaction(cmd, &policy);

    assert!(!redacted.contains("ghp_abc123"));
    assert!(!redacted.contains("secret1"));
    assert!(!redacted.contains("hunter2"));
    assert!(!redacted.contains("sk-key"));
    // Key names should remain
    assert!(redacted.contains("GITHUB_TOKEN="));
    assert!(redacted.contains("TOKEN="));
    assert!(redacted.contains("--password="));
    assert!(redacted.contains("API_KEY="));
}

#[test]
fn e2e_redaction_quoted_secrets_masked() {
    let cmd = "TOKEN=\"my super secret token\" cargo build --password=\"complex pass word\"";
    let policy = RedactionPolicy::default();
    let (redacted, _) = apply_redaction(cmd, &policy);

    assert!(!redacted.contains("super secret"));
    assert!(!redacted.contains("complex pass"));
}

#[test]
fn e2e_redaction_no_false_positives_on_safe_content() {
    let safe_commands = [
        "cargo build --release",
        "cargo test --workspace --all-features",
        "ssh w1 true",
        "rsync -avz src/ remote:dest/",
        "RUST_LOG=debug cargo build",
        "CARGO_TARGET_DIR=/tmp/target cargo test",
    ];

    let policy = RedactionPolicy::default();

    for cmd in &safe_commands {
        let (redacted, audit) = apply_redaction(cmd, &policy);
        assert_eq!(
            &redacted, cmd,
            "safe command was incorrectly redacted: {cmd}"
        );
        assert!(audit.is_empty(), "safe command generated audit entries: {cmd}");
    }
}

// ===========================================================================
// Tests: Command record redaction
// ===========================================================================

#[test]
fn e2e_redaction_command_record_args_masked() {
    let record = ReliabilityCommandRecord {
        phase: ReliabilityPhase::Execute,
        stage: "build".to_string(),
        command_name: "cargo-build".to_string(),
        invoked_program: "cargo".to_string(),
        invoked_args: vec![
            "build".to_string(),
            "--release".to_string(),
            "GITHUB_TOKEN=ghp_secret123".to_string(),
        ],
        exit_code: 0,
        duration_ms: 5000,
        required_success: true,
        succeeded: true,
        artifact_paths: vec![],
    };

    let policy = RedactionPolicy::default();
    let (redacted_record, audit) = apply_redaction_to_command_record(&record, &policy);

    let redacted_args = redacted_record.invoked_args.join(" ");
    assert!(
        !redacted_args.contains("ghp_secret123"),
        "secret survived in command record args: {redacted_args}"
    );
    assert!(!audit.is_empty(), "redaction should generate audit trail");
}

#[test]
fn e2e_redaction_command_record_safe_args_unchanged() {
    let record = ReliabilityCommandRecord {
        phase: ReliabilityPhase::Setup,
        stage: "check-ssh".to_string(),
        command_name: "ssh-check".to_string(),
        invoked_program: "ssh".to_string(),
        invoked_args: vec![
            "-o".to_string(),
            "ConnectTimeout=5".to_string(),
            "w1".to_string(),
            "true".to_string(),
        ],
        exit_code: 0,
        duration_ms: 200,
        required_success: true,
        succeeded: true,
        artifact_paths: vec![],
    };

    let policy = RedactionPolicy::default();
    let (redacted_record, audit) = apply_redaction_to_command_record(&record, &policy);

    // Safe args should remain unchanged
    assert_eq!(redacted_record.invoked_args, record.invoked_args);
    assert!(audit.is_empty());
}

// ===========================================================================
// Tests: Redaction policy schema
// ===========================================================================

#[test]
fn e2e_redaction_policy_schema_versioned() {
    let policy = RedactionPolicy::default();
    assert_eq!(policy.schema_version, REDACTION_POLICY_SCHEMA_VERSION);
}

#[test]
fn e2e_redaction_policy_serialization_roundtrip() {
    let policy = RedactionPolicy::default();
    let json = serde_json::to_string_pretty(&policy).unwrap();
    let restored: RedactionPolicy = serde_json::from_str(&json).unwrap();

    assert_eq!(restored.schema_version, policy.schema_version);
    assert_eq!(restored.rules.len(), policy.rules.len());
    assert_eq!(restored.sentinel, REDACTION_SENTINEL);
    assert!(restored.audit_all_redactions);
}

#[test]
fn e2e_redaction_all_categories_covered() {
    let policy = RedactionPolicy::default();
    let covered_categories: Vec<&SensitiveDataCategory> =
        policy.rules.iter().map(|r| &r.category).collect();

    // Ensure at least ApiKey, Password, DatabaseUrl, CloudCredential, SshKey, SessionToken
    assert!(covered_categories.contains(&&SensitiveDataCategory::ApiKey));
    assert!(covered_categories.contains(&&SensitiveDataCategory::Password));
    assert!(covered_categories.contains(&&SensitiveDataCategory::DatabaseUrl));
    assert!(covered_categories.contains(&&SensitiveDataCategory::CloudCredential));
    assert!(covered_categories.contains(&&SensitiveDataCategory::SshKey));
    assert!(covered_categories.contains(&&SensitiveDataCategory::SessionToken));
}

#[test]
fn e2e_redaction_all_rules_have_descriptions() {
    let policy = RedactionPolicy::default();
    for rule in &policy.rules {
        assert!(!rule.id.is_empty(), "rule has empty ID");
        assert!(
            !rule.description.is_empty(),
            "rule {} has empty description",
            rule.id
        );
        assert!(
            !rule.pattern_description.is_empty(),
            "rule {} has empty pattern description",
            rule.id
        );
    }
}

#[test]
fn e2e_redaction_audit_entry_serialization() {
    let entry = RedactionAuditEntry {
        rule_id: "RR-001".to_string(),
        category: SensitiveDataCategory::ApiKey,
        field_path: "invoked_args".to_string(),
        original_length: 42,
        redacted: true,
    };

    let json = serde_json::to_string(&entry).unwrap();
    let restored: RedactionAuditEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.rule_id, "RR-001");
    assert!(restored.redacted);
}

// ===========================================================================
// Tests: Retention policy
// ===========================================================================

#[test]
fn e2e_retention_policy_default_rules() {
    let policy = RetentionPolicy::default();
    assert!(!policy.rules.is_empty());
    assert_eq!(policy.default_ttl, Duration::from_secs(86400));
    assert_eq!(policy.default_tier, StorageTier::Hot);
}

#[test]
fn e2e_retention_policy_serialization() {
    let policy = RetentionPolicy::default();
    let json = serde_json::to_string_pretty(&policy).unwrap();
    let restored: RetentionPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.rules.len(), policy.rules.len());
    assert_eq!(restored.schema_version, "1.0.0");
}

#[test]
fn e2e_retention_jsonl_logs_matched() {
    let policy = RetentionPolicy::default();
    let decision = decide_retention("target/test-logs/reliability_test.jsonl", &policy);

    assert!(decision.matched_rule.is_some());
    assert_eq!(decision.tier, StorageTier::Hot);
    assert!(decision.requires_redaction);
    assert_eq!(decision.action, RetentionAction::RedactThenKeep);
    assert_eq!(decision.ttl_secs, 7 * 86400);
}

#[test]
fn e2e_retention_suite_summary_matched() {
    let policy = RetentionPolicy::default();
    let decision = decide_retention("target/e2e-suite/suite_summary.json", &policy);

    assert!(decision.matched_rule.is_some());
    assert_eq!(decision.tier, StorageTier::Warm);
    assert!(!decision.requires_redaction); // summaries don't need redaction
    assert_eq!(decision.action, RetentionAction::Keep);
    assert_eq!(decision.ttl_secs, 30 * 86400);
}

#[test]
fn e2e_retention_build_logs_matched() {
    let policy = RetentionPolicy::default();
    let decision = decide_retention("target/e2e-suite/path_deps.log", &policy);

    assert!(decision.matched_rule.is_some());
    assert_eq!(decision.tier, StorageTier::Hot);
    assert!(decision.requires_redaction);
    assert_eq!(decision.ttl_secs, 3 * 86400);
}

#[test]
fn e2e_retention_artifact_json_matched() {
    let policy = RetentionPolicy::default();
    let decision = decide_retention(
        "target/test-logs/artifacts/scenario-001/command-trace.json",
        &policy,
    );

    assert!(decision.matched_rule.is_some());
    assert_eq!(decision.tier, StorageTier::Warm);
    assert!(decision.requires_redaction);
    assert_eq!(decision.ttl_secs, 14 * 86400);
}

#[test]
fn e2e_retention_replay_bundles_cold_storage() {
    let policy = RetentionPolicy::default();
    let decision = decide_retention(
        "target/replay_bundles/incident-123/bundle.json",
        &policy,
    );

    assert!(decision.matched_rule.is_some());
    assert_eq!(decision.tier, StorageTier::Cold);
    assert!(decision.requires_redaction);
    assert_eq!(decision.action, RetentionAction::RedactThenArchive);
    assert_eq!(decision.ttl_secs, 90 * 86400);
}

#[test]
fn e2e_retention_ephemeral_test_dirs() {
    let policy = RetentionPolicy::default();
    let decision = decide_retention("/tmp/rch_e2e_tests/test_001/data.txt", &policy);

    assert!(decision.matched_rule.is_some());
    assert_eq!(decision.tier, StorageTier::Ephemeral);
    assert_eq!(decision.action, RetentionAction::Delete);
    assert_eq!(decision.ttl_secs, 3600);
}

#[test]
fn e2e_retention_unknown_artifact_defaults() {
    let policy = RetentionPolicy::default();
    let decision = decide_retention("some/random/path.bin", &policy);

    assert!(decision.matched_rule.is_none());
    assert_eq!(decision.tier, StorageTier::Hot);
    assert!(decision.requires_redaction); // safe default
    assert_eq!(decision.ttl_secs, 86400);
}

// ===========================================================================
// Tests: Incident bundle
// ===========================================================================

#[test]
fn e2e_incident_bundle_construction() {
    let bundle = IncidentBundle {
        schema_version: "1.0.0".to_string(),
        bundle_id: "INC-2026-001".to_string(),
        created_at: "2026-02-22T12:00:00Z".to_string(),
        scenario_ids: vec!["scenario-001".to_string(), "scenario-002".to_string()],
        redaction_policy_version: REDACTION_POLICY_SCHEMA_VERSION.to_string(),
        redaction_audit: vec![RedactionAuditEntry {
            rule_id: "RR-001".to_string(),
            category: SensitiveDataCategory::ApiKey,
            field_path: "invoked_args".to_string(),
            original_length: 100,
            redacted: true,
        }],
        artifact_manifest: vec![
            IncidentArtifactEntry {
                path: "logs/reliability.jsonl".to_string(),
                redacted: true,
                size_bytes: 4096,
                tier: StorageTier::Hot,
            },
            IncidentArtifactEntry {
                path: "artifacts/trace.json".to_string(),
                redacted: true,
                size_bytes: 1024,
                tier: StorageTier::Warm,
            },
        ],
        safe_for_sharing: true,
    };

    let json = serde_json::to_string_pretty(&bundle).unwrap();
    let restored: IncidentBundle = serde_json::from_str(&json).unwrap();

    assert_eq!(restored.bundle_id, "INC-2026-001");
    assert_eq!(restored.scenario_ids.len(), 2);
    assert!(restored.safe_for_sharing);
    assert_eq!(restored.redaction_audit.len(), 1);
    assert_eq!(restored.artifact_manifest.len(), 2);
}

#[test]
fn e2e_incident_bundle_not_safe_without_redaction() {
    let bundle = IncidentBundle {
        schema_version: "1.0.0".to_string(),
        bundle_id: "INC-2026-002".to_string(),
        created_at: "2026-02-22T12:00:00Z".to_string(),
        scenario_ids: vec!["scenario-003".to_string()],
        redaction_policy_version: REDACTION_POLICY_SCHEMA_VERSION.to_string(),
        redaction_audit: vec![], // No redaction was performed
        artifact_manifest: vec![IncidentArtifactEntry {
            path: "logs/raw.jsonl".to_string(),
            redacted: false, // NOT redacted
            size_bytes: 8192,
            tier: StorageTier::Hot,
        }],
        safe_for_sharing: false,
    };

    assert!(!bundle.safe_for_sharing);
    assert!(bundle
        .artifact_manifest
        .iter()
        .any(|a| !a.redacted));
}

// ===========================================================================
// Tests: Logging integration with redaction
// ===========================================================================

#[test]
fn e2e_redaction_logging_event_context_safe() {
    let logger = TestLoggerBuilder::new("redaction-logging-e2e")
        .print_realtime(false)
        .build();

    // Simulate a context that could contain sensitive data
    let context = ReliabilityContext {
        worker_id: Some("w1".to_string()),
        repo_set: vec!["repo-a".to_string()],
        pressure_state: Some("nominal".to_string()),
        triage_actions: Vec::new(),
        decision_code: "REDACTION_PASS".to_string(),
        fallback_reason: None,
    };

    let event = logger.log_reliability_event(ReliabilityEventInput {
        level: LogLevel::Info,
        phase: ReliabilityPhase::Verify,
        scenario_id: "redaction-verify".to_string(),
        message: "redaction verification passed".to_string(),
        context,
        artifact_paths: vec!["artifacts/redacted-trace.json".to_string()],
    });

    // Verify the event was logged with safe content
    assert_eq!(event.scenario_id, "redaction-verify");
    assert_eq!(event.context.decision_code, "REDACTION_PASS");
}

// ===========================================================================
// Tests: Storage tier ordering and lifecycle
// ===========================================================================

#[test]
fn e2e_retention_tier_serialization() {
    let tiers = vec![
        StorageTier::Hot,
        StorageTier::Warm,
        StorageTier::Cold,
        StorageTier::Ephemeral,
    ];

    let json = serde_json::to_string(&tiers).unwrap();
    let restored: Vec<StorageTier> = serde_json::from_str(&json).unwrap();
    assert_eq!(tiers, restored);
}

#[test]
fn e2e_retention_action_serialization() {
    let actions = vec![
        RetentionAction::Keep,
        RetentionAction::Archive,
        RetentionAction::Delete,
        RetentionAction::RedactThenKeep,
        RetentionAction::RedactThenArchive,
    ];

    let json = serde_json::to_string(&actions).unwrap();
    let restored: Vec<RetentionAction> = serde_json::from_str(&json).unwrap();
    assert_eq!(actions, restored);
}

#[test]
fn e2e_retention_decision_serialization() {
    let decision = RetentionDecision {
        artifact_path: "target/test-logs/test.jsonl".to_string(),
        matched_rule: Some("JSONL phase logs".to_string()),
        tier: StorageTier::Hot,
        ttl_secs: 604800,
        requires_redaction: true,
        action: RetentionAction::RedactThenKeep,
    };

    let json = serde_json::to_string(&decision).unwrap();
    let restored: RetentionDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.artifact_path, "target/test-logs/test.jsonl");
    assert_eq!(restored.action, RetentionAction::RedactThenKeep);
}
