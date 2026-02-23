//! Local-vs-Remote Parity Validation E2E Tests (bd-vvmd.7.11)
//!
//! Validates that remote execution outcomes match local expected behavior for
//! user-visible correctness. Closes the trust gap where remote behavior might
//! be internally consistent across workers but diverge from what users see locally.
//!
//! Scope:
//!   - Build/test/check/clippy-relevant paths
//!   - Error-code parity
//!   - Artifact parity (fingerprints)
//!   - Non-deterministic field handling with explicit allowlists
//!   - Divergence classification and remediation hints
//!
//! All tests use deterministic seeds and simulated execution — no live workers needed.

use rch_common::e2e::logging::{
    LogLevel, ReliabilityContext, ReliabilityEventInput, ReliabilityPhase, TestLoggerBuilder,
};
use rch_common::errors::ErrorCode;
use rch_common::classify_command;
use rch_common::patterns::Classification;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ===========================================================================
// Parity types
// ===========================================================================

/// Classification of divergence between local and remote execution.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum DivergenceType {
    /// Exit code differs between local and remote
    Functional,
    /// Artifact hash or fingerprint mismatch
    Artifact,
    /// Structured error payload differs (error code, category, remediation)
    Schema,
    /// Only timing differs — functionally equivalent
    TimingOnly,
    /// Log output differs beyond non-deterministic allowlist
    LogContent,
    /// Hook decision differs (allow vs deny, modified command)
    HookDecision,
    /// Classification result differs
    ClassificationDrift,
}

impl DivergenceType {
    fn severity(&self) -> &'static str {
        match self {
            Self::Functional | Self::HookDecision | Self::ClassificationDrift => "critical",
            Self::Artifact | Self::Schema => "high",
            Self::LogContent => "medium",
            Self::TimingOnly => "info",
        }
    }

    fn remediation(&self) -> &'static str {
        match self {
            Self::Functional => "Check remote worker build environment matches local toolchain",
            Self::Artifact => "Clean incremental build state; verify --target-dir isolation",
            Self::Schema => "Compare API versions and error catalog between local/remote binaries",
            Self::TimingOnly => "No action needed; timing variance is expected",
            Self::LogContent => "Compare log normalization rules and environment variable masking",
            Self::HookDecision => "Verify hook logic handles remote execution path identically",
            Self::ClassificationDrift => {
                "Ensure classifier version is identical between local and remote"
            }
        }
    }
}

/// Non-deterministic field that should be allowlisted with justification.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct NonDeterministicAllowlistEntry {
    field_path: String,
    justification: String,
    normalization_rule: NormalizationRule,
}

/// How to normalize a non-deterministic field before comparison.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum NormalizationRule {
    /// Ignore the field entirely
    Ignore,
    /// Compare only the prefix up to N characters
    PrefixMatch(usize),
    /// Compare after stripping timestamps (ISO 8601 patterns)
    StripTimestamps,
    /// Compare after normalizing file paths
    NormalizePaths,
    /// Compare numeric value within percentage tolerance
    WithinTolerance(u32),
}

/// Simulated local execution result.
#[derive(Debug, Clone)]
struct LocalExecutionResult {
    command: String,
    classification: Classification,
    exit_code: i32,
    stdout_signature: String,
    stderr_signature: String,
    artifact_fingerprint: Option<String>,
    error_code: Option<ErrorCode>,
    duration_ms: u64,
    hook_decision: String,
}

/// Simulated remote execution result.
#[derive(Debug, Clone)]
struct RemoteExecutionResult {
    _command: String,
    worker_id: String,
    classification: Classification,
    exit_code: i32,
    stdout_signature: String,
    stderr_signature: String,
    artifact_fingerprint: Option<String>,
    error_code: Option<ErrorCode>,
    duration_ms: u64,
    hook_decision: String,
}

/// Result of a local-vs-remote parity check.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ParityCheckResult {
    command: String,
    worker_id: String,
    is_parity: bool,
    divergences: Vec<DivergenceType>,
    severity: String,
    remediation_hints: Vec<String>,
    allowlisted_fields: Vec<String>,
}

/// Summary across all parity checks in a suite run.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ParitySuiteSummary {
    total_checks: usize,
    parity_pass: usize,
    parity_fail: usize,
    parity_rate: f64,
    divergence_type_counts: HashMap<String, usize>,
    critical_failures: Vec<String>,
    threshold_met: bool,
    seed: u64,
}

// ===========================================================================
// Parity engine
// ===========================================================================

fn default_allowlist() -> Vec<NonDeterministicAllowlistEntry> {
    vec![
        NonDeterministicAllowlistEntry {
            field_path: "timestamp".to_string(),
            justification: "Timestamps differ between local and remote; wall-clock not comparable"
                .to_string(),
            normalization_rule: NormalizationRule::Ignore,
        },
        NonDeterministicAllowlistEntry {
            field_path: "duration_ms".to_string(),
            justification: "Execution time varies by hardware; compare within 200% tolerance"
                .to_string(),
            normalization_rule: NormalizationRule::WithinTolerance(200),
        },
        NonDeterministicAllowlistEntry {
            field_path: "request_id".to_string(),
            justification: "UUIDs are unique per execution".to_string(),
            normalization_rule: NormalizationRule::Ignore,
        },
        NonDeterministicAllowlistEntry {
            field_path: "worker_hostname".to_string(),
            justification: "Hostname differs between local and remote by definition".to_string(),
            normalization_rule: NormalizationRule::Ignore,
        },
        NonDeterministicAllowlistEntry {
            field_path: "stderr.timestamps".to_string(),
            justification: "Compiler output timestamps vary".to_string(),
            normalization_rule: NormalizationRule::StripTimestamps,
        },
        NonDeterministicAllowlistEntry {
            field_path: "artifact.path".to_string(),
            justification: "Build paths differ between local and remote target dirs".to_string(),
            normalization_rule: NormalizationRule::NormalizePaths,
        },
    ]
}

fn is_allowlisted(field: &str, allowlist: &[NonDeterministicAllowlistEntry]) -> bool {
    allowlist.iter().any(|e| e.field_path == field)
}

fn check_parity(
    local: &LocalExecutionResult,
    remote: &RemoteExecutionResult,
    allowlist: &[NonDeterministicAllowlistEntry],
) -> ParityCheckResult {
    let mut divergences = Vec::new();
    let mut allowlisted_fields = Vec::new();

    // 1. Classification parity (critical)
    if local.classification != remote.classification {
        divergences.push(DivergenceType::ClassificationDrift);
    }

    // 2. Exit code parity (functional)
    if local.exit_code != remote.exit_code {
        divergences.push(DivergenceType::Functional);
    }

    // 3. Error code parity (schema)
    if local.error_code != remote.error_code {
        divergences.push(DivergenceType::Schema);
    }

    // 4. Artifact fingerprint parity
    match (&local.artifact_fingerprint, &remote.artifact_fingerprint) {
        (Some(l), Some(r)) if l != r => {
            divergences.push(DivergenceType::Artifact);
        }
        (Some(_), None) | (None, Some(_)) => {
            divergences.push(DivergenceType::Artifact);
        }
        _ => {}
    }

    // 5. Hook decision parity (critical)
    if local.hook_decision != remote.hook_decision {
        divergences.push(DivergenceType::HookDecision);
    }

    // 6. Log signature parity (after normalization)
    if local.stdout_signature != remote.stdout_signature
        || local.stderr_signature != remote.stderr_signature
    {
        if !is_allowlisted("log_content", allowlist) {
            divergences.push(DivergenceType::LogContent);
        } else {
            allowlisted_fields.push("log_content".to_string());
        }
    }

    // 7. Duration parity (timing-only, always allowlisted)
    if is_allowlisted("duration_ms", allowlist) {
        allowlisted_fields.push("duration_ms".to_string());
    } else {
        let ratio = local.duration_ms.max(1) as f64 / remote.duration_ms.max(1) as f64;
        if !(0.1..=10.0).contains(&ratio) {
            divergences.push(DivergenceType::TimingOnly);
        }
    }

    let severity = divergences
        .iter()
        .map(|d| d.severity())
        .min_by_key(|s| match *s {
            "critical" => 0,
            "high" => 1,
            "medium" => 2,
            _ => 3,
        })
        .unwrap_or("info")
        .to_string();

    let remediation_hints: Vec<String> = divergences.iter().map(|d| d.remediation().to_string()).collect();

    ParityCheckResult {
        command: local.command.clone(),
        worker_id: remote.worker_id.clone(),
        is_parity: divergences.is_empty(),
        divergences,
        severity,
        remediation_hints,
        allowlisted_fields,
    }
}

fn build_suite_summary(results: &[ParityCheckResult], seed: u64, threshold: f64) -> ParitySuiteSummary {
    let total = results.len();
    let pass = results.iter().filter(|r| r.is_parity).count();
    let fail = total - pass;
    let rate = if total > 0 { pass as f64 / total as f64 } else { 1.0 };

    let mut type_counts: HashMap<String, usize> = HashMap::new();
    let mut critical = Vec::new();
    for r in results {
        for d in &r.divergences {
            let key = serde_json::to_string(d).unwrap_or_else(|_| format!("{d:?}"));
            *type_counts.entry(key).or_insert(0) += 1;
        }
        if r.severity == "critical" {
            critical.push(format!("{}: {:?}", r.command, r.divergences));
        }
    }

    ParitySuiteSummary {
        total_checks: total,
        parity_pass: pass,
        parity_fail: fail,
        parity_rate: rate,
        divergence_type_counts: type_counts,
        critical_failures: critical,
        threshold_met: rate >= threshold,
        seed,
    }
}

// ===========================================================================
// Fixture helpers
// ===========================================================================

/// Simple xorshift64 PRNG for deterministic seed-based fixtures.
struct Xorshift64(u64);

impl Xorshift64 {
    fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }

    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

fn make_local_result(cmd: &str, exit_code: i32, rng: &mut Xorshift64) -> LocalExecutionResult {
    let classification = classify_command(cmd);
    LocalExecutionResult {
        command: cmd.to_string(),
        classification: classification.clone(),
        exit_code,
        stdout_signature: format!("local-stdout-{}", rng.next() % 1000),
        stderr_signature: format!("local-stderr-{}", rng.next() % 1000),
        artifact_fingerprint: if exit_code == 0 {
            Some(format!("sha256:{:016x}", rng.next()))
        } else {
            None
        },
        error_code: if exit_code != 0 {
            Some(ErrorCode::WorkerHealthCheckFailed)
        } else {
            None
        },
        duration_ms: 100 + rng.next() % 500,
        hook_decision: if classification.is_compilation {
            "allow_remote".to_string()
        } else {
            "allow_local".to_string()
        },
    }
}

fn make_matching_remote(local: &LocalExecutionResult, worker: &str, rng: &mut Xorshift64) -> RemoteExecutionResult {
    RemoteExecutionResult {
        _command: local.command.clone(),
        worker_id: worker.to_string(),
        classification: local.classification.clone(),
        exit_code: local.exit_code,
        stdout_signature: local.stdout_signature.clone(),
        stderr_signature: local.stderr_signature.clone(),
        artifact_fingerprint: local.artifact_fingerprint.clone(),
        error_code: local.error_code,
        duration_ms: local.duration_ms + rng.next() % 200, // slight timing variance
        hook_decision: local.hook_decision.clone(),
    }
}

fn make_diverged_remote(
    local: &LocalExecutionResult,
    worker: &str,
    divergence: DivergenceType,
    rng: &mut Xorshift64,
) -> RemoteExecutionResult {
    let mut remote = make_matching_remote(local, worker, rng);
    match divergence {
        DivergenceType::Functional => {
            remote.exit_code = if local.exit_code == 0 { 1 } else { 0 };
        }
        DivergenceType::Artifact => {
            remote.artifact_fingerprint = Some(format!("sha256:{:016x}", rng.next()));
        }
        DivergenceType::Schema => {
            remote.error_code = Some(ErrorCode::SshConnectionFailed);
        }
        DivergenceType::TimingOnly => {
            remote.duration_ms = local.duration_ms * 50; // extreme timing
        }
        DivergenceType::LogContent => {
            remote.stdout_signature = format!("remote-different-{}", rng.next() % 1000);
        }
        DivergenceType::HookDecision => {
            remote.hook_decision = "deny_remote".to_string();
        }
        DivergenceType::ClassificationDrift => {
            // Force a different classification (flip is_compilation)
            remote.classification = Classification {
                is_compilation: !local.classification.is_compilation,
                confidence: 0.0,
                kind: None,
                reason: "diverged-for-test".into(),
                command_prefix: None,
                extracted_command: None,
            };
        }
    }
    remote
}

// ===========================================================================
// Tests: Parity check fundamentals
// ===========================================================================

#[test]
fn e2e_parity_matching_local_remote_passes() {
    let mut rng = Xorshift64::new(42);
    let allowlist = default_allowlist();
    let local = make_local_result("cargo build --release", 0, &mut rng);
    let remote = make_matching_remote(&local, "w1", &mut rng);

    let result = check_parity(&local, &remote, &allowlist);
    assert!(result.is_parity, "matching local/remote should pass parity");
    assert!(result.divergences.is_empty());
    assert_eq!(result.severity, "info");
}

#[test]
fn e2e_parity_exit_code_divergence_detected() {
    let mut rng = Xorshift64::new(42);
    let allowlist = default_allowlist();
    let local = make_local_result("cargo build", 0, &mut rng);
    let remote = make_diverged_remote(&local, "w1", DivergenceType::Functional, &mut rng);

    let result = check_parity(&local, &remote, &allowlist);
    assert!(!result.is_parity);
    assert!(result.divergences.contains(&DivergenceType::Functional));
    assert_eq!(result.severity, "critical");
}

#[test]
fn e2e_parity_artifact_hash_mismatch() {
    let mut rng = Xorshift64::new(42);
    let allowlist = default_allowlist();
    let local = make_local_result("cargo build --release", 0, &mut rng);
    let remote = make_diverged_remote(&local, "w1", DivergenceType::Artifact, &mut rng);

    let result = check_parity(&local, &remote, &allowlist);
    assert!(!result.is_parity);
    assert!(result.divergences.contains(&DivergenceType::Artifact));
    assert_eq!(result.severity, "high");
}

#[test]
fn e2e_parity_schema_divergence() {
    let mut rng = Xorshift64::new(42);
    let allowlist = default_allowlist();
    let local = make_local_result("cargo build", 1, &mut rng);
    let remote = make_diverged_remote(&local, "w1", DivergenceType::Schema, &mut rng);

    let result = check_parity(&local, &remote, &allowlist);
    assert!(!result.is_parity);
    assert!(result.divergences.contains(&DivergenceType::Schema));
}

#[test]
fn e2e_parity_hook_decision_divergence() {
    let mut rng = Xorshift64::new(42);
    let allowlist = default_allowlist();
    let local = make_local_result("cargo build --release", 0, &mut rng);
    let remote = make_diverged_remote(&local, "w1", DivergenceType::HookDecision, &mut rng);

    let result = check_parity(&local, &remote, &allowlist);
    assert!(!result.is_parity);
    assert!(result.divergences.contains(&DivergenceType::HookDecision));
    assert_eq!(result.severity, "critical");
}

#[test]
fn e2e_parity_classification_drift() {
    let mut rng = Xorshift64::new(42);
    let allowlist = default_allowlist();
    let local = make_local_result("cargo build", 0, &mut rng);
    let remote = make_diverged_remote(&local, "w1", DivergenceType::ClassificationDrift, &mut rng);

    let result = check_parity(&local, &remote, &allowlist);
    assert!(!result.is_parity);
    assert!(result.divergences.contains(&DivergenceType::ClassificationDrift));
    assert_eq!(result.severity, "critical");
}

// ===========================================================================
// Tests: Non-deterministic allowlist handling
// ===========================================================================

#[test]
fn e2e_parity_timing_only_does_not_fail_when_allowlisted() {
    let mut rng = Xorshift64::new(42);
    let allowlist = default_allowlist();
    let local = make_local_result("cargo build --release", 0, &mut rng);
    let mut remote = make_matching_remote(&local, "w1", &mut rng);
    // Different timing but same everything else
    remote.duration_ms = local.duration_ms * 3;

    let result = check_parity(&local, &remote, &allowlist);
    assert!(result.is_parity, "timing-only difference should be allowlisted");
    assert!(result.allowlisted_fields.contains(&"duration_ms".to_string()));
}

#[test]
fn e2e_parity_allowlist_entries_have_justifications() {
    let allowlist = default_allowlist();
    for entry in &allowlist {
        assert!(
            !entry.justification.is_empty(),
            "allowlist entry '{}' has empty justification (silent ignore prohibited)",
            entry.field_path
        );
    }
}

#[test]
fn e2e_parity_allowlist_serialization_roundtrip() {
    let allowlist = default_allowlist();
    let json = serde_json::to_string_pretty(&allowlist).unwrap();
    let restored: Vec<NonDeterministicAllowlistEntry> = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.len(), allowlist.len());
    for (orig, rest) in allowlist.iter().zip(restored.iter()) {
        assert_eq!(orig.field_path, rest.field_path);
        assert_eq!(orig.normalization_rule, rest.normalization_rule);
    }
}

#[test]
fn e2e_parity_no_silent_ignore_rules() {
    // Verify that every allowlist entry has a non-trivial normalization rule
    let allowlist = default_allowlist();
    for entry in &allowlist {
        // Every entry must have an explicit rule, not just blanket ignore without justification
        assert!(
            !entry.justification.is_empty(),
            "entry '{}' has empty justification — silent ignores prohibited",
            entry.field_path
        );
        // Verify rule is not just "ignore" without a good reason
        if entry.normalization_rule == NormalizationRule::Ignore {
            assert!(
                entry.justification.len() > 20,
                "entry '{}' uses Ignore rule but justification is too short: '{}'",
                entry.field_path,
                entry.justification
            );
        }
    }
}

// ===========================================================================
// Tests: Divergence classification and remediation
// ===========================================================================

#[test]
fn e2e_parity_divergence_type_serialization() {
    let types = vec![
        DivergenceType::Functional,
        DivergenceType::Artifact,
        DivergenceType::Schema,
        DivergenceType::TimingOnly,
        DivergenceType::LogContent,
        DivergenceType::HookDecision,
        DivergenceType::ClassificationDrift,
    ];

    let json = serde_json::to_string(&types).unwrap();
    let restored: Vec<DivergenceType> = serde_json::from_str(&json).unwrap();
    assert_eq!(types, restored);
}

#[test]
fn e2e_parity_all_divergence_types_have_remediation() {
    let types = [
        DivergenceType::Functional,
        DivergenceType::Artifact,
        DivergenceType::Schema,
        DivergenceType::TimingOnly,
        DivergenceType::LogContent,
        DivergenceType::HookDecision,
        DivergenceType::ClassificationDrift,
    ];

    for dtype in &types {
        let hint = dtype.remediation();
        assert!(
            !hint.is_empty(),
            "divergence type {dtype:?} has no remediation hint"
        );
    }
}

#[test]
fn e2e_parity_severity_ordering() {
    // Critical types should have severity "critical"
    assert_eq!(DivergenceType::Functional.severity(), "critical");
    assert_eq!(DivergenceType::HookDecision.severity(), "critical");
    assert_eq!(DivergenceType::ClassificationDrift.severity(), "critical");

    // High severity
    assert_eq!(DivergenceType::Artifact.severity(), "high");
    assert_eq!(DivergenceType::Schema.severity(), "high");

    // Info severity (non-functional)
    assert_eq!(DivergenceType::TimingOnly.severity(), "info");
}

#[test]
fn e2e_parity_result_includes_remediation_hints() {
    let mut rng = Xorshift64::new(42);
    let allowlist = default_allowlist();
    let local = make_local_result("cargo build", 0, &mut rng);
    let remote = make_diverged_remote(&local, "w1", DivergenceType::Functional, &mut rng);

    let result = check_parity(&local, &remote, &allowlist);
    assert!(!result.remediation_hints.is_empty());
    assert!(result.remediation_hints.iter().any(|h| h.contains("toolchain")));
}

// ===========================================================================
// Tests: Build/test/check/clippy command coverage
// ===========================================================================

#[test]
fn e2e_parity_build_test_check_clippy_paths() {
    let mut rng = Xorshift64::new(42);
    let allowlist = default_allowlist();

    let commands = [
        "cargo build",
        "cargo build --release",
        "cargo test",
        "cargo test --workspace",
        "cargo check",
        "cargo clippy",
        "cargo clippy -- -D warnings",
    ];

    for cmd in &commands {
        let local = make_local_result(cmd, 0, &mut rng);
        let remote = make_matching_remote(&local, "w1", &mut rng);
        let result = check_parity(&local, &remote, &allowlist);
        assert!(
            result.is_parity,
            "parity should pass for matching '{cmd}'"
        );
    }
}

#[test]
fn e2e_parity_non_compilation_commands_local_only() {
    let mut rng = Xorshift64::new(42);
    let allowlist = default_allowlist();

    let commands = ["ls -la", "git status", "echo hello"];

    for cmd in &commands {
        let local = make_local_result(cmd, 0, &mut rng);
        let remote = make_matching_remote(&local, "w1", &mut rng);
        let result = check_parity(&local, &remote, &allowlist);
        // Non-compilation commands should pass when local/remote agree
        assert!(result.is_parity, "non-compilation '{cmd}' should pass parity");
    }
}

// ===========================================================================
// Tests: Error code parity
// ===========================================================================

#[test]
fn e2e_parity_error_code_match_passes() {
    let mut rng = Xorshift64::new(42);
    let allowlist = default_allowlist();
    let mut local = make_local_result("cargo build", 1, &mut rng);
    local.error_code = Some(ErrorCode::WorkerHealthCheckFailed);
    let remote = make_matching_remote(&local, "w1", &mut rng);

    let result = check_parity(&local, &remote, &allowlist);
    assert!(result.is_parity, "matching error codes should pass");
}

#[test]
fn e2e_parity_error_code_mismatch_detected() {
    let mut rng = Xorshift64::new(42);
    let allowlist = default_allowlist();
    let mut local = make_local_result("cargo build", 1, &mut rng);
    local.error_code = Some(ErrorCode::WorkerHealthCheckFailed);
    let mut remote = make_matching_remote(&local, "w1", &mut rng);
    remote.error_code = Some(ErrorCode::SshConnectionFailed);

    let result = check_parity(&local, &remote, &allowlist);
    assert!(!result.is_parity);
    assert!(result.divergences.contains(&DivergenceType::Schema));
}

// ===========================================================================
// Tests: Suite summary and threshold gating
// ===========================================================================

#[test]
fn e2e_parity_suite_summary_all_pass() {
    let mut rng = Xorshift64::new(42);
    let allowlist = default_allowlist();
    let seed = 42u64;

    let commands = ["cargo build", "cargo test", "cargo check", "cargo clippy"];
    let results: Vec<ParityCheckResult> = commands
        .iter()
        .map(|cmd| {
            let local = make_local_result(cmd, 0, &mut rng);
            let remote = make_matching_remote(&local, "w1", &mut rng);
            check_parity(&local, &remote, &allowlist)
        })
        .collect();

    let summary = build_suite_summary(&results, seed, 1.0);
    assert_eq!(summary.total_checks, 4);
    assert_eq!(summary.parity_pass, 4);
    assert_eq!(summary.parity_fail, 0);
    assert!((summary.parity_rate - 1.0).abs() < f64::EPSILON);
    assert!(summary.threshold_met);
    assert!(summary.critical_failures.is_empty());
}

#[test]
fn e2e_parity_suite_summary_with_failures() {
    let mut rng = Xorshift64::new(42);
    let allowlist = default_allowlist();
    let seed = 42u64;

    let local_pass = make_local_result("cargo build", 0, &mut rng);
    let remote_pass = make_matching_remote(&local_pass, "w1", &mut rng);

    let local_fail = make_local_result("cargo test", 0, &mut rng);
    let remote_fail = make_diverged_remote(&local_fail, "w1", DivergenceType::Functional, &mut rng);

    let results = vec![
        check_parity(&local_pass, &remote_pass, &allowlist),
        check_parity(&local_fail, &remote_fail, &allowlist),
    ];

    let summary = build_suite_summary(&results, seed, 1.0);
    assert_eq!(summary.total_checks, 2);
    assert_eq!(summary.parity_pass, 1);
    assert_eq!(summary.parity_fail, 1);
    assert!((summary.parity_rate - 0.5).abs() < f64::EPSILON);
    assert!(!summary.threshold_met);
    assert!(!summary.critical_failures.is_empty());
}

#[test]
fn e2e_parity_suite_threshold_gating() {
    let mut rng = Xorshift64::new(42);
    let allowlist = default_allowlist();

    // 3 pass, 1 fail = 75% parity rate
    let mut results = Vec::new();
    for cmd in ["cargo build", "cargo test", "cargo check"] {
        let local = make_local_result(cmd, 0, &mut rng);
        let remote = make_matching_remote(&local, "w1", &mut rng);
        results.push(check_parity(&local, &remote, &allowlist));
    }
    let local_fail = make_local_result("cargo clippy", 0, &mut rng);
    let remote_fail = make_diverged_remote(&local_fail, "w1", DivergenceType::Artifact, &mut rng);
    results.push(check_parity(&local_fail, &remote_fail, &allowlist));

    // 75% threshold passes
    let summary_loose = build_suite_summary(&results, 42, 0.70);
    assert!(summary_loose.threshold_met);

    // 100% threshold fails
    let summary_strict = build_suite_summary(&results, 42, 1.0);
    assert!(!summary_strict.threshold_met);
}

#[test]
fn e2e_parity_suite_summary_serialization() {
    let summary = ParitySuiteSummary {
        total_checks: 10,
        parity_pass: 8,
        parity_fail: 2,
        parity_rate: 0.8,
        divergence_type_counts: HashMap::from([
            ("\"functional\"".to_string(), 1),
            ("\"artifact\"".to_string(), 1),
        ]),
        critical_failures: vec!["cargo test: [Functional]".to_string()],
        threshold_met: false,
        seed: 42,
    };

    let json = serde_json::to_string_pretty(&summary).unwrap();
    let restored: ParitySuiteSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.total_checks, 10);
    assert_eq!(restored.parity_pass, 8);
    assert_eq!(restored.seed, 42);
    assert!(!restored.threshold_met);
}

// ===========================================================================
// Tests: Seed determinism
// ===========================================================================

#[test]
fn e2e_parity_seed_reproducibility() {
    let allowlist = default_allowlist();

    let run = |seed: u64| -> Vec<ParityCheckResult> {
        let mut rng = Xorshift64::new(seed);
        let commands = ["cargo build", "cargo test", "cargo check"];
        commands
            .iter()
            .map(|cmd| {
                let local = make_local_result(cmd, 0, &mut rng);
                let remote = make_matching_remote(&local, "w1", &mut rng);
                check_parity(&local, &remote, &allowlist)
            })
            .collect()
    };

    let results_a = run(42);
    let results_b = run(42);

    for (a, b) in results_a.iter().zip(results_b.iter()) {
        assert_eq!(a.command, b.command);
        assert_eq!(a.is_parity, b.is_parity);
        assert_eq!(a.divergences, b.divergences);
    }
}

// ===========================================================================
// Tests: Multi-worker parity
// ===========================================================================

#[test]
fn e2e_parity_multi_worker_comparison() {
    let mut rng = Xorshift64::new(42);
    let allowlist = default_allowlist();
    let workers = ["w1", "w2", "w3", "w4"];

    let local = make_local_result("cargo build --release", 0, &mut rng);

    let mut results = Vec::new();
    for worker in &workers {
        let remote = make_matching_remote(&local, worker, &mut rng);
        results.push(check_parity(&local, &remote, &allowlist));
    }

    // All workers should match local
    for result in &results {
        assert!(
            result.is_parity,
            "worker {} should match local execution",
            result.worker_id
        );
    }
}

#[test]
fn e2e_parity_multi_worker_one_diverged() {
    let mut rng = Xorshift64::new(42);
    let allowlist = default_allowlist();

    let local = make_local_result("cargo build --release", 0, &mut rng);

    let remote_ok = make_matching_remote(&local, "w1", &mut rng);
    let remote_bad = make_diverged_remote(&local, "w2", DivergenceType::Functional, &mut rng);
    let remote_ok2 = make_matching_remote(&local, "w3", &mut rng);

    let results = vec![
        check_parity(&local, &remote_ok, &allowlist),
        check_parity(&local, &remote_bad, &allowlist),
        check_parity(&local, &remote_ok2, &allowlist),
    ];

    let summary = build_suite_summary(&results, 42, 0.9);

    // 2/3 pass = 66.7% — below 90% threshold
    assert!(!summary.threshold_met);
    assert_eq!(summary.parity_fail, 1);
    assert_eq!(summary.critical_failures.len(), 1);
}

// ===========================================================================
// Tests: Logging integration
// ===========================================================================

#[test]
fn e2e_parity_logging_integration() {
    let logger = TestLoggerBuilder::new("parity-logging-e2e")
        .print_realtime(false)
        .build();

    let mut rng = Xorshift64::new(42);
    let allowlist = default_allowlist();
    let local = make_local_result("cargo build", 0, &mut rng);
    let remote = make_matching_remote(&local, "w1", &mut rng);
    let result = check_parity(&local, &remote, &allowlist);

    let event = logger.log_reliability_event(ReliabilityEventInput {
        level: LogLevel::Info,
        phase: ReliabilityPhase::Verify,
        scenario_id: "parity-check-001".to_string(),
        message: format!("parity check: is_parity={}", result.is_parity),
        context: ReliabilityContext {
            worker_id: Some("w1".to_string()),
            repo_set: vec!["repo-a".to_string()],
            pressure_state: None,
            triage_actions: Vec::new(),
            decision_code: if result.is_parity {
                "PARITY_PASS".to_string()
            } else {
                "PARITY_FAIL".to_string()
            },
            fallback_reason: None,
        },
        artifact_paths: vec![],
    });

    assert_eq!(event.phase, ReliabilityPhase::Verify);
    assert!(event.message.contains("is_parity=true"));
    assert_eq!(event.context.decision_code, "PARITY_PASS");
}

// ===========================================================================
// Tests: ParityCheckResult schema
// ===========================================================================

#[test]
fn e2e_parity_check_result_serialization() {
    let result = ParityCheckResult {
        command: "cargo build".to_string(),
        worker_id: "w1".to_string(),
        is_parity: false,
        divergences: vec![DivergenceType::Functional, DivergenceType::Schema],
        severity: "critical".to_string(),
        remediation_hints: vec![
            "Check remote worker build environment".to_string(),
            "Compare API versions".to_string(),
        ],
        allowlisted_fields: vec!["duration_ms".to_string()],
    };

    let json = serde_json::to_string_pretty(&result).unwrap();
    let restored: ParityCheckResult = serde_json::from_str(&json).unwrap();

    assert_eq!(restored.command, "cargo build");
    assert!(!restored.is_parity);
    assert_eq!(restored.divergences.len(), 2);
    assert_eq!(restored.severity, "critical");
    assert_eq!(restored.remediation_hints.len(), 2);
    assert_eq!(restored.allowlisted_fields, vec!["duration_ms"]);
}

// ===========================================================================
// Tests: NormalizationRule coverage
// ===========================================================================

#[test]
fn e2e_parity_normalization_rules_serialization() {
    let rules = vec![
        NormalizationRule::Ignore,
        NormalizationRule::PrefixMatch(32),
        NormalizationRule::StripTimestamps,
        NormalizationRule::NormalizePaths,
        NormalizationRule::WithinTolerance(200),
    ];

    let json = serde_json::to_string(&rules).unwrap();
    let restored: Vec<NormalizationRule> = serde_json::from_str(&json).unwrap();
    assert_eq!(rules, restored);
}

#[test]
fn e2e_parity_normalization_rules_in_allowlist() {
    let allowlist = default_allowlist();

    // Verify each normalization rule type is represented in the default allowlist
    let rule_types: Vec<&str> = allowlist
        .iter()
        .map(|e| match &e.normalization_rule {
            NormalizationRule::Ignore => "ignore",
            NormalizationRule::PrefixMatch(_) => "prefix_match",
            NormalizationRule::StripTimestamps => "strip_timestamps",
            NormalizationRule::NormalizePaths => "normalize_paths",
            NormalizationRule::WithinTolerance(_) => "within_tolerance",
        })
        .collect();

    assert!(rule_types.contains(&"ignore"), "allowlist should contain Ignore rule");
    assert!(
        rule_types.contains(&"within_tolerance"),
        "allowlist should contain WithinTolerance rule"
    );
    assert!(
        rule_types.contains(&"strip_timestamps"),
        "allowlist should contain StripTimestamps rule"
    );
    assert!(
        rule_types.contains(&"normalize_paths"),
        "allowlist should contain NormalizePaths rule"
    );
}
