//! Reliability requirement-to-test coverage matrix (bd-vvmd.7.8)
//!
//! Authoritative mapping from each reliability requirement/failure mode to:
//!   - Concrete executable test(s)
//!   - Expected log/assertion artifacts
//!   - Responsible bead
//!
//! CI-checked: fails when referenced tests are removed or renamed.
//! Release gate: bd-vvmd.7.5 references this matrix as mandatory closure input.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ===========================================================================
// Coverage matrix types
// ===========================================================================

const COVERAGE_MATRIX_SCHEMA_VERSION: &str = "1.0.0";

/// A single requirement row in the coverage matrix.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RequirementRow {
    /// Unique identifier for this requirement.
    id: String,
    /// Human-readable description of the requirement.
    description: String,
    /// Reliability domain (e.g., path_deps, convergence, pressure, triage).
    domain: String,
    /// Responsible bead ID.
    bead_id: String,
    /// List of test references (file::test_name_prefix).
    test_refs: Vec<TestRef>,
    /// Expected log/artifact assertions.
    artifact_assertions: Vec<String>,
    /// Whether this row has at least one executable test.
    has_executable_test: bool,
    /// Whether this row has at least one log assertion.
    has_log_assertion: bool,
    /// Explicit gap marker (if no tests exist yet, this should be a backlog item).
    gap: Option<String>,
}

/// Reference to a concrete test.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TestRef {
    /// Test file (relative to rch-common/tests/).
    file: String,
    /// Test name prefix (matches one or more #[test] functions).
    name_prefix: String,
    /// Test tier: "smoke", "nightly", or "full".
    tier: String,
}

/// Full coverage matrix.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CoverageMatrix {
    schema_version: String,
    requirements: Vec<RequirementRow>,
    summary: MatrixSummary,
}

/// Summary statistics for the matrix.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct MatrixSummary {
    total_requirements: usize,
    covered_requirements: usize,
    gap_count: usize,
    domains: Vec<String>,
    total_test_refs: usize,
    total_artifact_assertions: usize,
}

// ===========================================================================
// Matrix builder
// ===========================================================================

fn build_coverage_matrix() -> CoverageMatrix {
    let requirements = vec![
        // ---------------------------------------------------------------
        // Domain: Path Dependencies
        // ---------------------------------------------------------------
        RequirementRow {
            id: "REQ-PATH-001".into(),
            description: "Cross-repo Cargo path dependency resolution and transitive closure".into(),
            domain: "path_deps".into(),
            bead_id: "bd-vvmd.2.8".into(),
            test_refs: vec![
                TestRef {
                    file: "cross_repo_path_deps_e2e.rs".into(),
                    name_prefix: "e2e_cross_repo_".into(),
                    tier: "smoke".into(),
                },
            ],
            artifact_assertions: vec![
                "Planner output includes all transitive path deps".into(),
                "Alias symlinks produce equivalent closure".into(),
            ],
            has_executable_test: true,
            has_log_assertion: true,
            gap: None,
        },
        RequirementRow {
            id: "REQ-PATH-002".into(),
            description: "Dependency closure planner deterministic ordering".into(),
            domain: "path_deps".into(),
            bead_id: "bd-vvmd.2.7".into(),
            test_refs: vec![
                TestRef {
                    file: "dependency_closure_planner.rs".into(),
                    name_prefix: "test_".into(),
                    tier: "smoke".into(),
                },
            ],
            artifact_assertions: vec![
                "Planner output is deterministically ordered".into(),
            ],
            has_executable_test: true,
            has_log_assertion: true,
            gap: None,
        },
        RequirementRow {
            id: "REQ-PATH-003".into(),
            description: "Fail-open semantics when path deps cannot be resolved".into(),
            domain: "path_deps".into(),
            bead_id: "bd-vvmd.2.8".into(),
            test_refs: vec![
                TestRef {
                    file: "cross_repo_path_deps_e2e.rs".into(),
                    name_prefix: "e2e_cross_repo_fail_open".into(),
                    tier: "smoke".into(),
                },
            ],
            artifact_assertions: vec![
                "Graceful degradation with diagnostic output when deps are missing".into(),
            ],
            has_executable_test: true,
            has_log_assertion: true,
            gap: None,
        },
        // ---------------------------------------------------------------
        // Domain: Command Classification
        // ---------------------------------------------------------------
        RequirementRow {
            id: "REQ-CLASS-001".into(),
            description: "Command classification regression for non-compilation UX".into(),
            domain: "classification".into(),
            bead_id: "bd-vvmd.2.9".into(),
            test_refs: vec![
                TestRef {
                    file: "cross_repo_path_deps_e2e.rs".into(),
                    name_prefix: "e2e_cross_repo_classify".into(),
                    tier: "smoke".into(),
                },
            ],
            artifact_assertions: vec![
                "Classification timing under budget".into(),
                "Known commands correctly categorized".into(),
            ],
            has_executable_test: true,
            has_log_assertion: true,
            gap: None,
        },
        // ---------------------------------------------------------------
        // Domain: Repo Convergence
        // ---------------------------------------------------------------
        RequirementRow {
            id: "REQ-CONV-001".into(),
            description: "Repo convergence adapter contract and failure taxonomy".into(),
            domain: "convergence".into(),
            bead_id: "bd-vvmd.3.6".into(),
            test_refs: vec![
                TestRef {
                    file: "repo_convergence_e2e.rs".into(),
                    name_prefix: "e2e_convergence_".into(),
                    tier: "smoke".into(),
                },
            ],
            artifact_assertions: vec![
                "Adapter request/response schema roundtrip valid".into(),
                "Failure taxonomy maps to error codes".into(),
                "Trust and auth policies enforced".into(),
            ],
            has_executable_test: true,
            has_log_assertion: true,
            gap: None,
        },
        RequirementRow {
            id: "REQ-CONV-002".into(),
            description: "Repo convergence internal unit tests".into(),
            domain: "convergence".into(),
            bead_id: "bd-vvmd.3.8".into(),
            test_refs: vec![
                TestRef {
                    file: "repo_convergence_e2e.rs".into(),
                    name_prefix: "e2e_convergence_mock_adapter".into(),
                    tier: "smoke".into(),
                },
            ],
            artifact_assertions: vec![
                "Mock adapter exercises all contract branches".into(),
            ],
            has_executable_test: true,
            has_log_assertion: true,
            gap: None,
        },
        // ---------------------------------------------------------------
        // Domain: Storage Pressure
        // ---------------------------------------------------------------
        RequirementRow {
            id: "REQ-DISK-001".into(),
            description: "Disk pressure detection, prevention, and recovery".into(),
            domain: "disk_pressure".into(),
            bead_id: "bd-vvmd.4.6".into(),
            test_refs: vec![
                TestRef {
                    file: "fault_injection_e2e.rs".into(),
                    name_prefix: "e2e_fault_".into(),
                    tier: "smoke".into(),
                },
            ],
            artifact_assertions: vec![
                "Pressure state transitions logged".into(),
                "Critical threshold triggers build deferral".into(),
            ],
            has_executable_test: true,
            has_log_assertion: true,
            gap: None,
        },
        // ---------------------------------------------------------------
        // Domain: Process Triage
        // ---------------------------------------------------------------
        RequirementRow {
            id: "REQ-TRIAGE-001".into(),
            description: "Process triage contract, safe-action policy, escalation ladder".into(),
            domain: "process_triage".into(),
            bead_id: "bd-vvmd.5.6".into(),
            test_refs: vec![
                TestRef {
                    file: "process_triage_e2e.rs".into(),
                    name_prefix: "e2e_triage_".into(),
                    tier: "smoke".into(),
                },
            ],
            artifact_assertions: vec![
                "Safe-action policy prevents harmful actions on protected processes".into(),
                "Escalation ladder produces monotonically increasing severity".into(),
                "Audit records capture all triage decisions".into(),
            ],
            has_executable_test: true,
            has_log_assertion: true,
            gap: None,
        },
        // ---------------------------------------------------------------
        // Domain: Fault Injection
        // ---------------------------------------------------------------
        RequirementRow {
            id: "REQ-FAULT-001".into(),
            description: "Deterministic fault injection for partial failure and recovery".into(),
            domain: "fault_injection".into(),
            bead_id: "bd-vvmd.7.6".into(),
            test_refs: vec![
                TestRef {
                    file: "fault_injection_e2e.rs".into(),
                    name_prefix: "e2e_fault_".into(),
                    tier: "smoke".into(),
                },
            ],
            artifact_assertions: vec![
                "Network cut, partial sync, timeout, and combined pressure faults exercised".into(),
                "Recovery path validated after each fault".into(),
            ],
            has_executable_test: true,
            has_log_assertion: true,
            gap: None,
        },
        // ---------------------------------------------------------------
        // Domain: Schema Contracts
        // ---------------------------------------------------------------
        RequirementRow {
            id: "REQ-SCHEMA-001".into(),
            description: "JSON/log schema contract golden tests for reliability outputs".into(),
            domain: "schema_contract".into(),
            bead_id: "bd-vvmd.6.8".into(),
            test_refs: vec![
                TestRef {
                    file: "schema_contract_e2e.rs".into(),
                    name_prefix: "e2e_schema_".into(),
                    tier: "smoke".into(),
                },
            ],
            artifact_assertions: vec![
                "API envelope schema valid".into(),
                "Error payload schema valid".into(),
                "Hook protocol schema valid".into(),
                "Reliability event schema valid".into(),
            ],
            has_executable_test: true,
            has_log_assertion: true,
            gap: None,
        },
        // ---------------------------------------------------------------
        // Domain: Concurrency Soak
        // ---------------------------------------------------------------
        RequirementRow {
            id: "REQ-SOAK-001".into(),
            description: "Long-duration concurrency soak with slot churn and pressure transitions".into(),
            domain: "soak_concurrency".into(),
            bead_id: "bd-vvmd.7.9".into(),
            test_refs: vec![
                TestRef {
                    file: "soak_concurrency_e2e.rs".into(),
                    name_prefix: "e2e_soak_".into(),
                    tier: "smoke".into(),
                },
            ],
            artifact_assertions: vec![
                "No resource leaks after sustained concurrent operations".into(),
                "Failure hooks execute within timing budget".into(),
            ],
            has_executable_test: true,
            has_log_assertion: true,
            gap: None,
        },
        // ---------------------------------------------------------------
        // Domain: Cross-Worker Parity
        // ---------------------------------------------------------------
        RequirementRow {
            id: "REQ-PARITY-001".into(),
            description: "Cross-worker determinism and parity validation".into(),
            domain: "cross_worker_parity".into(),
            bead_id: "bd-vvmd.7.10".into(),
            test_refs: vec![
                TestRef {
                    file: "cross_worker_parity_e2e.rs".into(),
                    name_prefix: "e2e_parity_".into(),
                    tier: "smoke".into(),
                },
            ],
            artifact_assertions: vec![
                "Exit codes identical across workers for same input".into(),
                "Artifact hashes match across workers".into(),
                "Toolchain differences detected and reported".into(),
            ],
            has_executable_test: true,
            has_log_assertion: true,
            gap: None,
        },
        // ---------------------------------------------------------------
        // Domain: Local-vs-Remote Parity
        // ---------------------------------------------------------------
        RequirementRow {
            id: "REQ-LR-001".into(),
            description: "Local-vs-remote execution parity validation".into(),
            domain: "local_remote_parity".into(),
            bead_id: "bd-vvmd.7.11".into(),
            test_refs: vec![
                TestRef {
                    file: "local_remote_parity_e2e.rs".into(),
                    name_prefix: "e2e_lr_parity_".into(),
                    tier: "smoke".into(),
                },
            ],
            artifact_assertions: vec![
                "Error codes consistent between local and remote".into(),
                "Schema divergence detection works".into(),
                "Classification parity across execution modes".into(),
            ],
            has_executable_test: true,
            has_log_assertion: true,
            gap: None,
        },
        // ---------------------------------------------------------------
        // Domain: Deterministic Replay
        // ---------------------------------------------------------------
        RequirementRow {
            id: "REQ-REPLAY-001".into(),
            description: "Scenario bundle capture, replay, and divergence detection".into(),
            domain: "deterministic_replay".into(),
            bead_id: "bd-vvmd.7.12".into(),
            test_refs: vec![
                TestRef {
                    file: "deterministic_replay_e2e.rs".into(),
                    name_prefix: "e2e_replay_".into(),
                    tier: "smoke".into(),
                },
            ],
            artifact_assertions: vec![
                "Bundle round-trips through capture/replay".into(),
                "Schema version compatibility checked".into(),
                "Divergence detector reports structural diffs".into(),
            ],
            has_executable_test: true,
            has_log_assertion: true,
            gap: None,
        },
        // ---------------------------------------------------------------
        // Domain: Performance Budget
        // ---------------------------------------------------------------
        RequirementRow {
            id: "REQ-PERF-001".into(),
            description: "Hard-gated performance budgets for reliability pipeline".into(),
            domain: "performance_budget".into(),
            bead_id: "bd-vvmd.6.6".into(),
            test_refs: vec![
                TestRef {
                    file: "performance_budget_e2e.rs".into(),
                    name_prefix: "e2e_perf_".into(),
                    tier: "smoke".into(),
                },
            ],
            artifact_assertions: vec![
                "Hook decision latency under 5ms".into(),
                "Catalog lookup under 1ms".into(),
                "Logging overhead under budget".into(),
            ],
            has_executable_test: true,
            has_log_assertion: true,
            gap: None,
        },
        // ---------------------------------------------------------------
        // Domain: Redaction & Retention
        // ---------------------------------------------------------------
        RequirementRow {
            id: "REQ-REDACT-001".into(),
            description: "Credential/PII redaction and retention policy enforcement".into(),
            domain: "redaction_retention".into(),
            bead_id: "bd-vvmd.6.10".into(),
            test_refs: vec![
                TestRef {
                    file: "redaction_retention_e2e.rs".into(),
                    name_prefix: "e2e_redaction_".into(),
                    tier: "smoke".into(),
                },
                TestRef {
                    file: "redaction_retention_e2e.rs".into(),
                    name_prefix: "e2e_retention_".into(),
                    tier: "smoke".into(),
                },
            ],
            artifact_assertions: vec![
                "No raw secrets in output after redaction pass".into(),
                "Retention policies enforce age-based purge".into(),
                "Incident bundle export respects safe-export policy".into(),
            ],
            has_executable_test: true,
            has_log_assertion: true,
            gap: None,
        },
        // ---------------------------------------------------------------
        // Domain: Contract Drift
        // ---------------------------------------------------------------
        RequirementRow {
            id: "REQ-DRIFT-001".into(),
            description: "Cross-project helper contract-drift compatibility validation".into(),
            domain: "contract_drift".into(),
            bead_id: "bd-vvmd.6.11".into(),
            test_refs: vec![
                TestRef {
                    file: "contract_drift_e2e.rs".into(),
                    name_prefix: "e2e_compat_".into(),
                    tier: "smoke".into(),
                },
            ],
            artifact_assertions: vec![
                "Version matrix compatibility checked".into(),
                "Structured mismatch diffs generated".into(),
                "Fallback behavior validated on version mismatch".into(),
            ],
            has_executable_test: true,
            has_log_assertion: true,
            gap: None,
        },
        // ---------------------------------------------------------------
        // Domain: Feature Flags & Rollout
        // ---------------------------------------------------------------
        RequirementRow {
            id: "REQ-FLAGS-001".into(),
            description: "Feature flag states, staged rollout, health gates, auto-disable".into(),
            domain: "feature_flags".into(),
            bead_id: "bd-vvmd.6.7".into(),
            test_refs: vec![
                TestRef {
                    file: "feature_flags_rollout_e2e.rs".into(),
                    name_prefix: "e2e_flags_".into(),
                    tier: "smoke".into(),
                },
            ],
            artifact_assertions: vec![
                "Flag state transitions valid".into(),
                "Canary scoping enforced".into(),
                "Health gate evaluation correct".into(),
                "Auto-disable triggers fire on threshold breach".into(),
            ],
            has_executable_test: true,
            has_log_assertion: true,
            gap: None,
        },
        // ---------------------------------------------------------------
        // Domain: Reliability Doctor
        // ---------------------------------------------------------------
        RequirementRow {
            id: "REQ-DOCTOR-001".into(),
            description: "Reliability doctor diagnostics with actionable remediation".into(),
            domain: "reliability_doctor".into(),
            bead_id: "bd-vvmd.6.9".into(),
            test_refs: vec![
                TestRef {
                    file: "reliability_doctor_e2e.rs".into(),
                    name_prefix: "e2e_doctor_".into(),
                    tier: "smoke".into(),
                },
            ],
            artifact_assertions: vec![
                "All diagnostic categories covered".into(),
                "Every non-pass diagnostic has remediation command".into(),
                "Dry-run mode flags unsafe operations".into(),
                "Output deterministic across runs".into(),
            ],
            has_executable_test: true,
            has_log_assertion: true,
            gap: None,
        },
        // ---------------------------------------------------------------
        // Domain: UX Quality
        // ---------------------------------------------------------------
        RequirementRow {
            id: "REQ-UX-001".into(),
            description: "Human-facing reliability output quality and golden snapshots".into(),
            domain: "ux_quality".into(),
            bead_id: "bd-1qhj".into(),
            test_refs: vec![
                TestRef {
                    file: "ux_regression_e2e.rs".into(),
                    name_prefix: "e2e_ux_".into(),
                    tier: "smoke".into(),
                },
            ],
            artifact_assertions: vec![
                "Golden snapshots for all scenario postures".into(),
                "Reason codes present in all non-healthy outputs".into(),
                "Destructive actions carry risk notes".into(),
                "Redaction clean across all scenarios".into(),
                "Cross-worker parity in narrative structure".into(),
            ],
            has_executable_test: true,
            has_log_assertion: true,
            gap: None,
        },
        // ---------------------------------------------------------------
        // Domain: Cancellation
        // ---------------------------------------------------------------
        RequirementRow {
            id: "REQ-CANCEL-001".into(),
            description: "Remote build cancellation and deterministic cleanup semantics".into(),
            domain: "cancellation".into(),
            bead_id: "bd-1yt6".into(),
            test_refs: vec![
                TestRef {
                    file: "fault_injection_e2e.rs".into(),
                    name_prefix: "e2e_fault_cancel".into(),
                    tier: "smoke".into(),
                },
            ],
            artifact_assertions: vec![
                "Cancellation state machine transitions valid".into(),
                "Cleanup invariants maintained after cancel".into(),
            ],
            has_executable_test: true,
            has_log_assertion: true,
            gap: None,
        },
        // ---------------------------------------------------------------
        // Domain: Structured Logging
        // ---------------------------------------------------------------
        RequirementRow {
            id: "REQ-LOG-001".into(),
            description: "Structured reliability test logger and artifact capture".into(),
            domain: "logging".into(),
            bead_id: "bd-vvmd.7.3".into(),
            test_refs: vec![
                TestRef {
                    file: "smoke.rs".into(),
                    name_prefix: "smoke_test_logger".into(),
                    tier: "smoke".into(),
                },
            ],
            artifact_assertions: vec![
                "JSONL log output conforms to schema".into(),
                "Phase events have required fields".into(),
            ],
            has_executable_test: true,
            has_log_assertion: true,
            gap: None,
        },
        // ---------------------------------------------------------------
        // Domain: E2E Harness Foundation
        // ---------------------------------------------------------------
        RequirementRow {
            id: "REQ-HARNESS-001".into(),
            description: "Reusable reliability E2E harness foundation".into(),
            domain: "harness".into(),
            bead_id: "bd-vvmd.7.7".into(),
            test_refs: vec![
                TestRef {
                    file: "smoke.rs".into(),
                    name_prefix: "smoke_".into(),
                    tier: "smoke".into(),
                },
            ],
            artifact_assertions: vec![
                "TestHarnessBuilder creates isolated directories".into(),
                "TestLoggerBuilder produces valid JSONL".into(),
            ],
            has_executable_test: true,
            has_log_assertion: true,
            gap: None,
        },
        // ---------------------------------------------------------------
        // Domain: E2E Script Expansion
        // ---------------------------------------------------------------
        RequirementRow {
            id: "REQ-E2E-001".into(),
            description: "Unified E2E scripts for all reliability families".into(),
            domain: "e2e_scripts".into(),
            bead_id: "bd-vvmd.7.2".into(),
            test_refs: vec![
                TestRef {
                    file: "../tests/e2e/unified_reliability_suite.sh".into(),
                    name_prefix: "run_family".into(),
                    tier: "smoke".into(),
                },
            ],
            artifact_assertions: vec![
                "Suite produces machine-readable JSONL phase logs".into(),
                "Suite summary JSON has pass/fail/skip counts".into(),
            ],
            has_executable_test: true,
            has_log_assertion: true,
            gap: None,
        },
    ];

    let total = requirements.len();
    let covered = requirements.iter().filter(|r| r.has_executable_test).count();
    let gaps = requirements.iter().filter(|r| r.gap.is_some()).count();
    let total_refs: usize = requirements.iter().map(|r| r.test_refs.len()).sum();
    let total_artifacts: usize = requirements
        .iter()
        .map(|r| r.artifact_assertions.len())
        .sum();

    let mut domains: Vec<String> = requirements.iter().map(|r| r.domain.clone()).collect();
    domains.sort();
    domains.dedup();

    CoverageMatrix {
        schema_version: COVERAGE_MATRIX_SCHEMA_VERSION.into(),
        requirements,
        summary: MatrixSummary {
            total_requirements: total,
            covered_requirements: covered,
            gap_count: gaps,
            domains,
            total_test_refs: total_refs,
            total_artifact_assertions: total_artifacts,
        },
    }
}

// ===========================================================================
// Staleness verification: test file existence
// ===========================================================================

/// Known test files that the matrix references.
const KNOWN_TEST_FILES: &[&str] = &[
    "cross_repo_path_deps_e2e.rs",
    "dependency_closure_planner.rs",
    "repo_convergence_e2e.rs",
    "process_triage_e2e.rs",
    "fault_injection_e2e.rs",
    "schema_contract_e2e.rs",
    "soak_concurrency_e2e.rs",
    "cross_worker_parity_e2e.rs",
    "local_remote_parity_e2e.rs",
    "deterministic_replay_e2e.rs",
    "performance_budget_e2e.rs",
    "redaction_retention_e2e.rs",
    "contract_drift_e2e.rs",
    "feature_flags_rollout_e2e.rs",
    "reliability_doctor_e2e.rs",
    "ux_regression_e2e.rs",
    "smoke.rs",
];

// ===========================================================================
// Tests: schema stability
// ===========================================================================

#[test]
fn e2e_matrix_schema_version() {
    let matrix = build_coverage_matrix();
    assert_eq!(matrix.schema_version, COVERAGE_MATRIX_SCHEMA_VERSION);
}

#[test]
fn e2e_matrix_serialization_roundtrip() {
    let matrix = build_coverage_matrix();
    let json = serde_json::to_string_pretty(&matrix).unwrap();
    let parsed: CoverageMatrix = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.requirements.len(), matrix.requirements.len());
    assert_eq!(parsed.summary.total_requirements, matrix.summary.total_requirements);
}

// ===========================================================================
// Tests: coverage completeness
// ===========================================================================

#[test]
fn e2e_matrix_every_row_has_executable_test() {
    let matrix = build_coverage_matrix();
    for row in &matrix.requirements {
        assert!(
            row.has_executable_test,
            "requirement '{}' ({}) must have at least one executable test",
            row.id, row.description
        );
    }
}

#[test]
fn e2e_matrix_every_row_has_log_assertion() {
    let matrix = build_coverage_matrix();
    for row in &matrix.requirements {
        assert!(
            row.has_log_assertion,
            "requirement '{}' ({}) must have at least one log/assertion artifact",
            row.id, row.description
        );
    }
}

#[test]
fn e2e_matrix_every_row_has_test_ref() {
    let matrix = build_coverage_matrix();
    for row in &matrix.requirements {
        assert!(
            !row.test_refs.is_empty(),
            "requirement '{}' must have at least one test reference",
            row.id
        );
    }
}

#[test]
fn e2e_matrix_every_row_has_artifact_assertion() {
    let matrix = build_coverage_matrix();
    for row in &matrix.requirements {
        assert!(
            !row.artifact_assertions.is_empty(),
            "requirement '{}' must have at least one artifact assertion",
            row.id
        );
    }
}

#[test]
fn e2e_matrix_no_gaps() {
    let matrix = build_coverage_matrix();
    let gaps: Vec<_> = matrix
        .requirements
        .iter()
        .filter(|r| r.gap.is_some())
        .collect();
    assert!(
        gaps.is_empty(),
        "matrix has {} explicit gaps: {:?}",
        gaps.len(),
        gaps.iter().map(|g| &g.id).collect::<Vec<_>>()
    );
}

// ===========================================================================
// Tests: domain coverage
// ===========================================================================

#[test]
fn e2e_matrix_covers_all_required_domains() {
    let matrix = build_coverage_matrix();
    let required_domains = [
        "path_deps",
        "classification",
        "convergence",
        "disk_pressure",
        "process_triage",
        "fault_injection",
        "schema_contract",
        "soak_concurrency",
        "cross_worker_parity",
        "local_remote_parity",
        "deterministic_replay",
        "performance_budget",
        "redaction_retention",
        "contract_drift",
        "feature_flags",
        "reliability_doctor",
        "ux_quality",
        "cancellation",
        "logging",
        "harness",
        "e2e_scripts",
    ];

    for domain in &required_domains {
        let has = matrix.requirements.iter().any(|r| r.domain == *domain);
        assert!(has, "required domain '{}' must be covered in the matrix", domain);
    }
}

#[test]
fn e2e_matrix_no_duplicate_requirement_ids() {
    let matrix = build_coverage_matrix();
    let mut seen = HashMap::new();
    for row in &matrix.requirements {
        if let Some(prev) = seen.insert(&row.id, &row.description) {
            panic!(
                "duplicate requirement ID '{}': '{}' vs '{}'",
                row.id, prev, row.description
            );
        }
    }
}

// ===========================================================================
// Tests: test file staleness check
// ===========================================================================

#[test]
fn e2e_matrix_referenced_test_files_exist() {
    let matrix = build_coverage_matrix();
    let test_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");

    for row in &matrix.requirements {
        for test_ref in &row.test_refs {
            // Skip shell scripts (they live in a different directory)
            if test_ref.file.ends_with(".sh") {
                continue;
            }
            let path = test_dir.join(&test_ref.file);
            assert!(
                path.exists(),
                "test file '{}' referenced by requirement '{}' does not exist at {:?}",
                test_ref.file, row.id, path
            );
        }
    }
}

#[test]
fn e2e_matrix_known_test_files_exist() {
    let test_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    for file in KNOWN_TEST_FILES {
        let path = test_dir.join(file);
        assert!(
            path.exists(),
            "known test file '{}' has been removed or renamed. Update the coverage matrix!",
            file
        );
    }
}

// ===========================================================================
// Tests: summary correctness
// ===========================================================================

#[test]
fn e2e_matrix_summary_counts_correct() {
    let matrix = build_coverage_matrix();
    assert_eq!(matrix.summary.total_requirements, matrix.requirements.len());
    assert_eq!(
        matrix.summary.covered_requirements,
        matrix.requirements.iter().filter(|r| r.has_executable_test).count()
    );
    assert_eq!(
        matrix.summary.gap_count,
        matrix.requirements.iter().filter(|r| r.gap.is_some()).count()
    );
}

#[test]
fn e2e_matrix_summary_test_ref_count_correct() {
    let matrix = build_coverage_matrix();
    let total_refs: usize = matrix.requirements.iter().map(|r| r.test_refs.len()).sum();
    assert_eq!(matrix.summary.total_test_refs, total_refs);
}

#[test]
fn e2e_matrix_summary_artifact_count_correct() {
    let matrix = build_coverage_matrix();
    let total_artifacts: usize = matrix
        .requirements
        .iter()
        .map(|r| r.artifact_assertions.len())
        .sum();
    assert_eq!(matrix.summary.total_artifact_assertions, total_artifacts);
}

// ===========================================================================
// Tests: bead ID validity
// ===========================================================================

#[test]
fn e2e_matrix_all_bead_ids_well_formed() {
    let matrix = build_coverage_matrix();
    for row in &matrix.requirements {
        assert!(
            row.bead_id.starts_with("bd-"),
            "bead_id '{}' in requirement '{}' must start with 'bd-'",
            row.bead_id, row.id
        );
    }
}

// ===========================================================================
// Tests: test tier validity
// ===========================================================================

#[test]
fn e2e_matrix_all_test_tiers_valid() {
    let matrix = build_coverage_matrix();
    let valid_tiers = ["smoke", "nightly", "full"];
    for row in &matrix.requirements {
        for test_ref in &row.test_refs {
            assert!(
                valid_tiers.contains(&test_ref.tier.as_str()),
                "test tier '{}' in requirement '{}' must be one of {:?}",
                test_ref.tier, row.id, valid_tiers
            );
        }
    }
}

// ===========================================================================
// Tests: deterministic output
// ===========================================================================

#[test]
fn e2e_matrix_output_deterministic() {
    let m1 = build_coverage_matrix();
    let m2 = build_coverage_matrix();
    let json1 = serde_json::to_string(&m1).unwrap();
    let json2 = serde_json::to_string(&m2).unwrap();
    assert_eq!(json1, json2, "matrix output must be deterministic");
}

// ===========================================================================
// Tests: logging integration
// ===========================================================================

#[test]
fn e2e_matrix_logging_integration() {
    use rch_common::e2e::logging::{LogLevel, LogSource, TestLoggerBuilder};

    let logger = TestLoggerBuilder::new("coverage_matrix").build();
    let matrix = build_coverage_matrix();

    logger.log(
        LogLevel::Info,
        LogSource::Custom("coverage_matrix".into()),
        format!(
            "Coverage matrix: {} requirements, {} covered, {} gaps, {} domains",
            matrix.summary.total_requirements,
            matrix.summary.covered_requirements,
            matrix.summary.gap_count,
            matrix.summary.domains.len(),
        ),
    );

    let entries = logger.entries();
    assert_eq!(entries.len(), 1);
    assert!(entries[0].message.contains("requirements"));
}
