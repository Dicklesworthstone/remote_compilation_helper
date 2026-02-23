//! CI test tier definitions with reproducibility controls (bd-vvmd.7.4)
//!
//! Validates:
//!   - Explicit tier definitions (smoke, nightly, full) with runtime budgets
//!   - Deterministic seed policy per tier
//!   - Tier-to-scenario mapping completeness
//!   - Reproducibility controls: fixture reset guarantees, environment normalization
//!   - Flaky failure triage guidance per tier
//!   - Pass/fail thresholds per tier

use rch_common::e2e::logging::{LogLevel, LogSource, TestLoggerBuilder};
use serde::{Deserialize, Serialize};

// ===========================================================================
// CI tier types
// ===========================================================================

const CI_TIERS_SCHEMA_VERSION: &str = "1.0.0";

/// A CI test tier with runtime budget and reproducibility controls.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CiTestTier {
    /// Tier name: smoke, nightly, or full.
    name: String,
    /// Human-readable description of when this tier runs.
    description: String,
    /// Maximum runtime budget in seconds.
    runtime_budget_secs: u64,
    /// Deterministic seed policy.
    seed_policy: SeedPolicy,
    /// Scenario families included in this tier.
    scenario_families: Vec<String>,
    /// Required artifact outputs.
    required_artifacts: Vec<String>,
    /// Pass threshold: minimum pass rate (0.0 to 1.0).
    pass_threshold: f64,
    /// Whether this tier gates PR merges.
    gates_merge: bool,
    /// Triage guidance for flaky failures.
    flaky_triage_guidance: String,
    /// Environment normalization checks.
    env_normalization: Vec<String>,
    /// Fixture reset policy.
    fixture_reset: FixtureResetPolicy,
}

/// Seed policy for deterministic test execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SeedPolicy {
    /// Use a fixed seed for maximum reproducibility.
    Fixed { seed: u64 },
    /// Use a random seed but record it in artifacts for replay.
    RandomRecorded,
    /// Use CI run ID as seed for reproducibility within the same run.
    RunIdBased,
}

/// Fixture reset policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct FixtureResetPolicy {
    /// Whether fixtures are reset before each tier run.
    reset_before_run: bool,
    /// Whether temporary directories are cleaned after the tier.
    cleanup_after_run: bool,
    /// Isolation level: "process" (separate processes), "directory" (separate dirs),
    /// or "worktree" (git worktrees).
    isolation_level: String,
}

/// Full tier configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CiTierConfig {
    schema_version: String,
    tiers: Vec<CiTestTier>,
    summary: TierSummary,
}

/// Summary of tier configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TierSummary {
    total_tiers: usize,
    total_families: usize,
    merge_gating_tiers: Vec<String>,
}

// ===========================================================================
// Tier definitions
// ===========================================================================

/// All reliability scenario families that exist.
const ALL_FAMILIES: &[&str] = &[
    "path_deps",
    "repo_convergence",
    "process_triage",
    "disk_pressure",
    "reliability_harness",
    "reliability_logging",
    "topology_fixtures",
    "fault_injection",
    "classification_regression",
    "schema_contract",
    "soak_concurrency",
    "cross_worker_parity",
    "deterministic_replay",
    "performance_budget",
    "local_remote_parity",
    "redaction_retention",
    "contract_drift",
    "feature_flags_rollout",
    "reliability_doctor",
    "ux_regression",
    "coverage_matrix",
];

fn build_smoke_tier() -> CiTestTier {
    CiTestTier {
        name: "smoke".into(),
        description: "Fast contract + unit + integration tests. Runs on every PR and push."
            .into(),
        runtime_budget_secs: 300, // 5 minutes
        seed_policy: SeedPolicy::RunIdBased,
        scenario_families: ALL_FAMILIES.iter().map(|s| s.to_string()).collect(),
        required_artifacts: vec![
            "target/e2e-suite/suite_summary.json".into(),
            "target/e2e-suite/suite_run.jsonl".into(),
        ],
        pass_threshold: 1.0, // 100% pass required for smoke
        gates_merge: true,
        flaky_triage_guidance: concat!(
            "1. Check suite_run.jsonl for the failing family. ",
            "2. Re-run with RCH_E2E_SEED=<seed from artifact> for reproducibility. ",
            "3. If flaky, add to known_flaky list and open a bead. ",
            "4. Never merge with smoke failures."
        )
        .into(),
        env_normalization: vec![
            "CARGO_TARGET_DIR must be set".into(),
            "No ambient GITHUB_TOKEN or API keys in environment".into(),
            "Filesystem tmp space >= 1GB".into(),
        ],
        fixture_reset: FixtureResetPolicy {
            reset_before_run: true,
            cleanup_after_run: true,
            isolation_level: "directory".into(),
        },
    }
}

fn build_nightly_tier() -> CiTestTier {
    let mut families: Vec<String> = ALL_FAMILIES.iter().map(|s| s.to_string()).collect();
    families.extend([
        "nightly_topology_deep".to_string(),
        "nightly_contract_schema".to_string(),
        "nightly_benchmarks".to_string(),
    ]);

    CiTestTier {
        name: "nightly".into(),
        description:
            "Full suite including topology, soak, and regression. Scheduled nightly run."
                .into(),
        runtime_budget_secs: 1800, // 30 minutes
        seed_policy: SeedPolicy::RandomRecorded,
        scenario_families: families,
        required_artifacts: vec![
            "target/e2e-suite/suite_summary.json".into(),
            "target/e2e-suite/suite_run.jsonl".into(),
            "target/e2e-suite/*.log".into(),
        ],
        pass_threshold: 0.95, // 95% pass acceptable for nightly (soak may flake)
        gates_merge: false,
        flaky_triage_guidance: concat!(
            "1. Check per-family .log files for detailed output. ",
            "2. Nightly failures may be environment-specific; check host resources. ",
            "3. Soak concurrency failures under 5% are tracked, not blocking. ",
            "4. Open a bead for persistent nightly failures."
        )
        .into(),
        env_normalization: vec![
            "CARGO_TARGET_DIR must be set".into(),
            "Filesystem tmp space >= 5GB".into(),
            "No other cargo test processes running concurrently".into(),
        ],
        fixture_reset: FixtureResetPolicy {
            reset_before_run: true,
            cleanup_after_run: true,
            isolation_level: "directory".into(),
        },
    }
}

fn build_full_tier() -> CiTestTier {
    let mut families: Vec<String> = ALL_FAMILIES.iter().map(|s| s.to_string()).collect();
    families.extend([
        "nightly_topology_deep".to_string(),
        "nightly_contract_schema".to_string(),
        "nightly_benchmarks".to_string(),
    ]);

    CiTestTier {
        name: "full".into(),
        description:
            "Complete release-gate suite. Runs before release and on-demand."
                .into(),
        runtime_budget_secs: 3600, // 60 minutes
        seed_policy: SeedPolicy::Fixed { seed: 42 },
        scenario_families: families,
        required_artifacts: vec![
            "target/e2e-suite/suite_summary.json".into(),
            "target/e2e-suite/suite_run.jsonl".into(),
            "target/e2e-suite/*.log".into(),
            "target/e2e-suite/coverage_report.json".into(),
        ],
        pass_threshold: 1.0, // 100% for release gate
        gates_merge: false,  // gates release, not individual merges
        flaky_triage_guidance: concat!(
            "1. Full tier uses fixed seed=42 for exact reproducibility. ",
            "2. Any failure blocks release. ",
            "3. Reproduce locally: RCH_E2E_MODE=full RCH_E2E_SEED=42 bash tests/e2e/unified_reliability_suite.sh ",
            "4. Check coverage_report.json for regression evidence."
        )
        .into(),
        env_normalization: vec![
            "CARGO_TARGET_DIR must be set".into(),
            "Filesystem tmp space >= 10GB".into(),
            "Clean git state (no uncommitted changes)".into(),
            "All workspace crates compile without warnings".into(),
        ],
        fixture_reset: FixtureResetPolicy {
            reset_before_run: true,
            cleanup_after_run: false, // preserve artifacts for release audit
            isolation_level: "directory".into(),
        },
    }
}

fn build_tier_config() -> CiTierConfig {
    let tiers = vec![build_smoke_tier(), build_nightly_tier(), build_full_tier()];

    let total_families: usize = tiers
        .iter()
        .flat_map(|t| t.scenario_families.iter())
        .collect::<std::collections::HashSet<_>>()
        .len();

    let merge_gating: Vec<String> = tiers
        .iter()
        .filter(|t| t.gates_merge)
        .map(|t| t.name.clone())
        .collect();

    CiTierConfig {
        schema_version: CI_TIERS_SCHEMA_VERSION.into(),
        tiers: tiers.clone(),
        summary: TierSummary {
            total_tiers: tiers.len(),
            total_families,
            merge_gating_tiers: merge_gating,
        },
    }
}

// ===========================================================================
// Tests: schema stability
// ===========================================================================

#[test]
fn e2e_tiers_schema_version() {
    let config = build_tier_config();
    assert_eq!(config.schema_version, CI_TIERS_SCHEMA_VERSION);
}

#[test]
fn e2e_tiers_serialization_roundtrip() {
    let config = build_tier_config();
    let json = serde_json::to_string_pretty(&config).unwrap();
    let parsed: CiTierConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.tiers.len(), config.tiers.len());
    assert_eq!(parsed.summary.total_tiers, 3);
}

// ===========================================================================
// Tests: tier definitions
// ===========================================================================

#[test]
fn e2e_tiers_three_tiers_defined() {
    let config = build_tier_config();
    assert_eq!(config.tiers.len(), 3);
    let names: Vec<_> = config.tiers.iter().map(|t| t.name.as_str()).collect();
    assert_eq!(names, ["smoke", "nightly", "full"]);
}

#[test]
fn e2e_tiers_smoke_gates_merge() {
    let config = build_tier_config();
    let smoke = config.tiers.iter().find(|t| t.name == "smoke").unwrap();
    assert!(smoke.gates_merge, "smoke tier must gate PR merges");
}

#[test]
fn e2e_tiers_smoke_requires_100_percent_pass() {
    let config = build_tier_config();
    let smoke = config.tiers.iter().find(|t| t.name == "smoke").unwrap();
    assert!(
        (smoke.pass_threshold - 1.0).abs() < f64::EPSILON,
        "smoke tier must require 100% pass rate"
    );
}

#[test]
fn e2e_tiers_full_requires_100_percent_pass() {
    let config = build_tier_config();
    let full = config.tiers.iter().find(|t| t.name == "full").unwrap();
    assert!(
        (full.pass_threshold - 1.0).abs() < f64::EPSILON,
        "full tier must require 100% pass rate"
    );
}

#[test]
fn e2e_tiers_nightly_allows_some_flake() {
    let config = build_tier_config();
    let nightly = config.tiers.iter().find(|t| t.name == "nightly").unwrap();
    assert!(
        nightly.pass_threshold < 1.0 && nightly.pass_threshold >= 0.9,
        "nightly tier should allow small flake margin but require >= 90%"
    );
}

// ===========================================================================
// Tests: runtime budgets
// ===========================================================================

#[test]
fn e2e_tiers_runtime_budgets_ordered() {
    let config = build_tier_config();
    let smoke = config.tiers.iter().find(|t| t.name == "smoke").unwrap();
    let nightly = config.tiers.iter().find(|t| t.name == "nightly").unwrap();
    let full = config.tiers.iter().find(|t| t.name == "full").unwrap();

    assert!(
        smoke.runtime_budget_secs < nightly.runtime_budget_secs,
        "smoke budget must be less than nightly"
    );
    assert!(
        nightly.runtime_budget_secs <= full.runtime_budget_secs,
        "nightly budget must be <= full"
    );
}

#[test]
fn e2e_tiers_smoke_budget_under_10_minutes() {
    let config = build_tier_config();
    let smoke = config.tiers.iter().find(|t| t.name == "smoke").unwrap();
    assert!(
        smoke.runtime_budget_secs <= 600,
        "smoke tier must complete within 10 minutes"
    );
}

// ===========================================================================
// Tests: seed policy
// ===========================================================================

#[test]
fn e2e_tiers_each_tier_has_seed_policy() {
    let config = build_tier_config();
    for tier in &config.tiers {
        // Just verify it serializes (policy is always set)
        let json = serde_json::to_string(&tier.seed_policy).unwrap();
        assert!(!json.is_empty(), "tier '{}' must have a seed policy", tier.name);
    }
}

#[test]
fn e2e_tiers_full_uses_fixed_seed() {
    let config = build_tier_config();
    let full = config.tiers.iter().find(|t| t.name == "full").unwrap();
    assert!(
        matches!(full.seed_policy, SeedPolicy::Fixed { .. }),
        "full tier must use fixed seed for exact reproducibility"
    );
}

#[test]
fn e2e_tiers_nightly_records_seed() {
    let config = build_tier_config();
    let nightly = config.tiers.iter().find(|t| t.name == "nightly").unwrap();
    assert!(
        matches!(nightly.seed_policy, SeedPolicy::RandomRecorded),
        "nightly tier must use random-recorded seed"
    );
}

// ===========================================================================
// Tests: scenario family coverage
// ===========================================================================

#[test]
fn e2e_tiers_smoke_covers_all_base_families() {
    let config = build_tier_config();
    let smoke = config.tiers.iter().find(|t| t.name == "smoke").unwrap();

    for family in ALL_FAMILIES {
        assert!(
            smoke.scenario_families.contains(&family.to_string()),
            "smoke tier must include family '{}'",
            family
        );
    }
}

#[test]
fn e2e_tiers_nightly_superset_of_smoke() {
    let config = build_tier_config();
    let smoke = config.tiers.iter().find(|t| t.name == "smoke").unwrap();
    let nightly = config.tiers.iter().find(|t| t.name == "nightly").unwrap();

    for family in &smoke.scenario_families {
        assert!(
            nightly.scenario_families.contains(family),
            "nightly tier must include all smoke families (missing '{}')",
            family
        );
    }
}

#[test]
fn e2e_tiers_nightly_has_extra_families() {
    let config = build_tier_config();
    let smoke = config.tiers.iter().find(|t| t.name == "smoke").unwrap();
    let nightly = config.tiers.iter().find(|t| t.name == "nightly").unwrap();

    assert!(
        nightly.scenario_families.len() > smoke.scenario_families.len(),
        "nightly must have more families than smoke"
    );
}

#[test]
fn e2e_tiers_full_superset_of_nightly() {
    let config = build_tier_config();
    let nightly = config.tiers.iter().find(|t| t.name == "nightly").unwrap();
    let full = config.tiers.iter().find(|t| t.name == "full").unwrap();

    for family in &nightly.scenario_families {
        assert!(
            full.scenario_families.contains(family),
            "full tier must include all nightly families (missing '{}')",
            family
        );
    }
}

// ===========================================================================
// Tests: required artifacts
// ===========================================================================

#[test]
fn e2e_tiers_all_tiers_require_summary() {
    let config = build_tier_config();
    for tier in &config.tiers {
        assert!(
            tier.required_artifacts
                .iter()
                .any(|a| a.contains("suite_summary.json")),
            "tier '{}' must require suite_summary.json artifact",
            tier.name
        );
    }
}

#[test]
fn e2e_tiers_all_tiers_require_jsonl_log() {
    let config = build_tier_config();
    for tier in &config.tiers {
        assert!(
            tier.required_artifacts
                .iter()
                .any(|a| a.contains("suite_run.jsonl")),
            "tier '{}' must require suite_run.jsonl artifact",
            tier.name
        );
    }
}

// ===========================================================================
// Tests: reproducibility controls
// ===========================================================================

#[test]
fn e2e_tiers_all_tiers_reset_fixtures_before_run() {
    let config = build_tier_config();
    for tier in &config.tiers {
        assert!(
            tier.fixture_reset.reset_before_run,
            "tier '{}' must reset fixtures before run",
            tier.name
        );
    }
}

#[test]
fn e2e_tiers_all_tiers_have_env_normalization() {
    let config = build_tier_config();
    for tier in &config.tiers {
        assert!(
            !tier.env_normalization.is_empty(),
            "tier '{}' must have environment normalization checks",
            tier.name
        );
    }
}

#[test]
fn e2e_tiers_all_tiers_require_cargo_target_dir() {
    let config = build_tier_config();
    for tier in &config.tiers {
        assert!(
            tier.env_normalization
                .iter()
                .any(|e| e.contains("CARGO_TARGET_DIR")),
            "tier '{}' must require CARGO_TARGET_DIR",
            tier.name
        );
    }
}

#[test]
fn e2e_tiers_full_preserves_artifacts() {
    let config = build_tier_config();
    let full = config.tiers.iter().find(|t| t.name == "full").unwrap();
    assert!(
        !full.fixture_reset.cleanup_after_run,
        "full tier must preserve artifacts for release audit"
    );
}

// ===========================================================================
// Tests: flaky triage guidance
// ===========================================================================

#[test]
fn e2e_tiers_all_tiers_have_triage_guidance() {
    let config = build_tier_config();
    for tier in &config.tiers {
        assert!(
            !tier.flaky_triage_guidance.is_empty(),
            "tier '{}' must have flaky triage guidance",
            tier.name
        );
    }
}

#[test]
fn e2e_tiers_smoke_triage_never_merge() {
    let config = build_tier_config();
    let smoke = config.tiers.iter().find(|t| t.name == "smoke").unwrap();
    assert!(
        smoke.flaky_triage_guidance.contains("Never merge"),
        "smoke triage guidance must say never merge with failures"
    );
}

#[test]
fn e2e_tiers_full_triage_blocks_release() {
    let config = build_tier_config();
    let full = config.tiers.iter().find(|t| t.name == "full").unwrap();
    assert!(
        full.flaky_triage_guidance.contains("blocks release"),
        "full triage guidance must state failures block release"
    );
}

// ===========================================================================
// Tests: summary correctness
// ===========================================================================

#[test]
fn e2e_tiers_summary_correct() {
    let config = build_tier_config();
    assert_eq!(config.summary.total_tiers, 3);
    assert!(config.summary.total_families > 0);
    assert!(config.summary.merge_gating_tiers.contains(&"smoke".into()));
}

// ===========================================================================
// Tests: deterministic output
// ===========================================================================

#[test]
fn e2e_tiers_output_deterministic() {
    let c1 = build_tier_config();
    let c2 = build_tier_config();
    let json1 = serde_json::to_string(&c1).unwrap();
    let json2 = serde_json::to_string(&c2).unwrap();
    assert_eq!(json1, json2, "tier config output must be deterministic");
}

// ===========================================================================
// Tests: logging integration
// ===========================================================================

#[test]
fn e2e_tiers_logging_integration() {
    let logger = TestLoggerBuilder::new("ci_tiers").build();
    let config = build_tier_config();

    for tier in &config.tiers {
        logger.log(
            LogLevel::Info,
            LogSource::Custom("ci_tiers".into()),
            format!(
                "Tier '{}': {} families, budget={}s, pass_threshold={:.0}%, seed={:?}",
                tier.name,
                tier.scenario_families.len(),
                tier.runtime_budget_secs,
                tier.pass_threshold * 100.0,
                tier.seed_policy,
            ),
        );
    }

    let entries = logger.entries();
    assert_eq!(entries.len(), 3, "should log one entry per tier");
}
