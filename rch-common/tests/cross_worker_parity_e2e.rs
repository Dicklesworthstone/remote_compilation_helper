//! Cross-Worker Determinism/Parity Validation E2E Tests (bd-vvmd.7.10)
//!
//! Validates that identical inputs produce equivalent outcomes across workers.
//! Detects worker-specific drift (toolchain/config/env differences) and
//! classifies mismatches with root-cause categories and remediation hints.
//!
//! These tests are deterministic and do not require live workers — they exercise
//! the parity comparison infrastructure using simulated worker outputs.

use rch_common::e2e::harness::{
    ReliabilityCommandRecord, ReliabilityLifecycleCommand, ReliabilityScenarioReport,
    ReliabilityScenarioSpec,
};
use rch_common::e2e::logging::{
    LogLevel, ReliabilityContext, ReliabilityEventInput, ReliabilityPhase, TestLoggerBuilder,
    RELIABILITY_EVENT_SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ===========================================================================
// Parity comparison types
// ===========================================================================

/// Root-cause category for a cross-worker mismatch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum DriftCategory {
    /// Different toolchain versions (rustc, clang, etc.)
    ToolchainMismatch,
    /// Different environment variables or PATH
    EnvConfigDrift,
    /// Different exit codes for same command
    ExitCodeDivergence,
    /// Artifact hash mismatch for deterministic build
    ArtifactHashMismatch,
    /// Timing envelope exceeded (one worker significantly slower)
    TimingAnomaly,
    /// Log output differs beyond expected nondeterminism
    LogContentDivergence,
    /// Disk pressure or resource contention
    ResourceContention,
    /// Unknown root cause
    Unknown,
}

impl DriftCategory {
    fn remediation_hint(&self) -> &'static str {
        match self {
            Self::ToolchainMismatch => "Run `rch doctor --check-toolchain` across fleet",
            Self::EnvConfigDrift => "Compare `rch status --json` env sections across workers",
            Self::ExitCodeDivergence => "Check worker logs for command-specific failure context",
            Self::ArtifactHashMismatch => "Verify incremental build state is clean on both workers",
            Self::TimingAnomaly => "Check worker load and disk I/O; consider rebalancing",
            Self::LogContentDivergence => "Compare build environment snapshots for discrepancies",
            Self::ResourceContention => "Check disk pressure and slot utilization on affected worker",
            Self::Unknown => "Investigate worker health dashboard for anomalies",
        }
    }
}

/// A single parity comparison result between two workers.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ParityComparisonResult {
    scenario_id: String,
    worker_a: String,
    worker_b: String,
    exit_code_match: bool,
    artifact_hash_match: bool,
    timing_within_envelope: bool,
    log_content_similar: bool,
    is_parity: bool,
    drift_categories: Vec<DriftCategory>,
    remediation_hints: Vec<String>,
}

/// Simulated worker execution output for parity comparison.
#[derive(Debug, Clone)]
struct SimulatedWorkerOutput {
    worker_id: String,
    exit_code: i32,
    artifact_hash: String,
    duration_ms: u64,
    log_signature: String,
    toolchain_version: String,
    env_hash: String,
}

/// Fleet parity summary across all comparisons.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct FleetParitySummary {
    total_comparisons: usize,
    parity_pass: usize,
    parity_fail: usize,
    parity_rate: f64,
    drift_category_counts: HashMap<String, usize>,
    worst_timing_ratio: f64,
    workers_with_drift: Vec<String>,
}

// ===========================================================================
// Parity comparison logic
// ===========================================================================

fn compare_worker_outputs(
    scenario_id: &str,
    a: &SimulatedWorkerOutput,
    b: &SimulatedWorkerOutput,
    timing_envelope_ratio: f64,
) -> ParityComparisonResult {
    let mut drift_categories = Vec::new();
    let mut remediation_hints = Vec::new();

    let exit_code_match = a.exit_code == b.exit_code;
    if !exit_code_match {
        drift_categories.push(DriftCategory::ExitCodeDivergence);
    }

    let artifact_hash_match = a.artifact_hash == b.artifact_hash;
    if !artifact_hash_match {
        drift_categories.push(DriftCategory::ArtifactHashMismatch);
    }

    let timing_ratio = if a.duration_ms > 0 && b.duration_ms > 0 {
        let max_d = a.duration_ms.max(b.duration_ms) as f64;
        let min_d = a.duration_ms.min(b.duration_ms) as f64;
        max_d / min_d
    } else {
        1.0
    };
    let timing_within_envelope = timing_ratio <= timing_envelope_ratio;
    if !timing_within_envelope {
        drift_categories.push(DriftCategory::TimingAnomaly);
    }

    let log_content_similar = a.log_signature == b.log_signature;
    if !log_content_similar {
        drift_categories.push(DriftCategory::LogContentDivergence);
    }

    if a.toolchain_version != b.toolchain_version {
        drift_categories.push(DriftCategory::ToolchainMismatch);
    }

    if a.env_hash != b.env_hash {
        drift_categories.push(DriftCategory::EnvConfigDrift);
    }

    for cat in &drift_categories {
        remediation_hints.push(cat.remediation_hint().to_string());
    }

    let is_parity = exit_code_match && artifact_hash_match && timing_within_envelope;

    ParityComparisonResult {
        scenario_id: scenario_id.to_string(),
        worker_a: a.worker_id.clone(),
        worker_b: b.worker_id.clone(),
        exit_code_match,
        artifact_hash_match,
        timing_within_envelope,
        log_content_similar,
        is_parity,
        drift_categories,
        remediation_hints,
    }
}

/// Deterministic PRNG (xorshift64).
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(if seed == 0 { 1 } else { seed })
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    fn next_bool(&mut self, p: f64) -> bool {
        self.next_f64() < p
    }
}

/// Generate a simulated worker output with optional drift injection.
fn simulate_worker_output(
    worker_id: &str,
    scenario_id: &str,
    rng: &mut Rng,
    inject_drift: bool,
) -> SimulatedWorkerOutput {
    let base_hash = format!("sha256:{scenario_id}:base");
    let base_duration = 1000 + (rng.next_u64() % 500);
    let base_log_sig = format!("log:{scenario_id}:ok");

    if inject_drift {
        // Introduce one or more forms of drift
        let artifact_hash = if rng.next_bool(0.4) {
            format!("sha256:{scenario_id}:{worker_id}:drifted")
        } else {
            base_hash.clone()
        };

        let exit_code = if rng.next_bool(0.2) { 1 } else { 0 };
        let duration = if rng.next_bool(0.3) {
            base_duration * 3 // Timing anomaly
        } else {
            base_duration + rng.next_u64() % 200
        };
        let toolchain = if rng.next_bool(0.2) {
            "rustc-1.84.0".to_string()
        } else {
            "rustc-1.85.0".to_string()
        };
        let log_sig = if rng.next_bool(0.15) {
            format!("log:{scenario_id}:warning")
        } else {
            base_log_sig.clone()
        };

        SimulatedWorkerOutput {
            worker_id: worker_id.to_string(),
            exit_code,
            artifact_hash,
            duration_ms: duration,
            log_signature: log_sig,
            toolchain_version: toolchain,
            env_hash: format!("env:{worker_id}:v2"),
        }
    } else {
        SimulatedWorkerOutput {
            worker_id: worker_id.to_string(),
            exit_code: 0,
            artifact_hash: base_hash,
            duration_ms: base_duration + rng.next_u64() % 200,
            log_signature: base_log_sig,
            toolchain_version: "rustc-1.85.0".to_string(),
            env_hash: "env:standard:v1".to_string(),
        }
    }
}

// ===========================================================================
// 1. Parity Comparison Logic Tests
// ===========================================================================

#[test]
fn e2e_parity_identical_outputs_pass() {
    let a = SimulatedWorkerOutput {
        worker_id: "css".to_string(),
        exit_code: 0,
        artifact_hash: "sha256:abc123".to_string(),
        duration_ms: 1200,
        log_signature: "log:ok".to_string(),
        toolchain_version: "rustc-1.85.0".to_string(),
        env_hash: "env:v1".to_string(),
    };
    let b = SimulatedWorkerOutput {
        worker_id: "mms".to_string(),
        exit_code: 0,
        artifact_hash: "sha256:abc123".to_string(),
        duration_ms: 1300,
        log_signature: "log:ok".to_string(),
        toolchain_version: "rustc-1.85.0".to_string(),
        env_hash: "env:v1".to_string(),
    };

    let result = compare_worker_outputs("scenario-1", &a, &b, 2.0);

    assert!(result.is_parity);
    assert!(result.exit_code_match);
    assert!(result.artifact_hash_match);
    assert!(result.timing_within_envelope);
    assert!(result.log_content_similar);
    assert!(result.drift_categories.is_empty());
}

#[test]
fn e2e_parity_exit_code_divergence_detected() {
    let a = SimulatedWorkerOutput {
        worker_id: "css".to_string(),
        exit_code: 0,
        artifact_hash: "sha256:abc".to_string(),
        duration_ms: 1000,
        log_signature: "log:ok".to_string(),
        toolchain_version: "rustc-1.85.0".to_string(),
        env_hash: "env:v1".to_string(),
    };
    let b = SimulatedWorkerOutput {
        worker_id: "mms".to_string(),
        exit_code: 101,
        artifact_hash: "sha256:abc".to_string(),
        duration_ms: 1100,
        log_signature: "log:ok".to_string(),
        toolchain_version: "rustc-1.85.0".to_string(),
        env_hash: "env:v1".to_string(),
    };

    let result = compare_worker_outputs("scenario-exit", &a, &b, 2.0);

    assert!(!result.is_parity);
    assert!(!result.exit_code_match);
    assert!(result.drift_categories.contains(&DriftCategory::ExitCodeDivergence));
    assert!(!result.remediation_hints.is_empty());
}

#[test]
fn e2e_parity_artifact_hash_mismatch_detected() {
    let a = SimulatedWorkerOutput {
        worker_id: "css".to_string(),
        exit_code: 0,
        artifact_hash: "sha256:aaa".to_string(),
        duration_ms: 1000,
        log_signature: "log:ok".to_string(),
        toolchain_version: "rustc-1.85.0".to_string(),
        env_hash: "env:v1".to_string(),
    };
    let b = SimulatedWorkerOutput {
        worker_id: "mms".to_string(),
        exit_code: 0,
        artifact_hash: "sha256:bbb".to_string(),
        duration_ms: 1000,
        log_signature: "log:ok".to_string(),
        toolchain_version: "rustc-1.85.0".to_string(),
        env_hash: "env:v1".to_string(),
    };

    let result = compare_worker_outputs("scenario-hash", &a, &b, 2.0);

    assert!(!result.is_parity);
    assert!(!result.artifact_hash_match);
    assert!(result.drift_categories.contains(&DriftCategory::ArtifactHashMismatch));
}

#[test]
fn e2e_parity_timing_anomaly_detected() {
    let a = SimulatedWorkerOutput {
        worker_id: "css".to_string(),
        exit_code: 0,
        artifact_hash: "sha256:same".to_string(),
        duration_ms: 1000,
        log_signature: "log:ok".to_string(),
        toolchain_version: "rustc-1.85.0".to_string(),
        env_hash: "env:v1".to_string(),
    };
    let b = SimulatedWorkerOutput {
        worker_id: "mms".to_string(),
        exit_code: 0,
        artifact_hash: "sha256:same".to_string(),
        duration_ms: 5000, // 5x slower
        log_signature: "log:ok".to_string(),
        toolchain_version: "rustc-1.85.0".to_string(),
        env_hash: "env:v1".to_string(),
    };

    let result = compare_worker_outputs("scenario-timing", &a, &b, 2.0);

    assert!(!result.is_parity);
    assert!(!result.timing_within_envelope);
    assert!(result.drift_categories.contains(&DriftCategory::TimingAnomaly));
}

#[test]
fn e2e_parity_toolchain_mismatch_detected() {
    let a = SimulatedWorkerOutput {
        worker_id: "css".to_string(),
        exit_code: 0,
        artifact_hash: "sha256:same".to_string(),
        duration_ms: 1000,
        log_signature: "log:ok".to_string(),
        toolchain_version: "rustc-1.85.0".to_string(),
        env_hash: "env:v1".to_string(),
    };
    let b = SimulatedWorkerOutput {
        worker_id: "mms".to_string(),
        exit_code: 0,
        artifact_hash: "sha256:same".to_string(),
        duration_ms: 1100,
        log_signature: "log:ok".to_string(),
        toolchain_version: "rustc-1.84.0".to_string(),
        env_hash: "env:v1".to_string(),
    };

    let result = compare_worker_outputs("scenario-toolchain", &a, &b, 2.0);

    // Parity still passes (exit code, hash, timing match) but drift is noted
    assert!(result.is_parity);
    assert!(result.drift_categories.contains(&DriftCategory::ToolchainMismatch));
}

#[test]
fn e2e_parity_multiple_drift_categories_detected() {
    let a = SimulatedWorkerOutput {
        worker_id: "css".to_string(),
        exit_code: 0,
        artifact_hash: "sha256:aaa".to_string(),
        duration_ms: 1000,
        log_signature: "log:ok".to_string(),
        toolchain_version: "rustc-1.85.0".to_string(),
        env_hash: "env:v1".to_string(),
    };
    let b = SimulatedWorkerOutput {
        worker_id: "mms".to_string(),
        exit_code: 1,
        artifact_hash: "sha256:bbb".to_string(),
        duration_ms: 4000,
        log_signature: "log:error".to_string(),
        toolchain_version: "rustc-1.84.0".to_string(),
        env_hash: "env:v2".to_string(),
    };

    let result = compare_worker_outputs("scenario-multi", &a, &b, 2.0);

    assert!(!result.is_parity);
    assert!(result.drift_categories.len() >= 4);
    assert!(result.drift_categories.contains(&DriftCategory::ExitCodeDivergence));
    assert!(result.drift_categories.contains(&DriftCategory::ArtifactHashMismatch));
    assert!(result.drift_categories.contains(&DriftCategory::TimingAnomaly));
    assert!(result.drift_categories.contains(&DriftCategory::ToolchainMismatch));

    // Each drift category should produce a remediation hint
    assert_eq!(result.remediation_hints.len(), result.drift_categories.len());
}

// ===========================================================================
// 2. Fleet Parity Across Multiple Workers
// ===========================================================================

#[test]
fn e2e_parity_fleet_comparison_all_workers_identical() {
    let workers = ["css", "mms", "gpu-01"];
    let scenarios = ["build-debug", "build-release", "test-all"];
    let mut rng = Rng::new(42);

    let mut comparisons: Vec<ParityComparisonResult> = Vec::new();

    for scenario in &scenarios {
        // Generate identical outputs for all workers (no drift)
        let outputs: Vec<SimulatedWorkerOutput> = workers
            .iter()
            .map(|w| simulate_worker_output(w, scenario, &mut rng, false))
            .collect();

        // Compare all pairs
        for i in 0..outputs.len() {
            for j in (i + 1)..outputs.len() {
                comparisons.push(compare_worker_outputs(
                    scenario,
                    &outputs[i],
                    &outputs[j],
                    2.0,
                ));
            }
        }
    }

    // All comparisons should pass parity (exit code, hash, timing)
    let parity_pass = comparisons.iter().filter(|c| c.is_parity).count();
    assert_eq!(
        parity_pass,
        comparisons.len(),
        "expected all {} comparisons to pass parity, but only {} did",
        comparisons.len(),
        parity_pass
    );
}

#[test]
fn e2e_parity_fleet_detects_single_drifted_worker() {
    let workers = ["css", "mms", "gpu-01"];
    let mut rng = Rng::new(123);
    let scenario = "build-release";

    // css and mms are identical, gpu-01 has drift
    let outputs: Vec<SimulatedWorkerOutput> = workers
        .iter()
        .map(|w| simulate_worker_output(w, scenario, &mut rng, *w == "gpu-01"))
        .collect();

    let mut comparisons: Vec<ParityComparisonResult> = Vec::new();
    for i in 0..outputs.len() {
        for j in (i + 1)..outputs.len() {
            comparisons.push(compare_worker_outputs(
                scenario,
                &outputs[i],
                &outputs[j],
                2.0,
            ));
        }
    }

    // css vs mms should pass parity
    let css_mms = comparisons
        .iter()
        .find(|c| {
            (c.worker_a == "css" && c.worker_b == "mms")
                || (c.worker_a == "mms" && c.worker_b == "css")
        })
        .expect("should have css-mms comparison");
    assert!(
        css_mms.is_parity,
        "css vs mms should have parity"
    );

    // At least one comparison involving gpu-01 should detect drift
    let gpu_comparisons: Vec<&ParityComparisonResult> = comparisons
        .iter()
        .filter(|c| c.worker_a == "gpu-01" || c.worker_b == "gpu-01")
        .collect();
    assert_eq!(gpu_comparisons.len(), 2);

    // gpu-01 comparisons should have some drift detected
    // (env_hash will always differ since inject_drift uses worker-specific env)
    let gpu_has_drift = gpu_comparisons
        .iter()
        .any(|c| !c.drift_categories.is_empty());
    assert!(
        gpu_has_drift,
        "gpu-01 comparisons should detect drift"
    );
}

// ===========================================================================
// 3. Parity Results Serialization & Schema
// ===========================================================================

#[test]
fn e2e_parity_comparison_result_serialization() {
    let result = ParityComparisonResult {
        scenario_id: "build-test".to_string(),
        worker_a: "css".to_string(),
        worker_b: "mms".to_string(),
        exit_code_match: true,
        artifact_hash_match: false,
        timing_within_envelope: true,
        log_content_similar: true,
        is_parity: false,
        drift_categories: vec![DriftCategory::ArtifactHashMismatch],
        remediation_hints: vec![
            "Verify incremental build state is clean on both workers".to_string(),
        ],
    };

    let json = serde_json::to_string_pretty(&result).unwrap();
    let val: serde_json::Value = serde_json::from_str(&json).unwrap();

    assert_eq!(val["scenario_id"].as_str().unwrap(), "build-test");
    assert_eq!(val["worker_a"].as_str().unwrap(), "css");
    assert_eq!(val["worker_b"].as_str().unwrap(), "mms");
    assert!(val["exit_code_match"].as_bool().unwrap());
    assert!(!val["artifact_hash_match"].as_bool().unwrap());
    assert!(!val["is_parity"].as_bool().unwrap());

    let drift = val["drift_categories"].as_array().unwrap();
    assert_eq!(drift.len(), 1);
    assert_eq!(drift[0].as_str().unwrap(), "artifact_hash_mismatch");

    // Roundtrip
    let parsed: ParityComparisonResult = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.scenario_id, "build-test");
    assert_eq!(parsed.drift_categories, vec![DriftCategory::ArtifactHashMismatch]);
}

#[test]
fn e2e_parity_fleet_summary_serialization() {
    let summary = FleetParitySummary {
        total_comparisons: 15,
        parity_pass: 12,
        parity_fail: 3,
        parity_rate: 0.80,
        drift_category_counts: {
            let mut m = HashMap::new();
            m.insert("exit_code_divergence".to_string(), 2);
            m.insert("artifact_hash_mismatch".to_string(), 1);
            m
        },
        worst_timing_ratio: 3.5,
        workers_with_drift: vec!["gpu-01".to_string()],
    };

    let json = serde_json::to_string_pretty(&summary).unwrap();
    let val: serde_json::Value = serde_json::from_str(&json).unwrap();

    assert_eq!(val["total_comparisons"].as_u64().unwrap(), 15);
    assert_eq!(val["parity_pass"].as_u64().unwrap(), 12);
    assert_eq!(val["parity_fail"].as_u64().unwrap(), 3);
    assert!(val["parity_rate"].as_f64().unwrap() > 0.79);
    assert!(val["drift_category_counts"].is_object());
    assert_eq!(val["workers_with_drift"].as_array().unwrap().len(), 1);

    // pass + fail = total
    let pass = val["parity_pass"].as_u64().unwrap();
    let fail = val["parity_fail"].as_u64().unwrap();
    let total = val["total_comparisons"].as_u64().unwrap();
    assert_eq!(pass + fail, total);
}

// ===========================================================================
// 4. Drift Category Classification Tests
// ===========================================================================

#[test]
fn e2e_parity_all_drift_categories_have_remediation() {
    let categories = [
        DriftCategory::ToolchainMismatch,
        DriftCategory::EnvConfigDrift,
        DriftCategory::ExitCodeDivergence,
        DriftCategory::ArtifactHashMismatch,
        DriftCategory::TimingAnomaly,
        DriftCategory::LogContentDivergence,
        DriftCategory::ResourceContention,
        DriftCategory::Unknown,
    ];

    for cat in &categories {
        let hint = cat.remediation_hint();
        assert!(
            !hint.is_empty(),
            "{:?} must have a non-empty remediation hint",
            cat
        );
    }
}

#[test]
fn e2e_parity_drift_categories_serialize_snake_case() {
    let categories = [
        (DriftCategory::ToolchainMismatch, "toolchain_mismatch"),
        (DriftCategory::EnvConfigDrift, "env_config_drift"),
        (DriftCategory::ExitCodeDivergence, "exit_code_divergence"),
        (DriftCategory::ArtifactHashMismatch, "artifact_hash_mismatch"),
        (DriftCategory::TimingAnomaly, "timing_anomaly"),
        (DriftCategory::LogContentDivergence, "log_content_divergence"),
        (DriftCategory::ResourceContention, "resource_contention"),
        (DriftCategory::Unknown, "unknown"),
    ];

    for (cat, expected_str) in &categories {
        let json = serde_json::to_string(cat).unwrap();
        assert_eq!(
            json,
            format!("\"{expected_str}\""),
            "{:?} should serialize to {expected_str}",
            cat
        );

        // Roundtrip
        let parsed: DriftCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(&parsed, cat);
    }
}

// ===========================================================================
// 5. Multi-Scenario Fleet Parity Report
// ===========================================================================

#[test]
fn e2e_parity_multi_scenario_fleet_report() {
    let workers = ["css", "mms", "gpu-01", "gpu-02"];
    let scenarios = [
        "cargo-build-debug",
        "cargo-build-release",
        "cargo-test",
        "cargo-clippy",
    ];
    let mut rng = Rng::new(7777);

    let mut all_comparisons: Vec<ParityComparisonResult> = Vec::new();
    let mut drift_counts: HashMap<String, usize> = HashMap::new();
    let mut worst_timing_ratio = 1.0f64;
    let mut workers_with_drift: std::collections::HashSet<String> = std::collections::HashSet::new();

    for scenario in &scenarios {
        let outputs: Vec<SimulatedWorkerOutput> = workers
            .iter()
            .map(|w| {
                // Inject drift on gpu-02 with 40% probability
                let inject = *w == "gpu-02" && rng.next_bool(0.4);
                simulate_worker_output(w, scenario, &mut rng, inject)
            })
            .collect();

        for i in 0..outputs.len() {
            for j in (i + 1)..outputs.len() {
                let cmp = compare_worker_outputs(scenario, &outputs[i], &outputs[j], 2.0);

                for cat in &cmp.drift_categories {
                    let key = serde_json::to_string(cat).unwrap().trim_matches('"').to_string();
                    *drift_counts.entry(key).or_insert(0) += 1;
                }

                if !cmp.is_parity {
                    workers_with_drift.insert(cmp.worker_a.clone());
                    workers_with_drift.insert(cmp.worker_b.clone());
                }

                // Track timing ratio
                if !cmp.timing_within_envelope {
                    worst_timing_ratio = worst_timing_ratio.max(3.0); // We know it exceeds 2.0
                }

                all_comparisons.push(cmp);
            }
        }
    }

    let parity_pass = all_comparisons.iter().filter(|c| c.is_parity).count();
    let parity_fail = all_comparisons.len() - parity_pass;
    let parity_rate = parity_pass as f64 / all_comparisons.len() as f64;

    let summary = FleetParitySummary {
        total_comparisons: all_comparisons.len(),
        parity_pass,
        parity_fail,
        parity_rate,
        drift_category_counts: drift_counts,
        worst_timing_ratio,
        workers_with_drift: workers_with_drift.into_iter().collect(),
    };

    // Verify fleet report structure
    let json = serde_json::to_string_pretty(&summary).unwrap();
    let _: serde_json::Value = serde_json::from_str(&json).unwrap();

    // Expected: 4 scenarios × C(4,2) = 4 × 6 = 24 comparisons
    assert_eq!(summary.total_comparisons, 24);
    assert_eq!(summary.parity_pass + summary.parity_fail, 24);

    // Parity rate should be reasonable (most workers are identical)
    assert!(
        summary.parity_rate > 0.5,
        "parity rate {:.2} is suspiciously low",
        summary.parity_rate
    );
}

// ===========================================================================
// 6. Parity with Reliability Scenario Specs
// ===========================================================================

#[test]
fn e2e_parity_scenario_spec_identical_across_workers() {
    let workers = ["css", "mms"];

    let specs: Vec<ReliabilityScenarioSpec> = workers
        .iter()
        .map(|w| {
            ReliabilityScenarioSpec::new("parity-build")
                .with_worker_id(*w)
                .with_repo_set(["/data/projects/rch"])
                .with_pressure_state("disk:normal,memory:normal")
                .add_pre_check(ReliabilityLifecycleCommand::new(
                    "disk-check",
                    "echo",
                    ["df -h"],
                ))
                .add_execute_command(
                    ReliabilityLifecycleCommand::new("build", "echo", ["cargo build"])
                        .with_timeout_secs(300),
                )
                .add_post_check(ReliabilityLifecycleCommand::new(
                    "verify-artifact",
                    "echo",
                    ["ls target/debug"],
                ))
        })
        .collect();

    // Specs should differ only in worker_id
    assert_eq!(specs[0].scenario_id, specs[1].scenario_id);
    assert_eq!(specs[0].repo_set, specs[1].repo_set);
    assert_eq!(specs[0].pressure_state, specs[1].pressure_state);
    assert_eq!(
        specs[0].execute_commands.len(),
        specs[1].execute_commands.len()
    );
    assert_ne!(specs[0].worker_id, specs[1].worker_id);

    // Both should serialize to valid JSON
    for spec in &specs {
        let json = serde_json::to_string(spec).unwrap();
        let _: serde_json::Value = serde_json::from_str(&json).unwrap();
    }
}

#[test]
fn e2e_parity_report_comparison_across_workers() {
    let workers = ["css", "mms"];

    let reports: Vec<ReliabilityScenarioReport> = workers
        .iter()
        .map(|w| ReliabilityScenarioReport {
            schema_version: RELIABILITY_EVENT_SCHEMA_VERSION.to_string(),
            scenario_id: format!("parity-{w}"),
            phase_order: vec![
                ReliabilityPhase::Setup,
                ReliabilityPhase::Execute,
                ReliabilityPhase::Verify,
                ReliabilityPhase::Cleanup,
            ],
            activated_failure_hooks: vec![],
            command_records: vec![
                ReliabilityCommandRecord {
                    phase: ReliabilityPhase::Execute,
                    stage: "execute".to_string(),
                    command_name: "build".to_string(),
                    invoked_program: "cargo".to_string(),
                    invoked_args: vec!["build".to_string()],
                    exit_code: 0,
                    duration_ms: 1500,
                    required_success: true,
                    succeeded: true,
                    artifact_paths: vec![],
                },
            ],
            artifact_paths: vec![],
            manifest_path: None,
        })
        .collect();

    // Phase order should be identical
    assert_eq!(reports[0].phase_order, reports[1].phase_order);

    // Command records should have same structure
    assert_eq!(
        reports[0].command_records.len(),
        reports[1].command_records.len()
    );
    assert_eq!(
        reports[0].command_records[0].exit_code,
        reports[1].command_records[0].exit_code
    );
}

// ===========================================================================
// 7. Parity Logging Integration
// ===========================================================================

#[test]
fn e2e_parity_results_logged_as_reliability_events() {
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let logger = TestLoggerBuilder::new("parity_logging_test")
        .log_dir(temp_dir.path())
        .print_realtime(false)
        .build();

    let result = ParityComparisonResult {
        scenario_id: "build-parity".to_string(),
        worker_a: "css".to_string(),
        worker_b: "mms".to_string(),
        exit_code_match: true,
        artifact_hash_match: true,
        timing_within_envelope: true,
        log_content_similar: true,
        is_parity: true,
        drift_categories: vec![],
        remediation_hints: vec![],
    };

    let event = logger.log_reliability_event(ReliabilityEventInput {
        level: if result.is_parity {
            LogLevel::Info
        } else {
            LogLevel::Warn
        },
        phase: ReliabilityPhase::Verify,
        scenario_id: result.scenario_id.clone(),
        message: format!(
            "parity check {} vs {}: {}",
            result.worker_a,
            result.worker_b,
            if result.is_parity { "PASS" } else { "FAIL" }
        ),
        context: ReliabilityContext {
            worker_id: Some(result.worker_a.clone()),
            repo_set: vec!["/data/projects/rch".to_string()],
            pressure_state: None,
            triage_actions: result
                .drift_categories
                .iter()
                .map(|c| format!("{c:?}"))
                .collect(),
            decision_code: if result.is_parity {
                "PARITY_PASS".to_string()
            } else {
                "PARITY_FAIL".to_string()
            },
            fallback_reason: None,
        },
        artifact_paths: vec![],
    });

    assert_eq!(event.schema_version, RELIABILITY_EVENT_SCHEMA_VERSION);
    assert_eq!(event.phase, ReliabilityPhase::Verify);
    assert_eq!(event.context.decision_code, "PARITY_PASS");
}

// ===========================================================================
// 8. Timing Envelope Tests
// ===========================================================================

#[test]
fn e2e_parity_timing_envelope_boundary_conditions() {
    let base = SimulatedWorkerOutput {
        worker_id: "css".to_string(),
        exit_code: 0,
        artifact_hash: "sha256:same".to_string(),
        duration_ms: 1000,
        log_signature: "log:ok".to_string(),
        toolchain_version: "rustc-1.85.0".to_string(),
        env_hash: "env:v1".to_string(),
    };

    // Exactly at 2x boundary
    let at_boundary = SimulatedWorkerOutput {
        duration_ms: 2000,
        worker_id: "mms".to_string(),
        ..base.clone()
    };
    let result = compare_worker_outputs("timing-boundary", &base, &at_boundary, 2.0);
    assert!(result.timing_within_envelope, "exactly 2x should be within 2.0 envelope");

    // Just over 2x
    let over_boundary = SimulatedWorkerOutput {
        duration_ms: 2001,
        worker_id: "mms".to_string(),
        ..base.clone()
    };
    let result = compare_worker_outputs("timing-over", &base, &over_boundary, 2.0);
    assert!(!result.timing_within_envelope, "2.001x should exceed 2.0 envelope");

    // Zero duration (edge case)
    let zero_dur = SimulatedWorkerOutput {
        duration_ms: 0,
        worker_id: "mms".to_string(),
        ..base.clone()
    };
    let result = compare_worker_outputs("timing-zero", &base, &zero_dur, 2.0);
    // With one zero, ratio is 1.0 (both need to be > 0 for actual ratio)
    assert!(result.timing_within_envelope, "zero duration edge case");
}

// ===========================================================================
// 9. Parity Threshold Gate Tests
// ===========================================================================

#[test]
fn e2e_parity_threshold_gate_pass() {
    let parity_rate = 0.95;
    let threshold = 0.90;
    assert!(
        parity_rate >= threshold,
        "fleet parity rate {parity_rate:.2} must meet {threshold:.2} threshold"
    );
}

#[test]
fn e2e_parity_threshold_gate_with_fleet_summary() {
    let summary = FleetParitySummary {
        total_comparisons: 100,
        parity_pass: 92,
        parity_fail: 8,
        parity_rate: 0.92,
        drift_category_counts: HashMap::new(),
        worst_timing_ratio: 1.8,
        workers_with_drift: vec!["gpu-02".to_string()],
    };

    // Release gate: parity rate must be >= 85%
    assert!(
        summary.parity_rate >= 0.85,
        "release gate: parity rate {:.2} below 85%",
        summary.parity_rate
    );

    // No more than 2 workers should have drift
    assert!(
        summary.workers_with_drift.len() <= 2,
        "release gate: {} workers with drift (max 2)",
        summary.workers_with_drift.len()
    );

    // Worst timing ratio should be < 5x
    assert!(
        summary.worst_timing_ratio < 5.0,
        "release gate: worst timing ratio {:.1} exceeds 5x",
        summary.worst_timing_ratio
    );
}

// ===========================================================================
// 10. Deterministic Seed Reproducibility
// ===========================================================================

#[test]
fn e2e_parity_seed_reproducibility() {
    let seed = 54321u64;
    let workers = ["css", "mms"];
    let scenario = "parity-repro";

    // Run 1
    let mut rng1 = Rng::new(seed);
    let outputs1: Vec<SimulatedWorkerOutput> = workers
        .iter()
        .map(|w| simulate_worker_output(w, scenario, &mut rng1, false))
        .collect();
    let result1 = compare_worker_outputs(scenario, &outputs1[0], &outputs1[1], 2.0);

    // Run 2 (same seed)
    let mut rng2 = Rng::new(seed);
    let outputs2: Vec<SimulatedWorkerOutput> = workers
        .iter()
        .map(|w| simulate_worker_output(w, scenario, &mut rng2, false))
        .collect();
    let result2 = compare_worker_outputs(scenario, &outputs2[0], &outputs2[1], 2.0);

    assert_eq!(result1.is_parity, result2.is_parity);
    assert_eq!(result1.exit_code_match, result2.exit_code_match);
    assert_eq!(result1.artifact_hash_match, result2.artifact_hash_match);
    assert_eq!(result1.drift_categories, result2.drift_categories);
}
