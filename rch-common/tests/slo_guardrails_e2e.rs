//! SLO guardrails and regression checks for reliability features (bd-vvmd.6.5)
//!
//! Validates:
//!   - Measurable budgets for hook latency, convergence latency, fallback rate, triage overhead
//!   - SLO definitions with measurement windows and error-budget consumption semantics
//!   - Regression checks that fail clearly when thresholds are exceeded
//!   - Alert criteria with debouncing/hysteresis to avoid noise
//!   - Regression reports with actionable attribution data

use rch_common::e2e::logging::{LogLevel, LogSource, TestLoggerBuilder};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ===========================================================================
// SLO types
// ===========================================================================

const SLO_GUARDRAILS_SCHEMA_VERSION: &str = "1.0.0";

/// A measurable SLO guardrail definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SloGuardrail {
    /// Unique SLO identifier (e.g., "SLO-HOOK-LATENCY-P99").
    id: String,
    /// Human-readable description.
    description: String,
    /// The metric being measured.
    metric: String,
    /// Unit of measurement.
    unit: String,
    /// Budget threshold value (exceeding this is a violation).
    threshold: f64,
    /// Measurement window in seconds.
    measurement_window_secs: u64,
    /// Error budget: fraction of requests allowed to violate (0.0 to 1.0).
    error_budget: f64,
    /// Responsible component/subsystem.
    component: String,
    /// CI tier where this check runs.
    ci_tier: String,
    /// Alert criteria.
    alert: AlertCriteria,
}

/// Alert criteria with debouncing.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AlertCriteria {
    /// Number of consecutive violations before alerting.
    consecutive_violations_threshold: u32,
    /// Minimum time between alerts in seconds (debouncing).
    min_alert_interval_secs: u64,
    /// Whether this alert blocks release.
    blocks_release: bool,
}

/// A simulated metric sample for validation.
#[derive(Debug, Clone)]
struct MetricSample {
    value: f64,
    #[allow(dead_code)]
    timestamp_ms: u64,
}

/// Result of checking a metric against an SLO.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SloCheckResult {
    slo_id: String,
    passed: bool,
    current_value: f64,
    threshold: f64,
    error_budget_remaining: f64,
    violation_count: u32,
    sample_count: u32,
}

/// Alert state tracker for hysteresis.
#[derive(Debug, Clone)]
struct AlertState {
    consecutive_violations: u32,
    last_alert_timestamp_ms: u64,
    alert_fired: bool,
}

/// A regression report entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RegressionEntry {
    slo_id: String,
    component: String,
    regression_pct: f64,
    baseline_value: f64,
    current_value: f64,
    attribution: String,
}

/// Full SLO configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SloConfig {
    schema_version: String,
    guardrails: Vec<SloGuardrail>,
    summary: SloSummary,
}

/// Summary of SLO definitions.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SloSummary {
    total_guardrails: usize,
    release_blocking: usize,
    components: Vec<String>,
}

// ===========================================================================
// SLO definitions
// ===========================================================================

fn build_slo_guardrails() -> Vec<SloGuardrail> {
    vec![
        // Hook latency
        SloGuardrail {
            id: "SLO-HOOK-P50".into(),
            description: "Hook decision latency P50 must stay under 1ms".into(),
            metric: "hook_decision_latency_ms".into(),
            unit: "ms".into(),
            threshold: 1.0,
            measurement_window_secs: 3600,
            error_budget: 0.01, // 1% violations allowed
            component: "hook".into(),
            ci_tier: "smoke".into(),
            alert: AlertCriteria {
                consecutive_violations_threshold: 3,
                min_alert_interval_secs: 300,
                blocks_release: true,
            },
        },
        SloGuardrail {
            id: "SLO-HOOK-P99".into(),
            description: "Hook decision latency P99 must stay under 5ms".into(),
            metric: "hook_decision_latency_ms".into(),
            unit: "ms".into(),
            threshold: 5.0,
            measurement_window_secs: 3600,
            error_budget: 0.001, // 0.1% violations
            component: "hook".into(),
            ci_tier: "smoke".into(),
            alert: AlertCriteria {
                consecutive_violations_threshold: 2,
                min_alert_interval_secs: 60,
                blocks_release: true,
            },
        },
        // Convergence latency
        SloGuardrail {
            id: "SLO-CONV-P50".into(),
            description: "Repo convergence check latency P50 under 100ms".into(),
            metric: "convergence_check_latency_ms".into(),
            unit: "ms".into(),
            threshold: 100.0,
            measurement_window_secs: 3600,
            error_budget: 0.05,
            component: "convergence".into(),
            ci_tier: "smoke".into(),
            alert: AlertCriteria {
                consecutive_violations_threshold: 5,
                min_alert_interval_secs: 600,
                blocks_release: false,
            },
        },
        SloGuardrail {
            id: "SLO-CONV-P99".into(),
            description: "Repo convergence check latency P99 under 500ms".into(),
            metric: "convergence_check_latency_ms".into(),
            unit: "ms".into(),
            threshold: 500.0,
            measurement_window_secs: 3600,
            error_budget: 0.01,
            component: "convergence".into(),
            ci_tier: "nightly".into(),
            alert: AlertCriteria {
                consecutive_violations_threshold: 3,
                min_alert_interval_secs: 300,
                blocks_release: true,
            },
        },
        // Fallback rate
        SloGuardrail {
            id: "SLO-FALLBACK-RATE".into(),
            description: "Local fallback rate must stay under 10%".into(),
            metric: "local_fallback_rate".into(),
            unit: "ratio".into(),
            threshold: 0.10,
            measurement_window_secs: 86400, // 24h
            error_budget: 0.0, // any sustained violation is a problem
            component: "routing".into(),
            ci_tier: "nightly".into(),
            alert: AlertCriteria {
                consecutive_violations_threshold: 2,
                min_alert_interval_secs: 3600,
                blocks_release: true,
            },
        },
        // Triage overhead
        SloGuardrail {
            id: "SLO-TRIAGE-OVERHEAD".into(),
            description: "Process triage decision overhead under 2ms".into(),
            metric: "triage_decision_overhead_ms".into(),
            unit: "ms".into(),
            threshold: 2.0,
            measurement_window_secs: 3600,
            error_budget: 0.01,
            component: "process_triage".into(),
            ci_tier: "smoke".into(),
            alert: AlertCriteria {
                consecutive_violations_threshold: 3,
                min_alert_interval_secs: 300,
                blocks_release: true,
            },
        },
        // Cancellation cleanup
        SloGuardrail {
            id: "SLO-CANCEL-CLEANUP".into(),
            description: "Build cancellation cleanup must complete within 10s".into(),
            metric: "cancellation_cleanup_latency_ms".into(),
            unit: "ms".into(),
            threshold: 10_000.0,
            measurement_window_secs: 3600,
            error_budget: 0.02,
            component: "cancellation".into(),
            ci_tier: "nightly".into(),
            alert: AlertCriteria {
                consecutive_violations_threshold: 2,
                min_alert_interval_secs: 300,
                blocks_release: true,
            },
        },
        // Disk pressure detection
        SloGuardrail {
            id: "SLO-PRESSURE-DETECT".into(),
            description: "Disk pressure state detection latency under 50ms".into(),
            metric: "pressure_detection_latency_ms".into(),
            unit: "ms".into(),
            threshold: 50.0,
            measurement_window_secs: 3600,
            error_budget: 0.01,
            component: "disk_pressure".into(),
            ci_tier: "smoke".into(),
            alert: AlertCriteria {
                consecutive_violations_threshold: 3,
                min_alert_interval_secs: 300,
                blocks_release: false,
            },
        },
        // Schema compatibility check
        SloGuardrail {
            id: "SLO-SCHEMA-COMPAT".into(),
            description: "Schema compatibility check overhead under 1ms".into(),
            metric: "schema_compat_check_ms".into(),
            unit: "ms".into(),
            threshold: 1.0,
            measurement_window_secs: 3600,
            error_budget: 0.01,
            component: "schema".into(),
            ci_tier: "smoke".into(),
            alert: AlertCriteria {
                consecutive_violations_threshold: 5,
                min_alert_interval_secs: 600,
                blocks_release: false,
            },
        },
        // UX doctor response time
        SloGuardrail {
            id: "SLO-DOCTOR-LATENCY".into(),
            description: "Doctor diagnostics response time under 200ms".into(),
            metric: "doctor_response_latency_ms".into(),
            unit: "ms".into(),
            threshold: 200.0,
            measurement_window_secs: 3600,
            error_budget: 0.05,
            component: "doctor".into(),
            ci_tier: "nightly".into(),
            alert: AlertCriteria {
                consecutive_violations_threshold: 3,
                min_alert_interval_secs: 600,
                blocks_release: false,
            },
        },
    ]
}

fn build_slo_config() -> SloConfig {
    let guardrails = build_slo_guardrails();
    let release_blocking = guardrails
        .iter()
        .filter(|g| g.alert.blocks_release)
        .count();

    let mut components: Vec<String> = guardrails.iter().map(|g| g.component.clone()).collect();
    components.sort();
    components.dedup();

    SloConfig {
        schema_version: SLO_GUARDRAILS_SCHEMA_VERSION.into(),
        guardrails: guardrails.clone(),
        summary: SloSummary {
            total_guardrails: guardrails.len(),
            release_blocking,
            components,
        },
    }
}

// ===========================================================================
// Engine: SLO checking
// ===========================================================================

fn check_slo(guardrail: &SloGuardrail, samples: &[MetricSample]) -> SloCheckResult {
    if samples.is_empty() {
        return SloCheckResult {
            slo_id: guardrail.id.clone(),
            passed: true,
            current_value: 0.0,
            threshold: guardrail.threshold,
            error_budget_remaining: guardrail.error_budget,
            violation_count: 0,
            sample_count: 0,
        };
    }

    let violations = samples.iter().filter(|s| s.value > guardrail.threshold).count() as u32;
    let violation_rate = violations as f64 / samples.len() as f64;
    let budget_remaining = guardrail.error_budget - violation_rate;
    let avg_value = samples.iter().map(|s| s.value).sum::<f64>() / samples.len() as f64;

    SloCheckResult {
        slo_id: guardrail.id.clone(),
        passed: budget_remaining >= 0.0,
        current_value: avg_value,
        threshold: guardrail.threshold,
        error_budget_remaining: budget_remaining.max(-1.0),
        violation_count: violations,
        sample_count: samples.len() as u32,
    }
}

fn check_alert_hysteresis(
    guardrail: &SloGuardrail,
    state: &mut AlertState,
    check_result: &SloCheckResult,
    current_timestamp_ms: u64,
) -> bool {
    if !check_result.passed {
        state.consecutive_violations += 1;
    } else {
        state.consecutive_violations = 0;
        state.alert_fired = false;
        return false;
    }

    if state.consecutive_violations < guardrail.alert.consecutive_violations_threshold {
        return false;
    }

    let elapsed_since_last = current_timestamp_ms.saturating_sub(state.last_alert_timestamp_ms);
    let min_interval_ms = guardrail.alert.min_alert_interval_secs * 1000;

    if elapsed_since_last < min_interval_ms && state.alert_fired {
        return false; // debounced
    }

    state.alert_fired = true;
    state.last_alert_timestamp_ms = current_timestamp_ms;
    true
}

fn build_regression_report(
    guardrail: &SloGuardrail,
    baseline: f64,
    current: f64,
) -> Option<RegressionEntry> {
    if current <= baseline {
        return None;
    }
    let regression_pct = ((current - baseline) / baseline) * 100.0;
    Some(RegressionEntry {
        slo_id: guardrail.id.clone(),
        component: guardrail.component.clone(),
        regression_pct,
        baseline_value: baseline,
        current_value: current,
        attribution: format!(
            "{} regressed by {:.1}% (baseline={:.2}{}, current={:.2}{})",
            guardrail.metric, regression_pct, baseline, guardrail.unit, current, guardrail.unit
        ),
    })
}

// ===========================================================================
// Tests: schema stability
// ===========================================================================

#[test]
fn e2e_slo_schema_version() {
    let config = build_slo_config();
    assert_eq!(config.schema_version, SLO_GUARDRAILS_SCHEMA_VERSION);
}

#[test]
fn e2e_slo_serialization_roundtrip() {
    let config = build_slo_config();
    let json = serde_json::to_string_pretty(&config).unwrap();
    let parsed: SloConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.guardrails.len(), config.guardrails.len());
}

// ===========================================================================
// Tests: guardrail definitions
// ===========================================================================

#[test]
fn e2e_slo_guardrails_defined() {
    let config = build_slo_config();
    assert!(
        config.guardrails.len() >= 8,
        "must have at least 8 guardrails covering core reliability dimensions"
    );
}

#[test]
fn e2e_slo_all_guardrails_have_positive_threshold() {
    let config = build_slo_config();
    for g in &config.guardrails {
        assert!(
            g.threshold > 0.0,
            "guardrail '{}' must have positive threshold",
            g.id
        );
    }
}

#[test]
fn e2e_slo_all_guardrails_have_measurement_window() {
    let config = build_slo_config();
    for g in &config.guardrails {
        assert!(
            g.measurement_window_secs > 0,
            "guardrail '{}' must have non-zero measurement window",
            g.id
        );
    }
}

#[test]
fn e2e_slo_error_budgets_in_range() {
    let config = build_slo_config();
    for g in &config.guardrails {
        assert!(
            (0.0..=1.0).contains(&g.error_budget),
            "guardrail '{}' error budget {} must be in [0.0, 1.0]",
            g.id,
            g.error_budget
        );
    }
}

#[test]
fn e2e_slo_all_guardrails_have_valid_ci_tier() {
    let config = build_slo_config();
    let valid_tiers = ["smoke", "nightly", "full"];
    for g in &config.guardrails {
        assert!(
            valid_tiers.contains(&g.ci_tier.as_str()),
            "guardrail '{}' has invalid CI tier '{}'",
            g.id,
            g.ci_tier
        );
    }
}

#[test]
fn e2e_slo_no_duplicate_ids() {
    let config = build_slo_config();
    let mut seen = HashMap::new();
    for g in &config.guardrails {
        if let Some(prev) = seen.insert(&g.id, &g.description) {
            panic!("duplicate SLO ID '{}': '{}' vs '{}'", g.id, prev, g.description);
        }
    }
}

// ===========================================================================
// Tests: required component coverage
// ===========================================================================

#[test]
fn e2e_slo_covers_hook_latency() {
    let config = build_slo_config();
    assert!(
        config.guardrails.iter().any(|g| g.component == "hook"),
        "must have hook latency guardrail"
    );
}

#[test]
fn e2e_slo_covers_convergence_latency() {
    let config = build_slo_config();
    assert!(
        config.guardrails.iter().any(|g| g.component == "convergence"),
        "must have convergence latency guardrail"
    );
}

#[test]
fn e2e_slo_covers_fallback_rate() {
    let config = build_slo_config();
    assert!(
        config.guardrails.iter().any(|g| g.component == "routing"),
        "must have fallback rate guardrail"
    );
}

#[test]
fn e2e_slo_covers_triage_overhead() {
    let config = build_slo_config();
    assert!(
        config
            .guardrails
            .iter()
            .any(|g| g.component == "process_triage"),
        "must have triage overhead guardrail"
    );
}

#[test]
fn e2e_slo_covers_cancellation() {
    let config = build_slo_config();
    assert!(
        config
            .guardrails
            .iter()
            .any(|g| g.component == "cancellation"),
        "must have cancellation cleanup guardrail"
    );
}

// ===========================================================================
// Tests: SLO checking engine
// ===========================================================================

#[test]
fn e2e_slo_check_passes_when_under_threshold() {
    let guardrail = &build_slo_guardrails()[0]; // SLO-HOOK-P50, threshold=1.0ms
    let samples = vec![
        MetricSample { value: 0.5, timestamp_ms: 1000 },
        MetricSample { value: 0.8, timestamp_ms: 2000 },
        MetricSample { value: 0.3, timestamp_ms: 3000 },
    ];
    let result = check_slo(guardrail, &samples);
    assert!(result.passed, "should pass when all samples under threshold");
    assert_eq!(result.violation_count, 0);
}

#[test]
fn e2e_slo_check_fails_when_budget_exhausted() {
    let guardrail = &build_slo_guardrails()[0]; // error_budget=0.01
    // 50% violations far exceeds 1% budget
    let samples = vec![
        MetricSample { value: 2.0, timestamp_ms: 1000 }, // violation
        MetricSample { value: 0.5, timestamp_ms: 2000 },
    ];
    let result = check_slo(guardrail, &samples);
    assert!(!result.passed, "should fail when error budget exhausted");
    assert_eq!(result.violation_count, 1);
}

#[test]
fn e2e_slo_check_passes_within_budget() {
    // SLO-CONV-P50: threshold=100ms, error_budget=0.05 (5%)
    let guardrail = &build_slo_guardrails()[2];
    // 1/100 = 1% violations, within 5% budget
    let mut samples: Vec<MetricSample> = (0..99)
        .map(|i| MetricSample {
            value: 50.0,
            timestamp_ms: i * 1000,
        })
        .collect();
    samples.push(MetricSample {
        value: 150.0,
        timestamp_ms: 99000,
    }); // 1 violation
    let result = check_slo(guardrail, &samples);
    assert!(result.passed, "1% violation rate should be within 5% budget");
    assert_eq!(result.violation_count, 1);
}

#[test]
fn e2e_slo_check_empty_samples_passes() {
    let guardrail = &build_slo_guardrails()[0];
    let result = check_slo(guardrail, &[]);
    assert!(result.passed, "empty samples should pass (no data)");
    assert_eq!(result.sample_count, 0);
}

// ===========================================================================
// Tests: alert hysteresis
// ===========================================================================

#[test]
fn e2e_slo_alert_requires_consecutive_violations() {
    let guardrail = &build_slo_guardrails()[0]; // consecutive_violations_threshold=3
    let mut state = AlertState {
        consecutive_violations: 0,
        last_alert_timestamp_ms: 0,
        alert_fired: false,
    };

    let failing_result = SloCheckResult {
        slo_id: "test".into(),
        passed: false,
        current_value: 2.0,
        threshold: 1.0,
        error_budget_remaining: -0.1,
        violation_count: 5,
        sample_count: 10,
    };

    // First two violations: no alert yet
    assert!(!check_alert_hysteresis(guardrail, &mut state, &failing_result, 1000));
    assert!(!check_alert_hysteresis(guardrail, &mut state, &failing_result, 2000));

    // Third violation: alert fires
    assert!(check_alert_hysteresis(guardrail, &mut state, &failing_result, 3000));
}

#[test]
fn e2e_slo_alert_debounced() {
    let guardrail = &build_slo_guardrails()[0]; // min_alert_interval_secs=300
    let mut state = AlertState {
        consecutive_violations: 3,
        last_alert_timestamp_ms: 1000,
        alert_fired: true,
    };

    let failing_result = SloCheckResult {
        slo_id: "test".into(),
        passed: false,
        current_value: 2.0,
        threshold: 1.0,
        error_budget_remaining: -0.1,
        violation_count: 5,
        sample_count: 10,
    };

    // Too soon after last alert (300s = 300_000ms)
    assert!(!check_alert_hysteresis(guardrail, &mut state, &failing_result, 100_000));

    // After debounce interval
    assert!(check_alert_hysteresis(guardrail, &mut state, &failing_result, 400_000));
}

#[test]
fn e2e_slo_alert_resets_on_pass() {
    let guardrail = &build_slo_guardrails()[0];
    let mut state = AlertState {
        consecutive_violations: 5,
        last_alert_timestamp_ms: 1000,
        alert_fired: true,
    };

    let passing_result = SloCheckResult {
        slo_id: "test".into(),
        passed: true,
        current_value: 0.5,
        threshold: 1.0,
        error_budget_remaining: 0.01,
        violation_count: 0,
        sample_count: 10,
    };

    let fired = check_alert_hysteresis(guardrail, &mut state, &passing_result, 5000);
    assert!(!fired);
    assert_eq!(state.consecutive_violations, 0);
    assert!(!state.alert_fired);
}

// ===========================================================================
// Tests: regression reporting
// ===========================================================================

#[test]
fn e2e_slo_regression_detected() {
    let guardrail = &build_slo_guardrails()[0];
    let report = build_regression_report(guardrail, 0.5, 1.5);
    assert!(report.is_some());
    let entry = report.unwrap();
    assert!((entry.regression_pct - 200.0).abs() < 0.1);
    assert!(entry.attribution.contains("regressed"));
}

#[test]
fn e2e_slo_no_regression_when_improved() {
    let guardrail = &build_slo_guardrails()[0];
    let report = build_regression_report(guardrail, 1.0, 0.5);
    assert!(report.is_none(), "improvement should not generate regression report");
}

#[test]
fn e2e_slo_regression_report_has_attribution() {
    let guardrail = &build_slo_guardrails()[0];
    let report = build_regression_report(guardrail, 0.5, 0.8).unwrap();
    assert!(!report.attribution.is_empty());
    assert!(report.attribution.contains("baseline"));
    assert!(report.attribution.contains("current"));
}

// ===========================================================================
// Tests: release-blocking guardrails
// ===========================================================================

#[test]
fn e2e_slo_has_release_blocking_guardrails() {
    let config = build_slo_config();
    assert!(
        config.summary.release_blocking > 0,
        "must have at least one release-blocking guardrail"
    );
}

#[test]
fn e2e_slo_hook_latency_blocks_release() {
    let config = build_slo_config();
    let hook_p99 = config.guardrails.iter().find(|g| g.id == "SLO-HOOK-P99").unwrap();
    assert!(
        hook_p99.alert.blocks_release,
        "hook P99 latency violation must block release"
    );
}

#[test]
fn e2e_slo_fallback_rate_blocks_release() {
    let config = build_slo_config();
    let fallback = config
        .guardrails
        .iter()
        .find(|g| g.id == "SLO-FALLBACK-RATE")
        .unwrap();
    assert!(
        fallback.alert.blocks_release,
        "elevated fallback rate must block release"
    );
}

// ===========================================================================
// Tests: summary correctness
// ===========================================================================

#[test]
fn e2e_slo_summary_counts_correct() {
    let config = build_slo_config();
    assert_eq!(config.summary.total_guardrails, config.guardrails.len());
    assert_eq!(
        config.summary.release_blocking,
        config
            .guardrails
            .iter()
            .filter(|g| g.alert.blocks_release)
            .count()
    );
}

#[test]
fn e2e_slo_summary_components_complete() {
    let config = build_slo_config();
    let expected_components = [
        "cancellation",
        "convergence",
        "disk_pressure",
        "doctor",
        "hook",
        "process_triage",
        "routing",
        "schema",
    ];
    for comp in &expected_components {
        assert!(
            config.summary.components.contains(&comp.to_string()),
            "summary should include component '{}'",
            comp
        );
    }
}

// ===========================================================================
// Tests: deterministic output
// ===========================================================================

#[test]
fn e2e_slo_output_deterministic() {
    let c1 = build_slo_config();
    let c2 = build_slo_config();
    let json1 = serde_json::to_string(&c1).unwrap();
    let json2 = serde_json::to_string(&c2).unwrap();
    assert_eq!(json1, json2, "SLO config output must be deterministic");
}

// ===========================================================================
// Tests: full guardrail sweep
// ===========================================================================

#[test]
fn e2e_slo_full_guardrail_sweep() {
    let guardrails = build_slo_guardrails();

    // Simulate all guardrails passing with good data
    for g in &guardrails {
        let samples: Vec<MetricSample> = (0..100)
            .map(|i| MetricSample {
                value: g.threshold * 0.5, // well under threshold
                timestamp_ms: i * 1000,
            })
            .collect();
        let result = check_slo(g, &samples);
        assert!(
            result.passed,
            "guardrail '{}' should pass with good data",
            g.id
        );
    }
}

// ===========================================================================
// Tests: logging integration
// ===========================================================================

#[test]
fn e2e_slo_logging_integration() {
    let logger = TestLoggerBuilder::new("slo_guardrails").build();
    let config = build_slo_config();

    logger.log(
        LogLevel::Info,
        LogSource::Custom("slo_guardrails".into()),
        format!(
            "SLO config: {} guardrails, {} release-blocking, {} components",
            config.summary.total_guardrails,
            config.summary.release_blocking,
            config.summary.components.len(),
        ),
    );

    let entries = logger.entries();
    assert_eq!(entries.len(), 1);
    assert!(entries[0].message.contains("guardrails"));
}
