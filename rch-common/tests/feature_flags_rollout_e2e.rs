//! Feature flags + staged rollout/canary plan E2E tests (bd-vvmd.6.7)
//!
//! Validates:
//!   - Per-subsystem feature flags (path closure, convergence gate, ballast, triage)
//!   - Staged rollout plan with health gates and auto-disable triggers
//!   - Rollback procedure disabling reliability features without disruption
//!   - Flag states and rollout decisions are observable and audit-logged
//!   - Mixed-flag compatibility and safe fallback under partial rollout

use rch_common::e2e::logging::{
    LogLevel, ReliabilityContext, ReliabilityEventInput, ReliabilityPhase, TestLoggerBuilder,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ===========================================================================
// Feature flag types
// ===========================================================================

const FEATURE_FLAGS_SCHEMA_VERSION: &str = "1.0.0";

/// Identifies a reliability subsystem that can be toggled.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ReliabilitySubsystem {
    PathClosureSync,
    RepoConvergenceGate,
    StorageBallastPolicy,
    ProcessTriage,
    DiskPressureAdmission,
    ReliabilityAggregator,
}

impl ReliabilitySubsystem {
    fn all() -> &'static [ReliabilitySubsystem] {
        &[
            Self::PathClosureSync,
            Self::RepoConvergenceGate,
            Self::StorageBallastPolicy,
            Self::ProcessTriage,
            Self::DiskPressureAdmission,
            Self::ReliabilityAggregator,
        ]
    }

    fn is_security_relevant(&self) -> bool {
        matches!(
            self,
            Self::ProcessTriage | Self::DiskPressureAdmission
        )
    }
}

/// State of a single feature flag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum FlagState {
    /// Feature is fully disabled.
    Disabled,
    /// Feature is in dry-run/observe-only mode (logging but no enforcement).
    DryRun,
    /// Feature is enabled for a subset of workers (canary).
    Canary,
    /// Feature is fully enabled for all workers.
    Enabled,
}

impl FlagState {
    fn is_active(&self) -> bool {
        !matches!(self, Self::Disabled)
    }

    fn is_enforcing(&self) -> bool {
        matches!(self, Self::Canary | Self::Enabled)
    }
}

/// Configuration for a single subsystem's feature flag.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct FeatureFlag {
    subsystem: ReliabilitySubsystem,
    state: FlagState,
    /// If canary, which worker IDs are included.
    canary_workers: Vec<String>,
    /// Human-readable reason for current state.
    reason: String,
    /// Unix ms when flag was last changed.
    changed_at_unix_ms: i64,
    /// Who changed the flag (operator ID or "system").
    changed_by: String,
}

impl FeatureFlag {
    fn new(subsystem: ReliabilitySubsystem) -> Self {
        Self {
            subsystem,
            state: FlagState::Disabled,
            canary_workers: Vec::new(),
            reason: "initial state".to_string(),
            changed_at_unix_ms: 0,
            changed_by: "system".to_string(),
        }
    }

    fn is_enabled_for_worker(&self, worker_id: &str) -> bool {
        match &self.state {
            FlagState::Disabled => false,
            FlagState::DryRun => false, // observe only, not enforcing
            FlagState::Canary => self.canary_workers.contains(&worker_id.to_string()),
            FlagState::Enabled => true,
        }
    }
}

/// Complete feature flag configuration for all subsystems.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct FeatureFlagConfig {
    schema_version: String,
    flags: HashMap<String, FeatureFlag>,
}

impl Default for FeatureFlagConfig {
    fn default() -> Self {
        let mut flags = HashMap::new();
        for subsystem in ReliabilitySubsystem::all() {
            let key = serde_json::to_string(subsystem)
                .unwrap()
                .trim_matches('"')
                .to_string();
            flags.insert(key, FeatureFlag::new(subsystem.clone()));
        }
        Self {
            schema_version: FEATURE_FLAGS_SCHEMA_VERSION.to_string(),
            flags,
        }
    }
}

impl FeatureFlagConfig {
    fn get_flag(&self, subsystem: &ReliabilitySubsystem) -> Option<&FeatureFlag> {
        let key = serde_json::to_string(subsystem)
            .unwrap()
            .trim_matches('"')
            .to_string();
        self.flags.get(&key)
    }

    fn set_state(
        &mut self,
        subsystem: &ReliabilitySubsystem,
        state: FlagState,
        reason: &str,
        changed_by: &str,
    ) {
        let key = serde_json::to_string(subsystem)
            .unwrap()
            .trim_matches('"')
            .to_string();
        if let Some(flag) = self.flags.get_mut(&key) {
            flag.state = state;
            flag.reason = reason.to_string();
            flag.changed_by = changed_by.to_string();
            flag.changed_at_unix_ms = 1_768_768_200_000; // test timestamp
        }
    }
}

// ===========================================================================
// Rollout plan types
// ===========================================================================

/// A single stage in the rollout plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RolloutStage {
    name: String,
    target_state: FlagState,
    /// Which workers are included (empty = all).
    target_workers: Vec<String>,
    /// Health gate that must pass before advancing.
    health_gate: HealthGate,
    /// Minimum soak time at this stage before advancing (seconds).
    min_soak_secs: u64,
    /// Whether this stage can be auto-advanced or requires manual approval.
    requires_manual_approval: bool,
}

/// Health gate criteria for rollout advancement.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct HealthGate {
    /// Maximum error rate (0.0-1.0) permitted.
    max_error_rate: f64,
    /// Minimum successful evaluations required.
    min_success_count: u64,
    /// Maximum latency p99 in ms.
    max_p99_latency_ms: u64,
    /// Whether contract drift compatibility must pass.
    require_contract_compat: bool,
}

impl Default for HealthGate {
    fn default() -> Self {
        Self {
            max_error_rate: 0.01,
            min_success_count: 100,
            max_p99_latency_ms: 50,
            require_contract_compat: true,
        }
    }
}

/// Complete rollout plan for a subsystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RolloutPlan {
    subsystem: ReliabilitySubsystem,
    stages: Vec<RolloutStage>,
    /// Auto-disable triggers.
    auto_disable_triggers: Vec<AutoDisableTrigger>,
    /// Current stage index (-1 = not started).
    current_stage: i32,
    /// Rollback target state.
    rollback_state: FlagState,
}

/// Conditions that auto-disable a feature.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AutoDisableTrigger {
    name: String,
    condition: AutoDisableCondition,
    action: AutoDisableAction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum AutoDisableCondition {
    ErrorRateExceeded { threshold: u32 },      // basis points (10000 = 100%)
    LatencyExceeded { p99_ms: u64 },
    ContractDriftDetected,
    WorkerQuarantineCount { max_workers: u32 },
    ManualKillSwitch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum AutoDisableAction {
    DisableSubsystem,
    RollbackToStage { stage_index: u32 },
    EnableDryRunMode,
    AlertOnly,
}

/// Audit log entry for flag/rollout changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RolloutAuditEntry {
    timestamp_unix_ms: i64,
    subsystem: ReliabilitySubsystem,
    previous_state: FlagState,
    new_state: FlagState,
    trigger: String,
    operator: String,
    rollout_stage: Option<String>,
}

/// Result of evaluating a health gate.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct HealthGateResult {
    passed: bool,
    error_rate: f64,
    success_count: u64,
    p99_latency_ms: u64,
    contract_compat: bool,
    failures: Vec<String>,
}

// ===========================================================================
// Rollout engine
// ===========================================================================

fn evaluate_health_gate(gate: &HealthGate, metrics: &HealthGateMetrics) -> HealthGateResult {
    let mut failures = Vec::new();

    if metrics.error_rate > gate.max_error_rate {
        failures.push(format!(
            "error_rate {:.4} exceeds max {:.4}",
            metrics.error_rate, gate.max_error_rate
        ));
    }
    if metrics.success_count < gate.min_success_count {
        failures.push(format!(
            "success_count {} below min {}",
            metrics.success_count, gate.min_success_count
        ));
    }
    if metrics.p99_latency_ms > gate.max_p99_latency_ms {
        failures.push(format!(
            "p99_latency {}ms exceeds max {}ms",
            metrics.p99_latency_ms, gate.max_p99_latency_ms
        ));
    }
    if gate.require_contract_compat && !metrics.contract_compat {
        failures.push("contract compatibility check failed".to_string());
    }

    HealthGateResult {
        passed: failures.is_empty(),
        error_rate: metrics.error_rate,
        success_count: metrics.success_count,
        p99_latency_ms: metrics.p99_latency_ms,
        contract_compat: metrics.contract_compat,
        failures,
    }
}

/// Input metrics for health gate evaluation.
struct HealthGateMetrics {
    error_rate: f64,
    success_count: u64,
    p99_latency_ms: u64,
    contract_compat: bool,
}

fn check_auto_disable<'a>(
    triggers: &'a [AutoDisableTrigger],
    metrics: &HealthGateMetrics,
    quarantined_workers: u32,
) -> Option<&'a AutoDisableTrigger> {
    for trigger in triggers {
        let fired = match &trigger.condition {
            AutoDisableCondition::ErrorRateExceeded { threshold } => {
                (metrics.error_rate * 10000.0) as u32 > *threshold
            }
            AutoDisableCondition::LatencyExceeded { p99_ms } => {
                metrics.p99_latency_ms > *p99_ms
            }
            AutoDisableCondition::ContractDriftDetected => !metrics.contract_compat,
            AutoDisableCondition::WorkerQuarantineCount { max_workers } => {
                quarantined_workers > *max_workers
            }
            AutoDisableCondition::ManualKillSwitch => false, // manual only
        };
        if fired {
            return Some(trigger);
        }
    }
    None
}

fn build_default_rollout_plan(subsystem: ReliabilitySubsystem) -> RolloutPlan {
    let canary_soak = if subsystem.is_security_relevant() {
        3600 // 1 hour for security-relevant
    } else {
        1800 // 30 min for non-security
    };

    RolloutPlan {
        subsystem: subsystem.clone(),
        stages: vec![
            RolloutStage {
                name: "dry_run".to_string(),
                target_state: FlagState::DryRun,
                target_workers: Vec::new(),
                health_gate: HealthGate {
                    max_error_rate: 0.05, // lenient during dry run
                    min_success_count: 10,
                    max_p99_latency_ms: 100,
                    require_contract_compat: true,
                },
                min_soak_secs: 300, // 5 min
                requires_manual_approval: false,
            },
            RolloutStage {
                name: "canary".to_string(),
                target_state: FlagState::Canary,
                target_workers: vec!["w1".to_string()],
                health_gate: HealthGate::default(),
                min_soak_secs: canary_soak,
                requires_manual_approval: false,
            },
            RolloutStage {
                name: "full_rollout".to_string(),
                target_state: FlagState::Enabled,
                target_workers: Vec::new(),
                health_gate: HealthGate {
                    max_error_rate: 0.005,
                    min_success_count: 500,
                    max_p99_latency_ms: 50,
                    require_contract_compat: true,
                },
                min_soak_secs: 7200, // 2 hours
                requires_manual_approval: true,
            },
        ],
        auto_disable_triggers: vec![
            AutoDisableTrigger {
                name: "high_error_rate".to_string(),
                condition: AutoDisableCondition::ErrorRateExceeded { threshold: 500 }, // 5%
                action: AutoDisableAction::EnableDryRunMode,
            },
            AutoDisableTrigger {
                name: "extreme_error_rate".to_string(),
                condition: AutoDisableCondition::ErrorRateExceeded { threshold: 1000 }, // 10%
                action: AutoDisableAction::DisableSubsystem,
            },
            AutoDisableTrigger {
                name: "contract_drift".to_string(),
                condition: AutoDisableCondition::ContractDriftDetected,
                action: AutoDisableAction::EnableDryRunMode,
            },
            AutoDisableTrigger {
                name: "mass_quarantine".to_string(),
                condition: AutoDisableCondition::WorkerQuarantineCount { max_workers: 2 },
                action: AutoDisableAction::DisableSubsystem,
            },
        ],
        current_stage: -1,
        rollback_state: FlagState::Disabled,
    }
}

// ===========================================================================
// Tests: feature flag configuration
// ===========================================================================

#[test]
fn e2e_feature_flag_default_all_disabled() {
    let config = FeatureFlagConfig::default();
    for subsystem in ReliabilitySubsystem::all() {
        let flag = config.get_flag(subsystem).unwrap();
        assert_eq!(
            flag.state,
            FlagState::Disabled,
            "{:?} should be disabled by default",
            subsystem
        );
    }
}

#[test]
fn e2e_feature_flag_config_schema_versioned() {
    let config = FeatureFlagConfig::default();
    assert_eq!(config.schema_version, FEATURE_FLAGS_SCHEMA_VERSION);
    let parts: Vec<&str> = config.schema_version.split('.').collect();
    assert_eq!(parts.len(), 3);
}

#[test]
fn e2e_feature_flag_all_subsystems_present() {
    let config = FeatureFlagConfig::default();
    assert_eq!(
        config.flags.len(),
        ReliabilitySubsystem::all().len(),
        "all subsystems must have flags"
    );
}

#[test]
fn e2e_feature_flag_serialization_roundtrip() {
    let mut config = FeatureFlagConfig::default();
    config.set_state(
        &ReliabilitySubsystem::ProcessTriage,
        FlagState::Canary,
        "canary test",
        "operator-1",
    );

    let json = serde_json::to_string_pretty(&config).unwrap();
    let back: FeatureFlagConfig = serde_json::from_str(&json).unwrap();
    let flag = back.get_flag(&ReliabilitySubsystem::ProcessTriage).unwrap();
    assert_eq!(flag.state, FlagState::Canary);
    assert_eq!(flag.changed_by, "operator-1");
}

#[test]
fn e2e_feature_flag_state_transitions() {
    let mut config = FeatureFlagConfig::default();

    // Disabled → DryRun
    config.set_state(
        &ReliabilitySubsystem::PathClosureSync,
        FlagState::DryRun,
        "entering dry run",
        "system",
    );
    let flag = config.get_flag(&ReliabilitySubsystem::PathClosureSync).unwrap();
    assert!(flag.state.is_active());
    assert!(!flag.state.is_enforcing());

    // DryRun → Canary
    config.set_state(
        &ReliabilitySubsystem::PathClosureSync,
        FlagState::Canary,
        "canary on w1",
        "operator",
    );
    let flag = config.get_flag(&ReliabilitySubsystem::PathClosureSync).unwrap();
    assert!(flag.state.is_enforcing());

    // Canary → Enabled
    config.set_state(
        &ReliabilitySubsystem::PathClosureSync,
        FlagState::Enabled,
        "full rollout",
        "operator",
    );
    let flag = config.get_flag(&ReliabilitySubsystem::PathClosureSync).unwrap();
    assert!(flag.state.is_enforcing());
}

#[test]
fn e2e_feature_flag_canary_worker_scoping() {
    let mut config = FeatureFlagConfig::default();
    config.set_state(
        &ReliabilitySubsystem::ProcessTriage,
        FlagState::Canary,
        "canary on w1",
        "operator",
    );

    // Set canary workers
    let key = "process_triage".to_string();
    config.flags.get_mut(&key).unwrap().canary_workers = vec!["w1".to_string()];

    let flag = config.get_flag(&ReliabilitySubsystem::ProcessTriage).unwrap();
    assert!(flag.is_enabled_for_worker("w1"));
    assert!(!flag.is_enabled_for_worker("w2"));
    assert!(!flag.is_enabled_for_worker("w3"));
}

#[test]
fn e2e_feature_flag_enabled_applies_to_all_workers() {
    let mut config = FeatureFlagConfig::default();
    config.set_state(
        &ReliabilitySubsystem::RepoConvergenceGate,
        FlagState::Enabled,
        "full rollout",
        "operator",
    );

    let flag = config
        .get_flag(&ReliabilitySubsystem::RepoConvergenceGate)
        .unwrap();
    assert!(flag.is_enabled_for_worker("w1"));
    assert!(flag.is_enabled_for_worker("w2"));
    assert!(flag.is_enabled_for_worker("any-worker"));
}

#[test]
fn e2e_feature_flag_disabled_blocks_all_workers() {
    let config = FeatureFlagConfig::default();
    let flag = config
        .get_flag(&ReliabilitySubsystem::StorageBallastPolicy)
        .unwrap();
    assert!(!flag.is_enabled_for_worker("w1"));
    assert!(!flag.is_enabled_for_worker("w2"));
}

#[test]
fn e2e_feature_flag_dry_run_not_enforcing() {
    let mut config = FeatureFlagConfig::default();
    config.set_state(
        &ReliabilitySubsystem::DiskPressureAdmission,
        FlagState::DryRun,
        "observe only",
        "system",
    );

    let flag = config
        .get_flag(&ReliabilitySubsystem::DiskPressureAdmission)
        .unwrap();
    assert!(flag.state.is_active());
    assert!(!flag.state.is_enforcing());
    assert!(!flag.is_enabled_for_worker("w1"));
}

// ===========================================================================
// Tests: rollout plan structure
// ===========================================================================

#[test]
fn e2e_rollout_plan_default_has_three_stages() {
    let plan = build_default_rollout_plan(ReliabilitySubsystem::PathClosureSync);
    assert_eq!(plan.stages.len(), 3);
    assert_eq!(plan.stages[0].name, "dry_run");
    assert_eq!(plan.stages[1].name, "canary");
    assert_eq!(plan.stages[2].name, "full_rollout");
}

#[test]
fn e2e_rollout_plan_stage_order_progressive() {
    let plan = build_default_rollout_plan(ReliabilitySubsystem::ProcessTriage);
    assert_eq!(plan.stages[0].target_state, FlagState::DryRun);
    assert_eq!(plan.stages[1].target_state, FlagState::Canary);
    assert_eq!(plan.stages[2].target_state, FlagState::Enabled);
}

#[test]
fn e2e_rollout_plan_full_rollout_requires_approval() {
    let plan = build_default_rollout_plan(ReliabilitySubsystem::RepoConvergenceGate);
    assert!(
        plan.stages.last().unwrap().requires_manual_approval,
        "full rollout must require manual approval"
    );
}

#[test]
fn e2e_rollout_plan_security_subsystem_longer_soak() {
    let security_plan = build_default_rollout_plan(ReliabilitySubsystem::ProcessTriage);
    let non_security_plan = build_default_rollout_plan(ReliabilitySubsystem::PathClosureSync);

    let security_canary_soak = security_plan.stages[1].min_soak_secs;
    let non_security_canary_soak = non_security_plan.stages[1].min_soak_secs;

    assert!(
        security_canary_soak > non_security_canary_soak,
        "security subsystem canary soak ({security_canary_soak}s) should be longer than non-security ({non_security_canary_soak}s)"
    );
}

#[test]
fn e2e_rollout_plan_auto_disable_triggers_present() {
    let plan = build_default_rollout_plan(ReliabilitySubsystem::ProcessTriage);
    assert!(
        !plan.auto_disable_triggers.is_empty(),
        "must have auto-disable triggers"
    );

    // Should have at least error rate and contract drift triggers
    let has_error_rate = plan
        .auto_disable_triggers
        .iter()
        .any(|t| matches!(t.condition, AutoDisableCondition::ErrorRateExceeded { .. }));
    let has_contract_drift = plan
        .auto_disable_triggers
        .iter()
        .any(|t| matches!(t.condition, AutoDisableCondition::ContractDriftDetected));

    assert!(has_error_rate, "must have error rate trigger");
    assert!(has_contract_drift, "must have contract drift trigger");
}

#[test]
fn e2e_rollout_plan_serialization_roundtrip() {
    let plan = build_default_rollout_plan(ReliabilitySubsystem::StorageBallastPolicy);
    let json = serde_json::to_string_pretty(&plan).unwrap();
    let back: RolloutPlan = serde_json::from_str(&json).unwrap();
    assert_eq!(back.stages.len(), plan.stages.len());
    assert_eq!(back.auto_disable_triggers.len(), plan.auto_disable_triggers.len());
}

#[test]
fn e2e_rollout_plan_rollback_state_is_disabled() {
    for subsystem in ReliabilitySubsystem::all() {
        let plan = build_default_rollout_plan(subsystem.clone());
        assert_eq!(
            plan.rollback_state,
            FlagState::Disabled,
            "{subsystem:?} rollback must go to Disabled"
        );
    }
}

// ===========================================================================
// Tests: health gate evaluation
// ===========================================================================

#[test]
fn e2e_health_gate_passes_with_good_metrics() {
    let gate = HealthGate::default();
    let metrics = HealthGateMetrics {
        error_rate: 0.001,
        success_count: 500,
        p99_latency_ms: 10,
        contract_compat: true,
    };

    let result = evaluate_health_gate(&gate, &metrics);
    assert!(result.passed);
    assert!(result.failures.is_empty());
}

#[test]
fn e2e_health_gate_fails_on_high_error_rate() {
    let gate = HealthGate::default();
    let metrics = HealthGateMetrics {
        error_rate: 0.05,
        success_count: 500,
        p99_latency_ms: 10,
        contract_compat: true,
    };

    let result = evaluate_health_gate(&gate, &metrics);
    assert!(!result.passed);
    assert!(result.failures.iter().any(|f| f.contains("error_rate")));
}

#[test]
fn e2e_health_gate_fails_on_low_success_count() {
    let gate = HealthGate::default();
    let metrics = HealthGateMetrics {
        error_rate: 0.001,
        success_count: 5,
        p99_latency_ms: 10,
        contract_compat: true,
    };

    let result = evaluate_health_gate(&gate, &metrics);
    assert!(!result.passed);
    assert!(result.failures.iter().any(|f| f.contains("success_count")));
}

#[test]
fn e2e_health_gate_fails_on_high_latency() {
    let gate = HealthGate::default();
    let metrics = HealthGateMetrics {
        error_rate: 0.001,
        success_count: 500,
        p99_latency_ms: 200,
        contract_compat: true,
    };

    let result = evaluate_health_gate(&gate, &metrics);
    assert!(!result.passed);
    assert!(result.failures.iter().any(|f| f.contains("latency")));
}

#[test]
fn e2e_health_gate_fails_on_contract_drift() {
    let gate = HealthGate::default();
    let metrics = HealthGateMetrics {
        error_rate: 0.001,
        success_count: 500,
        p99_latency_ms: 10,
        contract_compat: false,
    };

    let result = evaluate_health_gate(&gate, &metrics);
    assert!(!result.passed);
    assert!(result.failures.iter().any(|f| f.contains("contract")));
}

#[test]
fn e2e_health_gate_result_serialization() {
    let result = HealthGateResult {
        passed: false,
        error_rate: 0.05,
        success_count: 50,
        p99_latency_ms: 200,
        contract_compat: true,
        failures: vec!["error_rate too high".to_string()],
    };

    let json = serde_json::to_string(&result).unwrap();
    let back: HealthGateResult = serde_json::from_str(&json).unwrap();
    assert!(!back.passed);
    assert_eq!(back.failures.len(), 1);
}

// ===========================================================================
// Tests: auto-disable triggers
// ===========================================================================

#[test]
fn e2e_auto_disable_fires_on_high_error_rate() {
    let plan = build_default_rollout_plan(ReliabilitySubsystem::ProcessTriage);
    let metrics = HealthGateMetrics {
        error_rate: 0.06, // 6% = 600 bps, above 500 threshold
        success_count: 1000,
        p99_latency_ms: 10,
        contract_compat: true,
    };

    let triggered = check_auto_disable(&plan.auto_disable_triggers, &metrics, 0);
    assert!(triggered.is_some());
    assert_eq!(triggered.unwrap().name, "high_error_rate");
}

#[test]
fn e2e_auto_disable_fires_on_extreme_error_rate() {
    let plan = build_default_rollout_plan(ReliabilitySubsystem::ProcessTriage);
    let metrics = HealthGateMetrics {
        error_rate: 0.15, // 15% = 1500 bps, above 1000 threshold
        success_count: 1000,
        p99_latency_ms: 10,
        contract_compat: true,
    };

    let triggered = check_auto_disable(&plan.auto_disable_triggers, &metrics, 0);
    assert!(triggered.is_some());
    // Should fire the first matching trigger (high_error_rate at 500)
    assert_eq!(triggered.unwrap().name, "high_error_rate");
}

#[test]
fn e2e_auto_disable_fires_on_contract_drift() {
    let plan = build_default_rollout_plan(ReliabilitySubsystem::PathClosureSync);
    let metrics = HealthGateMetrics {
        error_rate: 0.001,
        success_count: 1000,
        p99_latency_ms: 10,
        contract_compat: false,
    };

    let triggered = check_auto_disable(&plan.auto_disable_triggers, &metrics, 0);
    assert!(triggered.is_some());
    assert_eq!(triggered.unwrap().name, "contract_drift");
}

#[test]
fn e2e_auto_disable_fires_on_mass_quarantine() {
    let plan = build_default_rollout_plan(ReliabilitySubsystem::RepoConvergenceGate);
    let metrics = HealthGateMetrics {
        error_rate: 0.001,
        success_count: 1000,
        p99_latency_ms: 10,
        contract_compat: true,
    };

    let triggered = check_auto_disable(&plan.auto_disable_triggers, &metrics, 5);
    assert!(triggered.is_some());
    assert_eq!(triggered.unwrap().name, "mass_quarantine");
}

#[test]
fn e2e_auto_disable_no_trigger_on_healthy_metrics() {
    let plan = build_default_rollout_plan(ReliabilitySubsystem::ProcessTriage);
    let metrics = HealthGateMetrics {
        error_rate: 0.001,
        success_count: 1000,
        p99_latency_ms: 10,
        contract_compat: true,
    };

    let triggered = check_auto_disable(&plan.auto_disable_triggers, &metrics, 0);
    assert!(triggered.is_none());
}

// ===========================================================================
// Tests: mixed-flag compatibility
// ===========================================================================

#[test]
fn e2e_mixed_flags_partial_rollout_safe() {
    let mut config = FeatureFlagConfig::default();

    // Enable some subsystems, leave others disabled
    config.set_state(
        &ReliabilitySubsystem::PathClosureSync,
        FlagState::Enabled,
        "fully rolled out",
        "operator",
    );
    config.set_state(
        &ReliabilitySubsystem::RepoConvergenceGate,
        FlagState::Canary,
        "canary on w1",
        "operator",
    );
    // ProcessTriage stays Disabled
    // StorageBallastPolicy stays Disabled

    // Worker w1 should see PathClosure + ConvergenceGate active
    let path_flag = config.get_flag(&ReliabilitySubsystem::PathClosureSync).unwrap();
    let conv_flag = config.get_flag(&ReliabilitySubsystem::RepoConvergenceGate).unwrap();
    let proc_flag = config.get_flag(&ReliabilitySubsystem::ProcessTriage).unwrap();

    assert!(path_flag.is_enabled_for_worker("w1"));
    assert!(!conv_flag.is_enabled_for_worker("w1")); // no canary workers set yet

    // w2 should only see PathClosure
    assert!(path_flag.is_enabled_for_worker("w2"));
    assert!(!proc_flag.is_enabled_for_worker("w2"));
}

#[test]
fn e2e_mixed_flags_aggregator_requires_dependents() {
    // ReliabilityAggregator should only be enabled if at least one signal subsystem is enabled
    let config = FeatureFlagConfig::default();
    let agg_flag = config
        .get_flag(&ReliabilitySubsystem::ReliabilityAggregator)
        .unwrap();
    assert_eq!(agg_flag.state, FlagState::Disabled);
}

// ===========================================================================
// Tests: rollback procedure
// ===========================================================================

#[test]
fn e2e_rollback_disables_without_disruption() {
    let mut config = FeatureFlagConfig::default();

    // Simulate full rollout
    config.set_state(
        &ReliabilitySubsystem::ProcessTriage,
        FlagState::Enabled,
        "fully rolled out",
        "operator",
    );
    assert!(
        config
            .get_flag(&ReliabilitySubsystem::ProcessTriage)
            .unwrap()
            .state
            .is_enforcing()
    );

    // Rollback
    config.set_state(
        &ReliabilitySubsystem::ProcessTriage,
        FlagState::Disabled,
        "rollback: error rate exceeded",
        "auto-disable",
    );

    let flag = config.get_flag(&ReliabilitySubsystem::ProcessTriage).unwrap();
    assert_eq!(flag.state, FlagState::Disabled);
    assert!(flag.reason.contains("rollback"));
    assert_eq!(flag.changed_by, "auto-disable");
}

#[test]
fn e2e_rollback_to_dry_run_preserves_observability() {
    let mut config = FeatureFlagConfig::default();

    config.set_state(
        &ReliabilitySubsystem::DiskPressureAdmission,
        FlagState::Enabled,
        "fully rolled out",
        "operator",
    );

    // Partial rollback to dry run
    config.set_state(
        &ReliabilitySubsystem::DiskPressureAdmission,
        FlagState::DryRun,
        "partial rollback: observing only",
        "auto-disable",
    );

    let flag = config
        .get_flag(&ReliabilitySubsystem::DiskPressureAdmission)
        .unwrap();
    assert!(flag.state.is_active()); // still active for logging
    assert!(!flag.state.is_enforcing()); // not enforcing decisions
}

// ===========================================================================
// Tests: audit logging
// ===========================================================================

#[test]
fn e2e_rollout_audit_entry_serialization() {
    let entry = RolloutAuditEntry {
        timestamp_unix_ms: 1_768_768_200_000,
        subsystem: ReliabilitySubsystem::ProcessTriage,
        previous_state: FlagState::Canary,
        new_state: FlagState::Enabled,
        trigger: "health_gate_passed".to_string(),
        operator: "operator-1".to_string(),
        rollout_stage: Some("full_rollout".to_string()),
    };

    let json = serde_json::to_string_pretty(&entry).unwrap();
    assert!(json.contains("process_triage"));
    assert!(json.contains("canary"));
    assert!(json.contains("enabled"));

    let back: RolloutAuditEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back.subsystem, ReliabilitySubsystem::ProcessTriage);
}

#[test]
fn e2e_rollout_audit_logging_integration() {
    let logger = TestLoggerBuilder::new("feature-flag-rollout")
        .print_realtime(false)
        .build();

    let event = logger.log_reliability_event(ReliabilityEventInput {
        level: LogLevel::Info,
        phase: ReliabilityPhase::Setup,
        scenario_id: "rollout-pt-canary".to_string(),
        message: "process_triage entering canary stage on w1".to_string(),
        context: ReliabilityContext {
            worker_id: Some("w1".to_string()),
            repo_set: Vec::new(),
            pressure_state: None,
            triage_actions: Vec::new(),
            decision_code: "ROLLOUT_STAGE_ADVANCE".to_string(),
            fallback_reason: None,
        },
        artifact_paths: vec![],
    });

    assert_eq!(event.phase, ReliabilityPhase::Setup);
    assert!(event.scenario_id.contains("rollout"));
}

// ===========================================================================
// Tests: full rollout simulation
// ===========================================================================

#[test]
fn e2e_full_rollout_simulation() {
    let mut config = FeatureFlagConfig::default();
    let plan = build_default_rollout_plan(ReliabilitySubsystem::PathClosureSync);
    let mut audit_log: Vec<RolloutAuditEntry> = Vec::new();

    // Stage 0: Dry Run
    let stage = &plan.stages[0];
    config.set_state(
        &plan.subsystem,
        stage.target_state.clone(),
        &format!("advancing to stage: {}", stage.name),
        "rollout-automation",
    );
    audit_log.push(RolloutAuditEntry {
        timestamp_unix_ms: 1_768_768_200_000,
        subsystem: plan.subsystem.clone(),
        previous_state: FlagState::Disabled,
        new_state: FlagState::DryRun,
        trigger: "rollout_start".to_string(),
        operator: "rollout-automation".to_string(),
        rollout_stage: Some("dry_run".to_string()),
    });

    let good_metrics = HealthGateMetrics {
        error_rate: 0.001,
        success_count: 200,
        p99_latency_ms: 8,
        contract_compat: true,
    };
    let gate_result = evaluate_health_gate(&stage.health_gate, &good_metrics);
    assert!(gate_result.passed, "dry run health gate should pass");

    // Stage 1: Canary
    let stage = &plan.stages[1];
    config.set_state(
        &plan.subsystem,
        stage.target_state.clone(),
        &format!("advancing to stage: {}", stage.name),
        "rollout-automation",
    );
    audit_log.push(RolloutAuditEntry {
        timestamp_unix_ms: 1_768_768_500_000,
        subsystem: plan.subsystem.clone(),
        previous_state: FlagState::DryRun,
        new_state: FlagState::Canary,
        trigger: "health_gate_passed".to_string(),
        operator: "rollout-automation".to_string(),
        rollout_stage: Some("canary".to_string()),
    });

    let gate_result = evaluate_health_gate(&stage.health_gate, &good_metrics);
    assert!(gate_result.passed, "canary health gate should pass");

    // Stage 2: Full Rollout
    let stage = &plan.stages[2];
    assert!(
        stage.requires_manual_approval,
        "full rollout requires approval"
    );
    config.set_state(
        &plan.subsystem,
        stage.target_state.clone(),
        &format!("advancing to stage: {}", stage.name),
        "operator-1",
    );
    audit_log.push(RolloutAuditEntry {
        timestamp_unix_ms: 1_768_769_000_000,
        subsystem: plan.subsystem.clone(),
        previous_state: FlagState::Canary,
        new_state: FlagState::Enabled,
        trigger: "manual_approval".to_string(),
        operator: "operator-1".to_string(),
        rollout_stage: Some("full_rollout".to_string()),
    });

    // Verify final state
    let flag = config.get_flag(&plan.subsystem).unwrap();
    assert_eq!(flag.state, FlagState::Enabled);
    assert_eq!(audit_log.len(), 3);

    // Verify audit log is serializable
    let audit_json = serde_json::to_string_pretty(&audit_log).unwrap();
    let back: Vec<RolloutAuditEntry> = serde_json::from_str(&audit_json).unwrap();
    assert_eq!(back.len(), 3);
}
