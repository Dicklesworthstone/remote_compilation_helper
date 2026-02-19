//! Unified multi-signal worker reliability model (bd-vvmd.5.5).
//!
//! Aggregates process-triage debt, repo-convergence drift confidence,
//! disk-pressure admission risk, and circuit-breaker health into
//! deterministic health states with quarantine/recovery hysteresis.
//!
//! The aggregator produces a per-worker `ReliabilityAssessment` consumed
//! by `WorkerSelector::compute_balanced_score()` as a scoring penalty
//! (0.0 = no penalty, 1.0 = full penalty / quarantined).
//!
//! # Health States
//!
//! - **Healthy**: all signals nominal — no penalty.
//! - **Degraded**: one or more signals show moderate risk — scoring penalty.
//! - **Quarantined**: severe multi-signal risk — hard exclusion from selection.
//! - **ProbingRecovery**: previously quarantined, now showing improvement —
//!   reduced penalty while recovery is validated.
//!
//! # Quarantine Hysteresis
//!
//! Workers enter quarantine when aggregated debt exceeds `quarantine_threshold`.
//! They exit quarantine only after `recovery_ticks` consecutive evaluations
//! with debt below `recovery_threshold`, preventing flapping.

#![allow(dead_code)] // Integration wiring lands in follow-on beads.

use crate::admission::AdmissionGate;
use crate::cancellation::CancellationOrchestrator;
use crate::disk_pressure::PressureState;
use crate::process_triage::RemediationPipeline;
use crate::repo_convergence::RepoConvergenceService;
use crate::workers::WorkerState;
use rch_common::WorkerId;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::debug;

// ── Constants ──────────────────────────────────────────────────────────────

/// Aggregated debt at or above which a worker enters Quarantined state.
const DEFAULT_QUARANTINE_THRESHOLD: f64 = 0.7;

/// Debt must be at or below this for `recovery_ticks` consecutive evaluations
/// before a quarantined worker transitions to ProbingRecovery.
const DEFAULT_RECOVERY_THRESHOLD: f64 = 0.3;

/// Consecutive low-debt evaluations required to exit quarantine.
const DEFAULT_RECOVERY_TICKS: u32 = 3;

/// Minimum dwell time in quarantine before recovery is allowed.
const DEFAULT_MIN_QUARANTINE_DURATION: Duration = Duration::from_secs(60);

/// Penalty multiplier while in ProbingRecovery (0.0-1.0).
/// Worker receives `probing_penalty * base_score` during recovery probe.
const DEFAULT_PROBING_PENALTY: f64 = 0.5;

/// Penalty floor for Degraded state (minimum penalty applied).
const DEFAULT_DEGRADED_PENALTY_FLOOR: f64 = 0.05;

/// Maximum age of a per-worker assessment before it's considered stale.
const ASSESSMENT_STALENESS: Duration = Duration::from_secs(120);

// ── Signal Weights ─────────────────────────────────────────────────────────

/// Weights for each signal in the aggregated debt computation.
///
/// Normalized such that their sum is 1.0.
#[derive(Debug, Clone)]
pub struct SignalWeights {
    /// Weight for circuit-breaker error rate (heartbeat/liveness).
    pub circuit: f64,
    /// Weight for repo-convergence drift confidence.
    pub convergence: f64,
    /// Weight for disk-pressure admission penalty.
    pub pressure: f64,
    /// Weight for process-triage remediation debt.
    pub process: f64,
    /// Weight for cancellation frequency/escalation debt.
    pub cancellation: f64,
}

impl Default for SignalWeights {
    fn default() -> Self {
        Self {
            circuit: 0.30,
            convergence: 0.22,
            pressure: 0.22,
            process: 0.13,
            cancellation: 0.13,
        }
    }
}

impl SignalWeights {
    /// Normalize weights so they sum to 1.0.
    fn normalized(&self) -> Self {
        let sum = self.circuit + self.convergence + self.pressure + self.process + self.cancellation;
        if sum <= 0.0 {
            return Self::default();
        }
        Self {
            circuit: self.circuit / sum,
            convergence: self.convergence / sum,
            pressure: self.pressure / sum,
            process: self.process / sum,
            cancellation: self.cancellation / sum,
        }
    }
}

// ── Configuration ──────────────────────────────────────────────────────────

/// Configuration for the reliability aggregator.
#[derive(Debug, Clone)]
pub struct ReliabilityConfig {
    /// Signal weights for aggregation.
    pub weights: SignalWeights,
    /// Debt threshold at/above which a worker is quarantined.
    pub quarantine_threshold: f64,
    /// Debt threshold at/below which recovery ticks accumulate.
    pub recovery_threshold: f64,
    /// Consecutive evaluations below recovery_threshold to exit quarantine.
    pub recovery_ticks: u32,
    /// Minimum time in quarantine before recovery is possible.
    pub min_quarantine_duration: Duration,
    /// Penalty multiplier during ProbingRecovery.
    pub probing_penalty: f64,
    /// Minimum penalty for Degraded state.
    pub degraded_penalty_floor: f64,
}

impl Default for ReliabilityConfig {
    fn default() -> Self {
        Self {
            weights: SignalWeights::default(),
            quarantine_threshold: DEFAULT_QUARANTINE_THRESHOLD,
            recovery_threshold: DEFAULT_RECOVERY_THRESHOLD,
            recovery_ticks: DEFAULT_RECOVERY_TICKS,
            min_quarantine_duration: DEFAULT_MIN_QUARANTINE_DURATION,
            probing_penalty: DEFAULT_PROBING_PENALTY,
            degraded_penalty_floor: DEFAULT_DEGRADED_PENALTY_FLOOR,
        }
    }
}

// ── Health State ───────────────────────────────────────────────────────────

/// Deterministic health states for worker reliability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerHealthState {
    /// All signals nominal.
    Healthy,
    /// One or more signals degraded; scoring penalty applied.
    Degraded,
    /// Severe multi-signal risk; hard exclusion from selection.
    Quarantined,
    /// Previously quarantined, now improving; reduced penalty.
    ProbingRecovery,
}

impl std::fmt::Display for WorkerHealthState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Healthy => write!(f, "healthy"),
            Self::Degraded => write!(f, "degraded"),
            Self::Quarantined => write!(f, "quarantined"),
            Self::ProbingRecovery => write!(f, "probing_recovery"),
        }
    }
}

// ── Per-Signal Debt ────────────────────────────────────────────────────────

/// Individual signal debt scores (0.0 = healthy, 1.0 = maximum risk).
#[derive(Debug, Clone, Default, Serialize)]
pub struct SignalDebts {
    /// Circuit-breaker error rate (0.0 = all success, 1.0 = all failure).
    pub circuit_debt: f64,
    /// Repo convergence drift (0.0 = Ready, partial = Drifting, 1.0 = Failed/Stale).
    pub convergence_debt: f64,
    /// Disk pressure admission penalty (0.0 = healthy, 1.0 = critical).
    pub pressure_debt: f64,
    /// Process-triage remediation debt (0.0 = no actions, 1.0 = saturated).
    pub process_debt: f64,
    /// Cancellation frequency/escalation debt (0.0 = none, 1.0 = saturated).
    pub cancellation_debt: f64,
}

// ── Per-Worker Hysteresis ──────────────────────────────────────────────────

/// Tracks per-worker reliability state and quarantine hysteresis.
#[derive(Debug, Clone)]
struct WorkerReliabilityTracker {
    /// Current health state.
    state: WorkerHealthState,
    /// Last aggregated debt score.
    last_debt: f64,
    /// Individual signal debts from the last evaluation.
    last_signals: SignalDebts,
    /// When the worker entered quarantine (for minimum dwell enforcement).
    quarantined_at: Option<Instant>,
    /// Consecutive evaluations with debt below recovery_threshold.
    recovery_tick_count: u32,
    /// When this tracker was last evaluated.
    last_evaluated_at: Option<Instant>,
}

impl Default for WorkerReliabilityTracker {
    fn default() -> Self {
        Self {
            state: WorkerHealthState::Healthy,
            last_debt: 0.0,
            last_signals: SignalDebts::default(),
            quarantined_at: None,
            recovery_tick_count: 0,
            last_evaluated_at: None,
        }
    }
}

// ── Reliability Assessment ─────────────────────────────────────────────────

/// Assessment produced per-worker consumed by the selection pipeline.
#[derive(Debug, Clone, Serialize)]
pub struct ReliabilityAssessment {
    /// Computed health state.
    pub health_state: WorkerHealthState,
    /// Aggregated debt score (0.0-1.0).
    pub aggregated_debt: f64,
    /// Scoring penalty to apply (0.0 = none, 1.0 = full exclusion).
    pub penalty: f64,
    /// Whether this worker should be hard-excluded from selection.
    pub hard_exclude: bool,
    /// Individual signal debts for diagnostics.
    pub signals: SignalDebts,
}

// ── Aggregator ─────────────────────────────────────────────────────────────

/// Aggregates multi-signal reliability debt into health assessments.
///
/// Wired with optional references to the convergence service, admission gate,
/// and remediation pipeline. Missing sources are treated as healthy (fail-open).
pub struct ReliabilityAggregator {
    config: ReliabilityConfig,
    /// Per-worker hysteresis trackers.
    trackers: RwLock<HashMap<String, WorkerReliabilityTracker>>,
    /// Optional repo convergence service.
    convergence: Option<Arc<RepoConvergenceService>>,
    /// Optional admission gate.
    admission: Option<Arc<AdmissionGate>>,
    /// Optional remediation pipeline.
    remediation: Option<Arc<RemediationPipeline>>,
    /// Optional cancellation orchestrator.
    cancellation: Option<Arc<CancellationOrchestrator>>,
}

impl ReliabilityAggregator {
    /// Create a new aggregator with default configuration.
    pub fn new(config: ReliabilityConfig) -> Self {
        Self {
            config,
            trackers: RwLock::new(HashMap::new()),
            convergence: None,
            admission: None,
            remediation: None,
            cancellation: None,
        }
    }

    /// Wire the repo convergence service.
    pub fn set_convergence(&mut self, svc: Arc<RepoConvergenceService>) {
        self.convergence = Some(svc);
    }

    /// Wire the admission gate.
    pub fn set_admission(&mut self, gate: Arc<AdmissionGate>) {
        self.admission = Some(gate);
    }

    /// Wire the remediation pipeline.
    pub fn set_remediation(&mut self, pipeline: Arc<RemediationPipeline>) {
        self.remediation = Some(pipeline);
    }

    /// Wire the cancellation orchestrator.
    pub fn set_cancellation(&mut self, orch: Arc<CancellationOrchestrator>) {
        self.cancellation = Some(orch);
    }

    /// Evaluate a single worker and return its reliability assessment.
    ///
    /// This is the main entry point called by the selection pipeline.
    /// Each signal is queried independently; missing services produce 0.0 debt.
    pub async fn evaluate(
        &self,
        worker: &WorkerState,
        worker_id: &str,
    ) -> ReliabilityAssessment {
        let weights = self.config.weights.normalized();

        // 1. Circuit-breaker debt: error rate from sliding window.
        let circuit_debt = {
            let stats = worker.circuit_stats().await;
            stats.error_rate().clamp(0.0, 1.0)
        };

        // 2. Convergence drift debt.
        let convergence_debt = self.compute_convergence_debt(worker_id).await;

        // 3. Pressure debt from admission gate.
        let pressure_debt = self.compute_pressure_debt(worker).await;

        // 4. Process-triage remediation debt.
        let process_debt = self.compute_process_debt(worker_id).await;

        // 5. Cancellation frequency/escalation debt.
        let cancellation_debt = self.compute_cancellation_debt(worker_id).await;

        let signals = SignalDebts {
            circuit_debt,
            convergence_debt,
            pressure_debt,
            process_debt,
            cancellation_debt,
        };

        // Weighted aggregation.
        let aggregated_debt = (weights.circuit * circuit_debt
            + weights.convergence * convergence_debt
            + weights.pressure * pressure_debt
            + weights.process * process_debt
            + weights.cancellation * cancellation_debt)
            .clamp(0.0, 1.0);

        // State machine transition with hysteresis.
        let (health_state, penalty, hard_exclude) = self
            .transition_state(worker_id, aggregated_debt, &signals)
            .await;

        debug!(
            "Worker {} reliability: state={}, debt={:.3}, penalty={:.3}, exclude={}, \
             circuit={:.2}, convergence={:.2}, pressure={:.2}, process={:.2}, cancel={:.2}",
            worker_id,
            health_state,
            aggregated_debt,
            penalty,
            hard_exclude,
            circuit_debt,
            convergence_debt,
            pressure_debt,
            process_debt,
            cancellation_debt,
        );

        ReliabilityAssessment {
            health_state,
            aggregated_debt,
            penalty,
            hard_exclude,
            signals,
        }
    }

    /// Get the current assessment for a worker without re-evaluating.
    pub async fn get_assessment(&self, worker_id: &str) -> Option<ReliabilityAssessment> {
        let trackers = self.trackers.read().await;
        trackers.get(worker_id).map(|tracker| {
            let (penalty, hard_exclude) = self.penalty_for_state(tracker.state, tracker.last_debt);
            ReliabilityAssessment {
                health_state: tracker.state,
                aggregated_debt: tracker.last_debt,
                penalty,
                hard_exclude,
                signals: tracker.last_signals.clone(),
            }
        })
    }

    /// Get health states for all tracked workers.
    pub async fn all_states(&self) -> HashMap<String, WorkerHealthState> {
        let trackers = self.trackers.read().await;
        trackers
            .iter()
            .map(|(id, t)| (id.clone(), t.state))
            .collect()
    }

    /// Reset tracker for a worker (for manual recovery or testing).
    pub async fn reset(&self, worker_id: &str) {
        self.trackers.write().await.remove(worker_id);
    }

    // ── Signal Computation ────────────────────────────────────────────────

    async fn compute_convergence_debt(&self, worker_id: &str) -> f64 {
        let Some(ref svc) = self.convergence else {
            return 0.0; // Fail-open: no service → no debt.
        };
        let wid = WorkerId::new(worker_id);
        let drift_state = svc.get_drift_state(&wid).await;

        match drift_state {
            crate::repo_convergence::ConvergenceDriftState::Ready => 0.0,
            crate::repo_convergence::ConvergenceDriftState::Drifting => {
                // Use drift confidence if available, otherwise moderate penalty.
                if let Some(ws) = svc.get_worker_state(&wid).await {
                    // drift_confidence = missing/total (0.0-1.0)
                    // Scale to 0.3-0.7 range for Drifting.
                    if ws.required_repos.is_empty() {
                        0.3
                    } else {
                        let missing = ws.missing_repos.len() as f64;
                        let total = ws.required_repos.len() as f64;
                        0.3 + (missing / total).clamp(0.0, 1.0) * 0.4
                    }
                } else {
                    0.4 // Moderate default for Drifting.
                }
            }
            crate::repo_convergence::ConvergenceDriftState::Converging => 0.5,
            crate::repo_convergence::ConvergenceDriftState::Failed => 1.0,
            crate::repo_convergence::ConvergenceDriftState::Stale => 0.2, // Fail-open: mild penalty.
        }
    }

    async fn compute_pressure_debt(&self, worker: &WorkerState) -> f64 {
        let pressure = worker.pressure_assessment().await;
        match pressure.state {
            PressureState::Healthy => 0.0,
            PressureState::TelemetryGap => {
                // Fail-open: un-evaluated workers (reason_code contains
                // "not_evaluated") carry zero debt.  Stale telemetry from
                // an already-evaluated worker carries a small penalty.
                if pressure.reason_code.contains("not_evaluated") {
                    0.0
                } else {
                    0.15
                }
            }
            PressureState::Warning => 0.6,
            PressureState::Critical => 1.0,
        }
    }

    async fn compute_process_debt(&self, worker_id: &str) -> f64 {
        let Some(ref pipeline) = self.remediation else {
            return 0.0; // Fail-open: no pipeline → no debt.
        };
        let Some(state) = pipeline.worker_state(worker_id).await else {
            return 0.0; // No remediation history → clean.
        };

        // Compute debt from remediation intensity:
        // - hard_terminations carry heavy weight
        // - consecutive_failures indicate persistent problems
        // - total_actions indicate ongoing churn
        //
        // Scale: 0-1 where 1.0 means saturated trouble.
        let hard_term_debt = (state.hard_terminations as f64 * 0.3).min(0.6);
        let failure_debt = (state.consecutive_failures as f64 * 0.15).min(0.3);
        let action_churn = (state.total_actions as f64 * 0.02).min(0.2);

        (hard_term_debt + failure_debt + action_churn).clamp(0.0, 1.0)
    }

    async fn compute_cancellation_debt(&self, worker_id: &str) -> f64 {
        let Some(ref orch) = self.cancellation else {
            return 0.0; // Fail-open: no orchestrator → no debt.
        };
        orch.cancellation_debt(worker_id).await
    }

    // ── State Machine ─────────────────────────────────────────────────────

    /// Compute penalty and hard_exclude for a given state and debt.
    fn penalty_for_state(&self, state: WorkerHealthState, debt: f64) -> (f64, bool) {
        match state {
            WorkerHealthState::Healthy => (0.0, false),
            WorkerHealthState::Degraded => {
                // Penalty proportional to debt, with a minimum floor.
                let penalty = debt.max(self.config.degraded_penalty_floor);
                (penalty.clamp(0.0, 0.8), false)
            }
            WorkerHealthState::Quarantined => (1.0, true),
            WorkerHealthState::ProbingRecovery => (self.config.probing_penalty, false),
        }
    }

    /// Transition the per-worker state machine and return (state, penalty, hard_exclude).
    async fn transition_state(
        &self,
        worker_id: &str,
        debt: f64,
        signals: &SignalDebts,
    ) -> (WorkerHealthState, f64, bool) {
        let mut trackers = self.trackers.write().await;
        let tracker = trackers
            .entry(worker_id.to_string())
            .or_default();

        let prev_state = tracker.state;
        let now = Instant::now();

        // Determine the new state based on debt and previous state.
        let new_state = match prev_state {
            WorkerHealthState::Healthy => {
                if debt >= self.config.quarantine_threshold {
                    WorkerHealthState::Quarantined
                } else if debt >= self.config.degraded_penalty_floor {
                    WorkerHealthState::Degraded
                } else {
                    WorkerHealthState::Healthy
                }
            }
            WorkerHealthState::Degraded => {
                if debt >= self.config.quarantine_threshold {
                    WorkerHealthState::Quarantined
                } else if debt < self.config.degraded_penalty_floor {
                    // Debt below the floor is effectively zero → recover.
                    WorkerHealthState::Healthy
                } else {
                    WorkerHealthState::Degraded
                }
            }
            WorkerHealthState::Quarantined => {
                // Check minimum dwell time.
                let min_dwell_elapsed = tracker
                    .quarantined_at
                    .map(|at| now.duration_since(at) >= self.config.min_quarantine_duration)
                    .unwrap_or(false);

                if min_dwell_elapsed && debt <= self.config.recovery_threshold {
                    // Accumulate recovery tick.
                    tracker.recovery_tick_count += 1;
                    if tracker.recovery_tick_count >= self.config.recovery_ticks {
                        WorkerHealthState::ProbingRecovery
                    } else {
                        WorkerHealthState::Quarantined
                    }
                } else {
                    // Reset recovery ticks if debt spikes again.
                    if debt > self.config.recovery_threshold {
                        tracker.recovery_tick_count = 0;
                    }
                    WorkerHealthState::Quarantined
                }
            }
            WorkerHealthState::ProbingRecovery => {
                if debt >= self.config.quarantine_threshold {
                    // Relapse: back to quarantine.
                    WorkerHealthState::Quarantined
                } else if debt <= self.config.recovery_threshold {
                    // Full recovery.
                    WorkerHealthState::Healthy
                } else {
                    // Still probing: moderate debt.
                    WorkerHealthState::ProbingRecovery
                }
            }
        };

        // Bookkeeping for transitions.
        if new_state != prev_state {
            debug!(
                "Worker {} reliability transition: {} → {}",
                worker_id, prev_state, new_state
            );

            if new_state == WorkerHealthState::Quarantined {
                tracker.quarantined_at = Some(now);
                tracker.recovery_tick_count = 0;
            }
            if new_state == WorkerHealthState::Healthy {
                tracker.quarantined_at = None;
                tracker.recovery_tick_count = 0;
            }
        }

        tracker.state = new_state;
        tracker.last_debt = debt;
        tracker.last_signals = signals.clone();
        tracker.last_evaluated_at = Some(now);

        let (penalty, hard_exclude) = self.penalty_for_state(new_state, debt);
        (new_state, penalty, hard_exclude)
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::EventBus;
    use crate::process_triage::RemediationPipelineConfig;
    use crate::workers::WorkerPool;
    use rch_common::WorkerConfig;
    use rch_common::e2e::process_triage::ProcessTriageContract;

    fn test_config() -> ReliabilityConfig {
        ReliabilityConfig {
            min_quarantine_duration: Duration::from_millis(10),
            recovery_ticks: 2,
            ..Default::default()
        }
    }

    fn test_events() -> EventBus {
        EventBus::new(16)
    }

    fn test_pipeline() -> Arc<RemediationPipeline> {
        Arc::new(RemediationPipeline::new(
            ProcessTriageContract::default(),
            test_events(),
            RemediationPipelineConfig::default(),
        ))
    }

    fn test_convergence() -> Arc<RepoConvergenceService> {
        Arc::new(RepoConvergenceService::new(test_events()))
    }

    fn make_worker(id: &str) -> WorkerState {
        WorkerState::new(WorkerConfig {
            id: WorkerId::new(id),
            ..WorkerConfig::default()
        })
    }

    async fn make_pool_with_worker(id: &str) -> (WorkerPool, Arc<WorkerState>) {
        let pool = WorkerPool::new();
        let config = WorkerConfig {
            id: WorkerId::new(id),
            ..WorkerConfig::default()
        };
        pool.add_worker(config).await;
        let worker = pool.get(&WorkerId::new(id)).await.unwrap();
        (pool, worker)
    }

    // ── Basic health state tests ──────────────────────────────────────

    #[tokio::test]
    async fn test_healthy_worker_no_debt() {
        let agg = ReliabilityAggregator::new(test_config());
        let worker = make_worker("w1");

        let assessment = agg.evaluate(&worker, "w1").await;

        assert_eq!(assessment.health_state, WorkerHealthState::Healthy);
        assert_eq!(assessment.penalty, 0.0);
        assert!(!assessment.hard_exclude);
        assert!(assessment.aggregated_debt < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_circuit_debt_causes_degradation() {
        let agg = ReliabilityAggregator::new(test_config());
        let worker = make_worker("w1");

        // Record failures to increase circuit error rate.
        // 5 failures + 1 success → error_rate=5/6≈0.83 → circuit_debt≈0.83
        // Weighted: 0.30 * 0.83 ≈ 0.25 → well above degraded_penalty_floor(0.05).
        for _ in 0..5 {
            worker.record_failure(Some("test error".to_string())).await;
        }
        worker.record_success().await;

        let assessment = agg.evaluate(&worker, "w1").await;

        assert!(assessment.aggregated_debt > 0.05);
        assert!(assessment.penalty > 0.0);
        assert_eq!(assessment.health_state, WorkerHealthState::Degraded);
    }

    #[tokio::test]
    async fn test_convergence_debt_integration() {
        let convergence = test_convergence();
        let mut agg = ReliabilityAggregator::new(test_config());
        agg.set_convergence(convergence.clone());

        let worker = make_worker("w1");
        let wid = WorkerId::new("w1");

        // Set up a Drifting state: some repos synced, some missing.
        convergence
            .update_required_repos(
                &wid,
                vec!["repo_a".into(), "repo_b".into()],
                vec!["repo_a".into()], // Only repo_a synced → repo_b missing.
            )
            .await;

        let assessment = agg.evaluate(&worker, "w1").await;

        assert!(assessment.signals.convergence_debt > 0.0);
        assert!(assessment.aggregated_debt > 0.0);
    }

    #[tokio::test]
    async fn test_process_debt_from_remediation() {
        let pipeline = test_pipeline();
        let mut agg = ReliabilityAggregator::new(test_config());
        agg.set_remediation(pipeline.clone());

        let worker = make_worker("w1");

        // No remediation history → no debt.
        let clean = agg.evaluate(&worker, "w1").await;
        assert!(clean.signals.process_debt < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_quarantine_on_high_circuit_debt() {
        // With circuit-only debt at 100%, weighted = 0.30.
        // Set quarantine threshold at exactly that.
        let config = ReliabilityConfig {
            quarantine_threshold: 0.3,
            min_quarantine_duration: Duration::from_millis(10),
            ..Default::default()
        };
        let agg = ReliabilityAggregator::new(config);
        let worker = make_worker("w1");

        // Drive circuit error rate to 100% → circuit_debt=1.0, weighted=0.30 >= 0.3.
        for _ in 0..10 {
            worker.record_failure(Some("test".to_string())).await;
        }

        let assessment = agg.evaluate(&worker, "w1").await;
        assert_eq!(assessment.health_state, WorkerHealthState::Quarantined);
        assert!(assessment.hard_exclude);
        assert_eq!(assessment.penalty, 1.0);
    }

    #[tokio::test]
    async fn test_quarantine_transition_full_debt() {
        let convergence = test_convergence();
        let mut config = test_config();
        config.quarantine_threshold = 0.5;
        let mut agg = ReliabilityAggregator::new(config);
        agg.set_convergence(convergence.clone());

        let worker = make_worker("w1");
        let wid = WorkerId::new("w1");

        // Circuit: 100% failure → debt 1.0
        for _ in 0..10 {
            worker.record_failure(Some("test".to_string())).await;
        }

        // Convergence: Failed state → debt 1.0
        convergence
            .update_required_repos(
                &wid,
                vec!["repo_a".into()],
                vec![], // All missing.
            )
            .await;
        // Force to Failed via exhausting budgets.
        for _ in 0..3 {
            let _ = convergence
                .record_convergence_attempt(&wid, 0, 1, 0, 50_000, Some("fail".into()))
                .await;
        }

        let assessment = agg.evaluate(&worker, "w1").await;

        // circuit_debt=1.0 * 0.30 + convergence_debt=1.0 * 0.22 = 0.52 → > 0.5
        assert_eq!(assessment.health_state, WorkerHealthState::Quarantined);
        assert!(assessment.hard_exclude);
        assert_eq!(assessment.penalty, 1.0);
    }

    // ── Hysteresis tests ──────────────────────────────────────────────

    #[tokio::test]
    async fn test_quarantine_recovery_hysteresis() {
        let config = ReliabilityConfig {
            quarantine_threshold: 0.15,
            recovery_threshold: 0.05,
            recovery_ticks: 2,
            min_quarantine_duration: Duration::from_millis(10),
            degraded_penalty_floor: 0.05,
            ..Default::default()
        };
        let agg = ReliabilityAggregator::new(config);
        let worker = make_worker("w1");

        // Drive into quarantine: 10 failures → error_rate=1.0 → debt=0.30 > 0.15.
        for _ in 0..10 {
            worker.record_failure(Some("test".to_string())).await;
        }
        let assessment = agg.evaluate(&worker, "w1").await;
        assert_eq!(assessment.health_state, WorkerHealthState::Quarantined);

        // Fix: 500 successes → error_rate=10/510≈0.02 → debt≈0.006 < 0.05.
        for _ in 0..500 {
            worker.record_success().await;
        }

        tokio::time::sleep(Duration::from_millis(20)).await;

        // Recovery tick 1: debt should be low but need 2 ticks.
        let a1 = agg.evaluate(&worker, "w1").await;
        assert_eq!(a1.health_state, WorkerHealthState::Quarantined);

        // Recovery tick 2 → ProbingRecovery.
        let a2 = agg.evaluate(&worker, "w1").await;
        assert_eq!(a2.health_state, WorkerHealthState::ProbingRecovery);
        assert!(!a2.hard_exclude);

        // One more eval with low debt → Healthy.
        let a3 = agg.evaluate(&worker, "w1").await;
        assert_eq!(a3.health_state, WorkerHealthState::Healthy);
        assert_eq!(a3.penalty, 0.0);
    }

    #[tokio::test]
    async fn test_quarantine_min_dwell_enforced() {
        let config = ReliabilityConfig {
            quarantine_threshold: 0.15,
            recovery_threshold: 0.05,
            recovery_ticks: 1,
            min_quarantine_duration: Duration::from_secs(60),
            ..Default::default()
        };
        let agg = ReliabilityAggregator::new(config);
        let worker = make_worker("w1");

        // Drive into quarantine: 10 failures → debt=0.30 > 0.15.
        for _ in 0..10 {
            worker.record_failure(Some("test".to_string())).await;
        }
        let _ = agg.evaluate(&worker, "w1").await;

        // Fix worker: 500 successes → debt≈0.006 < 0.05.
        for _ in 0..500 {
            worker.record_success().await;
        }

        // Evaluate again — should still be quarantined because min_dwell (60s) not elapsed.
        let assessment = agg.evaluate(&worker, "w1").await;
        assert_eq!(assessment.health_state, WorkerHealthState::Quarantined);
    }

    #[tokio::test]
    async fn test_probing_recovery_relapse() {
        let config = ReliabilityConfig {
            quarantine_threshold: 0.15,
            recovery_threshold: 0.05,
            recovery_ticks: 1,
            min_quarantine_duration: Duration::from_millis(10),
            ..Default::default()
        };
        let agg = ReliabilityAggregator::new(config);
        let worker = make_worker("w1");

        // Drive into quarantine: 10 failures, error_rate=1.0, debt=0.30 > 0.15.
        for _ in 0..10 {
            worker.record_failure(Some("test".to_string())).await;
        }
        let _ = agg.evaluate(&worker, "w1").await;

        // Fix: 200 successes → error_rate=10/210≈0.048 → debt=0.014 < 0.05.
        for _ in 0..200 {
            worker.record_success().await;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;

        // One recovery tick → ProbingRecovery.
        let a1 = agg.evaluate(&worker, "w1").await;
        assert_eq!(a1.health_state, WorkerHealthState::ProbingRecovery);

        // Now re-break the worker: 200 failures → error_rate≈210/410≈0.51 → debt=0.179 > 0.15.
        for _ in 0..200 {
            worker.record_failure(Some("relapse".to_string())).await;
        }

        // Should go back to Quarantined.
        let a2 = agg.evaluate(&worker, "w1").await;
        assert_eq!(a2.health_state, WorkerHealthState::Quarantined);
        assert!(a2.hard_exclude);
    }

    // ── Fail-open tests ───────────────────────────────────────────────

    #[tokio::test]
    async fn test_no_services_all_healthy() {
        // No convergence, no admission, no remediation → all debt = 0.
        let agg = ReliabilityAggregator::new(test_config());
        let worker = make_worker("w1");

        let assessment = agg.evaluate(&worker, "w1").await;
        assert_eq!(assessment.health_state, WorkerHealthState::Healthy);
        assert_eq!(assessment.aggregated_debt, 0.0);
        assert_eq!(assessment.penalty, 0.0);
    }

    #[tokio::test]
    async fn test_degraded_penalty_floor() {
        let config = ReliabilityConfig {
            degraded_penalty_floor: 0.05,
            ..test_config()
        };
        let agg = ReliabilityAggregator::new(config);
        let worker = make_worker("w1");

        // Introduce circuit debt: 3 failures + 1 success → error_rate=0.75
        // circuit_debt=0.75, weighted=0.30*0.75=0.225 → Degraded.
        for _ in 0..3 {
            worker.record_failure(Some("test".to_string())).await;
        }
        worker.record_success().await;

        let assessment = agg.evaluate(&worker, "w1").await;
        assert_eq!(assessment.health_state, WorkerHealthState::Degraded);
        // Penalty should be at least the floor.
        assert!(assessment.penalty >= 0.05);
    }

    // ── Multi-signal combination tests ────────────────────────────────

    #[tokio::test]
    async fn test_all_signals_combined() {
        let convergence = test_convergence();
        let pipeline = test_pipeline();
        let mut agg = ReliabilityAggregator::new(test_config());
        agg.set_convergence(convergence.clone());
        agg.set_remediation(pipeline.clone());

        let worker = make_worker("w1");
        let wid = WorkerId::new("w1");

        // Set up convergence: Drifting.
        convergence
            .update_required_repos(
                &wid,
                vec!["a".into(), "b".into()],
                vec!["a".into()],
            )
            .await;

        // Add some circuit failures.
        for _ in 0..3 {
            worker.record_failure(Some("test".to_string())).await;
        }
        worker.record_success().await;

        let assessment = agg.evaluate(&worker, "w1").await;

        // Should have debt from both circuit and convergence signals.
        assert!(assessment.signals.circuit_debt > 0.0);
        assert!(assessment.signals.convergence_debt > 0.0);
        assert!(assessment.aggregated_debt > 0.0);
        assert_eq!(assessment.health_state, WorkerHealthState::Degraded);
    }

    #[tokio::test]
    async fn test_convergence_ready_no_debt() {
        let convergence = test_convergence();
        let mut agg = ReliabilityAggregator::new(test_config());
        agg.set_convergence(convergence.clone());

        let worker = make_worker("w1");
        let wid = WorkerId::new("w1");

        // All repos present and synced.
        convergence
            .update_required_repos(
                &wid,
                vec!["repo_a".into()],
                vec!["repo_a".into()],
            )
            .await;

        let assessment = agg.evaluate(&worker, "w1").await;
        assert!(assessment.signals.convergence_debt < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_convergence_stale_mild_debt() {
        let convergence = test_convergence();
        let mut agg = ReliabilityAggregator::new(test_config());
        agg.set_convergence(convergence.clone());

        let worker = make_worker("w1");
        // Worker not tracked → Stale state.

        let assessment = agg.evaluate(&worker, "w1").await;
        // Stale = 0.2 debt.
        assert!((assessment.signals.convergence_debt - 0.2).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_get_assessment_cached() {
        let agg = ReliabilityAggregator::new(test_config());
        let worker = make_worker("w1");

        // No evaluation yet → no cached assessment.
        assert!(agg.get_assessment("w1").await.is_none());

        // Evaluate.
        let _ = agg.evaluate(&worker, "w1").await;

        // Cached assessment should exist.
        let cached = agg.get_assessment("w1").await;
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().health_state, WorkerHealthState::Healthy);
    }

    #[tokio::test]
    async fn test_all_states_returns_tracked_workers() {
        let agg = ReliabilityAggregator::new(test_config());

        let w1 = make_worker("w1");
        let w2 = make_worker("w2");

        let _ = agg.evaluate(&w1, "w1").await;
        let _ = agg.evaluate(&w2, "w2").await;

        let states = agg.all_states().await;
        assert_eq!(states.len(), 2);
        assert_eq!(states["w1"], WorkerHealthState::Healthy);
        assert_eq!(states["w2"], WorkerHealthState::Healthy);
    }

    #[tokio::test]
    async fn test_reset_clears_tracker() {
        let agg = ReliabilityAggregator::new(test_config());
        let worker = make_worker("w1");

        // Drive into degraded.
        for _ in 0..5 {
            worker.record_failure(Some("test".to_string())).await;
        }
        let _ = agg.evaluate(&worker, "w1").await;
        assert!(agg.get_assessment("w1").await.is_some());

        // Reset.
        agg.reset("w1").await;
        assert!(agg.get_assessment("w1").await.is_none());

        // Re-evaluate after fixing worker → clean state.
        let clean_worker = make_worker("w1");
        let assessment = agg.evaluate(&clean_worker, "w1").await;
        assert_eq!(assessment.health_state, WorkerHealthState::Healthy);
    }

    // ── Signal weight normalization tests ─────────────────────────────

    #[test]
    fn test_signal_weights_normalize() {
        let weights = SignalWeights {
            circuit: 1.0,
            convergence: 1.0,
            pressure: 1.0,
            process: 1.0,
            cancellation: 1.0,
        };
        let normalized = weights.normalized();
        let sum = normalized.circuit
            + normalized.convergence
            + normalized.pressure
            + normalized.process
            + normalized.cancellation;
        assert!((sum - 1.0).abs() < f64::EPSILON);
        assert!((normalized.circuit - 0.2).abs() < f64::EPSILON);
    }

    #[test]
    fn test_signal_weights_zero_fallback() {
        let weights = SignalWeights {
            circuit: 0.0,
            convergence: 0.0,
            pressure: 0.0,
            process: 0.0,
            cancellation: 0.0,
        };
        let normalized = weights.normalized();
        // Should fall back to default.
        assert!(normalized.circuit > 0.0);
    }

    // ── Degraded → Healthy transition ─────────────────────────────────

    #[tokio::test]
    async fn test_degraded_to_healthy_on_low_debt() {
        let agg = ReliabilityAggregator::new(test_config());
        let worker = make_worker("w1");

        // Make degraded: need enough debt to cross degraded_penalty_floor (0.05).
        // 5 failures → error_rate=1.0 → circuit_debt=1.0 → weighted=0.30 > 0.05.
        for _ in 0..5 {
            worker.record_failure(Some("test".to_string())).await;
        }
        let d = agg.evaluate(&worker, "w1").await;
        assert_eq!(d.health_state, WorkerHealthState::Degraded);

        // Fix: overwhelm with successes to drive debt below floor.
        // 500 successes → error_rate=5/505≈0.0099 → circuit_debt≈0.01 → weighted≈0.003
        // 0.003 < degraded_penalty_floor(0.05) → Healthy.
        for _ in 0..500 {
            worker.record_success().await;
        }

        let h = agg.evaluate(&worker, "w1").await;
        assert_eq!(h.health_state, WorkerHealthState::Healthy);
        assert!(h.aggregated_debt < 0.05);
    }

    // ── Pressure debt mapping ─────────────────────────────────────────

    #[tokio::test]
    async fn test_pressure_healthy_no_debt() {
        let agg = ReliabilityAggregator::new(test_config());
        let worker = make_worker("w1");
        // Default pressure is Healthy.
        let debt = agg.compute_pressure_debt(&worker).await;
        assert!(debt < f64::EPSILON);
    }

    // ── Cancellation signal tests ────────────────────────────────────

    #[tokio::test]
    async fn test_cancellation_no_orchestrator_zero_debt() {
        let agg = ReliabilityAggregator::new(test_config());
        let worker = make_worker("w1");

        let assessment = agg.evaluate(&worker, "w1").await;
        assert!(assessment.signals.cancellation_debt < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_cancellation_signal_included_in_aggregation() {
        use crate::cancellation::{CancellationConfig, CancellationOrchestrator};

        let orch = Arc::new(CancellationOrchestrator::new(
            CancellationConfig::default(),
            test_events(),
        ));

        let mut agg = ReliabilityAggregator::new(test_config());
        agg.set_cancellation(orch.clone());

        let worker = make_worker("w1");

        // No cancellation history → debt should be 0.
        let assessment = agg.evaluate(&worker, "w1").await;
        assert!(assessment.signals.cancellation_debt < f64::EPSILON);
        assert_eq!(assessment.health_state, WorkerHealthState::Healthy);
    }

    #[test]
    fn test_signal_weights_five_signals_sum_to_one() {
        let weights = SignalWeights::default();
        let sum = weights.circuit + weights.convergence + weights.pressure
            + weights.process + weights.cancellation;
        assert!(
            (sum - 1.0).abs() < f64::EPSILON,
            "Default weights should sum to 1.0, got {}",
            sum
        );
    }
}
