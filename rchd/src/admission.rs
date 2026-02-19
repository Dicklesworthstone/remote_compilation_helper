//! Scheduler admission gate for disk-pressure risk.
//!
//! Evaluates workers before selection using pressure state, headroom
//! estimates, and hysteresis to produce admission verdicts.  Critical
//! pressure is always a hard reject.  Warning pressure or insufficient
//! headroom result in scoring penalties or soft rejections.  Hysteresis
//! prevents rapid oscillation when disk free space hovers near a threshold.
//!
//! # Fail-open guarantee
//!
//! The admission gate never blocks *all* workers silently.  Callers
//! (the selection pipeline) track soft-rejected workers in a fallback
//! list and can still choose them when no admitted worker remains.

#![allow(dead_code)] // Consumers in follow-on beads.

use crate::disk_pressure::PressureState;
use crate::headroom::HeadroomEstimator;
use crate::workers::WorkerState;
use rch_common::WorkerId;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::debug;

// =========================================================================
// Configuration
// =========================================================================

/// Configuration for the admission gate.
#[derive(Debug, Clone)]
pub struct AdmissionConfig {
    /// Minimum headroom score (0.0-1.0) required for admission.
    /// Workers scoring below this are rejected.
    pub min_headroom_score: f64,
    /// Pressure penalty applied when worker is in Warning state (0.0-1.0).
    pub warning_pressure_penalty: f64,
    /// Pressure penalty applied when telemetry is stale (0.0-1.0).
    /// Fail-open: small penalty rather than rejection.
    pub telemetry_gap_penalty: f64,
    /// Number of consecutive healthy evaluations required to re-admit
    /// a previously rejected worker (hysteresis recovery).
    pub hysteresis_recover_count: u32,
    /// Minimum cooldown duration before a rejected worker is re-evaluated
    /// for recovery.
    pub hysteresis_cooldown: Duration,
}

impl Default for AdmissionConfig {
    fn default() -> Self {
        Self {
            min_headroom_score: 0.2,
            warning_pressure_penalty: 0.4,
            telemetry_gap_penalty: 0.15,
            hysteresis_recover_count: 3,
            hysteresis_cooldown: Duration::from_secs(30),
        }
    }
}

// =========================================================================
// Verdict
// =========================================================================

/// Outcome of an admission evaluation for a single worker.
#[derive(Debug, Clone, Serialize)]
pub enum AdmissionVerdict {
    /// Worker admitted for selection with optional scoring penalties.
    Admit {
        /// Pressure-based scoring penalty (0.0 = none, up to 1.0).
        pressure_penalty: f64,
        /// Headroom score from the estimator (0.0-1.0).
        headroom_score: f64,
    },
    /// Worker rejected from selection with explicit reason.
    Reject {
        /// Machine-readable reason code.
        reason_code: String,
        /// Human-readable rejection reason.
        reason: String,
    },
}

impl AdmissionVerdict {
    /// Whether this verdict admits the worker.
    pub fn is_admitted(&self) -> bool {
        matches!(self, AdmissionVerdict::Admit { .. })
    }

    /// Pressure penalty for scoring (0.0 for admitted, 1.0 for rejected).
    pub fn pressure_penalty(&self) -> f64 {
        match self {
            AdmissionVerdict::Admit {
                pressure_penalty, ..
            } => *pressure_penalty,
            AdmissionVerdict::Reject { .. } => 1.0,
        }
    }
}

// =========================================================================
// Hysteresis State
// =========================================================================

/// Per-worker hysteresis state tracking admission history.
#[derive(Debug, Clone)]
struct WorkerHysteresis {
    /// Whether the worker was last admitted (`true`) or rejected (`false`).
    last_admitted: bool,
    /// Timestamp of the most recent rejection.
    last_rejected_at: Option<Instant>,
    /// Count of consecutive evaluations where the raw decision was "admit"
    /// since the last rejection.
    consecutive_healthy: u32,
}

impl Default for WorkerHysteresis {
    fn default() -> Self {
        Self {
            last_admitted: true, // fail-open: assume admitted
            last_rejected_at: None,
            consecutive_healthy: 0,
        }
    }
}

// =========================================================================
// Admission Gate
// =========================================================================

/// Scheduler admission gate that evaluates workers for build safety.
///
/// Combines pressure state, headroom estimates, and hysteresis to produce
/// per-worker admission verdicts consumed by the selection pipeline.
pub struct AdmissionGate {
    config: AdmissionConfig,
    headroom: Arc<HeadroomEstimator>,
    /// Per-worker hysteresis tracking (across selection rounds).
    hysteresis: RwLock<HashMap<String, WorkerHysteresis>>,
    /// Latest verdicts from the current selection round (cleared per round).
    latest_verdicts: RwLock<HashMap<String, AdmissionVerdict>>,
}

impl AdmissionGate {
    /// Create a new admission gate.
    pub fn new(config: AdmissionConfig, headroom: Arc<HeadroomEstimator>) -> Self {
        Self {
            config,
            headroom,
            hysteresis: RwLock::new(HashMap::new()),
            latest_verdicts: RwLock::new(HashMap::new()),
        }
    }

    /// Clear cached verdicts at the start of a new selection round.
    pub async fn begin_round(&self) {
        self.latest_verdicts.write().await.clear();
    }

    /// Evaluate a worker for admission into the selection pool.
    ///
    /// Called once per worker per selection round.  The verdict is cached
    /// for later retrieval by [`get_pressure_penalty`].
    pub async fn evaluate(
        &self,
        worker: &WorkerState,
        worker_id: &str,
        project_id: &str,
    ) -> AdmissionVerdict {
        let pressure = worker.pressure_assessment().await;

        // Critical pressure: always hard reject (no hysteresis override).
        if pressure.state == PressureState::Critical {
            let verdict = AdmissionVerdict::Reject {
                reason_code: "admission_critical_pressure".to_string(),
                reason: format!(
                    "critical pressure (confidence={}, rule={})",
                    pressure.confidence, pressure.policy_rule
                ),
            };
            self.record_rejection(worker_id).await;
            self.cache_verdict(worker_id, &verdict).await;
            return verdict;
        }

        // Compute headroom score.
        let disk_free_gb = pressure.disk_free_gb.unwrap_or(0.0);
        let wid = WorkerId::new(worker_id);
        let h_score = self
            .headroom
            .headroom_score(&wid, project_id, disk_free_gb)
            .await;

        // Insufficient headroom: reject (immediate, safety first).
        if h_score < self.config.min_headroom_score {
            let verdict = AdmissionVerdict::Reject {
                reason_code: "admission_insufficient_headroom".to_string(),
                reason: format!(
                    "headroom score {:.2} < min {:.2} (free={:.1}GB)",
                    h_score, self.config.min_headroom_score, disk_free_gb
                ),
            };
            self.record_rejection(worker_id).await;
            self.cache_verdict(worker_id, &verdict).await;
            return verdict;
        }

        // Raw eval says admit — apply hysteresis for recovery from prior rejection.
        if self.is_hysteresis_blocked(worker_id).await {
            let verdict = AdmissionVerdict::Reject {
                reason_code: "admission_hysteresis_cooldown".to_string(),
                reason: format!(
                    "hysteresis recovery (needs {} consecutive healthy evals)",
                    self.config.hysteresis_recover_count
                ),
            };
            self.cache_verdict(worker_id, &verdict).await;
            return verdict;
        }

        // Worker admitted — record healthy evaluation and compute penalty.
        self.record_admission(worker_id).await;

        let pressure_penalty = match pressure.state {
            PressureState::Warning => self.config.warning_pressure_penalty,
            PressureState::TelemetryGap => self.config.telemetry_gap_penalty,
            PressureState::Healthy => 0.0,
            PressureState::Critical => unreachable!(),
        };

        let verdict = AdmissionVerdict::Admit {
            pressure_penalty,
            headroom_score: h_score,
        };
        self.cache_verdict(worker_id, &verdict).await;

        debug!(
            worker_id,
            pressure_penalty,
            headroom_score = h_score,
            pressure_state = %pressure.state,
            "admission: worker admitted"
        );

        verdict
    }

    /// Get the cached pressure penalty for a worker in the current round.
    ///
    /// Returns 0.0 (no penalty) if the worker was not evaluated, preserving
    /// fail-open semantics.
    pub async fn get_pressure_penalty(&self, worker_id: &str) -> f64 {
        self.latest_verdicts
            .read()
            .await
            .get(worker_id)
            .map(|v| v.pressure_penalty())
            .unwrap_or(0.0)
    }

    /// Get the current hysteresis state for a worker (for diagnostics).
    ///
    /// Returns `(last_admitted, consecutive_healthy)`.
    pub async fn worker_hysteresis_state(&self, worker_id: &str) -> Option<(bool, u32)> {
        self.hysteresis
            .read()
            .await
            .get(worker_id)
            .map(|h| (h.last_admitted, h.consecutive_healthy))
    }

    /// Reset hysteresis state for a worker (e.g. after manual intervention).
    pub async fn reset_hysteresis(&self, worker_id: &str) {
        self.hysteresis.write().await.remove(worker_id);
    }

    // ----- internal helpers -----

    async fn cache_verdict(&self, worker_id: &str, verdict: &AdmissionVerdict) {
        self.latest_verdicts
            .write()
            .await
            .insert(worker_id.to_string(), verdict.clone());
    }

    async fn record_rejection(&self, worker_id: &str) {
        let mut state = self.hysteresis.write().await;
        let entry = state.entry(worker_id.to_string()).or_default();
        entry.last_admitted = false;
        entry.last_rejected_at = Some(Instant::now());
        entry.consecutive_healthy = 0;
    }

    async fn record_admission(&self, worker_id: &str) {
        let mut state = self.hysteresis.write().await;
        let entry = state.entry(worker_id.to_string()).or_default();
        entry.last_admitted = true;
        entry.consecutive_healthy = entry.consecutive_healthy.saturating_add(1);
    }

    /// Check if a worker is blocked from re-admission due to hysteresis.
    ///
    /// Returns `true` when the worker must remain rejected (still in cooldown
    /// or hasn't accumulated enough consecutive healthy evaluations).
    async fn is_hysteresis_blocked(&self, worker_id: &str) -> bool {
        let mut state = self.hysteresis.write().await;
        let entry = state.entry(worker_id.to_string()).or_default();

        // If worker was last admitted, no hysteresis block.
        if entry.last_admitted {
            return false;
        }

        // Still in cooldown period after rejection.
        if let Some(rejected_at) = entry.last_rejected_at
            && rejected_at.elapsed() < self.config.hysteresis_cooldown
        {
            return true;
        }

        // Past cooldown — count this healthy evaluation.
        entry.consecutive_healthy = entry.consecutive_healthy.saturating_add(1);

        if entry.consecutive_healthy >= self.config.hysteresis_recover_count {
            // Recovery complete — clear rejection state.
            entry.last_admitted = true;
            entry.consecutive_healthy = 0;
            entry.last_rejected_at = None;
            false
        } else {
            true
        }
    }
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disk_pressure::{PressureAssessment, PressureConfidence};
    use crate::headroom::HeadroomConfig;
    use crate::history::BuildHistory;
    use rch_common::{BuildLocation, BuildRecord, WorkerConfig, test_guard};

    fn make_assessment(state: PressureState, disk_free_gb: Option<f64>) -> PressureAssessment {
        PressureAssessment {
            state,
            confidence: PressureConfidence::High,
            reason_code: "test_rule".to_string(),
            policy_rule: "test".to_string(),
            disk_free_gb,
            disk_total_gb: Some(100.0),
            disk_free_ratio: disk_free_gb.map(|g| g / 100.0),
            disk_io_util_pct: None,
            memory_pressure: None,
            telemetry_age_secs: Some(5),
            telemetry_fresh: true,
            evaluated_at_unix_ms: 1000,
        }
    }

    async fn make_worker(id: &str, assessment: PressureAssessment) -> Arc<WorkerState> {
        let config = WorkerConfig {
            id: WorkerId::new(id),
            host: "localhost".to_string(),
            user: "test".to_string(),
            total_slots: 4,
            priority: 100,
            ..WorkerConfig::default()
        };
        let ws = WorkerState::new(config);
        ws.set_pressure_assessment(assessment).await;
        Arc::new(ws)
    }

    fn make_gate(history: Arc<BuildHistory>) -> AdmissionGate {
        let estimator = Arc::new(HeadroomEstimator::new(history, HeadroomConfig::default()));
        AdmissionGate::new(AdmissionConfig::default(), estimator)
    }

    fn make_gate_with_config(history: Arc<BuildHistory>, config: AdmissionConfig) -> AdmissionGate {
        let estimator = Arc::new(HeadroomEstimator::new(history, HeadroomConfig::default()));
        AdmissionGate::new(config, estimator)
    }

    fn make_remote_build(id: u64, project_id: &str, bytes: u64) -> BuildRecord {
        BuildRecord {
            id,
            started_at: "2026-01-01T00:00:00Z".to_string(),
            completed_at: "2026-01-01T00:01:00Z".to_string(),
            project_id: project_id.to_string(),
            worker_id: Some("w1".to_string()),
            command: "cargo build".to_string(),
            exit_code: 0,
            duration_ms: 60000,
            location: BuildLocation::Remote,
            bytes_transferred: Some(bytes),
            timing: None,
            cancellation: None,
        }
    }

    // =================================================================
    // Configuration Tests
    // =================================================================

    #[test]
    fn config_defaults() {
        let _guard = test_guard!();
        let config = AdmissionConfig::default();

        assert!((config.min_headroom_score - 0.2).abs() < f64::EPSILON);
        assert!((config.warning_pressure_penalty - 0.4).abs() < f64::EPSILON);
        assert!((config.telemetry_gap_penalty - 0.15).abs() < f64::EPSILON);
        assert_eq!(config.hysteresis_recover_count, 3);
        assert_eq!(config.hysteresis_cooldown, Duration::from_secs(30));
    }

    // =================================================================
    // Critical Pressure Tests
    // =================================================================

    #[tokio::test]
    async fn critical_pressure_always_rejects() {
        let _guard = test_guard!();
        let history = Arc::new(BuildHistory::new(10));
        let gate = make_gate(history);

        let worker = make_worker("w1", make_assessment(PressureState::Critical, Some(5.0))).await;
        let verdict = gate.evaluate(&worker, "w1", "proj-a").await;

        assert!(!verdict.is_admitted());
        if let AdmissionVerdict::Reject { reason_code, .. } = &verdict {
            assert_eq!(reason_code, "admission_critical_pressure");
        } else {
            panic!("Expected Reject verdict");
        }
    }

    #[tokio::test]
    async fn critical_pressure_records_hysteresis_rejection() {
        let _guard = test_guard!();
        let history = Arc::new(BuildHistory::new(10));
        let gate = make_gate(history);

        let worker = make_worker("w1", make_assessment(PressureState::Critical, Some(5.0))).await;
        gate.evaluate(&worker, "w1", "proj-a").await;

        let state = gate.worker_hysteresis_state("w1").await;
        assert!(state.is_some());
        let (admitted, healthy) = state.unwrap();
        assert!(!admitted);
        assert_eq!(healthy, 0);
    }

    // =================================================================
    // Headroom Tests
    // =================================================================

    #[tokio::test]
    async fn insufficient_headroom_rejects() {
        let _guard = test_guard!();
        let history = Arc::new(BuildHistory::new(10));
        let gate = make_gate(history);

        // With defaults: floor=10GB, expected=7.5GB (fallback) → required ~17.5GB
        // headroom_score with 5GB free: (5-0)/17.5/2 ≈ 0.14 < min 0.2
        let worker = make_worker("w1", make_assessment(PressureState::Healthy, Some(5.0))).await;
        let verdict = gate.evaluate(&worker, "w1", "proj-a").await;

        assert!(!verdict.is_admitted());
        if let AdmissionVerdict::Reject { reason_code, .. } = &verdict {
            assert_eq!(reason_code, "admission_insufficient_headroom");
        } else {
            panic!("Expected Reject verdict");
        }
    }

    #[tokio::test]
    async fn sufficient_headroom_admits() {
        let _guard = test_guard!();
        let history = Arc::new(BuildHistory::new(10));
        let gate = make_gate(history);

        // 50GB free → headroom_score ≈ (50-0)/17.5/2 ≈ 1.0 → admitted
        let worker = make_worker("w1", make_assessment(PressureState::Healthy, Some(50.0))).await;
        let verdict = gate.evaluate(&worker, "w1", "proj-a").await;

        assert!(verdict.is_admitted());
        assert!((verdict.pressure_penalty() - 0.0).abs() < f64::EPSILON);
    }

    // =================================================================
    // Pressure Penalty Tests
    // =================================================================

    #[tokio::test]
    async fn warning_pressure_applies_penalty() {
        let _guard = test_guard!();
        let history = Arc::new(BuildHistory::new(10));
        let gate = make_gate(history);

        let worker = make_worker("w1", make_assessment(PressureState::Warning, Some(50.0))).await;
        let verdict = gate.evaluate(&worker, "w1", "proj-a").await;

        assert!(verdict.is_admitted());
        assert!((verdict.pressure_penalty() - 0.4).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn telemetry_gap_applies_small_penalty() {
        let _guard = test_guard!();
        let history = Arc::new(BuildHistory::new(10));
        let gate = make_gate(history);

        let worker = make_worker(
            "w1",
            make_assessment(PressureState::TelemetryGap, Some(50.0)),
        )
        .await;
        let verdict = gate.evaluate(&worker, "w1", "proj-a").await;

        assert!(verdict.is_admitted());
        assert!((verdict.pressure_penalty() - 0.15).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn healthy_pressure_no_penalty() {
        let _guard = test_guard!();
        let history = Arc::new(BuildHistory::new(10));
        let gate = make_gate(history);

        let worker = make_worker("w1", make_assessment(PressureState::Healthy, Some(50.0))).await;
        let verdict = gate.evaluate(&worker, "w1", "proj-a").await;

        assert!(verdict.is_admitted());
        assert!((verdict.pressure_penalty() - 0.0).abs() < f64::EPSILON);

        if let AdmissionVerdict::Admit { headroom_score, .. } = &verdict {
            assert!(*headroom_score > 0.5);
        }
    }

    // =================================================================
    // Verdict Caching Tests
    // =================================================================

    #[tokio::test]
    async fn get_pressure_penalty_from_cache() {
        let _guard = test_guard!();
        let history = Arc::new(BuildHistory::new(10));
        let gate = make_gate(history);

        let worker = make_worker("w1", make_assessment(PressureState::Warning, Some(50.0))).await;
        gate.evaluate(&worker, "w1", "proj-a").await;

        let penalty = gate.get_pressure_penalty("w1").await;
        assert!((penalty - 0.4).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn get_pressure_penalty_unknown_worker_returns_zero() {
        let _guard = test_guard!();
        let history = Arc::new(BuildHistory::new(10));
        let gate = make_gate(history);

        let penalty = gate.get_pressure_penalty("unknown").await;
        assert!((penalty - 0.0).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn begin_round_clears_cached_verdicts() {
        let _guard = test_guard!();
        let history = Arc::new(BuildHistory::new(10));
        let gate = make_gate(history);

        let worker = make_worker("w1", make_assessment(PressureState::Warning, Some(50.0))).await;
        gate.evaluate(&worker, "w1", "proj-a").await;
        assert!((gate.get_pressure_penalty("w1").await - 0.4).abs() < f64::EPSILON);

        gate.begin_round().await;
        assert!((gate.get_pressure_penalty("w1").await - 0.0).abs() < f64::EPSILON);
    }

    // =================================================================
    // Hysteresis Tests
    // =================================================================

    #[tokio::test]
    async fn hysteresis_blocks_immediate_readmission() {
        let _guard = test_guard!();
        let history = Arc::new(BuildHistory::new(10));
        let config = AdmissionConfig {
            hysteresis_recover_count: 3,
            hysteresis_cooldown: Duration::from_millis(0), // no cooldown for test
            ..Default::default()
        };
        let gate = make_gate_with_config(history, config);

        // First: reject due to insufficient headroom
        let worker_low =
            make_worker("w1", make_assessment(PressureState::Healthy, Some(5.0))).await;
        let v1 = gate.evaluate(&worker_low, "w1", "proj-a").await;
        assert!(!v1.is_admitted());

        // Now worker has plenty of space, but hysteresis blocks re-admission
        let worker_high =
            make_worker("w1", make_assessment(PressureState::Healthy, Some(50.0))).await;

        // Eval 1: still blocked (consecutive_healthy goes to 1)
        gate.begin_round().await;
        let v2 = gate.evaluate(&worker_high, "w1", "proj-a").await;
        assert!(!v2.is_admitted());
        if let AdmissionVerdict::Reject { reason_code, .. } = &v2 {
            assert_eq!(reason_code, "admission_hysteresis_cooldown");
        }

        // Eval 2: still blocked (consecutive_healthy goes to 2)
        gate.begin_round().await;
        let v3 = gate.evaluate(&worker_high, "w1", "proj-a").await;
        assert!(!v3.is_admitted());

        // Eval 3: recovery complete (consecutive_healthy reaches 3)
        gate.begin_round().await;
        let v4 = gate.evaluate(&worker_high, "w1", "proj-a").await;
        assert!(v4.is_admitted());
    }

    #[tokio::test]
    async fn hysteresis_cooldown_blocks_early_recovery() {
        let _guard = test_guard!();
        let history = Arc::new(BuildHistory::new(10));
        let config = AdmissionConfig {
            hysteresis_recover_count: 1, // only 1 healthy eval needed
            hysteresis_cooldown: Duration::from_secs(60), // but 60s cooldown
            ..Default::default()
        };
        let gate = make_gate_with_config(history, config);

        // Reject first
        let worker_low =
            make_worker("w1", make_assessment(PressureState::Healthy, Some(5.0))).await;
        gate.evaluate(&worker_low, "w1", "proj-a").await;

        // Try to readmit with good state - blocked by cooldown
        let worker_high =
            make_worker("w1", make_assessment(PressureState::Healthy, Some(50.0))).await;
        gate.begin_round().await;
        let verdict = gate.evaluate(&worker_high, "w1", "proj-a").await;
        assert!(!verdict.is_admitted());
        if let AdmissionVerdict::Reject { reason_code, .. } = &verdict {
            assert_eq!(reason_code, "admission_hysteresis_cooldown");
        }
    }

    #[tokio::test]
    async fn hysteresis_rejection_is_immediate() {
        let _guard = test_guard!();
        let history = Arc::new(BuildHistory::new(10));
        let gate = make_gate(history);

        // First: admit the worker normally
        let worker_good =
            make_worker("w1", make_assessment(PressureState::Healthy, Some(50.0))).await;
        let v1 = gate.evaluate(&worker_good, "w1", "proj-a").await;
        assert!(v1.is_admitted());

        // Now: worker goes critical → immediate rejection (no hysteresis delay)
        let worker_crit =
            make_worker("w1", make_assessment(PressureState::Critical, Some(2.0))).await;
        gate.begin_round().await;
        let v2 = gate.evaluate(&worker_crit, "w1", "proj-a").await;
        assert!(!v2.is_admitted());
    }

    #[tokio::test]
    async fn hysteresis_reset_allows_immediate_admission() {
        let _guard = test_guard!();
        let history = Arc::new(BuildHistory::new(10));
        let config = AdmissionConfig {
            hysteresis_recover_count: 10,
            hysteresis_cooldown: Duration::from_secs(3600),
            ..Default::default()
        };
        let gate = make_gate_with_config(history, config);

        // Reject
        let worker_low =
            make_worker("w1", make_assessment(PressureState::Healthy, Some(5.0))).await;
        gate.evaluate(&worker_low, "w1", "proj-a").await;

        // Reset hysteresis
        gate.reset_hysteresis("w1").await;

        // Now should admit immediately (no hysteresis state)
        let worker_high =
            make_worker("w1", make_assessment(PressureState::Healthy, Some(50.0))).await;
        gate.begin_round().await;
        let verdict = gate.evaluate(&worker_high, "w1", "proj-a").await;
        assert!(verdict.is_admitted());
    }

    // =================================================================
    // Historical Data Tests
    // =================================================================

    #[tokio::test]
    async fn headroom_uses_historical_build_sizes() {
        let _guard = test_guard!();
        let history = Arc::new(BuildHistory::new(10));

        // Record builds with ~1GB transfers
        let one_gb = 1024 * 1024 * 1024_u64;
        history.record(make_remote_build(1, "proj-a", one_gb));
        history.record(make_remote_build(2, "proj-a", one_gb));

        let gate = make_gate(history);

        // With 1GB builds: expected ~1.5GB (1*1.5), floor 10GB → required ~11.5GB
        // 30GB free → headroom_score = (30/11.5)/2 ≈ 1.0
        let worker = make_worker("w1", make_assessment(PressureState::Healthy, Some(30.0))).await;
        let verdict = gate.evaluate(&worker, "w1", "proj-a").await;
        assert!(verdict.is_admitted());
    }

    #[tokio::test]
    async fn headroom_rejects_with_historical_large_builds() {
        let _guard = test_guard!();
        let history = Arc::new(BuildHistory::new(10));

        // Record builds with ~20GB transfers
        let twenty_gb = 20 * 1024 * 1024 * 1024_u64;
        history.record(make_remote_build(1, "proj-big", twenty_gb));
        history.record(make_remote_build(2, "proj-big", twenty_gb));

        let gate = make_gate(history);

        // 20GB builds: expected ~30GB (20*1.5), floor 10GB → required ~40GB
        // 15GB free → headroom_score = (15/40)/2 ≈ 0.19 < 0.2 → reject
        let worker = make_worker("w1", make_assessment(PressureState::Healthy, Some(15.0))).await;
        let verdict = gate.evaluate(&worker, "w1", "proj-big").await;
        assert!(!verdict.is_admitted());
    }

    // =================================================================
    // Multiple Workers Tests
    // =================================================================

    #[tokio::test]
    async fn multiple_workers_evaluated_independently() {
        let _guard = test_guard!();
        let history = Arc::new(BuildHistory::new(10));
        let gate = make_gate(history);

        let w1 = make_worker("w1", make_assessment(PressureState::Healthy, Some(50.0))).await;
        let w2 = make_worker("w2", make_assessment(PressureState::Warning, Some(50.0))).await;
        let w3 = make_worker("w3", make_assessment(PressureState::Critical, Some(5.0))).await;

        let v1 = gate.evaluate(&w1, "w1", "proj-a").await;
        let v2 = gate.evaluate(&w2, "w2", "proj-a").await;
        let v3 = gate.evaluate(&w3, "w3", "proj-a").await;

        assert!(v1.is_admitted());
        assert!((v1.pressure_penalty() - 0.0).abs() < f64::EPSILON);

        assert!(v2.is_admitted());
        assert!((v2.pressure_penalty() - 0.4).abs() < f64::EPSILON);

        assert!(!v3.is_admitted());

        // Verify cached penalties
        assert!((gate.get_pressure_penalty("w1").await - 0.0).abs() < f64::EPSILON);
        assert!((gate.get_pressure_penalty("w2").await - 0.4).abs() < f64::EPSILON);
        assert!((gate.get_pressure_penalty("w3").await - 1.0).abs() < f64::EPSILON);
    }

    // =================================================================
    // Fail-Open Tests
    // =================================================================

    #[tokio::test]
    async fn unknown_worker_penalty_is_fail_open() {
        let _guard = test_guard!();
        let history = Arc::new(BuildHistory::new(10));
        let gate = make_gate(history);

        // Worker not evaluated → penalty is 0.0 (fail-open)
        assert!((gate.get_pressure_penalty("not-evaluated").await - 0.0).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn telemetry_gap_with_no_disk_info_still_admits() {
        let _guard = test_guard!();
        let history = Arc::new(BuildHistory::new(10));
        // Very low headroom threshold so even 0GB "free" can pass
        let config = AdmissionConfig {
            min_headroom_score: 0.0, // disable headroom check
            ..Default::default()
        };
        let gate = make_gate_with_config(history, config);

        let worker = make_worker("w1", make_assessment(PressureState::TelemetryGap, None)).await;
        let verdict = gate.evaluate(&worker, "w1", "proj-a").await;

        // Should admit with telemetry_gap penalty (fail-open)
        assert!(verdict.is_admitted());
        assert!((verdict.pressure_penalty() - 0.15).abs() < f64::EPSILON);
    }
}
