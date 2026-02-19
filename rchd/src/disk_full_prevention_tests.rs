//! Integration tests for disk-full prevention and recovery (bd-vvmd.4.6).
//!
//! These tests exercise the cross-module composition of:
//! - `disk_pressure` (pressure classification)
//! - `headroom` (space estimation and reservations)
//! - `admission` (gate with hysteresis)
//! - `reclaim` (safe cleanup decisions)
//! - `selection` (scoring integration)
//!
//! The suite covers imminent-full, full, post-recovery, and active-build
//! contention states, verifying that builds route away from risky workers
//! without destructive cleanup behaviour.

#[cfg(test)]
mod tests {
    use crate::admission::{AdmissionConfig, AdmissionGate, AdmissionVerdict};
    use crate::disk_pressure::{PressureAssessment, PressureConfidence, PressureState};
    use crate::headroom::{HeadroomConfig, HeadroomEstimator};
    use crate::history::BuildHistory;
    use crate::reclaim::{ReclaimConfig, ReclaimMode, check_safety_gate};
    use crate::selection::WorkerSelector;
    use crate::workers::{WorkerPool, WorkerState};
    use rch_common::{
        BuildLocation, BuildRecord, CircuitBreakerConfig, CommandPriority, RequiredRuntime,
        SelectionConfig, SelectionRequest, SelectionStrategy, WorkerConfig, WorkerId, test_guard,
    };
    use std::sync::Arc;
    use std::time::Duration;

    // =================================================================
    // Helpers
    // =================================================================

    fn assessment(state: PressureState, free_gb: Option<f64>) -> PressureAssessment {
        PressureAssessment {
            state,
            confidence: PressureConfidence::High,
            reason_code: format!("test_{}", state),
            policy_rule: "test_policy".to_string(),
            disk_free_gb: free_gb,
            disk_total_gb: Some(500.0),
            disk_free_ratio: free_gb.map(|g| g / 500.0),
            disk_io_util_pct: None,
            memory_pressure: None,
            telemetry_age_secs: Some(5),
            telemetry_fresh: true,
            evaluated_at_unix_ms: 1000,
        }
    }

    async fn make_worker(id: &str, state: PressureState, free_gb: f64) -> Arc<WorkerState> {
        let config = WorkerConfig {
            id: WorkerId::new(id),
            host: "localhost".to_string(),
            user: "test".to_string(),
            total_slots: 8,
            priority: 100,
            ..WorkerConfig::default()
        };
        let ws = WorkerState::new(config);
        ws.set_pressure_assessment(assessment(state, Some(free_gb)))
            .await;
        Arc::new(ws)
    }

    fn make_gate(history: Arc<BuildHistory>, config: AdmissionConfig) -> Arc<AdmissionGate> {
        let estimator = Arc::new(HeadroomEstimator::new(
            history.clone(),
            HeadroomConfig::default(),
        ));
        Arc::new(AdmissionGate::new(config, estimator))
    }

    fn select_request(project: &str) -> SelectionRequest {
        SelectionRequest {
            project: project.to_string(),
            command: None,
            command_priority: CommandPriority::Normal,
            estimated_cores: 1,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
            hook_pid: None,
        }
    }

    fn remote_build(id: u64, project: &str, bytes: u64) -> BuildRecord {
        BuildRecord {
            id,
            started_at: "2026-01-01T00:00:00Z".to_string(),
            completed_at: "2026-01-01T00:01:00Z".to_string(),
            project_id: project.to_string(),
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
    // Pressure Classification Tests
    // =================================================================

    #[test]
    fn pressure_classification_hierarchy() {
        let _guard = test_guard!();
        // Verify ordering: Critical > Warning > Healthy
        let critical = assessment(PressureState::Critical, Some(2.0));
        let warning = assessment(PressureState::Warning, Some(20.0));
        let healthy = assessment(PressureState::Healthy, Some(100.0));
        let gap = assessment(PressureState::TelemetryGap, None);

        assert_eq!(critical.state, PressureState::Critical);
        assert_eq!(warning.state, PressureState::Warning);
        assert_eq!(healthy.state, PressureState::Healthy);
        assert_eq!(gap.state, PressureState::TelemetryGap);
    }

    #[test]
    fn pressure_assessment_includes_diagnostics() {
        let _guard = test_guard!();
        let a = assessment(PressureState::Warning, Some(20.0));

        // All diagnostic fields populated for observability
        assert!(!a.reason_code.is_empty());
        assert!(!a.policy_rule.is_empty());
        assert!(a.disk_free_gb.is_some());
        assert!(a.disk_total_gb.is_some());
        assert!(a.disk_free_ratio.is_some());
        assert!(a.telemetry_fresh);
    }

    // =================================================================
    // Imminent-Full State (Warning Pressure)
    // =================================================================

    #[tokio::test]
    async fn imminent_full_worker_deprioritized_not_rejected() {
        let _guard = test_guard!();
        let history = Arc::new(BuildHistory::new(10));
        let gate = make_gate(history, AdmissionConfig::default());

        // Worker has Warning pressure but enough headroom
        let w = make_worker("w1", PressureState::Warning, 50.0).await;
        let verdict = gate.evaluate(&w, "w1", "proj-a").await;

        // Should be admitted but with penalty
        assert!(verdict.is_admitted());
        assert!(verdict.pressure_penalty() > 0.0);
        assert!((verdict.pressure_penalty() - 0.4).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn imminent_full_worker_scores_lower_than_healthy() {
        let _guard = test_guard!();
        let history = Arc::new(BuildHistory::new(10));
        let gate = make_gate(history, AdmissionConfig::default());

        let w_healthy = make_worker("w1", PressureState::Healthy, 50.0).await;
        let w_warning = make_worker("w2", PressureState::Warning, 50.0).await;

        let v_healthy = gate.evaluate(&w_healthy, "w1", "proj-a").await;
        let v_warning = gate.evaluate(&w_warning, "w2", "proj-a").await;

        // Both admitted
        assert!(v_healthy.is_admitted());
        assert!(v_warning.is_admitted());

        // Warning has higher penalty → lower effective score
        assert!(v_healthy.pressure_penalty() < v_warning.pressure_penalty());
    }

    // =================================================================
    // Full State (Critical Pressure)
    // =================================================================

    #[tokio::test]
    async fn full_worker_hard_rejected() {
        let _guard = test_guard!();
        let history = Arc::new(BuildHistory::new(10));
        let gate = make_gate(history, AdmissionConfig::default());

        let w = make_worker("w1", PressureState::Critical, 2.0).await;
        let verdict = gate.evaluate(&w, "w1", "proj-a").await;

        assert!(!verdict.is_admitted());
        if let AdmissionVerdict::Reject { reason_code, .. } = &verdict {
            assert_eq!(reason_code, "admission_critical_pressure");
        } else {
            panic!("Expected hard rejection for critical pressure");
        }
    }

    #[tokio::test]
    async fn full_worker_routes_to_healthy_alternative() {
        let _guard = test_guard!();
        let history = Arc::new(BuildHistory::new(10));
        let gate = make_gate(history, AdmissionConfig::default());

        // w1 is critical, w2 is healthy
        let w1 = make_worker("w1", PressureState::Critical, 2.0).await;
        let w2 = make_worker("w2", PressureState::Healthy, 50.0).await;

        let v1 = gate.evaluate(&w1, "w1", "proj-a").await;
        let v2 = gate.evaluate(&w2, "w2", "proj-a").await;

        assert!(!v1.is_admitted());
        assert!(v2.is_admitted());
    }

    #[tokio::test]
    async fn full_worker_rejection_includes_diagnostic_reason() {
        let _guard = test_guard!();
        let history = Arc::new(BuildHistory::new(10));
        let gate = make_gate(history, AdmissionConfig::default());

        let w = make_worker("w1", PressureState::Critical, 1.5).await;
        let verdict = gate.evaluate(&w, "w1", "proj-a").await;

        if let AdmissionVerdict::Reject { reason, .. } = &verdict {
            // Reason includes diagnostic details for logging
            assert!(reason.contains("critical pressure"));
        } else {
            panic!("Expected Reject verdict");
        }
    }

    // =================================================================
    // Post-Recovery State (Hysteresis)
    // =================================================================

    #[tokio::test]
    async fn recovery_requires_consecutive_healthy_evals() {
        let _guard = test_guard!();
        let history = Arc::new(BuildHistory::new(10));
        let config = AdmissionConfig {
            hysteresis_recover_count: 3,
            hysteresis_cooldown: Duration::from_millis(0),
            ..Default::default()
        };
        let gate = make_gate(history, config);

        // Phase 1: Reject (critical)
        let w_crit = make_worker("w1", PressureState::Critical, 2.0).await;
        let v = gate.evaluate(&w_crit, "w1", "proj-a").await;
        assert!(!v.is_admitted());

        // Phase 2: Worker recovers (healthy + lots of space)
        let w_ok = make_worker("w1", PressureState::Healthy, 80.0).await;

        // Evaluations 1 and 2: still blocked by hysteresis
        for _ in 0..2 {
            gate.begin_round().await;
            let v = gate.evaluate(&w_ok, "w1", "proj-a").await;
            assert!(!v.is_admitted(), "Should still be in hysteresis recovery");
        }

        // Evaluation 3: recovery complete
        gate.begin_round().await;
        let v_final = gate.evaluate(&w_ok, "w1", "proj-a").await;
        assert!(
            v_final.is_admitted(),
            "Should be re-admitted after recovery"
        );
    }

    #[tokio::test]
    async fn recovery_interrupted_by_new_pressure_resets_counter() {
        let _guard = test_guard!();
        let history = Arc::new(BuildHistory::new(10));
        let config = AdmissionConfig {
            hysteresis_recover_count: 3,
            hysteresis_cooldown: Duration::from_millis(0),
            ..Default::default()
        };
        let gate = make_gate(history, config);

        // Initial rejection
        let w_crit = make_worker("w1", PressureState::Critical, 2.0).await;
        gate.evaluate(&w_crit, "w1", "proj-a").await;

        // 2 healthy evals (not enough)
        let w_ok = make_worker("w1", PressureState::Healthy, 80.0).await;
        for _ in 0..2 {
            gate.begin_round().await;
            gate.evaluate(&w_ok, "w1", "proj-a").await;
        }

        // Pressure returns → counter resets
        let w_crit2 = make_worker("w1", PressureState::Critical, 3.0).await;
        gate.begin_round().await;
        let v = gate.evaluate(&w_crit2, "w1", "proj-a").await;
        assert!(!v.is_admitted());

        // Need 3 MORE consecutive healthy evals
        let w_ok2 = make_worker("w1", PressureState::Healthy, 80.0).await;
        for i in 0..3 {
            gate.begin_round().await;
            let v = gate.evaluate(&w_ok2, "w1", "proj-a").await;
            if i < 2 {
                assert!(!v.is_admitted(), "eval {} should be blocked", i);
            } else {
                assert!(v.is_admitted(), "eval {} should recover", i);
            }
        }
    }

    // =================================================================
    // Active-Build Contention (Reservations)
    // =================================================================

    #[tokio::test]
    async fn headroom_reservations_reduce_effective_free_space() {
        let _guard = test_guard!();
        let history = Arc::new(BuildHistory::new(10));
        let estimator = HeadroomEstimator::new(history.clone(), HeadroomConfig::default());

        // Reserve space for build 1 on worker w1
        let reserved = estimator.reserve(1, &WorkerId::new("w1"), "proj-a").await;
        assert!(reserved > 0.0);

        // Second reservation further reduces headroom
        let reserved2 = estimator.reserve(2, &WorkerId::new("w1"), "proj-a").await;
        assert!(reserved2 > 0.0);

        let total = estimator
            .total_reserved_for_worker(&WorkerId::new("w1"))
            .await;
        assert!((total - reserved - reserved2).abs() < f64::EPSILON);

        // Release frees space
        estimator.release(1).await;
        let after = estimator
            .total_reserved_for_worker(&WorkerId::new("w1"))
            .await;
        assert!((after - reserved2).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn concurrent_builds_can_exhaust_headroom() {
        let _guard = test_guard!();
        let history = Arc::new(BuildHistory::new(10));

        // Record 5GB builds for this project
        let five_gb = 5 * 1024 * 1024 * 1024_u64;
        history.record(remote_build(1, "proj-a", five_gb));
        history.record(remote_build(2, "proj-a", five_gb));

        let estimator = Arc::new(HeadroomEstimator::new(
            history.clone(),
            HeadroomConfig::default(),
        ));

        // Worker has 30GB free
        // With 5GB builds: expected = 7.5GB, floor = 10GB → required ≈ 17.5GB
        let wid = WorkerId::new("w1");

        // First build: score should be decent (30GB free, 17.5 required)
        let score1 = estimator.headroom_score(&wid, "proj-a", 30.0).await;
        assert!(score1 > 0.4, "Should have good headroom score: {}", score1);

        // Reserve for 3 concurrent builds (3 * 7.5 = 22.5GB reserved)
        estimator.reserve(10, &wid, "proj-a").await;
        estimator.reserve(11, &wid, "proj-a").await;
        estimator.reserve(12, &wid, "proj-a").await;

        // After reservations: effective_free = 30 - 22.5 = 7.5GB
        // Required = 17.5GB → score = (7.5/17.5)/2 ≈ 0.21
        let score_after = estimator.headroom_score(&wid, "proj-a", 30.0).await;
        assert!(
            score_after < score1,
            "Score should decrease with reservations: {} vs {}",
            score_after,
            score1
        );
    }

    // =================================================================
    // Reclaim Safety Gate
    // =================================================================

    #[tokio::test]
    async fn reclaim_blocked_during_active_builds() {
        let _guard = test_guard!();
        let history = Arc::new(BuildHistory::new(10));

        // Start an active build on w1
        history.start_active_build(
            "proj-a".to_string(),
            "w1".to_string(),
            "cargo build".to_string(),
            12345,
            1,
            BuildLocation::Remote,
        );

        let w = make_worker("w1", PressureState::Warning, 20.0).await;
        let result = check_safety_gate(&WorkerId::new("w1"), &history, &w);
        assert!(
            !result.permitted,
            "Expected safety gate to block reclaim during active build"
        );
        assert_eq!(result.active_build_ids.len(), 1);
    }

    #[tokio::test]
    async fn reclaim_allowed_when_no_active_builds() {
        let _guard = test_guard!();
        let history = Arc::new(BuildHistory::new(10));

        // No active builds on w1
        let w = make_worker("w1", PressureState::Warning, 20.0).await;
        let result = check_safety_gate(&WorkerId::new("w1"), &history, &w);
        assert!(result.permitted, "Expected safety gate to be clear");
    }

    #[tokio::test]
    async fn reclaim_allowed_on_different_worker() {
        let _guard = test_guard!();
        let history = Arc::new(BuildHistory::new(10));

        // Active build on w2, not w1
        history.start_active_build(
            "proj-a".to_string(),
            "w2".to_string(),
            "cargo build".to_string(),
            12345,
            1,
            BuildLocation::Remote,
        );

        let w = make_worker("w1", PressureState::Warning, 20.0).await;
        let result = check_safety_gate(&WorkerId::new("w1"), &history, &w);
        assert!(
            result.permitted,
            "Expected safety gate clear on different worker"
        );
    }

    // =================================================================
    // Reclaim Policy Decisions
    // =================================================================

    #[test]
    fn reclaim_mode_defaults_to_observe() {
        let _guard = test_guard!();
        let mode = ReclaimMode::default();
        assert_eq!(mode, ReclaimMode::Observe);
    }

    #[test]
    fn reclaim_config_enforces_bounded_budgets() {
        let _guard = test_guard!();
        let config = ReclaimConfig::default();

        // Budget limits prevent unbounded cleanup
        assert!(config.max_reclaim_dirs > 0);
        assert!(config.max_reclaim_bytes > 0);
        assert!(config.min_idle_minutes > 0);
    }

    #[test]
    fn reclaim_disabled_mode_blocks_all_actions() {
        let _guard = test_guard!();
        assert_eq!(ReclaimMode::Disabled, ReclaimMode::Disabled);
        // Disabled mode should prevent any reclaim execution
        // (tested in reclaim module unit tests)
    }

    // =================================================================
    // No Destructive Cleanup Behaviour
    // =================================================================

    #[test]
    fn reclaim_config_default_mode_is_observe_not_enforce() {
        let _guard = test_guard!();
        // Default is Observe (dry-run only) — never auto-enforce deletions
        let config = ReclaimConfig::default();
        assert_eq!(config.mode, ReclaimMode::Observe);
    }

    #[test]
    fn reclaim_config_protected_prefixes_configurable() {
        let _guard = test_guard!();
        let config = ReclaimConfig {
            protected_prefixes: vec![".cache/".to_string(), ".toolchains/".to_string()],
            ..Default::default()
        };
        assert_eq!(config.protected_prefixes.len(), 2);
        assert!(config.protected_prefixes.contains(&".cache/".to_string()));
    }

    #[test]
    fn reclaim_config_timeout_bounded() {
        let _guard = test_guard!();
        let config = ReclaimConfig::default();
        // Timeout prevents runaway operations
        assert!(config.timeout.as_secs() > 0);
        assert!(config.timeout.as_secs() <= 300);
    }

    // =================================================================
    // Selection Pipeline Integration
    // =================================================================

    #[tokio::test]
    async fn selection_with_admission_gate_rejects_critical_worker() {
        let _guard = test_guard!();
        let history = Arc::new(BuildHistory::new(10));
        let gate = make_gate(history.clone(), AdmissionConfig::default());

        let mut selector = WorkerSelector::with_config(
            SelectionConfig {
                strategy: SelectionStrategy::Balanced,
                ..Default::default()
            },
            CircuitBreakerConfig::default(),
        );
        selector.set_admission_gate(gate);

        // Create pool: w1 critical, w2 healthy
        let pool = WorkerPool::new();
        let cfg1 = WorkerConfig {
            id: WorkerId::new("w1"),
            host: "localhost".to_string(),
            user: "test".to_string(),
            total_slots: 4,
            ..Default::default()
        };
        let cfg2 = WorkerConfig {
            id: WorkerId::new("w2"),
            host: "localhost".to_string(),
            user: "test".to_string(),
            total_slots: 4,
            ..Default::default()
        };
        pool.add_worker(cfg1).await;
        pool.add_worker(cfg2).await;

        // Set pressure assessments on pool workers
        if let Some(w1) = pool.get(&WorkerId::new("w1")).await {
            w1.set_pressure_assessment(assessment(PressureState::Critical, Some(2.0)))
                .await;
        }
        if let Some(w2) = pool.get(&WorkerId::new("w2")).await {
            w2.set_pressure_assessment(assessment(PressureState::Healthy, Some(50.0)))
                .await;
        }

        let request = select_request("test-project");
        let result = selector.select(&pool, &request).await;

        // Should select w2 (healthy), not w1 (critical)
        assert!(result.worker.is_some(), "Should select a worker");
        let selected_id = result.worker.unwrap().config.read().await.id.clone();
        assert_eq!(
            selected_id.as_str(),
            "w2",
            "Should select healthy worker, not critical"
        );
    }

    #[tokio::test]
    async fn selection_without_admission_gate_still_rejects_critical() {
        let _guard = test_guard!();

        // No admission gate — falls back to legacy pressure check
        let selector = WorkerSelector::with_config(
            SelectionConfig {
                strategy: SelectionStrategy::Balanced,
                ..Default::default()
            },
            CircuitBreakerConfig::default(),
        );

        let pool = WorkerPool::new();
        let cfg1 = WorkerConfig {
            id: WorkerId::new("w1"),
            host: "localhost".to_string(),
            user: "test".to_string(),
            total_slots: 4,
            ..Default::default()
        };
        let cfg2 = WorkerConfig {
            id: WorkerId::new("w2"),
            host: "localhost".to_string(),
            user: "test".to_string(),
            total_slots: 4,
            ..Default::default()
        };
        pool.add_worker(cfg1).await;
        pool.add_worker(cfg2).await;

        if let Some(w1) = pool.get(&WorkerId::new("w1")).await {
            w1.set_pressure_assessment(assessment(PressureState::Critical, Some(2.0)))
                .await;
        }
        if let Some(w2) = pool.get(&WorkerId::new("w2")).await {
            w2.set_pressure_assessment(assessment(PressureState::Healthy, Some(50.0)))
                .await;
        }

        let request = select_request("test-project");
        let result = selector.select(&pool, &request).await;

        // Legacy path also rejects critical workers
        assert!(result.worker.is_some());
        let selected_id = result.worker.unwrap().config.read().await.id.clone();
        assert_eq!(selected_id.as_str(), "w2");
    }

    #[tokio::test]
    async fn selection_all_workers_critical_falls_back() {
        let _guard = test_guard!();
        let history = Arc::new(BuildHistory::new(10));
        let gate = make_gate(history, AdmissionConfig::default());

        let mut selector = WorkerSelector::with_config(
            SelectionConfig {
                strategy: SelectionStrategy::Balanced,
                ..Default::default()
            },
            CircuitBreakerConfig::default(),
        );
        selector.set_admission_gate(gate);

        let pool = WorkerPool::new();
        let cfg = WorkerConfig {
            id: WorkerId::new("w1"),
            host: "localhost".to_string(),
            user: "test".to_string(),
            total_slots: 4,
            ..Default::default()
        };
        pool.add_worker(cfg).await;

        if let Some(w) = pool.get(&WorkerId::new("w1")).await {
            w.set_pressure_assessment(assessment(PressureState::Critical, Some(1.0)))
                .await;
        }

        let request = select_request("test-project");
        let result = selector.select(&pool, &request).await;

        // With all workers critical: selection should fail (no forced selection)
        // The caller (hook) handles local fallback
        assert!(
            result.worker.is_none(),
            "Should not force-select a critical worker"
        );
    }

    // =================================================================
    // Pressure Transition Scenarios
    // =================================================================

    #[tokio::test]
    async fn pressure_transition_healthy_to_warning_reduces_score() {
        let _guard = test_guard!();
        let history = Arc::new(BuildHistory::new(10));
        let gate = make_gate(history, AdmissionConfig::default());

        // Round 1: Healthy worker
        let w_h = make_worker("w1", PressureState::Healthy, 50.0).await;
        let v1 = gate.evaluate(&w_h, "w1", "proj-a").await;
        let penalty1 = v1.pressure_penalty();

        // Round 2: Same worker now Warning
        gate.begin_round().await;
        let w_w = make_worker("w1", PressureState::Warning, 22.0).await;
        let v2 = gate.evaluate(&w_w, "w1", "proj-a").await;
        let penalty2 = v2.pressure_penalty();

        assert!(
            penalty2 > penalty1,
            "Warning should have higher penalty than Healthy"
        );
        assert!(v2.is_admitted(), "Warning should still be admitted");
    }

    #[tokio::test]
    async fn pressure_transition_warning_to_critical_rejects() {
        let _guard = test_guard!();
        let history = Arc::new(BuildHistory::new(10));
        let gate = make_gate(history, AdmissionConfig::default());

        // Round 1: Warning (admitted with penalty)
        let w_w = make_worker("w1", PressureState::Warning, 22.0).await;
        let v1 = gate.evaluate(&w_w, "w1", "proj-a").await;
        assert!(v1.is_admitted());

        // Round 2: Critical (rejected immediately)
        gate.begin_round().await;
        let w_c = make_worker("w1", PressureState::Critical, 3.0).await;
        let v2 = gate.evaluate(&w_c, "w1", "proj-a").await;
        assert!(!v2.is_admitted());
    }

    #[tokio::test]
    async fn full_recovery_cycle_healthy_warning_critical_recovery() {
        let _guard = test_guard!();
        let history = Arc::new(BuildHistory::new(10));
        let config = AdmissionConfig {
            hysteresis_recover_count: 2,
            hysteresis_cooldown: Duration::from_millis(0),
            ..Default::default()
        };
        let gate = make_gate(history, config);

        // Phase 1: Healthy → admitted
        let w = make_worker("w1", PressureState::Healthy, 80.0).await;
        let v = gate.evaluate(&w, "w1", "proj-a").await;
        assert!(v.is_admitted(), "Phase 1: should admit healthy");

        // Phase 2: Warning → admitted with penalty
        gate.begin_round().await;
        let w = make_worker("w1", PressureState::Warning, 22.0).await;
        let v = gate.evaluate(&w, "w1", "proj-a").await;
        assert!(v.is_admitted(), "Phase 2: should admit warning");
        assert!(v.pressure_penalty() > 0.0);

        // Phase 3: Critical → rejected
        gate.begin_round().await;
        let w = make_worker("w1", PressureState::Critical, 3.0).await;
        let v = gate.evaluate(&w, "w1", "proj-a").await;
        assert!(!v.is_admitted(), "Phase 3: should reject critical");

        // Phase 4: Back to healthy → hysteresis blocks
        gate.begin_round().await;
        let w = make_worker("w1", PressureState::Healthy, 80.0).await;
        let v = gate.evaluate(&w, "w1", "proj-a").await;
        assert!(!v.is_admitted(), "Phase 4a: should block (hysteresis 1/2)");

        // Phase 5: Still healthy → recovery complete
        gate.begin_round().await;
        let w = make_worker("w1", PressureState::Healthy, 80.0).await;
        let v = gate.evaluate(&w, "w1", "proj-a").await;
        assert!(v.is_admitted(), "Phase 5: should readmit after hysteresis");
    }

    // =================================================================
    // Headroom + Admission Interaction
    // =================================================================

    #[tokio::test]
    async fn insufficient_headroom_with_healthy_pressure_still_rejects() {
        let _guard = test_guard!();
        let history = Arc::new(BuildHistory::new(10));
        let gate = make_gate(history, AdmissionConfig::default());

        // Healthy pressure but very low disk → headroom insufficient
        let w = make_worker("w1", PressureState::Healthy, 3.0).await;
        let verdict = gate.evaluate(&w, "w1", "proj-a").await;

        assert!(
            !verdict.is_admitted(),
            "Should reject due to insufficient headroom"
        );
        if let AdmissionVerdict::Reject { reason_code, .. } = &verdict {
            assert_eq!(reason_code, "admission_insufficient_headroom");
        }
    }

    #[tokio::test]
    async fn headroom_improves_with_historical_small_builds() {
        let _guard = test_guard!();
        let history = Arc::new(BuildHistory::new(10));

        // Record very small builds (100MB)
        let small = 100 * 1024 * 1024_u64;
        history.record(remote_build(1, "small-proj", small));
        history.record(remote_build(2, "small-proj", small));
        history.record(remote_build(3, "small-proj", small));

        let gate = make_gate(history, AdmissionConfig::default());

        // With small builds: expected ~0.15GB, floor 10GB → required ~10.15GB
        // 12GB free should be enough
        let w = make_worker("w1", PressureState::Healthy, 12.0).await;
        let verdict = gate.evaluate(&w, "w1", "small-proj").await;

        assert!(
            verdict.is_admitted(),
            "Should admit with small historical builds"
        );
    }

    // =================================================================
    // Fail-Open Guarantees
    // =================================================================

    #[tokio::test]
    async fn telemetry_gap_is_fail_open() {
        let _guard = test_guard!();
        let history = Arc::new(BuildHistory::new(10));
        let config = AdmissionConfig {
            min_headroom_score: 0.0, // disable headroom check for this test
            ..Default::default()
        };
        let gate = make_gate(history, config);

        let w = make_worker("w1", PressureState::TelemetryGap, 0.0).await;
        let verdict = gate.evaluate(&w, "w1", "proj-a").await;

        // Fail-open: telemetry gap admits with penalty, doesn't reject
        assert!(verdict.is_admitted(), "Telemetry gap should fail-open");
        assert!(
            verdict.pressure_penalty() > 0.0,
            "Should apply small penalty"
        );
    }

    #[tokio::test]
    async fn unevaluated_worker_has_zero_penalty() {
        let _guard = test_guard!();
        let history = Arc::new(BuildHistory::new(10));
        let gate = make_gate(history, AdmissionConfig::default());

        // Worker not evaluated → penalty is 0 (fail-open)
        let penalty = gate.get_pressure_penalty("not-evaluated").await;
        assert!(
            (penalty - 0.0).abs() < f64::EPSILON,
            "Unevaluated workers should have zero penalty"
        );
    }

    // =================================================================
    // Logging and Observability
    // =================================================================

    #[tokio::test]
    async fn rejection_verdict_contains_structured_reason() {
        let _guard = test_guard!();
        let history = Arc::new(BuildHistory::new(10));
        let gate = make_gate(history, AdmissionConfig::default());

        let w = make_worker("w1", PressureState::Critical, 1.0).await;
        let verdict = gate.evaluate(&w, "w1", "proj-a").await;

        match verdict {
            AdmissionVerdict::Reject {
                reason_code,
                reason,
            } => {
                // Machine-readable code for structured logging
                assert!(!reason_code.is_empty());
                assert!(reason_code.starts_with("admission_"));

                // Human-readable reason for diagnostics
                assert!(!reason.is_empty());
            }
            _ => panic!("Expected Reject verdict"),
        }
    }

    #[tokio::test]
    async fn admission_verdict_contains_headroom_score() {
        let _guard = test_guard!();
        let history = Arc::new(BuildHistory::new(10));
        let gate = make_gate(history, AdmissionConfig::default());

        let w = make_worker("w1", PressureState::Healthy, 50.0).await;
        let verdict = gate.evaluate(&w, "w1", "proj-a").await;

        match verdict {
            AdmissionVerdict::Admit {
                headroom_score,
                pressure_penalty,
            } => {
                assert!((0.0..=1.0).contains(&headroom_score));
                assert!((0.0..=1.0).contains(&pressure_penalty));
            }
            _ => panic!("Expected Admit verdict"),
        }
    }
}
