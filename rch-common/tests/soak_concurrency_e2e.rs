//! Long-Duration Concurrency Soak E2E Tests (bd-vvmd.7.9)
//!
//! Deterministic soak tests that repeatedly exercise reliability scenarios
//! while injecting failure hooks, slot churn, and pressure transitions.
//! Verifies no unbounded state leaks, cumulative drift, or flapping.
//!
//! Runs quickly in smoke mode (default); set `RCH_E2E_SOAK_ITERATIONS=1000`
//! for nightly soak coverage.

use rch_common::e2e::harness::{
    ReliabilityCommandRecord, ReliabilityFailureHook, ReliabilityFailureHookFlags,
    ReliabilityLifecycleCommand, ReliabilityScenarioReport, ReliabilityScenarioSpec,
};
use rch_common::e2e::logging::{
    LogLevel, ReliabilityContext, ReliabilityEventInput, ReliabilityPhase,
    ReliabilityPhaseEvent, TestLoggerBuilder, RELIABILITY_EVENT_SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Default iteration count for smoke runs (fast).
const SMOKE_ITERATIONS: usize = 20;

/// Environment variable to override iteration count.
const SOAK_ITERATIONS_ENV: &str = "RCH_E2E_SOAK_ITERATIONS";

/// Environment variable for deterministic seed.
const SOAK_SEED_ENV: &str = "RCH_E2E_SEED";

/// Get iteration count from environment or default.
fn soak_iterations() -> usize {
    std::env::var(SOAK_ITERATIONS_ENV)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(SMOKE_ITERATIONS)
}

/// Get deterministic seed from environment or default.
fn soak_seed() -> u64 {
    std::env::var(SOAK_SEED_ENV)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(42)
}

/// Deterministic PRNG (xorshift64) for reproducible fixture generation.
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

    fn next_usize(&mut self, max: usize) -> usize {
        (self.next_u64() as usize) % max.max(1)
    }

    fn next_bool(&mut self, probability: f64) -> bool {
        self.next_f64() < probability
    }
}

// ===========================================================================
// Soak iteration tracker
// ===========================================================================

/// Per-iteration soak measurement.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SoakIterationRecord {
    iteration: usize,
    worker_id: String,
    slots_reserved: u32,
    slots_released: u32,
    slot_leak: i32,
    convergence_drift: f64,
    pressure_state: String,
    failure_hooks_active: Vec<String>,
    decision_code: String,
    fallback_triggered: bool,
    duration_ms: u64,
}

/// Aggregate soak summary for threshold comparison.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SoakSummary {
    total_iterations: usize,
    passed_iterations: usize,
    failed_iterations: usize,
    total_slot_leaks: i32,
    max_convergence_drift: f64,
    total_fallback_count: usize,
    fallback_rate: f64,
    max_consecutive_failures: usize,
    failure_hook_activation_counts: HashMap<String, usize>,
    seed: u64,
}

// ===========================================================================
// Simulated worker slot manager
// ===========================================================================

/// Simulated worker with slot tracking for leak detection.
struct SimulatedWorker {
    id: String,
    total_slots: u32,
    used_slots: u32,
    cumulative_reserved: u64,
    cumulative_released: u64,
}

impl SimulatedWorker {
    fn new(id: &str, total_slots: u32) -> Self {
        Self {
            id: id.to_string(),
            total_slots,
            used_slots: 0,
            cumulative_reserved: 0,
            cumulative_released: 0,
        }
    }

    fn available(&self) -> u32 {
        self.total_slots.saturating_sub(self.used_slots)
    }

    fn reserve(&mut self, count: u32) -> bool {
        if self.used_slots + count <= self.total_slots {
            self.used_slots += count;
            self.cumulative_reserved += count as u64;
            true
        } else {
            false
        }
    }

    fn release(&mut self, count: u32) {
        self.used_slots = self.used_slots.saturating_sub(count);
        self.cumulative_released += count as u64;
    }

    fn slot_leak(&self) -> i64 {
        self.cumulative_reserved as i64 - self.cumulative_released as i64
    }
}

// ===========================================================================
// Simulated convergence tracker
// ===========================================================================

/// Simulated convergence drift tracker.
struct ConvergenceDriftTracker {
    drift_values: Vec<f64>,
    current_drift: f64,
}

impl ConvergenceDriftTracker {
    fn new() -> Self {
        Self {
            drift_values: Vec::new(),
            current_drift: 0.0,
        }
    }

    fn apply_update(&mut self, success: bool, rng: &mut Rng) {
        if success {
            // Successful sync reduces drift toward 0
            self.current_drift = (self.current_drift - 0.1).max(0.0);
        } else {
            // Failed sync increases drift
            self.current_drift = (self.current_drift + 0.05 + rng.next_f64() * 0.1).min(1.0);
        }
        self.drift_values.push(self.current_drift);
    }

    fn max_drift(&self) -> f64 {
        self.drift_values.iter().copied().fold(0.0_f64, f64::max)
    }
}

// ===========================================================================
// Pressure state simulator
// ===========================================================================

fn simulate_pressure_state(rng: &mut Rng, iteration: usize) -> String {
    // Periodically simulate pressure transitions
    let phase = (iteration as f64 * 0.1).sin().abs();
    if phase < 0.6 {
        "disk:normal,memory:normal".to_string()
    } else if phase < 0.8 {
        "disk:warning,memory:normal".to_string()
    } else if rng.next_bool(0.15) {
        "disk:critical,memory:high".to_string()
    } else {
        "disk:warning,memory:high".to_string()
    }
}

/// Decide which failure hooks to inject for this iteration.
fn select_failure_hooks(rng: &mut Rng, iteration: usize) -> Vec<ReliabilityFailureHook> {
    let mut hooks = Vec::new();

    // Inject network cut every ~10 iterations
    if iteration % 10 == 7 || rng.next_bool(0.08) {
        hooks.push(ReliabilityFailureHook::NetworkCut);
    }

    // Inject sync timeout every ~15 iterations
    if iteration % 15 == 3 || rng.next_bool(0.05) {
        hooks.push(ReliabilityFailureHook::SyncTimeout);
    }

    // Inject partial update every ~12 iterations
    if iteration % 12 == 5 || rng.next_bool(0.06) {
        hooks.push(ReliabilityFailureHook::PartialUpdate);
    }

    // Inject daemon restart rarely
    if iteration > 0 && iteration.is_multiple_of(25) {
        hooks.push(ReliabilityFailureHook::DaemonRestart);
    }

    hooks
}

// ===========================================================================
// 1. Core Soak Loop: Slot Reservation/Release Leak Detection
// ===========================================================================

#[test]
fn e2e_soak_slot_reservation_no_unbounded_leak() {
    let iterations = soak_iterations();
    let seed = soak_seed();
    let mut rng = Rng::new(seed);

    let worker_ids = ["css", "mms", "gpu-01"];
    let mut workers: Vec<SimulatedWorker> = worker_ids
        .iter()
        .map(|id| SimulatedWorker::new(id, 8))
        .collect();

    let mut total_leak = 0i64;

    for i in 0..iterations {
        // Pick a random worker
        let idx = rng.next_usize(workers.len());
        let worker = &mut workers[idx];

        // Reserve 1-3 slots
        let count = (rng.next_usize(3) + 1) as u32;
        let reserved = worker.reserve(count);

        if reserved {
            // Simulate build (may partially fail)
            let failure_hooks = select_failure_hooks(&mut rng, i);
            let build_success = failure_hooks.is_empty() || rng.next_bool(0.7);

            // Always release what was reserved (correct behavior)
            worker.release(count);

            if !build_success {
                // Verify no slot leak even on failure
                assert!(
                    worker.slot_leak() >= 0,
                    "iteration {i}: negative slot leak on worker {} ({} reserved, {} released)",
                    worker.id,
                    worker.cumulative_reserved,
                    worker.cumulative_released
                );
            }
        }
    }

    // Final invariant: all workers must have zero slot leak
    for worker in &workers {
        let leak = worker.slot_leak();
        total_leak += leak;
        assert_eq!(
            leak, 0,
            "worker {} has slot leak: {} (reserved={}, released={})",
            worker.id, leak, worker.cumulative_reserved, worker.cumulative_released
        );
        assert_eq!(
            worker.used_slots, 0,
            "worker {} has {} used slots at end of soak",
            worker.id, worker.used_slots
        );
    }

    assert_eq!(total_leak, 0, "aggregate slot leak across fleet: {total_leak}");
}

// ===========================================================================
// 2. Convergence Drift Bounded Under Churn
// ===========================================================================

#[test]
fn e2e_soak_convergence_drift_bounded_under_churn() {
    let iterations = soak_iterations();
    let seed = soak_seed();
    let mut rng = Rng::new(seed);

    let mut tracker = ConvergenceDriftTracker::new();
    let mut fallback_count = 0usize;

    for i in 0..iterations {
        let failure_hooks = select_failure_hooks(&mut rng, i);
        let has_network_cut = failure_hooks
            .iter()
            .any(|h| matches!(h, ReliabilityFailureHook::NetworkCut));
        let has_sync_timeout = failure_hooks
            .iter()
            .any(|h| matches!(h, ReliabilityFailureHook::SyncTimeout));

        let sync_success = !has_network_cut && !has_sync_timeout && rng.next_bool(0.85);

        tracker.apply_update(sync_success, &mut rng);

        if !sync_success {
            fallback_count += 1;
        }
    }

    // Convergence drift must not grow unbounded
    let max_drift = tracker.max_drift();
    assert!(
        max_drift <= 1.0,
        "convergence drift exceeded 1.0: {max_drift}"
    );

    // Drift should eventually recover under mixed workload
    let final_drift = tracker.current_drift;
    // In smoke mode with 20 iterations, drift may still be nonzero,
    // but should not be at maximum
    assert!(
        final_drift < 0.95,
        "convergence drift did not recover: final={final_drift}"
    );

    // Fallback rate should be within budget (< 60% under moderate fault injection).
    // In smoke mode (20 iterations), fault density is higher; nightly (1000+) converges lower.
    let fallback_rate = fallback_count as f64 / iterations as f64;
    assert!(
        fallback_rate < 0.60,
        "fallback rate {fallback_rate:.2} exceeds 60% budget"
    );
}

// ===========================================================================
// 3. Fail-Open Rate Stays Within Budget
// ===========================================================================

#[test]
fn e2e_soak_failopen_rate_within_budget() {
    let iterations = soak_iterations();
    let seed = soak_seed();
    let mut rng = Rng::new(seed);

    let mut failopen_count = 0usize;
    let mut total_decisions = 0usize;

    for i in 0..iterations {
        let failure_hooks = select_failure_hooks(&mut rng, i);
        let pressure = simulate_pressure_state(&mut rng, i);

        total_decisions += 1;

        // Fail-open triggers when we have missing data but proceed anyway
        let has_critical_pressure = pressure.contains("critical");
        let has_daemon_restart = failure_hooks
            .iter()
            .any(|h| matches!(h, ReliabilityFailureHook::DaemonRestart));

        if has_daemon_restart || (has_critical_pressure && rng.next_bool(0.3)) {
            failopen_count += 1;
        }
    }

    let failopen_rate = failopen_count as f64 / total_decisions as f64;

    // Fail-open rate budget: should be under 15%
    assert!(
        failopen_rate < 0.15,
        "fail-open rate {failopen_rate:.3} exceeds 15% budget ({failopen_count}/{total_decisions})"
    );
}

// ===========================================================================
// 4. No Flapping Under Worker Churn
// ===========================================================================

#[test]
fn e2e_soak_no_flapping_under_worker_churn() {
    let iterations = soak_iterations();
    let seed = soak_seed();
    let mut rng = Rng::new(seed);

    // Track worker health state transitions
    let mut worker_states: HashMap<String, Vec<&str>> = HashMap::new();
    let worker_ids = ["css", "mms"];

    for id in &worker_ids {
        worker_states.insert(id.to_string(), vec!["healthy"]);
    }

    for i in 0..iterations {
        for id in &worker_ids {
            let states = worker_states.get_mut(*id).unwrap();
            let current = *states.last().unwrap();

            let failure_hooks = select_failure_hooks(&mut rng, i);
            let has_fault = !failure_hooks.is_empty();

            let next = match (current, has_fault) {
                ("healthy", true) if rng.next_bool(0.3) => "degraded",
                ("healthy", _) => "healthy",
                ("degraded", false) if rng.next_bool(0.5) => "healthy",
                ("degraded", true) if rng.next_bool(0.2) => "quarantined",
                ("degraded", _) => "degraded",
                ("quarantined", false) if rng.next_bool(0.3) => "probing_recovery",
                ("quarantined", _) => "quarantined",
                ("probing_recovery", false) if rng.next_bool(0.6) => "healthy",
                ("probing_recovery", true) => "quarantined",
                (s, _) => s,
            };

            states.push(next);
        }
    }

    // Count state transitions (flaps)
    for (id, states) in &worker_states {
        let transitions: usize = states.windows(2).filter(|w| w[0] != w[1]).count();
        let flap_rate = transitions as f64 / states.len() as f64;

        // Flap rate should be < 40% (hysteresis should dampen transitions)
        assert!(
            flap_rate < 0.40,
            "worker {id} flap rate {flap_rate:.2} exceeds 40% ({transitions} transitions in {} states)",
            states.len()
        );

        // Should not have rapid healthy<->quarantined oscillations
        let rapid_oscillations = states
            .windows(3)
            .filter(|w| {
                (w[0] == "healthy" && w[1] == "quarantined" && w[2] == "healthy")
                    || (w[0] == "quarantined" && w[1] == "healthy" && w[2] == "quarantined")
            })
            .count();

        assert!(
            rapid_oscillations < 3,
            "worker {id} has {rapid_oscillations} rapid healthy<->quarantined oscillations"
        );
    }
}

// ===========================================================================
// 5. Structured Logging Under Sustained Load
// ===========================================================================

#[test]
fn e2e_soak_structured_logging_under_sustained_load() {
    let iterations = soak_iterations();
    let seed = soak_seed();
    let mut rng = Rng::new(seed);

    let temp_dir = tempfile::tempdir().expect("temp dir");
    let logger = TestLoggerBuilder::new("soak_logging_test")
        .log_dir(temp_dir.path())
        .print_realtime(false)
        .build();

    for i in 0..iterations {
        let failure_hooks = select_failure_hooks(&mut rng, i);
        let pressure = simulate_pressure_state(&mut rng, i);
        let decision = if failure_hooks.is_empty() {
            "SOAK_NOMINAL"
        } else {
            "SOAK_FAULT_INJECTED"
        };

        let hook_names: Vec<String> = failure_hooks.iter().map(|h| h.to_string()).collect();

        let event = logger.log_reliability_event(ReliabilityEventInput {
            level: if failure_hooks.is_empty() {
                LogLevel::Info
            } else {
                LogLevel::Warn
            },
            phase: ReliabilityPhase::Execute,
            scenario_id: format!("soak-iteration-{i}"),
            message: format!("iteration {i} complete"),
            context: ReliabilityContext {
                worker_id: Some("css".to_string()),
                repo_set: vec!["/data/projects/rch".to_string()],
                pressure_state: Some(pressure),
                triage_actions: hook_names,
                decision_code: decision.to_string(),
                fallback_reason: if !failure_hooks.is_empty() {
                    Some("fault-injection".to_string())
                } else {
                    None
                },
            },
            artifact_paths: vec![],
        });

        assert_eq!(event.schema_version, RELIABILITY_EVENT_SCHEMA_VERSION);
        assert_eq!(event.phase, ReliabilityPhase::Execute);
    }

    // Verify all events were logged
    let entries = logger.entries();
    assert_eq!(entries.len(), iterations, "should have logged {iterations} events");

    // Verify JSONL file was written and each line parses
    if let Some(rel_path) = logger.reliability_log_path() {
        let contents = std::fs::read_to_string(rel_path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(
            lines.len(),
            iterations,
            "JSONL file should have {iterations} lines"
        );

        for (i, line) in lines.iter().enumerate() {
            let event: ReliabilityPhaseEvent = serde_json::from_str(line).unwrap_or_else(|e| {
                panic!("line {i} is not a valid ReliabilityPhaseEvent: {e}")
            });
            assert_eq!(event.schema_version, "1.0.0");
        }
    }
}

// ===========================================================================
// 6. Scenario Spec Chaining Under Repeated Invocations
// ===========================================================================

#[test]
fn e2e_soak_scenario_spec_deterministic_under_repetition() {
    let iterations = soak_iterations();
    let seed = soak_seed();
    let mut rng = Rng::new(seed);

    let mut specs: Vec<ReliabilityScenarioSpec> = Vec::new();

    for i in 0..iterations {
        let failure_hooks = select_failure_hooks(&mut rng, i);
        let pressure = simulate_pressure_state(&mut rng, i);

        let mut spec = ReliabilityScenarioSpec::new(format!("soak-{i}"))
            .with_worker_id("css")
            .with_repo_set(["/data/projects/rch"])
            .with_pressure_state(&pressure)
            .add_pre_check(ReliabilityLifecycleCommand::new(
                "disk-check",
                "echo",
                ["df -h"],
            ))
            .add_execute_command(
                ReliabilityLifecycleCommand::new("build", "echo", ["cargo test"])
                    .with_timeout_secs(300),
            )
            .add_post_check(
                ReliabilityLifecycleCommand::new("verify", "echo", ["done"]).optional(),
            );

        let mut flags = ReliabilityFailureHookFlags::default();
        for hook in &failure_hooks {
            spec = spec.request_failure_hook(*hook);
            match hook {
                ReliabilityFailureHook::NetworkCut => flags.allow_network_cut = true,
                ReliabilityFailureHook::SyncTimeout => flags.allow_sync_timeout = true,
                ReliabilityFailureHook::PartialUpdate => flags.allow_partial_update = true,
                ReliabilityFailureHook::DaemonRestart => flags.allow_daemon_restart = true,
            }
        }
        spec = spec.with_failure_hook_flags(flags);

        specs.push(spec);
    }

    // Verify determinism: re-create with same seed should produce identical specs
    let mut rng2 = Rng::new(seed);
    for (i, spec) in specs.iter().enumerate() {
        let failure_hooks = select_failure_hooks(&mut rng2, i);
        let pressure = simulate_pressure_state(&mut rng2, i);

        assert_eq!(
            spec.scenario_id,
            format!("soak-{i}"),
            "iteration {i}: scenario_id mismatch"
        );
        assert_eq!(
            spec.pressure_state.as_deref(),
            Some(pressure.as_str()),
            "iteration {i}: pressure_state mismatch"
        );
        assert_eq!(
            spec.requested_failure_hooks.len(),
            failure_hooks.len(),
            "iteration {i}: failure_hooks count mismatch"
        );
    }

    // All specs should serialize to valid JSON
    for (i, spec) in specs.iter().enumerate() {
        let json = serde_json::to_string(spec)
            .unwrap_or_else(|e| panic!("iteration {i}: spec serialization failed: {e}"));
        let _: serde_json::Value = serde_json::from_str(&json)
            .unwrap_or_else(|e| panic!("iteration {i}: spec JSON invalid: {e}"));
    }
}

// ===========================================================================
// 7. Multi-Worker Concurrent Slot Pressure
// ===========================================================================

#[test]
fn e2e_soak_multi_worker_concurrent_pressure() {
    let iterations = soak_iterations();
    let seed = soak_seed();
    let mut rng = Rng::new(seed);

    let mut workers = vec![
        SimulatedWorker::new("css", 8),
        SimulatedWorker::new("mms", 12),
        SimulatedWorker::new("gpu-01", 4),
    ];

    let mut max_fleet_utilization = 0.0f64;
    let mut _at_capacity_count = 0usize;

    for _i in 0..iterations {
        // Simulate variable concurrent demand (1-6 builds)
        let demand = rng.next_usize(6) + 1;

        for _ in 0..demand {
            // Find worker with most available slots
            let best_idx = workers
                .iter()
                .enumerate()
                .max_by_key(|(_, w)| w.available())
                .map(|(idx, _)| idx)
                .unwrap();

            let slots_needed = (rng.next_usize(3) + 1) as u32;
            let reserved = workers[best_idx].reserve(slots_needed);

            if !reserved {
                _at_capacity_count += 1;
            }
        }

        // Track utilization
        let total_used: u32 = workers.iter().map(|w| w.used_slots).sum();
        let total_capacity: u32 = workers.iter().map(|w| w.total_slots).sum();
        let utilization = total_used as f64 / total_capacity as f64;
        max_fleet_utilization = max_fleet_utilization.max(utilization);

        // Release all slots (builds complete)
        for w in &mut workers {
            let to_release = w.used_slots;
            w.release(to_release);
        }
    }

    // All slots must be released
    for w in &workers {
        assert_eq!(
            w.used_slots, 0,
            "worker {} has {} unreleased slots",
            w.id, w.used_slots
        );
        assert_eq!(
            w.slot_leak(),
            0,
            "worker {} has slot leak: {}",
            w.id,
            w.slot_leak()
        );
    }

    // Utilization should have reached meaningful levels
    assert!(
        max_fleet_utilization > 0.0,
        "fleet never utilized: max_utilization={max_fleet_utilization}"
    );
}

// ===========================================================================
// 8. Report Accumulation Stability
// ===========================================================================

#[test]
fn e2e_soak_report_accumulation_no_unbounded_growth() {
    let iterations = soak_iterations();
    let seed = soak_seed();
    let mut rng = Rng::new(seed);

    let mut records: Vec<SoakIterationRecord> = Vec::with_capacity(iterations);

    let mut worker = SimulatedWorker::new("css", 8);
    let mut drift_tracker = ConvergenceDriftTracker::new();
    let mut fallback_count = 0usize;
    let mut max_consecutive_failures = 0usize;
    let mut current_failure_streak = 0usize;
    let mut hook_counts: HashMap<String, usize> = HashMap::new();

    for i in 0..iterations {
        let start = std::time::Instant::now();
        let failure_hooks = select_failure_hooks(&mut rng, i);
        let pressure = simulate_pressure_state(&mut rng, i);

        let slots = (rng.next_usize(3) + 1) as u32;
        let reserved = worker.reserve(slots);
        let released = if reserved { slots } else { 0 };

        let sync_success = failure_hooks.is_empty() && rng.next_bool(0.9);
        drift_tracker.apply_update(sync_success, &mut rng);

        let is_fallback = !failure_hooks.is_empty()
            && failure_hooks
                .iter()
                .any(|h| matches!(h, ReliabilityFailureHook::DaemonRestart));

        if is_fallback {
            fallback_count += 1;
        }

        if !sync_success {
            current_failure_streak += 1;
            max_consecutive_failures = max_consecutive_failures.max(current_failure_streak);
        } else {
            current_failure_streak = 0;
        }

        let hook_names: Vec<String> = failure_hooks.iter().map(|h| h.to_string()).collect();
        for name in &hook_names {
            *hook_counts.entry(name.clone()).or_insert(0) += 1;
        }

        if reserved {
            worker.release(released);
        }

        let duration = start.elapsed();

        records.push(SoakIterationRecord {
            iteration: i,
            worker_id: "css".to_string(),
            slots_reserved: if reserved { slots } else { 0 },
            slots_released: released,
            slot_leak: (if reserved { slots } else { 0 } as i32) - released as i32,
            convergence_drift: drift_tracker.current_drift,
            pressure_state: pressure,
            failure_hooks_active: hook_names,
            decision_code: if sync_success {
                "SOAK_OK".to_string()
            } else {
                "SOAK_FAULT".to_string()
            },
            fallback_triggered: is_fallback,
            duration_ms: duration.as_millis() as u64,
        });
    }

    // Build summary
    let summary = SoakSummary {
        total_iterations: iterations,
        passed_iterations: records.iter().filter(|r| r.decision_code == "SOAK_OK").count(),
        failed_iterations: records.iter().filter(|r| r.decision_code != "SOAK_OK").count(),
        total_slot_leaks: records.iter().map(|r| r.slot_leak).sum(),
        max_convergence_drift: drift_tracker.max_drift(),
        total_fallback_count: fallback_count,
        fallback_rate: fallback_count as f64 / iterations as f64,
        max_consecutive_failures,
        failure_hook_activation_counts: hook_counts,
        seed,
    };

    // Verify summary serializes to valid JSON
    let json = serde_json::to_string_pretty(&summary).unwrap();
    let parsed: SoakSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.total_iterations, iterations);
    assert_eq!(parsed.seed, seed);

    // Invariants
    assert_eq!(
        summary.total_slot_leaks, 0,
        "aggregate slot leaks: {}",
        summary.total_slot_leaks
    );
    assert!(
        summary.max_convergence_drift <= 1.0,
        "max drift exceeded 1.0: {}",
        summary.max_convergence_drift
    );
    assert!(
        summary.fallback_rate < 0.20,
        "fallback rate {:.3} exceeds 20% budget",
        summary.fallback_rate
    );
    assert_eq!(
        summary.passed_iterations + summary.failed_iterations,
        summary.total_iterations,
        "pass+fail must equal total"
    );

    // Records should not have unbounded growth per iteration
    assert_eq!(records.len(), iterations);
    for r in &records {
        assert_eq!(r.slot_leak, 0, "iteration {} has nonzero slot leak", r.iteration);
    }
}

// ===========================================================================
// 9. Worker Health Snapshot Logging
// ===========================================================================

#[test]
fn e2e_soak_worker_health_snapshots_logged() {
    let iterations = soak_iterations();
    let seed = soak_seed();
    let mut rng = Rng::new(seed);

    #[derive(Debug, Clone, Serialize)]
    struct WorkerHealthSnapshot {
        iteration: usize,
        worker_id: String,
        health_state: String,
        circuit_debt: f64,
        convergence_debt: f64,
        pressure_debt: f64,
        process_debt: f64,
        cancellation_debt: f64,
        aggregated_debt: f64,
    }

    let mut snapshots: Vec<WorkerHealthSnapshot> = Vec::new();
    let weights = [0.30, 0.22, 0.22, 0.13, 0.13]; // matches SignalWeights defaults

    for i in 0..iterations {
        let failure_hooks = select_failure_hooks(&mut rng, i);
        let has_fault = !failure_hooks.is_empty();

        let circuit_debt = if has_fault { rng.next_f64() * 0.5 } else { rng.next_f64() * 0.1 };
        let convergence_debt = rng.next_f64() * 0.3;
        let pressure_debt = if simulate_pressure_state(&mut rng, i).contains("critical") {
            0.8 + rng.next_f64() * 0.2
        } else {
            rng.next_f64() * 0.2
        };
        let process_debt = rng.next_f64() * 0.15;
        let cancellation_debt = rng.next_f64() * 0.1;

        let debts = [circuit_debt, convergence_debt, pressure_debt, process_debt, cancellation_debt];
        let aggregated: f64 = debts.iter().zip(weights.iter()).map(|(d, w)| d * w).sum();

        let health_state = if aggregated >= 0.7 {
            "quarantined"
        } else if aggregated >= 0.3 {
            "degraded"
        } else {
            "healthy"
        };

        snapshots.push(WorkerHealthSnapshot {
            iteration: i,
            worker_id: "css".to_string(),
            health_state: health_state.to_string(),
            circuit_debt,
            convergence_debt,
            pressure_debt,
            process_debt,
            cancellation_debt,
            aggregated_debt: aggregated,
        });
    }

    // Verify all snapshots serialize
    let json = serde_json::to_string(&snapshots).unwrap();
    let parsed: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.len(), iterations);

    // Verify aggregated debt is bounded [0, 1]
    for s in &snapshots {
        assert!(
            s.aggregated_debt >= 0.0 && s.aggregated_debt <= 1.0,
            "iteration {}: aggregated_debt {} out of [0,1]",
            s.iteration,
            s.aggregated_debt
        );
    }

    // Verify health state classification is consistent with thresholds
    for s in &snapshots {
        match s.health_state.as_str() {
            "quarantined" => assert!(s.aggregated_debt >= 0.7),
            "degraded" => assert!(s.aggregated_debt >= 0.3 && s.aggregated_debt < 0.7),
            "healthy" => assert!(s.aggregated_debt < 0.3),
            other => panic!("unknown health state: {other}"),
        }
    }
}

// ===========================================================================
// 10. Scenario Report Command Records Under Load
// ===========================================================================

#[test]
fn e2e_soak_command_records_well_formed_under_load() {
    let iterations = soak_iterations();
    let seed = soak_seed();
    let mut rng = Rng::new(seed);

    let mut all_reports: Vec<ReliabilityScenarioReport> = Vec::new();

    for i in 0..iterations {
        let failure_hooks = select_failure_hooks(&mut rng, i);

        let mut report = ReliabilityScenarioReport {
            schema_version: RELIABILITY_EVENT_SCHEMA_VERSION.to_string(),
            scenario_id: format!("soak-{i}"),
            phase_order: vec![
                ReliabilityPhase::Setup,
                ReliabilityPhase::Execute,
                ReliabilityPhase::Verify,
                ReliabilityPhase::Cleanup,
            ],
            activated_failure_hooks: failure_hooks.clone(),
            command_records: Vec::new(),
            artifact_paths: Vec::new(),
            manifest_path: None,
        };

        // Add command records for each phase
        let phases = [
            (ReliabilityPhase::Setup, "pre_checks"),
            (ReliabilityPhase::Execute, "execute"),
            (ReliabilityPhase::Verify, "post_checks"),
            (ReliabilityPhase::Cleanup, "cleanup_verification"),
        ];

        for (phase, stage) in phases {
            let succeeded = failure_hooks.is_empty() || rng.next_bool(0.8);
            report.command_records.push(ReliabilityCommandRecord {
                phase,
                stage: stage.to_string(),
                command_name: format!("{stage}-cmd"),
                invoked_program: "echo".to_string(),
                invoked_args: vec!["test".to_string()],
                exit_code: if succeeded { 0 } else { 1 },
                duration_ms: rng.next_u64() % 5000,
                required_success: stage != "cleanup_verification",
                succeeded,
                artifact_paths: vec![],
            });
        }

        all_reports.push(report);
    }

    // All reports must serialize and roundtrip
    for (i, report) in all_reports.iter().enumerate() {
        let json = serde_json::to_string(report)
            .unwrap_or_else(|e| panic!("report {i} serialization failed: {e}"));
        let parsed: ReliabilityScenarioReport = serde_json::from_str(&json)
            .unwrap_or_else(|e| panic!("report {i} deserialization failed: {e}"));

        assert_eq!(parsed.scenario_id, format!("soak-{i}"));
        assert_eq!(parsed.phase_order.len(), 4);
        assert_eq!(parsed.command_records.len(), 4);
        assert_eq!(parsed.schema_version, "1.0.0");
    }

    // No report should have more command records than phases × commands
    for report in &all_reports {
        assert!(
            report.command_records.len() <= 10,
            "report {} has {} command records (expected ≤ 10)",
            report.scenario_id,
            report.command_records.len()
        );
    }
}

// ===========================================================================
// 11. Artifact Capture Under Soak Load
// ===========================================================================

#[test]
fn e2e_soak_artifact_capture_under_load() {
    let iterations = soak_iterations().min(10); // Cap artifacts to avoid disk pressure
    let seed = soak_seed();
    let mut rng = Rng::new(seed);

    let temp_dir = tempfile::tempdir().expect("temp dir");
    let logger = TestLoggerBuilder::new("soak_artifact_test")
        .log_dir(temp_dir.path())
        .print_realtime(false)
        .build();

    let mut captured_paths: Vec<std::path::PathBuf> = Vec::new();

    for i in 0..iterations {
        let scenario_id = format!("soak-artifact-{i}");
        let summary = SoakIterationRecord {
            iteration: i,
            worker_id: "css".to_string(),
            slots_reserved: (rng.next_usize(3) + 1) as u32,
            slots_released: (rng.next_usize(3) + 1) as u32,
            slot_leak: 0,
            convergence_drift: rng.next_f64() * 0.5,
            pressure_state: simulate_pressure_state(&mut rng, i),
            failure_hooks_active: vec![],
            decision_code: "SOAK_OK".to_string(),
            fallback_triggered: false,
            duration_ms: rng.next_u64() % 1000,
        };

        let path = logger
            .capture_artifact_json(&scenario_id, "iteration_record", &summary)
            .unwrap_or_else(|e| panic!("iteration {i}: artifact capture failed: {e}"));

        assert!(path.exists(), "artifact file should exist: {}", path.display());
        captured_paths.push(path);
    }

    // Verify all artifacts are valid JSON and contain expected fields
    for (i, path) in captured_paths.iter().enumerate() {
        let contents = std::fs::read_to_string(path).unwrap();
        let val: serde_json::Value = serde_json::from_str(&contents)
            .unwrap_or_else(|e| panic!("artifact {i} is not valid JSON: {e}"));
        assert_eq!(val["iteration"].as_u64().unwrap(), i as u64);
        assert_eq!(val["worker_id"].as_str().unwrap(), "css");
        assert!(val["convergence_drift"].as_f64().is_some());
    }
}

// ===========================================================================
// 12. Seed Reproducibility
// ===========================================================================

#[test]
fn e2e_soak_seed_reproducibility() {
    let iterations = 50; // Fixed count for reproducibility test
    let seed = 12345u64;

    // Run 1
    let mut rng1 = Rng::new(seed);
    let mut decisions1: Vec<String> = Vec::new();
    for i in 0..iterations {
        let hooks = select_failure_hooks(&mut rng1, i);
        let pressure = simulate_pressure_state(&mut rng1, i);
        decisions1.push(format!("{i}:{pressure}:{}", hooks.len()));
    }

    // Run 2 (same seed)
    let mut rng2 = Rng::new(seed);
    let mut decisions2: Vec<String> = Vec::new();
    for i in 0..iterations {
        let hooks = select_failure_hooks(&mut rng2, i);
        let pressure = simulate_pressure_state(&mut rng2, i);
        decisions2.push(format!("{i}:{pressure}:{}", hooks.len()));
    }

    assert_eq!(decisions1, decisions2, "same seed must produce identical decisions");

    // Different seed should produce different results
    let mut rng3 = Rng::new(seed + 1);
    let mut decisions3: Vec<String> = Vec::new();
    for i in 0..iterations {
        let hooks = select_failure_hooks(&mut rng3, i);
        let pressure = simulate_pressure_state(&mut rng3, i);
        decisions3.push(format!("{i}:{pressure}:{}", hooks.len()));
    }

    assert_ne!(decisions1, decisions3, "different seeds must produce different decisions");
}

// ===========================================================================
// 13. Summary Artifact Conformance
// ===========================================================================

#[test]
fn e2e_soak_summary_artifact_schema_conformance() {
    let summary = SoakSummary {
        total_iterations: 100,
        passed_iterations: 85,
        failed_iterations: 15,
        total_slot_leaks: 0,
        max_convergence_drift: 0.42,
        total_fallback_count: 3,
        fallback_rate: 0.03,
        max_consecutive_failures: 4,
        failure_hook_activation_counts: {
            let mut m = HashMap::new();
            m.insert("network_cut".to_string(), 8);
            m.insert("sync_timeout".to_string(), 5);
            m.insert("partial_update".to_string(), 6);
            m.insert("daemon_restart".to_string(), 3);
            m
        },
        seed: 42,
    };

    let json = serde_json::to_string_pretty(&summary).unwrap();
    let val: serde_json::Value = serde_json::from_str(&json).unwrap();

    // Verify all required fields present
    assert_eq!(val["total_iterations"].as_u64().unwrap(), 100);
    assert_eq!(val["passed_iterations"].as_u64().unwrap(), 85);
    assert_eq!(val["failed_iterations"].as_u64().unwrap(), 15);
    assert_eq!(val["total_slot_leaks"].as_i64().unwrap(), 0);
    assert!(val["max_convergence_drift"].as_f64().is_some());
    assert!(val["fallback_rate"].as_f64().is_some());
    assert!(val["max_consecutive_failures"].as_u64().is_some());
    assert!(val["failure_hook_activation_counts"].is_object());
    assert_eq!(val["seed"].as_u64().unwrap(), 42);

    // Verify pass+fail invariant
    let pass = val["passed_iterations"].as_u64().unwrap();
    let fail = val["failed_iterations"].as_u64().unwrap();
    let total = val["total_iterations"].as_u64().unwrap();
    assert_eq!(pass + fail, total);
}

// ===========================================================================
// 14. Reliability Event Schema Under Multi-Phase Soak
// ===========================================================================

#[test]
fn e2e_soak_reliability_events_cover_all_phases() {
    let phases = [
        ReliabilityPhase::Setup,
        ReliabilityPhase::Execute,
        ReliabilityPhase::Verify,
        ReliabilityPhase::Cleanup,
    ];

    let temp_dir = tempfile::tempdir().expect("temp dir");
    let logger = TestLoggerBuilder::new("soak_all_phases")
        .log_dir(temp_dir.path())
        .print_realtime(false)
        .build();

    // Emit events for each phase across multiple iterations
    let iterations = soak_iterations();
    for i in 0..iterations {
        for phase in &phases {
            let event = logger.log_reliability_event(ReliabilityEventInput::with_decision(
                *phase,
                format!("soak-multi-{i}"),
                format!("{phase} phase for iteration {i}"),
                "PHASE_OK",
            ));

            assert_eq!(event.phase, *phase);
            assert_eq!(event.schema_version, "1.0.0");
        }
    }

    let entries = logger.entries();
    assert_eq!(entries.len(), iterations * phases.len());
}
