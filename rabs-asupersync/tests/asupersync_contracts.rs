//! Consumer-driven contract tests against the PINNED Asupersync
//! revision (bead A009; risk R8; pin + ADR in bead A003).
//!
//! Every test here encodes a behavior RABS RELIES ON, as an executable
//! contract against the real pinned crate — so a pin bump that changes
//! semantics fails loudly HERE, in the adapter crate, instead of deep
//! inside RABS. Each contract names its RABS consumer.
//!
//! Discriminating power is part of the acceptance: the determinism
//! contracts also prove they would FAIL on perturbed behavior (a
//! different seed produces a different certificate), so a vacuous
//! always-equal comparison cannot silently pass a broken pin.

use asupersync::lab::chaos::ChaosConfig;
use asupersync::lab::config::LabConfig;
use asupersync::lab::runtime::LabRuntime;
use asupersync::types::Budget;

const SEED: u64 = 0x5AB5_0000_0000_A009;

fn lab_config(seed: u64) -> LabConfig {
    LabConfig::new(seed)
        .worker_count(4)
        .entropy_seed(seed ^ 0xFFFF)
        .max_steps(100_000)
        .panic_on_leak(true)
}

/// Run one small multi-task workload to quiescence and return the
/// report. Several tasks so the SCHEDULE matters (a single task would
/// make every seed look identical and rob the determinism contract of
/// discriminating power).
fn run_workload(seed: u64, with_chaos: bool) -> asupersync::lab::runtime::LabRunReport {
    let mut config = lab_config(seed);
    if with_chaos {
        config = config.with_chaos(ChaosConfig::new(seed).with_delay_probability(0.3));
    }
    let mut runtime = LabRuntime::new(config);
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let mut task_ids = Vec::new();
    for i in 0..8u32 {
        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move { i * 2 })
            .expect("create task");
        task_ids.push(task_id);
    }
    for task_id in task_ids {
        runtime.scheduler.lock().schedule(task_id, 0);
    }
    runtime.run_until_quiescent_with_report()
}

/// CONTRACT (Epic T deterministic lab; plan §10.7): the lab runtime is
/// DETERMINISTIC — the same config replays to an identical trace
/// certificate (event hash, event count, schedule hash) and trace
/// fingerprint. RABS's entire T-epic (crash matrices, replay
/// verification) stands on this.
#[test]
fn contract_lab_replays_identically_for_the_same_seed() {
    let a = run_workload(SEED, false);
    let b = run_workload(SEED, false);
    assert!(a.quiescent && b.quiescent);
    assert_eq!(
        a.trace_certificate.event_hash,
        b.trace_certificate.event_hash
    );
    assert_eq!(
        a.trace_certificate.event_count,
        b.trace_certificate.event_count
    );
    assert_eq!(
        a.trace_certificate.schedule_hash,
        b.trace_certificate.schedule_hash
    );
    assert_eq!(a.trace_fingerprint, b.trace_fingerprint);
    assert_eq!(a.steps_total, b.steps_total);
}

/// PERTURBATION (the acceptance's second half): the determinism
/// contract has DISCRIMINATING POWER — a perturbed execution (different
/// seed, chaos delays enabled so scheduling actually varies) produces a
/// DIFFERENT certificate. If this test ever fails, the certificate
/// comparison has gone vacuous and the contract above proves nothing.
#[test]
fn contract_perturbed_execution_is_detected_not_absorbed() {
    let baseline = run_workload(SEED, true);
    let perturbed = run_workload(SEED ^ 0xDEAD_BEEF, true);
    assert!(baseline.quiescent && perturbed.quiescent);
    assert_ne!(
        (
            baseline.trace_certificate.schedule_hash,
            baseline.trace_certificate.event_hash,
        ),
        (
            perturbed.trace_certificate.schedule_hash,
            perturbed.trace_certificate.event_hash,
        ),
        "different seeds must not replay identically — the certificate \
         comparison would be vacuous"
    );
    // And chaos itself is seed-deterministic (RABS replays chaos
    // schedules in T-epic fixtures).
    let chaos_replay = run_workload(SEED, true);
    assert_eq!(
        baseline.trace_certificate.schedule_hash, chaos_replay.trace_certificate.schedule_hash,
        "chaos with the same seed must replay identically"
    );
}

/// CONTRACT (I7 obligations; G-series regions): a region-owned
/// workload runs to QUIESCENCE with zero invariant violations under
/// panic_on_leak — region close implies every child task resolved and
/// no obligation leaked. RABS's root-permit/lease/pin obligations map
/// onto exactly this guarantee.
#[test]
fn contract_region_owned_workload_quiesces_leak_free() {
    let report = run_workload(SEED, false);
    assert!(
        report.quiescent,
        "region-owned tasks must drain to quiescence"
    );
    assert!(report.steps_delta > 0, "the workload actually ran");
    assert!(
        report.invariant_violations.is_empty(),
        "invariant violations: {:?}",
        report.invariant_violations
    );
    assert!(
        report.temporal_invariant_failures.is_empty(),
        "temporal failures: {:?}",
        report.temporal_invariant_failures
    );
}

/// CONTRACT (J026 lease sequences; K-series deadlines): virtual time
/// advances EXACTLY by the requested amount and identically across
/// runtimes — RABS lease/deadline fixtures depend on nanosecond-exact,
/// reproducible virtual clocks.
#[test]
fn contract_virtual_time_is_exact_and_reproducible() {
    let mut a = LabRuntime::new(lab_config(SEED));
    let mut b = LabRuntime::new(lab_config(SEED));
    let start_a = a.now();
    let start_b = b.now();
    a.advance_time(1_000_000_000);
    b.advance_time(1_000_000_000);
    assert_eq!(
        a.now().as_nanos() - start_a.as_nanos(),
        1_000_000_000,
        "advance_time must be exact to the nanosecond"
    );
    assert_eq!(
        a.now().as_nanos() - start_a.as_nanos(),
        b.now().as_nanos() - start_b.as_nanos(),
        "virtual time must advance identically across runtimes"
    );
}
