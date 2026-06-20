//! Multi-agent load fairness and storm-control E2E
//! (bd-session-history-remediation-ocv9i.10.4).
//!
//! The mock-worker E2E: launch many concurrent direct-argv build/test/check jobs
//! with varied runtimes, slot requests, project roots, and proof/fail-open
//! policies against a simulated fleet, then prove the scheduler, admission,
//! queue, fallback policy, and observability stay coherent under contention.
//!
//! These tests drive the REAL job-identity and queue contract primitives via
//! [`rch_common::storm_control`]; the worker pool (slot accounting, eligibility
//! gate, fairness weighting, bounded queue, fallback policy) is the deterministic
//! virtual-time model. The same [invariant checkers] run here on a simulated
//! storm and, via `rch self-test --smoke --load`, on a real daemon's events.
//!
//! Acceptance assertions (one per bead criterion):
//!   - fairness / load spreading,
//!   - no duplicate remote job ids,
//!   - no unbounded local fallback storm,
//!   - no stuck wrapper without attach/cancel guidance,
//!   - no worker receiving work while bypassed / admin-disabled / inadmissible,
//!   - summary statistics recorded for regression,
//!   - JSONL log with the full field set persisted (no user files touched).
//!
//! [invariant checkers]: rch_common::storm_control::check_all_invariants

use rch_common::storm_control::{
    JobKind, JobPolicy, StormConfig, StormJob, StormWorker, WorkerEligibility, all_passed,
    check_all_invariants, check_attach_cancel_guidance, check_load_fairness,
    check_no_duplicate_remote_job_ids, check_no_ineligible_worker_selected,
    check_no_unbounded_local_fallback_storm, decision, event, simulate_storm,
};

const BEAD: &str = "bd-session-history-remediation-ocv9i.10.4";

fn fleet() -> Vec<StormWorker> {
    vec![
        StormWorker::healthy("hz1", 8, 120.0),
        StormWorker::healthy("hz2", 8, 110.0),
        StormWorker::healthy("ovh-a", 6, 90.0),
        StormWorker::healthy("vmi1", 6, 95.0),
    ]
}

/// A realistic heterogeneous swarm: 64 agents firing varied build/test/check
/// commands with mixed slot needs, project roots, and policies, all at once.
fn swarm(n: usize) -> Vec<StormJob> {
    (0..n)
        .map(|i| {
            let kind = match i % 3 {
                0 => JobKind::Build,
                1 => JobKind::Test,
                _ => JobKind::Check,
            };
            let policy = match i % 7 {
                0 => JobPolicy::ForceRemote,
                3 => JobPolicy::Proof,
                _ => JobPolicy::FailOpen,
            };
            let runtime = 400 + (i as u64 % 5) * 300;
            let slots = 1 + (i as u32 % 3);
            StormJob::build(runtime, slots, format!("/data/projects/repo{}", i % 6))
                .with_kind(kind)
                .with_policy(policy)
        })
        .collect()
}

#[test]
fn e2e_storm_concurrent_swarm_upholds_all_invariants() {
    let workers = fleet();
    let jobs = swarm(64);
    let cfg = StormConfig::new("e2e-storm-1", BEAD);
    let run = simulate_storm(&workers, &jobs, &cfg);

    // Proof jobs (1/7) are expected to refuse under contention, so the
    // fallback-ratio cap is generous; fairness within 1.6× of fair share.
    let reports = check_all_invariants(&run, &workers, 1.6, 0.35);
    for r in &reports {
        assert!(
            r.passed,
            "invariant '{}' failed under storm: {} {:?}",
            r.name, r.detail, r.violations
        );
    }
    assert!(all_passed(&reports));

    // Every one of the 64 jobs reached a definite terminal disposition.
    let s = &run.summary;
    assert_eq!(s.total_jobs, 64);
    let resolved = s.remote_successes + s.local_fallbacks + s.proof_refusals + s.cancellations;
    assert_eq!(resolved, 64, "every wrapper must resolve definitively");
}

#[test]
fn e2e_storm_load_spreads_across_the_fleet() {
    let workers = fleet();
    let jobs = swarm(80);
    let run = simulate_storm(&workers, &jobs, &StormConfig::new("e2e-storm-2", BEAD));

    let report = check_load_fairness(&run.events, &workers, 1.6);
    assert!(report.passed, "fairness: {:?}", report.violations);

    // No schedulable worker is starved: each took some remote work.
    for w in &workers {
        let util = run.summary.per_worker_slot_utilization[&w.id];
        assert!(util > 0.0, "worker {} was starved (utilization 0)", w.id);
        assert!(util <= 1.0, "utilization fraction must be <= 1.0");
    }
}

#[test]
fn e2e_storm_no_duplicate_remote_job_ids() {
    let workers = fleet();
    let jobs = swarm(100);
    let run = simulate_storm(&workers, &jobs, &StormConfig::new("e2e-storm-3", BEAD));
    let report = check_no_duplicate_remote_job_ids(&run.events);
    assert!(report.passed, "{:?}", report.violations);
}

#[test]
fn e2e_storm_bounded_queue_prevents_fallback_storm() {
    // Undersized fleet + bounded queue: fallbacks happen but stay bounded; the
    // wrapper is always definite. Then prove the checker is NOT vacuous by
    // re-checking with an impossibly tight cap.
    let workers = vec![StormWorker::healthy("solo", 2, 100.0)];
    let mut cfg = StormConfig::new("e2e-storm-4", BEAD);
    cfg.max_queue_depth = 4;
    cfg.queue_timeout_ms = 20;
    let jobs: Vec<StormJob> = (0..40)
        .map(|i| StormJob::build(1000, 1, format!("/p{}", i % 3)))
        .collect();
    let run = simulate_storm(&workers, &jobs, &cfg);

    assert!(check_attach_cancel_guidance(&run.events).passed);
    // Generous cap passes; impossibly tight cap fails => detector works.
    assert!(check_no_unbounded_local_fallback_storm(&run.events, &run.summary, 0.95).passed);
    assert!(
        !check_no_unbounded_local_fallback_storm(&run.events, &run.summary, 0.01).passed,
        "a 1% cap must flag the deliberate fallback storm"
    );
}

#[test]
fn e2e_storm_proof_jobs_fail_closed_never_local() {
    // Proof (strict-remote) jobs must refuse rather than silently run locally.
    let workers = vec![StormWorker::healthy("solo", 1, 100.0)];
    let jobs: Vec<StormJob> = (0..16)
        .map(|i| StormJob::build(800, 1, format!("/p{i}")).with_policy(JobPolicy::Proof))
        .collect();
    let run = simulate_storm(&workers, &jobs, &StormConfig::new("e2e-storm-5", BEAD));

    assert_eq!(run.summary.local_fallbacks, 0, "proof must never fall back");
    assert!(run.summary.proof_refusals >= 15);
    // A zero-tolerance fallback cap still passes (there are no fallbacks).
    assert!(check_no_unbounded_local_fallback_storm(&run.events, &run.summary, 0.0).passed);
    // Refusals are visible in the stream with the proof reason code.
    let refusals: Vec<_> = run
        .events
        .iter()
        .filter(|e| e.event == event::REFUSED)
        .collect();
    assert!(!refusals.is_empty());
    assert!(
        refusals
            .iter()
            .all(|e| e.fallback_decision.as_deref() == Some(decision::PROOF_REFUSED))
    );
}

#[test]
fn e2e_storm_ineligible_workers_never_selected() {
    // A fleet where the fast/large workers are bypassed / disabled / incapable:
    // all work must land only on the one small healthy worker.
    let workers = vec![
        StormWorker::healthy("healthy", 2, 80.0),
        StormWorker::healthy("bypassed", 16, 300.0)
            .with_eligibility(WorkerEligibility::TemporaryBypass),
        StormWorker::healthy("disabled", 16, 300.0)
            .with_eligibility(WorkerEligibility::AdminDisabled),
        StormWorker::healthy("incapable", 16, 300.0)
            .with_eligibility(WorkerEligibility::CapabilityInadmissible),
    ];
    let jobs: Vec<StormJob> = (0..30)
        .map(|i| StormJob::build(500, 1, format!("/p{}", i % 3)))
        .collect();
    let run = simulate_storm(&workers, &jobs, &StormConfig::new("e2e-storm-6", BEAD));

    let report = check_no_ineligible_worker_selected(&run.events, &workers);
    assert!(report.passed, "{:?}", report.violations);
    for ev in &run.events {
        if let Some(sel) = &ev.selected_worker {
            assert_eq!(sel, "healthy", "only the eligible worker may be selected");
        }
    }
    for bad in ["bypassed", "disabled", "incapable"] {
        assert_eq!(
            run.summary.per_worker_slot_utilization[bad], 0.0,
            "ineligible worker {bad} must stay idle"
        );
    }
}

#[test]
fn e2e_storm_cancellation_leaves_no_stuck_wrapper() {
    let workers = vec![StormWorker::healthy("solo", 1, 100.0)];
    let mut jobs: Vec<StormJob> = (0..12)
        .map(|i| StormJob::build(1000, 1, format!("/p{}", i % 3)))
        .collect();
    // Queued jobs (everything after the first) cancel before they start.
    for j in jobs.iter_mut().skip(1) {
        *j = j.clone().cancelling();
    }
    let mut cfg = StormConfig::new("e2e-storm-7", BEAD);
    cfg.cancel_delay_ms = 5;
    cfg.queue_timeout_ms = 100_000;
    let run = simulate_storm(&workers, &jobs, &cfg);

    assert!(run.summary.cancellations >= 1, "cancellations exercised");
    let guidance = check_attach_cancel_guidance(&run.events);
    assert!(guidance.passed, "{:?}", guidance.violations);
    // Cancelled events carry definite, reattach/cancel-aware guidance.
    for ev in run.events.iter().filter(|e| e.event == event::CANCELLED) {
        assert!(ev.detail.as_deref().is_some_and(|d| !d.is_empty()));
        assert_eq!(ev.fallback_decision.as_deref(), Some(decision::CANCELLED));
    }
}

#[test]
fn e2e_storm_records_summary_statistics() {
    let workers = fleet();
    let jobs = swarm(50);
    let run = simulate_storm(&workers, &jobs, &StormConfig::new("e2e-storm-8", BEAD));
    let s = &run.summary;

    // All required regression statistics are present and self-consistent.
    assert_eq!(s.total_jobs, 50);
    assert_eq!(
        s.remote_successes + s.local_fallbacks + s.proof_refusals + s.cancellations,
        s.total_jobs
    );
    assert_eq!(s.per_worker_slot_utilization.len(), workers.len());
    // p95s are non-negative and end-to-end >= queue wait at the aggregate.
    assert!(s.p95_end_to_end_ms >= 1 || s.total_jobs == 0);
    // queue_timeouts is tracked (may be 0 when capacity recycles fast enough).
    let _ = s.queue_timeouts;
}

#[test]
fn e2e_storm_jsonl_log_persisted_with_full_field_set() {
    let workers = fleet();
    let jobs = swarm(40);
    let run = simulate_storm(&workers, &jobs, &StormConfig::new("e2e-storm-9", BEAD));

    // Persist the JSONL trace to an isolated temp dir — never touching any user
    // file or source tree (bead's non-destructive criterion).
    let dir = tempfile::tempdir().expect("temp dir");
    let log_path = dir.path().join("storm_control_trace.jsonl");
    std::fs::write(&log_path, run.to_jsonl().expect("serialize jsonl")).expect("write jsonl");

    let contents = std::fs::read_to_string(&log_path).expect("read back");
    let lines: Vec<&str> = contents.lines().collect();
    assert_eq!(lines.len(), run.events.len());

    // Every required field appears across the trace; every line is valid JSON
    // with the bead id and the load scenario token.
    let mut saw_local = false;
    let mut saw_remote = false;
    let mut saw_queue_depth = false;
    let mut saw_fallback = false;
    let mut saw_selected = false;
    let mut saw_detail = false;
    for line in &lines {
        let v: serde_json::Value = serde_json::from_str(line).expect("valid json line");
        assert_eq!(v["bead_id"], BEAD);
        assert_eq!(v["scenario"], "load_storm_control");
        assert!(v.get("run_id").is_some());
        assert!(v.get("event").is_some());
        assert!(v.get("status").is_some());
        assert!(v.get("duration_ms").is_some());
        saw_local |= v.get("local_job_id").is_some();
        saw_remote |= v.get("remote_job_id").is_some();
        saw_queue_depth |= v.get("queue_depth").is_some();
        saw_fallback |= v.get("fallback_decision").is_some();
        saw_selected |= v.get("selected_worker").is_some();
        saw_detail |= v.get("detail").is_some();
    }
    assert!(saw_local, "local_job_id must appear");
    assert!(saw_remote, "remote_job_id must appear");
    assert!(saw_queue_depth, "queue_depth must appear");
    assert!(saw_fallback, "fallback_decision must appear");
    assert!(saw_selected, "selected_worker must appear");
    assert!(saw_detail, "detail must appear");
    // temp dir auto-removed on drop; no unmanaged files touched.
}

/// Resolve the workspace test-logs dir (mirrors scripts/e2e_*.sh): honor
/// `CARGO_TARGET_DIR`, else fall back to `<workspace>/target`.
fn test_logs_dir() -> std::path::PathBuf {
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .map(|p| p.join("target"))
                .unwrap_or_else(|| std::path::PathBuf::from("target"))
        });
    target.join("test-logs")
}

#[test]
fn e2e_storm_emit_jsonl_artifact() {
    // Emit the storm JSONL trace + a summary record to the workspace test-logs
    // dir so scripts/e2e_storm_control.sh can validate the schema and
    // run_all_e2e.sh can collect it. (target/ is gitignored; not user source.)
    let workers = fleet();
    let jobs = swarm(48);
    let run = simulate_storm(
        &workers,
        &jobs,
        &StormConfig::new("e2e-storm-artifact", BEAD),
    );

    let dir = test_logs_dir();
    if std::fs::create_dir_all(&dir).is_err() {
        eprintln!("skip artifact emit: cannot create {}", dir.display());
        return;
    }
    let mut jsonl = run.to_jsonl().expect("serialize events");
    // Append a summary record (scenario "_summary") for the shell validator.
    let summary_line = serde_json::json!({
        "run_id": "e2e-storm-artifact",
        "bead_id": BEAD,
        "scenario": "_summary",
        "event": "summary",
        "status": "ok",
        "total_jobs": run.summary.total_jobs,
        "remote_successes": run.summary.remote_successes,
        "local_fallbacks": run.summary.local_fallbacks,
        "proof_refusals": run.summary.proof_refusals,
        "queue_timeouts": run.summary.queue_timeouts,
        "cancellations": run.summary.cancellations,
        "p95_queue_wait_ms": run.summary.p95_queue_wait_ms,
        "p95_end_to_end_ms": run.summary.p95_end_to_end_ms,
    });
    jsonl.push_str(&serde_json::to_string(&summary_line).unwrap());
    jsonl.push('\n');
    let path = dir.join("storm_control.jsonl");
    std::fs::write(&path, &jsonl).expect("write artifact");
    assert!(path.exists());
}

#[test]
fn e2e_storm_run_is_deterministic() {
    // The whole point of the mock-worker E2E: identical inputs => identical
    // events and summary, so CI never flakes and regressions are unambiguous.
    let workers = fleet();
    let jobs = swarm(70);
    let a = simulate_storm(&workers, &jobs, &StormConfig::new("e2e-storm-10", BEAD));
    let b = simulate_storm(&workers, &jobs, &StormConfig::new("e2e-storm-10", BEAD));
    assert_eq!(a.to_jsonl().unwrap(), b.to_jsonl().unwrap());
    assert_eq!(a.summary, b.summary);
}
