//! G012 acceptance (bead rabs-root-4pidu.25.12): THE LAB
//! CANCELLATION-AT-EVERY-AWAIT SUITE.
//!
//! Deterministic scenarios that cancel at EVERY await point across the
//! currently-covered paths and verify BOUNDED CLEANUP and OBLIGATION
//! RESOLUTION:
//!
//! - **Injection leg** (`asupersync::lab::instrumented_future`): a
//!   subsystem-shaped flow — opens the CLEANUP obligation pair
//!   (`SandboxCleanup`, `ProcessGroupDrain`) exactly like
//!   `daemon_runtime::subsystem_body`, awaits across stage boundaries —
//!   is cancelled at EVERY recorded await point (`AllPoints`). The law
//!   under test: whichever way the flow ends, `may_close_region()` is
//!   satisfied — cleanup resolves on the success path AND via the
//!   Drop-guard backstop on every cancellation path (the RAII pattern
//!   `RootPermit`/`ManagedCargoLaunch` already model). A cancellation
//!   landing BEFORE the body's first poll means the flow never
//!   constructed: nothing was opened, nothing is owed.
//! - **Live-lab leg** (`run_async_under_lab_with_config`): the same
//!   flow shape under the REAL pinned lab runtime with a REAL `Cx`
//!   (checkpoints, seeded scheduling) — asserting quiescence, zero
//!   invariant violations, clean oracle report, and seed-determinism /
//!   seed-discrimination of the trace certificate.
//!
//! ## Honestly DEFERRED paths (recorded, not silently skipped)
//!
//! - `rabs-cas` transfer/publication/materialization/serving are fully
//!   SYNCHRONOUS today (zero `.await` sites): cancellation-at-every-
//!   await is VACUOUS there until those paths go async. Their failure-
//!   path staging-file cleanup is sync-discipline territory
//!   (materialization removes staging on every branch).
//! - `rabs-wkr` session_loop has multiple awaits but NO obligation
//!   ledger yet (temp/spill dirs are never cleaned on any exit path) —
//!   wiring worker obligations is prerequisite work before its loop can
//!   join this suite meaningfully.
//! - `rabsd` edge per-connection cancellation needs real UDS sockets
//!   (wall-clock, Linux-gated); its detach-without-abort semantics
//!   deserve their own bead.
//!
//! The suite extends automatically as those paths land: add a leg per
//! path, keep the assertion shape identical.

use asupersync::cx::Cx;
use asupersync::lab::config::LabConfig;
use asupersync::lab::instrumented_future::{
    CancellationInjector, InjectionOutcome, InjectionReport, InjectionRunner, InjectionStrategy,
    InstrumentedFuture, InstrumentedPollResult,
};
use asupersync::lab::runtime::run_async_under_lab_with_config;
use asupersync::runtime::yield_now;
use parking_lot::Mutex;
use rabs_asupersync::obligations::{ObligationKind, ObligationSet};
use std::sync::Arc;

/// How many cooperative stage boundaries the fixture flow has. Each is
/// one await point the injector can land on; plus the implicit final
/// completing poll.
const STAGES: usize = 3;

/// Shared observable state of one flow run: what the grader asserts on
/// AFTER the runner finished driving (or dropped) the future.
#[derive(Debug, Default)]
struct FlowWitness {
    /// The flow body was polled at least once: `SubsystemFlow` was
    /// constructed and its CLEANUP obligations were OPENED. This is
    /// distinct from reaching a stage — the first stage boundary is
    /// awaited BEFORE `advance()` runs, so a flow cancelled at its
    /// second poll has opened obligations but reached no stage.
    opened: bool,
    /// Stages actually reached (1-based).
    stages_reached: Vec<usize>,
    /// Cleanup obligations were resolved by NORMAL completion.
    resolved_on_completion: bool,
    /// Cleanup obligations were resolved by the Drop-guard backstop.
    resolved_on_drop: bool,
}

impl FlowWitness {
    /// The flow STARTED (body polled at least once: obligations opened).
    ///
    /// Keyed on `opened`, not on `stages_reached`: the instrumented
    /// wrapper counts an await point BEFORE polling the inner future,
    /// so injection at point N tears down a flow that was polled N-1
    /// times. At N == 2 that flow constructed (obligations opened) and
    /// parked on its first stage boundary without ever advancing — its
    /// drop-resolution is the backstop doing its job, not a phantom.
    fn started(&self) -> bool {
        self.opened
    }

    fn closed_cleanly(&self) -> bool {
        self.resolved_on_completion || self.resolved_on_drop
    }
}

/// The canonical subsystem discipline under test: CLEANUP obligations
/// open at construction, resolved at normal completion OR by the Drop
/// backstop — `may_close_region()` holds on EVERY ending.
#[derive(Debug)]
struct SubsystemFlow {
    witness: Arc<Mutex<FlowWitness>>,
    obligations: ObligationSet,
    stage: usize,
}

impl SubsystemFlow {
    fn new(witness: Arc<Mutex<FlowWitness>>) -> Self {
        let mut obligations = ObligationSet::default();
        obligations.open(ObligationKind::SandboxCleanup);
        obligations.open(ObligationKind::ProcessGroupDrain);
        witness.lock().opened = true;
        Self {
            witness,
            obligations,
            stage: 0,
        }
    }

    fn advance(&mut self) {
        self.stage += 1;
        self.witness.lock().stages_reached.push(self.stage);
    }

    fn finish(mut self) -> &'static str {
        let _ = self.obligations.resolve(ObligationKind::SandboxCleanup);
        let _ = self.obligations.resolve(ObligationKind::ProcessGroupDrain);
        self.witness.lock().resolved_on_completion = true;
        "completed"
    }
}

impl Drop for SubsystemFlow {
    fn drop(&mut self) {
        // THE bounded-cleanup backstop: cancellation in Rust IS drop,
        // so the CLEANUP pair resolves here on every torn-down ending.
        // ATTEMPT_SUCCESS-class obligations would deliberately stay
        // open (named by may_close_region) — this fixture opens only
        // the CLEANUP pair, matching the obligations.rs cancelled-path
        // model proof.
        let _ = self.obligations.resolve(ObligationKind::SandboxCleanup);
        let _ = self.obligations.resolve(ObligationKind::ProcessGroupDrain);
        self.witness.lock().resolved_on_drop = true;
    }
}

/// A stage boundary that is genuinely `Pending` exactly once, so the
/// instrumented wrapper records one await point per boundary without
/// needing an executor.
fn yield_once() -> YieldOnce {
    YieldOnce { yielded: false }
}

struct YieldOnce {
    yielded: bool,
}

impl Future for YieldOnce {
    type Output = ();
    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<()> {
        if self.yielded {
            std::task::Poll::Ready(())
        } else {
            self.yielded = true;
            std::task::Poll::Pending
        }
    }
}

/// The flow future: STAGES stage boundaries then normal completion.
async fn subsystem_flow_future(witness: Arc<Mutex<FlowWitness>>) -> &'static str {
    let mut flow = SubsystemFlow::new(witness);
    for _ in 0..STAGES {
        yield_once().await;
        flow.advance();
    }
    flow.finish()
}

/// Drive an instrumented future to completion with the noop waker
/// (same discipline as the upstream runner's own poller).
fn poll_to_result<F: Future>(future: InstrumentedFuture<F>) -> InstrumentedPollResult<F::Output> {
    use std::task::{Context, Poll, Waker};
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut pinned = Box::pin(future);
    loop {
        match pinned.as_mut().poll(&mut cx) {
            Poll::Ready(output) => return output,
            Poll::Pending => {}
        }
    }
}

/// Shared slot so the poll closure can grade the run it just drove:
/// `build_flow` publishes each run's witness here before polling.
type WitnessSlot = Arc<Mutex<Option<Arc<Mutex<FlowWitness>>>>>;

/// Grade one finished run:
/// - never-started flow → nothing owed, nothing resolved (phantom
///   cleanup would be a bug);
/// - started → EXACTLY ONE resolution path fired and the region closes;
/// - never neither-path nor both-paths.
fn grade(witness: &Mutex<FlowWitness>, point_label: &str) -> InjectionOutcome {
    let w = witness.lock();
    if !w.started() {
        assert!(
            !w.resolved_on_completion && !w.resolved_on_drop,
            "{point_label}: phantom cleanup for a never-started flow ({w:?})"
        );
        return InjectionOutcome::Success;
    }
    if !w.closed_cleanly() {
        return InjectionOutcome::AssertionFailed(format!(
            "{point_label}: region could not close cleanly ({w:?})"
        ));
    }
    if w.resolved_on_completion && w.resolved_on_drop {
        return InjectionOutcome::AssertionFailed(format!(
            "{point_label}: completed AND drop-resolved — double resolve"
        ));
    }
    InjectionOutcome::Success
}

#[test]
fn g012_recording_discovers_every_stage_boundary_as_an_await_point() {
    let slot: WitnessSlot = Arc::new(Mutex::new(None));
    let mut runner = InjectionRunner::new(0xA009);
    let report: InjectionReport = runner.run_with_injection(
        InjectionStrategy::Never,
        |injector: Arc<CancellationInjector>| {
            let witness = Arc::new(Mutex::new(FlowWitness::default()));
            *slot.lock() = Some(witness.clone());
            let inner = subsystem_flow_future(witness);
            InstrumentedFuture::new(inner, injector)
        },
        |future| {
            let _outcome = poll_to_result(future);
            let witness = slot.lock().take();
            match witness {
                Some(w) => grade(&w, "recording"),
                None => InjectionOutcome::AssertionFailed("no witness published".into()),
            }
        },
    );
    assert_eq!(
        report.total_await_points,
        STAGES + 1,
        "one await point per stage boundary plus the completing poll"
    );
    assert_eq!(report.tests_run, 0, "recording mode never injects");
}

#[test]
fn g012_cancel_at_every_await_still_resolves_cleanup_before_close() {
    const SEED: u64 = 0x6A12_0000_0000_C7E1;
    let slot: WitnessSlot = Arc::new(Mutex::new(None));
    let mut runner = InjectionRunner::new(SEED);
    let report: InjectionReport = runner.run_with_injection(
        InjectionStrategy::AllPoints,
        |injector: Arc<CancellationInjector>| {
            let witness = Arc::new(Mutex::new(FlowWitness::default()));
            *slot.lock() = Some(witness.clone());
            let inner = subsystem_flow_future(witness);
            InstrumentedFuture::new(inner, injector)
        },
        |future| {
            let _ = poll_to_result(future);
            let witness = slot.lock().take();
            match witness {
                Some(w) => grade(&w, "injected"),
                None => InjectionOutcome::AssertionFailed("no witness published".into()),
            }
        },
    );

    assert_eq!(
        report.tests_run, report.total_await_points,
        "AllPoints must exercise every recorded point"
    );
    assert!(
        report.tests_run >= STAGES,
        "the fixture must have real await-point coverage"
    );
    assert!(
        report.all_passed(),
        "cancellation handling failed at some await point: {report:?}"
    );

    // Explicit per-point sweep naming the exact await sequence that
    // would leak (the report aggregates; this localizes).
    for point in 1..=report.total_await_points as u64 {
        let witness = Arc::new(Mutex::new(FlowWitness::default()));
        let injector = CancellationInjector::inject_at(point);
        let inner = subsystem_flow_future(witness.clone());
        let outcome = poll_to_result(InstrumentedFuture::new(inner, injector));

        let w = witness.lock();
        match outcome {
            InstrumentedPollResult::CancellationInjected(seq) => {
                assert_eq!(seq, point);
                if w.started() {
                    assert!(
                        w.resolved_on_drop && !w.resolved_on_completion,
                        "await point {point}: started flow must resolve via the \
                         drop backstop only ({w:?})"
                    );
                }
            }
            InstrumentedPollResult::Inner(_) => {
                assert!(
                    w.started() && w.resolved_on_completion,
                    "await point {point}: completed flow must have run to the end"
                );
            }
        }
        assert!(
            w.closed_cleanly() || !w.started(),
            "await point {point}: started region could not close cleanly"
        );
    }
}

#[test]
fn g012_live_lab_runtime_quiesces_leak_free_with_clean_oracles() {
    const SEED: u64 = 0x6A12_0000_0000_C7E2;
    let config = LabConfig::new(SEED)
        .worker_count(4)
        .entropy_seed(SEED ^ 0xC1EA)
        .max_steps(100_000)
        .panic_on_leak(true);

    let (outcome, report) = run_async_under_lab_with_config(config, |cx: Cx| async move {
        // Three subsystem-shaped flows under the REAL Cx: open CLEANUP
        // obligations, cross a checkpoint each stage, resolve, close.
        let mut regions_closed_cleanly = 0usize;
        for _ in 0..3 {
            let mut obligations = ObligationSet::default();
            obligations.open(ObligationKind::SandboxCleanup);
            obligations.open(ObligationKind::ProcessGroupDrain);
            for _ in 0..STAGES {
                // A REAL cancellation checkpoint: Err(Cancelled) would
                // route to the Drop/cleanup path in production code.
                let _ = cx.checkpoint();
                obligations.resolve(ObligationKind::SandboxCleanup).ok();
                obligations.resolve(ObligationKind::ProcessGroupDrain).ok();
                obligations = ObligationSet::default();
                obligations.open(ObligationKind::SandboxCleanup);
                obligations.open(ObligationKind::ProcessGroupDrain);
            }
            let _ = cx.checkpoint();
            let _ = obligations.resolve(ObligationKind::SandboxCleanup);
            let _ = obligations.resolve(ObligationKind::ProcessGroupDrain);
            assert!(obligations.may_close_region().is_ok());
            regions_closed_cleanly += 1;
        }
        regions_closed_cleanly
    });

    assert_eq!(outcome, 3, "all subsystem regions closed cleanly");
    assert!(report.quiescent, "lab runtime reached quiescence");
    assert!(
        report.invariant_violations.is_empty(),
        "no invariant violations: {:?}",
        report.invariant_violations
    );
    assert!(
        report.oracle_report.all_passed(),
        "oracles clean: {:?}",
        report.oracle_report
    );
}

#[test]
fn g012_shutdown_race_matrix_is_seed_deterministic_and_discriminating() {
    // Same workload: same seed MUST replay to an identical certificate
    // (bounded cleanup is reproducible); different seed MUST produce a
    // different one (the matrix has discriminating power — a vacuous
    // always-equal check would hide scheduler-dependent leaks).
    //
    // The seed reaches the lab ONLY through its ready-task pick
    // (`pop_for_worker(worker_hint, rng_value, ..)`): it chooses among
    // tasks that are runnable AT THE SAME STEP. A single task with
    // synchronous checkpoints never offers that choice, so its
    // certificate is legitimately seed-invariant and proves nothing.
    // The matrix therefore runs FLOWS concurrent subsystem-shaped
    // flows that each yield at every stage boundary, so the seeded
    // interleaving of their cleanup/resolution events is what the
    // certificate captures.
    const FLOWS: usize = 4;
    let certificates_for = |seed: u64| {
        let (closed, report) = run_async_under_lab_with_config(
            LabConfig::new(seed)
                .worker_count(4)
                .entropy_seed(seed.rotate_left(17))
                .max_steps(100_000),
            |cx: Cx| async move {
                let mut handles = Vec::with_capacity(FLOWS);
                for _ in 0..FLOWS {
                    let handle = cx
                        .spawn(|child: Cx| async move {
                            let mut obligations = ObligationSet::default();
                            obligations.open(ObligationKind::DiagnosticStream);
                            obligations.open(ObligationKind::ProcessGroupDrain);
                            for _ in 0..STAGES {
                                let _ = child.checkpoint();
                                yield_now().await;
                            }
                            let _ = child.checkpoint();
                            let _ = obligations.resolve(ObligationKind::DiagnosticStream);
                            let _ = obligations.resolve(ObligationKind::ProcessGroupDrain);
                            obligations.may_close_region().expect("clean close");
                        })
                        .expect("lab Cx must be able to spawn concurrent flows");
                    handles.push(handle);
                }
                let mut closed = 0usize;
                for handle in &mut handles {
                    handle
                        .join(&cx)
                        .await
                        .expect("every concurrent flow completes");
                    closed += 1;
                }
                closed
            },
        );
        assert_eq!(closed, FLOWS, "every concurrent flow closed cleanly");
        assert!(report.quiescent, "lab runtime reached quiescence");
        (
            report.trace_certificate.event_hash,
            report.trace_certificate.schedule_hash,
        )
    };

    let s = 0x6A12_DEAD_BEEF_0001;
    assert_eq!(
        certificates_for(s),
        certificates_for(s),
        "same seed replays identically"
    );
    assert_ne!(
        certificates_for(s),
        certificates_for(s ^ 0xFFFF_FFFF_FFFF_FFFF),
        "different seeds must schedule differently"
    );
}
