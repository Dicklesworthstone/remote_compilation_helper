//! T033: the plane-specific grant accounting matrix (bead I023; risk
//! R102).
//!
//! I023 ships five fixtures, one per rule, and they are good ones —
//! frontier grants admit only on the frontier plane, whole-command
//! derives execution from the selected worker, coordinated-local from
//! edge pressure alone, fail-open refuses both families, and the
//! frontier plane admits no execution at all. None of that is redone.
//!
//! What they are not is a MATRIX. Each fixture picks the input
//! combination that demonstrates its own rule, which leaves most cells
//! of the cross-product unvisited — and the interesting conflations
//! live in the cells nobody picked. Two examples that were untested:
//!
//! - `admit_execution(WholeCommand, None, Some(n))` — no worker
//!   selected, but edge-pressure information happens to be at hand.
//!   "We could not select a worker, but we do know the local pressure,
//!   so use that" is the single most natural way to reintroduce R102,
//!   and it would have passed every existing fixture.
//! - `admit_execution(WholeCommand, Some(w), Some(p))` — both sources
//!   present. If the worker-derived answer were ever influenced by `p`,
//!   the planes would have conflated silently in the one case where
//!   both numbers are real.
//!
//! So this enumerates every (plane x worker-slots x edge-pressure)
//! cell, states the expected outcome for each from the stated rules,
//! and then asserts the property those cells add up to: **a plane's
//! answer never depends on the input that plane does not own.** That
//! is R102 as a property rather than as a list of examples.

use rabs_scheduler::grant_planes::{
    FrontierGrant, GrantPlane, PlaneAdmission, PlaneRefusal, admit_execution, admit_frontier,
};

const PLANES: [GrantPlane; 4] = [
    GrantPlane::LocalCargoRemoteChildren,
    GrantPlane::WholeCommand,
    GrantPlane::CoordinatedLocal,
    GrantPlane::UncoordinatedFailOpen,
];

/// Every worker-selection state worth distinguishing: absent, selected
/// with nothing free, selected with capacity.
const WORKER_SLOTS: [Option<u32>; 3] = [None, Some(0), Some(8)];

/// Every edge-pressure state: unknown, measured zero, measured room.
const EDGE_PRESSURE: [Option<u32>; 3] = [None, Some(0), Some(5)];

/// The expected execution outcome for one cell, derived from the rules
/// rather than from the implementation:
///
/// - fail-open carries no fleet grant, ever, whatever is observed;
/// - the frontier plane admits no execution of any kind;
/// - whole-command admits exactly the SELECTED WORKER's slots, or
///   refuses when no worker is selected — edge pressure is not an
///   input it owns;
/// - coordinated-local admits exactly the measured edge pressure, with
///   unknown pressure showing as zero rather than being invented —
///   worker slots are not an input it owns.
fn expected_execution(
    plane: GrantPlane,
    worker: Option<u32>,
    pressure: Option<u32>,
) -> Result<PlaneAdmission, PlaneRefusal> {
    match plane {
        GrantPlane::UncoordinatedFailOpen => Err(PlaneRefusal::FailOpenCarriesNoFleetGrant),
        GrantPlane::LocalCargoRemoteChildren => {
            Err(PlaneRefusal::EdgePressureGrantWrongPlane { plane })
        }
        GrantPlane::WholeCommand => match worker {
            Some(cpu_slots) => Ok(PlaneAdmission::WorkerExecution { cpu_slots }),
            None => Err(PlaneRefusal::ExecutionGrantBeforeWorkerSelection),
        },
        GrantPlane::CoordinatedLocal => Ok(PlaneAdmission::EdgePressureExecution {
            cpu_slots: pressure.unwrap_or(0),
        }),
    }
}

#[test]
fn t033_every_execution_cell_matches_its_plane_s_own_source_of_truth() {
    let mut cells = 0usize;
    for plane in PLANES {
        for worker in WORKER_SLOTS {
            for pressure in EDGE_PRESSURE {
                assert_eq!(
                    admit_execution(plane, worker, pressure),
                    expected_execution(plane, worker, pressure),
                    "cell (plane={plane:?}, worker={worker:?}, pressure={pressure:?}) \
                     did not match the rule for its plane"
                );
                cells += 1;
            }
        }
    }
    assert_eq!(
        cells,
        PLANES.len() * WORKER_SLOTS.len() * EDGE_PRESSURE.len(),
        "the matrix must actually visit every cell"
    );
}

#[test]
fn t033_no_plane_s_answer_depends_on_the_input_it_does_not_own() {
    // R102 stated as the property the matrix adds up to. Vary ONLY the
    // input a plane has no claim on and require the answer to be
    // identical — this is what "planes never conflate" means, and it
    // holds for refusals as well as admissions.
    for plane in PLANES {
        // Whole-command owns worker selection, not edge pressure.
        for worker in WORKER_SLOTS {
            let answers: Vec<_> = EDGE_PRESSURE
                .iter()
                .map(|p| admit_execution(plane, worker, *p))
                .collect();
            if plane != GrantPlane::CoordinatedLocal {
                assert!(
                    answers.windows(2).all(|w| w[0] == w[1]),
                    "{plane:?} with worker={worker:?} changed its answer when only edge \
                     pressure varied: {answers:?}"
                );
            }
        }
        // Coordinated-local owns edge pressure, not worker selection.
        for pressure in EDGE_PRESSURE {
            let answers: Vec<_> = WORKER_SLOTS
                .iter()
                .map(|w| admit_execution(plane, *w, pressure))
                .collect();
            if plane != GrantPlane::WholeCommand {
                assert!(
                    answers.windows(2).all(|w| w[0] == w[1]),
                    "{plane:?} with pressure={pressure:?} changed its answer when only \
                     worker selection varied: {answers:?}"
                );
            }
        }
    }
}

#[test]
fn t033_a_missing_worker_is_never_rescued_by_edge_pressure() {
    // The cell that matters most, called out because it is the single
    // most natural way to reintroduce R102: worker selection failed,
    // but local pressure is known, so use it. Every existing fixture
    // would have passed an implementation that did this.
    for pressure in [None, Some(0), Some(5), Some(u32::MAX)] {
        assert_eq!(
            admit_execution(GrantPlane::WholeCommand, None, pressure),
            Err(PlaneRefusal::ExecutionGrantBeforeWorkerSelection),
            "pressure={pressure:?} must not substitute for a selected worker"
        );
    }
    // And a selected worker with NOTHING free admits zero slots rather
    // than falling back to pressure: zero is an answer, not a failure.
    assert_eq!(
        admit_execution(GrantPlane::WholeCommand, Some(0), Some(5)),
        Ok(PlaneAdmission::WorkerExecution { cpu_slots: 0 })
    );
}

#[test]
fn t033_every_frontier_cell_admits_only_on_the_frontier_plane() {
    // The frontier family is the other half of the accounting. Caps are
    // varied so the admitted grant is checked to carry the caller's
    // policy rather than a constant, and every refusing plane is named.
    for (max_live_graphs, max_submitted_requests) in [(0, 0), (1, 1), (4, 16), (u32::MAX, u32::MAX)]
    {
        assert_eq!(
            admit_frontier(
                GrantPlane::LocalCargoRemoteChildren,
                max_live_graphs,
                max_submitted_requests
            ),
            Ok(PlaneAdmission::Frontier(FrontierGrant {
                max_live_graphs,
                max_submitted_requests,
            })),
            "the frontier plane must admit exactly the caps it was given"
        );
        for plane in [GrantPlane::WholeCommand, GrantPlane::CoordinatedLocal] {
            assert_eq!(
                admit_frontier(plane, max_live_graphs, max_submitted_requests),
                Err(PlaneRefusal::FrontierGrantOffFrontierPlane { plane }),
                "{plane:?} derives resources from its own source, not a frontier grant"
            );
        }
        assert_eq!(
            admit_frontier(
                GrantPlane::UncoordinatedFailOpen,
                max_live_graphs,
                max_submitted_requests
            ),
            Err(PlaneRefusal::FailOpenCarriesNoFleetGrant),
            "fail-open refuses the frontier family by its OWN rule, not the off-plane one"
        );
    }
}

#[test]
fn t033_fail_open_refuses_both_families_under_every_observation() {
    // "Uncoordinated fallback reuses no stale fleet grant", exhaustively
    // rather than by example. No combination of real-looking
    // observations mints a grant, and the refusal always names fail-open
    // rather than a plane-mismatch — the distinction matters, because a
    // plane-mismatch reads as "ask elsewhere" while this one means "run
    // local, carrying nothing".
    for worker in WORKER_SLOTS {
        for pressure in EDGE_PRESSURE {
            assert_eq!(
                admit_execution(GrantPlane::UncoordinatedFailOpen, worker, pressure),
                Err(PlaneRefusal::FailOpenCarriesNoFleetGrant),
                "worker={worker:?} pressure={pressure:?} must not mint a fleet grant"
            );
        }
    }
    for caps in [(0, 0), (4, 16), (u32::MAX, u32::MAX)] {
        assert_eq!(
            admit_frontier(GrantPlane::UncoordinatedFailOpen, caps.0, caps.1),
            Err(PlaneRefusal::FailOpenCarriesNoFleetGrant)
        );
    }
}

#[test]
fn t033_the_matrix_is_not_satisfied_by_refusing_everything() {
    // The control. Every assertion above is about refusals or about
    // grants derived from the right source; a implementation that
    // refused every request would satisfy most of them. So: each plane
    // that is SUPPOSED to admit something does, and the admission
    // carries a real value rather than a placeholder.
    assert!(matches!(
        admit_frontier(GrantPlane::LocalCargoRemoteChildren, 4, 16),
        Ok(PlaneAdmission::Frontier(_))
    ));
    assert_eq!(
        admit_execution(GrantPlane::WholeCommand, Some(8), None),
        Ok(PlaneAdmission::WorkerExecution { cpu_slots: 8 })
    );
    assert_eq!(
        admit_execution(GrantPlane::CoordinatedLocal, None, Some(5)),
        Ok(PlaneAdmission::EdgePressureExecution { cpu_slots: 5 })
    );
}
