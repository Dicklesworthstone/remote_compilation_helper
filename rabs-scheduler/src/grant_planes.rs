//! Plane-specific frontier vs execution grants (bead I023; risk R102;
//! acceptance T033).
//!
//! A Cargo invocation runs in ONE of four planes, and each plane
//! admits exactly ITS OWN kind of grant — the two grant families
//! never imply one another:
//!
//! - `LocalCargoRemoteChildren`: a SUBMISSION-FRONTIER grant bounding
//!   live graphs + submitted requests. It bounds what may be IN
//!   FLIGHT, and says NOTHING about worker CPU — "local Cargo holds a
//!   graph token" is never evidence that an execution slot exists;
//! - `WholeCommand`: execution resources derived from the SELECTED
//!   WORKER — no worker selection, no grant;
//! - `CoordinatedLocal`: execution resources from EDGE PRESSURE
//!   admission — not from any frontier;
//! - `UncoordinatedFailOpen`: deliberately NO fleet grant at all — a
//!   fail-open run must never carry a stale fleet claim.
//!
//! The refusal variants name the exact conflation attempted, so a
//! T033 fixture can pin each one separately.

/// The plane a Cargo invocation runs in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantPlane {
    /// Local Cargo coordinating remote children: frontier-granted.
    LocalCargoRemoteChildren,
    /// One whole command dispatched to a worker: worker-derived.
    WholeCommand,
    /// Local execution under edge pressure coordination.
    CoordinatedLocal,
    /// Uncoordinated fail-open: local, carrying NO fleet grant.
    UncoordinatedFailOpen,
}

/// A submission-frontier grant: bounds how many live graphs and how
/// much submitted-request volume the plane may hold. Deliberately has
/// NO cpu/slot field — there is nothing here an execution decision
/// can consume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrontierGrant {
    /// Maximum simultaneously-live dependency graphs.
    pub max_live_graphs: u32,
    /// Maximum submitted (not yet resolved) requests in flight.
    pub max_submitted_requests: u32,
}

/// What a plane admitted (or deliberately refused to invent).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaneAdmission {
    /// The plane's own submission-frontier grant.
    Frontier(FrontierGrant),
    /// Worker-derived execution resources (CPU slots).
    WorkerExecution {
        /// Admitted CPU slots from the selected worker.
        cpu_slots: u32,
    },
    /// Edge-pressure-derived local execution resources.
    EdgePressureExecution {
        /// Admitted CPU slots from edge pressure accounting.
        cpu_slots: u32,
    },
    /// Deliberately nothing: the uncoordinated fail-open plane runs
    /// WITHOUT a fleet grant rather than carrying a stale one.
    NoFleetGrant,
}

/// Typed conflation refusals — each names the exact rule violated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaneRefusal {
    /// An execution grant was requested on the frontier plane without
    /// a selected worker: a graph token does not imply CPU (R102).
    ExecutionGrantBeforeWorkerSelection,
    /// A frontier grant was requested off the frontier plane:
    /// whole-command derives resources from the WORKER instead.
    FrontierGrantOffFrontierPlane {
        /// The plane that asked for it.
        plane: GrantPlane,
    },
    /// Edge-pressure execution requested OFF the coordinated-local
    /// plane.
    EdgePressureGrantWrongPlane {
        /// The plane that asked for it.
        plane: GrantPlane,
    },
    /// The uncoordinated fail-open plane asked for ANY fleet grant:
    /// fail-open means run local with no stale fleet claims.
    FailOpenCarriesNoFleetGrant,
}

/// Admit the plane's SUBMISSION-FRONTIER grant with explicit policy
/// caps. Legal ONLY on [`GrantPlane::LocalCargoRemoteChildren`].
///
/// # Errors
/// Typed [`PlaneRefusal`] on every other plane.
pub fn admit_frontier(
    plane: GrantPlane,
    max_live_graphs: u32,
    max_submitted_requests: u32,
) -> Result<PlaneAdmission, PlaneRefusal> {
    match plane {
        GrantPlane::LocalCargoRemoteChildren => Ok(PlaneAdmission::Frontier(FrontierGrant {
            max_live_graphs,
            max_submitted_requests,
        })),
        GrantPlane::WholeCommand => Err(PlaneRefusal::FrontierGrantOffFrontierPlane {
            plane: GrantPlane::WholeCommand,
        }),
        GrantPlane::CoordinatedLocal => Err(PlaneRefusal::FrontierGrantOffFrontierPlane {
            plane: GrantPlane::CoordinatedLocal,
        }),
        GrantPlane::UncoordinatedFailOpen => Err(PlaneRefusal::FailOpenCarriesNoFleetGrant),
    }
}

/// Admit the plane's EXECUTION resource grant. Each plane has its own
/// source of truth — worker selection for whole-command, edge
/// pressure for coordinated local — and NONE of them accepts a
/// frontier grant as evidence.
///
/// # Errors
/// Typed [`PlaneRefusal`] naming the missing source or wrong plane.
pub fn admit_execution(
    plane: GrantPlane,
    selected_worker_slots: Option<u32>,
    edge_pressure_cpu: Option<u32>,
) -> Result<PlaneAdmission, PlaneRefusal> {
    match plane {
        GrantPlane::WholeCommand => match selected_worker_slots {
            Some(cpu_slots) => Ok(PlaneAdmission::WorkerExecution { cpu_slots }),
            // THE R102 headline: no worker selection, no execution
            // grant — holding a frontier grant changes nothing,
            // because this function never even sees one.
            None => Err(PlaneRefusal::ExecutionGrantBeforeWorkerSelection),
        },
        GrantPlane::CoordinatedLocal => match edge_pressure_cpu {
            Some(cpu_slots) if cpu_slots > 0 => {
                Ok(PlaneAdmission::EdgePressureExecution { cpu_slots })
            }
            _ => Ok(PlaneAdmission::EdgePressureExecution { cpu_slots: 0 }),
        },
        GrantPlane::LocalCargoRemoteChildren => {
            Err(PlaneRefusal::EdgePressureGrantWrongPlane { plane })
        }
        GrantPlane::UncoordinatedFailOpen => Err(PlaneRefusal::FailOpenCarriesNoFleetGrant),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frontier_grants_admit_only_on_the_local_cargo_plane() {
        assert!(matches!(
            admit_frontier(GrantPlane::LocalCargoRemoteChildren, 4, 16),
            Ok(PlaneAdmission::Frontier(FrontierGrant {
                max_live_graphs: 4,
                max_submitted_requests: 16,
            }))
        ));
        // Every other plane refuses, each naming its own reason.
        assert_eq!(
            admit_frontier(GrantPlane::WholeCommand, 4, 16),
            Err(PlaneRefusal::FrontierGrantOffFrontierPlane {
                plane: GrantPlane::WholeCommand
            })
        );
        assert_eq!(
            admit_frontier(GrantPlane::CoordinatedLocal, 4, 16),
            Err(PlaneRefusal::FrontierGrantOffFrontierPlane {
                plane: GrantPlane::CoordinatedLocal
            })
        );
        assert_eq!(
            admit_frontier(GrantPlane::UncoordinatedFailOpen, 4, 16),
            Err(PlaneRefusal::FailOpenCarriesNoFleetGrant)
        );
    }

    #[test]
    fn whole_command_derives_execution_from_the_worker_never_a_frontier() {
        // Selected worker present: worker-derived slots.
        assert_eq!(
            admit_execution(GrantPlane::WholeCommand, Some(8), None),
            Ok(PlaneAdmission::WorkerExecution { cpu_slots: 8 })
        );
        // THE headline conflation: no worker selection yet. A caller
        // may hold the biggest frontier grant imaginable — this API
        // never even receives it, so a graph token cannot be traded
        // for CPU (R102).
        assert_eq!(
            admit_execution(GrantPlane::WholeCommand, None, None),
            Err(PlaneRefusal::ExecutionGrantBeforeWorkerSelection)
        );
    }

    #[test]
    fn coordinated_local_admits_from_edge_pressure_alone() {
        assert_eq!(
            admit_execution(GrantPlane::CoordinatedLocal, Some(4), Some(2)),
            Ok(PlaneAdmission::EdgePressureExecution { cpu_slots: 2 }),
            "edge pressure decides; an unused worker selection is irrelevant"
        );
        // Zero pressure admits ZERO slots — visible, not invented.
        assert_eq!(
            admit_execution(GrantPlane::CoordinatedLocal, None, None),
            Ok(PlaneAdmission::EdgePressureExecution { cpu_slots: 0 })
        );
    }

    #[test]
    fn the_fail_open_plane_never_invents_a_fleet_grant() {
        // Both grant families refuse: fail-open runs LOCAL with no
        // stale fleet claims attached.
        assert_eq!(
            admit_frontier(GrantPlane::UncoordinatedFailOpen, 1, 1),
            Err(PlaneRefusal::FailOpenCarriesNoFleetGrant)
        );
        assert_eq!(
            admit_execution(GrantPlane::UncoordinatedFailOpen, Some(8), Some(8)),
            Err(PlaneRefusal::FailOpenCarriesNoFleetGrant),
            "even real-looking observations cannot mint a stale grant"
        );
    }

    #[test]
    fn the_local_cargo_plane_cannot_admit_worker_or_edge_execution() {
        // The frontier plane's execution requests refuse per-plane:
        // worker-derived grants belong to WholeCommand, edge-pressure
        // grants to CoordinatedLocal.
        assert_eq!(
            admit_execution(GrantPlane::LocalCargoRemoteChildren, Some(8), None),
            Err(PlaneRefusal::EdgePressureGrantWrongPlane {
                plane: GrantPlane::LocalCargoRemoteChildren
            })
        );
        assert_eq!(
            admit_execution(GrantPlane::LocalCargoRemoteChildren, None, Some(3)),
            Err(PlaneRefusal::EdgePressureGrantWrongPlane {
                plane: GrantPlane::LocalCargoRemoteChildren
            })
        );
    }
}
