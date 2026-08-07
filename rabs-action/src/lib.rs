//! # rabs-action — pure action semantics and state machines
//!
//! Owns the four **separate** RABS state machines (invariants I29/I30; risk
//! R61 forbids collapsing them into one lifecycle enum):
//!
//! 1. **Build operation** — one user/agent/IDE/CI Cargo command:
//!    `Created → Snapshotting → CargoStarting → CargoRunning → CargoDraining
//!    → Completed` (alternates: `Cancelled`, `FailedBeforeStart`,
//!    `FailedAfterObservableCommit`, `LocalFallbackCompleted`,
//!    `AbandonedClient`, `InternalFailure`). Owns the requested→resolved
//!    snapshot lineage and root permit.
//! 2. **Logical action publication** — the authority-bearing slot:
//!    `Absent → Executing(ActionGenerationId) → Committed(PublicationRecord)`,
//!    with mutable serving disposition as a *separate* versioned record
//!    (I50). A cache hit never re-commits.
//! 3. **Execution attempt** — per-attempt lifecycle with an independent
//!    execution lease (`Created → LeaseOffered → … → PreparedResultOffered →
//!    AcceptedAsWinner | Rejected* → Draining → Finished`).
//! 4. **Subscriber delivery** — the two-frontier transcript/stateful
//!    machine with write-ahead intent, acknowledgement, and fail-closed
//!    uncertainty states (I43/I46).
//!
//! Also owned here: subscriber interest accounting, attempt fencing,
//! deterministic retry classification, publication eligibility, provisional
//! metadata ownership, the failure taxonomy
//! (`DeterministicFailure`/`VolatileFailure`/`InfrastructureFailure`/
//! `WorkerLost`/`LeaseExpired`/`Cancelled`/`OomKilled`/`SignalTerminated`/
//! `InternalPanic`/`PolicyRefused`), action-result validation rules, and
//! pure reconciliation decisions.
//!
//! ## Dependency rules (binding; enforced by dependency-direction CI, bead A002)
//!
//! - May depend on `rabs-protocol` **only**.
//! - **Zero filesystem, network, or process effects.** Every function here
//!   must be runnable in the Asupersync deterministic lab *and* in ordinary
//!   unit/property tests with no runtime at all.
//! - No Tokio, no Asupersync, no clocks: time enters as explicit
//!   `rabs-protocol` causal/budget values.

pub mod state_machines;
