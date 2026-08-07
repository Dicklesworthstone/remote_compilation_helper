//! Shared incremental-serving gate (bead M018; plan §100/§103; risk
//! R31; the P-gates' serving coupling).
//!
//! An incremental directory is NEVER an implicit unkeyed input. Until
//! every incremental input/output state is explicit and the Epic P
//! gates pass, a workspace action does ONE of:
//!
//! - run with incremental compilation DISABLED for shared serving, or
//! - treat its incremental state as PRIVATE non-shareable (the local
//!   session may benefit; the fleet never sees it).
//!
//! The serving decision is DERIVED from the P-gate standing — the
//! gate struct has no serve boolean, so shared incremental serving
//! cannot be flipped on without the gates actually passing.

/// The Epic P gates the serving decision couples to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum PGate {
    /// P001: compatibility contract enforced on every selection.
    CompatibilityContract,
    /// P002: atomic paired capture after quiescence.
    AtomicPairedCapture,
    /// P00x: explicit incremental input/output state accounting.
    ExplicitStateAccounting,
    /// P00x: divergence differential over incremental warm starts.
    WarmStartDifferential,
}

/// The current P-gate standing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PGateStanding {
    /// Gates that have PASSED (with evidence, appended by the P-series
    /// beads as they land).
    pub passed: Vec<PGate>,
}

impl PGateStanding {
    /// Whether every required gate passed.
    #[must_use]
    pub fn all_passed(&self) -> bool {
        [
            PGate::CompatibilityContract,
            PGate::AtomicPairedCapture,
            PGate::ExplicitStateAccounting,
            PGate::WarmStartDifferential,
        ]
        .iter()
        .all(|g| self.passed.contains(g))
    }
}

/// How a workspace action handles incremental state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncrementalMode {
    /// Incremental disabled for the shared-serving build.
    DisabledForSharedServing,
    /// Incremental runs, state stays PRIVATE non-shareable.
    PrivateNonShareable,
    /// Shared incremental serving (only when every P-gate passed).
    SharedServing,
}

/// Derive the incremental mode. `wants_incremental` — whether the
/// user/profile asked for incremental compilation at all.
#[must_use]
pub fn incremental_mode(standing: &PGateStanding, wants_incremental: bool) -> IncrementalMode {
    if !wants_incremental {
        return IncrementalMode::DisabledForSharedServing;
    }
    if standing.all_passed() {
        IncrementalMode::SharedServing
    } else {
        // Incremental wanted, gates not passed: the state is private —
        // the local session benefits, the fleet never sees it.
        IncrementalMode::PrivateNonShareable
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_serving_requires_every_p_gate() {
        // THE enforcement: with ANY gate missing, shared serving is
        // unreachable — the mode is private or disabled.
        let mut standing = PGateStanding::default();
        assert_eq!(
            incremental_mode(&standing, true),
            IncrementalMode::PrivateNonShareable
        );
        standing.passed = vec![
            PGate::CompatibilityContract,
            PGate::AtomicPairedCapture,
            PGate::ExplicitStateAccounting,
        ];
        assert_eq!(
            incremental_mode(&standing, true),
            IncrementalMode::PrivateNonShareable,
            "three of four gates is not enough"
        );
        standing.passed.push(PGate::WarmStartDifferential);
        assert_eq!(
            incremental_mode(&standing, true),
            IncrementalMode::SharedServing
        );
    }

    #[test]
    fn the_serving_flag_is_derived_never_stored() {
        // Structural: PGateStanding has only the passed-gate list —
        // no serve boolean exists to flip without the gates.
        let PGateStanding { passed: _ } = PGateStanding::default();
        // And every mode is an explicit variant (no silent default).
        match incremental_mode(&PGateStanding::default(), true) {
            IncrementalMode::DisabledForSharedServing
            | IncrementalMode::PrivateNonShareable
            | IncrementalMode::SharedServing => {}
        }
    }

    #[test]
    fn non_incremental_builds_are_simply_disabled() {
        // No incremental wanted: nothing to gate — disabled for shared
        // serving regardless of standing.
        let full = PGateStanding {
            passed: vec![
                PGate::CompatibilityContract,
                PGate::AtomicPairedCapture,
                PGate::ExplicitStateAccounting,
                PGate::WarmStartDifferential,
            ],
        };
        assert_eq!(
            incremental_mode(&full, false),
            IncrementalMode::DisabledForSharedServing
        );
    }

    #[test]
    fn an_incremental_directory_is_never_an_implicit_unkeyed_input() {
        // The rule's negative space: in Private mode the state never
        // reaches the fleet; in Shared mode the P001 compatibility
        // contract (a PASSED gate) keys every selection. There is no
        // mode where incremental state flows unkeyed — the exhaustive
        // match above covers all three, and none is "shared without
        // gates".
        let ungated = incremental_mode(&PGateStanding::default(), true);
        assert_ne!(ungated, IncrementalMode::SharedServing);
    }
}
