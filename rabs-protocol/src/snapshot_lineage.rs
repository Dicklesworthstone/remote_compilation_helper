//! Requested→resolved snapshot lineage with sealed-generation binding
//! (bead A024; invariant I53; risk R110).
//!
//! A Cargo command begins from an immutable **requested** snapshot. If
//! unmodified Cargo legitimately resolves dependencies or mutates
//! `Cargo.lock` in its private overlay, RABS seals a **derived resolved**
//! snapshot before compilation actions bind to it. The rules encoded here:
//!
//! - every fine-grained action names **exactly one sealed generation**;
//! - no action closure may mix state from different generations — a
//!   pre-resolution `Cargo.toml` with a post-resolution `Cargo.lock` is
//!   the R110 corruption this module makes unrepresentable;
//! - sealing is strictly ordered: each derived phase supersedes, never
//!   interleaves; a post-seal mutation of semantically relevant state
//!   forces a strictly newer seal (or coherent replanning/downgrade —
//!   an operation-level decision outside these types).

use crate::result_identity::ObjectId;

/// Identity of one immutable snapshot object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotId(pub ObjectId);

/// One sealed phase of a build operation's snapshot lineage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedSnapshot {
    /// Strictly increasing phase number within the operation
    /// (0 = the requested snapshot itself).
    pub phase: u32,
    /// The immutable snapshot for this phase.
    pub snapshot: SnapshotId,
}

/// A build operation's snapshot lineage: the requested snapshot plus zero
/// or more derived resolved phases.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotLineage {
    sealed: Vec<SealedSnapshot>,
}

/// Lineage errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineageError {
    /// A new seal's phase did not strictly exceed the latest phase.
    PhaseNotMonotonic,
    /// A binding referenced a phase this lineage never sealed.
    UnknownPhase,
    /// A binding's snapshot does not match the sealed snapshot of its phase.
    SnapshotMismatch,
    /// A closure mixed bindings from different sealed phases (R110).
    MixedGenerations,
    /// A closure was empty (nothing to validate is a caller bug, not a pass).
    EmptyClosure,
}

impl SnapshotLineage {
    /// Start a lineage from the requested snapshot (phase 0).
    #[must_use]
    pub fn from_requested(requested: SnapshotId) -> Self {
        Self {
            sealed: vec![SealedSnapshot {
                phase: 0,
                snapshot: requested,
            }],
        }
    }

    /// Seal a derived resolved snapshot as a strictly newer phase.
    ///
    /// # Errors
    /// [`LineageError::PhaseNotMonotonic`] when `phase` does not strictly
    /// exceed the latest sealed phase.
    pub fn seal(&mut self, phase: u32, snapshot: SnapshotId) -> Result<(), LineageError> {
        let latest = self.latest().phase;
        if phase <= latest {
            return Err(LineageError::PhaseNotMonotonic);
        }
        self.sealed.push(SealedSnapshot { phase, snapshot });
        Ok(())
    }

    /// The most recently sealed phase.
    #[must_use]
    pub fn latest(&self) -> &SealedSnapshot {
        self.sealed.last().expect("lineage always has phase 0")
    }

    /// Look up a sealed phase.
    #[must_use]
    pub fn phase(&self, phase: u32) -> Option<&SealedSnapshot> {
        self.sealed.iter().find(|s| s.phase == phase)
    }

    /// Validate one action binding: the phase must exist and the snapshot
    /// must be the one sealed for it.
    ///
    /// # Errors
    /// [`LineageError::UnknownPhase`] / [`LineageError::SnapshotMismatch`].
    pub fn validate_binding(&self, binding: &ActionSnapshotBinding) -> Result<(), LineageError> {
        let Some(sealed) = self.phase(binding.sealed_phase) else {
            return Err(LineageError::UnknownPhase);
        };
        if sealed.snapshot != binding.snapshot {
            return Err(LineageError::SnapshotMismatch);
        }
        Ok(())
    }

    /// Validate a whole closure: every binding valid AND all bindings from
    /// ONE sealed generation — mixed pre/post-resolution state is the R110
    /// corruption and is rejected here.
    ///
    /// # Errors
    /// Any per-binding error, [`LineageError::MixedGenerations`], or
    /// [`LineageError::EmptyClosure`].
    pub fn validate_closure(&self, bindings: &[ActionSnapshotBinding]) -> Result<(), LineageError> {
        let Some(first) = bindings.first() else {
            return Err(LineageError::EmptyClosure);
        };
        for b in bindings {
            self.validate_binding(b)?;
            if b.sealed_phase != first.sealed_phase {
                return Err(LineageError::MixedGenerations);
            }
        }
        Ok(())
    }
}

/// An action subscription's binding to exactly one sealed generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionSnapshotBinding {
    /// The sealed phase this action derives its closure from.
    pub sealed_phase: u32,
    /// The snapshot the action believes that phase is (verified against
    /// the lineage — a stale/forged snapshot is a mismatch, not a pass).
    pub snapshot: SnapshotId,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::result_identity::{DigestAlgorithm, TypedDigest};

    fn snap(tag: u8) -> SnapshotId {
        SnapshotId(ObjectId(TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "rabs.snapshot.v1",
            bytes: [tag; 32],
        }))
    }

    #[test]
    fn seal_phases_strictly_increase() {
        let mut l = SnapshotLineage::from_requested(snap(1));
        l.seal(1, snap(2)).unwrap();
        assert_eq!(l.seal(1, snap(3)), Err(LineageError::PhaseNotMonotonic));
        assert_eq!(l.seal(0, snap(3)), Err(LineageError::PhaseNotMonotonic));
        l.seal(5, snap(3)).unwrap();
        assert_eq!(l.latest().phase, 5);
    }

    #[test]
    fn bindings_verify_phase_and_snapshot() {
        let mut l = SnapshotLineage::from_requested(snap(1));
        l.seal(1, snap(2)).unwrap();
        // Valid binding to the resolved phase.
        l.validate_binding(&ActionSnapshotBinding {
            sealed_phase: 1,
            snapshot: snap(2),
        })
        .unwrap();
        // Unknown phase.
        assert_eq!(
            l.validate_binding(&ActionSnapshotBinding {
                sealed_phase: 9,
                snapshot: snap(2),
            }),
            Err(LineageError::UnknownPhase)
        );
        // Right phase, wrong snapshot (stale/forged).
        assert_eq!(
            l.validate_binding(&ActionSnapshotBinding {
                sealed_phase: 1,
                snapshot: snap(9),
            }),
            Err(LineageError::SnapshotMismatch)
        );
    }

    #[test]
    fn mixed_generation_closures_are_the_r110_corruption_and_are_rejected() {
        let mut l = SnapshotLineage::from_requested(snap(1));
        l.seal(1, snap(2)).unwrap();
        // A closure straddling the requested and resolved phases — the
        // pre-resolution-Cargo.toml + post-resolution-Cargo.lock case.
        let mixed = [
            ActionSnapshotBinding {
                sealed_phase: 0,
                snapshot: snap(1),
            },
            ActionSnapshotBinding {
                sealed_phase: 1,
                snapshot: snap(2),
            },
        ];
        assert_eq!(
            l.validate_closure(&mixed),
            Err(LineageError::MixedGenerations)
        );
        // Single-generation closures pass.
        let clean = [
            ActionSnapshotBinding {
                sealed_phase: 1,
                snapshot: snap(2),
            },
            ActionSnapshotBinding {
                sealed_phase: 1,
                snapshot: snap(2),
            },
        ];
        l.validate_closure(&clean).unwrap();
        // Empty closures are a caller bug, never a silent pass.
        assert_eq!(l.validate_closure(&[]), Err(LineageError::EmptyClosure));
    }
}
