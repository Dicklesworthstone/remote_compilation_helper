//! Incremental-snapshot compatibility contract (bead P001; plan §103;
//! invariant I4's incremental arm; risk R31).
//!
//! Incremental state is ATTEMPT AUXILIARY (never result identity —
//! I4), but selecting the WRONG snapshot corrupts a compile: rustc's
//! incremental caches are toolchain- and configuration-specific, and
//! reusing one across a boundary rustc never promised produces
//! miscompiles or ICEs. The contract: a snapshot carries its full
//! compatibility class, and selection requires EXACT class equality —
//! no cross-class reuse exists without a proof, and no proof mechanism
//! exists today (the refusal names the mismatching dimension so the
//! operator sees exactly why the warm start was declined).

use crate::result_identity::TypedDigest;

/// The full compatibility class of an incremental snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncrementalCompatibilityClass {
    /// Toolchain contract digest (F007).
    pub toolchain: TypedDigest,
    /// Target triple.
    pub target: String,
    /// Cargo profile name (debug/release/custom).
    pub profile: String,
    /// Projection identity (the F010 projection epoch).
    pub projection_epoch: u32,
    /// Output-platform class digest (F008).
    pub output_platform: TypedDigest,
    /// Isolation class name (the snapshot's producing profile).
    pub isolation_class: String,
}

/// Which dimension refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum MismatchDimension {
    Toolchain,
    Target,
    Profile,
    ProjectionEpoch,
    OutputPlatform,
    IsolationClass,
}

/// Selection outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotSelection {
    /// Exact class match: the snapshot may seed this attempt.
    Selectable,
    /// Refused, naming the FIRST mismatching dimension.
    Refused(MismatchDimension),
}

/// Decide whether a stored snapshot may seed an attempt in `wanted`'s
/// class. Exact equality per dimension; the first mismatch names
/// itself.
#[must_use]
pub fn select_snapshot(
    stored: &IncrementalCompatibilityClass,
    wanted: &IncrementalCompatibilityClass,
) -> SnapshotSelection {
    if stored.toolchain != wanted.toolchain {
        return SnapshotSelection::Refused(MismatchDimension::Toolchain);
    }
    if stored.target != wanted.target {
        return SnapshotSelection::Refused(MismatchDimension::Target);
    }
    if stored.profile != wanted.profile {
        return SnapshotSelection::Refused(MismatchDimension::Profile);
    }
    if stored.projection_epoch != wanted.projection_epoch {
        return SnapshotSelection::Refused(MismatchDimension::ProjectionEpoch);
    }
    if stored.output_platform != wanted.output_platform {
        return SnapshotSelection::Refused(MismatchDimension::OutputPlatform);
    }
    if stored.isolation_class != wanted.isolation_class {
        return SnapshotSelection::Refused(MismatchDimension::IsolationClass);
    }
    SnapshotSelection::Selectable
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::result_identity::DigestAlgorithm;

    fn d(domain: &'static str, tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain,
            bytes: [tag; 32],
        }
    }

    fn class() -> IncrementalCompatibilityClass {
        IncrementalCompatibilityClass {
            toolchain: d("rabs.toolchain-contract.v1", 1),
            target: "x86_64-unknown-linux-gnu".into(),
            profile: "debug".into(),
            projection_epoch: 1,
            output_platform: d("rabs.output-platform.v1", 2),
            isolation_class: "strict-hermetic-linux".into(),
        }
    }

    #[test]
    fn exact_class_matches_select() {
        assert_eq!(
            select_snapshot(&class(), &class()),
            SnapshotSelection::Selectable
        );
    }

    #[test]
    fn every_dimension_mismatch_refuses_by_name() {
        // THE acceptance: one refusal fixture per dimension, each
        // naming itself.
        let mut m = class();
        m.toolchain = d("rabs.toolchain-contract.v1", 9);
        assert_eq!(
            select_snapshot(&m, &class()),
            SnapshotSelection::Refused(MismatchDimension::Toolchain)
        );
        let mut m = class();
        m.target = "aarch64-unknown-linux-gnu".into();
        assert_eq!(
            select_snapshot(&m, &class()),
            SnapshotSelection::Refused(MismatchDimension::Target)
        );
        let mut m = class();
        m.profile = "release".into();
        assert_eq!(
            select_snapshot(&m, &class()),
            SnapshotSelection::Refused(MismatchDimension::Profile)
        );
        let mut m = class();
        m.projection_epoch = 2;
        assert_eq!(
            select_snapshot(&m, &class()),
            SnapshotSelection::Refused(MismatchDimension::ProjectionEpoch)
        );
        let mut m = class();
        m.output_platform = d("rabs.output-platform.v1", 9);
        assert_eq!(
            select_snapshot(&m, &class()),
            SnapshotSelection::Refused(MismatchDimension::OutputPlatform)
        );
        let mut m = class();
        m.isolation_class = "host-audit".into();
        assert_eq!(
            select_snapshot(&m, &class()),
            SnapshotSelection::Refused(MismatchDimension::IsolationClass)
        );
    }

    #[test]
    fn no_cross_class_reuse_mechanism_exists() {
        // The contract's negative space: SnapshotSelection has exactly
        // two arms — Selectable and Refused. There is no
        // reuse-with-proof arm because no proof mechanism exists today;
        // adding one forces this match (and the plan decision) first.
        let outcome = select_snapshot(&class(), &class());
        match outcome {
            SnapshotSelection::Selectable | SnapshotSelection::Refused(_) => {}
        }
        // Schema completeness: the class carries all six dimensions.
        let IncrementalCompatibilityClass {
            toolchain: _,
            target: _,
            profile: _,
            projection_epoch: _,
            output_platform: _,
            isolation_class: _,
        } = class();
    }
}
