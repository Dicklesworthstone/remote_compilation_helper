//! `BuildPathSemanticPolicy` + the path-preserving lane (bead D030;
//! invariant I41; plan §59; risk R96; fixture family T030).
//!
//! Some programs OBSERVE their own build paths: `file!()`,
//! `env!("CARGO_MANIFEST_DIR")`, `OUT_DIR`-derived strings, panic
//! locations, embedded source maps, runtime resource lookup, and
//! path-asserting tests. For those, a canonical-path build is
//! OBSERVABLY DIFFERENT from the user's original-path build, and
//! serving the canonical artifact would hand the user bytes their own
//! machine would never have produced. The policy decides per
//! workspace-action family:
//!
//! - `CanonicalPortablePath` — the family proved path-insensitive;
//!   canonical builds share fleet-wide;
//! - `PathOpaqueVerified` — paths appear in artifacts but a verified
//!   differential proved them semantically inert byte-for-byte;
//! - `ProjectRelativeRemapped` — a versioned remap rewrites to
//!   project-relative form, proven stable;
//! - `SubscriberPathPreserving` — the LANE: build under the
//!   subscriber's original paths, locally, no cross-worktree sharing;
//! - a NEW family defaults to **shadow/audit** (canonical shadow
//!   builds run for evidence, the subscriber is served from the
//!   preserving lane until the differential earns a promotion).
//!
//! The policy is a keyed descriptor component
//! (`build_path_semantic_policy`) — two subscribers under different
//! policies are different actions by construction.

use rabs_protocol::result_identity::TypedDigest;

use crate::canonical::CanonicalEncoder;
use crate::typed_digest::compute;

/// Digest domain for the path-policy component.
pub const DOMAIN_PATH_POLICY: &str = "rabs.path-policy.v1";

/// Per-family build-path semantic policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildPathSemanticPolicy {
    /// Proven path-insensitive; canonical builds share fleet-wide.
    CanonicalPortablePath,
    /// Paths present but differentially proven inert.
    PathOpaqueVerified,
    /// Versioned project-relative remapping, proven stable.
    ProjectRelativeRemapped,
    /// The preserving lane: original paths, local only.
    SubscriberPathPreserving,
}

/// Wire-stable policy tag.
#[must_use]
pub const fn policy_tag(policy: BuildPathSemanticPolicy) -> u32 {
    match policy {
        BuildPathSemanticPolicy::CanonicalPortablePath => 1,
        BuildPathSemanticPolicy::PathOpaqueVerified => 2,
        BuildPathSemanticPolicy::ProjectRelativeRemapped => 3,
        BuildPathSemanticPolicy::SubscriberPathPreserving => 4,
    }
}

/// The canonical path-observation hazards (the audit checklist the
/// differential runner scans for — plan-named, pinned by test).
pub const PATH_HAZARDS: [&str; 7] = [
    "file!()",
    "env!(CARGO_MANIFEST_DIR)",
    "OUT_DIR-derived strings",
    "panic locations",
    "embedded source maps",
    "runtime resource lookup",
    "path-asserting tests",
];

/// Differential evidence for one family: did the original-path build
/// and the canonical-path build differ observably?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DifferentialEvidence {
    /// No differential has run for this family yet.
    NotYetRun,
    /// Ran; outputs byte-identical and behavior equivalent.
    NoObservableDifference,
    /// Ran; the builds differ observably (any hazard fired).
    ObservableDifference,
    /// Ran but coverage was incomplete/ambiguous.
    Ambiguous,
}

/// The routing decision for one family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathLaneDecision {
    /// Serve from the canonical shared lane under the given policy.
    CanonicalShared(BuildPathSemanticPolicy),
    /// Route to the path-preserving/local lane (with shadow builds
    /// gathering evidence when the family is new).
    PreservingLane {
        /// Whether canonical shadow builds run alongside for evidence.
        shadow_audit: bool,
    },
}

/// Decide the lane for a family from its policy standing + evidence.
#[must_use]
pub fn decide_lane(
    configured: Option<BuildPathSemanticPolicy>,
    evidence: DifferentialEvidence,
) -> PathLaneDecision {
    match (configured, evidence) {
        // A new family (no configured policy): shadow/audit default.
        (None, _) => PathLaneDecision::PreservingLane { shadow_audit: true },
        // Explicit preserving policy: preserving, no shadow needed.
        (Some(BuildPathSemanticPolicy::SubscriberPathPreserving), _) => {
            PathLaneDecision::PreservingLane {
                shadow_audit: false,
            }
        }
        // Any shared policy is honored ONLY while the differential
        // stays clean; a difference or ambiguity demotes to preserving
        // (unsafe/ambiguous remapping never becomes a canonical hit).
        (Some(policy), DifferentialEvidence::NoObservableDifference) => {
            PathLaneDecision::CanonicalShared(policy)
        }
        (
            Some(_),
            DifferentialEvidence::ObservableDifference
            | DifferentialEvidence::Ambiguous
            | DifferentialEvidence::NotYetRun,
        ) => PathLaneDecision::PreservingLane { shadow_audit: true },
    }
}

/// The keyed component digest for the descriptor's
/// `build_path_semantic_policy` slot.
#[must_use]
pub fn policy_component_digest(policy: BuildPathSemanticPolicy) -> TypedDigest {
    let mut enc = CanonicalEncoder::new();
    enc.u32(policy_tag(policy));
    compute(DOMAIN_PATH_POLICY, &enc.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use BuildPathSemanticPolicy as P;

    #[test]
    fn observable_difference_routes_to_the_preserving_lane() {
        // THE T030 acceptance fixture: a family configured for shared
        // canonical serving whose differential fired — routed to the
        // preserving lane with shadow audit, never a canonical hit.
        for policy in [
            P::CanonicalPortablePath,
            P::PathOpaqueVerified,
            P::ProjectRelativeRemapped,
        ] {
            assert_eq!(
                decide_lane(Some(policy), DifferentialEvidence::ObservableDifference),
                PathLaneDecision::PreservingLane { shadow_audit: true },
                "{policy:?} must demote on observable difference"
            );
            // Ambiguity is treated exactly like a difference.
            assert_eq!(
                decide_lane(Some(policy), DifferentialEvidence::Ambiguous),
                PathLaneDecision::PreservingLane { shadow_audit: true }
            );
        }
    }

    #[test]
    fn new_families_default_to_shadow_audit() {
        assert_eq!(
            decide_lane(None, DifferentialEvidence::NotYetRun),
            PathLaneDecision::PreservingLane { shadow_audit: true }
        );
        // Even clean evidence does not skip configuration: promotion
        // is a policy decision, not an inference.
        assert_eq!(
            decide_lane(None, DifferentialEvidence::NoObservableDifference),
            PathLaneDecision::PreservingLane { shadow_audit: true }
        );
    }

    #[test]
    fn clean_differentials_serve_the_configured_shared_lane() {
        assert_eq!(
            decide_lane(
                Some(P::CanonicalPortablePath),
                DifferentialEvidence::NoObservableDifference
            ),
            PathLaneDecision::CanonicalShared(P::CanonicalPortablePath)
        );
        // An explicitly preserving family needs no shadow.
        assert_eq!(
            decide_lane(
                Some(P::SubscriberPathPreserving),
                DifferentialEvidence::NoObservableDifference
            ),
            PathLaneDecision::PreservingLane {
                shadow_audit: false
            }
        );
    }

    #[test]
    fn policy_is_a_keyed_component_with_stable_tags() {
        // The four policies produce four distinct component digests —
        // two subscribers under different policies are different
        // actions (the descriptor slot carries this digest).
        let all = [
            P::CanonicalPortablePath,
            P::PathOpaqueVerified,
            P::ProjectRelativeRemapped,
            P::SubscriberPathPreserving,
        ];
        let tags: Vec<u32> = all.iter().map(|p| policy_tag(*p)).collect();
        assert_eq!(tags, vec![1, 2, 3, 4]);
        let mut digests: Vec<_> = all.iter().map(|p| policy_component_digest(*p)).collect();
        digests.dedup();
        assert_eq!(digests.len(), all.len());
        assert!(digests.iter().all(|d| d.domain == DOMAIN_PATH_POLICY));
    }

    #[test]
    fn hazard_checklist_is_the_plan_list_verbatim() {
        assert_eq!(
            PATH_HAZARDS,
            [
                "file!()",
                "env!(CARGO_MANIFEST_DIR)",
                "OUT_DIR-derived strings",
                "panic locations",
                "embedded source maps",
                "runtime resource lookup",
                "path-asserting tests",
            ]
        );
    }
}
