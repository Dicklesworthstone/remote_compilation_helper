//! Canonical Cargo-driver lane gate for workspace publication
//! (bead rabs-root-4pidu.31.14 / M014; invariant I19; risks R43/R112;
//! plan §26 authority matrix, `WorkspaceServing` cells).
//!
//! I19: workspace-member authority requires CANONICAL Cargo planning —
//! Cargo's own planning (dep-info resolution, fingerprinting, jobserver
//! semantics) must have run under the canonical namespace spelling of
//! the workspace parent, proven by a planning-provenance receipt bound
//! to the action's descriptor. The fast/immutable paths prove nothing
//! about workspace members (authority matrix: `DependencyImmutableFastPath`
//! × `WorkspaceServing` is `NotAuthorized` for exactly this reason).
//!
//! Two decisions live here:
//!
//! - [`decide_lane`] — total classification used by schedulers: which
//!   lane may this result occupy? Noncanonical parents get the
//!   dependency/local lane AT MOST (never an error by itself).
//! - [`require_workspace_shared`] — the publication gate: when
//!   cross-worktree serving IS attempted, a noncanonical parent or a
//!   missing proof REFUSES with the registered reason code
//!   ([`REASON_CODE`]), never silently downgrades mid-flight.
//!
//! Canonicality is BYTE-LITERAL against coordinator-configured canonical
//! parents after one safe normalization (leading `./` strip). No case
//! folds, no symlink resolution, no environment expansion — path
//! semantics are the Path family's contract (I-path rules), and anything
//! this module cannot affirmatively prove reduces to the lesser lane
//! (I28 posture).

use crate::result_identity::TypedDigest;

/// Registered refusal code for a noncanonical workspace parent attempted
/// at cross-worktree publication (see `reason_codes::ReasonCode`).
pub const REASON_CODE: &str = "PATH_WORKSPACE_PARENT_NONCANONICAL";

/// Proof that Cargo's own planning ran in the canonical namespace: the
/// digest of the planning-provenance receipt, itself bound to the
/// action descriptor. Opaque here — binding verification belongs to the
/// provenance layer; this gate refuses its ABSENCE and records its
/// presence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalPlanningProof {
    /// Digest key of the planning-provenance receipt.
    pub receipt_digest: TypedDigest,
}

/// Which execution/serving lane a workspace result may occupy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceLane {
    /// Full cross-worktree shared serving (still subject to the ordinary
    /// correctness gates — shadow corpus, divergence, SLOs).
    WorkspaceSharedServing,
    /// Dependency results and local execution only: no cross-worktree
    /// workspace-member serving from this parent.
    DependencyOrLocalOnly,
}

/// Why cross-worktree publication was refused (M014 acceptance).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkspaceLaneRefusal {
    /// The parent is not among the configured canonical parents:
    /// refused with the registered [`REASON_CODE`] and the dependency/
    /// local fallback named.
    NonCanonicalParent {
        /// The offending parent (bytes as offered).
        parent: String,
        /// The lane this result is still allowed to occupy.
        fallback: &'static str,
        /// Always [`REASON_CODE`]; carried so logs are greppable without
        /// the registry.
        code: &'static str,
    },
    /// Parent IS canonical but no canonical-planning proof was presented
    /// — I19 demands the receipt, not good intentions.
    MissingCanonicalPlanningProof {
        /// The canonical parent that WOULD have been acceptable.
        parent: String,
    },
    /// The parent contains a traversal component (`..`) or is empty:
    /// fail-closed before any comparison.
    ParentTraversal {
        /// The offending parent (bytes as offered).
        parent: String,
    },
}

impl WorkspaceLaneRefusal {
    /// The registry reason code this refusal reports (empty-string-free).
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::NonCanonicalParent { code, .. } => code,
            Self::MissingCanonicalPlanningProof { .. } | Self::ParentTraversal { .. } => {
                REASON_CODE
            }
        }
    }
}

impl std::fmt::Display for WorkspaceLaneRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonCanonicalParent {
                parent,
                fallback,
                code,
            } => write!(
                f,
                "{code}: workspace parent {parent:?} is noncanonical; reduced to {fallback}"
            ),
            Self::MissingCanonicalPlanningProof { parent } => write!(
                f,
                "canonical Cargo planning unproven for parent {parent:?}; \
                 workspace-shared serving requires the planning receipt"
            ),
            Self::ParentTraversal { parent } => {
                write!(f, "workspace parent {parent:?} contains traversal")
            }
        }
    }
}
impl std::error::Error for WorkspaceLaneRefusal {}

/// Coordinator-configured canonical namespace policy: every parent path
/// a workspace member MAY plan under for shared serving. Byte-literal
/// after leading-`./` normalization.
#[derive(Debug, Clone)]
pub struct WorkspaceLanePolicy<'a> {
    canonical_parents: &'a [Vec<u8>],
}

impl<'a> WorkspaceLanePolicy<'a> {
    /// Policy over the configured canonical parents (bytes, e.g.
    /// `/data/projects/acme` — alias spellings must be listed too; the
    /// gate never guesses equivalence).
    #[must_use]
    pub fn new(canonical_parents: &'a [Vec<u8>]) -> Self {
        Self { canonical_parents }
    }

    fn normalize(parent: &[u8]) -> Vec<u8> {
        // Leading "./" strip ONLY. No traversal forgiveness here — a
        // parent containing ".." is refused outright downstream.
        if parent.starts_with(b"./") {
            parent[2..].to_vec()
        } else {
            parent.to_vec()
        }
    }

    fn has_traversal(parent: &[u8]) -> bool {
        parent.is_empty()
            || parent.split(|b| *b == b'/').any(|comp| comp == b"..")
            || parent == b".."
    }

    fn canonical_parent(&self, parent: &[u8]) -> Option<Vec<u8>> {
        self.canonical_parents
            .iter()
            .find(|candidate| candidate.as_slice() == parent)
            .cloned()
    }
}

/// Total scheduler-facing classification (never fails): which lane may
/// this result occupy? Traversal parents classify to the dependency/
/// local lane like any other noncanonical parent.
#[must_use]
pub fn decide_lane(
    policy: &WorkspaceLanePolicy<'_>,
    parent: &[u8],
    proof: Option<&CanonicalPlanningProof>,
) -> WorkspaceLane {
    if WorkspaceLanePolicy::has_traversal(parent) {
        return WorkspaceLane::DependencyOrLocalOnly;
    }
    let normalized = WorkspaceLanePolicy::normalize(parent);
    let canonical = policy.canonical_parent(&normalized).is_some();
    if canonical && proof.is_some() {
        WorkspaceLane::WorkspaceSharedServing
    } else {
        WorkspaceLane::DependencyOrLocalOnly
    }
}

/// Publication gate for cross-worktree workspace serving (M014): refuse
/// unless the parent is canonical AND canonical Cargo planning is proven.
///
/// # Errors
/// Typed [`WorkspaceLaneRefusal`]s naming the registered reason code.
pub fn require_workspace_shared(
    policy: &WorkspaceLanePolicy<'_>,
    parent: &[u8],
    proof: Option<&CanonicalPlanningProof>,
) -> Result<(), WorkspaceLaneRefusal> {
    if WorkspaceLanePolicy::has_traversal(parent) {
        return Err(WorkspaceLaneRefusal::ParentTraversal {
            parent: String::from_utf8_lossy(parent).into_owned(),
        });
    }
    let normalized = WorkspaceLanePolicy::normalize(parent);
    if policy.canonical_parent(&normalized).is_none() {
        return Err(WorkspaceLaneRefusal::NonCanonicalParent {
            parent: String::from_utf8_lossy(&normalized).into_owned(),
            fallback: "dependency/local",
            code: REASON_CODE,
        });
    }
    proof.ok_or_else(|| WorkspaceLaneRefusal::MissingCanonicalPlanningProof {
        parent: String::from_utf8_lossy(&normalized).into_owned(),
    })?;
    Ok(())
}

// ---------------------------------------------------------------------
// Tests — the M014 acceptance suite.
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::result_identity::{DigestAlgorithm, TypedDigest};

    fn proof(tag: u8) -> CanonicalPlanningProof {
        CanonicalPlanningProof {
            receipt_digest: TypedDigest {
                algorithm: DigestAlgorithm::Sha256V1,
                domain: "rabs.planning-receipt.sha256.v1",
                bytes: {
                    let mut b = [0u8; 32];
                    b[0] = tag;
                    b[31] = tag;
                    b
                },
            },
        }
    }

    fn policy() -> WorkspaceLanePolicy<'static> {
        static PARENTS: std::sync::LazyLock<Vec<Vec<u8>>> = std::sync::LazyLock::new(|| {
            vec![b"/data/projects/acme".to_vec(), b"/dp/acme".to_vec()]
        });
        WorkspaceLanePolicy::new(PARENTS.as_slice())
    }

    #[test]
    fn m014_canonical_parent_with_proof_gets_shared_serving() {
        assert_eq!(
            decide_lane(&policy(), b"/data/projects/acme", Some(&proof(1))),
            WorkspaceLane::WorkspaceSharedServing
        );
        assert_eq!(
            decide_lane(&policy(), b"/dp/acme", Some(&proof(1))),
            WorkspaceLane::WorkspaceSharedServing
        );
    }

    #[test]
    fn m014_canonical_parent_without_proof_refuses_missing_receipt() {
        // Canonical parent but NO proof presented: I19 wants the
        // planning receipt, not the address alone.
        assert_eq!(
            decide_lane(&policy(), b"/data/projects/acme", None),
            WorkspaceLane::DependencyOrLocalOnly
        );
        let err = require_workspace_shared(&policy(), b"/data/projects/acme", None).unwrap_err();
        assert_eq!(
            err,
            WorkspaceLaneRefusal::MissingCanonicalPlanningProof {
                parent: "/data/projects/acme".to_owned()
            }
        );
    }

    #[test]
    fn m014_refusal_code_is_registered_in_the_reason_registry() {
        // The refusal code is not a string literal orphan: the reason
        // registry carries it with the Path family so logs/dashboards
        // classify it without bespoke parsing.
        assert!(crate::reason_codes::REGISTRY.iter().any(|entry| {
            entry.code == REASON_CODE
                && matches!(entry.family, crate::reason_codes::ReasonFamily::Path)
        }));
    }

    #[test]
    fn m014_noncanonical_publication_refused_with_reason_code() {
        // THE acceptance: noncanonical-parent publication refused with
        // the registered reason code, naming the fallback lane.
        let err =
            require_workspace_shared(&policy(), b"/home/me/code", Some(&proof(1))).unwrap_err();
        assert_eq!(
            err,
            WorkspaceLaneRefusal::NonCanonicalParent {
                parent: "/home/me/code".to_owned(),
                fallback: "dependency/local",
                code: "PATH_WORKSPACE_PARENT_NONCANONICAL"
            }
        );
        assert_eq!(err.reason_code(), "PATH_WORKSPACE_PARENT_NONCANONICAL");
    }

    #[test]
    fn m014_canonical_without_proof_refuses_missing_receipt() {
        // Canonical parent but NO proof presented: I19 wants the
        // planning receipt, not the address alone. decide_lane proves
        // the proof actually gates the decision.
        assert_eq!(
            decide_lane(&policy(), b"/data/projects/acme", None),
            WorkspaceLane::DependencyOrLocalOnly
        );
        let err = require_workspace_shared(&policy(), b"/data/projects/acme", None).unwrap_err();
        assert_eq!(
            err,
            WorkspaceLaneRefusal::MissingCanonicalPlanningProof {
                parent: "/data/projects/acme".to_owned()
            }
        );
    }

    #[test]
    fn m014_traversal_parents_fail_closed_before_comparison() {
        for hostile in [&b"../acme"[..], &b"/data/projects/../acme"[..], &b""[..]] {
            assert_eq!(
                decide_lane(&policy(), hostile, Some(&proof(1))),
                WorkspaceLane::DependencyOrLocalOnly
            );
            let err = require_workspace_shared(&policy(), hostile, Some(&proof(1))).unwrap_err();
            assert!(matches!(err, WorkspaceLaneRefusal::ParentTraversal { .. }));
        }
    }

    #[test]
    fn m014_relative_spellings_are_not_canonical() {
        // Leading-"./" stripping lands on a RELATIVE spelling, which can
        // never equal an absolute canonical root — relative parents get
        // the lesser lane (fail-closed; only literal canonical spellings
        // are admitted).
        assert_eq!(
            decide_lane(&policy(), b"./dp/acme", Some(&proof(1))),
            WorkspaceLane::DependencyOrLocalOnly
        );
    }
}
