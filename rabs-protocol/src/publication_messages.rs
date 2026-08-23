//! The result-publication message family (bead J024; plan §64; risk R50):
//! a prepared-result OFFER replaces any worker commit message.
//!
//! Structural enforcement of "there is no worker-authoritative
//! `CommitActionResult` anywhere in the protocol":
//!
//! - the WORKER vocabulary is a deliberately closed, single-variant enum:
//!   [`WorkerPublicationMessage::OfferPreparedActionResult`] is the only
//!   thing a worker can say about a result;
//! - EVERY coordinator decision/notification carries an
//!   [`AuthorityProof`] — construction requires the full
//!   [`CoordinatorAuthority`] value, which worker code never holds — so
//!   commit/quarantine/failure notifications are structurally
//!   coordinator-minted;
//! - [`PUBLICATION_SCHEMAS`] pins the complete six-schema catalog; the
//!   fixture tests audit both enums against it exhaustively (a new
//!   variant fails the audit until the catalog is consciously updated),
//!   and assert no worker kind names or implies a commit.
//!
//! Relationship to the J012 session catalog ([`crate::messages`]): those
//! messages drive attempt/session lifecycle; this family drives result
//! publication decisions. They compose on the wire but keep separate
//! schemas so the R50 invariant stays locally auditable.

use crate::authority::CoordinatorAuthority;
use crate::durable_ids::DurableWireIdentity;
use crate::result_identity::{ObjectId, TypedDigest};

/// The complete publication schema catalog (J024). Order is the fixture
/// order; the audit test walks BOTH enums against this list.
pub const PUBLICATION_SCHEMAS: &[&str] = &[
    "OfferPreparedActionResult",
    "PreparedResultAccepted",
    "PreparedResultRejected",
    "ActionResultCommitted",
    "ActionResultQuarantined",
    "ActionTerminalFailure",
];

/// Why a coordinator rejected a prepared-result offer (typed, compact;
/// detailed refusals live in the CAS layer's offer validation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfferRejectionKind {
    /// The presenting authority/generation/attempt fence failed.
    AuthorityFence,
    /// The generation was tombstoned before the offer arrived.
    GenerationTombstoned,
    /// Canonical manifest/descriptor validation failed.
    ManifestInvalid,
    /// A same-key candidate with different semantics already committed.
    DivergentCandidate,
}

impl OfferRejectionKind {
    /// Stable schema tag persisted in traces and counters.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthorityFence => "authority-fence",
            Self::GenerationTombstoned => "generation-tombstoned",
            Self::ManifestInvalid => "manifest-invalid",
            Self::DivergentCandidate => "divergent-candidate",
        }
    }
}

/// Quarantine class of a committed-vs-candidate divergence (mirrors the
/// A018 taxonomy tags used by the CAS divergence incidents).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuarantineClass {
    /// Different semantic result under the same key.
    SemanticDivergence,
    /// Same semantics, observably different presentation.
    ObservableOnlyDivergence,
    /// Equal declared digests, different canonical manifest bytes.
    ProjectionCompleteness,
}

impl QuarantineClass {
    /// Stable schema tag (matches the divergence-incident class tags).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SemanticDivergence => "semantic",
            Self::ObservableOnlyDivergence => "observable-only",
            Self::ProjectionCompleteness => "projection-completeness",
        }
    }
}

/// Proof that the emitter holds coordinator authority for the cluster.
///
/// Construction consumes the FULL authority value; the inner field is
/// private and the type is neither `Copy` nor constructible from parts,
/// so coordinator-plane messages cannot be assembled by code that does
/// not genuinely hold authority (risk R50's teeth at the type level).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityProof {
    authority: CoordinatorAuthority,
}

impl AuthorityProof {
    /// Mint a proof from the full authority value.
    #[must_use]
    pub fn new(authority: CoordinatorAuthority) -> Self {
        Self { authority }
    }

    /// The authority backing this message.
    #[must_use]
    pub fn authority(&self) -> &CoordinatorAuthority {
        &self.authority
    }
}

/// Everything a WORKER may say about result publication (J024).
///
/// One variant, by construction: the worker OFFERS its harvested,
/// uploaded candidate and waits. Any future variant added here must
/// survive the schema-catalog audit and the no-worker-commit review —
/// the audit test enumerates this enum exhaustively.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerPublicationMessage {
    /// Offer the prepared candidate: uploaded manifest + evidence objects
    /// bound to the offering attempt's durable identity. Candidate pins
    /// remain valid through coordinator decision/reconciliation (§64.7).
    OfferPreparedActionResult {
        /// Coordinator/generation/attempt/lease identity of the offer.
        identity: DurableWireIdentity,
        /// Digest of the offered action key.
        action_key: TypedDigest,
        /// CAS object holding the canonical result manifest.
        manifest_id: ObjectId,
        /// CAS object holding the attempt evidence bundle.
        evidence_id: ObjectId,
    },
}

impl WorkerPublicationMessage {
    /// Schema tag of this message.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::OfferPreparedActionResult { .. } => "OfferPreparedActionResult",
        }
    }
}

/// Coordinator decisions and notifications about result publication.
///
/// All variants carry [`AuthorityProof`]: commits are notifications of
/// ALREADY-durable facts, quarantines are authority-gated incident
/// declarations, failures are terminal attempt adjudications. None of
/// these can be minted by worker code (see [`AuthorityProof`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoordinatorPublicationMessage {
    /// The offer passed validation and is recorded as the current
    /// candidate.
    PreparedResultAccepted {
        /// Minting authority.
        proof: AuthorityProof,
        /// The offered attempt's identity.
        identity: DurableWireIdentity,
    },
    /// The offer was rejected; the worker drains its candidate pins.
    PreparedResultRejected {
        /// Minting authority.
        proof: AuthorityProof,
        /// The offered attempt's identity.
        identity: DurableWireIdentity,
        /// Typed rejection cause.
        reason: OfferRejectionKind,
    },
    /// Notification of an ALREADY-durable commit (the metadata
    /// transaction — including the publication pin — committed before
    /// this message exists; risk R50: it informs, it never authorizes).
    ActionResultCommitted {
        /// Minting authority.
        proof: AuthorityProof,
        /// The committed action key.
        action_key: TypedDigest,
        /// CAS object of the winning canonical manifest.
        manifest_id: ObjectId,
        /// Winning generation id.
        winner_generation_id: u128,
        /// Winning attempt id.
        winner_attempt: u128,
    },
    /// The action entered quarantine (divergence taxonomy tag attached).
    ActionResultQuarantined {
        /// Minting authority.
        proof: AuthorityProof,
        /// The quarantined action key.
        action_key: TypedDigest,
        /// Divergence class.
        class: QuarantineClass,
    },
    /// Terminal failure adjudication for an attempt (no result will ever
    /// be published for it under this identity).
    ActionTerminalFailure {
        /// Minting authority.
        proof: AuthorityProof,
        /// The failed attempt's identity.
        identity: DurableWireIdentity,
    },
}

impl CoordinatorPublicationMessage {
    /// Schema tag of this message.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::PreparedResultAccepted { .. } => "PreparedResultAccepted",
            Self::PreparedResultRejected { .. } => "PreparedResultRejected",
            Self::ActionResultCommitted { .. } => "ActionResultCommitted",
            Self::ActionResultQuarantined { .. } => "ActionResultQuarantined",
            Self::ActionTerminalFailure { .. } => "ActionTerminalFailure",
        }
    }

    /// The authority minting this decision/notification.
    #[must_use]
    pub fn authority(&self) -> &CoordinatorAuthority {
        match self {
            Self::PreparedResultAccepted { proof, .. }
            | Self::PreparedResultRejected { proof, .. }
            | Self::ActionResultCommitted { proof, .. }
            | Self::ActionResultQuarantined { proof, .. }
            | Self::ActionTerminalFailure { proof, .. } => proof.authority(),
        }
    }
}

// ---------------------------------------------------------------------
// Fixtures + audits — the J024 acceptance surface.
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::{ClusterId, CoordinatorIncarnationId};
    use crate::durable_ids::BuildOperationId;

    fn fixture_authority(term: u64) -> CoordinatorAuthority {
        CoordinatorAuthority {
            cluster_id: ClusterId("cluster-j024".to_owned()),
            credential_generation: 1,
            term,
            incarnation_id: CoordinatorIncarnationId(0xA024),
        }
    }

    fn fixture_identity(tag: u128) -> DurableWireIdentity {
        DurableWireIdentity {
            operation: BuildOperationId(tag),
            generation: crate::generation::ActionGenerationId(0x60),
            attempt: crate::generation::AttemptId(20),
            lease: crate::generation::ExecutionLeaseId(30),
        }
    }

    fn tagged_key(tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: crate::result_identity::DigestAlgorithm::Sha256V1,
            domain: "rabs.action-key.sha256.v1",
            bytes: [tag; 32],
        }
    }

    fn tagged_object(tag: u8) -> ObjectId {
        ObjectId(tagged_key(tag))
    }

    #[test]
    fn j024_worker_vocabulary_is_exactly_one_offer_kind() {
        // Exhaustive single-arm match: adding ANY worker variant breaks
        // this compile — the worker commit hole cannot reopen silently.
        let msg = WorkerPublicationMessage::OfferPreparedActionResult {
            identity: fixture_identity(1),
            action_key: tagged_key(1),
            manifest_id: tagged_object(2),
            evidence_id: tagged_object(3),
        };
        let kind = match &msg {
            WorkerPublicationMessage::OfferPreparedActionResult { .. } => msg.kind(),
        };
        assert_eq!(kind, "OfferPreparedActionResult");
    }

    #[test]
    fn j024_coordinator_plane_is_authority_gated_end_to_end() {
        // Every coordinator-plane construction REQUIRES a full authority
        // value; the emitted message exposes exactly that authority.
        let authority = fixture_authority(7);
        let messages = [
            CoordinatorPublicationMessage::PreparedResultAccepted {
                proof: AuthorityProof::new(fixture_authority(7)),
                identity: fixture_identity(1),
            },
            CoordinatorPublicationMessage::PreparedResultRejected {
                proof: AuthorityProof::new(fixture_authority(7)),
                identity: fixture_identity(1),
                reason: OfferRejectionKind::DivergentCandidate,
            },
            CoordinatorPublicationMessage::ActionResultCommitted {
                proof: AuthorityProof::new(fixture_authority(7)),
                action_key: tagged_key(5),
                manifest_id: tagged_object(6),
                winner_generation_id: 11,
                winner_attempt: 20,
            },
            CoordinatorPublicationMessage::ActionResultQuarantined {
                proof: AuthorityProof::new(fixture_authority(7)),
                action_key: tagged_key(5),
                class: QuarantineClass::ObservableOnlyDivergence,
            },
            CoordinatorPublicationMessage::ActionTerminalFailure {
                proof: AuthorityProof::new(fixture_authority(7)),
                identity: fixture_identity(2),
            },
        ];
        for m in &messages {
            assert_eq!(m.authority().term, 7);
        }
        // Rejection reasons and quarantine classes carry stable tags.
        assert_eq!(
            CoordinatorPublicationMessage::PreparedResultRejected {
                proof: AuthorityProof::new(fixture_authority(8)),
                identity: fixture_identity(1),
                reason: OfferRejectionKind::GenerationTombstoned,
            }
            .kind(),
            "PreparedResultRejected"
        );
        assert_eq!(
            OfferRejectionKind::GenerationTombstoned.as_str(),
            "generation-tombstoned"
        );
        assert_eq!(
            QuarantineClass::ProjectionCompleteness.as_str(),
            "projection-completeness"
        );
        let _ = authority;
    }

    #[test]
    fn j024_schema_catalog_audits_both_planes_with_no_worker_commit() {
        // Walk EVERY variant of BOTH planes (exhaustive matches make any
        // new variant a compile error here until the catalog is updated
        // consciously) and pin the six-schema catalog.
        let worker_kinds = [WorkerPublicationMessage::OfferPreparedActionResult {
            identity: fixture_identity(1),
            action_key: tagged_key(1),
            manifest_id: tagged_object(2),
            evidence_id: tagged_object(3),
        }]
        .iter()
        .map(|m| match m {
            WorkerPublicationMessage::OfferPreparedActionResult { .. } => m.kind(),
        })
        .collect::<Vec<_>>();

        let coordinator_kinds = [
            CoordinatorPublicationMessage::PreparedResultAccepted {
                proof: AuthorityProof::new(fixture_authority(1)),
                identity: fixture_identity(1),
            },
            CoordinatorPublicationMessage::PreparedResultRejected {
                proof: AuthorityProof::new(fixture_authority(1)),
                identity: fixture_identity(1),
                reason: OfferRejectionKind::ManifestInvalid,
            },
            CoordinatorPublicationMessage::ActionResultCommitted {
                proof: AuthorityProof::new(fixture_authority(1)),
                action_key: tagged_key(5),
                manifest_id: tagged_object(6),
                winner_generation_id: 11,
                winner_attempt: 20,
            },
            CoordinatorPublicationMessage::ActionResultQuarantined {
                proof: AuthorityProof::new(fixture_authority(1)),
                action_key: tagged_key(5),
                class: QuarantineClass::SemanticDivergence,
            },
            CoordinatorPublicationMessage::ActionTerminalFailure {
                proof: AuthorityProof::new(fixture_authority(1)),
                identity: fixture_identity(2),
            },
        ]
        .iter()
        .map(|m| match m {
            CoordinatorPublicationMessage::PreparedResultAccepted { .. } => m.kind(),
            CoordinatorPublicationMessage::PreparedResultRejected { .. } => m.kind(),
            CoordinatorPublicationMessage::ActionResultCommitted { .. } => m.kind(),
            CoordinatorPublicationMessage::ActionResultQuarantined { .. } => m.kind(),
            CoordinatorPublicationMessage::ActionTerminalFailure { .. } => m.kind(),
        })
        .collect::<Vec<_>>();

        let mut seen = worker_kinds.clone();
        seen.extend(coordinator_kinds);
        seen.sort_unstable();
        let mut expected = PUBLICATION_SCHEMAS.to_vec();
        expected.sort_unstable();
        assert_eq!(
            seen, expected,
            "publication vocabulary drifted from the pinned catalog"
        );

        // THE R50 assertion: nothing the worker says is a commit, and no
        // worker-authoritative commit schema exists in the catalog.
        for kind in &worker_kinds {
            assert!(!kind.to_lowercase().contains("commit"));
        }
        assert!(!PUBLICATION_SCHEMAS.contains(&"CommitActionResult"));
    }
}
