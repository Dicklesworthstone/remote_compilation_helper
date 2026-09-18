//! Authenticated worker control-session admission (bead bd-085cm, bridge
//! plan Phase S5).
//!
//! Every decision a coordinator makes about a worker's control session is
//! here, and every one of them is composed from machinery that already
//! existed and was already tested in isolation — version negotiation
//! ([`crate::version_negotiation`]), enrolled identity
//! ([`crate::identity_store`]), least-privilege capability tokens
//! ([`crate::capability_tokens`]), pre-allocation envelope limits
//! ([`crate::envelope`]) and per-domain sequence windows
//! ([`crate::sequence_domains`]).
//!
//! That composition is the point. The first S5 attempt reached the fleet
//! with a hand-rolled newline-JSON handshake carrying a hardcoded token id
//! and a substring check for "session-ok": every pure decision below
//! existed and was unit-tested, and the wire called none of them. A
//! capability check that the transport never invokes is not a capability
//! check. So this module is deliberately the ONLY place a session verdict
//! is formed, and the transports (worker and coordinator) do I/O and
//! serialization exclusively — they cannot reach a verdict of their own.
//!
//! **R50 is structural here, not advisory.** [`WorkerFrame`] is a closed
//! vocabulary with no commit or publish variant, so a worker cannot
//! *express* a commit; and because coordinator-only tags are nonetheless
//! nameable on the wire, [`WorkerFrame::from_wire_tag`] resolves them to a
//! typed [`SessionRefusal::ForbiddenByRole`] rather than to "unknown
//! frame". An attacker's commit attempt and a version skew must not be
//! reported the same way.

use crate::capability_tokens::{CapabilityKind, CapabilityToken, TokenRefusal, validate};
use crate::envelope::{EnvelopeLimits, EnvelopeRejection, RabsEnvelope, admit_envelope};
use crate::identity_store::{
    BindingRefusal, BindingVerdict, IdentityStore, SessionBinding, TransportIdentity, TrustScope,
};
use crate::sequence_domains::{DomainSet, ReceiveOutcome, SequenceDomain};
use crate::version_negotiation::{Negotiation, VersionHello, VersionRefusal};

/// Frames a WORKER may originate on the control session.
///
/// Closed on purpose. R50 says only the coordinator commits, so there is
/// no commit or publish variant for a worker to construct — the absence
/// is the enforcement, and [`WorkerFrame::from_wire_tag`] keeps it true
/// for bytes arriving off the wire as well as for values in this process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerFrame {
    /// Opening claim: versions, identity, capability token, capabilities.
    Hello,
    /// Liveness plus current capability/pressure.
    Heartbeat,
    /// The outcome of one canonical execution: an OFFER carrying content
    /// digests. Never a published pointer — publication is the
    /// coordinator's, and this frame cannot carry one.
    ExecResult,
    /// Prepared-result metadata offered for the coordinator to consider.
    PreparedOffer,
    /// A typed per-request error that does not end the session.
    Error,
}

impl WorkerFrame {
    /// The stable wire tag.
    #[must_use]
    pub const fn wire_tag(self) -> u16 {
        match self {
            Self::Hello => 1,
            Self::Heartbeat => 2,
            Self::ExecResult => 3,
            Self::PreparedOffer => 4,
            Self::Error => 5,
        }
    }

    /// The sequence domain a frame belongs to.
    ///
    /// Heartbeats are best-effort telemetry; losing one must not stall the
    /// action stream, and a stale one must not be able to replay an action
    /// outcome. Keeping them in separate domains is what makes that true.
    #[must_use]
    pub const fn domain(self) -> SequenceDomain {
        match self {
            Self::Hello => SequenceDomain::AuthorityControl,
            Self::Heartbeat => SequenceDomain::TelemetryBestEffort,
            Self::ExecResult | Self::PreparedOffer | Self::Error => SequenceDomain::ActionLifecycle,
        }
    }

    /// Resolve a wire tag a worker presented.
    ///
    /// Coordinator-only tags resolve to [`SessionRefusal::ForbiddenByRole`]
    /// rather than to an unknown-frame error: "this peer tried to commit"
    /// and "this peer speaks a newer protocol" are different incidents and
    /// must not share a reason code.
    ///
    /// # Errors
    /// [`SessionRefusal::ForbiddenByRole`] for a coordinator-only tag,
    /// [`SessionRefusal::UnknownFrame`] for a tag in neither vocabulary.
    pub fn from_wire_tag(tag: u16) -> Result<Self, SessionRefusal> {
        match tag {
            1 => Ok(Self::Hello),
            2 => Ok(Self::Heartbeat),
            3 => Ok(Self::ExecResult),
            4 => Ok(Self::PreparedOffer),
            5 => Ok(Self::Error),
            _ => match CoordinatorFrame::from_wire_tag(tag) {
                Some(coordinator_only) => Err(SessionRefusal::ForbiddenByRole {
                    attempted: coordinator_only,
                }),
                None => Err(SessionRefusal::UnknownFrame { tag }),
            },
        }
    }
}

/// Frames only a COORDINATOR may originate.
///
/// Named here so a worker presenting one is refused as a role violation
/// with the attempted frame in the refusal, rather than being waved off as
/// an unknown tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoordinatorFrame {
    /// Session accepted, carrying the negotiated versions.
    SessionOk,
    /// Session refused, carrying the typed reason.
    SessionRefused,
    /// Liveness probe.
    Ping,
    /// A canonical execution request (namespace spec + argv).
    CanonicalExec,
    /// Cancellation of an in-flight execution.
    Cancel,
    /// Publication of a result. Coordinator-only: this is R50.
    Commit,
}

impl CoordinatorFrame {
    /// The stable wire tag.
    #[must_use]
    pub const fn wire_tag(self) -> u16 {
        match self {
            Self::SessionOk => 101,
            Self::SessionRefused => 102,
            Self::Ping => 103,
            Self::CanonicalExec => 104,
            Self::Cancel => 105,
            Self::Commit => 106,
        }
    }

    /// Resolve a coordinator tag, or `None` when it is not one.
    #[must_use]
    pub const fn from_wire_tag(tag: u16) -> Option<Self> {
        match tag {
            101 => Some(Self::SessionOk),
            102 => Some(Self::SessionRefused),
            103 => Some(Self::Ping),
            104 => Some(Self::CanonicalExec),
            105 => Some(Self::Cancel),
            106 => Some(Self::Commit),
            _ => None,
        }
    }
}

/// What a worker's opening frame CLAIMS. Claims, not facts: every field
/// here is checked against evidence the coordinator already holds before
/// any of it is believed.
#[derive(Debug, Clone)]
pub struct WorkerHelloClaims {
    /// The worker's supported version ranges.
    pub versions: VersionHello,
    /// The peer id the worker claims to be. Checked against the id the
    /// TRANSPORT authenticated — a claim that diverges is a refusal, never
    /// a relabelling.
    pub claimed_peer: [u8; 32],
    /// The session this handshake opens.
    pub session_id: u64,
    /// The operation the capability token was minted for.
    pub operation_id: u64,
    /// The presented capability token.
    pub token: CapabilityToken,
    /// Whether the worker reports a usable canonical namespace.
    pub canonical_namespace: bool,
    /// Executor slots the worker advertises.
    pub slots: u32,
}

/// Every way a control session can be refused, each naming its evidence.
///
/// One variant per distinguishable cause on purpose: an operator reading
/// "refused" learns nothing, and a fleet that reports a rotated key and a
/// forged commit identically cannot be triaged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionRefusal {
    /// No overlapping transport/application version.
    Version(VersionRefusal),
    /// The identity claim did not prove against the store.
    Identity(BindingRefusal),
    /// The identity rotated after this session bound to it: re-handshake.
    StaleBinding {
        /// Generation the session bound at.
        bound: u32,
        /// Current generation.
        current: u32,
    },
    /// The identity vanished (revoked/unknown) mid-session.
    IdentityGone,
    /// The capability token failed validation.
    Token(TokenRefusal),
    /// The token is valid but authorizes the wrong thing.
    WrongCapabilityKind {
        /// What was presented.
        presented: CapabilityKind,
        /// What this session requires.
        required: CapabilityKind,
    },
    /// The coordinator requires canonical execution; the worker has none.
    NotCanonicalCapable,
    /// A coordinator-only frame arrived from a worker (R50).
    ForbiddenByRole {
        /// The coordinator-only frame the worker attempted.
        attempted: CoordinatorFrame,
    },
    /// A tag in neither vocabulary.
    UnknownFrame {
        /// The unrecognized tag.
        tag: u16,
    },
    /// The envelope was refused before any allocation for its payload.
    Envelope(EnvelopeRejection),
    /// A worker presented coordinator authority (R50): the one power a
    /// worker never holds, refused explicitly rather than ignored.
    WorkerPresentedCoordinatorAuthority,
    /// An offer arrived without the durable identity naming the attempt
    /// and lease it answers, so it could not be attributed to anything.
    OfferWithoutIdentity,
    /// The frame's envelope does not belong to this session.
    WrongSession {
        /// The session id the envelope carried.
        presented: u128,
    },
    /// A sequence at or below the domain's high-water: a replay, or a
    /// stale incarnation resending what a previous one already delivered.
    ReplayedSequence {
        /// The domain.
        domain: SequenceDomain,
        /// The sequence presented.
        sequence: u64,
    },
    /// A sequence so far ahead that buffering it would be unbounded.
    SequenceWindowExceeded {
        /// The domain.
        domain: SequenceDomain,
        /// The sequence presented.
        sequence: u64,
    },
}

/// The coordinator's admission policy for worker sessions.
///
/// Grouped rather than passed as eight loose arguments, because these
/// values are one decision: which peers, running what, holding which
/// capability, under what limits. A caller that can get them out of order
/// can admit the wrong worker, and the type makes that impossible.
#[derive(Debug, Clone, Copy)]
pub struct SessionPolicy<'a> {
    /// The coordinator's own supported version ranges.
    pub ours: VersionHello,
    /// Token ids revoked since minting.
    pub revoked_token_ids: &'a [u64],
    /// The current lease sequence, for token expiry.
    pub current_seq: u64,
    /// The capability a worker session requires.
    pub required_capability: CapabilityKind,
    /// Whether a usable canonical namespace is mandatory.
    pub require_canonical: bool,
    /// Pre-allocation envelope limits.
    pub limits: EnvelopeLimits,
    /// Bound on out-of-order buffering per sequence domain.
    pub max_sequence_buffer: usize,
}

/// A granted session: what both sides agreed and what the coordinator
/// proved about the peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionGrant {
    /// Negotiated transport version.
    pub transport_version: u32,
    /// Negotiated application version.
    pub application_version: u32,
    /// The durable binding to the identity generation proven at handshake.
    pub binding: SessionBinding,
    /// The trust scope the verified identity holds.
    pub scope: TrustScope,
    /// Slots the worker advertised (advisory scheduling input).
    pub slots: u32,
}

/// A frame the session accepted, and what it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceptedFrame {
    /// The resolved worker frame.
    pub frame: WorkerFrame,
    /// Its sequence domain.
    pub domain: SequenceDomain,
    /// Whether it advanced the domain (`false` for an idempotent
    /// duplicate the sender may retransmit after a resume).
    pub delivered: bool,
}

/// The live coordinator-side state of one worker control session.
#[derive(Debug, Clone)]
pub struct CoordinatorSession {
    grant: SessionGrant,
    domains: DomainSet,
    limits: EnvelopeLimits,
    required_capability: CapabilityKind,
}

impl CoordinatorSession {
    /// Admit a worker's opening claim, or refuse it with the reason.
    ///
    /// The order of checks is deliberate and is the cheap-and-certain
    /// first rule: version overlap (no shared language ends it), then
    /// identity (an unproven peer's other claims are not worth reading),
    /// then capability (an authenticated peer still needs authorization),
    /// then the canonical-execution requirement (a capability the host
    /// simply lacks). Reordering it would spend work on claims from peers
    /// that were never going to be admitted.
    ///
    /// # Errors
    /// A [`SessionRefusal`] naming the first check that failed.
    pub fn admit_hello(
        store: &IdentityStore,
        transport: &TransportIdentity,
        claims: &WorkerHelloClaims,
        policy: &SessionPolicy<'_>,
    ) -> Result<Self, SessionRefusal> {
        let SessionPolicy {
            ours,
            revoked_token_ids,
            current_seq,
            required_capability,
            require_canonical,
            limits,
            max_sequence_buffer,
        } = *policy;
        let (transport_version, application_version) =
            match crate::version_negotiation::negotiate(&ours, &claims.versions) {
                Negotiation::Agreed {
                    transport,
                    application,
                } => (transport, application),
                Negotiation::Refused(refusal) => return Err(SessionRefusal::Version(refusal)),
            };

        let bound = store
            .bind_transport_identity(&claims.claimed_peer, transport, claims.session_id)
            .map_err(SessionRefusal::Identity)?;

        validate(
            &claims.token,
            revoked_token_ids,
            current_seq,
            claims.session_id,
            claims.operation_id,
        )
        .map_err(SessionRefusal::Token)?;
        if claims.token.kind != required_capability {
            return Err(SessionRefusal::WrongCapabilityKind {
                presented: claims.token.kind,
                required: required_capability,
            });
        }

        if require_canonical && !claims.canonical_namespace {
            return Err(SessionRefusal::NotCanonicalCapable);
        }

        Ok(Self {
            grant: SessionGrant {
                transport_version,
                application_version,
                binding: bound.binding,
                scope: bound.scope,
                slots: claims.slots,
            },
            domains: DomainSet::new(max_sequence_buffer),
            limits,
            required_capability,
        })
    }

    /// What this session granted.
    #[must_use]
    pub const fn grant(&self) -> &SessionGrant {
        &self.grant
    }

    /// The capability kind this session requires of its worker.
    #[must_use]
    pub const fn required_capability(&self) -> CapabilityKind {
        self.required_capability
    }

    /// Admit one frame a worker sent mid-session.
    ///
    /// Re-checks the identity binding on EVERY frame rather than trusting
    /// the handshake forever: a key revoked or rotated while a session is
    /// open must stop that session's next frame, not its next handshake.
    /// That is the whole value of binding to a generation.
    ///
    /// # Errors
    /// A [`SessionRefusal`] naming the failed check.
    pub fn admit_frame(
        &mut self,
        store: &IdentityStore,
        wire_tag: u16,
        envelope: &RabsEnvelope,
    ) -> Result<AcceptedFrame, SessionRefusal> {
        // R50 and vocabulary first: a forbidden frame is refused before its
        // envelope is even measured, so a commit attempt cannot be masked by
        // an oversize rejection and counted as a mere limit violation.
        let frame = WorkerFrame::from_wire_tag(wire_tag)?;

        match store.check_binding(&self.grant.binding) {
            BindingVerdict::Bound => {}
            BindingVerdict::StaleGeneration { bound, current } => {
                return Err(SessionRefusal::StaleBinding { bound, current });
            }
            BindingVerdict::IdentityGone => return Err(SessionRefusal::IdentityGone),
        }

        if envelope.session_id != u128::from(self.grant.binding.session_id) {
            return Err(SessionRefusal::WrongSession {
                presented: envelope.session_id,
            });
        }

        // R50 restated in the envelope's own vocabulary: a WORKER frame is
        // never authority-bearing. Coordinator authority is the
        // coordinator's to present, so a worker carrying one is claiming
        // precisely the power R50 denies it — refused explicitly rather
        // than merely ignored, because a field that is silently dropped is
        // a field someone will eventually come to rely on.
        if envelope.coordinator_authority.is_some() {
            return Err(SessionRefusal::WorkerPresentedCoordinatorAuthority);
        }
        // Every claimed size is checked BEFORE anything is allocated for
        // the payload.
        admit_envelope(envelope, &self.limits, false, &[]).map_err(SessionRefusal::Envelope)?;

        // An offer is an offer FOR something. Without durable identity the
        // coordinator cannot know which attempt and lease it answers, and a
        // result that cannot be attributed is worse than no result.
        if matches!(frame, WorkerFrame::ExecResult | WorkerFrame::PreparedOffer)
            && envelope.durable_identity.is_none()
        {
            return Err(SessionRefusal::OfferWithoutIdentity);
        }

        let domain = frame.domain();
        match self.domains.window(domain).receive(envelope.sequence) {
            ReceiveOutcome::Deliver => Ok(AcceptedFrame {
                frame,
                domain,
                delivered: true,
            }),
            // A duplicate is idempotent, not an attack: after a resume the
            // sender legitimately retransmits from its last acked point.
            // It is accepted and NOT delivered twice.
            ReceiveOutcome::DuplicateIgnored => Ok(AcceptedFrame {
                frame,
                domain,
                delivered: false,
            }),
            ReceiveOutcome::Buffered => Ok(AcceptedFrame {
                frame,
                domain,
                delivered: false,
            }),
            ReceiveOutcome::WindowExceeded => Err(SessionRefusal::SequenceWindowExceeded {
                domain,
                sequence: envelope.sequence,
            }),
        }
    }

    /// The per-domain point a reconnecting worker must resume from.
    ///
    /// Buffered-but-unacked entries are dropped by
    /// [`crate::sequence_domains::DomainWindow::resume_from`], so the
    /// worker retransmits them — which is why a duplicate after resume is
    /// an expected, accepted no-op above rather than a replay refusal.
    pub fn resume_points(&mut self) -> Vec<(SequenceDomain, u64)> {
        SequenceDomain::ALL
            .iter()
            .map(|domain| (*domain, self.domains.window(*domain).resume_from()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability_tokens::mint;
    use crate::envelope::{DEFAULT_LIMITS, PrivacyClass};
    use crate::identity_store::IdentityStore;
    use crate::version_negotiation::VersionRange;
    use crate::wire_time::PeerId;

    const PEER: [u8; 32] = [7u8; 32];
    const FINGERPRINT: [u8; 32] = [9u8; 32];
    const SESSION: u64 = 42;
    const OPERATION: u64 = 3;

    fn versions() -> VersionHello {
        VersionHello {
            transport: VersionRange {
                minimum_compatible: 1,
                current: 2,
            },
            application: VersionRange {
                minimum_compatible: 1,
                current: 3,
            },
        }
    }

    fn enrolled() -> IdentityStore {
        let mut store = IdentityStore::default();
        store
            .create(PEER, FINGERPRINT, TrustScope::Worker, 1)
            .expect("enroll worker identity");
        store
    }

    fn transport() -> TransportIdentity {
        TransportIdentity {
            peer_id: PEER,
            fingerprint: FINGERPRINT,
        }
    }

    fn claims() -> WorkerHelloClaims {
        WorkerHelloClaims {
            versions: versions(),
            claimed_peer: PEER,
            session_id: SESSION,
            operation_id: OPERATION,
            token: mint(
                11,
                CapabilityKind::ExecuteAction,
                SESSION,
                OPERATION,
                "worker/exec",
                100,
            )
            .expect("mint"),
            canonical_namespace: true,
            slots: 8,
        }
    }

    fn policy() -> SessionPolicy<'static> {
        SessionPolicy {
            ours: versions(),
            revoked_token_ids: &[],
            current_seq: 50,
            required_capability: CapabilityKind::ExecuteAction,
            require_canonical: true,
            limits: DEFAULT_LIMITS,
            max_sequence_buffer: 16,
        }
    }

    fn session(store: &IdentityStore) -> CoordinatorSession {
        CoordinatorSession::admit_hello(store, &transport(), &claims(), &policy())
            .expect("valid session must be admitted")
    }

    fn envelope(sequence: u64, authority: bool) -> RabsEnvelope {
        RabsEnvelope {
            application_version: 3,
            session_id: u128::from(SESSION),
            authenticated_roles: vec!["worker".to_string()],
            coordinator_authority: None,
            trace_id: 1,
            sender: PeerId("worker".to_string()),
            destination: PeerId("coordinator".to_string()),
            durable_identity: None,
            subscriber_id: None,
            idempotency_key: u128::from(sequence),
            sequence_domain: "action".to_string(),
            sequence,
            payload_length: 128,
            collection_counts: vec![1],
            nesting_depth: 2,
            manifest_fanout: 0,
            decompressed_bytes: 0,
            capability_scope: vec!["worker/exec".to_string()],
            privacy: PrivacyClass::ProjectScoped,
            response_to: None,
            resume_from: None,
            unknown_authority_fields: Vec::new(),
            unknown_plain_fields: Vec::new(),
        }
        .tap_authority(authority)
    }

    // Authority-bearing frames need durable identity; give it to them
    // exactly when the frame under test is one.
    trait TapAuthority {
        fn tap_authority(self, authority: bool) -> Self;
    }
    impl TapAuthority for RabsEnvelope {
        fn tap_authority(mut self, authority: bool) -> Self {
            if authority {
                self.durable_identity = Some(crate::durable_ids::DurableWireIdentity {
                    operation: crate::durable_ids::BuildOperationId(u128::from(OPERATION)),
                    generation: crate::generation::ActionGenerationId(1),
                    attempt: crate::generation::AttemptId(1),
                    lease: crate::generation::ExecutionLeaseId(1),
                });
            }
            self
        }
    }

    #[test]
    fn valid_worker_is_admitted_with_the_negotiated_versions_and_proven_identity() {
        let store = enrolled();
        let session = session(&store);
        let grant = session.grant();
        assert_eq!(grant.transport_version, 2);
        assert_eq!(grant.application_version, 3);
        assert_eq!(grant.binding.peer_id, PEER);
        assert_eq!(grant.binding.session_id, SESSION);
        assert_eq!(grant.slots, 8);
        assert_eq!(session.required_capability(), CapabilityKind::ExecuteAction);
    }

    #[test]
    fn a_worker_claiming_another_peer_is_refused_on_identity_not_relabelled() {
        let store = enrolled();
        let mut forged = claims();
        forged.claimed_peer = [1u8; 32];
        // The transport authenticated PEER; the wire claims someone else.
        // A configuration label must never reconcile that difference.
        assert_eq!(
            CoordinatorSession::admit_hello(&store, &transport(), &forged, &policy(),)
                .expect_err("a diverging identity claim must be refused"),
            SessionRefusal::Identity(BindingRefusal::ClaimedIdMismatch)
        );
    }

    #[test]
    fn an_unenrolled_or_revoked_worker_cannot_open_a_session() {
        // Never enrolled.
        let empty = IdentityStore::default();
        assert_eq!(
            CoordinatorSession::admit_hello(&empty, &transport(), &claims(), &policy(),)
                .expect_err("an unknown peer must not be admitted"),
            SessionRefusal::Identity(BindingRefusal::UnknownPeer)
        );

        // Enrolled then revoked.
        let mut store = enrolled();
        store.revoke(PEER, 2).expect("revoke");
        assert_eq!(
            CoordinatorSession::admit_hello(&store, &transport(), &claims(), &policy(),)
                .expect_err("a revoked peer must not be admitted"),
            SessionRefusal::Identity(BindingRefusal::RevokedIdentity)
        );
    }

    #[test]
    fn a_stale_key_after_rotation_is_refused_and_names_the_generation() {
        let mut store = enrolled();
        store.rotate(PEER, [11u8; 32], 2).expect("rotate");
        // The worker still presents the OLD fingerprint.
        let SessionRefusal::Identity(BindingRefusal::FingerprintMismatch { matches_generation }) =
            CoordinatorSession::admit_hello(&store, &transport(), &claims(), &policy())
                .expect_err("a stale key must not be admitted")
        else {
            panic!("a rotated identity must refuse on fingerprint, not on something else");
        };
        assert_eq!(
            matches_generation,
            Some(1),
            "the refusal must say which generation the old key WAS, so an \
             operator can tell a stale worker from an impostor"
        );
    }

    #[test]
    fn capability_token_must_be_valid_and_for_the_right_thing() {
        let store = enrolled();
        // Revoked token id.
        assert_eq!(
            CoordinatorSession::admit_hello(
                &store,
                &transport(),
                &claims(),
                &SessionPolicy {
                    revoked_token_ids: &[11],
                    ..policy()
                },
            )
            .expect_err("a revoked token must not be admitted"),
            SessionRefusal::Token(TokenRefusal::Revoked)
        );
        // Expired lease (sequence past the token's bound).
        assert_eq!(
            CoordinatorSession::admit_hello(
                &store,
                &transport(),
                &claims(),
                &SessionPolicy {
                    current_seq: 100,
                    ..policy()
                },
            )
            .expect_err("an expired lease must not be admitted"),
            SessionRefusal::Token(TokenRefusal::LeaseExpired(100))
        );
        // A VALID token for the wrong capability: authenticated, authorized
        // for something else. Least privilege means this is still a refusal.
        let mut wrong = claims();
        wrong.token = mint(
            12,
            CapabilityKind::ReadSecret,
            SESSION,
            OPERATION,
            "slot/registry",
            100,
        )
        .expect("mint");
        assert_eq!(
            CoordinatorSession::admit_hello(&store, &transport(), &wrong, &policy(),)
                .expect_err("a token for another capability must not open an exec session"),
            SessionRefusal::WrongCapabilityKind {
                presented: CapabilityKind::ReadSecret,
                required: CapabilityKind::ExecuteAction,
            }
        );
    }

    #[test]
    fn version_skew_refuses_before_identity_is_even_consulted() {
        // An empty store would refuse on identity; a version gap must win,
        // because two peers with no shared language cannot exchange a
        // meaningful identity proof either.
        let empty = IdentityStore::default();
        let mut ancient = claims();
        ancient.versions.application = VersionRange {
            minimum_compatible: 99,
            current: 99,
        };
        assert!(matches!(
            CoordinatorSession::admit_hello(&empty, &transport(), &ancient, &policy(),),
            Err(SessionRefusal::Version(_))
        ));
    }

    #[test]
    fn a_host_without_canonical_namespace_is_refused_when_it_is_required() {
        let store = enrolled();
        let mut weak = claims();
        weak.canonical_namespace = false;
        assert_eq!(
            CoordinatorSession::admit_hello(&store, &transport(), &weak, &policy(),)
                .expect_err("canonical execution cannot run on a host that lacks it"),
            SessionRefusal::NotCanonicalCapable
        );
        // ...and the same host IS admissible when canonical is not required.
        assert!(
            CoordinatorSession::admit_hello(
                &store,
                &transport(),
                &weak,
                &SessionPolicy {
                    require_canonical: false,
                    ..policy()
                },
            )
            .is_ok()
        );
    }

    #[test]
    fn r50_a_worker_cannot_commit_and_the_attempt_is_named_as_such() {
        let store = enrolled();
        let mut live = session(&store);
        // The worker frame vocabulary has no commit variant at all...
        assert!(
            WorkerFrame::from_wire_tag(CoordinatorFrame::Commit.wire_tag()).is_err(),
            "a commit tag must never resolve to a worker frame"
        );
        // ...and a worker presenting the coordinator's commit tag is refused
        // as a ROLE violation, not as an unknown frame. The distinction is
        // the incident: one is an impostor, the other is version skew.
        assert_eq!(
            live.admit_frame(
                &store,
                CoordinatorFrame::Commit.wire_tag(),
                &envelope(1, true)
            )
            .expect_err("a worker commit attempt must be refused"),
            SessionRefusal::ForbiddenByRole {
                attempted: CoordinatorFrame::Commit
            }
        );
        // Every coordinator-only frame is refused the same way.
        for attempted in [
            CoordinatorFrame::CanonicalExec,
            CoordinatorFrame::Cancel,
            CoordinatorFrame::Ping,
            CoordinatorFrame::SessionOk,
            CoordinatorFrame::SessionRefused,
        ] {
            assert_eq!(
                live.admit_frame(&store, attempted.wire_tag(), &envelope(1, true))
                    .expect_err("coordinator-only frames must not come from a worker"),
                SessionRefusal::ForbiddenByRole { attempted }
            );
        }
        // A tag in neither vocabulary is its own, different answer.
        assert_eq!(
            live.admit_frame(&store, 60000, &envelope(1, true))
                .expect_err("an unknown tag must be refused"),
            SessionRefusal::UnknownFrame { tag: 60000 }
        );
    }

    #[test]
    fn replayed_and_out_of_session_frames_are_refused_or_ignored_idempotently() {
        let store = enrolled();
        let mut live = session(&store);

        // First action frame delivers.
        let accepted = live
            .admit_frame(
                &store,
                WorkerFrame::ExecResult.wire_tag(),
                &envelope(1, true),
            )
            .expect("in-order frame");
        assert!(accepted.delivered);
        assert_eq!(accepted.domain, SequenceDomain::ActionLifecycle);

        // The SAME sequence again is an idempotent no-op, not a delivery:
        // after a resume a worker legitimately retransmits, and refusing
        // that would break reconnection rather than stop an attacker.
        let repeat = live
            .admit_frame(
                &store,
                WorkerFrame::ExecResult.wire_tag(),
                &envelope(1, true),
            )
            .expect("a duplicate is accepted");
        assert!(
            !repeat.delivered,
            "a replayed sequence must never be delivered twice"
        );

        // A frame for a different session is refused outright.
        let mut foreign = envelope(2, true);
        foreign.session_id = 999;
        assert_eq!(
            live.admit_frame(&store, WorkerFrame::ExecResult.wire_tag(), &foreign)
                .expect_err("a frame from another session must be refused"),
            SessionRefusal::WrongSession { presented: 999 }
        );

        // Heartbeats live in their OWN domain: a telemetry sequence must
        // not be able to advance or replay the action stream.
        let heartbeat = live
            .admit_frame(
                &store,
                WorkerFrame::Heartbeat.wire_tag(),
                &envelope(1, false),
            )
            .expect("heartbeat sequence 1 is unused in its own domain");
        assert!(heartbeat.delivered);
        assert_eq!(heartbeat.domain, SequenceDomain::TelemetryBestEffort);
    }

    #[test]
    fn a_rotated_or_revoked_identity_stops_the_next_frame_not_the_next_handshake() {
        let mut store = enrolled();
        let mut live = session(&store);
        assert!(
            live.admit_frame(
                &store,
                WorkerFrame::Heartbeat.wire_tag(),
                &envelope(1, false)
            )
            .is_ok()
        );

        // Rotate the key while the session is open.
        store.rotate(PEER, [12u8; 32], 2).expect("rotate");
        assert_eq!(
            live.admit_frame(
                &store,
                WorkerFrame::Heartbeat.wire_tag(),
                &envelope(2, false)
            )
            .expect_err("a session bound to a superseded generation must stop"),
            SessionRefusal::StaleBinding {
                bound: 1,
                current: 2
            }
        );

        // Revocation is terminal and distinct from rotation.
        let mut store = enrolled();
        let mut live = session(&store);
        store.revoke(PEER, 3).expect("revoke");
        assert_eq!(
            live.admit_frame(
                &store,
                WorkerFrame::Heartbeat.wire_tag(),
                &envelope(1, false)
            )
            .expect_err("a revoked identity must stop its live session"),
            SessionRefusal::IdentityGone
        );
    }

    #[test]
    fn oversized_claims_are_refused_before_anything_is_allocated_for_them() {
        let store = enrolled();
        let mut live = session(&store);
        let mut huge = envelope(1, true);
        huge.payload_length = DEFAULT_LIMITS.max_payload_bytes + 1;
        assert_eq!(
            live.admit_frame(&store, WorkerFrame::ExecResult.wire_tag(), &huge)
                .expect_err("a payload above the limit must be refused from its claim alone"),
            SessionRefusal::Envelope(EnvelopeRejection::PayloadTooLarge {
                claimed: DEFAULT_LIMITS.max_payload_bytes + 1,
                limit: DEFAULT_LIMITS.max_payload_bytes,
            })
        );

        // A zip-bomb claim is refused on its decompressed size, not its
        // wire size.
        let mut bomb = envelope(1, true);
        bomb.decompressed_bytes = DEFAULT_LIMITS.max_decompressed_bytes + 1;
        assert_eq!(
            live.admit_frame(&store, WorkerFrame::ExecResult.wire_tag(), &bomb)
                .expect_err("a decompression claim above the limit must be refused"),
            SessionRefusal::Envelope(EnvelopeRejection::DecompressionTooLarge)
        );
    }

    #[test]
    fn an_offer_without_durable_identity_is_refused() {
        let store = enrolled();
        let mut live = session(&store);
        // ExecResult and PreparedOffer are offers against a specific
        // attempt/lease. Without that identity the coordinator cannot know
        // WHAT is being offered, so it is refused rather than guessed.
        assert_eq!(
            live.admit_frame(
                &store,
                WorkerFrame::PreparedOffer.wire_tag(),
                &envelope(1, false)
            )
            .expect_err("an offer must carry the identity it is an offer FOR"),
            SessionRefusal::OfferWithoutIdentity
        );
        // A heartbeat is not an offer and needs none.
        assert!(
            live.admit_frame(
                &store,
                WorkerFrame::Heartbeat.wire_tag(),
                &envelope(1, false)
            )
            .is_ok()
        );
    }

    #[test]
    fn r50_a_worker_that_presents_coordinator_authority_is_refused_for_that_reason() {
        use crate::authority::{ClusterId, CoordinatorAuthority, CoordinatorIncarnationId};
        let store = enrolled();
        let mut live = session(&store);
        let mut forged = envelope(1, true);
        forged.coordinator_authority = Some(CoordinatorAuthority {
            cluster_id: ClusterId("fleet-1".into()),
            incarnation_id: CoordinatorIncarnationId(1),
            term: 1,
            credential_generation: 1,
        });
        // Coordinator authority is the one power a worker never holds.
        // Ignoring the field would be worse than refusing it: a silently
        // dropped authority claim is one somebody eventually relies on.
        assert_eq!(
            live.admit_frame(&store, WorkerFrame::ExecResult.wire_tag(), &forged)
                .expect_err("a worker must not present coordinator authority"),
            SessionRefusal::WorkerPresentedCoordinatorAuthority
        );
    }

    #[test]
    fn resume_points_are_per_domain_high_water_marks() {
        let store = enrolled();
        let mut live = session(&store);
        for sequence in 1..=3 {
            assert!(
                live.admit_frame(
                    &store,
                    WorkerFrame::ExecResult.wire_tag(),
                    &envelope(sequence, true)
                )
                .expect("in-order")
                .delivered
            );
        }
        let points: Vec<_> = live.resume_points();
        let action = points
            .iter()
            .find(|(domain, _)| *domain == SequenceDomain::ActionLifecycle)
            .expect("action domain");
        assert_eq!(action.1, 3, "resume from the last contiguous delivery");
        let telemetry = points
            .iter()
            .find(|(domain, _)| *domain == SequenceDomain::TelemetryBestEffort)
            .expect("telemetry domain");
        assert_eq!(telemetry.1, 0, "an untouched domain resumes from zero");
    }
}
