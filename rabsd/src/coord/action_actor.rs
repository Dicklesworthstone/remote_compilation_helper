//! # rabs-coord ActionActor — the ONE authoritative actor per action key
//!
//! Bead `rabs-root-4pidu.25.3` (G003); plan §21. The [`ActionActor`] owns,
//! for exactly one action key:
//!
//! - the immutable action descriptor, its canonical key breakdown
//!   (whose final digest is both the action key and the descriptor
//!   digest — one serializer, F034), and the region binding from G001's
//!   [`coordinator_root`] constructor;
//! - the publication slot ([`PublicationSlotState`]) with at most one
//!   active [`ActionGeneration`] (admitted through the F031
//!   [`GenerationFence`], so a generation id is never reused) and the
//!   immutable publication history;
//! - the separately versioned serving/trust record
//!   ([`ActionServingStateRecord`] driven ONLY through the A020 legality
//!   table [`evaluate`]);
//! - cross-host subscribers, each keyed by its own
//!   [`BuildOperationId`] with priority/deadline/presentation and an
//!   independent [`SubscriberDeliveryState`] — there is deliberately NO
//!   actor-level BuildOperationId field and NO actor-level
//!   observable-commit bit (I29/I30): exposure lives only in per-subscriber
//!   delivery state and frontiers;
//! - the attempt set, where every attempt carries its own unique
//!   [`ExecutionLeaseId`] plus the worker incarnation it runs under, with
//!   selection receipts and generation-level retry/hedge budgets;
//! - prepared candidates and the compare-and-set winner: the first valid
//!   offer wins; byte-identical later offers are duplicates; a DIFFERENT
//!   canonical result after commit is divergence — it quarantines serving
//!   and opens an incident instead of replacing or coexisting with the
//!   committed result (§21.4);
//! - provisional artifacts and their transitive producer lineage;
//! - the append-only evidence set and the canonical event stream
//!   (provenance).
//!
//! ## Shape
//!
//! The decision core is pure and synchronous (deterministic lab testing,
//! same posture as the scheduler policy crates). [`ActionActorHost`] is the
//! thin Asupersync [`Actor`] shell that feeds [`ActionActorMsg`]s into the
//! core from a bounded mailbox under a coordinator region. Registry wiring,
//! reply channels, and durable rows land with G017/I018/H-series.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::pin::Pin;

use asupersync::actor::Actor;
use asupersync::cx::Cx;
use rabs_action::generation_fence::{FenceDecision, GenerationFence};
use rabs_action::serving_transitions::{
    RefuseReason, ServingTransitionTrigger, TransitionDecision, evaluate,
};
use rabs_action::state_machines::{
    AttemptState, ExposureFrontiers, PublicationSlotState, SubscriberDeliveryState,
};
use rabs_asupersync::region_tree::{Attribution, RegionSpec, attribution_chains, coordinator_root};
use rabs_key::action_key::{ActionKeyBreakdown, compute_action_key};
use rabs_protocol::authority_matrix::IsolationProfile;
use rabs_protocol::descriptor::{ActionDescriptor, SubscriberKind};
use rabs_protocol::durable_ids::BuildOperationId;
use rabs_protocol::generation::{
    ActionGeneration, ActionGenerationId, AttemptId, ExecutionLeaseId, LeaseRenewal,
    LeaseRenewalSeq, RenewalDecision, WorkerBootGeneration, WorkerIncarnationId,
};
use rabs_protocol::result_identity::{DigestAlgorithm, ObjectId, TypedDigest};
use rabs_protocol::serving::{ActionServingDisposition, ActionServingStateRecord, ServingValidity};
use rabs_protocol::wire_time::PeerId;

/// Retry attempts permitted per generation before new ones are refused.
pub const MAX_RETRIES_PER_GENERATION: u32 = 2;

/// Hedge attempts permitted per generation before new ones are refused.
pub const MAX_HEDGES_PER_GENERATION: u32 = 2;

/// Serving TTL applied to committed DETERMINISTIC-FAILURE publications
/// (`maximum_age_micros`); success publications carry no expiry here.
pub const DETERMINISTIC_FAILURE_TTL_MICROS: u64 = 24 * 60 * 60 * 1_000_000;

/// Queue priority stamped onto a promoted subscriber (§21.2: promotion
/// raises scheduler priority; it never touches the artifact identity).
pub const FOREGROUND_QUEUE_PRIORITY: u8 = 200;

// ---------------------------------------------------------------------------
// Attempt purpose (plan §21.4: purpose, not action class)
// ---------------------------------------------------------------------------

/// Why this attempt exists. Hedging/pre-commit verification is expressed
/// HERE — never as a new semantic key or class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptPurpose {
    /// The first execution for a generation.
    Primary,
    /// A fresh execution after a nonpublishable failure.
    Retry,
    /// A sibling racing the primary under its OWN lease.
    Hedge,
    /// Pre-commit verification pass.
    VerificationAudit,
    /// Post-commit determinism audit (can append evidence; can never
    /// publish — offers compare against the committed winner).
    DeterminismAudit,
}

impl AttemptPurpose {
    /// Whether opening this attempt consumes the generation retry budget.
    #[must_use]
    pub const fn consumes_retry_budget(self) -> bool {
        matches!(self, Self::Retry)
    }

    /// Whether opening this attempt consumes the hedge budget.
    #[must_use]
    pub const fn consumes_hedge_budget(self) -> bool {
        matches!(self, Self::Hedge)
    }

    /// Whether this is a post/pre-commit audit purpose.
    #[must_use]
    pub const fn is_audit(self) -> bool {
        matches!(self, Self::VerificationAudit | Self::DeterminismAudit)
    }
}

// ---------------------------------------------------------------------------
// Per-subscriber / per-attempt records
// ---------------------------------------------------------------------------

/// One cross-host subscriber of this action. Its operation id is the map
/// key and its delivery state is ITS OWN — the actor holds neither a
/// global operation id nor a global commit bit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionRequirements {
    /// Evidence bundles that must back the publication before serving.
    pub minimum_evidence_bundles: u32,
    /// Isolation profiles this subscriber accepts; `None` = any.
    pub acceptable_isolation: Option<Vec<IsolationProfile>>,
    /// Privacy scope that must match the attestation; `None` = any.
    pub privacy_scope: Option<String>,
    /// Output-platform contract digest that must match; `None` = any.
    pub platform: Option<TypedDigest>,
}

impl SubscriptionRequirements {
    /// Accept anything the fleet produces (the common agent case).
    #[must_use]
    pub const fn unrestricted() -> Self {
        Self {
            minimum_evidence_bundles: 0,
            acceptable_isolation: None,
            privacy_scope: None,
            platform: None,
        }
    }
}

/// Execution properties ATTESTED alongside a candidate offer; the facts
/// per-subscriber requirement filtering compares against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResultAttestation {
    /// Isolation profile the attempt actually ran under.
    pub isolation_attained: IsolationProfile,
    /// Privacy scope the execution was contained within.
    pub privacy_scope: String,
    /// Output-platform contract digest the execution targeted.
    pub platform: TypedDigest,
}

/// Per-subscriber outcome when consulting requirement filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequirementDecision {
    /// This subscriber may be served from the committed result now.
    Served,
    /// Identity-compatible but unsatisfied today (e.g. evidence
    /// shortfall): a verification attempt can still satisfy it.
    NeedsAdditionalVerification,
    /// This result can NEVER serve this subscriber as-is.
    Refused(RequirementRefusal),
}

/// Why a committed result can never satisfy a subscription.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequirementRefusal {
    /// Attained isolation profile not in the accepted set.
    IsolationUnacceptable,
    /// Attested privacy scope differs from the demanded scope.
    PrivacyScopeMismatch,
    /// Attested platform contract differs from the demanded platform.
    PlatformMismatch,
}

/// The strongest live interest across all subscribers: max priority and
/// earliest deadline (`None` deadline = unbounded).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StrongestInterest {
    /// Highest queue priority among live interests.
    pub priority: u8,
    /// Earliest deadline among live interests, if any is bounded.
    pub earliest_deadline_unix_micros: Option<i64>,
}
/// Per-subscriber record for one operation's subscription.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subscriber {
    /// The build operation this subscription belongs to (per-subscriber).
    pub operation: BuildOperationId,
    /// Subscriber interest kind (never a key component).
    pub kind: SubscriberKind,
    /// Queue priority (promotable).
    pub queue_priority: u8,
    /// Optional deadline (Unix micros).
    pub deadline_unix_micros: Option<i64>,
    /// Presentation contract digest (I24).
    pub presentation: TypedDigest,
    /// This subscriber's independent delivery state.
    pub delivery: SubscriberDeliveryState,
    /// This subscriber's two exposure frontiers.
    pub frontiers: ExposureFrontiers,
    /// What this subscription demands before accepting a result.
    pub requirements: SubscriptionRequirements,
    /// Reference count of live interests for THIS operation (§21.1);
    /// the subscription dies only when it reaches zero.
    pub interests: u32,
}

/// One concrete attempt registered under the active generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptEntry {
    /// Unique attempt identity.
    pub attempt: AttemptId,
    /// The generation this attempt executes under.
    pub generation: ActionGenerationId,
    /// THIS attempt's own execution lease (unique among live attempts).
    pub lease: ExecutionLeaseId,
    /// Executing worker.
    pub worker: PeerId,
    /// Worker durable boot generation.
    pub worker_boot_generation: WorkerBootGeneration,
    /// Worker process incarnation fencing clones/overlaps.
    pub worker_incarnation: WorkerIncarnationId,
    /// Why this attempt exists.
    pub purpose: AttemptPurpose,
    /// Attempt lifecycle position (A017 machine).
    pub state: AttemptState,
    /// Last accepted lease renewal sequence.
    pub lease_renewal_seq: LeaseRenewalSeq,
}

/// Coordinator-side receipt of a placement decision (the scheduler picks;
/// the actor records).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectionReceipt {
    /// Attempt placed.
    pub attempt: AttemptId,
    /// Worker chosen.
    pub worker: PeerId,
    /// Worker boot generation at placement.
    pub worker_boot_generation: WorkerBootGeneration,
    /// Purpose of the placed attempt.
    pub purpose: AttemptPurpose,
    /// Event sequence when recorded.
    pub recorded_at_event: u64,
}

/// An immutable committed-publication history entry. There is no transition
/// out of `Committed`; correction means quarantine or a new key epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicationEntry {
    /// Publication object identity (V1: the canonical result digest;
    /// H-series durable rows mint their own ids).
    pub publication_record: ObjectId,
    /// The committed canonical result (success OR deterministic failure).
    pub canonical_result: TypedDigest,
    /// Whether this publication is a terminal deterministic failure.
    pub deterministic_failure: bool,
    /// Event sequence of the commit.
    pub committed_at_event: u64,
    /// The winning attempt.
    pub winning_attempt: AttemptId,
}

/// A prepared candidate offered for compare-and-set commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedCandidateOffer {
    /// Generation the offering attempt believes is active.
    pub generation: ActionGenerationId,
    /// Offering attempt.
    pub attempt: AttemptId,
    /// Canonical result digest (success or deterministic-failure record).
    pub canonical_result: TypedDigest,
    /// Terminal deterministic failure rather than success.
    pub deterministic_failure: bool,
    /// Evidence bundle digest accompanying the offer.
    /// Evidence bundle digest accompanying the offer.
    pub evidence_bundle: TypedDigest,
    /// Execution properties attested by the offering attempt.
    pub attestation: ResultAttestation,
}

/// The compare-and-set winner state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CasWinner {
    /// Winning attempt.
    pub attempt: AttemptId,
    /// Committed canonical result.
    pub canonical_result: TypedDigest,
    /// Terminal deterministic failure rather than success.
    pub deterministic_failure: bool,
    /// Event sequence of the CAS decision.
    pub decided_at_event: u64,
    /// Attestation captured from the winning offer.
    pub attestation: ResultAttestation,
}

/// Append-only evidence entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceEntry {
    /// Digest of the evidence bundle.
    pub digest: TypedDigest,
    /// Event sequence when appended.
    pub recorded_at_event: u64,
}

// ---------------------------------------------------------------------------
// Events (canonical provenance stream)
// ---------------------------------------------------------------------------

/// What happened, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    /// Actor constructed and bound to its region.
    Constructed,
    /// A subscriber joined.
    Joined,
    /// A known subscriber re-joined (idempotent refresh).
    Rejoined,
    /// A subscriber was promoted to foreground interest.
    Promoted,
    /// A subscriber detached/cancelled.
    Cancelled,
    /// A generation opened (slot Absent → Executing).
    GenerationOpened,
    /// A generation closed (tombstoned; slot Executing → Absent).
    GenerationClosed,
    /// An attempt was registered with its own lease.
    AttemptRegistered,
    /// An attempt advanced along its state machine.
    AttemptAdvanced,
    /// A lease renewal was accepted.
    LeaseRenewed,
    /// A candidate offer arrived.
    CandidateOffered,
    /// A candidate won compare-and-set.
    CandidateAccepted,
    /// A candidate lost to an identical committed winner.
    CandidateRejectedDuplicate,
    /// A candidate diverged from the committed result.
    CandidateRejectedDivergent,
    /// The publication slot committed.
    Committed,
    /// Evidence appended.
    EvidenceRecorded,
    /// The versioned serving disposition changed.
    ServingChanged,
    /// A provisional artifact entered the lineage graph.
    ProvisionalRegistered,
    /// A live attempt lost to the winner and must drain.
    LostToWinner,
}

/// One canonical event: monotone sequence + what happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActionEvent {
    /// Monotone within the actor.
    pub seq: u64,
    /// What happened.
    pub kind: EventKind,
}

// ---------------------------------------------------------------------------
// Receipts
// ---------------------------------------------------------------------------

/// Outcome of a join.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinReceipt {
    /// Committed AND servable right now: served from the committed result;
    /// nothing re-committed and no generation opened.
    ServedFromCommitted,
    /// Committed but the versioned serving record refuses to serve now.
    CommittedButNotServable(ActionServingDisposition),
    /// Joined an in-flight execution generation.
    JoinedExecution,
    /// No result yet and no generation open: awaiting coordinator
    /// `open_generation`.
    AwaitingGeneration,
    /// Known subscriber re-joined; context refreshed and its interest
    /// reference count incremented.
    Rejoined {
        /// Live interest count for the operation after the re-join.
        interests: u32,
    },
}

/// Outcome of opening a generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenGenerationReceipt {
    /// Opened; slot is now Executing.
    Opened,
    /// Slot is not Absent (a generation is active or already committed).
    RefusedSlotNotAbsent(PublicationSlotState),
    /// The fence rejected the generation id as previously seen (ABA).
    RefusedGenerationReused,
}

/// Outcome of registering an attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterAttemptReceipt {
    /// Registered with its own lease; slot offered.
    Registered,
    /// No generation is active and this is not a post-commit audit.
    RefusedNoActiveGeneration,
    /// Names a generation other than the active one.
    RefusedForeignGeneration,
    /// Attempt id already exists.
    RefusedDuplicateAttempt,
    /// Lease id already held by a live attempt.
    RefusedDuplicateLease,
    /// Generation retry budget exhausted.
    RefusedRetryBudgetExhausted,
    /// Generation hedge budget exhausted.
    RefusedHedgeBudgetExhausted,
}

/// Outcome of advancing an attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdvanceAttemptReceipt {
    /// Advanced.
    Advanced,
    /// Unknown attempt id.
    RefusedUnknownAttempt,
    /// The A017 machine refuses the transition.
    RefusedIllegalTransition {
        /// Current state.
        from: AttemptState,
        /// Requested state.
        to: AttemptState,
    },
}

/// Outcome of a candidate offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfferReceipt {
    /// Won compare-and-set and committed the publication.
    AcceptedAsWinner,
    /// Byte-identical to the committed result: duplicate.
    RejectedAsDuplicate,
    /// Names a stale/foreign generation.
    RejectedAsStale,
    /// DIFFERENT canonical result vs the committed winner: divergence;
    /// serving quarantined and an incident opened.
    RejectedAsDivergent,
    /// Unknown attempt id.
    RefusedUnknownAttempt,
    /// Attempt is not in `PreparedResultOffered`.
    RefusedNotOfferable,
}

/// Outcome of a subscriber cancellation (§21.3 steps 4–6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelReceipt {
    /// Retained interests remain: shared work continues untouched.
    SharedWorkContinues {
        /// How many interests remain.
        retained: usize,
    },
    /// One reference of a multi-interest operation detached; the
    /// subscription itself survives with this many interests left.
    InterestDecremented {
        /// Remaining interest references for the operation.
        remaining: u32,
    },
    /// Last interest left while an attempt was near-complete: policy let
    /// the cache-populating generation finish.
    LastInterestFinishedForCache,
    /// Last interest left early: the generation was cancelled and drained.
    LastInterestCancelledGeneration,
    /// Unknown subscriber.
    UnknownSubscriber,
}

/// Outcome of a promotion request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromoteReceipt {
    /// Promoted to foreground interest.
    Promoted,
    /// Already foreground-class.
    AlreadyForeground,
    /// Unknown subscriber.
    UnknownSubscriber,
}

/// Outcome of applying a serving trigger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServingApplyReceipt {
    /// Disposition updated to a strictly newer revision.
    Applied(ActionServingDisposition),
    /// Divergence incident opened; serving quarantined.
    QuarantinedWithDivergenceIncident,
    /// No publication exists yet.
    RefusedNoPublication,
    /// The legality table refused.
    Refused(RefuseReason),
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/// A subscriber join request (per-subscriber fields only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinRequest {
    /// The subscribing build operation (its own id, NOT an actor field).
    pub operation: BuildOperationId,
    /// Interest kind.
    pub kind: SubscriberKind,
    /// Queue priority.
    pub queue_priority: u8,
    /// Optional deadline (Unix micros).
    pub deadline_unix_micros: Option<i64>,
    /// Presentation contract digest.
    pub presentation: TypedDigest,
    /// What this subscription demands before accepting a result.
    pub requirements: SubscriptionRequirements,
}

/// Registration of one attempt under its own lease.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterAttempt {
    /// Unique attempt identity.
    pub attempt: AttemptId,
    /// The generation this attempt believes it executes under.
    pub generation: ActionGenerationId,
    /// This attempt's own execution lease.
    pub lease: ExecutionLeaseId,
    /// Executing worker.
    pub worker: PeerId,
    /// Worker durable boot generation.
    pub worker_boot_generation: WorkerBootGeneration,
    /// Worker process incarnation.
    pub worker_incarnation: WorkerIncarnationId,
    /// Why this attempt exists.
    pub purpose: AttemptPurpose,
}

/// Everything the coordinator may ask the actor to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionActorMsg {
    /// Subscribe an operation.
    Join(JoinRequest),
    /// Promote an existing subscriber to foreground interest.
    Promote(BuildOperationId),
    /// Remove one subscriber's retained interest.
    CancelSubscriber(BuildOperationId),
    /// Open the single active generation (coordinator-minted id).
    OpenGeneration { generation: ActionGeneration },
    /// Register an attempt with its own lease.
    RegisterAttempt(Box<RegisterAttempt>),
    /// Advance an attempt along its machine.
    AdvanceAttempt {
        attempt: AttemptId,
        to: AttemptState,
    },
    /// Renew one attempt's lease.
    RenewLease {
        attempt: AttemptId,
        renewal: LeaseRenewal,
    },
    /// Offer a prepared candidate for compare-and-set.
    OfferCandidate(Box<PreparedCandidateOffer>),
    /// Append evidence; optionally completes required evidence.
    RecordEvidence {
        digest: TypedDigest,
        completes_requirements: bool,
    },
    /// Apply a serving-disposition trigger through the legality table.
    ServingTrigger(ServingTransitionTrigger),
    /// Register a provisional artifact with its direct producers.
    RegisterProvisional {
        artifact: ObjectId,
        producers: Vec<ObjectId>,
    },
}

// ---------------------------------------------------------------------------
// The actor
// ---------------------------------------------------------------------------

/// The authoritative ActionActor for exactly one action key (plan §21).
///
/// Pure decision core: synchronous, deterministic, event-sourcing its own
/// transitions into [`Self::events`]. Time enters only via the boot stamp
/// used for serving validity; H-series re-stamps durable rows with real
/// clocks.
#[derive(Debug, Clone)]
pub struct ActionActor {
    descriptor: ActionDescriptor,
    breakdown: ActionKeyBreakdown,
    authority_label: String,
    region: RegionSpec,
    boot_micros: i64,

    slot: PublicationSlotState,
    active_generation: Option<ActionGeneration>,
    fence: GenerationFence,
    history: Vec<PublicationEntry>,
    serving: Option<ActionServingStateRecord>,

    subscribers: BTreeMap<u128, Subscriber>,
    attempts: BTreeMap<u128, AttemptEntry>,
    selection_receipts: Vec<SelectionReceipt>,

    winner: Option<CasWinner>,
    provisional: BTreeMap<[u8; 32], (ObjectId, Vec<ObjectId>)>,
    evidence: Vec<EvidenceEntry>,
    next_incident: u64,

    retries_used: u32,
    hedges_used: u32,
    foreground_interest: bool,

    next_seq: u64,
    events: Vec<ActionEvent>,
}

impl ActionActor {
    /// New actor bound to `authority_label`, computing the action key once
    /// from `descriptor`. `boot_unix_micros` seeds serving validity.
    #[must_use]
    pub fn new(descriptor: ActionDescriptor, authority_label: &str, boot_unix_micros: i64) -> Self {
        let breakdown = compute_action_key(&descriptor);
        let region = coordinator_root(authority_label, &short_hex(&breakdown.final_key), "pending");
        let mut actor = Self {
            descriptor,
            breakdown,
            authority_label: authority_label.to_owned(),
            region,
            boot_micros: boot_unix_micros,
            slot: PublicationSlotState::Absent,
            active_generation: None,
            fence: GenerationFence::new(),
            history: Vec::new(),
            serving: None,
            subscribers: BTreeMap::new(),
            attempts: BTreeMap::new(),
            selection_receipts: Vec::new(),
            winner: None,
            provisional: BTreeMap::new(),
            evidence: Vec::new(),
            next_incident: 0,
            retries_used: 0,
            hedges_used: 0,
            foreground_interest: false,
            next_seq: 0,
            events: Vec::new(),
        };
        actor.push(EventKind::Constructed);
        actor
    }

    // -- immutable identity ------------------------------------------------

    /// The action key (canonical digest over exactly the key components).
    #[must_use]
    pub const fn key(&self) -> &TypedDigest {
        &self.breakdown.final_key
    }

    /// The full key breakdown (redaction-safe component digests).
    #[must_use]
    pub const fn breakdown(&self) -> &ActionKeyBreakdown {
        &self.breakdown
    }

    /// The descriptor digest: by construction this IS the final key digest,
    /// because the key hashes exactly the descriptor's key-input components
    /// (F034) — one serializer, no second digest to keep consistent.
    #[must_use]
    pub const fn descriptor_digest(&self) -> &TypedDigest {
        &self.breakdown.final_key
    }

    /// The immutable descriptor.
    #[must_use]
    pub const fn descriptor(&self) -> &ActionDescriptor {
        &self.descriptor
    }

    /// Region binding (G001 tree); rebound when a generation opens.
    #[must_use]
    pub const fn region(&self) -> &RegionSpec {
        &self.region
    }

    /// Attribution chains for the bound region — the exact lines tracing
    /// and crashpacks stamp on leaked effects.
    #[must_use]
    pub fn attribution_chains(&self) -> Vec<(String, Attribution)> {
        attribution_chains(&self.region)
    }

    // -- observation -------------------------------------------------------

    /// Current publication slot state.
    #[must_use]
    pub const fn slot(&self) -> PublicationSlotState {
        self.slot
    }
    /// Whether the versioned serving record permits serving right now.
    #[must_use]
    pub fn serving_eligible(&self, now_unix_micros: i64, clock_epoch: u64) -> bool {
        self.serving
            .as_ref()
            .is_some_and(|record| record.may_serve_now(now_unix_micros, clock_epoch))
    }

    /// The single active generation, if any.
    #[must_use]
    pub const fn active_generation(&self) -> Option<&ActionGeneration> {
        self.active_generation.as_ref()
    }

    /// Immutable publication history.
    #[must_use]
    pub const fn history(&self) -> &Vec<PublicationEntry> {
        &self.history
    }

    /// Current versioned serving record, if committed.
    #[must_use]
    pub const fn serving(&self) -> Option<&ActionServingStateRecord> {
        self.serving.as_ref()
    }

    /// Compare-and-set winner, if any.
    #[must_use]
    pub const fn winner(&self) -> Option<&CasWinner> {
        self.winner.as_ref()
    }

    /// Live attempts.
    pub fn attempts(&self) -> impl Iterator<Item = &AttemptEntry> {
        self.attempts.values()
    }

    /// Selection receipts (placement decisions recorded at registration).
    #[must_use]
    pub const fn selection_receipts(&self) -> &Vec<SelectionReceipt> {
        &self.selection_receipts
    }

    /// Append-only evidence set.
    #[must_use]
    pub const fn evidence(&self) -> &Vec<EvidenceEntry> {
        &self.evidence
    }

    /// One subscriber's independent state.
    #[must_use]
    pub fn subscriber(&self, operation: &BuildOperationId) -> Option<&Subscriber> {
        self.subscribers.get(&operation.0)
    }

    /// Whether any foreground interest currently exists (brownout lift).
    #[must_use]
    pub const fn has_foreground_interest(&self) -> bool {
        self.foreground_interest
    }

    /// Canonical event stream.
    #[must_use]
    pub const fn events(&self) -> &Vec<ActionEvent> {
        &self.events
    }

    // -- subscribers ---------------------------------------------------------

    /// Subscribe an operation (§21.1). Idempotent per operation id: a
    /// re-join refreshes presentation/priority instead of duplicating.
    /// A hit NEVER re-commits: it serves from the committed result if the
    /// versioned serving record permits, else reports why not.
    pub fn join(
        &mut self,
        request: JoinRequest,
        now_unix_micros: i64,
        clock_epoch: u64,
    ) -> JoinReceipt {
        let rejoined_interests =
            if let Some(existing) = self.subscribers.get_mut(&request.operation.0) {
                // Reference-counted interest (§21.1): a re-join increments
                // the operation's live interest count while refreshing
                // context; per-subscriber fallback/presentation state stays
                // ITS OWN.
                existing.interests = existing.interests.saturating_add(1);
                existing.kind = request.kind;
                existing.queue_priority = existing.queue_priority.max(request.queue_priority);
                existing.deadline_unix_micros =
                    match (existing.deadline_unix_micros, request.deadline_unix_micros) {
                        (Some(a), Some(b)) => Some(a.min(b)),
                        (a, b) => a.or(b),
                    };
                existing.presentation = request.presentation.clone();
                Some(existing.interests)
            } else {
                None
            };
        if let Some(interests) = rejoined_interests {
            self.push(EventKind::Rejoined);
            return JoinReceipt::Rejoined { interests };
        }
        let receipt = if self.slot == PublicationSlotState::Committed {
            match self.serving.as_ref() {
                Some(record) if record.may_serve_now(now_unix_micros, clock_epoch) => {
                    JoinReceipt::ServedFromCommitted
                }
                Some(record) => JoinReceipt::CommittedButNotServable(record.disposition),
                None => {
                    JoinReceipt::CommittedButNotServable(ActionServingDisposition::EvidencePending)
                }
            }
        } else if self.active_generation.is_some() {
            JoinReceipt::JoinedExecution
        } else {
            JoinReceipt::AwaitingGeneration
        };

        self.foreground_interest |= !is_background_kind(request.kind);
        self.subscribers.insert(
            request.operation.0,
            Subscriber {
                operation: request.operation,
                kind: request.kind,
                queue_priority: request.queue_priority,
                deadline_unix_micros: request.deadline_unix_micros,
                presentation: request.presentation,
                delivery: SubscriberDeliveryState::Subscribed,
                frontiers: ExposureFrontiers::default(),
                requirements: request.requirements,
                interests: 1,
            },
        );
        self.push(EventKind::Joined);
        receipt
    }

    /// Promote a background subscriber to foreground interest (§21.2):
    /// same actor, same key, same generation; priority rises; brownout
    /// lifts; promotion is recorded in provenance.
    pub fn promote(&mut self, operation: BuildOperationId) -> PromoteReceipt {
        let Some(subscriber) = self.subscribers.get_mut(&operation.0) else {
            return PromoteReceipt::UnknownSubscriber;
        };
        if !is_background_kind(subscriber.kind) {
            return PromoteReceipt::AlreadyForeground;
        }
        subscriber.kind = SubscriberKind::ForegroundAgent;
        subscriber.queue_priority = subscriber.queue_priority.max(FOREGROUND_QUEUE_PRIORITY);
        self.foreground_interest = true;
        self.push(EventKind::Promoted);
        PromoteReceipt::Promoted
    }
    /// Strongest live interest across subscribers (§21.1): maximum queue
    /// priority and earliest deadline, computed over CURRENT state so it
    /// tracks promotions and cancellations without stale caches.
    #[must_use]
    pub fn strongest_interest(&self) -> Option<StrongestInterest> {
        self.subscribers.values().fold(None, |acc, subscriber| {
            let priority = subscriber.queue_priority;
            let deadline = subscriber.deadline_unix_micros;
            Some(match acc {
                None => StrongestInterest {
                    priority,
                    earliest_deadline_unix_micros: deadline,
                },
                Some(mut strongest) => {
                    strongest.priority = strongest.priority.max(priority);
                    strongest.earliest_deadline_unix_micros =
                        match (strongest.earliest_deadline_unix_micros, deadline) {
                            (Some(a), Some(b)) => Some(a.min(b)),
                            (a, b) => a.or(b),
                        };
                    strongest
                }
            })
        })
    }

    /// Whether optional-work brownout is currently suspended (§21.2):
    /// brownout never applies while foreground interest exists.
    #[must_use]
    pub const fn brownout_suspended(&self) -> bool {
        self.foreground_interest
    }

    /// Requirement filtering for ONE subscriber against the committed
    /// winner's attestation (G004 acceptance): identity mismatches refuse
    /// outright; an evidence shortfall stays satisfiable through
    /// verification attempts. `None` = unknown operation.
    #[must_use]
    pub fn serving_filter(&self, operation: &BuildOperationId) -> Option<RequirementDecision> {
        let subscriber = self.subscribers.get(&operation.0)?;
        let requirements = &subscriber.requirements;
        let Some(winner) = self.winner.as_ref() else {
            // Still executing: waiting IS pending verification.
            return Some(RequirementDecision::NeedsAdditionalVerification);
        };
        let attested = &winner.attestation;
        if let Some(acceptable) = &requirements.acceptable_isolation
            && !acceptable.contains(&attested.isolation_attained)
        {
            return Some(RequirementDecision::Refused(
                RequirementRefusal::IsolationUnacceptable,
            ));
        }
        if let Some(scope) = &requirements.privacy_scope
            && *scope != attested.privacy_scope
        {
            return Some(RequirementDecision::Refused(
                RequirementRefusal::PrivacyScopeMismatch,
            ));
        }
        if let Some(platform) = &requirements.platform
            && *platform != attested.platform
        {
            return Some(RequirementDecision::Refused(
                RequirementRefusal::PlatformMismatch,
            ));
        }
        if u32::try_from(self.evidence.len()).unwrap_or(u32::MAX)
            < requirements.minimum_evidence_bundles
        {
            return Some(RequirementDecision::NeedsAdditionalVerification);
        }
        Some(RequirementDecision::Served)
    }

    /// Remove ONE subscriber's retained interest (§21.3): closes only that
    /// subscriber's delivery obligation. Shared work continues while any
    /// interest remains; the last cancellation consults policy — finish a
    /// near-complete cache-populating generation, else cancel and drain.
    pub fn cancel_subscriber(&mut self, operation: BuildOperationId) -> CancelReceipt {
        let Some(subscriber) = self.subscribers.get_mut(&operation.0) else {
            return CancelReceipt::UnknownSubscriber;
        };
        if subscriber.interests > 1 {
            // Reference-counted interest: only ONE reference detaches; the
            // subscription (and its delivery state) survives.
            subscriber.interests -= 1;
            let remaining = subscriber.interests;
            self.push(EventKind::Cancelled);
            return CancelReceipt::InterestDecremented { remaining };
        }
        self.subscribers.remove(&operation.0);
        self.push(EventKind::Cancelled);

        let retained = self.subscribers.len();
        if retained > 0 {
            return CancelReceipt::SharedWorkContinues { retained };
        }

        let Some(active) = self.active_generation.as_ref() else {
            // Nothing executing (absent or already committed).
            return CancelReceipt::LastInterestCancelledGeneration;
        };
        let generation_id = active.generation_id;

        let near_complete = self.attempts.values().any(|attempt| {
            attempt.generation == generation_id && attempt_near_complete(attempt.state)
        });
        if near_complete {
            // Policy step 5: let the near-complete generation finish so the
            // result populates the cache for future operations.
            return CancelReceipt::LastInterestFinishedForCache;
        }

        self.close_generation(generation_id);
        CancelReceipt::LastInterestCancelledGeneration
    }

    /// Advance one subscriber's independent delivery state.
    ///
    /// # Errors
    /// The current state and requested state when the delivery machine
    /// refuses the transition.
    pub fn advance_delivery(
        &mut self,
        operation: BuildOperationId,
        to: SubscriberDeliveryState,
    ) -> Result<(), (SubscriberDeliveryState, SubscriberDeliveryState)> {
        let Some(subscriber) = self.subscribers.get_mut(&operation.0) else {
            return Err((SubscriberDeliveryState::Detached, to));
        };
        if !SubscriberDeliveryState::may_transition(subscriber.delivery, to) {
            return Err((subscriber.delivery, to));
        }
        subscriber.delivery = to;
        Ok(())
    }

    // -- generations -------------------------------------------------------

    /// Open the single active generation (slot Absent → Executing). The
    /// coordinator mints the never-reused id; the fence tombstones any
    /// reuse (ABA), and closing a generation tombstones it forever.
    pub fn open_generation(&mut self, generation: ActionGeneration) -> OpenGenerationReceipt {
        if self.slot != PublicationSlotState::Absent {
            return OpenGenerationReceipt::RefusedSlotNotAbsent(self.slot);
        }
        let generation_id = generation.generation_id;
        if let FenceDecision::RejectReused = self.fence.admit(generation_id) {
            return OpenGenerationReceipt::RefusedGenerationReused;
        }
        self.active_generation = Some(generation);
        self.slot = PublicationSlotState::Executing;
        self.retries_used = 0;
        self.hedges_used = 0;
        self.region = coordinator_root(
            &self.authority_label,
            &short_hex(&self.breakdown.final_key),
            &format!("{:032x}", generation_id.0),
        );
        self.push(EventKind::GenerationOpened);
        OpenGenerationReceipt::Opened
    }

    /// Close and tombstone the named generation (cancel path). Attempts
    /// still alive are ordered to drain; the slot returns to Absent.
    fn close_generation(&mut self, generation_id: ActionGenerationId) {
        // Collect first, then drain: `push` needs `&mut self`, which cannot
        // nest inside an outstanding `values_mut` borrow.
        let to_drain: Vec<u128> = self
            .attempts
            .values()
            .filter(|attempt| {
                attempt.generation == generation_id
                    && !matches!(
                        attempt.state,
                        AttemptState::Draining | AttemptState::Finished
                    )
            })
            .map(|attempt| attempt.attempt.0)
            .collect();
        for id in to_drain {
            if let Some(attempt) = self.attempts.get_mut(&id) {
                attempt.state = AttemptState::Draining;
            }
            self.push(EventKind::LostToWinner);
        }
        self.fence.close(generation_id);
        debug_assert!(PublicationSlotState::may_transition(
            self.slot,
            PublicationSlotState::Absent
        ));
        self.slot = PublicationSlotState::Absent;
        self.active_generation = None;
        self.region = coordinator_root(
            &self.authority_label,
            &short_hex(&self.breakdown.final_key),
            "pending",
        );
        self.push(EventKind::GenerationClosed);
    }

    // -- attempts ----------------------------------------------------------

    /// Register an attempt under its OWN unique lease (I31). Non-audit
    /// purposes require the active generation; audits require a committed
    /// publication (they compare against the winner, never publish first).
    pub fn register_attempt(&mut self, registration: RegisterAttempt) -> RegisterAttemptReceipt {
        let audit = registration.purpose.is_audit();
        match (self.active_generation.as_ref(), audit) {
            (Some(active), _) if active.generation_id == registration.generation => {}
            (None, true) if self.slot == PublicationSlotState::Committed => {}
            (Some(_), _) => return RegisterAttemptReceipt::RefusedForeignGeneration,
            (None, _) => return RegisterAttemptReceipt::RefusedNoActiveGeneration,
        }

        if self.attempts.contains_key(&registration.attempt.0) {
            return RegisterAttemptReceipt::RefusedDuplicateAttempt;
        }
        if self
            .attempts
            .values()
            .any(|attempt| attempt.lease == registration.lease)
        {
            return RegisterAttemptReceipt::RefusedDuplicateLease;
        }
        if registration.purpose.consumes_retry_budget() {
            if self.retries_used >= MAX_RETRIES_PER_GENERATION {
                return RegisterAttemptReceipt::RefusedRetryBudgetExhausted;
            }
            self.retries_used += 1;
        }
        if registration.purpose.consumes_hedge_budget() {
            if self.hedges_used >= MAX_HEDGES_PER_GENERATION {
                return RegisterAttemptReceipt::RefusedHedgeBudgetExhausted;
            }
            self.hedges_used += 1;
        }

        let recorded_at_event = self.next_seq + 1;
        self.selection_receipts.push(SelectionReceipt {
            attempt: registration.attempt,
            worker: registration.worker.clone(),
            worker_boot_generation: registration.worker_boot_generation,
            purpose: registration.purpose,
            recorded_at_event,
        });
        self.attempts.insert(
            registration.attempt.0,
            AttemptEntry {
                attempt: registration.attempt,
                generation: registration.generation,
                lease: registration.lease,
                worker: registration.worker,
                worker_boot_generation: registration.worker_boot_generation,
                worker_incarnation: registration.worker_incarnation,
                purpose: registration.purpose,
                // Registration IS the lease offer from the coordinator.
                state: AttemptState::LeaseOffered,
                lease_renewal_seq: LeaseRenewalSeq(0),
            },
        );
        self.push(EventKind::AttemptRegistered);
        RegisterAttemptReceipt::Registered
    }

    /// Advance an attempt along the A017 machine (denial-default).
    pub fn advance_attempt(
        &mut self,
        attempt_id: AttemptId,
        to: AttemptState,
    ) -> AdvanceAttemptReceipt {
        let Some(attempt) = self.attempts.get_mut(&attempt_id.0) else {
            return AdvanceAttemptReceipt::RefusedUnknownAttempt;
        };
        if !AttemptState::may_transition(attempt.state, to) {
            return AdvanceAttemptReceipt::RefusedIllegalTransition {
                from: attempt.state,
                to,
            };
        }
        attempt.state = to;
        self.push(EventKind::AttemptAdvanced);
        AdvanceAttemptReceipt::Advanced
    }

    /// Evaluate a lease renewal against the owning attempt only. A sibling
    /// hedge's renewal is inert here (I31/R62).
    pub fn renew_lease(&mut self, attempt_id: AttemptId, renewal: LeaseRenewal) -> RenewalDecision {
        let Some(attempt) = self.attempts.get_mut(&attempt_id.0) else {
            return RenewalDecision::RefuseWrongLease;
        };
        let probe = AttemptAuthorityProbe {
            lease: attempt.lease,
            seq: attempt.lease_renewal_seq,
        };
        match probe.evaluate(renewal) {
            RenewalDecision::Accept => {
                attempt.lease_renewal_seq = renewal.seq;
                self.push(EventKind::LeaseRenewed);
                RenewalDecision::Accept
            }
            refused => refused,
        }
    }

    // -- compare-and-set commit ---------------------------------------------

    /// Offer a prepared candidate. First valid offer wins the CAS; later
    /// byte-identical offers are duplicates; a DIFFERENT canonical result
    /// after commit quarantines serving and opens a divergence incident
    /// (§21.4). Only attempts in `PreparedResultOffered` may offer.
    pub fn offer_candidate(&mut self, offer: PreparedCandidateOffer) -> OfferReceipt {
        self.push(EventKind::CandidateOffered);

        if !self.attempts.contains_key(&offer.attempt.0) {
            return OfferReceipt::RefusedUnknownAttempt;
        }
        // Only attempts in `PreparedResultOffered` may offer (I16).
        if self.attempts[&offer.attempt.0].state != AttemptState::PreparedResultOffered {
            return OfferReceipt::RefusedNotOfferable;
        }

        // Stale check BEFORE the CAS: an offer naming a foreign generation
        // while one is active can never win.
        if let Some(active) = self.active_generation.as_ref()
            && active.generation_id != offer.generation
        {
            return OfferReceipt::RejectedAsStale;
        }

        // Snapshot the winner so the attempt mutation below never fights an
        // outstanding borrow of `self.winner`.
        let Some(winner) = self.winner.clone() else {
            return if self.commit(offer) {
                OfferReceipt::AcceptedAsWinner
            } else {
                // Unreachable in practice (winner None ⇒ slot Executing);
                // treated as refusal, never as a silent success.
                OfferReceipt::RefusedUnknownAttempt
            };
        };

        let identical = winner.canonical_result == offer.canonical_result
            && winner.deterministic_failure == offer.deterministic_failure;
        if identical {
            let attempt = self
                .attempts
                .get_mut(&offer.attempt.0)
                .expect("existence checked");
            attempt.state = AttemptState::RejectedAsDuplicate;
            self.push(EventKind::CandidateRejectedDuplicate);
            return OfferReceipt::RejectedAsDuplicate;
        }

        {
            let attempt = self
                .attempts
                .get_mut(&offer.attempt.0)
                .expect("existence checked");
            attempt.state = AttemptState::RejectedAsDivergent;
        }
        self.open_divergence_incident();
        self.push(EventKind::CandidateRejectedDivergent);
        OfferReceipt::RejectedAsDivergent
    }

    /// Commit path behind the CAS: slot Executing → Committed, immutable
    /// history entry, versioned serving record (evidence-pending; TTL for
    /// deterministic failures), losers drained, subscribers readied.
    fn commit(&mut self, offer: PreparedCandidateOffer) -> bool {
        if !PublicationSlotState::may_transition(self.slot, PublicationSlotState::Committed) {
            return false;
        }
        let generation_digest = self
            .active_generation
            .as_ref()
            .map_or(digest_of(0), |generation| {
                generation.created_under_authority_digest.clone()
            });
        let generation_id = self
            .active_generation
            .as_ref()
            .map(|generation| generation.generation_id);

        let publication_record = ObjectId(offer.canonical_result.clone());
        self.history.push(PublicationEntry {
            publication_record: publication_record.clone(),
            canonical_result: offer.canonical_result.clone(),
            deterministic_failure: offer.deterministic_failure,
            committed_at_event: self.next_seq + 1,
            winning_attempt: offer.attempt,
        });
        self.winner = Some(CasWinner {
            attempt: offer.attempt,
            canonical_result: offer.canonical_result.clone(),
            deterministic_failure: offer.deterministic_failure,
            decided_at_event: self.next_seq,
            attestation: offer.attestation.clone(),
        });

        self.serving = Some(ActionServingStateRecord {
            publication_record_id: publication_record,
            disposition: ActionServingDisposition::EvidencePending,
            blocking_quarantine_ids: Vec::new(),
            state_revision: 1,
            coordinator_authority_digest: generation_digest,
            validity: ServingValidity {
                evaluated_at_unix_micros: self.boot_micros,
                maximum_age_micros: if offer.deterministic_failure {
                    Some(DETERMINISTIC_FAILURE_TTL_MICROS)
                } else {
                    None
                },
                clock_uncertainty_micros: 0,
                coordinator_clock_epoch: 0,
            },
        });

        // Losing attempts: decisions then drain (any live state → Draining).
        let winner_id = offer.attempt;
        let losers: Vec<u128> = self
            .attempts
            .iter()
            .filter(|(id, attempt)| {
                **id != winner_id.0
                    && attempt.generation == offer.generation
                    && !matches!(
                        attempt.state,
                        AttemptState::Draining | AttemptState::Finished
                    )
            })
            .map(|(id, _)| *id)
            .collect();
        for id in losers {
            if let Some(attempt) = self.attempts.get_mut(&id) {
                attempt.state = if attempt.state == AttemptState::PreparedResultOffered {
                    AttemptState::RejectedAsDuplicate
                } else {
                    attempt.state
                };
                attempt.state = AttemptState::Draining;
                self.push(EventKind::LostToWinner);
            }
        }
        if let Some(attempt) = self.attempts.get_mut(&winner_id.0) {
            attempt.state = AttemptState::AcceptedAsWinner;
        }

        // The execution generation ends at commit; its identity stays
        // tombstoned forever.
        if let Some(id) = generation_id {
            self.fence.close(id);
        }
        self.slot = PublicationSlotState::Committed;
        self.active_generation = None;

        // Every waiting subscriber moves to Waiting (delivery itself stays
        // per-subscriber; the edge drives the frontier transitions).
        for subscriber in self.subscribers.values_mut() {
            if SubscriberDeliveryState::may_transition(
                subscriber.delivery,
                SubscriberDeliveryState::Waiting,
            ) {
                subscriber.delivery = SubscriberDeliveryState::Waiting;
            }
        }

        self.push(EventKind::Committed);
        true
    }

    /// The divergence incident opener: bumps the incident counter and
    /// quarantines the versioned serving record through the legality table.
    fn open_divergence_incident(&mut self) {
        let incident = self.next_incident + 1;
        self.next_incident = incident;
        if let Some(current) = self.serving.clone() {
            let mut next = current.clone();
            next.disposition = ActionServingDisposition::Quarantined;
            next.state_revision += 1;
            next.blocking_quarantine_ids.push(incident);
            debug_assert!(current.accepts_update(&next));
            self.serving = Some(next);
            self.push(EventKind::ServingChanged);
        }
    }

    // -- evidence & serving --------------------------------------------------

    /// Append evidence. When the appended bundle completes the required
    /// set on an `EvidencePending` publication, the legality table moves
    /// serving to Eligible. Evidence NEVER creates a new key nor rewrites
    /// the publication record (§21.1).
    pub fn record_evidence(&mut self, digest: TypedDigest, completes_requirements: bool) {
        self.evidence.push(EvidenceEntry {
            digest,
            recorded_at_event: self.next_seq + 1,
        });
        self.push(EventKind::EvidenceRecorded);
        if completes_requirements
            && self.slot == PublicationSlotState::Committed
            && self.serving.as_ref().is_some_and(|record| {
                record.disposition == ActionServingDisposition::EvidencePending
            })
        {
            let _ = self.apply_serving_trigger(ServingTransitionTrigger::EvidenceComplete);
        }
    }

    /// Apply a serving trigger through the A020 legality table; application
    /// writes a strictly newer revision (replays refuse upstream).
    pub fn apply_serving_trigger(
        &mut self,
        trigger: ServingTransitionTrigger,
    ) -> ServingApplyReceipt {
        let Some(current) = self.serving.clone() else {
            return ServingApplyReceipt::RefusedNoPublication;
        };
        match evaluate(current.disposition, trigger) {
            TransitionDecision::Apply(new_disposition) => {
                let mut next = current.clone();
                next.disposition = new_disposition;
                next.state_revision += 1;
                if matches!(
                    trigger,
                    ServingTransitionTrigger::QuarantineReleased(Some(_))
                ) {
                    // V1 tracks at most one blocking incident class; the
                    // verified receipt releases it. Multi-incident rows land
                    // with H-series durable incidents.
                    next.blocking_quarantine_ids.clear();
                }
                debug_assert!(current.accepts_update(&next));
                self.serving = Some(next);
                self.push(EventKind::ServingChanged);
                ServingApplyReceipt::Applied(new_disposition)
            }
            TransitionDecision::QuarantineWithDivergenceIncident => {
                self.open_divergence_incident();
                ServingApplyReceipt::QuarantinedWithDivergenceIncident
            }
            TransitionDecision::Refuse(reason) => ServingApplyReceipt::Refused(reason),
        }
    }

    // -- provisional lineage ---------------------------------------------------

    /// Register a provisional artifact with its DIRECT producers.
    pub fn register_provisional(&mut self, artifact: ObjectId, producers: Vec<ObjectId>) {
        self.provisional
            .insert(artifact.0.bytes, (artifact.clone(), producers));
        self.push(EventKind::ProvisionalRegistered);
    }

    /// Transitive producer closure of one artifact (itself included),
    /// deterministically ordered by digest bytes.
    #[must_use]
    pub fn ancestor_closure(&self, artifact: &ObjectId) -> Vec<ObjectId> {
        let mut seen: BTreeSet<[u8; 32]> = BTreeSet::new();
        let mut closure: Vec<ObjectId> = Vec::new();
        let mut frontier = vec![artifact.clone()];
        while let Some(current) = frontier.pop() {
            if !seen.insert(current.0.bytes) {
                continue;
            }
            if let Some((_, parents)) = self.provisional.get(&current.0.bytes) {
                frontier.extend(parents.iter().cloned());
            }
            closure.push(current);
        }
        closure.sort_by_key(|artifact| artifact.0.bytes);
        closure
    }

    /// Whether every registered provisional artifact's producer chain
    /// bottoms out at producer-less artifacts (the §20.5 precondition that
    /// complete ancestor closure precedes terminal positive delivery).
    /// Unregistered producers count as INCOMPLETE (missing evidence).
    #[must_use]
    pub fn provisional_closure_complete(&self) -> bool {
        fn chain_complete(
            bytes: &[u8; 32],
            provisional: &BTreeMap<[u8; 32], (ObjectId, Vec<ObjectId>)>,
            seen: &mut BTreeSet<[u8; 32]>,
        ) -> bool {
            if !seen.insert(*bytes) {
                // Cycle guard: treat revisits as satisfied so termination
                // holds; cycles are malformed input rejected upstream.
                return true;
            }
            match provisional.get(bytes) {
                None => false,
                Some((_, parents)) => parents
                    .iter()
                    .all(|parent| chain_complete(&parent.0.bytes, provisional, seen)),
            }
        }
        self.provisional
            .keys()
            .all(|bytes| chain_complete(bytes, &self.provisional, &mut BTreeSet::new()))
    }

    // -- message shell --------------------------------------------------------

    /// Dispatch one message, ignoring typed receipts (every outcome lands
    /// in the event stream; the edge proxy layer adds reply channels).
    pub fn apply(&mut self, msg: ActionActorMsg) {
        match msg {
            ActionActorMsg::Join(request) => {
                let _ = self.join(request, self.boot_micros, 0);
            }
            ActionActorMsg::Promote(operation) => {
                let _ = self.promote(operation);
            }
            ActionActorMsg::CancelSubscriber(operation) => {
                let _ = self.cancel_subscriber(operation);
            }
            ActionActorMsg::OpenGeneration { generation } => {
                let _ = self.open_generation(generation);
            }
            ActionActorMsg::RegisterAttempt(registration) => {
                let _ = self.register_attempt(*registration);
            }
            ActionActorMsg::AdvanceAttempt { attempt, to } => {
                let _ = self.advance_attempt(attempt, to);
            }
            ActionActorMsg::RenewLease { attempt, renewal } => {
                let _ = self.renew_lease(attempt, renewal);
            }
            ActionActorMsg::OfferCandidate(offer) => {
                let _ = self.offer_candidate(*offer);
            }
            ActionActorMsg::RecordEvidence {
                digest,
                completes_requirements,
            } => self.record_evidence(digest, completes_requirements),
            ActionActorMsg::ServingTrigger(trigger) => {
                let _ = self.apply_serving_trigger(trigger);
            }
            ActionActorMsg::RegisterProvisional {
                artifact,
                producers,
            } => self.register_provisional(artifact, producers),
        }
    }

    // -- internals --------------------------------------------------------------

    fn push(&mut self, kind: EventKind) {
        self.next_seq += 1;
        self.events.push(ActionEvent {
            seq: self.next_seq,
            kind,
        });
    }
}

// ---------------------------------------------------------------------------
// Asupersync actor shell
// ---------------------------------------------------------------------------

/// Thin [`Actor`] wrapper: bounded mailbox → sequential [`ActionActorMsg`]s
/// into the pure core. Spawn wiring under the coordinator region lands with
/// G017/I018; the core stays runtime-free for lab tests.
#[derive(Debug)]
pub struct ActionActorHost {
    /// The authoritative core.
    pub core: ActionActor,
}

impl Actor for ActionActorHost {
    type Message = ActionActorMsg;

    fn handle(
        &mut self,
        _cx: &Cx,
        msg: Self::Message,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            self.core.apply(msg);
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Background interest kinds eligible for promotion (§21.2).
const fn is_background_kind(kind: SubscriberKind) -> bool {
    matches!(
        kind,
        SubscriberKind::Speculative | SubscriberKind::GitPrewarm
    )
}

/// Attempts near completion worth finishing for the cache (§21.3 step 5).
const fn attempt_near_complete(state: AttemptState) -> bool {
    matches!(
        state,
        AttemptState::Running
            | AttemptState::ProcessExited
            | AttemptState::HarvestingOutputs
            | AttemptState::UploadingOutputs
            | AttemptState::VerifyingOutputs
            | AttemptState::HarvestingCanonicalObservations
            | AttemptState::VerifyingFailure
            | AttemptState::PreparedResultOffered
    )
}

/// Short hex label for region naming (diagnostic only).
fn short_hex(digest: &TypedDigest) -> String {
    let mut out = String::new();
    for byte in &digest.bytes[..4] {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn digest_of(tag: u8) -> TypedDigest {
    TypedDigest {
        algorithm: DigestAlgorithm::Sha256V1,
        domain: "rabs.coord.action-actor.v1",
        bytes: [tag; 32],
    }
}

/// Local lease-freshness probe mirroring `AttemptAuthority::evaluate_renewal`
/// without requiring the FULL authority value inside the actor.
struct AttemptAuthorityProbe {
    lease: ExecutionLeaseId,
    seq: LeaseRenewalSeq,
}

impl AttemptAuthorityProbe {
    fn evaluate(&self, renewal: LeaseRenewal) -> RenewalDecision {
        if renewal.lease != self.lease {
            return RenewalDecision::RefuseWrongLease;
        }
        if renewal.seq <= self.seq {
            return RenewalDecision::RefuseStaleSequence;
        }
        RenewalDecision::Accept
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rabs_protocol::descriptor::ActionClass;

    const OP_ONE: BuildOperationId = BuildOperationId(0xA1);
    const OP_TWO: BuildOperationId = BuildOperationId(0xA2);

    fn d(tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "test.actor.component.v1",
            bytes: [tag; 32],
        }
    }

    fn descriptor() -> ActionDescriptor {
        ActionDescriptor {
            key_epoch: 1,
            projection_epoch: 1,
            action_class: ActionClass::RustcDependencyCompile,
            normalized_invocation: d(1),
            virtual_working_directory: d(2),
            action_inputs: d(3),
            negative_dependencies: d(4),
            dependency_inputs: d(5),
            toolchain: d(6),
            output_platform: d(7),
            environment: d(8),
            sandbox_semantic_policy: d(9),
            build_path_semantic_policy: d(10),
            execution_semantics: d(11),
            output_declarations: d(12),
        }
    }

    fn actor() -> ActionActor {
        ActionActor::new(descriptor(), "coord-test", 1_000)
    }

    fn generation(id: u128) -> ActionGeneration {
        ActionGeneration {
            generation_id: ActionGenerationId(id),
            per_key_ordinal: 1,
            created_under_authority_digest: d(200),
        }
    }

    fn join_request(op: u128, kind: SubscriberKind, priority: u8) -> JoinRequest {
        JoinRequest {
            operation: BuildOperationId(op),
            kind,
            queue_priority: priority,
            deadline_unix_micros: None,
            presentation: d(77),
            requirements: SubscriptionRequirements::unrestricted(),
        }
    }

    fn registration(
        attempt: u128,
        lease: u128,
        incarnation: u128,
        purpose: AttemptPurpose,
    ) -> RegisterAttempt {
        RegisterAttempt {
            attempt: AttemptId(attempt),
            generation: ActionGenerationId(0x60),
            lease: ExecutionLeaseId(lease),
            worker: PeerId("wkr-1".into()),
            worker_boot_generation: WorkerBootGeneration(7),
            worker_incarnation: WorkerIncarnationId(incarnation),
            purpose,
        }
    }

    fn open_with_primary(actor: &mut ActionActor) {
        assert_eq!(
            actor.open_generation(generation(0x60)),
            OpenGenerationReceipt::Opened
        );
        assert_eq!(
            actor.register_attempt(registration(1, 11, 111, AttemptPurpose::Primary)),
            RegisterAttemptReceipt::Registered
        );
    }

    /// Walk the success spine up to `PreparedResultOffered`.
    fn drive_to_offer(actor: &mut ActionActor, attempt: u128) {
        let spine = [
            AttemptState::LeaseAccepted,
            AttemptState::AwaitingInputs,
            AttemptState::Materializing,
            AttemptState::Running,
            AttemptState::ProcessExited,
            AttemptState::HarvestingOutputs,
            AttemptState::UploadingOutputs,
            AttemptState::VerifyingOutputs,
            AttemptState::PreparedResultOffered,
        ];
        for step in spine {
            assert_eq!(
                actor.advance_attempt(AttemptId(attempt), step),
                AdvanceAttemptReceipt::Advanced,
                "advancing to {step:?}"
            );
        }
    }

    fn offer(attempt: u128, result_tag: u8, failure: bool) -> PreparedCandidateOffer {
        PreparedCandidateOffer {
            generation: ActionGenerationId(0x60),
            attempt: AttemptId(attempt),
            canonical_result: d(result_tag),
            deterministic_failure: failure,
            evidence_bundle: d(result_tag + 100),
            attestation: attestation(),
        }
    }

    fn attestation() -> ResultAttestation {
        ResultAttestation {
            isolation_attained: IsolationProfile::StrictHermeticLinux,
            privacy_scope: "test-scope".into(),
            platform: d(7),
        }
    }

    fn events_of(actor: &ActionActor, kind: EventKind) -> usize {
        actor
            .events()
            .iter()
            .filter(|event| event.kind == kind)
            .count()
    }

    // -- acceptance: hit ---------------------------------------------------

    #[test]
    fn hit_serves_from_committed_without_recommit() {
        let mut actor = actor();
        open_with_primary(&mut actor);
        drive_to_offer(&mut actor, 1);
        assert_eq!(
            actor.offer_candidate(offer(1, 42, false)),
            OfferReceipt::AcceptedAsWinner
        );
        assert_eq!(actor.slot(), PublicationSlotState::Committed);
        assert_eq!(actor.history().len(), 1);

        // A fresh publication is EvidencePending; completing the required
        // evidence makes it servable. THEN the hit: joins are served from
        // the committed result; NOTHING commits again and NO generation
        // opens (I29).
        actor.record_evidence(d(80), true);
        let events_before_join = actor.events().len();
        let receipt = actor.join(
            join_request(9, SubscriberKind::ForegroundAgent, 10),
            1_500,
            0,
        );
        assert_eq!(receipt, JoinReceipt::ServedFromCommitted);
        assert_eq!(actor.events().len(), events_before_join + 1);
        assert_eq!(actor.history().len(), 1);
        assert_eq!(actor.slot(), PublicationSlotState::Committed);
        assert_eq!(events_of(&actor, EventKind::GenerationOpened), 1);
    }

    // -- acceptance: miss+execute -------------------------------------------

    #[test]
    fn miss_executes_and_commits_once() {
        let mut actor = actor();
        assert_eq!(
            actor.join(
                join_request(OP_ONE.0, SubscriberKind::CiRequired, 50),
                1_100,
                0
            ),
            JoinReceipt::AwaitingGeneration
        );
        open_with_primary(&mut actor);
        assert_eq!(
            actor.join(
                join_request(OP_TWO.0, SubscriberKind::Speculative, 5),
                1_100,
                0
            ),
            JoinReceipt::JoinedExecution
        );
        drive_to_offer(&mut actor, 1);
        assert_eq!(
            actor.offer_candidate(offer(1, 42, false)),
            OfferReceipt::AcceptedAsWinner
        );

        assert_eq!(actor.slot(), PublicationSlotState::Committed);
        assert_eq!(actor.active_generation(), None);
        assert_eq!(actor.history().len(), 1);
        assert_eq!(events_of(&actor, EventKind::Committed), 1);

        let winner = actor.winner().expect("winner set");
        assert_eq!(winner.attempt, AttemptId(1));
        assert_eq!(actor.attempts().count(), 1);
        assert_eq!(
            actor.attempts().next().map(|entry| entry.state),
            Some(AttemptState::AcceptedAsWinner)
        );

        let serving = actor.serving().expect("serving record");
        assert_eq!(
            serving.disposition,
            ActionServingDisposition::EvidencePending
        );
        assert_eq!(serving.state_revision, 1);
        assert_eq!(
            serving.coordinator_authority_digest,
            d(200),
            "serving stamps the creating authority digest"
        );

        // Drain the winner to Finished; the publication stays immutable.
        assert_eq!(
            actor.advance_attempt(AttemptId(1), AttemptState::Draining),
            AdvanceAttemptReceipt::Advanced
        );
        assert_eq!(
            actor.advance_attempt(AttemptId(1), AttemptState::Finished),
            AdvanceAttemptReceipt::Advanced
        );
        assert_eq!(actor.history().len(), 1);
    }

    // -- acceptance: join -----------------------------------------------------

    #[test]
    fn second_subscriber_joins_in_flight_with_independent_delivery() {
        let mut actor = actor();
        open_with_primary(&mut actor);
        assert_eq!(
            actor.join(
                join_request(OP_ONE.0, SubscriberKind::ForegroundAgent, 90),
                1_100,
                0
            ),
            JoinReceipt::JoinedExecution
        );
        assert_eq!(
            actor.join(
                join_request(OP_TWO.0, SubscriberKind::ForegroundAgent, 40),
                1_150,
                0
            ),
            JoinReceipt::JoinedExecution
        );

        // Independent delivery frontiers: op-one reaches terminal completion
        // while op-two stays waiting. No global commit bit moved op-two.
        assert!(
            actor
                .advance_delivery(OP_ONE, SubscriberDeliveryState::Waiting)
                .is_ok()
        );
        assert!(
            actor
                .advance_delivery(OP_ONE, SubscriberDeliveryState::EmittingStatefulObservable)
                .is_ok()
        );
        assert!(
            actor
                .advance_delivery(OP_ONE, SubscriberDeliveryState::Waiting)
                .is_ok()
        );
        assert!(
            actor
                .advance_delivery(OP_ONE, SubscriberDeliveryState::DeliveryComplete)
                .is_ok()
        );
        assert_eq!(
            actor.subscriber(&OP_TWO).map(|sub| sub.delivery),
            Some(SubscriberDeliveryState::Subscribed)
        );

        // Cancelling op-two leaves shared work running for op-one.
        assert_eq!(
            actor.cancel_subscriber(OP_TWO),
            CancelReceipt::SharedWorkContinues { retained: 1 }
        );
        assert_eq!(actor.slot(), PublicationSlotState::Executing);
    }

    // -- acceptance: cancel ------------------------------------------------------

    #[test]
    fn last_cancel_early_cancels_generation_and_tombstones_it() {
        let mut actor = actor();
        open_with_primary(&mut actor);
        assert_eq!(
            actor.join(
                join_request(OP_ONE.0, SubscriberKind::GitPrewarm, 1),
                1_100,
                0
            ),
            JoinReceipt::JoinedExecution
        );

        // Early cancel (attempt only LeaseOffered): cancel wins.
        assert_eq!(
            actor.cancel_subscriber(OP_ONE),
            CancelReceipt::LastInterestCancelledGeneration
        );
        assert_eq!(actor.slot(), PublicationSlotState::Absent);
        assert_eq!(actor.active_generation(), None);
        assert!(
            actor
                .attempts()
                .all(|entry| entry.state == AttemptState::Draining)
        );

        // ABA: the SAME generation id can never reopen (fence tombstone).
        assert_eq!(
            actor.open_generation(generation(0x60)),
            OpenGenerationReceipt::RefusedGenerationReused
        );
        // A fresh id opens cleanly.
        assert_eq!(
            actor.open_generation(generation(0x61)),
            OpenGenerationReceipt::Opened
        );
    }

    #[test]
    fn last_cancel_near_complete_finishes_for_cache() {
        let mut actor = actor();
        open_with_primary(&mut actor);
        assert_eq!(
            actor.join(
                join_request(OP_ONE.0, SubscriberKind::Speculative, 3),
                1_100,
                0
            ),
            JoinReceipt::JoinedExecution
        );
        let spine = [
            AttemptState::LeaseAccepted,
            AttemptState::AwaitingInputs,
            AttemptState::Materializing,
            AttemptState::Running,
        ];
        for step in spine {
            let _ = actor.advance_attempt(AttemptId(1), step);
        }

        // Near-complete: policy lets the cache-populating generation run on.
        assert_eq!(
            actor.cancel_subscriber(OP_ONE),
            CancelReceipt::LastInterestFinishedForCache
        );
        assert_eq!(actor.slot(), PublicationSlotState::Executing);

        // It can still commit afterwards.
        // Only the REMAINING spine states — the early ones already ran.
        for step in [
            AttemptState::ProcessExited,
            AttemptState::HarvestingOutputs,
            AttemptState::UploadingOutputs,
            AttemptState::VerifyingOutputs,
            AttemptState::PreparedResultOffered,
        ] {
            assert_eq!(
                actor.advance_attempt(AttemptId(1), step),
                AdvanceAttemptReceipt::Advanced
            );
        }
        assert_eq!(
            actor.offer_candidate(offer(1, 42, false)),
            OfferReceipt::AcceptedAsWinner
        );
        assert_eq!(actor.slot(), PublicationSlotState::Committed);
    }

    // -- acceptance: hedge --------------------------------------------------------

    #[test]
    fn hedge_has_independent_lease_and_loses_cas_cleanly() {
        let mut actor = actor();
        open_with_primary(&mut actor);

        assert_eq!(
            actor.register_attempt(registration(2, 12, 222, AttemptPurpose::Hedge)),
            RegisterAttemptReceipt::Registered,
            "hedge registers with its OWN lease/incarnation"
        );
        // Lease uniqueness is enforced across live attempts.
        assert_eq!(
            actor.register_attempt(registration(3, 12, 333, AttemptPurpose::Hedge)),
            RegisterAttemptReceipt::RefusedDuplicateLease
        );
        // Budget: two hedges max; third refused.
        assert_eq!(
            actor.register_attempt(registration(4, 14, 444, AttemptPurpose::Hedge)),
            RegisterAttemptReceipt::Registered
        );
        assert_eq!(
            actor.register_attempt(registration(5, 15, 555, AttemptPurpose::Hedge)),
            RegisterAttemptReceipt::RefusedHedgeBudgetExhausted
        );

        drive_to_offer(&mut actor, 1);
        drive_to_offer(&mut actor, 2);

        // Primary wins the CAS…
        assert_eq!(
            actor.offer_candidate(offer(1, 42, false)),
            OfferReceipt::AcceptedAsWinner
        );
        // …and the hedge was already CAS-DECIDED at commit time (marked
        // RejectedAsDuplicate, then ordered to drain), so its late offer is
        // refused as not-offerable — the decision already exists.
        assert_eq!(
            actor.offer_candidate(offer(2, 42, false)),
            OfferReceipt::RefusedNotOfferable
        );
        // BOTH live sibling hedges (the offer-ready #2 and the early #4)
        // are CAS-decided and drained at commit time.
        assert_eq!(events_of(&actor, EventKind::LostToWinner), 2);
        assert_eq!(
            actor
                .attempts()
                .find(|entry| entry.attempt == AttemptId(2))
                .map(|entry| entry.state),
            Some(AttemptState::Draining)
        );

        // Sibling-hedge independence: a renewal for hedge TWO's lease is
        // inert when evaluated against the primary's attempt.
        assert_eq!(
            actor.renew_lease(
                AttemptId(1),
                LeaseRenewal {
                    lease: ExecutionLeaseId(12),
                    seq: LeaseRenewalSeq(5),
                }
            ),
            RenewalDecision::RefuseWrongLease
        );
    }

    #[test]
    fn divergent_post_commit_offer_quarantines_serving() {
        let mut actor = actor();
        open_with_primary(&mut actor);
        drive_to_offer(&mut actor, 1);
        assert_eq!(
            actor.offer_candidate(offer(1, 42, false)),
            OfferReceipt::AcceptedAsWinner
        );

        // Post-commit verification audit with DIFFERENT bytes: cannot
        // publish, cannot coexist — quarantine + incident (§21.4).
        assert_eq!(
            actor.register_attempt(registration(9, 91, 999, AttemptPurpose::DeterminismAudit)),
            RegisterAttemptReceipt::Registered,
            "audits register against a committed publication"
        );
        drive_to_offer(&mut actor, 9);
        assert_eq!(
            actor.offer_candidate(offer(9, 43, false)),
            OfferReceipt::RejectedAsDivergent
        );

        let serving = actor.serving().expect("serving");
        assert_eq!(serving.disposition, ActionServingDisposition::Quarantined);
        assert_eq!(serving.blocking_quarantine_ids.len(), 1);
        assert!(!actor.serving_eligible(2_000, 0));
        // The publication record is untouched — divergence is evidence.
        assert_eq!(actor.history().len(), 1);
    }

    #[test]
    fn stale_foreign_generation_offer_is_rejected_as_stale() {
        let mut actor = actor();
        open_with_primary(&mut actor);
        drive_to_offer(&mut actor, 1);
        let mut stale = offer(1, 42, false);
        stale.generation = ActionGenerationId(0xDEAD);
        assert_eq!(actor.offer_candidate(stale), OfferReceipt::RejectedAsStale);
        assert_eq!(actor.winner(), None, "CAS untouched by a stale offer");
    }

    // -- deterministic failure + serving table ---------------------------------

    #[test]
    fn deterministic_failure_commits_with_ttl_and_expiry_flows() {
        let mut actor = actor();
        open_with_primary(&mut actor);
        drive_to_offer(&mut actor, 1);
        assert_eq!(
            actor.offer_candidate(offer(1, 77, true)),
            OfferReceipt::AcceptedAsWinner
        );

        let serving = actor.serving().expect("serving");
        assert_eq!(
            serving.validity.maximum_age_micros,
            Some(DETERMINISTIC_FAILURE_TTL_MICROS),
            "negative outcomes serve under a TTL"
        );

        // Required evidence completes → Eligible (revision bump).
        actor.record_evidence(d(80), true);
        let serving = actor.serving().expect("serving");
        assert_eq!(serving.disposition, ActionServingDisposition::Eligible);
        assert_eq!(serving.state_revision, 2);

        // TTL expiry suppresses serving pending revalidation.
        assert_eq!(
            actor.apply_serving_trigger(ServingTransitionTrigger::ValidityExpired),
            ServingApplyReceipt::Applied(ActionServingDisposition::ExpiredNeedsRevalidation)
        );
        // Byte-identical revalidation renews.
        assert_eq!(
            actor.apply_serving_trigger(ServingTransitionTrigger::RevalidationByteIdentical),
            ServingApplyReceipt::Applied(ActionServingDisposition::Eligible)
        );
        // Release-without-receipt is refused by the table even out of band.
        assert_eq!(
            actor.apply_serving_trigger(ServingTransitionTrigger::QuarantineReleased(None)),
            ServingApplyReceipt::Refused(RefuseReason::NotInTable)
        );
    }

    #[test]
    fn evidence_never_commits_a_hit_twice() {
        let mut actor = actor();
        open_with_primary(&mut actor);
        drive_to_offer(&mut actor, 1);
        assert_eq!(
            actor.offer_candidate(offer(1, 42, false)),
            OfferReceipt::AcceptedAsWinner
        );

        // A success publication starts EvidencePending; late completing
        // evidence legitimately moves serving to Eligible (revision bump).
        // The INVARIANT under test: evidence never re-commits — history
        // stays at one entry with exactly one Committed event.
        let revision_before = actor.serving().expect("serving").state_revision;
        actor.record_evidence(d(81), true);
        let serving = actor.serving().expect("serving");
        assert_eq!(serving.disposition, ActionServingDisposition::Eligible);
        assert_eq!(serving.state_revision, revision_before + 1);
        assert_eq!(actor.evidence().len(), 1);
        assert_eq!(events_of(&actor, EventKind::Committed), 1);
        assert_eq!(actor.history().len(), 1);
    }

    // -- promotion ---------------------------------------------------------------

    #[test]
    fn speculative_promotion_keeps_identity_and_raises_priority() {
        let mut actor = actor();
        open_with_primary(&mut actor);
        assert_eq!(
            actor.join(
                join_request(OP_ONE.0, SubscriberKind::Speculative, 3),
                1_100,
                0
            ),
            JoinReceipt::JoinedExecution
        );
        assert!(!actor.has_foreground_interest());

        assert_eq!(actor.promote(OP_ONE), PromoteReceipt::Promoted);
        assert!(actor.has_foreground_interest());
        let subscriber = actor.subscriber(&OP_ONE).expect("subscriber");
        assert_eq!(subscriber.kind, SubscriberKind::ForegroundAgent);
        assert_eq!(subscriber.queue_priority, FOREGROUND_QUEUE_PRIORITY);
        assert_eq!(events_of(&actor, EventKind::Promoted), 1);
        // Same key, same generation — promotion never touches identity.
        assert_eq!(actor.promote(OP_TWO), PromoteReceipt::UnknownSubscriber);
    }

    // -- lineage --------------------------------------------------------------------

    #[test]
    fn provisional_lineage_closure_and_completeness() {
        let mut actor = actor();
        let a = ObjectId(d(1));
        let b = ObjectId(d(2));
        let c = ObjectId(d(3));
        let orphan = ObjectId(d(4));

        actor.register_provisional(a.clone(), Vec::new());
        actor.register_provisional(b.clone(), vec![a.clone()]);
        actor.register_provisional(c.clone(), vec![b.clone()]);
        // An unregistered PRODUCER reference makes the closure incomplete.
        actor.register_provisional(orphan.clone(), vec![ObjectId(d(99))]);

        let closure = actor.ancestor_closure(&c);
        assert_eq!(closure.len(), 3);
        assert!(closure.contains(&a) && closure.contains(&b) && closure.contains(&c));

        assert!(!actor.provisional_closure_complete(), "missing producer");

        // Register the missing producer: closure bottoms out everywhere.
        actor.register_provisional(ObjectId(d(99)), Vec::new());
        assert!(actor.provisional_closure_complete());
    }

    // -- receipts & bookkeeping ---------------------------------------------------------

    #[test]
    fn retry_budget_and_illegal_transitions_refuse() {
        let mut actor = actor();
        open_with_primary(&mut actor);
        assert_eq!(
            actor.register_attempt(registration(2, 12, 22, AttemptPurpose::Retry)),
            RegisterAttemptReceipt::Registered
        );
        assert_eq!(
            actor.register_attempt(registration(3, 13, 23, AttemptPurpose::Retry)),
            RegisterAttemptReceipt::Registered
        );
        assert_eq!(
            actor.register_attempt(registration(4, 14, 24, AttemptPurpose::Retry)),
            RegisterAttemptReceipt::RefusedRetryBudgetExhausted
        );
        // Denial-default machine: LeaseOffered → Running skips spine states.
        assert_eq!(
            actor.advance_attempt(AttemptId(1), AttemptState::Running),
            AdvanceAttemptReceipt::RefusedIllegalTransition {
                from: AttemptState::LeaseOffered,
                to: AttemptState::Running,
            }
        );
    }

    #[test]
    fn events_are_monotone_and_region_carries_attribution() {
        let mut actor = actor();
        open_with_primary(&mut actor);
        let chains = actor.attribution_chains();
        assert!(!chains.is_empty(), "region binds an attribution chain");
        for window in actor.events().windows(2) {
            assert!(window[0].seq < window[1].seq, "monotone event stream");
        }
        assert_eq!(
            actor.events().first().map(|event| event.kind),
            Some(EventKind::Constructed)
        );
    }

    // -- Asupersync shell -----------------------------------------------------------------

    #[test]
    fn actor_shell_processes_messages_under_a_test_cx() {
        let cx = Cx::for_testing();
        let mut host = ActionActorHost {
            core: ActionActor::new(descriptor(), "coord-shell-test", 1_000),
        };
        let waker = std::task::Waker::noop();
        let mut task = std::task::Context::from_waker(waker);

        // Scope each future: it borrows `host` until dropped, so the next
        // handle() call and the state assertions must wait.
        {
            let opened = host.handle(
                &cx,
                ActionActorMsg::OpenGeneration {
                    generation: generation(0x60),
                },
            );
            let mut opened = std::pin::pin!(opened);
            assert!(matches!(
                opened.as_mut().poll(&mut task),
                std::task::Poll::Ready(())
            ));
        }
        {
            let registered = host.handle(
                &cx,
                ActionActorMsg::RegisterAttempt(Box::new(registration(
                    1,
                    11,
                    111,
                    AttemptPurpose::Primary,
                ))),
            );
            let mut registered = std::pin::pin!(registered);
            assert!(matches!(
                registered.as_mut().poll(&mut task),
                std::task::Poll::Ready(())
            ));
        }
        assert_eq!(host.core.slot(), PublicationSlotState::Executing);
        assert_eq!(host.core.attempts().count(), 1);
    }

    // -- G004: promotion retains work ---------------------------------------

    #[test]
    fn promotion_retains_generation_attempts_and_region() {
        let mut actor = actor();
        open_with_primary(&mut actor);
        assert_eq!(
            actor.join(
                join_request(OP_ONE.0, SubscriberKind::Speculative, 3),
                1_100,
                0
            ),
            JoinReceipt::JoinedExecution
        );
        // Partial execution exists BEFORE the promotion.
        assert_eq!(
            actor.advance_attempt(AttemptId(1), AttemptState::LeaseAccepted),
            AdvanceAttemptReceipt::Advanced
        );
        let generation_before = actor.active_generation().cloned();
        let region_before = actor.region().clone();

        assert_eq!(actor.promote(OP_ONE), PromoteReceipt::Promoted);

        // Same actor, same key, same generation; transferred inputs and
        // partial execution retained (§21.2).
        assert_eq!(actor.active_generation(), generation_before.as_ref());
        assert_eq!(actor.region(), &region_before);
        assert_eq!(actor.attempts().count(), 1);
        assert_eq!(
            actor.attempts().next().map(|entry| entry.state),
            Some(AttemptState::LeaseAccepted)
        );
        assert!(actor.has_foreground_interest());
        assert!(actor.brownout_suspended());
        assert_eq!(events_of(&actor, EventKind::Promoted), 1);
    }

    // -- G004: reference-counted interests ----------------------------------

    #[test]
    fn interest_refcount_survives_partial_cancel() {
        let mut actor = actor();
        open_with_primary(&mut actor);
        assert_eq!(
            actor.join(
                join_request(OP_ONE.0, SubscriberKind::ForegroundAgent, 40),
                1_100,
                0
            ),
            JoinReceipt::JoinedExecution
        );
        // A second interest handle for the SAME operation.
        assert_eq!(
            actor.join(
                join_request(OP_ONE.0, SubscriberKind::ForegroundAgent, 50),
                1_150,
                0
            ),
            JoinReceipt::Rejoined { interests: 2 }
        );

        // First detach: only one reference dies; delivery state survives.
        assert_eq!(
            actor.cancel_subscriber(OP_ONE),
            CancelReceipt::InterestDecremented { remaining: 1 }
        );
        assert!(actor.subscriber(&OP_ONE).is_some());
        assert_eq!(actor.slot(), PublicationSlotState::Executing);

        // Last detach: the real cancellation policy runs.
        assert_eq!(
            actor.cancel_subscriber(OP_ONE),
            CancelReceipt::LastInterestCancelledGeneration
        );
        assert!(actor.subscriber(&OP_ONE).is_none());
    }

    #[test]
    fn strongest_interest_aggregates_priority_and_deadline() {
        let mut actor = actor();
        open_with_primary(&mut actor);
        let mut bounded = join_request(OP_ONE.0, SubscriberKind::CiRequired, 30);
        bounded.deadline_unix_micros = Some(5_000);
        let mut urgent = join_request(OP_TWO.0, SubscriberKind::Speculative, 90);
        urgent.deadline_unix_micros = Some(2_000);

        assert_eq!(actor.strongest_interest(), None);
        assert_eq!(actor.join(bounded, 1_100, 0), JoinReceipt::JoinedExecution);
        assert_eq!(actor.join(urgent, 1_100, 0), JoinReceipt::JoinedExecution);

        let strongest = actor.strongest_interest().expect("interests live");
        assert_eq!(strongest.priority, 90);
        assert_eq!(strongest.earliest_deadline_unix_micros, Some(2_000));

        // The aggregate tracks cancellations.
        let _ = actor.cancel_subscriber(OP_TWO);
        let strongest = actor.strongest_interest().expect("one remains");
        assert_eq!(strongest.priority, 30);
        assert_eq!(strongest.earliest_deadline_unix_micros, Some(5_000));
    }

    // -- G004: per-subscriber requirement filtering ---------------------------

    #[test]
    fn serving_filter_matches_requirements_per_subscriber() {
        let mut actor = actor();
        open_with_primary(&mut actor);
        assert_eq!(
            actor.join(
                join_request(OP_ONE.0, SubscriberKind::ForegroundAgent, 10),
                1_100,
                0
            ),
            JoinReceipt::JoinedExecution
        );
        // Pre-commit: compatible subscribers wait as pending verification;
        // unknown operations have no filter answer at all.
        assert_eq!(
            actor.serving_filter(&OP_ONE),
            Some(RequirementDecision::NeedsAdditionalVerification)
        );
        assert_eq!(actor.serving_filter(&OP_TWO), None, "unknown operation");

        drive_to_offer(&mut actor, 1);
        assert_eq!(
            actor.offer_candidate(offer(1, 42, false)),
            OfferReceipt::AcceptedAsWinner
        );

        // Post-commit joiners land on committed-but-EvidencePending.
        let mut demanding = join_request(OP_TWO.0, SubscriberKind::DeterminismAudit, 20);
        demanding.requirements.minimum_evidence_bundles = 2;
        assert_eq!(
            actor.join(demanding, 1_200, 0),
            JoinReceipt::CommittedButNotServable(ActionServingDisposition::EvidencePending)
        );
        let mut wrong_isolation = join_request(3, SubscriberKind::ForegroundAgent, 30);
        wrong_isolation.requirements.acceptable_isolation =
            Some(vec![IsolationProfile::VolatileLocal]);
        let _ = actor.join(wrong_isolation, 1_200, 0);
        let mut wrong_scope = join_request(4, SubscriberKind::CiRequired, 40);
        wrong_scope.requirements.privacy_scope = Some("other-scope".into());
        let _ = actor.join(wrong_scope, 1_200, 0);
        let mut wrong_platform = join_request(5, SubscriberKind::CiRequired, 50);
        wrong_platform.requirements.platform = Some(d(99));
        let _ = actor.join(wrong_platform, 1_200, 0);

        // Unrestricted subscriber: served.
        assert_eq!(
            actor.serving_filter(&OP_ONE),
            Some(RequirementDecision::Served)
        );
        // Evidence shortfall stays satisfiable via verification attempts.
        assert_eq!(
            actor.serving_filter(&OP_TWO),
            Some(RequirementDecision::NeedsAdditionalVerification)
        );
        // Identity mismatches can NEVER be served from this result.
        assert_eq!(
            actor.serving_filter(&BuildOperationId(3)),
            Some(RequirementDecision::Refused(
                RequirementRefusal::IsolationUnacceptable
            ))
        );
        assert_eq!(
            actor.serving_filter(&BuildOperationId(4)),
            Some(RequirementDecision::Refused(
                RequirementRefusal::PrivacyScopeMismatch
            ))
        );
        assert_eq!(
            actor.serving_filter(&BuildOperationId(5)),
            Some(RequirementDecision::Refused(
                RequirementRefusal::PlatformMismatch
            ))
        );

        // Completing evidence upgrades the shortfall to Served.
        actor.record_evidence(d(80), false);
        actor.record_evidence(d(81), false);
        assert_eq!(
            actor.serving_filter(&OP_TWO),
            Some(RequirementDecision::Served)
        );
    }
}
