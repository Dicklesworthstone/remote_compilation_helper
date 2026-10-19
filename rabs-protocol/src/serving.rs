//! Mutable serving disposition and versioned trust evaluation, layered
//! over immutable publication history (bead A020; invariants I42/I50;
//! risks R99/R126).
//!
//! A committed `ActionPublicationRecord` is history and never changes.
//! Everything that CAN change — eligibility, evidence expiry, quarantine,
//! object availability, retention eviction, trust tier — lives in the
//! records here, keyed by a monotonic `state_revision` and bound to the
//! evaluating coordinator authority. Changing serving never rewrites
//! canonical result identity; the types make the mutation target explicit.
//!
//! Clock discipline (risk R126): durable TTLs use `ServingValidity` with a
//! coordinator clock epoch and an uncertainty bound; wall-clock rollback,
//! epoch discontinuity, or uncertainty that crosses the not-after bound
//! expires serving **conservatively** (deny), never optimistically.

use crate::authority_matrix::IsolationProfile;
use crate::provenance_receipt::{
    MAX_AUTHENTICATOR_BYTES, NO_CLAIM_CACHE_EQUIVALENCE_PROVES_APPLICATION_CORRECTNESS,
    VerificationLevel,
};
use crate::result_identity::{DigestAlgorithm, ObjectId, TypedDigest};
use crate::wire_time::PeerId;

/// Current serving disposition for one committed publication (plan §178).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionServingDisposition {
    /// Servable to subscribers whose requirements the trust evaluation meets.
    Eligible,
    /// Committed but awaiting required evidence.
    EvidencePending,
    /// Validity elapsed (e.g. deterministic-failure TTL); revalidation
    /// required before serving resumes.
    ExpiredNeedsRevalidation,
    /// Blocked by one or more quarantine incidents.
    Quarantined,
    /// Result closure objects not currently available locally/fleet-wide.
    ObjectsUnavailable,
    /// Evicted from the active index (tombstone retains result digests for
    /// divergence detection — bead H034).
    EvictedFromActiveIndex,
}

/// Durable validity with conservative clock handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServingValidity {
    /// Coordinator wall-clock microseconds at evaluation (diagnostic +
    /// TTL base within one clock epoch).
    pub evaluated_at_unix_micros: i64,
    /// Maximum age in microseconds; `None` = no expiry.
    pub maximum_age_micros: Option<u64>,
    /// Clock uncertainty bound at evaluation time.
    pub clock_uncertainty_micros: u64,
    /// Coordinator clock epoch (bumped on detected discontinuity/rollback).
    pub coordinator_clock_epoch: u64,
}

impl ServingValidity {
    /// Conservative validity check at `now` within `now_epoch`.
    ///
    /// Denies when: the clock epoch changed (discontinuity), the clock ran
    /// backward, or `now + uncertainty` crosses the not-after bound.
    #[must_use]
    pub const fn still_valid(&self, now_unix_micros: i64, now_epoch: u64) -> bool {
        if now_epoch != self.coordinator_clock_epoch {
            return false;
        }
        if now_unix_micros < self.evaluated_at_unix_micros {
            return false;
        }
        match self.maximum_age_micros {
            None => true,
            Some(max_age) => {
                let age = now_unix_micros.saturating_sub(self.evaluated_at_unix_micros);
                let age_with_uncertainty =
                    (age as u64).saturating_add(self.clock_uncertainty_micros);
                age_with_uncertainty <= max_age
            }
        }
    }
}

/// The mutable serving-state record (revisioned, authority-bound).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionServingStateRecord {
    /// Which publication this disposition governs (immutable target).
    pub publication_record_id: ObjectId,
    /// Current disposition.
    pub disposition: ActionServingDisposition,
    /// Quarantine incidents blocking serving (IDs are the authority; a
    /// reason string is never the gate — risk R126).
    pub blocking_quarantine_ids: Vec<u64>,
    /// Monotonic revision; replays with a stale revision are rejected.
    pub state_revision: u64,
    /// Digest of the coordinator authority that evaluated this state.
    pub coordinator_authority_digest: TypedDigest,
    /// Conservative validity window.
    pub validity: ServingValidity,
}

impl ActionServingStateRecord {
    /// Whether `update` may replace `self`: same publication, strictly newer
    /// revision. A stale or equal revision is a replay and is refused —
    /// idempotency lives at the message layer, not by overwriting state.
    #[must_use]
    pub fn accepts_update(&self, update: &Self) -> bool {
        self.publication_record_id == update.publication_record_id
            && update.state_revision > self.state_revision
    }

    /// Whether this record permits serving right now.
    #[must_use]
    pub const fn may_serve_now(&self, now_unix_micros: i64, now_epoch: u64) -> bool {
        matches!(self.disposition, ActionServingDisposition::Eligible)
            && self.blocking_quarantine_ids.is_empty()
            && self.validity.still_valid(now_unix_micros, now_epoch)
    }
}

/// Evidence tiers (labels of observed evidence + policy approval — never
/// assertions of semantic correctness; plan §113).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrustEvidenceTier {
    /// Produced, not yet verified.
    UnverifiedCandidate,
    /// Matched an authoritative stock execution under the recorded profile.
    ShadowMatched,
    /// Repeated executions matched on the same worker.
    ReproducibleSameWorker,
    /// Repeated executions matched across workers.
    ReproducibleCrossWorker,
    /// Produced/verified by an authorized CI lane.
    CiPolicyApproved,
    /// Project policy grants release eligibility (a policy decision; RABS
    /// does not claim compilation equivalence proves app correctness).
    ProjectReleaseEligible,
}

/// One immutable, versioned trust evaluation over an append-only evidence
/// set (I42: promotion/demotion never rewrites the publication).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionTrustEvaluationRecord {
    /// The canonical result being evaluated.
    canonical_result_manifest_id: ObjectId,
    /// Digest over the canonically sorted + deduplicated evidence-bundle
    /// ID set (see [`evidence_set_digest_input`]).
    evidence_set_digest: TypedDigest,
    /// The evaluated tier.
    evaluated_tier: TrustEvidenceTier,
    /// Monotonic evaluation sequence (later evaluations supersede).
    evaluated_causal_sequence: u64,
}

/// Refusal to construct a trust evaluation without its required policy gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustEvaluationConstructionRefusal {
    /// CI/release tiers require their dedicated policy evaluators; a caller
    /// cannot assert one through the ordinary observed-evidence constructor.
    PolicyApprovalRequired,
}

impl ActionTrustEvaluationRecord {
    /// Construct a record from ordinary observed evidence. Policy-granted
    /// tiers are structurally refused; S011's verified evaluator is the only
    /// public path to `CiPolicyApproved`.
    ///
    /// # Errors
    /// [`TrustEvaluationConstructionRefusal::PolicyApprovalRequired`] for CI
    /// or project-release policy tiers.
    pub fn from_observed_evidence(
        canonical_result_manifest_id: ObjectId,
        evidence_set_digest: TypedDigest,
        evaluated_tier: TrustEvidenceTier,
        evaluated_causal_sequence: u64,
    ) -> Result<Self, TrustEvaluationConstructionRefusal> {
        if evaluated_tier >= TrustEvidenceTier::CiPolicyApproved {
            return Err(TrustEvaluationConstructionRefusal::PolicyApprovalRequired);
        }
        Ok(Self {
            canonical_result_manifest_id,
            evidence_set_digest,
            evaluated_tier,
            evaluated_causal_sequence,
        })
    }

    /// Canonical result referenced by this immutable evaluation.
    #[must_use]
    pub const fn canonical_result_manifest_id(&self) -> &ObjectId {
        &self.canonical_result_manifest_id
    }

    /// Canonical evidence-set digest evaluated.
    #[must_use]
    pub const fn evidence_set_digest(&self) -> &TypedDigest {
        &self.evidence_set_digest
    }

    /// Evidence/policy tier granted by this evaluation.
    #[must_use]
    pub const fn evaluated_tier(&self) -> TrustEvidenceTier {
        self.evaluated_tier
    }

    /// Monotonic causal sequence of this evaluation.
    #[must_use]
    pub const fn evaluated_causal_sequence(&self) -> u64 {
        self.evaluated_causal_sequence
    }

    fn ci_policy_approved(context: &CiEvaluationContext) -> Self {
        Self {
            canonical_result_manifest_id: context.expected_canonical_result_manifest_id.clone(),
            evidence_set_digest: context.expected_evidence_set_digest.clone(),
            evaluated_tier: TrustEvidenceTier::CiPolicyApproved,
            evaluated_causal_sequence: context.coordinator_causal_sequence,
        }
    }

    fn project_release_eligible(
        canonical_result_manifest_id: ObjectId,
        evidence_set_digest: TypedDigest,
        evaluated_causal_sequence: u64,
    ) -> Self {
        Self {
            canonical_result_manifest_id,
            evidence_set_digest,
            evaluated_tier: TrustEvidenceTier::ProjectReleaseEligible,
            evaluated_causal_sequence,
        }
    }
}

/// Canonicalize an evidence-ID set for digesting: sorted, deduplicated.
/// Append-only growth therefore changes the digest deterministically, and
/// insertion order can never produce two names for one set.
#[must_use]
pub fn evidence_set_digest_input(mut ids: Vec<[u8; 32]>) -> Vec<[u8; 32]> {
    ids.sort_unstable();
    ids.dedup();
    ids
}

/// Canonical framing version for signed CI policy claims (bead S011).
pub const CI_POLICY_CLAIM_SCHEMA_VERSION: u32 = 1;
/// Schema version for CI canonical-writer policy revisions.
pub const CI_CANONICAL_WRITER_POLICY_SCHEMA_VERSION: u32 = 1;
/// Domain of the stable identity shared by revisions of one CI policy.
pub const CI_POLICY_ID_DOMAIN: &str = "rabs.ci-policy-id.sha256.v1";
/// Domain of the content digest naming one exact CI policy revision.
pub const CI_POLICY_CONTENT_DOMAIN: &str = "rabs.ci-policy-content.sha256.v1";
/// Canonical framing domain for one exact CI policy revision.
pub const CI_POLICY_FRAMING_DOMAIN: &str = "rabs.ci-policy-canonical.v1";
/// Canonical framing domain for signed CI trust claims.
pub const CI_POLICY_CLAIM_FRAMING_DOMAIN: &str = "rabs.ci-policy-claim.v1";
/// Only action-key digests in this semantic domain may be authorized.
pub const CI_ACTION_KEY_DOMAIN: &str = "rabs.action-key.sha256.v1";
/// Only canonical result-manifest objects in this domain may be approved.
pub const CI_RESULT_MANIFEST_DOMAIN: &str = "rabs.object.sha256.v1";
/// Only independently derived evidence-set digests in this domain may be used.
pub const CI_EVIDENCE_SET_DOMAIN: &str = "rabs.evidence-set.sha256.v1";
/// Only rotation-safe signer fingerprints in this domain may authorize a lane.
pub const CI_SIGNER_FINGERPRINT_DOMAIN: &str = "rabs.identity-fingerprint.sha256.v1";
/// Maximum number of lane authorizations in one policy revision.
pub const MAX_CI_POLICY_AUTHORIZATIONS: usize = 256;
/// Maximum UTF-8 byte length of a CI lane identifier.
pub const MAX_CI_LANE_ID_BYTES: usize = 128;

/// How an authorized CI lane participated in a canonical publication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CiLaneRole {
    /// The lane produced the canonical result and its evidence.
    Producer,
    /// The lane independently verified an existing canonical result.
    Verifier,
}

impl CiLaneRole {
    const fn tag(self) -> u8 {
        match self {
            Self::Producer => 1,
            Self::Verifier => 2,
        }
    }
}

/// Closed set of signature algorithms admitted by the V1 CI policy wire form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CiSignatureAlgorithm {
    /// Ed25519 over the canonical claim body.
    Ed25519V1,
    /// ECDSA P-256 with SHA-256 over the canonical claim body.
    EcdsaP256Sha256V1,
}

impl CiSignatureAlgorithm {
    const fn tag(self) -> u8 {
        match self {
            Self::Ed25519V1 => 1,
            Self::EcdsaP256Sha256V1 => 2,
        }
    }
}

/// The action-key subset one CI authorization is allowed to approve.
///
/// Scope matching always includes digest algorithm and semantic domain.
/// Broad authority is represented explicitly by `AnyAction`, never by a
/// digest-prefix convention that could accidentally overlap another grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CiActionKeyScope {
    /// Exactly one action key.
    Exact(TypedDigest),
    /// Every action key in one typed-digest domain, across every project.
    /// This is intentionally broad and must be granted only to a fleet-wide
    /// canonical writer; use [`Self::Exact`] for project-specific authority.
    AnyAction {
        /// Admitted digest algorithm.
        algorithm: DigestAlgorithm,
        /// Exact semantic domain separator.
        domain: String,
    },
}

impl CiActionKeyScope {
    /// Whether this scope contains `action_key`.
    #[must_use]
    pub fn contains(&self, action_key: &TypedDigest) -> bool {
        match self {
            Self::Exact(expected) => expected == action_key,
            Self::AnyAction { algorithm, domain } => {
                *algorithm == action_key.algorithm && domain == action_key.domain
            }
        }
    }

    fn is_valid(&self) -> bool {
        match self {
            Self::Exact(digest) => digest_has_domain(digest, CI_ACTION_KEY_DOMAIN),
            Self::AnyAction { domain, .. } => domain == CI_ACTION_KEY_DOMAIN,
        }
    }
}

/// One lane/signer/scope grant in a versioned CI canonical-writer policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiLaneAuthorization {
    /// Stable operator-defined lane identity.
    pub lane_id: String,
    /// Fingerprint of the key allowed to sign this lane's claims.
    pub signer_fingerprint: TypedDigest,
    /// Rotation generation of the allowed signing key.
    pub signer_generation: u64,
    /// Signature algorithm the policy permits for this key.
    pub signature_algorithm: CiSignatureAlgorithm,
    /// Action keys this lane may approve.
    pub action_key_scope: CiActionKeyScope,
    /// Whether the lane produced or independently verified the result.
    pub role: CiLaneRole,
    /// Minimum recorded S006 verification evidence required.
    pub minimum_verification: VerificationLevel,
    /// Revocation is fail-closed without deleting policy history.
    pub revoked: bool,
}

/// One immutable revision of the CI canonical-writer authorization policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiCanonicalWriterPolicy {
    /// Policy schema version.
    pub schema_version: u32,
    /// Stable identity shared across revisions of this policy family.
    pub policy_id: TypedDigest,
    /// Content digest of this exact policy revision.
    pub policy_content_digest: TypedDigest,
    /// Monotonic policy revision; zero is invalid.
    pub version: u32,
    /// Whole-policy revocation switch.
    pub revoked: bool,
    /// Bounded lane authorization set.
    pub authorizations: Vec<CiLaneAuthorization>,
}

impl CiCanonicalWriterPolicy {
    /// Canonical policy bytes for storage-layer content-digest computation.
    /// `policy_content_digest` is excluded to avoid circular framing; lane
    /// authorizations are encoded then sorted so configuration order cannot
    /// rename one policy revision.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        ci_put_str(&mut out, CI_POLICY_FRAMING_DOMAIN);
        ci_put_u32(&mut out, self.schema_version);
        ci_put_digest(&mut out, &self.policy_id);
        ci_put_u32(&mut out, self.version);
        ci_put_u8(&mut out, u8::from(self.revoked));
        let mut authorizations: Vec<Vec<u8>> = self
            .authorizations
            .iter()
            .map(ci_authorization_bytes)
            .collect();
        authorizations.sort_unstable();
        ci_put_u64(&mut out, authorizations.len() as u64);
        for authorization in authorizations {
            ci_put_field(&mut out, &authorization);
        }
        out
    }
}

/// Detached authenticator over [`CiCanonicalWriterClaim::canonical_bytes`].
///
/// Bytes remain opaque here because `rabs-protocol` is deliberately
/// dependency-free. Presence is never treated as verification: the evaluator
/// must call a supplied cryptographic verifier before granting a tier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiClaimAuthenticator {
    /// Closed algorithm identifier, which must match the policy authorization.
    pub algorithm: CiSignatureAlgorithm,
    /// Detached signature/MAC bytes.
    pub bytes: Vec<u8>,
}

/// Signed assertion from one CI lane about one canonical result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiCanonicalWriterClaim {
    /// Canonical claim framing version.
    pub schema_version: u32,
    /// Exact policy revision under which the claim was issued.
    pub policy_version: u32,
    /// Stable policy family identity.
    pub policy_id: TypedDigest,
    /// Exact content digest of the policy revision applied.
    pub policy_content_digest: TypedDigest,
    /// Stable CI lane identity.
    pub lane_id: String,
    /// Signing-key fingerprint (rotation-safe identity).
    pub signer_fingerprint: TypedDigest,
    /// Signing-key generation.
    pub signer_generation: u64,
    /// Action key the canonical result answers.
    pub action_key: TypedDigest,
    /// Canonical manifest being approved.
    pub canonical_result_manifest_id: ObjectId,
    /// Canonical digest over the evidence bundle ID set.
    pub evidence_set_digest: TypedDigest,
    /// Whether this lane produced or verified the result.
    pub role: CiLaneRole,
    /// Verification evidence the lane attests was completed.
    pub verification: VerificationLevel,
    /// Causal sequence copied into the immutable trust evaluation.
    pub evaluated_causal_sequence: u64,
    /// Detached authenticator; excluded from the signed bytes themselves.
    pub authenticator: CiClaimAuthenticator,
}

impl CiCanonicalWriterClaim {
    /// Canonical, length-delimited bytes covered by the detached signature.
    /// Every authorization-sensitive fact is bound, including signer
    /// generation, role, verification level, and policy revision.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        ci_put_str(&mut out, CI_POLICY_CLAIM_FRAMING_DOMAIN);
        ci_put_u32(&mut out, self.schema_version);
        ci_put_digest(&mut out, &self.policy_id);
        ci_put_digest(&mut out, &self.policy_content_digest);
        ci_put_u32(&mut out, self.policy_version);
        ci_put_str(&mut out, &self.lane_id);
        ci_put_digest(&mut out, &self.signer_fingerprint);
        ci_put_u64(&mut out, self.signer_generation);
        ci_put_digest(&mut out, &self.action_key);
        ci_put_digest(&mut out, &self.canonical_result_manifest_id.0);
        ci_put_digest(&mut out, &self.evidence_set_digest);
        ci_put_u8(&mut out, self.role.tag());
        let (verification_tag, distinct_workers) = verification_framing(self.verification);
        ci_put_u8(&mut out, verification_tag);
        ci_put_u8(&mut out, distinct_workers);
        ci_put_u64(&mut out, self.evaluated_causal_sequence);
        ci_put_u8(&mut out, self.authenticator.algorithm.tag());
        out
    }
}

/// Coordinator-owned facts a CI signer is not allowed to choose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiEvaluationContext {
    /// Stable policy family the coordinator selected from policy history.
    pub expected_policy_id: TypedDigest,
    /// Durable current-policy version high-water from the coordinator store.
    pub expected_policy_version: u32,
    /// Durable content identity of that exact current policy revision.
    pub expected_policy_content_digest: TypedDigest,
    /// Action currently being evaluated.
    pub expected_action_key: TypedDigest,
    /// Published canonical manifest currently being evaluated.
    pub expected_canonical_result_manifest_id: ObjectId,
    /// Independently computed current evidence-set digest.
    pub expected_evidence_set_digest: TypedDigest,
    /// Verification level independently derived from admitted evidence.
    pub independently_observed_verification: VerificationLevel,
    /// Coordinator-assigned causal sequence for this evaluation.
    pub coordinator_causal_sequence: u64,
    /// Commit sequence of the publication being evaluated.
    pub publication_causal_sequence: u64,
    /// Durable trust-ledger high-water (`0` before the first evaluation).
    pub trust_ledger_high_water: u64,
}

/// Auditable result of applying one CI policy revision to a verified claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiPolicyApproval {
    /// Action key whose publication was approved.
    action_key: TypedDigest,
    /// General trust-evaluation record consumed by serving policy.
    evaluation: ActionTrustEvaluationRecord,
    /// Exact policy revision that authorized the lane.
    policy_version: u32,
    /// Stable policy family identity.
    policy_id: TypedDigest,
    /// Content digest of the exact applied policy revision.
    policy_content_digest: TypedDigest,
    /// Independently observed verification level accepted by policy.
    verification: VerificationLevel,
    /// Complete signed claim retained for audit and later reverification.
    verified_claim: CiCanonicalWriterClaim,
}

impl CiPolicyApproval {
    /// Action key approved by this opaque policy result.
    #[must_use]
    pub const fn action_key(&self) -> &TypedDigest {
        &self.action_key
    }

    /// Immutable general trust evaluation carrying `CiPolicyApproved`.
    #[must_use]
    pub const fn evaluation(&self) -> &ActionTrustEvaluationRecord {
        &self.evaluation
    }

    /// Exact policy revision applied.
    #[must_use]
    pub const fn policy_version(&self) -> u32 {
        self.policy_version
    }

    /// Stable policy family identity.
    #[must_use]
    pub const fn policy_id(&self) -> &TypedDigest {
        &self.policy_id
    }

    /// Content digest of the exact policy revision applied.
    #[must_use]
    pub const fn policy_content_digest(&self) -> &TypedDigest {
        &self.policy_content_digest
    }

    /// Authorized CI lane identity.
    #[must_use]
    pub fn lane_id(&self) -> &str {
        &self.verified_claim.lane_id
    }

    /// Verified signing-key fingerprint.
    #[must_use]
    pub const fn signer_fingerprint(&self) -> &TypedDigest {
        &self.verified_claim.signer_fingerprint
    }

    /// Verified signing-key generation.
    #[must_use]
    pub const fn signer_generation(&self) -> u64 {
        self.verified_claim.signer_generation
    }

    /// Authorized producer/verifier role.
    #[must_use]
    pub const fn role(&self) -> CiLaneRole {
        self.verified_claim.role
    }

    /// Verification level independently observed by the coordinator.
    #[must_use]
    pub const fn verification(&self) -> VerificationLevel {
        self.verification
    }

    /// Complete claim whose authenticator was cryptographically accepted.
    #[must_use]
    pub const fn verified_claim(&self) -> &CiCanonicalWriterClaim {
        &self.verified_claim
    }
}

/// Typed refusal from CI policy validation/evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CiPolicyRefusal {
    /// Policy schema version is not supported.
    UnsupportedPolicySchema,
    /// Policy ID/content digests do not carry their required domains.
    MalformedPolicyIdentity,
    /// Policy revision zero is never valid.
    InvalidPolicyVersion,
    /// Policy history contains duplicate revisions for one policy identity.
    AmbiguousPolicyHistory,
    /// No policy revision exists for the coordinator-selected identity.
    NoCurrentPolicy,
    /// The entire policy revision has been revoked.
    PolicyRevoked,
    /// The policy exceeds its bounded authorization count.
    TooManyAuthorizations,
    /// A policy authorization has a malformed lane, signer, algorithm, or
    /// action-key scope.
    MalformedAuthorization,
    /// A policy asks for an impossible verification level (for example,
    /// cross-worker consensus with fewer than two workers).
    InvalidVerificationRequirement,
    /// Two grants for the same lane/signer/role overlap in action scope.
    AmbiguousAuthorization,
    /// Claim framing version is not supported.
    UnsupportedClaimSchema,
    /// A claim has malformed/bounds-violating fields or authenticator bytes.
    MalformedClaim,
    /// The coordinator supplied malformed expected facts.
    InvalidEvaluationContext,
    /// Claim/current policy family differs from coordinator selection.
    PolicyIdentityMismatch,
    /// Claim and active policy revisions differ (stale/future claim).
    PolicyVersionMismatch,
    /// Claim names different policy bytes at the same revision.
    PolicyContentMismatch,
    /// The injected digest verifier rejected the selected policy bytes.
    InvalidPolicyContentDigest,
    /// Claim action differs from the coordinator's action.
    ActionKeyMismatch,
    /// Claim manifest differs from the published canonical manifest.
    CanonicalManifestMismatch,
    /// Claim evidence set differs from the independently computed set.
    EvidenceSetMismatch,
    /// Claim verification differs from independently admitted evidence.
    VerificationMismatch,
    /// Signer-supplied and coordinator-assigned evaluation sequences differ.
    CausalSequenceMismatch,
    /// Coordinator sequence is not newer than both the publication and the
    /// durable trust-ledger high-water.
    NonMonotonicEvaluationSequence,
    /// No authorization names the presented lane.
    UnauthorizedLane,
    /// The lane does not authorize the presented fingerprint/generation.
    UnauthorizedSigner,
    /// The signer is not authorized for the presented signature algorithm.
    SignatureAlgorithmNotAuthorized,
    /// The lane/signer is not authorized for the claimed role.
    RoleNotAuthorized,
    /// No matching lane/signer/role grant contains the action key.
    ActionKeyOutOfScope,
    /// Every otherwise matching grant is revoked.
    AuthorizationRevoked,
    /// The claim presents structurally invalid verification evidence.
    InvalidVerificationEvidence,
    /// Recorded evidence does not meet the policy's minimum.
    InsufficientVerification {
        /// Minimum required by the matching authorization set.
        required: VerificationLevel,
        /// Level presented by the claim.
        presented: VerificationLevel,
    },
    /// The supplied cryptographic verifier rejected the detached signature.
    InvalidSignature,
}

/// Validate a CI policy revision before it is admitted or evaluated.
///
/// # Errors
/// A typed refusal naming the first fail-closed structural defect.
pub fn validate_ci_canonical_writer_policy(
    policy: &CiCanonicalWriterPolicy,
) -> Result<(), CiPolicyRefusal> {
    if policy.schema_version != CI_CANONICAL_WRITER_POLICY_SCHEMA_VERSION {
        return Err(CiPolicyRefusal::UnsupportedPolicySchema);
    }
    if !digest_has_domain(&policy.policy_id, CI_POLICY_ID_DOMAIN)
        || !digest_has_domain(&policy.policy_content_digest, CI_POLICY_CONTENT_DOMAIN)
    {
        return Err(CiPolicyRefusal::MalformedPolicyIdentity);
    }
    if policy.version == 0 {
        return Err(CiPolicyRefusal::InvalidPolicyVersion);
    }
    if policy.authorizations.len() > MAX_CI_POLICY_AUTHORIZATIONS {
        return Err(CiPolicyRefusal::TooManyAuthorizations);
    }
    for authorization in &policy.authorizations {
        if !valid_lane_id(&authorization.lane_id)
            || authorization.signer_generation == 0
            || !digest_has_domain(
                &authorization.signer_fingerprint,
                CI_SIGNER_FINGERPRINT_DOMAIN,
            )
            || !authorization.action_key_scope.is_valid()
        {
            return Err(CiPolicyRefusal::MalformedAuthorization);
        }
        if !valid_verification_level(authorization.minimum_verification) {
            return Err(CiPolicyRefusal::InvalidVerificationRequirement);
        }
    }
    for (index, authorization) in policy.authorizations.iter().enumerate() {
        if policy
            .authorizations
            .iter()
            .skip(index + 1)
            .any(|other| authorizations_are_ambiguous(authorization, other))
        {
            return Err(CiPolicyRefusal::AmbiguousAuthorization);
        }
    }
    Ok(())
}

/// Evaluate one signed CI claim under the unique current policy revision.
///
/// `verify_policy_content` recomputes the selected policy's content digest
/// from its canonical bytes. `verify_signature` receives the policy-authorized
/// algorithm, fingerprint, generation, canonical claim bytes, and detached
/// authenticator. The signature verifier is invoked only after every
/// lane/scope/role/evidence check passes; an authenticator's mere presence can
/// never grant trust.
///
/// One claim establishes exactly one authorized role: producer **or**
/// verifier. A policy that requires independent production and verification
/// must evaluate two claims from the separately authorized identities.
///
/// # Errors
/// A typed refusal for malformed, stale, unauthorized, revoked,
/// insufficiently verified, or cryptographically invalid claims.
pub fn evaluate_ci_canonical_writer_claim<P, F>(
    policy_history: &[CiCanonicalWriterPolicy],
    claim: &CiCanonicalWriterClaim,
    context: &CiEvaluationContext,
    verify_policy_content: P,
    verify_signature: F,
) -> Result<CiPolicyApproval, CiPolicyRefusal>
where
    P: FnOnce(&TypedDigest, &[u8]) -> bool,
    F: FnOnce(CiSignatureAlgorithm, &TypedDigest, u64, &[u8], &[u8]) -> bool,
{
    validate_ci_evaluation_context(context)?;
    validate_ci_claim(claim)?;
    let policy = current_ci_policy(policy_history, &context.expected_policy_id)?;

    if policy.version != context.expected_policy_version {
        return Err(CiPolicyRefusal::PolicyVersionMismatch);
    }
    if policy.policy_content_digest != context.expected_policy_content_digest {
        return Err(CiPolicyRefusal::PolicyContentMismatch);
    }
    if policy.revoked {
        return Err(CiPolicyRefusal::PolicyRevoked);
    }
    let canonical_policy = policy.canonical_bytes();
    if !verify_policy_content(&policy.policy_content_digest, &canonical_policy) {
        return Err(CiPolicyRefusal::InvalidPolicyContentDigest);
    }
    validate_ci_claim_bindings(policy, claim, context)?;
    authorize_ci_claim(policy, claim, context.independently_observed_verification)?;

    let canonical_bytes = claim.canonical_bytes();
    if !verify_signature(
        claim.authenticator.algorithm,
        &claim.signer_fingerprint,
        claim.signer_generation,
        &canonical_bytes,
        &claim.authenticator.bytes,
    ) {
        return Err(CiPolicyRefusal::InvalidSignature);
    }

    Ok(CiPolicyApproval {
        action_key: context.expected_action_key.clone(),
        evaluation: ActionTrustEvaluationRecord::ci_policy_approved(context),
        policy_version: policy.version,
        policy_id: policy.policy_id.clone(),
        policy_content_digest: policy.policy_content_digest.clone(),
        verification: context.independently_observed_verification,
        verified_claim: claim.clone(),
    })
}

fn validate_ci_claim_bindings(
    policy: &CiCanonicalWriterPolicy,
    claim: &CiCanonicalWriterClaim,
    context: &CiEvaluationContext,
) -> Result<(), CiPolicyRefusal> {
    if claim.policy_id != context.expected_policy_id || claim.policy_id != policy.policy_id {
        return Err(CiPolicyRefusal::PolicyIdentityMismatch);
    }
    if claim.policy_version != policy.version {
        return Err(CiPolicyRefusal::PolicyVersionMismatch);
    }
    if claim.policy_content_digest != policy.policy_content_digest {
        return Err(CiPolicyRefusal::PolicyContentMismatch);
    }
    if claim.action_key != context.expected_action_key {
        return Err(CiPolicyRefusal::ActionKeyMismatch);
    }
    if claim.canonical_result_manifest_id != context.expected_canonical_result_manifest_id {
        return Err(CiPolicyRefusal::CanonicalManifestMismatch);
    }
    if claim.evidence_set_digest != context.expected_evidence_set_digest {
        return Err(CiPolicyRefusal::EvidenceSetMismatch);
    }
    if claim.verification != context.independently_observed_verification {
        return Err(CiPolicyRefusal::VerificationMismatch);
    }
    if claim.evaluated_causal_sequence != context.coordinator_causal_sequence {
        return Err(CiPolicyRefusal::CausalSequenceMismatch);
    }
    Ok(())
}

fn authorize_ci_claim(
    policy: &CiCanonicalWriterPolicy,
    claim: &CiCanonicalWriterClaim,
    observed_verification: VerificationLevel,
) -> Result<(), CiPolicyRefusal> {
    if !policy
        .authorizations
        .iter()
        .any(|authorization| authorization.lane_id == claim.lane_id)
    {
        return Err(CiPolicyRefusal::UnauthorizedLane);
    }
    if !policy.authorizations.iter().any(|authorization| {
        authorization.lane_id == claim.lane_id
            && authorization.signer_fingerprint == claim.signer_fingerprint
            && authorization.signer_generation == claim.signer_generation
    }) {
        return Err(CiPolicyRefusal::UnauthorizedSigner);
    }
    if !policy.authorizations.iter().any(|authorization| {
        authorization.lane_id == claim.lane_id
            && authorization.signer_fingerprint == claim.signer_fingerprint
            && authorization.signer_generation == claim.signer_generation
            && authorization.signature_algorithm == claim.authenticator.algorithm
    }) {
        return Err(CiPolicyRefusal::SignatureAlgorithmNotAuthorized);
    }
    if !policy.authorizations.iter().any(|authorization| {
        authorization.lane_id == claim.lane_id
            && authorization.signer_fingerprint == claim.signer_fingerprint
            && authorization.signer_generation == claim.signer_generation
            && authorization.signature_algorithm == claim.authenticator.algorithm
            && authorization.role == claim.role
    }) {
        return Err(CiPolicyRefusal::RoleNotAuthorized);
    }
    let scoped_authorizations: Vec<&CiLaneAuthorization> = policy
        .authorizations
        .iter()
        .filter(|authorization| {
            authorization.lane_id == claim.lane_id
                && authorization.signer_fingerprint == claim.signer_fingerprint
                && authorization.signer_generation == claim.signer_generation
                && authorization.signature_algorithm == claim.authenticator.algorithm
                && authorization.role == claim.role
                && authorization.action_key_scope.contains(&claim.action_key)
        })
        .collect();
    if scoped_authorizations.is_empty() {
        return Err(CiPolicyRefusal::ActionKeyOutOfScope);
    }
    let active_authorizations: Vec<&CiLaneAuthorization> = scoped_authorizations
        .into_iter()
        .filter(|authorization| !authorization.revoked)
        .collect();
    if active_authorizations.is_empty() {
        return Err(CiPolicyRefusal::AuthorizationRevoked);
    }
    if !active_authorizations.iter().any(|authorization| {
        verification_meets(observed_verification, authorization.minimum_verification)
    }) {
        let Some(required) = active_authorizations
            .iter()
            .map(|authorization| authorization.minimum_verification)
            .min_by_key(|minimum| verification_requirement_key(*minimum))
        else {
            return Err(CiPolicyRefusal::AuthorizationRevoked);
        };
        return Err(CiPolicyRefusal::InsufficientVerification {
            required,
            presented: observed_verification,
        });
    }
    Ok(())
}

fn current_ci_policy<'a>(
    policy_history: &'a [CiCanonicalWriterPolicy],
    expected_policy_id: &TypedDigest,
) -> Result<&'a CiCanonicalWriterPolicy, CiPolicyRefusal> {
    use std::collections::BTreeSet;

    let mut seen_versions = BTreeSet::new();
    let mut current: Option<&CiCanonicalWriterPolicy> = None;
    for policy in policy_history
        .iter()
        .filter(|policy| policy.policy_id == *expected_policy_id)
    {
        validate_ci_canonical_writer_policy(policy)?;
        if !seen_versions.insert(policy.version) {
            return Err(CiPolicyRefusal::AmbiguousPolicyHistory);
        }
        if current.is_none_or(|candidate| policy.version > candidate.version) {
            current = Some(policy);
        }
    }
    let current = current.ok_or(CiPolicyRefusal::NoCurrentPolicy)?;
    Ok(current)
}

fn validate_ci_evaluation_context(context: &CiEvaluationContext) -> Result<(), CiPolicyRefusal> {
    if !digest_has_domain(&context.expected_policy_id, CI_POLICY_ID_DOMAIN)
        || context.expected_policy_version == 0
        || !digest_has_domain(
            &context.expected_policy_content_digest,
            CI_POLICY_CONTENT_DOMAIN,
        )
        || !digest_has_domain(&context.expected_action_key, CI_ACTION_KEY_DOMAIN)
        || !digest_has_domain(
            &context.expected_canonical_result_manifest_id.0,
            CI_RESULT_MANIFEST_DOMAIN,
        )
        || !digest_has_domain(
            &context.expected_evidence_set_digest,
            CI_EVIDENCE_SET_DOMAIN,
        )
        || !valid_verification_level(context.independently_observed_verification)
        || context.coordinator_causal_sequence == 0
        || context.publication_causal_sequence == 0
    {
        return Err(CiPolicyRefusal::InvalidEvaluationContext);
    }
    if context.coordinator_causal_sequence <= context.publication_causal_sequence
        || context.coordinator_causal_sequence <= context.trust_ledger_high_water
    {
        return Err(CiPolicyRefusal::NonMonotonicEvaluationSequence);
    }
    Ok(())
}

fn validate_ci_claim(claim: &CiCanonicalWriterClaim) -> Result<(), CiPolicyRefusal> {
    if claim.schema_version != CI_POLICY_CLAIM_SCHEMA_VERSION {
        return Err(CiPolicyRefusal::UnsupportedClaimSchema);
    }
    if claim.policy_version == 0
        || !digest_has_domain(&claim.policy_id, CI_POLICY_ID_DOMAIN)
        || !digest_has_domain(&claim.policy_content_digest, CI_POLICY_CONTENT_DOMAIN)
        || !valid_lane_id(&claim.lane_id)
        || claim.signer_generation == 0
        || !digest_has_domain(&claim.signer_fingerprint, CI_SIGNER_FINGERPRINT_DOMAIN)
        || !digest_has_domain(&claim.action_key, CI_ACTION_KEY_DOMAIN)
        || !digest_has_domain(
            &claim.canonical_result_manifest_id.0,
            CI_RESULT_MANIFEST_DOMAIN,
        )
        || !digest_has_domain(&claim.evidence_set_digest, CI_EVIDENCE_SET_DOMAIN)
        || claim.authenticator.bytes.is_empty()
        || claim.authenticator.bytes.len() > MAX_AUTHENTICATOR_BYTES
        || claim.evaluated_causal_sequence == 0
    {
        return Err(CiPolicyRefusal::MalformedClaim);
    }
    if !valid_verification_level(claim.verification) {
        return Err(CiPolicyRefusal::InvalidVerificationEvidence);
    }
    Ok(())
}

fn valid_identifier(value: &str, max_bytes: usize) -> bool {
    !value.is_empty() && value.len() <= max_bytes && value.trim() == value
}

fn valid_lane_id(value: &str) -> bool {
    valid_identifier(value, MAX_CI_LANE_ID_BYTES)
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
}

fn digest_has_domain(digest: &TypedDigest, expected_domain: &str) -> bool {
    digest.domain == expected_domain
}

fn scopes_overlap(left: &CiActionKeyScope, right: &CiActionKeyScope) -> bool {
    match (left, right) {
        (CiActionKeyScope::Exact(left), CiActionKeyScope::Exact(right)) => left == right,
        (CiActionKeyScope::AnyAction { algorithm, domain }, CiActionKeyScope::Exact(exact))
        | (CiActionKeyScope::Exact(exact), CiActionKeyScope::AnyAction { algorithm, domain }) => {
            *algorithm == exact.algorithm && domain == exact.domain
        }
        (
            CiActionKeyScope::AnyAction {
                algorithm: left_algorithm,
                domain: left_domain,
            },
            CiActionKeyScope::AnyAction {
                algorithm: right_algorithm,
                domain: right_domain,
            },
        ) => left_algorithm == right_algorithm && left_domain == right_domain,
    }
}

fn authorizations_are_ambiguous(left: &CiLaneAuthorization, right: &CiLaneAuthorization) -> bool {
    left.lane_id == right.lane_id
        && left.signer_fingerprint == right.signer_fingerprint
        && left.signer_generation == right.signer_generation
        && left.signature_algorithm == right.signature_algorithm
        && left.role == right.role
        && scopes_overlap(&left.action_key_scope, &right.action_key_scope)
}

const fn valid_verification_level(level: VerificationLevel) -> bool {
    !matches!(
        level,
        VerificationLevel::CrossWorkerConsensus {
            distinct_workers: 0 | 1
        }
    )
}

const fn verification_meets(actual: VerificationLevel, minimum: VerificationLevel) -> bool {
    match (actual, minimum) {
        (
            VerificationLevel::CrossWorkerConsensus {
                distinct_workers: actual_workers,
            },
            VerificationLevel::CrossWorkerConsensus {
                distinct_workers: required_workers,
            },
        ) => actual_workers >= required_workers,
        _ => actual.rank() >= minimum.rank(),
    }
}

const fn verification_framing(level: VerificationLevel) -> (u8, u8) {
    match level {
        VerificationLevel::None => (0, 0),
        VerificationLevel::CoordinatorDigestRecompute => (1, 0),
        VerificationLevel::IndependentReplay => (2, 0),
        VerificationLevel::CrossWorkerConsensus { distinct_workers } => (3, distinct_workers),
        VerificationLevel::StockToolchainComparison => (4, 0),
    }
}

const fn verification_requirement_key(level: VerificationLevel) -> (u8, u8) {
    let (rank, workers) = verification_framing(level);
    (rank, workers)
}

const fn digest_algorithm_tag(algorithm: DigestAlgorithm) -> u8 {
    match algorithm {
        DigestAlgorithm::Sha256V1 => 1,
    }
}

fn ci_authorization_bytes(authorization: &CiLaneAuthorization) -> Vec<u8> {
    let mut out = Vec::new();
    ci_put_str(&mut out, &authorization.lane_id);
    ci_put_digest(&mut out, &authorization.signer_fingerprint);
    ci_put_u64(&mut out, authorization.signer_generation);
    ci_put_u8(&mut out, authorization.signature_algorithm.tag());
    match &authorization.action_key_scope {
        CiActionKeyScope::Exact(action_key) => {
            ci_put_u8(&mut out, 1);
            ci_put_digest(&mut out, action_key);
        }
        CiActionKeyScope::AnyAction { algorithm, domain } => {
            ci_put_u8(&mut out, 2);
            ci_put_u8(&mut out, digest_algorithm_tag(*algorithm));
            ci_put_str(&mut out, domain);
        }
    }
    ci_put_u8(&mut out, authorization.role.tag());
    let (verification_tag, distinct_workers) =
        verification_framing(authorization.minimum_verification);
    ci_put_u8(&mut out, verification_tag);
    ci_put_u8(&mut out, distinct_workers);
    ci_put_u8(&mut out, u8::from(authorization.revoked));
    out
}

fn ci_put_field(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn ci_put_u8(out: &mut Vec<u8>, value: u8) {
    ci_put_field(out, &[value]);
}

fn ci_put_u32(out: &mut Vec<u8>, value: u32) {
    ci_put_field(out, &value.to_be_bytes());
}

fn ci_put_u64(out: &mut Vec<u8>, value: u64) {
    ci_put_field(out, &value.to_be_bytes());
}

fn ci_put_str(out: &mut Vec<u8>, value: &str) {
    ci_put_field(out, value.as_bytes());
}

fn ci_put_digest(out: &mut Vec<u8>, digest: &TypedDigest) {
    ci_put_u8(out, digest_algorithm_tag(digest.algorithm));
    ci_put_str(out, digest.domain);
    ci_put_field(out, &digest.bytes);
}

// ---------------------------------------------------------------------------
// S012: Project-defined release-eligibility policy + explicit non-claim
// ---------------------------------------------------------------------------

/// Schema version for project release-eligibility policies (bead S012).
pub const PROJECT_RELEASE_POLICY_SCHEMA_VERSION: u32 = 1;

/// Project-defined release-eligibility policy (bead S012).
///
/// `ProjectReleaseEligible` is a project policy decision layered on top of
/// observed/CI evidence tiers; RABS never claims that cache/compilation
/// equivalence proves application semantic correctness
/// ([`NO_CLAIM_CACHE_EQUIVALENCE_PROVES_APPLICATION_CORRECTNESS`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectReleaseEligibilityPolicy {
    /// Policy schema version ([`PROJECT_RELEASE_POLICY_SCHEMA_VERSION`]).
    pub schema_version: u32,
    /// Project identifier governed by this policy.
    pub project_id: String,
    /// Monotonic policy revision (`> 0`).
    pub policy_version: u32,
    /// Whether this policy revision is revoked.
    pub revoked: bool,
    /// Minimum prerequisite tier (`>= ReproducibleCrossWorker` or `CiPolicyApproved`).
    pub minimum_prerequisite_tier: TrustEvidenceTier,
    /// Minimum verification level required before release eligibility.
    pub minimum_verification: VerificationLevel,
}

/// Coordinator-verified input to [`evaluate_project_release_eligibility`] (bead S012).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectReleaseEligibilityInput {
    /// Project requesting release eligibility.
    pub project_id: String,
    /// Action key being evaluated.
    pub action_key: TypedDigest,
    /// Canonical result manifest being evaluated.
    pub canonical_result_manifest_id: ObjectId,
    /// Canonical evidence-set digest.
    pub evidence_set_digest: TypedDigest,
    /// Prerequisite trust evaluation record already achieved.
    pub prerequisite_evaluation: ActionTrustEvaluationRecord,
    /// Independently observed verification level.
    pub observed_verification: VerificationLevel,
    /// Coordinator causal sequence for the new evaluation (`> prerequisite_evaluation.evaluated_causal_sequence()`).
    pub coordinator_causal_sequence: u64,
    /// Non-claims carried on the release receipt/evaluation (must include
    /// [`NO_CLAIM_CACHE_EQUIVALENCE_PROVES_APPLICATION_CORRECTNESS`]).
    pub receipt_non_claims: Vec<&'static str>,
}

/// Auditable approval granting [`TrustEvidenceTier::ProjectReleaseEligible`] (bead S012).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectReleaseApproval {
    /// Project identifier.
    pub project_id: String,
    /// Policy revision applied.
    pub policy_version: u32,
    /// Action key approved for project release.
    pub action_key: TypedDigest,
    /// Immutable trust evaluation record at [`TrustEvidenceTier::ProjectReleaseEligible`].
    pub evaluation: ActionTrustEvaluationRecord,
    /// Explicit non-claims carried by the approval receipt (always includes
    /// [`NO_CLAIM_CACHE_EQUIVALENCE_PROVES_APPLICATION_CORRECTNESS`]).
    pub non_claims: Vec<&'static str>,
}

/// Typed refusal from [`evaluate_project_release_eligibility`] (bead S012).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectReleaseRefusal {
    /// Policy schema version is unsupported.
    UnsupportedPolicySchema,
    /// Policy version zero or empty project identifier.
    MalformedPolicy,
    /// Policy revision is revoked.
    PolicyRevoked,
    /// Policy sets a prerequisite floor weaker than `ReproducibleCrossWorker`.
    WeakPrerequisitePolicyFloor,
    /// Input project ID does not match the policy's project ID.
    ProjectIdMismatch,
    /// Input manifest or evidence set does not match the prerequisite evaluation.
    PrerequisiteBindingMismatch,
    /// Coordinator causal sequence does not strictly advance past the prerequisite evaluation.
    NonMonotonicEvaluationSequence,
    /// Prerequisite tier is below the policy's minimum prerequisite tier.
    InsufficientPrerequisiteTier {
        /// Required prerequisite tier.
        required: TrustEvidenceTier,
        /// Presented prerequisite tier.
        presented: TrustEvidenceTier,
    },
    /// Observed verification level is below the policy's minimum verification level.
    InsufficientVerification {
        /// Required verification level.
        required: VerificationLevel,
        /// Presented verification level.
        presented: VerificationLevel,
    },
    /// Receipt non-claims omitted [`NO_CLAIM_CACHE_EQUIVALENCE_PROVES_APPLICATION_CORRECTNESS`].
    MissingApplicationCorrectnessNonClaim,
}

/// Evaluate project-defined release eligibility and emit a
/// [`TrustEvidenceTier::ProjectReleaseEligible`] evaluation carrying the
/// mandatory [`NO_CLAIM_CACHE_EQUIVALENCE_PROVES_APPLICATION_CORRECTNESS`] non-claim (bead S012).
///
/// # Errors
/// [`ProjectReleaseRefusal`] if the policy is malformed/revoked, prerequisite
/// evidence is insufficient, or the explicit application-correctness non-claim is absent.
pub fn evaluate_project_release_eligibility(
    policy: &ProjectReleaseEligibilityPolicy,
    input: &ProjectReleaseEligibilityInput,
) -> Result<ProjectReleaseApproval, ProjectReleaseRefusal> {
    if policy.schema_version != PROJECT_RELEASE_POLICY_SCHEMA_VERSION {
        return Err(ProjectReleaseRefusal::UnsupportedPolicySchema);
    }
    if policy.policy_version == 0
        || policy.project_id.trim().is_empty()
        || !valid_verification_level(policy.minimum_verification)
    {
        return Err(ProjectReleaseRefusal::MalformedPolicy);
    }
    if policy.revoked {
        return Err(ProjectReleaseRefusal::PolicyRevoked);
    }
    if policy.minimum_prerequisite_tier < TrustEvidenceTier::ReproducibleCrossWorker {
        return Err(ProjectReleaseRefusal::WeakPrerequisitePolicyFloor);
    }
    if input.project_id != policy.project_id {
        return Err(ProjectReleaseRefusal::ProjectIdMismatch);
    }
    if input.prerequisite_evaluation.canonical_result_manifest_id()
        != &input.canonical_result_manifest_id
        || input.prerequisite_evaluation.evidence_set_digest() != &input.evidence_set_digest
    {
        return Err(ProjectReleaseRefusal::PrerequisiteBindingMismatch);
    }
    if input.coordinator_causal_sequence
        <= input.prerequisite_evaluation.evaluated_causal_sequence()
    {
        return Err(ProjectReleaseRefusal::NonMonotonicEvaluationSequence);
    }
    let presented_tier = input.prerequisite_evaluation.evaluated_tier();
    if presented_tier < policy.minimum_prerequisite_tier {
        return Err(ProjectReleaseRefusal::InsufficientPrerequisiteTier {
            required: policy.minimum_prerequisite_tier,
            presented: presented_tier,
        });
    }
    if !verification_meets(input.observed_verification, policy.minimum_verification) {
        return Err(ProjectReleaseRefusal::InsufficientVerification {
            required: policy.minimum_verification,
            presented: input.observed_verification,
        });
    }
    if !input
        .receipt_non_claims
        .contains(&NO_CLAIM_CACHE_EQUIVALENCE_PROVES_APPLICATION_CORRECTNESS)
    {
        return Err(ProjectReleaseRefusal::MissingApplicationCorrectnessNonClaim);
    }

    Ok(ProjectReleaseApproval {
        project_id: policy.project_id.clone(),
        policy_version: policy.policy_version,
        action_key: input.action_key.clone(),
        evaluation: ActionTrustEvaluationRecord::project_release_eligible(
            input.canonical_result_manifest_id.clone(),
            input.evidence_set_digest.clone(),
            input.coordinator_causal_sequence,
        ),
        non_claims: input.receipt_non_claims.clone(),
    })
}

// ---------------------------------------------------------------------------
// S018: Compromised-worker threat verification + cross-worker/stock policy (R79)
// ---------------------------------------------------------------------------

/// Release-tier verification policy addressing compromised-worker threats (bead S018; risk R79).
///
/// A cryptographically authenticated worker is still a semantic trust principal:
/// digests prove transport/storage integrity, not honest execution. Higher-trust
/// and release serving therefore require independent cross-worker consensus,
/// stock toolchain differential execution, or authorized CI approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseVerificationPolicy {
    /// Require at least `minimum_distinct_workers` (>= 2) independent authenticated workers
    /// to produce identical observable digests.
    TwoOrMoreIndependentWorkers {
        /// Minimum distinct authenticated workers (>= 2).
        minimum_distinct_workers: u8,
    },
    /// Require differential execution against a stock local toolchain run.
    StockDifferentialExecution,
    /// Require an authorized CI canonical-writer approval (`CiPolicyApproved`).
    CiApprovalRequired,
    /// Accept any of: >= 2 independent authenticated workers, stock differential execution,
    /// or authorized CI approval. Never accepts a single worker's uncorroborated execution.
    AnyHighTrustReleaseProof,
}

/// One worker execution observation compared by [`evaluate_release_verification_and_compromise`] (bead S018).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerAttemptObservation {
    /// Executing worker identity.
    pub worker_peer_id: PeerId,
    /// Whether the worker's transport/key identity was cryptographically authenticated.
    pub authenticated: bool,
    /// Observable output digest produced by this execution.
    pub observable_output_digest: TypedDigest,
}

/// Verdict of S018 release-tier verification and compromised-worker detection (risk R79).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompromisedWorkerVerdict {
    /// All observations matched and satisfied the release verification policy.
    VerifiedReleaseEligible {
        /// Derived verification level.
        verification_level: VerificationLevel,
        /// Count of distinct authenticated workers that agreed.
        distinct_authenticated_workers: u8,
    },
    /// No divergence occurred, but a single worker's execution (even cryptographically
    /// authenticated) does not meet the release verification policy (R79).
    InsufficientReleaseVerification {
        /// Derived verification level so far.
        observed_verification: VerificationLevel,
        /// Count of distinct authenticated workers observed.
        distinct_authenticated_workers: u8,
    },
    /// Worker output diverged from peer/stock verification: malicious or broken worker caught!
    /// Immediately revokes publication eligibility for the diverging worker(s) and quarantines the action.
    MaliciousOrDivergentWorkerDetected {
        /// Workers whose outputs diverged from the reference/consensus digest.
        revoked_workers: Vec<PeerId>,
        /// Whether authoritative publication eligibility is immediately revoked.
        publication_eligibility_revoked: bool,
        /// Whether the action is quarantined from serving.
        action_quarantined: bool,
        /// Stable incident reason code.
        reason: &'static str,
    },
}

/// Evaluate worker execution observations, optional stock-toolchain digest, and optional
/// CI approval against [`ReleaseVerificationPolicy`] (bead S018; risk R79).
///
/// Any digest mismatch between workers or against a stock toolchain reference immediately
/// returns [`CompromisedWorkerVerdict::MaliciousOrDivergentWorkerDetected`] and revokes
/// authoritative publication eligibility for the diverging worker(s).
#[must_use]
pub fn evaluate_release_verification_and_compromise(
    policy: ReleaseVerificationPolicy,
    observations: &[WorkerAttemptObservation],
    stock_toolchain_digest: Option<&TypedDigest>,
    ci_approved: bool,
) -> CompromisedWorkerVerdict {
    use std::collections::BTreeSet;

    let Some(first) = observations.first() else {
        return CompromisedWorkerVerdict::InsufficientReleaseVerification {
            observed_verification: VerificationLevel::None,
            distinct_authenticated_workers: 0,
        };
    };

    let reference_digest = stock_toolchain_digest.unwrap_or(&first.observable_output_digest);
    let mut diverging_workers = Vec::new();
    let mut distinct_authenticated = BTreeSet::new();

    for obs in observations {
        if &obs.observable_output_digest != reference_digest {
            if !diverging_workers.contains(&obs.worker_peer_id) {
                diverging_workers.push(obs.worker_peer_id.clone());
            }
        } else if obs.authenticated {
            distinct_authenticated.insert(obs.worker_peer_id.0.clone());
        }
    }

    if !diverging_workers.is_empty() {
        // If no stock digest anchored the comparison, every worker involved in a
        // conflicting multi-worker disagreement is removed from publication eligibility
        // until audited.
        if stock_toolchain_digest.is_none() {
            for obs in observations {
                if !diverging_workers.contains(&obs.worker_peer_id) {
                    diverging_workers.push(obs.worker_peer_id.clone());
                }
            }
        }
        return CompromisedWorkerVerdict::MaliciousOrDivergentWorkerDetected {
            revoked_workers: diverging_workers,
            publication_eligibility_revoked: true,
            action_quarantined: true,
            reason: "r79-semantic-divergence-detected-publication-eligibility-revoked",
        };
    }

    let distinct_count = u8::try_from(distinct_authenticated.len()).unwrap_or(u8::MAX);
    let observed_verification = if stock_toolchain_digest.is_some() && distinct_count >= 1 {
        VerificationLevel::StockToolchainComparison
    } else if distinct_count >= 2 {
        VerificationLevel::CrossWorkerConsensus {
            distinct_workers: distinct_count,
        }
    } else if distinct_count == 1 {
        VerificationLevel::CoordinatorDigestRecompute
    } else {
        VerificationLevel::None
    };

    let satisfied = match policy {
        ReleaseVerificationPolicy::TwoOrMoreIndependentWorkers {
            minimum_distinct_workers,
        } => {
            let required = minimum_distinct_workers.max(2);
            distinct_count >= required
        }
        ReleaseVerificationPolicy::StockDifferentialExecution => {
            matches!(
                observed_verification,
                VerificationLevel::StockToolchainComparison
            )
        }
        ReleaseVerificationPolicy::CiApprovalRequired => ci_approved && distinct_count >= 1,
        ReleaseVerificationPolicy::AnyHighTrustReleaseProof => {
            distinct_count >= 2
                || matches!(
                    observed_verification,
                    VerificationLevel::StockToolchainComparison
                )
                || (ci_approved && distinct_count >= 1)
        }
    };

    if satisfied {
        CompromisedWorkerVerdict::VerifiedReleaseEligible {
            verification_level: observed_verification,
            distinct_authenticated_workers: distinct_count,
        }
    } else {
        CompromisedWorkerVerdict::InsufficientReleaseVerification {
            observed_verification,
            distinct_authenticated_workers: distinct_count,
        }
    }
}

// ---------------------------------------------------------------------------
// S021: Per-subscriber minimum evidence/isolation/privacy requirements + re-evaluation (I42)
// ---------------------------------------------------------------------------

/// Per-subscriber minimum serving requirements (bead S021; invariant I42).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriberServingRequirements {
    /// Subscribing principal.
    pub subscriber_id: PeerId,
    /// Minimum trust evidence tier required by this subscriber.
    pub minimum_tier: TrustEvidenceTier,
    /// Minimum verification level required by this subscriber.
    pub minimum_verification: VerificationLevel,
    /// Minimum isolation profile required by this subscriber.
    pub required_isolation: IsolationProfile,
    /// Required privacy/secret scope (if `Some(scope)`, publication must match `scope`).
    pub required_privacy_scope: Option<String>,
    /// Whether this subscriber requires redacted diagnostics.
    pub require_redacted_diagnostics: bool,
}

/// Current committed publication and serving posture evaluated for a subscriber (bead S021; I42).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedPublicationPosture {
    /// Action key of the committed publication.
    pub action_key: TypedDigest,
    /// Immutable committed result manifest ID.
    pub canonical_result_manifest_id: ObjectId,
    /// Current mutable serving state record.
    pub serving_state: ActionServingStateRecord,
    /// Latest versioned trust evaluation record (under the latest non-revoked policy).
    pub latest_trust_evaluation: ActionTrustEvaluationRecord,
    /// Current verification level achieved by appended evidence.
    pub observed_verification: VerificationLevel,
    /// Isolation profile enforced when the result was produced.
    pub enforced_isolation: IsolationProfile,
    /// Optional privacy/secret scope of the publication.
    pub privacy_scope: Option<String>,
    /// Whether child diagnostics were scrubbed/redacted cleanly.
    pub diagnostics_redacted: bool,
}

/// Per-subscriber serving eligibility decision (bead S021; invariant I42).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubscriberEligibilityDecision {
    /// Committed result meets all of this subscriber's evidence, isolation, and privacy requirements.
    Eligible {
        /// Trust tier satisfied at evaluation time.
        satisfied_tier: TrustEvidenceTier,
        /// Causal sequence of the [`ActionTrustEvaluationRecord`] that authorized serving.
        evaluation_causal_sequence: u64,
    },
    /// Committed result exists and is healthy, but its current evidence tier or verification
    /// level is below this subscriber's minimum: the coordinator can launch/join a verification
    /// attempt, append evidence, emit a new [`ActionTrustEvaluationRecord`], and re-evaluate.
    IneligibleNeedsVerificationAttempt {
        /// Current evaluated tier.
        current_tier: TrustEvidenceTier,
        /// Subscriber's required minimum tier.
        required_tier: TrustEvidenceTier,
        /// Current verification level.
        current_verification: VerificationLevel,
        /// Subscriber's required minimum verification level.
        required_verification: VerificationLevel,
    },
    /// Publication's isolation profile does not satisfy the subscriber's required isolation.
    IneligibleIsolationProfile {
        /// Enforced isolation profile.
        enforced: IsolationProfile,
        /// Subscriber's required isolation profile.
        required: IsolationProfile,
    },
    /// Publication's privacy scope or diagnostic-redaction posture does not satisfy the subscriber.
    IneligiblePrivacyPosture {
        /// Reason code.
        reason: &'static str,
    },
    /// Serving state is currently not eligible (quarantined, expired TTL, or objects unavailable).
    IneligibleServingState {
        /// Current serving disposition.
        disposition: ActionServingDisposition,
    },
}

const fn isolation_rank(profile: IsolationProfile) -> u8 {
    match profile {
        IsolationProfile::VolatileLocal => 0,
        IsolationProfile::WindowsInitial | IsolationProfile::HostSandboxAudit => 1,
        IsolationProfile::DependencyImmutableFastPath => 2,
        IsolationProfile::StrictHermeticVm | IsolationProfile::StrictHermeticLinux => 3,
    }
}

/// Evaluate whether a committed publication is eligible for a specific subscriber's
/// evidence, isolation, and privacy requirements at `(now_unix_micros, now_epoch)` (bead S021; I42).
#[must_use]
pub fn evaluate_subscriber_serving_eligibility(
    posture: &CommittedPublicationPosture,
    requirements: &SubscriberServingRequirements,
    now_unix_micros: i64,
    now_epoch: u64,
) -> SubscriberEligibilityDecision {
    if !posture
        .serving_state
        .may_serve_now(now_unix_micros, now_epoch)
        && !matches!(
            posture.serving_state.disposition,
            ActionServingDisposition::EvidencePending
        )
    {
        return SubscriberEligibilityDecision::IneligibleServingState {
            disposition: posture.serving_state.disposition,
        };
    }
    if posture
        .latest_trust_evaluation
        .canonical_result_manifest_id()
        != &posture.canonical_result_manifest_id
    {
        return SubscriberEligibilityDecision::IneligibleServingState {
            disposition: ActionServingDisposition::Quarantined,
        };
    }
    if isolation_rank(posture.enforced_isolation) < isolation_rank(requirements.required_isolation)
    {
        return SubscriberEligibilityDecision::IneligibleIsolationProfile {
            enforced: posture.enforced_isolation,
            required: requirements.required_isolation,
        };
    }
    if requirements.require_redacted_diagnostics && !posture.diagnostics_redacted {
        return SubscriberEligibilityDecision::IneligiblePrivacyPosture {
            reason: "unredacted-diagnostics-refused-by-subscriber",
        };
    }
    if requirements.required_privacy_scope != posture.privacy_scope {
        return SubscriberEligibilityDecision::IneligiblePrivacyPosture {
            reason: "privacy-scope-mismatch",
        };
    }

    let current_tier = posture.latest_trust_evaluation.evaluated_tier();
    if current_tier < requirements.minimum_tier
        || !verification_meets(
            posture.observed_verification,
            requirements.minimum_verification,
        )
        || matches!(
            posture.serving_state.disposition,
            ActionServingDisposition::EvidencePending
        )
    {
        return SubscriberEligibilityDecision::IneligibleNeedsVerificationAttempt {
            current_tier,
            required_tier: requirements.minimum_tier,
            current_verification: posture.observed_verification,
            required_verification: requirements.minimum_verification,
        };
    }

    SubscriberEligibilityDecision::Eligible {
        satisfied_tier: current_tier,
        evaluation_causal_sequence: posture.latest_trust_evaluation.evaluated_causal_sequence(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::result_identity::DigestAlgorithm;

    fn digest(tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "rabs.coordinator-authority.v1",
            bytes: [tag; 32],
        }
    }

    fn object(tag: u8) -> ObjectId {
        ObjectId(TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: CI_RESULT_MANIFEST_DOMAIN,
            bytes: [tag; 32],
        })
    }

    fn action_key(tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "rabs.action-key.sha256.v1",
            bytes: [tag; 32],
        }
    }

    fn evidence_set(tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "rabs.evidence-set.sha256.v1",
            bytes: [tag; 32],
        }
    }

    fn signer_fingerprint(tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "rabs.identity-fingerprint.sha256.v1",
            bytes: [tag; 32],
        }
    }

    fn policy_id(tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: CI_POLICY_ID_DOMAIN,
            bytes: [tag; 32],
        }
    }

    fn policy_content(tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: CI_POLICY_CONTENT_DOMAIN,
            bytes: [tag; 32],
        }
    }

    fn authorization(
        lane_id: &str,
        signer_fingerprint: &TypedDigest,
        action_key_scope: CiActionKeyScope,
        role: CiLaneRole,
        minimum_verification: VerificationLevel,
    ) -> CiLaneAuthorization {
        CiLaneAuthorization {
            lane_id: lane_id.to_owned(),
            signer_fingerprint: signer_fingerprint.clone(),
            signer_generation: 3,
            signature_algorithm: CiSignatureAlgorithm::Ed25519V1,
            action_key_scope,
            role,
            minimum_verification,
            revoked: false,
        }
    }

    fn ci_policy(authorizations: Vec<CiLaneAuthorization>) -> CiCanonicalWriterPolicy {
        CiCanonicalWriterPolicy {
            schema_version: CI_CANONICAL_WRITER_POLICY_SCHEMA_VERSION,
            policy_id: policy_id(1),
            policy_content_digest: policy_content(7),
            version: 7,
            revoked: false,
            authorizations,
        }
    }

    fn signed_claim(
        lane_id: &str,
        signer_fingerprint: &TypedDigest,
        action_key: TypedDigest,
        role: CiLaneRole,
        verification: VerificationLevel,
        manifest_tag: u8,
        evidence_tag: u8,
    ) -> (CiCanonicalWriterClaim, Vec<u8>) {
        let claim = CiCanonicalWriterClaim {
            schema_version: CI_POLICY_CLAIM_SCHEMA_VERSION,
            policy_version: 7,
            policy_id: policy_id(1),
            policy_content_digest: policy_content(7),
            lane_id: lane_id.to_owned(),
            signer_fingerprint: signer_fingerprint.clone(),
            signer_generation: 3,
            action_key,
            canonical_result_manifest_id: object(manifest_tag),
            evidence_set_digest: evidence_set(evidence_tag),
            role,
            verification,
            evaluated_causal_sequence: 91,
            authenticator: CiClaimAuthenticator {
                algorithm: CiSignatureAlgorithm::Ed25519V1,
                bytes: vec![0xa5; 64],
            },
        };
        let canonical_bytes = claim.canonical_bytes();
        (claim, canonical_bytes)
    }

    fn context_for(
        policy: &CiCanonicalWriterPolicy,
        claim: &CiCanonicalWriterClaim,
    ) -> CiEvaluationContext {
        coordinator_context(
            policy,
            claim.action_key.clone(),
            claim.canonical_result_manifest_id.clone(),
            claim.evidence_set_digest.clone(),
            claim.verification,
        )
    }

    fn coordinator_context(
        policy: &CiCanonicalWriterPolicy,
        action_key: TypedDigest,
        canonical_result_manifest_id: ObjectId,
        evidence_set_digest: TypedDigest,
        verification: VerificationLevel,
    ) -> CiEvaluationContext {
        CiEvaluationContext {
            expected_policy_id: policy.policy_id.clone(),
            expected_policy_version: policy.version,
            expected_policy_content_digest: policy.policy_content_digest.clone(),
            expected_action_key: action_key,
            expected_canonical_result_manifest_id: canonical_result_manifest_id,
            expected_evidence_set_digest: evidence_set_digest,
            independently_observed_verification: verification,
            coordinator_causal_sequence: 91,
            publication_causal_sequence: 89,
            trust_ledger_high_water: 90,
        }
    }

    fn accept_policy_content(_: &TypedDigest, _: &[u8]) -> bool {
        true
    }

    fn verifier_for(
        expected_bytes: Vec<u8>,
        expected_signer: TypedDigest,
    ) -> impl FnOnce(CiSignatureAlgorithm, &TypedDigest, u64, &[u8], &[u8]) -> bool {
        let expected_signature = vec![0xa5; 64];
        move |algorithm, fingerprint, generation, bytes, signature| {
            algorithm == CiSignatureAlgorithm::Ed25519V1
                && fingerprint == &expected_signer
                && generation == 3
                && bytes == expected_bytes
                && signature == expected_signature
        }
    }

    fn validity(evaluated_at: i64, max_age: Option<u64>, uncertainty: u64) -> ServingValidity {
        ServingValidity {
            evaluated_at_unix_micros: evaluated_at,
            maximum_age_micros: max_age,
            clock_uncertainty_micros: uncertainty,
            coordinator_clock_epoch: 1,
        }
    }

    #[test]
    fn ttl_expires_conservatively_under_uncertainty() {
        let v = validity(1_000, Some(500), 100);
        // Well inside: age 300 + uncertainty 100 <= 500.
        assert!(v.still_valid(1_300, 1));
        // Age 450 + uncertainty 100 crosses the bound: DENY, even though the
        // naive age alone would still pass.
        assert!(!v.still_valid(1_450, 1));
        // No expiry configured: valid at any forward time.
        let forever = validity(1_000, None, 100);
        assert!(forever.still_valid(i64::MAX, 1));
    }

    #[test]
    fn clock_rollback_and_epoch_discontinuity_deny() {
        let v = validity(1_000, Some(1_000_000), 0);
        // Wall clock ran backward: deny.
        assert!(!v.still_valid(999, 1));
        // Clock epoch changed (restart/discontinuity): deny regardless.
        assert!(!v.still_valid(2_000, 2));
    }

    #[test]
    fn stale_revision_replays_are_refused() {
        let current = ActionServingStateRecord {
            publication_record_id: object(1),
            disposition: ActionServingDisposition::Eligible,
            blocking_quarantine_ids: vec![],
            state_revision: 5,
            coordinator_authority_digest: digest(7),
            validity: validity(0, None, 0),
        };
        let newer = ActionServingStateRecord {
            state_revision: 6,
            disposition: ActionServingDisposition::Quarantined,
            ..current.clone()
        };
        let replay = ActionServingStateRecord {
            state_revision: 5,
            ..current.clone()
        };
        let other_pub = ActionServingStateRecord {
            publication_record_id: object(2),
            state_revision: 9,
            ..current.clone()
        };
        assert!(current.accepts_update(&newer));
        assert!(!current.accepts_update(&replay), "equal revision = replay");
        assert!(!current.accepts_update(&other_pub), "wrong publication");
    }

    #[test]
    fn quarantine_ids_block_serving_even_when_eligible() {
        let mut r = ActionServingStateRecord {
            publication_record_id: object(1),
            disposition: ActionServingDisposition::Eligible,
            blocking_quarantine_ids: vec![42],
            state_revision: 1,
            coordinator_authority_digest: digest(7),
            validity: validity(0, None, 0),
        };
        assert!(!r.may_serve_now(10, 1), "blocking incident denies serving");
        r.blocking_quarantine_ids.clear();
        assert!(r.may_serve_now(10, 1));
        r.disposition = ActionServingDisposition::ExpiredNeedsRevalidation;
        assert!(!r.may_serve_now(10, 1));
    }

    #[test]
    fn evidence_sets_are_order_insensitive_and_deduplicated() {
        let a = evidence_set_digest_input(vec![[3; 32], [1; 32], [2; 32]]);
        let b = evidence_set_digest_input(vec![[2; 32], [3; 32], [1; 32], [2; 32]]);
        assert_eq!(a, b, "insertion order and duplicates never rename a set");
        assert_eq!(a.len(), 3);
    }

    #[test]
    fn trust_tiers_order_and_never_touch_publication_types() {
        assert!(TrustEvidenceTier::ShadowMatched < TrustEvidenceTier::CiPolicyApproved);
        // Type-level separation (I50): a trust evaluation references the
        // canonical result by ID; there is no field through which it could
        // mutate a CanonicalActionResultManifest or ActionPublicationRecord.
        let eval = ActionTrustEvaluationRecord::from_observed_evidence(
            object(1),
            digest(9),
            TrustEvidenceTier::ReproducibleCrossWorker,
            3,
        )
        .unwrap();
        assert_eq!(
            eval.evaluated_tier(),
            TrustEvidenceTier::ReproducibleCrossWorker
        );
    }

    #[test]
    fn s011_authorized_producer_and_verifier_earn_ci_policy_approved() {
        let signer = signer_fingerprint(4);
        let producer_key = action_key(10);
        let verifier_key = action_key(11);
        let policy = ci_policy(vec![
            authorization(
                "release-producer",
                &signer,
                CiActionKeyScope::Exact(producer_key.clone()),
                CiLaneRole::Producer,
                VerificationLevel::CoordinatorDigestRecompute,
            ),
            authorization(
                "release-verifier",
                &signer,
                CiActionKeyScope::AnyAction {
                    algorithm: DigestAlgorithm::Sha256V1,
                    domain: "rabs.action-key.sha256.v1".to_owned(),
                },
                CiLaneRole::Verifier,
                VerificationLevel::CrossWorkerConsensus {
                    distinct_workers: 2,
                },
            ),
        ]);

        let (producer_claim, producer_bytes) = signed_claim(
            "release-producer",
            &signer,
            producer_key.clone(),
            CiLaneRole::Producer,
            VerificationLevel::CoordinatorDigestRecompute,
            20,
            30,
        );
        let producer_context = coordinator_context(
            &policy,
            producer_key.clone(),
            object(20),
            evidence_set(30),
            VerificationLevel::CoordinatorDigestRecompute,
        );
        let producer = evaluate_ci_canonical_writer_claim(
            std::slice::from_ref(&policy),
            &producer_claim,
            &producer_context,
            accept_policy_content,
            verifier_for(producer_bytes, signer.clone()),
        )
        .unwrap();
        assert_eq!(producer.policy_version(), 7);
        assert_eq!(producer.lane_id(), "release-producer");
        assert_eq!(producer.role(), CiLaneRole::Producer);
        assert_eq!(producer.action_key(), &producer_key);
        assert_eq!(producer.policy_id(), &policy.policy_id);
        assert_eq!(
            producer.policy_content_digest(),
            &policy.policy_content_digest
        );
        assert_eq!(
            producer.verification(),
            VerificationLevel::CoordinatorDigestRecompute
        );
        assert_eq!(
            producer.evaluation().evaluated_tier(),
            TrustEvidenceTier::CiPolicyApproved
        );

        let (verifier_claim, verifier_bytes) = signed_claim(
            "release-verifier",
            &signer,
            verifier_key.clone(),
            CiLaneRole::Verifier,
            VerificationLevel::StockToolchainComparison,
            21,
            31,
        );
        let verifier_context = coordinator_context(
            &policy,
            verifier_key.clone(),
            object(21),
            evidence_set(31),
            VerificationLevel::StockToolchainComparison,
        );
        let verifier = evaluate_ci_canonical_writer_claim(
            std::slice::from_ref(&policy),
            &verifier_claim,
            &verifier_context,
            accept_policy_content,
            verifier_for(verifier_bytes, signer.clone()),
        )
        .unwrap();
        assert_eq!(verifier.role(), CiLaneRole::Verifier);
        assert_eq!(verifier.action_key(), &verifier_key);
        assert_eq!(verifier.signer_fingerprint(), &signer);
        assert_eq!(verifier.signer_generation(), 3);
        assert_eq!(
            verifier.evaluation().evaluated_tier(),
            TrustEvidenceTier::CiPolicyApproved
        );
    }

    #[test]
    fn s011_unauthorized_lane_signer_and_role_cannot_earn_tier() {
        use std::cell::Cell;

        let signer = signer_fingerprint(4);
        let action = action_key(10);
        let policy = ci_policy(vec![authorization(
            "release-producer",
            &signer,
            CiActionKeyScope::Exact(action.clone()),
            CiLaneRole::Producer,
            VerificationLevel::CoordinatorDigestRecompute,
        )]);

        let (rogue_lane, _) = signed_claim(
            "rogue-lane",
            &signer,
            action.clone(),
            CiLaneRole::Producer,
            VerificationLevel::CoordinatorDigestRecompute,
            20,
            30,
        );
        let rogue_context = context_for(&policy, &rogue_lane);
        let verifier_called = Cell::new(false);
        assert_eq!(
            evaluate_ci_canonical_writer_claim(
                std::slice::from_ref(&policy),
                &rogue_lane,
                &rogue_context,
                accept_policy_content,
                |_, _, _, _, _| {
                    verifier_called.set(true);
                    true
                },
            ),
            Err(CiPolicyRefusal::UnauthorizedLane)
        );
        assert!(!verifier_called.get());

        let (rogue_signer, _) = signed_claim(
            "release-producer",
            &signer_fingerprint(9),
            action.clone(),
            CiLaneRole::Producer,
            VerificationLevel::CoordinatorDigestRecompute,
            20,
            30,
        );
        assert_eq!(
            evaluate_ci_canonical_writer_claim(
                std::slice::from_ref(&policy),
                &rogue_signer,
                &context_for(&policy, &rogue_signer),
                accept_policy_content,
                |_, _, _, _, _| true,
            ),
            Err(CiPolicyRefusal::UnauthorizedSigner)
        );

        let (wrong_role, _) = signed_claim(
            "release-producer",
            &signer,
            action,
            CiLaneRole::Verifier,
            VerificationLevel::CoordinatorDigestRecompute,
            20,
            30,
        );
        assert_eq!(
            evaluate_ci_canonical_writer_claim(
                std::slice::from_ref(&policy),
                &wrong_role,
                &context_for(&policy, &wrong_role),
                accept_policy_content,
                |_, _, _, _, _| true,
            ),
            Err(CiPolicyRefusal::RoleNotAuthorized)
        );

        let mut stale_generation = wrong_role.clone();
        stale_generation.role = CiLaneRole::Producer;
        stale_generation.signer_generation = 2;
        assert_eq!(
            evaluate_ci_canonical_writer_claim(
                std::slice::from_ref(&policy),
                &stale_generation,
                &context_for(&policy, &stale_generation),
                accept_policy_content,
                |_, _, _, _, _| true,
            ),
            Err(CiPolicyRefusal::UnauthorizedSigner)
        );

        let mut substituted_algorithm = stale_generation;
        substituted_algorithm.signer_generation = 3;
        substituted_algorithm.authenticator.algorithm = CiSignatureAlgorithm::EcdsaP256Sha256V1;
        assert_eq!(
            evaluate_ci_canonical_writer_claim(
                std::slice::from_ref(&policy),
                &substituted_algorithm,
                &context_for(&policy, &substituted_algorithm),
                accept_policy_content,
                |_, _, _, _, _| true,
            ),
            Err(CiPolicyRefusal::SignatureAlgorithmNotAuthorized)
        );

        let (mut authorized_claim, _) = signed_claim(
            "release-producer",
            &signer,
            action_key(10),
            CiLaneRole::Producer,
            VerificationLevel::CoordinatorDigestRecompute,
            20,
            30,
        );
        let mut revoked_policy = policy;
        revoked_policy.authorizations[0].revoked = true;
        revoked_policy.policy_content_digest = policy_content(8);
        authorized_claim.policy_content_digest = policy_content(8);
        assert_eq!(
            evaluate_ci_canonical_writer_claim(
                std::slice::from_ref(&revoked_policy),
                &authorized_claim,
                &context_for(&revoked_policy, &authorized_claim),
                accept_policy_content,
                |_, _, _, _, _| true,
            ),
            Err(CiPolicyRefusal::AuthorizationRevoked)
        );
    }

    #[test]
    fn s011_out_of_scope_and_insufficient_verification_are_refused() {
        let signer = signer_fingerprint(4);
        let allowed_action = action_key(10);
        let policy = ci_policy(vec![authorization(
            "release-verifier",
            &signer,
            CiActionKeyScope::Exact(allowed_action.clone()),
            CiLaneRole::Verifier,
            VerificationLevel::CrossWorkerConsensus {
                distinct_workers: 4,
            },
        )]);

        let (out_of_scope, _) = signed_claim(
            "release-verifier",
            &signer,
            action_key(11),
            CiLaneRole::Verifier,
            VerificationLevel::StockToolchainComparison,
            20,
            30,
        );
        assert_eq!(
            evaluate_ci_canonical_writer_claim(
                std::slice::from_ref(&policy),
                &out_of_scope,
                &context_for(&policy, &out_of_scope),
                accept_policy_content,
                |_, _, _, _, _| true,
            ),
            Err(CiPolicyRefusal::ActionKeyOutOfScope)
        );

        let presented = VerificationLevel::CrossWorkerConsensus {
            distinct_workers: 2,
        };
        let required = VerificationLevel::CrossWorkerConsensus {
            distinct_workers: 4,
        };
        let (insufficient, _) = signed_claim(
            "release-verifier",
            &signer,
            allowed_action.clone(),
            CiLaneRole::Verifier,
            presented,
            20,
            30,
        );
        assert_eq!(
            evaluate_ci_canonical_writer_claim(
                std::slice::from_ref(&policy),
                &insufficient,
                &context_for(&policy, &insufficient),
                accept_policy_content,
                |_, _, _, _, _| true,
            ),
            Err(CiPolicyRefusal::InsufficientVerification {
                required,
                presented,
            })
        );

        let (fake_consensus, _) = signed_claim(
            "release-verifier",
            &signer,
            allowed_action,
            CiLaneRole::Verifier,
            VerificationLevel::CrossWorkerConsensus {
                distinct_workers: 1,
            },
            20,
            30,
        );
        let mut valid_context = context_for(&policy, &fake_consensus);
        valid_context.independently_observed_verification =
            VerificationLevel::CoordinatorDigestRecompute;
        assert_eq!(
            evaluate_ci_canonical_writer_claim(
                std::slice::from_ref(&policy),
                &fake_consensus,
                &valid_context,
                accept_policy_content,
                |_, _, _, _, _| true,
            ),
            Err(CiPolicyRefusal::InvalidVerificationEvidence)
        );
    }

    #[test]
    fn s011_current_policy_selection_rejects_replay_and_revoked_newest() {
        let signer = signer_fingerprint(4);
        let action = action_key(10);
        let authorization = authorization(
            "release-producer",
            &signer,
            CiActionKeyScope::Exact(action.clone()),
            CiLaneRole::Producer,
            VerificationLevel::CoordinatorDigestRecompute,
        );
        let mut old_policy = ci_policy(vec![authorization.clone()]);
        old_policy.version = 6;
        old_policy.policy_content_digest = policy_content(6);
        let mut current_policy = ci_policy(vec![authorization]);
        current_policy.version = 8;
        current_policy.policy_content_digest = policy_content(8);

        let (stale_claim, _) = signed_claim(
            "release-producer",
            &signer,
            action.clone(),
            CiLaneRole::Producer,
            VerificationLevel::CoordinatorDigestRecompute,
            20,
            30,
        );
        assert_eq!(
            evaluate_ci_canonical_writer_claim(
                &[old_policy.clone(), current_policy.clone()],
                &stale_claim,
                &context_for(&current_policy, &stale_claim),
                accept_policy_content,
                |_, _, _, _, _| true,
            ),
            Err(CiPolicyRefusal::PolicyVersionMismatch)
        );

        let mut current_claim = stale_claim.clone();
        current_claim.policy_version = 8;
        current_claim.policy_content_digest = policy_content(8);
        let current_bytes = current_claim.canonical_bytes();
        let approval = evaluate_ci_canonical_writer_claim(
            &[old_policy.clone(), current_policy.clone()],
            &current_claim,
            &context_for(&current_policy, &current_claim),
            accept_policy_content,
            verifier_for(current_bytes, signer.clone()),
        )
        .unwrap();
        assert_eq!(approval.policy_version(), 8);

        assert_eq!(
            evaluate_ci_canonical_writer_claim(
                std::slice::from_ref(&old_policy),
                &stale_claim,
                &context_for(&current_policy, &stale_claim),
                accept_policy_content,
                |_, _, _, _, _| true,
            ),
            Err(CiPolicyRefusal::PolicyVersionMismatch),
            "the durable policy high-water rejects a truncated history"
        );

        current_policy.revoked = true;
        assert_eq!(
            evaluate_ci_canonical_writer_claim(
                &[old_policy.clone(), current_policy.clone()],
                &current_claim,
                &context_for(&current_policy, &current_claim),
                accept_policy_content,
                |_, _, _, _, _| true,
            ),
            Err(CiPolicyRefusal::PolicyRevoked)
        );

        current_policy.revoked = false;
        let duplicate_context = context_for(&current_policy, &current_claim);
        assert_eq!(
            evaluate_ci_canonical_writer_claim(
                &[old_policy.clone(), old_policy, current_policy],
                &current_claim,
                &duplicate_context,
                accept_policy_content,
                |_, _, _, _, _| true,
            ),
            Err(CiPolicyRefusal::AmbiguousPolicyHistory)
        );
    }

    #[test]
    fn s011_context_mismatches_and_nonmonotonic_sequences_are_refused() {
        let signer = signer_fingerprint(4);
        let action = action_key(10);
        let policy = ci_policy(vec![authorization(
            "release-producer",
            &signer,
            CiActionKeyScope::Exact(action.clone()),
            CiLaneRole::Producer,
            VerificationLevel::CoordinatorDigestRecompute,
        )]);
        let (claim, signed_bytes) = signed_claim(
            "release-producer",
            &signer,
            action.clone(),
            CiLaneRole::Producer,
            VerificationLevel::CoordinatorDigestRecompute,
            20,
            30,
        );
        let context = context_for(&policy, &claim);

        let mut tampered = claim.clone();
        tampered.action_key = action_key(99);
        assert_eq!(
            evaluate_ci_canonical_writer_claim(
                std::slice::from_ref(&policy),
                &tampered,
                &context,
                accept_policy_content,
                |_, _, _, _, _| true,
            ),
            Err(CiPolicyRefusal::ActionKeyMismatch)
        );

        let mut mislabeled = claim.clone();
        mislabeled.action_key.domain = CI_EVIDENCE_SET_DOMAIN;
        assert_eq!(
            evaluate_ci_canonical_writer_claim(
                std::slice::from_ref(&policy),
                &mislabeled,
                &context,
                accept_policy_content,
                |_, _, _, _, _| true,
            ),
            Err(CiPolicyRefusal::MalformedClaim)
        );

        tampered = claim.clone();
        tampered.canonical_result_manifest_id = object(99);
        assert_eq!(
            evaluate_ci_canonical_writer_claim(
                std::slice::from_ref(&policy),
                &tampered,
                &context,
                accept_policy_content,
                |_, _, _, _, _| true,
            ),
            Err(CiPolicyRefusal::CanonicalManifestMismatch)
        );

        tampered = claim.clone();
        tampered.evidence_set_digest = evidence_set(99);
        assert_eq!(
            evaluate_ci_canonical_writer_claim(
                std::slice::from_ref(&policy),
                &tampered,
                &context,
                accept_policy_content,
                |_, _, _, _, _| true,
            ),
            Err(CiPolicyRefusal::EvidenceSetMismatch)
        );

        tampered = claim.clone();
        tampered.verification = VerificationLevel::IndependentReplay;
        assert_eq!(
            evaluate_ci_canonical_writer_claim(
                std::slice::from_ref(&policy),
                &tampered,
                &context,
                accept_policy_content,
                |_, _, _, _, _| true,
            ),
            Err(CiPolicyRefusal::VerificationMismatch)
        );

        tampered = claim.clone();
        tampered.evaluated_causal_sequence = u64::MAX;
        assert_eq!(
            evaluate_ci_canonical_writer_claim(
                std::slice::from_ref(&policy),
                &tampered,
                &context,
                accept_policy_content,
                |_, _, _, _, _| true,
            ),
            Err(CiPolicyRefusal::CausalSequenceMismatch)
        );

        let mut replay_context = context;
        replay_context.trust_ledger_high_water = 91;
        assert_eq!(
            evaluate_ci_canonical_writer_claim(
                std::slice::from_ref(&policy),
                &claim,
                &replay_context,
                accept_policy_content,
                |_, _, _, _, _| true,
            ),
            Err(CiPolicyRefusal::NonMonotonicEvaluationSequence)
        );

        let mut prepublication_context = context_for(&policy, &claim);
        prepublication_context.publication_causal_sequence = 91;
        assert_eq!(
            evaluate_ci_canonical_writer_claim(
                std::slice::from_ref(&policy),
                &claim,
                &prepublication_context,
                accept_policy_content,
                |_, _, _, _, _| true,
            ),
            Err(CiPolicyRefusal::NonMonotonicEvaluationSequence)
        );

        let mut wrong_policy = claim;
        wrong_policy.policy_content_digest = policy_content(99);
        assert_ne!(wrong_policy.canonical_bytes(), signed_bytes);
        assert_eq!(
            evaluate_ci_canonical_writer_claim(
                std::slice::from_ref(&policy),
                &wrong_policy,
                &context_for(&policy, &wrong_policy),
                accept_policy_content,
                |_, _, _, _, _| true,
            ),
            Err(CiPolicyRefusal::PolicyContentMismatch)
        );
    }

    #[test]
    fn s011_ambiguous_policy_grants_are_rejected_order_independently() {
        let signer = signer_fingerprint(4);
        let action = action_key(10);
        let exact = authorization(
            "release-producer",
            &signer,
            CiActionKeyScope::Exact(action.clone()),
            CiLaneRole::Producer,
            VerificationLevel::CoordinatorDigestRecompute,
        );
        let broad = authorization(
            "release-producer",
            &signer,
            CiActionKeyScope::AnyAction {
                algorithm: DigestAlgorithm::Sha256V1,
                domain: action.domain.to_owned(),
            },
            CiLaneRole::Producer,
            VerificationLevel::IndependentReplay,
        );

        assert_eq!(
            validate_ci_canonical_writer_policy(&ci_policy(vec![exact.clone(), broad.clone()])),
            Err(CiPolicyRefusal::AmbiguousAuthorization)
        );
        assert_eq!(
            validate_ci_canonical_writer_policy(&ci_policy(vec![broad, exact.clone()])),
            Err(CiPolicyRefusal::AmbiguousAuthorization)
        );

        let other = authorization(
            "release-producer",
            &signer,
            CiActionKeyScope::Exact(action_key(11)),
            CiLaneRole::Producer,
            VerificationLevel::CoordinatorDigestRecompute,
        );
        let policy_a = ci_policy(vec![exact.clone(), other.clone()]);
        let policy_b = ci_policy(vec![other, exact]);
        assert_eq!(policy_a.canonical_bytes(), policy_b.canonical_bytes());
        assert_eq!(validate_ci_canonical_writer_policy(&policy_a), Ok(()));

        let mut alternate_algorithm = policy_a.authorizations[0].clone();
        alternate_algorithm.signature_algorithm = CiSignatureAlgorithm::EcdsaP256Sha256V1;
        assert_eq!(
            validate_ci_canonical_writer_policy(&ci_policy(vec![
                policy_a.authorizations[0].clone(),
                alternate_algorithm,
            ])),
            Ok(()),
            "a closed algorithm identifier selects the grant without list ordering"
        );

        let mut malformed_lane = policy_a.authorizations[0].clone();
        malformed_lane.lane_id = "release\nproducer".to_owned();
        assert_eq!(
            validate_ci_canonical_writer_policy(&ci_policy(vec![malformed_lane])),
            Err(CiPolicyRefusal::MalformedAuthorization)
        );

        let mut wrong_domain = policy_a.authorizations[0].clone();
        if let CiActionKeyScope::Exact(action) = &mut wrong_domain.action_key_scope {
            action.domain = CI_EVIDENCE_SET_DOMAIN;
        }
        assert_eq!(
            validate_ci_canonical_writer_policy(&ci_policy(vec![wrong_domain])),
            Err(CiPolicyRefusal::MalformedAuthorization)
        );
    }

    #[test]
    fn s011_signature_is_verified_once_and_envelope_is_bounded() {
        use std::cell::Cell;

        let signer = signer_fingerprint(4);
        let action = action_key(10);
        let mut authorization = authorization(
            "release-producer",
            &signer,
            CiActionKeyScope::Exact(action.clone()),
            CiLaneRole::Producer,
            VerificationLevel::CoordinatorDigestRecompute,
        );
        let policy = ci_policy(vec![authorization.clone()]);
        let (claim, signed_bytes) = signed_claim(
            "release-producer",
            &signer,
            action,
            CiLaneRole::Producer,
            VerificationLevel::CoordinatorDigestRecompute,
            20,
            30,
        );

        assert_eq!(
            evaluate_ci_canonical_writer_claim(
                std::slice::from_ref(&policy),
                &claim,
                &context_for(&policy, &claim),
                accept_policy_content,
                |_, _, _, _, _| false,
            ),
            Err(CiPolicyRefusal::InvalidSignature)
        );

        let admitted_policy_bytes = policy.canonical_bytes();
        let admitted_policy_digest = policy.policy_content_digest.clone();
        let mut altered_policy = policy.clone();
        altered_policy.authorizations[0].minimum_verification =
            VerificationLevel::IndependentReplay;
        assert_eq!(
            evaluate_ci_canonical_writer_claim(
                std::slice::from_ref(&altered_policy),
                &claim,
                &context_for(&policy, &claim),
                move |digest, bytes| {
                    digest == &admitted_policy_digest && bytes == admitted_policy_bytes
                },
                |_, _, _, _, _| true,
            ),
            Err(CiPolicyRefusal::InvalidPolicyContentDigest),
            "mutated policy bytes cannot retain a stale content digest"
        );

        let calls = Cell::new(0);
        let approval = evaluate_ci_canonical_writer_claim(
            std::slice::from_ref(&policy),
            &claim,
            &context_for(&policy, &claim),
            accept_policy_content,
            |algorithm, fingerprint, generation, bytes, signature| {
                calls.set(calls.get() + 1);
                algorithm == CiSignatureAlgorithm::Ed25519V1
                    && fingerprint == &signer
                    && generation == 3
                    && bytes == signed_bytes
                    && signature == [0xa5; 64]
            },
        )
        .unwrap();
        assert_eq!(calls.get(), 1);
        assert_eq!(approval.verification(), claim.verification);

        let mut changed_signature = claim.clone();
        changed_signature.authenticator.bytes = vec![0x5a; 64];
        assert_eq!(changed_signature.canonical_bytes(), claim.canonical_bytes());

        changed_signature.authenticator.bytes.clear();
        assert_eq!(
            evaluate_ci_canonical_writer_claim(
                std::slice::from_ref(&policy),
                &changed_signature,
                &context_for(&policy, &changed_signature),
                accept_policy_content,
                |_, _, _, _, _| true,
            ),
            Err(CiPolicyRefusal::MalformedClaim)
        );

        changed_signature.authenticator.bytes = vec![0; MAX_AUTHENTICATOR_BYTES + 1];
        assert_eq!(
            evaluate_ci_canonical_writer_claim(
                std::slice::from_ref(&policy),
                &changed_signature,
                &context_for(&policy, &changed_signature),
                accept_policy_content,
                |_, _, _, _, _| true,
            ),
            Err(CiPolicyRefusal::MalformedClaim)
        );

        authorization.minimum_verification = VerificationLevel::CrossWorkerConsensus {
            distinct_workers: 1,
        };
        assert_eq!(
            validate_ci_canonical_writer_policy(&ci_policy(vec![authorization])),
            Err(CiPolicyRefusal::InvalidVerificationRequirement)
        );
    }

    #[test]
    fn s011_policy_approval_is_opaque_and_does_not_change_identity() {
        assert_eq!(
            ActionTrustEvaluationRecord::from_observed_evidence(
                object(1),
                evidence_set(2),
                TrustEvidenceTier::CiPolicyApproved,
                3,
            ),
            Err(TrustEvaluationConstructionRefusal::PolicyApprovalRequired)
        );

        let signer = signer_fingerprint(4);
        let action = action_key(10);
        let policy = ci_policy(vec![authorization(
            "release-producer",
            &signer,
            CiActionKeyScope::Exact(action.clone()),
            CiLaneRole::Producer,
            VerificationLevel::CoordinatorDigestRecompute,
        )]);
        let (claim, signed_bytes) = signed_claim(
            "release-producer",
            &signer,
            action.clone(),
            CiLaneRole::Producer,
            VerificationLevel::CoordinatorDigestRecompute,
            20,
            30,
        );
        let original_manifest = claim.canonical_result_manifest_id.clone();
        let original_evidence = claim.evidence_set_digest.clone();
        let approval = evaluate_ci_canonical_writer_claim(
            std::slice::from_ref(&policy),
            &claim,
            &context_for(&policy, &claim),
            accept_policy_content,
            verifier_for(signed_bytes, signer),
        )
        .unwrap();
        assert_eq!(approval.action_key(), &action);
        assert_eq!(
            approval.evaluation().canonical_result_manifest_id(),
            &original_manifest
        );
        assert_eq!(
            approval.evaluation().evidence_set_digest(),
            &original_evidence
        );
        assert_eq!(approval.evaluation().evaluated_causal_sequence(), 91);
        assert_eq!(
            approval.verified_claim().authenticator.algorithm,
            CiSignatureAlgorithm::Ed25519V1
        );
        assert_eq!(
            approval.verified_claim().authenticator.bytes,
            vec![0xa5; 64]
        );
    }

    #[test]
    fn s012_project_release_eligibility_policy_requires_prerequisite_tier_and_explicit_non_claim() {
        const TRUST_DOC: &str = include_str!("../../docs/rabs-trust-model-v1.md");
        assert!(
            TRUST_DOC.contains(NO_CLAIM_CACHE_EQUIVALENCE_PROVES_APPLICATION_CORRECTNESS),
            "docs/rabs-trust-model-v1.md must document NO_CLAIM_CACHE_EQUIVALENCE_PROVES_APPLICATION_CORRECTNESS"
        );

        let manifest = object(41);
        let ev_set = evidence_set(42);
        let action = action_key(43);

        // Ordinary observed-evidence constructor cannot mint ProjectReleaseEligible directly.
        assert_eq!(
            ActionTrustEvaluationRecord::from_observed_evidence(
                manifest.clone(),
                ev_set.clone(),
                TrustEvidenceTier::ProjectReleaseEligible,
                10,
            ),
            Err(TrustEvaluationConstructionRefusal::PolicyApprovalRequired)
        );

        let policy = ProjectReleaseEligibilityPolicy {
            schema_version: PROJECT_RELEASE_POLICY_SCHEMA_VERSION,
            project_id: "rch-release-lane".into(),
            policy_version: 2,
            revoked: false,
            minimum_prerequisite_tier: TrustEvidenceTier::ReproducibleCrossWorker,
            minimum_verification: VerificationLevel::CrossWorkerConsensus {
                distinct_workers: 2,
            },
        };

        let cross_worker_prereq = ActionTrustEvaluationRecord::from_observed_evidence(
            manifest.clone(),
            ev_set.clone(),
            TrustEvidenceTier::ReproducibleCrossWorker,
            20,
        )
        .unwrap();

        let valid_input = ProjectReleaseEligibilityInput {
            project_id: "rch-release-lane".into(),
            action_key: action.clone(),
            canonical_result_manifest_id: manifest.clone(),
            evidence_set_digest: ev_set.clone(),
            prerequisite_evaluation: cross_worker_prereq,
            observed_verification: VerificationLevel::CrossWorkerConsensus {
                distinct_workers: 2,
            },
            coordinator_causal_sequence: 21,
            receipt_non_claims: vec![NO_CLAIM_CACHE_EQUIVALENCE_PROVES_APPLICATION_CORRECTNESS],
        };

        let approval = evaluate_project_release_eligibility(&policy, &valid_input).unwrap();
        assert_eq!(
            approval.evaluation.evaluated_tier(),
            TrustEvidenceTier::ProjectReleaseEligible
        );
        assert_eq!(approval.evaluation.evaluated_causal_sequence(), 21);
        assert!(
            approval
                .non_claims
                .contains(&NO_CLAIM_CACHE_EQUIVALENCE_PROVES_APPLICATION_CORRECTNESS)
        );

        // Omitting the application-correctness non-claim is refused.
        let mut missing_non_claim = valid_input.clone();
        missing_non_claim.receipt_non_claims.clear();
        assert_eq!(
            evaluate_project_release_eligibility(&policy, &missing_non_claim),
            Err(ProjectReleaseRefusal::MissingApplicationCorrectnessNonClaim)
        );

        // Prerequisite tier below policy floor is refused.
        let mut weak_prereq = valid_input;
        weak_prereq.prerequisite_evaluation = ActionTrustEvaluationRecord::from_observed_evidence(
            manifest,
            ev_set,
            TrustEvidenceTier::ShadowMatched,
            20,
        )
        .unwrap();
        assert_eq!(
            evaluate_project_release_eligibility(&policy, &weak_prereq),
            Err(ProjectReleaseRefusal::InsufficientPrerequisiteTier {
                required: TrustEvidenceTier::ReproducibleCrossWorker,
                presented: TrustEvidenceTier::ShadowMatched,
            })
        );
    }

    #[test]
    fn s018_compromised_worker_caught_by_cross_worker_or_stock_verification_and_revoked() {
        let honest_digest = digest(0x70);
        let malicious_digest = digest(0x99);

        let wkr_a = WorkerAttemptObservation {
            worker_peer_id: PeerId("wkr-honest-a".into()),
            authenticated: true,
            observable_output_digest: honest_digest.clone(),
        };
        let wkr_b_honest = WorkerAttemptObservation {
            worker_peer_id: PeerId("wkr-honest-b".into()),
            authenticated: true,
            observable_output_digest: honest_digest.clone(),
        };
        let wkr_malicious = WorkerAttemptObservation {
            worker_peer_id: PeerId("wkr-compromised-c".into()),
            authenticated: true,
            observable_output_digest: malicious_digest,
        };

        // 1. A single cryptographically authenticated worker is still a semantic trust principal (R79):
        // its uncorroborated digest is insufficient for release verification.
        assert_eq!(
            evaluate_release_verification_and_compromise(
                ReleaseVerificationPolicy::TwoOrMoreIndependentWorkers {
                    minimum_distinct_workers: 2,
                },
                std::slice::from_ref(&wkr_a),
                None,
                false,
            ),
            CompromisedWorkerVerdict::InsufficientReleaseVerification {
                observed_verification: VerificationLevel::CoordinatorDigestRecompute,
                distinct_authenticated_workers: 1,
            }
        );

        // 2. Two independent honest workers satisfy TwoOrMoreIndependentWorkers.
        assert_eq!(
            evaluate_release_verification_and_compromise(
                ReleaseVerificationPolicy::TwoOrMoreIndependentWorkers {
                    minimum_distinct_workers: 2,
                },
                &[wkr_a.clone(), wkr_b_honest],
                None,
                false,
            ),
            CompromisedWorkerVerdict::VerifiedReleaseEligible {
                verification_level: VerificationLevel::CrossWorkerConsensus {
                    distinct_workers: 2,
                },
                distinct_authenticated_workers: 2,
            }
        );

        // 3. Stock differential execution catches a compromised worker and revokes its publication eligibility.
        assert_eq!(
            evaluate_release_verification_and_compromise(
                ReleaseVerificationPolicy::StockDifferentialExecution,
                &[wkr_a.clone(), wkr_malicious.clone()],
                Some(&honest_digest),
                false,
            ),
            CompromisedWorkerVerdict::MaliciousOrDivergentWorkerDetected {
                revoked_workers: vec![PeerId("wkr-compromised-c".into())],
                publication_eligibility_revoked: true,
                action_quarantined: true,
                reason: "r79-semantic-divergence-detected-publication-eligibility-revoked",
            }
        );

        // 4. Cross-worker divergence without a stock anchor revokes both contending workers until audited.
        assert_eq!(
            evaluate_release_verification_and_compromise(
                ReleaseVerificationPolicy::AnyHighTrustReleaseProof,
                &[wkr_a, wkr_malicious],
                None,
                false,
            ),
            CompromisedWorkerVerdict::MaliciousOrDivergentWorkerDetected {
                revoked_workers: vec![
                    PeerId("wkr-compromised-c".into()),
                    PeerId("wkr-honest-a".into()),
                ],
                publication_eligibility_revoked: true,
                action_quarantined: true,
                reason: "r79-semantic-divergence-detected-publication-eligibility-revoked",
            }
        );
    }

    #[test]
    fn s021_per_subscriber_requirements_and_versioned_trust_reevaluation() {
        let action = action_key(80);
        let manifest = object(81);
        let ev_v1 = evidence_set(82);
        let ev_v2 = evidence_set(83);

        let eval_v1 = ActionTrustEvaluationRecord::from_observed_evidence(
            manifest.clone(),
            ev_v1,
            TrustEvidenceTier::ShadowMatched,
            100,
        )
        .unwrap();

        let mut posture = CommittedPublicationPosture {
            action_key: action,
            canonical_result_manifest_id: manifest.clone(),
            serving_state: ActionServingStateRecord {
                publication_record_id: manifest.clone(),
                disposition: ActionServingDisposition::Eligible,
                blocking_quarantine_ids: Vec::new(),
                state_revision: 1,
                coordinator_authority_digest: digest(1),
                validity: ServingValidity {
                    evaluated_at_unix_micros: 1_000,
                    maximum_age_micros: None,
                    clock_uncertainty_micros: 0,
                    coordinator_clock_epoch: 1,
                },
            },
            latest_trust_evaluation: eval_v1,
            observed_verification: VerificationLevel::IndependentReplay,
            enforced_isolation: IsolationProfile::StrictHermeticLinux,
            privacy_scope: Some("team-core".into()),
            diagnostics_redacted: true,
        };

        let dev_subscriber = SubscriberServingRequirements {
            subscriber_id: PeerId("sub-dev-1".into()),
            minimum_tier: TrustEvidenceTier::ShadowMatched,
            minimum_verification: VerificationLevel::IndependentReplay,
            required_isolation: IsolationProfile::StrictHermeticLinux,
            required_privacy_scope: Some("team-core".into()),
            require_redacted_diagnostics: true,
        };
        let release_subscriber = SubscriberServingRequirements {
            subscriber_id: PeerId("sub-release-2".into()),
            minimum_tier: TrustEvidenceTier::ReproducibleCrossWorker,
            minimum_verification: VerificationLevel::CrossWorkerConsensus {
                distinct_workers: 2,
            },
            required_isolation: IsolationProfile::StrictHermeticLinux,
            required_privacy_scope: Some("team-core".into()),
            require_redacted_diagnostics: true,
        };

        // 1. Committed result is immediately eligible for dev_subscriber, but ineligible
        // for release_subscriber (needs verification attempt).
        assert_eq!(
            evaluate_subscriber_serving_eligibility(&posture, &dev_subscriber, 2_000, 1),
            SubscriberEligibilityDecision::Eligible {
                satisfied_tier: TrustEvidenceTier::ShadowMatched,
                evaluation_causal_sequence: 100,
            }
        );
        assert_eq!(
            evaluate_subscriber_serving_eligibility(&posture, &release_subscriber, 2_000, 1),
            SubscriberEligibilityDecision::IneligibleNeedsVerificationAttempt {
                current_tier: TrustEvidenceTier::ShadowMatched,
                required_tier: TrustEvidenceTier::ReproducibleCrossWorker,
                current_verification: VerificationLevel::IndependentReplay,
                required_verification: VerificationLevel::CrossWorkerConsensus {
                    distinct_workers: 2,
                },
            }
        );

        // 2. Coordinator runs a verification attempt on a second worker, appends evidence,
        // and emits a new versioned ActionTrustEvaluationRecord (seq 105) without mutating
        // canonical_result_manifest_id (I42).
        let eval_v2 = ActionTrustEvaluationRecord::from_observed_evidence(
            manifest.clone(),
            ev_v2,
            TrustEvidenceTier::ReproducibleCrossWorker,
            105,
        )
        .unwrap();
        posture.latest_trust_evaluation = eval_v2;
        posture.observed_verification = VerificationLevel::CrossWorkerConsensus {
            distinct_workers: 2,
        };
        posture.serving_state.state_revision = 2;

        // Re-evaluating release_subscriber now succeeds against the new evaluation record!
        assert_eq!(
            evaluate_subscriber_serving_eligibility(&posture, &release_subscriber, 2_000, 1),
            SubscriberEligibilityDecision::Eligible {
                satisfied_tier: TrustEvidenceTier::ReproducibleCrossWorker,
                evaluation_causal_sequence: 105,
            }
        );
        assert_eq!(posture.canonical_result_manifest_id, manifest);
    }
}
