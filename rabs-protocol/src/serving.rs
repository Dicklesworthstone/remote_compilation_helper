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

use crate::provenance_receipt::{MAX_AUTHENTICATOR_BYTES, VerificationLevel};
use crate::result_identity::{DigestAlgorithm, ObjectId, TypedDigest};

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
}
