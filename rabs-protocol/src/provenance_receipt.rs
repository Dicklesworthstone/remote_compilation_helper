//! Provenance and evidence-tier receipts (bead S006; plan §106; couples to
//! S003 capability receipts, S001 identity store, S014 non-claim registry,
//! and H011's coordinator-only publication transaction).
//!
//! A [`ProvenanceReceipt`] is the immutable, per-publication record of HOW a
//! result was produced. It is EVIDENCE, never authority:
//!
//! - **THE STRUCTURAL LAW (this bead's title): worker identity evidence
//!   grants NO commit authority.** There is no function, trait, or type path
//!   from receipt contents — however complete, authenticated, or signed — to
//!   a commit grant. [`evaluate_commit_request`] accepts any number of
//!   perfectly authenticated receipts and they are provably inert: commit
//!   authority flows ONLY from a [`CoordinatorCommitVerification`], which is
//!   produced solely by the coordinator's own independent recomputation
//!   (H011). A stolen, validly signed receipt is still worth nothing.
//! - Receipts are REDACTION-SAFE by construction: every field is an id,
//!   digest, count, enum, sequence, or an S003 [`CapabilityReceipt`] (whose
//!   schema already forbids secret values). Secret slot NAMES may appear;
//!   values are unrepresentable.
//! - NON-CLAIMS are validated against CLOSED registries: the S014 V1
//!   registry plus this module's own authority non-claim. An invented
//!   non-claim string is a typed construction refusal — a receipt cannot be
//!   talked into overclaiming (mirrors S014's admission posture).
//! - Evidence tiers ([`TrustEvidenceTier`]) are DERIVED from recorded facts
//!   (authentication state + verification level), never asserted as claims.
//!   Unauthenticated observations are capped at [`TrustEvidenceTier::SelfReported`]
//!   no matter what the worker claims happened.
//! - Serve/materialization receipts ([`ServingReceipt`],
//!   [`MaterializationReceipt`]) are SEPARATE records that name the
//!   CONSUMING snapshot — the snapshot the outputs landed into — which is a
//!   different object from the producing snapshot named in the provenance
//!   receipt. Consuming context is per-subscriber history, not result
//!   identity (I50).
//!
//! Canonical byte framing lives here as a pure byte projection
//! ([`ProvenanceReceipt::canonical_bytes`]); digest COMPUTATION over that
//! framing stays with the storage layer (F034 ownership; this crate has no
//! hash dependencies by rule).

use crate::capability_tokens::CapabilityReceipt;
use crate::durable_ids::BuildOperationId;
use crate::generation::{
    ActionGenerationId, AttemptId, ExecutionLeaseId, LeaseRenewalSeq, WorkerBootGeneration,
    WorkerIncarnationId,
};
use crate::invocation_record::NormalizedOutcome;
use crate::result_identity::{ObjectId, TypedDigest};
use crate::trust_domain::v1_non_claims;
use crate::wire_time::PeerId;

/// Schema version for all three receipt kinds in this module (provenance,
/// serving, materialization); they evolve together as one publication-
/// evidence surface.
pub const PROVENANCE_RECEIPT_SCHEMA_VERSION: u32 = 1;

/// Domain separator for the canonical receipt framing (the storage layer
/// hashes `canonical_bytes` under this domain).
pub const PROVENANCE_RECEIPT_FRAMING_DOMAIN: &str = "rabs.provenance-receipt.sha256.v1";

/// This module's own closed non-claim addition to the S014 registry: carried
/// by every provenance receipt because the receipt itself is the thing most
/// likely to be mistaken for authority.
pub const NO_CLAIM_WORKER_IDENTITY_GRANTS_COMMIT_AUTHORITY: &str =
    "NO_CLAIM_WORKER_IDENTITY_GRANTS_COMMIT_AUTHORITY";

/// Bound on minimal-closure references (bounded collections rule).
pub const MAX_CLOSURE_REFS: usize = 4096;
/// Bound on recorded capability-use entries.
pub const MAX_CAPABILITY_USE_ENTRIES: usize = 256;
/// Bound on authenticator bytes (a signature/MAC, never a key or secret).
pub const MAX_AUTHENTICATOR_BYTES: usize = 512;

/// Whether the receipt's worker identity was authenticated, and at which
/// identity-store generation (S001). `Unauthenticated` is recorded loudly —
/// it caps the evidence tier rather than being silently upgraded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerAuthenticationEvidence {
    /// Key-derived identity verified against the S001 store at the named
    /// generation (exact-generation verification; stale generations are a
    /// typed mismatch there, so a receipt can only record a passing one).
    KeyFingerprint {
        /// Fingerprint digest of the verifying key.
        fingerprint_digest: TypedDigest,
        /// Identity-store generation the fingerprint matched.
        identity_generation: u64,
    },
    /// No authentication passed. The reason is recorded, never smoothed over.
    Unauthenticated {
        /// Why authentication did not happen (stable short code).
        reason: &'static str,
    },
}

/// How thoroughly the RESULT was verified before publication. Ordered: the
/// rank is the evidence ladder rung the level supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationLevel {
    /// Nothing beyond the offer's structural checks.
    None,
    /// The coordinator independently recomputed semantic/observable digests
    /// from stored projections (H011's admission bar).
    CoordinatorDigestRecompute,
    /// A second execution replayed the action and reproduced the observable
    /// digest.
    IndependentReplay,
    /// Distinct workers (>= 2) reproduced the observable digest.
    CrossWorkerConsensus {
        /// Number of DISTINCT workers agreeing (>= 2 when this level holds).
        distinct_workers: u8,
    },
    /// Compared against a stock local-toolchain run (release-tier bar; see
    /// S018 for the threat model this addresses).
    StockToolchainComparison,
}

impl VerificationLevel {
    /// Evidence-ladder rank (higher is stronger).
    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::None => 0,
            Self::CoordinatorDigestRecompute => 1,
            Self::IndependentReplay => 2,
            Self::CrossWorkerConsensus { .. } => 3,
            Self::StockToolchainComparison => 4,
        }
    }
}

/// The derived evidence tier of a publication (what its receipts SUPPORT,
/// not what anyone claims). Ordered ladder; [`TrustEvidenceTier::meets`]
/// compares against subscriber requirements (S021 consumes this).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrustEvidenceTier {
    /// Self-reported observation; nothing stands behind it.
    SelfReported,
    /// Authenticated worker identity plus coordinator digest recompute.
    AuthenticatedSingleWitness,
    /// An independent second execution reproduced the observable digest.
    IndependentlyReplayed,
    /// Distinct workers reproduced the observable digest.
    CrossWorkerConsensus,
    /// Verified against a stock local-toolchain run.
    StockVerified,
}

impl TrustEvidenceTier {
    /// Whether this tier satisfies a minimum requirement.
    #[must_use]
    pub const fn meets(self, minimum: Self) -> bool {
        self.rank() >= minimum.rank()
    }

    /// Ladder rank (higher is stronger).
    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::SelfReported => 0,
            Self::AuthenticatedSingleWitness => 1,
            Self::IndependentlyReplayed => 2,
            Self::CrossWorkerConsensus => 3,
            Self::StockVerified => 4,
        }
    }
}

/// The authenticated worker identity block of a provenance receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerIdentityEvidence {
    /// The executing worker's peer id.
    pub peer_id: PeerId,
    /// Authentication state at a specific identity generation.
    pub authentication: WorkerAuthenticationEvidence,
    /// Durable boot generation (restart fencing correlation).
    pub boot_generation: WorkerBootGeneration,
    /// Process incarnation (clone/overlap detection correlation).
    pub incarnation: WorkerIncarnationId,
}

/// Optional detached authenticator over the canonical receipt bytes. The
/// algorithm is NAMED and the payload is opaque bounded bytes — keys and
/// secret values are unrepresentable here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptAuthenticator {
    /// Named algorithm (e.g. `"ed25519-v1"`, `"hmac-sha256-v1"`).
    pub algorithm: &'static str,
    /// Signature/MAC bytes over `canonical_bytes`.
    pub bytes: Vec<u8>,
}

/// The immutable provenance receipt for ONE publication. Generated by the
/// coordinator at commit time from attempt evidence; verified by auditors
/// and subscribers thereafter. All fields are ids/digests/enums/sequences —
/// no secrets, no paths-as-truth, no claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvenanceReceipt {
    /// Schema version ([`PROVENANCE_RECEIPT_SCHEMA_VERSION`]).
    pub schema_version: u32,
    /// The action key this publication answers.
    pub action_key: TypedDigest,
    /// Key epoch at publication (cold-namespace lever in effect).
    pub key_epoch: u32,
    /// Projection epoch at publication.
    pub projection_epoch: u32,
    /// Digest of the canonical descriptor that was executed.
    pub canonical_descriptor_digest: TypedDigest,
    /// Producing snapshot root (full snapshot is provenance, not key — I4).
    pub producing_snapshot_root: ObjectId,
    /// Minimal required-repository closure behind the producing snapshot,
    /// ascending order, duplicates refused.
    pub minimal_closure: Vec<ObjectId>,
    /// Toolchain contract component digest that was honored.
    pub toolchain_contract: TypedDigest,
    /// Output platform contract component digest that was honored.
    pub output_platform_contract: TypedDigest,
    /// Sandbox semantic policy id digest that was requested.
    pub sandbox_semantic_policy: TypedDigest,
    /// Object reference to the IsolationEvidenceRecord: what the sandbox
    /// ACTUALLY enforced (E010's profiles-record-enforcement rule).
    pub isolation_evidence: ObjectId,
    /// The authenticated worker identity block.
    pub worker: WorkerIdentityEvidence,
    /// Durable build operation identity.
    pub operation_id: BuildOperationId,
    /// Action generation identity.
    pub generation_id: ActionGenerationId,
    /// Attempt identity.
    pub attempt_id: AttemptId,
    /// Execution lease identity.
    pub lease_id: ExecutionLeaseId,
    /// Last accepted lease renewal sequence.
    pub lease_renewal_seq: LeaseRenewalSeq,
    /// How the attempt terminated (signal-vs-exit preserved; C008/R94).
    pub termination: NormalizedOutcome,
    /// Observed-input report object (what the action ACTUALLY read).
    pub observed_input_report: ObjectId,
    /// The canonical result manifest this publication committed.
    pub canonical_result_manifest_id: ObjectId,
    /// How thoroughly the result was verified pre-commit.
    pub verification: VerificationLevel,
    /// Causal commit sequence at the coordinator.
    pub causal_sequence: u64,
    /// Redacted S003 receipts for capabilities exercised during the attempt
    /// (slot NAMES at most; values unrepresentable).
    pub capability_use: Vec<CapabilityReceipt>,
    /// Optional detached signature/MAC over [`Self::canonical_bytes`].
    pub authenticator: Option<ReceiptAuthenticator>,
    /// Closed-registry non-claims this publication carries.
    pub non_claims: Vec<&'static str>,
}

/// Typed construction/validation refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptRefusal {
    /// Minimal closure must ascend.
    ClosureNotSorted,
    /// Minimal closure must not repeat a reference.
    DuplicateClosureRef,
    /// Too many closure references.
    ClosureTooLarge,
    /// Too many capability-use entries.
    CapabilityUseTooLarge,
    /// Authenticator bytes exceed the bound.
    AuthenticatorTooLarge,
    /// Authenticator present but unnamed or empty.
    AuthenticatorMalformed,
    /// A non-claim outside every closed registry.
    NonClaimNotInRegistry,
}
/// Validate receipt invariants (used at construction and again at
/// verification time — storage may be corrupt; receipts re-check).
///
/// # Errors
/// The first violated invariant, typed.
pub fn validate(receipt: &ProvenanceReceipt) -> Result<(), ReceiptRefusal> {
    if receipt.minimal_closure.len() > MAX_CLOSURE_REFS {
        return Err(ReceiptRefusal::ClosureTooLarge);
    }
    for pair in receipt.minimal_closure.windows(2) {
        match object_sort_key(&pair[0]).cmp(&object_sort_key(&pair[1])) {
            std::cmp::Ordering::Greater => return Err(ReceiptRefusal::ClosureNotSorted),
            std::cmp::Ordering::Equal => return Err(ReceiptRefusal::DuplicateClosureRef),
            std::cmp::Ordering::Less => {}
        }
    }
    if receipt.capability_use.len() > MAX_CAPABILITY_USE_ENTRIES {
        return Err(ReceiptRefusal::CapabilityUseTooLarge);
    }
    if let Some(auth) = &receipt.authenticator {
        if auth.algorithm.is_empty() || auth.bytes.is_empty() {
            return Err(ReceiptRefusal::AuthenticatorMalformed);
        }
        if auth.bytes.len() > MAX_AUTHENTICATOR_BYTES {
            return Err(ReceiptRefusal::AuthenticatorTooLarge);
        }
    }
    for code in &receipt.non_claims {
        if !is_registered_non_claim(code) {
            return Err(ReceiptRefusal::NonClaimNotInRegistry);
        }
    }
    Ok(())
}

/// Canonical ascending order key for closure references: domain, then
/// digest bytes. (`ObjectId` deliberately has no `Ord` impl — ordering is
/// a local presentation concern, not part of identity semantics.)
fn object_sort_key(o: &ObjectId) -> (&'static str, [u8; 32]) {
    (o.0.domain, o.0.bytes)
}

/// Whether a non-claim string is in a CLOSED registry (S014 V1 plus this
/// module's authority non-claim). Private on purpose: the registries do not
/// grow by caller demand.
const fn is_registered_non_claim(code: &str) -> bool {
    let mut i = 0;
    while i < v1_non_claims().len() {
        if str_eq(v1_non_claims()[i], code) {
            return true;
        }
        i += 1;
    }
    str_eq(NO_CLAIM_WORKER_IDENTITY_GRANTS_COMMIT_AUTHORITY, code)
}

/// `const fn` string equality (loop-and-compare; no traits in const ctx).
const fn str_eq(a: &str, b: &str) -> bool {
    let (ab, bb) = (a.as_bytes(), b.as_bytes());
    if ab.len() != bb.len() {
        return false;
    }
    let mut i = 0;
    while i < ab.len() {
        if ab[i] != bb[i] {
            return false;
        }
        i += 1;
    }
    true
}

impl ProvenanceReceipt {
    /// Construct and validate a receipt (the intended constructor; callers
    /// assembling fields by hand MUST still run [`validate`] before trust).
    ///
    /// # Errors
    /// [`ReceiptRefusal`] citing the first violated invariant.
    pub fn new(mut receipt: Self) -> Result<Self, ReceiptRefusal> {
        receipt.schema_version = PROVENANCE_RECEIPT_SCHEMA_VERSION;
        validate(&receipt)?;
        Ok(receipt)
    }

    /// Derive the evidence tier from RECORDED FACTS. Unauthenticated
    /// observations cap at [`TrustEvidenceTier::SelfReported`] regardless of
    /// any claimed verification; authenticated tiers follow the verification
    /// ladder.
    #[must_use]
    pub fn evidence_tier(&self) -> TrustEvidenceTier {
        if matches!(
            self.worker.authentication,
            WorkerAuthenticationEvidence::Unauthenticated { .. }
        ) {
            return TrustEvidenceTier::SelfReported;
        }
        match self.verification {
            VerificationLevel::None | VerificationLevel::CoordinatorDigestRecompute => {
                TrustEvidenceTier::AuthenticatedSingleWitness
            }
            VerificationLevel::IndependentReplay => TrustEvidenceTier::IndependentlyReplayed,
            VerificationLevel::CrossWorkerConsensus { distinct_workers } => {
                if distinct_workers >= 2 {
                    TrustEvidenceTier::CrossWorkerConsensus
                } else {
                    // A consensus claim naming fewer than two workers does
                    // not stand: fall back to single-witness, loudly.
                    TrustEvidenceTier::AuthenticatedSingleWitness
                }
            }
            VerificationLevel::StockToolchainComparison => TrustEvidenceTier::StockVerified,
        }
    }

    /// The canonical, versioned, length-delimited byte projection of this
    /// receipt (little-endian lengths; fixed field order; enums as stable
    /// tags). Pure bytes: the STORAGE layer hashes this under
    /// [`PROVENANCE_RECEIPT_FRAMING_DOMAIN`] (F034 owns computation).
    /// Signatures (if any) cover exactly these bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_u32(&mut out, self.schema_version);
        put_digest(&mut out, &self.action_key);
        put_u32(&mut out, self.key_epoch);
        put_u32(&mut out, self.projection_epoch);
        put_digest(&mut out, &self.canonical_descriptor_digest);
        put_object(&mut out, &self.producing_snapshot_root);
        put_u64(&mut out, self.minimal_closure.len() as u64);
        for obj in &self.minimal_closure {
            put_object(&mut out, obj);
        }
        put_digest(&mut out, &self.toolchain_contract);
        put_digest(&mut out, &self.output_platform_contract);
        put_digest(&mut out, &self.sandbox_semantic_policy);
        put_object(&mut out, &self.isolation_evidence);
        put_str(&mut out, &self.worker.peer_id.0);
        match &self.worker.authentication {
            WorkerAuthenticationEvidence::KeyFingerprint {
                fingerprint_digest,
                identity_generation,
            } => {
                out.push(1);
                put_digest(&mut out, fingerprint_digest);
                put_u64(&mut out, *identity_generation);
            }
            WorkerAuthenticationEvidence::Unauthenticated { reason } => {
                out.push(2);
                put_str(&mut out, reason);
            }
        }
        put_u64(&mut out, self.worker.boot_generation.0);
        put_u128(&mut out, self.worker.incarnation.0);
        put_u128(&mut out, self.operation_id.0);
        put_u128(&mut out, self.generation_id.0);
        put_u128(&mut out, self.attempt_id.0);
        put_u128(&mut out, self.lease_id.0);
        put_u64(&mut out, self.lease_renewal_seq.0);
        match self.termination {
            NormalizedOutcome::Exited(code) => {
                out.push(1);
                out.extend_from_slice(&code.to_le_bytes());
            }
            NormalizedOutcome::Signaled(signal) => {
                out.push(2);
                out.extend_from_slice(&signal.to_le_bytes());
            }
        }
        put_object(&mut out, &self.observed_input_report);
        put_object(&mut out, &self.canonical_result_manifest_id);
        put_u8(&mut out, self.verification.tag());
        if let VerificationLevel::CrossWorkerConsensus { distinct_workers } = self.verification {
            put_u8(&mut out, distinct_workers);
        }
        put_u64(&mut out, self.causal_sequence);
        put_u64(&mut out, self.capability_use.len() as u64);
        for cap in &self.capability_use {
            put_u64(&mut out, cap.token_id);
            put_u8(&mut out, cap.kind.tag());
            put_str(&mut out, &cap.scope);
            put_u64(&mut out, cap.operation_id);
            put_u64(&mut out, cap.exercised_at_seq);
        }
        match &self.authenticator {
            None => out.push(0),
            Some(auth) => {
                out.push(1);
                put_str(&mut out, auth.algorithm);
                put_byte_slice(&mut out, &auth.bytes);
            }
        }
        put_u64(&mut out, self.non_claims.len() as u64);
        for code in &self.non_claims {
            put_str(&mut out, code);
        }
        out
    }
}

impl VerificationLevel {
    /// Stable framing tag.
    const fn tag(self) -> u8 {
        match self {
            Self::None => 0,
            Self::CoordinatorDigestRecompute => 1,
            Self::IndependentReplay => 2,
            Self::CrossWorkerConsensus { .. } => 3,
            Self::StockToolchainComparison => 4,
        }
    }
}

// --- Framing helpers (module-private; little-endian, length-delimited). ---

fn put_u8(out: &mut Vec<u8>, v: u8) {
    out.push(v);
}

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn put_u128(out: &mut Vec<u8>, v: u128) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn put_len(out: &mut Vec<u8>, len: usize) {
    put_u64(out, len as u64);
}

fn put_byte_slice(out: &mut Vec<u8>, bytes: &[u8]) {
    put_len(out, bytes.len());
    out.extend_from_slice(bytes);
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    put_byte_slice(out, s.as_bytes());
}

fn put_digest(out: &mut Vec<u8>, d: &TypedDigest) {
    put_u8(
        out,
        match d.algorithm {
            crate::result_identity::DigestAlgorithm::Sha256V1 => 1,
        },
    );
    put_str(out, d.domain);
    out.extend_from_slice(&d.bytes);
}

fn put_object(out: &mut Vec<u8>, o: &ObjectId) {
    put_digest(out, &o.0);
}

/// The coordinator-side verification record. Constructed ONLY by the
/// coordinator's own admission pipeline (H011) after ITS independent
/// recomputation — never from worker-supplied bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoordinatorCommitVerification {
    /// The manifest the coordinator's recompute endorsed.
    pub verified_manifest: ObjectId,
    /// The coordinator authority epoch under which verification ran.
    pub commit_authority_epoch: u64,
    /// The causal sequence the coordinator will stamp on commit.
    pub verified_sequence: u64,
}

/// The sole commit-authority grant shape. Carries no worker identity: who
/// ran the build is irrelevant to whether the commit may happen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitGrant {
    /// The manifest granted for commit.
    pub manifest: ObjectId,
    /// The stamped causal sequence.
    pub committed_sequence: u64,
}

/// Typed commit-authority refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityRefusal {
    /// No coordinator verification was presented. NOTE: no quantity or
    /// quality of worker receipts can ever substitute — this arm exists so
    /// the refusal is nameable in audits.
    NoCoordinatorVerification,
    /// Coordinator verification named a DIFFERENT result than requested.
    VerificationNamesDifferentResult,
    /// The verified sequence would move causality backwards.
    StaleCommitSequence,
}

/// Evaluate a commit request. THE STRUCTURAL LAW, executable form:
/// `presented_worker_evidence` — any number of provenance receipts, however
/// authenticated or signed — is deliberately INERT here. Authority comes
/// exclusively from [`CoordinatorCommitVerification`].
///
/// # Errors
/// [`AuthorityRefusal`] — missing coordinator verification, mismatched
/// result, or stale sequence.
pub fn evaluate_commit_request(
    coordinator_verification: Option<&CoordinatorCommitVerification>,
    presented_worker_evidence: &[ProvenanceReceipt],
    expected_manifest: &ObjectId,
    current_commit_sequence: u64,
) -> Result<CommitGrant, AuthorityRefusal> {
    // S006: receipts are evidence, never authority. The binding below is
    // intentionally the ONLY use of this parameter.
    let _receipts_are_inert: &[ProvenanceReceipt] = presented_worker_evidence;
    let Some(verification) = coordinator_verification else {
        return Err(AuthorityRefusal::NoCoordinatorVerification);
    };
    if &verification.verified_manifest != expected_manifest {
        return Err(AuthorityRefusal::VerificationNamesDifferentResult);
    }
    if verification.verified_sequence <= current_commit_sequence {
        return Err(AuthorityRefusal::StaleCommitSequence);
    }
    Ok(CommitGrant {
        manifest: verification.verified_manifest.clone(),
        committed_sequence: verification.verified_sequence,
    })
}

/// Receipt that a subscriber WAS SERVED a committed result. Names the
/// CONSUMING snapshot — the tree the subscriber will resolve outputs
/// against — which is a per-subscriber fact, never part of result identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServingReceipt {
    /// Schema version.
    pub schema_version: u32,
    /// The action key served.
    pub action_key: TypedDigest,
    /// Key epoch governing the served result.
    pub key_epoch: u32,
    /// The committed manifest that was served.
    pub served_result_manifest: ObjectId,
    /// The CONSUMING snapshot root (distinct from any producing snapshot).
    pub consuming_snapshot_root: ObjectId,
    /// The subscribing principal (peer id).
    pub subscriber: PeerId,
    /// Evidence tier the result held AT SERVING TIME (derived then; frozen
    /// here so later re-evaluation cannot rewrite history — S021 re-evaluates
    /// FORWARD, never retroactively).
    pub tier_at_serving: TrustEvidenceTier,
    /// Serving causal sequence.
    pub serving_sequence: u64,
}

/// Outcome of a materialization into a consumer's tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaterializationOutcome {
    /// Every declared output landed.
    Complete,
    /// Some outputs failed to land; the reason is recorded.
    Partial {
        /// Stable short reason code.
        reason: &'static str,
    },
}

/// Receipt that outputs were MATERIALIZED into a consumer's tree. Like
/// [`ServingReceipt`], it names the CONSUMING snapshot — the materialization
/// destination — separately from the producing snapshot in the provenance
/// receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializationReceipt {
    /// Schema version.
    pub schema_version: u32,
    /// The action key whose outputs landed.
    pub action_key: TypedDigest,
    /// The manifest whose logical-output map drove placement.
    pub served_result_manifest: ObjectId,
    /// The CONSUMING snapshot root the outputs landed into.
    pub consuming_snapshot_root: ObjectId,
    /// How many logical outputs landed.
    pub outputs_materialized: u32,
    /// Complete or partial (with reason).
    pub outcome: MaterializationOutcome,
    /// Materialization causal sequence.
    pub materialization_sequence: u64,
}

/// Construct a validated [`ServingReceipt`].
///
/// # Errors
/// Currently none beyond schema stamping; present for constructor symmetry
/// so call sites survive future validation additions unchanged.
pub fn serving_receipt(receipt: ServingReceipt) -> Result<ServingReceipt, ReceiptRefusal> {
    Ok(ServingReceipt {
        schema_version: PROVENANCE_RECEIPT_SCHEMA_VERSION,
        ..receipt
    })
}

/// Construct a validated [`MaterializationReceipt`].
///
/// # Errors
/// Currently none beyond schema stamping; present for constructor symmetry
/// so call sites survive future validation additions unchanged.
pub fn materialization_receipt(
    receipt: MaterializationReceipt,
) -> Result<MaterializationReceipt, ReceiptRefusal> {
    Ok(MaterializationReceipt {
        schema_version: PROVENANCE_RECEIPT_SCHEMA_VERSION,
        ..receipt
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability_tokens::CapabilityKind;
    use crate::result_identity::DigestAlgorithm;

    fn digest(domain: &'static str, seed: u8) -> TypedDigest {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain,
            bytes,
        }
    }

    fn object(seed: u8) -> ObjectId {
        ObjectId(digest("rabs.object.sha256.v1", seed))
    }

    fn key(seed: u8) -> TypedDigest {
        digest("rabs.action-key.sha256.v1", seed)
    }

    fn authenticated_worker(peer: &str) -> WorkerIdentityEvidence {
        WorkerIdentityEvidence {
            peer_id: PeerId(peer.to_owned()),
            authentication: WorkerAuthenticationEvidence::KeyFingerprint {
                fingerprint_digest: digest("rabs.identity-fingerprint.sha256.v1", 9),
                identity_generation: 3,
            },
            boot_generation: WorkerBootGeneration(7),
            incarnation: WorkerIncarnationId(0xABCD),
        }
    }

    fn base_receipt() -> ProvenanceReceipt {
        ProvenanceReceipt {
            schema_version: PROVENANCE_RECEIPT_SCHEMA_VERSION,
            action_key: key(1),
            key_epoch: 2,
            projection_epoch: 5,
            canonical_descriptor_digest: digest("rabs.action-descriptor.sha256.v1", 3),
            producing_snapshot_root: object(10),
            minimal_closure: vec![object(20), object(21)],
            toolchain_contract: digest("rabs.toolchain-contract.sha256.v1", 4),
            output_platform_contract: digest("rabs.platform-contract.sha256.v1", 5),
            sandbox_semantic_policy: digest("rabs.sandbox-policy.sha256.v1", 6),
            isolation_evidence: object(30),
            worker: authenticated_worker("worker-a"),
            operation_id: BuildOperationId(0x1000),
            generation_id: ActionGenerationId(0x2000),
            attempt_id: AttemptId(0x3000),
            lease_id: ExecutionLeaseId(0x4000),
            lease_renewal_seq: LeaseRenewalSeq(11),
            termination: NormalizedOutcome::Exited(0),
            observed_input_report: object(40),
            canonical_result_manifest_id: object(50),
            verification: VerificationLevel::CoordinatorDigestRecompute,
            causal_sequence: 42,
            capability_use: Vec::new(),
            authenticator: None,
            non_claims: vec![
                crate::trust_domain::NO_CLAIM_BYZANTINE_WORKER_TOLERANCE,
                NO_CLAIM_WORKER_IDENTITY_GRANTS_COMMIT_AUTHORITY,
            ],
        }
    }

    #[test]
    fn s006_valid_receipt_constructs_and_revalidates() {
        let receipt = ProvenanceReceipt::new(base_receipt()).expect("base receipt is valid");
        assert_eq!(receipt.schema_version, 1);
        validate(&receipt).expect("revalidation of stored receipt succeeds");
        assert_eq!(
            receipt.non_claims,
            vec![
                crate::trust_domain::NO_CLAIM_BYZANTINE_WORKER_TOLERANCE,
                NO_CLAIM_WORKER_IDENTITY_GRANTS_COMMIT_AUTHORITY,
            ]
        );
    }

    #[test]
    fn s006_construction_refusals_are_typed() {
        // Unsorted closure.
        let mut r = base_receipt();
        r.minimal_closure = vec![object(21), object(20)];
        assert_eq!(
            ProvenanceReceipt::new(r),
            Err(ReceiptRefusal::ClosureNotSorted)
        );
        // Duplicate closure ref.
        let mut r = base_receipt();
        r.minimal_closure = vec![object(20), object(20)];
        assert_eq!(
            ProvenanceReceipt::new(r),
            Err(ReceiptRefusal::DuplicateClosureRef)
        );
        // Invented non-claim: the receipt cannot be talked into new language.
        let mut r = base_receipt();
        r.non_claims = vec!["NO_CLAIM_I_INVENTED_JUST_NOW"];
        assert_eq!(
            ProvenanceReceipt::new(r),
            Err(ReceiptRefusal::NonClaimNotInRegistry)
        );
        // Malformed authenticator: named but empty.
        let mut r = base_receipt();
        r.authenticator = Some(ReceiptAuthenticator {
            algorithm: "ed25519-v1",
            bytes: Vec::new(),
        });
        assert_eq!(
            ProvenanceReceipt::new(r),
            Err(ReceiptRefusal::AuthenticatorMalformed)
        );
        // Oversized authenticator.
        let mut r = base_receipt();
        r.authenticator = Some(ReceiptAuthenticator {
            algorithm: "ed25519-v1",
            bytes: vec![0u8; MAX_AUTHENTICATOR_BYTES + 1],
        });
        assert_eq!(
            ProvenanceReceipt::new(r),
            Err(ReceiptRefusal::AuthenticatorTooLarge)
        );
    }

    #[test]
    fn s006_canonical_bytes_are_deterministic_and_field_sensitive() {
        let receipt = ProvenanceReceipt::new(base_receipt()).expect("valid");
        let baseline = receipt.canonical_bytes();
        assert!(!baseline.is_empty());
        // Deterministic across clones.
        assert_eq!(baseline, receipt.clone().canonical_bytes());

        // Each mutated field changes the framing (field-sensitivity sample
        // across every framing section).
        /// One named mutation applied to a receipt (test-local helper type;
        /// keeps the clippy type-complexity gate quiet without weakening
        /// the sensitivity sample).
        type Mutation<'a> = (&'a str, Box<dyn Fn(&mut ProvenanceReceipt)>);
        let mutations: Vec<Mutation<'_>> = vec![
            ("action_key", Box::new(|r| r.action_key = key(99))),
            ("key_epoch", Box::new(|r| r.key_epoch += 1)),
            (
                "descriptor",
                Box::new(|r| {
                    r.canonical_descriptor_digest = digest("rabs.action-descriptor.sha256.v1", 77)
                }),
            ),
            (
                "producing_snapshot",
                Box::new(|r| r.producing_snapshot_root = object(88)),
            ),
            (
                "closure",
                Box::new(|r| r.minimal_closure = vec![object(20), object(21), object(22)]),
            ),
            (
                "worker_auth",
                Box::new(|r| {
                    r.worker.authentication =
                        WorkerAuthenticationEvidence::Unauthenticated { reason: "no-mtls" }
                }),
            ),
            (
                "termination",
                Box::new(|r| r.termination = NormalizedOutcome::Signaled(9)),
            ),
            (
                "manifest",
                Box::new(|r| r.canonical_result_manifest_id = object(55)),
            ),
            (
                "verification",
                Box::new(|r| r.verification = VerificationLevel::StockToolchainComparison),
            ),
            ("causal_sequence", Box::new(|r| r.causal_sequence += 1)),
            (
                "capability_use",
                Box::new(|r| {
                    let token = crate::capability_tokens::mint(
                        1,
                        CapabilityKind::ExecuteAction,
                        7,
                        9,
                        "rabs.object.sha256.v1:50",
                        100,
                    )
                    .expect("scoped token mints");
                    r.capability_use = vec![crate::capability_tokens::receipt(&token, 50)];
                }),
            ),
            (
                "authenticator",
                Box::new(|r| {
                    r.authenticator = Some(ReceiptAuthenticator {
                        algorithm: "ed25519-v1",
                        bytes: vec![1, 2, 3],
                    })
                }),
            ),
            (
                "non_claims",
                Box::new(|r| {
                    r.non_claims
                        .push(crate::trust_domain::NO_CLAIM_MULTI_TENANT_ISOLATION)
                }),
            ),
        ];
        for (name, mutate) in mutations {
            let mut r = receipt.clone();
            mutate(&mut r);
            let mutated = ProvenanceReceipt::new(r)
                .unwrap_or_else(|e| panic!("mutation {name} must stay constructible: {e:?}"));
            assert_ne!(
                baseline,
                mutated.canonical_bytes(),
                "framing must be sensitive to {name}"
            );
        }
    }

    #[test]
    fn s006_evidence_tier_is_derived_from_facts_not_claims() {
        // Authenticated + digest recompute -> single witness.
        let r = ProvenanceReceipt::new(base_receipt()).expect("valid");
        assert_eq!(
            r.evidence_tier(),
            TrustEvidenceTier::AuthenticatedSingleWitness
        );

        // UNAUTHENTICATED caps at SelfReported EVEN IF the worker claims the
        // strongest verification level — claims do not lift tiers.
        let mut lying = base_receipt();
        lying.verification = VerificationLevel::StockToolchainComparison;
        lying.worker.authentication = WorkerAuthenticationEvidence::Unauthenticated {
            reason: "fingerprint-stale",
        };
        let lying = ProvenanceReceipt::new(lying).expect("valid");
        assert_eq!(lying.evidence_tier(), TrustEvidenceTier::SelfReported);

        // Ladder climbs only with recorded verification facts.
        let mut replay = base_receipt();
        replay.verification = VerificationLevel::IndependentReplay;
        let replay = ProvenanceReceipt::new(replay).expect("valid");
        assert_eq!(
            replay.evidence_tier(),
            TrustEvidenceTier::IndependentlyReplayed
        );

        let mut consensus = base_receipt();
        consensus.verification = VerificationLevel::CrossWorkerConsensus {
            distinct_workers: 3,
        };
        let consensus = ProvenanceReceipt::new(consensus).expect("valid");
        assert_eq!(
            consensus.evidence_tier(),
            TrustEvidenceTier::CrossWorkerConsensus
        );

        // A "consensus" of one is not consensus: falls back loudly.
        let mut fake_consensus = base_receipt();
        fake_consensus.verification = VerificationLevel::CrossWorkerConsensus {
            distinct_workers: 1,
        };
        let fake_consensus = ProvenanceReceipt::new(fake_consensus).expect("valid");
        assert_eq!(
            fake_consensus.evidence_tier(),
            TrustEvidenceTier::AuthenticatedSingleWitness
        );

        let mut stock = base_receipt();
        stock.verification = VerificationLevel::StockToolchainComparison;
        let stock = ProvenanceReceipt::new(stock).expect("valid");
        assert_eq!(stock.evidence_tier(), TrustEvidenceTier::StockVerified);

        // Tier ordering + meets().
        assert!(TrustEvidenceTier::StockVerified.meets(TrustEvidenceTier::CrossWorkerConsensus));
        assert!(
            !TrustEvidenceTier::SelfReported.meets(TrustEvidenceTier::AuthenticatedSingleWitness)
        );
    }

    #[test]
    fn s006_worker_identity_evidence_grants_no_commit_authority() {
        // The maximally privileged receipt possible: authenticated worker at
        // a real generation, signed, strongest claimed verification, full
        // evidence chain — and STILL zero commit authority without the
        // coordinator's own verification record.
        let mut supreme = base_receipt();
        supreme.verification = VerificationLevel::StockToolchainComparison;
        supreme.authenticator = Some(ReceiptAuthenticator {
            algorithm: "ed25519-v1",
            bytes: vec![7u8; 64],
        });
        supreme.capability_use = {
            let t = crate::capability_tokens::mint(
                5,
                CapabilityKind::OfferPreparedActionResult,
                7,
                9,
                "staging-prefix:/cas/staging/50",
                200,
            )
            .expect("mints");
            vec![crate::capability_tokens::receipt(&t, 90)]
        };
        let supreme = ProvenanceReceipt::new(supreme).expect("valid");
        assert_eq!(supreme.evidence_tier(), TrustEvidenceTier::StockVerified);

        // Receipts alone (one, many, whatever): refused.
        let expected = supreme.canonical_result_manifest_id.clone();
        assert_eq!(
            evaluate_commit_request(None, std::slice::from_ref(&supreme), &expected, 41),
            Err(AuthorityRefusal::NoCoordinatorVerification)
        );

        // ...and the refusal is unchanged by QUANTITY of evidence.
        assert_eq!(
            evaluate_commit_request(None, &[supreme.clone(), supreme], &expected, 41),
            Err(AuthorityRefusal::NoCoordinatorVerification)
        );

        // With the coordinator's OWN verification record: granted.
        let verification = CoordinatorCommitVerification {
            verified_manifest: expected.clone(),
            commit_authority_epoch: 1,
            verified_sequence: 43,
        };
        let grant = evaluate_commit_request(Some(&verification), &[], &expected, 41)
            .expect("coordinator verification alone authorizes");
        assert_eq!(grant.manifest, expected);
        assert_eq!(grant.committed_sequence, 43);

        // Verification naming a different result refuses.
        assert_eq!(
            evaluate_commit_request(Some(&verification), &[], &object(255), 41),
            Err(AuthorityRefusal::VerificationNamesDifferentResult)
        );

        // Stale sequences refuse (causality never moves backwards).
        assert_eq!(
            evaluate_commit_request(Some(&verification), &[], &expected, 43),
            Err(AuthorityRefusal::StaleCommitSequence)
        );
        assert_eq!(
            evaluate_commit_request(Some(&verification), &[], &expected, 100),
            Err(AuthorityRefusal::StaleCommitSequence)
        );
    }

    #[test]
    fn s006_serving_and_materialization_receipts_name_the_consuming_snapshot() {
        let provenance = ProvenanceReceipt::new(base_receipt()).expect("valid");
        let producing = provenance.producing_snapshot_root.clone();

        // The SERVING receipt names a DIFFERENT (consuming) snapshot.
        let serve = serving_receipt(ServingReceipt {
            schema_version: 0, // stamped by constructor
            action_key: provenance.action_key.clone(),
            key_epoch: provenance.key_epoch,
            served_result_manifest: provenance.canonical_result_manifest_id.clone(),
            consuming_snapshot_root: object(70),
            subscriber: PeerId("edge-1".to_owned()),
            tier_at_serving: provenance.evidence_tier(),
            serving_sequence: 44,
        })
        .expect("serving receipt constructs");
        assert_eq!(serve.schema_version, PROVENANCE_RECEIPT_SCHEMA_VERSION);
        assert_ne!(
            serve.consuming_snapshot_root, producing,
            "serving receipts name the CONSUMING snapshot, never the producer"
        );
        // Frozen-at-serving tier: later re-evaluation cannot rewrite history.
        assert_eq!(
            serve.tier_at_serving,
            TrustEvidenceTier::AuthenticatedSingleWitness
        );

        // The MATERIALIZATION receipt likewise names its consuming snapshot.
        let mat = materialization_receipt(MaterializationReceipt {
            schema_version: 0,
            action_key: provenance.action_key.clone(),
            served_result_manifest: provenance.canonical_result_manifest_id.clone(),
            consuming_snapshot_root: object(71),
            outputs_materialized: 12,
            outcome: MaterializationOutcome::Partial {
                reason: "locked-file",
            },
            materialization_sequence: 45,
        })
        .expect("materialization receipt constructs");
        assert_eq!(mat.schema_version, PROVENANCE_RECEIPT_SCHEMA_VERSION);
        assert_ne!(mat.consuming_snapshot_root, producing);
        assert_eq!(
            mat.outcome,
            MaterializationOutcome::Partial {
                reason: "locked-file"
            }
        );

        // Serving receipts are per-subscriber history: the same result served
        // to another subscriber/consuming snapshot is a distinct receipt.
        let serve_two = serving_receipt(ServingReceipt {
            schema_version: 0,
            action_key: provenance.action_key.clone(),
            key_epoch: provenance.key_epoch,
            served_result_manifest: provenance.canonical_result_manifest_id.clone(),
            consuming_snapshot_root: object(72),
            subscriber: PeerId("ci-req".to_owned()),
            tier_at_serving: provenance.evidence_tier(),
            serving_sequence: 46,
        })
        .expect("constructs");
        assert_ne!(
            serve.consuming_snapshot_root,
            serve_two.consuming_snapshot_root
        );
        assert_eq!(
            serve.served_result_manifest,
            serve_two.served_result_manifest
        );
    }
}
