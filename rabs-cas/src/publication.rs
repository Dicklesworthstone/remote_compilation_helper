//! Prepared-result offer + coordinator-only atomic publication (bead
//! H011; plan §62/§66; invariants I8/I9/I10; risk R50).
//!
//! The worker side ends at [`OfferPreparedActionResult::build`]: a worker
//! harvests its private write set, validates outputs against declarations,
//! uploads objects under candidate pins, and OFFERS. There is deliberately
//! no worker-reachable commit API — a worker never sends a command asking
//! another component to commit on its behalf; the type system enforces it
//! (only [`process_offer`] touches the store).
//!
//! The coordinator side is an ordered admission pipeline over the H009
//! metadata store:
//!
//! 1. authority fence: the offer's full coordinator authority must digest
//!    to the ACTIVE authority, and the generation's
//!    `created_under_authority_digest` must equal that digest (the F033
//!    equality check — one full authority copy, bound by digest);
//! 2. generation fence: the generation exists and is not tombstoned;
//! 3. attempt/lease fences: the attempt exists under that generation and
//!    its execution lease is unreleased;
//! 4. descriptor reload + byte-compare against the coordinator's own copy;
//! 5. key + epoch validation against the action entry;
//! 6. INDEPENDENT digest recompute: the coordinator recomputes
//!    `semantic_result_digest` and `observable_result_digest` from the
//!    versioned projections and refuses on any declared-digest mismatch;
//! 7. complete object closure: every referenced object must already have
//!    a recorded location;
//! 8. same-key candidates classify through the A018 divergence taxonomy:
//!    idempotent re-offers append evidence; every divergence class
//!    quarantines the ACTION and preserves the committed row (no in-place
//!    patching — correction is quarantine + recompute or a new epoch);
//! 9. commit: publication pointer, serving state, winner evidence row,
//!    AND the durable reachability pin in ONE store transaction (H009's
//!    `commit_publication`); the receipt is emitted only after the store
//!    reports durable success.
//!
//! The crash matrix over this protocol is bead H015.

use rabs_protocol::generation::AttemptAuthority;
use rabs_protocol::raw_bytes::RawBytes;
use rabs_protocol::result_identity::{
    ActionPublicationRecord, AttemptEvidenceBundle, CanonicalActionResultManifest, DigestAlgorithm,
    DivergenceClass, ObjectId, OutputRole, ResultKind, TypedDigest,
};
use sha2::{Digest, Sha256};

use crate::metadata_store::{
    CommitOutcome, DivergenceIncidentRow, ProvisionalAncestorRow, PublicationRow, QuarantineScope,
    RabsMetadataStore, ResultKindTag, StoreError, digest_key,
};
use crate::trust_evidence::DISPOSITION_QUARANTINED;

/// Domain separator for the canonical coordinator-authority digest.
pub const AUTHORITY_DIGEST_DOMAIN: &str = "rabs.coordinator-authority.sha256.v1";
/// Domain separator for the v1 semantic result projection.
pub const SEMANTIC_PROJECTION_DOMAIN: &str = "rabs.semantic-result-projection.sha256.v1";
/// Domain separator for the v1 observable result projection.
pub const OBSERVABLE_PROJECTION_DOMAIN: &str = "rabs.observable-result-projection.sha256.v1";

/// Serving disposition for observable-only divergence (H026): ordinary
/// replay is disabled (any disposition other than `"servable"` refuses
/// the serving gate), but the narrower tag records that the semantic
/// result itself was reproduced — only presentation/observability
/// differed.
pub const DISPOSITION_PRESENTATION_QUARANTINED: &str = "presentation-quarantined";

/// Pin class preserving the LOSING candidate of a divergence incident
/// (H026; I34): both candidates outlive GC until the incident is
/// resolved.
pub const DIVERGENCE_EVIDENCE_PIN_CLASS: &str = "divergence-evidence";

/// Length-delimited canonical framing (the F034 pattern): every field is
/// `len(u64 be) || bytes`, so no concatenation ambiguity exists.
struct Framing(Sha256);

impl Framing {
    fn new(domain: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update((domain.len() as u64).to_be_bytes());
        hasher.update(domain.as_bytes());
        Self(hasher)
    }

    fn field(&mut self, bytes: &[u8]) -> &mut Self {
        self.0.update((bytes.len() as u64).to_be_bytes());
        self.0.update(bytes);
        self
    }

    fn u64(&mut self, v: u64) -> &mut Self {
        self.field(&v.to_be_bytes())
    }

    fn digest_field(&mut self, d: &TypedDigest) -> &mut Self {
        self.field(d.domain.as_bytes());
        self.field(&d.bytes)
    }

    fn finish(self, domain: &'static str) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain,
            bytes: self.0.finalize().into(),
        }
    }
}

/// Canonical digest of a FULL coordinator authority value. The generation
/// stores only this digest (risk R117: two independently mutable full
/// copies are forbidden by construction).
#[must_use]
pub fn authority_digest(authority: &rabs_protocol::authority::CoordinatorAuthority) -> TypedDigest {
    let mut framing = Framing::new(AUTHORITY_DIGEST_DOMAIN);
    framing
        .field(authority.cluster_id.0.as_bytes())
        .u64(authority.credential_generation)
        .u64(authority.term)
        .field(&authority.incarnation_id.0.to_be_bytes());
    framing.finish(AUTHORITY_DIGEST_DOMAIN)
}

const fn result_kind_tag(kind: ResultKind) -> u64 {
    match kind {
        ResultKind::Success => 0,
        ResultKind::DeterministicFailure => 1,
    }
}

const fn output_role_tag(role: OutputRole) -> u64 {
    match role {
        OutputRole::Materializable => 0,
        OutputRole::DepInfo => 1,
        OutputRole::ProvisionalMetadata => 2,
        OutputRole::BuildScriptMetadata => 3,
        OutputRole::TestSideEffect => 4,
    }
}

/// The v1 semantic result projection: replayable output/exit facts only.
/// Excludes both declared digest fields by construction.
#[must_use]
pub fn semantic_result_digest_v1(manifest: &CanonicalActionResultManifest) -> TypedDigest {
    let mut framing = Framing::new(SEMANTIC_PROJECTION_DOMAIN);
    framing
        .digest_field(&manifest.action_key)
        .digest_field(&manifest.canonical_descriptor_digest)
        .u64(u64::from(manifest.key_epoch))
        .u64(u64::from(manifest.projection_epoch))
        .u64(result_kind_tag(manifest.result_kind));
    match &manifest.artifact_bundle_root {
        None => framing.u64(0),
        Some(root) => framing.u64(1).digest_field(&root.0),
    };
    let mut outputs: Vec<&rabs_protocol::result_identity::LogicalOutput> =
        manifest.logical_outputs.iter().collect();
    outputs.sort_by(|a, b| {
        (output_role_tag(a.role), a.virtual_path.as_bytes())
            .cmp(&(output_role_tag(b.role), b.virtual_path.as_bytes()))
    });
    framing.u64(outputs.len() as u64);
    for output in outputs {
        framing
            .u64(output_role_tag(output.role))
            .field(output.virtual_path.as_bytes())
            .digest_field(&output.object.0);
    }
    framing.finish(SEMANTIC_PROJECTION_DOMAIN)
}

/// The v1 observable result projection: the semantic projection plus the
/// canonical observation stream digest.
#[must_use]
pub fn observable_result_digest_v1(
    manifest: &CanonicalActionResultManifest,
    canonical_observations: &TypedDigest,
) -> TypedDigest {
    let mut framing = Framing::new(OBSERVABLE_PROJECTION_DOMAIN);
    framing
        .digest_field(&semantic_result_digest_v1(manifest))
        .digest_field(canonical_observations);
    framing.finish(OBSERVABLE_PROJECTION_DOMAIN)
}

/// Worker-side offer construction failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OfferBuildError {
    /// The manifest failed structural validation.
    ManifestInvalid(&'static str),
    /// The evidence bundle does not reference this manifest.
    EvidenceManifestMismatch,
    /// Evidence/manifest/authority disagree on the action key.
    ActionKeyMismatch,
    /// An output was harvested that the action never declared.
    UndeclaredOutput {
        /// Escaped virtual path of the offending output.
        path: String,
    },
    /// Two provisional-ancestor references name the same
    /// (producer, role, path) — the canonical set admits no duplicates.
    DuplicateAncestorRef {
        /// Escaped virtual path of the duplicated reference.
        path: String,
    },
    /// A provisional-ancestor reference names the offering action itself.
    SelfAncestorRef,
}

/// One provisional-ancestor reference carried by a prepared result
/// (H028; I32): the offering attempt consumed `consumed_object` as the
/// producer action's `(role, virtual_path)` provisional output before
/// that producer had committed. Commit verifies the producer is now
/// committed and resolves that logical output to the EXACT consumed
/// object (or an explicit adoption edge).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionalAncestorRef {
    /// Action key of the producer whose provisional output was consumed.
    pub producer_action_key: TypedDigest,
    /// Role of the consumed logical output.
    pub role: OutputRole,
    /// Canonical virtual path of the consumed logical output.
    pub virtual_path: RawBytes,
    /// The exact object the attempt consumed.
    pub consumed_object: ObjectId,
}

/// Stable string tag for an output role (persisted in lineage and
/// adoption rows; the numeric `output_role_tag` above is framing-only).
const fn output_role_name(role: OutputRole) -> &'static str {
    match role {
        OutputRole::Materializable => "materializable",
        OutputRole::DepInfo => "dep-info",
        OutputRole::ProvisionalMetadata => "provisional-metadata",
        OutputRole::BuildScriptMetadata => "build-script-metadata",
        OutputRole::TestSideEffect => "test-side-effect",
    }
}

/// A prepared result offered for publication, carrying FULL authority
/// identity (never bare ids).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfferPreparedActionResult {
    /// The full attempt authority (coordinator + generation + attempt +
    /// lease + worker identity).
    pub authority: AttemptAuthority,
    /// The canonical result manifest.
    pub manifest: CanonicalActionResultManifest,
    /// CAS identity of the uploaded manifest object.
    pub manifest_id: ObjectId,
    /// The attempt evidence bundle.
    pub evidence: AttemptEvidenceBundle,
    /// CAS identity of the uploaded evidence object.
    pub evidence_id: ObjectId,
    /// Digest of the canonical observation stream (input to the
    /// observable projection recompute).
    pub canonical_observations: TypedDigest,
    /// Canonical (sorted, duplicate-free) provisional-ancestor set
    /// (H028; I32). Empty when no provisional outputs were consumed.
    pub provisional_ancestors: Vec<ProvisionalAncestorRef>,
}

impl OfferPreparedActionResult {
    /// Worker-side build: validate the harvested manifest against the
    /// action's output declarations, recompute and STAMP both projection
    /// digests, and bind evidence to manifest. The returned offer is the
    /// only thing a worker may send — committing is structurally out of
    /// reach.
    ///
    /// # Errors
    /// A typed [`OfferBuildError`] naming the violated rule.
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        authority: AttemptAuthority,
        mut manifest: CanonicalActionResultManifest,
        manifest_id: ObjectId,
        evidence: AttemptEvidenceBundle,
        evidence_id: ObjectId,
        canonical_observations: TypedDigest,
        declared_outputs: &[(OutputRole, RawBytes)],
        mut provisional_ancestors: Vec<ProvisionalAncestorRef>,
    ) -> Result<Self, OfferBuildError> {
        manifest
            .validate()
            .map_err(OfferBuildError::ManifestInvalid)?;
        // Canonical sorted ancestor set: order-independent identity,
        // duplicates refused, self-reference refused (H028).
        provisional_ancestors.sort_by(|a, b| {
            (
                digest_key(&a.producer_action_key),
                output_role_name(a.role),
                a.virtual_path.as_bytes(),
            )
                .cmp(&(
                    digest_key(&b.producer_action_key),
                    output_role_name(b.role),
                    b.virtual_path.as_bytes(),
                ))
        });
        for pair in provisional_ancestors.windows(2) {
            if pair[0].producer_action_key == pair[1].producer_action_key
                && pair[0].role == pair[1].role
                && pair[0].virtual_path == pair[1].virtual_path
            {
                return Err(OfferBuildError::DuplicateAncestorRef {
                    path: pair[1].virtual_path.escaped(),
                });
            }
        }
        if provisional_ancestors
            .iter()
            .any(|a| a.producer_action_key == manifest.action_key)
        {
            return Err(OfferBuildError::SelfAncestorRef);
        }
        if evidence.canonical_result_manifest_id != manifest_id {
            return Err(OfferBuildError::EvidenceManifestMismatch);
        }
        if evidence.action_key != manifest.action_key || authority.action_key != manifest.action_key
        {
            return Err(OfferBuildError::ActionKeyMismatch);
        }
        for output in &manifest.logical_outputs {
            let declared = declared_outputs
                .iter()
                .any(|(role, path)| *role == output.role && *path == output.virtual_path);
            if !declared {
                return Err(OfferBuildError::UndeclaredOutput {
                    path: output.virtual_path.escaped(),
                });
            }
        }
        manifest.semantic_result_digest = semantic_result_digest_v1(&manifest);
        manifest.observable_result_digest =
            observable_result_digest_v1(&manifest, &canonical_observations);
        Ok(Self {
            authority,
            manifest,
            manifest_id,
            evidence,
            evidence_id,
            canonical_observations,
            provisional_ancestors,
        })
    }
}

/// Typed coordinator refusals — the offer is NOT admitted, nothing was
/// written (a refusal is not a divergence).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OfferRefusal {
    /// The offer's full authority does not digest to the active one.
    NotActiveAuthority,
    /// The generation's `created_under_authority_digest` differs from the
    /// digest of the offer's full authority (F033 equality violation).
    GenerationAuthorityMismatch,
    /// The generation does not exist in the store.
    UnknownGeneration,
    /// The generation is tombstoned (superseded/aborted).
    GenerationTombstoned,
    /// The attempt is not recorded under that generation.
    UnknownAttempt,
    /// The execution lease is missing.
    UnknownLease,
    /// The execution lease was released.
    LeaseReleased,
    /// Reloaded canonical descriptor digest differs byte-for-byte.
    DescriptorMismatch,
    /// Manifest action key differs from the authority's action key.
    ActionKeyMismatch,
    /// No action entry exists for the key.
    UnknownActionEntry,
    /// Manifest epochs disagree with the action entry.
    EpochMismatch,
    /// Independent recompute of `semantic_result_digest` disagrees with
    /// the declared value.
    SemanticDigestMismatch,
    /// Independent recompute of `observable_result_digest` disagrees with
    /// the declared value.
    ObservableDigestMismatch,
    /// A referenced object has no recorded location (incomplete closure).
    IncompleteObjectClosure {
        /// Digest key of the first missing object.
        missing: String,
    },
    /// A referenced object is located but no copy satisfies the FULL
    /// durability profile the commit is configured to require (H032):
    /// acknowledging would create a committed pointer to bytes that may
    /// only exist in volatile page cache.
    ObjectNotDurable {
        /// Digest key of the first non-durable object.
        missing: String,
    },
    /// The committed manifest for a same-key offer could not be loaded
    /// for divergence classification.
    CommittedManifestUnavailable,
    /// A referenced provisional-ancestor producer (direct or transitive)
    /// has no committed publication (H028; I32: no dependent commit
    /// before producer finalization).
    ProvisionalProducerNotCommitted {
        /// Digest key of the uncommitted producer action.
        producer: String,
    },
    /// A committed ancestor's manifest bytes could not be loaded for the
    /// exact-object check.
    AncestorManifestUnavailable {
        /// Digest key of the producer action.
        producer: String,
    },
    /// The producer committed, but its canonical manifest has no logical
    /// output at the referenced (role, path).
    AncestorOutputMissing {
        /// Digest key of the producer action.
        producer: String,
        /// Escaped virtual path of the missing output.
        path: String,
    },
    /// The producer committed a DIFFERENT object at the referenced
    /// logical output and no adoption edge covers the consumed object
    /// (risk R64: the consumed provisional bytes are not what the
    /// winning attempt published).
    DivergentProvisionalAncestor {
        /// Digest key of the producer action.
        producer: String,
        /// Escaped virtual path of the divergent output.
        path: String,
    },
    /// The store refused or failed.
    Store(StoreError),
}

impl From<StoreError> for OfferRefusal {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

/// One consumer escalated after a semantic divergence (H026): the
/// consumer was previously served this action's result, so it must be
/// told the result's determinism is now in question. The decision is
/// tiered by the action's latest trust/release evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumerEscalation {
    /// The served consumer (as recorded in `served-to` provenance).
    pub consumer: String,
    /// The action's latest trust-evaluation state at escalation time
    /// (`"unevaluated"` when no evaluation exists).
    pub trust_state: String,
    /// The tiered escalation decision recorded in the receipt.
    pub decision: String,
}

/// The full H026 quarantine outcome for a same-key divergence: what was
/// quarantined, which incident row records it, which pin preserves the
/// losing candidate, and who was escalated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DivergenceQuarantine {
    /// The A018 divergence class.
    pub class: DivergenceClass,
    /// Sequence of the append-only incident row.
    pub incident_seq: u64,
    /// Id of the durable candidate-preservation pin.
    pub candidate_pin_id: u128,
    /// Consumers escalated from `served-to` provenance (semantic
    /// divergence only; empty for the other classes).
    pub escalations: Vec<ConsumerEscalation>,
}

/// Admitted outcomes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicationOutcome {
    /// Committed durably; the receipt exists only after the store
    /// transaction succeeded.
    Committed(ActionPublicationRecord),
    /// Same manifest already committed: evidence appended, nothing else
    /// changed.
    IdempotentEvidenceAppended,
    /// Same key, different result: the action is quarantined with the
    /// A018 divergence class; the committed row is preserved untouched
    /// and BOTH candidates survive (H026).
    Quarantined(DivergenceQuarantine),
}

/// The configured CAS durability profile a commit acknowledgement gates
/// on (H032): what "the objects exist" must mean BEFORE the metadata
/// transaction may commit. `ActionResultCommitted` (the
/// [`PublicationOutcome::Committed`] receipt) exists only after both the
/// CAS side satisfies this profile and the store transaction reported
/// durable success.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitDurabilityProfile {
    /// Authoritative default: every object in the offer's closure must
    /// have a durable (full fsync profile), non-quarantined location. A
    /// power failure after commit can then never orphan the committed
    /// pointer.
    RequireDurableClosure,
    /// Explicitly volatile deployment (throwaway scratch cache): any
    /// non-quarantined location admits. Named, never the silent default.
    AcceptVolatileLocations,
}

const fn result_kind_to_tag(kind: ResultKind) -> ResultKindTag {
    match kind {
        ResultKind::Success => ResultKindTag::Success,
        ResultKind::DeterministicFailure => ResultKindTag::DeterministicFailure,
    }
}

/// Coordinator-only admission + atomic publication. `expected_descriptor`
/// is the coordinator's OWN reloaded copy of the canonical descriptor
/// digest; `committed_manifest` resolves a manifest digest key to the
/// manifest bytes the coordinator holds in its CAS (used only for
/// same-key divergence classification); `pin_id` is the coordinator-
/// allocated durable pin id — the publication reachability pin on
/// commit, or the candidate-preservation pin when the offer diverges
/// (H026); `seq` is the causal commit sequence stamped into the receipt
/// (and into the incident row on divergence); `durability` is the
/// configured H032 commit profile — under
/// [`CommitDurabilityProfile::RequireDurableClosure`] every closure
/// object must have a durable location BEFORE the metadata transaction
/// runs, so the committed pointer can never name bytes a power failure
/// may still lose.
///
/// # Errors
/// A typed [`OfferRefusal`]; refusals write nothing.
pub fn process_offer(
    store: &mut dyn RabsMetadataStore,
    offer: &OfferPreparedActionResult,
    expected_descriptor: &TypedDigest,
    manifest_resolver: impl Fn(&str) -> Option<CanonicalActionResultManifest>,
    pin_id: u128,
    seq: u64,
    durability: CommitDurabilityProfile,
) -> Result<PublicationOutcome, OfferRefusal> {
    // 1. Authority fence: active authority + F033 digest equality.
    let offered_authority = authority_digest(&offer.authority.coordinator);
    let active = store.active_authority()?;
    match active {
        Some(row) if row.digest == offered_authority => {}
        _ => return Err(OfferRefusal::NotActiveAuthority),
    }
    if offer
        .authority
        .action_generation
        .created_under_authority_digest
        != offered_authority
    {
        return Err(OfferRefusal::GenerationAuthorityMismatch);
    }

    // 2. Generation fence.
    let generation_id = offer.authority.action_generation.generation_id.0;
    match store.generation_state(generation_id)? {
        None => return Err(OfferRefusal::UnknownGeneration),
        Some(state) if state.tombstoned => return Err(OfferRefusal::GenerationTombstoned),
        Some(_) => {}
    }

    // 3. Attempt + lease fences.
    let attempt_id = offer.authority.attempt_id.0;
    if !store.attempt_exists(attempt_id, generation_id)? {
        return Err(OfferRefusal::UnknownAttempt);
    }
    match store.lease_state(offer.authority.execution_lease_id.0)? {
        None => return Err(OfferRefusal::UnknownLease),
        Some(state) if state.released => return Err(OfferRefusal::LeaseReleased),
        Some(_) => {}
    }

    // 4. Descriptor reload + byte-compare.
    if offer.manifest.canonical_descriptor_digest != *expected_descriptor {
        return Err(OfferRefusal::DescriptorMismatch);
    }

    // 5. Key + epoch validation.
    if offer.manifest.action_key != offer.authority.action_key {
        return Err(OfferRefusal::ActionKeyMismatch);
    }
    let entry = store
        .lookup_action(&offer.manifest.action_key)?
        .ok_or(OfferRefusal::UnknownActionEntry)?;
    if entry.key_epoch != offer.manifest.key_epoch
        || entry.projection_epoch != offer.manifest.projection_epoch
    {
        return Err(OfferRefusal::EpochMismatch);
    }

    // 6. Independent digest recompute from the versioned projections.
    if semantic_result_digest_v1(&offer.manifest) != offer.manifest.semantic_result_digest {
        return Err(OfferRefusal::SemanticDigestMismatch);
    }
    if observable_result_digest_v1(&offer.manifest, &offer.canonical_observations)
        != offer.manifest.observable_result_digest
    {
        return Err(OfferRefusal::ObservableDigestMismatch);
    }

    // 7. Complete object closure: manifest, evidence, bundle root, every
    // logical output, every evidence constituent.
    let mut closure: Vec<&TypedDigest> = vec![&offer.manifest_id.0, &offer.evidence_id.0];
    if let Some(root) = &offer.manifest.artifact_bundle_root {
        closure.push(&root.0);
    }
    for output in &offer.manifest.logical_outputs {
        closure.push(&output.object.0);
    }
    closure.push(&offer.evidence.execution_snapshot_root.0);
    closure.push(&offer.evidence.observed_input_report.0);
    closure.push(&offer.evidence.raw_process_and_event_evidence.0);
    closure.push(&offer.evidence.provenance_receipt.0);
    if let Some(snapshot) = &offer.evidence.incremental_snapshot {
        closure.push(&snapshot.0);
    }
    for object in closure {
        if !store.object_located(object)? {
            return Err(OfferRefusal::IncompleteObjectClosure {
                missing: digest_key(object),
            });
        }
        // H032: under the authoritative profile the metadata transaction
        // may not even begin until every closure object has a durable
        // copy — located-but-volatile is a typed refusal, not a commit.
        if durability == CommitDurabilityProfile::RequireDurableClosure
            && !store.object_durably_located(object)?
        {
            return Err(OfferRefusal::ObjectNotDurable {
                missing: digest_key(object),
            });
        }
    }

    // 7.5. Provisional-ancestor closure (H028; I32): EVERY referenced
    // producer — direct AND transitive through each committed producer's
    // recorded lineage — must be committed and resolve the referenced
    // logical output to the exact consumed object (or an explicit
    // adoption edge). Direct-only checking would let an A→B→C chain
    // commit C over a hole at A.
    let ancestor_rows = verify_provisional_ancestry(store, offer, &manifest_resolver)?;

    // 8. Same-key candidates: divergence taxonomy, never overwrite.
    if let Some(committed_key) = store.published_manifest_key(&offer.manifest.action_key)? {
        let candidate_key = digest_key(&offer.manifest_id.0);
        if committed_key == candidate_key {
            // Idempotent re-offer: append evidence only, bound to the
            // committed canonical manifest it supports (H029; I37).
            store.append_evidence(
                &offer.manifest.action_key,
                &committed_key,
                &offer.evidence_id.0,
                generation_id,
                attempt_id,
            )?;
            return Ok(PublicationOutcome::IdempotentEvidenceAppended);
        }
        let committed =
            manifest_resolver(&committed_key).ok_or(OfferRefusal::CommittedManifestUnavailable)?;
        // A018 taxonomy with the manifest-id inequality already
        // established above (committed_key != candidate_key), so the
        // idempotent branch is unreachable here by construction.
        let class = if committed.semantic_result_digest != offer.manifest.semantic_result_digest {
            DivergenceClass::SemanticDivergence
        } else if committed.observable_result_digest != offer.manifest.observable_result_digest {
            DivergenceClass::ObservableOnlyDivergence
        } else {
            DivergenceClass::ProjectionCompletenessIncident
        };
        let quarantine = quarantine_divergence(
            store,
            &offered_authority,
            offer,
            class,
            &committed_key,
            generation_id,
            attempt_id,
            pin_id,
            seq,
        )?;
        return Ok(PublicationOutcome::Quarantined(quarantine));
    }

    // 9. Compare-and-set commit: publication pointer + serving state +
    // winner evidence + durable reachability pin, ONE transaction.
    let row = PublicationRow {
        action_key: offer.manifest.action_key.clone(),
        descriptor_digest: offer.manifest.canonical_descriptor_digest.clone(),
        manifest_digest: offer.manifest_id.0.clone(),
        evidence_digest: offer.evidence_id.0.clone(),
        winner_generation: generation_id,
        winner_attempt: attempt_id,
        result_kind: result_kind_to_tag(offer.manifest.result_kind),
        pin_id,
        pin_owner: "coordinator".to_owned(),
        provisional_ancestors: ancestor_rows,
    };
    match store.commit_publication(&offered_authority, &row)? {
        CommitOutcome::Committed => {}
        // The pipeline checked for an existing row above; hitting either
        // branch here means the store's own CAS caught a same-key row —
        // surface it as the conservative refusal, never a silent success.
        CommitOutcome::IdempotentDuplicate | CommitOutcome::ConflictQuarantined => {
            return Err(OfferRefusal::Store(StoreError::Corruption(
                "publication row appeared during admission".into(),
            )));
        }
    }
    // ActionResultCommitted: emitted only after durable success.
    Ok(PublicationOutcome::Committed(ActionPublicationRecord {
        action_key: offer.manifest.action_key.clone(),
        canonical_result_manifest_id: offer.manifest_id.clone(),
        winner_evidence_bundle_id: offer.evidence_id.clone(),
        committed_causal_sequence: seq,
    }))
}

/// One lineage reference to verify: producer/role/path/consumed-object,
/// all in digest-key/tag form so direct refs (typed) and recorded rows
/// (strings) share one code path.
struct PendingAncestorCheck {
    producer_key: String,
    role_tag: String,
    path: Vec<u8>,
    consumed_key: String,
    /// Direct refs are recorded on the consumer's own publication row;
    /// transitive ones are already recorded on their consumer.
    direct: bool,
}

/// The H028 transitive provisional-ancestor verification (I32; R64).
///
/// Walks the offer's direct references plus, for every committed
/// producer, the lineage rows recorded at THAT producer's commit —
/// breadth-first with a visited set, so diamond graphs verify once and
/// cycles terminate. Every reference (at every depth) must satisfy:
/// producer committed, its canonical manifest resolves the (role, path)
/// logical output, and that output is the EXACT consumed object or an
/// explicit adoption edge from consumed to committed exists.
///
/// Returns the verified direct rows for the consumer's own publication.
fn verify_provisional_ancestry(
    store: &mut dyn RabsMetadataStore,
    offer: &OfferPreparedActionResult,
    manifest_resolver: &impl Fn(&str) -> Option<CanonicalActionResultManifest>,
) -> Result<Vec<ProvisionalAncestorRow>, OfferRefusal> {
    let mut direct_rows = Vec::new();
    let mut queue: std::collections::VecDeque<PendingAncestorCheck> = offer
        .provisional_ancestors
        .iter()
        .map(|a| PendingAncestorCheck {
            producer_key: digest_key(&a.producer_action_key),
            role_tag: output_role_name(a.role).to_owned(),
            path: a.virtual_path.as_bytes().to_vec(),
            consumed_key: digest_key(&a.consumed_object.0),
            direct: true,
        })
        .collect();
    let mut walked_producers = std::collections::BTreeSet::new();

    while let Some(check) = queue.pop_front() {
        // Producer committed? (Direct-only shortcuts are exactly the
        // R64 hole; this fires at every depth.)
        let manifest_key = store
            .published_manifest_key_str(&check.producer_key)?
            .ok_or_else(|| OfferRefusal::ProvisionalProducerNotCommitted {
                producer: check.producer_key.clone(),
            })?;
        let manifest = manifest_resolver(&manifest_key).ok_or_else(|| {
            OfferRefusal::AncestorManifestUnavailable {
                producer: check.producer_key.clone(),
            }
        })?;
        // Exact-object resolution at the referenced logical output.
        let output = manifest
            .logical_outputs
            .iter()
            .find(|o| {
                output_role_name(o.role) == check.role_tag
                    && o.virtual_path.as_bytes() == check.path.as_slice()
            })
            .ok_or_else(|| OfferRefusal::AncestorOutputMissing {
                producer: check.producer_key.clone(),
                path: RawBytes::new(check.path.clone()).escaped(),
            })?;
        let committed_key = digest_key(&output.object.0);
        let adopted = if committed_key == check.consumed_key {
            false
        } else if store.has_adoption_edge(
            &check.producer_key,
            &check.role_tag,
            &check.path,
            &check.consumed_key,
            &committed_key,
        )? {
            true
        } else {
            return Err(OfferRefusal::DivergentProvisionalAncestor {
                producer: check.producer_key.clone(),
                path: RawBytes::new(check.path.clone()).escaped(),
            });
        };
        if check.direct {
            direct_rows.push(ProvisionalAncestorRow {
                producer_action_key: check.producer_key.clone(),
                role: check.role_tag.clone(),
                virtual_path: check.path.clone(),
                object_key: check.consumed_key.clone(),
                adopted,
            });
        }
        // Transitive expansion: the producer's own recorded lineage.
        if walked_producers.insert(check.producer_key.clone()) {
            for row in store.list_provisional_ancestors(&check.producer_key)? {
                if walked_producers.contains(&row.producer_action_key) {
                    continue;
                }
                queue.push_back(PendingAncestorCheck {
                    producer_key: row.producer_action_key,
                    role_tag: row.role,
                    path: row.virtual_path,
                    consumed_key: row.object_key,
                    direct: false,
                });
            }
        }
    }
    Ok(direct_rows)
}

const fn divergence_class_tag(class: DivergenceClass) -> &'static str {
    match class {
        DivergenceClass::IdempotentSameResult => "idempotent",
        DivergenceClass::SemanticDivergence => "semantic",
        DivergenceClass::ObservableOnlyDivergence => "observable-only",
        DivergenceClass::ProjectionCompletenessIncident => "projection-completeness",
    }
}

const fn divergence_quarantine_reason(class: DivergenceClass) -> &'static str {
    match class {
        DivergenceClass::IdempotentSameResult => "same-key re-offer",
        DivergenceClass::SemanticDivergence => {
            "semantic divergence: determinism/key-soundness incident"
        }
        DivergenceClass::ObservableOnlyDivergence => {
            "observable-only divergence: presentation quarantine"
        }
        DivergenceClass::ProjectionCompletenessIncident => {
            "projection completeness incident: equal digests, different manifests"
        }
    }
}

/// Tiered escalation decision for a served consumer (H026): a consumer
/// served under a RELEASE tier may have shipped artifacts built on the
/// now-suspect result, so it gets a recall; everything below release
/// tier is notified for re-verification.
fn escalation_decision(trust_state: &str) -> &'static str {
    match trust_state {
        "ci-policy-approved" | "project-release-eligible" => "recall-and-reverify",
        _ => "notify-and-reverify",
    }
}

/// The H026 divergence quarantine: quarantine the ACTION, disable
/// serving with a per-class disposition, preserve BOTH candidates (the
/// committed row is untouched; the losing candidate gets a durable
/// `divergence-evidence` pin plus reachability edges and its evidence is
/// appended to the index), open an append-only incident row, and — for
/// semantic divergence — escalate every consumer previously served this
/// result, tiered by the action's latest trust/release evaluation.
///
/// Write order is stricter-state-first: a crash mid-sequence can leave
/// the action quarantined with partial bookkeeping, never bookkept but
/// unquarantined.
#[allow(clippy::too_many_arguments)]
fn quarantine_divergence(
    store: &mut dyn RabsMetadataStore,
    authority: &TypedDigest,
    offer: &OfferPreparedActionResult,
    class: DivergenceClass,
    committed_key: &str,
    generation_id: u128,
    attempt_id: u128,
    pin_id: u128,
    seq: u64,
) -> Result<DivergenceQuarantine, OfferRefusal> {
    let action_key = digest_key(&offer.manifest.action_key);
    let candidate_key = digest_key(&offer.manifest_id.0);

    // 1. Quarantine first (strictest state lands before anything else).
    store.add_quarantine(
        QuarantineScope::ActionEntry,
        &action_key,
        divergence_quarantine_reason(class),
    )?;

    // 2. Per-class serving disposition: semantic and
    // projection-completeness fully disable serving; observable-only is
    // the narrower presentation quarantine. Either way ordinary replay
    // is disabled — the serving gate refuses any non-"servable"
    // disposition.
    let disposition = match class {
        DivergenceClass::ObservableOnlyDivergence => DISPOSITION_PRESENTATION_QUARANTINED,
        _ => DISPOSITION_QUARANTINED,
    };
    store.set_serving_disposition_key(&action_key, disposition)?;

    // 3. Preserve the losing candidate: reachability edges from its
    // manifest to everything it references, then a durable pin rooted at
    // the manifest so GC preserves the whole candidate closure.
    store.add_object_edge(
        &offer.manifest_id.0,
        &offer.evidence_id.0,
        "divergence-candidate",
    )?;
    if let Some(root) = &offer.manifest.artifact_bundle_root {
        store.add_object_edge(&offer.manifest_id.0, &root.0, "divergence-candidate")?;
    }
    for output in &offer.manifest.logical_outputs {
        store.add_object_edge(
            &offer.manifest_id.0,
            &output.object.0,
            "divergence-candidate",
        )?;
    }
    store.create_pin(
        pin_id,
        &offer.manifest_id.0,
        "coordinator",
        DIVERGENCE_EVIDENCE_PIN_CLASS,
        None,
        Some(&format!("divergence-incident:{action_key}:{seq}")),
        true,
        divergence_quarantine_reason(class),
    )?;

    // 4. The candidate's evidence bundle joins the append-only index —
    // attempt evidence is preserved for BOTH candidates (I34) — bound to
    // the CANDIDATE manifest, so the committed canonical result's
    // evidence view never absorbs a divergent candidate's evidence
    // (H029; I37).
    store.append_evidence(
        &offer.manifest.action_key,
        &candidate_key,
        &offer.evidence_id.0,
        generation_id,
        attempt_id,
    )?;

    // 5. Open the incident (append-only; authority-gated).
    store.record_divergence_incident(
        authority,
        &DivergenceIncidentRow {
            action_key: action_key.clone(),
            seq,
            class: divergence_class_tag(class).to_owned(),
            committed_manifest_key: committed_key.to_owned(),
            candidate_manifest_key: candidate_key,
            candidate_evidence_key: digest_key(&offer.evidence_id.0),
            candidate_pin_hex: format!("{pin_id:032x}"),
            generation_hex: format!("{generation_id:032x}"),
            attempt_hex: format!("{attempt_id:032x}"),
            detail: divergence_quarantine_reason(class).to_owned(),
        },
    )?;

    // 6. Semantic divergence escalates previously served consumers from
    // provenance, tiered by the latest trust/release evaluation.
    let mut escalations = Vec::new();
    if class == DivergenceClass::SemanticDivergence {
        let trust_state = store
            .latest_trust_evaluation(&offer.manifest.action_key)?
            .map_or_else(|| "unevaluated".to_owned(), |row| row.state);
        for consumer in store.list_served_consumers(&action_key)? {
            let decision = escalation_decision(&trust_state);
            store.record_decision_receipt(
                "divergence-escalation",
                &consumer,
                seq,
                decision,
                &format!("semantic divergence on {action_key}; trust {trust_state}"),
            )?;
            escalations.push(ConsumerEscalation {
                consumer,
                trust_state: trust_state.clone(),
                decision: decision.to_owned(),
            });
        }
    }

    Ok(DivergenceQuarantine {
        class,
        incident_seq: seq,
        candidate_pin_id: pin_id,
        escalations,
    })
}

/// Outcome of comparing a post-eviction recomputation against the
/// retained eviction tombstone (bead H034).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecomputationCheck {
    /// No tombstone exists for the key: nothing to compare.
    NoTombstone,
    /// Both digests match the retained values: the recomputation
    /// reproduces the evicted result; the tombstone is consumed.
    Reproduced,
    /// The recomputation DIVERGES from the evicted result: an incident —
    /// the action is quarantined, never silently replaced.
    Divergence(DivergenceClass),
}

/// H034: retain a published result's projection digests before its blobs
/// are evicted, so a later recomputation of the same key has something
/// to answer to.
///
/// # Errors
/// Store errors from the tombstone write.
pub fn retain_eviction_tombstone(
    store: &mut dyn RabsMetadataStore,
    manifest: &CanonicalActionResultManifest,
    evicted_seq: u64,
) -> Result<(), StoreError> {
    store.record_eviction_tombstone(
        &manifest.action_key,
        &manifest.semantic_result_digest,
        &manifest.observable_result_digest,
        evicted_seq,
    )
}

/// H034: compare a re-executed result's digests against the eviction
/// tombstone. A match consumes the tombstone (the result is reproduced
/// and may republish); a mismatch quarantines the ACTION with the A018
/// divergence class and LEAVES the tombstone in place as incident
/// evidence.
///
/// # Errors
/// Store errors from the lookup/quarantine writes.
pub fn check_recomputation_against_tombstone(
    store: &mut dyn RabsMetadataStore,
    action: &TypedDigest,
    new_semantic: &TypedDigest,
    new_observable: &TypedDigest,
) -> Result<RecomputationCheck, StoreError> {
    let Some((retained_semantic, retained_observable)) = store.eviction_tombstone(action)? else {
        return Ok(RecomputationCheck::NoTombstone);
    };
    if retained_semantic == *new_semantic && retained_observable == *new_observable {
        store.consume_eviction_tombstone(action)?;
        return Ok(RecomputationCheck::Reproduced);
    }
    let class = if retained_semantic == *new_semantic {
        DivergenceClass::ObservableOnlyDivergence
    } else {
        DivergenceClass::SemanticDivergence
    };
    store.add_quarantine(
        QuarantineScope::ActionEntry,
        &digest_key(action),
        "post-eviction recomputation divergence",
    )?;
    Ok(RecomputationCheck::Divergence(class))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rabs_protocol::authority::{ClusterId, CoordinatorAuthority, CoordinatorIncarnationId};
    use rabs_protocol::generation::{
        ActionGeneration, ActionGenerationId, AttemptId, ExecutionLeaseId, LeaseRenewalSeq,
        WorkerBootGeneration, WorkerIncarnationId,
    };
    use rabs_protocol::result_identity::LogicalOutput;
    use rabs_protocol::wire_time::PeerId;

    use crate::metadata_store::{
        ActionEntryRow, AuthorityRow, FsqliteEngine, RusqliteEngine, SqlMetadataStore,
    };
    use std::sync::atomic::{AtomicU64, Ordering};

    static DB_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn fresh_path(tag: &str) -> std::path::PathBuf {
        let n = DB_COUNTER.fetch_add(1, Ordering::SeqCst);
        std::env::temp_dir().join(format!("rabs-h011-{}-{}-{}.db", std::process::id(), tag, n))
    }

    fn digest(domain: &'static str, tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain,
            bytes: [tag; 32],
        }
    }

    fn object(tag: u8) -> ObjectId {
        ObjectId(digest("rabs.object.sha256.v1", tag))
    }

    fn coordinator_authority() -> CoordinatorAuthority {
        CoordinatorAuthority {
            cluster_id: ClusterId("cluster-a".to_owned()),
            credential_generation: 1,
            term: 3,
            incarnation_id: CoordinatorIncarnationId(77),
        }
    }

    fn attempt_authority() -> AttemptAuthority {
        let coordinator = coordinator_authority();
        let created_under = authority_digest(&coordinator);
        AttemptAuthority {
            coordinator,
            action_key: digest("rabs.action-key.sha256.v1", 7),
            action_generation: ActionGeneration {
                generation_id: ActionGenerationId(11),
                per_key_ordinal: 1,
                created_under_authority_digest: created_under,
            },
            attempt_id: AttemptId(20),
            execution_lease_id: ExecutionLeaseId(30),
            lease_renewal_seq: LeaseRenewalSeq(1),
            worker_peer_id: PeerId("worker-a".to_owned()),
            worker_boot_generation: WorkerBootGeneration(1),
            worker_incarnation_id: WorkerIncarnationId(5),
        }
    }

    fn manifest() -> CanonicalActionResultManifest {
        CanonicalActionResultManifest {
            action_key: digest("rabs.action-key.sha256.v1", 7),
            canonical_descriptor_digest: digest("rabs.descriptor.sha256.v1", 8),
            key_epoch: 1,
            projection_epoch: 1,
            result_kind: ResultKind::Success,
            artifact_bundle_root: Some(object(40)),
            logical_outputs: vec![LogicalOutput {
                role: OutputRole::Materializable,
                virtual_path: RawBytes::new(b"out/lib.rlib".to_vec()),
                object: object(41),
            }],
            // Stamped by build().
            semantic_result_digest: digest(SEMANTIC_PROJECTION_DOMAIN, 0),
            observable_result_digest: digest(OBSERVABLE_PROJECTION_DOMAIN, 0),
        }
    }

    fn evidence(manifest_id: &ObjectId) -> AttemptEvidenceBundle {
        AttemptEvidenceBundle {
            action_key: digest("rabs.action-key.sha256.v1", 7),
            canonical_result_manifest_id: manifest_id.clone(),
            execution_snapshot_root: object(60),
            observed_input_report: object(61),
            raw_process_and_event_evidence: object(62),
            provenance_receipt: object(63),
            incremental_snapshot: None,
        }
    }

    fn declared() -> Vec<(OutputRole, RawBytes)> {
        vec![(
            OutputRole::Materializable,
            RawBytes::new(b"out/lib.rlib".to_vec()),
        )]
    }

    fn offer() -> OfferPreparedActionResult {
        let manifest_id = object(50);
        OfferPreparedActionResult::build(
            attempt_authority(),
            manifest(),
            manifest_id.clone(),
            evidence(&manifest_id),
            object(51),
            digest("rabs.observation-stream.sha256.v1", 9),
            &declared(),
            Vec::new(),
        )
        .unwrap()
    }

    /// A store with the full admission world installed: active authority,
    /// action entry, generation, attempt, lease, and every closure object
    /// located.
    fn ready_store(store: &mut dyn RabsMetadataStore) {
        let auth = authority_digest(&coordinator_authority());
        store
            .acquire_authority(&AuthorityRow {
                digest: auth.clone(),
                cluster_id: "cluster-a".to_owned(),
                incarnation: 77,
                term: 3,
                acquired_seq: 1,
            })
            .unwrap();
        store
            .upsert_action_entry(&ActionEntryRow {
                action_key: digest("rabs.action-key.sha256.v1", 7),
                key_epoch: 1,
                projection_epoch: 1,
            })
            .unwrap();
        store
            .create_generation(&auth, 11, &digest("rabs.action-key.sha256.v1", 7))
            .unwrap();
        store.record_attempt(20, 11, "worker-a", 1).unwrap();
        store.acquire_lease(30, 20, 1, 100).unwrap();
        for tag in [40, 41, 50, 51, 60, 61, 62, 63] {
            let id = object(tag);
            store.record_object(&id.0, 64).unwrap();
            store
                .add_location(&id.0, &format!("/cas/{tag}"), Some(1), "raw", true)
                .unwrap();
        }
    }

    fn expected_descriptor() -> TypedDigest {
        digest("rabs.descriptor.sha256.v1", 8)
    }

    fn no_committed(_: &str) -> Option<CanonicalActionResultManifest> {
        None
    }

    /// A committed producer world for the H028 scenarios: `key_tag`
    /// names the producer action, its canonical manifest (id
    /// `manifest_tag`) resolves one ProvisionalMetadata output at `path`
    /// to `output_tag`, and its publication row carries `ancestors`.
    #[allow(clippy::too_many_arguments)]
    fn plant_producer(
        store: &mut dyn RabsMetadataStore,
        resolver_map: &mut std::collections::BTreeMap<String, CanonicalActionResultManifest>,
        key_tag: u8,
        manifest_tag: u8,
        path: &str,
        output_tag: u8,
        pin: u128,
        ancestors: Vec<ProvisionalAncestorRow>,
    ) {
        let action = digest("rabs.action-key.sha256.v1", key_tag);
        let mut producer_manifest = manifest();
        producer_manifest.action_key = action.clone();
        producer_manifest.logical_outputs = vec![LogicalOutput {
            role: OutputRole::ProvisionalMetadata,
            virtual_path: RawBytes::from(path),
            object: object(output_tag),
        }];
        resolver_map.insert(digest_key(&object(manifest_tag).0), producer_manifest);
        let auth = authority_digest(&coordinator_authority());
        assert_eq!(
            store
                .commit_publication(
                    &auth,
                    &PublicationRow {
                        action_key: action,
                        descriptor_digest: expected_descriptor(),
                        manifest_digest: object(manifest_tag).0,
                        evidence_digest: object(manifest_tag).0.clone(),
                        winner_generation: 11,
                        winner_attempt: 20,
                        result_kind: ResultKindTag::Success,
                        pin_id: pin,
                        pin_owner: "coordinator".to_owned(),
                        provisional_ancestors: ancestors,
                    },
                )
                .unwrap(),
            CommitOutcome::Committed
        );
    }

    fn ancestor_ref(producer_tag: u8, path: &str, consumed_tag: u8) -> ProvisionalAncestorRef {
        ProvisionalAncestorRef {
            producer_action_key: digest("rabs.action-key.sha256.v1", producer_tag),
            role: OutputRole::ProvisionalMetadata,
            virtual_path: RawBytes::from(path),
            consumed_object: object(consumed_tag),
        }
    }

    fn offer_with_ancestors(ancestors: Vec<ProvisionalAncestorRef>) -> OfferPreparedActionResult {
        let manifest_id = object(50);
        OfferPreparedActionResult::build(
            attempt_authority(),
            manifest(),
            manifest_id.clone(),
            evidence(&manifest_id),
            object(51),
            digest("rabs.observation-stream.sha256.v1", 9),
            &declared(),
            ancestors,
        )
        .unwrap()
    }

    #[test]
    fn h028_transitive_ancestor_closure_adoption_and_divergence() {
        // World: A (key 100) committed ProvisionalMetadata "out/a.rmeta"
        // -> object 110; B (key 101) committed "out/b.rmeta" -> object
        // 111 and RECORDS having consumed A's object 110; C offers,
        // naming only B (consumed object 111). T020.
        let engine = RusqliteEngine::open_in_memory().unwrap();
        let mut store = SqlMetadataStore::open(engine).unwrap();
        ready_store(&mut store);
        let mut manifests = std::collections::BTreeMap::new();
        plant_producer(
            &mut store,
            &mut manifests,
            100,
            120,
            "out/a.rmeta",
            110,
            800,
            vec![],
        );
        plant_producer(
            &mut store,
            &mut manifests,
            101,
            121,
            "out/b.rmeta",
            111,
            801,
            vec![ProvisionalAncestorRow {
                producer_action_key: digest_key(&digest("rabs.action-key.sha256.v1", 100)),
                role: "provisional-metadata".to_owned(),
                virtual_path: b"out/a.rmeta".to_vec(),
                object_key: digest_key(&object(110).0),
                adopted: false,
            }],
        );
        let resolver = {
            let manifests = manifests.clone();
            move |key: &str| manifests.get(key).cloned()
        };

        // Happy path: full A->B->C chain verified; C commits and its
        // publication records the direct lineage row.
        let c_offer = offer_with_ancestors(vec![ancestor_ref(101, "out/b.rmeta", 111)]);
        assert!(matches!(
            process_offer(
                &mut store,
                &c_offer,
                &expected_descriptor(),
                resolver.clone(),
                900,
                1,
                CommitDurabilityProfile::RequireDurableClosure,
            )
            .unwrap(),
            PublicationOutcome::Committed(_)
        ));
        let c_key = digest_key(&digest("rabs.action-key.sha256.v1", 7));
        let recorded = store.list_provisional_ancestors(&c_key).unwrap();
        assert_eq!(recorded.len(), 1);
        assert_eq!(
            recorded[0].producer_action_key,
            digest_key(&digest("rabs.action-key.sha256.v1", 101))
        );
        assert_eq!(recorded[0].object_key, digest_key(&object(111).0));
        assert!(!recorded[0].adopted);
    }

    #[test]
    fn h028_transitive_hole_refuses_where_direct_only_would_commit() {
        // B is committed, but B's recorded lineage names producer 102
        // which never committed: C's direct check on B alone would pass
        // — the transitive walk must refuse (I32).
        let engine = RusqliteEngine::open_in_memory().unwrap();
        let mut store = SqlMetadataStore::open(engine).unwrap();
        ready_store(&mut store);
        let mut manifests = std::collections::BTreeMap::new();
        plant_producer(
            &mut store,
            &mut manifests,
            101,
            121,
            "out/b.rmeta",
            111,
            801,
            vec![ProvisionalAncestorRow {
                producer_action_key: digest_key(&digest("rabs.action-key.sha256.v1", 102)),
                role: "provisional-metadata".to_owned(),
                virtual_path: b"out/x.rmeta".to_vec(),
                object_key: digest_key(&object(112).0),
                adopted: false,
            }],
        );
        let resolver = move |key: &str| manifests.get(key).cloned();
        let c_offer = offer_with_ancestors(vec![ancestor_ref(101, "out/b.rmeta", 111)]);
        assert_eq!(
            process_offer(
                &mut store,
                &c_offer,
                &expected_descriptor(),
                resolver,
                900,
                1,
                CommitDurabilityProfile::RequireDurableClosure,
            ),
            Err(OfferRefusal::ProvisionalProducerNotCommitted {
                producer: digest_key(&digest("rabs.action-key.sha256.v1", 102)),
            })
        );
        // Nothing committed for C.
        assert!(
            !store
                .has_publication(&digest("rabs.action-key.sha256.v1", 7))
                .unwrap()
        );
    }

    #[test]
    fn h028_divergent_consumed_object_refuses_until_adoption_edge() {
        // C consumed object 119 from B's losing attempt, but B's winning
        // attempt committed object 111 at the same logical output: typed
        // refusal (R64) — until the coordinator records the explicit
        // adoption edge 119 -> 111, after which the re-offer commits
        // with adopted=true lineage.
        let engine = RusqliteEngine::open_in_memory().unwrap();
        let mut store = SqlMetadataStore::open(engine).unwrap();
        ready_store(&mut store);
        let mut manifests = std::collections::BTreeMap::new();
        plant_producer(
            &mut store,
            &mut manifests,
            101,
            121,
            "out/b.rmeta",
            111,
            801,
            vec![],
        );
        let resolver = {
            let manifests = manifests.clone();
            move |key: &str| manifests.get(key).cloned()
        };
        let b_key = digest_key(&digest("rabs.action-key.sha256.v1", 101));
        let c_offer = offer_with_ancestors(vec![ancestor_ref(101, "out/b.rmeta", 119)]);
        assert_eq!(
            process_offer(
                &mut store,
                &c_offer,
                &expected_descriptor(),
                resolver.clone(),
                900,
                1,
                CommitDurabilityProfile::RequireDurableClosure,
            ),
            Err(OfferRefusal::DivergentProvisionalAncestor {
                producer: b_key.clone(),
                path: "out/b.rmeta".to_owned(),
            })
        );

        // Authority-gated adoption edge; conflicting rewrite refused.
        let auth = authority_digest(&coordinator_authority());
        store
            .record_adoption_edge(
                &auth,
                &b_key,
                "provisional-metadata",
                b"out/b.rmeta",
                &digest_key(&object(119).0),
                &digest_key(&object(111).0),
            )
            .unwrap();
        assert_eq!(
            store.record_adoption_edge(
                &auth,
                &b_key,
                "provisional-metadata",
                b"out/b.rmeta",
                &digest_key(&object(119).0),
                &digest_key(&object(112).0),
            ),
            Err(StoreError::AdoptionEdgeConflict)
        );

        assert!(matches!(
            process_offer(
                &mut store,
                &c_offer,
                &expected_descriptor(),
                resolver,
                900,
                1,
                CommitDurabilityProfile::RequireDurableClosure,
            )
            .unwrap(),
            PublicationOutcome::Committed(_)
        ));
        let c_key = digest_key(&digest("rabs.action-key.sha256.v1", 7));
        let recorded = store.list_provisional_ancestors(&c_key).unwrap();
        assert_eq!(recorded.len(), 1);
        assert!(
            recorded[0].adopted,
            "adoption edge must be recorded as such"
        );
    }

    #[test]
    fn h028_canonical_ancestor_set_refuses_duplicates_and_self() {
        let manifest_id = object(50);
        assert_eq!(
            OfferPreparedActionResult::build(
                attempt_authority(),
                manifest(),
                manifest_id.clone(),
                evidence(&manifest_id),
                object(51),
                digest("rabs.observation-stream.sha256.v1", 9),
                &declared(),
                vec![
                    ancestor_ref(101, "out/b.rmeta", 111),
                    ancestor_ref(101, "out/b.rmeta", 119),
                ],
            ),
            Err(OfferBuildError::DuplicateAncestorRef {
                path: "out/b.rmeta".to_owned()
            })
        );
        assert_eq!(
            OfferPreparedActionResult::build(
                attempt_authority(),
                manifest(),
                manifest_id.clone(),
                evidence(&manifest_id),
                object(51),
                digest("rabs.observation-stream.sha256.v1", 9),
                &declared(),
                vec![ancestor_ref(7, "out/self.rmeta", 111)],
            ),
            Err(OfferBuildError::SelfAncestorRef)
        );
        // The canonical set is SORTED regardless of input order.
        let shuffled = OfferPreparedActionResult::build(
            attempt_authority(),
            manifest(),
            manifest_id.clone(),
            evidence(&manifest_id),
            object(51),
            digest("rabs.observation-stream.sha256.v1", 9),
            &declared(),
            vec![
                ancestor_ref(102, "out/x.rmeta", 112),
                ancestor_ref(101, "out/b.rmeta", 111),
            ],
        )
        .unwrap();
        let ordered = OfferPreparedActionResult::build(
            attempt_authority(),
            manifest(),
            manifest_id.clone(),
            evidence(&manifest_id),
            object(51),
            digest("rabs.observation-stream.sha256.v1", 9),
            &declared(),
            vec![
                ancestor_ref(101, "out/b.rmeta", 111),
                ancestor_ref(102, "out/x.rmeta", 112),
            ],
        )
        .unwrap();
        assert_eq!(shuffled, ordered, "ancestor order never changes identity");
    }

    #[test]
    fn h032_commit_ack_gates_on_the_configured_durability_profile() {
        // A located-but-volatile closure object refuses the commit under
        // the authoritative profile with a typed refusal naming it.
        let engine = RusqliteEngine::open_in_memory().unwrap();
        let mut store = SqlMetadataStore::open(engine).unwrap();
        ready_store(&mut store);
        store
            .add_location(&object(61).0, "/cas/61", Some(1), "raw", false)
            .unwrap();
        assert_eq!(
            process_offer(
                &mut store,
                &offer(),
                &expected_descriptor(),
                no_committed,
                900,
                1,
                CommitDurabilityProfile::RequireDurableClosure,
            ),
            Err(OfferRefusal::ObjectNotDurable {
                missing: digest_key(&object(61).0),
            })
        );
        // The refusal wrote nothing: no publication, no ack.
        let action = digest("rabs.action-key.sha256.v1", 7);
        assert!(!store.has_publication(&action).unwrap());

        // POWER-FAIL SIMULATION over the refused state: the volatile
        // copy is lost (quarantined as suspect on reopen). There is no
        // committed pointer to the lost object — the gate held.
        store
            .set_location_quarantined(&object(61).0, "/cas/61", true)
            .unwrap();
        assert!(!store.has_publication(&action).unwrap());

        // An explicitly volatile deployment admits the same offer — the
        // relaxation is NAMED, never the silent default.
        let engine = RusqliteEngine::open_in_memory().unwrap();
        let mut volatile_store = SqlMetadataStore::open(engine).unwrap();
        ready_store(&mut volatile_store);
        volatile_store
            .add_location(&object(61).0, "/cas/61", Some(1), "raw", false)
            .unwrap();
        assert!(matches!(
            process_offer(
                &mut volatile_store,
                &offer(),
                &expected_descriptor(),
                no_committed,
                900,
                1,
                CommitDurabilityProfile::AcceptVolatileLocations,
            )
            .unwrap(),
            PublicationOutcome::Committed(_)
        ));

        // Durable closure commits under the authoritative profile, and a
        // power failure afterward cannot orphan the pointer: every
        // closure object still has a durable location.
        let engine = RusqliteEngine::open_in_memory().unwrap();
        let mut durable_store = SqlMetadataStore::open(engine).unwrap();
        ready_store(&mut durable_store);
        assert!(matches!(
            process_offer(
                &mut durable_store,
                &offer(),
                &expected_descriptor(),
                no_committed,
                900,
                1,
                CommitDurabilityProfile::RequireDurableClosure,
            )
            .unwrap(),
            PublicationOutcome::Committed(_)
        ));
        assert!(durable_store.has_publication(&action).unwrap());
        for tag in [40, 41, 50, 51, 60, 61, 62, 63] {
            assert!(
                durable_store
                    .object_durably_located(&object(tag).0)
                    .unwrap(),
                "committed closure object {tag} must be durable"
            );
        }
    }

    #[test]
    fn h011_worker_build_validates_and_stamps_projection_digests() {
        let built = offer();
        // The stamped digests ARE the recomputable projections.
        assert_eq!(
            built.manifest.semantic_result_digest,
            semantic_result_digest_v1(&built.manifest)
        );
        assert_eq!(
            built.manifest.observable_result_digest,
            observable_result_digest_v1(&built.manifest, &built.canonical_observations)
        );

        // Undeclared output refused.
        let manifest_id = object(50);
        assert_eq!(
            OfferPreparedActionResult::build(
                attempt_authority(),
                manifest(),
                manifest_id.clone(),
                evidence(&manifest_id),
                object(51),
                digest("rabs.observation-stream.sha256.v1", 9),
                &[],
                Vec::new(),
            ),
            Err(OfferBuildError::UndeclaredOutput {
                path: "out/lib.rlib".to_owned()
            })
        );

        // Evidence bound to a different manifest refused.
        assert_eq!(
            OfferPreparedActionResult::build(
                attempt_authority(),
                manifest(),
                manifest_id,
                evidence(&object(99)),
                object(51),
                digest("rabs.observation-stream.sha256.v1", 9),
                &declared(),
                Vec::new(),
            ),
            Err(OfferBuildError::EvidenceManifestMismatch)
        );

        // Structurally invalid manifest refused (deterministic failure
        // with outputs).
        let mut bad = manifest();
        bad.result_kind = ResultKind::DeterministicFailure;
        let manifest_id = object(50);
        assert!(matches!(
            OfferPreparedActionResult::build(
                attempt_authority(),
                bad,
                manifest_id.clone(),
                evidence(&manifest_id),
                object(51),
                digest("rabs.observation-stream.sha256.v1", 9),
                &declared(),
                Vec::new(),
            ),
            Err(OfferBuildError::ManifestInvalid(_))
        ));
    }

    #[test]
    fn h011_commit_writes_publication_evidence_and_pin_atomically() {
        let engine = RusqliteEngine::open_in_memory().unwrap();
        let mut store = SqlMetadataStore::open(engine).unwrap();
        ready_store(&mut store);
        let outcome = process_offer(
            &mut store,
            &offer(),
            &expected_descriptor(),
            no_committed,
            900,
            42,
            CommitDurabilityProfile::RequireDurableClosure,
        )
        .unwrap();
        let PublicationOutcome::Committed(receipt) = outcome else {
            panic!("expected commit, got {outcome:?}");
        };
        assert_eq!(receipt.committed_causal_sequence, 42);
        assert_eq!(receipt.canonical_result_manifest_id, object(50));
        assert_eq!(receipt.winner_evidence_bundle_id, object(51));
        assert!(
            store
                .has_publication(&digest("rabs.action-key.sha256.v1", 7))
                .unwrap()
        );
        let snapshot = store.differential_snapshot().unwrap();
        // Publication pin + evidence row landed with the commit.
        assert!(snapshot.iter().any(|l| l.starts_with("pins|")
            && l.contains("action-publication")
            && l.contains("coordinator")));
        assert!(
            snapshot
                .iter()
                .any(|l| l.starts_with("action_evidence_index|"))
        );
    }

    #[test]
    fn h011_fence_refusals_write_nothing() {
        let engine = RusqliteEngine::open_in_memory().unwrap();
        let mut store = SqlMetadataStore::open(engine).unwrap();

        // No active authority at all.
        assert_eq!(
            process_offer(
                &mut store,
                &offer(),
                &expected_descriptor(),
                no_committed,
                900,
                1,
                CommitDurabilityProfile::RequireDurableClosure,
            ),
            Err(OfferRefusal::NotActiveAuthority)
        );

        ready_store(&mut store);

        // F033: generation bound to a DIFFERENT authority digest.
        let mut tampered = offer();
        tampered
            .authority
            .action_generation
            .created_under_authority_digest = digest(AUTHORITY_DIGEST_DOMAIN, 99);
        assert_eq!(
            process_offer(
                &mut store,
                &tampered,
                &expected_descriptor(),
                no_committed,
                900,
                1,
                CommitDurabilityProfile::RequireDurableClosure,
            ),
            Err(OfferRefusal::GenerationAuthorityMismatch)
        );

        // Unknown generation.
        let mut tampered = offer();
        tampered.authority.action_generation.generation_id = ActionGenerationId(999);
        assert_eq!(
            process_offer(
                &mut store,
                &tampered,
                &expected_descriptor(),
                no_committed,
                900,
                1,
                CommitDurabilityProfile::RequireDurableClosure,
            ),
            Err(OfferRefusal::UnknownGeneration)
        );

        // Unknown attempt.
        let mut tampered = offer();
        tampered.authority.attempt_id = AttemptId(999);
        assert_eq!(
            process_offer(
                &mut store,
                &tampered,
                &expected_descriptor(),
                no_committed,
                900,
                1,
                CommitDurabilityProfile::RequireDurableClosure,
            ),
            Err(OfferRefusal::UnknownAttempt)
        );

        // Released lease.
        store.release_lease(30).unwrap();
        assert_eq!(
            process_offer(
                &mut store,
                &offer(),
                &expected_descriptor(),
                no_committed,
                900,
                1,
                CommitDurabilityProfile::RequireDurableClosure,
            ),
            Err(OfferRefusal::LeaseReleased)
        );
        // Nothing was published by any refusal.
        assert!(
            !store
                .has_publication(&digest("rabs.action-key.sha256.v1", 7))
                .unwrap()
        );
    }

    #[test]
    fn h011_tombstoned_generation_refused() {
        let engine = RusqliteEngine::open_in_memory().unwrap();
        let mut store = SqlMetadataStore::open(engine).unwrap();
        ready_store(&mut store);
        store.tombstone_generation(11).unwrap();
        assert_eq!(
            process_offer(
                &mut store,
                &offer(),
                &expected_descriptor(),
                no_committed,
                900,
                1,
                CommitDurabilityProfile::RequireDurableClosure,
            ),
            Err(OfferRefusal::GenerationTombstoned)
        );
    }

    #[test]
    fn h011_content_validation_refusals() {
        let engine = RusqliteEngine::open_in_memory().unwrap();
        let mut store = SqlMetadataStore::open(engine).unwrap();
        ready_store(&mut store);

        // Descriptor byte-compare.
        assert_eq!(
            process_offer(
                &mut store,
                &offer(),
                &digest("rabs.descriptor.sha256.v1", 99),
                no_committed,
                900,
                1,
                CommitDurabilityProfile::RequireDurableClosure,
            ),
            Err(OfferRefusal::DescriptorMismatch)
        );

        // Epoch mismatch against the action entry.
        let mut tampered = offer();
        tampered.manifest.key_epoch = 2;
        tampered.manifest.semantic_result_digest = semantic_result_digest_v1(&tampered.manifest);
        tampered.manifest.observable_result_digest =
            observable_result_digest_v1(&tampered.manifest, &tampered.canonical_observations);
        assert_eq!(
            process_offer(
                &mut store,
                &tampered,
                &expected_descriptor(),
                no_committed,
                900,
                1,
                CommitDurabilityProfile::RequireDurableClosure,
            ),
            Err(OfferRefusal::EpochMismatch)
        );

        // Declared semantic digest disagrees with independent recompute.
        let mut tampered = offer();
        tampered.manifest.semantic_result_digest = digest(SEMANTIC_PROJECTION_DOMAIN, 99);
        assert_eq!(
            process_offer(
                &mut store,
                &tampered,
                &expected_descriptor(),
                no_committed,
                900,
                1,
                CommitDurabilityProfile::RequireDurableClosure,
            ),
            Err(OfferRefusal::SemanticDigestMismatch)
        );

        // Declared observable digest disagrees.
        let mut tampered = offer();
        tampered.manifest.observable_result_digest = digest(OBSERVABLE_PROJECTION_DOMAIN, 99);
        assert_eq!(
            process_offer(
                &mut store,
                &tampered,
                &expected_descriptor(),
                no_committed,
                900,
                1,
                CommitDurabilityProfile::RequireDurableClosure,
            ),
            Err(OfferRefusal::ObservableDigestMismatch)
        );
    }

    #[test]
    fn h011_incomplete_object_closure_refused() {
        let engine = RusqliteEngine::open_in_memory().unwrap();
        let mut store = SqlMetadataStore::open(engine).unwrap();
        ready_store(&mut store);
        // Take one evidence constituent's location away by using an offer
        // referencing an object that was never located.
        let manifest_id = object(50);
        let mut tampered_evidence = evidence(&manifest_id);
        tampered_evidence.provenance_receipt = object(200);
        let tampered = OfferPreparedActionResult::build(
            attempt_authority(),
            manifest(),
            manifest_id,
            tampered_evidence,
            object(51),
            digest("rabs.observation-stream.sha256.v1", 9),
            &declared(),
            Vec::new(),
        )
        .unwrap();
        assert_eq!(
            process_offer(
                &mut store,
                &tampered,
                &expected_descriptor(),
                no_committed,
                900,
                1,
                CommitDurabilityProfile::RequireDurableClosure,
            ),
            Err(OfferRefusal::IncompleteObjectClosure {
                missing: digest_key(&object(200).0)
            })
        );
    }

    #[test]
    fn h011_repeat_offer_is_idempotent_and_divergence_quarantines() {
        let engine = RusqliteEngine::open_in_memory().unwrap();
        let mut store = SqlMetadataStore::open(engine).unwrap();
        ready_store(&mut store);
        let first = offer();
        assert!(matches!(
            process_offer(
                &mut store,
                &first,
                &expected_descriptor(),
                no_committed,
                900,
                1,
                CommitDurabilityProfile::RequireDurableClosure,
            )
            .unwrap(),
            PublicationOutcome::Committed(_)
        ));

        // Identical re-offer: evidence appended, still exactly one
        // publication, no quarantine.
        assert_eq!(
            process_offer(
                &mut store,
                &first,
                &expected_descriptor(),
                no_committed,
                901,
                2,
                CommitDurabilityProfile::RequireDurableClosure,
            )
            .unwrap(),
            PublicationOutcome::IdempotentEvidenceAppended
        );

        // A different manifest object for the same key with a different
        // semantic digest: determinism incident, action quarantined, the
        // committed row preserved.
        let mut divergent_manifest = manifest();
        divergent_manifest.logical_outputs[0].object = object(42);
        let divergent_id = object(52);
        store.record_object(&object(42).0, 64).unwrap();
        store
            .add_location(&object(42).0, "/cas/42", Some(1), "raw", true)
            .unwrap();
        store.record_object(&divergent_id.0, 64).unwrap();
        store
            .add_location(&divergent_id.0, "/cas/52", Some(1), "raw", true)
            .unwrap();
        let divergent = OfferPreparedActionResult::build(
            attempt_authority(),
            divergent_manifest,
            divergent_id.clone(),
            evidence(&divergent_id),
            object(51),
            digest("rabs.observation-stream.sha256.v1", 9),
            &declared(),
            Vec::new(),
        )
        .unwrap();
        let committed = first.manifest.clone();
        let outcome = process_offer(
            &mut store,
            &divergent,
            &expected_descriptor(),
            move |_| Some(committed.clone()),
            902,
            3,
            CommitDurabilityProfile::RequireDurableClosure,
        )
        .unwrap();
        let PublicationOutcome::Quarantined(quarantine) = outcome else {
            panic!("expected quarantine, got {outcome:?}");
        };
        assert_eq!(quarantine.class, DivergenceClass::SemanticDivergence);
        assert_eq!(quarantine.incident_seq, 3);
        assert_eq!(quarantine.candidate_pin_id, 902);
        // Committed manifest pointer unchanged.
        assert_eq!(
            store
                .published_manifest_key(&digest("rabs.action-key.sha256.v1", 7))
                .unwrap()
                .unwrap(),
            digest_key(&object(50).0)
        );
    }

    /// A second offer for the same key whose manifest object differs.
    /// `output_tag`/`manifest_tag`/`evidence_tag` pick the divergent
    /// output object, manifest id, and evidence id; `observations` picks
    /// the observation stream.
    fn divergent_offer(
        store: &mut dyn RabsMetadataStore,
        output_tag: Option<u8>,
        manifest_tag: u8,
        evidence_tag: u8,
        observations: TypedDigest,
    ) -> OfferPreparedActionResult {
        let mut m = manifest();
        if let Some(tag) = output_tag {
            m.logical_outputs[0].object = object(tag);
        }
        let id = object(manifest_tag);
        for tag in output_tag
            .iter()
            .copied()
            .chain([manifest_tag, evidence_tag])
        {
            store.record_object(&object(tag).0, 64).unwrap();
            store
                .add_location(&object(tag).0, &format!("/cas/{tag}"), Some(1), "raw", true)
                .unwrap();
        }
        OfferPreparedActionResult::build(
            attempt_authority(),
            m,
            id.clone(),
            evidence(&id),
            object(evidence_tag),
            observations,
            &declared(),
            Vec::new(),
        )
        .unwrap()
    }

    #[test]
    fn h026_semantic_divergence_quarantines_preserves_and_escalates() {
        let mut store = SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap();
        ready_store(&mut store);
        let action = digest("rabs.action-key.sha256.v1", 7);
        let action_key = digest_key(&action);
        let auth = authority_digest(&coordinator_authority());

        let first = offer();
        assert!(matches!(
            process_offer(
                &mut store,
                &first,
                &expected_descriptor(),
                no_committed,
                900,
                1,
                CommitDurabilityProfile::RequireDurableClosure,
            )
            .unwrap(),
            PublicationOutcome::Committed(_)
        ));

        // Two consumers were served this result under a RELEASE tier.
        store
            .record_served_consumer(&action_key, "consumer-b")
            .unwrap();
        store
            .record_served_consumer(&action_key, "consumer-a")
            .unwrap();
        store
            .append_trust_evaluation(
                &auth,
                &action,
                &crate::metadata_store::TrustEvaluationRow {
                    version: 1,
                    state: "project-release-eligible".to_owned(),
                    reason: "release gate".to_owned(),
                    evaluated_seq: 2,
                },
            )
            .unwrap();

        // Semantic divergence: different output object under the same key.
        let divergent = divergent_offer(
            &mut store,
            Some(42),
            52,
            55,
            digest("rabs.observation-stream.sha256.v1", 9),
        );
        let committed = first.manifest.clone();
        let outcome = process_offer(
            &mut store,
            &divergent,
            &expected_descriptor(),
            move |_| Some(committed.clone()),
            902,
            3,
            CommitDurabilityProfile::RequireDurableClosure,
        )
        .unwrap();
        let PublicationOutcome::Quarantined(quarantine) = outcome else {
            panic!("expected quarantine, got {outcome:?}");
        };
        assert_eq!(quarantine.class, DivergenceClass::SemanticDivergence);

        // Serving is DISABLED with the full quarantine disposition.
        assert_eq!(
            store.serving_disposition_key(&action_key).unwrap().unwrap(),
            DISPOSITION_QUARANTINED
        );

        // BOTH candidates preserved: the committed row is untouched...
        assert_eq!(
            store.published_manifest_key(&action).unwrap().unwrap(),
            digest_key(&object(50).0)
        );
        // ...and the losing candidate sits under a durable
        // divergence-evidence pin with reachability edges.
        let pin = store.pin_row(902).unwrap().unwrap();
        assert_eq!(pin.class, DIVERGENCE_EVIDENCE_PIN_CLASS);
        assert_eq!(pin.root_key, digest_key(&object(52).0));
        assert!(!pin.released);
        let snapshot = store.differential_snapshot().unwrap();
        assert!(
            snapshot
                .iter()
                .any(|l| l.starts_with("object_edges|") && l.contains("divergence-candidate"))
        );
        // The candidate's evidence bundle joined the append-only index.
        assert!(
            store
                .list_evidence_keys(&action)
                .unwrap()
                .contains(&digest_key(&object(55).0))
        );
        // H029/I37: the candidate's evidence is bound to the CANDIDATE
        // manifest — the committed canonical result's evidence view never
        // absorbs a divergent candidate's evidence.
        let candidate_view = store
            .list_evidence_keys_for_manifest(&digest_key(&object(52).0))
            .unwrap();
        assert!(candidate_view.contains(&digest_key(&object(55).0)));
        let committed_view = store
            .list_evidence_keys_for_manifest(&digest_key(&object(50).0))
            .unwrap();
        assert!(!committed_view.contains(&digest_key(&object(55).0)));

        // The incident row names class, both manifests, and the pin.
        let incidents = store.list_divergence_incidents(&action_key).unwrap();
        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0].seq, 3);
        assert_eq!(incidents[0].class, "semantic");
        assert_eq!(
            incidents[0].committed_manifest_key,
            digest_key(&object(50).0)
        );
        assert_eq!(
            incidents[0].candidate_manifest_key,
            digest_key(&object(52).0)
        );
        assert_eq!(incidents[0].candidate_pin_hex, format!("{:032x}", 902));

        // Previously served consumers escalated by RELEASE tier: recall.
        assert_eq!(
            quarantine.escalations,
            vec![
                ConsumerEscalation {
                    consumer: "consumer-a".to_owned(),
                    trust_state: "project-release-eligible".to_owned(),
                    decision: "recall-and-reverify".to_owned(),
                },
                ConsumerEscalation {
                    consumer: "consumer-b".to_owned(),
                    trust_state: "project-release-eligible".to_owned(),
                    decision: "recall-and-reverify".to_owned(),
                },
            ]
        );
        assert!(snapshot.iter().any(|l| {
            l.starts_with(
                "decision_receipts|divergence-escalation|consumer-a|3|recall-and-reverify",
            )
        }));
    }

    #[test]
    fn h026_observable_only_divergence_gets_presentation_quarantine() {
        let mut store = SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap();
        ready_store(&mut store);
        let action = digest("rabs.action-key.sha256.v1", 7);
        let action_key = digest_key(&action);

        let first = offer();
        assert!(matches!(
            process_offer(
                &mut store,
                &first,
                &expected_descriptor(),
                no_committed,
                900,
                1,
                CommitDurabilityProfile::RequireDurableClosure,
            )
            .unwrap(),
            PublicationOutcome::Committed(_)
        ));
        store
            .record_served_consumer(&action_key, "consumer-a")
            .unwrap();

        // Same semantic result, different observation stream, offered as
        // a different manifest object: observable-only divergence.
        let divergent = divergent_offer(
            &mut store,
            None,
            53,
            56,
            digest("rabs.observation-stream.sha256.v1", 10),
        );
        assert_eq!(
            divergent.manifest.semantic_result_digest,
            first.manifest.semantic_result_digest
        );
        let committed = first.manifest.clone();
        let outcome = process_offer(
            &mut store,
            &divergent,
            &expected_descriptor(),
            move |_| Some(committed.clone()),
            903,
            4,
            CommitDurabilityProfile::RequireDurableClosure,
        )
        .unwrap();
        let PublicationOutcome::Quarantined(quarantine) = outcome else {
            panic!("expected quarantine, got {outcome:?}");
        };
        assert_eq!(quarantine.class, DivergenceClass::ObservableOnlyDivergence);

        // The NARROWER disposition: ordinary replay disabled, tagged as
        // presentation-only.
        assert_eq!(
            store.serving_disposition_key(&action_key).unwrap().unwrap(),
            DISPOSITION_PRESENTATION_QUARANTINED
        );
        // Candidate still preserved; incident recorded with the narrower
        // class; NO consumer escalation for observable-only.
        assert!(store.pin_row(903).unwrap().is_some());
        let incidents = store.list_divergence_incidents(&action_key).unwrap();
        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0].class, "observable-only");
        assert!(quarantine.escalations.is_empty());
        assert!(
            !store
                .differential_snapshot()
                .unwrap()
                .iter()
                .any(|l| l.starts_with("decision_receipts|divergence-escalation|"))
        );
    }

    #[test]
    fn h026_attempt_evidence_difference_appends_normally() {
        let mut store = SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap();
        ready_store(&mut store);
        let action = digest("rabs.action-key.sha256.v1", 7);
        let action_key = digest_key(&action);

        let first = offer();
        assert!(matches!(
            process_offer(
                &mut store,
                &first,
                &expected_descriptor(),
                no_committed,
                900,
                1,
                CommitDurabilityProfile::RequireDurableClosure,
            )
            .unwrap(),
            PublicationOutcome::Committed(_)
        ));

        // Same manifest, DIFFERENT evidence bundle: the third H026 class
        // — attempt-evidence variation appends normally, no quarantine,
        // no incident, serving untouched.
        let manifest_id = object(50);
        let mut other_evidence = evidence(&manifest_id);
        other_evidence.provenance_receipt = object(64);
        store.record_object(&object(64).0, 64).unwrap();
        store
            .add_location(&object(64).0, "/cas/64", Some(1), "raw", true)
            .unwrap();
        let reoffer = OfferPreparedActionResult::build(
            attempt_authority(),
            manifest(),
            manifest_id,
            other_evidence,
            object(54),
            digest("rabs.observation-stream.sha256.v1", 9),
            &declared(),
            Vec::new(),
        )
        .unwrap();
        store.record_object(&object(54).0, 64).unwrap();
        store
            .add_location(&object(54).0, "/cas/54", Some(1), "raw", true)
            .unwrap();
        assert_eq!(
            process_offer(
                &mut store,
                &reoffer,
                &expected_descriptor(),
                no_committed,
                904,
                5,
                CommitDurabilityProfile::RequireDurableClosure,
            )
            .unwrap(),
            PublicationOutcome::IdempotentEvidenceAppended
        );
        let evidence_keys = store.list_evidence_keys(&action).unwrap();
        assert!(evidence_keys.contains(&digest_key(&object(51).0)));
        assert!(evidence_keys.contains(&digest_key(&object(54).0)));
        // H029: both equivalent attempts' evidence bundles bind to the ONE
        // committed canonical manifest, and the per-manifest view shows
        // the appended set.
        let manifest_view = store
            .list_evidence_keys_for_manifest(&digest_key(&object(50).0))
            .unwrap();
        assert!(manifest_view.contains(&digest_key(&object(51).0)));
        assert!(manifest_view.contains(&digest_key(&object(54).0)));
        assert_eq!(
            store.serving_disposition_key(&action_key).unwrap().unwrap(),
            "servable"
        );
        assert!(
            store
                .list_divergence_incidents(&action_key)
                .unwrap()
                .is_empty()
        );
        assert!(
            !store
                .differential_snapshot()
                .unwrap()
                .iter()
                .any(|l| l.starts_with("quarantines|"))
        );
    }

    #[test]
    fn h026_incident_rows_are_append_only_and_authority_gated() {
        let mut store = SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap();
        let auth = authority_digest(&coordinator_authority());
        let row = DivergenceIncidentRow {
            action_key: "k".to_owned(),
            seq: 1,
            class: "semantic".to_owned(),
            committed_manifest_key: "m1".to_owned(),
            candidate_manifest_key: "m2".to_owned(),
            candidate_evidence_key: "e2".to_owned(),
            candidate_pin_hex: format!("{:032x}", 7),
            generation_hex: format!("{:032x}", 11),
            attempt_hex: format!("{:032x}", 20),
            detail: "detail".to_owned(),
        };
        // No active authority: refused, nothing written.
        assert_eq!(
            store.record_divergence_incident(&auth, &row),
            Err(StoreError::NotActiveAuthority)
        );
        ready_store(&mut store);
        store.record_divergence_incident(&auth, &row).unwrap();
        // Identical re-record: idempotent.
        store.record_divergence_incident(&auth, &row).unwrap();
        // Conflicting rewrite: typed refusal; the stored row survives.
        let mut tampered = row.clone();
        tampered.detail = "rewritten".to_owned();
        assert_eq!(
            store.record_divergence_incident(&auth, &tampered),
            Err(StoreError::AppendConflict("divergence_incidents".into()))
        );
        let incidents = store.list_divergence_incidents("k").unwrap();
        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0], row);
    }

    #[test]
    fn h026_differential_reference_vs_frankensqlite() {
        // Semantic divergence with escalation AND observable-only
        // divergence must leave both engines byte-identical.
        fn scenario(store: &mut dyn RabsMetadataStore) -> Vec<String> {
            ready_store(store);
            let action = digest("rabs.action-key.sha256.v1", 7);
            let action_key = digest_key(&action);
            let first = offer();
            assert!(matches!(
                process_offer(
                    store,
                    &first,
                    &expected_descriptor(),
                    no_committed,
                    900,
                    1,
                    CommitDurabilityProfile::RequireDurableClosure,
                )
                .unwrap(),
                PublicationOutcome::Committed(_)
            ));
            store
                .record_served_consumer(&action_key, "consumer-a")
                .unwrap();
            let divergent = divergent_offer(
                store,
                Some(42),
                52,
                55,
                digest("rabs.observation-stream.sha256.v1", 9),
            );
            let committed = first.manifest.clone();
            let outcome = process_offer(
                store,
                &divergent,
                &expected_descriptor(),
                move |_| Some(committed.clone()),
                902,
                3,
                CommitDurabilityProfile::RequireDurableClosure,
            )
            .unwrap();
            assert!(matches!(outcome, PublicationOutcome::Quarantined(_)));
            store.differential_snapshot().unwrap()
        }
        let mut reference =
            SqlMetadataStore::open(RusqliteEngine::open(&fresh_path("ref26")).unwrap()).unwrap();
        let mut candidate =
            SqlMetadataStore::open(FsqliteEngine::open(&fresh_path("fsq26")).unwrap()).unwrap();
        assert_eq!(scenario(&mut reference), scenario(&mut candidate));
    }

    #[test]
    fn h011_differential_full_pipeline_reference_vs_frankensqlite() {
        // The entire H011 scenario (commit, idempotent re-offer,
        // divergence quarantine, plus every refusal fence) must leave the
        // reference and FrankenSQLite stores byte-identical.
        fn scenario(store: &mut dyn RabsMetadataStore) -> Vec<String> {
            ready_store(store);
            let first = offer();
            assert!(matches!(
                process_offer(
                    store,
                    &first,
                    &expected_descriptor(),
                    no_committed,
                    900,
                    1,
                    CommitDurabilityProfile::RequireDurableClosure,
                )
                .unwrap(),
                PublicationOutcome::Committed(_)
            ));
            assert_eq!(
                process_offer(
                    store,
                    &first,
                    &expected_descriptor(),
                    no_committed,
                    901,
                    2,
                    CommitDurabilityProfile::RequireDurableClosure,
                )
                .unwrap(),
                PublicationOutcome::IdempotentEvidenceAppended
            );
            assert_eq!(
                process_offer(
                    store,
                    &first,
                    &digest("rabs.descriptor.sha256.v1", 99),
                    no_committed,
                    902,
                    3,
                    CommitDurabilityProfile::RequireDurableClosure,
                ),
                Err(OfferRefusal::DescriptorMismatch)
            );
            store.differential_snapshot().unwrap()
        }
        let mut reference =
            SqlMetadataStore::open(RusqliteEngine::open(&fresh_path("ref")).unwrap()).unwrap();
        let mut candidate =
            SqlMetadataStore::open(FsqliteEngine::open(&fresh_path("fsq")).unwrap()).unwrap();
        assert_eq!(scenario(&mut reference), scenario(&mut candidate));
    }

    #[test]
    fn h034_evict_then_recompute_divergence_is_detected() {
        let mut store = SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap();
        ready_store(&mut store);
        let first = offer();
        assert!(matches!(
            process_offer(
                &mut store,
                &first,
                &expected_descriptor(),
                no_committed,
                900,
                1,
                CommitDurabilityProfile::RequireDurableClosure,
            )
            .unwrap(),
            PublicationOutcome::Committed(_)
        ));

        // Blobs get evicted; the digests are RETAINED first.
        retain_eviction_tombstone(&mut store, &first.manifest, 50).unwrap();
        for tag in [40u8, 41, 50] {
            store
                .remove_location_by_key(&digest_key(&object(tag).0), &format!("/cas/{tag}"))
                .unwrap();
        }

        let action = digest("rabs.action-key.sha256.v1", 7);
        // Re-execution produces a DIFFERENT semantic result: divergence
        // incident, quarantined, tombstone preserved as evidence.
        let outcome = check_recomputation_against_tombstone(
            &mut store,
            &action,
            &digest(SEMANTIC_PROJECTION_DOMAIN, 99),
            &first.manifest.observable_result_digest,
        )
        .unwrap();
        assert_eq!(
            outcome,
            RecomputationCheck::Divergence(DivergenceClass::SemanticDivergence)
        );
        assert!(
            store
                .differential_snapshot()
                .unwrap()
                .iter()
                .any(|l| l.starts_with("quarantines|")
                    && l.contains("post-eviction recomputation divergence"))
        );
        assert!(
            store.eviction_tombstone(&action).unwrap().is_some(),
            "divergence keeps the tombstone as incident evidence"
        );

        // Same semantic, different observable: the narrower class.
        assert_eq!(
            check_recomputation_against_tombstone(
                &mut store,
                &action,
                &first.manifest.semantic_result_digest,
                &digest(OBSERVABLE_PROJECTION_DOMAIN, 99),
            )
            .unwrap(),
            RecomputationCheck::Divergence(DivergenceClass::ObservableOnlyDivergence)
        );

        // A faithful reproduction matches and CONSUMES the tombstone.
        assert_eq!(
            check_recomputation_against_tombstone(
                &mut store,
                &action,
                &first.manifest.semantic_result_digest,
                &first.manifest.observable_result_digest,
            )
            .unwrap(),
            RecomputationCheck::Reproduced
        );
        assert!(store.eviction_tombstone(&action).unwrap().is_none());
        assert_eq!(
            check_recomputation_against_tombstone(
                &mut store,
                &action,
                &first.manifest.semantic_result_digest,
                &first.manifest.observable_result_digest,
            )
            .unwrap(),
            RecomputationCheck::NoTombstone
        );
    }

    #[test]
    fn h034_differential_reference_vs_frankensqlite() {
        fn scenario(store: &mut dyn RabsMetadataStore) -> Vec<String> {
            ready_store(store);
            let first = offer();
            assert!(matches!(
                process_offer(
                    store,
                    &first,
                    &expected_descriptor(),
                    no_committed,
                    900,
                    1,
                    CommitDurabilityProfile::RequireDurableClosure,
                )
                .unwrap(),
                PublicationOutcome::Committed(_)
            ));
            retain_eviction_tombstone(store, &first.manifest, 50).unwrap();
            let action = digest("rabs.action-key.sha256.v1", 7);
            assert_eq!(
                check_recomputation_against_tombstone(
                    store,
                    &action,
                    &digest(SEMANTIC_PROJECTION_DOMAIN, 99),
                    &first.manifest.observable_result_digest,
                )
                .unwrap(),
                RecomputationCheck::Divergence(DivergenceClass::SemanticDivergence)
            );
            store.differential_snapshot().unwrap()
        }
        let mut reference =
            SqlMetadataStore::open(RusqliteEngine::open(&fresh_path("ref34")).unwrap()).unwrap();
        let mut candidate =
            SqlMetadataStore::open(FsqliteEngine::open(&fresh_path("fsq34")).unwrap()).unwrap();
        assert_eq!(scenario(&mut reference), scenario(&mut candidate));
    }
}
