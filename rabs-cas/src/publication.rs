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
    CommitOutcome, DivergenceIncidentRow, PublicationRow, QuarantineScope, RabsMetadataStore,
    ResultKindTag, StoreError, digest_key,
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
    pub fn build(
        authority: AttemptAuthority,
        mut manifest: CanonicalActionResultManifest,
        manifest_id: ObjectId,
        evidence: AttemptEvidenceBundle,
        evidence_id: ObjectId,
        canonical_observations: TypedDigest,
        declared_outputs: &[(OutputRole, RawBytes)],
    ) -> Result<Self, OfferBuildError> {
        manifest
            .validate()
            .map_err(OfferBuildError::ManifestInvalid)?;
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
    /// The committed manifest for a same-key offer could not be loaded
    /// for divergence classification.
    CommittedManifestUnavailable,
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
/// allocated durable reachability pin; `seq` is the causal commit
/// sequence stamped into the receipt.
///
/// # Errors
/// A typed [`OfferRefusal`]; refusals write nothing.
pub fn process_offer(
    store: &mut dyn RabsMetadataStore,
    offer: &OfferPreparedActionResult,
    expected_descriptor: &TypedDigest,
    committed_manifest: impl FnOnce(&str) -> Option<CanonicalActionResultManifest>,
    pin_id: u128,
    seq: u64,
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
    }

    // 8. Same-key candidates: divergence taxonomy, never overwrite.
    if let Some(committed_key) = store.published_manifest_key(&offer.manifest.action_key)? {
        let candidate_key = digest_key(&offer.manifest_id.0);
        if committed_key == candidate_key {
            // Idempotent re-offer: append evidence only.
            store.append_evidence(
                &offer.manifest.action_key,
                &offer.evidence_id.0,
                generation_id,
                attempt_id,
            )?;
            return Ok(PublicationOutcome::IdempotentEvidenceAppended);
        }
        let committed =
            committed_manifest(&committed_key).ok_or(OfferRefusal::CommittedManifestUnavailable)?;
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
                .add_location(&id.0, &format!("/cas/{tag}"), Some(1), "raw")
                .unwrap();
        }
    }

    fn expected_descriptor() -> TypedDigest {
        digest("rabs.descriptor.sha256.v1", 8)
    }

    fn no_committed(_: &str) -> Option<CanonicalActionResultManifest> {
        None
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
                1
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
                1
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
                1
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
                1
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
                1
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
                1
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
                1
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
                1
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
                1
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
                1
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
        )
        .unwrap();
        assert_eq!(
            process_offer(
                &mut store,
                &tampered,
                &expected_descriptor(),
                no_committed,
                900,
                1
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
                1
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
                2
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
            .add_location(&object(42).0, "/cas/42", Some(1), "raw")
            .unwrap();
        store.record_object(&divergent_id.0, 64).unwrap();
        store
            .add_location(&divergent_id.0, "/cas/52", Some(1), "raw")
            .unwrap();
        let divergent = OfferPreparedActionResult::build(
            attempt_authority(),
            divergent_manifest,
            divergent_id.clone(),
            evidence(&divergent_id),
            object(51),
            digest("rabs.observation-stream.sha256.v1", 9),
            &declared(),
        )
        .unwrap();
        let committed = first.manifest.clone();
        let outcome = process_offer(
            &mut store,
            &divergent,
            &expected_descriptor(),
            move |_| Some(committed),
            902,
            3,
        )
        .unwrap();
        assert_eq!(
            outcome,
            PublicationOutcome::Quarantined(DivergenceClass::SemanticDivergence)
        );
        // Committed manifest pointer unchanged.
        assert_eq!(
            store
                .published_manifest_key(&digest("rabs.action-key.sha256.v1", 7))
                .unwrap()
                .unwrap(),
            digest_key(&object(50).0)
        );
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
                process_offer(store, &first, &expected_descriptor(), no_committed, 900, 1).unwrap(),
                PublicationOutcome::Committed(_)
            ));
            assert_eq!(
                process_offer(store, &first, &expected_descriptor(), no_committed, 901, 2).unwrap(),
                PublicationOutcome::IdempotentEvidenceAppended
            );
            assert_eq!(
                process_offer(
                    store,
                    &first,
                    &digest("rabs.descriptor.sha256.v1", 99),
                    no_committed,
                    902,
                    3
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
                1
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
                process_offer(store, &first, &expected_descriptor(), no_committed, 900, 1).unwrap(),
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
