//! Public offer / ready-store builders for DOWNSTREAM live commit tests
//! (bead bd-g900u). Gated behind the `test-support` feature so it never
//! ships in a normal build.
//!
//! `publication::process_offer` is the real atomic commit+pin+quarantine
//! engine, but constructing a valid [`OfferPreparedActionResult`] and the
//! "ready" store it commits into requires a deep stack of authority /
//! manifest / evidence / lease / object rows. Those builders existed only
//! as `#[cfg(test)]` privates inside `publication.rs`, so a live test in
//! `rabsd` could not drive a commit at all. This module exposes the same
//! construction over PUBLIC types, so the coordinator commit path can be
//! proven under the running daemon (bd-epyez) rather than only inside
//! rabs-cas's own tests.
//!
//! These are DETERMINISTIC synthetic fixtures (byte-`tag` digests), not
//! production values — they exist to exercise the commit machinery.

use rabs_protocol::authority::{ClusterId, CoordinatorAuthority, CoordinatorIncarnationId};
use rabs_protocol::generation::{
    ActionGeneration, ActionGenerationId, AttemptAuthority, AttemptId, ExecutionLeaseId,
    LeaseRenewalSeq, WorkerBootGeneration, WorkerIncarnationId,
};
use rabs_protocol::raw_bytes::RawBytes;
use rabs_protocol::result_identity::{
    AttemptEvidenceBundle, CanonicalActionResultManifest, DigestAlgorithm, LogicalOutput, ObjectId,
    OutputRole, ResultKind, TypedDigest,
};
use rabs_protocol::wire_time::PeerId;
use rabs_protocol::worker_fence::WorkerSessionOffer;

use crate::metadata_store::{ActionEntryRow, AuthorityRow, RabsMetadataStore};
use crate::publication::{
    OBSERVABLE_PROJECTION_DOMAIN, OfferPreparedActionResult, ProvisionalAncestorRef,
    SEMANTIC_PROJECTION_DOMAIN, authority_digest,
};

/// The action key every fixture shares.
const ACTION_KEY_DOMAIN: &str = "rabs.action-key.sha256.v1";

/// A deterministic digest: every byte is `tag`, under `domain`.
#[must_use]
pub fn tagged_digest(domain: &'static str, tag: u8) -> TypedDigest {
    TypedDigest {
        algorithm: DigestAlgorithm::Sha256V1,
        domain,
        bytes: [tag; 32],
    }
}

/// A deterministic object id (tagged content digest).
#[must_use]
pub fn tagged_object(tag: u8) -> ObjectId {
    ObjectId(tagged_digest("rabs.object.sha256.v1", tag))
}

/// The shared fixture action key.
#[must_use]
pub fn sample_action_key() -> TypedDigest {
    tagged_digest(ACTION_KEY_DOMAIN, 7)
}

/// The coordinator authority the ready store acquires.
#[must_use]
pub fn sample_coordinator_authority() -> CoordinatorAuthority {
    CoordinatorAuthority {
        cluster_id: ClusterId("cluster-a".to_owned()),
        credential_generation: 1,
        term: 3,
        incarnation_id: CoordinatorIncarnationId(77),
    }
}

/// The (generation, attempt, lease) triple naming one admission world.
/// Restart-reissue fixtures mint FRESH ids: store uniqueness makes the
/// sample triple single-use across incarnations (attempt ids are unique,
/// and generation ids must rise above the never-reuse high-water mark).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixtureAttemptIds {
    /// Generation id (strictly above the high-water mark when created).
    pub generation: u128,
    /// Attempt id (unique per store).
    pub attempt: u128,
    /// Execution lease id (unique per store).
    pub lease: u128,
}

/// The sample triple every single-world helper uses.
pub const SAMPLE_ATTEMPT_IDS: FixtureAttemptIds = FixtureAttemptIds {
    generation: 11,
    attempt: 20,
    lease: 30,
};

/// The full attempt authority carried by an offer.
#[must_use]
pub fn sample_attempt_authority() -> AttemptAuthority {
    attempt_authority_for(&sample_coordinator_authority())
}

/// The full attempt authority under a CALLER-SUPPLIED coordinator
/// authority — the live daemon acquires its own (fresh incarnation,
/// advanced term) at boot, so a live commit test cannot use the fixture
/// coordinator: `process_offer`'s first fence compares the offer's
/// authority digest against the store's ACTIVE row.
#[must_use]
pub fn attempt_authority_for(coordinator: &CoordinatorAuthority) -> AttemptAuthority {
    attempt_authority_with_ids(coordinator, SAMPLE_ATTEMPT_IDS)
}

/// [`attempt_authority_for`] bound to a caller-supplied identity triple —
/// the fresh-generation reissue path (G020): a restarted coordinator's
/// world needs ids the previous incarnation never used.
#[must_use]
fn attempt_authority_with_ids(
    coordinator: &CoordinatorAuthority,
    ids: FixtureAttemptIds,
) -> AttemptAuthority {
    let coordinator = coordinator.clone();
    let created_under = authority_digest(&coordinator);
    AttemptAuthority {
        coordinator,
        action_key: sample_action_key(),
        action_generation: ActionGeneration {
            generation_id: ActionGenerationId(ids.generation),
            per_key_ordinal: 1,
            created_under_authority_digest: created_under,
        },
        attempt_id: AttemptId(ids.attempt),
        execution_lease_id: ExecutionLeaseId(ids.lease),
        lease_renewal_seq: LeaseRenewalSeq(1),
        worker_peer_id: PeerId("worker-a".to_owned()),
        worker_boot_generation: WorkerBootGeneration(1),
        worker_incarnation_id: WorkerIncarnationId(5),
    }
}

/// A canonical result manifest (one materializable output). The two
/// projection digests are placeholders here; `build()` stamps them.
#[must_use]
pub fn sample_manifest() -> CanonicalActionResultManifest {
    manifest_with_output(41)
}

/// A canonical result manifest whose single materializable output is the
/// object tagged `output_tag`. Two manifests differing only in that tag
/// share an action key but carry different semantic result digests —
/// exactly the A018 `SemanticDivergence` shape.
#[must_use]
pub fn manifest_with_output(output_tag: u8) -> CanonicalActionResultManifest {
    manifest_with_output_object(&tagged_object(output_tag))
}

/// A manifest whose single materializable output is `object` — used
/// when that object must be a REAL blob (serving tests materialize its
/// bytes), not a synthetic tagged digest.
#[must_use]
pub fn manifest_with_output_object(object: &ObjectId) -> CanonicalActionResultManifest {
    let object = object.clone();
    CanonicalActionResultManifest {
        action_key: sample_action_key(),
        canonical_descriptor_digest: tagged_digest("rabs.descriptor.sha256.v1", 8),
        key_epoch: 1,
        projection_epoch: 1,
        result_kind: ResultKind::Success,
        artifact_bundle_root: Some(tagged_object(40)),
        logical_outputs: vec![LogicalOutput {
            role: OutputRole::Materializable,
            virtual_path: RawBytes::new(b"out/lib.rlib".to_vec()),
            object,
        }],
        semantic_result_digest: tagged_digest(SEMANTIC_PROJECTION_DOMAIN, 0),
        observable_result_digest: tagged_digest(OBSERVABLE_PROJECTION_DOMAIN, 0),
    }
}

/// The evidence bundle bound to a manifest object.
#[must_use]
pub fn sample_evidence(manifest_id: &ObjectId) -> AttemptEvidenceBundle {
    AttemptEvidenceBundle {
        action_key: sample_action_key(),
        canonical_result_manifest_id: manifest_id.clone(),
        execution_snapshot_root: tagged_object(60),
        observed_input_report: tagged_object(61),
        raw_process_and_event_evidence: tagged_object(62),
        provenance_receipt: tagged_object(63),
        incremental_snapshot: None,
    }
}

/// The declared outputs the manifest is validated against.
#[must_use]
pub fn sample_declared() -> Vec<(OutputRole, RawBytes)> {
    vec![(
        OutputRole::Materializable,
        RawBytes::new(b"out/lib.rlib".to_vec()),
    )]
}

/// The coordinator-reloaded descriptor `process_offer` byte-compares
/// against the manifest's `canonical_descriptor_digest`.
#[must_use]
pub fn sample_expected_descriptor() -> TypedDigest {
    tagged_digest("rabs.descriptor.sha256.v1", 8)
}

/// A valid, commit-ready offer (no provisional ancestors).
///
/// # Panics
/// If the fixture ever fails `OfferPreparedActionResult::build` validation
/// (it never should — the fixtures are internally consistent).
#[must_use]
pub fn sample_offer() -> OfferPreparedActionResult {
    sample_offer_with_ancestors(Vec::new())
}

/// A valid, commit-ready offer carrying the given provisional ancestors.
///
/// # Panics
/// If `build` rejects the (fixture, ancestors) combination.
#[must_use]
pub fn sample_offer_with_ancestors(
    ancestors: Vec<ProvisionalAncestorRef>,
) -> OfferPreparedActionResult {
    offer_for(&sample_coordinator_authority(), 41, 50, 51, ancestors)
}

/// The commit-ready offer under a caller-supplied coordinator authority
/// (the live-daemon counterpart of [`sample_offer`]).
///
/// # Panics
/// If `build` rejects the fixtures (it never should).
#[must_use]
pub fn offer_under(coordinator: &CoordinatorAuthority) -> OfferPreparedActionResult {
    offer_for(coordinator, 41, 50, 51, Vec::new())
}

/// A SECOND offer for the SAME action key under the same authority whose
/// materializable output is a different object: same key, different
/// result. `process_offer` must quarantine it as
/// `DivergenceClass::SemanticDivergence` and leave the committed row
/// untouched.
///
/// # Panics
/// If `build` rejects the fixtures (it never should).
#[must_use]
pub fn divergent_offer_under(coordinator: &CoordinatorAuthority) -> OfferPreparedActionResult {
    offer_for(coordinator, 42, 52, 53, Vec::new())
}

/// The commit-ready offer whose `manifest_id` is the REAL content id of
/// its canonical manifest bytes, together with those bytes — so a caller
/// can `put_if_absent` them into an actual blob store and prove the
/// coordinator can RELOAD the committed manifest from the CAS (bd-h8sp5)
/// instead of remembering it in process memory.
///
/// # Panics
/// If the fixture's own two-pass construction is inconsistent (the
/// re-stamped manifest must encode to the bytes its id was taken from).
#[must_use]
pub fn offer_with_manifest_bytes(
    coordinator: &CoordinatorAuthority,
) -> (OfferPreparedActionResult, Vec<u8>) {
    offer_with_bytes(coordinator, &tagged_object(41), 51)
}

/// An offer whose materializable output is a REAL object the caller has
/// put in a blob store — the fixture a serving test needs, since serving
/// materializes that object's actual bytes.
///
/// # Panics
/// As [`offer_with_manifest_bytes`].
#[must_use]
pub fn offer_serving_object(
    coordinator: &CoordinatorAuthority,
    output: &ObjectId,
) -> (OfferPreparedActionResult, Vec<u8>) {
    offer_with_bytes(coordinator, output, 51)
}

/// The divergent counterpart of [`offer_with_manifest_bytes`]: same
/// action key, different materializable output, real manifest bytes.
///
/// # Panics
/// As [`offer_with_manifest_bytes`].
#[must_use]
pub fn divergent_offer_with_manifest_bytes(
    coordinator: &CoordinatorAuthority,
) -> (OfferPreparedActionResult, Vec<u8>) {
    offer_with_bytes(coordinator, &tagged_object(42), 53)
}

/// Two-pass build: stamp the manifest once to learn its final bytes,
/// take the content id of those bytes, then rebuild the offer with that
/// id (and the evidence rebound to it). The second stamp is by
/// construction identical to the first — asserted, because a drift here
/// would silently produce an id that names nothing.
fn offer_with_bytes(
    coordinator: &CoordinatorAuthority,
    output: &ObjectId,
    evidence_tag: u8,
) -> (OfferPreparedActionResult, Vec<u8>) {
    offer_with_bytes_with_ids(coordinator, output, evidence_tag, SAMPLE_ATTEMPT_IDS)
}

/// [`offer_with_bytes`] under a caller-supplied identity triple (G020
/// fresh-generation reissue fixtures).
fn offer_with_bytes_with_ids(
    coordinator: &CoordinatorAuthority,
    output: &ObjectId,
    evidence_tag: u8,
    ids: FixtureAttemptIds,
) -> (OfferPreparedActionResult, Vec<u8>) {
    let stamped = offer_for_object(coordinator, output, 50, evidence_tag, Vec::new(), ids);
    let bytes = crate::manifest_codec::encode_manifest_v1(&stamped.manifest);
    let manifest_id = ObjectId(
        crate::digest_set::digest_set(&bytes, crate::digest_set::DigestRequest::default(), None)
            .expect("digest the manifest bytes")
            .atp_content_id,
    );
    let offer = OfferPreparedActionResult::build(
        attempt_authority_with_ids(coordinator, ids),
        stamped.manifest,
        manifest_id.clone(),
        sample_evidence(&manifest_id),
        tagged_object(evidence_tag),
        tagged_digest("rabs.observation-stream.sha256.v1", 9),
        &sample_declared(),
        Vec::new(),
    )
    .expect("sample offer fixtures are internally consistent");
    assert_eq!(
        crate::manifest_codec::encode_manifest_v1(&offer.manifest),
        bytes,
        "re-stamping must not change the manifest bytes its id was taken from"
    );
    (offer, bytes)
}

/// Build an offer from the fixture parts: `output_tag` selects the
/// materializable output object, `manifest_tag`/`evidence_tag` the
/// manifest and evidence object ids.
fn offer_for(
    coordinator: &CoordinatorAuthority,
    output_tag: u8,
    manifest_tag: u8,
    evidence_tag: u8,
    ancestors: Vec<ProvisionalAncestorRef>,
) -> OfferPreparedActionResult {
    offer_for_object(
        coordinator,
        &tagged_object(output_tag),
        manifest_tag,
        evidence_tag,
        ancestors,
        SAMPLE_ATTEMPT_IDS,
    )
}

/// [`offer_for`] with the materializable output given as an object id.
#[allow(clippy::too_many_arguments)]
fn offer_for_object(
    coordinator: &CoordinatorAuthority,
    output: &ObjectId,
    manifest_tag: u8,
    evidence_tag: u8,
    ancestors: Vec<ProvisionalAncestorRef>,
    ids: FixtureAttemptIds,
) -> OfferPreparedActionResult {
    let manifest_id = tagged_object(manifest_tag);
    OfferPreparedActionResult::build(
        attempt_authority_with_ids(coordinator, ids),
        manifest_with_output_object(output),
        manifest_id.clone(),
        sample_evidence(&manifest_id),
        tagged_object(evidence_tag),
        tagged_digest("rabs.observation-stream.sha256.v1", 9),
        &sample_declared(),
        ancestors,
    )
    .expect("sample offer fixtures are internally consistent")
}

/// Install the full admission world `process_offer` requires: active
/// coordinator authority, the action entry, generation, attempt, lease,
/// and every closure object located durably.
///
/// # Panics
/// If any store operation fails on a fresh store.
pub fn install_ready_store(store: &mut dyn RabsMetadataStore) {
    let coordinator = sample_coordinator_authority();
    store
        .acquire_authority(&AuthorityRow {
            digest: authority_digest(&coordinator),
            cluster_id: "cluster-a".to_owned(),
            incarnation: 77,
            term: 3,
            acquired_seq: 1,
        })
        .expect("acquire authority");
    install_admission_world(store, &coordinator);
    install_offer_closure(store, &offer_under(&coordinator));
}

/// Everything `process_offer` admits against EXCEPT the coordinator
/// authority row: the action entry, the generation, the attempt, and the
/// execution lease, all bound to `coordinator`. Split out of
/// [`install_ready_store`] because a live daemon has already acquired its
/// own authority at boot — a test must build its world UNDER that one, not
/// acquire a second (which the store refuses as `AuthorityHeld`).
///
/// # Panics
/// If any store operation fails.
pub fn install_admission_world(
    store: &mut dyn RabsMetadataStore,
    coordinator: &CoordinatorAuthority,
) {
    install_admission_world_with_ids(store, coordinator, SAMPLE_ATTEMPT_IDS);
}

/// [`install_admission_world`] under a caller-supplied identity triple —
/// the fresh-generation reissue path (G020): after a restart closes the
/// prior incarnation's generations, the new authority's world needs
/// ids above the never-reuse high-water mark and a never-used attempt.
///
/// # Panics
/// If any store operation fails.
pub fn install_admission_world_with_ids(
    store: &mut dyn RabsMetadataStore,
    coordinator: &CoordinatorAuthority,
    ids: FixtureAttemptIds,
) {
    let auth = authority_digest(coordinator);
    let attempt_authority = attempt_authority_with_ids(coordinator, ids);
    store
        .upsert_action_entry(&ActionEntryRow {
            action_key: sample_action_key(),
            key_epoch: 1,
            projection_epoch: 1,
        })
        .expect("upsert action entry");
    store
        .create_bound_generation(
            &auth,
            &attempt_authority.action_generation,
            &sample_action_key(),
        )
        .expect("create generation");
    store
        .admit_worker_session(
            &auth,
            &WorkerSessionOffer {
                worker_peer_id: attempt_authority.worker_peer_id.clone(),
                boot_generation: attempt_authority.worker_boot_generation,
                incarnation: attempt_authority.worker_incarnation_id,
                reenrollment_proof: None,
            },
            1,
        )
        .expect("worker session");
    store
        .admit_attempt_lease(&attempt_authority, 1, 100)
        .expect("attempt lease");
}

/// [`offer_with_manifest_bytes`] under a caller-supplied identity triple:
/// the offer side of a fresh-generation reissue world (G020). The
/// attempt/lease/generation ids here MUST match those installed by
/// [`install_admission_world_with_ids`].
///
/// # Panics
/// As [`offer_with_manifest_bytes`].
#[must_use]
pub fn offer_with_manifest_bytes_with_ids(
    coordinator: &CoordinatorAuthority,
    ids: FixtureAttemptIds,
) -> (OfferPreparedActionResult, Vec<u8>) {
    offer_with_bytes_with_ids(coordinator, &tagged_object(41), 51, ids)
}

/// The divergent counterpart of [`offer_with_manifest_bytes_with_ids`]:
/// same action key, different materializable output, real manifest
/// bytes, under a fresh-generation identity triple (G020 reissue).
///
/// # Panics
/// As [`offer_with_manifest_bytes`].
#[must_use]
pub fn divergent_offer_with_manifest_bytes_with_ids(
    coordinator: &CoordinatorAuthority,
    ids: FixtureAttemptIds,
) -> (OfferPreparedActionResult, Vec<u8>) {
    offer_with_bytes_with_ids(coordinator, &tagged_object(42), 53, ids)
}

/// Record and DURABLY locate every object in `offer`'s commit closure —
/// manifest, evidence bundle, the F035-derived artifact bundle root, each
/// logical output, and each evidence constituent. Under
/// `CommitDurabilityProfile::RequireDurableClosure` a located-but-volatile
/// object is a typed refusal, so the locations are written durable.
///
/// # Panics
/// If any store operation fails.
pub fn install_offer_closure(store: &mut dyn RabsMetadataStore, offer: &OfferPreparedActionResult) {
    let mut closure = vec![
        offer.manifest_id.0.clone(),
        offer.evidence_id.0.clone(),
        offer.evidence.execution_snapshot_root.0.clone(),
        offer.evidence.observed_input_report.0.clone(),
        offer.evidence.raw_process_and_event_evidence.0.clone(),
        offer.evidence.provenance_receipt.0.clone(),
    ];
    if let Some(root) = &offer.manifest.artifact_bundle_root {
        closure.push(root.0.clone());
    }
    for output in &offer.manifest.logical_outputs {
        closure.push(output.object.0.clone());
    }
    if let Some(snapshot) = &offer.evidence.incremental_snapshot {
        closure.push(snapshot.0.clone());
    }
    for id in &closure {
        // An object that ALREADY has a durable copy is left alone: when
        // a caller has put real bytes in a real blob store (the manifest
        // object, say), fabricating a second location beside them would
        // hand readers a path with nothing behind it.
        if store
            .object_durably_located(id)
            .expect("check object location")
        {
            continue;
        }
        let key = crate::metadata_store::digest_key(id);
        store.record_object(id, 64).expect("record object");
        store
            .add_location(id, &format!("/cas/{key}"), Some(1), "raw", true)
            .expect("locate object");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata_store::{RusqliteEngine, SqlMetadataStore};
    use crate::publication::{CommitDurabilityProfile, PublicationOutcome, process_offer};

    #[test]
    fn sample_offer_commits_into_a_ready_store() {
        let engine = RusqliteEngine::open_in_memory().unwrap();
        let mut store = SqlMetadataStore::open(engine).unwrap();
        install_ready_store(&mut store);
        let outcome = process_offer(
            &mut store,
            &sample_offer(),
            &sample_expected_descriptor(),
            |_| None, // no prior committed manifest for this key
            900,      // pin_id
            1,        // seq
            CommitDurabilityProfile::RequireDurableClosure,
        )
        .expect("offer must be accepted");
        assert!(
            matches!(outcome, PublicationOutcome::Committed(_)),
            "expected a real commit, got {outcome:?}"
        );
    }
}
