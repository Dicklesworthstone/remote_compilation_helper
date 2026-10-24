//! Live publication of pipelined dependency graphs through verified CAS bytes.
//!
//! Action/worker identities and non-manifest closure locations are synthetic
//! test-support fixtures. Manifests are real, content-addressed CAS files and
//! every normal publication calls CoordLive::commit_offer. These are not
//! compiler, transport, sandbox, or whole-Cargo acceptance tests.
#![cfg(unix)]

use std::sync::Arc;

use rabs_cas::blob_store::{DurabilityPolicy, PutLimits, put_if_absent};
use rabs_cas::digest_set::{DigestRequest, digest_set};
use rabs_cas::manifest_codec::encode_manifest_v1;
use rabs_cas::metadata_store::{
    ActionEntryRow, CommitOutcome, ProvisionalAncestorRow, PublicationRow, QuarantineScope, RabsMetadataStore,
    ResultKindTag, digest_key,
};
use rabs_cas::publication::{
    OfferPreparedActionResult, OfferRefusal, ProvisionalAncestorRef, PublicationOutcome,
    authority_digest, observable_result_digest_v1, semantic_result_digest_v1,
};
use rabs_cas::test_support::{
    install_offer_closure, offer_with_manifest_bytes, sample_expected_descriptor, tagged_object,
};
use rabs_protocol::generation::{
    ActionGenerationId, AttemptId, ExecutionLeaseId, WorkerBootGeneration, WorkerIncarnationId,
};
use rabs_protocol::result_identity::{DigestAlgorithm, ObjectId, TypedDigest};
use rabs_protocol::wire_time::PeerId;
use rabs_protocol::worker_fence::WorkerSessionOffer;
use rabsd::coord::live::{CommitRefusal, CoordLive};
use rabsd::janitor::store::{LiveCas, mount_and_reconcile};

struct World {
    coord: Arc<CoordLive>,
    cas: Arc<LiveCas>,
    // Drop the live owners before their temporary filesystem backing.
    _root: tempfile::TempDir,
}

impl World {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let cas = Arc::new(mount_and_reconcile(&root.path().join("cas")).unwrap());
        let coord = Arc::new(CoordLive::with_cas(Arc::clone(&cas)));
        coord.acquire_boot_authority("publication-lineage").unwrap();
        coord.mark_up();
        Self { coord, cas, _root: root }
    }

    fn prepare(
        &self,
        tag: u8,
        generation: u128,
        parents: Vec<ProvisionalAncestorRef>,
    ) -> OfferPreparedActionResult {
        let authority = self.coord.authority().unwrap();
        let (mut offer, _) = offer_with_manifest_bytes(&authority);
        let key = TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "rabs.action-key.sha256.v1",
            bytes: [tag; 32],
        };
        offer.authority.action_key = key.clone();
        offer.authority.action_generation.generation_id = ActionGenerationId(generation);
        offer.authority.attempt_id = AttemptId(10 * generation + 1);
        offer.authority.execution_lease_id = ExecutionLeaseId(10 * generation + 2);
        offer.authority.worker_peer_id = PeerId(format!("lineage-worker-{generation}"));
        offer.authority.worker_boot_generation = WorkerBootGeneration(1);
        offer.authority.worker_incarnation_id = WorkerIncarnationId(generation);
        self.coord
            .admit_worker_session(&WorkerSessionOffer {
                worker_peer_id: offer.authority.worker_peer_id.clone(),
                boot_generation: offer.authority.worker_boot_generation,
                incarnation: offer.authority.worker_incarnation_id,
                reenrollment_proof: None,
            })
            .unwrap();
        offer.manifest.action_key = key.clone();
        offer.manifest.semantic_result_digest = semantic_result_digest_v1(&offer.manifest);
        offer.manifest.observable_result_digest =
            observable_result_digest_v1(&offer.manifest, &offer.canonical_observations);
        let bytes = encode_manifest_v1(&offer.manifest);
        offer.manifest_id = ObjectId(
            digest_set(&bytes, DigestRequest::default(), None)
                .unwrap()
                .atp_content_id,
        );
        offer.evidence.action_key = key.clone();
        offer.evidence.canonical_result_manifest_id = offer.manifest_id.clone();
        offer.provisional_ancestors = parents;
        {
            let mut store = self.cas.store().lock().unwrap();
            store
                .upsert_action_entry(&ActionEntryRow {
                    action_key: key.clone(),
                    key_epoch: offer.manifest.key_epoch,
                    projection_epoch: offer.manifest.projection_epoch,
                })
                .unwrap();
            store
                .create_bound_generation(
                    &authority_digest(&authority),
                    &offer.authority.action_generation,
                    &key,
                )
                .unwrap();
            put_if_absent(
                self.cas.layout(),
                &mut *store,
                &offer.manifest_id.0,
                &mut &bytes[..],
                PutLimits::default(),
                DurabilityPolicy::FULL,
            )
            .unwrap();
            install_offer_closure(&mut *store, &offer);
        }
        // Use the live monotonic-clock lease API, not a fixture wall clock.
        self.coord.admit_attempt_lease(&offer.authority, 600_000).unwrap();
        offer
    }

    fn commit(&self, offer: &OfferPreparedActionResult) {
        assert!(matches!(
            self.coord.commit_offer(offer, &sample_expected_descriptor()).unwrap(),
            PublicationOutcome::Committed(_)
        ));
    }

    fn no_publication(&self, offer: &OfferPreparedActionResult) {
        assert!(!self.cas.store().lock().unwrap().has_publication(&offer.manifest.action_key).unwrap());
    }

    fn restart_coordinator(&mut self) {
        // Restart only coordinator state over the mounted CAS. Fake closure
        // locations intentionally preclude claiming filesystem boot recovery.
        self.coord.mark_down();
        let replacement = Arc::new(CoordLive::with_cas(Arc::clone(&self.cas)));
        replacement.acquire_boot_authority("publication-lineage").unwrap();
        replacement.mark_up();
        self.coord = replacement;
    }
}

fn consumes(producer: &OfferPreparedActionResult) -> ProvisionalAncestorRef {
    let output = &producer.manifest.logical_outputs[0];
    ProvisionalAncestorRef {
        producer_action_key: producer.manifest.action_key.clone(),
        role: output.role,
        virtual_path: output.virtual_path.clone(),
        consumed_object: output.object.clone(),
    }
}

#[test]
fn live_coordinator_publishes_direct_and_transitive_consumers() {
    let world = World::new();
    let a = world.prepare(1, 1, Vec::new());
    world.commit(&a);
    let b = world.prepare(2, 2, vec![consumes(&a)]);
    world.commit(&b);
    let c = world.prepare(3, 3, vec![consumes(&b)]);
    world.commit(&c);
    let mut store = world.cas.store().lock().unwrap();
    let rows = store.list_provisional_ancestors(&digest_key(&c.manifest.action_key)).unwrap();
    assert_eq!(rows.len(), 1, "store only C's direct reference, not a flattened graph");
    assert_eq!(rows[0].producer_action_key, digest_key(&b.manifest.action_key));
    assert_eq!(rows[0].object_key, digest_key(&b.manifest.logical_outputs[0].object.0));
    assert!(!rows[0].adopted);
    assert_eq!(
        store.published_manifest_key(&a.manifest.action_key).unwrap(),
        Some(digest_key(&a.manifest_id.0))
    );
}

#[test]
fn diamond_publication_reuses_the_same_verified_ancestor() {
    let world = World::new();
    let a = world.prepare(1, 1, Vec::new());
    world.commit(&a);
    let b = world.prepare(2, 2, vec![consumes(&a)]);
    world.commit(&b);
    let c = world.prepare(3, 3, vec![consumes(&a)]);
    world.commit(&c);
    let d = world.prepare(4, 4, vec![consumes(&b), consumes(&c)]);
    world.commit(&d);
    assert_eq!(
        world.cas.store().lock().unwrap()
            .list_provisional_ancestors(&digest_key(&d.manifest.action_key)).unwrap().len(),
        2
    );
}

#[test]
fn uncommitted_producer_is_not_replaced_by_the_consumers_manifest() {
    let world = World::new();
    let a = world.prepare(1, 1, Vec::new());
    let b = world.prepare(2, 2, vec![consumes(&a)]);
    assert_eq!(
        world.coord.commit_offer(&b, &sample_expected_descriptor()),
        Err(CommitRefusal::Offer(OfferRefusal::ProvisionalProducerNotCommitted {
            producer: digest_key(&a.manifest.action_key),
        }))
    );
    world.no_publication(&a);
    world.no_publication(&b);
}

#[test]
fn resolved_manifests_still_require_the_exact_consumed_object() {
    let world = World::new();
    let a = world.prepare(1, 1, Vec::new());
    world.commit(&a);
    let mut wrong = consumes(&a);
    wrong.consumed_object = tagged_object(222);
    let b = world.prepare(2, 2, vec![wrong]);
    assert!(matches!(
        world.coord.commit_offer(&b, &sample_expected_descriptor()),
        Err(CommitRefusal::Offer(OfferRefusal::DivergentProvisionalAncestor { .. }))
    ));
    world.no_publication(&b);
}

#[test]
fn transitive_manifest_quarantine_cannot_hide_behind_a_valid_direct_producer() {
    let world = World::new();
    let a = world.prepare(1, 1, Vec::new());
    world.commit(&a);
    let b = world.prepare(2, 2, vec![consumes(&a)]);
    world.commit(&b);
    world.cas.store().lock().unwrap()
        .add_quarantine(QuarantineScope::LogicalObject, &digest_key(&a.manifest_id.0), "bad ancestor")
        .unwrap();
    let c = world.prepare(3, 3, vec![consumes(&b)]);
    assert_eq!(
        world.coord.commit_offer(&c, &sample_expected_descriptor()),
        Err(CommitRefusal::Offer(OfferRefusal::AncestorManifestUnavailable {
            producer: digest_key(&a.manifest.action_key),
        }))
    );
    world.no_publication(&c);
}

#[test]
fn fresh_coordinator_reloads_the_producer_graph_but_rejects_old_attempt_authority() {
    let mut world = World::new();
    let a = world.prepare(1, 1, Vec::new());
    world.commit(&a);
    let b = world.prepare(2, 2, vec![consumes(&a)]);
    world.commit(&b);
    let stale = world.prepare(3, 3, vec![consumes(&b)]);
    world.restart_coordinator();
    assert!(matches!(
        world.coord.commit_offer(&stale, &sample_expected_descriptor()),
        Err(CommitRefusal::StaleAuthority { .. })
    ));
    world.no_publication(&stale);
    let fresh = world.prepare(3, 4, vec![consumes(&b)]);
    world.commit(&fresh);
}

#[test]
fn producer_publication_must_bind_the_loaded_manifests_action_identity() {
    let world = World::new();
    let a = world.prepare(1, 1, Vec::new());
    world.commit(&a);
    let alias = world.prepare(2, 2, Vec::new());
    // Inject a corrupt metadata pointer through the raw store fixture API:
    // action 2 names action 1's correctly hashed, decodable manifest. Their
    // output objects/path are identical, so checking outputs alone is unsound.
    let active = authority_digest(&world.coord.authority().unwrap());
    {
        let mut store = world.cas.store().lock().unwrap();
        assert_eq!(
            store.commit_publication(
                &active,
                None,
                &PublicationRow {
                    action_key: alias.manifest.action_key.clone(),
                    descriptor_digest: alias.manifest.canonical_descriptor_digest.clone(),
                    manifest_digest: a.manifest_id.0.clone(),
                    evidence_digest: alias.evidence_id.0.clone(),
                    winner_generation: alias.authority.action_generation.generation_id.0,
                    winner_attempt: alias.authority.attempt_id.0,
                    result_kind: ResultKindTag::Success,
                    pin_id: 987_654,
                    pin_owner: "corrupt-pointer-fixture".into(),
                    provisional_ancestors: Vec::new(),
                },
            ).unwrap(),
            CommitOutcome::Committed
        );
    }
    let consumer = world.prepare(3, 3, vec![consumes(&alias)]);
    assert_eq!(
        world.coord.commit_offer(&consumer, &sample_expected_descriptor()),
        Err(CommitRefusal::Offer(OfferRefusal::AncestorManifestUnavailable {
            producer: digest_key(&alias.manifest.action_key),
        }))
    );
    world.no_publication(&consumer);
}

#[test]
fn excessive_lineage_is_refused_before_publication() {
    let world = World::new();
    let a = world.prepare(1, 1, Vec::new());
    world.commit(&a);
    let b = world.prepare(2, 2, vec![consumes(&a); 65_537]);
    assert!(matches!(
        world.coord.commit_offer(&b, &sample_expected_descriptor()),
        Err(CommitRefusal::Offer(OfferRefusal::Store(
            rabs_cas::metadata_store::StoreError::Corruption(ref message)
        ))) if message == "lineage exceeds admission bound"
    ));
    world.no_publication(&b);
}

#[test]
fn already_visited_producer_does_not_hide_a_different_consumption_edge() {
    let world = World::new();
    let a = world.prepare(1, 1, Vec::new());
    world.commit(&a);
    let b = world.prepare(2, 2, Vec::new());
    let wrong = tagged_object(222);
    let active = authority_digest(&world.coord.authority().unwrap());
    {
        // Inject inconsistent historical lineage using the raw metadata API.
        // C consumes A directly and also through B. H028 must check B -> A
        // even after it already checked C -> A; visiting a producer is not
        // proof that all consumers used the same object from that producer.
        let mut store = world.cas.store().lock().unwrap();
        store.record_object(&wrong.0, 64).unwrap();
        assert_eq!(
            store.commit_publication(
                &active,
                None,
                &PublicationRow {
                    action_key: b.manifest.action_key.clone(),
                    descriptor_digest: b.manifest.canonical_descriptor_digest.clone(),
                    manifest_digest: b.manifest_id.0.clone(),
                    evidence_digest: b.evidence_id.0.clone(),
                    winner_generation: b.authority.action_generation.generation_id.0,
                    winner_attempt: b.authority.attempt_id.0,
                    result_kind: ResultKindTag::Success,
                    pin_id: 987_655,
                    pin_owner: "inconsistent-lineage-fixture".into(),
                    provisional_ancestors: vec![ProvisionalAncestorRow {
                        producer_action_key: digest_key(&a.manifest.action_key),
                        role: "materializable".into(),
                        virtual_path: a.manifest.logical_outputs[0].virtual_path.as_bytes().to_vec(),
                        object_key: digest_key(&wrong.0),
                        adopted: false,
                    }],
                },
            ).unwrap(),
            CommitOutcome::Committed
        );
    }
    let c = world.prepare(3, 3, vec![consumes(&a), consumes(&b)]);
    assert!(matches!(
        world.coord.commit_offer(&c, &sample_expected_descriptor()),
        Err(CommitRefusal::Offer(OfferRefusal::DivergentProvisionalAncestor { .. }))
    ));
    world.no_publication(&c);
}

#[test]
fn rejected_attempt_does_not_read_or_quarantine_a_producers_cas_location() {
    use std::os::unix::fs::PermissionsExt;

    let world = World::new();
    let producer = world.prepare(1, 1, Vec::new());
    world.commit(&producer);
    let consumer = world.prepare(2, 2, vec![consumes(&producer)]);
    let location = {
        let mut store = world.cas.store().lock().unwrap();
        let locations = store.object_locations(&producer.manifest_id.0).unwrap();
        assert_eq!(locations.len(), 1);
        locations[0].0.clone()
    };
    // Deliberate corruption of this fixture's private CAS file. Metadata still
    // records the location until the real verified loader observes bad bytes.
    std::fs::set_permissions(&location, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(&location, b"not the content-addressed producer manifest").unwrap();
    let mut unknown = consumer.clone();
    unknown.authority.attempt_id = AttemptId(999_999);
    assert_eq!(
        world.coord.commit_offer(&unknown, &sample_expected_descriptor()),
        Err(CommitRefusal::Offer(OfferRefusal::UnknownAttempt))
    );
    assert!(
        world.cas.store().lock().unwrap()
            .object_durably_located(&producer.manifest_id.0).unwrap(),
        "an early refusal must not preload or mutate the producer's location"
    );
    // The honestly admitted consumer DOES reach the loader, which quarantines
    // the corrupt physical copy and refuses instead of publishing the consumer.
    assert_eq!(
        world.coord.commit_offer(&consumer, &sample_expected_descriptor()),
        Err(CommitRefusal::Offer(OfferRefusal::AncestorManifestUnavailable {
            producer: digest_key(&producer.manifest.action_key),
        }))
    );
    assert!(!world.cas.store().lock().unwrap()
        .object_durably_located(&producer.manifest_id.0).unwrap());
    world.no_publication(&consumer);
}