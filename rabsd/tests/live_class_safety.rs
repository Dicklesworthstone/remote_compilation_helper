//! Cross-key live replay demotion through production commit and install APIs.
//!
//! Artifacts and manifest objects are real CAS bytes. Action descriptors,
//! class enrollment and worker evidence are synthetic test-support fixtures;
//! these tests do not claim a real rustc run or authenticated remote execution.
#![cfg(unix)]

use std::path::Path;
use std::sync::Arc;

use rabs_cas::blob_store::{DurabilityPolicy, PutLimits, put_if_absent};
use rabs_cas::digest_set::{DigestRequest, digest_set};
use rabs_cas::manifest_codec::encode_manifest_v1;
use rabs_cas::metadata_store::{ActionEntryRow, RabsMetadataStore, digest_key};
use rabs_cas::publication::{OfferPreparedActionResult, PublicationOutcome, authority_digest};
use rabs_cas::serving_sample_gate::PrivateExecutionReason;
use rabs_cas::test_support::{
    install_admission_world, install_offer_closure, offer_serving_object, sample_declared,
    sample_expected_descriptor, tagged_digest,
};
use rabs_protocol::generation::{ActionGenerationId, AttemptId, ExecutionLeaseId};
use rabs_protocol::result_identity::{ObjectId, TypedDigest};
use rabsd::coord::live::{CoordLive, ExpectedOutputs, ReplayRefusal, ServeOutcome};
use rabsd::janitor::store::{LiveCas, mount_and_reconcile};

const CLASS_RECEIPT: &str = "rabs-live-action-class-v1";
const CLASS: &str = "rustc-dependency-compile";
const GOOD: &[u8] = b"verified compiler output";
const DIFFERENT: &[u8] = b"independently divergent compiler output";

struct Fixture {
    root: tempfile::TempDir,
    cas: Arc<LiveCas>,
    coord: Arc<CoordLive>,
    serial: u128,
}

fn put(cas: &LiveCas, bytes: &[u8]) -> ObjectId {
    let digest = digest_set(bytes, DigestRequest::default(), None)
        .unwrap()
        .atp_content_id;
    put_if_absent(
        cas.layout(),
        &mut *cas.store().lock().unwrap(),
        &digest,
        &mut &bytes[..],
        PutLimits::default(),
        DurabilityPolicy::FULL,
    )
    .unwrap();
    ObjectId(digest)
}

fn key(tag: u8) -> TypedDigest {
    tagged_digest("rabs.action-key.sha256.v1", tag)
}

fn now_micros() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros(),
    )
    .unwrap()
}

fn serve(coord: &Arc<CoordLive>, action: &TypedDigest, destination: &Path) -> ServeOutcome {
    coord
        .edge_subscriber()
        .serve_action(
            action,
            destination,
            &ExpectedOutputs::WhateverWasCommitted,
            now_micros(),
            0,
        )
        .unwrap()
}

fn held(culprit: &TypedDigest, reason: &'static str) -> ServeOutcome {
    ServeOutcome::ExecutePrivately(ReplayRefusal::Sampling(
        PrivateExecutionReason::ClassSafetyHold {
            class: CLASS.to_owned(),
            culprit_action_key: digest_key(culprit),
            reason,
        },
    ))
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let cas = Arc::new(mount_and_reconcile(&root.path().join("cas")).unwrap());
        let coord = Arc::new(CoordLive::with_cas(Arc::clone(&cas)));
        let authority = coord
            .acquire_boot_authority("class-safety-fixture")
            .unwrap();
        coord.mark_up();
        // Reuse the shared worker-enrollment/authority fixture. Its unused
        // sample action has no class receipt and grants no replay authority.
        install_admission_world(&mut *cas.store().lock().unwrap(), &authority);
        Self {
            root,
            cas,
            coord,
            serial: 100,
        }
    }

    /// Admit fresh identity for each comparison, then offer real manifest bytes
    /// through the same publication engine the live dependency lane calls.
    fn commit(&mut self, action: &TypedDigest, artifact: &[u8]) -> PublicationOutcome {
        self.serial += 1;
        let coordinator = self.coord.authority().unwrap();
        let object = put(&self.cas, artifact);
        let (template, _) = offer_serving_object(&coordinator, &object);
        let mut authority = template.authority;
        authority.action_key = action.clone();
        authority.action_generation.generation_id = ActionGenerationId(self.serial);
        authority.attempt_id = AttemptId(self.serial + 1_000);
        authority.execution_lease_id = ExecutionLeaseId(self.serial + 2_000);
        let mut manifest = template.manifest;
        manifest.action_key = action.clone();
        let mut evidence = template.evidence;
        evidence.action_key = action.clone();
        let mut offer = OfferPreparedActionResult::build(
            authority,
            manifest,
            template.manifest_id,
            evidence,
            template.evidence_id,
            template.canonical_observations,
            &sample_declared(),
            Vec::new(),
        )
        .unwrap();
        let bytes = encode_manifest_v1(&offer.manifest);
        let manifest_id = put(&self.cas, &bytes);
        offer.manifest_id = manifest_id.clone();
        offer.evidence.canonical_result_manifest_id = manifest_id;
        {
            let mut store = self.cas.store().lock().unwrap();
            store
                .upsert_action_entry(&ActionEntryRow {
                    action_key: action.clone(),
                    key_epoch: offer.manifest.key_epoch,
                    projection_epoch: offer.manifest.projection_epoch,
                })
                .unwrap();
            store
                .create_bound_generation(
                    &authority_digest(&coordinator),
                    &offer.authority.action_generation,
                    action,
                )
                .unwrap();
            store
                .record_decision_receipt(
                    CLASS_RECEIPT,
                    &digest_key(action),
                    0,
                    CLASS,
                    "synthetic descriptor classification",
                )
                .unwrap();
            install_offer_closure(&mut *store, &offer);
        }
        self.coord
            .admit_attempt_lease(&offer.authority, 600_000)
            .unwrap();
        self.coord
            .commit_offer(&offer, &sample_expected_descriptor())
            .unwrap()
    }

    fn warm(&mut self, action: &TypedDigest) {
        assert!(matches!(
            self.commit(action, GOOD),
            PublicationOutcome::Committed(_)
        ));
        for _ in 0..2 {
            assert_eq!(
                self.commit(action, GOOD),
                PublicationOutcome::IdempotentEvidenceAppended
            );
        }
    }
}

#[test]
fn a_real_publication_conflict_stops_peer_replay_and_survives_coordinator_restart() {
    let mut fixture = Fixture::new();
    let requested = key(71);
    let culprit = key(72);
    fixture.warm(&requested);
    assert!(matches!(
        fixture.commit(&culprit, GOOD),
        PublicationOutcome::Committed(_)
    ));
    let before = fixture.root.path().join("before-divergence");
    assert!(matches!(
        serve(&fixture.coord, &requested, &before),
        ServeOutcome::Served { .. }
    ));
    assert_eq!(std::fs::read(before.join("out/lib.rlib")).unwrap(), GOOD);
    let publication = fixture
        .cas
        .store()
        .lock()
        .unwrap()
        .published_manifest_key(&requested)
        .unwrap();

    assert!(matches!(
        fixture.commit(&culprit, DIFFERENT),
        PublicationOutcome::Quarantined(_)
    ));
    let refused = fixture.root.path().join("after-divergence");
    assert_eq!(
        serve(&fixture.coord, &requested, &refused),
        held(&culprit, "divergence-incident")
    );
    assert!(
        !refused.exists(),
        "no output directory or partial artifact may be created"
    );
    // A successful new comparison renews the existing per-key replay budget,
    // but must NOT clear the class hold. The old good output stays untouched.
    assert_eq!(
        fixture.commit(&requested, GOOD),
        PublicationOutcome::IdempotentEvidenceAppended
    );
    let before_metadata = std::fs::metadata(before.join("out/lib.rlib")).unwrap();
    assert_eq!(
        serve(&fixture.coord, &requested, &before),
        held(&culprit, "divergence-incident")
    );
    assert_eq!(std::fs::read(before.join("out/lib.rlib")).unwrap(), GOOD);
    assert_eq!(
        std::fs::metadata(before.join("out/lib.rlib"))
            .unwrap()
            .modified()
            .unwrap(),
        before_metadata.modified().unwrap()
    );
    {
        let mut store = fixture.cas.store().lock().unwrap();
        assert_eq!(
            store.published_manifest_key(&requested).unwrap(),
            publication
        );
        assert_eq!(
            store
                .serving_disposition_key(&digest_key(&requested))
                .unwrap()
                .as_deref(),
            Some("servable")
        );
        assert!(
            store
                .list_divergence_incidents(&digest_key(&requested))
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            store
                .list_divergence_incidents(&digest_key(&culprit))
                .unwrap()
                .len(),
            1
        );
    }
    let Fixture {
        root, cas, coord, ..
    } = fixture;
    drop(coord);
    drop(cas);
    let cas = Arc::new(mount_and_reconcile(&root.path().join("cas")).unwrap());
    let coord = Arc::new(CoordLive::with_cas(Arc::clone(&cas)));
    coord
        .acquire_boot_authority("class-safety-fixture")
        .unwrap();
    coord.mark_up();
    let refused = root.path().join("after-restart");
    assert_eq!(
        serve(&coord, &requested, &refused),
        held(&culprit, "divergence-incident")
    );
    assert!(!refused.exists());
}

#[test]
fn interrupted_peer_quarantine_blocks_live_install_before_incident_feedback() {
    for disposition in ["quarantined", "presentation-quarantined"] {
        let mut fixture = Fixture::new();
        let requested = key(81);
        let culprit = key(82);
        fixture.warm(&requested);
        assert!(matches!(
            fixture.commit(&culprit, GOOD),
            PublicationOutcome::Committed(_)
        ));
        // Inject the exact first durable mutation used by process_offer, but
        // deliberately omit its later incident/sample bookkeeping.
        fixture
            .cas
            .store()
            .lock()
            .unwrap()
            .set_serving_disposition_key(&digest_key(&culprit), disposition)
            .unwrap();
        let refused = fixture.root.path().join("must-not-write");
        let before = fixture
            .cas
            .store()
            .lock()
            .unwrap()
            .differential_snapshot()
            .unwrap();
        for _ in 0..2 {
            assert_eq!(
                serve(&fixture.coord, &requested, &refused),
                held(&culprit, "serving-quarantine")
            );
            assert!(!refused.exists());
        }
        let mut store = fixture.cas.store().lock().unwrap();
        assert_eq!(store.differential_snapshot().unwrap(), before);
        assert!(
            store
                .list_divergence_incidents(&digest_key(&culprit))
                .unwrap()
                .is_empty()
        );
        assert!(
            store
                .list_verification_samples(&culprit)
                .unwrap()
                .is_empty()
        );
    }
}
