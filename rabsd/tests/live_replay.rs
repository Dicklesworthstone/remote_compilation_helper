//! Live coordinator/edge replay admission and on-disk manifest integrity.
//!
//! Uses real CAS bytes and the production publication/materialization methods.
//! Offers and class enrollment are synthetic fixtures: these tests do not claim
//! an authenticated remote compile or that a Cargo wrapper skipped rustc.
#![cfg(unix)]

use std::collections::BTreeSet;
use std::sync::Arc;

use rabs_cas::blob_store::{DurabilityPolicy, PutLimits, PutOutcome, put_if_absent};
use rabs_cas::digest_set::{DigestRequest, digest_set};
use rabs_cas::metadata_store::{RabsMetadataStore, digest_key};
use rabs_cas::publication::{OfferPreparedActionResult, PublicationOutcome};
use rabs_cas::serving_state::ServeDecision;
use rabs_cas::test_support::{
    divergent_offer_with_manifest_bytes, install_admission_world,
    install_admission_world_with_ids, install_offer_closure, offer_serving_object,
    offer_with_manifest_bytes, sample_action_key, sample_expected_descriptor,
};
use rabs_protocol::result_identity::ObjectId;
use rabsd::coord::live::{CoordLive, ExpectedOutputs, ServeOutcome, load_manifest};
use rabsd::janitor::store::{LiveCas, mount_and_reconcile};

fn now_micros() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros(),
    )
    .unwrap()
}

fn store_manifest_object(cas: &LiveCas, offer: &OfferPreparedActionResult, bytes: &[u8]) {
    let mut store = cas.store().lock().unwrap();
    let outcome = put_if_absent(
        cas.layout(),
        &mut *store,
        &offer.manifest_id.0,
        &mut &bytes[..],
        PutLimits::default(),
        DurabilityPolicy::FULL,
    )
    .unwrap();
    assert!(matches!(
        outcome,
        PutOutcome::Stored { .. } | PutOutcome::IdempotentDuplicate { .. }
    ));
    install_offer_closure(&mut *store, offer);
}

#[test]
fn live_edge_replay_uses_completed_comparisons_and_blocks_divergence() {
    use rabs_cas::metadata_store::SqlValue;
    use rabs_cas::serving_sample_gate::PrivateExecutionReason;
    use rabs_cas::test_support::FixtureAttemptIds;
    use rabs_protocol::generation::{ActionGenerationId, AttemptId, ExecutionLeaseId};
    use rabsd::coord::live::{ReplayRefusal, ServeError};

    let dir = tempfile::tempdir().unwrap();
    let cas = Arc::new(mount_and_reconcile(&dir.path().join("cas")).unwrap());
    let coord = Arc::new(CoordLive::with_cas(Arc::clone(&cas)));
    let authority = coord.acquire_boot_authority("live-replay-fixture").unwrap();
    coord.mark_up();
    let edge = coord.edge_subscriber();
    let artifact = b"real bytes behind a verified dependency result";
    let object = {
        let mut store = cas.store().lock().unwrap();
        let digest = digest_set(artifact, DigestRequest::default(), None)
            .unwrap()
            .atp_content_id;
        put_if_absent(
            cas.layout(),
            &mut *store,
            &digest,
            &mut &artifact[..],
            PutLimits::default(),
            DurabilityPolicy::FULL,
        )
        .unwrap();
        ObjectId(digest)
    };
    let (offer, bytes) = offer_serving_object(&authority, &object);
    {
        let mut store = cas.store().lock().unwrap();
        install_admission_world(&mut *store, &authority);
    }
    store_manifest_object(&cas, &offer, &bytes);
    assert!(matches!(
        coord.commit_offer(&offer, &sample_expected_descriptor()).unwrap(),
        PublicationOutcome::Committed(_)
    ));
    let expected = ExpectedOutputs::Exactly(BTreeSet::from(["out/lib.rlib".to_owned()]));
    let destination = dir.path().join("edge-replay");
    assert_eq!(
        edge.serve_action(&sample_action_key(), &destination, &expected, now_micros(), 0)
            .unwrap(),
        ServeOutcome::ExecutePrivately(ReplayRefusal::Sampling(
            PrivateExecutionReason::ElevatedClassRisk
        ))
    );
    assert!(!destination.exists());
    {
        // Offer fixtures have synthetic tagged keys. The source-submission unit
        // test separately proves production class enrollment from a descriptor.
        let mut store = cas.store().lock().unwrap();
        store.record_decision_receipt(
            "rabs-live-action-class-v1", &digest_key(&sample_action_key()), 0,
            "rustc-dependency-compile", "synthetic fixture classification",
        ).unwrap();
    }
    for _ in 0..3 {
        assert_eq!(
            coord.commit_offer(&offer, &sample_expected_descriptor()).unwrap(),
            PublicationOutcome::IdempotentEvidenceAppended
        );
    }
    assert_eq!(
        edge.serve_action(&sample_action_key(), &destination, &expected, now_micros(), 0)
            .unwrap(),
        ServeOutcome::ExecutePrivately(ReplayRefusal::Sampling(
            PrivateExecutionReason::InsufficientVerificationSamples {
                observed: 0, required: 2,
            }
        ))
    );
    assert!(!destination.exists());

    for n in 1..=2_u128 {
        let ids = FixtureAttemptIds {
            generation: 11 + n, attempt: 20 + n, lease: 30 + n,
        };
        {
            let mut store = cas.store().lock().unwrap();
            install_admission_world_with_ids(&mut *store, &authority, ids);
        }
        let mut comparison = offer.clone();
        comparison.authority.action_generation.generation_id = ActionGenerationId(ids.generation);
        comparison.authority.attempt_id = AttemptId(ids.attempt);
        comparison.authority.execution_lease_id = ExecutionLeaseId(ids.lease);
        for _ in 0..3 {
            assert_eq!(
                coord.commit_offer(&comparison, &sample_expected_descriptor()).unwrap(),
                PublicationOutcome::IdempotentEvidenceAppended
            );
        }
        let mut store = cas.store().lock().unwrap();
        let samples = store.list_verification_samples(&sample_action_key()).unwrap();
        assert_eq!(samples.len(), usize::try_from(n).unwrap());
        assert!(samples.iter().all(|sample| sample.passed));
    }
    assert!(matches!(
        edge.serve_action(&sample_action_key(), &destination, &expected, now_micros(), 0)
            .unwrap(),
        ServeOutcome::Served { .. }
    ));
    assert_eq!(std::fs::read(destination.join("out/lib.rlib")).unwrap(), artifact);

    let unavailable = dir.path().join("coordinator-down");
    coord.mark_down();
    assert_eq!(
        edge.serve_action(&sample_action_key(), &unavailable, &expected, now_micros(), 0),
        Err(ServeError::CoordinatorUnavailable)
    );
    assert!(!unavailable.exists());
    coord.mark_up();
    let wrong_epoch = dir.path().join("wrong-clock-epoch");
    assert_eq!(
        edge.serve_action(&sample_action_key(), &wrong_epoch, &expected, now_micros(), 1)
            .unwrap(),
        ServeOutcome::NotServable(ServeDecision::ExpiredClockEpoch)
    );
    assert!(!wrong_epoch.exists());

    // Unattributed negative evidence cannot disappear in a 100% pass rate
    // calculated using only attributable positive attempts.
    {
        let mut store = cas.store().lock().unwrap();
        store.record_verification_sample(&sample_action_key(), 999, false, 10).unwrap();
    }
    let refused = dir.path().join("after-negative-evidence");
    assert_eq!(
        edge.serve_action(&sample_action_key(), &refused, &expected, now_micros(), 0)
            .unwrap(),
        ServeOutcome::ExecutePrivately(ReplayRefusal::FailedVerification { observations: 1 })
    );
    assert!(!refused.exists());

    let (divergent, divergent_bytes) = divergent_offer_with_manifest_bytes(&authority);
    store_manifest_object(&cas, &divergent, &divergent_bytes);
    assert!(matches!(
        coord.commit_offer(&divergent, &sample_expected_descriptor()).unwrap(),
        PublicationOutcome::Quarantined(_)
    ));
    let refused = dir.path().join("after-live-divergence");
    assert!(matches!(
        edge.serve_action(&sample_action_key(), &refused, &expected, now_micros(), 0)
            .unwrap(),
        ServeOutcome::NotServable(_)
    ));
    assert!(!refused.exists());
    let mut store = cas.store().lock().unwrap();
    let samples = store.list_verification_samples(&sample_action_key()).unwrap();
    assert_eq!(samples.iter().filter(|sample| !sample.passed).count(), 2);
    assert_eq!(
        store.query(
            "SELECT decision FROM decision_receipts WHERE kind = ?1 AND subject = ?2 AND seq = 0",
            &[
                SqlValue::Text("rabs-live-action-class-v1".to_owned()),
                SqlValue::Text(digest_key(&sample_action_key())),
            ],
        ).unwrap(),
        vec![vec![SqlValue::Text("rustc-dependency-compile".to_owned())]]
    );
}

fn live_manifest_fixture() -> (
    tempfile::TempDir, Arc<LiveCas>, CoordLive, OfferPreparedActionResult,
) {
    let dir = tempfile::tempdir().unwrap();
    let cas = Arc::new(mount_and_reconcile(&dir.path().join("cas")).unwrap());
    let coord = CoordLive::with_cas(Arc::clone(&cas));
    let authority = coord.acquire_boot_authority("manifest-fixture").unwrap();
    let (offer, bytes) = offer_with_manifest_bytes(&authority);
    {
        let mut store = cas.store().lock().unwrap();
        install_admission_world(&mut *store, &authority);
    }
    store_manifest_object(&cas, &offer, &bytes);
    coord.commit_offer(&offer, &sample_expected_descriptor()).unwrap();
    (dir, cas, coord, offer)
}

#[test]
fn live_manifest_loader_rejects_decodable_bytes_under_the_wrong_digest() {
    use std::os::unix::fs::PermissionsExt;
    let (dir, cas, coord, offer) = live_manifest_fixture();
    let key = digest_key(&offer.manifest_id.0);
    let location = {
        let mut store = cas.store().lock().unwrap();
        store.object_locations(&offer.manifest_id.0).unwrap().into_iter()
            .find(|(path, _, _)| std::path::Path::new(path).is_file()).unwrap().0
    };
    let (_, different_bytes) = divergent_offer_with_manifest_bytes(&offer.authority.coordinator);
    std::fs::set_permissions(&location, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(&location, &different_bytes).unwrap();
    {
        let mut store = cas.store().lock().unwrap();
        assert!(load_manifest(&mut *store, &key).is_none());
        assert!(store.object_locations(&offer.manifest_id.0).unwrap().iter()
            .all(|(path, _, _)| path != &location));
        assert_eq!(store.published_manifest_key(&sample_action_key()).unwrap(), Some(key));
    }
    let destination = dir.path().join("must-not-install");
    assert!(matches!(
        coord.serve_action(
            &sample_action_key(), &destination, &ExpectedOutputs::WhateverWasCommitted,
            now_micros(), 0,
        ).unwrap(),
        ServeOutcome::ManifestUnavailable { .. }
    ));
    assert!(!destination.exists());
}

#[test]
fn live_manifest_loader_uses_a_good_replica_but_respects_logical_quarantine() {
    use rabs_cas::blob_store::RAW_PROFILE_V1;
    use rabs_cas::metadata_store::QuarantineScope;
    let (dir, cas, _coord, offer) = live_manifest_fixture();
    let key = digest_key(&offer.manifest_id.0);
    let bad_replica = dir.path().join("000-bad-replica");
    std::fs::write(&bad_replica, b"corrupted replica").unwrap();
    let mut store = cas.store().lock().unwrap();
    store.add_location(
        &offer.manifest_id.0, bad_replica.to_str().unwrap(), Some(1), RAW_PROFILE_V1, true,
    ).unwrap();
    assert_eq!(load_manifest(&mut *store, &key), Some(offer.manifest.clone()));
    assert!(store.object_locations(&offer.manifest_id.0).unwrap().iter()
        .all(|(path, _, _)| path != bad_replica.to_str().unwrap()));
    store.add_quarantine(QuarantineScope::LogicalObject, &key, "suspect manifest").unwrap();
    assert!(load_manifest(&mut *store, &key).is_none());
}

#[test]
fn live_manifest_loader_bounds_oversized_files_before_decoding() {
    use std::os::unix::fs::PermissionsExt;
    let (_dir, cas, _coord, offer) = live_manifest_fixture();
    let mut store = cas.store().lock().unwrap();
    let location = store.object_locations(&offer.manifest_id.0).unwrap().into_iter()
        .find(|(path, _, _)| std::path::Path::new(path).is_file()).unwrap().0;
    std::fs::set_permissions(&location, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::File::create(&location).unwrap().set_len(16 * 1024 * 1024 + 1).unwrap();
    assert!(load_manifest(&mut *store, &digest_key(&offer.manifest_id.0)).is_none());
}
