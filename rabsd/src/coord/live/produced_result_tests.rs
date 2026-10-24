//! Current-producer installation through real CAS bytes and H011 publication.
//!
//! Compiler artifacts, descriptor enrollment and worker admission are explicit
//! test-support fixtures. These checks do not claim a rustc run or TLS session.

use super::*;
use crate::janitor::store::mount_and_reconcile;
use rabs_cas::blob_store::{DurabilityPolicy, PutLimits, PutOutcome, put_if_absent};
use rabs_cas::metadata_store::{ActionEntryRow, QuarantineScope};
use rabs_cas::test_support::{
    install_admission_world, install_offer_closure, offer_serving_object, sample_action_key,
    sample_expected_descriptor,
};
use rabs_protocol::result_identity::ObjectId;

const ARTIFACT: &[u8] = b"current producer's verified compiler output";
const CLUSTER: &str = "current-producer-tests";

struct Fixture {
    root: tempfile::TempDir,
    cas: Arc<LiveCas>,
    coord: Arc<CoordLive>,
    offer: OfferPreparedActionResult,
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

fn put(cas: &LiveCas, bytes: &[u8]) -> ObjectId {
    let digest = digest_set(bytes, DigestRequest::default(), None)
        .unwrap()
        .atp_content_id;
    let outcome = put_if_absent(
        cas.layout(),
        &mut *cas.store().lock().unwrap(),
        &digest,
        &mut &bytes[..],
        PutLimits::default(),
        DurabilityPolicy::FULL,
    )
    .unwrap();
    assert!(matches!(
        outcome,
        PutOutcome::Stored { .. } | PutOutcome::IdempotentDuplicate { .. }
    ));
    ObjectId(digest)
}

impl Fixture {
    fn new() -> Self {
        let root = crate::test_util::private_tempdir();
        let cas = Arc::new(mount_and_reconcile(&root.path().join("cas")).unwrap());
        let coord = Arc::new(CoordLive::with_cas(Arc::clone(&cas)));
        let authority = coord.acquire_boot_authority(CLUSTER).unwrap();
        coord.mark_up();
        {
            let mut store = cas.store().lock().unwrap();
            install_admission_world(&mut *store, &authority);
            store
                .record_decision_receipt(
                    LIVE_CLASS_RECEIPT,
                    &digest_key(&sample_action_key()),
                    0,
                    LIVE_DEPENDENCY_CLASS,
                    "synthetic descriptor class for producer-gate fixture",
                )
                .unwrap();
        }
        let object = put(&cas, ARTIFACT);
        let (offer, bytes) = offer_serving_object(&authority, &object);
        assert_eq!(put(&cas, &bytes), offer.manifest_id);
        install_offer_closure(&mut *cas.store().lock().unwrap(), &offer);
        assert!(matches!(
            coord
                .commit_offer(&offer, &sample_expected_descriptor())
                .unwrap(),
            PublicationOutcome::Committed(_)
        ));
        Self {
            root,
            cas,
            coord,
            offer,
        }
    }

    fn expected(&self) -> ExpectedOutputs {
        ExpectedOutputs::Exactly(BTreeSet::from(["out/lib.rlib".to_owned()]))
    }

    fn produce(&self, destination: &Path, manifest: &str) -> Result<ServeOutcome, ServeError> {
        self.coord.serve_produced_result(
            &self.offer.manifest.action_key,
            manifest,
            destination,
            &self.expected(),
            now_micros(),
        )
    }

    fn replay(&self, destination: &Path) -> ServeOutcome {
        self.coord
            .edge_subscriber()
            .serve_action(
                &self.offer.manifest.action_key,
                destination,
                &self.expected(),
                now_micros(),
                0,
            )
            .unwrap()
    }
}

#[test]
fn current_producer_pins_exact_manifest_and_does_not_grant_later_cache_replay() {
    let fixture = Fixture::new();
    let manifest = digest_key(&fixture.offer.manifest_id.0);
    let replay_refusal = ServeOutcome::ExecutePrivately(ReplayRefusal::Sampling(
        PrivateExecutionReason::InsufficientVerificationSamples {
            observed: 0,
            required: 2,
        },
    ));
    let before = fixture.root.path().join("replay-before-producer");
    assert_eq!(fixture.replay(&before), replay_refusal);
    assert!(!before.exists());

    let wrong = fixture.root.path().join("wrong-manifest");
    assert_eq!(
        fixture
            .produce(&wrong, "a-manifest-the-subscriber-did-not-accept")
            .unwrap(),
        ServeOutcome::ManifestUnavailable {
            key: manifest.clone()
        }
    );
    assert!(
        !wrong.exists(),
        "manifest mismatch must not create a target writer"
    );

    let destination = fixture.root.path().join("current-producer");
    assert!(matches!(
        fixture.produce(&destination, &manifest).unwrap(),
        ServeOutcome::Served { files } if files.len() == 1
    ));
    assert_eq!(
        std::fs::read(destination.join("out/lib.rlib")).unwrap(),
        ARTIFACT
    );
    assert!(
        fixture
            .cas
            .store()
            .lock()
            .unwrap()
            .list_verification_samples(&fixture.offer.manifest.action_key)
            .unwrap()
            .is_empty()
    );

    let after = fixture.root.path().join("replay-after-producer");
    assert_eq!(fixture.replay(&after), replay_refusal);
    assert!(
        !after.exists(),
        "primary-result installation cannot manufacture replay qualification"
    );
}

#[test]
fn current_producer_rechecks_running_and_durable_coordinator_authority() {
    let fixture = Fixture::new();
    let manifest = digest_key(&fixture.offer.manifest_id.0);
    fixture.coord.mark_down();
    let stopped = fixture.root.path().join("coordinator-stopped");
    assert_eq!(
        fixture.produce(&stopped, &manifest),
        Err(ServeError::CoordinatorUnavailable)
    );
    assert!(!stopped.exists());
    fixture.coord.mark_up();

    // The old owner still reports up and retains its in-memory authority. The
    // durable authority has moved, so its exact accepted manifest cannot write.
    let replacement = CoordLive::with_cas(Arc::clone(&fixture.cas));
    replacement.acquire_boot_authority(CLUSTER).unwrap();
    replacement.mark_up();
    let stale = fixture.root.path().join("authority-superseded");
    assert_eq!(
        fixture.produce(&stale, &manifest),
        Err(ServeError::CoordinatorUnavailable)
    );
    assert!(!stale.exists());
}

#[test]
fn current_producer_keeps_action_and_cross_key_class_negative_evidence_vetoes() {
    for other_action in [false, true] {
        let fixture = Fixture::new();
        let action = fixture.offer.manifest.action_key.clone();
        let expected = if other_action {
            let mut culprit = action.clone();
            culprit.bytes[0] ^= 1;
            let culprit_key = digest_key(&culprit);
            let mut store = fixture.cas.store().lock().unwrap();
            store
                .upsert_action_entry(&ActionEntryRow {
                    action_key: culprit,
                    key_epoch: 1,
                    projection_epoch: 1,
                })
                .unwrap();
            store
                .record_decision_receipt(
                    LIVE_CLASS_RECEIPT,
                    &culprit_key,
                    0,
                    LIVE_DEPENDENCY_CLASS,
                    "synthetic peer action for durable class-veto fixture",
                )
                .unwrap();
            store
                .add_quarantine(
                    QuarantineScope::ActionEntry,
                    &culprit_key,
                    "known class divergence",
                )
                .unwrap();
            // The requested publication itself is still servable: this proves
            // that the class veto is independent of its per-action disposition.
            assert_eq!(
                store
                    .serving_disposition_key(&digest_key(&action))
                    .unwrap()
                    .as_deref(),
                Some("servable")
            );
            ReplayRefusal::Sampling(PrivateExecutionReason::ClassSafetyHold {
                class: LIVE_DEPENDENCY_CLASS.to_owned(),
                culprit_action_key: culprit_key,
                reason: "action-quarantine",
            })
        } else {
            fixture
                .cas
                .store()
                .lock()
                .unwrap()
                .record_verification_sample(&action, 999_999, false, 999)
                .unwrap();
            ReplayRefusal::FailedVerification { observations: 1 }
        };
        let destination = fixture.root.path().join("negative-evidence");
        assert_eq!(
            fixture
                .produce(&destination, &digest_key(&fixture.offer.manifest_id.0))
                .unwrap(),
            ServeOutcome::ExecutePrivately(expected)
        );
        assert!(
            !destination.exists(),
            "current producer must not write after a safety veto"
        );
    }
}

#[test]
fn current_producer_still_requires_configured_release_authorization() {
    let fixture = Fixture::new();
    let required = CoordLive::with_cas(Arc::clone(&fixture.cas)).with_release_authorization(
        "unqualified-current-producer-build",
        ReleaseAuthorizationMode::Required,
    );
    required.acquire_boot_authority(CLUSTER).unwrap();
    required.mark_up();
    let destination = fixture.root.path().join("release-held");
    assert!(matches!(
        required
            .serve_produced_result(
                &fixture.offer.manifest.action_key,
                &digest_key(&fixture.offer.manifest_id.0),
                &destination,
                &fixture.expected(),
                now_micros(),
            )
            .unwrap(),
        ServeOutcome::ReleaseUnauthorized {
            standing: ReleaseAuthorization::Absent
        }
    ));
    assert!(!destination.exists());
}
