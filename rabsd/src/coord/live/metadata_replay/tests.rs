//! Actual coordinator/CAS publication and phased installation. Compiler bytes,
//! descriptor enrollment and worker evidence are explicit fixture inputs; these
//! tests do not claim a Cargo/rustc execution or a network session.

use super::super::*;
use crate::janitor::store::mount_and_reconcile;
use rabs_cas::blob_store::{DurabilityPolicy, PutLimits, put_if_absent};
use rabs_cas::test_support::{
    FixtureAttemptIds, install_admission_world, install_admission_world_with_ids,
    install_offer_closure, offer_serving_object, sample_action_key, sample_evidence,
    sample_expected_descriptor,
};
use rabs_protocol::generation::{ActionGenerationId, AttemptId, ExecutionLeaseId};
use rabs_protocol::raw_bytes::RawBytes;
use rabs_protocol::result_identity::{LogicalOutput, OutputRole};
use std::os::unix::ffi::OsStrExt;

const HEAD: &[u8] = b"verified committed metadata fixture";
const TAIL: &[u8] = b"verified committed archive fixture";
const DEP_INFO: &[u8] = b"/__rabs/out/libfixture.rmeta:\n";

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
    let object = digest_set(bytes, DigestRequest::default(), None)
        .unwrap()
        .atp_content_id;
    put_if_absent(
        cas.layout(),
        &mut *cas.store().lock().unwrap(),
        &object,
        &mut &bytes[..],
        PutLimits::default(),
        DurabilityPolicy::FULL,
    )
    .unwrap();
    ObjectId(object)
}

impl Fixture {
    fn new() -> Self {
        let root = crate::test_util::private_tempdir();
        let cas = Arc::new(mount_and_reconcile(&root.path().join("cas")).unwrap());
        let coord = Arc::new(CoordLive::with_cas(Arc::clone(&cas)));
        let authority = coord
            .acquire_boot_authority("metadata-replay-fixture")
            .unwrap();
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
                    "explicit metadata replay fixture descriptor class",
                )
                .unwrap();
        }
        let head = put(&cas, HEAD);
        let tail = put(&cas, TAIL);
        let dep_info = put(&cas, DEP_INFO);
        let (base, _) = offer_serving_object(&authority, &tail);
        let mut manifest = base.manifest.clone();
        manifest.logical_outputs = vec![
            LogicalOutput {
                role: OutputRole::DepInfo,
                virtual_path: RawBytes::from("fixture.d"),
                object: dep_info,
            },
            LogicalOutput {
                role: OutputRole::Materializable,
                virtual_path: RawBytes::from("libfixture.rlib"),
                object: tail,
            },
            LogicalOutput {
                role: OutputRole::ProvisionalMetadata,
                virtual_path: RawBytes::from("libfixture.rmeta"),
                object: head,
            },
        ];
        let declared: Vec<_> = manifest
            .logical_outputs
            .iter()
            .map(|output| (output.role, output.virtual_path.clone()))
            .collect();
        let build = |id: ObjectId| {
            OfferPreparedActionResult::build(
                base.authority.clone(),
                manifest.clone(),
                id.clone(),
                sample_evidence(&id),
                base.evidence_id.clone(),
                base.canonical_observations.clone(),
                &declared,
                Vec::new(),
            )
            .unwrap()
        };
        let first = build(base.manifest_id.clone());
        let bytes = encode_manifest_v1(&first.manifest);
        let offer = build(put(&cas, &bytes));
        assert_eq!(encode_manifest_v1(&offer.manifest), bytes);
        install_offer_closure(&mut *cas.store().lock().unwrap(), &offer);
        assert!(matches!(
            coord
                .commit_offer(&offer, &sample_expected_descriptor())
                .unwrap(),
            PublicationOutcome::Committed(_)
        ));
        // Two separately fenced, admitted matching attempts establish the live
        // minimum and a durable replay allowance through the production path.
        for number in 1..=2 {
            let ids = FixtureAttemptIds {
                generation: 11 + number,
                attempt: 20 + number,
                lease: 30 + number,
            };
            install_admission_world_with_ids(&mut *cas.store().lock().unwrap(), &authority, ids);
            let mut comparison = offer.clone();
            comparison.authority.action_generation.generation_id =
                ActionGenerationId(ids.generation);
            comparison.authority.attempt_id = AttemptId(ids.attempt);
            comparison.authority.execution_lease_id = ExecutionLeaseId(ids.lease);
            assert_eq!(
                coord
                    .commit_offer(&comparison, &sample_expected_descriptor())
                    .unwrap(),
                PublicationOutcome::IdempotentEvidenceAppended,
            );
        }
        Self {
            root,
            cas,
            coord,
            offer,
        }
    }

    fn install(
        &self,
        destination: &Path,
        callback: Option<&mut dyn FnMut(&[PathBuf]) -> Result<(), String>>,
    ) -> Result<ServeOutcome, ServeError> {
        self.coord.serve_cached_result(
            &self.offer.manifest.action_key,
            &digest_key(&self.offer.manifest_id.0),
            destination,
            &ExpectedOutputs::WithDepInfo {
                paths: BTreeSet::from([
                    "fixture.d".into(),
                    "libfixture.rmeta".into(),
                    "libfixture.rlib".into(),
                ]),
                mappings: vec![(
                    b"/__rabs/out".to_vec(),
                    destination.as_os_str().as_bytes().to_vec(),
                )],
            },
            now_micros(),
            callback,
        )
    }

    fn installs(&self) -> i64 {
        let rows = self
            .cas
            .store()
            .lock()
            .unwrap()
            .query(
                "SELECT COUNT(*) FROM decision_receipts WHERE kind = ?1",
                &[SqlValue::Text(LIVE_INSTALL_RECEIPT.into())],
            )
            .unwrap();
        let [SqlValue::Int(count)] = rows[0].as_slice() else {
            panic!("install count shape")
        };
        *count
    }
}

#[test]
fn metadata_callback_unlocks_store_and_holds_every_destination_until_tail_finishes() {
    let fixture = Fixture::new();
    let destination = fixture.root.path().join("subscriber");
    let mut calls = 0;
    let mut ready = |files: &[PathBuf]| {
        calls += 1;
        assert_eq!(
            files,
            &[
                destination.join("libfixture.rmeta"),
                destination.join("fixture.d")
            ]
        );
        assert_eq!(std::fs::read(&files[0]).unwrap(), HEAD);
        assert_eq!(
            std::fs::read(&files[1]).unwrap(),
            format!("{}/libfixture.rmeta:\n", destination.display()).as_bytes()
        );
        assert!(!destination.join("libfixture.rlib").exists());
        assert!(
            fixture.cas.store().try_lock().is_ok(),
            "callback cannot hold the store mutex"
        );
        assert!(matches!(
            fixture.install(&destination, None),
            Err(ServeError::DestinationConflict { .. })
        ));
        Ok(())
    };
    assert!(
        matches!(fixture.install(&destination, Some(&mut ready)).unwrap(), ServeOutcome::Served { files } if files.len() == 3)
    );
    assert_eq!(calls, 1);
    assert_eq!(
        std::fs::read(destination.join("libfixture.rlib")).unwrap(),
        TAIL
    );
    assert_eq!(
        fixture.installs(),
        1,
        "a competing writer and a tail cannot spend extra allowance"
    );
}

#[test]
fn metadata_and_tail_complete_on_the_final_replay_allowance() {
    let fixture = Fixture::new();
    for index in 0..LIVE_REPLAY_INSTALL_LIMIT - 1 {
        assert!(matches!(
            fixture
                .install(&fixture.root.path().join(format!("earlier-{index}")), None)
                .unwrap(),
            ServeOutcome::Served { .. }
        ));
    }
    let destination = fixture.root.path().join("final-allowance");
    let mut called = false;
    let mut ready = |_: &[PathBuf]| {
        called = true;
        assert!(!destination.join("libfixture.rlib").exists());
        Ok(())
    };
    assert!(matches!(
        fixture.install(&destination, Some(&mut ready)).unwrap(),
        ServeOutcome::Served { .. }
    ));
    assert!(called);
    assert_eq!(
        fixture.installs(),
        i64::try_from(LIVE_REPLAY_INSTALL_LIMIT).unwrap()
    );
    assert_eq!(
        fixture
            .install(&fixture.root.path().join("requires-verification"), None)
            .unwrap(),
        ServeOutcome::ExecutePrivately(ReplayRefusal::FreshVerificationRequired)
    );
}

#[test]
fn metadata_delivery_is_sticky_across_receiver_authority_manifest_evidence_and_tail_failures() {
    for fault in ["receiver", "authority", "manifest", "evidence", "tail"] {
        let fixture = Fixture::new();
        let destination = fixture.root.path().join(fault);
        let mut ready = |_: &[PathBuf]| {
            match fault {
                "receiver" => return Err("metadata receiver disconnected".into()),
                "authority" => fixture.coord.mark_down(),
                "manifest" => {
                    fixture.cas.store().lock().unwrap().execute(
                        "UPDATE action_publications SET manifest_bytes = ?1 WHERE action_key = ?2",
                        &[SqlValue::Blob(vec![0; 32]), SqlValue::Text(digest_key(&fixture.offer.manifest.action_key))],
                    ).unwrap();
                }
                "evidence" => {
                    fixture
                        .cas
                        .store()
                        .lock()
                        .unwrap()
                        .record_verification_sample(
                            &fixture.offer.manifest.action_key,
                            999,
                            false,
                            999,
                        )
                        .unwrap();
                }
                "tail" => {
                    let source = fixture
                        .cas
                        .store()
                        .lock()
                        .unwrap()
                        .object_locations(
                            &fixture
                                .offer
                                .manifest
                                .logical_outputs
                                .iter()
                                .find(|output| output.role == OutputRole::Materializable)
                                .unwrap()
                                .object
                                .0,
                        )
                        .unwrap()[0]
                        .0
                        .clone();
                    std::fs::write(source, b"corrupted after metadata was acknowledged").unwrap();
                }
                _ => unreachable!(),
            }
            Ok(())
        };
        assert!(
            matches!(fixture.install(&destination, Some(&mut ready)), Err(ServeError::MetadataExposed { installed, .. }) if installed == vec![destination.join("libfixture.rmeta"), destination.join("fixture.d")]),
            "{fault}"
        );
        assert_eq!(
            std::fs::read(destination.join("libfixture.rmeta")).unwrap(),
            HEAD,
            "{fault}"
        );
        assert!(!destination.join("libfixture.rlib").exists(), "{fault}");
        assert_eq!(fixture.installs(), 1, "{fault}");
    }
}

#[test]
fn a_changed_preview_manifest_refuses_before_metadata_or_any_destination_write() {
    let fixture = Fixture::new();
    let destination = fixture.root.path().join("changed-preview");
    let mut ready =
        |_: &[PathBuf]| -> Result<(), String> { panic!("unbound manifest cannot expose metadata") };
    assert!(matches!(
        fixture
            .coord
            .serve_cached_result(
                &fixture.offer.manifest.action_key,
                "not-the-accepted-manifest",
                &destination,
                &ExpectedOutputs::WhateverWasCommitted,
                now_micros(),
                Some(&mut ready),
            )
            .unwrap(),
        ServeOutcome::ManifestUnavailable { .. }
    ));
    assert!(!destination.exists());
    assert_eq!(fixture.installs(), 0);
}
