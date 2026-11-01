//! Real CAS and filesystem installation with explicit synthetic capture owners.
//! These fixtures exercise custody/installation, not rustc execution or TLS.

use super::super::{CapturePins, LIVE_TRANSCRIPT_RECEIPT, object_id, put_bytes};
use super::*;
use crate::coord::live::ExpectedOutputs;
use crate::janitor::store::{LiveCas, mount_and_reconcile};
use rabs_cas::metadata_store::{QuarantineScope, RabsMetadataStore, SqlValue, digest_key};
use rabs_cas::publication::OfferPreparedActionResult;
use rabs_cas::test_support::{offer_serving_object, sample_evidence};
use rabs_protocol::generation::AttemptId;
use rabs_protocol::raw_bytes::RawBytes;
use rabs_protocol::result_identity::{LogicalOutput, ObjectId};
use std::cell::Cell;
use std::collections::BTreeSet;
use std::os::unix::ffi::OsStrExt;

const ARTIFACT: &[u8] = b"fresh request-owned compiler output";
const METADATA: &[u8] = b"fresh request-owned compiler metadata";
const DEP_INFO: &[u8] = b"/__rabs/out/lib.rmeta:\n";
const CLUSTER: &str = "request-owned-install-tests";

pub(super) struct Fixture {
    pub(super) root: tempfile::TempDir,
    cas: Arc<LiveCas>,
    coord: Arc<CoordLive>,
    key: TypedDigest,
    manifest: String,
    next_attempt: Cell<u128>,
}

impl Fixture {
    pub(super) fn new() -> Self {
        let root = crate::test_util::private_tempdir();
        let cas = Arc::new(mount_and_reconcile(&root.path().join("cas")).unwrap());
        let coord = Arc::new(CoordLive::with_cas(Arc::clone(&cas)));
        let authority = coord.acquire_boot_authority(CLUSTER).unwrap();
        coord.mark_up();
        let (offer, _) = offer_serving_object(&authority, &ObjectId(object_id(ARTIFACT).unwrap()));
        Self {
            root,
            cas,
            coord,
            key: offer.manifest.action_key,
            manifest: digest_key(&offer.manifest_id.0),
            next_attempt: Cell::new(1),
        }
    }

    pub(super) fn capture(&self) -> RequestOwnedResult {
        let authority = self.coord.authority().unwrap();
        let object = ObjectId(object_id(ARTIFACT).unwrap());
        let (mut offer, bytes) = offer_serving_object(&authority, &object);
        let attempt = self.next_attempt.get();
        self.next_attempt.set(attempt + 1);
        offer.authority.attempt_id = AttemptId(attempt);
        let mut pins = CapturePins::new(Arc::clone(&self.cas), &offer.authority);
        assert_eq!(put_bytes(&self.cas, ARTIFACT, &mut pins).unwrap(), object);
        assert_eq!(
            put_bytes(&self.cas, &bytes, &mut pins).unwrap(),
            offer.manifest_id
        );
        let transcript = put_bytes(&self.cas, b"", &mut pins).unwrap();
        RequestOwnedResult {
            captured: CapturedLocalResult {
                offer,
                transcript,
                manifest_key: self.manifest.clone(),
                known: Vec::new(),
                pins,
            },
        }
    }

    fn capture_with_metadata(&self, archive: bool) -> RequestOwnedResult {
        self.capture_metadata_bytes(METADATA, archive)
    }

    fn capture_metadata_bytes(&self, metadata: &[u8], archive: bool) -> RequestOwnedResult {
        let mut result = self.capture();
        let captured = &mut result.captured;
        let metadata = put_bytes(&self.cas, metadata, &mut captured.pins).unwrap();
        let dep_info = put_bytes(&self.cas, DEP_INFO, &mut captured.pins).unwrap();
        let base = captured.offer.clone();
        let mut manifest = base.manifest.clone();
        manifest.logical_outputs = vec![
            LogicalOutput {
                role: OutputRole::DepInfo,
                virtual_path: RawBytes::from("out/lib.d"),
                object: dep_info,
            },
            LogicalOutput {
                role: OutputRole::ProvisionalMetadata,
                virtual_path: RawBytes::from("out/lib.rmeta"),
                object: metadata,
            },
        ];
        if archive {
            manifest
                .logical_outputs
                .push(base.manifest.logical_outputs[0].clone());
        }
        let declared = manifest
            .logical_outputs
            .iter()
            .map(|output| (output.role, output.virtual_path.clone()))
            .collect::<Vec<_>>();
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
        let bytes = rabs_cas::manifest_codec::encode_manifest_v1(&first.manifest);
        let id = put_bytes(&self.cas, &bytes, &mut captured.pins).unwrap();
        captured.offer = build(id);
        captured.manifest_key = digest_key(&captured.offer.manifest_id.0);
        assert_eq!(
            rabs_cas::manifest_codec::encode_manifest_v1(&captured.offer.manifest),
            bytes
        );
        result
    }

    fn install_with_metadata(
        &self,
        result: RequestOwnedResult,
        destination: &Path,
        verify: impl Fn() -> Result<(), String>,
        callback: &mut dyn FnMut(&[PathBuf]) -> Result<(), String>,
    ) -> Result<Vec<PathBuf>, RequestOwnedInstallError> {
        let manifest = result.captured.manifest_key.clone();
        let expected = ExpectedOutputs::WithDepInfo {
            paths: result
                .manifest()
                .logical_outputs
                .iter()
                .map(|output| String::from_utf8(output.virtual_path.as_bytes().to_vec()).unwrap())
                .collect(),
            mappings: vec![(
                b"/__rabs/out".to_vec(),
                destination.join("out").as_os_str().as_bytes().to_vec(),
            )],
        };
        self.coord.install_request_owned_result(
            result,
            &self.key,
            &manifest,
            destination,
            &expected,
            verify,
            Some(callback),
        )
    }

    fn expected(&self) -> ExpectedOutputs {
        ExpectedOutputs::Exactly(BTreeSet::from(["out/lib.rlib".to_owned()]))
    }

    pub(super) fn install(
        &self,
        result: RequestOwnedResult,
        destination: &Path,
        verify: impl Fn() -> Result<(), String>,
    ) -> Result<Vec<PathBuf>, RequestOwnedInstallError> {
        self.coord.install_request_owned_result(
            result,
            &self.key,
            &self.manifest,
            destination,
            &self.expected(),
            verify,
            None,
        )
    }

    pub(super) fn assert_unpublished(&self) {
        let mut store = self.cas.store().lock().unwrap();
        assert!(store.published_manifest_key(&self.key).unwrap().is_none());
        assert!(
            store
                .list_verification_samples(&self.key)
                .unwrap()
                .is_empty()
        );
        assert!(
            store
                .query(
                    "SELECT decision FROM decision_receipts WHERE kind = ?1 AND subject = ?2",
                    &[
                        SqlValue::Text(LIVE_TRANSCRIPT_RECEIPT.into()),
                        SqlValue::Text(digest_key(&self.key)),
                    ],
                )
                .unwrap()
                .is_empty()
        );
    }

    fn active_capture_pins(&self) -> usize {
        self.cas
            .store()
            .lock()
            .unwrap()
            .query(
                "SELECT id_hex FROM pins WHERE class = ?1 AND released = 0",
                &[SqlValue::Text("live-dependency-capture-v1".into())],
            )
            .unwrap()
            .len()
    }
}

#[test]
fn fresh_request_installs_only_declared_files_without_publication_or_replay() {
    let fixture = Fixture::new();
    let destination = fixture.root.path().join("cargo-deps");
    std::fs::create_dir_all(destination.join("out")).unwrap();
    std::fs::write(destination.join("out/lib.rlib"), b"previous output").unwrap();
    std::fs::write(destination.join("unrelated.rmeta"), b"another unit").unwrap();
    let owner = fixture.capture();
    assert!(fixture.active_capture_pins() >= 3);
    fixture.assert_unpublished();
    let checks = Cell::new(0);
    let files = fixture
        .install(owner, &destination, || {
            checks.set(checks.get() + 1);
            assert!(fixture.active_capture_pins() >= 3);
            Ok(())
        })
        .unwrap();
    assert_eq!(
        checks.get(),
        2,
        "revalidate again after expensive private staging"
    );
    assert_eq!(files, vec![destination.join("out/lib.rlib")]);
    assert_eq!(std::fs::read(&files[0]).unwrap(), ARTIFACT);
    assert_eq!(
        std::fs::read(destination.join("unrelated.rmeta")).unwrap(),
        b"another unit"
    );
    assert_eq!(fixture.active_capture_pins(), 0);
    fixture.assert_unpublished();
    let replay = fixture.root.path().join("later-cache-reader");
    let outcome = fixture
        .coord
        .edge_subscriber()
        .serve_action(&fixture.key, &replay, &fixture.expected(), now_micros(), 0)
        .unwrap();
    assert!(!matches!(
        outcome,
        ServeOutcome::Served { .. } | ServeOutcome::Servable
    ));
    assert!(!replay.exists());
}

#[test]
fn separately_owned_equal_outputs_remain_private_and_inode_isolated() {
    let fixture = Fixture::new();
    let first = fixture.root.path().join("first");
    fixture
        .install(fixture.capture(), &first, || Ok(()))
        .unwrap();
    std::fs::write(first.join("out/lib.rlib"), b"caller mutation").unwrap();
    // The second owner represents a second fresh result, never a lookup or
    // adoption of the first request's installation capability.
    let second = fixture.root.path().join("second");
    fixture
        .install(fixture.capture(), &second, || Ok(()))
        .unwrap();
    assert_eq!(
        std::fs::read(second.join("out/lib.rlib")).unwrap(),
        ARTIFACT
    );
    fixture.assert_unpublished();
    assert_eq!(fixture.active_capture_pins(), 0);
}

#[test]
fn wrong_manifest_or_action_acknowledgment_never_creates_target_output() {
    for wrong_action in [false, true] {
        let fixture = Fixture::new();
        let destination = fixture.root.path().join("wrong-acknowledgment");
        let mut key = fixture.key.clone();
        if wrong_action {
            key.bytes[0] ^= 1;
        }
        let manifest = if wrong_action {
            fixture.manifest.as_str()
        } else {
            "other-manifest"
        };
        let result = fixture.coord.install_request_owned_result(
            fixture.capture(),
            &key,
            manifest,
            &destination,
            &fixture.expected(),
            || Ok(()),
            None,
        );
        assert!(matches!(result, Err(RequestOwnedInstallError::Declined(_))));
        assert!(!destination.exists());
        assert_eq!(fixture.active_capture_pins(), 0);
        fixture.assert_unpublished();
    }
}

#[test]
fn changed_request_after_staging_declines_before_first_destination_write() {
    let fixture = Fixture::new();
    let destination = fixture.root.path().join("changed-inputs");
    std::fs::create_dir_all(destination.join("out")).unwrap();
    std::fs::write(destination.join("out/lib.rlib"), b"original output").unwrap();
    let checks = Cell::new(0);
    let result = fixture.install(fixture.capture(), &destination, || {
        checks.set(checks.get() + 1);
        if checks.get() == 2 {
            Err("source generation changed".into())
        } else {
            Ok(())
        }
    });
    assert!(
        matches!(result, Err(RequestOwnedInstallError::Declined(reason))
        if reason.contains("source generation changed"))
    );
    assert_eq!(
        std::fs::read(destination.join("out/lib.rlib")).unwrap(),
        b"original output"
    );
    assert_eq!(fixture.active_capture_pins(), 0);
    fixture.assert_unpublished();
}

#[test]
fn coordinator_replacement_during_staging_fences_fresh_result() {
    let fixture = Fixture::new();
    let destination = fixture.root.path().join("stale-coordinator");
    let replacement = CoordLive::with_cas(Arc::clone(&fixture.cas));
    let checks = Cell::new(0);
    let result = fixture.install(fixture.capture(), &destination, || {
        checks.set(checks.get() + 1);
        if checks.get() == 2 {
            replacement.acquire_boot_authority(CLUSTER).unwrap();
            replacement.mark_up();
        }
        Ok(())
    });
    assert!(matches!(result, Err(RequestOwnedInstallError::Declined(_))));
    assert!(!destination.join("out/lib.rlib").exists());
    fixture.assert_unpublished();
}

#[test]
fn object_quarantine_after_staging_still_prevents_fresh_result_installation() {
    let fixture = Fixture::new();
    let destination = fixture.root.path().join("quarantined");
    let checks = Cell::new(0);
    let result = fixture.install(fixture.capture(), &destination, || {
        checks.set(checks.get() + 1);
        if checks.get() == 2 {
            fixture
                .cas
                .store()
                .lock()
                .unwrap()
                .add_quarantine(
                    QuarantineScope::LogicalObject,
                    &digest_key(&object_id(ARTIFACT).unwrap()),
                    "fixture object quarantined after private staging",
                )
                .unwrap();
        }
        Ok(())
    });
    assert!(matches!(result, Err(RequestOwnedInstallError::Fault(_))));
    assert!(!destination.join("out/lib.rlib").exists());
    assert_eq!(fixture.active_capture_pins(), 0);
    fixture.assert_unpublished();
}

#[test]
fn abandoned_private_capture_releases_only_capture_pins_without_installation() {
    let fixture = Fixture::new();
    let first = fixture.capture();
    let second = fixture.capture();
    let both = fixture.active_capture_pins();
    assert!(both >= 6);
    drop(first);
    assert_eq!(fixture.active_capture_pins(), both / 2);
    drop(second);
    assert_eq!(fixture.active_capture_pins(), 0);
    fixture.assert_unpublished();
}

#[test]
fn shared_flight_conversion_refuses_affine_workspace_custody() {
    let fixture = Fixture::new();
    let captured = fixture.capture();
    let output = Arc::new(RemoteOutput {
        manifest: captured.manifest().clone(),
        manifest_key: fixture.manifest.clone(),
        canonical_transcript: b"private workspace transcript".to_vec(),
    });
    assert!(fixture.active_capture_pins() >= 3);
    let refused = RemoteInstallAuthority::RequestOwned(Box::new(captured))
        .into_shared_output(Arc::clone(&output));
    assert!(
        refused
            .unwrap_err()
            .contains("workspace execution cannot enter a shared result")
    );
    // Rejecting fan-out drops exactly this affine capture, releases its pins,
    // and creates no publication, sample, transcript index or target writer.
    assert_eq!(fixture.active_capture_pins(), 0);
    assert_eq!(Arc::strong_count(&output), 1);
    fixture.assert_unpublished();
}

#[test]
fn request_owned_metadata_precedes_archive_and_keeps_pins_and_destination_ownership() {
    let fixture = Fixture::new();
    let destination = fixture.root.path().join("metadata-first");
    let owner = fixture.capture_with_metadata(true);
    let capture_pins = fixture.active_capture_pins();
    let checks = Cell::new(0);
    let mut calls = 0;
    let files = fixture
        .install_with_metadata(
            owner,
            &destination,
            || {
                checks.set(checks.get() + 1);
                assert_eq!(fixture.active_capture_pins(), capture_pins);
                Ok(())
            },
            &mut |files: &[PathBuf]| {
                calls += 1;
                assert_eq!(
                    files,
                    &[
                        destination.join("out/lib.rmeta"),
                        destination.join("out/lib.d"),
                    ]
                );
                assert_eq!(std::fs::read(&files[0]).unwrap(), METADATA);
                assert_eq!(
                    std::fs::read(&files[1]).unwrap(),
                    format!("{}/out/lib.rmeta:\n", destination.display()).as_bytes()
                );
                assert!(!destination.join("out/lib.rlib").exists());
                assert!(fixture.cas.store().try_lock().is_ok());
                assert_eq!(fixture.active_capture_pins(), capture_pins);
                fixture.assert_unpublished();
                // This fresh competing owner claims only the archive. It must
                // still conflict while the first owner's head awaits its ACK.
                let competing = fixture.install(fixture.capture(), &destination, || Ok(()));
                assert!(matches!(
                    competing,
                    Err(RequestOwnedInstallError::Declined(reason))
                        if reason.contains("destination")
                ));
                assert_eq!(fixture.active_capture_pins(), capture_pins);
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(calls, 1);
    assert_eq!(checks.get(), 4);
    assert_eq!(files.len(), 3);
    assert_eq!(
        std::fs::read(destination.join("out/lib.rlib")).unwrap(),
        ARTIFACT
    );
    assert_eq!(fixture.active_capture_pins(), 0);
    fixture.assert_unpublished();
    // Returning the writer releases the whole reservation. A separately owned
    // fresh execution can install later, without adopting the consumed owner.
    fixture
        .install(fixture.capture(), &destination, || Ok(()))
        .unwrap();
}

#[test]
fn request_owned_metadata_callback_failure_is_exposed_and_leaves_tail_private() {
    let fixture = Fixture::new();
    let destination = fixture.root.path().join("receiver-lost");
    let result = fixture.install_with_metadata(
        fixture.capture_with_metadata(true),
        &destination,
        || Ok(()),
        &mut |_| Err("exact metadata ACK was not received".into()),
    );
    assert!(matches!(
        result,
        Err(RequestOwnedInstallError::MetadataExposed(reason))
            if reason.contains("ACK was not received")
    ));
    assert_eq!(
        std::fs::read(destination.join("out/lib.rmeta")).unwrap(),
        METADATA
    );
    assert!(!destination.join("out/lib.rlib").exists());
    assert_eq!(fixture.active_capture_pins(), 0);
    fixture.assert_unpublished();
}

#[test]
fn request_owned_metadata_ack_rechecks_input_and_coordinator_ownership() {
    for fault in ["inputs", "coordinator-down", "coordinator-replaced"] {
        let fixture = Fixture::new();
        let destination = fixture.root.path().join(fault);
        let input_changed = Cell::new(false);
        let replacement = CoordLive::with_cas(Arc::clone(&fixture.cas));
        let result = fixture.install_with_metadata(
            fixture.capture_with_metadata(true),
            &destination,
            || {
                if input_changed.get() {
                    Err("retained input generation changed during metadata ACK".into())
                } else {
                    Ok(())
                }
            },
            &mut |_| {
                match fault {
                    "inputs" => input_changed.set(true),
                    "coordinator-down" => fixture.coord.mark_down(),
                    "coordinator-replaced" => {
                        replacement.acquire_boot_authority(CLUSTER).unwrap();
                        replacement.mark_up();
                    }
                    _ => unreachable!(),
                }
                Ok(())
            },
        );
        assert!(
            matches!(result, Err(RequestOwnedInstallError::MetadataExposed(_))),
            "{fault}: {result:?}"
        );
        assert_eq!(
            std::fs::read(destination.join("out/lib.rmeta")).unwrap(),
            METADATA,
            "{fault}"
        );
        assert!(!destination.join("out/lib.rlib").exists(), "{fault}");
        assert_eq!(fixture.active_capture_pins(), 0);
        fixture.assert_unpublished();
    }
}

#[test]
fn request_owned_metadata_ack_cannot_accept_corrupted_or_displaced_head_outputs() {
    for archive in [false, true] {
        for name in ["lib.d", "lib.rmeta"] {
            for displaced in [false, true] {
                let fixture = Fixture::new();
                let destination = fixture.root.path().join("changed-metadata-head");
                let owner = fixture.capture_with_metadata(archive);
                let mut calls = 0;
                let result =
                    fixture.install_with_metadata(owner, &destination, || Ok(()), &mut |files| {
                        calls += 1;
                        let path = destination.join("out").join(name);
                        assert!(files.contains(&path));
                        assert!(!destination.join("out/lib.rlib").exists());
                        if displaced {
                            // Preserve the original fixture bytes while making
                            // the acknowledged destination disappear.
                            std::fs::rename(&path, path.with_extension("displaced")).unwrap();
                        } else {
                            std::fs::write(&path, b"corrupted while metadata ACK was pending")
                                .unwrap();
                        }
                        Ok(())
                    });
                assert_eq!(calls, 1);
                assert!(
                    matches!(&result, Err(RequestOwnedInstallError::MetadataExposed(_))),
                    "archive={archive} name={name} displaced={displaced}: {result:?}",
                );
                assert!(!destination.join("out/lib.rlib").exists());
                assert_eq!(fixture.active_capture_pins(), 0);
                fixture.assert_unpublished();
                // The terminal exposed failure releases this owner's complete
                // reservation without allowing it to rerun or publish a result.
                fixture
                    .install_with_metadata(
                        fixture.capture_with_metadata(archive),
                        &destination,
                        || Ok(()),
                        &mut |_| Ok(()),
                    )
                    .unwrap();
                assert_eq!(fixture.active_capture_pins(), 0);
                fixture.assert_unpublished();
            }
        }
    }
}

#[test]
fn request_owned_metadata_head_is_rechecked_after_tail_preparation() {
    let fixture = Fixture::new();
    let destination = fixture
        .root
        .path()
        .join("head-changed-during-tail-preparation");
    let checks = Cell::new(0);
    let result = fixture.install_with_metadata(
        fixture.capture_with_metadata(true),
        &destination,
        || {
            checks.set(checks.get() + 1);
            if checks.get() == 4 {
                // This is the original-request check after private tail
                // preparation, before the archive may be renamed into place.
                std::fs::write(destination.join("out/lib.d"), b"changed after tail staging")
                    .unwrap();
            }
            Ok(())
        },
        &mut |_| Ok(()),
    );
    assert_eq!(checks.get(), 4);
    assert!(matches!(
        result,
        Err(RequestOwnedInstallError::MetadataExposed(_))
    ));
    assert!(!destination.join("out/lib.rlib").exists());
    assert_eq!(fixture.active_capture_pins(), 0);
    fixture.assert_unpublished();
}

#[test]
fn request_owned_metadata_tail_corruption_fails_after_head_exposure() {
    let fixture = Fixture::new();
    let destination = fixture.root.path().join("tail-corrupted-after-ack");
    let result = fixture.install_with_metadata(
        fixture.capture_with_metadata(true),
        &destination,
        || Ok(()),
        &mut |_| {
            let source = fixture
                .cas
                .store()
                .lock()
                .unwrap()
                .object_locations(&object_id(ARTIFACT).unwrap())
                .unwrap()[0]
                .0
                .clone();
            // Corruption here must fail the subsequent tail copy. If the
            // archive had already been staged, this test would wrongly succeed.
            std::fs::write(source, b"changed after the metadata head was acknowledged").unwrap();
            Ok(())
        },
    );
    assert!(matches!(
        result,
        Err(RequestOwnedInstallError::MetadataExposed(_))
    ));
    assert_eq!(
        std::fs::read(destination.join("out/lib.rmeta")).unwrap(),
        METADATA
    );
    assert!(!destination.join("out/lib.rlib").exists());
    assert_eq!(fixture.active_capture_pins(), 0);
    fixture.assert_unpublished();
}

#[test]
fn request_owned_metadata_tail_quarantine_prevents_installation_after_ack() {
    let fixture = Fixture::new();
    let destination = fixture.root.path().join("tail-quarantined-after-ack");
    let result = fixture.install_with_metadata(
        fixture.capture_with_metadata(true),
        &destination,
        || Ok(()),
        &mut |_| {
            fixture
                .cas
                .store()
                .lock()
                .unwrap()
                .add_quarantine(
                    QuarantineScope::LogicalObject,
                    &digest_key(&object_id(ARTIFACT).unwrap()),
                    "tail quarantined while the metadata ACK was in flight",
                )
                .unwrap();
            Ok(())
        },
    );
    assert!(matches!(
        result,
        Err(RequestOwnedInstallError::MetadataExposed(_))
    ));
    assert!(!destination.join("out/lib.rlib").exists());
    assert_eq!(fixture.active_capture_pins(), 0);
    fixture.assert_unpublished();
}

#[test]
fn request_owned_metadata_without_archive_still_fences_acknowledgment() {
    for changed in [false, true] {
        let fixture = Fixture::new();
        let destination = fixture.root.path().join("metadata-only");
        let input_changed = Cell::new(false);
        let mut calls = 0;
        let result = fixture.install_with_metadata(
            fixture.capture_with_metadata(false),
            &destination,
            || {
                if input_changed.get() {
                    Err("metadata-only request changed".into())
                } else {
                    Ok(())
                }
            },
            &mut |_| {
                calls += 1;
                input_changed.set(changed);
                Ok(())
            },
        );
        assert_eq!(calls, 1);
        if changed {
            assert!(matches!(
                result,
                Err(RequestOwnedInstallError::MetadataExposed(_))
            ));
        } else {
            assert_eq!(result.unwrap().len(), 2);
        }
        assert_eq!(fixture.active_capture_pins(), 0);
        fixture.assert_unpublished();
    }
}

#[test]
fn request_owned_nonmetadata_outputs_do_not_offer_a_metadata_head() {
    let fixture = Fixture::new();
    let destination = fixture.root.path().join("archive-only");
    let result = fixture.coord.install_request_owned_result(
        fixture.capture(),
        &fixture.key,
        &fixture.manifest,
        &destination,
        &fixture.expected(),
        || Ok(()),
        Some(&mut |_| panic!("an archive alone cannot authorize metadata notification")),
    );
    assert_eq!(result.unwrap(), vec![destination.join("out/lib.rlib")]);
    assert_eq!(fixture.active_capture_pins(), 0);
    fixture.assert_unpublished();
}

#[test]
fn request_owned_metadata_binding_failure_never_calls_receiver_or_writes_outputs() {
    let fixture = Fixture::new();
    let destination = fixture.root.path().join("wrong-metadata-capture");
    let result = fixture.coord.install_request_owned_result(
        fixture.capture_with_metadata(true),
        &fixture.key,
        &fixture.manifest,
        &destination,
        &fixture.expected(),
        || Ok(()),
        Some(&mut |_| panic!("a foreign capture cannot authorize metadata notification")),
    );
    assert!(matches!(result, Err(RequestOwnedInstallError::Declined(_))));
    assert!(!destination.exists());
    assert_eq!(fixture.active_capture_pins(), 0);
    fixture.assert_unpublished();
}

#[test]
fn request_owned_empty_metadata_keeps_the_complete_delivery_protocol() {
    let fixture = Fixture::new();
    let destination = fixture.root.path().join("valid-empty-workspace-metadata");
    let owner = fixture.capture_metadata_bytes(b"", false);
    let output = RemoteOutput {
        manifest: owner.manifest().clone(),
        manifest_key: owner.captured.manifest_key.clone(),
        canonical_transcript: Vec::new(),
    };
    assert!(!output.has_nonempty_metadata());
    let expected = ExpectedOutputs::WithDepInfo {
        paths: BTreeSet::from(["out/lib.d".into(), "out/lib.rmeta".into()]),
        mappings: vec![(
            b"/__rabs/out".to_vec(),
            destination.join("out").as_os_str().as_bytes().to_vec(),
        )],
    };
    let files = fixture
        .coord
        .install_request_owned_result(
            owner,
            &fixture.key,
            &output.manifest_key,
            &destination,
            &expected,
            || Ok(()),
            None,
        )
        .unwrap();
    assert_eq!(files.len(), 2);
    assert_eq!(
        std::fs::read(destination.join("out/lib.rmeta")).unwrap(),
        b""
    );
    assert_eq!(
        std::fs::read(destination.join("out/lib.d")).unwrap(),
        format!("{}/out/lib.rmeta:\n", destination.display()).as_bytes()
    );
    assert_eq!(fixture.active_capture_pins(), 0);
    fixture.assert_unpublished();

    let nonempty = fixture.capture_with_metadata(false);
    let output = RemoteOutput {
        manifest: nonempty.manifest().clone(),
        manifest_key: nonempty.captured.manifest_key.clone(),
        canonical_transcript: Vec::new(),
    };
    assert!(output.has_nonempty_metadata());
}
