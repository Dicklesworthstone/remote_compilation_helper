//! Real CAS and filesystem installation with explicit synthetic capture owners.
//! These fixtures exercise custody/installation, not rustc execution or TLS.

use super::super::{CapturePins, LIVE_TRANSCRIPT_RECEIPT, object_id, put_bytes};
use super::*;
use crate::coord::live::ExpectedOutputs;
use crate::janitor::store::{LiveCas, mount_and_reconcile};
use rabs_cas::metadata_store::{QuarantineScope, RabsMetadataStore, SqlValue, digest_key};
use rabs_cas::test_support::offer_serving_object;
use rabs_protocol::generation::AttemptId;
use rabs_protocol::result_identity::ObjectId;
use std::cell::Cell;
use std::collections::BTreeSet;

const ARTIFACT: &[u8] = b"fresh request-owned compiler output";
const CLUSTER: &str = "request-owned-install-tests";

struct Fixture {
    root: tempfile::TempDir,
    cas: Arc<LiveCas>,
    coord: Arc<CoordLive>,
    key: TypedDigest,
    manifest: String,
    next_attempt: Cell<u128>,
}

impl Fixture {
    fn new() -> Self {
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

    fn capture(&self) -> RequestOwnedResult {
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

    fn expected(&self) -> ExpectedOutputs {
        ExpectedOutputs::Exactly(BTreeSet::from(["out/lib.rlib".to_owned()]))
    }

    fn install(
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
        )
    }

    fn assert_unpublished(&self) {
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
