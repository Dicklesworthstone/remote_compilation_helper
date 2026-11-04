//! Retention across the live compiler capture/acknowledgment/publication handoff.
//!
//! A durable location is not a GC root. Pin each object under the SAME store
//! lock that installs its location, including objects already in CAS. Keep the
//! owner through publication, whose transaction installs its independent roots.
//! Normal abandonment releases only this capture's pins. Process loss or a
//! failed release retains durable pins for reconciliation; no clock expires
//! an unacknowledged capture and no file is deleted by this owner.

use crate::janitor::store::LiveCas;
use rabs_cas::metadata_store::{RabsMetadataStore, digest_key};
use rabs_cas::pin_leases::{ReleaseOutcome, Releaser, release_pin_scoped};
use rabs_cas::publication::authority_digest;
use rabs_key::typed_digest::compute;
use rabs_protocol::generation::AttemptAuthority;
use rabs_protocol::result_identity::{DigestAlgorithm, TypedDigest};
use std::collections::BTreeMap;
use std::sync::Arc;

mod recovery;

const CAPTURE_PIN_CLASS: &str = "live-dependency-capture-v1";

fn field(bytes: &mut Vec<u8>, value: &[u8]) {
    bytes.extend_from_slice(&(value.len() as u64).to_le_bytes());
    bytes.extend_from_slice(value);
}

fn digest_field(bytes: &mut Vec<u8>, value: &TypedDigest) {
    // Exhaustive: adding an algorithm must explicitly extend pin identity.
    match value.algorithm {
        DigestAlgorithm::Sha256V1 => field(bytes, b"sha256-v1"),
    }
    field(bytes, value.domain.as_bytes());
    field(bytes, &value.bytes);
}

fn capture_owner(authority: &AttemptAuthority) -> String {
    let mut bytes = Vec::new();
    digest_field(&mut bytes, &authority_digest(&authority.coordinator));
    digest_field(&mut bytes, &authority.action_key);
    field(
        &mut bytes,
        &authority.action_generation.generation_id.0.to_le_bytes(),
    );
    field(&mut bytes, &authority.attempt_id.0.to_le_bytes());
    field(&mut bytes, &authority.execution_lease_id.0.to_le_bytes());
    digest_key(&compute("rabs.live-dependency.capture-owner.v1", &bytes))
}

fn pin_id(owner: &str, root: &TypedDigest) -> u128 {
    let mut bytes = Vec::new();
    field(&mut bytes, owner.as_bytes());
    digest_field(&mut bytes, root);
    let hash = compute("rabs.live-dependency.capture-pin.v1", &bytes);
    let mut id = [0; 16];
    id.copy_from_slice(&hash.bytes[..16]);
    u128::from_le_bytes(id)
}

/// An affine, attempt-bound owner, not a global pin shared by equal results.
/// No `Clone`: one capture cannot release a sibling capture's protection.
#[derive(Debug)]
pub(super) struct CapturePins {
    cas: Arc<LiveCas>,
    owner: String,
    authority: AttemptAuthority,
    held: BTreeMap<u128, TypedDigest>,
}

impl CapturePins {
    pub(super) fn new(cas: Arc<LiveCas>, authority: &AttemptAuthority) -> Self {
        Self {
            cas,
            owner: capture_owner(authority),
            authority: authority.clone(),
            held: BTreeMap::new(),
        }
    }

    /// Caller holds this mount's metadata lock through pin + object/location
    /// publication. No collection can interleave in an unprotected interval.
    pub(super) fn protect(
        &mut self,
        store: &mut dyn RabsMetadataStore,
        root: &TypedDigest,
    ) -> Result<(), String> {
        let id = pin_id(&self.owner, root);
        let existing = store
            .pin_row(id)
            .map_err(|error| format!("capture pin: {error:?}"))?;
        if let Some(held) = self.held.get(&id) {
            if held == root
                && existing.is_some_and(|row| {
                    row.owner == self.owner
                        && row.class == CAPTURE_PIN_CLASS
                        && row.root_key == digest_key(root)
                        && !row.released
                })
            {
                return Ok(());
            }
            return Err("capture pin changed or collided".into());
        }
        // Neither an old released pin nor another capture's pin is adopted.
        // A truncated-ID collision must refuse, never overwrite or release it.
        if existing.is_some() {
            return Err("capture pin identity already exists".into());
        }
        // Root and attempt witness share create_pin's durable transaction.
        // Encoding failure must not leave an unjournaled new capture pin.
        let evidence = recovery::evidence(&self.authority, root)?;
        store
            .create_pin(
                id,
                root,
                &self.owner,
                CAPTURE_PIN_CLASS,
                None,
                Some(&evidence),
                true,
                "compiler result capture awaiting acknowledgment/publication",
            )
            .map_err(|error| format!("create capture pin: {error:?}"))?;
        self.held.insert(id, root.clone());
        Ok(())
    }
}

impl Drop for CapturePins {
    fn drop(&mut self) {
        if self.held.is_empty() {
            return;
        }
        let Ok(mut store) = self.cas.store().lock() else {
            eprintln!("rabsd: retaining compiler capture pins after poisoned store lock");
            return;
        };
        // Check the class as well as the owner: even contradictory metadata
        // cannot turn capture abandonment into publication/incident release.
        let releaser = Releaser::Worker(self.owner.clone());
        for (id, root) in &self.held {
            if !matches!(store.pin_row(*id), Ok(Some(row))
                if row.owner == self.owner && row.class == CAPTURE_PIN_CLASS
                    && row.root_key == digest_key(root))
            {
                eprintln!("rabsd: retaining changed compiler capture pin {id:032x}");
                continue;
            }
            match release_pin_scoped(&mut *store, *id, &releaser) {
                Ok(ReleaseOutcome::Released | ReleaseOutcome::AlreadyReleased) => {}
                other => eprintln!(
                    "rabsd: compiler capture pin {id:032x} release unconfirmed: {other:?}"
                ),
            }
        }
        // Drain old-incarnation custody only AFTER this capture's ordinary
        // handoff. Keep the same exclusive mount/store lock. Recovery is one
        // bounded page per capture, not a full-history scan on rustc admission;
        // its durable authority-scoped cursor makes later captures resume it.
        // Failure retains unreconciled roots and cannot change compiler status
        // or undo a publication that has already acquired independent pins.
        match recovery::reconcile_page(&mut *store, &self.authority.coordinator) {
            Ok(page) if page.released != 0 => eprintln!(
                "rabsd: recovered {} fenced capture pins (scanned {}, complete {})",
                page.released, page.scanned, page.complete
            ),
            Ok(_) => {}
            Err(error) => eprintln!("rabsd: capture recovery incomplete: {error}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::output_capture::put_output;
    use super::super::{put_bundle_root, put_bytes};
    use super::*;
    use crate::janitor::store::mount_and_reconcile;
    use rabs_cas::gc::{GcMode, GcWorld, plan_gc};
    use rabs_cas::materialization::{MaterializationMode, MaterializeError, materialize_object};
    use rabs_protocol::authority::{ClusterId, CoordinatorAuthority, CoordinatorIncarnationId};
    use rabs_protocol::generation::{
        ActionGeneration, ActionGenerationId, AttemptId, ExecutionLeaseId, LeaseRenewalSeq,
        WorkerBootGeneration, WorkerIncarnationId,
    };
    use rabs_protocol::raw_bytes::RawBytes;
    use rabs_protocol::result_identity::{LogicalOutput, OutputRole};
    use rabs_protocol::wire_time::PeerId;

    pub(super) fn authority(attempt: u128) -> AttemptAuthority {
        let coordinator = CoordinatorAuthority {
            cluster_id: ClusterId("capture-tests".into()),
            credential_generation: 1,
            term: 1,
            incarnation_id: CoordinatorIncarnationId(1),
        };
        AttemptAuthority {
            action_generation: ActionGeneration {
                generation_id: ActionGenerationId(9),
                per_key_ordinal: 1,
                created_under_authority_digest: authority_digest(&coordinator),
            },
            coordinator,
            action_key: compute("rabs.action-key.sha256.v1", b"capture-test"),
            attempt_id: AttemptId(attempt),
            execution_lease_id: ExecutionLeaseId(attempt),
            lease_renewal_seq: LeaseRenewalSeq(0),
            worker_peer_id: PeerId("local-test".into()),
            worker_boot_generation: WorkerBootGeneration(1),
            worker_incarnation_id: WorkerIncarnationId(1),
        }
    }

    fn collectible(cas: &LiveCas) -> Vec<String> {
        let mut store = cas.store().lock().unwrap();
        plan_gc(
            &mut *store,
            &GcWorld {
                reclaim_budget: 100,
                reconciliation_complete: true,
                ..GcWorld::default()
            },
            GcMode::Emergency,
            u64::MAX / 2,
        )
        .unwrap()
        .reclaim
        .into_iter()
        .map(|location| location.object_key)
        .collect()
    }

    #[test]
    fn capture_objects_are_protected_between_puts_and_until_owner_drop() {
        let dir = crate::test_util::private_tempdir();
        let cas = Arc::new(mount_and_reconcile(dir.path()).unwrap());
        let mut pins = CapturePins::new(Arc::clone(&cas), &authority(1));
        let output = put_bytes(&cas, b"compiler output", &mut pins).unwrap();
        assert!(collectible(&cas).is_empty());
        let transcript = put_bytes(&cas, b"compiler transcript", &mut pins).unwrap();
        assert!(collectible(&cas).is_empty());
        let logical = vec![LogicalOutput {
            role: OutputRole::Materializable,
            virtual_path: RawBytes::new(b"libfoo.rlib".to_vec()),
            object: output.clone(),
        }];
        put_bundle_root(&cas, &logical, &mut pins).unwrap();
        let bundle = rabs_key::logical_output_map::compute_bundle_root(&logical).unwrap();
        assert!(collectible(&cas).is_empty());
        drop(pins);
        let candidates = collectible(&cas);
        for root in [&output.0, &transcript.0, &bundle.0] {
            assert!(
                candidates.contains(&digest_key(root)),
                "un-pinned negative control"
            );
        }
    }

    #[test]
    fn identical_bytes_have_independent_attempt_owners_and_deduplicate_within_one() {
        let dir = crate::test_util::private_tempdir();
        let cas = Arc::new(mount_and_reconcile(dir.path()).unwrap());
        let mut first = CapturePins::new(Arc::clone(&cas), &authority(1));
        let mut second = CapturePins::new(Arc::clone(&cas), &authority(2));
        let object = put_bytes(&cas, b"shared", &mut first).unwrap();
        assert_eq!(put_bytes(&cas, b"shared", &mut first).unwrap(), object);
        assert_eq!(first.held.len(), 1);
        assert_eq!(put_bytes(&cas, b"shared", &mut second).unwrap(), object);
        assert_ne!(first.held.keys().next(), second.held.keys().next());
        drop(first);
        assert!(collectible(&cas).is_empty());
        drop(second);
        assert!(collectible(&cas).contains(&digest_key(&object.0)));
    }

    #[test]
    fn native_output_duplicates_keep_independent_custody_and_original_sources() {
        let dir = crate::test_util::private_tempdir();
        let cas = Arc::new(mount_and_reconcile(dir.path()).unwrap());
        let first_source = dir.path().join("first.rlib");
        let second_source = dir.path().join("second.rlib");
        let bytes = vec![19; 3 * 65536 + 7];
        std::fs::write(&first_source, &bytes).unwrap();
        std::fs::write(&second_source, &bytes).unwrap();
        let mut first = CapturePins::new(Arc::clone(&cas), &authority(41));
        let mut second = CapturePins::new(Arc::clone(&cas), &authority(42));
        let captured = put_output(&cas, &first_source, 1 << 20, &mut first).unwrap();
        assert_eq!(
            put_output(&cas, &first_source, 1 << 20, &mut first)
                .unwrap()
                .digest,
            captured.digest,
        );
        assert_eq!(
            put_output(&cas, &second_source, 1 << 20, &mut second)
                .unwrap()
                .digest,
            captured.digest,
        );
        assert_eq!(first.held.len(), 1);
        assert_eq!(second.held.len(), 1);
        assert_ne!(first.held.keys().next(), second.held.keys().next());
        assert_eq!(captured.sig.size(), bytes.len() as u64);
        assert_eq!(std::fs::read(first_source).unwrap(), bytes);
        assert_eq!(std::fs::read(second_source).unwrap(), bytes);
        drop(first);
        assert!(collectible(&cas).is_empty());
        drop(second);
        assert!(collectible(&cas).contains(&digest_key(&captured.digest)));
    }

    #[test]
    fn native_output_invalid_duplicate_refuses_without_waiting_for_metadata_lock() {
        let dir = crate::test_util::private_tempdir();
        let cas = Arc::new(mount_and_reconcile(dir.path()).unwrap());
        let source = dir.path().join("caller.rlib");
        std::fs::write(&source, b"original compiler artifact").unwrap();
        let digest = rabs_cas::digest_set::digest_set(
            b"original compiler artifact",
            rabs_cas::digest_set::DigestRequest::default(),
            None,
        )
        .unwrap()
        .atp_content_id;
        let target =
            cas.layout()
                .published_path(&digest, rabs_cas::blob_store::RAW_PROFILE_V1, &digest);
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&source, &target).unwrap();
        let held_store = cas.store().lock().unwrap();
        let worker_cas = Arc::clone(&cas);
        let (sender, receiver) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let mut pins = CapturePins::new(Arc::clone(&worker_cas), &authority(43));
            let result = put_output(&worker_cas, &source, 1 << 20, &mut pins);
            sender
                .send(result.map(|_| ()).map_err(|error| error.to_string()))
                .unwrap();
        });
        let answer = receiver.recv_timeout(std::time::Duration::from_secs(5));
        // Release before joining even on test failure: the negative control
        // must fail, not strand a worker blocked behind the test's own lock.
        drop(held_store);
        worker.join().unwrap();
        let error = answer
            .expect("duplicate observation waited behind the store lock")
            .unwrap_err();
        assert!(error.contains("observe output target"), "{error}");
        assert!(target.symlink_metadata().unwrap().file_type().is_symlink());
    }

    #[test]
    fn publication_protection_survives_capture_release() {
        let dir = crate::test_util::private_tempdir();
        let cas = Arc::new(mount_and_reconcile(dir.path()).unwrap());
        let mut pins = CapturePins::new(Arc::clone(&cas), &authority(1));
        let object = put_bytes(&cas, b"published", &mut pins).unwrap();
        {
            let mut store = cas.store().lock().unwrap();
            store
                .create_pin(
                    7,
                    &object.0,
                    "coordinator",
                    "action-publication",
                    None,
                    None,
                    true,
                    "publication handoff control",
                )
                .unwrap();
        }
        drop(pins);
        assert!(collectible(&cas).is_empty());
        assert!(
            !cas.store()
                .lock()
                .unwrap()
                .pin_row(7)
                .unwrap()
                .unwrap()
                .released
        );
    }

    #[test]
    fn old_or_foreign_pin_identity_is_not_adopted_or_released() {
        let dir = crate::test_util::private_tempdir();
        let cas = Arc::new(mount_and_reconcile(dir.path()).unwrap());
        let object = super::super::object_id(b"collision").unwrap();
        let mut pins = CapturePins::new(Arc::clone(&cas), &authority(1));
        let id = pin_id(&pins.owner, &object);
        {
            let mut store = cas.store().lock().unwrap();
            store
                .create_pin(
                    id,
                    &object,
                    "another-owner",
                    CAPTURE_PIN_CLASS,
                    None,
                    None,
                    true,
                    "collision control",
                )
                .unwrap();
            assert!(pins.protect(&mut *store, &object).is_err());
        }
        drop(pins);
        let mut store = cas.store().lock().unwrap();
        assert!(!store.pin_row(id).unwrap().unwrap().released);
    }

    #[test]
    fn released_capture_identity_cannot_be_reused() {
        let dir = crate::test_util::private_tempdir();
        let cas = Arc::new(mount_and_reconcile(dir.path()).unwrap());
        let mut pins = CapturePins::new(Arc::clone(&cas), &authority(1));
        put_bytes(&cas, b"first capture", &mut pins).unwrap();
        drop(pins);
        let mut reused = CapturePins::new(Arc::clone(&cas), &authority(1));
        assert!(put_bytes(&cas, b"first capture", &mut reused).is_err());
        assert!(reused.held.is_empty());
    }

    #[test]
    fn durable_unreleased_capture_survives_reopen_and_large_gc_sequence() {
        let dir = crate::test_util::private_tempdir();
        let cas = Arc::new(mount_and_reconcile(dir.path()).unwrap());
        let mut pins = CapturePins::new(Arc::clone(&cas), &authority(1));
        let object = put_bytes(&cas, b"unacknowledged capture", &mut pins).unwrap();
        // Simulate loss of in-memory cleanup state, without running Drop's
        // releases. The durable store is genuinely closed and reopened below.
        pins.held.clear();
        drop(pins);
        drop(cas);
        let reopened = mount_and_reconcile(dir.path()).unwrap();
        assert!(!collectible(&reopened).contains(&digest_key(&object.0)));
    }

    #[test]
    fn owner_identity_fences_coordinator_restart_generation_attempt_and_lease() {
        let original = authority(1);
        let owner = capture_owner(&original);
        let mut changed = original.clone();
        changed.coordinator.incarnation_id.0 += 1;
        assert_ne!(capture_owner(&changed), owner);
        changed = original.clone();
        changed.action_generation.generation_id.0 += 1;
        assert_ne!(capture_owner(&changed), owner);
        changed = original.clone();
        changed.attempt_id.0 += 1;
        assert_ne!(capture_owner(&changed), owner);
        changed = original.clone();
        changed.execution_lease_id.0 += 1;
        assert_ne!(capture_owner(&changed), owner);
        // Renewing one existing attempt is not a new capture owner.
        changed = original;
        changed.lease_renewal_seq.0 += 1;
        assert_eq!(capture_owner(&changed), owner);
    }

    #[test]
    fn streamed_outputs_keep_independent_pins_across_idempotent_puts() {
        use std::io::Write;
        let dir = crate::test_util::private_tempdir();
        let source = dir.path().join("libstream.rlib");
        let chunk = [123_u8; 64 * 1024];
        let size = 17 * chunk.len() as u64 + 3;
        {
            let mut file = std::fs::File::create(&source).unwrap();
            for _ in 0..17 {
                file.write_all(&chunk).unwrap();
            }
            file.write_all(b"end").unwrap();
        }
        let cas = Arc::new(mount_and_reconcile(&dir.path().join("cas")).unwrap());
        let mut first = CapturePins::new(Arc::clone(&cas), &authority(1));
        let mut second = CapturePins::new(Arc::clone(&cas), &authority(2));
        let output = put_output(&cas, &source, size, &mut first).unwrap();
        let repeated = put_output(&cas, &source, size, &mut first).unwrap();
        let sibling = put_output(&cas, &source, size, &mut second).unwrap();
        assert_eq!(output.digest, repeated.digest);
        assert_eq!(output.digest, sibling.digest);
        assert_eq!(first.held.len(), 1);
        assert_eq!(second.held.len(), 1);
        assert_ne!(first.held.keys().next(), second.held.keys().next());
        assert!(collectible(&cas).is_empty());
        assert_eq!(
            crate::edge::live_facts::digest_stable(&source).unwrap(),
            (output.sig, output.digest.clone())
        );
        let locations = cas
            .store()
            .lock()
            .unwrap()
            .object_locations(&output.digest)
            .unwrap();
        assert_eq!(
            locations.len(),
            1,
            "equal outputs share one physical representation"
        );
        assert!(
            cas.store()
                .lock()
                .unwrap()
                .object_durably_located(&output.digest)
                .unwrap()
        );
        assert_eq!(
            std::fs::read_dir(cas.layout().root().join("staging"))
                .unwrap()
                .count(),
            0
        );
        drop(first);
        assert!(
            collectible(&cas).is_empty(),
            "sibling still awaits acknowledgment"
        );
        drop(second);
        assert!(collectible(&cas).contains(&digest_key(&output.digest)));
    }

    #[test]
    fn streamed_readonly_cas_materializes_as_an_independent_writable_output() {
        use std::os::unix::fs::MetadataExt;
        let dir = crate::test_util::private_tempdir();
        let source = dir.path().join("libsource.rmeta");
        let destination = dir.path().join("subscriber/libsource.rmeta");
        let original = b"metadata\0\xff\n";
        std::fs::write(&source, original).unwrap();
        let cas = Arc::new(mount_and_reconcile(&dir.path().join("cas")).unwrap());
        let mut pins = CapturePins::new(Arc::clone(&cas), &authority(1));
        let output = put_output(&cas, &source, 1024, &mut pins).unwrap();
        let stored = cas
            .store()
            .lock()
            .unwrap()
            .object_locations(&output.digest)
            .unwrap()[0]
            .0
            .clone();
        let stored_meta = std::fs::metadata(&stored).unwrap();
        assert_eq!(stored_meta.mode() & 0o222, 0);
        assert_ne!(stored_meta.ino(), std::fs::metadata(&source).unwrap().ino());
        std::fs::write(&source, b"later compiler output").unwrap();
        let bytes = materialize_object(
            &mut *cas.store().lock().unwrap(),
            &output.digest,
            &destination,
            MaterializationMode::PrivateCopy,
        )
        .unwrap();
        assert_eq!(bytes, original.len() as u64);
        assert_eq!(std::fs::read(&destination).unwrap(), original);
        let installed_meta = std::fs::metadata(&destination).unwrap();
        assert_ne!(installed_meta.mode() & 0o200, 0);
        assert_ne!(installed_meta.ino(), stored_meta.ino());
        std::fs::write(&destination, b"subscriber-owned mutation").unwrap();
        assert_eq!(std::fs::read(&stored).unwrap(), original);
        assert_eq!(std::fs::read(&source).unwrap(), b"later compiler output");
        assert!(collectible(&cas).is_empty());
    }

    #[test]
    fn streamed_put_preserves_collision_evidence_and_refuses_materialization() {
        let dir = crate::test_util::private_tempdir();
        let source = dir.path().join("libsource.rmeta");
        let expected = b"good metadata";
        std::fs::write(&source, expected).unwrap();
        let cas = Arc::new(mount_and_reconcile(&dir.path().join("cas")).unwrap());
        let mut original = CapturePins::new(Arc::clone(&cas), &authority(1));
        let object = put_bytes(&cas, expected, &mut original).unwrap();
        let stored = cas
            .store()
            .lock()
            .unwrap()
            .object_locations(&object.0)
            .unwrap()[0]
            .0
            .clone();
        // Exercise the real existing-representation collision path, not a
        // mocked publisher: a recorded raw copy now contains different bytes.
        std::fs::write(&stored, b"bad! metadata").unwrap();
        let mut incoming = CapturePins::new(Arc::clone(&cas), &authority(2));
        let error = put_output(&cas, &source, 1024, &mut incoming).unwrap_err();
        assert!(error.contains("CollisionIncident"), "{error}");
        assert_eq!(std::fs::read(&stored).unwrap(), b"bad! metadata");
        assert_eq!(std::fs::read(&source).unwrap(), expected);
        let preserved = std::fs::read_dir(cas.layout().root().join("quarantine"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        assert!(
            preserved
                .iter()
                .any(|path| { std::fs::read(path).unwrap().as_slice() == expected.as_slice() })
        );
        assert_eq!(
            std::fs::read_dir(cas.layout().root().join("staging"))
                .unwrap()
                .count(),
            0
        );
        drop(incoming);
        drop(original);
        let destination = dir.path().join("must-not-install");
        assert!(matches!(
            materialize_object(
                &mut *cas.store().lock().unwrap(),
                &object.0,
                &destination,
                MaterializationMode::PrivateCopy,
            ),
            Err(MaterializeError::QuarantinedObject { .. })
        ));
        assert!(!destination.exists());
        assert!(
            preserved
                .iter()
                .any(|path| { std::fs::read(path).unwrap().as_slice() == expected.as_slice() })
        );
    }

    #[test]
    fn a_later_failed_stream_abandons_only_its_own_capture_pins() {
        let dir = crate::test_util::private_tempdir();
        let source = dir.path().join("libsource.rmeta");
        std::fs::write(&source, b"first output").unwrap();
        let cas = Arc::new(mount_and_reconcile(&dir.path().join("cas")).unwrap());
        let attempt = authority(1);
        let mut pins = CapturePins::new(Arc::clone(&cas), &attempt);
        let output = put_output(&cas, &source, 1024, &mut pins).unwrap();
        let mut sibling = CapturePins::new(Arc::clone(&cas), &authority(2));
        put_output(&cas, &source, 1024, &mut sibling).unwrap();
        let reserved = pins.held.keys().copied().collect::<Vec<_>>();
        assert!(put_output(&cas, &dir.path().join("missing.rlib"), 1024, &mut pins).is_err());
        assert_eq!(pins.held.keys().copied().collect::<Vec<_>>(), reserved);
        assert!(
            cas.store()
                .lock()
                .unwrap()
                .published_manifest_key(&attempt.action_key)
                .unwrap()
                .is_none()
        );
        drop(pins);
        assert!(collectible(&cas).is_empty());
        drop(sibling);
        assert!(collectible(&cas).contains(&digest_key(&output.digest)));
        assert_eq!(std::fs::read(&source).unwrap(), b"first output");
    }
}
