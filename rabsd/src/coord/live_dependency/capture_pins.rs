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
    held: BTreeMap<u128, TypedDigest>,
}

impl CapturePins {
    pub(super) fn new(cas: Arc<LiveCas>, authority: &AttemptAuthority) -> Self {
        Self {
            cas,
            owner: capture_owner(authority),
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
                    row.owner == self.owner && row.class == CAPTURE_PIN_CLASS && !row.released
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
        store
            .create_pin(
                id,
                root,
                &self.owner,
                CAPTURE_PIN_CLASS,
                None,
                None,
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
        for id in self.held.keys() {
            if !matches!(store.pin_row(*id), Ok(Some(row))
                if row.owner == self.owner && row.class == CAPTURE_PIN_CLASS)
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
    }
}

#[cfg(test)]
mod tests {
    use super::super::{put_bundle_root, put_bytes};
    use super::*;
    use crate::janitor::store::mount_and_reconcile;
    use rabs_cas::gc::{GcMode, GcWorld, plan_gc};
    use rabs_protocol::authority::{ClusterId, CoordinatorAuthority, CoordinatorIncarnationId};
    use rabs_protocol::generation::{
        ActionGeneration, ActionGenerationId, AttemptId, ExecutionLeaseId, LeaseRenewalSeq,
        WorkerBootGeneration, WorkerIncarnationId,
    };
    use rabs_protocol::raw_bytes::RawBytes;
    use rabs_protocol::result_identity::{LogicalOutput, OutputRole};
    use rabs_protocol::wire_time::PeerId;

    fn authority(attempt: u128) -> AttemptAuthority {
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
}
