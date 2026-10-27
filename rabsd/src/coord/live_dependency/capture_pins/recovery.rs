//! Durable restart-recovery witness for compiler-output capture custody.
//!
//! Evidence is written in the SAME `create_pin` transaction as its root. It is
//! a consistency witness, never release authority. The bounded live reconciler
//! also proves the normalized attempt binding and the old generation's fence.

mod reconcile;
pub(super) use reconcile::reconcile_page;

use super::{capture_owner, digest_field, field, pin_id};
use rabs_cas::metadata_store::digest_key;
use rabs_cas::publication::authority_digest;
use rabs_key::typed_digest::compute;
use rabs_protocol::authority::{ClusterId, CoordinatorAuthority, CoordinatorIncarnationId};
use rabs_protocol::generation::AttemptAuthority;
use rabs_protocol::result_identity::{DigestAlgorithm, TypedDigest};
use serde::{Deserialize, Serialize};

const EVIDENCE_VERSION: u32 = 1;
const MAX_EVIDENCE_BYTES: usize = 8 * 1024;

/// Version 1 uses SHA-256 for both digests. Do not deserialize `TypedDigest` or
/// intern untrusted domain strings: these fields only reconstruct a witness.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CaptureEvidence {
    version: u32,
    cluster: String,
    credential_generation: u64,
    term: u64,
    coordinator_incarnation: u128,
    action_domain: String,
    action_bytes: [u8; 32],
    generation: u128,
    ordinal: u64,
    attempt: u128,
    lease: u128,
    renewal: u64,
    worker: String,
    worker_boot: u64,
    worker_incarnation: u128,
    root_domain: String,
    root_bytes: [u8; 32],
}

impl CaptureEvidence {
    fn new(authority: &AttemptAuthority, root: &TypedDigest) -> Self {
        // Exhaustive: a future digest algorithm needs a new evidence contract.
        match (authority.action_key.algorithm, root.algorithm) {
            (DigestAlgorithm::Sha256V1, DigestAlgorithm::Sha256V1) => {}
        }
        Self {
            version: EVIDENCE_VERSION,
            cluster: authority.coordinator.cluster_id.0.clone(),
            credential_generation: authority.coordinator.credential_generation,
            term: authority.coordinator.term,
            coordinator_incarnation: authority.coordinator.incarnation_id.0,
            action_domain: authority.action_key.domain.to_owned(),
            action_bytes: authority.action_key.bytes,
            generation: authority.action_generation.generation_id.0,
            ordinal: authority.action_generation.per_key_ordinal,
            attempt: authority.attempt_id.0,
            lease: authority.execution_lease_id.0,
            renewal: authority.lease_renewal_seq.0,
            worker: authority.worker_peer_id.0.clone(),
            worker_boot: authority.worker_boot_generation.0,
            worker_incarnation: authority.worker_incarnation_id.0,
            root_domain: root.domain.to_owned(),
            root_bytes: root.bytes,
        }
    }

    fn coordinator(&self) -> CoordinatorAuthority {
        CoordinatorAuthority {
            cluster_id: ClusterId(self.cluster.clone()),
            credential_generation: self.credential_generation,
            term: self.term,
            incarnation_id: CoordinatorIncarnationId(self.coordinator_incarnation),
        }
    }

    fn append_digest(bytes: &mut Vec<u8>, domain: &str, digest: &[u8; 32]) {
        field(bytes, b"sha256-v1");
        field(bytes, domain.as_bytes());
        field(bytes, digest);
    }

    fn owner(&self) -> String {
        let mut bytes = Vec::new();
        digest_field(&mut bytes, &authority_digest(&self.coordinator()));
        Self::append_digest(&mut bytes, &self.action_domain, &self.action_bytes);
        field(&mut bytes, &self.generation.to_le_bytes());
        field(&mut bytes, &self.attempt.to_le_bytes());
        field(&mut bytes, &self.lease.to_le_bytes());
        digest_key(&compute("rabs.live-dependency.capture-owner.v1", &bytes))
    }

    fn pin_id(&self, owner: &str) -> u128 {
        let mut bytes = Vec::new();
        field(&mut bytes, owner.as_bytes());
        Self::append_digest(&mut bytes, &self.root_domain, &self.root_bytes);
        let hash = compute("rabs.live-dependency.capture-pin.v1", &bytes);
        let mut id = [0; 16];
        id.copy_from_slice(&hash.bytes[..16]);
        u128::from_le_bytes(id)
    }
}

/// Serialize before creating the pin; failure must never leave an unjournaled
/// new capture pin. `create_pin` persists this and the root in one transaction.
pub(super) fn evidence(authority: &AttemptAuthority, root: &TypedDigest) -> Result<String, String> {
    let witness = CaptureEvidence::new(authority, root);
    // Bind the journal to the existing canonical identity functions, including
    // at write time. Changing either scheme without updating recovery refuses.
    let owner = capture_owner(authority);
    if witness.owner() != owner || witness.pin_id(&owner) != pin_id(&owner, root) {
        return Err("capture recovery identity disagrees with capture owner".into());
    }
    if authority.action_generation.created_under_authority_digest
        != authority_digest(&authority.coordinator)
    {
        return Err("capture generation is bound to another authority".into());
    }
    let encoded = serde_json::to_string(&witness)
        .map_err(|error| format!("encode capture recovery evidence: {error}"))?;
    if encoded.len() > MAX_EVIDENCE_BYTES {
        return Err("capture recovery evidence exceeds size bound".into());
    }
    Ok(encoded)
}

#[cfg(test)]
mod journal_tests {
    use super::super::{CapturePins, tests::authority};
    use super::*;
    use crate::janitor::store::mount_and_reconcile;
    use rabs_cas::metadata_store::{RabsMetadataStore, SqlValue};
    use std::sync::Arc;

    #[test]
    fn capture_journal_round_trips_full_width_authority_and_object_identity() {
        let mut attempt = authority(u128::MAX);
        attempt.coordinator.incarnation_id.0 = u128::MAX - 1;
        attempt.action_generation.generation_id.0 = u128::MAX - 2;
        attempt.action_generation.created_under_authority_digest =
            authority_digest(&attempt.coordinator);
        attempt.worker_incarnation_id.0 = u128::MAX - 3;
        let root = compute("rabs.object.sha256.v1", b"captured object");
        let encoded = evidence(&attempt, &root).unwrap();
        let decoded: CaptureEvidence = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded.version, EVIDENCE_VERSION);
        assert_eq!(decoded.coordinator(), attempt.coordinator);
        assert_eq!(
            decoded.generation,
            attempt.action_generation.generation_id.0
        );
        assert_eq!(decoded.attempt, attempt.attempt_id.0);
        assert_eq!(decoded.lease, attempt.execution_lease_id.0);
        assert_eq!(decoded.worker_incarnation, attempt.worker_incarnation_id.0);
        assert_eq!(decoded.root_domain, root.domain);
        assert_eq!(decoded.root_bytes, root.bytes);
        assert_eq!(decoded.owner(), capture_owner(&attempt));
        assert_eq!(
            decoded.pin_id(&decoded.owner()),
            pin_id(&decoded.owner(), &root)
        );
    }

    #[test]
    fn live_capture_persists_the_witness_with_the_pin_and_refuses_invalid_binding() {
        let dir = crate::test_util::private_tempdir();
        let cas = Arc::new(mount_and_reconcile(dir.path()).unwrap());
        let attempt = authority(7);
        let root = compute("rabs.object.sha256.v1", b"journaled capture");
        let mut pins = CapturePins::new(Arc::clone(&cas), &attempt);
        {
            let mut store = cas.store().lock().unwrap();
            pins.protect(&mut *store, &root).unwrap();
            let rows = store
                .query(
                    "SELECT evidence FROM pins WHERE id_hex = ?1",
                    &[SqlValue::Text(format!(
                        "{:032x}",
                        pin_id(&pins.owner, &root)
                    ))],
                )
                .unwrap();
            assert_eq!(
                rows,
                vec![vec![SqlValue::Text(evidence(&attempt, &root).unwrap())]]
            );
        }
        let mut invalid = attempt;
        invalid
            .action_generation
            .created_under_authority_digest
            .bytes[0] ^= 1;
        let other = compute("rabs.object.sha256.v1", b"must not be pinned");
        let mut rejected = CapturePins::new(Arc::clone(&cas), &invalid);
        let mut store = cas.store().lock().unwrap();
        assert!(rejected.protect(&mut *store, &other).is_err());
        assert!(
            store
                .pin_row(pin_id(&rejected.owner, &other))
                .unwrap()
                .is_none()
        );
        drop(store);
    }

    #[test]
    fn oversized_identity_refuses_before_pin_creation() {
        let mut attempt = authority(9);
        attempt.worker_peer_id.0 = "x".repeat(MAX_EVIDENCE_BYTES + 1);
        let root = compute("rabs.object.sha256.v1", b"bounded witness");
        assert!(evidence(&attempt, &root).is_err());
    }
}
