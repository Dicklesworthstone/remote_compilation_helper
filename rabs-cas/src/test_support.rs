//! Public offer / ready-store builders for DOWNSTREAM live commit tests
//! (bead bd-g900u). Gated behind the `test-support` feature so it never
//! ships in a normal build.
//!
//! `publication::process_offer` is the real atomic commit+pin+quarantine
//! engine, but constructing a valid [`OfferPreparedActionResult`] and the
//! "ready" store it commits into requires a deep stack of authority /
//! manifest / evidence / lease / object rows. Those builders existed only
//! as `#[cfg(test)]` privates inside `publication.rs`, so a live test in
//! `rabsd` could not drive a commit at all. This module exposes the same
//! construction over PUBLIC types, so the coordinator commit path can be
//! proven under the running daemon (bd-epyez) rather than only inside
//! rabs-cas's own tests.
//!
//! These are DETERMINISTIC synthetic fixtures (byte-`tag` digests), not
//! production values — they exist to exercise the commit machinery.

use rabs_protocol::authority::{ClusterId, CoordinatorAuthority, CoordinatorIncarnationId};
use rabs_protocol::generation::{
    ActionGeneration, ActionGenerationId, AttemptAuthority, AttemptId, ExecutionLeaseId,
    LeaseRenewalSeq, WorkerBootGeneration, WorkerIncarnationId,
};
use rabs_protocol::raw_bytes::RawBytes;
use rabs_protocol::result_identity::{
    AttemptEvidenceBundle, CanonicalActionResultManifest, DigestAlgorithm, LogicalOutput, ObjectId,
    OutputRole, ResultKind, TypedDigest,
};
use rabs_protocol::wire_time::PeerId;

use crate::metadata_store::{ActionEntryRow, AuthorityRow, RabsMetadataStore};
use crate::publication::{
    OBSERVABLE_PROJECTION_DOMAIN, OfferPreparedActionResult, ProvisionalAncestorRef,
    SEMANTIC_PROJECTION_DOMAIN, authority_digest,
};

/// The action key every fixture shares.
const ACTION_KEY_DOMAIN: &str = "rabs.action-key.sha256.v1";

/// A deterministic digest: every byte is `tag`, under `domain`.
#[must_use]
pub fn tagged_digest(domain: &'static str, tag: u8) -> TypedDigest {
    TypedDigest {
        algorithm: DigestAlgorithm::Sha256V1,
        domain,
        bytes: [tag; 32],
    }
}

/// A deterministic object id (tagged content digest).
#[must_use]
pub fn tagged_object(tag: u8) -> ObjectId {
    ObjectId(tagged_digest("rabs.object.sha256.v1", tag))
}

/// The shared fixture action key.
#[must_use]
pub fn sample_action_key() -> TypedDigest {
    tagged_digest(ACTION_KEY_DOMAIN, 7)
}

/// The coordinator authority the ready store acquires.
#[must_use]
pub fn sample_coordinator_authority() -> CoordinatorAuthority {
    CoordinatorAuthority {
        cluster_id: ClusterId("cluster-a".to_owned()),
        credential_generation: 1,
        term: 3,
        incarnation_id: CoordinatorIncarnationId(77),
    }
}

/// The full attempt authority carried by an offer.
#[must_use]
pub fn sample_attempt_authority() -> AttemptAuthority {
    let coordinator = sample_coordinator_authority();
    let created_under = authority_digest(&coordinator);
    AttemptAuthority {
        coordinator,
        action_key: sample_action_key(),
        action_generation: ActionGeneration {
            generation_id: ActionGenerationId(11),
            per_key_ordinal: 1,
            created_under_authority_digest: created_under,
        },
        attempt_id: AttemptId(20),
        execution_lease_id: ExecutionLeaseId(30),
        lease_renewal_seq: LeaseRenewalSeq(1),
        worker_peer_id: PeerId("worker-a".to_owned()),
        worker_boot_generation: WorkerBootGeneration(1),
        worker_incarnation_id: WorkerIncarnationId(5),
    }
}

/// A canonical result manifest (one materializable output). The two
/// projection digests are placeholders here; `build()` stamps them.
#[must_use]
pub fn sample_manifest() -> CanonicalActionResultManifest {
    CanonicalActionResultManifest {
        action_key: sample_action_key(),
        canonical_descriptor_digest: tagged_digest("rabs.descriptor.sha256.v1", 8),
        key_epoch: 1,
        projection_epoch: 1,
        result_kind: ResultKind::Success,
        artifact_bundle_root: Some(tagged_object(40)),
        logical_outputs: vec![LogicalOutput {
            role: OutputRole::Materializable,
            virtual_path: RawBytes::new(b"out/lib.rlib".to_vec()),
            object: tagged_object(41),
        }],
        semantic_result_digest: tagged_digest(SEMANTIC_PROJECTION_DOMAIN, 0),
        observable_result_digest: tagged_digest(OBSERVABLE_PROJECTION_DOMAIN, 0),
    }
}

/// The evidence bundle bound to a manifest object.
#[must_use]
pub fn sample_evidence(manifest_id: &ObjectId) -> AttemptEvidenceBundle {
    AttemptEvidenceBundle {
        action_key: sample_action_key(),
        canonical_result_manifest_id: manifest_id.clone(),
        execution_snapshot_root: tagged_object(60),
        observed_input_report: tagged_object(61),
        raw_process_and_event_evidence: tagged_object(62),
        provenance_receipt: tagged_object(63),
        incremental_snapshot: None,
    }
}

/// The declared outputs the manifest is validated against.
#[must_use]
pub fn sample_declared() -> Vec<(OutputRole, RawBytes)> {
    vec![(
        OutputRole::Materializable,
        RawBytes::new(b"out/lib.rlib".to_vec()),
    )]
}

/// The coordinator-reloaded descriptor `process_offer` byte-compares
/// against the manifest's `canonical_descriptor_digest`.
#[must_use]
pub fn sample_expected_descriptor() -> TypedDigest {
    tagged_digest("rabs.descriptor.sha256.v1", 8)
}

/// A valid, commit-ready offer (no provisional ancestors).
///
/// # Panics
/// If the fixture ever fails `OfferPreparedActionResult::build` validation
/// (it never should — the fixtures are internally consistent).
#[must_use]
pub fn sample_offer() -> OfferPreparedActionResult {
    sample_offer_with_ancestors(Vec::new())
}

/// A valid, commit-ready offer carrying the given provisional ancestors.
///
/// # Panics
/// If `build` rejects the (fixture, ancestors) combination.
#[must_use]
pub fn sample_offer_with_ancestors(
    ancestors: Vec<ProvisionalAncestorRef>,
) -> OfferPreparedActionResult {
    let manifest_id = tagged_object(50);
    OfferPreparedActionResult::build(
        sample_attempt_authority(),
        sample_manifest(),
        manifest_id.clone(),
        sample_evidence(&manifest_id),
        tagged_object(51),
        tagged_digest("rabs.observation-stream.sha256.v1", 9),
        &sample_declared(),
        ancestors,
    )
    .expect("sample offer fixtures are internally consistent")
}

/// Install the full admission world `process_offer` requires: active
/// coordinator authority, the action entry, generation, attempt, lease,
/// and every closure object located durably.
///
/// # Panics
/// If any store operation fails on a fresh store.
pub fn install_ready_store(store: &mut dyn RabsMetadataStore) {
    let auth = authority_digest(&sample_coordinator_authority());
    store
        .acquire_authority(&AuthorityRow {
            digest: auth.clone(),
            cluster_id: "cluster-a".to_owned(),
            incarnation: 77,
            term: 3,
            acquired_seq: 1,
        })
        .expect("acquire authority");
    store
        .upsert_action_entry(&ActionEntryRow {
            action_key: sample_action_key(),
            key_epoch: 1,
            projection_epoch: 1,
        })
        .expect("upsert action entry");
    store
        .create_generation(&auth, 11, &sample_action_key())
        .expect("create generation");
    store.record_attempt(20, 11, "worker-a", 1).expect("attempt");
    store.acquire_lease(30, 20, 1, 100).expect("lease");
    for tag in [40u8, 41, 50, 51, 60, 61, 62, 63] {
        let id = tagged_object(tag);
        store.record_object(&id.0, 64).expect("record object");
        store
            .add_location(&id.0, &format!("/cas/{tag}"), Some(1), "raw", true)
            .expect("locate object");
    }
    // build() stamps the F035-derived bundle root; the closure check
    // requires it located like any other object.
    if let Some(root) = &sample_offer().manifest.artifact_bundle_root {
        store.record_object(&root.0, 0).expect("record bundle root");
        store
            .add_location(&root.0, "/cas/bundle-root", Some(1), "raw", true)
            .expect("locate bundle root");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata_store::{RusqliteEngine, SqlMetadataStore};
    use crate::publication::{CommitDurabilityProfile, PublicationOutcome, process_offer};

    #[test]
    fn sample_offer_commits_into_a_ready_store() {
        let engine = RusqliteEngine::open_in_memory().unwrap();
        let mut store = SqlMetadataStore::open(engine).unwrap();
        install_ready_store(&mut store);
        let outcome = process_offer(
            &mut store,
            &sample_offer(),
            &sample_expected_descriptor(),
            |_| None, // no prior committed manifest for this key
            900,      // pin_id
            1,        // seq
            CommitDurabilityProfile::RequireDurableClosure,
        )
        .expect("offer must be accepted");
        assert!(
            matches!(outcome, PublicationOutcome::Committed(_)),
            "expected a real commit, got {outcome:?}"
        );
    }
}
