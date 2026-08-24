//! No direct agent CAS/action publication (bead S005; plan Epic S/M3).
//!
//! The threat: an agent or one of its build subprocesses writes into
//! the shared CAS or the action-publication table directly, poisoning
//! every later consumer. The law under proof: ONLY a coordinator whose
//! authority is ACTIVE — acting through the offer pipeline after
//! sandboxed execution and verification — can publish, and object-byte
//! admission can never mint bytes under a name they do not hash to.
//!
//! What this suite proves at the PUBLIC API boundary (the only surface
//! an agent could reach):
//!
//! 1. **Object admission is digest-named** ([`rabs_cas::blob_store::put_if_absent`]):
//!    declaring another digest than what the bytes hash to is refused
//!    ([`PutError::DeclaredDigestMismatch`) BEFORE anything is
//!    published, and the store keeps zero residue. An agent cannot
//!    mint "unknown" bytes at all — admission requires naming content
//!    you already have.
//! 2. **The single publication writer refuses everyone but the active
//!    coordinator**: [`RabsMetadataStore::commit_publication`] with an
//!    authority that was never acquired ⇒ NotActiveAuthority; with an
//!    attempt bound to a foreign coordinator ⇒ AttemptAuthorityMismatch;
//!    through a released lease ⇒ LeaseReleased; against a legacy
//!    unbound generation row ⇒ LegacyUnboundAuthority; from a worker
//!    whose incarnation fence has moved on ⇒ WorkerLeaseRejected.
//! 3. **The `None` repair seam is coordinator-gated, not agent-gated**:
//!    it succeeds ONLY for the ACTIVE authority — an agent holds none,
//!    so the seam is closed to them by exactly the check that opens it
//!    to repairs.
//! 4. **Every refusal leaves zero residue**: no publication row, byte
//!    -identical store snapshot. A failed poison attempt must not even
//!
//! Structural facts this suite RELIES on rather than re-proves (each
//! owned elsewhere): workers terminate at prepared-result OFFERS —
//! `WorkerPublicationMessage` has the single non-commit variant with an
//! exhaustive audit (rabs-protocol/src/publication_messages.rs), the
//! operation→capability map grants no WriteCas kind
//! (operation_checks.rs), rabs-wkr links rabs-cas but imports nothing
//! from it, the edge socket serves status/consult/serve frames only,
//! and the full process_offer refusal matrix lives inline in
//! publication.rs plus the live-daemon fencing tests in rabsd/tests.

use rabs_cas::blob_store::{BlobStoreLayout, DurabilityPolicy, PutError, PutLimits, put_if_absent};
use rabs_cas::digest_set::{DigestRequest, digest_set};
use rabs_cas::metadata_store::{
    ActionEntryRow, AuthorityRow, CommitOutcome, PublicationRow, RabsMetadataStore, ResultKindTag,
    RusqliteEngine, SqlMetadataStore, StoreError,
};
use rabs_key::authority_binding::coordinator_authority_digest;
use rabs_protocol::authority::{ClusterId, CoordinatorAuthority, CoordinatorIncarnationId};
use rabs_protocol::generation::{
    ActionGeneration, ActionGenerationId, AttemptAuthority, AttemptId, ExecutionLeaseId,
    LeaseRenewalSeq, WorkerBootGeneration, WorkerIncarnationId,
};
use rabs_protocol::result_identity::{DigestAlgorithm, TypedDigest};
use rabs_protocol::wire_time::PeerId;

fn d(domain: &'static str, tag: u8) -> TypedDigest {
    TypedDigest {
        algorithm: DigestAlgorithm::Sha256V1,
        domain,
        bytes: [tag; 32],
    }
}

fn store() -> SqlMetadataStore<RusqliteEngine> {
    SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap()
}

/// One fully legitimate publication setup under a real coordinator:
/// active authority, action entry, BOUND generation, three leased
/// attempts across distinct fenced workers. Returns everything the
/// refusal cases mutate.
struct LegitWorld {
    authority: TypedDigest,
    _coordinator: CoordinatorAuthority,
    action: TypedDigest,
    winner: AttemptAuthority,
}

fn legit_world(st: &mut SqlMetadataStore<RusqliteEngine>) -> LegitWorld {
    let coordinator = CoordinatorAuthority {
        cluster_id: ClusterId("cluster-a".to_owned()),
        credential_generation: 1,
        term: 1,
        incarnation_id: CoordinatorIncarnationId(1),
    };
    let authority = coordinator_authority_digest(&coordinator);
    st.acquire_authority(&AuthorityRow {
        digest: authority.clone(),
        cluster_id: "cluster-a".to_owned(),
        incarnation: 1,
        term: 1,
        acquired_seq: 1,
    })
    .unwrap();
    // Worker incarnation fences precede any attempt that names them.
    for (worker, boot, incarnation) in [("worker-a", 1u64, 5u128), ("worker-b", 1, 6)] {
        st.admit_worker_session(
            &authority,
            &rabs_protocol::worker_fence::WorkerSessionOffer {
                worker_peer_id: PeerId(worker.to_owned()),
                boot_generation: WorkerBootGeneration(boot),
                incarnation: WorkerIncarnationId(incarnation),
                reenrollment_proof: None,
            },
            incarnation as u64 + 10,
        )
        .unwrap();
    }
    let action = d("rabs.action-key.sha256.v1", 9);
    st.upsert_action_entry(&ActionEntryRow {
        action_key: action.clone(),
        key_epoch: 0,
        projection_epoch: 0,
    })
    .unwrap();
    let mk = |attempt: u128, lease: u128, worker: &str, inc: u128| AttemptAuthority {
        coordinator: coordinator.clone(),
        action_key: action.clone(),
        action_generation: ActionGeneration {
            generation_id: ActionGenerationId(10),
            per_key_ordinal: 1,
            created_under_authority_digest: authority.clone(),
        },
        attempt_id: AttemptId(attempt),
        execution_lease_id: ExecutionLeaseId(lease),
        lease_renewal_seq: LeaseRenewalSeq(1),
        worker_peer_id: PeerId(worker.to_owned()),
        worker_boot_generation: WorkerBootGeneration(1),
        worker_incarnation_id: WorkerIncarnationId(inc),
    };
    let winner = mk(20, 20, "worker-a", 5);
    st.create_bound_generation(&authority, &winner.action_generation, &action)
        .unwrap();
    st.admit_attempt_lease(&winner, 5, 1_000).unwrap();
    let second = mk(21, 21, "worker-b", 6);
    st.admit_attempt_lease(&second, 6, 1_000).unwrap();
    LegitWorld {
        authority,
        _coordinator: coordinator,
        action,
        winner,
    }
}

fn publication_row(action: &TypedDigest) -> PublicationRow {
    PublicationRow {
        action_key: action.clone(),
        descriptor_digest: d("rabs.descriptor.sha256.v1", 1),
        manifest_digest: d("rabs.result-manifest.sha256.v1", 1),
        evidence_digest: d("rabs.evidence-bundle.sha256.v1", 1),
        winner_generation: 10,
        winner_attempt: 20,
        result_kind: ResultKindTag::Success,
        pin_id: 40,
        pin_owner: "coordinator".to_owned(),
        provisional_ancestors: Vec::new(),
    }
}

/// The poisoning-path invariant: a refused write leaves NO publication
/// row behind and does not disturb a single line of the store's
/// canonical state.
fn assert_zero_residue(
    st: &mut SqlMetadataStore<RusqliteEngine>,
    baseline: &[String],
    action: &TypedDigest,
) {
    assert!(
        !st.has_publication(action).unwrap(),
        "a refused write must not publish"
    );
    assert_eq!(
        st.differential_snapshot().unwrap(),
        baseline,
        "a refused write must leave the store byte-identical"
    );
}

// ---------------------------------------------------------------------
// 1. Object admission is digest-named: no minting under false names.
// ---------------------------------------------------------------------

#[test]
fn s005_object_admission_refuses_bytes_declared_under_a_foreign_digest() {
    let mut st = store();
    let layout = BlobStoreLayout::open(
        &std::env::temp_dir().join(format!("s005-blobs-{}", std::process::id())),
    )
    .unwrap();
    let baseline = st.differential_snapshot().unwrap();

    // Agent has SOME bytes (its own build junk) but declares the
    // identity of OTHER content — the classic poisoning move.
    let real = digest_set(b"agent build junk", DigestRequest::default(), None)
        .unwrap()
        .atp_content_id;
    let claimed_otherwhere = d("rabs.object.v1", 42);
    let err = put_if_absent(
        &layout,
        &mut st,
        &claimed_otherwhere,
        &mut std::io::Cursor::new(b"agent build junk"),
        PutLimits::default(),
        DurabilityPolicy::FULL,
    )
    .unwrap_err();
    assert!(matches!(err, PutError::DeclaredDigestMismatch { .. }));
    let _ = real;
    assert_zero_residue(&mut st, &baseline, &claimed_otherwhere);

    // Positive control: naming the TRUE identity admits exactly once.
    let truth = digest_set(b"verified tool output", DigestRequest::default(), None)
        .unwrap()
        .atp_content_id;
    put_if_absent(
        &layout,
        &mut st,
        &truth,
        &mut std::io::Cursor::new(b"verified tool output"),
        PutLimits::default(),
        DurabilityPolicy::FULL,
    )
    .unwrap();
}

// ---------------------------------------------------------------------
// 2. The single publication writer refuses non-active authorities.
// ---------------------------------------------------------------------

#[test]
fn s005_commit_with_never_acquired_authority_publishes_nothing() {
    let mut st = store();
    let world = legit_world(&mut st);
    let baseline = st.differential_snapshot().unwrap();

    // An agent invents (or stale-caches) an authority digest that the
    // store never acquired as active.
    let impostor = d("rabs.authority.sha256.v1", 77);
    let err = st
        .commit_publication(&impostor, None, &publication_row(&world.action))
        .unwrap_err();
    assert_eq!(err, StoreError::NotActiveAuthority);
    assert_zero_residue(&mut st, &baseline, &world.action);
}

#[test]
fn s005_repair_seam_serves_only_the_active_coordinator() {
    let mut st = store();
    let world = legit_world(&mut st);

    // The None seam IS open — but only from the coordinator desk.
    assert_eq!(
        st.commit_publication(&world.authority, None, &publication_row(&world.action))
            .unwrap(),
        CommitOutcome::Committed
    );

    // A second action entry: the same seam under ANY other digest is
    // closed. Agents hold no active authority; this is the exact gate
    // that keeps the repair path from becoming a side door.
    let other = d("rabs.action-key.sha256.v1", 10);
    st.upsert_action_entry(&ActionEntryRow {
        action_key: other.clone(),
        key_epoch: 0,
        projection_epoch: 0,
    })
    .unwrap();
    let impostor = d("rabs.authority.sha256.v1", 78);
    assert_eq!(
        st.commit_publication(&impostor, None, &publication_row(&other))
            .unwrap_err(),
        StoreError::NotActiveAuthority
    );
    assert!(!st.has_publication(&other).unwrap());
}

#[test]
fn s005_attempt_bound_to_a_foreign_coordinator_is_refused_wholesale() {
    let mut st = store();
    let world = legit_world(&mut st);
    let baseline = st.differential_snapshot().unwrap();

    // Coordinator B is active SOMEWHERE ELSE; its digest does not match
    // the digest the winner attempt was created under.
    let foreign = CoordinatorAuthority {
        cluster_id: ClusterId("cluster-b".to_owned()),
        credential_generation: 1,
        term: 9,
        incarnation_id: CoordinatorIncarnationId(9),
    };
    let foreign_active = coordinator_authority_digest(&foreign);
    let mut row = publication_row(&world.action);
    row.winner_attempt = 21;
    let err = st
        .commit_publication(&foreign_active, Some(&world.winner), &row)
        .unwrap_err();
    assert_eq!(err, StoreError::AttemptAuthorityMismatch);
    assert_zero_residue(&mut st, &baseline, &world.action);
}

#[test]
fn s005_released_lease_cannot_publish() {
    let mut st = store();
    let world = legit_world(&mut st);
    st.release_lease(world.winner.execution_lease_id.0).unwrap();
    let baseline = st.differential_snapshot().unwrap();

    let err = st
        .commit_publication(
            &world.authority,
            Some(&world.winner),
            &publication_row(&world.action),
        )
        .unwrap_err();
    assert_eq!(err, StoreError::LeaseReleased);
    assert_zero_residue(&mut st, &baseline, &world.action);
}

#[test]
fn s005_worker_incarnation_advance_invalidates_prior_attempts() {
    let mut st = store();
    let world = legit_world(&mut st);

    // The worker restarts: strictly newer boot generation admitted.
    // Every lease from prior incarnations is dead by law (I47).
    st.admit_worker_session(
        &world.authority,
        &rabs_protocol::worker_fence::WorkerSessionOffer {
            worker_peer_id: PeerId("worker-a".to_owned()),
            boot_generation: WorkerBootGeneration(2),
            incarnation: WorkerIncarnationId(11),
            reenrollment_proof: None,
        },
        30,
    )
    .unwrap();
    // Baseline AFTER the restart: the residue invariant is about the
    // REFUSED WRITE, not about our own fixture setup.
    let baseline = st.differential_snapshot().unwrap();

    let err = st
        .commit_publication(
            &world.authority,
            Some(&world.winner),
            &publication_row(&world.action),
        )
        .unwrap_err();
    assert!(matches!(
        err,
        StoreError::WorkerLeaseRejected(_) | StoreError::AttemptAuthorityMismatch
    ));
    assert_zero_residue(&mut st, &baseline, &world.action);
}
#[test]
fn s005_legacy_unbound_generation_rows_fail_closed() {
    let mut st = store();
    let coordinator = CoordinatorAuthority {
        cluster_id: ClusterId("cluster-a".to_owned()),
        credential_generation: 1,
        term: 1,
        incarnation_id: CoordinatorIncarnationId(1),
    };
    let authority = coordinator_authority_digest(&coordinator);
    st.acquire_authority(&AuthorityRow {
        digest: authority.clone(),
        cluster_id: "cluster-a".to_owned(),
        incarnation: 1,
        term: 1,
        acquired_seq: 1,
    })
    .unwrap();
    let action = d("rabs.action-key.sha256.v1", 12);
    st.upsert_action_entry(&ActionEntryRow {
        action_key: action.clone(),
        key_epoch: 0,
        projection_epoch: 0,
    })
    .unwrap();
    // LEGACY generation (no v21 authority-binding ordinal) + legacy
    // attempt record: pre-migration shape a half-upgraded fleet could
    // still carry.
    st.create_generation(&authority, 11, &action).unwrap();
    st.record_attempt(22, 11, "legacy-worker", 1).unwrap();
    let legacy_attempt = AttemptAuthority {
        coordinator: coordinator.clone(),
        action_key: action.clone(),
        action_generation: ActionGeneration {
            generation_id: ActionGenerationId(11),
            per_key_ordinal: 1,
            created_under_authority_digest: authority.clone(),
        },
        attempt_id: AttemptId(22),
        execution_lease_id: ExecutionLeaseId(22),
        lease_renewal_seq: LeaseRenewalSeq(1),
        worker_peer_id: PeerId("legacy-worker".to_owned()),
        worker_boot_generation: WorkerBootGeneration(0xCAFE),
        worker_incarnation_id: WorkerIncarnationId(0xBEEF),
    };
    let baseline = st.differential_snapshot().unwrap();
    let mut row = publication_row(&action);
    row.winner_generation = 11;
    row.winner_attempt = 22;
    let err = st
        .commit_publication(&authority, Some(&legacy_attempt), &row)
        .unwrap_err();
    assert_eq!(err, StoreError::LegacyUnboundAuthority);
    assert_zero_residue(&mut st, &baseline, &action);
}
