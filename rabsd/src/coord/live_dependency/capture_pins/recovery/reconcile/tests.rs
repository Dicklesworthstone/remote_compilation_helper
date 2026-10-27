use super::super::super::{
    CapturePins, capture_owner, pin_id, tests::authority as fixture_attempt,
};
use super::super::evidence;
use super::*;
use rabs_cas::metadata_store::{AuthorityRow, RusqliteEngine, SqlMetadataStore};
use rabs_key::typed_digest::compute;
use rabs_protocol::generation::AttemptAuthority;
use rabs_protocol::result_identity::TypedDigest;
use rabs_protocol::worker_fence::WorkerSessionOffer;

fn acquire(store: &mut dyn RabsMetadataStore, authority: &CoordinatorAuthority) {
    store
        .acquire_authority(&AuthorityRow {
            digest: authority_digest(authority),
            cluster_id: authority.cluster_id.0.clone(),
            incarnation: authority.incarnation_id.0,
            term: authority.term,
            acquired_seq: authority.term,
        })
        .unwrap();
}

fn seed(store: &mut dyn RabsMetadataStore, attempt: &AttemptAuthority) {
    acquire(store, &attempt.coordinator);
    let digest = authority_digest(&attempt.coordinator);
    store
        .create_bound_generation(&digest, &attempt.action_generation, &attempt.action_key)
        .unwrap();
    store
        .admit_worker_session(
            &digest,
            &WorkerSessionOffer {
                worker_peer_id: attempt.worker_peer_id.clone(),
                boot_generation: attempt.worker_boot_generation,
                incarnation: attempt.worker_incarnation_id,
                reenrollment_proof: None,
            },
            2,
        )
        .unwrap();
    store.admit_attempt_lease(attempt, 3, 1_000_000).unwrap();
}

fn fixture() -> (SqlMetadataStore<RusqliteEngine>, AttemptAuthority) {
    let mut store = SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap();
    let attempt = fixture_attempt(7);
    seed(&mut store, &attempt);
    (store, attempt)
}

fn next_boot(
    store: &mut dyn RabsMetadataStore,
    prior: &CoordinatorAuthority,
    close: bool,
) -> CoordinatorAuthority {
    store.release_authority(&authority_digest(prior)).unwrap();
    let mut next = prior.clone();
    next.term += 1;
    next.incarnation_id.0 += 1;
    acquire(store, &next);
    if close {
        store
            .close_generations_for_other_authorities(&authority_digest(&next))
            .unwrap();
    }
    next
}

fn root(index: u64) -> TypedDigest {
    compute("rabs.capture-recovery.test-object.v1", &index.to_le_bytes())
}

fn capture(
    store: &mut dyn RabsMetadataStore,
    attempt: &AttemptAuthority,
    object: &TypedDigest,
) -> u128 {
    let owner = capture_owner(attempt);
    let id = pin_id(&owner, object);
    let encoded = evidence(attempt, object).unwrap();
    store
        .create_pin(
            id,
            object,
            &owner,
            CAPTURE_PIN_CLASS,
            None,
            Some(&encoded),
            true,
            "test lost compiler capture",
        )
        .unwrap();
    id
}

fn released(store: &mut dyn RabsMetadataStore, id: u128) -> bool {
    store.pin_row(id).unwrap().unwrap().released
}

#[test]
fn only_a_different_released_authority_and_closed_generation_allow_recovery() {
    let (mut store, attempt) = fixture();
    let id = capture(&mut store, &attempt, &root(1));
    assert_eq!(
        reconcile_page(&mut store, &attempt.coordinator)
            .unwrap()
            .released,
        0
    );
    assert!(!released(&mut store, id));
    let next = next_boot(&mut store, &attempt.coordinator, false);
    assert_eq!(reconcile_page(&mut store, &next).unwrap().released, 0);
    assert!(!released(&mut store, id));
    // A new boot gets its own cursor and fences every prior generation.
    let final_boot = next_boot(&mut store, &next, true);
    assert_eq!(reconcile_page(&mut store, &final_boot).unwrap().released, 1);
    assert!(released(&mut store, id));
    assert_eq!(reconcile_page(&mut store, &final_boot).unwrap().scanned, 0);
}

#[test]
fn stale_reconciler_cannot_release_or_checkpoint() {
    let (mut store, attempt) = fixture();
    let id = capture(&mut store, &attempt, &root(2));
    let next = next_boot(&mut store, &attempt.coordinator, true);
    assert_eq!(
        reconcile_page(&mut store, &attempt.coordinator),
        Err(StoreError::NotActiveAuthority)
    );
    assert!(!released(&mut store, id));
    assert_eq!(reconcile_page(&mut store, &next).unwrap().released, 1);
}

#[test]
fn each_page_is_bounded_and_releasing_rows_never_skips_the_next_page() {
    let (mut store, attempt) = fixture();
    let ids: Vec<_> = (0..(2 * PAGE_SIZE + 5) as u64)
        .map(|index| capture(&mut store, &attempt, &root(index)))
        .collect();
    let next = next_boot(&mut store, &attempt.coordinator, true);
    for expected in [PAGE_SIZE, PAGE_SIZE, 5] {
        let page = reconcile_page(&mut store, &next).unwrap();
        assert_eq!(page.scanned, expected);
        assert_eq!(page.released, expected);
        assert_eq!(page.complete, expected < PAGE_SIZE);
    }
    assert!(ids.into_iter().all(|id| released(&mut store, id)));
    let before = store.differential_snapshot().unwrap();
    assert_eq!(reconcile_page(&mut store, &next).unwrap().scanned, 0);
    assert_eq!(
        store.differential_snapshot().unwrap(),
        before,
        "idle means no writes"
    );
}

#[test]
fn malformed_legacy_and_other_pin_classes_remain_protected() {
    let (mut store, attempt) = fixture();
    let owner = capture_owner(&attempt);
    let mut ids = Vec::new();
    for (index, encoded) in [None, Some("{"), Some("{}"), Some("null")]
        .into_iter()
        .enumerate()
    {
        let object = root(index as u64);
        let id = pin_id(&owner, &object);
        store
            .create_pin(
                id,
                &object,
                &owner,
                CAPTURE_PIN_CLASS,
                None,
                encoded,
                true,
                "legacy",
            )
            .unwrap();
        ids.push(id);
    }
    let object = root(20);
    let pin = capture(&mut store, &attempt, &object);
    store
        .create_pin(
            1,
            &object,
            "coordinator",
            "action-publication",
            None,
            None,
            true,
            "independent",
        )
        .unwrap();
    let next = next_boot(&mut store, &attempt.coordinator, true);
    let page = reconcile_page(&mut store, &next).unwrap();
    assert_eq!(page.released, 1);
    assert!(released(&mut store, pin));
    assert!(!released(&mut store, 1));
    assert!(ids.into_iter().all(|id| !released(&mut store, id)));
}

#[test]
fn malformed_checkpoint_retains_every_remaining_pin() {
    let (mut store, attempt) = fixture();
    let id = capture(&mut store, &attempt, &root(1));
    let next = next_boot(&mut store, &attempt.coordinator, true);
    store
        .record_decision_receipt(
            CURSOR_KIND,
            &digest_key(&authority_digest(&next)),
            1,
            "pending",
            "not-hex",
        )
        .unwrap();
    assert!(matches!(
        reconcile_page(&mut store, &next),
        Err(StoreError::Corruption(_))
    ));
    assert!(!released(&mut store, id));
}

#[test]
fn checkpoint_after_confirmed_releases_makes_an_interruption_replay_safe() {
    let (mut store, attempt) = fixture();
    let mut ids: Vec<_> = (0..(PAGE_SIZE + 3) as u64)
        .map(|index| capture(&mut store, &attempt, &root(index)))
        .collect();
    ids.sort_unstable();
    let next = next_boot(&mut store, &attempt.coordinator, true);
    // Model interruption between confirmed scoped releases and the checkpoint.
    // No cursor is advanced; the subsequent real reconciler must cover all rows.
    for id in &ids[..7] {
        assert_eq!(
            release_pin_scoped(&mut store, *id, &Releaser::Coordinator(next.clone())).unwrap(),
            ReleaseOutcome::Released
        );
    }
    let page = reconcile_page(&mut store, &next).unwrap();
    assert_eq!(page.released, ids.len() - 7);
    assert!(page.complete);
    assert!(ids.into_iter().all(|id| released(&mut store, id)));
}

#[test]
fn production_capture_drop_recovers_old_custody_after_actual_cas_reopen() {
    use crate::coord::live::CoordLive;
    use crate::coord::live_dependency::put_bytes;
    use crate::janitor::store::mount_and_reconcile;
    use std::sync::Arc;

    let dir = crate::test_util::private_tempdir();
    let old_id;
    let object;
    {
        let cas = Arc::new(mount_and_reconcile(dir.path()).unwrap());
        let coord = CoordLive::with_cas(Arc::clone(&cas));
        let mut attempt = fixture_attempt(7);
        attempt.coordinator = coord.acquire_boot_authority("capture-tests").unwrap();
        attempt.action_generation.created_under_authority_digest =
            authority_digest(&attempt.coordinator);
        seed(&mut *cas.store().lock().unwrap(), &attempt);
        let mut pins = CapturePins::new(Arc::clone(&cas), &attempt);
        object = put_bytes(&cas, b"captured bytes survive recovery", &mut pins).unwrap();
        old_id = pin_id(&pins.owner, &object.0);
        cas.store()
            .lock()
            .unwrap()
            .create_pin(
                1,
                &object.0,
                "coordinator",
                "action-publication",
                None,
                None,
                true,
                "independent publication",
            )
            .unwrap();
        // Discard only the in-memory cleanup inventory to model process loss.
        pins.held.clear();
    }
    let cas = Arc::new(mount_and_reconcile(dir.path()).unwrap());
    let coord = CoordLive::with_cas(Arc::clone(&cas));
    let mut current = fixture_attempt(17);
    current.coordinator = coord.acquire_boot_authority("capture-tests").unwrap();
    assert_eq!(coord.closed_prior_generations(), 1);
    current.action_generation = cas
        .store()
        .lock()
        .unwrap()
        .allocate_bound_generation(&authority_digest(&current.coordinator), &current.action_key)
        .unwrap();
    let mut pins = CapturePins::new(Arc::clone(&cas), &current);
    put_bytes(&cas, b"current captured bytes", &mut pins).unwrap();
    assert!(!released(&mut *cas.store().lock().unwrap(), old_id));
    drop(pins); // The actual production hook, not a direct recovery call.
    let mut store = cas.store().lock().unwrap();
    assert!(released(&mut *store, old_id));
    assert!(!released(&mut *store, 1));
    let locations = store.object_locations(&object.0).unwrap();
    assert_eq!(locations.len(), 1);
    assert_eq!(
        std::fs::read(&locations[0].0).unwrap(),
        b"captured bytes survive recovery"
    );
    let snapshot = store.gc_snapshot(900).unwrap();
    assert!(
        snapshot
            .reachable_from_pins
            .contains(&digest_key(&object.0))
    );
}

#[test]
fn every_forged_witness_field_retains_its_original_pin() {
    for field in 0..17 {
        let (mut store, attempt) = fixture();
        let object = root(1);
        let owner = capture_owner(&attempt);
        let id = pin_id(&owner, &object);
        let mut witness = CaptureEvidence::new(&attempt, &object);
        match field {
            0 => witness.version += 1,
            1 => witness.cluster.push_str("-foreign"),
            2 => witness.credential_generation += 1,
            3 => witness.term += 1,
            4 => witness.coordinator_incarnation += 1,
            5 => witness.action_domain.push_str("-different"),
            6 => witness.action_bytes[0] ^= 1,
            7 => witness.generation += 1,
            8 => witness.ordinal += 1,
            9 => witness.attempt += 1,
            10 => witness.lease += 1,
            11 => witness.renewal += 1,
            12 => witness.worker.push_str("-different"),
            13 => witness.worker_boot += 1,
            14 => witness.worker_incarnation += 1,
            15 => witness.root_domain.push_str("-different"),
            16 => witness.root_bytes[0] ^= 1,
            _ => unreachable!(),
        }
        // Construct a contradictory witness through the actual metadata API;
        // no mutable SQL bypass is used. The original identity remains pinned.
        let encoded = serde_json::to_string(&witness).unwrap();
        store
            .create_pin(
                id,
                &object,
                &owner,
                CAPTURE_PIN_CLASS,
                None,
                Some(&encoded),
                true,
                "forged witness control",
            )
            .unwrap();
        let valid = capture(&mut store, &attempt, &root(2));
        let next = next_boot(&mut store, &attempt.coordinator, true);
        let page = reconcile_page(&mut store, &next).unwrap();
        assert_eq!(page.scanned, 2, "mutation {field}");
        assert_eq!(page.released, 1, "mutation {field}");
        assert!(!released(&mut store, id), "mutation {field}");
        assert!(released(&mut store, valid), "valid control {field}");
    }
}

#[test]
fn full_width_witnesses_recover_through_both_metadata_backends() {
    use rabs_cas::metadata_store::FsqliteEngine;

    let dir = crate::test_util::private_tempdir();
    let stores: [Box<dyn RabsMetadataStore>; 2] = [
        Box::new(SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap()),
        Box::new(
            SqlMetadataStore::open(FsqliteEngine::open(&dir.path().join("metadata.db")).unwrap())
                .unwrap(),
        ),
    ];
    for mut store in stores {
        let mut attempt = fixture_attempt(u128::MAX - 2);
        attempt.coordinator.incarnation_id.0 = u128::MAX - 10;
        attempt.action_generation.generation_id.0 = u128::MAX - 3;
        attempt.action_generation.per_key_ordinal = u64::MAX;
        attempt.action_generation.created_under_authority_digest =
            authority_digest(&attempt.coordinator);
        attempt.execution_lease_id.0 = u128::MAX - 1;
        attempt.worker_boot_generation.0 = u64::MAX;
        attempt.worker_incarnation_id.0 = u128::MAX;
        seed(&mut *store, &attempt);
        let id = capture(&mut *store, &attempt, &root(7));
        let next = next_boot(&mut *store, &attempt.coordinator, true);
        assert_eq!(reconcile_page(&mut *store, &next).unwrap().released, 1);
        assert!(released(&mut *store, id));
        assert_eq!(reconcile_page(&mut *store, &next).unwrap().scanned, 0);
    }
}

#[test]
fn durable_cursor_resumes_after_the_metadata_connection_is_closed_and_reopened() {
    let dir = crate::test_util::private_tempdir();
    let path = dir.path().join("metadata.db");
    let next;
    let ids;
    {
        let mut store = SqlMetadataStore::open(RusqliteEngine::open(&path).unwrap()).unwrap();
        let attempt = fixture_attempt(7);
        seed(&mut store, &attempt);
        ids = (0..(PAGE_SIZE + 3) as u64)
            .map(|index| capture(&mut store, &attempt, &root(index)))
            .collect::<Vec<_>>();
        next = next_boot(&mut store, &attempt.coordinator, true);
        let page = reconcile_page(&mut store, &next).unwrap();
        assert_eq!(page.released, PAGE_SIZE);
        assert!(!page.complete);
    }
    let mut store = SqlMetadataStore::open(RusqliteEngine::open(&path).unwrap()).unwrap();
    // The recovery entry point re-declares the authority domain itself; no
    // unrelated write or fixture interning is needed to read the saved cursor.
    let page = reconcile_page(&mut store, &next).unwrap();
    assert_eq!(page.scanned, 3);
    assert_eq!(page.released, 3);
    assert!(page.complete);
    assert!(ids.into_iter().all(|id| released(&mut store, id)));
    let before = store.differential_snapshot().unwrap();
    assert_eq!(reconcile_page(&mut store, &next).unwrap().scanned, 0);
    assert_eq!(store.differential_snapshot().unwrap(), before);
}
