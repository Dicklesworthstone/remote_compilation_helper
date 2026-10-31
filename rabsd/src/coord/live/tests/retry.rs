//! Actual SQLite/source ownership tests for typed pre-execution failover. These
//! drive coordinator admission and retirement; they do not claim a compiler ran.

use super::*;
use crate::coord::live_dependency::settle_finished_dispatch;
use rabs_action::state_machines::AttemptState;

struct Flight {
    _state: tempfile::TempDir,
    source_root: tempfile::TempDir,
    source: Arc<SealedSourceSnapshot>,
    manifest: ActionInputManifest,
    descriptor: ActionDescriptor,
    coord: CoordLive,
    key: TypedDigest,
    serial: u64,
    primary: AttemptAuthority,
    worker: WorkerSessionOffer,
    session: u64,
}

impl Flight {
    fn new() -> Self {
        let (state, coord) = submission_coordinator();
        let (source_root, source, manifest, descriptor) = source_fixture();
        let key = coord
            .submit_action(
                submission(&source, &manifest, &descriptor),
                request(1, SubscriberKind::ForegroundAgent, 200),
                1,
                0,
            )
            .unwrap()
            .action_key;
        let serial = coord.claim_submitted_dispatch(&key).unwrap().unwrap();
        let worker = worker_offer(1, 17);
        let session = coord.admit_worker_session(&worker).unwrap().1.unwrap();
        let primary = coord
            .begin_claimed_dispatch(&key, serial, &worker, 60_000)
            .unwrap();
        let flight = Self {
            _state: state,
            source_root,
            source,
            manifest,
            descriptor,
            coord,
            key,
            serial,
            primary,
            worker,
            session,
        };
        flight.running(&flight.primary);
        flight
    }

    fn running(&self, authority: &AttemptAuthority) {
        for state in [
            AttemptState::LeaseAccepted,
            AttemptState::AwaitingInputs,
            AttemptState::Materializing,
            AttemptState::Running,
        ] {
            self.coord
                .advance_started_dispatch(&self.key, self.serial, authority, state)
                .unwrap();
        }
    }

    fn retire_attempt(&self, authority: &AttemptAuthority, session: u64) {
        self.coord
            .prepare_retry_dispatch(&self.key, self.serial, authority)
            .unwrap();
        assert!(
            self.coord
                .release_worker_session(
                    &authority.worker_peer_id,
                    authority.worker_incarnation_id,
                    session,
                )
                .unwrap()
        );
        assert!(self.lease_released(authority));
        assert!(self.coord.next_action_dispatch().unwrap().is_none());
        assert!(
            self.coord
                .claim_submitted_dispatch(&self.key)
                .unwrap()
                .is_none()
        );
    }

    fn lease_released(&self, authority: &AttemptAuthority) -> bool {
        self.coord
            .live_cas()
            .unwrap()
            .store()
            .lock()
            .unwrap()
            .lease_state(authority.execution_lease_id.0)
            .unwrap()
            .unwrap()
            .released
    }

    fn input(&self) -> Arc<ActionSubmission> {
        Arc::clone(&self.coord.submissions.lock().unwrap().entries[&self.key].input)
    }

    fn expire_lease_clock(&mut self) {
        let expires = self
            .coord
            .live_cas()
            .unwrap()
            .store()
            .lock()
            .unwrap()
            .lease_state(self.primary.execution_lease_id.0)
            .unwrap()
            .unwrap()
            .expires_at_own_monotonic_ms;
        self.coord.lease_clock =
            OnceLock::from(Instant::now() - std::time::Duration::from_millis(expires + 1));
    }

    fn assert_no_result(&self) {
        let mut store = self.coord.live_cas().unwrap().store().lock().unwrap();
        assert!(store.published_manifest_key(&self.key).unwrap().is_none());
        assert!(
            store
                .list_verification_samples(&self.key)
                .unwrap()
                .is_empty()
        );
    }

    fn finish(&self, authority: &AttemptAuthority) {
        settle_finished_dispatch(&self.coord, &self.key, self.serial, authority).unwrap();
        assert!(self.coord.submitted_actor(&self.key).unwrap().is_none());
        let mut store = self.coord.live_cas().unwrap().store().lock().unwrap();
        assert!(
            store
                .generation_state(authority.action_generation.generation_id.0)
                .unwrap()
                .unwrap()
                .tombstoned
        );
    }
}

fn alternate(name: &str, incarnation: u128) -> WorkerSessionOffer {
    WorkerSessionOffer {
        worker_peer_id: PeerId(name.to_owned()),
        ..worker_offer(1, incarnation)
    }
}

#[test]
fn worker_failover_retains_one_generation_and_captured_inputs_with_two_retries() {
    let flight = Flight::new();
    let retained = flight.input();
    std::fs::write(
        flight.source_root.path().join("input.txt"),
        b"changed live source",
    )
    .unwrap();
    let mut previous = flight.primary.clone();
    let mut session = flight.session;
    for (index, worker) in [alternate("worker-b", 18), alternate("worker-c", 19)]
        .into_iter()
        .enumerate()
    {
        flight.retire_attempt(&previous, session);
        session = flight
            .coord
            .admit_worker_session(&worker)
            .unwrap()
            .1
            .unwrap();
        let retry = flight
            .coord
            .begin_retry_dispatch(&flight.key, flight.serial, &previous, &worker, 60_000)
            .unwrap();
        assert_eq!(retry.action_generation, flight.primary.action_generation);
        assert_eq!(retry.action_key, flight.primary.action_key);
        assert_ne!(retry.attempt_id, previous.attempt_id);
        assert_ne!(retry.execution_lease_id, previous.execution_lease_id);
        assert!(Arc::ptr_eq(&retained, &flight.input()));
        let actor = flight.coord.submitted_actor(&flight.key).unwrap().unwrap();
        assert_eq!(actor.retries_remaining(), u32::try_from(1 - index).unwrap());
        assert!(actor.attempts().any(|attempt| {
            attempt.attempt == retry.attempt_id && attempt.purpose == AttemptPurpose::Retry
        }));
        assert_eq!(
            flight.coord.advance_started_dispatch(
                &flight.key,
                flight.serial,
                &previous,
                AttemptState::Draining,
            ),
            Err(SubmissionRefusal::StaleDispatch),
        );
        assert_eq!(
            flight
                .coord
                .complete_started_dispatch(&flight.key, flight.serial, &previous),
            Err(SubmissionRefusal::StaleDispatch),
            "a predecessor cannot settle its successor's dispatch",
        );
        flight.running(&retry);
        previous = retry;
    }
    flight.retire_attempt(&previous, session);
    let fourth = alternate("worker-d", 20);
    flight.coord.admit_worker_session(&fourth).unwrap();
    assert_eq!(
        flight
            .coord
            .begin_retry_dispatch(&flight.key, flight.serial, &previous, &fourth, 60_000,),
        Err(SubmissionRefusal::Admission(
            "actor retry budget exhausted".into()
        )),
    );
    {
        let mut store = flight.coord.live_cas().unwrap().store().lock().unwrap();
        assert_eq!(store.generation_count().unwrap(), 1);
        assert_eq!(
            store
                .query("SELECT COUNT(*) FROM action_attempts", &[])
                .unwrap(),
            vec![vec![SqlValue::Int(3)]],
        );
        assert_eq!(
            store
                .query(
                    "SELECT COUNT(*) FROM execution_leases WHERE released = 0",
                    &[]
                )
                .unwrap(),
            vec![vec![SqlValue::Int(0)]],
        );
    }
    let materialized = crate::test_util::private_tempdir();
    let roots = retained
        .materialize_into(&materialized.path().join("capture"))
        .unwrap();
    assert_eq!(
        std::fs::read(roots["workspace"].join("input.txt")).unwrap(),
        b"projected bytes\n",
    );
    flight.assert_no_result();
    flight.finish(&previous);
}

#[test]
fn retry_admission_refusals_preserve_the_settleable_owner_and_budget() {
    let flight = Flight::new();
    let worker = alternate("worker-b", 18);
    assert_eq!(
        flight.coord.begin_retry_dispatch(
            &flight.key,
            flight.serial,
            &flight.primary,
            &worker,
            60_000,
        ),
        Err(SubmissionRefusal::StaleDispatch),
        "retirement and lease release must happen before replacement admission",
    );
    flight.retire_attempt(&flight.primary, flight.session);
    for refused in [
        flight.coord.begin_retry_dispatch(
            &flight.key,
            flight.serial,
            &flight.primary,
            &flight.worker,
            60_000,
        ),
        flight.coord.begin_retry_dispatch(
            &flight.key,
            flight.serial,
            &flight.primary,
            &worker,
            60_000,
        ),
    ] {
        assert!(matches!(refused, Err(SubmissionRefusal::Admission(_))));
    }
    flight.coord.admit_worker_session(&worker).unwrap();
    assert_eq!(
        flight
            .coord
            .begin_retry_dispatch(&flight.key, flight.serial, &flight.primary, &worker, 0,),
        Err(SubmissionRefusal::Admission(
            "retry lease: LeaseExpired".into()
        )),
    );
    let actor = flight.coord.submitted_actor(&flight.key).unwrap().unwrap();
    assert_eq!(actor.retries_remaining(), 2);
    assert_eq!(actor.attempts().count(), 1);
    assert_eq!(
        flight
            .coord
            .live_cas()
            .unwrap()
            .store()
            .lock()
            .unwrap()
            .query("SELECT COUNT(*) FROM execution_leases", &[])
            .unwrap(),
        vec![vec![SqlValue::Int(1)]],
    );
    flight.finish(&flight.primary);
    flight.assert_no_result();
}

#[test]
fn retry_ready_settlement_fences_the_old_generation_before_a_fresh_primary() {
    let flight = Flight::new();
    flight.retire_attempt(&flight.primary, flight.session);
    flight.finish(&flight.primary);
    flight.assert_no_result();
    let joined = flight
        .coord
        .submit_action(
            submission(&flight.source, &flight.manifest, &flight.descriptor),
            request(2, SubscriberKind::ForegroundAgent, 200),
            2,
            0,
        )
        .unwrap();
    assert_eq!(joined.action_key, flight.key);
    let serial = flight
        .coord
        .claim_submitted_dispatch(&flight.key)
        .unwrap()
        .unwrap();
    assert_ne!(serial, flight.serial);
    let worker = alternate("worker-b", 18);
    flight.coord.admit_worker_session(&worker).unwrap();
    let primary = flight
        .coord
        .begin_claimed_dispatch(&flight.key, serial, &worker, 60_000)
        .unwrap();
    assert_ne!(primary.action_generation, flight.primary.action_generation);
    assert_ne!(primary.attempt_id, flight.primary.attempt_id);
    assert_eq!(
        flight
            .coord
            .submitted_actor(&flight.key)
            .unwrap()
            .unwrap()
            .attempts()
            .next()
            .unwrap()
            .purpose,
        AttemptPurpose::Primary,
    );
    assert_eq!(
        flight
            .coord
            .complete_started_dispatch(&flight.key, flight.serial, &flight.primary),
        Err(SubmissionRefusal::StaleDispatch),
    );
}

#[test]
fn retry_retirement_requires_the_exact_current_authority_and_pre_execution_state() {
    let flight = Flight::new();
    let mut changed = flight.primary.clone();
    changed.execution_lease_id = ExecutionLeaseId(changed.execution_lease_id.0 + 100);
    assert_eq!(
        flight
            .coord
            .prepare_retry_dispatch(&flight.key, flight.serial, &changed),
        Err(SubmissionRefusal::StaleDispatch),
    );
    let mut changed = flight.primary.clone();
    changed.worker_incarnation_id = WorkerIncarnationId(999);
    assert_eq!(
        flight
            .coord
            .prepare_retry_dispatch(&flight.key, flight.serial, &changed),
        Err(SubmissionRefusal::StaleDispatch),
    );
    assert_eq!(
        flight
            .coord
            .prepare_retry_dispatch(&flight.key, flight.serial + 1, &flight.primary),
        Err(SubmissionRefusal::StaleDispatch),
    );
    assert!(!flight.lease_released(&flight.primary));
    flight
        .coord
        .advance_started_dispatch(
            &flight.key,
            flight.serial,
            &flight.primary,
            AttemptState::ProcessExited,
        )
        .unwrap();
    assert_eq!(
        flight
            .coord
            .prepare_retry_dispatch(&flight.key, flight.serial, &flight.primary),
        Err(SubmissionRefusal::StaleDispatch),
        "a known executed result cannot enter pre-execution failover",
    );
    assert!(!flight.lease_released(&flight.primary));
    flight.assert_no_result();
}

#[test]
fn canceled_retry_ready_generation_cannot_admit_an_alternate() {
    let flight = Flight::new();
    flight.retire_attempt(&flight.primary, flight.session);
    assert_eq!(
        flight
            .coord
            .cancel_subscriber(&flight.key, BuildOperationId(1))
            .unwrap(),
        CancelReceipt::LastInterestCancelledGeneration,
    );
    let worker = alternate("worker-b", 18);
    flight.coord.admit_worker_session(&worker).unwrap();
    assert_eq!(
        flight.coord.begin_retry_dispatch(
            &flight.key,
            flight.serial,
            &flight.primary,
            &worker,
            60_000,
        ),
        Err(SubmissionRefusal::StaleDispatch),
    );
    assert!(flight.coord.next_action_dispatch().unwrap().is_none());
    let mut store = flight.coord.live_cas().unwrap().store().lock().unwrap();
    assert!(
        store
            .generation_state(flight.primary.action_generation.generation_id.0)
            .unwrap()
            .unwrap()
            .tombstoned
    );
    assert_eq!(store.generation_count().unwrap(), 1);
}

#[test]
fn uncertain_abandoned_attempt_does_not_become_retry_ready() {
    let flight = Flight::new();
    flight
        .coord
        .release_dispatch_claim(&flight.key, flight.serial);
    assert_eq!(
        flight
            .coord
            .prepare_retry_dispatch(&flight.key, flight.serial, &flight.primary),
        Err(SubmissionRefusal::StaleDispatch),
    );
    assert!(!flight.lease_released(&flight.primary));
    assert!(!flight.coord.retire_finished_action(&flight.key).unwrap());
    assert!(
        flight
            .coord
            .claim_submitted_dispatch(&flight.key)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        flight
            .coord
            .submit_action(
                submission(&flight.source, &flight.manifest, &flight.descriptor),
                request(2, SubscriberKind::ForegroundAgent, 200),
                2,
                0,
            )
            .unwrap_err(),
        SubmissionRefusal::UnreconciledAttempt,
    );
}

#[test]
fn pre_execution_retirement_can_fence_an_expired_or_already_released_lease() {
    for already_released in [false, true] {
        let mut flight = Flight::new();
        if already_released {
            flight
                .coord
                .live_cas()
                .unwrap()
                .store()
                .lock()
                .unwrap()
                .release_lease(flight.primary.execution_lease_id.0)
                .unwrap();
        }
        // As in the lease-expiry tests above, advance only this coordinator's
        // own clock. Expiry is not execution proof: the caller still explicitly
        // chooses the proven pre-execution retirement API.
        flight.expire_lease_clock();
        flight.retire_attempt(&flight.primary, flight.session);
        let worker = alternate("worker-b", 18);
        let session = flight
            .coord
            .admit_worker_session(&worker)
            .unwrap()
            .1
            .unwrap();
        let retry = flight
            .coord
            .begin_retry_dispatch(&flight.key, flight.serial, &flight.primary, &worker, 60_000)
            .unwrap();
        assert_eq!(retry.action_generation, flight.primary.action_generation);
        assert_eq!(
            flight
                .coord
                .submitted_actor(&flight.key)
                .unwrap()
                .unwrap()
                .retries_remaining(),
            1,
        );
        flight.retire_attempt(&retry, session);
        flight.finish(&retry);
        flight.assert_no_result();
    }
}

#[test]
fn expiry_cannot_hide_a_changed_lease_renewal_during_retry_retirement() {
    let mut flight = Flight::new();
    flight
        .coord
        .renew_attempt_lease(
            &flight.primary,
            LeaseRenewal {
                lease: flight.primary.execution_lease_id,
                seq: LeaseRenewalSeq(1),
            },
            60_000,
        )
        .unwrap();
    flight.expire_lease_clock();
    assert_eq!(
        flight
            .coord
            .prepare_retry_dispatch(&flight.key, flight.serial, &flight.primary),
        Err(SubmissionRefusal::StaleDispatch),
    );
    assert!(!flight.lease_released(&flight.primary));
    assert_eq!(
        flight
            .coord
            .submitted_actor(&flight.key)
            .unwrap()
            .unwrap()
            .attempts()
            .next()
            .unwrap()
            .state,
        AttemptState::Running,
        "failed retirement must not commit its private actor copy",
    );
    flight.assert_no_result();
}
