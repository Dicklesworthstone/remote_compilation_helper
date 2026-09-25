//! Publication -> trust -> serving regression for bd-rhdef / H026 / H033.
//!
//! These tests call the production publication engine with synthetic offer
//! digests and locations. They verify metadata and admission semantics, not an
//! authenticated remote compile, real artifact transfer, or wrapper cache hit.
#![cfg(feature = "test-support")]

use std::cell::Cell;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};

use rabs_cas::metadata_store::{
    FsqliteEngine, RabsMetadataStore, RusqliteEngine, SqlEngine, SqlMetadataStore, SqlValue,
    StoreError, digest_key,
};
use rabs_cas::publication::{
    CommitDurabilityProfile, DISPOSITION_PRESENTATION_QUARANTINED, DIVERGENCE_EVIDENCE_PIN_CLASS,
    OfferPreparedActionResult, OfferRefusal, PublicationOutcome, authority_digest, process_offer,
};
use rabs_cas::serving_sample_gate::{
    ActionClassRisk, SampleGateDecision, SamplingPolicy, serving_sample_decision,
};
use rabs_cas::serving_state::{RevalidationError, ServeDecision, apply_revalidation, serving_gate};
use rabs_cas::test_support::{
    divergent_offer_under, install_offer_closure, install_ready_store, sample_action_key,
    sample_coordinator_authority, sample_declared, sample_evidence, sample_expected_descriptor,
    sample_offer, tagged_digest, tagged_object,
};
use rabs_cas::trust_evidence::{
    DISPOSITION_QUARANTINED, DISPOSITION_SERVABLE, TrustPolicy, reevaluate_action,
};
use rabs_protocol::result_identity::DivergenceClass;
use rabs_protocol::serving::{ServingValidity, TrustEvidenceTier};

static DB_COUNTER: AtomicU64 = AtomicU64::new(0);

fn fresh_path(tag: &str) -> std::path::PathBuf {
    let n = DB_COUNTER.fetch_add(1, Ordering::SeqCst);
    std::env::temp_dir().join(format!(
        "rabs-divergence-trust-{tag}-{}-{n}.db",
        std::process::id()
    ))
}

fn expected_disposition(presentation_only: bool) -> &'static str {
    if presentation_only {
        DISPOSITION_PRESENTATION_QUARANTINED
    } else {
        DISPOSITION_QUARANTINED
    }
}

/// The canonical publication, both candidates' evidence, and all pins/edges
/// must remain unchanged while only the trust ledger and serving state move.
fn protected_snapshot(store: &mut dyn RabsMetadataStore) -> Vec<String> {
    store
        .differential_snapshot()
        .unwrap()
        .into_iter()
        .filter(|line| {
            [
                "action_publications|",
                "action_evidence_index|",
                "divergence_incidents|",
                "pins|",
                "object_edges|",
            ]
            .iter()
            .any(|prefix| line.starts_with(*prefix))
        })
        .collect()
}

fn assert_serving_refused(store: &mut dyn RabsMetadataStore, presentation_only: bool) {
    let action = sample_action_key();
    let key = digest_key(&action);
    assert_eq!(
        serving_gate(store, &key, 50, 0).unwrap(),
        ServeDecision::NotServable {
            disposition: expected_disposition(presentation_only).to_owned(),
        }
    );
    assert!(matches!(
        serving_sample_decision(
            store,
            &action,
            ActionClassRisk::LowRiskRegistry,
            &SamplingPolicy::sample_all(2, 10_000),
        )
        .unwrap(),
        SampleGateDecision::ExecutePrivately(_)
    ));
}

fn divergence_scenario(
    store: &mut dyn RabsMetadataStore,
    presentation_only: bool,
    stale_renewal: bool,
) -> Vec<String> {
    install_ready_store(store);
    let coordinator = sample_coordinator_authority();
    let authority = authority_digest(&coordinator);
    let action = sample_action_key();
    let key = digest_key(&action);
    let winner = sample_offer();
    assert!(matches!(
        process_offer(
            store,
            &winner,
            &sample_expected_descriptor(),
            |_| None,
            900,
            1,
            CommitDurabilityProfile::RequireDurableClosure,
            || 10,
        )
        .unwrap(),
        PublicationOutcome::Committed(_)
    ));

    // Positive control: independent passing verification really permits
    // serving before the divergence. Repeated offers are not used as samples.
    store.record_attempt(21, 11, "worker-b", 9).unwrap();
    store
        .record_verification_sample(&action, 20, true, 10)
        .unwrap();
    store
        .record_verification_sample(&action, 21, true, 11)
        .unwrap();
    let policy = [TrustPolicy {
        version: 1,
        revoked: false,
        required_tier: TrustEvidenceTier::ShadowMatched,
    }];
    let evaluation = reevaluate_action(store, &authority, &action, &policy, 12).unwrap();
    assert_eq!(evaluation.disposition, DISPOSITION_SERVABLE);
    assert_eq!(
        serving_gate(store, &key, 50, 0).unwrap(),
        ServeDecision::Servable
    );
    assert_eq!(
        serving_sample_decision(
            store,
            &action,
            ActionClassRisk::LowRiskRegistry,
            &SamplingPolicy::sample_all(2, 10_000),
        )
        .unwrap(),
        SampleGateDecision::ServeFromCache
    );
    let renewal = store.serving_record(&key).unwrap().unwrap();

    let candidate = if presentation_only {
        let manifest_id = tagged_object(54);
        OfferPreparedActionResult::build(
            winner.authority.clone(),
            winner.manifest.clone(),
            manifest_id.clone(),
            sample_evidence(&manifest_id),
            tagged_object(55),
            tagged_digest("rabs.observation-stream.sha256.v1", 10),
            &sample_declared(),
            Vec::new(),
        )
        .unwrap()
    } else {
        divergent_offer_under(&coordinator)
    };
    install_offer_closure(store, &candidate);
    let committed_key = digest_key(&winner.manifest_id.0);
    let outcome = process_offer(
        store,
        &candidate,
        &sample_expected_descriptor(),
        |loaded_key| (loaded_key == committed_key.as_str()).then(|| winner.manifest.clone()),
        901,
        20,
        CommitDurabilityProfile::RequireDurableClosure,
        || 10,
    )
    .unwrap();
    let PublicationOutcome::Quarantined(quarantine) = outcome else {
        panic!("divergent candidate was not quarantined: {outcome:?}");
    };
    assert_eq!(
        quarantine.class,
        if presentation_only {
            DivergenceClass::ObservableOnlyDivergence
        } else {
            DivergenceClass::SemanticDivergence
        }
    );
    assert_eq!(quarantine.candidate_pin_id, 901);
    assert_serving_refused(store, presentation_only);

    let incidents = store.list_divergence_incidents(&key).unwrap();
    assert_eq!(incidents.len(), 1);
    assert_eq!(incidents[0].committed_manifest_key, committed_key);
    assert_eq!(
        incidents[0].candidate_manifest_key,
        digest_key(&candidate.manifest_id.0)
    );
    assert_eq!(
        store
            .query(
                "SELECT root_key, class FROM pins WHERE id_hex = ?1 AND released = 0",
                &[SqlValue::Text(incidents[0].candidate_pin_hex.clone())],
            )
            .unwrap(),
        vec![vec![
            SqlValue::Text(digest_key(&candidate.manifest_id.0)),
            SqlValue::Text(DIVERGENCE_EVIDENCE_PIN_CLASS.to_owned()),
        ]]
    );
    let protected = protected_snapshot(store);
    assert!(!protected.is_empty());

    if stale_renewal {
        assert!(presentation_only);
        // The publication's disposition-only write must now fence a renewal
        // prepared before the divergence. Exercise that production writer
        // rather than corrupting the database or inventing a quarantine.
        assert_eq!(
            store.serving_record(&key).unwrap().unwrap().state_revision,
            renewal.state_revision + 1
        );
        let before_stale_write = store.differential_snapshot().unwrap();
        assert_eq!(
            store.put_serving_record(
                &authority,
                &key,
                DISPOSITION_SERVABLE,
                renewal.state_revision + 1,
                &renewal.validity,
                &[],
            ),
            Err(StoreError::StaleServingRevision)
        );
        assert_eq!(store.differential_snapshot().unwrap(), before_stale_write);

        // A fresh revision is not a repair receipt either. Reject the
        // downgrade inside the same transaction that would write it.
        assert_eq!(
            store.put_serving_record(
                &authority,
                &key,
                DISPOSITION_SERVABLE,
                renewal.state_revision + 2,
                &renewal.validity,
                &[],
            ),
            Err(StoreError::QuarantineRequiresRepair)
        );
        assert_eq!(store.differential_snapshot().unwrap(), before_stale_write);
        assert_eq!(
            store.serving_disposition_key(&key).unwrap().as_deref(),
            Some(DISPOSITION_PRESENTATION_QUARANTINED)
        );
        assert!(
            store
                .query(
                    "SELECT 1 FROM quarantines WHERE scope = 'action-entry' AND subject = ?1",
                    &[SqlValue::Text(key.clone())],
                )
                .unwrap()
                .is_empty(),
            "observable divergence must retain its narrower scope"
        );
        // Before the writer checks, both serving decisions returned a hit
        // here. No failed verification samples happen to hide that bug.
        assert_serving_refused(store, true);

        // Matching failure revalidation is another positive writer. An
        // unresolved incident must refuse before appending any new evidence
        // or renewing the TTL.
        let before_revalidation = store.differential_snapshot().unwrap();
        assert_eq!(
            apply_revalidation(
                store,
                &authority,
                &key,
                &action,
                renewal.state_revision + 1,
                21,
                11,
                "same-observation",
                "same-observation",
                &committed_key,
                &committed_key,
                &digest_key(&winner.evidence_id.0),
                30,
                0,
                None,
            ),
            Err(RevalidationError::ServingBlocked)
        );
        assert_eq!(store.differential_snapshot().unwrap(), before_revalidation);
    }

    // Fresh, independent positive evidence arrives AFTER the divergence.
    // It may strengthen trust evidence, but it is not an incident repair.
    store.record_attempt(22, 11, "worker-c", 21).unwrap();
    store
        .record_verification_sample(&action, 22, true, 21)
        .unwrap();

    // There are no failed samples to mask the bug: the incident itself must
    // keep replay disabled despite adequate evidence and a weaker policy.
    for (version, required_tier) in [
        (2, TrustEvidenceTier::ShadowMatched),
        (3, TrustEvidenceTier::ReproducibleCrossWorker),
        (4, TrustEvidenceTier::UnverifiedCandidate),
    ] {
        if stale_renewal {
            // A later disposition-only update is not a repair either.
            // Reevaluate against the incident itself on every policy change.
            let before = store.differential_snapshot().unwrap();
            assert_eq!(
                store.set_serving_disposition_key(&key, DISPOSITION_SERVABLE),
                Err(StoreError::QuarantineRequiresRepair)
            );
            assert_eq!(store.differential_snapshot().unwrap(), before);
            assert_serving_refused(store, true);
        }
        let policies = [TrustPolicy {
            version,
            revoked: false,
            required_tier,
        }];
        let evaluation = reevaluate_action(
            store,
            &authority,
            &action,
            &policies,
            20 + u64::from(version),
        )
        .unwrap();
        assert_eq!(evaluation.adverse_samples, 0);
        assert!(!evaluation.compromised);
        assert_eq!(
            evaluation.observed_tier,
            TrustEvidenceTier::ReproducibleCrossWorker
        );
        assert_eq!(
            evaluation.disposition,
            expected_disposition(presentation_only)
        );
        assert_serving_refused(store, presentation_only);
        assert_eq!(protected_snapshot(store), protected);
    }
    store.differential_snapshot().unwrap()
}

#[test]
fn publication_divergence_survives_trust_reevaluation_reference() {
    for presentation_only in [false, true] {
        let engine = RusqliteEngine::open_in_memory().unwrap();
        let mut store = SqlMetadataStore::open(engine).unwrap();
        divergence_scenario(&mut store, presentation_only, false);
    }
}

#[test]
fn stale_serving_renewal_cannot_release_presentation_divergence() {
    let engine = RusqliteEngine::open_in_memory().unwrap();
    let mut store = SqlMetadataStore::open(engine).unwrap();
    divergence_scenario(&mut store, true, true);
}

#[test]
fn publication_divergence_survives_reevaluation_and_reopen_differential() {
    for (presentation_only, stale_renewal) in [(false, false), (true, false), (true, true)] {
        let reference_path = fresh_path("ref");
        let candidate_path = fresh_path("fsq");
        let snapshot = {
            let reference_engine = RusqliteEngine::open(&reference_path).unwrap();
            let candidate_engine = FsqliteEngine::open(&candidate_path).unwrap();
            let mut reference = SqlMetadataStore::open(reference_engine).unwrap();
            let mut candidate = SqlMetadataStore::open(candidate_engine).unwrap();
            let snapshot = divergence_scenario(&mut reference, presentation_only, stale_renewal);
            assert_eq!(
                divergence_scenario(&mut candidate, presentation_only, stale_renewal),
                snapshot
            );
            snapshot
        };
        let reference_engine = RusqliteEngine::open(&reference_path).unwrap();
        let candidate_engine = FsqliteEngine::open(&candidate_path).unwrap();
        let mut reference = SqlMetadataStore::open(reference_engine).unwrap();
        let mut candidate = SqlMetadataStore::open(candidate_engine).unwrap();
        let authority = authority_digest(&sample_coordinator_authority());
        let action = sample_action_key();
        let policies = [TrustPolicy {
            version: 5,
            revoked: false,
            required_tier: TrustEvidenceTier::UnverifiedCandidate,
        }];
        for store in [
            &mut reference as &mut dyn RabsMetadataStore,
            &mut candidate as &mut dyn RabsMetadataStore,
        ] {
            assert_eq!(store.differential_snapshot().unwrap(), snapshot);
            let protected = protected_snapshot(store);
            let evaluation = reevaluate_action(store, &authority, &action, &policies, 60).unwrap();
            assert_eq!(
                evaluation.disposition,
                expected_disposition(presentation_only)
            );
            assert_serving_refused(store, presentation_only);
            assert_eq!(protected_snapshot(store), protected);
        }
        assert_eq!(
            reference.differential_snapshot().unwrap(),
            candidate.differential_snapshot().unwrap()
        );
    }
}

/// Fail the real diagnostic transaction after publication has accepted the
/// divergence. All other statements run on the actual metadata backend.
struct FailIncident<E> {
    inner: E,
    armed: Rc<Cell<bool>>,
}

impl<E: SqlEngine> SqlEngine for FailIncident<E> {
    fn execute(&mut self, sql: &str, params: &[SqlValue]) -> Result<usize, StoreError> {
        if self.armed.get() && sql.starts_with("INSERT INTO divergence_incidents") {
            self.armed.set(false);
            return Err(StoreError::Backend(
                "injected incident write failure".to_owned(),
            ));
        }
        self.inner.execute(sql, params)
    }

    fn query(&mut self, sql: &str, params: &[SqlValue]) -> Result<Vec<Vec<SqlValue>>, StoreError> {
        self.inner.query(sql, params)
    }
}

fn failed_incident_scenario(engine: impl SqlEngine, presentation_only: bool) -> (Vec<String>, u64) {
    let armed = Rc::new(Cell::new(false));
    let mut store = SqlMetadataStore::open(FailIncident {
        inner: engine,
        armed: armed.clone(),
    })
    .unwrap();
    install_ready_store(&mut store);
    let authority = authority_digest(&sample_coordinator_authority());
    let action = sample_action_key();
    let key = digest_key(&action);
    let winner = sample_offer();
    assert!(matches!(
        process_offer(
            &mut store,
            &winner,
            &sample_expected_descriptor(),
            |_| None,
            900,
            1,
            CommitDurabilityProfile::RequireDurableClosure,
            || 10,
        )
        .unwrap(),
        PublicationOutcome::Committed(_)
    ));
    store
        .put_serving_record(
            &authority,
            &key,
            DISPOSITION_SERVABLE,
            1,
            &ServingValidity {
                evaluated_at_unix_micros: 1,
                maximum_age_micros: Some(1_000),
                clock_uncertainty_micros: 5,
                coordinator_clock_epoch: 0,
            },
            &[],
        )
        .unwrap();
    let renewal = store.serving_record(&key).unwrap().unwrap();
    assert_eq!(
        serving_gate(&mut store, &key, 50, 0).unwrap(),
        ServeDecision::Servable
    );
    let candidate = if presentation_only {
        let manifest_id = tagged_object(54);
        OfferPreparedActionResult::build(
            winner.authority.clone(),
            winner.manifest.clone(),
            manifest_id.clone(),
            sample_evidence(&manifest_id),
            tagged_object(55),
            tagged_digest("rabs.observation-stream.sha256.v1", 10),
            &sample_declared(),
            Vec::new(),
        )
        .unwrap()
    } else {
        divergent_offer_under(&sample_coordinator_authority())
    };
    install_offer_closure(&mut store, &candidate);
    armed.set(true);
    assert_eq!(
        process_offer(
            &mut store,
            &candidate,
            &sample_expected_descriptor(),
            |_| Some(winner.manifest.clone()),
            901,
            20,
            CommitDurabilityProfile::RequireDurableClosure,
            || 10,
        ),
        Err(OfferRefusal::Store(StoreError::Backend(
            "injected incident write failure".to_owned()
        )))
    );
    assert!(
        !armed.get(),
        "the diagnostic failure boundary must be reached"
    );
    assert!(store.list_divergence_incidents(&key).unwrap().is_empty());
    let quarantined = store.serving_record(&key).unwrap().unwrap();
    assert_eq!(quarantined.state_revision, renewal.state_revision + 1);
    assert_eq!(
        quarantined.disposition,
        expected_disposition(presentation_only)
    );
    assert_eq!(quarantined.validity, renewal.validity);
    assert_eq!(quarantined.authority_key, renewal.authority_key);
    assert_eq!(quarantined.blocking, renewal.blocking);
    let before = store.differential_snapshot().unwrap();
    assert_eq!(
        store.put_serving_record(
            &authority,
            &key,
            DISPOSITION_SERVABLE,
            renewal.state_revision + 1,
            &renewal.validity,
            &[],
        ),
        Err(StoreError::StaleServingRevision)
    );
    assert_eq!(store.differential_snapshot().unwrap(), before);
    for proposed in [
        DISPOSITION_SERVABLE,
        "evidence-pending",
        DISPOSITION_PRESENTATION_QUARANTINED,
    ] {
        if presentation_only && proposed == DISPOSITION_PRESENTATION_QUARANTINED {
            continue;
        }
        assert_eq!(
            store.put_serving_record(
                &authority,
                &key,
                proposed,
                renewal.state_revision + 2,
                &renewal.validity,
                &[],
            ),
            Err(StoreError::QuarantineRequiresRepair)
        );
        assert_eq!(
            store.set_serving_disposition_key(&key, proposed),
            Err(StoreError::QuarantineRequiresRepair)
        );
        assert_eq!(store.differential_snapshot().unwrap(), before);
    }
    assert_serving_refused(&mut store, presentation_only);
    (before, renewal.state_revision + 1)
}

#[test]
fn failed_incident_diagnostic_keeps_stale_renewals_fenced_after_reopen_differential() {
    for presentation_only in [false, true] {
        let reference_path = fresh_path("failed-incident-ref");
        let candidate_path = fresh_path("failed-incident-fsq");
        let (snapshot, stale_revision) = failed_incident_scenario(
            RusqliteEngine::open(&reference_path).unwrap(),
            presentation_only,
        );
        assert_eq!(
            failed_incident_scenario(
                FsqliteEngine::open(&candidate_path).unwrap(),
                presentation_only,
            ),
            (snapshot.clone(), stale_revision)
        );
        let mut reference =
            SqlMetadataStore::open(RusqliteEngine::open(&reference_path).unwrap()).unwrap();
        let mut candidate =
            SqlMetadataStore::open(FsqliteEngine::open(&candidate_path).unwrap()).unwrap();
        let authority = authority_digest(&sample_coordinator_authority());
        let action = sample_action_key();
        let key = digest_key(&action);
        for store in [
            &mut reference as &mut dyn RabsMetadataStore,
            &mut candidate as &mut dyn RabsMetadataStore,
        ] {
            assert_eq!(store.differential_snapshot().unwrap(), snapshot);
            assert!(store.list_divergence_incidents(&key).unwrap().is_empty());
            assert_serving_refused(store, presentation_only);
            let validity = store.serving_record(&key).unwrap().unwrap().validity;
            assert_eq!(
                store.put_serving_record(
                    &authority,
                    &key,
                    DISPOSITION_SERVABLE,
                    stale_revision,
                    &validity,
                    &[],
                ),
                Err(StoreError::StaleServingRevision)
            );
            assert_eq!(store.differential_snapshot().unwrap(), snapshot);
            let policy = [TrustPolicy {
                version: 1,
                revoked: false,
                required_tier: TrustEvidenceTier::UnverifiedCandidate,
            }];
            let evaluation = reevaluate_action(store, &authority, &action, &policy, 60).unwrap();
            assert_eq!(
                evaluation.disposition,
                expected_disposition(presentation_only)
            );
            assert_serving_refused(store, presentation_only);
        }
        assert_eq!(
            reference.differential_snapshot().unwrap(),
            candidate.differential_snapshot().unwrap()
        );
    }
}

/// A second metadata connection quarantines after the evaluator has read its
/// serving snapshot, before it writes its disposition. The incident ledger is
/// deliberately still empty, matching the interrupted-diagnostic boundary.
struct QuarantineAfterServingRead<E: SqlEngine> {
    inner: E,
    writer: SqlMetadataStore<E>,
    armed: Rc<Cell<bool>>,
}

impl<E: SqlEngine> SqlEngine for QuarantineAfterServingRead<E> {
    fn execute(&mut self, sql: &str, params: &[SqlValue]) -> Result<usize, StoreError> {
        self.inner.execute(sql, params)
    }

    fn query(&mut self, sql: &str, params: &[SqlValue]) -> Result<Vec<Vec<SqlValue>>, StoreError> {
        let observed = self.inner.query(sql, params)?;
        if self.armed.get() && sql.starts_with("SELECT disposition, state_revision, authority_key")
        {
            self.armed.set(false);
            self.writer.set_serving_disposition_key(
                &digest_key(&sample_action_key()),
                DISPOSITION_PRESENTATION_QUARANTINED,
            )?;
        }
        Ok(observed)
    }
}

fn stale_trust_scenario<E: SqlEngine>(reader: E, writer: E) -> Vec<String> {
    // Both engines must have the same concrete type for the wrapping store.
    // The generic helper below preserves that constraint without dynamic SQL
    // interception or a second implementation of the serving decision.
    fn scenario<E: SqlEngine>(reader: E, writer: E) -> Vec<String> {
        let writer = SqlMetadataStore::open(writer).unwrap();
        let armed = Rc::new(Cell::new(false));
        let mut store = SqlMetadataStore::open(QuarantineAfterServingRead {
            inner: reader,
            writer,
            armed: armed.clone(),
        })
        .unwrap();
        install_ready_store(&mut store);
        let authority = authority_digest(&sample_coordinator_authority());
        let action = sample_action_key();
        let key = digest_key(&action);
        let winner = sample_offer();
        assert!(matches!(
            process_offer(
                &mut store,
                &winner,
                &sample_expected_descriptor(),
                |_| None,
                900,
                1,
                CommitDurabilityProfile::RequireDurableClosure,
                || 10,
            )
            .unwrap(),
            PublicationOutcome::Committed(_)
        ));
        assert_eq!(
            serving_gate(&mut store, &key, 50, 0).unwrap(),
            ServeDecision::Servable
        );
        let protected = protected_snapshot(&mut store);
        armed.set(true);
        let policy = [TrustPolicy {
            version: 1,
            revoked: false,
            required_tier: TrustEvidenceTier::UnverifiedCandidate,
        }];
        assert_eq!(
            reevaluate_action(&mut store, &authority, &action, &policy, 20),
            Err(rabs_cas::trust_evidence::TrustEvidenceError::Store(
                StoreError::QuarantineRequiresRepair
            ))
        );
        assert!(
            !armed.get(),
            "the concurrent writer must run after the stale read"
        );
        assert!(store.list_divergence_incidents(&key).unwrap().is_empty());
        assert_serving_refused(&mut store, true);
        assert_eq!(protected_snapshot(&mut store), protected);
        store.differential_snapshot().unwrap()
    }
    scenario(reader, writer)
}

#[test]
fn stale_trust_evaluation_cannot_clear_quarantine_from_another_connection() {
    let reference_path = fresh_path("stale-trust-ref");
    let candidate_path = fresh_path("stale-trust-fsq");
    assert_eq!(
        stale_trust_scenario(
            RusqliteEngine::open(&reference_path).unwrap(),
            RusqliteEngine::open(&reference_path).unwrap(),
        ),
        stale_trust_scenario(
            FsqliteEngine::open(&candidate_path).unwrap(),
            FsqliteEngine::open(&candidate_path).unwrap(),
        )
    );
}

/// Model persisted state left by the older writer bug: a genuine divergence
/// incident survives, but the mutable serving projection says "servable".
/// This deliberate SQL fixture is separate from the production writer tests.
struct LegacyServingProjection<E> {
    inner: E,
    armed: Rc<Cell<bool>>,
}

impl<E: SqlEngine> SqlEngine for LegacyServingProjection<E> {
    fn execute(&mut self, sql: &str, params: &[SqlValue]) -> Result<usize, StoreError> {
        let changed = self.inner.execute(sql, params)?;
        if self.armed.get() && sql.starts_with("INSERT INTO divergence_incidents") {
            let action = params
                .first()
                .expect("incident insert binds its action key");
            self.inner.execute(
                "UPDATE action_serving_states SET disposition = 'servable' WHERE action_key = ?1",
                std::slice::from_ref(action),
            )?;
            self.armed.set(false);
        }
        Ok(changed)
    }

    fn query(&mut self, sql: &str, params: &[SqlValue]) -> Result<Vec<Vec<SqlValue>>, StoreError> {
        self.inner.query(sql, params)
    }
}

#[test]
fn durable_incident_blocks_legacy_servable_projection_differential() {
    fn scenario(engine: impl SqlEngine) -> Vec<String> {
        let armed = Rc::new(Cell::new(true));
        let mut store = SqlMetadataStore::open(LegacyServingProjection {
            inner: engine,
            armed: armed.clone(),
        })
        .unwrap();
        let snapshot = divergence_scenario(&mut store, true, false);
        assert!(
            !armed.get(),
            "the legacy damaged projection must be installed"
        );
        snapshot
    }
    assert_eq!(
        scenario(RusqliteEngine::open_in_memory().unwrap()),
        scenario(FsqliteEngine::open(&fresh_path("legacy-projection-fsq")).unwrap())
    );
}
