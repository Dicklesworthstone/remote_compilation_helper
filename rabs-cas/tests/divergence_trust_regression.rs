//! Publication -> trust -> serving regression for bd-rhdef / H026 / H033.
//!
//! These tests call the production publication engine with synthetic offer
//! digests and locations. They verify metadata and admission semantics, not an
//! authenticated remote compile, real artifact transfer, or wrapper cache hit.
#![cfg(feature = "test-support")]

use std::sync::atomic::{AtomicU64, Ordering};

use rabs_cas::metadata_store::{
    FsqliteEngine, RabsMetadataStore, RusqliteEngine, SqlMetadataStore, SqlValue, digest_key,
};
use rabs_cas::publication::{
    CommitDurabilityProfile, DISPOSITION_PRESENTATION_QUARANTINED, DIVERGENCE_EVIDENCE_PIN_CLASS,
    OfferPreparedActionResult, PublicationOutcome, authority_digest, process_offer,
};
use rabs_cas::serving_sample_gate::{
    ActionClassRisk, SampleGateDecision, SamplingPolicy, serving_sample_decision,
};
use rabs_cas::serving_state::{ServeDecision, serving_gate};
use rabs_cas::test_support::{
    divergent_offer_under, install_offer_closure, install_ready_store, sample_action_key,
    sample_coordinator_authority, sample_declared, sample_evidence, sample_expected_descriptor,
    sample_offer, tagged_digest, tagged_object,
};
use rabs_cas::trust_evidence::{
    DISPOSITION_QUARANTINED, DISPOSITION_SERVABLE, TrustPolicy, reevaluate_action,
};
use rabs_protocol::result_identity::DivergenceClass;
use rabs_protocol::serving::TrustEvidenceTier;

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

fn divergence_scenario(store: &mut dyn RabsMetadataStore, presentation_only: bool) -> Vec<String> {
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
        let policies = [TrustPolicy {
            version,
            revoked: false,
            required_tier,
        }];
        let evaluation =
            reevaluate_action(store, &authority, &action, &policies, 20 + u64::from(version))
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
        divergence_scenario(&mut store, presentation_only);
    }
}

#[test]
fn publication_divergence_survives_reevaluation_and_reopen_differential() {
    for presentation_only in [false, true] {
        let reference_path = fresh_path("ref");
        let candidate_path = fresh_path("fsq");
        let snapshot = {
            let reference_engine = RusqliteEngine::open(&reference_path).unwrap();
            let candidate_engine = FsqliteEngine::open(&candidate_path).unwrap();
            let mut reference = SqlMetadataStore::open(reference_engine).unwrap();
            let mut candidate = SqlMetadataStore::open(candidate_engine).unwrap();
            let snapshot = divergence_scenario(&mut reference, presentation_only);
            assert_eq!(
                divergence_scenario(&mut candidate, presentation_only),
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
