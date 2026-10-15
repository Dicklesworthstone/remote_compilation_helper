//! Class-wide negative-evidence veto for the first live dependency lane.
//!
//! Use the existing submission receipts and quarantine/evidence tables, not a
//! second state machine or a best-effort post-publication notification. The
//! publication engine's FIRST accepted divergence mutation changes serving
//! disposition; K008 first writes an action quarantine. Both block peers even
//! if subsequent incident/candidate bookkeeping fails. Completed incidents and
//! failed samples survive restart and cannot be outvoted by positive evidence.
//!
//! This is only the conservative demotion half of bd-okthi, not its SPRT
//! promotion ladder. No sampling floor, replay allowance, or repair authority
//! is relaxed. Class holds do not rewrite canonical publications, release
//! candidate pins, or label unrelated keys as having themselves diverged.

use super::PrivateExecutionReason;
use crate::metadata_store::{RabsMetadataStore, SqlValue, StoreError};

// Persisted by rabsd::coord::live::record_descriptor_class from the submitted
// ActionDescriptor. Keep this versioned vocabulary identical to its writer.
const CLASS_RECEIPT: &str = "rabs-live-action-class-v1";
const DEPENDENCY_CLASS: &str = "rustc-dependency-compile";

const CLASS_SQL: &str = r#"
SELECT decision FROM decision_receipts
WHERE kind = ?1 AND subject = ?2 AND seq = 0
"#;

// Bound returned evidence to one witness per category. Do not load every
// action, transcript, sample, or manifest on a compiler's serving path. The
// receipt and evidence primary keys support these exact class/member joins.
const INCIDENT_SQL: &str = r#"
SELECT c.subject FROM decision_receipts AS c
JOIN divergence_incidents AS d ON d.action_key = c.subject
WHERE c.kind = ?1 AND c.seq = 0 AND c.decision = ?2
LIMIT 1
"#;
const ADVERSE_SQL: &str = r#"
SELECT c.subject FROM decision_receipts AS c
JOIN verification_samples AS v ON v.action_key = c.subject
WHERE c.kind = ?1 AND c.seq = 0 AND c.decision = ?2 AND v.passed != 1
LIMIT 1
"#;
const QUARANTINE_SQL: &str = r#"
SELECT c.subject FROM decision_receipts AS c
JOIN quarantines AS q ON q.subject = c.subject
WHERE c.kind = ?1 AND c.seq = 0 AND c.decision = ?2 AND q.scope = 'action-entry'
LIMIT 1
"#;
const DISPOSITION_SQL: &str = r#"
SELECT c.subject FROM decision_receipts AS c
JOIN action_serving_states AS s ON s.action_key = c.subject
WHERE c.kind = ?1 AND c.seq = 0 AND c.decision = ?2
AND s.disposition IN ('quarantined', 'presentation-quarantined')
LIMIT 1
"#;

/// Called under the caller's existing serving transaction/lock. These reads
/// must not be cached across requests: every installation needs a fresh check.
pub(super) fn refusal(
    store: &mut dyn RabsMetadataStore,
    action_key: &str,
) -> Result<Option<PrivateExecutionReason>, StoreError> {
    let rows = store.query(
        CLASS_SQL,
        &[
            SqlValue::Text(CLASS_RECEIPT.to_owned()),
            SqlValue::Text(action_key.to_owned()),
        ],
    )?;
    match rows.as_slice() {
        // The generic CAS gate has non-live users with their own class policy.
        // Do not invent a class for their legacy entries. The live coordinator
        // already treats a missing receipt as Elevated before calling us.
        [] => return Ok(None),
        [row] => match row.as_slice() {
            [SqlValue::Text(class)] if class == DEPENDENCY_CLASS => {}
            // A caller's LowRiskRegistry flag cannot overrule a recorded
            // private/unknown class, even if its per-action evidence passes.
            [SqlValue::Text(_)] => return Ok(Some(PrivateExecutionReason::ElevatedClassRisk)),
            _ => return Err(StoreError::Corruption("invalid live class receipt".into())),
        },
        _ => return Err(StoreError::Corruption("ambiguous live class receipt".into())),
    }
    let parameters = [
        SqlValue::Text(CLASS_RECEIPT.to_owned()),
        SqlValue::Text(DEPENDENCY_CLASS.to_owned()),
    ];
    for (sql, reason) in [
        (INCIDENT_SQL, "divergence-incident"),
        (ADVERSE_SQL, "adverse-verification"),
        (QUARANTINE_SQL, "action-quarantine"),
        (DISPOSITION_SQL, "serving-quarantine"),
    ] {
        let rows = store.query(sql, &parameters)?;
        match rows.as_slice() {
            [] => {}
            [row] => match row.as_slice() {
                [SqlValue::Text(culprit)] if !culprit.is_empty() => {
                    return Ok(Some(PrivateExecutionReason::ClassSafetyHold {
                        class: DEPENDENCY_CLASS.to_owned(),
                        culprit_action_key: culprit.clone(),
                        reason,
                    }));
                }
                _ => return Err(StoreError::Corruption("invalid class safety witness".into())),
            },
            _ => return Err(StoreError::Corruption("unbounded class safety query".into())),
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::super::tests::{action, digest, fresh_path, published, samples};
    use super::super::{
        ActionClassRisk, SampleGateDecision, SamplingPolicy, serving_sample_decision,
    };
    use super::*;
    use crate::metadata_store::{
        DivergenceIncidentRow, FsqliteEngine, QuarantineScope, RusqliteEngine, SqlMetadataStore,
    };

    fn bind(store: &mut dyn RabsMetadataStore, key: &str, class: &str) {
        store
            .record_decision_receipt(CLASS_RECEIPT, key, 0, class, "submitted descriptor")
            .unwrap();
    }

    fn healthy(store: &mut dyn RabsMetadataStore, tag: u8, generation: u128) -> String {
        let key = published(store, tag, generation);
        bind(store, &key, DEPENDENCY_CLASS);
        samples(store, tag, generation, 3, 0);
        key
    }

    fn decide(store: &mut dyn RabsMetadataStore, tag: u8) -> SampleGateDecision {
        serving_sample_decision(
            store,
            &action(tag),
            ActionClassRisk::LowRiskRegistry,
            &SamplingPolicy::sample_all(2, 10_000),
        )
        .unwrap()
    }

    fn assert_hold(
        store: &mut dyn RabsMetadataStore,
        tag: u8,
        culprit: &str,
        reason: &'static str,
    ) {
        let before = store.differential_snapshot().unwrap();
        assert_eq!(
            decide(store, tag),
            SampleGateDecision::ExecutePrivately(PrivateExecutionReason::ClassSafetyHold {
                class: DEPENDENCY_CLASS.to_owned(),
                culprit_action_key: culprit.to_owned(),
                reason,
            })
        );
        assert_eq!(store.differential_snapshot().unwrap(), before);
    }

    fn incident(store: &mut dyn RabsMetadataStore, key: &str, class: &str) {
        store
            .record_divergence_incident(
                &digest("rabs.authority.sha256.v1", 1),
                &DivergenceIncidentRow {
                    action_key: key.to_owned(),
                    seq: 1,
                    class: class.to_owned(),
                    committed_manifest_key: "committed-object".into(),
                    candidate_manifest_key: "candidate-object".into(),
                    candidate_evidence_key: "candidate-evidence".into(),
                    candidate_pin_hex: "retained-pin".into(),
                    generation_hex: "b".into(),
                    attempt_hex: "6f".into(),
                    detail: "preserve existing evidence, do not copy or release it".into(),
                },
            )
            .unwrap();
    }

    fn interrupted_and_completed_scenarios(store: &mut dyn RabsMetadataStore) -> Vec<String> {
        let requested = healthy(store, 1, 10);
        let culprit = healthy(store, 2, 11);
        assert_eq!(decide(store, 1), SampleGateDecision::ServeFromCache);

        // process_offer's first accepted divergence write is sufficient. No
        // feedback sample, incident receipt or post-commit callback is needed.
        for disposition in ["quarantined", "presentation-quarantined"] {
            store
                .set_serving_disposition_key(&culprit, disposition)
                .unwrap();
            assert_hold(store, 1, &culprit, "serving-quarantine");
        }
        store
            .set_serving_disposition_key(&culprit, "servable")
            .unwrap();
        assert_eq!(decide(store, 1), SampleGateDecision::ServeFromCache);

        // K008 instead writes the action-entry quarantine first.
        store
            .add_quarantine(QuarantineScope::ActionEntry, &culprit, "interrupted K008")
            .unwrap();
        assert_hold(store, 1, &culprit, "action-quarantine");
        assert!(
            store
                .list_divergence_incidents(&culprit)
                .unwrap()
                .is_empty()
        );
        // Failed observations are adverse even without an attributable attempt.
        store
            .record_verification_sample(&action(2), 999_999, false, 99)
            .unwrap();
        assert_hold(store, 1, &culprit, "adverse-verification");
        store
            .record_verification_sample(&action(2), 999_999, true, 100)
            .unwrap();
        samples(store, 2, 11, 4, 0);
        assert_hold(store, 1, &culprit, "adverse-verification");

        incident(store, &culprit, "semantic");
        assert_hold(store, 1, &culprit, "divergence-incident");
        // The requested key's own publication, serving state and evidence
        // stay unchanged. Demoting a class does not fabricate N divergences.
        assert_eq!(
            store.serving_disposition_key(&requested).unwrap().as_deref(),
            Some("servable")
        );
        assert!(
            store
                .list_divergence_incidents(&requested)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            store.list_verification_samples(&action(1)).unwrap().len(),
            3
        );
        store.differential_snapshot().unwrap()
    }

    #[test]
    fn class_demotion_is_enforced_by_the_existing_sample_gate() {
        let mut store = SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap();
        interrupted_and_completed_scenarios(&mut store);
    }

    #[test]
    fn class_demotion_matches_the_frankensqlite_backend() {
        let reference_engine = RusqliteEngine::open(&fresh_path("class-ref")).unwrap();
        let candidate_engine = FsqliteEngine::open(&fresh_path("class-fsq")).unwrap();
        let mut reference = SqlMetadataStore::open(reference_engine).unwrap();
        let mut candidate = SqlMetadataStore::open(candidate_engine).unwrap();
        assert_eq!(
            interrupted_and_completed_scenarios(&mut reference),
            interrupted_and_completed_scenarios(&mut candidate)
        );
    }

    #[test]
    fn every_incident_class_blocks_without_rewriting_the_requested_publication() {
        for class in [
            "semantic",
            "observable-only",
            "projection-completeness",
            "serving-sample-divergence",
            "future-unknown",
        ] {
            let mut store =
                SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap();
            healthy(&mut store, 1, 10);
            let culprit = healthy(&mut store, 2, 11);
            incident(&mut store, &culprit, class);
            assert_hold(&mut store, 1, &culprit, "divergence-incident");
            store
                .set_serving_disposition_key(&culprit, "servable")
                .unwrap();
            samples(&mut store, 2, 11, 4, 0);
            assert_hold(&mut store, 1, &culprit, "divergence-incident");
        }
    }

    #[test]
    fn descriptor_class_not_wire_risk_or_incident_text_selects_the_peer_set() {
        let mut store = SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap();
        healthy(&mut store, 1, 10);
        let private = published(&mut store, 2, 11);
        bind(&mut store, &private, "private-only");
        samples(&mut store, 2, 11, 3, 0);
        // Even a forged incident detail/class string cannot change membership.
        incident(&mut store, &private, DEPENDENCY_CLASS);
        assert_eq!(decide(&mut store, 1), SampleGateDecision::ServeFromCache);
        assert_eq!(
            refusal(&mut store, &private).unwrap(),
            Some(PrivateExecutionReason::ElevatedClassRisk)
        );

        let legacy = published(&mut store, 3, 12);
        incident(&mut store, &legacy, DEPENDENCY_CLASS);
        store
            .record_decision_receipt(CLASS_RECEIPT, &legacy, 1, DEPENDENCY_CLASS, "wrong sequence")
            .unwrap();
        store
            .record_decision_receipt("untrusted-class", &legacy, 0, DEPENDENCY_CLASS, "wrong kind")
            .unwrap();
        assert_eq!(decide(&mut store, 1), SampleGateDecision::ServeFromCache);
        // Once the real submission binding exists, legacy evidence is not lost.
        bind(&mut store, &legacy, DEPENDENCY_CLASS);
        assert_hold(&mut store, 1, &legacy, "divergence-incident");
    }

    #[test]
    fn object_quarantine_and_pending_evidence_do_not_fabricate_class_divergence() {
        let mut store = SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap();
        healthy(&mut store, 1, 10);
        let other = healthy(&mut store, 2, 11);
        store
            .add_quarantine(QuarantineScope::LogicalObject, &other, "object repair")
            .unwrap();
        store
            .add_quarantine(QuarantineScope::Location, &other, "replica repair")
            .unwrap();
        store
            .set_serving_disposition_key(&other, "evidence-pending")
            .unwrap();
        assert_eq!(decide(&mut store, 1), SampleGateDecision::ServeFromCache);
    }

    #[test]
    fn reopening_the_store_keeps_the_class_hold_without_a_notification() {
        let path = fresh_path("class-reopen");
        let requested;
        let culprit;
        {
            let mut store = SqlMetadataStore::open(RusqliteEngine::open(&path).unwrap()).unwrap();
            requested = healthy(&mut store, 1, 10);
            culprit = healthy(&mut store, 2, 11);
            incident(&mut store, &culprit, "observable-only");
        }
        let mut reopened = SqlMetadataStore::open(RusqliteEngine::open(&path).unwrap()).unwrap();
        let before = reopened.differential_snapshot().unwrap();
        assert_eq!(
            refusal(&mut reopened, &requested).unwrap(),
            Some(PrivateExecutionReason::ClassSafetyHold {
                class: DEPENDENCY_CLASS.into(),
                culprit_action_key: culprit,
                reason: "divergence-incident",
            })
        );
        assert_eq!(reopened.differential_snapshot().unwrap(), before);
    }
}
