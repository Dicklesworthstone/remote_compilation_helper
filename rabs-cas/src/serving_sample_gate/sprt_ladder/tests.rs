//! Real metadata-engine exercises with synthetic admitted-comparison fixtures.
//! These do not claim real compiler executions or a measured divergence rate.

use super::*;
use crate::metadata_store::{FsqliteEngine, RusqliteEngine, SqlMetadataStore};
use crate::serving_sample_gate::tests::{action, fresh_path, published, samples};
use crate::serving_sample_gate::{ActionClassRisk, SampleGateDecision, SamplingPolicy, decide};

fn bound(store: &mut dyn RabsMetadataStore, tag: u8, generation: u128) -> String {
    let key = published(store, tag, generation);
    store
        .record_decision_receipt(CLASS_KIND, &key, 0, CLASS, "synthetic descriptor binding")
        .unwrap();
    key
}

fn proof(store: &mut dyn RabsMetadataStore, tag: u8, generation: u128, attempt: u128, seq: u64) {
    let key = crate::metadata_store::digest_key(&action(tag));
    store
        .record_attempt(attempt, generation, "fixture-verifier", seq)
        .unwrap();
    store
        .record_verification_sample(&action(tag), attempt, true, seq)
        .unwrap();
    let manifest = store.published_manifest_key_str(&key).unwrap().unwrap();
    store
        .record_decision_receipt(VERIFIED, &key, seq, &format!("{attempt:032x}"), &manifest)
        .unwrap();
}

fn drain(store: &mut dyn RabsMetadataStore) -> Checkpoint {
    let mut previous = None;
    for _ in 0..100 {
        let next = advance(store).unwrap();
        if previous == Some(next) {
            return next;
        }
        previous = Some(next);
    }
    panic!("bounded fixture journal never settled");
}

fn attribution_scenarios(store: &mut dyn RabsMetadataStore) -> Vec<String> {
    let key = bound(store, 1, 10);
    proof(store, 1, 10, 10_001, 1);
    assert_eq!(drain(store).passes, 1);
    let manifest = store.published_manifest_key_str(&key).unwrap().unwrap();

    // A second sample and receipt for the same admitted attempt is NOT a trial.
    store
        .record_verification_sample(&action(1), 10_001, true, 2)
        .unwrap();
    store
        .record_decision_receipt(VERIFIED, &key, 2, &format!("{:032x}", 10_001), &manifest)
        .unwrap();
    // A raw sample has no publication-engine acknowledgment.
    store
        .record_attempt(10_002, 10, "fixture-verifier", 3)
        .unwrap();
    store
        .record_verification_sample(&action(1), 10_002, true, 3)
        .unwrap();
    // A winner re-offer, even with a forged positive receipt, is not independent.
    store
        .record_verification_sample(&action(1), 101, true, 4)
        .unwrap();
    store
        .record_decision_receipt(VERIFIED, &key, 4, &format!("{:032x}", 101), &manifest)
        .unwrap();
    // Unknown attempt and wrong manifest cannot manufacture positive credit.
    store
        .record_verification_sample(&action(1), 999_999, true, 5)
        .unwrap();
    store
        .record_decision_receipt(VERIFIED, &key, 5, &format!("{:032x}", 999_999), &manifest)
        .unwrap();
    store
        .record_attempt(10_003, 10, "fixture-verifier", 6)
        .unwrap();
    store
        .record_verification_sample(&action(1), 10_003, true, 6)
        .unwrap();
    store
        .record_decision_receipt(
            VERIFIED,
            &key,
            6,
            &format!("{:032x}", 10_003),
            "wrong-manifest",
        )
        .unwrap();
    assert_eq!(drain(store).passes, 1);

    let private = published(store, 2, 11);
    store
        .record_decision_receipt(CLASS_KIND, &private, 0, "private-only", CLASS)
        .unwrap();
    proof(store, 2, 11, 11_001, 1);
    // Attribute a private action's attempt to the requested action: refused.
    store
        .record_verification_sample(&action(1), 11_001, true, 7)
        .unwrap();
    store
        .record_decision_receipt(VERIFIED, &key, 7, &format!("{:032x}", 11_001), &manifest)
        .unwrap();
    assert_eq!(drain(store).passes, 1);

    proof(store, 1, 10, 10_004, 8);
    assert_eq!(drain(store).passes, 2);
    store.differential_snapshot().unwrap()
}

#[test]
fn exact_sprt_crossings_spend_three_disjoint_windows_and_never_reach_zero_floor() {
    let expected = [10_000, 2_500, 500, 100];
    for passes in 0..=FINAL_PASSES {
        let checkpoint = Checkpoint {
            cursor: passes as i64,
            passes,
        };
        let stage = (passes / PASSES_PER_STEP) as usize;
        assert_eq!(checkpoint.verification_bps(), expected[stage]);
        assert_eq!(
            checkpoint.replay_limit() + 1,
            10_000 / u64::from(expected[stage])
        );
    }
    // The previous integer is strictly before every boundary, not promoted.
    for step in 1..=3_u64 {
        let before = Checkpoint {
            cursor: 0,
            passes: step * PASSES_PER_STEP - 1,
        };
        let at = Checkpoint {
            cursor: 0,
            passes: step * PASSES_PER_STEP,
        };
        assert_eq!(before.step() + 1, at.step());
    }
}

#[test]
fn only_attributed_independent_publication_comparisons_earn_credit() {
    let mut store = SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap();
    attribution_scenarios(&mut store);
}

#[test]
fn reference_and_frankensqlite_fold_the_same_evidence() {
    let mut reference =
        SqlMetadataStore::open(RusqliteEngine::open(&fresh_path("sprt-ref")).unwrap()).unwrap();
    let mut candidate =
        SqlMetadataStore::open(FsqliteEngine::open(&fresh_path("sprt-fsq")).unwrap()).unwrap();
    assert_eq!(
        attribution_scenarios(&mut reference),
        attribution_scenarios(&mut candidate)
    );
}

#[test]
fn marker_before_checkpoint_crash_loses_credit_instead_of_double_counting() {
    let mut store = SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap();
    let key = bound(&mut store, 1, 10);
    proof(&mut store, 1, 10, 10_001, 1);
    store
        .record_decision_receipt(
            COUNTED,
            &format!("{key}:{:032x}", 10_001),
            0,
            "consumed",
            CLASS,
        )
        .unwrap();
    assert_eq!(drain(&mut store).passes, 0);
    proof(&mut store, 1, 10, 10_002, 2);
    assert_eq!(drain(&mut store).passes, 1);
    // Even losing/rewinding the scan checkpoint cannot replay consumed trials.
    Checkpoint::default().persist(&mut store).unwrap();
    assert_eq!(drain(&mut store).passes, 0);
    proof(&mut store, 1, 10, 10_003, 3);
    assert_eq!(drain(&mut store).passes, 1);
}

#[test]
fn checkpoint_and_attempt_identity_survive_real_database_reopening() {
    let path = fresh_path("sprt-reopen");
    let key;
    {
        let mut store = SqlMetadataStore::open(RusqliteEngine::open(&path).unwrap()).unwrap();
        key = bound(&mut store, 1, 10);
        proof(&mut store, 1, 10, 10_001, 1);
        assert_eq!(drain(&mut store).passes, 1);
    }
    let mut store = SqlMetadataStore::open(RusqliteEngine::open(&path).unwrap()).unwrap();
    store.intern_domain("rabs.result-manifest.sha256.v1");
    let manifest = store.published_manifest_key_str(&key).unwrap().unwrap();
    // Reinsert the same receipt: the append-only API acknowledges an exact
    // retry without rewriting it. The stable attempt marker must still win.
    store
        .record_decision_receipt(VERIFIED, &key, 1, &format!("{:032x}", 10_001), &manifest)
        .unwrap();
    assert_eq!(drain(&mut store).passes, 1);
    proof(&mut store, 1, 10, 10_002, 2);
    assert_eq!(drain(&mut store).passes, 2);
    drop(store);

    let mut store = SqlMetadataStore::open(RusqliteEngine::open(&path).unwrap()).unwrap();
    store.intern_domain("rabs.result-manifest.sha256.v1");
    assert_eq!(Checkpoint::load(&mut store).unwrap().passes, 2);
    proof(&mut store, 1, 10, 10_003, 3);
    assert_eq!(drain(&mut store).passes, 3);
    assert_eq!(checkpoint_history(&mut store).len(), 3);
}

#[test]
fn opt_in_gate_requires_verification_without_mutating_existing_publication() {
    let mut store = SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap();
    let key = bound(&mut store, 1, 10);
    samples(&mut store, 1, 10, 3, 0);
    let policy = SamplingPolicy::sample_all(2, 10_000);
    let before = store.differential_snapshot().unwrap();
    assert_eq!(
        decide(
            &mut store,
            &action(1),
            ActionClassRisk::LowRiskRegistry,
            &policy,
            false
        )
        .unwrap(),
        SampleGateDecision::ServeFromCache
    );
    assert_eq!(store.differential_snapshot().unwrap(), before);
    let manifest = store.published_manifest_key_str(&key).unwrap();
    assert_eq!(
        decide(
            &mut store,
            &action(1),
            ActionClassRisk::LowRiskRegistry,
            &policy,
            true
        )
        .unwrap(),
        SampleGateDecision::ExecutePrivately(PrivateExecutionReason::ClassVerificationRequired {
            class: CLASS.into(),
            credited_comparisons: 0,
            verification_basis_points: 10_000,
        })
    );
    assert_eq!(store.published_manifest_key_str(&key).unwrap(), manifest);
    assert_eq!(
        store.serving_disposition_key(&key).unwrap().as_deref(),
        Some("servable")
    );
}

#[test]
fn negative_evidence_vetoes_before_any_sprt_credit_or_checkpoint_write() {
    let mut store = SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap();
    bound(&mut store, 1, 10);
    samples(&mut store, 1, 10, 3, 0);
    let culprit = bound(&mut store, 2, 11);
    proof(&mut store, 1, 10, 10_099, 99);
    store
        .record_verification_sample(&action(2), 999_999, false, 1)
        .unwrap();
    let before = store.differential_snapshot().unwrap();
    let result = decide(
        &mut store,
        &action(1),
        ActionClassRisk::LowRiskRegistry,
        &SamplingPolicy::sample_all(2, 10_000),
        true,
    )
    .unwrap();
    assert!(
        matches!(result, SampleGateDecision::ExecutePrivately(PrivateExecutionReason::ClassSafetyHold { culprit_action_key, .. }) if culprit_action_key == culprit)
    );
    assert_eq!(store.differential_snapshot().unwrap(), before);
}

#[test]
fn invalid_checkpoints_and_conflicting_attempt_markers_refuse() {
    for (passes, cursor) in [
        ("01", "10"),
        ("1", "0"),
        ("209287", "300000"),
        ("1", "-1"),
        ("1", "9223372036854775808"),
    ] {
        // Each corrupt receipt is immutable; test it independently instead
        // of assuming that the same primary key can be overwritten.
        let mut store = SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap();
        store
            .record_decision_receipt(STATE, CLASS, 0, passes, cursor)
            .unwrap();
        assert!(Checkpoint::load(&mut store).is_err());
    }
    let mut store = SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap();
    let key = bound(&mut store, 1, 10);
    Checkpoint::default().persist(&mut store).unwrap();
    proof(&mut store, 1, 10, 10_001, 1);
    store
        .record_decision_receipt(
            COUNTED,
            &format!("{key}:{:032x}", 10_001),
            0,
            "consumed",
            "another-class",
        )
        .unwrap();
    assert!(advance(&mut store).is_err());
}

#[test]
fn promotion_receipts_bind_each_boundary_and_do_not_advance_evidence() {
    let mut store = SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap();
    // Boundary injection exercises receipt encoding/idempotency ONLY. It is
    // not a substitute for earning comparisons through the journal reducer.
    let at = Checkpoint {
        cursor: FINAL_PASSES as i64,
        passes: FINAL_PASSES,
    };
    record_crossings(&mut store, at).unwrap();
    for (step, bps) in [(1, 2500), (2, 500), (3, 100)] {
        let (decision, reason) = receipt(&mut store, PROMOTION, CLASS, step)
            .unwrap()
            .unwrap();
        assert_eq!(decision, format!("verification-bps={bps}"));
        assert!(reason.contains(&format!("cumulative-passes={}", step * PASSES_PER_STEP)));
        assert!(reason.contains("llr=-6.906786798374720935"));
    }
    let before = store.differential_snapshot().unwrap();
    record_crossings(&mut store, at).unwrap();
    assert_eq!(store.differential_snapshot().unwrap(), before);
    assert_eq!(Checkpoint::load(&mut store).unwrap().passes, 0);
}

#[test]
fn comparison_cadence_uses_existing_durable_install_receipts() {
    let mut store = SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap();
    let key = bound(&mut store, 1, 10);
    assert_eq!(used_since_comparison(&mut store, &key).unwrap(), None);
    proof(&mut store, 1, 10, 10_001, 1);
    for used in 0..=3 {
        assert_eq!(used_since_comparison(&mut store, &key).unwrap(), Some(used));
        store
            .record_decision_receipt(INSTALL, &format!("{key}:1"), used, "install", "fixture")
            .unwrap();
    }
    proof(&mut store, 1, 10, 10_002, 2);
    assert_eq!(used_since_comparison(&mut store, &key).unwrap(), Some(0));
}

fn checkpoint_history(store: &mut dyn RabsMetadataStore) -> Vec<Vec<SqlValue>> {
    store
        .query(
            "SELECT seq, decision, reason FROM decision_receipts WHERE kind = ?1 AND subject = ?2 ORDER BY seq",
            &[SqlValue::Text(STATE.into()), SqlValue::Text(CLASS.into())],
        )
        .unwrap()
}

fn progressive_checkpoint_scenario(store: &mut dyn RabsMetadataStore) -> Vec<String> {
    bound(store, 1, 10);
    let mut prior = Vec::new();
    for comparison in 1..=4_u64 {
        proof(store, 1, 10, 20_000 + u128::from(comparison), comparison);
        assert_eq!(drain(store).passes, comparison);
        let history = checkpoint_history(store);
        assert_eq!(history.len(), comparison as usize);
        assert_eq!(&history[..prior.len()], prior.as_slice());
        assert_eq!(
            history.last().unwrap()[0],
            SqlValue::Int(comparison as i64 - 1)
        );
        assert_eq!(
            history.last().unwrap()[1],
            SqlValue::Text(comparison.to_string())
        );
        prior = history;

        // An exact retry after an ambiguous successful append must not even
        // create another generation. It cannot earn or reset sample credit.
        let checkpoint = Checkpoint::load(store).unwrap();
        let before = store.differential_snapshot().unwrap();
        checkpoint.persist(store).unwrap();
        assert_eq!(store.differential_snapshot().unwrap(), before);
    }
    store.differential_snapshot().unwrap()
}

#[test]
fn successive_checkpoint_generations_preserve_history_and_retry_idempotently() {
    let mut store = SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap();
    progressive_checkpoint_scenario(&mut store);
}

#[test]
fn reference_and_frankensqlite_append_identical_checkpoint_histories() {
    let mut reference =
        SqlMetadataStore::open(RusqliteEngine::open(&fresh_path("sprt-generations-ref")).unwrap())
            .unwrap();
    let mut candidate =
        SqlMetadataStore::open(FsqliteEngine::open(&fresh_path("sprt-generations-fsq")).unwrap())
            .unwrap();
    assert_eq!(
        progressive_checkpoint_scenario(&mut reference),
        progressive_checkpoint_scenario(&mut candidate)
    );
}

#[test]
fn legacy_seq_zero_is_retained_while_new_evidence_advances() {
    let mut store = SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap();
    bound(&mut store, 1, 10);
    store
        .record_decision_receipt(STATE, CLASS, 0, "0", "0")
        .unwrap();
    let legacy = checkpoint_history(&mut store);
    for comparison in 1..=3_u64 {
        proof(
            &mut store,
            1,
            10,
            30_000 + u128::from(comparison),
            comparison,
        );
        assert_eq!(drain(&mut store).passes, comparison);
    }
    let history = checkpoint_history(&mut store);
    assert_eq!(history.len(), 4);
    assert_eq!(&history[..1], legacy.as_slice());
    // The store still rejects rewriting an old checkpoint. This fix must not
    // turn the shared audit journal into a mutable state table.
    assert!(matches!(
        store.record_decision_receipt(STATE, CLASS, 0, "1", "1"),
        Err(StoreError::AppendConflict(_))
    ));
    assert_eq!(checkpoint_history(&mut store), history);
}

#[test]
fn latest_generation_not_rowid_cursor_or_pass_count_selects_the_checkpoint() {
    let mut store = SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap();
    // Synthetic restore order: an older, more optimistic checkpoint gets a
    // later rowid. A higher cursor/pass count does not make it authoritative.
    store
        .record_decision_receipt(STATE, CLASS, 5, "1", "7")
        .unwrap();
    store
        .record_decision_receipt(STATE, CLASS, 4, "100", "100")
        .unwrap();
    // Other receipt kinds and other class subjects cannot select a generation.
    store
        .record_decision_receipt(STATE, "other-class", i64::MAX as u64, "1", "1")
        .unwrap();
    store
        .record_decision_receipt("other-state", CLASS, i64::MAX as u64, "1", "1")
        .unwrap();
    assert_eq!(
        Checkpoint::load(&mut store).unwrap(),
        Checkpoint {
            cursor: 7,
            passes: 1
        }
    );
    Checkpoint {
        cursor: 10,
        passes: 2,
    }
    .persist(&mut store)
    .unwrap();
    assert_eq!(
        Checkpoint::latest(&mut store).unwrap(),
        Some((
            6,
            Checkpoint {
                cursor: 10,
                passes: 2
            }
        ))
    );
}

#[test]
fn malformed_latest_generation_never_falls_back_to_a_valid_older_checkpoint() {
    for (passes, cursor) in [
        ("01", "10"),
        ("1", "0"),
        ("1", "-1"),
        ("1", "9223372036854775808"),
    ] {
        let mut store = SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap();
        Checkpoint {
            cursor: 10,
            passes: 1,
        }
        .persist(&mut store)
        .unwrap();
        store
            .record_decision_receipt(STATE, CLASS, 1, passes, cursor)
            .unwrap();
        let before = store.differential_snapshot().unwrap();
        assert!(Checkpoint::load(&mut store).is_err());
        assert!(Checkpoint::default().persist(&mut store).is_err());
        assert!(advance(&mut store).is_err());
        assert_eq!(store.differential_snapshot().unwrap(), before);
    }
}

#[test]
fn generation_overflow_refuses_without_rewriting_or_resetting_evidence() {
    let mut store = SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap();
    store
        .record_decision_receipt(STATE, CLASS, i64::MAX as u64, "1", "10")
        .unwrap();
    let before = store.differential_snapshot().unwrap();
    // An exact retry needs no new generation even at the integer boundary.
    Checkpoint {
        cursor: 10,
        passes: 1,
    }
    .persist(&mut store)
    .unwrap();
    assert!(matches!(
        Checkpoint { cursor: 11, passes: 2 }.persist(&mut store),
        Err(StoreError::Corruption(reason)) if reason.contains("generation overflow")
    ));
    assert_eq!(store.differential_snapshot().unwrap(), before);
}

#[test]
fn invalid_new_checkpoint_cannot_append_over_a_healthy_journal() {
    let mut store = SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap();
    Checkpoint {
        cursor: 10,
        passes: 1,
    }
    .persist(&mut store)
    .unwrap();
    let before = store.differential_snapshot().unwrap();
    for checkpoint in [
        Checkpoint {
            cursor: -1,
            passes: 0,
        },
        Checkpoint {
            cursor: 1,
            passes: 2,
        },
        Checkpoint {
            cursor: i64::MAX,
            passes: FINAL_PASSES + 1,
        },
    ] {
        assert!(checkpoint.persist(&mut store).is_err());
    }
    assert_eq!(store.differential_snapshot().unwrap(), before);
}

#[test]
fn full_pages_of_internal_history_advance_but_idle_scans_do_not_append_forever() {
    let mut store = SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap();
    bound(&mut store, 1, 10);
    proof(&mut store, 1, 10, 40_001, 1);
    assert_eq!(drain(&mut store).passes, 1);
    for index in 0..2 * PAGE {
        store
            .record_decision_receipt(
                COUNTED,
                &format!("synthetic-history-{index}"),
                0,
                "consumed",
                CLASS,
            )
            .unwrap();
    }
    proof(&mut store, 1, 10, 40_002, 2);
    assert_eq!(drain(&mut store).passes, 2);
    assert!(checkpoint_history(&mut store).len() >= 4);
    let before = store.differential_snapshot().unwrap();
    for _ in 0..100 {
        assert_eq!(advance(&mut store).unwrap().passes, 2);
    }
    assert_eq!(store.differential_snapshot().unwrap(), before);
}
