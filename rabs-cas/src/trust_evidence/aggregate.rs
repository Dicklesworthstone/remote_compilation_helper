//! Exact, non-cached evidence reduction with bounded result rows.
//!
//! The database still examines this action's samples and may use temporary
//! grouping storage. Only two scalar rows cross the metadata API, instead of
//! every sample plus every attributable attempt. The caller holds the existing
//! CAS lock across both queries. No materialized summary can lag a new failure.

use super::VerificationEvidence;
use crate::metadata_store::{RabsMetadataStore, SqlValue, StoreError, digest_key};
use rabs_protocol::result_identity::TypedDigest;

// Match list_verification_samples: nonnegative integer flags are decoded as
// nonzero=true; negative/noninteger flags or sequences and nontext attempt IDs
// are corruption, including for UNKNOWN attempts. Class safety independently
// treats any flag != 1 as adverse. Do not silently narrow either existing rule.
const SAMPLES_SQL: &str = r#"
SELECT COUNT(*),
       COALESCE(SUM(CASE WHEN passed = 0 THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN typeof(attempt_hex) != 'text'
                         OR typeof(passed) != 'integer' OR passed < 0
                         OR typeof(seq) != 'integer' OR seq < 0
                        THEN 1 ELSE 0 END), 0)
FROM verification_samples WHERE action_key = ?1
"#;

// Group one row per attributable attempt BEFORE counting workers. A failure
// dominates every passing observation of the same attempt, not just the last.
// Empty worker identities count neither as attempts nor as distinct workers.
// Validate attribution types before permitting the aggregate to become evidence.
const ATTEMPTS_SQL: &str = r#"
SELECT COALESCE(SUM(CASE WHEN worker != '' THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN worker != '' AND failed = 0 THEN 1 ELSE 0 END), 0),
       COUNT(DISTINCT CASE WHEN worker != '' AND failed = 0 THEN worker END),
       COALESCE(SUM(CASE WHEN typeof(attempt) != 'text' OR typeof(worker) != 'text'
                        THEN 1 ELSE 0 END), 0)
FROM (
    SELECT a.id_hex AS attempt, a.worker AS worker,
           MAX(CASE WHEN s.passed = 0 THEN 1 ELSE 0 END) AS failed
    FROM verification_samples AS s
    JOIN action_attempts AS a ON a.id_hex = s.attempt_hex
    JOIN action_generations AS g ON g.id_hex = a.generation_hex
    WHERE s.action_key = ?1 AND g.action_key = ?1
    GROUP BY a.id_hex, a.worker
) AS attributed
"#;

fn counts<const N: usize>(rows: Vec<Vec<SqlValue>>) -> Result<[u64; N], StoreError> {
    let invalid = || StoreError::Corruption("verification aggregate shape or count".into());
    let [row] = rows.as_slice() else {
        return Err(invalid());
    };
    if row.len() != N {
        return Err(invalid());
    }
    let mut counts = [0; N];
    for (out, value) in counts.iter_mut().zip(row) {
        let SqlValue::Int(value) = value else {
            return Err(invalid());
        };
        *out = u64::try_from(*value).map_err(|_| invalid())?;
    }
    Ok(counts)
}

pub(super) fn read(
    store: &mut dyn RabsMetadataStore,
    action: &TypedDigest,
) -> Result<VerificationEvidence, StoreError> {
    let parameters = [SqlValue::Text(digest_key(action))];
    let [samples, adverse_samples, malformed] = counts(store.query(SAMPLES_SQL, &parameters)?)?;
    if malformed != 0 || adverse_samples > samples {
        return Err(StoreError::Corruption(
            "invalid verification sample aggregate".into(),
        ));
    }
    let [attempts, passed_attempts, workers, malformed] =
        counts(store.query(ATTEMPTS_SQL, &parameters)?)?;
    if malformed != 0
        || workers > passed_attempts
        || passed_attempts > attempts
        || attempts > samples
    {
        return Err(StoreError::Corruption(
            "invalid verification attribution aggregate".into(),
        ));
    }
    let passed_workers = usize::try_from(workers)
        .map_err(|_| StoreError::Corruption("verification worker count overflow".into()))?;
    Ok(VerificationEvidence {
        attempts,
        passed_attempts,
        passed_workers,
        adverse_samples,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata_store::{ActionEntryRow, AuthorityRow};
    use crate::metadata_store::{FsqliteEngine, RusqliteEngine, SqlEngine, SqlMetadataStore};
    use rabs_protocol::result_identity::DigestAlgorithm;
    use std::collections::{BTreeMap, BTreeSet};

    fn action(tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "rabs.action-key.sha256.v1",
            bytes: [tag; 32],
        }
    }

    fn enroll(store: &mut dyn RabsMetadataStore, tag: u8, generation: u128) {
        // Attribution needs recorded action/generation/attempt identities, not
        // invented publication evidence. This helper creates ONLY those rows.
        let authority = TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "rabs.authority.sha256.v1",
            bytes: [1; 32],
        };
        store
            .acquire_authority(&AuthorityRow {
                digest: authority.clone(),
                cluster_id: "aggregate-fixture".into(),
                incarnation: 1,
                term: 1,
                acquired_seq: 1,
            })
            .unwrap();
        store
            .upsert_action_entry(&ActionEntryRow {
                action_key: action(tag),
                key_epoch: 1,
                projection_epoch: 1,
            })
            .unwrap();
        store
            .create_generation(&authority, generation, &action(tag))
            .unwrap();
    }

    // Keep the old list-based algorithm as a differential oracle, not as a
    // production fallback that can hide an unsupported/failed aggregate query.
    fn oracle(store: &mut dyn RabsMetadataStore, key: &TypedDigest) -> [u64; 4] {
        let samples = store.list_verification_samples(key).unwrap();
        let rows = store
            .query(
                "SELECT DISTINCT a.id_hex, a.worker FROM verification_samples s \
             JOIN action_attempts a ON a.id_hex = s.attempt_hex \
             JOIN action_generations g ON g.id_hex = a.generation_hex \
             WHERE s.action_key = ?1 AND g.action_key = ?1 ORDER BY a.id_hex",
                &[SqlValue::Text(digest_key(key))],
            )
            .unwrap();
        let mut attempts = BTreeMap::new();
        for row in rows {
            let [SqlValue::Text(attempt), SqlValue::Text(worker)] = row.as_slice() else {
                panic!("oracle attribution malformed");
            };
            if !worker.is_empty() {
                attempts.insert(attempt.clone(), (worker.clone(), true));
            }
        }
        for sample in &samples {
            if let Some((_, passed)) = attempts.get_mut(&sample.attempt_hex) {
                *passed &= sample.passed;
            }
        }
        let workers: BTreeSet<_> = attempts
            .values()
            .filter(|(_, passed)| *passed)
            .map(|(worker, _)| worker)
            .collect();
        [
            attempts.len() as u64,
            attempts.values().filter(|(_, passed)| *passed).count() as u64,
            workers.len() as u64,
            samples.iter().filter(|sample| !sample.passed).count() as u64,
        ]
    }

    fn actual(store: &mut dyn RabsMetadataStore, key: &TypedDigest) -> [u64; 4] {
        let result = read(store, key).unwrap();
        [
            result.attempts,
            result.passed_attempts,
            result.passed_workers as u64,
            result.adverse_samples,
        ]
    }

    fn scenario(store: &mut dyn RabsMetadataStore) -> Vec<String> {
        enroll(store, 1, 10);
        enroll(store, 2, 11);
        assert_eq!(actual(store, &action(1)), [0; 4]);
        for (id, generation, worker) in [
            (10001, 10, "a"),
            (10002, 10, "a"),
            (10003, 10, "b"),
            (10004, 10, ""),
            (11001, 11, "foreign"),
        ] {
            store.record_attempt(id, generation, worker, 0).unwrap();
        }
        for (seq, id, passed) in [
            (1, 10001, true),
            (2, 10001, true),
            (3, 10002, true),
            (4, 10003, true),
            (5, 10004, true),
            (6, 11001, true),
            (7, 99999, true),
            (8, 99999, false),
            (9, 10001, false),
            (10, 10001, true),
            (11, 11001, false),
        ] {
            store
                .record_verification_sample(&action(1), id, passed, seq)
                .unwrap();
            let before = store.differential_snapshot().unwrap();
            assert_eq!(actual(store, &action(1)), oracle(store, &action(1)));
            assert_eq!(store.differential_snapshot().unwrap(), before);
        }
        assert_eq!(actual(store, &action(1)), [3, 2, 2, 3]);
        assert_eq!(actual(store, &action(2)), [0; 4]);
        store.differential_snapshot().unwrap()
    }

    #[test]
    fn aggregates_match_original_evidence_after_every_observation() {
        let mut store = SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap();
        scenario(&mut store);
    }

    #[test]
    fn both_metadata_engines_reduce_and_reopen_the_same_history() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("rabs-aggregate-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let reference_path = directory.join("reference.db");
        let candidate_path = directory.join("candidate.db");
        {
            let mut reference =
                SqlMetadataStore::open(RusqliteEngine::open(&reference_path).unwrap()).unwrap();
            let mut candidate =
                SqlMetadataStore::open(FsqliteEngine::open(&candidate_path).unwrap()).unwrap();
            assert_eq!(scenario(&mut reference), scenario(&mut candidate));
        }
        let mut reference =
            SqlMetadataStore::open(RusqliteEngine::open(&reference_path).unwrap()).unwrap();
        let mut candidate =
            SqlMetadataStore::open(FsqliteEngine::open(&candidate_path).unwrap()).unwrap();
        assert_eq!(actual(&mut reference, &action(1)), [3, 2, 2, 3]);
        assert_eq!(
            actual(&mut reference, &action(1)),
            actual(&mut candidate, &action(1))
        );
    }

    #[test]
    fn malformed_unknown_samples_cannot_disappear_in_aggregation() {
        for (column, value) in [
            ("passed", SqlValue::Int(-1)),
            ("passed", SqlValue::Text("bad".into())),
            ("seq", SqlValue::Int(-1)),
            ("seq", SqlValue::Text("bad".into())),
            ("attempt_hex", SqlValue::Blob(vec![255])),
        ] {
            let mut store =
                SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap();
            enroll(&mut store, 1, 10);
            store
                .record_verification_sample(&action(1), 99999, true, 1)
                .unwrap();
            store
                .engine_mut()
                .execute(
                    &format!("UPDATE verification_samples SET {column} = ?1"),
                    &[value],
                )
                .unwrap();
            assert!(store.list_verification_samples(&action(1)).is_err());
            assert!(read(&mut store, &action(1)).is_err());
        }
    }

    #[test]
    fn nonzero_integer_outcomes_keep_the_existing_decoder_meaning() {
        let mut store = SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap();
        enroll(&mut store, 1, 10);
        store.record_attempt(10001, 10, "worker", 1).unwrap();
        store
            .record_verification_sample(&action(1), 10001, true, 1)
            .unwrap();
        for flag in [1, 2, i64::MAX, 0] {
            store
                .engine_mut()
                .execute(
                    "UPDATE verification_samples SET passed = ?1",
                    &[SqlValue::Int(flag)],
                )
                .unwrap();
            assert_eq!(
                actual(&mut store, &action(1)),
                oracle(&mut store, &action(1))
            );
        }
    }

    #[test]
    fn malformed_worker_identity_still_refuses_attribution() {
        let mut store = SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap();
        enroll(&mut store, 1, 10);
        store.record_attempt(10001, 10, "worker", 1).unwrap();
        store
            .record_verification_sample(&action(1), 10001, true, 1)
            .unwrap();
        store
            .engine_mut()
            .execute("UPDATE action_attempts SET worker = X'FF'", &[])
            .unwrap();
        assert!(read(&mut store, &action(1)).is_err());
    }

    #[test]
    fn aggregate_shape_and_count_validation_never_default_to_success() {
        assert_eq!(
            counts::<2>(vec![vec![SqlValue::Int(0), SqlValue::Int(3)]]).unwrap(),
            [0, 3]
        );
        for rows in [
            vec![],
            vec![vec![]],
            vec![vec![SqlValue::Int(-1)]],
            vec![vec![SqlValue::Text("1".into())]],
            vec![vec![SqlValue::Null]],
            vec![vec![SqlValue::Int(1)], vec![SqlValue::Int(2)]],
        ] {
            assert!(counts::<1>(rows).is_err());
        }
    }
}
