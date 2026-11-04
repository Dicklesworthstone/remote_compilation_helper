//! Non-authoritative secondary indexes for the live serving queries.
//!
//! The versioned metadata schema remains the sole definition of authoritative
//! tables. These optional access paths do not add data, summaries, policy state,
//! or a second evidence journal. Old/library clients give the same answers
//! without them. The live mount installs the whole profile transactionally,
//! after schema migration and before reconciliation or coordinator admission.
//! Index construction can take time/disk on an old store; it never happens on
//! the compiler's hot path. Reopening a store does not rebuild existing indexes.

use crate::metadata_store::{SqlEngine, SqlMetadataStore, StoreError};

const OUTCOME_INDEX: &str = "CREATE INDEX IF NOT EXISTS idx_rabs_verification_outcome_action_v1 ON verification_samples (passed, action_key)";
const DISPOSITION_INDEX: &str = "CREATE INDEX IF NOT EXISTS idx_rabs_serving_disposition_action_v1 ON action_serving_states (disposition, action_key)";

/// No correctness judgment depends on either index. Failure rolls back this
/// profile, reports the error, and leaves the mounted caller to close its store.
/// Never rollback on BEGIN failure: a transaction we did not start is not ours.
pub fn prepare_serving_indexes<E: SqlEngine>(
    store: &mut SqlMetadataStore<E>,
) -> Result<(), StoreError> {
    install(store.engine_mut())
}

fn install(engine: &mut impl SqlEngine) -> Result<(), StoreError> {
    engine.execute("BEGIN IMMEDIATE", &[])?;
    let result: Result<(), StoreError> = (|| {
        engine.execute(OUTCOME_INDEX, &[])?;
        engine.execute(DISPOSITION_INDEX, &[])?;
        engine.execute("COMMIT", &[])?;
        Ok(())
    })();
    if let Err(error) = result {
        if let Err(rollback) = engine.execute("ROLLBACK", &[]) {
            return Err(StoreError::Backend(format!(
                "read-index setup failed: {error:?}; rollback failed: {rollback:?}"
            )));
        }
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata_store::{
        FsqliteEngine, RabsMetadataStore, RusqliteEngine, SqlMetadataStore, SqlValue,
    };

    const PROFILE: &str = "SELECT name FROM sqlite_master WHERE type = 'index' AND name IN ('idx_rabs_verification_outcome_action_v1', 'idx_rabs_serving_disposition_action_v1') ORDER BY name";

    fn exercise<E: SqlEngine>(engine: E) -> Vec<String> {
        let mut store = SqlMetadataStore::open(engine).unwrap();
        // Use real schema tables. Indexing does not repair/reclassify a sample
        // even when that sample names an unknown attempt or has an invalid flag.
        for (seq, outcome) in [0, 1, 2, -1].into_iter().enumerate() {
            store.engine_mut().execute(
                "INSERT INTO verification_samples (action_key, attempt_hex, passed, seq) VALUES (?1, ?2, ?3, ?4)",
                &[
                    SqlValue::Text("fixture-action".into()),
                    SqlValue::Text("unknown-attempt".into()),
                    SqlValue::Int(outcome),
                    SqlValue::Int(seq as i64),
                ],
            ).unwrap();
        }
        let before = store.differential_snapshot().unwrap();
        install(store.engine_mut()).unwrap();
        install(store.engine_mut()).unwrap();
        assert_eq!(store.differential_snapshot().unwrap(), before);
        assert_eq!(store.engine_mut().query(PROFILE, &[]).unwrap().len(), 2);
        let adverse = store.engine_mut().query(
            "SELECT passed FROM verification_samples WHERE passed < 1 OR passed > 1 ORDER BY passed",
            &[],
        ).unwrap();
        assert_eq!(
            adverse,
            vec![
                vec![SqlValue::Int(-1)],
                vec![SqlValue::Int(0)],
                vec![SqlValue::Int(2)],
            ]
        );
        before
    }

    #[test]
    fn secondary_indexes_are_idempotent_and_preserve_authoritative_rows() {
        exercise(RusqliteEngine::open_in_memory().unwrap());
    }

    #[test]
    fn both_metadata_engines_preserve_the_same_rows_and_predicates() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("rabs-read-indexes-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        assert_eq!(
            exercise(RusqliteEngine::open(&dir.join("reference.db")).unwrap()),
            exercise(FsqliteEngine::open(&dir.join("candidate.db")).unwrap()),
        );
    }

    struct FailOnce<'a, E> {
        engine: &'a mut E,
        statement: &'static str,
        failed: bool,
    }

    impl<E: SqlEngine> SqlEngine for FailOnce<'_, E> {
        fn execute(&mut self, sql: &str, parameters: &[SqlValue]) -> Result<usize, StoreError> {
            if sql == self.statement && !self.failed {
                self.failed = true;
                return Err(StoreError::Backend("injected index setup failure".into()));
            }
            self.engine.execute(sql, parameters)
        }

        fn query(
            &mut self,
            sql: &str,
            parameters: &[SqlValue],
        ) -> Result<Vec<Vec<SqlValue>>, StoreError> {
            self.engine.query(sql, parameters)
        }
    }

    #[test]
    fn every_failed_setup_boundary_rolls_back_without_data_or_partial_profile() {
        for statement in [OUTCOME_INDEX, DISPOSITION_INDEX, "COMMIT"] {
            let mut store =
                SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap();
            let before = store.differential_snapshot().unwrap();
            let mut fault = FailOnce {
                engine: store.engine_mut(),
                statement,
                failed: false,
            };
            assert!(install(&mut fault).is_err());
            assert!(fault.failed);
            assert!(fault.query(PROFILE, &[]).unwrap().is_empty());
            install(&mut fault).unwrap();
            assert_eq!(fault.query(PROFILE, &[]).unwrap().len(), 2);
            assert_eq!(store.differential_snapshot().unwrap(), before);
        }
    }

    #[test]
    fn failed_begin_does_not_rollback_an_existing_caller_transaction() {
        let mut store = SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap();
        let engine = store.engine_mut();
        engine.execute("BEGIN IMMEDIATE", &[]).unwrap();
        engine.execute(
            "INSERT INTO decision_receipts (kind, subject, seq, decision, reason) VALUES ('caller', 'owned', 0, 'retain', 'not an index transaction')",
            &[],
        ).unwrap();
        assert!(install(engine).is_err());
        engine.execute("COMMIT", &[]).unwrap();
        assert_eq!(
            engine
                .query(
                    "SELECT subject FROM decision_receipts WHERE kind = 'caller'",
                    &[]
                )
                .unwrap(),
            vec![vec![SqlValue::Text("owned".into())]]
        );
    }
}
