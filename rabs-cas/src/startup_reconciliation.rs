//! Startup consistency reconciliation (bead H013; plan §62; risk R119).
//!
//! On start, the coordinator checks metadata rows against filesystem
//! reality before it serves anything:
//!
//! - a LOCATION row whose path is gone is drift: the row is repaired
//!   away (the object's logical identity is untouched — losing a copy
//!   degrades to a miss, never to source loss);
//! - a TOMBSTONE whose location row is already gone is stale staging/
//!   journal state: cleared;
//! - a filesystem path with no metadata row is an ORPHAN: reported for
//!   operator adoption or deletion, never auto-deleted (RULE: repair
//!   metadata to match reality, report reality that metadata never
//!   claimed);
//! - AUTHORITY/PUBLICATION/FENCE incompleteness is NOT drift, it is a
//!   torn authoritative state: serving is REFUSED (fail-closed) until
//!   restore/reconciliation or an explicit operator reset. Concretely:
//!   publications with a missing or released reachability pin, missing
//!   serving state, or missing winner evidence; publications or
//!   generations present while the authority history is empty;
//!   generations present without the never-reuse high-water mark.
//!
//! The distinction is the point: losing nonauthority location/index
//! metadata degrades to misses and reindex; losing authority,
//! publication, or fence state must never be treated as an ordinary
//! cold cache (plan §62).

use crate::metadata_store::{QuarantineScope, RabsMetadataStore, StoreError};

/// Filesystem reality as the reconciler sees it. The production adapter
/// wraps real IO; tests use a set-backed view.
pub trait FilesystemReality {
    /// Whether the stored path currently exists with readable content.
    fn exists(&self, store_path: &str) -> bool;
    /// Every path present under the store roots (orphan detection).
    fn all_paths(&self) -> Vec<String>;
}

/// A set-backed filesystem view (tests, dry runs, remote reports).
#[derive(Debug, Clone, Default)]
pub struct SetFilesystem {
    /// Present paths.
    pub paths: std::collections::BTreeSet<String>,
}

impl FilesystemReality for SetFilesystem {
    fn exists(&self, store_path: &str) -> bool {
        self.paths.contains(store_path)
    }

    fn all_paths(&self) -> Vec<String> {
        self.paths.iter().cloned().collect()
    }
}

/// One observed drift item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Drift {
    /// Metadata claimed a location whose path is gone; row removed.
    MissingLocationRepaired {
        /// Object digest key.
        object_key: String,
        /// The vanished path.
        store_path: String,
    },
    /// A tombstone pointed at a location row that no longer exists;
    /// tombstone cleared.
    StaleTombstoneCleared {
        /// Object digest key.
        object_key: String,
        /// The tombstoned path.
        store_path: String,
    },
    /// A path exists on disk that no metadata row claims. Reported only —
    /// never auto-deleted.
    OrphanPathReported {
        /// The unclaimed path.
        store_path: String,
    },
}

/// Why serving is refused (torn authoritative state; R119).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IncompleteState {
    /// A publication's reachability pin is missing entirely.
    PublicationPinMissing {
        /// The action key.
        action_key: String,
    },
    /// A publication's reachability pin exists but was released.
    PublicationPinReleased {
        /// The action key.
        action_key: String,
    },
    /// A publication has no serving-state row.
    ServingStateMissing {
        /// The action key.
        action_key: String,
    },
    /// A publication has no winner evidence row.
    EvidenceMissing {
        /// The action key.
        action_key: String,
    },
    /// Publications or generations exist but the authority history is
    /// empty (restored/rolled-back database).
    AuthorityHistoryMissing,
    /// Generations exist without the never-reuse high-water mark.
    GenerationHighWaterMissing,
}

/// Serving decision after reconciliation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServingDecision {
    /// Authoritative state is complete; serving may start.
    Allowed,
    /// Torn authoritative state: REFUSE serving until restored or
    /// explicitly reset by an operator.
    Refused(Vec<IncompleteState>),
}

/// The reconciliation product.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupReport {
    /// Drift repaired in the metadata (rows removed/cleared).
    pub repaired: Vec<Drift>,
    /// Drift reported for the operator (nothing touched).
    pub reported: Vec<Drift>,
    /// Whether this store may serve.
    pub serving: ServingDecision,
}

/// Run startup reconciliation: repair location/tombstone drift against
/// filesystem reality, report orphans, and evaluate authoritative
/// completeness fail-closed.
///
/// # Errors
/// Store errors from the underlying queries/repairs.
pub fn reconcile_startup(
    store: &mut dyn RabsMetadataStore,
    filesystem: &dyn FilesystemReality,
) -> Result<StartupReport, StoreError> {
    let mut repaired = Vec::new();
    let mut reported = Vec::new();

    // 1. Location rows vs reality: vanished copies are repaired away.
    let mut claimed_paths = std::collections::BTreeSet::new();
    for row in store.reconciliation_scan()? {
        claimed_paths.insert(row.store_path.clone());
        if !filesystem.exists(&row.store_path) {
            store.remove_location_by_key(&row.object_key, &row.store_path)?;
            repaired.push(Drift::MissingLocationRepaired {
                object_key: row.object_key,
                store_path: row.store_path,
            });
        }
    }

    // 2. Tombstones whose location row is gone (stale staging/journal
    // state — includes rows repaired in step 1).
    let live_locations: std::collections::BTreeSet<(String, String)> = store
        .reconciliation_scan()?
        .into_iter()
        .map(|r| (r.object_key, r.store_path))
        .collect();
    for tombstone in store.due_gc_tombstones(u64::MAX)? {
        let key = (tombstone.object_key.clone(), tombstone.store_path.clone());
        if !live_locations.contains(&key) {
            store.remove_gc_tombstone(&tombstone.object_key, &tombstone.store_path)?;
            repaired.push(Drift::StaleTombstoneCleared {
                object_key: tombstone.object_key,
                store_path: tombstone.store_path,
            });
        }
    }

    // 3. Orphan paths: reality no metadata row claims. Reported, never
    // deleted.
    for path in filesystem.all_paths() {
        if !claimed_paths.contains(&path) {
            reported.push(Drift::OrphanPathReported { store_path: path });
        }
    }

    // 4. Authoritative completeness — fail-closed (R119).
    let incomplete = authoritative_incompleteness(store)?;

    Ok(StartupReport {
        repaired,
        reported,
        serving: if incomplete.is_empty() {
            ServingDecision::Allowed
        } else {
            ServingDecision::Refused(incomplete)
        },
    })
}

/// Evaluate authoritative completeness (shared by startup and by the
/// H037 reset path). A publication whose serving disposition is
/// `"quarantined"` has already been adjudicated — its torn rows no
/// longer refuse serving. The history-wide gaps (empty authority
/// history, missing generation high-water) refuse serving only until an
/// operator reset has been consumed: the reset opens a NEW authority
/// lineage in which the old lineage's guarantees are void by
/// declaration, not by accident.
fn authoritative_incompleteness(
    store: &mut dyn RabsMetadataStore,
) -> Result<Vec<IncompleteState>, StoreError> {
    let mut incomplete = Vec::new();
    let publications = store.list_publications()?;
    for (action_key, pin_hex) in &publications {
        if store.serving_disposition_key(action_key)?.as_deref() == Some("quarantined") {
            continue;
        }
        match store.pin_released_by_hex(pin_hex)? {
            None => incomplete.push(IncompleteState::PublicationPinMissing {
                action_key: action_key.clone(),
            }),
            Some(true) => incomplete.push(IncompleteState::PublicationPinReleased {
                action_key: action_key.clone(),
            }),
            Some(false) => {}
        }
        if !store.has_serving_state_key(action_key)? {
            incomplete.push(IncompleteState::ServingStateMissing {
                action_key: action_key.clone(),
            });
        }
        if !store.has_evidence_key(action_key)? {
            incomplete.push(IncompleteState::EvidenceMissing {
                action_key: action_key.clone(),
            });
        }
    }
    let reset_consumed = store.highest_operator_reset()?.is_some();
    let generations = store.generation_count()?;
    if (!publications.is_empty() || generations > 0)
        && store.authority_count()? == 0
        && !reset_consumed
    {
        incomplete.push(IncompleteState::AuthorityHistoryMissing);
    }
    if generations > 0 && !store.has_generation_high_water()? && !reset_consumed {
        incomplete.push(IncompleteState::GenerationHighWaterMissing);
    }
    Ok(incomplete)
}

/// Outcome of consuming an operator reset (H037).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResetOutcome {
    /// The consumed reset generation.
    pub generation: u64,
    /// Action keys whose torn publications were quarantined under the
    /// reset (they will never serve as cache hits from the old lineage).
    pub quarantined_actions: Vec<String>,
}

/// H037: consume an explicit operator-reset generation over a store
/// whose authoritative state is torn. Every publication that is
/// currently incomplete is quarantined (serving disposition
/// `"quarantined"` + a scoped quarantine row — adjudicated, never
/// silently trusted), and the reset generation is recorded monotonically
/// (a replayed or stale proof is `StoreError::StaleOperatorReset`).
/// After a successful reset, `reconcile_startup` allows serving under
/// the new lineage.
///
/// # Errors
/// `StaleOperatorReset` for replayed proofs; store errors otherwise.
pub fn apply_operator_reset(
    store: &mut dyn RabsMetadataStore,
    generation: u64,
    seq: u64,
) -> Result<ResetOutcome, StoreError> {
    // Record FIRST: a stale proof must not quarantine anything.
    store.record_operator_reset(generation, seq)?;
    let incomplete = authoritative_incompleteness(store)?;
    let mut quarantined_actions = Vec::new();
    for state in incomplete {
        let action_key = match state {
            IncompleteState::PublicationPinMissing { action_key }
            | IncompleteState::PublicationPinReleased { action_key }
            | IncompleteState::ServingStateMissing { action_key }
            | IncompleteState::EvidenceMissing { action_key } => action_key,
            IncompleteState::AuthorityHistoryMissing
            | IncompleteState::GenerationHighWaterMissing => continue,
        };
        if quarantined_actions.contains(&action_key) {
            continue;
        }
        store.set_serving_disposition_key(&action_key, "quarantined")?;
        store.add_quarantine(
            QuarantineScope::ActionEntry,
            &action_key,
            "operator reset: pre-reset publication state incomplete",
        )?;
        quarantined_actions.push(action_key);
    }
    Ok(ResetOutcome {
        generation,
        quarantined_actions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata_store::{
        ActionEntryRow, AuthorityRow, FsqliteEngine, PublicationRow, ResultKindTag, RusqliteEngine,
        SqlEngine, SqlMetadataStore, digest_key,
    };
    use rabs_protocol::result_identity::{DigestAlgorithm, TypedDigest};
    use std::sync::atomic::{AtomicU64, Ordering};

    static DB_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn fresh_path(tag: &str) -> std::path::PathBuf {
        let n = DB_COUNTER.fetch_add(1, Ordering::SeqCst);
        std::env::temp_dir().join(format!("rabs-h013-{}-{}-{}.db", std::process::id(), tag, n))
    }

    fn digest(domain: &'static str, tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain,
            bytes: [tag; 32],
        }
    }

    fn object(tag: u8) -> TypedDigest {
        digest("rabs.object.sha256.v1", tag)
    }

    /// A healthy store: authority, action, generation, attempt, lease,
    /// committed publication, two located objects.
    fn healthy<E: SqlEngine>(store: &mut SqlMetadataStore<E>) {
        let auth = digest("rabs.authority.sha256.v1", 1);
        store
            .acquire_authority(&AuthorityRow {
                digest: auth.clone(),
                cluster_id: "c".to_owned(),
                incarnation: 1,
                term: 1,
                acquired_seq: 1,
            })
            .unwrap();
        let action = digest("rabs.action-key.sha256.v1", 7);
        store
            .upsert_action_entry(&ActionEntryRow {
                action_key: action.clone(),
                key_epoch: 0,
                projection_epoch: 0,
            })
            .unwrap();
        store.create_generation(&auth, 11, &action).unwrap();
        store.record_attempt(20, 11, "w", 1).unwrap();
        for tag in [50u8, 51] {
            store.record_object(&object(tag), 64).unwrap();
            store
                .add_location(&object(tag), &format!("/cas/{tag}"), Some(1), "raw", true)
                .unwrap();
        }
        store
            .commit_publication(
                &auth,
                &PublicationRow {
                    action_key: action,
                    descriptor_digest: digest("rabs.descriptor.sha256.v1", 8),
                    manifest_digest: object(50),
                    evidence_digest: object(51),
                    winner_generation: 11,
                    winner_attempt: 20,
                    result_kind: ResultKindTag::Success,
                    pin_id: 40,
                    pin_owner: "coordinator".to_owned(),
                },
            )
            .unwrap();
    }

    fn full_filesystem() -> SetFilesystem {
        SetFilesystem {
            paths: ["/cas/50", "/cas/51"]
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
        }
    }

    #[test]
    fn h013_healthy_store_serves_with_no_drift() {
        let mut store = SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap();
        healthy(&mut store);
        let report = reconcile_startup(&mut store, &full_filesystem()).unwrap();
        assert!(report.repaired.is_empty());
        assert!(report.reported.is_empty());
        assert_eq!(report.serving, ServingDecision::Allowed);
    }

    #[test]
    fn h013_seeded_drift_is_repaired_and_reported() {
        let mut store = SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap();
        healthy(&mut store);
        // Extra object with a location AND a tombstone; its path vanishes.
        store.record_object(&object(60), 64).unwrap();
        store
            .add_location(&object(60), "/cas/60", None, "raw", true)
            .unwrap();
        store
            .add_gc_tombstone(&digest_key(&object(60)), "/cas/60", 1, 2)
            .unwrap();
        // Filesystem: /cas/60 is GONE; /cas/99 is an unclaimed orphan.
        let mut filesystem = full_filesystem();
        filesystem.paths.insert("/cas/99".to_owned());

        let report = reconcile_startup(&mut store, &filesystem).unwrap();
        assert_eq!(
            report.repaired,
            vec![
                Drift::MissingLocationRepaired {
                    object_key: digest_key(&object(60)),
                    store_path: "/cas/60".to_owned(),
                },
                Drift::StaleTombstoneCleared {
                    object_key: digest_key(&object(60)),
                    store_path: "/cas/60".to_owned(),
                },
            ]
        );
        assert_eq!(
            report.reported,
            vec![Drift::OrphanPathReported {
                store_path: "/cas/99".to_owned(),
            }]
        );
        // Drift is NOT torn authority: serving still allowed.
        assert_eq!(report.serving, ServingDecision::Allowed);
        // Repairs are durable: a second pass finds nothing.
        let again = reconcile_startup(&mut store, &filesystem).unwrap();
        assert!(again.repaired.is_empty());
    }

    #[test]
    fn h013_incomplete_authoritative_state_refuses_serving() {
        let mut store = SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap();
        healthy(&mut store);
        let action_key = digest_key(&digest("rabs.action-key.sha256.v1", 7));

        // Seed torn state the public API refuses to produce: the
        // publication's pin, serving state, evidence, and the entire
        // authority history vanish (restored/rolled-back database).
        for sql in [
            "DELETE FROM pins",
            "DELETE FROM action_serving_states",
            "DELETE FROM action_evidence_index",
            "DELETE FROM coordinator_authorities",
            "DELETE FROM generation_high_water",
        ] {
            store.engine_mut().execute(sql, &[]).unwrap();
        }

        let report = reconcile_startup(&mut store, &full_filesystem()).unwrap();
        let ServingDecision::Refused(reasons) = report.serving else {
            panic!("torn authoritative state must refuse serving");
        };
        assert_eq!(
            reasons,
            vec![
                IncompleteState::PublicationPinMissing {
                    action_key: action_key.clone(),
                },
                IncompleteState::ServingStateMissing {
                    action_key: action_key.clone(),
                },
                IncompleteState::EvidenceMissing { action_key },
                IncompleteState::AuthorityHistoryMissing,
                IncompleteState::GenerationHighWaterMissing,
            ]
        );
    }

    #[test]
    fn h013_released_publication_pin_refuses_serving() {
        let mut store = SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap();
        healthy(&mut store);
        store.release_pin(40, "coordinator").unwrap();
        let report = reconcile_startup(&mut store, &full_filesystem()).unwrap();
        assert_eq!(
            report.serving,
            ServingDecision::Refused(vec![IncompleteState::PublicationPinReleased {
                action_key: digest_key(&digest("rabs.action-key.sha256.v1", 7)),
            }])
        );
    }

    #[test]
    fn h013_differential_reference_vs_frankensqlite() {
        fn scenario<E: SqlEngine>(store: &mut SqlMetadataStore<E>) -> Vec<String> {
            healthy(store);
            store.record_object(&object(60), 64).unwrap();
            store
                .add_location(&object(60), "/cas/60", None, "raw", true)
                .unwrap();
            let report = reconcile_startup(store, &full_filesystem()).unwrap();
            assert_eq!(report.repaired.len(), 1); // /cas/60 vanished
            assert_eq!(report.serving, ServingDecision::Allowed);
            store.differential_snapshot().unwrap()
        }
        let mut reference =
            SqlMetadataStore::open(RusqliteEngine::open(&fresh_path("ref")).unwrap()).unwrap();
        let mut candidate =
            SqlMetadataStore::open(FsqliteEngine::open(&fresh_path("fsq")).unwrap()).unwrap();
        assert_eq!(scenario(&mut reference), scenario(&mut candidate));
    }

    /// Seed the T039-style rolled-back database: authoritative rows
    /// survive but their authority history, pins, serving states,
    /// evidence, and generation high-water are gone.
    fn roll_back<E: SqlEngine>(store: &mut SqlMetadataStore<E>) {
        for sql in [
            "DELETE FROM pins",
            "DELETE FROM action_serving_states",
            "DELETE FROM action_evidence_index",
            "DELETE FROM coordinator_authorities",
            "DELETE FROM generation_high_water",
        ] {
            store.engine_mut().execute(sql, &[]).unwrap();
        }
    }

    #[test]
    fn h037_rolled_back_db_refuses_until_reset_then_serves_quarantined() {
        let mut store = SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap();
        healthy(&mut store);
        roll_back(&mut store);
        let action_key = digest_key(&digest("rabs.action-key.sha256.v1", 7));

        // NEVER an ordinary cold cache: startup refuses.
        let before = reconcile_startup(&mut store, &full_filesystem()).unwrap();
        assert!(matches!(before.serving, ServingDecision::Refused(_)));

        // Operator reset: torn publication quarantined, reset recorded.
        let outcome = apply_operator_reset(&mut store, 1, 500).unwrap();
        assert_eq!(outcome.generation, 1);
        assert_eq!(outcome.quarantined_actions, vec![action_key.clone()]);
        assert_eq!(
            store
                .serving_disposition_key(&action_key)
                .unwrap()
                .as_deref(),
            Some("quarantined")
        );

        // Serving resumes under the new lineage; the quarantined action
        // never counts as incomplete again.
        let after = reconcile_startup(&mut store, &full_filesystem()).unwrap();
        assert_eq!(after.serving, ServingDecision::Allowed);

        // A replayed or stale reset proof is refused, and quarantines
        // nothing further.
        assert_eq!(
            apply_operator_reset(&mut store, 1, 501),
            Err(crate::metadata_store::StoreError::StaleOperatorReset)
        );
        assert_eq!(store.highest_operator_reset().unwrap(), Some(1));
    }

    #[test]
    fn h037_reset_covers_history_gaps_without_publications() {
        let mut store = SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap();
        healthy(&mut store);
        // Drop the publication too: only generations remain, with the
        // authority history and high-water gone.
        for sql in [
            "DELETE FROM action_publications",
            "DELETE FROM pins",
            "DELETE FROM action_serving_states",
            "DELETE FROM action_evidence_index",
            "DELETE FROM coordinator_authorities",
            "DELETE FROM generation_high_water",
        ] {
            store.engine_mut().execute(sql, &[]).unwrap();
        }
        let before = reconcile_startup(&mut store, &full_filesystem()).unwrap();
        assert_eq!(
            before.serving,
            ServingDecision::Refused(vec![
                IncompleteState::AuthorityHistoryMissing,
                IncompleteState::GenerationHighWaterMissing,
            ])
        );
        let outcome = apply_operator_reset(&mut store, 3, 600).unwrap();
        assert!(outcome.quarantined_actions.is_empty());
        let after = reconcile_startup(&mut store, &full_filesystem()).unwrap();
        assert_eq!(after.serving, ServingDecision::Allowed);
    }

    #[test]
    fn h037_differential_reference_vs_frankensqlite() {
        fn scenario<E: SqlEngine>(store: &mut SqlMetadataStore<E>) -> Vec<String> {
            healthy(store);
            roll_back(store);
            assert!(matches!(
                reconcile_startup(store, &full_filesystem())
                    .unwrap()
                    .serving,
                ServingDecision::Refused(_)
            ));
            apply_operator_reset(store, 2, 700).unwrap();
            assert_eq!(
                reconcile_startup(store, &full_filesystem())
                    .unwrap()
                    .serving,
                ServingDecision::Allowed
            );
            store.differential_snapshot().unwrap()
        }
        let mut reference =
            SqlMetadataStore::open(RusqliteEngine::open(&fresh_path("ref37")).unwrap()).unwrap();
        let mut candidate =
            SqlMetadataStore::open(FsqliteEngine::open(&fresh_path("fsq37")).unwrap()).unwrap();
        assert_eq!(scenario(&mut reference), scenario(&mut candidate));
    }
}
