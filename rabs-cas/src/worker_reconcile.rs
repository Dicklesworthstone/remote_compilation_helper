//! Worker reconcile + stale-operation findings (bead R006; plan §5399
//! operator surface `rch rabs worker reconcile <W>` and the doctor half
//! of Epic R).
//!
//! Two jobs, deliberately split:
//!
//! - **RECONCILE (executes)**: a worker identified as gone (crash,
//!   decommission, operator decision) has its OPEN `worker_sessions` rows
//!   ended, and the CAS-level reconciliation engine
//!   ([`reconcile_startup`]) repairs location drift against filesystem
//!   reality. This produces the evidence that
//!   `GcWorld.reconciliation_complete` previously could only assert.
//! - **DOCTOR (proposes)**: stale operations (non-terminal `state` whose
//!   `updated_seq` lags the operation watermark) and expired-looking pins
//!   are FOUND and turned into typed proposals naming the exact
//!   safe-resolution primitive and its arguments — never applied here.
//!   Applying stays operator work through the fail-closed store methods
//!   (`update_operation_state`, owner-matched `release_pin`); H041's
//!   asymmetry means expiry-looking pins stay protecting until
//!   reconciliation is confirmed, so pin-expiry proposals say so.
//!
//! Enumeration of sessions/operations/pins has no trait-level scan API,
//! so these functions are generic over the SQL engine and use the
//! store's own raw-query seam (`engine_mut`) — the same escape hatch the
//! startup-reconciliation tests use for seeding. Everything else is
//! store + filesystem facts in, report out; no clocks, no I/O beyond
//! the injected [`FilesystemReality`].

use crate::metadata_store::{RabsMetadataStore, SqlEngine, SqlMetadataStore, SqlValue, StoreError};
use crate::startup_reconciliation::{
    Drift, FilesystemReality, ServingDecision, StartupReport, reconcile_startup,
};

/// One still-open worker session row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenSession {
    /// Worker identity.
    pub worker: String,
    /// Process incarnation blob, hex-rendered.
    pub incarnation_hex: String,
    /// The session's start sequence (needed to end it).
    pub started_seq: u64,
}

/// A non-terminal operation whose bookkeeping fell behind the watermark.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaleOperation {
    /// Operation id (hex text).
    pub id_hex: String,
    /// Operation kind.
    pub kind: String,
    /// Current state (never advanced past this).
    pub state: String,
    /// The sequence it was last touched at.
    pub updated_seq: u64,
    /// How far behind the operation watermark it sits.
    pub lag: u64,
}

/// A proposed safe resolution: names the exact fail-closed primitive and
/// its arguments. Never applied by this module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposedResolution {
    /// What is stale (e.g. `operation:<id_hex>`, `pin:<id_hex>`).
    pub target: String,
    /// The primitive to call, rendered with arguments.
    pub action: String,
    /// Why this is safe (and any precondition, e.g. H041 confirmation).
    pub remediation: String,
}

/// The full receipt of one worker reconciliation pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerReconcileReport {
    /// Worker this pass targeted.
    pub worker: String,
    /// Open session rows ended by this pass.
    pub sessions_ended: u32,
    /// Location drift repaired by [`reconcile_startup`].
    pub repaired: Vec<Drift>,
    /// Orphan paths reported (never deleted) by [`reconcile_startup`].
    pub reported_orphans: Vec<String>,
    /// Authoritative completeness verdict after repair.
    pub serving: ServingDecision,
    /// Stale non-terminal operations found (proposals below).
    pub stale_operations: Vec<StaleOperation>,
    /// Safe resolutions proposed for everything found.
    pub proposals: Vec<ProposedResolution>,
}

fn text_at(row: &[SqlValue], i: usize) -> String {
    match row.get(i) {
        Some(SqlValue::Text(t)) => t.clone(),
        Some(other) => format!("{other:?}"),
        None => String::new(),
    }
}

fn int_at(row: &[SqlValue], i: usize) -> u64 {
    match row.get(i) {
        Some(SqlValue::Int(v)) => (*v).max(0) as u64,
        _ => 0,
    }
}

/// Open `worker_sessions` rows for one worker.
fn open_sessions_for_worker<E: SqlEngine>(
    store: &mut SqlMetadataStore<E>,
    worker: &str,
) -> Result<Vec<OpenSession>, StoreError> {
    let rows = store.engine_mut().query(
        "SELECT worker, incarnation, started_seq FROM worker_sessions \
         WHERE worker = ?1 AND ended_seq IS NULL",
        &[SqlValue::Text(worker.to_owned())],
    )?;
    Ok(rows
        .into_iter()
        .map(|row| {
            let incarnation_hex = match row.get(1) {
                Some(SqlValue::Blob(bytes)) => {
                    bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
                }
                other => format!("{other:?}"),
            };
            OpenSession {
                worker: text_at(&row, 0),
                incarnation_hex,
                started_seq: int_at(&row, 2),
            }
        })
        .collect())
}

/// Non-terminal operations lagging the operation watermark by more than
/// `min_seq_lag`. Terminal states are excluded: they are history, not
/// staleness.
fn stale_operations<E: SqlEngine>(
    store: &mut SqlMetadataStore<E>,
    min_seq_lag: u64,
) -> Result<Vec<StaleOperation>, StoreError> {
    let rows = store.engine_mut().query(
        "SELECT id_hex, kind, state, updated_seq, \
         (SELECT COALESCE(MAX(updated_seq), 0) FROM operations \
          WHERE state NOT IN ('committed', 'failed', 'abandoned')) - updated_seq AS lag \
         FROM operations \
         WHERE state NOT IN ('committed', 'failed', 'abandoned') \
         ORDER BY lag DESC",
        &[],
    )?;
    Ok(rows
        .into_iter()
        .filter_map(|row| {
            let lag = int_at(&row, 4);
            if lag <= min_seq_lag {
                return None;
            }
            Some(StaleOperation {
                id_hex: text_at(&row, 0),
                kind: text_at(&row, 1),
                state: text_at(&row, 2),
                updated_seq: int_at(&row, 3),
                lag,
            })
        })
        .collect())
}

/// Expired-LOOKING pins: released=0 with an `expires_at_seq` already
/// behind `now_seq`. Proposals only — H041 keeps them protecting until
/// reconciliation is confirmed.
fn expired_looking_pins<E: SqlEngine>(
    store: &mut SqlMetadataStore<E>,
    now_seq: u64,
) -> Result<Vec<(String, String, u64)>, StoreError> {
    let rows = store.engine_mut().query(
        "SELECT id_hex, owner, expires_at_seq FROM pins \
         WHERE released = 0 AND expires_at_seq IS NOT NULL AND expires_at_seq < ?1",
        &[SqlValue::Int(now_seq as i64)],
    )?;
    Ok(rows
        .into_iter()
        .map(|row| (text_at(&row, 0), text_at(&row, 1), int_at(&row, 2)))
        .collect())
}

fn operation_proposal(op: &StaleOperation) -> ProposedResolution {
    ProposedResolution {
        target: format!("operation:{}", op.id_hex),
        action: format!("update_operation_state({}, \"abandoned\")", op.id_hex),
        remediation: format!(
            "non-terminal '{}' untouched for {} seqs; abandoning writes one \
             row and releases nothing",
            op.state, op.lag
        ),
    }
}

fn pin_proposal(pin_hex: &str, owner: &str, expires_at: u64, now_seq: u64) -> ProposedResolution {
    ProposedResolution {
        target: format!("pin:{pin_hex}"),
        action: format!("release_pin({pin_hex}, owner={owner:?})"),
        remediation: format!(
            "expires_at_seq {expires_at} < current {now_seq}; H041: stays \
             protecting until reconciliation is CONFIRMED — confirm first"
        ),
    }
}

/// Reconcile one worker: end its open sessions, run the CAS-level
/// startup reconciliation, then FIND stale operations/pins and propose
/// their safe resolutions. Proposals are never applied here.
///
/// # Errors
/// Typed [`StoreError`] from any store step; nothing is partially
/// reported — every completed pass carries the full receipt.
pub fn reconcile_worker<E: SqlEngine>(
    store: &mut SqlMetadataStore<E>,
    filesystem: &dyn FilesystemReality,
    worker: &str,
    now_seq: u64,
    min_operation_seq_lag: u64,
) -> Result<WorkerReconcileReport, StoreError> {
    // 1. End every open session row for this worker. `end_worker_session`
    //    updates only the matching (worker, started_seq) open row and
    //    reports whether it did — re-runs are naturally idempotent.
    let mut sessions_ended = 0u32;
    for session in open_sessions_for_worker(store, worker)? {
        if store.end_worker_session(&session.worker, session.started_seq, now_seq)? {
            sessions_ended += 1;
        }
    }

    // 2. Repair location drift / clear stale tombstones against reality;
    //    orphans are reported, never deleted; completeness is evaluated
    //    fail-closed.
    let startup: StartupReport = reconcile_startup(store, filesystem)?;
    let mut reported_orphans = Vec::new();
    for drift in &startup.reported {
        if let Drift::OrphanPathReported { store_path } = drift {
            reported_orphans.push(store_path.clone());
        }
    }

    // 3. FIND stale operations and expired-looking pins; propose, never
    //    apply. Every proposal names its exact fail-closed primitive.
    let stale = stale_operations(store, min_operation_seq_lag)?;
    let mut proposals: Vec<ProposedResolution> = stale.iter().map(operation_proposal).collect();
    for (pin_hex, owner, expires_at) in expired_looking_pins(store, now_seq)? {
        proposals.push(pin_proposal(&pin_hex, &owner, expires_at, now_seq));
    }

    Ok(WorkerReconcileReport {
        worker: worker.to_owned(),
        sessions_ended,
        repaired: startup.repaired,
        reported_orphans,
        serving: startup.serving,
        stale_operations: stale,
        proposals,
    })
}

/// Read-only variant for `rch rabs doctor`: same FIND half, zero
/// mutation — no session ends, no startup repair.
///
/// # Errors
/// Typed [`StoreError`] from the underlying scans.
pub fn find_stale_state<E: SqlEngine>(
    store: &mut SqlMetadataStore<E>,
    now_seq: u64,
    min_operation_seq_lag: u64,
) -> Result<Vec<ProposedResolution>, StoreError> {
    let mut proposals: Vec<ProposedResolution> = stale_operations(store, min_operation_seq_lag)?
        .iter()
        .map(operation_proposal)
        .collect();
    for (pin_hex, owner, expires_at) in expired_looking_pins(store, now_seq)? {
        proposals.push(pin_proposal(&pin_hex, &owner, expires_at, now_seq));
    }
    Ok(proposals)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata_store::{AuthorityRow, RusqliteEngine, SqlMetadataStore};
    use crate::publication::authority_digest;
    use crate::startup_reconciliation::SetFilesystem;
    use rabs_protocol::authority::{ClusterId, CoordinatorAuthority, CoordinatorIncarnationId};

    /// A store with one ACTIVE authority (operations require it) and two
    /// open sessions for `worker-a`, one abandoned-lagging operation, and
    /// one fresh operation as the watermark.
    fn seeded_store() -> SqlMetadataStore<RusqliteEngine> {
        let mut store =
            SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).expect("store");
        let coordinator = CoordinatorAuthority {
            cluster_id: ClusterId("cluster-a".to_owned()),
            credential_generation: 1,
            term: 3,
            incarnation_id: CoordinatorIncarnationId(77),
        };
        store
            .acquire_authority(&AuthorityRow {
                digest: authority_digest(&coordinator),
                cluster_id: "cluster-a".to_owned(),
                incarnation: 77,
                term: 3,
                acquired_seq: 1,
            })
            .expect("acquire authority");
        store
            .record_worker_session("worker-a", 0x1111, 10)
            .expect("session 1");
        store
            .record_worker_session("worker-a", 0x2222, 20)
            .expect("session 2");
        // The STALE operation: touched at seq 100, never advanced.
        store
            .create_operation(
                &authority_digest(&coordinator),
                0xAA00,
                "build",
                "running",
                100,
            )
            .expect("stale operation");
        // The WATERMARK operation: far ahead, so the first looks stale.
        store
            .create_operation(
                &authority_digest(&coordinator),
                0xAB00,
                "build",
                "running",
                5_000,
            )
            .expect("watermark operation");
        store
    }

    #[test]
    fn reconcile_worker_ends_sessions_and_reports_stale_operations() {
        let mut store = seeded_store();
        let fs = SetFilesystem::default();

        let report = reconcile_worker(&mut store, &fs, "worker-a", 6_000, 100).expect("reconcile");

        // Sessions: both open rows for this worker ended in ONE pass.
        assert_eq!(report.sessions_ended, 2, "both open sessions ended");
        assert!(
            open_sessions_for_worker(&mut store, "worker-a")
                .unwrap()
                .is_empty(),
            "no open session rows survive"
        );

        // FIND: exactly the lagging operation is stale; the watermark op
        // is not.
        assert_eq!(report.stale_operations.len(), 1);
        let stale = &report.stale_operations[0];
        assert_eq!(stale.id_hex, u128_hex(0xAA00));
        assert_eq!(stale.lag, 4_900);
        assert!(
            report
                .proposals
                .iter()
                .any(|p| p.target == format!("operation:{}", u128_hex(0xAA00))),
            "every finding gets a named safe-resolution proposal"
        );
    }

    #[test]
    fn applying_the_proposal_resolves_the_finding() {
        let mut store = seeded_store();
        // Read-only doctor: no filesystem view is needed or touched.
        let _fs = SetFilesystem::default();
        let before = find_stale_state(&mut store, 6_000, 100).expect("doctor");
        assert_eq!(before.len(), 1, "seeded staleness is found");

        // The operator applies the PROPOSED primitive: abandon the op.
        store
            .update_operation_state(0xAA00, "abandoned", 6_000)
            .expect("apply proposal");

        let after = find_stale_state(&mut store, 6_100, 100).expect("doctor again");
        assert!(
            after.is_empty(),
            "seeded stale state is FOUND + RESOLVED: {after:?}"
        );
    }

    #[test]
    fn reconcile_pass_is_idempotent_for_sessions_and_doctor_finds_nothing_else() {
        let mut store = seeded_store();
        let fs = SetFilesystem::default();
        let first = reconcile_worker(&mut store, &fs, "worker-a", 6_000, 100).unwrap();
        assert_eq!(first.sessions_ended, 2);
        let second = reconcile_worker(&mut store, &fs, "worker-a", 6_500, 100).unwrap();
        assert_eq!(second.sessions_ended, 0, "no sessions left to end");

        // Serving completeness is evaluated and surfaced either way.
        assert!(matches!(
            second.serving,
            ServingDecision::Allowed | ServingDecision::Refused(_)
        ));
    }

    fn u128_hex(v: u128) -> String {
        format!("{v:032x}")
    }
}
