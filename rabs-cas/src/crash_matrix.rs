//! H015 — crash-injection matrix for every publication boundary (plan
//! §66; M3 acceptance backbone; risks R50/R119).
//!
//! The matrix kills the coordinator at EVERY SQL mutation boundary of
//! the publication protocol — setup (authority/generation/attempt/
//! lease), object upload, offer admission, the atomic commit
//! transaction (publication + serving state + winner evidence +
//! reachability pin), and the H026 divergence-quarantine sequence
//! (quarantine → disposition → edges → pin → evidence → incident →
//! escalation receipts) — including INSIDE store transactions (the
//! budget expires between `BEGIN` and `COMMIT`, leaving a torn
//! transaction for the engine to discard on reopen).
//!
//! After each kill the store is reopened cold and checked:
//!
//! - **no partial result exposure**: a publication row implies its
//!   serving state, winner evidence, and unreleased pin all exist
//!   (verified through H013's [`reconcile_startup`], which refuses
//!   serving on any torn authoritative state);
//! - **no double commit**: never more than one publication row for the
//!   key, and a post-recovery retry converges idempotently to exactly
//!   one, pointing at the original manifest;
//! - **no lost pins**: the committed publication's pin is unreleased,
//!   and once a divergence incident exists its candidate-preservation
//!   pin exists unreleased;
//! - **correct reconciliation**: [`reconcile_startup`] repairs nothing
//!   (the matrix induces no filesystem drift) and always reaches a
//!   serving decision of `Allowed`;
//! - **quarantine monotonicity** (divergence phase): the H026
//!   stricter-state-first write order is visible in every crash state —
//!   escalation receipt ⇒ incident row ⇒ preservation pin ⇒ quarantined
//!   disposition ⇒ quarantine row; the reverse implications may be
//!   absent mid-sequence, the forward ones never.
//!
//! The per-boundary reopened snapshots are returned so the caller can
//! additionally assert the reference and FrankenSQLite engines walk
//! through byte-identical crash states (the T004/T048 differential
//! discipline).

use std::path::{Path, PathBuf};

use rabs_protocol::authority::{ClusterId, CoordinatorAuthority, CoordinatorIncarnationId};
use rabs_protocol::generation::{
    ActionGeneration, ActionGenerationId, AttemptAuthority, AttemptId, ExecutionLeaseId,
    LeaseRenewalSeq, WorkerBootGeneration, WorkerIncarnationId,
};
use rabs_protocol::raw_bytes::RawBytes;
use rabs_protocol::result_identity::{
    AttemptEvidenceBundle, CanonicalActionResultManifest, DigestAlgorithm, DivergenceClass,
    LogicalOutput, ObjectId, OutputRole, ResultKind, TypedDigest,
};
use rabs_protocol::wire_time::PeerId;

use crate::metadata_store::{
    ActionEntryRow, AuthorityRow, RabsMetadataStore, SqlEngine, SqlMetadataStore, SqlValue,
    StoreError, digest_key,
};
use crate::publication::{
    CommitDurabilityProfile, OfferPreparedActionResult, OfferRefusal, PublicationOutcome,
    authority_digest, process_offer,
};
use crate::startup_reconciliation::{ServingDecision, SetFilesystem, reconcile_startup};

/// Marker carried by every engine call refused after the injected
/// crash point: the simulated process is dead.
pub const CRASH_MARKER: &str = "crash-injected";

/// An [`SqlEngine`] wrapper with a mutation budget: once armed, the
/// N-plus-first `execute` (and every call after it, reads included)
/// fails with [`CRASH_MARKER`]. Unarmed it is transparent, so store
/// opening/migrations are never part of the matrix.
pub struct FaultEngine<E> {
    inner: E,
    budget: Option<u64>,
}

impl<E> FaultEngine<E> {
    /// Wrap an engine with no fault armed.
    pub const fn unarmed(inner: E) -> Self {
        Self {
            inner,
            budget: None,
        }
    }

    /// Arm the fault: allow exactly `statements` further mutations,
    /// then fail everything.
    pub const fn arm(&mut self, statements: u64) {
        self.budget = Some(statements);
    }
}

impl<E: SqlEngine> SqlEngine for FaultEngine<E> {
    fn execute(&mut self, sql: &str, params: &[SqlValue]) -> Result<usize, StoreError> {
        match self.budget {
            Some(0) => Err(StoreError::Backend(CRASH_MARKER.to_owned())),
            Some(ref mut remaining) => {
                *remaining -= 1;
                self.inner.execute(sql, params)
            }
            None => self.inner.execute(sql, params),
        }
    }

    fn query(&mut self, sql: &str, params: &[SqlValue]) -> Result<Vec<Vec<SqlValue>>, StoreError> {
        if self.budget == Some(0) {
            return Err(StoreError::Backend(CRASH_MARKER.to_owned()));
        }
        self.inner.query(sql, params)
    }
}

/// One phase of the matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatrixPhase {
    /// Setup + upload + offer + atomic commit of the winner.
    Commit,
    /// A committed baseline, then a semantically divergent offer through
    /// the full H026 quarantine sequence.
    Divergence,
}

impl MatrixPhase {
    const fn tag(self) -> &'static str {
        match self {
            Self::Commit => "commit",
            Self::Divergence => "divergence",
        }
    }
}

/// The matrix product: how many kill points each phase exercised, every
/// invariant violation found (empty = pass), and the reopened snapshot
/// at each kill point for cross-engine differential comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrashMatrixReport {
    /// Kill points injected in the commit phase.
    pub commit_boundaries: u64,
    /// Kill points injected in the divergence phase.
    pub divergence_boundaries: u64,
    /// Invariant violations, each naming phase + kill point + fact.
    pub violations: Vec<String>,
    /// Post-crash, pre-retry differential snapshot per (phase-tag, k).
    pub snapshots: Vec<(String, Vec<String>)>,
}

// ---------------------------------------------------------------------
// Scenario fixtures (self-contained; the matrix is its own world).
// ---------------------------------------------------------------------

fn digest(domain: &'static str, tag: u8) -> TypedDigest {
    TypedDigest {
        algorithm: DigestAlgorithm::Sha256V1,
        domain,
        bytes: [tag; 32],
    }
}

fn object(tag: u8) -> ObjectId {
    ObjectId(digest("rabs.object.sha256.v1", tag))
}

fn coordinator() -> CoordinatorAuthority {
    CoordinatorAuthority {
        cluster_id: ClusterId("crash-matrix".to_owned()),
        credential_generation: 1,
        term: 3,
        incarnation_id: CoordinatorIncarnationId(77),
    }
}

fn attempt_authority() -> AttemptAuthority {
    let coordinator = coordinator();
    let created_under = authority_digest(&coordinator);
    AttemptAuthority {
        coordinator,
        action_key: digest("rabs.action-key.sha256.v1", 7),
        action_generation: ActionGeneration {
            generation_id: ActionGenerationId(11),
            per_key_ordinal: 1,
            created_under_authority_digest: created_under,
        },
        attempt_id: AttemptId(20),
        execution_lease_id: ExecutionLeaseId(30),
        lease_renewal_seq: LeaseRenewalSeq(1),
        worker_peer_id: PeerId("worker-a".to_owned()),
        worker_boot_generation: WorkerBootGeneration(1),
        worker_incarnation_id: WorkerIncarnationId(5),
    }
}

fn winner_manifest() -> CanonicalActionResultManifest {
    CanonicalActionResultManifest {
        action_key: digest("rabs.action-key.sha256.v1", 7),
        canonical_descriptor_digest: digest("rabs.descriptor.sha256.v1", 8),
        key_epoch: 1,
        projection_epoch: 1,
        result_kind: ResultKind::Success,
        artifact_bundle_root: Some(object(40)),
        logical_outputs: vec![LogicalOutput {
            role: OutputRole::Materializable,
            virtual_path: RawBytes::new(b"out/lib.rlib".to_vec()),
            object: object(41),
        }],
        semantic_result_digest: digest("rabs.semantic-result-projection.sha256.v1", 0),
        observable_result_digest: digest("rabs.observable-result-projection.sha256.v1", 0),
    }
}

fn build_offer(
    manifest: CanonicalActionResultManifest,
    manifest_tag: u8,
    evidence_tag: u8,
) -> Result<OfferPreparedActionResult, StoreError> {
    let manifest_id = object(manifest_tag);
    let evidence = AttemptEvidenceBundle {
        action_key: digest("rabs.action-key.sha256.v1", 7),
        canonical_result_manifest_id: manifest_id.clone(),
        execution_snapshot_root: object(60),
        observed_input_report: object(61),
        raw_process_and_event_evidence: object(62),
        provenance_receipt: object(63),
        incremental_snapshot: None,
    };
    OfferPreparedActionResult::build(
        attempt_authority(),
        manifest,
        manifest_id,
        evidence,
        object(evidence_tag),
        digest("rabs.observation-stream.sha256.v1", 9),
        &[(
            OutputRole::Materializable,
            RawBytes::new(b"out/lib.rlib".to_vec()),
        )],
        Vec::new(),
    )
    .map_err(|e| StoreError::Corruption(format!("offer construction failed: {e:?}")))
}

const WINNER_UPLOAD_TAGS: [u8; 8] = [40, 41, 50, 51, 60, 61, 62, 63];
const DIVERGENT_UPLOAD_TAGS: [u8; 3] = [42, 52, 55];

/// Recovery-aware setup: every step checks durable state first, so the
/// same function is both the first attempt and the coordinator's
/// restart path.
fn ensure_setup(store: &mut dyn RabsMetadataStore) -> Result<(), StoreError> {
    let auth = authority_digest(&coordinator());
    // Always RE-ACQUIRE (idempotent by digest): this is exactly what a
    // restarted coordinator does, and it re-interns the authority's
    // digest domain so the fail-closed R121 restore path accepts the
    // rows this lineage wrote before the crash.
    store.acquire_authority(&AuthorityRow {
        digest: auth.clone(),
        cluster_id: "crash-matrix".to_owned(),
        incarnation: 77,
        term: 3,
        acquired_seq: 1,
    })?;
    store.upsert_action_entry(&ActionEntryRow {
        action_key: digest("rabs.action-key.sha256.v1", 7),
        key_epoch: 1,
        projection_epoch: 1,
    })?;
    if store.generation_state(11)?.is_none() {
        store.create_generation(&auth, 11, &digest("rabs.action-key.sha256.v1", 7))?;
    }
    if !store.attempt_exists(20, 11)? {
        store.record_attempt(20, 11, "worker-a", 1)?;
    }
    if store.lease_state(30)?.is_none() {
        store.acquire_lease(30, 20, 1, 100)?;
    }
    Ok(())
}

/// Upload: record + locate each object (both calls idempotent).
fn upload(store: &mut dyn RabsMetadataStore, tags: &[u8]) -> Result<(), StoreError> {
    for &tag in tags {
        let id = object(tag);
        store.record_object(&id.0, 64)?;
        store.add_location(&id.0, &format!("/cas/{tag}"), Some(1), "raw", true)?;
    }
    Ok(())
}

/// Locate the offer's derived bundle root (H039: build() stamps the
/// F035 derivation, and the closure check requires it located like
/// any other object). Idempotent, recovery-aware like `upload`.
fn upload_bundle_root(
    store: &mut dyn RabsMetadataStore,
    offer: &OfferPreparedActionResult,
) -> Result<(), StoreError> {
    if let Some(root) = &offer.manifest.artifact_bundle_root {
        store.record_object(&root.0, 0)?;
        store.add_location(&root.0, "/cas/bundle-root", Some(1), "raw", true)?;
    }
    Ok(())
}

fn expected_descriptor() -> TypedDigest {
    digest("rabs.descriptor.sha256.v1", 8)
}

/// Map a refusal into the scenario's error space: only store errors are
/// legitimate here (the crash marker); any protocol refusal means the
/// scenario itself is broken.
fn refusal_to_error(refusal: OfferRefusal) -> StoreError {
    match refusal {
        OfferRefusal::Store(e) => e,
        other => StoreError::Corruption(format!("unexpected refusal in matrix: {other:?}")),
    }
}

/// Run one phase attempt. `attempt` distinguishes the initial (armed)
/// run from post-crash retries: retries allocate fresh pin ids and
/// sequences exactly as a restarted coordinator would.
fn run_phase(
    store: &mut dyn RabsMetadataStore,
    phase: MatrixPhase,
    attempt: u64,
) -> Result<PublicationOutcome, StoreError> {
    ensure_setup(store)?;
    match phase {
        MatrixPhase::Commit => {
            upload(store, &WINNER_UPLOAD_TAGS)?;
            let offer = build_offer(winner_manifest(), 50, 51)?;
            upload_bundle_root(store, &offer)?;
            process_offer(
                store,
                &offer,
                &expected_descriptor(),
                |_| None,
                900 + u128::from(attempt),
                1 + attempt,
                CommitDurabilityProfile::RequireDurableClosure,
            )
            .map_err(refusal_to_error)
        }
        MatrixPhase::Divergence => {
            upload(store, &DIVERGENT_UPLOAD_TAGS)?;
            let mut divergent = winner_manifest();
            divergent.logical_outputs[0].object = object(42);
            let offer = build_offer(divergent, 52, 55)?;
            upload_bundle_root(store, &offer)?;
            process_offer(
                store,
                &offer,
                &expected_descriptor(),
                |_| Some(winner_manifest_as_committed()),
                950 + u128::from(attempt),
                10 + attempt,
                CommitDurabilityProfile::RequireDurableClosure,
            )
            .map_err(refusal_to_error)
        }
    }
}

/// The committed winner manifest as the coordinator would reload it for
/// divergence classification (projection digests stamped).
fn winner_manifest_as_committed() -> CanonicalActionResultManifest {
    let mut m = winner_manifest();
    m.semantic_result_digest = crate::publication::semantic_result_digest_v1(&m);
    m.observable_result_digest = crate::publication::observable_result_digest_v1(
        &m,
        &digest("rabs.observation-stream.sha256.v1", 9),
    );
    m
}

fn is_injected(error: &StoreError) -> bool {
    matches!(error, StoreError::Backend(m) if m == CRASH_MARKER)
}

// ---------------------------------------------------------------------
// Recovery invariants.
// ---------------------------------------------------------------------

fn action_key_str() -> String {
    digest_key(&digest("rabs.action-key.sha256.v1", 7))
}

/// Check every reopen-time invariant; push violations with context.
fn check_recovery(
    store: &mut dyn RabsMetadataStore,
    phase: MatrixPhase,
    k: u64,
    snapshot: &[String],
    violations: &mut Vec<String>,
) -> Result<(), StoreError> {
    let ctx = |fact: &str| format!("{}[k={k}]: {fact}", phase.tag());

    // No double commit, ever — at most one publication row for the key.
    let publications = store.list_publications()?;
    if publications.len() > 1 {
        violations.push(ctx(&format!("{} publication rows", publications.len())));
    }

    // No partial result exposure / no lost pins: H013's reconciliation
    // is the oracle. Filesystem reality is exactly the claimed paths, so
    // any repair or refusal is a genuine metadata tear.
    let filesystem = SetFilesystem {
        paths: store
            .reconciliation_scan()?
            .into_iter()
            .map(|row| row.store_path)
            .collect(),
    };
    let report = reconcile_startup(store, &filesystem)?;
    if !report.repaired.is_empty() {
        violations.push(ctx(&format!(
            "reconciliation repaired {:?}",
            report.repaired
        )));
    }
    if report.serving != ServingDecision::Allowed {
        violations.push(ctx(&format!("serving refused: {:?}", report.serving)));
    }

    // A 'servable' disposition may exist only with the publication row
    // it was committed with (exposure check from the serving side).
    let disposition = store.serving_disposition_key(&action_key_str())?;
    if disposition.as_deref() == Some("servable") && publications.is_empty() {
        violations.push(ctx("servable disposition without a publication row"));
    }

    // H032: a committed pointer may NEVER name a non-durable object. At
    // every kill point, if the publication row survived the crash, its
    // full winner closure must have durable locations — a commit that
    // slipped past the durability gate would trip this at the boundary
    // where the volatile copy is gone.
    if !publications.is_empty() {
        for tag in WINNER_UPLOAD_TAGS {
            if !store.object_durably_located(&object(tag).0)? {
                violations.push(ctx(&format!(
                    "committed pointer to non-durable object /cas/{tag}"
                )));
            }
        }
    }

    if phase == MatrixPhase::Divergence {
        // H026 stricter-state-first monotone chain: each later artifact
        // implies every earlier one.
        let quarantine_row = snapshot
            .iter()
            .any(|l| l.starts_with("quarantines|action-entry|") && l.contains(&action_key_str()));
        let quarantined_disposition = disposition.as_deref() == Some("quarantined");
        let preservation_pin = snapshot
            .iter()
            .any(|l| l.starts_with("pins|") && l.contains("|divergence-evidence|"));
        let incident = snapshot
            .iter()
            .any(|l| l.starts_with("divergence_incidents|"));
        let receipt = snapshot
            .iter()
            .any(|l| l.starts_with("decision_receipts|divergence-escalation|"));
        let chain = [
            ("receipt", receipt, "incident", incident),
            ("incident", incident, "preservation pin", preservation_pin),
            (
                "preservation pin",
                preservation_pin,
                "quarantined disposition",
                quarantined_disposition,
            ),
            (
                "quarantined disposition",
                quarantined_disposition,
                "quarantine row",
                quarantine_row,
            ),
        ];
        for (later_name, later, earlier_name, earlier) in chain {
            if later && !earlier {
                violations.push(ctx(&format!(
                    "monotonicity broken: {later_name} present without {earlier_name}"
                )));
            }
        }
    }
    Ok(())
}

/// Check the invariants that must hold after the post-crash retry
/// completed: exactly one publication pointing at the original winner,
/// its pin unreleased, and (divergence phase) the full quarantine.
fn check_converged(
    store: &mut dyn RabsMetadataStore,
    phase: MatrixPhase,
    k: u64,
    outcome: &PublicationOutcome,
    violations: &mut Vec<String>,
) -> Result<(), StoreError> {
    let ctx = |fact: &str| format!("{}[k={k}] post-retry: {fact}", phase.tag());

    match store.published_manifest_key(&digest("rabs.action-key.sha256.v1", 7))? {
        Some(key) if key == digest_key(&object(50).0) => {}
        other => violations.push(ctx(&format!("winner manifest is {other:?}"))),
    }
    let publications = store.list_publications()?;
    if publications.len() != 1 {
        violations.push(ctx(&format!("{} publication rows", publications.len())));
    }
    for (_, pin_hex) in &publications {
        if store.pin_released_by_hex(pin_hex)? != Some(false) {
            violations.push(ctx("publication pin missing or released"));
        }
    }

    match phase {
        MatrixPhase::Commit => {
            if !matches!(
                outcome,
                PublicationOutcome::Committed(_) | PublicationOutcome::IdempotentEvidenceAppended
            ) {
                violations.push(ctx(&format!("unexpected outcome {outcome:?}")));
            }
        }
        MatrixPhase::Divergence => {
            match outcome {
                PublicationOutcome::Quarantined(q)
                    if q.class == DivergenceClass::SemanticDivergence => {}
                other => violations.push(ctx(&format!("unexpected outcome {other:?}"))),
            }
            if store.serving_disposition_key(&action_key_str())?.as_deref() != Some("quarantined") {
                violations.push(ctx("disposition not quarantined"));
            }
            if store
                .list_divergence_incidents(&action_key_str())?
                .is_empty()
            {
                violations.push(ctx("no divergence incident recorded"));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------
// The matrix driver.
// ---------------------------------------------------------------------

/// Runaway guard far above any real scenario length.
const KILL_POINT_CAP: u64 = 4096;

/// Run the full crash matrix for one engine family. `open` opens (or
/// reopens) the engine at a path; each kill point gets its own database
/// file under `root`.
///
/// # Errors
/// Infrastructure failures only (open/migration errors, scenario
/// construction). Invariant breaches are DATA — collected in
/// [`CrashMatrixReport::violations`] — so a broken engine cannot mask
/// itself behind an early error.
pub fn run_crash_matrix<E: SqlEngine>(
    root: &Path,
    open: &dyn Fn(&Path) -> Result<E, StoreError>,
) -> Result<CrashMatrixReport, StoreError> {
    let mut report = CrashMatrixReport {
        commit_boundaries: 0,
        divergence_boundaries: 0,
        violations: Vec::new(),
        snapshots: Vec::new(),
    };

    for phase in [MatrixPhase::Commit, MatrixPhase::Divergence] {
        for k in 0..KILL_POINT_CAP {
            let path: PathBuf = root.join(format!("{}-{k}.db", phase.tag()));

            // Fresh store; baseline (divergence phase) runs unarmed.
            let mut store = SqlMetadataStore::open(FaultEngine::unarmed(open(&path)?))?;
            if phase == MatrixPhase::Divergence {
                run_phase(&mut store, MatrixPhase::Commit, 0)?;
                store.record_served_consumer(&action_key_str(), "consumer-a")?;
            }

            // Arm and run the scenario until it crashes (or completes).
            store.engine_mut().arm(k);
            let armed = run_phase(&mut store, phase, 0);
            drop(store);
            let crashed = match &armed {
                Ok(_) => false,
                Err(e) if is_injected(e) => true,
                Err(e) => {
                    report
                        .violations
                        .push(format!("{}[k={k}]: non-crash error {e:?}", phase.tag()));
                    true // still recover + retry below
                }
            };

            // Reopen cold; recovery invariants; snapshot for the
            // cross-engine differential.
            let mut store = SqlMetadataStore::open(FaultEngine::unarmed(open(&path)?))?;
            let snapshot = store.differential_snapshot()?;
            check_recovery(&mut store, phase, k, &snapshot, &mut report.violations)?;
            report
                .snapshots
                .push((format!("{}-{k}", phase.tag()), snapshot));

            // Restarted-coordinator retry must converge.
            match run_phase(&mut store, phase, 1) {
                Ok(outcome) => {
                    check_converged(&mut store, phase, k, &outcome, &mut report.violations)?;
                }
                Err(e) => report
                    .violations
                    .push(format!("{}[k={k}]: retry failed {e:?}", phase.tag())),
            }

            if !crashed {
                match phase {
                    MatrixPhase::Commit => report.commit_boundaries = k,
                    MatrixPhase::Divergence => report.divergence_boundaries = k,
                }
                break;
            }
            if k + 1 == KILL_POINT_CAP {
                report.violations.push(format!(
                    "{}: scenario never completed within {KILL_POINT_CAP} kill points",
                    phase.tag()
                ));
            }
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata_store::{FsqliteEngine, RusqliteEngine};
    use std::sync::atomic::{AtomicU64, Ordering};

    static DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn fresh_root(tag: &str) -> PathBuf {
        let n = DIR_COUNTER.fetch_add(1, Ordering::SeqCst);
        let root = std::env::temp_dir().join(format!("rabs-h015-{}-{tag}-{n}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn h015_reference_matrix_passes_every_boundary() {
        let report = run_crash_matrix(&fresh_root("ref"), &|path: &Path| {
            RusqliteEngine::open(path)
        })
        .unwrap();
        assert!(
            report.violations.is_empty(),
            "violations: {:#?}",
            report.violations
        );
        // The matrix genuinely exercised both protocols: the clean run
        // sits past dozens of mutation boundaries in each phase.
        assert!(
            report.commit_boundaries > 20,
            "commit phase only reached {} boundaries",
            report.commit_boundaries
        );
        assert!(
            report.divergence_boundaries > 20,
            "divergence phase only reached {} boundaries",
            report.divergence_boundaries
        );
    }

    #[test]
    fn h015_frankensqlite_matrix_matches_reference_at_every_kill_point() {
        let reference = run_crash_matrix(&fresh_root("d-ref"), &|path: &Path| {
            RusqliteEngine::open(path)
        })
        .unwrap();
        let candidate = run_crash_matrix(&fresh_root("d-fsq"), &|path: &Path| {
            FsqliteEngine::open(path)
        })
        .unwrap();
        assert!(
            candidate.violations.is_empty(),
            "candidate violations: {:#?}",
            candidate.violations
        );
        assert_eq!(reference.commit_boundaries, candidate.commit_boundaries);
        assert_eq!(
            reference.divergence_boundaries,
            candidate.divergence_boundaries
        );
        // Byte-identical crash states at EVERY kill point.
        assert_eq!(reference.snapshots.len(), candidate.snapshots.len());
        for (r, c) in reference.snapshots.iter().zip(&candidate.snapshots) {
            assert_eq!(r, c, "snapshot divergence at {}", r.0);
        }
    }

    #[test]
    fn h015_fault_engine_kills_exactly_at_budget() {
        let inner = RusqliteEngine::open_in_memory().unwrap();
        let mut engine = FaultEngine::unarmed(inner);
        engine
            .execute("CREATE TABLE t (x INTEGER)", &[])
            .expect("unarmed passes");
        engine.arm(1);
        engine
            .execute("INSERT INTO t (x) VALUES (1)", &[])
            .expect("within budget");
        let dead = engine.execute("INSERT INTO t (x) VALUES (2)", &[]);
        assert!(matches!(&dead, Err(e) if is_injected(e)));
        // Once dead, reads are dead too.
        assert!(matches!(&engine.query("SELECT * FROM t", &[]), Err(e) if is_injected(e)));
    }
}
