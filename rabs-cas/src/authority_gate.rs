//! FrankenSQLite authority gate (bead H024; risk R59).
//!
//! FrankenSQLite becomes the AUTHORITATIVE metadata engine only after
//! matching the reference SQLite backend under the gate's executed
//! lanes; until then it is dogfood/differential only. The gate is a
//! runtime chokepoint, not a report: [`open_authoritative_store`] is
//! the way to obtain an authoritative store, and it opens FrankenSQLite
//! only when every lane passed in THIS process against THIS build.
//! A verdict is never persisted or trusted across restarts — a
//! regression in the candidate demotes it at the next startup.
//!
//! Lanes (all executed for real, per evaluation):
//!
//! - **Differential**: one deterministic operation script — success
//!   paths AND typed-refusal probes across the full store surface —
//!   runs on both engines; per-step outcome transcripts and the full
//!   table snapshots must match. The first divergent line is named in
//!   the refusal.
//! - **Migration**: fresh open applies the full migration chain;
//!   reopen must be idempotent; schema version, epoch rows, and the
//!   `sqlite_master` table list must match the reference.
//! - **Crash (connection-drop)**: committed work must survive a
//!   dropped connection; an open transaction dropped without COMMIT
//!   must leave no trace. HONEST SCOPE: this exercises rollback and
//!   reopen recovery at the connection level; it is NOT a power-loss /
//!   torn-page injection harness (that torture belongs to the engine's
//!   own suite).
//! - **Concurrency**: a second connection to the same database while a
//!   write transaction is open must behave like the reference (refuse
//!   or serialize — and identically), and the final state must match.
//!
//! Outcome normalization: engine-level error TEXT is presentation, not
//! semantics, so `StoreError::Backend(_)` compares by class, never by
//! message. Every TYPED refusal compares exactly. The residual risk —
//! two engines failing the same step with different backend-class
//! causes — is accepted here because the state snapshots that follow
//! must still match; consequential divergence cannot hide.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use rabs_protocol::result_identity::{DigestAlgorithm, TypedDigest};

use crate::metadata_store::{
    ActionEntryRow, AuthorityRow, FsqliteEngine, GcReceiptRow, PublicationRow, RabsMetadataStore,
    ResultKindTag, RusqliteEngine, SCHEMA_VERSION, SqlEngine, SqlMetadataStore, SqlValue,
    StoreError, TrustEvaluationRow,
};

impl SqlEngine for Box<dyn SqlEngine> {
    fn execute(&mut self, sql: &str, params: &[SqlValue]) -> Result<usize, StoreError> {
        self.as_mut().execute(sql, params)
    }

    fn query(&mut self, sql: &str, params: &[SqlValue]) -> Result<Vec<Vec<SqlValue>>, StoreError> {
        self.as_mut().query(sql, params)
    }
}

/// Opens one engine over a database path. The gate reopens databases
/// several times per lane, so it needs a factory, not a connection.
pub type EngineOpener<'a> = dyn Fn(&Path) -> Result<Box<dyn SqlEngine>, StoreError> + 'a;

/// The gate lanes, in evaluation order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateLane {
    /// Operation-script transcript + snapshot differential.
    Differential,
    /// Migration chain application + reopen idempotence.
    Migration,
    /// Connection-drop atomicity and committed durability.
    Crash,
    /// Second-connection behavior under an open write transaction.
    Concurrency,
}

impl GateLane {
    const fn name(self) -> &'static str {
        match self {
            Self::Differential => "differential",
            Self::Migration => "migration",
            Self::Crash => "crash",
            Self::Concurrency => "concurrency",
        }
    }
}

/// One lane's executed result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaneReport {
    /// Which lane ran.
    pub lane: GateLane,
    /// Whether the candidate matched the reference.
    pub passed: bool,
    /// On failure: the first divergence or error, named. On success: a
    /// short statement of what was compared.
    pub detail: String,
}

/// The full gate verdict: promotion requires EVERY lane to pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateVerdict {
    /// All lane reports, in evaluation order.
    pub lanes: Vec<LaneReport>,
}

impl GateVerdict {
    /// Whether the candidate may serve authoritatively.
    #[must_use]
    pub fn promoted(&self) -> bool {
        !self.lanes.is_empty() && self.lanes.iter().all(|lane| lane.passed)
    }

    /// The failed lanes, for refusal reporting.
    #[must_use]
    pub fn failures(&self) -> Vec<&LaneReport> {
        self.lanes.iter().filter(|lane| !lane.passed).collect()
    }
}

/// Which engine the gate selected as authoritative.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectedAuthority {
    /// The reference C-SQLite engine (always eligible).
    Reference,
    /// FrankenSQLite, promoted by a fully passed gate in this process.
    FrankenSqlite,
}

/// The gate's runtime decision: which engine is authoritative, plus
/// the verdict that justified it.
#[derive(Debug)]
pub struct AuthoritativeSelection {
    /// The selected engine.
    pub authority: SelectedAuthority,
    /// The verdict the selection branched on.
    pub verdict: GateVerdict,
}

fn digest(domain: &'static str, tag: u8) -> TypedDigest {
    TypedDigest {
        algorithm: DigestAlgorithm::Sha256V1,
        domain,
        bytes: [tag; 32],
    }
}

fn authority(tag: u8) -> AuthorityRow {
    AuthorityRow {
        digest: digest("rabs.authority.sha256.v1", tag),
        cluster_id: "gate-cluster".to_owned(),
        incarnation: u128::from(tag),
        term: u64::from(tag),
        acquired_seq: 1,
    }
}

fn publication(action_tag: u8, descriptor_tag: u8, pin: u128) -> PublicationRow {
    PublicationRow {
        action_key: digest("rabs.action-key.sha256.v1", action_tag),
        descriptor_digest: digest("rabs.descriptor.sha256.v1", descriptor_tag),
        manifest_digest: digest("rabs.result-manifest.sha256.v1", descriptor_tag),
        evidence_digest: digest("rabs.evidence-bundle.sha256.v1", descriptor_tag),
        winner_generation: 11,
        winner_attempt: 20,
        result_kind: ResultKindTag::Success,
        pin_id: pin,
        pin_owner: "coordinator".to_owned(),
    }
}

/// Normalize one step outcome for cross-engine comparison: typed
/// errors compare exactly; backend error TEXT is engine presentation
/// and compares by class only.
fn outcome<T: std::fmt::Debug>(
    transcript: &mut Vec<String>,
    step: &str,
    result: &Result<T, StoreError>,
) {
    let rendered = match result {
        Ok(value) => format!("{step}: Ok({value:?})"),
        Err(StoreError::Backend(_)) => format!("{step}: Err(Backend)"),
        Err(error) => format!("{step}: Err({error:?})"),
    };
    transcript.push(rendered);
}

/// The deterministic gate operation script: success paths and typed
/// refusal probes over the WHOLE store surface, recorded step by step.
/// Returns the transcript and the final differential snapshot.
#[allow(clippy::too_many_lines)]
fn operation_script(
    store: &mut dyn RabsMetadataStore,
) -> (Vec<String>, Result<Vec<String>, StoreError>) {
    let mut t = Vec::new();
    let active = digest("rabs.authority.sha256.v1", 1);
    let wrong = digest("rabs.authority.sha256.v1", 2);
    let action = ActionEntryRow {
        action_key: digest("rabs.action-key.sha256.v1", 7),
        key_epoch: 3,
        projection_epoch: 4,
    };

    outcome(&mut t, "schema_version", &store.schema_version());
    outcome(&mut t, "acquire", &store.acquire_authority(&authority(1)));
    outcome(&mut t, "reacquire", &store.acquire_authority(&authority(1)));
    outcome(
        &mut t,
        "acquire-held",
        &store.acquire_authority(&authority(2)),
    );
    outcome(&mut t, "upsert-action", &store.upsert_action_entry(&action));
    outcome(
        &mut t,
        "lookup-hit",
        &store.lookup_action(&action.action_key),
    );
    outcome(
        &mut t,
        "lookup-miss",
        &store.lookup_action(&digest("rabs.action-key.sha256.v1", 99)),
    );
    outcome(
        &mut t,
        "gen-wrong-authority",
        &store.create_generation(&wrong, 10, &action.action_key),
    );
    outcome(
        &mut t,
        "gen-create",
        &store.create_generation(&active, 10, &action.action_key),
    );
    outcome(&mut t, "gen-tombstone", &store.tombstone_generation(10));
    outcome(
        &mut t,
        "gen-reuse",
        &store.create_generation(&active, 10, &action.action_key),
    );
    outcome(
        &mut t,
        "gen-create-2",
        &store.create_generation(&active, 11, &action.action_key),
    );
    outcome(
        &mut t,
        "attempt",
        &store.record_attempt(20, 11, "worker-a", 5),
    );
    outcome(
        &mut t,
        "attempt-dup",
        &store.record_attempt(20, 11, "worker-a", 6),
    );
    outcome(
        &mut t,
        "attempt-unknown-gen",
        &store.record_attempt(21, 999, "worker-a", 6),
    );
    outcome(&mut t, "lease", &store.acquire_lease(30, 20, 1, 100));
    outcome(&mut t, "lease-renew", &store.renew_lease(30, 2, 200));
    outcome(&mut t, "lease-stale", &store.renew_lease(30, 2, 300));
    outcome(&mut t, "lease-release", &store.release_lease(30));
    outcome(
        &mut t,
        "lease-renew-released",
        &store.renew_lease(30, 3, 300),
    );
    let publication_row = publication(7, 1, 40);
    outcome(
        &mut t,
        "publish-wrong-authority",
        &store.commit_publication(&wrong, &publication_row),
    );
    outcome(
        &mut t,
        "publish",
        &store.commit_publication(&active, &publication_row),
    );
    outcome(
        &mut t,
        "publish-idempotent",
        &store.commit_publication(&active, &publication_row),
    );
    outcome(
        &mut t,
        "publish-conflict",
        &store.commit_publication(&active, &publication(7, 2, 41)),
    );
    let mut failure_row = publication(8, 3, 42);
    failure_row.result_kind = ResultKindTag::DeterministicFailure;
    outcome(
        &mut t,
        "publish-det-failure",
        &store.commit_publication(&active, &failure_row),
    );
    let extra_evidence = digest("rabs.evidence-bundle.sha256.v1", 90);
    outcome(
        &mut t,
        "evidence",
        &store.append_evidence(&publication_row.action_key, &extra_evidence, 11, 20),
    );
    outcome(
        &mut t,
        "evidence-idempotent",
        &store.append_evidence(&publication_row.action_key, &extra_evidence, 11, 20),
    );

    let object = digest("rabs.object.sha256.v1", 50);
    let child = digest("rabs.object.sha256.v1", 51);
    outcome(&mut t, "object", &store.record_object(&object, 4096));
    outcome(&mut t, "object-child", &store.record_object(&child, 16));
    outcome(
        &mut t,
        "location",
        &store.add_location(&object, "/cas/aa/bb", Some(7), "raw"),
    );
    outcome(
        &mut t,
        "edge",
        &store.add_object_edge(&object, &child, "manifest-entry"),
    );
    outcome(
        &mut t,
        "pin",
        &store.create_pin(
            60,
            &object,
            "operator",
            "administrative",
            Some(500),
            Some("gate"),
            false,
            "gate script",
        ),
    );
    outcome(
        &mut t,
        "pin-release-wrong-owner",
        &store.release_pin(60, "someone-else"),
    );
    outcome(&mut t, "pin-renew", &store.renew_pin(60, 2));
    outcome(&mut t, "pin-renew-stale", &store.renew_pin(60, 2));
    outcome(
        &mut t,
        "quarantine-location",
        &store.set_location_quarantined(&object, "/cas/aa/bb", true),
    );
    outcome(
        &mut t,
        "located-after-quarantine",
        &store.object_located(&object),
    );
    outcome(
        &mut t,
        "unquarantine-location",
        &store.set_location_quarantined(&object, "/cas/aa/bb", false),
    );
    outcome(
        &mut t,
        "recipe",
        &store.put_recipe(&action.action_key, &digest("rabs.recipe.sha256.v1", 70)),
    );
    outcome(
        &mut t,
        "breakdown",
        &store.put_key_breakdown(
            &action.action_key,
            "toolchain",
            &digest("rabs.component.sha256.v1", 71),
        ),
    );
    outcome(
        &mut t,
        "trust",
        &store.set_trust(&action.action_key, "trusted", "gate"),
    );
    outcome(
        &mut t,
        "verification-sample",
        &store.record_verification_sample(&action.action_key, 20, true, 8),
    );
    outcome(&mut t, "gc-snapshot", &store.gc_snapshot(9));
    outcome(&mut t, "reconciliation", &store.reconciliation_scan());
    outcome(
        &mut t,
        "gc-tombstone",
        &store.add_gc_tombstone("obj-x", "/cas/xx", 10, 20),
    );
    outcome(&mut t, "gc-due", &store.due_gc_tombstones(25));
    outcome(
        &mut t,
        "gc-receipt",
        &store.record_gc_receipt(&GcReceiptRow {
            seq: 26,
            mode: "normal".to_owned(),
            planned: 1,
            reclaimed: 1,
            skipped: 0,
            truncated: false,
        }),
    );
    outcome(
        &mut t,
        "eviction-tombstone",
        &store.record_eviction_tombstone(
            &action.action_key,
            &digest("rabs.semantic.sha256.v1", 60),
            &digest("rabs.observable.sha256.v1", 61),
            30,
        ),
    );
    outcome(
        &mut t,
        "eviction-read",
        &store.eviction_tombstone(&action.action_key),
    );
    outcome(
        &mut t,
        "operator-reset",
        &store.record_operator_reset(1, 31),
    );
    outcome(
        &mut t,
        "operator-reset-stale",
        &store.record_operator_reset(1, 32),
    );

    // H038 surface: fences, high-waters, handoffs, ledgers.
    outcome(
        &mut t,
        "peer-high-water",
        &store.record_peer_authority_high_water(&active, "peer-1", 5, 100),
    );
    outcome(
        &mut t,
        "peer-high-water-stale",
        &store.record_peer_authority_high_water(&active, "peer-1", 4, 101),
    );
    outcome(
        &mut t,
        "worker-fence",
        &store.advance_worker_fence(&active, "worker-a", 3),
    );
    outcome(
        &mut t,
        "worker-fence-stale",
        &store.advance_worker_fence(&active, "worker-a", 2),
    );
    outcome(
        &mut t,
        "edge-fence",
        &store.advance_edge_fence(&active, "edge-1", 10),
    );
    outcome(
        &mut t,
        "handoff-bad-predecessor",
        &store.begin_edge_handoff(&active, "edge-1", 11, 9, 200),
    );
    outcome(
        &mut t,
        "handoff",
        &store.begin_edge_handoff(&active, "edge-1", 11, 10, 200),
    );
    outcome(
        &mut t,
        "handoff-second-active",
        &store.begin_edge_handoff(&active, "edge-1", 12, 10, 201),
    );
    outcome(
        &mut t,
        "handoff-resolve",
        &store.resolve_edge_handoff(&active, "edge-1", 11),
    );
    outcome(
        &mut t,
        "edge-fence-after-resolve",
        &store.edge_fence("edge-1"),
    );
    outcome(
        &mut t,
        "trust-evaluation",
        &store.append_trust_evaluation(
            &active,
            &action.action_key,
            &TrustEvaluationRow {
                version: 1,
                state: "trusted".to_owned(),
                reason: "gate".to_owned(),
                evaluated_seq: 300,
            },
        ),
    );
    outcome(
        &mut t,
        "trust-evaluation-stale",
        &store.append_trust_evaluation(
            &active,
            &action.action_key,
            &TrustEvaluationRow {
                version: 1,
                state: "trusted".to_owned(),
                reason: "gate".to_owned(),
                evaluated_seq: 301,
            },
        ),
    );
    outcome(
        &mut t,
        "operation",
        &store.create_operation(&active, 400, "transfer", "running", 310),
    );
    outcome(
        &mut t,
        "operation-dup",
        &store.create_operation(&active, 400, "transfer", "running", 311),
    );
    outcome(
        &mut t,
        "operation-update",
        &store.update_operation_state(400, "done", 312),
    );
    outcome(
        &mut t,
        "subscriber",
        &store.register_edge_subscriber("edge-1", "sub-a", 320),
    );
    outcome(
        &mut t,
        "manifest",
        &store.record_manifest(&digest("rabs.result-manifest.sha256.v1", 80), "tree", 12),
    );
    outcome(
        &mut t,
        "manifest-divergence",
        &store.record_manifest(&digest("rabs.result-manifest.sha256.v1", 80), "tree", 13),
    );
    outcome(
        &mut t,
        "worker-session",
        &store.record_worker_session("worker-a", 3, 330),
    );
    outcome(
        &mut t,
        "worker-session-conflict",
        &store.record_worker_session("worker-a", 4, 330),
    );
    outcome(
        &mut t,
        "worker-capability",
        &store.record_worker_capability("worker-a", "cargo"),
    );
    outcome(
        &mut t,
        "health-sample",
        &store.record_worker_health_sample("worker-a", 350, true, "ok"),
    );
    outcome(
        &mut t,
        "decision-receipt",
        &store.record_decision_receipt("gc", "run-1", 360, "reclaim", "pressure"),
    );
    outcome(
        &mut t,
        "provenance",
        &store.add_provenance_edge(&object, &child, "derived-from"),
    );
    outcome(
        &mut t,
        "determinism-audit",
        &store.record_determinism_audit(&action.action_key, 20, 370, "deterministic"),
    );
    outcome(
        &mut t,
        "materialization",
        &store.create_materialization(500, &object, "/work/out", "staging", 380),
    );
    outcome(
        &mut t,
        "materialization-update",
        &store.update_materialization_state(500, "complete", 382),
    );
    outcome(&mut t, "release", &store.release_authority(&active));
    outcome(&mut t, "handover", &store.acquire_authority(&authority(2)));

    let snapshot = store.differential_snapshot();
    (t, snapshot)
}

fn open_store(
    opener: &EngineOpener<'_>,
    path: &Path,
) -> Result<SqlMetadataStore<Box<dyn SqlEngine>>, StoreError> {
    SqlMetadataStore::open(opener(path)?)
}

fn first_divergence(reference: &[String], candidate: &[String]) -> Option<String> {
    let max = reference.len().max(candidate.len());
    for i in 0..max {
        let r = reference.get(i);
        let c = candidate.get(i);
        if r != c {
            return Some(format!(
                "line {}: reference={:?} candidate={:?}",
                i,
                r.map_or("<missing>", String::as_str),
                c.map_or("<missing>", String::as_str),
            ));
        }
    }
    None
}

fn differential_lane(
    root: &Path,
    reference: &EngineOpener<'_>,
    candidate: &EngineOpener<'_>,
) -> LaneReport {
    let run = |opener: &EngineOpener<'_>, path: PathBuf| -> Result<Vec<String>, StoreError> {
        let mut store = open_store(opener, &path)?;
        let (mut transcript, snapshot) = operation_script(&mut store);
        match snapshot {
            Ok(mut lines) => transcript.append(&mut lines),
            Err(error) => transcript.push(format!("snapshot: Err({error:?})")),
        }
        Ok(transcript)
    };
    let reference_out = run(reference, root.join("differential-ref.db"));
    let candidate_out = run(candidate, root.join("differential-cand.db"));
    match (reference_out, candidate_out) {
        (Ok(reference_lines), Ok(candidate_lines)) => {
            first_divergence(&reference_lines, &candidate_lines).map_or_else(
                || LaneReport {
                    lane: GateLane::Differential,
                    passed: true,
                    detail: format!(
                        "{} transcript+snapshot lines identical",
                        reference_lines.len()
                    ),
                },
                |divergence| LaneReport {
                    lane: GateLane::Differential,
                    passed: false,
                    detail: divergence,
                },
            )
        }
        (Err(error), _) => LaneReport {
            lane: GateLane::Differential,
            passed: false,
            detail: format!("reference engine failed to run: {error:?}"),
        },
        (_, Err(error)) => LaneReport {
            lane: GateLane::Differential,
            passed: false,
            detail: format!("candidate engine failed to run: {error:?}"),
        },
    }
}

fn migration_lane(
    root: &Path,
    reference: &EngineOpener<'_>,
    candidate: &EngineOpener<'_>,
) -> LaneReport {
    let run = |opener: &EngineOpener<'_>, path: PathBuf| -> Result<Vec<String>, StoreError> {
        let mut lines = Vec::new();
        {
            let mut store = open_store(opener, &path)?;
            lines.push(format!("fresh-version: {:?}", store.schema_version()?));
        }
        // Reopen: migrations must be idempotent, version stable.
        let mut store = open_store(opener, &path)?;
        lines.push(format!("reopen-version: {:?}", store.schema_version()?));
        let mut engine = opener(&path)?;
        for row in engine.query("SELECT version FROM schema_epochs ORDER BY version", &[])? {
            lines.push(format!("epoch: {row:?}"));
        }
        for row in engine.query(
            "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name",
            &[],
        )? {
            lines.push(format!("table: {row:?}"));
        }
        Ok(lines)
    };
    let reference_out = run(reference, root.join("migration-ref.db"));
    let candidate_out = run(candidate, root.join("migration-cand.db"));
    match (reference_out, candidate_out) {
        (Ok(reference_lines), Ok(candidate_lines)) => {
            if let Some(divergence) = first_divergence(&reference_lines, &candidate_lines) {
                return LaneReport {
                    lane: GateLane::Migration,
                    passed: false,
                    detail: divergence,
                };
            }
            let expected = format!("fresh-version: {SCHEMA_VERSION}");
            if reference_lines.first() != Some(&expected) {
                return LaneReport {
                    lane: GateLane::Migration,
                    passed: false,
                    detail: format!(
                        "migration chain did not reach v{SCHEMA_VERSION}: {:?}",
                        reference_lines.first()
                    ),
                };
            }
            LaneReport {
                lane: GateLane::Migration,
                passed: true,
                detail: format!(
                    "v{SCHEMA_VERSION} reached, reopen idempotent, epochs+tables identical"
                ),
            }
        }
        (Err(error), _) => LaneReport {
            lane: GateLane::Migration,
            passed: false,
            detail: format!("reference engine failed to run: {error:?}"),
        },
        (_, Err(error)) => LaneReport {
            lane: GateLane::Migration,
            passed: false,
            detail: format!("candidate engine failed to run: {error:?}"),
        },
    }
}

fn crash_lane(
    root: &Path,
    reference: &EngineOpener<'_>,
    candidate: &EngineOpener<'_>,
) -> LaneReport {
    let run = |opener: &EngineOpener<'_>, path: PathBuf| -> Result<Vec<String>, StoreError> {
        let mut lines = Vec::new();
        {
            // Committed work, then an open transaction dropped without
            // COMMIT: the drop is the simulated crash.
            let mut store = open_store(opener, &path)?;
            store.acquire_authority(&authority(1))?;
            let active = digest("rabs.authority.sha256.v1", 1);
            let action = ActionEntryRow {
                action_key: digest("rabs.action-key.sha256.v1", 7),
                key_epoch: 0,
                projection_epoch: 0,
            };
            store.upsert_action_entry(&action)?;
            store.create_generation(&active, 10, &action.action_key)?;
            let engine = store.engine_mut();
            engine.execute("BEGIN", &[])?;
            engine.execute(
                "INSERT INTO objects (key, algo, domain, bytes, logical_size) \
                 VALUES ('torn:aa', 'sha256-v1', 'torn', x'00', 1)",
                &[],
            )?;
            // No COMMIT: the store (and its connection) drops here.
        }
        let mut engine = opener(&path)?;
        let objects = engine.query("SELECT COUNT(*) FROM objects", &[])?;
        lines.push(format!("uncommitted-objects: {objects:?}"));
        let generations = engine.query("SELECT COUNT(*) FROM action_generations", &[])?;
        lines.push(format!("committed-generations: {generations:?}"));
        drop(engine);
        let mut store = open_store(opener, &path)?;
        let mut snapshot = store.differential_snapshot()?;
        lines.append(&mut snapshot);
        Ok(lines)
    };
    let reference_out = run(reference, root.join("crash-ref.db"));
    let candidate_out = run(candidate, root.join("crash-cand.db"));
    match (reference_out, candidate_out) {
        (Ok(reference_lines), Ok(candidate_lines)) => {
            if let Some(divergence) = first_divergence(&reference_lines, &candidate_lines) {
                return LaneReport {
                    lane: GateLane::Crash,
                    passed: false,
                    detail: divergence,
                };
            }
            let atomicity = "uncommitted-objects: [[Int(0)]]".to_owned();
            let durability = "committed-generations: [[Int(1)]]".to_owned();
            if reference_lines.first() != Some(&atomicity) {
                return LaneReport {
                    lane: GateLane::Crash,
                    passed: false,
                    detail: format!(
                        "uncommitted transaction survived the drop: {:?}",
                        reference_lines.first()
                    ),
                };
            }
            if reference_lines.get(1) != Some(&durability) {
                return LaneReport {
                    lane: GateLane::Crash,
                    passed: false,
                    detail: format!(
                        "committed work lost across the drop: {:?}",
                        reference_lines.get(1)
                    ),
                };
            }
            LaneReport {
                lane: GateLane::Crash,
                passed: true,
                detail: "uncommitted work discarded, committed work durable, states identical"
                    .to_owned(),
            }
        }
        (Err(error), _) => LaneReport {
            lane: GateLane::Crash,
            passed: false,
            detail: format!("reference engine failed to run: {error:?}"),
        },
        (_, Err(error)) => LaneReport {
            lane: GateLane::Crash,
            passed: false,
            detail: format!("candidate engine failed to run: {error:?}"),
        },
    }
}

fn concurrency_lane(
    root: &Path,
    reference: &EngineOpener<'_>,
    candidate: &EngineOpener<'_>,
) -> LaneReport {
    let run = |opener: &EngineOpener<'_>, path: PathBuf| -> Result<Vec<String>, StoreError> {
        let mut lines = Vec::new();
        // Migrate first, on a single connection.
        drop(open_store(opener, &path)?);
        let mut writer = opener(&path)?;
        writer.execute("BEGIN", &[])?;
        writer.execute(
            "INSERT INTO objects (key, algo, domain, bytes, logical_size) \
             VALUES ('conc:aa', 'sha256-v1', 'conc', x'00', 1)",
            &[],
        )?;
        // A second connection while the write transaction is open.
        match opener(&path) {
            Ok(mut second) => {
                let contended = second.execute(
                    "INSERT INTO objects (key, algo, domain, bytes, logical_size) \
                     VALUES ('conc:bb', 'sha256-v1', 'conc', x'01', 1)",
                    &[],
                );
                lines.push(match &contended {
                    Ok(n) => format!("contended-write: Ok({n})"),
                    Err(StoreError::Backend(_)) => "contended-write: Err(Backend)".to_owned(),
                    Err(error) => format!("contended-write: Err({error:?})"),
                });
                writer.execute("COMMIT", &[])?;
                let after = second.execute(
                    "INSERT INTO objects (key, algo, domain, bytes, logical_size) \
                     VALUES ('conc:cc', 'sha256-v1', 'conc', x'02', 1)",
                    &[],
                );
                lines.push(match &after {
                    Ok(n) => format!("post-commit-write: Ok({n})"),
                    Err(StoreError::Backend(_)) => "post-commit-write: Err(Backend)".to_owned(),
                    Err(error) => format!("post-commit-write: Err({error:?})"),
                });
            }
            Err(StoreError::Backend(_)) => {
                lines.push("second-connection: Err(Backend)".to_owned());
                writer.execute("COMMIT", &[])?;
            }
            Err(error) => {
                lines.push(format!("second-connection: Err({error:?})"));
                writer.execute("COMMIT", &[])?;
            }
        }
        drop(writer);
        let mut check = opener(&path)?;
        let keys = check.query("SELECT key FROM objects ORDER BY key", &[])?;
        lines.push(format!("final-objects: {keys:?}"));
        Ok(lines)
    };
    let reference_out = run(reference, root.join("concurrency-ref.db"));
    let candidate_out = run(candidate, root.join("concurrency-cand.db"));
    match (reference_out, candidate_out) {
        (Ok(reference_lines), Ok(candidate_lines)) => {
            first_divergence(&reference_lines, &candidate_lines).map_or_else(
                || LaneReport {
                    lane: GateLane::Concurrency,
                    passed: true,
                    detail: format!(
                        "second-connection behavior and final state identical: {}",
                        reference_lines.join("; ")
                    ),
                },
                |divergence| LaneReport {
                    lane: GateLane::Concurrency,
                    passed: false,
                    detail: divergence,
                },
            )
        }
        (Err(error), _) => LaneReport {
            lane: GateLane::Concurrency,
            passed: false,
            detail: format!("reference engine failed to run: {error:?}"),
        },
        (_, Err(error)) => LaneReport {
            lane: GateLane::Concurrency,
            passed: false,
            detail: format!("candidate engine failed to run: {error:?}"),
        },
    }
}

/// Run every gate lane for a candidate engine against a reference
/// engine. `root` must be a writable directory; each lane creates its
/// own database files under it (nothing is deleted).
pub fn evaluate_gate(
    root: &Path,
    reference: &EngineOpener<'_>,
    candidate: &EngineOpener<'_>,
) -> GateVerdict {
    GateVerdict {
        lanes: vec![
            differential_lane(root, reference, candidate),
            migration_lane(root, reference, candidate),
            crash_lane(root, reference, candidate),
            concurrency_lane(root, reference, candidate),
        ],
    }
}

fn reference_opener() -> impl Fn(&Path) -> Result<Box<dyn SqlEngine>, StoreError> {
    |path: &Path| RusqliteEngine::open(path).map(|engine| Box::new(engine) as Box<dyn SqlEngine>)
}

fn frankensqlite_opener() -> impl Fn(&Path) -> Result<Box<dyn SqlEngine>, StoreError> {
    |path: &Path| FsqliteEngine::open(path).map(|engine| Box::new(engine) as Box<dyn SqlEngine>)
}

/// Run the gate for the real FrankenSQLite engine against the real
/// reference engine.
pub fn frankensqlite_gate(root: &Path) -> GateVerdict {
    evaluate_gate(root, &reference_opener(), &frankensqlite_opener())
}

/// THE runtime chokepoint (R59): open the authoritative metadata store
/// at `db_path`, selecting FrankenSQLite only if it passes every gate
/// lane executed under `gate_root` in this process. Any lane failure —
/// including any differential mismatch — keeps the reference engine
/// authoritative; the refusal is carried in the returned selection.
pub fn open_authoritative_store(
    gate_root: &Path,
    db_path: &Path,
) -> Result<(AuthoritativeSelection, SqlMetadataStore<Box<dyn SqlEngine>>), StoreError> {
    let verdict = frankensqlite_gate(gate_root);
    if verdict.promoted() {
        let store = SqlMetadataStore::open(frankensqlite_opener()(db_path)?)?;
        Ok((
            AuthoritativeSelection {
                authority: SelectedAuthority::FrankenSqlite,
                verdict,
            },
            store,
        ))
    } else {
        let store = SqlMetadataStore::open(reference_opener()(db_path)?)?;
        Ok((
            AuthoritativeSelection {
                authority: SelectedAuthority::Reference,
                verdict,
            },
            store,
        ))
    }
}

/// Render a verdict for logs/incident reports: one line per lane.
#[must_use]
pub fn render_verdict(verdict: &GateVerdict) -> String {
    let mut out = String::new();
    for lane in &verdict.lanes {
        let _ = writeln!(
            out,
            "{}: {} — {}",
            lane.lane.name(),
            if lane.passed { "PASS" } else { "FAIL" },
            lane.detail
        );
    }
    let _ = writeln!(
        out,
        "promotion: {}",
        if verdict.promoted() {
            "FrankenSQLite AUTHORITATIVE"
        } else {
            "refused (reference stays authoritative; FrankenSQLite remains dogfood)"
        }
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn fresh_root(tag: &str) -> PathBuf {
        let n = DIR_COUNTER.fetch_add(1, Ordering::SeqCst);
        let root =
            std::env::temp_dir().join(format!("rabs-h024-{}-{}-{}", std::process::id(), tag, n));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn h024_reference_vs_reference_promotes() {
        // Self-check against false refusals: an engine differentially
        // compared with itself must pass every lane.
        let root = fresh_root("ref-ref");
        let verdict = evaluate_gate(&root, &reference_opener(), &reference_opener());
        assert!(
            verdict.promoted(),
            "reference-vs-reference must pass every lane:\n{}",
            render_verdict(&verdict)
        );
        assert_eq!(verdict.lanes.len(), 4);
    }

    /// A candidate engine that silently drops every INSERT into `pins`
    /// — the planted divergence the gate MUST catch.
    struct SabotagedEngine {
        inner: RusqliteEngine,
    }

    impl SqlEngine for SabotagedEngine {
        fn execute(&mut self, sql: &str, params: &[SqlValue]) -> Result<usize, StoreError> {
            if sql.contains("INSERT INTO pins") {
                return Ok(1); // claims success, writes nothing
            }
            self.inner.execute(sql, params)
        }

        fn query(
            &mut self,
            sql: &str,
            params: &[SqlValue],
        ) -> Result<Vec<Vec<SqlValue>>, StoreError> {
            self.inner.query(sql, params)
        }
    }

    #[test]
    fn h024_differential_mismatch_blocks_promotion() {
        // THE acceptance: a candidate that diverges (here: silently
        // dropping pin writes while claiming success) must fail the
        // differential lane and be refused promotion.
        let root = fresh_root("sabotage");
        let sabotaged = |path: &Path| -> Result<Box<dyn SqlEngine>, StoreError> {
            RusqliteEngine::open(path)
                .map(|inner| Box::new(SabotagedEngine { inner }) as Box<dyn SqlEngine>)
        };
        let verdict = evaluate_gate(&root, &reference_opener(), &sabotaged);
        assert!(!verdict.promoted(), "sabotaged candidate must not promote");
        let differential = &verdict.lanes[0];
        assert_eq!(differential.lane, GateLane::Differential);
        assert!(!differential.passed);
        assert!(
            differential.detail.contains("reference=")
                && differential.detail.contains("candidate="),
            "refusal must name the first divergent line: {}",
            differential.detail
        );
    }

    #[test]
    fn h024_frankensqlite_gate_runs_and_wires_selection() {
        // The REAL gate against the real FrankenSQLite engine. The
        // selection must branch exactly on the verdict — promotion if
        // and only if every lane passed. This test asserts the wiring
        // invariant, not a hard-coded pass, so an engine regression
        // demotes instead of breaking the build; the verdict itself is
        // printed for the record.
        let root = fresh_root("real");
        let verdict = frankensqlite_gate(&root);
        println!("{}", render_verdict(&verdict));
        assert_eq!(verdict.lanes.len(), 4);
        for lane in &verdict.lanes {
            assert!(!lane.detail.is_empty(), "every lane must explain itself");
        }
        let db_root = fresh_root("real-db");
        let (selection, mut store) =
            open_authoritative_store(&root, &db_root.join("authoritative.db")).unwrap();
        assert_eq!(
            selection.authority == SelectedAuthority::FrankenSqlite,
            selection.verdict.promoted(),
            "selection must branch exactly on the gate verdict"
        );
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
    }

    #[test]
    fn h024_frankensqlite_passes_differential_and_migration_lanes() {
        // Grounded expectation from H009–H041: the FrankenSQLite
        // engine matches the reference across the store surface and
        // the migration chain. If THIS fails, either the engine
        // regressed or the gate's normalization is wrong — both must
        // be looked at, not papered over.
        let root = fresh_root("fsq-lanes");
        let differential = differential_lane(&root, &reference_opener(), &frankensqlite_opener());
        assert!(differential.passed, "differential: {}", differential.detail);
        let migration = migration_lane(&root, &reference_opener(), &frankensqlite_opener());
        assert!(migration.passed, "migration: {}", migration.detail);
    }

    #[test]
    fn h024_crash_lane_enforces_atomicity_and_durability() {
        // The crash lane is not only a differential: even if BOTH
        // engines lost committed work identically, the lane must fail
        // on the absolute check. Prove the absolute checks are wired
        // by running reference-vs-reference and inspecting the PASS
        // detail names both properties.
        let root = fresh_root("crash");
        let lane = crash_lane(&root, &reference_opener(), &reference_opener());
        assert!(lane.passed, "{}", lane.detail);
        assert!(lane.detail.contains("uncommitted work discarded"));
        assert!(lane.detail.contains("committed work durable"));
    }
}
