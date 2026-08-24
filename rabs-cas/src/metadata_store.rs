//! `RabsMetadataStore`: the narrow transactional metadata interface, its
//! reference SQLite backend, and the FrankenSQLite differential backend
//! (bead H009; plan §62; risk R59).
//!
//! One generic SQL implementation runs on two engines:
//!
//! - **rusqlite** (bundled C SQLite) — the differential/crash-recovery
//!   TRUTH;
//! - **fsqlite** (FrankenSQLite, pure Rust) — the preferred dogfood,
//!   authoritative only after it passes the identical suite (the H024
//!   gate builds on the harness here).
//!
//! Because both backends share the store logic, the differential harness
//! compares the ENGINES: SQL semantics, constraint behavior, transaction
//! atomicity, and on-disk round-tripping — exactly what the FrankenSQLite
//! gate must prove. The plan's binding constraints encoded here:
//!
//! - one active coordinator authority owns authoritative writes; only it
//!   may create a generation or commit a publication;
//! - `ActionGenerationId` is never reused: a monotone high-water mark
//!   survives tombstoning and store reopen;
//! - the publication row, its serving state, and its durable reachability
//!   pin are written in ONE transaction;
//! - a same-key candidate with a different descriptor digest enters
//!   conflict quarantine — never an overwrite;
//! - attempts are append-only lifecycle records; lease renewals are
//!   strictly monotonic sequence numbers (no wall clocks, risk R127);
//! - migrations are transactional and versioned (`schema_epochs`);
//! - the database never holds large object bytes (digests + scalar
//!   metadata only);
//! - typed digests round-trip with their semantic domain, and a domain
//!   read back that this process never wrote is a fail-closed corruption
//!   error, not a silent re-typing (risk R121).

use std::collections::HashMap;

use rabs_protocol::generation::{
    ActionGeneration, AttemptAuthority, LeaseRenewal, WorkerBootGeneration, WorkerIncarnationId,
};
use rabs_protocol::result_identity::{DigestAlgorithm, TypedDigest};
use rabs_protocol::serving::ServingValidity;
use rabs_protocol::wire_time::PeerId;
use rabs_protocol::worker_fence::{
    WorkerAdmission, WorkerIncarnationFenceRecord, WorkerLeaseBindingRejection, WorkerSessionOffer,
};

/// Current schema version (v8 = the full H038 authoritative table set;
/// v9 = H040 revisioned authority-bound serving state; v10 = H026
/// append-only divergence incidents; v11 = H029 evidence rows name the
/// canonical result manifest they support; v12 = H032 location rows
/// carry their durability state; v13 = H028 provisional-ancestor
/// lineage + adoption edges; v14 = M004 provisional `.rmeta` upload
/// pins + authorized-visibility grants; v15 = M006 dependent-action
/// provisional-consumption obligations; v16 = M017 transitive
/// pin-lineage closure edges + producer contract bindings on pins;
/// v17 = M020 per-edge min-hop depths (I025 transitive-depth bounds)
/// on the lineage closure; v18 = M019 provisional install journal
/// (edge-local records of outputs installed before lineage closure,
/// with ownership-safe recovery state); v19 = L008 native child
/// bindings gating parent build-script publication; v20 = S022 durable
/// worker boot-generation and active-incarnation fencing; v21 = T038
/// durable clone ambiguity plus normalized worker bindings on attempts
/// (every execution lease links through its attempt).
pub const SCHEMA_VERSION: u32 = 21;

/// One transactional, versioned migration step.
pub struct Migration {
    /// Version this step migrates TO.
    pub version: u32,
    /// DDL statements applied inside one transaction.
    pub statements: &'static [&'static str],
}

/// The versioned migration set. Digest columns are always the triple
/// `*_algo TEXT, *_domain TEXT, *_bytes BLOB` plus a derived `*_key TEXT`
/// (domain:hex) used for keys/joins; object bytes NEVER appear here.
pub const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        statements: &[
            "CREATE TABLE schema_epochs (version INTEGER PRIMARY KEY, applied_seq INTEGER NOT NULL)",
            "CREATE TABLE coordinator_authorities (key TEXT PRIMARY KEY, algo TEXT NOT NULL, \
         domain TEXT NOT NULL, bytes BLOB NOT NULL, cluster_id TEXT NOT NULL, \
         incarnation BLOB NOT NULL, term INTEGER NOT NULL, acquired_seq INTEGER NOT NULL, \
         released INTEGER NOT NULL)",
            "CREATE TABLE action_entries (key TEXT PRIMARY KEY, algo TEXT NOT NULL, \
         domain TEXT NOT NULL, bytes BLOB NOT NULL, key_epoch INTEGER NOT NULL, \
         projection_epoch INTEGER NOT NULL)",
            "CREATE TABLE action_generations (id_hex TEXT PRIMARY KEY, id BLOB NOT NULL, \
         action_key TEXT NOT NULL, authority_key TEXT NOT NULL, tombstoned INTEGER NOT NULL)",
            "CREATE TABLE generation_high_water (kind TEXT PRIMARY KEY, value BLOB NOT NULL)",
            "CREATE TABLE action_attempts (id_hex TEXT PRIMARY KEY, id BLOB NOT NULL, \
         generation_hex TEXT NOT NULL, worker TEXT NOT NULL, seq INTEGER NOT NULL)",
            "CREATE TABLE execution_leases (id_hex TEXT PRIMARY KEY, id BLOB NOT NULL, \
         attempt_hex TEXT NOT NULL, renewal_seq INTEGER NOT NULL, \
         expires_at_seq INTEGER NOT NULL, released INTEGER NOT NULL)",
            "CREATE TABLE action_publications (action_key TEXT PRIMARY KEY, \
         descriptor_algo TEXT NOT NULL, descriptor_domain TEXT NOT NULL, \
         descriptor_bytes BLOB NOT NULL, manifest_algo TEXT NOT NULL, \
         manifest_domain TEXT NOT NULL, manifest_bytes BLOB NOT NULL, \
         winner_generation_hex TEXT NOT NULL, winner_attempt_hex TEXT NOT NULL, \
         result_kind TEXT NOT NULL, pin_hex TEXT NOT NULL)",
            "CREATE TABLE action_serving_states (action_key TEXT PRIMARY KEY, \
         disposition TEXT NOT NULL, version INTEGER NOT NULL)",
            "CREATE TABLE objects (key TEXT PRIMARY KEY, algo TEXT NOT NULL, \
         domain TEXT NOT NULL, bytes BLOB NOT NULL, logical_size INTEGER NOT NULL)",
            "CREATE TABLE object_locations (object_key TEXT NOT NULL, store_path TEXT NOT NULL, \
         verified_seq INTEGER, PRIMARY KEY (object_key, store_path))",
            "CREATE TABLE pins (id_hex TEXT PRIMARY KEY, id BLOB NOT NULL, root_key TEXT NOT NULL, \
         owner TEXT NOT NULL, class TEXT NOT NULL, expires_at_seq INTEGER, \
         released INTEGER NOT NULL)",
            "CREATE TABLE observed_input_recipes (action_key TEXT PRIMARY KEY, \
         recipe_algo TEXT NOT NULL, recipe_domain TEXT NOT NULL, recipe_bytes BLOB NOT NULL)",
            "CREATE TABLE key_breakdowns (action_key TEXT NOT NULL, component TEXT NOT NULL, \
         algo TEXT NOT NULL, domain TEXT NOT NULL, bytes BLOB NOT NULL, \
         PRIMARY KEY (action_key, component))",
            "CREATE TABLE trust_states (action_key TEXT PRIMARY KEY, state TEXT NOT NULL, \
         reason TEXT NOT NULL)",
            "CREATE TABLE quarantines (scope TEXT NOT NULL, subject TEXT NOT NULL, \
         reason TEXT NOT NULL, PRIMARY KEY (scope, subject))",
            "CREATE TABLE verification_samples (action_key TEXT NOT NULL, attempt_hex TEXT NOT NULL, \
         passed INTEGER NOT NULL, seq INTEGER NOT NULL, \
         PRIMARY KEY (action_key, attempt_hex, seq))",
            "CREATE TABLE gc_runs (id INTEGER PRIMARY KEY, seq INTEGER NOT NULL, \
         pinned_roots INTEGER NOT NULL, located_objects INTEGER NOT NULL)",
        ],
    },
    Migration {
        // H011: attempts' evidence bundles are append-only associations; the
        // winner's evidence row is written in the SAME transaction as the
        // publication pointer + pin.
        version: 2,
        statements: &[
            "CREATE TABLE action_evidence_index (action_key TEXT NOT NULL, \
         evidence_algo TEXT NOT NULL, evidence_domain TEXT NOT NULL, \
         evidence_bytes BLOB NOT NULL, generation_hex TEXT NOT NULL, \
         attempt_hex TEXT NOT NULL, PRIMARY KEY (action_key, evidence_domain, evidence_bytes))",
        ],
    },
    Migration {
        // H010: object edges (reachability), location EVIDENCE columns
        // (encoding + quarantine status — never identity), and full pin
        // semantics (evidence, renewal lease, durable-vs-ephemeral,
        // reason).
        version: 3,
        statements: &[
            "CREATE TABLE object_edges (parent_key TEXT NOT NULL, child_key TEXT NOT NULL, \
         kind TEXT NOT NULL, PRIMARY KEY (parent_key, child_key, kind))",
            "ALTER TABLE object_locations ADD COLUMN encoding TEXT NOT NULL DEFAULT 'raw'",
            "ALTER TABLE object_locations ADD COLUMN quarantined INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE pins ADD COLUMN evidence TEXT",
            "ALTER TABLE pins ADD COLUMN renewal_seq INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE pins ADD COLUMN durable INTEGER NOT NULL DEFAULT 1",
            "ALTER TABLE pins ADD COLUMN reason TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE gc_runs ADD COLUMN reachable_objects INTEGER NOT NULL DEFAULT 0",
        ],
    },
    Migration {
        // H014: planned + actual reclaim receipts, one row per GC run.
        version: 4,
        statements: &[
            "CREATE TABLE gc_receipts (id INTEGER PRIMARY KEY, seq INTEGER NOT NULL, \
         mode TEXT NOT NULL, planned INTEGER NOT NULL, reclaimed INTEGER NOT NULL, \
         skipped INTEGER NOT NULL, truncated INTEGER NOT NULL)",
        ],
    },
    Migration {
        // H022: mark → tombstone → grace → recheck → unlink. A tombstone
        // is a marked location awaiting its grace window; deletion is
        // NEVER immediate.
        version: 5,
        statements: &["CREATE TABLE gc_tombstones (object_key TEXT NOT NULL, \
         store_path TEXT NOT NULL, marked_seq INTEGER NOT NULL, \
         grace_until_seq INTEGER NOT NULL, PRIMARY KEY (object_key, store_path))"],
    },
    Migration {
        // H034: result digests survive blob eviction so a post-eviction
        // recomputation can be compared — mismatch is a divergence
        // incident, never a silent replacement.
        version: 6,
        statements: &[
            "CREATE TABLE eviction_tombstones (action_key TEXT PRIMARY KEY, \
         semantic_algo TEXT NOT NULL, semantic_domain TEXT NOT NULL, \
         semantic_bytes BLOB NOT NULL, observable_algo TEXT NOT NULL, \
         observable_domain TEXT NOT NULL, observable_bytes BLOB NOT NULL, \
         evicted_seq INTEGER NOT NULL)",
        ],
    },
    Migration {
        // H037: consumed operator-reset generations — the ONLY path that
        // resumes serving over lost/rolled-back authoritative state.
        version: 7,
        statements: &[
            "CREATE TABLE operator_resets (generation INTEGER PRIMARY KEY, \
         applied_seq INTEGER NOT NULL)",
        ],
    },
    Migration {
        // H038: the remainder of the full authoritative table set.
        // Incarnations and peer terms fence stale writers; edge handoffs
        // model at most ONE active row with exactly one NAMED
        // predecessor; trust evaluations are the append-only versioned
        // ledger behind the mutable `trust_states` row. Deterministic
        // failures remain `ResultKind` publications — there is
        // deliberately NO failure table in this set.
        version: 8,
        statements: &[
            "CREATE TABLE peer_authority_high_water (peer_id TEXT PRIMARY KEY, \
         term INTEGER NOT NULL, observed_seq INTEGER NOT NULL)",
            "CREATE TABLE worker_incarnation_fences (worker TEXT PRIMARY KEY, \
         incarnation BLOB NOT NULL)",
            "CREATE TABLE edge_incarnation_fences (edge_id TEXT PRIMARY KEY, \
         incarnation BLOB NOT NULL)",
            "CREATE TABLE edge_handoffs (edge_id TEXT PRIMARY KEY, \
         active_incarnation BLOB NOT NULL, predecessor_incarnation BLOB NOT NULL, \
         begun_seq INTEGER NOT NULL, resolved INTEGER NOT NULL)",
            "CREATE TABLE action_trust_evaluations (action_key TEXT NOT NULL, \
         version INTEGER NOT NULL, state TEXT NOT NULL, reason TEXT NOT NULL, \
         evaluated_seq INTEGER NOT NULL, PRIMARY KEY (action_key, version))",
            "CREATE TABLE operations (id_hex TEXT PRIMARY KEY, id BLOB NOT NULL, \
         kind TEXT NOT NULL, state TEXT NOT NULL, updated_seq INTEGER NOT NULL)",
            "CREATE TABLE edge_subscribers (edge_id TEXT NOT NULL, subscriber TEXT NOT NULL, \
         registered_seq INTEGER NOT NULL, PRIMARY KEY (edge_id, subscriber))",
            "CREATE TABLE manifests (key TEXT PRIMARY KEY, algo TEXT NOT NULL, \
         domain TEXT NOT NULL, bytes BLOB NOT NULL, kind TEXT NOT NULL, \
         entry_count INTEGER NOT NULL)",
            "CREATE TABLE worker_sessions (worker TEXT NOT NULL, incarnation BLOB NOT NULL, \
         started_seq INTEGER NOT NULL, ended_seq INTEGER, \
         PRIMARY KEY (worker, started_seq))",
            "CREATE TABLE worker_capabilities (worker TEXT NOT NULL, capability TEXT NOT NULL, \
         PRIMARY KEY (worker, capability))",
            "CREATE TABLE worker_health_samples (worker TEXT NOT NULL, seq INTEGER NOT NULL, \
         healthy INTEGER NOT NULL, detail TEXT NOT NULL, PRIMARY KEY (worker, seq))",
            "CREATE TABLE decision_receipts (kind TEXT NOT NULL, subject TEXT NOT NULL, \
         seq INTEGER NOT NULL, decision TEXT NOT NULL, reason TEXT NOT NULL, \
         PRIMARY KEY (kind, subject, seq))",
            "CREATE TABLE provenance_edges (from_key TEXT NOT NULL, to_key TEXT NOT NULL, \
         kind TEXT NOT NULL, PRIMARY KEY (from_key, to_key, kind))",
            "CREATE TABLE determinism_audits (action_key TEXT NOT NULL, \
         attempt_hex TEXT NOT NULL, seq INTEGER NOT NULL, verdict TEXT NOT NULL, \
         PRIMARY KEY (action_key, attempt_hex, seq))",
            "CREATE TABLE materialization_records (id_hex TEXT PRIMARY KEY, id BLOB NOT NULL, \
         root_key TEXT NOT NULL, dest_path TEXT NOT NULL, state TEXT NOT NULL, \
         updated_seq INTEGER NOT NULL)",
        ],
    },
    Migration {
        // H040: revisioned authority-bound serving state with a durable
        // conservative validity window (R126). Blocking quarantines are
        // NAMED rows in a junction table — a reason string is never the
        // gate. Legacy rows carry state_revision 0, so every H040 write
        // (revision >= 1) supersedes them.
        version: 9,
        statements: &[
            "ALTER TABLE action_serving_states ADD COLUMN state_revision INTEGER NOT NULL \
         DEFAULT 0",
            "ALTER TABLE action_serving_states ADD COLUMN authority_key TEXT NOT NULL \
         DEFAULT ''",
            "ALTER TABLE action_serving_states ADD COLUMN evaluated_at_micros INTEGER NOT NULL \
         DEFAULT 0",
            "ALTER TABLE action_serving_states ADD COLUMN max_age_micros INTEGER",
            "ALTER TABLE action_serving_states ADD COLUMN clock_uncertainty_micros INTEGER \
         NOT NULL DEFAULT 0",
            "ALTER TABLE action_serving_states ADD COLUMN clock_epoch INTEGER NOT NULL \
         DEFAULT 0",
            "CREATE TABLE serving_blocking_quarantines (action_key TEXT NOT NULL, \
         scope TEXT NOT NULL, subject TEXT NOT NULL, PRIMARY KEY (action_key, scope, subject))",
        ],
    },
    Migration {
        // H026: same-key divergence incidents (I34; risk R63). Append-only:
        // one row per admitted divergence observation, keyed by
        // (action_key, seq); a conflicting rewrite of an existing key is a
        // typed refusal. Both candidates' manifest/evidence keys and the
        // candidate-preservation pin are NAMED in the row, so the incident
        // is auditable after the offer path returns.
        version: 10,
        statements: &[
            "CREATE TABLE divergence_incidents (action_key TEXT NOT NULL, \
         seq INTEGER NOT NULL, class TEXT NOT NULL, \
         committed_manifest_key TEXT NOT NULL, candidate_manifest_key TEXT NOT NULL, \
         candidate_evidence_key TEXT NOT NULL, candidate_pin_hex TEXT NOT NULL, \
         generation_hex TEXT NOT NULL, attempt_hex TEXT NOT NULL, detail TEXT NOT NULL, \
         PRIMARY KEY (action_key, seq))",
        ],
    },
    Migration {
        // H029: every evidence row NAMES the canonical result manifest it
        // supports (I37; risks R80/R115). Evidence for a divergence
        // candidate binds to the CANDIDATE manifest, so listing evidence
        // for the committed canonical result can never conflate the two.
        // Legacy rows carry '' (pre-H029 attribution is unknown, never
        // guessed).
        version: 11,
        statements: &[
            "ALTER TABLE action_evidence_index ADD COLUMN manifest_key TEXT NOT NULL DEFAULT ''",
        ],
    },
    Migration {
        // H032: a location row states whether its copy satisfied the FULL
        // durability policy (file + directory fsync) when recorded.
        // Commit acknowledgement gates on durable locations, so a
        // committed pointer can never name an object that only exists in
        // volatile page cache. Legacy rows default to 0: durability is
        // never assumed retroactively.
        version: 12,
        statements: &["ALTER TABLE object_locations ADD COLUMN durable INTEGER NOT NULL DEFAULT 0"],
    },
    Migration {
        // H028: provisional-ancestor lineage (I32; risk R64). A committed
        // consumer NAMES every producer whose provisional output it
        // consumed — rows are written in the SAME transaction as the
        // publication pointer, so the transitive closure walk at a later
        // dependent's commit reads durable truth, never offer-time
        // claims. Adoption edges are the coordinator's explicit,
        // authority-gated declaration that a consumed losing-attempt
        // object is compatible with the winning attempt's committed
        // object for the same logical output.
        version: 13,
        statements: &[
            "CREATE TABLE provisional_ancestry (consumer_action_key TEXT NOT NULL, \
         producer_action_key TEXT NOT NULL, role TEXT NOT NULL, \
         virtual_path BLOB NOT NULL, object_key TEXT NOT NULL, \
         adopted INTEGER NOT NULL, \
         PRIMARY KEY (consumer_action_key, producer_action_key, role, virtual_path))",
            "CREATE TABLE adoption_edges (producer_action_key TEXT NOT NULL, \
         role TEXT NOT NULL, virtual_path BLOB NOT NULL, \
         from_object_key TEXT NOT NULL, to_object_key TEXT NOT NULL, \
         PRIMARY KEY (producer_action_key, role, virtual_path, from_object_key))",
        ],
    },
    Migration {
        // M004: provisional `.rmeta` upload pins (plan §65). One row per
        // candidate pin binding an early metadata object to its full
        // producer identity tuple; grants name the ONLY readers (dependent
        // attempts + the awaiting edge/subscriber) — visibility is closed
        // by default and every read is authorized against this table.
        version: 14,
        statements: &[
            "CREATE TABLE provisional_pins (pin_key TEXT PRIMARY KEY, \
         authority_key TEXT NOT NULL, action_key TEXT NOT NULL, \
         generation_hex TEXT NOT NULL, attempt_hex TEXT NOT NULL, \
         lease_hex TEXT NOT NULL, role INTEGER NOT NULL, \
         virtual_path BLOB NOT NULL, obj_algo TEXT NOT NULL, \
         obj_domain TEXT NOT NULL, obj_bytes BLOB NOT NULL, \
         object_key TEXT NOT NULL, protective_pin_hex TEXT NOT NULL, \
         renewal_seq INTEGER NOT NULL DEFAULT 0, adopted_object_key TEXT, \
         invalidated_reason TEXT, released INTEGER NOT NULL DEFAULT 0)",
            "CREATE TABLE provisional_pin_grants (pin_key TEXT NOT NULL, \
         grantee_kind TEXT NOT NULL, grantee_id TEXT NOT NULL, \
         granted_seq INTEGER NOT NULL, \
         PRIMARY KEY (pin_key, grantee_kind, grantee_id))",
        ],
    },
    Migration {
        // M006: dependent-action provisional obligations. Consuming a
        // provisional output creates ONE row binding the consumer attempt
        // to the producer lineage (action/generation/attempt, logical
        // output, exact object). Open rows block the descendant's terminal
        // paths; resolved rows record the satisfying commit; cancelled
        // rows permanently refuse it (producer lineage failed/superseded).
        version: 15,
        statements: &[
            "CREATE TABLE provisional_obligations (consumer_worker TEXT NOT NULL, \
         consumer_attempt_hex TEXT NOT NULL, pin_key TEXT NOT NULL, \
         producer_action_key TEXT NOT NULL, producer_generation_hex TEXT NOT NULL, \
         producer_attempt_hex TEXT NOT NULL, role INTEGER NOT NULL, \
         virtual_path BLOB NOT NULL, object_key TEXT NOT NULL, \
         status TEXT NOT NULL DEFAULT 'open', resolution_object_key TEXT, \
         created_seq INTEGER NOT NULL, \
         PRIMARY KEY (consumer_worker, consumer_attempt_hex, pin_key))",
        ],
    },
    Migration {
        // M017: transitive pin-lineage closure + producer contract
        // bindings. Every prepared descendant pin materializes the FULL
        // transitive ancestor-pin closure at open time (edges written in
        // the SAME transaction as the pin row, so a tear can never leave
        // a pin without its recorded ancestry), and each pin binds the
        // toolchain/event contract digests its producer ran under — the
        // equality a different-winning-attempt adoption must prove.
        version: 16,
        statements: &[
            "ALTER TABLE provisional_pins ADD COLUMN toolchain_contract_key \
         TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE provisional_pins ADD COLUMN event_contract_key \
         TEXT NOT NULL DEFAULT ''",
            "CREATE TABLE provisional_pin_lineage (descendant_pin_key TEXT NOT NULL, \
         ancestor_pin_key TEXT NOT NULL, \
         PRIMARY KEY (descendant_pin_key, ancestor_pin_key))",
            "CREATE INDEX idx_provisional_pin_lineage_ancestor \
         ON provisional_pin_lineage (ancestor_pin_key)",
        ],
    },
    Migration {
        // M020: per-edge min-hop depths on the materialized closure
        // (I025). Depth is computed at pin-open time by layered BFS over
        // the ancestors' own recorded depths and lets the terminal-gate
        // layer bound lineage-waiting wrappers by TRANSITIVE DEPTH, not
        // just count. Legacy (v16) rows read as depth 1 — a conservative
        // underestimate only for pre-M020 pins, which never carried
        // multi-hop closures anyway.
        version: 17,
        statements: &["ALTER TABLE provisional_pin_lineage ADD COLUMN \
         min_hops INTEGER NOT NULL DEFAULT 1"],
    },
    Migration {
        // M019: provisional install journal (R86). Edge-local record of
        // EVERY output installed to a real path before its lineage
        // closed, keyed by (pin, consumer attempt, exact path) so
        // recovery can be ownership-safe: a path is removed only when
        // its CURRENT bytes still hash to the recorded object AND the
        // path is one this operation recorded; anything else is marked
        // dirty for Cargo revalidation — never guess-deleted.
        version: 18,
        statements: &[
            "CREATE TABLE provisional_install_journal (pin_key TEXT NOT NULL, \
         consumer_worker TEXT NOT NULL, consumer_attempt_hex TEXT NOT NULL, \
         installed_path BLOB NOT NULL, obj_algo TEXT NOT NULL, \
         obj_domain TEXT NOT NULL, obj_bytes BLOB NOT NULL, object_key TEXT NOT NULL, \
         installed_seq INTEGER NOT NULL, state TEXT NOT NULL DEFAULT 'installed', \
         PRIMARY KEY (pin_key, consumer_attempt_hex, installed_path))",
            "CREATE INDEX idx_provisional_install_state \
         ON provisional_install_journal (state)",
        ],
    },
    Migration {
        // L008: native child bindings. A build-script (parent) action
        // declares the native child actions whose outputs it consumes;
        // the parent's publication is refused while any binding stays
        // `bound` (child unresolved) and flips to `satisfied` — with an
        // idempotent provenance edge — once the child result commits.
        version: 19,
        statements: &[
            "CREATE TABLE native_child_bindings (parent_action_key TEXT NOT NULL, \
         child_action_key TEXT NOT NULL, bound_seq INTEGER NOT NULL, \
         state TEXT NOT NULL DEFAULT 'bound', \
         PRIMARY KEY (parent_action_key, child_action_key))",
        ],
    },
    Migration {
        // S022/I47: a worker incarnation is random, so it is NOT an
        // ordered high-water value. The durable ordering fence is the
        // worker's boot generation; the random incarnation names the
        // one live session admitted for that identity/generation. Old
        // rows conservatively remain active at generation zero until an
        // exact-incarnation release or a newer boot supersedes them.
        version: 20,
        statements: &[
            "ALTER TABLE worker_incarnation_fences ADD COLUMN \
         highest_boot_generation BLOB NOT NULL DEFAULT X'0000000000000000'",
            "ALTER TABLE worker_incarnation_fences ADD COLUMN \
         active INTEGER NOT NULL DEFAULT 1",
            "ALTER TABLE worker_incarnation_fences ADD COLUMN \
         operator_reenrollment_generation BLOB NOT NULL DEFAULT X'0000000000000000'",
        ],
    },
    Migration {
        // T038/I47: clone detection fences BOTH contenders until a fresh
        // proof selects one. Attempts created before this migration remain
        // NULL-bound and therefore can never acquire/renew a live lease or
        // publish; silently defaulting them to a current worker would turn
        // unknown legacy provenance into authority.
        version: 21,
        statements: &[
            "ALTER TABLE worker_incarnation_fences ADD COLUMN \
         clone_ambiguous INTEGER NOT NULL DEFAULT 1",
            "ALTER TABLE action_generations ADD COLUMN per_key_ordinal BLOB",
            "ALTER TABLE action_attempts ADD COLUMN worker_boot_generation BLOB",
            "ALTER TABLE action_attempts ADD COLUMN worker_incarnation BLOB",
            "ALTER TABLE action_attempts ADD COLUMN execution_lease_hex TEXT",
        ],
    },
];

impl std::fmt::Display for StoreError {
    /// Delegates to the derived [`Debug`] output: the enum is closed over by
    /// this crate's tests, every variant is information-carrying, and a
    /// hand-written arm list would silently rot as M019/M020 add variants.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "store error: {self:?}")
    }
}

impl std::error::Error for StoreError {}

/// Typed store errors (comparable so the differential harness can assert
/// both backends fail IDENTICALLY).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// Engine-level failure (SQL error, I/O), carried verbatim.
    Backend(String),
    /// A different unreleased authority already holds the slot.
    AuthorityHeld {
        /// Digest key of the current holder.
        holder: String,
    },
    /// The presented authority is not the active one.
    NotActiveAuthority,
    /// Generation id at or below the high-water mark (ids are NEVER
    /// reused, even after tombstoning).
    GenerationIdNotAboveHighWater,
    /// Attempt id already recorded (attempts are append-only).
    DuplicateAttempt,
    /// Execution lease id already exists.
    DuplicateLease,
    /// Referenced generation does not exist.
    UnknownGeneration,
    /// Referenced generation was closed and may issue no new/renewed work.
    GenerationTombstoned,
    /// Referenced lease does not exist.
    UnknownLease,
    /// The lease row names a different attempt than the presented full
    /// attempt authority.
    LeaseAttemptMismatch,
    /// The attempt row is legacy/unbound or disagrees with the presented
    /// generation/worker tuple.
    AttemptAuthorityMismatch,
    /// A pre-v21 generation or attempt lacks the authority columns needed
    /// to prove a lease binding; legacy uncertainty always fails closed.
    LegacyUnboundAuthority,
    /// No durable worker fence exists for the attempt's worker.
    UnknownWorkerFence,
    /// The attempt's bound worker tuple is stale, inactive, or ambiguous.
    WorkerLeaseRejected(WorkerLeaseBindingRejection),
    /// The renewal sequence carried by an authority-bearing message does
    /// not equal the store's last accepted value.
    LeaseRenewalMismatch,
    /// Lease already released.
    LeaseReleased,
    /// Renewal sequence not strictly greater than the stored one.
    NonMonotonicRenewal,
    /// Referenced pin does not exist.
    UnknownPin,
    /// Pin release attempted by a non-owner.
    PinOwnerMismatch,
    /// Pin already released.
    PinReleased,
    /// Pin renewal sequence not strictly greater than the stored one.
    NonMonotonicPinRenewal,
    /// Operator-reset generation not strictly greater than every
    /// recorded one (replayed or stale proof).
    StaleOperatorReset,
    /// Peer authority term below the recorded per-peer high-water
    /// (a stale view of that peer; H038).
    StalePeerAuthority,
    /// Edge incarnation below the recorded fence, or a handoff whose
    /// active incarnation does not exceed its named predecessor.
    StaleEdgeIncarnation,
    /// An unresolved handoff with different content already exists for
    /// this edge (at most ONE active handoff per edge).
    EdgeHandoffActive,
    /// An adoption edge for this (producer, role, path, from-object)
    /// already exists with a DIFFERENT target object (H028; edges are
    /// never patched).
    AdoptionEdgeConflict,
    /// The handoff's named predecessor is not the edge's fenced
    /// incarnation.
    EdgeHandoffPredecessorMismatch,
    /// No unresolved handoff row matches (edge, active incarnation).
    UnknownEdgeHandoff,
    /// Trust-evaluation version not strictly greater than the stored
    /// maximum for the action (evaluations are append-only history).
    NonMonotonicTrustEvaluation,
    /// Operation id already recorded.
    DuplicateOperation,
    /// Referenced operation does not exist.
    UnknownOperation,
    /// A manifest row exists under this digest with different metadata
    /// (same-digest/different-content is an incident, never an
    /// overwrite).
    ManifestDivergence,
    /// An append-only row exists under this key with different content;
    /// carries the table name for diagnosis.
    AppendConflict(String),
    /// Referenced materialization record does not exist.
    UnknownMaterialization,
    /// Serving-state revision not strictly greater than the stored one
    /// (replayed or stale evaluation; H040).
    StaleServingRevision,
    /// A named blocking quarantine row does not exist — references are
    /// the authority, so dangling ones are refused at write.
    UnknownQuarantineReference,
    /// A digest domain was read back that this process never wrote —
    /// fail-closed (R121), never silently re-typed.
    DomainNotInterned(String),
    /// Structural corruption (wrong column shape, bad enum tag).
    Corruption(String),
}

/// Outcome of a publication commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitOutcome {
    /// Publication + serving state + pin written in one transaction.
    Committed,
    /// Same key, same descriptor digest: idempotent no-op.
    IdempotentDuplicate,
    /// Same key, DIFFERENT descriptor digest: quarantined, original row
    /// untouched.
    ConflictQuarantined,
}

/// Coordinator authority row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityRow {
    /// Canonical digest of the full authority.
    pub digest: TypedDigest,
    /// Cluster identity.
    pub cluster_id: String,
    /// Coordinator incarnation id.
    pub incarnation: u128,
    /// Election/lock term.
    pub term: u64,
    /// Logical sequence at acquisition.
    pub acquired_seq: u64,
}

/// Action-cache entry row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionEntryRow {
    /// The action key.
    pub action_key: TypedDigest,
    /// Key epoch (retained for inspection/migration; plan §62).
    pub key_epoch: u32,
    /// Projection epoch.
    pub projection_epoch: u32,
}

/// Publication submitted for coordinator-only commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicationRow {
    /// The action key being answered.
    pub action_key: TypedDigest,
    /// Canonical descriptor digest (conflict identity).
    pub descriptor_digest: TypedDigest,
    /// Canonical result-manifest digest.
    pub manifest_digest: TypedDigest,
    /// Winning attempt's evidence-bundle digest (recorded in the SAME
    /// transaction as the publication pointer; H011).
    pub evidence_digest: TypedDigest,
    /// Winning generation id.
    pub winner_generation: u128,
    /// Winning attempt id.
    pub winner_attempt: u128,
    /// `"success"` or `"deterministic-failure"` (one publication path for
    /// both; I16).
    pub result_kind: ResultKindTag,
    /// Pin id created in the same transaction as the publication.
    pub pin_id: u128,
    /// Pin owner recorded for the publication reachability root.
    pub pin_owner: String,
    /// Verified provisional-ancestor lineage, written in the SAME
    /// transaction as the publication pointer (H028; I32). Empty when
    /// the result consumed no provisional outputs.
    pub provisional_ancestors: Vec<ProvisionalAncestorRow>,
}

/// Sealed authority capability for a publication transaction.
///
/// Production callers can construct this only from a full, worker-bound
/// [`AttemptAuthority`]. The coordinator-only constructor exists solely in
/// unit-test builds for fixtures that exercise unrelated metadata behavior;
/// it is absent from production artifacts.
#[derive(Debug, Clone, Copy)]
pub struct PublicationPermit<'a> {
    source: PublicationPermitSource<'a>,
}

#[derive(Debug, Clone, Copy)]
enum PublicationPermitSource<'a> {
    Attempt(&'a AttemptAuthority),
    #[cfg(test)]
    Fixture(&'a TypedDigest),
}

impl<'a> PublicationPermit<'a> {
    /// Bind a publication to one exact attempt, execution lease, renewal,
    /// worker boot generation, and worker incarnation.
    #[must_use]
    pub const fn for_attempt(authority: &'a AttemptAuthority) -> Self {
        Self {
            source: PublicationPermitSource::Attempt(authority),
        }
    }

    #[cfg(test)]
    pub(crate) const fn for_fixture(authority: &'a TypedDigest) -> Self {
        Self {
            source: PublicationPermitSource::Fixture(authority),
        }
    }

    fn into_parts(self) -> (TypedDigest, Option<AttemptAuthority>) {
        match self.source {
            PublicationPermitSource::Attempt(attempt) => (
                rabs_key::authority_binding::coordinator_authority_digest(&attempt.coordinator),
                Some(attempt.clone()),
            ),
            #[cfg(test)]
            PublicationPermitSource::Fixture(authority) => (authority.clone(), None),
        }
    }
}

/// One verified provisional-ancestor lineage row (H028): the consumer
/// consumed `object_key` as the producer's `(role, virtual_path)`
/// provisional output; `adopted` records that compatibility went through
/// an explicit adoption edge rather than exact-object identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionalAncestorRow {
    /// Digest key of the producer action.
    pub producer_action_key: String,
    /// Role tag of the consumed logical output.
    pub role: String,
    /// Canonical virtual path bytes of the consumed logical output.
    pub virtual_path: Vec<u8>,
    /// Digest key of the exact object the consumer consumed.
    pub object_key: String,
    /// Whether an explicit adoption edge (not exact-object identity)
    /// established compatibility.
    pub adopted: bool,
}

/// One provisional-upload pin row (M004; plan §65): an early `.rmeta`
/// object bound to its full producer identity tuple
/// `(authority, action key, generation, attempt, lease, logical output)`.
/// State columns are read-side facts: `adopted_object_key` records a
/// winner adoption (§65.1), `invalidated_reason` a producer failure or
/// supersession, `released` the post-drain close. The contract keys
/// (M017) bind the toolchain/event contracts the producer ran under;
/// empty on pre-v16 rows, and a different-winning-attempt adoption
/// refuses fail-closed against an unbound pin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionalPinRecord {
    /// Canonical digest key of the identity tuple.
    pub pin_key: String,
    /// Digest key of the minting coordinator authority.
    pub authority_key: String,
    /// Digest key of the producer action.
    pub action_key: String,
    /// Producer generation id (hex).
    pub generation_hex: String,
    /// Producer attempt id (hex).
    pub attempt_hex: String,
    /// Producer execution lease id (hex).
    pub lease_hex: String,
    /// Role tag of the logical output.
    pub role_tag: i64,
    /// Canonical virtual path bytes.
    pub virtual_path: Vec<u8>,
    /// The pinned object (domain-restored digest).
    pub object: TypedDigest,
    /// Derived digest key of [`Self::object`].
    pub object_key: String,
    /// Hex id of the protective row in `pins` keeping this object
    /// GC-safe while the candidate pin is live.
    pub protective_pin_hex: String,
    /// Monotonic renewal sequence.
    pub renewal_seq: u64,
    /// Object key of the committed result that adopted this pin, if any.
    pub adopted_object_key: Option<String>,
    /// Why the producer lineage failed/superseded/lost authority, if it did.
    pub invalidated_reason: Option<String>,
    /// Whether the pin is closed (drained or invalidated).
    pub released: bool,
    /// Digest key of the producer's toolchain contract (F007); empty when
    /// the pin predates v16 or the caller bound no contracts.
    pub toolchain_contract_key: String,
    /// Digest key of the producer's event contract; same binding rules.
    pub event_contract_key: String,
}

/// Insert payload for a new provisional-upload pin. Identity scalars are
/// raw values (hex encoding happens at the SQL boundary); the object is a
/// full typed digest so its domain is interned on write (R121).
///
/// M017: `ancestor_pin_keys` is the COMPLETE transitive ancestor-pin
/// closure of the producing attempt, computed by the caller and written
/// in the SAME transaction as the pin row — a prepared descendant always
/// carries its full lineage, and no tear can strip it. Each entry pairs
/// the ancestor key with its MIN-HOP distance from the new pin (M020):
/// 1 for direct ancestors, min-over-parents otherwise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionalPinInsert {
    /// Canonical digest key of the identity tuple.
    pub pin_key: String,
    /// Digest key of the minting coordinator authority.
    pub authority_key: String,
    /// Digest key of the producer action.
    pub action_key: String,
    /// Producer generation id.
    pub generation: u128,
    /// Producer attempt id.
    pub attempt: u128,
    /// Producer execution lease id.
    pub lease: u128,
    /// Role tag of the logical output.
    pub role_tag: i64,
    /// Canonical virtual path bytes.
    pub virtual_path: Vec<u8>,
    /// The pinned object.
    pub object: TypedDigest,
    /// Deterministic id of the protective `pins` row (derived from the
    /// pin digest by the caller).
    pub protective_pin_id: u128,
    /// Human-auditable reason stored with the protective pin.
    pub reason: String,
    /// Digest key of the producer's toolchain contract (F007); empty when
    /// unbound — different-winner adoption then refuses fail-closed.
    pub toolchain_contract_key: String,
    /// Digest key of the producer's event contract; empty when unbound.
    pub event_contract_key: String,
    /// Complete transitive ancestor-pin closure (M017): (ancestor key,
    /// min-hop distance from this pin) pairs, sorted for deterministic
    /// SQL ordering. Distances feed I025 transitive-depth bounds.
    pub ancestor_pin_keys: Vec<(String, u64)>,
}
/// One dependent-action provisional-consumption obligation (M006; plan
/// §65): the consumer attempt consumed `object_key` as the producer
/// tuple's provisional `(role, virtual_path)` output. Status lifecycle:
/// `open` (blocks descendant terminal paths) → `resolved` (producer
/// committed/adoption satisfied the lineage with `resolution_object_key`)
/// or `cancelled` (producer failed/superseded — the descendant is refused,
/// never published).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionalObligationRow {
    /// Worker running the consuming attempt.
    pub consumer_worker: String,
    /// Consuming attempt id (hex).
    pub consumer_attempt_hex: String,
    /// Canonical key of the consumed provisional pin.
    pub pin_key: String,
    /// Digest key of the producer action.
    pub producer_action_key: String,
    /// Producer generation id (hex).
    pub producer_generation_hex: String,
    /// Producer attempt id (hex).
    pub producer_attempt_hex: String,
    /// Role tag of the consumed logical output.
    pub role_tag: i64,
    /// Canonical virtual path bytes.
    pub virtual_path: Vec<u8>,
    /// Digest key of the exact object consumed.
    pub object_key: String,
    /// Lifecycle status (`open` | `resolved` | `cancelled`).
    pub status: String,
    /// Object key of the commit that resolved the obligation, if resolved.
    pub resolution_object_key: Option<String>,
    /// Coordinator sequence at consumption.
    pub created_seq: u64,
}

/// Insert payload for one consumption obligation (identity scalars raw;
/// encoding at the SQL boundary).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionalObligationInsert {
    /// Worker running the consuming attempt.
    pub consumer_worker: String,
    /// Consuming attempt id.
    pub consumer_attempt: u128,
    /// Canonical key of the consumed provisional pin.
    pub pin_key: String,
    /// Digest key of the producer action.
    pub producer_action_key: String,
    /// Producer generation id.
    pub producer_generation: u128,
    /// Producer attempt id.
    pub producer_attempt: u128,
    /// Role tag of the consumed logical output.
    pub role_tag: i64,
    /// Canonical virtual path bytes.
    pub virtual_path: Vec<u8>,
    /// Digest key of the exact object consumed.
    pub object_key: String,
    /// Coordinator sequence at consumption.
    pub created_seq: u64,
}

/// One provisional install-journal row (M019/R86): an output this
/// operation installed to a REAL path before its lineage closed.
/// `object` is the identity the installed bytes had at record time;
/// recovery removes the path only when current bytes still hash to it,
/// otherwise marks the row dirty for Cargo revalidation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionalInstallRecord {
    /// Pin whose lineage the installed output belonged to.
    pub pin_key: String,
    /// Worker running the consuming/installing attempt.
    pub consumer_worker: String,
    /// Installing attempt id (hex).
    pub consumer_attempt_hex: String,
    /// Exact recorded path bytes (full path; recovery never touches
    /// anything not recorded verbatim).
    pub installed_path: Vec<u8>,
    /// Identity of the installed bytes at record time.
    pub object: TypedDigest,
    /// Derived digest key of [`Self::object`].
    pub object_key: String,
    /// Coordinator sequence at install.
    pub installed_seq: u64,
    /// Lifecycle state (`installed` | `removed` | `dirty`).
    pub state: String,
}

/// Insert payload for one provisional install journal row (identity
/// scalars raw; encoding at the SQL boundary).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionalInstallInsert {
    /// Pin whose lineage the installed output belongs to.
    pub pin_key: String,
    /// Worker running the installing attempt.
    pub consumer_worker: String,
    /// Installing attempt id.
    pub consumer_attempt: u128,
    /// Exact recorded path bytes.
    pub installed_path: Vec<u8>,
    /// Identity of the installed bytes (recomputed from disk by the
    /// caller at record time — journal what IS there).
    pub object: TypedDigest,
    /// Coordinator sequence at install.
    pub installed_seq: u64,
}

/// Result kind tag persisted with a publication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultKindTag {
    /// Successful result.
    Success,
    /// Admitted deterministic failure.
    DeterministicFailure,
}

impl ResultKindTag {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::DeterministicFailure => "deterministic-failure",
        }
    }
}

/// Quarantine scope: distinct selection rules per scope (risk R51).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuarantineScope {
    /// One stored location is suspect.
    Location,
    /// A logical object/manifest is suspect.
    LogicalObject,
    /// An action entry is suspect.
    ActionEntry,
}

impl QuarantineScope {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Location => "location",
            Self::LogicalObject => "logical-object",
            Self::ActionEntry => "action-entry",
        }
    }
}

/// Existence + tombstone state of a generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenerationState {
    /// Whether the generation is tombstoned.
    pub tombstoned: bool,
}

/// Observable lease state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseState {
    /// Whether the lease has been released.
    pub released: bool,
    /// Last accepted renewal sequence.
    pub renewal_seq: u64,
}

/// One pin row as the lease layer sees it (H041).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinRow {
    /// Pin root digest key.
    pub root_key: String,
    /// Owner identity string.
    pub owner: String,
    /// Pin class (e.g. `"action-publication"`).
    pub class: String,
    /// Expiry sequence, if any.
    pub expires_at_seq: Option<u64>,
    /// Whether the pin has been released.
    pub released: bool,
    /// Last accepted renewal sequence.
    pub renewal_seq: u64,
}

/// One tombstoned location awaiting (or past) its grace window (H022).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcTombstoneRow {
    /// Object digest key.
    pub object_key: String,
    /// Store path of the marked copy.
    pub store_path: String,
    /// Sequence at marking.
    pub marked_seq: u64,
    /// First sequence at which unlink may proceed.
    pub grace_until_seq: u64,
}

/// One planned-vs-actual GC reclaim receipt (H014).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcReceiptRow {
    /// Logical sequence of the run.
    pub seq: u64,
    /// `"normal"` or `"emergency"`.
    pub mode: String,
    /// Locations the plan intended to reclaim.
    pub planned: u64,
    /// Locations actually reclaimed.
    pub reclaimed: u64,
    /// Planned locations skipped at execution time.
    pub skipped: u64,
    /// Whether the plan was truncated by the reclaim budget.
    pub truncated: bool,
}

/// GC snapshot: what the collector must preserve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcSnapshot {
    /// Unreleased pin roots (digest keys).
    pub pinned_roots: Vec<String>,
    /// Objects with at least one recorded location (digest keys).
    pub located_objects: Vec<String>,
    /// Closure of the unreleased pin roots over `object_edges` (digest
    /// keys, sorted): what GC must preserve beyond the roots themselves.
    pub reachable_from_pins: Vec<String>,
}

/// One row of a reconciliation scan (checked against filesystem reality).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconciliationRow {
    /// Object digest key.
    pub object_key: String,
    /// Recorded store path.
    pub store_path: String,
    /// Last verification sequence, if any.
    pub verified_seq: Option<u64>,
    /// Storage encoding of this copy (location EVIDENCE, never identity).
    pub encoding: String,
    /// Whether this location (this COPY, not the object) is quarantined.
    pub quarantined: bool,
}

/// One versioned trust evaluation (H038). The mutable `trust_states`
/// row is the CURRENT state; this is the append-only ledger behind it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustEvaluationRow {
    /// Strictly increasing evaluation version for the action.
    pub version: u32,
    /// Evaluated trust state.
    pub state: String,
    /// Why this evaluation was reached.
    pub reason: String,
    /// Logical sequence of the evaluation.
    pub evaluated_seq: u64,
}

/// The unresolved handoff for an edge: exactly one active incarnation
/// and exactly one NAMED predecessor (H038).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EdgeHandoffRow {
    /// Incarnation taking over the edge.
    pub active_incarnation: u128,
    /// The named predecessor incarnation being replaced.
    pub predecessor_incarnation: u128,
    /// Logical sequence when the handoff began.
    pub begun_seq: u64,
}

/// One revisioned, authority-bound serving-state record (H040). The
/// legacy `disposition`-only rows read back with `state_revision` 0 and
/// an empty authority key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServingRecordRow {
    /// Serving disposition string (`"servable"`, `"evidence-pending"`,
    /// `"quarantined"`, ...).
    pub disposition: String,
    /// Monotonic revision; replays are refused, never overwritten.
    pub state_revision: u64,
    /// Digest key of the authority that evaluated this state.
    pub authority_key: String,
    /// Conservative durable validity window (R126).
    pub validity: ServingValidity,
    /// NAMED blocking quarantine rows (scope tag, subject), sorted. The
    /// references are the gate — a reason string never is.
    pub blocking: Vec<(String, String)>,
}

/// One append-only same-key divergence incident (H026; I34/R63). The
/// committed candidate stays the published row; the offered candidate is
/// preserved under the named pin — neither is ever patched in place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DivergenceIncidentRow {
    /// Action key (digest key form) the divergence was observed on.
    pub action_key: String,
    /// Logical sequence of the observation (part of the primary key).
    pub seq: u64,
    /// Divergence class tag (`"semantic"`, `"observable-only"`,
    /// `"projection-completeness"`).
    pub class: String,
    /// Manifest digest key of the already-committed candidate.
    pub committed_manifest_key: String,
    /// Manifest digest key of the offered (losing) candidate.
    pub candidate_manifest_key: String,
    /// Evidence-bundle digest key of the offered candidate.
    pub candidate_evidence_key: String,
    /// Hex id of the durable candidate-preservation pin.
    pub candidate_pin_hex: String,
    /// Offering generation id, hex.
    pub generation_hex: String,
    /// Offering attempt id, hex.
    pub attempt_hex: String,
    /// Human-readable incident detail.
    pub detail: String,
}

/// One recorded verification sample (H033 trust-evaluation input).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationSampleRow {
    /// Attempt id, hex.
    pub attempt_hex: String,
    /// Whether the verification passed.
    pub passed: bool,
    /// Logical sequence of the sample.
    pub seq: u64,
}

/// The narrow transactional metadata interface (plan §62). Every method
/// is one transaction in the backing engine.
pub trait RabsMetadataStore {
    /// Applied schema version.
    fn schema_version(&mut self) -> Result<u32, StoreError>;

    /// Raw read-only SQL over the store backend (`?1..?N` placeholders).
    /// Escape hatch for operator surfaces (e.g. `rch rabs gc` receipts)
    /// whose schemas are owned by the rch crate, not by typed methods here.
    fn query(&mut self, sql: &str, params: &[SqlValue]) -> Result<Vec<Vec<SqlValue>>, StoreError>;

    /// Declare a digest domain this process is prepared to read back.
    ///
    /// Restoring a stored digest requires the READING process to already
    /// know its domain as a `&'static str` (R121: a domain a process
    /// never named cannot be silently re-typed on read — the read fails
    /// with [`StoreError::DomainNotInterned`]). Writes intern implicitly,
    /// which is enough within one incarnation; a FRESH process that must
    /// read rows an earlier incarnation wrote — the coordinator reading
    /// back the authority it left behind, at boot, before it has written
    /// anything — declares them here first.
    ///
    /// This does not weaken the fence: the caller can only pass a
    /// `'static` domain its own code holds, so an unknown domain in the
    /// database still cannot be restored.
    fn intern_domain(&mut self, domain: &'static str);

    /// Acquire the coordinator authority slot. Refused while a DIFFERENT
    /// unreleased authority holds it; re-acquiring the same digest is
    /// idempotent.
    fn acquire_authority(&mut self, row: &AuthorityRow) -> Result<(), StoreError>;

    /// Release an authority (by digest).
    fn release_authority(&mut self, digest: &TypedDigest) -> Result<(), StoreError>;

    /// The active (unreleased) authority, if any.
    fn active_authority(&mut self) -> Result<Option<AuthorityRow>, StoreError>;

    /// Insert or update an action entry.
    fn upsert_action_entry(&mut self, row: &ActionEntryRow) -> Result<(), StoreError>;

    /// Look up an action entry.
    fn lookup_action(&mut self, key: &TypedDigest) -> Result<Option<ActionEntryRow>, StoreError>;

    /// Create a generation. Coordinator-only; the id must be strictly
    /// above the never-reuse high-water mark.
    fn create_generation(
        &mut self,
        authority: &TypedDigest,
        id: u128,
        action_key: &TypedDigest,
    ) -> Result<(), StoreError>;

    /// Create a generation with its full v21 authority binding. Unlike
    /// [`Self::create_generation`], this persists the diagnostic ordinal;
    /// only bound generations may receive live execution leases.
    fn create_bound_generation(
        &mut self,
        authority: &TypedDigest,
        generation: &ActionGeneration,
        action_key: &TypedDigest,
    ) -> Result<(), StoreError>;

    /// Tombstone a generation (the id stays burned forever).
    fn tombstone_generation(&mut self, id: u128) -> Result<(), StoreError>;

    /// G020/R120: on a coordinator term/incarnation change, close every
    /// still-ACTIVE generation created under any authority other than
    /// `active`. Returns how many generations were closed. Idempotent:
    /// already-tombstoned generations are left alone, and the active
    /// authority's own generations are never touched. Publication-eligible
    /// work reissues only in fresh generations minted under `active`
    /// (whose ids sit above the never-reuse high-water mark).
    fn close_generations_for_other_authorities(
        &mut self,
        active: &TypedDigest,
    ) -> Result<u64, StoreError>;

    /// Record an attempt without granting an execution lease (append-only;
    /// duplicate id is an error). This observational/recovery seam leaves
    /// the v21 authority-binding columns NULL, so the row can never pass a
    /// lease or publication gate. Live admission must use
    /// [`Self::admit_attempt_lease`].
    fn record_attempt(
        &mut self,
        id: u128,
        generation: u128,
        worker: &str,
        seq: u64,
    ) -> Result<(), StoreError>;

    /// Atomically record an attempt and acquire its execution lease after
    /// validating the full authority, generation, and exact active,
    /// non-ambiguous worker tuple.
    fn admit_attempt_lease(
        &mut self,
        authority: &AttemptAuthority,
        recorded_seq: u64,
        expires_at_seq: u64,
    ) -> Result<(), StoreError>;

    /// Renew an execution lease after revalidating its normalized
    /// lease-to-attempt link and the attempt's exact current worker fence.
    /// The authority carries the last accepted sequence; `renewal` must
    /// name the same lease and advance it strictly (a durable CAS).
    fn renew_attempt_lease(
        &mut self,
        authority: &AttemptAuthority,
        renewal: LeaseRenewal,
        expires_at_seq: u64,
    ) -> Result<(), StoreError>;

    /// Release a lease.
    fn release_lease(&mut self, id: u128) -> Result<(), StoreError>;

    /// Coordinator-only atomic publication commit (row + serving state +
    /// winner evidence row + reachability pin in ONE transaction;
    /// conflicts quarantine). Live offer admission supplies
    /// a sealed [`PublicationPermit`] so the exact lease and worker fence
    /// are revalidated inside this same transaction. Production permits
    /// are constructible only from a full [`AttemptAuthority`].
    fn commit_publication(
        &mut self,
        permit: PublicationPermit<'_>,
        row: &PublicationRow,
    ) -> Result<CommitOutcome, StoreError>;

    /// Append an evidence-bundle association for an action, bound to the
    /// canonical result manifest (digest key) the evidence supports
    /// (H029; I37). Append-only and first-writer-wins: re-appending the
    /// same evidence digest is an idempotent no-op that NEVER rewrites
    /// the original (manifest, generation, attempt) attribution.
    fn append_evidence(
        &mut self,
        action: &TypedDigest,
        manifest_key: &str,
        evidence: &TypedDigest,
        generation: u128,
        attempt: u128,
    ) -> Result<(), StoreError>;

    /// Whether a publication row exists for an action key.
    fn has_publication(&mut self, action: &TypedDigest) -> Result<bool, StoreError>;

    /// The committed manifest digest key for an action, if published.
    fn published_manifest_key(
        &mut self,
        action: &TypedDigest,
    ) -> Result<Option<String>, StoreError>;

    /// [`Self::published_manifest_key`] addressed by the action's digest
    /// KEY string (H028 transitive walk: recorded lineage rows carry
    /// keys, not typed digests — R121).
    fn published_manifest_key_str(
        &mut self,
        action_key: &str,
    ) -> Result<Option<String>, StoreError>;

    /// Whether a generation exists, and whether it is tombstoned.
    fn generation_state(&mut self, id: u128) -> Result<Option<GenerationState>, StoreError>;

    /// Whether an attempt exists under the given generation.
    fn attempt_exists(&mut self, id: u128, generation: u128) -> Result<bool, StoreError>;

    /// Lease state (released flag + last renewal), if the lease exists.
    fn lease_state(&mut self, id: u128) -> Result<Option<LeaseState>, StoreError>;

    /// Revalidate one authority-bearing attempt/lease against the durable
    /// normalized binding and the worker's current non-ambiguous fence.
    /// The returned state belongs to this exact attempt and lease.
    fn validate_attempt_lease(
        &mut self,
        authority: &AttemptAuthority,
    ) -> Result<LeaseState, StoreError>;

    /// Whether an object has at least one recorded location.
    fn object_located(&mut self, object: &TypedDigest) -> Result<bool, StoreError>;

    /// Every NON-QUARANTINED stored copy of an object, as
    /// `(store_path, encoding, durable)`, ordered by path so the answer
    /// is stable. A reader (materialization, manifest reload) needs the
    /// path, not just the boolean — and must never be handed a
    /// quarantined copy, which is exactly why this filters the same way
    /// [`RabsMetadataStore::object_located`] does.
    fn object_locations(
        &mut self,
        object: &TypedDigest,
    ) -> Result<Vec<(String, String, bool)>, StoreError>;

    /// Record object metadata (digest + logical size; never bytes).
    fn record_object(&mut self, id: &TypedDigest, logical_size: u64) -> Result<(), StoreError>;

    /// Record a stored location for an object. `encoding` names the
    /// stored representation of this COPY (location evidence — it never
    /// changes the object's logical identity). `durable` states whether
    /// this copy satisfied the FULL durability policy (file + directory
    /// fsync) when recorded (H032) — a claim about THIS copy, never
    /// inferred.
    fn add_location(
        &mut self,
        object: &TypedDigest,
        store_path: &str,
        verified_seq: Option<u64>,
        encoding: &str,
        durable: bool,
    ) -> Result<(), StoreError>;

    /// Whether the object has at least one durable, non-quarantined
    /// location (H032: the commit-gate durability check).
    fn object_durably_located(&mut self, object: &TypedDigest) -> Result<bool, StoreError>;

    /// Quarantine (or clear quarantine on) one location. Location
    /// quarantine is evidence about a COPY: the object row and its edges
    /// are untouched by construction.
    fn set_location_quarantined(
        &mut self,
        object: &TypedDigest,
        store_path: &str,
        quarantined: bool,
    ) -> Result<(), StoreError>;

    /// Record a reachability edge between two objects.
    fn add_object_edge(
        &mut self,
        parent: &TypedDigest,
        child: &TypedDigest,
        kind: &str,
    ) -> Result<(), StoreError>;

    /// Create a pin with full H010 semantics.
    #[allow(clippy::too_many_arguments)]
    fn create_pin(
        &mut self,
        id: u128,
        root: &TypedDigest,
        owner: &str,
        class: &str,
        expires_at_seq: Option<u64>,
        evidence: Option<&str>,
        durable: bool,
        reason: &str,
    ) -> Result<(), StoreError>;

    /// Renew a pin's lease: `renewal_seq` must be strictly greater than
    /// the stored one; released pins refuse renewal.
    fn renew_pin(&mut self, id: u128, renewal_seq: u64) -> Result<(), StoreError>;

    /// Full pin row by id (H041 lease judgments).
    fn pin_row(&mut self, id: u128) -> Result<Option<PinRow>, StoreError>;

    /// Release a pin; the owner must match.
    fn release_pin(&mut self, id: u128, owner: &str) -> Result<(), StoreError>;

    /// Store the observed-input recipe digest for an action.
    fn put_recipe(&mut self, action: &TypedDigest, recipe: &TypedDigest) -> Result<(), StoreError>;

    /// Store one component of a key breakdown.
    fn put_key_breakdown(
        &mut self,
        action: &TypedDigest,
        component: &str,
        digest: &TypedDigest,
    ) -> Result<(), StoreError>;

    /// Set trust state for an action.
    fn set_trust(
        &mut self,
        action: &TypedDigest,
        state: &str,
        reason: &str,
    ) -> Result<(), StoreError>;

    /// Add a scoped quarantine row.
    fn add_quarantine(
        &mut self,
        scope: QuarantineScope,
        subject: &str,
        reason: &str,
    ) -> Result<(), StoreError>;

    /// Record a verification sample.
    fn record_verification_sample(
        &mut self,
        action: &TypedDigest,
        attempt: u128,
        passed: bool,
        seq: u64,
    ) -> Result<(), StoreError>;

    /// Canonical evidence-ID keys (`domain:hex`) recorded for an action,
    /// sorted (H033 evidence-set input). Keys, not typed digests, so a
    /// fresh process can enumerate history without re-typing domains it
    /// never wrote (R121).
    fn list_evidence_keys(&mut self, action: &TypedDigest) -> Result<Vec<String>, StoreError>;

    /// Canonical evidence-ID keys (`domain:hex`) bound to ONE canonical
    /// result manifest (digest key), sorted (H029; I37). Divergence
    /// candidates' evidence binds to the candidate manifest, so this view
    /// never conflates evidence across same-key candidates.
    fn list_evidence_keys_for_manifest(
        &mut self,
        manifest_key: &str,
    ) -> Result<Vec<String>, StoreError>;

    /// All verification samples recorded for an action, ordered by
    /// (attempt, seq).
    fn list_verification_samples(
        &mut self,
        action: &TypedDigest,
    ) -> Result<Vec<VerificationSampleRow>, StoreError>;

    /// The worker that ran an attempt (addressed by hex id), if the
    /// attempt exists.
    fn attempt_worker_by_hex(&mut self, attempt_hex: &str) -> Result<Option<String>, StoreError>;

    /// Take a GC snapshot (and record the run).
    fn gc_snapshot(&mut self, seq: u64) -> Result<GcSnapshot, StoreError>;

    /// List location rows for reconciliation against the filesystem.
    fn reconciliation_scan(&mut self) -> Result<Vec<ReconciliationRow>, StoreError>;

    /// Remove one location row (GC reclaim). Works on digest KEYS because
    /// GC plans over snapshot keys, never typed digests. Returns whether
    /// a row was removed.
    fn remove_location_by_key(
        &mut self,
        object_key: &str,
        store_path: &str,
    ) -> Result<bool, StoreError>;

    /// Record a planned-vs-actual GC reclaim receipt (H014).
    fn record_gc_receipt(&mut self, receipt: &GcReceiptRow) -> Result<(), StoreError>;

    /// Mark a location with a tombstone (H022 phase 1): idempotent —
    /// re-marking keeps the ORIGINAL grace deadline.
    fn add_gc_tombstone(
        &mut self,
        object_key: &str,
        store_path: &str,
        marked_seq: u64,
        grace_until_seq: u64,
    ) -> Result<(), StoreError>;

    /// Tombstones whose grace window has elapsed at `now_seq`.
    fn due_gc_tombstones(&mut self, now_seq: u64) -> Result<Vec<GcTombstoneRow>, StoreError>;

    /// Remove a tombstone (after unlink, or as a rescue). Returns whether
    /// a row was removed.
    fn remove_gc_tombstone(
        &mut self,
        object_key: &str,
        store_path: &str,
    ) -> Result<bool, StoreError>;

    /// All publications as (action key, pin hex) pairs (H013 integrity
    /// sweep input).
    fn list_publications(&mut self) -> Result<Vec<(String, String)>, StoreError>;

    /// Released flag of a pin addressed by hex id, if it exists.
    fn pin_released_by_hex(&mut self, pin_hex: &str) -> Result<Option<bool>, StoreError>;

    /// Whether a serving-state row exists for an action key.
    fn has_serving_state_key(&mut self, action_key: &str) -> Result<bool, StoreError>;

    /// Whether at least one evidence row exists for an action key.
    fn has_evidence_key(&mut self, action_key: &str) -> Result<bool, StoreError>;

    /// Total authority rows ever recorded (released or not).
    fn authority_count(&mut self) -> Result<u64, StoreError>;

    /// Total generation rows.
    fn generation_count(&mut self) -> Result<u64, StoreError>;

    /// Whether the generation never-reuse high-water mark exists.
    fn has_generation_high_water(&mut self) -> Result<bool, StoreError>;

    /// Retain a published result's projection digests across blob
    /// eviction (H034). Overwrites an existing tombstone for the key.
    fn record_eviction_tombstone(
        &mut self,
        action: &TypedDigest,
        semantic: &TypedDigest,
        observable: &TypedDigest,
        evicted_seq: u64,
    ) -> Result<(), StoreError>;

    /// The retained (semantic, observable) digests for an action, if a
    /// tombstone exists.
    fn eviction_tombstone(
        &mut self,
        action: &TypedDigest,
    ) -> Result<Option<(TypedDigest, TypedDigest)>, StoreError>;

    /// Consume (remove) an eviction tombstone. Returns whether one
    /// existed.
    fn consume_eviction_tombstone(&mut self, action: &TypedDigest) -> Result<bool, StoreError>;

    /// Record a consumed operator-reset generation (H037). The
    /// generation must be strictly greater than every recorded one —
    /// replayed or stale proofs are refused.
    fn record_operator_reset(&mut self, generation: u64, seq: u64) -> Result<(), StoreError>;

    /// Highest consumed operator-reset generation, if any.
    fn highest_operator_reset(&mut self) -> Result<Option<u64>, StoreError>;

    /// Serving disposition for an action key, if a row exists.
    fn serving_disposition_key(&mut self, action_key: &str) -> Result<Option<String>, StoreError>;

    /// Set (insert or overwrite) the serving disposition for an action
    /// key.
    fn set_serving_disposition_key(
        &mut self,
        action_key: &str,
        disposition: &str,
    ) -> Result<(), StoreError>;

    // --- H038: fences, peer high-water, handoffs (authoritative
    // coordination state; writes require the ACTIVE authority) ---

    /// Record the highest authority term observed from a peer. The
    /// high-water is monotone: a lower term is refused as stale, an
    /// equal term is an idempotent no-op.
    fn record_peer_authority_high_water(
        &mut self,
        authority: &TypedDigest,
        peer_id: &str,
        term: u64,
        observed_seq: u64,
    ) -> Result<(), StoreError>;

    /// The recorded (term, `observed_seq`) high-water for a peer, if any.
    fn peer_authority_high_water(
        &mut self,
        peer_id: &str,
    ) -> Result<Option<(u64, u64)>, StoreError>;

    /// Atomically admit a worker session under the active coordinator:
    /// evaluate the durable boot-generation/incarnation fence, advance
    /// it on admission, and append the open session row in the SAME
    /// transaction. Rejections are typed [`WorkerAdmission`] values.
    /// Stale/identity refusals write nothing; clone ambiguity atomically
    /// persists the ambiguity and revokes that worker's live leases while
    /// appending no session row.
    fn admit_worker_session(
        &mut self,
        authority: &TypedDigest,
        offer: &WorkerSessionOffer,
        started_seq: u64,
    ) -> Result<WorkerAdmission, StoreError>;

    /// End the exact admitted worker session and clear the active
    /// incarnation in the SAME transaction. A stale/different session
    /// cannot clear the current incarnation and returns `false`.
    fn release_worker_session(
        &mut self,
        authority: &TypedDigest,
        worker: &PeerId,
        incarnation: WorkerIncarnationId,
        started_seq: u64,
        ended_seq: u64,
    ) -> Result<bool, StoreError>;

    /// The durable worker fence row, if this identity has ever been
    /// admitted.
    fn worker_incarnation_fence(
        &mut self,
        worker: &PeerId,
    ) -> Result<Option<WorkerIncarnationFenceRecord>, StoreError>;

    /// Advance an edge's ordered incarnation fence. A lower incarnation
    /// is refused as stale; equality is an idempotent no-op.
    fn advance_edge_fence(
        &mut self,
        authority: &TypedDigest,
        edge_id: &str,
        incarnation: u128,
    ) -> Result<(), StoreError>;

    /// The fenced incarnation for an edge, if any.
    fn edge_fence(&mut self, edge_id: &str) -> Result<Option<u128>, StoreError>;

    /// Begin an edge handoff: at most ONE unresolved handoff per edge;
    /// the predecessor must be NAMED and must match the edge's fenced
    /// incarnation when a fence exists; the active incarnation must
    /// exceed the predecessor. Identical re-begin is idempotent.
    fn begin_edge_handoff(
        &mut self,
        authority: &TypedDigest,
        edge_id: &str,
        active_incarnation: u128,
        predecessor_incarnation: u128,
        begun_seq: u64,
    ) -> Result<(), StoreError>;

    /// Resolve the unresolved handoff matching (edge, active) and
    /// advance the edge fence to the active incarnation in the SAME
    /// transaction.
    fn resolve_edge_handoff(
        &mut self,
        authority: &TypedDigest,
        edge_id: &str,
        active_incarnation: u128,
    ) -> Result<(), StoreError>;

    /// The unresolved handoff for an edge, if any.
    fn active_edge_handoff(&mut self, edge_id: &str) -> Result<Option<EdgeHandoffRow>, StoreError>;

    // --- H038: versioned trust evaluations (authority-gated ledger) ---

    /// Append a trust evaluation; the version must be strictly greater
    /// than the stored maximum for the action.
    fn append_trust_evaluation(
        &mut self,
        authority: &TypedDigest,
        action: &TypedDigest,
        row: &TrustEvaluationRow,
    ) -> Result<(), StoreError>;

    /// The highest-version trust evaluation for an action, if any.
    fn latest_trust_evaluation(
        &mut self,
        action: &TypedDigest,
    ) -> Result<Option<TrustEvaluationRow>, StoreError>;

    // --- H038: operations (creation is the authoritative admission) ---

    /// Create an operation lifecycle record (coordinator-only;
    /// duplicate ids refused).
    fn create_operation(
        &mut self,
        authority: &TypedDigest,
        id: u128,
        kind: &str,
        state: &str,
        seq: u64,
    ) -> Result<(), StoreError>;

    /// Update an existing operation's state.
    fn update_operation_state(&mut self, id: u128, state: &str, seq: u64)
    -> Result<(), StoreError>;

    /// Current state of an operation, if it exists.
    fn operation_state(&mut self, id: u128) -> Result<Option<String>, StoreError>;

    // --- H038: edge subscribers, manifests, worker records,
    // receipts/audits/provenance, materializations (observational
    // lifecycle; conflicting rewrites are typed refusals, never silent
    // overwrites) ---

    /// Register an edge subscriber. Idempotent: the FIRST registration
    /// sequence wins; re-registration is a no-op.
    fn register_edge_subscriber(
        &mut self,
        edge_id: &str,
        subscriber: &str,
        registered_seq: u64,
    ) -> Result<(), StoreError>;

    /// Remove an edge subscriber. Returns whether a row was removed.
    fn remove_edge_subscriber(
        &mut self,
        edge_id: &str,
        subscriber: &str,
    ) -> Result<bool, StoreError>;

    /// Subscribers registered for an edge, ordered.
    fn list_edge_subscribers(&mut self, edge_id: &str) -> Result<Vec<String>, StoreError>;

    /// Record manifest metadata (digest + kind + entry count; never
    /// manifest bytes). Identical re-record is idempotent; different
    /// content under the same digest is a divergence incident.
    fn record_manifest(
        &mut self,
        manifest: &TypedDigest,
        kind: &str,
        entry_count: u64,
    ) -> Result<(), StoreError>;

    /// Recorded (kind, entry count) for a manifest digest, if any.
    fn manifest_meta(
        &mut self,
        manifest: &TypedDigest,
    ) -> Result<Option<(String, u64)>, StoreError>;

    /// Record a worker session journal row without granting authority.
    /// This is an append-only recovery/fixture seam; live coordinator
    /// admission must use [`Self::admit_worker_session`] so the fence and
    /// journal change atomically. A conflicting rewrite of the same
    /// (worker, start) is refused.
    fn record_worker_session(
        &mut self,
        worker: &str,
        incarnation: u128,
        started_seq: u64,
    ) -> Result<(), StoreError>;

    /// Mark only the journal row ended; this does not clear an active
    /// authority fence. Live teardown must use
    /// [`Self::release_worker_session`]. Returns whether an open session
    /// row was updated.
    fn end_worker_session(
        &mut self,
        worker: &str,
        started_seq: u64,
        ended_seq: u64,
    ) -> Result<bool, StoreError>;

    /// Record a worker capability (idempotent).
    fn record_worker_capability(
        &mut self,
        worker: &str,
        capability: &str,
    ) -> Result<(), StoreError>;

    /// Capabilities recorded for a worker, ordered.
    fn list_worker_capabilities(&mut self, worker: &str) -> Result<Vec<String>, StoreError>;

    /// Record a worker health sample (append-only; conflicting rewrite
    /// refused).
    fn record_worker_health_sample(
        &mut self,
        worker: &str,
        seq: u64,
        healthy: bool,
        detail: &str,
    ) -> Result<(), StoreError>;

    /// Record a decision receipt (append-only; conflicting rewrite
    /// refused).
    fn record_decision_receipt(
        &mut self,
        kind: &str,
        subject: &str,
        seq: u64,
        decision: &str,
        reason: &str,
    ) -> Result<(), StoreError>;

    /// Record a provenance edge between two digests (idempotent).
    fn add_provenance_edge(
        &mut self,
        from: &TypedDigest,
        to: &TypedDigest,
        kind: &str,
    ) -> Result<(), StoreError>;

    /// Record a determinism-audit verdict (append-only; conflicting
    /// rewrite refused).
    fn record_determinism_audit(
        &mut self,
        action: &TypedDigest,
        attempt: u128,
        seq: u64,
        verdict: &str,
    ) -> Result<(), StoreError>;

    /// Create a materialization record. Identical re-create is
    /// idempotent; a different-content duplicate id is refused.
    fn create_materialization(
        &mut self,
        id: u128,
        root: &TypedDigest,
        dest_path: &str,
        state: &str,
        seq: u64,
    ) -> Result<(), StoreError>;

    /// Update an existing materialization's state.
    fn update_materialization_state(
        &mut self,
        id: u128,
        state: &str,
        seq: u64,
    ) -> Result<(), StoreError>;

    /// Current state of a materialization record, if it exists.
    fn materialization_state(&mut self, id: u128) -> Result<Option<String>, StoreError>;

    // --- H040: revisioned authority-bound serving state ---

    /// Write a serving-state record in ONE transaction: the revision
    /// must be strictly greater than the stored one (legacy rows are
    /// revision 0, so H040 records start at 1); every named blocking
    /// quarantine must exist; the record is stamped with the ACTIVE
    /// authority's digest key. The junction reference set is replaced
    /// atomically with the row.
    fn put_serving_record(
        &mut self,
        authority: &TypedDigest,
        action_key: &str,
        disposition: &str,
        state_revision: u64,
        validity: &ServingValidity,
        blocking: &[(QuarantineScope, String)],
    ) -> Result<(), StoreError>;

    /// The full serving record for an action key, if a row exists
    /// (legacy rows read back at revision 0 with defaults).
    fn serving_record(&mut self, action_key: &str) -> Result<Option<ServingRecordRow>, StoreError>;

    // --- H026: same-key divergence incidents + served-consumer
    // provenance (append-only; coordinator-authority-gated writes) ---

    /// Append a divergence incident (H026). Requires the ACTIVE
    /// authority. Identical re-record of an existing (action, seq) row is
    /// idempotent; a conflicting rewrite is a typed refusal — incidents
    /// are never patched.
    fn record_divergence_incident(
        &mut self,
        authority: &TypedDigest,
        row: &DivergenceIncidentRow,
    ) -> Result<(), StoreError>;

    /// All divergence incidents recorded for an action key, ordered by
    /// sequence.
    fn list_divergence_incidents(
        &mut self,
        action_key: &str,
    ) -> Result<Vec<DivergenceIncidentRow>, StoreError>;

    /// Record an explicit adoption edge (H028): the coordinator's
    /// authority-gated declaration that `from_object_key` (a consumed
    /// losing-attempt output) is compatible with `to_object_key` (the
    /// winning attempt's committed object) for the producer's
    /// `(role, virtual_path)` logical output. Idempotent per
    /// (producer, role, path, from) — a conflicting rewrite to a
    /// DIFFERENT target is a typed refusal.
    fn record_adoption_edge(
        &mut self,
        authority: &TypedDigest,
        producer_action_key: &str,
        role: &str,
        virtual_path: &[u8],
        from_object_key: &str,
        to_object_key: &str,
    ) -> Result<(), StoreError>;

    /// Whether an adoption edge exists for exactly this
    /// (producer, role, path, from → to) tuple (H028 commit check).
    fn has_adoption_edge(
        &mut self,
        producer_action_key: &str,
        role: &str,
        virtual_path: &[u8],
        from_object_key: &str,
        to_object_key: &str,
    ) -> Result<bool, StoreError>;
    /// Record (idempotently) that a dependent attempt consumed a
    /// provisional output, creating its DirectProducerCommit obligation
    /// (M006). Repeat reads of the same output by the same attempt do not
    /// duplicate the row.
    fn record_provisional_consumption(
        &mut self,
        consumption: &ProvisionalObligationInsert,
    ) -> Result<(), StoreError>;

    /// All NON-resolved obligations of one consumer attempt, ordered by
    /// (status, pin key): `open` rows block terminal paths, `cancelled`
    /// rows refuse them.
    fn list_open_provisional_obligations(
        &mut self,
        consumer_worker: &str,
        consumer_attempt_hex: &str,
    ) -> Result<Vec<ProvisionalObligationRow>, StoreError>;

    /// Resolve every open obligation on one pin (producer committed /
    /// adoption satisfied the lineage); returns how many rows resolved.
    fn resolve_provisional_obligations(
        &mut self,
        pin_key: &str,
        resolution_object_key: &str,
    ) -> Result<usize, StoreError>;

    /// Cancel every open obligation on one pin (producer lineage failed /
    /// superseded / lost authority); returns how many rows cancelled.
    fn cancel_provisional_obligations(&mut self, pin_key: &str) -> Result<usize, StoreError>;

    /// Number of OPEN (unresolved, uncancelled) obligations on one pin —
    /// the consumer-debt figure the §65 drain/GC rule gates on.
    fn count_open_provisional_obligations(&mut self, pin_key: &str) -> Result<usize, StoreError>;

    /// Record (idempotently) one provisional output installed to a real
    /// path before lineage closure (M019/R86). The journal is the
    /// ownership truth for recovery: paths absent from it are never
    /// touched.
    fn insert_provisional_install(
        &mut self,
        install: &ProvisionalInstallInsert,
    ) -> Result<(), StoreError>;

    /// Journal rows for the given pins, ANY state, ordered by
    /// (pin key, attempt, path) — the recovery sweep's input.
    fn list_provisional_installs_for_pins(
        &mut self,
        pin_keys: &[String],
    ) -> Result<Vec<ProvisionalInstallRecord>, StoreError>;

    /// Journal rows in ONE state (e.g. `dirty` for the Cargo
    /// revalidation audit), ordered by (pin key, attempt, path).
    fn list_provisional_installs_by_state(
        &mut self,
        state: &str,
    ) -> Result<Vec<ProvisionalInstallRecord>, StoreError>;

    /// Transition one journal row's state (`installed` → `removed` |
    /// `dirty`). Unknown rows are a typed error — recovery never
    /// invents bookkeeping.
    fn set_provisional_install_state(
        &mut self,
        pin_key: &str,
        consumer_attempt_hex: &str,
        installed_path: &[u8],
        state: &str,
    ) -> Result<(), StoreError>;

    /// Bind native child actions to a parent build-script action
    /// (L008). Idempotent per (parent, child); children are appended to
    /// any existing set.
    fn bind_native_children(
        &mut self,
        parent_action_key: &str,
        child_action_keys: &[String],
        bound_seq: u64,
    ) -> Result<(), StoreError>;

    /// All native child bindings of one parent action with their
    /// states (`bound` | `satisfied`), ordered by child key.
    fn list_native_child_bindings(
        &mut self,
        parent_action_key: &str,
    ) -> Result<Vec<(String, String)>, StoreError>;

    /// Transition one binding's state (`bound` → `satisfied`). Unknown
    /// rows are a typed error.
    fn set_native_child_binding_state(
        &mut self,
        parent_action_key: &str,
        child_action_key: &str,
        state: &str,
    ) -> Result<(), StoreError>;
    /// Open provisional pins minted by ONE action generation (M007
    /// generation-failure invalidation trigger), ordered by pin key.
    fn list_open_provisional_pins_for_action_generation(
        &mut self,
        action_key: &str,
        generation_hex: &str,
    ) -> Result<Vec<ProvisionalPinRecord>, StoreError>;

    /// Open provisional pins of an action across ALL generations (M007
    /// supersession trigger), ordered by pin key.
    fn list_open_provisional_pins_for_action(
        &mut self,
        action_key: &str,
    ) -> Result<Vec<ProvisionalPinRecord>, StoreError>;

    /// Open provisional pins minted under one coordinator authority
    /// (M007 authority-loss trigger), ordered by pin key.
    fn list_open_provisional_pins_for_authority(
        &mut self,
        authority_key: &str,
    ) -> Result<Vec<ProvisionalPinRecord>, StoreError>;

    /// ALL consumption obligations on one pin — every status — the M007
    /// causal-trace record of which dependents started from this output.
    fn list_provisional_obligations_for_pin(
        &mut self,
        pin_key: &str,
    ) -> Result<Vec<ProvisionalObligationRow>, StoreError>;

    /// Ancestor pin keys of one provisional pin with their min-hop
    /// distances (M017/M020): the materialized transitive closure
    /// recorded at open time, ordered by key.
    fn list_provisional_pin_ancestors(
        &mut self,
        descendant_pin_key: &str,
    ) -> Result<Vec<(String, u64)>, StoreError>;

    /// Longest min-hop chain in one pin's recorded closure — the pin's
    /// transitive lineage depth (M020/I025). Zero for a root producer.
    fn provisional_pin_closure_depth(
        &mut self,
        descendant_pin_key: &str,
    ) -> Result<u64, StoreError>;

    /// Descendant pin keys whose recorded closure contains this pin
    /// (M017) — the reverse edge that makes lineage invalidation cascade
    /// transitively. Ordered by key.
    fn list_provisional_pin_descendants(
        &mut self,
        ancestor_pin_key: &str,
    ) -> Result<Vec<String>, StoreError>;

    /// All NON-resolved obligations of ONE consuming attempt regardless
    /// of worker (M017): attempt ids are globally unique, so lineage
    /// closure walks key on the attempt alone. Ordered by pin key.
    fn list_open_provisional_obligations_by_attempt(
        &mut self,
        consumer_attempt_hex: &str,
    ) -> Result<Vec<ProvisionalObligationRow>, StoreError>;

    /// ALL obligations of ONE consuming attempt regardless of worker or
    /// status (M020): the terminal-delivery gate verifies each row's
    /// final state, including that `resolved` rows resolved to the EXACT
    /// consumed object. Ordered by (status, pin key).
    fn list_provisional_obligations_by_attempt_all(
        &mut self,
        consumer_attempt_hex: &str,
    ) -> Result<Vec<ProvisionalObligationRow>, StoreError>;

    /// The recorded provisional-ancestor lineage of a committed consumer
    /// (H028), ordered by (producer, role, path) — input to the
    /// transitive closure walk at a dependent's commit.
    fn list_provisional_ancestors(
        &mut self,
        consumer_action_key: &str,
    ) -> Result<Vec<ProvisionalAncestorRow>, StoreError>;

    /// One provisional-upload pin row by canonical key (M004).
    fn provisional_pin_row(
        &mut self,
        pin_key: &str,
    ) -> Result<Option<ProvisionalPinRecord>, StoreError>;

    /// Register a provisional-upload pin AND its protective `pins` row in
    /// ONE transaction (M004): the object is GC-safe from the instant the
    /// registry row exists, and no tear can leave one without the other.
    fn insert_provisional_pin(&mut self, pin: &ProvisionalPinInsert) -> Result<(), StoreError>;

    /// Grant one reader visibility of a provisional output (M004). The
    /// grant table IS the authorization truth; readers absent from it are
    /// refused.
    fn record_provisional_grant(
        &mut self,
        pin_key: &str,
        grantee_kind: &str,
        grantee_id: &str,
        granted_seq: u64,
    ) -> Result<(), StoreError>;

    /// Grants of one provisional pin, ordered by (kind, id).
    fn list_provisional_grants(
        &mut self,
        pin_key: &str,
    ) -> Result<Vec<(String, String, u64)>, StoreError>;

    /// Monotonically renew a provisional pin's sequence; refuses closed
    /// pins and stale sequences.
    fn renew_provisional_pin(&mut self, pin_key: &str, renewal_seq: u64) -> Result<(), StoreError>;

    /// Close a provisional pin: mark it released (recording WHY when the
    /// producer lineage failed/superseded/lost authority) so reads refuse
    /// immediately. Closing happens BEFORE the protective pin is released
    /// by the caller — a tear between the two fails toward retention.
    fn close_provisional_pin(
        &mut self,
        pin_key: &str,
        invalidation_reason: Option<&str>,
    ) -> Result<(), StoreError>;

    /// Record a winner adoption (§65.1) on a provisional pin. Callers
    /// MUST have verified exact-object compatibility first; this only
    /// persists the resolution.
    fn adopt_provisional_pin(
        &mut self,
        pin_key: &str,
        committed_object_key: &str,
    ) -> Result<(), StoreError>;
    /// Record that a consumer was served this action's published result
    /// (a `served-to` provenance edge; idempotent). This is what H026
    /// escalation later enumerates — serving paths must call it when they
    /// hand a result to a consumer.
    fn record_served_consumer(
        &mut self,
        action_key: &str,
        consumer: &str,
    ) -> Result<(), StoreError>;

    /// Consumers previously served this action's result, from `served-to`
    /// provenance edges, ordered.
    fn list_served_consumers(&mut self, action_key: &str) -> Result<Vec<String>, StoreError>;

    /// Deterministic dump of every table for differential comparison.
    fn differential_snapshot(&mut self) -> Result<Vec<String>, StoreError>;
}

// ---------------------------------------------------------------------
// SQL engine abstraction: one store logic, two engines.
// ---------------------------------------------------------------------

/// A bound SQL value (the subset the schema uses; floats deliberately
/// excluded from authoritative metadata).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SqlValue {
    /// SQL NULL.
    Null,
    /// 64-bit integer.
    Int(i64),
    /// UTF-8 text.
    Text(String),
    /// Byte blob.
    Blob(Vec<u8>),
}

/// Minimal SQL engine surface the store needs. `?1..?N` placeholders.
pub trait SqlEngine {
    /// Execute a statement; returns affected-row count.
    fn execute(&mut self, sql: &str, params: &[SqlValue]) -> Result<usize, StoreError>;
    /// Run a query; returns all rows.
    fn query(&mut self, sql: &str, params: &[SqlValue]) -> Result<Vec<Vec<SqlValue>>, StoreError>;
}

/// The generic SQL-backed store.
pub struct SqlMetadataStore<E: SqlEngine> {
    engine: E,
    /// Domains this process has written, interned so reads can restore
    /// `&'static str` domains fail-closed (R121).
    domains: HashMap<String, &'static str>,
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Canonical `domain:hex` key for a typed digest (table keys/joins).
#[must_use]
pub fn digest_key(d: &TypedDigest) -> String {
    format!("{}:{}", d.domain, hex(&d.bytes))
}

const fn algo_tag(a: DigestAlgorithm) -> &'static str {
    match a {
        DigestAlgorithm::Sha256V1 => "sha256-v1",
    }
}

fn u128_blob(v: u128) -> Vec<u8> {
    v.to_be_bytes().to_vec()
}

fn u64_blob(v: u64) -> Vec<u8> {
    v.to_be_bytes().to_vec()
}

fn u128_hex(v: u128) -> String {
    hex(&v.to_be_bytes())
}

impl<E: SqlEngine> SqlMetadataStore<E> {
    /// Open the store over an engine, applying pending migrations
    /// transactionally.
    pub fn open(engine: E) -> Result<Self, StoreError> {
        let mut store = Self {
            engine,
            domains: HashMap::new(),
        };
        store.apply_migrations()?;
        Ok(store)
    }

    /// Highest durable operation update sequence, clamped to the initial
    /// sequence floor used by operator tooling.
    ///
    /// This narrow query keeps cross-crate diagnostics from receiving a
    /// mutable SQL escape hatch around authority and clone fencing.
    pub fn operation_update_high_water(&mut self) -> Result<u64, StoreError> {
        let rows = self
            .engine
            .query("SELECT COALESCE(MAX(updated_seq), 1) FROM operations", &[])?;
        let [row] = rows.as_slice() else {
            return Err(StoreError::Corruption(
                "operation update high-water row count".into(),
            ));
        };
        let [value] = row.as_slice() else {
            return Err(StoreError::Corruption(
                "operation update high-water shape".into(),
            ));
        };
        Ok(expect_u64(value, "operation update high-water")?.max(1))
    }

    /// Crate-internal engine access for reconciliation, authority-gate,
    /// crash-injection, and corruption fixtures. External callers cannot
    /// bypass the transactional metadata API with arbitrary SQL.
    pub(crate) fn engine_mut(&mut self) -> &mut E {
        &mut self.engine
    }

    fn apply_migrations(&mut self) -> Result<(), StoreError> {
        let applied: u32 = {
            let has_epochs = !self
                .engine
                .query(
                    "SELECT name FROM sqlite_master WHERE type = 'table' \
                     AND name = 'schema_epochs'",
                    &[],
                )?
                .is_empty();
            if has_epochs {
                let rows = self
                    .engine
                    .query("SELECT MAX(version) FROM schema_epochs", &[])?;
                match rows.first().and_then(|r| r.first()) {
                    Some(SqlValue::Int(v)) => u32::try_from(*v)
                        .map_err(|_| StoreError::Corruption("negative schema version".into()))?,
                    _ => 0,
                }
            } else {
                0
            }
        };
        for migration in MIGRATIONS {
            if migration.version <= applied {
                continue;
            }
            self.engine.execute("BEGIN", &[])?;
            let mut apply = || -> Result<(), StoreError> {
                for statement in migration.statements {
                    self.engine.execute(statement, &[])?;
                }
                self.engine.execute(
                    "INSERT INTO schema_epochs (version, applied_seq) VALUES (?1, ?2)",
                    &[
                        SqlValue::Int(i64::from(migration.version)),
                        SqlValue::Int(0),
                    ],
                )?;
                Ok(())
            };
            match apply() {
                Ok(()) => {
                    self.engine.execute("COMMIT", &[])?;
                }
                Err(e) => {
                    let _ = self.engine.execute("ROLLBACK", &[]);
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    fn intern(&mut self, domain: &'static str) {
        self.domains.entry(domain.to_owned()).or_insert(domain);
    }

    fn restore_domain(&self, domain: &str) -> Result<&'static str, StoreError> {
        self.domains
            .get(domain)
            .copied()
            .ok_or_else(|| StoreError::DomainNotInterned(domain.to_owned()))
    }

    fn restore_digest(
        &self,
        algo: &SqlValue,
        domain: &SqlValue,
        bytes: &SqlValue,
    ) -> Result<TypedDigest, StoreError> {
        let (SqlValue::Text(algo), SqlValue::Text(domain), SqlValue::Blob(bytes)) =
            (algo, domain, bytes)
        else {
            return Err(StoreError::Corruption("digest column shape".into()));
        };
        if algo != "sha256-v1" {
            return Err(StoreError::Corruption(format!("unknown algorithm {algo}")));
        }
        let bytes: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::Corruption("digest not 32 bytes".into()))?;
        Ok(TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: self.restore_domain(domain)?,
            bytes,
        })
    }

    fn create_bound_generation(
        &mut self,
        authority: &TypedDigest,
        generation: &ActionGeneration,
        action_key: &TypedDigest,
    ) -> Result<(), StoreError> {
        if generation.created_under_authority_digest != *authority {
            return Err(StoreError::AttemptAuthorityMismatch);
        }
        let authority = authority.clone();
        let action = digest_key(action_key);
        let generation = generation.clone();
        self.in_txn(move |engine| {
            SqlMetadataStore::<E>::require_active(engine, &authority)?;
            let id = generation.generation_id.0;
            let high_water = SqlMetadataStore::<E>::generation_high_water(engine)?;
            if id <= high_water {
                return Err(StoreError::GenerationIdNotAboveHighWater);
            }
            engine.execute(
                "INSERT INTO action_generations \
                 (id_hex, id, action_key, authority_key, tombstoned, per_key_ordinal) \
                 VALUES (?1, ?2, ?3, ?4, 0, ?5)",
                &[
                    SqlValue::Text(u128_hex(id)),
                    SqlValue::Blob(u128_blob(id)),
                    SqlValue::Text(action),
                    SqlValue::Text(digest_key(&authority)),
                    SqlValue::Blob(u64_blob(generation.per_key_ordinal)),
                ],
            )?;
            engine.execute(
                "INSERT OR REPLACE INTO generation_high_water (kind, value) \
                 VALUES ('action-generation', ?1)",
                &[SqlValue::Blob(u128_blob(id))],
            )?;
            Ok(())
        })
    }

    fn digest_params(d: &TypedDigest) -> [SqlValue; 3] {
        [
            SqlValue::Text(algo_tag(d.algorithm).to_owned()),
            SqlValue::Text(d.domain.to_owned()),
            SqlValue::Blob(d.bytes.to_vec()),
        ]
    }

    fn in_txn<T>(
        &mut self,
        body: impl FnOnce(&mut E) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        self.engine.execute("BEGIN", &[])?;
        match body(&mut self.engine) {
            Ok(v) => {
                self.engine.execute("COMMIT", &[])?;
                Ok(v)
            }
            Err(e) => {
                let _ = self.engine.execute("ROLLBACK", &[]);
                Err(e)
            }
        }
    }

    fn active_authority_key(engine: &mut E) -> Result<Option<String>, StoreError> {
        let rows = engine.query(
            "SELECT key FROM coordinator_authorities WHERE released = 0",
            &[],
        )?;
        match rows.as_slice() {
            [] => Ok(None),
            [row] => match row.first() {
                Some(SqlValue::Text(k)) => Ok(Some(k.clone())),
                _ => Err(StoreError::Corruption("authority key shape".into())),
            },
            _ => Err(StoreError::Corruption(
                "more than one active authority".into(),
            )),
        }
    }

    fn require_active(engine: &mut E, authority: &TypedDigest) -> Result<(), StoreError> {
        match Self::active_authority_key(engine)? {
            Some(active) if active == digest_key(authority) => Ok(()),
            _ => Err(StoreError::NotActiveAuthority),
        }
    }

    fn attempt_authority_digest(authority: &AttemptAuthority) -> TypedDigest {
        rabs_key::authority_binding::coordinator_authority_digest(&authority.coordinator)
    }

    fn require_attempt_context(
        engine: &mut E,
        authority: &AttemptAuthority,
    ) -> Result<TypedDigest, StoreError> {
        let coordinator = Self::attempt_authority_digest(authority);
        Self::require_active(engine, &coordinator)?;
        if authority.action_generation.created_under_authority_digest != coordinator {
            return Err(StoreError::AttemptAuthorityMismatch);
        }
        let rows = engine.query(
            "SELECT action_key, authority_key, tombstoned, per_key_ordinal \
             FROM action_generations WHERE id_hex = ?1",
            &[SqlValue::Text(u128_hex(
                authority.action_generation.generation_id.0,
            ))],
        )?;
        let Some(row) = rows.first() else {
            return Err(StoreError::UnknownGeneration);
        };
        if rows.len() != 1 {
            return Err(StoreError::Corruption(
                "duplicate action generation rows".into(),
            ));
        }
        let [action_key, authority_key, tombstoned, ordinal] = row.as_slice() else {
            return Err(StoreError::Corruption(
                "action generation binding shape".into(),
            ));
        };
        if expect_u64(tombstoned, "generation tombstoned")? != 0 {
            return Err(StoreError::GenerationTombstoned);
        }
        let stored_ordinal = match ordinal {
            SqlValue::Null => return Err(StoreError::LegacyUnboundAuthority),
            value => expect_u64_blob(value, "generation ordinal")?,
        };
        if expect_text(action_key, "generation action key")? != digest_key(&authority.action_key)
            || expect_text(authority_key, "generation authority")? != digest_key(&coordinator)
            || stored_ordinal != authority.action_generation.per_key_ordinal
        {
            return Err(StoreError::AttemptAuthorityMismatch);
        }
        Ok(coordinator)
    }

    fn require_worker_lease_binding(
        engine: &mut E,
        worker: &PeerId,
        boot_generation: WorkerBootGeneration,
        incarnation: WorkerIncarnationId,
    ) -> Result<(), StoreError> {
        let rows = engine.query(
            "SELECT highest_boot_generation, incarnation, active, \
             operator_reenrollment_generation, clone_ambiguous \
             FROM worker_incarnation_fences WHERE worker = ?1",
            &[SqlValue::Text(worker.0.clone())],
        )?;
        let Some(row) = rows.first() else {
            return Err(StoreError::UnknownWorkerFence);
        };
        if rows.len() != 1 {
            return Err(StoreError::Corruption("duplicate worker fence rows".into()));
        }
        let fence = decode_worker_incarnation_fence(&worker.0, row)?;
        fence
            .validate_lease_binding(worker, boot_generation, incarnation)
            .map_err(StoreError::WorkerLeaseRejected)
    }

    fn revoke_worker_leases(engine: &mut E, worker: &str) -> Result<(), StoreError> {
        engine.execute(
            "UPDATE execution_leases SET released = 1 \
             WHERE released = 0 AND attempt_hex IN \
             (SELECT id_hex FROM action_attempts WHERE worker = ?1)",
            &[SqlValue::Text(worker.to_owned())],
        )?;
        Ok(())
    }

    fn bound_lease_state(
        engine: &mut E,
        authority: &AttemptAuthority,
    ) -> Result<LeaseState, StoreError> {
        Self::require_attempt_context(engine, authority)?;
        let rows = engine.query(
            "SELECT l.attempt_hex, l.released, l.renewal_seq, \
                    a.generation_hex, a.worker, a.worker_boot_generation, \
                    a.worker_incarnation, a.execution_lease_hex \
             FROM execution_leases l \
             LEFT JOIN action_attempts a ON a.id_hex = l.attempt_hex \
             WHERE l.id_hex = ?1",
            &[SqlValue::Text(u128_hex(authority.execution_lease_id.0))],
        )?;
        let Some(row) = rows.first() else {
            return Err(StoreError::UnknownLease);
        };
        if rows.len() != 1 {
            return Err(StoreError::Corruption(
                "duplicate execution lease rows".into(),
            ));
        }
        let [
            attempt_hex,
            released,
            renewal_seq,
            generation_hex,
            worker,
            boot,
            incarnation,
            attempt_lease_hex,
        ] = row.as_slice()
        else {
            return Err(StoreError::Corruption("bound lease row shape".into()));
        };
        if expect_text(attempt_hex, "lease attempt")? != u128_hex(authority.attempt_id.0) {
            return Err(StoreError::LeaseAttemptMismatch);
        }
        let (stored_boot, stored_incarnation, stored_attempt_lease) =
            match (boot, incarnation, attempt_lease_hex) {
                (SqlValue::Null, _, _) | (_, SqlValue::Null, _) | (_, _, SqlValue::Null) => {
                    return Err(StoreError::LegacyUnboundAuthority);
                }
                (boot, incarnation, attempt_lease) => (
                    expect_u64_blob(boot, "attempt worker boot generation")?,
                    expect_u128(incarnation, "attempt worker incarnation")?,
                    expect_text(attempt_lease, "attempt execution lease")?,
                ),
            };
        if expect_text(generation_hex, "attempt generation")?
            != u128_hex(authority.action_generation.generation_id.0)
            || expect_text(worker, "attempt worker")? != authority.worker_peer_id.0
            || stored_boot != authority.worker_boot_generation.0
            || stored_incarnation != authority.worker_incarnation_id.0
            || stored_attempt_lease != u128_hex(authority.execution_lease_id.0)
        {
            return Err(StoreError::AttemptAuthorityMismatch);
        }
        Self::require_worker_lease_binding(
            engine,
            &authority.worker_peer_id,
            authority.worker_boot_generation,
            authority.worker_incarnation_id,
        )?;
        Ok(LeaseState {
            released: expect_u64(released, "released")? != 0,
            renewal_seq: expect_u64(renewal_seq, "renewal_seq")?,
        })
    }

    fn generation_high_water(engine: &mut E) -> Result<u128, StoreError> {
        let rows = engine.query(
            "SELECT value FROM generation_high_water WHERE kind = 'action-generation'",
            &[],
        )?;
        match rows.first().and_then(|r| r.first()) {
            None => Ok(0),
            Some(SqlValue::Blob(b)) => {
                let bytes: [u8; 16] = b
                    .as_slice()
                    .try_into()
                    .map_err(|_| StoreError::Corruption("high-water not 16 bytes".into()))?;
                Ok(u128::from_be_bytes(bytes))
            }
            Some(_) => Err(StoreError::Corruption("high-water shape".into())),
        }
    }

    /// Shared row mapper for `provisional_pins` SELECTs (single source of
    /// truth for the 19-column shape; R121 domain restore included).
    fn map_provisional_pin_row(
        &self,
        row: &[SqlValue],
    ) -> Result<ProvisionalPinRecord, StoreError> {
        let [
            pin,
            authority,
            action,
            generation,
            attempt,
            lease,
            role,
            path,
            algo,
            domain,
            bytes,
            object,
            protective,
            renewal,
            adopted,
            invalidation,
            released,
            toolchain_contract,
            event_contract,
        ] = row
        else {
            return Err(StoreError::Corruption("provisional pin shape".into()));
        };
        Ok(ProvisionalPinRecord {
            pin_key: expect_text(pin, "provisional pin key")?,
            authority_key: expect_text(authority, "provisional authority")?,
            action_key: expect_text(action, "provisional action")?,
            generation_hex: expect_text(generation, "provisional generation")?,
            attempt_hex: expect_text(attempt, "provisional attempt")?,
            lease_hex: expect_text(lease, "provisional lease")?,
            role_tag: match role {
                SqlValue::Int(v) => *v,
                _ => return Err(StoreError::Corruption("provisional role shape".into())),
            },
            virtual_path: match path {
                SqlValue::Blob(b) => b.clone(),
                _ => return Err(StoreError::Corruption("provisional path shape".into())),
            },
            object: self.restore_digest(algo, domain, bytes)?,
            object_key: expect_text(object, "provisional object")?,
            protective_pin_hex: expect_text(protective, "provisional protective pin")?,
            renewal_seq: expect_u64(renewal, "provisional renewal")?,
            adopted_object_key: expect_opt_text(adopted, "provisional adoption")?,
            invalidated_reason: expect_opt_text(invalidation, "provisional invalidation")?,
            released: expect_u64(released, "provisional released")? != 0,
            toolchain_contract_key: expect_text(
                toolchain_contract,
                "provisional toolchain contract",
            )?,
            event_contract_key: expect_text(event_contract, "provisional event contract")?,
        })
    }

    /// Shared row mapper for `provisional_obligations` SELECTs (single
    /// source of truth for the 12-column shape).
    fn map_obligation_row(row: &[SqlValue]) -> Result<ProvisionalObligationRow, StoreError> {
        let [
            worker,
            attempt_hex,
            pin,
            action,
            generation,
            producer,
            role,
            path,
            object,
            status,
            resolution,
            created,
        ] = row
        else {
            return Err(StoreError::Corruption("obligation row shape".into()));
        };
        Ok(ProvisionalObligationRow {
            consumer_worker: expect_text(worker, "obligation worker")?,
            consumer_attempt_hex: expect_text(attempt_hex, "obligation attempt")?,
            pin_key: expect_text(pin, "obligation pin")?,
            producer_action_key: expect_text(action, "obligation action")?,
            producer_generation_hex: expect_text(generation, "obligation generation")?,
            producer_attempt_hex: expect_text(producer, "obligation producer")?,
            role_tag: match role {
                SqlValue::Int(v) => *v,
                _ => return Err(StoreError::Corruption("obligation role shape".into())),
            },
            virtual_path: match path {
                SqlValue::Blob(b) => b.clone(),
                _ => return Err(StoreError::Corruption("obligation path shape".into())),
            },
            object_key: expect_text(object, "obligation object")?,
            status: expect_text(status, "obligation status")?,
            resolution_object_key: expect_opt_text(resolution, "obligation resolution")?,
            created_seq: expect_u64(created, "obligation seq")?,
        })
    }

    /// Shared row mapper for `provisional_install_journal` SELECTs
    /// (single source of truth for the 10-column shape; R121 domain
    /// restore included).
    fn map_install_row(&self, row: &[SqlValue]) -> Result<ProvisionalInstallRecord, StoreError> {
        let [
            pin,
            worker,
            attempt_hex,
            path,
            algo,
            domain,
            bytes,
            object_key,
            seq,
            state,
        ] = row
        else {
            return Err(StoreError::Corruption("install journal shape".into()));
        };
        Ok(ProvisionalInstallRecord {
            pin_key: expect_text(pin, "install pin")?,
            consumer_worker: expect_text(worker, "install worker")?,
            consumer_attempt_hex: expect_text(attempt_hex, "install attempt")?,
            installed_path: match path {
                SqlValue::Blob(b) => b.clone(),
                _ => return Err(StoreError::Corruption("install path shape".into())),
            },
            object: self.restore_digest(algo, domain, bytes)?,
            object_key: expect_text(object_key, "install object")?,
            installed_seq: expect_u64(seq, "install seq")?,
            state: expect_text(state, "install state")?,
        })
    }
}

fn expect_u64(v: &SqlValue, what: &str) -> Result<u64, StoreError> {
    match v {
        SqlValue::Int(i) => {
            u64::try_from(*i).map_err(|_| StoreError::Corruption(format!("negative {what}")))
        }
        _ => Err(StoreError::Corruption(format!("{what} shape"))),
    }
}

fn expect_u128(v: &SqlValue, what: &str) -> Result<u128, StoreError> {
    match v {
        SqlValue::Blob(b) => {
            let bytes: [u8; 16] = b
                .as_slice()
                .try_into()
                .map_err(|_| StoreError::Corruption(format!("{what} not 16 bytes")))?;
            Ok(u128::from_be_bytes(bytes))
        }
        _ => Err(StoreError::Corruption(format!("{what} shape"))),
    }
}

fn expect_u64_blob(v: &SqlValue, what: &str) -> Result<u64, StoreError> {
    match v {
        SqlValue::Blob(b) => {
            let bytes: [u8; 8] = b
                .as_slice()
                .try_into()
                .map_err(|_| StoreError::Corruption(format!("{what} not 8 bytes")))?;
            Ok(u64::from_be_bytes(bytes))
        }
        _ => Err(StoreError::Corruption(format!("{what} shape"))),
    }
}

fn decode_worker_incarnation_fence(
    worker: &str,
    row: &[SqlValue],
) -> Result<WorkerIncarnationFenceRecord, StoreError> {
    let [
        highest_boot_generation,
        incarnation,
        active,
        operator_reenrollment_generation,
        clone_ambiguous,
    ] = row
    else {
        return Err(StoreError::Corruption("worker fence shape".into()));
    };
    let incarnation = WorkerIncarnationId(expect_u128(incarnation, "worker incarnation")?);
    let active_incarnation = match expect_u64(active, "worker fence active")? {
        0 => None,
        1 => Some(incarnation),
        other => {
            return Err(StoreError::Corruption(format!(
                "worker fence active flag {other}"
            )));
        }
    };
    Ok(WorkerIncarnationFenceRecord {
        worker_peer_id: PeerId(worker.to_owned()),
        highest_boot_generation: WorkerBootGeneration(expect_u64_blob(
            highest_boot_generation,
            "worker boot generation",
        )?),
        active_incarnation,
        clone_ambiguous: match expect_u64(clone_ambiguous, "clone ambiguous")? {
            0 => false,
            1 => true,
            other => {
                return Err(StoreError::Corruption(format!(
                    "clone ambiguous flag {other}"
                )));
            }
        },
        operator_reenrollment_generation: expect_u64_blob(
            operator_reenrollment_generation,
            "worker reenrollment generation",
        )?,
    })
}

fn expect_text(v: &SqlValue, what: &str) -> Result<String, StoreError> {
    match v {
        SqlValue::Text(t) => Ok(t.clone()),
        _ => Err(StoreError::Corruption(format!("{what} shape"))),
    }
}

fn expect_opt_text(v: &SqlValue, what: &str) -> Result<Option<String>, StoreError> {
    match v {
        SqlValue::Null => Ok(None),
        SqlValue::Text(t) => Ok(Some(t.clone())),
        _ => Err(StoreError::Corruption(format!("{what} shape"))),
    }
}

fn to_seq(v: u64, what: &str) -> Result<i64, StoreError> {
    i64::try_from(v).map_err(|_| StoreError::Corruption(format!("{what} out of range")))
}

/// Decode `(evidence_domain, evidence_bytes)` rows into sorted
/// `domain:hex` keys (shared by the per-action and per-manifest listings).
fn evidence_key_rows(rows: &[Vec<SqlValue>]) -> Result<Vec<String>, StoreError> {
    rows.iter()
        .map(|row| {
            let [domain, bytes] = row.as_slice() else {
                return Err(StoreError::Corruption("evidence row shape".into()));
            };
            let SqlValue::Blob(bytes) = bytes else {
                return Err(StoreError::Corruption("evidence bytes shape".into()));
            };
            Ok(format!(
                "{}:{}",
                expect_text(domain, "evidence domain")?,
                hex(bytes)
            ))
        })
        .collect()
}

impl<E: SqlEngine> RabsMetadataStore for SqlMetadataStore<E> {
    fn query(&mut self, sql: &str, params: &[SqlValue]) -> Result<Vec<Vec<SqlValue>>, StoreError> {
        self.engine.query(sql, params)
    }

    fn schema_version(&mut self) -> Result<u32, StoreError> {
        let rows = self
            .engine
            .query("SELECT MAX(version) FROM schema_epochs", &[])?;
        match rows.first().and_then(|r| r.first()) {
            Some(SqlValue::Int(v)) => u32::try_from(*v)
                .map_err(|_| StoreError::Corruption("negative schema version".into())),
            _ => Err(StoreError::Corruption("missing schema_epochs".into())),
        }
    }

    fn intern_domain(&mut self, domain: &'static str) {
        self.intern(domain);
    }

    fn acquire_authority(&mut self, row: &AuthorityRow) -> Result<(), StoreError> {
        self.intern(row.digest.domain);
        let key = digest_key(&row.digest);
        let [algo, domain, bytes] = SqlMetadataStore::<E>::digest_params(&row.digest);
        let cluster = row.cluster_id.clone();
        let incarnation = u128_blob(row.incarnation);
        let term = i64::try_from(row.term)
            .map_err(|_| StoreError::Corruption("term out of range".into()))?;
        let acquired = i64::try_from(row.acquired_seq)
            .map_err(|_| StoreError::Corruption("acquired_seq out of range".into()))?;
        self.in_txn(move |engine| {
            match SqlMetadataStore::<E>::active_authority_key(engine)? {
                Some(active) if active == key => return Ok(()), // idempotent
                Some(active) => return Err(StoreError::AuthorityHeld { holder: active }),
                None => {}
            }
            engine.execute(
                "INSERT OR REPLACE INTO coordinator_authorities \
                 (key, algo, domain, bytes, cluster_id, incarnation, term, acquired_seq, released) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0)",
                &[
                    SqlValue::Text(key),
                    algo,
                    domain,
                    bytes,
                    SqlValue::Text(cluster),
                    SqlValue::Blob(incarnation),
                    SqlValue::Int(term),
                    SqlValue::Int(acquired),
                ],
            )?;
            Ok(())
        })
    }

    fn release_authority(&mut self, digest: &TypedDigest) -> Result<(), StoreError> {
        let key = digest_key(digest);
        self.in_txn(move |engine| {
            engine.execute(
                "UPDATE coordinator_authorities SET released = 1 WHERE key = ?1",
                &[SqlValue::Text(key)],
            )?;
            Ok(())
        })
    }

    fn active_authority(&mut self) -> Result<Option<AuthorityRow>, StoreError> {
        let rows = self.engine.query(
            "SELECT algo, domain, bytes, cluster_id, incarnation, term, acquired_seq \
             FROM coordinator_authorities WHERE released = 0",
            &[],
        )?;
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        if rows.len() > 1 {
            return Err(StoreError::Corruption(
                "more than one active authority".into(),
            ));
        }
        let [algo, domain, bytes, cluster, incarnation, term, acquired] = row.as_slice() else {
            return Err(StoreError::Corruption("authority row shape".into()));
        };
        let digest = self.restore_digest(algo, domain, bytes)?;
        let SqlValue::Text(cluster) = cluster else {
            return Err(StoreError::Corruption("cluster_id shape".into()));
        };
        let SqlValue::Blob(incarnation) = incarnation else {
            return Err(StoreError::Corruption("incarnation shape".into()));
        };
        let incarnation_bytes: [u8; 16] = incarnation
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::Corruption("incarnation not 16 bytes".into()))?;
        Ok(Some(AuthorityRow {
            digest,
            cluster_id: cluster.clone(),
            incarnation: u128::from_be_bytes(incarnation_bytes),
            term: expect_u64(term, "term")?,
            acquired_seq: expect_u64(acquired, "acquired_seq")?,
        }))
    }

    fn upsert_action_entry(&mut self, row: &ActionEntryRow) -> Result<(), StoreError> {
        self.intern(row.action_key.domain);
        let key = digest_key(&row.action_key);
        let [algo, domain, bytes] = SqlMetadataStore::<E>::digest_params(&row.action_key);
        let key_epoch = i64::from(row.key_epoch);
        let projection_epoch = i64::from(row.projection_epoch);
        self.in_txn(move |engine| {
            engine.execute(
                "INSERT OR REPLACE INTO action_entries \
                 (key, algo, domain, bytes, key_epoch, projection_epoch) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                &[
                    SqlValue::Text(key),
                    algo,
                    domain,
                    bytes,
                    SqlValue::Int(key_epoch),
                    SqlValue::Int(projection_epoch),
                ],
            )?;
            Ok(())
        })
    }

    fn lookup_action(&mut self, key: &TypedDigest) -> Result<Option<ActionEntryRow>, StoreError> {
        let rows = self.engine.query(
            "SELECT algo, domain, bytes, key_epoch, projection_epoch \
             FROM action_entries WHERE key = ?1",
            &[SqlValue::Text(digest_key(key))],
        )?;
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        let [algo, domain, bytes, key_epoch, projection_epoch] = row.as_slice() else {
            return Err(StoreError::Corruption("action entry shape".into()));
        };
        let action_key = self.restore_digest(algo, domain, bytes)?;
        let key_epoch = u32::try_from(expect_u64(key_epoch, "key_epoch")?)
            .map_err(|_| StoreError::Corruption("key_epoch out of range".into()))?;
        let projection_epoch = u32::try_from(expect_u64(projection_epoch, "projection_epoch")?)
            .map_err(|_| StoreError::Corruption("projection_epoch out of range".into()))?;
        Ok(Some(ActionEntryRow {
            action_key,
            key_epoch,
            projection_epoch,
        }))
    }

    fn create_generation(
        &mut self,
        authority: &TypedDigest,
        id: u128,
        action_key: &TypedDigest,
    ) -> Result<(), StoreError> {
        let authority = authority.clone();
        let action = digest_key(action_key);
        self.in_txn(move |engine| {
            SqlMetadataStore::<E>::require_active(engine, &authority)?;
            let high_water = SqlMetadataStore::<E>::generation_high_water(engine)?;
            if id <= high_water {
                return Err(StoreError::GenerationIdNotAboveHighWater);
            }
            engine.execute(
                "INSERT INTO action_generations (id_hex, id, action_key, authority_key, tombstoned) \
                 VALUES (?1, ?2, ?3, ?4, 0)",
                &[
                    SqlValue::Text(u128_hex(id)),
                    SqlValue::Blob(u128_blob(id)),
                    SqlValue::Text(action),
                    SqlValue::Text(digest_key(&authority)),
                ],
            )?;
            engine.execute(
                "INSERT OR REPLACE INTO generation_high_water (kind, value) \
                 VALUES ('action-generation', ?1)",
                &[SqlValue::Blob(u128_blob(id))],
            )?;
            Ok(())
        })
    }

    fn create_bound_generation(
        &mut self,
        authority: &TypedDigest,
        generation: &ActionGeneration,
        action_key: &TypedDigest,
    ) -> Result<(), StoreError> {
        SqlMetadataStore::create_bound_generation(self, authority, generation, action_key)
    }

    fn close_generations_for_other_authorities(
        &mut self,
        active: &TypedDigest,
    ) -> Result<u64, StoreError> {
        let active = digest_key(active);
        self.in_txn(move |engine| {
            let closed = engine.execute(
                "UPDATE action_generations SET tombstoned = 1 \
                 WHERE tombstoned = 0 AND authority_key != ?1",
                &[SqlValue::Text(active)],
            )?;
            u64::try_from(closed)
                .map_err(|_| StoreError::Corruption("generation close count out of range".into()))
        })
    }
    fn tombstone_generation(&mut self, id: u128) -> Result<(), StoreError> {
        self.in_txn(move |engine| {
            let changed = engine.execute(
                "UPDATE action_generations SET tombstoned = 1 WHERE id_hex = ?1",
                &[SqlValue::Text(u128_hex(id))],
            )?;
            if changed == 0 {
                return Err(StoreError::UnknownGeneration);
            }
            Ok(())
        })
    }

    fn record_attempt(
        &mut self,
        id: u128,
        generation: u128,
        worker: &str,
        seq: u64,
    ) -> Result<(), StoreError> {
        let worker = worker.to_owned();
        let seq =
            i64::try_from(seq).map_err(|_| StoreError::Corruption("seq out of range".into()))?;
        self.in_txn(move |engine| {
            let existing = engine.query(
                "SELECT id_hex FROM action_attempts WHERE id_hex = ?1",
                &[SqlValue::Text(u128_hex(id))],
            )?;
            if !existing.is_empty() {
                return Err(StoreError::DuplicateAttempt);
            }
            let generation_exists = engine.query(
                "SELECT id_hex FROM action_generations WHERE id_hex = ?1",
                &[SqlValue::Text(u128_hex(generation))],
            )?;
            if generation_exists.is_empty() {
                return Err(StoreError::UnknownGeneration);
            }
            engine.execute(
                "INSERT INTO action_attempts (id_hex, id, generation_hex, worker, seq) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                &[
                    SqlValue::Text(u128_hex(id)),
                    SqlValue::Blob(u128_blob(id)),
                    SqlValue::Text(u128_hex(generation)),
                    SqlValue::Text(worker),
                    SqlValue::Int(seq),
                ],
            )?;
            Ok(())
        })
    }

    fn admit_attempt_lease(
        &mut self,
        authority: &AttemptAuthority,
        recorded_seq: u64,
        expires_at_seq: u64,
    ) -> Result<(), StoreError> {
        let authority = authority.clone();
        let recorded = i64::try_from(recorded_seq)
            .map_err(|_| StoreError::Corruption("recorded_seq out of range".into()))?;
        let renewal = i64::try_from(authority.lease_renewal_seq.0)
            .map_err(|_| StoreError::Corruption("renewal_seq out of range".into()))?;
        let expires = i64::try_from(expires_at_seq)
            .map_err(|_| StoreError::Corruption("expires_at_seq out of range".into()))?;
        self.in_txn(move |engine| {
            SqlMetadataStore::<E>::require_attempt_context(engine, &authority)?;
            SqlMetadataStore::<E>::require_worker_lease_binding(
                engine,
                &authority.worker_peer_id,
                authority.worker_boot_generation,
                authority.worker_incarnation_id,
            )?;
            let attempt_id = authority.attempt_id.0;
            if !engine
                .query(
                    "SELECT id_hex FROM action_attempts WHERE id_hex = ?1",
                    &[SqlValue::Text(u128_hex(attempt_id))],
                )?
                .is_empty()
            {
                return Err(StoreError::DuplicateAttempt);
            }
            let lease_id = authority.execution_lease_id.0;
            if !engine
                .query(
                    "SELECT id_hex FROM execution_leases WHERE id_hex = ?1",
                    &[SqlValue::Text(u128_hex(lease_id))],
                )?
                .is_empty()
            {
                return Err(StoreError::DuplicateLease);
            }
            engine.execute(
                "INSERT INTO action_attempts \
                 (id_hex, id, generation_hex, worker, seq, \
                  worker_boot_generation, worker_incarnation, execution_lease_hex) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                &[
                    SqlValue::Text(u128_hex(attempt_id)),
                    SqlValue::Blob(u128_blob(attempt_id)),
                    SqlValue::Text(u128_hex(authority.action_generation.generation_id.0)),
                    SqlValue::Text(authority.worker_peer_id.0.clone()),
                    SqlValue::Int(recorded),
                    SqlValue::Blob(u64_blob(authority.worker_boot_generation.0)),
                    SqlValue::Blob(u128_blob(authority.worker_incarnation_id.0)),
                    SqlValue::Text(u128_hex(lease_id)),
                ],
            )?;
            engine.execute(
                "INSERT INTO execution_leases \
                 (id_hex, id, attempt_hex, renewal_seq, expires_at_seq, released) \
                 VALUES (?1, ?2, ?3, ?4, ?5, 0)",
                &[
                    SqlValue::Text(u128_hex(lease_id)),
                    SqlValue::Blob(u128_blob(lease_id)),
                    SqlValue::Text(u128_hex(attempt_id)),
                    SqlValue::Int(renewal),
                    SqlValue::Int(expires),
                ],
            )?;
            Ok(())
        })
    }

    fn renew_attempt_lease(
        &mut self,
        authority: &AttemptAuthority,
        renewal: LeaseRenewal,
        expires_at_seq: u64,
    ) -> Result<(), StoreError> {
        let authority = authority.clone();
        let expires = i64::try_from(expires_at_seq)
            .map_err(|_| StoreError::Corruption("expires_at_seq out of range".into()))?;
        self.in_txn(move |engine| {
            let state = SqlMetadataStore::<E>::bound_lease_state(engine, &authority)?;
            if state.released {
                return Err(StoreError::LeaseReleased);
            }
            if renewal.lease != authority.execution_lease_id {
                return Err(StoreError::LeaseAttemptMismatch);
            }
            if authority.lease_renewal_seq.0 != state.renewal_seq {
                return Err(StoreError::LeaseRenewalMismatch);
            }
            if renewal.seq.0 <= state.renewal_seq {
                return Err(StoreError::NonMonotonicRenewal);
            }
            let renewal_seq = i64::try_from(renewal.seq.0)
                .map_err(|_| StoreError::Corruption("renewal_seq out of range".into()))?;
            engine.execute(
                "UPDATE execution_leases SET renewal_seq = ?1, expires_at_seq = ?2 \
                 WHERE id_hex = ?3",
                &[
                    SqlValue::Int(renewal_seq),
                    SqlValue::Int(expires),
                    SqlValue::Text(u128_hex(authority.execution_lease_id.0)),
                ],
            )?;
            Ok(())
        })
    }

    fn release_lease(&mut self, id: u128) -> Result<(), StoreError> {
        self.in_txn(move |engine| {
            let changed = engine.execute(
                "UPDATE execution_leases SET released = 1 WHERE id_hex = ?1",
                &[SqlValue::Text(u128_hex(id))],
            )?;
            if changed == 0 {
                return Err(StoreError::UnknownLease);
            }
            Ok(())
        })
    }

    fn commit_publication(
        &mut self,
        permit: PublicationPermit<'_>,
        row: &PublicationRow,
    ) -> Result<CommitOutcome, StoreError> {
        self.intern(row.action_key.domain);
        self.intern(row.descriptor_digest.domain);
        self.intern(row.manifest_digest.domain);
        self.intern(row.evidence_digest.domain);
        let (authority, attempt_authority) = permit.into_parts();
        let row = row.clone();
        self.in_txn(move |engine| {
            match &attempt_authority {
                Some(attempt) => {
                    if SqlMetadataStore::<E>::attempt_authority_digest(attempt) != authority
                        || row.action_key != attempt.action_key
                        || row.winner_generation != attempt.action_generation.generation_id.0
                        || row.winner_attempt != attempt.attempt_id.0
                    {
                        return Err(StoreError::AttemptAuthorityMismatch);
                    }
                    let state = SqlMetadataStore::<E>::bound_lease_state(engine, attempt)?;
                    if state.released {
                        return Err(StoreError::LeaseReleased);
                    }
                    if state.renewal_seq != attempt.lease_renewal_seq.0 {
                        return Err(StoreError::LeaseRenewalMismatch);
                    }
                }
                None => SqlMetadataStore::<E>::require_active(engine, &authority)?,
            }
            let action = digest_key(&row.action_key);
            let existing = engine.query(
                "SELECT descriptor_domain, descriptor_bytes FROM action_publications \
                 WHERE action_key = ?1",
                &[SqlValue::Text(action.clone())],
            )?;
            if let Some(existing_row) = existing.first() {
                let [domain, bytes] = existing_row.as_slice() else {
                    return Err(StoreError::Corruption("publication row shape".into()));
                };
                let (SqlValue::Text(domain), SqlValue::Blob(bytes)) = (domain, bytes) else {
                    return Err(StoreError::Corruption("publication digest shape".into()));
                };
                let same = domain == row.descriptor_digest.domain
                    && bytes.as_slice() == row.descriptor_digest.bytes.as_slice();
                if same {
                    return Ok(CommitOutcome::IdempotentDuplicate);
                }
                // Different descriptor for the same key: quarantine, never
                // overwrite.
                engine.execute(
                    "INSERT OR REPLACE INTO quarantines (scope, subject, reason) \
                     VALUES ('action-entry', ?1, 'publication descriptor conflict')",
                    &[SqlValue::Text(action)],
                )?;
                return Ok(CommitOutcome::ConflictQuarantined);
            }
            let [d_algo, d_domain, d_bytes] =
                SqlMetadataStore::<E>::digest_params(&row.descriptor_digest);
            let [m_algo, m_domain, m_bytes] =
                SqlMetadataStore::<E>::digest_params(&row.manifest_digest);
            engine.execute(
                "INSERT INTO action_publications \
                 (action_key, descriptor_algo, descriptor_domain, descriptor_bytes, \
                  manifest_algo, manifest_domain, manifest_bytes, \
                  winner_generation_hex, winner_attempt_hex, result_kind, pin_hex) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                &[
                    SqlValue::Text(action.clone()),
                    d_algo,
                    d_domain,
                    d_bytes,
                    m_algo,
                    m_domain,
                    m_bytes,
                    SqlValue::Text(u128_hex(row.winner_generation)),
                    SqlValue::Text(u128_hex(row.winner_attempt)),
                    SqlValue::Text(row.result_kind.as_str().to_owned()),
                    SqlValue::Text(u128_hex(row.pin_id)),
                ],
            )?;
            // Disposition-only write: UPDATE first so the H040 revision
            // and validity columns are never silently reset by a legacy
            // path.
            let serving_changed = engine.execute(
                "UPDATE action_serving_states SET disposition = 'servable' WHERE action_key = ?1",
                &[SqlValue::Text(action.clone())],
            )?;
            if serving_changed == 0 {
                engine.execute(
                    "INSERT INTO action_serving_states (action_key, disposition, version) \
                     VALUES (?1, 'servable', 1)",
                    &[SqlValue::Text(action.clone())],
                )?;
            }
            // The winner's evidence association, SAME transaction (H011),
            // bound to the committed canonical manifest (H029; I37) and
            // append-only (OR IGNORE: never rewrite prior attribution).
            let [e_algo, e_domain, e_bytes] =
                SqlMetadataStore::<E>::digest_params(&row.evidence_digest);
            engine.execute(
                "INSERT OR IGNORE INTO action_evidence_index \
                 (action_key, evidence_algo, evidence_domain, evidence_bytes, \
                  generation_hex, attempt_hex, manifest_key) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                &[
                    SqlValue::Text(action),
                    e_algo,
                    e_domain,
                    e_bytes,
                    SqlValue::Text(u128_hex(row.winner_generation)),
                    SqlValue::Text(u128_hex(row.winner_attempt)),
                    SqlValue::Text(digest_key(&row.manifest_digest)),
                ],
            )?;
            // The durable publication reachability pin, SAME transaction.
            engine.execute(
                "INSERT INTO pins (id_hex, id, root_key, owner, class, expires_at_seq, released, \
                 evidence, renewal_seq, durable, reason) \
                 VALUES (?1, ?2, ?3, ?4, 'action-publication', NULL, 0, ?5, 0, 1, \
                 'publication reachability root')",
                &[
                    SqlValue::Text(u128_hex(row.pin_id)),
                    SqlValue::Blob(u128_blob(row.pin_id)),
                    SqlValue::Text(digest_key(&row.manifest_digest)),
                    SqlValue::Text(row.pin_owner.clone()),
                    SqlValue::Text(digest_key(&row.action_key)),
                ],
            )?;
            // The verified provisional-ancestor lineage, SAME transaction
            // (H028; I32): a dependent's later commit walks these rows as
            // durable truth.
            for ancestor in &row.provisional_ancestors {
                engine.execute(
                    "INSERT OR IGNORE INTO provisional_ancestry \
                     (consumer_action_key, producer_action_key, role, virtual_path, \
                      object_key, adopted) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    &[
                        SqlValue::Text(digest_key(&row.action_key)),
                        SqlValue::Text(ancestor.producer_action_key.clone()),
                        SqlValue::Text(ancestor.role.clone()),
                        SqlValue::Blob(ancestor.virtual_path.clone()),
                        SqlValue::Text(ancestor.object_key.clone()),
                        SqlValue::Int(i64::from(ancestor.adopted)),
                    ],
                )?;
            }
            Ok(CommitOutcome::Committed)
        })
    }

    fn append_evidence(
        &mut self,
        action: &TypedDigest,
        manifest_key: &str,
        evidence: &TypedDigest,
        generation: u128,
        attempt: u128,
    ) -> Result<(), StoreError> {
        self.intern(evidence.domain);
        let action = digest_key(action);
        let manifest_key = manifest_key.to_owned();
        let [algo, domain, bytes] = SqlMetadataStore::<E>::digest_params(evidence);
        self.in_txn(move |engine| {
            // OR IGNORE, not OR REPLACE: append-only, first-writer-wins.
            // A re-append of the same evidence digest under a different
            // (manifest, generation, attempt) is an idempotent no-op —
            // the original attribution is history and never rewritten
            // (H029; I37).
            engine.execute(
                "INSERT OR IGNORE INTO action_evidence_index \
                 (action_key, evidence_algo, evidence_domain, evidence_bytes, \
                  generation_hex, attempt_hex, manifest_key) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                &[
                    SqlValue::Text(action),
                    algo,
                    domain,
                    bytes,
                    SqlValue::Text(u128_hex(generation)),
                    SqlValue::Text(u128_hex(attempt)),
                    SqlValue::Text(manifest_key),
                ],
            )?;
            Ok(())
        })
    }

    fn has_publication(&mut self, action: &TypedDigest) -> Result<bool, StoreError> {
        let rows = self.engine.query(
            "SELECT action_key FROM action_publications WHERE action_key = ?1",
            &[SqlValue::Text(digest_key(action))],
        )?;
        Ok(!rows.is_empty())
    }

    fn published_manifest_key(
        &mut self,
        action: &TypedDigest,
    ) -> Result<Option<String>, StoreError> {
        self.published_manifest_key_str(&digest_key(action))
    }

    fn published_manifest_key_str(
        &mut self,
        action_key: &str,
    ) -> Result<Option<String>, StoreError> {
        let rows = self.engine.query(
            "SELECT manifest_domain, manifest_bytes FROM action_publications WHERE action_key = ?1",
            &[SqlValue::Text(action_key.to_owned())],
        )?;
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        let [SqlValue::Text(domain), SqlValue::Blob(bytes)] = row.as_slice() else {
            return Err(StoreError::Corruption("publication manifest shape".into()));
        };
        Ok(Some(format!("{}:{}", domain, hex(bytes))))
    }

    fn generation_state(&mut self, id: u128) -> Result<Option<GenerationState>, StoreError> {
        let rows = self.engine.query(
            "SELECT tombstoned FROM action_generations WHERE id_hex = ?1",
            &[SqlValue::Text(u128_hex(id))],
        )?;
        match rows.first().and_then(|r| r.first()) {
            None => Ok(None),
            Some(v) => Ok(Some(GenerationState {
                tombstoned: expect_u64(v, "tombstoned")? != 0,
            })),
        }
    }

    fn attempt_exists(&mut self, id: u128, generation: u128) -> Result<bool, StoreError> {
        let rows = self.engine.query(
            "SELECT id_hex FROM action_attempts WHERE id_hex = ?1 AND generation_hex = ?2",
            &[
                SqlValue::Text(u128_hex(id)),
                SqlValue::Text(u128_hex(generation)),
            ],
        )?;
        Ok(!rows.is_empty())
    }

    fn lease_state(&mut self, id: u128) -> Result<Option<LeaseState>, StoreError> {
        let rows = self.engine.query(
            "SELECT released, renewal_seq FROM execution_leases WHERE id_hex = ?1",
            &[SqlValue::Text(u128_hex(id))],
        )?;
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        let [released, renewal_seq] = row.as_slice() else {
            return Err(StoreError::Corruption("lease state shape".into()));
        };
        Ok(Some(LeaseState {
            released: expect_u64(released, "released")? != 0,
            renewal_seq: expect_u64(renewal_seq, "renewal_seq")?,
        }))
    }

    fn validate_attempt_lease(
        &mut self,
        authority: &AttemptAuthority,
    ) -> Result<LeaseState, StoreError> {
        let state = SqlMetadataStore::<E>::bound_lease_state(&mut self.engine, authority)?;
        if state.released {
            return Err(StoreError::LeaseReleased);
        }
        if state.renewal_seq != authority.lease_renewal_seq.0 {
            return Err(StoreError::LeaseRenewalMismatch);
        }
        Ok(state)
    }

    fn object_located(&mut self, object: &TypedDigest) -> Result<bool, StoreError> {
        // A quarantined location is suspect COPY evidence: it does not
        // count as availability (the object's identity is untouched).
        let rows = self.engine.query(
            "SELECT object_key FROM object_locations \
             WHERE object_key = ?1 AND quarantined = 0 LIMIT 1",
            &[SqlValue::Text(digest_key(object))],
        )?;
        Ok(!rows.is_empty())
    }

    fn object_locations(
        &mut self,
        object: &TypedDigest,
    ) -> Result<Vec<(String, String, bool)>, StoreError> {
        let rows = self.engine.query(
            "SELECT store_path, encoding, durable FROM object_locations \
             WHERE object_key = ?1 AND quarantined = 0 ORDER BY store_path",
            &[SqlValue::Text(digest_key(object))],
        )?;
        rows.iter()
            .map(|row| {
                let [path, encoding, durable] = row.as_slice() else {
                    return Err(StoreError::Corruption("object location shape".into()));
                };
                Ok((
                    expect_text(path, "store_path")?,
                    expect_text(encoding, "encoding")?,
                    expect_u64(durable, "durable")? != 0,
                ))
            })
            .collect()
    }

    fn record_object(&mut self, id: &TypedDigest, logical_size: u64) -> Result<(), StoreError> {
        self.intern(id.domain);
        let key = digest_key(id);
        let [algo, domain, bytes] = SqlMetadataStore::<E>::digest_params(id);
        let size = i64::try_from(logical_size)
            .map_err(|_| StoreError::Corruption("logical_size out of range".into()))?;
        self.in_txn(move |engine| {
            engine.execute(
                "INSERT OR REPLACE INTO objects (key, algo, domain, bytes, logical_size) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                &[
                    SqlValue::Text(key),
                    algo,
                    domain,
                    bytes,
                    SqlValue::Int(size),
                ],
            )?;
            Ok(())
        })
    }

    fn add_location(
        &mut self,
        object: &TypedDigest,
        store_path: &str,
        verified_seq: Option<u64>,
        encoding: &str,
        durable: bool,
    ) -> Result<(), StoreError> {
        let key = digest_key(object);
        let path = store_path.to_owned();
        let encoding = encoding.to_owned();
        let verified = match verified_seq {
            None => SqlValue::Null,
            Some(v) => SqlValue::Int(
                i64::try_from(v)
                    .map_err(|_| StoreError::Corruption("verified_seq out of range".into()))?,
            ),
        };
        self.in_txn(move |engine| {
            engine.execute(
                "INSERT OR REPLACE INTO object_locations \
                 (object_key, store_path, verified_seq, encoding, quarantined, durable) \
                 VALUES (?1, ?2, ?3, ?4, 0, ?5)",
                &[
                    SqlValue::Text(key),
                    SqlValue::Text(path),
                    verified,
                    SqlValue::Text(encoding),
                    SqlValue::Int(i64::from(durable)),
                ],
            )?;
            Ok(())
        })
    }

    fn object_durably_located(&mut self, object: &TypedDigest) -> Result<bool, StoreError> {
        // Same quarantine rule as `object_located`, plus the H032 gate:
        // only a copy recorded as satisfying the FULL durability policy
        // counts.
        let rows = self.engine.query(
            "SELECT object_key FROM object_locations \
             WHERE object_key = ?1 AND quarantined = 0 AND durable = 1 LIMIT 1",
            &[SqlValue::Text(digest_key(object))],
        )?;
        Ok(!rows.is_empty())
    }

    fn set_location_quarantined(
        &mut self,
        object: &TypedDigest,
        store_path: &str,
        quarantined: bool,
    ) -> Result<(), StoreError> {
        let key = digest_key(object);
        let path = store_path.to_owned();
        self.in_txn(move |engine| {
            let changed = engine.execute(
                "UPDATE object_locations SET quarantined = ?1 \
                 WHERE object_key = ?2 AND store_path = ?3",
                &[
                    SqlValue::Int(i64::from(quarantined)),
                    SqlValue::Text(key),
                    SqlValue::Text(path),
                ],
            )?;
            if changed == 0 {
                return Err(StoreError::Corruption("unknown location".into()));
            }
            Ok(())
        })
    }

    fn add_object_edge(
        &mut self,
        parent: &TypedDigest,
        child: &TypedDigest,
        kind: &str,
    ) -> Result<(), StoreError> {
        let parent = digest_key(parent);
        let child = digest_key(child);
        let kind = kind.to_owned();
        self.in_txn(move |engine| {
            engine.execute(
                "INSERT OR REPLACE INTO object_edges (parent_key, child_key, kind) \
                 VALUES (?1, ?2, ?3)",
                &[
                    SqlValue::Text(parent),
                    SqlValue::Text(child),
                    SqlValue::Text(kind),
                ],
            )?;
            Ok(())
        })
    }

    fn create_pin(
        &mut self,
        id: u128,
        root: &TypedDigest,
        owner: &str,
        class: &str,
        expires_at_seq: Option<u64>,
        evidence: Option<&str>,
        durable: bool,
        reason: &str,
    ) -> Result<(), StoreError> {
        let root = digest_key(root);
        let owner = owner.to_owned();
        let class = class.to_owned();
        let evidence = match evidence {
            None => SqlValue::Null,
            Some(e) => SqlValue::Text(e.to_owned()),
        };
        let reason = reason.to_owned();
        let expires = match expires_at_seq {
            None => SqlValue::Null,
            Some(v) => SqlValue::Int(
                i64::try_from(v)
                    .map_err(|_| StoreError::Corruption("expires_at_seq out of range".into()))?,
            ),
        };
        self.in_txn(move |engine| {
            engine.execute(
                "INSERT INTO pins (id_hex, id, root_key, owner, class, expires_at_seq, released, \
                 evidence, renewal_seq, durable, reason) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7, 0, ?8, ?9)",
                &[
                    SqlValue::Text(u128_hex(id)),
                    SqlValue::Blob(u128_blob(id)),
                    SqlValue::Text(root),
                    SqlValue::Text(owner),
                    SqlValue::Text(class),
                    expires,
                    evidence,
                    SqlValue::Int(i64::from(durable)),
                    SqlValue::Text(reason),
                ],
            )?;
            Ok(())
        })
    }

    fn renew_pin(&mut self, id: u128, renewal_seq: u64) -> Result<(), StoreError> {
        self.in_txn(move |engine| {
            let rows = engine.query(
                "SELECT renewal_seq, released FROM pins WHERE id_hex = ?1",
                &[SqlValue::Text(u128_hex(id))],
            )?;
            let Some(row) = rows.first() else {
                return Err(StoreError::UnknownPin);
            };
            let [stored_seq, released] = row.as_slice() else {
                return Err(StoreError::Corruption("pin row shape".into()));
            };
            if expect_u64(released, "released")? != 0 {
                return Err(StoreError::PinReleased);
            }
            if renewal_seq <= expect_u64(stored_seq, "renewal_seq")? {
                return Err(StoreError::NonMonotonicPinRenewal);
            }
            let renewal = i64::try_from(renewal_seq)
                .map_err(|_| StoreError::Corruption("renewal_seq out of range".into()))?;
            engine.execute(
                "UPDATE pins SET renewal_seq = ?1 WHERE id_hex = ?2",
                &[SqlValue::Int(renewal), SqlValue::Text(u128_hex(id))],
            )?;
            Ok(())
        })
    }

    fn release_pin(&mut self, id: u128, owner: &str) -> Result<(), StoreError> {
        let owner = owner.to_owned();
        self.in_txn(move |engine| {
            let rows = engine.query(
                "SELECT owner FROM pins WHERE id_hex = ?1",
                &[SqlValue::Text(u128_hex(id))],
            )?;
            let Some(row) = rows.first() else {
                return Err(StoreError::UnknownPin);
            };
            match row.first() {
                Some(SqlValue::Text(stored)) if *stored == owner => {}
                Some(SqlValue::Text(_)) => return Err(StoreError::PinOwnerMismatch),
                _ => return Err(StoreError::Corruption("pin owner shape".into())),
            }
            engine.execute(
                "UPDATE pins SET released = 1 WHERE id_hex = ?1",
                &[SqlValue::Text(u128_hex(id))],
            )?;
            Ok(())
        })
    }

    fn put_recipe(&mut self, action: &TypedDigest, recipe: &TypedDigest) -> Result<(), StoreError> {
        self.intern(recipe.domain);
        let action = digest_key(action);
        let [algo, domain, bytes] = SqlMetadataStore::<E>::digest_params(recipe);
        self.in_txn(move |engine| {
            engine.execute(
                "INSERT OR REPLACE INTO observed_input_recipes \
                 (action_key, recipe_algo, recipe_domain, recipe_bytes) VALUES (?1, ?2, ?3, ?4)",
                &[SqlValue::Text(action), algo, domain, bytes],
            )?;
            Ok(())
        })
    }

    fn put_key_breakdown(
        &mut self,
        action: &TypedDigest,
        component: &str,
        digest: &TypedDigest,
    ) -> Result<(), StoreError> {
        self.intern(digest.domain);
        let action = digest_key(action);
        let component = component.to_owned();
        let [algo, domain, bytes] = SqlMetadataStore::<E>::digest_params(digest);
        self.in_txn(move |engine| {
            engine.execute(
                "INSERT OR REPLACE INTO key_breakdowns \
                 (action_key, component, algo, domain, bytes) VALUES (?1, ?2, ?3, ?4, ?5)",
                &[
                    SqlValue::Text(action),
                    SqlValue::Text(component),
                    algo,
                    domain,
                    bytes,
                ],
            )?;
            Ok(())
        })
    }

    fn set_trust(
        &mut self,
        action: &TypedDigest,
        state: &str,
        reason: &str,
    ) -> Result<(), StoreError> {
        let action = digest_key(action);
        let state = state.to_owned();
        let reason = reason.to_owned();
        self.in_txn(move |engine| {
            engine.execute(
                "INSERT OR REPLACE INTO trust_states (action_key, state, reason) \
                 VALUES (?1, ?2, ?3)",
                &[
                    SqlValue::Text(action),
                    SqlValue::Text(state),
                    SqlValue::Text(reason),
                ],
            )?;
            Ok(())
        })
    }

    fn add_quarantine(
        &mut self,
        scope: QuarantineScope,
        subject: &str,
        reason: &str,
    ) -> Result<(), StoreError> {
        let subject = subject.to_owned();
        let reason = reason.to_owned();
        self.in_txn(move |engine| {
            engine.execute(
                "INSERT OR REPLACE INTO quarantines (scope, subject, reason) \
                 VALUES (?1, ?2, ?3)",
                &[
                    SqlValue::Text(scope.as_str().to_owned()),
                    SqlValue::Text(subject),
                    SqlValue::Text(reason),
                ],
            )?;
            Ok(())
        })
    }

    fn record_verification_sample(
        &mut self,
        action: &TypedDigest,
        attempt: u128,
        passed: bool,
        seq: u64,
    ) -> Result<(), StoreError> {
        let action = digest_key(action);
        let seq =
            i64::try_from(seq).map_err(|_| StoreError::Corruption("seq out of range".into()))?;
        self.in_txn(move |engine| {
            engine.execute(
                "INSERT OR REPLACE INTO verification_samples (action_key, attempt_hex, passed, seq) \
                 VALUES (?1, ?2, ?3, ?4)",
                &[
                    SqlValue::Text(action),
                    SqlValue::Text(u128_hex(attempt)),
                    SqlValue::Int(i64::from(passed)),
                    SqlValue::Int(seq),
                ],
            )?;
            Ok(())
        })
    }

    fn list_evidence_keys(&mut self, action: &TypedDigest) -> Result<Vec<String>, StoreError> {
        let rows = self.engine.query(
            "SELECT evidence_domain, evidence_bytes FROM action_evidence_index \
             WHERE action_key = ?1 ORDER BY evidence_domain, evidence_bytes",
            &[SqlValue::Text(digest_key(action))],
        )?;
        evidence_key_rows(&rows)
    }

    fn list_evidence_keys_for_manifest(
        &mut self,
        manifest_key: &str,
    ) -> Result<Vec<String>, StoreError> {
        let rows = self.engine.query(
            "SELECT evidence_domain, evidence_bytes FROM action_evidence_index \
             WHERE manifest_key = ?1 ORDER BY evidence_domain, evidence_bytes",
            &[SqlValue::Text(manifest_key.to_owned())],
        )?;
        evidence_key_rows(&rows)
    }

    fn list_verification_samples(
        &mut self,
        action: &TypedDigest,
    ) -> Result<Vec<VerificationSampleRow>, StoreError> {
        let rows = self.engine.query(
            "SELECT attempt_hex, passed, seq FROM verification_samples \
             WHERE action_key = ?1 ORDER BY attempt_hex, seq",
            &[SqlValue::Text(digest_key(action))],
        )?;
        rows.iter()
            .map(|row| {
                let [attempt_hex, passed, seq] = row.as_slice() else {
                    return Err(StoreError::Corruption("verification sample shape".into()));
                };
                Ok(VerificationSampleRow {
                    attempt_hex: expect_text(attempt_hex, "attempt_hex")?,
                    passed: expect_u64(passed, "passed")? != 0,
                    seq: expect_u64(seq, "seq")?,
                })
            })
            .collect()
    }

    fn attempt_worker_by_hex(&mut self, attempt_hex: &str) -> Result<Option<String>, StoreError> {
        let rows = self.engine.query(
            "SELECT worker FROM action_attempts WHERE id_hex = ?1",
            &[SqlValue::Text(attempt_hex.to_owned())],
        )?;
        match rows.first().and_then(|r| r.first()) {
            None => Ok(None),
            Some(v) => Ok(Some(expect_text(v, "worker")?)),
        }
    }

    fn gc_snapshot(&mut self, seq: u64) -> Result<GcSnapshot, StoreError> {
        let seq =
            i64::try_from(seq).map_err(|_| StoreError::Corruption("seq out of range".into()))?;
        self.in_txn(move |engine| {
            let pinned = engine.query(
                "SELECT root_key FROM pins WHERE released = 0 ORDER BY root_key",
                &[],
            )?;
            let located = engine.query(
                "SELECT DISTINCT object_key FROM object_locations ORDER BY object_key",
                &[],
            )?;
            let text_col = |rows: Vec<Vec<SqlValue>>| -> Result<Vec<String>, StoreError> {
                rows.into_iter()
                    .map(|row| match row.into_iter().next() {
                        Some(SqlValue::Text(t)) => Ok(t),
                        _ => Err(StoreError::Corruption("gc column shape".into())),
                    })
                    .collect()
            };
            let pinned_roots = text_col(pinned)?;
            let located_objects = text_col(located)?;
            // Reachability closure over object_edges from the unreleased
            // pin roots (cycle-safe via the visited set).
            let edges = engine.query(
                "SELECT parent_key, child_key FROM object_edges ORDER BY parent_key, child_key",
                &[],
            )?;
            let mut children: std::collections::BTreeMap<String, Vec<String>> =
                std::collections::BTreeMap::new();
            for row in edges {
                let [SqlValue::Text(parent), SqlValue::Text(child)] = row.as_slice() else {
                    return Err(StoreError::Corruption("edge row shape".into()));
                };
                children
                    .entry(parent.clone())
                    .or_default()
                    .push(child.clone());
            }
            let mut reachable: std::collections::BTreeSet<String> =
                std::collections::BTreeSet::new();
            let mut frontier: Vec<String> = pinned_roots.clone();
            while let Some(key) = frontier.pop() {
                if !reachable.insert(key.clone()) {
                    continue;
                }
                if let Some(next) = children.get(&key) {
                    frontier.extend(next.iter().cloned());
                }
            }
            let reachable_from_pins: Vec<String> = reachable.into_iter().collect();
            let pinned_count = i64::try_from(pinned_roots.len())
                .map_err(|_| StoreError::Corruption("pin count".into()))?;
            let located_count = i64::try_from(located_objects.len())
                .map_err(|_| StoreError::Corruption("location count".into()))?;
            let reachable_count = i64::try_from(reachable_from_pins.len())
                .map_err(|_| StoreError::Corruption("reachable count".into()))?;
            engine.execute(
                "INSERT INTO gc_runs (seq, pinned_roots, located_objects, reachable_objects) \
                 VALUES (?1, ?2, ?3, ?4)",
                &[
                    SqlValue::Int(seq),
                    SqlValue::Int(pinned_count),
                    SqlValue::Int(located_count),
                    SqlValue::Int(reachable_count),
                ],
            )?;
            Ok(GcSnapshot {
                pinned_roots,
                located_objects,
                reachable_from_pins,
            })
        })
    }

    fn reconciliation_scan(&mut self) -> Result<Vec<ReconciliationRow>, StoreError> {
        let rows = self.engine.query(
            "SELECT object_key, store_path, verified_seq, encoding, quarantined \
             FROM object_locations ORDER BY object_key, store_path",
            &[],
        )?;
        rows.into_iter()
            .map(|row| {
                let [key, path, verified, encoding, quarantined] = row.as_slice() else {
                    return Err(StoreError::Corruption("location row shape".into()));
                };
                let (SqlValue::Text(key), SqlValue::Text(path), SqlValue::Text(encoding)) =
                    (key, path, encoding)
                else {
                    return Err(StoreError::Corruption("location column shape".into()));
                };
                let verified_seq = match verified {
                    SqlValue::Null => None,
                    other => Some(expect_u64(other, "verified_seq")?),
                };
                Ok(ReconciliationRow {
                    object_key: key.clone(),
                    store_path: path.clone(),
                    verified_seq,
                    encoding: encoding.clone(),
                    quarantined: expect_u64(quarantined, "quarantined")? != 0,
                })
            })
            .collect()
    }

    fn remove_location_by_key(
        &mut self,
        object_key: &str,
        store_path: &str,
    ) -> Result<bool, StoreError> {
        let object_key = object_key.to_owned();
        let store_path = store_path.to_owned();
        self.in_txn(move |engine| {
            let removed = engine.execute(
                "DELETE FROM object_locations WHERE object_key = ?1 AND store_path = ?2",
                &[SqlValue::Text(object_key), SqlValue::Text(store_path)],
            )?;
            Ok(removed > 0)
        })
    }

    fn record_gc_receipt(&mut self, receipt: &GcReceiptRow) -> Result<(), StoreError> {
        let to_int = |v: u64, what: &str| -> Result<i64, StoreError> {
            i64::try_from(v).map_err(|_| StoreError::Corruption(format!("{what} out of range")))
        };
        let seq = to_int(receipt.seq, "seq")?;
        let planned = to_int(receipt.planned, "planned")?;
        let reclaimed = to_int(receipt.reclaimed, "reclaimed")?;
        let skipped = to_int(receipt.skipped, "skipped")?;
        let mode = receipt.mode.clone();
        let truncated = i64::from(receipt.truncated);
        self.in_txn(move |engine| {
            engine.execute(
                "INSERT INTO gc_receipts (seq, mode, planned, reclaimed, skipped, truncated) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                &[
                    SqlValue::Int(seq),
                    SqlValue::Text(mode),
                    SqlValue::Int(planned),
                    SqlValue::Int(reclaimed),
                    SqlValue::Int(skipped),
                    SqlValue::Int(truncated),
                ],
            )?;
            Ok(())
        })
    }

    fn add_gc_tombstone(
        &mut self,
        object_key: &str,
        store_path: &str,
        marked_seq: u64,
        grace_until_seq: u64,
    ) -> Result<(), StoreError> {
        let object_key = object_key.to_owned();
        let store_path = store_path.to_owned();
        let marked = i64::try_from(marked_seq)
            .map_err(|_| StoreError::Corruption("marked_seq out of range".into()))?;
        let grace = i64::try_from(grace_until_seq)
            .map_err(|_| StoreError::Corruption("grace_until_seq out of range".into()))?;
        self.in_txn(move |engine| {
            let existing = engine.query(
                "SELECT object_key FROM gc_tombstones WHERE object_key = ?1 AND store_path = ?2",
                &[
                    SqlValue::Text(object_key.clone()),
                    SqlValue::Text(store_path.clone()),
                ],
            )?;
            if !existing.is_empty() {
                // Idempotent re-mark keeps the ORIGINAL deadline.
                return Ok(());
            }
            engine.execute(
                "INSERT INTO gc_tombstones (object_key, store_path, marked_seq, grace_until_seq) \
                 VALUES (?1, ?2, ?3, ?4)",
                &[
                    SqlValue::Text(object_key),
                    SqlValue::Text(store_path),
                    SqlValue::Int(marked),
                    SqlValue::Int(grace),
                ],
            )?;
            Ok(())
        })
    }

    fn due_gc_tombstones(&mut self, now_seq: u64) -> Result<Vec<GcTombstoneRow>, StoreError> {
        // Clamp: any u64 beyond i64::MAX is later than every storable
        // deadline, so the clamp is semantically exact.
        let now = i64::try_from(now_seq).unwrap_or(i64::MAX);
        let rows = self.engine.query(
            "SELECT object_key, store_path, marked_seq, grace_until_seq FROM gc_tombstones \
             WHERE grace_until_seq <= ?1 ORDER BY object_key, store_path",
            &[SqlValue::Int(now)],
        )?;
        rows.into_iter()
            .map(|row| {
                let [key, path, marked, grace] = row.as_slice() else {
                    return Err(StoreError::Corruption("tombstone row shape".into()));
                };
                let (SqlValue::Text(key), SqlValue::Text(path)) = (key, path) else {
                    return Err(StoreError::Corruption("tombstone column shape".into()));
                };
                Ok(GcTombstoneRow {
                    object_key: key.clone(),
                    store_path: path.clone(),
                    marked_seq: expect_u64(marked, "marked_seq")?,
                    grace_until_seq: expect_u64(grace, "grace_until_seq")?,
                })
            })
            .collect()
    }

    fn remove_gc_tombstone(
        &mut self,
        object_key: &str,
        store_path: &str,
    ) -> Result<bool, StoreError> {
        let object_key = object_key.to_owned();
        let store_path = store_path.to_owned();
        self.in_txn(move |engine| {
            let removed = engine.execute(
                "DELETE FROM gc_tombstones WHERE object_key = ?1 AND store_path = ?2",
                &[SqlValue::Text(object_key), SqlValue::Text(store_path)],
            )?;
            Ok(removed > 0)
        })
    }

    fn list_publications(&mut self) -> Result<Vec<(String, String)>, StoreError> {
        let rows = self.engine.query(
            "SELECT action_key, pin_hex FROM action_publications ORDER BY action_key",
            &[],
        )?;
        rows.into_iter()
            .map(|row| match row.as_slice() {
                [SqlValue::Text(action), SqlValue::Text(pin)] => Ok((action.clone(), pin.clone())),
                _ => Err(StoreError::Corruption("publication list shape".into())),
            })
            .collect()
    }

    fn pin_row(&mut self, id: u128) -> Result<Option<PinRow>, StoreError> {
        let rows = self.engine.query(
            "SELECT root_key, owner, class, expires_at_seq, released, renewal_seq \
             FROM pins WHERE id_hex = ?1",
            &[SqlValue::Text(u128_hex(id))],
        )?;
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        let [root_key, owner, class, expires, released, renewal] = row.as_slice() else {
            return Err(StoreError::Corruption("pin row shape".into()));
        };
        let (SqlValue::Text(root_key), SqlValue::Text(owner), SqlValue::Text(class)) =
            (root_key, owner, class)
        else {
            return Err(StoreError::Corruption("pin column shape".into()));
        };
        let expires_at_seq = match expires {
            SqlValue::Null => None,
            other => Some(expect_u64(other, "expires_at_seq")?),
        };
        Ok(Some(PinRow {
            root_key: root_key.clone(),
            owner: owner.clone(),
            class: class.clone(),
            expires_at_seq,
            released: expect_u64(released, "released")? != 0,
            renewal_seq: expect_u64(renewal, "renewal_seq")?,
        }))
    }

    fn pin_released_by_hex(&mut self, pin_hex: &str) -> Result<Option<bool>, StoreError> {
        let rows = self.engine.query(
            "SELECT released FROM pins WHERE id_hex = ?1",
            &[SqlValue::Text(pin_hex.to_owned())],
        )?;
        match rows.first().and_then(|r| r.first()) {
            None => Ok(None),
            Some(v) => Ok(Some(expect_u64(v, "released")? != 0)),
        }
    }

    fn has_serving_state_key(&mut self, action_key: &str) -> Result<bool, StoreError> {
        let rows = self.engine.query(
            "SELECT action_key FROM action_serving_states WHERE action_key = ?1",
            &[SqlValue::Text(action_key.to_owned())],
        )?;
        Ok(!rows.is_empty())
    }

    fn has_evidence_key(&mut self, action_key: &str) -> Result<bool, StoreError> {
        let rows = self.engine.query(
            "SELECT action_key FROM action_evidence_index WHERE action_key = ?1 LIMIT 1",
            &[SqlValue::Text(action_key.to_owned())],
        )?;
        Ok(!rows.is_empty())
    }

    fn authority_count(&mut self) -> Result<u64, StoreError> {
        let rows = self
            .engine
            .query("SELECT COUNT(*) FROM coordinator_authorities", &[])?;
        match rows.first().and_then(|r| r.first()) {
            Some(v) => expect_u64(v, "authority count"),
            None => Err(StoreError::Corruption("count shape".into())),
        }
    }

    fn generation_count(&mut self) -> Result<u64, StoreError> {
        let rows = self
            .engine
            .query("SELECT COUNT(*) FROM action_generations", &[])?;
        match rows.first().and_then(|r| r.first()) {
            Some(v) => expect_u64(v, "generation count"),
            None => Err(StoreError::Corruption("count shape".into())),
        }
    }

    fn has_generation_high_water(&mut self) -> Result<bool, StoreError> {
        let rows = self.engine.query(
            "SELECT kind FROM generation_high_water WHERE kind = 'action-generation'",
            &[],
        )?;
        Ok(!rows.is_empty())
    }

    fn record_eviction_tombstone(
        &mut self,
        action: &TypedDigest,
        semantic: &TypedDigest,
        observable: &TypedDigest,
        evicted_seq: u64,
    ) -> Result<(), StoreError> {
        self.intern(semantic.domain);
        self.intern(observable.domain);
        let action = digest_key(action);
        let [s_algo, s_domain, s_bytes] = SqlMetadataStore::<E>::digest_params(semantic);
        let [o_algo, o_domain, o_bytes] = SqlMetadataStore::<E>::digest_params(observable);
        let seq = i64::try_from(evicted_seq)
            .map_err(|_| StoreError::Corruption("evicted_seq out of range".into()))?;
        self.in_txn(move |engine| {
            engine.execute(
                "INSERT OR REPLACE INTO eviction_tombstones \
                 (action_key, semantic_algo, semantic_domain, semantic_bytes, \
                  observable_algo, observable_domain, observable_bytes, evicted_seq) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                &[
                    SqlValue::Text(action),
                    s_algo,
                    s_domain,
                    s_bytes,
                    o_algo,
                    o_domain,
                    o_bytes,
                    SqlValue::Int(seq),
                ],
            )?;
            Ok(())
        })
    }

    fn eviction_tombstone(
        &mut self,
        action: &TypedDigest,
    ) -> Result<Option<(TypedDigest, TypedDigest)>, StoreError> {
        let rows = self.engine.query(
            "SELECT semantic_algo, semantic_domain, semantic_bytes, \
             observable_algo, observable_domain, observable_bytes \
             FROM eviction_tombstones WHERE action_key = ?1",
            &[SqlValue::Text(digest_key(action))],
        )?;
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        let [s_algo, s_domain, s_bytes, o_algo, o_domain, o_bytes] = row.as_slice() else {
            return Err(StoreError::Corruption("eviction tombstone shape".into()));
        };
        let semantic = self.restore_digest(s_algo, s_domain, s_bytes)?;
        let observable = self.restore_digest(o_algo, o_domain, o_bytes)?;
        Ok(Some((semantic, observable)))
    }

    fn consume_eviction_tombstone(&mut self, action: &TypedDigest) -> Result<bool, StoreError> {
        let action = digest_key(action);
        self.in_txn(move |engine| {
            let removed = engine.execute(
                "DELETE FROM eviction_tombstones WHERE action_key = ?1",
                &[SqlValue::Text(action)],
            )?;
            Ok(removed > 0)
        })
    }

    fn record_operator_reset(&mut self, generation: u64, seq: u64) -> Result<(), StoreError> {
        let generation_int = i64::try_from(generation)
            .map_err(|_| StoreError::Corruption("reset generation out of range".into()))?;
        let seq =
            i64::try_from(seq).map_err(|_| StoreError::Corruption("seq out of range".into()))?;
        self.in_txn(move |engine| {
            let rows = engine.query("SELECT MAX(generation) FROM operator_resets", &[])?;
            if let Some(SqlValue::Int(highest)) = rows.first().and_then(|r| r.first())
                && generation_int <= *highest
            {
                return Err(StoreError::StaleOperatorReset);
            }
            engine.execute(
                "INSERT INTO operator_resets (generation, applied_seq) VALUES (?1, ?2)",
                &[SqlValue::Int(generation_int), SqlValue::Int(seq)],
            )?;
            Ok(())
        })
    }

    fn highest_operator_reset(&mut self) -> Result<Option<u64>, StoreError> {
        let rows = self
            .engine
            .query("SELECT MAX(generation) FROM operator_resets", &[])?;
        match rows.first().and_then(|r| r.first()) {
            Some(SqlValue::Int(v)) => {
                Ok(Some(u64::try_from(*v).map_err(|_| {
                    StoreError::Corruption("negative reset generation".into())
                })?))
            }
            _ => Ok(None),
        }
    }

    fn serving_disposition_key(&mut self, action_key: &str) -> Result<Option<String>, StoreError> {
        let rows = self.engine.query(
            "SELECT disposition FROM action_serving_states WHERE action_key = ?1",
            &[SqlValue::Text(action_key.to_owned())],
        )?;
        match rows.first().and_then(|r| r.first()) {
            None => Ok(None),
            Some(SqlValue::Text(d)) => Ok(Some(d.clone())),
            Some(_) => Err(StoreError::Corruption("disposition shape".into())),
        }
    }

    fn set_serving_disposition_key(
        &mut self,
        action_key: &str,
        disposition: &str,
    ) -> Result<(), StoreError> {
        let action_key = action_key.to_owned();
        let disposition = disposition.to_owned();
        self.in_txn(move |engine| {
            // UPDATE first: a disposition-only write must never reset
            // the H040 revision/validity columns to their defaults.
            let changed = engine.execute(
                "UPDATE action_serving_states SET disposition = ?2 WHERE action_key = ?1",
                &[
                    SqlValue::Text(action_key.clone()),
                    SqlValue::Text(disposition.clone()),
                ],
            )?;
            if changed == 0 {
                engine.execute(
                    "INSERT INTO action_serving_states (action_key, disposition, version) \
                     VALUES (?1, ?2, 1)",
                    &[SqlValue::Text(action_key), SqlValue::Text(disposition)],
                )?;
            }
            Ok(())
        })
    }

    fn record_peer_authority_high_water(
        &mut self,
        authority: &TypedDigest,
        peer_id: &str,
        term: u64,
        observed_seq: u64,
    ) -> Result<(), StoreError> {
        let authority = authority.clone();
        let peer = peer_id.to_owned();
        let term_int = to_seq(term, "term")?;
        let observed = to_seq(observed_seq, "observed_seq")?;
        self.in_txn(move |engine| {
            SqlMetadataStore::<E>::require_active(engine, &authority)?;
            let rows = engine.query(
                "SELECT term FROM peer_authority_high_water WHERE peer_id = ?1",
                &[SqlValue::Text(peer.clone())],
            )?;
            if let Some(row) = rows.first() {
                let stored = expect_u64(
                    row.first()
                        .ok_or_else(|| StoreError::Corruption("peer high-water shape".into()))?,
                    "peer term",
                )?;
                if term < stored {
                    return Err(StoreError::StalePeerAuthority);
                }
                if term == stored {
                    return Ok(()); // idempotent
                }
            }
            engine.execute(
                "INSERT OR REPLACE INTO peer_authority_high_water \
                 (peer_id, term, observed_seq) VALUES (?1, ?2, ?3)",
                &[
                    SqlValue::Text(peer),
                    SqlValue::Int(term_int),
                    SqlValue::Int(observed),
                ],
            )?;
            Ok(())
        })
    }

    fn peer_authority_high_water(
        &mut self,
        peer_id: &str,
    ) -> Result<Option<(u64, u64)>, StoreError> {
        let rows = self.engine.query(
            "SELECT term, observed_seq FROM peer_authority_high_water WHERE peer_id = ?1",
            &[SqlValue::Text(peer_id.to_owned())],
        )?;
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        let [term, observed] = row.as_slice() else {
            return Err(StoreError::Corruption("peer high-water shape".into()));
        };
        Ok(Some((
            expect_u64(term, "peer term")?,
            expect_u64(observed, "observed_seq")?,
        )))
    }

    fn admit_worker_session(
        &mut self,
        authority: &TypedDigest,
        offer: &WorkerSessionOffer,
        started_seq: u64,
    ) -> Result<WorkerAdmission, StoreError> {
        let authority = authority.clone();
        let offer = offer.clone();
        let worker = offer.worker_peer_id.0.clone();
        let started = to_seq(started_seq, "started_seq")?;
        self.in_txn(move |engine| {
            SqlMetadataStore::<E>::require_active(engine, &authority)?;
            let rows = engine.query(
                "SELECT highest_boot_generation, incarnation, active, \
                 operator_reenrollment_generation, clone_ambiguous \
                 FROM worker_incarnation_fences \
                 WHERE worker = ?1",
                &[SqlValue::Text(worker.clone())],
            )?;
            let (admission, fence, revoke_prior_leases) = match rows.as_slice() {
                [] => (
                    WorkerAdmission::AdmitNewGeneration,
                    WorkerIncarnationFenceRecord {
                        worker_peer_id: offer.worker_peer_id.clone(),
                        highest_boot_generation: offer.boot_generation,
                        active_incarnation: Some(offer.incarnation),
                        clone_ambiguous: false,
                        operator_reenrollment_generation: offer
                            .reenrollment_proof
                            .unwrap_or_default(),
                    },
                    false,
                ),
                [row] => {
                    let prior_incarnation =
                        WorkerIncarnationId(expect_u128(&row[1], "worker incarnation")?);
                    let mut fence = decode_worker_incarnation_fence(&worker, row)?;
                    let admission = fence.evaluate(&offer);
                    let revoke_prior_leases = match admission {
                        WorkerAdmission::AdmitNewGeneration => {
                            fence.highest_boot_generation = offer.boot_generation;
                            fence.active_incarnation = Some(offer.incarnation);
                            fence.clone_ambiguous = false;
                            true
                        }
                        WorkerAdmission::AdmitReconnect => false,
                        WorkerAdmission::AdmitResume => {
                            fence.active_incarnation = Some(offer.incarnation);
                            prior_incarnation != offer.incarnation
                        }
                        WorkerAdmission::AdmitViaReenrollment => {
                            let proof = offer.reenrollment_proof.ok_or_else(|| {
                                StoreError::Corruption(
                                    "reenrollment admission without proof".into(),
                                )
                            })?;
                            // `evaluate` admits re-enrollment only at or
                            // above the durable global high-water. Never
                            // lower it: an old clone at the former mark
                            // must remain stale after operator recovery.
                            fence.highest_boot_generation = offer.boot_generation;
                            fence.active_incarnation = Some(offer.incarnation);
                            fence.clone_ambiguous = false;
                            fence.operator_reenrollment_generation = proof;
                            true
                        }
                        WorkerAdmission::RejectCloneAmbiguity => {
                            engine.execute(
                                "UPDATE worker_incarnation_fences \
                                 SET clone_ambiguous = 1 WHERE worker = ?1",
                                &[SqlValue::Text(worker.clone())],
                            )?;
                            SqlMetadataStore::<E>::revoke_worker_leases(engine, &worker)?;
                            return Ok(admission);
                        }
                        WorkerAdmission::RejectStaleBootGeneration
                        | WorkerAdmission::RejectIdentityMismatch => return Ok(admission),
                    };
                    (admission, fence, revoke_prior_leases)
                }
                _ => {
                    return Err(StoreError::Corruption("duplicate worker fence rows".into()));
                }
            };

            if revoke_prior_leases {
                SqlMetadataStore::<E>::revoke_worker_leases(engine, &worker)?;
            }

            let active_incarnation = fence.active_incarnation.ok_or_else(|| {
                StoreError::Corruption("admitted worker fence is inactive".into())
            })?;
            let existing = engine.query(
                "SELECT incarnation, ended_seq FROM worker_sessions \
                 WHERE worker = ?1 AND started_seq = ?2",
                &[SqlValue::Text(worker.clone()), SqlValue::Int(started)],
            )?;
            let insert_session = match existing.as_slice() {
                [] => true,
                [row] => {
                    let [stored_incarnation, ended_seq] = row.as_slice() else {
                        return Err(StoreError::Corruption("worker session shape".into()));
                    };
                    if expect_u128(stored_incarnation, "session incarnation")?
                        == active_incarnation.0
                        && matches!(ended_seq, SqlValue::Null)
                    {
                        false
                    } else {
                        return Err(StoreError::AppendConflict("worker_sessions".into()));
                    }
                }
                _ => {
                    return Err(StoreError::Corruption(
                        "duplicate worker session rows".into(),
                    ));
                }
            };

            engine.execute(
                "INSERT OR REPLACE INTO worker_incarnation_fences \
                 (worker, incarnation, highest_boot_generation, active, \
                  operator_reenrollment_generation, clone_ambiguous) \
                 VALUES (?1, ?2, ?3, 1, ?4, ?5)",
                &[
                    SqlValue::Text(worker.clone()),
                    SqlValue::Blob(u128_blob(active_incarnation.0)),
                    SqlValue::Blob(u64_blob(fence.highest_boot_generation.0)),
                    SqlValue::Blob(u64_blob(fence.operator_reenrollment_generation)),
                    SqlValue::Int(i64::from(fence.clone_ambiguous)),
                ],
            )?;
            if insert_session {
                engine.execute(
                    "INSERT INTO worker_sessions \
                     (worker, incarnation, started_seq, ended_seq) VALUES (?1, ?2, ?3, NULL)",
                    &[
                        SqlValue::Text(worker),
                        SqlValue::Blob(u128_blob(active_incarnation.0)),
                        SqlValue::Int(started),
                    ],
                )?;
            }
            Ok(admission)
        })
    }

    fn release_worker_session(
        &mut self,
        authority: &TypedDigest,
        worker: &PeerId,
        incarnation: WorkerIncarnationId,
        started_seq: u64,
        ended_seq: u64,
    ) -> Result<bool, StoreError> {
        let authority = authority.clone();
        let worker = worker.0.clone();
        let started = to_seq(started_seq, "started_seq")?;
        let ended = to_seq(ended_seq, "ended_seq")?;
        self.in_txn(move |engine| {
            SqlMetadataStore::<E>::require_active(engine, &authority)?;
            let rows = engine.query(
                "SELECT highest_boot_generation, incarnation, active, \
                 operator_reenrollment_generation, clone_ambiguous \
                 FROM worker_incarnation_fences \
                 WHERE worker = ?1",
                &[SqlValue::Text(worker.clone())],
            )?;
            let fence = match rows.as_slice() {
                [] => return Ok(false),
                [row] => decode_worker_incarnation_fence(&worker, row)?,
                _ => {
                    return Err(StoreError::Corruption("duplicate worker fence rows".into()));
                }
            };
            if fence.active_incarnation != Some(incarnation) {
                return Ok(false);
            }
            let ended_session = engine.execute(
                "UPDATE worker_sessions SET ended_seq = ?1 \
                 WHERE worker = ?2 AND incarnation = ?3 AND started_seq = ?4 \
                 AND ended_seq IS NULL",
                &[
                    SqlValue::Int(ended),
                    SqlValue::Text(worker.clone()),
                    SqlValue::Blob(u128_blob(incarnation.0)),
                    SqlValue::Int(started),
                ],
            )?;
            if ended_session == 0 {
                return Ok(false);
            }
            let remaining = engine.query(
                "SELECT COUNT(*) FROM worker_sessions \
                 WHERE worker = ?1 AND incarnation = ?2 AND ended_seq IS NULL",
                &[
                    SqlValue::Text(worker.clone()),
                    SqlValue::Blob(u128_blob(incarnation.0)),
                ],
            )?;
            let remaining = match remaining.as_slice() {
                [row] => match row.as_slice() {
                    [value] => expect_u64(value, "open worker session count")?,
                    _ => {
                        return Err(StoreError::Corruption(
                            "open worker session count shape".into(),
                        ));
                    }
                },
                _ => {
                    return Err(StoreError::Corruption(
                        "open worker session count shape".into(),
                    ));
                }
            };
            if remaining > 0 {
                return Ok(true);
            }
            let cleared = engine.execute(
                "UPDATE worker_incarnation_fences SET active = 0 \
                 WHERE worker = ?1 AND incarnation = ?2 AND active = 1",
                &[
                    SqlValue::Text(worker),
                    SqlValue::Blob(u128_blob(incarnation.0)),
                ],
            )?;
            if cleared != 1 {
                return Err(StoreError::Corruption(
                    "worker session ended without clearing its fence".into(),
                ));
            }
            Ok(true)
        })
    }

    fn worker_incarnation_fence(
        &mut self,
        worker: &PeerId,
    ) -> Result<Option<WorkerIncarnationFenceRecord>, StoreError> {
        let rows = self.engine.query(
            "SELECT highest_boot_generation, incarnation, active, \
             operator_reenrollment_generation, clone_ambiguous \
             FROM worker_incarnation_fences \
             WHERE worker = ?1",
            &[SqlValue::Text(worker.0.clone())],
        )?;
        match rows.as_slice() {
            [] => Ok(None),
            [row] => decode_worker_incarnation_fence(&worker.0, row).map(Some),
            _ => Err(StoreError::Corruption("duplicate worker fence rows".into())),
        }
    }

    fn advance_edge_fence(
        &mut self,
        authority: &TypedDigest,
        edge_id: &str,
        incarnation: u128,
    ) -> Result<(), StoreError> {
        let authority = authority.clone();
        let edge = edge_id.to_owned();
        self.in_txn(move |engine| {
            SqlMetadataStore::<E>::require_active(engine, &authority)?;
            let rows = engine.query(
                "SELECT incarnation FROM edge_incarnation_fences WHERE edge_id = ?1",
                &[SqlValue::Text(edge.clone())],
            )?;
            if let Some(row) = rows.first() {
                let stored = expect_u128(
                    row.first()
                        .ok_or_else(|| StoreError::Corruption("edge fence shape".into()))?,
                    "edge fence",
                )?;
                if incarnation < stored {
                    return Err(StoreError::StaleEdgeIncarnation);
                }
                if incarnation == stored {
                    return Ok(()); // idempotent
                }
            }
            engine.execute(
                "INSERT OR REPLACE INTO edge_incarnation_fences (edge_id, incarnation) \
                 VALUES (?1, ?2)",
                &[SqlValue::Text(edge), SqlValue::Blob(u128_blob(incarnation))],
            )?;
            Ok(())
        })
    }

    fn edge_fence(&mut self, edge_id: &str) -> Result<Option<u128>, StoreError> {
        let rows = self.engine.query(
            "SELECT incarnation FROM edge_incarnation_fences WHERE edge_id = ?1",
            &[SqlValue::Text(edge_id.to_owned())],
        )?;
        match rows.first().and_then(|r| r.first()) {
            None => Ok(None),
            Some(v) => Ok(Some(expect_u128(v, "edge fence")?)),
        }
    }

    fn begin_edge_handoff(
        &mut self,
        authority: &TypedDigest,
        edge_id: &str,
        active_incarnation: u128,
        predecessor_incarnation: u128,
        begun_seq: u64,
    ) -> Result<(), StoreError> {
        let authority = authority.clone();
        let edge = edge_id.to_owned();
        let begun = to_seq(begun_seq, "begun_seq")?;
        self.in_txn(move |engine| {
            SqlMetadataStore::<E>::require_active(engine, &authority)?;
            // At most one handoff row per edge; only a RESOLVED row may
            // be replaced.
            let rows = engine.query(
                "SELECT active_incarnation, predecessor_incarnation, resolved \
                 FROM edge_handoffs WHERE edge_id = ?1",
                &[SqlValue::Text(edge.clone())],
            )?;
            if let Some(row) = rows.first() {
                let [active, predecessor, resolved] = row.as_slice() else {
                    return Err(StoreError::Corruption("edge handoff shape".into()));
                };
                if expect_u64(resolved, "resolved")? == 0 {
                    if expect_u128(active, "active incarnation")? == active_incarnation
                        && expect_u128(predecessor, "predecessor incarnation")?
                            == predecessor_incarnation
                    {
                        return Ok(()); // idempotent re-begin
                    }
                    return Err(StoreError::EdgeHandoffActive);
                }
            }
            // The NAMED predecessor must be the fenced incarnation when
            // a fence exists.
            let fence = engine.query(
                "SELECT incarnation FROM edge_incarnation_fences WHERE edge_id = ?1",
                &[SqlValue::Text(edge.clone())],
            )?;
            if let Some(v) = fence.first().and_then(|r| r.first())
                && expect_u128(v, "edge fence")? != predecessor_incarnation
            {
                return Err(StoreError::EdgeHandoffPredecessorMismatch);
            }
            if active_incarnation <= predecessor_incarnation {
                return Err(StoreError::StaleEdgeIncarnation);
            }
            engine.execute(
                "INSERT OR REPLACE INTO edge_handoffs \
                 (edge_id, active_incarnation, predecessor_incarnation, begun_seq, resolved) \
                 VALUES (?1, ?2, ?3, ?4, 0)",
                &[
                    SqlValue::Text(edge),
                    SqlValue::Blob(u128_blob(active_incarnation)),
                    SqlValue::Blob(u128_blob(predecessor_incarnation)),
                    SqlValue::Int(begun),
                ],
            )?;
            Ok(())
        })
    }

    fn resolve_edge_handoff(
        &mut self,
        authority: &TypedDigest,
        edge_id: &str,
        active_incarnation: u128,
    ) -> Result<(), StoreError> {
        let authority = authority.clone();
        let edge = edge_id.to_owned();
        self.in_txn(move |engine| {
            SqlMetadataStore::<E>::require_active(engine, &authority)?;
            let rows = engine.query(
                "SELECT active_incarnation, resolved FROM edge_handoffs WHERE edge_id = ?1",
                &[SqlValue::Text(edge.clone())],
            )?;
            let Some(row) = rows.first() else {
                return Err(StoreError::UnknownEdgeHandoff);
            };
            let [active, resolved] = row.as_slice() else {
                return Err(StoreError::Corruption("edge handoff shape".into()));
            };
            if expect_u64(resolved, "resolved")? != 0
                || expect_u128(active, "active incarnation")? != active_incarnation
            {
                return Err(StoreError::UnknownEdgeHandoff);
            }
            engine.execute(
                "UPDATE edge_handoffs SET resolved = 1 WHERE edge_id = ?1",
                &[SqlValue::Text(edge.clone())],
            )?;
            // Fence advance in the SAME transaction: the handoff is not
            // resolved unless the edge is fenced at the new incarnation.
            engine.execute(
                "INSERT OR REPLACE INTO edge_incarnation_fences (edge_id, incarnation) \
                 VALUES (?1, ?2)",
                &[
                    SqlValue::Text(edge),
                    SqlValue::Blob(u128_blob(active_incarnation)),
                ],
            )?;
            Ok(())
        })
    }

    fn active_edge_handoff(&mut self, edge_id: &str) -> Result<Option<EdgeHandoffRow>, StoreError> {
        let rows = self.engine.query(
            "SELECT active_incarnation, predecessor_incarnation, begun_seq \
             FROM edge_handoffs WHERE edge_id = ?1 AND resolved = 0",
            &[SqlValue::Text(edge_id.to_owned())],
        )?;
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        let [active, predecessor, begun] = row.as_slice() else {
            return Err(StoreError::Corruption("edge handoff shape".into()));
        };
        Ok(Some(EdgeHandoffRow {
            active_incarnation: expect_u128(active, "active incarnation")?,
            predecessor_incarnation: expect_u128(predecessor, "predecessor incarnation")?,
            begun_seq: expect_u64(begun, "begun_seq")?,
        }))
    }

    fn append_trust_evaluation(
        &mut self,
        authority: &TypedDigest,
        action: &TypedDigest,
        row: &TrustEvaluationRow,
    ) -> Result<(), StoreError> {
        let authority = authority.clone();
        let action = digest_key(action);
        let row = row.clone();
        let evaluated = to_seq(row.evaluated_seq, "evaluated_seq")?;
        self.in_txn(move |engine| {
            SqlMetadataStore::<E>::require_active(engine, &authority)?;
            let stored = engine.query(
                "SELECT MAX(version) FROM action_trust_evaluations WHERE action_key = ?1",
                &[SqlValue::Text(action.clone())],
            )?;
            if let Some(SqlValue::Int(max)) = stored.first().and_then(|r| r.first())
                && u64::from(row.version) <= u64::try_from(*max).unwrap_or(0)
            {
                return Err(StoreError::NonMonotonicTrustEvaluation);
            }
            engine.execute(
                "INSERT INTO action_trust_evaluations \
                 (action_key, version, state, reason, evaluated_seq) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                &[
                    SqlValue::Text(action),
                    SqlValue::Int(i64::from(row.version)),
                    SqlValue::Text(row.state),
                    SqlValue::Text(row.reason),
                    SqlValue::Int(evaluated),
                ],
            )?;
            Ok(())
        })
    }

    fn latest_trust_evaluation(
        &mut self,
        action: &TypedDigest,
    ) -> Result<Option<TrustEvaluationRow>, StoreError> {
        let rows = self.engine.query(
            "SELECT version, state, reason, evaluated_seq FROM action_trust_evaluations \
             WHERE action_key = ?1 ORDER BY version DESC LIMIT 1",
            &[SqlValue::Text(digest_key(action))],
        )?;
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        let [version, state, reason, evaluated] = row.as_slice() else {
            return Err(StoreError::Corruption("trust evaluation shape".into()));
        };
        Ok(Some(TrustEvaluationRow {
            version: u32::try_from(expect_u64(version, "version")?)
                .map_err(|_| StoreError::Corruption("version out of range".into()))?,
            state: expect_text(state, "state")?,
            reason: expect_text(reason, "reason")?,
            evaluated_seq: expect_u64(evaluated, "evaluated_seq")?,
        }))
    }

    fn create_operation(
        &mut self,
        authority: &TypedDigest,
        id: u128,
        kind: &str,
        state: &str,
        seq: u64,
    ) -> Result<(), StoreError> {
        let authority = authority.clone();
        let kind = kind.to_owned();
        let state = state.to_owned();
        let seq = to_seq(seq, "seq")?;
        self.in_txn(move |engine| {
            SqlMetadataStore::<E>::require_active(engine, &authority)?;
            let existing = engine.query(
                "SELECT id_hex FROM operations WHERE id_hex = ?1",
                &[SqlValue::Text(u128_hex(id))],
            )?;
            if !existing.is_empty() {
                return Err(StoreError::DuplicateOperation);
            }
            engine.execute(
                "INSERT INTO operations (id_hex, id, kind, state, updated_seq) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                &[
                    SqlValue::Text(u128_hex(id)),
                    SqlValue::Blob(u128_blob(id)),
                    SqlValue::Text(kind),
                    SqlValue::Text(state),
                    SqlValue::Int(seq),
                ],
            )?;
            Ok(())
        })
    }

    fn update_operation_state(
        &mut self,
        id: u128,
        state: &str,
        seq: u64,
    ) -> Result<(), StoreError> {
        let state = state.to_owned();
        let seq = to_seq(seq, "seq")?;
        self.in_txn(move |engine| {
            let changed = engine.execute(
                "UPDATE operations SET state = ?1, updated_seq = ?2 WHERE id_hex = ?3",
                &[
                    SqlValue::Text(state),
                    SqlValue::Int(seq),
                    SqlValue::Text(u128_hex(id)),
                ],
            )?;
            if changed == 0 {
                return Err(StoreError::UnknownOperation);
            }
            Ok(())
        })
    }

    fn operation_state(&mut self, id: u128) -> Result<Option<String>, StoreError> {
        let rows = self.engine.query(
            "SELECT state FROM operations WHERE id_hex = ?1",
            &[SqlValue::Text(u128_hex(id))],
        )?;
        match rows.first().and_then(|r| r.first()) {
            None => Ok(None),
            Some(v) => Ok(Some(expect_text(v, "operation state")?)),
        }
    }

    fn register_edge_subscriber(
        &mut self,
        edge_id: &str,
        subscriber: &str,
        registered_seq: u64,
    ) -> Result<(), StoreError> {
        let edge = edge_id.to_owned();
        let subscriber = subscriber.to_owned();
        let seq = to_seq(registered_seq, "registered_seq")?;
        self.in_txn(move |engine| {
            engine.execute(
                "INSERT OR IGNORE INTO edge_subscribers (edge_id, subscriber, registered_seq) \
                 VALUES (?1, ?2, ?3)",
                &[
                    SqlValue::Text(edge),
                    SqlValue::Text(subscriber),
                    SqlValue::Int(seq),
                ],
            )?;
            Ok(())
        })
    }

    fn remove_edge_subscriber(
        &mut self,
        edge_id: &str,
        subscriber: &str,
    ) -> Result<bool, StoreError> {
        let edge = edge_id.to_owned();
        let subscriber = subscriber.to_owned();
        self.in_txn(move |engine| {
            let changed = engine.execute(
                "DELETE FROM edge_subscribers WHERE edge_id = ?1 AND subscriber = ?2",
                &[SqlValue::Text(edge), SqlValue::Text(subscriber)],
            )?;
            Ok(changed > 0)
        })
    }

    fn list_edge_subscribers(&mut self, edge_id: &str) -> Result<Vec<String>, StoreError> {
        let rows = self.engine.query(
            "SELECT subscriber FROM edge_subscribers WHERE edge_id = ?1 ORDER BY subscriber",
            &[SqlValue::Text(edge_id.to_owned())],
        )?;
        rows.iter()
            .map(|row| {
                expect_text(
                    row.first()
                        .ok_or_else(|| StoreError::Corruption("subscriber shape".into()))?,
                    "subscriber",
                )
            })
            .collect()
    }

    fn record_manifest(
        &mut self,
        manifest: &TypedDigest,
        kind: &str,
        entry_count: u64,
    ) -> Result<(), StoreError> {
        self.intern(manifest.domain);
        let key = digest_key(manifest);
        let [algo, domain, bytes] = SqlMetadataStore::<E>::digest_params(manifest);
        let kind = kind.to_owned();
        let count = to_seq(entry_count, "entry_count")?;
        self.in_txn(move |engine| {
            let existing = engine.query(
                "SELECT kind, entry_count FROM manifests WHERE key = ?1",
                &[SqlValue::Text(key.clone())],
            )?;
            if let Some(row) = existing.first() {
                let [stored_kind, stored_count] = row.as_slice() else {
                    return Err(StoreError::Corruption("manifest row shape".into()));
                };
                if expect_text(stored_kind, "manifest kind")? == kind
                    && expect_u64(stored_count, "entry_count")? == entry_count
                {
                    return Ok(()); // idempotent
                }
                return Err(StoreError::ManifestDivergence);
            }
            engine.execute(
                "INSERT INTO manifests (key, algo, domain, bytes, kind, entry_count) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                &[
                    SqlValue::Text(key),
                    algo,
                    domain,
                    bytes,
                    SqlValue::Text(kind),
                    SqlValue::Int(count),
                ],
            )?;
            Ok(())
        })
    }

    fn manifest_meta(
        &mut self,
        manifest: &TypedDigest,
    ) -> Result<Option<(String, u64)>, StoreError> {
        let rows = self.engine.query(
            "SELECT kind, entry_count FROM manifests WHERE key = ?1",
            &[SqlValue::Text(digest_key(manifest))],
        )?;
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        let [kind, count] = row.as_slice() else {
            return Err(StoreError::Corruption("manifest row shape".into()));
        };
        Ok(Some((
            expect_text(kind, "manifest kind")?,
            expect_u64(count, "entry_count")?,
        )))
    }

    fn record_worker_session(
        &mut self,
        worker: &str,
        incarnation: u128,
        started_seq: u64,
    ) -> Result<(), StoreError> {
        let worker = worker.to_owned();
        let started = to_seq(started_seq, "started_seq")?;
        self.in_txn(move |engine| {
            let existing = engine.query(
                "SELECT incarnation FROM worker_sessions WHERE worker = ?1 AND started_seq = ?2",
                &[SqlValue::Text(worker.clone()), SqlValue::Int(started)],
            )?;
            if let Some(row) = existing.first() {
                let stored = expect_u128(
                    row.first()
                        .ok_or_else(|| StoreError::Corruption("worker session shape".into()))?,
                    "session incarnation",
                )?;
                if stored == incarnation {
                    return Ok(()); // idempotent
                }
                return Err(StoreError::AppendConflict("worker_sessions".into()));
            }
            engine.execute(
                "INSERT INTO worker_sessions (worker, incarnation, started_seq, ended_seq) \
                 VALUES (?1, ?2, ?3, NULL)",
                &[
                    SqlValue::Text(worker),
                    SqlValue::Blob(u128_blob(incarnation)),
                    SqlValue::Int(started),
                ],
            )?;
            Ok(())
        })
    }

    fn end_worker_session(
        &mut self,
        worker: &str,
        started_seq: u64,
        ended_seq: u64,
    ) -> Result<bool, StoreError> {
        let worker = worker.to_owned();
        let started = to_seq(started_seq, "started_seq")?;
        let ended = to_seq(ended_seq, "ended_seq")?;
        self.in_txn(move |engine| {
            let changed = engine.execute(
                "UPDATE worker_sessions SET ended_seq = ?1 \
                 WHERE worker = ?2 AND started_seq = ?3 AND ended_seq IS NULL",
                &[
                    SqlValue::Int(ended),
                    SqlValue::Text(worker),
                    SqlValue::Int(started),
                ],
            )?;
            Ok(changed > 0)
        })
    }

    fn record_worker_capability(
        &mut self,
        worker: &str,
        capability: &str,
    ) -> Result<(), StoreError> {
        let worker = worker.to_owned();
        let capability = capability.to_owned();
        self.in_txn(move |engine| {
            engine.execute(
                "INSERT OR IGNORE INTO worker_capabilities (worker, capability) \
                 VALUES (?1, ?2)",
                &[SqlValue::Text(worker), SqlValue::Text(capability)],
            )?;
            Ok(())
        })
    }

    fn list_worker_capabilities(&mut self, worker: &str) -> Result<Vec<String>, StoreError> {
        let rows = self.engine.query(
            "SELECT capability FROM worker_capabilities WHERE worker = ?1 ORDER BY capability",
            &[SqlValue::Text(worker.to_owned())],
        )?;
        rows.iter()
            .map(|row| {
                expect_text(
                    row.first()
                        .ok_or_else(|| StoreError::Corruption("capability shape".into()))?,
                    "capability",
                )
            })
            .collect()
    }

    fn record_worker_health_sample(
        &mut self,
        worker: &str,
        seq: u64,
        healthy: bool,
        detail: &str,
    ) -> Result<(), StoreError> {
        let worker = worker.to_owned();
        let seq = to_seq(seq, "seq")?;
        let detail = detail.to_owned();
        let healthy_int = i64::from(healthy);
        self.in_txn(move |engine| {
            let existing = engine.query(
                "SELECT healthy, detail FROM worker_health_samples \
                 WHERE worker = ?1 AND seq = ?2",
                &[SqlValue::Text(worker.clone()), SqlValue::Int(seq)],
            )?;
            if let Some(row) = existing.first() {
                let [stored_healthy, stored_detail] = row.as_slice() else {
                    return Err(StoreError::Corruption("health sample shape".into()));
                };
                if expect_u64(stored_healthy, "healthy")? == u64::from(healthy)
                    && expect_text(stored_detail, "detail")? == detail
                {
                    return Ok(()); // idempotent
                }
                return Err(StoreError::AppendConflict("worker_health_samples".into()));
            }
            engine.execute(
                "INSERT INTO worker_health_samples (worker, seq, healthy, detail) \
                 VALUES (?1, ?2, ?3, ?4)",
                &[
                    SqlValue::Text(worker),
                    SqlValue::Int(seq),
                    SqlValue::Int(healthy_int),
                    SqlValue::Text(detail),
                ],
            )?;
            Ok(())
        })
    }

    fn record_decision_receipt(
        &mut self,
        kind: &str,
        subject: &str,
        seq: u64,
        decision: &str,
        reason: &str,
    ) -> Result<(), StoreError> {
        let kind = kind.to_owned();
        let subject = subject.to_owned();
        let seq = to_seq(seq, "seq")?;
        let decision = decision.to_owned();
        let reason = reason.to_owned();
        self.in_txn(move |engine| {
            let existing = engine.query(
                "SELECT decision, reason FROM decision_receipts \
                 WHERE kind = ?1 AND subject = ?2 AND seq = ?3",
                &[
                    SqlValue::Text(kind.clone()),
                    SqlValue::Text(subject.clone()),
                    SqlValue::Int(seq),
                ],
            )?;
            if let Some(row) = existing.first() {
                let [stored_decision, stored_reason] = row.as_slice() else {
                    return Err(StoreError::Corruption("decision receipt shape".into()));
                };
                if expect_text(stored_decision, "decision")? == decision
                    && expect_text(stored_reason, "reason")? == reason
                {
                    return Ok(()); // idempotent
                }
                return Err(StoreError::AppendConflict("decision_receipts".into()));
            }
            engine.execute(
                "INSERT INTO decision_receipts (kind, subject, seq, decision, reason) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                &[
                    SqlValue::Text(kind),
                    SqlValue::Text(subject),
                    SqlValue::Int(seq),
                    SqlValue::Text(decision),
                    SqlValue::Text(reason),
                ],
            )?;
            Ok(())
        })
    }

    fn add_provenance_edge(
        &mut self,
        from: &TypedDigest,
        to: &TypedDigest,
        kind: &str,
    ) -> Result<(), StoreError> {
        let from = digest_key(from);
        let to = digest_key(to);
        let kind = kind.to_owned();
        self.in_txn(move |engine| {
            engine.execute(
                "INSERT OR IGNORE INTO provenance_edges (from_key, to_key, kind) \
                 VALUES (?1, ?2, ?3)",
                &[
                    SqlValue::Text(from),
                    SqlValue::Text(to),
                    SqlValue::Text(kind),
                ],
            )?;
            Ok(())
        })
    }

    fn record_determinism_audit(
        &mut self,
        action: &TypedDigest,
        attempt: u128,
        seq: u64,
        verdict: &str,
    ) -> Result<(), StoreError> {
        let action = digest_key(action);
        let seq = to_seq(seq, "seq")?;
        let verdict = verdict.to_owned();
        self.in_txn(move |engine| {
            let existing = engine.query(
                "SELECT verdict FROM determinism_audits \
                 WHERE action_key = ?1 AND attempt_hex = ?2 AND seq = ?3",
                &[
                    SqlValue::Text(action.clone()),
                    SqlValue::Text(u128_hex(attempt)),
                    SqlValue::Int(seq),
                ],
            )?;
            if let Some(row) = existing.first() {
                let stored = expect_text(
                    row.first()
                        .ok_or_else(|| StoreError::Corruption("determinism audit shape".into()))?,
                    "verdict",
                )?;
                if stored == verdict {
                    return Ok(()); // idempotent
                }
                return Err(StoreError::AppendConflict("determinism_audits".into()));
            }
            engine.execute(
                "INSERT INTO determinism_audits (action_key, attempt_hex, seq, verdict) \
                 VALUES (?1, ?2, ?3, ?4)",
                &[
                    SqlValue::Text(action),
                    SqlValue::Text(u128_hex(attempt)),
                    SqlValue::Int(seq),
                    SqlValue::Text(verdict),
                ],
            )?;
            Ok(())
        })
    }

    fn create_materialization(
        &mut self,
        id: u128,
        root: &TypedDigest,
        dest_path: &str,
        state: &str,
        seq: u64,
    ) -> Result<(), StoreError> {
        let root = digest_key(root);
        let dest = dest_path.to_owned();
        let state = state.to_owned();
        let seq = to_seq(seq, "seq")?;
        self.in_txn(move |engine| {
            let existing = engine.query(
                "SELECT root_key, dest_path FROM materialization_records WHERE id_hex = ?1",
                &[SqlValue::Text(u128_hex(id))],
            )?;
            if let Some(row) = existing.first() {
                let [stored_root, stored_dest] = row.as_slice() else {
                    return Err(StoreError::Corruption("materialization shape".into()));
                };
                if expect_text(stored_root, "root_key")? == root
                    && expect_text(stored_dest, "dest_path")? == dest
                {
                    return Ok(()); // idempotent
                }
                return Err(StoreError::AppendConflict("materialization_records".into()));
            }
            engine.execute(
                "INSERT INTO materialization_records \
                 (id_hex, id, root_key, dest_path, state, updated_seq) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                &[
                    SqlValue::Text(u128_hex(id)),
                    SqlValue::Blob(u128_blob(id)),
                    SqlValue::Text(root),
                    SqlValue::Text(dest),
                    SqlValue::Text(state),
                    SqlValue::Int(seq),
                ],
            )?;
            Ok(())
        })
    }

    fn update_materialization_state(
        &mut self,
        id: u128,
        state: &str,
        seq: u64,
    ) -> Result<(), StoreError> {
        let state = state.to_owned();
        let seq = to_seq(seq, "seq")?;
        self.in_txn(move |engine| {
            let changed = engine.execute(
                "UPDATE materialization_records SET state = ?1, updated_seq = ?2 \
                 WHERE id_hex = ?3",
                &[
                    SqlValue::Text(state),
                    SqlValue::Int(seq),
                    SqlValue::Text(u128_hex(id)),
                ],
            )?;
            if changed == 0 {
                return Err(StoreError::UnknownMaterialization);
            }
            Ok(())
        })
    }

    fn materialization_state(&mut self, id: u128) -> Result<Option<String>, StoreError> {
        let rows = self.engine.query(
            "SELECT state FROM materialization_records WHERE id_hex = ?1",
            &[SqlValue::Text(u128_hex(id))],
        )?;
        match rows.first().and_then(|r| r.first()) {
            None => Ok(None),
            Some(v) => Ok(Some(expect_text(v, "materialization state")?)),
        }
    }

    fn put_serving_record(
        &mut self,
        authority: &TypedDigest,
        action_key: &str,
        disposition: &str,
        state_revision: u64,
        validity: &ServingValidity,
        blocking: &[(QuarantineScope, String)],
    ) -> Result<(), StoreError> {
        let authority = authority.clone();
        let action_key = action_key.to_owned();
        let disposition = disposition.to_owned();
        let revision = to_seq(state_revision, "state_revision")?;
        let evaluated_at = validity.evaluated_at_unix_micros;
        let max_age = validity
            .maximum_age_micros
            .map(|v| to_seq(v, "max_age_micros"))
            .transpose()?;
        let uncertainty = to_seq(
            validity.clock_uncertainty_micros,
            "clock_uncertainty_micros",
        )?;
        let epoch = to_seq(validity.coordinator_clock_epoch, "clock_epoch")?;
        let blocking: Vec<(String, String)> = blocking
            .iter()
            .map(|(scope, subject)| (scope.as_str().to_owned(), subject.clone()))
            .collect();
        self.in_txn(move |engine| {
            SqlMetadataStore::<E>::require_active(engine, &authority)?;
            let stored = engine.query(
                "SELECT state_revision FROM action_serving_states WHERE action_key = ?1",
                &[SqlValue::Text(action_key.clone())],
            )?;
            let stored_revision = match stored.first().and_then(|r| r.first()) {
                None => None,
                Some(v) => Some(expect_u64(v, "state_revision")?),
            };
            // Legacy rows are revision 0; H040 records start at 1.
            if state_revision == 0 || stored_revision.is_some_and(|s| state_revision <= s) {
                return Err(StoreError::StaleServingRevision);
            }
            // Every NAMED blocking quarantine must exist (references are
            // the authority; dangling ones are refused at write).
            for (scope, subject) in &blocking {
                let exists = engine.query(
                    "SELECT scope FROM quarantines WHERE scope = ?1 AND subject = ?2",
                    &[
                        SqlValue::Text(scope.clone()),
                        SqlValue::Text(subject.clone()),
                    ],
                )?;
                if exists.is_empty() {
                    return Err(StoreError::UnknownQuarantineReference);
                }
            }
            engine.execute(
                "INSERT OR REPLACE INTO action_serving_states \
                 (action_key, disposition, version, state_revision, authority_key, \
                  evaluated_at_micros, max_age_micros, clock_uncertainty_micros, clock_epoch) \
                 VALUES (?1, ?2, 1, ?3, ?4, ?5, ?6, ?7, ?8)",
                &[
                    SqlValue::Text(action_key.clone()),
                    SqlValue::Text(disposition),
                    SqlValue::Int(revision),
                    SqlValue::Text(digest_key(&authority)),
                    SqlValue::Int(evaluated_at),
                    max_age.map_or(SqlValue::Null, SqlValue::Int),
                    SqlValue::Int(uncertainty),
                    SqlValue::Int(epoch),
                ],
            )?;
            // Replace the reference set atomically with the row.
            engine.execute(
                "DELETE FROM serving_blocking_quarantines WHERE action_key = ?1",
                &[SqlValue::Text(action_key.clone())],
            )?;
            for (scope, subject) in &blocking {
                engine.execute(
                    "INSERT OR IGNORE INTO serving_blocking_quarantines \
                     (action_key, scope, subject) VALUES (?1, ?2, ?3)",
                    &[
                        SqlValue::Text(action_key.clone()),
                        SqlValue::Text(scope.clone()),
                        SqlValue::Text(subject.clone()),
                    ],
                )?;
            }
            Ok(())
        })
    }

    fn serving_record(&mut self, action_key: &str) -> Result<Option<ServingRecordRow>, StoreError> {
        let rows = self.engine.query(
            "SELECT disposition, state_revision, authority_key, evaluated_at_micros, \
             max_age_micros, clock_uncertainty_micros, clock_epoch \
             FROM action_serving_states WHERE action_key = ?1",
            &[SqlValue::Text(action_key.to_owned())],
        )?;
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        let [
            disposition,
            revision,
            authority_key,
            evaluated_at,
            max_age,
            uncertainty,
            epoch,
        ] = row.as_slice()
        else {
            return Err(StoreError::Corruption("serving record shape".into()));
        };
        let evaluated_at = match evaluated_at {
            SqlValue::Int(v) => *v,
            _ => return Err(StoreError::Corruption("evaluated_at_micros shape".into())),
        };
        let max_age = match max_age {
            SqlValue::Null => None,
            SqlValue::Int(_) => Some(expect_u64(max_age, "max_age_micros")?),
            _ => return Err(StoreError::Corruption("max_age_micros shape".into())),
        };
        let blocking_rows = self.engine.query(
            "SELECT scope, subject FROM serving_blocking_quarantines \
             WHERE action_key = ?1 ORDER BY scope, subject",
            &[SqlValue::Text(action_key.to_owned())],
        )?;
        let blocking = blocking_rows
            .iter()
            .map(|row| {
                let [scope, subject] = row.as_slice() else {
                    return Err(StoreError::Corruption("blocking reference shape".into()));
                };
                Ok((
                    expect_text(scope, "scope")?,
                    expect_text(subject, "subject")?,
                ))
            })
            .collect::<Result<Vec<_>, StoreError>>()?;
        Ok(Some(ServingRecordRow {
            disposition: expect_text(disposition, "disposition")?,
            state_revision: expect_u64(revision, "state_revision")?,
            authority_key: expect_text(authority_key, "authority_key")?,
            validity: ServingValidity {
                evaluated_at_unix_micros: evaluated_at,
                maximum_age_micros: max_age,
                clock_uncertainty_micros: expect_u64(uncertainty, "clock_uncertainty_micros")?,
                coordinator_clock_epoch: expect_u64(epoch, "clock_epoch")?,
            },
            blocking,
        }))
    }

    fn record_divergence_incident(
        &mut self,
        authority: &TypedDigest,
        row: &DivergenceIncidentRow,
    ) -> Result<(), StoreError> {
        let authority = authority.clone();
        let row = row.clone();
        let seq = to_seq(row.seq, "seq")?;
        self.in_txn(move |engine| {
            SqlMetadataStore::<E>::require_active(engine, &authority)?;
            let existing = engine.query(
                "SELECT class, committed_manifest_key, candidate_manifest_key, \
                 candidate_evidence_key, candidate_pin_hex, generation_hex, attempt_hex, \
                 detail FROM divergence_incidents WHERE action_key = ?1 AND seq = ?2",
                &[SqlValue::Text(row.action_key.clone()), SqlValue::Int(seq)],
            )?;
            if let Some(stored) = existing.first() {
                let same = stored.len() == 8
                    && expect_text(&stored[0], "class")? == row.class
                    && expect_text(&stored[1], "committed_manifest_key")?
                        == row.committed_manifest_key
                    && expect_text(&stored[2], "candidate_manifest_key")?
                        == row.candidate_manifest_key
                    && expect_text(&stored[3], "candidate_evidence_key")?
                        == row.candidate_evidence_key
                    && expect_text(&stored[4], "candidate_pin_hex")? == row.candidate_pin_hex
                    && expect_text(&stored[5], "generation_hex")? == row.generation_hex
                    && expect_text(&stored[6], "attempt_hex")? == row.attempt_hex
                    && expect_text(&stored[7], "detail")? == row.detail;
                if same {
                    return Ok(()); // idempotent
                }
                return Err(StoreError::AppendConflict("divergence_incidents".into()));
            }
            engine.execute(
                "INSERT INTO divergence_incidents (action_key, seq, class, \
                 committed_manifest_key, candidate_manifest_key, candidate_evidence_key, \
                 candidate_pin_hex, generation_hex, attempt_hex, detail) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                &[
                    SqlValue::Text(row.action_key),
                    SqlValue::Int(seq),
                    SqlValue::Text(row.class),
                    SqlValue::Text(row.committed_manifest_key),
                    SqlValue::Text(row.candidate_manifest_key),
                    SqlValue::Text(row.candidate_evidence_key),
                    SqlValue::Text(row.candidate_pin_hex),
                    SqlValue::Text(row.generation_hex),
                    SqlValue::Text(row.attempt_hex),
                    SqlValue::Text(row.detail),
                ],
            )?;
            Ok(())
        })
    }

    fn list_divergence_incidents(
        &mut self,
        action_key: &str,
    ) -> Result<Vec<DivergenceIncidentRow>, StoreError> {
        let rows = self.engine.query(
            "SELECT seq, class, committed_manifest_key, candidate_manifest_key, \
             candidate_evidence_key, candidate_pin_hex, generation_hex, attempt_hex, detail \
             FROM divergence_incidents WHERE action_key = ?1 ORDER BY seq",
            &[SqlValue::Text(action_key.to_owned())],
        )?;
        rows.iter()
            .map(|row| {
                let [
                    seq,
                    class,
                    committed,
                    candidate,
                    evidence,
                    pin,
                    generation,
                    attempt,
                    detail,
                ] = row.as_slice()
                else {
                    return Err(StoreError::Corruption("divergence incident shape".into()));
                };
                Ok(DivergenceIncidentRow {
                    action_key: action_key.to_owned(),
                    seq: expect_u64(seq, "seq")?,
                    class: expect_text(class, "class")?,
                    committed_manifest_key: expect_text(committed, "committed_manifest_key")?,
                    candidate_manifest_key: expect_text(candidate, "candidate_manifest_key")?,
                    candidate_evidence_key: expect_text(evidence, "candidate_evidence_key")?,
                    candidate_pin_hex: expect_text(pin, "candidate_pin_hex")?,
                    generation_hex: expect_text(generation, "generation_hex")?,
                    attempt_hex: expect_text(attempt, "attempt_hex")?,
                    detail: expect_text(detail, "detail")?,
                })
            })
            .collect()
    }

    fn record_adoption_edge(
        &mut self,
        authority: &TypedDigest,
        producer_action_key: &str,
        role: &str,
        virtual_path: &[u8],
        from_object_key: &str,
        to_object_key: &str,
    ) -> Result<(), StoreError> {
        let authority = authority.clone();
        let producer = producer_action_key.to_owned();
        let role = role.to_owned();
        let path = virtual_path.to_vec();
        let from = from_object_key.to_owned();
        let to = to_object_key.to_owned();
        self.in_txn(move |engine| {
            SqlMetadataStore::<E>::require_active(engine, &authority)?;
            let existing = engine.query(
                "SELECT to_object_key FROM adoption_edges \
                 WHERE producer_action_key = ?1 AND role = ?2 AND virtual_path = ?3 \
                 AND from_object_key = ?4",
                &[
                    SqlValue::Text(producer.clone()),
                    SqlValue::Text(role.clone()),
                    SqlValue::Blob(path.clone()),
                    SqlValue::Text(from.clone()),
                ],
            )?;
            if let Some(row) = existing.first() {
                let [existing_to] = row.as_slice() else {
                    return Err(StoreError::Corruption("adoption edge shape".into()));
                };
                // Idempotent re-record; a rewrite to a DIFFERENT target
                // is a typed refusal — edges are never patched.
                return if expect_text(existing_to, "adoption target")? == to {
                    Ok(())
                } else {
                    Err(StoreError::AdoptionEdgeConflict)
                };
            }
            engine.execute(
                "INSERT INTO adoption_edges (producer_action_key, role, virtual_path, \
                 from_object_key, to_object_key) VALUES (?1, ?2, ?3, ?4, ?5)",
                &[
                    SqlValue::Text(producer),
                    SqlValue::Text(role),
                    SqlValue::Blob(path),
                    SqlValue::Text(from),
                    SqlValue::Text(to),
                ],
            )?;
            Ok(())
        })
    }

    fn has_adoption_edge(
        &mut self,
        producer_action_key: &str,
        role: &str,
        virtual_path: &[u8],
        from_object_key: &str,
        to_object_key: &str,
    ) -> Result<bool, StoreError> {
        let rows = self.engine.query(
            "SELECT producer_action_key FROM adoption_edges \
             WHERE producer_action_key = ?1 AND role = ?2 AND virtual_path = ?3 \
             AND from_object_key = ?4 AND to_object_key = ?5 LIMIT 1",
            &[
                SqlValue::Text(producer_action_key.to_owned()),
                SqlValue::Text(role.to_owned()),
                SqlValue::Blob(virtual_path.to_vec()),
                SqlValue::Text(from_object_key.to_owned()),
                SqlValue::Text(to_object_key.to_owned()),
            ],
        )?;
        Ok(!rows.is_empty())
    }

    fn list_provisional_ancestors(
        &mut self,
        consumer_action_key: &str,
    ) -> Result<Vec<ProvisionalAncestorRow>, StoreError> {
        let rows = self.engine.query(
            "SELECT producer_action_key, role, virtual_path, object_key, adopted \
             FROM provisional_ancestry WHERE consumer_action_key = ?1 \
             ORDER BY producer_action_key, role, virtual_path",
            &[SqlValue::Text(consumer_action_key.to_owned())],
        )?;
        rows.iter()
            .map(|row| {
                let [producer, role, path, object, adopted] = row.as_slice() else {
                    return Err(StoreError::Corruption("provisional ancestry shape".into()));
                };
                let SqlValue::Blob(path) = path else {
                    return Err(StoreError::Corruption("ancestry path shape".into()));
                };
                Ok(ProvisionalAncestorRow {
                    producer_action_key: expect_text(producer, "ancestry producer")?,
                    role: expect_text(role, "ancestry role")?,
                    virtual_path: path.clone(),
                    object_key: expect_text(object, "ancestry object")?,
                    adopted: expect_u64(adopted, "ancestry adopted")? != 0,
                })
            })
            .collect()
    }

    fn provisional_pin_row(
        &mut self,
        pin_key: &str,
    ) -> Result<Option<ProvisionalPinRecord>, StoreError> {
        let rows = self.engine.query(
            "SELECT pin_key, authority_key, action_key, generation_hex, attempt_hex, \
             lease_hex, role, virtual_path, obj_algo, obj_domain, obj_bytes, object_key, \
             protective_pin_hex, renewal_seq, adopted_object_key, invalidated_reason, \
             released, toolchain_contract_key, event_contract_key \
             FROM provisional_pins WHERE pin_key = ?1",
            &[SqlValue::Text(pin_key.to_owned())],
        )?;
        rows.first()
            .map(|row| self.map_provisional_pin_row(row))
            .transpose()
    }

    fn insert_provisional_pin(&mut self, pin: &ProvisionalPinInsert) -> Result<(), StoreError> {
        let row = pin.clone();
        // R121: intern the object's domain so later reads in THIS process
        // can restore the typed digest fail-closed.
        self.intern(row.object.domain);
        self.in_txn(move |engine| {
            engine.execute(
                "INSERT INTO provisional_pins (pin_key, authority_key, action_key, \
                 generation_hex, attempt_hex, lease_hex, role, virtual_path, obj_algo, \
                 obj_domain, obj_bytes, object_key, protective_pin_hex, renewal_seq, \
                 adopted_object_key, invalidated_reason, released, \
                 toolchain_contract_key, event_contract_key) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, 0, \
                 NULL, NULL, 0, ?14, ?15)",
                &[
                    SqlValue::Text(row.pin_key.clone()),
                    SqlValue::Text(row.authority_key.clone()),
                    SqlValue::Text(row.action_key.clone()),
                    SqlValue::Text(u128_hex(row.generation)),
                    SqlValue::Text(u128_hex(row.attempt)),
                    SqlValue::Text(u128_hex(row.lease)),
                    SqlValue::Int(row.role_tag),
                    SqlValue::Blob(row.virtual_path.clone()),
                    SqlValue::Text(algo_tag(row.object.algorithm).to_owned()),
                    SqlValue::Text(row.object.domain.to_owned()),
                    SqlValue::Blob(row.object.bytes.to_vec()),
                    SqlValue::Text(digest_key(&row.object)),
                    SqlValue::Text(u128_hex(row.protective_pin_id)),
                    SqlValue::Text(row.toolchain_contract_key.clone()),
                    SqlValue::Text(row.event_contract_key.clone()),
                ],
            )?;
            // The GC-protective twin in `pins` (H010 semantics): same
            // transaction, so the registry row and the protection root are
            // born together.
            engine.execute(
                "INSERT INTO pins (id_hex, id, root_key, owner, class, expires_at_seq, \
                 released, evidence, renewal_seq, durable, reason) \
                 VALUES (?1, ?2, ?3, 'coordinator', 'provisional-metadata', NULL, 0, \
                 NULL, 0, 1, ?4)",
                &[
                    SqlValue::Text(u128_hex(row.protective_pin_id)),
                    SqlValue::Blob(row.protective_pin_id.to_be_bytes().to_vec()),
                    SqlValue::Text(digest_key(&row.object)),
                    SqlValue::Text(row.reason),
                ],
            )?;
            // M017: the materialized transitive ancestor closure is born
            // in the SAME transaction as the pin — a tear can never leave
            // a prepared descendant without its recorded lineage.
            for (ancestor_key, min_hops) in &row.ancestor_pin_keys {
                engine.execute(
                    "INSERT OR IGNORE INTO provisional_pin_lineage \
                     (descendant_pin_key, ancestor_pin_key, min_hops) VALUES (?1, ?2, ?3)",
                    &[
                        SqlValue::Text(row.pin_key.clone()),
                        SqlValue::Text(ancestor_key.clone()),
                        SqlValue::Int(*min_hops as i64),
                    ],
                )?;
            }
            Ok(())
        })
    }

    fn list_provisional_pin_ancestors(
        &mut self,
        descendant_pin_key: &str,
    ) -> Result<Vec<(String, u64)>, StoreError> {
        let rows = self.engine.query(
            "SELECT ancestor_pin_key, min_hops FROM provisional_pin_lineage \
             WHERE descendant_pin_key = ?1 ORDER BY ancestor_pin_key",
            &[SqlValue::Text(descendant_pin_key.to_owned())],
        )?;
        rows.into_iter()
            .map(|row| match row.as_slice() {
                [SqlValue::Text(k), SqlValue::Int(h)] => {
                    Ok((k.clone(), u64::try_from(*h).unwrap_or(0)))
                }
                _ => Err(StoreError::Corruption("pin lineage ancestor shape".into())),
            })
            .collect()
    }

    fn provisional_pin_closure_depth(
        &mut self,
        descendant_pin_key: &str,
    ) -> Result<u64, StoreError> {
        let rows = self.engine.query(
            "SELECT COALESCE(MAX(min_hops), 0) FROM provisional_pin_lineage \
             WHERE descendant_pin_key = ?1",
            &[SqlValue::Text(descendant_pin_key.to_owned())],
        )?;
        match rows.first().map(Vec::as_slice) {
            Some([SqlValue::Int(h)]) => Ok(u64::try_from(*h).unwrap_or(0)),
            _ => Err(StoreError::Corruption("pin lineage depth shape".into())),
        }
    }

    fn list_provisional_pin_descendants(
        &mut self,
        ancestor_pin_key: &str,
    ) -> Result<Vec<String>, StoreError> {
        let rows = self.engine.query(
            "SELECT descendant_pin_key FROM provisional_pin_lineage \
             WHERE ancestor_pin_key = ?1 ORDER BY descendant_pin_key",
            &[SqlValue::Text(ancestor_pin_key.to_owned())],
        )?;
        rows.into_iter()
            .map(|row| match row.first() {
                Some(SqlValue::Text(k)) => Ok(k.clone()),
                _ => Err(StoreError::Corruption(
                    "pin lineage descendant shape".into(),
                )),
            })
            .collect()
    }

    fn record_provisional_grant(
        &mut self,
        pin_key: &str,
        grantee_kind: &str,
        grantee_id: &str,
        granted_seq: u64,
    ) -> Result<(), StoreError> {
        let (pin_key, kind, id) = (
            pin_key.to_owned(),
            grantee_kind.to_owned(),
            grantee_id.to_owned(),
        );
        self.in_txn(move |engine| {
            engine.execute(
                "INSERT OR IGNORE INTO provisional_pin_grants \
                 (pin_key, grantee_kind, grantee_id, granted_seq) VALUES (?1, ?2, ?3, ?4)",
                &[
                    SqlValue::Text(pin_key),
                    SqlValue::Text(kind),
                    SqlValue::Text(id),
                    SqlValue::Int(granted_seq as i64),
                ],
            )?;
            Ok(())
        })
    }

    fn list_provisional_grants(
        &mut self,
        pin_key: &str,
    ) -> Result<Vec<(String, String, u64)>, StoreError> {
        let rows = self.engine.query(
            "SELECT grantee_kind, grantee_id, granted_seq FROM provisional_pin_grants \
             WHERE pin_key = ?1 ORDER BY grantee_kind, grantee_id",
            &[SqlValue::Text(pin_key.to_owned())],
        )?;
        rows.iter()
            .map(|row| {
                let [kind, id, seq] = row.as_slice() else {
                    return Err(StoreError::Corruption("provisional grant shape".into()));
                };
                Ok((
                    expect_text(kind, "grant kind")?,
                    expect_text(id, "grant id")?,
                    expect_u64(seq, "grant seq")?,
                ))
            })
            .collect()
    }

    fn renew_provisional_pin(&mut self, pin_key: &str, renewal_seq: u64) -> Result<(), StoreError> {
        let pin_key = pin_key.to_owned();
        self.in_txn(move |engine| {
            let rows = engine.query(
                "SELECT renewal_seq, released FROM provisional_pins WHERE pin_key = ?1",
                &[SqlValue::Text(pin_key.clone())],
            )?;
            let Some(row) = rows.first() else {
                return Err(StoreError::UnknownPin);
            };
            let [stored, released] = row.as_slice() else {
                return Err(StoreError::Corruption("provisional renewal shape".into()));
            };
            if expect_u64(released, "released")? != 0 {
                return Err(StoreError::PinReleased);
            }
            if renewal_seq <= expect_u64(stored, "renewal")? {
                return Err(StoreError::NonMonotonicPinRenewal);
            }
            engine.execute(
                "UPDATE provisional_pins SET renewal_seq = ?1 WHERE pin_key = ?2",
                &[SqlValue::Int(renewal_seq as i64), SqlValue::Text(pin_key)],
            )?;
            Ok(())
        })
    }

    fn close_provisional_pin(
        &mut self,
        pin_key: &str,
        invalidation_reason: Option<&str>,
    ) -> Result<(), StoreError> {
        let pin_key = pin_key.to_owned();
        let reason = invalidation_reason.map(str::to_owned);
        self.in_txn(move |engine| {
            // Idempotent close; the protective pin is left for the caller
            // to release AFTER this commit (fail toward retention on tear).
            let changed = engine.execute(
                "UPDATE provisional_pins SET released = 1, invalidated_reason = \
                 COALESCE(?1, invalidated_reason) WHERE pin_key = ?2 AND released = 0",
                &[
                    reason.map(SqlValue::Text).unwrap_or(SqlValue::Null),
                    SqlValue::Text(pin_key.clone()),
                ],
            )?;
            if changed == 0
                && engine
                    .query(
                        "SELECT 1 FROM provisional_pins WHERE pin_key = ?1",
                        &[SqlValue::Text(pin_key)],
                    )?
                    .is_empty()
            {
                return Err(StoreError::UnknownPin);
            }
            Ok(())
        })
    }

    fn adopt_provisional_pin(
        &mut self,
        pin_key: &str,
        committed_object_key: &str,
    ) -> Result<(), StoreError> {
        let pin_key = pin_key.to_owned();
        let committed = committed_object_key.to_owned();
        self.in_txn(move |engine| {
            let changed = engine.execute(
                "UPDATE provisional_pins SET adopted_object_key = ?1 \
                 WHERE pin_key = ?2 AND adopted_object_key IS NULL",
                &[SqlValue::Text(committed), SqlValue::Text(pin_key.clone())],
            )?;
            if changed == 0
                && engine
                    .query(
                        "SELECT 1 FROM provisional_pins WHERE pin_key = ?1",
                        &[SqlValue::Text(pin_key)],
                    )?
                    .is_empty()
            {
                return Err(StoreError::UnknownPin);
            }
            Ok(())
        })
    }

    fn record_provisional_consumption(
        &mut self,
        consumption: &ProvisionalObligationInsert,
    ) -> Result<(), StoreError> {
        let row = consumption.clone();
        self.in_txn(move |engine| {
            engine.execute(
                "INSERT OR IGNORE INTO provisional_obligations (consumer_worker, \
                 consumer_attempt_hex, pin_key, producer_action_key, \
                 producer_generation_hex, producer_attempt_hex, role, virtual_path, \
                 object_key, status, resolution_object_key, created_seq) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'open', NULL, ?10)",
                &[
                    SqlValue::Text(row.consumer_worker),
                    SqlValue::Text(u128_hex(row.consumer_attempt)),
                    SqlValue::Text(row.pin_key),
                    SqlValue::Text(row.producer_action_key),
                    SqlValue::Text(u128_hex(row.producer_generation)),
                    SqlValue::Text(u128_hex(row.producer_attempt)),
                    SqlValue::Int(row.role_tag),
                    SqlValue::Blob(row.virtual_path),
                    SqlValue::Text(row.object_key),
                    SqlValue::Int(to_seq(row.created_seq, "consumption seq")?),
                ],
            )?;
            Ok(())
        })
    }

    fn list_open_provisional_obligations(
        &mut self,
        consumer_worker: &str,
        consumer_attempt_hex: &str,
    ) -> Result<Vec<ProvisionalObligationRow>, StoreError> {
        let rows = self.engine.query(
            "SELECT consumer_worker, consumer_attempt_hex, pin_key, producer_action_key, \
             producer_generation_hex, producer_attempt_hex, role, virtual_path, object_key, \
             status, resolution_object_key, created_seq FROM provisional_obligations \
             WHERE consumer_worker = ?1 AND consumer_attempt_hex = ?2 AND status != 'resolved' \
             ORDER BY status, pin_key",
            &[
                SqlValue::Text(consumer_worker.to_owned()),
                SqlValue::Text(consumer_attempt_hex.to_owned()),
            ],
        )?;
        rows.iter()
            .map(|row| {
                let [
                    worker,
                    attempt_hex,
                    pin,
                    action,
                    generation,
                    producer,
                    role,
                    path,
                    object,
                    status,
                    resolution,
                    created,
                ] = row.as_slice()
                else {
                    return Err(StoreError::Corruption("obligation row shape".into()));
                };
                Ok(ProvisionalObligationRow {
                    consumer_worker: expect_text(worker, "obligation worker")?,
                    consumer_attempt_hex: expect_text(attempt_hex, "obligation attempt")?,
                    pin_key: expect_text(pin, "obligation pin")?,
                    producer_action_key: expect_text(action, "obligation action")?,
                    producer_generation_hex: expect_text(generation, "obligation generation")?,
                    producer_attempt_hex: expect_text(producer, "obligation producer")?,
                    role_tag: match role {
                        SqlValue::Int(v) => *v,
                        _ => return Err(StoreError::Corruption("obligation role shape".into())),
                    },
                    virtual_path: match path {
                        SqlValue::Blob(b) => b.clone(),
                        _ => return Err(StoreError::Corruption("obligation path shape".into())),
                    },
                    object_key: expect_text(object, "obligation object")?,
                    status: expect_text(status, "obligation status")?,
                    resolution_object_key: expect_opt_text(resolution, "obligation resolution")?,
                    created_seq: expect_u64(created, "obligation seq")?,
                })
            })
            .collect()
    }

    fn resolve_provisional_obligations(
        &mut self,
        pin_key: &str,
        resolution_object_key: &str,
    ) -> Result<usize, StoreError> {
        let (pin_key, resolved) = (pin_key.to_owned(), resolution_object_key.to_owned());
        self.in_txn(move |engine| {
            engine.execute(
                "UPDATE provisional_obligations SET status = 'resolved', \
                 resolution_object_key = ?1 WHERE pin_key = ?2 AND status = 'open'",
                &[SqlValue::Text(resolved), SqlValue::Text(pin_key)],
            )
        })
    }

    fn cancel_provisional_obligations(&mut self, pin_key: &str) -> Result<usize, StoreError> {
        let pin_key = pin_key.to_owned();
        self.in_txn(move |engine| {
            engine.execute(
                "UPDATE provisional_obligations SET status = 'cancelled' \
                 WHERE pin_key = ?1 AND status = 'open'",
                &[SqlValue::Text(pin_key)],
            )
        })
    }

    fn record_served_consumer(
        &mut self,
        action_key: &str,
        consumer: &str,
    ) -> Result<(), StoreError> {
        let action_key = action_key.to_owned();
        let consumer = consumer.to_owned();
        self.in_txn(move |engine| {
            engine.execute(
                "INSERT OR IGNORE INTO provenance_edges (from_key, to_key, kind) \
                 VALUES (?1, ?2, 'served-to')",
                &[SqlValue::Text(action_key), SqlValue::Text(consumer)],
            )?;
            Ok(())
        })
    }

    fn list_served_consumers(&mut self, action_key: &str) -> Result<Vec<String>, StoreError> {
        let rows = self.engine.query(
            "SELECT to_key FROM provenance_edges \
             WHERE from_key = ?1 AND kind = 'served-to' ORDER BY to_key",
            &[SqlValue::Text(action_key.to_owned())],
        )?;
        rows.iter()
            .map(|row| {
                expect_text(
                    row.first()
                        .ok_or_else(|| StoreError::Corruption("served consumer shape".into()))?,
                    "consumer",
                )
            })
            .collect()
    }

    fn differential_snapshot(&mut self) -> Result<Vec<String>, StoreError> {
        // Deterministic dump: every table, every column, ordered rows.
        const DUMPS: &[(&str, &str)] = &[
            (
                "schema_epochs",
                "SELECT version, applied_seq FROM schema_epochs ORDER BY version",
            ),
            (
                "coordinator_authorities",
                "SELECT key, algo, domain, bytes, cluster_id, incarnation, term, acquired_seq, \
                 released FROM coordinator_authorities ORDER BY key",
            ),
            (
                "action_entries",
                "SELECT key, algo, domain, bytes, key_epoch, projection_epoch \
                 FROM action_entries ORDER BY key",
            ),
            (
                "action_generations",
                "SELECT id_hex, id, action_key, authority_key, tombstoned, per_key_ordinal \
                 FROM action_generations ORDER BY id_hex",
            ),
            (
                "generation_high_water",
                "SELECT kind, value FROM generation_high_water ORDER BY kind",
            ),
            (
                "action_attempts",
                "SELECT id_hex, id, generation_hex, worker, seq, worker_boot_generation, \
                 worker_incarnation, execution_lease_hex FROM action_attempts \
                 ORDER BY id_hex",
            ),
            (
                "execution_leases",
                "SELECT id_hex, id, attempt_hex, renewal_seq, expires_at_seq, released \
                 FROM execution_leases ORDER BY id_hex",
            ),
            (
                "action_publications",
                "SELECT action_key, descriptor_algo, descriptor_domain, descriptor_bytes, \
                 manifest_algo, manifest_domain, manifest_bytes, winner_generation_hex, \
                 winner_attempt_hex, result_kind, pin_hex FROM action_publications \
                 ORDER BY action_key",
            ),
            (
                "action_serving_states",
                "SELECT action_key, disposition, version, state_revision, authority_key, \
                 evaluated_at_micros, max_age_micros, clock_uncertainty_micros, clock_epoch \
                 FROM action_serving_states ORDER BY action_key",
            ),
            (
                "serving_blocking_quarantines",
                "SELECT action_key, scope, subject FROM serving_blocking_quarantines \
                 ORDER BY action_key, scope, subject",
            ),
            (
                "objects",
                "SELECT key, algo, domain, bytes, logical_size FROM objects ORDER BY key",
            ),
            (
                "object_locations",
                "SELECT object_key, store_path, verified_seq, encoding, quarantined, durable \
                 FROM object_locations ORDER BY object_key, store_path",
            ),
            (
                "object_edges",
                "SELECT parent_key, child_key, kind FROM object_edges \
                 ORDER BY parent_key, child_key, kind",
            ),
            (
                "pins",
                "SELECT id_hex, id, root_key, owner, class, expires_at_seq, released, \
                 evidence, renewal_seq, durable, reason FROM pins ORDER BY id_hex",
            ),
            (
                "observed_input_recipes",
                "SELECT action_key, recipe_algo, recipe_domain, recipe_bytes \
                 FROM observed_input_recipes ORDER BY action_key",
            ),
            (
                "key_breakdowns",
                "SELECT action_key, component, algo, domain, bytes FROM key_breakdowns \
                 ORDER BY action_key, component",
            ),
            (
                "trust_states",
                "SELECT action_key, state, reason FROM trust_states ORDER BY action_key",
            ),
            (
                "quarantines",
                "SELECT scope, subject, reason FROM quarantines ORDER BY scope, subject",
            ),
            (
                "verification_samples",
                "SELECT action_key, attempt_hex, passed, seq FROM verification_samples \
                 ORDER BY action_key, attempt_hex, seq",
            ),
            (
                "gc_runs",
                "SELECT id, seq, pinned_roots, located_objects, reachable_objects \
                 FROM gc_runs ORDER BY id",
            ),
            (
                "operator_resets",
                "SELECT generation, applied_seq FROM operator_resets ORDER BY generation",
            ),
            (
                "eviction_tombstones",
                "SELECT action_key, semantic_algo, semantic_domain, semantic_bytes, \
                 observable_algo, observable_domain, observable_bytes, evicted_seq \
                 FROM eviction_tombstones ORDER BY action_key",
            ),
            (
                "gc_tombstones",
                "SELECT object_key, store_path, marked_seq, grace_until_seq \
                 FROM gc_tombstones ORDER BY object_key, store_path",
            ),
            (
                "gc_receipts",
                "SELECT id, seq, mode, planned, reclaimed, skipped, truncated \
                 FROM gc_receipts ORDER BY id",
            ),
            (
                "action_evidence_index",
                "SELECT action_key, evidence_algo, evidence_domain, evidence_bytes, \
                 generation_hex, attempt_hex, manifest_key FROM action_evidence_index \
                 ORDER BY action_key, evidence_domain, evidence_bytes",
            ),
            (
                "peer_authority_high_water",
                "SELECT peer_id, term, observed_seq FROM peer_authority_high_water \
                 ORDER BY peer_id",
            ),
            (
                "worker_incarnation_fences",
                "SELECT worker, incarnation, highest_boot_generation, active, \
                 operator_reenrollment_generation, clone_ambiguous \
                 FROM worker_incarnation_fences \
                 ORDER BY worker",
            ),
            (
                "edge_incarnation_fences",
                "SELECT edge_id, incarnation FROM edge_incarnation_fences ORDER BY edge_id",
            ),
            (
                "edge_handoffs",
                "SELECT edge_id, active_incarnation, predecessor_incarnation, begun_seq, \
                 resolved FROM edge_handoffs ORDER BY edge_id",
            ),
            (
                "action_trust_evaluations",
                "SELECT action_key, version, state, reason, evaluated_seq \
                 FROM action_trust_evaluations ORDER BY action_key, version",
            ),
            (
                "operations",
                "SELECT id_hex, id, kind, state, updated_seq FROM operations ORDER BY id_hex",
            ),
            (
                "edge_subscribers",
                "SELECT edge_id, subscriber, registered_seq FROM edge_subscribers \
                 ORDER BY edge_id, subscriber",
            ),
            (
                "manifests",
                "SELECT key, algo, domain, bytes, kind, entry_count FROM manifests \
                 ORDER BY key",
            ),
            (
                "worker_sessions",
                "SELECT worker, incarnation, started_seq, ended_seq FROM worker_sessions \
                 ORDER BY worker, started_seq",
            ),
            (
                "worker_capabilities",
                "SELECT worker, capability FROM worker_capabilities \
                 ORDER BY worker, capability",
            ),
            (
                "native_child_bindings",
                "SELECT parent_action_key, child_action_key, bound_seq, state \
                 FROM native_child_bindings \
                 ORDER BY parent_action_key, child_action_key",
            ),
            (
                "worker_health_samples",
                "SELECT worker, seq, healthy, detail FROM worker_health_samples \
                 ORDER BY worker, seq",
            ),
            (
                "decision_receipts",
                "SELECT kind, subject, seq, decision, reason FROM decision_receipts \
                 ORDER BY kind, subject, seq",
            ),
            (
                "provenance_edges",
                "SELECT from_key, to_key, kind FROM provenance_edges \
                 ORDER BY from_key, to_key, kind",
            ),
            (
                "determinism_audits",
                "SELECT action_key, attempt_hex, seq, verdict FROM determinism_audits \
                 ORDER BY action_key, attempt_hex, seq",
            ),
            (
                "materialization_records",
                "SELECT id_hex, id, root_key, dest_path, state, updated_seq \
                 FROM materialization_records ORDER BY id_hex",
            ),
            (
                "divergence_incidents",
                "SELECT action_key, seq, class, committed_manifest_key, \
                 candidate_manifest_key, candidate_evidence_key, candidate_pin_hex, \
                 generation_hex, attempt_hex, detail FROM divergence_incidents \
                 ORDER BY action_key, seq",
            ),
            (
                "provisional_ancestry",
                "SELECT consumer_action_key, producer_action_key, role, virtual_path, \
                 object_key, adopted FROM provisional_ancestry \
                 ORDER BY consumer_action_key, producer_action_key, role, virtual_path",
            ),
            (
                "adoption_edges",
                "SELECT producer_action_key, role, virtual_path, from_object_key, \
                 to_object_key FROM adoption_edges \
                 ORDER BY producer_action_key, role, virtual_path, from_object_key",
            ),
            (
                "provisional_pins",
                "SELECT pin_key, authority_key, action_key, generation_hex, attempt_hex, \
                 lease_hex, role, virtual_path, obj_algo, obj_domain, obj_bytes, object_key, \
                 protective_pin_hex, renewal_seq, adopted_object_key, invalidated_reason, \
                 released, toolchain_contract_key, event_contract_key \
                 FROM provisional_pins ORDER BY pin_key",
            ),
            (
                "provisional_pin_grants",
                "SELECT pin_key, grantee_kind, grantee_id, granted_seq \
                 FROM provisional_pin_grants ORDER BY pin_key, grantee_kind, grantee_id",
            ),
            (
                "provisional_pin_lineage",
                "SELECT descendant_pin_key, ancestor_pin_key, min_hops \
                 FROM provisional_pin_lineage \
                 ORDER BY descendant_pin_key, ancestor_pin_key",
            ),
            (
                "provisional_install_journal",
                "SELECT pin_key, consumer_worker, consumer_attempt_hex, installed_path, \
                 obj_algo, obj_domain, obj_bytes, object_key, installed_seq, state \
                 FROM provisional_install_journal \
                 ORDER BY pin_key, consumer_attempt_hex, installed_path",
            ),
            (
                "provisional_obligations",
                "SELECT consumer_worker, consumer_attempt_hex, pin_key, producer_action_key, \
                 producer_generation_hex, producer_attempt_hex, role, virtual_path, object_key, \
                 status, resolution_object_key, created_seq FROM provisional_obligations \
                 ORDER BY consumer_worker, consumer_attempt_hex, pin_key",
            ),
        ];
        let mut lines = Vec::new();
        for (table, sql) in DUMPS {
            for row in self.engine.query(sql, &[])? {
                let mut line = String::new();
                line.push_str(table);
                for value in &row {
                    line.push('|');
                    match value {
                        SqlValue::Null => line.push_str("NULL"),
                        SqlValue::Int(i) => {
                            use std::fmt::Write;
                            let _ = write!(line, "{i}");
                        }
                        SqlValue::Text(t) => line.push_str(t),
                        SqlValue::Blob(b) => line.push_str(&hex(b)),
                    }
                }
                lines.push(line);
            }
        }
        Ok(lines)
    }

    fn count_open_provisional_obligations(&mut self, pin_key: &str) -> Result<usize, StoreError> {
        let rows = self.engine.query(
            "SELECT COUNT(*) FROM provisional_obligations \
             WHERE pin_key = ?1 AND status = 'open'",
            &[SqlValue::Text(pin_key.to_owned())],
        )?;
        let Some(row) = rows.first() else {
            return Ok(0);
        };
        expect_u64(
            row.first()
                .ok_or_else(|| StoreError::Corruption("obligation count shape".into()))?,
            "obligation count",
        )
        .map(|v| v as usize)
    }

    fn list_open_provisional_pins_for_action_generation(
        &mut self,
        action_key: &str,
        generation_hex: &str,
    ) -> Result<Vec<ProvisionalPinRecord>, StoreError> {
        let rows = self.engine.query(
            "SELECT pin_key, authority_key, action_key, generation_hex, attempt_hex, \
             lease_hex, role, virtual_path, obj_algo, obj_domain, obj_bytes, object_key, \
             protective_pin_hex, renewal_seq, adopted_object_key, invalidated_reason, \
             released, toolchain_contract_key, event_contract_key \
             FROM provisional_pins \
             WHERE action_key = ?1 AND generation_hex = ?2 AND released = 0 ORDER BY pin_key",
            &[
                SqlValue::Text(action_key.to_owned()),
                SqlValue::Text(generation_hex.to_owned()),
            ],
        )?;
        rows.iter()
            .map(|row| self.map_provisional_pin_row(row))
            .collect()
    }

    fn list_open_provisional_pins_for_action(
        &mut self,
        action_key: &str,
    ) -> Result<Vec<ProvisionalPinRecord>, StoreError> {
        let rows = self.engine.query(
            "SELECT pin_key, authority_key, action_key, generation_hex, attempt_hex, \
             lease_hex, role, virtual_path, obj_algo, obj_domain, obj_bytes, object_key, \
             protective_pin_hex, renewal_seq, adopted_object_key, invalidated_reason, \
             released, toolchain_contract_key, event_contract_key \
             FROM provisional_pins WHERE action_key = ?1 AND released = 0 \
             ORDER BY pin_key",
            &[SqlValue::Text(action_key.to_owned())],
        )?;
        rows.iter()
            .map(|row| self.map_provisional_pin_row(row))
            .collect()
    }

    fn list_open_provisional_pins_for_authority(
        &mut self,
        authority_key: &str,
    ) -> Result<Vec<ProvisionalPinRecord>, StoreError> {
        let rows = self.engine.query(
            "SELECT pin_key, authority_key, action_key, generation_hex, attempt_hex, \
             lease_hex, role, virtual_path, obj_algo, obj_domain, obj_bytes, object_key, \
             protective_pin_hex, renewal_seq, adopted_object_key, invalidated_reason, \
             released, toolchain_contract_key, event_contract_key \
             FROM provisional_pins WHERE authority_key = ?1 AND released = 0 \
             ORDER BY pin_key",
            &[SqlValue::Text(authority_key.to_owned())],
        )?;
        rows.iter()
            .map(|row| self.map_provisional_pin_row(row))
            .collect()
    }

    fn list_open_provisional_obligations_by_attempt(
        &mut self,
        consumer_attempt_hex: &str,
    ) -> Result<Vec<ProvisionalObligationRow>, StoreError> {
        let rows = self.engine.query(
            "SELECT consumer_worker, consumer_attempt_hex, pin_key, producer_action_key, \
             producer_generation_hex, producer_attempt_hex, role, virtual_path, object_key, \
             status, resolution_object_key, created_seq FROM provisional_obligations \
             WHERE consumer_attempt_hex = ?1 AND status != 'resolved' \
             ORDER BY pin_key",
            &[SqlValue::Text(consumer_attempt_hex.to_owned())],
        )?;
        rows.iter()
            .map(|row| Self::map_obligation_row(row))
            .collect()
    }

    fn list_provisional_obligations_by_attempt_all(
        &mut self,
        consumer_attempt_hex: &str,
    ) -> Result<Vec<ProvisionalObligationRow>, StoreError> {
        let rows = self.engine.query(
            "SELECT consumer_worker, consumer_attempt_hex, pin_key, producer_action_key, \
             producer_generation_hex, producer_attempt_hex, role, virtual_path, object_key, \
             status, resolution_object_key, created_seq FROM provisional_obligations \
             WHERE consumer_attempt_hex = ?1 \
             ORDER BY status, pin_key",
            &[SqlValue::Text(consumer_attempt_hex.to_owned())],
        )?;
        rows.iter()
            .map(|row| Self::map_obligation_row(row))
            .collect()
    }

    fn insert_provisional_install(
        &mut self,
        install: &ProvisionalInstallInsert,
    ) -> Result<(), StoreError> {
        let row = install.clone();
        // R121: intern the object's domain for fail-closed restoration.
        self.intern(row.object.domain);
        self.in_txn(move |engine| {
            engine.execute(
                "INSERT OR IGNORE INTO provisional_install_journal \
                 (pin_key, consumer_worker, consumer_attempt_hex, installed_path, \
                 obj_algo, obj_domain, obj_bytes, object_key, installed_seq, state) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'installed')",
                &[
                    SqlValue::Text(row.pin_key),
                    SqlValue::Text(row.consumer_worker),
                    SqlValue::Text(u128_hex(row.consumer_attempt)),
                    SqlValue::Blob(row.installed_path),
                    SqlValue::Text(algo_tag(row.object.algorithm).to_owned()),
                    SqlValue::Text(row.object.domain.to_owned()),
                    SqlValue::Blob(row.object.bytes.to_vec()),
                    SqlValue::Text(digest_key(&row.object)),
                    SqlValue::Int(row.installed_seq as i64),
                ],
            )?;
            Ok(())
        })
    }

    fn list_provisional_installs_for_pins(
        &mut self,
        pin_keys: &[String],
    ) -> Result<Vec<ProvisionalInstallRecord>, StoreError> {
        if pin_keys.is_empty() {
            return Ok(Vec::new());
        }
        let placeholders = (0..pin_keys.len())
            .map(|i| format!("?{}", i + 1))
            .collect::<Vec<_>>()
            .join(", ");
        let params: Vec<SqlValue> = pin_keys
            .iter()
            .map(|key| SqlValue::Text(key.clone()))
            .collect();
        let rows = self.engine.query(
            &format!(
                "SELECT pin_key, consumer_worker, consumer_attempt_hex, installed_path, \
                 obj_algo, obj_domain, obj_bytes, object_key, installed_seq, state \
                 FROM provisional_install_journal WHERE pin_key IN ({placeholders}) \
                 ORDER BY pin_key, consumer_attempt_hex, installed_path"
            ),
            &params,
        )?;
        rows.iter()
            .map(|row| Self::map_install_row(self, row))
            .collect()
    }

    fn list_provisional_installs_by_state(
        &mut self,
        state: &str,
    ) -> Result<Vec<ProvisionalInstallRecord>, StoreError> {
        let rows = self.engine.query(
            "SELECT pin_key, consumer_worker, consumer_attempt_hex, installed_path, \
             obj_algo, obj_domain, obj_bytes, object_key, installed_seq, state \
             FROM provisional_install_journal WHERE state = ?1 \
             ORDER BY pin_key, consumer_attempt_hex, installed_path",
            &[SqlValue::Text(state.to_owned())],
        )?;
        rows.iter()
            .map(|row| Self::map_install_row(self, row))
            .collect()
    }

    fn set_provisional_install_state(
        &mut self,
        pin_key: &str,
        consumer_attempt_hex: &str,
        installed_path: &[u8],
        state: &str,
    ) -> Result<(), StoreError> {
        let (pin_key, attempt_hex, path, state) = (
            pin_key.to_owned(),
            consumer_attempt_hex.to_owned(),
            installed_path.to_vec(),
            state.to_owned(),
        );
        self.in_txn(move |engine| {
            let affected = engine.execute(
                "UPDATE provisional_install_journal SET state = ?4 \
                 WHERE pin_key = ?1 AND consumer_attempt_hex = ?2 AND installed_path = ?3",
                &[
                    SqlValue::Text(pin_key),
                    SqlValue::Text(attempt_hex),
                    SqlValue::Blob(path),
                    SqlValue::Text(state),
                ],
            )?;
            if affected == 0 {
                return Err(StoreError::UnknownPin);
            }
            Ok(())
        })
    }

    fn bind_native_children(
        &mut self,
        parent_action_key: &str,
        child_action_keys: &[String],
        bound_seq: u64,
    ) -> Result<(), StoreError> {
        let parent = parent_action_key.to_owned();
        let children: Vec<String> = child_action_keys.to_vec();
        self.in_txn(move |engine| {
            for child in children {
                engine.execute(
                    "INSERT OR IGNORE INTO native_child_bindings \
                     (parent_action_key, child_action_key, bound_seq, state) \
                     VALUES (?1, ?2, ?3, 'bound')",
                    &[
                        SqlValue::Text(parent.clone()),
                        SqlValue::Text(child),
                        SqlValue::Int(bound_seq as i64),
                    ],
                )?;
            }
            Ok(())
        })
    }

    fn list_native_child_bindings(
        &mut self,
        parent_action_key: &str,
    ) -> Result<Vec<(String, String)>, StoreError> {
        let rows = self.engine.query(
            "SELECT child_action_key, state FROM native_child_bindings \
             WHERE parent_action_key = ?1 ORDER BY child_action_key",
            &[SqlValue::Text(parent_action_key.to_owned())],
        )?;
        rows.into_iter()
            .map(|row| match row.as_slice() {
                [SqlValue::Text(child), SqlValue::Text(state)] => {
                    Ok((child.clone(), state.clone()))
                }
                _ => Err(StoreError::Corruption("native child binding shape".into())),
            })
            .collect()
    }

    fn set_native_child_binding_state(
        &mut self,
        parent_action_key: &str,
        child_action_key: &str,
        state: &str,
    ) -> Result<(), StoreError> {
        let (parent, child, state) = (
            parent_action_key.to_owned(),
            child_action_key.to_owned(),
            state.to_owned(),
        );
        self.in_txn(move |engine| {
            let affected = engine.execute(
                "UPDATE native_child_bindings SET state = ?3 \
                 WHERE parent_action_key = ?1 AND child_action_key = ?2",
                &[
                    SqlValue::Text(parent),
                    SqlValue::Text(child),
                    SqlValue::Text(state),
                ],
            )?;
            if affected == 0 {
                return Err(StoreError::UnknownPin);
            }
            Ok(())
        })
    }

    fn list_provisional_obligations_for_pin(
        &mut self,
        pin_key: &str,
    ) -> Result<Vec<ProvisionalObligationRow>, StoreError> {
        let rows = self.engine.query(
            "SELECT consumer_worker, consumer_attempt_hex, pin_key, producer_action_key, \
             producer_generation_hex, producer_attempt_hex, role, virtual_path, object_key, \
             status, resolution_object_key, created_seq FROM provisional_obligations \
             WHERE pin_key = ?1 ORDER BY consumer_worker, consumer_attempt_hex",
            &[SqlValue::Text(pin_key.to_owned())],
        )?;
        rows.iter()
            .map(|row| Self::map_obligation_row(row))
            .collect()
    }
}

// ---------------------------------------------------------------------
// Engine: rusqlite (reference TRUTH).
// ---------------------------------------------------------------------

/// The reference SQLite engine (bundled C SQLite via rusqlite).
pub struct RusqliteEngine {
    conn: rusqlite::Connection,
}

impl RusqliteEngine {
    /// Open (or create) a database file.
    pub fn open(path: &std::path::Path) -> Result<Self, StoreError> {
        rusqlite::Connection::open(path)
            .map(|conn| Self { conn })
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    /// Open an in-memory database.
    pub fn open_in_memory() -> Result<Self, StoreError> {
        rusqlite::Connection::open_in_memory()
            .map(|conn| Self { conn })
            .map_err(|e| StoreError::Backend(e.to_string()))
    }
}

fn to_rusqlite(v: &SqlValue) -> rusqlite::types::Value {
    match v {
        SqlValue::Null => rusqlite::types::Value::Null,
        SqlValue::Int(i) => rusqlite::types::Value::Integer(*i),
        SqlValue::Text(t) => rusqlite::types::Value::Text(t.clone()),
        SqlValue::Blob(b) => rusqlite::types::Value::Blob(b.clone()),
    }
}

impl SqlEngine for RusqliteEngine {
    fn execute(&mut self, sql: &str, params: &[SqlValue]) -> Result<usize, StoreError> {
        let bound = rusqlite::params_from_iter(params.iter().map(to_rusqlite));
        self.conn
            .execute(sql, bound)
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    fn query(&mut self, sql: &str, params: &[SqlValue]) -> Result<Vec<Vec<SqlValue>>, StoreError> {
        let mut statement = self
            .conn
            .prepare(sql)
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        let column_count = statement.column_count();
        let bound = rusqlite::params_from_iter(params.iter().map(to_rusqlite));
        let mut rows = statement
            .query(bound)
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        let mut out = Vec::new();
        while let Some(row) = rows
            .next()
            .map_err(|e| StoreError::Backend(e.to_string()))?
        {
            let mut cols = Vec::with_capacity(column_count);
            for i in 0..column_count {
                let value: rusqlite::types::Value =
                    row.get(i).map_err(|e| StoreError::Backend(e.to_string()))?;
                cols.push(match value {
                    rusqlite::types::Value::Null => SqlValue::Null,
                    rusqlite::types::Value::Integer(v) => SqlValue::Int(v),
                    rusqlite::types::Value::Real(f) => {
                        return Err(StoreError::Corruption(format!(
                            "unexpected float column {f}"
                        )));
                    }
                    rusqlite::types::Value::Text(t) => SqlValue::Text(t),
                    rusqlite::types::Value::Blob(b) => SqlValue::Blob(b),
                });
            }
            out.push(cols);
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------
// Engine: fsqlite (FrankenSQLite dogfood candidate).
// ---------------------------------------------------------------------

/// The FrankenSQLite engine (pure Rust).
pub struct FsqliteEngine {
    conn: fsqlite::Connection,
}

impl FsqliteEngine {
    /// Open (or create) a database file.
    pub fn open(path: &std::path::Path) -> Result<Self, StoreError> {
        fsqlite::Connection::open(path.display().to_string())
            .map(|conn| Self { conn })
            .map_err(|e| StoreError::Backend(e.to_string()))
    }
}

fn to_fsqlite(v: &SqlValue) -> fsqlite::SqliteValue {
    match v {
        SqlValue::Null => fsqlite::SqliteValue::Null,
        SqlValue::Int(i) => fsqlite::SqliteValue::Integer(*i),
        SqlValue::Text(t) => fsqlite::SqliteValue::Text(t.as_str().into()),
        SqlValue::Blob(b) => fsqlite::SqliteValue::Blob(b.clone().into()),
    }
}

fn from_fsqlite(v: &fsqlite::SqliteValue) -> Result<SqlValue, StoreError> {
    match v {
        fsqlite::SqliteValue::Null => Ok(SqlValue::Null),
        fsqlite::SqliteValue::Integer(i) => Ok(SqlValue::Int(*i)),
        fsqlite::SqliteValue::Float(f) => Err(StoreError::Corruption(format!(
            "unexpected float column {f}"
        ))),
        fsqlite::SqliteValue::Text(t) => Ok(SqlValue::Text(t.as_str().to_owned())),
        fsqlite::SqliteValue::Blob(b) => Ok(SqlValue::Blob(b.as_ref().to_vec())),
    }
}

impl SqlEngine for FsqliteEngine {
    fn execute(&mut self, sql: &str, params: &[SqlValue]) -> Result<usize, StoreError> {
        if params.is_empty() {
            // fsqlite's prepare() is DML/PRAGMA-only; DDL and transaction
            // control (all parameterless here) go through Connection::execute.
            return self
                .conn
                .execute(sql)
                .map_err(|e| StoreError::Backend(e.to_string()));
        }
        let statement = self
            .conn
            .prepare(sql)
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        let bound: Vec<fsqlite::SqliteValue> = params.iter().map(to_fsqlite).collect();
        statement
            .execute_with_params(&bound)
            .map_err(|e| StoreError::Backend(e.to_string()))
    }

    fn query(&mut self, sql: &str, params: &[SqlValue]) -> Result<Vec<Vec<SqlValue>>, StoreError> {
        let statement = self
            .conn
            .prepare(sql)
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        let bound: Vec<fsqlite::SqliteValue> = params.iter().map(to_fsqlite).collect();
        let rows = statement
            .query_with_params(&bound)
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        rows.iter()
            .map(|row| row.values().iter().map(from_fsqlite).collect())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rabs_protocol::authority::{ClusterId, CoordinatorAuthority, CoordinatorIncarnationId};
    use rabs_protocol::generation::{
        ActionGenerationId, AttemptId, ExecutionLeaseId, LeaseRenewalSeq,
    };
    use std::sync::atomic::{AtomicU64, Ordering};

    static DB_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn fresh_path(tag: &str) -> std::path::PathBuf {
        let n = DB_COUNTER.fetch_add(1, Ordering::SeqCst);
        std::env::temp_dir().join(format!("rabs-h009-{}-{}-{}.db", std::process::id(), tag, n))
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
            cluster_id: "cluster-a".to_owned(),
            incarnation: u128::from(tag),
            term: u64::from(tag),
            acquired_seq: 1,
        }
    }

    fn coordinator_authority() -> CoordinatorAuthority {
        CoordinatorAuthority {
            cluster_id: ClusterId("cluster-a".to_owned()),
            credential_generation: 1,
            term: 1,
            incarnation_id: CoordinatorIncarnationId(1),
        }
    }

    fn bound_authority_row() -> AuthorityRow {
        let coordinator = coordinator_authority();
        AuthorityRow {
            digest: rabs_key::authority_binding::coordinator_authority_digest(&coordinator),
            cluster_id: "cluster-a".to_owned(),
            incarnation: 1,
            term: 1,
            acquired_seq: 1,
        }
    }

    fn bound_attempt_authority() -> AttemptAuthority {
        let coordinator = coordinator_authority();
        let created_under = rabs_key::authority_binding::coordinator_authority_digest(&coordinator);
        AttemptAuthority {
            coordinator,
            action_key: digest("rabs.action-key.sha256.v1", 7),
            action_generation: ActionGeneration {
                generation_id: ActionGenerationId(11),
                per_key_ordinal: 1,
                created_under_authority_digest: created_under,
            },
            attempt_id: AttemptId(22),
            execution_lease_id: ExecutionLeaseId(30),
            lease_renewal_seq: LeaseRenewalSeq(1),
            worker_peer_id: PeerId("lease-worker".to_owned()),
            worker_boot_generation: WorkerBootGeneration(3),
            worker_incarnation_id: WorkerIncarnationId(99),
        }
    }

    fn worker_offer(worker: &str, generation: u64, incarnation: u128) -> WorkerSessionOffer {
        WorkerSessionOffer {
            worker_peer_id: PeerId(worker.to_owned()),
            boot_generation: WorkerBootGeneration(generation),
            incarnation: WorkerIncarnationId(incarnation),
            reenrollment_proof: None,
        }
    }

    fn publication(action_tag: u8, descriptor_tag: u8, pin: u128) -> PublicationRow {
        PublicationRow {
            action_key: digest("rabs.action-key.sha256.v1", action_tag),
            descriptor_digest: digest("rabs.descriptor.sha256.v1", descriptor_tag),
            manifest_digest: digest("rabs.result-manifest.sha256.v1", descriptor_tag),
            evidence_digest: digest("rabs.evidence-bundle.sha256.v1", descriptor_tag),
            winner_generation: 10,
            winner_attempt: 20,
            result_kind: ResultKindTag::Success,
            pin_id: pin,
            pin_owner: "coordinator".to_owned(),
            provisional_ancestors: Vec::new(),
        }
    }

    /// Drive one full behavioral pass over any backend. Returns the
    /// differential snapshot so callers can compare backends.
    fn behavioral_pass(store: &mut dyn RabsMetadataStore) -> Vec<String> {
        // H009 migrations: versioned, applied, reported.
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);

        // Single-writer authority.
        let bound_authority = bound_authority_row();
        store.acquire_authority(&bound_authority).unwrap();
        store.acquire_authority(&bound_authority).unwrap(); // idempotent
        assert!(matches!(
            store.acquire_authority(&authority(2)),
            Err(StoreError::AuthorityHeld { .. })
        ));
        assert_eq!(store.active_authority().unwrap().unwrap(), bound_authority);

        // Action entries round-trip.
        let action = ActionEntryRow {
            action_key: digest("rabs.action-key.sha256.v1", 7),
            key_epoch: 3,
            projection_epoch: 4,
        };
        store.upsert_action_entry(&action).unwrap();
        assert_eq!(
            store.lookup_action(&action.action_key).unwrap(),
            Some(action.clone())
        );
        assert_eq!(
            store
                .lookup_action(&digest("rabs.action-key.sha256.v1", 99))
                .unwrap(),
            None
        );

        // Generations: coordinator-only + never-reused ids.
        let active = bound_authority_row().digest;
        let wrong = digest("rabs.authority.sha256.v1", 2);
        assert_eq!(
            store.create_generation(&wrong, 10, &action.action_key),
            Err(StoreError::NotActiveAuthority)
        );
        store
            .create_generation(&active, 10, &action.action_key)
            .unwrap();
        store.tombstone_generation(10).unwrap();
        // Tombstoning does NOT free the id — high-water forbids reuse.
        assert_eq!(
            store.create_generation(&active, 10, &action.action_key),
            Err(StoreError::GenerationIdNotAboveHighWater)
        );
        assert_eq!(
            store.create_generation(&active, 9, &action.action_key),
            Err(StoreError::GenerationIdNotAboveHighWater)
        );
        let attempt_authority = bound_attempt_authority();
        store
            .create_bound_generation(
                &active,
                &attempt_authority.action_generation,
                &action.action_key,
            )
            .unwrap();

        // Attempts: append-only.
        store.record_attempt(20, 11, "worker-a", 5).unwrap();
        assert_eq!(
            store.record_attempt(20, 11, "worker-a", 6),
            Err(StoreError::DuplicateAttempt)
        );
        assert_eq!(
            store.record_attempt(21, 999, "worker-a", 6),
            Err(StoreError::UnknownGeneration)
        );

        // Leases: exact worker binding + durable compare-and-swap renewal,
        // with no renewal after release.
        store
            .admit_worker_session(
                &active,
                &WorkerSessionOffer {
                    worker_peer_id: attempt_authority.worker_peer_id.clone(),
                    boot_generation: attempt_authority.worker_boot_generation,
                    incarnation: attempt_authority.worker_incarnation_id,
                    reenrollment_proof: None,
                },
                4,
            )
            .unwrap();
        store
            .admit_attempt_lease(&attempt_authority, 5, 100)
            .unwrap();
        let renewal = LeaseRenewal {
            lease: attempt_authority.execution_lease_id,
            seq: LeaseRenewalSeq(2),
        };
        store
            .renew_attempt_lease(&attempt_authority, renewal, 200)
            .unwrap();
        assert_eq!(
            store.renew_attempt_lease(&attempt_authority, renewal, 300),
            Err(StoreError::LeaseRenewalMismatch)
        );
        let mut current_authority = attempt_authority.clone();
        current_authority.lease_renewal_seq = LeaseRenewalSeq(2);
        assert_eq!(
            store.renew_attempt_lease(
                &current_authority,
                LeaseRenewal {
                    lease: current_authority.execution_lease_id,
                    seq: LeaseRenewalSeq(2),
                },
                300,
            ),
            Err(StoreError::NonMonotonicRenewal)
        );
        let mut unknown = current_authority.clone();
        unknown.execution_lease_id = rabs_protocol::generation::ExecutionLeaseId(31);
        assert_eq!(
            store.renew_attempt_lease(
                &unknown,
                LeaseRenewal {
                    lease: unknown.execution_lease_id,
                    seq: LeaseRenewalSeq(3),
                },
                300,
            ),
            Err(StoreError::UnknownLease)
        );
        store.release_lease(30).unwrap();
        assert_eq!(
            store.renew_attempt_lease(
                &current_authority,
                LeaseRenewal {
                    lease: current_authority.execution_lease_id,
                    seq: LeaseRenewalSeq(3),
                },
                300,
            ),
            Err(StoreError::LeaseReleased)
        );

        // Publication: coordinator-only, transactional with pin,
        // conflict-quarantined on descriptor mismatch.
        let publication_row = publication(7, 1, 40);
        assert_eq!(
            store.commit_publication(PublicationPermit::for_fixture(&wrong), &publication_row),
            Err(StoreError::NotActiveAuthority)
        );
        assert_eq!(
            store
                .commit_publication(PublicationPermit::for_fixture(&active), &publication_row)
                .unwrap(),
            CommitOutcome::Committed
        );
        assert_eq!(
            store
                .commit_publication(PublicationPermit::for_fixture(&active), &publication_row)
                .unwrap(),
            CommitOutcome::IdempotentDuplicate
        );
        assert_eq!(
            store
                .commit_publication(
                    PublicationPermit::for_fixture(&active),
                    &publication(7, 2, 41),
                )
                .unwrap(),
            CommitOutcome::ConflictQuarantined
        );
        assert!(store.has_publication(&publication_row.action_key).unwrap());
        assert!(
            !store
                .has_publication(&digest("rabs.action-key.sha256.v1", 99))
                .unwrap()
        );
        // Evidence is append-only and idempotent per digest.
        let extra_evidence = digest("rabs.evidence-bundle.sha256.v1", 90);
        let manifest_key = digest_key(&publication_row.manifest_digest);
        store
            .append_evidence(
                &publication_row.action_key,
                &manifest_key,
                &extra_evidence,
                11,
                20,
            )
            .unwrap();
        // Re-append under a DIFFERENT attribution: idempotent no-op, the
        // original (manifest, generation, attempt) row is never rewritten
        // (H029).
        store
            .append_evidence(
                &publication_row.action_key,
                "rabs.canonical-result-manifest.sha256.v1:ff",
                &extra_evidence,
                99,
                98,
            )
            .unwrap();
        let evidence_line = store
            .differential_snapshot()
            .unwrap()
            .into_iter()
            .find(|l| l.starts_with("action_evidence_index|") && l.contains("|5a5a"))
            .expect("extra evidence row present");
        assert!(
            evidence_line.contains(&u128_hex(11)) && evidence_line.contains(&u128_hex(20)),
            "first-writer attribution preserved: {evidence_line}"
        );
        assert!(
            !evidence_line.ends_with(":ff"),
            "re-append must not rebind the manifest: {evidence_line}"
        );
        // Per-manifest listing binds evidence to the canonical result.
        let for_manifest = store
            .list_evidence_keys_for_manifest(&manifest_key)
            .unwrap();
        assert!(for_manifest.contains(&digest_key(&extra_evidence)));
        assert!(
            store
                .list_evidence_keys_for_manifest("rabs.canonical-result-manifest.sha256.v1:ff")
                .unwrap()
                .is_empty()
        );

        // Objects, locations, pins.
        let object = digest("rabs.object.sha256.v1", 50);
        store.record_object(&object, 4096).unwrap();
        store
            .add_location(&object, "/cas/aa/bb", Some(7), "raw", true)
            .unwrap();
        store
            .add_location(&object, "/cas/cc/dd", None, "zstd", false)
            .unwrap();
        store
            .create_pin(
                60,
                &object,
                "operator",
                "administrative",
                Some(500),
                Some("manual hold"),
                false,
                "operator investigation",
            )
            .unwrap();
        assert_eq!(
            store.release_pin(60, "someone-else"),
            Err(StoreError::PinOwnerMismatch)
        );
        assert_eq!(
            store.release_pin(61, "operator"),
            Err(StoreError::UnknownPin)
        );
        // H010: pin lease renewal is strictly monotonic.
        store.renew_pin(60, 2).unwrap();
        assert_eq!(
            store.renew_pin(60, 2),
            Err(StoreError::NonMonotonicPinRenewal)
        );
        assert_eq!(store.renew_pin(62, 1), Err(StoreError::UnknownPin));

        // H010: reachability edges from the pinned root.
        let child = digest("rabs.object.sha256.v1", 51);
        let grandchild = digest("rabs.object.sha256.v1", 52);
        let orphan = digest("rabs.object.sha256.v1", 53);
        store.record_object(&child, 16).unwrap();
        store.record_object(&grandchild, 16).unwrap();
        store.record_object(&orphan, 16).unwrap();
        store
            .add_object_edge(&object, &child, "manifest-entry")
            .unwrap();
        store.add_object_edge(&child, &grandchild, "chunk").unwrap();
        // Cycle back to the root must not loop the traversal.
        store
            .add_object_edge(&grandchild, &object, "back-ref")
            .unwrap();

        // H010: location quarantine is COPY evidence, never identity.
        store
            .set_location_quarantined(&object, "/cas/aa/bb", true)
            .unwrap();
        assert!(
            store.object_located(&object).unwrap(),
            "second clean copy remains"
        );
        store
            .set_location_quarantined(&object, "/cas/cc/dd", true)
            .unwrap();
        assert!(
            !store.object_located(&object).unwrap(),
            "all copies quarantined: object unavailable"
        );
        // The object row and its edges are untouched by construction.
        store
            .set_location_quarantined(&object, "/cas/aa/bb", false)
            .unwrap();
        assert!(store.object_located(&object).unwrap());

        // Recipes, breakdowns, trust, quarantine, verification.
        store
            .put_recipe(&action.action_key, &digest("rabs.recipe.sha256.v1", 70))
            .unwrap();
        store
            .put_key_breakdown(
                &action.action_key,
                "toolchain",
                &digest("rabs.component.sha256.v1", 71),
            )
            .unwrap();
        store
            .set_trust(&action.action_key, "trusted", "verified twice")
            .unwrap();
        store
            .add_quarantine(QuarantineScope::Location, "/cas/cc/dd", "checksum mismatch")
            .unwrap();
        store
            .record_verification_sample(&action.action_key, 20, true, 8)
            .unwrap();

        // GC snapshot + reconciliation scan.
        let snapshot = store.gc_snapshot(9).unwrap();
        // Publication pin (40) + administrative pin (60) both unreleased.
        assert_eq!(snapshot.pinned_roots.len(), 2);
        assert_eq!(snapshot.located_objects, vec![digest_key(&object)]);
        // H010 reachability: both pin roots plus the object→child→
        // grandchild closure (the cycle edge terminates via the visited
        // set); the orphan is NOT reachable.
        assert_eq!(snapshot.reachable_from_pins.len(), 4);
        assert!(snapshot.reachable_from_pins.contains(&digest_key(&object)));
        assert!(snapshot.reachable_from_pins.contains(&digest_key(&child)));
        assert!(
            snapshot
                .reachable_from_pins
                .contains(&digest_key(&grandchild))
        );
        assert!(!snapshot.reachable_from_pins.contains(&digest_key(&orphan)));
        let scan = store.reconciliation_scan().unwrap();
        assert_eq!(scan.len(), 2);
        assert_eq!(scan[0].verified_seq, Some(7));
        assert_eq!(scan[0].encoding, "raw");
        assert!(!scan[0].quarantined);
        assert_eq!(scan[1].verified_seq, None);
        assert_eq!(scan[1].encoding, "zstd");
        assert!(scan[1].quarantined);

        // H038: peer authority high-water is monotone in term.
        assert_eq!(
            store.record_peer_authority_high_water(&wrong, "peer-1", 5, 100),
            Err(StoreError::NotActiveAuthority)
        );
        store
            .record_peer_authority_high_water(&active, "peer-1", 5, 100)
            .unwrap();
        store
            .record_peer_authority_high_water(&active, "peer-1", 5, 101)
            .unwrap(); // equal term: idempotent no-op
        assert_eq!(
            store.record_peer_authority_high_water(&active, "peer-1", 4, 102),
            Err(StoreError::StalePeerAuthority)
        );
        store
            .record_peer_authority_high_water(&active, "peer-1", 6, 103)
            .unwrap();
        assert_eq!(
            store.peer_authority_high_water("peer-1").unwrap(),
            Some((6, 103))
        );
        assert_eq!(store.peer_authority_high_water("peer-2").unwrap(), None);

        // S022/I47: BOOT generations are monotone; random incarnation
        // IDs are equality fences, never ordered counters. Admission and
        // the open-session journal append are one transaction.
        let first = worker_offer("worker-a", 3, 11);
        assert_eq!(
            store.admit_worker_session(&wrong, &first, 1_100),
            Err(StoreError::NotActiveAuthority)
        );
        assert_eq!(
            store.admit_worker_session(&active, &first, 1_100),
            Ok(WorkerAdmission::AdmitNewGeneration)
        );
        assert_eq!(
            store.admit_worker_session(&active, &first, 1_100),
            Ok(WorkerAdmission::AdmitReconnect),
            "same session admission is idempotent"
        );
        assert_eq!(
            store.admit_worker_session(&active, &first, 1_101),
            Ok(WorkerAdmission::AdmitReconnect),
            "one incarnation may hold multiple reconnect sessions"
        );
        assert_eq!(
            store.admit_worker_session(&active, &worker_offer("worker-a", 2, u128::MAX), 1_102,),
            Ok(WorkerAdmission::RejectStaleBootGeneration)
        );
        assert_eq!(
            store.admit_worker_session(&active, &worker_offer("worker-a", 3, 22), 1_103),
            Ok(WorkerAdmission::RejectCloneAmbiguity)
        );
        assert!(
            !store
                .release_worker_session(
                    &active,
                    &PeerId("worker-a".into()),
                    WorkerIncarnationId(22),
                    1_100,
                    1_104,
                )
                .unwrap()
        );
        assert!(
            store
                .release_worker_session(
                    &active,
                    &PeerId("worker-a".into()),
                    WorkerIncarnationId(11),
                    1_100,
                    1_104,
                )
                .unwrap()
        );
        assert_eq!(
            store.admit_worker_session(&active, &worker_offer("worker-a", 3, 22), 1_105),
            Ok(WorkerAdmission::RejectCloneAmbiguity),
            "releasing one reconnect must not clear another open session's fence"
        );
        assert!(
            store
                .release_worker_session(
                    &active,
                    &PeerId("worker-a".into()),
                    WorkerIncarnationId(11),
                    1_101,
                    1_106,
                )
                .unwrap()
        );
        assert_eq!(
            store.admit_worker_session(&active, &worker_offer("worker-a", 3, 22), 1_107),
            Ok(WorkerAdmission::RejectCloneAmbiguity),
            "session release cannot adjudicate a detected clone"
        );
        let mut rolled_back = worker_offer("worker-a", 1, 99);
        rolled_back.reenrollment_proof = Some(1);
        assert_eq!(
            store.admit_worker_session(&active, &rolled_back, 1_108),
            Ok(WorkerAdmission::RejectStaleBootGeneration),
            "operator proof cannot lower the durable global high-water"
        );
        let mut reenrolled = worker_offer("worker-a", 3, 99);
        reenrolled.reenrollment_proof = Some(1);
        assert_eq!(
            store.admit_worker_session(&active, &reenrolled, 1_109),
            Ok(WorkerAdmission::AdmitViaReenrollment)
        );
        let mut replay = worker_offer("worker-a", 3, 100);
        replay.reenrollment_proof = Some(1);
        assert_eq!(
            store.admit_worker_session(&active, &replay, 1_110),
            Ok(WorkerAdmission::RejectCloneAmbiguity),
            "a consumed operator proof cannot pick a second clone"
        );
        assert_eq!(
            store.worker_incarnation_fence(&PeerId("worker-a".into())),
            Ok(Some(WorkerIncarnationFenceRecord {
                worker_peer_id: PeerId("worker-a".into()),
                highest_boot_generation: WorkerBootGeneration(3),
                active_incarnation: Some(WorkerIncarnationId(99)),
                clone_ambiguous: true,
                operator_reenrollment_generation: 1,
            }))
        );
        assert_eq!(
            store.worker_incarnation_fence(&PeerId("worker-b".into())),
            Ok(None)
        );

        let max_generation = worker_offer("worker-max", u64::MAX, u128::MAX);
        assert_eq!(
            store.admit_worker_session(&active, &max_generation, 1_111),
            Ok(WorkerAdmission::AdmitNewGeneration)
        );
        assert_eq!(
            store
                .worker_incarnation_fence(&PeerId("worker-max".into()))
                .unwrap()
                .unwrap()
                .highest_boot_generation,
            WorkerBootGeneration(u64::MAX),
        );

        // H038: edge handoff — at most one active row, predecessor NAMED
        // and matching the fence, fence advances only at resolve.
        store.advance_edge_fence(&active, "edge-1", 10).unwrap();
        assert_eq!(
            store.advance_edge_fence(&active, "edge-1", 9),
            Err(StoreError::StaleEdgeIncarnation)
        );
        assert_eq!(
            store.begin_edge_handoff(&active, "edge-1", 11, 9, 200),
            Err(StoreError::EdgeHandoffPredecessorMismatch)
        );
        assert_eq!(
            store.begin_edge_handoff(&active, "edge-1", 10, 10, 200),
            Err(StoreError::StaleEdgeIncarnation)
        );
        store
            .begin_edge_handoff(&active, "edge-1", 11, 10, 200)
            .unwrap();
        store
            .begin_edge_handoff(&active, "edge-1", 11, 10, 200)
            .unwrap(); // idempotent re-begin
        assert_eq!(
            store.begin_edge_handoff(&active, "edge-1", 12, 10, 201),
            Err(StoreError::EdgeHandoffActive)
        );
        assert_eq!(
            store.active_edge_handoff("edge-1").unwrap(),
            Some(EdgeHandoffRow {
                active_incarnation: 11,
                predecessor_incarnation: 10,
                begun_seq: 200,
            })
        );
        assert_eq!(
            store.edge_fence("edge-1").unwrap(),
            Some(10),
            "fence advances only at resolve"
        );
        assert_eq!(
            store.resolve_edge_handoff(&active, "edge-1", 12),
            Err(StoreError::UnknownEdgeHandoff)
        );
        store.resolve_edge_handoff(&active, "edge-1", 11).unwrap();
        assert_eq!(store.edge_fence("edge-1").unwrap(), Some(11));
        assert_eq!(store.active_edge_handoff("edge-1").unwrap(), None);
        // The NEXT handoff must name the NEW fence as predecessor.
        assert_eq!(
            store.begin_edge_handoff(&active, "edge-1", 12, 10, 202),
            Err(StoreError::EdgeHandoffPredecessorMismatch)
        );
        store
            .begin_edge_handoff(&active, "edge-1", 12, 11, 202)
            .unwrap();

        // H038: trust evaluations are an authority-gated append-only
        // versioned ledger.
        let evaluation = TrustEvaluationRow {
            version: 1,
            state: "trusted".to_owned(),
            reason: "verified once".to_owned(),
            evaluated_seq: 300,
        };
        assert_eq!(
            store.append_trust_evaluation(&wrong, &action.action_key, &evaluation),
            Err(StoreError::NotActiveAuthority)
        );
        store
            .append_trust_evaluation(&active, &action.action_key, &evaluation)
            .unwrap();
        assert_eq!(
            store.append_trust_evaluation(&active, &action.action_key, &evaluation),
            Err(StoreError::NonMonotonicTrustEvaluation)
        );
        let demotion = TrustEvaluationRow {
            version: 2,
            state: "suspect".to_owned(),
            reason: "divergent recompute".to_owned(),
            evaluated_seq: 301,
        };
        store
            .append_trust_evaluation(&active, &action.action_key, &demotion)
            .unwrap();
        assert_eq!(
            store.latest_trust_evaluation(&action.action_key).unwrap(),
            Some(demotion)
        );

        // H038: operations — coordinator-only creation, duplicates
        // refused.
        assert_eq!(
            store.create_operation(&wrong, 400, "transfer", "running", 310),
            Err(StoreError::NotActiveAuthority)
        );
        store
            .create_operation(&active, 400, "transfer", "running", 310)
            .unwrap();
        assert_eq!(
            store.create_operation(&active, 400, "transfer", "running", 311),
            Err(StoreError::DuplicateOperation)
        );
        store.update_operation_state(400, "done", 312).unwrap();
        assert_eq!(
            store.update_operation_state(401, "done", 312),
            Err(StoreError::UnknownOperation)
        );
        assert_eq!(store.operation_state(400).unwrap(), Some("done".to_owned()));

        // H038: edge subscribers — first registration wins.
        store
            .register_edge_subscriber("edge-1", "sub-a", 320)
            .unwrap();
        store
            .register_edge_subscriber("edge-1", "sub-a", 999)
            .unwrap(); // no-op; seq 320 retained
        store
            .register_edge_subscriber("edge-1", "sub-b", 321)
            .unwrap();
        assert_eq!(
            store.list_edge_subscribers("edge-1").unwrap(),
            vec!["sub-a".to_owned(), "sub-b".to_owned()]
        );
        assert!(store.remove_edge_subscriber("edge-1", "sub-b").unwrap());
        assert!(!store.remove_edge_subscriber("edge-1", "sub-b").unwrap());

        // H038: manifest metadata — divergence under one digest refused.
        let manifest = digest("rabs.result-manifest.sha256.v1", 80);
        store.record_manifest(&manifest, "tree", 12).unwrap();
        store.record_manifest(&manifest, "tree", 12).unwrap();
        assert_eq!(
            store.record_manifest(&manifest, "tree", 13),
            Err(StoreError::ManifestDivergence)
        );
        assert_eq!(
            store.manifest_meta(&manifest).unwrap(),
            Some(("tree".to_owned(), 12))
        );

        // H038: worker sessions / capabilities / health samples.
        store.record_worker_session("worker-a", 3, 330).unwrap();
        store.record_worker_session("worker-a", 3, 330).unwrap();
        assert_eq!(
            store.record_worker_session("worker-a", 4, 330),
            Err(StoreError::AppendConflict("worker_sessions".into()))
        );
        assert!(store.end_worker_session("worker-a", 330, 340).unwrap());
        assert!(!store.end_worker_session("worker-a", 330, 341).unwrap());
        store.record_worker_capability("worker-a", "nix").unwrap();
        store.record_worker_capability("worker-a", "nix").unwrap();
        store.record_worker_capability("worker-a", "cargo").unwrap();
        assert_eq!(
            store.list_worker_capabilities("worker-a").unwrap(),
            vec!["cargo".to_owned(), "nix".to_owned()]
        );
        store
            .record_worker_health_sample("worker-a", 350, true, "ok")
            .unwrap();
        store
            .record_worker_health_sample("worker-a", 350, true, "ok")
            .unwrap();
        assert_eq!(
            store.record_worker_health_sample("worker-a", 350, false, "ok"),
            Err(StoreError::AppendConflict("worker_health_samples".into()))
        );

        // H038: decision receipts, provenance edges, determinism audits.
        store
            .record_decision_receipt("gc", "run-1", 360, "reclaim", "under pressure")
            .unwrap();
        store
            .record_decision_receipt("gc", "run-1", 360, "reclaim", "under pressure")
            .unwrap();
        assert_eq!(
            store.record_decision_receipt("gc", "run-1", 360, "skip", "under pressure"),
            Err(StoreError::AppendConflict("decision_receipts".into()))
        );
        store
            .add_provenance_edge(&object, &child, "derived-from")
            .unwrap();
        store
            .add_provenance_edge(&object, &child, "derived-from")
            .unwrap();
        store
            .record_determinism_audit(&action.action_key, 20, 370, "deterministic")
            .unwrap();
        store
            .record_determinism_audit(&action.action_key, 20, 370, "deterministic")
            .unwrap();
        assert_eq!(
            store.record_determinism_audit(&action.action_key, 20, 370, "divergent"),
            Err(StoreError::AppendConflict("determinism_audits".into()))
        );

        // H038: materialization records.
        store
            .create_materialization(500, &object, "/work/out", "staging", 380)
            .unwrap();
        store
            .create_materialization(500, &object, "/work/out", "staging", 380)
            .unwrap();
        assert_eq!(
            store.create_materialization(500, &object, "/work/other", "staging", 381),
            Err(StoreError::AppendConflict("materialization_records".into()))
        );
        store
            .update_materialization_state(500, "complete", 382)
            .unwrap();
        assert_eq!(
            store.update_materialization_state(501, "complete", 382),
            Err(StoreError::UnknownMaterialization)
        );
        assert_eq!(
            store.materialization_state(500).unwrap(),
            Some("complete".to_owned())
        );

        // Authority release + handover.
        store.release_authority(&active).unwrap();
        assert_eq!(store.active_authority().unwrap(), None);
        store.acquire_authority(&authority(2)).unwrap();

        store.differential_snapshot().unwrap()
    }

    #[test]
    fn h009_reference_backend_full_behavioral_pass() {
        let engine = RusqliteEngine::open_in_memory().unwrap();
        let mut store = SqlMetadataStore::open(engine).unwrap();
        let snapshot = behavioral_pass(&mut store);
        assert!(!snapshot.is_empty());
    }

    #[test]
    fn h009_frankensqlite_backend_full_behavioral_pass() {
        let engine = FsqliteEngine::open(&fresh_path("fsqlite-pass")).unwrap();
        let mut store = SqlMetadataStore::open(engine).unwrap();
        let snapshot = behavioral_pass(&mut store);
        assert!(!snapshot.is_empty());
    }

    #[test]
    fn h009_differential_harness_reference_vs_frankensqlite() {
        // THE H009 acceptance: the identical operation script runs on the
        // reference backend and on FrankenSQLite, and every table dumps
        // IDENTICALLY (outcome equality is asserted inside the pass).
        let reference_engine = RusqliteEngine::open(&fresh_path("ref-diff")).unwrap();
        let mut reference = SqlMetadataStore::open(reference_engine).unwrap();
        let candidate_engine = FsqliteEngine::open(&fresh_path("fsq-diff")).unwrap();
        let mut candidate = SqlMetadataStore::open(candidate_engine).unwrap();
        let reference_snapshot = behavioral_pass(&mut reference);
        let candidate_snapshot = behavioral_pass(&mut candidate);
        assert_eq!(reference_snapshot, candidate_snapshot);
    }

    #[test]
    fn h009_generation_high_water_survives_reopen() {
        // Never-reused generation ids must survive a store restart (the
        // high-water outlives active-slot state; plan §62).
        let path = fresh_path("reopen");
        {
            let engine = RusqliteEngine::open(&path).unwrap();
            let mut store = SqlMetadataStore::open(engine).unwrap();
            store.acquire_authority(&authority(1)).unwrap();
            let action = ActionEntryRow {
                action_key: digest("rabs.action-key.sha256.v1", 7),
                key_epoch: 0,
                projection_epoch: 0,
            };
            store.upsert_action_entry(&action).unwrap();
            store
                .create_generation(
                    &digest("rabs.authority.sha256.v1", 1),
                    42,
                    &action.action_key,
                )
                .unwrap();
        }
        let engine = RusqliteEngine::open(&path).unwrap();
        let mut store = SqlMetadataStore::open(engine).unwrap();
        // Migrations are idempotent across reopen.
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
        store.acquire_authority(&authority(1)).unwrap();
        assert_eq!(
            store.create_generation(
                &digest("rabs.authority.sha256.v1", 1),
                42,
                &digest("rabs.action-key.sha256.v1", 7),
            ),
            Err(StoreError::GenerationIdNotAboveHighWater)
        );
    }

    #[test]
    fn h009_domain_restore_is_fail_closed() {
        // A domain never written by this process cannot be silently
        // re-typed on read (R121): a fresh store instance over the same
        // file refuses to restore rows whose domains it has not interned.
        let path = fresh_path("domains");
        {
            let engine = RusqliteEngine::open(&path).unwrap();
            let mut store = SqlMetadataStore::open(engine).unwrap();
            store.acquire_authority(&authority(1)).unwrap();
        }
        let engine = RusqliteEngine::open(&path).unwrap();
        let mut store = SqlMetadataStore::open(engine).unwrap();
        assert_eq!(
            store.active_authority(),
            Err(StoreError::DomainNotInterned(
                "rabs.authority.sha256.v1".to_owned()
            ))
        );
    }

    fn h038_fence_seed(store: &mut dyn RabsMetadataStore) {
        store.acquire_authority(&authority(1)).unwrap();
        let active = digest("rabs.authority.sha256.v1", 1);
        assert_eq!(
            store.admit_worker_session(&active, &worker_offer("worker-a", 7, 70), 700),
            Ok(WorkerAdmission::AdmitNewGeneration)
        );
        store.advance_edge_fence(&active, "edge-1", 9).unwrap();
    }
    fn h038_fence_check_after_reopen(store: &mut dyn RabsMetadataStore) {
        // Fence rows written by the seed survive the reopen: values set
        // before the reopen stay refused after it.
        store.acquire_authority(&authority(1)).unwrap();
        let active = digest("rabs.authority.sha256.v1", 1);
        assert_eq!(
            store
                .worker_incarnation_fence(&PeerId("worker-a".into()))
                .unwrap()
                .unwrap()
                .highest_boot_generation,
            WorkerBootGeneration(7)
        );
        assert_eq!(store.edge_fence("edge-1").unwrap(), Some(9));
        assert_eq!(
            store.admit_worker_session(&active, &worker_offer("worker-a", 6, 60), 701),
            Ok(WorkerAdmission::RejectStaleBootGeneration)
        );
        assert_eq!(
            store.admit_worker_session(&active, &worker_offer("worker-a", 7, 71), 702),
            Ok(WorkerAdmission::RejectCloneAmbiguity)
        );
        assert_eq!(
            store.advance_edge_fence(&active, "edge-1", 8),
            Err(StoreError::StaleEdgeIncarnation)
        );
        assert_eq!(
            store.admit_worker_session(&active, &worker_offer("worker-a", 8, 80), 703),
            Ok(WorkerAdmission::RejectCloneAmbiguity),
            "a self-reported boot increment cannot select the legitimate clone"
        );
        let mut resolved = worker_offer("worker-a", 8, 80);
        resolved.reenrollment_proof = Some(1);
        assert_eq!(
            store.admit_worker_session(&active, &resolved, 704),
            Ok(WorkerAdmission::AdmitViaReenrollment)
        );
    }

    fn seed_v19_worker_fence<E: SqlEngine>(engine: &mut E) {
        for migration in MIGRATIONS
            .iter()
            .filter(|migration| migration.version <= 19)
        {
            engine.execute("BEGIN", &[]).unwrap();
            for statement in migration.statements {
                engine.execute(statement, &[]).unwrap();
            }
            engine
                .execute(
                    "INSERT INTO schema_epochs (version, applied_seq) VALUES (?1, 0)",
                    &[SqlValue::Int(i64::from(migration.version))],
                )
                .unwrap();
            engine.execute("COMMIT", &[]).unwrap();
        }
        engine
            .execute(
                "INSERT INTO worker_incarnation_fences (worker, incarnation) VALUES (?1, ?2)",
                &[
                    SqlValue::Text("legacy-worker".to_owned()),
                    SqlValue::Blob(u128_blob(0xCAFE)),
                ],
            )
            .unwrap();
    }

    fn assert_v19_worker_fence_migrated(store: &mut dyn RabsMetadataStore) {
        assert_eq!(store.schema_version(), Ok(SCHEMA_VERSION));
        assert_eq!(
            store.worker_incarnation_fence(&PeerId("legacy-worker".to_owned())),
            Ok(Some(WorkerIncarnationFenceRecord {
                worker_peer_id: PeerId("legacy-worker".to_owned()),
                highest_boot_generation: WorkerBootGeneration(0),
                active_incarnation: Some(WorkerIncarnationId(0xCAFE)),
                clone_ambiguous: true,
                operator_reenrollment_generation: 0,
            })),
            "a pre-S022 row migrates as an ambiguous active generation-zero fence"
        );
    }

    fn seed_v20_attempt_lease<E: SqlEngine>(engine: &mut E) {
        for migration in MIGRATIONS
            .iter()
            .filter(|migration| migration.version <= 20)
        {
            engine.execute("BEGIN", &[]).unwrap();
            for statement in migration.statements {
                engine.execute(statement, &[]).unwrap();
            }
            engine
                .execute(
                    "INSERT INTO schema_epochs (version, applied_seq) VALUES (?1, 0)",
                    &[SqlValue::Int(i64::from(migration.version))],
                )
                .unwrap();
            engine.execute("COMMIT", &[]).unwrap();
        }

        let authority = bound_authority_row().digest;
        let action = digest("rabs.action-key.sha256.v1", 7);
        engine
            .execute(
                "INSERT INTO action_generations \
                 (id_hex, id, action_key, authority_key, tombstoned) \
                 VALUES (?1, ?2, ?3, ?4, 0)",
                &[
                    SqlValue::Text(u128_hex(11)),
                    SqlValue::Blob(u128_blob(11)),
                    SqlValue::Text(digest_key(&action)),
                    SqlValue::Text(digest_key(&authority)),
                ],
            )
            .unwrap();
        engine
            .execute(
                "INSERT INTO generation_high_water (kind, value) \
                 VALUES ('action-generation', ?1)",
                &[SqlValue::Blob(u128_blob(11))],
            )
            .unwrap();
        engine
            .execute(
                "INSERT INTO action_attempts (id_hex, id, generation_hex, worker, seq) \
                 VALUES (?1, ?2, ?3, 'lease-worker', 5)",
                &[
                    SqlValue::Text(u128_hex(22)),
                    SqlValue::Blob(u128_blob(22)),
                    SqlValue::Text(u128_hex(11)),
                ],
            )
            .unwrap();
        engine
            .execute(
                "INSERT INTO execution_leases \
                 (id_hex, id, attempt_hex, renewal_seq, expires_at_seq, released) \
                 VALUES (?1, ?2, ?3, 1, 100, 0)",
                &[
                    SqlValue::Text(u128_hex(30)),
                    SqlValue::Blob(u128_blob(30)),
                    SqlValue::Text(u128_hex(22)),
                ],
            )
            .unwrap();
        engine
            .execute(
                "INSERT INTO worker_incarnation_fences \
                 (worker, incarnation, highest_boot_generation, active, \
                  operator_reenrollment_generation) \
                 VALUES ('lease-worker', ?1, ?2, 1, ?3)",
                &[
                    SqlValue::Blob(u128_blob(99)),
                    SqlValue::Blob(u64_blob(3)),
                    SqlValue::Blob(u64_blob(0)),
                ],
            )
            .unwrap();
    }

    fn assert_v20_attempt_lease_fails_closed(store: &mut dyn RabsMetadataStore) {
        assert_eq!(store.schema_version(), Ok(SCHEMA_VERSION));
        store.acquire_authority(&bound_authority_row()).unwrap();
        assert_eq!(
            store.worker_incarnation_fence(&PeerId("lease-worker".to_owned())),
            Ok(Some(WorkerIncarnationFenceRecord {
                worker_peer_id: PeerId("lease-worker".to_owned()),
                highest_boot_generation: WorkerBootGeneration(3),
                active_incarnation: Some(WorkerIncarnationId(99)),
                clone_ambiguous: true,
                operator_reenrollment_generation: 0,
            }))
        );
        let legacy = bound_attempt_authority();
        assert_eq!(
            store.validate_attempt_lease(&legacy),
            Err(StoreError::LegacyUnboundAuthority)
        );
        assert_eq!(
            store.renew_attempt_lease(
                &legacy,
                LeaseRenewal {
                    lease: legacy.execution_lease_id,
                    seq: LeaseRenewalSeq(2),
                },
                200,
            ),
            Err(StoreError::LegacyUnboundAuthority)
        );
        let mut legacy_row = publication(7, 1, 40);
        legacy_row.winner_generation = 11;
        legacy_row.winner_attempt = 22;
        assert_eq!(
            store.commit_publication(PublicationPermit::for_attempt(&legacy), &legacy_row),
            Err(StoreError::LegacyUnboundAuthority)
        );
        assert!(!store.has_publication(&legacy.action_key).unwrap());

        let mut selected = worker_offer("lease-worker", 3, 100);
        selected.reenrollment_proof = Some(1);
        assert_eq!(
            store.admit_worker_session(&bound_authority_row().digest, &selected, 200),
            Ok(WorkerAdmission::AdmitViaReenrollment)
        );
        let mut replacement = legacy;
        replacement.action_generation.generation_id = ActionGenerationId(12);
        replacement.action_generation.per_key_ordinal = 2;
        replacement.attempt_id = AttemptId(23);
        replacement.execution_lease_id = ExecutionLeaseId(31);
        replacement.worker_incarnation_id = WorkerIncarnationId(100);
        store
            .upsert_action_entry(&ActionEntryRow {
                action_key: replacement.action_key.clone(),
                key_epoch: 1,
                projection_epoch: 1,
            })
            .unwrap();
        store
            .create_bound_generation(
                &bound_authority_row().digest,
                &replacement.action_generation,
                &replacement.action_key,
            )
            .unwrap();
        store.admit_attempt_lease(&replacement, 201, 300).unwrap();
        assert_eq!(
            store.validate_attempt_lease(&replacement),
            Ok(LeaseState {
                released: false,
                renewal_seq: 1,
            })
        );
    }

    #[test]
    fn s022_migrates_populated_v19_worker_fence_reference() {
        let path = fresh_path("s022-v19-ref");
        {
            let mut engine = RusqliteEngine::open(&path).unwrap();
            seed_v19_worker_fence(&mut engine);
        }
        let engine = RusqliteEngine::open(&path).unwrap();
        let mut store = SqlMetadataStore::open(engine).unwrap();
        assert_v19_worker_fence_migrated(&mut store);
    }

    #[test]
    fn s022_migrates_populated_v19_worker_fence_frankensqlite() {
        let path = fresh_path("s022-v19-fsq");
        {
            let mut engine = FsqliteEngine::open(&path).unwrap();
            seed_v19_worker_fence(&mut engine);
        }
        let engine = FsqliteEngine::open(&path).unwrap();
        let mut store = SqlMetadataStore::open(engine).unwrap();
        assert_v19_worker_fence_migrated(&mut store);
    }

    #[test]
    fn t038_migrates_populated_v20_attempt_lease_fail_closed_reference() {
        let path = fresh_path("t038-v20-ref");
        {
            let mut engine = RusqliteEngine::open(&path).unwrap();
            seed_v20_attempt_lease(&mut engine);
        }
        let engine = RusqliteEngine::open(&path).unwrap();
        let mut store = SqlMetadataStore::open(engine).unwrap();
        assert_v20_attempt_lease_fails_closed(&mut store);
    }

    #[test]
    fn t038_migrates_populated_v20_attempt_lease_fail_closed_frankensqlite() {
        let path = fresh_path("t038-v20-fsq");
        {
            let mut engine = FsqliteEngine::open(&path).unwrap();
            seed_v20_attempt_lease(&mut engine);
        }
        let engine = FsqliteEngine::open(&path).unwrap();
        let mut store = SqlMetadataStore::open(engine).unwrap();
        assert_v20_attempt_lease_fails_closed(&mut store);
    }

    #[test]
    fn s022_and_h038_fences_survive_reopen_reference() {
        let path = fresh_path("h038-fence-ref");
        {
            let engine = RusqliteEngine::open(&path).unwrap();
            let mut store = SqlMetadataStore::open(engine).unwrap();
            h038_fence_seed(&mut store);
        }
        let engine = RusqliteEngine::open(&path).unwrap();
        let mut store = SqlMetadataStore::open(engine).unwrap();
        h038_fence_check_after_reopen(&mut store);
    }

    #[test]
    fn s022_and_h038_fences_survive_reopen_frankensqlite() {
        let path = fresh_path("h038-fence-fsq");
        {
            let engine = FsqliteEngine::open(&path).unwrap();
            let mut store = SqlMetadataStore::open(engine).unwrap();
            h038_fence_seed(&mut store);
        }
        let engine = FsqliteEngine::open(&path).unwrap();
        let mut store = SqlMetadataStore::open(engine).unwrap();
        h038_fence_check_after_reopen(&mut store);
    }

    fn table_names<E: SqlEngine>(store: &mut SqlMetadataStore<E>) -> Vec<String> {
        store
            .engine_mut()
            .query(
                "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name",
                &[],
            )
            .unwrap()
            .into_iter()
            .map(|row| match row.into_iter().next() {
                Some(SqlValue::Text(t)) => t,
                other => panic!("table name shape: {other:?}"),
            })
            .collect()
    }

    #[test]
    fn h038_full_authoritative_table_set_no_failure_table() {
        // The COMPLETE Epic-H table surface, pinned exactly: a table
        // appearing or disappearing without this list changing is a
        // schema regression. Deterministic failures are ResultKind
        // publications — the absence of any failure table is asserted
        // below, not just assumed.
        let expected: Vec<String> = [
            "action_attempts",
            "action_entries",
            "action_evidence_index",
            "action_generations",
            "action_publications",
            "action_serving_states",
            "action_trust_evaluations",
            "adoption_edges",
            "coordinator_authorities",
            "decision_receipts",
            "determinism_audits",
            "divergence_incidents",
            "edge_handoffs",
            "edge_incarnation_fences",
            "edge_subscribers",
            "eviction_tombstones",
            "execution_leases",
            "gc_receipts",
            "gc_runs",
            "gc_tombstones",
            "generation_high_water",
            "key_breakdowns",
            "manifests",
            "materialization_records",
            "native_child_bindings",
            "object_edges",
            "object_locations",
            "objects",
            "observed_input_recipes",
            "operations",
            "operator_resets",
            "peer_authority_high_water",
            "pins",
            "provenance_edges",
            "provisional_ancestry",
            "provisional_install_journal",
            "provisional_obligations",
            "provisional_pin_grants",
            "provisional_pin_lineage",
            "provisional_pins",
            "quarantines",
            "schema_epochs",
            "serving_blocking_quarantines",
            "trust_states",
            "verification_samples",
            "worker_capabilities",
            "worker_health_samples",
            "worker_incarnation_fences",
            "worker_sessions",
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
        assert!(
            expected.iter().all(|name| !name.contains("failure")),
            "deterministic failures are ResultKind publications; no failure table may exist"
        );
        let engine = RusqliteEngine::open_in_memory().unwrap();
        let mut store = SqlMetadataStore::open(engine).unwrap();
        assert_eq!(table_names(&mut store), expected);
        let engine = FsqliteEngine::open(&fresh_path("h038-tables")).unwrap();
        let mut store = SqlMetadataStore::open(engine).unwrap();
        assert_eq!(table_names(&mut store), expected);
    }

    #[test]
    fn h038_deterministic_failure_publishes_as_result_kind() {
        // One publication path for success AND deterministic failure
        // (I16): the failure lands in action_publications carrying its
        // result kind — there is no separate failure table to receive
        // it (asserted structurally in the table-set test above).
        let engine = RusqliteEngine::open_in_memory().unwrap();
        let mut store = SqlMetadataStore::open(engine).unwrap();
        store.acquire_authority(&authority(1)).unwrap();
        let active = digest("rabs.authority.sha256.v1", 1);
        let mut row = publication(9, 3, 90);
        row.result_kind = ResultKindTag::DeterministicFailure;
        assert_eq!(
            store
                .commit_publication(PublicationPermit::for_fixture(&active), &row)
                .unwrap(),
            CommitOutcome::Committed
        );
        let dump = store.differential_snapshot().unwrap();
        assert!(
            dump.iter().any(|line| {
                line.starts_with("action_publications|") && line.contains("|deterministic-failure|")
            }),
            "failure publication must appear in action_publications with its result kind"
        );
    }
}
