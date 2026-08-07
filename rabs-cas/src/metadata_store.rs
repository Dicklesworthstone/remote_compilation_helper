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

use rabs_protocol::result_identity::{DigestAlgorithm, TypedDigest};

/// Current schema version (the single v1 epoch; H010/H038 add tables in
/// later epochs).
pub const SCHEMA_VERSION: u32 = 5;

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
];

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
    /// Referenced generation does not exist.
    UnknownGeneration,
    /// Referenced lease does not exist.
    UnknownLease,
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

/// The narrow transactional metadata interface (plan §62). Every method
/// is one transaction in the backing engine.
pub trait RabsMetadataStore {
    /// Applied schema version.
    fn schema_version(&mut self) -> Result<u32, StoreError>;

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

    /// Tombstone a generation (the id stays burned forever).
    fn tombstone_generation(&mut self, id: u128) -> Result<(), StoreError>;

    /// Record an attempt (append-only; duplicate id is an error).
    fn record_attempt(
        &mut self,
        id: u128,
        generation: u128,
        worker: &str,
        seq: u64,
    ) -> Result<(), StoreError>;

    /// Acquire an execution lease for an attempt.
    fn acquire_lease(
        &mut self,
        id: u128,
        attempt: u128,
        renewal_seq: u64,
        expires_at_seq: u64,
    ) -> Result<(), StoreError>;

    /// Renew a lease: `renewal_seq` must be strictly greater than stored.
    fn renew_lease(
        &mut self,
        id: u128,
        renewal_seq: u64,
        expires_at_seq: u64,
    ) -> Result<(), StoreError>;

    /// Release a lease.
    fn release_lease(&mut self, id: u128) -> Result<(), StoreError>;

    /// Coordinator-only atomic publication commit (row + serving state +
    /// winner evidence row + reachability pin in ONE transaction;
    /// conflicts quarantine).
    fn commit_publication(
        &mut self,
        authority: &TypedDigest,
        row: &PublicationRow,
    ) -> Result<CommitOutcome, StoreError>;

    /// Append an evidence-bundle association for an action (append-only;
    /// re-appending the same evidence digest is an idempotent no-op).
    fn append_evidence(
        &mut self,
        action: &TypedDigest,
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

    /// Whether a generation exists, and whether it is tombstoned.
    fn generation_state(&mut self, id: u128) -> Result<Option<GenerationState>, StoreError>;

    /// Whether an attempt exists under the given generation.
    fn attempt_exists(&mut self, id: u128, generation: u128) -> Result<bool, StoreError>;

    /// Lease state (released flag + last renewal), if the lease exists.
    fn lease_state(&mut self, id: u128) -> Result<Option<LeaseState>, StoreError>;

    /// Whether an object has at least one recorded location.
    fn object_located(&mut self, object: &TypedDigest) -> Result<bool, StoreError>;

    /// Record object metadata (digest + logical size; never bytes).
    fn record_object(&mut self, id: &TypedDigest, logical_size: u64) -> Result<(), StoreError>;

    /// Record a stored location for an object. `encoding` names the
    /// stored representation of this COPY (location evidence — it never
    /// changes the object's logical identity).
    fn add_location(
        &mut self,
        object: &TypedDigest,
        store_path: &str,
        verified_seq: Option<u64>,
        encoding: &str,
    ) -> Result<(), StoreError>;

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
}

fn expect_u64(v: &SqlValue, what: &str) -> Result<u64, StoreError> {
    match v {
        SqlValue::Int(i) => {
            u64::try_from(*i).map_err(|_| StoreError::Corruption(format!("negative {what}")))
        }
        _ => Err(StoreError::Corruption(format!("{what} shape"))),
    }
}

impl<E: SqlEngine> RabsMetadataStore for SqlMetadataStore<E> {
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

    fn acquire_lease(
        &mut self,
        id: u128,
        attempt: u128,
        renewal_seq: u64,
        expires_at_seq: u64,
    ) -> Result<(), StoreError> {
        let renewal = i64::try_from(renewal_seq)
            .map_err(|_| StoreError::Corruption("renewal_seq out of range".into()))?;
        let expires = i64::try_from(expires_at_seq)
            .map_err(|_| StoreError::Corruption("expires_at_seq out of range".into()))?;
        self.in_txn(move |engine| {
            engine.execute(
                "INSERT INTO execution_leases \
                 (id_hex, id, attempt_hex, renewal_seq, expires_at_seq, released) \
                 VALUES (?1, ?2, ?3, ?4, ?5, 0)",
                &[
                    SqlValue::Text(u128_hex(id)),
                    SqlValue::Blob(u128_blob(id)),
                    SqlValue::Text(u128_hex(attempt)),
                    SqlValue::Int(renewal),
                    SqlValue::Int(expires),
                ],
            )?;
            Ok(())
        })
    }

    fn renew_lease(
        &mut self,
        id: u128,
        renewal_seq: u64,
        expires_at_seq: u64,
    ) -> Result<(), StoreError> {
        let expires = i64::try_from(expires_at_seq)
            .map_err(|_| StoreError::Corruption("expires_at_seq out of range".into()))?;
        self.in_txn(move |engine| {
            let rows = engine.query(
                "SELECT renewal_seq, released FROM execution_leases WHERE id_hex = ?1",
                &[SqlValue::Text(u128_hex(id))],
            )?;
            let Some(row) = rows.first() else {
                return Err(StoreError::UnknownLease);
            };
            let [stored_seq, released] = row.as_slice() else {
                return Err(StoreError::Corruption("lease row shape".into()));
            };
            if expect_u64(released, "released")? != 0 {
                return Err(StoreError::LeaseReleased);
            }
            if renewal_seq <= expect_u64(stored_seq, "renewal_seq")? {
                return Err(StoreError::NonMonotonicRenewal);
            }
            let renewal = i64::try_from(renewal_seq)
                .map_err(|_| StoreError::Corruption("renewal_seq out of range".into()))?;
            engine.execute(
                "UPDATE execution_leases SET renewal_seq = ?1, expires_at_seq = ?2 \
                 WHERE id_hex = ?3",
                &[
                    SqlValue::Int(renewal),
                    SqlValue::Int(expires),
                    SqlValue::Text(u128_hex(id)),
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
        authority: &TypedDigest,
        row: &PublicationRow,
    ) -> Result<CommitOutcome, StoreError> {
        self.intern(row.action_key.domain);
        self.intern(row.descriptor_digest.domain);
        self.intern(row.manifest_digest.domain);
        self.intern(row.evidence_digest.domain);
        let authority = authority.clone();
        let row = row.clone();
        self.in_txn(move |engine| {
            SqlMetadataStore::<E>::require_active(engine, &authority)?;
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
            engine.execute(
                "INSERT OR REPLACE INTO action_serving_states (action_key, disposition, version) \
                 VALUES (?1, 'servable', 1)",
                &[SqlValue::Text(action.clone())],
            )?;
            // The winner's evidence association, SAME transaction (H011).
            let [e_algo, e_domain, e_bytes] =
                SqlMetadataStore::<E>::digest_params(&row.evidence_digest);
            engine.execute(
                "INSERT OR REPLACE INTO action_evidence_index \
                 (action_key, evidence_algo, evidence_domain, evidence_bytes, \
                  generation_hex, attempt_hex) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                &[
                    SqlValue::Text(action),
                    e_algo,
                    e_domain,
                    e_bytes,
                    SqlValue::Text(u128_hex(row.winner_generation)),
                    SqlValue::Text(u128_hex(row.winner_attempt)),
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
            Ok(CommitOutcome::Committed)
        })
    }

    fn append_evidence(
        &mut self,
        action: &TypedDigest,
        evidence: &TypedDigest,
        generation: u128,
        attempt: u128,
    ) -> Result<(), StoreError> {
        self.intern(evidence.domain);
        let action = digest_key(action);
        let [algo, domain, bytes] = SqlMetadataStore::<E>::digest_params(evidence);
        self.in_txn(move |engine| {
            engine.execute(
                "INSERT OR REPLACE INTO action_evidence_index \
                 (action_key, evidence_algo, evidence_domain, evidence_bytes, \
                  generation_hex, attempt_hex) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                &[
                    SqlValue::Text(action),
                    algo,
                    domain,
                    bytes,
                    SqlValue::Text(u128_hex(generation)),
                    SqlValue::Text(u128_hex(attempt)),
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
        let rows = self.engine.query(
            "SELECT manifest_domain, manifest_bytes FROM action_publications WHERE action_key = ?1",
            &[SqlValue::Text(digest_key(action))],
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
                 (object_key, store_path, verified_seq, encoding, quarantined) \
                 VALUES (?1, ?2, ?3, ?4, 0)",
                &[
                    SqlValue::Text(key),
                    SqlValue::Text(path),
                    verified,
                    SqlValue::Text(encoding),
                ],
            )?;
            Ok(())
        })
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
        let now = i64::try_from(now_seq)
            .map_err(|_| StoreError::Corruption("now_seq out of range".into()))?;
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
                "SELECT id_hex, id, action_key, authority_key, tombstoned \
                 FROM action_generations ORDER BY id_hex",
            ),
            (
                "generation_high_water",
                "SELECT kind, value FROM generation_high_water ORDER BY kind",
            ),
            (
                "action_attempts",
                "SELECT id_hex, id, generation_hex, worker, seq FROM action_attempts \
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
                "SELECT action_key, disposition, version FROM action_serving_states \
                 ORDER BY action_key",
            ),
            (
                "objects",
                "SELECT key, algo, domain, bytes, logical_size FROM objects ORDER BY key",
            ),
            (
                "object_locations",
                "SELECT object_key, store_path, verified_seq, encoding, quarantined \
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
                 generation_hex, attempt_hex FROM action_evidence_index \
                 ORDER BY action_key, evidence_domain, evidence_bytes",
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
        }
    }

    /// Drive one full behavioral pass over any backend. Returns the
    /// differential snapshot so callers can compare backends.
    fn behavioral_pass(store: &mut dyn RabsMetadataStore) -> Vec<String> {
        // H009 migrations: versioned, applied, reported.
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);

        // Single-writer authority.
        store.acquire_authority(&authority(1)).unwrap();
        store.acquire_authority(&authority(1)).unwrap(); // idempotent
        assert!(matches!(
            store.acquire_authority(&authority(2)),
            Err(StoreError::AuthorityHeld { .. })
        ));
        assert_eq!(store.active_authority().unwrap().unwrap(), authority(1));

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
        let active = digest("rabs.authority.sha256.v1", 1);
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
        store
            .create_generation(&active, 11, &action.action_key)
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

        // Leases: strictly monotonic renewal, no renewal after release.
        store.acquire_lease(30, 20, 1, 100).unwrap();
        store.renew_lease(30, 2, 200).unwrap();
        assert_eq!(
            store.renew_lease(30, 2, 300),
            Err(StoreError::NonMonotonicRenewal)
        );
        assert_eq!(
            store.renew_lease(30, 1, 300),
            Err(StoreError::NonMonotonicRenewal)
        );
        assert_eq!(store.renew_lease(31, 3, 300), Err(StoreError::UnknownLease));
        store.release_lease(30).unwrap();
        assert_eq!(
            store.renew_lease(30, 3, 300),
            Err(StoreError::LeaseReleased)
        );

        // Publication: coordinator-only, transactional with pin,
        // conflict-quarantined on descriptor mismatch.
        let publication_row = publication(7, 1, 40);
        assert_eq!(
            store.commit_publication(&wrong, &publication_row),
            Err(StoreError::NotActiveAuthority)
        );
        assert_eq!(
            store.commit_publication(&active, &publication_row).unwrap(),
            CommitOutcome::Committed
        );
        assert_eq!(
            store.commit_publication(&active, &publication_row).unwrap(),
            CommitOutcome::IdempotentDuplicate
        );
        assert_eq!(
            store
                .commit_publication(&active, &publication(7, 2, 41))
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
        store
            .append_evidence(&publication_row.action_key, &extra_evidence, 11, 20)
            .unwrap();
        store
            .append_evidence(&publication_row.action_key, &extra_evidence, 11, 20)
            .unwrap();

        // Objects, locations, pins.
        let object = digest("rabs.object.sha256.v1", 50);
        store.record_object(&object, 4096).unwrap();
        store
            .add_location(&object, "/cas/aa/bb", Some(7), "raw")
            .unwrap();
        store
            .add_location(&object, "/cas/cc/dd", None, "zstd")
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
}
