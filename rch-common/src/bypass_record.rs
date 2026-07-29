//! Temporary-bypass record schema and persistent store
//! (bd-session-history-remediation-ocv9i.1.2).
//!
//! When a worker hits a *transient* failure (SSH flake, disk pressure, a missing
//! toolchain, stale telemetry, circuit churn, …) the recovery path quarantines
//! it on the live eligibility axis ([`crate`] consumers call this a
//! "temporary bypass") instead of mutating operator-desired inventory. This
//! module owns the durable record of that quarantine.
//!
//! A [`BypassRecord`] is the persisted, status-surfaceable description of one
//! bypassed worker: who it is (id/host/user), why it was bypassed (the precise
//! [`BypassFailureClass`] plus a stable [`IncidentReasonCode`] for ledger
//! correlation), the failure/probe bookkeeping (first/last failure, next probe,
//! backoff, consecutive pass/fail counts), the last diagnostic summary, the
//! auto-rejoin criteria, and whether local fallback was allowed for affected
//! commands. It feeds `rch status`, `rch workers list --json`, incident-ledger
//! events, and future admission explanations.
//!
//! The [`BypassRecordStore`] is a single-document JSON map keyed by worker id
//! (one current record per worker), persisted atomically (temp-file + rename)
//! and corruption-tolerant on load. Unlike the append-only
//! [`crate::incident_ledger`] (an *event* log), the bypass store holds *current
//! state*: a record is removed when its worker fully rejoins.
//!
//! ## Migration
//!
//! Historically, agents reacted to transient worker illness by *admin-disabling*
//! the worker, which leaves the fleet permanently smaller after recovery. The
//! [`migrate_disabled_worker`] strategy inspects a disabled worker's reason
//! string: when it looks transient ([`classify_disable_reason`] matches a
//! failure class) it produces a [`BypassRecord`] so the worker can auto-rejoin;
//! otherwise the worker is kept disabled (a genuine or unknown operator intent
//! must never be silently auto-undone).
//!
//! ## Privacy
//!
//! The record carries a bounded `last_diagnostic` summary and a small `details`
//! map; it never stores raw command lines or secrets. `last_diagnostic` is
//! truncated to [`MAX_DIAGNOSTIC_CHARS`].

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use schemars::schema::RootSchema;
use schemars::{JsonSchema, schema_for};
use serde::{Deserialize, Serialize};

use crate::incident::IncidentReasonCode;
use crate::schema_versions::{SchemaComponent, current_version};

/// Maximum retained length (in characters) of a record's diagnostic summary.
/// Keeps records compact and avoids accidentally persisting large command
/// output into the state file.
pub const MAX_DIAGNOSTIC_CHARS: usize = 512;

/// Concrete failure class that quarantined a worker into a temporary bypass.
///
/// Mirrors the raw session-history failure classes enumerated in the program
/// validation contract (`docs/guides/session-history-remediation-validation.md`)
/// so incident/status output can attribute a bypass to a specific root cause.
///
/// Serialized as `snake_case`. New variants must be **appended**, never
/// reordered or renamed, so historical state/JSONL replays continue to
/// deserialize (this enum crosses the daemon/status JSON boundary and is stored
/// on disk).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BypassFailureClass {
    /// SSH connection/auth failure to the worker.
    Ssh,
    /// `rch-wkr` missing, wrong path, or wrong user on the worker.
    WorkerBinary,
    /// Required runtime/toolchain/Rust target absent on the worker.
    RuntimeToolchain,
    /// Disk or inode pressure on the worker.
    DiskInodePressure,
    /// Worker telemetry is stale or its age is unknown.
    StaleTelemetry,
    /// Path/source sync (rsync) failure to the worker.
    PathSync,
    /// Artifact retrieval from the worker failed.
    ArtifactRetrieval,
    /// Worker's circuit breaker is open.
    CircuitBreaker,
    /// Worker OS/architecture does not match the build target.
    OsArchMismatch,
}

impl BypassFailureClass {
    /// Every failure class, in stable declaration order. Used for exhaustive
    /// attribution tests and enumeration.
    pub const ALL: &'static [BypassFailureClass] = &[
        Self::Ssh,
        Self::WorkerBinary,
        Self::RuntimeToolchain,
        Self::DiskInodePressure,
        Self::StaleTelemetry,
        Self::PathSync,
        Self::ArtifactRetrieval,
        Self::CircuitBreaker,
        Self::OsArchMismatch,
    ];

    /// Stable `snake_case` wire identifier (matches the serde form).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ssh => "ssh",
            Self::WorkerBinary => "worker_binary",
            Self::RuntimeToolchain => "runtime_toolchain",
            Self::DiskInodePressure => "disk_inode_pressure",
            Self::StaleTelemetry => "stale_telemetry",
            Self::PathSync => "path_sync",
            Self::ArtifactRetrieval => "artifact_retrieval",
            Self::CircuitBreaker => "circuit_breaker",
            Self::OsArchMismatch => "os_arch_mismatch",
        }
    }

    /// Operator-facing label for status surfaces.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Ssh => "SSH connection failure",
            Self::WorkerBinary => "worker binary missing/wrong path or user",
            Self::RuntimeToolchain => "missing runtime/toolchain/target",
            Self::DiskInodePressure => "disk/inode pressure",
            Self::StaleTelemetry => "telemetry stale/age unknown",
            Self::PathSync => "path/source sync failure",
            Self::ArtifactRetrieval => "artifact retrieval failure",
            Self::CircuitBreaker => "circuit breaker open",
            Self::OsArchMismatch => "OS/arch mismatch",
        }
    }

    /// Stable [`IncidentReasonCode`] this failure class maps to, so a bypass can
    /// feed the incident ledger with the shared reason-code vocabulary.
    ///
    /// The mapping is total and reuses the existing registry rather than
    /// inventing a parallel one. `Ssh` (a worker the daemon cannot even reach)
    /// maps to [`IncidentReasonCode::HardPreflight`] — an unreachable candidate
    /// hard-fails the very first preflight check.
    #[must_use]
    pub const fn incident_reason_code(self) -> IncidentReasonCode {
        match self {
            Self::Ssh => IncidentReasonCode::HardPreflight,
            Self::WorkerBinary => IncidentReasonCode::WrongUserPathWorkerBinary,
            Self::RuntimeToolchain => IncidentReasonCode::MissingRuntimeToolchainTarget,
            Self::DiskInodePressure => IncidentReasonCode::DiskFull,
            Self::StaleTelemetry => IncidentReasonCode::TelemetryStale,
            Self::PathSync => IncidentReasonCode::RsyncVanishedFile,
            Self::ArtifactRetrieval => IncidentReasonCode::ArtifactMiss,
            Self::CircuitBreaker => IncidentReasonCode::CircuitOpen,
            Self::OsArchMismatch => IncidentReasonCode::OsArchMismatch,
        }
    }

    /// Parse a `snake_case` wire identifier back to a failure class.
    #[must_use]
    pub fn from_str_opt(s: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|c| c.as_str() == s)
    }
}

/// The quarantine state a bypassed worker is currently in. Mirrors the two
/// transient eligibility states a record can describe: a worker with a live
/// bypass record is either still bypassed or has passed recovery and awaits a
/// canary build before full rejoin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BypassState {
    /// Quarantined out of scheduling because of [`BypassRecord::failure_class`].
    TemporaryBypass,
    /// Passed its recovery probe(s); awaiting one canary build before rejoin.
    RecoveredPendingCanary,
}

impl BypassState {
    /// Human label for status surfaces.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::TemporaryBypass => "temporary bypass",
            Self::RecoveredPendingCanary => "recovered, pending canary",
        }
    }
}

/// Exponential backoff window for recovery probing of a bypassed worker.
///
/// The record carries this state so the probe/canary loop (bead 1.3) can
/// schedule the next probe deterministically; [`BypassBackoff::advanced`] is the
/// pure doubling step used when a probe fails again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BypassBackoff {
    /// Current backoff window in milliseconds (gap before the next probe).
    pub current_ms: u64,
    /// Number of probe attempts scheduled since the bypass began.
    pub attempts: u32,
    /// Ceiling for the backoff window in milliseconds.
    pub max_ms: u64,
}

impl BypassBackoff {
    /// Default initial backoff window (30s).
    pub const DEFAULT_INITIAL_MS: u64 = 30_000;
    /// Default backoff ceiling (15min).
    pub const DEFAULT_MAX_MS: u64 = 900_000;

    /// A fresh backoff: the default initial window, zero attempts.
    #[must_use]
    pub const fn initial() -> Self {
        Self {
            current_ms: Self::DEFAULT_INITIAL_MS,
            attempts: 0,
            max_ms: Self::DEFAULT_MAX_MS,
        }
    }

    /// The next backoff after another failed probe: double the window (capped at
    /// `max_ms`) and increment the attempt count.
    #[must_use]
    pub const fn advanced(self) -> Self {
        let doubled = self.current_ms.saturating_mul(2);
        let current_ms = if doubled > self.max_ms {
            self.max_ms
        } else {
            doubled
        };
        Self {
            current_ms,
            attempts: self.attempts.saturating_add(1),
            max_ms: self.max_ms,
        }
    }
}

impl Default for BypassBackoff {
    fn default() -> Self {
        Self::initial()
    }
}

/// The criteria a bypassed worker must satisfy before auto-rejoining.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AutoRejoinCriteria {
    /// Consecutive successful recovery probes required before advancing.
    pub required_consecutive_passes: u32,
    /// Whether one canary build is required before full rejoin.
    pub canary_required: bool,
}

impl Default for AutoRejoinCriteria {
    fn default() -> Self {
        Self {
            required_consecutive_passes: 2,
            canary_required: true,
        }
    }
}

/// A durable record of one temporarily-bypassed worker.
///
/// This is the persisted, status-surfaceable description of a transient
/// quarantine. It is *not* operator inventory: an entry here never implies the
/// operator disabled the worker, and clearing it lets the worker auto-rejoin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BypassRecord {
    /// Schema version (`SchemaComponent::WorkerBypassRecord`).
    pub schema_version: String,
    /// Worker id (the store's key).
    pub worker_id: String,
    /// Worker host (for status display and exact-path validation).
    pub host: String,
    /// Worker SSH user (for status display and exact-path validation).
    pub user: String,
    /// Precise worker-lifecycle failure class that caused the bypass.
    pub failure_class: BypassFailureClass,
    /// Stable incident reason code for ledger correlation (serializes as
    /// `RCH-Innn`). Derived from [`Self::failure_class`] at construction.
    #[schemars(with = "String")]
    pub reason_code: IncidentReasonCode,
    /// Current quarantine state.
    pub state: BypassState,
    /// Unix epoch milliseconds of the first failure that began this bypass.
    pub first_failure_unix_ms: u64,
    /// Unix epoch milliseconds of the most recent failure.
    pub last_failure_unix_ms: u64,
    /// Unix epoch milliseconds when the next recovery probe is due.
    pub next_probe_unix_ms: u64,
    /// Exponential backoff state for recovery probing.
    pub backoff: BypassBackoff,
    /// Consecutive failed checks observed for this worker.
    pub consecutive_failures: u32,
    /// Consecutive successful recovery probes observed for this worker.
    pub consecutive_passes: u32,
    /// Short, bounded diagnostic summary (never a raw command or secret).
    pub last_diagnostic: String,
    /// Criteria the worker must meet before auto-rejoining.
    pub auto_rejoin: AutoRejoinCriteria,
    /// Whether local fallback was allowed for commands affected by this bypass.
    pub local_fallback_allowed: bool,
    /// Compact, ordered free-form details (small, bounded; not for secrets).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub details: BTreeMap<String, String>,
}

impl BypassRecord {
    /// Begin a bypass: a worker just hit `failure_class` at
    /// `first_failure_unix_ms`. The first recovery probe is scheduled one
    /// initial-backoff window later.
    #[must_use]
    pub fn new(
        worker_id: impl Into<String>,
        host: impl Into<String>,
        user: impl Into<String>,
        failure_class: BypassFailureClass,
        first_failure_unix_ms: u64,
    ) -> Self {
        let backoff = BypassBackoff::initial();
        Self {
            schema_version: bypass_record_schema_version().to_string(),
            worker_id: worker_id.into(),
            host: host.into(),
            user: user.into(),
            failure_class,
            reason_code: failure_class.incident_reason_code(),
            state: BypassState::TemporaryBypass,
            first_failure_unix_ms,
            last_failure_unix_ms: first_failure_unix_ms,
            next_probe_unix_ms: first_failure_unix_ms.saturating_add(backoff.current_ms),
            backoff,
            consecutive_failures: 1,
            consecutive_passes: 0,
            last_diagnostic: String::new(),
            auto_rejoin: AutoRejoinCriteria::default(),
            local_fallback_allowed: true,
            details: BTreeMap::new(),
        }
    }

    /// Set the diagnostic summary (truncated to [`MAX_DIAGNOSTIC_CHARS`]).
    #[must_use]
    pub fn with_diagnostic(mut self, diagnostic: impl Into<String>) -> Self {
        self.last_diagnostic = truncate_diagnostic(diagnostic.into());
        self
    }

    /// Set whether local fallback was allowed for affected commands.
    #[must_use]
    pub fn with_local_fallback_allowed(mut self, allowed: bool) -> Self {
        self.local_fallback_allowed = allowed;
        self
    }

    /// Set the auto-rejoin criteria (builder style).
    #[must_use]
    pub fn with_auto_rejoin(mut self, criteria: AutoRejoinCriteria) -> Self {
        self.auto_rejoin = criteria;
        self
    }

    /// Insert a compact detail key/value (builder style).
    #[must_use]
    pub fn with_detail(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.details.insert(key.into(), value.into());
        self
    }

    /// Record another failure for an already-bypassed worker: bump the failure
    /// count, reset the pass count, advance the backoff, reschedule the next
    /// probe, and return to [`BypassState::TemporaryBypass`].
    ///
    /// This is record bookkeeping only; deciding *when* to probe is the
    /// probe/canary loop's job (bead 1.3).
    pub fn record_failure(&mut self, now_unix_ms: u64, diagnostic: impl Into<String>) {
        self.last_failure_unix_ms = now_unix_ms;
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.consecutive_passes = 0;
        self.backoff = self.backoff.advanced();
        self.next_probe_unix_ms = now_unix_ms.saturating_add(self.backoff.current_ms);
        self.state = BypassState::TemporaryBypass;
        let diagnostic = diagnostic.into();
        if !diagnostic.is_empty() {
            self.last_diagnostic = truncate_diagnostic(diagnostic);
        }
    }

    /// Record a successful recovery probe: bump the pass count, reset the
    /// failure count, and reschedule the next probe. Returns `true` once the
    /// worker has met [`AutoRejoinCriteria::required_consecutive_passes`]. When
    /// the criteria require a canary, the state advances to
    /// [`BypassState::RecoveredPendingCanary`]; otherwise the caller may rejoin
    /// the worker (removing this record).
    pub fn record_probe_pass(&mut self, now_unix_ms: u64) -> bool {
        self.consecutive_passes = self.consecutive_passes.saturating_add(1);
        self.consecutive_failures = 0;
        self.next_probe_unix_ms = now_unix_ms.saturating_add(self.backoff.current_ms);
        let met = self.consecutive_passes >= self.auto_rejoin.required_consecutive_passes;
        if met && self.auto_rejoin.canary_required {
            self.state = BypassState::RecoveredPendingCanary;
        }
        met
    }

    /// Whether a recovery probe is due at `now_unix_ms`.
    #[must_use]
    pub const fn probe_due(&self, now_unix_ms: u64) -> bool {
        now_unix_ms >= self.next_probe_unix_ms
    }
}

/// Truncate a diagnostic string to [`MAX_DIAGNOSTIC_CHARS`] on a char boundary,
/// appending an ellipsis marker when truncated.
#[must_use]
pub fn truncate_diagnostic(mut s: String) -> String {
    if s.chars().count() <= MAX_DIAGNOSTIC_CHARS {
        return s;
    }
    let cut = s
        .char_indices()
        .nth(MAX_DIAGNOSTIC_CHARS)
        .map_or(s.len(), |(i, _)| i);
    s.truncate(cut);
    s.push('…');
    s
}

/// The current worker-bypass-record schema version.
#[must_use]
pub fn bypass_record_schema_version() -> &'static str {
    current_version(SchemaComponent::WorkerBypassRecord)
}

/// Export the JSON Schema for [`BypassRecord`].
#[must_use]
pub fn bypass_record_schema() -> RootSchema {
    schema_for!(BypassRecord)
}

// ---------------------------------------------------------------------------
// Persistent store
// ---------------------------------------------------------------------------

/// On-disk wrapper document. A top-level object (not a bare array) so the file
/// can grow new top-level fields without a breaking format change.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
struct BypassRecordFile {
    /// Store-format schema version (matches the record schema version).
    schema_version: String,
    /// Current records (one per worker; deduplicated by worker id on load).
    records: Vec<BypassRecord>,
}

/// Resolve the default store path: `${RCH_STATE_HOME}/bypass_records.json`,
/// falling through the same XDG hierarchy as [`crate::incident_ledger`].
#[must_use]
pub fn default_bypass_record_path() -> PathBuf {
    let base = std::env::var_os("RCH_STATE_HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .or_else(|| {
            std::env::var_os("XDG_STATE_HOME")
                .map(|d| PathBuf::from(d).join("rch"))
                .filter(|p| p.as_os_str().len() > "rch".len())
        })
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/state/rch")))
        .unwrap_or_else(|| PathBuf::from("/tmp/rch"));
    base.join("bypass_records.json")
}

/// A single-document, atomically-persisted, corruption-tolerant store of
/// current [`BypassRecord`]s keyed by worker id.
#[derive(Debug, Clone)]
pub struct BypassRecordStore {
    path: PathBuf,
    records: BTreeMap<String, BypassRecord>,
}

impl BypassRecordStore {
    /// An empty store bound to `path` (nothing read from disk).
    #[must_use]
    pub fn with_path(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            records: BTreeMap::new(),
        }
    }

    /// Load the store from `path`. A missing or unparseable file yields an empty
    /// store (the bypass state is reconstructable from live worker state and the
    /// incident ledger), so a corrupt file never blocks daemon startup.
    #[must_use]
    pub fn load(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let mut records = BTreeMap::new();
        if let Ok(bytes) = fs::read(&path)
            && let Ok(file) = serde_json::from_slice::<BypassRecordFile>(&bytes)
        {
            for record in file.records {
                // Latest entry wins if a malformed file duplicated a worker id.
                records.insert(record.worker_id.clone(), record);
            }
        }
        Self { path, records }
    }

    /// The store file path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The current record for a worker, if bypassed.
    #[must_use]
    pub fn get(&self, worker_id: &str) -> Option<&BypassRecord> {
        self.records.get(worker_id)
    }

    /// Whether a worker currently has a bypass record.
    #[must_use]
    pub fn contains(&self, worker_id: &str) -> bool {
        self.records.contains_key(worker_id)
    }

    /// All current records, ordered by worker id.
    #[must_use]
    pub fn all(&self) -> Vec<&BypassRecord> {
        self.records.values().collect()
    }

    /// Number of bypassed workers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether any worker is currently bypassed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Insert or replace a worker's record and persist the store.
    pub fn upsert(&mut self, record: BypassRecord) -> std::io::Result<()> {
        self.records.insert(record.worker_id.clone(), record);
        self.persist()
    }

    /// Remove a worker's record (e.g. after full rejoin) and persist. Returns
    /// the removed record, if any.
    pub fn remove(&mut self, worker_id: &str) -> std::io::Result<Option<BypassRecord>> {
        let removed = self.records.remove(worker_id);
        if removed.is_some() {
            self.persist()?;
        }
        Ok(removed)
    }

    /// Atomically write the current records to disk (temp-file + rename), so a
    /// concurrent reader never observes a partial file.
    fn persist(&self) -> std::io::Result<()> {
        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }
        let doc = BypassRecordFile {
            schema_version: bypass_record_schema_version().to_string(),
            records: self.records.values().cloned().collect(),
        };
        let body = serde_json::to_vec_pretty(&doc)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        let tmp = parent.join(format!(".bypass_records.{}.tmp", std::process::id()));
        {
            let mut tmp_file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp)?;
            tmp_file.write_all(&body)?;
            tmp_file.flush()?;
        }
        match fs::rename(&tmp, &self.path) {
            Ok(()) => Ok(()),
            Err(e) => {
                let _ = fs::remove_file(&tmp);
                Err(e)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Migration: admin-disabled (for transient illness) -> temporary bypass
// ---------------------------------------------------------------------------

/// A snapshot of an admin-disabled worker, used to decide whether its disable
/// was a reaction to transient illness (and thus migrate-able to a temporary
/// bypass) or a deliberate operator action (and thus left disabled).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisabledWorkerSnapshot {
    /// Worker id.
    pub worker_id: String,
    /// Worker host.
    pub host: String,
    /// Worker SSH user.
    pub user: String,
    /// The recorded disable reason, if any.
    pub disabled_reason: Option<String>,
    /// When the worker was disabled (Unix epoch milliseconds), if known.
    pub disabled_at_unix_ms: Option<u64>,
}

/// The outcome of evaluating a disabled worker for migration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisabledMigration {
    /// The disable looked transient: migrate to this temporary-bypass record so
    /// the worker can auto-rejoin once healthy again.
    Migrate(Box<BypassRecord>),
    /// The disable is a deliberate or unknown operator action: keep it disabled.
    KeepDisabled {
        /// Why migration was declined.
        reason: String,
    },
}

/// Heuristically classify a disable-reason string into a transient
/// [`BypassFailureClass`]. Returns `None` when the reason does not look
/// transient (or is empty), in which case the worker should stay disabled.
///
/// Matching is case-insensitive and substring-based; order is most-specific
/// first so e.g. "no space left on device" is classified as disk pressure
/// rather than something more generic.
#[must_use]
pub fn classify_disable_reason(reason: &str) -> Option<BypassFailureClass> {
    let r = reason.to_ascii_lowercase();
    if r.trim().is_empty() {
        return None;
    }
    // Most-specific signals first.
    const TABLE: &[(&[&str], BypassFailureClass)] = &[
        (
            &["no space", "enospc", "disk full", "inode", "disk pressure"],
            BypassFailureClass::DiskInodePressure,
        ),
        (
            &["toolchain", "rustup", "nightly", "missing target", "rustc"],
            BypassFailureClass::RuntimeToolchain,
        ),
        (
            &[
                "rch-wkr",
                "worker binary",
                "wrong user",
                "wrong path",
                "no such file",
            ],
            BypassFailureClass::WorkerBinary,
        ),
        (&["circuit"], BypassFailureClass::CircuitBreaker),
        (
            &["telemetry", "stale", "heartbeat"],
            BypassFailureClass::StaleTelemetry,
        ),
        (
            &["rsync", "vanished", "path sync", "source sync"],
            BypassFailureClass::PathSync,
        ),
        (&["artifact"], BypassFailureClass::ArtifactRetrieval),
        (
            &["os/arch", "architecture", "arch mismatch", "triple"],
            BypassFailureClass::OsArchMismatch,
        ),
        (
            &[
                "ssh",
                "connection refused",
                "connection reset",
                "connection failed",
                "connection timed out",
                "unreachable",
                "timed out",
                "auth",
                "permission denied",
            ],
            BypassFailureClass::Ssh,
        ),
    ];
    for (needles, class) in TABLE {
        if needles.iter().any(|n| r.contains(n)) {
            return Some(*class);
        }
    }
    None
}

/// Decide whether an admin-disabled worker should be migrated to a temporary
/// bypass. Workers disabled for a recognizably transient reason are migrated so
/// they can auto-rejoin; deliberate or unrecognized disables are kept disabled.
///
/// `now_unix_ms` stamps the migrated record's probe schedule (probe promptly).
#[must_use]
pub fn migrate_disabled_worker(
    snapshot: &DisabledWorkerSnapshot,
    now_unix_ms: u64,
) -> DisabledMigration {
    let Some(reason) = snapshot.disabled_reason.as_deref() else {
        return DisabledMigration::KeepDisabled {
            reason: "no disable reason recorded — treat as deliberate operator disable".to_string(),
        };
    };
    let Some(class) = classify_disable_reason(reason) else {
        return DisabledMigration::KeepDisabled {
            reason: format!("disable reason does not look transient: {reason:?}"),
        };
    };

    let first_failure = snapshot.disabled_at_unix_ms.unwrap_or(now_unix_ms);
    let mut record = BypassRecord::new(
        &snapshot.worker_id,
        &snapshot.host,
        &snapshot.user,
        class,
        first_failure,
    )
    .with_diagnostic(format!("migrated from admin-disabled: {reason}"))
    .with_detail("migrated_from", "admin_disabled");
    // Probe promptly after migration rather than waiting a full initial backoff
    // window from the original (possibly old) disable time.
    record.next_probe_unix_ms = now_unix_ms;
    DisabledMigration::Migrate(Box::new(record))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TS: u64 = 1_700_000_000_000;

    fn record(class: BypassFailureClass) -> BypassRecord {
        BypassRecord::new("css", "203.0.113.20", "ubuntu", class, TS)
    }

    #[test]
    fn failure_class_wire_form_is_stable_snake_case() {
        assert_eq!(BypassFailureClass::Ssh.as_str(), "ssh");
        assert_eq!(
            BypassFailureClass::DiskInodePressure.as_str(),
            "disk_inode_pressure"
        );
        // serde form matches as_str().
        for c in BypassFailureClass::ALL {
            let json = serde_json::to_string(c).unwrap();
            assert_eq!(json, format!("\"{}\"", c.as_str()));
            assert_eq!(BypassFailureClass::from_str_opt(c.as_str()), Some(*c));
        }
        assert_eq!(BypassFailureClass::from_str_opt("nonsense"), None);
    }

    #[test]
    fn failure_class_maps_to_an_incident_reason_for_every_variant() {
        // Total mapping — every class has a stable reason code for the ledger.
        for c in BypassFailureClass::ALL {
            let code = c.incident_reason_code();
            // Round-trips through the incident registry.
            assert_eq!(
                IncidentReasonCode::from_code_str(code.code()),
                Some(code),
                "reason code for {c:?} not in registry"
            );
        }
        assert_eq!(
            BypassFailureClass::Ssh.incident_reason_code(),
            IncidentReasonCode::HardPreflight
        );
        assert_eq!(
            BypassFailureClass::CircuitBreaker.incident_reason_code(),
            IncidentReasonCode::CircuitOpen
        );
        assert_eq!(
            BypassFailureClass::DiskInodePressure.incident_reason_code(),
            IncidentReasonCode::DiskFull
        );
    }

    #[test]
    fn new_record_is_consistent_and_schema_stamped() {
        let r = record(BypassFailureClass::Ssh);
        assert_eq!(r.schema_version, bypass_record_schema_version());
        assert_eq!(r.state, BypassState::TemporaryBypass);
        assert_eq!(r.reason_code, IncidentReasonCode::HardPreflight);
        assert_eq!(r.consecutive_failures, 1);
        assert_eq!(r.consecutive_passes, 0);
        assert_eq!(r.first_failure_unix_ms, TS);
        assert_eq!(r.last_failure_unix_ms, TS);
        assert_eq!(r.next_probe_unix_ms, TS + BypassBackoff::DEFAULT_INITIAL_MS);
        assert!(r.local_fallback_allowed);
    }

    #[test]
    fn record_serializes_required_fields_and_roundtrips() {
        let r = record(BypassFailureClass::CircuitBreaker)
            .with_diagnostic("circuit open after 5 failures")
            .with_local_fallback_allowed(false)
            .with_detail("attempts", "5");
        let v = serde_json::to_value(&r).unwrap();
        // Every field the bead requires must be present and machine-readable.
        for key in [
            "worker_id",
            "host",
            "user",
            "failure_class",
            "reason_code",
            "state",
            "first_failure_unix_ms",
            "last_failure_unix_ms",
            "next_probe_unix_ms",
            "backoff",
            "consecutive_failures",
            "consecutive_passes",
            "last_diagnostic",
            "auto_rejoin",
            "local_fallback_allowed",
        ] {
            assert!(v.get(key).is_some(), "missing record field {key}");
        }
        assert_eq!(v["failure_class"], "circuit_breaker");
        assert_eq!(v["reason_code"], "RCH-I009");
        assert_eq!(v["local_fallback_allowed"], false);
        let back: BypassRecord = serde_json::from_value(v).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn record_never_carries_raw_command_or_secret_fields() {
        let v = serde_json::to_value(record(BypassFailureClass::Ssh)).unwrap();
        let obj = v.as_object().unwrap();
        for forbidden in ["command", "raw_command", "secret", "password", "token"] {
            assert!(
                !obj.contains_key(forbidden),
                "must not expose `{forbidden}`"
            );
        }
    }

    #[test]
    fn diagnostic_is_truncated() {
        let long = "x".repeat(MAX_DIAGNOSTIC_CHARS + 50);
        let r = record(BypassFailureClass::Ssh).with_diagnostic(long);
        assert!(r.last_diagnostic.chars().count() <= MAX_DIAGNOSTIC_CHARS + 1);
        assert!(r.last_diagnostic.ends_with('…'));
        // Short diagnostics are untouched.
        let short = record(BypassFailureClass::Ssh).with_diagnostic("brief");
        assert_eq!(short.last_diagnostic, "brief");
    }

    #[test]
    fn backoff_doubles_up_to_ceiling() {
        let mut b = BypassBackoff::initial();
        assert_eq!(b.current_ms, BypassBackoff::DEFAULT_INITIAL_MS);
        let mut last = b.current_ms;
        for _ in 0..20 {
            b = b.advanced();
            assert!(b.current_ms >= last);
            assert!(b.current_ms <= BypassBackoff::DEFAULT_MAX_MS);
            last = b.current_ms;
        }
        // Eventually pinned at the ceiling.
        assert_eq!(b.current_ms, BypassBackoff::DEFAULT_MAX_MS);
        assert_eq!(b.attempts, 20);
    }

    #[test]
    fn record_failure_advances_backoff_and_resets_passes() {
        let mut r = record(BypassFailureClass::Ssh);
        r.consecutive_passes = 1;
        let before = r.backoff.current_ms;
        r.record_failure(TS + 1000, "ssh timed out");
        assert_eq!(r.consecutive_failures, 2);
        assert_eq!(r.consecutive_passes, 0);
        assert!(r.backoff.current_ms > before);
        assert_eq!(r.next_probe_unix_ms, TS + 1000 + r.backoff.current_ms);
        assert_eq!(r.last_diagnostic, "ssh timed out");
        assert_eq!(r.state, BypassState::TemporaryBypass);
    }

    #[test]
    fn probe_pass_advances_to_canary_when_criteria_met() {
        let mut r = record(BypassFailureClass::Ssh);
        // Default criteria: 2 passes, canary required.
        assert!(!r.record_probe_pass(TS + 1));
        assert_eq!(r.state, BypassState::TemporaryBypass);
        assert!(r.record_probe_pass(TS + 2));
        assert_eq!(r.state, BypassState::RecoveredPendingCanary);
        assert_eq!(r.consecutive_passes, 2);
        assert_eq!(r.consecutive_failures, 0);
    }

    #[test]
    fn probe_due_respects_schedule() {
        let r = record(BypassFailureClass::Ssh);
        assert!(!r.probe_due(r.next_probe_unix_ms - 1));
        assert!(r.probe_due(r.next_probe_unix_ms));
        assert!(r.probe_due(r.next_probe_unix_ms + 1));
    }

    #[test]
    fn schema_export_names_the_record_and_fields() {
        let text = serde_json::to_string(&bypass_record_schema()).unwrap();
        assert!(text.contains("BypassRecord"));
        for f in [
            "failure_class",
            "reason_code",
            "next_probe_unix_ms",
            "auto_rejoin",
            "local_fallback_allowed",
        ] {
            assert!(text.contains(f), "schema omits {f}");
        }
    }

    // ---- store ----

    #[test]
    fn store_upsert_get_remove_and_persist() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bypass_records.json");
        let mut store = BypassRecordStore::load(&path);
        assert!(store.is_empty());

        store.upsert(record(BypassFailureClass::Ssh)).unwrap();
        store
            .upsert(BypassRecord::new(
                "bil",
                "203.0.113.21",
                "ubuntu",
                BypassFailureClass::DiskInodePressure,
                TS,
            ))
            .unwrap();
        assert_eq!(store.len(), 2);
        assert!(store.contains("css"));
        assert_eq!(
            store.get("css").unwrap().failure_class,
            BypassFailureClass::Ssh
        );
        // all() is ordered by worker id.
        let ids: Vec<&str> = store.all().iter().map(|r| r.worker_id.as_str()).collect();
        assert_eq!(ids, vec!["bil", "css"]);

        let removed = store.remove("css").unwrap();
        assert_eq!(removed.unwrap().worker_id, "css");
        assert!(!store.contains("css"));
        assert!(store.remove("nope").unwrap().is_none());
    }

    #[test]
    fn store_survives_reload_across_instances() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bypass_records.json");
        {
            let mut store = BypassRecordStore::load(&path);
            store
                .upsert(record(BypassFailureClass::CircuitBreaker).with_diagnostic("circuit churn"))
                .unwrap();
        }
        let reopened = BypassRecordStore::load(&path);
        assert_eq!(reopened.len(), 1);
        let r = reopened.get("css").unwrap();
        assert_eq!(r.failure_class, BypassFailureClass::CircuitBreaker);
        assert_eq!(r.last_diagnostic, "circuit churn");
    }

    #[test]
    fn store_tolerates_corrupt_or_missing_file() {
        // Missing file -> empty.
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope.json");
        assert!(BypassRecordStore::load(&missing).is_empty());

        // Corrupt file -> empty (does not panic / block startup).
        let corrupt = dir.path().join("corrupt.json");
        fs::write(&corrupt, b"{ not valid json").unwrap();
        assert!(BypassRecordStore::load(&corrupt).is_empty());
    }

    #[test]
    fn default_path_ends_with_bypass_records_json() {
        assert!(default_bypass_record_path().ends_with("bypass_records.json"));
    }

    // ---- migration ----

    #[test]
    fn classify_disable_reason_recognizes_transient_classes() {
        assert_eq!(
            classify_disable_reason("ssh: connection refused"),
            Some(BypassFailureClass::Ssh)
        );
        assert_eq!(
            classify_disable_reason("No space left on device"),
            Some(BypassFailureClass::DiskInodePressure)
        );
        assert_eq!(
            classify_disable_reason("circuit breaker tripped"),
            Some(BypassFailureClass::CircuitBreaker)
        );
        assert_eq!(
            classify_disable_reason("missing rustup toolchain nightly"),
            Some(BypassFailureClass::RuntimeToolchain)
        );
        // Non-transient / deliberate / empty -> None.
        assert_eq!(classify_disable_reason("decommissioned by ops"), None);
        assert_eq!(classify_disable_reason(""), None);
        assert_eq!(classify_disable_reason("   "), None);
    }

    #[test]
    fn migrate_transient_disable_produces_bypass_record() {
        let snap = DisabledWorkerSnapshot {
            worker_id: "css".to_string(),
            host: "203.0.113.20".to_string(),
            user: "ubuntu".to_string(),
            disabled_reason: Some("ssh connection timed out during probe".to_string()),
            disabled_at_unix_ms: Some(TS),
        };
        match migrate_disabled_worker(&snap, TS + 100_000) {
            DisabledMigration::Migrate(record) => {
                assert_eq!(record.worker_id, "css");
                assert_eq!(record.failure_class, BypassFailureClass::Ssh);
                assert_eq!(record.first_failure_unix_ms, TS);
                // Probe promptly at migration time, not a full backoff later.
                assert_eq!(record.next_probe_unix_ms, TS + 100_000);
                assert_eq!(
                    record.details.get("migrated_from").map(String::as_str),
                    Some("admin_disabled")
                );
                assert!(
                    record
                        .last_diagnostic
                        .contains("migrated from admin-disabled")
                );
            }
            other => panic!("expected migration, got {other:?}"),
        }
    }

    #[test]
    fn migrate_deliberate_or_unknown_disable_keeps_disabled() {
        // No reason recorded -> keep disabled.
        let no_reason = DisabledWorkerSnapshot {
            worker_id: "css".to_string(),
            host: "h".to_string(),
            user: "u".to_string(),
            disabled_reason: None,
            disabled_at_unix_ms: Some(TS),
        };
        assert!(matches!(
            migrate_disabled_worker(&no_reason, TS),
            DisabledMigration::KeepDisabled { .. }
        ));

        // Deliberate reason -> keep disabled.
        let deliberate = DisabledWorkerSnapshot {
            disabled_reason: Some("retired hardware".to_string()),
            ..no_reason
        };
        assert!(matches!(
            migrate_disabled_worker(&deliberate, TS),
            DisabledMigration::KeepDisabled { .. }
        ));
    }
}
