//! Build history tracking.
//!
//! Maintains a ring buffer of recent builds for status reporting and analytics.

use crate::disk_pressure::{DiskHeadroomAdmission, DiskHeadroomRejection};
use crate::headroom::{FootprintBook, footprint_key};
use crate::workers::{WorkerEndpointIdentity, WorkerEndpointSnapshot};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use rch_common::{
    BuildCancellationMetadata, BuildHeartbeatPhase, BuildHeartbeatRequest, BuildLocation,
    BuildRecord, BuildStats, CommandTimingBreakdown, SavedTimeStats,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::fs::OpenOptions as AsyncOpenOptions;
use tokio::io::AsyncWriteExt;
use tracing::{debug, warn};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableOwnership {
    version: u32,
    active: Vec<ActiveBuildState>,
    completed: Vec<TerminalOwnership>,
    #[serde(default)]
    cancelled_wrappers: HashSet<String>,
    #[serde(default)]
    next_queue_id: Option<u64>,
    /// Required in version 2. Absence in version 1 means that the old daemon
    /// never persisted its queue, not that a version-2 queue may be discarded.
    #[serde(default)]
    queued: Option<VecDeque<QueuedBuildState>>,
}

/// Cancellation and admission compete under the same ownership lock.
pub enum WrapperCancellation {
    BeforeStart,
    Active(u64),
    Completed(Box<BuildRecord>),
    NotQueued,
}

const MAX_CANCELLED_WRAPPERS: usize = 100_000;
/// Queue IDs occupy a separate numeric namespace from daemon build IDs.
const QUEUE_ID_NAMESPACE: u64 = 1 << 63;
/// Heartbeat progress is advisory. It is made durable this often (identity
/// and phase changes at once), so a restart sees it at most this stale.
const HEARTBEAT_PERSIST_INTERVAL: Duration = Duration::from_secs(30);
/// Terminal receipts answer a live or briefly restarted wrapper; recovery
/// reads the worker's own completion receipt. Bound them so each ownership
/// commit does not rewrite and fsync an ever-growing history.
const TERMINAL_RECEIPT_RETENTION_DAYS: i64 = 3;
const MAX_TERMINAL_RECEIPTS: usize = 500;

#[derive(Clone, Serialize, Deserialize)]
struct TerminalOwnership {
    record: BuildRecord,
    local_wrapper_id: Option<String>,
    /// Completion must not erase an owner-validated infrastructure fault
    /// before its worker quarantine is durable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending_disk_fault: Option<PendingDiskFault>,
    /// Preserve a late fault whose endpoint is stale or unknown, without
    /// granting it authority over a replacement worker. This evidence follows
    /// normal terminal receipt retention; it is never replayed as quarantine.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    unapplied_disk_fault: Option<PendingDiskFault>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PendingDiskFault {
    pub build_id: u64,
    pub worker_id: String,
    pub incident_id: String,
    pub roots: Vec<String>,
    pub reported_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_endpoint: Option<WorkerEndpointIdentity>,
    /// Additional same-daemon ABA evidence; persistence equality deliberately
    /// excludes this runtime-only authority, which never survives restart.
    #[serde(skip)]
    pub runtime_endpoint: Option<WorkerEndpointSnapshot>,
}

impl PartialEq for PendingDiskFault {
    fn eq(&self, other: &Self) -> bool {
        self.build_id == other.build_id
            && self.worker_id == other.worker_id
            && self.incident_id == other.incident_id
            && self.roots == other.roots
            && self.reported_unix_ms == other.reported_unix_ms
            && self.worker_endpoint == other.worker_endpoint
    }
}

impl Eq for PendingDiskFault {}

/// Terminal result supplied by completion or cancellation; ownership stays separate.
pub struct BuildCompletion {
    pub exit_code: i32,
    pub duration_ms: Option<u64>,
    pub bytes_transferred: Option<u64>,
    pub timing: Option<CommandTimingBreakdown>,
    pub cancellation: Option<BuildCancellationMetadata>,
}

/// Shared kernel birth proof. Linux durable strings remain compatible; Darwin
/// records microseconds rather than the old second-resolution ps display.
pub fn process_identity(pid: u32) -> Option<String> {
    match rch_common::process_identity::observe_process(pid) {
        rch_common::process_identity::ProcessObservation::Present(identity) => identity.to_record(),
        _ => None,
    }
}

/// Keep live-owner tests in the same PID namespace as the procfs identity
/// reader. Some test sandboxes virtualize getpid without remounting procfs;
/// their numeric getpid names a different process in that procfs mount.
#[cfg(test)]
pub(crate) fn observable_test_process_id() -> u32 {
    #[cfg(target_os = "linux")]
    let pid = std::fs::read_to_string("/proc/self/stat")
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap();
    #[cfg(not(target_os = "linux"))]
    let pid = std::process::id();
    assert!(
        process_identity(pid).is_some(),
        "live test process {pid} has no observable birth identity"
    );
    pid
}
/// Default maximum number of builds to retain.
const DEFAULT_CAPACITY: usize = 100;

/// Whether the recorded command completed successfully.
///
/// History carries a terminal exit code, not compilation-stage evidence.
/// In particular, Cargo's exit 101 can mean compilation or test failure, and
/// a signal can interrupt either stage. Never infer successful compilation
/// from the command kind. These counts follow the `BuildStats` exit-code
/// contract; stage-specific success requires separate evidence.
fn build_record_succeeded(record: &BuildRecord) -> bool {
    record.exit_code == 0
}

/// In-flight build state tracked for active build visibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveBuildState {
    pub id: u64,
    pub project_id: String,
    pub worker_id: String,
    pub command: String,
    /// SSH coordinates admitted for this exact build. A worker ID may be
    /// retargeted while the build runs; missing legacy coordinates stay unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) worker_endpoint: Option<WorkerEndpointSnapshot>,
    pub started_at: String,
    #[serde(skip, default = "Instant::now")]
    pub started_at_mono: Instant,
    pub hook_pid: u32,
    #[serde(default)]
    pub hook_process_identity: Option<String>,
    /// Client wrapper identity, allowing the daemon's active build to be
    /// joined with the client-side durable lease without relying on a reusable PID.
    pub local_wrapper_id: Option<String>,
    pub remote_pgid_file: Option<String>,
    pub slots: u32,
    /// Declared additional build space retained until this owner completes.
    #[serde(default)]
    pub disk_headroom_gib: u32,
    /// Free build-disk GiB on the worker at admission (bd-wv746 footprint).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_free_start_gib: Option<u64>,
    /// Lowest free build-disk GiB probed on the worker while this build ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_free_min_gib: Option<u64>,
    /// Another build admitted by this daemon overlapped on the same worker,
    /// so the observed growth cannot be attributed to this build alone.
    #[serde(default)]
    pub disk_shared: bool,
    pub location: BuildLocation,
    pub heartbeat_phase: BuildHeartbeatPhase,
    pub heartbeat_detail: Option<String>,
    pub heartbeat_counter: u64,
    pub heartbeat_percent: Option<f64>,
    pub heartbeat_count: u64,
    pub last_heartbeat_at: String,
    #[serde(skip, default = "Instant::now")]
    pub last_heartbeat_mono: Instant,
    pub last_progress_at: String,
    #[serde(skip, default = "Instant::now")]
    pub last_progress_mono: Instant,
    pub detector_hook_alive: bool,
    pub detector_heartbeat_stale: bool,
    pub detector_progress_stale: bool,
    pub detector_confidence: f64,
    pub detector_build_age_secs: u64,
    pub detector_slots_owned: u32,
    pub detector_last_evaluated_at: Option<String>,
    /// Restarted ownership must not authorize signalling a reused local PID.
    #[serde(skip)]
    pub recovered: bool,
}

impl ActiveBuildState {
    /// Whether the build's command started on its remote worker.
    ///
    /// The hook reports `Execute` (flushed immediately) before it launches the
    /// remote command, then `SyncDown` and `Finalize`. A build still at
    /// `SyncUp` never ran there, so it says nothing about the worker's cache.
    pub fn remote_command_started(&self) -> bool {
        self.location == BuildLocation::Remote
            && !matches!(self.heartbeat_phase, BuildHeartbeatPhase::SyncUp)
    }
}

/// Snapshot of stuck-detector evidence for an active build.
#[derive(Debug, Clone, Copy)]
pub struct StuckDetectorSnapshot {
    pub hook_alive: bool,
    pub heartbeat_stale: bool,
    pub progress_stale: bool,
    pub confidence: f64,
    pub build_age_secs: u64,
    pub slots_owned: u32,
}

/// Queued build state for builds waiting for available workers.
///
/// When all workers are busy and `queue_when_busy` is enabled,
/// builds are queued here instead of falling back to local execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueuedBuildState {
    /// Queue position ID (monotonically increasing).
    pub id: u64,
    /// Project identifier (hash or path).
    pub project_id: String,
    /// Command to execute.
    pub command: String,
    /// When the build was queued (ISO 8601).
    pub queued_at: String,
    /// Monotonic timestamp for duration calculations, reconstructed on restart.
    #[serde(skip, default = "Instant::now")]
    pub queued_at_mono: Instant,
    /// Hook process ID (for cancellation).
    pub hook_pid: u32,
    /// Capture at enqueue, never by adopting a PID after daemon restart.
    pub hook_process_identity: Option<String>,
    pub local_wrapper_id: Option<String>,
    /// Number of slots needed.
    pub slots_needed: u32,
    /// Exact selection constraints and the original queue timeout. Old snapshots
    /// lack this authority and remain inspectable/cancellable, not resumable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selection_contract: Option<QueueSelectionContract>,
    /// An exclusive waiter exists only in this daemon incarnation.
    #[serde(skip)]
    waiter_claim: Option<u64>,
    /// Estimated start time is advisory and must be recomputed after restart.
    #[serde(skip)]
    pub estimated_start: Option<String>,
    /// A recovered row is visible/cancellable, not a replacement live waiter.
    /// Replaying selection requires a separate, identity-fenced reattachment.
    #[serde(skip)]
    pub recovered: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueueSelectionContract {
    pub digest: [u8; 32],
    pub timeout_secs: u64,
}

/// An in-process authority to consume one queued row. It is never sent to a
/// client or recovered from disk; restart requires identity-fenced reattachment.
#[derive(Debug)]
pub struct QueuedWaiterClaim {
    queue_id: u64,
    nonce: u64,
}

/// Build history manager.
///
/// Thread-safe ring buffer of recent builds with optional persistence.
pub struct BuildHistory {
    /// Ring buffer of recent builds.
    records: RwLock<VecDeque<BuildRecord>>,
    /// Active builds (in-flight).
    active: RwLock<HashMap<u64, ActiveBuildState>>,
    /// Latest release of a positive remote disk budget. Access only while
    /// holding `active`, so completion cannot race admission's capacity check.
    /// Transient: startup loads history before probing workers, and WorkerState
    /// never restores capacity observations from disk.
    disk_budget_completed_at: Mutex<HashMap<String, Instant>>,
    /// Queued builds (waiting for workers). Membership changes take `active`
    /// first, so queue departure, cancellation and admission share one commit.
    queued: RwLock<VecDeque<QueuedBuildState>>,
    /// Maximum capacity for history.
    capacity: usize,
    /// Maximum queue depth (0 = unlimited).
    max_queue_depth: usize,
    /// Next build ID.
    next_id: AtomicU64,
    /// Next queue ID.
    next_queue_id: AtomicU64,
    next_waiter_claim: AtomicU64,
    /// Persistence path (optional).
    persistence_path: Option<PathBuf>,
    /// Terminal receipts share the atomic ownership commit, not the JSONL log.
    terminal: RwLock<HashMap<u64, TerminalOwnership>>,
    /// Never evict an intent while a delayed same-identity admission can arrive.
    cancelled_wrappers: RwLock<HashSet<String>>,
    /// When each active build's heartbeat was last made durable.
    heartbeat_persisted: Mutex<HashMap<u64, Instant>>,
    /// Learned per-project build-disk growth (bd-wv746). Advisory only.
    footprints: Mutex<FootprintBook>,
    /// A duplicate release may resume a fault, but never race the first
    /// completion's slot release or its quarantine acknowledgment.
    release_lock: tokio::sync::Mutex<()>,
    ownership_failed: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    fail_after_ownership_rename: std::sync::atomic::AtomicBool,
}

/// Default maximum queue depth.
const DEFAULT_MAX_QUEUE_DEPTH: usize = 100;

impl BuildHistory {
    /// Create a new build history with the given capacity.
    pub fn new(capacity: usize) -> Self {
        // Use a timestamp-based epoch for build IDs to prevent collisions
        // with orphaned remote processes if the daemon crashes and restarts.
        let epoch_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let initial_id = (epoch_secs << 24) | 1;

        Self {
            records: RwLock::new(VecDeque::with_capacity(capacity)),
            active: RwLock::new(HashMap::new()),
            disk_budget_completed_at: Mutex::new(HashMap::new()),
            queued: RwLock::new(VecDeque::new()),
            capacity,
            max_queue_depth: DEFAULT_MAX_QUEUE_DEPTH,
            next_id: AtomicU64::new(initial_id),
            next_queue_id: AtomicU64::new(QUEUE_ID_NAMESPACE | initial_id),
            next_waiter_claim: AtomicU64::new(1),
            persistence_path: None,
            terminal: RwLock::new(HashMap::new()),
            cancelled_wrappers: RwLock::new(HashSet::new()),
            heartbeat_persisted: Mutex::new(HashMap::new()),
            footprints: Mutex::new(FootprintBook::default()),
            release_lock: tokio::sync::Mutex::new(()),
            ownership_failed: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            fail_after_ownership_rename: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Create a new build history with default capacity.
    pub fn with_default_capacity() -> Self {
        Self::new(DEFAULT_CAPACITY)
    }

    /// Set the maximum queue depth.
    pub fn with_max_queue_depth(mut self, depth: usize) -> Self {
        self.max_queue_depth = depth;
        self
    }

    /// Enable persistence to the given path.
    pub fn with_persistence(mut self, path: PathBuf) -> Self {
        self.persistence_path = Some(path);
        self
    }
    pub fn ownership_failed(&self) -> bool {
        self.ownership_failed.load(Ordering::SeqCst)
    }

    /// Get the next build ID.
    pub fn next_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::SeqCst)
    }

    /// Record a completed build.
    ///
    /// Returns a handle to the persistence task if persistence is enabled.
    pub fn record(&self, record: BuildRecord) -> Option<tokio::task::JoinHandle<()>> {
        debug!(
            "Recording build {}: {} ({:?}, {} ms)",
            record.id, record.command, record.location, record.duration_ms
        );

        // Prepare for persistence before locking
        let persistence_task = self
            .persistence_path
            .as_ref()
            .map(|path| (path.clone(), record.clone()));

        // Update memory state under lock
        {
            let mut records = self.records.write().unwrap_or_else(|e| e.into_inner());

            // Evict oldest if at capacity
            if records.len() >= self.capacity {
                records.pop_front();
            }

            records.push_back(record);
        }

        // Persist asynchronously (fire and forget or awaitable)
        if let Some((path, record)) = persistence_task {
            Some(tokio::spawn(async move {
                if let Err(e) = Self::persist_record_async(&path, &record).await {
                    warn!("Failed to persist build record: {}", e);
                }
            }))
        } else {
            None
        }
    }

    /// Register a new active build and return its state.
    pub fn start_active_build(
        &self,
        project_id: String,
        worker_id: String,
        command: String,
        hook_pid: u32,
        slots: u32,
        location: BuildLocation,
    ) -> ActiveBuildState {
        self.start_active_build_with_wrapper(
            project_id, worker_id, command, hook_pid, None, slots, location,
        )
    }

    /// Register an active build while preserving the client durable-lease id.
    #[allow(clippy::too_many_arguments)] // Mirrors the existing explicit active-build registration contract plus correlation id.
    pub fn start_active_build_with_wrapper(
        &self,
        project_id: String,
        worker_id: String,
        command: String,
        hook_pid: u32,
        local_wrapper_id: Option<String>,
        slots: u32,
        location: BuildLocation,
    ) -> ActiveBuildState {
        let id = self.next_id();
        let started_at = Utc::now().to_rfc3339();
        let started_at_mono = Instant::now();
        let state = ActiveBuildState {
            id,
            project_id,
            worker_id,
            command,
            worker_endpoint: None,
            started_at: started_at.clone(),
            hook_process_identity: process_identity(hook_pid),
            started_at_mono,
            hook_pid,
            local_wrapper_id,
            remote_pgid_file: None,
            slots,
            disk_headroom_gib: 0,
            disk_free_start_gib: None,
            disk_free_min_gib: None,
            disk_shared: false,
            location,
            heartbeat_phase: BuildHeartbeatPhase::SyncUp,
            heartbeat_detail: Some("build_started".to_string()),
            heartbeat_counter: 0,
            heartbeat_percent: None,
            heartbeat_count: 0,
            last_heartbeat_at: started_at.clone(),
            last_heartbeat_mono: started_at_mono,
            last_progress_at: started_at,
            last_progress_mono: started_at_mono,
            detector_hook_alive: true,
            detector_heartbeat_stale: false,
            detector_progress_stale: false,
            detector_confidence: 0.0,
            detector_build_age_secs: 0,
            detector_slots_owned: slots,
            detector_last_evaluated_at: None,
            recovered: false,
        };

        let mut active = self.active.write().unwrap_or_else(|e| e.into_inner());
        active.insert(id, state.clone());
        self.persist_ownership(&active, None)
            .expect("persist active build before exposing ownership");
        state
    }

    /// Try to register a new active build, failing if the same worker already
    /// has a live build for the same project.
    pub fn try_start_active_build(
        &self,
        project_id: String,
        worker_id: String,
        command: String,
        hook_pid: u32,
        slots: u32,
        location: BuildLocation,
    ) -> Option<ActiveBuildState> {
        self.try_start_active_build_with_wrapper(
            project_id, worker_id, command, hook_pid, None, slots, location,
        )
        .expect("persist active build before exposing ownership")
    }

    /// Try to register an active build with a client durable-lease id.
    #[allow(clippy::too_many_arguments)] // Mirrors the existing explicit active-build registration contract plus correlation id.
    pub fn try_start_active_build_with_wrapper(
        &self,
        project_id: String,
        worker_id: String,
        command: String,
        hook_pid: u32,
        local_wrapper_id: Option<String>,
        slots: u32,
        location: BuildLocation,
    ) -> std::io::Result<Option<ActiveBuildState>> {
        self.try_start_active_build_with_waiter(
            project_id,
            worker_id,
            command,
            hook_pid,
            local_wrapper_id,
            slots,
            location,
            None,
            DiskHeadroomAdmission::default(),
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn try_start_active_build_with_waiter(
        &self,
        project_id: String,
        worker_id: String,
        command: String,
        hook_pid: u32,
        local_wrapper_id: Option<String>,
        slots: u32,
        location: BuildLocation,
        waiter: Option<&QueuedWaiterClaim>,
        disk: DiskHeadroomAdmission,
        worker_endpoint: Option<WorkerEndpointSnapshot>,
    ) -> std::io::Result<Option<ActiveBuildState>> {
        if worker_endpoint.as_ref().is_some_and(|endpoint| {
            endpoint.config.id.as_str() != worker_id || location != BuildLocation::Remote
        }) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "active build endpoint does not match its remote worker",
            ));
        }
        let id = self.next_id();
        if id >= QUEUE_ID_NAMESPACE {
            return Err(std::io::Error::other(
                "active build identifier namespace exhausted",
            ));
        }
        let started_at = Utc::now().to_rfc3339();
        let started_at_mono = Instant::now();
        let disk_free_start_gib = if location == BuildLocation::Remote {
            disk.capacity
                .as_ref()
                .and_then(|sample| sample.current_free_gib(&worker_id))
        } else {
            None
        };
        let mut state = ActiveBuildState {
            id,
            project_id,
            worker_id,
            command,
            worker_endpoint,
            started_at: started_at.clone(),
            hook_process_identity: process_identity(hook_pid),
            started_at_mono,
            hook_pid,
            local_wrapper_id,
            remote_pgid_file: None,
            slots,
            disk_headroom_gib: disk.requested_gib,
            disk_free_start_gib,
            disk_free_min_gib: None,
            disk_shared: false,
            location,
            heartbeat_phase: BuildHeartbeatPhase::SyncUp,
            heartbeat_detail: Some("build_started".to_string()),
            heartbeat_counter: 0,
            heartbeat_percent: None,
            heartbeat_count: 0,
            last_heartbeat_at: started_at.clone(),
            last_heartbeat_mono: started_at_mono,
            last_progress_at: started_at,
            last_progress_mono: started_at_mono,
            detector_hook_alive: true,
            detector_heartbeat_stale: false,
            detector_progress_stale: false,
            detector_confidence: 0.0,
            detector_build_age_secs: 0,
            detector_slots_owned: slots,
            detector_last_evaluated_at: None,
            recovered: false,
        };

        let mut active = self.active.write().unwrap_or_else(|e| e.into_inner());
        if self.ownership_failed() {
            return Ok(None);
        }
        // Completion publishes its terminal disk intent under this same
        // active lock, before it can await the separate bypass-store lock.
        // Recovery may meanwhile have promoted the worker from an older
        // healthy probe. Its transient lifecycle must not authorize a new
        // build while the newer fault is still awaiting durable quarantine.
        let pending_disk_fault = state.worker_endpoint.as_ref().map_or_else(
            || self.has_pending_disk_fault(&state.worker_id),
            |endpoint| {
                self.has_pending_disk_fault_for_endpoint(&WorkerEndpointIdentity::from_config(
                    &endpoint.config,
                ))
            },
        );
        if pending_disk_fault {
            return Ok(None);
        }
        // This lock also serializes completion. Two selectors may have seen
        // the same free-space sample; only durable admission spends its budget.
        if self
            .check_disk_headroom_locked(&active, &state.worker_id, &disk)
            .is_err()
        {
            return Ok(None);
        }
        {
            let queue = self.queued.read().unwrap_or_else(|e| e.into_inner());
            let owned_row = queue.iter().find(|row| {
                row.local_wrapper_id.is_some() && row.local_wrapper_id == state.local_wrapper_id
            });
            if let Some(claim) = waiter {
                let Some(row) = queue.iter().find(|row| row.id == claim.queue_id) else {
                    return Ok(None);
                };
                if row.waiter_claim != Some(claim.nonce)
                    || row.recovered
                    || row.local_wrapper_id != state.local_wrapper_id
                    || row.hook_pid != state.hook_pid
                    || row.hook_process_identity != state.hook_process_identity
                    || row.project_id != state.project_id
                    || row.command != state.command
                {
                    return Ok(None);
                }
            } else if owned_row.is_some_and(|row| row.selection_contract.is_some()) {
                // A new request cannot steal a queued request's authority, even
                // when a worker became free between the two requests.
                return Ok(None);
            }
        }
        if state
            .local_wrapper_id
            .as_deref()
            .is_some_and(|id| self.wrapper_cancelled(id))
        {
            return Ok(None);
        }
        if state.local_wrapper_id.as_deref().is_some_and(|wrapper| {
            wrapper.is_empty()
                || active
                    .values()
                    .any(|existing| existing.local_wrapper_id.as_deref() == Some(wrapper))
        }) {
            // A durable wrapper identity is a single live execution authority.
            // Allowing the same wrapper onto two workers makes a lost selection
            // reply or retry indistinguishable from duplicate execution.
            return Ok(None);
        }
        if active.values().any(|existing| {
            existing.project_id == state.project_id && existing.worker_id == state.worker_id
        }) {
            return Ok(None);
        }
        if state.location == BuildLocation::Remote {
            // Overlapping builds on one worker share its free-space drop, so
            // none of them can attribute that growth to itself (bd-wv746).
            for other in active.values_mut().filter(|other| {
                other.location == BuildLocation::Remote && other.worker_id == state.worker_id
            }) {
                other.disk_shared = true;
                state.disk_shared = true;
            }
        }
        active.insert(id, state.clone());
        if let Some(claim) = waiter {
            let mut queue = self.queued.write().unwrap_or_else(|e| e.into_inner());
            let mut remaining = queue.clone();
            remaining.retain(|row| row.id != claim.queue_id);
            self.persist_ownership_with_queue(&active, None, &remaining)?;
            *queue = remaining;
        } else {
            self.persist_ownership(&active, None)?;
        }
        Ok(Some(state))
    }

    pub(crate) fn reserved_disk_headroom_gib(&self, worker_id: &str) -> u64 {
        let active = self.active.read().unwrap_or_else(|e| e.into_inner());
        reserved_disk_headroom(&active, worker_id)
    }

    /// Feed one worker build-disk probe into every remote build running there.
    /// Only probes taken after a build's admission can describe its growth.
    pub(crate) fn observe_build_disk(&self, worker_id: &str, free_gib: u64, observed_at: Instant) {
        let mut active = self.active.write().unwrap_or_else(|e| e.into_inner());
        for state in active.values_mut().filter(|state| {
            state.location == BuildLocation::Remote
                && state.worker_id == worker_id
                && state.disk_free_start_gib.is_some()
                && observed_at > state.started_at_mono
        }) {
            state.disk_free_min_gib = Some(
                state
                    .disk_free_min_gib
                    .map_or(free_gib, |min| min.min(free_gib)),
            );
        }
    }

    /// Learned build-disk growth for this project and command class.
    pub(crate) fn learned_footprint_gib(&self, project_id: &str, command: &str) -> Option<f64> {
        self.footprints
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .estimate_gib(&footprint_key(project_id, command), Utc::now().timestamp())
    }

    /// Learned growth still expected from builds running on this worker: each
    /// one's footprint minus the growth already visible in its probes.
    pub(crate) fn pending_footprint_gib(&self, worker_id: &str) -> f64 {
        let builds: Vec<(String, String, f64)> = self
            .active
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .filter(|state| state.location == BuildLocation::Remote && state.worker_id == worker_id)
            .map(|state| {
                let grown = match (state.disk_free_start_gib, state.disk_free_min_gib) {
                    (Some(start), Some(min)) => start.saturating_sub(min) as f64,
                    _ => 0.0,
                };
                (state.project_id.clone(), state.command.clone(), grown)
            })
            .collect();
        builds
            .into_iter()
            .filter_map(|(project, command, grown)| {
                self.learned_footprint_gib(&project, &command)
                    .map(|footprint| (footprint - grown).max(0.0))
            })
            .sum()
    }

    /// Learn from a finished remote build that had the worker to itself.
    fn learn_footprint(&self, state: &ActiveBuildState, exit_code: i32) {
        // A cancelled build stopped early; its growth says little.
        if state.location != BuildLocation::Remote || state.disk_shared || exit_code == 130 {
            return;
        }
        let (Some(start), Some(min)) = (state.disk_free_start_gib, state.disk_free_min_gib) else {
            return;
        };
        let growth = start.saturating_sub(min) as f64;
        let now = Utc::now().timestamp();
        let mut book = self.footprints.lock().unwrap_or_else(|e| e.into_inner());
        if !book.record(
            &footprint_key(&state.project_id, &state.command),
            growth,
            now,
        ) {
            return;
        }
        book.prune(now);
        debug!(
            build_id = state.id,
            project = %state.project_id,
            worker = %state.worker_id,
            growth_gib = growth,
            "learned remote build disk footprint"
        );
        if let Some(path) = self.persistence_path.as_deref().map(footprint_path)
            && let Err(error) = book.persist(&path)
        {
            warn!(path = %path.display(), %error, "could not persist build footprints");
        }
    }

    /// Advisory selection uses the same budget and completion boundary checked
    /// again by authoritative admission under the same ownership lock.
    pub(crate) fn check_disk_headroom(
        &self,
        worker_id: &str,
        disk: &DiskHeadroomAdmission,
    ) -> Result<(), DiskHeadroomRejection> {
        let active = self.active.read().unwrap_or_else(|e| e.into_inner());
        self.check_disk_headroom_locked(&active, worker_id, disk)
    }

    fn check_disk_headroom_locked(
        &self,
        active: &HashMap<u64, ActiveBuildState>,
        worker_id: &str,
        disk: &DiskHeadroomAdmission,
    ) -> Result<(), DiskHeadroomRejection> {
        if disk.requested_gib > 0 && self.ownership_failed() {
            return Err(DiskHeadroomRejection::Unknown);
        }
        let completed = self
            .disk_budget_completed_at
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        disk.check_after_completion(
            worker_id,
            reserved_disk_headroom(active, worker_id),
            completed.get(worker_id).copied(),
        )
    }

    /// Record a heartbeat/progress update for an active build.
    ///
    /// Returns the updated active state if the build exists.
    pub fn record_build_heartbeat(
        &self,
        heartbeat: BuildHeartbeatRequest,
    ) -> Option<ActiveBuildState> {
        let now = Instant::now();
        let now_rfc3339 = Utc::now().to_rfc3339();

        let mut active = self.active.write().unwrap_or_else(|e| e.into_inner());
        let state = active.get_mut(&heartbeat.build_id)?;

        // Ignore worker mismatch updates to avoid cross-build contamination.
        if state.worker_id != heartbeat.worker_id.as_str() {
            return None;
        }

        // A durable identity can never be replaced or omitted when reattaching.
        if state.local_wrapper_id.is_some() && state.local_wrapper_id != heartbeat.local_wrapper_id
        {
            return None;
        }
        if state.recovered && state.local_wrapper_id.is_none() {
            return None;
        }
        if heartbeat.remote_pgid_file.as_ref().is_some_and(|path| {
            state
                .remote_pgid_file
                .as_ref()
                .is_some_and(|recorded| recorded != path)
        }) {
            return None;
        }
        // A heartbeat describes the original wrapper; it is not a process
        // handoff. A delayed message can outlive that process and its PID can
        // already belong to somebody else. Never capture the new occupant's
        // identity or replace the recorded PID from the message.
        if heartbeat
            .hook_pid
            .filter(|pid| *pid > 0)
            .is_some_and(|pid| pid != state.hook_pid)
        {
            return None;
        }
        if let Some(identity) = state.hook_process_identity.as_ref()
            && process_identity(state.hook_pid).as_ref() != Some(identity)
        {
            return None;
        }
        if state.recovered && state.hook_process_identity.is_none() {
            return None;
        }
        let identity_changed = heartbeat
            .local_wrapper_id
            .as_ref()
            .is_some_and(|wrapper| state.local_wrapper_id.as_ref() != Some(wrapper))
            || heartbeat
                .remote_pgid_file
                .as_ref()
                .filter(|path| !path.trim().is_empty())
                .is_some_and(|path| state.remote_pgid_file.as_ref() != Some(path));
        if let Some(local_wrapper_id) = heartbeat.local_wrapper_id {
            state.local_wrapper_id = Some(local_wrapper_id);
        }
        if let Some(remote_pgid_file) = heartbeat
            .remote_pgid_file
            .filter(|path| !path.trim().is_empty())
        {
            state.remote_pgid_file = Some(remote_pgid_file);
        }

        let previous_phase = state.heartbeat_phase.clone();
        let previous_counter = state.heartbeat_counter;
        let previous_percent = state.heartbeat_percent;
        let previous_detail = state.heartbeat_detail.clone();

        state.heartbeat_phase = heartbeat.phase;
        state.heartbeat_detail = heartbeat.detail;
        if let Some(counter) = heartbeat.progress_counter {
            state.heartbeat_counter = state.heartbeat_counter.max(counter);
        }
        if let Some(percent) = heartbeat.progress_percent {
            // `f64::clamp` returns NaN when given NaN — so a worker sending
            // `NaN` would poison the heartbeat state, making every
            // subsequent percent comparison `false` (NaN never compares >)
            // and leaving status displays to render "NaN%". Drop invalid
            // values silently; a progress report with no number is better
            // than a stuck progress bar for the rest of the build.
            if percent.is_finite() {
                state.heartbeat_percent = Some(percent.clamp(0.0, 100.0));
            }
        }
        state.heartbeat_count = state.heartbeat_count.saturating_add(1);
        state.last_heartbeat_at = now_rfc3339.clone();
        state.last_heartbeat_mono = now;

        // Progress evidence can come from phase transitions, increasing counters,
        // percent improvements, or detail updates.
        let counter_progressed = state.heartbeat_counter > previous_counter;
        let percent_progressed = match (previous_percent, state.heartbeat_percent) {
            (Some(before), Some(after)) => after > before + f64::EPSILON,
            (None, Some(_)) => true,
            _ => false,
        };
        let detail_changed = state.heartbeat_detail != previous_detail;
        let phase_changed = state.heartbeat_phase != previous_phase;

        if counter_progressed || percent_progressed || detail_changed || phase_changed {
            state.last_progress_at = now_rfc3339;
            state.last_progress_mono = now;
        }

        let updated = state.clone();
        // Rewriting and fsyncing the whole ownership file on every heartbeat,
        // under the active lock, stalled admission and completion behind it.
        let mut persisted = self
            .heartbeat_persisted
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        persisted.retain(|id, _| active.contains_key(id));
        // A failed ownership store must keep surfacing on every heartbeat.
        let due = identity_changed
            || phase_changed
            || self.ownership_failed()
            || persisted
                .get(&heartbeat.build_id)
                .is_none_or(|at| now.duration_since(*at) >= HEARTBEAT_PERSIST_INTERVAL);
        if due {
            if let Err(error) = self.persist_ownership(&active, None) {
                warn!("Unable to persist build heartbeat: {error}");
                return None;
            }
            persisted.insert(heartbeat.build_id, now);
        }
        Some(updated)
    }

    /// Record the latest stuck-detector evidence snapshot for an active build.
    pub fn record_stuck_detector_snapshot(
        &self,
        build_id: u64,
        snapshot: StuckDetectorSnapshot,
    ) -> Option<ActiveBuildState> {
        let now_rfc3339 = Utc::now().to_rfc3339();
        let mut active = self.active.write().unwrap_or_else(|e| e.into_inner());
        let state = active.get_mut(&build_id)?;

        state.detector_hook_alive = snapshot.hook_alive;
        state.detector_heartbeat_stale = snapshot.heartbeat_stale;
        state.detector_progress_stale = snapshot.progress_stale;
        state.detector_confidence = snapshot.confidence.clamp(0.0, 1.0);
        state.detector_build_age_secs = snapshot.build_age_secs;
        state.detector_slots_owned = snapshot.slots_owned;
        state.detector_last_evaluated_at = Some(now_rfc3339);

        Some(state.clone())
    }

    /// Complete an active build, moving it into history.
    pub fn finish_active_build(
        &self,
        build_id: u64,
        exit_code: i32,
        duration_ms: Option<u64>,
        bytes_transferred: Option<u64>,
        timing: Option<CommandTimingBreakdown>,
    ) -> Option<BuildRecord> {
        let state = self.active_build(build_id)?;
        self.complete_durable(
            build_id,
            &state.worker_id,
            state.local_wrapper_id.as_deref(),
            BuildCompletion {
                exit_code,
                duration_ms,
                bytes_transferred,
                timing,
                cancellation: None,
            },
        )
        .expect("persist terminal ownership before release")
        .map(|(_, record)| record)
    }

    /// Cancel an active build, moving it into history with a cancel exit code.
    pub fn cancel_active_build(
        &self,
        build_id: u64,
        bytes_transferred: Option<u64>,
        cancellation: Option<BuildCancellationMetadata>,
    ) -> Option<BuildRecord> {
        let state = self.active_build(build_id)?;
        self.complete_durable(
            build_id,
            &state.worker_id,
            state.local_wrapper_id.as_deref(),
            BuildCompletion {
                exit_code: 130,
                duration_ms: None,
                bytes_transferred,
                timing: None,
                cancellation,
            },
        )
        .expect("persist terminal ownership before release")
        .map(|(_, record)| record)
    }

    /// Get a specific active build by ID.
    pub fn active_build(&self, build_id: u64) -> Option<ActiveBuildState> {
        self.active
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&build_id)
            .cloned()
    }

    /// Get all active builds.
    pub fn active_builds(&self) -> Vec<ActiveBuildState> {
        self.active
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .cloned()
            .collect()
    }

    /// Check whether a worker already has an active build for the same project.
    pub fn has_active_build_for_project_on_worker(
        &self,
        project_id: &str,
        worker_id: &str,
    ) -> bool {
        self.active
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .any(|state| state.project_id == project_id && state.worker_id == worker_id)
    }

    /// Return worker IDs currently running an active build for the given project.
    pub fn active_workers_for_project(&self, project_id: &str) -> HashSet<String> {
        self.active
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .filter(|state| state.project_id == project_id)
            .map(|state| state.worker_id.clone())
            .collect()
    }

    // =========================================================================
    // Queue Management
    // =========================================================================

    pub fn wrapper_cancelled(&self, wrapper: &str) -> bool {
        !self.ownership_failed()
            && self
                .cancelled_wrappers
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .contains(wrapper)
    }

    /// Persist cancellation before removing queue visibility or acknowledging it.
    /// A bounded full journal refuses new cancellation rather than forgetting an
    /// identity that might still be delivered by a disconnected wrapper.
    pub fn cancel_wrapper(&self, wrapper: &str) -> std::io::Result<WrapperCancellation> {
        let active = self.active.write().unwrap_or_else(|e| e.into_inner());
        if self.ownership_failed() {
            return Err(std::io::Error::other(
                "durable ownership uncertain; restart required",
            ));
        }
        if let Some(state) = active
            .values()
            .find(|state| state.local_wrapper_id.as_deref() == Some(wrapper))
        {
            return Ok(WrapperCancellation::Active(state.id));
        }
        let queued = self.has_queued_wrapper(wrapper);
        let completed = self
            .terminal
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .filter(|receipt| receipt.local_wrapper_id.as_deref() == Some(wrapper))
            // A wrapper can fail over through several completed attempts.
            // Its latest receipt must not depend on HashMap iteration order.
            .max_by_key(|receipt| receipt.record.id)
            .map(|receipt| receipt.record.clone());
        let already_cancelled = self.wrapper_cancelled(wrapper);
        if !queued && completed.is_none() && !already_cancelled {
            return Ok(WrapperCancellation::NotQueued);
        }
        if !already_cancelled {
            let mut cancelled = self
                .cancelled_wrappers
                .write()
                .unwrap_or_else(|e| e.into_inner());
            if cancelled.len() >= MAX_CANCELLED_WRAPPERS {
                return Err(std::io::Error::other(
                    "queued cancellation journal is full; intent not accepted",
                ));
            }
            cancelled.insert(wrapper.to_owned());
        }
        if !already_cancelled || queued {
            // An older completion is not a fence against a delayed retry.
            // Persist the cancellation before acknowledging either a queued
            // no-start or an already-completed attempt. Existing terminal
            // receipts remain exact and do not release any resources again.
            self.persist_ownership(&active, None)?;
        }
        if queued {
            Ok(WrapperCancellation::BeforeStart)
        } else {
            Ok(
                completed.map_or(WrapperCancellation::BeforeStart, |record| {
                    WrapperCancellation::Completed(Box::new(record))
                }),
            )
        }
    }

    /// Decide queue departure against cancellation while admission is locked.
    /// Once departure wins, cancellation cannot claim a no-start receipt for a
    /// wrapper that may already be handling timeout or local fallback.
    pub fn finish_queued_build(
        &self,
        queue_id: u64,
        wrapper: Option<&str>,
    ) -> std::io::Result<bool> {
        let active = self.active.write().unwrap_or_else(|e| e.into_inner());
        if self.ownership_failed() {
            return Err(std::io::Error::other(
                "durable ownership uncertain; restart required",
            ));
        }
        let cancelled = wrapper.is_some_and(|id| self.wrapper_cancelled(id));
        let mut queue = self.queued.write().unwrap_or_else(|e| e.into_inner());
        if let Some(state) = queue.iter().find(|state| state.id == queue_id) {
            if state.local_wrapper_id.as_deref() != wrapper {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "queued build ownership mismatch",
                ));
            }
            let mut remaining = queue.clone();
            remaining.retain(|state| state.id != queue_id);
            self.persist_ownership_with_queue(&active, None, &remaining)?;
            *queue = remaining;
        }
        Ok(cancelled)
    }

    /// Allocate without wrapping into a previously used identity.
    fn next_queue_id(&self) -> Option<u64> {
        self.next_queue_id
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |id| {
                if id < QUEUE_ID_NAMESPACE {
                    None
                } else {
                    id.checked_add(1)
                }
            })
            .ok()
    }

    /// Enqueue a build waiting for an available worker.
    ///
    /// Returns `None` if the queue is full, the wrapper already owns a row or
    /// execution, or persistence fails. Only the last closes admission through
    /// ownership_failed; a duplicate enqueue never grants another waiter.
    pub fn enqueue_build(
        &self,
        project_id: String,
        command: String,
        hook_pid: u32,
        slots_needed: u32,
        local_wrapper_id: Option<String>,
    ) -> Option<QueuedBuildState> {
        self.enqueue_build_inner(
            project_id,
            command,
            hook_pid,
            slots_needed,
            local_wrapper_id,
            None,
        )
        .map(|(state, _)| state)
    }

    pub fn enqueue_selection_build(
        &self,
        project_id: String,
        command: String,
        hook_pid: u32,
        slots_needed: u32,
        local_wrapper_id: Option<String>,
        contract: QueueSelectionContract,
    ) -> Option<(QueuedBuildState, QueuedWaiterClaim)> {
        self.enqueue_build_inner(
            project_id,
            command,
            hook_pid,
            slots_needed,
            local_wrapper_id,
            Some(contract),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn enqueue_build_inner(
        &self,
        project_id: String,
        command: String,
        hook_pid: u32,
        slots_needed: u32,
        local_wrapper_id: Option<String>,
        selection_contract: Option<QueueSelectionContract>,
    ) -> Option<(QueuedBuildState, QueuedWaiterClaim)> {
        let active = self.active.write().unwrap_or_else(|e| e.into_inner());
        if self.ownership_failed()
            || local_wrapper_id
                .as_deref()
                .is_some_and(|id| self.wrapper_cancelled(id))
        {
            return None;
        }
        let mut queue = self.queued.write().unwrap_or_else(|e| e.into_inner());
        if let Some(wrapper) = local_wrapper_id.as_deref()
            && (wrapper.is_empty()
                || queue
                    .iter()
                    .any(|state| state.local_wrapper_id.as_deref() == Some(wrapper))
                || active
                    .values()
                    .any(|state| state.local_wrapper_id.as_deref() == Some(wrapper))
                || self
                    .terminal
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .values()
                    .any(|receipt| receipt.local_wrapper_id.as_deref() == Some(wrapper)))
        {
            return None;
        }

        // Check queue depth limit
        if self.max_queue_depth > 0 && queue.len() >= self.max_queue_depth {
            debug!(
                "Queue full ({}/{}), rejecting build for {}",
                queue.len(),
                self.max_queue_depth,
                project_id
            );
            return None;
        }

        let id = self.next_queue_id()?;
        let nonce = self.next_waiter_claim.fetch_add(1, Ordering::SeqCst);
        let queued_at = Utc::now().to_rfc3339();
        let state = QueuedBuildState {
            id,
            project_id,
            command,
            queued_at,
            queued_at_mono: Instant::now(),
            hook_pid,
            hook_process_identity: process_identity(hook_pid),
            local_wrapper_id,
            slots_needed,
            selection_contract,
            waiter_claim: Some(nonce),
            estimated_start: None,
            recovered: false,
        };

        // Do not expose queue membership before both it and its ID high-water
        // mark are durable. A post-rename failure may leave the row on disk;
        // admission stays closed until restart resolves that uncertainty.
        let mut pending = queue.clone();
        pending.push_back(state.clone());
        self.persist_ownership_with_queue(&active, None, &pending)
            .ok()?;
        *queue = pending;
        debug!(
            "Build queued: id={}, position={}, project={}",
            id,
            queue.len(),
            state.project_id
        );

        Some((
            state,
            QueuedWaiterClaim {
                queue_id: id,
                nonce,
            },
        ))
    }

    /// Reattach exactly one waiter to a durable queued row after restart. PID
    /// alone is not ownership: it must still name the process born at enqueue.
    pub fn resume_queued_build(
        &self,
        wrapper: &str,
        hook_pid: u32,
        digest: &[u8; 32],
    ) -> std::io::Result<(QueuedBuildState, QueuedWaiterClaim)> {
        let _active = self.active.write().unwrap_or_else(|e| e.into_inner());
        let refused = || {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "queued selection cannot be safely resumed",
            )
        };
        if self.ownership_failed() || self.wrapper_cancelled(wrapper) {
            return Err(refused());
        }
        let identity = process_identity(hook_pid).ok_or_else(refused)?;
        let mut queue = self.queued.write().unwrap_or_else(|e| e.into_inner());
        let row = queue
            .iter_mut()
            .find(|row| row.local_wrapper_id.as_deref() == Some(wrapper))
            .ok_or_else(refused)?;
        if !row.recovered
            || row.waiter_claim.is_some()
            || row.hook_pid != hook_pid
            || row.hook_process_identity.as_deref() != Some(identity.as_str())
            || !row
                .selection_contract
                .as_ref()
                .is_some_and(|contract| &contract.digest == digest && contract.timeout_secs > 0)
        {
            return Err(refused());
        }
        let nonce = self.next_waiter_claim.fetch_add(1, Ordering::SeqCst);
        row.waiter_claim = Some(nonce);
        row.recovered = false;
        Ok((
            row.clone(),
            QueuedWaiterClaim {
                queue_id: row.id,
                nonce,
            },
        ))
    }

    pub fn has_queued_wrapper(&self, wrapper: &str) -> bool {
        self.queued
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .any(|row| row.local_wrapper_id.as_deref() == Some(wrapper))
    }

    pub fn owns_queued_waiter(&self, claim: &QueuedWaiterClaim) -> bool {
        self.queued
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .any(|row| {
                row.id == claim.queue_id && row.waiter_claim == Some(claim.nonce) && !row.recovered
            })
    }

    /// Dequeue the next build (FIFO).
    ///
    /// Called when a worker becomes available.
    pub fn dequeue_build(&self) -> Option<QueuedBuildState> {
        self.remove_queued_matching(|_| true)
    }

    /// Remove a specific queued build by ID (e.g., for cancellation).
    pub fn remove_queued_build(&self, queue_id: u64) -> Option<QueuedBuildState> {
        self.remove_queued_matching(|state| state.id == queue_id)
    }

    /// PID-only removal cannot identify an owner recovered after restart.
    /// Recovered rows require their queue ID or durable wrapper identity.
    pub fn remove_queued_build_by_pid(&self, hook_pid: u32) -> Option<QueuedBuildState> {
        self.remove_queued_matching(|state| !state.recovered && state.hook_pid == hook_pid)
    }

    /// All membership mutations share the ownership serialization lock. On
    /// failure retain visibility and close admission; never acknowledge a
    /// departure whose durable result is unknown.
    fn remove_queued_matching(
        &self,
        matches: impl Fn(&QueuedBuildState) -> bool,
    ) -> Option<QueuedBuildState> {
        let active = self.active.write().unwrap_or_else(|e| e.into_inner());
        if self.ownership_failed() {
            return None;
        }
        let mut queue = self.queued.write().unwrap_or_else(|e| e.into_inner());
        let pos = queue.iter().position(matches)?;
        let mut remaining = queue.clone();
        let removed = remaining.remove(pos)?;
        self.persist_ownership_with_queue(&active, None, &remaining)
            .ok()?;
        *queue = remaining;
        Some(removed)
    }

    /// Get all queued builds (in queue order).
    pub fn queued_builds(&self) -> Vec<QueuedBuildState> {
        self.queued
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .cloned()
            .collect()
    }

    /// Get a specific queued build by ID.
    pub fn queued_build(&self, queue_id: u64) -> Option<QueuedBuildState> {
        // Use the same poisoned-lock recovery pattern as the rest of this
        // file: a prior panic under this lock shouldn't propagate a panic
        // into a simple read-only query.
        self.queued
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .find(|b| b.id == queue_id)
            .cloned()
    }

    /// Get the queue position of a build (1-indexed, None if not found).
    pub fn queue_position(&self, queue_id: u64) -> Option<usize> {
        self.queued
            .read()
            .unwrap()
            .iter()
            .position(|b| b.id == queue_id)
            .map(|p| p + 1)
    }

    /// Get the current queue depth.
    pub fn queue_depth(&self) -> usize {
        self.queued.read().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Check if the queue is empty.
    pub fn queue_is_empty(&self) -> bool {
        self.queued
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty()
    }

    /// Update estimated start times for all queued builds.
    ///
    /// Uses average build duration from history and active build state.
    pub fn update_queue_estimates(&self) {
        let avg_duration = self.stats().avg_duration_ms;
        let active_count = self.active.read().unwrap_or_else(|e| e.into_inner()).len();

        let mut queue = self.queued.write().unwrap_or_else(|e| e.into_inner());

        // Estimate when each queued build will start
        let now = Utc::now();
        for (i, build) in queue.iter_mut().enumerate() {
            // Simple estimate: position * avg_duration, adjusted for active builds
            let position = i + 1;
            let wait_ms = if active_count > 0 {
                // Assume active builds are half-done on average
                let remaining_active_ms = (avg_duration / 2) as i64;
                let queue_wait_ms = (position as u64 * avg_duration) as i64;
                remaining_active_ms + queue_wait_ms
            } else {
                0 // No active builds, next in queue starts immediately
            };

            let estimated = now + chrono::Duration::milliseconds(wait_ms.max(0));
            build.estimated_start = Some(estimated.to_rfc3339());
        }
    }

    /// Get recent builds (most recent first).
    pub fn recent(&self, limit: usize) -> Vec<BuildRecord> {
        let records = self.records.read().unwrap_or_else(|e| e.into_inner());
        records.iter().rev().take(limit).cloned().collect()
    }

    /// Get all builds (most recent first).
    pub fn all(&self) -> Vec<BuildRecord> {
        let records = self.records.read().unwrap_or_else(|e| e.into_inner());
        records.iter().rev().cloned().collect()
    }

    /// Get builds by worker (most recent first).
    pub fn by_worker(&self, worker_id: &str, limit: usize) -> Vec<BuildRecord> {
        let records = self.records.read().unwrap_or_else(|e| e.into_inner());
        records
            .iter()
            .rev()
            .filter(|r| r.worker_id.as_deref() == Some(worker_id))
            .take(limit)
            .cloned()
            .collect()
    }

    /// Get builds by project (most recent first).
    pub fn by_project(&self, project_id: &str, limit: usize) -> Vec<BuildRecord> {
        let records = self.records.read().unwrap_or_else(|e| e.into_inner());
        records
            .iter()
            .rev()
            .filter(|r| r.project_id == project_id)
            .take(limit)
            .cloned()
            .collect()
    }

    /// Get aggregate statistics.
    pub fn stats(&self) -> BuildStats {
        let records = self.records.read().unwrap_or_else(|e| e.into_inner());
        let total = records.len();

        if total == 0 {
            return BuildStats::default();
        }

        let successes = records.iter().filter(|r| build_record_succeeded(r)).count();
        let remote = records
            .iter()
            .filter(|r| r.location == BuildLocation::Remote)
            .count();
        let total_duration: u64 = records.iter().map(|r| r.duration_ms).sum();
        let avg_duration = total_duration / total as u64;

        BuildStats {
            total_builds: total,
            success_count: successes,
            failure_count: total - successes,
            remote_count: remote,
            local_count: total - remote,
            avg_duration_ms: avg_duration,
        }
    }

    /// Calculate saved time statistics from remote builds.
    ///
    /// Estimates what remote builds would have taken locally ONLY from an
    /// observed baseline of successful local builds (`estimate_basis` =
    /// "observed_local_mean"). Without such a baseline no savings are claimed:
    /// the stats report measured remote durations with `estimate_basis` =
    /// "none" and zero estimated savings.
    pub fn saved_time_stats(&self) -> SavedTimeStats {
        let records = self.records.read().unwrap_or_else(|e| e.into_inner());
        let now = Utc::now();
        let today_start = now.date_naive().and_hms_opt(0, 0, 0).unwrap();
        let week_start = today_start - ChronoDuration::days(7);

        // Separate local and remote builds
        let local_builds: Vec<_> = records
            .iter()
            .filter(|r| r.location == BuildLocation::Local && r.exit_code == 0)
            .collect();
        let remote_builds: Vec<_> = records
            .iter()
            .filter(|r| r.location == BuildLocation::Remote && r.exit_code == 0)
            .collect();

        if remote_builds.is_empty() {
            return SavedTimeStats::default();
        }

        // Calculate average local build duration (if we have local builds)
        let avg_local_duration_ms = if !local_builds.is_empty() {
            let total_local: u64 = local_builds.iter().map(|r| r.duration_ms).sum();
            total_local / local_builds.len() as u64
        } else {
            0
        };

        // Calculate totals and time saved
        let mut total_remote_duration_ms: u64 = 0;
        let mut estimated_local_duration_ms: u64 = 0;
        let mut today_remote_ms: u64 = 0;
        let mut today_estimated_local_ms: u64 = 0;
        let mut week_remote_ms: u64 = 0;
        let mut week_estimated_local_ms: u64 = 0;

        for build in &remote_builds {
            let remote_ms = build.duration_ms;
            total_remote_duration_ms += remote_ms;

            // Estimate local duration only from the observed local mean. No
            // invented per-build scaling: without a baseline the estimate is
            // zero and the stats say so via estimate_basis = "none".
            let estimated_local_ms = if avg_local_duration_ms > 0 {
                avg_local_duration_ms
            } else {
                0
            };
            estimated_local_duration_ms += estimated_local_ms;

            // Parse timestamp for daily/weekly aggregation
            if let Ok(completed) = DateTime::parse_from_rfc3339(&build.completed_at) {
                let completed_naive = completed.naive_utc();
                if completed_naive >= today_start.and_utc().naive_utc() {
                    today_remote_ms += remote_ms;
                    today_estimated_local_ms += estimated_local_ms;
                }
                if completed_naive >= week_start.and_utc().naive_utc() {
                    week_remote_ms += remote_ms;
                    week_estimated_local_ms += estimated_local_ms;
                }
            }
        }

        let time_saved_ms = estimated_local_duration_ms.saturating_sub(total_remote_duration_ms);
        let today_saved_ms = today_estimated_local_ms.saturating_sub(today_remote_ms);
        let week_saved_ms = week_estimated_local_ms.saturating_sub(week_remote_ms);

        let avg_speedup = if total_remote_duration_ms > 0 {
            estimated_local_duration_ms as f64 / total_remote_duration_ms as f64
        } else {
            0.0
        };

        let (estimate_basis, local_baseline_builds) = if avg_local_duration_ms > 0 {
            ("observed_local_mean", local_builds.len())
        } else {
            ("none", 0)
        };

        SavedTimeStats {
            total_remote_duration_ms,
            estimated_local_duration_ms,
            time_saved_ms,
            builds_counted: remote_builds.len(),
            avg_speedup,
            today_saved_ms,
            week_saved_ms,
            estimate_basis: estimate_basis.to_string(),
            local_baseline_builds,
        }
    }

    /// Get the number of builds in history.
    pub fn len(&self) -> usize {
        self.records.read().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Check if history is empty.
    pub fn is_empty(&self) -> bool {
        self.records
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty()
    }

    /// Clear all build records.
    #[allow(dead_code)] // May be used for testing or admin operations
    pub fn clear(&self) {
        let mut records = self.records.write().unwrap_or_else(|e| e.into_inner());
        records.clear();
    }

    /// Load history from a JSONL file.
    pub fn load_from_file(path: &Path, capacity: usize) -> std::io::Result<Self> {
        let file = match File::open(path) {
            Ok(file) => Some(file),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };

        let mut records = VecDeque::with_capacity(capacity);
        let mut max_id = 0u64;

        // Split on raw bytes: `lines()` turns one invalid UTF-8 sequence (a
        // short append cut through a multi-byte char on disk-full or crash)
        // into an error for the whole load, and the daemon then refused to
        // start. A damaged line is skipped like any other unparseable record;
        // only real read errors still fail the load.
        for line in file
            .into_iter()
            .flat_map(|file| BufReader::new(file).split(b'\n'))
        {
            let line = line?;
            if line.trim_ascii().is_empty() {
                continue;
            }

            match serde_json::from_slice::<BuildRecord>(&line) {
                Ok(record) => {
                    max_id = max_id.max(record.id);
                    if records.len() >= capacity {
                        records.pop_front();
                    }
                    records.push_back(record);
                }
                Err(e) => {
                    warn!("Skipping invalid history line: {}", e);
                }
            }
        }

        let ownership_path = path.with_extension("ownership.json");
        let mut active = HashMap::new();
        let mut terminal = HashMap::new();
        let mut queued = VecDeque::new();
        let mut cancelled_wrappers = HashSet::new();
        let mut next_queue_id = None;
        let mut ownership_existed = false;
        match File::open(&ownership_path) {
            Ok(file) => {
                ownership_existed = true;
                let snapshot: DurableOwnership = serde_json::from_reader(file)?;
                queued = match (snapshot.version, snapshot.queued) {
                    (1, None) => VecDeque::new(),
                    (2, Some(queue)) if snapshot.next_queue_id.is_some() => queue,
                    _ => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "unsupported ownership version or missing durable queue/high-water mark",
                        ));
                    }
                };
                cancelled_wrappers = snapshot.cancelled_wrappers;
                next_queue_id = snapshot.next_queue_id;
                if next_queue_id.is_some_and(|id| id < QUEUE_ID_NAMESPACE) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "invalid queued identifier high-water mark",
                    ));
                }
                if cancelled_wrappers.len() > MAX_CANCELLED_WRAPPERS {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "queued cancellation journal exceeds limit",
                    ));
                }
                if cancelled_wrappers.contains("") {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "empty cancelled wrapper identity",
                    ));
                }
                // Older daemons could admit one wrapper on several workers.
                // Never pick an arbitrary winner on restart, or rewrite that
                // contradictory evidence into an apparently valid snapshot.
                let mut active_wrappers = HashSet::new();
                for mut state in snapshot.active {
                    if state.id == 0
                        || state.id >= QUEUE_ID_NAMESPACE
                        || state.worker_id.is_empty()
                        || state.worker_endpoint.as_ref().is_some_and(|endpoint| {
                            endpoint.config.id.as_str() != state.worker_id
                                || state.location != BuildLocation::Remote
                        })
                        || active.contains_key(&state.id)
                        || state.local_wrapper_id.as_ref().is_some_and(|wrapper| {
                            wrapper.is_empty()
                                || cancelled_wrappers.contains(wrapper)
                                || !active_wrappers.insert(wrapper.clone())
                        })
                    {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "invalid or duplicate active ownership",
                        ));
                    }
                    for (wall, mono) in [
                        (&state.started_at, &mut state.started_at_mono),
                        (&state.last_heartbeat_at, &mut state.last_heartbeat_mono),
                        (&state.last_progress_at, &mut state.last_progress_mono),
                    ] {
                        let timestamp = DateTime::parse_from_rfc3339(wall).map_err(|error| {
                            std::io::Error::new(std::io::ErrorKind::InvalidData, error)
                        })?;
                        let age = Utc::now()
                            .signed_duration_since(timestamp)
                            .to_std()
                            .unwrap_or_default();
                        *mono = Instant::now().checked_sub(age).unwrap_or_else(Instant::now);
                    }
                    state.recovered = true;
                    max_id = max_id.max(state.id);
                    active.insert(state.id, state);
                }
                for receipt in snapshot.completed {
                    let id = receipt.record.id;
                    if receipt.pending_disk_fault.is_some()
                        && receipt.unapplied_disk_fault.is_some()
                    {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "disk fault cannot be pending and archived",
                        ));
                    }
                    for fault in receipt
                        .pending_disk_fault
                        .iter()
                        .chain(receipt.unapplied_disk_fault.iter())
                    {
                        let normalized =
                            crate::bypass_recovery_service::validate_disk_fault_roots(&fault.roots)
                                .map_err(|error| {
                                    std::io::Error::new(
                                        std::io::ErrorKind::InvalidData,
                                        error.to_string(),
                                    )
                                })?;
                        if fault.build_id != id
                            || receipt.record.worker_id.as_deref() != Some(fault.worker_id.as_str())
                            || fault.worker_id.is_empty()
                            || fault.worker_endpoint.as_ref().is_some_and(|endpoint| {
                                endpoint.id.as_str() != fault.worker_id
                                    || receipt.record.location != BuildLocation::Remote
                            })
                            || receipt.record.exit_code == 0
                            || fault.incident_id
                                != format!("build:{id}:{}", receipt.record.completed_at)
                            || fault.roots != normalized
                        {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "invalid terminal worker disk fault",
                            ));
                        }
                    }
                    // Terminal attempts keep their own build IDs. Sequential
                    // worker failover may legitimately reuse a wrapper ID, so
                    // do not compare these wrappers with active_wrappers.
                    // A cancellation may fence future attempts after completion;
                    // its terminal receipts own no resources and remain valid.
                    if id == 0
                        || id >= QUEUE_ID_NAMESPACE
                        || active.contains_key(&id)
                        || terminal.contains_key(&id)
                        || receipt
                            .local_wrapper_id
                            .as_ref()
                            .is_some_and(|wrapper| wrapper.is_empty())
                    {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "invalid or conflicting terminal ownership",
                        ));
                    }
                    max_id = max_id.max(id);
                    if !records.iter().any(|record| record.id == id) {
                        records.push_back(receipt.record.clone());
                    }
                    terminal.insert(id, receipt);
                }
                let mut occupied = occupied_wrapper_ids(&active, &terminal, &cancelled_wrappers);
                let wall_now = Utc::now();
                let mono_now = Instant::now();
                let mut previous_id = None;
                for state in &mut queued {
                    if state.id < QUEUE_ID_NAMESPACE
                        || next_queue_id.is_none_or(|next| state.id >= next)
                        || previous_id.is_some_and(|previous| state.id <= previous)
                        || state.local_wrapper_id.as_ref().is_some_and(|wrapper| {
                            wrapper.is_empty() || !occupied.insert(wrapper.clone())
                        })
                    {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "invalid, out-of-order or conflicting queued ownership",
                        ));
                    }
                    previous_id = Some(state.id);
                    let timestamp =
                        DateTime::parse_from_rfc3339(&state.queued_at).map_err(|error| {
                            std::io::Error::new(std::io::ErrorKind::InvalidData, error)
                        })?;
                    let age = wall_now
                        .signed_duration_since(timestamp)
                        .to_std()
                        .unwrap_or_default();
                    state.queued_at_mono = mono_now.checked_sub(age).ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "queued timestamp cannot be represented by the monotonic clock",
                        )
                    })?;
                    state.estimated_start = None;
                    state.recovered = true;
                }
                while records.len() > capacity {
                    records.pop_front();
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        debug!("Loaded {} build records from {:?}", records.len(), path);

        let epoch_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let epoch_id = (epoch_secs << 24) | 1;
        let initial_id = std::cmp::max(max_id.saturating_add(1), epoch_id);
        let queue_epoch = QUEUE_ID_NAMESPACE | epoch_id;
        let next_queue_id = next_queue_id.map_or(queue_epoch, |id| id.max(queue_epoch));
        // After max_id counted them: a pruned receipt's id is never reissued.
        prune_terminal_receipts(&mut terminal, Utc::now());

        let history = Self {
            records: RwLock::new(records),
            active: RwLock::new(active),
            disk_budget_completed_at: Mutex::new(HashMap::new()),
            queued: RwLock::new(queued),
            capacity,
            max_queue_depth: DEFAULT_MAX_QUEUE_DEPTH,
            next_id: AtomicU64::new(initial_id),
            next_queue_id: AtomicU64::new(next_queue_id),
            next_waiter_claim: AtomicU64::new(1),
            persistence_path: Some(path.to_path_buf()),
            terminal: RwLock::new(terminal),
            cancelled_wrappers: RwLock::new(cancelled_wrappers),
            heartbeat_persisted: Mutex::new(HashMap::new()),
            footprints: Mutex::new(FootprintBook::load(&footprint_path(path))),
            release_lock: tokio::sync::Mutex::new(()),
            ownership_failed: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            fail_after_ownership_rename: std::sync::atomic::AtomicBool::new(false),
        };
        // A fresh start has nothing to make durable: the snapshot would hold
        // only the clock-derived queue epoch, which the next start recomputes,
        // and no queue ID has been issued yet. Skipping it keeps an fsync off
        // the path between binding the socket and serving it — on a worker
        // with heavy writeback that fsync stalled startup for 10+ seconds while
        // the bound socket accepted connections nobody answered.
        if ownership_existed {
            history.persist_ownership(
                &history.active.read().unwrap_or_else(|e| e.into_inner()),
                None,
            )?;
        }
        Ok(history)
    }

    /// Persist a single record to the JSONL file (append mode).
    ///
    /// Each completed build spawns its own task that calls this function,
    /// so multiple concurrent writers are normal. We rely on POSIX
    /// `O_APPEND` to serialize writes at the end of the file — but that
    /// guarantee only holds for a single `write()` syscall. The previous
    /// implementation split the record into two writes (JSON bytes, then
    /// `\n`) and two racing writers could produce
    /// `{record_a}{record_b}\n\n` instead of `{record_a}\n{record_b}\n`,
    /// corrupting the JSONL stream and breaking history recovery on
    /// daemon restart. Assemble the whole line in one buffer so a single
    /// `write_all` (which for <PIPE_BUF-sized payloads is a single
    /// syscall on Linux) keeps each line intact under concurrent append.
    async fn persist_record_async(path: &Path, record: &BuildRecord) -> std::io::Result<()> {
        let mut file = AsyncOpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await?;

        let mut line = serde_json::to_vec(record)?;
        line.push(b'\n');
        file.write_all(&line).await?;
        file.flush().await?;
        Ok(())
    }

    /// Compact the persistence file to only contain current records.
    #[allow(dead_code)] // May be used for maintenance operations
    pub fn compact(&self) -> std::io::Result<()> {
        let Some(ref path) = self.persistence_path else {
            return Ok(());
        };

        let records = self.records.read().unwrap_or_else(|e| e.into_inner());
        let temp_path = path.with_extension("tmp");

        {
            let mut file = File::create(&temp_path)?;
            for record in records.iter() {
                writeln!(file, "{}", serde_json::to_string(record)?)?;
            }
        }

        std::fs::rename(temp_path, path)?;
        debug!("Compacted history file: {:?}", path);

        Ok(())
    }

    pub fn terminal_build(&self, build_id: u64, wrapper: &str) -> Option<BuildRecord> {
        self.terminal
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&build_id)
            .filter(|receipt| receipt.local_wrapper_id.as_deref() == Some(wrapper))
            .map(|receipt| receipt.record.clone())
    }
    pub fn has_terminal_build(&self, build_id: u64) -> bool {
        self.terminal
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(&build_id)
    }

    pub(crate) async fn lock_releases(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.release_lock.lock().await
    }

    pub(crate) fn pending_disk_faults(&self) -> Vec<PendingDiskFault> {
        let mut faults: Vec<_> = self
            .terminal
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .filter_map(|receipt| receipt.pending_disk_fault.clone())
            .collect();
        faults.sort_by_key(|fault| fault.build_id);
        faults
    }

    pub(crate) fn pending_disk_fault(&self, build_id: u64) -> Option<PendingDiskFault> {
        self.terminal
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&build_id)
            .and_then(|receipt| receipt.pending_disk_fault.clone())
    }

    pub fn has_pending_disk_fault(&self, worker_id: &str) -> bool {
        self.terminal
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .any(|receipt| {
                receipt
                    .pending_disk_fault
                    .as_ref()
                    .is_some_and(|fault| fault.worker_id == worker_id)
            })
    }

    pub(crate) fn has_pending_disk_fault_for_endpoint(
        &self,
        endpoint: &WorkerEndpointIdentity,
    ) -> bool {
        self.terminal
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .any(|receipt| {
                receipt
                    .pending_disk_fault
                    .as_ref()
                    .is_some_and(|fault| fault.worker_endpoint.as_ref() == Some(endpoint))
            })
    }

    #[cfg(test)]
    pub(crate) fn unapplied_disk_fault(&self, build_id: u64) -> Option<PendingDiskFault> {
        self.terminal
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&build_id)
            .and_then(|receipt| receipt.unapplied_disk_fault.clone())
    }

    /// The caller holds the bypass store lock until this commit finishes, so
    /// recovery cannot erase its incident receipt before acknowledgment.
    pub(crate) fn acknowledge_disk_fault(
        &self,
        build_id: u64,
        incident_id: &str,
    ) -> std::io::Result<()> {
        self.resolve_disk_fault(build_id, incident_id, false)
    }

    /// A mismatched or legacy fault remains inspectable in its terminal
    /// receipt, but cannot block admission or later quarantine any endpoint.
    pub(crate) fn archive_disk_fault(
        &self,
        build_id: u64,
        incident_id: &str,
    ) -> std::io::Result<()> {
        self.resolve_disk_fault(build_id, incident_id, true)
    }

    fn resolve_disk_fault(
        &self,
        build_id: u64,
        incident_id: &str,
        archive: bool,
    ) -> std::io::Result<()> {
        let active = self.active.write().unwrap_or_else(|e| e.into_inner());
        let mut receipt = self
            .terminal
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&build_id)
            .cloned()
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "terminal build not found")
            })?;
        let Some(fault) = &receipt.pending_disk_fault else {
            return Ok(());
        };
        if fault.incident_id != incident_id {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "worker disk fault identity mismatch",
            ));
        }
        let fault = receipt.pending_disk_fault.take();
        if archive {
            receipt.unapplied_disk_fault = fault;
        }
        self.persist_ownership(&active, Some(&receipt))?;
        self.terminal
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(build_id, receipt);
        Ok(())
    }

    /// One locked transition owns both the durable terminal receipt and release.
    pub fn complete_durable(
        &self,
        build_id: u64,
        worker_id: &str,
        wrapper: Option<&str>,
        completion: BuildCompletion,
    ) -> std::io::Result<Option<(ActiveBuildState, BuildRecord)>> {
        self.complete_durable_with_disk_fault(build_id, worker_id, wrapper, completion, None)
    }

    /// Commit a fault with its exact owner's terminal receipt. Repeated
    /// requests can only resume that stored fault, never add or replace it.
    pub(crate) fn complete_durable_with_disk_fault(
        &self,
        build_id: u64,
        worker_id: &str,
        wrapper: Option<&str>,
        completion: BuildCompletion,
        disk_roots: Option<Vec<String>>,
    ) -> std::io::Result<Option<(ActiveBuildState, BuildRecord)>> {
        let BuildCompletion {
            exit_code,
            duration_ms,
            bytes_transferred,
            timing,
            cancellation,
        } = completion;
        let mut active = self.active.write().unwrap_or_else(|e| e.into_inner());
        let Some(state) = active.get(&build_id) else {
            let terminal = self.terminal.read().unwrap_or_else(|e| e.into_inner());
            if terminal.get(&build_id).is_some_and(|receipt| {
                receipt.record.worker_id.as_deref() == Some(worker_id)
                    && receipt.local_wrapper_id.as_deref() == wrapper
            }) {
                return Ok(None);
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "unknown build or ownership mismatch",
            ));
        };
        if state.worker_id != worker_id || state.local_wrapper_id.as_deref() != wrapper {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "build ownership mismatch",
            ));
        }
        let record = BuildRecord {
            id: state.id,
            started_at: state.started_at.clone(),
            completed_at: Utc::now().to_rfc3339(),
            project_id: state.project_id.clone(),
            worker_id: Some(state.worker_id.clone()),
            command: state.command.clone(),
            exit_code,
            duration_ms: duration_ms
                .unwrap_or_else(|| state.started_at_mono.elapsed().as_millis() as u64),
            location: state.location,
            bytes_transferred,
            timing,
            cancellation,
        };
        let disk_fault = if exit_code != 0 {
            disk_roots
                .map(|roots| {
                    crate::bypass_recovery_service::validate_disk_fault_roots(&roots).map(|roots| {
                        PendingDiskFault {
                            build_id,
                            worker_id: worker_id.to_owned(),
                            incident_id: format!("build:{build_id}:{}", record.completed_at),
                            roots,
                            reported_unix_ms: u64::try_from(Utc::now().timestamp_millis())
                                .unwrap_or(0),
                            worker_endpoint: state.worker_endpoint.as_ref().map(|endpoint| {
                                WorkerEndpointIdentity::from_config(&endpoint.config)
                            }),
                            runtime_endpoint: state
                                .worker_endpoint
                                .as_ref()
                                .filter(|endpoint| endpoint.has_runtime_identity())
                                .cloned(),
                        }
                    })
                })
                .transpose()
                .map_err(|error| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, error.to_string())
                })?
        } else {
            None
        };
        // The first terminal commit must retain a retarget already known by
        // the originating incarnation. Deferring this decision until bypass
        // publication loses ABA evidence if the daemon crashes in between.
        // Unknown restart epochs and same-generation retirement remain valid
        // durable obligations for their saved coordinates.
        let (pending_disk_fault, unapplied_disk_fault) = if state
            .worker_endpoint
            .as_ref()
            .is_some_and(WorkerEndpointSnapshot::source_was_retargeted)
        {
            (None, disk_fault)
        } else {
            (disk_fault, None)
        };
        let receipt = TerminalOwnership {
            record: record.clone(),
            local_wrapper_id: state.local_wrapper_id.clone(),
            pending_disk_fault,
            unapplied_disk_fault,
        };
        prune_terminal_receipts(
            &mut self.terminal.write().unwrap_or_else(|e| e.into_inner()),
            Utc::now(),
        );
        self.persist_ownership(&active, Some(&receipt))?;
        self.terminal
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(build_id, receipt);
        if state.location == BuildLocation::Remote && state.disk_headroom_gib > 0 {
            // Keep the old sample fenced before releasing `active`: completed
            // output still occupies disk even though its reservation is gone.
            self.disk_budget_completed_at
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(state.worker_id.clone(), Instant::now());
        }
        let state = active.remove(&build_id).expect("locked ownership exists");
        self.learn_footprint(&state, exit_code);
        self.record(record.clone());
        Ok(Some((state, record)))
    }

    /// Atomically commit ownership before admitting or acknowledging a job.
    /// An identity-bound queue-to-active or queue-to-cancelled transition must
    /// not leave a second queued copy in the durable file, even if the daemon
    /// dies before its API handler performs the old explicit queue removal.
    fn persist_ownership(
        &self,
        active: &HashMap<u64, ActiveBuildState>,
        completed: Option<&TerminalOwnership>,
    ) -> std::io::Result<()> {
        let mut queued = self.queued.write().unwrap_or_else(|e| e.into_inner());
        if queued.is_empty() {
            return self.persist_ownership_with_queue(active, completed, &queued);
        }
        let occupied = occupied_wrapper_ids(
            active,
            &self.terminal.read().unwrap_or_else(|e| e.into_inner()),
            &self
                .cancelled_wrappers
                .read()
                .unwrap_or_else(|e| e.into_inner()),
        );
        let mut remaining = queued.clone();
        remaining.retain(|state| {
            state
                .local_wrapper_id
                .as_deref()
                .is_none_or(|wrapper| !occupied.contains(wrapper))
        });
        self.persist_ownership_with_queue(active, completed, &remaining)?;
        *queued = remaining;
        Ok(())
    }

    /// Commit a projected queue while its caller holds `active` then `queued`.
    /// Separating this from persist_ownership avoids recursively locking the
    /// queue in enqueue/departure paths. No memory rollback claims disk success.
    fn persist_ownership_with_queue(
        &self,
        active: &HashMap<u64, ActiveBuildState>,
        completed: Option<&TerminalOwnership>,
        queued: &VecDeque<QueuedBuildState>,
    ) -> std::io::Result<()> {
        if self.ownership_failed() {
            return Err(std::io::Error::other(
                "durable ownership uncertain; restart required",
            ));
        }
        let result = self.write_ownership(active, completed, queued);
        if result.is_err() {
            self.ownership_failed.store(true, Ordering::SeqCst);
        }
        result
    }

    fn write_ownership(
        &self,
        active: &HashMap<u64, ActiveBuildState>,
        completed: Option<&TerminalOwnership>,
        queued: &VecDeque<QueuedBuildState>,
    ) -> std::io::Result<()> {
        let Some(path) = &self.persistence_path else {
            return Ok(());
        };
        let path = path.with_extension("ownership.json");
        let terminal = self.terminal.read().unwrap_or_else(|e| e.into_inner());
        let snapshot = DurableOwnership {
            version: 2,
            active: active
                .values()
                .filter(|state| completed.is_none_or(|receipt| receipt.record.id != state.id))
                .cloned()
                .collect(),
            completed: terminal
                .values()
                .filter(|receipt| completed.is_none_or(|new| new.record.id != receipt.record.id))
                .chain(completed)
                .cloned()
                .collect(),
            cancelled_wrappers: self
                .cancelled_wrappers
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .clone(),
            next_queue_id: Some(self.next_queue_id.load(Ordering::SeqCst)),
            queued: Some(queued.clone()),
        };
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        std::fs::create_dir_all(parent)?;
        let temporary = path.with_extension("tmp");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temporary)?;
        serde_json::to_writer(&mut file, &snapshot)?;
        file.sync_all()?;
        std::fs::rename(&temporary, &path)?;
        #[cfg(test)]
        if self.fail_after_ownership_rename.load(Ordering::SeqCst) {
            return Err(std::io::Error::other(
                "injected post-rename ownership failure",
            ));
        }
        File::open(parent)?.sync_all()?;
        Ok(())
    }
}

/// Queue visibility and active/terminal/no-start ownership are disjoint for
/// durable wrapper identities. Anonymous legacy queue rows cannot be joined
/// to an execution by a reusable PID and are never guessed away here.
fn occupied_wrapper_ids(
    active: &HashMap<u64, ActiveBuildState>,
    terminal: &HashMap<u64, TerminalOwnership>,
    cancelled: &HashSet<String>,
) -> HashSet<String> {
    active
        .values()
        .filter_map(|state| state.local_wrapper_id.clone())
        .chain(
            terminal
                .values()
                .filter_map(|receipt| receipt.local_wrapper_id.clone()),
        )
        .chain(cancelled.iter().cloned())
        .collect()
}

/// Drop receipts past retention, then the oldest beyond the cap. An
/// unparseable completion time sorts oldest.
fn prune_terminal_receipts(terminal: &mut HashMap<u64, TerminalOwnership>, now: DateTime<Utc>) {
    let cutoff = now - ChronoDuration::days(TERMINAL_RECEIPT_RETENTION_DAYS);
    terminal.retain(|_, receipt| {
        receipt.pending_disk_fault.is_some()
            || DateTime::parse_from_rfc3339(&receipt.record.completed_at)
                .map_or(true, |completed| completed >= cutoff)
    });
    let Some(excess) = terminal.len().checked_sub(MAX_TERMINAL_RECEIPTS) else {
        return;
    };
    let mut by_age: Vec<_> = terminal
        .iter()
        .filter(|(_, receipt)| receipt.pending_disk_fault.is_none())
        .map(|(id, receipt)| {
            (
                DateTime::parse_from_rfc3339(&receipt.record.completed_at).ok(),
                *id,
            )
        })
        .collect();
    by_age.sort_unstable();
    for (_, id) in by_age.into_iter().take(excess) {
        terminal.remove(&id);
    }
}

/// Learned footprints live beside the history log (`history.footprints.json`).
fn footprint_path(history_path: &Path) -> PathBuf {
    history_path.with_extension("footprints.json")
}

fn reserved_disk_headroom(active: &HashMap<u64, ActiveBuildState>, worker_id: &str) -> u64 {
    active
        .values()
        .filter(|state| state.worker_id == worker_id && state.location == BuildLocation::Remote)
        .fold(0u64, |sum, state| {
            sum.saturating_add(u64::from(state.disk_headroom_gib))
        })
}

impl Default for BuildHistory {
    fn default() -> Self {
        Self::with_default_capacity()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rch_common::{WorkerId, test_guard};
    use std::time::{SystemTime, UNIX_EPOCH};
    use tempfile::TempDir;

    fn disk_budget_admit(
        history: &BuildHistory,
        project: &str,
        worker: &str,
        budget: u32,
        free: f64,
    ) -> Option<ActiveBuildState> {
        disk_budget_admit_snapshot(
            history,
            project,
            worker,
            DiskHeadroomAdmission {
                requested_gib: budget,
                capacity: Some(crate::disk_pressure::DiskCapacityObservation::fixture(
                    worker,
                    free,
                    Duration::ZERO,
                )),
            },
        )
    }

    fn disk_budget_admit_snapshot(
        history: &BuildHistory,
        project: &str,
        worker: &str,
        disk: DiskHeadroomAdmission,
    ) -> Option<ActiveBuildState> {
        history
            .try_start_active_build_with_waiter(
                project.into(),
                worker.into(),
                "cargo test".into(),
                0,
                Some(format!("owner-{project}-{worker}")),
                1,
                BuildLocation::Remote,
                None,
                disk,
                None,
            )
            .unwrap()
    }

    fn disk_budget_completion(exit_code: i32) -> BuildCompletion {
        BuildCompletion {
            exit_code,
            duration_ms: None,
            bytes_transferred: None,
            timing: None,
            cancellation: None,
        }
    }

    fn finish_owned(history: &BuildHistory, active: &ActiveBuildState, exit_code: i32) {
        history
            .complete_durable(
                active.id,
                &active.worker_id,
                active.local_wrapper_id.as_deref(),
                disk_budget_completion(exit_code),
            )
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn footprint_is_learned_from_an_unshared_remote_build_and_persisted() {
        let root = TempDir::new().unwrap();
        let path = root.path().join("history.jsonl");
        let history = BuildHistory::new(10).with_persistence(path.clone());
        let active = disk_budget_admit(&history, "fgdb", "ovh-b", 0, 120.0).unwrap();
        assert_eq!(active.disk_free_start_gib, Some(120));

        // A probe taken before admission says nothing about this build.
        history.observe_build_disk("ovh-b", 10, active.started_at_mono);
        // Probes on another worker are not this build's.
        history.observe_build_disk("other", 1, Instant::now());
        history.observe_build_disk("ovh-b", 70, Instant::now());
        history.observe_build_disk("ovh-b", 56, Instant::now());
        history.observe_build_disk("ovh-b", 90, Instant::now());
        assert_eq!(
            history.active_build(active.id).unwrap().disk_free_min_gib,
            Some(56)
        );
        // While running, the learned footprint is still unknown.
        assert_eq!(history.pending_footprint_gib("ovh-b"), 0.0);

        // A failing test run (101) still filled the disk: learn from it.
        finish_owned(&history, &active, 101);
        assert_eq!(
            history.learned_footprint_gib("fgdb", "cargo test"),
            Some(64.0)
        );
        // The command class is part of the identity.
        assert_eq!(history.learned_footprint_gib("fgdb", "cargo check"), None);
        assert_eq!(history.learned_footprint_gib("other", "cargo test"), None);

        // The book survives a daemon restart beside the history log.
        drop(history);
        let reloaded = BuildHistory::load_from_file(&path, 10).unwrap();
        assert_eq!(
            reloaded.learned_footprint_gib("fgdb", "cargo test"),
            Some(64.0)
        );
    }

    #[test]
    fn footprint_running_build_reserves_its_remaining_growth() {
        let history = BuildHistory::new(10);
        let first = disk_budget_admit(&history, "fgdb", "ovh-b", 0, 120.0).unwrap();
        history.observe_build_disk("ovh-b", 56, Instant::now());
        finish_owned(&history, &first, 0);

        let second = disk_budget_admit(&history, "fgdb", "ovh-b", 0, 100.0).unwrap();
        assert_eq!(history.pending_footprint_gib("ovh-b"), 64.0);
        history.observe_build_disk("ovh-b", 80, Instant::now());
        assert_eq!(history.pending_footprint_gib("ovh-b"), 44.0);
        history.observe_build_disk("ovh-b", 10, Instant::now());
        assert_eq!(history.pending_footprint_gib("ovh-b"), 0.0);
        assert_eq!(history.pending_footprint_gib("elsewhere"), 0.0);
        finish_owned(&history, &second, 0);
        // The larger observation is now the estimate.
        assert_eq!(
            history.learned_footprint_gib("fgdb", "cargo test"),
            Some(90.0)
        );
    }

    #[test]
    fn footprint_is_not_learned_from_shared_cancelled_or_unprobed_builds() {
        let history = BuildHistory::new(10);

        // Two of this daemon's builds overlapped on one worker: neither can
        // claim the drop, including the one that finishes after the other.
        let a = disk_budget_admit(&history, "a", "w", 0, 200.0).unwrap();
        let b = disk_budget_admit(&history, "b", "w", 0, 200.0).unwrap();
        history.observe_build_disk("w", 100, Instant::now());
        finish_owned(&history, &a, 0);
        history.observe_build_disk("w", 90, Instant::now());
        finish_owned(&history, &b, 0);
        assert_eq!(history.learned_footprint_gib("a", "cargo test"), None);
        assert_eq!(history.learned_footprint_gib("b", "cargo test"), None);

        // Cancelled builds stopped early.
        let cancelled = disk_budget_admit(&history, "c", "w", 0, 200.0).unwrap();
        history.observe_build_disk("w", 100, Instant::now());
        finish_owned(&history, &cancelled, 130);
        assert_eq!(history.learned_footprint_gib("c", "cargo test"), None);

        // No probe arrived during the build.
        let unprobed = disk_budget_admit(&history, "d", "w", 0, 200.0).unwrap();
        finish_owned(&history, &unprobed, 0);
        assert_eq!(history.learned_footprint_gib("d", "cargo test"), None);

        // A stale admission sample cannot be a starting point.
        let stale = disk_budget_admit_snapshot(
            &history,
            "e",
            "w",
            DiskHeadroomAdmission {
                requested_gib: 0,
                capacity: Some(crate::disk_pressure::DiskCapacityObservation::fixture(
                    "w",
                    200.0,
                    Duration::from_secs(3600),
                )),
            },
        )
        .unwrap();
        assert_eq!(stale.disk_free_start_gib, None);
        history.observe_build_disk("w", 100, Instant::now());
        finish_owned(&history, &stale, 0);
        assert_eq!(history.learned_footprint_gib("e", "cargo test"), None);
    }

    #[tokio::test]
    async fn disk_budget_completion_cannot_spend_the_same_capacity_sample_twice() {
        let root = TempDir::new().unwrap();
        let path = root.path().join("history.jsonl");
        let history = BuildHistory::new(10).with_persistence(path);
        let request = |worker, free| DiskHeadroomAdmission {
            requested_gib: 80,
            capacity: Some(crate::disk_pressure::DiskCapacityObservation::fixture(
                worker,
                free,
                Duration::ZERO,
            )),
        };
        let old = request("worker", 100.0);
        let other = request("other-worker", 100.0);
        let active = disk_budget_admit_snapshot(&history, "a", "worker", old.clone()).unwrap();
        assert!(
            history
                .complete_durable(
                    active.id,
                    "worker",
                    Some("wrong-owner"),
                    disk_budget_completion(0)
                )
                .is_err()
        );
        assert!(
            history
                .check_disk_headroom(
                    "worker",
                    &DiskHeadroomAdmission {
                        requested_gib: 20,
                        ..old.clone()
                    }
                )
                .is_ok(),
            "a rejected completion cannot invalidate the still-funded sample"
        );
        history
            .complete_durable(
                active.id,
                "worker",
                active.local_wrapper_id.as_deref(),
                disk_budget_completion(0),
            )
            .unwrap()
            .unwrap();
        assert_eq!(history.reserved_disk_headroom_gib("worker"), 0);
        assert_eq!(
            history.check_disk_headroom("worker", &old),
            Err(DiskHeadroomRejection::Stale)
        );
        assert!(
            disk_budget_admit_snapshot(&history, "b", "worker", old).is_none(),
            "completion cannot reuse a pre-build sample even within the probe TTL"
        );
        assert!(disk_budget_admit_snapshot(&history, "other", "other-worker", other).is_some());

        // Neither an idempotent release nor a forged owner may advance the
        // cutoff and invalidate evidence observed after the real completion.
        let fresh = request("worker", 100.0);
        assert!(
            history
                .complete_durable(
                    active.id,
                    "worker",
                    active.local_wrapper_id.as_deref(),
                    disk_budget_completion(0)
                )
                .unwrap()
                .is_none()
        );
        assert!(
            history
                .complete_durable(
                    active.id,
                    "wrong-worker",
                    active.local_wrapper_id.as_deref(),
                    disk_budget_completion(0)
                )
                .is_err()
        );
        assert!(history.check_disk_headroom("worker", &fresh).is_ok());

        // A genuine post-build sample reports the remaining 20 GiB. The 80 GiB
        // request still does not fit, but a smaller declared build can proceed.
        let mut remaining = request("worker", 20.0);
        assert!(matches!(
            history.check_disk_headroom("worker", &remaining),
            Err(DiskHeadroomRejection::Insufficient { .. })
        ));
        remaining.requested_gib = 20;
        assert!(disk_budget_admit_snapshot(&history, "fits", "worker", remaining).is_some());
        assert_eq!(history.reserved_disk_headroom_gib("worker"), 20);
        assert_eq!(history.reserved_disk_headroom_gib("other-worker"), 80);
    }

    #[tokio::test]
    async fn disk_budget_completion_racing_admission_never_exposes_unfunded_capacity() {
        use std::sync::{Arc, Barrier};
        for _ in 0..8 {
            let root = TempDir::new().unwrap();
            let history =
                Arc::new(BuildHistory::new(10).with_persistence(root.path().join("history.jsonl")));
            let sample = DiskHeadroomAdmission {
                requested_gib: 80,
                capacity: Some(crate::disk_pressure::DiskCapacityObservation::fixture(
                    "worker",
                    100.0,
                    Duration::ZERO,
                )),
            };
            let first =
                disk_budget_admit_snapshot(&history, "a", "worker", sample.clone()).unwrap();
            let barrier = Arc::new(Barrier::new(2));
            let admitting = Arc::clone(&history);
            let admission_barrier = Arc::clone(&barrier);
            let retry = std::thread::spawn(move || {
                admission_barrier.wait();
                disk_budget_admit_snapshot(&admitting, "b", "worker", sample)
            });
            barrier.wait();
            history
                .complete_durable(
                    first.id,
                    "worker",
                    first.local_wrapper_id.as_deref(),
                    disk_budget_completion(0),
                )
                .unwrap()
                .unwrap();
            assert!(
                retry.join().unwrap().is_none(),
                "admission must see either the active budget or the completion cutoff"
            );
            assert_eq!(history.reserved_disk_headroom_gib("worker"), 0);
            assert!(disk_budget_admit(&history, "fresh", "worker", 20, 20.0).is_some());
        }
    }

    #[tokio::test]
    async fn disk_budget_completion_failed_commit_retains_budget_and_refuses_advice() {
        let root = TempDir::new().unwrap();
        let path = root.path().join("history.jsonl");
        let history = BuildHistory::new(10).with_persistence(path.clone());
        let active = disk_budget_admit(&history, "a", "worker", 80, 100.0).unwrap();
        history
            .fail_after_ownership_rename
            .store(true, Ordering::SeqCst);
        assert!(
            history
                .complete_durable(
                    active.id,
                    "worker",
                    active.local_wrapper_id.as_deref(),
                    disk_budget_completion(0)
                )
                .is_err()
        );
        assert_eq!(history.reserved_disk_headroom_gib("worker"), 80);
        assert!(history.disk_budget_completed_at.lock().unwrap().is_empty());
        let sample = DiskHeadroomAdmission {
            requested_gib: 1,
            capacity: Some(crate::disk_pressure::DiskCapacityObservation::fixture(
                "worker",
                100.0,
                Duration::ZERO,
            )),
        };
        assert_eq!(
            history.check_disk_headroom("worker", &sample),
            Err(DiskHeadroomRejection::Unknown)
        );
        assert!(disk_budget_admit_snapshot(&history, "b", "worker", sample).is_none());
        drop(history);
        let restored = BuildHistory::load_from_file(&path, 10).unwrap();
        assert_eq!(restored.reserved_disk_headroom_gib("worker"), 0);
        // Restarted WorkerStates have no cached observation. A subsequent live
        // probe can fund only the headroom it actually reports after restart.
        assert_eq!(
            restored.check_disk_headroom(
                "worker",
                &DiskHeadroomAdmission {
                    requested_gib: 20,
                    capacity: None
                }
            ),
            Err(DiskHeadroomRejection::Unknown)
        );
        assert!(disk_budget_admit(&restored, "after-restart", "worker", 20, 20.0).is_some());
    }

    #[tokio::test]
    async fn disk_budget_completion_only_fences_positive_remote_budgets() {
        let history = BuildHistory::new(10);
        let sample = DiskHeadroomAdmission {
            requested_gib: 80,
            capacity: Some(crate::disk_pressure::DiskCapacityObservation::fixture(
                "worker",
                100.0,
                Duration::ZERO,
            )),
        };
        let undeclared = disk_budget_admit(&history, "undeclared", "worker", 0, 100.0).unwrap();
        history
            .complete_durable(
                undeclared.id,
                "worker",
                undeclared.local_wrapper_id.as_deref(),
                disk_budget_completion(0),
            )
            .unwrap()
            .unwrap();
        assert!(history.check_disk_headroom("worker", &sample).is_ok());
        let local = history
            .try_start_active_build_with_waiter(
                "local".into(),
                "worker".into(),
                "build".into(),
                0,
                Some("local-owner".into()),
                1,
                BuildLocation::Local,
                None,
                sample.clone(),
                None,
            )
            .unwrap()
            .unwrap();
        history
            .complete_durable(
                local.id,
                "worker",
                Some("local-owner"),
                disk_budget_completion(0),
            )
            .unwrap()
            .unwrap();
        assert!(history.check_disk_headroom("worker", &sample).is_ok());
        assert!(history.disk_budget_completed_at.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn declared_disk_budget_is_atomic_across_projects_and_durable_until_owned_completion() {
        use std::sync::{Arc, Barrier};
        let root = TempDir::new().unwrap();
        let path = root.path().join("history.jsonl");
        let history = Arc::new(BuildHistory::new(10).with_persistence(path.clone()));
        let barrier = Arc::new(Barrier::new(2));
        let handles: Vec<_> = ["a", "b"]
            .into_iter()
            .map(|project| {
                let history = Arc::clone(&history);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    disk_budget_admit(&history, project, "worker", 64, 100.0)
                })
            })
            .collect();
        let admitted: Vec<_> = handles
            .into_iter()
            .filter_map(|handle| handle.join().unwrap())
            .collect();
        assert_eq!(
            admitted.len(),
            1,
            "the same free space cannot fund both projects"
        );
        assert_eq!(history.reserved_disk_headroom_gib("worker"), 64);
        assert!(disk_budget_admit(&history, "other", "second-worker", 64, 100.0).is_some());
        drop(history);
        let restored = BuildHistory::load_from_file(&path, 10).unwrap();
        assert_eq!(restored.reserved_disk_headroom_gib("worker"), 64);
        assert!(disk_budget_admit(&restored, "c", "worker", 37, 100.0).is_none());
        let exact = disk_budget_admit(&restored, "c", "worker", 36, 100.0).unwrap();
        assert_eq!(restored.reserved_disk_headroom_gib("worker"), 100);
        let completion = || BuildCompletion {
            exit_code: 0,
            duration_ms: None,
            bytes_transferred: None,
            timing: None,
            cancellation: None,
        };
        assert!(
            restored
                .complete_durable(exact.id, "worker", Some("wrong-owner"), completion())
                .is_err()
        );
        assert_eq!(restored.reserved_disk_headroom_gib("worker"), 100);
        restored
            .complete_durable(
                exact.id,
                "worker",
                exact.local_wrapper_id.as_deref(),
                completion(),
            )
            .unwrap()
            .unwrap();
        assert_eq!(restored.reserved_disk_headroom_gib("worker"), 64);
        assert_eq!(restored.reserved_disk_headroom_gib("second-worker"), 64);
        drop(restored);
        let restored = BuildHistory::load_from_file(&path, 10).unwrap();
        assert_eq!(restored.reserved_disk_headroom_gib("worker"), 64);
        // Completed output still occupies disk: reduced telemetry plus the
        // whole running budget is conservative, never an implicit release.
        assert!(disk_budget_admit(&restored, "d", "worker", 1, 64.0).is_none());
    }

    #[test]
    fn declared_disk_budget_rejects_stale_snapshot_at_final_admission() {
        let history = BuildHistory::new(10);
        let rejected = history
            .try_start_active_build_with_waiter(
                "a".into(),
                "worker".into(),
                "cargo test".into(),
                0,
                Some("owner".into()),
                1,
                BuildLocation::Remote,
                None,
                DiskHeadroomAdmission {
                    requested_gib: 64,
                    capacity: Some(crate::disk_pressure::DiskCapacityObservation::fixture(
                        "worker",
                        100.0,
                        Duration::from_secs(91),
                    )),
                },
                None,
            )
            .unwrap();
        assert!(rejected.is_none());
        assert!(history.active_builds().is_empty());
        assert_eq!(history.reserved_disk_headroom_gib("worker"), 0);
    }

    fn queue_resume_enqueue(
        history: &BuildHistory,
        wrapper: Option<&str>,
    ) -> (QueuedBuildState, QueuedWaiterClaim) {
        history
            .enqueue_selection_build(
                "project".into(),
                "cargo build".into(),
                observable_test_process_id(),
                2,
                wrapper.map(str::to_owned),
                QueueSelectionContract {
                    digest: [7; 32],
                    timeout_secs: 45,
                },
            )
            .unwrap()
    }

    #[test]
    fn queue_resume_requires_recovery_contract_and_original_process_birth() {
        let pid = observable_test_process_id();
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("history.jsonl");
        let history = BuildHistory::new(10).with_persistence(path.clone());
        let (queued, _) = queue_resume_enqueue(&history, Some("owner"));
        assert!(history.resume_queued_build("owner", pid, &[7; 32]).is_err());
        drop(history);
        let history = BuildHistory::load_from_file(&path, 10).unwrap();
        assert!(
            history
                .resume_queued_build("missing", pid, &[7; 32])
                .is_err()
        );
        assert!(history.resume_queued_build("owner", 1, &[7; 32]).is_err());
        assert!(history.resume_queued_build("owner", pid, &[8; 32]).is_err());
        for missing_identity in [false, true] {
            let mut rows = history.queued.write().unwrap();
            rows[0].hook_process_identity = if missing_identity {
                None
            } else {
                Some("another-process-birth".into())
            };
            drop(rows);
            assert!(history.resume_queued_build("owner", pid, &[7; 32]).is_err());
        }
        let mut rows = history.queued.write().unwrap();
        rows[0].hook_process_identity = queued.hook_process_identity;
        rows[0].selection_contract = None;
        drop(rows);
        assert!(history.resume_queued_build("owner", pid, &[7; 32]).is_err());
        assert_eq!(history.queue_depth(), 1);
        assert!(history.active_builds().is_empty());
    }

    #[test]
    fn queue_resume_claim_is_exclusive_and_survives_another_restart_without_resetting_age() {
        use std::sync::{Arc, Barrier};
        let pid = observable_test_process_id();
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("history.jsonl");
        let history = BuildHistory::new(10).with_persistence(path.clone());
        let (first, _) = queue_resume_enqueue(&history, Some("first"));
        let (second, _) = queue_resume_enqueue(&history, Some("second"));
        drop(history);
        let history = Arc::new(BuildHistory::load_from_file(&path, 10).unwrap());
        let barrier = Arc::new(Barrier::new(3));
        let tasks: Vec<_> = (0..2)
            .map(|_| {
                let history = history.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    history.resume_queued_build("first", pid, &[7; 32])
                })
            })
            .collect();
        barrier.wait();
        let claims: Vec<_> = tasks
            .into_iter()
            .filter_map(|task| task.join().unwrap().ok())
            .collect();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].0.id, first.id);
        assert_eq!(
            history
                .queued_builds()
                .iter()
                .map(|row| row.id)
                .collect::<Vec<_>>(),
            vec![first.id, second.id]
        );
        let age = claims[0].0.queued_at_mono.elapsed();
        drop(history);
        let restarted = BuildHistory::load_from_file(&path, 10).unwrap();
        let (again, _) = restarted
            .resume_queued_build("first", pid, &[7; 32])
            .unwrap();
        assert_eq!(again.id, first.id);
        assert_eq!(again.queued_at, first.queued_at);
        assert!(again.queued_at_mono.elapsed() >= age);
        assert_eq!(again.selection_contract.unwrap().timeout_secs, 45);
    }

    #[test]
    fn queue_resume_claimed_admission_atomically_replaces_queue_and_cannot_replay() {
        let pid = observable_test_process_id();
        for wrapper in [Some("owner"), None] {
            let tmp = TempDir::new().unwrap();
            let path = tmp.path().join("history.jsonl");
            let history = BuildHistory::new(10).with_persistence(path.clone());
            let (queued, claim) = queue_resume_enqueue(&history, wrapper);
            if wrapper.is_some() {
                assert!(
                    history
                        .try_start_active_build_with_wrapper(
                            "project".into(),
                            "worker".into(),
                            "cargo build".into(),
                            pid,
                            wrapper.map(str::to_owned),
                            2,
                            BuildLocation::Remote,
                        )
                        .unwrap()
                        .is_none()
                );
            }
            let active = history
                .try_start_active_build_with_waiter(
                    "project".into(),
                    "worker".into(),
                    "cargo build".into(),
                    pid,
                    wrapper.map(str::to_owned),
                    2,
                    BuildLocation::Remote,
                    Some(&claim),
                    DiskHeadroomAdmission::default(),
                    None,
                )
                .unwrap()
                .unwrap();
            assert!(!history.owns_queued_waiter(&claim));
            assert!(history.queued_build(queued.id).is_none());
            assert!(
                history
                    .try_start_active_build_with_waiter(
                        "project".into(),
                        "second-worker".into(),
                        "cargo build".into(),
                        pid,
                        wrapper.map(str::to_owned),
                        2,
                        BuildLocation::Remote,
                        Some(&claim),
                        DiskHeadroomAdmission::default(),
                        None,
                    )
                    .unwrap()
                    .is_none()
            );
            // Observe the durable commit before any handler cleanup can run.
            let restored = BuildHistory::load_from_file(&path, 10).unwrap();
            assert_eq!(restored.queue_depth(), 0);
            assert_eq!(restored.active_builds().len(), 1);
            assert!(restored.active_build(active.id).is_some());
            assert!(
                restored
                    .resume_queued_build("owner", pid, &[7; 32])
                    .is_err()
            );
        }
    }

    #[test]
    fn queue_resume_cancellation_and_claimed_admission_have_one_durable_winner() {
        use std::sync::{Arc, Barrier};
        let pid = observable_test_process_id();
        for _ in 0..8 {
            let tmp = TempDir::new().unwrap();
            let path = tmp.path().join("history.jsonl");
            let history = BuildHistory::new(10).with_persistence(path.clone());
            queue_resume_enqueue(&history, Some("owner"));
            drop(history);
            let history = Arc::new(BuildHistory::load_from_file(&path, 10).unwrap());
            let (_, claim) = history.resume_queued_build("owner", pid, &[7; 32]).unwrap();
            let barrier = Arc::new(Barrier::new(2));
            let admission_history = history.clone();
            let admission_barrier = barrier.clone();
            let admission = std::thread::spawn(move || {
                admission_barrier.wait();
                admission_history
                    .try_start_active_build_with_waiter(
                        "project".into(),
                        "worker".into(),
                        "cargo build".into(),
                        pid,
                        Some("owner".into()),
                        2,
                        BuildLocation::Remote,
                        Some(&claim),
                        DiskHeadroomAdmission::default(),
                        None,
                    )
                    .unwrap()
            });
            barrier.wait();
            let cancellation = history.cancel_wrapper("owner").unwrap();
            let admitted = admission.join().unwrap();
            let restored = BuildHistory::load_from_file(&path, 10).unwrap();
            assert_eq!(restored.queue_depth(), 0);
            match cancellation {
                WrapperCancellation::BeforeStart => {
                    assert!(admitted.is_none());
                    assert!(restored.active_builds().is_empty());
                    assert!(restored.wrapper_cancelled("owner"));
                }
                WrapperCancellation::Active(id) => {
                    assert_eq!(admitted.unwrap().id, id);
                    assert!(restored.active_build(id).is_some());
                    assert!(!restored.wrapper_cancelled("owner"));
                }
                WrapperCancellation::Completed(_) | WrapperCancellation::NotQueued => {
                    panic!("queued cancellation lost both queue and execution")
                }
            }
            assert!(
                restored
                    .resume_queued_build("owner", pid, &[7; 32])
                    .is_err()
            );
        }
    }

    #[test]
    fn queue_resume_uncertain_admission_never_restores_a_second_waiter() {
        let pid = observable_test_process_id();
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("history.jsonl");
        let history = BuildHistory::new(10).with_persistence(path.clone());
        queue_resume_enqueue(&history, Some("owner"));
        drop(history);
        let history = BuildHistory::load_from_file(&path, 10).unwrap();
        let (_, claim) = history.resume_queued_build("owner", pid, &[7; 32]).unwrap();
        history
            .fail_after_ownership_rename
            .store(true, Ordering::SeqCst);
        assert!(
            history
                .try_start_active_build_with_waiter(
                    "project".into(),
                    "worker".into(),
                    "cargo build".into(),
                    pid,
                    Some("owner".into()),
                    2,
                    BuildLocation::Remote,
                    Some(&claim),
                    DiskHeadroomAdmission::default(),
                    None,
                )
                .is_err()
        );
        assert!(history.ownership_failed());
        assert!(history.resume_queued_build("owner", pid, &[7; 32]).is_err());
        drop(history);
        let restored = BuildHistory::load_from_file(&path, 10).unwrap();
        assert_eq!(restored.queue_depth(), 0);
        assert_eq!(restored.active_builds().len(), 1);
        assert!(
            restored
                .resume_queued_build("owner", pid, &[7; 32])
                .is_err()
        );
    }

    fn recovery_validation_fixture(
        path: &Path,
        version: u32,
    ) -> (serde_json::Value, ActiveBuildState) {
        let history = BuildHistory::new(10).with_persistence(path.to_owned());
        let active = history.start_active_build_with_wrapper(
            "recovery-validation".into(),
            "original-worker".into(),
            "cargo check".into(),
            std::process::id(),
            Some("recovery-owner".into()),
            2,
            BuildLocation::Remote,
        );
        let mut snapshot: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path.with_extension("ownership.json")).unwrap())
                .unwrap();
        if version == 1 {
            snapshot["version"] = serde_json::json!(1);
            snapshot.as_object_mut().unwrap().remove("queued");
        }
        (snapshot, active)
    }

    fn recovery_validation_receipt(id: u64, wrapper: Option<&str>) -> serde_json::Value {
        let mut record = make_build_record(id);
        record.completed_at = Utc::now().to_rfc3339();
        record.worker_id = Some("previous-worker".into());
        record.location = BuildLocation::Remote;
        serde_json::json!({
            "record": record,
            "local_wrapper_id": wrapper,
        })
    }

    fn assert_recovery_rejects_without_rewriting(path: &Path, snapshot: &serde_json::Value) {
        let ownership = path.with_extension("ownership.json");
        let temporary = ownership.with_extension("tmp");
        let bytes = serde_json::to_vec(snapshot).unwrap();
        std::fs::write(&ownership, &bytes).unwrap();
        // The real writer truncates this path before committing a snapshot.
        // A rejected load must not touch it, even if it already holds evidence.
        let prior_temporary = b"retained preexisting ownership-write evidence";
        std::fs::write(&temporary, prior_temporary).unwrap();
        let Err(error) = BuildHistory::load_from_file(path, 10) else {
            panic!("contradictory ownership must not start the daemon");
        };
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData, "{error}");
        assert_eq!(std::fs::read(&ownership).unwrap(), bytes);
        assert_eq!(
            std::fs::read(&temporary).unwrap().as_slice(),
            &prior_temporary[..]
        );
    }

    #[tokio::test]
    async fn admitted_endpoint_persists_coordinates_without_restoring_runtime_authority() {
        let root = TempDir::new().unwrap();
        let path = root.path().join("history.jsonl");
        let config = rch_common::WorkerConfig {
            id: WorkerId::new("durable-endpoint"),
            host: "admitted.example".into(),
            user: "build-user".into(),
            identity_file: "/keys/admitted key".into(),
            tags: vec!["os:linux".into()],
            ..rch_common::WorkerConfig::default()
        };
        let worker = crate::workers::WorkerState::new(config.clone());
        let endpoint = worker.endpoint_snapshot().await;
        let history = BuildHistory::new(10).with_persistence(path.clone());
        let active = history
            .try_start_active_build_with_waiter(
                "persist-endpoint".into(),
                config.id.to_string(),
                "cargo test".into(),
                std::process::id(),
                Some("endpoint-owner".into()),
                3,
                BuildLocation::Remote,
                None,
                DiskHeadroomAdmission::default(),
                Some(endpoint.clone()),
            )
            .unwrap()
            .unwrap();
        assert!(
            worker
                .lock_current_endpoint(active.worker_endpoint.as_ref().unwrap())
                .await
                .is_some()
        );
        let snapshot: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path.with_extension("ownership.json")).unwrap())
                .unwrap();
        let saved = snapshot["active"][0]["worker_endpoint"]
            .as_object()
            .unwrap();
        assert_eq!(
            saved.len(),
            1,
            "only endpoint coordinates are durable, never a process-local epoch"
        );
        assert_eq!(saved["config"]["host"], "admitted.example");
        assert_eq!(saved["config"]["identity_file"], "/keys/admitted key");

        let restored = BuildHistory::load_from_file(&path, 10).unwrap();
        let recovered = restored.active_build(active.id).unwrap();
        let recovered_endpoint = recovered.worker_endpoint.as_ref().unwrap();
        assert!(recovered.recovered);
        assert_eq!(recovered.slots, 3);
        assert_eq!(recovered_endpoint.config.id, config.id);
        assert_eq!(recovered_endpoint.config.host, config.host);
        assert_eq!(recovered_endpoint.config.user, config.user);
        assert_eq!(
            recovered_endpoint.config.identity_file,
            config.identity_file
        );
        assert_eq!(recovered_endpoint.config.tags, config.tags);
        assert!(
            worker
                .lock_current_endpoint(recovered_endpoint)
                .await
                .is_none()
        );
        let restarted_worker = crate::workers::WorkerState::new(config);
        assert!(
            restarted_worker
                .lock_current_endpoint(&endpoint)
                .await
                .is_none()
        );
        assert!(
            restarted_worker
                .lock_current_endpoint(recovered_endpoint)
                .await
                .is_none(),
            "same coordinates and generation zero cannot credit an earlier daemon's build"
        );
    }

    #[tokio::test]
    async fn active_endpoint_rejects_mismatched_worker_at_admission_and_recovery() {
        let config = rch_common::WorkerConfig {
            id: WorkerId::new("original-worker"),
            ..rch_common::WorkerConfig::default()
        };
        let worker = crate::workers::WorkerState::new(config);
        let endpoint = worker.endpoint_snapshot().await;
        for (worker_id, location) in [
            ("other-worker", BuildLocation::Remote),
            ("original-worker", BuildLocation::Local),
        ] {
            let history = BuildHistory::new(10);
            let error = history
                .try_start_active_build_with_waiter(
                    "invalid-endpoint".into(),
                    worker_id.into(),
                    "cargo check".into(),
                    0,
                    None,
                    2,
                    location,
                    None,
                    DiskHeadroomAdmission::default(),
                    Some(endpoint.clone()),
                )
                .unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
            assert!(history.active_builds().is_empty());
        }
        for version in [1, 2] {
            for mismatch in ["worker_id", "location"] {
                let root = TempDir::new().unwrap();
                let path = root.path().join("history.jsonl");
                let (mut snapshot, _) = recovery_validation_fixture(&path, version);
                snapshot["active"][0]["worker_endpoint"] = serde_json::to_value(&endpoint).unwrap();
                if mismatch == "worker_id" {
                    snapshot["active"][0]["worker_endpoint"]["config"]["id"] =
                        serde_json::json!("other-worker");
                } else {
                    snapshot["active"][0]["location"] =
                        serde_json::to_value(BuildLocation::Local).unwrap();
                }
                assert_recovery_rejects_without_rewriting(&path, &snapshot);
            }
        }
    }

    #[tokio::test]
    async fn legacy_active_ownership_keeps_unknown_endpoint_after_recovery() {
        for version in [1, 2] {
            let root = TempDir::new().unwrap();
            let path = root.path().join("history.jsonl");
            let (snapshot, active) = recovery_validation_fixture(&path, version);
            assert!(snapshot["active"][0].get("worker_endpoint").is_none());
            std::fs::write(
                path.with_extension("ownership.json"),
                serde_json::to_vec(&snapshot).unwrap(),
            )
            .unwrap();
            let restored = BuildHistory::load_from_file(&path, 10).unwrap();
            let recovered = restored.active_build(active.id).unwrap();
            assert!(recovered.worker_endpoint.is_none());
            assert_eq!(recovered.worker_id, "original-worker");
            assert_eq!(recovered.slots, 2);
            let (completed, _) = restored
                .complete_durable(
                    active.id,
                    "original-worker",
                    Some("recovery-owner"),
                    disk_budget_completion(0),
                )
                .unwrap()
                .unwrap();
            assert!(completed.worker_endpoint.is_none());
            assert_eq!(completed.slots, 2);
        }
    }

    #[tokio::test]
    async fn disk_fault_archive_is_durable_owner_validated_and_endpoint_scoped() {
        let root = TempDir::new().unwrap();
        let path = root.path().join("history.jsonl");
        let config = rch_common::WorkerConfig {
            id: WorkerId::new("disk-worker"),
            host: "admitted.example".into(),
            ..Default::default()
        };
        let worker = crate::workers::WorkerState::new(config.clone());
        let endpoint = worker.endpoint_snapshot().await;
        let history = BuildHistory::new(10).with_persistence(path.clone());
        let build = history
            .try_start_active_build_with_waiter(
                "failed-volume".into(),
                config.id.to_string(),
                "cargo test".into(),
                0,
                Some("disk-owner".into()),
                2,
                BuildLocation::Remote,
                None,
                DiskHeadroomAdmission::default(),
                Some(endpoint.clone()),
            )
            .unwrap()
            .unwrap();
        history
            .complete_durable_with_disk_fault(
                build.id,
                "disk-worker",
                Some("disk-owner"),
                disk_budget_completion(101),
                Some(vec!["/admitted-volume/rch".into()]),
            )
            .unwrap()
            .unwrap();
        let fault = history.pending_disk_fault(build.id).unwrap();
        assert!(fault.runtime_endpoint.is_some());
        assert!(
            history
                .has_pending_disk_fault_for_endpoint(&WorkerEndpointIdentity::from_config(&config))
        );
        assert!(
            history
                .try_start_active_build_with_waiter(
                    "same-endpoint".into(),
                    config.id.to_string(),
                    "cargo build".into(),
                    0,
                    None,
                    1,
                    BuildLocation::Remote,
                    None,
                    DiskHeadroomAdmission::default(),
                    Some(endpoint),
                )
                .unwrap()
                .is_none()
        );
        let replacement = crate::workers::WorkerState::new(rch_common::WorkerConfig {
            host: "replacement.example".into(),
            ..config
        });
        let replacement_endpoint = replacement.endpoint_snapshot().await;
        assert!(!history.has_pending_disk_fault_for_endpoint(
            &WorkerEndpointIdentity::from_config(&replacement_endpoint.config)
        ));
        assert!(
            history
                .try_start_active_build_with_waiter(
                    "different-endpoint".into(),
                    "disk-worker".into(),
                    "cargo build".into(),
                    0,
                    None,
                    1,
                    BuildLocation::Remote,
                    None,
                    DiskHeadroomAdmission::default(),
                    Some(replacement_endpoint),
                )
                .unwrap()
                .is_some(),
            "an absent endpoint's fault cannot fence a replacement ID"
        );

        assert_eq!(
            history
                .archive_disk_fault(build.id, "wrong-incident")
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert_eq!(history.pending_disk_fault(build.id), Some(fault.clone()));
        history
            .archive_disk_fault(build.id, &fault.incident_id)
            .unwrap();
        assert!(history.pending_disk_fault(build.id).is_none());
        assert_eq!(history.unapplied_disk_fault(build.id), Some(fault.clone()));
        let restored = BuildHistory::load_from_file(&path, 10).unwrap();
        let archived = restored.unapplied_disk_fault(build.id).unwrap();
        assert_eq!(archived, fault);
        assert!(archived.runtime_endpoint.is_none());
        assert!(restored.pending_disk_faults().is_empty());
        let snapshot: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path.with_extension("ownership.json")).unwrap())
                .unwrap();
        for corruption in [
            "mismatched_worker",
            "pending_and_archived",
            "wrong_incident",
        ] {
            let mut invalid = snapshot.clone();
            match corruption {
                "mismatched_worker" => {
                    invalid["completed"][0]["unapplied_disk_fault"]["worker_endpoint"]["id"] =
                        serde_json::json!("replacement-owner")
                }
                "pending_and_archived" => {
                    invalid["completed"][0]["pending_disk_fault"] =
                        invalid["completed"][0]["unapplied_disk_fault"].clone()
                }
                "wrong_incident" => {
                    invalid["completed"][0]["unapplied_disk_fault"]["incident_id"] =
                        serde_json::json!("new-unowned-incident")
                }
                _ => unreachable!(),
            }
            assert_recovery_rejects_without_rewriting(&path, &invalid);
        }
    }

    #[tokio::test]
    async fn disk_fault_first_terminal_commit_preserves_known_retarget_across_restart() {
        for change in ["aba", "retarget_removed", "removed", "active_restarted"] {
            let root = TempDir::new().unwrap();
            let path = root.path().join("history.jsonl");
            let store_path = root.path().join("bypasses.json");
            let original = rch_common::WorkerConfig {
                id: WorkerId::new("disk-worker"),
                host: "admitted.example".into(),
                total_slots: 8,
                ..Default::default()
            };
            let pool = crate::workers::WorkerPool::new();
            pool.add_worker(original.clone()).await;
            let worker = pool.get(&original.id).await.unwrap();
            let mut history = BuildHistory::new(10).with_persistence(path.clone());
            let build = history
                .try_start_active_build_with_waiter(
                    "late-disk-fault".into(),
                    original.id.to_string(),
                    "cargo build".into(),
                    0,
                    Some("disk-owner".into()),
                    2,
                    BuildLocation::Remote,
                    None,
                    DiskHeadroomAdmission::default(),
                    Some(worker.endpoint_snapshot().await),
                )
                .unwrap()
                .unwrap();
            if matches!(change, "aba" | "retarget_removed") {
                pool.add_worker(rch_common::WorkerConfig {
                    host: "replacement.example".into(),
                    ..original.clone()
                })
                .await;
                if change == "aba" {
                    pool.add_worker(original.clone()).await;
                }
            }
            if matches!(change, "removed" | "retarget_removed") {
                assert!(pool.remove_worker(&original.id).await);
            } else if change == "active_restarted" {
                history = BuildHistory::load_from_file(&path, 10).unwrap();
            }
            let (completed, record) = history
                .complete_durable_with_disk_fault(
                    build.id,
                    "disk-worker",
                    Some("disk-owner"),
                    disk_budget_completion(101),
                    Some(vec!["/admitted-volume/rch".into()]),
                )
                .unwrap()
                .unwrap();
            assert_eq!(completed.slots, 2);
            let known_retarget = matches!(change, "aba" | "retarget_removed");
            let evidence = if known_retarget {
                assert!(history.pending_disk_fault(build.id).is_none(), "{change}");
                history.unapplied_disk_fault(build.id).unwrap()
            } else {
                assert!(history.unapplied_disk_fault(build.id).is_none(), "{change}");
                history.pending_disk_fault(build.id).unwrap()
            };
            assert_eq!(
                evidence.incident_id,
                format!("build:{}:{}", build.id, record.completed_at)
            );
            assert_eq!(evidence.roots, ["/admitted-volume/rch"]);
            assert!(
                evidence
                    .worker_endpoint
                    .as_ref()
                    .unwrap()
                    .matches_config(&original)
            );

            // Stop at the actual first ownership commit: no bypass producer or
            // archive acknowledgment runs before reopening the durable file.
            drop(history);
            let restored = BuildHistory::load_from_file(&path, 10).unwrap();
            let worker = std::sync::Arc::new(crate::workers::WorkerState::new(original));
            assert!(worker.reserve_slots(1).await); // Unrelated surviving work.
            let store = std::sync::Arc::new(tokio::sync::Mutex::new(
                rch_common::BypassRecordStore::with_path(&store_path),
            ));
            let restored_evidence = if known_retarget {
                assert!(restored.pending_disk_faults().is_empty());
                restored.unapplied_disk_fault(build.id).unwrap()
            } else {
                restored.pending_disk_fault(build.id).unwrap()
            };
            assert_eq!(restored_evidence, evidence);
            assert!(restored_evidence.runtime_endpoint.is_none());
            crate::bypass_recovery_service::apply_owned_disk_fault(
                &store,
                Some(&worker),
                &restored,
                &restored_evidence,
            )
            .await
            .unwrap();
            assert_eq!(
                worker.used_slots(),
                1,
                "replay cannot release another build"
            );
            assert_eq!(
                worker.lifecycle().await.is_schedulable(),
                known_retarget,
                "{change}"
            );
            assert_eq!(
                rch_common::BypassRecordStore::load(&store_path).contains("disk-worker"),
                !known_retarget,
                "{change}"
            );
            if known_retarget {
                assert_eq!(restored.unapplied_disk_fault(build.id), Some(evidence));
            } else {
                assert!(restored.pending_disk_faults().is_empty());
                assert!(restored.unapplied_disk_fault(build.id).is_none());
            }
        }
    }

    #[test]
    fn recovery_rejects_duplicate_active_wrappers_across_projects_and_workers() {
        for version in [1, 2] {
            for worker in ["original-worker", "other-worker"] {
                let root = TempDir::new().unwrap();
                let path = root.path().join("history.jsonl");
                let (mut snapshot, original) = recovery_validation_fixture(&path, version);
                let mut duplicate = snapshot["active"][0].clone();
                duplicate["id"] = serde_json::json!(original.id + 1);
                duplicate["project_id"] = serde_json::json!("different-project");
                duplicate["worker_id"] = serde_json::json!(worker);
                snapshot["active"].as_array_mut().unwrap().push(duplicate);
                assert_recovery_rejects_without_rewriting(&path, &snapshot);
            }
        }
    }

    #[test]
    fn recovery_rejects_empty_and_cancelled_active_wrapper_identities() {
        for version in [1, 2] {
            for case in ["empty_active", "cancelled_active", "empty_cancellation"] {
                let root = TempDir::new().unwrap();
                let path = root.path().join("history.jsonl");
                let (mut snapshot, _) = recovery_validation_fixture(&path, version);
                match case {
                    "empty_active" => {
                        snapshot["active"][0]["local_wrapper_id"] = serde_json::json!("");
                    }
                    "cancelled_active" => {
                        snapshot["cancelled_wrappers"] = serde_json::json!(["recovery-owner"]);
                    }
                    _ => snapshot["cancelled_wrappers"] = serde_json::json!([""]),
                }
                assert_recovery_rejects_without_rewriting(&path, &snapshot);
            }
        }
    }

    #[test]
    fn recovery_rejects_terminal_ids_that_would_exhaust_the_active_namespace() {
        for version in [1, 2] {
            for id in [0, QUEUE_ID_NAMESPACE, u64::MAX] {
                let root = TempDir::new().unwrap();
                let path = root.path().join("history.jsonl");
                let (mut snapshot, _) = recovery_validation_fixture(&path, version);
                snapshot["completed"] =
                    serde_json::json!([recovery_validation_receipt(id, Some("completed-owner"))]);
                assert_recovery_rejects_without_rewriting(&path, &snapshot);
            }
        }
    }

    #[test]
    fn recovery_rejects_empty_terminal_wrapper_identities() {
        for version in [1, 2] {
            let root = TempDir::new().unwrap();
            let path = root.path().join("history.jsonl");
            let (mut snapshot, original) = recovery_validation_fixture(&path, version);
            snapshot["completed"] =
                serde_json::json!([recovery_validation_receipt(original.id - 1, Some(""))]);
            assert_recovery_rejects_without_rewriting(&path, &snapshot);
        }
    }

    #[test]
    fn recovery_preserves_sequential_failover_receipts_for_one_active_wrapper() {
        for version in [1, 2] {
            let root = TempDir::new().unwrap();
            let path = root.path().join("history.jsonl");
            let (mut snapshot, original) = recovery_validation_fixture(&path, version);
            let earlier_ids = [original.id - 2, original.id - 1];
            snapshot["completed"] = serde_json::json!(
                earlier_ids.map(|id| recovery_validation_receipt(id, Some("recovery-owner")))
            );
            std::fs::write(
                path.with_extension("ownership.json"),
                serde_json::to_vec(&snapshot).unwrap(),
            )
            .unwrap();
            // Repeat recovery: migration/rewrite must retain every attempt,
            // not mistake an older receipt for a second active admission.
            for _ in 0..2 {
                let recovered = BuildHistory::load_from_file(&path, 10).unwrap();
                assert_eq!(recovered.active_builds().len(), 1);
                let active = recovered.active_build(original.id).unwrap();
                assert!(active.recovered);
                assert_eq!(active.local_wrapper_id, original.local_wrapper_id);
                for id in earlier_ids {
                    assert!(recovered.terminal_build(id, "recovery-owner").is_some());
                }
                assert!(!recovered.wrapper_cancelled("recovery-owner"));
                assert!(recovered.next_id() > original.id);
            }
        }
    }

    #[test]
    fn recovery_does_not_guess_wrapper_identity_for_anonymous_active_builds() {
        for version in [1, 2] {
            let root = TempDir::new().unwrap();
            let path = root.path().join("history.jsonl");
            let (mut snapshot, original) = recovery_validation_fixture(&path, version);
            snapshot["active"][0]["local_wrapper_id"] = serde_json::Value::Null;
            let mut second = snapshot["active"][0].clone();
            second["id"] = serde_json::json!(original.id + 1);
            second["worker_id"] = serde_json::json!("another-worker");
            snapshot["active"].as_array_mut().unwrap().push(second);
            snapshot["completed"] =
                serde_json::json!([recovery_validation_receipt(original.id - 1, None)]);
            std::fs::write(
                path.with_extension("ownership.json"),
                serde_json::to_vec(&snapshot).unwrap(),
            )
            .unwrap();
            let recovered = BuildHistory::load_from_file(&path, 10).unwrap();
            assert_eq!(recovered.active_builds().len(), 2);
            assert!(
                recovered
                    .active_builds()
                    .iter()
                    .all(|state| { state.recovered && state.local_wrapper_id.is_none() })
            );
            assert!(recovered.has_terminal_build(original.id - 1));
        }
    }

    fn now_iso() -> String {
        let since_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        format!("2024-01-01T00:00:{}Z", since_epoch % 60)
    }

    fn make_build_record(id: u64) -> BuildRecord {
        BuildRecord {
            id,
            started_at: now_iso(),
            completed_at: now_iso(),
            project_id: "test-project".to_string(),
            worker_id: None,
            command: "cargo build".to_string(),
            exit_code: 0,
            duration_ms: 100,
            location: BuildLocation::Local,
            bytes_transferred: None,
            timing: None,
            cancellation: None,
        }
    }

    #[tokio::test]
    async fn active_build_survives_history_restart() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("history.jsonl");
        let history = BuildHistory::new(10).with_persistence(path.clone());
        // Ensure the persistence file exists through the normal completed
        // history path, so a missing file cannot mask loss of the active job.
        history
            .record(make_build_record(1))
            .expect("persistence task")
            .await
            .unwrap();
        let running = history.start_active_build_with_wrapper(
            "restart-project".to_string(),
            "worker-1".to_string(),
            "cargo check".to_string(),
            std::process::id(),
            Some("restart-wrapper".to_string()),
            2,
            BuildLocation::Remote,
        );
        drop(history);

        let recovered = BuildHistory::load_from_file(&path, 10).unwrap();
        assert!(
            recovered.active_build(running.id).is_some(),
            "restart lost active build {}; surviving work must remain tracked",
            running.id
        );
    }

    #[test]
    fn test_ring_buffer_capacity() {
        let _guard = test_guard!();
        let history = BuildHistory::new(3);

        for i in 1..=5 {
            history.record(make_build_record(i));
        }

        let recent = history.recent(10);
        assert_eq!(recent.len(), 3); // Capped at capacity
        assert_eq!(recent[0].id, 5); // Most recent first
        assert_eq!(recent[2].id, 3); // Oldest retained
    }

    #[test]
    fn test_recent_ordering() {
        let _guard = test_guard!();
        let history = BuildHistory::new(10);
        history.record(make_build_record(1));
        history.record(make_build_record(2));
        history.record(make_build_record(3));

        let recent = history.recent(2);
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].id, 3); // Most recent first
        assert_eq!(recent[1].id, 2);
    }

    #[test]
    fn test_by_worker_filter() {
        let _guard = test_guard!();
        let history = BuildHistory::new(10);

        let mut record1 = make_build_record(1);
        record1.worker_id = Some("worker-1".to_string());
        history.record(record1);

        let mut record2 = make_build_record(2);
        record2.worker_id = Some("worker-2".to_string());
        history.record(record2);

        let mut record3 = make_build_record(3);
        record3.worker_id = Some("worker-1".to_string());
        history.record(record3);

        let worker1_builds = history.by_worker("worker-1", 10);
        assert_eq!(worker1_builds.len(), 2);
        assert!(
            worker1_builds
                .iter()
                .all(|b| b.worker_id.as_deref() == Some("worker-1"))
        );
    }

    #[test]
    fn test_by_project_filter() {
        let _guard = test_guard!();
        let history = BuildHistory::new(10);

        let mut record1 = make_build_record(1);
        record1.project_id = "proj-a".to_string();
        history.record(record1);

        let mut record2 = make_build_record(2);
        record2.project_id = "proj-b".to_string();
        history.record(record2);

        let mut record3 = make_build_record(3);
        record3.project_id = "proj-a".to_string();
        history.record(record3);

        let proj_a_builds = history.by_project("proj-a", 10);
        assert_eq!(proj_a_builds.len(), 2);
        assert!(proj_a_builds.iter().all(|b| b.project_id == "proj-a"));
    }

    #[test]
    fn test_stats_calculation() {
        let _guard = test_guard!();
        let history = BuildHistory::new(10);

        // 2 successes, 1 failure, 2 remote, 1 local
        let mut record1 = make_build_record(1);
        record1.exit_code = 0;
        record1.location = BuildLocation::Remote;
        record1.duration_ms = 1000;
        history.record(record1);

        let mut record2 = make_build_record(2);
        record2.exit_code = 0;
        record2.location = BuildLocation::Remote;
        record2.duration_ms = 2000;
        history.record(record2);

        let mut record3 = make_build_record(3);
        record3.exit_code = 1;
        record3.location = BuildLocation::Local;
        record3.duration_ms = 500;
        history.record(record3);

        let stats = history.stats();
        assert_eq!(stats.total_builds, 3);
        assert_eq!(stats.success_count, 2);
        assert_eq!(stats.failure_count, 1);
        assert_eq!(stats.remote_count, 2);
        assert_eq!(stats.local_count, 1);
        assert_eq!(stats.avg_duration_ms, 1166); // (1000+2000+500)/3
    }

    #[test]
    fn test_stats_preserve_terminal_outcomes_across_command_kinds() {
        let _guard = test_guard!();
        let history = BuildHistory::new(10);

        // Exit 101 does not tell us whether compilation or assertions failed.
        let mut failing_test = make_build_record(1);
        failing_test.command =
            "env cargo test -p frankenterm-core some_test -- --nocapture".to_string();
        failing_test.exit_code = 101;
        history.record(failing_test);

        // A real build command that failed to compile — genuine build failure.
        let mut failing_build = make_build_record(2);
        failing_build.command = "cargo build --release".to_string();
        failing_build.exit_code = 1;
        history.record(failing_build);

        // A different nonzero test exit is also a failed command.
        let mut test_compile_error = make_build_record(3);
        test_compile_error.command = "cargo test --workspace".to_string();
        test_compile_error.exit_code = 1;
        history.record(test_compile_error);

        // A passing test command.
        let mut passing_test = make_build_record(4);
        passing_test.command = "cargo nextest run".to_string();
        passing_test.exit_code = 0;
        history.record(passing_test);

        let stats = history.stats();
        assert_eq!(stats.total_builds, 4);
        assert_eq!(
            stats.success_count, 1,
            "only a successful terminal command belongs in the success numerator"
        );
        assert_eq!(stats.failure_count, 3);
    }

    #[test]
    fn test_stats_never_promote_nonzero_exits_to_success() {
        let _guard = test_guard!();
        for command in [
            "cargo test",
            "cargo bench",
            "cargo nextest run",
            "bun test",
            "cargo build",
            "cargo check",
            "env cargo test --workspace",
        ] {
            let history = BuildHistory::new(256);
            for exit_code in 0..=255 {
                let mut record = make_build_record(exit_code as u64);
                record.command = command.to_string();
                record.exit_code = exit_code;
                history.record(record);
            }
            let stats = history.stats();
            assert_eq!(stats.total_builds, 256, "{command}");
            assert_eq!(stats.success_count, 1, "{command}");
            assert_eq!(stats.failure_count, 255, "{command}");
            assert_eq!(history.recent(1)[0].exit_code, 255);
        }
    }

    #[test]
    fn test_empty_history() {
        let _guard = test_guard!();
        let history = BuildHistory::new(10);

        assert!(history.recent(10).is_empty());
        assert!(history.by_worker("any", 10).is_empty());

        let stats = history.stats();
        assert_eq!(stats.total_builds, 0);
        assert_eq!(stats.avg_duration_ms, 0);
    }

    #[test]
    fn test_next_id() {
        let _guard = test_guard!();
        let history = BuildHistory::new(10);

        // IDs use a timestamp-based epoch, so we verify monotonic sequence
        // rather than exact values.
        let id1 = history.next_id();
        let id2 = history.next_id();
        let id3 = history.next_id();
        assert!(id1 > 0, "first ID should be positive");
        assert_eq!(id2, id1 + 1, "IDs should be sequential");
        assert_eq!(id3, id2 + 1, "IDs should be sequential");
    }

    #[test]
    fn test_try_start_active_build_blocks_same_project_on_same_worker() {
        let _guard = test_guard!();
        let history = BuildHistory::new(10);

        let first = history.try_start_active_build(
            "proj-a".to_string(),
            "worker-1".to_string(),
            "cargo test".to_string(),
            1111,
            2,
            BuildLocation::Remote,
        );
        assert!(first.is_some(), "first active build should be registered");

        let second = history.try_start_active_build(
            "proj-a".to_string(),
            "worker-1".to_string(),
            "cargo test".to_string(),
            2222,
            2,
            BuildLocation::Remote,
        );
        assert!(
            second.is_none(),
            "same project on same worker must be rejected"
        );

        let different_worker = history.try_start_active_build(
            "proj-a".to_string(),
            "worker-2".to_string(),
            "cargo test".to_string(),
            3333,
            2,
            BuildLocation::Remote,
        );
        assert!(
            different_worker.is_some(),
            "same project on a different worker should still be allowed"
        );

        let different_project = history.try_start_active_build(
            "proj-b".to_string(),
            "worker-1".to_string(),
            "cargo test".to_string(),
            4444,
            2,
            BuildLocation::Remote,
        );
        assert!(
            different_project.is_some(),
            "different project on the same worker should still be allowed"
        );
    }

    #[test]
    fn test_active_workers_for_project_tracks_current_workers() {
        let _guard = test_guard!();
        let history = BuildHistory::new(10);

        history.start_active_build(
            "proj-a".to_string(),
            "worker-1".to_string(),
            "cargo build".to_string(),
            1111,
            2,
            BuildLocation::Remote,
        );
        history.start_active_build(
            "proj-a".to_string(),
            "worker-2".to_string(),
            "cargo build".to_string(),
            2222,
            2,
            BuildLocation::Remote,
        );
        history.start_active_build(
            "proj-b".to_string(),
            "worker-3".to_string(),
            "cargo build".to_string(),
            3333,
            2,
            BuildLocation::Remote,
        );

        let active_workers = history.active_workers_for_project("proj-a");
        assert_eq!(active_workers.len(), 2);
        assert!(active_workers.contains("worker-1"));
        assert!(active_workers.contains("worker-2"));
        assert!(!active_workers.contains("worker-3"));
    }

    #[test]
    fn test_cancel_active_build_records_cancellation_metadata() {
        let _guard = test_guard!();
        let history = BuildHistory::new(10);
        let active = history.start_active_build(
            "proj".to_string(),
            "worker-a".to_string(),
            "cargo test".to_string(),
            0,
            4,
            BuildLocation::Remote,
        );

        let metadata = BuildCancellationMetadata {
            operation_id: "cancel-1".to_string(),
            origin: "timeout".to_string(),
            reason_code: "timeout".to_string(),
            decision_path: vec![
                "requested".to_string(),
                "term_sent".to_string(),
                "remote_kill_sent".to_string(),
                "completed".to_string(),
            ],
            escalation_stage: "remote_kill".to_string(),
            escalation_count: 1,
            remote_kill_attempted: true,
            cleanup_ok: true,
            history_cancelled: true,
            final_state: "completed".to_string(),
            worker_health: Some(rch_common::BuildCancellationWorkerHealth {
                status: "healthy".to_string(),
                speed_score: 91.2,
                used_slots: 0,
                available_slots: 8,
                pressure_state: "healthy".to_string(),
                pressure_reason_code: "healthy".to_string(),
            }),
        };

        let cancelled = history
            .cancel_active_build(active.id, None, Some(metadata.clone()))
            .expect("cancelled build record");
        assert_eq!(cancelled.exit_code, 130);
        assert_eq!(
            cancelled
                .cancellation
                .as_ref()
                .expect("cancellation metadata")
                .operation_id,
            metadata.operation_id
        );
        assert!(history.active_build(active.id).is_none());

        let recent = history.recent(1);
        assert_eq!(recent.len(), 1);
        assert_eq!(
            recent[0]
                .cancellation
                .as_ref()
                .expect("persisted cancellation metadata")
                .escalation_stage,
            "remote_kill"
        );
    }

    #[test]
    fn test_record_build_heartbeat_updates_progress_metadata() {
        let _guard = test_guard!();
        let history = BuildHistory::new(10);
        let build = history.start_active_build(
            "proj".to_string(),
            "worker-a".to_string(),
            "cargo build".to_string(),
            1234,
            4,
            BuildLocation::Remote,
        );
        let initial_progress_at = build.last_progress_at.clone();

        let updated = history
            .record_build_heartbeat(BuildHeartbeatRequest {
                build_id: build.id,
                worker_id: rch_common::WorkerId::new("worker-a"),
                hook_pid: Some(1234),
                local_wrapper_id: Some("rchw-test".to_string()),
                remote_pgid_file: Some("/tmp/rch/proj/hash/.rch-run/1.pgid".to_string()),
                phase: BuildHeartbeatPhase::Execute,
                detail: Some("Compiling".to_string()),
                progress_counter: Some(3),
                progress_percent: Some(25.0),
            })
            .expect("active build should be updated");

        assert_eq!(updated.heartbeat_phase, BuildHeartbeatPhase::Execute);
        assert_eq!(updated.heartbeat_counter, 3);
        assert_eq!(updated.heartbeat_percent, Some(25.0));
        assert_eq!(updated.heartbeat_count, 1);
        assert_eq!(
            updated.remote_pgid_file.as_deref(),
            Some("/tmp/rch/proj/hash/.rch-run/1.pgid")
        );
        assert_ne!(updated.last_progress_at, initial_progress_at);
    }

    #[test]
    fn heartbeat_progress_is_durable_on_identity_phase_or_interval_only() {
        let _guard = test_guard!();
        let root = TempDir::new().unwrap();
        let path = root.path().join("history.jsonl");
        std::fs::write(&path, b"").unwrap();
        let history = BuildHistory::new(10).with_persistence(path.clone());
        let build = history.start_active_build(
            "proj".to_string(),
            "worker-a".to_string(),
            "cargo build".to_string(),
            1234,
            4,
            BuildLocation::Remote,
        );
        let ownership = path.with_extension("ownership.json");
        let beat = |counter, phase| BuildHeartbeatRequest {
            build_id: build.id,
            worker_id: rch_common::WorkerId::new("worker-a"),
            hook_pid: Some(1234),
            local_wrapper_id: None,
            remote_pgid_file: None,
            phase,
            detail: None,
            progress_counter: Some(counter),
            progress_percent: None,
        };

        history
            .record_build_heartbeat(beat(1, BuildHeartbeatPhase::Execute))
            .unwrap();
        let first = std::fs::read(&ownership).unwrap();
        history
            .record_build_heartbeat(beat(2, BuildHeartbeatPhase::Execute))
            .unwrap();
        assert_eq!(
            std::fs::read(&ownership).unwrap(),
            first,
            "progress-only beat was fsynced"
        );
        assert_eq!(history.active_build(build.id).unwrap().heartbeat_counter, 2);

        history
            .record_build_heartbeat(beat(3, BuildHeartbeatPhase::SyncDown))
            .unwrap();
        assert_ne!(
            std::fs::read(&ownership).unwrap(),
            first,
            "phase change must be durable"
        );
    }

    #[test]
    fn terminal_receipts_are_bounded_by_age_then_count() {
        let receipt = |id: u64, completed: DateTime<Utc>| {
            let mut record = make_build_record(id);
            record.completed_at = completed.to_rfc3339();
            (
                id,
                TerminalOwnership {
                    record,
                    local_wrapper_id: None,
                    pending_disk_fault: None,
                    unapplied_disk_fault: None,
                },
            )
        };
        let now = Utc::now();
        let mut terminal: HashMap<_, _> = (1..=MAX_TERMINAL_RECEIPTS as u64 + 10)
            .map(|id| receipt(id, now - ChronoDuration::seconds(id as i64)))
            .collect();
        terminal.extend([receipt(9_999, now - ChronoDuration::days(4))]);
        prune_terminal_receipts(&mut terminal, now);
        assert_eq!(terminal.len(), MAX_TERMINAL_RECEIPTS);
        assert!(!terminal.contains_key(&9_999), "expired receipt kept");
        assert!(terminal.contains_key(&1), "newest receipt dropped");
        assert!(
            !terminal.contains_key(&(MAX_TERMINAL_RECEIPTS as u64 + 10)),
            "oldest kept"
        );
    }

    #[tokio::test]
    async fn disk_fault_intent_is_owned_durable_and_cannot_be_replaced_by_a_retry() {
        let temporary = TempDir::new().unwrap();
        let path = temporary.path().join("history.jsonl");
        let history = BuildHistory::new(10).with_persistence(path.clone());
        let build = history.start_active_build_with_wrapper(
            "project".into(),
            "worker".into(),
            "cargo build".into(),
            12345,
            Some("owner".into()),
            2,
            BuildLocation::Remote,
        );
        let completion = || BuildCompletion {
            exit_code: 101,
            duration_ms: Some(10),
            bytes_transferred: None,
            timing: None,
            cancellation: None,
        };
        for (worker, wrapper, roots) in [
            ("other-worker", "owner", vec!["/build-volume/rch".into()]),
            ("worker", "other-owner", vec!["/build-volume/rch".into()]),
            ("worker", "owner", vec!["../relative".into()]),
        ] {
            assert!(
                history
                    .complete_durable_with_disk_fault(
                        build.id,
                        worker,
                        Some(wrapper),
                        completion(),
                        Some(roots),
                    )
                    .is_err()
            );
            assert!(history.active_build(build.id).is_some());
            assert!(!history.has_pending_disk_fault("worker"));
        }
        history
            .complete_durable_with_disk_fault(
                build.id,
                "worker",
                Some("owner"),
                completion(),
                Some(vec!["/build-volume/rch".into(), "/build-volume/rch".into()]),
            )
            .unwrap()
            .unwrap();
        let fault = history.pending_disk_fault(build.id).unwrap();
        assert_eq!(fault.roots, ["/build-volume/rch"]);
        let restored = BuildHistory::load_from_file(&path, 10).unwrap();
        assert!(restored.active_build(build.id).is_none());
        assert_eq!(restored.pending_disk_fault(build.id), Some(fault.clone()));
        assert!(
            restored
                .complete_durable_with_disk_fault(
                    build.id,
                    "worker",
                    Some("owner"),
                    completion(),
                    Some(vec!["../untrusted-retry".into()]),
                )
                .unwrap()
                .is_none()
        );
        assert_eq!(restored.pending_disk_fault(build.id), Some(fault.clone()));
        assert!(
            restored
                .acknowledge_disk_fault(build.id, "wrong-incident")
                .is_err()
        );
        restored
            .acknowledge_disk_fault(build.id, &fault.incident_id)
            .unwrap();
        restored
            .acknowledge_disk_fault(build.id, &fault.incident_id)
            .unwrap();
        let acknowledged = BuildHistory::load_from_file(&path, 10).unwrap();
        assert!(acknowledged.pending_disk_faults().is_empty());
        assert!(acknowledged.has_terminal_build(build.id));
    }

    #[tokio::test]
    async fn disk_fault_pending_receipt_survives_retention_and_uncertain_acknowledgment() {
        let temporary = TempDir::new().unwrap();
        let path = temporary.path().join("history.jsonl");
        let history = BuildHistory::new(10).with_persistence(path.clone());
        let build = history.start_active_build_with_wrapper(
            "project".into(),
            "worker".into(),
            "gcc main.c".into(),
            12345,
            Some("owner".into()),
            1,
            BuildLocation::Remote,
        );
        history
            .complete_durable_with_disk_fault(
                build.id,
                "worker",
                Some("owner"),
                BuildCompletion {
                    exit_code: 1,
                    duration_ms: None,
                    bytes_transferred: None,
                    timing: None,
                    cancellation: None,
                },
                Some(vec!["/build-volume/rch".into()]),
            )
            .unwrap();
        // A fault that was never delivered cannot expire as routine history.
        {
            let mut terminal = history.terminal.write().unwrap();
            prune_terminal_receipts(&mut terminal, Utc::now() + ChronoDuration::days(4));
            assert!(terminal.contains_key(&build.id));
        }
        let fault = history.pending_disk_fault(build.id).unwrap();
        history
            .fail_after_ownership_rename
            .store(true, Ordering::SeqCst);
        assert!(
            history
                .acknowledge_disk_fault(build.id, &fault.incident_id)
                .is_err()
        );
        assert!(history.ownership_failed());
        assert!(history.has_pending_disk_fault("worker"));
        // The renamed file may have committed. Only a restart resolves that
        // uncertainty; it must not resurrect an active owner or duplicate ID.
        let restored = BuildHistory::load_from_file(&path, 10).unwrap();
        assert!(!restored.has_pending_disk_fault("worker"));
        assert!(restored.has_terminal_build(build.id));
        assert!(restored.active_builds().is_empty());
    }

    #[tokio::test]
    async fn disk_fault_pending_intent_fences_transient_healthy_admission_until_acknowledged() {
        let temporary = TempDir::new().unwrap();
        let path = temporary.path().join("history.jsonl");
        let history = BuildHistory::new(10).with_persistence(path.clone());
        let failed = history.start_active_build_with_wrapper(
            "failed-project".into(),
            "worker".into(),
            "cargo build".into(),
            12345,
            Some("failed-owner".into()),
            2,
            BuildLocation::Remote,
        );
        let running = history.start_active_build_with_wrapper(
            "running-project".into(),
            "worker".into(),
            "cargo build".into(),
            12346,
            Some("running-owner".into()),
            7,
            BuildLocation::Remote,
        );
        history
            .complete_durable_with_disk_fault(
                failed.id,
                "worker",
                Some("failed-owner"),
                BuildCompletion {
                    exit_code: 101,
                    duration_ms: None,
                    bytes_transferred: None,
                    timing: None,
                    cancellation: None,
                },
                Some(vec!["/build-volume/rch".into()]),
            )
            .unwrap()
            .unwrap();
        let fault = history.pending_disk_fault(failed.id).unwrap();
        let durable_before = std::fs::read(path.with_extension("ownership.json")).unwrap();
        let attempt = |history: &BuildHistory| {
            history.try_start_active_build_with_wrapper(
                "new-project".into(),
                "worker".into(),
                "cargo build".into(),
                12347,
                Some("new-owner".into()),
                4,
                BuildLocation::Remote,
            )
        };
        // This is the race's exact admission boundary: a stale healthy
        // selection reaches history while the completed fault is waiting for
        // the bypass-store lock. No lifecycle flag is trusted by this fence.
        assert!(attempt(&history).unwrap().is_none());
        let held = history.active_builds();
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].id, running.id);
        assert_eq!(held[0].slots, 7, "another build's reservation stays owned");
        assert_eq!(
            std::fs::read(path.with_extension("ownership.json")).unwrap(),
            durable_before
        );
        assert_eq!(history.pending_disk_fault(failed.id), Some(fault.clone()));

        let restored = BuildHistory::load_from_file(&path, 10).unwrap();
        assert!(
            attempt(&restored).unwrap().is_none(),
            "restart preserves the admission fence"
        );
        restored
            .acknowledge_disk_fault(failed.id, &fault.incident_id)
            .unwrap();
        let admitted = attempt(&restored).unwrap().unwrap();
        assert_eq!(admitted.local_wrapper_id.as_deref(), Some("new-owner"));
        assert_eq!(restored.active_build(running.id).unwrap().slots, 7);
        assert_eq!(restored.active_builds().len(), 2);
    }

    #[test]
    fn test_record_build_heartbeat_rejects_worker_mismatch() {
        let _guard = test_guard!();
        let history = BuildHistory::new(10);
        let build = history.start_active_build(
            "proj".to_string(),
            "worker-a".to_string(),
            "cargo check".to_string(),
            9999,
            2,
            BuildLocation::Remote,
        );

        let updated = history.record_build_heartbeat(BuildHeartbeatRequest {
            build_id: build.id,
            worker_id: rch_common::WorkerId::new("worker-b"),
            hook_pid: Some(9999),
            local_wrapper_id: None,
            remote_pgid_file: None,
            phase: BuildHeartbeatPhase::Execute,
            detail: Some("Unexpected".to_string()),
            progress_counter: Some(1),
            progress_percent: Some(10.0),
        });
        assert!(
            updated.is_none(),
            "mismatched worker heartbeat must be ignored"
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    mod heartbeat_identity {
        use super::*;

        struct OwnedWrapper(std::process::Child);

        impl OwnedWrapper {
            fn start() -> Self {
                Self(
                    std::process::Command::new("/bin/sleep")
                        .arg("60")
                        .spawn()
                        .unwrap(),
                )
            }

            fn assert_running(&mut self) {
                assert!(self.0.try_wait().unwrap().is_none());
            }
        }

        impl Drop for OwnedWrapper {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        fn register(history: &BuildHistory, pid: u32) -> ActiveBuildState {
            history.start_active_build_with_wrapper(
                "heartbeat-owner-project".to_owned(),
                "heartbeat-owner-worker".to_owned(),
                "controlled heartbeat fixture".to_owned(),
                pid,
                Some("exact-heartbeat-wrapper".to_owned()),
                2,
                BuildLocation::Remote,
            )
        }

        fn heartbeat(build: &ActiveBuildState, pid: Option<u32>) -> BuildHeartbeatRequest {
            BuildHeartbeatRequest {
                build_id: build.id,
                worker_id: rch_common::WorkerId::new(&build.worker_id),
                hook_pid: pid,
                local_wrapper_id: build.local_wrapper_id.clone(),
                remote_pgid_file: Some("/tmp/rch/heartbeat-owner/.rch-run/owned.pgid".to_owned()),
                phase: BuildHeartbeatPhase::Execute,
                detail: Some("owned wrapper making progress".to_owned()),
                progress_counter: Some(3),
                progress_percent: Some(25.0),
            }
        }

        fn persistent_history(root: &TempDir) -> (BuildHistory, PathBuf) {
            let path = root.path().join("history.jsonl");
            std::fs::write(&path, b"").unwrap();
            (BuildHistory::new(10).with_persistence(path.clone()), path)
        }

        fn persist_process_identity(
            history: &BuildHistory,
            build_id: u64,
            identity: Option<String>,
        ) {
            let mut active = history.active.write().unwrap();
            active.get_mut(&build_id).unwrap().hook_process_identity = identity;
            history.persist_ownership(&active, None).unwrap();
        }

        fn assert_unchanged(history: &BuildHistory, before: &ActiveBuildState) {
            let after = history.active_build(before.id).unwrap();
            assert_eq!(
                serde_json::to_value(&after).unwrap(),
                serde_json::to_value(before).unwrap()
            );
            assert_eq!(after.started_at_mono, before.started_at_mono);
            assert_eq!(after.last_heartbeat_mono, before.last_heartbeat_mono);
            assert_eq!(after.last_progress_mono, before.last_progress_mono);
        }

        #[test]
        fn live_heartbeat_preserves_established_process_identity() {
            let mut owner = OwnedWrapper::start();
            let history = BuildHistory::new(10);
            let build = register(&history, owner.0.id());
            let identity = process_identity(owner.0.id()).unwrap();
            assert_eq!(
                build.hook_process_identity.as_deref(),
                Some(identity.as_str())
            );

            let updated = history
                .record_build_heartbeat(heartbeat(&build, Some(owner.0.id())))
                .unwrap();
            assert_eq!(updated.hook_process_identity, Some(identity));
            assert_eq!(updated.hook_pid, build.hook_pid);
            assert_eq!(updated.local_wrapper_id, build.local_wrapper_id);
            assert_eq!(updated.heartbeat_counter, 3);
            assert_eq!(updated.heartbeat_count, 1);
            assert_eq!(updated.heartbeat_phase, BuildHeartbeatPhase::Execute);
            owner.assert_running();
        }

        #[test]
        fn heartbeat_cannot_replace_wrapper_pid_even_with_exact_wrapper_id() {
            let mut owner = OwnedWrapper::start();
            let mut unrelated = OwnedWrapper::start();
            let root = TempDir::new().unwrap();
            let (history, path) = persistent_history(&root);
            let build = register(&history, owner.0.id());
            let journal = std::fs::read(path.with_extension("ownership.json")).unwrap();

            assert!(
                history
                    .record_build_heartbeat(heartbeat(&build, Some(unrelated.0.id())))
                    .is_none()
            );
            assert_unchanged(&history, &build);
            assert_eq!(
                std::fs::read(path.with_extension("ownership.json")).unwrap(),
                journal
            );
            owner.assert_running();
            unrelated.assert_running();
        }

        #[test]
        fn delayed_recovered_heartbeat_rejects_modelled_pid_reuse_without_adoption() {
            let mut unrelated = OwnedWrapper::start();
            let actual = process_identity(unrelated.0.id()).unwrap();
            use rch_common::process_identity::{ProcessIdentity, ProcessStart};
            let mut prior = ProcessIdentity::from_record(&actual).unwrap();
            match &mut prior.start {
                ProcessStart::Linux { ticks } => *ticks = if *ticks > 0 { *ticks - 1 } else { 1 },
                ProcessStart::Darwin { microseconds, .. } => {
                    *microseconds = (*microseconds + 1) % 1_000_000;
                }
            }
            let prior_identity = prior.to_record().unwrap();
            assert_ne!(prior_identity, actual);

            let root = TempDir::new().unwrap();
            let (history, path) = persistent_history(&root);
            let build = register(&history, unrelated.0.id());
            // Model PID reuse by recording the prior owner's distinct start
            // marker (only microseconds on Darwin). The current occupant is live;
            // this test does not claim to force operating-system PID reuse.
            persist_process_identity(&history, build.id, Some(prior_identity));
            drop(history);
            let recovered = BuildHistory::load_from_file(&path, 10).unwrap();
            let before = recovered.active_build(build.id).unwrap();
            assert!(before.recovered);
            let journal = std::fs::read(path.with_extension("ownership.json")).unwrap();

            for pid in [Some(unrelated.0.id()), None] {
                assert!(
                    recovered
                        .record_build_heartbeat(heartbeat(&before, pid))
                        .is_none(),
                    "a delayed heartbeat must not authorize the current PID occupant"
                );
                assert_unchanged(&recovered, &before);
                assert_eq!(
                    std::fs::read(path.with_extension("ownership.json")).unwrap(),
                    journal
                );
            }
            assert_eq!(process_identity(unrelated.0.id()).unwrap(), actual);
            unrelated.assert_running();
        }

        #[test]
        fn recovered_heartbeat_accepts_matching_live_process_without_rebinding() {
            let mut owner = OwnedWrapper::start();
            let root = TempDir::new().unwrap();
            let (history, path) = persistent_history(&root);
            let build = register(&history, owner.0.id());
            assert!(build.hook_process_identity.is_some());
            drop(history);
            let recovered = BuildHistory::load_from_file(&path, 10).unwrap();
            assert!(recovered.active_build(build.id).unwrap().recovered);

            let updated = recovered
                .record_build_heartbeat(heartbeat(&build, Some(owner.0.id())))
                .unwrap();
            assert_eq!(updated.hook_process_identity, build.hook_process_identity);
            assert_eq!(updated.hook_pid, build.hook_pid);
            assert_eq!(updated.local_wrapper_id, build.local_wrapper_id);
            assert!(updated.recovered);
            assert_eq!(updated.heartbeat_count, 1);
            drop(recovered);

            let reopened = BuildHistory::load_from_file(&path, 10).unwrap();
            let persisted = reopened.active_build(build.id).unwrap();
            assert_eq!(persisted.hook_process_identity, build.hook_process_identity);
            assert_eq!(persisted.heartbeat_count, 1);
            assert_eq!(persisted.heartbeat_counter, 3);
            owner.assert_running();
        }

        #[test]
        fn heartbeat_never_captures_identity_for_preexisting_unverified_pid() {
            let mut unrelated = OwnedWrapper::start();
            let history = BuildHistory::new(10);
            let build = register(&history, unrelated.0.id());
            persist_process_identity(&history, build.id, None);
            let before = history.active_build(build.id).unwrap();
            assert!(!before.recovered);

            let _ = history.record_build_heartbeat(heartbeat(&before, Some(unrelated.0.id())));
            let after = history.active_build(build.id).unwrap();
            assert!(after.hook_process_identity.is_none());
            assert_eq!(after.hook_pid, before.hook_pid);
            assert!(!after.recovered);
            unrelated.assert_running();
        }

        #[test]
        fn recovered_heartbeat_refuses_missing_process_identity() {
            let mut unrelated = OwnedWrapper::start();
            let root = TempDir::new().unwrap();
            let (history, path) = persistent_history(&root);
            let build = register(&history, unrelated.0.id());
            persist_process_identity(&history, build.id, None);
            drop(history);
            let recovered = BuildHistory::load_from_file(&path, 10).unwrap();
            let before = recovered.active_build(build.id).unwrap();
            assert!(before.recovered);
            let journal = std::fs::read(path.with_extension("ownership.json")).unwrap();

            assert!(
                recovered
                    .record_build_heartbeat(heartbeat(&before, Some(unrelated.0.id())))
                    .is_none()
            );
            assert_unchanged(&recovered, &before);
            assert_eq!(
                std::fs::read(path.with_extension("ownership.json")).unwrap(),
                journal
            );
            unrelated.assert_running();
        }
    }

    #[test]
    fn test_record_stuck_detector_snapshot_updates_active_build() {
        let _guard = test_guard!();
        let history = BuildHistory::new(10);
        let build = history.start_active_build(
            "proj".to_string(),
            "worker-a".to_string(),
            "cargo test".to_string(),
            4321,
            6,
            BuildLocation::Remote,
        );

        let updated = history
            .record_stuck_detector_snapshot(
                build.id,
                StuckDetectorSnapshot {
                    hook_alive: false,
                    heartbeat_stale: true,
                    progress_stale: true,
                    confidence: 0.91,
                    build_age_secs: 140,
                    slots_owned: 6,
                },
            )
            .expect("active build should exist");

        assert!(!updated.detector_hook_alive);
        assert!(updated.detector_heartbeat_stale);
        assert!(updated.detector_progress_stale);
        assert_eq!(updated.detector_confidence, 0.91);
        assert_eq!(updated.detector_build_age_secs, 140);
        assert_eq!(updated.detector_slots_owned, 6);
        assert!(updated.detector_last_evaluated_at.is_some());
    }

    #[tokio::test]
    async fn test_thread_safety() {
        use std::sync::Arc;

        let history = Arc::new(BuildHistory::new(100));

        let handles: Vec<_> = (0..10)
            .map(|i| {
                let h = Arc::clone(&history);
                tokio::spawn(async move {
                    for j in 0..10 {
                        h.record(make_build_record((i * 10 + j) as u64));
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.await.unwrap();
        }

        let recent = history.recent(200);
        assert_eq!(recent.len(), 100); // All 100 recorded
    }

    #[tokio::test]
    async fn test_persisted_stats_do_not_invent_compilation_success() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("history.jsonl");
        let history = BuildHistory::new(10).with_persistence(path.clone());
        let exits = [0, 1, 101, 130, 137, 143];
        for (id, exit_code) in exits.into_iter().enumerate() {
            let mut record = make_build_record(id as u64);
            record.command = "cargo test".to_string();
            record.exit_code = exit_code;
            if let Some(handle) = history.record(record) {
                handle.await.unwrap();
            }
        }
        let loaded = BuildHistory::load_from_file(&path, 10).unwrap();
        for stats in [history.stats(), loaded.stats()] {
            assert_eq!(stats.total_builds, exits.len());
            assert_eq!(stats.success_count, 1);
            assert_eq!(stats.failure_count, exits.len() - 1);
        }
        let persisted_exits: Vec<_> = loaded
            .recent(10)
            .iter()
            .rev()
            .map(|record| record.exit_code)
            .collect();
        assert_eq!(persisted_exits, exits);
    }

    #[tokio::test]
    async fn test_persistence_save_load() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("history.jsonl");

        // Create and populate history
        let history = BuildHistory::new(5).with_persistence(path.clone());
        for i in 1..=3 {
            if let Some(handle) = history.record(make_build_record(i)) {
                handle.await.unwrap();
            }
        }

        // Load into new instance
        let loaded = BuildHistory::load_from_file(&path, 5).unwrap();
        let recent = loaded.recent(10);

        assert_eq!(recent.len(), 3);
        assert_eq!(recent[0].id, 3);
    }

    /// A torn append (disk full / crash mid multi-byte char) must cost one
    /// record, not the daemon's ability to start.
    #[tokio::test]
    async fn test_load_skips_non_utf8_line_instead_of_failing() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("history.jsonl");
        let history = BuildHistory::new(5).with_persistence(path.clone());
        if let Some(handle) = history.record(make_build_record(1)) {
            handle.await.unwrap();
        }
        let mut bytes = std::fs::read(&path).unwrap();
        bytes.extend_from_slice(b"{\"id\":2,\"command\":\"cargo build \xE2\x82\n");
        std::fs::write(&path, &bytes).unwrap();
        let history = BuildHistory::new(5).with_persistence(path.clone());
        if let Some(handle) = history.record(make_build_record(3)) {
            handle.await.unwrap();
        }

        let loaded = BuildHistory::load_from_file(&path, 5).unwrap();
        let ids: Vec<u64> = loaded.recent(10).iter().map(|record| record.id).collect();
        assert_eq!(ids, vec![3, 1]);
    }

    #[tokio::test]
    async fn test_persistence_append_mode() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("history.jsonl");

        // First session
        {
            let history = BuildHistory::new(10).with_persistence(path.clone());
            if let Some(handle) = history.record(make_build_record(1)) {
                handle.await.unwrap();
            }
            if let Some(handle) = history.record(make_build_record(2)) {
                handle.await.unwrap();
            }
        }

        // Second session - load and add more
        {
            let history = BuildHistory::load_from_file(&path, 10).unwrap();
            // Use next_id to ensure we don't duplicate IDs
            let id = history.next_id();
            if let Some(handle) = history.record(make_build_record(id)) {
                handle.await.unwrap();
            }
        }

        // Third session - verify all records
        let history = BuildHistory::load_from_file(&path, 10).unwrap();
        assert_eq!(history.len(), 3);
    }

    #[tokio::test]
    async fn test_compaction() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("history.jsonl");

        // Create history with 3 records but capacity 2
        let history = BuildHistory::new(2).with_persistence(path.clone());
        for i in 1..=3 {
            if let Some(handle) = history.record(make_build_record(i)) {
                handle.await.unwrap();
            }
        }

        // Compact
        history.compact().unwrap();

        // Verify file only has 2 records
        let loaded = BuildHistory::load_from_file(&path, 10).unwrap();
        assert_eq!(loaded.len(), 2);
    }

    #[test]
    fn test_clear() {
        let _guard = test_guard!();
        let history = BuildHistory::new(10);
        history.record(make_build_record(1));
        history.record(make_build_record(2));

        assert_eq!(history.len(), 2);

        history.clear();

        assert_eq!(history.len(), 0);
        assert!(history.is_empty());
    }

    // =========================================================================
    // Queue Tests
    // =========================================================================

    fn complete_retry_attempt(history: &BuildHistory, worker: &str, wrapper: &str) -> BuildRecord {
        let attempt = history
            .try_start_active_build_with_wrapper(
                "retry-project".into(),
                worker.into(),
                "cargo build".into(),
                0,
                Some(wrapper.into()),
                2,
                BuildLocation::Remote,
            )
            .unwrap()
            .unwrap();
        history
            .complete_durable(
                attempt.id,
                worker,
                Some(wrapper),
                BuildCompletion {
                    exit_code: 137,
                    duration_ms: Some(17),
                    bytes_transferred: Some(23),
                    timing: None,
                    cancellation: None,
                },
            )
            .unwrap()
            .unwrap()
            .1
    }

    #[tokio::test]
    async fn retry_cancellation_fences_delayed_admission_without_releasing_other_ownership() {
        let root = TempDir::new().unwrap();
        let path = root.path().join("history.jsonl");
        let history = BuildHistory::new(10).with_persistence(path.clone());
        let first = complete_retry_attempt(&history, "worker-a", "retrying");
        let latest = complete_retry_attempt(&history, "worker-b", "retrying");
        let other = disk_budget_admit(&history, "other", "worker-b", 40, 100.0).unwrap();
        let queued = history
            .enqueue_build(
                "queued".into(),
                "build".into(),
                0,
                1,
                Some("queued-owner".into()),
            )
            .unwrap();
        let WrapperCancellation::Completed(cancelled) = history.cancel_wrapper("retrying").unwrap()
        else {
            panic!("a completed wrapper must retain its exact terminal receipt");
        };
        assert_eq!(
            serde_json::to_value(&*cancelled).unwrap(),
            serde_json::to_value(&latest).unwrap()
        );
        assert!(history.wrapper_cancelled("retrying"));
        assert_eq!(history.reserved_disk_headroom_gib("worker-b"), 40);
        assert_eq!(history.active_build(other.id).unwrap().slots, 1);
        assert_eq!(history.queued_builds()[0].id, queued.id);
        assert!(history.terminal_build(first.id, "retrying").is_some());
        let durable = std::fs::read(path.with_extension("ownership.json")).unwrap();
        assert!(
            matches!(history.cancel_wrapper("retrying").unwrap(), WrapperCancellation::Completed(record) if record.id == latest.id)
        );
        assert_eq!(
            std::fs::read(path.with_extension("ownership.json")).unwrap(),
            durable
        );
        // A duplicate release remains idempotent; cancellation cannot consume
        // someone else's slots or budget to satisfy the old completion again.
        assert!(
            history
                .complete_durable(
                    latest.id,
                    "worker-b",
                    Some("retrying"),
                    BuildCompletion {
                        exit_code: 0,
                        duration_ms: None,
                        bytes_transferred: None,
                        timing: None,
                        cancellation: None,
                    }
                )
                .unwrap()
                .is_none()
        );
        drop(history);
        let restored = BuildHistory::load_from_file(&path, 10).unwrap();
        assert!(restored.wrapper_cancelled("retrying"));
        assert!(
            restored
                .try_start_active_build_with_wrapper(
                    "retry-project".into(),
                    "worker-c".into(),
                    "cargo build".into(),
                    0,
                    Some("retrying".into()),
                    2,
                    BuildLocation::Remote,
                )
                .unwrap()
                .is_none(),
            "a request delivered after cancellation must not acquire ownership"
        );
        assert_eq!(restored.reserved_disk_headroom_gib("worker-b"), 40);
        assert_eq!(restored.active_build(other.id).unwrap().slots, 1);
        assert_eq!(restored.queued_builds()[0].id, queued.id);
        assert_eq!(
            serde_json::to_value(restored.terminal_build(latest.id, "retrying").unwrap()).unwrap(),
            serde_json::to_value(&latest).unwrap()
        );
        assert!(
            restored
                .try_start_active_build_with_wrapper(
                    "retry-project".into(),
                    "worker-c".into(),
                    "cargo build".into(),
                    0,
                    Some("unrelated".into()),
                    2,
                    BuildLocation::Remote,
                )
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn retry_cancellation_racing_admission_identifies_the_current_attempt() {
        use std::sync::{Arc, Barrier};
        for _ in 0..16 {
            let root = TempDir::new().unwrap();
            let path = root.path().join("history.jsonl");
            let history = Arc::new(BuildHistory::new(10).with_persistence(path.clone()));
            let completed = complete_retry_attempt(&history, "old-worker", "retrying");
            let barrier = Arc::new(Barrier::new(2));
            let admitting = Arc::clone(&history);
            let admission_barrier = Arc::clone(&barrier);
            let task = std::thread::spawn(move || {
                admission_barrier.wait();
                admitting
                    .try_start_active_build_with_wrapper(
                        "retry-project".into(),
                        "new-worker".into(),
                        "cargo build".into(),
                        0,
                        Some("retrying".into()),
                        2,
                        BuildLocation::Remote,
                    )
                    .unwrap()
            });
            barrier.wait();
            let cancellation = history.cancel_wrapper("retrying").unwrap();
            let admitted = task.join().unwrap();
            drop(history);
            let restored = BuildHistory::load_from_file(&path, 10).unwrap();
            match cancellation {
                WrapperCancellation::Completed(record) => {
                    assert_eq!(record.id, completed.id);
                    assert!(admitted.is_none());
                    assert!(restored.wrapper_cancelled("retrying"));
                    assert!(restored.active_builds().is_empty());
                }
                WrapperCancellation::Active(id) => {
                    assert_eq!(admitted.unwrap().id, id);
                    assert_ne!(id, completed.id);
                    assert!(!restored.wrapper_cancelled("retrying"));
                    assert_eq!(restored.active_build(id).unwrap().worker_id, "new-worker");
                    assert_eq!(restored.active_build(id).unwrap().slots, 2);
                }
                _ => panic!("cancellation must fence the retry or identify its active attempt"),
            }
            assert!(restored.terminal_build(completed.id, "retrying").is_some());
        }
    }

    #[tokio::test]
    async fn retry_cancellation_uncertain_persistence_never_acknowledges_completion() {
        let root = TempDir::new().unwrap();
        let path = root.path().join("history.jsonl");
        let history = BuildHistory::new(10).with_persistence(path.clone());
        let completed = complete_retry_attempt(&history, "worker", "retrying");
        history
            .fail_after_ownership_rename
            .store(true, Ordering::SeqCst);
        assert!(history.cancel_wrapper("retrying").is_err());
        assert!(history.ownership_failed());
        assert!(history.cancel_wrapper("retrying").is_err());
        assert!(
            history
                .try_start_active_build_with_wrapper(
                    "project".into(),
                    "worker".into(),
                    "build".into(),
                    0,
                    Some("unrelated".into()),
                    1,
                    BuildLocation::Remote,
                )
                .unwrap()
                .is_none()
        );
        drop(history);
        let restored = BuildHistory::load_from_file(&path, 10).unwrap();
        assert!(restored.wrapper_cancelled("retrying"));
        assert!(
            matches!(restored.cancel_wrapper("retrying").unwrap(), WrapperCancellation::Completed(record) if record.id == completed.id)
        );
    }

    #[tokio::test]
    async fn retry_cancellation_full_journal_cannot_claim_a_completed_wrapper_is_fenced() {
        let history = BuildHistory::new(10);
        let completed = complete_retry_attempt(&history, "worker", "retrying");
        *history.cancelled_wrappers.write().unwrap() = (0..MAX_CANCELLED_WRAPPERS)
            .map(|id| format!("cancelled-{id}"))
            .collect();
        assert!(history.cancel_wrapper("retrying").is_err());
        assert!(!history.wrapper_cancelled("retrying"));
        assert!(history.terminal_build(completed.id, "retrying").is_some());
        assert!(history.active_builds().is_empty());
        assert!(!history.ownership_failed());
        assert!(matches!(
            history.cancel_wrapper("unknown").unwrap(),
            WrapperCancellation::NotQueued
        ));
    }

    #[test]
    fn queued_cancellation_survives_restart_and_blocks_only_same_wrapper() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("history.jsonl");
        let history = BuildHistory::new(10).with_persistence(path.clone());
        history
            .enqueue_build(
                "project".into(),
                "cargo build".into(),
                0,
                2,
                Some("cancelled".into()),
            )
            .unwrap();
        history
            .enqueue_build(
                "other".into(),
                "cargo build".into(),
                0,
                2,
                Some("other".into()),
            )
            .unwrap();
        assert!(matches!(
            history.cancel_wrapper("cancelled").unwrap(),
            WrapperCancellation::BeforeStart
        ));
        assert_eq!(history.queue_depth(), 1);
        assert!(matches!(
            history.cancel_wrapper("cancelled").unwrap(),
            WrapperCancellation::BeforeStart
        ));
        let recovered = BuildHistory::load_from_file(&path, 10).unwrap();
        assert!(recovered.wrapper_cancelled("cancelled"));
        assert!(
            recovered
                .try_start_active_build_with_wrapper(
                    "project".into(),
                    "worker".into(),
                    "cargo build".into(),
                    0,
                    Some("cancelled".into()),
                    2,
                    BuildLocation::Remote
                )
                .unwrap()
                .is_none()
        );
        assert!(
            recovered
                .try_start_active_build_with_wrapper(
                    "project".into(),
                    "worker".into(),
                    "cargo build".into(),
                    0,
                    Some("other".into()),
                    2,
                    BuildLocation::Remote
                )
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn active_wrapper_admission_has_exactly_one_live_owner() {
        use std::sync::{Arc, Barrier};

        for _ in 0..32 {
            let history = Arc::new(BuildHistory::new(10));
            let barrier = Arc::new(Barrier::new(3));
            let mut tasks = Vec::new();

            for (project, worker) in [("project-a", "worker-a"), ("project-b", "worker-b")] {
                let history = history.clone();
                let barrier = barrier.clone();
                tasks.push(std::thread::spawn(move || {
                    barrier.wait();
                    history
                        .try_start_active_build_with_wrapper(
                            project.into(),
                            worker.into(),
                            "cargo build".into(),
                            0,
                            Some("single-live-owner".into()),
                            2,
                            BuildLocation::Remote,
                        )
                        .unwrap()
                }));
            }

            barrier.wait();
            let admitted = tasks
                .into_iter()
                .filter_map(|task| task.join().unwrap())
                .collect::<Vec<_>>();

            assert_eq!(admitted.len(), 1);
            assert_eq!(history.active_builds().len(), 1);
            assert_eq!(
                history.active_builds()[0].local_wrapper_id.as_deref(),
                Some("single-live-owner")
            );

            assert!(
                history
                    .try_start_active_build_with_wrapper(
                        "project-c".into(),
                        "worker-c".into(),
                        "cargo build".into(),
                        0,
                        Some("different-live-owner".into()),
                        2,
                        BuildLocation::Remote,
                    )
                    .unwrap()
                    .is_some(),
                "a distinct wrapper must remain independently admissible"
            );
        }
    }

    #[test]
    fn queued_cancellation_and_admission_have_exactly_one_winner() {
        use std::sync::{Arc, Barrier};
        for _ in 0..32 {
            let history = Arc::new(BuildHistory::new(10));
            history
                .enqueue_build(
                    "project".into(),
                    "cargo build".into(),
                    0,
                    2,
                    Some("racing".into()),
                )
                .unwrap();
            let barrier = Arc::new(Barrier::new(2));
            let admission_history = history.clone();
            let admission_barrier = barrier.clone();
            let admission = std::thread::spawn(move || {
                admission_barrier.wait();
                admission_history
                    .try_start_active_build_with_wrapper(
                        "project".into(),
                        "worker".into(),
                        "cargo build".into(),
                        0,
                        Some("racing".into()),
                        2,
                        BuildLocation::Remote,
                    )
                    .unwrap()
            });
            barrier.wait();
            let cancellation = history.cancel_wrapper("racing").unwrap();
            let admitted = admission.join().unwrap();
            match cancellation {
                WrapperCancellation::BeforeStart => {
                    assert!(admitted.is_none());
                    assert!(history.active_builds().is_empty());
                    assert!(history.wrapper_cancelled("racing"));
                }
                WrapperCancellation::Active(build_id) => {
                    assert_eq!(admitted.unwrap().id, build_id);
                    assert!(!history.wrapper_cancelled("racing"));
                    assert_eq!(history.active_builds().len(), 1);
                }
                WrapperCancellation::Completed(_) => panic!("no command completed in this race"),
                WrapperCancellation::NotQueued => panic!("the queue entry was not removed"),
            }
        }
    }

    #[test]
    fn queued_departure_and_cancellation_cannot_both_authorize_their_outcome() {
        use std::sync::{Arc, Barrier};
        for _ in 0..32 {
            let history = Arc::new(BuildHistory::new(10));
            let queued = history
                .enqueue_build(
                    "project".into(),
                    "cargo build".into(),
                    0,
                    2,
                    Some("racing".into()),
                )
                .unwrap();
            let barrier = Arc::new(Barrier::new(2));
            let leaving_history = history.clone();
            let leaving_barrier = barrier.clone();
            let departure = std::thread::spawn(move || {
                leaving_barrier.wait();
                leaving_history
                    .finish_queued_build(queued.id, Some("racing"))
                    .unwrap()
            });
            barrier.wait();
            let cancelled = history.cancel_wrapper("racing").unwrap();
            let must_stop = departure.join().unwrap();
            match cancelled {
                WrapperCancellation::BeforeStart => assert!(must_stop),
                WrapperCancellation::NotQueued => assert!(!must_stop),
                _ => panic!("no active or completed build in departure race"),
            }
            assert_eq!(history.queue_depth(), 0);
        }
    }

    #[test]
    fn queued_cancellation_persistence_failure_never_acknowledges_or_drops_queue() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("history.jsonl");
        let history = BuildHistory::new(10).with_persistence(path.clone());
        history
            .enqueue_build(
                "project".into(),
                "cargo build".into(),
                0,
                2,
                Some("cancelled".into()),
            )
            .unwrap();
        history
            .fail_after_ownership_rename
            .store(true, Ordering::SeqCst);
        assert!(history.cancel_wrapper("cancelled").is_err());
        assert!(history.ownership_failed());
        assert_eq!(history.queue_depth(), 1);
        assert!(
            history
                .try_start_active_build_with_wrapper(
                    "project".into(),
                    "worker".into(),
                    "cargo build".into(),
                    0,
                    Some("different".into()),
                    2,
                    BuildLocation::Remote
                )
                .unwrap()
                .is_none()
        );
        let recovered = BuildHistory::load_from_file(&path, 10).unwrap();
        assert!(recovered.wrapper_cancelled("cancelled"));
    }

    #[test]
    fn queued_cancellation_full_journal_retains_old_intents() {
        let history = BuildHistory::new(10);
        *history.cancelled_wrappers.write().unwrap() = (0..MAX_CANCELLED_WRAPPERS)
            .map(|i| format!("wrapper-{i}"))
            .collect();
        history
            .enqueue_build(
                "project".into(),
                "cargo build".into(),
                0,
                2,
                Some("new-wrapper".into()),
            )
            .unwrap();
        assert!(history.cancel_wrapper("new-wrapper").is_err());
        assert!(!history.wrapper_cancelled("new-wrapper"));
        assert!(matches!(
            history.cancel_wrapper("wrapper-0").unwrap(),
            WrapperCancellation::BeforeStart
        ));
        assert_eq!(
            history.cancelled_wrappers.read().unwrap().len(),
            MAX_CANCELLED_WRAPPERS
        );
    }

    #[test]
    fn queued_ids_survive_restart_and_clock_rollback_without_reuse() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("history.jsonl");
        let history = BuildHistory::new(10).with_persistence(path.clone());
        // Model a previous daemon that allocated beyond the current wall-clock
        // seed. Restart must honor the durable high-water, even after rollback.
        let future = history.next_queue_id.load(Ordering::SeqCst) + (7200 << 24);
        history.next_queue_id.store(future, Ordering::SeqCst);
        let old = history
            .enqueue_build(
                "old".into(),
                "cargo build".into(),
                0,
                2,
                Some("old-wrapper".into()),
            )
            .unwrap();
        assert_eq!(old.id, future);
        let recovered = BuildHistory::load_from_file(&path, 10).unwrap();
        let new = recovered
            .enqueue_build(
                "new".into(),
                "cargo build".into(),
                0,
                2,
                Some("new-wrapper".into()),
            )
            .unwrap();
        assert_eq!(new.id, old.id + 1);
        assert!(new.id >= QUEUE_ID_NAMESPACE);
        assert!(recovered.queued_build(old.id).unwrap().recovered);
        assert_eq!(
            recovered
                .queued_build(new.id)
                .unwrap()
                .local_wrapper_id
                .as_deref(),
            Some("new-wrapper")
        );
        assert_eq!(recovered.queue_depth(), 2);
        assert!(matches!(
            recovered.cancel_wrapper("old-wrapper").unwrap(),
            WrapperCancellation::BeforeStart
        ));
        assert_eq!(recovered.queue_depth(), 1);
        assert!(recovered.queued_build(new.id).is_some());
    }

    #[test]
    fn fresh_load_defers_ownership_write_but_existing_snapshot_is_rewritten() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("history.jsonl");
        let ownership = path.with_extension("ownership.json");

        // Fresh start: nothing recovered, so no durable write before serving.
        let fresh = BuildHistory::load_from_file(&path, 10).unwrap();
        assert!(!ownership.exists());
        assert!(!path.with_extension("tmp").exists());

        // The first ownership change still becomes durable immediately.
        fresh
            .try_start_active_build_with_wrapper(
                "active".into(),
                "worker".into(),
                "cargo build".into(),
                0,
                None,
                2,
                BuildLocation::Remote,
            )
            .unwrap()
            .unwrap();
        assert!(ownership.exists());

        // A restart that finds a snapshot re-persists it (queue epoch advance).
        std::fs::write(&ownership, br#"{"version":1,"active":[],"completed":[]}"#).unwrap();
        BuildHistory::load_from_file(&path, 10).unwrap();
        let rewritten = std::fs::read_to_string(&ownership).unwrap();
        assert!(rewritten.contains("next_queue_id"), "{rewritten}");
    }

    #[test]
    fn queued_ids_migrate_legacy_snapshot_into_separate_namespace() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("history.jsonl");
        std::fs::write(
            path.with_extension("ownership.json"),
            br#"{"version":1,"active":[],"completed":[]}"#,
        )
        .unwrap();
        let history = BuildHistory::load_from_file(&path, 10).unwrap();
        let queued = history
            .enqueue_build("queued".into(), "cargo build".into(), 0, 2, None)
            .unwrap();
        let active = history
            .try_start_active_build_with_wrapper(
                "active".into(),
                "worker".into(),
                "cargo build".into(),
                0,
                None,
                2,
                BuildLocation::Remote,
            )
            .unwrap()
            .unwrap();
        assert!(queued.id >= QUEUE_ID_NAMESPACE);
        assert!(active.id < QUEUE_ID_NAMESPACE);
        let recovered = BuildHistory::load_from_file(&path, 10).unwrap();
        assert!(
            recovered
                .enqueue_build("next".into(), "cargo build".into(), 0, 2, None)
                .unwrap()
                .id
                > queued.id
        );
    }

    #[test]
    fn queued_id_allocation_failure_stays_invisible_and_exhaustion_never_wraps() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("history.jsonl");
        let history = BuildHistory::new(10).with_persistence(path.clone());
        let skipped = history.next_queue_id.load(Ordering::SeqCst);
        history
            .fail_after_ownership_rename
            .store(true, Ordering::SeqCst);
        assert!(
            history
                .enqueue_build("failed".into(), "cargo build".into(), 0, 2, None)
                .is_none()
        );
        assert!(history.ownership_failed());
        assert_eq!(history.queue_depth(), 0);
        let recovered = BuildHistory::load_from_file(&path, 10).unwrap();
        // The injected error occurred after the atomic rename: the queue
        // intent exists on disk even though the enqueue was not acknowledged.
        assert!(recovered.queued_build(skipped).unwrap().recovered);
        let queued = recovered
            .enqueue_build("next".into(), "cargo build".into(), 0, 2, None)
            .unwrap();
        assert!(queued.id > skipped);
        recovered.next_queue_id.store(u64::MAX, Ordering::SeqCst);
        assert!(
            recovered
                .enqueue_build("overflow".into(), "cargo build".into(), 0, 2, None)
                .is_none()
        );
        assert_eq!(recovered.next_queue_id.load(Ordering::SeqCst), u64::MAX);
        assert_eq!(recovered.queue_depth(), 2);
    }

    #[test]
    fn durable_queue_restart_preserves_order_identity_and_capacity() {
        let root = TempDir::new().unwrap();
        let path = root.path().join("history.jsonl");
        let history = BuildHistory::new(1).with_persistence(path.clone());
        let expected: Vec<_> = (0..5)
            .map(|i| {
                history
                    .enqueue_build(
                        format!("project-{i}"),
                        format!("cargo test -p package-{i}"),
                        std::process::id(),
                        i + 1,
                        Some(format!("wrapper-{i}")),
                    )
                    .unwrap()
            })
            .collect();
        history.update_queue_estimates();
        drop(history);
        for _ in 0..3 {
            let recovered = BuildHistory::load_from_file(&path, 1)
                .unwrap()
                .with_max_queue_depth(2);
            assert_eq!(
                recovered.queue_depth(),
                5,
                "history/queue limits do not evict owners"
            );
            assert!(
                recovered.active_builds().is_empty(),
                "loading is not admission"
            );
            for (position, (before, after)) in
                expected.iter().zip(recovered.queued_builds()).enumerate()
            {
                assert_eq!(
                    serde_json::to_value(before).unwrap(),
                    serde_json::to_value(&after).unwrap()
                );
                assert_eq!(recovered.queue_position(after.id), Some(position + 1));
                assert!(after.recovered);
                assert!(after.estimated_start.is_none());
            }
            assert!(
                recovered
                    .enqueue_build("extra".into(), "build".into(), 0, 1, None)
                    .is_none()
            );
        }
    }

    #[test]
    fn durable_queue_departures_and_cancellation_do_not_resurrect() {
        let root = TempDir::new().unwrap();
        let path = root.path().join("history.jsonl");
        let history = BuildHistory::new(10).with_persistence(path.clone());
        let rows: Vec<_> = (0..5)
            .map(|i| {
                history
                    .enqueue_build(
                        format!("p-{i}"),
                        "build".into(),
                        100 + i,
                        1,
                        Some(format!("w-{i}")),
                    )
                    .unwrap()
            })
            .collect();
        assert_eq!(history.dequeue_build().unwrap().id, rows[0].id);
        assert_eq!(
            history.remove_queued_build(rows[2].id).unwrap().id,
            rows[2].id
        );
        assert_eq!(
            history.remove_queued_build_by_pid(103).unwrap().id,
            rows[3].id
        );
        assert!(
            !history
                .finish_queued_build(rows[1].id, Some("w-1"))
                .unwrap()
        );
        drop(history);
        let recovered = BuildHistory::load_from_file(&path, 10).unwrap();
        assert_eq!(
            recovered
                .queued_builds()
                .iter()
                .map(|row| row.id)
                .collect::<Vec<_>>(),
            vec![rows[4].id]
        );
        assert!(matches!(
            recovered.cancel_wrapper("w-4").unwrap(),
            WrapperCancellation::BeforeStart
        ));
        drop(recovered);
        let reopened = BuildHistory::load_from_file(&path, 10).unwrap();
        assert!(reopened.queue_is_empty());
        assert!(reopened.wrapper_cancelled("w-4"));
        assert!(matches!(
            reopened.cancel_wrapper("w-1").unwrap(),
            WrapperCancellation::NotQueued
        ));
    }

    #[test]
    fn durable_queue_admission_retires_waiter_in_the_same_snapshot() {
        let root = TempDir::new().unwrap();
        let path = root.path().join("history.jsonl");
        let history = BuildHistory::new(10).with_persistence(path.clone());
        let queued = history
            .enqueue_build(
                "project".into(),
                "cargo build".into(),
                0,
                2,
                Some("owner".into()),
            )
            .unwrap();
        let active = history
            .try_start_active_build_with_wrapper(
                "project".into(),
                "worker".into(),
                "cargo build".into(),
                0,
                Some("owner".into()),
                2,
                BuildLocation::Remote,
            )
            .unwrap()
            .unwrap();
        // No explicit API queue removal: model a crash immediately after admission.
        assert!(history.queued_build(queued.id).is_none());
        drop(history);
        let recovered = BuildHistory::load_from_file(&path, 10).unwrap();
        assert!(recovered.queue_is_empty());
        assert_eq!(recovered.active_builds().len(), 1);
        assert_eq!(recovered.active_build(active.id).unwrap().slots, 2);
        assert!(matches!(
            recovered.cancel_wrapper("owner").unwrap(),
            WrapperCancellation::Active(id) if id == active.id
        ));
    }

    #[test]
    fn durable_queue_departure_failure_retains_visibility_until_restart() {
        for after_rename in [false, true] {
            let root = TempDir::new().unwrap();
            let path = root.path().join("history.jsonl");
            let mut history = BuildHistory::new(10).with_persistence(path.clone());
            let row = history
                .enqueue_build("project".into(), "build".into(), 0, 1, Some("owner".into()))
                .unwrap();
            if after_rename {
                history
                    .fail_after_ownership_rename
                    .store(true, Ordering::SeqCst);
            } else {
                let blocker = root.path().join("not-a-directory");
                std::fs::write(&blocker, b"retained").unwrap();
                history.persistence_path = Some(blocker.join("history.jsonl"));
            }
            assert!(history.finish_queued_build(row.id, Some("owner")).is_err());
            assert!(history.ownership_failed());
            assert!(history.queued_build(row.id).is_some());
            assert!(history.remove_queued_build(row.id).is_none());
            assert!(history.dequeue_build().is_none());
            drop(history);
            let recovered = BuildHistory::load_from_file(&path, 10).unwrap();
            assert_eq!(recovered.queued_build(row.id).is_none(), after_rename);
        }
    }

    #[test]
    fn durable_queue_wrong_departure_identity_changes_nothing() {
        let root = TempDir::new().unwrap();
        let path = root.path().join("history.jsonl");
        let history = BuildHistory::new(10).with_persistence(path.clone());
        let row = history
            .enqueue_build("project".into(), "build".into(), 0, 1, Some("owner".into()))
            .unwrap();
        let before = std::fs::read(path.with_extension("ownership.json")).unwrap();
        for wrong in [None, Some("different")] {
            assert_eq!(
                history
                    .finish_queued_build(row.id, wrong)
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::PermissionDenied
            );
            assert!(history.queued_build(row.id).is_some());
            assert!(!history.ownership_failed());
            assert_eq!(
                std::fs::read(path.with_extension("ownership.json")).unwrap(),
                before
            );
        }
    }

    #[test]
    fn durable_queue_reload_reconstructs_age_without_rebinding_pid() {
        let root = TempDir::new().unwrap();
        let path = root.path().join("history.jsonl");
        let history = BuildHistory::new(10).with_persistence(path.clone());
        let row = history
            .enqueue_build(
                "project".into(),
                "build".into(),
                std::process::id(),
                1,
                Some("owner".into()),
            )
            .unwrap();
        let ownership = path.with_extension("ownership.json");
        let mut snapshot: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&ownership).unwrap()).unwrap();
        let old = (Utc::now() - ChronoDuration::seconds(120)).to_rfc3339();
        snapshot["queued"][0]["queued_at"] = serde_json::json!(old);
        // Model an old incarnation; this does not force real OS PID reuse.
        snapshot["queued"][0]["hook_process_identity"] =
            serde_json::json!("prior-process-incarnation");
        std::fs::write(&ownership, serde_json::to_vec(&snapshot).unwrap()).unwrap();
        drop(history);
        let recovered = BuildHistory::load_from_file(&path, 10).unwrap();
        let restored = recovered.queued_build(row.id).unwrap();
        assert_eq!(restored.queued_at, old);
        assert!(restored.queued_at_mono.elapsed() >= Duration::from_secs(120));
        assert_eq!(
            restored.hook_process_identity.as_deref(),
            Some("prior-process-incarnation")
        );
        assert_eq!(restored.hook_pid, std::process::id());
        assert!(restored.recovered);
        assert!(
            recovered
                .remove_queued_build_by_pid(std::process::id())
                .is_none(),
            "a recycled PID cannot identify recovered queue ownership"
        );
        assert!(recovered.queued_build(row.id).is_some());
    }

    #[test]
    fn durable_queue_invalid_snapshot_is_rejected_without_rewriting_evidence() {
        for case in 0..10 {
            let root = TempDir::new().unwrap();
            let path = root.path().join("history.jsonl");
            let history = BuildHistory::new(10).with_persistence(path.clone());
            let row = history
                .enqueue_build("project".into(), "build".into(), 0, 1, Some("owner".into()))
                .unwrap();
            let ownership = path.with_extension("ownership.json");
            let mut snapshot: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&ownership).unwrap()).unwrap();
            match case {
                0 => snapshot["queued"][0]["id"] = serde_json::json!(1),
                1 => snapshot["next_queue_id"] = serde_json::json!(row.id),
                2 => snapshot["queued"][0]["queued_at"] = serde_json::json!("not-a-time"),
                3 => {
                    let duplicate = snapshot["queued"][0].clone();
                    snapshot["queued"].as_array_mut().unwrap().push(duplicate);
                }
                4 => snapshot["cancelled_wrappers"] = serde_json::json!(["owner"]),
                5 => {
                    snapshot.as_object_mut().unwrap().remove("queued");
                }
                6 => snapshot["version"] = serde_json::json!(1),
                7 => {
                    snapshot["queued"] = serde_json::json!([]);
                    snapshot.as_object_mut().unwrap().remove("next_queue_id");
                }
                8 => {
                    let mut duplicate = snapshot["queued"][0].clone();
                    duplicate["id"] = serde_json::json!(row.id + 1);
                    snapshot["next_queue_id"] = serde_json::json!(row.id + 2);
                    snapshot["queued"].as_array_mut().unwrap().push(duplicate);
                }
                _ => snapshot["queued"][0]["local_wrapper_id"] = serde_json::json!(""),
            }
            let bytes = serde_json::to_vec(&snapshot).unwrap();
            std::fs::write(&ownership, &bytes).unwrap();
            drop(history);
            assert!(
                BuildHistory::load_from_file(&path, 10).is_err(),
                "case {case}"
            );
            assert_eq!(std::fs::read(&ownership).unwrap(), bytes, "case {case}");
        }
    }

    #[tokio::test]
    async fn durable_queue_rejects_duplicate_and_existing_execution_owners() {
        let root = TempDir::new().unwrap();
        let path = root.path().join("history.jsonl");
        let history = BuildHistory::new(10).with_persistence(path.clone());
        let enqueue = |wrapper: &str| {
            history.enqueue_build(
                "project".into(),
                "build".into(),
                0,
                1,
                Some(wrapper.to_owned()),
            )
        };
        let queued = enqueue("queued-owner").unwrap();
        let before = std::fs::read(path.with_extension("ownership.json")).unwrap();
        let next = history.next_queue_id.load(Ordering::SeqCst);
        assert!(enqueue("queued-owner").is_none());
        assert!(enqueue("").is_none());
        assert_eq!(history.next_queue_id.load(Ordering::SeqCst), next);
        assert_eq!(
            std::fs::read(path.with_extension("ownership.json")).unwrap(),
            before
        );
        let active = history
            .try_start_active_build_with_wrapper(
                "active-project".into(),
                "worker".into(),
                "build".into(),
                0,
                Some("execution-owner".into()),
                2,
                BuildLocation::Remote,
            )
            .unwrap()
            .unwrap();
        assert!(enqueue("execution-owner").is_none());
        history
            .complete_durable(
                active.id,
                "worker",
                Some("execution-owner"),
                BuildCompletion {
                    exit_code: 0,
                    duration_ms: None,
                    bytes_transferred: None,
                    timing: None,
                    cancellation: None,
                },
            )
            .unwrap()
            .unwrap();
        assert!(enqueue("execution-owner").is_none());
        assert!(!history.ownership_failed());
        let recovered = BuildHistory::load_from_file(&path, 10).unwrap();
        assert_eq!(recovered.queue_depth(), 1);
        assert_eq!(recovered.queued_builds()[0].id, queued.id);
    }

    #[test]
    fn durable_queue_admission_cancellation_race_survives_restart() {
        use std::sync::{Arc, Barrier};

        for _ in 0..8 {
            let root = TempDir::new().unwrap();
            let path = root.path().join("history.jsonl");
            let history = Arc::new(BuildHistory::new(10).with_persistence(path.clone()));
            history
                .enqueue_build(
                    "project".into(),
                    "cargo build".into(),
                    0,
                    2,
                    Some("racing".into()),
                )
                .unwrap();
            let barrier = Arc::new(Barrier::new(2));
            let admitting = history.clone();
            let admission_barrier = barrier.clone();
            let task = std::thread::spawn(move || {
                admission_barrier.wait();
                admitting
                    .try_start_active_build_with_wrapper(
                        "project".into(),
                        "worker".into(),
                        "cargo build".into(),
                        0,
                        Some("racing".into()),
                        2,
                        BuildLocation::Remote,
                    )
                    .unwrap()
            });
            barrier.wait();
            let cancellation = history.cancel_wrapper("racing").unwrap();
            let admitted = task.join().unwrap();
            drop(history);
            let recovered = BuildHistory::load_from_file(&path, 10).unwrap();
            assert!(recovered.queue_is_empty());
            match cancellation {
                WrapperCancellation::BeforeStart => {
                    assert!(admitted.is_none());
                    assert!(recovered.wrapper_cancelled("racing"));
                    assert!(recovered.active_builds().is_empty());
                }
                WrapperCancellation::Active(id) => {
                    assert_eq!(admitted.unwrap().id, id);
                    assert!(!recovered.wrapper_cancelled("racing"));
                    assert_eq!(recovered.active_builds().len(), 1);
                    assert_eq!(recovered.active_build(id).unwrap().slots, 2);
                }
                _ => panic!("race must resolve to admission or no-start cancellation"),
            }
        }
    }

    /// Kill the process using the real ownership writer without orderly
    /// shutdown. This is a storage crash test, not a client reconnect test.
    #[cfg(unix)]
    #[test]
    fn durable_queue_survives_process_kill_before_shutdown() {
        const ROOT: &str = "RCH_DURABLE_QUEUE_CRASH_TEST_ROOT";
        const TEST: &str = "history::tests::durable_queue_survives_process_kill_before_shutdown";
        if let Some(root) = std::env::var_os(ROOT) {
            let root = PathBuf::from(root);
            let history = BuildHistory::new(10).with_persistence(root.join("history.jsonl"));
            let ids: Vec<_> = (0..4)
                .map(|i| {
                    history
                        .enqueue_build(
                            format!("project-{i}"),
                            "cargo check".into(),
                            std::process::id(),
                            i + 1,
                            Some(format!("crash-wrapper-{i}")),
                        )
                        .unwrap()
                        .id
                })
                .collect();
            std::fs::write(
                root.join("ready.pending"),
                serde_json::to_vec(&ids).unwrap(),
            )
            .unwrap();
            std::fs::rename(root.join("ready.pending"), root.join("ready.json")).unwrap();
            loop {
                std::thread::park();
            }
        }

        struct OwnedChild(std::process::Child);
        impl Drop for OwnedChild {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let root = TempDir::new().unwrap();
        let mut child = OwnedChild(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST, "--nocapture"])
                .env(ROOT, root.path())
                .stdout(File::create(root.path().join("child.stdout")).unwrap())
                .stderr(File::create(root.path().join("child.stderr")).unwrap())
                .spawn()
                .unwrap(),
        );
        let started = Instant::now();
        while !root.path().join("ready.json").is_file() {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "writer exited before enqueue"
            );
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "writer startup timed out"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let ids: Vec<u64> =
            serde_json::from_slice(&std::fs::read(root.path().join("ready.json")).unwrap())
                .unwrap();
        child.0.kill().unwrap();
        let status = child.0.wait().unwrap();
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(status.signal(), Some(9));
        let path = root.path().join("history.jsonl");
        let recovered = BuildHistory::load_from_file(&path, 1).unwrap();
        assert!(recovered.active_builds().is_empty());
        assert_eq!(
            recovered
                .queued_builds()
                .iter()
                .map(|row| row.id)
                .collect::<Vec<_>>(),
            ids
        );
        for (i, row) in recovered.queued_builds().iter().enumerate() {
            assert_eq!(row.project_id, format!("project-{i}"));
            assert_eq!(row.slots_needed, i as u32 + 1);
            assert_eq!(row.hook_pid, child.0.id());
            assert!(row.recovered);
            assert!(matches!(
                recovered
                    .cancel_wrapper(&format!("crash-wrapper-{i}"))
                    .unwrap(),
                WrapperCancellation::BeforeStart
            ));
        }
        drop(recovered);
        assert!(
            BuildHistory::load_from_file(&path, 1)
                .unwrap()
                .queue_is_empty()
        );
    }

    #[test]
    fn test_enqueue_dequeue_fifo() {
        let _guard = test_guard!();
        let history = BuildHistory::new(10);

        // Enqueue three builds
        let b1 = history
            .enqueue_build("proj-a".into(), "cargo build".into(), 1001, 4, None)
            .unwrap();
        let b2 = history
            .enqueue_build("proj-b".into(), "cargo test".into(), 1002, 8, None)
            .unwrap();
        let b3 = history
            .enqueue_build("proj-c".into(), "cargo check".into(), 1003, 2, None)
            .unwrap();

        assert_eq!(history.queue_depth(), 3);

        // Dequeue in FIFO order
        let d1 = history.dequeue_build().unwrap();
        assert_eq!(d1.id, b1.id);
        assert_eq!(d1.project_id, "proj-a");

        let d2 = history.dequeue_build().unwrap();
        assert_eq!(d2.id, b2.id);

        let d3 = history.dequeue_build().unwrap();
        assert_eq!(d3.id, b3.id);

        assert!(history.queue_is_empty());
        assert!(history.dequeue_build().is_none());
    }

    #[test]
    fn test_queue_depth_limit() {
        let _guard = test_guard!();
        let history = BuildHistory::new(10).with_max_queue_depth(2);

        // First two should succeed
        assert!(
            history
                .enqueue_build("proj-a".into(), "build".into(), 1, 4, None)
                .is_some()
        );
        assert!(
            history
                .enqueue_build("proj-b".into(), "build".into(), 2, 4, None)
                .is_some()
        );

        // Third should fail
        assert!(
            history
                .enqueue_build("proj-c".into(), "build".into(), 3, 4, None)
                .is_none()
        );

        // Dequeue one, then third should succeed
        history.dequeue_build();
        assert!(
            history
                .enqueue_build("proj-c".into(), "build".into(), 3, 4, None)
                .is_some()
        );
    }

    #[test]
    fn test_queue_position() {
        let _guard = test_guard!();
        let history = BuildHistory::new(10);

        let b1 = history
            .enqueue_build("proj-a".into(), "build".into(), 1, 4, None)
            .unwrap();
        let b2 = history
            .enqueue_build("proj-b".into(), "build".into(), 2, 4, None)
            .unwrap();
        let b3 = history
            .enqueue_build("proj-c".into(), "build".into(), 3, 4, None)
            .unwrap();

        // Positions are 1-indexed
        assert_eq!(history.queue_position(b1.id), Some(1));
        assert_eq!(history.queue_position(b2.id), Some(2));
        assert_eq!(history.queue_position(b3.id), Some(3));
        assert_eq!(history.queue_position(999), None);
    }

    #[test]
    fn test_remove_queued_build() {
        let _guard = test_guard!();
        let history = BuildHistory::new(10);

        let b1 = history
            .enqueue_build("proj-a".into(), "build".into(), 1001, 4, None)
            .unwrap();
        let b2 = history
            .enqueue_build("proj-b".into(), "build".into(), 1002, 4, None)
            .unwrap();
        let b3 = history
            .enqueue_build("proj-c".into(), "build".into(), 1003, 4, None)
            .unwrap();

        // Remove middle build by ID
        let removed = history.remove_queued_build(b2.id).unwrap();
        assert_eq!(removed.project_id, "proj-b");
        assert_eq!(history.queue_depth(), 2);

        // Remove by PID
        let removed = history.remove_queued_build_by_pid(1003).unwrap();
        assert_eq!(removed.id, b3.id);
        assert_eq!(history.queue_depth(), 1);

        // Only b1 remains
        let d = history.dequeue_build().unwrap();
        assert_eq!(d.id, b1.id);
    }

    #[test]
    fn test_queued_builds_list() {
        let _guard = test_guard!();
        let history = BuildHistory::new(10);

        history.enqueue_build("proj-a".into(), "build".into(), 1, 4, None);
        history.enqueue_build("proj-b".into(), "test".into(), 2, 8, None);

        let queued = history.queued_builds();
        assert_eq!(queued.len(), 2);
        assert_eq!(queued[0].project_id, "proj-a");
        assert_eq!(queued[1].project_id, "proj-b");
    }

    #[test]
    fn test_queued_build_lookup() {
        let _guard = test_guard!();
        let history = BuildHistory::new(10);

        let b = history
            .enqueue_build("proj-a".into(), "cargo build".into(), 1001, 4, None)
            .unwrap();

        let found = history.queued_build(b.id).unwrap();
        assert_eq!(found.command, "cargo build");
        assert_eq!(found.hook_pid, 1001);
        assert_eq!(found.slots_needed, 4);

        assert!(history.queued_build(999).is_none());
    }

    #[test]
    fn test_queue_unlimited_depth() {
        let _guard = test_guard!();
        // max_queue_depth = 0 means unlimited
        let history = BuildHistory::new(10).with_max_queue_depth(0);

        // Should be able to enqueue many
        for i in 0..1000 {
            assert!(
                history
                    .enqueue_build(format!("proj-{}", i), "build".into(), i, 4, None)
                    .is_some()
            );
        }

        assert_eq!(history.queue_depth(), 1000);
    }

    // =========================================================================
    // Saved Time Stats Tests
    // =========================================================================

    #[test]
    fn test_saved_time_stats_empty_history() {
        let _guard = test_guard!();
        let history = BuildHistory::new(10);
        let stats = history.saved_time_stats();

        assert_eq!(stats.builds_counted, 0);
        assert_eq!(stats.time_saved_ms, 0);
        assert_eq!(stats.total_remote_duration_ms, 0);
        assert_eq!(stats.estimated_local_duration_ms, 0);
    }

    #[test]
    fn test_saved_time_stats_only_local_builds() {
        let _guard = test_guard!();
        let history = BuildHistory::new(10);

        // Add local builds only
        for i in 1..=3 {
            let mut record = make_build_record(i);
            record.location = BuildLocation::Local;
            record.duration_ms = 1000;
            history.record(record);
        }

        let stats = history.saved_time_stats();
        assert_eq!(stats.builds_counted, 0);
        assert_eq!(stats.time_saved_ms, 0);
    }

    #[test]
    fn test_saved_time_stats_without_local_baseline_makes_no_up_estimate() {
        let _guard = test_guard!();
        let history = BuildHistory::new(10);

        // Remote builds only: there is no observed local baseline, so no local
        // estimate may be invented (the old code fabricated a 2.0x factor).
        for i in 1..=3 {
            let mut record = make_build_record(i);
            record.location = BuildLocation::Remote;
            record.worker_id = Some("worker-1".to_string());
            record.duration_ms = 1000;
            history.record(record);
        }

        let stats = history.saved_time_stats();
        assert_eq!(stats.builds_counted, 3);
        assert_eq!(stats.total_remote_duration_ms, 3000);
        assert_eq!(stats.estimate_basis, "none");
        assert_eq!(stats.local_baseline_builds, 0);
        assert_eq!(stats.estimated_local_duration_ms, 0);
        assert_eq!(stats.time_saved_ms, 0);
        assert_eq!(stats.today_saved_ms, 0);
        assert_eq!(stats.week_saved_ms, 0);
        assert_eq!(stats.avg_speedup, 0.0);
    }

    #[test]
    fn test_saved_time_stats_observed_local_mean_backs_estimate() {
        let _guard = test_guard!();
        let history = BuildHistory::new(10);

        for i in 1..=2 {
            let mut record = make_build_record(i);
            record.location = BuildLocation::Local;
            record.duration_ms = 2000;
            history.record(record);
        }
        let mut remote = make_build_record(3);
        remote.location = BuildLocation::Remote;
        remote.worker_id = Some("worker-1".to_string());
        remote.duration_ms = 1000;
        history.record(remote);

        let stats = history.saved_time_stats();
        assert_eq!(stats.builds_counted, 1);
        assert_eq!(stats.estimate_basis, "observed_local_mean");
        assert_eq!(stats.local_baseline_builds, 2);
        assert_eq!(stats.estimated_local_duration_ms, 2000);
        assert_eq!(stats.time_saved_ms, 1000);
        assert!((stats.avg_speedup - 2.0).abs() < 0.01);
    }

    #[test]
    fn test_saved_time_stats_mixed_builds() {
        let _guard = test_guard!();
        let history = BuildHistory::new(10);

        // Add local builds
        for i in 1..=2 {
            let mut record = make_build_record(i);
            record.location = BuildLocation::Local;
            record.duration_ms = 2000; // Local takes 2s
            history.record(record);
        }

        // Add remote builds
        for i in 3..=4 {
            let mut record = make_build_record(i);
            record.location = BuildLocation::Remote;
            record.worker_id = Some("worker-1".to_string());
            record.duration_ms = 1000; // Remote takes 1s
            history.record(record);
        }

        let stats = history.saved_time_stats();
        assert_eq!(stats.builds_counted, 2);
        assert_eq!(stats.total_remote_duration_ms, 2000);
        // With avg local duration 2000ms: estimated local = 2 * 2000 = 4000
        assert_eq!(stats.estimated_local_duration_ms, 4000);
        assert_eq!(stats.time_saved_ms, 2000);
        assert!((stats.avg_speedup - 2.0).abs() < 0.01);
    }

    #[test]
    fn test_saved_time_stats_failed_builds_excluded() {
        let _guard = test_guard!();
        let history = BuildHistory::new(10);

        // Add successful remote build
        let mut record1 = make_build_record(1);
        record1.location = BuildLocation::Remote;
        record1.worker_id = Some("worker-1".to_string());
        record1.duration_ms = 1000;
        record1.exit_code = 0;
        history.record(record1);

        // Add failed remote build
        let mut record2 = make_build_record(2);
        record2.location = BuildLocation::Remote;
        record2.worker_id = Some("worker-1".to_string());
        record2.duration_ms = 5000;
        record2.exit_code = 1;
        history.record(record2);

        let stats = history.saved_time_stats();
        // Only successful remote builds are counted
        assert_eq!(stats.builds_counted, 1);
        assert_eq!(stats.total_remote_duration_ms, 1000);
    }

    #[test]
    fn test_saved_time_stats_no_negative_savings() {
        let _guard = test_guard!();
        let history = BuildHistory::new(10);

        // Add fast local builds (500ms)
        for i in 1..=2 {
            let mut record = make_build_record(i);
            record.location = BuildLocation::Local;
            record.duration_ms = 500;
            history.record(record);
        }

        // Add slow remote builds (1000ms - slower than local!)
        for i in 3..=4 {
            let mut record = make_build_record(i);
            record.location = BuildLocation::Remote;
            record.worker_id = Some("worker-1".to_string());
            record.duration_ms = 1000;
            history.record(record);
        }

        let stats = history.saved_time_stats();
        // estimated_local = 500ms * 2 = 1000ms
        // time_saved = max(0, 1000 - 2000) = 0 (no negative savings)
        assert_eq!(stats.time_saved_ms, 0);
    }
}
