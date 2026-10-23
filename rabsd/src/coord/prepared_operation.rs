//! Durable admission for the daemon's prepared, execution-only build service.
//!
//! The saved request is an operation identity, never an ActionDescriptor or a
//! cache key. An exclusive local owner records Running before invoking the real
//! worker adapter. Proven transport loss can queue bounded result-only recovery;
//! lost owners without that durable intent become Uncertain and require explicit
//! recovery. Source bytes are revalidated against the saved
//! manifest by the execution adapter; a mutable bundle cannot change the request.
//! State and build directories are operator-owned, not hostile shared storage.

mod archival;
mod completion;
mod local_recovery;
mod preview;
pub use completion::{DiagnosticSnapshot, DiagnosticStream, PreparedCompletion};
pub use preview::PreviewObserver;

use super::secure_worker_delivery::{OperationCancellation, parse_worker_pin};
use super::source_delivery::request_manifest;
use super::worker_delivery::{DeliveryMode, MAX_FRAME_BYTES, toolchain_identity, validate_request};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

const MAX_OPERATIONS: usize = 1024;
const MAX_RETAINED_BYTES: usize = 64 * 1024 * 1024;
const RECORD_OVERHEAD: usize = 96 * 1024;
const MAX_WORKER_POOL_BYTES: usize = 16 * 1024;
const MAX_RECORD_BYTES: usize = MAX_FRAME_BYTES + RECORD_OVERHEAD + MAX_WORKER_POOL_BYTES;
const MAX_DETAIL_BYTES: usize = 2048;
const MAX_RUNNING: usize = 4;
const MAX_AUTOMATIC_RECOVERIES: u8 = 3;
const MAX_PREPARED_WORKERS: usize = 32;
/// Locality is a bounded admission hint, not an inventory of worker caches.
/// Ignore cold archives and executions older than this many queue admissions.
const CARGO_LOCALITY_WINDOW: u64 = 128;

fn recovery_delay(attempt: u8) -> Duration {
    Duration::from_secs(1_u64 << u32::from(attempt.saturating_sub(1).min(2)))
}

/// All execution placement and destination choices remain bound to this ID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedOperationSpec {
    pub id: String,
    pub address: String,
    pub worker: String,
    pub worker_spki_sha256: String,
    pub bundle: PathBuf,
    pub delivery: PathBuf,
    pub output: PathBuf,
}

/// An operator-approved canonical worker and its fixed coordinator listener.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedWorker {
    pub address: String,
    pub worker: String,
    pub worker_spki_sha256: String,
}

/// Placement is selected once when this immutable template enters the queue.
/// The ordered candidate list remains part of admission identity on retries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedPoolOperationSpec {
    pub id: String,
    pub workers: Vec<PreparedWorker>,
    pub bundle: PathBuf,
    pub delivery: PathBuf,
    pub output: PathBuf,
}

impl PreparedPoolOperationSpec {
    /// Validate immutable admission shape without reading or creating inputs.
    /// Native callers can reject a malformed pool before expensive capture.
    pub fn validate(&self) -> io::Result<()> {
        validate_worker_pool(&self.workers)?;
        let first = self
            .workers
            .first()
            .ok_or_else(|| invalid("canonical worker pool is empty"))?;
        validate_spec_shape(&PreparedOperationSpec {
            id: self.id.clone(),
            address: first.address.clone(),
            worker: first.worker.clone(),
            worker_spki_sha256: first.worker_spki_sha256.clone(),
            bundle: self.bundle.clone(),
            delivery: self.delivery.clone(),
            output: self.output.clone(),
        })
    }
}

/// These are operation/recovery states, not action publication states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    Queued,
    Running,
    Cancelling,
    Completed,
    Cancelled,
    FailedBeforeStart,
    Uncertain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StoredMode {
    Execute,
    Resume,
    Acknowledge,
    LocalRecovery,
}

/// Bounded status; full compiler artifacts and receipts stay in the delivery.
#[derive(Debug, Clone, Serialize)]
pub struct OperationStatus {
    pub id: String,
    pub state: OperationState,
    /// Domain-separated job identity. Version 1 binds the numeric request;
    /// version 2 binds the immutable allocation intent. Actual delivery always
    /// verifies the separately retained full numeric execution request.
    pub request_sha256: String,
    /// Pending daemon allocation has no worker identity. Numeric identities are
    /// exposed only after the exclusive claim has durably bound the request.
    pub request_id: Option<u64>,
    /// Durable claim number, zero until the first execution owner is admitted.
    pub attempt: u64,
    /// Number of automatically scheduled result/ACK recovery attempts. These
    /// never authorize another compiler execution.
    pub automatic_recoveries: u8,
    /// A durably queued recovery is waiting for its bounded reconnect backoff.
    pub recovery_pending: bool,
    /// The original claim followed by the current automatic recovery sequence.
    /// Explicit manual recovery starts a new follow owner instead.
    pub recovery_origin_attempt: Option<u64>,
    pub address: String,
    pub listen_address: Option<String>,
    pub worker: String,
    pub worker_spki_sha256: String,
    pub bundle: PathBuf,
    pub delivery: PathBuf,
    pub output: PathBuf,
    pub mode: &'static str,
    pub cancel_requested: bool,
    pub execution_may_have_run: bool,
    pub exit_code: Option<i32>,
    pub stop_reason: Option<String>,
    pub acknowledgments_confirmed: Option<bool>,
    /// A verified installation occurred; ACK retry does not recheck caller edits.
    pub outputs_installed: bool,
    /// The observed compiler completed successfully and its outputs were installed.
    pub succeeded: bool,
    pub detail: Option<String>,
    /// Optional lossy tail from this exact live execution attempt. Never persisted
    /// and never a substitute for the independently verified terminal diagnostics.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub live_diagnostics: Option<Value>,
}

/// Only the actual execution adapter can supply observed delivery outcomes.
#[derive(Debug)]
pub enum OperationOutcome {
    Completed {
        result: Value,
    },
    Cancelled {
        result: Value,
    },
    Failed {
        detail: String,
        execution_may_have_run: bool,
    },
    /// The native transport observed a socket interruption. Protocol, trust,
    /// filesystem and cancellation errors cannot construct this via the adapter.
    TransportInterrupted {
        detail: String,
        execution_may_have_run: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u32,
    spec: PreparedOperationSpec,
    /// Retain the exact ordered placement intent without changing execution or
    /// recovery identity. Older singleton records intentionally omit this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    worker_pool: Option<Vec<PreparedWorker>>,
    request: Value,
    request_sha256: String,
    /// Version 2 additionally binds the complete numeric execution request.
    /// The stable intent fingerprint deliberately excludes its assigned ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    allocated_request_sha256: Option<String>,
    order: u64,
    attempt: u64,
    #[serde(default)]
    automatic_recoveries: u8,
    #[serde(default)]
    recovery_pending: bool,
    #[serde(default)]
    recovery_origin_attempt: Option<u64>,
    state: OperationState,
    mode: StoredMode,
    delivery: PathBuf,
    prior_deliveries: Vec<PathBuf>,
    resume_from: Option<PathBuf>,
    listen_address: Option<String>,
    bound_address: Option<String>,
    cancel_requested: bool,
    execution_may_have_run: bool,
    exit_code: Option<i32>,
    stop_reason: Option<String>,
    acknowledgments_confirmed: Option<bool>,
    outputs_installed: bool,
    detail: Option<String>,
}

impl Record {
    fn allocation_pending(&self) -> bool {
        self.version == 2 && self.request["request_id"].as_str() == Some("allocate")
    }

    fn status(&self) -> OperationStatus {
        OperationStatus {
            id: self.spec.id.clone(),
            state: self.state,
            request_sha256: self.request_sha256.clone(),
            request_id: self.request["request_id"].as_u64(),
            attempt: self.attempt,
            automatic_recoveries: self.automatic_recoveries,
            recovery_pending: self.recovery_pending,
            recovery_origin_attempt: self.recovery_origin_attempt,
            address: self.spec.address.clone(),
            listen_address: self.listen_address.clone(),
            worker: self.spec.worker.clone(),
            worker_spki_sha256: self.spec.worker_spki_sha256.clone(),
            bundle: self.spec.bundle.clone(),
            delivery: self.delivery.clone(),
            output: self.spec.output.clone(),
            mode: match self.mode {
                StoredMode::Execute => "execute",
                StoredMode::Resume => "resume",
                StoredMode::Acknowledge => "acknowledge",
                StoredMode::LocalRecovery => "recover-local",
            },
            cancel_requested: self.cancel_requested,
            execution_may_have_run: self.execution_may_have_run,
            exit_code: self.exit_code,
            stop_reason: self.stop_reason.clone(),
            acknowledgments_confirmed: self.acknowledgments_confirmed,
            outputs_installed: self.outputs_installed,
            succeeded: self.state == OperationState::Completed
                && self.exit_code == Some(0)
                && self.stop_reason.is_none()
                && self.outputs_installed,
            detail: self.detail.clone(),
            live_diagnostics: None,
        }
    }

    fn weight(&self) -> io::Result<usize> {
        Ok(serde_json::to_vec(&self.request)?.len()
            + serde_json::to_vec(&self.spec)?.len()
            + self
                .worker_pool
                .as_ref()
                .map(serde_json::to_vec)
                .transpose()?
                .map_or(0, |bytes| bytes.len())
            + RECORD_OVERHEAD)
    }

    fn unresolved(&self) -> bool {
        self.state == OperationState::Uncertain
            || (self.state == OperationState::Queued && self.mode != StoredMode::Execute)
            || (matches!(
                self.state,
                OperationState::Completed | OperationState::Cancelled
            ) && self.execution_may_have_run
                && self.acknowledgments_confirmed != Some(true))
    }

    fn paths(&self) -> Vec<&Path> {
        let mut paths = vec![
            self.spec.bundle.as_path(),
            self.delivery.as_path(),
            self.spec.output.as_path(),
        ];
        paths.extend(self.prior_deliveries.iter().map(PathBuf::as_path));
        if let Some(path) = &self.resume_from {
            paths.push(path);
        }
        paths
    }
}

#[derive(Debug)]
struct State {
    records: BTreeMap<String, Record>,
    active: BTreeMap<String, OperationCancellation>,
    /// Runtime-only monotonic deadlines. Reopening a pending durable recovery
    /// starts its full backoff again without relying on wall-clock continuity.
    recovery_ready: BTreeMap<String, Instant>,
    retained_bytes: usize,
    next_order: u64,
    archive_revision: u64,
    accepting: bool,
    poisoned: bool,
}

#[derive(Debug)]
enum AutomaticRecovery {
    Resume(PathBuf),
    Acknowledge,
}

#[derive(Debug)]
struct StoreLock(File);
impl Drop for StoreLock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

/// One durable queue shared by the daemon's bounded worker threads.
#[derive(Debug)]
pub struct PreparedOperationStore {
    root: PathBuf,
    _lock: StoreLock,
    state: Mutex<State>,
    previews: preview::PreviewRegistry,
    changed: Condvar,
    #[cfg(test)]
    fail_after_rename: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    fail_after_archive_rename: std::sync::atomic::AtomicBool,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn require(condition: bool, message: &str) -> io::Result<()> {
    if condition {
        Ok(())
    } else {
        Err(invalid(message))
    }
}
fn valid_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn overlap(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn endpoints_overlap(left: SocketAddr, right: SocketAddr) -> bool {
    let canonical_ip = |address: SocketAddr| match address.ip() {
        std::net::IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(std::net::IpAddr::V4)
            .unwrap_or(std::net::IpAddr::V6(ip)),
        ip => ip,
    };
    let left_ip = canonical_ip(left);
    let right_ip = canonical_ip(right);
    left.port() != 0
        && left.port() == right.port()
        && (left_ip == right_ip
            // A wildcard listener may own every local interface, including a
            // dual-stack IPv6 socket. Do not place simultaneous jobs there.
            || left_ip.is_unspecified()
            || right_ip.is_unspecified())
}

fn worker_owns_record(worker: &PreparedWorker, record: &Record) -> bool {
    worker.worker == record.spec.worker
        || worker.worker_spki_sha256 == record.spec.worker_spki_sha256
        || worker.address.parse::<SocketAddr>().is_ok_and(|candidate| {
            record
                .bound_address
                .as_deref()
                .unwrap_or(&record.spec.address)
                .parse::<SocketAddr>()
                .is_ok_and(|other| endpoints_overlap(candidate, other))
        })
}

/// Prefer a worker that recently finished this exact captured Cargo command
/// when queue loads are equal. The existing allocated-intent fingerprint binds
/// every captured source, toolchain, command and extension byte except the wire
/// request ID. Do not infer source-edit compatibility here: the worker alone
/// validates and chooses retained targets, and Cargo still executes normally.
///
/// Resolved ordinary failures can also leave useful targets. Cancellation,
/// stopped processes, uncertain ownership and jobs never dispatched cannot.
/// This uses only bounded live history and never changes durable request or
/// recovery identity. Missing or evicted worker targets merely make it a miss.
fn cargo_locality(
    state: &State,
    request: &Value,
    workers: &[PreparedWorker],
) -> io::Result<Vec<Option<u64>>> {
    let mut recent = vec![None; workers.len()];
    if rabs_sandbox::cargo_artifacts::requested(request)?.is_none() {
        return Ok(recent);
    }
    let fingerprint = record_request_digest(2, request)?;
    for record in state.records.values().filter(|record| {
        record.state == OperationState::Completed
            && !record.unresolved()
            && record.execution_may_have_run
            && !record.cancel_requested
            && record
                .exit_code
                .is_some_and(|code| (0..128).contains(&code))
            && record.stop_reason.is_none()
            && state.next_order.saturating_sub(record.order) <= CARGO_LOCALITY_WINDOW
    }) {
        let matches = if record.version == 2 {
            record.request_sha256 == fingerprint
        } else {
            record_request_digest(2, &record.request)? == fingerprint
        };
        if !matches {
            continue;
        }
        for (index, worker) in workers.iter().enumerate() {
            // Unlike overlapping-owner exclusion, a locality hint requires
            // all three identities. Rotating an endpoint, worker or pin must
            // not inherit another approved placement's execution history.
            if worker.address == record.spec.address
                && worker.worker == record.spec.worker
                && worker.worker_spki_sha256 == record.spec.worker_spki_sha256
            {
                recent[index] = recent[index].max(Some(record.order));
            }
        }
    }
    Ok(recent)
}

fn shares_worker_or_endpoint(left: &Record, right: &Record) -> bool {
    let endpoint = |record: &Record| {
        record
            .bound_address
            .as_deref()
            .unwrap_or(&record.spec.address)
            .parse::<SocketAddr>()
            .ok()
            .filter(|address| address.port() != 0)
    };
    left.spec.worker == right.spec.worker
        || left.spec.worker_spki_sha256 == right.spec.worker_spki_sha256
        || endpoint(left)
            .is_some_and(|left| endpoint(right).is_some_and(|right| endpoints_overlap(left, right)))
}

/// A captured bundle is read-only during dispatch, unlike delivery/output state.
/// Permit only the exact same bundle and saved input identity to be shared.
/// Allocated jobs retain that identity after binding different numeric IDs;
/// neither claiming a job nor allocating its ID rewrites the bundle template.
/// The adapter still revalidates each upload against its saved numeric request.
fn conflicting_active_paths(left: &Record, right: &Record) -> bool {
    let share_bundle = left.spec.bundle == right.spec.bundle
        && left.version == right.version
        && left.request_sha256 == right.request_sha256;
    let left_paths = left.paths();
    let right_paths = right.paths();
    left_paths.iter().enumerate().any(|(left_index, left)| {
        right_paths.iter().enumerate().any(|(right_index, right)| {
            // paths() puts the input bundle first. All remaining roles stay
            // exclusive, including prior deliveries and recovery prefixes.
            // Compare roles, not path equality: a destination or prefix equal
            // to a bundle must never inherit its read-sharing exception.
            !(share_bundle && left_index == 0 && right_index == 0) && overlap(left, right)
        })
    })
}

fn bounded_detail(value: &str) -> String {
    let mut end = value.len().min(MAX_DETAIL_BYTES);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

fn path_shape(path: &Path) -> bool {
    path.is_absolute()
        && path.file_name().is_some()
        && path.as_os_str().len() <= 4096
        && path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
}

fn ordinary_directory(path: &Path, allow_missing: bool) -> io::Result<()> {
    require(
        path_shape(path),
        "operation paths must be bounded named absolute paths without traversal",
    )?;
    let mut prefix = PathBuf::new();
    for part in path.components() {
        prefix.push(part.as_os_str());
        match fs::symlink_metadata(&prefix) {
            Ok(metadata) => require(
                metadata.is_dir(),
                "operation path contains a link or non-directory",
            )?,
            Err(error)
                if allow_missing && prefix == path && error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn validate_spec_shape(spec: &PreparedOperationSpec) -> io::Result<()> {
    require(
        valid_id(&spec.id),
        "operation id must be 32 lowercase hexadecimal characters",
    )?;
    spec.address
        .parse::<SocketAddr>()
        .map_err(|_| invalid("worker listener must be an IP:port"))?;
    require(
        !spec.worker.is_empty()
            && spec.worker.len() <= 1024
            && !spec.worker.chars().any(char::is_control),
        "worker name must be bounded and nonempty",
    )?;
    parse_worker_pin(&spec.worker_spki_sha256)?;
    for path in [&spec.bundle, &spec.delivery, &spec.output] {
        require(path_shape(path), "invalid operation directory")?;
    }
    for (left, right) in [
        (&spec.bundle, &spec.delivery),
        (&spec.bundle, &spec.output),
        (&spec.delivery, &spec.output),
    ] {
        require(
            !overlap(left, right),
            "operation bundle, delivery and output overlap",
        )?;
    }
    Ok(())
}

fn validate_worker_pool(workers: &[PreparedWorker]) -> io::Result<()> {
    require(
        !workers.is_empty() && workers.len() <= MAX_PREPARED_WORKERS,
        "canonical worker pool requires 1..=32 workers",
    )?;
    let mut names = BTreeSet::new();
    let mut pins = BTreeSet::new();
    let mut endpoints = Vec::new();
    for worker in workers {
        require(
            worker.worker.len() <= 128
                && worker
                    .worker
                    .bytes()
                    .next()
                    .is_some_and(|byte| byte.is_ascii_alphanumeric())
                && worker
                    .worker
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')),
            "canonical pool worker name must be a bounded ASCII identifier",
        )?;
        parse_worker_pin(&worker.worker_spki_sha256)?;
        let endpoint = worker
            .address
            .parse::<SocketAddr>()
            .map_err(|_| invalid("canonical pool listener must be a literal IP:port"))?;
        require(
            worker.address.len() <= 128 && endpoint.port() != 0,
            "canonical pool listener requires a bounded address and nonzero port",
        )?;
        require(
            names.insert(worker.worker.as_str())
                && pins.insert(worker.worker_spki_sha256.as_str())
                && endpoints
                    .iter()
                    .all(|other| !endpoints_overlap(endpoint, *other)),
            "canonical worker pool repeats a worker, pin or overlapping listener",
        )?;
        endpoints.push(endpoint);
    }
    require(
        serde_json::to_vec(workers)?.len() <= MAX_WORKER_POOL_BYTES,
        "canonical worker pool exceeds its byte limit",
    )
}

fn validate_record_pool(record: &Record) -> io::Result<()> {
    if let Some(workers) = &record.worker_pool {
        validate_worker_pool(workers)?;
        require(
            record.version == 2
                && workers.iter().any(|worker| {
                    worker.address == record.spec.address
                        && worker.worker == record.spec.worker
                        && worker.worker_spki_sha256 == record.spec.worker_spki_sha256
                }),
            "pooled operation does not bind an approved allocated worker",
        )?;
    }
    Ok(())
}

fn validate_bound_request(request: &Value) -> io::Result<()> {
    validate_request(request)?;
    require(
        request_manifest(request)?.is_some() && request.get("artifacts").is_some(),
        "prepared operations require source_manifest and declared artifacts",
    )?;
    require(
        toolchain_identity(request)?.is_some(),
        "prepared operations require pinned toolchain_identity",
    )
}

/// Allocation intent is accepted only on the explicit local daemon API. Probe
/// all ordinary execution/source/toolchain constraints without turning the
/// template into a wire request or assigning it a placeholder identity.
fn validate_allocation_template(request: &Value) -> io::Result<()> {
    require(
        request["kind"] == "canonical-exec" && request["request_id"].as_str() == Some("allocate"),
        "daemon allocation requires an explicit prepared request template",
    )?;
    let mut probe = request.clone();
    probe["request_id"] = serde_json::json!(0);
    validate_bound_request(&probe)
}

fn record_request_digest(version: u32, request: &Value) -> io::Result<String> {
    match version {
        1 => request_digest(request),
        2 => {
            let mut intent = request.clone();
            intent["request_id"] = serde_json::json!("allocate");
            let bytes = serde_json::to_vec(&intent)?;
            require(
                bytes.len() <= MAX_FRAME_BYTES,
                "prepared intent exceeds frame budget",
            )?;
            let mut hash = Sha256::new();
            hash.update(b"rabs.prepared-operation.allocated-intent.v1\0");
            hash.update((bytes.len() as u64).to_le_bytes());
            hash.update(bytes);
            Ok(hash
                .finalize()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect())
        }
        _ => Err(invalid("unsupported prepared operation record version")),
    }
}

fn request_digest(request: &Value) -> io::Result<String> {
    let bytes = serde_json::to_vec(request)?;
    require(
        bytes.len() <= MAX_FRAME_BYTES,
        "prepared request exceeds frame budget",
    )?;
    let mut hash = Sha256::new();
    hash.update(b"rabs.prepared-operation.request.v1\0");
    hash.update((bytes.len() as u64).to_le_bytes());
    hash.update(bytes);
    Ok(hash
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn read_bounded(path: &Path, limit: usize, private: bool) -> io::Result<Vec<u8>> {
    let named = fs::symlink_metadata(path)?;
    require(
        named.is_file() && named.len() <= limit as u64,
        "state/request must be a bounded ordinary file",
    )?;
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        require(
            named.nlink() == 1 && named.permissions().mode() & 0o077 == 0,
            "operation state must be private with one link",
        )?;
    }
    let file = File::open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let opened = file.metadata()?;
        require(
            opened.dev() == named.dev() && opened.ino() == named.ino(),
            "state/request changed while opening",
        )?;
    }
    let mut bytes = Vec::new();
    file.take((limit + 1) as u64).read_to_end(&mut bytes)?;
    require(bytes.len() <= limit, "state/request exceeds byte budget")?;
    Ok(bytes)
}

impl PreparedOperationStore {
    pub fn open(root: &Path) -> io::Result<Arc<Self>> {
        ordinary_directory(root, true)?;
        if !root.exists() {
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(root)?;
            File::open(
                root.parent()
                    .ok_or_else(|| invalid("operation state parent missing"))?,
            )?
            .sync_all()?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            require(
                fs::metadata(root)?.permissions().mode() & 0o077 == 0,
                "operation state root must be private (0700)",
            )?;
        }
        let root = root.canonicalize()?;
        let lock_path = root.join(".operations.lock");
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = match options.open(&lock_path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                read_bounded(&lock_path, 0, true)?;
                OpenOptions::new().read(true).write(true).open(&lock_path)?
            }
            Err(error) => return Err(error),
        };
        lock.try_lock().map_err(|error| {
            io::Error::other(format!("prepared operation store already owned: {error}"))
        })?;
        let lock = StoreLock(lock);
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let named = fs::symlink_metadata(&lock_path)?;
            let opened = lock.0.metadata()?;
            require(
                named.is_file()
                    && named.dev() == opened.dev()
                    && named.ino() == opened.ino()
                    && named.nlink() == 1,
                "operation lock changed while opening",
            )?;
        }
        lock.0.sync_all()?;
        File::open(&root)?.sync_all()?;
        archival::prepare_archive(&root)?;
        let mut records = BTreeMap::new();
        let mut retained_bytes = 0usize;
        let mut next_order = 1u64;
        let mut recovery_ready = BTreeMap::new();
        for entry in fs::read_dir(&root)? {
            let path = entry?.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            require(
                records.len() < MAX_OPERATIONS,
                "too many retained prepared operations",
            )?;
            let record = archival::load_record(&root, &path)?;
            retained_bytes = retained_bytes
                .checked_add(record.weight()?)
                .ok_or_else(|| invalid("operation storage budget overflow"))?;
            require(
                retained_bytes <= MAX_RETAINED_BYTES,
                "prepared operation byte budget exceeded",
            )?;
            next_order = next_order.max(
                record
                    .order
                    .checked_add(1)
                    .ok_or_else(|| invalid("operation queue order exhausted"))?,
            );
            if record.recovery_pending {
                recovery_ready.insert(
                    record.spec.id.clone(),
                    Instant::now() + recovery_delay(record.automatic_recoveries),
                );
            }
            require(
                records.insert(record.spec.id.clone(), record).is_none(),
                "duplicate prepared operation id",
            )?;
        }
        let store = Arc::new(Self {
            root,
            _lock: lock,
            state: Mutex::new(State {
                records,
                active: BTreeMap::new(),
                recovery_ready,
                retained_bytes,
                next_order,
                archive_revision: 0,
                accepting: true,
                poisoned: false,
            }),
            changed: Condvar::new(),
            previews: preview::PreviewRegistry::default(),
            #[cfg(test)]
            fail_after_rename: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            fail_after_archive_rename: std::sync::atomic::AtomicBool::new(false),
        });
        {
            let mut state = store.lock_state()?;
            // History stays on disk, but startup still verifies every archived
            // identity and detects duplicate live/archive records before work.
            store.for_each_archived(|record| {
                require(
                    !state.records.contains_key(&record.spec.id),
                    "operation exists in both live and archived storage",
                )?;
                state.next_order = state.next_order.max(
                    record
                        .order
                        .checked_add(1)
                        .ok_or_else(|| invalid("operation queue order exhausted"))?,
                );
                Ok(())
            })?;
            let recover: Vec<_> = state
                .records
                .values()
                .filter(|r| {
                    matches!(
                        r.state,
                        OperationState::Running | OperationState::Cancelling
                    )
                })
                .cloned()
                .collect();
            for mut record in recover {
                let pending = record.allocation_pending();
                record.state = if pending {
                    OperationState::FailedBeforeStart
                } else {
                    OperationState::Uncertain
                };
                record.execution_may_have_run = !pending;
                record.listen_address = None;
                record.recovery_pending = false;
                record.detail = Some(if pending {
                    "daemon owner stopped before binding a worker request; no execution was dispatched"
                } else {
                    "daemon owner stopped before a terminal result; explicit resume required"
                }.into());
                store.replace(&mut state, record)?;
            }
        }
        Ok(store)
    }

    fn lock_state(&self) -> io::Result<std::sync::MutexGuard<'_, State>> {
        let state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("prepared operation lock poisoned"))?;
        require(
            !state.poisoned,
            "prepared operation persistence uncertain; restart required",
        )?;
        Ok(state)
    }

    fn persist(&self, record: &Record) -> io::Result<()> {
        let bytes = serde_json::to_vec(record)?;
        require(
            bytes.len() <= MAX_RECORD_BYTES,
            "prepared operation record exceeds byte budget",
        )?;
        let destination = self.root.join(format!("{}.json", record.spec.id));
        if destination.exists() {
            read_bounded(&destination, MAX_RECORD_BYTES, true)?;
        }
        let mut temporary = tempfile::NamedTempFile::new_in(&self.root)?;
        temporary.write_all(&bytes)?;
        temporary.as_file().sync_all()?;
        temporary
            .persist(&destination)
            .map_err(|error| error.error)?;
        #[cfg(test)]
        if self
            .fail_after_rename
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(io::Error::other("injected failure after operation rename"));
        }
        File::open(&self.root)?.sync_all()
    }

    fn replace(&self, state: &mut State, record: Record) -> io::Result<()> {
        if let Err(error) = self.persist(&record) {
            self.poison(state);
            return Err(error);
        }
        state.records.insert(record.spec.id.clone(), record);
        self.changed.notify_all();
        Ok(())
    }

    fn validate_paths(&self, spec: &PreparedOperationSpec) -> io::Result<()> {
        validate_spec_shape(spec)?;
        ordinary_directory(&spec.bundle, false)?;
        ordinary_directory(&spec.delivery, true)?;
        ordinary_directory(&spec.output, true)?;
        for path in [&spec.bundle, &spec.delivery, &spec.output] {
            require(
                !overlap(path, &self.root),
                "operation paths overlap daemon state",
            )?;
        }
        Ok(())
    }

    pub fn submit(&self, spec: PreparedOperationSpec) -> io::Result<OperationStatus> {
        self.submit_inner(spec, false, None)
    }

    /// Admit a fully captured template, leaving request allocation to its sole
    /// claimed execution owner. Queue order cannot be overtaken by allocating
    /// IDs in clients, and a client disconnect does not relinquish saved work.
    pub fn submit_allocated(&self, spec: PreparedOperationSpec) -> io::Result<OperationStatus> {
        self.submit_inner(spec, true, None)
    }

    /// Select one approved worker under durable admission ownership. Busy
    /// workers remain queue candidates; unresolved execution ownership does
    /// not. Retries and restart retain the selected worker, never fail over.
    pub fn submit_allocated_pool(
        &self,
        spec: PreparedPoolOperationSpec,
    ) -> io::Result<OperationStatus> {
        spec.validate()?;
        let first = spec
            .workers
            .first()
            .ok_or_else(|| invalid("canonical worker pool is empty"))?;
        let operation = PreparedOperationSpec {
            id: spec.id,
            address: first.address.clone(),
            worker: first.worker.clone(),
            worker_spki_sha256: first.worker_spki_sha256.clone(),
            bundle: spec.bundle,
            delivery: spec.delivery,
            output: spec.output,
        };
        self.submit_inner(operation, true, Some(spec.workers))
    }

    fn submit_inner(
        &self,
        mut spec: PreparedOperationSpec,
        allocate: bool,
        worker_pool: Option<Vec<PreparedWorker>>,
    ) -> io::Result<OperationStatus> {
        self.validate_paths(&spec)?;
        let request: Value = serde_json::from_slice(&read_bounded(
            &spec.bundle.join("request.json"),
            MAX_FRAME_BYTES,
            false,
        )?)?;
        let version = if allocate { 2 } else { 1 };
        if allocate {
            validate_allocation_template(&request)?;
        } else {
            validate_bound_request(&request)?;
        }
        let fingerprint = record_request_digest(version, &request)?;
        let existing_status = |record: Record| -> io::Result<OperationStatus> {
            let mut accepted = record.request.clone();
            if allocate {
                accepted["request_id"] = serde_json::json!("allocate");
            }
            let mut intended_spec = spec.clone();
            if worker_pool.is_some() {
                // Exact pool identity binds the previously selected placement.
                // Do not rerun selection against a changed queue on retry.
                intended_spec.address = record.spec.address.clone();
                intended_spec.worker = record.spec.worker.clone();
                intended_spec.worker_spki_sha256 = record.spec.worker_spki_sha256.clone();
            }
            require(
                record.version == version
                    && record.spec == intended_spec
                    && record.worker_pool == worker_pool
                    && accepted == request
                    && record.request_sha256 == fingerprint,
                "operation id already belongs to another request or destination",
            )?;
            Ok(record.status())
        };
        {
            let state = self.lock_state()?;
            require(state.accepting, "prepared operation service is stopping")?;
            if let Some(record) = self.read_record(&state, &spec.id)? {
                return existing_status(record);
            }
        }
        // Scan cold history without holding cancellation/status behind disk
        // reads. Once the archive revision is stable, the same lock protects
        // checking the current live set through admission and persistence.
        let check_paths = |existing: &Record| -> io::Result<()> {
            if existing.spec.id == spec.id {
                return Ok(());
            }
            for destination in [&spec.delivery, &spec.output] {
                require(
                    existing
                        .paths()
                        .iter()
                        .all(|path| !overlap(destination, path)),
                    "destination overlaps retained operation",
                )?;
            }
            for destination in std::iter::once(existing.delivery.as_path())
                .chain(existing.prior_deliveries.iter().map(PathBuf::as_path))
                .chain(std::iter::once(existing.spec.output.as_path()))
            {
                require(
                    !overlap(&spec.bundle, destination),
                    "bundle overlaps retained operation destination",
                )?;
            }
            Ok(())
        };
        let mut state = self.lock_after_archived_check(&check_paths)?;
        require(state.accepting, "prepared operation service is stopping")?;
        if let Some(record) = self.read_record(&state, &spec.id)? {
            return existing_status(record);
        }
        for existing in state.records.values() {
            check_paths(existing)?;
        }
        if let Some(workers) = &worker_pool {
            let locality = cargo_locality(&state, &request, workers)?;
            let (_, selected) = workers
                .iter()
                .enumerate()
                .filter(|(_, worker)| {
                    state
                        .records
                        .values()
                        .all(|record| !record.unresolved() || !worker_owns_record(worker, record))
                })
                .min_by_key(|(index, worker)| {
                    let load = state
                        .records
                        .values()
                        .filter(|record| {
                            matches!(
                                record.state,
                                OperationState::Queued
                                    | OperationState::Running
                                    | OperationState::Cancelling
                            ) && worker_owns_record(worker, record)
                        })
                        .count();
                    (load, std::cmp::Reverse(locality[*index]), *index)
                })
                .ok_or_else(|| invalid("all canonical pool workers have unresolved ownership"))?;
            spec.address = selected.address.clone();
            spec.worker = selected.worker.clone();
            spec.worker_spki_sha256 = selected.worker_spki_sha256.clone();
        }
        let record = Record {
            version,
            delivery: spec.delivery.clone(),
            spec,
            worker_pool,
            request,
            request_sha256: fingerprint,
            allocated_request_sha256: None,
            order: state.next_order,
            attempt: 0,
            automatic_recoveries: 0,
            recovery_pending: false,
            recovery_origin_attempt: None,
            state: OperationState::Queued,
            mode: StoredMode::Execute,
            prior_deliveries: Vec::new(),
            resume_from: None,
            listen_address: None,
            bound_address: None,
            cancel_requested: false,
            execution_may_have_run: false,
            exit_code: None,
            stop_reason: None,
            acknowledgments_confirmed: None,
            outputs_installed: false,
            detail: None,
        };
        let weight = record.weight()?;
        self.make_room(&mut state, weight)?;
        state.next_order = state
            .next_order
            .checked_add(1)
            .ok_or_else(|| invalid("operation queue exhausted"))?;
        let status = record.status();
        self.replace(&mut state, record)?;
        state.retained_bytes += weight;
        Ok(status)
    }

    pub fn status(&self, id: &str) -> io::Result<Option<OperationStatus>> {
        require(valid_id(id), "invalid operation id")?;
        // Release the durable state lock before looking at optional diagnostics.
        // The existing preview registry uses try_lock and binds its response to
        // the exact saved request and attempt captured by this status snapshot.
        let mut status = {
            let state = self.lock_state()?;
            self.read_record(&state, id)?.map(|record| record.status())
        };
        if let Some(status) = &mut status
            && status.mode == "execute"
            && matches!(
                status.state,
                OperationState::Running | OperationState::Cancelling
            )
        {
            status.live_diagnostics = self
                .preview(id, &status.request_sha256, status.attempt, 0, 0)
                .ok()
                .filter(|reply| reply["available"] == true);
            // Missing support, contention, closure, or a racing recovery omits
            // the field. None is not an empty stream or terminal evidence.
        }
        Ok(status)
    }

    pub fn cancel(&self, id: &str) -> io::Result<OperationStatus> {
        let mut state = self.lock_state()?;
        let mut record = self
            .read_record(&state, id)?
            .ok_or_else(|| invalid("unknown prepared operation"))?;
        match record.state {
            OperationState::Queued => {
                record.cancel_requested = true;
                record.recovery_pending = false;
                // Cancelling a recovery request says nothing about the old run.
                record.state = if record.mode != StoredMode::Execute {
                    OperationState::Uncertain
                } else {
                    OperationState::Cancelled
                };
                if record.mode == StoredMode::Execute {
                    record.exit_code = Some(130);
                    record.stop_reason = Some("cancelled".into());
                }
                record.detail = Some("cancelled before this queued dispatch".into());
            }
            OperationState::Running | OperationState::Cancelling => {
                record.cancel_requested = true;
                record.state = OperationState::Cancelling;
            }
            _ => return Ok(record.status()),
        }
        let status = record.status();
        self.replace(&mut state, record)?;
        state.recovery_ready.remove(id);
        if let Some(cancellation) = state.active.get(id) {
            cancellation.cancel();
        }
        Ok(status)
    }

    pub fn resume(
        &self,
        id: &str,
        new_delivery: PathBuf,
        resume_from: Option<PathBuf>,
    ) -> io::Result<OperationStatus> {
        require(valid_id(id), "invalid operation id")?;
        ordinary_directory(&new_delivery, true)?;
        require(
            !new_delivery.exists(),
            "resume requires a fresh delivery directory",
        )?;
        if let Some(path) = &resume_from {
            ordinary_directory(path, false)?;
        }
        let mut state = self.lock_after_archived_check(|other| {
            require(
                other
                    .paths()
                    .iter()
                    .all(|path| !overlap(&new_delivery, path)),
                "resume destination overlaps retained operation",
            )
        })?;
        require(state.accepting, "prepared operation service is stopping")?;
        let mut record = self
            .read_record(&state, id)?
            .ok_or_else(|| invalid("unknown prepared operation"))?;
        require(
            record.unresolved() && !state.active.contains_key(id),
            "only unresolved operations may resume",
        )?;
        require(
            record.prior_deliveries.len() < 16,
            "operation resume directory limit exhausted",
        )?;
        for path in [&record.spec.bundle, &record.spec.output, &self.root] {
            require(
                !overlap(&new_delivery, path),
                "resume destination overlaps bundle, output or state",
            )?;
        }
        for other in state.records.values() {
            require(
                other
                    .paths()
                    .iter()
                    .all(|path| !overlap(&new_delivery, path)),
                "resume destination overlaps retained operation",
            )?;
        }
        if let Some(path) = &resume_from {
            require(
                !overlap(path, &new_delivery)
                    && !overlap(path, &record.spec.bundle)
                    && !overlap(path, &record.spec.output)
                    && !overlap(path, &self.root),
                "resume prefixes overlap writable or input paths",
            )?;
        }
        record.prior_deliveries.push(record.delivery.clone());
        record.delivery = new_delivery;
        record.resume_from = resume_from;
        record.mode = StoredMode::Resume;
        record.state = OperationState::Queued;
        record.cancel_requested = false;
        record.recovery_pending = false;
        record.recovery_origin_attempt = None;
        record.listen_address = None;
        record.detail = None;
        record.order = state.next_order;
        state.next_order = state
            .next_order
            .checked_add(1)
            .ok_or_else(|| invalid("operation queue exhausted"))?;
        let status = record.status();
        self.replace(&mut state, record)?;
        state.recovery_ready.remove(id);
        Ok(status)
    }

    /// Retry only acceptance of an existing verified delivery. The worker may
    /// already have released its result bytes, so this never downloads them or
    /// turns a lost acknowledgment into another execution.
    pub fn acknowledge(&self, id: &str, delivery: PathBuf) -> io::Result<OperationStatus> {
        ordinary_directory(&delivery, false)?;
        let mut state = self.lock_state()?;
        require(state.accepting, "prepared operation service is stopping")?;
        let mut record = self
            .read_record(&state, id)?
            .ok_or_else(|| invalid("unknown prepared operation"))?;
        require(
            record.unresolved() && !state.active.contains_key(id),
            "only unresolved operations may retry acknowledgment",
        )?;
        require(
            delivery == record.delivery || record.prior_deliveries.contains(&delivery),
            "acknowledgment requires an owned delivery directory",
        )?;
        if record.mode == StoredMode::Acknowledge
            && record.state == OperationState::Queued
            && record.delivery == delivery
        {
            return Ok(record.status());
        }
        if delivery != record.delivery {
            record.prior_deliveries.retain(|path| path != &delivery);
            record.prior_deliveries.push(record.delivery.clone());
            record.delivery = delivery;
        }
        record.mode = StoredMode::Acknowledge;
        record.state = OperationState::Queued;
        record.resume_from = None;
        record.cancel_requested = false;
        record.recovery_pending = false;
        record.recovery_origin_attempt = None;
        record.listen_address = None;
        record.detail = None;
        record.order = state.next_order;
        state.next_order = state
            .next_order
            .checked_add(1)
            .ok_or_else(|| invalid("operation queue exhausted"))?;
        let status = record.status();
        self.replace(&mut state, record)?;
        state.recovery_ready.remove(id);
        Ok(status)
    }

    pub fn claim_next(self: &Arc<Self>) -> io::Result<Option<OperationClaim>> {
        self.claim_next_at(Instant::now())
    }

    fn claim_next_at(self: &Arc<Self>, now: Instant) -> io::Result<Option<OperationClaim>> {
        let mut state = self.lock_state()?;
        if !state.accepting || state.active.len() >= MAX_RUNNING {
            return Ok(None);
        }
        let next = state
            .records
            .values()
            .filter(|record| {
                record.state == OperationState::Queued && record.mode != StoredMode::LocalRecovery
            })
            .filter(|record| {
                !record.recovery_pending
                    || state
                        .recovery_ready
                        .get(&record.spec.id)
                        .is_some_and(|ready| *ready <= now)
            })
            .filter(|record| {
                state.records.values().all(|other| {
                    if other.spec.id == record.spec.id {
                        return true;
                    }
                    let owns_worker =
                        state.active.contains_key(&other.spec.id) || other.unresolved();
                    (!owns_worker || !shares_worker_or_endpoint(record, other))
                        && (!state.active.contains_key(&other.spec.id)
                            || !conflicting_active_paths(record, other))
                })
            })
            .min_by_key(|record| record.order)
            .cloned();
        let Some(mut record) = next else {
            return Ok(None);
        };
        record.state = OperationState::Running;
        record.recovery_pending = false;
        record.attempt = record
            .attempt
            .checked_add(1)
            .ok_or_else(|| invalid("operation attempts exhausted"))?;
        // Persist this before the callback can listen, upload, or send execution.
        record.execution_may_have_run = !record.allocation_pending();
        let cancellation = OperationCancellation::default();
        let mut spec = record.spec.clone();
        spec.delivery = record.delivery.clone();
        if record.mode != StoredMode::Execute
            && let Some(address) = &record.bound_address
        {
            spec.address = address.clone();
        }
        self.replace(&mut state, record.clone())?;
        state.recovery_ready.remove(&spec.id);
        state.active.insert(spec.id.clone(), cancellation.clone());
        let preview = if record.mode == StoredMode::Execute {
            self.previews
                .register(&spec.id, &record.request_sha256, record.attempt)
        } else {
            None
        };
        let claim = OperationClaim {
            store: Arc::clone(self),
            spec,
            request: record.request.clone(),
            allocation_pending: record.allocation_pending(),
            mode: record.mode,
            resume_from: record.resume_from.clone(),
            attempt: record.attempt,
            cancellation: cancellation.clone(),
            preview,
            finished: false,
        };
        Ok(Some(claim))
    }

    /// Shutdown leaves unclaimed requests queued and requests cleanup of owners.
    pub fn stop(&self) -> io::Result<()> {
        self.previews.stop();
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("prepared operation lock poisoned"))?;
        state.accepting = false;
        for cancellation in state.active.values() {
            cancellation.cancel();
        }
        self.changed.notify_all();
        Ok(())
    }

    /// A bounded blocking wait for dedicated driver threads, never a reactor wait.
    pub fn wait_for_work(&self, budget: Duration) {
        if let Ok(state) = self.state.lock() {
            if !state.accepting || state.poisoned {
                return;
            }
            let _ = self.changed.wait_timeout(state, budget);
        }
    }
}

/// Linear ownership of one dispatch; dropping it never queues execution again.
#[derive(Debug)]
pub struct OperationClaim {
    store: Arc<PreparedOperationStore>,
    spec: PreparedOperationSpec,
    request: Value,
    allocation_pending: bool,
    mode: StoredMode,
    resume_from: Option<PathBuf>,
    attempt: u64,
    cancellation: OperationCancellation,
    preview: Option<PreviewObserver>,
    finished: bool,
}

impl OperationClaim {
    pub fn spec(&self) -> &PreparedOperationSpec {
        &self.spec
    }
    pub fn request(&self) -> &Value {
        &self.request
    }

    pub fn needs_request_allocation(&self) -> bool {
        self.allocation_pending
    }

    /// Bind once while the caller retains the exclusive pinned-worker admission
    /// that supplied this ID. Persistence precedes any execution-capable network
    /// work. A crash after binding retains this request for result-only recovery;
    /// neither this owner nor a restarted daemon may allocate a replacement.
    pub fn bind_request_id(&mut self, request_id: u64) -> io::Result<()> {
        require(
            request_id > 0 && self.allocation_pending,
            "worker request is not awaiting allocation",
        )?;
        let mut state = self.store.lock_state()?;
        let mut record = self.current(&state)?;
        require(
            state.accepting
                && !self.cancellation.is_cancelled()
                && !record.cancel_requested
                && record.allocation_pending()
                && record.mode == StoredMode::Execute,
            "worker request allocation cancelled or already bound",
        )?;
        let old_weight = record.weight()?;
        record.request["request_id"] = serde_json::json!(request_id);
        validate_bound_request(&record.request)?;
        let execution_bytes = serde_json::to_vec(&record.request)?;
        require(
            execution_bytes.len() <= MAX_FRAME_BYTES,
            "bound worker request exceeds frame budget",
        )?;
        record.allocated_request_sha256 = Some(
            Sha256::digest(execution_bytes)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        );
        require(
            record_request_digest(record.version, &record.request)? == record.request_sha256,
            "worker request binding changed its admitted intent",
        )?;
        // Persist the execution frontier with the assigned request. The native
        // adapter still owns the reservation and validates every byte at handoff.
        record.execution_may_have_run = true;
        let new_weight = record.weight()?;
        let retained_bytes = state
            .retained_bytes
            .checked_sub(old_weight)
            .and_then(|bytes| bytes.checked_add(new_weight))
            .filter(|bytes| *bytes <= MAX_RETAINED_BYTES)
            .ok_or_else(|| invalid("operation storage budget exceeded while binding request"))?;
        self.store.replace(&mut state, record.clone())?;
        state.retained_bytes = retained_bytes;
        self.request = record.request;
        self.allocation_pending = false;
        Ok(())
    }
    pub fn mode(&self) -> DeliveryMode {
        if self.mode == StoredMode::Execute {
            DeliveryMode::Execute
        } else {
            DeliveryMode::Resume
        }
    }
    pub fn resume_from(&self) -> Option<&Path> {
        self.resume_from.as_deref()
    }
    pub fn cancellation(&self) -> OperationCancellation {
        self.cancellation.clone()
    }

    /// Optional diagnostics exist only for this original execution attempt.
    pub fn preview_observer(&self) -> Option<PreviewObserver> {
        self.preview.clone()
    }

    pub fn acknowledgment_only(&self) -> bool {
        self.mode == StoredMode::Acknowledge
    }

    pub fn listening(&self, address: SocketAddr) -> io::Result<()> {
        require(
            !self.allocation_pending,
            "unbound request cannot listen for a worker",
        )?;
        let mut state = self.store.lock_state()?;
        let mut record = self.current(&state)?;
        require(
            state.accepting && !self.cancellation.is_cancelled(),
            "operation listener cancelled before readiness",
        )?;
        require(address.port() != 0, "operation listener has no bound port")?;
        if let Some(bound) = &record.bound_address {
            require(
                bound == &address.to_string(),
                "operation recovery listener differs from the original endpoint",
            )?;
        } else {
            record.bound_address = Some(address.to_string());
        }
        record.listen_address = Some(address.to_string());
        self.store.replace(&mut state, record)
    }

    fn current(&self, state: &State) -> io::Result<Record> {
        let record = state
            .records
            .get(&self.spec.id)
            .cloned()
            .ok_or_else(|| invalid("operation claim disappeared"))?;
        require(
            record.attempt == self.attempt
                && state.active.contains_key(&self.spec.id)
                && matches!(
                    record.state,
                    OperationState::Running | OperationState::Cancelling
                ),
            "stale prepared operation claim",
        )?;
        Ok(record)
    }

    fn automatic_recovery(
        &self,
        outcome: &OperationOutcome,
    ) -> io::Result<Option<AutomaticRecovery>> {
        let acknowledge = match outcome {
            OperationOutcome::TransportInterrupted {
                execution_may_have_run: true,
                ..
            } => self.mode == StoredMode::Acknowledge,
            OperationOutcome::Completed { result } | OperationOutcome::Cancelled { result }
                if result["delivery"]["acknowledgments_confirmed"] == false
                    && result["delivery"]["acknowledgment_interrupted"] == true =>
            {
                true
            }
            _ => return Ok(None),
        };
        let state = self.store.lock_state()?;
        let record = self.current(&state)?;
        if !state.accepting
            || record.cancel_requested
            || self.cancellation.is_cancelled()
            || self.mode == StoredMode::LocalRecovery
            || record.automatic_recoveries >= MAX_AUTOMATIC_RECOVERIES
            || record.bound_address.is_none()
        {
            return Ok(None);
        }
        if acknowledge {
            return Ok(Some(AutomaticRecovery::Acknowledge));
        }
        if record.prior_deliveries.len() >= 16 {
            return Ok(None);
        }
        let parent = record
            .spec
            .delivery
            .parent()
            .ok_or_else(|| invalid("operation delivery parent disappeared"))?;
        Ok(Some(AutomaticRecovery::Resume(parent.join(format!(
            "rabs-recovery-{}-{}",
            record.spec.id,
            record.automatic_recoveries + 1,
        )))))
    }

    fn schedule_recovery(
        &self,
        state: &mut State,
        record: &mut Record,
        recovery: AutomaticRecovery,
    ) -> io::Result<()> {
        let next_order = state
            .next_order
            .checked_add(1)
            .ok_or_else(|| invalid("operation recovery queue exhausted"))?;
        match recovery {
            AutomaticRecovery::Resume(destination) => {
                // The archive was checked outside the state mutex. This final
                // live-set check and persistence share its stable revision lock,
                // exactly as ordinary resume admission does.
                require(
                    !overlap(&destination, &self.store.root)
                        && state.records.values().all(|other| {
                            other
                                .paths()
                                .iter()
                                .all(|path| !overlap(&destination, path))
                        }),
                    "automatic recovery destination overlaps retained operation",
                )?;
                require(
                    record.prior_deliveries.len() < 16,
                    "operation resume directory limit exhausted",
                )?;
                record.prior_deliveries.push(record.delivery.clone());
                record.delivery = destination;
                record.mode = StoredMode::Resume;
            }
            AutomaticRecovery::Acknowledge => record.mode = StoredMode::Acknowledge,
        }
        record.resume_from = None;
        record.state = OperationState::Queued;
        record.recovery_pending = true;
        record.recovery_origin_attempt.get_or_insert(record.attempt);
        record.automatic_recoveries += 1;
        record.order = state.next_order;
        state.next_order = next_order;
        Ok(())
    }

    pub fn finish(mut self, outcome: OperationOutcome) -> io::Result<OperationStatus> {
        if let Some(preview) = &self.preview {
            preview.close();
        }
        let (mut state, recovery, mut scheduling_error) = match self.automatic_recovery(&outcome)? {
            Some(AutomaticRecovery::Resume(destination)) => {
                // An optional retry must not turn a path collision into a fatal
                // daemon error, nor scan growing history under cancellation's
                // state mutex. A failed preflight leaves the result Uncertain.
                let prepare = || {
                    ordinary_directory(&destination, true)?;
                    require(
                        !destination.exists(),
                        "automatic recovery destination already exists",
                    )?;
                    self.store.lock_after_archived_check(|other| {
                        require(
                            other
                                .paths()
                                .iter()
                                .all(|path| !overlap(&destination, path)),
                            "automatic recovery destination overlaps archived operation",
                        )
                    })
                };
                match prepare() {
                    Ok(state) => (state, Some(AutomaticRecovery::Resume(destination)), None),
                    Err(error) => (self.store.lock_state()?, None, Some(error.to_string())),
                }
            }
            recovery => (self.store.lock_state()?, recovery, None),
        };
        let mut record = self.current(&state)?;
        record.listen_address = None;
        require(
            !record.allocation_pending()
                || matches!(
                    &outcome,
                    OperationOutcome::Failed {
                        execution_may_have_run: false,
                        ..
                    } | OperationOutcome::TransportInterrupted {
                        execution_may_have_run: false,
                        ..
                    }
                ),
            "unallocated operation cannot report an execution outcome",
        )?;
        match outcome {
            OperationOutcome::Completed { result } | OperationOutcome::Cancelled { result } => {
                let delivery = &result["delivery"];
                let receipt = &delivery["receipt"];
                let exit_code = receipt["exit_code"]
                    .as_i64()
                    .and_then(|code| i32::try_from(code).ok())
                    .filter(|code| (0..=255).contains(code))
                    .ok_or_else(|| invalid("adapter completion has no bounded exit code"))?;
                require(
                    receipt["request_id"] == record.request["request_id"]
                        && receipt["worker_id"].as_str() == Some(record.spec.worker.as_str())
                        && receipt["worker_spki_sha256"].as_str()
                            == Some(record.spec.worker_spki_sha256.as_str())
                        && receipt["transport_authenticated"] == true
                        && receipt["request_sha256"].as_str()
                            == Some(
                                Sha256::digest(serde_json::to_vec(&record.request)?)
                                    .iter()
                                    .map(|byte| format!("{byte:02x}"))
                                    .collect::<String>()
                                    .as_str(),
                            )
                        && receipt["publication_authorized"] == false
                        && result["publication_authorized"] == false,
                    "adapter completion differs from the saved operation",
                )?;
                record.state = if receipt["stop_reason"] == "cancelled" {
                    OperationState::Cancelled
                } else {
                    OperationState::Completed
                };
                record.exit_code = Some(exit_code);
                require(
                    receipt["stop_reason"].is_null()
                        || receipt["stop_reason"]
                            .as_str()
                            .is_some_and(|s| s.len() <= 128),
                    "adapter stop reason exceeds summary bound",
                )?;
                record.stop_reason = receipt["stop_reason"].as_str().map(str::to_owned);
                let succeeded = exit_code == 0 && record.stop_reason.is_none();
                if self.mode == StoredMode::Acknowledge {
                    require(
                        result["operation"] == "acknowledge"
                            && result["installed_outputs"].is_null(),
                        "acknowledgment completion must not claim a new installation",
                    )?;
                    // This records a previous verified installation, not a
                    // fresh check of operator-owned outputs during ACK retry.
                    record.outputs_installed &= succeeded;
                } else if succeeded {
                    let installed = &result["installed_outputs"];
                    require(
                        installed["kind"] == "worker-output-install"
                            && installed["directory"] == serde_json::to_value(&record.spec.output)?
                            && installed["publication_authorized"] == false
                            && installed["reexecute"] == false
                            && installed["files"].as_u64().is_some()
                            && installed["total_bytes"].as_u64().is_some()
                            && installed["reused"].as_bool().is_some(),
                        "successful adapter completion lacks the owned output installation",
                    )?;
                    record.outputs_installed = true;
                } else {
                    require(
                        result["installed_outputs"].is_null(),
                        "unsuccessful adapter completion claims installed outputs",
                    )?;
                    record.outputs_installed = false;
                }
                record.acknowledgments_confirmed = delivery["acknowledgments_confirmed"].as_bool();
                require(
                    record.acknowledgments_confirmed.is_some(),
                    "adapter completion lacks acceptance status",
                )?;
                record.execution_may_have_run = true;
                record.detail = delivery["acknowledgment_error"]
                    .as_str()
                    .map(bounded_detail);
            }
            OperationOutcome::Failed {
                detail,
                execution_may_have_run,
            }
            | OperationOutcome::TransportInterrupted {
                detail,
                execution_may_have_run,
            } => {
                // A failed resume never disproves an earlier uncertain run.
                record.execution_may_have_run =
                    execution_may_have_run || self.mode != StoredMode::Execute;
                record.state = if self.mode == StoredMode::Acknowledge
                    && record.exit_code.is_some()
                    && record.acknowledgments_confirmed.is_some()
                {
                    // A failed release exchange cannot erase the already
                    // verified compiler outcome or installed local bytes. Keep
                    // the worker reserved through unresolved() while callers
                    // can still consume that proven completion.
                    record.acknowledgments_confirmed = Some(false);
                    if record.stop_reason.as_deref() == Some("cancelled") {
                        OperationState::Cancelled
                    } else {
                        OperationState::Completed
                    }
                } else if record.execution_may_have_run {
                    OperationState::Uncertain
                } else if record.cancel_requested {
                    record.exit_code = Some(130);
                    record.stop_reason = Some("cancelled".into());
                    OperationState::Cancelled
                } else {
                    OperationState::FailedBeforeStart
                };
                record.detail = Some(bounded_detail(&detail));
            }
        }
        if let Some(recovery) = recovery
            && state.accepting
            && !record.cancel_requested
            && !self.cancellation.is_cancelled()
            && record.unresolved()
            && let Err(error) = self.schedule_recovery(&mut state, &mut record, recovery)
        {
            scheduling_error = Some(error.to_string());
        }
        if let Some(error) = scheduling_error {
            record.detail = Some(bounded_detail(&format!(
                "{}; automatic result recovery unavailable: {error}",
                record
                    .detail
                    .as_deref()
                    .unwrap_or("worker delivery interrupted"),
            )));
        }
        let status = record.status();
        let recovery_ready = record
            .recovery_pending
            .then(|| Instant::now() + recovery_delay(record.automatic_recoveries));
        self.store.replace(&mut state, record)?;
        if let Some(ready) = recovery_ready {
            state.recovery_ready.insert(self.spec.id.clone(), ready);
        }
        state.active.remove(&self.spec.id);
        self.finished = true;
        self.store.changed.notify_all();
        Ok(status)
    }
}

impl Drop for OperationClaim {
    fn drop(&mut self) {
        if let Some(preview) = &self.preview {
            preview.close();
        }
        if self.finished {
            return;
        }
        self.cancellation.cancel();
        if let Ok(mut state) = self.store.state.lock()
            && let Some(mut record) = state.records.get(&self.spec.id).cloned()
            && record.attempt == self.attempt
            && state.active.contains_key(&self.spec.id)
        {
            let pending = record.allocation_pending();
            record.state = if pending {
                OperationState::FailedBeforeStart
            } else {
                OperationState::Uncertain
            };
            record.execution_may_have_run = !pending;
            record.listen_address = None;
            record.detail = Some(if pending {
                "dispatch owner ended before binding a worker request; no execution was dispatched"
            } else {
                "dispatch owner ended without terminal evidence; explicit resume required"
            }.into());
            if !state.poisoned {
                let _ = self.store.replace(&mut state, record);
            }
            state.active.remove(&self.spec.id);
        }
        self.store.changed.notify_all();
    }
}

#[cfg(test)]
mod tests;

#[cfg(all(test, unix))]
mod shared_bundle_tests;

#[cfg(all(test, unix))]
mod pool_tests;
