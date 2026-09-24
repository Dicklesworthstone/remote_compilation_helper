//! Durable admission for the daemon's prepared, execution-only build service.
//!
//! The saved request is an operation identity, never an ActionDescriptor or a
//! cache key. An exclusive local owner records Running before invoking the real
//! worker adapter. Lost owners become Uncertain, and only an explicit result
//! resume can proceed thereafter. Source bytes are revalidated against the saved
//! manifest by the execution adapter; a mutable bundle cannot change the request.
//! State and build directories are operator-owned, not hostile shared storage.

mod completion;
pub use completion::{DiagnosticSnapshot, DiagnosticStream, PreparedCompletion};

use super::secure_worker_delivery::{OperationCancellation, parse_worker_pin};
use super::source_delivery::request_manifest;
use super::worker_delivery::{DeliveryMode, MAX_FRAME_BYTES, toolchain_identity, validate_request};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

const MAX_OPERATIONS: usize = 1024;
const MAX_RETAINED_BYTES: usize = 64 * 1024 * 1024;
const RECORD_OVERHEAD: usize = 96 * 1024;
const MAX_RECORD_BYTES: usize = MAX_FRAME_BYTES + RECORD_OVERHEAD;
const MAX_DETAIL_BYTES: usize = 2048;
const MAX_RUNNING: usize = 4;

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
}

/// Bounded status; full compiler artifacts and receipts stay in the delivery.
#[derive(Debug, Clone, Serialize)]
pub struct OperationStatus {
    pub id: String,
    pub state: OperationState,
    pub request_sha256: String,
    pub request_id: u64,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u32,
    spec: PreparedOperationSpec,
    request: Value,
    request_sha256: String,
    order: u64,
    attempt: u64,
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
    fn status(&self) -> OperationStatus {
        OperationStatus {
            id: self.spec.id.clone(),
            state: self.state,
            request_sha256: self.request_sha256.clone(),
            request_id: self.request["request_id"]
                .as_u64()
                .expect("validated request"),
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
        }
    }

    fn weight(&self) -> io::Result<usize> {
        Ok(serde_json::to_vec(&self.request)?.len()
            + serde_json::to_vec(&self.spec)?.len()
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
    retained_bytes: usize,
    next_order: u64,
    accepting: bool,
    poisoned: bool,
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
    changed: Condvar,
    #[cfg(test)]
    fail_after_rename: std::sync::atomic::AtomicBool,
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
fn same_worker(left: &PreparedOperationSpec, right: &PreparedOperationSpec) -> bool {
    left.worker == right.worker
        || left.worker_spki_sha256 == right.worker_spki_sha256
        || (left.address == right.address
            && left
                .address
                .parse::<SocketAddr>()
                .is_ok_and(|address| address.port() != 0))
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
        let mut records = BTreeMap::new();
        let mut retained_bytes = 0usize;
        let mut next_order = 1u64;
        for entry in fs::read_dir(&root)? {
            let path = entry?.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            require(
                records.len() < MAX_OPERATIONS,
                "too many retained prepared operations",
            )?;
            let bytes = read_bounded(&path, MAX_RECORD_BYTES, true)?;
            let record: Record = serde_json::from_slice(&bytes)?;
            validate_spec_shape(&record.spec)?;
            validate_bound_request(&record.request)?;
            require(
                record.version == 1
                    && record.request_sha256 == request_digest(&record.request)?
                    && path.file_stem().and_then(|s| s.to_str()) == Some(record.spec.id.as_str())
                    && record.prior_deliveries.len() <= 16
                    && record
                        .detail
                        .as_ref()
                        .is_none_or(|s| s.len() <= MAX_DETAIL_BYTES)
                    && record.stop_reason.as_ref().is_none_or(|s| s.len() <= 128),
                "invalid prepared operation record",
            )?;
            require(
                record
                    .paths()
                    .iter()
                    .all(|path| path_shape(path) && !overlap(path, &root))
                    && !overlap(&record.delivery, &record.spec.bundle)
                    && !overlap(&record.delivery, &record.spec.output)
                    && record
                        .listen_address
                        .as_ref()
                        .is_none_or(|address| address.parse::<SocketAddr>().is_ok())
                    && record.bound_address.as_ref().is_none_or(|address| {
                        address
                            .parse::<SocketAddr>()
                            .is_ok_and(|address| address.port() != 0)
                    }),
                "invalid recovered operation paths",
            )?;
            require(
                match record.mode {
                    StoredMode::Execute => {
                        record.prior_deliveries.is_empty()
                            && record.resume_from.is_none()
                            && (record.state != OperationState::Queued
                                || (record.attempt == 0 && !record.execution_may_have_run))
                    }
                    StoredMode::Resume => {
                        !record.prior_deliveries.is_empty()
                            && record.attempt > 0
                            && record.execution_may_have_run
                    }
                    StoredMode::Acknowledge => {
                        record.attempt > 0
                            && record.execution_may_have_run
                            && record.resume_from.is_none()
                    }
                },
                "invalid recovered operation execution frontier",
            )?;
            require(
                record
                    .exit_code
                    .is_none_or(|code| (0..=255).contains(&code))
                    && (!record.outputs_installed
                        || (record.exit_code == Some(0)
                            && record.stop_reason.is_none()
                            && record.execution_may_have_run))
                    && match record.state {
                        OperationState::Queued => true,
                        OperationState::Running | OperationState::Uncertain => {
                            record.attempt > 0 && record.execution_may_have_run
                        }
                        OperationState::Cancelling => {
                            record.attempt > 0
                                && record.execution_may_have_run
                                && record.cancel_requested
                        }
                        OperationState::Completed => {
                            record.attempt > 0
                                && record.execution_may_have_run
                                && record.exit_code.is_some()
                                && record.acknowledgments_confirmed.is_some()
                                && record.stop_reason.as_deref() != Some("cancelled")
                                && (record.exit_code != Some(0)
                                    || record.stop_reason.is_some()
                                    || record.outputs_installed
                                    || record.mode == StoredMode::Acknowledge)
                        }
                        OperationState::Cancelled => {
                            if record.execution_may_have_run {
                                record.attempt > 0
                                    && record.exit_code.is_some()
                                    && record.stop_reason.as_deref() == Some("cancelled")
                                    && record.acknowledgments_confirmed.is_some()
                            } else {
                                record.mode == StoredMode::Execute
                                    && record.exit_code == Some(130)
                                    && record.cancel_requested
                                    && !record.outputs_installed
                                    && record.acknowledgments_confirmed.is_none()
                            }
                        }
                        OperationState::FailedBeforeStart => {
                            record.mode == StoredMode::Execute
                                && record.attempt > 0
                                && !record.execution_may_have_run
                                && record.exit_code.is_none()
                                && record.acknowledgments_confirmed.is_none()
                                && !record.outputs_installed
                        }
                    },
                "invalid recovered operation outcome",
            )?;
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
                retained_bytes,
                next_order,
                accepting: true,
                poisoned: false,
            }),
            changed: Condvar::new(),
            #[cfg(test)]
            fail_after_rename: std::sync::atomic::AtomicBool::new(false),
        });
        {
            let mut state = store.lock_state()?;
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
                record.state = OperationState::Uncertain;
                record.execution_may_have_run = true;
                record.listen_address = None;
                record.detail = Some(
                    "daemon owner stopped before a terminal result; explicit resume required"
                        .into(),
                );
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
            state.poisoned = true;
            state.accepting = false;
            for cancellation in state.active.values() {
                cancellation.cancel();
            }
            self.changed.notify_all();
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
        self.validate_paths(&spec)?;
        let request: Value = serde_json::from_slice(&read_bounded(
            &spec.bundle.join("request.json"),
            MAX_FRAME_BYTES,
            false,
        )?)?;
        validate_bound_request(&request)?;
        let fingerprint = request_digest(&request)?;
        let mut state = self.lock_state()?;
        require(state.accepting, "prepared operation service is stopping")?;
        if let Some(record) = state.records.get(&spec.id) {
            require(
                record.spec == spec
                    && record.request == request
                    && record.request_sha256 == fingerprint,
                "operation id already belongs to another request or destination",
            )?;
            return Ok(record.status());
        }
        require(
            state.records.len() < MAX_OPERATIONS,
            "prepared operation capacity exhausted",
        )?;
        // Existing outputs and abandoned deliveries remain owned across restarts.
        for existing in state.records.values() {
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
        }
        let record = Record {
            version: 1,
            delivery: spec.delivery.clone(),
            spec,
            request,
            request_sha256: fingerprint,
            order: state.next_order,
            attempt: 0,
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
        require(
            weight <= MAX_RETAINED_BYTES.saturating_sub(state.retained_bytes),
            "prepared operation byte capacity exhausted",
        )?;
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
        Ok(self.lock_state()?.records.get(id).map(Record::status))
    }

    pub fn cancel(&self, id: &str) -> io::Result<OperationStatus> {
        let mut state = self.lock_state()?;
        let mut record = state
            .records
            .get(id)
            .cloned()
            .ok_or_else(|| invalid("unknown prepared operation"))?;
        match record.state {
            OperationState::Queued => {
                record.cancel_requested = true;
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
        ordinary_directory(&new_delivery, true)?;
        require(
            !new_delivery.exists(),
            "resume requires a fresh delivery directory",
        )?;
        if let Some(path) = &resume_from {
            ordinary_directory(path, false)?;
        }
        let mut state = self.lock_state()?;
        require(state.accepting, "prepared operation service is stopping")?;
        let mut record = state
            .records
            .get(id)
            .cloned()
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
        record.listen_address = None;
        record.detail = None;
        record.order = state.next_order;
        state.next_order = state
            .next_order
            .checked_add(1)
            .ok_or_else(|| invalid("operation queue exhausted"))?;
        let status = record.status();
        self.replace(&mut state, record)?;
        Ok(status)
    }

    /// Retry only acceptance of an existing verified delivery. The worker may
    /// already have released its result bytes, so this never downloads them or
    /// turns a lost acknowledgment into another execution.
    pub fn acknowledge(&self, id: &str, delivery: PathBuf) -> io::Result<OperationStatus> {
        ordinary_directory(&delivery, false)?;
        let mut state = self.lock_state()?;
        require(state.accepting, "prepared operation service is stopping")?;
        let mut record = state
            .records
            .get(id)
            .cloned()
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
        record.listen_address = None;
        record.detail = None;
        record.order = state.next_order;
        state.next_order = state
            .next_order
            .checked_add(1)
            .ok_or_else(|| invalid("operation queue exhausted"))?;
        let status = record.status();
        self.replace(&mut state, record)?;
        Ok(status)
    }

    pub fn claim_next(self: &Arc<Self>) -> io::Result<Option<OperationClaim>> {
        let mut state = self.lock_state()?;
        if !state.accepting || state.active.len() >= MAX_RUNNING {
            return Ok(None);
        }
        let next = state
            .records
            .values()
            .filter(|record| record.state == OperationState::Queued)
            .filter(|record| {
                state.records.values().all(|other| {
                    if other.spec.id == record.spec.id {
                        return true;
                    }
                    let owns_worker =
                        state.active.contains_key(&other.spec.id) || other.unresolved();
                    (!owns_worker || !same_worker(&record.spec, &other.spec))
                        && (!state.active.contains_key(&other.spec.id)
                            || !record
                                .paths()
                                .iter()
                                .any(|left| other.paths().iter().any(|right| overlap(left, right))))
                })
            })
            .min_by_key(|record| record.order)
            .cloned();
        let Some(mut record) = next else {
            return Ok(None);
        };
        record.state = OperationState::Running;
        record.attempt = record
            .attempt
            .checked_add(1)
            .ok_or_else(|| invalid("operation attempts exhausted"))?;
        // Persist this before the callback can listen, upload, or send execution.
        record.execution_may_have_run = true;
        let cancellation = OperationCancellation::default();
        let mut spec = record.spec.clone();
        spec.delivery = record.delivery.clone();
        if record.mode != StoredMode::Execute
            && let Some(address) = &record.bound_address
        {
            spec.address = address.clone();
        }
        self.replace(&mut state, record.clone())?;
        state.active.insert(spec.id.clone(), cancellation.clone());
        let claim = OperationClaim {
            store: Arc::clone(self),
            spec,
            request: record.request.clone(),
            mode: record.mode,
            resume_from: record.resume_from.clone(),
            attempt: record.attempt,
            cancellation: cancellation.clone(),
            finished: false,
        };
        Ok(Some(claim))
    }

    /// Shutdown leaves unclaimed requests queued and requests cleanup of owners.
    pub fn stop(&self) -> io::Result<()> {
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
    mode: StoredMode,
    resume_from: Option<PathBuf>,
    attempt: u64,
    cancellation: OperationCancellation,
    finished: bool,
}

impl OperationClaim {
    pub fn spec(&self) -> &PreparedOperationSpec {
        &self.spec
    }
    pub fn request(&self) -> &Value {
        &self.request
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

    pub fn acknowledgment_only(&self) -> bool {
        self.mode == StoredMode::Acknowledge
    }

    pub fn listening(&self, address: SocketAddr) -> io::Result<()> {
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

    pub fn finish(mut self, outcome: OperationOutcome) -> io::Result<OperationStatus> {
        let mut state = self.store.lock_state()?;
        let mut record = self.current(&state)?;
        record.listen_address = None;
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
            } => {
                // A failed resume never disproves an earlier uncertain run.
                record.execution_may_have_run =
                    execution_may_have_run || self.mode != StoredMode::Execute;
                record.state = if record.execution_may_have_run {
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
        let status = record.status();
        self.store.replace(&mut state, record)?;
        state.active.remove(&self.spec.id);
        self.finished = true;
        self.store.changed.notify_all();
        Ok(status)
    }
}

impl Drop for OperationClaim {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        self.cancellation.cancel();
        if let Ok(mut state) = self.store.state.lock()
            && let Some(mut record) = state.records.get(&self.spec.id).cloned()
            && record.attempt == self.attempt
            && state.active.contains_key(&self.spec.id)
        {
            record.state = OperationState::Uncertain;
            record.execution_may_have_run = true;
            record.listen_address = None;
            record.detail = Some(
                "dispatch owner ended without terminal evidence; explicit resume required".into(),
            );
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
