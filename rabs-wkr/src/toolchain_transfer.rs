//! Request-bound toolchain input with one owned filesystem worker.
//!
//! The wire never supplies a worker staging path. A new private tree or an
//! explicitly negotiated retained lease must verify against the request's full
//! identity before durable execution admission. Work stays off the reactor, and
//! cancellation revokes readiness even when a filesystem operation completes late.

use crate::session::toolchain_pool::{self, ToolchainLease, ToolchainPool};
use crate::session::{CanonicalExecRequest, parse_toolchain_identity};
use crate::source_transfer::hex;
use rabs_sandbox::toolchain_dataset::{PreparedToolchain, ToolchainIdentity, ToolchainLimits};
use rabs_sandbox::toolchain_transfer::{
    MAX_TOOLCHAIN_CHUNK, TOOLCHAIN_REUSE_VERSION, TOOLCHAIN_TRANSFER_VERSION,
    TOOLCHAIN_UPLOAD_BUDGET, ToolchainEntry, ToolchainEntryKind, ToolchainReceiver,
};
use serde_json::{Value, json};
use std::borrow::Cow;
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak, mpsc};
use std::task::{Context, Poll, Waker};
use std::thread::JoinHandle;
use std::time::Instant;

fn fields(value: &Value, names: &[&str]) -> Result<(), String> {
    if value.as_object().is_some_and(|object| {
        object.len() == names.len() && names.iter().all(|name| object.contains_key(*name))
    }) {
        Ok(())
    } else {
        Err("invalid toolchain transfer fields".to_owned())
    }
}

fn decode_hex(value: &Value, maximum: usize) -> Result<Vec<u8>, String> {
    let text = value.as_str().ok_or("toolchain hex must be a string")?;
    if !text.len().is_multiple_of(2)
        || text.len() / 2 > maximum
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("invalid bounded toolchain hex".to_owned());
    }
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let digit = |byte: u8| {
                if byte <= b'9' {
                    byte - b'0'
                } else {
                    byte - b'a' + 10
                }
            };
            Ok((digit(pair[0]) << 4) | digit(pair[1]))
        })
        .collect()
}

fn digest(value: &Value) -> Result<[u8; 32], String> {
    decode_hex(value, 32)?
        .try_into()
        .map_err(|_| "invalid toolchain digest length".to_owned())
}

/// Explicit selection never falls back to a worker-local pathname.
pub fn request_identity(value: &Value) -> Result<Option<ToolchainIdentity>, String> {
    match value.get("toolchain_transfer") {
        None => Ok(None),
        Some(selection) if selection.as_str() == Some(TOOLCHAIN_TRANSFER_VERSION) => {
            if value.get("source_manifest").is_none() {
                return Err("uploaded toolchain requires an uploaded source_manifest".to_owned());
            }
            if value.get("toolchain_backing").is_some() || value.get("toolchain_source").is_some() {
                return Err("uploaded toolchain excludes local toolchain paths".to_owned());
            }
            parse_toolchain_identity(value)?
                .ok_or_else(|| "uploaded toolchain requires toolchain_identity".to_owned())
                .map(Some)
        }
        Some(_) => Err("unsupported toolchain_transfer selection".to_owned()),
    }
}

pub fn selected(frame: &str, authenticated: bool, source_enabled: bool) -> Result<bool, String> {
    let value: Value = serde_json::from_str(frame).map_err(|error| error.to_string())?;
    match value.get("toolchain_transfer") {
        None => Ok(false),
        Some(selection) if selection.as_str() == Some(TOOLCHAIN_TRANSFER_VERSION) => {
            if !authenticated {
                return Err("toolchain transfer requires authenticated transport".to_owned());
            }
            if !source_enabled {
                return Err("toolchain transfer requires source transfer".to_owned());
            }
            Ok(true)
        }
        Some(_) => Err("unsupported toolchain_transfer selection".to_owned()),
    }
}

pub fn selected_reuse(
    frame: &str,
    authenticated: bool,
    transfer_enabled: bool,
) -> Result<bool, String> {
    let value: Value = serde_json::from_str(frame).map_err(|error| error.to_string())?;
    match value.get("toolchain_reuse") {
        None => Ok(false),
        Some(selection) if selection.as_str() == Some(TOOLCHAIN_REUSE_VERSION) => {
            if !authenticated {
                return Err("toolchain reuse requires authenticated transport".to_owned());
            }
            if !transfer_enabled {
                return Err("toolchain reuse requires toolchain transfer".to_owned());
            }
            Ok(true)
        }
        Some(_) => Err("unsupported toolchain_reuse selection".to_owned()),
    }
}

struct UploadedToolchain {
    // Inventory and receiver descriptors close before the parent is removed.
    prepared: Option<PreparedToolchain>,
    receiver: ToolchainReceiver,
    _directory: tempfile::TempDir,
}

/// A consumed receiver's complete private image. Only this module can construct
/// the handoff: neither a pathname nor a separately opened inventory owns its
/// backing directory. The pool must still verify it before granting a lease.
pub(crate) struct SealedToolchain {
    prepared: PreparedToolchain,
    directory: tempfile::TempDir,
}

impl SealedToolchain {
    pub(crate) fn identity(&self) -> &ToolchainIdentity {
        self.prepared.identity()
    }

    pub(crate) fn prepared(&self) -> &PreparedToolchain {
        &self.prepared
    }

    pub(crate) fn directory(&self) -> &Path {
        self.directory.path()
    }

    pub(crate) fn into_parts(self) -> (PreparedToolchain, tempfile::TempDir) {
        (self.prepared, self.directory)
    }
}

impl UploadedToolchain {
    fn into_sealed(self, expected: &ToolchainIdentity) -> io::Result<SealedToolchain> {
        let Self {
            prepared,
            receiver,
            _directory: directory,
        } = self;
        let prepared = prepared.ok_or_else(|| io::Error::other("toolchain is not sealed"))?;
        if prepared.identity() != expected
            || prepared.root() != std::fs::canonicalize(directory.path())?.join("tree")
        {
            return Err(io::Error::other(
                "sealed toolchain differs from its owned image",
            ));
        }
        // No transfer descriptor or operation survives the ownership handoff.
        drop(receiver);
        Ok(SealedToolchain {
            prepared,
            directory,
        })
    }
}

enum ToolchainBacking {
    Uploaded(Box<UploadedToolchain>),
    UploadedRetained {
        lease: ToolchainLease,
        pool: Weak<ToolchainPool>,
    },
    Reused(ToolchainLease),
    Unavailable,
}

impl ToolchainBacking {
    fn prepared_root(&self) -> Option<&Path> {
        match self {
            Self::Uploaded(upload) => upload.prepared.as_ref().map(PreparedToolchain::root),
            Self::UploadedRetained { lease, .. } | Self::Reused(lease) => Some(lease.root()),
            Self::Unavailable => None,
        }
    }
}

/// Moved into the blocking execution owner before its lease can be armed. The
/// executor consumes the same verified identity through its toolchain pool;
/// an uploaded image can become the execution lease without another byte copy.
pub struct ToolchainOwner {
    backing: ToolchainBacking,
    request_id: u64,
    identity: ToolchainIdentity,
    entries: usize,
    deadline: Instant,
    failed: bool,
}

impl ToolchainOwner {
    fn into_execution_backing(
        self,
        request: &CanonicalExecRequest,
    ) -> io::Result<ToolchainBacking> {
        if self.failed
            || request.request_id != self.request_id
            || request.toolchain_identity.as_ref() != Some(&self.identity)
            || self.backing.prepared_root() != Some(Path::new(&request.toolchain_backing))
        {
            return Err(io::Error::other(
                "execution differs from its owned toolchain identity",
            ));
        }
        Ok(self.backing)
    }

    /// Input deadlines were checked before durable execution admission. From
    /// this handoff onward the blocking executor's cancellation/lease controls
    /// acquisition and every consumer verification, including reused images.
    pub(crate) fn into_lease(
        self,
        request: &CanonicalExecRequest,
        stopped: impl Fn() -> bool,
    ) -> io::Result<ToolchainLease> {
        let expected = self.identity;
        match self.into_execution_backing(request)? {
            ToolchainBacking::Uploaded(upload) => {
                toolchain_pool::adopt(upload.into_sealed(&expected)?, stopped)
            }
            ToolchainBacking::UploadedRetained { lease, pool } => {
                toolchain_pool::revalidate_retained_upload(lease, &pool, &expected, stopped)
            }
            ToolchainBacking::Reused(lease) => {
                if lease.identity() != &expected {
                    return Err(io::Error::other(
                        "retained lease differs from its request identity",
                    ));
                }
                // Keep the selected lease alive while the existing acquisition
                // path verifies it and applies the active pool's failure policy.
                toolchain_pool::prepare(lease.root(), Some(&expected), stopped)
            }
            ToolchainBacking::Unavailable => Err(io::Error::other("toolchain upload failed")),
        }
    }

    /// Retain only a completely sealed receiver under the original input budget.
    /// The handoff consumes every transfer descriptor before pool publication.
    /// A later execution still fully verifies the exact lease, adding a separate
    /// verification boundary rather than treating the seal as execution admission.
    fn retain_sealed(
        &mut self,
        pool: &Arc<ToolchainPool>,
        cancelled: &AtomicBool,
    ) -> Result<(), String> {
        self.check(cancelled)?;
        self.failed = true;
        let ToolchainBacking::Uploaded(upload) =
            std::mem::replace(&mut self.backing, ToolchainBacking::Unavailable)
        else {
            return Err("toolchain upload is already retained".to_owned());
        };
        let sealed = upload
            .into_sealed(&self.identity)
            .map_err(|error| error.to_string())?;
        let deadline = self.deadline;
        let lease = pool
            .adopt(sealed, || {
                cancelled.load(Ordering::Acquire) || Instant::now() >= deadline
            })
            .map_err(|error| error.to_string())?;
        self.backing = ToolchainBacking::UploadedRetained {
            lease,
            // Outstanding inputs retain their own dataset and directory, not
            // every idle SDK in a supervisor that has already shut down.
            pool: Arc::downgrade(pool),
        };
        self.failed = false;
        if let Err(error) = self.check(cancelled) {
            self.failed = true;
            return Err(error);
        }
        Ok(())
    }

    fn check(&self, cancelled: &AtomicBool) -> Result<(), String> {
        if self.failed {
            return Err("toolchain upload failed".to_owned());
        }
        if cancelled.load(Ordering::Acquire) {
            return Err("toolchain upload cancelled".to_owned());
        }
        if Instant::now() >= self.deadline {
            return Err("toolchain upload deadline exceeded".to_owned());
        }
        Ok(())
    }

    fn ready(&self, cancelled: &AtomicBool) -> Result<Value, String> {
        self.check(cancelled)?;
        Ok(
            json!({"kind":"toolchain-ready", "request_id":self.request_id,
            "sha256":hex(&self.identity.sha256), "sealed":self.backing.prepared_root().is_some()}),
        )
    }

    fn handle(&mut self, frame: &Value, cancelled: &AtomicBool) -> Result<Value, String> {
        self.check(cancelled)?;
        if self.backing.prepared_root().is_some() {
            return Err("toolchain upload is already sealed".to_owned());
        }
        let ToolchainBacking::Uploaded(upload) = &mut self.backing else {
            return Err("toolchain upload is already sealed".to_owned());
        };
        let UploadedToolchain {
            prepared, receiver, ..
        } = &mut **upload;
        let identity = hex(&self.identity.sha256);
        let result = (|| match frame["kind"].as_str() {
            Some("toolchain-entry") => {
                fields(frame, &["kind", "request_id", "sha256", "path", "entry"])?;
                if receiver.entry_count() >= self.entries {
                    return Err("toolchain entry count exceeds declaration".to_owned());
                }
                let path = frame["path"]
                    .as_str()
                    .ok_or("toolchain entry requires path")?;
                let value = &frame["entry"];
                let kind = match value["kind"].as_str() {
                    Some("directory") => {
                        fields(value, &["kind"])?;
                        ToolchainEntryKind::Directory
                    }
                    Some("symlink") => {
                        fields(value, &["kind", "target"])?;
                        ToolchainEntryKind::Symlink {
                            target: value["target"]
                                .as_str()
                                .ok_or("toolchain link requires target")?
                                .to_owned(),
                        }
                    }
                    Some("file") => {
                        fields(value, &["kind", "bytes", "executable"])?;
                        ToolchainEntryKind::File {
                            bytes: value["bytes"]
                                .as_u64()
                                .ok_or("toolchain file bytes must be unsigned")?,
                            executable: value["executable"]
                                .as_bool()
                                .ok_or("toolchain executable must be boolean")?,
                        }
                    }
                    _ => return Err("unsupported toolchain entry kind".to_owned()),
                };
                receiver
                    .entry(ToolchainEntry {
                        path: path.to_owned(),
                        kind,
                    })
                    .map_err(|error| error.to_string())?;
                Ok(
                    json!({"kind":"toolchain-entry-accepted", "request_id":self.request_id,
                        "sha256":identity, "path":path}),
                )
            }
            Some("toolchain-chunk") => {
                fields(
                    frame,
                    &[
                        "kind",
                        "request_id",
                        "sha256",
                        "path",
                        "offset",
                        "data_hex",
                        "chunk_sha256",
                    ],
                )?;
                let path = frame["path"]
                    .as_str()
                    .ok_or("toolchain chunk requires path")?;
                let offset = frame["offset"]
                    .as_u64()
                    .ok_or("toolchain chunk offset must be unsigned")?;
                let bytes = decode_hex(&frame["data_hex"], MAX_TOOLCHAIN_CHUNK)?;
                let next = offset
                    .checked_add(bytes.len() as u64)
                    .ok_or("toolchain chunk offset overflow")?;
                receiver
                    .write_chunk(path, offset, &bytes, digest(&frame["chunk_sha256"])?)
                    .map_err(|error| error.to_string())?;
                Ok(
                    json!({"kind":"toolchain-chunk-accepted", "request_id":self.request_id,
                        "sha256":identity, "path":path, "next_offset":next}),
                )
            }
            Some("toolchain-seal") => {
                fields(frame, &["kind", "request_id", "sha256"])?;
                if receiver.entry_count() != self.entries {
                    return Err("toolchain entry count differs from declaration".to_owned());
                }
                let deadline = self.deadline;
                let verified = receiver
                    .seal(|| cancelled.load(Ordering::Acquire) || Instant::now() >= deadline)
                    .map_err(|error| error.to_string())?;
                *prepared = Some(verified);
                Ok(
                    json!({"kind":"toolchain-ready", "request_id":self.request_id,
                    "sha256":identity, "sealed":true}),
                )
            }
            _ => Err("unknown toolchain operation".to_owned()),
        })()
        .and_then(|reply| {
            self.check(cancelled)?;
            Ok(reply)
        });
        if result.is_err() {
            self.failed = true;
        }
        result
    }
}

#[derive(Default)]
struct TransferState {
    owner: Option<ToolchainOwner>,
    reuse: bool,
    // Test receivers get a real isolated pool, avoiding process-global registry
    // changes or environment mutation while parallel tests own other sessions.
    #[cfg(test)]
    pool: Option<Arc<toolchain_pool::ToolchainPool>>,
}

impl TransferState {
    fn retention_pool(
        &self,
        identity: &ToolchainIdentity,
    ) -> io::Result<Option<Arc<ToolchainPool>>> {
        #[cfg(test)]
        if let Some(pool) = &self.pool {
            return Ok(pool.retention_enabled(identity).then(|| Arc::clone(pool)));
        }
        toolchain_pool::retention_pool(identity)
    }

    fn lookup(
        &self,
        identity: &ToolchainIdentity,
        stopped: impl Fn() -> bool,
    ) -> io::Result<Option<ToolchainLease>> {
        #[cfg(test)]
        if let Some(pool) = &self.pool {
            return pool.lookup(identity, stopped);
        }
        toolchain_pool::lookup(identity, stopped)
    }

    fn handle(&mut self, frame: &Value, cancelled: &AtomicBool) -> Result<Value, String> {
        let id = frame["request_id"]
            .as_u64()
            .ok_or("toolchain request_id must be unsigned")?;
        if cancelled.load(Ordering::Acquire) {
            return Err("toolchain upload cancelled".to_owned());
        }
        if frame["kind"] == "toolchain-begin" {
            fields(frame, &["kind", "request_id", "identity", "entries"])?;
            let identity =
                parse_toolchain_identity(&json!({"toolchain_identity":frame["identity"]}))?
                    .ok_or("toolchain begin requires identity")?;
            let limits = ToolchainLimits::default();
            let entries = frame["entries"]
                .as_u64()
                .and_then(|value| usize::try_from(value).ok())
                .filter(|entries| *entries != 0 && *entries <= limits.max_entries)
                .ok_or("toolchain entry count outside bounds")?;
            if identity.files > entries as u64 || identity.bytes > limits.max_bytes {
                return Err("toolchain identity outside upload bounds".to_owned());
            }
            if let Some(owner) = &self.owner {
                if owner.request_id != id || owner.identity != identity || owner.entries != entries
                {
                    return Err("another toolchain transfer owns this session".to_owned());
                }
                return owner.ready(cancelled);
            }
            let deadline = Instant::now() + TOOLCHAIN_UPLOAD_BUDGET;
            if self.reuse
                && let Some(lease) = self
                    .lookup(&identity, || {
                        cancelled.load(Ordering::Acquire) || Instant::now() >= deadline
                    })
                    .map_err(|error| error.to_string())?
            {
                if lease.entry_count().map_err(|error| error.to_string())? != entries {
                    return Err(
                        "retained toolchain entry count differs from declaration".to_owned()
                    );
                }
                let owner = ToolchainOwner {
                    backing: ToolchainBacking::Reused(lease),
                    request_id: id,
                    identity,
                    entries,
                    deadline,
                    failed: false,
                };
                let reply = owner.ready(cancelled)?;
                self.owner = Some(owner);
                return Ok(reply);
            }
            let mut builder = tempfile::Builder::new();
            builder.prefix("rabs-toolchain-upload-");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                builder.permissions(std::fs::Permissions::from_mode(0o700));
            }
            let directory = builder.tempdir().map_err(|error| error.to_string())?;
            let receiver =
                ToolchainReceiver::create(&directory.path().join("tree"), identity, limits)
                    .map_err(|error| error.to_string())?;
            let owner = ToolchainOwner {
                backing: ToolchainBacking::Uploaded(Box::new(UploadedToolchain {
                    prepared: None,
                    receiver,
                    _directory: directory,
                })),
                request_id: id,
                identity,
                entries,
                deadline,
                failed: false,
            };
            let reply = owner.ready(cancelled)?;
            self.owner = Some(owner);
            return Ok(reply);
        }
        let owner = self
            .owner
            .as_mut()
            .ok_or("no toolchain transfer in this session")?;
        if owner.request_id != id || digest(&frame["sha256"])? != owner.identity.sha256 {
            return Err("toolchain transfer identity mismatch".to_owned());
        }
        let reply = owner.handle(frame, cancelled)?;
        if frame["kind"] != "toolchain-seal" || !self.reuse {
            return Ok(reply);
        }
        let identity = owner.identity;
        let result = (|| {
            if let Some(pool) = self
                .retention_pool(&identity)
                .map_err(|error| error.to_string())?
            {
                self.owner
                    .as_mut()
                    .expect("the sealed upload still owns this session")
                    .retain_sealed(&pool, cancelled)?;
            }
            self.owner
                .as_ref()
                .expect("the sealed upload still owns this session")
                .ready(cancelled)
        })();
        if result.is_err()
            && let Some(owner) = &mut self.owner
        {
            owner.failed = true;
        }
        result
    }

    fn prepared_path(
        &self,
        request: &Value,
        cancelled: &AtomicBool,
    ) -> Result<Option<String>, String> {
        let Some(identity) = request_identity(request)? else {
            return Ok(None);
        };
        let owner = self
            .owner
            .as_ref()
            .ok_or("execution toolchain has not been uploaded")?;
        owner.check(cancelled)?;
        if request["request_id"].as_u64() != Some(owner.request_id) || identity != owner.identity {
            return Err("execution differs from its uploaded toolchain identity".to_owned());
        }
        let root = owner
            .backing
            .prepared_root()
            .ok_or("execution toolchain is not completely verified")?;
        root.to_str()
            .map(|path| Some(path.to_owned()))
            .ok_or_else(|| "worker toolchain staging path is not UTF-8".to_owned())
    }
}

struct Job {
    state: TransferState,
    frame: Value,
}
struct Completed {
    state: TransferState,
    response: Result<Value, String>,
}

#[derive(Default)]
struct CompletionState {
    result: Option<Result<Completed, String>>,
    waker: Option<Waker>,
}

pub struct ToolchainReply {
    pub request_id: u64,
    pub response: Result<Value, String>,
}

/// One command and one completion, with no filesystem lock on the reactor.
/// Drop joins an accepted operation; it never detaches work after cancellation.
pub struct ToolchainTransferTask {
    state: Option<TransferState>,
    shared: Arc<Mutex<CompletionState>>,
    cancelled: Arc<AtomicBool>,
    sender: Option<mpsc::SyncSender<Job>>,
    thread: Option<JoinHandle<()>>,
    pending_id: Option<u64>,
    upload_id: Option<u64>,
    failed: bool,
}

impl Default for ToolchainTransferTask {
    fn default() -> Self {
        Self::with_reuse(false)
    }
}

impl ToolchainTransferTask {
    /// Reuse is an explicit session selection; local cache configuration alone
    /// never permits the receiver to skip the sender's full transfer protocol.
    #[must_use]
    pub fn with_reuse(reuse: bool) -> Self {
        Self {
            state: Some(TransferState {
                reuse,
                ..TransferState::default()
            }),
            shared: Arc::new(Mutex::new(CompletionState::default())),
            cancelled: Arc::new(AtomicBool::new(false)),
            sender: None,
            thread: None,
            pending_id: None,
            upload_id: None,
            failed: false,
        }
    }

    fn start_worker(
        &mut self,
        mut handle: impl FnMut(&mut TransferState, &Value, &AtomicBool) -> Result<Value, String>
        + Send
        + 'static,
    ) -> io::Result<()> {
        let (sender, receiver) = mpsc::sync_channel::<Job>(1);
        let shared = Arc::clone(&self.shared);
        let cancelled = Arc::clone(&self.cancelled);
        let thread = std::thread::Builder::new()
            .name("rabs-toolchain-io".to_owned())
            .spawn(move || {
                while let Ok(mut job) = receiver.recv() {
                    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        handle(&mut job.state, &job.frame, &cancelled)
                    }));
                    let fatal = outcome.is_err();
                    let result = match outcome {
                        Ok(response) => Ok(Completed {
                            state: job.state,
                            response,
                        }),
                        Err(_) => Err("toolchain filesystem worker panicked".to_owned()),
                    };
                    let wake = {
                        let mut completion =
                            shared.lock().unwrap_or_else(|error| error.into_inner());
                        completion.result = Some(result);
                        completion.waker.take()
                    };
                    if let Some(waker) = wake {
                        waker.wake();
                    }
                    if fatal {
                        break;
                    }
                }
            })?;
        self.sender = Some(sender);
        self.thread = Some(thread);
        Ok(())
    }

    pub fn submit(&mut self, frame: &Value, enabled: bool, busy: bool) -> Result<(), String> {
        self.submit_frame(Cow::Borrowed(frame), enabled, busy)
    }

    /// Move the reactor's parsed frame into its filesystem job without copying
    /// the encoded toolchain payload. Admission and ownership match borrowed submit.
    pub fn submit_owned(&mut self, frame: Value, enabled: bool, busy: bool) -> Result<(), String> {
        self.submit_frame(Cow::Owned(frame), enabled, busy)
    }

    fn submit_frame(
        &mut self,
        frame: Cow<'_, Value>,
        enabled: bool,
        busy: bool,
    ) -> Result<(), String> {
        if !enabled {
            return Err("toolchain transfer not negotiated".to_owned());
        }
        if busy {
            return Err("worker-busy-or-result-pending".to_owned());
        }
        if self.cancelled.load(Ordering::Acquire) {
            return Err("toolchain upload cancelled".to_owned());
        }
        if self.failed {
            return Err("toolchain filesystem worker failed".to_owned());
        }
        if self.pending_id.is_some() {
            return Err("toolchain-operation-pending".to_owned());
        }
        if !matches!(
            frame["kind"].as_str(),
            Some("toolchain-begin" | "toolchain-entry" | "toolchain-chunk" | "toolchain-seal")
        ) {
            return Err("unknown toolchain operation".to_owned());
        }
        let id = frame["request_id"]
            .as_u64()
            .ok_or("toolchain request_id must be unsigned")?;
        if self.sender.is_none() {
            self.start_worker(|state, frame, cancelled| state.handle(frame, cancelled))
                .map_err(|error| format!("start toolchain filesystem worker: {error}"))?;
        }
        let sender = self
            .sender
            .as_ref()
            .ok_or("toolchain filesystem worker unavailable")?;
        let state = self.state.take().ok_or("toolchain-operation-pending")?;
        match sender.try_send(Job {
            state,
            frame: frame.into_owned(),
        }) {
            Ok(()) => {
                self.pending_id = Some(id);
                Ok(())
            }
            Err(mpsc::TrySendError::Full(job) | mpsc::TrySendError::Disconnected(job)) => {
                self.state = Some(job.state);
                self.failed = true;
                Err("toolchain filesystem worker unavailable".to_owned())
            }
        }
    }

    pub fn poll_completion(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<ToolchainReply, String>> {
        let Some(id) = self.pending_id else {
            return Poll::Pending;
        };
        let result = {
            let mut shared = self
                .shared
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            match shared.result.take() {
                Some(result) => result,
                None => {
                    if shared
                        .waker
                        .as_ref()
                        .is_none_or(|waker| !waker.will_wake(cx.waker()))
                    {
                        shared.waker = Some(cx.waker().clone());
                    }
                    return Poll::Pending;
                }
            }
        };
        self.pending_id = None;
        match result {
            Ok(Completed {
                state,
                mut response,
            }) => {
                self.upload_id = state.owner.as_ref().map(|owner| owner.request_id);
                self.state = Some(state);
                if self.cancelled.load(Ordering::Acquire) {
                    response = Err("toolchain upload cancelled".to_owned());
                }
                Poll::Ready(Ok(ToolchainReply {
                    request_id: id,
                    response,
                }))
            }
            Err(error) => {
                self.failed = true;
                Poll::Ready(Err(error))
            }
        }
    }

    #[must_use]
    pub fn request_id(&self) -> Option<u64> {
        self.upload_id.or(self.pending_id)
    }
    #[must_use]
    pub fn is_pending(&self) -> bool {
        self.pending_id.is_some()
    }

    pub fn cancel(&mut self, request_id: u64) -> Option<bool> {
        if self.request_id() != Some(request_id) {
            return None;
        }
        Some(!self.cancelled.swap(true, Ordering::AcqRel))
    }

    pub fn prepared_path(&self, request: &Value, enabled: bool) -> Result<Option<String>, String> {
        if request_identity(request)?.is_none() {
            return Ok(None);
        }
        if !enabled {
            return Err("toolchain transfer not negotiated".to_owned());
        }
        if self.failed {
            return Err("toolchain filesystem worker failed".to_owned());
        }
        self.state
            .as_ref()
            .ok_or("toolchain-operation-pending")?
            .prepared_path(request, &self.cancelled)
    }

    pub fn take_prepared(&mut self, request: &Value) -> io::Result<Option<ToolchainOwner>> {
        if self
            .prepared_path(request, true)
            .map_err(io::Error::other)?
            .is_none()
        {
            return Ok(None);
        }
        let owner = self
            .state
            .as_mut()
            .ok_or_else(|| io::Error::other("toolchain-operation-pending"))?
            .owner
            .take();
        if owner.is_some() {
            self.upload_id = None;
        }
        Ok(owner)
    }
}

impl Drop for ToolchainTransferTask {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
        drop(self.sender.take());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> Value {
        json!({"kind":"canonical-exec", "request_id":0,
        "toolchain_transfer":TOOLCHAIN_TRANSFER_VERSION,
        "source_manifest":{"manifest_sha256":"unparsed-by-selection", "files":[]},
        "toolchain_identity":{
            "version":rabs_sandbox::toolchain_dataset::TOOLCHAIN_DATASET_VERSION,
            "sha256":"11".repeat(32), "files":1, "bytes":7,
        }})
    }

    #[test]
    fn transfer_selection_requires_authenticated_source_upload() {
        let ack = json!({"kind":"session-ok", "toolchain_transfer":TOOLCHAIN_TRANSFER_VERSION})
            .to_string();
        assert!(selected(&ack, true, true).unwrap());
        assert!(selected(&ack, false, true).is_err());
        assert!(selected(&ack, true, false).is_err());
        assert!(!selected(r#"{"kind":"session-ok"}"#, false, false).unwrap());
        for invalid in [
            Value::Null,
            json!(false),
            json!(17),
            json!("toolchain-tree-v2"),
        ] {
            assert!(
                selected(
                    &json!({"kind":"session-ok", "toolchain_transfer":invalid}).to_string(),
                    true,
                    true
                )
                .is_err()
            );
        }
    }

    #[test]
    fn reuse_selection_requires_authenticated_toolchain_transfer() {
        let ack =
            json!({"kind":"session-ok", "toolchain_reuse":TOOLCHAIN_REUSE_VERSION}).to_string();
        assert!(selected_reuse(&ack, true, true).unwrap());
        assert!(selected_reuse(&ack, false, true).is_err());
        assert!(selected_reuse(&ack, true, false).is_err());
        assert!(!selected_reuse(r#"{"kind":"session-ok"}"#, false, false).unwrap());
        for invalid in [
            Value::Null,
            json!(false),
            json!(17),
            json!("toolchain-reuse-v2"),
        ] {
            assert!(
                selected_reuse(
                    &json!({"kind":"session-ok", "toolchain_reuse":invalid}).to_string(),
                    true,
                    true,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn selected_requests_require_exact_identity_and_exclude_host_paths() {
        assert_eq!(
            request_identity(&request()).unwrap(),
            Some(ToolchainIdentity {
                sha256: [0x11; 32],
                files: 1,
                bytes: 7,
            })
        );
        for missing in ["source_manifest", "toolchain_identity"] {
            let mut incomplete = request();
            incomplete.as_object_mut().unwrap().remove(missing);
            assert!(request_identity(&incomplete).is_err());
        }
        for local in ["toolchain_backing", "toolchain_source"] {
            let mut mixed = request();
            mixed[local] = json!("/untrusted");
            assert!(request_identity(&mixed).is_err());
        }
        let mut unknown = request();
        unknown["toolchain_identity"]["version"] = json!("toolchain-dataset-v2");
        assert!(request_identity(&unknown).is_err());
        let mut extra = request();
        extra["toolchain_identity"]["extra"] = json!(true);
        assert!(request_identity(&extra).is_err());
        assert!(
            request_identity(&json!({"toolchain_backing":"/existing"}))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn transfer_controls_are_bounded_before_creating_filesystem_work() {
        assert_eq!(decode_hex(&json!("00ff"), 2).unwrap(), [0, 255]);
        for invalid in ["0", "0F", " 00", "000000"] {
            assert!(decode_hex(&json!(invalid), 2).is_err());
        }
        let frame = json!({"kind":"toolchain-begin", "request_id":0});
        let mut task = ToolchainTransferTask::default();
        assert!(task.submit(&frame, false, false).is_err());
        assert!(task.submit(&frame, true, true).is_err());
        assert!(task.submit(&request(), true, false).is_err());
        assert_eq!(
            task.submit_owned(frame.clone(), false, false).unwrap_err(),
            "toolchain transfer not negotiated"
        );
        assert_eq!(
            task.submit_owned(frame, true, true).unwrap_err(),
            "worker-busy-or-result-pending"
        );
        assert_eq!(
            task.submit_owned(request(), true, false).unwrap_err(),
            "unknown toolchain operation"
        );
        assert_eq!(
            task.submit_owned(json!({"kind":"toolchain-begin"}), true, false)
                .unwrap_err(),
            "toolchain request_id must be unsigned"
        );
        assert!(task.thread.is_none());
        assert!(task.sender.is_none());
        assert!(!task.is_pending());
        assert!(task.prepared_path(&request(), true).is_err());
        assert!(task.prepared_path(&request(), false).is_err());
    }

    #[cfg(target_os = "linux")]
    mod reuse {
        use super::*;
        use rabs_sandbox::toolchain_dataset::fingerprint_toolchain;
        use std::fs;
        use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
        use std::task::Wake;
        use std::time::Duration;

        const CONTENTS: &[u8] = b"retained compiler\0\xff";
        const ENTRIES: usize = 5;

        fn fixture(
            budget: u64,
            seed: bool,
        ) -> (tempfile::TempDir, Arc<toolchain_pool::ToolchainPool>, Value) {
            let source = tempfile::tempdir().unwrap();
            fs::create_dir(source.path().join("bin")).unwrap();
            fs::create_dir(source.path().join("empty")).unwrap();
            fs::write(source.path().join("bin/compiler"), CONTENTS).unwrap();
            fs::set_permissions(
                source.path().join("bin/compiler"),
                fs::Permissions::from_mode(0o755),
            )
            .unwrap();
            symlink("bin/compiler", source.path().join("rustc")).unwrap();
            let identity =
                fingerprint_toolchain(source.path(), &ToolchainLimits::default(), || false)
                    .unwrap();
            let pool = Arc::new(toolchain_pool::ToolchainPool::new(budget, 2).unwrap());
            if seed {
                // The same real capture as execution seeds this isolated pool.
                drop(
                    pool.acquire(source.path(), Some(&identity), || false)
                        .unwrap(),
                );
            }
            let mut request = super::request();
            request["toolchain_identity"] = json!({
                "version":rabs_sandbox::toolchain_dataset::TOOLCHAIN_DATASET_VERSION,
                "sha256":hex(&identity.sha256), "files":identity.files, "bytes":identity.bytes,
            });
            (source, pool, request)
        }

        fn task(pool: &Arc<toolchain_pool::ToolchainPool>, reuse: bool) -> ToolchainTransferTask {
            let mut task = ToolchainTransferTask::with_reuse(reuse);
            task.state.as_mut().unwrap().pool = Some(Arc::clone(pool));
            task
        }

        fn begin(request: &Value) -> Value {
            json!({"kind":"toolchain-begin", "request_id":request["request_id"],
                "identity":request["toolchain_identity"], "entries":ENTRIES})
        }

        struct ThreadWake(std::thread::Thread);
        impl Wake for ThreadWake {
            fn wake(self: Arc<Self>) {
                self.0.unpark();
            }
            fn wake_by_ref(self: &Arc<Self>) {
                self.0.unpark();
            }
        }

        fn wait<T>(mut poll: impl FnMut(&mut Context<'_>) -> Poll<T>) -> T {
            let waker = Waker::from(Arc::new(ThreadWake(std::thread::current())));
            let mut cx = Context::from_waker(&waker);
            let until = Instant::now() + Duration::from_secs(5);
            loop {
                if let Poll::Ready(value) = poll(&mut cx) {
                    return value;
                }
                assert!(
                    Instant::now() < until,
                    "owned filesystem/execution task did not finish"
                );
                std::thread::park_timeout(Duration::from_millis(5));
            }
        }

        fn exchange(task: &mut ToolchainTransferTask, frame: &Value) -> Result<Value, String> {
            task.submit(frame, true, false)?;
            wait(|cx| task.poll_completion(cx))?.response
        }

        fn transfer_frames(request: &Value) -> Vec<Value> {
            let id = &request["request_id"];
            let digest = &request["toolchain_identity"]["sha256"];
            let entry = |path: &str, entry: Value| {
                json!({"kind":"toolchain-entry",
                "request_id":id, "sha256":digest, "path":path, "entry":entry})
            };
            vec![
                entry("", json!({"kind":"directory"})),
                entry("bin", json!({"kind":"directory"})),
                entry(
                    "bin/compiler",
                    json!({"kind":"file", "bytes":CONTENTS.len(), "executable":true}),
                ),
                json!({"kind":"toolchain-chunk", "request_id":id, "sha256":digest,
                    "path":"bin/compiler", "offset":0, "data_hex":hex(CONTENTS),
                    "chunk_sha256":crate::session::sha256_hex(CONTENTS)}),
                entry("empty", json!({"kind":"directory"})),
                entry("rustc", json!({"kind":"symlink", "target":"bin/compiler"})),
                json!({"kind":"toolchain-seal", "request_id":id, "sha256":digest}),
            ]
        }

        #[test]
        fn owned_toolchain_frames_reach_the_receiver_without_copying_payloads() {
            let (_source, pool, request) = fixture(0, false);
            let reactor = std::thread::current().id();
            let (observed_tx, observed_rx) = mpsc::channel();
            let mut task = task(&pool, false);
            task.start_worker(move |state, frame, cancelled| {
                if let Some(payload) = frame["data_hex"].as_str() {
                    observed_tx
                        .send((std::thread::current().id(), payload.as_ptr() as usize))
                        .unwrap();
                }
                state.handle(frame, cancelled)
            })
            .unwrap();
            let id = &request["request_id"];
            let digest = &request["toolchain_identity"]["sha256"];
            for frame in std::iter::once(begin(&request)).chain(transfer_frames(&request)) {
                let expected = match frame["kind"].as_str().unwrap() {
                    "toolchain-begin" | "toolchain-seal" => json!({
                        "kind":"toolchain-ready", "request_id":id, "sha256":digest,
                        "sealed":frame["kind"] == "toolchain-seal",
                    }),
                    "toolchain-entry" => json!({
                        "kind":"toolchain-entry-accepted", "request_id":id, "sha256":digest,
                        "path":frame["path"],
                    }),
                    "toolchain-chunk" => json!({
                        "kind":"toolchain-chunk-accepted", "request_id":id, "sha256":digest,
                        "path":frame["path"], "next_offset":CONTENTS.len(),
                    }),
                    _ => unreachable!(),
                };
                let payload = frame["data_hex"]
                    .as_str()
                    .map(|text| text.as_ptr() as usize);
                task.submit_owned(frame, true, false).unwrap();
                assert_eq!(
                    task.submit_owned(begin(&request), true, false).unwrap_err(),
                    "toolchain-operation-pending"
                );
                if let Some(payload) = payload {
                    let (worker, received) =
                        observed_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                    assert_ne!(worker, reactor);
                    assert_eq!(received, payload, "the encoded chunk allocation must move");
                }
                let reply = wait(|cx| task.poll_completion(cx)).unwrap();
                assert_eq!(Some(reply.request_id), id.as_u64());
                assert_eq!(reply.response.unwrap(), expected);
            }
            let root =
                Path::new(&task.prepared_path(&request, true).unwrap().unwrap()).to_path_buf();
            let owner = task.take_prepared(&request).unwrap().unwrap();
            drop(task);
            assert_eq!(fs::read(root.join("rustc")).unwrap(), CONTENTS);
            let ToolchainBacking::Uploaded(upload) = &owner.backing else {
                panic!("fixture must retain the uploaded image");
            };
            upload.prepared.as_ref().unwrap().verify(|| false).unwrap();
            drop(owner);
            assert!(!root.exists());
        }

        fn upload(
            pool: &Arc<toolchain_pool::ToolchainPool>,
            request: &Value,
        ) -> (ToolchainOwner, CanonicalExecRequest) {
            let (mut task, _) = receive_upload(pool, false, request);
            let root = task.prepared_path(request, true).unwrap().unwrap();
            let owner = task.take_prepared(request).unwrap().unwrap();
            drop(task);
            (owner, execution_request(request, root))
        }

        fn receive_upload(
            pool: &Arc<toolchain_pool::ToolchainPool>,
            reuse: bool,
            request: &Value,
        ) -> (ToolchainTransferTask, std::path::PathBuf) {
            let mut task = task(pool, reuse);
            assert_eq!(
                exchange(&mut task, &begin(request)).unwrap()["sealed"],
                false
            );
            let ToolchainBacking::Uploaded(upload) =
                &task.state.as_ref().unwrap().owner.as_ref().unwrap().backing
            else {
                panic!("cold begin must create an owned receiver");
            };
            let uploaded = fs::canonicalize(upload._directory.path())
                .unwrap()
                .join("tree");
            for frame in transfer_frames(request) {
                let reply = exchange(&mut task, &frame).unwrap();
                if frame["kind"] == "toolchain-seal" {
                    assert_eq!(
                        reply,
                        json!({"kind":"toolchain-ready",
                        "request_id":request["request_id"],
                        "sha256":request["toolchain_identity"]["sha256"], "sealed":true})
                    );
                }
            }
            (task, uploaded)
        }

        fn execution_request(request: &Value, root: String) -> CanonicalExecRequest {
            CanonicalExecRequest {
                request_id: request["request_id"].as_u64().unwrap(),
                program: "/__rabs/toolchain/bin/compiler".into(),
                args: Vec::new(),
                toolchain_backing: root,
                toolchain_identity: parse_toolchain_identity(request).unwrap(),
                workspace_backing: "/unused-source-fixture".into(),
                dependency_context: None,
                jobserver_grant: None,
                command_context: Default::default(),
            }
        }

        fn sealed(owner: ToolchainOwner, request: &CanonicalExecRequest) -> SealedToolchain {
            let expected = owner.identity;
            let ToolchainBacking::Uploaded(upload) = owner.into_execution_backing(request).unwrap()
            else {
                panic!("fixture must own an actual received image");
            };
            upload.into_sealed(&expected).unwrap()
        }

        fn inode(path: &Path) -> (u64, u64) {
            let metadata = fs::symlink_metadata(path).unwrap();
            (metadata.dev(), metadata.ino())
        }

        #[test]
        fn negotiated_seal_survives_disconnect_before_execution_without_reupload() {
            let (_source, pool, mut wire) = fixture(1024, false);
            let (cold, uploaded) = receive_upload(&pool, true, &wire);
            let compiler_inode = inode(&uploaded.join("bin/compiler"));
            assert_eq!(
                cold.prepared_path(&wire, true).unwrap().unwrap(),
                uploaded.to_str().unwrap()
            );
            let ToolchainBacking::UploadedRetained { lease, .. } =
                &cold.state.as_ref().unwrap().owner.as_ref().unwrap().backing
            else {
                panic!("negotiated seal must retain the completed SDK");
            };
            assert_eq!(lease.disposition(), "adopted");
            // Disconnect before taking an execution owner or submitting any
            // canonical-exec. The session drop joins its filesystem worker.
            drop(cold);
            assert!(uploaded.is_dir());
            wire["request_id"] = json!(37);
            let mut warm = task(&pool, true);
            assert_eq!(
                exchange(&mut warm, &begin(&wire)).unwrap(),
                json!({
                    "kind":"toolchain-ready", "request_id":37,
                    "sha256":wire["toolchain_identity"]["sha256"], "sealed":true,
                })
            );
            // The fresh request sent only begin: no entry, chunk or seal.
            assert_eq!(
                warm.prepared_path(&wire, true).unwrap().unwrap(),
                uploaded.to_str().unwrap()
            );
            assert_eq!(inode(&uploaded.join("bin/compiler")), compiler_inode);
            assert_eq!(fs::read(uploaded.join("rustc")).unwrap(), CONTENTS);
            assert!(uploaded.join("empty").is_dir());
            drop(warm);
            drop(pool);
            assert!(!uploaded.exists());
        }

        #[test]
        fn negotiated_seal_publishes_durable_input_before_any_execution() {
            let (_source, initial, mut wire) = fixture(1024, false);
            drop(initial);
            let parent = tempfile::tempdir().unwrap();
            let directory = parent.path().join("durable");
            let pool = Arc::new(ToolchainPool::with_directory(1024, 2, Some(&directory)).unwrap());
            let (cold, uploaded) = receive_upload(&pool, true, &wire);
            let published =
                std::path::PathBuf::from(cold.prepared_path(&wire, true).unwrap().unwrap());
            assert_ne!(published, uploaded);
            assert!(!uploaded.exists());
            let ToolchainBacking::UploadedRetained { lease, .. } =
                &cold.state.as_ref().unwrap().owner.as_ref().unwrap().backing
            else {
                panic!("the seal must publish a complete durable SDK");
            };
            assert_eq!(lease.disposition(), "adopted");
            let compiler_inode = inode(&published.join("bin/compiler"));
            drop(cold);
            drop(pool);

            let reopened =
                Arc::new(ToolchainPool::with_directory(1024, 2, Some(&directory)).unwrap());
            wire["request_id"] = json!(73);
            let mut warm = task(&reopened, true);
            let reply = exchange(&mut warm, &begin(&wire)).unwrap();
            assert_eq!(reply["request_id"], 73);
            assert_eq!(reply["sealed"], true);
            assert_eq!(
                Path::new(&warm.prepared_path(&wire, true).unwrap().unwrap()),
                published
            );
            assert_eq!(inode(&published.join("bin/compiler")), compiler_inode);
            assert_eq!(fs::read(published.join("rustc")).unwrap(), CONTENTS);
            let owner = warm.take_prepared(&wire).unwrap().unwrap();
            drop(warm);
            drop(reopened);
            assert!(ToolchainPool::with_directory(1024, 2, Some(&directory)).is_err());
            drop(owner);
            assert!(published.is_dir());
            let reopened = ToolchainPool::with_directory(1024, 2, Some(&directory)).unwrap();
            let identity = request_identity(&wire).unwrap().unwrap();
            reopened
                .lookup(&identity, || false)
                .unwrap()
                .unwrap()
                .verify(|| false)
                .unwrap();
        }

        #[test]
        fn seal_retention_requires_negotiation_and_a_sufficient_enabled_budget() {
            for (reuse, budget) in [(false, 1024), (true, 0), (true, CONTENTS.len() as u64 - 1)] {
                let (_source, pool, mut wire) = fixture(budget, false);
                let (cold, uploaded) = receive_upload(&pool, reuse, &wire);
                assert!(matches!(
                    cold.state.as_ref().unwrap().owner.as_ref().unwrap().backing,
                    ToolchainBacking::Uploaded(_)
                ));
                drop(cold);
                assert!(!uploaded.exists());
                wire["request_id"] = json!(19);
                let mut fresh = task(&pool, true);
                assert_eq!(
                    exchange(&mut fresh, &begin(&wire)).unwrap()["sealed"],
                    false
                );
            }
        }

        #[test]
        fn full_pool_keeps_sealed_upload_private_without_recapture_or_busy_eviction() {
            let (source, pool, wire) = fixture(CONTENTS.len() as u64, false);
            fs::write(
                source.path().join("bin/compiler"),
                vec![b'x'; CONTENTS.len()],
            )
            .unwrap();
            let other = fingerprint_toolchain(source.path(), &ToolchainLimits::default(), || false)
                .unwrap();
            let busy = pool.acquire(source.path(), Some(&other), || false).unwrap();
            let busy_root = busy.root().to_path_buf();
            let (mut cold, uploaded) = receive_upload(&pool, true, &wire);
            let compiler_inode = inode(&uploaded.join("bin/compiler"));
            let root = cold.prepared_path(&wire, true).unwrap().unwrap();
            let owner = cold.take_prepared(&wire).unwrap().unwrap();
            drop(cold);
            let lease = owner
                .into_lease(&execution_request(&wire, root), || false)
                .unwrap();
            assert_eq!(lease.disposition(), "private");
            assert_eq!(lease.root(), uploaded);
            assert_eq!(inode(&uploaded.join("bin/compiler")), compiler_inode);
            assert_eq!(busy.root(), busy_root);
            busy.verify(|| false).unwrap();
            assert!(pool.lookup(lease.identity(), || false).unwrap().is_none());
            drop(lease);
            assert!(!uploaded.exists());
            assert!(busy_root.is_dir());
        }

        #[test]
        fn seal_time_owner_outlives_its_pool_and_keeps_its_exact_execution_image() {
            let (_source, pool, wire) = fixture(1024, false);
            let (mut cold, uploaded) = receive_upload(&pool, true, &wire);
            let compiler_inode = inode(&uploaded.join("bin/compiler"));
            let root = cold.prepared_path(&wire, true).unwrap().unwrap();
            let owner = cold.take_prepared(&wire).unwrap().unwrap();
            drop(cold);
            let weak = Arc::downgrade(&pool);
            drop(pool);
            assert!(
                weak.upgrade().is_none(),
                "an input must not retain every idle SDK"
            );
            assert!(uploaded.is_dir());
            let lease = owner
                .into_lease(&execution_request(&wire, root), || false)
                .unwrap();
            assert_eq!(lease.disposition(), "adopted");
            assert_eq!(lease.root(), uploaded);
            assert_eq!(inode(&uploaded.join("bin/compiler")), compiler_inode);
            lease.verify(|| false).unwrap();
            drop(lease);
            assert!(!uploaded.exists());
        }

        #[test]
        fn changed_or_restored_seal_time_image_refuses_execution_and_retires_its_slot() {
            for restored in [false, true] {
                let (_source, pool, wire) = fixture(1024, false);
                let (mut cold, uploaded) = receive_upload(&pool, true, &wire);
                let root = cold.prepared_path(&wire, true).unwrap().unwrap();
                let owner = cold.take_prepared(&wire).unwrap().unwrap();
                drop(cold);
                let compiler = uploaded.join("bin/compiler");
                let mode = fs::metadata(&compiler).unwrap().permissions();
                fs::set_permissions(&compiler, fs::Permissions::from_mode(0o700)).unwrap();
                fs::write(&compiler, vec![b'x'; CONTENTS.len()]).unwrap();
                if restored {
                    fs::write(&compiler, CONTENTS).unwrap();
                    fs::set_permissions(&compiler, mode).unwrap();
                }
                assert!(
                    owner
                        .into_lease(&execution_request(&wire, root), || false)
                        .is_err()
                );
                let identity = request_identity(&wire).unwrap().unwrap();
                assert!(pool.lookup(&identity, || false).unwrap().is_none());
                assert!(!uploaded.exists());
            }
        }

        #[test]
        fn retained_upload_handoff_keeps_request_full_identity_and_root_binding() {
            for changed in ["request_id", "sha256", "files", "bytes", "missing", "root"] {
                let (_source, pool, wire) = fixture(1024, false);
                let (mut cold, uploaded) = receive_upload(&pool, true, &wire);
                let root = cold.prepared_path(&wire, true).unwrap().unwrap();
                let owner = cold.take_prepared(&wire).unwrap().unwrap();
                drop(cold);
                let mut request = execution_request(&wire, root);
                match changed {
                    "request_id" => request.request_id += 1,
                    "sha256" => request.toolchain_identity.as_mut().unwrap().sha256[0] ^= 1,
                    "files" => request.toolchain_identity.as_mut().unwrap().files += 1,
                    "bytes" => request.toolchain_identity.as_mut().unwrap().bytes += 1,
                    "missing" => request.toolchain_identity = None,
                    "root" => request.toolchain_backing.push_str("/bin"),
                    _ => unreachable!(),
                }
                assert!(owner.into_lease(&request, || false).is_err(), "{changed}");
                // A foreign execution cannot consume this owner, but it also
                // cannot revoke a correctly retained SDK for independent peers.
                let identity = request_identity(&wire).unwrap().unwrap();
                pool.lookup(&identity, || false)
                    .unwrap()
                    .unwrap()
                    .verify(|| false)
                    .unwrap();
                drop(pool);
                assert!(!uploaded.exists());
            }
        }

        #[test]
        fn cancellation_after_seal_publication_never_delivers_readiness_to_that_request() {
            let (_source, pool, mut wire) = fixture(1024, false);
            let (sealed_tx, sealed_rx) = mpsc::sync_channel(1);
            let (release_tx, release_rx) = mpsc::sync_channel(1);
            let mut cold = task(&pool, true);
            cold.start_worker(move |state, frame, cancelled| {
                let reply = state.handle(frame, cancelled);
                if frame["kind"] == "toolchain-seal" {
                    assert_eq!(reply.as_ref().unwrap()["sealed"], true);
                    sealed_tx.send(()).unwrap();
                    release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                }
                reply
            })
            .unwrap();
            exchange(&mut cold, &begin(&wire)).unwrap();
            let mut frames = transfer_frames(&wire);
            let seal = frames.pop().unwrap();
            for frame in frames {
                exchange(&mut cold, &frame).unwrap();
            }
            cold.submit_owned(seal, true, false).unwrap();
            sealed_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            assert_eq!(
                cold.cancel(wire["request_id"].as_u64().unwrap()),
                Some(true)
            );
            release_tx.send(()).unwrap();
            let reply = wait(|cx| cold.poll_completion(cx)).unwrap();
            assert_eq!(reply.request_id, wire["request_id"].as_u64().unwrap());
            assert_eq!(reply.response.unwrap_err(), "toolchain upload cancelled");
            assert!(cold.prepared_path(&wire, true).is_err());
            assert!(cold.take_prepared(&wire).is_err());
            drop(cold);
            // Complete independent input is reusable; cancellation has granted
            // neither execution nor a successful reply to the old request.
            wire["request_id"] = json!(42);
            let mut fresh = task(&pool, true);
            assert_eq!(exchange(&mut fresh, &begin(&wire)).unwrap()["sealed"], true);
        }

        #[test]
        fn cancellation_or_original_deadline_before_seal_cannot_publish_an_upload() {
            for cancel in [false, true] {
                let (_source, pool, wire) = fixture(1024, false);
                let mut cold = task(&pool, true);
                exchange(&mut cold, &begin(&wire)).unwrap();
                let mut frames = transfer_frames(&wire);
                let seal = frames.pop().unwrap();
                for frame in frames {
                    exchange(&mut cold, &frame).unwrap();
                }
                if cancel {
                    assert_eq!(
                        cold.cancel(wire["request_id"].as_u64().unwrap()),
                        Some(true)
                    );
                } else {
                    cold.state
                        .as_mut()
                        .unwrap()
                        .owner
                        .as_mut()
                        .unwrap()
                        .deadline = Instant::now();
                }
                assert!(exchange(&mut cold, &seal).is_err());
                assert!(cold.take_prepared(&wire).is_err());
                let identity = request_identity(&wire).unwrap().unwrap();
                assert!(pool.lookup(&identity, || false).unwrap().is_none());
            }
        }

        #[test]
        fn competing_corrupt_pool_owner_refuses_seal_instead_of_refreshing_from_upload() {
            for durable in [false, true] {
                let (source, initial, wire) = fixture(1024, false);
                let parent = tempfile::tempdir().unwrap();
                let pool = if durable {
                    Arc::new(
                        ToolchainPool::with_directory(
                            1024,
                            2,
                            Some(&parent.path().join("durable")),
                        )
                        .unwrap(),
                    )
                } else {
                    initial
                };
                let identity = request_identity(&wire).unwrap().unwrap();
                let mut cold = task(&pool, true);
                assert_eq!(exchange(&mut cold, &begin(&wire)).unwrap()["sealed"], false);
                let mut frames = transfer_frames(&wire);
                let seal = frames.pop().unwrap();
                for frame in frames {
                    exchange(&mut cold, &frame).unwrap();
                }
                let competing = pool
                    .acquire(source.path(), Some(&identity), || false)
                    .unwrap();
                let compiler = competing.root().join("bin/compiler");
                fs::set_permissions(&compiler, fs::Permissions::from_mode(0o700)).unwrap();
                fs::write(&compiler, vec![b'x'; CONTENTS.len()]).unwrap();
                assert!(exchange(&mut cold, &seal).is_err());
                assert!(cold.prepared_path(&wire, true).is_err());
                assert!(cold.take_prepared(&wire).is_err());
                assert_eq!(
                    exchange(&mut cold, &begin(&wire)).unwrap_err(),
                    "toolchain upload failed"
                );
                assert!(competing.verify(|| false).is_err());
                if durable {
                    assert!(pool.lookup(&identity, || false).is_err());
                } else {
                    assert!(pool.lookup(&identity, || false).unwrap().is_none());
                }
            }
        }

        #[test]
        fn sealed_upload_becomes_the_same_private_tree_until_its_last_lease_drops() {
            for budget in [0, 1024] {
                let (_source, pool, wire) = fixture(budget, false);
                let (owner, request) = upload(&pool, &wire);
                let root = Path::new(&request.toolchain_backing).to_path_buf();
                let directory_inode = inode(&root);
                let compiler_inode = inode(&root.join("bin/compiler"));
                let lease = pool.adopt(sealed(owner, &request), || false).unwrap();
                assert_eq!(
                    lease.disposition(),
                    if budget == 0 { "private" } else { "adopted" }
                );
                assert_eq!(lease.root(), root);
                assert_eq!(inode(lease.root()), directory_inode);
                assert_eq!(inode(&lease.root().join("bin/compiler")), compiler_inode);
                assert_eq!(fs::read(lease.root().join("rustc")).unwrap(), CONTENTS);
                lease.verify(|| false).unwrap();
                let retained = pool.lookup(lease.identity(), || false).unwrap();
                assert_eq!(retained.is_some(), budget != 0);
                if let Some(retained) = retained {
                    assert_eq!(retained.root(), root);
                    drop(retained);
                }
                drop(pool);
                assert!(
                    root.is_dir(),
                    "execution lease must own the original upload"
                );
                lease.verify(|| false).unwrap();
                drop(lease);
                assert!(!root.exists(), "last owner must release private storage");
            }
        }

        #[test]
        fn execution_handoff_without_a_supervisor_adopts_the_received_owner() {
            let (_source, pool, wire) = fixture(0, false);
            let (owner, request) = upload(&pool, &wire);
            let root = Path::new(&request.toolchain_backing).to_path_buf();
            let compiler_inode = inode(&root.join("bin/compiler"));
            let lease = owner.into_lease(&request, || false).unwrap();
            assert_eq!(lease.root(), root);
            assert_eq!(inode(&lease.root().join("bin/compiler")), compiler_inode);
            lease.verify(|| false).unwrap();
            drop(lease);
            assert!(!root.exists());
        }

        #[test]
        fn adopted_root_and_parent_cannot_be_exposed_through_a_writable_mount() {
            use rabs_sandbox::canonical_namespace::{Bind, CanonicalNamespaceSpec};
            let (_source, pool, wire) = fixture(1024, false);
            let (owner, request) = upload(&pool, &wire);
            let lease = pool.adopt(sealed(owner, &request), || false).unwrap();
            let child = lease.root().join("bin");
            for writable in [
                lease.root(),
                lease.root().parent().unwrap(),
                child.as_path(),
            ] {
                let mut spec = CanonicalNamespaceSpec::new();
                spec.ro_binds
                    .push(Bind::new(lease.root(), rabs_sandbox::layout::TOOLCHAIN));
                spec.rw_binds
                    .push(Bind::new(writable, rabs_sandbox::layout::WORKSPACE));
                assert!(
                    lease.validate_namespace(&spec).is_err(),
                    "{}",
                    writable.display()
                );
            }
            let workspace = tempfile::tempdir().unwrap();
            let mut spec = CanonicalNamespaceSpec::new();
            spec.ro_binds
                .push(Bind::new(lease.root(), rabs_sandbox::layout::TOOLCHAIN));
            spec.rw_binds
                .push(Bind::new(workspace.path(), rabs_sandbox::layout::WORKSPACE));
            lease.validate_namespace(&spec).unwrap();
        }

        #[test]
        fn full_or_small_pool_executes_the_upload_privately_without_an_extra_copy() {
            for busy in [false, true] {
                let budget = CONTENTS.len() as u64 - u64::from(!busy);
                let (source, pool, wire) = fixture(budget, false);
                let other = if busy {
                    fs::write(
                        source.path().join("bin/compiler"),
                        vec![b'x'; CONTENTS.len()],
                    )
                    .unwrap();
                    let other_identity =
                        fingerprint_toolchain(source.path(), &ToolchainLimits::default(), || false)
                            .unwrap();
                    Some(
                        pool.acquire(source.path(), Some(&other_identity), || false)
                            .unwrap(),
                    )
                } else {
                    None
                };
                let (owner, request) = upload(&pool, &wire);
                let root = Path::new(&request.toolchain_backing).to_path_buf();
                let compiler_inode = inode(&root.join("bin/compiler"));
                let lease = pool.adopt(sealed(owner, &request), || false).unwrap();
                assert_eq!(lease.disposition(), "private");
                assert_eq!(lease.root(), root);
                assert_eq!(inode(&lease.root().join("bin/compiler")), compiler_inode);
                assert!(pool.lookup(lease.identity(), || false).unwrap().is_none());
                if let Some(other) = other {
                    other.verify(|| false).unwrap();
                    assert_ne!(other.identity(), lease.identity());
                }
                drop(lease);
                assert!(!root.exists());
            }
        }

        #[test]
        fn same_identity_ready_owner_wins_without_retaining_a_redundant_upload() {
            let (_source, pool, wire) = fixture(1024, false);
            let (owner, request) = upload(&pool, &wire);
            let first = pool.adopt(sealed(owner, &request), || false).unwrap();
            let (owner, request) = upload(&pool, &wire);
            let redundant = Path::new(&request.toolchain_backing).to_path_buf();
            assert_ne!(first.root(), redundant);
            let second = pool.adopt(sealed(owner, &request), || false).unwrap();
            assert_eq!(first.root(), second.root());
            assert_eq!(second.disposition(), "reused");
            assert!(!redundant.exists());
            first.verify(|| false).unwrap();
            second.verify(|| false).unwrap();
        }

        fn full_durable_fixture() -> (
            tempfile::TempDir,
            Arc<toolchain_pool::ToolchainPool>,
            Value,
            std::path::PathBuf,
        ) {
            let (source, initial_pool, wire) = fixture(1024, false);
            drop(initial_pool);
            fs::write(
                source.path().join("bin/compiler"),
                vec![b'x'; CONTENTS.len()],
            )
            .unwrap();
            let other = fingerprint_toolchain(source.path(), &ToolchainLimits::default(), || false)
                .unwrap();
            let parent = tempfile::tempdir().unwrap();
            let root = parent.path().join("durable");
            let budget = CONTENTS.len() as u64;
            let pool =
                toolchain_pool::ToolchainPool::with_directory(budget, 1, Some(&root)).unwrap();
            let retained = pool.acquire(source.path(), Some(&other), || false).unwrap();
            let retained_root = retained.root().to_path_buf();
            drop(retained);
            drop(pool);
            // Reopening empties the memory pool while the durable catalogue
            // remains full. Its refusal must not force another private copy.
            let pool = Arc::new(
                toolchain_pool::ToolchainPool::with_directory(budget, 1, Some(&root)).unwrap(),
            );
            (parent, pool, wire, retained_root)
        }

        #[test]
        fn full_durable_cache_adopts_the_upload_until_its_last_ephemeral_lease_drops() {
            use rabs_sandbox::canonical_namespace::{Bind, CanonicalNamespaceSpec};

            let (parent, pool, wire, retained_root) = full_durable_fixture();
            let cache_root = parent.path().join("durable");
            let retained_inode = inode(&retained_root.join("bin/compiler"));
            let (owner, request) = upload(&pool, &wire);
            let root = Path::new(&request.toolchain_backing).to_path_buf();
            let directory_inode = inode(&root);
            let compiler_inode = inode(&root.join("bin/compiler"));
            let lease = pool.adopt(sealed(owner, &request), || false).unwrap();
            assert_eq!(lease.disposition(), "adopted");
            assert_eq!(lease.root(), root);
            assert_eq!(inode(lease.root()), directory_inode);
            assert_eq!(inode(&lease.root().join("bin/compiler")), compiler_inode);
            assert_eq!(fs::read(lease.root().join("rustc")).unwrap(), CONTENTS);
            lease.verify(|| false).unwrap();
            let retained = pool.lookup(lease.identity(), || false).unwrap().unwrap();
            assert_eq!(retained.root(), root);
            drop(retained);
            assert_eq!(
                fs::read_dir(cache_root.join("toolchains-v1"))
                    .unwrap()
                    .count(),
                1
            );
            assert_eq!(inode(&retained_root.join("bin/compiler")), retained_inode);

            for writable in [root.parent().unwrap(), cache_root.as_path()] {
                let mut spec = CanonicalNamespaceSpec::new();
                spec.ro_binds
                    .push(Bind::new(&root, rabs_sandbox::layout::TOOLCHAIN));
                spec.rw_binds
                    .push(Bind::new(writable, rabs_sandbox::layout::WORKSPACE));
                assert!(lease.validate_namespace(&spec).is_err());
            }
            let identity = *lease.identity();
            drop(pool);
            assert!(root.is_dir());
            assert!(
                toolchain_pool::ToolchainPool::with_directory(
                    CONTENTS.len() as u64,
                    1,
                    Some(&cache_root),
                )
                .is_err(),
                "the private lease must also retain the durable store lock",
            );
            lease.verify(|| false).unwrap();
            drop(lease);
            assert!(!root.exists());
            assert_eq!(inode(&retained_root.join("bin/compiler")), retained_inode);
            let reopened = toolchain_pool::ToolchainPool::with_directory(
                CONTENTS.len() as u64,
                1,
                Some(&cache_root),
            )
            .unwrap();
            assert!(reopened.lookup(&identity, || false).unwrap().is_none());
        }

        #[test]
        fn too_small_durable_budget_keeps_the_owned_upload_private_without_copying() {
            let (_source, initial_pool, wire) = fixture(1024, false);
            drop(initial_pool);
            let parent = tempfile::tempdir().unwrap();
            let cache_root = parent.path().join("durable");
            let pool = Arc::new(
                toolchain_pool::ToolchainPool::with_directory(
                    CONTENTS.len() as u64 - 1,
                    2,
                    Some(&cache_root),
                )
                .unwrap(),
            );
            let (owner, request) = upload(&pool, &wire);
            let root = Path::new(&request.toolchain_backing).to_path_buf();
            let directory_inode = inode(&root);
            let compiler_inode = inode(&root.join("bin/compiler"));
            let lease = pool.adopt(sealed(owner, &request), || false).unwrap();
            assert_eq!(lease.disposition(), "private");
            assert_eq!(lease.root(), root);
            assert_eq!(inode(lease.root()), directory_inode);
            assert_eq!(inode(&lease.root().join("bin/compiler")), compiler_inode);
            assert!(pool.lookup(lease.identity(), || false).unwrap().is_none());
            assert_eq!(
                fs::read_dir(cache_root.join("toolchains-v1"))
                    .unwrap()
                    .count(),
                0
            );
            drop(pool);
            lease.verify(|| false).unwrap();
            drop(lease);
            assert!(!root.exists());
        }

        #[test]
        fn busy_durable_writer_adopts_an_unrelated_upload_without_copying_or_waiting() {
            use std::cell::Cell;

            let (source, initial_pool, wire) = fixture(1024, false);
            drop(initial_pool);
            fs::write(
                source.path().join("bin/compiler"),
                vec![b'x'; CONTENTS.len()],
            )
            .unwrap();
            let other = fingerprint_toolchain(source.path(), &ToolchainLimits::default(), || false)
                .unwrap();
            let parent = tempfile::tempdir().unwrap();
            let cache_root = parent.path().join("durable");
            let pool = Arc::new(
                toolchain_pool::ToolchainPool::with_directory(1024, 2, Some(&cache_root)).unwrap(),
            );
            let (owner, request) = upload(&pool, &wire);
            let root = Path::new(&request.toolchain_backing).to_path_buf();
            let directory_inode = inode(&root);
            let compiler_inode = inode(&root.join("bin/compiler"));
            let (entered_tx, entered_rx) = mpsc::sync_channel(1);
            let (resume_tx, resume_rx) = mpsc::sync_channel(1);
            let writer_pool = Arc::clone(&pool);
            let source_root = source.path().to_path_buf();
            let objects = cache_root.join("toolchains-v1");
            let writer = std::thread::spawn(move || {
                let paused = Cell::new(false);
                writer_pool.acquire(&source_root, Some(&other), || {
                    if !paused.get()
                        && fs::read_dir(&objects).unwrap().any(|entry| {
                            entry
                                .unwrap()
                                .file_name()
                                .to_string_lossy()
                                .starts_with(".pending-")
                        })
                    {
                        // An actual durable capture holds the writer and its
                        // on-disk reservation, before copying the first byte.
                        paused.set(true);
                        entered_tx.send(()).unwrap();
                        resume_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                    }
                    false
                })
            });
            entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            let lease = pool.adopt(sealed(owner, &request), || false).unwrap();
            assert_eq!(lease.disposition(), "adopted");
            assert_eq!(lease.root(), root);
            assert_eq!(inode(lease.root()), directory_inode);
            assert_eq!(inode(&lease.root().join("bin/compiler")), compiler_inode);
            assert_eq!(
                fs::read_dir(cache_root.join("toolchains-v1"))
                    .unwrap()
                    .count(),
                1
            );
            lease.verify(|| false).unwrap();
            resume_tx.send(()).unwrap();
            let captured = writer.join().unwrap().unwrap();
            assert_eq!(captured.disposition(), "captured");
            assert_ne!(captured.identity(), lease.identity());
            captured.verify(|| false).unwrap();
            drop(captured);
            drop(pool);
            assert!(root.is_dir());
            drop(lease);
            assert!(!root.exists());
        }

        #[test]
        fn durable_upload_adoption_preserves_all_inodes_and_survives_restart() {
            use std::cell::Cell;

            let (_source, initial_pool, wire) = fixture(1024, false);
            drop(initial_pool);
            let cache_parent = tempfile::tempdir().unwrap();
            let cache_root = cache_parent.path().join("durable");
            let pool = Arc::new(
                toolchain_pool::ToolchainPool::with_directory(1024, 2, Some(&cache_root)).unwrap(),
            );
            let identity = parse_toolchain_identity(&wire).unwrap().unwrap();
            let (owner, request) = upload(&pool, &wire);
            let uploaded = Path::new(&request.toolchain_backing).to_path_buf();
            let uploaded_inode = inode(&uploaded.join("bin/compiler"));
            let container_inode = inode(uploaded.parent().unwrap());
            let paths = ["", "bin", "bin/compiler", "empty", "rustc"];
            let inodes = paths.map(|path| inode(&uploaded.join(path)));
            let check_image = |root: &Path| {
                for (path, expected) in paths.iter().zip(inodes) {
                    assert_eq!(inode(&root.join(path)), expected, "{path}");
                }
                assert_eq!(fs::read(root.join("rustc")).unwrap(), CONTENTS);
            };
            let published = cache_root
                .join("toolchains-v1")
                .join(format!(
                    "v1-{}-{}-{}",
                    hex(&identity.sha256),
                    identity.files,
                    identity.bytes
                ))
                .join("tree");
            let observed_upload = Cell::new(false);
            let observed_pending = Cell::new(false);
            let observed_publication = Cell::new(false);
            let lease = pool
                .adopt(sealed(owner, &request), || {
                    if uploaded.exists() {
                        check_image(&uploaded);
                        observed_upload.set(true);
                    } else if published.exists() {
                        check_image(&published);
                        observed_publication.set(true);
                    } else {
                        // The owned container moves atomically to its charged
                        // pending name; none of its dataset inodes may change.
                        let pending = fs::read_dir(cache_root.join("toolchains-v1"))
                            .unwrap()
                            .next()
                            .unwrap()
                            .unwrap()
                            .path();
                        assert!(
                            pending
                                .file_name()
                                .unwrap()
                                .to_string_lossy()
                                .starts_with(".pending-")
                        );
                        assert_eq!(inode(&pending), container_inode);
                        check_image(&pending.join("tree"));
                        observed_pending.set(true);
                    }
                    false
                })
                .unwrap();
            assert!(observed_upload.get() && observed_pending.get() && observed_publication.get());
            assert_eq!(lease.disposition(), "adopted");
            assert_eq!(lease.root(), published);
            assert!(!uploaded.exists());
            let published_inode = inode(&published.join("bin/compiler"));
            assert_eq!(published_inode, uploaded_inode);
            assert_eq!(inode(published.parent().unwrap()), container_inode);
            assert!(!uploaded.parent().unwrap().exists());
            lease.verify(|| false).unwrap();

            // Supervisor shutdown does not release durable ownership while an
            // execution still holds the lease, nor remove a published image.
            drop(pool);
            assert!(published.is_dir());
            assert!(
                toolchain_pool::ToolchainPool::with_directory(1024, 2, Some(&cache_root)).is_err()
            );
            drop(lease);
            assert!(published.is_dir());
            let reopened = Arc::new(
                toolchain_pool::ToolchainPool::with_directory(1024, 2, Some(&cache_root)).unwrap(),
            );
            let retained = reopened.lookup(&identity, || false).unwrap().unwrap();
            assert_eq!(retained.root(), published);
            assert_eq!(
                inode(&retained.root().join("bin/compiler")),
                published_inode
            );
            retained.verify(|| false).unwrap();

            let mut warm = task(&reopened, true);
            assert_eq!(exchange(&mut warm, &begin(&wire)).unwrap()["sealed"], true);
            assert_eq!(
                Path::new(&warm.prepared_path(&wire, true).unwrap().unwrap()),
                published
            );
            drop(warm.take_prepared(&wire).unwrap().unwrap());
            drop(warm);

            // A peer that uploads again still resolves through the ready pool
            // owner; its redundant temporary image must not become retained.
            let (owner, request) = upload(&reopened, &wire);
            let redundant = Path::new(&request.toolchain_backing).to_path_buf();
            let reused = reopened.adopt(sealed(owner, &request), || false).unwrap();
            assert_eq!(reused.disposition(), "reused");
            assert_eq!(reused.root(), published);
            assert!(!redundant.exists());
            assert_eq!(inode(&reused.root().join("bin/compiler")), published_inode);
            reused.verify(|| false).unwrap();
        }

        #[test]
        fn cancelled_durable_move_preserves_charged_pending_image_across_restart() {
            use std::cell::Cell;

            let (_source, initial_pool, wire) = fixture(1024, false);
            drop(initial_pool);
            let parent = tempfile::tempdir().unwrap();
            let cache_root = parent.path().join("durable");
            let objects = cache_root.join("toolchains-v1");
            let budget = CONTENTS.len() as u64;
            let pool = Arc::new(
                toolchain_pool::ToolchainPool::with_directory(budget, 1, Some(&cache_root))
                    .unwrap(),
            );
            let identity = parse_toolchain_identity(&wire).unwrap().unwrap();
            let (owner, request) = upload(&pool, &wire);
            let uploaded = Path::new(&request.toolchain_backing).to_path_buf();
            let root_inode = inode(&uploaded);
            let compiler_inode = inode(&uploaded.join("bin/compiler"));
            let container_inode = inode(uploaded.parent().unwrap());
            let moved = Cell::new(false);
            let error = pool
                .adopt(sealed(owner, &request), || {
                    let cancelled = !uploaded.exists();
                    moved.set(moved.get() || cancelled);
                    cancelled
                })
                .err()
                .unwrap();
            assert_eq!(error.kind(), io::ErrorKind::Interrupted);
            assert!(moved.get());
            assert!(!uploaded.exists());
            let entries: Vec<_> = fs::read_dir(&objects)
                .unwrap()
                .map(Result::unwrap)
                .collect();
            assert_eq!(entries.len(), 1);
            let pending = entries[0].path();
            assert!(
                pending
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with(".pending-")
            );
            assert_eq!(inode(&pending), container_inode);
            assert_eq!(inode(&pending.join("tree")), root_inode);
            assert_eq!(inode(&pending.join("tree/bin/compiler")), compiler_inode);
            assert_eq!(fs::read(pending.join("tree/rustc")).unwrap(), CONTENTS);
            assert!(pool.lookup(&identity, || false).unwrap().is_none());
            drop(pool);
            assert!(pending.is_dir());

            // A restart must charge the complete interrupted reservation. It
            // cannot reuse or erase those bytes to admit a fresh durable entry.
            let restarted = Arc::new(
                toolchain_pool::ToolchainPool::with_directory(budget, 1, Some(&cache_root))
                    .unwrap(),
            );
            let (owner, request) = upload(&restarted, &wire);
            let fresh = Path::new(&request.toolchain_backing).to_path_buf();
            let lease = restarted.adopt(sealed(owner, &request), || false).unwrap();
            assert_eq!(lease.disposition(), "adopted");
            assert_eq!(lease.root(), fresh);
            assert_ne!(inode(lease.root()), root_inode);
            lease.verify(|| false).unwrap();
            assert_eq!(fs::read_dir(&objects).unwrap().count(), 1);
            assert_eq!(inode(&pending), container_inode);
            assert_eq!(inode(&pending.join("tree/bin/compiler")), compiler_inode);
        }

        #[test]
        fn durable_move_never_replaces_an_existing_pending_directory() {
            let (_source, initial_pool, wire) = fixture(1024, false);
            drop(initial_pool);
            let parent = tempfile::tempdir().unwrap();
            let cache_root = parent.path().join("durable");
            let objects = cache_root.join("toolchains-v1");
            let pool = Arc::new(
                toolchain_pool::ToolchainPool::with_directory(1024, 2, Some(&cache_root)).unwrap(),
            );
            let identity = parse_toolchain_identity(&wire).unwrap().unwrap();
            let (owner, request) = upload(&pool, &wire);
            let uploaded = Path::new(&request.toolchain_backing).to_path_buf();
            let container = fs::symlink_metadata(uploaded.parent().unwrap()).unwrap();
            let pending = objects.join(format!(
                ".pending-v1-{}-{}-{}-{:016x}{:016x}",
                hex(&identity.sha256),
                identity.files,
                identity.bytes,
                container.dev(),
                container.ino(),
            ));
            fs::create_dir(&pending).unwrap();
            fs::set_permissions(&pending, fs::Permissions::from_mode(0o700)).unwrap();
            fs::write(pending.join("receipt"), b"keep existing reservation").unwrap();
            let pending_inode = inode(&pending);
            let error = pool
                .adopt(sealed(owner, &request), || false)
                .err()
                .unwrap();
            assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
            assert_eq!(inode(&pending), pending_inode);
            assert_eq!(
                fs::read(pending.join("receipt")).unwrap(),
                b"keep existing reservation",
            );
            assert_eq!(fs::read_dir(&objects).unwrap().count(), 1);
            assert!(pool.lookup(&identity, || false).unwrap().is_none());
            assert!(!uploaded.exists());
        }

        #[test]
        fn durable_move_refuses_unrelated_entries_in_the_owned_upload_container() {
            let (_source, initial_pool, wire) = fixture(1024, false);
            drop(initial_pool);
            let parent = tempfile::tempdir().unwrap();
            let cache_root = parent.path().join("durable");
            let pool = Arc::new(
                toolchain_pool::ToolchainPool::with_directory(1024, 2, Some(&cache_root)).unwrap(),
            );
            let (owner, request) = upload(&pool, &wire);
            let uploaded = Path::new(&request.toolchain_backing).to_path_buf();
            fs::write(uploaded.parent().unwrap().join("unrelated"), b"not keyed").unwrap();
            assert!(pool.adopt(sealed(owner, &request), || false).is_err());
            assert!(!uploaded.exists());
            assert_eq!(
                fs::read_dir(cache_root.join("toolchains-v1"))
                    .unwrap()
                    .count(),
                0
            );
        }

        #[test]
        fn durable_upload_cannot_refresh_its_generation_during_published_reopen() {
            use std::cell::Cell;

            let (_source, initial_pool, wire) = fixture(1024, false);
            drop(initial_pool);
            let parent = tempfile::tempdir().unwrap();
            let cache_root = parent.path().join("durable");
            let pool = Arc::new(
                toolchain_pool::ToolchainPool::with_directory(1024, 2, Some(&cache_root)).unwrap(),
            );
            let identity = parse_toolchain_identity(&wire).unwrap().unwrap();
            let (owner, request) = upload(&pool, &wire);
            let uploaded = Path::new(&request.toolchain_backing).to_path_buf();
            let compiler_inode = inode(&uploaded.join("bin/compiler"));
            let published = cache_root
                .join("toolchains-v1")
                .join(format!(
                    "v1-{}-{}-{}",
                    hex(&identity.sha256),
                    identity.files,
                    identity.bytes,
                ))
                .join("tree");
            let changed = Cell::new(false);
            let error = pool
                .adopt(sealed(owner, &request), || {
                    if !changed.get() && published.exists() {
                        // The original witness retains one root descriptor. The
                        // mandatory reopen holds a new directory plus its inventory
                        // clone before scanning. A transient rebind probe holds at
                        // most two, so this restores bytes only inside fresh scan.
                        let roots = fs::read_dir("/proc/self/fd")
                            .unwrap()
                            .filter_map(Result::ok)
                            .filter_map(|entry| fs::read_link(entry.path()).ok())
                            .filter(|path| path == &published)
                            .count();
                        if roots >= 3 {
                            changed.set(true);
                            let compiler = published.join("bin/compiler");
                            fs::set_permissions(&compiler, fs::Permissions::from_mode(0o755))
                                .unwrap();
                            fs::write(&compiler, CONTENTS).unwrap();
                            fs::set_permissions(&compiler, fs::Permissions::from_mode(0o555))
                                .unwrap();
                        }
                    }
                    false
                })
                .err()
                .unwrap();
            assert!(changed.get(), "the actual durable reopen must be exercised");
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert!(!uploaded.exists());
            assert_eq!(inode(&published.join("bin/compiler")), compiler_inode);
            assert_eq!(fs::read(published.join("rustc")).unwrap(), CONTENTS);
            // Publication may have completed before refusal. Retain the actual
            // entry for inspection; never turn uncertainty into cleanup.
            assert!(published.parent().unwrap().is_dir());
        }

        #[test]
        #[ignore = "requires RABS_TEST_TOOLCHAIN_UPLOAD_FS on a distinct writable filesystem"]
        fn cross_filesystem_durable_upload_uses_verified_copy_and_keeps_its_source_owner() {
            use rabs_sandbox::toolchain_dataset::open_toolchain;
            use sha2::{Digest, Sha256};
            use std::cell::Cell;

            let alternate = std::path::PathBuf::from(
                std::env::var_os("RABS_TEST_TOOLCHAIN_UPLOAD_FS")
                    .expect("set an explicit second writable filesystem for real EXDEV coverage"),
            );
            assert!(alternate.is_absolute());
            let alternate = fs::canonicalize(alternate).unwrap();
            for contents in [b"".as_slice(), CONTENTS] {
                let (source, initial_pool, _) = fixture(1024, false);
                drop(initial_pool);
                fs::write(source.path().join("bin/compiler"), contents).unwrap();
                let limits = ToolchainLimits::default();
                let identity = fingerprint_toolchain(source.path(), &limits, || false).unwrap();
                let exported = open_toolchain(source.path(), &identity, &limits, || false).unwrap();
                let cache_parent = tempfile::tempdir().unwrap();
                assert_ne!(
                    fs::metadata(&alternate).unwrap().dev(),
                    fs::metadata(cache_parent.path()).unwrap().dev(),
                    "the explicit fixture must exercise an actual cross-device rename",
                );
                let cache_root = cache_parent.path().join("durable");
                let pool =
                    toolchain_pool::ToolchainPool::with_directory(1024, 2, Some(&cache_root))
                        .unwrap();
                let directory = tempfile::Builder::new()
                    .prefix("rabs-toolchain-upload-")
                    .permissions(fs::Permissions::from_mode(0o700))
                    .tempdir_in(&alternate)
                    .unwrap();
                let uploaded = directory.path().join("tree");
                let mut receiver =
                    ToolchainReceiver::create(&uploaded, identity, limits).unwrap();
                for entry in exported.entries().unwrap() {
                    let path = entry.path.clone();
                    let length = match &entry.kind {
                        ToolchainEntryKind::File { bytes, .. } => Some(*bytes),
                        _ => None,
                    };
                    receiver.entry(entry).unwrap();
                    if let Some(length) = length {
                        let mut offset = 0;
                        while offset < length {
                            let chunk = exported
                                .read_chunk(&path, offset, MAX_TOOLCHAIN_CHUNK, || false)
                                .unwrap();
                            assert!(!chunk.is_empty());
                            receiver
                                .write_chunk(
                                    &path,
                                    offset,
                                    &chunk,
                                    Sha256::digest(&chunk).into(),
                                )
                                .unwrap();
                            offset += chunk.len() as u64;
                        }
                    }
                }
                let prepared = receiver.seal(|| false).unwrap();
                let owner = UploadedToolchain {
                    prepared: Some(prepared),
                    receiver,
                    _directory: directory,
                }
                .into_sealed(&identity)
                .unwrap();
                let compiler_inode = inode(&uploaded.join("bin/compiler"));
                let published = cache_root
                    .join("toolchains-v1")
                    .join(format!(
                        "v1-{}-{}-{}",
                        hex(&identity.sha256),
                        identity.files,
                        identity.bytes,
                    ))
                    .join("tree");
                let source_at_publication = Cell::new(false);
                let lease = pool
                    .adopt(owner, || {
                        if uploaded.exists() {
                            assert_eq!(inode(&uploaded.join("bin/compiler")), compiler_inode);
                            assert_eq!(fs::read(uploaded.join("rustc")).unwrap(), contents);
                            if published.exists() {
                                source_at_publication.set(true);
                            }
                        } else {
                            // The copied image must already be complete before its
                            // still-owned source is released.
                            assert_eq!(fs::read(published.join("rustc")).unwrap(), contents);
                        }
                        false
                    })
                    .unwrap();
                assert_eq!(lease.disposition(), "captured");
                assert_eq!(lease.root(), published);
                assert!(source_at_publication.get());
                assert!(!uploaded.exists());
                assert_ne!(inode(&published.join("bin/compiler")), compiler_inode);
                assert_eq!(fs::read(published.join("rustc")).unwrap(), contents);
                lease.verify(|| false).unwrap();
            }
        }

        #[test]
        fn execution_handoff_requires_the_original_request_and_complete_identity() {
            let (_source, pool, wire) = fixture(1024, false);
            for changed in ["request_id", "sha256", "files", "bytes", "missing", "root"] {
                let (owner, mut request) = upload(&pool, &wire);
                let root = Path::new(&request.toolchain_backing).to_path_buf();
                match changed {
                    "request_id" => request.request_id += 1,
                    "sha256" => request.toolchain_identity.as_mut().unwrap().sha256[0] ^= 1,
                    "files" => request.toolchain_identity.as_mut().unwrap().files += 1,
                    "bytes" => request.toolchain_identity.as_mut().unwrap().bytes += 1,
                    "missing" => request.toolchain_identity = None,
                    "root" => request.toolchain_backing.push_str("/bin"),
                    _ => unreachable!(),
                }
                assert!(owner.into_lease(&request, || false).is_err(), "{changed}");
                assert!(!root.exists());
            }
        }

        #[test]
        fn changed_or_cancelled_upload_never_becomes_a_retained_lease() {
            for cache in ["memory", "durable-full", "durable-available"] {
                let (_parent, pool, wire) = match cache {
                    "durable-full" => {
                        let (parent, pool, wire, _) = full_durable_fixture();
                        (parent, pool, wire)
                    }
                    "durable-available" => {
                        let (_source, initial_pool, wire) = fixture(1024, false);
                        drop(initial_pool);
                        let parent = tempfile::tempdir().unwrap();
                        let pool = Arc::new(
                            toolchain_pool::ToolchainPool::with_directory(
                                1024,
                                2,
                                Some(&parent.path().join("durable")),
                            )
                            .unwrap(),
                        );
                        (parent, pool, wire)
                    }
                    _ => fixture(1024, false),
                };
                let identity = parse_toolchain_identity(&wire).unwrap().unwrap();
                let (owner, request) = upload(&pool, &wire);
                let root = Path::new(&request.toolchain_backing).to_path_buf();
                let compiler = root.join("bin/compiler");
                fs::set_permissions(&compiler, fs::Permissions::from_mode(0o755)).unwrap();
                // Even restored bytes and final modes cannot refresh the sealed
                // inode's mutation witness into a newly admitted generation.
                fs::write(&compiler, CONTENTS).unwrap();
                fs::set_permissions(&compiler, fs::Permissions::from_mode(0o555)).unwrap();
                assert!(
                    pool.adopt(sealed(owner, &request), || false).is_err(),
                    "{cache}"
                );
                assert!(!root.exists());
                assert!(pool.lookup(&identity, || false).unwrap().is_none());

                let (owner, request) = upload(&pool, &wire);
                let root = Path::new(&request.toolchain_backing).to_path_buf();
                let error = pool.adopt(sealed(owner, &request), || true).err().unwrap();
                assert_eq!(error.kind(), io::ErrorKind::Interrupted);
                assert!(!root.exists());
                assert!(pool.lookup(&identity, || false).unwrap().is_none());

                // A refused owner must release its memory reservation, so a
                // fresh exact upload can occupy the same bounded slot.
                let (owner, request) = upload(&pool, &wire);
                let lease = pool.adopt(sealed(owner, &request), || false).unwrap();
                if cache == "durable-available" {
                    assert_eq!(lease.disposition(), "adopted");
                    assert!(!Path::new(&request.toolchain_backing).exists());
                } else {
                    assert_eq!(lease.disposition(), "adopted");
                    assert_eq!(lease.root(), Path::new(&request.toolchain_backing));
                }
                assert!(pool.lookup(&identity, || false).unwrap().is_some());
            }
        }

        #[test]
        fn durable_upload_rejects_a_refreshed_generation_after_reservation_before_publication() {
            use std::cell::Cell;

            let (_source, initial_pool, wire) = fixture(1024, false);
            drop(initial_pool);
            let parent = tempfile::tempdir().unwrap();
            let cache_root = parent.path().join("durable");
            let objects = cache_root.join("toolchains-v1");
            let pool = Arc::new(
                toolchain_pool::ToolchainPool::with_directory(
                    CONTENTS.len() as u64,
                    1,
                    Some(&cache_root),
                )
                .unwrap(),
            );
            let (owner, request) = upload(&pool, &wire);
            let root = Path::new(&request.toolchain_backing).to_path_buf();
            let compiler = root.join("bin/compiler");
            let changed = Cell::new(false);
            assert!(
                pool.adopt(sealed(owner, &request), || {
                    if !changed.get() && fs::read_dir(&objects).unwrap().next().is_some() {
                        // Admission has preserved the original generation and
                        // reserved durable storage. A fresh source scan could now
                        // accept these restored bytes, but the sealed witness cannot.
                        changed.set(true);
                        let compiler = if compiler.exists() {
                            compiler.clone()
                        } else {
                            fs::read_dir(&objects)
                                .unwrap()
                                .next()
                                .unwrap()
                                .unwrap()
                                .path()
                                .join("tree/bin/compiler")
                        };
                        fs::set_permissions(&compiler, fs::Permissions::from_mode(0o755)).unwrap();
                        fs::write(&compiler, CONTENTS).unwrap();
                        fs::set_permissions(&compiler, fs::Permissions::from_mode(0o555)).unwrap();
                    }
                    false
                })
                .is_err()
            );
            assert!(changed.get());
            assert!(!root.exists());
            let entries: Vec<_> = fs::read_dir(&objects)
                .unwrap()
                .map(Result::unwrap)
                .collect();
            assert_eq!(entries.len(), 1);
            assert!(
                entries[0]
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".pending-")
            );
            assert_eq!(
                fs::read(entries[0].path().join("tree/bin/compiler")).unwrap(),
                CONTENTS
            );
            let identity = parse_toolchain_identity(&wire).unwrap().unwrap();
            assert!(pool.lookup(&identity, || false).unwrap().is_none());
            // The failed durable reservation remains charged and unpublished;
            // only the failed in-memory acquisition reservation is released.
            let (owner, request) = upload(&pool, &wire);
            let lease = pool.adopt(sealed(owner, &request), || false).unwrap();
            assert_eq!(lease.disposition(), "adopted");
            assert_eq!(lease.root(), Path::new(&request.toolchain_backing));
            lease.verify(|| false).unwrap();
            assert!(entries[0].path().exists());
        }

        #[test]
        fn independent_durable_hit_does_not_revalidate_a_redundant_uploaded_generation() {
            let (source, initial_pool, wire) = fixture(1024, false);
            drop(initial_pool);
            let parent = tempfile::tempdir().unwrap();
            let cache_root = parent.path().join("durable");
            let identity = parse_toolchain_identity(&wire).unwrap().unwrap();
            let initial =
                toolchain_pool::ToolchainPool::with_directory(1024, 2, Some(&cache_root)).unwrap();
            let retained = initial
                .acquire(source.path(), Some(&identity), || false)
                .unwrap();
            let published = retained.root().to_path_buf();
            let published_inode = inode(&published.join("bin/compiler"));
            drop(retained);
            drop(initial);
            let pool = Arc::new(
                toolchain_pool::ToolchainPool::with_directory(1024, 2, Some(&cache_root)).unwrap(),
            );
            let (owner, request) = upload(&pool, &wire);
            let root = Path::new(&request.toolchain_backing).to_path_buf();
            let compiler = root.join("bin/compiler");
            fs::set_permissions(&compiler, fs::Permissions::from_mode(0o755)).unwrap();
            fs::write(&compiler, vec![b'x'; CONTENTS.len()]).unwrap();
            fs::set_permissions(&compiler, fs::Permissions::from_mode(0o555)).unwrap();
            let lease = pool.adopt(sealed(owner, &request), || false).unwrap();
            assert_eq!(lease.root(), published);
            assert_eq!(inode(&lease.root().join("bin/compiler")), published_inode);
            assert_eq!(fs::read(lease.root().join("rustc")).unwrap(), CONTENTS);
            lease.verify(|| false).unwrap();
            assert!(!root.exists());
        }

        #[test]
        fn durable_decline_checks_cancellation_during_the_owned_byte_scan() {
            use std::cell::Cell;

            let (_parent, pool, wire, _) = full_durable_fixture();
            let identity = parse_toolchain_identity(&wire).unwrap().unwrap();
            let (owner, request) = upload(&pool, &wire);
            let root = Path::new(&request.toolchain_backing).to_path_buf();
            let compiler = root.join("bin/compiler");
            let cancelled = Cell::new(false);
            let error = pool
                .adopt(sealed(owner, &request), || {
                    // Cancel only once the actual owned file is open for its byte
                    // scan. No timing assumption or checkpoint count decides when
                    // durable admission has declined and verification has begun.
                    let reading = fs::read_dir("/proc/self/fd").unwrap().any(|entry| {
                        entry
                            .ok()
                            .and_then(|entry| fs::read_link(entry.path()).ok())
                            .as_deref()
                            == Some(compiler.as_path())
                    });
                    cancelled.set(cancelled.get() || reading);
                    cancelled.get()
                })
                .err()
                .unwrap();
            assert!(
                cancelled.get(),
                "cancellation must reach owned-image verification"
            );
            assert_eq!(error.kind(), io::ErrorKind::Interrupted);
            assert!(!root.exists());
            assert!(pool.lookup(&identity, || false).unwrap().is_none());
            let (owner, request) = upload(&pool, &wire);
            let lease = pool.adopt(sealed(owner, &request), || false).unwrap();
            assert_eq!(lease.disposition(), "adopted");
            assert_eq!(lease.root(), Path::new(&request.toolchain_backing));
            lease.verify(|| false).unwrap();
        }

        #[test]
        fn durable_corruption_and_io_errors_never_fall_back_to_a_valid_upload() {
            for corrupt_bytes in [false, true] {
                let (source, initial_pool, wire) = fixture(1024, false);
                drop(initial_pool);
                let identity = parse_toolchain_identity(&wire).unwrap().unwrap();
                let parent = tempfile::tempdir().unwrap();
                let cache_root = parent.path().join("durable");
                let initial =
                    toolchain_pool::ToolchainPool::with_directory(1024, 2, Some(&cache_root))
                        .unwrap();
                let retained = initial
                    .acquire(source.path(), Some(&identity), || false)
                    .unwrap();
                let compiler = retained.root().join("bin/compiler");
                drop(retained);
                drop(initial);
                let pool = Arc::new(
                    toolchain_pool::ToolchainPool::with_directory(1024, 2, Some(&cache_root))
                        .unwrap(),
                );
                let (owner, request) = upload(&pool, &wire);
                let root = Path::new(&request.toolchain_backing).to_path_buf();
                if corrupt_bytes {
                    fs::set_permissions(&compiler, fs::Permissions::from_mode(0o755)).unwrap();
                    fs::write(&compiler, vec![b'x'; CONTENTS.len()]).unwrap();
                    fs::set_permissions(&compiler, fs::Permissions::from_mode(0o555)).unwrap();
                } else {
                    fs::rename(
                        cache_root.join("toolchains-v1"),
                        cache_root.join("held-objects"),
                    )
                    .unwrap();
                }
                assert!(pool.adopt(sealed(owner, &request), || false).is_err());
                assert!(!root.exists());
                assert!(pool.lookup(&identity, || false).is_err());
            }
        }

        #[test]
        fn warm_begin_checks_declaration_and_retains_request_bound_verified_owner() {
            let (source, pool, request) = fixture(1024, true);
            fs::rename(source.path().join("bin"), source.path().join("unavailable")).unwrap();
            let mut task = task(&pool, true);
            let mut wrong = begin(&request);
            wrong["entries"] = json!(ENTRIES + 1);
            assert!(exchange(&mut task, &wrong).is_err());
            assert!(task.prepared_path(&request, true).is_err());
            let ready = exchange(&mut task, &begin(&request)).unwrap();
            assert_eq!(
                ready,
                json!({"kind":"toolchain-ready", "request_id":0,
                "sha256":request["toolchain_identity"]["sha256"], "sealed":true})
            );
            assert_eq!(exchange(&mut task, &begin(&request)).unwrap(), ready);
            let path = task.prepared_path(&request, true).unwrap().unwrap();
            assert_eq!(fs::read(Path::new(&path).join("rustc")).unwrap(), CONTENTS);
            assert!(matches!(
                task.state.as_ref().unwrap().owner.as_ref().unwrap().backing,
                ToolchainBacking::Reused(_)
            ));
            for field in ["request_id", "toolchain_identity"] {
                let mut foreign = request.clone();
                if field == "request_id" {
                    foreign[field] = json!(1);
                } else {
                    foreign[field]["files"] = json!(2);
                }
                assert!(task.prepared_path(&foreign, true).is_err());
                assert!(task.take_prepared(&foreign).is_err());
            }
            // A hit is already sealed; no subsequent upload traffic is accepted.
            assert!(exchange(&mut task, &transfer_frames(&request)[0]).is_err());
            let owner = task.take_prepared(&request).unwrap().unwrap();
            drop(task);
            drop(pool);
            assert_eq!(
                fs::read(Path::new(&path).join("bin/compiler")).unwrap(),
                CONTENTS
            );
            drop(owner);
            assert!(!Path::new(&path).exists());
        }

        #[test]
        fn warm_owner_outlives_pool_shutdown_until_real_process_and_drains_finish() {
            use crate::execution::ExecutionTask;
            use crate::output::CapturedOutputs;
            use rabs_asupersync::process_groups::ManagedProcessGroup;
            use rabs_asupersync::region_tree::Attribution;
            use rabs_asupersync::stream_drain::DrainLimits;
            use std::process::{Command, Stdio};

            let (source, pool, request) = fixture(1024, true);
            let mut task = task(&pool, true);
            assert_eq!(
                exchange(&mut task, &begin(&request)).unwrap()["sealed"],
                true
            );
            let owner = task.take_prepared(&request).unwrap().unwrap();
            let root = owner.backing.prepared_root().unwrap().to_path_buf();
            let execution_root = root.clone();
            let gate = source.path().join("continue");
            let execution_gate = gate.clone();
            let spill = source.path().join("spill");
            let (started, running) = mpsc::sync_channel(1);
            let mut execution = ExecutionTask::spawn(0, Duration::from_secs(5), move |control| {
                let _owner = owner;
                // This tests owned input lifetime with a real managed child; it
                // does not substitute for a canonical sandbox or TLS fixture.
                let mut command = Command::new("/bin/sh");
                command
                    .args([
                        "-c",
                        "while [ ! -f \"$GATE\" ]; do sleep 0.01; done; cat \"$INPUT\"",
                    ])
                    .env_clear()
                    .env("PATH", "/usr/bin:/bin")
                    .env("GATE", execution_gate)
                    .env("INPUT", execution_root.join("rustc"))
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());
                let group =
                    ManagedProcessGroup::spawn_command(command, Attribution::default()).unwrap();
                started.send(()).unwrap();
                let drained = group
                    .wait_with_bounded_drain_budget(
                        &DrainLimits {
                            resident_bound: 1024,
                            spill_dir: spill,
                        },
                        4096,
                        || control.reason().is_some(),
                    )
                    .unwrap();
                assert_eq!(drained.residual_group_members, 0);
                assert_eq!(
                    fs::read(execution_root.join("bin/compiler")).unwrap(),
                    CONTENTS
                );
                let outputs =
                    CapturedOutputs::from_lanes(&drained.stdout, &drained.stderr).unwrap();
                crate::session::ExecResult {
                    request_id: 0,
                    exit_code: drained.status.code().unwrap_or(125),
                    executed: true,
                    stdout_sha256: outputs.stdout.sha256().to_owned(),
                    stderr_sha256: outputs.stderr.sha256().to_owned(),
                    residual_group_members: drained.residual_group_members,
                    stdout_spill_bytes: drained.stdout.spilled_bytes(),
                    stderr_spill_bytes: drained.stderr.spilled_bytes(),
                    stdout_spill_path: None,
                    stderr_spill_path: None,
                }
            })
            .unwrap();
            running.recv_timeout(Duration::from_secs(5)).unwrap();
            drop(task);
            drop(pool);
            assert!(
                root.is_dir(),
                "the executing owner's lease retains the pool parent"
            );
            fs::write(gate, b"continue").unwrap();
            let completed = wait(|cx| execution.poll_completion(cx)).unwrap();
            assert_eq!(completed.result.exit_code, 0);
            assert_eq!(
                completed.result.stdout_sha256,
                crate::session::sha256_hex(CONTENTS)
            );
            assert_eq!(completed.result.residual_group_members, 0);
            assert!(
                !root.exists(),
                "the final lease is released after process cleanup"
            );
        }

        #[test]
        fn unselected_disabled_and_missing_reuse_finish_the_full_real_upload() {
            for (reuse, budget, seed) in [(false, 1024, true), (true, 0, true), (true, 1024, false)]
            {
                let (_source, pool, request) = fixture(budget, seed);
                let mut task = task(&pool, reuse);
                assert_eq!(
                    exchange(&mut task, &begin(&request)).unwrap()["sealed"],
                    false
                );
                assert!(task.prepared_path(&request, true).is_err());
                for frame in transfer_frames(&request) {
                    assert_ne!(exchange(&mut task, &frame).unwrap()["kind"], "error");
                }
                let owner = task.take_prepared(&request).unwrap().unwrap();
                let prepared = match &owner.backing {
                    ToolchainBacking::Uploaded(upload) => {
                        let prepared = upload.prepared.as_ref().unwrap();
                        prepared.verify(|| false).unwrap();
                        prepared.root()
                    }
                    ToolchainBacking::UploadedRetained { lease, .. } => {
                        assert!(reuse && budget != 0);
                        lease.verify(|| false).unwrap();
                        lease.root()
                    }
                    _ => panic!("full upload did not retain its verified image"),
                };
                assert_eq!(fs::read(prepared.join("rustc")).unwrap(), CONTENTS);
                assert!(prepared.join("empty").is_dir());
            }
        }

        #[test]
        fn corrupt_retained_input_refuses_begin_then_retires_the_bad_entry() {
            let (_source, pool, request) = fixture(1024, true);
            let identity = request_identity(&request).unwrap().unwrap();
            let lease = pool.lookup(&identity, || false).unwrap().unwrap();
            let compiler = lease.root().join("bin/compiler");
            fs::set_permissions(&compiler, fs::Permissions::from_mode(0o700)).unwrap();
            fs::write(&compiler, b"tampered compiler!!").unwrap();
            let mut task = task(&pool, true);
            assert!(exchange(&mut task, &begin(&request)).is_err());
            assert!(task.prepared_path(&request, true).is_err());
            assert!(pool.lookup(&identity, || false).unwrap().is_none());
            assert!(lease.verify(|| false).is_err());
            // A subsequent begin can only recover by receiving all bytes again.
            assert_eq!(
                exchange(&mut task, &begin(&request)).unwrap()["sealed"],
                false
            );
        }

        #[test]
        fn cancellation_or_expiry_revokes_a_warm_owner_before_transfer_to_execution() {
            let (_source, pool, request) = fixture(1024, true);
            let mut cancelled = task(&pool, true);
            cancelled.submit(&begin(&request), true, false).unwrap();
            // The real verification may still be running or already completed;
            // cancellation must fence either outcome before the reactor takes it.
            assert!(cancelled.is_pending());
            assert_eq!(cancelled.cancel(1), None);
            assert_eq!(cancelled.cancel(0), Some(true));
            let reply = wait(|cx| cancelled.poll_completion(cx)).unwrap();
            assert_eq!(reply.response.unwrap_err(), "toolchain upload cancelled");
            assert!(cancelled.prepared_path(&request, true).is_err());
            assert!(cancelled.take_prepared(&request).is_err());
            assert_eq!(
                cancelled
                    .submit_owned(begin(&request), true, false)
                    .unwrap_err(),
                "toolchain upload cancelled"
            );
            let mut expired = task(&pool, true);
            assert_eq!(
                exchange(&mut expired, &begin(&request)).unwrap()["sealed"],
                true
            );
            expired
                .state
                .as_mut()
                .unwrap()
                .owner
                .as_mut()
                .unwrap()
                .deadline = Instant::now();
            assert!(expired.prepared_path(&request, true).is_err());
            assert!(expired.take_prepared(&request).is_err());
        }
    }
}
