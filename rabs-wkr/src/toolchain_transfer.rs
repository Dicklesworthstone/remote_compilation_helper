//! Request-bound toolchain input with one owned filesystem worker.
//!
//! The wire never supplies a worker staging path. A new private tree or an
//! explicitly negotiated retained lease must verify against the request's full
//! identity before durable execution admission. Work stays off the reactor, and
//! cancellation revokes readiness even when a filesystem operation completes late.

use crate::session::parse_toolchain_identity;
use crate::session::toolchain_pool::{self, ToolchainLease};
use crate::source_transfer::hex;
use rabs_sandbox::toolchain_dataset::{PreparedToolchain, ToolchainIdentity, ToolchainLimits};
use rabs_sandbox::toolchain_transfer::{
    MAX_TOOLCHAIN_CHUNK, TOOLCHAIN_REUSE_VERSION, TOOLCHAIN_TRANSFER_VERSION,
    TOOLCHAIN_UPLOAD_BUDGET, ToolchainEntry, ToolchainEntryKind, ToolchainReceiver,
};
use serde_json::{Value, json};
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
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
    if text.len() % 2 != 0
        || text.len() / 2 > maximum
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("invalid bounded toolchain hex".to_owned());
    }
    text.as_bytes()
        .chunks_exact(2)
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
    frame: &str, authenticated: bool, transfer_enabled: bool,
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

enum ToolchainBacking {
    Uploaded(Box<UploadedToolchain>),
    Reused(ToolchainLease),
}

impl ToolchainBacking {
    fn prepared_root(&self) -> Option<&Path> {
        match self {
            Self::Uploaded(upload) => upload.prepared.as_ref().map(PreparedToolchain::root),
            Self::Reused(lease) => Some(lease.root()),
        }
    }
}

/// Moved into the blocking execution owner before its lease can be armed. The
/// executor captures or leases the same verified identity through its existing
/// toolchain pool; this owner keeps either input backing alive through cleanup.
pub struct ToolchainOwner {
    backing: ToolchainBacking,
    request_id: u64,
    identity: ToolchainIdentity,
    entries: usize,
    deadline: Instant,
    failed: bool,
}

impl ToolchainOwner {
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
        let UploadedToolchain { prepared, receiver, .. } = &mut **upload;
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
                Ok(json!({"kind":"toolchain-ready", "request_id":self.request_id,
                    "sha256":identity, "sealed":true}))
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
    fn lookup(
        &self, identity: &ToolchainIdentity, stopped: impl Fn() -> bool,
    ) -> io::Result<Option<ToolchainLease>> {
        #[cfg(test)]
        if let Some(pool) = &self.pool { return pool.lookup(identity, stopped); }
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
                && let Some(lease) = self.lookup(&identity, || {
                    cancelled.load(Ordering::Acquire) || Instant::now() >= deadline
                }).map_err(|error| error.to_string())?
            {
                if lease.entry_count().map_err(|error| error.to_string())? != entries {
                    return Err("retained toolchain entry count differs from declaration".to_owned());
                }
                let owner = ToolchainOwner {
                    backing: ToolchainBacking::Reused(lease),
                    request_id: id, identity, entries, deadline, failed: false,
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
                ToolchainReceiver::create(&directory.path().join("dataset"), identity, limits)
                    .map_err(|error| error.to_string())?;
            let owner = ToolchainOwner {
                backing: ToolchainBacking::Uploaded(Box::new(UploadedToolchain {
                    prepared: None, receiver, _directory: directory,
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
        owner.handle(frame, cancelled)
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
        root
            .to_str()
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
            state: Some(TransferState { reuse, ..TransferState::default() }),
            shared: Arc::new(Mutex::new(CompletionState::default())),
            cancelled: Arc::new(AtomicBool::new(false)),
            sender: None,
            thread: None,
            pending_id: None,
            upload_id: None,
            failed: false,
        }
    }

    fn start_worker(&mut self) -> io::Result<()> {
        let (sender, receiver) = mpsc::sync_channel::<Job>(1);
        let shared = Arc::clone(&self.shared);
        let cancelled = Arc::clone(&self.cancelled);
        let thread = std::thread::Builder::new()
            .name("rabs-toolchain-io".to_owned())
            .spawn(move || {
                while let Ok(mut job) = receiver.recv() {
                    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        job.state.handle(&job.frame, &cancelled)
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
            self.start_worker()
                .map_err(|error| format!("start toolchain filesystem worker: {error}"))?;
        }
        let sender = self
            .sender
            .as_ref()
            .ok_or("toolchain filesystem worker unavailable")?;
        let state = self.state.take().ok_or("toolchain-operation-pending")?;
        match sender.try_send(Job {
            state,
            frame: frame.clone(),
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
        let ack = json!({"kind":"session-ok", "toolchain_reuse":TOOLCHAIN_REUSE_VERSION})
            .to_string();
        assert!(selected_reuse(&ack, true, true).unwrap());
        assert!(selected_reuse(&ack, false, true).is_err());
        assert!(selected_reuse(&ack, true, false).is_err());
        assert!(!selected_reuse(r#"{"kind":"session-ok"}"#, false, false).unwrap());
        for invalid in [Value::Null, json!(false), json!(17), json!("toolchain-reuse-v2")] {
            assert!(selected_reuse(
                &json!({"kind":"session-ok", "toolchain_reuse":invalid}).to_string(),
                true, true,
            ).is_err());
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
        use std::os::unix::fs::{PermissionsExt, symlink};
        use std::task::Wake;
        use std::time::Duration;

        const CONTENTS: &[u8] = b"retained compiler\0\xff";
        const ENTRIES: usize = 5;

        fn fixture(
            budget: u64, seed: bool,
        ) -> (tempfile::TempDir, Arc<toolchain_pool::ToolchainPool>, Value) {
            let source = tempfile::tempdir().unwrap();
            fs::create_dir(source.path().join("bin")).unwrap();
            fs::create_dir(source.path().join("empty")).unwrap();
            fs::write(source.path().join("bin/compiler"), CONTENTS).unwrap();
            fs::set_permissions(source.path().join("bin/compiler"), fs::Permissions::from_mode(0o755)).unwrap();
            symlink("bin/compiler", source.path().join("rustc")).unwrap();
            let identity = fingerprint_toolchain(source.path(), &ToolchainLimits::default(), || false).unwrap();
            let pool = Arc::new(toolchain_pool::ToolchainPool::new(budget, 2).unwrap());
            if seed {
                // The same real capture as execution seeds this isolated pool.
                drop(pool.acquire(source.path(), Some(&identity), || false).unwrap());
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
            fn wake(self: Arc<Self>) { self.0.unpark(); }
            fn wake_by_ref(self: &Arc<Self>) { self.0.unpark(); }
        }

        fn wait<T>(mut poll: impl FnMut(&mut Context<'_>) -> Poll<T>) -> T {
            let waker = Waker::from(Arc::new(ThreadWake(std::thread::current())));
            let mut cx = Context::from_waker(&waker);
            let until = Instant::now() + Duration::from_secs(5);
            loop {
                if let Poll::Ready(value) = poll(&mut cx) { return value; }
                assert!(Instant::now() < until, "owned filesystem/execution task did not finish");
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
            let entry = |path: &str, entry: Value| json!({"kind":"toolchain-entry",
                "request_id":id, "sha256":digest, "path":path, "entry":entry});
            vec![
                entry("", json!({"kind":"directory"})),
                entry("bin", json!({"kind":"directory"})),
                entry("bin/compiler", json!({"kind":"file", "bytes":CONTENTS.len(), "executable":true})),
                json!({"kind":"toolchain-chunk", "request_id":id, "sha256":digest,
                    "path":"bin/compiler", "offset":0, "data_hex":hex(CONTENTS),
                    "chunk_sha256":crate::session::sha256_hex(CONTENTS)}),
                entry("empty", json!({"kind":"directory"})),
                entry("rustc", json!({"kind":"symlink", "target":"bin/compiler"})),
                json!({"kind":"toolchain-seal", "request_id":id, "sha256":digest}),
            ]
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
            assert_eq!(ready, json!({"kind":"toolchain-ready", "request_id":0,
                "sha256":request["toolchain_identity"]["sha256"], "sealed":true}));
            assert_eq!(exchange(&mut task, &begin(&request)).unwrap(), ready);
            let path = task.prepared_path(&request, true).unwrap().unwrap();
            assert_eq!(fs::read(Path::new(&path).join("rustc")).unwrap(), CONTENTS);
            assert!(matches!(task.state.as_ref().unwrap().owner.as_ref().unwrap().backing,
                ToolchainBacking::Reused(_)));
            for field in ["request_id", "toolchain_identity"] {
                let mut foreign = request.clone();
                if field == "request_id" { foreign[field] = json!(1); }
                else { foreign[field]["files"] = json!(2); }
                assert!(task.prepared_path(&foreign, true).is_err());
                assert!(task.take_prepared(&foreign).is_err());
            }
            // A hit is already sealed; no subsequent upload traffic is accepted.
            assert!(exchange(&mut task, &transfer_frames(&request)[0]).is_err());
            let owner = task.take_prepared(&request).unwrap().unwrap();
            drop(task);
            drop(pool);
            assert_eq!(fs::read(Path::new(&path).join("bin/compiler")).unwrap(), CONTENTS);
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
            assert_eq!(exchange(&mut task, &begin(&request)).unwrap()["sealed"], true);
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
                command.args(["-c", "while [ ! -f \"$GATE\" ]; do sleep 0.01; done; cat \"$INPUT\""])
                    .env_clear().env("PATH", "/usr/bin:/bin")
                    .env("GATE", execution_gate).env("INPUT", execution_root.join("rustc"))
                    .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
                let group = ManagedProcessGroup::spawn_command(command, Attribution::default()).unwrap();
                started.send(()).unwrap();
                let drained = group.wait_with_bounded_drain_budget(
                    &DrainLimits { resident_bound:1024, spill_dir:spill }, 4096,
                    || control.reason().is_some(),
                ).unwrap();
                assert_eq!(drained.residual_group_members, 0);
                assert_eq!(fs::read(execution_root.join("bin/compiler")).unwrap(), CONTENTS);
                let outputs = CapturedOutputs::from_lanes(&drained.stdout, &drained.stderr).unwrap();
                crate::session::ExecResult {
                    request_id:0, exit_code:drained.status.code().unwrap_or(125), executed:true,
                    stdout_sha256:outputs.stdout.sha256().to_owned(),
                    stderr_sha256:outputs.stderr.sha256().to_owned(),
                    residual_group_members:drained.residual_group_members,
                    stdout_spill_bytes:drained.stdout.spilled_bytes(),
                    stderr_spill_bytes:drained.stderr.spilled_bytes(),
                    stdout_spill_path:None, stderr_spill_path:None,
                }
            }).unwrap();
            running.recv_timeout(Duration::from_secs(5)).unwrap();
            drop(task);
            drop(pool);
            assert!(root.is_dir(), "the executing owner's lease retains the pool parent");
            fs::write(gate, b"continue").unwrap();
            let completed = wait(|cx| execution.poll_completion(cx)).unwrap();
            assert_eq!(completed.result.exit_code, 0);
            assert_eq!(completed.result.stdout_sha256, crate::session::sha256_hex(CONTENTS));
            assert_eq!(completed.result.residual_group_members, 0);
            assert!(!root.exists(), "the final lease is released after process cleanup");
        }

        #[test]
        fn unselected_disabled_and_missing_reuse_finish_the_full_real_upload() {
            for (reuse, budget, seed) in [(false, 1024, true), (true, 0, true), (true, 1024, false)] {
                let (_source, pool, request) = fixture(budget, seed);
                let mut task = task(&pool, reuse);
                assert_eq!(exchange(&mut task, &begin(&request)).unwrap()["sealed"], false);
                assert!(task.prepared_path(&request, true).is_err());
                for frame in transfer_frames(&request) {
                    assert_ne!(exchange(&mut task, &frame).unwrap()["kind"], "error");
                }
                let owner = task.take_prepared(&request).unwrap().unwrap();
                let ToolchainBacking::Uploaded(upload) = &owner.backing else {
                    panic!("full upload did not retain its verified receiver");
                };
                let prepared = upload.prepared.as_ref().unwrap();
                prepared.verify(|| false).unwrap();
                assert_eq!(fs::read(prepared.root().join("rustc")).unwrap(), CONTENTS);
                assert!(prepared.root().join("empty").is_dir());
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
            assert_eq!(exchange(&mut task, &begin(&request)).unwrap()["sealed"], false);
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
            let mut expired = task(&pool, true);
            assert_eq!(exchange(&mut expired, &begin(&request)).unwrap()["sealed"], true);
            expired.state.as_mut().unwrap().owner.as_mut().unwrap().deadline = Instant::now();
            assert!(expired.prepared_path(&request, true).is_err());
            assert!(expired.take_prepared(&request).is_err());
        }
    }
}
