//! Request-bound full toolchain upload with one owned filesystem worker.
//!
//! The wire never supplies a worker staging path. A new private tree must seal
//! against the request's complete toolchain identity before durable execution
//! admission. Upload work stays off the control reactor, and cancellation
//! revokes readiness even when a filesystem operation completes late.

use crate::session::parse_toolchain_identity;
use crate::source_transfer::hex;
use rabs_sandbox::toolchain_dataset::{PreparedToolchain, ToolchainIdentity, ToolchainLimits};
use rabs_sandbox::toolchain_transfer::{
    MAX_TOOLCHAIN_CHUNK, TOOLCHAIN_TRANSFER_VERSION, TOOLCHAIN_UPLOAD_BUDGET, ToolchainEntry,
    ToolchainEntryKind, ToolchainReceiver,
};
use serde_json::{Value, json};
use std::io;
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

/// Moved into the blocking execution owner before its lease can be armed. The
/// executor captures or leases the same verified identity through its existing
/// toolchain pool; this owner keeps the uploaded backing alive through cleanup.
pub struct ToolchainOwner {
    prepared: Option<PreparedToolchain>,
    receiver: ToolchainReceiver,
    _directory: tempfile::TempDir,
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
            "sha256":hex(&self.identity.sha256), "sealed":self.prepared.is_some()}),
        )
    }

    fn handle(&mut self, frame: &Value, cancelled: &AtomicBool) -> Result<Value, String> {
        self.check(cancelled)?;
        if self.prepared.is_some() {
            return Err("toolchain upload is already sealed".to_owned());
        }
        let identity = hex(&self.identity.sha256);
        let result = (|| match frame["kind"].as_str() {
            Some("toolchain-entry") => {
                fields(frame, &["kind", "request_id", "sha256", "path", "entry"])?;
                if self.receiver.entry_count() >= self.entries {
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
                self.receiver
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
                self.receiver
                    .write_chunk(path, offset, &bytes, digest(&frame["chunk_sha256"])?)
                    .map_err(|error| error.to_string())?;
                Ok(
                    json!({"kind":"toolchain-chunk-accepted", "request_id":self.request_id,
                        "sha256":identity, "path":path, "next_offset":next}),
                )
            }
            Some("toolchain-seal") => {
                fields(frame, &["kind", "request_id", "sha256"])?;
                if self.receiver.entry_count() != self.entries {
                    return Err("toolchain entry count differs from declaration".to_owned());
                }
                let deadline = self.deadline;
                let prepared = self
                    .receiver
                    .seal(|| cancelled.load(Ordering::Acquire) || Instant::now() >= deadline)
                    .map_err(|error| error.to_string())?;
                self.prepared = Some(prepared);
                self.ready(cancelled)
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
}

impl TransferState {
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
                prepared: None,
                receiver,
                _directory: directory,
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
        let prepared = owner
            .prepared
            .as_ref()
            .ok_or("execution toolchain is not completely verified")?;
        prepared
            .root()
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
        Self {
            state: Some(TransferState::default()),
            shared: Arc::new(Mutex::new(CompletionState::default())),
            cancelled: Arc::new(AtomicBool::new(false)),
            sender: None,
            thread: None,
            pending_id: None,
            upload_id: None,
            failed: false,
        }
    }
}

impl ToolchainTransferTask {
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
}
