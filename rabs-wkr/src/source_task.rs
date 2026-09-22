//! Session-owned source filesystem work (S5/D018).
//!
//! Cache lookup, copying and sealing may touch the whole source projection.
//! They must not run on the worker's control reactor. One lazily created,
//! joined thread executes the existing source receiver, one frame at a time.
//! The reactor never holds a source-state lock across filesystem work, and
//! cannot obtain an execution source while a frame is being processed.
//!
//! Cancellation revokes readiness immediately. It is not interruption of a
//! blocking kernel filesystem call: cleanup joins the worker rather than
//! detaching it or exposing a late successful seal after cancellation.

use crate::source_transfer::{SourceOwner, SourceTransferState};
use serde_json::Value;
use std::io;
use std::sync::{Arc, Mutex, mpsc};
use std::task::{Context, Poll, Waker};
use std::thread::JoinHandle;

struct Job {
    source: SourceTransferState,
    frame: Value,
}

struct Completed {
    source: SourceTransferState,
    response: Result<Value, String>,
}

#[derive(Default)]
struct CompletionState {
    result: Option<Result<Completed, String>>,
    waker: Option<Waker>,
}

/// Exactly one response to a submitted source frame. The request ID belongs
/// to the submitted frame, including refusals; it is never inferred from a
/// filesystem path or from a worker-supplied response.
pub struct SourceReply {
    pub request_id: u64,
    pub response: Result<Value, String>,
}

/// Non-clone owner of the source receiver and its filesystem thread.
/// An idle/unnegotiated session creates no thread. Each session retains at
/// most one in-flight source frame and one completion, not an unbounded queue.
pub struct SourceTransferTask {
    source: Option<SourceTransferState>,
    shared: Arc<Mutex<CompletionState>>,
    sender: Option<mpsc::SyncSender<Job>>,
    thread: Option<JoinHandle<()>>,
    pending_id: Option<u64>,
    upload_id: Option<u64>,
    cancelled: bool,
    failed: bool,
}

impl Default for SourceTransferTask {
    fn default() -> Self {
        Self {
            source: Some(SourceTransferState::default()),
            shared: Arc::new(Mutex::new(CompletionState::default())),
            sender: None,
            thread: None,
            pending_id: None,
            upload_id: None,
            cancelled: false,
            failed: false,
        }
    }
}

impl SourceTransferTask {
    fn start_worker(
        &mut self,
        mut handle: impl FnMut(&mut SourceTransferState, &Value) -> Result<Value, String>
        + Send + 'static,
    ) -> io::Result<()> {
        if self.thread.is_some() || self.sender.is_some() {
            return Err(io::Error::other("source filesystem worker already started"));
        }
        let (sender, receiver) = mpsc::sync_channel::<Job>(1);
        let shared = Arc::clone(&self.shared);
        let thread = std::thread::Builder::new()
            .name("rabs-source-io".to_owned())
            .spawn(move || {
                while let Ok(mut job) = receiver.recv() {
                    // An unwind cannot return partly mutated state to the
                    // admission path. The session receives a fatal error.
                    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        handle(&mut job.source, &job.frame)
                    }));
                    let fatal = outcome.is_err();
                    let result = match outcome {
                        Ok(response) => Ok(Completed { source: job.source, response }),
                        Err(_) => Err("source filesystem worker panicked".to_owned()),
                    };
                    let wake = {
                        let mut completion = shared.lock().unwrap_or_else(|e| e.into_inner());
                        completion.result = Some(result);
                        completion.waker.take()
                    };
                    if let Some(waker) = wake { waker.wake(); }
                    if fatal { break; }
                }
            })?;
        self.sender = Some(sender);
        self.thread = Some(thread);
        Ok(())
    }

    /// Submit only after session negotiation and execution/output busy checks.
    /// Refusals before submission do not move, poison or replace the receiver.
    /// A second source frame must wait for the first one's completion.
    pub fn submit(&mut self, frame: &Value, enabled: bool, busy: bool) -> Result<(), String> {
        if !enabled { return Err("source transfer not negotiated".to_owned()); }
        if busy { return Err("worker-busy-or-result-pending".to_owned()); }
        if self.cancelled { return Err("source upload cancelled".to_owned()); }
        if self.failed { return Err("source filesystem worker failed".to_owned()); }
        if self.pending_id.is_some() { return Err("source-operation-pending".to_owned()); }
        if !matches!(frame["kind"].as_str(), Some("source-begin" | "source-chunk" | "source-seal")) {
            return Err("unknown source operation".to_owned());
        }
        let id = frame["request_id"].as_u64().ok_or("source request_id must be unsigned")?;
        if self.sender.is_none() {
            self.start_worker(|state, value| state.handle(value, true, false))
                .map_err(|error| format!("start source filesystem worker: {error}"))?;
        }
        let sender = self.sender.as_ref().ok_or("source filesystem worker unavailable")?;
        let source = self.source.take().ok_or("source-operation-pending")?;
        match sender.try_send(Job { source, frame: frame.clone() }) {
            Ok(()) => {
                self.pending_id = Some(id);
                Ok(())
            }
            Err(mpsc::TrySendError::Full(job) | mpsc::TrySendError::Disconnected(job)) => {
                self.source = Some(job.source);
                self.failed = true;
                Err("source filesystem worker unavailable".to_owned())
            }
        }
    }

    /// Complete a frame without waiting on filesystem work. Registering the
    /// waker and testing for a result share one lock, so completion cannot race
    /// between a readiness check and subscription and leave the reactor asleep.
    pub fn poll_completion(&mut self, cx: &mut Context<'_>) -> Poll<Result<SourceReply, String>> {
        let Some(id) = self.pending_id else { return Poll::Pending; };
        let result = {
            let mut completion = self.shared.lock().unwrap_or_else(|e| e.into_inner());
            match completion.result.take() {
                Some(result) => result,
                None => {
                    if completion.waker.as_ref().is_none_or(|wake| !wake.will_wake(cx.waker())) {
                        completion.waker = Some(cx.waker().clone());
                    }
                    return Poll::Pending;
                }
            }
        };
        self.pending_id = None;
        match result {
            Ok(Completed { source, mut response }) => {
                self.source = Some(source);
                if response.as_ref().is_ok_and(|value| value["kind"] == "source-ready") {
                    self.upload_id = Some(id);
                }
                if self.cancelled { response = Err("source upload cancelled".to_owned()); }
                Poll::Ready(Ok(SourceReply { request_id: id, response }))
            }
            Err(error) => {
                self.failed = true;
                Poll::Ready(Err(error))
            }
        }
    }

    /// The source identity currently owned by this session. A foreign frame
    /// in flight cannot change which already-admitted upload is cancellable.
    #[must_use]
    pub fn request_id(&self) -> Option<u64> { self.upload_id.or(self.pending_id) }

    #[must_use]
    pub fn is_pending(&self) -> bool { self.pending_id.is_some() }

    /// Revoke this upload's execution readiness without waiting for disk I/O.
    /// None means a foreign/unknown ID. Some(false) is an idempotent repeat.
    /// The retained state is discarded with the session; cancellation never
    /// clears execution history or authorizes a new upload under the same ID.
    pub fn cancel(&mut self, request_id: u64) -> Option<bool> {
        if self.request_id() != Some(request_id) { return None; }
        let accepted = !self.cancelled;
        self.cancelled = true;
        Some(accepted)
    }

    /// The synchronous admission check is available only while the receiver
    /// is back on this thread. It parses identity; it does no filesystem work.
    pub fn prepared_path(&self, request: &Value, enabled: bool) -> Result<Option<String>, String> {
        if request.get("source_manifest").is_some() && (self.cancelled || self.failed) {
            return Err("execution source is cancelled or failed".to_owned());
        }
        self.source.as_ref().ok_or("source-operation-pending")?.prepared_path(request, enabled)
    }

    /// Transfer the verified source owner only after durable execution
    /// admission. The caller must retain it through process and drain cleanup.
    pub fn take_prepared(&mut self, request: &Value) -> io::Result<Option<SourceOwner>> {
        self.prepared_path(request, true).map_err(io::Error::other)?;
        let owner = self.source.as_mut().ok_or_else(|| io::Error::other("source-operation-pending"))?
            .take_prepared(request)?;
        if owner.is_some() { self.upload_id = None; }
        Ok(owner)
    }
}

impl Drop for SourceTransferTask {
    fn drop(&mut self) {
        // Close the command channel FIRST. The worker completes the one
        // accepted job, then exits; no join while an idle recv stays open.
        drop(self.sender.take());
        if let Some(thread) = self.thread.take() { let _ = thread.join(); }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::source_transfer::hex;
    use rabs_sandbox::source_transfer::{SourceFile, SourceManifest};
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Wake;
    use std::time::{Duration, Instant};

    const BYTES: &[u8] = b"source\0\xff";

    fn request() -> Value {
        let manifest = SourceManifest::new(vec![SourceFile {
            path: "lib.rs".to_owned(), len: BYTES.len() as u64,
            sha256: Sha256::digest(BYTES).into(), executable: false,
        }]).unwrap();
        json!({"kind":"canonical-exec", "request_id":7, "source_manifest":{
            "manifest_sha256":hex(&manifest.digest()), "files":[{
                "path":"lib.rs", "bytes":BYTES.len(),
                "sha256":hex(&Sha256::digest(BYTES)), "executable":false,
            }],
        }})
    }

    fn begin(request: &Value) -> Value {
        json!({"kind":"source-begin", "request_id":7, "manifest":request["source_manifest"]})
    }

    struct Notifier { thread: std::thread::Thread, wakes: AtomicUsize }
    impl Wake for Notifier {
        fn wake(self: Arc<Self>) {
            self.wakes.fetch_add(1, Ordering::SeqCst);
            self.thread.unpark();
        }
    }

    fn notifier() -> Arc<Notifier> {
        Arc::new(Notifier { thread: std::thread::current(), wakes: AtomicUsize::new(0) })
    }

    fn finish(task: &mut SourceTransferTask) -> Result<SourceReply, String> {
        let waker = Waker::from(notifier());
        let mut cx = Context::from_waker(&waker);
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            if let Poll::Ready(reply) = task.poll_completion(&mut cx) { return reply; }
            assert!(Instant::now() < until, "source task failed to wake or finish");
            std::thread::park_timeout(Duration::from_millis(5));
        }
    }

    fn exchange(task: &mut SourceTransferTask, frame: &Value) -> Value {
        task.submit(frame, true, false).unwrap();
        let reply = finish(task).unwrap();
        assert_eq!(reply.request_id, 7);
        reply.response.unwrap()
    }

    fn upload(task: &mut SourceTransferTask, request: &Value) {
        assert_eq!(exchange(task, &begin(request))["sealed"], false);
        assert!(task.prepared_path(request, true).is_err());
        exchange(task, &json!({"kind":"source-chunk", "request_id":7,
            "manifest_sha256":request["source_manifest"]["manifest_sha256"],
            "path":"lib.rs", "offset":0, "data_hex":hex(BYTES),
            "chunk_sha256":hex(&Sha256::digest(BYTES))}));
        assert_eq!(exchange(task, &json!({"kind":"source-seal", "request_id":7,
            "manifest_sha256":request["source_manifest"]["manifest_sha256"]}))["sealed"], true);
    }

    #[test]
    fn source_bytes_roundtrip_on_one_thread_then_transfer_execution_ownership() {
        let mut task = SourceTransferTask::default();
        let request = request();
        upload(&mut task, &request);
        let path = std::path::PathBuf::from(task.prepared_path(&request, true).unwrap().unwrap());
        assert_eq!(std::fs::read(path.join("lib.rs")).unwrap(), BYTES);
        let owner = task.take_prepared(&request).unwrap().unwrap();
        assert_eq!(task.request_id(), None);
        assert!(task.prepared_path(&request, true).is_err());
        drop(task);
        assert!(path.exists(), "execution, not the I/O thread, owns the sealed tree");
        drop(owner);
        assert!(!path.exists());
    }

    #[test]
    fn blocked_filesystem_work_is_pending_and_wakes_without_holding_the_reactor() {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let reactor = std::thread::current().id();
        let mut task = SourceTransferTask::default();
        task.start_worker(move |source, frame| {
            entered_tx.send(std::thread::current().id()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            source.handle(frame, true, false)
        }).unwrap();
        let request = request();
        task.submit(&begin(&request), true, false).unwrap();
        assert_ne!(entered_rx.recv_timeout(Duration::from_secs(5)).unwrap(), reactor);
        let notify = notifier();
        let waker = Waker::from(Arc::clone(&notify));
        assert!(task.poll_completion(&mut Context::from_waker(&waker)).is_pending());
        assert!(task.is_pending());
        assert!(task.prepared_path(&request, true).is_err());
        assert!(task.take_prepared(&request).is_err());
        assert_eq!(task.submit(&begin(&request), true, false).unwrap_err(), "source-operation-pending");
        release_tx.send(()).unwrap();
        let until = Instant::now() + Duration::from_secs(5);
        while notify.wakes.load(Ordering::SeqCst) == 0 {
            assert!(Instant::now() < until, "completion did not wake the registered reactor");
            std::thread::park_timeout(Duration::from_millis(5));
        }
        assert_eq!(finish(&mut task).unwrap().response.unwrap()["sealed"], false);
        // Joining also waits for the wake that follows publishing the result.
        drop(task);
        assert!(notify.wakes.load(Ordering::SeqCst) > 0);
    }

    #[test]
    fn cancellation_fences_a_late_ready_and_cannot_target_another_upload() {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let mut task = SourceTransferTask::default();
        task.start_worker(move |source, frame| {
            let result = source.handle(frame, true, false);
            entered_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            result
        }).unwrap();
        let request = request();
        task.submit(&begin(&request), true, false).unwrap();
        entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(task.cancel(8), None);
        assert_eq!(task.cancel(7), Some(true));
        assert_eq!(task.cancel(7), Some(false));
        release_tx.send(()).unwrap();
        assert_eq!(finish(&mut task).unwrap().response.unwrap_err(), "source upload cancelled");
        assert!(task.prepared_path(&request, true).is_err());
        assert!(task.take_prepared(&request).is_err());
        assert!(task.submit(&begin(&request), true, false).is_err());
    }

    #[test]
    fn sealed_source_can_be_cancelled_before_execution_admission() {
        let mut task = SourceTransferTask::default();
        let request = request();
        upload(&mut task, &request);
        assert!(task.prepared_path(&request, true).is_ok());
        assert_eq!(task.cancel(7), Some(true));
        assert!(task.take_prepared(&request).is_err());
        assert!(task.prepared_path(&request, true).is_err());
    }

    #[test]
    fn unnegotiated_busy_and_invalid_frames_do_not_create_a_thread() {
        let mut task = SourceTransferTask::default();
        let request = request();
        assert!(task.submit(&begin(&request), false, false).is_err());
        assert!(task.submit(&begin(&request), true, true).is_err());
        assert!(task.submit(&request, true, false).is_err());
        let mut missing = begin(&request); missing["request_id"] = Value::Null;
        assert!(task.submit(&missing, true, false).is_err());
        assert!(task.thread.is_none());
        assert!(!task.is_pending());
        upload(&mut task, &request);
    }

    #[test]
    fn worker_unwind_never_returns_source_authority_or_accepts_more_work() {
        let mut task = SourceTransferTask::default();
        task.start_worker(|_, _| panic!("injected source worker unwind")).unwrap();
        let request = request();
        task.submit(&begin(&request), true, false).unwrap();
        assert!(finish(&mut task).is_err());
        assert!(task.prepared_path(&request, true).is_err());
        assert!(task.take_prepared(&request).is_err());
        assert!(task.submit(&begin(&request), true, false).is_err());
    }

    #[test]
    fn dropping_a_busy_owner_joins_instead_of_detaching_filesystem_work() {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let mut task = SourceTransferTask::default();
        task.start_worker(move |source, frame| {
            entered_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            source.handle(frame, true, false)
        }).unwrap();
        task.submit(&begin(&request()), true, false).unwrap();
        entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let (done_tx, done_rx) = mpsc::channel();
        let dropper = std::thread::spawn(move || { drop(task); done_tx.send(()).unwrap(); });
        assert!(done_rx.try_recv().is_err(), "owner returned with an outstanding filesystem operation");
        release_tx.send(()).unwrap();
        done_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        dropper.join().unwrap();
    }
}
