//! Bounded messages for one authenticated canonical operation per connection.
//!
//! The TLS/ATP layer owns framing and peer identity. This layer admits only
//! logical build intent and bytes. Requests cannot select host paths or carry
//! coordinator authority, worker assignments or in-process subscriber handles.
//! Diagnostic bytes are presentation, never filesystem or execution authority.

use super::super::remote_operation::RemoteOperationSettings;
use asupersync::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use rabs_asupersync::worker_transport::{MAX_JSON_RECORD, runtime_transport_now};
use rabs_protocol::raw_bytes::encode_hex;
use rabs_sandbox::source_transfer::{MAX_SOURCE_CHUNK, SourceFile, SourceManifest};
use rabs_sandbox::toolchain_dataset::{
    TOOLCHAIN_DATASET_VERSION, ToolchainIdentity, ToolchainLimits,
};
use rabs_sandbox::toolchain_transfer::{ToolchainEntry, ToolchainEntryKind};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::future::{Future, poll_fn};
use std::io;
use std::pin::pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;
use std::time::{Duration, Instant};

pub(super) const VERSION: &str = "canonical-compile-remote-v1";
pub(super) const WIRE_VERSION: &str = "canonical-compile-remote-v2";
pub(super) const WINDOW: u64 = 4;
pub(super) const IO_BUDGET: Duration = Duration::from_secs(15);
pub(super) const ADMISSION_BUDGET: Duration = Duration::from_secs(30 * 60);
pub(super) const ADMISSION_POLL: Duration = Duration::from_millis(100);
const CANCELLATION_POLL: Duration = Duration::from_millis(100);
const READS_BEFORE_YIELD: usize = 32;

pub(super) fn invalid(detail: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, detail.into())
}

pub(super) fn require(condition: bool, detail: &str) -> io::Result<()> {
    if condition {
        Ok(())
    } else {
        Err(invalid(detail))
    }
}

pub(super) fn checkpoint(stopped: &AtomicBool, deadline: Instant) -> io::Result<()> {
    if stopped.load(Ordering::Acquire) {
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "remote canonical operation cancelled",
        ))
    } else if Instant::now() >= deadline {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "remote canonical operation deadline exceeded",
        ))
    } else {
        Ok(())
    }
}

pub(super) fn decode_hex(value: &str, maximum: usize) -> io::Result<Vec<u8>> {
    require(
        value.len().is_multiple_of(2) && value.len() / 2 <= maximum,
        "remote byte string exceeds its bound or has an odd length",
    )?;
    fn digit(value: u8) -> io::Result<u8> {
        match value {
            b'0'..=b'9' => Ok(value - b'0'),
            b'a'..=b'f' => Ok(value - b'a' + 10),
            _ => Err(invalid(
                "remote byte strings require canonical lowercase hexadecimal",
            )),
        }
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| Ok((digit(pair[0])? << 4) | digit(pair[1])?))
        .collect()
}

pub(super) fn digest(value: &str) -> io::Result<[u8; 32]> {
    decode_hex(value, 32)?
        .try_into()
        .map_err(|_| invalid("expected a SHA-256 digest"))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ManifestFile {
    path: String,
    bytes: u64,
    sha256: String,
    executable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Manifest {
    files: Vec<ManifestFile>,
    pub(super) manifest_sha256: String,
}

impl Manifest {
    pub(super) fn from_native(manifest: &SourceManifest) -> Self {
        Self {
            files: manifest
                .files()
                .iter()
                .map(|file| ManifestFile {
                    path: file.path.clone(),
                    bytes: file.len,
                    sha256: encode_hex(&file.sha256),
                    executable: file.executable,
                })
                .collect(),
            manifest_sha256: encode_hex(&manifest.digest()),
        }
    }

    pub(super) fn native(&self) -> io::Result<SourceManifest> {
        let files = self
            .files
            .iter()
            .map(|file| {
                Ok(SourceFile {
                    path: file.path.clone(),
                    len: file.bytes,
                    sha256: digest(&file.sha256)?,
                    executable: file.executable,
                })
            })
            .collect::<io::Result<Vec<_>>>()?;
        let manifest = SourceManifest::new(files)?;
        require(
            manifest.digest() == digest(&self.manifest_sha256)?,
            "remote manifest digest differs from its complete file declaration",
        )?;
        Ok(manifest)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Toolchain {
    version: String,
    sha256: String,
    files: u64,
    bytes: u64,
}

impl Toolchain {
    pub(super) fn from_native(identity: &ToolchainIdentity) -> Self {
        Self {
            version: TOOLCHAIN_DATASET_VERSION.into(),
            sha256: encode_hex(&identity.sha256),
            files: identity.files,
            bytes: identity.bytes,
        }
    }

    pub(super) fn native(&self) -> io::Result<ToolchainIdentity> {
        let limits = ToolchainLimits::default();
        require(
            self.version == TOOLCHAIN_DATASET_VERSION
                && self.files != 0
                && self.files <= limits.max_entries as u64
                && self.bytes <= limits.max_bytes,
            "unsupported or oversized remote toolchain identity",
        )?;
        Ok(ToolchainIdentity {
            sha256: digest(&self.sha256)?,
            files: self.files,
            bytes: self.bytes,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CargoHome {
    version: String,
    prefix: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub(super) enum Entry {
    Directory {
        path: String,
    },
    Symlink {
        path: String,
        target: String,
    },
    File {
        path: String,
        bytes: u64,
        executable: bool,
    },
}

impl Entry {
    pub(super) fn from_native(entry: ToolchainEntry) -> Self {
        match entry.kind {
            ToolchainEntryKind::Directory => Self::Directory { path: entry.path },
            ToolchainEntryKind::Symlink { target } => Self::Symlink {
                path: entry.path,
                target,
            },
            ToolchainEntryKind::File { bytes, executable } => Self::File {
                path: entry.path,
                bytes,
                executable,
            },
        }
    }

    pub(super) fn native(self) -> ToolchainEntry {
        let (path, kind) = match self {
            Self::Directory { path } => (path, ToolchainEntryKind::Directory),
            Self::Symlink { path, target } => (path, ToolchainEntryKind::Symlink { target }),
            Self::File {
                path,
                bytes,
                executable,
            } => (path, ToolchainEntryKind::File { bytes, executable }),
        };
        ToolchainEntry { path, kind }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Chunk {
    pub(super) path: String,
    pub(super) offset: u64,
    sha256: String,
    bytes: String,
}

impl Chunk {
    pub(super) fn new(path: &str, offset: u64, bytes: &[u8]) -> io::Result<Self> {
        require(
            !bytes.is_empty() && bytes.len() <= MAX_SOURCE_CHUNK,
            "invalid remote chunk length",
        )?;
        Ok(Self {
            path: path.into(),
            offset,
            sha256: encode_hex(&Sha256::digest(bytes)),
            bytes: encode_hex(bytes),
        })
    }

    pub(super) fn verified_bytes(&self) -> io::Result<(Vec<u8>, [u8; 32])> {
        let bytes = decode_hex(&self.bytes, MAX_SOURCE_CHUNK)?;
        let expected = digest(&self.sha256)?;
        require(
            !bytes.is_empty() && <[u8; 32]>::from(Sha256::digest(&bytes)) == expected,
            "remote chunk is empty or its digest differs",
        )?;
        Ok((bytes, expected))
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Output {
    pub(super) offset: u64,
    pub(super) bytes: String,
}

/// The authenticated coordinator owns any reused SDK for this operation.
/// Reuse changes only which input bytes are sent, never their declared identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum ToolchainDisposition {
    Upload,
    Reuse,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(super) enum Message {
    Hello {
        version: String,
        build_identity: String,
        require_release: bool,
        settings: Box<RemoteOperationSettings>,
        source_manifest: Manifest,
        toolchain_identity: Toolchain,
        cargo_home: Option<CargoHome>,
    },
    Queued,
    Ready {
        toolchain: ToolchainDisposition,
    },
    SourceChunk {
        chunk: Chunk,
    },
    ToolchainEntry {
        entry: Entry,
    },
    ToolchainChunk {
        chunk: Chunk,
    },
    WindowEnd {
        count: u64,
    },
    Window {
        count: u64,
    },
    InputsDone,
    Accepted,
    Poll,
    Progress {
        stdout: Output,
        stderr: Output,
    },
    BuildFinished {
        exit_code: i32,
        stdout_bytes: u64,
        stderr_bytes: u64,
        target: Option<Manifest>,
    },
    ReceiveTarget,
    ArtifactChunk {
        chunk: Chunk,
    },
    ArtifactEnd,
    Received {
        manifest_sha256: String,
    },
    Commit {
        manifest_sha256: String,
    },
    Published {
        manifest_sha256: String,
    },
    Complete {
        exit_code: i32,
    },
    Close,
    Cancel,
    Failure {
        message: String,
    },
}

/// A fixed byte/frame deadline and a finite buffer belong to this connection.
/// Partial records are never retried on another connection or another build.
pub(super) struct Wire<S> {
    stream: S,
    buffered: Vec<u8>,
    failed: bool,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Wire<S> {
    pub(super) fn new(stream: S) -> Self {
        Self {
            stream,
            buffered: Vec::new(),
            failed: false,
        }
    }

    pub(super) async fn send(
        &mut self,
        message: &Message,
        stopped: &AtomicBool,
        deadline: Instant,
    ) -> io::Result<()> {
        require(
            !self.failed,
            "remote connection is terminal after an I/O failure",
        )?;
        let result = async {
            checkpoint(stopped, deadline)?;
            let mut bytes = serde_json::to_vec(message)?;
            require(
                bytes.len() <= MAX_JSON_RECORD,
                "remote record exceeds its ATP bound",
            )?;
            bytes.push(b'\n');
            let write_deadline = deadline.min(Instant::now() + IO_BUDGET);
            controlled_future(stopped, write_deadline, async {
                self.stream.write_all(&bytes).await?;
                self.stream.flush().await
            })
            .await
        }
        .await;
        // ATP retains partial output independently of this future. A later
        // error-reporting send must never resume an expired Commit/Complete.
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    pub(super) async fn receive(
        &mut self,
        stopped: &AtomicBool,
        deadline: Instant,
    ) -> io::Result<Message> {
        self.receive_until(stopped, deadline.min(Instant::now() + IO_BUDGET))
            .await
    }

    /// A client may wait while the server seals an SDK or revalidates complete
    /// artifact provenance. Keep the original phase deadline through that idle
    /// wait; the enclosing ATP adapter still bounds each partial wire record.
    pub(super) async fn receive_until(
        &mut self,
        stopped: &AtomicBool,
        deadline: Instant,
    ) -> io::Result<Message> {
        require(
            !self.failed,
            "remote connection is terminal after an I/O failure",
        )?;
        let result = async {
            let message = controlled_future(
                stopped,
                deadline,
                read_record(&mut self.stream, &mut self.buffered),
            )
            .await?;
            match message {
                Message::Failure { message } => Err(invalid(format!(
                    "remote canonical service: {}",
                    message.chars().take(4096).collect::<String>()
                ))),
                Message::Cancel => Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "remote client cancelled its operation",
                )),
                message => Ok(message),
            }
        }
        .await;
        if result.is_err() {
            self.failed = true;
        }
        result
    }
}

/// Poll one retained I/O future while an independent timer observes atomic
/// cancellation. Ticks neither recreate partial reads/writes nor renew the
/// supplied deadline. A quiet peer therefore cannot delay local cancellation.
pub(super) async fn controlled_future<T>(
    stopped: &AtomicBool,
    deadline: Instant,
    future: impl Future<Output = io::Result<T>>,
) -> io::Result<T> {
    let mut work = pin!(future);
    loop {
        checkpoint(stopped, deadline)?;
        let budget = CANCELLATION_POLL.min(deadline.saturating_duration_since(Instant::now()));
        let mut tick = pin!(asupersync::time::sleep(runtime_transport_now(), budget));
        let completed = poll_fn(|cx| {
            if let Err(error) = checkpoint(stopped, deadline) {
                return Poll::Ready(Err(error));
            }
            if let Poll::Ready(result) = work.as_mut().poll(cx) {
                return Poll::Ready(result.map(Some));
            }
            if tick.as_mut().poll(cx).is_ready() {
                Poll::Ready(Ok(None))
            } else {
                Poll::Pending
            }
        })
        .await?;
        if let Some(completed) = completed {
            checkpoint(stopped, deadline)?;
            return Ok(completed);
        }
    }
}

async fn read_record<S: AsyncRead + Unpin>(
    stream: &mut S,
    buffered: &mut Vec<u8>,
) -> io::Result<Message> {
    let mut scanned = 0;
    let mut chunk = [0_u8; 16 * 1024];
    let mut reads = 0;
    loop {
        if let Some(offset) = buffered[scanned..].iter().position(|byte| *byte == b'\n') {
            let end = scanned + offset;
            require(
                end <= MAX_JSON_RECORD,
                "remote record exceeds its ATP bound",
            )?;
            let message = serde_json::from_slice(&buffered[..end])
                .map_err(|error| invalid(error.to_string()))?;
            buffered.drain(..=end);
            return Ok(message);
        }
        require(
            buffered.len() <= MAX_JSON_RECORD,
            "remote record exceeds its ATP bound",
        )?;
        scanned = buffered.len();
        let capacity = chunk.len().min(MAX_JSON_RECORD + 1 - buffered.len());
        let count = stream.read(&mut chunk[..capacity]).await?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "remote connection ended without a terminal receipt",
            ));
        }
        buffered.extend_from_slice(&chunk[..count]);
        reads += 1;
        if reads == READS_BEFORE_YIELD {
            reads = 0;
            // A continuously ready socket must return to the owning poll so
            // its deadline and cancellation win over more buffered input.
            let mut yielded = false;
            poll_fn(|cx| {
                if yielded {
                    Poll::Ready(())
                } else {
                    yielded = true;
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            })
            .await;
        }
    }
}

/// Both directions acknowledge exact cumulative counts after at most four
/// chunks/entries. TCP can pipeline a window without unbounded queued memory.
#[derive(Debug, Default)]
pub(super) struct Window {
    count: u64,
    pending: u64,
}

impl Window {
    pub(super) fn record(&mut self) -> io::Result<bool> {
        require(
            self.pending < WINDOW,
            "remote transfer exceeded its unacknowledged window",
        )?;
        self.count = self
            .count
            .checked_add(1)
            .ok_or_else(|| invalid("remote transfer counter exhausted"))?;
        self.pending += 1;
        Ok(self.pending == WINDOW)
    }

    pub(super) fn pending(&self) -> bool {
        self.pending != 0
    }
    pub(super) fn count(&self) -> u64 {
        self.count
    }

    pub(super) fn acknowledge(&mut self, count: u64) -> io::Result<()> {
        require(
            self.pending != 0 && count == self.count,
            "remote transfer acknowledgment is stale or out of order",
        )?;
        self.pending = 0;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asupersync::io::ReadBuf;
    use serde_json::json;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;
    use std::task::{Context, Waker};

    struct MemoryStream {
        input: Vec<u8>,
        offset: usize,
        quantum: usize,
        eof: bool,
        reads: Arc<AtomicUsize>,
        output: Vec<u8>,
        write_gate: Option<Arc<AtomicBool>>,
        write_prefix: usize,
    }

    impl MemoryStream {
        fn new(input: Vec<u8>, quantum: usize) -> Self {
            Self {
                input,
                offset: 0,
                quantum,
                eof: true,
                reads: Arc::new(AtomicUsize::new(0)),
                output: Vec::new(),
                write_gate: None,
                write_prefix: usize::MAX,
            }
        }
    }

    impl AsyncRead for MemoryStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            output: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let stream = self.get_mut();
            stream.reads.fetch_add(1, Ordering::Relaxed);
            if stream.offset == stream.input.len() && !stream.eof {
                // Deliberately supply no wakeup. The controller's own timer
                // must observe stop/deadline without assistance from its peer.
                return Poll::Pending;
            }
            let count = output
                .remaining()
                .min(stream.quantum)
                .min(stream.input.len() - stream.offset);
            output.put_slice(&stream.input[stream.offset..stream.offset + count]);
            stream.offset += count;
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for MemoryStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            let stream = self.get_mut();
            let allowed = if stream
                .write_gate
                .as_ref()
                .is_some_and(|open| !open.load(Ordering::Acquire))
            {
                stream.write_prefix.saturating_sub(stream.output.len())
            } else {
                usize::MAX
            };
            if allowed == 0 {
                return Poll::Pending;
            }
            let count = bytes.len().min(3).min(allowed);
            stream.output.extend_from_slice(&bytes[..count]);
            Poll::Ready(Ok(count))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.poll_flush(cx)
        }
    }

    fn ready<T>(future: impl Future<Output = T>) -> T {
        let mut future = pin!(future);
        let mut context = Context::from_waker(Waker::noop());
        for _ in 0..100_000 {
            if let Poll::Ready(value) = future.as_mut().poll(&mut context) {
                return value;
            }
        }
        panic!("deterministic remote record did not settle");
    }

    fn native_timer_test(future: impl Future<Output = ()> + Send + 'static) {
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap();
        let handle = runtime.handle();
        rabs_asupersync::daemon_runtime::block_on_top_level(&runtime, async move {
            handle
                .spawn(async move {
                    asupersync::time::timeout(
                        runtime_transport_now(),
                        Duration::from_secs(2),
                        future,
                    )
                    .await
                    .expect("wire cancellation/deadline failed to wake idle I/O");
                })
                .await
        });
    }

    fn record(message: &Message) -> Vec<u8> {
        let mut bytes = serde_json::to_vec(message).unwrap();
        bytes.push(b'\n');
        bytes
    }

    #[test]
    fn fragmented_and_coalesced_records_keep_the_exact_next_phase() {
        let mut bytes = record(&Message::Queued);
        bytes.extend(record(&Message::Ready {
            toolchain: ToolchainDisposition::Reuse,
        }));
        bytes.extend(record(&Message::Window { count: 4 }));
        bytes.extend(record(&Message::Complete { exit_code: 0 }));
        for quantum in [1, 3, 16 * 1024] {
            let mut stream = MemoryStream::new(bytes.clone(), quantum);
            let mut buffered = Vec::new();
            assert!(matches!(
                ready(read_record(&mut stream, &mut buffered)).unwrap(),
                Message::Queued
            ));
            assert!(matches!(
                ready(read_record(&mut stream, &mut buffered)).unwrap(),
                Message::Ready {
                    toolchain: ToolchainDisposition::Reuse
                }
            ));
            assert!(matches!(
                ready(read_record(&mut stream, &mut buffered)).unwrap(),
                Message::Window { count: 4 }
            ));
            assert!(matches!(
                ready(read_record(&mut stream, &mut buffered)).unwrap(),
                Message::Complete { exit_code: 0 }
            ));
            assert!(buffered.is_empty());
            if quantum == 16 * 1024 {
                assert_eq!(stream.reads.load(Ordering::Relaxed), 1);
            }
        }
    }

    #[test]
    fn record_boundary_allows_the_delimiter_but_refuses_oversize_and_partial_eof() {
        let payload = serde_json::to_vec(&Message::Poll).unwrap();
        for (length, accepted) in [(MAX_JSON_RECORD, true), (MAX_JSON_RECORD + 1, false)] {
            let mut bytes = payload.clone();
            bytes.resize(length, b' ');
            bytes.push(b'\n');
            let mut stream = MemoryStream::new(bytes, usize::MAX);
            let mut buffered = Vec::new();
            let result = ready(read_record(&mut stream, &mut buffered));
            if accepted {
                assert!(matches!(result.unwrap(), Message::Poll));
            } else {
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
                assert!(buffered.len() <= MAX_JSON_RECORD + 1);
            }
        }
        for bytes in [Vec::new(), payload, br#"{"kind":"po"#.to_vec()] {
            let mut stream = MemoryStream::new(bytes, 3);
            assert_eq!(
                ready(read_record(&mut stream, &mut Vec::new()))
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::UnexpectedEof
            );
        }
    }

    #[test]
    fn continuously_ready_fragments_yield_before_starving_the_controller() {
        let mut bytes = serde_json::to_vec(&Message::Poll).unwrap();
        bytes.resize(4 * READS_BEFORE_YIELD, b' ');
        bytes.push(b'\n');
        let mut stream = MemoryStream::new(bytes, 1);
        let reads = Arc::clone(&stream.reads);
        let mut buffered = Vec::new();
        let mut future = pin!(read_record(&mut stream, &mut buffered));
        let mut context = Context::from_waker(Waker::noop());
        assert!(future.as_mut().poll(&mut context).is_pending());
        assert_eq!(reads.load(Ordering::Relaxed), READS_BEFORE_YIELD);
        assert!(matches!(ready(future), Ok(Message::Poll)));
    }

    #[test]
    fn retained_write_continues_after_multiple_control_ticks_without_duplicate_prefix() {
        native_timer_test(async {
            let gate = Arc::new(AtomicBool::new(false));
            let release = Arc::clone(&gate);
            let setter = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(230));
                release.store(true, Ordering::Release);
            });
            let mut stream = MemoryStream::new(Vec::new(), 3);
            stream.write_gate = Some(gate);
            stream.write_prefix = 5;
            let mut wire = Wire::new(stream);
            let message = Message::Window { count: 17 };
            wire.send(
                &message,
                &AtomicBool::new(false),
                Instant::now() + Duration::from_secs(1),
            )
            .await
            .unwrap();
            setter.join().unwrap();
            assert_eq!(wire.stream.output, record(&message));
        });
    }

    #[test]
    fn atomic_stop_wakes_stalled_partial_read_and_write_without_a_peer_event() {
        native_timer_test(async {
            for writing in [false, true] {
                let stopped = Arc::new(AtomicBool::new(false));
                let stop = Arc::clone(&stopped);
                let setter = std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(25));
                    stop.store(true, Ordering::Release);
                });
                let prefix = br#"{"kind":"#.to_vec();
                let mut stream = MemoryStream::new(prefix.clone(), 3);
                stream.eof = false;
                stream.write_gate = Some(Arc::new(AtomicBool::new(false)));
                stream.write_prefix = 5;
                let mut wire = Wire::new(stream);
                let deadline = Instant::now() + Duration::from_secs(60);
                let error = if writing {
                    wire.send(&Message::Poll, &stopped, deadline)
                        .await
                        .unwrap_err()
                } else {
                    wire.receive_until(&stopped, deadline).await.unwrap_err()
                };
                setter.join().unwrap();
                assert_eq!(error.kind(), io::ErrorKind::Interrupted);
                if writing {
                    assert_eq!(wire.stream.output, record(&Message::Poll)[..5]);
                } else {
                    assert_eq!(wire.buffered, prefix);
                }
            }
        });
    }

    #[test]
    fn whole_phase_wait_expires_at_its_fixed_deadline_without_peer_wakeups() {
        native_timer_test(async {
            let mut stream = MemoryStream::new(Vec::new(), 1);
            stream.eof = false;
            let mut wire = Wire::new(stream);
            let error = wire
                .receive_until(
                    &AtomicBool::new(false),
                    Instant::now() + Duration::from_millis(30),
                )
                .await
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        });
    }

    #[test]
    fn failed_partial_io_never_resumes_when_error_reporting_or_the_peer_recovers() {
        native_timer_test(async {
            for writing in [false, true] {
                for cancelled in [false, true] {
                    let stopped = Arc::new(AtomicBool::new(false));
                    let setter = cancelled.then(|| {
                        let stop = Arc::clone(&stopped);
                        std::thread::spawn(move || {
                            std::thread::sleep(Duration::from_millis(25));
                            stop.store(true, Ordering::Release);
                        })
                    });
                    let gate = Arc::new(AtomicBool::new(false));
                    let mut stream = MemoryStream::new(br#"{"kind":"#.to_vec(), 3);
                    stream.eof = false;
                    stream.write_gate = Some(Arc::clone(&gate));
                    stream.write_prefix = 5;
                    let mut wire = Wire::new(stream);
                    let deadline = Instant::now()
                        + if cancelled {
                            Duration::from_secs(1)
                        } else {
                            Duration::from_millis(30)
                        };
                    let error = if writing {
                        wire.send(
                            &Message::Commit {
                                manifest_sha256: "11".repeat(32),
                            },
                            &stopped,
                            deadline,
                        )
                        .await
                        .unwrap_err()
                    } else {
                        wire.receive_until(&stopped, deadline).await.unwrap_err()
                    };
                    if let Some(setter) = setter {
                        setter.join().unwrap();
                    }
                    assert_eq!(
                        error.kind(),
                        if cancelled {
                            io::ErrorKind::Interrupted
                        } else {
                            io::ErrorKind::TimedOut
                        }
                    );
                    let written = wire.stream.output.clone();
                    let reads = wire.stream.reads.load(Ordering::Relaxed);
                    if writing {
                        assert_eq!(written.len(), 5);
                    } else {
                        assert!(!wire.buffered.is_empty());
                    }

                    // A fresh budget, cleared cancellation and ready peer must
                    // not let generic Failure reporting flush the stale Commit.
                    stopped.store(false, Ordering::Release);
                    gate.store(true, Ordering::Release);
                    wire.stream.input = record(&Message::Ready {
                        toolchain: ToolchainDisposition::Upload,
                    });
                    wire.stream.offset = 0;
                    wire.stream.eof = true;
                    let deadline = Instant::now() + Duration::from_secs(1);
                    assert!(
                        wire.send(
                            &Message::Failure {
                                message: "operation aborted".into(),
                            },
                            &stopped,
                            deadline,
                        )
                        .await
                        .is_err()
                    );
                    assert!(wire.receive_until(&stopped, deadline).await.is_err());
                    assert!(wire.receive(&stopped, deadline).await.is_err());
                    assert_eq!(wire.stream.output, written);
                    assert_eq!(wire.stream.reads.load(Ordering::Relaxed), reads);
                }
            }
        });
    }

    #[test]
    fn peer_failure_cancel_malformed_record_and_eof_are_terminal() {
        native_timer_test(async {
            for first in [
                record(&Message::Failure {
                    message: "refused".into(),
                }),
                record(&Message::Cancel),
                b"{invalid}\n".to_vec(),
                Vec::new(),
            ] {
                let mut wire = Wire::new(MemoryStream::new(first, 3));
                let stopped = AtomicBool::new(false);
                let deadline = Instant::now() + Duration::from_secs(1);
                assert!(wire.receive_until(&stopped, deadline).await.is_err());
                let reads = wire.stream.reads.load(Ordering::Relaxed);
                wire.stream.input = record(&Message::Ready {
                    toolchain: ToolchainDisposition::Upload,
                });
                wire.stream.offset = 0;
                assert!(wire.receive_until(&stopped, deadline).await.is_err());
                assert!(wire.send(&Message::Poll, &stopped, deadline).await.is_err());
                assert_eq!(wire.stream.reads.load(Ordering::Relaxed), reads);
                assert!(wire.stream.output.is_empty());
            }
        });
    }

    #[test]
    fn wire_refuses_duplicate_unknown_and_host_control_fields() {
        for bytes in [
            br#"{"kind":"poll","extra":1}"#.as_slice(),
            br#"{"kind":"queued","position":1}"#,
            br#"{"kind":"queued","kind":"ready"}"#,
            br#"{"kind":"ready"}"#,
            br#"{"kind":"ready","toolchain":"unknown"}"#,
            br#"{"kind":"ready","toolchain":"reuse","toolchain":"upload"}"#,
            br#"{"kind":"ready","toolchain":"reuse","toolchain_root":"/server/sdk"}"#,
            br#"{"kind":"window","count":1,"count":2}"#,
            br#"{"kind":"source-chunk","chunk":{"path":"x","offset":0,"sha256":"","bytes":"","source_root":"/"}}"#,
        ] {
            assert!(serde_json::from_slice::<Message>(bytes).is_err());
        }
        let settings = json!({"state_root":"/server/state"});
        assert!(serde_json::from_value::<RemoteOperationSettings>(settings).is_err());
    }

    #[test]
    fn ready_contract_carries_exact_upload_or_reuse_disposition() {
        for (spelling, expected) in [
            ("upload", ToolchainDisposition::Upload),
            ("reuse", ToolchainDisposition::Reuse),
        ] {
            let bytes = serde_json::to_vec(&json!({
                "kind": "ready", "toolchain": spelling
            }))
            .unwrap();
            let Message::Ready { toolchain } = serde_json::from_slice::<Message>(&bytes).unwrap()
            else {
                panic!("expected explicit SDK admission");
            };
            assert_eq!(toolchain, expected);
            assert_eq!(
                serde_json::to_value(Message::Ready { toolchain }).unwrap(),
                json!({"kind": "ready", "toolchain": spelling})
            );
        }
    }

    #[test]
    fn windows_refuse_overflow_duplicates_and_skipped_acknowledgments() {
        let mut window = Window::default();
        assert!(window.acknowledge(0).is_err());
        for index in 1..=WINDOW {
            assert_eq!(window.record().unwrap(), index == WINDOW);
        }
        assert!(window.record().is_err());
        assert!(window.acknowledge(WINDOW - 1).is_err());
        window.acknowledge(WINDOW).unwrap();
        assert!(window.acknowledge(WINDOW).is_err());
        assert!(!window.record().unwrap());
        window.acknowledge(WINDOW + 1).unwrap();
    }

    #[test]
    fn bytes_and_manifests_bind_exact_content_and_modes() {
        let bytes = b"binary\0\xff";
        let mut chunk = Chunk::new("artifact", 0, bytes).unwrap();
        assert_eq!(chunk.verified_bytes().unwrap().0, bytes);
        chunk.bytes.replace_range(0..2, "ff");
        assert!(chunk.verified_bytes().is_err());
        for invalid in ["f", "FF", "é", "00ff"] {
            assert!(decode_hex(invalid, 1).is_err());
        }
        let native = SourceManifest::new(vec![SourceFile {
            path: "bin/program".into(),
            len: bytes.len() as u64,
            sha256: Sha256::digest(bytes).into(),
            executable: true,
        }])
        .unwrap();
        let mut manifest = Manifest::from_native(&native);
        assert_eq!(manifest.native().unwrap(), native);
        manifest.files[0].executable = false;
        assert!(manifest.native().is_err());
    }
}
