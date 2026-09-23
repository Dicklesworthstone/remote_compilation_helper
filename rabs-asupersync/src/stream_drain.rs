//! Bounded stdout/stderr drain with spill objects (bead G007; risk R36).
//!
//! A build action's output is UNTRUSTED VOLUME: one chatty compiler (or a
//! misbehaving build script) can emit gigabytes, and capturing that into
//! memory exhausts the worker. The pre-G007 stopgap drained both pipes
//! concurrently (G006, no pipe-buffer deadlock) but accumulated the whole
//! stream in RAM. This module replaces that with a STRICT two-tier policy:
//!
//! - **Resident tier**: the FIRST [`DrainLimits::resident_bound`] bytes of
//!   each stream stay in memory. Heads carry the diagnostic gold — panics,
//!   `error[E...]:` blocks, warnings — so context extraction never needs
//!   the spill.
//! - **Spill tier**: every byte past the bound diverts, incrementally, to
//!   a file under [`DrainLimits::spill_dir`] (`stdout.spill` /
//!   `stderr.spill`). Spill writes stream straight from a fixed-size read
//!   buffer to disk: resident memory NEVER grows past the bound no matter
//!   the output volume, and the spilled archive is retrievable by path.
//!
//! ## Cancellation semantics (the R36 drain-during-cancellation rule)
//!
//! Drain lanes read until EOF, and EOF arrives only when EVERY writer
//! holding the pipes closes them — including orphaned group descendants.
//! Cancellation therefore cannot abandon mid-stream data: when the owning
//! policy tears the group down (TERM → escalate → KILL via
//! [`crate::process_groups::reap_residuals`]), the dying writers'
//! descriptors close, the pipes reach EOF, and the lanes complete having
//! captured everything written up to the kill. The composed entry point
//! [`crate::process_groups::ManagedProcessGroup::wait_with_bounded_drain`]
//! encodes exactly that ordering: lanes first, leader-exit observation,
//! residual closer (forces EOF for orphans BEFORE any lane join), lane
//! join, THEN the exit status — so a cancelled action still yields its
//! full pre-kill output, and an orphan-held pipe can no longer hang the
//! drain the way a plain `read-to-end + wait` would.
//!
//! Managed waits also enforce one aggregate capture budget and monitor lane
//! failures while the compiler is alive. Storage exhaustion, quota exhaustion,
//! or thread startup failure stops execution and returns an error after cleanup;
//! incomplete output is never represented by a successful `DrainedOutput`.
//! The standalone `spawn_lanes` primitive retains its caller-supervised contract.
//!
//! Safety posture: pure `std`, no `unsafe`, no allocation growth tied to
//! input volume (one fixed 64 KiB read buffer plus the bounded resident
//! vector per lane).

pub mod preview;

use preview::{LiveOutputPreview, PreviewStream};
use std::fs::File;
use std::io::{self, BufWriter, Read, Write};
use std::path::PathBuf;
use std::process::{Child, ExitStatus};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// Fixed-size read chunk: the ONLY heap traffic per lane beyond the
/// bounded resident vector. 64 KiB amortizes syscalls without approaching
/// any plausible resident bound from below.
const READ_CHUNK: usize = 64 * 1024;

/// Default aggregate stdout + stderr capture budget for managed execution.
/// This includes resident prefixes and spill tails, not just bytes on disk.
/// An exceeded budget fails the execution; it never produces truncated success.
pub const DEFAULT_MAX_CAPTURE_BYTES: u64 = 1024 * 1024 * 1024;

/// A capture failure observed while the process may still be running.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DrainFailure {
    /// The two output streams exhausted their shared byte allowance.
    OutputLimitExceeded {
        /// Aggregate maximum, including both resident and spilled bytes.
        maximum: u64,
    },
    /// A stream could not be read, retained, or assigned a drain thread.
    Io {
        /// The affected stream's fixed spill name.
        stream: &'static str,
        /// Original operating-system error classification.
        kind: io::ErrorKind,
        /// Original error description.
        detail: String,
    },
    /// A lane unwound before producing a complete capture.
    Panicked {
        /// The affected stream's fixed spill name.
        stream: &'static str,
    },
}

impl std::fmt::Display for DrainFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OutputLimitExceeded { maximum } => {
                write!(f, "combined stdout/stderr capture exceeds {maximum} bytes")
            }
            Self::Io { stream, detail, .. } => write!(f, "{stream} capture failed: {detail}"),
            Self::Panicked { stream } => write!(f, "{stream} drain panicked"),
        }
    }
}

impl std::error::Error for DrainFailure {}

impl DrainFailure {
    fn into_io(self) -> io::Error {
        let kind = match &self {
            Self::Io { kind, .. } => *kind,
            Self::OutputLimitExceeded { .. } => io::ErrorKind::InvalidData,
            Self::Panicked { .. } => io::ErrorKind::Other,
        };
        io::Error::new(kind, self)
    }
}

#[derive(Debug)]
struct DrainState {
    maximum: u64,
    remaining: AtomicU64,
    failed: AtomicBool,
    failure: Mutex<Option<DrainFailure>>,
    preview: Option<Arc<LiveOutputPreview>>,
}

/// Shared by exactly one pair of lanes. Reservations happen BEFORE retention,
/// so concurrently writing stderr cannot overspend stdout's disk allowance.
#[derive(Debug, Clone)]
struct DrainControl(Arc<DrainState>);

impl DrainControl {
    fn new(maximum: u64) -> Self {
        Self::with_preview(maximum, None)
    }

    fn with_preview(maximum: u64, preview: Option<Arc<LiveOutputPreview>>) -> Self {
        Self(Arc::new(DrainState {
            maximum,
            remaining: AtomicU64::new(maximum),
            failed: AtomicBool::new(false),
            failure: Mutex::new(None),
            preview,
        }))
    }

    fn failed(&self) -> bool {
        self.0.failed.load(Ordering::Acquire)
    }

    fn record(&self, failure: DrainFailure) {
        let mut first = self.0.failure.lock().unwrap_or_else(|error| error.into_inner());
        first.get_or_insert(failure);
        self.0.failed.store(true, Ordering::Release);
    }

    fn error(&self) -> Option<io::Error> {
        self.0.failure.lock().unwrap_or_else(|error| error.into_inner())
            .clone().map(DrainFailure::into_io)
    }

    fn reserve(&self, count: u64) -> io::Result<()> {
        if let Some(error) = self.error() {
            return Err(error);
        }
        if self.0.remaining.try_update(Ordering::AcqRel, Ordering::Acquire,
            |remaining| remaining.checked_sub(count)).is_err()
        {
            self.record(DrainFailure::OutputLimitExceeded { maximum: self.0.maximum });
        }
        // Another lane may have failed between our reservation and this check.
        // Failed captures do not refund capacity or produce reusable results.
        self.error().map_or(Ok(()), Err)
    }
}

/// Bounds for one bounded drain.
#[derive(Debug, Clone)]
pub struct DrainLimits {
    /// Maximum bytes kept resident PER STREAM. Bytes past this bound
    /// divert to spill files.
    pub resident_bound: usize,
    /// Directory receiving spill files. Created lazily on first overflow;
    /// per-attempt callers pass a fresh directory so retrieval names are
    /// deterministic (`stdout.spill`, `stderr.spill`).
    pub spill_dir: PathBuf,
}

impl DrainLimits {
    /// Limits with the default 1 MiB resident bound per stream.
    #[must_use]
    pub fn new(spill_dir: impl Into<PathBuf>) -> Self {
        Self {
            resident_bound: 1024 * 1024,
            spill_dir: spill_dir.into(),
        }
    }
}

/// Where one stream's overflow landed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpillReceipt {
    /// Spill archive path, constructed verbatim from
    /// [`DrainLimits::spill_dir`] joined with the stream name.
    pub path: PathBuf,
    /// Bytes written to the spill file (== total stream bytes minus the
    /// resident prefix).
    pub bytes: u64,
}

/// Final state of ONE drained stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaneDrain {
    /// Resident head bytes. `len() <= resident_bound` ALWAYS — the
    /// bounding invariant the gigabyte fixture asserts.
    resident: Vec<u8>,
    /// Present iff any byte overflowed the resident bound.
    spill: Option<SpillReceipt>,
    /// Total bytes seen on the stream (resident + spilled).
    total_bytes: u64,
}

impl LaneDrain {
    /// An empty lane (stream was not piped).
    #[must_use]
    pub fn empty() -> Self {
        Self {
            resident: Vec::new(),
            spill: None,
            total_bytes: 0,
        }
    }

    /// Resident head bytes (never past the bound).
    #[must_use]
    pub fn resident(&self) -> &[u8] {
        &self.resident
    }

    /// Spill receipt iff overflow occurred.
    #[must_use]
    pub fn spill(&self) -> Option<&SpillReceipt> {
        self.spill.as_ref()
    }

    /// Total bytes captured across both tiers.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// Bytes that overflowed into the spill archive (0 when none).
    #[must_use]
    pub fn spilled_bytes(&self) -> u64 {
        self.spill.as_ref().map_or(0, |s| s.bytes)
    }
}

/// Outcome of one bounded drain: both streams plus the leader's exit.
#[derive(Debug)]
pub struct DrainedOutput {
    /// Leader exit status (observed after leader exit; output completeness
    /// precedes status hand-back because lanes are joined first).
    pub status: ExitStatus,
    /// Captured stdout.
    pub stdout: LaneDrain,
    /// Captured stderr.
    pub stderr: LaneDrain,
    /// Live group members still present after the post-exit residual
    /// closer ran (forces EOF for orphans before lane join). 0 = clean;
    /// nonzero is an honest incident record.
    pub residual_group_members: u32,
}

/// Drain one stream lane to EOF under `limits`.
///
/// Runs on its own thread (one per stream): reads fixed chunks, extends
/// the resident vector only while under the bound, and streams everything
/// else straight to the spill file. Blocks until EOF — cancellation closes
/// writers (group teardown) which produces EOF, so the lane always
/// finishes.
fn drain_lane<R: Read>(
    reader: R,
    limits: DrainLimits,
    spill_name: &'static str,
) -> io::Result<LaneDrain> {
    drain_lane_inner(reader, limits, spill_name, None)
}

fn drain_lane_inner<R: Read>(
    mut reader: R,
    limits: DrainLimits,
    spill_name: &'static str,
    control: Option<&DrainControl>,
) -> io::Result<LaneDrain> {
    let mut chunk = vec![0u8; READ_CHUNK];
    let mut resident: Vec<u8> = Vec::new();
    let mut spill_writer: Option<(PathBuf, BufWriter<File>)> = None;
    let mut spilled_bytes: u64 = 0;
    let mut total: u64 = 0;

    loop {
        if let Some(error) = control.and_then(DrainControl::error) {
            return Err(error);
        }
        let n = match reader.read(&mut chunk) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if n == 0 {
            break; // EOF: every writer closed (possibly via group teardown)
        }
        if let Some(control) = control {
            control.reserve(n as u64)?;
        }
        total = total.checked_add(n as u64)
            .ok_or_else(|| io::Error::other("stream length overflow"))?;

        let remaining = limits.resident_bound.saturating_sub(resident.len());
        let keep = remaining.min(n);
        if keep > 0 {
            resident.extend_from_slice(&chunk[..keep]);
        }
        let overflow = &chunk[keep..n];
        if !overflow.is_empty() {
            let (_, writer) = match &mut spill_writer {
                Some(entry) => entry,
                None => {
                    std::fs::create_dir_all(&limits.spill_dir)?;
                    let path = limits.spill_dir.join(spill_name);
                    let mut options = std::fs::OpenOptions::new();
                    options.write(true).create_new(true);
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::OpenOptionsExt;
                        options.mode(0o600);
                    }
                    // Fresh archives only: neither a previous attempt's bytes
                    // nor a pre-planted symlink may be truncated by a new drain.
                    let file = options.open(&path)?;
                    spill_writer.insert((path, BufWriter::new(file)))
                }
            };
            writer.write_all(overflow)?;
            spilled_bytes += u64::try_from(overflow.len()).unwrap_or(u64::MAX);
        }
        // Observation follows successful retention and never controls capture.
        // The tail uses try_lock: even a stalled observer cannot backpressure a
        // pipe. Buffered spill bytes are not promised durable by a preview.
        if let Some(preview) = control.and_then(|control| control.0.preview.as_ref()) {
            let stream = match spill_name {
                "stdout.spill" => Some(PreviewStream::Stdout),
                "stderr.spill" => Some(PreviewStream::Stderr),
                _ => None,
            };
            if let Some(stream) = stream {
                preview.record(stream, total - n as u64, &chunk[..n]);
            }
        }
    }

    let spill = match spill_writer {
        None => None,
        Some((path, mut writer)) => {
            writer.flush()?;
            Some(SpillReceipt {
                path,
                bytes: spilled_bytes,
            })
        }
    };
    debug_assert_eq!(total, resident.len() as u64 + spilled_bytes);
    Ok(LaneDrain {
        resident,
        spill,
        total_bytes: total,
    })
}

/// One piped stream handed to a drain lane thread.
pub type LaneHandle = std::thread::JoinHandle<io::Result<LaneDrain>>;

type LaneJob = Box<dyn FnOnce() -> io::Result<LaneDrain> + Send>;

fn monitored_lane<R: Read>(
    reader: R,
    limits: DrainLimits,
    stream: &'static str,
    control: &DrainControl,
) -> io::Result<LaneDrain> {
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        drain_lane_inner(reader, limits, stream, Some(control))
    }));
    let result = match outcome {
        Ok(result) => result,
        Err(_) => Err(DrainFailure::Panicked { stream }.into_io()),
    };
    if let Err(error) = &result {
        let failure = error.get_ref().and_then(|inner| inner.downcast_ref::<DrainFailure>())
            .cloned().unwrap_or_else(|| DrainFailure::Io {
                stream, kind: error.kind(), detail: error.to_string(),
            });
        // Publish BEFORE the thread completes. The process owner can terminate
        // the compiler now, without waiting for its ordinary execution deadline.
        control.record(failure);
    }
    result
}

/// Drain ownership used by managed process supervision. Even a partial thread
/// startup returns this owner: the caller must stop the process before joining
/// every thread that did start. No fallible spawn path silently detaches a lane.
#[must_use = "stop the managed process and join its drain lanes before returning"]
pub(crate) struct MonitoredLanes {
    stdout: Option<LaneHandle>,
    stderr: Option<LaneHandle>,
    control: DrainControl,
}

impl MonitoredLanes {
    pub(crate) fn spawn(child: &mut Child, limits: &DrainLimits, maximum: u64) -> Self {
        Self::spawn_with(child, limits, maximum, |name, job| {
            std::thread::Builder::new().name(format!("rabs-g007-{name}"))
                .spawn(job)
        })
    }

    pub(crate) fn spawn_preview(
        child: &mut Child, limits: &DrainLimits, maximum: u64,
        preview: Arc<LiveOutputPreview>,
    ) -> Self {
        Self::spawn_with_preview(child, limits, maximum, Some(preview), |name, job| {
            std::thread::Builder::new().name(format!("rabs-g007-{name}")).spawn(job)
        })
    }

    fn spawn_with(
        child: &mut Child,
        limits: &DrainLimits,
        maximum: u64,
        spawn: impl FnMut(&'static str, LaneJob) -> io::Result<LaneHandle>,
    ) -> Self {
        Self::spawn_with_preview(child, limits, maximum, None, spawn)
    }

    fn spawn_with_preview(
        child: &mut Child,
        limits: &DrainLimits,
        maximum: u64,
        preview: Option<Arc<LiveOutputPreview>>,
        mut spawn: impl FnMut(&'static str, LaneJob) -> io::Result<LaneHandle>,
    ) -> Self {
        let control = match preview {
            Some(preview) => DrainControl::with_preview(maximum, Some(preview)),
            None => DrainControl::new(maximum),
        };
        let mut start = |reader: Box<dyn Read + Send>, name| {
            let lane_control = control.clone();
            let limits = limits.clone();
            let job: LaneJob = Box::new(move || {
                monitored_lane(reader, limits, name, &lane_control)
            });
            match spawn(name, job) {
                Ok(handle) => Some(handle),
                Err(error) => {
                    control.record(DrainFailure::Io {
                        stream: name, kind: error.kind(), detail: error.to_string(),
                    });
                    None
                }
            }
        };
        let stdout = child.stdout.take().and_then(|reader| start(Box::new(reader), "stdout.spill"));
        let stderr = child.stderr.take().and_then(|reader| start(Box::new(reader), "stderr.spill"));
        Self { stdout, stderr, control }
    }

    pub(crate) fn failed(&self) -> bool {
        self.control.failed()
    }

    /// Call only after process cleanup. Evaluate BOTH joins before propagating
    /// either error, and preserve the original failure rather than a sibling's
    /// resulting broken pipe. Unwind catching does not apply to panic=abort.
    pub(crate) fn join(self) -> io::Result<(LaneDrain, LaneDrain)> {
        let stdout = self.stdout.map_or_else(|| Ok(LaneDrain::empty()), join_lane);
        let stderr = self.stderr.map_or_else(|| Ok(LaneDrain::empty()), join_lane);
        if let Some(error) = self.control.error() {
            return Err(error);
        }
        Ok((stdout?, stderr?))
    }
}

/// Spawn the two lane threads for a child's piped streams.
///
/// Exposed separately from the composed wait so the cancellation path can
/// be exercised precisely: lanes start, THEN the group is torn down, THEN
/// lanes are joined — proving drains survive cancellation mid-stream.
///
/// Each lane gets an OWNED [`DrainLimits`] clone (threads require
/// `'static`; the struct is two small fields, cloning is trivial).
pub fn spawn_lanes(
    child: &mut Child,
    limits: &DrainLimits,
) -> (Option<LaneHandle>, Option<LaneHandle>) {
    let stdout_limits = limits.clone();
    let stdout_lane = child.stdout.take().map(|r| {
        std::thread::Builder::new()
            .name("rabs-g007-stdout-drain".into())
            .spawn(move || drain_lane(r, stdout_limits, "stdout.spill"))
            .expect("spawn stdout drain lane")
    });
    let stderr_limits = limits.clone();
    let stderr_lane = child.stderr.take().map(|r| {
        std::thread::Builder::new()
            .name("rabs-g007-stderr-drain".into())
            .spawn(move || drain_lane(r, stderr_limits, "stderr.spill"))
            .expect("spawn stderr drain lane")
    });
    (stdout_lane, stderr_lane)
}

/// Join one lane thread, mapping panic-poisoning into a typed error.
///
/// # Errors
/// Typed [`io::Error`] from the lane itself, or when the lane thread
/// panicked.
pub fn join_lane(lane: LaneHandle) -> io::Result<LaneDrain> {
    lane.join()
        .map_err(|_| io::Error::other("drain lane thread panicked"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};

    #[test]
    fn managed_budget_counts_both_resident_and_spilled_bytes() {
        let (_dir, limits) = temp_limits("budget", 1);
        let control = DrainControl::new(5);
        let out = monitored_lane(&b"abc"[..], limits.clone(), "stdout.spill", &control).unwrap();
        let err = monitored_lane(&b"de"[..], limits.clone(), "stderr.spill", &control).unwrap();
        assert_eq!(out.resident(), b"a");
        assert_eq!(err.resident(), b"d");
        assert_eq!(out.spilled_bytes() + err.spilled_bytes(), 3);
        assert_eq!(control.0.remaining.load(Ordering::Acquire), 0);
        assert!(!control.failed(), "exactly at the combined limit is valid");
        let failure = monitored_lane(&b"f"[..], limits, "extra.spill", &control).unwrap_err();
        assert!(matches!(failure.get_ref().and_then(|e| e.downcast_ref::<DrainFailure>()),
            Some(DrainFailure::OutputLimitExceeded { maximum: 5 })));
        assert!(control.failed());
    }

    #[test]
    fn managed_budget_is_atomic_across_concurrent_lanes_and_cannot_wrap() {
        let control = DrainControl::new(127);
        let barrier = Arc::new(std::sync::Barrier::new(8));
        let threads: Vec<_> = (0..8).map(|_| {
            let control = control.clone();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                let mut retained = 0;
                while control.reserve(1).is_ok() { retained += 1; }
                retained
            })
        }).collect();
        let retained: u64 = threads.into_iter().map(|thread| thread.join().unwrap()).sum();
        assert!(retained <= 127);
        assert_eq!(control.0.remaining.load(Ordering::Acquire), 0);
        assert!(control.failed());
        let limit = DrainControl::new(u64::MAX);
        limit.reserve(u64::MAX).unwrap();
        assert!(limit.reserve(1).is_err());
        assert_eq!(limit.0.remaining.load(Ordering::Acquire), 0);
    }

    #[test]
    fn zero_budget_accepts_empty_streams_but_not_one_byte() {
        let (_dir, limits) = temp_limits("zero", 64);
        let control = DrainControl::new(0);
        assert_eq!(monitored_lane(io::empty(), limits.clone(), "stdout.spill", &control).unwrap(), LaneDrain::empty());
        assert!(monitored_lane(&b"x"[..], limits, "stderr.spill", &control).is_err());
    }

    #[test]
    fn interrupted_reads_retry_without_losing_or_double_charging_bytes() {
        struct Interrupted<R> { reader: R, interrupt: bool }
        impl<R: Read> Read for Interrupted<R> {
            fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
                self.interrupt = !self.interrupt;
                if self.interrupt { Err(io::ErrorKind::Interrupted.into()) }
                else { self.reader.read(bytes) }
            }
        }
        let (_dir, limits) = temp_limits("interrupted", 2);
        let control = DrainControl::new(4);
        let lane = monitored_lane(Interrupted { reader: &b"a\0\xffb"[..], interrupt: false },
            limits, "stdout.spill", &control).unwrap();
        let mut captured = lane.resident().to_vec();
        captured.extend(std::fs::read(&lane.spill().unwrap().path).unwrap());
        assert_eq!(captured, b"a\0\xffb");
        assert_eq!(lane.total_bytes(), 4);
        assert!(!control.failed());
    }

    #[test]
    fn spill_failures_latch_before_join_and_never_truncate_prior_archives() {
        let (dir, limits) = temp_limits("existing", 0);
        std::fs::create_dir(&limits.spill_dir).unwrap();
        let path = limits.spill_dir.join("stdout.spill");
        std::fs::write(&path, b"prior-attempt").unwrap();
        let control = DrainControl::new(16);
        assert!(monitored_lane(&b"new"[..], limits, "stdout.spill", &control).is_err());
        assert!(control.failed());
        assert_eq!(std::fs::read(path).unwrap(), b"prior-attempt");
        let blocked = dir.path().join("not-a-directory");
        std::fs::write(&blocked, b"unchanged").unwrap();
        let limits = DrainLimits { resident_bound: 0, spill_dir: blocked.clone() };
        let control = DrainControl::new(16);
        assert!(monitored_lane(&b"x"[..], limits, "stderr.spill", &control).is_err());
        assert!(control.failed());
        assert_eq!(std::fs::read(blocked).unwrap(), b"unchanged");
    }

    #[cfg(panic = "unwind")]
    #[test]
    fn a_panicked_lane_is_visible_to_the_owner_before_join() {
        struct PanickingReader;
        impl Read for PanickingReader {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> { panic!("injected drain panic") }
        }
        let (_dir, limits) = temp_limits("panic", 64);
        let control = DrainControl::new(64);
        assert!(monitored_lane(PanickingReader, limits, "stdout.spill", &control).is_err());
        assert!(control.failed());
        assert!(matches!(control.error().unwrap().get_ref().and_then(|e| e.downcast_ref::<DrainFailure>()),
            Some(DrainFailure::Panicked { stream: "stdout.spill" })));
    }

    #[test]
    fn partial_lane_start_failure_keeps_and_joins_the_started_lane() {
        let (_dir, limits) = temp_limits("thread-start", 64);
        let mut child = Command::new("sh").args(["-c", "printf out; printf err >&2"])
            .stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        let joined = Arc::new(AtomicBool::new(false));
        let mut starts = 0;
        let lanes = MonitoredLanes::spawn_with(&mut child, &limits, 64, |_, job| {
            starts += 1;
            if starts == 2 { return Err(io::Error::other("injected thread exhaustion")); }
            let joined = Arc::clone(&joined);
            Ok(std::thread::spawn(move || {
                let result = job();
                joined.store(true, Ordering::Release);
                result
            }))
        });
        // The process owner must close writers before joining, even when only
        // one lane started. The tiny child itself needs no external resources.
        let _ = child.kill();
        child.wait().unwrap();
        assert!(lanes.failed());
        assert!(lanes.join().unwrap_err().to_string().contains("thread exhaustion"));
        assert!(joined.load(Ordering::Acquire), "started lane was detached");
    }

    fn temp_limits(tag: &str, bound: usize) -> (tempfile::TempDir, DrainLimits) {
        let dir = tempfile::tempdir().expect("tempdir");
        let spill_dir = dir.path().join(tag);
        (
            dir,
            DrainLimits {
                resident_bound: bound,
                spill_dir,
            },
        )
    }

    /// Deterministic pseudo-output line: index-encoded so content
    /// correctness is verifiable positionally (27 bytes each).
    fn line_for(i: usize) -> String {
        format!("line-{i:08}-abcdefghijklmnopqrst\n")
    }

    fn script_emitting(lines: usize) -> String {
        let mut script = String::from("set -e; ");
        for i in 0..lines {
            script.push_str(&format!("printf '%s\\n' '{}'; ", line_for(i).trim_end()));
        }
        script
    }

    fn drain_command(
        mut cmd: Command,
        limits: &DrainLimits,
    ) -> io::Result<(ExitStatus, LaneDrain, LaneDrain)> {
        let mut child = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let (out_lane, err_lane) = spawn_lanes(&mut child, limits);
        let status = child.wait()?;
        let stdout = out_lane.map_or_else(|| Ok(LaneDrain::empty()), join_lane)?;
        let stderr = err_lane.map_or_else(|| Ok(LaneDrain::empty()), join_lane)?;
        Ok((status, stdout, stderr))
    }

    #[test]
    fn g007_under_bound_output_stays_fully_resident_without_spill() {
        let (_dir, limits) = temp_limits("under", 1 << 20);
        let mut cmd = Command::new("sh");
        cmd.arg("-c")
            .arg("printf 'hello\\nworld\\n'; printf 'err\\n' >&2");
        let (status, stdout, stderr) = drain_command(cmd, &limits).expect("drain");
        assert!(status.success());
        assert_eq!(stdout.resident(), b"hello\nworld\n");
        assert_eq!(stdout.total_bytes(), 12);
        assert!(stdout.spill().is_none(), "no spill under bound");
        assert_eq!(stderr.resident(), b"err\n");
        assert!(stderr.spill().is_none());
    }

    #[test]
    fn g007_overflow_diverts_tail_to_retrievable_spill_archive() {
        // 100 deterministic lines; bound 500 => resident exactly 500,
        // spill = total - 500, concatenation reconstructs the stream.
        const LINES: usize = 100;
        let line_len = line_for(0).len() as u64;
        let (_dir, limits) = temp_limits("over", 500);
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg(script_emitting(LINES));
        let (status, stdout, _stderr) = drain_command(cmd, &limits).expect("drain");
        assert!(status.success());

        assert_eq!(
            stdout.resident().len(),
            500,
            "resident capped EXACTLY at the bound"
        );
        let total = line_len * LINES as u64;
        assert_eq!(stdout.total_bytes(), total);
        let spill = stdout.spill().expect("overflow produced a spill receipt");
        assert_eq!(spill.bytes, total - 500);
        assert_eq!(stdout.spilled_bytes(), total - 500);

        // RETRIEVABILITY: the archive exists at the reported path and its
        // contents concatenate with the resident head into the exact
        // original byte stream.
        let archived = std::fs::read(&spill.path).expect("spill archive readable");
        assert_eq!(archived.len() as u64, spill.bytes);
        let mut full = stdout.resident().to_vec();
        full.extend_from_slice(&archived);
        let mut expected = Vec::with_capacity(total as usize);
        for i in 0..LINES {
            expected.extend_from_slice(line_for(i).as_bytes());
        }
        assert_eq!(full, expected, "resident ++ spill reconstructs the stream");
    }

    #[test]
    fn g007_gigabyte_output_stays_bounded_and_spill_archive_is_complete() {
        // THE acceptance fixture (R36): ~1 GiB of output against a tiny
        // resident bound. Peak RESIDENT memory stays at the bound; the
        // spill archive accounts for every byte and round-trips.
        const TOTAL: u64 = 1024 * 1024 * 1024;
        const BOUND: usize = 64 * 1024;
        const FLOOD_LINE: &str = "0123456789abcdefghijklmnopqrstuvwxyz";
        let (_dir, limits) = temp_limits("gib", BOUND);

        let mut cmd = Command::new("sh");
        // `yes` floods, `head -c` stops the pipeline at exactly 1 GiB.
        cmd.arg("-c")
            .arg(format!("yes '{FLOOD_LINE}' | head -c {TOTAL}"));
        let (status, stdout, _stderr) = drain_command(cmd, &limits).expect("drain");
        assert!(status.success());

        assert_eq!(
            stdout.resident().len(),
            BOUND,
            "resident pinned at bound despite 1 GiB input"
        );
        assert_eq!(stdout.total_bytes(), TOTAL);
        let spill = stdout.spill().expect("gigabyte stream spilled");
        assert_eq!(spill.bytes, TOTAL - u64::from(BOUND as u32));

        // Archive integrity: size matches AND content is the verbatim
        // stream tail. The stream is periodic (line + newline), so the
        // archive byte at spill offset i must equal the pattern byte at
        // absolute stream offset BOUND + i — verified positionally for
        // the first 128 bytes.
        let archived_len = std::fs::metadata(&spill.path)
            .expect("spill metadata")
            .len();
        assert_eq!(archived_len, spill.bytes);
        let mut archived_head = vec![0u8; 128];
        let mut f = File::open(&spill.path).expect("spill reopenable");
        assert_eq!(f.read(&mut archived_head).unwrap_or(0), 128);
        let period = FLOOD_LINE.len() + 1; // + trailing newline from `yes`
        let pattern: Vec<u8> = FLOOD_LINE.bytes().chain(std::iter::once(b'\n')).collect();
        for (i, b) in archived_head.iter().enumerate() {
            let abs = BOUND + i;
            assert_eq!(
                *b,
                pattern[abs % period],
                "spill byte {i} matches the verbatim stream at offset {abs}"
            );
        }
    }

    #[test]
    fn g007_drain_completes_after_group_cancellation_midstream() {
        // An orphaned descendant holds the stdout pipe and keeps writing
        // after the leader would exit. Plain read-to-end would HANG here.
        // With managed groups: cancellation signals the whole GROUP (the
        // orphan included), writers die, EOF arrives, lanes complete
        // bounded.
        use std::os::unix::process::CommandExt;

        const BOUND: usize = 4096;
        let (_dir, limits) = temp_limits("cancel", BOUND);

        let mut cmd = Command::new("sh");
        // Leader backgrounds a flooder (same process GROUP via inherited
        // pgid), then sleeps; cancellation fires long before either ends.
        cmd.arg("-c")
            .arg("yes cancelled-flood-line-xxxxxxxxxxxxxxxx & sleep 30");
        cmd.process_group(0);
        let mut child = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("managed-style spawn");
        let pgid = child.id();

        let (out_lane, _err_lane) = spawn_lanes(&mut child, &limits);
        // Let the flood start, then cancel MID-STREAM like a coordinator
        // would: TERM the group, then run the escalating closer.
        std::thread::sleep(std::time::Duration::from_millis(250));
        let term_ok = Command::new("kill")
            .args(["-TERM", "--", &format!("-{pgid}")])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        assert!(term_ok, "group TERM delivered");
        let residual = crate::process_groups::reap_residuals(pgid);

        let status = child.wait().expect("leader reaped after cancellation");
        let stdout = out_lane
            .map_or_else(|| Ok(LaneDrain::empty()), join_lane)
            .expect("lane completes after cancellation-forced EOF");

        assert!(stdout.total_bytes() > 0, "pre-cancel output captured");
        assert!(
            stdout.resident().len() <= BOUND,
            "bounded despite ongoing flood at cancel time"
        );
        assert_eq!(residual, 0, "escalating closer resolved the group");
        assert!(
            !status.success(),
            "signalled leader reported honestly, not as success"
        );
    }
}
