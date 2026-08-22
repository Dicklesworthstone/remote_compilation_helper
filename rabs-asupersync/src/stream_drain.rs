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
//! Safety posture: pure `std`, no `unsafe`, no allocation growth tied to
//! input volume (one fixed 64 KiB read buffer plus the bounded resident
//! vector per lane).

use std::fs::File;
use std::io::{self, BufWriter, Read, Write};
use std::path::PathBuf;
use std::process::{Child, ExitStatus};

/// Fixed-size read chunk: the ONLY heap traffic per lane beyond the
/// bounded resident vector. 64 KiB amortizes syscalls without approaching
/// any plausible resident bound from below.
const READ_CHUNK: usize = 64 * 1024;

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
    mut reader: R,
    limits: DrainLimits,
    spill_name: &'static str,
) -> io::Result<LaneDrain> {
    let mut chunk = vec![0u8; READ_CHUNK];
    let mut resident: Vec<u8> = Vec::new();
    let mut spill_writer: Option<(PathBuf, BufWriter<File>)> = None;
    let mut spilled_bytes: u64 = 0;
    let mut total: u64 = 0;

    loop {
        let n = reader.read(&mut chunk)?;
        if n == 0 {
            break; // EOF: every writer closed (possibly via group teardown)
        }
        total += n as u64;

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
                    let file = File::create(&path)?;
                    spill_writer.insert((path, BufWriter::new(file)))
                }
            };
            writer.write_all(overflow)?;
            spilled_bytes += u64::try_from(overflow.len()).unwrap_or(u64::MAX);
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
