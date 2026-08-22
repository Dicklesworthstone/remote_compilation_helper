//! Worker-local jobserver reconstruction (bead G006; plan §189).
//!
//! Contract partner of `rabs-key/src/environment.rs`, which excludes
//! jobserver descriptors from semantic keys precisely because they are
//! "**reconstructed per host**". This module is that reconstruction:
//! when an action arrives carrying an edge/client jobserver (inherited
//! pipe fds referenced by `CARGO_MAKEFLAGS`), the worker replaces those
//! handles with its OWN jobserver instance, so parallelism is granted by
//! worker slots — never throttled by tokens minted on another host (and
//! never widened by a client pipe nobody feeds).
//!
//! Protocol (GNU make jobserver, the dialect cargo/make speak): one
//! pipe; N live tokens = N readable bytes; taking a token reads one
//! byte, releasing writes it back.
//!
//! # FD placement invariant
//!
//! Passing arbitrary fd *numbers* into a child requires `dup2`, which is
//! `unsafe` and therefore forbidden workspace-wide. The endpoints are
//! therefore handed to actions through the spawn configurator (e.g. as
//! stdin/stdout via `Stdio::from(pipe_end)`), or constructed early
//! enough that the kernel's lowest-available-fd allocation places them
//! at predictable low numbers. Either way,
//! [`WorkerJobserver::auth_fds`] reports what was actually allocated
//! and MUST be the source for any emitted environment — never hardcode.
//! A test proves real byte flow through the endpoints across an exec.
//!
//! Scope note: token *policy* (who may hold how many, hedging budgets)
//! lives with the scheduler; this module provides the mechanism only.

use std::io::{PipeReader, PipeWriter, Read, Write};
use std::os::fd::AsRawFd;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

/// Environment variable cargo consults for jobserver auth (GNU make
/// `MAKEFLAGS` dialect).
pub const CARGO_MAKEFLAGS_ENV: &str = "CARGO_MAKEFLAGS";

/// A live jobserver token. Release happens on `Drop` (byte write-back),
/// so a forgotten token cannot silently shrink the pool.
#[derive(Debug)]
pub struct JobserverToken<'a> {
    writer: &'a PipeWriter,
    /// The exact byte read (protocol: return what was taken).
    byte: u8,
}

impl JobserverToken<'_> {
    /// Explicit early release (equivalent to dropping).
    pub fn release(self) {}
}

impl std::ops::Drop for JobserverToken<'_> {
    fn drop(&mut self) {
        // Best effort: a failed write-back means the pool lost a token;
        // callers who care re-create the jobserver rather than limp.
        let _ = self.writer.write_all(std::slice::from_ref(&self.byte));
    }
}

/// Why an acquire failed.
#[derive(Debug)]
pub enum AcquireError {
    /// Pipe-level failure.
    Io(std::io::Error),
    /// No token within the budget; the in-flight read is parked in
    /// [`AcquireError::Timeout.0`] and its byte returns to the pool when
    /// satisfied (call [`parked_reclaim`] or drop the error after
    /// spawning your own drainer). A timed-out acquire never loses a
    /// token as long as the parked read is eventually reclaimed.
    Timeout(ParkedRead),
}

/// A still-pending token read whose result can be returned to the pool.
#[derive(Debug)]
pub struct ParkedRead {
    rx: mpsc::Receiver<std::io::Result<u8>>,
}

/// Wait out a parked read and write its byte back, restoring the pool.
pub fn parked_reclaim(parked: ParkedRead, mut writer: &PipeWriter) {
    if let Ok(Ok(byte)) = parked.rx.recv() {
        let _ = writer.write_all(std::slice::from_ref(&byte));
    }
}

/// Worker-owned jobserver instance (one per worker boot generation).
#[derive(Debug)]
pub struct WorkerJobserver {
    reader: PipeReader,
    writer: PipeWriter,
    /// Configured parallelism (tokens preloaded at construction).
    slots: usize,
}

impl WorkerJobserver {
    /// Create a jobserver with `slots` tokens available immediately.
    ///
    /// Construct EARLY in the worker lifecycle — see module docs for the
    /// fd-placement invariant.
    pub fn new(slots: usize) -> std::io::Result<Self> {
        assert!(slots > 0, "a zero-slot jobserver deadlocks every client");
        let (reader, mut writer) = std::io::pipe()?;
        // Preload the full budget: N readable bytes == N free slots.
        writer.write_all(&vec![b'|'; slots])?;
        Ok(Self {
            reader,
            writer,
            slots,
        })
    }

    /// Configured slot count.
    #[must_use]
    pub fn slots(&self) -> usize {
        self.slots
    }

    /// The `(read_fd, write_fd)` numbers actions must be told about.
    ///
    /// These are the ONLY numbers allowed in an emitted environment;
    /// hardcoding assumptions about them elsewhere is a bug.
    pub fn auth_fds(&self) -> (i32, i32) {
        (self.reader.as_raw_fd(), self.writer.as_raw_fd())
    }

    /// Read endpoint handle for spawn configuration (`Stdio::from`).
    pub fn reader_for_spawn(&self) -> std::io::Result<PipeReader> {
        self.reader.try_clone()
    }

    /// Write endpoint handle for spawn configuration (`Stdio::from`).
    pub fn writer_for_spawn(&self) -> std::io::Result<PipeWriter> {
        self.writer.try_clone()
    }

    /// `MAKEFLAGS`-dialect auth string for this instance.
    #[must_use]
    pub fn makeflags(&self) -> String {
        let (r, w) = self.auth_fds();
        format!("-j --jobserver-auth={r},{w}")
    }

    /// The `(key, value)` pair installing this jobserver into an action
    /// environment.
    #[must_use]
    pub fn env_pair(&self) -> (&'static str, String) {
        (CARGO_MAKEFLAGS_ENV, self.makeflags())
    }

    /// Take one token, waiting up to `timeout`.
    ///
    /// Direct consumers (child processes holding the fds) bypass this
    /// method entirely; it exists for in-process holders (tests, tools,
    /// coordinator accounting).
    pub fn acquire_timeout(&self, timeout: Duration) -> Result<JobserverToken<'_>, AcquireError> {
        let mut reader = match self.reader.try_clone() {
            Ok(r) => r,
            Err(e) => return Err(AcquireError::Io(e)),
        };
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let mut byte = [0u8; 1];
            let got = reader.read_exact(&mut byte).map(|_| byte[0]);
            let _ = tx.send(got);
        });
        match rx.recv_timeout(timeout) {
            Ok(Ok(byte)) => Ok(JobserverToken {
                writer: &self.writer,
                byte,
            }),
            Ok(Err(e)) => Err(AcquireError::Io(e)),
            Err(_) => Err(AcquireError::Timeout(ParkedRead { rx })),
        }
    }
}

/// The client jobserver found in an inherited action environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InheritedJobserver {
    /// Auth pipe read fd named by the client.
    pub read_fd: i32,
    /// Auth pipe write fd named by the client.
    pub write_fd: i32,
}

/// Parse jobserver auth out of a `MAKEFLAGS`-dialect string.
///
/// Understands modern `--jobserver-auth=R,W` and legacy
/// `--jobserver-fds=R,W`; ignores everything else (`-j`, `-l`,
/// subcommand flags).
#[must_use]
pub fn parse_makeflags(makeflags: &str) -> Option<InheritedJobserver> {
    for arg in makeflags.split_whitespace() {
        for prefix in ["--jobserver-auth=", "--jobserver-fds="] {
            if let Some(rest) = arg.strip_prefix(prefix) {
                let mut parts = rest.splitn(2, ',');
                let r = parts.next()?.parse().ok()?;
                let w = parts.next()?.parse().ok()?;
                return Some(InheritedJobserver {
                    read_fd: r,
                    write_fd: w,
                });
            }
        }
    }
    None
}

/// What a launch must change to honor "local jobserver handles replaced
/// with worker-local ones".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplacementPlan {
    /// Client auth fds to CLOSE before exec (they name pipes of another
    /// host/session — keeping them is a covert channel, cf.
    /// `rabs-sandbox::process_context` fd policy).
    pub close_fds: Vec<i32>,
    /// `(CARGO_MAKEFLAGS, value)` installing the worker-local auth.
    pub env: (String, String),
}

/// Build the replacement plan for one launch.
#[must_use]
pub fn replacement_plan(
    inherited: Option<InheritedJobserver>,
    worker: &WorkerJobserver,
) -> ReplacementPlan {
    let mut close_fds = Vec::new();
    if let Some(auth) = inherited {
        close_fds.push(auth.read_fd);
        close_fds.push(auth.write_fd);
    }
    let (k, v) = worker.env_pair();
    ReplacementPlan {
        close_fds,
        env: (k.to_owned(), v),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};

    #[test]
    fn tokens_are_bounded_by_slots() {
        let js = WorkerJobserver::new(2).expect("pipe");
        let t1 = js.acquire_timeout(Duration::from_secs(5)).expect("first");
        let t2 = js.acquire_timeout(Duration::from_secs(5)).expect("second");
        match js.acquire_timeout(Duration::from_millis(150)) {
            Err(AcquireError::Timeout(parked)) => {
                // Release a held token FIRST so the parked read has a byte
                // to consume, then drain the parked read and write its byte
                // back. Reclaiming while the pool is empty would deadlock:
                // the parked reader only wakes when a token is released.
                drop(t1);
                parked_reclaim(parked, &js.writer);
            }
            other => panic!("third acquire should time out, got {other:?}"),
        }
        let t3 = js
            .acquire_timeout(Duration::from_secs(5))
            .expect("after release");
        drop(t2);
        drop(t3);
    }

    #[test]
    fn makeflags_roundtrip_matches_real_fds() {
        let js = WorkerJobserver::new(3).expect("pipe");
        let parsed = parse_makeflags(&js.makeflags()).expect("parse own makeflags");
        assert_eq!(
            parsed,
            InheritedJobserver {
                read_fd: js.auth_fds().0,
                write_fd: js.auth_fds().1
            }
        );
        assert!(
            js.auth_fds().0 > 2 && js.auth_fds().1 > 2,
            "auth fds must not collide with stdio"
        );
    }

    #[test]
    fn parse_handles_legacy_and_modern_dialects() {
        let modern = parse_makeflags("-j --jobserver-auth=11,12 --subcommand-make");
        assert_eq!(
            modern,
            Some(InheritedJobserver {
                read_fd: 11,
                write_fd: 12
            })
        );
        let legacy = parse_makeflags("-j --jobserver-fds=7,8");
        assert_eq!(
            legacy,
            Some(InheritedJobserver {
                read_fd: 7,
                write_fd: 8
            })
        );
        assert_eq!(parse_makeflags("-j4 -l8"), None);
    }

    #[test]
    fn replacement_closes_client_and_installs_worker() {
        let js = WorkerJobserver::new(1).expect("pipe");
        let plan = replacement_plan(
            Some(InheritedJobserver {
                read_fd: 5,
                write_fd: 6,
            }),
            &js,
        );
        assert_eq!(plan.close_fds, vec![5, 6]);
        assert_eq!(plan.env.0, CARGO_MAKEFLAGS_ENV);
        let parsed = parse_makeflags(&plan.env.1).expect("worker env parses");
        assert_ne!((parsed.read_fd, parsed.write_fd), (5, 6));
        // No inherited handle → nothing to close, install only.
        let bare = replacement_plan(None, &js);
        assert!(bare.close_fds.is_empty());
    }

    #[test]
    fn child_consumes_token_through_real_endpoints() {
        // Acceptance-grade proof: a separate PROCESS takes a token by
        // reading the pipe endpoint handed to it and releases it through
        // the other endpoint — the exact byte flow the jobserver protocol
        // requires across an exec boundary.
        let js = WorkerJobserver::new(1).expect("pipe");

        let reader_clone = js.reader_for_spawn().expect("clone reader");
        let writer_clone = js.writer_for_spawn().expect("clone writer");

        // Child: consume one byte from stdin (the auth read end), then
        // echo one byte to stdout rewired onto the auth write end.
        let mut child = Command::new("sh")
            .arg("-c")
            .arg("dd bs=1 count=1 >/dev/null 2>&1; printf X")
            .stdin(Stdio::from(reader_clone))
            .stdout(Stdio::from(writer_clone))
            .spawn()
            .expect("spawn consumer");
        let status = child.wait().expect("wait consumer");
        assert!(status.success(), "token consumer failed");

        // The released token must be visible again: acquire succeeds
        // promptly instead of timing out.
        match js.acquire_timeout(Duration::from_secs(5)) {
            Ok(token) => token.release(),
            other => panic!("released token not observable after child exit: {other:?}"),
        }
    }
}
