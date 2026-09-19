//! `rabs-wrap` — the RABS tiny `RUSTC_WRAPPER` binary (bead S2 /
//! bridge plan Phase S).
//!
//! Invocation contract (Cargo): `rabs-wrap <real-rustc> <rustc args…>`.
//! The wrapper's whole job fits the p95 <10ms budget:
//!
//! 1. classify — version/target-info probes (`-vV`, `--crate-name ___`)
//!    exec the real chain instantly, zero consult;
//! 2. read the breaker-state file → `wrapper_breaker::decide` (the
//!    C-epic state machine, live);
//! 3. on `Attempt`/`Probe`: UDS connect + C001-shaped hello + consult
//!    frame under the breaker's OWN budgets (one decision deadline);
//!    shadow decisions are always pass-through;
//! 4. `on_outcome` update persisted (probe starts persisted WRITE-AHEAD
//!    per the breaker contract);
//! 5. `exec` the real rustc — the wrapper process BECOMES the compiler,
//!    so exit codes, signals, and stdio streaming are preserved by
//!    construction (no buffering exists to get wrong).
//!
//! Failure philosophy: every wrapper-side problem — no daemon, timeout,
//! malformed reply, unreadable state file — degrades to local exec.
//! A build must never fail because RABS had a bad day (fail-open).

use rabs_protocol::wrapper_breaker::{
    AttemptOutcome, BreakerPolicy, BreakerState, ConnectDecision, decide, decode_state,
    encode_state, on_outcome,
};
use std::ffi::{OsStr, OsString};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::time::{Duration, Instant};

/// Minimal JSON string encoder (quotes + escapes; no serde by design).
fn json_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn default_under_home(rel: &str) -> String {
    std::env::var("HOME").map_or_else(|_| format!("/tmp/{rel}"), |h| format!("{h}/{rel}"))
}

fn breaker_path() -> String {
    std::env::var("RABS_BREAKER_FILE")
        .unwrap_or_else(|_| default_under_home(".cache/rch/rabs-breaker"))
}

fn socket_path() -> String {
    std::env::var("RABS_SOCKET_PATH")
        .unwrap_or_else(|_| default_under_home(".cache/rch/rabsd.sock"))
}

/// Probes never consult: they are sub-millisecond cargo internals.
fn is_probe(args: &[OsString]) -> bool {
    args.iter().any(|a| a == "-vV" || a == "-V")
        || args
            .windows(2)
            .any(|w| w[0] == "--crate-name" && w[1] == "___")
}

/// Observation is optional; the original compiler invocation is not.
/// The shadow JSON protocol cannot represent arbitrary Unix argv bytes.
/// Do not panic or substitute replacement characters: skip observation
/// for such commands and exec the original OsStrings unchanged.
fn shadow_argv(real_rustc: &OsStr, args: &[OsString]) -> Option<Vec<String>> {
    if is_probe(args) {
        return None;
    }
    std::iter::once(real_rustc)
        .chain(args.iter().map(OsString::as_os_str))
        .map(|arg| arg.to_str().map(str::to_owned))
        .collect()
}

fn load_state(path: &str) -> BreakerState {
    // Missing/corrupt state fails OPEN to a fresh closed breaker (the
    // module contract: broken bookkeeping never blocks a build).
    // Every v1 record fits comfortably in 128 bytes. Do not read an
    // arbitrarily large corrupt state file into this tiny process.
    const MAX_STATE_BYTES: u64 = 128;
    let mut bytes = Vec::new();
    let result = std::fs::File::open(path)
        .and_then(|file| file.take(MAX_STATE_BYTES + 1).read_to_end(&mut bytes));
    if result.is_err() || bytes.len() as u64 > MAX_STATE_BYTES {
        return BreakerState::fresh();
    }
    decode_state(&bytes).unwrap_or_else(BreakerState::fresh)
}

/// The lock has a stable inode SEPARATE from the atomically replaced
/// state file. Never wait for another wrapper: contention and unavailable
/// locking both mean local passthrough, not a queue in front of rustc.
fn try_lock_breaker(path: &str) -> Option<std::fs::File> {
    if let Some(parent) = std::path::Path::new(path)
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent).ok()?;
    }
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(format!("{path}.lock"))
        .ok()?;
    lock.try_lock().ok()?;
    Some(lock)
}

/// Publish one complete record with atomic rename. The caller owns the
/// breaker lock through decision, optional probe write-ahead, and outcome.
/// This protects concurrent processes and process crashes; the breaker is
/// advisory cache state, not a power-loss-durable transaction journal.
fn store_state(path: &str, state: &BreakerState) -> io::Result<()> {
    if let Some(parent) = std::path::Path::new(path)
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let staged = format!("{path}.pending.{}.{nonce}", std::process::id());
    // create_new refuses collisions and symlinks rather than truncating
    // any existing file. A failed publication leaves the old record intact.
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&staged)?;
    file.write_all(encode_state(state).as_bytes())?;
    drop(file);
    std::fs::rename(staged, path)
}

const HELLO: &str = "{\"kind\":\"hello\",\
    \"transport\":{\"minimum_compatible\":1,\"current\":1},\
    \"application\":{\"minimum_compatible\":1,\"current\":1}}";

/// Shadow replies are metadata, never compiler output or artifact bytes.
/// Include the terminating newline in the bound; a peer must not be able
/// to grow the wrapper's allocation indefinitely before sending one.
const MAX_REPLY_BYTES: u64 = 64 * 1024;

/// A socket timeout is an idle timeout for ONE system call. A peer that
/// trickles bytes can therefore keep `read_line`/`write_all` alive forever
/// if each call gets the original budget. Both handshake and decision,
/// including partial writes, must spend the SAME monotonic deadline.
struct ConsultStream {
    stream: UnixStream,
    deadline: Instant,
}

impl ConsultStream {
    fn remaining(&self) -> io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "RABS consult deadline elapsed"))
    }
}

impl Read for ConsultStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(buf)
    }
}

impl Write for ConsultStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.remaining()?;
        self.stream.flush()
    }
}

fn read_reply(reader: &mut BufReader<ConsultStream>) -> io::Result<String> {
    // Check even when BufReader already has bytes: a pipelined reply
    // cannot make an expired attempt healthy without another socket read.
    reader.get_ref().remaining()?;
    let mut reply = String::new();
    (&mut *reader)
        .take(MAX_REPLY_BYTES + 1)
        .read_line(&mut reply)?;
    if reply.len() as u64 > MAX_REPLY_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "RABS reply exceeds frame limit",
        ));
    }
    if !reply.ends_with('\n') {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "RABS reply ended before frame delimiter",
        ));
    }
    reader.get_ref().remaining()?;
    Ok(reply)
}

/// One consult attempt under the breaker budgets. Ok(()) = decision
/// received (shadow: always pass-through).
fn consult(
    socket: &str,
    connect_timeout_ms: u32,
    decision_timeout_ms: u32,
    args: &[String],
) -> Result<(), ()> {
    // std UDS has no connect timeout: connect on a helper thread and
    // bound the wait. A short-lived process reaps stragglers at exit.
    let (sender, receiver) = std::sync::mpsc::channel();
    let socket_owned = socket.to_string();
    std::thread::Builder::new()
        .spawn(move || {
            let _ = sender.send(UnixStream::connect(socket_owned));
        })
        .map_err(|_| ())?;
    let stream = receiver
        .recv_timeout(Duration::from_millis(u64::from(connect_timeout_ms)))
        .map_err(|_| ())?
        .map_err(|_| ())?;
    let budget = Duration::from_millis(u64::from(decision_timeout_ms));
    let deadline = Instant::now().checked_add(budget).ok_or(())?;
    let mut reader = BufReader::new(ConsultStream { stream, deadline });

    reader
        .get_mut()
        .write_all(HELLO.as_bytes())
        .map_err(|_| ())?;
    reader.get_mut().write_all(b"\n").map_err(|_| ())?;
    let line = read_reply(&mut reader).map_err(|_| ())?;
    if !line.contains("hello-ok") {
        return Err(());
    }

    // The full S4 observation: real argv, cwd, CARGO_*/RUSTC_* env
    // NAMES (values never leave the process in shadow tier). The
    // daemon computes the Epic F key and redacts before persisting.
    let argv_json: Vec<String> = args.iter().map(|a| json_string(a)).collect();
    let env_names: Vec<String> = std::env::vars_os()
        .filter_map(|(name, _)| name.into_string().ok())
        .filter(|name| name.starts_with("CARGO") || name.starts_with("RUSTC"))
        .map(|name| json_string(&name))
        .collect();
    let cwd = std::env::current_dir()
        .map_err(|_| ())?
        .into_os_string()
        .into_string()
        .map_err(|_| ())?;
    let consult_frame = format!(
        "{{\"kind\":\"consult\",\"argv\":[{}],\"cwd\":{},\"env_names\":[{}]}}",
        argv_json.join(","),
        json_string(&cwd),
        env_names.join(","),
    );
    reader
        .get_mut()
        .write_all(consult_frame.as_bytes())
        .map_err(|_| ())?;
    reader.get_mut().write_all(b"\n").map_err(|_| ())?;
    let line = read_reply(&mut reader).map_err(|_| ())?;
    if consult_succeeded(&line) {
        Ok(())
    } else {
        Err(())
    }
}

/// Did the daemon actually answer this consult, or only admit that it
/// could not?
///
/// The breaker exists to notice a daemon that is not serving us. A
/// `decision` frame in `shadow-error` mode is the daemon reporting its
/// OWN failure — counting that as a healthy attempt keeps the breaker
/// closed against a daemon that is answering nothing useful, so the
/// wrapper pays the consult latency on every single rustc invocation for
/// as long as the fault lasts. It is a failed attempt.
///
/// Deliberately string-shaped, not serde: the wrapper's whole budget is
/// p95 <10 ms and it hand-rolls its JSON by design.
fn consult_succeeded(reply: &str) -> bool {
    if !reply.contains("\"kind\":\"decision\"") {
        return false; // refusal, garbage, or a truncated line
    }
    !reply.contains("\"mode\":\"shadow-error\"")
}

fn observe_with_breaker(socket: &str, path: &str, args: &[String]) {
    let Some(_guard) = try_lock_breaker(path) else {
        return;
    };
    let policy = BreakerPolicy::default();
    let state = load_state(path);
    let now = now_ms();
    let (state, connect_timeout_ms, decision_timeout_ms) = match decide(&policy, &state, now) {
        ConnectDecision::SkipToLocal => return,
        ConnectDecision::Attempt {
            connect_timeout_ms,
            decision_timeout_ms,
        } => (state, connect_timeout_ms, decision_timeout_ms),
        ConnectDecision::Probe {
            connect_timeout_ms,
            decision_timeout_ms,
        } => {
            // Do not probe unless the reservation was actually published.
            // Ignoring a write failure permits a storm of same-window probes.
            let probing = state.probe_started(now);
            if store_state(path, &probing).is_err() {
                return;
            }
            (probing, connect_timeout_ms, decision_timeout_ms)
        }
    };
    let outcome = consult(socket, connect_timeout_ms, decision_timeout_ms, args);
    let attempt = if outcome.is_ok() {
        AttemptOutcome::Succeeded
    } else {
        AttemptOutcome::Failed
    };
    let _ = store_state(path, &on_outcome(&policy, &state, attempt, now_ms()));
    // The guard drops BEFORE main execs the compiler. It is never a
    // compiler-lifetime lock, and contenders never block on its owner.
}

fn main() {
    let mut argv = std::env::args_os().skip(1);
    let Some(real_rustc) = argv.next() else {
        eprintln!("rabs-wrap: usage: rabs-wrap <real-rustc> <args…>");
        std::process::exit(2);
    };
    let args: Vec<OsString> = argv.collect();

    // Probes and unrepresentable argv: no state, no socket, no consult.
    if let Some(consult_argv) = shadow_argv(&real_rustc, &args) {
        // The consult argv is the FULL command the compiler runs:
        // argv[0] is the real tool (the daemon stats it for the
        // toolchain-identity key component and records it as argv0),
        // followed by every rustc argument. Sending only the args would
        // leave the daemon statting `--crate-name` and mislabeling
        // receipts.
        observe_with_breaker(&socket_path(), &breaker_path(), &consult_argv);
    }

    // Become the compiler. On success this never returns; exit codes,
    // signals, and stdio semantics are the real chain's, exactly.
    let error = std::process::Command::new(&real_rustc).args(&args).exec();
    eprintln!("rabs-wrap: exec {}: {error}", real_rustc.to_string_lossy());
    std::process::exit(127);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply_from_peer(bytes: Vec<u8>) -> io::Result<String> {
        let (stream, mut peer) = UnixStream::pair().unwrap();
        peer.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
        let sender = std::thread::spawn(move || {
            // An oversized/malformed reply may legitimately lose its reader.
            let _ = peer.write_all(&bytes);
        });
        let mut reader = BufReader::new(ConsultStream {
            stream,
            deadline: Instant::now() + Duration::from_secs(2),
        });
        let result = read_reply(&mut reader);
        drop(reader);
        sender.join().unwrap();
        result
    }

    #[test]
    fn reply_requires_a_complete_utf8_frame() {
        assert_eq!(reply_from_peer(b"{}\n".to_vec()).unwrap(), "{}\n");
        assert_eq!(reply_from_peer(b"{}\r\n".to_vec()).unwrap(), "{}\r\n");
        for bytes in [b"".as_slice(), b"{\"kind\":\"decision\"}"] {
            assert_eq!(
                reply_from_peer(bytes.to_vec()).unwrap_err().kind(),
                io::ErrorKind::UnexpectedEof
            );
        }
        assert_eq!(
            reply_from_peer(vec![0xff, b'\n']).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn reply_frame_limit_includes_the_newline() {
        let mut at_limit = vec![b'x'; MAX_REPLY_BYTES as usize - 1];
        at_limit.push(b'\n');
        assert_eq!(
            reply_from_peer(at_limit).unwrap().len() as u64,
            MAX_REPLY_BYTES
        );

        let mut oversized = vec![b'x'; MAX_REPLY_BYTES as usize];
        oversized.push(b'\n');
        assert_eq!(
            reply_from_peer(oversized).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        // An endless frame need not supply its delimiter to be refused.
        assert_eq!(
            reply_from_peer(vec![b'x'; MAX_REPLY_BYTES as usize + 1])
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn trickling_peer_cannot_renew_the_decision_deadline() {
        let (stream, mut peer) = UnixStream::pair().unwrap();
        peer.set_write_timeout(Some(Duration::from_secs(1))).unwrap();
        peer.write_all(b"{").unwrap();
        let sender = std::thread::spawn(move || {
            for _ in 0..100 {
                std::thread::sleep(Duration::from_millis(10));
                if peer.write_all(b" ").is_err() {
                    break;
                }
            }
        });
        let start = Instant::now();
        let mut reader = BufReader::new(ConsultStream {
            stream,
            deadline: start + Duration::from_millis(100),
        });
        let error = read_reply(&mut reader).unwrap_err();
        drop(reader);
        sender.join().unwrap();
        // Socket timeout errors differ between Unix platforms.
        assert!(matches!(
            error.kind(),
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
        ));
        // Without a shared deadline, this trickle ends in UnexpectedEof,
        // not timeout. Avoid mistaking host scheduling delay for a failure
        // of the deadline; release-profile tests own latency thresholds.
    }

    #[test]
    fn buffered_reply_cannot_bypass_an_expired_deadline() {
        let (stream, mut peer) = UnixStream::pair().unwrap();
        peer.write_all(b"first\nsecond\n").unwrap();
        let mut reader = BufReader::new(ConsultStream {
            stream,
            deadline: Instant::now() + Duration::from_secs(2),
        });
        assert_eq!(read_reply(&mut reader).unwrap(), "first\n");
        // Expire the SAME attempt between protocol stages, without a
        // timing-sensitive sleep. The next buffered frame must fail too.
        reader.get_mut().deadline = Instant::now();
        assert_eq!(
            read_reply(&mut reader).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }

    #[test]
    fn expired_deadline_prevents_a_new_write() {
        let (stream, mut peer) = UnixStream::pair().unwrap();
        let mut stream = ConsultStream {
            stream,
            deadline: Instant::now(),
        };
        assert_eq!(
            stream.write_all(b"consult\n").unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        peer.set_nonblocking(true).unwrap();
        assert_eq!(
            peer.read(&mut [0_u8; 1]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn probes_are_classified_and_never_consult() {
        let vv = vec!["-vV".into()];
        assert!(is_probe(&vv));
        let cap_v = vec!["-V".into()];
        assert!(is_probe(&cap_v));
        let target_info = vec![
            "--crate-name".into(),
            "___".into(),
            "--print=file-names".into(),
        ];
        assert!(is_probe(&target_info));
        let real = vec![
            "--crate-name".into(),
            "serde".into(),
            "--edition=2021".into(),
        ];
        assert!(!is_probe(&real));
    }

    #[test]
    fn shadow_argv_preserves_utf8_and_includes_the_real_compiler() {
        assert_eq!(
            shadow_argv(
                OsStr::new("/toolchain/rustc"),
                &["--crate-name".into(), "café".into(), "".into()]
            ),
            Some(vec![
                "/toolchain/rustc".to_string(),
                "--crate-name".to_string(),
                "café".to_string(),
                String::new()
            ])
        );
        assert!(shadow_argv(OsStr::new("rustc"), &["-vV".into()]).is_none());
    }

    #[test]
    fn non_utf8_argv_is_local_only_without_lossy_substitution() {
        use std::os::unix::ffi::OsStringExt;

        let raw = OsString::from_vec(b"source-\xff.rs".to_vec());
        assert!(shadow_argv(OsStr::new("rustc"), std::slice::from_ref(&raw)).is_none());
        assert!(shadow_argv(&raw, &["source.rs".into()]).is_none());
        assert_eq!(raw.into_vec(), b"source-\xff.rs".to_vec());
    }

    #[test]
    fn state_file_roundtrip_and_corrupt_fails_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("breaker");
        let path_str = path.to_str().unwrap();
        let _guard = try_lock_breaker(path_str).unwrap();
        // Missing: fresh closed.
        assert_eq!(load_state(path_str), BreakerState::fresh());
        // Roundtrip.
        let open = BreakerState::Open {
            opened_at_ms: 123,
            last_probe_started_at_ms: None,
        };
        store_state(path_str, &open).unwrap();
        assert_eq!(load_state(path_str), open);
        // Corrupt: fresh closed, never an error.
        std::fs::write(&path, b"\xff\xfe garbage").unwrap();
        assert_eq!(load_state(path_str), BreakerState::fresh());
    }

    #[test]
    fn breaker_lock_survives_state_replacement_and_releases_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("breaker");
        let path = path.to_str().unwrap();
        let guard = try_lock_breaker(path).unwrap();
        assert!(try_lock_breaker(path).is_none());

        let state = BreakerState::Open {
            opened_at_ms: 123,
            last_probe_started_at_ms: Some(456),
        };
        store_state(path, &state).unwrap();
        store_state(path, &BreakerState::fresh()).unwrap();
        assert_eq!(load_state(path), BreakerState::fresh());
        // Locking the state inode itself would lose exclusion on rename.
        assert!(try_lock_breaker(path).is_none());
        drop(guard);
        assert!(try_lock_breaker(path).is_some());
    }

    #[test]
    fn busy_breaker_skips_observation_without_touching_state_or_socket() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("breaker");
        let path = path.to_str().unwrap();
        let socket = dir.path().join("edge.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let _guard = try_lock_breaker(path).unwrap();
        let state = BreakerState::Closed {
            consecutive_failures: 2,
        };
        store_state(path, &state).unwrap();

        observe_with_breaker(socket.to_str().unwrap(), path, &[]);

        assert_eq!(load_state(path), state);
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn abandoned_probe_reservation_prevents_a_second_consult() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("breaker");
        let path = path.to_str().unwrap();
        let socket = dir.path().join("edge.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let now = now_ms();
        let policy = BreakerPolicy::default();
        let open = BreakerState::Open {
            opened_at_ms: now.saturating_sub(policy.cooldown_ms * 2),
            last_probe_started_at_ms: None,
        };
        assert!(matches!(
            decide(&policy, &open, now),
            ConnectDecision::Probe { .. }
        ));
        let probing = open.probe_started(now);
        {
            let _guard = try_lock_breaker(path).unwrap();
            store_state(path, &probing).unwrap();
            // No outcome publication: model an owner lost mid-consult.
        }

        observe_with_breaker(socket.to_str().unwrap(), path, &[]);

        assert_eq!(load_state(path), probing);
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn unavailable_breaker_lock_is_local_only() {
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("not-a-directory");
        std::fs::write(&parent, b"preserve me").unwrap();
        let path = parent.join("breaker");
        let socket = dir.path().join("edge.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();

        observe_with_breaker(socket.to_str().unwrap(), path.to_str().unwrap(), &[]);

        assert_eq!(std::fs::read(parent).unwrap(), b"preserve me");
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn oversized_breaker_state_fails_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("breaker");
        let path = path.to_str().unwrap();
        let _guard = try_lock_breaker(path).unwrap();
        std::fs::write(path, vec![b'x'; 4096]).unwrap();
        assert_eq!(load_state(path), BreakerState::fresh());
        store_state(path, &BreakerState::fresh()).unwrap();
        assert_eq!(load_state(path), BreakerState::fresh());
    }

    #[test]
    fn failed_state_publication_is_reported_without_replacing_destination() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("breaker");
        std::fs::create_dir(&path).unwrap();
        let marker = path.join("preserve");
        std::fs::write(&marker, b"existing data").unwrap();
        let path = path.to_str().unwrap();
        let _guard = try_lock_breaker(path).unwrap();

        assert!(store_state(path, &BreakerState::fresh()).is_err());
        assert_eq!(std::fs::read(marker).unwrap(), b"existing data");
    }

    #[test]
    fn a_daemon_reporting_its_own_failure_is_a_failed_attempt() {
        // A real answer.
        assert!(consult_succeeded(
            "{\"kind\":\"decision\",\"decision\":\"pass-through\",\"mode\":\"shadow\",\
             \"key\":\"ab\",\"hit_upper_bound\":false,\"class\":\"crate\",\"flight\":\"leader\"}"
        ));
        // Coord down but the edge still answering: the shadow plane did
        // its job, so the consult itself succeeded.
        assert!(consult_succeeded(
            "{\"kind\":\"decision\",\"decision\":\"pass-through\",\
             \"mode\":\"shadow-coord-degraded\"}"
        ));
        // The daemon admitting it could not decide — the breaker must
        // see this, or it never opens against a broken shadow plane.
        assert!(!consult_succeeded(
            "{\"kind\":\"decision\",\"decision\":\"pass-through\",\"mode\":\"shadow-error\"}"
        ));
        // Refusals and noise are failures.
        assert!(!consult_succeeded(
            "{\"kind\":\"refusal\",\"reason\":\"unknown-frame\",\"detail\":\"consult\"}"
        ));
        assert!(!consult_succeeded(""));
        assert!(!consult_succeeded("{\"kind\":\"hello-ok\"}"));
    }

    #[test]
    fn consult_against_nothing_fails_within_budget() {
        let start = std::time::Instant::now();
        let result = consult("/nonexistent/rabsd.sock", 25, 50, &[]);
        assert!(result.is_err());
        assert!(
            start.elapsed() < Duration::from_millis(200),
            "daemon-dead consult must fail fast: {:?}",
            start.elapsed()
        );
    }
}
