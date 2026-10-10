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
//! 5. on pass-through, `exec` the real rustc — the wrapper process
//!    BECOMES the compiler, preserving exit codes, signals, and stdio.
//!    An accepted hit instead awaits installation and replays the
//!    transcript only after explicit compiler-skip authorization.
//!
//! Failure philosophy: before hit acceptance, wrapper-side problems —
//! no daemon, timeout, malformed reply, unreadable state file — degrade
//! to local exec. After acceptance, the daemon may own output writes:
//! uncertain delivery fails closed. Local exec resumes only after a
//! complete, typed reply on the install connection explicitly
//! confirms that the install writer has returned.

mod capture;
mod singleflight;
mod supervision;

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

/// Minimal JSON reader for daemon replies (no serde by design). Accepts
/// the complete grammar the daemon emits; anything else is `None`.
/// Before hit acceptance that permits normal compilation; afterward it
/// is uncertain delivery and must fail closed.
mod reply_json {
    #[derive(Debug, Clone, PartialEq)]
    pub enum Value {
        Null,
        Bool(bool),
        Number(String),
        Str(String),
        Array(Vec<Value>),
        Object(Vec<(String, Value)>),
    }

    impl Value {
        pub fn get(&self, key: &str) -> Option<&Value> {
            match self {
                Self::Object(fields) => {
                    // An ambiguous control field cannot authorize a compiler
                    // skip or fallback. Scan only the requested name, keeping
                    // lookup linear even for a large malformed object.
                    let mut matching = fields.iter().filter(|(name, _)| name == key);
                    let first = matching.next()?;
                    matching.next().is_none().then_some(&first.1)
                }
                _ => None,
            }
        }
        pub fn as_str(&self) -> Option<&str> {
            match self {
                Self::Str(text) => Some(text),
                _ => None,
            }
        }
        pub fn as_array(&self) -> Option<&[Value]> {
            match self {
                Self::Array(items) => Some(items),
                _ => None,
            }
        }
        pub fn as_bool(&self) -> Option<bool> {
            match self {
                Self::Bool(value) => Some(*value),
                _ => None,
            }
        }
    }

    const MAX_DEPTH: usize = 16;

    struct Parser<'a> {
        bytes: &'a [u8],
        at: usize,
    }

    impl Parser<'_> {
        fn skip_ws(&mut self) {
            while self
                .bytes
                .get(self.at)
                .is_some_and(|b| matches!(b, b' ' | b'\t' | b'\n' | b'\r'))
            {
                self.at += 1;
            }
        }
        fn eat(&mut self, byte: u8) -> Option<()> {
            self.skip_ws();
            (self.bytes.get(self.at) == Some(&byte)).then(|| self.at += 1)
        }
        fn literal(&mut self, text: &str, value: Value) -> Option<Value> {
            let end = self.at.checked_add(text.len())?;
            (self.bytes.get(self.at..end)? == text.as_bytes()).then(|| {
                self.at = end;
                value
            })
        }
        fn hex4(&mut self) -> Option<u32> {
            let end = self.at.checked_add(4)?;
            let bytes = self.bytes.get(self.at..end)?;
            if !bytes.iter().all(u8::is_ascii_hexdigit) {
                return None;
            }
            let digits = std::str::from_utf8(bytes).ok()?;
            self.at = end;
            u32::from_str_radix(digits, 16).ok()
        }
        fn string(&mut self) -> Option<String> {
            self.eat(b'"')?;
            let mut out = String::new();
            loop {
                let start = self.at;
                while self
                    .bytes
                    .get(self.at)
                    .is_some_and(|b| *b != b'"' && *b != b'\\' && *b >= 0x20)
                {
                    self.at += 1;
                }
                out.push_str(std::str::from_utf8(&self.bytes[start..self.at]).ok()?);
                match *self.bytes.get(self.at)? {
                    b'"' => {
                        self.at += 1;
                        return Some(out);
                    }
                    b'\\' => {
                        self.at += 1;
                        let escape = *self.bytes.get(self.at)?;
                        self.at += 1;
                        match escape {
                            b'"' => out.push('"'),
                            b'\\' => out.push('\\'),
                            b'/' => out.push('/'),
                            b'b' => out.push('\u{8}'),
                            b'f' => out.push('\u{c}'),
                            b'n' => out.push('\n'),
                            b'r' => out.push('\r'),
                            b't' => out.push('\t'),
                            b'u' => {
                                let high = self.hex4()?;
                                let code = if (0xD800..0xDC00).contains(&high) {
                                    if self.bytes.get(self.at..self.at + 2)? != b"\\u" {
                                        return None;
                                    }
                                    self.at += 2;
                                    let low = self.hex4()?;
                                    if !(0xDC00..0xE000).contains(&low) {
                                        return None;
                                    }
                                    0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00)
                                } else {
                                    high
                                };
                                out.push(char::from_u32(code)?);
                            }
                            _ => return None,
                        }
                    }
                    _ => return None,
                }
            }
        }
        fn decimal_digits(&mut self) -> Option<()> {
            let start = self.at;
            while self.bytes.get(self.at).is_some_and(u8::is_ascii_digit) {
                self.at += 1;
            }
            (self.at != start).then_some(())
        }

        fn number(&mut self) -> Option<Value> {
            let start = self.at;
            if self.bytes.get(self.at) == Some(&b'-') {
                self.at += 1;
            }
            match self.bytes.get(self.at).copied()? {
                b'0' => self.at += 1,
                b'1'..=b'9' => self.decimal_digits()?,
                _ => return None,
            }
            if self.bytes.get(self.at) == Some(&b'.') {
                self.at += 1;
                self.decimal_digits()?;
            }
            if matches!(self.bytes.get(self.at).copied(), Some(b'e' | b'E')) {
                self.at += 1;
                if matches!(self.bytes.get(self.at).copied(), Some(b'+' | b'-')) {
                    self.at += 1;
                }
                self.decimal_digits()?;
            }
            Some(Value::Number(
                std::str::from_utf8(&self.bytes[start..self.at])
                    .ok()?
                    .to_owned(),
            ))
        }

        fn value(&mut self, depth: usize) -> Option<Value> {
            if depth > MAX_DEPTH {
                return None;
            }
            self.skip_ws();
            match *self.bytes.get(self.at)? {
                b'"' => self.string().map(Value::Str),
                b'n' => self.literal("null", Value::Null),
                b't' => self.literal("true", Value::Bool(true)),
                b'f' => self.literal("false", Value::Bool(false)),
                b'[' => {
                    self.at += 1;
                    let mut items = Vec::new();
                    if self.eat(b']').is_some() {
                        return Some(Value::Array(items));
                    }
                    loop {
                        items.push(self.value(depth + 1)?);
                        if self.eat(b']').is_some() {
                            return Some(Value::Array(items));
                        }
                        self.eat(b',')?;
                    }
                }
                b'{' => {
                    self.at += 1;
                    let mut fields = Vec::new();
                    if self.eat(b'}').is_some() {
                        return Some(Value::Object(fields));
                    }
                    loop {
                        self.skip_ws();
                        let name = self.string()?;
                        self.eat(b':')?;
                        fields.push((name, self.value(depth + 1)?));
                        if self.eat(b'}').is_some() {
                            return Some(Value::Object(fields));
                        }
                        self.eat(b',')?;
                    }
                }
                b'-' | b'0'..=b'9' => self.number(),
                _ => None,
            }
        }
    }

    /// Parse one complete JSON document (surrounding whitespace allowed).
    pub fn parse(text: &str) -> Option<Value> {
        let mut parser = Parser {
            bytes: text.as_bytes(),
            at: 0,
        };
        let value = parser.value(0)?;
        parser.skip_ws();
        (parser.at == parser.bytes.len()).then_some(value)
    }
}

fn hex_decode(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) || !text.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    text.as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
        .collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0xf)]));
    }
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
    read_reply_bounded(reader, MAX_REPLY_BYTES)
}

fn read_reply_bounded(reader: &mut BufReader<ConsultStream>, max_bytes: u64) -> io::Result<String> {
    // Check even when BufReader already has bytes: a pipelined reply
    // cannot make an expired attempt healthy without another socket read.
    reader.get_ref().remaining()?;
    let mut reply = String::new();
    (&mut *reader).take(max_bytes + 1).read_line(&mut reply)?;
    if reply.len() as u64 > max_bytes {
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

/// Live dependency decisions may hash an unseen package or dependency
/// artifact on the request path; they get a larger (but still bounded)
/// decision budget than a shadow consult. `RABS_LIVE_DECISION_MS`
/// overrides it.
const LIVE_DECISION_TIMEOUT_MS: u32 = 2_000;
/// A served reply carries the transcript (hex): bounded far above any
/// capped-lint dependency transcript the daemon publishes.
const MAX_LIVE_REPLY_BYTES: u64 = 4 * 1024 * 1024;
/// Requests above this size fall back to a names-only shadow consult.
const MAX_REQUEST_BYTES: usize = 60 * 1024;
/// After accepting a hit, the wrapper has committed to NOT running the
/// compiler while the daemon may be installing. A daemon that neither
/// answers nor dies within this bound fails the compile (closed), because
/// running rustc over a possibly changing output tree is never safe.
/// `RABS_INSTALL_WAIT_MS` overrides it.
const INSTALL_WAIT: Duration = Duration::from_secs(600);

fn install_wait() -> Duration {
    std::env::var("RABS_INSTALL_WAIT_MS")
        .ok()
        .and_then(|value| value.parse().ok())
        .map_or(INSTALL_WAIT, Duration::from_millis)
}
/// Captured compiler output above this is not publishable; it is still
/// streamed to the caller unchanged.
const MAX_CAPTURE_BYTES: usize = 1024 * 1024;

/// What the wrapper does after consulting the daemon.
enum Live {
    /// Run the real compiler as if RABS were absent.
    PassThrough,
    /// Every declared output is installed and verified: replay stderr and
    /// exit 0 WITHOUT running the compiler.
    Served(Vec<u8>),
    /// Run the compiler as the admitted attempt with exactly `env`, then
    /// report completion on `session`.
    Execute {
        session: Box<BufReader<ConsultStream>>,
        attempt: String,
        env: Vec<(String, String)>,
    },
    /// An accepted hit whose install outcome is unknown: fail the compile.
    FailClosed(String),
}

fn live_decision_timeout_ms(breaker_budget_ms: u32) -> u32 {
    std::env::var("RABS_LIVE_DECISION_MS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(LIVE_DECISION_TIMEOUT_MS)
        .max(breaker_budget_ms)
}

/// The full live request, or `None` when it cannot be represented
/// exactly (non-UTF-8 environment) or exceeds the frame bound — such
/// requests stay names-only shadow consults.
fn live_request_frame(args: &[String], cwd: &str) -> Option<String> {
    let mut env = Vec::new();
    for (name, value) in std::env::vars_os() {
        let (Ok(name), Ok(value)) = (name.into_string(), value.into_string()) else {
            return None;
        };
        env.push(format!("[{},{}]", json_string(&name), json_string(&value)));
    }
    let argv_json: Vec<String> = args.iter().map(|a| json_string(a)).collect();
    let frame = format!(
        "{{\"kind\":\"rustc-request\",\"argv\":[{}],\"cwd\":{},\"env\":[{}],\"wait_for_inflight\":true}}",
        argv_json.join(","),
        json_string(cwd),
        env.join(","),
    );
    (frame.len() <= MAX_REQUEST_BYTES).then_some(frame)
}

/// Interpret a live decision. `Err(())` = the daemon failed us (breaker).
fn live_outcome(
    reply: &reply_json::Value,
    mut reader: BufReader<ConsultStream>,
) -> Result<Live, ()> {
    match reply.get("decision").and_then(reply_json::Value::as_str) {
        Some("pass-through") => Ok(Live::PassThrough),
        Some("execute") => {
            // An older daemon may publish after the wrapper exits. Do not
            // supply it an observed completion without a custody handshake.
            if !capture::supported(reply) {
                return Ok(Live::PassThrough);
            }
            let attempt = reply.get("attempt").and_then(reply_json::Value::as_str);
            let env = reply.get("env").and_then(reply_json::Value::as_array);
            let (Some(attempt), Some(env)) = (attempt, env) else {
                return Err(());
            };
            let env = env
                .iter()
                .map(|pair| match pair.as_array()? {
                    [name, value] => Some((name.as_str()?.to_owned(), value.as_str()?.to_owned())),
                    _ => None,
                })
                .collect::<Option<Vec<_>>>()
                .ok_or(())?;
            Ok(Live::Execute {
                session: Box::new(reader),
                attempt: attempt.to_owned(),
                env,
            })
        }
        Some("hit") => {
            // Decline before accepting output writes from an older daemon:
            // its publications belong to the pre-custody key namespace.
            if !capture::supported(reply) {
                return Ok(Live::PassThrough);
            }
            // Commit to waiting: from here on the daemon may write outputs,
            // so this process must not run the compiler unless a complete,
            // typed answer confirms that the install writer returned. Losing
            // a connection does not prove that its daemon or writer died.
            reader.get_mut().deadline = Instant::now() + install_wait();
            if reader
                .get_mut()
                .write_all(b"{\"kind\":\"rustc-accept\"}\n")
                .is_err()
            {
                return Ok(Live::FailClosed(
                    "the RABS cache-hit acceptance could not be confirmed".into(),
                ));
            }
            match read_reply_bounded(&mut reader, MAX_LIVE_REPLY_BYTES) {
                Ok(line) => Ok(accepted_install_reply(&line)),
                // A socket read timeout surfaces as WouldBlock (EAGAIN) on
                // Linux and TimedOut elsewhere; both mean "still alive, no
                // answer", which is never evidence that the writer returned.
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                    ) =>
                {
                    Ok(Live::FailClosed(
                        "the RABS daemon accepted a cache hit but did not finish installing it"
                            .into(),
                    ))
                }
                // EOF/reset, invalid UTF-8, oversized or truncated frames
                // are all uncertain delivery. A daemon's independently owned
                // writer may still be running after its connection closes.
                Err(error) => Ok(Live::FailClosed(format!(
                    "the RABS cache-hit install outcome is unknown: {error}"
                ))),
            }
        }
        _ => Err(()),
    }
}

/// Decode an answer after the wrapper accepted a hit. This deliberately
/// returns `Live`, never `Result`: malformed replies must not reach the breaker's
/// ordinary error path, which runs the compiler over an uncertain output tree.
fn accepted_install_reply(line: &str) -> Live {
    let Some(answer) = reply_json::parse(line) else {
        return Live::FailClosed("malformed install answer".into());
    };
    if answer.get("kind").and_then(reply_json::Value::as_str) != Some("rustc-decision") {
        return Live::FailClosed("unrecognized install answer kind".into());
    }
    match answer.get("decision").and_then(reply_json::Value::as_str) {
        Some("served")
            if answer
                .get("compiler_skip_authorized")
                .and_then(reply_json::Value::as_bool)
                == Some(true) =>
        {
            answer
                .get("stderr_hex")
                .and_then(reply_json::Value::as_str)
                .and_then(hex_decode)
                .map_or_else(
                    || Live::FailClosed("malformed served transcript".into()),
                    Live::Served,
                )
        }
        Some("serve-failed")
            if answer
                .get("writer_returned")
                .and_then(reply_json::Value::as_bool)
                == Some(true) =>
        {
            Live::PassThrough
        }
        _ => Live::FailClosed("unrecognized install answer".into()),
    }
}

/// One consult attempt under the breaker budgets. `Ok(_)` = a decision
/// was received (shadow decisions are always pass-through).
fn consult(
    socket: &str,
    connect_timeout_ms: u32,
    decision_timeout_ms: u32,
    args: &[String],
) -> Result<Live, ()> {
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
    let cwd = std::env::current_dir()
        .map_err(|_| ())?
        .into_os_string()
        .into_string()
        .map_err(|_| ())?;
    let live_frame = live_request_frame(args, &cwd);
    let may_wait = live_frame.is_some();
    let budget = Duration::from_millis(u64::from(if live_frame.is_some() {
        live_decision_timeout_ms(decision_timeout_ms)
    } else {
        decision_timeout_ms
    }));
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

    // Live request (full argv, cwd and environment, so the daemon can key
    // the exact action), or the names-only S4 shadow observation when the
    // request cannot be represented exactly.
    let frame = match live_frame {
        Some(frame) => frame,
        None => {
            let argv_json: Vec<String> = args.iter().map(|a| json_string(a)).collect();
            let env_names: Vec<String> = std::env::vars_os()
                .filter_map(|(name, _)| name.into_string().ok())
                .filter(|name| name.starts_with("CARGO") || name.starts_with("RUSTC"))
                .map(|name| json_string(&name))
                .collect();
            format!(
                "{{\"kind\":\"consult\",\"argv\":[{}],\"cwd\":{},\"env_names\":[{}]}}",
                argv_json.join(","),
                json_string(&cwd),
                env_names.join(","),
            )
        }
    };
    reader
        .get_mut()
        .write_all(frame.as_bytes())
        .map_err(|_| ())?;
    reader.get_mut().write_all(b"\n").map_err(|_| ())?;
    singleflight::read_decision(reader, &frame, budget, may_wait)
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

fn observe_with_breaker(socket: &str, path: &str, args: &[String]) -> Live {
    let policy = BreakerPolicy::default();
    // The breaker lock covers DECISIONS and RECORDS, not the consult. A
    // closed breaker admits concurrent consults: holding the lock across a
    // consult made every parallel compile of a `cargo -jN` build skip RABS
    // (observed live: ~40% of eligible compiles under -j4). Only the open
    // breaker's single probe keeps the lock for its whole window, which is
    // what makes "one probe per cooldown" exact.
    let (probe_guard, probing_state, connect_timeout_ms, decision_timeout_ms) = {
        let Some(guard) = try_lock_breaker(path) else {
            return Live::PassThrough;
        };
        let state = load_state(path);
        let now = now_ms();
        match decide(&policy, &state, now) {
            ConnectDecision::SkipToLocal => return Live::PassThrough,
            ConnectDecision::Attempt {
                connect_timeout_ms,
                decision_timeout_ms,
            } => (None, None, connect_timeout_ms, decision_timeout_ms),
            ConnectDecision::Probe {
                connect_timeout_ms,
                decision_timeout_ms,
            } => {
                // Do not probe unless the reservation was actually published.
                // Ignoring a write failure permits a storm of same-window probes.
                let probing = state.probe_started(now);
                if store_state(path, &probing).is_err() {
                    return Live::PassThrough;
                }
                (
                    Some(guard),
                    Some(probing),
                    connect_timeout_ms,
                    decision_timeout_ms,
                )
            }
        }
    };
    let outcome = consult(socket, connect_timeout_ms, decision_timeout_ms, args);
    let attempt = match &outcome {
        Ok(Live::FailClosed(_)) | Err(()) => AttemptOutcome::Failed,
        Ok(_) => AttemptOutcome::Succeeded,
    };
    match (probe_guard, probing_state) {
        (Some(_guard), Some(probing)) => {
            let _ = store_state(path, &on_outcome(&policy, &probing, attempt, now_ms()));
        }
        _ => {
            // Fold this outcome into the CURRENT record: concurrent attempts
            // each contribute (success resets, failures count). A contended
            // record is skipped — the breaker is advisory, never a queue.
            if let Some(_guard) = try_lock_breaker(path) {
                let current = load_state(path);
                let _ = store_state(path, &on_outcome(&policy, &current, attempt, now_ms()));
            }
        }
    }
    // No guard outlives this function: it is never a compiler-lifetime lock,
    // and contenders never block on its owner.
    outcome.unwrap_or(Live::PassThrough)
}

/// Copy a compiler stream to ours as bytes arrive (no buffering beyond
/// one read), capturing up to `MAX_CAPTURE_BYTES`. Returns the capture and
/// whether it overflowed.
fn tee(mut source: impl Read, mut sink: impl Write) -> (Vec<u8>, bool) {
    let mut captured = Vec::new();
    let mut overflow = false;
    let mut buffer = [0_u8; 8192];
    loop {
        let read = match source.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => {
                overflow = true;
                break;
            }
        };
        let _ = sink.write_all(&buffer[..read]).and_then(|()| sink.flush());
        if captured.len() + read <= MAX_CAPTURE_BYTES {
            captured.extend_from_slice(&buffer[..read]);
        } else {
            overflow = true;
        }
    }
    (captured, overflow)
}

/// Terminate exactly as the compiler did: its exit code, or its signal.
fn exit_like(status: std::process::ExitStatus) -> ! {
    use std::os::unix::process::ExitStatusExt;
    if let Some(code) = status.code() {
        std::process::exit(code);
    }
    if let Some(signal) = status.signal() {
        // Re-raise on ourselves (no unsafe, no extra dependency): the
        // parent then observes the compiler's signal, not an exit code.
        let _ = std::process::Command::new("kill")
            .args(["-s", &signal.to_string(), &std::process::id().to_string()])
            .status();
        std::process::exit(128 + signal);
    }
    std::process::exit(1);
}

/// Run the admitted compiler with exact environment and live streams, then
/// retain output custody until the daemon has captured immutable bytes.
/// Overflowed, abandoned or unacknowledged captures are never published;
/// cache-population failure does not change the compiler's actual status.
fn run_attempt(
    real_rustc: &OsStr,
    args: &[OsString],
    mut session: BufReader<ConsultStream>,
    attempt: &str,
    env: &[(String, String)],
    owner: supervision::Owner,
) -> ! {
    let mut child = match supervision::spawn(real_rustc, args, env, owner) {
        Ok(child) => child,
        Err(_) => {
            // No compiler started. Abandon admission and become the original
            // compiler, rather than leave an unsupervised observed child.
            drop(session);
            let error = std::process::Command::new(real_rustc).args(args).exec();
            eprintln!("rabs-wrap: exec {}: {error}", real_rustc.to_string_lossy());
            std::process::exit(127);
        }
    };
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let out = std::thread::spawn(move || match stdout {
        Some(pipe) => tee(pipe, io::stdout()),
        None => (Vec::new(), true),
    });
    let err = std::thread::spawn(move || match stderr {
        Some(pipe) => tee(pipe, io::stderr()),
        None => (Vec::new(), true),
    });
    let status = match child.wait() {
        Ok(status) => status,
        Err(error) => {
            eprintln!("rabs-wrap: wait for compiler: {error}");
            std::process::exit(1);
        }
    };
    let (stdout, out_overflow) = out.join().unwrap_or((Vec::new(), true));
    let (stderr, err_overflow) = err.join().unwrap_or((Vec::new(), true));
    if !out_overflow && !err_overflow {
        use std::os::unix::process::ExitStatusExt;
        let number =
            |value: Option<i32>| value.map_or_else(|| "null".to_owned(), |v| v.to_string());
        let frame = format!(
            "{{\"kind\":\"rustc-complete\",\"capture_protocol\":1,\"attempt\":{},\"exit_code\":{},\"signal\":{},\
             \"stdout_hex\":\"{}\",\"stderr_hex\":\"{}\"}}\n",
            json_string(attempt),
            number(status.code()),
            number(status.signal()),
            hex_encode(&stdout),
            hex_encode(&stderr),
        );
        // A report is not publication consent. Hold Cargo's output lifetime
        // until capture is acknowledged, using one bounded deadline. No ACK
        // means no publication, including a receipt arriving after timeout.
        let _ = capture::finish(&mut session, attempt, &frame, || {
            owner.can_acknowledge_capture()
        });
    }
    drop(session);
    exit_like(status);
}

fn main() {
    supervision::run_if_guard();
    let mut argv = std::env::args_os().skip(1);
    let Some(real_rustc) = argv.next() else {
        eprintln!("rabs-wrap: usage: rabs-wrap <real-rustc> <args…>");
        std::process::exit(2);
    };
    let args: Vec<OsString> = argv.collect();

    // Probes and unrepresentable argv: no state, no socket, no consult.
    if let Some(consult_argv) = shadow_argv(&real_rustc, &args) {
        let owner = supervision::Owner::capture();
        // The consult argv is the FULL command the compiler runs:
        // argv[0] is the real tool (the daemon stats it for the
        // toolchain-identity key component and records it as argv0),
        // followed by every rustc argument. Sending only the args would
        // leave the daemon statting `--crate-name` and mislabeling
        // receipts.
        match observe_with_breaker(&socket_path(), &breaker_path(), &consult_argv) {
            Live::PassThrough => {}
            Live::Served(stderr) => {
                // The daemon installed and verified every declared output;
                // this is the compiler's exact transcript for this out-dir.
                let mut sink = io::stderr();
                if sink.write_all(&stderr).and_then(|()| sink.flush()).is_err() {
                    std::process::exit(1);
                }
                std::process::exit(0);
            }
            Live::Execute {
                session,
                attempt,
                env,
            } => {
                if let Ok(owner) = owner {
                    run_attempt(&real_rustc, &args, *session, &attempt, &env, owner);
                }
                // No usable supervision evidence: drop the admission and exec
                // normally. Never claim to have supervised or published it.
            }
            Live::FailClosed(reason) => {
                eprintln!(
                    "rabs-wrap: {reason}; refusing to run rustc over a possibly changing output tree"
                );
                std::process::exit(1);
            }
        }
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

    #[test]
    fn accepted_install_reply_requires_unambiguous_completion_authority() {
        for line in [
            "",
            "{",
            r#"{"decision":"serve-failed","writer_returned":true}"#,
            r#"{"kind":"status","decision":"serve-failed","writer_returned":true}"#,
            r#"{"kind":"rustc-decision","decision":"serve-failed"}"#,
            r#"{"kind":"rustc-decision","decision":"serve-failed","writer_returned":false}"#,
            r#"{"kind":"rustc-decision","decision":"serve-failed","writer_returned":"true"}"#,
            r#"{"kind":"rustc-decision","decision":"serve-failed","writer_returned":true,"writer_returned":false}"#,
            r#"{"kind":"rustc-decision","decision":"served","compiler_skip_authorized":true}"#,
            r#"{"kind":"rustc-decision","decision":"served","compiler_skip_authorized":true,"stderr_hex":"zz"}"#,
            r#"{"kind":"rustc-decision","decision":"served","compiler_skip_authorized":true,"stderr_hex":"+a"}"#,
            r#"{"kind":"rustc-decision","decision":"served","compiler_skip_authorized":true,"stderr_hex":"\u+030a"}"#,
            r#"{"kind":"rustc-decision","decision":"served","compiler_skip_authorized":true,"compiler_skip_authorized":false,"stderr_hex":""}"#,
            r#"{"kind":"rustc-decision","kind":"status","decision":"serve-failed","writer_returned":true}"#,
            r#"{"kind":"rustc-decision","decision":"serve-failed","decision":"served","writer_returned":true}"#,
        ] {
            assert!(
                matches!(accepted_install_reply(line), Live::FailClosed(_)),
                "accepted reply cannot authorize execution: {line}"
            );
        }
        assert!(matches!(
            accepted_install_reply(
                r#"{"kind":"rustc-decision","decision":"serve-failed","writer_returned":true}"#,
            ),
            Live::PassThrough
        ));
        let served = accepted_install_reply(
            r#"{"kind":"rustc-decision","decision":"served","compiler_skip_authorized":true,"stderr_hex":"6f6b0a"}"#,
        );
        assert!(matches!(served, Live::Served(bytes) if bytes == b"ok\n"));
    }

    #[test]
    fn reply_json_numbers_follow_exact_grammar() {
        for number in [
            "0",
            "-0",
            "1",
            "-42",
            "0.0",
            "-0.25",
            "1e0",
            "1E+03",
            "-1.25e-9",
            "123456789012345678901234567890",
            "1e9999",
        ] {
            assert!(
                matches!(
                    reply_json::parse(number),
                    Some(reply_json::Value::Number(raw)) if raw == number
                ),
                "valid number must retain its exact spelling: {number}"
            );
        }
        for number in [
            "-", "+1", "01", "-01", ".5", "-.5", "1.", "1e", "1E+", "1e-", "--1", "1+2", "1e+-2",
            "1..2", "0x1", "NaN", "inf",
        ] {
            assert!(
                reply_json::parse(number).is_none(),
                "malformed number must be rejected: {number}"
            );
        }
    }

    #[test]
    fn reply_hex_fields_require_ascii_hex_digits() {
        assert_eq!(hex_decode(""), Some(Vec::new()));
        assert_eq!(hex_decode("0aFf"), Some(vec![0x0a, 0xff]));
        for text in ["+a", "+0", "-0", "0+", "0g", "a"] {
            assert!(
                hex_decode(text).is_none(),
                "malformed transcript hex must be rejected: {text}"
            );
        }
        assert_eq!(
            reply_json::parse(r#""\u0000\u0041\u00e9\uD83D\uDE80""#),
            Some(reply_json::Value::Str("\0Aé🚀".into()))
        );
        for text in [r#""\u+000""#, r#""\u000g""#, r#""\u000""#] {
            assert!(
                reply_json::parse(text).is_none(),
                "malformed Unicode escape must be rejected: {text}"
            );
        }
    }

    #[test]
    fn accepted_install_reply_requires_valid_ignored_json() {
        for ignored in [
            "-",
            "01",
            "1.",
            "1e",
            "1E+",
            "1+2",
            "[1e]",
            r#"{"nested":01}"#,
            r#""\u+000""#,
        ] {
            let returned = format!(
                r#"{{"kind":"rustc-decision","decision":"serve-failed","writer_returned":true,"ignored":{ignored}}}"#,
            );
            let served = format!(
                r#"{{"kind":"rustc-decision","decision":"served","compiler_skip_authorized":true,"stderr_hex":"6f6b0a","ignored":{ignored}}}"#,
            );
            for line in [returned, served] {
                assert!(
                    matches!(accepted_install_reply(&line), Live::FailClosed(_)),
                    "malformed ignored JSON cannot authorize execution: {line}"
                );
            }
        }
        for ignored in [
            "1e9999",
            r#"{"numbers":[-0,0.25,1E+03,-1.5e-2,123456789012345678901234567890]}"#,
            r#""\u0000\u0041\u00e9\uD83D\uDE80""#,
        ] {
            let returned = format!(
                r#"{{"kind":"rustc-decision","decision":"serve-failed","writer_returned":true,"ignored":{ignored}}}"#,
            );
            assert!(
                matches!(accepted_install_reply(&returned), Live::PassThrough),
                "valid ignored JSON must preserve explicit writer return: {ignored}"
            );
            let served = format!(
                r#"{{"kind":"rustc-decision","decision":"served","compiler_skip_authorized":true,"stderr_hex":"6f6b0a","ignored":{ignored}}}"#,
            );
            let replay = accepted_install_reply(&served);
            assert!(
                matches!(replay, Live::Served(bytes) if bytes == b"ok\n"),
                "valid ignored JSON must preserve authorized replay: {ignored}"
            );
        }
    }

    fn reply_from_peer(bytes: Vec<u8>) -> io::Result<String> {
        let (stream, mut peer) = UnixStream::pair().unwrap();
        peer.set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
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
        peer.set_write_timeout(Some(Duration::from_secs(1)))
            .unwrap();
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
    fn a_closed_breaker_consult_leaves_the_lock_to_parallel_wrappers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("breaker");
        let path_text = path.to_str().unwrap().to_owned();
        let socket = dir.path().join("edge.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        store_state(
            &path_text,
            &BreakerState::Closed {
                consecutive_failures: 2,
            },
        )
        .unwrap();
        let (entered, mid_consult) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel::<()>();
        let daemon = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            entered.send(()).unwrap();
            released.recv().unwrap();
            stream.write_all(b"{\"kind\":\"hello-ok\"}\n").unwrap();
            line.clear();
            reader.read_line(&mut line).unwrap();
            stream
                .write_all(
                    b"{\"kind\":\"decision\",\"decision\":\"pass-through\",\"mode\":\"shadow\"}\n",
                )
                .unwrap();
        });
        let socket_text = socket.to_str().unwrap().to_owned();
        let wrapper_path = path_text.clone();
        let wrapper = std::thread::spawn(move || {
            observe_with_breaker(&socket_text, &wrapper_path, &["/tc/bin/rustc".to_owned()])
        });
        mid_consult
            .recv_timeout(Duration::from_secs(5))
            .expect("consult started");
        // Another wrapper of the same `cargo -jN` build is not locked out.
        assert!(try_lock_breaker(&path_text).is_some());
        release.send(()).unwrap();
        assert!(matches!(wrapper.join().unwrap(), Live::PassThrough));
        daemon.join().unwrap();
        // The success was folded into the current record.
        assert_eq!(load_state(&path_text), BreakerState::fresh());
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
