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
//!    transcript after explicit compiler-skip authorization. A negotiated
//!    metadata prefix can unblock Cargo before the remaining outputs finish.
//!
//! Failure philosophy: before hit acceptance, wrapper-side problems —
//! no daemon, timeout, malformed reply, unreadable state file — degrade
//! to local exec. After acceptance, the daemon may own output writes:
//! uncertain delivery fails closed. Local exec resumes only after a
//! complete, typed reply on the install connection explicitly
//! confirms that the install writer has returned, and only before any
//! metadata transcript exposure. A lost original caller
//! is cancellation, not a cache failure: it never authorizes local fallback,
//! a new compiler attempt, or acceptance of a cache installation.

mod capture;
mod metadata;
mod remote;
mod singleflight;
mod supervision;

use rabs_protocol::wrapper_breaker::{
    AttemptOutcome, BreakerPolicy, BreakerState, ConnectDecision, decide, decode_state,
    encode_state, on_outcome,
};
use std::ffi::{OsStr, OsString};
#[cfg(test)]
use std::io::BufRead;
use std::io::{self, BufReader, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
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

/// Bind the executable selected by this caller's PATH, without resolving
/// symlinks (rustup dispatches on their spelling). A later admitted environment
/// must not choose a different executable. Unknown lookup errors stay local.
fn compiler_for_observation(
    compiler: &OsStr,
    search: Option<&OsStr>,
    cwd: &Path,
) -> Option<PathBuf> {
    use rustix::fs::{Access, AtFlags, CWD, accessat};

    let program = Path::new(compiler);
    if program.is_absolute() {
        return Some(program.to_owned());
    }
    if compiler.is_empty() || !cwd.is_absolute() {
        return None;
    }
    let executable = |path: &Path| -> io::Result<bool> {
        let metadata = match std::fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound
                        | io::ErrorKind::NotADirectory
                        | io::ErrorKind::PermissionDenied
                ) =>
            {
                return Ok(false);
            }
            Err(error) => return Err(error),
        };
        if !metadata.is_file() {
            return Ok(false);
        }
        match accessat(CWD, path, Access::EXEC_OK, AtFlags::EACCESS) {
            Ok(()) => Ok(true),
            Err(error) => {
                let error = io::Error::from(error);
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound
                        | io::ErrorKind::NotADirectory
                        | io::ErrorKind::PermissionDenied
                ) {
                    Ok(false)
                } else {
                    Err(error)
                }
            }
        }
    };
    if compiler.as_bytes().contains(&b'/') {
        let path = cwd.join(program);
        return executable(&path).ok()?.then_some(path);
    }
    // An absent PATH has platform-specific exec defaults. Preserve the
    // original direct exec instead of inventing an executable search policy.
    for directory in std::env::split_paths(search?) {
        let path = cwd.join(directory).join(program);
        if executable(&path).ok()? {
            return Some(path);
        }
    }
    None
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
    for attempt in 0..20 {
        if lock.try_lock().is_ok() {
            return Some(lock);
        }
        if attempt < 19 {
            std::thread::sleep(Duration::from_micros(100));
        }
    }
    None
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

/// An unwind must not turn accepted work into an unrelated compiler retry.
/// This fence belongs to the whole wrapper invocation, including reconnects
/// and breaker bookkeeping after a response. Once set, it never reopens.
/// Explicit, successfully parsed writer-return/settlement replies retain their
/// existing normal fallback path; an unexpected panic gains no such authority.
#[derive(Clone, Default)]
struct PanicFence {
    state: Arc<AtomicU8>,
}

impl PanicFence {
    const RETRY_FORBIDDEN: u8 = 1;
    const PANIC_RECORDED: u8 = 2;

    fn forbid_retry(&self) {
        self.state.fetch_or(Self::RETRY_FORBIDDEN, Ordering::SeqCst);
    }

    fn install_recording_hook(&self) {
        let state = Arc::clone(&self.state);
        // The hook also covers relay threads. Recording one bounded fact
        // requires no allocation, lock or Cargo-visible write during a panic.
        // A failed relay still disconnects its completion channel normally.
        std::panic::set_hook(Box::new(move |_| {
            state.fetch_or(Self::PANIC_RECORDED, Ordering::SeqCst);
        }));
    }

    fn permits_panic_retry(&self) -> bool {
        self.state.load(Ordering::SeqCst) == Self::PANIC_RECORDED
    }
}

// Fault injection exists only in the Rust test executable. Shipping wrappers
// do not recognize a fault environment or expose an injection command.
#[cfg(test)]
std::thread_local! {
    static PANIC_FIXTURE_SITE: std::cell::Cell<Option<&'static str>> = const { std::cell::Cell::new(None) };
    static PANIC_FIXTURE_CALLER_LOST: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
fn panic_fixture_selected(site: &str) -> bool {
    PANIC_FIXTURE_SITE.with(|selected| selected.get() == Some(site))
}

#[cfg(test)]
fn inject_panic_fixture(site: &str) -> ! {
    let marker = std::env::var_os("RABS_PANIC_FAULT_MARKER").expect("fault marker configured");
    std::fs::write(marker, site).expect("fault site recorded");
    panic!("explicit wrapper panic fixture at {site}");
}

#[cfg(test)]
fn panic_fixture(site: &str) {
    if site == "before-consult" && panic_fixture_selected("caller-lost") {
        // This is an explicit lost-caller oracle, not evidence of real procfs
        // identity support on the host executing the regression.
        PANIC_FIXTURE_CALLER_LOST.set(true);
        inject_panic_fixture("caller-lost");
    }
    if panic_fixture_selected(site) {
        inject_panic_fixture(site);
    }
}

/// A socket timeout is an idle timeout for ONE system call. A peer that
/// trickles bytes can therefore keep `read_line`/`write_all` alive forever
/// if each call gets the original budget. Both handshake and decision,
/// including partial writes, must spend the SAME monotonic deadline.
struct ConsultStream {
    stream: UnixStream,
    deadline: Instant,
    panic_fence: PanicFence,
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

#[cfg(test)]
fn read_reply(reader: &mut BufReader<ConsultStream>) -> io::Result<String> {
    read_reply_bounded(reader, MAX_REPLY_BYTES)
}

#[cfg(test)]
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
const LIVE_DECISION_TIMEOUT_MS: u32 = 15_000;
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
    /// An accepted hit with an unknown outcome, or a cancelled caller.
    FailClosed(String),
    /// Metadata may have reached Cargo, or its stderr writer may still be
    /// blocked. Exit without another stderr write or any compiler fallback.
    FailClosedSilently,
}

fn live_decision_timeout_ms(breaker_budget_ms: u32) -> u32 {
    std::env::var("RABS_LIVE_DECISION_MS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(LIVE_DECISION_TIMEOUT_MS)
        .max(breaker_budget_ms)
}

/// Unsupported supervision keeps its existing pass-through behavior. Once a
/// caller was captured, however, losing that exact birth identity is terminal.
/// Never recapture a reparented wrapper as a new, apparently healthy request.
fn caller_still_owned(owner: Option<supervision::Owner>) -> bool {
    #[cfg(test)]
    if PANIC_FIXTURE_CALLER_LOST.get() {
        return false;
    }
    owner.is_none_or(supervision::Owner::can_acknowledge_capture)
}

fn stop_if_caller_lost(owner: Option<supervision::Owner>) {
    if !caller_still_owned(owner) {
        eprintln!("rabs-wrap: original compiler caller disappeared; refusing further work");
        std::process::exit(1);
    }
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
        "{{\"kind\":\"rustc-request\",\"argv\":[{}],\"cwd\":{},\"env\":[{}],\"wait_for_inflight\":true,\"remote_protocol\":1,\"metadata_protocol\":1}}",
        argv_json.join(","),
        json_string(cwd),
        env.join(","),
    );
    (frame.len() <= MAX_REQUEST_BYTES).then_some(frame)
}

/// Interpret a live decision. `Err(())` = the daemon failed us (breaker).
fn live_outcome(
    reply: &reply_json::Value,
    reader: BufReader<ConsultStream>,
    owned: &impl Fn() -> bool,
) -> Result<Live, ()> {
    if !owned() {
        return Ok(Live::FailClosed(
            "original compiler caller disappeared".into(),
        ));
    }
    #[cfg(test)]
    panic_fixture("before-decision");
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
            reader.get_ref().panic_fence.forbid_retry();
            #[cfg(test)]
            panic_fixture("local-execute-grant");
            Ok(Live::Execute {
                session: Box::new(reader),
                attempt: attempt.to_owned(),
                env,
            })
        }
        Some("remote") => remote::outcome(reply, reader, owned),
        Some("hit") => {
            // Decline before accepting output writes from an older daemon:
            // its publications belong to the pre-custody key namespace.
            if !capture::supported(reply) {
                return Ok(Live::PassThrough);
            }
            metadata::outcome(reply, reader, owned)
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
                == Some(true)
                && metadata::exposure_flag(&answer) == Some(false) =>
        {
            Live::PassThrough
        }
        _ => Live::FailClosed("unrecognized install answer".into()),
    }
}

/// Establish a bounded socket connection. The helper thread has no authority
/// to send protocol frames or accept an installation.
fn connect_owned(
    socket: &str,
    timeout: Duration,
    owned: &impl Fn() -> bool,
) -> io::Result<UnixStream> {
    if !owned() {
        return Err(io::Error::other("original compiler caller disappeared"));
    }
    let (sender, receiver) = std::sync::mpsc::channel();
    let socket_owned = socket.to_owned();
    std::thread::Builder::new().spawn(move || {
        let _ = sender.send(UnixStream::connect(socket_owned));
    })?;
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| io::Error::other("RABS connect deadline overflow"))?;
    loop {
        if !owned() {
            return Err(io::Error::other("original compiler caller disappeared"));
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "RABS connect deadline"))?;
        match receiver.recv_timeout(remaining.min(Duration::from_millis(100))) {
            Ok(result) => return result,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "RABS connect worker stopped",
                ));
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
        }
    }
}

/// One consult attempt under the breaker budgets. `Ok(_)` = a decision
/// was received (shadow decisions are always pass-through).
fn consult(
    socket: &str,
    connect_timeout_ms: u32,
    decision_timeout_ms: u32,
    args: &[String],
    owned: &impl Fn() -> bool,
    panic_fence: &PanicFence,
) -> Result<Live, ()> {
    if !owned() {
        return Err(());
    }
    let stream = connect_owned(
        socket,
        Duration::from_millis(u64::from(connect_timeout_ms)),
        owned,
    )
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
    let mut reader = BufReader::new(ConsultStream {
        stream,
        deadline,
        panic_fence: panic_fence.clone(),
    });

    singleflight::write_owned(&mut reader, HELLO.as_bytes(), deadline, owned).map_err(|_| ())?;
    singleflight::write_owned(&mut reader, b"\n", deadline, owned).map_err(|_| ())?;
    let line = singleflight::read_owned_reply(&mut reader, MAX_REPLY_BYTES, deadline, owned)
        .map_err(|_| ())?;
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
    singleflight::write_owned(&mut reader, frame.as_bytes(), deadline, owned).map_err(|_| ())?;
    singleflight::write_owned(&mut reader, b"\n", deadline, owned).map_err(|_| ())?;
    singleflight::read_decision(
        reader,
        &frame,
        budget,
        may_wait,
        socket,
        Duration::from_millis(u64::from(connect_timeout_ms)),
        owned,
    )
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

/// Opt-in diagnostics for observations that never reached a cache action.
/// Keep the original compiler environment intact, including the trace knob.
fn trace_bypass(reason: &str, args: &[String]) {
    if std::env::var_os("RABS_WRAP_TRACE").as_deref() != Some(std::ffi::OsStr::new("1")) {
        return;
    }
    let unit = args
        .windows(2)
        .find(|pair| pair[0] == "--crate-name")
        .map_or("?", |pair| pair[1].as_str());
    let unit: String = unit.chars().take(80).collect();
    eprintln!("rabs-wrap: observation bypass: {reason}; crate={unit:?}");
}

fn observe_with_breaker(
    socket: &str,
    path: &str,
    args: &[String],
    owner: Option<supervision::Owner>,
    panic_fence: &PanicFence,
) -> Live {
    let owned = || caller_still_owned(owner);
    if !owned() {
        return Live::FailClosed("original compiler caller disappeared".into());
    }
    let policy = BreakerPolicy::default();
    // The breaker lock covers DECISIONS and RECORDS, not the consult. A
    // closed breaker admits concurrent consults: holding the lock across a
    // consult made every parallel compile of a `cargo -jN` build skip RABS
    // (observed live: ~40% of eligible compiles under -j4). Only the open
    // breaker's single probe keeps the lock for its whole window, which is
    // what makes "one probe per cooldown" exact.
    let (probe_guard, probing_state, connect_timeout_ms, decision_timeout_ms) = {
        let Some(guard) = try_lock_breaker(path) else {
            trace_bypass("breaker-lock-busy", args);
            return Live::PassThrough;
        };
        let state = load_state(path);
        let now = now_ms();
        match decide(&policy, &state, now) {
            ConnectDecision::SkipToLocal => {
                trace_bypass("breaker-open", args);
                return Live::PassThrough;
            }
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
                    trace_bypass("probe-reservation-write-failed", args);
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
    let outcome = consult(
        socket,
        connect_timeout_ms,
        decision_timeout_ms,
        args,
        &owned,
        panic_fence,
    );
    #[cfg(test)]
    panic_fixture("after-consult");
    // A metadata writer can still be blocked on Cargo's stderr pipe. Neither
    // cancellation reporting nor breaker bookkeeping may turn this into a
    // fresh stderr write or a compiler retry.
    if matches!(outcome, Ok(Live::FailClosedSilently)) {
        return Live::FailClosedSilently;
    }
    if !owned() {
        // Cancellation is neither daemon failure nor evidence of its health.
        // An abandoned probe keeps its already published cooldown reservation;
        // the lock still drops here, and no compiler or install is retried.
        return Live::FailClosed("original compiler caller disappeared".into());
    }
    match &outcome {
        Err(()) => trace_bypass("daemon-consult-failed", args),
        Ok(Live::PassThrough) => trace_bypass("daemon-pass-through", args),
        _ => {}
    }
    let attempt = match &outcome {
        Ok(Live::FailClosed(_) | Live::FailClosedSilently) | Err(()) => AttemptOutcome::Failed,
        Ok(_) => AttemptOutcome::Succeeded,
    };
    match (probe_guard, probing_state) {
        (Some(_guard), Some(probing)) => {
            let _ = store_state(path, &on_outcome(&policy, &probing, attempt, now_ms()));
        }
        _ => {
            // Fold this outcome into the CURRENT record: concurrent attempts
            // each contribute (success resets, failures count). Skip lock and
            // disk churn when a healthy attempt observes an already-fresh state.
            if (attempt != AttemptOutcome::Succeeded || load_state(path) != BreakerState::fresh())
                && let Some(_guard) = try_lock_breaker(path)
            {
                let current = load_state(path);
                let next = on_outcome(&policy, &current, attempt, now_ms());
                if next != current {
                    let _ = store_state(path, &next);
                }
            }
        }
    }
    // No guard outlives this function: it is never a compiler-lifetime lock,
    // and contenders never block on its owner.
    outcome.unwrap_or(Live::PassThrough)
}

/// Capture limits are cache policy; delivery failures are build failures.
/// Never conflate an intentionally uncached transcript with lost compiler IO.
#[derive(Debug)]
struct CompilerStream {
    bytes: Vec<u8>,
    overflowed: bool,
    delivered: bool,
}

impl CompilerStream {
    fn unavailable() -> Self {
        Self {
            bytes: Vec::new(),
            overflowed: false,
            delivered: false,
        }
    }
}

/// Copy raw bytes live, keeping only a bounded PREFIX for optional caching.
/// After a sink error, drain the source without further writes: closing the
/// pipe would change the compiler's status, and stopping reads could wedge it.
fn tee(mut source: impl Read, mut sink: impl Write) -> CompilerStream {
    let mut capture = CompilerStream {
        bytes: Vec::new(),
        overflowed: false,
        delivered: true,
    };
    let mut buffer = [0_u8; 8192];
    loop {
        let read = match source.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => {
                capture.delivered = false;
                break;
            }
        };
        if capture.delivered && forward_compiler_bytes(&mut sink, &buffer[..read]).is_err() {
            capture.delivered = false;
        }
        let retained = read.min(MAX_CAPTURE_BYTES.saturating_sub(capture.bytes.len()));
        capture.bytes.extend_from_slice(&buffer[..retained]);
        capture.overflowed |= retained != read;
    }
    capture
}

fn forward_compiler_bytes(sink: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    sink.write_all(bytes)?;
    loop {
        match sink.flush() {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            result => return result,
        }
    }
}

/// This starts only AFTER the supervised compiler has stopped. It does not
/// impose a new runtime limit on a healthy, still-executing compiler.
const OUTPUT_DRAIN_BUDGET: Duration = Duration::from_secs(5);
const EXIT_OUTPUT_INCOMPLETE: i32 = 122;

#[derive(Debug)]
struct CompilerOutput {
    status: std::process::ExitStatus,
    stdout: CompilerStream,
    stderr: CompilerStream,
}

impl CompilerOutput {
    fn delivered(&self) -> bool {
        self.stdout.delivered && self.stderr.delivered
    }

    fn capture_eligible(&self) -> bool {
        self.delivered() && !self.stdout.overflowed && !self.stderr.overflowed
    }
}

/// Each relay sends exactly one completed capture. No stream bytes or progress
/// messages accumulate in this channel. A missing/panicked relay is incomplete.
fn collect_stream(
    receiver: &std::sync::mpsc::Receiver<CompilerStream>,
    output: &mut Option<CompilerStream>,
) {
    if output.is_none() {
        *output = match receiver.try_recv() {
            Ok(captured) => Some(captured),
            Err(std::sync::mpsc::TryRecvError::Empty) => None,
            Err(std::sync::mpsc::TryRecvError::Disconnected) => Some(CompilerStream::unavailable()),
        };
    }
}

/// Never join a thread that may be blocked in inherited stdout/stderr. Observe
/// the child AND the original caller while the relays run; a terminal status
/// starts a single bounded drain window for both streams. The caller MUST exit
/// the process on an incomplete result/error, which ends any blocked relays.
/// This is private to the short-lived wrapper, not a reusable detached-IO API.
fn collect_compiler_output(
    mut poll_child: impl FnMut() -> io::Result<Option<std::process::ExitStatus>>,
    stdout: std::sync::mpsc::Receiver<CompilerStream>,
    stderr: std::sync::mpsc::Receiver<CompilerStream>,
    owned: impl Fn() -> bool,
    drain_budget: Duration,
) -> io::Result<CompilerOutput> {
    let mut terminal = None;
    let mut drain_deadline = None;
    let mut out = None;
    let mut err = None;
    let started = Instant::now();
    loop {
        if !owned() {
            return Err(io::Error::other("original compiler caller disappeared"));
        }
        if terminal.is_none() {
            match poll_child() {
                Ok(Some(status)) => {
                    terminal = Some(status);
                    drain_deadline =
                        Some(Instant::now().checked_add(drain_budget).ok_or_else(|| {
                            io::Error::other("compiler output deadline is not representable")
                        })?);
                }
                Ok(None) => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        collect_stream(&stdout, &mut out);
        collect_stream(&stderr, &mut err);
        if let Some(status) = terminal {
            let expired = drain_deadline.is_some_and(|deadline| Instant::now() >= deadline);
            if (out.is_some() && err.is_some()) || expired {
                // Recheck after the last observation, before returning a result
                // that could lead to capture/publication consent.
                if !owned() {
                    return Err(io::Error::other("original compiler caller disappeared"));
                }
                return Ok(CompilerOutput {
                    status,
                    stdout: out.unwrap_or_else(CompilerStream::unavailable),
                    stderr: err.unwrap_or_else(CompilerStream::unavailable),
                });
            }
        }
        let poll = supervision::poll_interval(started.elapsed());
        let pause = drain_deadline.map_or(poll, |deadline| {
            poll.min(deadline.saturating_duration_since(Instant::now()))
        });
        std::thread::sleep(pause);
    }
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

fn is_executable_file_busy(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::ExecutableFileBusy || error.raw_os_error() == Some(26)
}

fn exec_compiler(real_rustc: &OsStr, argv0: &OsStr, args: &[OsString]) -> ! {
    let deadline = Instant::now() + Duration::from_millis(250);
    loop {
        let error = std::process::Command::new(real_rustc)
            .arg0(argv0)
            .args(args)
            .exec();
        if is_executable_file_busy(&error) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
            continue;
        }
        eprintln!("rabs-wrap: exec {}: {error}", real_rustc.to_string_lossy());
        std::process::exit(127);
    }
}

/// Run the admitted compiler with exact environment and live streams, then
/// retain output custody until the daemon has captured immutable bytes.
/// Overflowed, abandoned or unacknowledged captures are never published.
/// Cache-population failure preserves compiler status; incomplete IO delivery
/// refuses an otherwise successful result. Nonzero compiler exits/signals win.
fn run_attempt(
    real_rustc: &OsStr,
    argv0: &OsStr,
    args: &[OsString],
    mut session: BufReader<ConsultStream>,
    attempt: &str,
    env: &[(String, String)],
    owner: supervision::Owner,
) -> ! {
    // This stays set even if spawn fails: only the explicit, known-unstarted
    // error branch below may choose the original compiler after admission.
    session.get_ref().panic_fence.forbid_retry();
    let mut child = match supervision::spawn(real_rustc, argv0, args, env, owner) {
        Ok(child) => child,
        Err(_) => {
            // No compiler started. Abandon admission and become the original
            // compiler, rather than leave an unsupervised observed child.
            drop(session);
            stop_if_caller_lost(Some(owner));
            exec_compiler(real_rustc, argv0, args);
        }
    };
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let (out_tx, out_rx) = std::sync::mpsc::sync_channel(1);
    let (err_tx, err_rx) = std::sync::mpsc::sync_channel(1);
    let out = std::thread::Builder::new().spawn(move || {
        let capture = match stdout {
            // Hold stdout's lock through the relay. On process exit Rust's
            // best-effort stdout cleanup must not flush a buffer concurrently
            // with a blocked relay (including between its write and flush).
            Some(pipe) => tee(pipe, io::stdout().lock()),
            None => CompilerStream::unavailable(),
        };
        let _ = out_tx.send(capture);
    });
    let err = std::thread::Builder::new().spawn(move || {
        let capture = match stderr {
            Some(pipe) => tee(pipe, io::stderr().lock()),
            None => CompilerStream::unavailable(),
        };
        let _ = err_tx.send(capture);
    });
    if out.is_err() || err.is_err() {
        drop(session);
        // No fallback/replay after spawn. Exiting also releases a partial
        // relay setup; the Linux compiler guard observes its wrapper's death.
        std::process::exit(1);
    }
    let output = match collect_compiler_output(
        || child.try_wait(),
        out_rx,
        err_rx,
        || owner.can_acknowledge_capture(),
        OUTPUT_DRAIN_BUDGET,
    ) {
        Ok(output) => output,
        Err(_) => {
            drop(session);
            // Do not print or join here: a relay may hold the stderr lock
            // while its consumer is stalled. Process exit ends the relays;
            // the existing guard owns compiler-group cancellation, not us.
            std::process::exit(1);
        }
    };
    if !output.delivered() {
        drop(session);
        if output.status.success() {
            std::process::exit(EXIT_OUTPUT_INCOMPLETE);
        }
        exit_like(output.status);
    }
    if output.capture_eligible() {
        use std::os::unix::process::ExitStatusExt;
        let number =
            |value: Option<i32>| value.map_or_else(|| "null".to_owned(), |v| v.to_string());
        let frame = format!(
            "{{\"kind\":\"rustc-complete\",\"capture_protocol\":1,\"attempt\":{},\"exit_code\":{},\"signal\":{},\
             \"stdout_hex\":\"{}\",\"stderr_hex\":\"{}\"}}\n",
            json_string(attempt),
            number(output.status.code()),
            number(output.status.signal()),
            hex_encode(&output.stdout.bytes),
            hex_encode(&output.stderr.bytes),
        );
        // A report is not publication consent. Hold Cargo's output lifetime
        // until capture is acknowledged, using one bounded deadline. No ACK
        // means no publication, including a receipt arriving after timeout.
        let _ = capture::finish(&mut session, attempt, &frame, || {
            owner.can_acknowledge_capture()
        });
    }
    drop(session);
    exit_like(output.status);
}

fn main() {
    if let Some(info) = rabs_protocol::release_authorization::build_info_for_args(
        "rabs-wrap",
        std::env::args_os().skip(1),
    ) {
        println!("{info}");
        return;
    }
    supervision::run_if_guard();
    let mut argv = std::env::args_os().skip(1);
    let Some(real_rustc) = argv.next() else {
        eprintln!("rabs-wrap: usage: rabs-wrap <real-rustc> <args…>");
        std::process::exit(2);
    };
    let args: Vec<OsString> = argv.collect();
    run_wrapper(&real_rustc, &args);
}

/// Keep optional wrapper failures out of Cargo's diagnostic stream. The real
/// compiler invocation is retained outside the unwind boundary byte-for-byte;
/// a panic before any authority/exposure runs that exact original chain. An
/// accepted operation, lost original caller, or uncertain ownership check
/// instead exits silently, including when a relay still holds stderr's lock.
fn run_wrapper(real_rustc: &OsStr, args: &[OsString]) -> ! {
    if is_probe(args) {
        exec_compiler(real_rustc, real_rustc, args);
    }
    let panic_fence = PanicFence::default();
    panic_fence.install_recording_hook();
    // Capture once, before optional work. An incomplete capture is distinct
    // from a completed, unsupported capture: a panic cannot adopt a new
    // parent or treat uncertainty as permission to run another compiler.
    let original_owner = std::cell::Cell::new(None);
    let outcome: Result<(), _> = catch_unwind(AssertUnwindSafe(|| {
        #[cfg(test)]
        panic_fixture("owner-capture");
        let owner = supervision::Owner::capture().ok();
        original_owner.set(Some(owner));
        run_wrapper_inner(real_rustc, args, owner, &panic_fence);
    }));
    let ownership = if outcome.is_err() && panic_fence.permits_panic_retry() {
        original_owner
            .get()
            .map(|owner| catch_unwind(AssertUnwindSafe(|| caller_still_owned(owner))))
    } else {
        None
    };
    if matches!(ownership.as_ref(), Some(Ok(true))) {
        exec_compiler(real_rustc, real_rustc, args);
    }
    // Do not print, join relays, or drop an arbitrary panic payload here.
    // Process exit releases the socket and lets the existing compiler guard
    // settle any owned group; it never starts a replacement compiler.
    std::process::exit(1);
}

fn run_wrapper_inner(
    real_rustc: &OsStr,
    args: &[OsString],
    owner: Option<supervision::Owner>,
    panic_fence: &PanicFence,
) -> ! {
    #[cfg(test)]
    panic_fixture("before-consult");

    // Probes and unrepresentable argv: no state, no socket, no consult.
    let observation = shadow_argv(real_rustc, args).and_then(|mut argv| {
        let selected = compiler_for_observation(
            real_rustc,
            std::env::var_os("PATH").as_deref(),
            &std::env::current_dir().ok()?,
        )?;
        argv[0] = selected.to_str()?.to_owned();
        Some((selected, argv))
    });
    if let Some((selected, consult_argv)) = observation {
        stop_if_caller_lost(owner);
        // Name the selected executable before every original rustc argument.
        // The daemon stats this absolute path for toolchain identity. The
        // guard separately preserves Cargo's original argv[0] when executing
        // that selected file. Sending only the rustc arguments would leave
        // the daemon statting `--crate-name` and mislabeling receipts.
        let decision = observe_with_breaker(
            &socket_path(),
            &breaker_path(),
            &consult_argv,
            owner,
            panic_fence,
        );
        if matches!(decision, Live::FailClosedSilently) {
            std::process::exit(1);
        }
        // Every return path, including errors, an open/contended breaker,
        // legacy decisions and writer-returned fallback, keeps this fence.
        stop_if_caller_lost(owner);
        match decision {
            Live::PassThrough => {}
            Live::Served(stderr) => {
                panic_fence.forbid_retry();
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
                if let Some(owner) = owner {
                    panic_fence.forbid_retry();
                    run_attempt(
                        selected.as_os_str(),
                        real_rustc,
                        args,
                        *session,
                        &attempt,
                        &env,
                        owner,
                    );
                }
                // No usable supervision evidence: drop the admission and exec
                // normally. Never claim to have supervised or published it.
            }
            Live::FailClosed(reason) => {
                panic_fence.forbid_retry();
                eprintln!(
                    "rabs-wrap: {reason}; refusing to run rustc over a possibly changing output tree"
                );
                std::process::exit(1);
            }
            Live::FailClosedSilently => std::process::exit(1),
        }
        stop_if_caller_lost(owner);
    }

    // Become the compiler. On success this never returns; exit codes,
    // signals, and stdio semantics are the real chain's, exactly.
    exec_compiler(real_rustc, real_rustc, args);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn delivered_stream(bytes: &[u8]) -> CompilerStream {
        CompilerStream {
            bytes: bytes.to_vec(),
            overflowed: false,
            delivered: true,
        }
    }

    fn compiler_status(code: i32) -> std::process::ExitStatus {
        use std::os::unix::process::ExitStatusExt;
        std::process::ExitStatus::from_raw(code << 8)
    }

    #[test]
    fn compiler_tee_preserves_binary_bytes_and_unterminated_output() {
        for bytes in [b"".as_slice(), b"\0\xff\r\ncompiler\x1b[0m"] {
            let mut sink = Vec::new();
            let capture = tee(bytes, &mut sink);
            assert_eq!(sink, bytes);
            assert_eq!(capture.bytes, bytes);
            assert!(capture.delivered);
            assert!(!capture.overflowed);
        }
    }

    #[test]
    fn compiler_tee_overflow_only_disables_caching_and_keeps_an_exact_prefix() {
        let bytes = (0..MAX_CAPTURE_BYTES + 19)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let mut sink = Vec::new();
        let capture = tee(bytes.as_slice(), &mut sink);
        assert_eq!(sink, bytes);
        assert_eq!(capture.bytes, bytes[..MAX_CAPTURE_BYTES]);
        assert!(capture.delivered && capture.overflowed);
        let output = CompilerOutput {
            status: compiler_status(0),
            stdout: delivered_stream(b""),
            stderr: capture,
        };
        assert!(output.delivered() && output.status.success());
        assert!(!output.capture_eligible());
        let exact = tee(&bytes[..MAX_CAPTURE_BYTES], io::sink());
        assert!(exact.delivered && !exact.overflowed);
    }

    struct FailedSink {
        writes: usize,
        flushes: usize,
        fail_flush: bool,
    }

    impl Write for FailedSink {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.writes += 1;
            if self.fail_flush {
                Ok(bytes.len())
            } else {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed output"))
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flushes += 1;
            Err(io::Error::other("failed output flush"))
        }
    }

    #[test]
    fn compiler_tee_drains_after_write_or_flush_failure_without_retrying_delivery() {
        for fail_flush in [false, true] {
            let bytes = vec![b'x'; 32 * 1024];
            let mut source = io::Cursor::new(&bytes);
            let mut sink = FailedSink {
                writes: 0,
                flushes: 0,
                fail_flush,
            };
            let capture = tee(&mut source, &mut sink);
            assert_eq!(source.position(), bytes.len() as u64);
            assert_eq!(capture.bytes, bytes);
            assert!(!capture.delivered);
            assert!(!capture.overflowed);
            assert_eq!(sink.writes, 1, "do not repeat failed delivery");
            assert_eq!(sink.flushes, usize::from(fail_flush));
        }
    }

    #[test]
    fn compiler_tee_read_error_is_not_eof_or_capture_overflow() {
        struct FailedRead;
        impl Read for FailedRead {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("broken compiler stream"))
            }
        }
        let mut sink = Vec::new();
        let capture = tee(b"prefix".as_slice().chain(FailedRead), &mut sink);
        assert_eq!(sink, b"prefix");
        assert_eq!(capture.bytes, b"prefix");
        assert!(!capture.delivered && !capture.overflowed);
    }

    #[test]
    fn compiler_tee_retries_interrupted_io_without_duplicating_bytes() {
        struct InterruptedSink {
            bytes: Vec<u8>,
            write_interrupted: bool,
            flush_interrupted: bool,
        }
        impl Write for InterruptedSink {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if !self.write_interrupted {
                    self.write_interrupted = true;
                    return Err(io::ErrorKind::Interrupted.into());
                }
                let count = bytes.len().min(3);
                self.bytes.extend_from_slice(&bytes[..count]);
                Ok(count)
            }
            fn flush(&mut self) -> io::Result<()> {
                if !self.flush_interrupted {
                    self.flush_interrupted = true;
                    return Err(io::ErrorKind::Interrupted.into());
                }
                Ok(())
            }
        }
        let mut sink = InterruptedSink {
            bytes: Vec::new(),
            write_interrupted: false,
            flush_interrupted: false,
        };
        let bytes = b"partial\0binary\xffoutput";
        let capture = tee(bytes.as_slice(), &mut sink);
        assert!(capture.delivered && !capture.overflowed);
        assert_eq!(sink.bytes, bytes);
        assert_eq!(capture.bytes, bytes);
    }

    #[test]
    fn compiler_stream_eof_does_not_start_a_running_compilers_drain_deadline() {
        let (out_tx, out_rx) = std::sync::mpsc::channel();
        let (err_tx, err_rx) = std::sync::mpsc::channel();
        out_tx.send(delivered_stream(b"out")).unwrap();
        err_tx.send(delivered_stream(b"err")).unwrap();
        let mut polls = 0;
        let result = collect_compiler_output(
            || {
                polls += 1;
                Ok((polls == 3).then(|| compiler_status(0)))
            },
            out_rx,
            err_rx,
            || true,
            Duration::ZERO,
        )
        .unwrap();
        assert_eq!(polls, 3);
        assert!(result.status.success() && result.capture_eligible());
        assert_eq!(result.stdout.bytes, b"out");
        assert_eq!(result.stderr.bytes, b"err");
    }

    #[test]
    fn compiler_terminal_status_bounds_either_held_stream_without_masking_failure() {
        use std::os::unix::process::ExitStatusExt;
        for raw_status in [0, 41 << 8, 15] {
            for held_stdout in [false, true] {
                let (out_tx, out_rx) = std::sync::mpsc::channel();
                let (err_tx, err_rx) = std::sync::mpsc::channel();
                if held_stdout {
                    err_tx.send(delivered_stream(b"err")).unwrap();
                } else {
                    out_tx.send(delivered_stream(b"out")).unwrap();
                }
                let result = collect_compiler_output(
                    || Ok(Some(std::process::ExitStatus::from_raw(raw_status))),
                    out_rx,
                    err_rx,
                    || true,
                    Duration::ZERO,
                )
                .unwrap();
                assert_eq!(result.status.into_raw(), raw_status);
                assert!(!result.delivered() && !result.capture_eligible());
                assert_eq!(result.stdout.delivered, !held_stdout);
                assert_eq!(result.stderr.delivered, held_stdout);
            }
        }
    }

    #[test]
    fn compiler_output_wait_observes_caller_loss_before_and_after_child_exit() {
        use std::cell::Cell;
        for completed in [false, true] {
            let (out_tx, out_rx) = std::sync::mpsc::channel();
            let (err_tx, err_rx) = std::sync::mpsc::channel();
            let owned = Cell::new(true);
            let error = collect_compiler_output(
                || {
                    owned.set(false);
                    Ok(completed.then(|| compiler_status(0)))
                },
                out_rx,
                err_rx,
                || owned.get(),
                Duration::ZERO,
            )
            .unwrap_err();
            assert!(error.to_string().contains("caller disappeared"));
            drop((out_tx, err_tx));
        }
        let (out_tx, out_rx) = std::sync::mpsc::channel();
        let (err_tx, err_rx) = std::sync::mpsc::channel();
        assert!(
            collect_compiler_output(
                || panic!("lost owner must not poll or start work"),
                out_rx,
                err_rx,
                || false,
                Duration::ZERO,
            )
            .is_err()
        );
        drop((out_tx, err_tx));
    }

    #[test]
    fn compiler_output_wait_rejects_missing_relays_and_propagates_wait_errors() {
        let (out_tx, out_rx) = std::sync::mpsc::channel();
        let (err_tx, err_rx) = std::sync::mpsc::channel();
        drop((out_tx, err_tx));
        let result = collect_compiler_output(
            || Ok(Some(compiler_status(0))),
            out_rx,
            err_rx,
            || true,
            Duration::ZERO,
        )
        .unwrap();
        assert!(!result.delivered() && !result.capture_eligible());
        let (out_tx, out_rx) = std::sync::mpsc::channel();
        let (err_tx, err_rx) = std::sync::mpsc::channel();
        let error = collect_compiler_output(
            || Err(io::Error::other("wait failed")),
            out_rx,
            err_rx,
            || true,
            Duration::ZERO,
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "wait failed");
        drop((out_tx, err_tx));
    }

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
    fn cancelled_caller_cannot_accept_a_hit_or_admit_execution() {
        for line in [
            r#"{"kind":"rustc-decision","decision":"hit","capture_protocol":1}"#,
            r#"{"kind":"rustc-decision","decision":"execute","capture_protocol":1,"attempt":"id","env":[]}"#,
            r#"{"kind":"rustc-decision","decision":"pass-through"}"#,
        ] {
            let reply = reply_json::parse(line).unwrap();
            let (stream, mut peer) = UnixStream::pair().unwrap();
            let reader = BufReader::new(ConsultStream {
                stream,
                deadline: Instant::now() + Duration::from_secs(2),
                panic_fence: PanicFence::default(),
            });
            assert!(matches!(
                live_outcome(&reply, reader, &|| false),
                Ok(Live::FailClosed(_))
            ));
            assert_eq!(peer.read(&mut [0; 1]).unwrap(), 0, "no install consent");
        }
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
            panic_fence: PanicFence::default(),
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
            panic_fence: PanicFence::default(),
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
            panic_fence: PanicFence::default(),
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
            panic_fence: PanicFence::default(),
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
    fn compiler_lookup_uses_path_order_and_effective_execute_permission() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        for directory in ["directory", "denied", "first", "second"] {
            std::fs::create_dir(root.path().join(directory)).unwrap();
        }
        std::fs::create_dir(root.path().join("directory/rustc")).unwrap();
        for directory in ["denied", "first", "second"] {
            let path = root.path().join(directory).join("rustc");
            std::fs::write(&path, b"compiler fixture").unwrap();
            std::fs::set_permissions(
                path,
                std::fs::Permissions::from_mode(if directory == "denied" { 0o600 } else { 0o700 }),
            )
            .unwrap();
        }
        let lookup = |search: &str| {
            compiler_for_observation(OsStr::new("rustc"), Some(OsStr::new(search)), root.path())
        };
        assert_eq!(
            lookup("missing:directory:denied:first:second"),
            Some(root.path().join("first/rustc"))
        );
        assert_eq!(
            lookup("second:first"),
            Some(root.path().join("second/rustc"))
        );
        assert!(lookup("missing:directory:denied").is_none());
        assert!(compiler_for_observation(OsStr::new("rustc"), None, root.path()).is_none());
    }

    #[test]
    fn compiler_lookup_preserves_relative_and_symlink_spelling() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("selected");
        std::fs::write(&target, b"compiler fixture").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::symlink(&target, root.path().join("rustc")).unwrap();
        for (program, search) in [("rustc", Some(OsStr::new(""))), ("./rustc", None)] {
            let selected =
                compiler_for_observation(OsStr::new(program), search, root.path()).unwrap();
            assert_eq!(selected, root.path().join(program));
            assert_ne!(
                selected, target,
                "a symlink basename must not become rustup"
            );
        }
        let absolute = root.path().join("explicit/rustc");
        assert_eq!(
            compiler_for_observation(absolute.as_os_str(), None, root.path()),
            Some(absolute)
        );
    }

    #[test]
    fn compiler_lookup_does_not_search_past_an_unknown_path_error() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("loop")).unwrap();
        std::os::unix::fs::symlink("rustc", root.path().join("loop/rustc")).unwrap();
        assert!(
            compiler_for_observation(
                OsStr::new("rustc"),
                Some(OsStr::new("loop:/usr/bin:/bin")),
                root.path(),
            )
            .is_none()
        );
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
            observe_with_breaker(
                &socket_text,
                &wrapper_path,
                &["/tc/bin/rustc".to_owned()],
                None,
                &PanicFence::default(),
            )
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

        observe_with_breaker(
            socket.to_str().unwrap(),
            path,
            &[],
            None,
            &PanicFence::default(),
        );

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

        observe_with_breaker(
            socket.to_str().unwrap(),
            path,
            &[],
            None,
            &PanicFence::default(),
        );

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

        observe_with_breaker(
            socket.to_str().unwrap(),
            path.to_str().unwrap(),
            &[],
            None,
            &PanicFence::default(),
        );

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
        let result = consult(
            "/nonexistent/rabsd.sock",
            25,
            50,
            &[],
            &|| true,
            &PanicFence::default(),
        );
        assert!(result.is_err());
        assert!(
            start.elapsed() < Duration::from_millis(200),
            "daemon-dead consult must fail fast: {:?}",
            start.elapsed()
        );
    }

    /// This subprocess enters the same containment and dispatch functions as
    /// the installed wrapper. Only fault selection and its reachability marker
    /// are test-only; neither is recognized by a shipping binary.
    #[test]
    fn panic_containment_child() {
        let Ok(site) = std::env::var("RABS_PANIC_CASE") else {
            return;
        };
        let site = match site.as_str() {
            "before-consult" => "before-consult",
            "owner-capture" => "owner-capture",
            "before-decision" => "before-decision",
            "local-execute-grant" => "local-execute-grant",
            "remote-consent" => "remote-consent",
            "install-consent" => "install-consent",
            "metadata-delivered" => "metadata-delivered",
            "metadata-relay" => "metadata-relay",
            "after-consult" => "after-consult",
            "caller-lost" => "caller-lost",
            "no-panic" => "no-panic",
            other => panic!("unknown panic fixture {other}"),
        };
        PANIC_FIXTURE_SITE.set(Some(site));
        let compiler = std::env::var_os("RABS_PANIC_COMPILER").unwrap();
        run_wrapper(&compiler, &panic_compiler_arguments());
    }

    fn panic_compiler_arguments() -> Vec<OsString> {
        [
            "--crate-name",
            "demo",
            "source with spaces.rs",
            "literal$()`",
        ]
        .into_iter()
        .map(OsString::from)
        .collect()
    }

    #[derive(Clone, Copy)]
    enum PanicPeer {
        PassThrough,
        Execute,
        Remote,
        Hit,
        Metadata,
        Served,
        WriterReturned,
        RemoteFailed,
    }

    const PANIC_METADATA: &[u8] =
        b"{\"$message_type\":\"artifact\",\"artifact\":\"/fixture/libdemo.rmeta\"}\n";

    /// Peer messages and the compiler are explicit protocol doubles. These
    /// tests exercise native exec, sockets, writes and unwind behavior; they
    /// do not claim real Cargo compilation or host procfs qualification.
    fn panic_containment_case(
        site: &str,
        script: Option<PanicPeer>,
        runs_compiler: bool,
        stderr: &[u8],
    ) -> Vec<serde_json::Value> {
        use serde_json::{Value, json};
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::net::UnixListener;

        let root = tempfile::tempdir().unwrap();
        let compiler = root.path().join("compiler");
        let marker = root.path().join("compiler-arguments");
        let fault = root.path().join("fault-reached");
        let socket = root.path().join("edge.sock");
        std::fs::write(
            &compiler,
            b"#!/bin/sh\nprintf '%s\\0' \"$0\" \"$@\" \"$PRESERVED_VALUE\" >> \"$COMPILER_MARKER\"\nprintf 'compiler stdout\\n'\nprintf 'compiler stderr\\n' >&2\nexit 37\n",
        )
        .unwrap();
        std::fs::set_permissions(&compiler, std::fs::Permissions::from_mode(0o700)).unwrap();
        let daemon = script.map(|script| {
            let listener = UnixListener::bind(&socket).unwrap();
            listener.set_nonblocking(true).unwrap();
            std::thread::spawn(move || {
                let until = Instant::now() + Duration::from_secs(5);
                let stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            assert!(Instant::now() < until, "wrapper never connected");
                            std::thread::sleep(Duration::from_millis(1));
                        }
                        Err(error) => panic!("fixture accept: {error}"),
                    }
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut peer = BufReader::new(stream);
                let read = |peer: &mut BufReader<UnixStream>| -> Option<Value> {
                    let mut line = String::new();
                    (peer.read_line(&mut line).unwrap() != 0)
                        .then(|| serde_json::from_str(&line).unwrap())
                };
                let send = |peer: &mut BufReader<UnixStream>, value: Value| {
                    writeln!(peer.get_mut(), "{value}").unwrap();
                };
                assert_eq!(read(&mut peer).unwrap()["kind"], "hello");
                send(&mut peer, json!({"kind":"hello-ok"}));
                assert_eq!(read(&mut peer).unwrap()["kind"], "rustc-request");
                let mut offer = json!({
                    "kind":"rustc-decision", "decision":"hit", "capture_protocol":1,
                    "action_key":"action", "compiler_skip_authorized":false,
                });
                match script {
                    PanicPeer::PassThrough => offer["decision"] = json!("pass-through"),
                    PanicPeer::Execute => {
                        offer["decision"] = json!("execute");
                        offer["attempt"] = json!("attempt");
                        offer["env"] = json!([]);
                    }
                    PanicPeer::Remote | PanicPeer::RemoteFailed => {
                        offer["decision"] = json!("remote");
                        offer["remote_protocol"] = json!(1);
                    }
                    PanicPeer::Metadata => {
                        offer["metadata_protocol"] = json!(1);
                        offer["manifest_key"] = json!("manifest");
                    }
                    PanicPeer::Hit | PanicPeer::Served | PanicPeer::WriterReturned => {}
                }
                send(&mut peer, offer);
                let mut received = Vec::new();
                while let Some(frame) = read(&mut peer) {
                    if frame["kind"] == "rustc-accept" {
                        match script {
                            PanicPeer::Metadata => send(
                                &mut peer,
                                json!({
                                    "kind":"rustc-metadata", "metadata_protocol":1,
                                    "action_key":"action", "manifest_key":"manifest",
                                    "sequence":1, "stderr_hex":hex_encode(PANIC_METADATA),
                                }),
                            ),
                            PanicPeer::Served => send(
                                &mut peer,
                                json!({
                                    "kind":"rustc-decision", "decision":"served",
                                    "compiler_skip_authorized":true, "stderr_hex":"6361636865640a",
                                }),
                            ),
                            PanicPeer::WriterReturned => send(
                                &mut peer,
                                json!({
                                    "kind":"rustc-decision", "decision":"serve-failed",
                                    "writer_returned":true, "metadata_exposed":false,
                                }),
                            ),
                            _ => {}
                        }
                    } else if frame["kind"] == "rustc-remote-accept"
                        && matches!(script, PanicPeer::RemoteFailed)
                    {
                        send(
                            &mut peer,
                            json!({
                                "kind":"rustc-decision", "decision":"remote-failed",
                                "remote_protocol":1, "action_key":"action",
                                "execution_finished":true, "writer_returned":true,
                                "compiler_skip_authorized":false, "metadata_exposed":false,
                            }),
                        );
                    }
                    received.push(frame);
                }
                received
            })
        });
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::panic_containment_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("RABS_PANIC_CASE", site)
            .env("RABS_PANIC_COMPILER", &compiler)
            .env("RABS_PANIC_FAULT_MARKER", &fault)
            .env("COMPILER_MARKER", &marker)
            .env("PRESERVED_VALUE", "literal environment $()` value")
            .env("RABS_SOCKET_PATH", &socket)
            .env("RABS_BREAKER_FILE", root.path().join("breaker"))
            .env("RABS_LIVE_DECISION_MS", "2000")
            .env("RABS_REMOTE_WAIT_MS", "1000")
            .env("RABS_INSTALL_WAIT_MS", "1000")
            .env("RUST_BACKTRACE", "1")
            .env_remove("RABS_WRAP_TRACE")
            .current_dir(root.path())
            .output()
            .unwrap();
        let received = daemon.map_or_else(Vec::new, |daemon| daemon.join().unwrap());
        if site == "no-panic" {
            assert!(
                !fault.exists(),
                "ordinary settlement must not inject a panic"
            );
        } else {
            assert_eq!(
                std::fs::read(&fault).unwrap(),
                site.as_bytes(),
                "fault was reached"
            );
        }
        assert_eq!(
            output.status.code(),
            Some(if runs_compiler { 37 } else { 1 })
        );
        assert_eq!(
            output.stderr, stderr,
            "no wrapper panic diagnostic may reach Cargo"
        );
        if runs_compiler {
            let mut expected = Vec::new();
            for argument in std::iter::once(compiler.into_os_string())
                .chain(panic_compiler_arguments())
                .chain(std::iter::once(OsString::from(
                    "literal environment $()` value",
                )))
            {
                expected.extend_from_slice(argument.as_bytes());
                expected.push(0);
            }
            assert_eq!(
                std::fs::read(marker).unwrap(),
                expected,
                "exactly one original exec"
            );
            // libtest writes its own banner before the child enters the real
            // wrapper path; the exec'd compiler then writes directly to stdout.
            assert!(output.stdout.ends_with(b"compiler stdout\n"));
        } else {
            assert!(!marker.exists(), "panic started a replacement compiler");
            assert!(!output.stdout.ends_with(b"compiler stdout\n"));
        }
        received
    }

    #[test]
    fn panic_containment_before_authority_execs_the_exact_original_compiler() {
        assert!(
            panic_containment_case("before-consult", None, true, b"compiler stderr\n").is_empty()
        );
        assert!(
            panic_containment_case(
                "before-decision",
                Some(PanicPeer::Hit),
                true,
                b"compiler stderr\n",
            )
            .is_empty()
        );
        assert!(
            panic_containment_case(
                "after-consult",
                Some(PanicPeer::PassThrough),
                true,
                b"compiler stderr\n",
            )
            .is_empty()
        );
    }

    #[test]
    fn panic_containment_never_restarts_accepted_execution_or_installation() {
        assert!(
            panic_containment_case("local-execute-grant", Some(PanicPeer::Execute), false, b"",)
                .is_empty()
        );
        for (site, peer, kind) in [
            ("remote-consent", PanicPeer::Remote, "rustc-remote-accept"),
            ("install-consent", PanicPeer::Hit, "rustc-accept"),
            ("after-consult", PanicPeer::Served, "rustc-accept"),
        ] {
            let received = panic_containment_case(site, Some(peer), false, b"");
            assert_eq!(received.len(), 1, "no second consent or completion");
            assert_eq!(received[0]["kind"], kind);
        }
    }

    #[test]
    fn panic_containment_preserves_metadata_exposure_and_relay_failure() {
        for (site, expected) in [
            ("metadata-delivered", PANIC_METADATA),
            ("metadata-relay", b"".as_slice()),
        ] {
            let received = panic_containment_case(site, Some(PanicPeer::Metadata), false, expected);
            assert_eq!(
                received.len(),
                1,
                "panicked delivery cannot acknowledge metadata"
            );
            assert_eq!(received[0]["kind"], "rustc-accept");
        }
    }

    #[test]
    fn panic_containment_refuses_fallback_after_caller_loss() {
        assert!(panic_containment_case("caller-lost", None, false, b"").is_empty());
    }

    #[test]
    fn panic_containment_refuses_fallback_when_owner_capture_panics() {
        assert!(panic_containment_case("owner-capture", None, false, b"").is_empty());
    }

    #[test]
    fn panic_containment_preserves_explicit_settlement_without_reopening_the_panic_fence() {
        for (peer, kind) in [
            (PanicPeer::WriterReturned, "rustc-accept"),
            (PanicPeer::RemoteFailed, "rustc-remote-accept"),
        ] {
            let received =
                panic_containment_case("no-panic", Some(peer), true, b"compiler stderr\n");
            assert_eq!(received.len(), 1);
            assert_eq!(received[0]["kind"], kind);
            let received = panic_containment_case("after-consult", Some(peer), false, b"");
            assert_eq!(received.len(), 1);
            assert_eq!(received[0]["kind"], kind);
        }
    }
}
