//! Native, bounded startup and authenticated attachment for the worker cache.
//!
//! Preparation never runs Cargo. A new shared daemon owns independent session
//! and lifetime locks; failure or timeout never signals or removes that daemon.

use anyhow::{Context as _, Result, bail, ensure};
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::fd::{AsFd, AsRawFd, OwnedFd};
use rustix::fs::{AtFlags, CWD, FileType, FlockOperation, Mode, OFlags, Stat};
use rustix::io::{Errno, FdFlags};
use rustix::net::{AddressFamily, RecvFlags, SendFlags, SocketAddrUnix, SocketFlags, SocketType};
use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::{File, Metadata};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_FRAME: usize = 64 * 1024;
const MAX_STATUS_FRAME: usize = 128 * 1024;
const OWNER_RECEIPT: &str = "daemon-owner.json";
const MAX_OWNER_RECEIPT: usize = 2048;
const WORKER_KEYS: [&str; 3] = [
    "RABS_DEPENDENCY_WORKER_LISTEN",
    "RABS_DEPENDENCY_WORKER_ID",
    "RABS_DEPENDENCY_WORKER_SPKI_SHA256",
];
const POOL_KEY: &str = "RABS_DEPENDENCY_WORKERS_JSON";
const WORKER_FIELDS: [&str; 3] = ["listen", "worker_id", "worker_spki_sha256"];
const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK)
    .union(OFlags::CLOEXEC);

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Prepared {
    pub(super) wrapper: PathBuf,
    pub(super) socket: PathBuf,
}

type Environment = BTreeMap<OsString, OsString>;

pub(super) fn run(deadline_ns: u64) -> std::result::Result<Prepared, String> {
    prepare(deadline_ns).map_err(|error| format!("{error:#}"))
}

fn prepare(outer_deadline: u64) -> Result<Prepared> {
    let original: Environment = std::env::vars_os().collect();
    let milliseconds = match original.get(OsStr::new("CARGO_RABS_STARTUP_MS")) {
        Some(value) => value
            .to_str()
            .context("CARGO_RABS_STARTUP_MS must be UTF-8")?
            .parse::<u64>()
            .context("CARGO_RABS_STARTUP_MS must be an integer")?,
        None => 5000,
    };
    ensure!(
        milliseconds <= 30_000,
        "CARGO_RABS_STARTUP_MS must be between 0 and 30000"
    );
    let deadline = outer_deadline.min(super::now_ns().saturating_add(milliseconds * 1_000_000));
    remaining(deadline)?;
    let wrapper = executable("rabs-wrap", "CARGO_RABS_WRAP", &original)?;
    check_wrappers(&original, &wrapper)?;
    let daemon = executable("rabsd", "CARGO_RABS_DAEMON", &original)?;
    let mut daemon_env = original.clone();
    // Bootstrap helpers and the long-lived daemon must not recursively enter
    // worker preparation if they themselves invoke Cargo. The caller's Cargo
    // receives this marker only after preparation succeeds.
    daemon_env.insert("RCH_RABS_WORKER_ACTIVE".into(), "1".into());
    daemon_env.insert("RABS_LIVE_DEPENDENCY".into(), "1".into());
    daemon_env
        .entry("RABS_REUSE_CARGO_LAYOUT".into())
        .or_insert_with(|| "1".into());
    let socket = checked_config(&daemon, &daemon_env, deadline)?;
    let state = match original.get(OsStr::new("RABS_STATE_DIR")) {
        Some(value) => PathBuf::from(value),
        None => PathBuf::from(
            original
                .get(OsStr::new("HOME"))
                .context("an absolute HOME or RABS_STATE_DIR is required")?,
        )
        .join(".cache/rch/rabs-state"),
    };
    ensure!(
        state.is_absolute(),
        "RABS_STATE_DIR must be an absolute directory"
    );
    daemon_env.insert("RABS_SOCKET_PATH".into(), socket.as_os_str().into());
    daemon_env.insert("RABS_STATE_DIR".into(), state.as_os_str().into());
    let expected_remote = requested_dependency_worker(&original)?;
    ensure_daemon(
        &daemon,
        &socket,
        &state,
        &daemon_env,
        deadline,
        expected_remote.as_ref(),
    )?;
    Ok(Prepared { wrapper, socket })
}

fn remaining(deadline: u64) -> Result<Duration> {
    let nanos = deadline
        .checked_sub(super::now_ns())
        .filter(|nanos| *nanos != 0)
        .context("RABS setup deadline expired")?;
    Ok(Duration::from_nanos(nanos))
}

fn subdeadline(deadline: u64, nanos: u64) -> Result<u64> {
    remaining(deadline)?;
    Ok(deadline.min(super::now_ns().saturating_add(nanos)))
}

fn pause(deadline: u64) -> Result<()> {
    std::thread::sleep(remaining(deadline)?.min(Duration::from_millis(25)));
    Ok(())
}

fn wait_fd(fd: impl AsFd, events: PollFlags, deadline: u64) -> Result<()> {
    loop {
        let duration = remaining(deadline)?;
        let timeout =
            Timespec::try_from(duration).context("RABS wait duration is unrepresentable")?;
        match poll(&mut [PollFd::new(&fd, events)], Some(&timeout)) {
            Ok(0) => bail!("RABS setup deadline expired"),
            Ok(_) => return Ok(()),
            Err(Errno::INTR) => (),
            Err(error) => return Err(error).context("RABS setup poll"),
        }
    }
}

fn absolute(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_owned())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

fn is_executable(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|metadata| metadata.is_file())
        && rustix::fs::access(path, rustix::fs::Access::EXEC_OK).is_ok()
}

fn path_executable(value: &OsStr, env: &Environment) -> Option<PathBuf> {
    if value.as_bytes().contains(&b'/') {
        let path = PathBuf::from(value);
        return is_executable(&path).then_some(path);
    }
    let path = env.get(OsStr::new("PATH"))?;
    std::env::split_paths(path)
        .map(|directory| directory.join(value))
        .find(|candidate| is_executable(candidate))
}

fn executable(name: &str, override_name: &str, env: &Environment) -> Result<PathBuf> {
    if let Some(path) = env.get(OsStr::new(override_name)) {
        let path = Path::new(path);
        ensure!(
            !path.as_os_str().is_empty() && is_executable(path),
            "{override_name} is not executable"
        );
        return absolute(path);
    }
    let native = std::fs::read_link("/proc/self/exe")?;
    if let Some(parent) = native.parent() {
        let sibling = parent.join(name);
        if is_executable(&sibling) {
            return absolute(&sibling);
        }
    }
    path_executable(OsStr::new(name), env)
        .map(|path| absolute(&path))
        .transpose()?
        .with_context(|| format!("{name} is not installed (or {override_name} is not executable)"))
}

fn same_file(a: &Metadata, b: &Metadata) -> bool {
    a.dev() == b.dev() && a.ino() == b.ino()
}

fn check_wrappers(env: &Environment, wrapper: &Path) -> Result<()> {
    let expected = std::fs::metadata(wrapper)?;
    for name in ["RUSTC_WRAPPER", "CARGO_BUILD_RUSTC_WRAPPER"] {
        if let Some(value) = env.get(OsStr::new(name)) {
            let same = path_executable(value, env)
                .and_then(|path| std::fs::metadata(path).ok())
                .is_some_and(|metadata| same_file(&metadata, &expected));
            ensure!(
                same,
                "{name} already selects another wrapper or disables wrapping"
            );
        }
    }
    Ok(())
}

/// A killed configuration child remains owned by the enclosing prepare group.
/// Only this direct, short-lived child is signalled; never the shared daemon.
struct ConfigChild(Child);

impl Drop for ConfigChild {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_some() {
            return;
        }
        let _ = self.0.kill();
        let until = std::time::Instant::now() + Duration::from_millis(200);
        while std::time::Instant::now() < until {
            if self.0.try_wait().ok().flatten().is_some() {
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

fn checked_config(daemon: &Path, env: &Environment, deadline: u64) -> Result<PathBuf> {
    let deadline = subdeadline(deadline, 2_000_000_000)?;
    let mut child = ConfigChild(
        Command::new(daemon)
            .arg("--check-config")
            .env_clear()
            .envs(env)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .context("start rabsd --check-config")?,
    );
    let stdout = child
        .0
        .stdout
        .take()
        .context("rabsd configuration stdout missing")?;
    let flags = rustix::fs::fcntl_getfl(&stdout)?;
    rustix::fs::fcntl_setfl(&stdout, flags | OFlags::NONBLOCK)?;
    let mut data = Vec::new();
    let mut bytes = [0; 4096];
    loop {
        remaining(deadline)?;
        match rustix::io::read(&stdout, &mut bytes) {
            Ok(0) => break,
            Ok(count) => {
                ensure!(
                    data.len() + count <= MAX_FRAME,
                    "rabsd --check-config exceeded its output bound"
                );
                data.extend_from_slice(&bytes[..count]);
            }
            Err(Errno::AGAIN) => wait_fd(&stdout, PollFlags::IN, deadline)?,
            Err(Errno::INTR) => (),
            Err(error) => return Err(error).context("read rabsd --check-config"),
        }
    }
    loop {
        remaining(deadline)?;
        if let Some(status) = child.0.try_wait()? {
            ensure!(
                status.success(),
                "rabsd refused its configuration (run rabsd --check-config)"
            );
            break;
        }
        pause(deadline)?;
    }
    let config = decode_object(&data)?;
    ensure!(
        config.get("kind").and_then(Value::as_str) == Some("rabsd-config")
            && config.get("live_dependency").and_then(Value::as_bool) == Some(true),
        "installed rabsd does not acknowledge the opt-in live dependency lane"
    );
    let path = config
        .get("socket_path")
        .and_then(Value::as_str)
        .context("rabsd configured an invalid socket path")?;
    ensure!(
        path.starts_with('/') && !path.contains('\0') && path.len() <= 107,
        "rabsd configured an invalid absolute socket path"
    );
    Ok(PathBuf::from(path))
}

/// Reject duplicate keys at every level without interpreting an untrusted
/// receipt twice. serde_json retains its ordinary bounded recursion limit.
struct UniqueValue(Value);

impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct UniqueVisitor;
        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = UniqueValue;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("JSON without duplicate object fields")
            }
            fn visit_bool<E: serde::de::Error>(
                self,
                value: bool,
            ) -> std::result::Result<Self::Value, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_i64<E: serde::de::Error>(
                self,
                value: i64,
            ) -> std::result::Result<Self::Value, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_u64<E: serde::de::Error>(
                self,
                value: u64,
            ) -> std::result::Result<Self::Value, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_f64<E: serde::de::Error>(
                self,
                value: f64,
            ) -> std::result::Result<Self::Value, E> {
                serde_json::Number::from_f64(value)
                    .map(|number| UniqueValue(Value::Number(number)))
                    .ok_or_else(|| E::custom("nonfinite JSON number"))
            }
            fn visit_str<E: serde::de::Error>(
                self,
                value: &str,
            ) -> std::result::Result<Self::Value, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_string<E: serde::de::Error>(
                self,
                value: String,
            ) -> std::result::Result<Self::Value, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_none<E: serde::de::Error>(self) -> std::result::Result<Self::Value, E> {
                Ok(UniqueValue(Value::Null))
            }
            fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Self::Value, E> {
                Ok(UniqueValue(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element::<UniqueValue>()? {
                    values.push(value.0);
                }
                Ok(UniqueValue(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some((name, value)) = map.next_entry::<String, UniqueValue>()? {
                    if values.insert(name, value.0).is_some() {
                        return Err(serde::de::Error::custom("duplicate JSON field"));
                    }
                }
                Ok(UniqueValue(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(UniqueVisitor)
    }
}

fn decode_json(data: &[u8]) -> Result<Value> {
    Ok(serde_json::from_slice::<UniqueValue>(data)
        .context("RABS returned malformed JSON")?
        .0)
}

fn decode_object(data: &[u8]) -> Result<Value> {
    let value = decode_json(data)?;
    ensure!(value.is_object(), "RABS returned a non-object reply");
    Ok(value)
}

fn endpoint(values: [&str; 3]) -> Result<Value> {
    for value in values {
        ensure!(
            !value.is_empty() && value.len() <= 1024 && !value.chars().any(char::is_control),
            "dependency worker settings must be bounded strings without controls"
        );
    }
    let listen = values[0]
        .parse::<SocketAddr>()
        .context("dependency worker requires IPv4:port or [IPv6]:port")?;
    ensure!(listen.port() != 0, "dependency worker port must be nonzero");
    let pin = values[2];
    ensure!(
        pin.len() == 64
            && pin
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            && pin.bytes().any(|byte| byte != b'0'),
        "dependency worker pin must be nonzero lowercase SHA-256"
    );
    Ok(json!({"listen": listen.to_string(), "worker_id": values[1], "worker_spki_sha256": pin}))
}

fn requested_dependency_worker(env: &Environment) -> Result<Option<Value>> {
    let singleton = WORKER_KEYS
        .iter()
        .any(|name| env.contains_key(OsStr::new(name)));
    let mut configuration = if let Some(pool) = env.get(OsStr::new(POOL_KEY)) {
        ensure!(
            !singleton,
            "dependency worker pool cannot be mixed with singleton settings"
        );
        let pool = pool
            .to_str()
            .context("dependency worker pool must be UTF-8")?;
        ensure!(
            pool.len() <= MAX_STATUS_FRAME,
            "dependency worker pool exceeds its byte limit"
        );
        let value = decode_json(pool.as_bytes())?;
        let workers = value
            .as_array()
            .context("dependency worker pool must be an array")?;
        ensure!(
            (1..=32).contains(&workers.len()),
            "dependency worker pool requires 1..=32 workers"
        );
        let mut endpoints = Vec::new();
        let mut seen: [BTreeSet<String>; 3] = std::array::from_fn(|_| BTreeSet::new());
        for worker in workers {
            let worker = worker
                .as_object()
                .context("dependency worker pool member must be an object")?;
            ensure!(
                worker.len() == 3 && WORKER_FIELDS.iter().all(|name| worker.contains_key(*name)),
                "dependency worker requires exactly listen, worker_id and worker_spki_sha256"
            );
            let fields =
                WORKER_FIELDS.map(|name| worker.get(name).and_then(Value::as_str).unwrap_or(""));
            let endpoint = endpoint(fields)?;
            for (index, name) in WORKER_FIELDS.iter().enumerate() {
                let value = endpoint[*name]
                    .as_str()
                    .context("invalid normalized worker endpoint")?;
                ensure!(
                    seen[index].insert(value.to_owned()),
                    "duplicate dependency worker {name}"
                );
            }
            endpoints.push(endpoint);
        }
        json!({"workers": endpoints})
    } else if singleton {
        let values = WORKER_KEYS.map(|name| {
            env.get(OsStr::new(name))
                .and_then(|value| value.to_str())
                .unwrap_or("")
        });
        endpoint(values)?
    } else {
        return Ok(None);
    };
    configuration["remote_protocol"] = json!(1);
    configuration["dependency_context"] = json!("dependency-exec-v8");
    Ok(Some(configuration))
}

#[derive(Debug, thiserror::Error)]
#[error(
    "connected RABS daemon does not match requested dependency worker configuration; use a separate RABS_STATE_DIR and RABS_SOCKET_PATH"
)]
struct RemoteMismatch;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct SocketIdentity(u64, u64, i64);

fn socket_identity(path: &Path) -> Result<Option<SocketIdentity>> {
    let metadata = match rustix::fs::statat(CWD, path, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(metadata) => metadata,
        Err(Errno::NOENT) => return Ok(None),
        Err(error) => return Err(error).context("inspect RABS socket"),
    };
    ensure!(
        FileType::from_raw_mode(metadata.st_mode) == FileType::Socket,
        "RABS endpoint is not a socket; leaving it untouched"
    );
    ensure!(
        metadata.st_uid == rustix::process::geteuid().as_raw() && metadata.st_mode & 0o077 == 0,
        "RABS socket is not private to this user; leaving it untouched"
    );
    let changed = metadata
        .st_ctime
        .checked_mul(1_000_000_000)
        .and_then(|seconds| seconds.checked_add(i64::try_from(metadata.st_ctime_nsec).ok()?))
        .context("RABS socket ctime is unrepresentable")?;
    Ok(Some(SocketIdentity(
        metadata.st_dev,
        metadata.st_ino,
        changed,
    )))
}

enum Probe {
    Missing,
    Ready,
    Stale(SocketIdentity),
}

struct Frames {
    descriptor: OwnedFd,
    deadline: u64,
    buffer: Vec<u8>,
}

impl Frames {
    fn send(&self, value: &Value) -> Result<()> {
        let mut bytes = serde_json::to_vec(value)?;
        bytes.push(b'\n');
        let mut offset = 0;
        while offset != bytes.len() {
            remaining(self.deadline)?;
            match rustix::net::send(&self.descriptor, &bytes[offset..], SendFlags::NOSIGNAL) {
                Ok(0) => bail!("RABS closed while sending a request"),
                Ok(count) => offset += count,
                Err(Errno::AGAIN) => wait_fd(&self.descriptor, PollFlags::OUT, self.deadline)?,
                Err(Errno::INTR) => (),
                Err(error) => return Err(error).context("send RABS request"),
            }
        }
        Ok(())
    }

    fn receive(&mut self, maximum: usize) -> Result<Value> {
        loop {
            remaining(self.deadline)?;
            if let Some(end) = self.buffer.iter().position(|byte| *byte == b'\n') {
                ensure!(end < maximum, "RABS reply exceeded its frame bound");
                let value = decode_object(&self.buffer[..end])?;
                self.buffer.drain(..=end);
                return Ok(value);
            }
            ensure!(
                self.buffer.len() < maximum,
                "RABS reply exceeded its frame bound"
            );
            let mut bytes = [0; 4096];
            let length = bytes.len().min(maximum - self.buffer.len());
            match rustix::net::recv(&self.descriptor, &mut bytes[..length], RecvFlags::empty()) {
                Ok((0, _)) => bail!("RABS closed before a complete reply"),
                Ok((count, _)) => self.buffer.extend_from_slice(&bytes[..count]),
                Err(Errno::AGAIN) => wait_fd(&self.descriptor, PollFlags::IN, self.deadline)?,
                Err(Errno::INTR) => (),
                Err(error) => return Err(error).context("receive RABS reply"),
            }
        }
    }
}

fn probe(
    path: &Path,
    deadline: u64,
    expected_pid: Option<u32>,
    expected_remote: Option<&Value>,
) -> Result<Probe> {
    remaining(deadline)?;
    let Some(identity) = socket_identity(path)? else {
        return Ok(Probe::Missing);
    };
    let descriptor = rustix::net::socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )?;
    let address = SocketAddrUnix::new(path)?;
    match rustix::net::connect(&descriptor, &address) {
        Ok(()) => (),
        Err(Errno::CONNREFUSED) => {
            ensure!(
                socket_identity(path)? == Some(identity),
                "RABS endpoint changed during connection"
            );
            return Ok(Probe::Stale(identity));
        }
        // A full Unix listen backlog is not a dead daemon. Never reinterpret
        // EAGAIN, a timeout, or a connected-peer refusal as stale ownership.
        Err(error) => return Err(error).context("connect RABS endpoint"),
    }
    let credentials = rustix::net::sockopt::socket_peercred(&descriptor)?;
    ensure!(
        credentials.uid == rustix::process::geteuid() && socket_identity(path)? == Some(identity),
        "RABS endpoint ownership changed during connection"
    );
    ensure!(
        expected_pid
            .is_none_or(|expected| credentials.pid.as_raw_nonzero().get() as u32 == expected),
        "RABS readiness peer is not the daemon this launcher started"
    );
    let mut frames = Frames {
        descriptor,
        deadline,
        buffer: Vec::new(),
    };
    frames.send(
        &json!({"kind":"hello", "transport":{"minimum_compatible":1,"current":1},
        "application":{"minimum_compatible":1,"current":1}}),
    )?;
    let hello = frames.receive(MAX_FRAME)?;
    ensure!(
        hello.get("kind").and_then(Value::as_str) == Some("hello-ok")
            && hello.get("transport").and_then(Value::as_u64) == Some(1)
            && hello.get("application").and_then(Value::as_u64) == Some(1),
        "RABS refused protocol version 1"
    );
    frames.send(&json!({"kind":"status"}))?;
    let status = frames.receive(MAX_STATUS_FRAME)?;
    ensure!(
        status.get("kind").and_then(Value::as_str) == Some("coord-status"),
        "RABS did not return coordinator status"
    );
    ensure!(
        status.get("live_dependency").and_then(Value::as_bool) == Some(true),
        "connected RABS daemon does not enable live dependency serving"
    );
    if let Some(expected) = expected_remote {
        let matches = status
            .get("remote_dependency")
            .and_then(Value::as_object)
            .zip(expected.as_object())
            .is_some_and(|(actual, expected)| {
                expected
                    .iter()
                    .all(|(name, value)| actual.get(name) == Some(value))
            });
        if !matches {
            return Err(RemoteMismatch.into());
        }
    }
    ensure!(
        socket_identity(path)? == Some(identity),
        "RABS endpoint changed during readiness exchange"
    );
    Ok(Probe::Ready)
}

fn private_directory(path: &Path) -> Result<File> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)?;
    let file = File::from(rustix::fs::open(path, DIRECTORY_FLAGS, Mode::empty())?);
    check_directory(&rustix::fs::fstat(&file)?, 0o022)?;
    Ok(file)
}

fn check_directory(metadata: &Stat, mask: u32) -> Result<()> {
    ensure!(
        FileType::from_raw_mode(metadata.st_mode) == FileType::Directory
            && metadata.st_uid == rustix::process::geteuid().as_raw()
            && metadata.st_mode & mask == 0,
        "RABS startup directory has unsafe ownership or permissions"
    );
    Ok(())
}

fn check_lock(metadata: &Stat) -> Result<()> {
    ensure!(
        FileType::from_raw_mode(metadata.st_mode) == FileType::RegularFile
            && metadata.st_uid == rustix::process::geteuid().as_raw()
            && metadata.st_mode & 0o077 == 0
            && metadata.st_nlink == 1,
        "RABS startup lock has unsafe identity or permissions"
    );
    Ok(())
}

fn private_lock(directory: &File, name: &OsStr) -> Result<File> {
    let file = File::from(rustix::fs::openat(
        directory,
        name,
        OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )?);
    check_lock(&rustix::fs::fstat(&file)?)?;
    Ok(file)
}

fn same_identity(a: &Stat, b: &Stat) -> bool {
    a.st_dev == b.st_dev && a.st_ino == b.st_ino
}

struct StartupLock {
    path: PathBuf,
    directory: File,
    lock: File,
    socket_parent: PathBuf,
    socket_directory: File,
    endpoint_name: OsString,
    endpoint_lock: File,
    acquired: bool,
}

impl StartupLock {
    fn new(state: &Path, socket: &Path) -> Result<Self> {
        let parent = private_directory(state)?;
        match rustix::fs::mkdirat(&parent, "cargo-launcher", Mode::from_raw_mode(0o700)) {
            Ok(()) | Err(Errno::EXIST) => (),
            Err(error) => return Err(error).context("create RABS startup directory"),
        }
        let directory = File::from(rustix::fs::openat(
            &parent,
            "cargo-launcher",
            DIRECTORY_FLAGS,
            Mode::empty(),
        )?);
        check_directory(&rustix::fs::fstat(&directory)?, 0o077)?;
        let lock = private_lock(&directory, OsStr::new("startup.lock"))?;
        let socket_parent = socket
            .parent()
            .context("RABS socket must have a parent directory")?
            .to_owned();
        let socket_name = socket
            .file_name()
            .context("RABS socket must name a directory entry")?;
        let mut endpoint_name = OsString::from(".rabs-");
        endpoint_name.push(socket_name);
        endpoint_name.push(".startup.lock");
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&socket_parent)?;
        let socket_directory = private_directory(&std::fs::canonicalize(&socket_parent)?)?;
        let endpoint_lock = private_lock(&socket_directory, &endpoint_name)?;
        let state = Self {
            path: state.join("cargo-launcher"),
            directory,
            lock,
            socket_parent,
            socket_directory,
            endpoint_name,
            endpoint_lock,
            acquired: false,
        };
        state.verify()?;
        Ok(state)
    }

    fn verify(&self) -> Result<()> {
        for (path, descriptor, flags, mask) in [
            (
                &self.path,
                &self.directory,
                AtFlags::SYMLINK_NOFOLLOW,
                0o077,
            ),
            (
                &self.socket_parent,
                &self.socket_directory,
                AtFlags::empty(),
                0o022,
            ),
        ] {
            let held = rustix::fs::fstat(descriptor)?;
            let named = rustix::fs::statat(CWD, path, flags)?;
            check_directory(&named, mask)?;
            ensure!(
                same_identity(&held, &named),
                "RABS startup directory identity changed"
            );
        }
        for (directory, name, descriptor) in [
            (&self.directory, OsStr::new("startup.lock"), &self.lock),
            (
                &self.socket_directory,
                self.endpoint_name.as_os_str(),
                &self.endpoint_lock,
            ),
        ] {
            let held = rustix::fs::fstat(descriptor)?;
            let named = rustix::fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)?;
            check_lock(&held)?;
            check_lock(&named)?;
            ensure!(
                same_identity(&held, &named),
                "RABS startup lock identity changed"
            );
        }
        Ok(())
    }

    fn acquire(&mut self, socket: &Path, deadline: u64) -> Result<bool> {
        for descriptor in [&self.lock, &self.endpoint_lock] {
            loop {
                remaining(deadline)?;
                self.verify()?;
                match rustix::fs::flock(descriptor, FlockOperation::NonBlockingLockExclusive) {
                    Ok(()) => {
                        self.verify()?;
                        break;
                    }
                    Err(Errno::WOULDBLOCK) => {
                        if matches!(
                            probe(socket, subdeadline(deadline, 250_000_000)?, None, None),
                            Ok(Probe::Ready)
                        ) {
                            return Ok(false);
                        }
                        pause(deadline)?;
                    }
                    Err(Errno::INTR) => (),
                    Err(error) => return Err(error).context("acquire RABS startup lock"),
                }
            }
        }
        self.acquired = true;
        Ok(true)
    }

    fn binding(
        &self,
        pid: u32,
        socket: SocketIdentity,
        process: Option<ProcessIdentity>,
    ) -> Result<Value> {
        self.verify()?;
        ensure!(
            self.acquired,
            "RABS recovery requires both held startup locks"
        );
        let state = rustix::fs::fstat(&self.directory)?;
        let endpoint = rustix::fs::fstat(&self.endpoint_lock)?;
        let mut value = json!({"v":1, "pid":pid, "socket":socket,
            "state":[state.st_dev,state.st_ino], "endpoint_lock":[endpoint.st_dev,endpoint.st_ino]});
        if let Some(process) = process {
            value["v"] = json!(2);
            value["process"] = serde_json::to_value(process)?;
        }
        Ok(value)
    }

    fn new_file(&self, prefix: &str, suffix: &str) -> Result<(File, OsString)> {
        self.verify()?;
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let name = OsString::from(format!("{prefix}-{}-{nanos}.{suffix}", std::process::id()));
        let file = File::from(rustix::fs::openat(
            &self.directory,
            &name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        )?);
        Ok((file, name))
    }

    fn record_owner(&self, pid: u32, socket: SocketIdentity) -> Result<()> {
        let value = self.binding(pid, socket, Some(process_identity(pid)?))?;
        match rustix::fs::statat(&self.directory, OWNER_RECEIPT, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(metadata) => check_lock(&metadata)?,
            Err(Errno::NOENT) => (),
            Err(error) => return Err(error).context("inspect existing daemon receipt"),
        }
        let (mut file, name) = self.new_file("daemon-owner", "tmp")?;
        file.write_all(&serde_json::to_vec(&value)?)?;
        file.sync_all()?;
        self.verify()?;
        rustix::fs::renameat(&self.directory, &name, &self.directory, OWNER_RECEIPT)?;
        self.directory.sync_all()?;
        Ok(())
    }

    fn authorize_recovery(&self, socket: SocketIdentity) -> Result<()> {
        self.verify()?;
        let mut file = File::from(rustix::fs::openat(
            &self.directory,
            OWNER_RECEIPT,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )?);
        let before = rustix::fs::fstat(&file)?;
        check_lock(&before)?;
        ensure!(
            (0..=MAX_OWNER_RECEIPT as i64).contains(&before.st_size),
            "RABS owner receipt exceeds its bound"
        );
        let mut data = Vec::new();
        Read::by_ref(&mut file)
            .take((MAX_OWNER_RECEIPT + 1) as u64)
            .read_to_end(&mut data)?;
        let after = rustix::fs::fstat(&file)?;
        let named = rustix::fs::statat(&self.directory, OWNER_RECEIPT, AtFlags::SYMLINK_NOFOLLOW)?;
        check_lock(&named)?;
        let signature = |metadata: &Stat| {
            (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_size,
                metadata.st_ctime,
                metadata.st_ctime_nsec,
                metadata.st_mtime,
                metadata.st_mtime_nsec,
            )
        };
        ensure!(
            data.len() as i64 == before.st_size
                && signature(&before) == signature(&after)
                && signature(&before) == signature(&named),
            "RABS owner receipt changed while reading"
        );
        let value = decode_object(&data)?;
        let pid = value
            .get("pid")
            .and_then(Value::as_u64)
            .and_then(|pid| u32::try_from(pid).ok())
            .filter(|pid| (2..=i32::MAX as u32).contains(pid))
            .context("RABS owner receipt has invalid PID")?;
        let process = match value.get("v").and_then(Value::as_u64) {
            Some(1) => None,
            Some(2) => Some(serde_json::from_value::<ProcessIdentity>(
                value
                    .get("process")
                    .cloned()
                    .context("RABS owner receipt has no process evidence")?,
            )?),
            _ => bail!("RABS owner receipt has unsupported identity version"),
        };
        if let Some(process) = &process {
            process.validate()?;
        }
        ensure!(
            value == self.binding(pid, socket, process.clone())?,
            "RABS stale endpoint does not match this launcher's ownership receipt"
        );
        ensure!(
            process_exited(pid, process.as_ref())?,
            "RABS recorded daemon has not exited; leaving its endpoint untouched"
        );
        self.verify()
    }

    fn spawn(&self, daemon: &Path, env: &Environment, log: File) -> Result<Child> {
        self.verify()?;
        let worker = super::native_worker_executable()?;
        // The prepare role is single-threaded. All other descriptors are
        // CLOEXEC. These two original open descriptions, not reopened paths,
        // carry the flock lifetime across both execs and into the daemon.
        let state_flags = rustix::io::fcntl_getfd(&self.lock)?;
        let endpoint_flags = rustix::io::fcntl_getfd(&self.endpoint_lock)?;
        rustix::io::fcntl_setfd(&self.lock, state_flags - FdFlags::CLOEXEC)?;
        if let Err(error) =
            rustix::io::fcntl_setfd(&self.endpoint_lock, endpoint_flags - FdFlags::CLOEXEC)
        {
            let _ = rustix::io::fcntl_setfd(&self.lock, state_flags);
            return Err(error).context("inherit endpoint lifetime lock");
        }
        let child = Command::new(worker)
            .arg("worker-cache")
            .arg("--daemon-exec")
            .arg(daemon)
            .arg(self.lock.as_raw_fd().to_string())
            .arg(self.endpoint_lock.as_raw_fd().to_string())
            .env_clear()
            .envs(env)
            .env("TMPDIR", &self.path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(log))
            .spawn();
        let restored_state = rustix::io::fcntl_setfd(&self.lock, state_flags);
        let restored_endpoint = rustix::io::fcntl_setfd(&self.endpoint_lock, endpoint_flags);
        // A successfully spawned daemon may already serve another caller.
        // Restore failures must not kill it or explicitly unlock either fd.
        restored_state?;
        restored_endpoint?;
        child.context("start native RABS daemon owner")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcessIdentity {
    boot: String,
    pid_namespace: [u64; 2],
    start_ticks: u64,
}

impl ProcessIdentity {
    fn validate(&self) -> Result<()> {
        ensure!(
            valid_boot(&self.boot) && self.pid_namespace[1] != 0 && self.start_ticks != 0,
            "RABS owner receipt has invalid process evidence"
        );
        Ok(())
    }
}

fn valid_boot(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}

fn read_proc(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let mut file = File::from(rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    ensure!(
        FileType::from_raw_mode(rustix::fs::fstat(&file)?.st_mode) == FileType::RegularFile,
        "RABS process identity is not a regular procfs record"
    );
    let mut data = Vec::new();
    Read::by_ref(&mut file)
        .take((maximum + 1) as u64)
        .read_to_end(&mut data)?;
    ensure!(
        !data.is_empty() && data.len() <= maximum,
        "RABS process identity exceeds procfs bound"
    );
    Ok(data)
}

fn process_scope() -> Result<(String, [u64; 2])> {
    let expected_pid = std::process::id().to_string();
    ensure!(
        std::fs::read_link("/proc/self")?.as_os_str() == OsStr::new(&expected_pid),
        "RABS process identity requires matching native procfs"
    );
    let bytes = read_proc(Path::new("/proc/sys/kernel/random/boot_id"), 37)?;
    let bytes = bytes.strip_suffix(b"\n").unwrap_or(&bytes);
    let boot = std::str::from_utf8(bytes)?;
    ensure!(valid_boot(boot), "RABS kernel boot identity is malformed");
    let namespace = std::fs::metadata("/proc/self/ns/pid")?;
    Ok((boot.to_owned(), [namespace.dev(), namespace.ino()]))
}

fn process_start_ticks(bytes: &[u8], pid: u32) -> Result<u64> {
    let delimiter = bytes
        .windows(2)
        .rposition(|pair| pair == b") ")
        .context("RABS process stat is malformed")?;
    ensure!(
        bytes[..delimiter].starts_with(format!("{pid} (").as_bytes()),
        "RABS process stat has wrong PID"
    );
    let fields: Vec<&[u8]> = bytes[delimiter + 2..]
        .split(|byte| byte.is_ascii_whitespace())
        .filter(|field| !field.is_empty())
        .collect();
    ensure!(
        fields.len() >= 20 && fields[0].len() == 1 && b"RSDZTtXxKWPI".contains(&fields[0][0]),
        "RABS process stat has invalid state"
    );
    let ticks = fields[19];
    ensure!(
        !ticks.is_empty() && ticks.len() <= 20 && ticks.iter().all(u8::is_ascii_digit),
        "RABS process start ticks are malformed"
    );
    let value = std::str::from_utf8(ticks)?.parse::<u64>()?;
    ensure!(
        value != 0 && value.to_string().as_bytes() == ticks,
        "RABS process start ticks are malformed"
    );
    Ok(value)
}

fn process_identity(pid: u32) -> Result<ProcessIdentity> {
    ensure!(
        (2..=i32::MAX as u32).contains(&pid),
        "RABS process identity requires valid PID"
    );
    let scope = process_scope()?;
    let namespace = std::fs::metadata(format!("/proc/{pid}/ns/pid"))?;
    let data = read_proc(Path::new(&format!("/proc/{pid}/stat")), 4096)?;
    ensure!(
        [namespace.dev(), namespace.ino()] == scope.1 && process_scope()? == scope,
        "RABS process identity namespace changed or is foreign"
    );
    Ok(ProcessIdentity {
        boot: scope.0,
        pid_namespace: scope.1,
        start_ticks: process_start_ticks(&data, pid)?,
    })
}

fn missing_process(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
        || error
            .downcast_ref::<Errno>()
            .is_some_and(|error| matches!(*error, Errno::NOENT | Errno::SRCH))
}

fn process_exited(pid: u32, recorded: Option<&ProcessIdentity>) -> Result<bool> {
    if let Some(recorded) = recorded {
        recorded.validate()?;
        let scope = process_scope()?;
        if scope.0 != recorded.boot {
            return Ok(true);
        }
        if scope.1 != recorded.pid_namespace {
            return Ok(false);
        }
        let current = match process_identity(pid) {
            Ok(current) => Some(current),
            Err(error) if missing_process(&error) => None,
            Err(error) => return Err(error),
        };
        ensure!(
            process_scope()? == scope,
            "RABS process scope changed during recovery"
        );
        if let Some(current) = current {
            ensure!(
                current.boot == scope.0 && current.pid_namespace == scope.1,
                "RABS process scope changed during recovery"
            );
            if current.start_ticks != recorded.start_ticks {
                return Ok(true);
            }
        }
    }
    let native_pid = rustix::process::Pid::from_raw(pid as i32).context("invalid daemon PID")?;
    match rustix::process::pidfd_open(native_pid, rustix::process::PidfdFlags::empty()) {
        Ok(descriptor) => {
            let mut descriptors = [PollFd::new(&descriptor, PollFlags::IN)];
            poll(
                &mut descriptors,
                Some(&Timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                }),
            )?;
            Ok(descriptors[0]
                .revents()
                .intersects(PollFlags::IN | PollFlags::HUP))
        }
        Err(Errno::SRCH) => Ok(true),
        Err(_) => Ok(matches!(
            nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid as i32), None),
            Err(nix::errno::Errno::ESRCH)
        )),
    }
}

fn ensure_daemon(
    daemon: &Path,
    socket: &Path,
    state: &Path,
    env: &Environment,
    deadline: u64,
    expected_remote: Option<&Value>,
) -> Result<()> {
    let stale = match probe(
        socket,
        subdeadline(deadline, 1_000_000_000)?,
        None,
        expected_remote,
    )? {
        Probe::Ready => return Ok(()),
        Probe::Stale(identity) => Some(identity),
        Probe::Missing => None,
    };
    let mut lock = StartupLock::new(state, socket)?;
    if !lock.acquire(socket, deadline)? {
        ensure!(
            matches!(
                probe(
                    socket,
                    subdeadline(deadline, 1_000_000_000)?,
                    None,
                    expected_remote
                )?,
                Probe::Ready
            ),
            "RABS endpoint disappeared after startup handoff"
        );
        return Ok(());
    }
    match probe(
        socket,
        subdeadline(deadline, 1_000_000_000)?,
        None,
        expected_remote,
    )? {
        Probe::Ready => return Ok(()),
        Probe::Stale(identity) => {
            ensure!(
                stale == Some(identity),
                "RABS stale endpoint changed before recovery"
            );
            lock.authorize_recovery(identity)?;
        }
        Probe::Missing => (),
    }
    remaining(deadline)?;
    let (log, log_name) = lock.new_file("daemon", "log")?;
    if let Some(stale) = stale {
        ensure!(
            socket_identity(socket)? == Some(stale),
            "RABS endpoint changed before daemon restart"
        );
    }
    let mut child = lock.spawn(daemon, env, log)?;
    loop {
        if child.try_wait()?.is_some() {
            bail!(
                "rabsd exited during startup; see {}",
                lock.path.join(&log_name).display()
            );
        }
        let identity = socket_identity(socket)?;
        match probe(
            socket,
            subdeadline(deadline, 250_000_000)?,
            Some(child.id()),
            expected_remote,
        ) {
            Ok(Probe::Ready) => {
                ensure!(
                    socket_identity(socket)? == identity,
                    "RABS endpoint changed before recording its owner"
                );
                if let Some(identity) = identity {
                    if let Err(error) = lock.record_owner(child.id(), identity) {
                        eprintln!(
                            "RCH_WORKER_CACHE: daemon ready, but crash recovery ownership was not recorded: {error:#}"
                        );
                    }
                    return Ok(());
                }
            }
            Err(error) if error.is::<RemoteMismatch>() => return Err(error),
            _ => (),
        }
        pause(deadline).with_context(|| {
            format!(
                "rabsd startup was not confirmed; see {}",
                lock.path.join(&log_name).display()
            )
        })?;
    }
}

/// Re-exec before any runtime starts. The inherited descriptors are intentionally
/// left open through exec: reopening their paths would lose flock ownership.
pub(super) fn daemon_exec(arguments: &[OsString]) -> std::result::Result<(), String> {
    let execute = || -> Result<()> {
        let [daemon, state_fd, endpoint_fd] = arguments else {
            bail!("invalid daemon-exec arguments");
        };
        let parse_fd = |value: &OsString| -> Result<i32> {
            let value = value.to_str().context("invalid daemon lock descriptor")?;
            let descriptor = value.parse::<i32>()?;
            ensure!(
                descriptor >= 3 && descriptor.to_string() == value,
                "invalid daemon lock descriptor"
            );
            Ok(descriptor)
        };
        let state_fd = parse_fd(state_fd)?;
        let endpoint_fd = parse_fd(endpoint_fd)?;
        ensure!(
            state_fd != endpoint_fd,
            "daemon lifetime locks must be distinct descriptors"
        );
        for descriptor in [state_fd, endpoint_fd] {
            let path = format!("/proc/self/fd/{descriptor}");
            let metadata = rustix::fs::statat(CWD, path.as_str(), AtFlags::empty())?;
            check_lock(&metadata)?;
            let flags = read_proc(Path::new(&format!("/proc/self/fdinfo/{descriptor}")), 4096)?;
            let flags = std::str::from_utf8(&flags)?
                .lines()
                .find_map(|line| line.strip_prefix("flags:\t"))
                .context("inherited daemon lock has no flags")?;
            let flags = u64::from_str_radix(flags, 8)?;
            ensure!(
                flags & u64::from(OFlags::CLOEXEC.bits()) == 0,
                "daemon lifetime lock would close on exec"
            );
        }
        let session = rustix::process::setsid()?;
        ensure!(
            session == rustix::process::getpid() && session == rustix::process::getpgrp(),
            "daemon has no independent process session"
        );
        let error = Command::new(daemon).exec();
        Err(error).context("exec rabsd")
    };
    execute().map_err(|error| {
        let message = format!("{error:#}");
        let bounded = message.chars().take(4096).collect::<String>();
        let _ = writeln!(
            std::io::stderr().lock(),
            "RCH_RABS_DAEMON_STARTUP_REFUSED: {bounded}"
        );
        message
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead as _, BufReader};
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    use std::os::unix::net::{UnixListener, UnixStream};

    fn deadline() -> u64 {
        super::super::now_ns() + 2_000_000_000
    }

    fn private_listener(path: &Path) -> UnixListener {
        let listener = UnixListener::bind(path).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        listener
    }

    fn reply_server(listener: UnixListener, status: Value) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let hello = decode_object(line.as_bytes()).unwrap();
            assert_eq!(hello["kind"], "hello");
            stream
                .write_all(b"{\"kind\":\"hello-ok\",\"transport\":1,\"application\":1}\n")
                .unwrap();
            line.clear();
            reader.read_line(&mut line).unwrap();
            assert_eq!(decode_object(line.as_bytes()).unwrap()["kind"], "status");
            let mut bytes = serde_json::to_vec(&status).unwrap();
            bytes.push(b'\n');
            stream.write_all(&bytes).unwrap();
        })
    }

    #[test]
    fn cache_prepare_frames_exchange_large_and_buffered_replies_over_real_stream() {
        let (client, mut peer) = UnixStream::pair().unwrap();
        client.set_nonblocking(true).unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        peer.set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let large = json!({"kind":"coord-status", "payload":"x".repeat(8192)});
        let expected = large.clone();
        let server = std::thread::spawn(move || {
            let mut line = String::new();
            BufReader::new(peer.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            assert_eq!(line, "{\"kind\":\"status\"}\n");
            let mut bytes = serde_json::to_vec(&large).unwrap();
            bytes.extend_from_slice(b"\n{\"kind\":\"next\"}\n");
            peer.write_all(&bytes).unwrap();
        });
        let mut frames = Frames {
            descriptor: client.into(),
            deadline: deadline(),
            buffer: Vec::new(),
        };
        frames.send(&json!({"kind":"status"})).unwrap();
        // More than one 4096-byte receive is required even if the operating
        // system coalesces every peer write. The following frame is retained.
        assert_eq!(frames.receive(MAX_FRAME).unwrap(), expected);
        assert_eq!(frames.receive(MAX_FRAME).unwrap(), json!({"kind":"next"}));
        server.join().unwrap();
    }

    #[test]
    fn cache_prepare_frames_enforce_exact_bounds_json_eof_and_deadline() {
        let receive = |bytes: &[u8], maximum: usize| {
            let (client, mut peer) = UnixStream::pair().unwrap();
            client.set_nonblocking(true).unwrap();
            peer.write_all(bytes).unwrap();
            drop(peer);
            Frames {
                descriptor: client.into(),
                deadline: deadline(),
                buffer: Vec::new(),
            }
            .receive(maximum)
        };
        assert_eq!(receive(b"{}\n", 3).unwrap(), json!({}));
        for (bytes, maximum, reason) in [
            (b"{}\n".as_slice(), 2, "frame bound"),
            (b"12345678", 8, "frame bound"),
            (b"{\"kind\":", 64, "closed before a complete reply"),
            (b"{\"kind\":1,\"kind\":2}\n", 64, "malformed JSON"),
            (b"{} {}\n", 64, "malformed JSON"),
            (b"{\"value\":\"\xff\"}\n", 64, "malformed JSON"),
            (b"[]\n", 64, "non-object reply"),
        ] {
            let error = receive(bytes, maximum).unwrap_err();
            assert!(error.to_string().contains(reason), "{error:#}");
        }
        let (client, _silent_peer) = UnixStream::pair().unwrap();
        client.set_nonblocking(true).unwrap();
        let error = Frames {
            descriptor: client.into(),
            deadline: super::super::now_ns() + 25_000_000,
            buffer: Vec::new(),
        }
        .receive(MAX_FRAME)
        .unwrap_err();
        assert!(error.to_string().contains("deadline expired"));
    }

    #[test]
    fn cache_prepare_json_rejects_duplicate_nested_keys_and_trailing_bytes() {
        for bytes in [
            br#"{"kind":"hello-ok","kind":"other"}"#.as_slice(),
            br#"{"remote":{"worker":1,"worker":2}}"#,
            br#"{"ok":true} false"#,
            br#"[]"#,
        ] {
            assert!(decode_object(bytes).is_err());
        }
        assert_eq!(
            decode_object(br#"{"values":[true,null,1,"value"]}"#).unwrap()["values"]
                .as_array()
                .unwrap()
                .len(),
            4
        );
    }

    #[test]
    fn cache_prepare_worker_settings_normalize_literal_endpoints_and_reject_ambiguity() {
        let pin = "b".repeat(64);
        let endpoint = endpoint(["[0:0:0:0:0:ffff:192.0.2.1]:00123", "worker", &pin]).unwrap();
        assert_eq!(endpoint["listen"], "[::ffff:192.0.2.1]:123");
        for address in ["localhost:123", "127.0.0.1:0", "::1:123", "[::1%lo]:123"] {
            assert!(
                super::endpoint([address, "worker", &pin]).is_err(),
                "{address}"
            );
        }
        assert!(super::endpoint(["127.0.0.1:1", "bad\nname", &pin]).is_err());
        assert!(super::endpoint(["127.0.0.1:1", "worker", &"0".repeat(64)]).is_err());
        let mut env = Environment::new();
        env.insert(POOL_KEY.into(), json!([
            {"listen":"[::1]:99","worker_id":"a","worker_spki_sha256":pin},
            {"listen":"[0:0:0:0:0:0:0:1]:99","worker_id":"b","worker_spki_sha256":"c".repeat(64)},
        ]).to_string().into());
        assert!(requested_dependency_worker(&env).is_err());
        env.insert(WORKER_KEYS[0].into(), "127.0.0.1:1".into());
        assert!(requested_dependency_worker(&env).is_err());
    }

    #[test]
    fn cache_prepare_preserves_existing_wrapper_choices_and_empty_disable() {
        let current = std::env::current_exe().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let alias = directory.path().join("wrapper-alias");
        symlink(&current, &alias).unwrap();
        let mut env = Environment::new();
        env.insert("RUSTC_WRAPPER".into(), alias.into_os_string());
        env.insert(
            "CARGO_BUILD_RUSTC_WRAPPER".into(),
            current.clone().into_os_string(),
        );
        let before = env.clone();
        check_wrappers(&env, &current).unwrap();
        assert_eq!(env, before);
        env.insert("RUSTC_WRAPPER".into(), "".into());
        assert!(check_wrappers(&env, &current).is_err());
        env.insert("RUSTC_WRAPPER".into(), "/bin/false".into());
        assert!(check_wrappers(&env, &current).is_err());
    }

    #[test]
    fn cache_prepare_attaches_only_to_private_authenticated_live_daemon() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("ready.sock");
        let expected = json!({"listen":"127.0.0.1:1234", "worker_id":"one", "worker_spki_sha256":"a".repeat(64),
            "remote_protocol":1,"dependency_context":"dependency-exec-v8"});
        let server = reply_server(
            private_listener(&socket),
            json!({"kind":"coord-status", "live_dependency":true,
            "remote_dependency":expected}),
        );
        assert!(matches!(
            probe(
                &socket,
                deadline(),
                Some(std::process::id()),
                Some(&expected)
            )
            .unwrap(),
            Probe::Ready
        ));
        server.join().unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(socket_identity(&socket).is_err());
        let ordinary = directory.path().join("ordinary");
        std::fs::write(&ordinary, b"leave untouched").unwrap();
        assert!(socket_identity(&ordinary).is_err());
        assert_eq!(std::fs::read(ordinary).unwrap(), b"leave untouched");
    }

    #[test]
    fn cache_prepare_remote_mismatch_and_disabled_lane_cannot_attach() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("mismatch.sock");
        let server = reply_server(
            private_listener(&socket),
            json!({"kind":"coord-status", "live_dependency":true}),
        );
        let error = probe(
            &socket,
            deadline(),
            None,
            Some(&json!({"worker_id":"required"})),
        )
        .err()
        .unwrap();
        assert!(error.is::<RemoteMismatch>());
        server.join().unwrap();
        let disabled = directory.path().join("disabled.sock");
        let server = reply_server(
            private_listener(&disabled),
            json!({"kind":"coord-status", "live_dependency":false}),
        );
        assert!(probe(&disabled, deadline(), None, None).is_err());
        server.join().unwrap();
    }

    #[test]
    fn cache_prepare_only_connect_refusal_is_stale_evidence() {
        let directory = tempfile::tempdir().unwrap();
        let stale = directory.path().join("stale.sock");
        drop(private_listener(&stale));
        assert!(matches!(
            probe(&stale, deadline(), None, None).unwrap(),
            Probe::Stale(_)
        ));
        let live = directory.path().join("live.sock");
        let listener = private_listener(&live);
        let server = std::thread::spawn(move || {
            let (_stream, _) = listener.accept().unwrap();
            std::thread::sleep(Duration::from_millis(150));
        });
        assert!(probe(&live, super::super::now_ns() + 50_000_000, None, None).is_err());
        server.join().unwrap();
        assert!(socket_identity(&live).unwrap().is_some());
    }

    #[test]
    fn cache_prepare_endpoint_aliases_and_lifetime_descriptions_share_one_lock() {
        let directory = tempfile::tempdir().unwrap();
        let sockets = directory.path().join("sockets");
        std::fs::create_dir(&sockets).unwrap();
        let alias = directory.path().join("socket-alias");
        symlink(&sockets, &alias).unwrap();
        let mut owner = StartupLock::new(
            &directory.path().join("state-a"),
            &sockets.join("rabs.sock"),
        )
        .unwrap();
        assert!(
            owner
                .acquire(&sockets.join("rabs.sock"), deadline())
                .unwrap()
        );
        let inherited = owner.endpoint_lock.try_clone().unwrap();
        let contender =
            StartupLock::new(&directory.path().join("state-b"), &alias.join("rabs.sock")).unwrap();
        drop(owner);
        assert_eq!(
            rustix::fs::flock(
                &contender.endpoint_lock,
                FlockOperation::NonBlockingLockExclusive
            ),
            Err(Errno::WOULDBLOCK)
        );
        drop(inherited);
        rustix::fs::flock(
            &contender.endpoint_lock,
            FlockOperation::NonBlockingLockExclusive,
        )
        .unwrap();
    }

    #[test]
    fn cache_prepare_replaced_lock_path_is_never_spawn_authority() {
        let directory = tempfile::tempdir().unwrap();
        let owner = StartupLock::new(
            &directory.path().join("state"),
            &directory.path().join("rabs.sock"),
        )
        .unwrap();
        std::fs::rename(
            owner.path.join("startup.lock"),
            owner.path.join("old-startup.lock"),
        )
        .unwrap();
        let _replacement = private_lock(&owner.directory, OsStr::new("startup.lock")).unwrap();
        assert!(owner.verify().is_err());
    }

    #[test]
    fn cache_prepare_process_identity_parses_binary_comm_without_pid_reuse_authority() {
        let mut stat = b"42 (command ) with\n\xff bytes) S".to_vec();
        for _ in 0..18 {
            stat.extend_from_slice(b" 0");
        }
        stat.extend_from_slice(b" 987654321 0\n");
        assert_eq!(process_start_ticks(&stat, 42).unwrap(), 987654321);
        assert!(process_start_ticks(&stat, 43).is_err());
        let identity = process_identity(std::process::id()).unwrap();
        assert!(!process_exited(std::process::id(), Some(&identity)).unwrap());
        let mut reused = identity.clone();
        reused.start_ticks += 1;
        assert!(process_exited(std::process::id(), Some(&reused)).unwrap());
        let mut foreign = identity.clone();
        foreign.pid_namespace[1] += 1;
        assert!(!process_exited(std::process::id(), Some(&foreign)).unwrap());
        let mut rebooted = identity;
        rebooted.boot = "00000000-0000-0000-0000-000000000000".into();
        assert!(process_exited(std::process::id(), Some(&rebooted)).unwrap());
    }

    #[test]
    fn cache_prepare_receipt_binds_socket_lock_and_live_owner_without_removing_endpoint() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("rabs.sock");
        let mut lock = StartupLock::new(&directory.path().join("state"), &socket).unwrap();
        assert!(lock.acquire(&socket, deadline()).unwrap());
        let _listener = private_listener(&socket);
        let identity = socket_identity(&socket).unwrap().unwrap();
        lock.record_owner(std::process::id(), identity).unwrap();
        let error = lock.authorize_recovery(identity).unwrap_err();
        assert!(error.to_string().contains("has not exited"));
        let wrong = SocketIdentity(identity.0, identity.1, identity.2 + 1);
        assert!(
            lock.authorize_recovery(wrong)
                .unwrap_err()
                .to_string()
                .contains("does not match")
        );
        assert_eq!(socket_identity(&socket).unwrap(), Some(identity));
        let receipt =
            decode_object(&std::fs::read(lock.path.join(OWNER_RECEIPT)).unwrap()).unwrap();
        assert_eq!(receipt["v"], 2);
        assert!(receipt["process"]["start_ticks"].as_u64().unwrap() > 0);
    }
}
