//! Retained-intent validation and one-way handoff to the existing execution owner.

use crate::cli::{JobControl, Options};
use rustix::fd::{AsRawFd, OwnedFd};
use rustix::fs::{AtFlags, FileType, MemfdFlags, Mode, OFlags, SealFlags, Stat};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Number, Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

// The existing transport's MAX_JSON_RECORD. The native transport independently
// enforces its current envelope limit before it contacts a worker.
const MAX_RECORD: u64 = 1024 * 1024 - 64;
const LIVE_SCHEMA: &str = "rabs-live-remote-recovery-v1";
const CANONICAL_SCHEMA: &str = "rabs-canonical-cargo-recovery-v1";

#[derive(Debug)]
pub(crate) struct Refused(&'static str);

impl fmt::Display for Refused {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl From<io::Error> for Refused {
    fn from(_error: io::Error) -> Self {
        // Never echo record data, credentials, environment values, or argv in
        // a refusal. The same policy applies to errors produced during exec.
        Self("I/O operation failed")
    }
}

impl From<rustix::io::Errno> for Refused {
    fn from(_error: rustix::io::Errno) -> Self {
        Self("I/O operation failed")
    }
}

type Result<T> = std::result::Result<T, Refused>;

fn require(condition: bool, message: &'static str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(Refused(message))
    }
}

fn string<'a>(value: &'a Value, message: &'static str) -> Result<&'a str> {
    value.as_str().ok_or(Refused(message))
}

fn absolute(value: &str) -> Result<PathBuf> {
    require(
        value.starts_with('/') && !value.contains('\0'),
        "paths must be absolute",
    )?;
    require(
        !value.split('/').any(|part| matches!(part, "." | "..")),
        "paths must not contain traversal",
    )?;
    // Match the existing path representation: repeated separators and trailing
    // separators are normalized, while the POSIX double-leading slash is kept.
    let parts: Vec<_> = value.split('/').filter(|part| !part.is_empty()).collect();
    require(
        !parts.is_empty(),
        "paths must name a directory below the root",
    )?;
    let prefix = if value.starts_with("//") && !value.starts_with("///") {
        "//"
    } else {
        "/"
    };
    Ok(PathBuf::from(format!("{prefix}{}", parts.join("/"))))
}

fn absolute_os(value: &OsStr) -> Result<PathBuf> {
    absolute(value.to_str().ok_or(Refused("paths must be UTF-8"))?)
}

fn absolute_value(value: &Value) -> Result<PathBuf> {
    absolute(string(value, "paths must be absolute")?)
}

fn same_path(left: &Path, right: &Path) -> bool {
    left.as_os_str() == right.as_os_str()
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

fn open_directory(path: &Path) -> Result<OwnedFd> {
    require(path.is_absolute(), "paths must be absolute")?;
    let mut directory = rustix::fs::open("/", directory_flags(), Mode::empty())?;
    for part in path.components() {
        match part {
            Component::RootDir => {}
            Component::Normal(name) => {
                directory = rustix::fs::openat(&directory, name, directory_flags(), Mode::empty())?;
            }
            _ => return Err(Refused("paths must not contain traversal")),
        }
    }
    Ok(directory)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Identity {
    device: i128,
    inode: i128,
    uid: u32,
    mode: u32,
}

impl Identity {
    fn of(metadata: &Stat) -> Self {
        Self {
            device: i128::from(metadata.st_dev),
            inode: i128::from(metadata.st_ino),
            uid: metadata.st_uid,
            mode: metadata.st_mode,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Fingerprint {
    identity: Identity,
    size: i128,
    links: i128,
    modified: (i128, i128),
    changed: (i128, i128),
}

impl Fingerprint {
    fn of(metadata: &Stat) -> Self {
        Self {
            identity: Identity::of(metadata),
            size: i128::from(metadata.st_size),
            links: i128::from(metadata.st_nlink),
            modified: (
                i128::from(metadata.st_mtime),
                i128::from(metadata.st_mtime_nsec),
            ),
            changed: (
                i128::from(metadata.st_ctime),
                i128::from(metadata.st_ctime_nsec),
            ),
        }
    }
}

fn private_file(metadata: &Stat) -> Result<()> {
    require(
        FileType::from_raw_mode(metadata.st_mode) == FileType::RegularFile
            && metadata.st_nlink == 1,
        "recovery records must be ordinary files with one link",
    )?;
    require(
        metadata.st_uid == rustix::process::geteuid().as_raw() && metadata.st_mode & 0o077 == 0,
        "recovery records must be private to the current user",
    )?;
    require(
        metadata.st_size >= 0 && i128::from(metadata.st_size) <= i128::from(MAX_RECORD),
        "recovery record exceeds its byte bound",
    )
}

fn read_record(directory: &OwnedFd, name: &str) -> Result<(Vec<u8>, Fingerprint)> {
    let descriptor = rustix::fs::openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let mut file = File::from(descriptor);
    let before = rustix::fs::fstat(&file)?;
    private_file(&before)?;
    let mut data = Vec::new();
    (&mut file).take(MAX_RECORD + 1).read_to_end(&mut data)?;
    let length = i128::try_from(data.len()).map_err(|_| Refused("record length is unavailable"))?;
    require(
        length == i128::from(before.st_size) && length <= i128::from(MAX_RECORD),
        "recovery record changed length while reading",
    )?;
    let fingerprint = Fingerprint::of(&before);
    require(
        fingerprint == Fingerprint::of(&rustix::fs::fstat(&file)?)
            && fingerprint
                == Fingerprint::of(&rustix::fs::statat(
                    directory,
                    name,
                    AtFlags::SYMLINK_NOFOLLOW,
                )?),
        "recovery record changed while reading",
    )?;
    Ok((data, fingerprint))
}

// Value's default deserializer permits duplicate object fields. Recovery's
// authority records do not: check every object, including nested request data.
struct UniqueValue(Value);

impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct UniqueVisitor;
        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = UniqueValue;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON value without duplicate fields")
            }

            fn visit_bool<E: de::Error>(self, value: bool) -> std::result::Result<Self::Value, E> {
                Ok(UniqueValue(Value::Bool(value)))
            }

            fn visit_i64<E: de::Error>(self, value: i64) -> std::result::Result<Self::Value, E> {
                Ok(UniqueValue(Value::Number(value.into())))
            }

            fn visit_u64<E: de::Error>(self, value: u64) -> std::result::Result<Self::Value, E> {
                Ok(UniqueValue(Value::Number(value.into())))
            }

            fn visit_f64<E: de::Error>(self, value: f64) -> std::result::Result<Self::Value, E> {
                Number::from_f64(value)
                    .map(|number| UniqueValue(Value::Number(number)))
                    .ok_or_else(|| E::custom("non-finite recovery JSON number"))
            }

            fn visit_str<E: de::Error>(self, value: &str) -> std::result::Result<Self::Value, E> {
                Ok(UniqueValue(Value::String(value.into())))
            }

            fn visit_string<E: de::Error>(
                self,
                value: String,
            ) -> std::result::Result<Self::Value, E> {
                Ok(UniqueValue(Value::String(value)))
            }

            fn visit_unit<E: de::Error>(self) -> std::result::Result<Self::Value, E> {
                Ok(UniqueValue(Value::Null))
            }

            fn visit_none<E: de::Error>(self) -> std::result::Result<Self::Value, E> {
                self.visit_unit()
            }

            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(UniqueValue(value)) = sequence.next_element()? {
                    values.push(value);
                }
                Ok(UniqueValue(Value::Array(values)))
            }

            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut values = Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(de::Error::custom("duplicate recovery JSON field"));
                    }
                    let UniqueValue(value) = map.next_value()?;
                    values.insert(key, value);
                }
                Ok(UniqueValue(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(UniqueVisitor)
    }
}

fn decode(data: &[u8]) -> Result<Value> {
    let UniqueValue(value) = serde_json::from_slice(data)
        .map_err(|_| Refused("malformed or duplicate recovery JSON"))?;
    require(value.is_object(), "recovery JSON must be an object")?;
    Ok(value)
}

fn hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn digest(data: &[u8]) -> String {
    use fmt::Write as _;
    let mut result = String::with_capacity(64);
    for byte in Sha256::digest(data) {
        let _ = write!(result, "{byte:02x}");
    }
    result
}

fn listener(value: &str) -> Result<&str> {
    let (host, port) = value.rsplit_once(':').ok_or(Refused(
        "worker listener must be a literal IP and nonzero port",
    ))?;
    let host_valid = match host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
    {
        Some(ip) => !ip.contains('%') && ip.parse::<Ipv6Addr>().is_ok(),
        None => host.parse::<Ipv4Addr>().is_ok(),
    };
    require(
        host_valid,
        "worker listener must be a literal IP and nonzero port",
    )?;
    require(
        !port.is_empty()
            && port.bytes().all(|byte| byte.is_ascii_digit())
            && port.parse::<u16>().is_ok_and(|port| port != 0),
        "invalid recorded listener port",
    )?;
    Ok(value)
}

fn worker_identity(worker: &str, pin: &str) -> Result<()> {
    require(
        !worker.is_empty()
            && worker.len() <= 1024
            && worker
                .chars()
                .all(|ch| ch >= ' ' && !('\u{7f}'..='\u{9f}').contains(&ch)),
        "invalid recorded worker identity",
    )?;
    require(
        hex_digest(pin) && pin.bytes().any(|byte| byte != b'0'),
        "invalid recorded worker SPKI pin",
    )
}

#[derive(Debug)]
struct Intent {
    root: PathBuf,
    state: PathBuf,
    request: Vec<u8>,
    request_id: u64,
    action_key: Option<String>,
    worker: String,
    pin: String,
    listen: String,
    root_identity: Identity,
    state_identity: Identity,
    record_fingerprint: Fingerprint,
    request_fingerprint: Fingerprint,
    record_name: &'static str,
    request_folder: PathBuf,
    request_folder_identity: Identity,
    origin: &'static str,
}

impl Intent {
    fn verify_unchanged(&self) -> Result<()> {
        let state = open_directory(&self.state)?;
        require(
            Identity::of(&rustix::fs::fstat(&state)?) == self.state_identity,
            "transport state directory changed",
        )?;
        let root = open_directory(&self.root)?;
        require(
            Identity::of(&rustix::fs::fstat(&root)?) == self.root_identity,
            "recovery directory changed",
        )?;
        require(
            Fingerprint::of(&rustix::fs::statat(
                &root,
                self.record_name,
                AtFlags::SYMLINK_NOFOLLOW,
            )?) == self.record_fingerprint,
            "recovery identity changed before handoff",
        )?;
        let request = open_directory(&self.request_folder)?;
        require(
            Identity::of(&rustix::fs::fstat(&request)?) == self.request_folder_identity,
            "prepared request directory changed",
        )?;
        require(
            Fingerprint::of(&rustix::fs::statat(
                &request,
                "request.json",
                AtFlags::SYMLINK_NOFOLLOW,
            )?) == self.request_fingerprint,
            "recovery request changed before handoff",
        )
    }

    fn inspection(&self) -> Value {
        json!({
            "kind": "rabs-remote-recovery-intent", "directory": self.root,
            "request_id": self.request_id, "action_key": self.action_key,
            "origin": self.origin, "worker_id": self.worker, "listen": self.listen,
            "transport_state_dir": self.state, "outputs_verified": false,
            "publication_authorized": false, "reexecute": false,
        })
    }
}

/// A daemon job retains allocation intent, not a worker request. Its durable
/// owner alone knows which request/worker/result currently belongs to the job.
/// Recovery must not reopen a source bundle or bypass that owner through TLS.
#[derive(Debug)]
struct JobIntent {
    root: PathBuf,
    id: String,
    socket: PathBuf,
    live_stderr: bool,
    root_identity: Identity,
    record_fingerprint: Fingerprint,
}

impl JobIntent {
    fn verify_unchanged(&self) -> Result<()> {
        let root = open_directory(&self.root)?;
        require(
            Identity::of(&rustix::fs::fstat(&root)?) == self.root_identity,
            "daemon job directory changed",
        )?;
        require(
            Fingerprint::of(&rustix::fs::statat(
                &root,
                "operation.json",
                AtFlags::SYMLINK_NOFOLLOW,
            )?) == self.record_fingerprint,
            "daemon job identity changed before handoff",
        )
    }

    fn inspection(&self) -> Value {
        json!({
            "kind":"rabs-daemon-job-intent", "directory":self.root,
            "origin":"canonical-cargo-daemon", "job_id":self.id,
            "request_id":"allocate", "daemon_socket":self.socket,
            "live_stderr":self.live_stderr, "job_status_queried":false,
            "outputs_verified":false, "publication_authorized":false, "reexecute":false,
        })
    }
}

enum RetainedIntent {
    Direct(Box<Intent>),
    Job(Box<JobIntent>),
}

fn saved_job_argv<'a>(record: &'a Value, field: &str, length: usize) -> Result<Vec<&'a str>> {
    let arguments = record[field].as_array().ok_or(Refused(
        "daemon job changed its fixed native command contract",
    ))?;
    require(
        arguments.len() == length,
        "daemon job changed its fixed native command contract",
    )?;
    arguments
        .iter()
        .map(|value| {
            let argument = string(value, "invalid saved daemon job argument")?;
            require(
                !argument.is_empty()
                    && argument.chars().count() <= 4096
                    && !argument.contains('\0'),
                "invalid saved daemon job argument",
            )?;
            Ok(argument)
        })
        .collect()
}

fn job_worker(address: &str, worker: &str, pin: &str) -> Result<(IpAddr, u16)> {
    require(
        address.len() <= 128
            && !worker.is_empty()
            && worker.len() <= 128
            && worker.as_bytes()[0].is_ascii_alphanumeric()
            && worker
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')),
        "invalid recorded daemon worker endpoint",
    )?;
    worker_identity(worker, pin)?;
    let endpoint: SocketAddr = listener(address)?
        .parse()
        .map_err(|_| Refused("invalid recorded daemon worker endpoint"))?;
    let ip = match endpoint.ip() {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4),
        ip => ip,
    };
    Ok((ip, endpoint.port()))
}

fn validate_job_pool(value: &Value) -> Result<()> {
    let pool = value
        .as_array()
        .filter(|pool| (1..=32).contains(&pool.len()))
        .ok_or(Refused("daemon job requires a bounded worker pool"))?;
    let mut endpoints = Vec::<(IpAddr, u16)>::new();
    let mut workers = BTreeSet::new();
    let mut pins = BTreeSet::new();
    for entry in pool {
        let fields = entry
            .as_object()
            .ok_or(Refused("invalid recorded daemon worker pool"))?;
        require(
            fields.len() == 3
                && ["address", "worker", "worker_spki_sha256"]
                    .iter()
                    .all(|key| fields.contains_key(*key)),
            "invalid recorded daemon worker pool",
        )?;
        let address = string(&entry["address"], "invalid recorded daemon worker endpoint")?;
        let worker = string(&entry["worker"], "invalid recorded daemon worker identity")?;
        let pin = string(
            &entry["worker_spki_sha256"],
            "invalid recorded daemon worker pin",
        )?;
        let (ip, port) = job_worker(address, worker, pin)?;
        require(
            workers.insert(worker)
                && pins.insert(pin)
                && !endpoints.iter().any(|(other_ip, other_port)| {
                    port == *other_port
                        && (ip == *other_ip || ip.is_unspecified() || other_ip.is_unspecified())
                }),
            "daemon worker pool repeats a listener, worker identity or pin",
        )?;
        endpoints.push((ip, port));
    }
    Ok(())
}

fn load_job_intent(
    root: PathBuf,
    record: &Value,
    root_identity: Identity,
    record_fingerprint: Fingerprint,
) -> Result<JobIntent> {
    const REQUIRED: &[&str] = &[
        "version",
        "request_id",
        "operation_directory",
        "automatic_retry",
        "publication_authorized",
        "job_id",
        "daemon_socket",
        "job_submit_argv",
        "job_status_argv",
        "job_wait_argv",
        "job_cancel_argv",
    ];
    let fields = record
        .as_object()
        .ok_or(Refused("invalid daemon job record"))?;
    require(
        REQUIRED.iter().all(|key| fields.contains_key(*key))
            && fields.keys().all(|key| {
                REQUIRED.contains(&key.as_str())
                    || matches!(key.as_str(), "worker_pool" | "live_stderr")
            }),
        "daemon job record has missing, mixed or unsupported fields",
    )?;
    let id = string(&record["job_id"], "invalid daemon job identity")?;
    let name = format!("cargo-{id}");
    require(
        id.len() == 32
            && id
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
            && root.file_name() == Some(OsStr::new(&name))
            && record["request_id"] == "allocate",
        "invalid daemon job identity or allocation intent",
    )?;
    let live_stderr = match record.get("live_stderr") {
        None => false,
        Some(value) => value
            .as_bool()
            .ok_or(Refused("invalid daemon job live output policy"))?,
    };
    let pooled = record.get("worker_pool").is_some();
    let submit = saved_job_argv(record, "job_submit_argv", if pooled { 7 } else { 9 })?;
    absolute(submit[0])?;
    require(
        submit[1]
            == if pooled {
                "--job-submit-pool"
            } else {
                "--job-submit-allocated"
            }
            && submit[2] == id,
        "daemon job changed its fixed submission intent",
    )?;
    for (field, action) in [
        ("job_status_argv", "--job-status"),
        ("job_cancel_argv", "--job-cancel"),
        ("job_wait_argv", "--job-wait"),
    ] {
        let live = field == "job_wait_argv" && live_stderr;
        let saved = saved_job_argv(record, field, if live { 4 } else { 3 })?;
        let expected = if live {
            vec![action, "--live-stderr", id]
        } else {
            vec![action, id]
        };
        require(
            saved[0] == submit[0] && saved[1..] == expected,
            "daemon job changed its fixed control intent",
        )?;
    }
    for (saved, name) in submit[submit.len() - 3..]
        .iter()
        .zip(["bundle", "delivery", "outputs"])
    {
        require(
            same_path(Path::new(saved), &root.join(name)),
            "daemon job changed its retained bundle or result paths",
        )?;
    }
    if pooled {
        require(
            same_path(Path::new(submit[3]), &root.join("pool.json")),
            "daemon job changed its fixed worker pool path",
        )?;
        validate_job_pool(&record["worker_pool"])?;
    } else {
        job_worker(submit[3], submit[4], submit[5])?;
    }
    let socket = absolute_value(&record["daemon_socket"])?;
    require(
        socket.as_os_str().as_encoded_bytes().len() < 108 && !paths_overlap(&root, &socket),
        "invalid recorded daemon socket path",
    )?;
    let intent = JobIntent {
        root,
        id: id.into(),
        socket,
        live_stderr,
        root_identity,
        record_fingerprint,
    };
    intent.verify_unchanged()?;
    Ok(intent)
}

fn job_endpoint(socket: &Path) -> Result<(Identity, Identity)> {
    let parent = open_directory(
        socket
            .parent()
            .ok_or(Refused("daemon socket has no parent"))?,
    )?;
    let parent_metadata = rustix::fs::fstat(&parent)?;
    require(
        parent_metadata.st_uid == rustix::process::geteuid().as_raw()
            && parent_metadata.st_mode & 0o022 == 0,
        "daemon socket parent must belong to this user and not be writable by others",
    )?;
    let metadata = rustix::fs::statat(
        &parent,
        socket
            .file_name()
            .ok_or(Refused("daemon socket has no name"))?,
        AtFlags::SYMLINK_NOFOLLOW,
    )?;
    require(
        FileType::from_raw_mode(metadata.st_mode) == FileType::Socket
            && metadata.st_uid == rustix::process::geteuid().as_raw()
            && metadata.st_mode & 0o077 == 0,
        "daemon job requires its existing private Unix socket",
    )?;
    Ok((Identity::of(&parent_metadata), Identity::of(&metadata)))
}

fn load_live_intent(root: PathBuf) -> Result<Intent> {
    let state = root
        .parent()
        .ok_or(Refused("recovery state is unavailable"))?
        .to_path_buf();
    let state_fd = open_directory(&state)?;
    let state_identity = Identity::of(&rustix::fs::fstat(&state_fd)?);
    require(
        state_identity.uid == rustix::process::geteuid().as_raw(),
        "transport state belongs to another user",
    )?;
    let name = root
        .file_name()
        .ok_or(Refused("recovery directory is unavailable"))?;
    let root_fd = rustix::fs::openat(&state_fd, name, directory_flags(), Mode::empty())?;
    let root_metadata = rustix::fs::fstat(&root_fd)?;
    require(
        root_metadata.st_uid == rustix::process::geteuid().as_raw()
            && root_metadata.st_mode & 0o077 == 0,
        "recovery directory must be private to the current user",
    )?;
    let (record_bytes, record_fingerprint) = read_record(&root_fd, "recovery.json")?;
    let (request_bytes, request_fingerprint) = read_record(&root_fd, "request.json")?;
    let record = decode(&record_bytes)?;
    let request = decode(&request_bytes)?;
    require(
        record["schema"] == LIVE_SCHEMA
            && record["recovery_mode"] == "resume-or-acknowledge-only"
            && record["execution_state"] == "unknown"
            && record["reexecute"] == false
            && record["publication_authorized"] == false,
        "unsupported recovery schema or authority policy",
    )?;
    require(
        record["request_file"] == "request.json" && record["partial_delivery"] == "delivery",
        "recovery record changed its fixed file names",
    )?;
    require(
        same_path(&absolute_value(&record["transport_state_dir"])?, &state),
        "recovery directory must remain in its original transport state directory",
    )?;
    let request_id = record["request_id"]
        .as_u64()
        .filter(|id| *id != 0)
        .ok_or(Refused("request identity mismatch"))?;
    require(
        request["request_id"].as_u64() == Some(request_id) && request["kind"] == "canonical-exec",
        "request identity mismatch",
    )?;
    let saved_digest = string(&record["request_sha256"], "saved request digest mismatch")?;
    require(
        hex_digest(saved_digest) && digest(&request_bytes) == saved_digest,
        "saved request digest mismatch",
    )?;
    let action_key = string(
        &record["action_key"],
        "missing or oversized action identity",
    )?;
    require(
        !action_key.is_empty() && action_key.chars().count() <= 512,
        "missing or oversized action identity",
    )?;
    let config = &record["remote_configuration"];
    require(
        config.is_object() && config["remote_protocol"].as_u64() == Some(1),
        "unsupported remote configuration",
    )?;
    let worker = string(&config["worker_id"], "invalid recorded worker identity")?;
    let pin = string(
        &config["worker_spki_sha256"],
        "invalid recorded worker SPKI pin",
    )?;
    worker_identity(worker, pin)?;
    let listen = listener(string(
        &config["listen"],
        "missing recorded worker listener",
    )?)?;
    let root_identity = Identity::of(&root_metadata);
    let intent = Intent {
        request_folder: root.clone(),
        request_folder_identity: root_identity,
        root,
        state,
        request: request_bytes,
        request_id,
        action_key: Some(action_key.into()),
        worker: worker.into(),
        pin: pin.into(),
        listen: listen.into(),
        root_identity,
        state_identity,
        record_fingerprint,
        request_fingerprint,
        record_name: "recovery.json",
        origin: "live-dependency",
    };
    intent.verify_unchanged()?;
    Ok(intent)
}

fn canonical_state(
    record: &Value,
    root: &Path,
    override_state: Option<&OsStr>,
    peer: [&str; 3],
) -> Result<PathBuf> {
    let state = if let Some(recovery) = record.get("recovery") {
        let expected = [
            "schema",
            "transport_state_dir",
            "request_file",
            "partial_delivery",
            "recovery_mode",
            "worker_id",
            "worker_spki_sha256",
            "listen",
            "reexecute",
            "publication_authorized",
        ];
        let fields = recovery
            .as_object()
            .ok_or(Refused("invalid canonical recovery fields"))?;
        require(
            fields.len() == expected.len() && expected.iter().all(|key| fields.contains_key(*key)),
            "invalid canonical recovery fields",
        )?;
        require(
            recovery["schema"] == CANONICAL_SCHEMA
                && recovery["request_file"] == "bundle/request.json"
                && recovery["partial_delivery"] == "delivery"
                && recovery["recovery_mode"] == "resume-or-acknowledge-only"
                && recovery["reexecute"] == false
                && recovery["publication_authorized"] == false
                && recovery["listen"] == peer[0]
                && recovery["worker_id"] == peer[1]
                && recovery["worker_spki_sha256"] == peer[2],
            "canonical recovery identity or authority mismatch",
        )?;
        let state = absolute_value(&recovery["transport_state_dir"])?;
        if let Some(selected) = override_state {
            require(
                same_path(&absolute_os(selected)?, &state),
                "cannot replace the recorded canonical admission state",
            )?;
        }
        state
    } else {
        absolute_os(override_state.ok_or(Refused(
            "older canonical operation requires --canonical-state-dir with its ORIGINAL admission state",
        ))?)?
    };
    require(
        !paths_overlap(root, &state),
        "canonical admission state and operation must not overlap",
    )?;
    Ok(state)
}

fn load_canonical_intent(root: PathBuf, override_state: Option<&OsStr>) -> Result<RetainedIntent> {
    let root_fd = open_directory(&root)?;
    let root_metadata = rustix::fs::fstat(&root_fd)?;
    require(
        root_metadata.st_uid == rustix::process::geteuid().as_raw()
            && root_metadata.st_mode & 0o077 == 0,
        "canonical operation must be private to the current user",
    )?;
    let (record_bytes, record_fingerprint) = read_record(&root_fd, "operation.json")?;
    let record = decode(&record_bytes)?;
    require(
        record["version"] == "canonical-cargo-v1"
            && same_path(&absolute_value(&record["operation_directory"])?, &root)
            && record["automatic_retry"] == false
            && record["publication_authorized"] == false,
        "unsupported canonical operation or recovery authority",
    )?;
    if [
        "job_id",
        "daemon_socket",
        "job_submit_argv",
        "job_status_argv",
        "job_wait_argv",
        "job_cancel_argv",
        "worker_pool",
        "live_stderr",
    ]
    .iter()
    .any(|key| record.get(*key).is_some())
    {
        require(
            override_state.is_none(),
            "daemon jobs retain their own admission state; no state override is allowed",
        )?;
        return load_job_intent(
            root,
            &record,
            Identity::of(&root_metadata),
            record_fingerprint,
        )
        .map(|intent| RetainedIntent::Job(Box::new(intent)));
    }
    let argv = record["prepared_build_argv"].as_array().ok_or(Refused(
        "canonical operation changed its fixed prepared-build contract",
    ))?;
    require(
        argv.len() == 9
            && argv.iter().all(|arg| {
                arg.as_str().is_some_and(|arg| {
                    !arg.is_empty() && arg.chars().count() <= 4096 && !arg.contains('\0')
                })
            }),
        "canonical operation changed its fixed prepared-build contract",
    )?;
    require(
        argv[1] == "--worker-build-tls"
            && argv[2] == "--replay-diagnostics"
            && argv[6]
                == root
                    .join("bundle")
                    .to_str()
                    .ok_or(Refused("paths must be UTF-8"))?
            && argv[7]
                == root
                    .join("delivery")
                    .to_str()
                    .ok_or(Refused("paths must be UTF-8"))?
            && argv[8]
                == root
                    .join("outputs")
                    .to_str()
                    .ok_or(Refused("paths must be UTF-8"))?,
        "canonical operation changed its fixed prepared-build contract",
    )?;
    let listen = listener(string(&argv[3], "missing recorded worker listener")?)?;
    let worker = string(&argv[4], "invalid recorded worker identity")?;
    let pin = string(&argv[5], "invalid recorded worker SPKI pin")?;
    worker_identity(worker, pin)?;
    let state = canonical_state(&record, &root, override_state, [listen, worker, pin])?;
    let bundle_fd = rustix::fs::openat(&root_fd, "bundle", directory_flags(), Mode::empty())?;
    let bundle_metadata = rustix::fs::fstat(&bundle_fd)?;
    require(
        bundle_metadata.st_uid == rustix::process::geteuid().as_raw()
            && bundle_metadata.st_mode & 0o077 == 0,
        "prepared request directory must be private",
    )?;
    let (request_bytes, request_fingerprint) = read_record(&bundle_fd, "request.json")?;
    let request = decode(&request_bytes)?;
    let request_id = request["request_id"]
        .as_u64()
        .filter(|id| *id != 0)
        .ok_or(Refused(
            "canonical recovery needs the prepared numeric request, not allocation intent",
        ))?;
    require(
        request["kind"] == "canonical-exec",
        "canonical recovery needs the prepared numeric request, not allocation intent",
    )?;
    require(
        record["request_id"] == "allocate" || record["request_id"].as_u64() == Some(request_id),
        "prepared request differs from canonical operation identity",
    )?;
    let artifacts = &request["artifacts"];
    let cargo_formats = [
        "cargo-json-v1",
        "cargo-test-json-v1",
        "cargo-run-json-v1",
        "cargo-bench-json-v1",
        "cargo-private-incremental-json-v1",
        "cargo-private-incremental-test-json-v1",
        "cargo-private-incremental-run-json-v1",
        "cargo-private-incremental-bench-json-v1",
    ];
    require(
        matches!(
            request["program"].as_str(),
            Some("/__rabs/toolchain/bin/cargo" | "/__rabs/toolchain/bin/cargo-clippy")
        ) && request["source_manifest"].is_object()
            && request.get("dependency_context").is_none()
            && artifacts.is_object()
            && artifacts["unit"] == "cargo"
            && artifacts["tree"] == "tree-files-v1"
            && artifacts["cargo"]
                .as_str()
                .is_some_and(|format| cargo_formats.contains(&format)),
        "prepared request is not a canonical Cargo operation",
    )?;
    let state_fd = open_directory(&state)?;
    let state_metadata = rustix::fs::fstat(&state_fd)?;
    require(
        state_metadata.st_uid == rustix::process::geteuid().as_raw()
            && state_metadata.st_mode & 0o022 == 0,
        "canonical admission state has unsafe ownership or permissions",
    )?;
    let intent = Intent {
        request_folder: root.join("bundle"),
        request_folder_identity: Identity::of(&bundle_metadata),
        root,
        state,
        request: request_bytes,
        request_id,
        action_key: None,
        worker: worker.into(),
        pin: pin.into(),
        listen: listen.into(),
        root_identity: Identity::of(&root_metadata),
        state_identity: Identity::of(&state_metadata),
        record_fingerprint,
        request_fingerprint,
        record_name: "operation.json",
        origin: "canonical-cargo",
    };
    intent.verify_unchanged()?;
    Ok(RetainedIntent::Direct(Box::new(intent)))
}

fn load_intent(directory: &OsStr, override_state: Option<&OsStr>) -> Result<RetainedIntent> {
    let root = absolute_os(directory)?;
    let descriptor = open_directory(&root)?;
    let mut found = Vec::new();
    for name in ["recovery.json", "operation.json"] {
        match rustix::fs::statat(&descriptor, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => found.push(name),
            Err(rustix::io::Errno::NOENT) => {}
            Err(error) => return Err(error.into()),
        }
    }
    require(
        found.len() == 1,
        "directory must contain exactly one recovery intent format",
    )?;
    if found[0] == "recovery.json" {
        require(
            override_state.is_none(),
            "canonical state override cannot change dependency admission",
        )?;
        load_live_intent(root).map(|intent| RetainedIntent::Direct(Box::new(intent)))
    } else {
        load_canonical_intent(root, override_state)
    }
}

fn private_directory(path: &Path) -> Result<()> {
    let directory = open_directory(path)?;
    let metadata = rustix::fs::fstat(&directory)?;
    require(
        metadata.st_uid == rustix::process::geteuid().as_raw() && metadata.st_mode & 0o077 == 0,
        "delivery directory must be private to the current user",
    )
}

fn lexists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn operation(intent: &Intent, options: &Options) -> Result<(Vec<OsString>, PathBuf)> {
    if let Some(value) = &options.resume_to {
        let destination = absolute_os(value)?;
        let _parent = open_directory(
            destination
                .parent()
                .ok_or(Refused("resume parent is unavailable"))?,
        )?;
        require(
            !lexists(&destination)?,
            "resume destination must not already exist",
        )?;
        require(
            !paths_overlap(&intent.root, &destination),
            "recovery and resume directories must not overlap",
        )?;
        let previous = match &options.prefix_from {
            Some(value) => absolute_os(value)?,
            None => intent.root.join("delivery"),
        };
        require(
            !(options.no_prefix && options.prefix_from.is_some()),
            "conflicting prefix selection",
        )?;
        if options.prefix_from.is_some() {
            private_directory(&previous)?;
        }
        require(
            !paths_overlap(&previous, &destination),
            "resume prefix and destination must not overlap",
        )?;
        let flags = if !options.no_prefix && lexists(&previous)? {
            private_directory(&previous)?;
            vec!["--resume-from".into(), previous.into_os_string()]
        } else {
            vec!["--resume".into()]
        };
        Ok((flags, destination))
    } else {
        require(
            options.acknowledge.is_some() && !options.no_prefix && options.prefix_from.is_none(),
            "prefix selection requires --resume-to",
        )?;
        let destination = absolute_os(
            options
                .acknowledge
                .as_deref()
                .ok_or(Refused("acknowledgment destination is missing"))?,
        )?;
        private_directory(&destination)?;
        let descriptor = open_directory(&destination)?;
        // Structural preflight only. The native operator still verifies the
        // request, pinned provenance and every result byte before acknowledgment.
        read_record(&descriptor, "delivery.json")?;
        Ok((vec!["--acknowledge".into()], destination))
    }
}

fn executable(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|metadata| metadata.is_file())
        && rustix::fs::access(path, rustix::fs::Access::EXEC_OK).is_ok()
}

fn daemon_path(selected: Option<&OsStr>, current: &Path) -> Result<PathBuf> {
    let candidates = if let Some(selected) = selected {
        vec![PathBuf::from(selected)]
    } else if let Some(selected) = std::env::var_os("CARGO_RABS_DAEMON") {
        // Even an empty or unusable environment override is exclusive.
        vec![PathBuf::from(selected)]
    } else {
        let mut paths = vec![
            current
                .parent()
                .ok_or(Refused("recovery executable directory is unavailable"))?
                .join("rabsd"),
        ];
        let search = std::env::var_os("PATH").unwrap_or_else(|| "/bin:/usr/bin".into());
        paths.extend(std::env::split_paths(&search).map(|directory| directory.join("rabsd")));
        paths
    };
    for path in candidates {
        if executable(&path) {
            let metadata = fs::metadata(&path)?;
            let own_metadata = fs::metadata(current)?;
            require(
                metadata.dev() != own_metadata.dev() || metadata.ino() != own_metadata.ino(),
                "rabsd resolves to this recovery driver",
            )?;
            return std::path::absolute(path).map_err(Into::into);
        }
    }
    Err(Refused(
        "rabsd is not executable; select it with --rabsd or CARGO_RABS_DAEMON",
    ))
}

fn sealed_request(data: &[u8]) -> Result<File> {
    let descriptor = rustix::fs::memfd_create(
        "rabs-recovery-request",
        MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
    )?;
    // A caller may have closed stdin/stdout/stderr. Keep that state instead of
    // accidentally turning a standard descriptor into the request snapshot.
    let descriptor = if descriptor.as_raw_fd() < 3 {
        rustix::io::fcntl_dupfd_cloexec(&descriptor, 3)?
    } else {
        descriptor
    };
    let mut file = File::from(descriptor);
    file.write_all(data)?;
    file.seek(SeekFrom::Start(0))?;
    let seals = SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK | SealFlags::SEAL;
    rustix::fs::fcntl_add_seals(&file, seals)?;
    require(
        rustix::fs::fcntl_get_seals(&file)?.contains(seals),
        "request snapshot is not sealed",
    )?;
    require(
        fs::metadata(format!("/proc/self/fd/{}", file.as_raw_fd()))?.is_file(),
        "procfs request handoff is unavailable",
    )?;
    Ok(file)
}

fn job_operation(intent: &JobIntent, options: &Options) -> Result<Vec<OsString>> {
    if let Some(control) = options.job_control {
        let action = match control {
            JobControl::Wait => "--job-wait",
            JobControl::Status => "--job-status",
            JobControl::Cancel => "--job-cancel",
        };
        let mut arguments = vec![action.into()];
        if control == JobControl::Wait && intent.live_stderr {
            arguments.push("--live-stderr".into());
        }
        arguments.push(intent.id.clone().into());
        return Ok(arguments);
    }
    let (action, value, new) = if let Some(value) = &options.resume_to {
        ("--job-resume", value, true)
    } else if let Some(value) = &options.delivery {
        ("--job-recover-local", value, false)
    } else if let Some(value) = &options.acknowledge {
        ("--job-acknowledge", value, false)
    } else {
        return Err(Refused("select a daemon job operation"));
    };
    let destination = absolute_os(value)?;
    if new {
        open_directory(
            destination
                .parent()
                .ok_or(Refused("resume parent is unavailable"))?,
        )?;
        require(
            !lexists(&destination)?,
            "resume destination must not already exist",
        )?;
    } else {
        private_directory(&destination)?;
    }
    let bundle = intent.root.join("bundle");
    let output = intent.root.join("outputs");
    require(
        !paths_overlap(&destination, &bundle)
            && !paths_overlap(&destination, &output)
            && (!new || !paths_overlap(&destination, &intent.root.join("delivery"))),
        "daemon job delivery overlaps its retained bundle or outputs",
    )?;
    let mut arguments = vec![
        action.into(),
        intent.id.clone().into(),
        destination.clone().into(),
    ];
    if let Some(value) = &options.prefix_from {
        require(
            new && !options.no_prefix,
            "prefix selection requires a fresh resume destination",
        )?;
        let prefix = absolute_os(value)?;
        private_directory(&prefix)?;
        require(
            !paths_overlap(&prefix, &bundle)
                && !paths_overlap(&prefix, &output)
                && !paths_overlap(&prefix, &destination),
            "daemon job prefix overlaps retained inputs or its new destination",
        )?;
        arguments.push(prefix.into());
    }
    // The daemon owns receipt verification and all previous result attempts.
    // Only an explicitly selected prefix is forwarded; an old delivery path
    // is never guessed from allocation intent or treated as result evidence.
    Ok(arguments)
}

fn run_job(intent: &JobIntent, options: &Options, current_executable: &Path) -> Result<()> {
    if options.job_control.is_none()
        && options.resume_to.is_none()
        && options.delivery.is_none()
        && options.acknowledge.is_none()
    {
        intent.verify_unchanged()?;
        writeln!(io::stdout().lock(), "{}", intent.inspection())?;
        return Ok(());
    }
    let arguments = job_operation(intent, options)?;
    let daemon = daemon_path(options.daemon.as_deref(), current_executable)?;
    let endpoint = job_endpoint(&intent.socket)?;
    intent.verify_unchanged()?;
    require(
        job_endpoint(&intent.socket)? == endpoint,
        "daemon socket changed before handoff",
    )?;
    // The same durable owner retains the numeric worker request, authentication
    // and execution frontier. No client TLS credentials, input recapture or
    // submission path belongs in this handoff, including after a lost reply.
    let error = Command::new(daemon)
        .args(arguments)
        .env("RABS_SOCKET_PATH", &intent.socket)
        .env("CARGO_RABS_CANONICAL_ACTIVE", "1")
        .exec();
    Err(error.into())
}

pub(crate) fn run(options: &Options, current_executable: &Path) -> Result<()> {
    let intent = match load_intent(&options.directory, options.canonical_state.as_deref())? {
        RetainedIntent::Direct(intent) => intent,
        RetainedIntent::Job(intent) => return run_job(&intent, options, current_executable),
    };
    require(
        options.job_control.is_none() && options.delivery.is_none(),
        "wait, status, cancellation and local delivery recovery require a daemon-owned job",
    )?;
    if options.resume_to.is_none() && options.acknowledge.is_none() {
        writeln!(io::stdout().lock(), "{}", intent.inspection())?;
        return Ok(());
    }
    let (flags, destination) = operation(&intent, options)?;
    let daemon = daemon_path(options.daemon.as_deref(), current_executable)?;
    for name in [
        "RABS_COORD_TLS_CA",
        "RABS_COORD_TLS_CERT",
        "RABS_COORD_TLS_KEY",
    ] {
        let credential = std::env::var_os(name)
            .filter(|value| !value.is_empty())
            .ok_or(Refused(
                "recovery requires explicit coordinator TLS credentials",
            ))?;
        absolute_os(&credential)?;
    }
    intent.verify_unchanged()?;
    let request = sealed_request(&intent.request)?;
    let mut command = Command::new(daemon);
    command
        .arg("--worker-exec-tls")
        .args(flags)
        .arg(&intent.listen)
        .arg(&intent.worker)
        .arg(&intent.pin)
        .arg(format!("/proc/self/fd/{}", request.as_raw_fd()))
        .arg(destination)
        .env("RABS_STATE_DIR", &intent.state);
    rustix::io::fcntl_setfd(&request, rustix::io::FdFlags::empty())?;
    // Success replaces this process. Failure is terminal, with no other peer
    // selection, retry, state mutation, or execution permission.
    Err(command.exec().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn retained_job_intent() -> JobIntent {
        let parent = tempfile::Builder::new()
            .prefix("rjob-intent-")
            .tempdir()
            .unwrap()
            .keep();
        let id = "0123456789abcdef0123456789abcdef";
        let root = parent.join(format!("cargo-{id}"));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let record = json!({
            "version":"canonical-cargo-v1", "request_id":"allocate", "operation_directory":root,
            "automatic_retry":false, "publication_authorized":false, "job_id":id,
            "daemon_socket":parent.join("offline.socket"),
            "job_submit_argv":["/saved/rabsd", "--job-submit-allocated", id,
                "127.0.0.1:7443", "worker", "12".repeat(32), root.join("bundle"),
                root.join("delivery"), root.join("outputs")],
            "job_status_argv":["/saved/rabsd", "--job-status", id],
            "job_wait_argv":["/saved/rabsd", "--job-wait", id],
            "job_cancel_argv":["/saved/rabsd", "--job-cancel", id],
        });
        let path = root.join("operation.json");
        fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        let RetainedIntent::Job(intent) = load_intent(root.as_os_str(), None).unwrap() else {
            panic!("expected daemon-owned intent");
        };
        *intent
    }

    #[test]
    fn daemon_job_handoff_revalidation_rejects_replaced_directory_and_record() {
        for changed in ["directory", "record", "record-mode", "record-content"] {
            let intent = retained_job_intent();
            let record = intent.root.join("operation.json");
            match changed {
                "directory" => {
                    fs::rename(
                        &intent.root,
                        intent.root.with_file_name("retained-operation"),
                    )
                    .unwrap();
                    fs::create_dir(&intent.root).unwrap();
                    fs::set_permissions(&intent.root, fs::Permissions::from_mode(0o700)).unwrap();
                }
                "record" => {
                    let retained = intent.root.join("retained-record");
                    fs::rename(&record, &retained).unwrap();
                    fs::copy(retained, record).unwrap();
                }
                "record-mode" => {
                    fs::set_permissions(record, fs::Permissions::from_mode(0o640)).unwrap()
                }
                "record-content" => fs::write(record, b"changed job identity").unwrap(),
                _ => unreachable!(),
            }
            assert!(intent.verify_unchanged().is_err(), "{changed}");
        }
    }

    #[test]
    fn daemon_endpoint_identity_distinguishes_replacement_from_the_checked_owner() {
        let root = tempfile::Builder::new()
            .prefix("rjob-sock-")
            .tempdir()
            .unwrap()
            .keep();
        let socket = root.join("socket");
        let _first = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
        let original = job_endpoint(&socket).unwrap();
        fs::rename(&socket, root.join("retained-socket")).unwrap();
        let _second = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
        assert_ne!(job_endpoint(&socket).unwrap(), original);
    }

    fn retained_live_intent() -> Intent {
        let parent = tempfile::Builder::new()
            .prefix("rabs-recovery-witness-")
            .tempdir()
            .unwrap()
            .keep();
        let state = parent.join("state");
        let root = state.join("result");
        fs::create_dir(&state).unwrap();
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let request = br#"{"kind":"canonical-exec","request_id":1}"#;
        let record = json!({
            "schema":LIVE_SCHEMA, "recovery_mode":"resume-or-acknowledge-only", "execution_state":"unknown",
            "reexecute":false, "publication_authorized":false, "request_file":"request.json", "partial_delivery":"delivery",
            "transport_state_dir":state, "request_id":1, "request_sha256":digest(request), "action_key":"original",
            "remote_configuration":{"remote_protocol":1,"worker_id":"worker","worker_spki_sha256":"12".repeat(32),"listen":"127.0.0.1:7443"},
        });
        for (name, data) in [
            ("request.json", request.to_vec()),
            ("recovery.json", serde_json::to_vec(&record).unwrap()),
        ] {
            let path = root.join(name);
            fs::write(&path, data).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        load_live_intent(root).unwrap()
    }

    #[test]
    fn handoff_revalidation_rejects_replaced_state_root_record_and_request() {
        for changed in [
            "state",
            "root",
            "recovery.json",
            "request.json",
            "request-mode",
        ] {
            let intent = retained_live_intent();
            match changed {
                "state" => {
                    fs::rename(&intent.state, intent.state.with_file_name("retained-state"))
                        .unwrap();
                    fs::create_dir(&intent.state).unwrap();
                    fs::set_permissions(&intent.state, fs::Permissions::from_mode(0o700)).unwrap();
                }
                "root" => {
                    fs::rename(&intent.root, intent.state.join("retained-result")).unwrap();
                    fs::create_dir(&intent.root).unwrap();
                    fs::set_permissions(&intent.root, fs::Permissions::from_mode(0o700)).unwrap();
                }
                "request-mode" => fs::set_permissions(
                    intent.root.join("request.json"),
                    fs::Permissions::from_mode(0o640),
                )
                .unwrap(),
                name => {
                    let path = intent.root.join(name);
                    let retained = intent.state.join(format!("retained-{name}"));
                    fs::rename(&path, &retained).unwrap();
                    fs::copy(retained, path).unwrap();
                }
            }
            assert!(intent.verify_unchanged().is_err(), "{changed}");
        }
    }

    #[test]
    fn json_refuses_duplicate_nested_fields_nonfinite_and_nonobjects() {
        for input in [
            br#"{"kind":1,"kind":2}"#.as_slice(),
            br#"{"request":{"id":1,"id":2}}"#,
            br#"{"array":[{"id":1,"id":2}]}"#,
            br#"{"number":NaN}"#,
            br#"{"number":1e9999}"#,
            br#"[]"#,
            br#"{} {}"#,
        ] {
            assert!(decode(input).is_err(), "{input:?}");
        }
        let decoded = decode(br#"{"id":18446744073709551615,"fraction":1.0,"text":"ok"}"#).unwrap();
        assert_eq!(decoded["id"].as_u64(), Some(u64::MAX));
        assert_eq!(decoded["fraction"].as_u64(), None);
    }

    #[test]
    fn path_and_listener_domains_do_not_infer_authority() {
        for path in [
            "",
            "relative",
            "/",
            "///",
            "/root/./child",
            "/root/../child",
            "/root\0bad",
        ] {
            assert!(absolute(path).is_err(), "{path:?}");
        }
        assert_eq!(
            absolute("/state//result/").unwrap(),
            Path::new("/state/result")
        );
        assert_eq!(
            absolute("//state/result/").unwrap().as_os_str(),
            "//state/result"
        );
        for endpoint in [
            "localhost:443",
            "127.0.0.1:0",
            "127.0.0.1:65536",
            "::1:443",
            "[::1%lo]:443",
            "[127.0.0.1]:443",
            "127.0.0.1:+443",
        ] {
            assert!(listener(endpoint).is_err(), "{endpoint:?}");
        }
        for endpoint in ["127.0.0.1:443", "[::1]:443", "[2001:db8::1]:0443"] {
            assert_eq!(listener(endpoint).unwrap(), endpoint);
        }
    }

    #[test]
    fn snapshot_is_sealed_and_positioned_before_handoff() {
        let mut request = sealed_request(b"exact request\0bytes").unwrap();
        assert!(
            rustix::io::fcntl_getfd(&request)
                .unwrap()
                .contains(rustix::io::FdFlags::CLOEXEC)
        );
        let mut data = Vec::new();
        request.read_to_end(&mut data).unwrap();
        assert_eq!(data, b"exact request\0bytes");
        assert!(request.write_all(b"mutation").is_err());
        assert!(request.set_len(0).is_err());
        assert!(request.set_len(4096).is_err());
        assert!(
            rustix::fs::fcntl_get_seals(&request)
                .unwrap()
                .contains(SealFlags::SEAL | SealFlags::WRITE | SealFlags::SHRINK | SealFlags::GROW)
        );
    }
}
