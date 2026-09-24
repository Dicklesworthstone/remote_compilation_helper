//! Receiver for the worker's files-v1/ranges-v1 delivery protocols.
//!
//! This is byte delivery, not action-cache admission or publication. A worker's
//! identity and result are claims until the authenticated ATP path supplies its
//! own proof. Plaintext operator transport is deliberately restricted to loopback.
//! Nothing is installed into a Cargo target directory. A new private directory
//! receives all bytes; delivery.json is finalized only after complete verification
//! and filesystem sync. ACK loss after that frontier must never trigger execution
//! again. Failed directories are retained, never repaired in place or deleted.
//! Explicit resume may copy local prefixes, but verifies the complete new files.

mod reuse;
pub use reuse::{ResumePeer, ResumeSource};

use rabs_sandbox::artifact_tree::{
    MAX_TREE_ENTRIES, MAX_TREE_FILES, MAX_TREE_MANIFEST_BYTES, TREE_FILES_VERSION,
    validate_tree_names,
};
use rabs_sandbox::process_context::{
    COMMAND_CONTEXT_VERSION, CommandContext, MAX_COMMAND_ENV_ENTRIES,
};
use rabs_sandbox::toolchain_dataset::{TOOLCHAIN_DATASET_VERSION, ToolchainIdentity};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

/// Shared wire bounds; these match the worker contract, not its Rust layouts.
pub const CHUNK_BYTES: usize = 65_536;
/// Aggregate receiver disk budget for artifacts AND both diagnostic streams.
pub const MAX_DELIVERY_BYTES: u64 = 1024 * 1024 * 1024;
/// Maximum UTF-8 JSON frame before parsing or allocating its decoded payload.
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;

/// Local operator intent, never inferred from a peer response or a failed run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryMode {
    /// Admit one new execution; use durable result retention when advertised.
    Execute,
    /// Retrieve a previously sealed result. No execution dispatch is permitted.
    Resume,
}

impl DeliveryMode {
    pub(crate) fn frame(self, request: &Value) -> Value {
        match self {
            Self::Execute => request.clone(),
            Self::Resume => {
                json!({"kind":"result-resume", "request_id":request["request_id"], "request":request})
            }
        }
    }
}

const RESULT_RETENTION: &str = "durable-result-v1";

/// Evidence supplied by a trusted transport adapter AFTER session admission.
/// Never deserialize this from a worker's JSON: labels and claimed peer IDs are
/// not transport proof. Authentication does not authorize cache publication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkerAuthentication {
    pub spki_sha256: [u8; 32],
    pub session_id: u64,
    pub identity_generation: u32,
}

/// Ordered, bounded message transport. Implementations must enforce a deadline
/// on the entire exchange, not restart the deadline for every received byte.
pub trait WorkerPeer {
    fn send(&mut self, frame: &Value) -> io::Result<()>;
    fn receive(&mut self) -> io::Result<Value>;

    /// Complete transport-specific admission before the first execution write.
    /// The default is the explicitly unauthenticated loopback protocol. Secure
    /// transports must verify the hello against their authenticated peer and
    /// complete the challenge before sending the selected session grant.
    fn negotiate(&mut self, _hello: &Value, grant: &Value) -> io::Result<()> {
        self.send(grant)
    }

    /// Only the trusted adapter may supply authenticated provenance. A worker
    /// cannot upgrade the receipt by adding fields to its hello or result.
    fn authentication(&self) -> Option<WorkerAuthentication> {
        None
    }

    /// Explicit LOCAL byte hints, never supplied by worker JSON. These are
    /// accepted only for result resume and still require complete-file hashing.
    fn resume_source(&self) -> Option<&ResumeSource> {
        None
    }
}

/// Verified local delivery, even when its final ACK response was lost.
#[derive(Debug)]
pub struct Delivery {
    pub directory: PathBuf,
    pub receipt: Value,
    pub acknowledgments_confirmed: bool,
    pub acknowledgment_error: Option<String>,
}

impl Delivery {
    /// Status output deliberately carries no cache-hit or publication claim.
    pub fn to_json(&self) -> Value {
        json!({"kind":"worker-delivery", "directory":self.directory,
            "receipt":self.receipt, "acknowledgments_confirmed":self.acknowledgments_confirmed,
            "acknowledgment_error":self.acknowledgment_error, "reexecute":false})
    }
}

/// Once sending execution begins, even a partial write is an uncertain run.
#[derive(Debug)]
pub struct DeliveryFailure {
    pub directory: PathBuf,
    pub execution_may_have_run: bool,
    pub detail: String,
}

impl std::fmt::Display for DeliveryFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} (execution_may_have_run={}; directory={})",
            self.detail,
            self.execution_may_have_run,
            self.directory.display()
        )
    }
}
impl std::error::Error for DeliveryFailure {}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn require(condition: bool, message: &str) -> io::Result<()> {
    if condition {
        Ok(())
    } else {
        Err(invalid(message))
    }
}
fn number(value: &Value, field: &str) -> io::Result<u64> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid(field))
}
fn text<'a>(value: &'a Value, field: &str) -> io::Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(field))
}
fn is_hex(value: &str, digits: usize) -> bool {
    value.len() == digits
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
fn digest(value: &Value, field: &str) -> io::Result<String> {
    let value = text(value, field)?;
    require(is_hex(value, 64), "non-canonical SHA-256")?;
    Ok(value.to_owned())
}
fn safe_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 1024
        && !name.contains(['\\', ':'])
        && !name.chars().any(char::is_control)
        && name.split('/').count() <= 32
        && name
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

#[derive(Debug, Clone)]
struct Declaration {
    unit: String,
    names: BTreeSet<String>,
    tree: bool,
}

fn declaration(request: &Value) -> io::Result<Option<Declaration>> {
    let Some(value) = request.get("artifacts") else {
        return Ok(None);
    };
    let tree = match value.get("tree") {
        None => false,
        Some(value) if value.as_str() == Some(TREE_FILES_VERSION) => true,
        Some(_) => return Err(invalid("unsupported artifact tree declaration")),
    };
    require(
        value.as_object().is_some_and(|v| v.len() == if tree { 3 } else { 2 }),
        "invalid artifact declaration",
    )?;
    let unit = text(value, "unit")?;
    require(
        !unit.is_empty()
            && unit.len() <= 64
            && unit != "."
            && unit != ".."
            && unit
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
        "unsafe unit",
    )?;
    let files = value
        .get("files")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("artifact files"))?;
    require(!files.is_empty() && files.len() <= 128, "artifact count")?;
    let mut names = BTreeSet::new();
    for file in files {
        let name = file.as_str().ok_or_else(|| invalid("artifact name"))?;
        require(
            safe_name(name) && names.insert(name.to_owned()),
            "unsafe or duplicate artifact name",
        )?;
    }
    for name in &names {
        let mut parent = Path::new(name).parent();
        while let Some(path) = parent {
            if let Some(path) = path.to_str() {
                require(!names.contains(path), "file is also an artifact directory")?;
            }
            parent = path.parent();
        }
    }
    if tree {
        validate_tree_names(names.iter().map(String::as_str))?;
    }
    Ok(Some(Declaration {
        unit: unit.to_owned(),
        names,
        tree,
    }))
}

/// Decode only the JSON transport shape here. The same sandbox type used by
/// the worker owns cwd, environment, reserved-name and byte-limit policy.
/// Keep the original request untouched: sorting or dropping empty values here
/// would change the durable execution/recovery fingerprint.
fn command_context(request: &Value) -> io::Result<Option<CommandContext>> {
    let Some(value) = request.get("command_context") else {
        return Ok(None);
    };
    let object = value
        .as_object()
        .filter(|object| object.len() == 3)
        .ok_or_else(|| invalid("command_context requires exactly version, cwd and env"))?;
    require(
        object.get("version").and_then(Value::as_str) == Some(COMMAND_CONTEXT_VERSION),
        "unsupported command_context version",
    )?;
    let cwd = text(value, "cwd")?;
    let env = object
        .get("env")
        .and_then(Value::as_object)
        .filter(|env| env.len() <= MAX_COMMAND_ENV_ENTRIES)
        .ok_or_else(|| invalid("command_context env must be a bounded string map"))?;
    let entries = env
        .iter()
        .map(|(name, value)| {
            value
                .as_str()
                .map(|value| (name.clone(), value.to_owned()))
                .ok_or_else(|| invalid("command_context env values must be strings"))
        })
        .collect::<io::Result<Vec<_>>>()?;
    CommandContext::new(cwd, entries)
        .map(Some)
        .map_err(|error| invalid(&error.to_string()))
}

/// Validate before listening, reserving disk, or sending execution. Unknown
/// top-level extensions remain in the exact request sent and fingerprinted.
pub fn validate_request(request: &Value) -> io::Result<()> {
    require(
        request.get("kind").and_then(Value::as_str) == Some("canonical-exec"),
        "expected canonical-exec",
    )?;
    number(request, "request_id")?;
    require(
        request.get("toolchain_source").is_none(),
        "toolchain_source is local preparation input, not an execution field",
    )?;
    let toolchain = toolchain_identity(request)?;
    let transferred_toolchain = toolchain_transfer(request)?;
    let fields: &[&str] = if transferred_toolchain {
        require(toolchain.is_some(), "toolchain transfer requires a complete identity")?;
        require(request.get("toolchain_backing").is_none(),
            "toolchain transfer cannot fall back to a worker path")?;
        require(request.get("source_manifest").is_some(),
            "toolchain transfer requires a prepared source manifest")?;
        &["program"]
    } else {
        &["program", "toolchain_backing"]
    };
    for field in fields {
        let value = text(request, field)?;
        require(
            !value.is_empty() && !value.contains('\0'),
            "invalid execution string",
        )?;
    }
    // The worker owns the backing directory for a transferred projection.
    // Validate its canonical manifest here, including the mutually exclusive
    // workspace_backing rule. Recovery validates identity without source bytes.
    if super::source_delivery::request_manifest(request)?.is_none() {
        let backing = text(request, "workspace_backing")?;
        require(
            !backing.is_empty() && !backing.contains('\0'),
            "invalid workspace backing",
        )?;
    }
    if let Some(args) = request.get("args") {
        require(
            args.as_array().is_some_and(|args| {
                args.iter()
                    .all(|arg| arg.as_str().is_some_and(|arg| !arg.contains('\0')))
            }),
            "invalid argv",
        )?;
    }
    if request.get("jobserver_grant").is_some() {
        number(request, "jobserver_grant")?;
    }
    if request.get("timeout_ms").is_some() {
        require(number(request, "timeout_ms")? > 0, "zero execution budget")?;
    }
    command_context(request)?;
    declaration(request)?;
    require(
        serde_json::to_vec(request)?.len() <= MAX_FRAME_BYTES,
        "request frame too large",
    )
}

/// A transferred compiler is selected explicitly and never by a worker hint.
/// Recovery retains this selection in request identity without needing bytes.
pub fn toolchain_transfer(request: &Value) -> io::Result<bool> {
    match request.get("toolchain_transfer") {
        None => Ok(false),
        Some(value) if value == rabs_sandbox::toolchain_transfer::TOOLCHAIN_TRANSFER_VERSION => Ok(true),
        Some(_) => Err(invalid("unsupported toolchain transfer selection")),
    }
}

/// Parse the exact expected dataset before any worker admission or source upload.
/// An absent identity permits unpinned execution; malformed identity is an error.
pub fn toolchain_identity(request: &Value) -> io::Result<Option<ToolchainIdentity>> {
    let Some(value) = request.get("toolchain_identity") else {
        return Ok(None);
    };
    require(
        value.as_object().is_some_and(|fields| fields.len() == 4),
        "toolchain_identity requires exactly version, sha256, files and bytes",
    )?;
    require(
        text(value, "version")? == TOOLCHAIN_DATASET_VERSION,
        "unsupported toolchain_identity version",
    )?;
    let digest = text(value, "sha256")?;
    require(
        is_hex(digest, 64),
        "toolchain_identity sha256 must be lowercase SHA-256",
    )?;
    let mut sha256 = [0u8; 32];
    for (index, byte) in sha256.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&digest[index * 2..index * 2 + 2], 16)
            .map_err(|_| invalid("invalid toolchain_identity sha256"))?;
    }
    Ok(Some(ToolchainIdentity {
        sha256,
        files: number(value, "files")?,
        bytes: number(value, "bytes")?,
    }))
}

pub(super) fn toolchain_identity_value(identity: &ToolchainIdentity) -> Value {
    json!({"version":TOOLCHAIN_DATASET_VERSION,
        "sha256":identity.sha256.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
        "files":identity.files,"bytes":identity.bytes})
}

#[derive(Clone)]
struct Item {
    name: String,
    len: u64,
    sha256: String,
    executable: bool,
}
struct Manifest {
    files: Vec<Item>,
    sha256: String,
    total: u64,
}
fn field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}
fn manifest(value: &Value, expected: &Declaration) -> io::Result<Manifest> {
    require(
        text(value, "unit")? == expected.unit,
        "artifact unit mismatch",
    )?;
    require(
        serde_json::to_vec(value)?.len() <= MAX_TREE_MANIFEST_BYTES,
        "artifact manifest exceeds its byte bound",
    )?;
    let rows = value
        .get("files")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("manifest files"))?;
    let names = if expected.tree {
        require(!rows.is_empty() && rows.len() <= MAX_TREE_FILES, "artifact tree file count")?;
        let paths = rows.iter().map(|row| text(row, "name")).collect::<io::Result<Vec<_>>>()?;
        let names = validate_tree_names(paths)?;
        require(expected.names.is_subset(&names), "missing required tree artifact")?;
        names
    } else {
        require(rows.len() == expected.names.len(), "artifact set mismatch")?;
        expected.names.clone()
    };
    let mut files = Vec::new();
    let mut total = 0_u64;
    let mut hasher = Sha256::new();
    field(&mut hasher, b"rabs.worker-artifact-manifest.v1");
    field(&mut hasher, expected.unit.as_bytes());
    hasher.update((rows.len() as u64).to_be_bytes());
    for (row, expected_name) in rows.iter().zip(&names) {
        require(
            text(row, "name")? == expected_name,
            "artifact names missing, extra or unsorted",
        )?;
        let len = number(row, "bytes")?;
        total = total
            .checked_add(len)
            .ok_or_else(|| invalid("artifact length overflow"))?;
        require(total <= MAX_DELIVERY_BYTES, "artifact budget exceeded")?;
        let executable = row
            .get("executable")
            .and_then(Value::as_bool)
            .ok_or_else(|| invalid("artifact mode"))?;
        let sha256 = digest(row, "sha256")?;
        field(&mut hasher, expected_name.as_bytes());
        hasher.update([u8::from(executable)]);
        hasher.update(len.to_be_bytes());
        field(&mut hasher, sha256.as_bytes());
        files.push(Item {
            name: expected_name.clone(),
            len,
            sha256,
            executable,
        });
    }
    let sha256: String = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    require(
        number(value, "total_bytes")? == total && digest(value, "manifest_sha256")? == sha256,
        "artifact manifest identity mismatch",
    )?;
    Ok(Manifest {
        files,
        sha256,
        total,
    })
}

/// The single manifest admission rule used by live delivery, local recovery
/// and CAS archive/restore. Exact declarations require equality. Tree requests
/// require a bounded, safe, canonical full set containing every required name.
/// Manifest identity validates descriptors; each consumer must still verify bytes.
pub(crate) fn verified_artifact_names(request: &Value, value: &Value) -> io::Result<BTreeSet<String>> {
    let expected = declaration(request)?.ok_or_else(|| invalid("missing artifact declaration"))?;
    Ok(manifest(value, &expected)?.files.into_iter().map(|file| file.name).collect())
}

/// Create each implied directory exactly once in a new, caller-owned output
/// root. Never use create_dir_all to silently merge case/normalization aliases
/// on the receiving filesystem. The complete path set is validated beforehand.
pub(crate) fn create_artifact_directories<'a>(
    root: &Path, names: impl IntoIterator<Item = &'a str>,
) -> io::Result<()> {
    let mut directories = BTreeSet::new();
    let mut files = 0_usize;
    for name in names {
        require(safe_name(name), "unsafe output path")?;
        files += 1;
        for parent in Path::new(name).ancestors().skip(1) {
            if !parent.as_os_str().is_empty() {
                directories.insert(parent.to_path_buf());
            }
        }
        require(files + directories.len() <= MAX_TREE_ENTRIES, "artifact tree entry count")?;
    }
    // Lexical path order puts parents before their descendants.
    for directory in directories {
        create_directory(&root.join(directory))?;
    }
    Ok(())
}

const MAX_HEARTBEAT_BURST: usize = 64;
const HEARTBEAT_WINDOW: Duration = Duration::from_secs(1);

fn receive(peer: &mut impl WorkerPeer, worker: &str) -> io::Result<Value> {
    receive_with_clock(peer, worker, Instant::now)
}

/// Bound telemetry RATE, not the lifetime of a legitimate compiler operation.
/// The transport owns the absolute execution/transfer/ACK deadline and checks
/// it on every receive, including buffered frames. This window never changes
/// that deadline. The clock seam lets tests exercise long waits without sleeps.
fn receive_with_clock(
    peer: &mut impl WorkerPeer,
    worker: &str,
    mut now: impl FnMut() -> Instant,
) -> io::Result<Value> {
    let mut window_start = now();
    let mut heartbeats = 0;
    loop {
        let value = peer.receive()?;
        if value.get("kind").and_then(Value::as_str) != Some("heartbeat") {
            return Ok(value);
        }
        require(text(&value, "worker_id")? == worker, "foreign heartbeat")?;
        let observed = now();
        if observed.saturating_duration_since(window_start) >= HEARTBEAT_WINDOW {
            window_start = observed;
            heartbeats = 0;
        }
        require(
            heartbeats < MAX_HEARTBEAT_BURST,
            "too much telemetry in one heartbeat window",
        )?;
        heartbeats += 1;
    }
}
fn create_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}
fn create_directory(path: &Path) -> io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}
fn sync_tree_directories(root: &Path) -> io::Result<()> {
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            sync_tree_directories(&entry.path())?;
        }
    }
    File::open(root)?.sync_all()
}

fn download(
    peer: &mut impl WorkerPeer,
    worker: &str,
    id: u64,
    item: &Item,
    manifest_hash: Option<&str>,
    path: &Path,
) -> io::Result<()> {
    const RANGE_WINDOW: usize = 4;
    let artifact = manifest_hash.is_some();
    let mut file = create_file(path)?;
    let mut hasher = Sha256::new();
    let mut offset = match peer.resume_source() {
        Some(source) => source.copy_prefix(
            if artifact { "artifacts" } else { "diagnostics" },
            &item.name, item.len, &mut file, &mut hasher,
        )?,
        None => 0,
    };
    // Empty files retain the ordinary zero-length range check. A complete
    // nonempty prefix skips range I/O, never the complete-file hash below.
    // Keep at most four ordinary range requests in flight. The worker serves
    // ordered immutable ranges; no new wire operation or speculative bytes are
    // needed. Drain each batch before writing more requests, and retain the
    // existing transport's one absolute transfer deadline throughout.
    let mut requested = offset;
    let mut outstanding = 0_usize;
    while offset < item.len || item.len == 0 {
        if outstanding == 0 {
            for _ in 0..RANGE_WINDOW {
                let mut request = json!({"kind":if artifact {"artifact-read"} else {"output-read"},
                    "request_id":id,"offset":requested,"max_bytes":CHUNK_BYTES});
                request[if artifact { "name" } else { "stream" }] = json!(item.name);
                // A partial write aborts the whole operation. Never retry the
                // batch or fall back to execution when its outcome is unknown.
                peer.send(&request)?;
                outstanding += 1;
                requested += (item.len - requested).min(CHUNK_BYTES as u64);
                if requested == item.len {
                    break;
                }
            }
        }
        let chunk = receive(peer, worker)?;
        require(
            text(&chunk, "kind")?
                == if artifact {
                    "artifact-chunk"
                } else {
                    "output-chunk"
                },
            "expected byte chunk",
        )?;
        require(
            number(&chunk, "request_id")? == id
                && text(&chunk, if artifact { "name" } else { "stream" })? == item.name
                && number(&chunk, "offset")? == offset
                && number(&chunk, "total_bytes")? == item.len
                && digest(&chunk, "sha256")? == item.sha256,
            "chunk identity mismatch",
        )?;
        if let Some(hash) = manifest_hash {
            require(
                digest(&chunk, "manifest_sha256")? == hash
                    && chunk.get("executable").and_then(Value::as_bool) == Some(item.executable),
                "chunk manifest/mode mismatch",
            )?;
        }
        let count = (item.len - offset).min(CHUNK_BYTES as u64) as usize;
        let encoded = text(&chunk, "data_hex")?;
        require(
            is_hex(encoded, count * 2),
            "chunk encoding or length mismatch",
        )?;
        let mut bytes = Vec::with_capacity(count);
        for pair in encoded.as_bytes().as_chunks::<2>().0 {
            let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
            bytes.push(digit(pair[0]) * 16 + digit(pair[1]));
        }
        let next = offset + count as u64; // bounded by declared length, never unchecked peer arithmetic
        require(
            number(&chunk, "next_offset")? == next
                && chunk.get("eof").and_then(Value::as_bool) == Some(next == item.len)
                && digest(&chunk, "chunk_sha256")? == hash(&bytes),
            "chunk range or digest mismatch",
        )?;
        file.write_all(&bytes)?;
        hasher.update(&bytes);
        offset = next;
        outstanding -= 1;
        if offset == item.len {
            break;
        }
    }
    let actual: String = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    require(actual == item.sha256, "complete file digest mismatch")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(if item.executable {
            0o700
        } else {
            0o600
        }))?;
    }
    file.sync_all()
}

fn acknowledge(
    peer: &mut impl WorkerPeer,
    worker: &str,
    frame: Value,
    expected_kind: &str,
) -> io::Result<()> {
    peer.send(&frame)?;
    let reply = receive(peer, worker)?;
    require(
        text(&reply, "kind")? == expected_kind
            && reply.get("request_id") == frame.get("request_id")
            && reply
                .get("already_released")
                .and_then(Value::as_bool)
                .is_some(),
        "acknowledgment mismatch",
    )
}

/// Execute ONCE and receive verified files into a new private directory. Only a
/// complete durable local receipt permits release ACKs. No error path resubmits
/// execution. Existing destinations are never touched, including empty ones.
///
/// Failed staging directories have no valid delivery.json and are not usable
/// builds. Local storage must support file/directory fsync. This routine blocks;
/// use it on an operator thread, not the daemon's asynchronous control reactor.
pub fn receive_execution(
    peer: &mut impl WorkerPeer,
    request: &Value,
    expected_worker: &str,
    destination: &Path,
) -> Result<Delivery, DeliveryFailure> {
    receive_operation(
        peer,
        request,
        expected_worker,
        destination,
        DeliveryMode::Execute,
    )
}

/// Receive one explicitly selected operation through the same byte verifier.
/// Resume sends only result-resume, never canonical-exec or a fallback request.
/// Its destination must be NEW. ResumePeer may supply untrusted local prefixes;
/// complete hashes from the current retained result still verify every byte.
/// The original command may already have run even if resume fails before
/// contacting a worker, so uncertainty remains true in that mode.
pub fn receive_operation(
    peer: &mut impl WorkerPeer,
    request: &Value,
    expected_worker: &str,
    destination: &Path,
    mode: DeliveryMode,
) -> Result<Delivery, DeliveryFailure> {
    let mut execution_may_have_run = mode == DeliveryMode::Resume;
    let outcome = (|| -> io::Result<Delivery> {
        validate_request(request)?;
        if let Some(source) = peer.resume_source() {
            require(mode == DeliveryMode::Resume, "local prefixes require explicit result resume")?;
            source.validate_destination(destination)?;
        }
        let dispatch = mode.frame(request);
        require(
            serde_json::to_vec(&dispatch)?.len() <= MAX_FRAME_BYTES,
            "operation frame too large",
        )?;
        require(!expected_worker.is_empty(), "empty expected worker")?;
        require(
            destination.is_absolute()
                && destination
                    .components()
                    .all(|c| matches!(c, Component::RootDir | Component::Normal(_))),
            "destination must be absolute without traversal",
        )?;
        let expected = declaration(request)?;
        let id = number(request, "request_id")?;
        let hello = peer.receive()?;
        require(
            text(&hello, "kind")? == "worker-hello"
                && text(&hello, "worker_id")? == expected_worker,
            "unexpected worker (claimed identity is not authentication)",
        )?;
        let supports = |field: &str, value: &str| {
            hello
                .get(field)
                .and_then(Value::as_array)
                .is_some_and(|items| items.iter().any(|item| item.as_str() == Some(value)))
        };
        require(
            hello.get("canonical").and_then(Value::as_bool) == Some(true)
                && number(&hello, "slots")? > 0
                && number(&hello, "boot_generation")? > 0
                && supports("recovery_protocols", "request-journal-v1")
                && supports("output_transfers", "ranges-v1"),
            "worker lacks required delivery/recovery capabilities",
        )?;
        // A context changes execution semantics. Older workers accept unknown
        // request fields, so silently forwarding it could run a different build.
        // Refuse before disk creation, authentication grants or source upload.
        // Resume only retrieves a sealed exact-request result; it must not require
        // the restarted worker to retain the capability to execute that request.
        if mode == DeliveryMode::Execute && request.get("command_context").is_some() {
            require(
                supports("command_contexts", COMMAND_CONTEXT_VERSION),
                "worker lacks required env-cwd-v1 command context capability",
            )?;
        }
        if mode == DeliveryMode::Execute && request.get("toolchain_identity").is_some() {
            require(
                supports("toolchain_datasets", TOOLCHAIN_DATASET_VERSION),
                "worker lacks required toolchain-dataset-v1 execution binding",
            )?;
        }
        if mode == DeliveryMode::Execute && toolchain_transfer(request)? {
            require(
                supports("toolchain_transfers", rabs_sandbox::toolchain_transfer::TOOLCHAIN_TRANSFER_VERSION),
                "worker lacks required toolchain-tree-v1 transfer capability",
            )?;
        }
        let incarnation = text(&hello, "incarnation")?;
        require(
            is_hex(incarnation, 32) && incarnation.bytes().any(|b| b != b'0'),
            "invalid worker incarnation",
        )?;
        if mode == DeliveryMode::Resume {
            require(
                hello.get("request_high_water").and_then(Value::as_u64) == Some(id),
                "resume does not name the worker's retained admission",
            )?;
        } else {
            match hello.get("request_high_water") {
                Some(Value::Null) => {}
                Some(value) => require(
                    value.as_u64().is_some_and(|last| id > last),
                    "request is already admitted or retired; reconcile instead of reexecuting",
                )?,
                None => return Err(invalid("missing durable request high-water")),
            }
        }
        let retention = supports("result_retentions", RESULT_RETENTION);
        require(
            mode != DeliveryMode::Resume || retention,
            "worker lacks durable result recovery",
        )?;
        if expected.is_some() {
            require(
                supports("artifact_transfers", "files-v1"),
                "worker lacks files-v1",
            )?;
        }
        // Atomic create, never exists-then-truncate. Everything written below is
        // in this caller-owned private tree; no peer controls a host root.
        create_directory(destination)?;
        create_directory(&destination.join("diagnostics"))?;
        create_directory(&destination.join("artifacts"))?;
        let mut ack = json!({"kind":"session-ok","output_transfer":"ranges-v1","recovery_protocol":"request-journal-v1"});
        if expected.is_some() {
            ack["artifact_transfer"] = json!("files-v1");
        }
        if retention {
            ack["result_retention"] = json!(RESULT_RETENTION);
        }
        peer.negotiate(&hello, &ack)?;
        let authentication = peer.authentication();
        require(mode != DeliveryMode::Execute || !toolchain_transfer(request)? || authentication.is_some(),
            "transferred toolchains require authenticated execution admission")?;
        execution_may_have_run = true; // before even a partially successful write
        peer.send(&dispatch)?;
        let result = receive(peer, expected_worker)?;
        require(
            text(&result, "kind")? == "exec-result" && number(&result, "request_id")? == id,
            "execution refused or returned an unexpected identity; do not resubmit",
        )?;
        if mode == DeliveryMode::Resume {
            require(
                result.get("resumed").and_then(Value::as_bool) == Some(true),
                "worker did not return an explicitly resumed result",
            )?;
        } else {
            require(
                result
                    .get("resumed")
                    .is_none_or(|value| value.as_bool() == Some(false)),
                "new execution unexpectedly returned a resumed result",
            )?;
        }
        let retained_digest = if retention {
            require(
                text(&result, "result_retention")? == RESULT_RETENTION,
                "worker did not seal negotiated result",
            )?;
            Some(digest(&result, "retained_result_sha256")?)
        } else {
            None
        };
        require(
            result.get("executed").and_then(Value::as_bool) == Some(true)
                && number(&result, "residual_group_members")? == 0,
            "execution incomplete or descendants unresolved",
        )?;
        let exit_code = result
            .get("exit_code")
            .and_then(Value::as_i64)
            .filter(|code| (0..=255).contains(code))
            .ok_or_else(|| invalid("invalid exit code"))?;
        let stop = result
            .get("stop_reason")
            .ok_or_else(|| invalid("missing stop reason"))?;
        require(
            stop.is_null()
                || matches!(
                    stop.as_str(),
                    Some("cancelled" | "deadline-exceeded" | "session-lost" | "lease-expired")
                ),
            "unknown interruption",
        )?;
        require(
            stop.is_null() || exit_code != 0,
            "interrupted success contradiction",
        )?;
        require(
            text(&result, "output_transfer")? == "ranges-v1"
                && result.get("output_ack_required").and_then(Value::as_bool) == Some(true),
            "missing complete diagnostics",
        )?;
        let stdout = Item {
            name: "stdout".into(),
            len: number(&result, "stdout_bytes")?,
            sha256: digest(&result, "stdout_sha256")?,
            executable: false,
        };
        let stderr = Item {
            name: "stderr".into(),
            len: number(&result, "stderr_bytes")?,
            sha256: digest(&result, "stderr_sha256")?,
            executable: false,
        };
        let mut total = stdout
            .len
            .checked_add(stderr.len)
            .ok_or_else(|| invalid("diagnostic length overflow"))?;
        let artifacts = if exit_code == 0 && stop.is_null() && expected.is_some() {
            require(
                text(&result, "artifact_transfer")? == "files-v1"
                    && result.get("artifact_ack_required").and_then(Value::as_bool) == Some(true),
                "missing requested artifacts",
            )?;
            Some(manifest(
                &result["artifact_manifest"],
                expected
                    .as_ref()
                    .ok_or_else(|| invalid("missing declaration"))?,
            )?)
        } else {
            require(
                result.get("artifact_ack_required").and_then(Value::as_bool) == Some(false)
                    && result.get("artifact_manifest").is_some_and(Value::is_null),
                "unexpected or failed-execution artifacts",
            )?;
            None
        };
        if let Some(manifest) = &artifacts {
            total = total
                .checked_add(manifest.total)
                .ok_or_else(|| invalid("delivery length overflow"))?;
        }
        require(
            total <= MAX_DELIVERY_BYTES,
            "aggregate delivery budget exceeded",
        )?;
        download(
            peer,
            expected_worker,
            id,
            &stdout,
            None,
            &destination.join("diagnostics/stdout"),
        )?;
        download(
            peer,
            expected_worker,
            id,
            &stderr,
            None,
            &destination.join("diagnostics/stderr"),
        )?;
        if let Some(manifest) = &artifacts {
            create_artifact_directories(
                &destination.join("artifacts"), manifest.files.iter().map(|file| file.name.as_str()),
            )?;
            for file in &manifest.files {
                let path = destination.join("artifacts").join(&file.name);
                download(
                    peer,
                    expected_worker,
                    id,
                    file,
                    Some(&manifest.sha256),
                    &path,
                )?;
            }
        }
        sync_tree_directories(destination)?;
        // Sync parent ancestry too: a power loss must not erase a newly linked
        // delivery directory after the worker has discarded its only copies.
        for parent in destination.ancestors().skip(1) {
            File::open(parent)?.sync_all()?;
        }
        let mut receipt = json!({"version":1,"kind":"verified-worker-delivery","request_id":id,
            "worker_id":expected_worker,"boot_generation":hello["boot_generation"],"incarnation":incarnation,
            "request_sha256":hash(&serde_json::to_vec(request)?),"exit_code":exit_code,"stop_reason":stop,
            "stdout_bytes":stdout.len,"stdout_sha256":stdout.sha256,
            "stderr_bytes":stderr.len,"stderr_sha256":stderr.sha256,
            "artifact_manifest":result["artifact_manifest"],"total_bytes":total,
            "transport_authenticated":authentication.is_some(),
            "worker_spki_sha256":authentication.map(|proof| proof.spki_sha256.iter()
                .map(|byte| format!("{byte:02x}")).collect::<String>()),
            "authenticated_session_id":authentication.map(|proof| proof.session_id),
            "identity_generation":authentication.map(|proof| proof.identity_generation),
            "publication_authorized":false,"reexecute":false});
        if let Some(digest) = retained_digest {
            receipt["result_retention"] = json!(RESULT_RETENTION);
            receipt["retained_result_sha256"] = json!(digest);
        }
        if mode == DeliveryMode::Resume {
            // The authenticated hello identifies this DELIVERY session, not the
            // process incarnation that executed before the worker restarted.
            receipt["resumed"] = json!(true);
            receipt["worker_identity_scope"] = json!("delivery-session");
            receipt["execution_boot_generation"] = Value::Null;
        }
        let receipt_bytes = serde_json::to_vec_pretty(&receipt)?;
        require(receipt_bytes.len() <= MAX_FRAME_BYTES, "delivery receipt exceeds recovery bound")?;
        let mut marker = create_file(&destination.join("delivery.pending"))?;
        marker.write_all(&receipt_bytes)?;
        marker.sync_all()?;
        drop(marker);
        std::fs::rename(
            destination.join("delivery.pending"),
            destination.join("delivery.json"),
        )?;
        File::open(destination)?.sync_all()?;
        // Crossing the local delivery frontier is independent of remote ACK
        // confirmation. Losing this response does not invalidate verified bytes.
        let acknowledgments = (|| -> io::Result<()> {
            acknowledge(
                peer,
                expected_worker,
                json!({"kind":"output-ack","request_id":id,
                "stdout_bytes":stdout.len,"stdout_sha256":stdout.sha256,
                "stderr_bytes":stderr.len,"stderr_sha256":stderr.sha256}),
                "output-acknowledged",
            )?;
            if let Some(manifest) = artifacts {
                acknowledge(
                    peer,
                    expected_worker,
                    json!({"kind":"artifact-ack","request_id":id,
                    "manifest_sha256":manifest.sha256,"total_bytes":manifest.total}),
                    "artifact-acknowledged",
                )?;
            }
            Ok(())
        })();
        Ok(Delivery {
            directory: destination.to_path_buf(),
            receipt,
            acknowledgments_confirmed: acknowledgments.is_ok(),
            acknowledgment_error: acknowledgments.err().map(|e| e.to_string()),
        })
    })();
    outcome.map_err(|error| DeliveryFailure {
        directory: destination.to_path_buf(),
        execution_may_have_run,
        detail: error.to_string(),
    })
}

#[cfg(all(test, unix))]
mod tests {
    mod tree_tests;

    use super::*;
    use std::collections::VecDeque;

    struct Script {
        replies: VecDeque<Value>,
        sent: Vec<Value>,
        destination: PathBuf,
        fail_send: Option<&'static str>,
    }
    impl WorkerPeer for Script {
        fn send(&mut self, frame: &Value) -> io::Result<()> {
            self.sent.push(frame.clone());
            if matches!(frame["kind"].as_str(), Some("output-ack" | "artifact-ack")) {
                let receipt: Value = serde_json::from_slice(&std::fs::read(
                    self.destination.join("delivery.json"),
                )?)?;
                assert_eq!(receipt["kind"], "verified-worker-delivery");
                assert_eq!(
                    std::fs::read(self.destination.join("diagnostics/stdout"))?,
                    b"diagnostic\0\xff"
                );
            }
            if frame["kind"].as_str() == self.fail_send {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "injected lost write",
                ));
            }
            Ok(())
        }
        fn receive(&mut self) -> io::Result<Value> {
            self.replies
                .pop_front()
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "lost reply"))
        }
    }
    fn request() -> Value {
        json!({"kind":"canonical-exec","request_id":7,"program":"rustc","args":["lib.rs"],
            "toolchain_backing":"/tc","workspace_backing":"/ws","artifacts":{"unit":"dep","files":["a"]}})
    }
    fn chunk(name: &str, bytes: &[u8], artifact: bool) -> Value {
        let mut frame = json!({"kind":if artifact {"artifact-chunk"} else {"output-chunk"},
            "request_id":7,"offset":0,"next_offset":bytes.len(),"total_bytes":bytes.len(),
            "sha256":hash(bytes),"chunk_sha256":hash(bytes),"eof":true,
            "data_hex":bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()});
        frame[if artifact { "name" } else { "stream" }] = json!(name);
        if artifact {
            frame["executable"] = json!(false);
            frame["manifest_sha256"] =
                json!("548324c3a5c96511944c6ec6af94ee9bbb6683170bb0143f9d99cd192f80bfd6");
        }
        frame
    }
    fn fixture(destination: &Path) -> Script {
        let output = b"diagnostic\0\xff";
        Script {
            destination: destination.to_path_buf(),
            sent: vec![],
            fail_send: None,
            replies: VecDeque::from([
                json!({"kind":"worker-hello","worker_id":"worker","canonical":true,"slots":4,
                "boot_generation":1,"incarnation":"00000000000000000000000000000001","request_high_water":null,
                "recovery_protocols":["request-journal-v1"],"output_transfers":["ranges-v1"],"artifact_transfers":["files-v1"]}),
                json!({"kind":"exec-result","request_id":7,"executed":true,"exit_code":0,
                "residual_group_members":0,"stop_reason":null,"output_transfer":"ranges-v1","output_ack_required":true,
                "stdout_bytes":output.len(),"stdout_sha256":hash(output),"stderr_bytes":0,"stderr_sha256":hash(b""),
                "artifact_transfer":"files-v1","artifact_ack_required":true,"artifact_manifest":{
                    "unit":"dep","files":[{"name":"a","bytes":4,"sha256":hash(b"A\0\xffB"),"executable":false}],
                    "total_bytes":4,"manifest_sha256":"548324c3a5c96511944c6ec6af94ee9bbb6683170bb0143f9d99cd192f80bfd6"}}),
                chunk("stdout", output, false),
                chunk("stderr", b"", false),
                chunk("a", b"A\0\xffB", true),
                json!({"kind":"output-acknowledged","request_id":7,"already_released":false}),
                json!({"kind":"artifact-acknowledged","request_id":7,"already_released":false}),
            ]),
        }
    }
    fn no_ack(peer: &Script) -> bool {
        !peer
            .sent
            .iter()
            .any(|v| matches!(v["kind"].as_str(), Some("output-ack" | "artifact-ack")))
    }

    #[test]
    fn complete_binary_delivery_is_durable_before_either_ack() {
        let parent = tempfile::tempdir().unwrap();
        let destination = parent.path().join("delivery");
        let mut peer = fixture(&destination);
        let delivery = receive_execution(&mut peer, &request(), "worker", &destination).unwrap();
        assert!(delivery.acknowledgments_confirmed);
        assert!(peer.replies.is_empty());
        assert_eq!(
            std::fs::read(destination.join("artifacts/a")).unwrap(),
            b"A\0\xffB"
        );
        assert_eq!(delivery.receipt["publication_authorized"], false);
        assert_eq!(delivery.receipt["transport_authenticated"], false);
        assert_eq!(
            peer.sent
                .iter()
                .filter(|v| v["kind"] == "canonical-exec")
                .count(),
            1
        );
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(destination.join("artifacts/a"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(&destination)
                .unwrap()
                .permissions()
                .mode()
                & 0o077,
            0
        );
    }

    #[test]
    fn mismatched_chunks_never_ack_or_form_a_delivery() {
        for (field, value) in [
            ("request_id", json!(8)),
            ("offset", json!(1)),
            ("next_offset", json!(3)),
            ("total_bytes", json!(5)),
            ("name", json!("../secret")),
            ("executable", json!(true)),
            ("data_hex", json!("4100ff43")),
            ("eof", json!(false)),
            ("sha256", json!("00".repeat(32))),
            ("chunk_sha256", json!("00".repeat(32))),
            ("manifest_sha256", json!("00".repeat(32))),
        ] {
            let parent = tempfile::tempdir().unwrap();
            let dest = parent.path().join("delivery");
            let mut peer = fixture(&dest);
            peer.replies[4][field] = value;
            let error = receive_execution(&mut peer, &request(), "worker", &dest).unwrap_err();
            assert!(error.execution_may_have_run, "{field}");
            assert!(no_ack(&peer), "{field}");
            assert!(!dest.join("delivery.json").exists(), "{field}");
        }
    }

    #[test]
    fn valid_chunk_hash_does_not_substitute_for_complete_file_hash() {
        let parent = tempfile::tempdir().unwrap();
        let dest = parent.path().join("delivery");
        let mut peer = fixture(&dest);
        peer.replies[4]["data_hex"] = json!("4100ff43");
        peer.replies[4]["chunk_sha256"] = json!(hash(b"A\0\xffC"));
        assert!(
            receive_execution(&mut peer, &request(), "worker", &dest)
                .unwrap_err()
                .detail
                .contains("complete file")
        );
        assert!(no_ack(&peer));
    }

    #[test]
    fn manifest_and_aggregate_budget_are_checked_before_reading_bytes() {
        for case in 0..6 {
            let parent = tempfile::tempdir().unwrap();
            let dest = parent.path().join("delivery");
            let mut peer = fixture(&dest);
            match case {
                0 => peer.replies[1]["artifact_manifest"]["files"][0]["name"] = json!("../outside"),
                1 => peer.replies[1]["artifact_manifest"]["files"][0]["executable"] = json!(true),
                2 => peer.replies[1]["artifact_manifest"]["total_bytes"] = json!(5),
                3 => peer.replies[1]["stdout_bytes"] = json!(MAX_DELIVERY_BYTES),
                4 => peer.replies[1]["artifact_manifest"]["files"] = json!([]),
                _ => peer.replies[1]["residual_group_members"] = json!(1),
            }
            assert!(receive_execution(&mut peer, &request(), "worker", &dest).is_err());
            assert_eq!(peer.sent.len(), 2);
            assert!(no_ack(&peer));
            assert_eq!(
                std::fs::read_dir(dest.join("diagnostics")).unwrap().count(),
                0
            );
        }
    }

    #[test]
    fn ack_loss_keeps_verified_files_without_resubmitting_execution() {
        for fail_send in [Some("output-ack"), Some("artifact-ack"), None] {
            let parent = tempfile::tempdir().unwrap();
            let dest = parent.path().join("delivery");
            let mut peer = fixture(&dest);
            peer.fail_send = fail_send;
            if fail_send.is_none() {
                peer.replies[5]["request_id"] = json!(999);
            }
            let delivery = receive_execution(&mut peer, &request(), "worker", &dest).unwrap();
            assert!(!delivery.acknowledgments_confirmed);
            assert!(delivery.acknowledgment_error.is_some());
            assert_eq!(
                std::fs::read(dest.join("artifacts/a")).unwrap(),
                b"A\0\xffB"
            );
            assert!(dest.join("delivery.json").is_file());
            assert_eq!(
                peer.sent
                    .iter()
                    .filter(|v| v["kind"] == "canonical-exec")
                    .count(),
                1
            );
        }
    }

    #[test]
    fn existing_destination_or_retired_request_never_launches_work() {
        let parent = tempfile::tempdir().unwrap();
        let dest = parent.path().join("delivery");
        std::fs::create_dir(&dest).unwrap();
        let mut peer = fixture(&dest);
        let error = receive_execution(&mut peer, &request(), "worker", &dest).unwrap_err();
        assert!(!error.execution_may_have_run);
        assert!(peer.sent.is_empty());
        assert_eq!(std::fs::read_dir(&dest).unwrap().count(), 0);
        for high_water in [json!(7), json!(8), json!("6")] {
            let dest = parent.path().join("not-created");
            let mut peer = fixture(&dest);
            peer.replies[0]["request_high_water"] = high_water;
            assert!(
                !receive_execution(&mut peer, &request(), "worker", &dest)
                    .unwrap_err()
                    .execution_may_have_run
            );
            assert!(!dest.exists());
            assert!(peer.sent.is_empty());
        }
    }

    #[test]
    fn partial_execution_write_is_uncertain_and_never_retried() {
        let parent = tempfile::tempdir().unwrap();
        let dest = parent.path().join("delivery");
        let mut peer = fixture(&dest);
        peer.fail_send = Some("canonical-exec");
        assert!(
            receive_execution(&mut peer, &request(), "worker", &dest)
                .unwrap_err()
                .execution_may_have_run
        );
        assert_eq!(peer.sent.len(), 2);
        assert!(no_ack(&peer));
    }

    #[test]
    fn compiler_failure_delivers_diagnostics_but_never_artifacts() {
        let parent = tempfile::tempdir().unwrap();
        let dest = parent.path().join("delivery");
        let mut peer = fixture(&dest);
        peer.replies[1]["exit_code"] = json!(1);
        peer.replies[1]["artifact_ack_required"] = json!(false);
        peer.replies[1]["artifact_manifest"] = Value::Null;
        peer.replies.remove(4);
        peer.replies.pop_back();
        let delivery = receive_execution(&mut peer, &request(), "worker", &dest).unwrap();
        assert_eq!(delivery.receipt["exit_code"], 1);
        assert!(delivery.acknowledgments_confirmed);
        assert_eq!(
            std::fs::read_dir(dest.join("artifacts")).unwrap().count(),
            0
        );
    }

    #[test]
    fn malformed_requests_never_create_directories_or_contact_peers() {
        for files in [
            json!(["../x"]),
            json!(["a", "a"]),
            json!(["a", "a-z", "a/b"]),
            json!([]),
            json!(["/abs"]),
        ] {
            let parent = tempfile::tempdir().unwrap();
            let dest = parent.path().join("delivery");
            let mut request = request();
            request["artifacts"]["files"] = files;
            let mut peer = fixture(&dest);
            assert!(
                !receive_execution(&mut peer, &request, "worker", &dest)
                    .unwrap_err()
                    .execution_may_have_run
            );
            assert!(!dest.exists());
            assert_eq!(peer.replies.len(), 7);
        }
    }

    #[test]
    fn wire_claims_cannot_upgrade_transport_provenance() {
        let parent = tempfile::tempdir().unwrap();
        let destination = parent.path().join("delivery");
        let mut peer = fixture(&destination);
        peer.replies[0]["transport_authenticated"] = json!(true);
        peer.replies[0]["worker_spki_sha256"] = json!("01".repeat(32));
        peer.replies[1]["transport_authenticated"] = json!(true);
        let delivered = receive_execution(&mut peer, &request(), "worker", &destination).unwrap();
        assert_eq!(delivered.receipt["transport_authenticated"], false);
        assert!(delivered.receipt["worker_spki_sha256"].is_null());
    }

    struct AdmissionPeer {
        inner: Script,
        reject: bool,
        admitted: bool,
    }
    impl WorkerPeer for AdmissionPeer {
        fn negotiate(&mut self, _hello: &Value, grant: &Value) -> io::Result<()> {
            if self.reject {
                return Err(invalid("injected authentication refusal"));
            }
            self.inner.send(grant)?;
            self.admitted = true;
            Ok(())
        }
        fn authentication(&self) -> Option<WorkerAuthentication> {
            self.admitted.then_some(WorkerAuthentication {
                spki_sha256: [1; 32],
                session_id: 42,
                identity_generation: 1,
            })
        }
        fn send(&mut self, value: &Value) -> io::Result<()> {
            if matches!(value["kind"].as_str(), Some("output-ack" | "artifact-ack")) {
                let receipt: Value = serde_json::from_slice(&std::fs::read(
                    self.inner.destination.join("delivery.json"),
                )?)?;
                assert_eq!(receipt["transport_authenticated"], true);
                assert_eq!(receipt["worker_spki_sha256"], "01".repeat(32));
                assert_eq!(receipt["authenticated_session_id"], 42);
                assert_eq!(receipt["publication_authorized"], false);
            }
            self.inner.send(value)
        }
        fn receive(&mut self) -> io::Result<Value> {
            self.inner.receive()
        }
    }

    #[test]
    fn authentication_precedes_execution_and_is_durable_before_release() {
        for reject in [true, false] {
            let parent = tempfile::tempdir().unwrap();
            let destination = parent.path().join("delivery");
            let mut peer = AdmissionPeer {
                inner: fixture(&destination),
                reject,
                admitted: false,
            };
            let result = receive_execution(&mut peer, &request(), "worker", &destination);
            if reject {
                assert!(!result.unwrap_err().execution_may_have_run);
                assert!(peer.inner.sent.is_empty());
                assert!(!destination.join("delivery.json").exists());
            } else {
                assert!(result.unwrap().acknowledgments_confirmed);
            }
        }
    }

    fn resumable(destination: &Path) -> Script {
        let mut peer = fixture(destination);
        peer.replies[0]["request_high_water"] = json!(7);
        peer.replies[0]["boot_generation"] = json!(2);
        peer.replies[0]["result_retentions"] = json!([RESULT_RETENTION]);
        peer.replies[1]["resumed"] = json!(true);
        peer.replies[1]["result_retention"] = json!(RESULT_RETENTION);
        peer.replies[1]["retained_result_sha256"] = json!(hash(b"sealed result"));
        peer
    }

    #[test]
    fn resumed_delivery_reuses_full_verification_without_any_execution_dispatch() {
        let parent = tempfile::tempdir().unwrap();
        let dest = parent.path().join("resumed");
        let mut peer = resumable(&dest);
        let delivery =
            receive_operation(&mut peer, &request(), "worker", &dest, DeliveryMode::Resume)
                .unwrap();
        assert!(delivery.acknowledgments_confirmed);
        assert_eq!(peer.sent[0]["result_retention"], RESULT_RETENTION);
        assert_eq!(peer.sent[1], DeliveryMode::Resume.frame(&request()));
        assert!(
            !peer
                .sent
                .iter()
                .any(|frame| frame["kind"] == "canonical-exec")
        );
        assert_eq!(delivery.receipt["resumed"], true);
        assert_eq!(
            delivery.receipt["worker_identity_scope"],
            "delivery-session"
        );
        assert!(delivery.receipt["execution_boot_generation"].is_null());
        assert_eq!(
            std::fs::read(dest.join("artifacts/a")).unwrap(),
            b"A\0\xffB"
        );
        super::super::delivery_recovery::recover_existing_delivery(
            &request(),
            "worker",
            &dest,
            super::super::delivery_recovery::DeliveryTrust::Loopback,
        )
        .unwrap()
        .unwrap();
    }

    #[test]
    fn resume_refuses_wrong_high_water_or_missing_retention_before_sending() {
        for case in 0..5 {
            let parent = tempfile::tempdir().unwrap();
            let dest = parent.path().join("resumed");
            let mut peer = resumable(&dest);
            match case {
                0 => peer.replies[0]["request_high_water"] = Value::Null,
                1 => peer.replies[0]["request_high_water"] = json!(6),
                2 => peer.replies[0]["request_high_water"] = json!(8),
                3 => peer.replies[0]["result_retentions"] = json!([]),
                _ => peer.replies[0]["result_retentions"] = json!(["durable-result-v2"]),
            }
            assert!(
                receive_operation(&mut peer, &request(), "worker", &dest, DeliveryMode::Resume)
                    .is_err()
            );
            assert!(peer.sent.is_empty());
            assert!(!dest.exists());
        }
    }

    #[test]
    fn resumed_corruption_refusal_and_lost_write_never_fall_back_to_execution() {
        for case in 0..5 {
            let parent = tempfile::tempdir().unwrap();
            let dest = parent.path().join("resumed");
            let mut peer = resumable(&dest);
            match case {
                0 => peer.replies[1]["resumed"] = json!(false),
                1 => peer.replies[1]["retained_result_sha256"] = json!("bad"),
                2 => {
                    peer.replies[1] =
                        json!({"kind":"error","request_id":7,"reason":"result unavailable"})
                }
                3 => peer.replies[4]["data_hex"] = json!("4100ff43"),
                _ => peer.fail_send = Some("result-resume"),
            }
            let error =
                receive_operation(&mut peer, &request(), "worker", &dest, DeliveryMode::Resume)
                    .unwrap_err();
            assert!(
                error.execution_may_have_run,
                "prior execution remains possible"
            );
            assert!(
                !peer
                    .sent
                    .iter()
                    .any(|frame| frame["kind"] == "canonical-exec")
            );
            assert!(no_ack(&peer));
            assert!(!dest.join("delivery.json").exists());
        }
    }

    #[test]
    fn new_execution_selects_advertised_retention_and_persists_the_seal() {
        let parent = tempfile::tempdir().unwrap();
        let dest = parent.path().join("retained");
        let mut peer = resumable(&dest);
        peer.replies[0]["request_high_water"] = Value::Null;
        peer.replies[1].as_object_mut().unwrap().remove("resumed");
        let delivery = receive_execution(&mut peer, &request(), "worker", &dest).unwrap();
        assert_eq!(peer.sent[0]["result_retention"], RESULT_RETENTION);
        assert_eq!(peer.sent[1], request());
        assert_eq!(
            delivery.receipt["retained_result_sha256"],
            hash(b"sealed result")
        );
        assert_eq!(delivery.receipt["publication_authorized"], false);
    }


    fn source_request(root: &Path) -> (super::super::source_delivery::SourceUpload, Value) {
        use rabs_sandbox::snapshot_capture::capture_sealed_source;
        use super::super::source_delivery::SourceUpload;
        use std::sync::Arc;

        std::fs::write(root.join("lib.rs"), b"pub fn answer() -> u32 { 42 }\n").unwrap();
        std::fs::write(root.join("private.key"), b"not selected for upload").unwrap();
        let image = capture_sealed_source(
            &[("workspace".into(), root.to_path_buf())], false, 2, 200_000,
        ).unwrap();
        let upload = SourceUpload::from_snapshot(
            Arc::new(image), "workspace", &["lib.rs".into()],
        ).unwrap();
        let mut request = request();
        request.as_object_mut().unwrap().remove("workspace_backing");
        request["source_manifest"] = upload.wire_manifest();
        (upload, request)
    }

    fn source_replies(peer: &mut Script, request: &Value) {
        let manifest = &request["source_manifest"];
        peer.replies[0]["source_transfers"] = json!(["source-files-v1"]);
        peer.replies.insert(1, json!({"kind":"source-ready", "request_id":7,
            "manifest_sha256":manifest["manifest_sha256"], "sealed":false}));
        peer.replies.insert(2, json!({"kind":"source-chunk-accepted", "request_id":7,
            "manifest_sha256":manifest["manifest_sha256"], "path":"lib.rs",
            "next_offset":manifest["files"][0]["bytes"]}));
        peer.replies.insert(3, json!({"kind":"source-ready", "request_id":7,
            "manifest_sha256":manifest["manifest_sha256"], "sealed":true}));
    }

    #[test]
    fn source_projection_runs_through_the_complete_delivery_receiver() {
        use super::super::source_delivery::SourcePeer;

        let parent = tempfile::tempdir().unwrap();
        let source = tempfile::tempdir().unwrap();
        let (upload, request) = source_request(source.path());
        // The sender must use the sealed image, not this mutable checkout.
        std::fs::write(source.path().join("lib.rs"), b"changed after capture").unwrap();
        let destination = parent.path().join("delivery");
        let mut peer = fixture(&destination);
        source_replies(&mut peer, &request);
        let delivery = receive_execution(
            &mut SourcePeer::new(&mut peer, &upload, &request).unwrap(),
            &request, "worker", &destination,
        ).unwrap();
        assert!(delivery.acknowledgments_confirmed);
        assert!(peer.replies.is_empty());
        assert_eq!(peer.sent[0]["source_transfer"], "source-files-v1");
        assert_eq!(peer.sent[1]["kind"], "source-begin");
        assert_eq!(peer.sent[2]["kind"], "source-chunk");
        assert_eq!(peer.sent[2]["path"], "lib.rs");
        assert_eq!(peer.sent[2]["chunk_sha256"], request["source_manifest"]["files"][0]["sha256"]);
        assert_eq!(peer.sent[3]["kind"], "source-seal");
        assert_eq!(peer.sent[4], request);
        assert!(peer.sent[4].get("workspace_backing").is_none());
        assert_eq!(std::fs::read(destination.join("artifacts/a")).unwrap(), b"A\0\xffB");
        assert_eq!(delivery.receipt["request_sha256"], hash(&serde_json::to_vec(&request).unwrap()));
        assert_eq!(delivery.receipt["publication_authorized"], false);
    }

    #[test]
    fn source_failures_stop_before_the_execution_frontier() {
        use super::super::source_delivery::SourcePeer;

        let source = tempfile::tempdir().unwrap();
        let (upload, request) = source_request(source.path());
        for case in 0..7 {
            let parent = tempfile::tempdir().unwrap();
            let destination = parent.path().join("delivery");
            let mut peer = fixture(&destination);
            source_replies(&mut peer, &request);
            match case {
                0 => peer.replies[0]["source_transfers"] = json!([]),
                1 => peer.replies[1]["request_id"] = json!(8),
                2 => peer.replies[2]["next_offset"] = json!(0),
                3 => peer.replies[3]["manifest_sha256"] = json!("00".repeat(32)),
                4 => peer.replies[3]["sealed"] = json!(false),
                5 => peer.fail_send = Some("source-chunk"),
                _ => { peer.replies.remove(3); }
            }
            let failure = receive_execution(
                &mut SourcePeer::new(&mut peer, &upload, &request).unwrap(),
                &request, "worker", &destination,
            ).unwrap_err();
            assert!(!failure.execution_may_have_run, "case {case}: {failure}");
            assert!(!peer.sent.iter().any(|frame| frame["kind"] == "canonical-exec"));
            assert!(no_ack(&peer));
            assert!(!destination.join("delivery.json").exists());
        }
    }

    #[test]
    fn invalid_source_identity_is_rejected_without_contacting_the_worker() {
        let source = tempfile::tempdir().unwrap();
        let (_, original) = source_request(source.path());
        for case in 0..6 {
            let mut request = original.clone();
            match case {
                0 => request["workspace_backing"] = json!("/ws"),
                1 => request["source_manifest"] = Value::Null,
                2 => request["source_manifest"]["manifest_sha256"] = json!("00".repeat(32)),
                3 => request["source_manifest"]["files"][0]["path"] = json!("../private.key"),
                4 => request["source_manifest"]["files"][0]["bytes"] = json!(u64::MAX),
                _ => { request.as_object_mut().unwrap().remove("source_manifest"); }
            }
            let parent = tempfile::tempdir().unwrap();
            let destination = parent.path().join("delivery");
            let mut peer = fixture(&destination);
            let failure = receive_execution(&mut peer, &request, "worker", &destination).unwrap_err();
            assert!(!failure.execution_may_have_run, "case {case}");
            assert!(peer.sent.is_empty());
            assert_eq!(peer.replies.len(), 7);
            assert!(!destination.exists());
        }
    }

    #[test]
    fn source_backed_result_recovery_needs_no_checkout_or_source_upload() {
        let parent = tempfile::tempdir().unwrap();
        let request = {
            let source = tempfile::tempdir().unwrap();
            source_request(source.path()).1
        };
        let destination = parent.path().join("resumed");
        let mut peer = resumable(&destination);
        let delivery = receive_operation(
            &mut peer, &request, "worker", &destination, DeliveryMode::Resume,
        ).unwrap();
        assert!(delivery.acknowledgments_confirmed);
        assert_eq!(peer.sent[1], DeliveryMode::Resume.frame(&request));
        assert!(!peer.sent.iter().any(|frame| {
            matches!(frame["kind"].as_str(), Some("canonical-exec" | "source-begin" | "source-chunk" | "source-seal"))
        }));
        super::super::delivery_recovery::recover_existing_delivery(
            &request, "worker", &destination,
            super::super::delivery_recovery::DeliveryTrust::Loopback,
        ).unwrap().unwrap();
    }

    fn explicit_context() -> Value {
        json!({"version":COMMAND_CONTEXT_VERSION,"cwd":"/__rabs/workspace/packages/雪",
            "env":{"BUILD_LABEL":"spaces, \"quotes\", $HOME and\n雪","EMPTY":""}})
    }

    #[test]
    fn command_context_delivery_preserves_exact_request_and_transport_admission() {
        let parent = tempfile::tempdir().unwrap();
        let destination = parent.path().join("context");
        let mut request = request();
        request["command_context"] = explicit_context();
        let original = serde_json::to_vec(&request).unwrap();
        let mut peer = AdmissionPeer {
            inner: fixture(&destination),
            reject: false,
            admitted: false,
        };
        peer.inner.replies[0]["command_contexts"] = json!([COMMAND_CONTEXT_VERSION]);
        let delivery = receive_execution(&mut peer, &request, "worker", &destination).unwrap();
        assert!(delivery.acknowledgments_confirmed);
        assert!(peer.admitted);
        assert_eq!(serde_json::to_vec(&peer.inner.sent[1]).unwrap(), original);
        assert_eq!(serde_json::to_vec(&request).unwrap(), original);
        assert_eq!(delivery.receipt["request_sha256"], hash(&original));
        assert_eq!(delivery.receipt["transport_authenticated"], true);
        assert_eq!(delivery.receipt["publication_authorized"], false);
        assert!(!serde_json::to_string(&delivery.receipt).unwrap().contains("BUILD_LABEL"));
    }

    #[test]
    fn malformed_command_context_never_contacts_a_peer_or_creates_storage() {
        for case in 0..14 {
            let parent = tempfile::tempdir().unwrap();
            let destination = parent.path().join("refused");
            let mut request = request();
            request["command_context"] = explicit_context();
            match case {
                0 => request["command_context"] = Value::Null,
                1 => request["command_context"] = json!([]),
                2 => request["command_context"]["version"] = json!("env-cwd-v2"),
                3 => request["command_context"]["cwd"] = json!("/etc"),
                4 => request["command_context"]["cwd"] = json!("/__rabs/workspace/../home"),
                5 => request["command_context"]["cwd"] = json!("/__rabs/workspace//member"),
                6 => request["command_context"]["cwd"] = json!(false),
                7 => request["command_context"]["env"] = Value::Null,
                8 => request["command_context"]["env"]["SECRET"] = json!({"secret-marker":1}),
                9 => request["command_context"]["env"]["HOME"] = json!("secret-marker"),
                10 => request["command_context"]["env"]["BAD=NAME"] = json!("secret-marker"),
                11 => request["command_context"]["env"]["SECRET"] = json!("secret-marker\0"),
                12 => request["command_context"]["extra"] = json!(true),
                _ => {
                    request["command_context"].as_object_mut().unwrap().remove("env");
                }
            }
            let mut peer = fixture(&destination);
            let failure = receive_execution(&mut peer, &request, "worker", &destination).unwrap_err();
            assert!(!failure.execution_may_have_run, "case {case}");
            assert!(!failure.detail.contains("secret-marker"), "case {case}");
            assert!(peer.sent.is_empty());
            assert_eq!(peer.replies.len(), 7);
            assert!(!destination.exists());
        }
    }

    #[test]
    fn coordinator_enforces_shared_command_environment_limits() {
        use rabs_sandbox::process_context::{
            MAX_COMMAND_ENV_BYTES, MAX_COMMAND_ENV_VALUE_BYTES,
        };

        let mut request = request();
        request["command_context"] = explicit_context();
        let env: serde_json::Map<String, Value> = (0..MAX_COMMAND_ENV_ENTRIES)
            .map(|index| (format!("V{index}"), json!("")))
            .collect();
        request["command_context"]["env"] = Value::Object(env);
        validate_request(&request).unwrap();
        request["command_context"]["env"]["ONE_TOO_MANY"] = json!("");
        assert!(validate_request(&request).is_err());
        request["command_context"]["env"] = json!({"A":"x".repeat(MAX_COMMAND_ENV_VALUE_BYTES)});
        validate_request(&request).unwrap();
        request["command_context"]["env"]["A"] = json!("x".repeat(MAX_COMMAND_ENV_VALUE_BYTES + 1));
        assert!(validate_request(&request).is_err());
        // Each value is individually legal; their encoded aggregate is not.
        request["command_context"]["env"] = json!({
            "A":"x".repeat(MAX_COMMAND_ENV_BYTES / 2),
            "B":"x".repeat(MAX_COMMAND_ENV_BYTES / 2)
        });
        assert!(validate_request(&request).is_err());
    }

    #[test]
    fn command_context_requires_an_explicit_supported_worker_capability() {
        for advertised in [
            None,
            Some(Value::Null),
            Some(json!(true)),
            Some(json!(COMMAND_CONTEXT_VERSION)),
            Some(json!([])),
            Some(json!(["env-cwd-v2"])),
            Some(json!([{ "version":COMMAND_CONTEXT_VERSION }])),
        ] {
            let parent = tempfile::tempdir().unwrap();
            let destination = parent.path().join("refused");
            let mut request = request();
            request["command_context"] = explicit_context();
            let mut peer = fixture(&destination);
            if let Some(value) = advertised {
                peer.replies[0]["command_contexts"] = value;
            }
            let failure = receive_execution(&mut peer, &request, "worker", &destination).unwrap_err();
            assert!(!failure.execution_may_have_run);
            assert!(failure.detail.contains("env-cwd-v1"));
            assert!(peer.sent.is_empty());
            assert_eq!(peer.replies.len(), 6);
            assert!(!destination.exists());
        }
    }

    #[test]
    fn toolchain_binding_requires_worker_support_before_any_upload_or_dispatch() {
        use super::super::source_delivery::SourcePeer;
        let source = tempfile::tempdir().unwrap();
        let (upload, mut request) = source_request(source.path());
        let identity = ToolchainIdentity {
            sha256: [0xab; 32],
            files: 12,
            bytes: 345,
        };
        request["toolchain_identity"] = toolchain_identity_value(&identity);
        assert_eq!(toolchain_identity(&request).unwrap(), Some(identity));
        for supported in [false, true] {
            let parent = tempfile::tempdir().unwrap();
            let destination = parent.path().join("delivery");
            let mut peer = fixture(&destination);
            source_replies(&mut peer, &request);
            if supported {
                peer.replies[0]["toolchain_datasets"] = json!([TOOLCHAIN_DATASET_VERSION]);
            }
            let result = receive_execution(
                &mut SourcePeer::new(&mut peer, &upload, &request).unwrap(),
                &request,
                "worker",
                &destination,
            );
            if supported {
                let delivery = result.unwrap();
                assert_eq!(peer.sent[4], request);
                assert_eq!(
                    delivery.receipt["request_sha256"],
                    hash(&serde_json::to_vec(&request).unwrap())
                );
            } else {
                let failure = result.unwrap_err();
                assert!(!failure.execution_may_have_run);
                assert!(failure.detail.contains(TOOLCHAIN_DATASET_VERSION));
                assert!(peer.sent.is_empty());
                assert!(!destination.exists());
            }
        }
    }

    #[test]
    fn toolchain_binding_resume_uses_exact_request_without_requiring_execution_capability() {
        use super::super::delivery_recovery::{DeliveryTrust, recover_existing_delivery};
        let parent = tempfile::tempdir().unwrap();
        let destination = parent.path().join("resumed");
        let mut request = request();
        request["toolchain_identity"] = toolchain_identity_value(&ToolchainIdentity {
            sha256: [0xab; 32],
            files: 12,
            bytes: 345,
        });
        let mut peer = resumable(&destination);
        assert!(peer.replies[0].get("toolchain_datasets").is_none());
        receive_operation(
            &mut peer,
            &request,
            "worker",
            &destination,
            DeliveryMode::Resume,
        )
        .unwrap();
        assert_eq!(peer.sent[1], DeliveryMode::Resume.frame(&request));
        recover_existing_delivery(&request, "worker", &destination, DeliveryTrust::Loopback)
            .unwrap()
            .unwrap();
        request["toolchain_identity"]["sha256"] = json!("cd".repeat(32));
        assert!(
            recover_existing_delivery(&request, "worker", &destination, DeliveryTrust::Loopback)
                .is_err()
        );
    }

    #[test]
    fn invalid_toolchain_identity_refuses_before_receiving_a_worker_hello() {
        for invalid in [
            Value::Null,
            json!({"version":"v2","sha256":"ab".repeat(32),"files":12,"bytes":345}),
            json!({"version":TOOLCHAIN_DATASET_VERSION,"sha256":"AB".repeat(32),"files":12,"bytes":345}),
            json!({"version":TOOLCHAIN_DATASET_VERSION,"sha256":"ab".repeat(32),"files":12.5,"bytes":345}),
            json!({"version":TOOLCHAIN_DATASET_VERSION,"sha256":"ab".repeat(32),"files":12}),
            json!({"version":TOOLCHAIN_DATASET_VERSION,"sha256":"ab".repeat(32),"files":12,"bytes":345,"extra":true}),
        ] {
            let parent = tempfile::tempdir().unwrap();
            let destination = parent.path().join("refused");
            let mut request = request();
            request["toolchain_identity"] = invalid;
            let mut peer = fixture(&destination);
            let reply_count = peer.replies.len();
            assert!(
                !receive_execution(&mut peer, &request, "worker", &destination)
                    .unwrap_err()
                    .execution_may_have_run
            );
            assert_eq!(peer.replies.len(), reply_count);
            assert!(peer.sent.is_empty());
            assert!(!destination.exists());
        }
    }

    #[test]
    fn toolchain_transfer_requires_source_identity_and_excludes_host_path_fallback() {
        let source = tempfile::tempdir().unwrap();
        let (_, mut request) = source_request(source.path());
        request["toolchain_transfer"] = json!("toolchain-tree-v1");
        request["toolchain_identity"] = toolchain_identity_value(&ToolchainIdentity {
            sha256:[0xab;32], files:1, bytes:12,
        });
        assert!(validate_request(&request).is_err(), "worker backing and transfer cannot coexist");
        request.as_object_mut().unwrap().remove("toolchain_backing");
        validate_request(&request).unwrap();
        for field in ["toolchain_identity", "source_manifest"] {
            let mut incomplete = request.clone();
            incomplete.as_object_mut().unwrap().remove(field);
            assert!(validate_request(&incomplete).is_err(), "{field}");
        }
        for selection in [Value::Null, json!(true), json!("toolchain-tree-v2")] {
            request["toolchain_transfer"] = selection;
            assert!(validate_request(&request).is_err());
        }
    }

    #[test]
    fn unsupported_toolchain_transport_refuses_before_admission_or_dispatch() {
        let source = tempfile::tempdir().unwrap();
        let (_, mut request) = source_request(source.path());
        request.as_object_mut().unwrap().remove("toolchain_backing");
        request["toolchain_transfer"] = json!("toolchain-tree-v1");
        request["toolchain_identity"] = toolchain_identity_value(&ToolchainIdentity {
            sha256:[0xab;32], files:1, bytes:12,
        });
        let owner = tempfile::tempdir().unwrap();
        let destination = owner.path().join("delivery");
        let mut peer = fixture(&destination);
        peer.replies[0]["toolchain_datasets"] = json!([TOOLCHAIN_DATASET_VERSION]);
        let failure = receive_execution(&mut peer, &request, "worker", &destination).unwrap_err();
        assert!(!failure.execution_may_have_run);
        assert!(failure.detail.contains("toolchain-tree-v1"));
        assert!(peer.sent.is_empty());
        assert!(!destination.exists());
    }

    #[test]
    fn source_upload_cannot_precede_command_context_capability_admission() {
        use super::super::source_delivery::SourcePeer;

        let source = tempfile::tempdir().unwrap();
        let (upload, mut request) = source_request(source.path());
        request["command_context"] = explicit_context();
        for supported in [false, true] {
            let parent = tempfile::tempdir().unwrap();
            let destination = parent.path().join("delivery");
            let mut peer = fixture(&destination);
            source_replies(&mut peer, &request);
            if supported {
                peer.replies[0]["command_contexts"] = json!([COMMAND_CONTEXT_VERSION]);
            }
            let result = receive_execution(
                &mut SourcePeer::new(&mut peer, &upload, &request).unwrap(),
                &request,
                "worker",
                &destination,
            );
            if supported {
                let delivery = result.unwrap();
                assert!(delivery.acknowledgments_confirmed);
                assert_eq!(peer.sent[4], request);
                assert_eq!(peer.sent[4]["command_context"], explicit_context());
                assert_eq!(delivery.receipt["request_sha256"], hash(&serde_json::to_vec(&request).unwrap()));
            } else {
                assert!(!result.unwrap_err().execution_may_have_run);
                assert!(peer.sent.is_empty());
                assert!(!destination.exists());
            }
        }
    }

    #[test]
    fn context_resume_requires_exact_identity_not_current_execution_capability() {
        use super::super::delivery_recovery::{DeliveryTrust, recover_existing_delivery};

        let parent = tempfile::tempdir().unwrap();
        let destination = parent.path().join("resumed");
        let mut request = request();
        request["command_context"] = explicit_context();
        let mut peer = resumable(&destination);
        assert!(peer.replies[0].get("command_contexts").is_none());
        let delivery = receive_operation(
            &mut peer, &request, "worker", &destination, DeliveryMode::Resume,
        ).unwrap();
        assert!(delivery.acknowledgments_confirmed);
        assert_eq!(peer.sent[1], DeliveryMode::Resume.frame(&request));
        assert!(!peer.sent.iter().any(|frame| frame["kind"] == "canonical-exec"));
        recover_existing_delivery(&request, "worker", &destination, DeliveryTrust::Loopback)
            .unwrap().unwrap();
        for field in ["cwd", "env"] {
            let mut changed = request.clone();
            if field == "cwd" {
                changed["command_context"]["cwd"] = json!("/__rabs/workspace/other");
            } else {
                changed["command_context"]["env"]["EMPTY"] = json!("now-present");
            }
            assert!(recover_existing_delivery(
                &changed, "worker", &destination, DeliveryTrust::Loopback,
            ).is_err());
        }
    }

    fn heartbeat() -> Value {
        json!({"kind":"heartbeat", "worker_id":"worker", "active_request_id":7})
    }

    #[test]
    fn paced_heartbeats_do_not_impose_a_lifetime_limit_on_long_execution() {
        let parent = tempfile::tempdir().unwrap();
        let mut peer = fixture(&parent.path().join("unused"));
        peer.replies = std::iter::repeat_with(heartbeat).take(4096).collect();
        let terminal = json!({"kind":"exec-result", "request_id":7});
        peer.replies.push_back(terminal.clone());
        let mut clock = Instant::now();
        let result = receive_with_clock(&mut peer, "worker", || {
            let observed = clock;
            clock += HEARTBEAT_WINDOW;
            observed
        }).unwrap();
        assert_eq!(result, terminal);
        assert!(peer.replies.is_empty());
        assert!(peer.sent.is_empty());
    }

    #[test]
    fn heartbeat_flood_is_bounded_at_the_exact_window_boundary() {
        let parent = tempfile::tempdir().unwrap();
        let start = Instant::now();
        for renew in [false, true] {
            let mut peer = fixture(&parent.path().join("unused"));
            peer.replies = std::iter::repeat_with(heartbeat)
                .take(MAX_HEARTBEAT_BURST + 1).collect();
            peer.replies.push_back(json!({"kind":"exec-result", "request_id":7}));
            let mut observations = 0;
            let result = receive_with_clock(&mut peer, "worker", || {
                let elapsed = if observations > MAX_HEARTBEAT_BURST {
                    if renew { HEARTBEAT_WINDOW } else { HEARTBEAT_WINDOW - Duration::from_nanos(1) }
                } else {
                    Duration::ZERO
                };
                observations += 1;
                start + elapsed
            });
            if renew {
                assert_eq!(result.unwrap()["kind"], "exec-result");
                assert!(peer.replies.is_empty());
            } else {
                let error = result.unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::InvalidData);
                assert!(error.to_string().contains("heartbeat window"));
                assert_eq!(peer.replies.len(), 1);
            }
            assert!(peer.sent.is_empty());
        }
    }

    #[test]
    fn sustained_telemetry_does_not_mask_a_transport_deadline() {
        struct ExpiringPeer { remaining: usize }
        impl WorkerPeer for ExpiringPeer {
            fn send(&mut self, _: &Value) -> io::Result<()> {
                panic!("waiting for a result must not send a retry");
            }
            fn receive(&mut self) -> io::Result<Value> {
                if self.remaining == 0 {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "absolute phase deadline"));
                }
                self.remaining -= 1;
                Ok(heartbeat())
            }
        }
        let mut peer = ExpiringPeer { remaining: 256 };
        let mut clock = Instant::now();
        let error = receive_with_clock(&mut peer, "worker", || {
            let observed = clock;
            clock += HEARTBEAT_WINDOW;
            observed
        }).unwrap_err();
        assert_eq!(peer.remaining, 0);
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(error.to_string(), "absolute phase deadline");
    }

    #[test]
    fn full_heartbeat_burst_preserves_complete_delivery_and_release_order() {
        let parent = tempfile::tempdir().unwrap();
        let destination = parent.path().join("delivery");
        let mut peer = fixture(&destination);
        for _ in 0..MAX_HEARTBEAT_BURST {
            peer.replies.insert(1, heartbeat());
        }
        let delivery = receive_execution(&mut peer, &request(), "worker", &destination).unwrap();
        assert!(delivery.acknowledgments_confirmed);
        assert!(peer.replies.is_empty());
        assert_eq!(std::fs::read(destination.join("artifacts/a")).unwrap(), b"A\0\xffB");
        assert_eq!(peer.sent.iter().filter(|frame| frame["kind"] == "canonical-exec").count(), 1);
        assert_eq!(delivery.receipt["publication_authorized"], false);
    }

    #[test]
    fn foreign_heartbeat_never_releases_outputs_or_reexecutes() {
        let parent = tempfile::tempdir().unwrap();
        let destination = parent.path().join("delivery");
        let mut peer = fixture(&destination);
        let mut foreign = heartbeat();
        foreign["worker_id"] = json!("another-worker");
        peer.replies.insert(1, foreign);
        let failure = receive_execution(&mut peer, &request(), "worker", &destination).unwrap_err();
        assert!(failure.execution_may_have_run);
        assert!(failure.detail.contains("foreign heartbeat"));
        assert!(no_ack(&peer));
        assert!(!destination.join("delivery.json").exists());
        assert_eq!(peer.sent.iter().filter(|frame| frame["kind"] == "canonical-exec").count(), 1);
    }
}
