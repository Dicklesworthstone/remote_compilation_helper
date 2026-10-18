//! Canonical worker execution (bead S5 / bridge plan Phase S).
//!
//! The live session drives this executor through the existing sandbox launcher,
//! worker-local jobserver, owned process groups and bounded diagnostic drains.
//! Negotiated artifact requests add a fresh D005 output mount and exact-set
//! harvesting after successful cleanup. Results are offers, never publications;
//! the prototype newline transport is not authenticated ATP.

use crate::artifacts::PreparedArtifacts;
use crate::execution::{DEFAULT_EXECUTION_TIMEOUT, ExecutionControl};
use crate::output::CapturedOutputs;
use crate::source_transfer::SourceOwner;
use rabs_protocol::capability_tokens::CapabilityToken;
use rabs_sandbox::dependency_context::{
    DEPENDENCY_CONTEXT_VERSION, DependencyExecContext, MAX_DEPENDENCY_DIRS,
    MAX_DEPENDENCY_ENV_ENTRIES,
};
use rabs_sandbox::process_context::{
    COMMAND_CONTEXT_VERSION, CommandContext, MAX_COMMAND_ENV_ENTRIES,
};
use rabs_sandbox::toolchain_dataset::{TOOLCHAIN_DATASET_VERSION, ToolchainIdentity};

pub(crate) mod toolchain_pool;
pub use toolchain_pool::ToolchainReuseScope;

/// What this worker can do (advertised at handshake; the scheduler
/// gates placement on it). Derived from a real HostIsolationSupport
/// probe on the worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityReport {
    /// Worker id (stable per host).
    pub worker_id: String,
    /// Whether the canonical namespace can run here (bwrap + userns +
    /// the rest — `HostIsolationSupport::missing_for_canonical`
    /// empty).
    pub canonical_namespace: bool,
    /// Missing isolation facets (empty when `canonical_namespace`).
    pub missing: Vec<String>,
    /// Advertised execution slots (CPU-derived).
    pub slots: u32,
}

/// A live pressure sample (heartbeat payload).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PressureSample {
    /// 1-minute load average × 100 (integer to stay serde-free).
    pub load_x100: u64,
    /// Free disk MiB on the worker's staging filesystem.
    pub free_disk_mib: u64,
}

/// A canonical-execution request from the coordinator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalExecRequest {
    /// Correlation id (echoed in the result).
    pub request_id: u64,
    /// The program to run (e.g. `cargo`, or `/__rabs/toolchain/bin/rustc`).
    pub program: String,
    /// Program arguments.
    pub args: Vec<String>,
    /// Explicit, validated environment additions and canonical working directory.
    /// Absence on the wire uses the canonical workspace and pinned base only.
    pub command_context: CommandContext,
    /// Separately negotiated original-path leaf rustc execution. This never
    /// changes the semantics of an ordinary canonical command context.
    pub dependency_context: Option<DependencyExecContext>,
    /// Worker-local source of the toolchain dataset. Execution captures private
    /// bytes or leases an exactly pinned captured dataset, never this live path.
    pub toolchain_backing: String,
    /// Expected content identity, when the coordinator has pinned a toolchain.
    /// This is execution input binding, never action-cache authorization.
    pub toolchain_identity: Option<ToolchainIdentity>,
    /// Workspace backing directory (mounts at `/__rabs/workspace`).
    pub workspace_backing: String,
    /// Execution resource grant for this attempt (bead I004): the
    /// total jobserver slot budget the coordinator admits (one implicit
    /// slot plus C-1 transferable tokens).
    /// It cannot exceed the worker's own slot count; zero floors to
    /// one. `None` uses the worker's slot count.
    pub jobserver_grant: Option<u32>,
}

/// Decode the optional content identity before durable execution admission.
/// Missing identity permits an explicitly unpinned execution, but a malformed
/// or unknown identity never silently becomes an unpinned execution.
pub fn parse_toolchain_identity(
    request: &serde_json::Value,
) -> Result<Option<ToolchainIdentity>, String> {
    let Some(value) = request.get("toolchain_identity") else {
        return Ok(None);
    };
    let fields = value
        .as_object()
        .filter(|fields| fields.len() == 4)
        .ok_or("toolchain_identity requires exactly version, sha256, files and bytes")?;
    if fields.get("version").and_then(serde_json::Value::as_str) != Some(TOOLCHAIN_DATASET_VERSION)
    {
        return Err("unsupported toolchain_identity version".to_owned());
    }
    let digest = fields
        .get("sha256")
        .and_then(serde_json::Value::as_str)
        .filter(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .ok_or("toolchain_identity sha256 must be lowercase SHA-256")?;
    let mut sha256 = [0u8; 32];
    for (index, byte) in sha256.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&digest[index * 2..index * 2 + 2], 16)
            .map_err(|_| "invalid toolchain_identity sha256")?;
    }
    let number = |name| {
        fields
            .get(name)
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| format!("toolchain_identity {name} must be an unsigned integer"))
    };
    Ok(Some(ToolchainIdentity {
        sha256,
        files: number("files")?,
        bytes: number("bytes")?,
    }))
}

/// Decode the optional versioned execution context without reading the host
/// environment. Policy is shared with the coordinator through the sandbox's
/// validated type. The original JSON remains the journal fingerprint input.
///
/// # Errors
/// Malformed or unsupported contexts refuse before durable admission. Values
/// never appear in errors, including rejected non-string environment values.
pub fn parse_command_context(request: &serde_json::Value) -> Result<CommandContext, String> {
    let Some(value) = request.get("command_context") else {
        return Ok(CommandContext::default());
    };
    let object = value
        .as_object()
        .filter(|object| object.len() == 3)
        .ok_or("command_context requires exactly version, cwd and env")?;
    if object.get("version").and_then(serde_json::Value::as_str) != Some(COMMAND_CONTEXT_VERSION) {
        return Err("unsupported command_context version".to_owned());
    }
    let cwd = object
        .get("cwd")
        .and_then(serde_json::Value::as_str)
        .ok_or("command_context cwd must be a string")?;
    let env = object
        .get("env")
        .and_then(serde_json::Value::as_object)
        .filter(|env| env.len() <= MAX_COMMAND_ENV_ENTRIES)
        .ok_or("command_context env must be a bounded string map")?;
    let env = env
        .iter()
        .map(|(name, value)| {
            value
                .as_str()
                .map(|value| (name.clone(), value.to_owned()))
                .ok_or_else(|| "command_context env values must be strings".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    CommandContext::new(cwd, env).map_err(|error| error.to_string())
}

/// Decode the separately negotiated full dependency context. Unknown fields,
/// duplicate environment names and absent versus malformed values never fall
/// back to the canonical execution defaults.
pub fn parse_dependency_context(
    request: &serde_json::Value,
) -> Result<Option<DependencyExecContext>, String> {
    let Some(value) = request.get("dependency_context") else {
        return Ok(None);
    };
    if request.get("command_context").is_some() {
        return Err("dependency_context and command_context are mutually exclusive".to_owned());
    }
    let object = value
        .as_object()
        .ok_or("dependency_context must be an object")?;
    const REQUIRED: &[&str] = &[
        "version",
        "source_root",
        "cwd",
        "toolchain_root",
        "compiler",
        "out_dir",
        "env",
        "runtime_cohort_sha256",
    ];
    if REQUIRED.iter().any(|field| !object.contains_key(*field))
        || object.keys().any(|field| {
            !REQUIRED.contains(&field.as_str())
                && field != "dependency_dirs"
                && field != "loader_dirs"
        })
        || object.get("version").and_then(serde_json::Value::as_str)
            != Some(DEPENDENCY_CONTEXT_VERSION)
    {
        return Err("dependency_context requires supported exact fields".to_owned());
    }
    let text = |field: &str| -> Result<String, String> {
        object
            .get(field)
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| format!("dependency_context {field} must be a string"))
    };
    let env = object
        .get("env")
        .and_then(serde_json::Value::as_array)
        .filter(|values| values.len() <= MAX_DEPENDENCY_ENV_ENTRIES)
        .ok_or("dependency_context env must be a bounded array of name/value pairs")?
        .iter()
        .map(|value| {
            let pair = value
                .as_array()
                .filter(|pair| pair.len() == 2)
                .ok_or("dependency_context env requires name/value pairs")?;
            Ok((
                pair[0]
                    .as_str()
                    .ok_or("dependency environment name must be a string")?
                    .to_owned(),
                pair[1]
                    .as_str()
                    .ok_or("dependency environment value must be a string")?
                    .to_owned(),
            ))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let directories = |field: &str| -> Result<Vec<String>, String> {
        match object.get(field) {
            None => Ok(Vec::new()),
            Some(value) => value
                .as_array()
                .filter(|paths| paths.len() <= MAX_DEPENDENCY_DIRS)
                .ok_or_else(|| format!("{field} must be a bounded array"))?
                .iter()
                .map(|path| {
                    path.as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| format!("{field} entries must be strings"))
                })
                .collect(),
        }
    };
    let dirs = directories("dependency_dirs")?;
    let loader_dirs = directories("loader_dirs")?;
    let digest = text("runtime_cohort_sha256")?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("dependency runtime cohort must be lowercase SHA-256".to_owned());
    }
    let mut runtime_cohort = [0u8; 32];
    for (index, byte) in runtime_cohort.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&digest[index * 2..index * 2 + 2], 16)
            .map_err(|_| "invalid dependency runtime cohort")?;
    }
    DependencyExecContext::new_with_loader_dirs(
        text("source_root")?,
        text("cwd")?,
        text("toolchain_root")?,
        text("compiler")?,
        text("out_dir")?,
        dirs,
        loader_dirs,
        env,
        runtime_cohort,
    )
    .map(Some)
    .map_err(|error| error.to_string())
}

/// The result of one canonical execution — an OFFER, never a commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecResult {
    /// Echoes the request id.
    pub request_id: u64,
    /// Process exit code (or 128+signal). Controlled interruption uses a
    /// nonzero compatibility exit even if the process traps TERM and exits zero.
    pub exit_code: i32,
    /// SHA-256 of stdout bytes (hex).
    pub stdout_sha256: String,
    /// SHA-256 of stderr bytes (hex).
    pub stderr_sha256: String,
    /// Whether a complete execution result is available. False includes
    /// setup and capture failures and MUST NOT be taken as proof that no
    /// process ran. The execution owner reports capture errors separately.
    pub executed: bool,
    /// Live process-group members still present after post-exit
    /// cleanup (bead G006). 0 = the managed group resolved fully; any
    /// other value is an honest incident record for the receipt.
    pub residual_group_members: u32,
    /// Bytes diverted to the stdout spill archive when stdout exceeded
    /// G007's per-stream resident bound (0 = fully resident).
    pub stdout_spill_bytes: u64,
    /// Bytes diverted to the stderr spill archive under the same policy.
    pub stderr_spill_bytes: u64,
    /// Worker-side path of the stdout spill archive (retrievable offer;
    /// transport to the edge is later-bead work).
    pub stdout_spill_path: Option<String>,
    /// Worker-side path of the stderr spill archive.
    pub stderr_spill_path: Option<String>,
}

/// Typed handshake refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeRefusal {
    /// The presented capability token failed validation.
    TokenInvalid(String),
    /// The worker advertised no canonical-namespace capability and the
    /// coordinator requires it.
    NotCanonicalCapable,
    /// Protocol/frame error during handshake.
    Protocol(String),
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// SHA-256 of bytes as hex (via rabs-cas's hasher would pull a heavier
/// dep; the sandbox already links sha2 through rabs-protocol's tree).
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex(&hasher.finalize())
}

/// Hash the complete captured stream through the SAME descriptor-owned reader
/// as output delivery. Digest-only execution must not reopen a mutable spill
/// name or hash bytes beyond the completed drain's receipt. No temporary copy
/// is needed on this path; resident memory remains one fixed-size buffer.
///
/// # Errors
/// A missing/changed capture or read failure produces no successful digest.
/// Interrupted reads retry without losing or double-hashing their prefix.
fn stream_digest(lane: &rabs_asupersync::stream_drain::LaneDrain) -> std::io::Result<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read as _;
    let mut reader = lane.reader()?;
    let mut hasher = Sha256::new();
    let mut chunk = [0u8; 64 * 1024];
    loop {
        let n = match reader.read(&mut chunk) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if n == 0 {
            break;
        }
        hasher.update(&chunk[..n]);
    }
    Ok(hex(&hasher.finalize()))
}

/// Probe this host's real capability (the scheduler consumes it).
#[must_use]
pub fn probe_capability(worker_id: &str) -> CapabilityReport {
    let support = rabs_sandbox::canonical_namespace::HostIsolationSupport::probe();
    let missing: Vec<String> = support
        .missing_for_canonical()
        .into_iter()
        .map(str::to_string)
        .collect();
    let slots = std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(1);
    CapabilityReport {
        worker_id: worker_id.to_string(),
        canonical_namespace: missing.is_empty(),
        missing,
        slots,
    }
}

/// Sample this host's real pressure (heartbeat payload).
#[must_use]
pub fn sample_pressure(staging_dir: &std::path::Path) -> PressureSample {
    let load_x100 = std::fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|text| text.split_whitespace().next().map(str::to_string))
        .and_then(|first| first.parse::<f64>().ok())
        .map(|load| (load * 100.0) as u64)
        .unwrap_or(0);
    // 0 means unknown where the platform probe is unavailable.
    let free_disk_mib = free_disk_mib(staging_dir);
    PressureSample {
        load_x100,
        free_disk_mib,
    }
}

#[cfg(target_os = "linux")]
fn free_disk_mib(dir: &std::path::Path) -> u64 {
    // POSIX df output guarantees one line per filesystem; avoid libc/unsafe.
    let output = std::process::Command::new("df")
        .arg("-Pk")
        .arg(dir)
        .output();
    output
        .ok()
        .and_then(|o| {
            String::from_utf8(o.stdout).ok().and_then(|text| {
                text.lines().nth(1).and_then(|line| {
                    line.split_whitespace()
                        .nth(3)
                        .and_then(|kb| kb.parse::<u64>().ok())
                })
            })
        })
        .map(|kb| kb / 1024)
        .unwrap_or(0)
}

#[cfg(not(target_os = "linux"))]
fn free_disk_mib(_dir: &std::path::Path) -> u64 {
    0
}

/// Per-stream RESIDENT bound for canonical execution output (G007):
/// heads carry diagnostics; overflow streams to disk spill archives.
const EXEC_STREAM_RESIDENT_BOUND: usize = 1024 * 1024;

/// Execute through the canonical sandbox with the default finite local budget.
/// This synchronous interface is for blocking callers; async sessions must use
/// `ExecutionTask` so the reactor continues handling control traffic.
#[must_use]
pub fn execute_canonical(
    request: &CanonicalExecRequest,
    cargo_home_backing: &std::path::Path,
    home_backing: &std::path::Path,
    slots: u32,
    spill_root: &std::path::Path,
) -> ExecResult {
    let Ok(control) = ExecutionControl::new(DEFAULT_EXECUTION_TIMEOUT) else {
        return exec_error(request.request_id);
    };
    execute_canonical_controlled(
        request,
        cargo_home_backing,
        home_backing,
        slots,
        spill_root,
        &control,
    )
}

/// Execute using the session's cancellation/deadline authority. The sandbox,
/// worker-local jobserver, process-group ownership and full-stream digests are
/// shared with ordinary execution. A cancelled preflight never spawns; a stop
/// after spawn sends TERM, escalates, drains and reaps before returning.
#[must_use]
pub fn execute_canonical_controlled(
    request: &CanonicalExecRequest,
    cargo_home_backing: &std::path::Path,
    home_backing: &std::path::Path,
    slots: u32,
    spill_root: &std::path::Path,
    control: &ExecutionControl,
) -> ExecResult {
    let mut result = execute_canonical_inner(
        request,
        cargo_home_backing,
        home_backing,
        slots,
        spill_root,
        control,
        None,
    );
    if let Some(reason) = control.finish() {
        result.exit_code = reason.exit_code();
    }
    result
}

/// Execute an uploaded projection with kernel-enforced read-only source.
/// The caller retains the verified source owner until this blocking call has
/// drained and reaped the process. Neither a wire flag nor a pathname alone
/// can enable this path; the owner must match the admitted request and mount.
/// HOME and declared artifact output mounts remain writable.
#[must_use]
pub fn execute_uploaded_canonical_controlled(
    request: &CanonicalExecRequest,
    cargo_home_backing: &std::path::Path,
    home_backing: &std::path::Path,
    slots: u32,
    spill_root: &std::path::Path,
    control: &ExecutionControl,
    source: &SourceOwner,
) -> ExecResult {
    let mut result = execute_canonical_inner(
        request,
        cargo_home_backing,
        home_backing,
        slots,
        spill_root,
        control,
        Some(source),
    );
    if let Some(reason) = control.finish() {
        result.exit_code = reason.exit_code();
    }
    result
}

/// The host loader/runtime is visible read-only but is not retained with the
/// toolchain. Measure before spawn and after cleanup, so a changed host cohort
/// never becomes an accepted result for the caller's keyed execution profile.
fn verify_dependency_runtime(
    context: &DependencyExecContext,
    toolchain: &toolchain_pool::ToolchainLease,
    artifacts: Option<&PreparedArtifacts>,
) -> Result<(), String> {
    let artifacts = artifacts.ok_or("dependency runtime check lacks private output storage")?;
    let loader_paths = context
        .loader_search_paths(toolchain.root())
        .map_err(|error| error.to_string())?;
    let observed = rabs_sandbox::runtime_cohort::observe_runtime_cohort(
        &toolchain.root().join("bin/rustc"),
        toolchain.root(),
        &loader_paths,
        artifacts.backing(),
    )
    .map_err(|error| error.to_string())?;
    if observed.bytes != *context.runtime_cohort_sha256() {
        return Err("measured host runtime differs from the dependency context".to_owned());
    }
    Ok(())
}

fn execute_canonical_inner(
    request: &CanonicalExecRequest,
    cargo_home_backing: &std::path::Path,
    home_backing: &std::path::Path,
    slots: u32,
    spill_root: &std::path::Path,
    control: &ExecutionControl,
    source: Option<&SourceOwner>,
) -> ExecResult {
    use rabs_asupersync::process_groups::ManagedProcessGroup;
    use rabs_asupersync::region_tree::Attribution;
    use rabs_sandbox::canonical_mounts::CanonicalMountPlan;
    use rabs_sandbox::canonical_namespace::{
        HostIsolationSupport, build_canonical_argv, command_for,
    };
    use std::process::Stdio;
    if control.reason().is_some() {
        return exec_error(request.request_id);
    }
    let support = HostIsolationSupport::probe();
    if !support.missing_for_canonical().is_empty() {
        return exec_error(request.request_id);
    }

    // The lease retains independent bytes until processes and drains resolve.
    // Only an explicit complete content identity may reuse a captured dataset;
    // an unpinned request never resolves a mutable pathname through the pool.
    let toolchain = match toolchain_pool::prepare(
        std::path::Path::new(&request.toolchain_backing),
        request.toolchain_identity.as_ref(),
        || control.reason().is_some(),
    ) {
        Ok(toolchain) => toolchain,
        Err(error) => {
            let _ = control.retain_outputs(Err(format!("toolchain acquisition: {error}")));
            return exec_error(request.request_id);
        }
    };
    eprintln!(
        "{}",
        serde_json::json!({
            "kind":"worker-toolchain-acquired", "request_id":request.request_id,
            "disposition":toolchain.disposition(), "pinned":request.toolchain_identity.is_some(),
        })
    );
    if request.dependency_context.is_some()
        && (source.is_none()
            || request.toolchain_identity.is_none()
            || request.command_context != CommandContext::default())
    {
        let _ = control.retain_outputs(Err(
            "dependency execution requires owned source, pinned toolchain and exclusive context"
                .to_owned(),
        ));
        return exec_error(request.request_id);
    }
    // The peer supplies only a declaration; this execution owns fresh physical
    // backing. Use D005's existing mount builder and keep the owner alive until
    // the process and drains have resolved and the exact output set is captured.
    let artifacts = match control
        .artifact_plan()
        .map(PreparedArtifacts::new)
        .transpose()
    {
        Ok(artifacts) => artifacts,
        Err(error) => {
            let _ = control.retain_artifacts(Err(format!("artifact preparation: {error}")));
            return exec_error(request.request_id);
        }
    };
    // A dependency execution must not inherit files written into the worker's
    // persistent canonical HOME by a prior command. Only this fresh owner and
    // its jobserver FIFO are visible at the runtime mount, until drains resolve.
    let dependency_home = if request.dependency_context.is_some() {
        match tempfile::Builder::new()
            .prefix("rabs-dependency-home-")
            .tempdir()
        {
            Ok(directory) => Some(directory),
            Err(error) => {
                let _ =
                    control.retain_outputs(Err(format!("dependency runtime preparation: {error}")));
                return exec_error(request.request_id);
            }
        }
    } else {
        None
    };
    let execution_home = dependency_home
        .as_ref()
        .map_or(home_backing, |directory| directory.path());
    // This fresh empty tree is a separate owner: exposing it under writable
    // HOME as well would let a compiler populate a supposedly empty input.
    let dependency_empty = if request.dependency_context.is_some() {
        match tempfile::Builder::new()
            .prefix("rabs-dependency-empty-")
            .tempdir()
        {
            Ok(directory) => Some(directory),
            Err(error) => {
                let _ =
                    control.retain_outputs(Err(format!("dependency search preparation: {error}")));
                return exec_error(request.request_id);
            }
        }
    } else {
        None
    };
    let prepared_spec = (|| -> Result<_, String> {
        if let Some(context) = &request.dependency_context {
            let source = source.ok_or("dependency execution lacks its source owner")?;
            let artifacts = artifacts
                .as_ref()
                .ok_or("dependency execution requires declared outputs")?;
            let empty = dependency_empty
                .as_ref()
                .ok_or("dependency execution lacks its empty search owner")?;
            let source_root = source
                .dependency_root(request.request_id)
                .map_err(|error| error.to_string())?;
            // The runtime cohort probes the output materialization filesystem.
            // Both fresh trees normally share the temp parent; explicitly refuse
            // a different source filesystem instead of assuming its lookup rules.
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                let source_device = std::fs::metadata(source_root)
                    .map_err(|error| error.to_string())?
                    .dev();
                let output_device = std::fs::metadata(artifacts.backing())
                    .map_err(|error| error.to_string())?
                    .dev();
                if source_device != output_device {
                    return Err(
                        "dependency source and output materialization filesystems differ"
                            .to_owned(),
                    );
                }
            }
            context
                .prepare_empty_backings(empty.path())
                .map_err(|error| format!("dependency loader mountpoints: {error}"))?;
            let spec = context
                .namespace(
                    source_root,
                    toolchain.root(),
                    artifacts.backing(),
                    empty.path(),
                    execution_home,
                )
                .map_err(|error| error.to_string())?;
            source
                .protect_dependency(request.request_id, context, &spec)
                .map_err(|error| format!("dependency source isolation: {error}"))?;
            toolchain
                .validate_dependency_namespace(&spec, context)
                .map_err(|error| format!("dependency toolchain isolation: {error}"))?;
            let empty_root =
                std::fs::canonicalize(empty.path()).map_err(|error| error.to_string())?;
            for bind in &spec.rw_binds {
                let root =
                    std::fs::canonicalize(&bind.backing).map_err(|error| error.to_string())?;
                if root.starts_with(&empty_root) || empty_root.starts_with(&root) {
                    return Err("writable mount aliases empty dependency search storage".to_owned());
                }
            }
            Ok(spec)
        } else {
            let mut plan = CanonicalMountPlan::new(
                toolchain.root(),
                &request.workspace_backing,
                cargo_home_backing,
                home_backing,
            );
            if let Some(artifacts) = &artifacts {
                plan.out_units.push(artifacts.mount());
            }
            let mut spec = plan.to_spec().map_err(|error| error.to_string())?;
            request
                .command_context
                .apply_to(&mut spec)
                .map_err(|error| format!("command context: {error}"))?;
            if let Some(source) = source {
                source
                    .protect_workspace(request.request_id, &mut spec)
                    .map_err(|error| format!("source mount isolation: {error}"))?;
            }
            toolchain
                .validate_namespace(&spec)
                .map_err(|error| format!("toolchain mount isolation: {error}"))?;
            Ok(spec)
        }
    })();
    let mut spec = match prepared_spec {
        Ok(spec) => spec,
        Err(error) => {
            let _ = control.retain_outputs(Err(error));
            return exec_error(request.request_id);
        }
    };
    // Worker-local jobserver authority runs on the FINAL env: extra_env
    // may carry smuggled coordination keys, so replacement must see them.
    let grant = request.jobserver_grant.unwrap_or(slots).min(slots).max(1);
    // One real FIFO budget is held until the process group and drains resolve.
    // Runtime coordination belongs in writable HOME, never in verified source.
    let bridge = match crate::jobserver::JobserverBridge::mint(grant, execution_home) {
        Ok(bridge) => bridge,
        Err(_) => return exec_error(request.request_id),
    };
    let launch = if let Some(context) = &request.dependency_context {
        crate::jobserver::JobserverBridge::apply_dependency(&mut spec.env, &bridge);
        rabs_sandbox::dependency_context::build_dependency_argv(
            context,
            &spec,
            &support,
            &request.program,
            &request.args,
        )
    } else {
        crate::jobserver::JobserverBridge::apply(&mut spec.env, &bridge);
        build_canonical_argv(&spec, &support, &request.program, &request.args)
    };
    let launch = match launch {
        Ok(launch) => launch,
        Err(error) => {
            let _ = control.retain_outputs(Err(format!("namespace launch: {error}")));
            return exec_error(request.request_id);
        }
    };

    // Managed process-group execution (G006) with concurrent bounded G007 drains.
    let mut command = command_for(&launch);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let attribution = Attribution {
        attempt: Some(request.request_id.to_string()),
        ..Attribution::default()
    };
    if control.reason().is_some() {
        return exec_error(request.request_id);
    }
    if let Err(error) = toolchain.verify(|| control.reason().is_some()) {
        let _ = control.retain_outputs(Err(format!(
            "toolchain pre-execution verification: {error}"
        )));
        return exec_error(request.request_id);
    }
    if let Some(context) = &request.dependency_context
        && let Err(error) = verify_dependency_runtime(context, &toolchain, artifacts.as_ref())
    {
        let _ = control.retain_outputs(Err(format!(
            "dependency runtime pre-execution verification: {error}"
        )));
        return exec_error(request.request_id);
    }
    // Verification may have spent the remaining lease or execution budget.
    // Do not start a compiler after that final input-preparation boundary.
    if control.reason().is_some() {
        return exec_error(request.request_id);
    }
    let Ok(group) = ManagedProcessGroup::spawn_command(command, attribution) else {
        return exec_error(request.request_id);
    };
    let limits = rabs_asupersync::stream_drain::DrainLimits {
        resident_bound: EXEC_STREAM_RESIDENT_BOUND,
        spill_dir: spill_root.join(format!("attempt-{}", request.request_id)),
    };
    // Live tails are observational only. The SAME managed wait still owns the
    // aggregate capture budget, cancellation, descendant cleanup and full spools.
    let outcome = match group.wait_with_bounded_drain_preview(
        &limits,
        rabs_asupersync::stream_drain::DEFAULT_MAX_CAPTURE_BYTES,
        Some(control.output_observer()),
        || control.reason().is_some(),
    ) {
        Ok(output) => {
            // A same-credential host mutation is outside namespace isolation.
            // Detect retained backing changes before offering successful output;
            // read-only file modes alone are not a cryptographic seal.
            // Interrupted execution cannot offer successful artifacts, but its
            // diagnostics must still drain and be delivered. Do not turn an
            // intentional stop during this verification into lost output.
            if control.reason().is_none()
                && let Err(error) = toolchain.verify(|| control.reason().is_some())
                && control.reason().is_none()
            {
                let _ = control.retain_outputs(Err(format!(
                    "toolchain post-execution verification: {error}"
                )));
                return exec_error(request.request_id);
            }
            if control.reason().is_none()
                && let Some(context) = &request.dependency_context
                && let Err(error) =
                    verify_dependency_runtime(context, &toolchain, artifacts.as_ref())
                && control.reason().is_none()
            {
                let _ = control.retain_outputs(Err(format!(
                    "dependency runtime post-execution verification: {error}"
                )));
                return exec_error(request.request_id);
            }
            // Cleanup precedes both diagnostic and artifact capture. The outer
            // control frontier still overrides interrupted zero exits.
            #[cfg(unix)]
            let exit_code = output.status.code().unwrap_or_else(|| {
                use std::os::unix::process::ExitStatusExt;
                output.status.signal().map_or(-1, |s| 128 + s)
            });
            #[cfg(not(unix))]
            let exit_code = output.status.code().unwrap_or(-1);
            let (stdout_sha256, stderr_sha256) = if control.output_capture_requested() {
                let capture = CapturedOutputs::from_lanes(&output.stdout, &output.stderr);
                let digests = capture.as_ref().ok().map(|outputs| {
                    (
                        outputs.stdout.sha256().to_owned(),
                        outputs.stderr.sha256().to_owned(),
                    )
                });
                if control
                    .retain_outputs(capture.map_err(|error| error.to_string()))
                    .is_err()
                {
                    return exec_error(request.request_id);
                }
                let Some(digests) = digests else {
                    return exec_error(request.request_id);
                };
                digests
            } else {
                match (stream_digest(&output.stdout), stream_digest(&output.stderr)) {
                    (Ok(s), Ok(e)) => (s, e),
                    (Err(error), _) | (_, Err(error)) => {
                        let _ = control
                            .retain_outputs(Err(format!("diagnostic digest capture: {error}")));
                        return exec_error(request.request_id);
                    }
                }
            };
            if let Some(artifacts) = artifacts
                && exit_code == 0
                && output.residual_group_members == 0
                && control.reason().is_none()
            {
                let capture = artifacts.capture(|| control.reason().is_some());
                // Retain failure as evidence. A zero compiler exit is NOT a
                // successful completion if its requested artifact set is missing.
                if control
                    .retain_artifacts(capture.map_err(|error| error.to_string()))
                    .is_err()
                {
                    return exec_error(request.request_id);
                }
            }
            ExecResult {
                request_id: request.request_id,
                exit_code,
                stdout_sha256,
                stderr_sha256,
                executed: true,
                residual_group_members: output.residual_group_members,
                stdout_spill_bytes: output.stdout.spilled_bytes(),
                stderr_spill_bytes: output.stderr.spilled_bytes(),
                stdout_spill_path: output.stdout.spill().map(|s| s.path.display().to_string()),
                stderr_spill_path: output.stderr.spill().map(|s| s.path.display().to_string()),
            }
        }
        Err(_) => exec_error(request.request_id),
    };
    drop(bridge);
    outcome
}

fn exec_error(request_id: u64) -> ExecResult {
    ExecResult {
        request_id,
        exit_code: -1,
        stdout_sha256: sha256_hex(b""),
        stderr_sha256: sha256_hex(b""),
        executed: false,
        residual_group_members: 0,
        stdout_spill_bytes: 0,
        stderr_spill_bytes: 0,
        stdout_spill_path: None,
        stderr_spill_path: None,
    }
}

/// Validate a handshake's capability token + capability requirement
/// (pure: the coordinator's admission decision).
///
/// # Errors
/// Typed [`HandshakeRefusal`] on token failure or missing capability.
pub fn admit_worker(
    token: &CapabilityToken,
    revoked: &[u64],
    current_seq: u64,
    session_id: u64,
    operation_id: u64,
    report: &CapabilityReport,
    require_canonical: bool,
) -> Result<(), HandshakeRefusal> {
    rabs_protocol::capability_tokens::validate(
        token,
        revoked,
        current_seq,
        session_id,
        operation_id,
    )
    .map_err(|refusal| HandshakeRefusal::TokenInvalid(format!("{refusal:?}")))?;
    if require_canonical && !report.canonical_namespace {
        return Err(HandshakeRefusal::NotCanonicalCapable);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rabs_protocol::capability_tokens::{CapabilityKind, mint};

    fn token() -> CapabilityToken {
        mint(1, CapabilityKind::ExecuteAction, 7, 3, "worker/exec", 100).unwrap()
    }

    #[test]
    fn admission_validates_token_and_capability_requirement() {
        let report = CapabilityReport {
            worker_id: "hz2".into(),
            canonical_namespace: true,
            missing: vec![],
            slots: 8,
        };
        assert!(admit_worker(&token(), &[], 50, 7, 3, &report, true).is_ok());
        assert!(matches!(
            admit_worker(&token(), &[], 50, 999, 3, &report, true),
            Err(HandshakeRefusal::TokenInvalid(_))
        ));
        assert!(matches!(
            admit_worker(&token(), &[1], 50, 7, 3, &report, true),
            Err(HandshakeRefusal::TokenInvalid(_))
        ));
        let weak = CapabilityReport {
            canonical_namespace: false,
            missing: vec!["bubblewrap".into()],
            ..report.clone()
        };
        assert!(matches!(
            admit_worker(&token(), &[], 50, 7, 3, &weak, true),
            Err(HandshakeRefusal::NotCanonicalCapable)
        ));
        assert!(admit_worker(&token(), &[], 50, 7, 3, &weak, false).is_ok());
    }

    #[test]
    fn exec_result_is_an_offer_with_content_digests() {
        let result = ExecResult {
            request_id: 9,
            exit_code: 0,
            stdout_sha256: sha256_hex(b"hello"),
            stderr_sha256: sha256_hex(b""),
            executed: true,
            residual_group_members: 0,
            stdout_spill_bytes: 0,
            stderr_spill_bytes: 0,
            stdout_spill_path: None,
            stderr_spill_path: None,
        };
        assert_eq!(result.request_id, 9);
        assert_eq!(
            result.stdout_sha256,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn sha256_hex_is_stable() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn toolchain_identity_decode_is_exact_and_never_defaults_malformed_input() {
        use serde_json::json;
        assert_eq!(parse_toolchain_identity(&json!({})).unwrap(), None);
        let valid = json!({"version":TOOLCHAIN_DATASET_VERSION,
            "sha256":"ab".repeat(32), "files":12, "bytes":345});
        let request = json!({"toolchain_identity":valid});
        assert_eq!(
            parse_toolchain_identity(&request).unwrap(),
            Some(ToolchainIdentity {
                sha256: [0xab; 32],
                files: 12,
                bytes: 345,
            })
        );
        for invalid in [
            serde_json::Value::Null,
            json!("ab".repeat(32)),
            json!({"version":"v2","sha256":"ab".repeat(32),"files":12,"bytes":345}),
            json!({"version":TOOLCHAIN_DATASET_VERSION,"sha256":"AB".repeat(32),"files":12,"bytes":345}),
            json!({"version":TOOLCHAIN_DATASET_VERSION,"sha256":"é".repeat(32),"files":12,"bytes":345}),
            json!({"version":TOOLCHAIN_DATASET_VERSION,"sha256":"ab".repeat(32),"files":-1,"bytes":345}),
            json!({"version":TOOLCHAIN_DATASET_VERSION,"sha256":"ab".repeat(32),"files":12}),
            json!({"version":TOOLCHAIN_DATASET_VERSION,"sha256":"ab".repeat(32),"files":12,"bytes":345,"extra":true}),
        ] {
            assert!(parse_toolchain_identity(&json!({"toolchain_identity":invalid})).is_err());
        }
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn non_canonical_host_returns_typed_non_result_not_fake_success() {
        let dir = tempfile::tempdir().expect("tempdir");
        let request = CanonicalExecRequest {
            request_id: 1,
            program: "true".into(),
            args: vec![],
            toolchain_backing: "/tc".into(),
            toolchain_identity: None,
            workspace_backing: "/ws".into(),
            jobserver_grant: None,
            command_context: CommandContext::default(),
            dependency_context: None,
        };
        let result = execute_canonical(&request, dir.path(), dir.path(), 4, dir.path());
        assert!(!result.executed, "no fabricated success off-Linux");
    }

    #[test]
    fn cancelled_preflight_never_creates_a_jobserver_or_launches() {
        let dir = tempfile::tempdir().unwrap();
        let request = CanonicalExecRequest {
            request_id: 99,
            program: "true".into(),
            args: vec![],
            toolchain_backing: dir.path().join("absent-toolchain").display().to_string(),
            toolchain_identity: None,
            workspace_backing: dir.path().join("absent-workspace").display().to_string(),
            jobserver_grant: Some(2),
            command_context: CommandContext::default(),
            dependency_context: None,
        };
        let control = ExecutionControl::new(std::time::Duration::from_secs(10)).unwrap();
        control.cancel(crate::execution::StopReason::Cancelled);
        let result =
            execute_canonical_controlled(&request, dir.path(), dir.path(), 2, dir.path(), &control);
        assert!(!result.executed);
        assert_eq!(result.exit_code, 130);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn command_context_decode_preserves_exact_values_and_defaults_only_when_absent() {
        use serde_json::json;
        assert_eq!(
            parse_command_context(&json!({})).unwrap(),
            CommandContext::default()
        );
        let request = json!({"command_context": {"version":COMMAND_CONTEXT_VERSION,
            "cwd":"/__rabs/workspace/member", "env":{"EMPTY":"", "LABEL":"spaces \"$HOME\"\n雪"}}});
        let original = request.clone();
        let context = parse_command_context(&request).unwrap();
        assert_eq!(
            context.cwd(),
            std::path::Path::new("/__rabs/workspace/member")
        );
        assert_eq!(
            context.environment(),
            &[
                ("EMPTY".to_owned(), String::new()),
                ("LABEL".to_owned(), "spaces \"$HOME\"\n雪".to_owned())
            ]
        );
        assert_eq!(
            request, original,
            "parsing never rewrites the journal request"
        );
    }

    #[test]
    fn malformed_command_context_never_becomes_default_context() {
        use serde_json::{Value, json};
        let valid = json!({"version":COMMAND_CONTEXT_VERSION,"cwd":"/__rabs/workspace","env":{}});
        for invalid in [
            Value::Null,
            json!(true),
            json!([]),
            json!("env-cwd-v1"),
            json!({"version":COMMAND_CONTEXT_VERSION,"env":{}}),
        ] {
            assert!(parse_command_context(&json!({"command_context":invalid})).is_err());
        }
        for (field, value) in [
            ("version", json!("env-cwd-v2")),
            ("cwd", Value::Null),
            ("cwd", json!("/__rabs/workspace/../home")),
            ("env", json!([])),
            ("env", json!({"LABEL":17})),
            ("env", json!({"HOME":"/other"})),
            ("env", json!({"CARGO_MAKEFLAGS":"-j999"})),
            ("env", json!({"LABEL":"bad\u{0000}value"})),
        ] {
            let mut changed = valid.clone();
            changed[field] = value;
            assert!(parse_command_context(&json!({"command_context":changed})).is_err());
        }
        let mut extra = valid;
        extra["inherit_host"] = json!(true);
        assert!(parse_command_context(&json!({"command_context":extra})).is_err());
    }

    #[cfg(unix)]
    fn digest_fixture(
        bytes: &[u8],
        resident_bound: usize,
    ) -> (tempfile::TempDir, rabs_asupersync::stream_drain::LaneDrain) {
        use rabs_asupersync::stream_drain::{DrainLimits, join_lane, spawn_lanes};
        use std::process::{Command, Stdio};
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("input");
        std::fs::write(&source, bytes).unwrap();
        let mut child = Command::new("/bin/cat")
            .arg(&source)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let (stdout, stderr) = spawn_lanes(
            &mut child,
            &DrainLimits {
                resident_bound,
                spill_dir: dir.path().join("spill"),
            },
        );
        assert!(stderr.is_none());
        assert!(child.wait().unwrap().success());
        (dir, join_lane(stdout.unwrap()).unwrap())
    }

    #[cfg(unix)]
    #[test]
    fn stream_digest_matches_delivery_for_every_resident_partition() {
        use crate::output::{CapturedStream, MAX_OUTPUT_CHUNK_BYTES};
        for bytes in [Vec::new(), vec![0, 255, 128, 10], vec![37; 196_615]] {
            let expected = sha256_hex(&bytes);
            for resident in [0, 3, 1024 * 1024] {
                let (_dir, lane) = digest_fixture(&bytes, resident);
                assert_eq!(stream_digest(&lane).unwrap(), expected);
                let mut capture = CapturedStream::from_lane(&lane).unwrap();
                assert_eq!(capture.sha256(), expected);
                let mut restored = Vec::new();
                while (restored.len() as u64) < capture.len() {
                    restored.extend(
                        capture
                            .read_chunk(restored.len() as u64, MAX_OUTPUT_CHUNK_BYTES)
                            .unwrap(),
                    );
                }
                assert_eq!(restored, bytes);
                assert_eq!(stream_digest(&lane).unwrap(), expected);
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn stream_digest_cannot_adopt_replaced_or_linked_spill_names() {
        for link in [false, true] {
            let (dir, lane) = digest_fixture(b"original", 3);
            let expected = sha256_hex(b"original");
            assert_eq!(stream_digest(&lane).unwrap(), expected);
            let path = &lane.spill().unwrap().path;
            std::fs::rename(path, dir.path().join("retained-original")).unwrap();
            if link {
                let replacement = dir.path().join("replacement");
                std::fs::write(&replacement, b"wrong").unwrap();
                std::os::unix::fs::symlink(&replacement, path).unwrap();
            } else {
                std::fs::write(path, b"wrong").unwrap();
            }
            // Rename may alter ctime. Refusal is conservative; success must
            // still certify the original, not the equal-length replacement.
            if let Ok(digest) = stream_digest(&lane) {
                assert_eq!(digest, expected);
            }
            assert_eq!(std::fs::read(path).unwrap(), b"wrong");
        }
    }

    #[cfg(unix)]
    #[test]
    fn stream_digest_refuses_same_size_rewrite_with_restored_mtime() {
        let (_dir, lane) = digest_fixture(b"original", 3);
        assert_eq!(stream_digest(&lane).unwrap(), sha256_hex(b"original"));
        let path = &lane.spill().unwrap().path;
        let modified = std::fs::metadata(path).unwrap().modified().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2));
        std::fs::write(path, b"wrong").unwrap();
        std::fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(modified))
            .unwrap();
        assert!(stream_digest(&lane).is_err());
        assert!(crate::output::CapturedStream::from_lane(&lane).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn stream_digest_refuses_truncated_and_growing_spills() {
        for length in [0, 4, 6] {
            let (_dir, lane) = digest_fixture(b"original", 3);
            assert_eq!(lane.spilled_bytes(), 5);
            assert_eq!(stream_digest(&lane).unwrap(), sha256_hex(b"original"));
            std::fs::File::options()
                .write(true)
                .open(&lane.spill().unwrap().path)
                .unwrap()
                .set_len(length)
                .unwrap();
            assert!(stream_digest(&lane).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn stream_digest_and_delivery_keep_concurrent_cursors_independent() {
        let bytes: Vec<u8> = (0..131_079).map(|n| (n % 251) as u8).collect();
        let (_dir, lane) = digest_fixture(&bytes, 7);
        let lane = std::sync::Arc::new(lane);
        let threads: Vec<_> = (0..8)
            .map(|index| {
                let lane = std::sync::Arc::clone(&lane);
                std::thread::spawn(move || {
                    if index % 2 == 0 {
                        stream_digest(&lane).unwrap()
                    } else {
                        crate::output::CapturedStream::from_lane(&lane)
                            .unwrap()
                            .sha256()
                            .to_owned()
                    }
                })
            })
            .collect();
        let expected = sha256_hex(&bytes);
        for thread in threads {
            assert_eq!(thread.join().unwrap(), expected);
        }
    }
}
