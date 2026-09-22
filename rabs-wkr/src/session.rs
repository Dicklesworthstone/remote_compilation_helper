//! Canonical worker execution (bead S5 / bridge plan Phase S).
//!
//! The live session drives this executor through the existing sandbox launcher,
//! worker-local jobserver, owned process groups and bounded diagnostic drains.
//! Negotiated artifact requests add a fresh D005 output mount and exact-set
//! harvesting after successful cleanup. Results are offers, never publications;
//! the prototype newline transport is not authenticated ATP.

use rabs_protocol::capability_tokens::CapabilityToken;
use crate::artifacts::PreparedArtifacts;
use crate::execution::{DEFAULT_EXECUTION_TIMEOUT, ExecutionControl};
use crate::output::CapturedOutputs;
use crate::source_transfer::SourceOwner;

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
    /// Toolchain backing directory (mounts at `/__rabs/toolchain`).
    pub toolchain_backing: String,
    /// Workspace backing directory (mounts at `/__rabs/workspace`).
    pub workspace_backing: String,
    /// Execution resource grant for this attempt (bead I004): the
    /// total jobserver slot budget the coordinator admits (one implicit
    /// slot plus C-1 transferable tokens).
    /// It cannot exceed the worker's own slot count; zero floors to
    /// one. `None` uses the worker's slot count.
    pub jobserver_grant: Option<u32>,
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

/// SHA-256 of a G007 drained stream: the digest covers the FULL byte
/// sequence the action wrote — resident head first, then every spilled
/// byte read back incrementally from the archive — so a spilled stream
/// and a fully-resident one with identical content hash identically.
///
/// # Errors
/// Typed [`std::io::Error`] if the spill archive cannot be re-read; the
/// caller reports a typed non-result rather than a fabricated digest.
fn stream_digest(lane: &rabs_asupersync::stream_drain::LaneDrain) -> std::io::Result<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read as _;
    let mut hasher = Sha256::new();
    hasher.update(lane.resident());
    if let Some(spill) = lane.spill() {
        let file = std::fs::File::open(&spill.path)?;
        let mut reader = std::io::BufReader::new(file);
        let mut chunk = [0u8; 64 * 1024];
        loop {
            let n = reader.read(&mut chunk)?;
            if n == 0 { break; }
            hasher.update(&chunk[..n]);
        }
    }
    Ok(hex(&hasher.finalize()))
}

/// Probe this host's real capability (the scheduler consumes it).
#[must_use]
pub fn probe_capability(worker_id: &str) -> CapabilityReport {
    let support = rabs_sandbox::canonical_namespace::HostIsolationSupport::probe();
    let missing: Vec<String> = support.missing_for_canonical().into_iter().map(str::to_string).collect();
    let slots = std::thread::available_parallelism().map(|n| n.get() as u32).unwrap_or(1);
    CapabilityReport {
        worker_id: worker_id.to_string(), canonical_namespace: missing.is_empty(), missing, slots,
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
    PressureSample { load_x100, free_disk_mib }
}

#[cfg(target_os = "linux")]
fn free_disk_mib(dir: &std::path::Path) -> u64 {
    // POSIX df output guarantees one line per filesystem; avoid libc/unsafe.
    let output = std::process::Command::new("df").arg("-Pk").arg(dir).output();
    output.ok().and_then(|o| {
        String::from_utf8(o.stdout).ok().and_then(|text| {
            text.lines().nth(1).and_then(|line| {
                line.split_whitespace().nth(3).and_then(|kb| kb.parse::<u64>().ok())
            })
        })
    }).map(|kb| kb / 1024).unwrap_or(0)
}

#[cfg(not(target_os = "linux"))]
fn free_disk_mib(_dir: &std::path::Path) -> u64 { 0 }

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
    execute_canonical_controlled(request, cargo_home_backing, home_backing, slots, spill_root, &control)
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
    let mut result = execute_canonical_inner(request, cargo_home_backing, home_backing, slots, spill_root, control, None);
    if let Some(reason) = control.finish() { result.exit_code = reason.exit_code(); }
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
        request, cargo_home_backing, home_backing, slots, spill_root, control, Some(source),
    );
    if let Some(reason) = control.finish() { result.exit_code = reason.exit_code(); }
    result
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
    use rabs_sandbox::canonical_namespace::{HostIsolationSupport, build_canonical_argv, command_for};
    use std::process::Stdio;
    if control.reason().is_some() { return exec_error(request.request_id); }
    let support = HostIsolationSupport::probe();
    if !support.missing_for_canonical().is_empty() { return exec_error(request.request_id); }

    let mut plan = CanonicalMountPlan::new(
        &request.toolchain_backing, &request.workspace_backing, cargo_home_backing, home_backing,
    );
    // The peer supplies only a declaration; this execution owns fresh physical
    // backing. Use D005's existing mount builder and keep the owner alive until
    // the process and drains have resolved and the exact output set is captured.
    let artifacts = match control.artifact_plan().map(PreparedArtifacts::new).transpose() {
        Ok(artifacts) => artifacts,
        Err(error) => {
            let _ = control.retain_artifacts(Err(format!("artifact preparation: {error}")));
            return exec_error(request.request_id);
        }
    };
    if let Some(artifacts) = &artifacts { plan.out_units.push(artifacts.mount()); }
    let Ok(mut spec) = plan.to_spec() else { return exec_error(request.request_id); };
    if let Some(source) = source
        && let Err(error) = source.protect_workspace(request.request_id, &mut spec)
    {
        let _ = control.retain_outputs(Err(format!("source mount isolation: {error}")));
        return exec_error(request.request_id);
    }
    // Worker-local jobserver authority runs on the FINAL env: extra_env
    // may carry smuggled coordination keys, so replacement must see them.
    let grant = request.jobserver_grant.unwrap_or(slots).min(slots).max(1);
    // One real FIFO budget is held until the process group and drains resolve.
    // Runtime coordination belongs in writable HOME, never in verified source.
    let bridge = match crate::jobserver::JobserverBridge::mint(
        grant, home_backing,
    ) {
        Ok(bridge) => bridge,
        Err(_) => return exec_error(request.request_id),
    };
    crate::jobserver::JobserverBridge::apply(&mut spec.env, &bridge);
    let Ok(launch) = build_canonical_argv(&spec, &support, &request.program, &request.args) else {
        return exec_error(request.request_id);
    };

    // Managed process-group execution (G006) with concurrent bounded G007 drains.
    let mut command = command_for(&launch);
    command.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let attribution = Attribution { attempt: Some(request.request_id.to_string()), ..Attribution::default() };
    if control.reason().is_some() { return exec_error(request.request_id); }
    let Ok(group) = ManagedProcessGroup::spawn_command(command, attribution) else {
        return exec_error(request.request_id);
    };
    let limits = rabs_asupersync::stream_drain::DrainLimits {
        resident_bound: EXEC_STREAM_RESIDENT_BOUND,
        spill_dir: spill_root.join(format!("attempt-{}", request.request_id)),
    };
    let outcome = match group.wait_with_bounded_drain_controlled(&limits, || control.reason().is_some()) {
        Ok(output) => {
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
                let digests = capture.as_ref().ok().map(|outputs| (
                    outputs.stdout.sha256().to_owned(), outputs.stderr.sha256().to_owned(),
                ));
                if control.retain_outputs(capture.map_err(|error| error.to_string())).is_err() {
                    return exec_error(request.request_id);
                }
                let Some(digests) = digests else { return exec_error(request.request_id); };
                digests
            } else {
                match (stream_digest(&output.stdout), stream_digest(&output.stderr)) {
                    (Ok(s), Ok(e)) => (s, e),
                    _ => return exec_error(request.request_id),
                }
            };
            if let Some(artifacts) = artifacts
                && exit_code == 0 && output.residual_group_members == 0 && control.reason().is_none()
            {
                let capture = artifacts.capture(|| control.reason().is_some());
                // Retain failure as evidence. A zero compiler exit is NOT a
                // successful completion if its requested artifact set is missing.
                if control.retain_artifacts(capture.map_err(|error| error.to_string())).is_err() {
                    return exec_error(request.request_id);
                }
            }
            ExecResult {
                request_id: request.request_id, exit_code, stdout_sha256, stderr_sha256,
                executed: true, residual_group_members: output.residual_group_members,
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
        request_id, exit_code: -1, stdout_sha256: sha256_hex(b""), stderr_sha256: sha256_hex(b""),
        executed: false, residual_group_members: 0, stdout_spill_bytes: 0, stderr_spill_bytes: 0,
        stdout_spill_path: None, stderr_spill_path: None,
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
    rabs_protocol::capability_tokens::validate(token, revoked, current_seq, session_id, operation_id)
        .map_err(|refusal| HandshakeRefusal::TokenInvalid(format!("{refusal:?}")))?;
    if require_canonical && !report.canonical_namespace { return Err(HandshakeRefusal::NotCanonicalCapable); }
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
            worker_id: "hz2".into(), canonical_namespace: true, missing: vec![], slots: 8,
        };
        assert!(admit_worker(&token(), &[], 50, 7, 3, &report, true).is_ok());
        assert!(matches!(admit_worker(&token(), &[], 50, 999, 3, &report, true), Err(HandshakeRefusal::TokenInvalid(_))));
        assert!(matches!(admit_worker(&token(), &[1], 50, 7, 3, &report, true), Err(HandshakeRefusal::TokenInvalid(_))));
        let weak = CapabilityReport {
            canonical_namespace: false, missing: vec!["bubblewrap".into()], ..report.clone()
        };
        assert!(matches!(admit_worker(&token(), &[], 50, 7, 3, &weak, true), Err(HandshakeRefusal::NotCanonicalCapable)));
        assert!(admit_worker(&token(), &[], 50, 7, 3, &weak, false).is_ok());
    }

    #[test]
    fn exec_result_is_an_offer_with_content_digests() {
        let result = ExecResult {
            request_id: 9, exit_code: 0, stdout_sha256: sha256_hex(b"hello"), stderr_sha256: sha256_hex(b""),
            executed: true, residual_group_members: 0, stdout_spill_bytes: 0, stderr_spill_bytes: 0,
            stdout_spill_path: None, stderr_spill_path: None,
        };
        assert_eq!(result.request_id, 9);
        assert_eq!(result.stdout_sha256, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    }

    #[test]
    fn sha256_hex_is_stable() {
        assert_eq!(sha256_hex(b""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn non_canonical_host_returns_typed_non_result_not_fake_success() {
        let dir = tempfile::tempdir().expect("tempdir");
        let request = CanonicalExecRequest {
            request_id: 1, program: "true".into(), args: vec![], toolchain_backing: "/tc".into(),
            workspace_backing: "/ws".into(), jobserver_grant: None,
        };
        let result = execute_canonical(&request, dir.path(), dir.path(), 4, dir.path());
        assert!(!result.executed, "no fabricated success off-Linux");
    }

    #[test]
    fn cancelled_preflight_never_creates_a_jobserver_or_launches() {
        let dir = tempfile::tempdir().unwrap();
        let request = CanonicalExecRequest {
            request_id: 99, program: "true".into(), args: vec![],
            toolchain_backing: dir.path().join("absent-toolchain").display().to_string(),
            workspace_backing: dir.path().join("absent-workspace").display().to_string(),
            jobserver_grant: Some(2),
        };
        let control = ExecutionControl::new(std::time::Duration::from_secs(10)).unwrap();
        control.cancel(crate::execution::StopReason::Cancelled);
        let result = execute_canonical_controlled(&request, dir.path(), dir.path(), 2, dir.path(), &control);
        assert!(!result.executed);
        assert_eq!(result.exit_code, 130);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }
}
