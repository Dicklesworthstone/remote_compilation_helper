//! The worker session (bead S5 / bridge plan Phase S): the FIRST wire
//! use of the J-epic protocol schemas. A `rabs-wkr` worker connects to
//! the coordinator over asupersync TCP, authenticates with a capability
//! token, reports capability + pressure, and serves
//! `CanonicalExecRequest`s by running them through the PROVEN
//! rabs-sandbox launcher — the D003/D005 acceptance, now ORCHESTRATED
//! instead of hand-SSH'd.
//!
//! ## R50, structurally
//!
//! A worker OFFERS prepared-result metadata; it NEVER commits an action
//! pointer. This module imports no commit type and exposes no commit
//! frame — the coordinator refuses commits until Phase 1, and the
//! worker literally cannot express one. The only outbound result frame
//! is `exec-result` (exit + streamed output digests), which is an
//! offer, not a publication.
//!
//! ## Wire format
//!
//! Newline-delimited JSON, one frame per line (same discipline as the
//! edge UDS). Handshake: worker sends `worker-hello` (id + capability
//! token + capability report); coordinator replies `session-ok` or a
//! typed refusal. Steady state: coordinator sends `canonical-exec`
//! requests and `ping`s; worker answers `exec-result`/`pong` and
//! periodically pushes `heartbeat` (capability + pressure).

use rabs_protocol::capability_tokens::CapabilityToken;

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
}

/// The result of one canonical execution — an OFFER, never a commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecResult {
    /// Echoes the request id.
    pub request_id: u64,
    /// Process exit code (or 128+signal).
    pub exit_code: i32,
    /// SHA-256 of stdout bytes (hex).
    pub stdout_sha256: String,
    /// SHA-256 of stderr bytes (hex).
    pub stderr_sha256: String,
    /// Whether execution reached the sandbox at all (false = host
    /// cannot run the canonical namespace; a typed non-result, not a
    /// fake success).
    pub executed: bool,
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
    // Free disk via statvfs-free byte count is platform-specific; use a
    // portable fallback (metadata of the dir can't give free space, so
    // 0 = unknown until the platform probe lands — honest sentinel).
    let free_disk_mib = free_disk_mib(staging_dir);
    PressureSample {
        load_x100,
        free_disk_mib,
    }
}

#[cfg(target_os = "linux")]
fn free_disk_mib(dir: &std::path::Path) -> u64 {
    // `df -k` is portable across the fleet and avoids a libc dep in a
    // forbid-unsafe crate.
    let output = std::process::Command::new("df")
        .arg("-k")
        .arg(dir)
        .output();
    output
        .ok()
        .and_then(|o| {
            String::from_utf8(o.stdout).ok().and_then(|text| {
                text.lines().nth(1).and_then(|line| {
                    line.split_whitespace().nth(3).and_then(|kb| kb.parse::<u64>().ok())
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

/// Execute one canonical request through the PROVEN rabs-sandbox
/// launcher. On a host that cannot run the namespace, returns a typed
/// non-result (`executed: false`) — never a fabricated success.
#[must_use]
pub fn execute_canonical(
    request: &CanonicalExecRequest,
    cargo_home_backing: &std::path::Path,
    home_backing: &std::path::Path,
) -> ExecResult {
    use rabs_sandbox::canonical_mounts::CanonicalMountPlan;
    use rabs_sandbox::canonical_namespace::{HostIsolationSupport, build_canonical_argv, command_for};

    let support = HostIsolationSupport::probe();
    if !support.missing_for_canonical().is_empty() {
        return ExecResult {
            request_id: request.request_id,
            exit_code: -1,
            stdout_sha256: sha256_hex(b""),
            stderr_sha256: sha256_hex(b""),
            executed: false,
        };
    }

    let plan = CanonicalMountPlan::new(
        &request.toolchain_backing,
        &request.workspace_backing,
        cargo_home_backing,
        home_backing,
    );
    let Ok(spec) = plan.to_spec() else {
        return exec_error(request.request_id);
    };
    let Ok(launch) = build_canonical_argv(&spec, &support, &request.program, &request.args) else {
        return exec_error(request.request_id);
    };
    match command_for(&launch).output() {
        Ok(output) => ExecResult {
            request_id: request.request_id,
            exit_code: output.status.code().unwrap_or(-1),
            stdout_sha256: sha256_hex(&output.stdout),
            stderr_sha256: sha256_hex(&output.stderr),
            executed: true,
        },
        Err(_) => exec_error(request.request_id),
    }
}

fn exec_error(request_id: u64) -> ExecResult {
    ExecResult {
        request_id,
        exit_code: -1,
        stdout_sha256: sha256_hex(b""),
        stderr_sha256: sha256_hex(b""),
        executed: false,
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
        // Wrong session: typed refusal.
        assert!(matches!(
            admit_worker(&token(), &[], 50, 999, 3, &report, true),
            Err(HandshakeRefusal::TokenInvalid(_))
        ));
        // Revoked: typed refusal.
        assert!(matches!(
            admit_worker(&token(), &[1], 50, 7, 3, &report, true),
            Err(HandshakeRefusal::TokenInvalid(_))
        ));
        // Non-canonical host where canonical is required.
        let weak = CapabilityReport {
            canonical_namespace: false,
            missing: vec!["bubblewrap".into()],
            ..report.clone()
        };
        assert!(matches!(
            admit_worker(&token(), &[], 50, 7, 3, &weak, true),
            Err(HandshakeRefusal::NotCanonicalCapable)
        ));
        // Same weak host, canonical NOT required: admitted.
        assert!(admit_worker(&token(), &[], 50, 7, 3, &weak, false).is_ok());
    }

    #[test]
    fn exec_result_is_an_offer_with_content_digests() {
        // No commit type is reachable from this module: ExecResult
        // carries digests (an offer), never a published pointer.
        let result = ExecResult {
            request_id: 9,
            exit_code: 0,
            stdout_sha256: sha256_hex(b"hello"),
            stderr_sha256: sha256_hex(b""),
            executed: true,
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

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn non_canonical_host_returns_typed_non_result_not_fake_success() {
        // On macOS the canonical namespace is unavailable: executed=false,
        // never a fabricated exit 0.
        let request = CanonicalExecRequest {
            request_id: 1,
            program: "true".into(),
            args: vec![],
            toolchain_backing: "/tc".into(),
            workspace_backing: "/ws".into(),
        };
        let dir = tempfile::tempdir().unwrap();
        let result = execute_canonical(&request, dir.path(), dir.path());
        assert!(!result.executed, "no fabricated success off-Linux");
    }
}
