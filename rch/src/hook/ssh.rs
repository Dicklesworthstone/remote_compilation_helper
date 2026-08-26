//! Low-level SSH execution + remote topology-enforcement preflight for the hook.
//!
//! This submodule owns the offload pipeline's SSH primitives, extracted from
//! `hook.rs` per bead `remote_compilation_helper-zcecy.14`:
//!
//! - `run_offload_ssh_command` — the hardened executor for the offload flow's
//!   one-shot *control-plane* SSH commands (topology preflight, repo_updater
//!   closure convergence, and dependency-manifest verification). The build
//!   command itself does not go through here — it streams over a separate path
//!   (`transfer_orchestration`'s `execute_remote_streaming`). It takes a
//!   caller-supplied timeout and is hardened with `kill_on_drop` + concurrent
//!   stdout/stderr draining so a slow or hung worker can never leak a local
//!   `ssh` process or deadlock the child on a full pipe buffer.
//! - `ensure_worker_projects_topology` — runs the remote topology preflight that
//!   normalizes the worker's `/data/projects` ↔ `/dp` layout, plus its shell
//!   script builder `build_worker_projects_topology_cmd`.
//! - `should_skip_remote_preflight` — the mock-mode gate that short-circuits all
//!   remote preflight under test.
//! - `build_remote_shell_command` — wraps a remote command as a single
//!   `sh -lc '…'` argument.
//!
//! Naming note: this is deliberately distinct from
//! `commands::workers_setup::run_setup_ssh_command`, the simpler setup/probe
//! helper (fixed 10s connect timeout, plain `cmd.output()`). The two used to
//! share the name `run_worker_ssh_command`, which was a grep-navigation footgun.
//!
//! It reaches its support layer from the parent via `use super::*` (`WorkerConfig`,
//! `HookReporter`, `PathTopologyPolicy`, `mock`, the tokio `Command`/`timeout`
//! primitives, and the `rch_common` types). The three offload-pipeline entry
//! points (`run_offload_ssh_command`, `ensure_worker_projects_topology`,
//! `should_skip_remote_preflight`) are `pub(super)` so `hook` and its sibling
//! submodules (`transfer_orchestration`, `repo_updater`) can call them; the two
//! shell-script builders stay private to this module.

use super::*;

const MAX_OFFLOAD_SSH_OUTPUT_BYTES: usize = 32 * 1024 * 1024;
const REMOTE_SOURCE_AUTHORITY_LOCK_DIR: &str = "/tmp/rch-source-authority-locks";

/// Keeps the worker-side advisory locks for a mutable Cargo source closure alive.
///
/// The remote shell blocks on this SSH session's stdin after acquiring every
/// lock. Dropping the guard kills the local SSH child; the resulting EOF/HUP
/// tears down the nested `flock` processes and releases their kernel locks.
pub(super) struct RemoteSourceAuthorityLock {
    worker_id: WorkerId,
    child: Option<tokio::process::Child>,
    stdin: Option<tokio::process::ChildStdin>,
    stdout_drain: Option<tokio::task::JoinHandle<std::io::Result<Vec<u8>>>>,
    stderr_drain: Option<tokio::task::JoinHandle<std::io::Result<Vec<u8>>>>,
}

impl RemoteSourceAuthorityLock {
    /// Fail closed if the lock-holder SSH process disappeared before Cargo starts.
    pub(super) fn ensure_held(&mut self) -> anyhow::Result<()> {
        let child = self
            .child
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("remote source-authority lock is not active"))?;
        if let Some(status) = child.try_wait()? {
            anyhow::bail!(
                "remote source-authority lock on {} exited before Cargo started: {}",
                self.worker_id,
                status
            );
        }
        Ok(())
    }

    /// Release the locks after Cargo exits and prove the holder stayed healthy.
    pub(super) async fn release(mut self) -> anyhow::Result<()> {
        drop(self.stdin.take());
        let mut child = self
            .child
            .take()
            .ok_or_else(|| anyhow::anyhow!("remote source-authority lock is not active"))?;
        let status = match timeout(Duration::from_secs(15), child.wait()).await {
            Ok(status) => status?,
            Err(_) => {
                let _ = child.start_kill();
                anyhow::bail!(
                    "timed out releasing remote source-authority lock on {}",
                    self.worker_id
                );
            }
        };
        let stdout = join_lock_drain(self.stdout_drain.take()).await?;
        let stderr = join_lock_drain(self.stderr_drain.take()).await?;
        if !status.success() {
            anyhow::bail!(
                "remote source-authority lock on {} exited unexpectedly: {}; stdout={}; stderr={}",
                self.worker_id,
                status,
                String::from_utf8_lossy(&stdout).trim(),
                String::from_utf8_lossy(&stderr).trim()
            );
        }
        Ok(())
    }
}

impl Drop for RemoteSourceAuthorityLock {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.start_kill();
        }
        if let Some(task) = self.stdout_drain.take() {
            task.abort();
        }
        if let Some(task) = self.stderr_drain.take() {
            task.abort();
        }
    }
}

async fn join_lock_drain(
    task: Option<tokio::task::JoinHandle<std::io::Result<Vec<u8>>>>,
) -> anyhow::Result<Vec<u8>> {
    match task {
        Some(task) => Ok(task.await??),
        None => Ok(Vec::new()),
    }
}

fn source_authority_lock_paths(authority_roots: &[String]) -> Vec<String> {
    let mut roots = authority_roots.to_vec();
    roots.sort();
    roots.dedup();
    roots
        .into_iter()
        .map(|root| {
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"rch.remote_source_authority_lock.v1\0");
            hasher.update(root.as_bytes());
            format!(
                "{REMOTE_SOURCE_AUTHORITY_LOCK_DIR}/{}.lock",
                hasher.finalize().to_hex()
            )
        })
        .collect()
}

fn build_remote_source_authority_lock_cmd(
    lock_dir: &str,
    lock_paths: &[String],
    ready_marker: &str,
) -> anyhow::Result<String> {
    if lock_paths.is_empty() {
        anyhow::bail!("remote source-authority lock set must not be empty");
    }
    let mut nested = format!(
        "sh -c {}",
        shell_escape::escape(
            format!(
                "printf '%s\\n' {} && cat >/dev/null",
                shell_escape::escape(ready_marker.into())
            )
            .into()
        )
    );
    for path in lock_paths.iter().rev() {
        nested = format!(
            "flock -x {} {nested}",
            shell_escape::escape(path.as_str().into())
        );
    }
    Ok(format!(
        "set -e; mkdir -p -- {}; exec {nested}",
        shell_escape::escape(lock_dir.into())
    ))
}

/// Acquire sorted, worker-side locks for every mutable canonical source root.
/// One persistent SSH session owns the whole set, so separate coordinator
/// processes cannot overwrite any member of a Cargo closure while it compiles.
pub(super) async fn acquire_remote_source_authority_lock(
    worker: &WorkerConfig,
    authority_roots: &[String],
    wait_timeout: Duration,
) -> anyhow::Result<RemoteSourceAuthorityLock> {
    use anyhow::Context as _;
    use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _};

    let lock_paths = source_authority_lock_paths(authority_roots);
    let ready_marker = format!("RCH_SOURCE_AUTHORITY_READY:{}", uuid::Uuid::new_v4());
    let remote_cmd = build_remote_source_authority_lock_cmd(
        REMOTE_SOURCE_AUTHORITY_LOCK_DIR,
        &lock_paths,
        &ready_marker,
    )?;
    let identity_file = shellexpand::tilde(&worker.identity_file);
    let destination = format!("{}@{}", worker.user, worker.host);
    let mut cmd = Command::new("ssh");
    cmd.arg("-o").arg("BatchMode=yes");
    cmd.arg("-o").arg("StrictHostKeyChecking=accept-new");
    cmd.arg("-o").arg("ConnectTimeout=10");
    cmd.arg("-i").arg(identity_file.as_ref());
    cmd.arg(&destination);
    cmd.arg(build_remote_shell_command(&remote_cmd));
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let mut child = cmd
        .spawn()
        .with_context(|| format!("failed to start source-authority lock on {destination}"))?;
    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow::anyhow!("source-authority lock stdin was not piped"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("source-authority lock stdout was not piped"))?;
    let mut stdout = tokio::io::BufReader::new(stdout);
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow::anyhow!("source-authority lock stderr was not piped"))?;
    let stderr_drain = tokio::spawn(async move {
        let mut bytes = Vec::new();
        tokio::io::BufReader::new(stderr)
            .read_to_end(&mut bytes)
            .await?;
        Ok(bytes)
    });

    let mut observed = String::new();
    match timeout(wait_timeout, stdout.read_line(&mut observed)).await {
        Ok(Ok(0)) => {
            let _ = child.start_kill();
            let stderr = join_lock_drain(Some(stderr_drain)).await?;
            anyhow::bail!(
                "source-authority lock on {} exited before acquisition; stderr={}",
                worker.id,
                String::from_utf8_lossy(&stderr).trim()
            );
        }
        Ok(Ok(_)) if observed.trim_end() == ready_marker => {}
        Ok(Ok(_)) => {
            let _ = child.start_kill();
            anyhow::bail!(
                "source-authority lock on {} emitted an invalid ready marker: {:?}",
                worker.id,
                observed.trim_end()
            );
        }
        Ok(Err(err)) => {
            let _ = child.start_kill();
            return Err(err).context("failed reading source-authority lock readiness");
        }
        Err(_) => {
            let _ = child.start_kill();
            anyhow::bail!(
                "timed out waiting {:?} for source-authority locks on {}",
                wait_timeout,
                worker.id
            );
        }
    }

    let stdout_drain = tokio::spawn(async move {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).await?;
        Ok(bytes)
    });
    Ok(RemoteSourceAuthorityLock {
        worker_id: worker.id.clone(),
        child: Some(child),
        stdin: Some(stdin),
        stdout_drain: Some(stdout_drain),
        stderr_drain: Some(stderr_drain),
    })
}

pub(super) fn should_skip_remote_preflight(worker: &WorkerConfig) -> bool {
    mock::is_mock_enabled() || mock::is_mock_worker(worker)
}

pub(super) async fn run_offload_ssh_command(
    worker: &WorkerConfig,
    remote_cmd: &str,
    timeout_duration: Duration,
) -> anyhow::Result<Output> {
    let (remote_arg, stdin_payload) = offload_remote_command_transport(worker, remote_cmd);
    run_offload_ssh_command_with_optional_stdin(worker, remote_arg, stdin_payload, timeout_duration)
        .await
}

/// Windows OpenSSH passes its remote command through an additional shell
/// boundary, where the nested single quotes produced by `sh -lc` can be
/// reparsed and truncated. Feed control-plane scripts to `sh -s` instead;
/// POSIX workers retain the historical argv transport.
pub(super) fn offload_remote_command_transport<'a>(
    worker: &WorkerConfig,
    remote_cmd: &'a str,
) -> (&'a str, Option<&'a [u8]>) {
    if crate::transfer::WorkerPlatform::from_worker(worker).is_windows() {
        ("sh -s", Some(remote_cmd.as_bytes()))
    } else {
        (remote_cmd, None)
    }
}

/// Execute a hardened control-plane SSH command while streaming a bounded
/// caller-supplied payload to its stdin. Source-content verification uses this
/// instead of placing thousands of file identities in argv, where shell/OS
/// limits would make the proof denominator depend on repository size.
pub(super) async fn run_offload_ssh_command_with_stdin(
    worker: &WorkerConfig,
    remote_cmd: &str,
    stdin_payload: &[u8],
    timeout_duration: Duration,
) -> anyhow::Result<Output> {
    run_offload_ssh_command_with_optional_stdin(
        worker,
        remote_cmd,
        Some(stdin_payload),
        timeout_duration,
    )
    .await
}

async fn run_offload_ssh_command_with_optional_stdin(
    worker: &WorkerConfig,
    remote_cmd: &str,
    stdin_payload: Option<&[u8]>,
    timeout_duration: Duration,
) -> anyhow::Result<Output> {
    let identity_file = shellexpand::tilde(&worker.identity_file);
    let destination = format!("{}@{}", worker.user, worker.host);

    let mut cmd = Command::new("ssh");
    cmd.arg("-o").arg("BatchMode=yes");
    cmd.arg("-o").arg("StrictHostKeyChecking=accept-new");
    cmd.arg("-o").arg(format!(
        "ConnectTimeout={}",
        timeout_duration.as_secs().max(1)
    ));
    cmd.arg("-i").arg(identity_file.as_ref());
    cmd.arg(&destination);
    cmd.arg(build_remote_shell_command(remote_cmd));
    if stdin_payload.is_some() {
        cmd.stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::null());
    }
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    // Spawn manually instead of `cmd.output()` so the local SSH process is
    // killed if our outer timeout fires. `tokio::time::timeout` only drops
    // the future; without `kill_on_drop`, the spawned ssh process keeps
    // running, holding the network socket open until SSH's own keepalive
    // gives up. For a busy hook this leaks fds and ssh processes — exactly
    // the kind of slow accumulation that turns into a daemon-restart bug
    // weeks later.
    cmd.kill_on_drop(true);

    use anyhow::Context as _;
    use tokio::io::AsyncWriteExt as _;

    let mut child = cmd
        .spawn()
        .with_context(|| format!("Failed to spawn ssh to {}", destination))?;

    // Drain stdout/stderr concurrently with the wait so that even verbose
    // remote output never deadlocks the child on a full pipe buffer.
    let mut stdin_pipe = child.stdin.take();
    let mut stdout_pipe = child.stdout.take();
    let mut stderr_pipe = child.stderr.take();
    let stdin_payload = stdin_payload.map(<[u8]>::to_vec);
    let collect = async {
        let stdin_fut = async {
            if let (Some(mut pipe), Some(payload)) = (stdin_pipe.take(), stdin_payload.as_deref()) {
                pipe.write_all(payload).await?;
                pipe.shutdown().await?;
                drop(pipe);
            }
            Ok::<_, std::io::Error>(())
        };
        let stdout_fut = async {
            match stdout_pipe.take() {
                Some(pipe) => {
                    crate::transfer::read_bounded_output_stream(pipe, MAX_OFFLOAD_SSH_OUTPUT_BYTES)
                        .await
                }
                None => Ok(Vec::new()),
            }
        };
        let stderr_fut = async {
            match stderr_pipe.take() {
                Some(pipe) => {
                    crate::transfer::read_bounded_output_stream(pipe, MAX_OFFLOAD_SSH_OUTPUT_BYTES)
                        .await
                }
                None => Ok(Vec::new()),
            }
        };
        let ((), stdout_bytes, stderr_bytes) = tokio::try_join!(stdin_fut, stdout_fut, stderr_fut)?;
        let status = child.wait().await?;
        Ok::<_, std::io::Error>(Output {
            status,
            stdout: stdout_bytes,
            stderr: stderr_bytes,
        })
    };

    match timeout(timeout_duration, collect).await {
        Ok(result) => result.context("Failed to collect ssh output"),
        Err(_) => {
            // collect future is dropped here; with kill_on_drop=true the
            // local ssh process is SIGKILLed when `child` (still owned by
            // the dropped future) is dropped.
            anyhow::bail!("SSH command timed out after {:?}", timeout_duration);
        }
    }
}

fn build_remote_shell_command(remote_cmd: &str) -> String {
    format!("sh -lc {}", shell_escape::escape(remote_cmd.into()))
}

fn build_worker_projects_topology_cmd(topology_policy: &PathTopologyPolicy) -> String {
    let canonical_display = topology_policy.canonical_root().display().to_string();
    let alias_display = topology_policy.alias_root().display().to_string();
    let canonical_slash_display = format!("{}/", canonical_display.trim_end_matches('/'));

    format!(
        "set -e; \
         if [ ! -e {canonical} ] && [ ! -L {canonical} ]; then mkdir_stderr=$(mkdir -p -- {canonical} 2>&1) || {{ printf 'RCH_TOPOLOGY_ERR_CANONICAL_CREATE_FAILED:path=%s:%s\\n' {canonical} \"$mkdir_stderr\" >&2; exit 45; }}; fi; \
         if [ -e {canonical} ] && [ ! -d {canonical} ]; then printf 'RCH_TOPOLOGY_ERR_CANONICAL_NOT_DIRECTORY:path=%s\\n' {canonical} >&2; exit 41; fi; \
         canonical_real=$(readlink -f -- {canonical} 2>/dev/null || printf '%s' {canonical}); \
         ensure_alias_symlink() {{ \
         if [ -L {alias} ]; then \
           target=$(readlink -- {alias} 2>/dev/null || true); \
           target_real=$(readlink -f -- {alias} 2>/dev/null || true); \
           if [ \"$target\" != {canonical} ] && [ \"$target\" != {canonical_slash} ] && [ \"$target_real\" != \"$canonical_real\" ]; then \
             update_stderr=$(ln -sfn -- {canonical} {alias} 2>&1) || {{ printf 'RCH_TOPOLOGY_ERR_ALIAS_UPDATE_FAILED:path=%s:target=%s:%s\\n' {alias} {canonical} \"$update_stderr\" >&2; return 43; }}; \
           fi; \
         elif [ -e {alias} ]; then \
           alias_real=$(readlink -f -- {alias} 2>/dev/null || true); \
           if [ -n \"$alias_real\" ] && [ \"$alias_real\" = \"$canonical_real\" ]; then return 0; fi; \
           printf 'RCH_TOPOLOGY_ERR_ALIAS_NOT_SYMLINK:path=%s\\n' {alias} >&2; return 42; \
         else \
           create_stderr=$(ln -s -- {canonical} {alias} 2>&1) && return 0; \
           if [ -L {alias} ]; then ensure_alias_symlink; return $?; fi; \
           if [ -e {alias} ]; then \
             alias_real=$(readlink -f -- {alias} 2>/dev/null || true); \
             if [ -n \"$alias_real\" ] && [ \"$alias_real\" = \"$canonical_real\" ]; then return 0; fi; \
             printf 'RCH_TOPOLOGY_ERR_ALIAS_NOT_SYMLINK:path=%s\\n' {alias} >&2; return 42; fi; \
           printf 'RCH_TOPOLOGY_ERR_ALIAS_CREATE_FAILED:path=%s:target=%s:%s\\n' {alias} {canonical} \"$create_stderr\" >&2; return 44; \
         fi; \
         }}; \
         ensure_alias_symlink; \
         echo RCH_TOPOLOGY_OK",
        canonical = shell_escape::escape(canonical_display.into()),
        canonical_slash = shell_escape::escape(canonical_slash_display.into()),
        alias = shell_escape::escape(alias_display.into())
    )
}

/// bd-8iwkm: build the bounded ownership-drift detect+repair command for the
/// canonical mirror tree. Counts root-owned entries (the rsync exit-23 class),
/// chowns them to the SSH user via passwordless sudo, and re-counts to prove
/// the repair. Never deletes; touches only root-owned entries; the alias root
/// is intentionally not scanned separately because it resolves into (or is
/// policy-conflicting with) the canonical root, which this sweep already
/// covers. Exit codes: 0 = ok/repaired/check-unavailable (fail-open), 46 =
/// repair unavailable (sudo missing/refused), 47 = partial repair.
fn build_worker_ownership_repair_cmd(roots: &[PathBuf], ssh_user: &str) -> String {
    let quoted_user = shell_escape::escape(ssh_user.into());
    let quoted_roots = roots
        .iter()
        .map(|root| shell_escape::escape(root.to_string_lossy().into()))
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "set -e; u={user}; \
         detect_root() {{ \
           if ! b=$(sudo -n find \"$1\" -xdev -user root -print 2>/dev/null | wc -l); then \
             printf 'RCH_OWNERSHIP_CHECK_UNAVAILABLE\\n' >&2; exit 0; \
           fi; \
           echo $((b + 0)); \
         }}; \
         total=0; \
         for r in {roots}; do \
           [ -d \"$r\" ] || continue; \
           total=$((total + $(detect_root \"$r\"))); \
         done; \
         if [ \"$total\" -eq 0 ]; then echo RCH_OWNERSHIP_OK; exit 0; fi; \
         repair_ok=1; \
         for r in {roots}; do \
           [ -d \"$r\" ] || continue; \
           if ! sudo -n find \"$r\" -xdev -user root -exec chown -h \"$u\" {{}} + 2>/dev/null; then \
             repair_ok=0; \
           fi; \
         done; \
         if [ \"$repair_ok\" -eq 0 ]; then \
           printf 'RCH_OWNERSHIP_REPAIR_UNAVAILABLE:detected=%s\\n' \"$total\" >&2; exit 46; \
         fi; \
         remaining=0; \
         for r in {roots}; do \
           [ -d \"$r\" ] || continue; \
           remaining=$((remaining + $(detect_root \"$r\"))); \
         done; \
         if [ \"$remaining\" -eq 0 ]; then printf 'RCH_OWNERSHIP_REPAIRED:count=%s\\n' \"$total\"; exit 0; fi; \
         printf 'RCH_OWNERSHIP_PARTIAL:remaining=%s\\n' \"$remaining\" >&2; exit 47",
        user = quoted_user,
        roots = quoted_roots,
    )
}

/// bd-kugfc: detection-only ownership probe command for the canonical
/// mirror tree. Counts root-owned entries and mutates nothing — the
/// doctor must stay read-only. Contract mirrors the repair command's
/// sentinels where meaningful: stdout `RCH_OWNERSHIP_OK` or
/// `RCH_OWNERSHIP_DRIFT:count=N` (exit 0), stderr
/// `RCH_OWNERSHIP_CHECK_UNAVAILABLE` when passwordless sudo is
/// unavailable (also exit 0 — same fail-open posture as dispatch).
fn build_worker_ownership_detect_cmd(canonical_root: &Path) -> String {
    let root = shell_escape::escape(canonical_root.display().to_string().into());
    format!(
        "set -e; r={root}; \
         if ! b=$(sudo -n find \"$r\" -xdev -user root -print 2>/dev/null | wc -l); then \
           printf 'RCH_OWNERSHIP_CHECK_UNAVAILABLE\\n' >&2; exit 0; \
         fi; \
         b=$((b + 0)); \
         if [ \"$b\" -eq 0 ]; then echo RCH_OWNERSHIP_OK; \
         else printf 'RCH_OWNERSHIP_DRIFT:count=%s\\n' \"$b\"; fi",
        root = root,
    )
}

/// bd-kugfc: outcome of one worker's detection-only mirror-ownership
/// probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MirrorOwnershipProbe {
    /// Probe intentionally not run (mock mode or Windows worker —
    /// neither has the Unix canonical/alias mirror-tree semantics).
    Skipped,
    /// No root-owned entries under the canonical mirror tree.
    Healthy,
    /// Drift detected: N root-owned entries will make rsync-as-ssh-user
    /// fail exit 23 until repaired.
    Drift { count: u64 },
    /// The worker cannot run the count (passwordless sudo unavailable);
    /// dispatch-time repair fails open silently in this state too.
    CheckUnavailable,
    /// SSH transport failure, timeout, or unrecognized output; drift
    /// state on this worker is unknown.
    Unprobeable(String),
}

/// Pure classifier for the detect-command output so the parsing
/// contract stays unit-testable without an SSH fleet.
fn parse_ownership_detect_output(
    status_success: bool,
    stdout: &str,
    stderr: &str,
) -> MirrorOwnershipProbe {
    if !status_success {
        // `set -e` makes any non-zero exit an unexpected shell failure
        // (the sentinel paths all exit 0 by construction).
        return MirrorOwnershipProbe::Unprobeable(format!(
            "probe exited non-zero: stderr='{}'",
            stderr.trim()
        ));
    }
    if stderr.contains("RCH_OWNERSHIP_CHECK_UNAVAILABLE") {
        return MirrorOwnershipProbe::CheckUnavailable;
    }
    if let Some(count) = stdout
        .trim()
        .strip_prefix("RCH_OWNERSHIP_DRIFT:count=")
        .and_then(|value| value.parse::<u64>().ok())
    {
        return MirrorOwnershipProbe::Drift { count };
    }
    if stdout.contains("RCH_OWNERSHIP_OK") {
        return MirrorOwnershipProbe::Healthy;
    }
    MirrorOwnershipProbe::Unprobeable(format!(
        "unrecognized probe output: stdout='{}' stderr='{}'",
        stdout.trim(),
        stderr.trim()
    ))
}

/// bd-kugfc: run the detection-only ownership probe against one worker.
/// Read-only by contract — it never chowns, deletes, or otherwise
/// mutates the worker. Bounded to 8s so the reliability doctor's outer
/// per-probe ceiling (10s) stays authoritative across the fan-out.
pub(crate) async fn probe_worker_mirror_ownership(
    worker: &WorkerConfig,
    canonical_root: &Path,
) -> MirrorOwnershipProbe {
    if should_skip_remote_preflight(worker)
        || crate::transfer::WorkerPlatform::from_worker(worker).is_windows()
    {
        return MirrorOwnershipProbe::Skipped;
    }
    let cmd = build_worker_ownership_detect_cmd(canonical_root);
    match run_offload_ssh_command(worker, &cmd, Duration::from_secs(8)).await {
        Ok(output) => parse_ownership_detect_output(
            output.status.success(),
            &String::from_utf8_lossy(&output.stdout),
            &String::from_utf8_lossy(&output.stderr),
        ),
        Err(err) => MirrorOwnershipProbe::Unprobeable(err.to_string()),
    }
}

pub(super) async fn ensure_worker_projects_topology(
    worker: &WorkerConfig,
    reporter: &HookReporter,
    topology_policy: &PathTopologyPolicy,
    dispatch_closure_roots: &[PathBuf],
) -> anyhow::Result<()> {
    if should_skip_remote_preflight(worker) {
        reporter.verbose("[RCH] topology preflight skipped in mock mode");
        return Ok(());
    }

    if crate::transfer::WorkerPlatform::from_worker(worker).is_windows() {
        // Windows workers have no Unix canonical/alias projects topology — they
        // build under `C:/rch` via tar-over-ssh — so the `/dp`→canonical symlink
        // enforcement does not apply and would fail (no POSIX symlink there).
        reporter.verbose("[RCH] topology preflight skipped for Windows worker");
        return Ok(());
    }

    let canonical_display = topology_policy.canonical_root().display().to_string();
    let alias_display = topology_policy.alias_root().display().to_string();
    let topology_cmd = build_worker_projects_topology_cmd(topology_policy);

    let output = run_offload_ssh_command(worker, &topology_cmd, Duration::from_secs(20)).await?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        // A non-symlink alias that does NOT resolve to the canonical root is a
        // path_topology *policy* problem, not a worker fault — every worker will
        // refuse it identically. Name the config sources so operators fix the
        // policy instead of triaging (or "repairing") a healthy worker (rch#32).
        let policy_hint = if stderr.contains("RCH_TOPOLOGY_ERR_ALIAS_NOT_SYMLINK") {
            "; the alias root is a plain directory that does not resolve to the canonical root — \
             this is a [path_topology] policy conflict (RCH_ALIAS_PROJECT_ROOT / \
             RCH_CANONICAL_PROJECT_ROOT), not a worker fault; every worker refuses it identically"
        } else {
            ""
        };
        anyhow::bail!(
            "remote topology preflight failed on {} (status {:?}): stdout='{}' stderr='{}'{}",
            worker.id,
            output.status.code(),
            stdout,
            stderr,
            policy_hint
        );
    }
    reporter.verbose(&format!(
        "[RCH] topology preflight ok on {} ({} -> {} enforced)",
        worker.id, alias_display, canonical_display
    ));
    // bd-8iwkm: root-owned entries inside the canonical mirror tree make
    // rsync-as-ssh-user fail exit 23 on replace/unlink even when topology is
    // healthy. Repair them before sync so the failure window closes here
    // instead of mid-transfer.
    // bd-gc0ze follow-up: scope the ownership sweep to THIS dispatch's closure
    // roots instead of the whole canonical mirror. A global scan walks every
    // mirrored repo (13GB+ franken_engine mirrors included) on every dispatch,
    // which blew the fixed SSH budget and failed closed on E104 before any
    // rsync started. The drift that breaks THIS transfer can only live under
    // the remote roots THIS transfer writes into.
    let ownership_scan_roots: Vec<PathBuf> = if dispatch_closure_roots.is_empty() {
        vec![topology_policy.canonical_root().to_path_buf()]
    } else {
        dispatch_closure_roots.to_vec()
    };
    let repaired =
        repair_worker_mirror_ownership(worker, reporter, &ownership_scan_roots).await?;
    if repaired > 0 {
        reporter.summary(&format!(
            "[RCH] repaired ownership drift on {}: {repaired} root-owned entries chowned to {}",
            worker.id, worker.user
        ));
    }
    Ok(())
}

/// bd-8iwkm: detect and repair root-owned entries under the dispatch's closure
/// roots on the worker's canonical mirror. Returns the number of repaired
/// entries; zero means either no drift or a fail-open check-unavailable (never
/// blocks dispatch). Scoped to the closure roots (see caller) so cost tracks
/// the trees about to be rsynced rather than the entire mirror.
async fn repair_worker_mirror_ownership(
    worker: &WorkerConfig,
    reporter: &HookReporter,
    roots: &[PathBuf],
) -> anyhow::Result<u64> {
    if should_skip_remote_preflight(worker) {
        reporter.verbose("[RCH] ownership preflight skipped in mock mode");
        return Ok(0);
    }
    if crate::transfer::WorkerPlatform::from_worker(worker).is_windows() {
        reporter.verbose("[RCH] ownership preflight skipped for Windows worker");
        return Ok(0);
    }
    let cmd = build_worker_ownership_repair_cmd(roots, &worker.user);
    // bd-gc0ze: closure-scoped sweeps normally finish in seconds; 600s bounds
    // pathological trees without failing every dispatch the way the old fixed
    // 60s budget did once mirrors grew past multi-GB.
    let output = run_offload_ssh_command(worker, &cmd, Duration::from_secs(600)).await?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        anyhow::bail!(
            "worker mirror ownership repair failed on {} (status {:?}): stdout='{}' stderr='{}' — \
             root-owned entries under the dispatch closure block rsync-as-{} (bd-8iwkm)",
            worker.id,
            output.status.code(),
            stdout,
            stderr,
            worker.user
        );
    }
    if let Some(count) = stdout
        .strip_prefix("RCH_OWNERSHIP_REPAIRED:count=")
        .and_then(|value| value.parse::<u64>().ok())
    {
        reporter.verbose(&format!(
            "[RCH] ownership drift repaired on {}: {count} entries chowned to {}",
            worker.id, worker.user
        ));
        return Ok(count);
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rch_common::test_guard;

    #[test]
    fn source_authority_lock_keys_are_sorted_deduplicated_and_root_stable() {
        let _guard = test_guard!();
        let forward = source_authority_lock_paths(&[
            "/data/projects/franken_whisper".to_string(),
            "/data/projects/frankensqlite".to_string(),
            "/data/projects/frankensqlite".to_string(),
        ]);
        let reverse = source_authority_lock_paths(&[
            "/data/projects/frankensqlite".to_string(),
            "/data/projects/franken_whisper".to_string(),
        ]);

        assert_eq!(forward, reverse, "input order must not change lock order");
        assert_eq!(forward.len(), 2, "duplicate roots need one authority lock");
        assert_eq!(
            source_authority_lock_paths(&["/data/projects/frankensqlite".to_string()]),
            source_authority_lock_paths(&["/data/projects/frankensqlite".to_string()]),
            "the same canonical root must serialize source-only revisions even when their project hashes differ"
        );
    }

    #[cfg(target_os = "linux")]
    fn spawn_local_source_lock(
        lock_path: &str,
        marker: &str,
    ) -> (
        std::process::Child,
        std::sync::mpsc::Receiver<std::io::Result<String>>,
    ) {
        use std::io::BufRead as _;

        let command =
            build_remote_source_authority_lock_cmd("/tmp", &[lock_path.to_string()], marker)
                .expect("build source lock command");
        let mut child = std::process::Command::new("sh")
            .arg("-lc")
            .arg(command)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .spawn()
            .expect("spawn local source lock holder");
        let stdout = child.stdout.take().expect("lock holder stdout");
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut line = String::new();
            let result = std::io::BufReader::new(stdout)
                .read_line(&mut line)
                .map(|_| line);
            let _ = sender.send(result);
        });
        (child, receiver)
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn source_authority_lock_is_held_until_owner_stdin_closes() {
        let _guard = test_guard!();
        let (mut first, first_ready) = spawn_local_source_lock("/tmp", "FIRST_READY");
        assert_eq!(
            first_ready
                .recv_timeout(Duration::from_secs(2))
                .expect("first lock acquisition")
                .expect("first ready line")
                .trim_end(),
            "FIRST_READY"
        );

        let (mut second, second_ready) = spawn_local_source_lock("/tmp", "SECOND_READY");
        assert!(
            matches!(
                second_ready.recv_timeout(Duration::from_millis(200)),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ),
            "a competing sync must remain blocked for the entire execution phase"
        );

        drop(first.stdin.take());
        assert!(first.wait().expect("wait for first lock holder").success());
        assert_eq!(
            second_ready
                .recv_timeout(Duration::from_secs(2))
                .expect("second lock acquisition after first exits")
                .expect("second ready line")
                .trim_end(),
            "SECOND_READY"
        );
        drop(second.stdin.take());
        assert!(
            second
                .wait()
                .expect("wait for second lock holder")
                .success()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn disjoint_source_authorities_do_not_serialize() {
        let _guard = test_guard!();
        let current_dir = std::env::current_dir().expect("current directory");
        let current_dir = current_dir.to_string_lossy().to_string();
        let (mut first, first_ready) = spawn_local_source_lock("/tmp", "TMP_READY");
        let (mut second, second_ready) = spawn_local_source_lock(&current_dir, "REPO_READY");

        assert_eq!(
            first_ready
                .recv_timeout(Duration::from_secs(2))
                .expect("tmp authority acquisition")
                .expect("tmp ready line")
                .trim_end(),
            "TMP_READY"
        );
        assert_eq!(
            second_ready
                .recv_timeout(Duration::from_secs(2))
                .expect("disjoint authority must acquire concurrently")
                .expect("repo ready line")
                .trim_end(),
            "REPO_READY"
        );

        drop(first.stdin.take());
        drop(second.stdin.take());
        assert!(first.wait().expect("wait for tmp holder").success());
        assert!(second.wait().expect("wait for repo holder").success());
    }

    /// Platform-portable tempdir wrapper that canonicalizes its path
    /// (macOS resolves `/tmp` to `/private/tmp`).
    ///
    /// This is a local copy of the shared `topology_tempdir` helper in
    /// `hook::tests` (which serves the other ~26 topology tests). Keeping a
    /// private copy here lets the SSH tests stay self-contained without
    /// exposing the helper across module boundaries — the same pattern used
    /// for `create_test_state_dir` in the `auto_start` submodule.
    ///
    /// Gated `#[cfg(unix)]` because its only consumer here is the unix-only
    /// `..._treats_file_exists_race_as_success` test; without the gate it would
    /// be unused (dead_code → clippy `-D warnings`) on non-unix targets.
    #[cfg(unix)]
    struct CanonicalTempDir {
        _dir: tempfile::TempDir,
        path: PathBuf,
    }

    #[cfg(unix)]
    impl CanonicalTempDir {
        fn path(&self) -> &Path {
            &self.path
        }
    }

    #[cfg(unix)]
    fn topology_tempdir() -> (CanonicalTempDir, PathTopologyPolicy) {
        let raw = tempfile::tempdir().expect("create tempdir");
        let canonical = std::fs::canonicalize(raw.path()).expect("canonicalize tempdir");
        let alias_root = canonical
            .parent()
            .map(|parent| {
                let leaf = canonical
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("tmp");
                parent.join(format!("{leaf}__rch_alias_sentinel"))
            })
            .unwrap_or_else(|| canonical.clone());
        let policy = PathTopologyPolicy::new(canonical.clone(), alias_root);
        (
            CanonicalTempDir {
                _dir: raw,
                path: canonical,
            },
            policy,
        )
    }

    #[test]
    fn test_build_remote_shell_command_wraps_and_escapes_script() {
        let _guard = test_guard!();
        let command = "missing=0; if [ \"$missing\" -ne 0 ]; then echo 'bad'; fi";

        let wrapped = build_remote_shell_command(command);

        assert!(wrapped.starts_with("sh -lc "));
        assert!(
            wrapped.starts_with("sh -lc '"),
            "shell wrapper must quote the script as a single argument"
        );
        assert!(
            !wrapped.starts_with("sh -lc missing=0"),
            "script must not be passed unquoted"
        );
        assert!(
            wrapped.contains("if ["),
            "wrapped command should preserve the full script"
        );
    }

    #[test]
    fn test_build_worker_projects_topology_cmd_uses_supplied_policy() {
        let _guard = test_guard!();
        let policy = PathTopologyPolicy::new(
            PathBuf::from("/custom/projects"),
            PathBuf::from("/custom/dp"),
        );

        let command = build_worker_projects_topology_cmd(&policy);

        assert!(
            command.contains("/custom/projects"),
            "preflight command must use the supplied canonical root: {command}"
        );
        assert!(
            command.contains("/custom/dp"),
            "preflight command must use the supplied alias root: {command}"
        );
        assert!(
            !command.contains("/data/projects"),
            "preflight command must not silently fall back to default canonical root: {command}"
        );
    }

    #[test]
    fn test_build_worker_projects_topology_cmd_shell_escapes_policy_paths() {
        let _guard = test_guard!();
        let policy = PathTopologyPolicy::new(
            PathBuf::from("/tmp/rch weird'root"),
            PathBuf::from("/tmp/rch alias;bad"),
        );

        let command = build_worker_projects_topology_cmd(&policy);

        assert!(
            command.contains("'/tmp/rch weird'\\''root'"),
            "single quotes in canonical root must be shell escaped: {command}"
        );
        assert!(
            command.contains("'/tmp/rch alias;bad'"),
            "shell metacharacters in alias root must be quoted: {command}"
        );
    }

    #[test]
    fn test_build_worker_projects_topology_cmd_terminates_path_options() {
        let _guard = test_guard!();
        let policy = PathTopologyPolicy::new(
            PathBuf::from("-custom/projects"),
            PathBuf::from("-custom/dp"),
        );
        let canonical =
            shell_escape::escape(std::borrow::Cow::from("-custom/projects")).to_string();
        let alias = shell_escape::escape(std::borrow::Cow::from("-custom/dp")).to_string();

        let command = build_worker_projects_topology_cmd(&policy);

        assert!(
            command.contains(&format!("mkdir -p -- {canonical}")),
            "mkdir must terminate options before configured paths: {command}"
        );
        assert!(
            command.contains(&format!("readlink -- {alias}")),
            "readlink must terminate options before configured paths: {command}"
        );
        assert!(
            command.contains(&format!("ln -sfn -- {canonical} {alias}")),
            "ln update must terminate options before configured paths: {command}"
        );
        assert!(
            command.contains(&format!("ln -s -- {canonical} {alias}")),
            "ln create must terminate options before configured paths: {command}"
        );
    }

    #[test]
    fn test_build_worker_ownership_repair_cmd_scopes_and_never_deletes() {
        let _guard = test_guard!();
        let command = build_worker_ownership_repair_cmd(
            &[
                PathBuf::from("/data/projects"),
                PathBuf::from("/data/projects/franken_node"),
            ],
            "deploy-user",
        );

        assert!(
            command.contains("'--user root'") || command.contains("-user root"),
            "sweep must target root-owned entries only: {command}"
        );
        assert!(
            command.contains("'/data/projects'")
                && command.contains("'/data/projects/franken_node'"),
            "every dispatch closure root binds verbatim into the sweep: {command}"
        );
        let spaced = build_worker_ownership_repair_cmd(
            &[PathBuf::from("/data/projects with space")],
            "deploy u",
        );
        assert!(
            spaced.contains("'/data/projects with space'") && spaced.contains("u='deploy u'"),
            "paths or users with shell metacharacters must be single-quote escaped: {spaced}"
        );
        assert!(
            command.contains("-xdev"),
            "sweep must not cross filesystem boundaries: {command}"
        );
        assert!(
            command.contains("-exec chown -h"),
            "repair must chown links themselves without following them: {command}"
        );
        assert!(
            !command.contains(" rm ") && !command.contains("rm -"),
            "repair must never delete anything (bd-8iwkm constraint): {command}"
        );
        assert!(
            command.contains("RCH_OWNERSHIP_OK")
                && command.contains("RCH_OWNERSHIP_REPAIRED:count=")
                && command.contains("exit 46")
                && command.contains("exit 47"),
            "all outcome markers and the 46/47 exit codes must be present: {command}"
        );
    }

    #[test]
    fn test_build_worker_projects_topology_cmd_rechecks_alias_after_create_race() {
        let _guard = test_guard!();
        let policy = PathTopologyPolicy::new(
            PathBuf::from("/custom/projects"),
            PathBuf::from("/custom/dp"),
        );
        let canonical =
            shell_escape::escape(std::borrow::Cow::from("/custom/projects")).to_string();
        let alias = shell_escape::escape(std::borrow::Cow::from("/custom/dp")).to_string();

        let command = build_worker_projects_topology_cmd(&policy);

        assert!(
            command.contains(&format!(
                "create_stderr=$(ln -s -- {canonical} {alias} 2>&1) && return 0"
            )),
            "create path must handle normal symlink creation inside the alias helper: {command}"
        );
        assert!(
            command.contains(&format!(
                "if [ -L {alias} ]; then ensure_alias_symlink; return $?; fi"
            )),
            "failed create must re-check alias state so a concurrent correct symlink is harmless: {command}"
        );
        assert!(
            command.contains("RCH_TOPOLOGY_ERR_ALIAS_NOT_SYMLINK"),
            "regular-file alias conflicts must still fail with a structured reason: {command}"
        );
        assert!(
            command.contains("RCH_TOPOLOGY_ERR_ALIAS_CREATE_FAILED"),
            "missing-alias create failures must report a structured reason: {command}"
        );
        assert!(
            command.contains(&format!(
                "printf 'RCH_TOPOLOGY_ERR_ALIAS_CREATE_FAILED:path=%s:target=%s:%s\\n' {alias} {canonical} \"$create_stderr\""
            )),
            "missing-alias create failures must report the exact alias and canonical paths: {command}"
        );
        assert!(
            command.contains(&format!(
                "printf 'RCH_TOPOLOGY_ERR_ALIAS_UPDATE_FAILED:path=%s:target=%s:%s\\n' {alias} {canonical} \"$update_stderr\""
            )),
            "alias update failures must report the exact alias and canonical paths: {command}"
        );
        assert!(
            command.contains(&format!(
                "printf 'RCH_TOPOLOGY_ERR_CANONICAL_CREATE_FAILED:path=%s:%s\\n' {canonical} \"$mkdir_stderr\""
            )),
            "canonical mkdir failures must report the exact canonical path: {command}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_build_worker_projects_topology_cmd_treats_file_exists_race_as_success() {
        let _guard = test_guard!();
        use std::os::unix::fs::PermissionsExt;

        let (temp_dir, policy) = topology_tempdir();
        let fake_bin = temp_dir.path().join("fake-bin");
        std::fs::create_dir_all(&fake_bin).expect("create fake bin dir");
        let fake_ln = fake_bin.join("ln");
        std::fs::write(
            &fake_ln,
            "#!/bin/sh\n\
if [ \"$1\" = \"-s\" ] && [ \"$2\" = \"--\" ]; then\n\
  /bin/ln -s \"$3\" \"$4\" 2>/dev/null || true\n\
  echo \"ln: failed to create symbolic link '$4': File exists\" >&2\n\
  exit 1\n\
fi\n\
exec /bin/ln \"$@\"\n",
        )
        .expect("write fake ln");
        let mut perms = std::fs::metadata(&fake_ln)
            .expect("fake ln metadata")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&fake_ln, perms).expect("chmod fake ln");

        let command = build_worker_projects_topology_cmd(&policy);
        let path = format!(
            "{}:{}",
            fake_bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let output = std::process::Command::new("sh")
            .arg("-c")
            .arg(command)
            .env("PATH", path)
            .output()
            .expect("run topology command");

        assert!(
            output.status.success(),
            "file-exists create race should be harmless; status={:?} stdout={} stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("RCH_TOPOLOGY_OK"),
            "successful preflight should emit OK"
        );
        assert_eq!(
            std::fs::read_link(policy.alias_root()).expect("alias symlink target"),
            policy.canonical_root().to_path_buf()
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_build_worker_projects_topology_cmd_reports_alias_create_collision_path() {
        let _guard = test_guard!();
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = tempfile::tempdir().expect("temp dir");
        let sentinel = temp_dir.path().join("diagnostic-substitution-ran");
        let policy = PathTopologyPolicy::new(
            temp_dir.path().join("projects"),
            temp_dir
                .path()
                .join(format!("dp_$(touch {})", sentinel.display())),
        );
        let fake_bin = temp_dir.path().join("fake-bin");
        std::fs::create_dir_all(&fake_bin).expect("create fake bin dir");
        let fake_ln = fake_bin.join("ln");
        std::fs::write(
            &fake_ln,
            "#!/bin/sh\n\
if [ \"$1\" = \"-s\" ] && [ \"$2\" = \"--\" ]; then\n\
  echo \"ln: Already exists\" >&2\n\
  exit 1\n\
fi\n\
exec /bin/ln \"$@\"\n",
        )
        .expect("write fake ln");
        let mut perms = std::fs::metadata(&fake_ln)
            .expect("fake ln metadata")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&fake_ln, perms).expect("chmod fake ln");

        let command = build_worker_projects_topology_cmd(&policy);
        let path = format!(
            "{}:{}",
            fake_bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let output = std::process::Command::new("sh")
            .arg("-c")
            .arg(command)
            .env("PATH", path)
            .output()
            .expect("run topology command");
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(
            !output.status.success(),
            "unresolved alias create collision should fail"
        );
        assert!(
            stderr.contains("RCH_TOPOLOGY_ERR_ALIAS_CREATE_FAILED"),
            "stderr should keep a structured failure code: {stderr}"
        );
        assert!(
            stderr.contains(&format!("path={}", policy.alias_root().display())),
            "stderr should include the exact colliding alias path: {stderr}"
        );
        assert!(
            stderr.contains("$(touch "),
            "stderr should include the literal configured path: {stderr}"
        );
        assert!(
            stderr.contains(&format!("target={}", policy.canonical_root().display())),
            "stderr should include the intended canonical target: {stderr}"
        );
        assert!(
            stderr.contains("ln: Already exists"),
            "stderr should preserve the underlying ln diagnostic: {stderr}"
        );
        assert!(
            !sentinel.exists(),
            "diagnostic formatting must not re-expand command substitutions from configured paths"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_build_worker_projects_topology_cmd_accepts_resolved_alias_target() {
        let _guard = test_guard!();
        use std::os::unix::fs::symlink;

        let temp_dir = tempfile::tempdir().expect("temp dir");
        let real_root = temp_dir.path().join("data/projects");
        let configured_root = temp_dir.path().join("Users/jemanuel/projects");
        let alias_root = temp_dir.path().join("dp");
        std::fs::create_dir_all(&real_root).expect("create real root");
        std::fs::create_dir_all(configured_root.parent().expect("configured parent"))
            .expect("create configured parent");
        symlink(&real_root, &configured_root).expect("create configured canonical symlink");
        symlink(&real_root, &alias_root).expect("create alias symlink");

        let policy = PathTopologyPolicy::new(configured_root.clone(), alias_root.clone());
        let output = std::process::Command::new("sh")
            .arg("-lc")
            .arg(build_worker_projects_topology_cmd(&policy))
            .output()
            .expect("run topology command");

        assert!(
            output.status.success(),
            "resolved alias target should be accepted; status={:?} stdout={} stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("RCH_TOPOLOGY_OK"),
            "successful preflight should emit OK"
        );
        assert_eq!(
            std::fs::read_link(&alias_root).expect("alias symlink target"),
            real_root,
            "alias should not be rewritten when it resolves to the configured canonical root"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_build_worker_projects_topology_cmd_accepts_identity_policy() {
        let _guard = test_guard!();

        // rch#32: an identity policy (alias root == canonical root, a plain
        // directory) is accepted host-side, so the worker preflight must accept it
        // too — a non-symlink alias whose realpath equals canonical is satisfied,
        // not refused with RCH_TOPOLOGY_ERR_ALIAS_NOT_SYMLINK on every worker.
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let root = temp_dir.path().join("scratch");
        std::fs::create_dir_all(&root).expect("create root");

        let policy = PathTopologyPolicy::new(root.clone(), root.clone());
        let output = std::process::Command::new("sh")
            .arg("-lc")
            .arg(build_worker_projects_topology_cmd(&policy))
            .output()
            .expect("run topology command");

        assert!(
            output.status.success(),
            "identity policy (alias == canonical directory) must be accepted; status={:?} stdout={} stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("RCH_TOPOLOGY_OK"),
            "identity policy preflight should emit OK, not a per-worker refusal"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_build_worker_projects_topology_cmd_still_refuses_unrelated_dir_alias() {
        let _guard = test_guard!();

        // The realpath-equality relaxation must NOT admit a non-symlink alias that
        // resolves somewhere OTHER than canonical — that stays a structured exit-42.
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let canonical = temp_dir.path().join("canonical");
        let alias = temp_dir.path().join("alias");
        std::fs::create_dir_all(&canonical).expect("create canonical");
        std::fs::create_dir_all(&alias).expect("create unrelated alias dir");

        let policy = PathTopologyPolicy::new(canonical, alias);
        let output = std::process::Command::new("sh")
            .arg("-lc")
            .arg(build_worker_projects_topology_cmd(&policy))
            .output()
            .expect("run topology command");

        assert!(
            !output.status.success(),
            "an unrelated non-symlink alias directory must still be refused"
        );
        assert_eq!(output.status.code(), Some(42));
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("RCH_TOPOLOGY_ERR_ALIAS_NOT_SYMLINK"),
            "refusal must keep its structured error code"
        );
    }

    #[test]
    fn test_parse_ownership_detect_output_classifies_all_contract_paths() {
        let _guard = test_guard!();

        assert_eq!(
            parse_ownership_detect_output(true, "RCH_OWNERSHIP_OK\n", ""),
            MirrorOwnershipProbe::Healthy
        );
        assert_eq!(
            parse_ownership_detect_output(true, "RCH_OWNERSHIP_DRIFT:count=7\n", ""),
            MirrorOwnershipProbe::Drift { count: 7 }
        );
        assert_eq!(
            parse_ownership_detect_output(true, "", "RCH_OWNERSHIP_CHECK_UNAVAILABLE\n"),
            MirrorOwnershipProbe::CheckUnavailable
        );
        // Non-zero exit is unprobeable even when a sentinel also appears —
        // `set -e` means the script never intends a non-zero exit.
        assert!(matches!(
            parse_ownership_detect_output(false, "", "boom"),
            MirrorOwnershipProbe::Unprobeable(_)
        ));
        // Unrecognized stdout with exit 0 is honestly unprobeable too.
        assert!(matches!(
            parse_ownership_detect_output(true, "hello?", ""),
            MirrorOwnershipProbe::Unprobeable(_)
        ));
    }

    #[test]
    fn test_build_worker_ownership_detect_cmd_is_read_only_and_escapes_root() {
        let _guard = test_guard!();

        let weird = PathBuf::from("/tmp/rch own';root");
        let cmd = build_worker_ownership_detect_cmd(&weird);

        assert!(
            !cmd.contains("chown"),
            "detect command must never mutate worker state: {cmd}"
        );
        assert!(
            !cmd.contains("rm "),
            "detect command must never delete: {cmd}"
        );
        assert!(
            cmd.contains("sudo -n find \"$r\" -xdev -user root -print"),
            "detect command must only count root-owned entries: {cmd}"
        );
        assert!(
            cmd.contains("'\\''"),
            "shell metacharacters in the configured root must be escaped: {cmd}"
        );

        // The generated script must execute as valid shell. Run it against
        // a tempdir root; depending on whether passwordless sudo exists in
        // this environment it either reports OK/DRIFT or CHECK_UNAVAILABLE,
        // but it must always exit 0 (fail-open contract).
        let scratch = tempfile::tempdir().expect("temp dir");
        std::fs::write(scratch.path().join("marker"), b"x").expect("write marker");
        let output = std::process::Command::new("sh")
            .arg("-lc")
            .arg(build_worker_ownership_detect_cmd(scratch.path()))
            .output()
            .expect("run detect command locally");
        assert_eq!(
            output.status.code(),
            Some(0),
            "detect command is fail-open; status={:?} stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
