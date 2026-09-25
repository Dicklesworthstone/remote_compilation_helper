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
//! - `build_remote_shell_command` — quotes remote scripts for the login shell,
//!   or directly starts the Windows stdin-script reader.
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
use crate::transfer::WorkerPlatform;

const MAX_OFFLOAD_SSH_OUTPUT_BYTES: usize = 32 * 1024 * 1024;
const MAX_SOURCE_LOCK_READY_BYTES: usize = 4096;
const MAX_SOURCE_LOCK_OUTPUT_BYTES: usize = 64 * 1024;
const REMOTE_SOURCE_AUTHORITY_LOCK_DIR: &str = "/tmp/rch-source-authority-locks";
const SOURCE_AUTHORITY_LOCK_HOLDER: &str = include_str!("source_lock_holder.sh");

/// Keeps the worker-side advisory locks for a mutable Cargo source closure alive.
///
/// The remote holder blocks on this SSH session's stdin after acquiring every
/// lock. Dropping the guard kills the local SSH child; the resulting EOF/HUP
/// ends the holder and releases its inherited kernel locks.
pub(super) struct RemoteSourceAuthorityLock {
    worker_id: WorkerId,
    child: Option<tokio::process::Child>,
    stdin: Option<tokio::process::ChildStdin>,
    stdout_drain: Option<tokio::task::JoinHandle<std::io::Result<Vec<u8>>>>,
    stderr_drain: Option<tokio::task::JoinHandle<std::io::Result<Vec<u8>>>>,
    release_request: Option<String>,
}

impl RemoteSourceAuthorityLock {
    pub(super) fn pair_token(&self) -> Option<&str> {
        self.release_request
            .as_deref()?
            .strip_prefix("RCH_SOURCE_PAIR_RELEASE:")
    }

    /// OpenSSH uses 255 for transport errors; a missing local exit status is
    /// represented as -1. Neither proves that remote Cargo has stopped.
    pub(super) fn ensure_execution_finished(&mut self, exit_code: i32) -> anyhow::Result<()> {
        self.ensure_held()?;
        if !(0..255).contains(&exit_code) {
            anyhow::bail!(
                "source pair remains occupied: SSH execution exit {exit_code} does not prove remote completion"
            );
        }
        Ok(())
    }

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
    pub(super) async fn release(self) -> anyhow::Result<()> {
        self.release_with_timeout(Duration::from_secs(15)).await
    }

    async fn release_with_timeout(mut self, budget: Duration) -> anyhow::Result<()> {
        use tokio::io::AsyncWriteExt as _;

        let deadline = tokio::time::Instant::now() + budget;
        let collect = async {
            if let Some(request) = self.release_request.as_ref() {
                let stdin = self
                    .stdin
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("source-pair release stdin is missing"))?;
                stdin.write_all(format!("{request}\n").as_bytes()).await?;
            }
            drop(self.stdin.take());
            // Keep the child AND both handles in the guard until the whole
            // protocol finishes. Taking a JoinHandle would detach its reader
            // when this future times out or its caller stops waiting.
            let child = self
                .child
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("remote source-authority lock is not active"))?;
            let wait = async { Ok::<_, anyhow::Error>(child.wait().await?) };
            let (status, stdout, stderr) = tokio::try_join!(
                wait,
                join_lock_drain(self.stdout_drain.as_mut()),
                join_lock_drain(self.stderr_drain.as_mut()),
            )?;
            if !status.success() {
                anyhow::bail!(
                    "remote source-authority lock on {} exited unexpectedly: {}; stdout={}; stderr={}",
                    self.worker_id,
                    status,
                    String::from_utf8_lossy(&stdout).trim(),
                    String::from_utf8_lossy(&stderr).trim()
                );
            }
            if let Some(request) = self.release_request.as_ref()
                && stdout != format!("{request}\n").as_bytes()
            {
                anyhow::bail!(
                    "source-pair release acknowledgment missing on {}",
                    self.worker_id
                );
            }
            Ok(())
        };
        // A successful wait() does not imply EOF: descendants can retain the
        // pipes. The same deadline must cover the write, wait and BOTH drains.
        match tokio::time::timeout_at(deadline, collect).await {
            Ok(result) => result,
            Err(_) => anyhow::bail!(
                "timed out releasing remote source-authority lock on {}",
                self.worker_id
            ),
        }
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
    task: Option<&mut tokio::task::JoinHandle<std::io::Result<Vec<u8>>>>,
) -> anyhow::Result<Vec<u8>> {
    match task {
        Some(task) => Ok(task.await??),
        None => Ok(Vec::new()),
    }
}

fn source_authority_lock_path(root: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"rch.remote_source_authority_lock.v1\0");
    hasher.update(root.as_bytes());
    format!(
        "{REMOTE_SOURCE_AUTHORITY_LOCK_DIR}/{}.lock",
        hasher.finalize().to_hex()
    )
}

fn source_authority_lock_paths(authority_roots: &[String]) -> Vec<String> {
    let mut roots = authority_roots.to_vec();
    roots.sort();
    roots.dedup();
    roots
        .into_iter()
        .map(|root| source_authority_lock_path(&root))
        .collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SourceAuthorityLockSpec {
    path: String,
    shared: bool,
}

/// A full-tree writer must exclude writers of any subtree. Shared ancestor
/// locks make that conflict visible without serializing disjoint siblings.
/// Resolve the strongest mode before taking any lock: upgrades can deadlock.
fn source_authority_lock_plan(
    authority_roots: &[String],
    include_ancestors: bool,
) -> anyhow::Result<Vec<SourceAuthorityLockSpec>> {
    let mut roots = std::collections::BTreeMap::new();
    for root in authority_roots {
        let path = Path::new(root);
        let canonical = path.components().collect::<PathBuf>();
        anyhow::ensure!(
            path.is_absolute()
                && path.as_os_str() == canonical.as_os_str()
                && !path.components().any(|component| matches!(
                    component,
                    std::path::Component::ParentDir | std::path::Component::Prefix(_)
                )),
            "source authority must be a canonical absolute path: {root:?}"
        );
        roots.insert(root.clone(), false);
        if include_ancestors {
            for ancestor in path.ancestors().skip(1) {
                roots
                    .entry(ancestor.to_string_lossy().into_owned())
                    .or_insert(true);
            }
        }
    }
    // Sort by canonical source paths, never by their lock-file hashes. Every
    // invocation then acquires overlapping sets in the same global order.
    Ok(roots
        .into_iter()
        .map(|(root, shared)| SourceAuthorityLockSpec {
            path: source_authority_lock_path(&root),
            shared,
        })
        .collect())
}

fn build_remote_source_authority_lock_cmd(
    lock_dir: &str,
    locks: &[SourceAuthorityLockSpec],
    ready_marker: &str,
) -> anyhow::Result<String> {
    if locks.is_empty() {
        anyhow::bail!("remote source-authority lock set must not be empty");
    }
    let mut seen = std::collections::HashSet::new();
    for lock in locks {
        let path = &lock.path;
        // The quoted here-document carries literal, one-lock-per-line data.
        // Absolute paths cannot equal its non-path delimiter. Keep the caller's
        // established canonical-root order; re-sorting hashes could deadlock
        // against older holders that acquire the same roots in that order.
        if !path.starts_with('/')
            || path.bytes().any(|byte| matches!(byte, b'\n' | b'\r' | 0))
            || !seen.insert(path)
        {
            anyhow::bail!("invalid or duplicate source-authority lock path: {path:?}");
        }
    }
    if ready_marker.is_empty()
        || ready_marker.len() >= MAX_SOURCE_LOCK_READY_BYTES
        || ready_marker
            .bytes()
            .any(|byte| matches!(byte, b'\n' | b'\r' | 0))
    {
        anyhow::bail!("invalid source-authority ready marker");
    }
    // The closure is data on fd 3, not an argument to SSH, sh, or flock.
    // The fixed holder re-execs with --no-fork and inherits each acquired
    // descriptor, avoiding both E2BIG and one live flock process per root.
    // One descriptor per root is still necessary; exhaustion fails before
    // readiness and process exit releases every partially acquired lock.
    let holder = shell_escape::escape(SOURCE_AUTHORITY_LOCK_HOLDER.into());
    let records = locks
        .iter()
        .map(|lock| format!("{} {}", if lock.shared { "s" } else { "x" }, lock.path))
        .collect::<Vec<_>>()
        .join("\n");
    Ok(format!(
        "set -e\nmkdir -p -- {directory}\nexec 3<<'RCH_SOURCE_LOCK_PATHS'\n{paths}\nRCH_SOURCE_LOCK_PATHS\nexec sh -c {holder} {holder} {count} {ready}",
        directory = shell_escape::escape(lock_dir.into()),
        paths = records,
        count = locks.len(),
        ready = shell_escape::escape(ready_marker.into()),
    ))
}

fn source_authority_lock_transport(
    platform: WorkerPlatform,
    remote_cmd: &str,
) -> (String, Option<String>) {
    let reader = if platform.is_windows() {
        "sh -s".to_owned()
    } else {
        // Preserve POSIX login initialization without putting the closure in
        // its -c argument, and replace the login shell rather than retaining it.
        build_remote_shell_command(platform, "exec sh -s")
    };
    // Parse the entire compound command before executing any stdin consumer.
    // The pipe must remain OPEN afterward: EOF releases ordinary source locks,
    // while source pairs read their explicit release request from the same pipe.
    // An exec sh -c '<large script>' bootstrap would merely move E2BIG remotely.
    (reader, Some(format!("{{\n{remote_cmd}\n}}\n")))
}

/// Acquire sorted, worker-side locks for every mutable canonical source root.
/// One persistent SSH session owns the whole set, so separate coordinator
/// processes cannot overwrite any member of a Cargo closure while it compiles.
pub(super) async fn acquire_remote_source_authority_lock(
    worker: &WorkerConfig,
    authority_roots: &[String],
    source_pair: Option<&mut RemoteSourceAuthorityLock>,
    wait_timeout: Duration,
) -> anyhow::Result<RemoteSourceAuthorityLock> {
    // A validated clean-overlay pair already holds its container exclusively.
    // Its private descendants retain their exact locks; re-locking their parent
    // through another SSH session would deadlock against our own pair holder.
    // Derive this exception from the actual live pair, never a caller flag or
    // an unvalidated recovery-recipe path.
    let include_ancestors = if let Some(pair) = source_pair {
        pair.ensure_held()?;
        anyhow::ensure!(
            pair.pair_token().is_some(),
            "source pair has no owner token"
        );
        false
    } else {
        true
    };
    let locks = source_authority_lock_plan(authority_roots, include_ancestors)?;
    let ready_marker = format!("RCH_SOURCE_AUTHORITY_READY:{}", uuid::Uuid::new_v4());
    let remote_cmd = build_remote_source_authority_lock_cmd(
        REMOTE_SOURCE_AUTHORITY_LOCK_DIR,
        &locks,
        &ready_marker,
    )?;
    spawn_source_authority_lock(worker, &remote_cmd, &ready_marker, wait_timeout).await
}

/// A reusable source path must remain unavailable after holder loss: the old
/// upload/build can outlive its control SSH connection. Only explicit release
/// after execution, retrieval and source retirement permits the next owner.
pub(super) async fn acquire_clean_overlay_source_pair(
    worker: &WorkerConfig,
    source_root: &str,
    wait_timeout: Duration,
) -> anyhow::Result<RemoteSourceAuthorityLock> {
    let lock_path = source_authority_lock_paths(&[source_root.to_string()])
        .into_iter()
        .next()
        .expect("one source root produces one lock");
    let token = uuid::Uuid::new_v4().to_string();
    let ready = format!("RCH_SOURCE_PAIR_READY:{token}");
    let release = format!("RCH_SOURCE_PAIR_RELEASE:{token}");
    let command =
        clean_overlay_source_pair_lock_command(&lock_path, source_root, &token, &ready, &release);
    let mut guard = spawn_source_authority_lock(worker, &command, &ready, wait_timeout).await?;
    guard.release_request = Some(release);
    Ok(guard)
}
/// Reattach only the recorded owner; never create or steal a source pair.
pub(super) async fn recover_clean_overlay_source_pair(
    worker: &WorkerConfig,
    source_root: &str,
    token: &str,
    wait_timeout: Duration,
) -> anyhow::Result<RemoteSourceAuthorityLock> {
    let lock_path = source_authority_lock_paths(&[source_root.to_owned()])
        .pop()
        .expect("one source root");
    let quote = |value: &str| shell_escape::escape(value.into()).into_owned();
    let ready = format!("RCH_SOURCE_PAIR_READY:{token}");
    let release = format!("RCH_SOURCE_PAIR_RELEASE:{token}");
    let owner = format!("{lock_path}.owner");
    let receipt = format!(
        "{lock_path}.released-{}",
        blake3::hash(token.as_bytes()).to_hex()
    );
    let script = format!(
        "set -eu; owner={owner}; root={root}; token={token}; \
         [ ! -L \"$owner\" ] && [ \"$(cat \"$owner\")\" = \"$token\" ]; \
         printf '%s\\n' {ready}; IFS= read -r request; \
         [ \"$request\" = {release} ]; [ \"$(cat \"$owner\")\" = \"$token\" ]; \
         [ ! -e \"$root\" ] && [ ! -L \"$root\" ]; \
         printf '%s\\n' {token} > {receipt}; sync -f {receipt}; \
         printf 'released\\n' > \"$owner\"; sync -f \"$owner\"; printf '%s\\n' {release}",
        owner = quote(&owner),
        root = quote(source_root),
        token = quote(token),
        ready = quote(&ready),
        release = quote(&release),
        receipt = quote(&receipt),
    );
    let command = format!(
        "exec flock -x {} sh -c {}",
        quote(&lock_path),
        quote(&script)
    );
    let mut guard = spawn_source_authority_lock(worker, &command, &ready, wait_timeout).await?;
    guard.release_request = Some(release);
    Ok(guard)
}

/// Reconcile only an exact-token release receipt while holding the pair lock.
/// Consumed by retirement retry after a lost release acknowledgement.
pub(super) async fn clean_overlay_source_pair_was_released(
    worker: &WorkerConfig,
    source_root: &str,
    token: &str,
) -> anyhow::Result<bool> {
    let lock_path = source_authority_lock_paths(&[source_root.to_owned()])
        .pop()
        .expect("one source root");
    let quote = |value: &str| shell_escape::escape(value.into()).into_owned();
    let owner = format!("{lock_path}.owner");
    let receipt = format!(
        "{lock_path}.released-{}",
        blake3::hash(token.as_bytes()).to_hex()
    );
    let script = format!(
        "set -eu; [ ! -L {receipt} ]; \
         if [ ! -f {receipt} ]; then printf pending; exit 0; fi; \
         [ \"$(cat {receipt})\" = {token} ]; [ ! -L {owner} ]; \
         if [ \"$(cat {owner})\" = {token} ]; then \
         [ ! -e {root} ] && [ ! -L {root} ]; \
         printf 'released\\n' > {owner}; sync -f {owner}; fi; printf released",
        receipt = quote(&receipt),
        token = quote(token),
        owner = quote(&owner),
        root = quote(source_root),
    );
    let command = format!("flock -x {} sh -c {}", quote(&lock_path), quote(&script));
    let output = run_offload_ssh_command_with_stdin(
        worker,
        "sh -s",
        command.as_bytes(),
        Duration::from_secs(15),
    )
    .await?;
    anyhow::ensure!(
        output.status.success(),
        "cannot verify source-pair release receipt"
    );
    match output.stdout.as_slice() {
        b"released" => Ok(true),
        b"pending" => Ok(false),
        _ => anyhow::bail!("invalid source-pair release response"),
    }
}

fn clean_overlay_source_pair_lock_command(
    lock_path: &str,
    source_root: &str,
    token: &str,
    ready: &str,
    release: &str,
) -> String {
    let quote = |value: &str| shell_escape::escape(value.into()).into_owned();
    let owner = format!("{lock_path}.owner");
    let receipt = format!(
        "{lock_path}.released-{}",
        blake3::hash(token.as_bytes()).to_hex()
    );
    let script = format!(
        "set -eu; owner={owner}; root={root}; token={token}; \
         if [ -L \"$owner\" ] || {{ [ -e \"$owner\" ] && [ \"$(cat \"$owner\")\" != released ]; }}; then \
         echo 'RCH: source pair has an unfinished owner; inspect the prior job or use RCH_DISABLE_TARGET_REUSE=1' >&2; exit 1; fi; \
         if [ -e \"$root\" ] || [ -L \"$root\" ]; then \
         echo 'RCH: source pair has unretired source; refusing reuse' >&2; exit 1; fi; \
         printf '%s\\n' \"$token\" > \"$owner\"; mkdir -p \"$root\"; \
         printf '%s\\n' {ready}; IFS= read -r request; \
         [ \"$request\" = {release} ]; [ \"$(cat \"$owner\")\" = \"$token\" ]; \
         [ ! -e \"$root\" ] && [ ! -L \"$root\" ]; \
         printf '%s\\n' {token} > {receipt}; sync -f {receipt}; \
         printf 'released\\n' > \"$owner\"; sync -f \"$owner\"; printf '%s\\n' {release}",
        owner = quote(&owner),
        root = quote(source_root),
        token = quote(token),
        ready = quote(ready),
        release = quote(release),
        receipt = quote(&receipt),
    );
    format!(
        "mkdir -p {} && exec flock -x {} sh -c {}",
        quote(REMOTE_SOURCE_AUTHORITY_LOCK_DIR),
        quote(lock_path),
        quote(&script),
    )
}

async fn spawn_source_authority_lock(
    worker: &WorkerConfig,
    remote_cmd: &str,
    ready_marker: &str,
    wait_timeout: Duration,
) -> anyhow::Result<RemoteSourceAuthorityLock> {
    use anyhow::Context as _;
    let identity_file = shellexpand::tilde(&worker.identity_file);
    let destination = format!("{}@{}", worker.user, worker.host);
    let mut cmd = Command::new("ssh");
    cmd.arg("-o").arg("BatchMode=yes");
    cmd.arg("-o").arg("StrictHostKeyChecking=accept-new");
    cmd.arg("-o").arg("ConnectTimeout=10");
    cmd.arg("-i").arg(identity_file.as_ref());
    cmd.arg(&destination);
    let (remote_arg, stdin_bootstrap) =
        source_authority_lock_transport(WorkerPlatform::from_worker(worker), remote_cmd);
    cmd.arg(remote_arg);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let child = cmd
        .spawn()
        .with_context(|| format!("failed to start source-authority lock on {destination}"))?;
    finish_source_authority_lock_acquisition(
        child,
        worker.id.clone(),
        ready_marker,
        stdin_bootstrap.as_deref(),
        wait_timeout,
    )
    .await
}

async fn finish_source_authority_lock_acquisition(
    mut child: tokio::process::Child,
    worker_id: WorkerId,
    ready_marker: &str,
    stdin_bootstrap: Option<&str>,
    wait_timeout: Duration,
) -> anyhow::Result<RemoteSourceAuthorityLock> {
    use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _};

    let mut stdin = child
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
    let stderr_drain = tokio::spawn(crate::transfer::read_bounded_output_stream(
        stderr,
        MAX_SOURCE_LOCK_OUTPUT_BYTES,
    ));
    // Own cleanup before any fallible write/read: timeout, cancellation and
    // invalid readiness must not detach the drain or leave a lock holder.
    let mut guard = RemoteSourceAuthorityLock {
        worker_id,
        child: Some(child),
        stdin: None,
        stdout_drain: None,
        stderr_drain: Some(stderr_drain),
        release_request: None,
    };

    let mut observed = String::new();
    let acquisition = async {
        let write_bootstrap = async {
            if let Some(bootstrap) = stdin_bootstrap {
                stdin.write_all(bootstrap.as_bytes()).await?;
                stdin.flush().await?;
            }
            Ok::<(), std::io::Error>(())
        };
        let read_ready = async {
            // Bound the read itself, not just the buffer after read_line has
            // waited for an arbitrarily large or never-terminated frame.
            let read = (&mut stdout)
                .take((MAX_SOURCE_LOCK_READY_BYTES + 1) as u64)
                .read_line(&mut observed)
                .await?;
            if read > MAX_SOURCE_LOCK_READY_BYTES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "source-authority ready frame exceeded its byte limit",
                ));
            }
            Ok(read)
        };
        tokio::try_join!(write_bootstrap, read_ready)
    };
    let failure = match timeout(wait_timeout, acquisition).await {
        Ok(Ok(((), 0))) => Some(format!(
            "source-authority lock on {} exited before acquisition",
            guard.worker_id
        )),
        Ok(Ok(((), _)))
            if observed
                .strip_suffix('\n')
                .map(|line| line.strip_suffix('\r').unwrap_or(line))
                == Some(ready_marker) =>
        {
            None
        }
        Ok(Ok(((), _))) => Some(format!(
            "source-authority lock on {} emitted an invalid ready marker: {:?}",
            guard.worker_id,
            observed.trim_end()
        )),
        Ok(Err(err)) => Some(format!(
            "failed writing source-authority lock bootstrap or reading readiness on {}: {err}",
            guard.worker_id
        )),
        Err(_) => Some(format!(
            "timed out waiting {:?} for source-authority locks on {}",
            wait_timeout, guard.worker_id
        )),
    };
    if let Some(failure) = failure {
        drop(stdin);
        if let Some(child) = guard.child.as_mut() {
            let _ = child.start_kill();
            let _ = timeout(Duration::from_secs(1), child.wait()).await;
        }
        let stderr = if let Some(task) = guard.stderr_drain.as_mut() {
            match timeout(Duration::from_secs(1), task).await {
                Ok(Ok(Ok(bytes))) => String::from_utf8_lossy(&bytes).trim().to_string(),
                Ok(Ok(Err(err))) => format!("stderr read failed: {err}"),
                Ok(Err(err)) => format!("stderr task failed: {err}"),
                Err(_) => "stderr drain did not finish before cleanup deadline".into(),
            }
        } else {
            String::new()
        };
        anyhow::bail!("{failure}; stderr={stderr}");
    }

    guard.stdin = Some(stdin);
    guard.stdout_drain = Some(tokio::spawn(crate::transfer::read_bounded_output_stream(
        stdout,
        MAX_SOURCE_LOCK_OUTPUT_BYTES,
    )));
    Ok(guard)
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
    cmd.arg(build_remote_shell_command(
        WorkerPlatform::from_worker(worker),
        remote_cmd,
    ));
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

fn build_remote_shell_command(platform: WorkerPlatform, remote_cmd: &str) -> String {
    // The Windows control-plane script is carried on stdin. Its fixed reader
    // needs no quoting or login initialization; that extra startup can exhaust
    // the dependency probe budget before the file checks run.
    if platform.is_windows() && remote_cmd == "sh -s" {
        return remote_cmd.to_string();
    }
    format!("sh -lc {}", shell_escape::escape(remote_cmd.into()))
}

/// Isolated Git overlays live beneath the configured worker staging base,
/// not beneath the controller's canonical source root. Keep the controller
/// policy for ordinary mirrors and validate every isolated destination before
/// any remote topology command can create or repair a path.
pub(super) fn remote_preflight_topology_policy(
    controller_policy: &PathTopologyPolicy,
    clean_overlay: bool,
    remote_base: &str,
    dispatch_closure_roots: &[PathBuf],
) -> anyhow::Result<PathTopologyPolicy> {
    if !clean_overlay {
        return Ok(controller_policy.clone());
    }

    let remote_base = rch_common::types::validate_remote_base(remote_base)
        .map_err(|error| anyhow::anyhow!("invalid clean-overlay staging base: {error}"))?;
    if remote_base.chars().any(char::is_control) || remote_base.contains('\\') {
        anyhow::bail!("clean-overlay staging base contains an invalid path character");
    }
    let staging_root = PathBuf::from(remote_base);
    if dispatch_closure_roots.is_empty() {
        anyhow::bail!("clean-overlay staging preflight requires a planned source root");
    }
    for root in dispatch_closure_roots {
        let literal = root.to_str().ok_or_else(|| {
            anyhow::anyhow!("clean-overlay source destination is not a UTF-8 path")
        })?;
        if literal.chars().any(char::is_control)
            || literal.contains('\\')
            || literal.split('/').any(|part| part == "." || part == "..")
        {
            anyhow::bail!(
                "invalid clean-overlay source destination: {}",
                root.display()
            );
        }
        let relative = root.strip_prefix(&staging_root).ok().filter(|relative| {
            !relative.as_os_str().is_empty()
                && relative
                    .components()
                    .all(|part| matches!(part, std::path::Component::Normal(_)))
        });
        if relative.is_none() {
            anyhow::bail!(
                "clean-overlay source destination {} is not a strict descendant of staging base {}",
                root.display(),
                staging_root.display()
            );
        }
    }
    // No worker-global alias is required for an invocation-owned archive.
    Ok(PathTopologyPolicy::new(staging_root.clone(), staging_root))
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
        .map(|root| shell_escape::escape(root.to_string_lossy()))
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
    let repaired = repair_worker_mirror_ownership(worker, reporter, &ownership_scan_roots).await?;
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
    // bd-8iwkm/bd-gc0ze: when the SSH user IS root, rsync already runs as
    // root and root-owned entries cannot block replace/unlink. Counting them
    // would flag the entire mirror as drift while the repair chown is a
    // no-op, so the sweep would report RCH_OWNERSHIP_PARTIAL forever and
    // fail-closed every dispatch on root-login workers.
    if worker.user == "root" {
        reporter.verbose("[RCH] ownership preflight skipped for root-login worker");
        return Ok(0);
    }
    let cmd = build_worker_ownership_repair_cmd(roots, &worker.user);
    // bd-gc0ze: closure-scoped sweeps normally finish in seconds; 600s bounds
    // pathological trees without failing every dispatch the way the old fixed
    // 60s budget did once mirrors grew past multi-GB.
    // rch#71: keep the closure-sized script off argv. The existing stdin
    // executor retains the timeout, concurrent output drains and kill-on-drop.
    let output = run_offload_ssh_command_with_stdin(
        worker,
        "sh -s",
        cmd.as_bytes(),
        Duration::from_secs(600),
    )
    .await?;
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

    #[cfg(unix)]
    #[tokio::test]
    async fn test_worker_ownership_repair_streams_large_closure() {
        let _guard = test_guard!();
        const DIR_ENV: &str = "RCH_OWNERSHIP_TEST_DIR";
        const ROOT_ENV: &str = "RCH_OWNERSHIP_TEST_ROOT";

        // Re-enter this test in a child with its own PATH. Do not mutate the
        // process-wide environment while the rest of the test suite runs.
        if let Some(dir) = std::env::var_os(DIR_ENV) {
            let dir = PathBuf::from(dir);
            let worker = WorkerConfig {
                id: WorkerId::new("ownership-stdin-test"),
                host: "ownership-test.invalid".into(),
                user: "ubuntu".into(),
                ..WorkerConfig::default()
            };
            assert!(!should_skip_remote_preflight(&worker));
            let reporter = HookReporter::new(OutputVisibility::Summary);
            let mut roots: Vec<PathBuf> = (0..4096)
                .map(|i| {
                    dir.join("missing")
                        .join(format!("dep-{i:04}-{}", "x".repeat(160)))
                })
                .collect();
            // An existing, shell-sensitive root at the end also proves that
            // the large payload was not truncated or its roots reinterpreted.
            roots.push(PathBuf::from(std::env::var_os(ROOT_ENV).unwrap()));
            let script = build_worker_ownership_repair_cmd(&roots, &worker.user);
            assert!(script.len() > 128 * 1024);

            for (mode, count, error, calls) in [
                ("healthy", 0, None, "detect\n"),
                ("repair", 1, None, "detect\nrepair\ndetect\n"),
                ("check-unavailable", 0, None, "detect\n"),
                (
                    "unavailable",
                    0,
                    Some((46, "RCH_OWNERSHIP_REPAIR_UNAVAILABLE:detected=1")),
                    "detect\nrepair\n",
                ),
                (
                    "partial",
                    0,
                    Some((47, "RCH_OWNERSHIP_PARTIAL:remaining=1")),
                    "detect\nrepair\ndetect\n",
                ),
            ] {
                std::fs::write(dir.join("mode"), mode).unwrap();
                std::fs::write(dir.join("state"), "pending").unwrap();
                std::fs::write(dir.join("calls"), "").unwrap();
                let result = timeout(
                    Duration::from_secs(20),
                    repair_worker_mirror_ownership(&worker, &reporter, &roots),
                )
                .await
                .expect("ownership repair must not hang on stdin/EOF");
                if let Some((code, marker)) = error {
                    let error = result.expect_err(mode).to_string();
                    assert!(error.contains(&format!("status Some({code})")), "{error}");
                    assert!(error.contains(marker), "{error}");
                } else {
                    assert_eq!(result.expect(mode), count, "{mode}");
                }
                assert_eq!(
                    std::fs::read(dir.join("payload")).unwrap(),
                    script.as_bytes()
                );
                assert_eq!(std::fs::read_to_string(dir.join("calls")).unwrap(), calls);
            }
            std::fs::write(dir.join("finished"), "ok").unwrap();
            return;
        }

        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        let root = dir.path().join("root with ' quotes; $cash `echo nope`");
        std::fs::create_dir(&root).unwrap();
        let ssh = bin.join("ssh");
        std::fs::write(
            &ssh,
            r#"#!/bin/sh
set -eu
LC_ALL=C
export LC_ALL
remote=''
for arg; do
    [ "${#arg}" -lt 131072 ] || exit 90
    remote=$arg
done
[ "$remote" = "sh -lc 'sh -s'" ] || exit 91
cat > "$RCH_OWNERSHIP_TEST_DIR/payload"
# Execute the real remote wrapper and script, replacing only privileged work.
{
cat <<'RCH_TEST_SUDO'
sudo() {
    [ "$1" = -n ] && [ "$2" = find ] || return 92
    shift 2
    [ "$1" = "$RCH_OWNERSHIP_TEST_ROOT" ] || return 93
    shift
    [ "$1" = -xdev ] && [ "$2" = -user ] && [ "$3" = root ] || return 94
    shift 3
    mode=$(cat "$RCH_OWNERSHIP_TEST_DIR/mode")
    case "$1" in
        -print)
            [ "$#" -eq 1 ] || return 95
            echo detect >> "$RCH_OWNERSHIP_TEST_DIR/calls"
            [ "$mode" != check-unavailable ] || return 1
            if [ "$mode" != healthy ] && [ "$(cat "$RCH_OWNERSHIP_TEST_DIR/state")" != repaired ]; then
                printf 'root-owned-entry\n'
            fi
            ;;
        -exec)
            [ "$#" -eq 6 ] && [ "$2" = chown ] && [ "$3" = -h ] &&
                [ "$4" = ubuntu ] && [ "$5" = '{}' ] && [ "$6" = + ] || return 96
            echo repair >> "$RCH_OWNERSHIP_TEST_DIR/calls"
            [ "$mode" != unavailable ] || return 1
            if [ "$mode" = repair ]; then
                echo repaired > "$RCH_OWNERSHIP_TEST_DIR/state"
            fi
            ;;
        *) return 97 ;;
    esac
}
RCH_TEST_SUDO
cat "$RCH_OWNERSHIP_TEST_DIR/payload"
} | /bin/sh -c "$remote"
"#,
        )
        .unwrap();
        std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o755)).unwrap();
        let old_path = std::env::var_os("PATH").unwrap_or_default();
        let paths = std::iter::once(bin).chain(std::env::split_paths(&old_path));
        let path = std::env::join_paths(paths).unwrap();
        let test_name = concat!(
            module_path!(),
            "::test_worker_ownership_repair_streams_large_closure"
        );
        let test_name = test_name.split_once("::").unwrap().1;
        let output = timeout(
            Duration::from_secs(60),
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", test_name, "--nocapture"])
                .env(DIR_ENV, dir.path())
                .env(ROOT_ENV, &root)
                .env("PATH", path)
                .env("RCH_MOCK_SSH", "0")
                .kill_on_drop(true)
                .output(),
        )
        .await
        .expect("isolated ownership regression timed out")
        .expect("start isolated ownership regression");
        assert!(
            output.status.success(),
            "stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            dir.path().join("finished").is_file(),
            "child test did not run"
        );
    }

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

    fn exclusive_source_locks(paths: &[String]) -> Vec<SourceAuthorityLockSpec> {
        paths
            .iter()
            .map(|path| SourceAuthorityLockSpec {
                path: path.clone(),
                shared: false,
            })
            .collect()
    }

    #[test]
    fn source_authority_hierarchy_uses_one_order_and_strongest_mode() {
        let forward =
            source_authority_lock_plan(&["/a/child".into(), "/b/child".into(), "/a".into()], true)
                .unwrap();
        let reverse = source_authority_lock_plan(
            &[
                "/a".into(),
                "/b/child".into(),
                "/a/child".into(),
                "/a".into(),
            ],
            true,
        )
        .unwrap();
        assert_eq!(forward, reverse);
        let expected = [
            ("/", true),
            ("/a", false),
            ("/a/child", false),
            ("/b", true),
            ("/b/child", false),
        ]
        .into_iter()
        .map(|(root, shared)| SourceAuthorityLockSpec {
            path: source_authority_lock_path(root),
            shared,
        })
        .collect::<Vec<_>>();
        assert_eq!(forward, expected);
        for root in ["relative", "/a/../b", "/a/./b", "/a//b", "/a/"] {
            assert!(source_authority_lock_plan(&[root.into()], true).is_err());
        }
        let paired = source_authority_lock_plan(&["/private/child".into()], false).unwrap();
        assert_eq!(
            paired,
            exclusive_source_locks(&[source_authority_lock_path("/private/child")])
        );
    }

    #[cfg(target_os = "linux")]
    async fn claim_test_source_closure(roots: &[String]) -> RemoteSourceAuthorityLock {
        let locks = source_authority_lock_plan(roots, true).unwrap();
        let script = build_remote_source_authority_lock_cmd(
            REMOTE_SOURCE_AUTHORITY_LOCK_DIR,
            &locks,
            "CLOSURE_READY",
        )
        .unwrap();
        let (child, bootstrap) = local_source_lock_transport(WorkerPlatform::Posix, &script);
        finish_source_authority_lock_acquisition(
            child,
            WorkerId::new("local-closure-regression"),
            "CLOSURE_READY",
            bootstrap.as_deref(),
            Duration::from_secs(10),
        )
        .await
        .unwrap()
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn source_authority_hierarchy_prevents_nested_snapshot_mutation() {
        use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};

        let dir = tempfile::tempdir().unwrap().keep();
        let parent = dir.join("repository");
        let nested = parent.join("standalone");
        std::fs::create_dir_all(nested.join("src")).unwrap();
        std::fs::write(
            parent.join("Cargo.toml"),
            "[package]\nname='parent'\nversion='0.1.0'\n[dependencies]\nchild={path='standalone'}\n",
        )
        .unwrap();
        std::fs::write(
            nested.join("Cargo.toml"),
            "[package]\nname='child'\nversion='0.1.0'\n",
        )
        .unwrap();
        let source = nested.join("src/lib.rs");
        let policy = PathTopologyPolicy::new(dir.clone(), dir.join("alias"));
        // Exercise the production collapse that caused this race: the parent
        // transfer covers the child, while a child-cwd invocation syncs only
        // the child. Neither manifest declares a Cargo workspace.
        let parent_plan = build_sync_closure_plan(
            &[parent.clone(), nested.clone()],
            &parent,
            "parent-revision",
            &policy,
        );
        let nested_plan = build_sync_closure_plan(
            std::slice::from_ref(&nested),
            &nested,
            "child-revision",
            &policy,
        );
        assert_eq!(parent_plan.len(), 1);
        assert_eq!(nested_plan.len(), 1);
        assert_ne!(parent_plan[0].remote_root, nested_plan[0].remote_root);
        let parent_roots = vec![parent_plan[0].remote_root.clone()];
        let nested_roots = vec![nested_plan[0].remote_root.clone()];

        // Prove exclusion in both directions: ancestor writes versus a child
        // reader, and child writes versus an ancestor reader.
        for (reader_roots, writer_roots) in [
            (&parent_roots, &nested_roots),
            (&nested_roots, &parent_roots),
        ] {
            std::fs::write(&source, "revision A\n").unwrap();
            let first = claim_test_source_closure(reader_roots).await;
            let mut reader = Command::new("sh")
                .args([
                    "-c",
                    "cat -- \"$1\"; IFS= read -r resume; cat -- \"$1\"",
                    "snapshot-reader",
                ])
                .arg(&source)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .kill_on_drop(true)
                .spawn()
                .unwrap();
            let mut lines = BufReader::new(reader.stdout.take().unwrap()).lines();
            assert_eq!(
                timeout(Duration::from_secs(5), lines.next_line())
                    .await
                    .unwrap()
                    .unwrap()
                    .as_deref(),
                Some("revision A")
            );
            let mut competing_sync = Box::pin(async {
                let second = claim_test_source_closure(writer_roots).await;
                let status = Command::new("sh")
                    .args(["-c", "printf 'revision B\\n' > \"$1\"", "snapshot-writer"])
                    .arg(&source)
                    .kill_on_drop(true)
                    .status()
                    .await
                    .unwrap();
                assert!(status.success());
                second.release().await.unwrap();
            });
            let early_write = timeout(Duration::from_millis(150), &mut competing_sync).await;
            assert_eq!(
                std::fs::read_to_string(&source).unwrap(),
                "revision A\n",
                "a concurrent closure sync changed bytes while the reader was active"
            );
            assert!(
                early_write.is_err(),
                "overlapping sync acquired before reader exit"
            );
            reader
                .stdin
                .as_mut()
                .unwrap()
                .write_all(b"resume\n")
                .await
                .unwrap();
            assert_eq!(
                timeout(Duration::from_secs(5), lines.next_line())
                    .await
                    .unwrap()
                    .unwrap()
                    .as_deref(),
                Some("revision A")
            );
            assert!(
                timeout(Duration::from_secs(5), reader.wait())
                    .await
                    .unwrap()
                    .unwrap()
                    .success()
            );
            first.release().await.unwrap();
            timeout(Duration::from_secs(10), competing_sync)
                .await
                .unwrap();
            assert_eq!(std::fs::read_to_string(&source).unwrap(), "revision B\n");
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn source_authority_hierarchy_disjoint_siblings_proceed_concurrently() {
        let dir = tempfile::tempdir().unwrap().keep();
        let first_root = dir.join("left");
        let second_root = dir.join("right");
        std::fs::create_dir_all(&first_root).unwrap();
        std::fs::create_dir_all(&second_root).unwrap();
        let mut first = claim_test_source_closure(&[first_root.display().to_string()]).await;
        let second = timeout(
            Duration::from_secs(5),
            claim_test_source_closure(&[second_root.display().to_string()]),
        )
        .await
        .expect("shared ancestors must not serialize disjoint sibling closures");
        let source = second_root.join("source");
        let status = Command::new("sh")
            .args(["-c", "printf 'second writer' > \"$1\"", "sibling-writer"])
            .arg(&source)
            .kill_on_drop(true)
            .status()
            .await
            .unwrap();
        assert!(status.success());
        assert_eq!(std::fs::read_to_string(source).unwrap(), "second writer");
        first.ensure_held().unwrap();
        second.release().await.unwrap();
        first.release().await.unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn source_authority_hierarchy_reversed_multi_root_claims_finish() {
        async fn read_under_closure(roots: &[String], source: &Path) -> Vec<u8> {
            let guard = claim_test_source_closure(roots).await;
            let output = Command::new("cat")
                .arg(source)
                .kill_on_drop(true)
                .output()
                .await
                .unwrap();
            assert!(output.status.success());
            guard.release().await.unwrap();
            output.stdout
        }
        let dir = tempfile::tempdir().unwrap().keep();
        let parent = dir.join("a");
        let nested = parent.join("child");
        let sibling = dir.join("z");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::create_dir_all(&sibling).unwrap();
        let source = nested.join("source");
        std::fs::write(&source, "one coherent revision").unwrap();
        let forward = vec![
            nested.display().to_string(),
            parent.display().to_string(),
            sibling.display().to_string(),
        ];
        let reverse = forward.iter().rev().cloned().collect::<Vec<_>>();
        let (first, second) = timeout(Duration::from_secs(10), async {
            tokio::join!(
                read_under_closure(&forward, &source),
                read_under_closure(&reverse, &source)
            )
        })
        .await
        .expect("reversed overlapping root sets deadlocked");
        assert_eq!(first, b"one coherent revision");
        assert_eq!(second, b"one coherent revision");
    }

    /// How long a test may wait to ACQUIRE a source-authority lock.
    ///
    /// Generous on purpose. What these tests assert is serialization —
    /// "the second claimant does not get in while the first holds it", checked
    /// with a short NEGATIVE wait — and that property does not get weaker as
    /// this budget grows. A tight budget only adds a second, unintended
    /// assertion: "and the machine was not busy". Under a 3000-test parallel
    /// run on a loaded worker that one fails, and a suite that fails only under
    /// load is a suite people learn to ignore (bd-es64k).
    #[cfg(target_os = "linux")]
    const TEST_LOCK_ACQUIRE_BUDGET: Duration = Duration::from_secs(60);

    #[cfg(target_os = "linux")]
    async fn claim_test_source_pair(
        lock: &Path,
        root: &Path,
    ) -> anyhow::Result<RemoteSourceAuthorityLock> {
        let token = uuid::Uuid::new_v4().to_string();
        let ready = format!("ready:{token}");
        let release = format!("release:{token}");
        let script = clean_overlay_source_pair_lock_command(
            lock.to_str().unwrap(),
            root.to_str().unwrap(),
            &token,
            &ready,
            &release,
        );
        let (child, bootstrap) = local_source_lock_transport(WorkerPlatform::Posix, &script);
        let mut guard = finish_source_authority_lock_acquisition(
            child,
            WorkerId::new("local-pair-test"),
            &ready,
            bootstrap.as_deref(),
            TEST_LOCK_ACQUIRE_BUDGET,
        )
        .await?;
        guard.release_request = Some(release);
        Ok(guard)
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn source_pair_serializes_until_retirement_and_explicit_release() {
        let dir = tempfile::tempdir().unwrap().keep();
        let root = dir.join("source with ' quotes");
        let lock = dir.join("pair.lock");
        let first = claim_test_source_pair(&lock, &root).await.unwrap();
        std::fs::write(root.join("fixture"), "first").unwrap();
        let second_lock = lock.clone();
        let second_root = root.clone();
        let mut second =
            tokio::spawn(async move { claim_test_source_pair(&second_lock, &second_root).await });
        assert!(
            timeout(Duration::from_millis(100), &mut second)
                .await
                .is_err()
        );
        assert_eq!(
            std::fs::read_to_string(root.join("fixture")).unwrap(),
            "first"
        );
        // Retire rather than delete so the test preserves its evidence.
        std::fs::rename(&root, dir.join("first-retired")).unwrap();
        first.release().await.unwrap();
        // The serialization assertion is the 100ms negative wait above; this
        // one only says the release eventually lets the waiter through.
        let second = timeout(TEST_LOCK_ACQUIRE_BUDGET, second)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(root.is_dir());
        assert!(!root.join("fixture").exists());
        std::fs::write(root.join("fixture"), "second").unwrap();
        std::fs::rename(&root, dir.join("second-retired")).unwrap();
        second.release().await.unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.join("first-retired/fixture")).unwrap(),
            "first"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("second-retired/fixture")).unwrap(),
            "second"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("pair.lock.owner")).unwrap(),
            "released\n"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn source_pair_holder_loss_never_authorizes_another_writer() {
        let dir = tempfile::tempdir().unwrap().keep();
        let root = dir.join("source");
        let lock = dir.join("pair.lock");
        let first = claim_test_source_pair(&lock, &root).await.unwrap();
        std::fs::write(root.join("fixture"), "owned by interrupted job").unwrap();
        drop(first);
        let error = match claim_test_source_pair(&lock, &root).await {
            Ok(_) => panic!("holder loss must not release a reusable source path"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("unfinished owner"), "{error:#}");
        assert_eq!(
            std::fs::read_to_string(root.join("fixture")).unwrap(),
            "owned by interrupted job"
        );
        assert_ne!(
            std::fs::read_to_string(dir.join("pair.lock.owner")).unwrap(),
            "released\n"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn source_pair_holder_loss_blocks_setup_capability_fallback() {
        use crate::transfer::{RemoteExecutionUnconfirmed, RemoteProcessSetupUnavailable};

        let dir = tempfile::tempdir().unwrap().keep();
        let root = dir.join("source");
        let lock = dir.join("pair.lock");
        let mut owner = claim_test_source_pair(&lock, &root).await.unwrap();
        std::fs::write(root.join("fixture"), "source retained for original owner").unwrap();
        let ownership_path = dir.join("pair.lock.owner");
        let ownership = std::fs::read(&ownership_path).unwrap();
        let pipeline = TransferPipeline::new(
            root.clone(),
            "setup-capability-test".to_owned(),
            "source-pair".to_owned(),
            TransferConfig::default(),
        );
        let result = rch_common::CommandResult {
            exit_code: 125,
            stdout: String::new(),
            stderr: format!("{}\n", pipeline.remote_process_setup_marker()),
            duration_ms: 0,
        };

        // Establish that this exact setup receipt reaches the worker-fallback
        // classification while the real holder and source pair remain owned.
        let setup_error =
            super::super::transfer_orchestration::ensure_remote_process_setup_after_completion(
                &pipeline,
                &result,
                Some(&mut owner),
            )
            .unwrap_err();
        assert!(
            setup_error
                .downcast_ref::<RemoteProcessSetupUnavailable>()
                .is_some()
        );
        assert_eq!(
            classify_remote_pipeline_failure(&setup_error),
            RemotePipelineFailurePolicy::AllowLocalFallback
        );

        // Lose the actual holder after the execution receipt arrived. The
        // production boundary must recheck it before authorizing any fallback.
        owner.child.as_mut().unwrap().kill().await.unwrap();
        let error =
            super::super::transfer_orchestration::ensure_remote_process_setup_after_completion(
                &pipeline,
                &result,
                Some(&mut owner),
            )
            .unwrap_err();
        assert!(error.downcast_ref::<RemoteExecutionUnconfirmed>().is_some());
        assert!(
            error
                .downcast_ref::<RemoteProcessSetupUnavailable>()
                .is_none()
        );
        assert_eq!(
            classify_remote_pipeline_failure(&error),
            RemotePipelineFailurePolicy::FailClosedNoLocalFallback
        );
        drop(owner);

        let claim_error = match claim_test_source_pair(&lock, &root).await {
            Ok(_) => panic!("setup refusal must not release a pair whose ownership was lost"),
            Err(error) => error,
        };
        assert!(
            claim_error.to_string().contains("unfinished owner"),
            "{claim_error:#}"
        );
        assert_eq!(std::fs::read(&ownership_path).unwrap(), ownership);
        assert_eq!(
            std::fs::read_to_string(root.join("fixture")).unwrap(),
            "source retained for original owner"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn source_pair_execution_transport_loss_preserves_a_running_reader() {
        use tokio::io::AsyncWriteExt as _;

        for exit_code in [255, -1] {
            let dir = tempfile::tempdir().unwrap().keep();
            let root = dir.join("source");
            let lock = dir.join("pair.lock");
            let mut owner = claim_test_source_pair(&lock, &root).await.unwrap();
            std::fs::write(root.join("fixture"), "original source").unwrap();
            // A separate execution process can survive a transport failure.
            // Hold it until another claimant has attempted to reuse the pair.
            let mut reader = Command::new("sh")
                .current_dir(&root)
                .args(["-c", "IFS= read -r signal; cat fixture"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .kill_on_drop(true)
                .spawn()
                .unwrap();
            owner.ensure_execution_finished(0).unwrap();
            owner.ensure_execution_finished(101).unwrap();
            assert!(owner.ensure_execution_finished(exit_code).is_err());
            drop(owner);
            assert!(claim_test_source_pair(&lock, &root).await.is_err());
            let mut stdin = reader.stdin.take().unwrap();
            stdin.write_all(b"read\n").await.unwrap();
            drop(stdin);
            let output = timeout(Duration::from_secs(5), reader.wait_with_output())
                .await
                .unwrap()
                .unwrap();
            assert!(output.status.success());
            assert_eq!(output.stdout, b"original source");
            assert!(root.is_dir());
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn source_pair_rejects_empty_or_malformed_ownership_state() {
        let dir = tempfile::tempdir().unwrap().keep();
        for (index, contents) in ["", "release", "released\noccupied", "unknown"]
            .iter()
            .enumerate()
        {
            let lock = dir.join(format!("pair-{index}.lock"));
            let root = dir.join(format!("source-{index}"));
            std::fs::write(dir.join(format!("pair-{index}.lock.owner")), contents).unwrap();
            assert!(claim_test_source_pair(&lock, &root).await.is_err());
            assert!(!root.exists());
        }
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

        let command = build_remote_source_authority_lock_cmd(
            "/tmp",
            &exclusive_source_locks(&[lock_path.to_string()]),
            marker,
        )
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
    fn local_source_lock_transport(
        platform: WorkerPlatform,
        script: &str,
    ) -> (tokio::process::Child, Option<String>) {
        let (remote_arg, bootstrap) = source_authority_lock_transport(platform, script);
        let expected = if platform.is_windows() {
            "sh -s".to_owned()
        } else {
            build_remote_shell_command(platform, "exec sh -s")
        };
        assert_eq!(remote_arg, expected);
        assert_eq!(
            bootstrap.as_deref(),
            Some(format!("{{\n{script}\n}}\n").as_str())
        );
        // Actual POSIX reader/flock processes exercise the production stdin
        // and guard path. This does not emulate or claim native Windows SSH.
        let child = Command::new("sh")
            .args(["-c", &format!("exec {remote_arg}")])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn source lock transport");
        (child, bootstrap)
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn windows_source_lock_bootstrap_preserves_exclusion_eof_and_drop_release() {
        let _guard = test_guard!();
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_str().unwrap();
        let locks = vec![
            dir.path()
                .join("quote' %!& lock")
                .to_string_lossy()
                .into_owned(),
        ];
        let marker = "READY ' \" % ! & $()";
        let script =
            build_remote_source_authority_lock_cmd(root, &exclusive_source_locks(&locks), marker)
                .unwrap();
        let (child, bootstrap) = local_source_lock_transport(WorkerPlatform::Windows, &script);
        let mut first = finish_source_authority_lock_acquisition(
            child,
            WorkerId::new("windows-reader"),
            marker,
            bootstrap.as_deref(),
            TEST_LOCK_ACQUIRE_BUDGET,
        )
        .await
        .unwrap();
        first.ensure_held().unwrap();

        let (child, bootstrap) = local_source_lock_transport(WorkerPlatform::Posix, &script);
        let mut competing = Box::pin(finish_source_authority_lock_acquisition(
            child,
            WorkerId::new("posix-reader"),
            marker,
            bootstrap.as_deref(),
            TEST_LOCK_ACQUIRE_BUDGET,
        ));
        assert!(
            timeout(Duration::from_millis(100), &mut competing)
                .await
                .is_err()
        );
        first.ensure_held().unwrap();
        first.release().await.unwrap();
        let mut second = competing.await.unwrap();
        second.ensure_held().unwrap();
        drop(second);

        // Guard cancellation must close the inherited pipe as well: a fresh
        // Windows bootstrap acquires the same lock after the dropped owner.
        let (child, bootstrap) = local_source_lock_transport(WorkerPlatform::Windows, &script);
        let mut third = finish_source_authority_lock_acquisition(
            child,
            WorkerId::new("windows-after-drop"),
            marker,
            bootstrap.as_deref(),
            TEST_LOCK_ACQUIRE_BUDGET,
        )
        .await
        .unwrap();
        third.ensure_held().unwrap();
        third.release().await.unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn windows_source_lock_bootstrap_failures_keep_stderr_and_reap_child() {
        let _guard = test_guard!();
        for (script, expected) in [
            (
                "printf 'lock refused\\n' >&2; exit 37",
                "exited before acquisition",
            ),
            (
                "printf 'lock refused\\n' >&2; printf 'WRONG\\n'; exec cat",
                "invalid ready marker",
            ),
        ] {
            let (child, bootstrap) = local_source_lock_transport(WorkerPlatform::Windows, script);
            let pid = child.id().unwrap();
            let result = finish_source_authority_lock_acquisition(
                child,
                WorkerId::new("windows-failure"),
                "READY",
                bootstrap.as_deref(),
                Duration::from_secs(3),
            )
            .await;
            let error = match result {
                Ok(_) => panic!("invalid holder must fail acquisition"),
                Err(error) => error.to_string(),
            };
            assert!(error.contains(expected), "{error}");
            assert!(error.contains("lock refused"), "{error}");
            assert!(
                !Path::new(&format!("/proc/{pid}")).exists(),
                "owned child must be reaped"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn source_lock_bootstrap_and_readiness_share_deadline_and_reap_timeout() {
        let _guard = test_guard!();
        // A write larger than the pipe cannot finish until the first delay;
        // readiness follows a second delay. Each is below the one deadline,
        // but their sum exceeds it, catching a reset between write and read.
        let script = format!(
            "{}\nsleep 0.15; printf 'READY\\n'; exec cat",
            "#pad\n".repeat(18 * 1024)
        );
        let (_, bootstrap) = source_authority_lock_transport(WorkerPlatform::Windows, &script);
        let child = Command::new("sh")
            .args(["-c", "sleep 0.15; exec sh -s"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let pid = child.id().unwrap();
        let result = finish_source_authority_lock_acquisition(
            child,
            WorkerId::new("windows-deadline"),
            "READY",
            bootstrap.as_deref(),
            Duration::from_millis(250),
        )
        .await;
        let error = match result {
            Ok(_) => panic!("combined write/readiness deadline must not reset"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("timed out waiting"), "{error}");
        assert!(!Path::new(&format!("/proc/{pid}")).exists());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn source_lock_bootstrap_write_is_bounded_when_child_never_reads() {
        let _guard = test_guard!();
        let child = Command::new("sh")
            .args(["-c", "exec sleep 60"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let pid = child.id().unwrap();
        let bootstrap = "x".repeat(1024 * 1024);
        let result = finish_source_authority_lock_acquisition(
            child,
            WorkerId::new("blocked-writer"),
            "READY",
            Some(&bootstrap),
            Duration::from_millis(100),
        )
        .await;
        let error = match result {
            Ok(_) => panic!("blocked bootstrap writer must time out"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("timed out waiting"), "{error}");
        assert!(!Path::new(&format!("/proc/{pid}")).exists());

        let child = Command::new("sh")
            .args(["-c", "exec sleep 60"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let pid = child.id().unwrap();
        let mut acquisition = Box::pin(finish_source_authority_lock_acquisition(
            child,
            WorkerId::new("cancelled-writer"),
            "READY",
            Some(&bootstrap),
            Duration::from_secs(60),
        ));
        // Poll the real acquisition while its large write and readiness are
        // pending. Cancelling an unpolled future would miss the drain/guard
        // ownership established inside the acquisition function.
        assert!(
            timeout(Duration::from_millis(50), &mut acquisition)
                .await
                .is_err()
        );
        assert!(Path::new(&format!("/proc/{pid}")).exists());
        drop(acquisition);
        timeout(Duration::from_secs(2), async {
            while Path::new(&format!("/proc/{pid}")).exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("cancelled acquisition must kill and reap its owned child");
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
    fn clean_overlay_staging_maps_worker_paths_without_changing_controller_policy() {
        let controller = PathTopologyPolicy::default();
        let base = "/Users/jemanuel/.cache/rch-release";
        let roots = vec![PathBuf::from(format!("{base}/asupersync/job-1"))];
        let staged = remote_preflight_topology_policy(&controller, true, base, &roots)
            .expect("Mac staging path is independent of Linux controller source path");
        assert_eq!(staged.canonical_root(), Path::new(base));
        assert_eq!(staged.alias_root(), staged.canonical_root());
        assert_eq!(controller.canonical_root(), Path::new("/data/projects"));
        assert_eq!(controller.alias_root(), Path::new("/dp"));

        let ordinary = remote_preflight_topology_policy(
            &controller,
            false,
            base,
            &[PathBuf::from("/data/projects/asupersync")],
        )
        .expect("ordinary source mirrors retain the controller topology");
        assert_eq!(ordinary.canonical_root(), controller.canonical_root());
        assert_eq!(ordinary.alias_root(), controller.alias_root());
    }

    #[test]
    fn clean_overlay_staging_refuses_every_destination_outside_the_exact_base() {
        let controller = PathTopologyPolicy::default();
        let base = "/Users/jemanuel/.cache/rch-release";
        let valid = PathBuf::from(format!("{base}/asupersync/job-1"));
        for invalid in [
            base.to_string(),
            format!("{base}-peer/asupersync/job-1"),
            format!("{base}/../peer/job-1"),
            format!("{base}/asupersync/../../peer"),
            format!("{base}/./asupersync/job-1"),
            format!("{base}/asupersync/evil\npath"),
            format!("{base}/asupersync\\peer"),
            "/data/projects/asupersync".to_string(),
            "asupersync/job-1".to_string(),
        ] {
            let roots = vec![valid.clone(), PathBuf::from(&invalid)];
            assert!(
                remote_preflight_topology_policy(&controller, true, base, &roots).is_err(),
                "a valid first root must not hide invalid destination {invalid:?}"
            );
        }
        assert!(remote_preflight_topology_policy(&controller, true, base, &[]).is_err());
        for invalid_base in [
            "/",
            "/tmp",
            "relative/base",
            "/tmp/rch/../peer",
            "/tmp/rch\n",
        ] {
            assert!(
                remote_preflight_topology_policy(
                    &controller,
                    true,
                    invalid_base,
                    std::slice::from_ref(&valid),
                )
                .is_err(),
                "invalid staging base {invalid_base:?} must refuse before any remote command"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn clean_overlay_staging_preflight_creates_only_its_base_without_an_alias() {
        let _guard = test_guard!();
        let raw = tempfile::tempdir().expect("owned topology fixture");
        let fixture = raw.path().canonicalize().expect("physical fixture path");
        let controller_root = fixture.join("controller-projects");
        let controller_alias = fixture.join("controller-alias");
        // Both controller paths are intentionally unusable as worker topology.
        // The old preflight would refuse this regular-file canonical root.
        std::fs::write(&controller_root, b"controller source must stay untouched")
            .expect("controller sentinel");
        std::fs::write(&controller_alias, b"peer alias must stay untouched")
            .expect("peer alias sentinel");
        let controller = PathTopologyPolicy::new(controller_root.clone(), controller_alias.clone());
        let staging_base = fixture.join("worker staging");
        let source_root = staging_base.join("asupersync/job-1");
        let staged = remote_preflight_topology_policy(
            &controller,
            true,
            staging_base.to_str().expect("UTF-8 fixture path"),
            std::slice::from_ref(&source_root),
        )
        .expect("valid isolated staging topology");
        let command = build_worker_projects_topology_cmd(&staged);
        for _ in 0..2 {
            let output = std::process::Command::new("sh")
                .args(["-c", &command])
                .output()
                .expect("execute actual topology shell command");
            assert!(
                output.status.success(),
                "staging preflight failed: status={:?}, stdout={}, stderr={}",
                output.status.code(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("RCH_TOPOLOGY_OK"));
            assert!(staging_base.is_dir());
            assert!(
                !staging_base.is_symlink(),
                "alias==canonical stays a directory"
            );
            assert!(
                !source_root.exists(),
                "preflight only prepares the staging base"
            );
            assert_eq!(
                std::fs::read(&controller_root).expect("controller sentinel survives"),
                b"controller source must stay untouched"
            );
            assert_eq!(
                std::fs::read(&controller_alias).expect("peer alias sentinel survives"),
                b"peer alias must stay untouched"
            );
            assert_eq!(
                std::fs::read_dir(&fixture)
                    .expect("fixture entries")
                    .count(),
                3,
                "preflight must not create another alias or touch a peer tree"
            );
        }
    }

    #[test]
    fn test_build_remote_shell_command_wraps_and_escapes_script() {
        let _guard = test_guard!();
        let command = "missing=0; if [ \"$missing\" -ne 0 ]; then echo 'bad'; fi";

        let wrapped = build_remote_shell_command(WorkerPlatform::Posix, command);

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
    fn test_windows_stdin_reader_avoids_login_but_scripts_remain_quoted() {
        let _guard = test_guard!();
        let script = "printf '%s\\n' 'C:/rch/a b/Cargo.toml'; exit 43";

        assert_eq!(
            build_remote_shell_command(WorkerPlatform::Windows, "sh -s"),
            "sh -s"
        );
        assert_eq!(
            build_remote_shell_command(WorkerPlatform::Windows, script),
            format!("sh -lc {}", shell_escape::escape(script.into()))
        );

        assert_eq!(
            build_remote_shell_command(WorkerPlatform::Posix, "sh -s"),
            "sh -lc 'sh -s'"
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
            command.contains("for r in /data/projects /data/projects/franken_node"),
            "every dispatch closure root binds into the sweep loop: {command}"
        );
        let spaced = build_worker_ownership_repair_cmd(
            &[PathBuf::from("/data/projects with space")],
            "deploy u",
        );
        assert!(
            spaced.contains("for r in '/data/projects with space'")
                && spaced.contains("u='deploy u'"),
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

    #[cfg(unix)]
    async fn source_lock_pending_release_fixture() -> (
        RemoteSourceAuthorityLock,
        Vec<tokio::io::DuplexStream>,
        Vec<tokio::sync::oneshot::Receiver<()>>,
    ) {
        struct ReaderDropped(Option<tokio::sync::oneshot::Sender<()>>);
        impl Drop for ReaderDropped {
            fn drop(&mut self) {
                if let Some(sender) = self.0.take() {
                    let _ = sender.send(());
                }
            }
        }

        let mut child = Command::new("/bin/sh")
            .args(["-c", "exit 0"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        // Establish the exact regression boundary: SSH already exited, but
        // both reader pipes remain open as if inherited by descendants.
        assert!(child.wait().await.unwrap().success());
        let mut writers = Vec::new();
        let mut notices = Vec::new();
        let mut tasks = Vec::new();
        for _ in 0..2 {
            let (reader, writer) = tokio::io::duplex(16);
            let (sender, notice) = tokio::sync::oneshot::channel();
            let dropped = ReaderDropped(Some(sender));
            tasks.push(tokio::spawn(async move {
                let _dropped = dropped;
                crate::transfer::read_bounded_output_stream(reader, MAX_SOURCE_LOCK_OUTPUT_BYTES)
                    .await
            }));
            writers.push(writer);
            notices.push(notice);
        }
        let stderr_drain = tasks.pop();
        let stdout_drain = tasks.pop();
        (
            RemoteSourceAuthorityLock {
                worker_id: WorkerId::new("pending-lock-release"),
                child: Some(child),
                stdin: None,
                stdout_drain,
                stderr_drain,
                release_request: None,
            },
            writers,
            notices,
        )
    }

    #[cfg(unix)]
    async fn source_lock_assert_readers_dropped(notices: Vec<tokio::sync::oneshot::Receiver<()>>) {
        for notice in notices {
            timeout(Duration::from_secs(1), notice)
                .await
                .expect("release detached an output reader")
                .expect("reader drop notification lost");
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn source_lock_lifecycle_release_deadline_includes_eof_after_child_exit() {
        let (guard, _writers, notices) = source_lock_pending_release_fixture().await;
        let error = timeout(
            Duration::from_secs(1),
            guard.release_with_timeout(Duration::from_millis(40)),
        )
        .await
        .expect("release ignored its deadline after child exit")
        .unwrap_err();
        assert!(
            error.to_string().contains("timed out releasing"),
            "{error:#}"
        );
        source_lock_assert_readers_dropped(notices).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn source_lock_lifecycle_release_surfaces_stderr_error_without_waiting_for_stdout() {
        let (mut guard, _writers, notices) = source_lock_pending_release_fixture().await;
        guard.stderr_drain.take().unwrap().abort();
        guard.stderr_drain = Some(tokio::spawn(async {
            Err(std::io::Error::other("injected lock stderr failure"))
        }));
        let error = timeout(
            Duration::from_secs(1),
            guard.release_with_timeout(Duration::from_secs(60)),
        )
        .await
        .expect("stderr failure was hidden behind a pending stdout reader")
        .unwrap_err();
        assert!(error.to_string().contains("injected lock stderr failure"));
        source_lock_assert_readers_dropped(notices).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn source_lock_lifecycle_caller_cancellation_aborts_both_release_readers() {
        let (guard, _writers, notices) = source_lock_pending_release_fixture().await;
        let mut release = Box::pin(guard.release_with_timeout(Duration::from_secs(60)));
        assert!(
            timeout(Duration::from_millis(40), &mut release)
                .await
                .is_err()
        );
        drop(release);
        source_lock_assert_readers_dropped(notices).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn source_lock_lifecycle_release_requires_complete_ack_and_successful_exit() {
        for (reply, expected) in [
            ("printf '%s\\n' \"$request\"", true),
            ("printf '%s' \"$request\"", false),
            ("printf 'WRONG\\n'", false),
            ("printf '%s\\n' \"$request\" \"$request\"", false),
            ("printf '%s\\n' \"$request\"; exit 37", false),
        ] {
            let script = format!("printf 'READY\\n'; IFS= read -r request; {reply}");
            let child = Command::new("/bin/sh")
                .args(["-c", &script])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true)
                .spawn()
                .unwrap();
            let mut guard = finish_source_authority_lock_acquisition(
                child,
                WorkerId::new("lock-ack-fixture"),
                "READY",
                None,
                Duration::from_secs(2),
            )
            .await
            .unwrap();
            guard.release_request = Some("RELEASE".to_owned());
            let result = guard.release_with_timeout(Duration::from_secs(2)).await;
            assert_eq!(result.is_ok(), expected, "{reply}: {result:?}");
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn source_lock_lifecycle_readiness_refuses_truncated_padded_and_oversized_frames() {
        for script in [
            "printf READY".to_owned(),
            "printf 'READY \\n'; exec cat".to_owned(),
            format!(
                "printf %s {}; exec cat",
                "x".repeat(MAX_SOURCE_LOCK_READY_BYTES + 1)
            ),
        ] {
            let child = Command::new("/bin/sh")
                .args(["-c", &script])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true)
                .spawn()
                .unwrap();
            let result = timeout(
                Duration::from_secs(2),
                finish_source_authority_lock_acquisition(
                    child,
                    WorkerId::new("invalid-lock-ready"),
                    "READY",
                    None,
                    Duration::from_secs(60),
                ),
            )
            .await
            .expect("invalid readiness waited for EOF or the acquisition timeout");
            assert!(
                result.is_err(),
                "invalid readiness authorized a source writer"
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn source_lock_lifecycle_stdout_overflow_cannot_certify_release() {
        let script = format!(
            "printf 'READY\\n'; IFS= read -r request; head -c {} /dev/zero; exit 0",
            MAX_SOURCE_LOCK_OUTPUT_BYTES + 1
        );
        let child = Command::new("/bin/sh")
            .args(["-c", &script])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut guard = finish_source_authority_lock_acquisition(
            child,
            WorkerId::new("oversized-lock-output"),
            "READY",
            None,
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        guard.release_request = Some("RELEASE".to_owned());
        let error = guard
            .release_with_timeout(Duration::from_secs(2))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("exceeded"), "{error:#}");
    }

    #[test]
    fn source_lock_scaling_rejects_ambiguous_path_records() {
        assert!(build_remote_source_authority_lock_cmd("/tmp", &[], "READY").is_err());
        for path in ["relative", "/tmp/a\n/tmp/b", "/tmp/a\r", "/tmp/a\0b"] {
            let paths = vec!["/tmp/valid".to_owned(), path.to_owned()];
            assert!(
                build_remote_source_authority_lock_cmd(
                    "/tmp",
                    &exclusive_source_locks(&paths),
                    "READY"
                )
                .is_err()
            );
        }
        let duplicate = vec!["/tmp/same".to_owned(); 2];
        assert!(
            build_remote_source_authority_lock_cmd(
                "/tmp",
                &exclusive_source_locks(&duplicate),
                "READY"
            )
            .is_err()
        );
        for marker in ["", "READY\nFORGED", "READY\r", "READY\0"] {
            assert!(
                build_remote_source_authority_lock_cmd(
                    "/tmp",
                    &exclusive_source_locks(&["/tmp/one".into()]),
                    marker
                )
                .is_err()
            );
        }
    }

    #[cfg(target_os = "linux")]
    async fn source_lock_scaling_is_held(path: &str) -> bool {
        let output = timeout(
            Duration::from_secs(5),
            Command::new("flock")
                .args(["-n", "-x", "--", path, "sh", "-c", "exit 0"])
                .stdin(Stdio::null())
                .kill_on_drop(true)
                .output(),
        )
        .await
        .expect("independent nonblocking lock probe hung")
        .unwrap();
        assert!(matches!(output.status.code(), Some(0 | 1)), "{output:?}");
        output.status.code() == Some(1)
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn source_lock_scaling_streams_548_roots_and_preserves_exclusion() {
        let dir = tempfile::tempdir().unwrap().keep();
        let lock_dir = dir.join("d".repeat(100));
        std::fs::create_dir_all(&lock_dir).unwrap();
        let mut locks = (0..548)
            .map(|index| {
                lock_dir
                    .join(format!("{index:04}-{}.lock", "k".repeat(180)))
                    .display()
                    .to_string()
            })
            .collect::<Vec<_>>();
        locks[547] = lock_dir
            .join(format!("quote' $cash `literal`; {}", "z".repeat(170)))
            .display()
            .to_string();
        let marker = "READY ' \" $() ; `literal`";
        let script = build_remote_source_authority_lock_cmd(
            lock_dir.to_str().unwrap(),
            &exclusive_source_locks(&locks),
            marker,
        )
        .unwrap();
        assert!(script.len() > 128 * 1024);
        for platform in [WorkerPlatform::Posix, WorkerPlatform::Windows] {
            let (child, bootstrap) = local_source_lock_transport(platform, &script);
            let pid = child.id().unwrap();
            let mut first = finish_source_authority_lock_acquisition(
                child,
                WorkerId::new("large-closure"),
                marker,
                bootstrap.as_deref(),
                Duration::from_secs(20),
            )
            .await
            .unwrap();
            first.ensure_held().unwrap();
            // No nesting of live flock parents: the original process becomes
            // the final stdin holder. A shell may retain one heredoc helper.
            timeout(Duration::from_secs(3), async {
                loop {
                    if std::fs::read_link(format!("/proc/{pid}/exe"))
                        .ok()
                        .and_then(|path| path.file_name().map(|name| name == "cat"))
                        == Some(true)
                    {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("lock acquisition retained a flock process chain");
            for index in [0, 274, 547] {
                assert!(source_lock_scaling_is_held(&locks[index]).await);
            }
            assert!(
                !source_lock_scaling_is_held(dir.join("disjoint.lock").to_str().unwrap()).await
            );
            let overlap = build_remote_source_authority_lock_cmd(
                lock_dir.to_str().unwrap(),
                &exclusive_source_locks(std::slice::from_ref(&locks[547])),
                "SECOND",
            )
            .unwrap();
            let (child, bootstrap) = local_source_lock_transport(platform, &overlap);
            let mut second = Box::pin(finish_source_authority_lock_acquisition(
                child,
                WorkerId::new("overlapping-closure"),
                "SECOND",
                bootstrap.as_deref(),
                Duration::from_secs(20),
            ));
            assert!(
                timeout(Duration::from_millis(100), &mut second)
                    .await
                    .is_err()
            );
            first.release().await.unwrap();
            let second = second.await.unwrap();
            second.release().await.unwrap();
            for index in [0, 274, 547] {
                assert!(!source_lock_scaling_is_held(&locks[index]).await);
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn source_lock_scaling_descriptor_exhaustion_never_publishes_readiness() {
        let dir = tempfile::tempdir().unwrap().keep();
        let locks = (0..32)
            .map(|index| dir.join(format!("{index}.lock")).display().to_string())
            .collect::<Vec<_>>();
        let script = format!(
            "ulimit -n 16\n{}",
            build_remote_source_authority_lock_cmd(
                dir.to_str().unwrap(),
                &exclusive_source_locks(&locks),
                "READY"
            )
            .unwrap()
        );
        let (child, bootstrap) = local_source_lock_transport(WorkerPlatform::Posix, &script);
        let result = finish_source_authority_lock_acquisition(
            child,
            WorkerId::new("limited-descriptors"),
            "READY",
            bootstrap.as_deref(),
            Duration::from_secs(5),
        )
        .await;
        assert!(
            result.is_err(),
            "partial lock set must never authorize a source writer"
        );
        for path in &locks {
            assert!(!source_lock_scaling_is_held(path).await);
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn source_lock_scaling_cancelled_acquisition_releases_its_prefix() {
        let dir = tempfile::tempdir().unwrap().keep();
        let a = dir.join("a.lock").display().to_string();
        let b = dir.join("b.lock").display().to_string();
        let first_script = build_remote_source_authority_lock_cmd(
            dir.to_str().unwrap(),
            &exclusive_source_locks(std::slice::from_ref(&b)),
            "FIRST",
        )
        .unwrap();
        let (child, bootstrap) = local_source_lock_transport(WorkerPlatform::Posix, &first_script);
        let first = finish_source_authority_lock_acquisition(
            child,
            WorkerId::new("blocking-owner"),
            "FIRST",
            bootstrap.as_deref(),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        let script = build_remote_source_authority_lock_cmd(
            dir.to_str().unwrap(),
            &exclusive_source_locks(&[a.clone(), b.clone()]),
            "SECOND",
        )
        .unwrap();
        let (child, bootstrap) = local_source_lock_transport(WorkerPlatform::Posix, &script);
        let mut second = Box::pin(finish_source_authority_lock_acquisition(
            child,
            WorkerId::new("partial-owner"),
            "SECOND",
            bootstrap.as_deref(),
            Duration::from_secs(20),
        ));
        timeout(Duration::from_secs(5), async {
            loop {
                assert!(
                    timeout(Duration::from_millis(50), &mut second)
                        .await
                        .is_err()
                );
                if source_lock_scaling_is_held(&a).await {
                    break;
                }
            }
        })
        .await
        .unwrap();
        drop(second);
        timeout(Duration::from_secs(5), async {
            while source_lock_scaling_is_held(&a).await {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("aborted acquisition leaked its partial lock set");
        assert!(source_lock_scaling_is_held(&b).await);
        first.release().await.unwrap();
        assert!(!source_lock_scaling_is_held(&b).await);
    }
}
