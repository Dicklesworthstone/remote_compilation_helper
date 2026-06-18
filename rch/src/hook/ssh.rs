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

pub(super) fn should_skip_remote_preflight(worker: &WorkerConfig) -> bool {
    mock::is_mock_enabled() || mock::is_mock_worker(worker)
}

pub(super) async fn run_offload_ssh_command(
    worker: &WorkerConfig,
    remote_cmd: &str,
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
    use tokio::io::AsyncReadExt as _;

    let mut child = cmd
        .spawn()
        .with_context(|| format!("Failed to spawn ssh to {}", destination))?;

    // Drain stdout/stderr concurrently with the wait so that even verbose
    // remote output never deadlocks the child on a full pipe buffer.
    let mut stdout_pipe = child.stdout.take();
    let mut stderr_pipe = child.stderr.take();
    let collect = async {
        let stdout_fut = async {
            let mut buf = Vec::new();
            if let Some(p) = stdout_pipe.as_mut() {
                p.read_to_end(&mut buf).await?;
            }
            Ok::<_, std::io::Error>(buf)
        };
        let stderr_fut = async {
            let mut buf = Vec::new();
            if let Some(p) = stderr_pipe.as_mut() {
                p.read_to_end(&mut buf).await?;
            }
            Ok::<_, std::io::Error>(buf)
        };
        let (stdout_bytes, stderr_bytes) = tokio::try_join!(stdout_fut, stderr_fut)?;
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
           printf 'RCH_TOPOLOGY_ERR_ALIAS_NOT_SYMLINK:path=%s\\n' {alias} >&2; return 42; \
         else \
           create_stderr=$(ln -s -- {canonical} {alias} 2>&1) && return 0; \
           if [ -L {alias} ]; then ensure_alias_symlink; return $?; fi; \
           if [ -e {alias} ]; then printf 'RCH_TOPOLOGY_ERR_ALIAS_NOT_SYMLINK:path=%s\\n' {alias} >&2; return 42; fi; \
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

pub(super) async fn ensure_worker_projects_topology(
    worker: &WorkerConfig,
    reporter: &HookReporter,
    topology_policy: &PathTopologyPolicy,
) -> anyhow::Result<()> {
    if should_skip_remote_preflight(worker) {
        reporter.verbose("[RCH] topology preflight skipped in mock mode");
        return Ok(());
    }

    let canonical_display = topology_policy.canonical_root().display().to_string();
    let alias_display = topology_policy.alias_root().display().to_string();
    let topology_cmd = build_worker_projects_topology_cmd(topology_policy);

    let output = run_offload_ssh_command(worker, &topology_cmd, Duration::from_secs(20)).await?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        anyhow::bail!(
            "remote topology preflight failed on {} (status {:?}): stdout='{}' stderr='{}'",
            worker.id,
            output.status.code(),
            stdout,
            stderr
        );
    }
    reporter.verbose(&format!(
        "[RCH] topology preflight ok on {} ({} -> {} enforced)",
        worker.id, alias_display, canonical_display
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rch_common::test_guard;

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
}
