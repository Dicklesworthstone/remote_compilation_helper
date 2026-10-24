//! Resource-bounded compiler identity probes for the shared facts warm pool.
//!
//! Both queries spend ONE wall-clock and stdout/stderr byte budget. A timeout,
//! quota failure, malformed output or failed process is never toolchain evidence.
//! Reuse the existing managed process group and bounded drains: no timer thread
//! keeps a PID, no direct-child-only timeout leaves inherited pipe writers, and
//! no probe-specific process supervisor is introduced. This is blocking work
//! owned by the existing facts warmer, never an async reactor or compile lease.
//!
//! Containment is the existing POSIX group contract, not a sandbox. Descendants
//! that deliberately leave that group require a stronger isolation profile.
//! Filesystem enumeration and hashing retain their separate observation policy.

use rabs_asupersync::process_groups::ManagedProcessGroup;
use rabs_asupersync::region_tree::Attribution;
use rabs_asupersync::stream_drain::DrainLimits;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const PROBE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_PROBE_BYTES: u64 = 64 * 1024;

/// Raw outputs: the owning observer retains its existing trimming, sysroot
/// comparison and canonical hashing. No partial pair is returned on failure.
pub(super) fn identity(
    compiler: &Path,
    env: &[(String, String)],
) -> Result<(String, String), String> {
    let mut probes = ProbeSession::new(compiler, env, PROBE_TIMEOUT, MAX_PROBE_BYTES)?;
    let version = probes.run(&["-vV"])?;
    let sysroot = probes.run(&["--print", "sysroot"])?;
    Ok((version, sysroot))
}

struct ProbeSession<'a> {
    compiler: &'a Path,
    env: &'a [(String, String)],
    deadline: Instant,
    remaining_bytes: u64,
    scratch: tempfile::TempDir,
}

impl<'a> ProbeSession<'a> {
    fn new(
        compiler: &'a Path,
        env: &'a [(String, String)],
        timeout: Duration,
        maximum: u64,
    ) -> Result<Self, String> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or("toolchain probe deadline overflow")?;
        let scratch = tempfile::Builder::new()
            .prefix("rabs-toolchain-probe-")
            .tempdir()
            .map_err(|error| format!("toolchain probe scratch: {error}"))?;
        Ok(Self {
            compiler,
            env,
            deadline,
            remaining_bytes: maximum,
            scratch,
        })
    }

    fn run(&mut self, args: &[&str]) -> Result<String, String> {
        let timeout = || format!("probe {args:?}: toolchain probe deadline expired");
        if Instant::now() >= self.deadline {
            return Err(timeout());
        }
        if self.remaining_bytes == 0 {
            return Err(format!(
                "probe {args:?}: toolchain probe output budget exhausted"
            ));
        }
        let limits = DrainLimits {
            // The aggregate cap includes BOTH lanes. A successful capture
            // cannot spill: either lane fits entirely in this resident bound.
            resident_bound: usize::try_from(self.remaining_bytes)
                .map_err(|error| format!("probe byte bound: {error}"))?,
            spill_dir: self.scratch.path().to_path_buf(),
        };
        let mut command = Command::new(self.compiler);
        command
            .args(args)
            .env_clear()
            .envs(self.env.iter().map(|(name, value)| (name, value)))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // Preparation has no admitted action/attempt identity to invent.
        let group = ManagedProcessGroup::spawn_command(command, Attribution::default())
            .map_err(|error| format!("probe {args:?}: {error}"))?;
        let deadline = self.deadline;
        let mut expired = false;
        let output = group.wait_with_bounded_drain_budget(&limits, self.remaining_bytes, || {
            expired |= Instant::now() >= deadline;
            expired
        });
        // A TERM handler may exit zero, and a child may exit between polls.
        // Neither may turn an expired query into successful identity evidence.
        // Cleanup and both lane joins have already returned at this point.
        if expired || Instant::now() >= deadline {
            return Err(timeout());
        }
        let output = output.map_err(|error| format!("probe {args:?}: {error}"))?;
        if !output.status.success() {
            return Err(format!("probe {args:?} exited {}", output.status));
        }
        if output.residual_group_members != 0 {
            return Err(format!("probe {args:?}: process group cleanup incomplete"));
        }
        if output.stdout.spill().is_some() || output.stderr.spill().is_some() {
            return Err(format!("probe {args:?}: unexpected output spill"));
        }
        let consumed = output
            .stdout
            .total_bytes()
            .checked_add(output.stderr.total_bytes())
            .ok_or("toolchain probe output count overflow")?;
        self.remaining_bytes = self
            .remaining_bytes
            .checked_sub(consumed)
            .ok_or("toolchain probe output exceeded shared budget")?;
        String::from_utf8(output.stdout.resident().to_vec())
            .map_err(|_| format!("probe {args:?}: non-UTF-8"))
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    // These are real process/pipe exercises with scripted identity queries,
    // not claims about real rustc compilation, caching or fleet performance.
    fn fixture(version: &str, sysroot: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = crate::test_util::private_tempdir();
        let compiler = dir.path().join("rustc");
        std::fs::write(
            &compiler,
            format!(
                "#!/bin/sh\n\
                 if [ -n \"${{PROBE_LOG:-}}\" ]; then printf '%s\\n' \"$*\" >> \"$PROBE_LOG\"; fi\n\
                 case \"$*\" in\n\
                 '-vV') {version};;\n\
                 '--print sysroot') {sysroot};;\n\
                 *) exit 64;;\n\
                 esac\n",
            ),
        )
        .unwrap();
        std::fs::set_permissions(&compiler, std::fs::Permissions::from_mode(0o700)).unwrap();
        (dir, compiler)
    }

    fn logged_env(dir: &Path) -> Vec<(String, String)> {
        vec![(
            "PROBE_LOG".into(),
            dir.join("queries").to_str().unwrap().to_owned(),
        )]
    }

    fn assert_not_running(pid_file: &Path) {
        let pid = std::fs::read_to_string(pid_file).unwrap();
        let pid: u32 = pid.trim().parse().unwrap();
        match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(stat) => {
                // An orphan zombie has no executable work or open pipes; the
                // supervisor cannot reap another parent's child with wait().
                let state = stat.rsplit_once(')').unwrap().1.trim_start();
                assert!(state.starts_with('Z'), "probe process remains live: {stat}");
            }
            Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::NotFound),
        }
    }

    #[test]
    fn identity_preserves_query_bytes_environment_and_null_stdin() {
        let (dir, compiler) = fixture(
            "if read -r input; then exit 19; fi; printf '%s\\n' \"$LABEL\"; printf diagnostic >&2",
            "printf '/a toolchain/root\\n'",
        );
        let mut env = logged_env(dir.path());
        env.push(("LABEL".into(), "rustc fixture\nhost: test-host".into()));
        let (version, sysroot) = identity(&compiler, &env).unwrap();
        assert_eq!(version, "rustc fixture\nhost: test-host\n");
        assert_eq!(sysroot, "/a toolchain/root\n");
        assert_eq!(
            std::fs::read_to_string(dir.path().join("queries")).unwrap(),
            "-vV\n--print sysroot\n"
        );
    }

    #[test]
    fn both_queries_and_both_streams_spend_one_output_budget() {
        let (_dir, compiler) = fixture("printf abc; printf def >&2", "printf ghij");
        let mut exact = ProbeSession::new(&compiler, &[], Duration::from_secs(5), 10).unwrap();
        assert_eq!(exact.run(&["-vV"]).unwrap(), "abc");
        assert_eq!(exact.remaining_bytes, 4);
        assert_eq!(exact.run(&["--print", "sysroot"]).unwrap(), "ghij");
        assert_eq!(exact.remaining_bytes, 0);
        assert_eq!(std::fs::read_dir(exact.scratch.path()).unwrap().count(), 0);

        let mut short = ProbeSession::new(&compiler, &[], Duration::from_secs(5), 9).unwrap();
        short.run(&["-vV"]).unwrap();
        assert!(
            short
                .run(&["--print", "sysroot"])
                .unwrap_err()
                .contains("capture exceeds")
        );
        assert_eq!(std::fs::read_dir(short.scratch.path()).unwrap().count(), 0);
    }

    #[test]
    fn failed_or_non_utf8_version_prevents_the_second_query() {
        for version in ["printf plausible; exit 7", "printf '\\377'"] {
            let (dir, compiler) = fixture(version, "printf must-not-run");
            let env = logged_env(dir.path());
            assert!(identity(&compiler, &env).is_err());
            assert_eq!(
                std::fs::read_to_string(dir.path().join("queries")).unwrap(),
                "-vV\n"
            );
        }
    }

    #[test]
    fn failed_sysroot_never_returns_a_partial_identity_pair() {
        let (_dir, compiler) = fixture("printf version", "printf /plausible; exit 8");
        assert!(identity(&compiler, &[]).unwrap_err().contains("exited"));
    }

    #[test]
    fn stdout_and_stderr_floods_are_failures_without_disk_spill() {
        for redirect in ["", ">&2"] {
            let body =
                format!("trap 'exit 0' TERM; while :; do printf '%0200d' 0 {redirect}; done");
            let (_dir, compiler) = fixture(&body, "printf root");
            let mut probes =
                ProbeSession::new(&compiler, &[], Duration::from_secs(5), 1024).unwrap();
            let error = probes.run(&["-vV"]).unwrap_err();
            assert!(error.contains("capture exceeds"), "{error}");
            assert_eq!(std::fs::read_dir(probes.scratch.path()).unwrap().count(), 0);
        }
    }

    #[test]
    fn deadline_rejects_term_handler_success_and_kills_term_ignoring_children() {
        for trap in ["trap 'exit 0' TERM", "trap '' TERM"] {
            let body = format!("{trap}; printf '%s' $$ > \"$PID_FILE\"; while :; do :; done");
            let (dir, compiler) = fixture(&body, "printf root");
            let pid_file = dir.path().join("pid");
            let env = vec![("PID_FILE".into(), pid_file.to_str().unwrap().into())];
            let mut probes =
                ProbeSession::new(&compiler, &env, Duration::from_secs(2), 1024).unwrap();
            let error = probes.run(&["-vV"]).unwrap_err();
            assert!(error.contains("deadline expired"), "{error}");
            assert_not_running(&pid_file);
        }
    }

    #[test]
    fn leader_exit_does_not_leave_descendant_owned_pipes_waiting_for_eof() {
        let (dir, compiler) = fixture(
            "/bin/sleep 30 & printf '%s' $! > \"$PID_FILE\"; printf version",
            "printf root",
        );
        let pid_file = dir.path().join("descendant");
        let env = vec![("PID_FILE".into(), pid_file.to_str().unwrap().into())];
        assert_eq!(
            identity(&compiler, &env).unwrap(),
            ("version".into(), "root".into())
        );
        assert_not_running(&pid_file);
    }

    #[test]
    fn expired_shared_deadline_cannot_start_a_second_query() {
        let (dir, compiler) = fixture("printf version", "printf root");
        let env = logged_env(dir.path());
        let mut probes = ProbeSession::new(&compiler, &env, Duration::from_secs(5), 1024).unwrap();
        let deadline = probes.deadline;
        probes.run(&["-vV"]).unwrap();
        assert_eq!(
            probes.deadline, deadline,
            "a query must not renew the budget"
        );
        // Deterministic boundary injection: no sleep-sensitive comparison of
        // two near-deadline wall-clock intervals is needed to prove no spawn.
        probes.deadline = Instant::now();
        assert!(
            probes
                .run(&["--print", "sysroot"])
                .unwrap_err()
                .contains("deadline expired")
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("queries")).unwrap(),
            "-vV\n"
        );
    }

    #[test]
    fn an_empty_initial_budget_starts_no_compiler_process() {
        let (dir, compiler) = fixture("printf version", "printf root");
        let env = logged_env(dir.path());
        for (timeout, maximum) in [(Duration::ZERO, 1024), (Duration::from_secs(5), 0)] {
            let mut probes = ProbeSession::new(&compiler, &env, timeout, maximum).unwrap();
            assert!(probes.run(&["-vV"]).is_err());
            assert!(!dir.path().join("queries").exists());
        }
    }
}
