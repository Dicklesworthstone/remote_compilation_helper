//! Exercise disk-independent control capture through the actual worker binary.

#![cfg(any(target_os = "linux", target_os = "macos"))]
#![forbid(unsafe_code)]

use std::os::unix::process::{CommandExt as _, ExitStatusExt as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use rustix::process::{Pid, Signal, WaitId, WaitIdOptions};

const WORKER: &str = env!("CARGO_BIN_EXE_rch-wkr");

struct Fixture {
    directory: tempfile::TempDir,
    blocked: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::Builder::new()
            .prefix("control-capture-")
            .disable_cleanup(true)
            .tempdir()
            .unwrap();
        let blocked = directory.path().join("not-a-directory");
        std::fs::write(&blocked, b"preserve").unwrap();
        Self { directory, blocked }
    }

    fn configure(&self, command: &mut Command) {
        command
            .env_clear()
            .env("PATH", "")
            .env("TMPDIR", &self.blocked)
            .env("TOKIO_WORKER_THREADS", "0")
            .env("RCH_LOG_FILE", self.blocked.join("worker.log"));
    }

    fn command(&self) -> Command {
        let mut command = Command::new(WORKER);
        self.configure(&mut command);
        command.arg("control-capture");
        command
    }

    fn shell(&self, limit: &str, body: &str) -> Output {
        self.command()
            .args([limit, "/bin/sh", "-c", body])
            .output()
            .unwrap()
    }
}

#[test]
fn probe_and_invalid_arguments_need_no_runtime_logging_or_scratch() {
    let fixture = Fixture::new();
    let output = fixture.command().arg("probe").output().unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"rch-wkr control-capture v1\n");
    assert!(output.stderr.is_empty(), "{output:?}");
    for arguments in [
        vec![],
        vec!["probe", "extra"],
        vec!["64"],
        vec!["0", "/bin/true"],
        vec!["1048577", "/bin/true"],
        vec!["18446744073709551616", "/bin/true"],
        vec!["+64", "/bin/true"],
        vec![" 64", "/bin/true"],
        vec!["64", ""],
        vec!["64", "/not/a/command"],
    ] {
        let output = fixture.command().args(&arguments).output().unwrap();
        assert_eq!(output.status.code(), Some(125), "{arguments:?}: {output:?}");
        assert!(output.stdout.is_empty(), "{output:?}");
        assert!(
            output.stderr.starts_with(b"RCH_CONTROL_CAPTURE_REFUSED:"),
            "{output:?}"
        );
    }
    assert_eq!(std::fs::read(&fixture.blocked).unwrap(), b"preserve");
}

#[test]
fn merges_streams_preserves_whitespace_and_routes_child_failures_to_stderr() {
    let fixture = Fixture::new();
    for (body, code, expected) in [
        (
            "printf 'first\\t'; printf 'second\\n' >&2; printf '\\n\\n'",
            0,
            b"first\tsecond\n\n\n".as_slice(),
        ),
        (
            "printf 'before '; printf 'error\\n' >&2; exit 37",
            37,
            b"before error\n",
        ),
        (
            "printf 'terminated\\n'; kill -TERM $$",
            143,
            b"terminated\n",
        ),
        (
            "if read -r input; then exit 1; fi; printf closed",
            0,
            b"closed",
        ),
    ] {
        let output = fixture.shell("64", body);
        assert_eq!(output.status.code(), Some(code), "{output:?}");
        if code == 0 {
            assert_eq!(output.stdout, expected);
            assert!(output.stderr.is_empty(), "{output:?}");
        } else {
            assert_eq!(output.stderr, expected);
            assert!(output.stdout.is_empty(), "{output:?}");
        }
    }
}

#[test]
fn exact_limits_accept_complete_ascii_and_refuse_overflow_or_binary_bytes() {
    let fixture = Fixture::new();
    let input = fixture.directory.path().join("input");
    for limit in [1, 65_536, 1_048_576] {
        for extra in [0, 1] {
            let expected = vec![b'x'; limit + extra];
            std::fs::write(&input, &expected).unwrap();
            let output = fixture
                .command()
                .arg(limit.to_string())
                .arg("/bin/cat")
                .arg(&input)
                .output()
                .unwrap();
            assert!(output.stderr.is_empty(), "{output:?}");
            if extra == 0 {
                assert!(output.status.success(), "{output:?}");
                assert_eq!(output.stdout, expected);
            } else {
                assert_eq!(output.status.code(), Some(125));
                assert!(output.stdout.is_empty());
            }
        }
    }
    for invalid in [0, b'\r', 0x7f, 0x80, 0xff] {
        // A valid prefix and suffix must not make malformed middle bytes safe.
        let mut bytes = vec![b'x'; 8192];
        bytes.extend([invalid, b'\n']);
        std::fs::write(&input, &bytes).unwrap();
        let output = fixture
            .command()
            .args(["65536", "/bin/cat"])
            .arg(&input)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(125), "invalid byte {invalid}");
        assert!(output.stdout.is_empty() && output.stderr.is_empty());
    }
}

#[test]
fn preserves_inherited_witness_descriptors() {
    let fixture = Fixture::new();
    let witness = fixture.directory.path().join("scope witness");
    std::fs::write(&witness, b"pinned-scope\n").unwrap();
    let mut command = Command::new("/bin/sh");
    fixture.configure(&mut command);
    let output = command
        .args([
            "-c",
            "exec 8<\"$1\"; shift; exec \"$@\"",
            "inherited-witness",
        ])
        .arg(&witness)
        .args([
            WORKER,
            "control-capture",
            "64",
            "/bin/sh",
            "-c",
            "IFS= read -r witness <&8 || exit 1; printf '%s\\n' \"$witness\"",
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"pinned-scope\n");
    assert!(output.stderr.is_empty(), "{output:?}");
}

/// Keep the group leader unreaped while inspecting it or revoking the group.
/// This pins its numeric identity even if an assertion discovers early exit.
struct OwnedGroup {
    child: Option<Child>,
    pid: Pid,
}

impl OwnedGroup {
    fn spawn(mut command: Command) -> Self {
        let child = command
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let pid = Pid::from_child(&child);
        Self {
            child: Some(child),
            pid,
        }
    }

    fn exited(&self) -> bool {
        rustix::process::waitid(
            WaitId::Pid(self.pid),
            WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
        )
        .unwrap()
        .is_some()
    }

    fn ready(&self, path: &Path) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !std::fs::metadata(path).is_ok_and(|metadata| metadata.len() > 0) {
            assert!(
                !self.exited(),
                "collector exited before the command started"
            );
            assert!(Instant::now() < deadline, "command never became ready");
            thread::sleep(Duration::from_millis(5));
        }
    }

    fn assert_waiting(&self) {
        let deadline = Instant::now() + Duration::from_millis(200);
        while Instant::now() < deadline {
            assert!(
                !self.exited(),
                "collector abandoned a live command or pipe holder"
            );
            thread::sleep(Duration::from_millis(5));
        }
    }

    fn finish(mut self) -> Output {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !self.exited() {
            assert!(Instant::now() < deadline, "collector did not finish");
            thread::sleep(Duration::from_millis(5));
        }
        // Revoke before reaping even on a regression that returned too early.
        let _ = rustix::process::kill_process_group(self.pid, Signal::KILL);
        self.child.take().unwrap().wait_with_output().unwrap()
    }
}

impl Drop for OwnedGroup {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = rustix::process::kill_process_group(self.pid, Signal::KILL);
            let _ = child.wait();
        }
    }
}

#[test]
fn foreground_exit_does_not_finish_before_inherited_output_drains() {
    for invalid in [false, true] {
        let fixture = Fixture::new();
        let ready = fixture.directory.path().join("ready");
        let release = fixture.directory.path().join("release");
        let mut command = fixture.command();
        command.args([
            "64", "/bin/sh", "-c",
            "if [ \"$2\" = invalid ]; then printf '\\000'; else printf prefix; fi; (printf ready > \"$1\"; while [ ! -f \"$3\" ]; do /bin/sleep 0.01; done; printf suffix) & exit 0",
            "held-output",
        ]).arg(&ready).arg(if invalid { "invalid" } else { "valid" }).arg(&release);
        let child = OwnedGroup::spawn(command);
        child.ready(&ready);
        child.assert_waiting();
        std::fs::write(&release, b"release").unwrap();
        let output = child.finish();
        assert_eq!(
            output.status.code(),
            Some(if invalid { 125 } else { 0 }),
            "{output:?}"
        );
        assert!(output.stderr.is_empty(), "{output:?}");
        assert_eq!(
            output.stdout,
            if invalid {
                b"".as_slice()
            } else {
                b"prefixsuffix"
            }
        );
    }
}

#[test]
fn collector_interruptions_keep_the_owner_alive_until_the_command_stops() {
    for signal in [Signal::HUP, Signal::INT, Signal::TERM] {
        let fixture = Fixture::new();
        let ready = fixture.directory.path().join("ready");
        let release = fixture.directory.path().join("release");
        let mut command = fixture.command();
        command
            .args([
                "64",
                "/bin/sh",
                "-c",
                "printf ready > \"$1\"; while [ ! -f \"$2\" ]; do /bin/sleep 0.01; done",
                "interrupted-capture",
            ])
            .arg(&ready)
            .arg(&release);
        let child = OwnedGroup::spawn(command);
        child.ready(&ready);
        rustix::process::kill_process(child.pid, signal).unwrap();
        child.assert_waiting();
        std::fs::write(&release, b"release").unwrap();
        let output = child.finish();
        assert_eq!(
            output.status.code(),
            Some(128 + signal.as_raw()),
            "{output:?}"
        );
        assert!(
            output.stdout.is_empty() && output.stderr.is_empty(),
            "{output:?}"
        );
    }
}

#[test]
fn outer_group_termination_reaches_the_collector_and_observed_command() {
    let fixture = Fixture::new();
    let ready = fixture.directory.path().join("ready");
    let mut command = fixture.command();
    command
        .args([
            "64",
            "/bin/sh",
            "-c",
            "/bin/ps -o pgid= -p $$ > \"$1\"; printf '\\000'; exec /bin/sleep 30",
            "owned-capture",
        ])
        .arg(&ready);
    let child = OwnedGroup::spawn(command);
    child.ready(&ready);
    child.assert_waiting();
    let group = std::fs::read_to_string(&ready).unwrap();
    assert_eq!(group.trim(), child.pid.as_raw_nonzero().get().to_string());
    rustix::process::kill_process_group(child.pid, Signal::KILL).unwrap();
    let output = child.finish();
    assert_eq!(output.status.signal(), Some(9), "{output:?}");
    assert!(
        output.stdout.is_empty() && output.stderr.is_empty(),
        "{output:?}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn embedded_diskless_capture_owns_timeout_with_unusable_tmpdir() {
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = Fixture::new();
    let bin = fixture.directory.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    std::os::unix::fs::symlink("/usr/bin/uname", bin.join("uname")).unwrap();
    let timeout_selected = fixture.directory.path().join("unsuitable-timeout-selected");
    let unsuitable_timeout = bin.join("timeout");
    std::fs::write(
        &unsuitable_timeout,
        "#!/bin/sh\n: > \"$RCH_TEST_TIMEOUT_SELECTED\"\nexit 91\n",
    )
    .unwrap();
    std::fs::set_permissions(&unsuitable_timeout, std::fs::Permissions::from_mode(0o755)).unwrap();
    let script = format!(
        "{}\nrch_control_diskless=1\nrch_control_capture 2s /bin/sh -c \"$1\"",
        rch_common::REMOTE_PROCESS_IDENTITY_SCRIPT,
    );
    for (body, code, expected_stdout, expected_stderr) in [
        (
            "printf 'witness\\n\\n'",
            0,
            b"witness\n\n".as_slice(),
            b"".as_slice(),
        ),
        (":", 0, b"", b""),
        (
            "printf 'RCH_CONTROL_CAPTURE_STARTED_V1:\\n\\n'",
            0,
            b"RCH_CONTROL_CAPTURE_STARTED_V1:\n\n",
            b"",
        ),
        ("printf 'failed\\n\\n'; exit 37", 37, b"", b"failed\n\n"),
    ] {
        let mut command = Command::new("/bin/sh");
        fixture.configure(&mut command);
        let output = command
            .env("PATH", &bin)
            .env("RCH_WKR_BIN", WORKER)
            .env("RCH_TEST_TIMEOUT_SELECTED", &timeout_selected)
            .args(["-c", &script, "capture-fixture", body])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(code), "{body}: {output:?}");
        assert_eq!(output.stdout, expected_stdout, "{body}");
        assert_eq!(output.stderr, expected_stderr, "{body}");
        assert!(!timeout_selected.exists(), "generic timeout was selected");
    }
    assert_eq!(std::fs::read(&fixture.blocked).unwrap(), b"preserve");
}

#[cfg(target_os = "linux")]
#[test]
fn missing_or_incompatible_native_helpers_refuse_before_observation() {
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = Fixture::new();
    let bin = fixture.directory.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    std::os::unix::fs::symlink("/usr/bin/timeout", bin.join("timeout")).unwrap();
    let old = fixture.directory.path().join("old-worker");
    std::fs::write(&old, "#!/bin/sh\nprintf 'unknown worker protocol\\n'\n").unwrap();
    std::fs::set_permissions(&old, std::fs::Permissions::from_mode(0o755)).unwrap();
    let old_cli = fixture.directory.path().join("old-worker-cli");
    std::fs::write(
        &old_cli,
        "#!/bin/sh\nprintf '%s\\n' 'error: unrecognized subcommand scoped-launch' >&2\nexit 2\n",
    )
    .unwrap();
    std::fs::set_permissions(&old_cli, std::fs::Permissions::from_mode(0o755)).unwrap();
    let launched = fixture.directory.path().join("observation-started");
    let script = format!(
        "{}\nrch_control_diskless=1\nrch_control_capture 2s /bin/sh -c 'printf started > \"$1\"' observation \"$1\"",
        rch_common::REMOTE_PROCESS_IDENTITY_SCRIPT,
    );
    for worker in [
        fixture.directory.path().join("missing-worker"),
        old,
        old_cli.clone(),
        PathBuf::from("/bin/true"),
    ] {
        let mut command = Command::new("/bin/sh");
        fixture.configure(&mut command);
        let output = command
            .env("PATH", &bin)
            .env("RCH_WKR_BIN", &worker)
            .args(["-c", &script, "capture-fixture"])
            .arg(&launched)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(125), "{output:?}");
        assert!(output.stdout.is_empty(), "{output:?}");
        let expected_prefix = if worker == old_cli {
            "error: unrecognized subcommand scoped-launch\nRCH_CONTROL_CAPTURE_UNAVAILABLE:"
        } else {
            "RCH_CONTROL_CAPTURE_UNAVAILABLE:"
        };
        assert!(
            output.stderr.starts_with(expected_prefix.as_bytes()),
            "{output:?}"
        );
        assert!(!launched.exists());
    }
    assert_eq!(std::fs::read(&fixture.blocked).unwrap(), b"preserve");
}
