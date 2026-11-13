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

    fn snapshot(&self, milliseconds: u64) -> (PathBuf, Command) {
        let path = self.directory.path().join("snapshot");
        std::fs::write(&path, b"old snapshot must be replaced").unwrap();
        let mut command = self.command();
        command
            .arg("snapshot")
            .arg(milliseconds.to_string())
            .arg(&path);
        (path, command)
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

#[test]
fn snapshot_probe_and_complete_streams_need_no_optional_worker_services() {
    let fixture = Fixture::new();
    let probe = fixture.command().arg("snapshot-probe").output().unwrap();
    assert!(probe.status.success(), "{probe:?}");
    assert_eq!(probe.stdout, b"rch-wkr control-capture snapshot v1\n");
    assert!(probe.stderr.is_empty());
    let input = fixture.directory.path().join("input");
    // Raw filesystem names are not limited to ASCII or single lines, and the
    // inventory is streamed across many reads rather than truncated to 64 KiB.
    for bytes in [
        Vec::new(),
        b"/tree/\xff\0\n\n".to_vec(),
        vec![b'x'; 262_145],
    ] {
        std::fs::write(&input, &bytes).unwrap();
        let (path, mut command) = fixture.snapshot(5000);
        let result = command.arg("/bin/cat").arg(&input).output().unwrap();
        assert!(result.status.success(), "{result:?}");
        assert!(result.stdout.is_empty() && result.stderr.is_empty());
        assert_eq!(std::fs::read(path).unwrap(), bytes);
    }
    assert_eq!(std::fs::read(&fixture.blocked).unwrap(), b"preserve");
}

#[test]
fn snapshot_reaps_producers_with_inherited_ignored_or_blocked_child_signals() {
    for ignored in [false, true] {
        for blocked in [false, true] {
            for status in [0, 17] {
                let fixture = Fixture::new();
                let (path, _) = fixture.snapshot(5000);
                let mut command = Command::new("/bin/sh");
                fixture.configure(&mut command);
                command
                    .args([
                        "-c",
                        if ignored {
                            "trap '' CHLD; exec \"$@\""
                        } else {
                            "exec \"$@\""
                        },
                        "inherited-child-signals",
                        WORKER,
                        "control-capture",
                        "snapshot",
                        "5000",
                    ])
                    .arg(&path)
                    .args(["/bin/sh", "-c", "printf complete; exit \"$1\"", "producer"])
                    .arg(status.to_string());
                // Change only this fixture thread's signal mask. The worker
                // inherits it, while the test harness and other tests do not.
                let output = thread::spawn(move || {
                    if blocked {
                        let mut signals = nix::sys::signal::SigSet::empty();
                        signals.add(nix::sys::signal::Signal::SIGCHLD);
                        signals.thread_block().unwrap();
                    }
                    command.output().unwrap()
                })
                .join()
                .unwrap();
                assert_eq!(
                    output.status.code(),
                    Some(if status == 0 { 0 } else { 125 }),
                    "ignored={ignored} blocked={blocked} producer={status}: {output:?}"
                );
                assert_eq!(std::fs::read(path).unwrap(), b"complete");
            }
        }
    }
}

#[test]
fn snapshot_rejects_unsafe_files_and_invalid_budgets_before_launch() {
    let fixture = Fixture::new();
    let marker = fixture.directory.path().join("launched");
    let regular = fixture.directory.path().join("regular");
    std::fs::write(&regular, b"preserve original").unwrap();
    let symlink = fixture.directory.path().join("symlink");
    std::os::unix::fs::symlink(&regular, &symlink).unwrap();
    let hardlink = fixture.directory.path().join("hardlink");
    std::fs::hard_link(&regular, &hardlink).unwrap();
    for path in [
        symlink,
        hardlink,
        fixture.directory.path().to_path_buf(),
        fixture.directory.path().join("absent"),
        PathBuf::from("/dev/null"),
    ] {
        let result = fixture
            .command()
            .args(["snapshot", "5000"])
            .arg(&path)
            .args([
                "/bin/sh",
                "-c",
                "printf launched > \"$1\"",
                "unsafe-snapshot",
            ])
            .arg(&marker)
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(125), "{path:?}: {result:?}");
        assert!(result.stdout.is_empty());
        assert!(!marker.exists());
    }
    for milliseconds in ["0", "+1", " 1", "3600001", "18446744073709551616"] {
        let result = fixture
            .command()
            .args(["snapshot", milliseconds])
            .arg(&regular)
            .arg("/bin/true")
            .output()
            .unwrap();
        assert_eq!(
            result.status.code(),
            Some(125),
            "{milliseconds}: {result:?}"
        );
    }
    assert_eq!(std::fs::read(regular).unwrap(), b"preserve original");
}

#[test]
fn snapshot_partial_data_and_forged_completion_cannot_mask_producer_failure() {
    let fixture = Fixture::new();
    for body in [
        "printf '/unrelated\\n'; exit 1",
        "printf 'RCH_GC_SNAPSHOT_STATUS 0\\n'; exit 1",
        "printf 'RCH_GC_SNAPSHOT_STATUS 0\\n'; kill -KILL $$",
    ] {
        let (path, mut command) = fixture.snapshot(5000);
        let result = command.args(["/bin/sh", "-c", body]).output().unwrap();
        assert_eq!(result.status.code(), Some(125), "{body}: {result:?}");
        assert!(result.stdout.is_empty());
        assert!(
            !std::fs::read(path).unwrap().is_empty(),
            "real prefix was written"
        );
    }
}

fn assert_snapshot_producers_stopped(path: &Path) {
    let pids = std::fs::read_to_string(path).unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    for pid in pids.split_whitespace() {
        loop {
            let status = Command::new("/bin/ps")
                .args(["-o", "stat=", "-p", pid])
                .output()
                .unwrap();
            let text = String::from_utf8_lossy(&status.stdout);
            if text.trim().is_empty() || text.trim_start().starts_with(['Z', 'X']) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "owned producer {pid} is still live: {text}"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }
}

#[test]
fn snapshot_deadline_stops_live_leaders_and_orphaned_pipe_holders() {
    for leader_exits in [false, true] {
        let fixture = Fixture::new();
        let pids = fixture.directory.path().join("pids");
        let (_path, mut command) = fixture.snapshot(1000);
        command
            .args([
                "/bin/sh", "-c",
                "trap '' TERM; /bin/sleep 30 & printf '%s %s\\n' $$ $! > \"$1\"; printf prefix; if [ \"$2\" = exit ]; then exit 0; fi; wait",
                "snapshot-timeout",
            ])
            .arg(&pids)
            .arg(if leader_exits { "exit" } else { "wait" });
        let child = OwnedGroup::spawn(command);
        child.ready(&pids);
        let output = child.finish();
        assert_eq!(output.status.code(), Some(125), "{output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("timed out"),
            "{output:?}"
        );
        assert_snapshot_producers_stopped(&pids);
    }
}

#[test]
fn snapshot_collector_interruptions_settle_its_separate_producer_group() {
    for signal in [Signal::HUP, Signal::INT, Signal::TERM] {
        let fixture = Fixture::new();
        let pids = fixture.directory.path().join("pids");
        let (_path, mut command) = fixture.snapshot(5000);
        command
            .args([
                "/bin/sh",
                "-c",
                "trap '' TERM; /bin/sleep 30 & printf '%s %s\\n' $$ $! > \"$1\"; wait",
                "snapshot-interrupted",
            ])
            .arg(&pids);
        let child = OwnedGroup::spawn(command);
        child.ready(&pids);
        rustix::process::kill_process(child.pid, signal).unwrap();
        let output = child.finish();
        assert_eq!(output.status.code(), Some(125), "{output:?}");
        assert_snapshot_producers_stopped(&pids);
    }
}

#[test]
fn snapshot_observer_death_revokes_the_writer_lifetime_pipe() {
    let fixture = Fixture::new();
    let pids = fixture.directory.path().join("pids");
    let (_path, mut command) = fixture.snapshot(30_000);
    command
        .args([
            "/bin/sh",
            "-c",
            "trap '' TERM; /bin/sleep 30 & printf '%s %s %s\\n' \"$PPID\" $$ $! > \"$1\"; wait",
            "snapshot-orphaned-observer",
        ])
        .arg(&pids);
    let child = OwnedGroup::spawn(command);
    child.ready(&pids);
    // Only kill the observer. The writer and producer have their own group,
    // so the private pipe must revoke them without a signal handler or Drop.
    rustix::process::kill_process(child.pid, Signal::KILL).unwrap();
    let output = child.finish();
    assert_eq!(
        output.status.signal(),
        Some(Signal::KILL.as_raw()),
        "{output:?}"
    );
    assert_snapshot_producers_stopped(&pids);
}

#[test]
fn snapshot_writer_failure_preserves_error_and_stops_every_owned_writer() {
    let fixture = Fixture::new();
    let (snapshot, _) = fixture.snapshot(5000);
    let pids = fixture.directory.path().join("pids");
    let input = fixture.directory.path().join("input");
    std::fs::write(&input, vec![b'x'; 16_384]).unwrap();
    let mut command = Command::new("/bin/sh");
    fixture.configure(&mut command);
    command
        .args(["-c", "ulimit -f 1; exec \"$@\"", "limited-snapshot"])
        .args([WORKER, "control-capture", "snapshot", "5000"])
        .arg(&snapshot)
        .args([
            "/bin/sh", "-c",
            "trap '' TERM PIPE; /bin/sleep 30 & printf '%s %s\\n' $$ $! > \"$1\"; /bin/cat \"$2\"; wait",
            "snapshot-writer",
        ])
        .arg(&pids)
        .arg(&input);
    let child = OwnedGroup::spawn(command);
    child.ready(&pids);
    let output = child.finish();
    assert_eq!(output.status.code(), Some(125), "{output:?}");
    let written = std::fs::metadata(snapshot).unwrap().len();
    assert!(
        (1..=1024).contains(&written),
        "real partial write: {written}"
    );
    assert_snapshot_producers_stopped(&pids);
}

#[test]
fn snapshot_replacement_during_capture_is_never_successful_evidence() {
    let fixture = Fixture::new();
    let ready = fixture.directory.path().join("ready");
    let release = fixture.directory.path().join("release");
    let (snapshot, mut command) = fixture.snapshot(5000);
    command
        .args([
            "/bin/sh", "-c",
            "printf prefix; printf ready > \"$1\"; while [ ! -f \"$2\" ]; do /bin/sleep 0.01; done; printf suffix",
            "snapshot-replaced",
        ])
        .arg(&ready)
        .arg(&release);
    let child = OwnedGroup::spawn(command);
    child.ready(&ready);
    let retained = fixture.directory.path().join("retained-original");
    std::fs::rename(&snapshot, &retained).unwrap();
    std::fs::write(&snapshot, b"replacement is not the observed inventory").unwrap();
    std::fs::write(release, b"release").unwrap();
    let output = child.finish();
    assert_eq!(output.status.code(), Some(125), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("replaced"));
    assert_eq!(std::fs::read(retained).unwrap(), b"prefixsuffix");
    assert_eq!(
        std::fs::read(snapshot).unwrap(),
        b"replacement is not the observed inventory"
    );
}

/// Feed real GC shell fragments through the native collector. Only the OS
/// inventory producers are fixtures; snapshot writing and gate decisions use
/// the product implementation, including the fallback from find to lsof.
fn gc_shell(fixture: &Fixture, producers: &str) -> Command {
    use std::os::unix::fs::PermissionsExt as _;

    let bin = fixture.directory.path().join("producers");
    std::fs::create_dir(&bin).unwrap();
    for name in ["find", "lsof", "ps"] {
        let executable = bin.join(name);
        std::fs::write(
            &executable,
            format!(
                "#!/bin/sh\n\
                 find() {{ printf '/unrelated/file\\n'; }}\n\
                 lsof() {{ printf 'p999999\\nn/unrelated/file\\n'; }}\n\
                 ps() {{ if [ \"$1\" = -o ]; then printf '1\\n'; else printf '999999 unrelated\\n'; fi; }}\n\
                 {producers}\n{name} \"$@\"\n"
            ),
        )
        .unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let mut command = Command::new("/bin/sh");
    command
        .env_clear()
        .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
        .env("RCH_WKR_BIN", WORKER)
        .env("TMPDIR", fixture.directory.path())
        .env("RCH_GC_SCRATCH", fixture.directory.path())
        .env("TOKIO_WORKER_THREADS", "0");
    command
}

fn gc_gate_script(setup: &str, after_capture: &str) -> String {
    let (gates, _) = rch_common::stale_target_reap::gc_liveness_guard_fragments();
    format!(
        "__tmpbase=$TMPDIR; __candidate=${{RCH_TEST_CANDIDATE:-/candidate/pool}}; \
         {setup}\n{gates}\n{after_capture}\n\
         printf 'handles=%s\\n' \"$(__gc_handles \"$__candidate\")\"; \
         printf 'processes=%s\\n' \"$(__gc_procs \"$__candidate\")\"; \
         if __gc_gates_ok \"$__candidate\"; then printf 'collect=yes\\n'; \
         else printf 'collect=no\\n'; fi"
    )
}

fn run_gc_gates(producers: &str, setup: &str, after_capture: &str, worker: &str) -> Output {
    let fixture = Fixture::new();
    gc_shell(&fixture, producers)
        .env("RCH_WKR_BIN", worker)
        .args(["-c", &gc_gate_script(setup, after_capture)])
        .output()
        .unwrap()
}

#[test]
fn gc_shell_requires_complete_native_snapshots_before_collection() {
    for (producers, after_capture, expected) in [
        ("", "", "handles=free\nprocesses=free\ncollect=yes\n"),
        (
            "find() { printf '/unrelated/file\\n'; return 1; }; lsof() { return 1; };",
            "",
            "handles=unknown\nprocesses=free\ncollect=no\n",
        ),
        (
            "ps() { if [ \"$1\" = -o ]; then printf '1\\n'; else printf '999999 unrelated\\n'; return 1; fi; };",
            "",
            "handles=free\nprocesses=unknown\ncollect=no\n",
        ),
        (
            "ps() { case \"$1\" in -o) printf '1\\n';; -ww) printf '999998 /candidate/pool\\n'; return 1;; *) printf '999999 unrelated\\n';; esac; };",
            "",
            "handles=free\nprocesses=unknown\ncollect=no\n",
        ),
        (
            "find() { return 0; }; lsof() { return 1; }; ps() { return 0; };",
            "",
            "handles=unknown\nprocesses=unknown\ncollect=no\n",
        ),
        (
            "find() { return 1; }; lsof() { printf 'p999999\\nn/candidate/pool/artifact.o\\n'; };",
            "",
            "handles=held\nprocesses=free\ncollect=no\n",
        ),
        (
            "find() { printf '/candidate/pool/artifact.o\\n'; }; lsof() { printf 'n/candidate/pool/artifact.o\\n'; };",
            "",
            "handles=held\nprocesses=free\ncollect=no\n",
        ),
        (
            "ps() { if [ \"$1\" = -o ]; then printf '1\\n'; else printf '999999 build /candidate/pool\\n'; fi; };",
            "",
            "handles=free\nprocesses=held\ncollect=no\n",
        ),
        (
            "",
            "awk() { printf free; return 2; };",
            "handles=unknown\nprocesses=unknown\ncollect=no\n",
        ),
        (
            "",
            "mv \"$__held\" \"$__held.retained\";",
            "handles=unknown\nprocesses=free\ncollect=no\n",
        ),
        (
            "",
            "mv \"$__proc\" \"$__proc.retained\";",
            "handles=free\nprocesses=unknown\ncollect=no\n",
        ),
    ] {
        let output = run_gc_gates(producers, "", after_capture, WORKER);
        assert!(output.status.success(), "{producers}: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stdout).ends_with(expected),
            "{producers}, {after_capture}: {output:?}"
        );
    }
}

#[test]
fn gc_shell_refuses_unsupported_native_snapshot_workers() {
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = Fixture::new();
    let failed_probe = fixture.directory.path().join("failed-probe");
    std::fs::write(
        &failed_probe,
        b"#!/bin/sh\nprintf 'rch-wkr control-capture snapshot v1\\n'\nexit 17\n",
    )
    .unwrap();
    std::fs::set_permissions(&failed_probe, std::fs::Permissions::from_mode(0o755)).unwrap();
    for worker in [
        "/bin/true",
        "/absent/rch-wkr",
        failed_probe.to_str().unwrap(),
    ] {
        let output = run_gc_gates("", "", "", worker);
        assert!(output.status.success(), "{output:?}");
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .ends_with("handles=unknown\nprocesses=unknown\ncollect=no\n"),
            "{output:?}"
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("RCH_GC_SNAPSHOT_UNAVAILABLE"),
            "{output:?}"
        );
    }
}

#[test]
fn gc_shell_keeps_its_witness_but_inventory_producers_do_not_inherit_it() {
    let output = run_gc_gates(
        "if [ \"$1\" != -o ] && ( : <&8 ) 2>/dev/null; then exit 19; fi;",
        "printf 'metadata witness\\n' > \"$TMPDIR/witness\"; exec 8<\"$TMPDIR/witness\";",
        "IFS= read -r witness <&8 || exit 20; [ \"$witness\" = 'metadata witness' ] || exit 21;",
        WORKER,
    );
    assert!(output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .ends_with("handles=free\nprocesses=free\ncollect=yes\n"),
        "{output:?}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn gc_shell_protects_a_real_open_artifact() {
    use std::os::fd::AsRawFd as _;

    let fixture = Fixture::new();
    let candidate = fixture.directory.path().join("live-pool");
    std::fs::create_dir(&candidate).unwrap();
    let artifact = candidate.join("artifact.o");
    std::fs::write(&artifact, b"retained build output").unwrap();
    let held = std::fs::File::open(&artifact).unwrap();
    // Read an actual stable kernel descriptor, avoiding unrelated /proc races
    // caused by parallel test processes starting and exiting during find.
    let producers = format!(
        "find() {{ /usr/bin/find /proc/{}/fd/{} -maxdepth 0 -printf '%l\\n'; }};",
        std::process::id(),
        held.as_raw_fd(),
    );
    let output = gc_shell(&fixture, &producers)
        .env("RCH_TEST_CANDIDATE", &candidate)
        .args(["-c", &gc_gate_script("", "")])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .ends_with("handles=held\nprocesses=free\ncollect=no\n"),
        "{output:?}"
    );
    assert_eq!(std::fs::read(artifact).unwrap(), b"retained build output");
}

fn live_long_command(fixture: &Fixture, candidate: &Path) -> OwnedGroup {
    let ready = fixture.directory.path().join("live-process-ready");
    let mut command = Command::new("/bin/sh");
    command
        .args([
            "-c",
            "printf ready > \"$3\"; /bin/sleep 30 & wait",
            "live-gc-candidate",
        ])
        .arg("x".repeat(16_384))
        .arg(candidate)
        .arg(&ready);
    let child = OwnedGroup::spawn(command);
    child.ready(&ready);
    child
}

#[test]
fn gc_shell_protects_long_live_arguments_without_matching_its_own_observer() {
    let fixture = Fixture::new();
    let candidate = fixture.directory.path().join("live-pool");
    let child = live_long_command(&fixture, &candidate);
    let mut command = gc_shell(&fixture, "ps() { /bin/ps \"$@\"; };");
    // Put the candidate into the GC shell's own argv as real apply scripts do.
    // Its ancestor chain must be excluded, while the unrelated live child is
    // still visible beyond a normal ps display width.
    command
        .env("COLUMNS", "80")
        .env("RCH_TEST_CANDIDATE", &candidate)
        .args([
            "-c",
            &gc_gate_script("", &format!("# {}", candidate.display())),
        ]);
    let output = command.output().unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .ends_with("handles=free\nprocesses=held\ncollect=no\n"),
        "{output:?}"
    );
    rustix::process::kill_process_group(child.pid, Signal::KILL).unwrap();
    child.finish();
    let output = command.output().unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .ends_with("handles=free\nprocesses=free\ncollect=yes\n"),
        "{output:?}"
    );
}

#[cfg(target_os = "linux")]
fn gc_claim_fixture(fixture: &Fixture) -> (PathBuf, PathBuf, PathBuf, Vec<u8>) {
    use sha2::{Digest as _, Sha256};

    let registry = fixture.directory.path().join("claims");
    std::fs::create_dir(&registry).unwrap();
    let candidate = fixture.directory.path().join("claim-pool");
    let payload = format!("{}\n", candidate.display()).into_bytes();
    let name = format!(
        "fc-00000000-0000-4000-8000-000000000001.{:x}.claim",
        Sha256::digest(&payload),
    );
    let claim = registry.join(name);
    std::fs::write(&claim, &payload).unwrap();
    (registry, candidate, claim, payload)
}

#[cfg(target_os = "linux")]
#[test]
fn gc_abandoned_claims_keep_ownership_after_incomplete_or_unreadable_snapshots() {
    for (producers, setup, expected) in [
        (
            "find() { printf '/partial\\n'; return 1; };",
            "",
            "RCH_GC_CLAIMS incomplete-handles",
        ),
        (
            "ps() { printf '999999 partial\\n'; return 1; };",
            "",
            "RCH_GC_CLAIMS incomplete-processes",
        ),
        (
            "",
            "awk() { printf free; return 2; };",
            "keep unreadable-handles",
        ),
    ] {
        let fixture = Fixture::new();
        let (registry, _, claim, payload) = gc_claim_fixture(&fixture);
        let script = rch_common::stale_target_reap::abandoned_gc_claims_command_with_registry(
            true,
            registry.to_str().unwrap(),
            0,
        );
        let output = gc_shell(&fixture, producers)
            .args(["-c", &format!("{setup}\n{script}")])
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(
            String::from_utf8_lossy(&output.stdout).contains(expected),
            "{output:?}"
        );
        assert_eq!(std::fs::read(&claim).unwrap(), payload);
        assert!(
            !registry
                .join("released")
                .join(claim.file_name().unwrap())
                .exists()
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn gc_abandoned_claims_keep_long_live_processes_and_release_the_metadata_witness() {
    let fixture = Fixture::new();
    let (registry, candidate, claim, payload) = gc_claim_fixture(&fixture);
    let child = live_long_command(&fixture, &candidate);
    let mut command = gc_shell(
        &fixture,
        "if ( : <&8 ) 2>/dev/null; then exit 19; fi; ps() { /bin/ps \"$@\"; };",
    );
    let script = rch_common::stale_target_reap::abandoned_gc_claims_command_with_registry(
        false,
        registry.to_str().unwrap(),
        0,
    );
    command.env("COLUMNS", "80").args(["-c", &script]);
    let output = command.output().unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("keep live-process"),
        "{output:?}"
    );
    assert_eq!(std::fs::read(&claim).unwrap(), payload);
    rustix::process::kill_process_group(child.pid, Signal::KILL).unwrap();
    child.finish();
    let output = command.output().unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("would-release abandoned"),
        "{output:?}"
    );
    assert_eq!(std::fs::read(&claim).unwrap(), payload);
    // No inventory producer may retain the registry lock after the GC shell.
    let output = Command::new("flock")
        .args(["-n", "-E", "73"])
        .arg(registry.join("metadata.lock"))
        .arg("/bin/true")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
}

#[cfg(target_os = "linux")]
#[test]
fn gc_shell_rejects_real_enospc_even_if_the_producer_succeeds() {
    use std::io::Write as _;

    if let Ok(mode) = std::env::var("RCH_TEST_GC_ENOSPC_MODE") {
        let mount = PathBuf::from(std::env::var_os("RCH_TEST_GC_ENOSPC_MOUNT").unwrap());
        let output = Command::new("mount")
            .args(["-t", "tmpfs", "-o", "size=8m,nr_inodes=256", "tmpfs"])
            .arg(&mount)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let allowance = match mode.as_str() {
            "full" => 0,
            "partial-handles" => 4096,
            "partial-processes" => 8192,
            _ => panic!("unexpected ENOSPC fixture mode: {mode}"),
        };
        let filler = std::fs::File::create(mount.join("filler")).unwrap();
        rustix::fs::fallocate(
            &filler,
            rustix::fs::FallocateFlags::empty(),
            0,
            8 * 1024 * 1024 - allowance,
        )
        .unwrap();
        let fixture = Fixture::new();
        // Ignore a broken producer pipe deliberately: successful lsof versions
        // can do this after a disk fills. Only the native writer can reject it.
        let bulk = "dd if=/dev/zero bs=65536 count=4 2>/dev/null; return 0;";
        let producers = if mode == "partial-processes" {
            format!("ps() {{ if [ \"$1\" = -o ]; then printf '1\\n'; else {bulk} fi; }};")
        } else {
            format!("find() {{ {bulk} }}; lsof() {{ {bulk} }};")
        };
        let script = gc_gate_script(
            "",
            "printf 'handle_bytes=%s\\nprocess_bytes=%s\\n' \
             \"$(wc -c < \"$__held\")\" \"$(wc -c < \"$__proc\")\";",
        );
        let output = gc_shell(&fixture, &producers)
            .env("TMPDIR", &mount)
            .env("RCH_GC_SCRATCH", &mount)
            .args(["-c", &script])
            .output()
            .unwrap();
        assert!(output.status.success(), "{mode}: {output:?}");
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(text.ends_with("collect=no\n"), "{mode}: {output:?}");
        let (evidence, bytes) = if mode == "partial-processes" {
            assert!(text.contains("handles=free\n"), "{output:?}");
            ("processes=unknown\n", "process_bytes=")
        } else {
            ("handles=unknown\n", "handle_bytes=")
        };
        assert!(text.contains(evidence), "{mode}: {output:?}");
        if mode != "full" {
            let count: u64 = text
                .lines()
                .find_map(|line| line.strip_prefix(bytes))
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            assert!(count > 0, "a real prefix must precede ENOSPC: {output:?}");
        }
        let mut probe = std::fs::File::create(mount.join("enospc-probe")).unwrap();
        let error = probe.write_all(b"x").unwrap_err();
        assert_eq!(
            error.raw_os_error(),
            Some(rustix::io::Errno::NOSPC.raw_os_error())
        );
        return;
    }
    // As with the previous fixture, kernel namespace policy may prevent an
    // isolated tmpfs. Report that restriction; the unprivileged real short-
    // write regression above still runs on every Linux/macOS test host.
    let probe = Command::new("unshare")
        .args([
            "--user",
            "--map-root-user",
            "--mount",
            "--fork",
            "/bin/true",
        ])
        .output();
    if !probe.as_ref().is_ok_and(|output| output.status.success()) {
        eprintln!("isolated ENOSPC fixture unavailable: {probe:?}");
        return;
    }
    let fixture = Fixture::new();
    for mode in ["full", "partial-handles", "partial-processes"] {
        let mount = fixture.directory.path().join(mode);
        std::fs::create_dir(&mount).unwrap();
        let output = Command::new("unshare")
            .args(["--user", "--map-root-user", "--mount", "--fork"])
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "gc_shell_rejects_real_enospc_even_if_the_producer_succeeds",
                "--nocapture",
            ])
            .env("RCH_TEST_GC_ENOSPC_MODE", mode)
            .env("RCH_TEST_GC_ENOSPC_MOUNT", &mount)
            .output()
            .unwrap();
        assert!(output.status.success(), "{mode}: {output:?}");
    }
}
