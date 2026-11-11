//! Real process, descriptor and timeout coverage for native lifecycle helpers.

#![cfg(unix)]
#![forbid(unsafe_code)]

use std::fs::File;
use std::io::Write as _;
use std::os::unix::process::ExitStatusExt as _;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use rustix::process::{Pid, Signal};

const WORKER: &str = env!("CARGO_BIN_EXE_rch-wkr");

fn helper() -> Command {
    let mut command = Command::new(WORKER);
    command
        .arg("scoped-launch")
        .env("TOKIO_WORKER_THREADS", "0")
        .env("RCH_LOG_FILE", "/dev/null/not-a-log");
    command
}

struct Running {
    child: Child,
    _owner: tempfile::TempDir,
    stdout: PathBuf,
    stderr: PathBuf,
}

impl Running {
    fn new(mut command: Command) -> Self {
        let owner = tempfile::Builder::new()
            .prefix("rch-native-scope-")
            .disable_cleanup(true)
            .tempdir()
            .unwrap();
        let stdout = owner.path().join("stdout");
        let stderr = owner.path().join("stderr");
        let child = command
            .stdin(Stdio::null())
            .stdout(File::create(&stdout).unwrap())
            .stderr(File::create(&stderr).unwrap())
            .spawn()
            .unwrap();
        Self {
            child,
            _owner: owner,
            stdout,
            stderr,
        }
    }

    fn wait(&mut self) -> ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "native helper exceeded its bound: stdout={:?}, stderr={:?}",
                std::fs::read(&self.stdout).unwrap(),
                std::fs::read(&self.stderr).unwrap()
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn pids(&self) -> Vec<u32> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let text = std::fs::read_to_string(&self.stdout).unwrap();
            if text.ends_with('\n') {
                return text
                    .split_whitespace()
                    .map(|pid| pid.parse().unwrap())
                    .collect();
            }
            assert!(Instant::now() < deadline, "processes never reported ready");
            thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let pid = Pid::from_child(&self.child);
            // Only our unreaped direct child can authorize this cleanup, and
            // only after the kernel confirms that it owns the private group.
            if rustix::process::getpgid(Some(pid)).ok() == Some(pid) {
                let _ = rustix::process::kill_process_group(pid, Signal::KILL);
            }
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn timeout(seconds: &str, program: &str) -> Command {
    let mut command = helper();
    command
        .args(["timeout", "--closed-stdio", "0", "--signal=KILL", seconds])
        .args(["/bin/sh", "-c", program, "rch-timeout-test"]);
    command
}

#[test]
fn probe_and_invalid_requests_do_not_initialize_runtime_or_logging() {
    let output = helper().arg("probe").output().unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"rch-wkr scoped-launch v1\n");
    assert!(output.stderr.is_empty());
    for pid in ["", "0", "1", "-2", "+2", "2147483648", "2x", "2\n"] {
        for operation in ["absent", "kill-self"] {
            let output = helper().args([operation, pid]).output().unwrap();
            assert_eq!(output.status.code(), Some(125), "{operation} {pid:?}");
            assert!(output.stdout.is_empty());
        }
    }
    for seconds in ["0s", "01s", "1.0s", "81s", "1", "+1s"] {
        let output = timeout(seconds, "exit 99").output().unwrap();
        assert_eq!(output.status.code(), Some(125), "{seconds}: {output:?}");
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn absence_requires_a_kernel_esrch_witness() {
    let mut child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
    let pid = child.id().to_string();
    let output = helper().args(["absent", &pid]).output().unwrap();
    let _ = child.kill();
    child.wait().unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(output.stdout.is_empty());
    let output = helper().args(["absent", &pid]).output().unwrap();
    if output.status.success() {
        assert_eq!(
            output.stdout,
            format!("RCH_PROCESS_ABSENT_V1:{pid}\n").as_bytes()
        );
    } else {
        // Rapid PID reuse is legal but cannot manufacture an absence marker.
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn group_kill_refuses_a_foreign_group_and_kills_its_own_pinned_group() {
    let mut unrelated = Running::new(timeout("5s", "printf '%s\\n' \"$$\"; sleep 30"));
    unrelated.pids();
    let output = helper()
        .args(["kill-self", &unrelated.child.id().to_string()])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(125), "{output:?}");
    assert!(unrelated.child.try_wait().unwrap().is_none());

    let mut command = Command::new(WORKER);
    command.args([
        "setsid",
        "--",
        "/bin/sh",
        "-c",
        "exec \"$1\" scoped-launch kill-self \"$$\"",
        "rch-self-kill-test",
        WORKER,
    ]);
    let mut owned = Running::new(command);
    assert_eq!(owned.wait().signal(), Some(9));
    assert!(unrelated.child.try_wait().unwrap().is_none());
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn assert_stopped(pids: &[u32]) {
    let deadline = Instant::now() + Duration::from_secs(3);
    for &pid in pids {
        loop {
            if rch_common::process_identity::observe_process(pid)
                == rch_common::process_identity::ProcessObservation::Absent
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "owned process {pid} is still live"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn timeout_kills_stopped_children_and_descendants() {
    // Both the direct command and its descendant stop, while the monitor must
    // continue and revoke every member at the original one-second deadline.
    let started = Instant::now();
    let mut running = Running::new(timeout(
        "1s",
        "sleep 30 & descendant=$!; printf '%s %s\\n' \"$$\" \"$descendant\"; kill -STOP \"$descendant\" \"$$\"; wait",
    ));
    let pids = running.pids();
    assert_eq!(running.wait().signal(), Some(9));
    assert!(started.elapsed() < Duration::from_secs(4));
    assert_stopped(&pids);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_capture_keeps_the_timeout_armed_until_inherited_pipes_close() {
    let owner = tempfile::Builder::new()
        .prefix("rch-native-pipe-owner-")
        .disable_cleanup(true)
        .tempdir()
        .unwrap();
    let ready = owner.path().join("ready");
    let mut command = helper();
    command
        .args([
            "timeout",
            "--closed-stdio",
            "0",
            "--signal=KILL",
            "1s",
            WORKER,
            "control-capture",
            "64",
            "/bin/sh",
            "-c",
            "/bin/sleep 30 & descendant=$!; printf '%s %s\\n' \"$$\" \"$descendant\" > \"$1\"; printf '\\000'; exit 0",
            "rch-held-native-pipe",
        ])
        .arg(&ready);
    let started = Instant::now();
    let mut running = Running::new(command);
    let pids: Vec<u32> = loop {
        if let Ok(text) = std::fs::read_to_string(&ready)
            && text.ends_with('\n')
        {
            break text
                .split_whitespace()
                .map(|value| value.parse().unwrap())
                .collect();
        }
        assert!(started.elapsed() < Duration::from_secs(5));
        thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(running.wait().signal(), Some(9));
    assert!(started.elapsed() < Duration::from_secs(4));
    assert!(std::fs::read(&running.stdout).unwrap().is_empty());
    assert!(std::fs::read(&running.stderr).unwrap().is_empty());
    assert_stopped(&pids);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn observer_interruption_revokes_the_private_group_before_the_deadline() {
    for signal in [Signal::HUP, Signal::INT, Signal::TERM, Signal::ALARM] {
        let mut running = Running::new(timeout(
            "80s",
            "sleep 30 & descendant=$!; printf '%s %s\\n' \"$$\" \"$descendant\"; wait",
        ));
        let pids = running.pids();
        rustix::process::kill_process(Pid::from_child(&running.child), signal).unwrap();
        assert_eq!(running.wait().signal(), Some(9), "signal {signal:?}");
        assert_stopped(&pids);
    }
}

#[test]
fn completed_commands_preserve_output_status_and_no_coreutils_fallback() {
    let output = timeout("2s", "printf 'out\\n'; printf 'err\\n' >&2; exit 37")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(37), "{output:?}");
    assert_eq!(output.stdout, b"out\n");
    assert_eq!(output.stderr, b"err\n");

    // PATH hides all timeout binaries; the real shell fallback must locate and
    // call the candidate worker. No executable lookup is needed by the payload.
    let script = format!(
        "{}\nrch_group_timeout --signal=KILL 2s /bin/sh -c 'printf native-fallback; exit 29'\n",
        rch_common::REMOTE_PROCESS_IDENTITY_SCRIPT
    );
    let output = Command::new("/bin/sh")
        .args(["-c", &script, "rch-native-fallback"])
        .env("PATH", "")
        .env("RCH_WKR_BIN", WORKER)
        .env("RCH_TIMING_SCALE", "1")
        .env("TOKIO_WORKER_THREADS", "0")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(29), "{output:?}");
    assert_eq!(output.stdout, b"native-fallback");
    assert!(output.stderr.is_empty());
}

#[test]
fn native_timeout_preserves_closed_stdio_and_inherited_authority_descriptors() {
    let owner = tempfile::Builder::new()
        .prefix("rch-timeout-fds-")
        .disable_cleanup(true)
        .tempdir()
        .unwrap();
    let witness = owner.path().join("fd-eight");
    let script = format!(
        r#"{}
exec 8>"$1" 0<&- 2>&-
rch_group_timeout --signal=KILL 2s /bin/sh -c '
    if ( : 3>&0 ) 2>/dev/null; then exit 91; fi
    if ( : 3>&2 2>/dev/null ); then exit 92; fi
    printf preserved >&8
    printf native-closed-stdio
'
"#,
        rch_common::REMOTE_PROCESS_IDENTITY_SCRIPT
    );
    let output = Command::new("/bin/sh")
        .args(["-c", &script, "rch-timeout-fds"])
        .arg(&witness)
        .env("PATH", "")
        .env("RCH_WKR_BIN", WORKER)
        .env("RCH_TIMING_SCALE", "1")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"native-closed-stdio");
    assert!(output.stderr.is_empty());
    assert_eq!(std::fs::read(&witness).unwrap(), b"preserved");
}

#[cfg(target_os = "linux")]
#[test]
fn darwin_witness_lookup_cannot_substitute_an_unselected_path_worker() {
    use std::os::unix::fs::PermissionsExt as _;

    let owner = tempfile::Builder::new()
        .prefix("rch-witness-selection-")
        .disable_cleanup(true)
        .tempdir()
        .unwrap();
    let wrong_worker = owner.path().join("rch-wkr");
    let wrong_witness = owner.path().join("wrong-worker-used");
    std::fs::write(
        &wrong_worker,
        b"#!/bin/sh\n: > \"$RCH_WRONG_WORKER_WITNESS\"\nprintf '00000000-0000-0000-0000-000000000000 123 2\\n'\n",
    )
    .unwrap();
    std::fs::set_permissions(&wrong_worker, std::fs::Permissions::from_mode(0o700)).unwrap();
    // Lookup regression only: Linux's real candidate must refuse the Darwin
    // kernel witness. The deliberately false PATH helper would claim success.
    let script = format!(
        "{}\nrch_control_diskless=1\nif rch_darwin_process \"$$\"; then exit 91; fi\nprintf selected-native-worker\n",
        rch_common::REMOTE_PROCESS_IDENTITY_SCRIPT
    );
    let output = Command::new("/bin/sh")
        .args(["-c", &script, "rch-witness-selection"])
        .env("PATH", format!("{}:/usr/bin:/bin", owner.path().display()))
        .env("RCH_WKR_BIN", WORKER)
        .env("RCH_WRONG_WORKER_WITNESS", &wrong_witness)
        .env("RCH_TIMING_SCALE", "1")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"selected-native-worker");
    assert!(!wrong_witness.exists());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("kernel process identity unavailable"),
        "{output:?}"
    );
}

#[test]
fn descriptor_probe_never_consumes_input_or_borrows_an_occupied_slot() {
    let script = format!(
        r#"{}
uname() {{ printf Darwin; }}
exec 4>&1 5>&1 6>&1 7>&1 8>&1 9>&1
IFS= read -r before
if rch_scope_launch_save_input; then exit 91; fi
IFS= read -r after
printf '%s:%s:' "$before" "$after"
printf 4 >&4; printf 5 >&5; printf 6 >&6; printf 7 >&7; printf 8 >&8; printf 9 >&9
exec 0<&- 2>&-
rch_scope_launch_save_input || exit 92
[ "$__sl_input_redirect" = '0<&-' ] || exit 93
rch_scope_launch_fd_open 2 && exit 94
exit 0
"#,
        rch_common::REMOTE_PROCESS_IDENTITY_SCRIPT
    );
    let mut child = Command::new("/bin/sh")
        .args(["-c", &script, "rch-fd-probe"])
        .env("RCH_TIMING_SCALE", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"first\nsecond\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"first:second:456789");
    assert!(output.stderr.is_empty());
}
