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

#[test]
fn path_absence_distinguishes_missing_components_from_unobservable_paths() {
    use std::os::unix::ffi::OsStringExt as _;
    use std::os::unix::fs::symlink;

    let owner = tempfile::Builder::new()
        .prefix("rch-native-path-absence-")
        .disable_cleanup(true)
        .tempdir()
        .unwrap();
    let root = owner.path();
    let directory = root.join("directory");
    let file = root.join("record.pgid");
    let alias = root.join("directory-alias");
    let dangling = root.join("dangling");
    let looping = root.join("looping");
    std::fs::create_dir(&directory).unwrap();
    std::fs::write(&file, b"owned record\n").unwrap();
    symlink(&directory, &alias).unwrap();
    symlink(root.join("missing-target"), &dangling).unwrap();
    symlink("looping", &looping).unwrap();
    let probe = |path: &std::path::Path| helper().arg("path-absent").arg(path).output().unwrap();
    for path in [
        root.join("missing.pgid"),
        root.join("never-created/child/record.pgid"),
        directory.join("missing.pgid"),
        alias.join("missing.pgid"),
        root.join("missing 'quote $dollar;\u{0060}tick\u{0060}.pgid"),
        root.join(std::ffi::OsString::from_vec(b"missing-\xff.pgid".to_vec())),
    ] {
        let output = probe(&path);
        assert!(output.status.success(), "{path:?}: {output:?}");
        assert_eq!(output.stdout, b"RCH_PATH_ABSENT_V1\n");
        assert!(output.stderr.is_empty());
    }
    for path in [&file, &directory, &alias, &dangling, &looping] {
        let output = probe(path);
        assert_eq!(output.status.code(), Some(1), "{path:?}: {output:?}");
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }
    for path in [
        file.join("record"),
        dangling.join("record"),
        looping.join("record"),
        directory.join("x".repeat(256)),
    ] {
        let output = probe(&path);
        assert_eq!(output.status.code(), Some(125), "{path:?}: {output:?}");
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("RCH_SCOPED_LAUNCH_UNAVAILABLE"));
    }
    assert_eq!(std::fs::read(&file).unwrap(), b"owned record\n");
    assert_eq!(std::fs::read_link(&alias).unwrap(), directory);
    assert_eq!(
        std::fs::read_link(&dangling).unwrap(),
        root.join("missing-target")
    );
}

#[test]
fn path_absence_refuses_normalized_or_unbounded_path_spellings() {
    for path in [
        "",
        "relative",
        "/",
        "/missing/",
        "/missing/.",
        "/missing/../record",
        "/missing//record",
    ] {
        let output = helper().args(["path-absent", path]).output().unwrap();
        assert_eq!(output.status.code(), Some(125), "{path:?}: {output:?}");
        assert!(output.stdout.is_empty());
    }
    let path = format!("/{}record", "missing/".repeat(256));
    let output = helper().args(["path-absent", &path]).output().unwrap();
    assert_eq!(output.status.code(), Some(125), "{output:?}");
    assert!(output.stdout.is_empty());
}

#[test]
fn path_absence_never_hides_a_record_behind_denied_directory_access() {
    use std::os::unix::fs::PermissionsExt as _;

    let owner = tempfile::Builder::new()
        .prefix("rch-native-denied-record-")
        .disable_cleanup(true)
        .tempdir()
        .unwrap();
    let directory = owner.path().join("private");
    let path = directory.join("record.pgid");
    std::fs::create_dir(&directory).unwrap();
    std::fs::write(&path, b"still owned\n").unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o0)).unwrap();
    let observation = std::fs::symlink_metadata(&path);
    let result = helper().arg("path-absent").arg(&path).output();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let output = result.unwrap();
    match observation {
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            assert_eq!(output.status.code(), Some(125), "{output:?}");
        }
        // A privileged runner can traverse mode 000. It must observe the
        // actual record instead; this branch is not permission-error proof.
        Ok(_) => assert_eq!(output.status.code(), Some(1), "{output:?}"),
        other => panic!("unexpected permission fixture observation: {other:?}"),
    }
    assert!(output.stdout.is_empty());
    assert_eq!(std::fs::read(&path).unwrap(), b"still owned\n");
}

#[test]
fn path_absence_shell_receipt_is_diskless_and_requires_exact_native_output() {
    use std::os::unix::fs::PermissionsExt as _;

    let owner = tempfile::Builder::new()
        .prefix("rch-path-absence-receipt-")
        .disable_cleanup(true)
        .tempdir()
        .unwrap();
    let missing = owner.path().join("not-created/record.pgid");
    let script = format!(
        "{}\nrch_path_absent \"$1\" || exit 44\nprintf 'accepted\\n'\n",
        rch_common::REMOTE_PROCESS_IDENTITY_SCRIPT
    );
    let invoke = |worker: &std::path::Path| {
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", &script, "rch-path-absence-test"])
            .arg(&missing)
            .env("RCH_WKR_BIN", worker)
            .env("RCH_TIMING_SCALE", "1")
            .env("TMPDIR", "/dev/null/not-writable");
        command
    };
    let output = invoke(std::path::Path::new(WORKER)).output().unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"accepted\n");
    assert!(output.stderr.is_empty());

    let unavailable = invoke(&owner.path().join("no-worker")).output().unwrap();
    assert_eq!(unavailable.status.code(), Some(44), "{unavailable:?}");
    assert!(unavailable.stdout.is_empty());

    // Only the absence command is doubled. The timeout, memory capture and
    // shell protocol remain the production implementations.
    let double = owner.path().join("rch-wkr-double");
    std::fs::write(
        &double,
        b"#!/bin/sh\nif [ \"$1:$2\" = scoped-launch:path-absent ]; then\n\
          printf '%s' \"$RCH_TEST_ABSENCE_OUTPUT\"\n\
          exit \"$RCH_TEST_ABSENCE_STATUS\"\nfi\n\
          exec \"$RCH_TEST_NATIVE_WORKER\" \"$@\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&double, std::fs::Permissions::from_mode(0o700)).unwrap();
    for (marker, code) in [
        ("", "0"),
        ("RCH_PATH_ABSENT_V1", "0"),
        ("RCH_PATH_ABSENT_V1\n\n", "0"),
        ("RCH_PATH_ABSENT_V1\njunk\n", "0"),
        ("RCH_PATH_ABSENT_V1\n", "125"),
    ] {
        let output = invoke(&double)
            .env("RCH_TEST_NATIVE_WORKER", WORKER)
            .env("RCH_TEST_ABSENCE_OUTPUT", marker)
            .env("RCH_TEST_ABSENCE_STATUS", code)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(44), "{marker:?}: {output:?}");
        assert!(output.stdout.is_empty(), "{marker:?}: {output:?}");

        let quarantine = orphan_probe(&missing)
            .env("RCH_WKR_BIN", &double)
            .env("RCH_TEST_NATIVE_WORKER", WORKER)
            .env("RCH_TEST_ABSENCE_OUTPUT", marker)
            .env("RCH_TEST_ABSENCE_STATUS", code)
            .output()
            .unwrap();
        assert!(quarantine.status.success(), "{marker:?}: {quarantine:?}");
        assert_eq!(
            quarantine.stdout, b"RCH_E104_KILL=unverified\n",
            "{marker:?}: {quarantine:?}"
        );
    }
}

fn orphan_probe(path: &std::path::Path) -> Command {
    let script = rch_common::orphan_quarantine::kill_probe_script(path.to_str().unwrap(), 7);
    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", &script, "rch-orphan-probe-test"])
        .env("RCH_WKR_BIN", WORKER)
        .env("RCH_TIMING_SCALE", "1")
        .env("TOKIO_WORKER_THREADS", "0")
        .env("RCH_LOG_FILE", "/dev/null/not-a-log")
        .env("TMPDIR", "/dev/null/not-writable");
    command
}

#[test]
fn orphan_quarantine_absence_requires_the_real_worker_path_observation() {
    use std::os::unix::fs::symlink;

    let owner = tempfile::Builder::new()
        .prefix("rch-orphan-record-absence-")
        .disable_cleanup(true)
        .tempdir()
        .unwrap();
    let root = owner.path();
    let directory = root.join("directory");
    let file = root.join("record.pgid");
    let alias = root.join("directory-alias");
    let dangling = root.join("dangling");
    let looping = root.join("looping");
    std::fs::create_dir(&directory).unwrap();
    std::fs::write(&file, b"unparseable but still present\n").unwrap();
    symlink(&directory, &alias).unwrap();
    symlink(root.join("missing-target"), &dangling).unwrap();
    symlink("looping", &looping).unwrap();

    for path in [
        root.join("missing.pgid"),
        root.join("never-created/child/record.pgid"),
        alias.join("missing.pgid"),
        root.join("missing 'quote $dollar; \u{0060}tick\u{0060}.pgid"),
    ] {
        let output = orphan_probe(&path).output().unwrap();
        assert!(output.status.success(), "{path:?}: {output:?}");
        assert_eq!(output.stdout, b"RCH_E104_KILL=record_absent\n");
        assert!(output.stderr.is_empty(), "{path:?}: {output:?}");
        let receipt = String::from_utf8(output.stdout).unwrap();
        assert!(rch_common::orphan_quarantine::probe_record_absent(&receipt));
        assert!(!rch_common::orphan_quarantine::probe_verified_dead(
            &receipt
        ));
    }

    for path in [
        file.clone(),
        directory.clone(),
        dangling.clone(),
        file.join("record"),
        dangling.join("record"),
        looping.join("record"),
        directory.join("x".repeat(256)),
    ] {
        let output = orphan_probe(&path).output().unwrap();
        assert!(output.status.success(), "{path:?}: {output:?}");
        let receipt = String::from_utf8(output.stdout).unwrap();
        assert!(
            matches!(
                receipt.as_str(),
                "RCH_E104_KILL=still_alive\n" | "RCH_E104_KILL=unverified\n"
            ),
            "{path:?}: {receipt:?}"
        );
        assert!(!rch_common::orphan_quarantine::probe_record_absent(
            &receipt
        ));
        assert!(!rch_common::orphan_quarantine::probe_verified_dead(
            &receipt
        ));
    }
    assert_eq!(
        std::fs::read(&file).unwrap(),
        b"unparseable but still present\n"
    );
    assert_eq!(std::fs::read_link(&alias).unwrap(), directory);
    assert_eq!(
        std::fs::read_link(&dangling).unwrap(),
        root.join("missing-target")
    );
    assert!(!root.join("never-created").exists());
}

#[test]
fn orphan_quarantine_keeps_an_unobservable_record() {
    use std::os::unix::fs::PermissionsExt as _;

    let owner = tempfile::Builder::new()
        .prefix("rch-orphan-denied-record-")
        .disable_cleanup(true)
        .tempdir()
        .unwrap();
    let directory = owner.path().join("private");
    let path = directory.join("record.pgid");
    std::fs::create_dir(&directory).unwrap();
    std::fs::write(&path, b"retained ownership\n").unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o0)).unwrap();
    let observation = std::fs::symlink_metadata(&path);
    let result = orphan_probe(&path).output();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let output = result.unwrap();
    assert!(output.status.success(), "{output:?}");
    match observation {
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            assert_eq!(output.stdout, b"RCH_E104_KILL=unverified\n", "{output:?}");
        }
        // Root can observe the malformed record through mode 000; it must
        // still retain the quarantine, never reinterpret it as missing.
        Ok(_) => assert_eq!(output.stdout, b"RCH_E104_KILL=still_alive\n", "{output:?}"),
        other => panic!("unexpected permission fixture observation: {other:?}"),
    }
    let receipt = String::from_utf8(output.stdout).unwrap();
    assert!(!rch_common::orphan_quarantine::probe_record_absent(
        &receipt
    ));
    assert!(!rch_common::orphan_quarantine::probe_verified_dead(
        &receipt
    ));
    assert_eq!(std::fs::read(&path).unwrap(), b"retained ownership\n");
}

#[cfg(target_os = "linux")]
#[test]
fn orphan_quarantine_preserves_verified_prior_boot_retirement_without_signalling() {
    let mut unrelated = Running::new(timeout("80s", "printf '%s\\n' \"$$\"; sleep 30"));
    unrelated.pids();
    let owner = tempfile::Builder::new()
        .prefix("rch-orphan-prior-boot-")
        .disable_cleanup(true)
        .tempdir()
        .unwrap();
    let current_boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap();
    let prior_boot = if current_boot.trim() == "11111111-1111-1111-1111-111111111111" {
        "22222222-2222-2222-2222-222222222222"
    } else {
        "11111111-1111-1111-1111-111111111111"
    };
    let path = owner.path().join("7.pgid");
    let record = format!(
        "RCH_REMOTE_PROCESS_V1:7:{prior_boot}:{}:1\n",
        unrelated.child.id()
    );
    std::fs::write(&path, &record).unwrap();
    let output = orphan_probe(&path).output().unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"RCH_E104_KILL=verified_dead\n");
    assert!(unrelated.child.try_wait().unwrap().is_none());
    assert_eq!(std::fs::read_to_string(&path).unwrap(), record);
}
