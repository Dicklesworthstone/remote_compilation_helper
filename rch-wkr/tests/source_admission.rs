//! Native admission timing and real kernel-lock handoff, with no async runtime.
#![cfg(unix)]
#![forbid(unsafe_code)]

use std::fs::File;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use rustix::fs::{FlockOperation, Mode};

const WORKER: &str = env!("CARGO_BIN_EXE_rch-wkr");

struct Fixture {
    root: tempfile::TempDir,
    lock: PathBuf,
    mutation: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::Builder::new()
            .prefix("rch-native-admission-")
            .disable_cleanup(true)
            .tempdir()
            .unwrap();
        Self {
            lock: root.path().join("metadata ' ; lock"),
            mutation: root.path().join("admitted"),
            root,
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(WORKER);
        command
            .arg("source-admission")
            .env_clear()
            .env("PATH", "")
            .env("TOKIO_WORKER_THREADS", "0")
            .env("TMPDIR", self.root.path().join("missing"))
            .env("RCH_LOG_FILE", self.root.path().join("missing/log"));
        command
    }

    fn lock_command(&self, scale: &str, body: &str) -> Command {
        let mut command = self.command();
        command
            .args(["metadata-lock"])
            .arg(&self.lock)
            .args(["/bin/sh", "-c", body, "rch-admission-test"])
            .arg(&self.mutation)
            .env("RCH_TIMING_SCALE", scale);
        command
    }

    fn held_lock(&self) -> File {
        std::fs::write(&self.lock, b"retained metadata\n").unwrap();
        let held = File::open(&self.lock).unwrap();
        rustix::fs::flock(&held, FlockOperation::LockExclusive).unwrap();
        held
    }

    fn admission(&self, scale: &str) -> Command {
        self.lock_command(scale, "printf admitted > \"$1\"; printf 'ADMITTED\\n'")
    }
}

struct OwnedChild(Option<Child>);

impl OwnedChild {
    fn spawn(mut command: Command) -> Self {
        Self(Some(
            command
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        ))
    }

    fn child(&mut self) -> &mut Child {
        self.0.as_mut().unwrap()
    }

    fn finish(mut self, timeout: Duration) -> Output {
        let deadline = Instant::now() + timeout;
        loop {
            if self.child().try_wait().unwrap().is_some() {
                return self.0.take().unwrap().wait_with_output().unwrap();
            }
            assert!(Instant::now() < deadline, "native admission did not settle");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[cfg(target_os = "linux")]
    fn wait_for_lock_open(&mut self, held: &File) {
        let expected = held.metadata().unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            assert!(
                self.child().try_wait().unwrap().is_none(),
                "waiter exited early"
            );
            for entry in std::fs::read_dir(format!("/proc/{}/fd", self.child().id())).unwrap() {
                if let Ok(info) = std::fs::metadata(entry.unwrap().path())
                    && (info.dev(), info.ino()) == (expected.dev(), expected.ino())
                {
                    return;
                }
            }
            assert!(
                Instant::now() < deadline,
                "waiter never opened the held inode"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn assert_status(output: &Output, status: i32) {
    assert_eq!(output.status.code(), Some(status), "{output:?}");
}

#[test]
fn native_clock_works_without_tools_runtime_logging_or_temporary_storage() {
    let fixture = Fixture::new();
    let probe = fixture.command().arg("probe").output().unwrap();
    assert_status(&probe, 0);
    assert_eq!(probe.stdout, b"rch-wkr source-admission v1\n");
    assert!(probe.stderr.is_empty());
    let budget = fixture
        .command()
        .args(["budget", "5"])
        .env("RCH_TIMING_SCALE", "1.5")
        .output()
        .unwrap();
    assert_status(&budget, 0);
    assert_eq!(budget.stdout, b"7500000000\n");
    assert!(budget.stderr.is_empty());
    let start = fixture
        .command()
        .args(["start", "1500000000"])
        .output()
        .unwrap();
    assert_status(&start, 0);
    let deadline = std::str::from_utf8(&start.stdout).unwrap().trim();
    assert_status(
        &fixture
            .command()
            .args(["check", deadline])
            .output()
            .unwrap(),
        0,
    );
    let mut wait = fixture.command().args(["wait", deadline]).output().unwrap();
    if wait.status.success() {
        // One wait preserves the one-second retry cadence, so a longer
        // admission budget can need another wait before its absolute expiry.
        wait = fixture.command().args(["wait", deadline]).output().unwrap();
    }
    assert_status(&wait, 75);
    assert!(wait.stdout.is_empty() && wait.stderr.is_empty());
    assert_status(
        &fixture
            .command()
            .args(["check", deadline])
            .output()
            .unwrap(),
        75,
    );
    assert_eq!(std::fs::read_dir(fixture.root.path()).unwrap().count(), 0);
}

#[test]
fn malformed_or_unbounded_clock_requests_never_become_retryable_expiry() {
    let fixture = Fixture::new();
    for arguments in [
        vec![],
        vec!["budget", "0"],
        vec!["budget", "61"],
        vec!["start", "0"],
        vec!["start", "600000000001"],
        vec!["check", "0"],
        vec!["wait", "9223372036854775807"],
        vec!["check", "18446744073709551616"],
        vec!["wait", "+1"],
        vec!["check", "1", "extra"],
        vec!["unknown", "1"],
    ] {
        let output = fixture.command().args(&arguments).output().unwrap();
        assert_status(&output, 73);
        assert!(output.stdout.is_empty(), "{arguments:?}");
        assert_eq!(output.stderr, b"RCH_SOURCE_ADMISSION_CLOCK_UNAVAILABLE\n");
    }
}

#[test]
fn invalid_scale_refuses_before_creating_or_acquiring_metadata() {
    let fixture = Fixture::new();
    for value in [
        "",
        "0",
        "0.99",
        "10.1",
        "nan",
        "inf",
        "1e9999",
        "1_0",
        "٢",
        " 2",
        "2 ",
        "$(printf injected)",
        "1;printf injected",
    ] {
        let output = fixture.admission(value).output().unwrap();
        assert_status(&output, 78);
        assert!(output.stdout.is_empty());
        assert_eq!(
            output.stderr,
            b"RCH_SOURCE_NAMESPACE_INVALID_TIMING_SCALE\n"
        );
        assert!(!fixture.lock.exists() && !fixture.mutation.exists());
    }
    let output = fixture
        .admission(&format!("{}2", "0".repeat(128)))
        .output()
        .unwrap();
    assert_status(&output, 78);
    assert!(!fixture.lock.exists() && !fixture.mutation.exists());
}

#[test]
fn unsafe_lock_entries_are_rejected_without_changing_their_inodes_or_backing() {
    for kind in ["symlink", "fifo", "directory", "hardlink"] {
        let fixture = Fixture::new();
        let backing = fixture.root.path().join("backing");
        match kind {
            "symlink" | "hardlink" => {
                std::fs::write(&backing, b"untouched backing\n").unwrap();
                if kind == "symlink" {
                    std::os::unix::fs::symlink(&backing, &fixture.lock).unwrap();
                } else {
                    std::fs::hard_link(&backing, &fixture.lock).unwrap();
                }
            }
            "fifo" => rustix::fs::mknodat(
                rustix::fs::CWD,
                &fixture.lock,
                rustix::fs::FileType::Fifo,
                Mode::RUSR | Mode::WUSR,
                0,
            )
            .unwrap(),
            _ => std::fs::create_dir(&fixture.lock).unwrap(),
        }
        let before = std::fs::symlink_metadata(&fixture.lock).unwrap();
        let output = fixture.admission("1").output().unwrap();
        assert_status(&output, 73);
        assert!(output.stdout.is_empty());
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("RCH_SOURCE_NAMESPACE_METADATA_LOCK_INVALID")
        );
        assert!(!fixture.mutation.exists());
        let after = std::fs::symlink_metadata(&fixture.lock).unwrap();
        assert_eq!(
            (before.dev(), before.ino(), before.mode()),
            (after.dev(), after.ino(), after.mode())
        );
        if backing.exists() {
            assert_eq!(std::fs::read(&backing).unwrap(), b"untouched backing\n");
        }
    }
}

#[test]
fn busy_metadata_expires_with_named_elapsed_wait_and_no_late_mutation() {
    for scale in ["1", "2"] {
        let fixture = Fixture::new();
        let held = fixture.held_lock();
        let started = Instant::now();
        let output = OwnedChild::spawn(fixture.admission(scale)).finish(Duration::from_secs(13));
        assert_status(&output, 76);
        assert!(output.stdout.is_empty());
        let diagnostic = String::from_utf8(output.stderr).unwrap();
        assert!(diagnostic.contains("RCH_SOURCE_NAMESPACE_METADATA_LOCK_BUSY"));
        assert!(diagnostic.contains(&format!("lock={}", fixture.lock.display())));
        let millis: u64 = diagnostic
            .split("elapsed_ms=")
            .nth(1)
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .parse()
            .unwrap();
        assert!(millis >= if scale == "1" { 5000 } else { 10000 });
        assert!(started.elapsed() < Duration::from_secs(13));
        assert!(!fixture.mutation.exists());
        assert_eq!(
            std::fs::read(&fixture.lock).unwrap(),
            b"retained metadata\n"
        );
        drop(held);
        assert!(
            !fixture.mutation.exists(),
            "expired waiter admitted after lock release"
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn released_contention_execs_once_and_keeps_the_same_metadata_lock() {
    let fixture = Fixture::new();
    let held = fixture.held_lock();
    let mut child = OwnedChild::spawn(fixture.lock_command(
        "1",
        "printf admitted > \"$1\"; printf 'ADMITTED\\n'; IFS= read -r reply; [ \"$reply\" = done ]",
    ));
    child.wait_for_lock_open(&held);
    assert!(!fixture.mutation.exists());
    rustix::fs::flock(&held, FlockOperation::Unlock).unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while !fixture.mutation.exists() {
        assert!(child.child().try_wait().unwrap().is_none());
        assert!(Instant::now() < deadline, "no admission after unlock");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(std::fs::read(&fixture.mutation).unwrap(), b"admitted");
    assert!(matches!(
        rustix::fs::flock(&held, FlockOperation::NonBlockingLockExclusive),
        Err(rustix::io::Errno::AGAIN | rustix::io::Errno::ACCESS)
    ));
    child
        .child()
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"done\n")
        .unwrap();
    let output = child.finish(Duration::from_secs(3));
    assert_status(&output, 0);
    assert_eq!(output.stdout, b"ADMITTED\n");
    assert!(output.stderr.is_empty());
    rustix::fs::flock(&held, FlockOperation::NonBlockingLockExclusive).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn scaled_lock_wait_can_accept_release_after_the_default_deadline() {
    let fixture = Fixture::new();
    let held = fixture.held_lock();
    let mut child = OwnedChild::spawn(fixture.admission("2"));
    child.wait_for_lock_open(&held);
    std::thread::sleep(Duration::from_millis(5500));
    assert!(child.child().try_wait().unwrap().is_none());
    assert!(!fixture.mutation.exists());
    rustix::fs::flock(&held, FlockOperation::Unlock).unwrap();
    let output = child.finish(Duration::from_secs(5));
    assert_status(&output, 0);
    assert_eq!(output.stdout, b"ADMITTED\n");
    assert!(output.stderr.is_empty());
    assert_eq!(std::fs::read(&fixture.mutation).unwrap(), b"admitted");
}

#[cfg(target_os = "linux")]
#[test]
fn stopped_waiter_cannot_admit_after_its_deadline_even_if_lock_becomes_free() {
    let fixture = Fixture::new();
    let held = fixture.held_lock();
    let mut child = OwnedChild::spawn(fixture.admission("1"));
    child.wait_for_lock_open(&held);
    let pid = rustix::process::Pid::from_child(child.child());
    rustix::process::kill_process(pid, rustix::process::Signal::STOP).unwrap();
    std::thread::sleep(Duration::from_millis(5500));
    rustix::fs::flock(&held, FlockOperation::Unlock).unwrap();
    rustix::process::kill_process(pid, rustix::process::Signal::CONT).unwrap();
    let output = child.finish(Duration::from_secs(3));
    assert_status(&output, 76);
    assert!(output.stdout.is_empty());
    assert!(!fixture.mutation.exists());
    rustix::fs::flock(&held, FlockOperation::NonBlockingLockExclusive).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn replacing_a_waiting_lock_is_refused_without_mutating_either_inode() {
    let fixture = Fixture::new();
    let held = fixture.held_lock();
    let mut child = OwnedChild::spawn(fixture.admission("1"));
    child.wait_for_lock_open(&held);
    let old = fixture.root.path().join("old metadata");
    std::fs::rename(&fixture.lock, &old).unwrap();
    std::fs::write(&fixture.lock, b"replacement inode\n").unwrap();
    let output = child.finish(Duration::from_secs(3));
    assert_status(&output, 73);
    assert!(output.stdout.is_empty());
    let diagnostic = String::from_utf8_lossy(&output.stderr);
    assert!(diagnostic.contains("RCH_SOURCE_NAMESPACE_METADATA_LOCK_INVALID"));
    assert!(diagnostic.contains("changed"));
    assert!(!fixture.mutation.exists());
    assert_eq!(std::fs::read(old).unwrap(), b"retained metadata\n");
    assert_eq!(
        std::fs::read(&fixture.lock).unwrap(),
        b"replacement inode\n"
    );
    rustix::fs::flock(
        File::open(&fixture.lock).unwrap(),
        FlockOperation::NonBlockingLockExclusive,
    )
    .unwrap();
}

fn retry_command(fixture: &Fixture, seconds: u64, scale: &str, body: &str) -> Command {
    let program = format!(
        "{}\nrch_source_attempt() {{ ( set -eu; {body}\n); }}\nrch_admission_retry_seconds={seconds}\n{}",
        rch_common::wkr_locate::WKR_LOCATE_SHELL,
        include_str!("../../rch/src/hook/source_claim_admission.sh"),
    );
    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", &program, "rch-admission-retry"])
        .arg(&fixture.mutation)
        .env_clear()
        .env("PATH", "")
        .env("RCH_WKR_BIN", WORKER)
        .env("RCH_TIMING_SCALE", scale)
        .env("TOKIO_WORKER_THREADS", "0");
    command
}

#[test]
fn compiled_retry_keeps_slow_first_success_and_terminal_failure_semantics() {
    let fixture = Fixture::new();
    let started = Instant::now();
    let output = retry_command(&fixture, 1, "1", "/bin/sleep 1.3; printf owned")
        .output()
        .unwrap();
    assert_status(&output, 0);
    assert_eq!(output.stdout, b"owned");
    assert!(output.stderr.is_empty());
    assert!(started.elapsed() >= Duration::from_millis(1200));
    for status in [1, 73, 76, 137] {
        let output = retry_command(&fixture, 2, "1", &format!("printf attempt; exit {status}"))
            .output()
            .unwrap();
        assert_status(&output, status);
        assert_eq!(output.stdout, b"attempt");
    }
    let output = retry_command(&fixture, 2, "1", "false; printf invalid")
        .output()
        .unwrap();
    assert_status(&output, 1);
    assert!(output.stdout.is_empty());
}

#[test]
fn compiled_retry_preserves_unconfirmed_mutation_and_never_retries_it() {
    let fixture = Fixture::new();
    let body = "if [ ! -e \"$1\" ]; then printf first > \"$1\"; exit 75; fi; \
                printf admitted > \"$1\"; /bin/sleep 1.3; printf owned";
    let output = retry_command(&fixture, 2, "1", body).output().unwrap();
    assert_status(&output, 73);
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("RCH_SOURCE_ADMISSION_UNCONFIRMED cause=deadline-after-success")
    );
    // The enclosing namespace controller withholds these premature bytes. The
    // retry helper itself must preserve the terminal status and never retry.
    assert_eq!(std::fs::read(&fixture.mutation).unwrap(), b"admitted");
}

#[test]
fn missing_or_old_worker_refuses_before_any_admission_attempt() {
    let fixture = Fixture::new();
    for worker in ["/nonexistent/rch-wkr", "/bin/true"] {
        let output = retry_command(&fixture, 1, "1", "printf mutation > \"$1\"")
            .env("RCH_WKR_BIN", worker)
            .output()
            .unwrap();
        assert_status(&output, 73);
        assert!(output.stdout.is_empty());
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("RCH_SOURCE_ADMISSION_CLOCK_UNAVAILABLE")
        );
        assert!(!fixture.mutation.exists());
    }
}
