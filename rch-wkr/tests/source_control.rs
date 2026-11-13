//! Actual source-control child, pipe, lock and session regressions.

#![cfg(any(target_os = "linux", target_os = "macos"))]
#![forbid(unsafe_code)]

use std::ffi::OsStr;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd};
#[cfg(target_os = "linux")]
use std::path::Path;
use std::path::PathBuf;
use std::process::{Child, ChildStderr, ChildStdout, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use rustix::fs::FlockOperation;
use rustix::fs::OFlags;
#[cfg(target_os = "linux")]
use rustix::process::{Pid, Signal};

fn worker() -> PathBuf {
    std::env::var_os("RCH_WKR_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_rch-wkr")))
}

fn quote(value: impl AsRef<OsStr>) -> String {
    format!(
        "'{}'",
        value.as_ref().to_str().unwrap().replace('\'', "'\\''")
    )
}

fn root() -> PathBuf {
    tempfile::Builder::new()
        .prefix("rch-source-control-")
        .tempdir()
        .unwrap()
        .keep()
}

fn nonblocking(fd: impl AsFd) {
    let flags = rustix::fs::fcntl_getfl(&fd).unwrap();
    rustix::fs::fcntl_setfl(fd, flags | OFlags::NONBLOCK).unwrap();
}

struct Running {
    child: Child,
    stdout: ChildStdout,
    stderr: ChildStderr,
    out: Vec<u8>,
    err: Vec<u8>,
    status: Option<ExitStatus>,
}

impl Running {
    fn command(mut command: Command) -> Self {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        nonblocking(&stdout);
        nonblocking(&stderr);
        Self {
            child,
            stdout,
            stderr,
            out: Vec::new(),
            err: Vec::new(),
            status: None,
        }
    }

    fn new(contract: &str) -> Self {
        let mut command = Command::new(worker());
        command
            .args(["source-control", "--protocol", "v1", contract])
            .env_remove("RCH_TIMING_SCALE");
        Self::command(command)
    }

    fn upload(&mut self, script: &[u8], eof: bool) {
        nonblocking(self.child.stdin.as_ref().unwrap());
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut sent = 0;
        while sent < script.len() {
            assert!(
                Instant::now() < deadline,
                "controller stopped reading its upload"
            );
            match self.child.stdin.as_mut().unwrap().write(&script[sent..]) {
                Ok(0) => panic!("controller upload unexpectedly closed"),
                Ok(count) => sent += count,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5))
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => panic!("write controller upload: {error}"),
            }
        }
        if eof {
            self.child.stdin.take();
        }
    }

    fn drain(&mut self) {
        fn read(reader: &mut impl Read, bytes: &mut Vec<u8>) {
            let mut buffer = [0_u8; 8192];
            loop {
                match reader.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(count) => bytes.extend_from_slice(&buffer[..count]),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(error) => panic!("read controller: {error}"),
                }
            }
        }
        read(&mut self.stdout, &mut self.out);
        read(&mut self.stderr, &mut self.err);
    }

    fn finish(&mut self, seconds: u64) -> i32 {
        let end = Instant::now() + Duration::from_secs(seconds);
        loop {
            self.drain();
            if self.status.is_none() {
                self.status = self.child.try_wait().unwrap();
            }
            if let Some(status) = self.status {
                self.drain();
                return status.code().unwrap_or(-1);
            }
            assert!(
                Instant::now() < end,
                "controller did not finish; stdout={:?}, stderr={}",
                self.out,
                String::from_utf8_lossy(&self.err)
            );
            thread::sleep(Duration::from_millis(5));
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.child.stdin.take();
        if self.status.is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn wait_child(child: &mut Child, seconds: u64) -> ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(seconds);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "controller exceeded its delivery budget"
        );
        thread::sleep(Duration::from_millis(5));
    }
}

#[cfg(target_os = "linux")]
fn wait_file(path: &Path) -> String {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(contents) = std::fs::read_to_string(path)
            && contents.ends_with('\n')
        {
            return contents;
        }
        assert!(
            Instant::now() < deadline,
            "fixture never wrote {}",
            path.display()
        );
        thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn all_exact_reply_contracts_and_native_probe() {
    let probe = Command::new(worker())
        .args(["source-control", "probe"])
        .output()
        .unwrap();
    assert!(probe.status.success());
    assert_eq!(probe.stdout, b"rch-wkr source-control v1\n");
    assert!(probe.stderr.is_empty());
    for (contract, reply) in [
        ("RCH_TOPOLOGY_OK", "RCH_TOPOLOGY_OK\n"),
        (
            "RCH_SOURCE_CANCELLATION_SETTLED",
            "RCH_SOURCE_CANCELLATION_SETTLED\n",
        ),
        (
            "RCH_SOURCE_AUTHORITY_NAMESPACE",
            "RCH_SOURCE_AUTHORITY_NAMESPACE current\n",
        ),
        (
            "RCH_SOURCE_AUTHORITY_NAMESPACE",
            "RCH_SOURCE_AUTHORITY_NAMESPACE legacy\n",
        ),
        (
            "RCH_SOURCE_AUTHORITY_DISCOVERY",
            "RCH_SOURCE_AUTHORITY_DISCOVERY current\n",
        ),
        (
            "RCH_SOURCE_AUTHORITY_DISCOVERY",
            "RCH_SOURCE_AUTHORITY_DISCOVERY legacy\n",
        ),
        (
            "RCH_SOURCE_AUTHORITY_DISCOVERY",
            "RCH_SOURCE_AUTHORITY_DISCOVERY absent\n",
        ),
        ("RCH_SOURCE_INTENT_CANCEL", "owned"),
        ("RCH_SOURCE_INTENT_CANCEL", "unowned"),
        ("RCH_SOURCE_INTENT_RELEASED", "released"),
        ("RCH_SOURCE_INTENT_RELEASED", "pending"),
        ("RCH_SOURCE_INTENT_CANCELLED", "cancelled"),
        ("RCH_SOURCE_INTENT_CANCELLED", "pending"),
        ("RCH_SOURCE_INTENT_CANCELLATION_STATE", "cancellation"),
        ("RCH_SOURCE_INTENT_CANCELLATION_STATE", "pending"),
        ("RCH_SOURCE_INTENT_FINISHED", ""),
    ] {
        let mut running = Running::new(contract);
        running.upload(format!("printf %s {}\n", quote(reply)).as_bytes(), true);
        assert_eq!(
            running.finish(5),
            0,
            "{contract}: {}",
            String::from_utf8_lossy(&running.err)
        );
        assert_eq!(running.out, reply.as_bytes(), "{contract}");
        assert!(running.err.is_empty(), "{contract}: {:?}", running.err);
    }
}

#[test]
fn validates_protocol_contract_and_scale_before_program_launch() {
    let directory = root();
    let launched = directory.join("launched");
    for arguments in [
        vec!["source-control", "--protocol", "v2", "RCH_TOPOLOGY_OK"],
        vec!["source-control", "--protocol", "v1", "UNKNOWN"],
        vec!["source-control", "RCH_TOPOLOGY_OK"],
    ] {
        let mut command = Command::new(worker());
        command.args(arguments);
        let mut running = Running::command(command);
        let _ = running
            .child
            .stdin
            .take()
            .unwrap()
            .write_all(format!("touch {}\n", quote(&launched)).as_bytes());
        assert_eq!(running.finish(3), 73);
        assert!(running.out.is_empty());
        assert!(!launched.exists());
    }
    for value in [
        "",
        "nan",
        "inf",
        "0.9",
        "10.1",
        "1;touch nope",
        " 1",
        "1\n",
        "1e999",
    ] {
        let mut command = Command::new(worker());
        command
            .args(["source-control", "--protocol", "v1", "RCH_TOPOLOGY_OK"])
            .env("RCH_TIMING_SCALE", value);
        let mut running = Running::command(command);
        let _ = running
            .child
            .stdin
            .take()
            .unwrap()
            .write_all(format!("touch {}\n", quote(&launched)).as_bytes());
        assert_eq!(running.finish(3), 73, "{value:?}");
        assert!(running.out.is_empty());
        assert!(String::from_utf8_lossy(&running.err).contains("invalid RCH_TIMING_SCALE"));
        assert!(!launched.exists());
    }
}

#[test]
fn invalid_readiness_is_suppressed_and_nonzero_status_is_preserved() {
    for (script, status, stderr) in [
        ("printf owned\\n\n", 73, "invalid readiness"),
        (
            "printf owned; printf conflict\\n >&2; exit 75\n",
            75,
            "conflict",
        ),
        ("printf owned; exit 2\n", 2, ""),
        ("printf owned; exit 137\n", 137, "signal_origin=unknown"),
        (
            "printf owned; kill -KILL $$\n",
            137,
            "signal_origin=unknown",
        ),
    ] {
        let mut running = Running::new("RCH_SOURCE_INTENT_CANCEL");
        running.upload(script.as_bytes(), true);
        assert_eq!(
            running.finish(5),
            status,
            "{}",
            String::from_utf8_lossy(&running.err)
        );
        assert!(running.out.is_empty());
        assert!(String::from_utf8_lossy(&running.err).contains(stderr));
    }
}

#[test]
fn exact_output_caps_accept_complete_bytes_and_refuse_one_byte_over() {
    for (count, code) in [(65_536, 0), (65_537, 73)] {
        let mut running = Running::new("RCH_SOURCE_INTENT_CANCEL");
        running.upload(
            format!("head -c {count} /dev/zero >&2\nprintf owned\n").as_bytes(),
            true,
        );
        assert_eq!(running.finish(5), code);
        if code == 0 {
            assert_eq!(running.out, b"owned");
            assert_eq!(running.err, vec![0; count]);
        } else {
            assert!(running.out.is_empty());
            assert!(String::from_utf8_lossy(&running.err).contains("byte bound"));
        }
    }
    for (count, code) in [(4096, 75), (4097, 73)] {
        let mut running = Running::new("RCH_SOURCE_INTENT_FINISHED");
        running.upload(
            format!("head -c {count} /dev/zero\nexit 75\n").as_bytes(),
            true,
        );
        assert_eq!(running.finish(5), code);
        assert!(running.out.is_empty());
        if count == 4097 {
            assert!(String::from_utf8_lossy(&running.err).contains("byte bound"));
        }
    }
}

#[test]
fn upload_exceeds_argv_limit_and_preserves_inherited_authority_descriptor() {
    let directory = root();
    let path = directory.join("authority");
    std::fs::write(&path, b"authority").unwrap();
    let authority = File::open(&path).unwrap();
    let inherited = rustix::io::fcntl_dupfd_cloexec(&authority, 64).unwrap();
    rustix::io::fcntl_setfd(&inherited, rustix::io::FdFlags::empty()).unwrap();
    let mut command = Command::new(worker());
    command
        .args([
            "source-control",
            "--protocol",
            "v1",
            "RCH_SOURCE_INTENT_CANCEL",
        ])
        .env("RCH_TEST_AUTHORITY_FD", inherited.as_raw_fd().to_string())
        .env_remove("RCH_TIMING_SCALE");
    let mut running = Running::command(command);
    drop(inherited);
    let mut program = b"# native streaming upload\n".repeat(140_000);
    program.extend_from_slice(
        b"test \"$(cat /dev/fd/$RCH_TEST_AUTHORITY_FD)\" = authority || exit 91\nprintf owned\n",
    );
    assert!(program.len() > 3_000_000);
    running.upload(&program, true);
    assert_eq!(
        running.finish(8),
        0,
        "{}",
        String::from_utf8_lossy(&running.err)
    );
    assert_eq!(running.out, b"owned");
}

#[test]
fn ignored_and_blocked_sigchld_do_not_auto_reap_guardian() {
    use nix::sys::signal::{SigSet, SigmaskHow, Signal as NixSignal, pthread_sigmask};
    let mut blocked = SigSet::empty();
    blocked.add(NixSignal::SIGCHLD);
    let mut original = SigSet::empty();
    pthread_sigmask(SigmaskHow::SIG_BLOCK, Some(&blocked), Some(&mut original)).unwrap();
    let mut command = Command::new("/bin/sh");
    command
        .args([
            "-c",
            "trap '' CHLD; exec \"$1\" source-control --protocol v1 RCH_SOURCE_INTENT_CANCEL",
            "rch-source-signals",
        ])
        .arg(worker())
        .env_remove("RCH_TIMING_SCALE");
    let mut running = Running::command(command);
    pthread_sigmask(SigmaskHow::SIG_SETMASK, Some(&original), None).unwrap();
    running.upload(b"printf owned\n", true);
    assert_eq!(
        running.finish(5),
        0,
        "{}",
        String::from_utf8_lossy(&running.err)
    );
    assert_eq!(running.out, b"owned");
}

#[test]
fn stalled_diagnostic_delivery_never_releases_readiness() {
    // Pipe capacities differ by host. Fill this actual stderr description to
    // EAGAIN first, so even a small diagnostic must encounter backpressure.
    let (_read, write) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
    let original = rustix::fs::fcntl_getfl(&write).unwrap();
    nonblocking(&write);
    loop {
        match rustix::io::write(&write, &[b'x'; 4096]) {
            Ok(_) => {}
            Err(rustix::io::Errno::AGAIN) => break,
            Err(error) => panic!("fill real diagnostic pipe: {error}"),
        }
    }
    rustix::fs::fcntl_setfl(&write, original).unwrap();
    let child = Command::new(worker())
        .args([
            "source-control",
            "--protocol",
            "v1",
            "RCH_SOURCE_INTENT_CANCEL",
        ])
        .env_remove("RCH_TIMING_SCALE")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::from(
            rustix::io::fcntl_dupfd_cloexec(&write, 3).unwrap(),
        ))
        .spawn()
        .unwrap();
    let mut child = ChildGuard(child);
    child
        .0
        .stdin
        .take()
        .unwrap()
        .write_all(b"printf diagnostic >&2\nprintf owned\n")
        .unwrap();
    assert_eq!(wait_child(&mut child.0, 5).code(), Some(73));
    let mut stdout = Vec::new();
    child
        .0
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut stdout)
        .unwrap();
    assert!(
        stdout.is_empty(),
        "readiness preceded full diagnostic delivery"
    );
    assert_eq!(rustix::fs::fcntl_getfl(&write).unwrap(), original);
}

#[test]
fn delivery_restores_callers_shared_output_flags_on_success_and_refusal() {
    for program in ["printf owned\n", "printf invalid\n"] {
        let (_stdout_read, stdout_write) =
            rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
        let (_stderr_read, stderr_write) =
            rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
        let out_flags = rustix::fs::fcntl_getfl(&stdout_write).unwrap();
        let err_flags = rustix::fs::fcntl_getfl(&stderr_write).unwrap();
        let child = Command::new(worker())
            .args([
                "source-control",
                "--protocol",
                "v1",
                "RCH_SOURCE_INTENT_CANCEL",
            ])
            .env_remove("RCH_TIMING_SCALE")
            .stdin(Stdio::piped())
            .stdout(Stdio::from(
                rustix::io::fcntl_dupfd_cloexec(&stdout_write, 3).unwrap(),
            ))
            .stderr(Stdio::from(
                rustix::io::fcntl_dupfd_cloexec(&stderr_write, 3).unwrap(),
            ))
            .spawn()
            .unwrap();
        let mut child = ChildGuard(child);
        child
            .0
            .stdin
            .take()
            .unwrap()
            .write_all(program.as_bytes())
            .unwrap();
        assert_eq!(
            wait_child(&mut child.0, 5).code(),
            Some(if program.contains("invalid") { 73 } else { 0 })
        );
        assert_eq!(rustix::fs::fcntl_getfl(&stdout_write).unwrap(), out_flags);
        assert_eq!(rustix::fs::fcntl_getfl(&stderr_write).unwrap(), err_flags);
    }
}

#[test]
fn stalled_readiness_delivery_is_bounded_and_restores_flags() {
    let (_read, write) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
    let original = rustix::fs::fcntl_getfl(&write).unwrap();
    nonblocking(&write);
    loop {
        match rustix::io::write(&write, &[b'x'; 4096]) {
            Ok(_) => {}
            Err(rustix::io::Errno::AGAIN) => break,
            Err(error) => panic!("fill real output pipe: {error}"),
        }
    }
    rustix::fs::fcntl_setfl(&write, original).unwrap();
    let child = Command::new(worker())
        .args([
            "source-control",
            "--protocol",
            "v1",
            "RCH_SOURCE_INTENT_CANCEL",
        ])
        .env_remove("RCH_TIMING_SCALE")
        .stdin(Stdio::piped())
        .stdout(Stdio::from(
            rustix::io::fcntl_dupfd_cloexec(&write, 3).unwrap(),
        ))
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut child = ChildGuard(child);
    child
        .0
        .stdin
        .take()
        .unwrap()
        .write_all(b"printf owned\n")
        .unwrap();
    assert_eq!(wait_child(&mut child.0, 5).code(), Some(73));
    assert_eq!(rustix::fs::fcntl_getfl(&write).unwrap(), original);
}

#[test]
fn delivery_accepts_writable_null_devices_without_polling_them() {
    for discard_stdout in [false, true] {
        let child = Command::new(worker())
            .args([
                "source-control",
                "--protocol",
                "v1",
                "RCH_SOURCE_INTENT_CANCEL",
            ])
            .env_remove("RCH_TIMING_SCALE")
            .stdin(Stdio::piped())
            .stdout(if discard_stdout {
                Stdio::null()
            } else {
                Stdio::piped()
            })
            .stderr(if discard_stdout {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .spawn()
            .unwrap();
        let mut child = ChildGuard(child);
        child
            .0
            .stdin
            .take()
            .unwrap()
            .write_all(b"printf diagnostic >&2\nprintf owned\n")
            .unwrap();
        assert_eq!(wait_child(&mut child.0, 5).code(), Some(0));
        let mut bytes = Vec::new();
        if discard_stdout {
            child
                .0
                .stderr
                .take()
                .unwrap()
                .read_to_end(&mut bytes)
                .unwrap();
            assert_eq!(bytes, b"diagnostic");
        } else {
            child
                .0
                .stdout
                .take()
                .unwrap()
                .read_to_end(&mut bytes)
                .unwrap();
            assert_eq!(bytes, b"owned");
        }
    }
}

#[test]
fn incomplete_uploaded_stdin_expires_and_timing_scale_extends_execution() {
    let mut normal = Running::new("RCH_SOURCE_INTENT_CANCEL");
    let mut command = Command::new(worker());
    command
        .args([
            "source-control",
            "--protocol",
            "v1",
            "RCH_SOURCE_INTENT_CANCEL",
        ])
        .env("RCH_TIMING_SCALE", "2");
    let mut extended = Running::command(command);
    normal.upload(b"printf owned\n", false);
    extended.upload(b"printf owned\n", false);
    let started = Instant::now();
    assert_eq!(normal.finish(19), 73);
    assert!(started.elapsed() >= Duration::from_secs(14));
    assert!(
        normal.out.is_empty(),
        "valid bytes without program EOF are insufficient"
    );
    extended.drain();
    assert!(extended.out.is_empty());
    assert!(
        extended.child.try_wait().unwrap().is_none(),
        "scale two must still own its running program"
    );
    // Complete the real upload after the normal budget. The extended guardian
    // must still execute and settle it, not merely defer a refusal.
    extended.child.stdin.take();
    assert_eq!(
        extended.finish(5),
        0,
        "{}",
        String::from_utf8_lossy(&extended.err)
    );
    assert_eq!(extended.out, b"owned");
}

#[cfg(target_os = "linux")]
struct Fixture(rustix::fd::OwnedFd);

#[cfg(target_os = "linux")]
impl Fixture {
    fn from_file(path: &Path) -> Self {
        let pid = Pid::from_raw(wait_file(path).trim().parse().unwrap()).unwrap();
        Self(rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()).unwrap())
    }

    fn signal(&self, signal: Signal) {
        rustix::process::pidfd_send_signal(&self.0, signal).unwrap();
    }

    fn dead(&self) -> bool {
        let mut descriptor = [rustix::event::PollFd::new(
            &self.0,
            rustix::event::PollFlags::IN,
        )];
        rustix::event::poll(
            &mut descriptor,
            Some(&rustix::event::Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            }),
        )
        .unwrap();
        !descriptor[0].revents().is_empty()
    }

    fn wait_dead(&self, seconds: u64) {
        let end = Instant::now() + Duration::from_secs(seconds);
        while !self.dead() {
            assert!(
                Instant::now() < end,
                "owned fixture survived controller teardown"
            );
            thread::sleep(Duration::from_millis(5));
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = rustix::process::pidfd_send_signal(&self.0, Signal::KILL);
    }
}

#[cfg(target_os = "linux")]
fn fixture_script(directory: &Path, escape: bool, finish: &str) -> String {
    fixture_script_with_output(directory, escape, finish, false)
}

#[cfg(target_os = "linux")]
fn fixture_script_with_output(
    directory: &Path,
    escape: bool,
    finish: &str,
    hold_output: bool,
) -> String {
    format!(
        "printf '%s\\n' \"$PPID\" > {guardian}\nRCH_SOURCE_CONTROL_FIXTURE={root} RCH_SOURCE_CONTROL_ESCAPE={escape} {test} --ignored --exact process_fixture --nocapture {pipes}>/dev/null 2>&1 &\nwhile [ ! -s {pid} ]; do sleep 0.01; done\n{finish}\n",
        guardian = quote(directory.join("guardian")),
        root = quote(directory),
        escape = if escape { "1" } else { "0" },
        test = quote(std::env::current_exe().unwrap()),
        pid = quote(directory.join("pid")),
        pipes = if hold_output { "3>&1 4>&2 " } else { "" },
    )
}

#[cfg(target_os = "linux")]
#[test]
fn quiet_term_resistant_lock_holder_is_dead_before_success_or_conflict() {
    for (finish, code) in [
        ("printf owned", 0),
        ("printf owned; printf busy >&2; exit 75", 75),
    ] {
        let directory = root();
        let mut running = Running::new("RCH_SOURCE_INTENT_CANCEL");
        running.upload(
            fixture_script(&directory, false, &format!("sleep 0.2\n{finish}")).as_bytes(),
            true,
        );
        let fixture = Fixture::from_file(&directory.join("pid"));
        assert_eq!(
            running.finish(5),
            code,
            "{}",
            String::from_utf8_lossy(&running.err)
        );
        assert!(fixture.dead(), "readiness preceded quiet descendant death");
        let lock = File::open(directory.join("lock")).unwrap();
        rustix::fs::flock(&lock, FlockOperation::NonBlockingLockExclusive).unwrap();
        if code == 0 {
            assert_eq!(running.out, b"owned");
        } else {
            assert!(running.out.is_empty());
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn inherited_output_pipe_holder_expires_and_releases_its_actual_lock() {
    let directory = root();
    let mut running = Running::new("RCH_SOURCE_INTENT_CANCEL");
    running.upload(
        fixture_script_with_output(&directory, false, "printf owned", true).as_bytes(),
        true,
    );
    let fixture = Fixture::from_file(&directory.join("pid"));
    assert_eq!(running.finish(19), 73);
    assert!(
        running.out.is_empty(),
        "an open descendant pipe is not complete output"
    );
    fixture.wait_dead(2);
    let lock = File::open(directory.join("lock")).unwrap();
    rustix::fs::flock(&lock, FlockOperation::NonBlockingLockExclusive).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn killed_or_stopped_guardian_never_authorizes_readiness() {
    for signal in [Signal::KILL, Signal::STOP] {
        let directory = root();
        let mut running = Running::new("RCH_SOURCE_INTENT_CANCEL");
        running.upload(
            fixture_script(&directory, false, "printf owned; wait").as_bytes(),
            true,
        );
        let fixture = Fixture::from_file(&directory.join("pid"));
        let guardian = Fixture::from_file(&directory.join("guardian"));
        guardian.signal(signal);
        assert_eq!(running.finish(5), 73);
        assert!(running.out.is_empty());
        fixture.wait_dead(2);
        guardian.wait_dead(2);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn observer_death_revokes_guardian_and_quiet_descendants() {
    let directory = root();
    let mut running = Running::new("RCH_SOURCE_INTENT_CANCEL");
    running.upload(fixture_script(&directory, false, "wait").as_bytes(), true);
    let fixture = Fixture::from_file(&directory.join("pid"));
    let guardian = Fixture::from_file(&directory.join("guardian"));
    running.child.kill().unwrap();
    running.status = Some(running.child.wait().unwrap());
    fixture.wait_dead(3);
    guardian.wait_dead(3);
    running.drain();
    assert!(running.out.is_empty());
}

#[cfg(target_os = "linux")]
#[test]
fn stopped_observer_cannot_suspend_guardian_deadline() {
    let directory = root();
    let mut running = Running::new("RCH_SOURCE_INTENT_CANCEL");
    running.upload(fixture_script(&directory, false, "wait").as_bytes(), true);
    let fixture = Fixture::from_file(&directory.join("pid"));
    let guardian = Fixture::from_file(&directory.join("guardian"));
    rustix::process::kill_process(Pid::from_child(&running.child), Signal::STOP).unwrap();
    fixture.wait_dead(18);
    guardian.wait_dead(2);
    assert!(
        running.child.try_wait().unwrap().is_none(),
        "observer must really remain stopped"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn changed_process_group_in_owned_session_refuses_completion() {
    let directory = root();
    let mut running = Running::new("RCH_SOURCE_INTENT_CANCEL");
    running.upload(
        fixture_script(&directory, true, "printf owned").as_bytes(),
        true,
    );
    let fixture = Fixture::from_file(&directory.join("pid"));
    assert_eq!(running.finish(19), 73);
    assert!(
        running.out.is_empty(),
        "a live session sibling prevents complete teardown"
    );
    assert!(
        !fixture.dead(),
        "a census does not gain signal authority over an escaped group"
    );
    fixture.signal(Signal::KILL);
    fixture.wait_dead(2);
}

#[cfg(target_os = "linux")]
fn wait_checker(observer: &Child) -> Fixture {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        // Some supported kernels omit /proc/PID/task/TID/children. The parent
        // stat field still binds this test observation to our owned controller.
        for entry in std::fs::read_dir("/proc").unwrap().flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<i32>().ok())
            else {
                continue;
            };
            let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) else {
                continue;
            };
            let Some((_, fields)) = stat.rsplit_once(") ") else {
                continue;
            };
            let fields: Vec<_> = fields.split_ascii_whitespace().collect();
            if fields.len() < 20 || fields[1].parse::<u32>().ok() != Some(observer.id()) {
                continue;
            }
            let Ok(arguments) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
                continue;
            };
            if arguments
                .split(|byte| *byte == 0)
                .any(|argument| argument == b"--checker")
                && let Ok(descriptor) = rustix::process::pidfd_open(
                    Pid::from_raw(pid).unwrap(),
                    rustix::process::PidfdFlags::empty(),
                )
            {
                // Verify the birth and parent again after binding the
                // pidfd. No reused numeric PID authorizes a test signal.
                let Ok(current) = std::fs::read_to_string(entry.path().join("stat")) else {
                    continue;
                };
                let Some((_, current)) = current.rsplit_once(") ") else {
                    continue;
                };
                let current: Vec<_> = current.split_ascii_whitespace().collect();
                if current.len() >= 20 && current[1] == fields[1] && current[19] == fields[19] {
                    return Fixture(descriptor);
                }
            }
        }
        assert!(
            Instant::now() < deadline,
            "actual bounded session checker never started"
        );
        thread::sleep(Duration::from_millis(5));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn stopped_or_killed_census_never_authorizes_readiness() {
    for signal in [Signal::STOP, Signal::KILL] {
        let directory = root();
        let mut running = Running::new("RCH_SOURCE_INTENT_CANCEL");
        running.upload(
            fixture_script(&directory, true, "printf owned").as_bytes(),
            true,
        );
        let fixture = Fixture::from_file(&directory.join("pid"));
        let checker = wait_checker(&running.child);
        checker.signal(signal);
        assert_eq!(running.finish(5), 73);
        assert!(running.out.is_empty());
        checker.wait_dead(2);
        assert!(
            !fixture.dead(),
            "census revocation must not target an enumerated process"
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn census_has_independent_owner_death_and_deadline_enforcement() {
    for signal in [Signal::KILL, Signal::STOP] {
        let directory = root();
        let mut running = Running::new("RCH_SOURCE_INTENT_CANCEL");
        running.upload(
            fixture_script(&directory, true, "printf owned").as_bytes(),
            true,
        );
        let fixture = Fixture::from_file(&directory.join("pid"));
        let checker = wait_checker(&running.child);
        rustix::process::kill_process(Pid::from_child(&running.child), signal).unwrap();
        checker.wait_dead(if signal == Signal::STOP { 18 } else { 3 });
        running.drain();
        assert!(running.out.is_empty());
        assert!(
            !fixture.dead(),
            "checker lifetime never grants foreign signal authority"
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "native child process for source-control lifetime regressions"]
fn process_fixture() {
    let directory = PathBuf::from(std::env::var_os("RCH_SOURCE_CONTROL_FIXTURE").unwrap());
    if std::env::var("RCH_SOURCE_CONTROL_ESCAPE").unwrap() == "1" {
        rustix::process::setpgid(None, None).unwrap();
    }
    signal_hook::flag::register(
        signal_hook::consts::SIGTERM,
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    )
    .unwrap();
    let lock = File::options()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(directory.join("lock"))
        .unwrap();
    rustix::fs::flock(&lock, FlockOperation::NonBlockingLockExclusive).unwrap();
    std::fs::write(directory.join("pid"), format!("{}\n", std::process::id())).unwrap();
    loop {
        thread::sleep(Duration::from_secs(1));
    }
}
