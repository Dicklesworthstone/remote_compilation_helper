//! Real pipe, process-group and flock coverage for the native source holder.

#![cfg(unix)]
#![forbid(unsafe_code)]

use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::fs::symlink;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdout, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use nix::sys::signal::{SigSet, Signal as NixSignal};
use rustix::fs::{FlockOperation, OFlags};
use rustix::io::Errno;
use rustix::process::{Pid, Signal};

const WORKER: &str = env!("CARGO_BIN_EXE_rch-wkr");
const READY: &[u8] = b"GRANTED\n";

fn quote(value: impl AsRef<OsStr>) -> String {
    format!(
        "'{}'",
        value.as_ref().to_str().unwrap().replace('\'', "'\\''")
    )
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
    fn from_command(mut command: Command) -> Self {
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

    fn drain(&mut self) {
        fn read_available(reader: &mut impl Read, destination: &mut Vec<u8>) {
            let mut bytes = [0_u8; 8192];
            loop {
                match reader.read(&mut bytes) {
                    Ok(0) => return,
                    Ok(count) => destination.extend_from_slice(&bytes[..count]),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return,
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(error) => panic!("read child output: {error}"),
                }
            }
        }
        read_available(&mut self.stdout, &mut self.out);
        read_available(&mut self.stderr, &mut self.err);
    }

    fn wait_for(&mut self, marker: &[u8]) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            self.drain();
            if self
                .out
                .windows(marker.len())
                .any(|window| window == marker)
            {
                return;
            }
            self.status = self.child.try_wait().unwrap();
            assert!(
                self.status.is_none(),
                "exited before {marker:?}: {:?}; {}",
                self.status,
                String::from_utf8_lossy(&self.err)
            );
            assert!(
                Instant::now() < deadline,
                "missing marker {marker:?}: {}; {}",
                String::from_utf8_lossy(&self.out),
                String::from_utf8_lossy(&self.err)
            );
            thread::sleep(Duration::from_millis(5));
        }
    }

    fn assert_silent_for(&mut self, duration: Duration) {
        let deadline = Instant::now() + duration;
        while Instant::now() < deadline {
            self.drain();
            assert!(
                self.out.is_empty(),
                "premature grant: {}",
                String::from_utf8_lossy(&self.out)
            );
            self.status = self.child.try_wait().unwrap();
            assert!(
                self.status.is_none(),
                "premature exit {:?}: {}",
                self.status,
                String::from_utf8_lossy(&self.err)
            );
            thread::sleep(Duration::from_millis(5));
        }
    }

    fn finish(&mut self, expected: i32) {
        let deadline = Instant::now() + Duration::from_secs(7);
        loop {
            self.drain();
            if self.status.is_none() {
                self.status = self.child.try_wait().unwrap();
            }
            if let Some(status) = self.status {
                self.drain();
                assert_eq!(
                    status.code(),
                    Some(expected),
                    "stdout={}; stderr={}",
                    String::from_utf8_lossy(&self.out),
                    String::from_utf8_lossy(&self.err)
                );
                return;
            }
            assert!(
                Instant::now() < deadline,
                "holder did not finish: stdout={}; stderr={}",
                String::from_utf8_lossy(&self.out),
                String::from_utf8_lossy(&self.err)
            );
            thread::sleep(Duration::from_millis(5));
        }
    }

    fn send(&mut self, bytes: &[u8]) {
        self.child.stdin.as_mut().unwrap().write_all(bytes).unwrap();
    }

    fn disconnect(&mut self) {
        self.child.stdin.take();
    }

    fn monitor_pid(&mut self) -> Pid {
        self.wait_for(b"MONITOR:");
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            self.drain();
            for line in self.out.split_inclusive(|byte| *byte == b'\n') {
                if let Some(number) = line
                    .strip_prefix(b"MONITOR:")
                    .and_then(|n| n.strip_suffix(b"\n"))
                {
                    return Pid::from_raw(std::str::from_utf8(number).unwrap().parse().unwrap())
                        .unwrap();
                }
            }
            assert!(Instant::now() < deadline, "incomplete monitor pid");
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

fn with_plan(
    program: &Path,
    arguments: &[&OsStr],
    claims: Option<&Path>,
    ignore_child: bool,
) -> Command {
    let mut command = Command::new("sh");
    command
        .arg("-c")
        .arg(format!(
            "{}exec 3< \"$1\"; exec 4< \"$2\"; shift 2; exec \"$@\"",
            if ignore_child { "trap '' CHLD; " } else { "" },
        ))
        .arg("source-lock-test")
        .arg(program)
        .arg(claims.unwrap_or_else(|| Path::new("/dev/null")))
        .arg(WORKER)
        .arg("source-lock")
        .args(arguments);
    command
}

fn acquire(owner: &Path, name: &str, bytes: &[u8], count: &str) -> Running {
    let input = owner.join(format!("{name}.plan"));
    std::fs::write(&input, bytes).unwrap();
    Running::from_command(with_plan(
        &input,
        &[OsStr::new(count), OsStr::new("GRANTED")],
        None,
        false,
    ))
}

fn lock_file(path: &Path) -> File {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .unwrap()
}

fn exclusive(file: &File) {
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        match rustix::fs::flock(file, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => return,
            Err(Errno::AGAIN | Errno::ACCESS) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(5));
            }
            result => {
                panic!("source prefix remained reserved while a dependency was busy: {result:?}")
            }
        }
    }
}

fn assert_locked(path: &Path) {
    assert!(matches!(
        rustix::fs::flock(lock_file(path), FlockOperation::NonBlockingLockExclusive),
        Err(Errno::AGAIN | Errno::ACCESS)
    ));
}

fn assert_released(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(2);
    let file = lock_file(path);
    loop {
        match rustix::fs::flock(&file, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => return,
            Err(Errno::AGAIN | Errno::ACCESS) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(5))
            }
            result => panic!("descendant retained lock after teardown: {result:?}"),
        }
    }
}

fn session(owner: &Path, name: &str, program: &[u8], mode: &str, budget: &str) -> Running {
    let input = owner.join(format!("{name}.program"));
    std::fs::write(&input, program).unwrap();
    Running::from_command(with_plan(
        &input,
        &[OsStr::new(mode), OsStr::new(budget)],
        None,
        false,
    ))
}

fn holder_program(owner: &Path, terminal: &str) -> (PathBuf, String) {
    let lock = owner.join("source.lock");
    let plan = owner.join("source.plan");
    std::fs::write(&plan, format!("x {}\n", lock.display())).unwrap();
    let program = format!(
        "exec 3< {}; exec {} source-lock 1 GRANTED {}",
        quote(&plan),
        quote(WORKER),
        quote(terminal),
    );
    (lock, program)
}

const HOLD_AND_RELEASE: &str = "printf '%s\n' \"$1\"; printf 'MONITOR:%s\n' \"$PPID\"; sleep 300 & IFS= read -r release; [ \"$release\" = RCH_SOURCE_AUTHORITY_RELEASE:abc-123 ] || exit 61; exit 27";

#[test]
fn native_probe_is_exact_and_quiet() {
    let output = Command::new(WORKER)
        .args(["source-lock", "probe"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"rch-wkr source-lock v1\n");
    assert!(output.stderr.is_empty(), "{output:?}");
}

#[test]
fn malformed_plans_and_duplicate_physical_locks_never_grant() {
    let owner = tempfile::tempdir().unwrap();
    for (index, plan) in [
        b"x /missing-newline".as_slice(),
        b"x relative\n",
        b"q /wrong-mode\n",
        b"x /nul\0\n",
        b"x /carriage\r\n",
        b"x /extra\nx /row\n",
    ]
    .iter()
    .enumerate()
    {
        let mut holder = acquire(owner.path(), &format!("invalid-{index}"), plan, "1");
        holder.finish(73);
        assert!(holder.out.is_empty());
    }
    let original = owner.path().join("original");
    let alias = owner.path().join("alias");
    std::fs::write(&original, b"").unwrap();
    std::fs::hard_link(&original, &alias).unwrap();
    for mode in ["x", "s"] {
        let mut holder = acquire(
            owner.path(),
            mode,
            format!(
                "{mode} {}\n{mode} {}\n",
                original.display(),
                alias.display()
            )
            .as_bytes(),
            "2",
        );
        holder.finish(73);
        assert!(holder.out.is_empty());
        assert!(String::from_utf8_lossy(&holder.err).contains("duplicate source lock inode"));
    }
    let linked = owner.path().join("linked");
    symlink(&original, &linked).unwrap();
    let mut holder = acquire(
        owner.path(),
        "symlink",
        format!("x {}\n", linked.display()).as_bytes(),
        "1",
    );
    holder.finish(73);
    assert!(holder.out.is_empty());
    assert_released(&original);
}

#[test]
fn shared_holders_coexist_and_exclusive_holder_waits_for_every_reader() {
    let owner = tempfile::tempdir().unwrap();
    let path = owner.path().join("shared.lock");
    let shared = format!("s {}\n", path.display());
    let mut first = acquire(owner.path(), "first", shared.as_bytes(), "1");
    first.wait_for(READY);
    let mut second = acquire(owner.path(), "second", shared.as_bytes(), "1");
    second.wait_for(READY);
    let mut writer = acquire(
        owner.path(),
        "writer",
        format!("x {}\n", path.display()).as_bytes(),
        "1",
    );
    writer.assert_silent_for(Duration::from_millis(100));
    first.disconnect();
    first.finish(0);
    writer.assert_silent_for(Duration::from_millis(100));
    second.disconnect();
    second.finish(0);
    writer.wait_for(READY);
    assert_locked(&path);
    writer.disconnect();
    writer.finish(0);
    assert_released(&path);
}

#[test]
fn busy_dependency_releases_the_complete_prefix_and_cancellation_grants_nothing() {
    let owner = tempfile::tempdir().unwrap();
    let prefix = owner.path().join("z-first.lock");
    let dependency = owner.path().join("a-busy.lock");
    let blocker = lock_file(&dependency);
    exclusive(&blocker);
    let mut holder = acquire(
        owner.path(),
        "closure",
        format!("x {}\nx {}\n", prefix.display(), dependency.display()).as_bytes(),
        "2",
    );
    holder.assert_silent_for(Duration::from_millis(150));
    let independent = lock_file(&prefix);
    exclusive(&independent);
    // A blocked closure has not reserved its earlier root. Its reader may
    // also disconnect without waiting for the conflicting dependency.
    holder.disconnect();
    holder.finish(73);
    assert!(holder.out.is_empty());
    assert!(String::from_utf8_lossy(&holder.err).contains("requester ended"));
    drop(independent);
    drop(blocker);
    assert_released(&prefix);
    assert_released(&dependency);
}

#[test]
fn early_input_and_replaced_path_refuse_before_admission() {
    let owner = tempfile::tempdir().unwrap();
    let prefix = owner.path().join("prefix.lock");
    let dependency = owner.path().join("dependency.lock");
    let blocker = lock_file(&dependency);
    exclusive(&blocker);
    let plan = format!("x {}\nx {}\n", prefix.display(), dependency.display());
    let mut early = acquire(owner.path(), "early", plan.as_bytes(), "2");
    early.assert_silent_for(Duration::from_millis(100));
    early.send(b"unexpected-before-ready\n");
    early.finish(73);
    assert!(early.out.is_empty());
    let mut replaced = acquire(owner.path(), "replaced", plan.as_bytes(), "2");
    replaced.assert_silent_for(Duration::from_millis(100));
    std::fs::rename(&prefix, owner.path().join("retained-original.lock")).unwrap();
    std::fs::write(&prefix, b"replacement").unwrap();
    replaced.finish(73);
    assert!(replaced.out.is_empty());
    assert!(String::from_utf8_lossy(&replaced.err).contains("path changed"));
}

#[test]
fn terminal_inherits_all_locks_exact_arguments_and_fd4_claims() {
    let owner = tempfile::tempdir().unwrap();
    let paths: Vec<_> = (0..40)
        .map(|index| owner.path().join(format!("{index}.lock")))
        .collect();
    let input = owner.path().join("many.plan");
    let claims = owner.path().join("claims");
    std::fs::write(
        &input,
        paths
            .iter()
            .map(|path| format!("x {}\n", path.display()))
            .collect::<String>(),
    )
    .unwrap();
    std::fs::write(&claims, b"literal claim ' with spaces\n").unwrap();
    let terminal = "IFS= read -r claim <&4 || exit 51; if ( : <&3 ) 2>/dev/null; then exit 52; fi; printf '%s:%s:%s\n' \"$1\" \"$2\" \"$claim\"; IFS= read -r release; exit 19";
    let mut holder = Running::from_command(with_plan(
        &input,
        &[
            OsStr::new("40"),
            OsStr::new("GRANTED"),
            OsStr::new(terminal),
            OsStr::new("literal argument '"),
        ],
        Some(&claims),
        false,
    ));
    holder.wait_for(b"GRANTED:literal argument ':literal claim ' with spaces\n");
    for path in &paths {
        assert_locked(path);
    }
    holder.send(b"release\n");
    holder.finish(19);
    for path in &paths {
        assert_released(path);
    }
}

#[test]
fn zero_lock_terminal_preserves_ready_argument_without_waiting_on_control_input() {
    let owner = tempfile::tempdir().unwrap();
    let input = owner.path().join("empty.plan");
    std::fs::write(&input, b"").unwrap();
    let mut holder = Running::from_command(with_plan(
        &input,
        &[
            OsStr::new("0"),
            OsStr::new("ZERO"),
            OsStr::new("printf '%s\\n' \"$1\"; exit 33"),
        ],
        None,
        false,
    ));
    holder.disconnect();
    holder.finish(33);
    assert_eq!(holder.out, b"ZERO\n");
}

#[test]
fn heartbeats_extend_liveness_and_release_tears_down_inherited_descendant_locks() {
    let owner = tempfile::tempdir().unwrap();
    let (lock, program) = holder_program(owner.path(), HOLD_AND_RELEASE);
    let mut holder = session(
        owner.path(),
        "heartbeat",
        program.as_bytes(),
        "--rch-session",
        "1",
    );
    holder.wait_for(b"RCH_SOURCE_LOCK_SESSION_READY\n");
    holder.wait_for(READY);
    assert_locked(&lock);
    for _ in 0..3 {
        thread::sleep(Duration::from_millis(450));
        holder.send(b"RCH_SOURCE_LOCK_HEARTBEAT\n");
    }
    assert!(holder.child.try_wait().unwrap().is_none());
    holder.send(b"RCH_SOURCE_AUTHORITY_RELEASE:abc-123\n");
    holder.disconnect();
    holder.finish(27);
    assert_released(&lock);
}

#[test]
fn shell_heredoc_program_and_lock_plan_preserve_separate_control_stream() {
    let owner = tempfile::tempdir().unwrap();
    let lock = owner.path().join("heredoc.lock");
    let program = format!(
        "exec 3<<'SOURCE_LOCK_PLAN'\nx {}\nSOURCE_LOCK_PLAN\nexec {} source-lock 1 GRANTED {}",
        lock.display(),
        quote(WORKER),
        quote(HOLD_AND_RELEASE),
    );
    let bootstrap = format!(
        "exec 3<<'SOURCE_SESSION_PROGRAM'\n{program}\nSOURCE_SESSION_PROGRAM\nexec {} source-lock --rch-session 3",
        quote(WORKER),
    );
    let mut command = Command::new("sh");
    command.arg("-c").arg(bootstrap);
    let mut holder = Running::from_command(command);
    holder.wait_for(b"RCH_SOURCE_LOCK_SESSION_READY\n");
    holder.wait_for(READY);
    assert_locked(&lock);
    holder.send(b"RCH_SOURCE_AUTHORITY_RELEASE:abc-123\n");
    holder.disconnect();
    holder.finish(27);
    assert_released(&lock);
}

#[test]
fn incomplete_heartbeat_never_renews_and_disconnect_retains_durable_ownership() {
    for disconnect in [false, true] {
        let owner = tempfile::tempdir().unwrap();
        let durable = owner.path().join("durable-owner");
        std::fs::write(&durable, b"claimed\n").unwrap();
        let (lock, program) = holder_program(owner.path(), HOLD_AND_RELEASE);
        let mut holder = session(
            owner.path(),
            "partial",
            program.as_bytes(),
            "--rch-session",
            "1",
        );
        holder.wait_for(READY);
        holder.send(b"RCH_SOURCE_LOCK_HEART");
        if disconnect {
            holder.disconnect();
        }
        holder.finish(73);
        assert!(
            String::from_utf8_lossy(&holder.err).contains(if disconnect {
                "RCH_SOURCE_LOCK_DISCONNECTED"
            } else {
                "RCH_SOURCE_LOCK_HEARTBEAT_EXPIRED"
            })
        );
        assert_eq!(std::fs::read(&durable).unwrap(), b"claimed\n");
        assert_released(&lock);
    }
}

#[test]
fn unknown_oversized_and_post_release_frames_never_complete_release() {
    for frame in [
        b"not-a-release\n".to_vec(),
        vec![b'x'; 4096],
        b"RCH_SOURCE_AUTHORITY_RELEASE:abc-123\nRCH_SOURCE_LOCK_HEARTBEAT\n".to_vec(),
    ] {
        let owner = tempfile::tempdir().unwrap();
        let (lock, program) = holder_program(owner.path(), HOLD_AND_RELEASE);
        let mut holder = session(
            owner.path(),
            "protocol",
            program.as_bytes(),
            "--rch-session",
            "3",
        );
        holder.wait_for(READY);
        holder.send(&frame);
        holder.finish(73);
        assert!(String::from_utf8_lossy(&holder.err).contains("RCH_SOURCE_LOCK_PROTOCOL_ERROR"));
        assert_released(&lock);
    }
}

#[test]
fn independent_observer_revokes_killed_stopped_and_explicitly_notified_monitors() {
    for action in [Signal::KILL, Signal::STOP, Signal::CHILD] {
        let owner = tempfile::tempdir().unwrap();
        let (lock, program) = holder_program(owner.path(), HOLD_AND_RELEASE);
        let mut holder = session(
            owner.path(),
            "observer",
            program.as_bytes(),
            "--rch-session",
            "90",
        );
        holder.wait_for(READY);
        let monitor = holder.monitor_pid();
        assert_locked(&lock);
        let target = if action == Signal::CHILD {
            Pid::from_child(&holder.child)
        } else {
            monitor
        };
        rustix::process::kill_process(target, action).unwrap();
        holder.finish(73);
        assert!(
            String::from_utf8_lossy(&holder.err).contains("RCH_SOURCE_LOCK_SUPERVISOR_TERMINATED")
        );
        assert_released(&lock);
    }
}

#[test]
fn workload_stderr_cannot_forge_monitor_completion() {
    let owner = tempfile::tempdir().unwrap();
    let (lock, program) = holder_program(
        owner.path(),
        "printf '%s\n' \"$1\"; sleep 300 & printf '0\n' >&2; kill -KILL \"$PPID\"; sleep 300",
    );
    let mut holder = session(
        owner.path(),
        "forgery",
        program.as_bytes(),
        "--rch-session",
        "90",
    );
    holder.finish(73);
    assert!(holder.out.windows(READY.len()).any(|bytes| bytes == READY));
    assert!(String::from_utf8_lossy(&holder.err).contains("SUPERVISOR_TERMINATED"));
    assert_released(&lock);
}

#[test]
fn finite_rpc_deadlines_and_status_receipts_are_independent_of_heartbeat_policy() {
    let owner = tempfile::tempdir().unwrap();
    let mut timed = session(
        owner.path(),
        "timed",
        b"sleep 300 & wait\n",
        "--rch-finite-rpc",
        "120",
    );
    timed.finish(124);
    assert!(timed.out.is_empty());
    assert!(
        String::from_utf8_lossy(&timed.err).contains("RCH_SOURCE_ACTIVITY_TIMEOUT: budget_ms=120")
    );
    for budget in ["3600001", "18446744073709551615999"] {
        let mut successful = session(
            owner.path(),
            budget,
            b"exit 39\n",
            "--rch-finite-rpc",
            budget,
        );
        successful.finish(39);
        assert!(successful.out.is_empty());
        assert!(successful.err.is_empty());
    }
}

#[test]
fn failed_workload_shell_exec_preserves_status_127() {
    let owner = tempfile::tempdir().unwrap();
    let input = owner.path().join("missing-shell.program");
    std::fs::write(&input, b"exit 0\n").unwrap();
    let mut command = Command::new("/bin/sh");
    command
        .arg("-c")
        .arg("exec 3< \"$1\"; shift; exec \"$@\"")
        .arg("missing-shell-test")
        .arg(&input)
        .arg(WORKER)
        .args(["source-lock", "--rch-finite-rpc", "3000"])
        .env("PATH", owner.path().join("missing-command-directory"));
    let mut holder = Running::from_command(command);
    holder.finish(127);
    assert!(holder.out.is_empty());
    assert!(holder.err.is_empty());
}

#[test]
fn already_expired_absolute_rpc_deadline_prevents_even_workload_shell_exec() {
    let owner = tempfile::tempdir().unwrap();
    let input = owner.path().join("expired.program");
    std::fs::write(&input, b"exit 0\n").unwrap();
    let (receipt_read, receipt_write) =
        rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
    let inherited = rustix::io::fcntl_dupfd_cloexec(&receipt_write, 64).unwrap();
    rustix::io::fcntl_setfd(&inherited, rustix::io::FdFlags::empty()).unwrap();
    let mut child = Command::new("/bin/sh")
        .arg("-c")
        .arg("exec 3< \"$1\"; shift; exec \"$@\"")
        .arg("expired-monitor-test")
        .arg(&input)
        .arg(WORKER)
        .args(["source-lock", "--rch-monitor", "--rch-finite-rpc", "1000"])
        .arg(inherited.as_raw_fd().to_string())
        .arg("1")
        // An attempted workload spawn deterministically reports127. The
        // already-expired monotonic deadline must win before that attempt.
        .env("PATH", owner.path().join("missing-command-directory"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(inherited);
    drop(receipt_write);
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("already-expired monitor did not revoke itself");
        }
        thread::sleep(Duration::from_millis(5));
    };
    assert_eq!(status.signal(), Some(signal_hook::consts::SIGKILL));
    let mut receipt = Vec::new();
    File::from(receipt_read).read_to_end(&mut receipt).unwrap();
    assert_eq!(receipt, b"124\n");
    let output = child.wait_with_output().unwrap();
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("RCH_SOURCE_ACTIVITY_TIMEOUT: budget_ms=1000")
    );
}

#[test]
fn inherited_regular_stderr_keeps_current_offset_and_append_semantics() {
    let owner = tempfile::tempdir().unwrap();
    let input = owner.path().join("log.program");
    std::fs::write(&input, b"printf 'workload diagnostic\\n' >&2; sleep 300\n").unwrap();
    for append in [false, true] {
        let path = owner.path().join(format!("stderr-{append}.log"));
        let mut log = OpenOptions::new()
            .write(true)
            .append(append)
            .create_new(true)
            .open(&path)
            .unwrap();
        log.write_all(b"existing diagnostic\n").unwrap();
        if append {
            // Even a stale offset cannot override O_APPEND on the inherited
            // open description. Reopening /dev/fd without that flag loses it.
            log.seek(SeekFrom::Start(0)).unwrap();
        }
        let mut command = with_plan(
            &input,
            &[OsStr::new("--rch-finite-rpc"), OsStr::new("150")],
            None,
            false,
        );
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("finite RPC did not release its regular log stream");
            }
            thread::sleep(Duration::from_millis(5));
        };
        assert_eq!(status.code(), Some(124));
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(
            contents.starts_with("existing diagnostic\nworkload diagnostic\n"),
            "{contents:?}"
        );
        assert!(contents.contains("RCH_SOURCE_ACTIVITY_TIMEOUT: budget_ms=150"));
    }
}

#[test]
fn unread_reply_or_diagnostics_cannot_postpone_finite_rpc_revocation() {
    let owner = tempfile::tempdir().unwrap();
    for descriptor in [1, 2] {
        let input = owner.path().join(format!("blocked-{descriptor}.program"));
        let line = "x".repeat(1024);
        std::fs::write(
            &input,
            format!("while :; do printf '%s\\n' '{line}' >&{descriptor}; done\n"),
        )
        .unwrap();
        let mut command = with_plan(
            &input,
            &[OsStr::new("--rch-finite-rpc"), OsStr::new("250")],
            None,
            false,
        );
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        // Deliberately do not read either pipe until the observer exits.
        // The payload fills one; the monitor must still publish its private
        // completion receipt and revoke the entire group on the original budget.
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("blocked fd {descriptor} prevented finite RPC teardown");
            }
            thread::sleep(Duration::from_millis(5));
        };
        assert_eq!(status.code(), Some(124), "blocked descriptor {descriptor}");
        let output = child.wait_with_output().unwrap();
        let blocked = if descriptor == 1 {
            &output.stdout
        } else {
            &output.stderr
        };
        assert!(
            blocked.len() >= 1024,
            "payload never filled descriptor {descriptor}"
        );
    }
}

#[test]
fn monitor_still_revokes_descendants_after_observer_and_receipt_reader_die() {
    let owner = tempfile::tempdir().unwrap();
    let (lock, program) = holder_program(owner.path(), HOLD_AND_RELEASE);
    let mut holder = session(
        owner.path(),
        "orphan-monitor",
        program.as_bytes(),
        "--rch-session",
        "1",
    );
    holder.wait_for(READY);
    assert_locked(&lock);
    holder.child.kill().unwrap();
    let status = holder.child.wait().unwrap();
    holder.status = Some(status);
    holder.disconnect();
    // The observer can no longer consume the completion receipt. Expiry/EOF
    // must still trigger the monitor's unconditional group SIGKILL.
    assert_released(&lock);
}

#[test]
fn finite_rpc_forwards_programs_above_holder_bootstrap_limit() {
    let owner = tempfile::tempdir().unwrap();
    let mut program = Vec::with_capacity(33 * 1024 * 1024);
    for _ in 0..33 * 1024 {
        program.push(b'#');
        program.extend(std::iter::repeat_n(b'x', 1022));
        program.push(b'\n');
    }
    program.extend_from_slice(b"exit 41\n");
    let mut finite = session(
        owner.path(),
        "large-rpc",
        &program,
        "--rch-finite-rpc",
        "5000",
    );
    finite.finish(41);
    assert!(finite.err.is_empty());
    let mut holder = session(owner.path(), "large-holder", &program, "--rch-session", "3");
    holder.finish(73);
    assert!(holder.out.is_empty());
    assert!(String::from_utf8_lossy(&holder.err).contains("invalid bounded holder program"));
}

#[test]
fn inherited_child_ignore_and_mask_do_not_disable_observer_or_child_waits() {
    let owner = tempfile::tempdir().unwrap();
    let input = owner.path().join("signals.program");
    std::fs::write(
        &input,
        b"trap 'printf CHILD_EVENT\\n' CHLD; sleep 0.05 & wait \"$!\"; exit 43\n",
    )
    .unwrap();
    let mut blocked = SigSet::empty();
    blocked.add(NixSignal::SIGCHLD);
    let previous = SigSet::thread_get_mask().unwrap();
    blocked.thread_block().unwrap();
    let mut holder = Running::from_command(with_plan(
        &input,
        &[OsStr::new("--rch-finite-rpc"), OsStr::new("3000")],
        None,
        true,
    ));
    previous.thread_set_mask().unwrap();
    holder.finish(43);
    assert!(String::from_utf8_lossy(&holder.out).contains("CHILD_EVENT"));
    assert!(
        holder.err.is_empty(),
        "{}",
        String::from_utf8_lossy(&holder.err)
    );
}

#[test]
fn native_shell_dispatch_requires_exact_worker_capability_before_acquisition() {
    let owner = tempfile::tempdir().unwrap();
    let plan = owner.path().join("empty.plan");
    std::fs::write(&plan, b"").unwrap();
    let shim = format!(
        "{}\n{}",
        rch_common::wkr_locate::WKR_LOCATE_SHELL,
        include_str!("../../rch/src/hook/source_lock_holder.sh")
    );
    let mut command = Command::new("sh");
    command
        .arg("-c")
        .arg("exec 3< \"$1\"; shift; exec sh -c \"$@\"")
        .arg("shim-test")
        .arg(&plan)
        .arg(&shim)
        .arg("native-shim")
        .args(["0", "SHIM", "printf '%s\\n' \"$1\"; exit 45"])
        .env("RCH_WKR_BIN", WORKER);
    let mut valid = Running::from_command(command);
    valid.disconnect();
    valid.finish(45);
    assert_eq!(valid.out, b"SHIM\n");
    for mode in ["1", "--rch-session", "--rch-finite-rpc"] {
        let output = Command::new("sh")
            .arg("-c")
            .arg(&shim)
            .arg("missing-shim")
            .args([mode, "1"])
            .env("RCH_WKR_BIN", owner.path().join("missing-worker"))
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(73), "{output:?}");
        assert!(output.stdout.is_empty());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("rch-wkr source-lock v1 is required")
        );
    }
}
