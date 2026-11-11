//! Real-process admission through the shipped holder and matching worker.
//! Native descriptors observe kernel locks; no SSH server or fleet is needed.
#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]

use std::cell::Cell;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdout, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use rustix::fs::{FlockOperation, OFlags};
use rustix::io::Errno;

struct Fixture {
    directory: tempfile::TempDir,
    tools: PathBuf,
    worker: PathBuf,
    next: Cell<usize>,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::Builder::new()
            .prefix("source-lock-admission-")
            .disable_cleanup(true)
            .tempdir()
            .unwrap();
        let tools = directory.path().join("tools");
        std::fs::create_dir(&tools).unwrap();
        for name in ["sh", "cat"] {
            std::os::unix::fs::symlink(format!("/bin/{name}"), tools.join(name)).unwrap();
        }
        Self {
            directory,
            tools,
            worker: rch_common::testing::worker_binary(),
            next: Cell::new(0),
        }
    }

    fn paths(&self, count: usize) -> Vec<PathBuf> {
        (0..count)
            .map(|index| {
                let path = self
                    .directory
                    .path()
                    .join(format!("source root '{index}.lock"));
                std::fs::write(&path, b"").unwrap();
                path
            })
            .collect()
    }

    fn start(
        &self,
        paths: &[PathBuf],
        modes: &[char],
        terminal: Option<&str>,
        extra: bool,
    ) -> Holder {
        assert_eq!(paths.len(), modes.len());
        let index = self.next.get();
        self.next.set(index + 1);
        let plan = self.directory.path().join(format!("plan-{index}"));
        let claim = self.directory.path().join(format!("claim-{index}"));
        let mut records: String = paths
            .iter()
            .zip(modes)
            .map(|(path, mode)| format!("{mode} {}\n", path.display()))
            .collect();
        if extra {
            // A syntactically valid surplus row tests the exact count bound.
            records.push_str(&format!(
                "x {}\n",
                self.directory.path().join("extra.lock").display()
            ));
        }
        std::fs::write(&plan, records).unwrap();
        std::fs::write(&claim, b"durable-claim-sentinel\n").unwrap();
        let script = format!(
            "{}\n{}",
            rch_common::wkr_locate::WKR_LOCATE_SHELL,
            include_str!("../src/hook/source_lock_holder.sh")
        );
        let mut command = Command::new("/bin/sh");
        command
            .args([
                "-c",
                "exec 3<\"$1\"; exec 4<\"$2\"; shift 2; exec sh -c \"$@\"",
                "source-lock-test",
            ])
            .arg(&plan)
            .arg(&claim)
            .arg(&script)
            .arg("source-lock-holder")
            .arg(paths.len().to_string())
            .arg("READY")
            .env("RCH_WKR_BIN", &self.worker)
            .env("PATH", &self.tools);
        if let Some(terminal) = terminal {
            command.arg(terminal);
        }
        Holder::spawn(command)
    }

    fn exclusive(&self, paths: &[PathBuf]) -> Holder {
        self.start(paths, &vec!['x'; paths.len()], None, false)
    }
}

struct Holder {
    child: Child,
    stdout: ChildStdout,
    stderr: ChildStderr,
    out: Vec<u8>,
    err: Vec<u8>,
    status: Option<ExitStatus>,
}

impl Holder {
    fn spawn(mut command: Command) -> Self {
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
        fn read(reader: &mut impl Read, bytes: &mut Vec<u8>) {
            let mut buffer = [0_u8; 4096];
            loop {
                match reader.read(&mut buffer) {
                    Ok(0) => return,
                    Ok(count) => bytes.extend_from_slice(&buffer[..count]),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return,
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(error) => panic!("holder output: {error}"),
                }
            }
        }
        read(&mut self.stdout, &mut self.out);
        read(&mut self.stderr, &mut self.err);
    }

    fn running(&mut self) {
        self.drain();
        if self.status.is_none() {
            self.status = self.child.try_wait().unwrap();
        }
        assert!(
            self.status.is_none(),
            "holder exited {:?}: {}",
            self.status,
            String::from_utf8_lossy(&self.err)
        );
    }

    fn line(&mut self) -> Vec<u8> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            self.drain();
            if let Some(end) = self.out.iter().position(|byte| *byte == b'\n') {
                let line = self.out[..end].to_vec();
                self.out.drain(..=end);
                return line;
            }
            self.running();
            assert!(
                Instant::now() < deadline,
                "holder never announced readiness"
            );
            thread::sleep(Duration::from_millis(5));
        }
    }

    fn not_ready(&mut self) {
        let deadline = Instant::now() + Duration::from_millis(100);
        while Instant::now() < deadline {
            self.running();
            assert!(
                self.out.is_empty(),
                "partial source ownership was announced: {:?}",
                self.out
            );
            thread::sleep(Duration::from_millis(5));
        }
    }

    fn opened(&mut self, path: &Path) {
        // Observe the owned holder reaching contention before probing its
        // prefix. The script and worker execs retain this direct child's PID.
        let descriptors = PathBuf::from(format!("/proc/{}/fd", self.child.id()));
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            self.running();
            if let Ok(entries) = std::fs::read_dir(&descriptors)
                && entries.filter_map(Result::ok).any(|entry| {
                    std::fs::read_link(entry.path()).is_ok_and(|target| target == path)
                })
            {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "holder never opened contended root: {}",
                path.display()
            );
            thread::sleep(Duration::from_millis(5));
        }
    }

    fn close(&mut self) {
        self.child.stdin.take();
    }

    fn finish(&mut self, expected: i32) {
        let deadline = Instant::now() + Duration::from_secs(5);
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
                "holder did not finish: {}",
                String::from_utf8_lossy(&self.err)
            );
            thread::sleep(Duration::from_millis(5));
        }
    }
}

impl Drop for Holder {
    fn drop(&mut self) {
        self.close();
        if self.status.is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn nonblocking(fd: impl AsFd) {
    let flags = rustix::fs::fcntl_getfl(&fd).unwrap();
    rustix::fs::fcntl_setfl(fd, flags | OFlags::NONBLOCK).unwrap();
}

fn lock_file(path: &Path) -> File {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap()
}

fn block(path: &Path) -> File {
    let file = lock_file(path);
    rustix::fs::flock(&file, FlockOperation::NonBlockingLockExclusive).unwrap();
    file
}

fn available(path: &Path, shared: bool) -> bool {
    let mode = if shared {
        FlockOperation::NonBlockingLockShared
    } else {
        FlockOperation::NonBlockingLockExclusive
    };
    match rustix::fs::flock(lock_file(path), mode) {
        Ok(()) => true,
        Err(Errno::AGAIN | Errno::ACCESS) => false,
        Err(error) => panic!("probe native lock {}: {error}", path.display()),
    }
}

fn complete_grant(paths: &[PathBuf], shared_first: bool) {
    assert!(
        paths.iter().all(|path| !available(path, false)),
        "announced grant omitted a source root"
    );
    if shared_first {
        assert!(
            available(&paths[0], true),
            "shared intent upgraded to exclusive"
        );
    }
}

fn all_released(paths: &[PathBuf]) {
    assert!(
        paths.iter().all(|path| available(path, false)),
        "holder leaked a source lock"
    );
}

#[test]
fn blocked_closures_release_all_prefix_locks_for_independent_builds() {
    for count in [2, 32, 64] {
        for shared_first in [false, true] {
            let fixture = Fixture::new();
            let paths = fixture.paths(count);
            let busy = block(paths.last().unwrap());
            let mut modes = vec!['x'; count];
            if shared_first {
                modes[0] = 's';
            }
            let mut waiting = fixture.start(&paths, &modes, None, false);
            waiting.opened(paths.last().unwrap());
            waiting.not_ready();
            let mut independent = fixture.exclusive(&paths[..1]);
            assert_eq!(independent.line(), b"READY");
            assert!(
                !available(paths.last().unwrap(), false),
                "busy dependency was released early"
            );
            waiting.not_ready();
            independent.close();
            independent.finish(0);
            drop(busy);
            assert_eq!(waiting.line(), b"READY");
            complete_grant(&paths, shared_first);
            waiting.close();
            waiting.finish(0);
            all_released(&paths);
        }
    }
}

#[test]
fn cancelled_waiters_never_grant_or_leak_prefix_locks() {
    for count in [2, 32, 64] {
        let fixture = Fixture::new();
        let paths = fixture.paths(count);
        let busy = block(paths.last().unwrap());
        let mut waiting = fixture.exclusive(&paths);
        waiting.opened(paths.last().unwrap());
        waiting.close();
        waiting.finish(73);
        assert!(String::from_utf8_lossy(&waiting.err).contains("requester"));
        assert!(waiting.out.is_empty());
        drop(busy);
        all_released(&paths);
    }
}

#[test]
fn retry_rejects_replaced_lock_path_before_complete_grant() {
    for count in [2, 32, 64] {
        let fixture = Fixture::new();
        let paths = fixture.paths(count);
        let busy = block(paths.last().unwrap());
        let mut waiting = fixture.exclusive(&paths);
        waiting.opened(paths.last().unwrap());
        let retained = paths[0].with_extension("retained");
        std::fs::rename(&paths[0], &retained).unwrap();
        std::fs::write(&paths[0], b"").unwrap();
        drop(busy);
        waiting.finish(73);
        assert!(String::from_utf8_lossy(&waiting.err).contains("source lock path changed"));
        assert!(waiting.out.is_empty());
        assert!(available(&retained, false));
        all_released(&paths);
    }
}

#[test]
fn physical_aliases_refuse_every_exclusive_and_shared_combination() {
    for count in [2, 32, 64] {
        let fixture = Fixture::new();
        let mut paths = fixture.paths(count);
        let alias = fixture.directory.path().join("physical alias.lock");
        std::fs::hard_link(&paths[0], &alias).unwrap();
        paths[1] = alias;
        std::fs::write(&paths[0], b"retained original lock bytes").unwrap();
        for (first, second) in [('x', 'x'), ('x', 's'), ('s', 'x'), ('s', 's')] {
            let mut modes = vec!['x'; count];
            modes[0] = first;
            modes[1] = second;
            let mut waiting = fixture.start(&paths, &modes, None, false);
            waiting.finish(73);
            assert!(String::from_utf8_lossy(&waiting.err).contains("duplicate source lock inode"));
            assert!(waiting.out.is_empty());
            all_released(&paths);
            for path in &paths[..2] {
                assert_eq!(
                    std::fs::read(path).unwrap(),
                    b"retained original lock bytes"
                );
            }
        }
    }
}

#[test]
fn terminal_inherits_complete_grant_and_untouched_fd4_claim_input() {
    for count in [2, 32, 64] {
        let fixture = Fixture::new();
        let paths = fixture.paths(count);
        let busy = block(paths.last().unwrap());
        let terminal = "printf '%s\\n' \"$1\"; IFS= read -r claim <&4 || exit 91; printf 'CLAIM:%s\\n' \"$claim\"; IFS= read -r reply || exit 92; [ \"$reply\" = release ] || exit 93";
        let mut waiting = fixture.start(&paths, &vec!['x'; count], Some(terminal), false);
        waiting.opened(paths.last().unwrap());
        waiting.not_ready();
        drop(busy);
        assert_eq!(waiting.line(), b"READY");
        assert_eq!(waiting.line(), b"CLAIM:durable-claim-sentinel");
        complete_grant(&paths, false);
        waiting
            .child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(b"release\n")
            .unwrap();
        waiting.close();
        waiting.finish(0);
        all_released(&paths);
    }
}

#[test]
fn sequential_holders_preserve_complete_mutual_exclusion() {
    for count in [2, 32, 64] {
        let fixture = Fixture::new();
        let paths = fixture.paths(count);
        let mut first = fixture.exclusive(&paths);
        assert_eq!(first.line(), b"READY");
        let mut second = fixture.exclusive(&paths);
        second.opened(&paths[0]);
        second.not_ready();
        complete_grant(&paths, false);
        first.close();
        first.finish(0);
        assert_eq!(second.line(), b"READY");
        complete_grant(&paths, false);
        second.close();
        second.finish(0);
        all_released(&paths);
    }
}

#[test]
fn malformed_plan_count_refuses_without_waiting_on_contended_dependency() {
    for count in [2, 32, 64] {
        let fixture = Fixture::new();
        let paths = fixture.paths(count);
        let busy = block(paths.last().unwrap());
        let mut waiting = fixture.start(&paths, &vec!['x'; count], None, true);
        waiting.finish(73);
        assert!(String::from_utf8_lossy(&waiting.err).contains("count does not match"));
        assert!(waiting.out.is_empty());
        drop(busy);
        all_released(&paths);
    }
}

#[test]
fn unavailable_or_mismatched_explicit_worker_never_acquires_source_locks() {
    use std::os::unix::fs::PermissionsExt as _;

    for script in [
        None,
        Some("#!/bin/sh\nexit 2\n"),
        Some("#!/bin/sh\nprintf 'rch-wkr source-lock v0\\n'\n"),
        Some("#!/bin/sh\nprintf 'rch-wkr source-lock v1\\n'\nexit 3\n"),
    ] {
        let mut fixture = Fixture::new();
        fixture.worker = fixture.directory.path().join("selected-worker");
        if let Some(script) = script {
            std::fs::write(&fixture.worker, script).unwrap();
            std::fs::set_permissions(&fixture.worker, std::fs::Permissions::from_mode(0o755))
                .unwrap();
        }
        let source = fixture.directory.path().join("must-remain-absent.lock");
        let mut holder = fixture.exclusive(std::slice::from_ref(&source));
        holder.finish(73);
        assert!(holder.out.is_empty());
        assert!(String::from_utf8_lossy(&holder.err).contains("RCH_SOURCE_LOCK_UNAVAILABLE"));
        assert!(
            !source.exists(),
            "unsupported worker acquired a source lock"
        );
    }
}
