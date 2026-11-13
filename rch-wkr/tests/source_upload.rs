//! Exercise the native source-upload command with real processes and locks.
//! These are local Unix worker tests, not an SSH/fleet qualification.

#![cfg(unix)]

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use rustix::fs::{FlockOperation, flock};
use rustix::io::Errno;
use sha2::{Digest as _, Sha256};

const WORKER: &str = env!("CARGO_BIN_EXE_rch-wkr");
const TOKEN: &str = "c001";

struct Fixture {
    root: PathBuf,
    registry: PathBuf,
    first: PathBuf,
    second: PathBuf,
    contents: Vec<u8>,
    digest: String,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap().keep().canonicalize().unwrap();
        let registry = root.join("registry");
        let first = root.join("first ' $ literal");
        let second = root.join("second");
        for path in [&registry, &first, &second] {
            std::fs::create_dir(path).unwrap();
        }
        let contents = format!("{}\n{}\n", first.display(), second.display()).into_bytes();
        let digest = Sha256::digest(&contents)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        std::fs::write(registry.join(format!("{TOKEN}.{digest}.claim")), &contents).unwrap();
        Self {
            root,
            registry,
            first,
            second,
            contents,
            digest,
        }
    }

    fn command(&self, destination: &Path) -> Command {
        let mut command = Command::new(WORKER);
        command
            .args(["source-upload", "run"])
            .arg(&self.registry)
            .arg(TOKEN)
            .arg(destination);
        command
    }

    fn activity(&self) -> File {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.registry.join(format!("{TOKEN}.activity.lock")))
            .unwrap()
    }

    fn cancel(&self) {
        std::fs::write(
            self.registry
                .join(format!("{TOKEN}.{}.cancelling", self.digest)),
            &self.contents,
        )
        .unwrap();
    }
}

fn wait(child: &mut Child) -> ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "source upload outlived its observation deadline"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

struct HeldReceiver {
    child: Child,
    ready: Receiver<std::io::Result<[u8; 5]>>,
    stdout: Option<JoinHandle<std::io::Result<Vec<u8>>>>,
    stderr: Option<JoinHandle<std::io::Result<Vec<u8>>>>,
}

impl HeldReceiver {
    fn start(fixture: &Fixture, destination: &Path) -> Self {
        // Match the production HUP-resistant launch. The receiver deliberately
        // closes the activity descriptor; the waiting worker must retain it.
        let mut child = Command::new("nohup")
            .arg(WORKER)
            .args(["source-upload", "run"])
            .arg(&fixture.registry)
            .arg(TOKEN)
            .arg(destination)
            .args(["sh", "-c", "exec 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-; printf ready; IFS= read -r payload || exit 79; printf '%s' \"$payload\" > \"$1/uploaded\"", "receiver"])
            .arg(destination)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn().unwrap();
        let mut stdout = child.stdout.take().unwrap();
        let mut stderr = child.stderr.take().unwrap();
        let (ready_tx, ready) = mpsc::channel();
        let stdout = thread::spawn(move || {
            let mut bytes = [0; 5];
            let result = stdout.read_exact(&mut bytes).map(|()| bytes);
            let _ = ready_tx.send(result);
            let mut rest = Vec::new();
            stdout.read_to_end(&mut rest)?;
            Ok(rest)
        });
        let stderr = thread::spawn(move || {
            let mut bytes = Vec::new();
            stderr.read_to_end(&mut bytes)?;
            Ok(bytes)
        });
        Self {
            child,
            ready,
            stdout: Some(stdout),
            stderr: Some(stderr),
        }
    }

    fn ready(&self) {
        assert_eq!(
            self.ready
                .recv_timeout(Duration::from_secs(10))
                .unwrap()
                .unwrap(),
            *b"ready"
        );
    }

    fn finish(&mut self, payload: &str) {
        let mut input = self.child.stdin.take().unwrap();
        writeln!(input, "{payload}").unwrap();
        drop(input);
        let status = wait(&mut self.child);
        let stdout = self.stdout.take().unwrap().join().unwrap().unwrap();
        let stderr = self.stderr.take().unwrap().join().unwrap().unwrap();
        assert!(
            status.success(),
            "{status}: {}",
            String::from_utf8_lossy(&stderr)
        );
        assert!(stdout.is_empty());
        assert!(stderr.is_empty(), "{}", String::from_utf8_lossy(&stderr));
    }
}

impl Drop for HeldReceiver {
    fn drop(&mut self) {
        // This only owns the exact fixture child. Closing its input also lets
        // the deliberately held shell exit if its supervisor was interrupted.
        drop(self.child.stdin.take());
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

#[test]
fn native_upload_preserves_probe_stdin_streams_status_and_signal() {
    let probe = Command::new(WORKER)
        .args(["source-upload", "probe"])
        .output()
        .unwrap();
    assert!(probe.status.success());
    assert_eq!(probe.stdout, b"rch-wkr source-upload v1\n");
    assert!(probe.stderr.is_empty());
    let fixture = Fixture::new();
    let mut child = fixture
        .command(&fixture.first)
        .args(["sh", "-c", "cat; printf 'receiver-stderr' >&2; exit 42"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let payload = b"literal ' $ input\0with binary bytes\xff\n".repeat(8192);
    let written = payload.clone();
    let mut input = child.stdin.take().unwrap();
    let writer = thread::spawn(move || input.write_all(&written));
    let output = child.wait_with_output().unwrap();
    writer.join().unwrap().unwrap();
    assert_eq!(output.status.code(), Some(42), "{output:?}");
    assert_eq!(output.stdout, payload);
    assert_eq!(output.stderr, b"receiver-stderr");
    let output = fixture
        .command(&fixture.first)
        .args(["sh", "-c", "kill -TERM $$"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(143), "{output:?}");
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
fn native_upload_supervisor_holds_activity_across_hup_and_sanitized_receiver_fds() {
    let fixture = Fixture::new();
    let mut first = HeldReceiver::start(&fixture, &fixture.first);
    first.ready();
    let mut second = HeldReceiver::start(&fixture, &fixture.second);
    second.ready();
    let activity = fixture.activity();
    assert!(matches!(
        flock(&activity, FlockOperation::NonBlockingLockExclusive),
        Err(Errno::AGAIN | Errno::ACCESS)
    ));
    kill(
        Pid::from_raw(i32::try_from(first.child.id()).unwrap()),
        Signal::SIGHUP,
    )
    .unwrap();
    first.finish("first ' $ payload");
    assert!(matches!(
        flock(&activity, FlockOperation::NonBlockingLockExclusive),
        Err(Errno::AGAIN | Errno::ACCESS)
    ));
    second.finish("second payload");
    flock(&activity, FlockOperation::NonBlockingLockExclusive).unwrap();
    assert_eq!(
        std::fs::read(fixture.first.join("uploaded")).unwrap(),
        b"first ' $ payload"
    );
    assert_eq!(
        std::fs::read(fixture.second.join("uploaded")).unwrap(),
        b"second payload"
    );
}

#[test]
fn native_upload_queued_before_cancel_never_executes_or_consumes_receiver_input() {
    let fixture = Fixture::new();
    let activity = fixture.activity();
    flock(&activity, FlockOperation::LockExclusive).unwrap();
    let mut child = fixture
        .command(&fixture.first)
        .args(["sh", "-c", "cat > \"$1/uploaded\"", "receiver"])
        .arg(&fixture.first)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"never deliver this to a cancelled receiver\n")
        .unwrap();
    thread::sleep(Duration::from_millis(100));
    assert!(child.try_wait().unwrap().is_none());
    assert!(!fixture.first.join("uploaded").exists());
    fixture.cancel();
    drop(activity);
    let status = wait(&mut child);
    let output = child.wait_with_output().unwrap();
    assert_eq!(status.code(), Some(73));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("source grant is cancelling"));
    assert!(!fixture.first.join("uploaded").exists());
    assert_eq!(
        std::fs::read(
            fixture
                .registry
                .join(format!("{TOKEN}.{}.claim", fixture.digest))
        )
        .unwrap(),
        fixture.contents
    );
}

#[test]
fn native_upload_refuses_outside_grants_before_any_workload_effect() {
    let fixture = Fixture::new();
    let outside = fixture.root.join("outside");
    let marker = fixture.root.join("must-not-exist");
    let output = fixture
        .command(&outside)
        .args(["sh", "-c", "printf unexpected > \"$1\"", "receiver"])
        .arg(&marker)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(73), "{output:?}");
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("outside its source grant"));
    assert!(!marker.exists());
    assert!(!outside.exists());
}

#[test]
fn native_upload_refuses_overlapping_claim_name_without_panicking_or_running_receiver() {
    let fixture = Fixture::new();
    std::fs::rename(
        fixture
            .registry
            .join(format!("{TOKEN}.{}.claim", fixture.digest)),
        fixture.registry.join(format!("{TOKEN}.claim")),
    )
    .unwrap();
    let marker = fixture.root.join("must-not-exist");
    let output = fixture
        .command(&fixture.first)
        .args(["sh", "-c", "printf unexpected > \"$1\"", "receiver"])
        .arg(&marker)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(73), "{output:?}");
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid source grant identity"));
    assert!(!marker.exists());
}
