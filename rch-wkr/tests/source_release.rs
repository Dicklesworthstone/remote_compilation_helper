//! Exercise native release framing and read-only cancellation with real pipes.

#![cfg(unix)]
#![forbid(unsafe_code)]

use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use rustix::fs::FlockOperation;
use sha2::{Digest, Sha256};

const WORKER: &str = env!("CARGO_BIN_EXE_rch-wkr");
const TOKEN: &str = "abc-123";
const CONTENT: &[u8] = b"/source with ' spaces\n/dependency\n";

struct Fixture {
    owner: tempfile::TempDir,
    registry: PathBuf,
    digest: String,
}

impl Fixture {
    fn new() -> Self {
        let owner = tempfile::Builder::new()
            .prefix("source-release-cli-")
            .disable_cleanup(true)
            .tempdir()
            .unwrap();
        let registry = owner.path().join("registry ' ; café");
        std::fs::create_dir(&registry).unwrap();
        for name in ["cancelled", "released", "quarantine"] {
            std::fs::create_dir(registry.join(name)).unwrap();
        }
        std::fs::write(registry.join("metadata.lock"), b"").unwrap();
        std::fs::write(owner.path().join("blocked-log"), b"keep").unwrap();
        let digest = Sha256::digest(CONTENT)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        Self {
            owner,
            registry,
            digest,
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(WORKER);
        command
            .arg("source-release")
            .env_clear()
            .env("PATH", "")
            .env("TOKIO_WORKER_THREADS", "0")
            .env(
                "RCH_LOG_FILE",
                self.owner.path().join("blocked-log/worker.log"),
            );
        command
    }

    fn release(mode: &str) -> Vec<u8> {
        let prefix = if mode == "source" {
            "RCH_SOURCE_AUTHORITY_RELEASE"
        } else {
            "RCH_SOURCE_PAIR_RELEASE"
        };
        format!("{prefix}:{TOKEN}\n").into_bytes()
    }

    fn waiter(&self, mode: &str, pair_root: Option<&str>) -> Waiter {
        let selector = if mode == "source" {
            &self.digest
        } else {
            pair_root.unwrap_or("/source with ' spaces")
        };
        let release = Self::release(mode);
        let mut command = self.command();
        command
            .arg("wait")
            .arg(mode)
            .arg(&self.registry)
            .arg(TOKEN)
            .arg(selector)
            .arg(std::str::from_utf8(&release[..release.len() - 1]).unwrap());
        Waiter::new(command)
    }

    fn record(&self, place: &str, extension: &str) -> PathBuf {
        let path = self
            .registry
            .join(place)
            .join(format!("{TOKEN}.{}.{extension}", self.digest));
        std::fs::write(&path, CONTENT).unwrap();
        path
    }
}

struct Waiter {
    child: Child,
    finished: bool,
}

impl Waiter {
    fn new(mut command: Command) -> Self {
        let child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        Self {
            child,
            finished: false,
        }
    }

    fn send(&mut self, bytes: &[u8]) {
        self.child.stdin.as_mut().unwrap().write_all(bytes).unwrap();
    }

    fn disconnect(&mut self) {
        self.child.stdin.take();
    }

    fn assert_waiting(&mut self) {
        let deadline = Instant::now() + Duration::from_millis(350);
        while Instant::now() < deadline {
            assert!(
                self.child.try_wait().unwrap().is_none(),
                "ambiguous state or incomplete frame released the holder"
            );
            thread::sleep(Duration::from_millis(5));
        }
    }

    fn finish(&mut self, expected: i32) -> Output {
        let deadline = Instant::now() + Duration::from_secs(5);
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            assert!(Instant::now() < deadline, "release worker did not finish");
            thread::sleep(Duration::from_millis(5));
        };
        self.finished = true;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        self.child
            .stdout
            .take()
            .unwrap()
            .read_to_end(&mut stdout)
            .unwrap();
        self.child
            .stderr
            .take()
            .unwrap()
            .read_to_end(&mut stderr)
            .unwrap();
        let output = Output {
            status,
            stdout,
            stderr,
        };
        assert_eq!(status.code(), Some(expected), "{output:?}");
        assert!(
            output.stdout.is_empty(),
            "waiter published an unauthorized receipt: {output:?}"
        );
        output
    }
}

impl Drop for Waiter {
    fn drop(&mut self) {
        self.child.stdin.take();
        if !self.finished {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

#[test]
fn probe_and_argument_refusal_require_no_runtime_logging_or_host_programs() {
    let fixture = Fixture::new();
    let probe = fixture.command().arg("probe").output().unwrap();
    assert!(probe.status.success(), "{probe:?}");
    assert_eq!(probe.stdout, b"rch-wkr source-release v1\n");
    assert!(probe.stderr.is_empty());
    let mut command = fixture.command();
    command
        .args(["wait", "source"])
        .arg(&fixture.registry)
        .args([
            "invalid-token",
            &fixture.digest,
            "RCH_SOURCE_AUTHORITY_RELEASE:invalid-token",
        ]);
    let output = Waiter::new(command).finish(73);
    assert!(
        output
            .stderr
            .starts_with(b"RCH: source release wait failed:")
    );
    assert_eq!(
        std::fs::read(fixture.owner.path().join("blocked-log")).unwrap(),
        b"keep"
    );
}

#[test]
fn exact_partial_release_completes_without_stdin_eof_for_every_mode() {
    for mode in ["source", "pair", "cleanup-pair"] {
        let fixture = Fixture::new();
        let mut waiter = fixture.waiter(mode, None);
        let release = Fixture::release(mode);
        let split = release.len() / 2;
        waiter.send(&release[..split]);
        waiter.assert_waiting();
        waiter.send(&release[split..]);
        // Keep stdin open: exact release must return so the terminal can retire
        // ownership and write its acknowledgement on this same live session.
        let output = waiter.finish(0);
        assert!(waiter.child.stdin.is_some());
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn wrong_coalesced_or_incomplete_release_input_refuses_without_receipt() {
    let fixture = Fixture::new();
    let release = Fixture::release("source");
    for input in [
        b"RCH_SOURCE_AUTHORITY_RELEASE:def-456\n".to_vec(),
        [release.as_slice(), b"extra"].concat(),
        b"RCH_SOURCE_AUTHORITY_RELEASE:abc-123\0\n".to_vec(),
        release[..release.len() - 1].to_vec(),
        Vec::new(),
    ] {
        let mut waiter = fixture.waiter("source", None);
        waiter.send(&input);
        waiter.disconnect();
        let output = waiter.finish(73);
        assert!(
            output
                .stderr
                .starts_with(b"RCH: source release wait failed:")
        );
    }
}

#[test]
fn only_coherent_cancellation_yields_75_and_never_retires_durable_records() {
    for mode in ["source", "pair"] {
        for state in 0..3 {
            let fixture = Fixture::new();
            let claim = if state == 0 {
                fixture.record("", "claim")
            } else {
                fixture.record("cancelled", "claim")
            };
            let fence = (state != 1).then(|| fixture.record("", "cancelling"));
            let output = fixture.waiter(mode, None).finish(75);
            assert!(
                String::from_utf8_lossy(&output.stderr)
                    .contains("yielding kernel locks without retiring ownership")
            );
            assert_eq!(std::fs::read(&claim).unwrap(), CONTENT);
            if let Some(fence) = fence {
                assert_eq!(std::fs::read(fence).unwrap(), CONTENT);
            }
            assert!(
                std::fs::read_dir(fixture.registry.join("released"))
                    .unwrap()
                    .next()
                    .is_none()
            );
        }
    }
}

#[test]
fn corrupted_conflicting_or_unrelated_snapshots_keep_waiting_for_explicit_release() {
    for problem in [
        "fence-only",
        "corrupt",
        "pending",
        "wrong-digest",
        "wrong-pair-root",
        "unrelated",
    ] {
        let fixture = Fixture::new();
        let mode = if problem == "wrong-pair-root" {
            "pair"
        } else {
            "source"
        };
        match problem {
            "fence-only" => {
                fixture.record("", "cancelling");
            }
            "corrupt" => {
                std::fs::write(fixture.record("cancelled", "claim"), b"/wrong-content\n").unwrap();
            }
            "pending" => {
                fixture.record("cancelled", "claim");
                fixture.record("", "pending");
            }
            "wrong-digest" => {
                fixture.record("cancelled", "claim");
                std::fs::write(
                    fixture
                        .registry
                        .join(format!("{TOKEN}.{}.pending", "0".repeat(64))),
                    CONTENT,
                )
                .unwrap();
            }
            "wrong-pair-root" => {
                fixture.record("cancelled", "claim");
            }
            "unrelated" => {
                std::fs::write(
                    fixture
                        .registry
                        .join("cancelled")
                        .join(format!("def-456.{}.claim", fixture.digest)),
                    CONTENT,
                )
                .unwrap();
            }
            _ => unreachable!(),
        }
        let mut waiter = fixture.waiter(
            mode,
            (problem == "wrong-pair-root").then_some("/different-root"),
        );
        waiter.assert_waiting();
        waiter.send(&Fixture::release(mode));
        let output = waiter.finish(0);
        assert!(output.stderr.is_empty(), "{problem}: {output:?}");
    }
}

#[test]
fn metadata_contention_never_blocks_explicit_release_and_yields_after_unlock() {
    let fixture = Fixture::new();
    fixture.record("cancelled", "claim");
    let mutex = File::open(fixture.registry.join("metadata.lock")).unwrap();
    rustix::fs::flock(&mutex, FlockOperation::NonBlockingLockExclusive).unwrap();
    let mut explicit = fixture.waiter("source", None);
    explicit.assert_waiting();
    explicit.send(&Fixture::release("source"));
    assert!(explicit.finish(0).stderr.is_empty());
    let mut cancelled = fixture.waiter("source", None);
    cancelled.assert_waiting();
    drop(mutex);
    cancelled.finish(75);
}

#[test]
fn cleanup_pair_ignores_even_valid_cancellation_until_exact_explicit_release() {
    let fixture = Fixture::new();
    let claim = fixture.record("cancelled", "claim");
    let mut waiter = fixture.waiter("cleanup-pair", None);
    waiter.assert_waiting();
    waiter.send(&Fixture::release("cleanup-pair"));
    assert!(waiter.finish(0).stderr.is_empty());
    assert_eq!(std::fs::read(claim).unwrap(), CONTENT);
}

#[test]
fn unread_diagnostics_cannot_delay_cancellation_lock_yield() {
    let fixture = Fixture::new();
    fixture.record("cancelled", "claim");
    let (reader, writer) = rustix::pipe::pipe_with(
        rustix::pipe::PipeFlags::CLOEXEC | rustix::pipe::PipeFlags::NONBLOCK,
    )
    .unwrap();
    let block = [b'x'; 4096];
    loop {
        match rustix::io::write(&writer, &block) {
            Ok(_) => {}
            Err(rustix::io::Errno::AGAIN) => break,
            result => panic!("fill diagnostic pipe: {result:?}"),
        }
    }
    let flags = rustix::fs::fcntl_getfl(&writer).unwrap();
    rustix::fs::fcntl_setfl(&writer, flags & !rustix::fs::OFlags::NONBLOCK).unwrap();
    let mut command = fixture.command();
    let release = Fixture::release("source");
    let mut child = command
        .arg("wait")
        .arg("source")
        .arg(&fixture.registry)
        .arg(TOKEN)
        .arg(&fixture.digest)
        .arg(std::str::from_utf8(&release[..release.len() - 1]).unwrap())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::from(writer))
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
            panic!("full stderr pipe prevented cancellation yield");
        }
        thread::sleep(Duration::from_millis(5));
    };
    assert_eq!(status.code(), Some(75));
    drop(reader);
}
