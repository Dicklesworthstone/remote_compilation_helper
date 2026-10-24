//! The real wrapper must not turn an abandoned Cargo request into local work
//! or cache-install consent. Protocol fixtures use a separately killable parent;
//! no test kills the wrapper itself to manufacture a passing cancellation.
#![cfg(target_os = "linux")]

use serde_json::{Value, json};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const WAIT: &str = "{\"kind\":\"rustc-decision\",\"decision\":\"wait\",\"action_key\":\"unit\",\"compiler_skip_authorized\":false,\"materialization_started\":false}\n";
const HIT: &str = "{\"kind\":\"rustc-decision\",\"decision\":\"hit\",\"action_key\":\"unit\",\"capture_protocol\":1,\"compiler_skip_authorized\":false}\n";

struct Parent(Child);

impl Parent {
    fn wait(&mut self) -> ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                return status;
            }
            assert!(Instant::now() < deadline, "fixture parent did not exit");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn cancel(&mut self) {
        self.0.kill().unwrap();
        assert!(!self.wait().success());
    }
}

impl Drop for Parent {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn wait_until(mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !condition() {
        assert!(Instant::now() < deadline, "fixture did not settle");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn stopped(pid: u32) -> bool {
    match std::fs::read(format!("/proc/{pid}/stat")) {
        Ok(bytes) => {
            let tail = &bytes[bytes.iter().rposition(|byte| *byte == b')').unwrap() + 1..];
            matches!(
                tail.split(u8::is_ascii_whitespace)
                    .find(|part| !part.is_empty()),
                Some(b"Z" | b"X" | b"x")
            )
        }
        Err(error) => error.kind() == io::ErrorKind::NotFound,
    }
}

fn read_frame(peer: &mut BufReader<UnixStream>) -> Value {
    let mut line = String::new();
    assert!(peer.read_line(&mut line).unwrap() > 0);
    assert!(line.ends_with('\n'));
    serde_json::from_str(&line).unwrap()
}

fn read_pid(path: &Path) -> u32 {
    let mut pid = None;
    wait_until(|| {
        pid = std::fs::read_to_string(path)
            .ok()
            .and_then(|value| value.trim().parse().ok());
        pid.is_some()
    });
    pid.unwrap()
}

struct Fixture {
    root: tempfile::TempDir,
    parent: Parent,
    peer: Option<BufReader<UnixStream>>,
    wrapper_pid: u32,
    stdout: PathBuf,
}

impl Fixture {
    /// Stop just after the wrapper's hello, before sending any reply. The
    /// parent shell remains the original caller while waiting for its child.
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let socket = root.path().join("edge.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let compiler = root.path().join("compiler with spaces");
        std::fs::write(
            &compiler,
            "#!/bin/sh\nprintf 'run\\n' >> compiler-runs\nprintf 'compiler stdout\\n'\nexit 7\n",
        )
        .unwrap();
        std::fs::set_permissions(&compiler, std::fs::Permissions::from_mode(0o755)).unwrap();
        let stdout = root.path().join("stdout");
        let parent = Parent(
            Command::new("/bin/sh")
                .args([
                    "-c",
                    "\"$@\" & child=$!; printf '%s\\n' \"$child\" > wrapper.pid; wait \"$child\"",
                    "cargo-like-parent",
                ])
                .arg(env!("CARGO_BIN_EXE_rabs-wrap"))
                .arg(&compiler)
                .args(["--crate-name", "demo", "lib.rs"])
                .current_dir(root.path())
                .env("RABS_SOCKET_PATH", &socket)
                .env("RABS_BREAKER_FILE", root.path().join("breaker"))
                // Longer than the peer's read bound: cancellation, not a
                // decision/install timeout, must close a stalled connection.
                .env("RABS_LIVE_DECISION_MS", "30000")
                .env("RABS_INSTALL_WAIT_MS", "30000")
                .env("RABS_SINGLEFLIGHT_WAIT_MS", "30000")
                .stdin(Stdio::null())
                .stdout(std::fs::File::create(&stdout).unwrap())
                .stderr(std::fs::File::create(root.path().join("stderr")).unwrap())
                .spawn()
                .unwrap(),
        );
        let mut stream = None;
        wait_until(|| match listener.accept() {
            Ok((accepted, _)) => {
                stream = Some(accepted);
                true
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => false,
            Err(error) => panic!("accept: {error}"),
        });
        let stream = stream.unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut peer = BufReader::new(stream);
        assert_eq!(read_frame(&mut peer)["kind"], "hello");
        let wrapper_pid = read_pid(&root.path().join("wrapper.pid"));
        assert!(!stopped(wrapper_pid));
        Self {
            root,
            parent,
            peer: Some(peer),
            wrapper_pid,
            stdout,
        }
    }

    fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.peer.as_mut().unwrap().get_mut().write_all(bytes)
    }

    fn request(&mut self) -> Value {
        self.send(b"{\"kind\":\"hello-ok\",\"transport\":1,\"application\":1}\n")
            .unwrap();
        let request = read_frame(self.peer.as_mut().unwrap());
        assert_eq!(request["kind"], "rustc-request");
        assert_eq!(request["wait_for_inflight"], true);
        request
    }

    fn assert_cancelled(&mut self) {
        let mut bytes = Vec::new();
        let result = self.peer.as_mut().unwrap().read_to_end(&mut bytes);
        // Closing before assertions bounds the old implementation as well:
        // it may be waiting for a 30-second decision or installation reply.
        drop(self.peer.take());
        wait_until(|| stopped(self.wrapper_pid));
        assert!(
            result.is_ok()
                || matches!(result, Err(ref error) if error.kind() == io::ErrorKind::ConnectionReset),
            "cancelled wrapper retained its connection: {result:?}"
        );
        assert!(
            bytes.is_empty(),
            "new request or consent after caller loss: {bytes:?}"
        );
        assert!(
            !self.root.path().join("compiler-runs").exists(),
            "cancelled request started the real compiler"
        );
        assert_eq!(std::fs::read(&self.stdout).unwrap(), b"");
    }
}

#[test]
fn caller_loss_during_hello_never_sends_a_compile_request() {
    let mut fixture = Fixture::new();
    fixture.parent.cancel();
    fixture.assert_cancelled();
}

#[test]
fn caller_loss_before_decision_cannot_become_hit_acceptance_or_fallback() {
    for reply in [
        HIT.to_owned(),
        WAIT.to_owned(),
        json!({"kind":"rustc-decision", "decision":"pass-through"}).to_string() + "\n",
        json!({"kind":"decision", "decision":"pass-through", "mode":"shadow"}).to_string() + "\n",
        json!({"kind":"rustc-decision", "decision":"execute", "attempt":"unit", "capture_protocol":1, "env":[]}).to_string() + "\n",
        json!({"kind":"rustc-decision", "decision":"execute", "attempt":"legacy", "env":[]}).to_string() + "\n",
        "not valid JSON\n".to_owned(),
    ] {
        let mut fixture = Fixture::new();
        fixture.request();
        fixture.parent.cancel();
        // The cancellation-aware wrapper may have closed before this write.
        let _ = fixture.send(reply.as_bytes());
        fixture.assert_cancelled();
    }
}

#[test]
fn caller_loss_during_singleflight_stops_waiting_without_another_request() {
    let mut fixture = Fixture::new();
    let original = fixture.request();
    fixture.send(WAIT.as_bytes()).unwrap();
    assert_eq!(read_frame(fixture.peer.as_mut().unwrap()), original);
    // The wrapper is now waiting for the reply to its first retry. Do not
    // supply another decision: it must notice caller loss independently.
    fixture.parent.cancel();
    fixture.assert_cancelled();
}

#[test]
fn caller_loss_after_acceptance_fails_closed_without_waiting_for_install_timeout() {
    let mut fixture = Fixture::new();
    fixture.request();
    fixture.send(HIT.as_bytes()).unwrap();
    assert_eq!(
        read_frame(fixture.peer.as_mut().unwrap())["kind"],
        "rustc-accept"
    );
    fixture.parent.cancel();
    fixture.assert_cancelled();
}

#[test]
fn living_caller_retains_exactly_once_fallback_and_original_exit_status() {
    for accepted in [false, true] {
        let mut fixture = Fixture::new();
        fixture.request();
        if accepted {
            fixture.send(HIT.as_bytes()).unwrap();
            assert_eq!(
                read_frame(fixture.peer.as_mut().unwrap())["kind"],
                "rustc-accept"
            );
            fixture.send(b"{\"kind\":\"rustc-decision\",\"decision\":\"serve-failed\",\"writer_returned\":true}\n").unwrap();
        } else {
            fixture
                .send(b"{\"kind\":\"rustc-decision\",\"decision\":\"pass-through\"}\n")
                .unwrap();
        }
        assert_eq!(fixture.parent.wait().code(), Some(7));
        assert_eq!(
            std::fs::read(fixture.root.path().join("compiler-runs")).unwrap(),
            b"run\n"
        );
        assert_eq!(
            std::fs::read(&fixture.stdout).unwrap(),
            b"compiler stdout\n"
        );
    }
}
