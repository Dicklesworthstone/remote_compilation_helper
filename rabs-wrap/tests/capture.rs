//! Exercise output custody through the real wrapper binary and a real Unix
//! socket. The daemon is scripted: these tests exercise wrapper handoff behavior,
//! not the coordinator's storage or serving-evidence implementation.
#![cfg(unix)]

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const ATTEMPT: &str = "0123456789abcdef0123456789abcdef";
const CAPTURE: &str = "rabs.test-capture:0123456789";

struct Running(Option<Child>);

impl Running {
    fn output(&mut self) -> Output {
        let deadline = Instant::now() + Duration::from_secs(15);
        while self.0.as_mut().unwrap().try_wait().unwrap().is_none() {
            assert!(Instant::now() < deadline, "wrapper did not finish");
            std::thread::sleep(Duration::from_millis(10));
        }
        self.0.take().unwrap().wait_with_output().unwrap()
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

struct Fixture {
    root: tempfile::TempDir,
    socket: PathBuf,
    compiler: PathBuf,
}

fn read(peer: &mut BufReader<UnixStream>) -> Option<Value> {
    let mut line = String::new();
    if peer.read_line(&mut line).unwrap() == 0 {
        return None;
    }
    assert!(line.ends_with('\n'));
    Some(serde_json::from_str(&line).unwrap())
}

fn send(peer: &mut BufReader<UnixStream>, value: Value) {
    writeln!(peer.get_mut(), "{value}").unwrap();
}

fn captured() -> Value {
    json!({
        "kind": "rustc-captured", "capture_protocol": 1,
        "attempt": ATTEMPT, "capture": CAPTURE, "publication_authorized": false,
    })
}

impl Fixture {
    fn new(exit: u8) -> Self {
        let root = tempfile::tempdir().unwrap();
        let socket = root.path().join("capture.sock");
        let compiler = root.path().join("compiler with spaces");
        std::fs::write(
            &compiler,
            format!(
                "#!/bin/sh\nprintf 'run\\n' >> runs\nprintf '%s' \"$MODE_TOKEN\" > artifact\n\
                 printf 'diagnostic\\n' >&2\nexit {exit}\n"
            ),
        )
        .unwrap();
        std::fs::set_permissions(&compiler, std::fs::Permissions::from_mode(0o755)).unwrap();
        Self {
            root,
            socket,
            compiler,
        }
    }

    fn daemon(
        &self,
        modern: bool,
        script: impl FnOnce(&mut BufReader<UnixStream>) + Send + 'static,
    ) -> std::thread::JoinHandle<()> {
        let mut execute = json!({
            "kind": "rustc-decision", "decision": "execute", "attempt": ATTEMPT,
            "action_key": "action", "compiler_skip_authorized": false,
            "env": [["PATH", "/usr/bin:/bin"], ["MODE_TOKEN", "constructed"]],
        });
        if modern {
            execute["capture_protocol"] = json!(1);
        }
        self.daemon_reply(execute, script)
    }

    fn daemon_reply(
        &self,
        reply: Value,
        script: impl FnOnce(&mut BufReader<UnixStream>) + Send + 'static,
    ) -> std::thread::JoinHandle<()> {
        let listener = UnixListener::bind(&self.socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(15);
            let socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "wrapper did not connect");
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("accept: {error}"),
                }
            };
            socket
                .set_read_timeout(Some(Duration::from_secs(15)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(15)))
                .unwrap();
            let mut peer = BufReader::new(socket);
            assert_eq!(read(&mut peer).unwrap()["kind"], "hello");
            send(
                &mut peer,
                json!({"kind":"hello-ok", "transport":1, "application":1}),
            );
            assert_eq!(read(&mut peer).unwrap()["kind"], "rustc-request");
            send(&mut peer, reply);
            script(&mut peer);
        })
    }

    fn spawn(&self, capture_wait_ms: u64) -> Running {
        let child = Command::new(env!("CARGO_BIN_EXE_rabs-wrap"))
            .arg(&self.compiler)
            .args(["--crate-name", "demo", "src/lib.rs"])
            .current_dir(self.root.path())
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", self.root.path())
            .env("MODE_TOKEN", "original")
            .env("RABS_SOCKET_PATH", &self.socket)
            .env("RABS_BREAKER_FILE", self.root.path().join("breaker"))
            .env("RABS_LIVE_DECISION_MS", "5000")
            .env("RABS_CAPTURE_WAIT_MS", capture_wait_ms.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        Running(Some(child))
    }

    fn assert_once(&self, output: &Output, code: i32, token: &[u8]) {
        assert_eq!(output.status.code(), Some(code));
        assert!(output.stdout.is_empty());
        assert_eq!(output.stderr, b"diagnostic\n");
        assert_eq!(
            std::fs::read(self.root.path().join("runs")).unwrap(),
            b"run\n"
        );
        assert_eq!(
            std::fs::read(self.root.path().join("artifact")).unwrap(),
            token
        );
    }
}

#[test]
fn wrapper_retains_cargo_output_lifetime_until_capture_is_complete() {
    let fixture = Fixture::new(0);
    let artifact = fixture.root.path().join("artifact");
    let (ready, captured_report) = mpsc::channel();
    let (release, released) = mpsc::channel();
    let daemon = fixture.daemon(true, move |peer| {
        let report = read(peer).unwrap();
        assert_eq!(report["kind"], "rustc-complete");
        assert_eq!(report["capture_protocol"], 1);
        assert_eq!(report["exit_code"], 0);
        assert_eq!(report["attempt"], ATTEMPT);
        let bytes = std::fs::read(artifact).unwrap();
        assert_eq!(bytes, b"constructed");
        ready.send(()).unwrap();
        released.recv_timeout(Duration::from_secs(10)).unwrap();
        send(peer, captured());
        let ack = read(peer).unwrap();
        assert_eq!(ack["kind"], "rustc-capture-ack");
        assert_eq!(ack["attempt"], ATTEMPT);
        assert_eq!(ack["capture"], CAPTURE);
        assert!(
            read(peer).is_none(),
            "no retransmitted completion or execution"
        );
    });
    let mut wrapper = fixture.spawn(10_000);
    captured_report
        .recv_timeout(Duration::from_secs(10))
        .unwrap();
    assert!(wrapper.0.as_mut().unwrap().try_wait().unwrap().is_none());
    release.send(()).unwrap();
    let output = wrapper.output();
    daemon.join().unwrap();
    fixture.assert_once(&output, 0, b"constructed");
}

#[test]
fn disconnected_capture_does_not_change_exit_status_or_repeat_compilation() {
    let fixture = Fixture::new(7);
    let daemon = fixture.daemon(true, |peer| {
        let report = read(peer).unwrap();
        assert_eq!(report["exit_code"], 7);
        assert_eq!(report["capture_protocol"], 1);
        // Connection closes without claiming a captured result.
    });
    let output = fixture.spawn(5000).output();
    daemon.join().unwrap();
    fixture.assert_once(&output, 7, b"constructed");
}

#[test]
fn capture_timeout_or_wrong_identity_never_produces_acknowledgment() {
    for send_wrong_identity in [false, true] {
        let fixture = Fixture::new(0);
        let daemon = fixture.daemon(true, move |peer| {
            assert_eq!(read(peer).unwrap()["kind"], "rustc-complete");
            if send_wrong_identity {
                let mut receipt = captured();
                receipt["attempt"] = json!("another-attempt");
                send(peer, receipt);
            }
            assert!(
                read(peer).is_none(),
                "abandoned capture must not be acknowledged"
            );
        });
        let budget = if send_wrong_identity { 5000 } else { 100 };
        let output = fixture.spawn(budget).output();
        daemon.join().unwrap();
        fixture.assert_once(&output, 0, b"constructed");
    }
}

#[test]
fn old_daemon_execution_is_unobserved_and_cannot_receive_a_publishable_report() {
    let fixture = Fixture::new(7);
    let daemon = fixture.daemon(false, |peer| {
        assert!(
            read(peer).is_none(),
            "no completion report to an unversioned daemon"
        );
    });
    let output = fixture.spawn(5000).output();
    daemon.join().unwrap();
    fixture.assert_once(&output, 7, b"original");
}

#[test]
fn old_daemon_hit_is_declined_before_accepting_output_writes() {
    let fixture = Fixture::new(7);
    let daemon = fixture.daemon_reply(
        json!({
            "kind": "rustc-decision", "decision": "hit", "action_key": "action",
            "compiler_skip_authorized": false,
        }),
        |peer| {
            assert!(
                read(peer).is_none(),
                "no rustc-accept to a pre-custody daemon"
            )
        },
    );
    let output = fixture.spawn(5000).output();
    daemon.join().unwrap();
    fixture.assert_once(&output, 7, b"original");
}
