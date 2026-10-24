//! Exercise singleflight followers through the REAL wrapper process and Unix
//! socket, with a scripted daemon. The shell compiler records every execution.
//! These prove wrapper/protocol behavior, not coordinator trust qualification.
#![cfg(unix)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

struct Fixture {
    root: tempfile::TempDir,
    socket: PathBuf,
    compiler: PathBuf,
    marker: PathBuf,
}

fn read(peer: &mut BufReader<UnixStream>) -> Option<String> {
    let mut line = String::new();
    (peer.read_line(&mut line).unwrap() != 0).then_some(line)
}

fn send(peer: &mut BufReader<UnixStream>, value: Value) {
    writeln!(peer.get_mut(), "{value}").unwrap();
}

fn wait(peer: &mut BufReader<UnixStream>) {
    send(
        peer,
        json!({
            "kind": "rustc-decision", "decision": "wait", "action_key": "key",
            "compiler_skip_authorized": false, "materialization_started": false,
        }),
    );
}

fn hit(peer: &mut BufReader<UnixStream>) {
    send(
        peer,
        json!({
            "kind": "rustc-decision", "decision": "hit", "action_key": "key",
            "capture_protocol": 1, "compiler_skip_authorized": false,
        }),
    );
    let accept: Value = serde_json::from_str(&read(peer).unwrap()).unwrap();
    assert_eq!(accept["kind"], "rustc-accept");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let socket = root.path().join("edge.sock");
        let compiler = root.path().join("rustc");
        let marker = root.path().join("compiler-runs");
        std::fs::write(
            &compiler,
            concat!(
                "#!/bin/sh\n",
                "printf 'run\\n' >> \"$RABS_TEST_MARKER\"\n",
                "printf '%s\\n' \"$MODE_TOKEN\"\n",
                "printf 'compiler stderr\\n' >&2\n",
                "exit 7\n",
            ),
        )
        .unwrap();
        std::fs::set_permissions(&compiler, std::fs::Permissions::from_mode(0o755)).unwrap();
        Self {
            root,
            socket,
            compiler,
            marker,
        }
    }

    fn daemon(
        &self,
        script: impl FnOnce(&mut BufReader<UnixStream>, &str, &Path) + Send + 'static,
    ) -> std::thread::JoinHandle<()> {
        let listener = UnixListener::bind(&self.socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let marker = self.marker.clone();
        std::thread::spawn(move || {
            // A broken wrapper that never connects must fail, not hang tests.
            let deadline = Instant::now() + Duration::from_secs(10);
            let stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "wrapper never connected");
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("accept: {error}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut peer = BufReader::new(stream);
            let hello: Value = serde_json::from_str(&read(&mut peer).unwrap()).unwrap();
            assert_eq!(hello["kind"], "hello");
            send(
                &mut peer,
                json!({"kind":"hello-ok", "transport":1, "application":1}),
            );
            let original = read(&mut peer).unwrap();
            let request: Value = serde_json::from_str(&original).unwrap();
            assert_eq!(request["kind"], "rustc-request");
            assert_eq!(request["wait_for_inflight"], true);
            assert!(!marker.exists(), "consult precedes compiler execution");
            script(&mut peer, &original, &marker);
        })
    }

    fn run(&self, wait_ms: u64) -> Output {
        Command::new(env!("CARGO_BIN_EXE_rabs-wrap"))
            .arg(&self.compiler)
            .args(["--crate-name", "demo", "src/lib.rs"])
            .current_dir(self.root.path())
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", self.root.path())
            .env("RABS_SOCKET_PATH", &self.socket)
            .env("RABS_BREAKER_FILE", self.root.path().join("breaker"))
            .env("RABS_LIVE_DECISION_MS", "5000")
            .env("RABS_SINGLEFLIGHT_WAIT_MS", wait_ms.to_string())
            .env("RABS_INSTALL_WAIT_MS", "1000")
            .env("RABS_TEST_MARKER", &self.marker)
            .env("MODE_TOKEN", "original")
            .output()
            .unwrap()
    }

    fn assert_local_once(&self, output: &Output) {
        assert_eq!(output.status.code(), Some(7));
        assert_eq!(output.stdout, b"original\n");
        assert_eq!(output.stderr, b"compiler stderr\n");
        assert_eq!(std::fs::read(&self.marker).unwrap(), b"run\n");
    }
}

#[test]
fn follower_reuses_a_completed_result_without_running_its_compiler() {
    let fixture = Fixture::new();
    let transcript = b"cached transcript\xff\n";
    let daemon = fixture.daemon(move |peer, original, marker| {
        for _ in 0..2 {
            wait(peer);
            assert_eq!(
                read(peer).as_deref(),
                Some(original),
                "retry exact request bytes"
            );
            assert!(!marker.exists(), "waiting is not permission to compile");
        }
        hit(peer);
        assert!(!marker.exists());
        send(
            peer,
            json!({
                "kind":"rustc-decision", "decision":"served", "action_key":"key",
                "compiler_skip_authorized":true, "stderr_hex":hex(transcript),
            }),
        );
    });
    let output = fixture.run(5000);
    daemon.join().unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, transcript);
    assert!(!fixture.marker.exists());
}

#[test]
fn follower_can_become_the_next_admitted_executor_and_reports_exact_completion() {
    let fixture = Fixture::new();
    let daemon = fixture.daemon(|peer, original, marker| {
        wait(peer);
        assert_eq!(read(peer).as_deref(), Some(original));
        assert!(!marker.exists());
        send(peer, json!({
            "kind":"rustc-decision", "decision":"execute", "action_key":"key",
            "capture_protocol":1, "compiler_skip_authorized":false, "attempt":"00ab",
            "env":[["RABS_TEST_MARKER", marker.to_str().unwrap()], ["MODE_TOKEN", "constructed"]],
        }));
        let completion: Value = serde_json::from_str(&read(peer).unwrap()).unwrap();
        assert_eq!(completion["kind"], "rustc-complete");
        assert_eq!(completion["attempt"], "00ab");
        assert_eq!(completion["exit_code"], 7);
        assert!(completion["signal"].is_null());
        assert_eq!(completion["stdout_hex"], hex(b"constructed\n"));
        assert_eq!(completion["stderr_hex"], hex(b"compiler stderr\n"));
    });
    let output = fixture.run(5000);
    daemon.join().unwrap();
    assert_eq!(output.status.code(), Some(7));
    assert_eq!(output.stdout, b"constructed\n");
    assert_eq!(output.stderr, b"compiler stderr\n");
    assert_eq!(std::fs::read(&fixture.marker).unwrap(), b"run\n");
}

#[test]
fn disabled_waiting_falls_back_without_acceptance_or_breaker_failure() {
    let fixture = Fixture::new();
    let daemon = fixture.daemon(|peer, _, _| {
        wait(peer);
        assert!(
            read(peer).is_none(),
            "no retry or acceptance when the wait budget is zero"
        );
    });
    let output = fixture.run(0);
    daemon.join().unwrap();
    fixture.assert_local_once(&output);
    let state = std::fs::read(fixture.root.path().join("breaker")).unwrap();
    assert_eq!(
        rabs_protocol::wrapper_breaker::decode_state(&state).unwrap(),
        rabs_protocol::wrapper_breaker::BreakerState::fresh(),
        "healthy contention is not a failed daemon consult",
    );
}

#[test]
fn repeated_waits_exhaust_one_budget_instead_of_renewing_it() {
    let fixture = Fixture::new();
    let daemon = fixture.daemon(|peer, original, _| {
        let mut requests = 0;
        loop {
            wait(peer);
            let Some(retry) = read(peer) else { break };
            assert_eq!(retry, original);
            requests += 1;
            // 50ms first delay plus 100ms second delay cannot fit in 100ms.
            assert!(requests <= 1, "a wait reply renewed the absolute deadline");
        }
    });
    let output = fixture.run(100);
    daemon.join().unwrap();
    fixture.assert_local_once(&output);
}

#[test]
fn a_disconnected_waiter_runs_locally_before_any_hit_acceptance() {
    let fixture = Fixture::new();
    let daemon = fixture.daemon(|peer, _, _| wait(peer));
    let output = fixture.run(5000);
    daemon.join().unwrap();
    fixture.assert_local_once(&output);
}

#[test]
fn changed_action_identity_is_never_accepted_or_executed_as_the_followed_flight() {
    for decision in ["wait", "hit", "execute"] {
        let fixture = Fixture::new();
        let daemon = fixture.daemon(move |peer, original, _| {
            wait(peer);
            assert_eq!(read(peer).as_deref(), Some(original));
            send(
                peer,
                json!({
                    "kind":"rustc-decision", "decision":decision, "action_key":"different",
                    "compiler_skip_authorized":false, "materialization_started":false,
                    "attempt":"unexpected", "env":[],
                }),
            );
            assert!(
                read(peer).is_none(),
                "a different flight cannot receive acceptance"
            );
        });
        let output = fixture.run(5000);
        daemon.join().unwrap();
        fixture.assert_local_once(&output);
    }
}

#[test]
fn follower_remains_fail_closed_after_accepting_a_hit() {
    let fixture = Fixture::new();
    let daemon = fixture.daemon(|peer, original, marker| {
        wait(peer);
        assert_eq!(read(peer).as_deref(), Some(original));
        hit(peer);
        assert!(!marker.exists());
        // Close without confirmation: acceptance may have started a writer.
    });
    let output = fixture.run(5000);
    daemon.join().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("refusing to run rustc"));
    assert!(
        !fixture.marker.exists(),
        "ambiguous install cannot run a second compiler"
    );
}
