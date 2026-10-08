//! The wrapper half of the live dependency protocol (bd-k52xe), against a
//! scripted daemon on a real Unix socket and the REAL wrapper binary.
//!
//! The compiler is a script that leaves a marker when it runs, so every
//! test can state exactly whether the compiler executed:
//!
//! - a served hit replays the transcript and NEVER runs the compiler;
//! - a hit is only installed after the wrapper accepts it, and a failed
//!   install runs the compiler only after an explicit writer-return receipt;
//! - an uncertain install fails the compile closed, including connection
//!   loss while an independent daemon writer remains alive;
//! - an admitted execution runs with exactly the daemon's constructed
//!   environment and reports exact streams and exit status.
#![cfg(unix)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

fn wrap() -> &'static str {
    env!("CARGO_BIN_EXE_rabs-wrap")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
        .collect()
}

/// What the scripted daemon does after its decision.
enum Script {
    /// Reply this line to the request; done.
    Reply(String),
    /// Reply `hit`, require `rustc-accept`, then answer (None = close).
    Hit(Option<String>),
    /// Reply `hit`, require `rustc-accept`, then never answer.
    HitThenHang,
    /// Close after acceptance, then keep a writer alive until the test
    /// permits it to write. Connection loss cannot authorize local rustc.
    HitThenDisconnect {
        artifact: PathBuf,
        continue_writing: std::sync::mpsc::Receiver<()>,
    },
    /// Reply `execute` with this env, then return the completion frame.
    Execute(Vec<(String, String)>),
}

struct Fixture {
    dir: tempfile::TempDir,
    socket: PathBuf,
    compiler: PathBuf,
    marker: PathBuf,
}

impl Fixture {
    fn new(compiler_body: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("d.sock");
        let marker = dir.path().join("compiler-ran");
        let compiler = dir.path().join("rustc");
        std::fs::write(
            &compiler,
            format!("#!/bin/sh\ntouch '{}'\n{compiler_body}", marker.display()),
        )
        .unwrap();
        std::fs::set_permissions(&compiler, std::fs::Permissions::from_mode(0o755)).unwrap();
        Self {
            dir,
            socket,
            compiler,
            marker,
        }
    }

    /// Serve ONE connection on a thread; returns what the daemon received.
    fn daemon(&self, script: Script) -> std::thread::JoinHandle<Vec<serde_json::Value>> {
        let listener = UnixListener::bind(&self.socket).unwrap();
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(30)))
                .unwrap();
            let mut writer = stream.try_clone().unwrap();
            let mut reader = BufReader::new(stream);
            let mut received = Vec::new();
            let read = |reader: &mut BufReader<_>| -> Option<serde_json::Value> {
                let mut line = String::new();
                (reader.read_line(&mut line).ok()? > 0)
                    .then(|| serde_json::from_str(&line).unwrap())
            };
            let hello = read(&mut reader).unwrap();
            assert_eq!(hello["kind"], "hello");
            writer
                .write_all(b"{\"kind\":\"hello-ok\",\"transport\":1,\"application\":1}\n")
                .unwrap();
            let request = read(&mut reader).unwrap();
            received.push(request);
            let hit = "{\"kind\":\"rustc-decision\",\"decision\":\"hit\",\"action_key\":\"k\",\
                       \"capture_protocol\":1,\"compiler_skip_authorized\":false}\n";
            match script {
                Script::Reply(line) => {
                    writer.write_all(format!("{line}\n").as_bytes()).unwrap();
                }
                Script::Hit(answer) => {
                    writer.write_all(hit.as_bytes()).unwrap();
                    let accept = read(&mut reader).unwrap();
                    assert_eq!(accept["kind"], "rustc-accept");
                    received.push(accept);
                    if let Some(answer) = answer {
                        writer.write_all(format!("{answer}\n").as_bytes()).unwrap();
                    }
                }
                Script::HitThenHang => {
                    writer.write_all(hit.as_bytes()).unwrap();
                    let accept = read(&mut reader).unwrap();
                    received.push(accept);
                    // Hold the connection open without answering until the
                    // wrapper gives up.
                    let _ = read(&mut reader);
                }
                Script::HitThenDisconnect {
                    artifact,
                    continue_writing,
                } => {
                    writer.write_all(hit.as_bytes()).unwrap();
                    let accept = read(&mut reader).unwrap();
                    assert_eq!(accept["kind"], "rustc-accept");
                    received.push(accept);
                    drop(reader);
                    drop(writer);
                    // The daemon thread is still alive. Its filesystem work
                    // does not depend on the connection staying open.
                    continue_writing
                        .recv_timeout(Duration::from_secs(30))
                        .unwrap();
                    std::fs::write(artifact, b"late daemon output").unwrap();
                }
                Script::Execute(env) => {
                    let reply = serde_json::json!({
                        "kind": "rustc-decision", "decision": "execute",
                        "action_key": "k", "attempt": "00ab", "env": env,
                        "capture_protocol": 1, "compiler_skip_authorized": false,
                    });
                    writer.write_all(format!("{reply}\n").as_bytes()).unwrap();
                    if let Some(completion) = read(&mut reader) {
                        received.push(completion);
                    }
                }
            }
            received
        })
    }

    fn run(&self, extra_env: &[(&str, &str)]) -> std::process::Output {
        let mut command = Command::new(wrap());
        command
            .arg(&self.compiler)
            .args(["--crate-name", "demo", "src/lib.rs"])
            .current_dir(self.dir.path())
            .env("RABS_SOCKET_PATH", &self.socket)
            .env("RABS_BREAKER_FILE", self.dir.path().join("breaker"));
        for (name, value) in extra_env {
            command.env(name, value);
        }
        command.output().unwrap()
    }

    fn compiler_ran(&self) -> bool {
        Path::new(&self.marker).exists()
    }
}

#[test]
fn a_served_hit_replays_the_transcript_and_never_runs_the_compiler() {
    let fixture = Fixture::new("echo compiled >&2\nexit 0\n");
    let transcript = b"{\"$message_type\":\"artifact\",\"artifact\":\"/o/libdemo.rmeta\"}\n";
    let daemon = fixture.daemon(Script::Hit(Some(
        serde_json::json!({
            "kind": "rustc-decision", "decision": "served", "action_key": "k",
            "stderr_hex": hex(transcript), "compiler_skip_authorized": true,
        })
        .to_string(),
    )));
    let output = fixture.run(&[("CARGO_PKG_NAME", "demo")]);
    let received = daemon.join().unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stderr, transcript);
    assert!(output.stdout.is_empty());
    assert!(
        !fixture.compiler_ran(),
        "a served hit must not run the compiler"
    );
    // The request carried the complete argv (real compiler first), cwd and
    // environment VALUES — what the daemon needs to key the action exactly.
    let request = &received[0];
    assert_eq!(request["kind"], "rustc-request");
    assert_eq!(
        request["argv"][0].as_str().unwrap(),
        fixture.compiler.to_str().unwrap()
    );
    assert!(
        request["env"]
            .as_array()
            .unwrap()
            .iter()
            .any(|pair| pair[0] == "CARGO_PKG_NAME" && pair[1] == "demo")
    );
    assert_eq!(received[1]["kind"], "rustc-accept");
}

#[test]
fn a_served_reply_without_skip_authority_is_not_a_hit() {
    let fixture = Fixture::new("exit 0\n");
    let daemon = fixture.daemon(Script::Hit(Some(
        serde_json::json!({
            "kind": "rustc-decision", "decision": "served",
            "stderr_hex": "", "compiler_skip_authorized": false,
        })
        .to_string(),
    )));
    let output = fixture.run(&[]);
    daemon.join().unwrap();
    // Neither a skip nor a safe fall-through: the install outcome is
    // unexplained, so the wrapper fails closed.
    assert_eq!(output.status.code(), Some(1));
    assert!(!fixture.compiler_ran());
}

#[test]
fn a_confirmed_failed_install_runs_the_compiler() {
    let fixture = Fixture::new("echo compiled >&2\nexit 3\n");
    let daemon = fixture.daemon(Script::Hit(Some(
        "{\"kind\":\"rustc-decision\",\"decision\":\"serve-failed\",\"reason\":\"x\",\
         \"writer_returned\":true}"
            .to_owned(),
    )));
    let output = fixture.run(&[]);
    daemon.join().unwrap();
    assert!(fixture.compiler_ran());
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(output.stderr, b"compiled\n");
}

#[test]
fn malformed_or_unconfirmed_install_answers_fail_closed() {
    for answer in [
        None,
        Some("{\"kind\":\"rustc-decision\",\"decision\":\"served\""),
        Some("{\"kind\":\"rustc-decision\",\"decision\":\"serve-failed\"}"),
        Some(
            "{\"kind\":\"rustc-decision\",\"decision\":\"serve-failed\",\
             \"writer_returned\":false}",
        ),
        Some(
            "{\"kind\":\"rustc-decision\",\"decision\":\"serve-failed\",\
             \"writer_returned\":\"true\"}",
        ),
        Some(
            "{\"kind\":\"rustc-decision\",\"decision\":\"serve-failed\",\
             \"writer_returned\":true,\"writer_returned\":false}",
        ),
        Some("{\"decision\":\"serve-failed\",\"writer_returned\":true}"),
        Some(
            "{\"kind\":\"status\",\"decision\":\"serve-failed\",\
             \"writer_returned\":true}",
        ),
        Some(
            "{\"kind\":\"status\",\"decision\":\"served\",\
             \"compiler_skip_authorized\":true,\"stderr_hex\":\"\"}",
        ),
        Some(
            "{\"kind\":\"rustc-decision\",\"decision\":\"served\",\
             \"compiler_skip_authorized\":true,\"stderr_hex\":\"zz\"}",
        ),
        Some(
            "{\"kind\":\"rustc-decision\",\"decision\":\"served\",\
             \"compiler_skip_authorized\":true}",
        ),
    ] {
        let fixture = Fixture::new("echo compiled >&2\nexit 3\n");
        let daemon = fixture.daemon(Script::Hit(answer.map(str::to_owned)));
        let output = fixture.run(&[]);
        daemon.join().unwrap();
        assert!(!fixture.compiler_ran(), "answer: {answer:?}");
        assert_eq!(output.status.code(), Some(1), "answer: {answer:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("refusing to run rustc"),
            "answer: {answer:?}; output: {output:?}"
        );
    }
}

#[test]
fn a_disconnected_daemon_with_a_live_writer_cannot_trigger_compiler_reexecution() {
    let fixture = Fixture::new("echo compiled >&2\nexit 3\n");
    let artifact = fixture.dir.path().join("libdemo.rlib");
    let (release_writer, continue_writing) = std::sync::mpsc::channel();
    let daemon = fixture.daemon(Script::HitThenDisconnect {
        artifact: artifact.clone(),
        continue_writing,
    });
    let output = fixture.run(&[]);
    let compiler_ran_before_late_write = fixture.compiler_ran();
    let artifact_existed_before_late_write = artifact.exists();
    release_writer.send(()).unwrap();
    daemon.join().unwrap();
    assert_eq!(
        std::fs::read(&artifact).unwrap(),
        b"late daemon output",
        "the writer survives the closed connection and wrapper exit"
    );
    assert!(!artifact_existed_before_late_write);
    assert!(
        !compiler_ran_before_late_write && !fixture.compiler_ran(),
        "connection loss must not run rustc while the daemon can still write"
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("refusing to run rustc"));
}

#[test]
fn an_unanswered_install_fails_closed_without_running_the_compiler() {
    let fixture = Fixture::new("exit 0\n");
    let daemon = fixture.daemon(Script::HitThenHang);
    let output = fixture.run(&[("RABS_INSTALL_WAIT_MS", "300")]);
    daemon.join().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(!fixture.compiler_ran());
    assert!(String::from_utf8_lossy(&output.stderr).contains("refusing to run rustc"));
}

#[test]
fn an_admitted_execution_uses_the_constructed_env_and_reports_exact_streams() {
    let fixture = Fixture::new(
        "printf 'out:%s\\n' \"$ONLY\"\nprintf 'only=%s secret=%s\\n' \"$ONLY\" \"${SECRET:-absent}\" >&2\nexit 7\n",
    );
    let daemon = fixture.daemon(Script::Execute(vec![
        ("ONLY".to_owned(), "kept".to_owned()),
        ("PATH".to_owned(), "/usr/bin:/bin".to_owned()),
    ]));
    let output = fixture.run(&[("SECRET", "must-not-reach-the-compiler")]);
    let received = daemon.join().unwrap();
    assert!(fixture.compiler_ran());
    assert_eq!(output.status.code(), Some(7), "exit status preserved");
    assert_eq!(output.stdout, b"out:kept\n", "stdout forwarded");
    assert_eq!(
        output.stderr, b"only=kept secret=absent\n",
        "stderr forwarded"
    );
    let completion = &received[1];
    assert_eq!(completion["kind"], "rustc-complete");
    assert_eq!(completion["attempt"], "00ab");
    assert_eq!(completion["exit_code"], 7);
    assert_eq!(completion["signal"], serde_json::Value::Null);
    assert_eq!(
        unhex(completion["stderr_hex"].as_str().unwrap()),
        b"only=kept secret=absent\n"
    );
    assert_eq!(
        unhex(completion["stdout_hex"].as_str().unwrap()),
        b"out:kept\n"
    );
}

#[test]
fn pass_through_and_malformed_decisions_run_the_compiler() {
    for reply in [
        "{\"kind\":\"rustc-decision\",\"decision\":\"pass-through\",\"reason\":\"LIVE_DEP_X\"}",
        "{\"kind\":\"rustc-decision\",\"decision\":\"execute\"}",
        "{\"kind\":\"rustc-decision\",\"decision\":\"served\",\"stderr_hex\":\"zz\"}",
        "{\"kind\":\"rustc-decision\"",
    ] {
        let fixture = Fixture::new("echo compiled >&2\nexit 0\n");
        let daemon = fixture.daemon(Script::Reply(reply.to_owned()));
        let output = fixture.run(&[]);
        daemon.join().unwrap();
        assert!(fixture.compiler_ran(), "{reply}");
        assert_eq!(output.status.code(), Some(0), "{reply}");
        assert_eq!(output.stderr, b"compiled\n", "{reply}");
    }
}
