//! Exercise the actual wrapper, admitted-execution protocol, and Linux process
//! groups. Compiler fixtures are bounded even when run against the old wrapper.
#![cfg(target_os = "linux")]

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

struct Owned(Child);
impl Drop for Owned {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn until(mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !predicate() {
        assert!(
            Instant::now() < deadline,
            "subprocess condition did not settle"
        );
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
        Err(error) => error.kind() == std::io::ErrorKind::NotFound,
    }
}

fn wait(child: &mut Owned) -> ExitStatus {
    let mut status = None;
    until(|| {
        status = child.0.try_wait().unwrap();
        status.is_some()
    });
    status.unwrap()
}

fn group_stopped(pids: &[u32]) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while pids.iter().any(|pid| !stopped(*pid)) {
        assert!(
            Instant::now() < deadline,
            "owned processes survived cancellation: {pids:?}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn no_success(completion: Option<Value>) {
    if let Some(completion) = completion {
        assert_ne!(
            completion["exit_code"], 0,
            "cancelled execution reported success"
        );
    }
}

struct Fixture {
    root: tempfile::TempDir,
    socket: PathBuf,
    compiler: PathBuf,
}

impl Fixture {
    fn new(body: &str) -> Self {
        let root = tempfile::tempdir().unwrap();
        let socket = root.path().join("edge.sock");
        let compiler = root.path().join("compiler with spaces");
        std::fs::write(
            &compiler,
            format!("#!/bin/sh\nprintf '%s\\n' \"$$\" > compiler.pid\n{body}\n"),
        )
        .unwrap();
        std::fs::set_permissions(&compiler, std::fs::Permissions::from_mode(0o755)).unwrap();
        Self {
            root,
            socket,
            compiler,
        }
    }

    fn daemon(&self) -> std::thread::JoinHandle<Option<Value>> {
        self.daemon_paused(None)
    }

    fn daemon_paused(
        &self,
        pause: Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>,
    ) -> std::thread::JoinHandle<Option<Value>> {
        let listener = UnixListener::bind(&self.socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        std::thread::spawn(move || {
            let mut connection = None;
            until(|| match listener.accept() {
                Ok((stream, _)) => {
                    connection = Some(stream);
                    true
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => false,
                Err(error) => panic!("accept: {error}"),
            });
            let mut writer = connection.unwrap();
            writer
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            writer
                .set_write_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut reader = BufReader::new(writer.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            writer
                .write_all(b"{\"kind\":\"hello-ok\",\"transport\":1,\"application\":1}\n")
                .unwrap();
            line.clear();
            reader.read_line(&mut line).unwrap();
            let request: Value = serde_json::from_str(&line).unwrap();
            assert_eq!(request["kind"], "rustc-request");
            if let Some((arrived, release)) = pause {
                arrived.send(()).unwrap();
                release.recv_timeout(Duration::from_secs(10)).unwrap();
            }
            let reply = json!({"kind":"rustc-decision", "decision":"execute",
                "action_key":"fixture", "attempt":"supervised-attempt",
                "capture_protocol":1, "compiler_skip_authorized":false,
                "env":[["PATH","/usr/bin:/bin"],["EXACT","admitted value"]]});
            writeln!(writer, "{reply}").unwrap();
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => None,
                Ok(_) => Some(serde_json::from_str(&line).unwrap()),
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => None,
                Err(error) => panic!("completion: {error}"),
            }
        })
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_rabs-wrap"));
        command
            .arg(&self.compiler)
            .args(["--crate-name", "demo", "lib.rs"])
            .current_dir(self.root.path())
            .env("RABS_SOCKET_PATH", &self.socket)
            .env("RABS_BREAKER_FILE", self.root.path().join("breaker"))
            .env("RABS_LIVE_DECISION_MS", "5000")
            .env("NOT_ADMITTED", "must disappear")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command
    }

    /// A real, separately killable Cargo-like parent. The wrapper receives its
    /// own PID, not an exec-replacement parent. Compiler paths remain arguments,
    /// never interpolated into the shell source, including paths with spaces.
    fn caller(&self) -> Command {
        let wrapped = self.command();
        let mut caller = Command::new("/bin/sh");
        caller
            .args([
                "-c",
                "\"$@\" & child=$!; printf '%s\\n' \"$child\" > wrapper.pid; wait \"$child\"",
                "test-cargo-parent",
            ])
            .arg(wrapped.get_program())
            .args(wrapped.get_args())
            .envs(
                wrapped
                    .get_envs()
                    .filter_map(|(key, value)| value.map(|value| (key, value))),
            )
            .current_dir(self.root.path())
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        caller
    }

    fn pid(&self, name: &str) -> u32 {
        let path = self.root.path().join(name);
        let mut pid = None;
        until(|| {
            pid = std::fs::read_to_string(&path)
                .ok()
                .and_then(|text| text.trim().parse().ok());
            pid.is_some()
        });
        pid.unwrap()
    }
}

#[test]
fn supervised_execution_preserves_stdin_environment_streams_and_exit_code() {
    let fixture = Fixture::new(
        "IFS= read -r line\nprintf '%s:%s:%s' \"$EXACT\" \"$line\" \"${NOT_ADMITTED-unset}\"\nprintf 'diagnostic\\n' >&2\nexit 7",
    );
    let daemon = fixture.daemon();
    let stdout_path = fixture.root.path().join("stdout");
    let stderr_path = fixture.root.path().join("stderr");
    let mut command = fixture.command();
    command
        .stdin(Stdio::piped())
        .stdout(std::fs::File::create(&stdout_path).unwrap())
        .stderr(std::fs::File::create(&stderr_path).unwrap());
    let mut child = Owned(command.spawn().unwrap());
    child
        .0
        .stdin
        .take()
        .unwrap()
        .write_all(b"input bytes\n")
        .unwrap();
    assert_eq!(wait(&mut child).code(), Some(7));
    assert_eq!(
        std::fs::read(stdout_path).unwrap(),
        b"admitted value:input bytes:unset"
    );
    assert_eq!(std::fs::read(stderr_path).unwrap(), b"diagnostic\n");
    let completion = daemon.join().unwrap().unwrap();
    assert_eq!(completion["attempt"], "supervised-attempt");
    assert_eq!(completion["exit_code"], 7);
    assert!(completion["signal"].is_null());
    assert_eq!(completion["stderr_hex"], "646961676e6f737469630a");
}

#[test]
fn compiler_signal_is_not_replaced_by_supervisor_cleanup_status() {
    let fixture = Fixture::new("kill -TERM \"$$\"");
    let daemon = fixture.daemon();
    let mut child = Owned(fixture.command().spawn().unwrap());
    assert_eq!(wait(&mut child).signal(), Some(15));
    let completion = daemon.join().unwrap().unwrap();
    assert!(completion["exit_code"].is_null());
    assert_eq!(completion["signal"], 15);
}

#[test]
fn wrapper_death_stops_compiler_and_descendant_without_touching_other_jobs() {
    // The 5s fixture bound avoids leaving runaway processes on the old code;
    // the assertion deadline below distinguishes cleanup from natural exit.
    let fixture = Fixture::new("/bin/sleep 5 &\nprintf '%s\\n' \"$!\" > descendant.pid\nwait");
    let daemon = fixture.daemon();
    let mut child = Owned(fixture.command().spawn().unwrap());
    let mut witness = Owned(Command::new("/bin/sleep").arg("30").spawn().unwrap());
    let compiler = fixture.pid("compiler.pid");
    let descendant = fixture.pid("descendant.pid");
    assert!(
        !stopped(compiler) && !stopped(descendant),
        "fixture exited before cancellation"
    );
    child.0.kill().unwrap();
    assert_eq!(wait(&mut child).signal(), Some(9));
    group_stopped(&[compiler, descendant]);
    assert!(
        witness.0.try_wait().unwrap().is_none(),
        "unrelated job was signalled"
    );
    assert!(
        daemon.join().unwrap().is_none(),
        "lost wrapper cannot report success"
    );
}

#[test]
fn normal_exit_cleans_background_descendants_before_completion() {
    let fixture = Fixture::new(
        "(/bin/sleep 3; printf 'late' > late-output) &\nprintf '%s\\n' \"$!\" > descendant.pid\nexit 0",
    );
    let daemon = fixture.daemon();
    let mut child = Owned(fixture.command().spawn().unwrap());
    let descendant = fixture.pid("descendant.pid");
    let deadline = Instant::now() + Duration::from_secs(2);
    let status = wait(&mut child);
    assert!(
        Instant::now() < deadline,
        "inherited output pipes kept completion alive"
    );
    assert_eq!(status.code(), Some(0));
    assert!(stopped(descendant));
    assert!(!fixture.root.path().join("late-output").exists());
    assert_eq!(daemon.join().unwrap().unwrap()["exit_code"], 0);
}

#[test]
fn forged_guard_owner_never_starts_a_compiler() {
    let fixture = Fixture::new("exit 0");
    let mut command = Command::new(env!("CARGO_BIN_EXE_rabs-wrap"));
    command
        .args([
            "--rabs-internal-compiler-guard-v1",
            "1",
            "1",
            "1",
            "1",
            "--",
        ])
        .arg(&fixture.compiler)
        .current_dir(fixture.root.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = Owned(command.spawn().unwrap());
    assert!(!wait(&mut child).success());
    assert!(!fixture.root.path().join("compiler.pid").exists());
}

#[test]
fn original_caller_death_cancels_a_still_living_wrapper_and_its_compiler() {
    let fixture = Fixture::new("/bin/sleep 5 &\nprintf '%s\\n' \"$!\" > descendant.pid\nwait");
    let daemon = fixture.daemon();
    let mut caller = Owned(fixture.caller().spawn().unwrap());
    let wrapper = fixture.pid("wrapper.pid");
    let compiler = fixture.pid("compiler.pid");
    let descendant = fixture.pid("descendant.pid");
    assert!(!stopped(wrapper) && !stopped(compiler) && !stopped(descendant));
    // Kill ONLY the original parent, not the wrapper, supervisor or compiler.
    caller.0.kill().unwrap();
    assert_eq!(wait(&mut caller).signal(), Some(9));
    group_stopped(&[wrapper, compiler, descendant]);
    no_success(daemon.join().unwrap());
}

#[test]
fn parent_lost_during_the_decision_cannot_start_an_orphaned_compiler() {
    let fixture = Fixture::new("printf 'must not run' > forbidden\nexit 0");
    let (arrived, ready) = mpsc::channel();
    let (release, released) = mpsc::channel();
    let daemon = fixture.daemon_paused(Some((arrived, released)));
    let mut caller = Owned(fixture.caller().spawn().unwrap());
    ready.recv_timeout(Duration::from_secs(10)).unwrap();
    let wrapper = fixture.pid("wrapper.pid");
    assert!(!stopped(wrapper));
    assert!(!fixture.root.path().join("compiler.pid").exists());
    // The identity was captured before this request reached the daemon. Let
    // the kernel reparent the surviving wrapper BEFORE replying with execute.
    caller.0.kill().unwrap();
    wait(&mut caller);
    release.send(()).unwrap();
    group_stopped(&[wrapper]);
    no_success(daemon.join().unwrap());
    assert!(!fixture.root.path().join("compiler.pid").exists());
    assert!(!fixture.root.path().join("forbidden").exists());
}

#[test]
fn cancelling_the_callers_process_group_does_not_kill_the_cleanup_guard() {
    let fixture = Fixture::new("/bin/sleep 5 &\nprintf '%s\\n' \"$!\" > descendant.pid\nwait");
    let daemon = fixture.daemon();
    let mut caller = Owned(fixture.caller().spawn().unwrap());
    let wrapper = fixture.pid("wrapper.pid");
    let compiler = fixture.pid("compiler.pid");
    let descendant = fixture.pid("descendant.pid");
    assert!(caller.0.try_wait().unwrap().is_none());
    // This PGID belongs to our unreaped test child, created with PGID=PID.
    // The harness itself is in another group and cannot receive this signal.
    let signalled = Command::new("/bin/kill")
        .args(["-TERM", "--", &format!("-{}", caller.0.id())])
        .status()
        .unwrap();
    assert!(signalled.success());
    assert_eq!(wait(&mut caller).signal(), Some(15));
    group_stopped(&[wrapper, compiler, descendant]);
    assert!(daemon.join().unwrap().is_none());
}
