//! Exercise the real CLI against an owned daemon socket. A lost lifecycle
//! acknowledgement must never turn into a process-name kill, socket unlink,
//! successful exit, or restart of an unconfirmed daemon.

#![cfg(unix)]

use serde_json::{Value, json};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone, Copy)]
enum Reply {
    LostAdmission,
    LostShutdown,
    MalformedShutdown,
    UnknownShutdown,
    HttpErrorShutdown,
    ContradictoryShutdown,
    NeverRetires,
    Retires,
}

struct Daemon {
    socket: PathBuf,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Daemon {
    fn start(root: &Path, reply: Reply) -> Self {
        let socket = root.join("daemon.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&requests);
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let endpoint = socket.clone();
        let thread = std::thread::spawn(move || {
            while !stopping.load(Ordering::SeqCst) {
                let (mut stream, _) = match listener.accept() {
                    Ok(connection) => connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => panic!("scripted daemon accept: {error}"),
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut request = String::new();
                (&mut stream)
                    .take(8192)
                    .read_to_string(&mut request)
                    .unwrap();
                let request = request.trim().to_owned();
                seen.lock().unwrap().push(request.clone());
                if matches!(reply, Reply::LostAdmission) {
                    // A completed connection with no reply is not evidence
                    // that no builds exist; do not authorize a name-wide kill.
                    continue;
                }
                let mut status = "200 OK";
                let body = if request.ends_with("/restart-admission") {
                    let closed = request.starts_with("POST ");
                    json!({"admission_closed": closed, "restart_permitted": closed,
                           "active_build_ids": [], "queued_build_ids": [],
                           "client_lease_ids": [], "client_lease_scan_error": null})
                    .to_string()
                } else if request == "POST /shutdown" {
                    match reply {
                        Reply::LostShutdown => continue,
                        Reply::MalformedShutdown => "{}".into(),
                        Reply::UnknownShutdown => json!({"status":"queued"}).to_string(),
                        Reply::HttpErrorShutdown => {
                            status = "503 Unavailable";
                            json!({"status":"shutting_down"}).to_string()
                        }
                        Reply::ContradictoryShutdown => {
                            json!({"status":"shutting_down", "active_build_ids":[41]}).to_string()
                        }
                        _ => json!({"status":"shutting_down"}).to_string(),
                    }
                } else {
                    panic!("unexpected lifecycle request: {request}");
                };
                write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n\r\n{body}"
                )
                .unwrap();
                drop(stream);
                if request == "POST /shutdown" && matches!(reply, Reply::Retires) {
                    // The owned server retires its own endpoint; preserve the
                    // inode under a new name instead of deleting test evidence.
                    std::fs::rename(&endpoint, endpoint.with_extension("retired")).unwrap();
                    break;
                }
            }
        });
        Self {
            socket,
            requests,
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.thread.take().unwrap().join().unwrap();
    }
}

fn run_cli(root: &Path, socket: &Path, action: &str, json_output: bool, flags: &[&str]) -> Output {
    let bin = root.join("bin");
    let config = root.join("config");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::create_dir_all(&config).unwrap();
    std::fs::write(config.join("workers.toml"), "").unwrap();
    // A hard link gives current_exe an owned sibling directory without copying
    // a potentially large debug binary. The copy is only a cross-device fallback.
    let cli = bin.join("rch");
    if std::fs::hard_link(env!("CARGO_BIN_EXE_rch"), &cli).is_err() {
        std::fs::copy(env!("CARGO_BIN_EXE_rch"), &cli).unwrap();
    }
    // Never let the old implementation kill a real process, even when running
    // these regressions against a broken revision. No host PATH is inherited.
    for tool in ["pkill", "kill", "rchd", "nohup", "systemctl"] {
        let script = if tool == "systemctl" {
            "#!/bin/sh\nexit 1\n"
        } else {
            "#!/bin/sh\nprintf '%s %s\\n' \"$0\" \"$*\" >> \"$RCH_SAFETY_COMMAND_LOG\"\nexit 0\n"
        };
        let path = bin.join(tool);
        std::fs::write(&path, script).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut command = Command::new(cli);
    if json_output {
        command.arg("--json");
    }
    command.args(["--no-self-healing", "daemon", action, "--yes"]);
    command
        .args(flags)
        .current_dir(root)
        .env_clear()
        .env("PATH", &bin)
        .env("HOME", root)
        .env("XDG_CONFIG_HOME", root.join("xdg"))
        .env("XDG_DATA_HOME", root.join("data"))
        .env("XDG_STATE_HOME", root.join("state"))
        .env("XDG_RUNTIME_DIR", root.join("run"))
        .env("RCH_CONFIG_DIR", config)
        .env("RCH_SOCKET_PATH", socket)
        .env("RCH_SAFETY_COMMAND_LOG", root.join("unsafe-commands.log"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            child.kill().unwrap(); // Only this test's own child, never a PID search.
            let output = child.wait_with_output().unwrap();
            panic!("lifecycle CLI exceeded test deadline: {output:?}");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    child.wait_with_output().unwrap()
}

fn assert_refused(root: &Path, socket: &Path, before: (u64, u64), output: &Output, machine: bool) {
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let metadata = std::fs::symlink_metadata(socket).expect("original endpoint must be retained");
    assert_eq!((metadata.dev(), metadata.ino()), before);
    assert!(
        !root.join("unsafe-commands.log").exists(),
        "kill or daemon start was attempted"
    );
    if machine {
        let response: Value =
            serde_json::from_slice(&output.stdout).expect("one JSON error response");
        assert_eq!(response["success"], false, "{response}");
        assert!(response.to_string().contains("unconfirmed"), "{response}");
    } else {
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("unconfirmed"),
            "{output:?}"
        );
    }
}

#[test]
fn stop_lost_admission_never_kills_or_unlinks_even_with_force() {
    for (machine, flags) in [(false, &[][..]), (true, &[][..]), (true, &["--force"][..])] {
        let directory = tempfile::tempdir().unwrap();
        let daemon = Daemon::start(directory.path(), Reply::LostAdmission);
        let meta = std::fs::symlink_metadata(&daemon.socket).unwrap();
        let output = run_cli(directory.path(), &daemon.socket, "stop", machine, flags);
        assert_refused(
            directory.path(),
            &daemon.socket,
            (meta.dev(), meta.ino()),
            &output,
            machine,
        );
        assert_eq!(
            *daemon.requests.lock().unwrap(),
            ["POST /restart-admission"]
        );
    }
}

#[test]
fn stop_unreachable_socket_is_retained_without_process_fallback() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("daemon.sock");
    drop(UnixListener::bind(&socket).unwrap());
    let meta = std::fs::symlink_metadata(&socket).unwrap();
    let output = run_cli(directory.path(), &socket, "stop", true, &[]);
    assert_refused(
        directory.path(),
        &socket,
        (meta.dev(), meta.ino()),
        &output,
        true,
    );
}

#[test]
fn stop_requires_a_real_shutdown_acknowledgement() {
    for reply in [
        Reply::LostShutdown,
        Reply::MalformedShutdown,
        Reply::UnknownShutdown,
        Reply::HttpErrorShutdown,
        Reply::ContradictoryShutdown,
    ] {
        let directory = tempfile::tempdir().unwrap();
        let daemon = Daemon::start(directory.path(), reply);
        let meta = std::fs::symlink_metadata(&daemon.socket).unwrap();
        let output = run_cli(directory.path(), &daemon.socket, "stop", true, &[]);
        assert_refused(
            directory.path(),
            &daemon.socket,
            (meta.dev(), meta.ino()),
            &output,
            true,
        );
        assert_eq!(
            *daemon.requests.lock().unwrap(),
            ["POST /restart-admission", "POST /shutdown"]
        );
    }
}

#[test]
fn acknowledged_stop_with_a_live_endpoint_exits_nonzero() {
    let directory = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(directory.path(), Reply::NeverRetires);
    let meta = std::fs::symlink_metadata(&daemon.socket).unwrap();
    let output = run_cli(directory.path(), &daemon.socket, "stop", true, &[]);
    assert_refused(
        directory.path(),
        &daemon.socket,
        (meta.dev(), meta.ino()),
        &output,
        true,
    );
}

#[test]
fn restart_does_not_launch_after_an_unconfirmed_stop() {
    let directory = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(directory.path(), Reply::LostShutdown);
    let meta = std::fs::symlink_metadata(&daemon.socket).unwrap();
    let output = run_cli(directory.path(), &daemon.socket, "restart", true, &[]);
    assert_refused(
        directory.path(),
        &daemon.socket,
        (meta.dev(), meta.ino()),
        &output,
        true,
    );
    assert!(
        daemon
            .requests
            .lock()
            .unwrap()
            .iter()
            .any(|r| r == "POST /shutdown")
    );
}

#[test]
fn acknowledged_endpoint_retirement_still_reports_success() {
    let directory = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(directory.path(), Reply::Retires);
    let output = run_cli(directory.path(), &daemon.socket, "stop", true, &[]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["success"], true, "{response}");
    assert_eq!(response["data"]["success"], true, "{response}");
    assert!(!daemon.socket.exists());
    assert!(!directory.path().join("unsafe-commands.log").exists());
}
