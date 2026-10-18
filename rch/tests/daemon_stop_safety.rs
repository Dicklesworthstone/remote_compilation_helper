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
    LostRenewal,
    MalformedRenewal,
    ReleaseRefused,
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
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .build()
                .unwrap();
            let _runtime = runtime.enter();
            let incarnation = "bcb2d77f-9a55-42b3-8170-1913c1b30667";
            let mut owner: Option<(u32, String, rch_common::process_identity::ProcessIdentity)> =
                None;
            while !stopping.load(Ordering::SeqCst) {
                let (mut stream, _) = match listener.accept() {
                    Ok(connection) => connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => panic!("scripted daemon accept: {error}"),
                };
                stream.set_nonblocking(true).unwrap();
                let asynchronous = tokio::net::UnixStream::from_std(stream).unwrap();
                let peer_pid = asynchronous.peer_cred().unwrap().pid().unwrap() as u32;
                stream = asynchronous.into_std().unwrap();
                stream.set_nonblocking(false).unwrap();
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
                let route = request.split('?').next().unwrap();
                let token = request.split_once('?').and_then(|(_, query)| {
                    query
                        .split('&')
                        .find_map(|part| part.strip_prefix("token="))
                });
                let mut status = "200 OK";
                let snapshot = |owner: &Option<(
                    u32,
                    String,
                    rch_common::process_identity::ProcessIdentity,
                )>,
                                committed: bool,
                                state: &str| {
                    let maintenance_owner = owner.as_ref().map(|(pid, token, identity)| {
                        json!({
                            "token":token,"pid":pid,"purpose":"test","generation":1,
                            "process_identity":identity,
                            "acquired_unix_ms":1,"deadline_unix_ms":u64::MAX,"remaining_ms":30_000,
                            "owner_presence":"live"
                        })
                    });
                    let active = if matches!(
                        reply,
                        Reply::LostRenewal | Reply::MalformedRenewal | Reply::ReleaseRefused
                    ) {
                        vec![41]
                    } else {
                        Vec::new()
                    };
                    json!({"success":true,"status":state,"message":null,"daemon_incarnation":incarnation,
                        "admission_closed":owner.is_some(),"maintenance_closed":owner.is_some(),
                        "ownership_failed":false,"ownership_error":null,"shutdown_committed":committed,
                        "maintenance_owner":maintenance_owner,"last_recovery":null,
                        "restart_permitted":owner.is_some() && active.is_empty(),"active_build_ids":active,"queued_build_ids":[],
                        "client_lease_ids":[],"client_lease_scan_error":null})
                };
                let body = if route == "POST /restart-admission" {
                    let identity = request
                        .split_once('?')
                        .and_then(|(_, query)| {
                            query
                                .split('&')
                                .find_map(|part| part.strip_prefix("owner_identity="))
                        })
                        .and_then(rch_common::process_identity::ProcessIdentity::from_record)
                        .expect("acquisition caller identity");
                    assert_eq!(
                        rch_common::process_identity::owner_presence(peer_pid, Some(&identity)),
                        rch_common::process_identity::OwnerPresence::Live
                    );
                    owner = Some((
                        peer_pid,
                        token.expect("acquisition token").to_owned(),
                        identity,
                    ));
                    if matches!(reply, Reply::LostAdmission) {
                        // The mutation happened but its reply was lost. Only
                        // this known fence may clean up the stranded owner.
                        continue;
                    }
                    snapshot(&owner, false, "acquired").to_string()
                } else if route == "GET /restart-admission" {
                    snapshot(
                        &owner,
                        false,
                        if owner.is_some() { "owned" } else { "open" },
                    )
                    .to_string()
                } else if route == "POST /restart-admission/release" {
                    assert_eq!(owner.as_ref().map(|(_, token, _)| token.as_str()), token);
                    assert_eq!(owner.as_ref().map(|(pid, _, _)| *pid), Some(peer_pid));
                    if matches!(reply, Reply::ReleaseRefused) {
                        let mut refused = snapshot(&owner, false, "release_refused");
                        refused["success"] = json!(false);
                        refused.to_string()
                    } else {
                        owner = None;
                        snapshot(&owner, false, "released").to_string()
                    }
                } else if route == "POST /restart-admission/renew" {
                    assert_eq!(owner.as_ref().map(|(_, token, _)| token.as_str()), token);
                    match reply {
                        Reply::LostRenewal => continue,
                        Reply::MalformedRenewal => "{}".to_owned(),
                        _ => snapshot(&owner, false, "renewed").to_string(),
                    }
                } else if route == "POST /shutdown" {
                    assert_eq!(owner.as_ref().map(|(_, token, _)| token.as_str()), token);
                    match reply {
                        Reply::LostShutdown => continue,
                        Reply::MalformedShutdown => "{}".into(),
                        Reply::UnknownShutdown => json!({"status":"queued"}).to_string(),
                        Reply::HttpErrorShutdown => {
                            status = "503 Unavailable";
                            snapshot(&owner, true, "shutting_down").to_string()
                        }
                        Reply::ContradictoryShutdown => {
                            let mut state = snapshot(&owner, true, "shutting_down");
                            state["active_build_ids"] = json!([41]);
                            state.to_string()
                        }
                        _ => snapshot(&owner, true, "shutting_down").to_string(),
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
                if route == "POST /shutdown" && matches!(reply, Reply::Retires) {
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

fn routes(daemon: &Daemon) -> Vec<String> {
    daemon
        .requests
        .lock()
        .unwrap()
        .iter()
        .map(|request| request.split('?').next().unwrap().to_owned())
        .collect()
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
            "#!/bin/sh\nprintf '%s\\n' 'LoadState=not-found'\nexit 1\n"
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
            routes(&daemon),
            [
                "GET /restart-admission",
                "POST /restart-admission",
                "POST /restart-admission/release",
                "GET /restart-admission"
            ]
        );
    }
}

#[test]
fn restart_lost_admission_reply_releases_the_barrier_and_never_launches() {
    // The daemon may have closed its admission barrier before the reply was
    // lost. An abandoned restart must ask it to reopen, or every later worker
    // selection is refused until someone releases it by hand.
    let directory = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(directory.path(), Reply::LostAdmission);
    let meta = std::fs::symlink_metadata(&daemon.socket).unwrap();
    let output = run_cli(directory.path(), &daemon.socket, "restart", true, &[]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let metadata = std::fs::symlink_metadata(&daemon.socket).expect("endpoint retained");
    assert_eq!((metadata.dev(), metadata.ino()), (meta.dev(), meta.ino()));
    assert!(
        !directory.path().join("unsafe-commands.log").exists(),
        "kill or daemon start was attempted"
    );
    let response: Value = serde_json::from_slice(&output.stdout).expect("one JSON error response");
    assert_eq!(response["success"], false, "{response}");
    assert_eq!(
        routes(&daemon),
        [
            "GET /restart-admission",
            "POST /restart-admission",
            "POST /restart-admission/release",
            "GET /restart-admission"
        ]
    );
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
            routes(&daemon),
            [
                "GET /restart-admission",
                "POST /restart-admission",
                "POST /shutdown",
                "POST /restart-admission/release",
                "GET /restart-admission"
            ]
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
            .any(|r| r.starts_with("POST /shutdown?"))
    );
}

#[test]
fn acknowledged_endpoint_retirement_cannot_report_success_while_its_process_is_live() {
    let directory = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(directory.path(), Reply::Retires);
    let output = run_cli(directory.path(), &daemon.socket, "stop", true, &[]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["success"], false, "{response}");
    assert!(response.to_string().contains("unconfirmed"), "{response}");
    assert!(!daemon.socket.exists());
    assert!(!directory.path().join("unsafe-commands.log").exists());
}

#[test]
fn interrupted_drain_query_errors_release_only_their_fence_and_verify_open_state() {
    for reply in [Reply::LostRenewal, Reply::MalformedRenewal] {
        let directory = tempfile::tempdir().unwrap();
        let daemon = Daemon::start(directory.path(), reply);
        let meta = std::fs::symlink_metadata(&daemon.socket).unwrap();
        let output = run_cli(
            directory.path(),
            &daemon.socket,
            "restart",
            true,
            &["--drain", "--drain-timeout", "60"],
        );
        assert_refused(
            directory.path(),
            &daemon.socket,
            (meta.dev(), meta.ino()),
            &output,
            true,
        );
        assert_eq!(
            routes(&daemon),
            [
                "GET /restart-admission",
                "POST /restart-admission",
                "POST /restart-admission/renew",
                "POST /restart-admission/release",
                "GET /restart-admission"
            ]
        );
        let requests = daemon.requests.lock().unwrap();
        let token = |request: &str| {
            request
                .split_once("token=")
                .unwrap()
                .1
                .split('&')
                .next()
                .unwrap()
                .to_owned()
        };
        assert_eq!(
            token(&requests[1]),
            token(&requests[3]),
            "cleanup must fence the original operation"
        );
    }
}

#[test]
fn timeout_never_reports_reopened_when_release_or_readback_keeps_admission_closed() {
    let directory = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(directory.path(), Reply::ReleaseRefused);
    let output = run_cli(
        directory.path(),
        &daemon.socket,
        "stop",
        true,
        &["--drain", "--drain-timeout", "0"],
    );
    assert!(!output.status.success(), "{output:?}");
    let response: Value = serde_json::from_slice(&output.stdout).expect("one JSON failure");
    assert_eq!(response["success"], false);
    let rendered = response.to_string();
    assert!(
        rendered.contains("not confirmed") || rendered.contains("unconfirmed"),
        "{rendered}"
    );
    assert!(!rendered.contains("admission reopened"), "{rendered}");
    assert!(
        !routes(&daemon)
            .iter()
            .any(|route| route == "POST /shutdown")
    );
    assert_eq!(routes(&daemon).last().unwrap(), "GET /restart-admission");
    assert!(!directory.path().join("unsafe-commands.log").exists());
}
