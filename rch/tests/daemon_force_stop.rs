//! The production Linux force-stop implementation and compiled CLI, exercised
//! against real Unix sockets and child processes owned by this test only.
#![cfg(target_os = "linux")]

#[path = "../src/commands/daemon/force_stop.rs"]
mod force_stop;

use anyhow::{Context as _, Result, ensure};
use rch_common::process_identity::{
    ProcessIdentity, ProcessObservation, ProcessStart, current_process_identity, observe_process,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

#[derive(Serialize, Deserialize)]
struct Ready {
    pid: u32,
    identity: ProcessIdentity,
    incarnation: String,
}

struct Fixture {
    child: Child,
    socket: PathBuf,
    marker: PathBuf,
    requested: PathBuf,
    responded: PathBuf,
    release: PathBuf,
    ready: Ready,
}

impl Fixture {
    fn start(root: &Path, name: &str, mode: &str, committed: bool) -> Self {
        let ready_path = root.join(format!("{name}.ready"));
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "force_stop_fixture_child",
                "--ignored",
                "--nocapture",
            ])
            .env("RCH_FORCE_STOP_FIXTURE_ROOT", root)
            .env("RCH_FORCE_STOP_FIXTURE_NAME", name)
            .env("RCH_FORCE_STOP_FIXTURE_MODE", mode)
            .env("RCH_FORCE_STOP_FIXTURE_COMMITTED", committed.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !ready_path.exists() {
            if child.try_wait().unwrap().is_some() || Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("test-owned force-stop fixture failed to become ready");
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let ready: Ready = serde_json::from_slice(&fs::read(ready_path).unwrap()).unwrap();
        assert_eq!(ready.pid, child.id());
        assert!(ready.identity.is_valid());
        Self {
            child,
            socket: root.join(name),
            marker: root.join(format!("{name}.signals")),
            requested: root.join(format!("{name}.requested")),
            responded: root.join(format!("{name}.responded")),
            release: root.join(format!("{name}.release")),
            ready,
        }
    }

    async fn stop(&self) -> Result<()> {
        force_stop::stop_with_timing(
            &self.socket,
            self.ready.pid,
            &self.ready.identity,
            &self.ready.incarnation,
            Duration::from_millis(300),
            Duration::from_millis(350),
        )
        .await
    }

    fn assert_unsignalled(&mut self) {
        assert!(self.child.try_wait().unwrap().is_none());
        assert!(
            !self.marker.exists(),
            "unapproved TERM reached owned fixture"
        );
    }

    fn wait_exit(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success(), "fixture exited with {status}");
                return;
            }
            assert!(Instant::now() < deadline, "test-owned fixture did not exit");
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Only an unreaped Child created above is ever cleaned up. No PID
        // read from status, fixture files or process names grants authority.
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

fn root() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("rch-force-stop-")
        .disable_cleanup(true)
        .tempdir()
        .unwrap()
}

fn admission(incarnation: &str, owner: &Option<Value>, committed: bool) -> Value {
    json!({
        "success": true,
        "status": if committed { "shutting_down" } else if owner.is_some() { "owned" } else { "open" },
        "message": null,
        "daemon_incarnation": incarnation,
        "admission_closed": owner.is_some() || committed,
        "maintenance_closed": owner.is_some(),
        "ownership_failed": false,
        "ownership_error": null,
        "shutdown_committed": committed,
        "maintenance_owner": owner,
        "last_recovery": null,
        "restart_permitted": false,
        "active_build_ids": [41],
        "queued_build_ids": [],
        "client_lease_ids": [],
        "client_lease_scan_error": null
    })
}

async fn fixture_server() -> Result<()> {
    let root =
        PathBuf::from(std::env::var_os("RCH_FORCE_STOP_FIXTURE_ROOT").context("fixture root")?);
    let name = std::env::var("RCH_FORCE_STOP_FIXTURE_NAME")?;
    let mode = std::env::var("RCH_FORCE_STOP_FIXTURE_MODE")?;
    let mut committed = std::env::var("RCH_FORCE_STOP_FIXTURE_COMMITTED")? == "true";
    let socket = root.join(&name);
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let listener = tokio::net::UnixListener::bind(&socket)?;
    let ready = Ready {
        pid: std::process::id(),
        identity: current_process_identity().context("fixture birth identity")?,
        incarnation: uuid::Uuid::new_v4().to_string(),
    };
    let pending = root.join(format!("{name}.ready-pending"));
    fs::write(&pending, serde_json::to_vec(&ready)?)?;
    fs::rename(pending, root.join(format!("{name}.ready")))?;
    let mut owner = None;
    loop {
        let (mut peer, _) = tokio::select! {
            biased;
            _ = terminate.recv() => {
                fs::OpenOptions::new().create(true).append(true)
                    .open(root.join(format!("{name}.signals")))?.write_all(b"TERM\n")?;
                if mode == "ignore" {
                    continue;
                }
                if mode != "retain" {
                    fs::rename(&socket, root.join(format!("{name}.retired")))?;
                }
                if mode == "replace_after_term" {
                    fs::write(&socket, b"replacement evidence")?;
                }
                if mode == "retire_only" {
                    continue;
                }
                return Ok(());
            }
            accepted = listener.accept() => accepted?,
        };
        let peer_pid = peer.peer_cred()?.pid().context("fixture peer PID")? as u32;
        let mut request = String::new();
        (&mut peer)
            .take(16 * 1024)
            .read_to_string(&mut request)
            .await?;
        if request.is_empty() {
            continue;
        }
        let (method, target) = request.trim().split_once(' ').context("fixture request")?;
        let (route, query) = target.split_once('?').unwrap_or((target, ""));
        let query: std::collections::HashMap<_, _> = query
            .split('&')
            .filter_map(|part| part.split_once('='))
            .collect();
        if route.starts_with("/restart-admission") || route == "/shutdown" {
            if method == "POST" {
                ensure!(query.get("daemon_incarnation") == Some(&ready.incarnation.as_str()));
                let token = *query.get("token").context("fixture maintenance token")?;
                if route == "/restart-admission" {
                    let ProcessObservation::Present(identity) = observe_process(peer_pid) else {
                        anyhow::bail!("fixture maintenance peer has no birth identity");
                    };
                    ensure!(
                        query.get("owner_identity").copied() == identity.to_record().as_deref()
                    );
                    owner = Some(json!({
                        "token": token, "pid": peer_pid, "purpose": "stop",
                        "generation": 1, "acquired_unix_ms": 1,
                        "deadline_unix_ms": 9999999999999_u64, "remaining_ms": 30000,
                        "owner_presence": "live", "process_identity": identity
                    }));
                } else {
                    let current = owner.as_ref().context("fixture has no maintenance owner")?;
                    ensure!(current["token"] == token && current["pid"] == peer_pid);
                    if route == "/restart-admission/release" {
                        owner = None;
                    } else if route == "/shutdown" {
                        ensure!(query.get("force") == Some(&"true"));
                        committed = true;
                    }
                }
            }
            let reply = serde_json::to_vec(&admission(&ready.incarnation, &owner, committed))?;
            peer.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await?;
            peer.write_all(&reply).await?;
            continue;
        }
        ensure!(request == "GET /status\n", "unexpected fixture request");
        fs::write(root.join(format!("{name}.requested")), b"status\n")?;
        if mode == "hang" {
            tokio::time::sleep(Duration::from_secs(20)).await;
            continue;
        }
        if mode == "gated" {
            while !root.join(format!("{name}.release")).exists() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
        if mode == "lost" {
            continue;
        }
        let mut reply = json!({
            "daemon": {
                "pid": ready.pid, "socket_path": socket, "uptime_secs": 1,
                "version": "test", "started_at": "2026-01-01T00:00:00Z",
                "workers_total": 0, "workers_healthy": 0,
                "slots_total": 0, "slots_available": 0
            },
            "admission": admission(&ready.incarnation, &owner, committed),
            "workers": [], "active_builds": [], "recent_builds": [], "issues": [],
            "stats": { "total_builds": 0, "success_count": 0, "failure_count": 0,
                "remote_count": 0, "local_count": 0, "avg_duration_ms": 0 }
        });
        match mode.as_str() {
            "wrong_pid" => reply["daemon"]["pid"] = json!(ready.pid + 1),
            "zero_pid" => reply["daemon"]["pid"] = json!(0),
            "boolean_pid" => reply["daemon"]["pid"] = json!(true),
            "large_wrong_type" => {
                reply["daemon"]["pid"] =
                    json!(format!("private-status-sentinel{}", "x".repeat(768 * 1024)));
            }
            "wrong_path" => reply["daemon"]["socket_path"] = json!("/wrong/socket"),
            "missing_pid" => {
                reply["daemon"].as_object_mut().unwrap().remove("pid");
            }
            "wrong_incarnation" => {
                reply["admission"]["daemon_incarnation"] = json!(uuid::Uuid::new_v4().to_string())
            }
            "uncommitted" => reply["admission"]["shutdown_committed"] = json!(false),
            "open_admission" => reply["admission"]["admission_closed"] = json!(false),
            "unsuccessful" => reply["admission"]["success"] = json!(false),
            "nonboolean_fence" => reply["admission"]["shutdown_committed"] = json!(1),
            _ => {}
        }
        let encoded = serde_json::to_vec(&reply)?;
        let payload = match mode.as_str() {
            "malformed" => b"{".to_vec(),
            "duplicate" => format!(
                "{{\"daemon\":{{\"pid\":{},\"pid\":{}}}}}",
                ready.pid, ready.pid
            )
            .into_bytes(),
            "duplicate_unknown" => {
                let mut bytes = b"{\"unused\":{\"a\":1,\"a\":2},".to_vec();
                bytes.extend_from_slice(&encoded[1..]);
                bytes
            }
            "oversized" => vec![b' '; 1024 * 1024 + 1],
            "non_utf8" => vec![0xff],
            _ => encoded,
        };
        if mode == "replace_before_term" {
            fs::rename(&socket, root.join(format!("{name}.original")))?;
            fs::write(&socket, b"replacement evidence")?;
        }
        let status = if mode == "http_error" {
            "500 Nope"
        } else {
            "200 OK"
        };
        // A deliberately aborted observer may close its connection. That
        // must not terminate this process or fabricate a TERM observation.
        if peer
            .write_all(format!("HTTP/1.1 {status}\r\n\r\n").as_bytes())
            .await
            .is_ok()
        {
            let _ = peer.write_all(&payload).await;
        }
        fs::write(
            root.join(format!("{name}.responded")),
            b"response finished\n",
        )?;
    }
}

#[test]
#[ignore = "entrypoint for test-owned fixture subprocesses"]
fn force_stop_fixture_child() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(fixture_server())
        .unwrap();
}

#[tokio::test]
async fn real_term_requires_bound_process_exit_and_natural_socket_retirement() {
    for name in ["daemon.sock", "p q.sock", "x:y.sock"] {
        let root = root();
        let mut daemon = Fixture::start(root.path(), name, "normal", true);
        let mut peer = Fixture::start(root.path(), "other.sock", "normal", true);
        force_stop::stop(
            &daemon.socket,
            daemon.ready.pid,
            &daemon.ready.identity,
            &daemon.ready.incarnation,
        )
        .await
        .unwrap();
        daemon.wait_exit();
        assert!(!daemon.socket.exists());
        assert_eq!(fs::read(&daemon.marker).unwrap(), b"TERM\n");
        peer.assert_unsignalled();
        assert!(peer.socket.exists());
    }
}

#[tokio::test]
async fn malformed_unbound_and_uncommitted_status_never_sends_a_signal() {
    for mode in [
        "wrong_pid",
        "zero_pid",
        "boolean_pid",
        "large_wrong_type",
        "wrong_path",
        "missing_pid",
        "wrong_incarnation",
        "uncommitted",
        "open_admission",
        "unsuccessful",
        "nonboolean_fence",
        "malformed",
        "duplicate",
        "duplicate_unknown",
        "oversized",
        "non_utf8",
        "http_error",
        "lost",
        "hang",
    ] {
        let root = root();
        let mut daemon = Fixture::start(root.path(), "daemon.sock", mode, true);
        let before = fs::symlink_metadata(&daemon.socket).unwrap().ino();
        let result = if mode == "large_wrong_type" {
            force_stop::stop(
                &daemon.socket,
                daemon.ready.pid,
                &daemon.ready.identity,
                &daemon.ready.incarnation,
            )
            .await
        } else {
            daemon.stop().await
        };
        let error = result.expect_err(mode);
        if mode == "large_wrong_type" {
            assert_eq!(error.to_string(), "daemon status is malformed");
        }
        let diagnostic = format!("{error:#}");
        assert!(diagnostic.len() <= 1024, "unbounded diagnostic for {mode}");
        assert!(!diagnostic.contains("private-status-sentinel"));
        daemon.assert_unsignalled();
        assert_eq!(fs::symlink_metadata(&daemon.socket).unwrap().ino(), before);
    }
}

#[tokio::test]
async fn kernel_peer_and_birth_identity_cannot_be_replaced_by_reported_pids() {
    let root = root();
    let mut daemon = Fixture::start(root.path(), "daemon.sock", "normal", true);
    let mut other = Fixture::start(root.path(), "other.sock", "normal", true);
    assert!(
        force_stop::stop(
            &daemon.socket,
            other.ready.pid,
            &other.ready.identity,
            &other.ready.incarnation
        )
        .await
        .is_err()
    );
    let mut different_birth = daemon.ready.identity.clone();
    if let ProcessStart::Linux { ticks } = &mut different_birth.start {
        *ticks += 1;
    }
    let mut different_boot = daemon.ready.identity.clone();
    different_boot.boot_id = uuid::Uuid::new_v4().to_string();
    for identity in [different_birth, different_boot] {
        assert!(
            force_stop::stop(
                &daemon.socket,
                daemon.ready.pid,
                &identity,
                &daemon.ready.incarnation
            )
            .await
            .is_err()
        );
    }
    assert!(
        force_stop::stop(
            &daemon.socket,
            daemon.ready.pid,
            &daemon.ready.identity,
            &uuid::Uuid::new_v4().to_string()
        )
        .await
        .is_err()
    );
    daemon.assert_unsignalled();
    other.assert_unsignalled();
}

#[tokio::test]
async fn invalid_inputs_cannot_select_the_invoker_or_a_process_group() {
    let root = root();
    let mut daemon = Fixture::start(root.path(), "daemon.sock", "normal", true);
    let parent = rustix::process::getppid().unwrap().as_raw_nonzero().get() as u32;
    for pid in [0, 1, u32::MAX, std::process::id(), parent] {
        assert!(
            force_stop::stop(
                &daemon.socket,
                pid,
                &daemon.ready.identity,
                &daemon.ready.incarnation
            )
            .await
            .is_err()
        );
    }
    for path in [Path::new("relative"), Path::new("/invalid\n")] {
        assert!(
            force_stop::stop(
                path,
                daemon.ready.pid,
                &daemon.ready.identity,
                &daemon.ready.incarnation
            )
            .await
            .is_err()
        );
    }
    for (request, exit) in [
        (Duration::ZERO, Duration::from_secs(1)),
        (Duration::from_secs(6), Duration::from_secs(1)),
        (Duration::from_secs(1), Duration::ZERO),
        (Duration::from_secs(1), Duration::from_secs(11)),
    ] {
        assert!(
            force_stop::stop_with_timing(
                &daemon.socket,
                daemon.ready.pid,
                &daemon.ready.identity,
                &daemon.ready.incarnation,
                request,
                exit
            )
            .await
            .is_err()
        );
    }
    let mut invalid = daemon.ready.identity.clone();
    invalid.boot_id = "invalid".into();
    assert!(
        force_stop::stop(
            &daemon.socket,
            daemon.ready.pid,
            &invalid,
            &daemon.ready.incarnation
        )
        .await
        .is_err()
    );
    daemon.assert_unsignalled();
}

#[tokio::test]
async fn symlinked_and_replaced_socket_names_never_authorize_term() {
    let root = root();
    let mut daemon = Fixture::start(root.path(), "daemon.sock", "normal", true);
    let alias = root.path().join("alias.sock");
    symlink(&daemon.socket, &alias).unwrap();
    assert!(
        force_stop::stop(
            &alias,
            daemon.ready.pid,
            &daemon.ready.identity,
            &daemon.ready.incarnation
        )
        .await
        .is_err()
    );
    assert!(fs::symlink_metadata(&alias).unwrap().is_symlink());
    daemon.assert_unsignalled();
    let mut replaced = Fixture::start(root.path(), "replaced.sock", "replace_before_term", true);
    assert!(replaced.stop().await.is_err());
    assert_eq!(fs::read(&replaced.socket).unwrap(), b"replacement evidence");
    replaced.assert_unsignalled();
}

#[tokio::test]
async fn uncertain_term_never_escalates_or_removes_socket_evidence() {
    for mode in ["ignore", "retain", "retire_only", "replace_after_term"] {
        let root = root();
        let mut daemon = Fixture::start(root.path(), "daemon.sock", mode, true);
        let before = fs::symlink_metadata(&daemon.socket).unwrap().ino();
        assert!(daemon.stop().await.is_err(), "accepted {mode}");
        assert_eq!(fs::read(&daemon.marker).unwrap(), b"TERM\n");
        match mode {
            "ignore" => {
                assert!(daemon.child.try_wait().unwrap().is_none());
                assert_eq!(fs::symlink_metadata(&daemon.socket).unwrap().ino(), before);
            }
            "retain" => {
                daemon.wait_exit();
                assert_eq!(fs::symlink_metadata(&daemon.socket).unwrap().ino(), before);
            }
            "retire_only" => {
                assert!(daemon.child.try_wait().unwrap().is_none());
                assert!(!daemon.socket.exists());
            }
            "replace_after_term" => {
                daemon.wait_exit();
                assert_eq!(fs::read(&daemon.socket).unwrap(), b"replacement evidence");
            }
            _ => unreachable!(),
        }
    }
}

#[tokio::test]
async fn aborting_status_observation_leaves_no_detached_signal_authority() {
    let root = root();
    let mut daemon = Fixture::start(root.path(), "daemon.sock", "gated", true);
    let path = daemon.socket.clone();
    let pid = daemon.ready.pid;
    let identity = daemon.ready.identity.clone();
    let incarnation = daemon.ready.incarnation.clone();
    let pending =
        tokio::spawn(async move { force_stop::stop(&path, pid, &identity, &incarnation).await });
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while !daemon.requested.exists() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "status exchange never started"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    pending.abort();
    assert!(pending.await.unwrap_err().is_cancelled());
    fs::write(&daemon.release, b"release\n").unwrap();
    while !daemon.responded.exists() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "fixture did not finish its released response"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    daemon.assert_unsignalled();
    assert!(daemon.socket.exists());
}

#[test]
fn linux_force_stop_binds_the_real_cli_to_its_socket_peer_without_helpers() {
    for mode in [
        "normal",
        "zero_pid",
        "wrong_pid",
        "wrong_path",
        "large_wrong_type",
    ] {
        let root = root();
        let mut daemon = Fixture::start(root.path(), "daemon.sock", mode, false);
        let mut peer = Fixture::start(root.path(), "peer.sock", "normal", true);
        let config = root.path().join("config");
        fs::create_dir(&config).unwrap();
        fs::write(config.join("workers.toml"), b"").unwrap();
        let bin = root.path().join("bin");
        fs::create_dir(&bin).unwrap();
        let guard = root.path().join("unexpected-command");
        for name in ["kill", "pkill", "nohup", "rchd"] {
            let executable = bin.join(name);
            fs::write(
                &executable,
                "#!/bin/sh\nprintf attempted >> \"$RCH_FORCE_TEST_GUARD\"\nexit 99\n",
            )
            .unwrap();
            fs::set_permissions(executable, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let systemctl = bin.join("systemctl");
        fs::write(&systemctl,
            "#!/bin/sh\ncase \" $* \" in\n*\" show rchd \"*) echo LoadState=not-found; exit 0;;\n*\" is-enabled rchd \"*) echo not-found; exit 1;;\nesac\nprintf attempted >> \"$RCH_FORCE_TEST_GUARD\"\nexit 99\n"
        ).unwrap();
        fs::set_permissions(systemctl, fs::Permissions::from_mode(0o700)).unwrap();
        let mut cli = Command::new(env!("CARGO_BIN_EXE_rch"))
            .args(["--json", "daemon", "stop", "--force", "--yes"])
            .env_clear()
            .env("PATH", &bin)
            .env("HOME", root.path())
            .env("RCH_CONFIG_DIR", &config)
            .env("RCH_SOCKET_PATH", &daemon.socket)
            .env("RCH_FORCE_TEST_GUARD", &guard)
            .env("XDG_CONFIG_HOME", root.path().join("xdg"))
            .env("XDG_DATA_HOME", root.path().join("data"))
            .env("XDG_STATE_HOME", root.path().join("state"))
            .env("XDG_RUNTIME_DIR", root.path().join("run"))
            .env("RCH_NO_UPDATE_CHECK", "1")
            .current_dir(root.path())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(25);
        while cli.try_wait().unwrap().is_none() {
            if Instant::now() >= deadline {
                let _ = cli.kill();
                let output = cli.wait_with_output().unwrap();
                panic!("force-stop CLI exceeded test budget: {output:?}");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let output = cli.wait_with_output().unwrap();
        assert!(
            output.stdout.len() + output.stderr.len() <= 4096,
            "unbounded CLI diagnostic for {mode}"
        );
        assert!(!String::from_utf8_lossy(&output.stdout).contains("private-status-sentinel"));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("private-status-sentinel"));
        assert!(
            !guard.exists(),
            "CLI invoked an unauthorized helper: {output:?}"
        );
        peer.assert_unsignalled();
        let reply: Value = serde_json::from_slice(&output.stdout).unwrap();
        if mode == "normal" {
            assert!(output.status.success(), "{output:?}");
            assert_eq!(reply["success"], true);
            daemon.wait_exit();
            assert!(!daemon.socket.exists());
            assert_eq!(fs::read(&daemon.marker).unwrap(), b"TERM\n");
        } else {
            assert!(!output.status.success(), "{output:?}");
            assert_eq!(reply["success"], false);
            daemon.assert_unsignalled();
            assert!(daemon.socket.exists());
        }
    }
}
