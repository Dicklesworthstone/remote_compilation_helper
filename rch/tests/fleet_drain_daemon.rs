//! `rch fleet drain` against a scripted daemon (bd-bddpd).
//!
//! The command used to print success without draining anything. These tests
//! run the real `rch` binary in an isolated environment whose daemon socket is
//! served by this test, and assert what the daemon was actually asked to do
//! and what the command reports: a drained worker, a worker still busy at the
//! timeout, and a refused drain that must exit 1.

#![cfg(unix)]

use serde_json::Value;
use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};

/// Answers drain requests (refusing `refused`) and reports `used_slots` for
/// every worker on GET /status. Returns the request lines it received.
fn serve_daemon(socket: &Path, used_slots: u32, refused: &'static str) -> Arc<Mutex<Vec<String>>> {
    let listener = UnixListener::bind(socket).expect("bind scripted daemon socket");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&requests);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let mut request = String::new();
            // The client half-closes after its request line.
            let _ = stream.read_to_string(&mut request);
            let line = request.lines().next().unwrap_or_default().to_owned();
            seen.lock().unwrap().push(line.clone());
            let body = if line.starts_with("GET /status") {
                status_body(used_slots)
            } else if line.contains(&format!("/workers/{refused}/drain")) {
                r#"{"status":"error","message":"unknown worker"}"#.to_owned()
            } else if line.starts_with("POST /workers/") && line.ends_with("/drain") {
                r#"{"status":"ok"}"#.to_owned()
            } else {
                r#"{"status":"error","message":"unexpected request"}"#.to_owned()
            };
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{body}"
            );
        }
    });
    requests
}

fn status_body(used_slots: u32) -> String {
    let worker = |id: &str| {
        serde_json::json!({
            "id": id, "host": "127.0.0.1", "user": "u", "status": "draining",
            "circuit_state": "closed", "used_slots": used_slots, "total_slots": 4,
            "speed_score": 1.0, "last_error": null
        })
    };
    serde_json::json!({
        "daemon": {
            "pid": 1, "uptime_secs": 1, "version": "test", "socket_path": "/dev/null",
            "started_at": "2026-01-01T00:00:00Z", "workers_total": 2, "workers_healthy": 2,
            "slots_total": 8, "slots_available": 8
        },
        "workers": [worker("w1"), worker("w2")],
        "active_builds": [],
        "recent_builds": [],
        "issues": [],
        "stats": {
            "total_builds": 0, "success_count": 0, "failure_count": 0,
            "remote_count": 0, "local_count": 0, "avg_duration_ms": 0
        }
    })
    .to_string()
}

const TWO_WORKERS: &str = "[[workers]]\nid = \"w1\"\nhost = \"127.0.0.1\"\nuser = \"u\"\nidentity_file = \"~/.ssh/none\"\ntotal_slots = 4\n\n\
     [[workers]]\nid = \"w2\"\nhost = \"127.0.0.2\"\nuser = \"u\"\nidentity_file = \"~/.ssh/none\"\ntotal_slots = 4\n";

/// Runs `rch --json fleet drain <args>` with config, state and socket confined
/// to `dir`. Returns the exit code and the parsed JSON response.
fn fleet_drain(dir: &Path, socket: &Path, args: &[&str]) -> (Option<i32>, Value) {
    fleet_drain_with(dir, socket, TWO_WORKERS, args)
}

fn fleet_drain_with(
    dir: &Path,
    socket: &Path,
    workers_toml: &str,
    args: &[&str],
) -> (Option<i32>, Value) {
    let config = dir.join("config");
    std::fs::create_dir_all(&config).unwrap();
    std::fs::write(config.join("workers.toml"), workers_toml).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(["--json", "fleet", "drain"])
        .args(args)
        .current_dir(dir)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", dir)
        .env("XDG_CONFIG_HOME", dir.join("xdg"))
        .env("XDG_DATA_HOME", dir.join("data"))
        .env("XDG_STATE_HOME", dir.join("state"))
        // The fleet operation lock lives here; without it every test shares
        // ${TMPDIR:-/tmp}/rch-<user>/fleet_op.lock and they refuse each other.
        .env("XDG_RUNTIME_DIR", dir.join("run"))
        .env("RCH_CONFIG_DIR", &config)
        .env("RCH_SOCKET_PATH", socket)
        .output()
        .expect("run rch fleet drain");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json = serde_json::from_str(stdout.trim()).unwrap_or_else(|error| {
        panic!(
            "fleet drain printed no JSON ({error}): stdout={stdout} stderr={}",
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (output.status.code(), json)
}

#[test]
fn drain_asks_the_daemon_and_confirms_the_worker_idle() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("rchd.sock");
    let requests = serve_daemon(&socket, 0, "none");

    let (code, json) = fleet_drain(dir.path(), &socket, &["w1", "--yes", "--timeout", "5"]);

    assert_eq!(code, Some(0), "{json}");
    assert_eq!(json["success"], true, "{json}");
    assert_eq!(json["data"]["workers_drained"], serde_json::json!(["w1"]));
    assert_eq!(json["data"]["idle_confirmed"], true, "{json}");
    let requests = requests.lock().unwrap();
    assert!(
        requests.iter().any(|line| line == "POST /workers/w1/drain"),
        "the daemon was never asked to drain w1: {requests:?}"
    );
    assert!(
        !requests.iter().any(|line| line.contains("/workers/w2/")),
        "an untargeted worker was touched: {requests:?}"
    );
}

#[test]
fn drain_reports_a_worker_still_busy_at_the_timeout() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("rchd.sock");
    let _requests = serve_daemon(&socket, 2, "none");

    let (code, json) = fleet_drain(dir.path(), &socket, &["w1", "--yes", "--timeout", "0"]);

    assert_eq!(code, Some(0), "{json}");
    assert_eq!(json["data"]["idle_confirmed"], false, "{json}");
    assert_eq!(
        json["data"]["still_busy"],
        serde_json::json!([{"worker_id": "w1", "used_slots": 2}]),
        "{json}"
    );
}

#[test]
fn a_refused_drain_fails_the_command() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("rchd.sock");
    let _requests = serve_daemon(&socket, 0, "w2");

    let (code, json) = fleet_drain(dir.path(), &socket, &["--all", "--yes", "--timeout", "5"]);

    assert_eq!(code, Some(1), "a refused drain must not exit 0: {json}");
    assert_eq!(json["success"], false, "{json}");
    let rendered = json.to_string();
    assert!(
        rendered.contains("w2"),
        "the refused worker is not named: {json}"
    );
}

#[test]
fn drain_all_with_no_workers_configured_succeeds_without_touching_the_daemon() {
    // Formerly an in-process unit test, which read the host's real
    // workers.toml and drained a live fleet; here the config is confined.
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("rchd.sock");
    let requests = serve_daemon(&socket, 0, "none");

    let (code, json) = fleet_drain_with(dir.path(), &socket, "", &["--all", "--yes"]);

    assert_eq!(code, Some(0), "{json}");
    assert_eq!(json["success"], true, "{json}");
    let requests = requests.lock().unwrap();
    assert!(
        !requests.iter().any(|line| line.contains("/drain")),
        "no worker is configured, yet a drain was sent: {requests:?}"
    );
}
