#![cfg(unix)]
//! E2E Tests for Daemon Lifecycle and API
//!
//! Tests the daemon's lifecycle management including:
//! - Startup with custom socket path
//! - Health and readiness endpoints
//! - Status endpoint
//! - Graceful shutdown via /shutdown endpoint
//!
//! These tests use the rch-common e2e test infrastructure.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rch_common::e2e::{
    fixtures::DaemonConfigFixture,
    harness::{HarnessResult, TestHarnessBuilder},
};

/// Get the absolute path to the project root directory
fn project_root() -> PathBuf {
    // The test runs from the crate directory, so we need to go up to workspace root
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir.parent().unwrap().to_path_buf()
}

/// Get the resolved Cargo target directory for this test run
fn cargo_target_dir() -> PathBuf {
    if let Ok(target_dir) = std::env::var("CARGO_TARGET_DIR") {
        let path = PathBuf::from(target_dir);
        if path.is_absolute() {
            return path;
        }
        return project_root().join(path);
    }
    let compiled = PathBuf::from(env!("CARGO_BIN_EXE_rchd"));
    for ancestor in compiled.ancestors() {
        if ancestor.file_name().and_then(|n| n.to_str()) == Some("debug")
            && let Some(target_dir) = ancestor.parent()
        {
            return target_dir.to_path_buf();
        }
    }
    project_root().join("target")
}

/// Get the path to the rchd binary
fn rchd_binary_path() -> PathBuf {
    let compiled = PathBuf::from(env!("CARGO_BIN_EXE_rchd"));
    if compiled.is_file() {
        return compiled;
    }
    cargo_target_dir().join("debug").join("rchd")
}

/// Send a request to the daemon via Unix socket and get the response body
fn send_request(socket_path: &Path, request: &str) -> std::io::Result<String> {
    let mut stream = UnixStream::connect(socket_path)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    // Send request
    writeln!(stream, "{}", request)?;
    stream.flush()?;

    // Read response
    let reader = BufReader::new(&stream);
    let mut response = String::new();
    let mut in_body = false;

    for line in reader.lines() {
        let line = line?;
        if in_body {
            response.push_str(&line);
            response.push('\n');
        } else if line.is_empty() {
            // Empty line marks end of headers
            in_body = true;
        }
    }

    Ok(response.trim().to_string())
}

fn admission_snapshot(socket_path: &Path) -> rch_common::RestartAdmissionResponse {
    serde_json::from_str(&send_request(socket_path, "GET /restart-admission").unwrap()).unwrap()
}

fn acquire_maintenance(socket_path: &Path) -> String {
    let owner_identity = rch_common::process_identity::current_process_identity()
        .and_then(|identity| identity.to_record())
        .expect("test process birth identity");
    let observed = admission_snapshot(socket_path);
    let token = uuid::Uuid::new_v4().to_string();
    let fence = format!(
        "daemon_incarnation={}&token={token}",
        observed.daemon_incarnation
    );
    let response: rch_common::RestartAdmissionResponse = serde_json::from_str(
        &send_request(
            socket_path,
            &format!(
                "POST /restart-admission?{fence}&purpose=test&owner_identity={owner_identity}"
            ),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(
        response.success && response.admission_closed,
        "{response:?}"
    );
    assert_eq!(response.maintenance_owner.unwrap().token, token);
    fence
}

// These tests use real Linux process identities, the actual rch/rchd binaries,
// and isolated sockets/state. No remote worker or shared service is contacted.
#[cfg(target_os = "linux")]
mod maintenance_integration {
    use super::*;
    use rch_common::job_identity::{DurableJobLease, JobIdentity};
    use rch_common::process_identity::{ProcessStart, current_process_identity};
    use serde_json::Value;
    use std::process::{Child, Command, Output, Stdio};
    use std::time::Instant;

    struct OwnedChild(Option<Child>);

    impl OwnedChild {
        fn id(&self) -> u32 {
            self.0.as_ref().unwrap().id()
        }

        fn signal(&self, signal: nix::sys::signal::Signal) {
            nix::sys::signal::kill(nix::unistd::Pid::from_raw(self.id() as i32), signal).unwrap();
        }

        fn finish(mut self) -> Output {
            let deadline = Instant::now() + Duration::from_secs(20);
            let child = self.0.as_mut().unwrap();
            while child.try_wait().unwrap().is_none() {
                assert!(
                    Instant::now() < deadline,
                    "test child exceeded lifecycle deadline"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            self.0.take().unwrap().wait_with_output().unwrap()
        }
    }

    impl Drop for OwnedChild {
        fn drop(&mut self) {
            if let Some(child) = self.0.as_mut() {
                if child.try_wait().ok().flatten().is_none() {
                    let _ = child.kill();
                }
                let _ = child.wait();
            }
        }
    }

    fn ensure_rch_cli() -> &'static Path {
        static RCH_CLI: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
        RCH_CLI
            .get_or_init(|| {
                let target_dir = cargo_target_dir();
                let cli = target_dir.join("debug").join("rch");
                if cli.is_file() {
                    return cli;
                }
                // Avoid deadlocking on `<target_dir>/debug/.cargo-lock` held by
                // the parent `cargo test` process when `daemon_lifecycle` is
                // invoked without a prior `cargo build --bin rch`.
                let helper_target = target_dir.join("rch-cli-target");
                let helper_cli = helper_target.join("debug").join("rch");
                if !helper_cli.is_file() {
                    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
                    let _ = Command::new(cargo)
                        .current_dir(project_root())
                        .env("CARGO_TARGET_DIR", &helper_target)
                        .env("CARGO_BUILD_BUILD_DIR", &helper_target)
                        .args(["build", "-p", "rch", "--bin", "rch", "--quiet"])
                        .status();
                }
                assert!(
                    helper_cli.is_file(),
                    "build the rch CLI before Linux lifecycle tests: {}",
                    cli.display()
                );
                helper_cli
            })
            .as_path()
    }

    struct Fixture {
        daemon: OwnedChild,
        root: tempfile::TempDir,
        socket: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let root = tempfile::Builder::new()
                .prefix("rch-admission-")
                .tempdir()
                .unwrap();
            let socket = root.path().join("rch.sock");
            std::fs::create_dir_all(root.path().join("config")).unwrap();
            std::fs::create_dir_all(root.path().join("state/job-leases")).unwrap();
            std::fs::write(root.path().join("config/workers.toml"), "workers = []\n").unwrap();
            let daemon = Self::spawn_daemon(root.path(), &socket);
            let mut fixture = Self {
                daemon,
                root,
                socket,
            };
            fixture.wait_ready();
            fixture
        }

        fn command(root: &Path, socket: &Path, binary: &Path) -> Command {
            let mut command = Command::new(binary);
            command
                .env_clear()
                .current_dir(root)
                .env("PATH", "/usr/bin:/bin")
                .env("HOME", root)
                .env("XDG_CONFIG_HOME", root.join("xdg-config"))
                .env("XDG_DATA_HOME", root.join("data"))
                .env("XDG_CACHE_HOME", root.join("cache"))
                .env("XDG_STATE_HOME", root.join("xdg-state"))
                .env("XDG_RUNTIME_DIR", root.join("run"))
                .env("RCH_CONFIG_DIR", root.join("config"))
                .env("RCH_STATE_HOME", root.join("state"))
                .env("RCH_SOCKET_PATH", socket)
                .env("NO_COLOR", "1")
                .stdin(Stdio::null());
            command
        }

        fn spawn_daemon(root: &Path, socket: &Path) -> OwnedChild {
            let log = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(root.join("daemon.log"))
                .unwrap();
            let child = Self::command(root, socket, Path::new(env!("CARGO_BIN_EXE_rchd")))
                .args(["--foreground", "--metrics-port", "0", "--no-hot-reload"])
                .arg("--socket")
                .arg(socket)
                .arg("--history-file")
                .arg(root.join("history.jsonl"))
                .arg("--workers-config")
                .arg(root.join("config/workers.toml"))
                .stdout(log.try_clone().unwrap())
                .stderr(log)
                .spawn()
                .unwrap();
            OwnedChild(Some(child))
        }

        fn wait_ready(&mut self) {
            let deadline = Instant::now() + Duration::from_secs(15);
            loop {
                if send_request(&self.socket, "GET /restart-admission")
                    .ok()
                    .is_some_and(|body| {
                        serde_json::from_str::<rch_common::RestartAdmissionResponse>(&body).is_ok()
                    })
                {
                    return;
                }
                assert!(
                    self.daemon
                        .0
                        .as_mut()
                        .unwrap()
                        .try_wait()
                        .unwrap()
                        .is_none()
                        && Instant::now() < deadline,
                    "daemon did not become ready: {}",
                    std::fs::read_to_string(self.root.path().join("daemon.log")).unwrap()
                );
                std::thread::sleep(Duration::from_millis(20));
            }
        }

        fn cli(&self, args: &[&str]) -> OwnedChild {
            let cli = ensure_rch_cli();
            let child = Self::command(self.root.path(), &self.socket, cli)
                .args(["--json", "--no-self-healing"])
                .args(args)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            OwnedChild(Some(child))
        }

        fn lease(&self, stale: bool) -> DurableJobLease {
            let now = chrono::Utc::now().timestamp_millis() as u64;
            let mut lease = DurableJobLease::new(
                JobIdentity::new_local(),
                std::process::id(),
                None,
                None,
                if stale { now - 16 * 60 * 1000 } else { now },
                false,
                true,
                "blake3:integration".into(),
            );
            lease.process_birth = Some(current_process_identity().expect("real Linux identity"));
            lease
        }

        fn write_lease(&self, lease: &DurableJobLease) -> PathBuf {
            let path = self
                .root
                .path()
                .join("state/job-leases")
                .join(format!("{}.json", lease.identity.local_wrapper_id));
            std::fs::write(&path, serde_json::to_vec(lease).unwrap()).unwrap();
            path
        }

        fn wait_owner(&self, pid: u32) -> rch_common::RestartAdmissionResponse {
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                let snapshot = admission_snapshot(&self.socket);
                if snapshot
                    .maintenance_owner
                    .as_ref()
                    .is_some_and(|owner| owner.pid == pid)
                {
                    return snapshot;
                }
                assert!(
                    Instant::now() < deadline,
                    "maintenance owner never acquired: {snapshot:?}"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
        }

        fn request(&self, request: &str) -> rch_common::RestartAdmissionResponse {
            serde_json::from_str(&send_request(&self.socket, request).unwrap()).unwrap()
        }
    }

    // This is a protocol operator fixture, not an invocation of the rch CLI.
    // It deliberately exits without releasing, requiring the real daemon to
    // recover from process death after successful acquisition and renewal.
    #[test]
    fn linux_protocol_operator_signals_recover_admission_and_fence_successors() {
        use nix::sys::signal::Signal;
        const OPERATOR: &str = r#"
import json, os, pathlib, signal, socket, sys, uuid
# A detached test run (nohup, `&`) inherits SIGINT ignored, and Python then
# never raises KeyboardInterrupt. Model an interactive operator explicitly.
signal.signal(signal.SIGINT, signal.default_int_handler)
signal.signal(signal.SIGTERM, signal.SIG_DFL)
endpoint, ready_name, lease = sys.argv[1:]
boot = pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
start = int(pathlib.Path('/proc/self/stat').read_text().rpartition(')')[2].split()[19])
identity = f'{boot}:{start}'
def request(line):
    with socket.socket(socket.AF_UNIX) as stream:
        stream.settimeout(5)
        stream.connect(endpoint)
        stream.sendall((line + '\n').encode())
        response = bytearray()
        while True:
            chunk = stream.recv(65536)
            if not chunk:
                break
            response.extend(chunk)
            assert len(response) < 1048576
    return json.loads(bytes(response).split(b'\r\n\r\n', 1)[1])
incarnation = request('GET /restart-admission')['daemon_incarnation']
token = str(uuid.uuid4())
fence = f'daemon_incarnation={incarnation}&token={token}'
acquired = request(f'POST /restart-admission?{fence}&purpose=protocol_operator&owner_identity={identity}')
assert acquired['success'] and acquired['admission_closed'], acquired
renewed = request(f'POST /restart-admission/renew?{fence}')
assert renewed['success'] and renewed['admission_closed'], renewed
assert not renewed['restart_permitted'] and lease in renewed['client_lease_ids'], renewed
assert renewed['maintenance_owner']['pid'] == os.getpid(), renewed
assert renewed['maintenance_owner']['token'] == token, renewed
ready = pathlib.Path(ready_name)
pending = ready.with_suffix('.pending')
pending.write_text(json.dumps(renewed))
pending.replace(ready)
signal.pthread_sigmask(signal.SIG_UNBLOCK, [signal.SIGINT, signal.SIGTERM])
signal.signal(signal.SIGINT, signal.default_int_handler)
signal.signal(signal.SIGTERM, signal.SIG_DFL)
while True:
    signal.pause()
"#;
        let fixture = Fixture::new();
        let lease = fixture.lease(false);
        fixture.write_lease(&lease);
        let own_identity = current_process_identity().unwrap().to_record().unwrap();
        let probe = || -> rch_common::SelectionReason {
            let response: rch_common::SelectionResponse = serde_json::from_str(
                &send_request(
                    &fixture.socket,
                    "GET /select-worker?project=unrelated&cores=1",
                )
                .unwrap(),
            )
            .unwrap();
            response.reason
        };
        for (index, signal) in [Signal::SIGINT, Signal::SIGTERM, Signal::SIGKILL]
            .into_iter()
            .enumerate()
        {
            let ready = fixture.root.path().join(format!("operator-{index}.json"));
            let log_path = fixture.root.path().join(format!("operator-{index}.log"));
            let log = std::fs::File::create(&log_path).unwrap();
            let operator = OwnedChild(Some(
                Fixture::command(fixture.root.path(), &fixture.socket, Path::new("python3"))
                    .args(["-c", OPERATOR])
                    .arg(&fixture.socket)
                    .arg(&ready)
                    .arg(&lease.identity.local_wrapper_id)
                    .stdout(log.try_clone().unwrap())
                    .stderr(log)
                    .spawn()
                    .unwrap(),
            ));
            let deadline = Instant::now() + Duration::from_secs(10);
            while !ready.is_file() {
                assert!(
                    Instant::now() < deadline,
                    "protocol operator never renewed: {}",
                    std::fs::read_to_string(&log_path).unwrap()
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            let owned: rch_common::RestartAdmissionResponse =
                serde_json::from_slice(&std::fs::read(&ready).unwrap()).unwrap();
            let owner = owned.maintenance_owner.as_ref().unwrap();
            assert!(owned.admission_closed && !owned.restart_permitted);
            assert_eq!(owner.pid, operator.id());
            assert_eq!(owner.owner_presence, "live");
            assert_eq!(
                rch_common::process_identity::observe_process(operator.id()),
                rch_common::process_identity::ProcessObservation::Present(
                    owner.process_identity.clone()
                )
            );
            assert_eq!(
                owned.client_lease_ids,
                vec![lease.identity.local_wrapper_id.clone()]
            );
            let fence = format!(
                "daemon_incarnation={}&token={}",
                owned.daemon_incarnation, owner.token
            );
            let competing = fixture.request(&format!(
                "POST /restart-admission?daemon_incarnation={}&token={}&purpose=concurrent&owner_identity={own_identity}",
                owned.daemon_incarnation, uuid::Uuid::new_v4()
            ));
            assert!(!competing.success && competing.admission_closed);
            assert_eq!(competing.maintenance_owner.unwrap().token, owner.token);
            for endpoint in ["/restart-admission/release", "/restart-admission/recover"] {
                let refused = fixture.request(&format!("POST {endpoint}?{fence}"));
                assert!(!refused.success && refused.admission_closed, "{refused:?}");
                assert_eq!(refused.maintenance_owner.unwrap().token, owner.token);
            }
            let blocked = rch_common::SelectionReason::SelectionError(
                "restart_admission_barrier_active".into(),
            );
            assert_eq!(probe(), blocked);

            operator.signal(signal);
            assert!(!operator.finish().status.success());
            let deadline = Instant::now() + Duration::from_secs(10);
            let recovered = loop {
                let state = admission_snapshot(&fixture.socket);
                if !state.admission_closed {
                    break state;
                }
                assert!(
                    Instant::now() < deadline,
                    "dead protocol owner blocked admission: {state:?}"
                );
                std::thread::sleep(Duration::from_millis(10));
            };
            assert!(recovered.maintenance_owner.is_none());
            let recovery = recovered.last_recovery.unwrap();
            assert_eq!(recovery.token, owner.token);
            assert_eq!(recovery.reason, "owner_absent");
            assert_eq!(probe(), rch_common::SelectionReason::NoWorkersConfigured);
            let successor = acquire_maintenance(&fixture.socket);
            let successor_token = admission_snapshot(&fixture.socket)
                .maintenance_owner
                .unwrap()
                .token;
            for endpoint in [
                "/restart-admission/release",
                "/restart-admission/renew",
                "/shutdown",
            ] {
                let stale = fixture.request(&format!("POST {endpoint}?{fence}"));
                assert!(
                    !stale.success && stale.admission_closed && !stale.shutdown_committed,
                    "{stale:?}"
                );
                assert_eq!(stale.maintenance_owner.unwrap().token, successor_token);
            }
            assert_eq!(probe(), blocked);
            let released = fixture.request(&format!("POST /restart-admission/release?{successor}"));
            assert!(
                released.success && !released.admission_closed,
                "{released:?}"
            );
            assert!(
                admission_snapshot(&fixture.socket)
                    .maintenance_owner
                    .is_none()
            );
            assert_eq!(probe(), rch_common::SelectionReason::NoWorkersConfigured);
        }
    }

    #[test]
    fn linux_interrupted_drains_reopen_without_releasing_concurrent_maintenance() {
        use nix::sys::signal::Signal;
        let _ = ensure_rch_cli();
        let fixture = Fixture::new();
        fixture.write_lease(&fixture.lease(false));
        for signal in [Signal::SIGINT, Signal::SIGTERM, Signal::SIGKILL] {
            let draining = fixture.cli(&[
                "daemon",
                "restart",
                "--drain",
                "--drain-timeout",
                "60",
                "--yes",
            ]);
            let owned = fixture.wait_owner(draining.id());
            let owner = owned.maintenance_owner.as_ref().unwrap();
            assert!(owned.admission_closed);
            assert_eq!(owner.owner_presence, "live");

            let inspection = fixture.cli(&["daemon", "admission", "status"]).finish();
            assert!(inspection.status.success(), "{inspection:?}");
            let inspection: Value = serde_json::from_slice(&inspection.stdout).unwrap();
            assert_eq!(inspection["data"]["admission_closed"], true);
            assert_eq!(
                inspection["data"]["maintenance_owner"]["pid"],
                draining.id()
            );
            assert_eq!(
                inspection["data"]["maintenance_owner"]["token"],
                owner.token
            );
            assert_eq!(
                inspection["data"]["daemon_incarnation"],
                owned.daemon_incarnation
            );

            let status = fixture.cli(&["status"]).finish();
            assert!(status.status.success(), "{status:?}");
            let status: Value = serde_json::from_slice(&status.stdout).unwrap();
            assert_eq!(status["data"]["posture"], "admission_closed");
            assert_eq!(
                status["data"]["daemon"]["admission"]["maintenance_owner"]["token"],
                owner.token
            );

            let recovery = fixture.cli(&["daemon", "admission", "recover"]).finish();
            assert!(
                !recovery.status.success(),
                "live owner was stolen: {recovery:?}"
            );
            let recovery: Value = serde_json::from_slice(&recovery.stdout).unwrap();
            assert_eq!(recovery["success"], false);
            assert_eq!(
                admission_snapshot(&fixture.socket)
                    .maintenance_owner
                    .unwrap()
                    .token,
                owner.token
            );

            let concurrent = fixture
                .cli(&["daemon", "stop", "--drain", "--yes"])
                .finish();
            assert!(!concurrent.status.success(), "{concurrent:?}");
            let untouched = admission_snapshot(&fixture.socket);
            assert_eq!(
                untouched.maintenance_owner.as_ref().unwrap().token,
                owner.token
            );
            assert!(untouched.admission_closed);
            let fence = format!(
                "daemon_incarnation={}&token={}",
                owned.daemon_incarnation, owner.token
            );
            let wrong_peer = fixture.request(&format!("POST /restart-admission/release?{fence}"));
            assert!(
                !wrong_peer.success && wrong_peer.admission_closed,
                "{wrong_peer:?}"
            );

            draining.signal(signal);
            let output = draining.finish();
            assert!(
                !output.status.success(),
                "interrupted drain reported success: {output:?}"
            );
            let recovered = admission_snapshot(&fixture.socket);
            assert!(!recovered.admission_closed, "{recovered:?}");
            assert!(recovered.maintenance_owner.is_none(), "{recovered:?}");
            let verified = fixture.cli(&["daemon", "admission", "recover"]).finish();
            assert!(verified.status.success(), "{verified:?}");
            let verified: Value = serde_json::from_slice(&verified.stdout).unwrap();
            assert_eq!(verified["success"], true);
            assert_eq!(verified["data"]["admission_closed"], false);
            assert!(verified["data"]["maintenance_owner"].is_null());
            if signal != Signal::SIGKILL {
                let reply: Value =
                    serde_json::from_slice(&output.stdout).expect("one cancellation JSON response");
                assert_eq!(reply["success"], false, "{reply}");
            } else {
                assert_eq!(
                    recovered.last_recovery.as_ref().unwrap().reason,
                    "owner_absent"
                );
            }

            let next_fence = acquire_maintenance(&fixture.socket);
            let stale = fixture.request(&format!("POST /restart-admission/release?{fence}"));
            assert!(!stale.success && stale.admission_closed, "{stale:?}");
            let released =
                fixture.request(&format!("POST /restart-admission/release?{next_fence}"));
            assert!(
                released.success && !released.admission_closed,
                "{released:?}"
            );
            assert!(!admission_snapshot(&fixture.socket).admission_closed);
        }
    }

    #[test]
    fn linux_daemon_crash_starts_open_and_old_incarnation_cannot_release_or_shutdown() {
        let mut fixture = Fixture::new();
        let old_fence = acquire_maintenance(&fixture.socket);
        let old_incarnation = admission_snapshot(&fixture.socket).daemon_incarnation;
        fixture.daemon.0.as_mut().unwrap().kill().unwrap();
        fixture.daemon.0.as_mut().unwrap().wait().unwrap();
        fixture.daemon = Fixture::spawn_daemon(fixture.root.path(), &fixture.socket);
        fixture.wait_ready();
        let restarted = admission_snapshot(&fixture.socket);
        assert!(!restarted.admission_closed, "{restarted:?}");
        assert_ne!(restarted.daemon_incarnation, old_incarnation);
        let new_fence = acquire_maintenance(&fixture.socket);
        for endpoint in [
            "/restart-admission/release",
            "/restart-admission/renew",
            "/shutdown",
        ] {
            let stale = fixture.request(&format!("POST {endpoint}?{old_fence}"));
            assert!(!stale.success && stale.admission_closed, "{stale:?}");
            assert!(!stale.shutdown_committed);
        }
        let released = fixture.request(&format!("POST /restart-admission/release?{new_fence}"));
        assert!(released.success && !released.admission_closed);
    }

    #[test]
    fn linux_restart_scan_distinguishes_live_recycled_old_boot_and_uncertain_owners() {
        let fixture = Fixture::new();
        let live = fixture.lease(true);
        fixture.write_lease(&live);
        let mut recycled = fixture.lease(true);
        let ProcessStart::Linux { ticks } = &mut recycled.process_birth.as_mut().unwrap().start
        else {
            panic!("Linux birth marker required");
        };
        *ticks += 1;
        fixture.write_lease(&recycled);
        let mut rebooted = fixture.lease(true);
        rebooted.wrapper_pid = 1;
        rebooted.process_birth.as_mut().unwrap().boot_id =
            "00000000-0000-0000-0000-000000000001".into();
        fixture.write_lease(&rebooted);
        let mut unknown = fixture.lease(true);
        unknown.process_birth = None;
        fixture.write_lease(&unknown);
        let mut expected = vec![
            live.identity.local_wrapper_id,
            unknown.identity.local_wrapper_id,
        ];
        expected.sort();
        assert_eq!(
            admission_snapshot(&fixture.socket).client_lease_ids,
            expected
        );
    }

    #[test]
    fn linux_waiting_wrapper_does_not_deadlock_drain_or_lose_its_live_lease() {
        let mut fixture = Fixture::new();
        let mut waiting = fixture.lease(true);
        waiting.phase = "restart_admission_wait".into();
        waiting.heartbeat_unix_ms -= 2 * 60 * 60 * 1000;
        let path = fixture.write_lease(&waiting);
        let fence = acquire_maintenance(&fixture.socket);
        let admitted = admission_snapshot(&fixture.socket);
        assert!(admitted.client_lease_ids.is_empty(), "{admitted:?}");
        assert!(path.exists(), "a live waiting lease must not be reaped");
        let shutdown = fixture.request(&format!("POST /shutdown?{fence}"));
        assert!(
            shutdown.success && shutdown.shutdown_committed,
            "{shutdown:?}"
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        let status = loop {
            if let Some(status) = fixture.daemon.0.as_mut().unwrap().try_wait().unwrap() {
                break status;
            }
            assert!(Instant::now() < deadline, "committed shutdown did not exit");
            std::thread::sleep(Duration::from_millis(10));
        };
        assert!(status.success(), "graceful daemon exit failed: {status}");
        assert!(
            !fixture.socket.exists(),
            "retired daemon retained its endpoint"
        );
        assert!(
            path.exists(),
            "shutdown lost the live waiting wrapper's journal"
        );
    }

    #[test]
    fn linux_unrenewed_live_maintenance_expires_and_cannot_reopen_its_successor() {
        let fixture = Fixture::new();
        let old_fence = acquire_maintenance(&fixture.socket);
        let deadline = Instant::now() + Duration::from_secs(35);
        loop {
            let state = admission_snapshot(&fixture.socket);
            if !state.admission_closed {
                assert_eq!(
                    state.last_recovery.as_ref().unwrap().reason,
                    "deadline_expired"
                );
                break;
            }
            assert!(
                Instant::now() < deadline,
                "live abandoned maintenance never expired: {state:?}"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        let current = acquire_maintenance(&fixture.socket);
        for endpoint in [
            "/restart-admission/renew",
            "/restart-admission/release",
            "/shutdown",
        ] {
            let stale = fixture.request(&format!("POST {endpoint}?{old_fence}"));
            assert!(!stale.success && stale.admission_closed, "{stale:?}");
        }
        assert!(
            fixture
                .request(&format!("POST /restart-admission/release?{current}"))
                .success
        );
    }
}

/// Parse JSON response and extract a field
fn get_json_field(json: &str, field: &str) -> Option<String> {
    // Simple JSON field extraction without full parsing
    let pattern = format!("\"{}\":", field);
    if let Some(start) = json.find(&pattern) {
        let rest = &json[start + pattern.len()..];
        let rest = rest.trim_start();

        if let Some(rest) = rest.strip_prefix('"') {
            // String value
            if let Some(end) = rest.find('"') {
                return Some(rest[..end].to_string());
            }
        } else {
            // Non-string value (number, boolean, etc.)
            let end = rest.find([',', '}', ']']).unwrap_or(rest.len());
            return Some(rest[..end].trim().to_string());
        }
    }
    None
}

#[test]
fn test_daemon_startup_creates_socket() -> HarnessResult<()> {
    let _guard = rch_common::test_guard!();
    let harness = TestHarnessBuilder::new("daemon_startup_socket")
        .cleanup_on_success(true)
        .cleanup_on_failure(false)
        .rchd_binary(rchd_binary_path())
        .build()?;

    // Create minimal workers config
    let workers_config = r#"
[[workers]]
id = "test-worker"
host = "localhost"
user = "test"
total_slots = 4
"#;
    harness.create_workers_config(workers_config)?;

    // Create socket path in test directory
    let socket_path = harness.test_dir().join("rchd.sock");

    // Start daemon with custom socket
    let socket_arg = socket_path.to_string_lossy().to_string();
    let pid = harness.start_daemon(&["--socket", &socket_arg, "--foreground"])?;

    harness
        .logger
        .info(format!("Daemon started with PID: {}", pid));

    // Wait for socket to be created
    harness.wait_for_socket(&socket_path, Duration::from_secs(10))?;

    harness.assert(socket_path.exists(), "Socket file should exist")?;

    harness.mark_passed();
    Ok(())
}

#[test]
fn test_daemon_health_endpoint() -> HarnessResult<()> {
    let _guard = rch_common::test_guard!();
    let harness = TestHarnessBuilder::new("daemon_health")
        .cleanup_on_success(true)
        .cleanup_on_failure(false)
        .rchd_binary(rchd_binary_path())
        .build()?;

    // Create minimal workers config
    let workers_config = r#"
[[workers]]
id = "test-worker"
host = "localhost"
user = "test"
total_slots = 4
"#;
    harness.create_workers_config(workers_config)?;

    // Create socket path
    let socket_path = harness.test_dir().join("rchd.sock");
    let socket_arg = socket_path.to_string_lossy().to_string();

    // Start daemon
    harness.start_daemon(&["--socket", &socket_arg, "--foreground"])?;

    // Wait for socket
    harness.wait_for_socket(&socket_path, Duration::from_secs(10))?;

    // Send health check request
    let response = send_request(&socket_path, "GET /health")
        .map_err(rch_common::e2e::harness::HarnessError::Io)?;

    harness
        .logger
        .info(format!("Health response: {}", response));

    // Verify health response contains expected fields
    let status = get_json_field(&response, "status");
    harness.assert(
        status == Some("healthy".to_string()),
        &format!("Health status should be 'healthy', got: {:?}", status),
    )?;

    let version = get_json_field(&response, "version");
    harness.assert(version.is_some(), "Health response should include version")?;

    let uptime = get_json_field(&response, "uptime_seconds");
    harness.assert(
        uptime.is_some(),
        "Health response should include uptime_seconds",
    )?;

    harness.mark_passed();
    Ok(())
}

#[test]
fn test_daemon_ready_endpoint() -> HarnessResult<()> {
    let _guard = rch_common::test_guard!();
    let harness = TestHarnessBuilder::new("daemon_ready")
        .cleanup_on_success(true)
        .cleanup_on_failure(false)
        .rchd_binary(rchd_binary_path())
        .build()?;

    // Create workers config
    let workers_config = r#"
[[workers]]
id = "test-worker"
host = "localhost"
user = "test"
total_slots = 4
"#;
    harness.create_workers_config(workers_config)?;

    // Create socket path
    let socket_path = harness.test_dir().join("rchd.sock");
    let socket_arg = socket_path.to_string_lossy().to_string();

    // Start daemon
    harness.start_daemon(&["--socket", &socket_arg, "--foreground"])?;

    // Wait for socket
    harness.wait_for_socket(&socket_path, Duration::from_secs(10))?;

    // Send ready check request
    let response = send_request(&socket_path, "GET /ready")
        .map_err(rch_common::e2e::harness::HarnessError::Io)?;

    harness.logger.info(format!("Ready response: {}", response));

    // Verify ready response structure
    let status = get_json_field(&response, "status");
    harness.assert(
        status.is_some(),
        "Ready response should include status field",
    )?;

    let workers_available = get_json_field(&response, "workers_available");
    harness.assert(
        workers_available.is_some(),
        "Ready response should include workers_available field",
    )?;

    harness.mark_passed();
    Ok(())
}

#[test]
fn test_daemon_status_endpoint() -> HarnessResult<()> {
    let _guard = rch_common::test_guard!();
    let harness = TestHarnessBuilder::new("daemon_status")
        .cleanup_on_success(true)
        .cleanup_on_failure(false)
        .rchd_binary(rchd_binary_path())
        .build()?;

    // Create workers config
    let workers_config = r#"
[[workers]]
id = "test-worker-1"
host = "localhost"
user = "test"
total_slots = 4

[[workers]]
id = "test-worker-2"
host = "remote.example.com"
user = "builder"
total_slots = 8
"#;
    harness.create_workers_config(workers_config)?;

    // Create socket path
    let socket_path = harness.test_dir().join("rchd.sock");
    let socket_arg = socket_path.to_string_lossy().to_string();

    // Start daemon
    harness.start_daemon(&["--socket", &socket_arg, "--foreground"])?;

    // Wait for socket
    harness.wait_for_socket(&socket_path, Duration::from_secs(10))?;

    // Send status request
    let response = send_request(&socket_path, "GET /status")
        .map_err(rch_common::e2e::harness::HarnessError::Io)?;

    harness
        .logger
        .info(format!("Status response: {}", response));

    // Verify status response contains daemon info
    harness.assert(
        response.contains("\"daemon\""),
        "Status should contain daemon section",
    )?;
    harness.assert(
        response.contains("\"workers\""),
        "Status should contain workers section",
    )?;
    harness.assert(
        response.contains("\"pid\""),
        "Status should contain daemon PID",
    )?;
    harness.assert(
        response.contains("\"version\""),
        "Status should contain daemon version",
    )?;

    harness.mark_passed();
    Ok(())
}

#[test]
fn test_daemon_budget_endpoint() -> HarnessResult<()> {
    let _guard = rch_common::test_guard!();
    let harness = TestHarnessBuilder::new("daemon_budget")
        .cleanup_on_success(true)
        .cleanup_on_failure(false)
        .rchd_binary(rchd_binary_path())
        .build()?;

    // Create workers config
    let workers_config = r#"
[[workers]]
id = "test-worker"
host = "localhost"
user = "test"
total_slots = 4
"#;
    harness.create_workers_config(workers_config)?;

    // Create socket path
    let socket_path = harness.test_dir().join("rchd.sock");
    let socket_arg = socket_path.to_string_lossy().to_string();

    // Start daemon
    harness.start_daemon(&["--socket", &socket_arg, "--foreground"])?;

    // Wait for socket
    harness.wait_for_socket(&socket_path, Duration::from_secs(10))?;

    // Send budget request
    let response = send_request(&socket_path, "GET /budget")
        .map_err(rch_common::e2e::harness::HarnessError::Io)?;

    harness
        .logger
        .info(format!("Budget response: {}", response));

    // Budget endpoint should return a valid JSON response
    harness.assert(
        response.starts_with('{') && response.ends_with('}'),
        "Budget response should be valid JSON object",
    )?;

    harness.mark_passed();
    Ok(())
}

#[test]
fn test_daemon_graceful_shutdown() -> HarnessResult<()> {
    let _guard = rch_common::test_guard!();
    let harness = TestHarnessBuilder::new("daemon_shutdown")
        .cleanup_on_success(true)
        .cleanup_on_failure(false)
        .rchd_binary(rchd_binary_path())
        .build()?;

    // Create workers config
    let workers_config = r#"
[[workers]]
id = "test-worker"
host = "localhost"
user = "test"
total_slots = 4
"#;
    harness.create_workers_config(workers_config)?;

    // Create socket path
    let socket_path = harness.test_dir().join("rchd.sock");
    let socket_arg = socket_path.to_string_lossy().to_string();

    // Start daemon
    harness.start_daemon(&["--socket", &socket_arg, "--foreground"])?;

    // Wait for socket
    harness.wait_for_socket(&socket_path, Duration::from_secs(10))?;

    // Verify daemon is healthy first
    let health_response = send_request(&socket_path, "GET /health")
        .map_err(rch_common::e2e::harness::HarnessError::Io)?;
    harness.assert(
        health_response.contains("healthy"),
        "Daemon should be healthy before shutdown",
    )?;

    // The graceful-shutdown CONTRACT: /shutdown refuses while
    // admission is open (shutdown_blocked), and proceeds only after
    // the admission barrier is raised and no builds are active. Pin
    // both halves.
    let premature = send_request(&socket_path, "POST /shutdown")
        .map_err(rch_common::e2e::harness::HarnessError::Io)?;
    harness
        .logger
        .info(format!("Premature shutdown response: {}", premature));
    harness.assert(
        !premature.contains("\"status\":\"shutting_down\""),
        "Shutdown without a maintenance fence must be refused",
    )?;

    // Raise the admission barrier (the restart/shutdown precondition).
    let fence = acquire_maintenance(&socket_path);

    // Send shutdown request (now permitted: admission closed, idle).
    let shutdown_response = send_request(&socket_path, &format!("POST /shutdown?{fence}"))
        .map_err(rch_common::e2e::harness::HarnessError::Io)?;

    harness
        .logger
        .info(format!("Shutdown response: {}", shutdown_response));

    // Verify shutdown response
    harness.assert(
        shutdown_response.contains("shutting_down"),
        "Shutdown response should indicate shutting_down status",
    )?;

    // Wait a bit for the daemon to shut down
    std::thread::sleep(Duration::from_millis(500));

    // Socket should eventually become unavailable
    // Try to connect - it should fail after shutdown
    harness.wait_for(
        "daemon to shut down",
        Duration::from_secs(5),
        Duration::from_millis(200),
        || {
            // Try to send a request - if it fails, daemon has shut down
            send_request(&socket_path, "GET /health").is_err()
        },
    )?;

    harness.mark_passed();
    Ok(())
}

#[test]
fn test_daemon_metrics_endpoint() -> HarnessResult<()> {
    let _guard = rch_common::test_guard!();
    let harness = TestHarnessBuilder::new("daemon_metrics")
        .cleanup_on_success(true)
        .cleanup_on_failure(false)
        .rchd_binary(rchd_binary_path())
        .build()?;

    // Create workers config
    let workers_config = r#"
[[workers]]
id = "test-worker"
host = "localhost"
user = "test"
total_slots = 4
"#;
    harness.create_workers_config(workers_config)?;

    // Create socket path
    let socket_path = harness.test_dir().join("rchd.sock");
    let socket_arg = socket_path.to_string_lossy().to_string();

    // Start daemon
    harness.start_daemon(&["--socket", &socket_arg, "--foreground"])?;

    // Wait for socket
    harness.wait_for_socket(&socket_path, Duration::from_secs(10))?;

    // Send metrics request
    let response = send_request(&socket_path, "GET /metrics")
        .map_err(rch_common::e2e::harness::HarnessError::Io)?;

    harness.logger.info(format!(
        "Metrics response (first 500 chars): {}",
        &response[..response.len().min(500)]
    ));

    // Metrics should be in Prometheus format (text/plain)
    // Should contain standard metric comments or metric lines
    harness.assert(!response.is_empty(), "Metrics response should not be empty")?;

    harness.mark_passed();
    Ok(())
}

#[test]
fn test_daemon_unknown_endpoint_error() -> HarnessResult<()> {
    let _guard = rch_common::test_guard!();
    let harness = TestHarnessBuilder::new("daemon_unknown_endpoint")
        .cleanup_on_success(true)
        .cleanup_on_failure(false)
        .rchd_binary(rchd_binary_path())
        .build()?;

    // Create workers config
    let workers_config = r#"
[[workers]]
id = "test-worker"
host = "localhost"
user = "test"
total_slots = 4
"#;
    harness.create_workers_config(workers_config)?;

    // Create socket path
    let socket_path = harness.test_dir().join("rchd.sock");
    let socket_arg = socket_path.to_string_lossy().to_string();

    // Start daemon
    harness.start_daemon(&["--socket", &socket_arg, "--foreground"])?;

    // Wait for socket
    harness.wait_for_socket(&socket_path, Duration::from_secs(10))?;

    // Send request to unknown endpoint - this may cause connection to close with error
    let result = send_request(&socket_path, "GET /nonexistent");

    // Either an error response or connection drop is acceptable
    harness
        .logger
        .info(format!("Unknown endpoint result: {:?}", result));

    // The test passes as long as the daemon doesn't crash
    // Send a follow-up health check to verify daemon is still running
    let health_result = send_request(&socket_path, "GET /health");
    harness.assert(
        health_result.is_ok(),
        "Daemon should still be running after unknown endpoint request",
    )?;

    harness.mark_passed();
    Ok(())
}

#[test]
fn test_daemon_config_fixture_integration() -> HarnessResult<()> {
    let _guard = rch_common::test_guard!();
    use rch_common::e2e::fixtures::{WorkerFixture, WorkersFixture};

    let harness = TestHarnessBuilder::new("daemon_config_fixture")
        .cleanup_on_success(true)
        .cleanup_on_failure(false)
        .rchd_binary(rchd_binary_path())
        .build()?;

    // Use fixtures to generate config
    let socket_path = harness.test_dir().join("rchd.sock");
    let _daemon_config = DaemonConfigFixture::minimal(&socket_path);

    // Create workers using WorkersFixture
    let fixture_worker = WorkerFixture {
        id: "fixture-worker".to_string(),
        host: "fixture-host".to_string(),
        user: "builder".to_string(),
        identity_file: "~/.ssh/id_rsa".to_string(),
        total_slots: 8,
        priority: 100,
    };
    let workers_fixture = WorkersFixture::empty().add_worker(fixture_worker);

    // Write the workers config using fixture
    let workers_toml = workers_fixture.to_toml();
    harness.create_workers_config(&workers_toml)?;

    // Start daemon with socket from fixture config
    let socket_arg = socket_path.to_string_lossy().to_string();

    harness.start_daemon(&["--socket", &socket_arg, "--foreground"])?;

    // Wait for socket
    harness.wait_for_socket(&socket_path, Duration::from_secs(10))?;

    // Verify daemon is running with our fixture config
    let status = send_request(&socket_path, "GET /status")
        .map_err(rch_common::e2e::harness::HarnessError::Io)?;

    harness.assert(
        status.contains("fixture-worker"),
        "Status should contain the fixture worker ID",
    )?;

    harness.mark_passed();
    Ok(())
}

/// bd-b4hrx: a daemon started by a test harness must not outlive the process
/// that owns it. A stand-in owner (`sleep 3`) is named in
/// RCH_EXIT_WITH_PARENT_PID; once it exits, rchd must stop on its own.
#[test]
fn test_daemon_exits_when_its_owning_process_dies() -> HarnessResult<()> {
    let _guard = rch_common::test_guard!();
    let harness = TestHarnessBuilder::new("daemon_exit_with_owner")
        .cleanup_on_success(true)
        .cleanup_on_failure(false)
        .rchd_binary(rchd_binary_path())
        .build()?;
    harness.create_workers_config(
        "[[workers]]\nid = \"test-worker\"\nhost = \"localhost\"\nuser = \"test\"\ntotal_slots = 4\n",
    )?;
    let mut owner = std::process::Command::new("sleep")
        .arg("3")
        .spawn()
        .expect("spawn stand-in owner");
    let socket_path = harness.test_dir().join("rchd.sock");
    let socket_arg = socket_path.to_string_lossy().to_string();
    let workers = harness.test_dir().join("config").join("workers.toml");
    let workers_arg = workers.to_string_lossy().to_string();
    let env = std::collections::HashMap::from([(
        "RCH_EXIT_WITH_PARENT_PID".to_string(),
        owner.id().to_string(),
    )]);
    let started = harness
        .spawn_process(
            "daemon",
            &rchd_binary_path(),
            [
                "--workers-config",
                workers_arg.as_str(),
                "--socket",
                socket_arg.as_str(),
                "--foreground",
            ],
            Some(&env),
        )
        .and_then(|pid| {
            harness.wait_for_socket(&socket_path, Duration::from_secs(10))?;
            Ok(pid)
        });
    // Reap the owner on every path, so it is truly gone (not a zombie).
    owner.wait().expect("stand-in owner exits");
    let pid = started?;

    // The daemon is this test's child, so once it exits it lingers as a zombie
    // until reaped: treat a missing process or state Z as exited.
    let exited = || {
        std::process::Command::new("ps")
            .args(["-o", "stat=", "-p", &pid.to_string()])
            .output()
            .map(|out| {
                let stat = String::from_utf8_lossy(&out.stdout);
                stat.trim().is_empty() || stat.trim_start().starts_with('Z')
            })
            .unwrap_or(false)
    };
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while !exited() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(200));
    }
    harness.assert(
        exited(),
        "rchd kept running after its owning process exited",
    )?;
    harness.mark_passed();
    Ok(())
}
