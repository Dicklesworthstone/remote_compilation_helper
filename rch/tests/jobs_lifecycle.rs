//! Exercise the real jobs CLI against an isolated Unix-socket peer and durable
//! lease files. No SSH, compiler execution, shared daemon, or process-global
//! environment changes are involved.
#![cfg(target_os = "linux")]

use rch_common::job_identity::{DurableJobLease, JobIdentity};
use rch_common::{CompilationKind, TransferConfig, WorkerConfig, WorkerId};
use serde_json::{Value, json};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use tempfile::TempDir;

struct Fixture {
    root: TempDir,
    lease: DurableJobLease,
    lease_path: PathBuf,
    socket: PathBuf,
}

impl Fixture {
    fn new(admitted: bool) -> Self {
        let root = TempDir::new().unwrap();
        let state = root.path().join("state");
        fs::create_dir_all(state.join("job-leases")).unwrap();
        fs::create_dir_all(root.path().join("home")).unwrap();
        fs::create_dir_all(root.path().join("config")).unwrap();
        let pid = std::process::id();
        let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap();
        let mut lease = DurableJobLease::new(
            JobIdentity::new_local(),
            pid,
            Some(process_start_ticks(pid)),
            Some(boot.trim().to_owned()),
            0,
            true,
            false,
            "test-only-command-fingerprint".into(),
        );
        if admitted {
            lease.admit(42, "worker-a".into(), 1);
        }
        let lease_path = state
            .join("job-leases")
            .join(format!("{}.json", lease.identity.local_wrapper_id));
        write_lease(&lease_path, &lease);
        let socket = root.path().join("daemon.sock");
        Self {
            root,
            lease,
            lease_path,
            socket,
        }
    }

    fn command(&self, action: &str, timeout_secs: Option<u64>) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_rch"));
        command
            .env_clear()
            .env("HOME", self.root.path().join("home"))
            .env("XDG_CONFIG_HOME", self.root.path().join("config"))
            .env("RCH_STATE_HOME", self.root.path().join("state"))
            .env("RCH_SOCKET_PATH", &self.socket)
            .env("RCH_LOG_LEVEL", "error")
            .env("NO_COLOR", "1")
            .current_dir(self.root.path())
            .args([
                "--json",
                "jobs",
                action,
                &self.lease.identity.local_wrapper_id,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(timeout_secs) = timeout_secs {
            command.args(["--timeout-secs", &timeout_secs.to_string()]);
        }
        command
    }

    fn spawn(&self, action: &str, timeout_secs: Option<u64>) -> OwnedChild {
        OwnedChild(Some(self.command(action, timeout_secs).spawn().unwrap()))
    }

    fn spawn_local_settlement(&self, transport_bin: &Path, sentinel: &Path) -> OwnedChild {
        let mut command = self.command("recover", Some(5));
        command
            .args(["--daemon-managed", "false", "--daemon-local-only"])
            .env("PATH", transport_bin)
            .env("RCH_TEST_TRANSPORT_SENTINEL", sentinel)
            .process_group(0)
            // OwnedChild keeps this parent permission pipe open until exit.
            .stdin(Stdio::piped());
        OwnedChild(Some(command.spawn().unwrap()))
    }

    fn cancel_receipt(&self) -> PathBuf {
        self.lease_path
            .with_file_name(format!("{}.cancel", self.lease.identity.local_wrapper_id))
    }

    fn active(&self) -> Value {
        json!({
            "status": "active",
            "active": {
                "id": 42,
                "local_wrapper_id": self.lease.identity.local_wrapper_id,
                "worker_id": "worker-a",
            },
        })
    }

    fn completed(&self, code: i32) -> Value {
        json!({
            "status": "completed",
            "local_wrapper_id": self.lease.identity.local_wrapper_id,
            "record": {"id": 42, "worker_id": "worker-a", "exit_code": code},
        })
    }
}

fn process_start_ticks(pid: u32) -> u64 {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    stat.rsplit_once(") ")
        .unwrap()
        .1
        .split_whitespace()
        .nth(19)
        .unwrap()
        .parse()
        .unwrap()
}

fn write_lease(path: &Path, lease: &DurableJobLease) {
    let staged = path.with_extension("pending");
    fs::write(&staged, serde_json::to_vec(lease).unwrap()).unwrap();
    fs::rename(staged, path).unwrap();
}

/// Reap only the child this test created, including on assertion failure.
struct OwnedChild(Option<Child>);

impl OwnedChild {
    fn finish(mut self) -> Output {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if self.0.as_mut().unwrap().try_wait().unwrap().is_some() {
                return self.0.take().unwrap().wait_with_output().unwrap();
            }
            assert!(Instant::now() < deadline, "jobs CLI did not terminate");
            thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn peer(
    socket: &Path,
    replies: Vec<Value>,
    after_request: impl Fn(usize) + Send + 'static,
) -> JoinHandle<Vec<String>> {
    let listener = UnixListener::bind(socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut requests = Vec::new();
        for (index, reply) in replies.into_iter().enumerate() {
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "expected daemon request missing");
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("accept failed: {error}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = String::new();
            // The production helper half-closes its request before reading.
            Read::by_ref(&mut stream)
                .take(8192)
                .read_to_string(&mut request)
                .unwrap();
            requests.push(request);
            after_request(index);
            write!(
                stream,
                "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{reply}\n"
            )
            .unwrap();
        }
        requests
    })
}

fn output_json(output: &Output) -> Value {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    value.get("data").cloned().unwrap_or(value)
}

fn output_text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn queued_attach_waits_for_its_budget_without_querying_a_nonexistent_build() {
    let fixture = Fixture::new(false);
    let before = fs::read(&fixture.lease_path).unwrap();
    let started = Instant::now();
    let output = fixture.spawn("attach", Some(1)).finish();
    assert!(!output.status.success());
    assert!(output_text(&output).contains("same-id job is still pending"));
    assert!(started.elapsed() >= Duration::from_millis(900));
    assert_eq!(fs::read(&fixture.lease_path).unwrap(), before);
    assert!(!fixture.cancel_receipt().exists());
}

#[test]
fn attach_follows_admission_and_the_original_terminal_acknowledgement() {
    let fixture = Fixture::new(false);
    let path = fixture.lease_path.clone();
    let mut terminal = fixture.lease.clone();
    terminal.admit(42, "worker-a".into(), 1);
    terminal.exit_code = Some(101);
    terminal.acknowledge_terminal(2);
    let daemon = peer(&fixture.socket, vec![fixture.active()], move |_| {
        write_lease(&path, &terminal);
    });
    let child = fixture.spawn("attach", Some(5));
    thread::sleep(Duration::from_millis(150));
    let mut admitted = fixture.lease.clone();
    admitted.admit(42, "worker-a".into(), 1);
    write_lease(&fixture.lease_path, &admitted);
    let result = output_json(&child.finish());
    let requests = daemon.join().unwrap();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].starts_with("GET /builds/42?local_wrapper_id="));
    assert_eq!(
        result["identity"]["local_wrapper_id"],
        fixture.lease.identity.local_wrapper_id
    );
    assert_eq!(result["exit_code"], 101);
    assert_eq!(result["terminal_acknowledged"], true);
    assert!(!fixture.cancel_receipt().exists());
}

#[test]
fn cancellation_losing_to_completion_preserves_the_owner_journal() {
    let mut fixture = Fixture::new(true);
    fixture.lease.recovery = Some(json!({"retired": false}));
    write_lease(&fixture.lease_path, &fixture.lease);
    let before = fs::read(&fixture.lease_path).unwrap();
    let daemon = peer(
        &fixture.socket,
        vec![fixture.active(), fixture.completed(101)],
        |_| {},
    );
    let result = output_json(&fixture.spawn("cancel", None).finish());
    let requests = daemon.join().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests[1].starts_with("POST /builds/42/cancel?local_wrapper_id="));
    assert_eq!(result["status"], "completed");
    assert_eq!(result["exit_code"], 101);
    assert_eq!(result["terminal_acknowledged"], false);
    assert_eq!(result["has_recovery_journal"], true);
    assert_eq!(result["wrapper_stop_requested"], false);
    assert!(!fixture.cancel_receipt().exists());
    assert_eq!(fs::read(&fixture.lease_path).unwrap(), before);
}

#[test]
fn cancelling_an_already_completed_job_is_a_non_mutating_noop() {
    let fixture = Fixture::new(true);
    let before = fs::read(&fixture.lease_path).unwrap();
    let daemon = peer(&fixture.socket, vec![fixture.completed(0)], |_| {});
    let result = output_json(&fixture.spawn("cancel", None).finish());
    let requests = daemon.join().unwrap();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].starts_with("GET /builds/42?local_wrapper_id="));
    assert_eq!(result["status"], "completed");
    assert_eq!(result["wrapper_stop_requested"], false);
    assert_eq!(result["terminal_acknowledged"], false);
    assert!(!fixture.cancel_receipt().exists());
    assert_eq!(fs::read(&fixture.lease_path).unwrap(), before);
}

#[test]
fn foreign_cancellation_receipt_never_requests_a_wrapper_stop() {
    let fixture = Fixture::new(true);
    let before = fs::read(&fixture.lease_path).unwrap();
    let daemon = peer(
        &fixture.socket,
        vec![
            fixture.active(),
            json!({"status": "cancelled", "build_id": 43, "worker_id": "worker-a"}),
        ],
        |_| {},
    );
    let output = fixture.spawn("cancel", None).finish();
    daemon.join().unwrap();
    assert!(!output.status.success());
    assert!(output_text(&output).contains("cancellation build/worker mismatch"));
    assert!(!fixture.cancel_receipt().exists());
    assert_eq!(fs::read(&fixture.lease_path).unwrap(), before);
}

#[test]
fn observing_completion_cannot_overwrite_a_live_owners_newer_recovery_journal() {
    let fixture = Fixture::new(true);
    let path = fixture.lease_path.clone();
    let mut collecting = fixture.lease.clone();
    collecting.recovery = Some(json!({"retired": false, "phase": "sync_down"}));
    let daemon = peer(
        &fixture.socket,
        vec![fixture.completed(0), fixture.completed(0)],
        move |index| {
            if index == 0 {
                // Publish a newer journal after attach took its no-recovery
                // snapshot, but before it consumes the completion response.
                write_lease(&path, &collecting);
            } else {
                let retained: DurableJobLease =
                    serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                assert_eq!(retained.recovery, collecting.recovery);
                assert!(!retained.terminal_acknowledged);
                let mut terminal = collecting.clone();
                terminal.exit_code = Some(0);
                terminal.acknowledge_terminal(3);
                write_lease(&path, &terminal);
            }
        },
    );
    let result = output_json(&fixture.spawn("attach", Some(5)).finish());
    let requests = daemon.join().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(
        requests
            .iter()
            .all(|request| request.starts_with("GET /builds/42?"))
    );
    assert_eq!(result["terminal_acknowledged"], true);
    assert!(!fixture.cancel_receipt().exists());
}

#[test]
fn matching_cancellation_requests_only_the_original_wrapper() {
    let fixture = Fixture::new(true);
    let before = fs::read(&fixture.lease_path).unwrap();
    let daemon = peer(
        &fixture.socket,
        vec![
            fixture.active(),
            json!({"status": "cancelled", "build_id": 42, "worker_id": "worker-a"}),
        ],
        |_| {},
    );
    let result = output_json(&fixture.spawn("cancel", None).finish());
    daemon.join().unwrap();
    assert_eq!(result["wrapper_stop_requested"], true);
    let receipt: JobIdentity =
        serde_json::from_slice(&fs::read(fixture.cancel_receipt()).unwrap()).unwrap();
    assert_eq!(receipt, fixture.lease.identity);
    assert_eq!(fs::read(&fixture.lease_path).unwrap(), before);
}

#[test]
fn owner_exit_during_status_does_not_erase_a_new_recovery_intent() {
    let mut fixture = Fixture::new(true);
    // Positive absence of this synthetic process, without ever signalling it. Since
    // 3c3df8c6 a pid outside i32 (e.g. u32::MAX) is Unknown, not Absent, which skips
    // the completed-and-absent race this test exists for; i32::MAX is a valid pid
    // that is far above any kernel's pid_max, so it is positively absent.
    fixture.lease.wrapper_pid = i32::MAX as u32;
    write_lease(&fixture.lease_path, &fixture.lease);
    let path = fixture.lease_path.clone();
    let mut latest = fixture.lease.clone();
    latest.recovery = Some(json!({"retired": false, "phase": "sync_down"}));
    let retained = serde_json::to_vec(&latest).unwrap();
    let daemon = peer(
        &fixture.socket,
        vec![fixture.completed(0), fixture.completed(0)],
        move |index| {
            if index == 0 {
                write_lease(&path, &latest);
            }
        },
    );
    let output = fixture.spawn("attach", Some(5)).finish();
    daemon.join().unwrap();
    assert!(!output.status.success());
    assert!(output_text(&output).contains("use jobs recover"));
    assert_eq!(fs::read(&fixture.lease_path).unwrap(), retained);
    assert!(!fixture.cancel_receipt().exists());
}

#[test]
fn daemon_local_settlement_requires_exact_receipts_without_worker_transport() {
    for case in ["exact-receipt", "missing-slots", "foreign-readback"] {
        let mut fixture = Fixture::new(true);
        // Capture a real owner identity while it is alive, then reap only that
        // child. Local settlement must still prove the original wrapper exited.
        let mut owner = OwnedChild(Some(
            Command::new("/bin/cat")
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        ));
        let pid = owner.0.as_ref().unwrap().id();
        fixture.lease.wrapper_pid = pid;
        fixture.lease.process_start_ticks = Some(process_start_ticks(pid));
        drop(owner.0.as_mut().unwrap().stdin.take());
        assert!(owner.finish().status.success());

        let project = fixture.root.path().join("project");
        fs::create_dir_all(project.join("build")).unwrap();
        let source = project.join("source.c");
        let artifact = project.join("build/app");
        let artifact_bytes = b"original published output";
        fs::write(&source, b"original source").unwrap();
        fs::write(&artifact, artifact_bytes).unwrap();
        let worker = WorkerConfig {
            id: WorkerId::new("worker-a"),
            host: "unavailable.invalid".into(),
            user: "fixture".into(),
            identity_file: "/unused/worker-key".into(),
            ..WorkerConfig::default()
        };
        let transfer = TransferConfig::default();
        let identity = "0123456789abcdef0123456789abcdef";
        let original = json!({
            "version": 2,
            "wrapper_id": fixture.lease.identity.local_wrapper_id,
            "build_id": 42,
            "worker": worker,
            "identity": identity,
            "completion": format!(
                "{}/recovery-42-{identity}.done",
                transfer.remote_base.trim_end_matches('/'),
            ),
            "source_roots": ["/owned/project"],
            "source_authority_namespace": "current",
            "pair": null,
            "retire_root": null,
            "transfer": transfer,
            "project_root": project,
            "kind": CompilationKind::Make,
            "expected_triple": "x86_64-unknown-linux-gnu",
            "pinned_triple": null,
            "allow_foreign": false,
            "package_archive": false,
            "phases": [{
                "name": "project",
                "local": project,
                "remote": "/owned/project",
                "patterns": ["build/**"],
                "result_dir": null,
                "custom_target": false,
                "output_gate": false,
                "baseline": {},
                "published": {"build/app": blake3::hash(artifact_bytes).to_hex().to_string()},
                "complete": true,
            }],
            "exit_code": 0,
            "returned": 0,
            "prepared": true,
            "execution_started": true,
            "preparation_cancelled": false,
            "sources_released": true,
            "pair_released": true,
            "tree_retired": true,
            "retired": true,
            "custody_note": {"original_path": "/original//evidence/", "keep": [9, "exact"]},
        });
        fixture.lease.recovery = Some(original.clone());
        // Successful detached delivery may supersede the wrapper's original
        // retrieval failure, but only an exact daemon receipt permits ack.
        fixture.lease.exit_code = Some(102);
        fixture.lease.phase = "finalize".into();
        write_lease(&fixture.lease_path, &fixture.lease);

        let transport_bin = fixture.root.path().join("transport-bin");
        let sentinel = fixture.root.path().join("transport-attempted");
        fs::create_dir(&transport_bin).unwrap();
        for name in ["ssh", "rsync"] {
            let executable = transport_bin.join(name);
            fs::write(
                &executable,
                "#!/bin/sh\nprintf '%s\\n' \"$0\" >> \"$RCH_TEST_TRANSPORT_SENTINEL\"\nexit 97\n",
            )
            .unwrap();
            fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        }

        let mut active = fixture.active();
        let mut terminal = fixture.completed(0);
        let replies = if case == "missing-slots" {
            vec![active]
        } else {
            active["active"]["slots"] = json!(3);
            if case == "foreign-readback" {
                terminal["record"]["worker_id"] = json!("other-worker");
            }
            vec![active, json!({}), terminal]
        };
        let path = fixture.lease_path.clone();
        let daemon = peer(&fixture.socket, replies, move |_| {
            let lease: DurableJobLease = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            // Even after the release response, acknowledgement must wait for
            // the exact terminal readback that this peer has not yet sent.
            assert!(!lease.terminal_acknowledged, "{case}");
            assert!(
                lease
                    .recovery
                    .as_ref()
                    .unwrap()
                    .get("daemon_exit_code")
                    .is_none()
            );
        });
        let output = fixture
            .spawn_local_settlement(&transport_bin, &sentinel)
            .finish();
        let requests = daemon.join().unwrap();
        let wrapper = &fixture.lease.identity.local_wrapper_id;
        let query = format!("GET /builds/42?local_wrapper_id={wrapper}\n");
        if case == "missing-slots" {
            assert_eq!(requests, vec![query]);
        } else {
            assert_eq!(
                requests,
                vec![
                    query.clone(),
                    format!(
                        "POST /release-worker?worker=worker-a&slots=3&build_id=42&local_wrapper_id={wrapper}&exit_code=0\n"
                    ),
                    query,
                ],
            );
        }

        let after: DurableJobLease =
            serde_json::from_slice(&fs::read(&fixture.lease_path).unwrap()).unwrap();
        assert_eq!(after.identity, fixture.lease.identity);
        assert_eq!(after.wrapper_pid, pid);
        assert_eq!(after.owner_identity(), fixture.lease.owner_identity());
        assert_eq!(after.exit_code, Some(0));
        if case == "exact-receipt" {
            let result = output_json(&output);
            assert_eq!(result["status"], "recovered");
            assert_eq!(result["exit_code"], 0);
            assert_eq!(result["terminal_acknowledged"], true);
            assert!(after.terminal_acknowledged);
            let mut expected = original;
            expected["daemon_exit_code"] = json!(0);
            assert_eq!(after.recovery, Some(expected));

            // The peer has exited and its socket has no listener. An already
            // acknowledged retry must succeed without any IPC or release.
            let acknowledged = fs::read(&fixture.lease_path).unwrap();
            let retry = output_json(
                &fixture
                    .spawn_local_settlement(&transport_bin, &sentinel)
                    .finish(),
            );
            assert_eq!(retry, result);
            assert_eq!(fs::read(&fixture.lease_path).unwrap(), acknowledged);
        } else {
            assert!(!output.status.success(), "{case}");
            assert!(!after.terminal_acknowledged, "{case}");
            assert_eq!(after.recovery, Some(original));
            let expected = if case == "missing-slots" {
                "slot count"
            } else {
                "exact terminal receipt"
            };
            assert!(
                output_text(&output).contains(expected),
                "{case}: {}",
                output_text(&output)
            );
        }
        assert!(!sentinel.exists(), "{case}: worker transport was invoked");
        assert_eq!(fs::read(&artifact).unwrap(), artifact_bytes);
        assert_eq!(fs::read(&source).unwrap(), b"original source");
        assert!(!fixture.cancel_receipt().exists());
    }
}
