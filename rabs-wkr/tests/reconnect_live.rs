//! Real worker-process reconnection tests (S5), with an explicit loopback peer.
//!
//! These exercise the binary, native runtime, sockets and durable admission;
//! they do not claim TLS fleet qualification or execute a compiler. Retained
//! results are explicitly seeded capture fixtures, not fabricated compiler runs.
//! All child processes and listeners are isolated and bounded, including failures.
#![cfg(unix)]

use rabs_wkr::execution::DEFAULT_EXECUTION_TIMEOUT;
use rabs_wkr::request_journal::WorkerJournal;
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const WORKER_ID: &str = "reconnect-test";
const IO_BUDGET: Duration = Duration::from_secs(10);

struct Worker {
    child: Child,
    log: PathBuf,
}

impl Worker {
    fn start(address: &str, root: &Path, once: bool) -> Self {
        let log = root.join("worker.log");
        let mut command = Command::new(env!("CARGO_BIN_EXE_rabs-wkr"));
        command.args(["--coordinator", address, "--worker-id", WORKER_ID]);
        if once {
            command.arg("--once");
        }
        // Child-local settings only: no shared HOME, state, or test-wide env edits.
        for name in [
            "RABS_WORKER_TLS_CA", "RABS_WORKER_TLS_CERT", "RABS_WORKER_TLS_KEY",
            "RABS_WORKER_TLS_SERVER_NAME",
        ] {
            command.env_remove(name);
        }
        let child = command
            .env("RABS_WORKER_STATE_DIR", root.join("state"))
            .env("TMPDIR", root)
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(&log).unwrap())
            .spawn()
            .unwrap();
        Self { child, log }
    }

    fn logs(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    fn assert_alive(&mut self) {
        assert!(self.child.try_wait().unwrap().is_none(), "worker exited: {}", self.logs());
    }

    fn expect_exit(&mut self, code: i32) {
        let until = Instant::now() + IO_BUDGET;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert_eq!(status.code(), Some(code), "{}", self.logs());
                return;
            }
            assert!(Instant::now() < until, "worker did not exit: {}", self.logs());
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

struct Peer(BufReader<TcpStream>);

impl Peer {
    fn accept(listener: &TcpListener, worker: &mut Worker) -> Self {
        let until = Instant::now() + IO_BUDGET;
        loop {
            worker.assert_alive();
            match listener.accept() {
                Ok((stream, _)) => {
                    stream.set_read_timeout(Some(IO_BUDGET)).unwrap();
                    stream.set_write_timeout(Some(IO_BUDGET)).unwrap();
                    return Self(BufReader::new(stream));
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < until, "no worker reconnect: {}", worker.logs());
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("accept worker: {error}"),
            }
        }
    }

    fn send(&mut self, value: &Value) {
        writeln!(self.0.get_mut(), "{value}").unwrap();
    }

    fn receive(&mut self) -> Value {
        let mut line = String::new();
        (&mut self.0).take(1_048_577).read_line(&mut line).unwrap();
        assert!(line.len() <= 1_048_576 && line.ends_with('\n'), "incomplete/oversized reply");
        serde_json::from_str(&line).unwrap()
    }

    fn admit(&mut self) -> Value {
        let hello = self.receive();
        assert_eq!(hello["kind"], "worker-hello");
        assert_eq!(hello["worker_id"], WORKER_ID);
        self.send(&json!({"kind":"session-ok", "recovery_protocol":"request-journal-v1"}));
        self.send(&json!({"kind":"ping"}));
        assert_eq!(self.receive()["kind"], "heartbeat");
        hello
    }
}

fn listener() -> TcpListener {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    listener
}

fn request(id: u64) -> Value {
    json!({
        "kind":"canonical-exec", "request_id":id,
        "program":"/must-not-execute", "args":[],
        "toolchain_backing":"/absent-toolchain", "workspace_backing":"/absent-workspace",
    })
}

#[test]
fn persistent_worker_reconnects_with_one_process_identity_and_fresh_admission() {
    let root = tempfile::tempdir().unwrap();
    let listener = listener();
    let address = listener.local_addr().unwrap().to_string();
    let mut worker = Worker::start(&address, root.path(), false);
    let mut prior: Option<Value> = None;
    for _ in 0..3 {
        let mut peer = Peer::accept(&listener, &mut worker);
        let hello = peer.admit();
        if let Some(prior) = &prior {
            for field in ["boot_generation", "incarnation", "request_high_water"] {
                assert_eq!(hello[field], prior[field], "reconnect changed {field}");
            }
        }
        prior = Some(hello);
        worker.assert_alive();
        drop(peer);
    }
    // Each connection reached a real native-runtime heartbeat; the same child
    // must still be running, not an external process manager's replacement.
    worker.assert_alive();
    assert!(worker.logs().contains("worker-reconnect-scheduled"));
}

#[test]
fn rejected_handshake_is_retried_but_cannot_advance_execution() {
    let root = tempfile::tempdir().unwrap();
    let listener = listener();
    let address = listener.local_addr().unwrap().to_string();
    let mut worker = Worker::start(&address, root.path(), false);
    let mut denied = Peer::accept(&listener, &mut worker);
    let first = denied.receive();
    denied.send(&json!({"kind":"refusal", "reason":"session-ok is not a grant"}));
    drop(denied);
    let mut next = Peer::accept(&listener, &mut worker);
    let hello = next.admit();
    assert_eq!(hello["incarnation"], first["incarnation"]);
    assert_eq!(hello["boot_generation"], first["boot_generation"]);
    assert!(hello["request_high_water"].is_null());
    let journal: Value = serde_json::from_slice(
        &std::fs::read(root.path().join("state/requests.json")).unwrap(),
    ).unwrap();
    assert!(journal["last"].is_null(), "failed admission created execution ownership");
}

#[test]
fn uncertain_execution_stays_fenced_across_live_reconnections() {
    let root = tempfile::tempdir().unwrap();
    let listener = listener();
    let address = listener.local_addr().unwrap().to_string();
    {
        let mut journal = WorkerJournal::open(&root.path().join("state"), WORKER_ID, &address).unwrap();
        assert_eq!(journal.admit(&request(7), DEFAULT_EXECUTION_TIMEOUT).unwrap(), None);
    }
    let mut worker = Worker::start(&address, root.path(), false);
    let mut durable = None;
    for _ in 0..3 {
        let mut peer = Peer::accept(&listener, &mut worker);
        let hello = peer.admit();
        assert_eq!(hello["request_high_water"], 7);
        peer.send(&json!({"kind":"request-status", "request_id":7}));
        let status = peer.receive();
        assert_eq!(status["status"], "execution-uncertain");
        assert_eq!(status["replay_authorized"], false);
        assert_eq!(status["active_in_this_session"], false);
        peer.send(&request(7));
        assert_eq!(peer.receive()["reason"], "durable-request-already-admitted");
        peer.send(&request(8));
        assert_eq!(peer.receive()["reason"], "prior-execution-uncertain");
        let mut conflict = request(7);
        conflict["args"] = json!(["different"]);
        peer.send(&conflict);
        assert_eq!(peer.receive()["reason"], "durable-request-conflict");
        let bytes = std::fs::read(root.path().join("state/requests.json")).unwrap();
        if let Some(before) = &durable {
            assert_eq!(&bytes, before, "reconnection rewrote durable execution ownership");
        }
        durable = Some(bytes);
        drop(peer);
    }
    worker.assert_alive();
}

#[test]
fn once_keeps_its_clean_exit_and_no_reconnect_contract() {
    let root = tempfile::tempdir().unwrap();
    let listener = listener();
    let address = listener.local_addr().unwrap().to_string();
    let mut worker = Worker::start(&address, root.path(), true);
    let mut peer = Peer::accept(&listener, &mut worker);
    peer.admit();
    drop(peer);
    worker.expect_exit(0);
    assert!(matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock));
    assert!(!worker.logs().contains("worker-reconnect-scheduled"));
}

const RETAINED_STDOUT: &[u8] = b"original stdout\0\xff";
const RETAINED_ARTIFACT: &[u8] = b"archive\0\xff:never recompiled";

fn artifact_request(id: u64) -> Value {
    let mut request = request(id);
    request["artifacts"] = json!({"unit":"dep", "files":["lib.rlib"]});
    request
}

/// Seed real immutable capture bytes and a receipt through the production
/// storage APIs. This is an explicit completed-result fixture, NOT a compiler.
fn seed_retained_result(
    root: &Path, address: &str, recipient: rabs_wkr::result_spool::ResultRecipient,
) {
    use rabs_wkr::artifacts::{ArtifactPlan, PreparedArtifacts};
    use rabs_wkr::execution::ExecutionCompletion;
    use rabs_wkr::output::{CapturedOutputs, CapturedStream};
    use rabs_wkr::result_spool::RetentionTarget;
    use rabs_wkr::session::{ExecResult, sha256_hex};

    let mut journal = WorkerJournal::open(&root.join("state"), WORKER_ID, address).unwrap();
    assert_eq!(journal.admit(&artifact_request(50), DEFAULT_EXECUTION_TIMEOUT).unwrap(), None);
    let plan = ArtifactPlan::new("dep".to_owned(), vec!["lib.rlib".to_owned()]).unwrap();
    let prepared = PreparedArtifacts::new(plan).unwrap();
    std::fs::write(prepared.backing().join("lib.rlib"), RETAINED_ARTIFACT).unwrap();
    let mut completion = ExecutionCompletion {
        result: ExecResult {
            request_id: 50, exit_code: 0, executed: true, residual_group_members: 0,
            stdout_sha256: sha256_hex(RETAINED_STDOUT), stderr_sha256: sha256_hex(b""),
            stdout_spill_bytes: 0, stderr_spill_bytes: 0,
            stdout_spill_path: None, stderr_spill_path: None,
        },
        stop_reason: None,
        outputs: Some(CapturedOutputs {
            stdout: CapturedStream::from_reader(RETAINED_STDOUT, RETAINED_STDOUT.len() as u64).unwrap(),
            stderr: CapturedStream::from_reader(&b""[..], 0).unwrap(),
        }),
        artifacts: Some(prepared.capture(|| false).unwrap()),
    };
    let target = RetentionTarget::from_admitted(journal.storage_root(), 50, recipient).unwrap();
    let digest = target.seal(&mut completion).unwrap();
    journal.finish(50, &json!({
        "kind":"exec-result", "request_id":50, "exit_code":0, "executed":true,
        "residual_group_members":0, "stop_reason":null,
        "stdout_sha256":completion.result.stdout_sha256,
        "stderr_sha256":completion.result.stderr_sha256,
        "retained_result_sha256":digest,
    }), true).unwrap();
}

fn resume_request() -> Value {
    json!({"kind":"result-resume", "request_id":50, "request":artifact_request(50)})
}

fn admit_retention(peer: &mut Peer) -> Value {
    let hello = peer.receive();
    assert_eq!(hello["kind"], "worker-hello");
    assert_eq!(hello["worker_id"], WORKER_ID);
    peer.send(&json!({
        "kind":"session-ok", "recovery_protocol":"request-journal-v1",
        "output_transfer":"ranges-v1", "artifact_transfer":"files-v1",
        "result_retention":"durable-result-v1",
    }));
    peer.send(&json!({"kind":"ping"}));
    assert_eq!(peer.receive()["kind"], "heartbeat");
    hello
}

fn output_ack() -> Value {
    json!({
        "kind":"output-ack", "request_id":50,
        "stdout_sha256":rabs_wkr::session::sha256_hex(RETAINED_STDOUT),
        "stderr_sha256":rabs_wkr::session::sha256_hex(b""),
        "stdout_bytes":RETAINED_STDOUT.len(), "stderr_bytes":0,
    })
}

fn artifact_ack(result: &Value) -> Value {
    json!({
        "kind":"artifact-ack", "request_id":50,
        "manifest_sha256":result["artifact_manifest"]["manifest_sha256"],
        "total_bytes":result["artifact_manifest"]["total_bytes"],
    })
}

fn assert_range_bytes(peer: &mut Peer, request: Value, bytes: &[u8]) {
    peer.send(&request);
    let response = peer.receive();
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(response["data_hex"], hex);
    assert_eq!(response["chunk_sha256"], rabs_wkr::session::sha256_hex(bytes));
    assert_eq!(response["request_id"], 50);
    assert_eq!(response["eof"], true);
}

#[test]
fn same_process_recovers_complete_result_after_partial_ack_in_either_order() {
    for artifacts_first in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let listener = listener();
        let address = listener.local_addr().unwrap().to_string();
        seed_retained_result(root.path(), &address, rabs_wkr::result_spool::ResultRecipient::LoopbackFixture);
        let mut worker = Worker::start(&address, root.path(), false);

        // An ordinary session does NOT inherit a grant to read retained bytes.
        let mut peer = Peer::accept(&listener, &mut worker);
        let identity = peer.admit();
        assert_eq!(identity["retained_result_available"], true);
        peer.send(&resume_request());
        assert_eq!(peer.receive()["kind"], "error");
        drop(peer);

        let mut original_offer = None;
        for final_session in [false, true] {
            let mut peer = Peer::accept(&listener, &mut worker);
            let hello = admit_retention(&mut peer);
            for field in ["boot_generation", "incarnation", "request_high_water"] {
                assert_eq!(hello[field], identity[field]);
            }
            peer.send(&resume_request());
            let result = peer.receive();
            assert_eq!(result["kind"], "exec-result");
            assert_eq!(result["resumed"], true);
            assert_eq!(result["exit_code"], 0);
            assert_eq!(result["executed"], true);
            assert_eq!(result["stdout_sha256"], rabs_wkr::session::sha256_hex(RETAINED_STDOUT));
            assert_eq!(result["artifact_manifest"]["files"][0]["sha256"],
                rabs_wkr::session::sha256_hex(RETAINED_ARTIFACT));
            if let Some(original) = &original_offer {
                assert_eq!(&result, original, "reconnect changed the retained offer");
            }
            original_offer = Some(result.clone());
            assert_range_bytes(&mut peer, json!({
                "kind":"output-read", "request_id":50, "stream":"stdout", "offset":0, "max_bytes":64,
            }), RETAINED_STDOUT);
            assert_range_bytes(&mut peer, json!({
                "kind":"output-read", "request_id":50, "stream":"stderr", "offset":0, "max_bytes":64,
            }), b"");
            assert_range_bytes(&mut peer, json!({
                "kind":"artifact-read", "request_id":50, "name":"lib.rlib", "offset":0, "max_bytes":64,
            }), RETAINED_ARTIFACT);

            let first = if artifacts_first { artifact_ack(&result) } else { output_ack() };
            let second = if artifacts_first { output_ack() } else { artifact_ack(&result) };
            if final_session {
                let mut wrong = output_ack();
                wrong["stdout_bytes"] = json!(0);
                peer.send(&wrong);
                assert_eq!(peer.receive()["kind"], "error");
            }
            peer.send(&first);
            assert_ne!(peer.receive()["kind"], "error");
            peer.send(&json!({"kind":"request-status", "request_id":50}));
            assert_eq!(peer.receive()["receipt"]["retained_result_released"], false);
            assert!(root.path().join("state/retained-result/manifest.json").is_file());
            peer.send(&artifact_request(51));
            assert_eq!(peer.receive()["reason"],
                if artifacts_first { "output-unacknowledged" } else { "artifacts-unacknowledged" });
            if final_session {
                peer.send(&second);
                assert_ne!(peer.receive()["kind"], "error");
                peer.send(&json!({"kind":"request-status", "request_id":50}));
                assert_eq!(peer.receive()["receipt"]["retained_result_released"], true);
                assert!(!root.path().join("state/retained-result").exists());
            }
            drop(peer);
        }

        // Final ACK reclaimed bytes, not the durable duplicate-execution fence.
        let mut peer = Peer::accept(&listener, &mut worker);
        let hello = admit_retention(&mut peer);
        assert_eq!(hello["incarnation"], identity["incarnation"]);
        assert_eq!(hello["retained_result_available"], false);
        peer.send(&artifact_request(50));
        assert_eq!(peer.receive()["reason"], "durable-request-already-admitted");
        peer.send(&resume_request());
        assert_eq!(peer.receive()["kind"], "error");
        worker.assert_alive();
    }
}

#[test]
fn reconnect_cannot_downgrade_a_tls_bound_result_to_a_loopback_recipient() {
    let root = tempfile::tempdir().unwrap();
    let listener = listener();
    let address = listener.local_addr().unwrap().to_string();
    seed_retained_result(root.path(), &address, rabs_wkr::result_spool::ResultRecipient::TlsSpki([7; 32]));
    let mut worker = Worker::start(&address, root.path(), false);
    for _ in 0..2 {
        let mut peer = Peer::accept(&listener, &mut worker);
        let hello = admit_retention(&mut peer);
        assert_eq!(hello["retained_result_available"], true);
        peer.send(&resume_request());
        let refusal = peer.receive();
        assert_eq!(refusal["kind"], "error");
        assert!(refusal["reason"].as_str().unwrap().contains("another authenticated recipient"));
        peer.send(&json!({"kind":"output-read", "request_id":50, "stream":"stdout", "offset":0}));
        assert_eq!(peer.receive()["reason"], "unknown-output-request");
        peer.send(&artifact_request(51));
        assert_eq!(peer.receive()["reason"], "retained-result-unacknowledged");
        drop(peer);
    }
    assert!(root.path().join("state/retained-result/manifest.json").is_file());
    worker.assert_alive();
}

#[test]
fn corrupt_spool_on_disconnect_stops_service_without_resetting_ownership() {
    let root = tempfile::tempdir().unwrap();
    let listener = listener();
    let address = listener.local_addr().unwrap().to_string();
    seed_retained_result(root.path(), &address, rabs_wkr::result_spool::ResultRecipient::LoopbackFixture);
    let mut worker = Worker::start(&address, root.path(), false);
    let mut peer = Peer::accept(&listener, &mut worker);
    admit_retention(&mut peer);
    peer.send(&resume_request());
    assert_eq!(peer.receive()["resumed"], true);
    let before = std::fs::read(root.path().join("state/requests.json")).unwrap();
    // The current session holds a private verified copy. The next connection
    // must verify the durable seal again after that transfer owner is dropped.
    std::fs::write(root.path().join("state/retained-result/file-000"), b"corrupt").unwrap();
    drop(peer);
    worker.expect_exit(1);
    assert!(worker.logs().contains("worker-reconnect-refused"));
    assert_eq!(std::fs::read(root.path().join("state/requests.json")).unwrap(), before);
    assert!(root.path().join("state/retained-result/manifest.json").is_file());
    assert!(matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock));
}
