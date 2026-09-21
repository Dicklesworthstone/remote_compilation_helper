//! Signal shutdown of the actual persistent worker process.
//!
//! Every child and socket is isolated and bounded. Retained results below are
//! explicitly seeded capture fixtures, not compiler or TLS fleet executions.
#![cfg(unix)]

use rabs_wkr::execution::DEFAULT_EXECUTION_TIMEOUT;
use rabs_wkr::request_journal::WorkerJournal;
use serde_json::{Value, json};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const WORKER: &str = "signal-shutdown-test";
const BUDGET: Duration = Duration::from_secs(10);
const DATA: &[u8] = b"retained stdout\0\xff";

struct Worker {
    child: Child,
    log: PathBuf,
}

impl Worker {
    fn start(root: &Path, address: &str, once: bool) -> Self {
        let log = root.join("worker.log");
        let mut command = Command::new(env!("CARGO_BIN_EXE_rabs-wkr"));
        command.args(["--coordinator", address, "--worker-id", WORKER]);
        if once { command.arg("--once"); }
        for name in ["RABS_WORKER_TLS_CA", "RABS_WORKER_TLS_CERT", "RABS_WORKER_TLS_KEY", "RABS_WORKER_TLS_SERVER_NAME"] {
            command.env_remove(name);
        }
        let child = command.env("RABS_WORKER_STATE_DIR", root.join("state"))
            .stdin(Stdio::null()).stdout(Stdio::null())
            .stderr(File::create(&log).unwrap()).spawn().unwrap();
        Self { child, log }
    }

    fn signal(&mut self, signal: &str) {
        assert!(self.child.try_wait().unwrap().is_none(), "worker exited before signal: {}", self.logs());
        // Only this test's still-owned child is signalled, never a process found
        // by name, a shared daemon, or a remotely supplied PID.
        assert!(Command::new("kill").args([signal, &self.child.id().to_string()])
            .status().unwrap().success());
    }

    fn exit(&mut self, code: i32) -> Value {
        let until = Instant::now() + BUDGET;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert_eq!(status.code(), Some(code), "{}", self.logs());
                break;
            }
            assert!(Instant::now() < until, "shutdown did not drain: {}", self.logs());
            std::thread::sleep(Duration::from_millis(5));
        }
        let receipts: Vec<Value> = self.logs().lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter(|value| value["kind"] == "worker-shutdown-receipt").collect();
        assert_eq!(receipts.len(), 1, "one terminal receipt, not a signal death");
        assert_eq!(receipts[0]["clean"], code == 0);
        assert_eq!(receipts[0]["reexecute"], false);
        receipts[0].clone()
    }

    fn logs(&self) -> String { fs::read_to_string(&self.log).unwrap() }
}

impl Drop for Worker {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() { let _ = self.child.kill(); }
        let _ = self.child.wait();
    }
}

struct Peer { reader: BufReader<TcpStream> }
impl Peer {
    fn accept(listener: &TcpListener, worker: &mut Worker) -> Self {
        let until = Instant::now() + BUDGET;
        let stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(worker.child.try_wait().unwrap().is_none(), "{}", worker.logs());
                    assert!(Instant::now() < until, "worker connection deadline: {}", worker.logs());
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("accept: {error}"),
            }
        };
        stream.set_read_timeout(Some(BUDGET)).unwrap();
        stream.set_write_timeout(Some(BUDGET)).unwrap();
        Self { reader: BufReader::new(stream) }
    }
    fn receive(&mut self) -> Value {
        let mut line = String::new();
        (&mut self.reader).take(1_048_577).read_line(&mut line).unwrap();
        assert!(line.ends_with('\n') && line.len() <= 1_048_576, "invalid frame boundary");
        serde_json::from_str(&line).unwrap()
    }
    fn send(&mut self, frame: &Value) { writeln!(self.reader.get_mut(), "{frame}").unwrap(); }
    fn admit(&mut self, retained: bool) -> Value {
        let hello = self.receive();
        assert_eq!(hello["kind"], "worker-hello");
        assert_eq!(hello["worker_id"], WORKER);
        self.send(&if retained {
            json!({"kind":"session-ok", "output_transfer":"ranges-v1",
                "result_retention":"durable-result-v1", "recovery_protocol":"request-journal-v1"})
        } else { json!({"kind":"session-ok"}) });
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
fn journal_bytes(root: &Path) -> Vec<u8> { fs::read(root.join("state/requests.json")).unwrap() }
fn request() -> Value {
    json!({"kind":"canonical-exec", "request_id":7, "program":"unused-fixture",
        "args":[], "toolchain_backing":"/unused", "workspace_backing":"/unused"})
}

#[test]
fn sigterm_and_sigint_stop_idle_admitted_sessions_without_reconnecting() {
    for signal in ["-TERM", "-INT"] {
        let root = tempfile::tempdir().unwrap();
        let listener = listener();
        let address = listener.local_addr().unwrap().to_string();
        let mut worker = Worker::start(root.path(), &address, false);
        let mut peer = Peer::accept(&listener, &mut worker);
        let hello = peer.admit(false);
        let before = journal_bytes(root.path());
        worker.signal(signal);
        let receipt = worker.exit(0);
        assert_eq!(receipt["incarnation"], hello["incarnation"]);
        assert_eq!(receipt["request_status"], "unknown");
        assert_eq!(journal_bytes(root.path()), before);
        assert!(!worker.logs().contains("worker-reconnect-scheduled"));
        assert!(matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock));
    }
}

#[test]
fn signal_interrupts_an_unanswered_handshake_including_once_mode() {
    for once in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let listener = listener();
        let address = listener.local_addr().unwrap().to_string();
        let mut worker = Worker::start(root.path(), &address, once);
        let mut peer = Peer::accept(&listener, &mut worker);
        assert_eq!(peer.receive()["kind"], "worker-hello");
        // No session-ok and no EOF: shutdown must wake the pending transport.
        worker.signal("-TERM");
        assert_eq!(worker.exit(0)["request_status"], "unknown");
        assert!(!worker.logs().contains("worker-reconnect-scheduled"));
    }
}

#[test]
fn signal_during_reconnect_backoff_stops_before_a_new_connection() {
    let root = tempfile::tempdir().unwrap();
    let listener = listener();
    let address = listener.local_addr().unwrap().to_string();
    let mut worker = Worker::start(root.path(), &address, false);
    // Reach a nontrivial delay without changing production policy or test knobs.
    for _ in 0..5 {
        let mut peer = Peer::accept(&listener, &mut worker);
        peer.admit(false);
        drop(peer);
    }
    let until = Instant::now() + BUDGET;
    loop {
        let entries: Vec<Value> = worker.logs().lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter(|value| value["kind"] == "worker-reconnect-scheduled").collect();
        if entries.len() >= 5 {
            assert!(entries.last().unwrap()["delay_ms"].as_u64().unwrap() >= 2_000);
            break;
        }
        assert!(Instant::now() < until);
        std::thread::sleep(Duration::from_millis(5));
    }
    worker.signal("-INT");
    worker.exit(0);
    assert!(matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock));
}

#[test]
fn shutdown_does_not_certify_or_erase_a_previous_uncertain_execution() {
    let root = tempfile::tempdir().unwrap();
    let listener = listener();
    let address = listener.local_addr().unwrap().to_string();
    {
        let mut journal = WorkerJournal::open(&root.path().join("state"), WORKER, &address).unwrap();
        assert_eq!(journal.admit(&request(), DEFAULT_EXECUTION_TIMEOUT).unwrap(), None);
    }
    let mut worker = Worker::start(root.path(), &address, false);
    let mut peer = Peer::accept(&listener, &mut worker);
    assert_eq!(peer.admit(false)["request_high_water"], 7);
    let before = journal_bytes(root.path());
    worker.signal("-TERM");
    assert_eq!(worker.exit(1)["request_status"], "execution-uncertain");
    assert_eq!(journal_bytes(root.path()), before);
    let mut journal = WorkerJournal::open(&root.path().join("state"), WORKER, &address).unwrap();
    let mut next = request(); next["request_id"] = json!(8);
    assert_eq!(journal.admit(&next, DEFAULT_EXECUTION_TIMEOUT).unwrap(), Some("prior-execution-uncertain"));
}

fn seed_retained(root: &Path, address: &str) {
    use rabs_wkr::execution::ExecutionCompletion;
    use rabs_wkr::output::{CapturedOutputs, CapturedStream};
    use rabs_wkr::result_spool::{ResultRecipient, RetentionTarget};
    use rabs_wkr::session::{ExecResult, sha256_hex};
    let mut journal = WorkerJournal::open(&root.join("state"), WORKER, address).unwrap();
    assert_eq!(journal.admit(&request(), DEFAULT_EXECUTION_TIMEOUT).unwrap(), None);
    let target = RetentionTarget::from_admitted(journal.storage_root(), 7, ResultRecipient::LoopbackFixture).unwrap();
    let mut completion = ExecutionCompletion {
        result: ExecResult {
            request_id:7, exit_code:0, executed:true, residual_group_members:0,
            stdout_sha256:sha256_hex(DATA), stderr_sha256:sha256_hex(b""),
            stdout_spill_bytes:0, stderr_spill_bytes:0,
            stdout_spill_path:None, stderr_spill_path:None,
        },
        stop_reason:None,
        outputs:Some(CapturedOutputs {
            stdout:CapturedStream::from_reader(DATA, DATA.len() as u64).unwrap(),
            stderr:CapturedStream::from_reader(&b""[..], 0).unwrap(),
        }),
        artifacts:None,
    };
    let digest = target.seal(&mut completion).unwrap();
    journal.finish(7, &json!({
        "kind":"exec-result", "request_id":7, "exit_code":0, "executed":true,
        "residual_group_members":0, "stop_reason":null,
        "stdout_sha256":completion.result.stdout_sha256,
        "stderr_sha256":completion.result.stderr_sha256,
        "retained_result_sha256":digest,
    }), true).unwrap();
}

#[test]
fn shutdown_preserves_unacknowledged_result_bytes_for_explicit_recovery() {
    use rabs_wkr::result_spool::ResultRecipient;
    let root = tempfile::tempdir().unwrap();
    let listener = listener();
    let address = listener.local_addr().unwrap().to_string();
    seed_retained(root.path(), &address);
    let mut worker = Worker::start(root.path(), &address, false);
    let mut peer = Peer::accept(&listener, &mut worker);
    assert_eq!(peer.admit(true)["retained_result_available"], true);
    peer.send(&json!({"kind":"result-resume", "request_id":7, "request":request()}));
    let result = peer.receive();
    assert_eq!(result["kind"], "exec-result");
    assert_eq!(result["resumed"], true);
    let before = journal_bytes(root.path());
    worker.signal("-TERM");
    assert_eq!(worker.exit(0)["retained_result_available"], true);
    assert_eq!(journal_bytes(root.path()), before);
    assert!(root.path().join("state/retained-result/manifest.json").is_file());
    let mut journal = WorkerJournal::open(&root.path().join("state"), WORKER, &address).unwrap();
    journal.authorize_result_recipient(ResultRecipient::LoopbackFixture);
    let mut recovered = journal.resume_result(&request(), DEFAULT_EXECUTION_TIMEOUT, false).unwrap();
    assert_eq!(recovered.outputs.as_mut().unwrap().stdout.read_chunk(0, 64).unwrap(), DATA);
    assert_eq!(journal.admit(&request(), DEFAULT_EXECUTION_TIMEOUT).unwrap(), Some("durable-request-already-admitted"));
}
