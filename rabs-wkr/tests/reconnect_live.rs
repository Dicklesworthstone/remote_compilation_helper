//! Real worker-process reconnection tests (S5), with an explicit loopback peer.
//!
//! These exercise the binary, native runtime, sockets and durable admission;
//! they do not claim TLS fleet qualification or execute a compiler. All child
//! processes and listeners are isolated and bounded, including assertion failures.
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
