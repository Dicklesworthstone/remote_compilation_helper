//! Real operator signals delivered to the actual rabsd process over native TLS.
//!
//! The peer is scripted, not a compiler: these tests exercise OS signal wakeups,
//! authenticated request scoping, cancellation/completion ordering and verified
//! byte delivery. They do not qualify worker process cleanup or a live fleet.
//! All receiver/network waits are bounded and every spawned receiver is reaped.
#![cfg(unix)]

use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::runtime::RuntimeBuilder;
use rabs_asupersync::worker_transport::{SecureWorkerStream, TlsFiles, connect_peer};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const ARTIFACT: &[u8] = b"A\0\xffB";
const MANIFEST: &str = "548324c3a5c96511944c6ec6af94ee9bbb6683170bb0143f9d99cd192f80bfd6";
const LOG_LIMIT: u64 = 512 * 1024;

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|byte| format!("{byte:02x}")).collect() }
fn hash(bytes: &[u8]) -> String { hex(&Sha256::digest(bytes)) }
fn log(path: &Path) -> Vec<u8> {
    let mut bytes = Vec::new();
    File::open(path).unwrap().take(LOG_LIMIT + 1).read_to_end(&mut bytes).unwrap();
    assert!(bytes.len() as u64 <= LOG_LIMIT, "unbounded fixture log");
    bytes
}

struct Receiver { child:Child, stdout:PathBuf, stderr:PathBuf }
impl Receiver {
    fn spawn(root: &Path, tls: Option<&TlsFiles>, pin: &str, destination: &Path, resume: bool) -> Self {
        let stdout = root.join("receiver.stdout");
        let stderr = root.join("receiver.stderr");
        let request_path = root.join("request.json");
        if !request_path.exists() { fs::write(&request_path, request().to_string()).unwrap(); }
        let mut command = Command::new(env!("CARGO_BIN_EXE_rabsd"));
        command.args(["--worker-exec-tls", "127.0.0.1:0", "worker", pin])
            .arg(request_path).arg(destination)
            .env("RABS_STATE_DIR", root.join("state"))
            .env_remove("RABS_COORD_TLS_CA").env_remove("RABS_COORD_TLS_CERT").env_remove("RABS_COORD_TLS_KEY")
            .stdin(Stdio::null()).stdout(File::create(&stdout).unwrap()).stderr(File::create(&stderr).unwrap());
        if resume { command.arg("--resume"); }
        if let Some(tls) = tls {
            command.env("RABS_COORD_TLS_CA", &tls.ca)
                .env("RABS_COORD_TLS_CERT", &tls.certificate).env("RABS_COORD_TLS_KEY", &tls.private_key);
        }
        Self { child:command.spawn().unwrap(), stdout, stderr }
    }
    fn listening(&mut self) -> String {
        let until = Instant::now() + Duration::from_secs(15);
        loop {
            for value in self.messages() {
                if value["kind"] == "worker-exec-listening" {
                    assert_eq!(value["transport"], "mutual-tls-atp");
                    assert_eq!(value["authentication_required"], true);
                    return value["address"].as_str().unwrap().to_owned();
                }
            }
            assert!(self.child.try_wait().unwrap().is_none(), "receiver exited before listening: {:?}", self.messages());
            assert!(Instant::now() < until, "receiver readiness timeout");
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    fn signal(&mut self, name: &str) {
        assert!(matches!(name, "INT" | "TERM"));
        assert!(self.child.try_wait().unwrap().is_none(), "cannot signal an exited fixture");
        // Only this directly owned unreaped process, never a fleet PID/group.
        assert!(Command::new("/bin/kill").args(["-s", name, &self.child.id().to_string()])
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status().unwrap().success());
    }
    fn wait(&mut self) -> ExitStatus {
        let until = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() { return status; }
            assert!(Instant::now() < until, "receiver exit timeout: {:?}", self.messages());
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    fn messages(&self) -> Vec<Value> {
        String::from_utf8_lossy(&log(&self.stderr)).lines()
            .filter_map(|line| serde_json::from_str(line).ok()).collect()
    }
    fn failure(&self) -> Value {
        self.messages().into_iter().find(|value| value["kind"] == "worker-delivery-error")
            .expect("typed delivery failure, not termination by the default signal handler")
    }
}
impl Drop for Receiver {
    fn drop(&mut self) { let _ = self.child.kill(); let _ = self.child.wait(); }
}

struct Certificates { _owner:tempfile::TempDir, server:TlsFiles, worker:TlsFiles }
impl Certificates {
    fn new() -> Self {
        let owner = tempfile::tempdir().unwrap();
        let root = owner.path();
        let openssl = |args: &[&str]| {
            let output = Command::new("openssl").args(args).current_dir(root).output()
                .expect("OpenSSL is required, not a passing skip");
            assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        };
        openssl(&["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "1",
            "-subj", "/CN=RABS signal test CA", "-keyout", "ca.key", "-out", "ca.pem",
            "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"]);
        for (name, usage, serial) in [("server", "serverAuth", "2"), ("worker", "clientAuth", "3")] {
            let key = format!("{name}.key"); let csr = format!("{name}.csr");
            let pem = format!("{name}.pem"); let ext = format!("{name}.ext");
            openssl(&["req", "-new", "-newkey", "rsa:2048", "-nodes", "-sha256", "-subj", "/CN=localhost",
                "-keyout", &key, "-out", &csr]);
            fs::write(root.join(&ext), format!("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage={usage}\nsubjectAltName=DNS:localhost\n")).unwrap();
            openssl(&["x509", "-req", "-in", &csr, "-CA", "ca.pem", "-CAkey", "ca.key", "-set_serial", serial,
                "-days", "1", "-sha256", "-extfile", &ext, "-out", &pem]);
        }
        let files = |name: &str| TlsFiles { ca:root.join("ca.pem"), certificate:root.join(format!("{name}.pem")),
            private_key:root.join(format!("{name}.key")) };
        Self { server:files("server"), worker:files("worker"), _owner:owner }
    }
    fn pin(&self) -> String { hex(&self.worker.local_identity().unwrap().fingerprint) }
}

fn request() -> Value {
    json!({"kind":"canonical-exec", "request_id":7, "program":"rustc", "args":["lib.rs"],
        "toolchain_backing":"/tc", "workspace_backing":"/ws", "timeout_ms":10000,
        "artifacts":{"unit":"dep", "files":["a"]}})
}
fn hello(pin: &str, resume: bool) -> Value {
    let mut hello = json!({"kind":"worker-hello", "worker_id":"worker", "peer_id":pin,
        "canonical":true, "slots":1, "boot_generation":1,
        "incarnation":"00000000000000000000000000000001", "request_high_water":if resume {json!(7)} else {Value::Null},
        "transport":{"minimum_compatible":1,"current":1}, "application":{"minimum_compatible":1,"current":1},
        "recovery_protocols":["request-journal-v1"], "result_retentions":["durable-result-v1"],
        "output_transfers":["ranges-v1"], "artifact_transfers":["files-v1"]});
    if !resume {
        hello["execution_leases"] = json!(["request-renewal-v1"]);
    }
    hello
}
async fn send(stream: &mut SecureWorkerStream, value: &Value) {
    stream.write_all(format!("{value}\n").as_bytes()).await.unwrap();
    stream.flush().await.unwrap();
}
async fn receive(stream: &mut SecureWorkerStream) -> io::Result<Value> {
    let mut bytes = Vec::new(); let mut byte = [0];
    loop {
        if stream.read(&mut byte).await? == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "receiver disconnected"));
        }
        if byte[0] == b'\n' { return serde_json::from_slice(&bytes).map_err(io::Error::from); }
        if bytes.len() == 1024 * 1024 { return Err(io::Error::other("unbounded operator frame")); }
        bytes.push(byte[0]);
    }
}
async fn challenge(stream: &mut SecureWorkerStream, pin: &str, resume: bool) -> Value {
    send(stream, &hello(pin, resume)).await;
    let challenge = receive(stream).await.unwrap();
    assert_eq!(challenge["kind"], "session-challenge");
    assert_eq!(challenge["scope"], format!("canonical-probes:{pin}"));
    challenge
}
async fn authenticate(stream: &mut SecureWorkerStream, pin: &str, resume: bool) -> u64 {
    let challenge = challenge(stream, pin, resume).await;
    let session = challenge["session_id"].as_u64().unwrap();
    send(stream, &json!({"kind":"worker-auth", "peer_id":pin, "session_id":session,
        "operation_id":challenge["operation_id"], "token_id":challenge["token_id"]})).await;
    let grant = receive(stream).await.unwrap();
    assert_eq!(grant["kind"], "session-ok");
    assert_eq!(grant["session_id"], session);
    assert_eq!(grant["publication"], "disabled");
    assert_eq!(grant["result_retention"], "durable-result-v1");
    if resume {
        assert!(grant.get("execution_lease").is_none());
    } else {
        assert_eq!(
            grant["execution_lease"],
            json!({
                "version":"request-renewal-v1", "session_id":session,
                "lease_id":challenge["token_id"], "request_id":7,
                "request_sha256":hash(&serde_json::to_vec(&request()).unwrap()),
                "boot_generation":1, "incarnation":"00000000000000000000000000000001",
                "ttl_ms":30000,
            })
        );
    }
    let dispatch = receive(stream).await.unwrap();
    assert_eq!(dispatch, if resume { json!({"kind":"result-resume", "request_id":7, "request":request()}) } else { request() });
    session
}
async fn cancellation(stream: &mut SecureWorkerStream) {
    assert_eq!(receive(stream).await.unwrap(), json!({"kind":"cancel", "request_id":7}));
}
fn accepted() -> Value { json!({"kind":"cancel-accepted", "request_id":7, "accepted":true, "cleanup_pending":true}) }

async fn finish(stream: &mut SecureWorkerStream, destination: &Path, pin: &str, session: u64,
    cancelled: bool, late_cancel_reply: Option<Value>) {
    let stdout: Vec<u8> = (0..65_549).map(|index| (index % 256) as u8).collect();
    let stderr = b"final diagnostic after cleanup\0\xff";
    let result = json!({"kind":"exec-result", "request_id":7, "executed":true,
        "exit_code":if cancelled {130} else {0}, "stop_reason":if cancelled {json!("cancelled")} else {Value::Null},
        "residual_group_members":0, "output_transfer":"ranges-v1", "output_ack_required":true,
        "stdout_bytes":stdout.len(), "stdout_sha256":hash(&stdout), "stderr_bytes":stderr.len(), "stderr_sha256":hash(stderr),
        "result_retention":"durable-result-v1", "retained_result_sha256":"07".repeat(32),
        "artifact_transfer":if cancelled {Value::Null} else {json!("files-v1")}, "artifact_ack_required":!cancelled,
        "artifact_manifest":if cancelled {Value::Null} else {json!({"unit":"dep",
            "files":[{"name":"a", "bytes":ARTIFACT.len(), "sha256":hash(ARTIFACT), "executable":false}],
            "total_bytes":ARTIFACT.len(), "manifest_sha256":MANIFEST})}});
    send(stream, &result).await;
    if let Some(reply) = late_cancel_reply { send(stream, &reply).await; }
    let mut reads = 0;
    loop {
        let query = receive(stream).await.unwrap();
        assert_eq!(query["request_id"], 7);
        match query["kind"].as_str().unwrap() {
            "output-read" | "artifact-read" => {
                let artifact = query["kind"] == "artifact-read";
                let field = if artifact {"name"} else {"stream"};
                let bytes: &[u8] = match query[field].as_str().unwrap() {
                    "stdout" if !artifact => &stdout,
                    "stderr" if !artifact => stderr,
                    "a" if artifact && !cancelled => ARTIFACT,
                    _ => panic!("undeclared transfer: {query}"),
                };
                let offset = query["offset"].as_u64().unwrap() as usize;
                let max = query["max_bytes"].as_u64().unwrap() as usize;
                assert!((1..=65536).contains(&max));
                let next = (offset + max).min(bytes.len());
                let mut reply = json!({"kind":if artifact {"artifact-chunk"} else {"output-chunk"},
                    "request_id":7, "offset":offset, "next_offset":next, "total_bytes":bytes.len(), "eof":next == bytes.len(),
                    "sha256":hash(bytes), "data_hex":hex(&bytes[offset..next]), "chunk_sha256":hash(&bytes[offset..next])});
                reply[field] = query[field].clone();
                if artifact { reply["manifest_sha256"] = json!(MANIFEST); reply["executable"] = json!(false); }
                send(stream, &reply).await;
                reads += 1;
            }
            "output-ack" | "artifact-ack" => {
                assert_eq!(reads, if cancelled {3} else {4});
                let receipt: Value = serde_json::from_slice(&fs::read(destination.join("delivery.json")).unwrap()).unwrap();
                assert_eq!(receipt["exit_code"], result["exit_code"]);
                assert_eq!(receipt["stop_reason"], result["stop_reason"]);
                assert_eq!(receipt["transport_authenticated"], true);
                assert_eq!(receipt["worker_spki_sha256"], pin);
                assert_eq!(receipt["authenticated_session_id"], session);
                assert_eq!(receipt["publication_authorized"], false);
                assert_eq!(fs::read(destination.join("diagnostics/stdout")).unwrap(), stdout);
                assert_eq!(fs::read(destination.join("diagnostics/stderr")).unwrap(), stderr);
                let output = query["kind"] == "output-ack";
                if output { assert_eq!(query["stdout_sha256"], hash(&stdout)); assert_eq!(query["stderr_sha256"], hash(stderr)); }
                else { assert_eq!(query["manifest_sha256"], MANIFEST); }
                send(stream, &json!({"kind":if output {"output-acknowledged"} else {"artifact-acknowledged"},
                    "request_id":7, "already_released":false})).await;
                if cancelled || !output { return; }
            }
            _ => panic!("no cancellation retry, second execution or other request is permitted: {query}"),
        }
    }
}

fn exchange(future: impl std::future::Future<Output = ()>) {
    RuntimeBuilder::current_thread().build().unwrap().block_on(async {
        asupersync::time::timeout(asupersync::time::wall_now(), Duration::from_secs(20), future)
            .await.expect("native TLS signal exchange timed out");
    });
}

#[test]
fn sigint_and_sigterm_cancel_once_deliver_full_diagnostics_and_recover_offline() {
    let certificates = Certificates::new(); let pin = certificates.pin();
    for signal in ["INT", "TERM"] {
        let root = tempfile::tempdir().unwrap(); let destination = root.path().join("delivery");
        let mut receiver = Receiver::spawn(root.path(), Some(&certificates.server), &pin, &destination, false);
        let address = receiver.listening();
        exchange(async {
            let mut peer = connect_peer(&address, "localhost", &certificates.worker).await.unwrap();
            let session = authenticate(&mut peer.stream, &pin, false).await;
            receiver.signal(signal);
            cancellation(&mut peer.stream).await;
            send(&mut peer.stream, &accepted()).await;
            assert!(receiver.child.try_wait().unwrap().is_none());
            assert!(!destination.join("delivery.json").exists(), "cancel acceptance is not a terminal delivery");
            finish(&mut peer.stream, &destination, &pin, session, true, None).await;
        });
        assert_eq!(receiver.wait().code(), Some(130), "{:?}", receiver.messages());
        let report: Value = serde_json::from_slice(&log(&receiver.stdout)).unwrap();
        assert_eq!(report["acknowledgments_confirmed"], true);
        assert_eq!(report["reexecute"], false);
        assert_eq!(fs::read_dir(destination.join("artifacts")).unwrap().count(), 0);
        let before = fs::read(destination.join("delivery.json")).unwrap();
        let request_before = fs::read(root.path().join("request.json")).unwrap();
        drop(receiver);
        let mut recovered = Receiver::spawn(root.path(), None, &pin, &destination, false);
        assert_eq!(recovered.wait().code(), Some(130));
        assert!(!recovered.messages().iter().any(|value| value["kind"] == "worker-exec-listening"));
        assert_eq!(fs::read(destination.join("delivery.json")).unwrap(), before);
        assert_eq!(fs::read(root.path().join("request.json")).unwrap(), request_before);
    }
}

#[test]
fn completed_result_wins_cancel_race_without_losing_artifacts_or_original_exit_status() {
    let certificates = Certificates::new(); let pin = certificates.pin();
    for late in [accepted(), json!({"kind":"error", "request_id":7, "reason":"unknown-request"})] {
        let root = tempfile::tempdir().unwrap(); let destination = root.path().join("delivery");
        let mut receiver = Receiver::spawn(root.path(), Some(&certificates.server), &pin, &destination, false);
        let address = receiver.listening();
        exchange(async {
            let mut peer = connect_peer(&address, "localhost", &certificates.worker).await.unwrap();
            let session = authenticate(&mut peer.stream, &pin, false).await;
            receiver.signal("INT");
            cancellation(&mut peer.stream).await;
            // The completion existed before cancellation was processed. Its
            // frame precedes the control reply, as the actual worker permits.
            finish(&mut peer.stream, &destination, &pin, session, false, Some(late)).await;
        });
        assert!(receiver.wait().success(), "{:?}", receiver.messages());
        assert_eq!(fs::read(destination.join("artifacts/a")).unwrap(), ARTIFACT);
        let report: Value = serde_json::from_slice(&log(&receiver.stdout)).unwrap();
        assert_eq!(report["receipt"]["exit_code"], 0);
        assert!(report["receipt"]["stop_reason"].is_null());
        assert_eq!(report["acknowledgments_confirmed"], true);
    }
}

#[test]
fn interrupted_admission_and_result_resume_never_gain_execution_or_cancel_authority() {
    let certificates = Certificates::new(); let pin = certificates.pin();
    for resume in [false, true] {
        let root = tempfile::tempdir().unwrap(); let destination = root.path().join("delivery");
        let mut receiver = Receiver::spawn(root.path(), Some(&certificates.server), &pin, &destination, resume);
        let address = receiver.listening();
        exchange(async {
            let mut peer = connect_peer(&address, "localhost", &certificates.worker).await.unwrap();
            if resume { authenticate(&mut peer.stream, &pin, true).await; }
            else { challenge(&mut peer.stream, &pin, false).await; }
            receiver.signal("TERM");
            assert!(receive(&mut peer.stream).await.is_err(), "interruption must close, not grant/cancel/execute");
        });
        assert!(!receiver.wait().success());
        let failure = receiver.failure();
        assert_eq!(failure["execution_may_have_run"], resume);
        assert_eq!(failure["reexecute"], false);
        assert!(!destination.join("delivery.json").exists());
    }
}

#[test]
fn second_interrupt_abandons_without_acknowledging_or_repeating_the_cancel() {
    let certificates = Certificates::new(); let pin = certificates.pin();
    let root = tempfile::tempdir().unwrap(); let destination = root.path().join("delivery");
    let mut receiver = Receiver::spawn(root.path(), Some(&certificates.server), &pin, &destination, false);
    let address = receiver.listening();
    exchange(async {
        let mut peer = connect_peer(&address, "localhost", &certificates.worker).await.unwrap();
        authenticate(&mut peer.stream, &pin, false).await;
        receiver.signal("INT"); cancellation(&mut peer.stream).await;
        send(&mut peer.stream, &accepted()).await;
        receiver.signal("TERM");
        assert!(receive(&mut peer.stream).await.is_err(), "no ACK, second cancel or execution may be emitted");
    });
    assert!(!receiver.wait().success());
    let failure = receiver.failure();
    assert_eq!(failure["execution_may_have_run"], true);
    assert_eq!(failure["reexecute"], false);
    assert!(!destination.join("delivery.json").exists());
}

#[test]
fn authenticated_but_foreign_cancel_ack_cannot_substitute_for_execution_completion() {
    let certificates = Certificates::new(); let pin = certificates.pin();
    let root = tempfile::tempdir().unwrap(); let destination = root.path().join("delivery");
    let mut receiver = Receiver::spawn(root.path(), Some(&certificates.server), &pin, &destination, false);
    let address = receiver.listening();
    exchange(async {
        let mut peer = connect_peer(&address, "localhost", &certificates.worker).await.unwrap();
        authenticate(&mut peer.stream, &pin, false).await;
        receiver.signal("INT"); cancellation(&mut peer.stream).await;
        let mut reply = accepted(); reply["request_id"] = json!(8);
        send(&mut peer.stream, &reply).await;
        assert!(receive(&mut peer.stream).await.is_err());
    });
    assert!(!receiver.wait().success());
    assert_eq!(receiver.failure()["execution_may_have_run"], true);
    assert!(!destination.join("delivery.json").exists());
    assert_eq!(fs::read_dir(destination.join("diagnostics")).unwrap().count(), 0);
}
