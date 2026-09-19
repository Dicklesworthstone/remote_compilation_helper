//! Actual rabsd operator process and native mutually authenticated ATP peer.
//!
//! The peer is scripted: these tests prove TLS/admission/verified delivery and
//! refusal boundaries, NOT that a compiler ran or that a fleet was qualified.
//! Certificates are generated in a temporary fixture; no private key is stored
//! in the repository. OpenSSL is required rather than silently skipping security.
#![cfg(unix)]

use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::runtime::RuntimeBuilder;
use rabs_asupersync::worker_transport::{SecureWorkerStream, TlsFiles, connect_peer};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const MANIFEST: &str = "548324c3a5c96511944c6ec6af94ee9bbb6683170bb0143f9d99cd192f80bfd6";
const ARTIFACT: &[u8] = b"A\0\xffB";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn hash(bytes: &[u8]) -> String { hex(&Sha256::digest(bytes)) }

fn openssl(root: &Path, args: &[&str]) {
    let output = Command::new("openssl").current_dir(root).args(args).output()
        .expect("OpenSSL is required for the real TLS integration tests");
    assert!(output.status.success(), "openssl {args:?}: {}", String::from_utf8_lossy(&output.stderr));
}

struct Certificates {
    _root: tempfile::TempDir,
    server: TlsFiles,
    worker: TlsFiles,
}
impl Certificates {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        openssl(root.path(), &[
            "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "1",
            "-subj", "/CN=RABS test CA", "-keyout", "ca.key", "-out", "ca.pem",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        ]);
        for (name, usage, serial) in [("server", "serverAuth", "2"), ("worker", "clientAuth", "3")] {
            let key = format!("{name}.key");
            let csr = format!("{name}.csr");
            let pem = format!("{name}.pem");
            let extensions = format!("{name}.ext");
            openssl(root.path(), &[
                "req", "-new", "-newkey", "rsa:2048", "-nodes", "-sha256", "-subj", "/CN=localhost",
                "-keyout", &key, "-out", &csr,
            ]);
            fs::write(root.path().join(&extensions), format!(
                "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage={usage}\nsubjectAltName=DNS:localhost\n"
            )).unwrap();
            openssl(root.path(), &[
                "x509", "-req", "-in", &csr, "-CA", "ca.pem", "-CAkey", "ca.key",
                "-set_serial", serial, "-days", "1", "-sha256", "-extfile", &extensions, "-out", &pem,
            ]);
        }
        let files = |name: &str| TlsFiles {
            ca: root.path().join("ca.pem"),
            certificate: root.path().join(format!("{name}.pem")),
            private_key: root.path().join(format!("{name}.key")),
        };
        Self { server: files("server"), worker: files("worker"), _root: root }
    }
    fn pin(&self) -> String { hex(&self.worker.local_identity().unwrap().fingerprint) }
}

/// Every failure path kills and reaps the receiver. Log files avoid blocked
/// stdout/stderr pipes and readiness polling has a real, bounded deadline.
struct Receiver {
    child: Child,
    stdout: PathBuf,
    stderr: PathBuf,
}
impl Receiver {
    fn spawn(root: &Path, pin: &str, tls: Option<&TlsFiles>, destination: &Path) -> Self {
        let request_path = root.join("request.json");
        fs::write(&request_path, request().to_string()).unwrap();
        let stdout = root.join("receiver.stdout");
        let stderr = root.join("receiver.stderr");
        let mut command = Command::new(env!("CARGO_BIN_EXE_rabsd"));
        command.args(["--worker-exec-tls", "127.0.0.1:0", "worker", pin])
            .arg(&request_path).arg(destination)
            .env_remove("RABS_COORD_TLS_CA").env_remove("RABS_COORD_TLS_CERT").env_remove("RABS_COORD_TLS_KEY")
            .stdout(Stdio::from(File::create(&stdout).unwrap()))
            .stderr(Stdio::from(File::create(&stderr).unwrap()));
        if let Some(tls) = tls {
            command.env("RABS_COORD_TLS_CA", &tls.ca)
                .env("RABS_COORD_TLS_CERT", &tls.certificate).env("RABS_COORD_TLS_KEY", &tls.private_key);
        }
        Self { child: command.spawn().unwrap(), stdout, stderr }
    }
    fn listening(&mut self) -> String {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            for line in fs::read_to_string(&self.stderr).unwrap().lines() {
                if let Ok(value) = serde_json::from_str::<Value>(line)
                    && value["kind"] == "worker-exec-listening"
                {
                    assert_eq!(value["transport"], "mutual-tls-atp");
                    assert_eq!(value["authentication_required"], true);
                    return value["address"].as_str().unwrap().to_owned();
                }
            }
            assert!(self.child.try_wait().unwrap().is_none(), "receiver exited: {}", self.logs());
            assert!(Instant::now() < deadline, "receiver readiness timed out: {}", self.logs());
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    fn wait(&mut self) -> ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() { return status; }
            assert!(Instant::now() < deadline, "receiver exit timed out: {}", self.logs());
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    fn logs(&self) -> String { fs::read_to_string(&self.stderr).unwrap() }
    fn failure(&self) -> Value {
        self.logs().lines().filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .find(|value| value["kind"] == "worker-delivery-error").expect("typed delivery error")
    }
}
impl Drop for Receiver {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn request() -> Value {
    json!({"kind":"canonical-exec", "request_id":7, "program":"rustc", "args":["lib.rs"],
        "toolchain_backing":"/tc", "workspace_backing":"/ws", "timeout_ms":1000,
        "artifacts":{"unit":"dep", "files":["a"]}})
}
fn hello(pin: &str) -> Value {
    json!({"kind":"worker-hello", "worker_id":"worker", "peer_id":pin,
        "canonical":true, "slots":4, "boot_generation":1,
        "incarnation":"00000000000000000000000000000001", "request_high_water":null,
        "transport":{"minimum_compatible":1,"current":1},
        "application":{"minimum_compatible":1,"current":1},
        "recovery_protocols":["request-journal-v1"],
        "output_transfers":["ranges-v1"], "artifact_transfers":["files-v1"]})
}
async fn send(stream: &mut SecureWorkerStream, value: &Value) -> io::Result<()> {
    stream.write_all(format!("{value}\n").as_bytes()).await?;
    stream.flush().await
}
async fn receive(stream: &mut SecureWorkerStream) -> io::Result<Value> {
    let mut bytes = Vec::new();
    let mut byte = [0];
    loop {
        if stream.read(&mut byte).await? == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "receiver disconnected"));
        }
        if byte[0] == b'\n' { return serde_json::from_slice(&bytes).map_err(io::Error::from); }
        if bytes.len() == 1024 * 1024 { return Err(io::Error::other("unbounded server frame")); }
        bytes.push(byte[0]);
    }
}
async fn authenticate(stream: &mut SecureWorkerStream, pin: &str) -> u64 {
    send(stream, &hello(pin)).await.unwrap();
    let challenge = receive(stream).await.unwrap();
    assert_eq!(challenge["kind"], "session-challenge");
    assert_eq!(challenge["capability"], 3);
    assert_eq!(challenge["scope"], format!("canonical-probes:{pin}"));
    let session = challenge["session_id"].as_u64().unwrap();
    assert!(session > 0);
    send(stream, &json!({"kind":"worker-auth", "peer_id":pin, "session_id":session,
        "operation_id":challenge["operation_id"], "token_id":challenge["token_id"]})).await.unwrap();
    let grant = receive(stream).await.unwrap();
    assert_eq!(grant["kind"], "session-ok");
    assert_eq!(grant["session_id"], session);
    assert_eq!(grant["artifact_transfer"], "files-v1");
    assert_eq!(grant["output_transfer"], "ranges-v1");
    assert_eq!(grant["publication"], "disabled");
    assert_eq!(receive(stream).await.unwrap(), request(), "dispatch must preserve the entire request");
    session
}

async fn deliver(stream: &mut SecureWorkerStream, destination: &Path, pin: &str, session: u64, corrupt: bool) {
    // More than a range; includes NUL, invalid UTF-8 and all byte values.
    let stdout: Vec<u8> = (0..65_549).map(|index| (index % 256) as u8).collect();
    send(stream, &json!({"kind":"exec-result", "request_id":7, "executed":true, "exit_code":0,
        "residual_group_members":0, "stop_reason":null, "output_transfer":"ranges-v1", "output_ack_required":true,
        "stdout_bytes":stdout.len(), "stdout_sha256":hash(&stdout), "stderr_bytes":0, "stderr_sha256":hash(b""),
        "artifact_transfer":"files-v1", "artifact_ack_required":true, "artifact_manifest":{
            "unit":"dep", "files":[{"name":"a", "bytes":4, "sha256":hash(ARTIFACT), "executable":false}],
            "total_bytes":4, "manifest_sha256":MANIFEST}})).await.unwrap();
    let mut acknowledgments = 0;
    let mut stdout_ranges = 0;
    loop {
        let query = match receive(stream).await {
            Ok(query) => query,
            Err(_) if corrupt => {
                assert_eq!(acknowledgments, 0, "corruption must refuse before releasing either owner");
                assert!(!destination.join("delivery.json").exists());
                return;
            }
            Err(error) => panic!("receiver stopped before acceptance: {error}"),
        };
        assert_eq!(query["request_id"], 7);
        match query["kind"].as_str().unwrap() {
            "output-read" | "artifact-read" => {
                let artifact = query["kind"] == "artifact-read";
                let name = query[if artifact {"name"} else {"stream"}].as_str().unwrap();
                let bytes = match (artifact, name) {
                    (true, "a") => ARTIFACT,
                    (false, "stdout") => { stdout_ranges += 1; &stdout },
                    (false, "stderr") => &b""[..],
                    other => panic!("undeclared retrieval {other:?}"),
                };
                let offset = query["offset"].as_u64().unwrap() as usize;
                let maximum = query["max_bytes"].as_u64().unwrap() as usize;
                assert!((1..=65_536).contains(&maximum));
                let next = (offset + maximum).min(bytes.len());
                let mut part = bytes[offset..next].to_vec();
                if corrupt && artifact { part[0] ^= 1; }
                let mut chunk = json!({"kind":if artifact {"artifact-chunk"} else {"output-chunk"},
                    "request_id":7, "offset":offset, "next_offset":next, "total_bytes":bytes.len(),
                    "eof":next == bytes.len(), "data_hex":hex(&part), "chunk_sha256":hash(&part), "sha256":hash(bytes)});
                chunk[if artifact {"name"} else {"stream"}] = json!(name);
                if artifact {
                    chunk["executable"] = json!(false);
                    chunk["manifest_sha256"] = json!(MANIFEST);
                }
                send(stream, &chunk).await.unwrap();
            }
            "output-ack" | "artifact-ack" => {
                assert!(!corrupt, "receiver acknowledged corrupt data");
                assert_eq!(stdout_ranges, 2);
                let receipt: Value = serde_json::from_slice(&fs::read(destination.join("delivery.json")).unwrap()).unwrap();
                assert_eq!(receipt["transport_authenticated"], true);
                assert_eq!(receipt["worker_spki_sha256"], pin);
                assert_eq!(receipt["authenticated_session_id"], session);
                assert_eq!(receipt["publication_authorized"], false);
                assert_eq!(fs::read(destination.join("diagnostics/stdout")).unwrap(), stdout);
                assert_eq!(fs::read(destination.join("artifacts/a")).unwrap(), ARTIFACT);
                let output = query["kind"] == "output-ack";
                if output {
                    assert_eq!(query["stdout_bytes"], stdout.len());
                    assert_eq!(query["stdout_sha256"], hash(&stdout));
                } else {
                    assert_eq!(query["manifest_sha256"], MANIFEST);
                    assert_eq!(query["total_bytes"], 4);
                }
                send(stream, &json!({"kind":if output {"output-acknowledged"} else {"artifact-acknowledged"},
                    "request_id":7, "already_released":false})).await.unwrap();
                acknowledgments += 1;
                if acknowledgments == 2 { return; }
            }
            other => panic!("unexpected command (no second execution is allowed): {other}"),
        }
    }
}

#[test]
fn actual_receiver_authenticates_and_verifies_binary_delivery_before_both_acks() {
    let certificates = Certificates::new();
    let root = tempfile::tempdir().unwrap();
    let destination = root.path().join("delivery");
    let pin = certificates.pin();
    let mut receiver = Receiver::spawn(root.path(), &pin, Some(&certificates.server), &destination);
    let address = receiver.listening();
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    runtime.block_on(async {
        asupersync::time::timeout(asupersync::time::wall_now(), Duration::from_secs(15), async {
            let mut peer = connect_peer(&address, "localhost", &certificates.worker).await.unwrap();
            let session = authenticate(&mut peer.stream, &pin).await;
            deliver(&mut peer.stream, &destination, &pin, session, false).await;
        }).await.expect("authenticated exchange timed out");
    });
    assert!(receiver.wait().success(), "{}", receiver.logs());
    let reported: Value = serde_json::from_slice(&fs::read(&receiver.stdout).unwrap()).unwrap();
    assert_eq!(reported["acknowledgments_confirmed"], true);
    assert_eq!(reported["receipt"]["transport_authenticated"], true);
    assert_eq!(reported["reexecute"], false);
}

#[test]
fn valid_ca_peer_with_wrong_pinned_key_cannot_reach_application_admission() {
    let certificates = Certificates::new();
    let root = tempfile::tempdir().unwrap();
    let destination = root.path().join("delivery");
    let pin = certificates.pin();
    let wrong = if pin == "01".repeat(32) { "02".repeat(32) } else { "01".repeat(32) };
    let mut receiver = Receiver::spawn(root.path(), &wrong, Some(&certificates.server), &destination);
    let address = receiver.listening();
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    runtime.block_on(async {
        asupersync::time::timeout(asupersync::time::wall_now(), Duration::from_secs(15), async {
            let mut peer = connect_peer(&address, "localhost", &certificates.worker).await.unwrap();
            // TLS trusts this CA, but application enrollment must still refuse.
            let _ = send(&mut peer.stream, &hello(&pin)).await;
            assert!(receive(&mut peer.stream).await.is_err(), "wrong key received an application grant");
        }).await.expect("wrong-pin refusal timed out");
    });
    assert!(!receiver.wait().success());
    assert_eq!(receiver.failure()["execution_may_have_run"], false);
    assert!(!destination.exists());
    assert!(receiver.logs().contains("configured SPKI pin"));
}

#[test]
fn authenticated_corrupt_artifact_is_not_accepted_even_with_matching_chunk_hash() {
    let certificates = Certificates::new();
    let root = tempfile::tempdir().unwrap();
    let destination = root.path().join("delivery");
    let pin = certificates.pin();
    let mut receiver = Receiver::spawn(root.path(), &pin, Some(&certificates.server), &destination);
    let address = receiver.listening();
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    runtime.block_on(async {
        asupersync::time::timeout(asupersync::time::wall_now(), Duration::from_secs(15), async {
            let mut peer = connect_peer(&address, "localhost", &certificates.worker).await.unwrap();
            let session = authenticate(&mut peer.stream, &pin).await;
            deliver(&mut peer.stream, &destination, &pin, session, true).await;
        }).await.expect("corrupt transfer refusal timed out");
    });
    assert!(!receiver.wait().success());
    assert_eq!(receiver.failure()["execution_may_have_run"], true);
    assert!(receiver.logs().contains("complete file digest mismatch"));
    assert!(!destination.join("delivery.json").exists());
}

#[test]
fn missing_tls_configuration_never_starts_a_plaintext_listener() {
    let root = tempfile::tempdir().unwrap();
    let destination = root.path().join("delivery");
    let mut receiver = Receiver::spawn(root.path(), &"01".repeat(32), None, &destination);
    assert!(!receiver.wait().success());
    assert!(receiver.logs().contains("missing RABS_COORD_TLS_CA"));
    assert!(!receiver.logs().contains("worker-exec-listening"));
    assert_eq!(receiver.failure()["execution_may_have_run"], false);
    assert!(!destination.exists());
}

#[test]
fn existing_delivery_is_untouched_before_any_network_or_credential_operation() {
    let root = tempfile::tempdir().unwrap();
    let destination = root.path().join("delivery");
    fs::create_dir(&destination).unwrap();
    fs::write(destination.join("sentinel"), b"keep").unwrap();
    let mut receiver = Receiver::spawn(root.path(), &"01".repeat(32), None, &destination);
    assert!(!receiver.wait().success());
    assert!(receiver.logs().contains("delivery directory already exists"));
    assert!(!receiver.logs().contains("worker-exec-listening"));
    assert_eq!(fs::read(destination.join("sentinel")).unwrap(), b"keep");
    assert_eq!(receiver.failure()["execution_may_have_run"], false);
}

#[test]
fn tls_listener_never_accepts_a_plaintext_worker_hello() {
    use std::io::Write;
    let certificates = Certificates::new();
    let root = tempfile::tempdir().unwrap();
    let destination = root.path().join("delivery");
    let mut receiver = Receiver::spawn(root.path(), &certificates.pin(), Some(&certificates.server), &destination);
    let address = receiver.listening();
    let mut plaintext = std::net::TcpStream::connect(&address).unwrap();
    plaintext.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
    // An immediate TLS rejection can close the socket during this write.
    let _ = plaintext.write_all(format!("{}\n", hello(&certificates.pin())).as_bytes());
    assert!(!receiver.wait().success());
    assert_eq!(receiver.failure()["execution_may_have_run"], false);
    assert!(!destination.exists());
    assert!(!receiver.logs().contains("\"transport_authenticated\":false"));
}

#[test]
fn authenticated_peer_with_wrong_challenge_cannot_receive_execution() {
    let certificates = Certificates::new();
    let root = tempfile::tempdir().unwrap();
    let destination = root.path().join("delivery");
    let pin = certificates.pin();
    let mut receiver = Receiver::spawn(root.path(), &pin, Some(&certificates.server), &destination);
    let address = receiver.listening();
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    runtime.block_on(async {
        asupersync::time::timeout(asupersync::time::wall_now(), Duration::from_secs(15), async {
            let mut peer = connect_peer(&address, "localhost", &certificates.worker).await.unwrap();
            send(&mut peer.stream, &hello(&pin)).await.unwrap();
            let challenge = receive(&mut peer.stream).await.unwrap();
            assert_eq!(challenge["kind"], "session-challenge");
            send(&mut peer.stream, &json!({"kind":"worker-auth", "peer_id":pin,
                "session_id":challenge["session_id"], "operation_id":0,
                "token_id":challenge["token_id"]})).await.unwrap();
            assert!(receive(&mut peer.stream).await.is_err(), "bad challenge reached a grant or dispatch");
        }).await.expect("challenge refusal timed out");
    });
    assert!(!receiver.wait().success());
    assert_eq!(receiver.failure()["execution_may_have_run"], false);
    assert!(receiver.logs().contains("challenge response mismatch"));
    assert!(!destination.join("delivery.json").exists());
}
