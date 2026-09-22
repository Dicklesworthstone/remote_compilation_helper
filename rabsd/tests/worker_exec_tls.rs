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
use rabs_sandbox::source_transfer::{MAX_SOURCE_CHUNK, SOURCE_TRANSFER, SourceReceiver};
use rabsd::coord::source_delivery::{prepare_source_bundle, request_manifest};
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
fn hash(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn openssl(root: &Path, args: &[&str]) {
    let output = Command::new("openssl")
        .current_dir(root)
        .args(args)
        .output()
        .expect("OpenSSL is required for the real TLS integration tests");
    assert!(
        output.status.success(),
        "openssl {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

struct Certificates {
    _root: tempfile::TempDir,
    server: TlsFiles,
    worker: TlsFiles,
}
impl Certificates {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        openssl(
            root.path(),
            &[
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-sha256",
                "-days",
                "1",
                "-subj",
                "/CN=RABS test CA",
                "-keyout",
                "ca.key",
                "-out",
                "ca.pem",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
            ],
        );
        for (name, usage, serial) in [("server", "serverAuth", "2"), ("worker", "clientAuth", "3")]
        {
            let key = format!("{name}.key");
            let csr = format!("{name}.csr");
            let pem = format!("{name}.pem");
            let extensions = format!("{name}.ext");
            openssl(
                root.path(),
                &[
                    "req",
                    "-new",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-sha256",
                    "-subj",
                    "/CN=localhost",
                    "-keyout",
                    &key,
                    "-out",
                    &csr,
                ],
            );
            fs::write(root.path().join(&extensions), format!(
                "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage={usage}\nsubjectAltName=DNS:localhost\n"
            )).unwrap();
            openssl(
                root.path(),
                &[
                    "x509",
                    "-req",
                    "-in",
                    &csr,
                    "-CA",
                    "ca.pem",
                    "-CAkey",
                    "ca.key",
                    "-set_serial",
                    serial,
                    "-days",
                    "1",
                    "-sha256",
                    "-extfile",
                    &extensions,
                    "-out",
                    &pem,
                ],
            );
        }
        let files = |name: &str| TlsFiles {
            ca: root.path().join("ca.pem"),
            certificate: root.path().join(format!("{name}.pem")),
            private_key: root.path().join(format!("{name}.key")),
        };
        Self {
            server: files("server"),
            worker: files("worker"),
            _root: root,
        }
    }
    fn pin(&self) -> String {
        hex(&self.worker.local_identity().unwrap().fingerprint)
    }
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
        Self::spawn_mode(root, pin, tls, destination, false)
    }
    fn spawn_mode(
        root: &Path,
        pin: &str,
        tls: Option<&TlsFiles>,
        destination: &Path,
        resume: bool,
    ) -> Self {
        Self::spawn_operation(root, pin, tls, destination, resume.then_some("--resume"))
    }
    fn spawn_operation(
        root: &Path,
        pin: &str,
        tls: Option<&TlsFiles>,
        destination: &Path,
        flag: Option<&str>,
    ) -> Self {
        let request_path = root.join("request.json");
        fs::write(&request_path, request().to_string()).unwrap();
        let stdout = root.join("receiver.stdout");
        let stderr = root.join("receiver.stderr");
        let mut command = Command::new(env!("CARGO_BIN_EXE_rabsd"));
        command
            .args(["--worker-exec-tls", "127.0.0.1:0", "worker", pin])
            .arg(&request_path)
            .arg(destination)
            .env("RABS_STATE_DIR", root.join("state"))
            .env_remove("RABS_COORD_TLS_CA")
            .env_remove("RABS_COORD_TLS_CERT")
            .env_remove("RABS_COORD_TLS_KEY")
            .stdout(Stdio::from(File::create(&stdout).unwrap()))
            .stderr(Stdio::from(File::create(&stderr).unwrap()));
        if let Some(flag) = flag {
            command.arg(flag);
        }
        if let Some(tls) = tls {
            command
                .env("RABS_COORD_TLS_CA", &tls.ca)
                .env("RABS_COORD_TLS_CERT", &tls.certificate)
                .env("RABS_COORD_TLS_KEY", &tls.private_key);
        }
        Self {
            child: command.spawn().unwrap(),
            stdout,
            stderr,
        }
    }
    fn spawn_build(
        root: &Path,
        pin: &str,
        tls: Option<&TlsFiles>,
        bundle: &Path,
        destination: &Path,
        outputs: &Path,
        resume: bool,
    ) -> Self {
        let stdout = root.join("build.stdout");
        let stderr = root.join("build.stderr");
        let mut command = Command::new(env!("CARGO_BIN_EXE_rabsd"));
        command.arg("--worker-build-tls");
        if resume {
            command.arg("--resume");
        }
        command
            .args(["127.0.0.1:0", "worker", pin])
            .arg(bundle)
            .arg(destination)
            .arg(outputs)
            .env("RABS_STATE_DIR", root.join("state"))
            .env_remove("RABS_COORD_TLS_CA")
            .env_remove("RABS_COORD_TLS_CERT")
            .env_remove("RABS_COORD_TLS_KEY")
            .stdout(Stdio::from(File::create(&stdout).unwrap()))
            .stderr(Stdio::from(File::create(&stderr).unwrap()));
        if let Some(tls) = tls {
            command
                .env("RABS_COORD_TLS_CA", &tls.ca)
                .env("RABS_COORD_TLS_CERT", &tls.certificate)
                .env("RABS_COORD_TLS_KEY", &tls.private_key);
        }
        Self {
            child: command.spawn().unwrap(),
            stdout,
            stderr,
        }
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
            assert!(
                self.child.try_wait().unwrap().is_none(),
                "receiver exited: {}",
                self.logs()
            );
            assert!(
                Instant::now() < deadline,
                "receiver readiness timed out: {}",
                self.logs()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    fn wait(&mut self) -> ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "receiver exit timed out: {}",
                self.logs()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    fn logs(&self) -> String {
        fs::read_to_string(&self.stderr).unwrap()
    }
    fn failure(&self) -> Value {
        self.logs()
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .find(|value| value["kind"] == "worker-delivery-error")
            .expect("typed delivery error")
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
fn recovery_hello(pin: &str) -> Value {
    let mut hello = hello(pin);
    hello["boot_generation"] = json!(2);
    hello["incarnation"] = json!("00000000000000000000000000000002");
    hello["request_high_water"] = json!(7);
    hello["result_retentions"] = json!(["durable-result-v1"]);
    hello
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
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "receiver disconnected",
            ));
        }
        if byte[0] == b'\n' {
            return serde_json::from_slice(&bytes).map_err(io::Error::from);
        }
        if bytes.len() == 1024 * 1024 {
            return Err(io::Error::other("unbounded server frame"));
        }
        bytes.push(byte[0]);
    }
}
async fn authenticate(stream: &mut SecureWorkerStream, pin: &str) -> u64 {
    authenticate_mode(stream, pin, false).await
}
async fn authenticate_mode(stream: &mut SecureWorkerStream, pin: &str, resume: bool) -> u64 {
    let hello = if resume {
        recovery_hello(pin)
    } else {
        hello(pin)
    };
    authenticate_offer(stream, pin, &hello, resume).await
}
async fn authenticate_offer(
    stream: &mut SecureWorkerStream,
    pin: &str,
    hello: &Value,
    resume: bool,
) -> u64 {
    let (session, grant) = authenticate_grant(stream, pin, hello).await;
    let expected = if resume {
        assert_eq!(grant["result_retention"], "durable-result-v1");
        json!({"kind":"result-resume", "request_id":7, "request":request()})
    } else {
        request()
    };
    assert_eq!(
        receive(stream).await.unwrap(),
        expected,
        "dispatch must preserve the entire selected operation"
    );
    session
}

async fn authenticate_grant(
    stream: &mut SecureWorkerStream,
    pin: &str,
    hello: &Value,
) -> (u64, Value) {
    send(stream, hello).await.unwrap();
    let challenge = receive(stream).await.unwrap();
    assert_eq!(challenge["kind"], "session-challenge");
    assert_eq!(challenge["capability"], 3);
    assert_eq!(challenge["scope"], format!("canonical-probes:{pin}"));
    let session = challenge["session_id"].as_u64().unwrap();
    assert!(session > 0);
    send(
        stream,
        &json!({"kind":"worker-auth", "peer_id":pin, "session_id":session,
        "operation_id":challenge["operation_id"], "token_id":challenge["token_id"]}),
    )
    .await
    .unwrap();
    let grant = receive(stream).await.unwrap();
    assert_eq!(grant["kind"], "session-ok");
    assert_eq!(grant["session_id"], session);
    assert_eq!(grant["artifact_transfer"], "files-v1");
    assert_eq!(grant["output_transfer"], "ranges-v1");
    assert_eq!(grant["publication"], "disabled");
    (session, grant)
}

async fn deliver(
    stream: &mut SecureWorkerStream,
    destination: &Path,
    pin: &str,
    session: u64,
    corrupt: bool,
) {
    deliver_mode(stream, destination, pin, session, corrupt, false, false).await;
}
async fn deliver_mode(
    stream: &mut SecureWorkerStream,
    destination: &Path,
    pin: &str,
    session: u64,
    corrupt: bool,
    resumed: bool,
    lose_ack: bool,
) {
    // More than a range; includes NUL, invalid UTF-8 and all byte values.
    let stdout: Vec<u8> = (0..65_549).map(|index| (index % 256) as u8).collect();
    let mut result = json!({"kind":"exec-result", "request_id":7, "executed":true, "exit_code":0,
        "residual_group_members":0, "stop_reason":null, "output_transfer":"ranges-v1", "output_ack_required":true,
        "stdout_bytes":stdout.len(), "stdout_sha256":hash(&stdout), "stderr_bytes":0, "stderr_sha256":hash(b""),
        "artifact_transfer":"files-v1", "artifact_ack_required":true, "artifact_manifest":{
            "unit":"dep", "files":[{"name":"a", "bytes":4, "sha256":hash(ARTIFACT), "executable":false}],
            "total_bytes":4, "manifest_sha256":MANIFEST}});
    if resumed {
        result["resumed"] = json!(true);
        result["result_retention"] = json!("durable-result-v1");
        result["retained_result_sha256"] = json!("07".repeat(32));
    }
    send(stream, &result).await.unwrap();
    let mut acknowledgments = 0;
    let mut stdout_ranges = 0;
    loop {
        let query = match receive(stream).await {
            Ok(query) => query,
            Err(_) if corrupt => {
                assert_eq!(
                    acknowledgments, 0,
                    "corruption must refuse before releasing either owner"
                );
                assert!(!destination.join("delivery.json").exists());
                return;
            }
            Err(error) => panic!("receiver stopped before acceptance: {error}"),
        };
        assert_eq!(query["request_id"], 7);
        match query["kind"].as_str().unwrap() {
            "output-read" | "artifact-read" => {
                let artifact = query["kind"] == "artifact-read";
                let name = query[if artifact { "name" } else { "stream" }]
                    .as_str()
                    .unwrap();
                let bytes = match (artifact, name) {
                    (true, "a") => ARTIFACT,
                    (false, "stdout") => {
                        stdout_ranges += 1;
                        &stdout
                    }
                    (false, "stderr") => &b""[..],
                    other => panic!("undeclared retrieval {other:?}"),
                };
                let offset = query["offset"].as_u64().unwrap() as usize;
                let maximum = query["max_bytes"].as_u64().unwrap() as usize;
                assert!((1..=65_536).contains(&maximum));
                let next = (offset + maximum).min(bytes.len());
                let mut part = bytes[offset..next].to_vec();
                if corrupt && artifact {
                    part[0] ^= 1;
                }
                let mut chunk = json!({"kind":if artifact {"artifact-chunk"} else {"output-chunk"},
                    "request_id":7, "offset":offset, "next_offset":next, "total_bytes":bytes.len(),
                    "eof":next == bytes.len(), "data_hex":hex(&part), "chunk_sha256":hash(&part), "sha256":hash(bytes)});
                chunk[if artifact { "name" } else { "stream" }] = json!(name);
                if artifact {
                    chunk["executable"] = json!(false);
                    chunk["manifest_sha256"] = json!(MANIFEST);
                }
                send(stream, &chunk).await.unwrap();
            }
            "output-ack" | "artifact-ack" => {
                assert!(!corrupt, "receiver acknowledged corrupt data");
                assert_eq!(stdout_ranges, 2);
                let receipt: Value =
                    serde_json::from_slice(&fs::read(destination.join("delivery.json")).unwrap())
                        .unwrap();
                assert_eq!(receipt["transport_authenticated"], true);
                assert_eq!(receipt["worker_spki_sha256"], pin);
                assert_eq!(receipt["authenticated_session_id"], session);
                assert_eq!(receipt["publication_authorized"], false);
                if resumed {
                    assert_eq!(receipt["resumed"], true);
                    assert_eq!(receipt["worker_identity_scope"], "delivery-session");
                    assert!(receipt["execution_boot_generation"].is_null());
                }
                assert_eq!(
                    fs::read(destination.join("diagnostics/stdout")).unwrap(),
                    stdout
                );
                assert_eq!(fs::read(destination.join("artifacts/a")).unwrap(), ARTIFACT);
                let output = query["kind"] == "output-ack";
                if output {
                    assert_eq!(query["stdout_bytes"], stdout.len());
                    assert_eq!(query["stdout_sha256"], hash(&stdout));
                } else {
                    assert_eq!(query["manifest_sha256"], MANIFEST);
                    assert_eq!(query["total_bytes"], 4);
                    if lose_ack {
                        return;
                    } // peer drops after the local durability frontier
                }
                send(
                    stream,
                    &json!({"kind":if output {"output-acknowledged"} else {"artifact-acknowledged"},
                    "request_id":7, "already_released":false}),
                )
                .await
                .unwrap();
                acknowledgments += 1;
                if acknowledgments == 2 {
                    return;
                }
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
        asupersync::time::timeout(
            asupersync::time::wall_now(),
            Duration::from_secs(15),
            async {
                let mut peer = connect_peer(&address, "localhost", &certificates.worker)
                    .await
                    .unwrap();
                let session = authenticate(&mut peer.stream, &pin).await;
                deliver(&mut peer.stream, &destination, &pin, session, false).await;
            },
        )
        .await
        .expect("authenticated exchange timed out");
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
    let wrong = if pin == "01".repeat(32) {
        "02".repeat(32)
    } else {
        "01".repeat(32)
    };
    let mut receiver = Receiver::spawn(
        root.path(),
        &wrong,
        Some(&certificates.server),
        &destination,
    );
    let address = receiver.listening();
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    runtime.block_on(async {
        asupersync::time::timeout(
            asupersync::time::wall_now(),
            Duration::from_secs(15),
            async {
                let mut peer = connect_peer(&address, "localhost", &certificates.worker)
                    .await
                    .unwrap();
                // TLS trusts this CA, but application enrollment must still refuse.
                let _ = send(&mut peer.stream, &hello(&pin)).await;
                assert!(
                    receive(&mut peer.stream).await.is_err(),
                    "wrong key received an application grant"
                );
            },
        )
        .await
        .expect("wrong-pin refusal timed out");
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
        asupersync::time::timeout(
            asupersync::time::wall_now(),
            Duration::from_secs(15),
            async {
                let mut peer = connect_peer(&address, "localhost", &certificates.worker)
                    .await
                    .unwrap();
                let session = authenticate(&mut peer.stream, &pin).await;
                deliver(&mut peer.stream, &destination, &pin, session, true).await;
            },
        )
        .await
        .expect("corrupt transfer refusal timed out");
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
    assert!(
        receiver
            .logs()
            .contains("retained delivery cannot be replayed")
    );
    assert!(!receiver.logs().contains("worker-exec-listening"));
    assert_eq!(fs::read(destination.join("sentinel")).unwrap(), b"keep");
    // Existing partial state is uncertain, not evidence the original never ran.
    assert_eq!(receiver.failure()["execution_may_have_run"], true);
}

#[test]
fn tls_listener_never_accepts_a_plaintext_worker_hello() {
    use std::io::Write;
    let certificates = Certificates::new();
    let root = tempfile::tempdir().unwrap();
    let destination = root.path().join("delivery");
    let mut receiver = Receiver::spawn(
        root.path(),
        &certificates.pin(),
        Some(&certificates.server),
        &destination,
    );
    let address = receiver.listening();
    let mut plaintext = std::net::TcpStream::connect(&address).unwrap();
    plaintext
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    // An immediate TLS rejection can close the socket during this write.
    let _ = plaintext.write_all(format!("{}\n", hello(&certificates.pin())).as_bytes());
    assert!(!receiver.wait().success());
    assert_eq!(receiver.failure()["execution_may_have_run"], false);
    assert!(!destination.exists());
    assert!(
        !receiver
            .logs()
            .contains("\"transport_authenticated\":false")
    );
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
        asupersync::time::timeout(
            asupersync::time::wall_now(),
            Duration::from_secs(15),
            async {
                let mut peer = connect_peer(&address, "localhost", &certificates.worker)
                    .await
                    .unwrap();
                send(&mut peer.stream, &hello(&pin)).await.unwrap();
                let challenge = receive(&mut peer.stream).await.unwrap();
                assert_eq!(challenge["kind"], "session-challenge");
                send(
                    &mut peer.stream,
                    &json!({"kind":"worker-auth", "peer_id":pin,
                "session_id":challenge["session_id"], "operation_id":0,
                "token_id":challenge["token_id"]}),
                )
                .await
                .unwrap();
                assert!(
                    receive(&mut peer.stream).await.is_err(),
                    "bad challenge reached a grant or dispatch"
                );
            },
        )
        .await
        .expect("challenge refusal timed out");
    });
    assert!(!receiver.wait().success());
    assert_eq!(receiver.failure()["execution_may_have_run"], false);
    assert!(receiver.logs().contains("challenge response mismatch"));
    assert!(!destination.join("delivery.json").exists());
}

#[test]
fn actual_receiver_resumes_binary_outputs_and_replays_locally_after_ack_loss() {
    let certificates = Certificates::new();
    let pin = certificates.pin();
    for lose_ack in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let destination = root.path().join("recovered");
        let partial = root.path().join("previous-partial");
        fs::create_dir(&partial).unwrap();
        fs::write(partial.join("sentinel"), b"untrusted old bytes").unwrap();
        let mut receiver = Receiver::spawn_mode(
            root.path(),
            &pin,
            Some(&certificates.server),
            &destination,
            true,
        );
        let address = receiver.listening();
        let runtime = RuntimeBuilder::current_thread().build().unwrap();
        runtime.block_on(async {
            asupersync::time::timeout(
                asupersync::time::wall_now(),
                Duration::from_secs(15),
                async {
                    let mut peer = connect_peer(&address, "localhost", &certificates.worker)
                        .await
                        .unwrap();
                    let session = authenticate_mode(&mut peer.stream, &pin, true).await;
                    deliver_mode(
                        &mut peer.stream,
                        &destination,
                        &pin,
                        session,
                        false,
                        true,
                        lose_ack,
                    )
                    .await;
                },
            )
            .await
            .expect("authenticated resume timed out");
        });
        assert!(receiver.wait().success(), "{}", receiver.logs());
        let reported: Value = serde_json::from_slice(&fs::read(&receiver.stdout).unwrap()).unwrap();
        assert_eq!(reported["acknowledgments_confirmed"], !lose_ack);
        assert_eq!(reported["receipt"]["resumed"], true);
        assert_eq!(reported["receipt"]["transport_authenticated"], true);
        assert_eq!(reported["receipt"]["boot_generation"], 2);
        assert_eq!(reported["reexecute"], false);
        assert_eq!(
            fs::read(partial.join("sentinel")).unwrap(),
            b"untrusted old bytes"
        );
        let receipt = fs::read(destination.join("delivery.json")).unwrap();
        drop(receiver);
        // The complete result must be recoverable without a worker, credentials
        // or another TLS handshake, even if the remote final acknowledgment died.
        let mut offline = Receiver::spawn_mode(root.path(), &pin, None, &destination, true);
        assert!(offline.wait().success(), "{}", offline.logs());
        assert!(!offline.logs().contains("worker-exec-listening"));
        let replay: Value = serde_json::from_slice(&fs::read(&offline.stdout).unwrap()).unwrap();
        assert_eq!(replay["receipt"], reported["receipt"]);
        assert_eq!(replay["reexecute"], false);
        assert_eq!(
            fs::read(destination.join("delivery.json")).unwrap(),
            receipt
        );
    }
}

#[test]
fn unavailable_retained_result_is_not_reexecuted_by_actual_tls_operator() {
    let certificates = Certificates::new();
    let pin = certificates.pin();
    let root = tempfile::tempdir().unwrap();
    let destination = root.path().join("unavailable");
    let mut receiver = Receiver::spawn_mode(
        root.path(),
        &pin,
        Some(&certificates.server),
        &destination,
        true,
    );
    let address = receiver.listening();
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    runtime.block_on(async {
        asupersync::time::timeout(
            asupersync::time::wall_now(),
            Duration::from_secs(15),
            async {
                let mut peer = connect_peer(&address, "localhost", &certificates.worker)
                    .await
                    .unwrap();
                authenticate_mode(&mut peer.stream, &pin, true).await;
                send(
                    &mut peer.stream,
                    &json!({"kind":"error", "request_id":7, "error":"retained result unavailable"}),
                )
                .await
                .unwrap();
                assert!(
                    receive(&mut peer.stream).await.is_err(),
                    "resume failure caused another operation"
                );
            },
        )
        .await
        .expect("unavailable-result refusal timed out");
    });
    assert!(!receiver.wait().success());
    assert_eq!(receiver.failure()["execution_may_have_run"], true);
    assert_eq!(receiver.failure()["reexecute"], false);
    assert!(!destination.join("delivery.json").exists());
}

#[test]
fn resume_capability_high_water_and_pin_refusals_preserve_uncertainty() {
    let certificates = Certificates::new();
    let pin = certificates.pin();
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    for case in 0..4 {
        let root = tempfile::tempdir().unwrap();
        let destination = root.path().join("refused");
        let expected_pin = if case == 3 {
            if pin == "01".repeat(32) {
                "02".repeat(32)
            } else {
                "01".repeat(32)
            }
        } else {
            pin.clone()
        };
        let mut receiver = Receiver::spawn_mode(
            root.path(),
            &expected_pin,
            Some(&certificates.server),
            &destination,
            true,
        );
        let address = receiver.listening();
        runtime.block_on(async {
            asupersync::time::timeout(
                asupersync::time::wall_now(),
                Duration::from_secs(15),
                async {
                    let mut peer = connect_peer(&address, "localhost", &certificates.worker)
                        .await
                        .unwrap();
                    let mut hello = recovery_hello(&pin);
                    match case {
                        0 => hello["result_retentions"] = json!([]),
                        1 => hello["request_high_water"] = json!(6),
                        2 => hello["request_high_water"] = json!(8),
                        _ => {}
                    }
                    let _ = send(&mut peer.stream, &hello).await;
                    assert!(
                        receive(&mut peer.stream).await.is_err(),
                        "invalid recovery reached application admission"
                    );
                },
            )
            .await
            .expect("recovery admission refusal timed out");
        });
        assert!(!receiver.wait().success());
        assert_eq!(receiver.failure()["execution_may_have_run"], true);
        assert_eq!(receiver.failure()["reexecute"], false);
        assert!(!destination.exists());
    }
}

#[test]
fn resume_preconnect_errors_and_partial_directories_never_become_new_execution() {
    for case in 0..3 {
        let root = tempfile::tempdir().unwrap();
        let destination = root.path().join("refused");
        if case == 2 {
            fs::create_dir(&destination).unwrap();
            fs::write(destination.join("sentinel"), b"keep").unwrap();
        }
        let pin = if case == 1 {
            "invalid".to_owned()
        } else {
            "01".repeat(32)
        };
        let mut receiver = Receiver::spawn_mode(root.path(), &pin, None, &destination, true);
        assert!(!receiver.wait().success());
        assert!(!receiver.logs().contains("worker-exec-listening"));
        assert_eq!(receiver.failure()["execution_may_have_run"], true);
        assert_eq!(receiver.failure()["reexecute"], false);
        if case == 2 {
            assert_eq!(fs::read(destination.join("sentinel")).unwrap(), b"keep");
            assert_eq!(fs::read_dir(&destination).unwrap().count(), 1);
        } else {
            assert!(!destination.exists());
        }
    }
}

#[test]
fn resumed_artifact_corruption_keeps_old_partial_files_and_never_acknowledges() {
    let certificates = Certificates::new();
    let pin = certificates.pin();
    let root = tempfile::tempdir().unwrap();
    let destination = root.path().join("corrupt-resume");
    let mut receiver = Receiver::spawn_mode(
        root.path(),
        &pin,
        Some(&certificates.server),
        &destination,
        true,
    );
    let address = receiver.listening();
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    runtime.block_on(async {
        asupersync::time::timeout(
            asupersync::time::wall_now(),
            Duration::from_secs(15),
            async {
                let mut peer = connect_peer(&address, "localhost", &certificates.worker)
                    .await
                    .unwrap();
                let session = authenticate_mode(&mut peer.stream, &pin, true).await;
                deliver_mode(
                    &mut peer.stream,
                    &destination,
                    &pin,
                    session,
                    true,
                    true,
                    false,
                )
                .await;
            },
        )
        .await
        .expect("resumed corruption refusal timed out");
    });
    assert!(!receiver.wait().success());
    assert_eq!(receiver.failure()["execution_may_have_run"], true);
    assert!(receiver.logs().contains("complete file digest mismatch"));
    assert!(!destination.join("delivery.json").exists());
    let partial_bytes = fs::read(destination.join("artifacts/a")).unwrap();
    drop(receiver);
    let mut repeat = Receiver::spawn_mode(root.path(), &pin, None, &destination, true);
    assert!(!repeat.wait().success());
    assert!(!repeat.logs().contains("worker-exec-listening"));
    assert_eq!(
        fs::read(destination.join("artifacts/a")).unwrap(),
        partial_bytes
    );
    assert_eq!(repeat.failure()["reexecute"], false);
}

/// Establish local acceptance evidence through the actual TLS receiver, not by
/// writing a purported delivery receipt directly. Only the worker is scripted.
fn retained_delivery(certificates: &Certificates, root: &Path, destination: &Path) -> Value {
    let pin = certificates.pin();
    let mut receiver =
        Receiver::spawn_mode(root, &pin, Some(&certificates.server), destination, true);
    let address = receiver.listening();
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    runtime.block_on(async {
        asupersync::time::timeout(
            asupersync::time::wall_now(),
            Duration::from_secs(15),
            async {
                let mut peer = connect_peer(&address, "localhost", &certificates.worker)
                    .await
                    .unwrap();
                let session = authenticate_mode(&mut peer.stream, &pin, true).await;
                deliver_mode(
                    &mut peer.stream,
                    destination,
                    &pin,
                    session,
                    false,
                    true,
                    true,
                )
                .await;
            },
        )
        .await
        .expect("initial retained delivery timed out");
    });
    assert!(receiver.wait().success(), "{}", receiver.logs());
    let report: Value = serde_json::from_slice(&fs::read(&receiver.stdout).unwrap()).unwrap();
    assert_eq!(report["acknowledgments_confirmed"], false);
    assert_eq!(report["receipt"]["transport_authenticated"], true);
    report["receipt"].clone()
}

fn resumed_offer(receipt: &Value) -> Value {
    json!({"kind":"exec-result", "request_id":7, "executed":true,
        "exit_code":receipt["exit_code"], "stop_reason":receipt["stop_reason"],
        "residual_group_members":0, "resumed":true, "result_retention":"durable-result-v1",
        "retained_result_sha256":receipt["retained_result_sha256"],
        "output_transfer":"ranges-v1", "output_ack_required":true,
        "stdout_bytes":receipt["stdout_bytes"], "stdout_sha256":receipt["stdout_sha256"],
        "stderr_bytes":receipt["stderr_bytes"], "stderr_sha256":receipt["stderr_sha256"],
        "artifact_transfer":"files-v1", "artifact_ack_required":true,
        "artifact_manifest":receipt["artifact_manifest"]})
}

fn local_bytes_and_inodes(destination: &Path) -> Vec<(Vec<u8>, u64)> {
    use std::os::unix::fs::MetadataExt;
    assert_eq!(fs::read_dir(destination).unwrap().count(), 3);
    assert_eq!(
        fs::read_dir(destination.join("artifacts")).unwrap().count(),
        1
    );
    assert_eq!(
        fs::read_dir(destination.join("diagnostics"))
            .unwrap()
            .count(),
        2
    );
    [
        "delivery.json",
        "diagnostics/stdout",
        "diagnostics/stderr",
        "artifacts/a",
    ]
    .into_iter()
    .map(|name| {
        let path = destination.join(name);
        (fs::read(&path).unwrap(), fs::metadata(path).unwrap().ino())
    })
    .collect()
}

#[test]
fn actual_tls_acknowledgment_retries_lost_replies_without_ranges_or_local_replacement() {
    let certificates = Certificates::new();
    let pin = certificates.pin();
    let root = tempfile::tempdir().unwrap();
    let destination = root.path().join("delivery");
    let receipt = retained_delivery(&certificates, root.path(), &destination);
    let before = local_bytes_and_inodes(&destination);
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    for lose_again in [true, false] {
        let mut receiver = Receiver::spawn_operation(
            root.path(),
            &pin,
            Some(&certificates.server),
            &destination,
            Some("--acknowledge"),
        );
        let address = receiver.listening();
        assert!(receiver.logs().contains("result-acknowledgment"));
        runtime.block_on(async {
            asupersync::time::timeout(asupersync::time::wall_now(), Duration::from_secs(15), async {
                let mut peer = connect_peer(&address, "localhost", &certificates.worker).await.unwrap();
                authenticate_mode(&mut peer.stream, &pin, true).await;
                send(&mut peer.stream, &resumed_offer(&receipt)).await.unwrap();
                // Exact next-frame assertions reject any attempted range read,
                // source upload or second compiler dispatch, not just bad bytes.
                assert_eq!(receive(&mut peer.stream).await.unwrap(), json!({"kind":"output-ack", "request_id":7,
                    "stdout_bytes":receipt["stdout_bytes"], "stdout_sha256":receipt["stdout_sha256"],
                    "stderr_bytes":receipt["stderr_bytes"], "stderr_sha256":receipt["stderr_sha256"]}));
                send(&mut peer.stream, &json!({"kind":"output-acknowledged", "request_id":7,
                    "already_released":false})).await.unwrap();
                assert_eq!(receive(&mut peer.stream).await.unwrap(), json!({"kind":"artifact-ack", "request_id":7,
                    "manifest_sha256":MANIFEST, "total_bytes":ARTIFACT.len()}));
                if !lose_again {
                    send(&mut peer.stream, &json!({"kind":"artifact-acknowledged", "request_id":7,
                        "already_released":false})).await.unwrap();
                }
            }).await.expect("acknowledgment reconciliation timed out");
        });
        assert_eq!(
            receiver.wait().success(),
            !lose_again,
            "{}",
            receiver.logs()
        );
        if lose_again {
            assert!(fs::read(&receiver.stdout).unwrap().is_empty());
            assert_eq!(receiver.failure()["execution_may_have_run"], true);
            assert_eq!(receiver.failure()["reexecute"], false);
        } else {
            let report: Value =
                serde_json::from_slice(&fs::read(&receiver.stdout).unwrap()).unwrap();
            assert_eq!(report["acknowledgments_confirmed"], true);
            assert!(report["acknowledgment_error"].is_null());
            assert_eq!(
                report["receipt"], receipt,
                "recovery session cannot rewrite historical provenance"
            );
        }
        assert_eq!(local_bytes_and_inodes(&destination), before);
    }
}

#[test]
fn actual_tls_acknowledgment_confirms_only_the_exact_durably_released_result() {
    let certificates = Certificates::new();
    let pin = certificates.pin();
    let root = tempfile::tempdir().unwrap();
    let destination = root.path().join("delivery");
    let receipt = retained_delivery(&certificates, root.path(), &destination);
    let before = local_bytes_and_inodes(&destination);
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    for case in 0..4 {
        let mut receiver = Receiver::spawn_operation(
            root.path(),
            &pin,
            Some(&certificates.server),
            &destination,
            Some("--acknowledge"),
        );
        let address = receiver.listening();
        runtime.block_on(async {
            asupersync::time::timeout(asupersync::time::wall_now(), Duration::from_secs(15), async {
                let mut peer = connect_peer(&address, "localhost", &certificates.worker).await.unwrap();
                authenticate_mode(&mut peer.stream, &pin, true).await;
                send(&mut peer.stream, &json!({"kind":"error", "request_id":7,
                    "reason":"retained result does not match this request"})).await.unwrap();
                assert_eq!(receive(&mut peer.stream).await.unwrap(), json!({"kind":"request-status", "request_id":7}));
                // The worker's bounded journal receipt intentionally lacks the
                // full output manifest; the sealed digest binds that manifest.
                let terminal = json!({"kind":"exec-result", "request_id":7, "executed":true,
                    "exit_code":receipt["exit_code"], "stop_reason":receipt["stop_reason"],
                    "residual_group_members":0, "stdout_sha256":receipt["stdout_sha256"],
                    "stderr_sha256":receipt["stderr_sha256"],
                    "retained_result_sha256":receipt["retained_result_sha256"], "retained_result_released":true});
                let mut status = json!({"kind":"request-status", "request_id":7, "high_water":7,
                    "status":"terminal-observed", "output_recovery":"unavailable", "receipt":terminal,
                    "replay_authorized":false, "publication_authorized":false});
                match case {
                    0 => {}
                    1 => status["receipt"]["retained_result_sha256"] = json!("08".repeat(32)),
                    2 => status["receipt"]["retained_result_released"] = json!(false),
                    _ => status["status"] = json!("retired"),
                }
                send(&mut peer.stream, &status).await.unwrap();
                assert!(receive(&mut peer.stream).await.is_err(), "status confirmation sent another operation");
            }).await.expect("released-status confirmation timed out");
        });
        assert_eq!(receiver.wait().success(), case == 0, "{}", receiver.logs());
        if case == 0 {
            let report: Value =
                serde_json::from_slice(&fs::read(&receiver.stdout).unwrap()).unwrap();
            assert_eq!(report["acknowledgments_confirmed"], true);
            assert_eq!(report["receipt"], receipt);
        } else {
            assert_eq!(receiver.failure()["execution_may_have_run"], true);
            assert_eq!(receiver.failure()["reexecute"], false);
        }
        assert_eq!(local_bytes_and_inodes(&destination), before);
    }
}

#[test]
fn actual_tls_acknowledgment_refuses_changed_results_before_either_acceptance() {
    let certificates = Certificates::new();
    let pin = certificates.pin();
    let root = tempfile::tempdir().unwrap();
    let destination = root.path().join("delivery");
    let receipt = retained_delivery(&certificates, root.path(), &destination);
    let before = local_bytes_and_inodes(&destination);
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    for (field, value) in [
        ("retained_result_sha256", json!("09".repeat(32))),
        ("artifact_manifest", Value::Null),
        ("stdout_bytes", json!(1)),
        ("resumed", json!(false)),
    ] {
        let mut receiver = Receiver::spawn_operation(
            root.path(),
            &pin,
            Some(&certificates.server),
            &destination,
            Some("--acknowledge"),
        );
        let address = receiver.listening();
        runtime.block_on(async {
            asupersync::time::timeout(
                asupersync::time::wall_now(),
                Duration::from_secs(15),
                async {
                    let mut peer = connect_peer(&address, "localhost", &certificates.worker)
                        .await
                        .unwrap();
                    authenticate_mode(&mut peer.stream, &pin, true).await;
                    let mut result = resumed_offer(&receipt);
                    result[field] = value;
                    send(&mut peer.stream, &result).await.unwrap();
                    assert!(
                        receive(&mut peer.stream).await.is_err(),
                        "mismatched {field} caused an ACK or download"
                    );
                },
            )
            .await
            .expect("changed-result acknowledgment refusal timed out");
        });
        assert!(!receiver.wait().success());
        assert!(fs::read(&receiver.stdout).unwrap().is_empty());
        assert_eq!(receiver.failure()["execution_may_have_run"], true);
        assert_eq!(receiver.failure()["reexecute"], false);
        assert_eq!(local_bytes_and_inodes(&destination), before);
    }
}

#[test]
fn actual_tls_acknowledgment_preflight_preserves_local_evidence_without_downgrade() {
    let certificates = Certificates::new();
    let pin = certificates.pin();
    let root = tempfile::tempdir().unwrap();
    let destination = root.path().join("delivery");
    retained_delivery(&certificates, root.path(), &destination);
    for case in 0..3 {
        let wrong = if pin == "01".repeat(32) {
            "02".repeat(32)
        } else {
            "01".repeat(32)
        };
        let expected_pin = if case == 1 {
            wrong.as_str()
        } else {
            pin.as_str()
        };
        if case == 2 {
            fs::write(destination.join("artifacts/a"), b"bad!").unwrap();
        }
        let before = local_bytes_and_inodes(&destination);
        // Missing credentials distinguish preflight refusal from a listener
        // failure; no branch may quietly select a plaintext recovery session.
        let mut receiver = Receiver::spawn_operation(
            root.path(),
            expected_pin,
            None,
            &destination,
            Some("--acknowledge"),
        );
        assert!(!receiver.wait().success());
        assert_eq!(
            receiver.logs().contains("missing RABS_COORD_TLS_CA"),
            case == 0
        );
        assert!(!receiver.logs().contains("worker-exec-listening"));
        assert_eq!(receiver.failure()["execution_may_have_run"], true);
        assert_eq!(receiver.failure()["reexecute"], false);
        assert_eq!(local_bytes_and_inodes(&destination), before);
    }
}

#[test]
fn actual_tls_receiver_persists_boot_high_water_and_rejects_pin_reset() {
    let certificates = Certificates::new();
    let pin = certificates.pin();
    let root = tempfile::tempdir().unwrap();
    let runtime = RuntimeBuilder::current_thread().build().unwrap();

    for (generation, admitted) in [(5_u64, true), (4, false), (6, true)] {
        let destination = root.path().join(format!("generation-{generation}"));
        let mut receiver =
            Receiver::spawn(root.path(), &pin, Some(&certificates.server), &destination);
        let address = receiver.listening();
        runtime.block_on(async {
            asupersync::time::timeout(asupersync::time::wall_now(), Duration::from_secs(15), async {
                let mut peer = connect_peer(&address, "localhost", &certificates.worker).await.unwrap();
                let mut offered = hello(&pin);
                offered["boot_generation"] = json!(generation);
                offered["incarnation"] = json!(format!("{generation:032x}"));
                if admitted {
                    let session = authenticate_offer(&mut peer.stream, &pin, &offered, false).await;
                    deliver(&mut peer.stream, &destination, &pin, session, false).await;
                } else {
                    send(&mut peer.stream, &offered).await.unwrap();
                    let challenge = receive(&mut peer.stream).await.unwrap();
                    assert_eq!(challenge["kind"], "session-challenge");
                    send(&mut peer.stream, &json!({"kind":"worker-auth", "peer_id":pin,
                        "session_id":challenge["session_id"], "operation_id":challenge["operation_id"],
                        "token_id":challenge["token_id"]})).await.unwrap();
                    assert!(receive(&mut peer.stream).await.is_err(), "stale worker received a session grant");
                }
            }).await.expect("persistent worker admission timed out");
        });
        assert_eq!(receiver.wait().success(), admitted, "{}", receiver.logs());
        if admitted {
            let receipt: Value =
                serde_json::from_slice(&fs::read(destination.join("delivery.json")).unwrap())
                    .unwrap();
            assert_eq!(receipt["boot_generation"], generation);
        } else {
            assert!(receiver.logs().contains("RejectStaleBootGeneration"));
            assert_eq!(receiver.failure()["execution_may_have_run"], false);
            assert!(!destination.join("delivery.json").exists());
        }
    }

    let changed_pin = if pin == "01".repeat(32) {
        "02".repeat(32)
    } else {
        "01".repeat(32)
    };
    let destination = root.path().join("changed-pin");
    let mut receiver = Receiver::spawn(
        root.path(),
        &changed_pin,
        Some(&certificates.server),
        &destination,
    );
    assert!(!receiver.wait().success());
    assert!(!receiver.logs().contains("worker-exec-listening"));
    assert!(
        receiver
            .logs()
            .contains("already bound to another SPKI pin")
    );
    assert_eq!(receiver.failure()["execution_may_have_run"], false);
    assert!(!destination.exists());
}

/// Build a real immutable bundle through the operator's public preparation
/// path. The later upload must use the retained projection, never the changed
/// checkout or its unselected private file. The scripted peer still runs no tool.
fn prepared_build_bundle(root: &Path) -> (PathBuf, Value, Vec<u8>) {
    let checkout = root.join("checkout");
    fs::create_dir(&checkout).unwrap();
    fs::create_dir(checkout.join("src")).unwrap();
    let source = [
        b"// ".to_vec(),
        vec![b'x'; MAX_SOURCE_CHUNK + 17],
        b"\npub fn answer() -> u32 { 42 }\n".to_vec(),
    ]
    .concat();
    fs::write(checkout.join("src/lib.rs"), &source).unwrap();
    fs::write(checkout.join("empty"), b"").unwrap();
    fs::write(
        checkout.join("unselected.secret"),
        b"never transfer this private file",
    )
    .unwrap();
    let mut specification = request();
    specification
        .as_object_mut()
        .unwrap()
        .remove("workspace_backing");
    specification["args"] = json!(["src/lib.rs", "--crate-type", "lib"]);
    specification["source_files"] = json!(["src/lib.rs", "empty"]);
    specification["timeout_ms"] = json!(10000);
    specification["future_semantics"] = json!({"must_preserve":"prepared build"});
    let prepared = prepare_source_bundle(&checkout, &specification, &root.join("bundle")).unwrap();
    let bundle = PathBuf::from(prepared["directory"].as_str().unwrap());
    let request: Value =
        serde_json::from_slice(&fs::read(bundle.join("request.json")).unwrap()).unwrap();
    assert_eq!(prepared["source_files"], 2);
    assert_eq!(prepared["source_bytes"], source.len());
    assert!(!bundle.join("source/unselected.secret").exists());
    fs::write(
        checkout.join("src/lib.rs"),
        b"checkout changed after preparation",
    )
    .unwrap();
    (bundle, request, source)
}

/// Feed the actual TLS upload into the worker's real source receiver. Only
/// after its complete closure seals does the peer accept the exact execution.
async fn receive_prepared_source(
    stream: &mut SecureWorkerStream,
    request: &Value,
    destination: &Path,
) {
    let manifest = request_manifest(request).unwrap().unwrap();
    let identity = &request["source_manifest"]["manifest_sha256"];
    assert_eq!(
        receive(stream).await.unwrap(),
        json!({"kind":"source-begin",
        "request_id":request["request_id"], "manifest":request["source_manifest"],
        "allow_cached_files":true})
    );
    let mut receiver = SourceReceiver::create(destination, manifest.clone()).unwrap();
    send(
        stream,
        &json!({"kind":"source-ready", "request_id":request["request_id"],
        "manifest_sha256":identity, "sealed":false,
        "missing_files":manifest.files().iter().map(|file| &file.path).collect::<Vec<_>>()}),
    )
    .await
    .unwrap();
    let mut chunks = 0;
    for file in manifest.files() {
        let mut offset = 0;
        while offset < file.len {
            let frame = receive(stream).await.unwrap();
            assert_eq!(
                frame["kind"], "source-chunk",
                "execution must wait for source sealing"
            );
            assert_eq!(frame["request_id"], request["request_id"]);
            assert_eq!(frame["manifest_sha256"], *identity);
            assert_eq!(frame["path"], file.path);
            assert_eq!(frame["offset"], offset);
            let encoded = frame["data_hex"].as_str().unwrap();
            assert!(
                !encoded.is_empty()
                    && encoded.len() <= MAX_SOURCE_CHUNK * 2
                    && encoded.len().is_multiple_of(2)
            );
            let bytes: Vec<u8> = encoded
                .as_bytes()
                .chunks_exact(2)
                .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                .collect();
            assert_eq!(frame["chunk_sha256"], hash(&bytes));
            offset = receiver
                .write_chunk(&file.path, offset, &bytes, Sha256::digest(&bytes).into())
                .unwrap();
            send(
                stream,
                &json!({"kind":"source-chunk-accepted", "request_id":request["request_id"],
                "manifest_sha256":identity, "path":file.path, "next_offset":offset}),
            )
            .await
            .unwrap();
            chunks += 1;
        }
    }
    assert!(
        chunks >= 2,
        "fixture must cross a source-transfer range boundary"
    );
    assert_eq!(
        receive(stream).await.unwrap(),
        json!({"kind":"source-seal",
        "request_id":request["request_id"], "manifest_sha256":identity})
    );
    receiver.seal().unwrap();
    send(
        stream,
        &json!({"kind":"source-ready", "request_id":request["request_id"],
        "manifest_sha256":identity, "sealed":true}),
    )
    .await
    .unwrap();
    assert_eq!(
        receive(stream).await.unwrap(),
        *request,
        "saved request must be dispatched exactly once after sealing"
    );
}

#[test]
fn actual_prepared_build_uploads_installs_and_replays_offline_after_ack_loss() {
    use std::os::unix::fs::MetadataExt;
    let certificates = Certificates::new();
    let owner = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(owner.path()).unwrap();
    let (bundle, request, source) = prepared_build_bundle(&root);
    let delivery = root.join("delivery");
    let outputs = root.join("outputs");
    let received_source = root.join("worker-source");
    let pin = certificates.pin();
    let mut receiver = Receiver::spawn_build(
        &root,
        &pin,
        Some(&certificates.server),
        &bundle,
        &delivery,
        &outputs,
        false,
    );
    let address = receiver.listening();
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    runtime.block_on(async {
        asupersync::time::timeout(
            asupersync::time::wall_now(),
            Duration::from_secs(15),
            async {
                let mut peer = connect_peer(&address, "localhost", &certificates.worker)
                    .await
                    .unwrap();
                let mut offered = hello(&pin);
                offered["source_transfers"] = json!([SOURCE_TRANSFER]);
                let (session, grant) = authenticate_grant(&mut peer.stream, &pin, &offered).await;
                assert_eq!(grant["source_transfer"], SOURCE_TRANSFER);
                receive_prepared_source(&mut peer.stream, &request, &received_source).await;
                assert_eq!(
                    fs::read(received_source.join("src/lib.rs")).unwrap(),
                    source
                );
                assert_eq!(fs::read(received_source.join("empty")).unwrap(), b"");
                assert!(!received_source.join("unselected.secret").exists());
                assert!(
                    !outputs.exists(),
                    "outputs cannot be exposed before a complete result"
                );
                deliver_mode(
                    &mut peer.stream,
                    &delivery,
                    &pin,
                    session,
                    false,
                    false,
                    true,
                )
                .await;
            },
        )
        .await
        .expect("prepared build exchange timed out");
    });
    assert!(receiver.wait().success(), "{}", receiver.logs());
    let report: Value = serde_json::from_slice(&fs::read(&receiver.stdout).unwrap()).unwrap();
    assert_eq!(report["kind"], "worker-build");
    assert_eq!(report["delivery"]["acknowledgments_confirmed"], false);
    assert_eq!(
        report["delivery"]["receipt"]["request_sha256"],
        hash(&serde_json::to_vec(&request).unwrap())
    );
    assert_eq!(report["installed_outputs"]["kind"], "worker-output-install");
    assert_eq!(report["installed_outputs"]["reused"], false);
    assert_eq!(report["installed_outputs"]["files"], 1);
    assert_eq!(report["publication_authorized"], false);
    assert_eq!(report["reexecute"], false);
    assert_eq!(fs::read(outputs.join("a")).unwrap(), ARTIFACT);
    assert_eq!(fs::read_dir(&outputs).unwrap().count(), 1);
    let inode = fs::metadata(outputs.join("a")).unwrap().ino();
    assert_ne!(
        inode,
        fs::metadata(delivery.join("artifacts/a")).unwrap().ino()
    );
    let before = local_bytes_and_inodes(&delivery);
    drop(receiver);
    fs::rename(bundle.join("source"), root.join("retained-source-offline")).unwrap();
    let mut offline = Receiver::spawn_build(&root, &pin, None, &bundle, &delivery, &outputs, false);
    assert!(offline.wait().success(), "{}", offline.logs());
    assert!(!offline.logs().contains("worker-exec-listening"));
    let replay: Value = serde_json::from_slice(&fs::read(&offline.stdout).unwrap()).unwrap();
    assert_eq!(replay["delivery"]["receipt"], report["delivery"]["receipt"]);
    assert_eq!(replay["installed_outputs"]["reused"], true);
    assert_eq!(fs::metadata(outputs.join("a")).unwrap().ino(), inode);
    assert_eq!(local_bytes_and_inodes(&delivery), before);
    drop(offline);

    // A matching receipt never licenses silently repairing changed user output.
    fs::write(outputs.join("a"), b"user").unwrap();
    let mut changed = Receiver::spawn_build(&root, &pin, None, &bundle, &delivery, &outputs, false);
    assert!(!changed.wait().success());
    assert!(changed.logs().contains("worker-build-error"));
    assert!(!changed.logs().contains("worker-exec-listening"));
    assert_eq!(fs::read(outputs.join("a")).unwrap(), b"user");
    assert_eq!(local_bytes_and_inodes(&delivery), before);
}

#[test]
fn actual_prepared_build_resumes_and_installs_without_recapturing_missing_source() {
    let certificates = Certificates::new();
    let owner = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(owner.path()).unwrap();
    let (bundle, request, _) = prepared_build_bundle(&root);
    fs::rename(bundle.join("source"), root.join("retained-source-offline")).unwrap();
    let delivery = root.join("resumed-delivery");
    let outputs = root.join("resumed-outputs");
    let pin = certificates.pin();
    let mut receiver = Receiver::spawn_build(
        &root,
        &pin,
        Some(&certificates.server),
        &bundle,
        &delivery,
        &outputs,
        true,
    );
    let address = receiver.listening();
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    runtime.block_on(async {
        asupersync::time::timeout(
            asupersync::time::wall_now(),
            Duration::from_secs(15),
            async {
                let mut peer = connect_peer(&address, "localhost", &certificates.worker)
                    .await
                    .unwrap();
                let (session, grant) =
                    authenticate_grant(&mut peer.stream, &pin, &recovery_hello(&pin)).await;
                assert_eq!(grant["result_retention"], "durable-result-v1");
                assert!(
                    grant.get("source_transfer").is_none(),
                    "resume cannot negotiate another upload"
                );
                assert_eq!(
                    receive(&mut peer.stream).await.unwrap(),
                    json!({"kind":"result-resume",
                "request_id":7, "request":request})
                );
                assert!(!outputs.exists());
                deliver_mode(
                    &mut peer.stream,
                    &delivery,
                    &pin,
                    session,
                    false,
                    true,
                    false,
                )
                .await;
            },
        )
        .await
        .expect("prepared build resume timed out");
    });
    assert!(receiver.wait().success(), "{}", receiver.logs());
    let report: Value = serde_json::from_slice(&fs::read(&receiver.stdout).unwrap()).unwrap();
    assert_eq!(report["kind"], "worker-build");
    assert_eq!(report["delivery"]["receipt"]["resumed"], true);
    assert_eq!(
        report["delivery"]["receipt"]["worker_identity_scope"],
        "delivery-session"
    );
    assert_eq!(report["installed_outputs"]["reused"], false);
    assert_eq!(fs::read(outputs.join("a")).unwrap(), ARTIFACT);
    assert!(!bundle.join("source").exists());
    drop(receiver);
    let mut offline = Receiver::spawn_build(&root, &pin, None, &bundle, &delivery, &outputs, true);
    assert!(offline.wait().success(), "{}", offline.logs());
    assert!(!offline.logs().contains("worker-exec-listening"));
    let replay: Value = serde_json::from_slice(&fs::read(&offline.stdout).unwrap()).unwrap();
    assert_eq!(replay["delivery"]["receipt"], report["delivery"]["receipt"]);
    assert_eq!(replay["installed_outputs"]["reused"], true);
}

#[test]
fn actual_prepared_build_preserves_failed_compiler_exit_and_diagnostics_without_outputs() {
    let certificates = Certificates::new();
    let owner = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(owner.path()).unwrap();
    let (bundle, request, _) = prepared_build_bundle(&root);
    fs::rename(bundle.join("source"), root.join("retained-source-offline")).unwrap();
    let delivery = root.join("failed-delivery");
    let outputs = root.join("failed-outputs");
    let pin = certificates.pin();
    let diagnostic = b"error: scripted compiler rejected the source\n";
    let mut receiver = Receiver::spawn_build(
        &root,
        &pin,
        Some(&certificates.server),
        &bundle,
        &delivery,
        &outputs,
        true,
    );
    let address = receiver.listening();
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    runtime.block_on(async {
        asupersync::time::timeout(asupersync::time::wall_now(), Duration::from_secs(15), async {
            let mut peer = connect_peer(&address, "localhost", &certificates.worker).await.unwrap();
            let (_, grant) = authenticate_grant(&mut peer.stream, &pin, &recovery_hello(&pin)).await;
            assert_eq!(grant["result_retention"], "durable-result-v1");
            assert_eq!(receive(&mut peer.stream).await.unwrap(), json!({"kind":"result-resume",
                "request_id":7, "request":request}));
            send(&mut peer.stream, &json!({"kind":"exec-result", "request_id":7, "executed":true,
                "exit_code":101, "stop_reason":null, "residual_group_members":0,
                "resumed":true, "result_retention":"durable-result-v1", "retained_result_sha256":"07".repeat(32),
                "output_transfer":"ranges-v1", "output_ack_required":true,
                "stdout_bytes":0, "stdout_sha256":hash(b""),
                "stderr_bytes":diagnostic.len(), "stderr_sha256":hash(diagnostic),
                "artifact_ack_required":false, "artifact_manifest":null})).await.unwrap();
            let query = receive(&mut peer.stream).await.unwrap();
            assert_eq!(query["kind"], "output-read");
            assert_eq!(query["stream"], "stderr");
            assert_eq!(query["offset"], 0);
            send(&mut peer.stream, &json!({"kind":"output-chunk", "request_id":7,
                "stream":"stderr", "offset":0, "next_offset":diagnostic.len(), "total_bytes":diagnostic.len(),
                "eof":true, "data_hex":hex(diagnostic), "chunk_sha256":hash(diagnostic),
                "sha256":hash(diagnostic)})).await.unwrap();
            assert_eq!(receive(&mut peer.stream).await.unwrap(), json!({"kind":"output-ack", "request_id":7,
                "stdout_bytes":0, "stdout_sha256":hash(b""),
                "stderr_bytes":diagnostic.len(), "stderr_sha256":hash(diagnostic)}));
            assert_eq!(fs::read(delivery.join("diagnostics/stderr")).unwrap(), diagnostic);
            assert!(!outputs.exists());
            send(&mut peer.stream, &json!({"kind":"output-acknowledged", "request_id":7,
                "already_released":false})).await.unwrap();
            assert!(receive(&mut peer.stream).await.is_err(), "failed execution must not request artifacts or reexecute");
        }).await.expect("failed build delivery timed out");
    });
    assert_eq!(receiver.wait().code(), Some(101), "{}", receiver.logs());
    let report: Value = serde_json::from_slice(&fs::read(&receiver.stdout).unwrap()).unwrap();
    assert_eq!(report["kind"], "worker-build");
    assert_eq!(report["delivery"]["receipt"]["exit_code"], 101);
    assert!(report["installed_outputs"].is_null());
    assert_eq!(report["publication_authorized"], false);
    assert_eq!(fs::read_dir(delivery.join("artifacts")).unwrap().count(), 0);
    assert!(!outputs.exists());
    let receipt = fs::read(delivery.join("delivery.json")).unwrap();
    drop(receiver);
    let mut offline = Receiver::spawn_build(&root, &pin, None, &bundle, &delivery, &outputs, false);
    assert_eq!(offline.wait().code(), Some(101), "{}", offline.logs());
    assert!(!offline.logs().contains("worker-exec-listening"));
    assert_eq!(fs::read(delivery.join("delivery.json")).unwrap(), receipt);
    assert_eq!(
        fs::read(delivery.join("diagnostics/stderr")).unwrap(),
        diagnostic
    );
    assert!(!outputs.exists());
}

#[test]
fn actual_prepared_build_refuses_preexisting_output_without_delivery_before_dispatch() {
    let owner = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(owner.path()).unwrap();
    let (bundle, _, _) = prepared_build_bundle(&root);
    let delivery = root.join("absent-delivery");
    let outputs = root.join("existing-outputs");
    fs::create_dir(&outputs).unwrap();
    fs::write(outputs.join("sentinel"), b"keep user output").unwrap();
    let mut receiver = Receiver::spawn_build(
        &root,
        &"01".repeat(32),
        None,
        &bundle,
        &delivery,
        &outputs,
        false,
    );
    assert!(!receiver.wait().success());
    let failure: Value = receiver
        .logs()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|value| value["kind"] == "worker-build-error")
        .expect("typed build refusal");
    assert_eq!(failure["execution_may_have_run"], false);
    assert_eq!(failure["reexecute"], false);
    assert!(!receiver.logs().contains("worker-exec-listening"));
    assert!(
        !receiver.logs().contains("missing RABS_COORD_TLS_CA"),
        "output ownership must be checked before TLS"
    );
    assert!(!delivery.exists());
    assert_eq!(
        fs::read(outputs.join("sentinel")).unwrap(),
        b"keep user output"
    );
}

#[test]
fn killed_tls_receiver_preserves_incarnation_and_clone_refusal_across_restart() {
    let certificates = Certificates::new();
    let pin = certificates.pin();
    let root = tempfile::tempdir().unwrap();
    let runtime = RuntimeBuilder::current_thread().build().unwrap();

    let destination = root.path().join("interrupted");
    {
        let mut receiver =
            Receiver::spawn(root.path(), &pin, Some(&certificates.server), &destination);
        let address = receiver.listening();
        runtime.block_on(async {
            asupersync::time::timeout(
                asupersync::time::wall_now(),
                Duration::from_secs(15),
                async {
                    let mut peer = connect_peer(&address, "localhost", &certificates.worker)
                        .await
                        .unwrap();
                    authenticate(&mut peer.stream, &pin).await;
                    receiver.child.kill().unwrap();
                    assert!(!receiver.wait().success());
                },
            )
            .await
            .expect("interrupted worker admission timed out");
        });
    }
    assert!(!destination.join("delivery.json").exists());

    for (generation, incarnation) in [(1_u64, 2_u128), (2, 3)] {
        let destination = root.path().join(format!("clone-{incarnation}"));
        let mut receiver =
            Receiver::spawn(root.path(), &pin, Some(&certificates.server), &destination);
        let address = receiver.listening();
        runtime.block_on(async {
            asupersync::time::timeout(
                asupersync::time::wall_now(),
                Duration::from_secs(15),
                async {
                    let mut peer = connect_peer(&address, "localhost", &certificates.worker)
                        .await
                        .unwrap();
                    let mut offered = hello(&pin);
                    offered["boot_generation"] = json!(generation);
                    offered["incarnation"] = json!(format!("{incarnation:032x}"));
                    send(&mut peer.stream, &offered).await.unwrap();
                    let challenge = receive(&mut peer.stream).await.unwrap();
                    assert_eq!(challenge["kind"], "session-challenge");
                    send(
                        &mut peer.stream,
                        &json!({"kind":"worker-auth", "peer_id":pin,
                    "session_id":challenge["session_id"], "operation_id":challenge["operation_id"],
                    "token_id":challenge["token_id"]}),
                    )
                    .await
                    .unwrap();
                    assert!(
                        receive(&mut peer.stream).await.is_err(),
                        "ambiguous worker received a session grant"
                    );
                },
            )
            .await
            .expect("persistent clone refusal timed out");
        });
        assert!(!receiver.wait().success(), "{}", receiver.logs());
        assert!(receiver.logs().contains("RejectCloneAmbiguity"));
        assert_eq!(receiver.failure()["execution_may_have_run"], false);
        assert!(!destination.join("delivery.json").exists());
    }
}
