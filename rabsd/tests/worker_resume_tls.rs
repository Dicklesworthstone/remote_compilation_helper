//! Actual receiver CLI, native TLS and prefix reuse after interrupted delivery.
//! The worker peer is scripted: no compiler execution, real worker spool or fleet
//! qualification is claimed. Every candidate byte is checked by the production
//! receiver; no ready receipt is manufactured or patched by this fixture.
#![cfg(unix)]

use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::runtime::RuntimeBuilder;
use rabs_asupersync::worker_transport::{SecureWorkerStream, TlsFiles, connect_peer};
use rabs_sandbox::artifact_tree::TREE_FILES_VERSION;
use rabs_sandbox::source_transfer::{SourceFile, SourceManifest};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const CHUNK: usize = 65_536;
const LOG_LIMIT: u64 = 4 * 1024 * 1024;

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }
fn hash(bytes: &[u8]) -> String { hex(&Sha256::digest(bytes)) }
fn read_log(path: &Path) -> Vec<u8> {
    let mut bytes = Vec::new();
    File::open(path).unwrap().take(LOG_LIMIT + 1).read_to_end(&mut bytes).unwrap();
    assert!(bytes.len() as u64 <= LOG_LIMIT, "fixture log exceeded its bound");
    bytes
}

struct Process { child: Child, stdout: PathBuf, stderr: PathBuf }
impl Process {
    fn spawn(root: &Path, name: &str, command: &mut Command) -> Self {
        let stdout = root.join(format!("{name}.stdout"));
        let stderr = root.join(format!("{name}.stderr"));
        let child = command.stdin(Stdio::null()).stdout(File::create(&stdout).unwrap())
            .stderr(File::create(&stderr).unwrap()).spawn().expect("required fixture executable");
        Self { child, stdout, stderr }
    }
    fn wait(&mut self) -> ExitStatus {
        let until = Instant::now() + Duration::from_secs(30);
        loop {
            for path in [&self.stdout, &self.stderr] {
                assert!(fs::metadata(path).unwrap().len() <= LOG_LIMIT, "fixture log exceeded its bound");
            }
            if let Some(status) = self.child.try_wait().unwrap() { return status; }
            assert!(Instant::now() < until, "fixture process timed out: {}", String::from_utf8_lossy(&read_log(&self.stderr)));
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    fn listening(&mut self) -> String {
        let until = Instant::now() + Duration::from_secs(15);
        loop {
            for line in String::from_utf8_lossy(&read_log(&self.stderr)).lines() {
                if let Ok(value) = serde_json::from_str::<Value>(line)
                    && value["kind"] == "worker-exec-listening"
                {
                    assert_eq!(value["transport"], "mutual-tls-atp");
                    assert_eq!(value["operation"], "result-resume");
                    assert_eq!(value["authentication_required"], true);
                    return value["address"].as_str().unwrap().to_owned();
                }
            }
            assert!(self.child.try_wait().unwrap().is_none(), "receiver stopped: {}", String::from_utf8_lossy(&read_log(&self.stderr)));
            assert!(Instant::now() < until, "receiver did not listen");
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    fn failure(&self) -> Value {
        String::from_utf8_lossy(&read_log(&self.stderr)).lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .find(|value| matches!(value["kind"].as_str(), Some("worker-delivery-error" | "worker-build-error")))
            .expect("typed receiver failure")
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        // These commands are OpenSSL or a receiver with a scripted peer, not a
        // compiler/worker process tree. Always reap our directly owned process.
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

struct Certificates { _root: tempfile::TempDir, server: TlsFiles, worker: TlsFiles, foreign: TlsFiles }
impl Certificates {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let openssl = |name: &str, args: &[&str]| {
            let mut command = Command::new("openssl");
            command.current_dir(root.path()).args(args);
            let mut process = Process::spawn(root.path(), name, &mut command);
            assert!(process.wait().success(), "{}", String::from_utf8_lossy(&read_log(&process.stderr)));
        };
        openssl("ca", &["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "1",
            "-subj", "/CN=RABS reuse test CA", "-keyout", "ca.key", "-out", "ca.pem",
            "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"]);
        for (name, usage, serial) in [("server", "serverAuth", "2"), ("worker", "clientAuth", "3"), ("foreign", "clientAuth", "4")] {
            let key = format!("{name}.key");
            let csr = format!("{name}.csr");
            let pem = format!("{name}.pem");
            let extension = format!("{name}.ext");
            openssl(&format!("req-{name}"), &["req", "-new", "-newkey", "rsa:2048", "-nodes", "-sha256",
                "-subj", "/CN=localhost", "-keyout", &key, "-out", &csr]);
            fs::write(root.path().join(&extension), format!("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage={usage}\nsubjectAltName=DNS:localhost\n")).unwrap();
            openssl(&format!("sign-{name}"), &["x509", "-req", "-in", &csr, "-CA", "ca.pem", "-CAkey", "ca.key",
                "-set_serial", serial, "-days", "1", "-sha256", "-extfile", &extension, "-out", &pem]);
        }
        let files = |name: &str| TlsFiles { ca:root.path().join("ca.pem"),
            certificate:root.path().join(format!("{name}.pem")), private_key:root.path().join(format!("{name}.key")) };
        let server = files("server");
        let worker = files("worker");
        let foreign = files("foreign");
        Self { _root:root, server, worker, foreign }
    }
    fn pin(&self) -> String { hex(&self.worker.local_identity().unwrap().fingerprint) }
}

struct Fixture { owner: tempfile::TempDir, root: PathBuf, bundle: PathBuf, request: Value, files: BTreeMap<String, Vec<u8>>, result: Value }
impl Fixture {
    fn new() -> Self {
        let owner = tempfile::tempdir().unwrap();
        let root = owner.path().canonicalize().unwrap();
        let bundle = root.join("bundle");
        fs::create_dir(&bundle).unwrap();
        let source = SourceManifest::new(vec![SourceFile { path:"lib.rs".into(), len:6,
            sha256:Sha256::digest(b"source").into(), executable:false }]).unwrap();
        let request = json!({"kind":"canonical-exec", "request_id":7, "program":"rustc", "args":["lib.rs"],
            "toolchain_backing":"/tc", "source_manifest":{"manifest_sha256":hex(&source.digest()),
                "files":[{"path":"lib.rs", "bytes":6, "sha256":hash(b"source"), "executable":false}]},
            "artifacts":{"unit":"build", "files":["bin/app"], "tree":TREE_FILES_VERSION}});
        fs::write(bundle.join("request.json"), serde_json::to_vec(&request).unwrap()).unwrap();
        // No source directory is needed for any of these retained-result requests.
        let files: BTreeMap<String, Vec<u8>> = BTreeMap::from([
            ("diagnostics/stdout".into(), (0..CHUNK + 31).map(|n| (n % 256) as u8).collect::<Vec<_>>()),
            ("diagnostics/stderr".into(), b"diagnostic\0\xff".to_vec()),
            ("artifacts/a/dependency.rlib".into(), (0..CHUNK + 7).map(|n| (n % 251) as u8).collect::<Vec<_>>()),
            ("artifacts/bin/app".into(), (0..2 * CHUNK + 37).map(|n| (n % 249) as u8).collect::<Vec<_>>()),
        ]);
        let rows: Vec<Value> = files.iter().filter_map(|(name, bytes)| name.strip_prefix("artifacts/").map(|name|
            json!({"name":name, "bytes":bytes.len(), "sha256":hash(bytes), "executable":name == "bin/app"}))).collect();
        let mut manifest_hash = Sha256::new();
        let field = |hasher: &mut Sha256, bytes: &[u8]| { hasher.update((bytes.len() as u64).to_be_bytes()); hasher.update(bytes); };
        field(&mut manifest_hash, b"rabs.worker-artifact-manifest.v1");
        field(&mut manifest_hash, b"build");
        manifest_hash.update((rows.len() as u64).to_be_bytes());
        let mut total = 0_u64;
        for row in &rows {
            field(&mut manifest_hash, row["name"].as_str().unwrap().as_bytes());
            manifest_hash.update([u8::from(row["executable"].as_bool().unwrap())]);
            let len = row["bytes"].as_u64().unwrap();
            manifest_hash.update(len.to_be_bytes());
            field(&mut manifest_hash, row["sha256"].as_str().unwrap().as_bytes());
            total += len;
        }
        let result = json!({"kind":"exec-result", "request_id":7, "executed":true, "resumed":true,
            "exit_code":0, "stop_reason":null, "residual_group_members":0,
            "result_retention":"durable-result-v1", "retained_result_sha256":hash(b"retained fixture result"),
            "output_transfer":"ranges-v1", "output_ack_required":true,
            "stdout_bytes":files["diagnostics/stdout"].len(), "stdout_sha256":hash(&files["diagnostics/stdout"]),
            "stderr_bytes":files["diagnostics/stderr"].len(), "stderr_sha256":hash(&files["diagnostics/stderr"]),
            "artifact_transfer":"files-v1", "artifact_ack_required":true,
            "artifact_manifest":{"unit":"build", "files":rows, "total_bytes":total, "manifest_sha256":hex(&manifest_hash.finalize())}});
        Self { owner, root, bundle, request, files, result }
    }
    fn receiver(&self, name: &str, pin: &str, tls: Option<&TlsFiles>, from: Option<&Path>, build: bool) -> Process {
        let mut command = Command::new(env!("CARGO_BIN_EXE_rabsd"));
        command.arg(if build {"--worker-build-tls"} else {"--worker-exec-tls"});
        if let Some(from) = from { command.arg("--resume-from").arg(from); }
        else { command.arg("--resume"); }
        command.args(["127.0.0.1:0", "worker", pin]);
        command.arg(if build { self.bundle.clone() } else { self.bundle.join("request.json") });
        command.arg(self.root.join(name));
        if build { command.arg(self.root.join("installed")); }
        command.env("RABS_STATE_DIR", self.root.join("state"))
            .env_remove("RABS_COORD_TLS_CA").env_remove("RABS_COORD_TLS_CERT").env_remove("RABS_COORD_TLS_KEY");
        if let Some(tls) = tls {
            command.env("RABS_COORD_TLS_CA", &tls.ca).env("RABS_COORD_TLS_CERT", &tls.certificate).env("RABS_COORD_TLS_KEY", &tls.private_key);
        }
        Process::spawn(self.owner.path(), name, &mut command)
    }
}

async fn send(stream: &mut SecureWorkerStream, value: &Value) -> io::Result<()> {
    stream.write_all(format!("{value}\n").as_bytes()).await?;
    stream.flush().await
}
async fn receive(stream: &mut SecureWorkerStream) -> io::Result<Value> {
    let mut line = Vec::new();
    let mut byte = [0];
    loop {
        if stream.read(&mut byte).await? == 0 { return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "receiver disconnected")); }
        if byte[0] == b'\n' { return serde_json::from_slice(&line).map_err(io::Error::from); }
        if line.len() == 1024 * 1024 { return Err(io::Error::other("oversized receiver frame")); }
        line.push(byte[0]);
    }
}
async fn authenticate(stream: &mut SecureWorkerStream, pin: &str, boot: u64, request: &Value) -> u64 {
    send(stream, &json!({"kind":"worker-hello", "worker_id":"worker", "peer_id":pin,
        "canonical":true, "slots":1, "boot_generation":boot, "incarnation":format!("{boot:032x}"), "request_high_water":7,
        "transport":{"minimum_compatible":1,"current":1}, "application":{"minimum_compatible":1,"current":1},
        "recovery_protocols":["request-journal-v1"], "result_retentions":["durable-result-v1"],
        "output_transfers":["ranges-v1"], "artifact_transfers":["files-v1"]})).await.unwrap();
    let challenge = receive(stream).await.unwrap();
    assert_eq!(challenge["kind"], "session-challenge");
    assert_eq!(challenge["capability"], 3);
    assert_eq!(challenge["scope"], format!("canonical-probes:{pin}"));
    send(stream, &json!({"kind":"worker-auth", "peer_id":pin,
        "session_id":challenge["session_id"], "operation_id":challenge["operation_id"], "token_id":challenge["token_id"]})).await.unwrap();
    let grant = receive(stream).await.unwrap();
    assert_eq!(grant["kind"], "session-ok");
    assert_eq!(grant["publication"], "disabled");
    assert_eq!(grant["result_retention"], "durable-result-v1");
    assert!(grant.get("source_transfer").is_none());
    assert_eq!(receive(stream).await.unwrap(), json!({"kind":"result-resume", "request_id":7, "request":request}));
    grant["session_id"].as_u64().unwrap()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode { Interrupt, Complete, CorruptPrefix }
#[derive(Default)]
struct Transfers { reads:Vec<(String, u64)>, acknowledgments:usize }

async fn serve(stream: &mut SecureWorkerStream, fixture: &Fixture, destination: &Path, pin: &str, session: u64, mode: Mode) -> Transfers {
    send(stream, &fixture.result).await.unwrap();
    let mut transfers = Transfers::default();
    loop {
        let query = match receive(stream).await {
            Ok(query) => query,
            Err(_) if mode == Mode::CorruptPrefix => {
                assert_eq!(transfers.acknowledgments, 0);
                assert!(!destination.join("delivery.json").exists());
                return transfers;
            }
            Err(error) => panic!("unexpected receiver failure: {error}"),
        };
        assert_eq!(query["request_id"], 7);
        match query["kind"].as_str().unwrap() {
            "output-read" | "artifact-read" => {
                let artifact = query["kind"] == "artifact-read";
                let name = query[if artifact {"name"} else {"stream"}].as_str().unwrap();
                let key = format!("{}/{name}", if artifact {"artifacts"} else {"diagnostics"});
                let bytes = &fixture.files[&key];
                let offset = query["offset"].as_u64().unwrap();
                assert_eq!(query["max_bytes"], CHUNK);
                assert!(offset <= bytes.len() as u64);
                if mode == Mode::Interrupt && key == "artifacts/bin/app" && offset == CHUNK as u64 {
                    assert_eq!(transfers.acknowledgments, 0);
                    // With pipelined reads, the second request no longer proves
                    // the first reply has been written. Keep the exact intended
                    // failure frontier: one verified prefix, no second reply,
                    // no receipt, and no release. The receiver is a separate
                    // process; this bounded filesystem wait needs no peer I/O.
                    let until = Instant::now() + Duration::from_secs(5);
                    let prefix = destination.join("artifacts/bin/app");
                    loop {
                        match fs::metadata(&prefix) {
                            Ok(metadata) if metadata.len() == CHUNK as u64 => break,
                            Ok(metadata) => assert!(metadata.len() < CHUNK as u64),
                            Err(error) => assert_eq!(error.kind(), io::ErrorKind::NotFound),
                        }
                        assert!(Instant::now() < until, "receiver did not retain its first range");
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    assert_eq!(fs::read(&prefix).unwrap(), bytes[..CHUNK]);
                    assert!(!destination.join("delivery.json").exists());
                    return transfers; // Drop only after the same prefix frontier as the serial test.
                }
                transfers.reads.push((key, offset));
                let end = (offset as usize + CHUNK).min(bytes.len());
                let part = &bytes[offset as usize..end];
                let mut reply = json!({"kind":if artifact {"artifact-chunk"} else {"output-chunk"},
                    "request_id":7, "offset":offset, "next_offset":end, "total_bytes":bytes.len(),
                    "sha256":hash(bytes), "chunk_sha256":hash(part), "data_hex":hex(part), "eof":end == bytes.len()});
                reply[if artifact {"name"} else {"stream"}] = json!(name);
                if artifact {
                    reply["executable"] = json!(name == "bin/app");
                    reply["manifest_sha256"] = fixture.result["artifact_manifest"]["manifest_sha256"].clone();
                }
                send(stream, &reply).await.unwrap();
            }
            "output-ack" | "artifact-ack" => {
                assert!(mode == Mode::Complete, "unverified delivery released the worker's result");
                let receipt: Value = serde_json::from_slice(&fs::read(destination.join("delivery.json")).unwrap()).unwrap();
                assert_eq!(receipt["request_sha256"], hash(&serde_json::to_vec(&fixture.request).unwrap()));
                assert_eq!(receipt["transport_authenticated"], true);
                assert_eq!(receipt["worker_spki_sha256"], pin);
                assert_eq!(receipt["authenticated_session_id"], session);
                assert_eq!(receipt["publication_authorized"], false);
                for (path, bytes) in &fixture.files { assert_eq!(fs::read(destination.join(path)).unwrap(), *bytes); }
                let output = query["kind"] == "output-ack";
                if output {
                    assert_eq!(transfers.acknowledgments, 0);
                    assert_eq!(query["stdout_sha256"], fixture.result["stdout_sha256"]);
                    assert_eq!(query["stderr_sha256"], fixture.result["stderr_sha256"]);
                } else {
                    assert_eq!(transfers.acknowledgments, 1);
                    assert_eq!(query["manifest_sha256"], fixture.result["artifact_manifest"]["manifest_sha256"]);
                }
                send(stream, &json!({"kind":if output {"output-acknowledged"} else {"artifact-acknowledged"},
                    "request_id":7, "already_released":false})).await.unwrap();
                transfers.acknowledgments += 1;
                if transfers.acknowledgments == 2 { return transfers; }
            }
            other => panic!("unexpected operation: {other}; no source upload or execution is permitted"),
        }
    }
}

fn exchange(fixture: &Fixture, receiver: &mut Process, certificates: &Certificates, name: &str, boot: u64, mode: Mode) -> Transfers {
    let address = receiver.listening();
    let pin = certificates.pin();
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    runtime.block_on(async {
        asupersync::time::timeout(asupersync::time::wall_now(), Duration::from_secs(25), async {
            let mut peer = connect_peer(&address, "localhost", &certificates.worker).await.unwrap();
            let session = authenticate(&mut peer.stream, &pin, boot, &fixture.request).await;
            serve(&mut peer.stream, fixture, &fixture.root.join(name), &pin, session, mode).await
        }).await.expect("bounded native TLS fixture exchange")
    })
}

fn interrupted(fixture: &Fixture, certificates: &Certificates) -> PathBuf {
    let mut first = fixture.receiver("interrupted", &certificates.pin(), Some(&certificates.server), None, false);
    exchange(fixture, &mut first, certificates, "interrupted", 1, Mode::Interrupt);
    assert!(!first.wait().success());
    assert_eq!(first.failure()["execution_may_have_run"], true);
    let old = fixture.root.join("interrupted");
    assert!(!old.join("delivery.json").exists());
    assert_eq!(fs::read(old.join("artifacts/bin/app")).unwrap(), fixture.files["artifacts/bin/app"][..CHUNK]);
    old
}

#[test]
fn native_tls_reuses_interrupted_prefixes_and_prepared_builds_install_then_replay_offline() {
    let certificates = Certificates::new();
    for build in [false, true] {
        let fixture = Fixture::new();
        let old = interrupted(&fixture, &certificates);
        let before: BTreeMap<_, _> = fixture.files.keys().map(|path|
            (path.clone(), (fs::read(old.join(path)).unwrap(), fs::metadata(old.join(path)).unwrap()))).collect();
        let request_bytes = fs::read(fixture.bundle.join("request.json")).unwrap();
        let mut resumed = fixture.receiver("recovered", &certificates.pin(), Some(&certificates.server), Some(&old), build);
        let transfers = exchange(&fixture, &mut resumed, &certificates, "recovered", 2, Mode::Complete);
        assert!(resumed.wait().success(), "{}", String::from_utf8_lossy(&read_log(&resumed.stderr)));
        assert_eq!(transfers.reads, vec![("artifacts/bin/app".into(), CHUNK as u64), ("artifacts/bin/app".into(), (2 * CHUNK) as u64)]);
        let destination = fixture.root.join("recovered");
        let receipt = fs::read(destination.join("delivery.json")).unwrap();
        let inode = fs::metadata(destination.join("artifacts/bin/app")).unwrap().ino();
        for (path, (bytes, metadata)) in &before {
            assert_eq!(fs::read(old.join(path)).unwrap(), *bytes);
            let current = fs::metadata(old.join(path)).unwrap();
            assert_eq!((current.ino(), current.len(), current.mtime(), current.mtime_nsec()),
                (metadata.ino(), metadata.len(), metadata.mtime(), metadata.mtime_nsec()));
            assert_eq!(current.nlink(), 1);
            assert_ne!(current.ino(), fs::metadata(destination.join(path)).unwrap().ino());
        }
        assert_eq!(fs::metadata(destination.join("artifacts/bin/app")).unwrap().permissions().mode() & 0o777, 0o700);
        if build {
            for (name, bytes) in &fixture.files {
                if let Some(relative) = name.strip_prefix("artifacts/") {
                    assert_eq!(fs::read(fixture.root.join("installed").join(relative)).unwrap(), *bytes);
                }
            }
        }
        fs::rename(&old, fixture.root.join("retired-partial")).unwrap();
        let mut replay = fixture.receiver("recovered", &certificates.pin(), None, Some(&old), build);
        assert!(replay.wait().success(), "{}", String::from_utf8_lossy(&read_log(&replay.stderr)));
        assert!(!String::from_utf8_lossy(&read_log(&replay.stderr)).contains("worker-exec-listening"));
        assert_eq!(fs::read(destination.join("delivery.json")).unwrap(), receipt);
        assert_eq!(fs::read(fixture.bundle.join("request.json")).unwrap(), request_bytes);
        assert_eq!(fs::metadata(destination.join("artifacts/bin/app")).unwrap().ino(), inode);
    }
}

#[test]
fn valid_remote_tails_cannot_hide_corrupt_local_prefixes_or_install_partial_outputs() {
    let certificates = Certificates::new();
    let fixture = Fixture::new();
    let old = interrupted(&fixture, &certificates);
    let path = old.join("artifacts/bin/app");
    let mut corrupted = fs::read(&path).unwrap();
    corrupted[0] ^= 1;
    fs::write(&path, &corrupted).unwrap();
    let mut resumed = fixture.receiver("refused", &certificates.pin(), Some(&certificates.server), Some(&old), true);
    let transfers = exchange(&fixture, &mut resumed, &certificates, "refused", 2, Mode::CorruptPrefix);
    assert!(!resumed.wait().success());
    assert_eq!(transfers.acknowledgments, 0);
    assert_eq!(transfers.reads.len(), 2);
    let failure = resumed.failure();
    assert_eq!(failure["execution_may_have_run"], true);
    assert_eq!(failure["reexecute"], false);
    assert!(failure["detail"].as_str().unwrap().contains("complete file digest"));
    assert!(!fixture.root.join("refused/delivery.json").exists());
    assert!(!fixture.root.join("installed").exists());
    assert_eq!(fs::read(path).unwrap(), corrupted);
}

#[test]
fn usable_local_prefixes_never_allow_a_different_ca_valid_worker_key() {
    let certificates = Certificates::new();
    let fixture = Fixture::new();
    let old = interrupted(&fixture, &certificates);
    let bytes = fs::read(old.join("artifacts/bin/app")).unwrap();
    let mut receiver = fixture.receiver("wrong-key", &certificates.pin(), Some(&certificates.server), Some(&old), false);
    let address = receiver.listening();
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    runtime.block_on(async {
        asupersync::time::timeout(asupersync::time::wall_now(), Duration::from_secs(15), async {
            if let Ok(mut foreign) = connect_peer(&address, "localhost", &certificates.foreign).await {
                assert!(receive(&mut foreign.stream).await.is_err(), "wrong key must not receive an application challenge");
            }
        }).await.expect("wrong-key refusal deadline");
    });
    assert!(!receiver.wait().success());
    let failure = receiver.failure();
    assert_eq!(failure["execution_may_have_run"], true);
    assert!(failure["detail"].as_str().unwrap().contains("SPKI pin"), "{failure}");
    assert!(!fixture.root.join("wrong-key").exists());
    assert_eq!(fs::read(old.join("artifacts/bin/app")).unwrap(), bytes);
}
