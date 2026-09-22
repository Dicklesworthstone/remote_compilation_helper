//! Controlled-host acceptance for the actual worker's complete Cargo output
//! capture and restart recovery. This runs Cargo/rustc inside the canonical
//! namespace from uploaded sibling repositories; nothing is synthetically seeded
//! into the result spool. The client is a bounded loopback fixture, NOT an
//! authenticated fleet coordinator or an action-cache publication path.
//!
//! Run explicitly on a canonical-capable Linux worker:
//! cargo test -p rabs-wkr --test cargo_tree_worker_linux -- --ignored
//! Missing isolation fails this gate; it never becomes a passing skip.
#![cfg(target_os = "linux")]

use rabs_sandbox::artifact_tree::{MAX_TREE_FILES, TREE_FILES_VERSION, validate_tree_names};
use rabs_sandbox::source_transfer::{SourceFile, SourceManifest};
use rabs_wkr::session::sha256_hex;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const REQUEST_ID: u64 = 42;
const WORKER_ID: &str = "cargo-tree-test";
const MAX_FRAME: usize = 1024 * 1024;
const MAX_FIXTURE_BYTES: u64 = 128 * 1024 * 1024;

struct Worker(Child);
impl Worker {
    fn start(address: &str, state: &Path) -> Self {
        Self(Command::new(env!("CARGO_BIN_EXE_rabs-wkr"))
            .args(["--coordinator", address, "--worker-id", WORKER_ID, "--once"])
            .env("RABS_WORKER_STATE_DIR", state)
            .env_remove("RABS_WORKER_TLS_CA")
            .env_remove("RABS_WORKER_TLS_CERT")
            .env_remove("RABS_WORKER_TLS_KEY")
            .env_remove("RABS_WORKER_TLS_SERVER_NAME")
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::inherit())
            .spawn().expect("real worker binary"))
    }

    fn wait_success(&mut self) {
        let until = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                assert!(status.success(), "worker exited unsuccessfully: {status}");
                return;
            }
            assert!(Instant::now() < until, "worker did not finish after complete acceptance");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn crash_after_completed_result(&mut self) {
        // Called only after an executed, fully drained result was delivered.
        self.0.kill().unwrap();
        self.0.wait().unwrap();
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        // Peer owners are declared after the worker and therefore close first.
        // Give the existing session-loss cleanup path time to drain on failures.
        let until = Instant::now() + Duration::from_secs(5);
        while Instant::now() < until {
            if self.0.try_wait().ok().flatten().is_some() { return; }
            std::thread::sleep(Duration::from_millis(10));
        }
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Peer {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
    until: Instant,
    sent_execution: usize,
}
impl Peer {
    fn accept(listener: &TcpListener, worker: &mut Worker) -> Self {
        let until = Instant::now() + Duration::from_secs(15);
        let stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(worker.0.try_wait().unwrap().is_none(), "worker exited before connection");
                    assert!(Instant::now() < until, "worker connection timeout");
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("worker accept: {error}"),
            }
        };
        stream.set_nodelay(true).unwrap();
        Self { writer: stream.try_clone().unwrap(), reader: BufReader::new(stream),
            until: Instant::now() + Duration::from_secs(180), sent_execution:0 }
    }

    fn remaining(&self) -> Duration {
        self.until.checked_duration_since(Instant::now())
            .filter(|left| !left.is_zero()).expect("whole fixture exchange deadline")
    }

    fn send(&mut self, value: &Value) {
        let mut bytes = serde_json::to_vec(value).unwrap();
        assert!(bytes.len() <= MAX_FRAME);
        if value["kind"] == "canonical-exec" { self.sent_execution += 1; }
        bytes.push(b'\n');
        self.writer.set_write_timeout(Some(self.remaining())).unwrap();
        self.writer.write_all(&bytes).unwrap();
    }

    fn receive(&mut self) -> Value {
        loop {
            let mut line = Vec::new();
            loop {
                self.reader.get_ref().set_read_timeout(Some(self.remaining())).unwrap();
                let available = self.reader.fill_buf().expect("read worker frame");
                assert!(!available.is_empty(), "unexpected worker disconnect");
                let end = available.iter().position(|byte| *byte == b'\n');
                let count = end.map_or(available.len(), |end| end + 1);
                assert!(line.len() + count <= MAX_FRAME + 1, "oversized worker frame");
                line.extend_from_slice(&available[..count]);
                self.reader.consume(count);
                if end.is_some() { break; }
            }
            let value: Value = serde_json::from_slice(&line).expect("worker JSON");
            if value["kind"] != "heartbeat" { return value; }
            assert_eq!(value["worker_id"], WORKER_ID);
        }
    }

    fn admit(&mut self, upload: bool) -> Value {
        let hello = self.receive();
        assert_eq!(hello["kind"], "worker-hello");
        assert_eq!(hello["worker_id"], WORKER_ID);
        assert_eq!(hello["canonical"], true);
        assert!(hello["result_retentions"].as_array().unwrap().contains(&json!("durable-result-v1")));
        let mut grant = json!({"kind":"session-ok", "output_transfer":"ranges-v1",
            "artifact_transfer":"files-v1", "recovery_protocol":"request-journal-v1",
            "result_retention":"durable-result-v1"});
        if upload {
            assert!(hello["command_contexts"].as_array().unwrap().contains(&json!("env-cwd-v1")));
            assert!(hello["source_transfers"].as_array().unwrap().contains(&json!("source-files-v1")));
            grant["source_transfer"] = json!("source-files-v1");
        }
        self.send(&grant);
        hello
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn decode_hex(value: &str) -> Vec<u8> {
    assert!(value.len().is_multiple_of(2));
    value.as_bytes().chunks_exact(2).map(|pair| {
        u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap()
    }).collect()
}
fn toolchain() -> PathBuf {
    let cargo = fs::canonicalize(std::env::var_os("CARGO").expect("Cargo test runner")).unwrap();
    cargo.parent().and_then(Path::parent).expect("toolchain/bin/cargo").to_path_buf()
}

fn source_files() -> BTreeMap<String, Vec<u8>> {
    [
        ("app/Cargo.toml", "[package]\nname=\"closure_app\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[workspace]\n[dependencies]\nclosure_dep={path=\"../dep\"}\n"),
        ("app/Cargo.lock", "version = 4\n\n[[package]]\nname = \"closure_app\"\nversion = \"0.1.0\"\ndependencies = [\"closure_dep\"]\n\n[[package]]\nname = \"closure_dep\"\nversion = \"0.1.0\"\n"),
        ("app/src/main.rs", "fn main() { println!(\"{}:{}\", closure_dep::answer(), env!(\"BUILD_LABEL\")); }\n"),
        ("dep/Cargo.toml", "[package]\nname=\"closure_dep\"\nversion=\"0.1.0\"\nedition=\"2021\"\n"),
        ("dep/src/lib.rs", "pub fn answer() -> u32 { 42 }\n"),
    ].into_iter().map(|(path, bytes)| (path.to_owned(), bytes.as_bytes().to_vec())).collect()
}

fn upload(peer: &mut Peer, files: &BTreeMap<String, Vec<u8>>) -> Value {
    let manifest = SourceManifest::new(files.iter().map(|(path, bytes)| SourceFile {
        path:path.clone(), len:bytes.len() as u64, sha256:Sha256::digest(bytes).into(), executable:false,
    }).collect()).unwrap();
    let value = json!({"manifest_sha256":hex(&manifest.digest()),
        "files":manifest.files().iter().map(|file| json!({"path":file.path,
            "bytes":file.len, "sha256":hex(&file.sha256), "executable":file.executable})).collect::<Vec<_>>()});
    peer.send(&json!({"kind":"source-begin", "request_id":REQUEST_ID, "manifest":value}));
    let ready = peer.receive();
    assert_eq!(ready["kind"], "source-ready", "{ready}");
    assert_eq!(ready["sealed"], false);
    assert_eq!(ready["request_id"], REQUEST_ID);
    assert_eq!(ready["manifest_sha256"], value["manifest_sha256"]);
    for (path, bytes) in files {
        peer.send(&json!({"kind":"source-chunk", "request_id":REQUEST_ID,
            "manifest_sha256":value["manifest_sha256"], "path":path, "offset":0,
            "data_hex":hex(bytes), "chunk_sha256":sha256_hex(bytes)}));
        let ack = peer.receive();
        assert_eq!(ack["kind"], "source-chunk-accepted", "{ack}");
        assert_eq!(ack["request_id"], REQUEST_ID);
        assert_eq!(ack["path"], *path);
        assert_eq!(ack["manifest_sha256"], value["manifest_sha256"]);
        assert_eq!(ack["next_offset"], bytes.len());
    }
    peer.send(&json!({"kind":"source-seal", "request_id":REQUEST_ID, "manifest_sha256":value["manifest_sha256"]}));
    let ready = peer.receive();
    assert_eq!(ready["kind"], "source-ready", "{ready}");
    assert_eq!(ready["sealed"], true);
    assert_eq!(ready["request_id"], REQUEST_ID);
    assert_eq!(ready["manifest_sha256"], value["manifest_sha256"]);
    value
}

fn verify_manifest(value: &Value) {
    fn field(hash: &mut Sha256, bytes: &[u8]) { hash.update((bytes.len() as u64).to_be_bytes()); hash.update(bytes); }
    let rows = value["files"].as_array().unwrap();
    assert!(rows.len() > 1 && rows.len() <= MAX_TREE_FILES);
    let names: Vec<_> = rows.iter().map(|row| row["name"].as_str().unwrap()).collect();
    let ordered = validate_tree_names(names.clone()).unwrap();
    assert!(ordered.iter().map(String::as_str).eq(names));
    assert!(ordered.contains("debug/closure_app"));
    assert!(ordered.iter().any(|name| name.starts_with("debug/deps/")));
    assert!(ordered.iter().any(|name| name.starts_with("debug/.fingerprint/")));
    let mut hash = Sha256::new();
    field(&mut hash, b"rabs.worker-artifact-manifest.v1");
    field(&mut hash, b"build");
    hash.update((rows.len() as u64).to_be_bytes());
    let mut total = 0_u64;
    for row in rows {
        field(&mut hash, row["name"].as_str().unwrap().as_bytes());
        hash.update([u8::from(row["executable"].as_bool().unwrap())]);
        let len = row["bytes"].as_u64().unwrap();
        hash.update(len.to_be_bytes());
        field(&mut hash, row["sha256"].as_str().unwrap().as_bytes());
        total = total.checked_add(len).unwrap();
    }
    assert!(total <= MAX_FIXTURE_BYTES);
    assert_eq!(value["unit"], "build");
    assert_eq!(value["total_bytes"], total);
    assert_eq!(value["manifest_sha256"], hex(&hash.finalize()));
}

fn download(peer: &mut Peer, name: &str, len: u64, digest: &str, manifest: Option<(&Value, bool)>) -> Vec<u8> {
    assert!(len <= MAX_FIXTURE_BYTES);
    let mut bytes = Vec::new();
    loop {
        let offset = bytes.len() as u64;
        let mut request = json!({"kind":if manifest.is_some() {"artifact-read"} else {"output-read"},
            "request_id":REQUEST_ID, "offset":offset, "max_bytes":65536});
        request[if manifest.is_some() {"name"} else {"stream"}] = json!(name);
        peer.send(&request);
        let reply = peer.receive();
        assert_eq!(reply["kind"], if manifest.is_some() {"artifact-chunk"} else {"output-chunk"});
        assert_eq!(reply["request_id"], REQUEST_ID);
        assert_eq!(reply[if manifest.is_some() {"name"} else {"stream"}], name);
        assert_eq!(reply["offset"], offset);
        assert_eq!(reply["total_bytes"], len);
        assert_eq!(reply["sha256"], digest);
        if let Some((manifest, executable)) = manifest {
            assert_eq!(reply["manifest_sha256"], manifest["manifest_sha256"]);
            assert_eq!(reply["executable"], executable);
        }
        let data = decode_hex(reply["data_hex"].as_str().unwrap());
        assert!(data.len() <= 65536 && data.len() as u64 <= len - offset);
        assert_eq!(reply["chunk_sha256"], sha256_hex(&data));
        let next = offset + data.len() as u64;
        assert_eq!(reply["next_offset"], next);
        assert_eq!(reply["eof"], next == len);
        bytes.extend_from_slice(&data);
        if next == len { break; }
        assert!(!data.is_empty(), "no range progress");
    }
    assert_eq!(sha256_hex(&bytes), digest);
    bytes
}

#[test]
#[ignore = "requires canonical-capable Linux and a complete local Rust toolchain; run explicitly"]
fn real_cargo_tree_survives_worker_restart_and_downloaded_binary_uses_uploaded_dependency() {
    let missing = rabs_sandbox::canonical_namespace::HostIsolationSupport::probe().missing_for_canonical();
    assert!(missing.is_empty(), "canonical isolation is required, missing {missing:?}");
    let root = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let state = root.path().join("state");
    let mut worker = Worker::start(&address, &state);
    let mut peer = Peer::accept(&listener, &mut worker);
    let hello = peer.admit(true);
    let mut files = source_files();
    let source = upload(&mut peer, &files);
    // A later client-side edit must not change already-sealed execution inputs.
    files.insert("dep/src/lib.rs".into(), b"pub fn answer() -> u32 { 99 }\n".to_vec());
    let request = json!({"kind":"canonical-exec", "request_id":REQUEST_ID, "timeout_ms":60000,
        "program":"/__rabs/toolchain/bin/cargo", "args":["build", "--frozen", "--jobs=1"],
        "toolchain_backing":toolchain(), "source_manifest":source, "jobserver_grant":1,
        "command_context":{"version":"env-cwd-v1", "cwd":"/__rabs/workspace/app",
            "env":{"CARGO_TARGET_DIR":"/__rabs/out/build", "CARGO_INCREMENTAL":"0", "BUILD_LABEL":"exact\n雪"}},
        "artifacts":{"unit":"build", "files":["debug/closure_app"], "tree":TREE_FILES_VERSION}});
    peer.send(&request);
    let first = peer.receive();
    assert_eq!(first["kind"], "exec-result", "{first}");
    assert_eq!(first["executed"], true, "{first}");
    assert_eq!(first["exit_code"], 0, "{first}");
    assert_eq!(first["residual_group_members"], 0);
    assert!(first["stop_reason"].is_null());
    assert_eq!(first["result_retention"], "durable-result-v1");
    verify_manifest(&first["artifact_manifest"]);
    assert_eq!(peer.sent_execution, 1);
    assert!(state.join("retained-result/manifest.json").is_file());
    // No byte acceptance was sent. Recovery must use an actual successful
    // compile's durable captures, not a preseeded fixture or a second launch.
    worker.crash_after_completed_result();
    drop(peer);
    drop(worker);
    drop(files);

    let mut worker = Worker::start(&address, &state);
    let mut peer = Peer::accept(&listener, &mut worker);
    let restarted = peer.admit(false);
    assert!(restarted["boot_generation"].as_u64().unwrap() > hello["boot_generation"].as_u64().unwrap());
    assert_ne!(restarted["incarnation"], hello["incarnation"]);
    assert_eq!(restarted["request_high_water"], REQUEST_ID);
    peer.send(&json!({"kind":"result-resume", "request_id":REQUEST_ID, "request":request}));
    let result = peer.receive();
    assert_eq!(result["kind"], "exec-result", "{result}");
    assert_eq!(result["resumed"], true);
    for field in ["exit_code", "executed", "stop_reason", "stdout_bytes", "stdout_sha256",
        "stderr_bytes", "stderr_sha256", "artifact_manifest", "retained_result_sha256"] {
        assert_eq!(result[field], first[field], "restart changed {field}");
    }
    for stream in ["stdout", "stderr"] {
        let bytes = download(&mut peer, stream, result[format!("{stream}_bytes")].as_u64().unwrap(),
            result[format!("{stream}_sha256")].as_str().unwrap(), None);
        assert_eq!(sha256_hex(&bytes), first[format!("{stream}_sha256")]);
    }
    let destination = root.path().join("downloaded");
    fs::create_dir(&destination).unwrap();
    let manifest = &result["artifact_manifest"];
    let mut executable_path = None;
    for file in manifest["files"].as_array().unwrap() {
        let name = file["name"].as_str().unwrap();
        let executable = file["executable"].as_bool().unwrap();
        let bytes = download(&mut peer, name, file["bytes"].as_u64().unwrap(),
            file["sha256"].as_str().unwrap(), Some((manifest, executable)));
        let path = destination.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut output = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path).unwrap();
        output.write_all(&bytes).unwrap();
        output.set_permissions(fs::Permissions::from_mode(if executable {0o700} else {0o600})).unwrap();
        output.sync_all().unwrap();
        assert_eq!(output.metadata().unwrap().nlink(), 1, "downloaded aliases must be independent files");
        if name == "debug/closure_app" { assert!(executable); executable_path = Some(path); }
    }
    let report = root.path().join("program-output");
    let child = Command::new(executable_path.expect("required output"))
        .stdin(Stdio::null()).stdout(File::create(&report).unwrap()).stderr(Stdio::inherit()).spawn().unwrap();
    let mut binary = Worker(child);
    binary.wait_success();
    assert_eq!(fs::read(report).unwrap(), "42:exact\n雪\n".as_bytes());
    assert!(worker.0.try_wait().unwrap().is_none(), "worker discarded unacknowledged output");
    peer.send(&json!({"kind":"output-ack", "request_id":REQUEST_ID,
        "stdout_bytes":result["stdout_bytes"], "stdout_sha256":result["stdout_sha256"],
        "stderr_bytes":result["stderr_bytes"], "stderr_sha256":result["stderr_sha256"]}));
    assert_eq!(peer.receive()["kind"], "output-acknowledged");
    assert!(worker.0.try_wait().unwrap().is_none(), "remaining artifact acceptance was skipped");
    peer.send(&json!({"kind":"artifact-ack", "request_id":REQUEST_ID,
        "manifest_sha256":manifest["manifest_sha256"], "total_bytes":manifest["total_bytes"]}));
    assert_eq!(peer.receive()["kind"], "artifact-acknowledged");
    worker.wait_success();
    assert_eq!(peer.sent_execution, 0, "recovery must not dispatch compilation or source upload");
    assert!(!state.join("retained-result").exists());
}
