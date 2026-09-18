//! Live files-v1 acceptance: a TCP peer drives the actual worker binary and
//! canonical rustc, downloads rlib/rmeta/dep-info, then uses the received rlib.
//! No cache publication, authenticated ATP, or wrapper compiler-skipping is
//! implied. The compilation case explicitly skips without canonical isolation.
#![cfg(target_os = "linux")]

use rabs_wkr::session::sha256_hex;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

struct OwnedChild {
    child: Child,
    // Keep isolated durable state alive until after the worker is reaped.
    _state: Option<tempfile::TempDir>,
}

impl OwnedChild {
    fn wait_until(&mut self, timeout: Duration) -> ExitStatus {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait().expect("child status") {
                return status;
            }
            assert!(Instant::now() < deadline, "child did not exit within test budget");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn connect_worker() -> (OwnedChild, BufReader<TcpStream>, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let state = tempfile::tempdir().unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_rabs-wkr"))
        .args(["--coordinator", &address, "--worker-id", "artifact-test", "--once"])
        .env("RABS_WORKER_STATE_DIR", state.path())
        .stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let mut worker = OwnedChild { child, _state: Some(state) };
    let deadline = Instant::now() + Duration::from_secs(15);
    let stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(worker.child.try_wait().unwrap().is_none(), "worker exited before connecting");
                assert!(Instant::now() < deadline, "worker connection timeout");
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("accept worker: {error}"),
        }
    };
    stream.set_read_timeout(Some(Duration::from_secs(120))).unwrap();
    stream.set_write_timeout(Some(Duration::from_secs(10))).unwrap();
    let writer = stream.try_clone().unwrap();
    let mut reader = BufReader::new(stream);
    let hello = receive(&mut reader);
    assert_eq!(hello["kind"], "worker-hello");
    assert!(hello["artifact_transfers"].as_array().unwrap().contains(&json!("files-v1")));
    (worker, reader, writer)
}

fn receive(reader: &mut impl BufRead) -> Value {
    let mut line = String::new();
    assert!(reader.read_line(&mut line).expect("read worker frame") != 0, "unexpected worker EOF");
    assert!(line.len() <= 1 << 20, "unbounded worker frame");
    serde_json::from_str(&line).expect("worker frame is JSON")
}

fn send(writer: &mut TcpStream, value: &Value) {
    writeln!(writer, "{value}").expect("send coordinator frame");
}

fn toolchain() -> PathBuf {
    let cargo = std::fs::canonicalize(std::env::var("CARGO").expect("CARGO set by Cargo")).unwrap();
    cargo.parent().and_then(Path::parent).expect("toolchain/bin/cargo").to_path_buf()
}

fn decode_hex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "odd byte encoding");
    text.as_bytes().chunks_exact(2).map(|pair| {
        u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).expect("byte hex")
    }).collect()
}

/// Independently implement the documented framing rather than trusting an
/// echoed manifest digest. The file order on the wire must be canonical too.
fn verify_manifest(manifest: &Value) {
    fn field(hasher: &mut Sha256, bytes: &[u8]) {
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }
    let files = manifest["files"].as_array().unwrap();
    let mut hasher = Sha256::new();
    field(&mut hasher, b"rabs.worker-artifact-manifest.v1");
    field(&mut hasher, manifest["unit"].as_str().unwrap().as_bytes());
    hasher.update((files.len() as u64).to_be_bytes());
    let mut prior: Option<&str> = None;
    let mut total = 0_u64;
    for file in files {
        let name = file["name"].as_str().unwrap();
        assert!(prior.is_none_or(|previous| previous < name));
        prior = Some(name);
        let size = file["bytes"].as_u64().unwrap();
        total = total.checked_add(size).unwrap();
        field(&mut hasher, name.as_bytes());
        hasher.update([u8::from(file["executable"].as_bool().unwrap())]);
        hasher.update(size.to_be_bytes());
        field(&mut hasher, file["sha256"].as_str().unwrap().as_bytes());
    }
    assert_eq!(manifest["total_bytes"], total);
    let expected: String = hasher.finalize().iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(manifest["manifest_sha256"], expected);
}

fn fetch_artifact(reader: &mut impl BufRead, writer: &mut TcpStream, manifest: &Value, file: &Value) -> Vec<u8> {
    let size = file["bytes"].as_u64().unwrap();
    // These tiny fixtures must not hide an unexpectedly huge retained artifact.
    assert!(size < 16 * 1024 * 1024);
    let mut bytes = Vec::new();
    loop {
        let offset = bytes.len() as u64;
        let read = json!({"kind": "artifact-read", "request_id": 42, "name": file["name"],
            "offset": offset, "max_bytes": 4096});
        send(writer, &read);
        let chunk = receive(reader);
        assert_eq!(chunk["kind"], "artifact-chunk", "{chunk}");
        assert_eq!(chunk["request_id"], 42);
        assert_eq!(chunk["name"], file["name"]);
        assert_eq!(chunk["offset"], offset);
        assert_eq!(chunk["total_bytes"], size);
        assert_eq!(chunk["sha256"], file["sha256"]);
        assert_eq!(chunk["executable"], file["executable"]);
        assert_eq!(chunk["manifest_sha256"], manifest["manifest_sha256"]);
        let data = decode_hex(chunk["data_hex"].as_str().unwrap());
        assert!(data.len() <= 4096);
        assert_eq!(chunk["chunk_sha256"], sha256_hex(&data));
        assert_eq!(chunk["next_offset"], offset + data.len() as u64);
        if offset == 0 {
            send(writer, &read);
            assert_eq!(receive(reader), chunk, "retrying a range must return the same bytes");
        }
        bytes.extend_from_slice(&data);
        let eof = bytes.len() as u64 == size;
        assert_eq!(chunk["eof"], eof);
        if eof { break; }
        assert!(!data.is_empty(), "range stalled before EOF");
    }
    assert_eq!(bytes.len() as u64, size);
    assert_eq!(sha256_hex(&bytes), file["sha256"].as_str().unwrap());
    bytes
}

#[test]
fn canonical_compile_returns_usable_rlib_rmeta_and_dep_info_before_acknowledged_exit() {
    if !rabs_sandbox::canonical_namespace::HostIsolationSupport::probe().missing_for_canonical().is_empty() {
        eprintln!("SKIP: canonical namespace unavailable; artifact TCP compilation not exercised");
        return;
    }
    let source = tempfile::tempdir().unwrap();
    std::fs::write(source.path().join("lib.rs"), "pub fn answer() -> u32 { 42 }\n").unwrap();
    let toolchain = toolchain();
    let (mut worker, mut reader, mut writer) = connect_worker();
    send(&mut writer, &json!({"kind": "session-ok", "artifact_transfer": "files-v1"}));
    // The individual --emit=kind=path outputs are explicit. The worker must
    // not rewrite argv or guess a Cargo output set from the crate name.
    let request = json!({
        "kind": "canonical-exec", "request_id": 42, "timeout_ms": 60000,
        "program": "/__rabs/toolchain/bin/rustc",
        "args": ["--edition=2024", "--crate-name", "artifact_demo", "--crate-type=rlib",
            "/__rabs/workspace/lib.rs",
            "--emit=link=/__rabs/out/dep/libartifact_demo.rlib,metadata=/__rabs/out/dep/libartifact_demo.rmeta,dep-info=/__rabs/out/dep/artifact_demo.d"],
        "toolchain_backing": toolchain, "workspace_backing": source.path(),
        "artifacts": {"unit": "dep", "files": ["libartifact_demo.rmeta", "artifact_demo.d", "libartifact_demo.rlib"]}
    });
    send(&mut writer, &request);
    let result = receive(&mut reader);
    assert_eq!(result["kind"], "exec-result", "{result}");
    assert_eq!(result["executed"], true, "{result}");
    assert_eq!(result["exit_code"], 0, "{result}");
    assert!(result["stop_reason"].is_null());
    assert_eq!(result["artifact_transfer"], "files-v1");
    assert_eq!(result["artifact_ack_required"], true);
    let manifest = &result["artifact_manifest"];
    verify_manifest(manifest);
    let names: BTreeSet<_> = manifest["files"].as_array().unwrap().iter()
        .map(|file| file["name"].as_str().unwrap()).collect();
    assert_eq!(names, BTreeSet::from(["artifact_demo.d", "libartifact_demo.rlib", "libartifact_demo.rmeta"]));
    assert!(worker.child.try_wait().unwrap().is_none(), "--once lost files before acceptance");

    let received = tempfile::tempdir().unwrap();
    for file in manifest["files"].as_array().unwrap() {
        let bytes = fetch_artifact(&mut reader, &mut writer, manifest, file);
        let name = file["name"].as_str().unwrap();
        if name.ends_with(".rlib") { assert!(bytes.starts_with(b"!<arch>\n")); }
        if name.ends_with(".rmeta") { assert!(!bytes.is_empty()); }
        if name.ends_with(".d") {
            assert!(std::str::from_utf8(&bytes).unwrap().contains("/__rabs/workspace/lib.rs"));
        }
        std::fs::write(received.path().join(name), bytes).unwrap();
    }
    // Use the downloaded rlib, not a local recompilation of its source. This
    // catches returning syntactically plausible but unusable artifact content.
    std::fs::write(received.path().join("consumer.rs"),
        "fn main() { assert_eq!(artifact_demo::answer(), 42); }\n").unwrap();
    let binary = received.path().join("consumer");
    let child = Command::new(toolchain.join("bin/rustc"))
        .arg("--edition=2024").arg(received.path().join("consumer.rs"))
        .arg("--extern").arg(format!("artifact_demo={}", received.path().join("libartifact_demo.rlib").display()))
        .arg("-o").arg(&binary).stdout(Stdio::null()).stderr(Stdio::inherit()).spawn().unwrap();
    let mut compiler = OwnedChild { child, _state: None };
    assert!(compiler.wait_until(Duration::from_secs(60)).success());
    let child = Command::new(binary).stdout(Stdio::null()).stderr(Stdio::inherit()).spawn().unwrap();
    let mut consumer = OwnedChild { child, _state: None };
    assert!(consumer.wait_until(Duration::from_secs(10)).success());

    let ack = json!({"kind": "artifact-ack", "request_id": 42,
        "manifest_sha256": manifest["manifest_sha256"], "total_bytes": manifest["total_bytes"]});
    let mut wrong_ack = ack.clone(); wrong_ack["manifest_sha256"] = json!("0".repeat(64));
    send(&mut writer, &wrong_ack);
    assert_eq!(receive(&mut reader)["reason"], "artifact-ack-mismatch");
    let mut next = request.clone(); next["request_id"] = json!(43);
    send(&mut writer, &next);
    assert_eq!(receive(&mut reader)["reason"], "artifacts-unacknowledged");
    assert!(worker.child.try_wait().unwrap().is_none());
    send(&mut writer, &ack);
    assert_eq!(receive(&mut reader)["kind"], "artifact-acknowledged");
    assert!(worker.wait_until(Duration::from_secs(10)).success());
}

#[test]
fn unnegotiated_artifacts_are_refused_before_launch_and_session_remains_usable() {
    // No isolation requirement: rejection occurs before any execution thread or
    // backing directory is created. Nonexistent paths cannot mask a silent run.
    let (mut worker, mut reader, mut writer) = connect_worker();
    send(&mut writer, &json!({"kind": "session-ok"}));
    send(&mut writer, &json!({"kind": "canonical-exec", "request_id": 1,
        "program": "true", "args": [], "toolchain_backing": "/nonexistent-artifact-tc",
        "workspace_backing": "/nonexistent-artifact-workspace",
        "artifacts": {"unit": "dep", "files": ["lib.rlib"]}}));
    let refusal = receive(&mut reader);
    assert_eq!(refusal["kind"], "error");
    assert!(refusal["reason"].as_str().unwrap().contains("artifact transfer not negotiated"));
    send(&mut writer, &json!({"kind": "ping"}));
    let heartbeat = receive(&mut reader);
    assert_eq!(heartbeat["kind"], "heartbeat");
    assert!(heartbeat["active_request_id"].is_null());
    assert!(heartbeat["pending_artifact_request_id"].is_null());
    send(&mut writer, &json!({"kind": "request-status", "request_id": 1}));
    let status = receive(&mut reader);
    assert_eq!(status["status"], "unknown", "unnegotiated files must not acquire durable admission");
    assert!(status["high_water"].is_null());
    drop(reader); drop(writer);
    assert!(worker.wait_until(Duration::from_secs(10)).success());
}
