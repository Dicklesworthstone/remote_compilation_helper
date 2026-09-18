//! S5 diagnostic delivery through the actual worker binary and a TCP peer.
//! This checks post-execution ranges, not live pipe streaming or ATP resume.
#![cfg(target_os = "linux")]

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Worker(Child);

impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn send(writer: &mut TcpStream, value: Value) {
    writeln!(writer, "{value}").unwrap();
}

fn receive(reader: &mut impl BufRead) -> Value {
    let mut line = String::new();
    assert_ne!(reader.read_line(&mut line).unwrap(), 0, "worker closed before output ACK");
    serde_json::from_str(&line).unwrap()
}

fn decode_hex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    text.as_bytes().chunks_exact(2).map(|pair| {
        u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap()
    }).collect()
}

#[test]
fn real_worker_delivers_complete_output_and_once_waits_for_ack() {
    if !rabs_sandbox::canonical_namespace::HostIsolationSupport::probe()
        .missing_for_canonical().is_empty()
    {
        eprintln!("SKIP: canonical namespace unavailable; real output transfer not exercised");
        return;
    }
    let cargo = std::env::var("CARGO").expect("Cargo test sets CARGO");
    let toolchain = std::path::Path::new(&cargo).parent()
        .and_then(std::path::Path::parent).expect("<toolchain>/bin/cargo");
    let workspace = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let mut worker = Worker(Command::new(env!("CARGO_BIN_EXE_rabs-wkr"))
        .args(["--coordinator", &listener.local_addr().unwrap().to_string(),
            "--worker-id", "output-test", "--once"])
        .stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(10);
    let stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "worker did not connect");
                assert!(worker.0.try_wait().unwrap().is_none(), "worker exited before connect");
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("accept worker: {error}"),
        }
    };
    stream.set_read_timeout(Some(Duration::from_secs(120))).unwrap();
    stream.set_write_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut writer = stream.try_clone().unwrap();
    let mut reader = BufReader::new(stream);
    let hello = receive(&mut reader);
    assert_eq!(hello["kind"], "worker-hello");
    assert_eq!(hello["output_transfers"], json!(["ranges-v1"]));
    send(&mut writer, json!({"kind": "session-ok", "output_transfer": "ranges-v1"}));
    send(&mut writer, json!({
        "kind": "canonical-exec", "request_id": 42,
        "program": "/__rabs/toolchain/bin/rustc", "args": ["--print", "sysroot"],
        "toolchain_backing": toolchain, "workspace_backing": workspace.path(),
    }));
    let result = receive(&mut reader);
    assert_eq!(result["kind"], "exec-result");
    assert_eq!(result["exit_code"], 0);
    assert_eq!(result["executed"], true);
    assert_eq!(result["output_ack_required"], true);
    assert_eq!(result["output_transfer"], "ranges-v1");
    assert!(worker.0.try_wait().unwrap().is_none(), "--once exited before retrieval");

    let read = |stream: &str, offset: u64| json!({
        "kind": "output-read", "request_id": 42,
        "stream": stream, "offset": offset, "max_bytes": 8,
    });
    let mut restored = Vec::new();
    let mut first_chunk = None;
    loop {
        let offset = restored.len() as u64;
        send(&mut writer, read("stdout", offset));
        let chunk = receive(&mut reader);
        assert_eq!(chunk["kind"], "output-chunk");
        assert_eq!(chunk["request_id"], 42);
        assert_eq!(chunk["stream"], "stdout");
        assert_eq!(chunk["offset"], offset);
        assert_eq!(chunk["total_bytes"], result["stdout_bytes"]);
        assert_eq!(chunk["sha256"], result["stdout_sha256"]);
        let bytes = decode_hex(chunk["data_hex"].as_str().unwrap());
        assert!(bytes.len() <= 8);
        assert_eq!(chunk["chunk_sha256"], rabs_wkr::session::sha256_hex(&bytes));
        restored.extend_from_slice(&bytes);
        assert_eq!(chunk["next_offset"], restored.len() as u64);
        if offset == 0 {
            first_chunk = Some(chunk.clone());
        }
        if chunk["eof"] == true {
            break;
        }
        assert!(!bytes.is_empty(), "non-final range must make progress");
        assert!(restored.len() <= 1024, "unexpected sysroot output size");
    }
    assert_eq!(restored, b"/__rabs/toolchain\n");
    assert_eq!(result["stdout_sha256"], rabs_wkr::session::sha256_hex(&restored));
    send(&mut writer, read("stdout", 0));
    assert_eq!(receive(&mut reader), first_chunk.unwrap(), "retry must return identical range");
    send(&mut writer, read("stderr", 0));
    let stderr = receive(&mut reader);
    assert_eq!(stderr["eof"], true);
    assert_eq!(stderr["data_hex"], "");
    assert_eq!(result["stderr_bytes"], 0);
    assert_eq!(result["stderr_sha256"], rabs_wkr::session::sha256_hex(b""));

    let mut ack = json!({
        "kind": "output-ack", "request_id": 42,
        "stdout_bytes": restored.len() as u64, "stderr_bytes": 0,
        "stdout_sha256": rabs_wkr::session::sha256_hex(&restored),
        "stderr_sha256": rabs_wkr::session::sha256_hex(b""),
    });
    ack["stdout_bytes"] = json!(0);
    send(&mut writer, ack.clone());
    assert_eq!(receive(&mut reader)["reason"], "output-ack-mismatch");
    send(&mut writer, json!({"kind": "ping"}));
    assert_eq!(receive(&mut reader)["pending_output_request_id"], 42);
    ack["stdout_bytes"] = json!(restored.len() as u64);
    send(&mut writer, ack);
    assert_eq!(receive(&mut reader)["kind"], "output-acknowledged");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = worker.0.try_wait().unwrap() {
            assert_eq!(status.code(), Some(0));
            break;
        }
        assert!(Instant::now() < deadline, "--once did not exit after ACK");
        std::thread::sleep(Duration::from_millis(10));
    }
}
