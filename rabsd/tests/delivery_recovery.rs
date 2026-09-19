//! Exercise recovery against receipts written by the REAL delivery receiver,
//! including the binary command path. No compiler or worker is executed.
#![cfg(unix)]

use rabsd::coord::delivery_recovery::{DeliveryTrust, recover_existing_delivery};
use rabsd::coord::worker_delivery::{
    Delivery, MAX_FRAME_BYTES, WorkerAuthentication, WorkerPeer, receive_execution,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::fs;
use std::io;
use std::net::TcpListener;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;
use std::process::Command;

const PIN: [u8; 32] = [0x11; 32];
const MANIFEST: &str = "548324c3a5c96511944c6ec6af94ee9bbb6683170bb0143f9d99cd192f80bfd6";

fn hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect()
}

fn request() -> Value {
    json!({"kind":"canonical-exec","request_id":7,"program":"rustc","args":["lib.rs"],
        "toolchain_backing":"/tc","workspace_backing":"/ws",
        "artifacts":{"unit":"dep","files":["a"]}})
}

fn chunk(name: &str, bytes: &[u8], artifact: bool) -> Value {
    let mut value = json!({"kind":if artifact {"artifact-chunk"} else {"output-chunk"},
        "request_id":7,"offset":0,"next_offset":bytes.len(),"total_bytes":bytes.len(),
        "sha256":hash(bytes),"chunk_sha256":hash(bytes),"eof":true,
        "data_hex":bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()});
    value[if artifact {"name"} else {"stream"}] = json!(name);
    if artifact {
        value["executable"] = json!(false);
        value["manifest_sha256"] = json!(MANIFEST);
    }
    value
}

struct Peer {
    replies: VecDeque<Value>,
    authenticated: bool,
    executions: usize,
}

impl WorkerPeer for Peer {
    fn send(&mut self, value: &Value) -> io::Result<()> {
        if value["kind"] == "canonical-exec" {
            self.executions += 1;
            assert_eq!(self.executions, 1);
        }
        if value["kind"] == "output-ack" {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "lost final ACK"));
        }
        Ok(())
    }

    fn receive(&mut self) -> io::Result<Value> {
        self.replies.pop_front().ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
    }

    fn authentication(&self) -> Option<WorkerAuthentication> {
        self.authenticated.then_some(WorkerAuthentication {
            spki_sha256: PIN,
            session_id: 17,
            identity_generation: 1,
        })
    }
}

fn delivered(root: &Path, exit: i32, stop: Option<&str>, authenticated: bool) -> Delivery {
    let stdout = b"diagnostic\0\xff";
    let successful = exit == 0 && stop.is_none();
    let manifest = json!({"unit":"dep","files":[{
        "name":"a","bytes":4,"sha256":hash(b"A\0\xffB"),"executable":false}],
        "total_bytes":4,"manifest_sha256":MANIFEST});
    let mut replies = VecDeque::from([
        json!({"kind":"worker-hello","worker_id":"worker","canonical":true,"slots":4,
            "boot_generation":1,"incarnation":"00000000000000000000000000000001",
            "request_high_water":null,"recovery_protocols":["request-journal-v1"],
            "output_transfers":["ranges-v1"],"artifact_transfers":["files-v1"]}),
        json!({"kind":"exec-result","request_id":7,"executed":true,"exit_code":exit,
            "residual_group_members":0,"stop_reason":stop,
            "output_transfer":"ranges-v1","output_ack_required":true,
            "stdout_bytes":stdout.len(),"stdout_sha256":hash(stdout),
            "stderr_bytes":0,"stderr_sha256":hash(b""),
            "artifact_transfer":"files-v1","artifact_ack_required":successful,
            "artifact_manifest":if successful {manifest} else {Value::Null}}),
        chunk("stdout", stdout, false),
        chunk("stderr", b"", false),
    ]);
    if successful {
        replies.push_back(chunk("a", b"A\0\xffB", true));
    }
    let mut peer = Peer { replies, authenticated, executions: 0 };
    let delivery = receive_execution(&mut peer, &request(), "worker", &root.join("delivery")).unwrap();
    assert_eq!(peer.executions, 1);
    assert!(!delivery.acknowledgments_confirmed);
    delivery
}

fn recover(delivery: &Delivery, trust: DeliveryTrust) -> Result<Option<Delivery>, impl std::fmt::Debug> {
    recover_existing_delivery(&request(), "worker", &delivery.directory, trust)
}

fn edit_receipt(delivery: &Delivery, edit: impl FnOnce(&mut Value)) {
    let path = delivery.directory.join("delivery.json");
    let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    edit(&mut value);
    fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
}

#[test]
fn restart_replays_exact_committed_bytes_without_an_ack_or_execution() {
    let parent = tempfile::tempdir().unwrap();
    let original = delivered(parent.path(), 0, None, false);
    let marker = fs::read(original.directory.join("delivery.json")).unwrap();
    for _ in 0..3 {
        let restored = recover(&original, DeliveryTrust::Loopback).unwrap().unwrap();
        assert_eq!(restored.receipt, original.receipt);
        assert!(!restored.acknowledgments_confirmed);
        assert!(restored.acknowledgment_error.unwrap().contains("not rechecked"));
        assert_eq!(fs::read(restored.directory.join("delivery.json")).unwrap(), marker);
        assert_eq!(fs::read(restored.directory.join("artifacts/a")).unwrap(), b"A\0\xffB");
    }
}

#[test]
fn failed_and_interrupted_exit_semantics_survive_recovery() {
    for (exit, stop) in [(101, None), (130, Some("cancelled")), (143, Some("session-lost")), (124, Some("deadline-exceeded"))] {
        let parent = tempfile::tempdir().unwrap();
        let original = delivered(parent.path(), exit, stop, false);
        let restored = recover(&original, DeliveryTrust::Loopback).unwrap().unwrap();
        assert_eq!(restored.receipt, original.receipt);
        assert_eq!(restored.receipt["exit_code"], exit);
        assert_eq!(fs::read_dir(restored.directory.join("artifacts")).unwrap().count(), 0);
    }
}

#[test]
fn only_absence_is_a_new_delivery_not_a_partial_receipt() {
    let parent = tempfile::tempdir().unwrap();
    let destination = parent.path().join("delivery");
    assert!(recover_existing_delivery(&request(), "worker", &destination, DeliveryTrust::Loopback).unwrap().is_none());
    assert!(!destination.exists());
    fs::create_dir(&destination).unwrap();
    fs::set_permissions(&destination, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(destination.join("delivery.pending"), b"{}").unwrap();
    let error = recover_existing_delivery(&request(), "worker", &destination, DeliveryTrust::Loopback).unwrap_err();
    assert!(error.execution_may_have_run);
    assert!(destination.join("delivery.pending").exists());
    assert!(!destination.join("delivery.json").exists());
}

#[test]
fn binds_full_request_extensions_id_and_worker() {
    let parent = tempfile::tempdir().unwrap();
    let original = delivered(parent.path(), 0, None, false);
    for (field, value) in [("request_id", json!(8)), ("args", json!(["different.rs"])), ("future_semantics", json!("different"))] {
        let mut other = request();
        other[field] = value;
        assert!(recover_existing_delivery(&other, "worker", &original.directory, DeliveryTrust::Loopback).is_err());
    }
    assert!(recover_existing_delivery(&request(), "other-worker", &original.directory, DeliveryTrust::Loopback).is_err());
}

#[test]
fn pin_and_transport_cannot_be_downgraded_or_substituted() {
    for authenticated in [false, true] {
        let parent = tempfile::tempdir().unwrap();
        let original = delivered(parent.path(), 0, None, authenticated);
        assert_eq!(recover(&original, DeliveryTrust::Loopback).is_ok(), !authenticated);
        assert_eq!(recover(&original, DeliveryTrust::PinnedWorker(PIN)).is_ok(), authenticated);
        assert!(recover(&original, DeliveryTrust::PinnedWorker([0x22; 32])).is_err());
        assert!(recover(&original, DeliveryTrust::PinnedWorker([0; 32])).is_err());
    }
}

#[test]
fn receipt_corruption_never_becomes_an_execution_retry() {
    for (field, value) in [
        ("version", json!(2)), ("kind", json!("pending")), ("exit_code", json!(256)),
        ("stop_reason", json!("cancelled")), ("publication_authorized", json!(true)),
        ("reexecute", json!(true)), ("total_bytes", json!(0)),
        ("stdout_bytes", json!(u64::MAX)), ("request_sha256", json!("00".repeat(32))),
        ("boot_generation", json!(0)), ("incarnation", json!("0".repeat(32))),
    ] {
        let parent = tempfile::tempdir().unwrap();
        let original = delivered(parent.path(), 0, None, false);
        edit_receipt(&original, |receipt| receipt[field] = value);
        let error = recover_existing_delivery(&request(), "worker", &original.directory, DeliveryTrust::Loopback).unwrap_err();
        assert!(error.execution_may_have_run, "{field}");
        assert!(original.directory.join("artifacts/a").exists());
    }
}

#[test]
fn manifest_identity_order_mode_and_set_are_rechecked() {
    for (field, value) in [("name", json!("../escape")), ("bytes", json!(0)), ("executable", json!(true)), ("sha256", json!("00".repeat(32)))] {
        let parent = tempfile::tempdir().unwrap();
        let original = delivered(parent.path(), 0, None, false);
        edit_receipt(&original, |receipt| receipt["artifact_manifest"]["files"][0][field] = value);
        assert!(recover(&original, DeliveryTrust::Loopback).is_err(), "{field}");
    }
    let parent = tempfile::tempdir().unwrap();
    let original = delivered(parent.path(), 0, None, false);
    edit_receipt(&original, |receipt| receipt["artifact_manifest"]["manifest_sha256"] = json!("00".repeat(32)));
    assert!(recover(&original, DeliveryTrust::Loopback).is_err());
}

#[test]
fn changed_bytes_lengths_modes_and_extra_files_refuse() {
    for corruption in ["bytes", "length", "mode", "extra", "directory"] {
        let parent = tempfile::tempdir().unwrap();
        let original = delivered(parent.path(), 0, None, false);
        let path = original.directory.join("artifacts/a");
        match corruption {
            "bytes" => fs::write(path, b"B\0\xffA").unwrap(),
            "length" => fs::write(path, b"short").unwrap(),
            "mode" => fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap(),
            "extra" => fs::write(original.directory.join("artifacts/undeclared"), b"x").unwrap(),
            _ => fs::create_dir(original.directory.join("artifacts/extra")).unwrap(),
        }
        assert!(recover(&original, DeliveryTrust::Loopback).is_err(), "{corruption}");
    }
}

#[test]
fn symlink_receipts_payloads_and_roots_are_not_followed() {
    for relative in ["delivery.json", "artifacts/a", "diagnostics"] {
        let parent = tempfile::tempdir().unwrap();
        let original = delivered(parent.path(), 0, None, false);
        let path = original.directory.join(relative);
        let retained = parent.path().join("original");
        fs::rename(&path, &retained).unwrap();
        symlink(&retained, &path).unwrap();
        assert!(recover(&original, DeliveryTrust::Loopback).is_err(), "{relative}");
    }
    let parent = tempfile::tempdir().unwrap();
    let original = delivered(parent.path(), 0, None, false);
    let alias = parent.path().join("alias");
    symlink(&original.directory, &alias).unwrap();
    assert!(recover_existing_delivery(&request(), "worker", &alias, DeliveryTrust::Loopback).is_err());
}

#[test]
fn oversized_or_truncated_markers_do_not_allocate_unboundedly() {
    for bytes in [vec![b' '; MAX_FRAME_BYTES + 1], b"{\"version\":".to_vec()] {
        let parent = tempfile::tempdir().unwrap();
        let original = delivered(parent.path(), 0, None, false);
        fs::write(original.directory.join("delivery.json"), bytes).unwrap();
        assert!(recover(&original, DeliveryTrust::Loopback).is_err());
    }
}

#[test]
fn both_operator_commands_recover_before_binding_and_preserve_exit_status() {
    for (authenticated, exit) in [(false, 0), (false, 101), (true, 0), (true, 101)] {
        let parent = tempfile::tempdir().unwrap();
        let original = delivered(parent.path(), exit, None, authenticated);
        let request_path = parent.path().join("request.json");
        fs::write(&request_path, serde_json::to_vec_pretty(&request()).unwrap()).unwrap();
        // Binding this address would fail immediately. Successful recovery must
        // neither listen nor need a worker, TLS credentials, or another compile.
        let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_rabsd"));
        command.arg(if authenticated { "--worker-exec-tls" } else { "--worker-exec-loopback" });
        command.arg(occupied.local_addr().unwrap().to_string()).arg("worker");
        if authenticated {
            command.arg("11".repeat(32));
        }
        let output = command.arg(&request_path).arg(&original.directory)
            .env_remove("RABS_COORD_TLS_CA").env_remove("RABS_COORD_TLS_CERT")
            .env_remove("RABS_COORD_TLS_KEY").output().unwrap();
        assert_eq!(output.status.code(), Some(exit), "{}", String::from_utf8_lossy(&output.stderr));
        let result: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["receipt"], original.receipt);
        assert_eq!(result["reexecute"], false);
        assert_eq!(result["acknowledgments_confirmed"], false);
        assert!(!String::from_utf8_lossy(&output.stderr).contains("worker-exec-listening"));
    }
}
