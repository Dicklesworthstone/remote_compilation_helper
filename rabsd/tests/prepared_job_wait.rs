//! Actual daemon and --job-wait processes over the production UDS API.
//!
//! A scripted, transport-admitted peer seeds a terminal result through the real
//! receiver, output installer and durable job store. This is receiver/store/UDS
//! proof, NOT a compiler, native TLS or fleet acceptance test. The daemon then
//! reopens that state without the original bundle or worker credentials.
#![cfg(unix)]

use rabs_sandbox::source_transfer::{SourceFile, SourceManifest};
use rabsd::coord::delivery_recovery::{DeliveryTrust, install_delivery_outputs};
use rabsd::coord::prepared_operation::{OperationOutcome, PreparedOperationSpec, PreparedOperationStore};
use rabsd::coord::worker_delivery::{CHUNK_BYTES, WorkerAuthentication, WorkerPeer, receive_execution};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const ID: &str = "0123456789abcdef0123456789abcdef";
const LOG_LIMIT: u64 = 4 * 1024 * 1024;
const ARTIFACT: &[u8] = b"compiled fixture\0\xff";

fn hash(bytes: &[u8]) -> String { hex(&Sha256::digest(bytes)) }
fn hex(bytes: &[u8]) -> String { bytes.iter().map(|byte| format!("{byte:02x}")).collect() }
fn read_log(path: &Path) -> Vec<u8> {
    let mut bytes = Vec::new();
    File::open(path).unwrap().take(LOG_LIMIT + 1).read_to_end(&mut bytes).unwrap();
    assert!(bytes.len() as u64 <= LOG_LIMIT, "process output exceeded fixture bound");
    bytes
}

struct Process { child: Child, stdout: PathBuf, stderr: PathBuf }
impl Process {
    fn start(root: &Path, name: &str, command: &mut Command) -> Self {
        let stdout = root.join(format!("{name}.stdout"));
        let stderr = root.join(format!("{name}.stderr"));
        let child = command.stdin(Stdio::null()).stdout(File::create(&stdout).unwrap())
            .stderr(File::create(&stderr).unwrap()).spawn().expect("required rabsd executable");
        Self { child, stdout, stderr }
    }
    fn wait(&mut self) -> ExitStatus {
        let until = Instant::now() + Duration::from_secs(20);
        loop {
            for path in [&self.stdout, &self.stderr] {
                assert!(fs::metadata(path).unwrap().len() <= LOG_LIMIT, "process log exceeded fixture bound");
            }
            if let Some(status) = self.child.try_wait().unwrap() { return status; }
            assert!(Instant::now() < until, "process timed out: {}", String::from_utf8_lossy(&read_log(&self.stderr)));
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    fn ready(&mut self, socket: &Path) {
        let until = Instant::now() + Duration::from_secs(10);
        while std::os::unix::net::UnixStream::connect(socket).is_err() {
            assert!(self.child.try_wait().unwrap().is_none(), "daemon exited: {}", String::from_utf8_lossy(&read_log(&self.stderr)));
            assert!(Instant::now() < until, "daemon did not create its UDS endpoint");
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    fn shutdown(&mut self) {
        assert!(Command::new("kill").args(["-TERM", &self.child.id().to_string()]).status().unwrap().success());
        assert!(self.wait().success(), "daemon did not shut down cleanly: {}", String::from_utf8_lossy(&read_log(&self.stderr)));
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        // These are a daemon with no running compiler and a read-only client.
        // Never detach a test-owned process after a failed assertion.
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

struct Peer { result: Value, stdout: Vec<u8>, stderr: Vec<u8>, replies: VecDeque<Value> }
impl WorkerPeer for Peer {
    fn authentication(&self) -> Option<WorkerAuthentication> {
        Some(WorkerAuthentication { spki_sha256:[1;32], session_id:42, identity_generation:1 })
    }
    fn send(&mut self, query: &Value) -> io::Result<()> {
        match query["kind"].as_str().unwrap() {
            "session-ok" => {},
            "canonical-exec" => self.replies.push_back(self.result.clone()),
            "output-read" | "artifact-read" => {
                let artifact = query["kind"] == "artifact-read";
                let name = query[if artifact {"name"} else {"stream"}].as_str().unwrap();
                let bytes = match name {
                    "stdout" => self.stdout.as_slice(), "stderr" => self.stderr.as_slice(),
                    "app" => ARTIFACT, _ => panic!("unrequested fixture member"),
                };
                let offset = query["offset"].as_u64().unwrap() as usize;
                assert_eq!(query["max_bytes"],CHUNK_BYTES);
                let end = (offset + CHUNK_BYTES).min(bytes.len());
                let chunk = &bytes[offset..end];
                let mut reply = json!({"kind":if artifact {"artifact-chunk"} else {"output-chunk"},
                    "request_id":7,"offset":offset,"next_offset":end,"total_bytes":bytes.len(),
                    "sha256":hash(bytes),"chunk_sha256":hash(chunk),"eof":end == bytes.len(),"data_hex":hex(chunk)});
                reply[if artifact {"name"} else {"stream"}] = json!(name);
                if artifact {
                    reply["executable"] = json!(true);
                    reply["manifest_sha256"] = self.result["artifact_manifest"]["manifest_sha256"].clone();
                }
                self.replies.push_back(reply);
            }
            "output-ack" | "artifact-ack" => self.replies.push_back(json!({
                "kind":if query["kind"] == "output-ack" {"output-acknowledged"} else {"artifact-acknowledged"},
                "request_id":7,"already_released":false})),
            _ => panic!("unexpected fixture operation"),
        }
        Ok(())
    }
    fn receive(&mut self) -> io::Result<Value> {
        self.replies.pop_front().ok_or_else(|| io::Error::other("missing fixture response"))
    }
}

struct Fixture {
    _owner: tempfile::TempDir, root: PathBuf, state: PathBuf, socket: PathBuf,
    delivery: PathBuf, stdout: Vec<u8>, stderr: Vec<u8>, saved_record: Vec<u8>,
}
impl Fixture {
    /// None means a dropped execution owner; Some(130) with `before_start`
    /// means durable queued cancellation. Neither case manufactures a receipt.
    fn new(exit: Option<u8>, before_start: bool) -> Self {
        let owner = tempfile::tempdir().unwrap();
        let root = owner.path().canonicalize().unwrap();
        let state = root.join("state");
        fs::create_dir(&state).unwrap();
        let store = PreparedOperationStore::open(&state.join("prepared-operations")).unwrap();
        let bundle = root.join("bundle");
        fs::create_dir(&bundle).unwrap();
        let delivery = root.join("delivery");
        let output = root.join("installed");
        let source = SourceManifest::new(vec![SourceFile { path:"lib.rs".into(),len:1,
            sha256:Sha256::digest(b"x").into(), executable:false }]).unwrap();
        let request = json!({"kind":"canonical-exec","request_id":7,"program":"rustc","args":["lib.rs"],
            "toolchain_backing":"/tc","toolchain_identity":{"version":"toolchain-dataset-v1","sha256":"ab".repeat(32),"files":1,"bytes":1},
            "source_manifest":{"manifest_sha256":hex(&source.digest()),"files":[{"path":"lib.rs","bytes":1,"sha256":hash(b"x"),"executable":false}]},
            "artifacts":{"unit":"build","files":["app"]}});
        fs::write(bundle.join("request.json"),serde_json::to_vec(&request).unwrap()).unwrap();
        store.submit(PreparedOperationSpec { id:ID.into(),address:"127.0.0.1:7001".into(),worker:"worker".into(),
            worker_spki_sha256:"01".repeat(32),bundle:bundle.clone(),delivery:delivery.clone(),output:output.clone() }).unwrap();
        let stdout: Vec<u8> = (0..CHUNK_BYTES + 3).map(|index| (index % 256) as u8).collect();
        let stderr: Vec<u8> = (0..2 * CHUNK_BYTES + 7).map(|index| (index % 251) as u8).collect();
        if before_start {
            store.cancel(ID).unwrap();
        } else {
            let claim = store.claim_next().unwrap().unwrap();
            if let Some(exit) = exit {
                let mut hasher = Sha256::new();
                let field = |hasher: &mut Sha256, bytes: &[u8]| { hasher.update((bytes.len() as u64).to_be_bytes()); hasher.update(bytes); };
                field(&mut hasher,b"rabs.worker-artifact-manifest.v1"); field(&mut hasher,b"build");
                hasher.update(1_u64.to_be_bytes()); field(&mut hasher,b"app"); hasher.update([1]);
                hasher.update((ARTIFACT.len() as u64).to_be_bytes()); field(&mut hasher,hash(ARTIFACT).as_bytes());
                let manifest = json!({"unit":"build","files":[{"name":"app","bytes":ARTIFACT.len(),"sha256":hash(ARTIFACT),"executable":true}],
                    "total_bytes":ARTIFACT.len(),"manifest_sha256":hex(&hasher.finalize())});
                let mut peer = Peer {
                    stdout:stdout.clone(),stderr:stderr.clone(),
                    result:json!({"kind":"exec-result","request_id":7,"executed":true,"exit_code":exit,
                        "stop_reason":if exit == 130 {json!("cancelled")} else {Value::Null},"residual_group_members":0,
                        "output_transfer":"ranges-v1","output_ack_required":true,"stdout_bytes":stdout.len(),"stdout_sha256":hash(&stdout),
                        "stderr_bytes":stderr.len(),"stderr_sha256":hash(&stderr),"artifact_transfer":"files-v1",
                        "artifact_ack_required":exit == 0,"artifact_manifest":if exit == 0 {manifest} else {Value::Null},
                        "result_retention":"durable-result-v1","retained_result_sha256":hash(b"scripted complete result")}),
                    replies:VecDeque::from([json!({"kind":"worker-hello","worker_id":"worker","canonical":true,"slots":1,
                        "boot_generation":1,"incarnation":"00000000000000000000000000000001","request_high_water":null,
                        "recovery_protocols":["request-journal-v1"],"output_transfers":["ranges-v1"],"artifact_transfers":["files-v1"],
                        "toolchain_datasets":["toolchain-dataset-v1"],"result_retentions":["durable-result-v1"]})]),
                };
                let delivered = receive_execution(&mut peer,&request,"worker",&delivery).unwrap();
                assert!(peer.replies.is_empty());
                let installed = if exit == 0 {
                    Some(install_delivery_outputs(&request,"worker",&delivery,&output,DeliveryTrust::PinnedWorker([1;32])).unwrap().to_json())
                } else { None };
                claim.finish(OperationOutcome::Completed { result:json!({"kind":"worker-build","delivery":delivered.to_json(),
                    "installed_outputs":installed,"publication_authorized":false,"reexecute":false}) }).unwrap();
            } else {
                drop(claim);
            }
        }
        let saved_record = fs::read(state.join(format!("prepared-operations/{ID}.json"))).unwrap();
        drop(store);
        fs::rename(bundle,root.join("retired-bundle")).unwrap();
        fs::write(root.join("config.toml"),"").unwrap();
        let socket = root.join("daemon.sock");
        Self { _owner:owner,root,state,socket,delivery,stdout,stderr,saved_record }
    }
    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_rabsd"));
        command.env("RABS_STATE_DIR",&self.state).env("RABS_SOCKET_PATH",&self.socket)
            .env("RABS_CONFIG",self.root.join("config.toml")).env("RABS_BOOT_MARKER",self.root.join("daemon.boot"))
            .env_remove("RABS_COORD_TLS_CA").env_remove("RABS_COORD_TLS_CERT").env_remove("RABS_COORD_TLS_KEY");
        command
    }
    fn daemon(&self) -> Process {
        let mut command = self.command(); command.args(["--run-for-ms","60000"]);
        let mut process = Process::start(&self.root,"daemon",&mut command);
        process.ready(&self.socket); process
    }
    fn wait(&self) -> Process {
        let mut command = self.command(); command.args(["--job-wait",ID,"10"]);
        Process::start(&self.root,"wait",&mut command)
    }
    fn assert_unchanged(&self) {
        assert_eq!(fs::read(self.state.join(format!("prepared-operations/{ID}.json"))).unwrap(),self.saved_record);
    }
}

#[test]
fn actual_daemon_wait_replays_complete_binary_streams_and_original_exit_without_bundle_or_credentials() {
    for exit in [0,17,130] {
        let fixture = Fixture::new(Some(exit),false);
        let receipt = fs::read(fixture.delivery.join("delivery.json")).unwrap();
        let inode = fs::metadata(fixture.delivery.join("diagnostics/stdout")).unwrap().ino();
        let mut daemon = fixture.daemon();
        let mut client = fixture.wait();
        assert_eq!(client.wait().code(),Some(i32::from(exit)),"{}",String::from_utf8_lossy(&read_log(&client.stderr)));
        assert_eq!(read_log(&client.stdout),fixture.stdout);
        assert_eq!(read_log(&client.stderr),fixture.stderr);
        assert_eq!(fs::read(fixture.delivery.join("delivery.json")).unwrap(),receipt);
        assert_eq!(fs::metadata(fixture.delivery.join("diagnostics/stdout")).unwrap().ino(),inode);
        fixture.assert_unchanged();
        assert!(!String::from_utf8_lossy(&read_log(&daemon.stderr)).contains("worker-exec-listening"));
        daemon.shutdown();
    }
}

#[test]
fn actual_daemon_wait_refuses_damaged_results_without_printing_even_the_valid_first_stream() {
    for corrupt in ["artifacts/app","diagnostics/stderr"] {
        let fixture = Fixture::new(Some(0),false);
        fs::write(fixture.delivery.join(corrupt),b"corrupted").unwrap();
        let mut daemon = fixture.daemon();
        let mut client = fixture.wait();
        assert!(!client.wait().success());
        assert!(read_log(&client.stdout).is_empty());
        let failure: Value = serde_json::from_slice(&read_log(&client.stderr)).unwrap();
        assert_eq!(failure["kind"],"prepared-client-error");
        assert_eq!(failure["diagnostics_may_have_been_exposed"],false);
        assert_eq!(failure["reexecute"],false);
        fixture.assert_unchanged();
        daemon.shutdown();
    }
}

#[test]
fn actual_daemon_wait_never_reexecutes_uncertainty_or_reads_a_pre_start_cancelled_delivery() {
    for cancelled in [false,true] {
        let fixture = Fixture::new(None,cancelled);
        let mut daemon = fixture.daemon();
        let mut client = fixture.wait();
        let code = client.wait().code().unwrap();
        assert_eq!(code,if cancelled {130} else {1});
        assert!(read_log(&client.stdout).is_empty());
        if cancelled { assert!(read_log(&client.stderr).is_empty()); }
        else {
            let failure: Value = serde_json::from_slice(&read_log(&client.stderr)).unwrap();
            assert!(failure["detail"].as_str().unwrap().contains("uncertain"));
            assert_eq!(failure["diagnostics_may_have_been_exposed"],false);
        }
        assert!(!fixture.delivery.exists());
        assert!(!fixture.root.join("installed").exists());
        fixture.assert_unchanged();
        assert!(!String::from_utf8_lossy(&read_log(&daemon.stderr)).contains("worker-exec-listening"));
        daemon.shutdown();
    }
}
