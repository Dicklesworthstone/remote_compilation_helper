//! The real rabsd operator entry point, driven by a bounded scripted TCP worker.
//! This tests receiver delivery, not compilation or authenticated fleet identity.
#![cfg(unix)]

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) { let _=self.0.kill(); let _=self.0.wait(); }
}
impl OwnedChild {
    fn wait(&mut self) -> ExitStatus {
        let deadline=Instant::now()+Duration::from_secs(10);
        loop {
            if let Some(status)=self.0.try_wait().unwrap() {return status;}
            assert!(Instant::now()<deadline,"receiver did not exit");
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
fn hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b|format!("{b:02x}")).collect()
}
fn send(stream: &mut TcpStream, value: &Value) {
    writeln!(stream,"{value}").unwrap();
}
fn read(reader: &mut BufReader<TcpStream>) -> Value {
    let mut line=String::new();
    assert_ne!(reader.read_line(&mut line).unwrap(),0,"receiver unexpectedly disconnected");
    serde_json::from_str(&line).unwrap()
}
fn start(root: &Path) -> (OwnedChild,String) {
    let request=json!({"kind":"canonical-exec","request_id":7,"program":"fixture-only",
        "args":[],"toolchain_backing":"/tc","workspace_backing":"/ws",
        "artifacts":{"unit":"dep","files":["a"]}});
    let request_path=root.join("request.json");
    std::fs::write(&request_path,serde_json::to_vec(&request).unwrap()).unwrap();
    let report=std::fs::File::create(root.join("report.json")).unwrap();
    let mut child=OwnedChild(Command::new(env!("CARGO_BIN_EXE_rabsd"))
        .arg("--worker-exec-loopback").arg("127.0.0.1:0").arg("fixture-worker")
        .arg(request_path).arg(root.join("delivery"))
        .stdout(report).stderr(Stdio::piped()).spawn().unwrap());
    let stderr=child.0.stderr.take().unwrap();
    let (send_ready,ready)=mpsc::channel();
    std::thread::spawn(move || {
        let mut reader=BufReader::new(stderr); let mut line=String::new();
        let result=reader.read_line(&mut line).map(|_|line);
        let _=send_ready.send(result);
        // Keep stderr open until the process ends, including an error response.
        let mut tail=String::new(); let _=reader.read_to_string(&mut tail);
    });
    let line=ready.recv_timeout(Duration::from_secs(5)).expect("listener readiness").unwrap();
    let value:Value=serde_json::from_str(&line).unwrap();
    assert_eq!(value["kind"],"worker-exec-listening","{line}");
    assert_eq!(value["transport_authenticated"],false);
    (child,value["address"].as_str().unwrap().to_owned())
}
fn chunk(name: &str, bytes: &[u8], artifact: bool) -> Value {
    let mut chunk=json!({"kind":if artifact {"artifact-chunk"} else {"output-chunk"},
        "request_id":7,"offset":0,"next_offset":bytes.len(),"total_bytes":bytes.len(),
        "sha256":hash(bytes),"chunk_sha256":hash(bytes),"eof":true,
        "data_hex":bytes.iter().map(|b|format!("{b:02x}")).collect::<String>()});
    chunk[if artifact {"name"} else {"stream"}]=json!(name);
    if artifact {
        chunk["executable"]=json!(false);
        chunk["manifest_sha256"]=json!("548324c3a5c96511944c6ec6af94ee9bbb6683170bb0143f9d99cd192f80bfd6");
    }
    chunk
}

#[test]
fn operator_binary_verifies_all_bytes_before_acknowledging_them() {
    for output in [b"ok\n".to_vec(), (0..131_089).map(|i| (i % 256) as u8).collect()] {
    let root=tempfile::tempdir().unwrap();
    let (mut child,address)=start(root.path());
    let mut stream=TcpStream::connect(address).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut reader=BufReader::new(stream.try_clone().unwrap());
    send(&mut stream,&json!({"kind":"worker-hello","worker_id":"fixture-worker","canonical":true,"slots":1,
        "boot_generation":1,"incarnation":"00000000000000000000000000000001","request_high_water":null,
        "recovery_protocols":["request-journal-v1"],"output_transfers":["ranges-v1"],"artifact_transfers":["files-v1"]}));
    let negotiation=read(&mut reader);
    assert_eq!(negotiation["output_transfer"],"ranges-v1");
    assert_eq!(negotiation["artifact_transfer"],"files-v1");
    assert_eq!(read(&mut reader)["request_id"],7);
    send(&mut stream,&json!({"kind":"exec-result","request_id":7,"executed":true,"exit_code":0,
        "residual_group_members":0,"stop_reason":null,"output_transfer":"ranges-v1","output_ack_required":true,
        "stdout_bytes":output.len(),"stdout_sha256":hash(&output),"stderr_bytes":0,"stderr_sha256":hash(b""),
        "artifact_transfer":"files-v1","artifact_ack_required":true,"artifact_manifest":{
            "unit":"dep","files":[{"name":"a","bytes":4,"sha256":hash(b"A\0\xffB"),"executable":false}],
            "total_bytes":4,"manifest_sha256":"548324c3a5c96511944c6ec6af94ee9bbb6683170bb0143f9d99cd192f80bfd6"}}));
    for (name,bytes,artifact) in [("stdout",output.as_slice(),false),("stderr",&b""[..],false),("a",&b"A\0\xffB"[..],true)] {
        let mut offset = 0;
        loop {
        let request=read(&mut reader);
        assert_eq!(request["kind"],if artifact {"artifact-read"} else {"output-read"});
        assert_eq!(request["offset"],offset);
        assert_eq!(request["max_bytes"],65_536);
        let end = (offset + 65_536).min(bytes.len());
        let mut response = chunk(name,&bytes[offset..end],artifact);
        response["offset"] = json!(offset);
        response["next_offset"] = json!(end);
        response["total_bytes"] = json!(bytes.len());
        response["sha256"] = json!(hash(bytes));
        response["eof"] = json!(end == bytes.len());
        // Fragment the frame at a non-JSON boundary and coalesce the remainder.
        let encoded=format!("{response}\n");
        stream.write_all(&encoded.as_bytes()[..3]).unwrap();
        stream.write_all(&encoded.as_bytes()[3..]).unwrap();
        offset = end;
        if offset == bytes.len() { break; }
        }
    }
    for (kind,response) in [("output-ack","output-acknowledged"),("artifact-ack","artifact-acknowledged")] {
        assert_eq!(read(&mut reader)["kind"],kind);
        let receipt:Value=serde_json::from_slice(&std::fs::read(root.path().join("delivery/delivery.json")).unwrap()).unwrap();
        assert_eq!(receipt["publication_authorized"],false);
        assert_eq!(std::fs::read(root.path().join("delivery/artifacts/a")).unwrap(),b"A\0\xffB");
        send(&mut stream,&json!({"kind":response,"request_id":7,"already_released":false}));
    }
    assert!(child.wait().success());
    let report:Value=serde_json::from_slice(&std::fs::read(root.path().join("report.json")).unwrap()).unwrap();
    assert_eq!(report["acknowledgments_confirmed"],true);
    assert_eq!(report["receipt"]["exit_code"],0);
    assert_eq!(std::fs::read(root.path().join("delivery/diagnostics/stdout")).unwrap(),output);
    }
}

#[test]
fn operator_refuses_public_binding_before_creating_a_delivery() {
    let root=tempfile::tempdir().unwrap();
    let request = root.path().join("request.json");
    std::fs::write(&request,json!({"kind":"canonical-exec","request_id":1,"program":"fixture-only",
        "toolchain_backing":"/tc","workspace_backing":"/ws"}).to_string()).unwrap();
    let mut child=OwnedChild(Command::new(env!("CARGO_BIN_EXE_rabsd"))
        .args(["--worker-exec-loopback","0.0.0.0:0","worker"]).arg(request)
        .arg(root.path().join("delivery")).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap());
    let status = child.wait();
    assert!(!status.success()); assert!(!root.path().join("delivery").exists());
}

/// Run a real operator process with bounded lifetime and captured streams.
/// Invalid daemon configuration must not affect source preparation or help;
/// neither command has a reason to boot the daemon, bind a socket, or mount CAS.
fn operator_process(root: &Path, args: &[String]) -> (ExitStatus, Vec<u8>, Vec<u8>) {
    let logs = tempfile::tempdir_in(root).unwrap();
    let stdout = logs.path().join("stdout");
    let stderr = logs.path().join("stderr");
    let mut child = OwnedChild(Command::new(env!("CARGO_BIN_EXE_rabsd"))
        .args(args)
        .current_dir(root)
        .env("RABS_CONFIG", root.join("invalid-config.toml"))
        .env("RABS_SOCKET_PATH", root.join("must-not-bind.sock"))
        .env("RABS_STATE_DIR", root.join("must-not-create-state"))
        .env("RABS_BOOT_MARKER", root.join("must-not-create-boot"))
        .stdout(std::fs::File::create(&stdout).unwrap())
        .stderr(std::fs::File::create(&stderr).unwrap())
        .spawn().unwrap());
    let status = child.wait();
    (status, std::fs::read(stdout).unwrap(), std::fs::read(stderr).unwrap())
}

fn preparation_fixture(root: &Path) -> Vec<String> {
    use std::os::unix::fs::PermissionsExt;
    let checkout = root.join("source checkout");
    std::fs::create_dir_all(checkout.join("src")).unwrap();
    std::fs::create_dir(checkout.join("tools")).unwrap();
    std::fs::write(checkout.join("src/main.rs"), b"fn main() {}\n").unwrap();
    std::fs::write(checkout.join("empty"), b"").unwrap();
    std::fs::write(checkout.join("tools/run"), b"#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(checkout.join("tools/run"), std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(checkout.join("not-approved.private"), b"never copy or transmit me").unwrap();
    std::fs::write(root.join("invalid-config.toml"), b"[invalid configuration").unwrap();
    let specification = json!({
        "kind":"canonical-exec", "request_id":43,
        "program":"/worker-only/nonexistent-local-compiler", "toolchain_backing":"/worker-only/toolchain",
        "args":["src/main.rs", "-o", "/__rabs/out/demo/app"],
        "source_files":["tools/run", "src/main.rs", "empty"],
        "artifacts":{"unit":"demo", "files":["app"]},
        "timeout_ms":120000, "jobserver_grant":2, "extension":{"untouched":true}
    });
    let spec_path = root.join("specification.json");
    std::fs::write(&spec_path, serde_json::to_vec(&specification).unwrap()).unwrap();
    vec!["--worker-prepare".to_owned(), checkout.to_str().unwrap().to_owned(),
        spec_path.to_str().unwrap().to_owned(), root.join("bundle").to_str().unwrap().to_owned()]
}

fn assert_no_daemon(root: &Path) {
    for path in ["must-not-bind.sock", "must-not-create-state", "must-not-create-boot"] {
        assert!(!root.join(path).exists(), "preparation touched daemon state: {path}");
    }
}

#[test]
fn preparation_binary_saves_a_request_usable_without_the_original_checkout() {
    use rabs_sandbox::snapshot_capture::capture_sealed_source;
    use rabsd::coord::source_delivery::{SourceUpload, request_manifest};
    use rabsd::coord::worker_delivery::validate_request;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;

    let root = tempfile::tempdir().unwrap();
    let args = preparation_fixture(root.path());
    let original: Value = serde_json::from_slice(&std::fs::read(&args[2]).unwrap()).unwrap();
    let (status, stdout, stderr) = operator_process(root.path(), &args);
    assert!(status.success(), "{}", String::from_utf8_lossy(&stderr));
    assert!(stderr.is_empty());
    let summary: Value = serde_json::from_slice(&stdout).unwrap();
    assert_eq!(summary["kind"], "prepared-source-bundle");
    assert_eq!(summary["executed"], false);
    assert_eq!(summary["publication_authorized"], false);
    assert_eq!(summary["request_id"], 43);
    assert_eq!(summary["source_files"], 3);
    let source = Path::new(summary["source_root"].as_str().unwrap());
    let request_bytes = std::fs::read(summary["request_path"].as_str().unwrap()).unwrap();
    assert_eq!(summary["request_sha256"], hash(&request_bytes));
    let request: Value = serde_json::from_slice(&request_bytes).unwrap();
    validate_request(&request).unwrap();
    let manifest = request_manifest(&request).unwrap().unwrap();
    assert_eq!(manifest.files().len(), 3);
    assert!(request.get("source_files").is_none());
    for field in ["request_id", "program", "args", "artifacts", "toolchain_backing",
        "timeout_ms", "jobserver_grant", "extension"] {
        assert_eq!(request[field], original[field], "changed execution field {field}");
    }
    assert!(!source.join("not-approved.private").exists());
    assert_eq!(std::fs::read(source.join("empty")).unwrap(), b"");
    assert_eq!(std::fs::metadata(source.join("tools/run")).unwrap().permissions().mode() & 0o777, 0o555);
    assert_no_daemon(root.path());

    // The next process uses the retained projection, not the mutable checkout.
    let checkout = Path::new(&args[1]);
    std::fs::rename(checkout, root.path().join("retired-checkout")).unwrap();
    let image = capture_sealed_source(&[("workspace".into(), source.to_path_buf())], false, 2, 200_000).unwrap();
    let upload = SourceUpload::for_request(Arc::new(image), "workspace", &request).unwrap();
    assert_eq!(upload.wire_manifest(), request["source_manifest"]);
    assert_eq!(std::fs::read(source.join("src/main.rs")).unwrap(), b"fn main() {}\n");
}

#[test]
fn preparation_cli_rejects_ambiguous_arity_flags_and_relative_roots() {
    let root = tempfile::tempdir().unwrap();
    let good = preparation_fixture(root.path());
    let mut cases = vec![good[..1].to_vec(), good[..2].to_vec(), good[..3].to_vec()];
    let mut extra = good.clone(); extra.push("extra".into()); cases.push(extra);
    for (index, value) in [(1, "relative-source"), (2, "--resume"), (3, "relative-bundle")] {
        let mut args = good.clone(); args[index] = value.into(); cases.push(args);
    }
    for args in cases {
        let (status, stdout, stderr) = operator_process(root.path(), &args);
        assert_eq!(status.code(), Some(2), "{args:?}: {}", String::from_utf8_lossy(&stderr));
        assert!(stdout.is_empty());
        let error: Value = serde_json::from_slice(&stderr).unwrap();
        assert_eq!(error["kind"], "worker-prepare-failed");
        assert_eq!(error["executed"], false);
        assert!(error["detail"].as_str().unwrap().contains("usage:"));
        assert!(!root.path().join("bundle").exists());
        assert_no_daemon(root.path());
    }
}

#[test]
fn preparation_cli_reports_malformed_specs_without_publishing_output() {
    let root = tempfile::tempdir().unwrap();
    let args = preparation_fixture(root.path());
    for content in [b"{\"kind\":".as_slice(), b"[]", b"null", b"{}"] {
        std::fs::write(&args[2], content).unwrap();
        let (status, stdout, stderr) = operator_process(root.path(), &args);
        assert!(!status.success());
        assert!(stdout.is_empty());
        let error: Value = serde_json::from_slice(&stderr).unwrap();
        assert_eq!(error["kind"], "worker-prepare-failed");
        assert_eq!(error["executed"], false);
        assert!(error["detail"].as_str().is_some_and(|detail| !detail.is_empty()));
        assert!(!root.path().join("bundle").exists());
        assert_no_daemon(root.path());
    }
}

#[test]
fn preparation_cli_refuses_nonregular_specs_before_reading_them() {
    use std::os::unix::fs::symlink;
    use std::os::unix::net::UnixListener;
    let root = tempfile::tempdir().unwrap();
    let good = preparation_fixture(root.path());
    symlink(&good[2], root.path().join("spec-link")).unwrap();
    let _listener = UnixListener::bind(root.path().join("spec-socket")).unwrap();
    for spec in [root.path().to_path_buf(), root.path().join("spec-link"), root.path().join("spec-socket")] {
        let mut args = good.clone(); args[2] = spec.to_str().unwrap().to_owned();
        let (status, stdout, stderr) = operator_process(root.path(), &args);
        assert_eq!(status.code(), Some(2));
        assert!(stdout.is_empty());
        let error: Value = serde_json::from_slice(&stderr).unwrap();
        assert!(error["detail"].as_str().unwrap().contains("ordinary file"));
        assert!(!root.path().join("bundle").exists());
        assert_no_daemon(root.path());
    }
}

#[test]
fn preparation_cli_bounds_the_spec_file_without_rejecting_the_exact_limit() {
    use rabsd::coord::worker_delivery::MAX_FRAME_BYTES;
    let root = tempfile::tempdir().unwrap();
    let args = preparation_fixture(root.path());
    let mut bytes = std::fs::read(&args[2]).unwrap();
    bytes.resize(MAX_FRAME_BYTES, b' ');
    std::fs::write(&args[2], &bytes).unwrap();
    let (status, stdout, stderr) = operator_process(root.path(), &args);
    assert!(status.success(), "{}", String::from_utf8_lossy(&stderr));
    assert_eq!(serde_json::from_slice::<Value>(&stdout).unwrap()["kind"], "prepared-source-bundle");
    bytes.push(b' ');
    std::fs::write(&args[2], &bytes).unwrap();
    let mut next = args;
    next[3] = root.path().join("oversized-bundle").to_str().unwrap().to_owned();
    let (status, stdout, stderr) = operator_process(root.path(), &next);
    assert_eq!(status.code(), Some(2));
    assert!(stdout.is_empty());
    let error: Value = serde_json::from_slice(&stderr).unwrap();
    assert!(error["detail"].as_str().unwrap().contains("bounded ordinary file"));
    assert!(!root.path().join("oversized-bundle").exists());
    assert_no_daemon(root.path());
}

#[test]
fn preparation_cli_preserves_complete_and_incomplete_existing_bundles() {
    let root = tempfile::tempdir().unwrap();
    let args = preparation_fixture(root.path());
    let (status, _, stderr) = operator_process(root.path(), &args);
    assert!(status.success(), "{}", String::from_utf8_lossy(&stderr));
    let request_path = root.path().join("bundle/request.json");
    let request_before = std::fs::read(&request_path).unwrap();
    std::fs::write(Path::new(&args[1]).join("src/main.rs"), b"edited after preparation").unwrap();
    let (status, stdout, stderr) = operator_process(root.path(), &args);
    assert!(!status.success());
    assert!(stdout.is_empty());
    assert_eq!(serde_json::from_slice::<Value>(&stderr).unwrap()["kind"], "worker-prepare-failed");
    assert_eq!(std::fs::read(request_path).unwrap(), request_before);
    assert_eq!(std::fs::read(root.path().join("bundle/source/src/main.rs")).unwrap(), b"fn main() {}\n");

    let partial = root.path().join("partial");
    std::fs::create_dir(&partial).unwrap();
    std::fs::write(partial.join("evidence"), b"retain partial preparation").unwrap();
    let mut retry = args; retry[3] = partial.to_str().unwrap().to_owned();
    let (status, stdout, _) = operator_process(root.path(), &retry);
    assert!(!status.success());
    assert!(stdout.is_empty());
    assert_eq!(std::fs::read(partial.join("evidence")).unwrap(), b"retain partial preparation");
    assert!(!partial.join("request.json").exists());
    assert_no_daemon(root.path());
}

#[test]
fn unresolved_preparation_cannot_start_the_execution_listener() {
    let root = tempfile::tempdir().unwrap();
    let prep = preparation_fixture(root.path());
    let execution = vec!["--worker-exec-loopback".into(), "127.0.0.1:0".into(),
        "fixture-worker".into(), prep[2].clone(), root.path().join("delivery").to_str().unwrap().to_owned()];
    let (status, stdout, stderr) = operator_process(root.path(), &execution);
    assert!(!status.success());
    assert!(stdout.is_empty());
    let error: Value = serde_json::from_slice(&stderr).unwrap();
    assert_eq!(error["execution_may_have_run"], false);
    assert!(error["detail"].as_str().unwrap().contains("--worker-prepare"));
    assert!(!root.path().join("delivery").exists());
    assert_no_daemon(root.path());
}
