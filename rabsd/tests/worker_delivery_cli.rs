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
