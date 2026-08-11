//! S5 acceptance (Linux): THE ORCHESTRATION PROOF. A test coordinator
//! (std TCP listener) drives the real `rabs-wkr` binary over a real
//! asupersync TCP session: handshake with capability report, a
//! heartbeat with live pressure, and a `canonical-exec` request that
//! runs `rustc --print sysroot` through the PROVEN rabs-sandbox
//! launcher — asserting the D005 result (`/__rabs/toolchain`) came back
//! via the session, not hand-SSH'd. Skips loudly where the canonical
//! namespace is unavailable.
#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn worker_bin() -> &'static str {
    env!("CARGO_BIN_EXE_rabs-wkr")
}

fn toolchain_dir() -> String {
    let cargo = std::env::var("CARGO").expect("CARGO set");
    std::path::Path::new(&cargo)
        .parent()
        .and_then(std::path::Path::parent)
        .expect("<root>/bin/cargo")
        .display()
        .to_string()
}

fn canonical_supported() -> bool {
    rabs_sandbox::canonical_namespace::HostIsolationSupport::probe()
        .missing_for_canonical()
        .is_empty()
}

fn spawn_worker(addr: &str) -> Child {
    Command::new(worker_bin())
        .args(["--coordinator", addr, "--worker-id", "test-wkr", "--once"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn rabs-wkr")
}

fn read_line(reader: &mut impl BufRead) -> String {
    let mut line = String::new();
    reader.read_line(&mut line).expect("read frame");
    line.trim_end().to_string()
}

#[test]
fn orchestrated_canonical_exec_reports_d005_sysroot() {
    if !canonical_supported() {
        eprintln!("SKIP: canonical namespace unavailable on this host");
        return;
    }
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let mut worker = spawn_worker(&addr);

    listener
        .set_nonblocking(false)
        .expect("blocking accept");
    let (stream, _peer) = {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match listener.accept() {
                Ok(pair) => break pair,
                Err(_) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => panic!("accept: {e}"),
            }
        }
    };
    stream
        .set_read_timeout(Some(Duration::from_secs(120)))
        .unwrap();
    let mut writer = stream.try_clone().unwrap();
    let mut reader = BufReader::new(stream);

    // Handshake: worker-hello carries the capability report.
    let hello = read_line(&mut reader);
    assert!(hello.contains("worker-hello"), "{hello}");
    assert!(hello.contains("\"canonical\":true"), "{hello}");
    assert!(hello.contains("\"worker_id\":\"test-wkr\""), "{hello}");
    writeln!(writer, "{{\"kind\":\"session-ok\",\"session_id\":7}}").unwrap();

    // Heartbeat: live pressure from the worker.
    writeln!(writer, "{{\"kind\":\"ping\"}}").unwrap();
    let heartbeat = read_line(&mut reader);
    assert!(heartbeat.contains("heartbeat"), "{heartbeat}");
    assert!(heartbeat.contains("load_x100"), "{heartbeat}");

    // THE ORCHESTRATION PROOF: rustc --print sysroot through the
    // session, run inside the canonical namespace on the worker.
    let toolchain = toolchain_dir();
    let workspace = tempfile::tempdir().unwrap();
    let request = format!(
        "{{\"kind\":\"canonical-exec\",\"request_id\":42,\
         \"program\":\"/__rabs/toolchain/bin/rustc\",\
         \"args\":[\"--print\",\"sysroot\"],\
         \"toolchain_backing\":\"{}\",\"workspace_backing\":\"{}\"}}",
        toolchain,
        workspace.path().display(),
    );
    writeln!(writer, "{request}").unwrap();
    let result = read_line(&mut reader);
    assert!(result.contains("exec-result"), "{result}");
    assert!(result.contains("\"request_id\":42"), "{result}");
    assert!(result.contains("\"executed\":true"), "{result}");
    assert!(result.contains("\"exit_code\":0"), "not exit 0: {result}");

    // The sysroot is /__rabs/toolchain (D005) — assert via its digest.
    let expected_stdout = "/__rabs/toolchain\n";
    let expected_digest = rabs_wkr::session::sha256_hex(expected_stdout.as_bytes());
    assert!(
        result.contains(&expected_digest),
        "sysroot digest mismatch — expected {expected_digest} for {expected_stdout:?}\ngot: {result}"
    );

    let status = worker.wait().expect("worker exit");
    assert_eq!(status.code(), Some(0), "clean worker exit after --once");
}

#[test]
fn handshake_carries_real_capability_and_worker_exits_on_close() {
    if !canonical_supported() {
        eprintln!("SKIP: canonical namespace unavailable on this host");
        return;
    }
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    // No --once: verify the worker ends cleanly when the coordinator
    // drops the connection (session survives, exits, no orphan).
    let mut worker = Command::new(worker_bin())
        .args(["--coordinator", &addr, "--worker-id", "close-test"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    let (stream, _peer) = listener.accept().unwrap();
    let mut writer = stream.try_clone().unwrap();
    let mut reader = BufReader::new(stream);
    let hello = read_line(&mut reader);
    assert!(hello.contains("\"slots\":"), "{hello}");
    writeln!(writer, "{{\"kind\":\"session-ok\"}}").unwrap();
    // Drop the connection: the worker's read returns None => clean end.
    drop(writer);
    drop(reader);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = worker.try_wait().unwrap() {
            assert_eq!(status.code(), Some(0), "clean exit on coordinator close");
            return;
        }
        assert!(Instant::now() < deadline, "worker did not exit on close");
        std::thread::sleep(Duration::from_millis(20));
    }
}
