//! S3 acceptance against the REAL daemon + REAL socket: handshake +
//! consult round trip, the 64-way storm, malformed-frame fuzz (no
//! panic, typed refusals, daemon stays alive), a hung mid-frame client
//! that must not wedge shutdown, socket permissions, and stale-socket
//! takeover with liveness probing.
#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn spawn_daemon(socket: &std::path::Path, marker: &std::path::Path) -> Child {
    Command::new(env!("CARGO_BIN_EXE_rabsd"))
        .env("RABS_SOCKET_PATH", socket)
        .env("RABS_BOOT_MARKER", marker)
        .env("RABS_STATE_DIR", marker.with_extension("state"))
        .env("RABS_CONFIG", "/nonexistent-rabs-config")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn rabsd")
}

fn wait_for_socket(socket: &std::path::Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "socket never appeared");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn connect(socket: &std::path::Path) -> UnixStream {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match UnixStream::connect(socket) {
            Ok(stream) => {
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                return stream;
            }
            Err(_) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("connect: {error}"),
        }
    }
}

const HELLO: &str = "{\"kind\":\"hello\",\
    \"transport\":{\"minimum_compatible\":1,\"current\":1},\
    \"application\":{\"minimum_compatible\":1,\"current\":1}}";

fn send_line(stream: &mut UnixStream, line: &str) {
    stream.write_all(line.as_bytes()).unwrap();
    stream.write_all(b"\n").unwrap();
}

fn read_line(stream: &mut UnixStream) -> String {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    line.trim_end().to_string()
}

fn handshake(stream: &mut UnixStream) -> String {
    send_line(stream, HELLO);
    read_line(stream)
}

fn terminate(child: &mut Child) -> (i32, Duration) {
    let start = Instant::now();
    Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .expect("SIGTERM");
    let status = child.wait().expect("daemon exit");
    (status.code().unwrap_or(-1), start.elapsed())
}

#[test]
fn handshake_consult_roundtrip_and_socket_permissions() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("rabsd.sock");
    let marker = dir.path().join("rabsd.boot");
    let mut daemon = spawn_daemon(&socket, &marker);
    wait_for_socket(&socket);

    // Socket 0600.
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "socket must be 0600, got {mode:o}");

    let mut stream = connect(&socket);
    let reply = handshake(&mut stream);
    assert!(reply.contains("hello-ok"), "{reply}");
    assert!(reply.contains("\"transport\":1"), "{reply}");

    send_line(&mut stream, "{\"kind\":\"consult\",\"argv\":[\"rustc\"]}");
    let decision = read_line(&mut stream);
    assert!(decision.contains("pass-through"), "{decision}");
    assert!(decision.contains("\"mode\":\"shadow\""), "{decision}");
    assert!(
        decision.contains("\"key\":\""),
        "shadow key present: {decision}"
    );
    assert!(decision.contains("hit_upper_bound"), "{decision}");

    let (code, _) = terminate(&mut daemon);
    assert_eq!(code, 0, "clean exit");
    assert!(!socket.exists(), "clean shutdown removes the socket");
}

#[test]
fn shadow_discovery_cycle_live_and_report() {
    // S4 end to end on the real socket: identical consults collide in
    // the shadow index (miss -> upper-bound hit), receipts land 1:1,
    // and --shadow-report aggregates from the receipt stream.
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("rabsd.sock");
    let marker = dir.path().join("rabsd.boot");
    let state = marker.with_extension("state");
    let mut daemon = spawn_daemon(&socket, &marker);
    wait_for_socket(&socket);

    let consult = "{\"kind\":\"consult\",\"argv\":[\"/tc/rustc\",\"--crate-name\",\"fx\"],\
                   \"cwd\":\"/work\",\"env_names\":[\"CARGO_HOME\"]}";
    let mut stream = connect(&socket);
    assert!(handshake(&mut stream).contains("hello-ok"));
    send_line(&mut stream, consult);
    let first = read_line(&mut stream);
    assert!(first.contains("\"hit_upper_bound\":false"), "{first}");
    send_line(&mut stream, consult);
    let second = read_line(&mut stream);
    assert!(second.contains("\"hit_upper_bound\":true"), "{second}");
    // A different invocation must NOT smear into a hit.
    send_line(
        &mut stream,
        "{\"kind\":\"consult\",\"argv\":[\"/tc/rustc\",\"--crate-name\",\"other\"],\
         \"cwd\":\"/work\",\"env_names\":[]}",
    );
    let third = read_line(&mut stream);
    assert!(third.contains("\"hit_upper_bound\":false"), "{third}");

    let (code, _) = terminate(&mut daemon);
    assert_eq!(code, 0);

    // Receipts 1:1 with consults, all shadow-graded.
    let receipts = std::fs::read_to_string(state.join("shadow-receipts.ndjson")).unwrap();
    assert_eq!(receipts.lines().count(), 3, "{receipts}");
    assert!(receipts.lines().all(|l| l.contains("shadow-upper-bound")));

    // The report CLI aggregates from the same stream.
    let report = Command::new(env!("CARGO_BIN_EXE_rabsd"))
        .arg("--shadow-report")
        .env("RABS_STATE_DIR", &state)
        .output()
        .unwrap();
    let report = String::from_utf8_lossy(&report.stdout);
    assert!(report.contains("\"total_consults\":3"), "{report}");
    assert!(
        report.contains("\"consults\":3,\"hit_upper_bound\":1"),
        "{report}"
    );
}

#[test]
fn sixty_four_way_storm_zero_drops() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("rabsd.sock");
    let marker = dir.path().join("rabsd.boot");
    let mut daemon = spawn_daemon(&socket, &marker);
    wait_for_socket(&socket);

    let socket = std::sync::Arc::new(socket);
    let handles: Vec<_> = (0..64)
        .map(|i| {
            let socket = std::sync::Arc::clone(&socket);
            std::thread::spawn(move || {
                let mut stream = connect(&socket);
                let reply = handshake(&mut stream);
                assert!(reply.contains("hello-ok"), "conn {i}: {reply}");
                send_line(&mut stream, "{\"kind\":\"consult\",\"n\":1}");
                let decision = read_line(&mut stream);
                assert!(decision.contains("pass-through"), "conn {i}: {decision}");
            })
        })
        .collect();
    for handle in handles {
        handle.join().expect("storm connection failed");
    }
    let (code, _) = terminate(&mut daemon);
    assert_eq!(code, 0);
}

#[test]
fn malformed_frame_fuzz_typed_refusals_daemon_survives() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("rabsd.sock");
    let marker = dir.path().join("rabsd.boot");
    let mut daemon = spawn_daemon(&socket, &marker);
    wait_for_socket(&socket);

    // Arm 1: garbage instead of hello -> typed refusal.
    let mut stream = connect(&socket);
    send_line(&mut stream, "not json at all \u{7} \\x00");
    let reply = read_line(&mut stream);
    assert!(reply.contains("refusal"), "{reply}");
    assert!(reply.contains("malformed-hello"), "{reply}");

    // Arm 2: valid JSON, wrong kind -> typed refusal.
    let mut stream = connect(&socket);
    send_line(&mut stream, "{\"kind\":\"exploit\"}");
    let reply = read_line(&mut stream);
    assert!(
        reply.contains("malformed-hello") || reply.contains("refusal"),
        "{reply}"
    );

    // Arm 3: post-handshake malformed frames.
    let mut stream = connect(&socket);
    assert!(handshake(&mut stream).contains("hello-ok"));
    for junk in ["{{{{", "\"just a string\"", "{\"kind\":\"nope\"}"] {
        send_line(&mut stream, junk);
        let reply = read_line(&mut stream);
        assert!(reply.contains("refusal"), "junk {junk:?}: {reply}");
    }

    // Arm 4: oversize frame (> 64KiB, no newline) -> connection closed
    // without a panic.
    let mut stream = connect(&socket);
    let oversize = vec![b'a'; 70 * 1024];
    let _ = stream.write_all(&oversize);
    let mut buffer = [0u8; 1];
    let _ = stream.read(&mut buffer); // EOF or reset both fine

    // The daemon is still alive and serving.
    let mut stream = connect(&socket);
    assert!(handshake(&mut stream).contains("hello-ok"), "daemon died");

    let (code, _) = terminate(&mut daemon);
    assert_eq!(code, 0);
}

#[test]
fn hung_mid_frame_client_cannot_wedge_shutdown() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("rabsd.sock");
    let marker = dir.path().join("rabsd.boot");
    let mut daemon = spawn_daemon(&socket, &marker);
    wait_for_socket(&socket);

    // A client that sends HALF a frame and then just... sits there.
    let mut hung = connect(&socket);
    hung.write_all(b"{\"kind\":\"hel").unwrap(); // no newline, ever
    std::thread::sleep(Duration::from_millis(100));

    let (code, elapsed) = terminate(&mut daemon);
    assert_eq!(code, 0, "clean exit despite the hung connection");
    assert!(
        elapsed < Duration::from_millis(500),
        "hung client wedged shutdown: {elapsed:?}"
    );
    drop(hung);
}

#[test]
fn stale_socket_takeover_and_live_daemon_refusal() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("rabsd.sock");
    let marker = dir.path().join("rabsd.boot");

    // A stale socket file from a dead incarnation.
    drop(std::os::unix::net::UnixListener::bind(&socket).unwrap());
    assert!(socket.exists());

    let mut daemon = spawn_daemon(&socket, &marker);
    wait_for_socket(&socket);
    let mut stream = connect(&socket);
    assert!(
        handshake(&mut stream).contains("hello-ok"),
        "takeover must yield a working daemon"
    );

    // A SECOND daemon must refuse while the first is alive.
    let second = Command::new(env!("CARGO_BIN_EXE_rabsd"))
        .args(["--run-for-ms", "2000"])
        .env("RABS_SOCKET_PATH", &socket)
        .env("RABS_BOOT_MARKER", dir.path().join("second.boot"))
        .env("RABS_STATE_DIR", dir.path().join("second.state"))
        .env("RABS_CONFIG", "/nonexistent-rabs-config")
        .output()
        .expect("second daemon");
    let stdout = String::from_utf8_lossy(&second.stdout);
    assert!(
        stdout.contains("\"clean\":false") || !second.status.success(),
        "second daemon must not silently coexist: {stdout}"
    );
    assert!(
        String::from_utf8_lossy(&second.stdout).contains("another rabsd is alive")
            || String::from_utf8_lossy(&second.stderr).contains("another rabsd is alive")
            || stdout.contains("work failed"),
        "refusal must name the live daemon"
    );

    let (code, _) = terminate(&mut daemon);
    assert_eq!(code, 0);
}
