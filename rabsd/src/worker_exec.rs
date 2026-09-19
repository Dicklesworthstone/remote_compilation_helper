//! Explicit operator lanes for receiving one real worker execution.
//! Neither command starts a compiler locally or installs files into a worktree.
//! Plaintext loopback and mutually authenticated native ATP are separate modes;
//! an error in the secure path never selects the loopback path.
//! Repeating an exact command replays a verified durable delivery without dispatch.
//! --resume explicitly retrieves a sealed remote result into a NEW directory;
//! incomplete prior deliveries remain untouched and never trigger reexecution.

use rabsd::coord::delivery_recovery::{DeliveryTrust, recover_existing_delivery};
use rabsd::coord::worker_delivery::{
    Delivery, DeliveryFailure, DeliveryMode, MAX_FRAME_BYTES, WorkerPeer, receive_operation,
    validate_request,
};
use serde_json::{Value, json};
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const ACCEPT_BUDGET: Duration = Duration::from_secs(60);
const HANDSHAKE_BUDGET: Duration = Duration::from_secs(60);
const POLL_INTERVAL: Duration = Duration::from_millis(2);
const MAX_EXECUTION_MILLIS: u64 = 30 * 60 * 1000;
const TRANSFER_ALLOWANCE: Duration = Duration::from_secs(5 * 60);

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn deadline(budget: Duration) -> io::Result<Instant> {
    Instant::now().checked_add(budget).ok_or_else(|| invalid("deadline overflow"))
}
fn check_deadline(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        Err(io::Error::new(io::ErrorKind::TimedOut,"worker exchange deadline exceeded"))
    } else { Ok(()) }
}

/// Intent is a local flag, never a guess based on a failed response. Accept it
/// before or after the positional arguments, but never twice or in their midst.
fn operation_arguments(args: &[String], count: usize) -> Option<(&[String], DeliveryMode)> {
    let (positionals, mode) = if args.len() == count {
        (args, DeliveryMode::Execute)
    } else if args.len() == count + 1 && args.first().is_some_and(|arg| arg == "--resume") {
        (&args[1..], DeliveryMode::Resume)
    } else if args.len() == count + 1 && args.last().is_some_and(|arg| arg == "--resume") {
        (&args[..count], DeliveryMode::Resume)
    } else {
        return None;
    };
    if positionals.iter().any(|arg| arg == "--resume") { return None; }
    Some((positionals, mode))
}

fn loopback_address(address: &str) -> io::Result<SocketAddr> {
    let address: SocketAddr = address.parse().map_err(|_| invalid("listen must be a literal loopback IP:port"))?;
    if !address.ip().is_loopback() {
        return Err(invalid("plaintext worker execution is restricted to literal loopback"));
    }
    Ok(address)
}
fn read_request(path: &Path) -> io::Result<Value> {
    let file = File::open(path)?;
    if !file.metadata()?.is_file() { return Err(invalid("request must be an ordinary file")); }
    let mut bytes = Vec::new();
    file.take(MAX_FRAME_BYTES as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > MAX_FRAME_BYTES { return Err(invalid("request file exceeds frame limit")); }
    let value = serde_json::from_slice(&bytes)?;
    // Resume also takes the ORIGINAL request. Only the shared receiver builds
    // the result-resume envelope; accepting an operator-supplied envelope here
    // could lose the original request fingerprint or nest recovery operations.
    validate_request(&value)?;
    Ok(value)
}
fn accept_one(listener: &TcpListener, budget: Duration) -> io::Result<TcpStream> {
    listener.set_nonblocking(true)?;
    let until = deadline(budget)?;
    loop {
        check_deadline(until)?;
        match listener.accept() {
            Ok((stream, address)) if address.ip().is_loopback() => return Ok(stream),
            Ok(_) => return Err(invalid("non-loopback worker peer")),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => std::thread::sleep(POLL_INTERVAL),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

/// Nonblocking syscalls with absolute phase deadlines. A slow peer cannot renew
/// its budget one byte at a time, and truncated frames never become clean EOF.
struct TcpPeer {
    stream: TcpStream,
    buffered: Vec<u8>,
    until: Instant,
    execution_budget: Duration,
    mode: DeliveryMode,
    operation_started: bool,
}
impl TcpPeer {
    fn new(stream: TcpStream, handshake: Duration, execution_budget: Duration, mode: DeliveryMode) -> io::Result<Self> {
        if !stream.peer_addr()?.ip().is_loopback() { return Err(invalid("non-loopback worker peer")); }
        stream.set_nonblocking(true)?;
        stream.set_nodelay(true)?;
        Ok(Self {stream,buffered:Vec::new(),until:deadline(handshake)?,execution_budget,mode,operation_started:false})
    }
}
impl WorkerPeer for TcpPeer {
    fn send(&mut self, value: &Value) -> io::Result<()> {
        check_deadline(self.until)?;
        let mut bytes = serde_json::to_vec(value)?;
        if bytes.len() > MAX_FRAME_BYTES { return Err(invalid("outbound frame too large")); }
        if matches!(value.get("kind").and_then(Value::as_str), Some("canonical-exec" | "result-resume")) {
            let expected = match self.mode {
                DeliveryMode::Execute => "canonical-exec",
                DeliveryMode::Resume => "result-resume",
            };
            if value["kind"] != expected { return Err(invalid("operation differs from local operator intent")); }
            if self.operation_started { return Err(invalid("operator connection cannot dispatch twice")); }
            self.operation_started = true; // burn before any possibly partial write
            self.until = deadline(match self.mode {
                DeliveryMode::Execute => self.execution_budget,
                // Spool restoration and all range reads share ONE deadline.
                // A historical compiler timeout does not govern byte recovery.
                DeliveryMode::Resume => TRANSFER_ALLOWANCE,
            })?;
        }
        bytes.push(b'\n');
        let mut offset = 0;
        while offset < bytes.len() {
            check_deadline(self.until)?;
            match self.stream.write(&bytes[offset..]) {
                Ok(0) => return Err(io::Error::new(io::ErrorKind::WriteZero,"worker frame made no progress")),
                Ok(n) => offset += n,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => std::thread::sleep(POLL_INTERVAL),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
    fn receive(&mut self) -> io::Result<Value> {
        let mut bytes = [0_u8;4096];
        loop {
            check_deadline(self.until)?;
            if let Some(end) = self.buffered.iter().position(|byte| *byte == b'\n') {
                if end > MAX_FRAME_BYTES { return Err(invalid("inbound frame too large")); }
                let line: Vec<_> = self.buffered.drain(..=end).collect();
                return serde_json::from_slice(&line[..end])
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData,error));
            }
            if self.buffered.len() > MAX_FRAME_BYTES { return Err(invalid("inbound frame too large")); }
            let capacity = bytes.len().min(MAX_FRAME_BYTES + 1 - self.buffered.len());
            match self.stream.read(&mut bytes[..capacity]) {
                Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof,
                    if self.buffered.is_empty() {"worker disconnected before response"} else {"truncated worker frame"})),
                Ok(n) => self.buffered.extend_from_slice(&bytes[..n]),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => std::thread::sleep(POLL_INTERVAL),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
    }
}

fn run_once(args: &[String], mode: DeliveryMode) -> Result<Delivery, DeliveryFailure> {
    let directory = PathBuf::from(&args[3]);
    let failure = |error: io::Error| DeliveryFailure {
        directory: directory.clone(),
        execution_may_have_run: mode == DeliveryMode::Resume
            || !matches!(std::fs::symlink_metadata(&directory),
                Err(error) if error.kind() == io::ErrorKind::NotFound),
        detail: error.to_string(),
    };
    let (address, request) = (|| -> io::Result<_> {
        let address = loopback_address(&args[0])?;
        let request = read_request(Path::new(&args[2]))?;
        Ok((address, request))
    })().map_err(&failure)?;
    // A durable result is independent of the worker still being connected.
    // Verify it BEFORE binding, and never turn an incomplete delivery into a
    // new execution. The receiver still atomically creates new destinations.
    if let Some(delivery) = recover_existing_delivery(
        &request, &args[1], &directory, DeliveryTrust::Loopback,
    )? {
        return Ok(delivery);
    }
    let setup = (|| -> io::Result<_> {
        let parent = directory.parent().ok_or_else(|| invalid("delivery directory needs an existing parent"))?;
        if !parent.is_dir() { return Err(invalid("delivery parent directory does not exist")); }
        let listener = TcpListener::bind(address)?;
        eprintln!("{}",json!({"kind":"worker-exec-listening","address":listener.local_addr()?.to_string(),
            "expected_worker":args[1],"request_id":request["request_id"],"transport_authenticated":false,
            "operation":if mode == DeliveryMode::Resume {"result-resume"} else {"canonical-exec"}}));
        let stream = accept_one(&listener,ACCEPT_BUDGET)?;
        let budget = Duration::from_millis(request.get("timeout_ms").and_then(Value::as_u64)
            .unwrap_or(MAX_EXECUTION_MILLIS).min(MAX_EXECUTION_MILLIS)) + TRANSFER_ALLOWANCE;
        TcpPeer::new(stream,HANDSHAKE_BUDGET,budget,mode)
    })();
    let mut peer = setup.map_err(failure)?;
    receive_operation(&mut peer,&request,&args[1],&directory,mode)
}

/// One explicit command, not a background service or an automatic retry loop.
pub fn run(args: &[String]) -> i32 {
    let Some((args, mode)) = operation_arguments(args, 4) else {
        eprintln!("usage: rabsd --worker-exec-loopback [--resume] <127.0.0.1:port> <expected-worker> <request.json> <absolute-delivery-directory>");
        eprintln!("--resume retrieves the original request into a new directory; it never executes it");
        return 2;
    };
    report_result(run_once(args, mode))
}

fn report_result(result: Result<Delivery, DeliveryFailure>) -> i32 {
    match result {
        Ok(delivery) => {
            println!("{}",delivery.to_json());
            // Byte delivery success is distinct from compiler success. The
            // verified receipt retains a nonzero compiler/interruption status.
            delivery.receipt["exit_code"].as_i64().and_then(|code| i32::try_from(code).ok()).unwrap_or(1)
        }
        Err(error) => {
            eprintln!("{}",json!({"kind":"worker-delivery-error","directory":error.directory,
                "execution_may_have_run":error.execution_may_have_run,"detail":error.detail,"reexecute":false}));
            1
        }
    }
}

fn coordinator_tls_files() -> io::Result<rabs_asupersync::worker_transport::TlsFiles> {
    let path = |name: &str| -> io::Result<PathBuf> {
        let value = std::env::var_os(name).filter(|value| !value.is_empty())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, format!("missing {name}")))?;
        let path = PathBuf::from(value);
        if !path.is_absolute() { return Err(invalid("coordinator TLS files must use absolute paths")); }
        Ok(path)
    };
    Ok(rabs_asupersync::worker_transport::TlsFiles {
        ca: path("RABS_COORD_TLS_CA")?,
        certificate: path("RABS_COORD_TLS_CERT")?,
        private_key: path("RABS_COORD_TLS_KEY")?,
    })
}

fn run_tls_once(args: &[String], mode: DeliveryMode) -> Result<Delivery, DeliveryFailure> {
    use asupersync::runtime::RuntimeBuilder;
    use rabs_asupersync::worker_transport::{MAX_JSON_RECORD, accept_peer};
    use rabsd::coord::secure_worker_delivery::{parse_worker_pin, receive_authenticated_operation};

    let directory = PathBuf::from(&args[4]);
    let failure = |detail: String| DeliveryFailure {
        directory: directory.clone(),
        execution_may_have_run: mode == DeliveryMode::Resume
            || !matches!(std::fs::symlink_metadata(&directory),
                Err(error) if error.kind() == io::ErrorKind::NotFound),
        detail,
    };
    let (address, pin, request) = (|| -> Result<_, String> {
        let address: SocketAddr = args[0].parse().map_err(|_| "listen must be a literal IP:port")?;
        if args[1].is_empty() { return Err("expected worker must not be empty".to_owned()); }
        let pin = parse_worker_pin(&args[2]).map_err(|error| error.to_string())?;
        let request = read_request(Path::new(&args[3])).map_err(|error| error.to_string())?;
        if serde_json::to_vec(&request).map_err(|error| error.to_string())?.len() > MAX_JSON_RECORD {
            return Err("request exceeds native ATP record limit".to_owned());
        }
        Ok((address, pin, request))
    })().map_err(&failure)?;
    // Local recovery checks the original authenticated SPKI and never falls
    // back to a plaintext receipt. It needs no live listener or new TLS session.
    if let Some(delivery) = recover_existing_delivery(
        &request, &args[1], &directory, DeliveryTrust::PinnedWorker(pin),
    )? {
        return Ok(delivery);
    }
    if !directory.parent().is_some_and(Path::is_dir) {
        return Err(failure("delivery parent directory does not exist".to_owned()));
    }
    // Validate all credentials BEFORE binding. This branch never invokes the
    // loopback transport, including when the TLS listener itself is loopback.
    let acceptor = coordinator_tls_files().map_err(|error| failure(error.to_string()))?
        .acceptor().map_err(&failure)?;
    let runtime = RuntimeBuilder::current_thread().build()
        .map_err(|error| failure(format!("worker delivery runtime: {error:?}")))?;
    let peer = runtime.block_on(async {
        let listener = asupersync::net::TcpListener::bind(address).await
            .map_err(|error| format!("worker TLS listen: {error}"))?;
        eprintln!("{}", json!({"kind":"worker-exec-listening",
            "address":listener.local_addr().map_err(|error| error.to_string())?.to_string(),
            "expected_worker":args[1], "expected_worker_spki_sha256":args[2],
            "request_id":request["request_id"], "transport":"mutual-tls-atp",
            "operation":if mode == DeliveryMode::Resume {"result-resume"} else {"canonical-exec"},
            "authentication_required":true}));
        let (stream, _) = asupersync::time::timeout(asupersync::time::wall_now(), ACCEPT_BUDGET,
            listener.accept()).await.map_err(|_| "worker TLS accept deadline exceeded")?
            .map_err(|error| format!("worker TLS accept: {error}"))?;
        accept_peer(&acceptor, stream).await
    }).map_err(failure)?;
    receive_authenticated_operation(&runtime, peer, pin, &args[1], &request, &directory, mode)
}

/// One explicitly pinned worker, authenticated transport, and one exact command.
/// TLS/admission failures terminate without dispatch or a plaintext retry.
/// Repeating the exact command revalidates an existing durable delivery offline.
/// --resume selects retrieval only; absent/uncertain retained results are errors.
pub fn run_tls(args: &[String]) -> i32 {
    let Some((args, mode)) = operation_arguments(args, 5) else {
        eprintln!("usage: rabsd --worker-exec-tls [--resume] <IP:port> <expected-worker> <worker-spki-sha256> <request.json> <absolute-delivery-directory>");
        eprintln!("required: RABS_COORD_TLS_CA, RABS_COORD_TLS_CERT, RABS_COORD_TLS_KEY");
        eprintln!("--resume retrieves the original request into a new directory; it never executes it");
        return 2;
    };
    report_result(run_tls_once(args, mode))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn pair_with_mode(budget: Duration, mode: DeliveryMode) -> (TcpPeer,TcpStream) {
        let listener=TcpListener::bind("127.0.0.1:0").unwrap();
        let client=TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let stream=accept_one(&listener,Duration::from_secs(2)).unwrap();
        (TcpPeer::new(stream,budget,budget,mode).unwrap(),client)
    }
    fn pair(budget: Duration) -> (TcpPeer,TcpStream) {
        pair_with_mode(budget, DeliveryMode::Execute)
    }
    #[test]
    fn loopback_is_literal_and_never_a_public_fallback() {
        for good in ["127.0.0.1:7000","[::1]:7000","127.0.0.1:0"] { assert!(loopback_address(good).is_ok()); }
        for bad in ["0.0.0.0:7000","[::]:7000","192.0.2.1:7000","localhost:7000","example.com:7000"] {
            assert!(loopback_address(bad).is_err(),"{bad}");
        }
    }
    #[test]
    fn buffered_tcp_preserves_fragmented_and_coalesced_frames() {
        let (mut peer,mut client)=pair(Duration::from_secs(2));
        let writer=std::thread::spawn(move || {
            client.write_all(b"{\"kind\":").unwrap();
            std::thread::sleep(Duration::from_millis(5));
            client.write_all(b"\"one\"}\n{\"kind\":\"two\"}\n").unwrap();
        });
        assert_eq!(peer.receive().unwrap()["kind"],"one");
        assert_eq!(peer.receive().unwrap()["kind"],"two");
        writer.join().unwrap();
    }
    #[test]
    fn truncated_non_utf8_oversized_and_stalled_peers_refuse() {
        for bytes in [b"{\"x\":".to_vec(),vec![0xff,b'\n'],vec![b'x';MAX_FRAME_BYTES+1]] {
            let (mut peer,mut client)=pair(Duration::from_secs(2));
            let writer=std::thread::spawn(move || { let _=client.write_all(&bytes); });
            assert!(peer.receive().is_err()); writer.join().unwrap();
        }
        let (mut peer,_client)=pair(Duration::from_millis(20));
        assert_eq!(peer.receive().unwrap_err().kind(),io::ErrorKind::TimedOut);
    }
    #[test]
    fn trickling_bytes_cannot_renew_the_absolute_deadline() {
        let (mut peer,mut client)=pair(Duration::from_millis(30));
        let writer=std::thread::spawn(move || {
            for _ in 0..20 { if client.write_all(b" ").is_err() {break;} std::thread::sleep(Duration::from_millis(5)); }
        });
        assert_eq!(peer.receive().unwrap_err().kind(),io::ErrorKind::TimedOut);
        drop(peer); writer.join().unwrap();
    }
    #[test]
    fn operator_never_sends_a_second_execution_on_one_connection() {
        let (mut peer,_client)=pair(Duration::from_secs(2));
        peer.send(&json!({"kind":"canonical-exec","request_id":1})).unwrap();
        assert!(peer.send(&json!({"kind":"canonical-exec","request_id":2})).is_err());
        assert!(peer.send(&json!({"kind":"result-resume","request_id":1})).is_err());
    }

    #[test]
    fn resume_intent_is_explicit_and_cannot_be_duplicated_or_misplaced() {
        let plain: Vec<String> = ["127.0.0.1:0", "worker", "request.json", "/delivery"]
            .into_iter().map(str::to_owned).collect();
        assert_eq!(operation_arguments(&plain, 4), Some((plain.as_slice(), DeliveryMode::Execute)));
        let mut leading = vec!["--resume".to_owned()];
        leading.extend(plain.clone());
        assert_eq!(operation_arguments(&leading, 4), Some((&leading[1..], DeliveryMode::Resume)));
        let mut trailing = plain.clone();
        trailing.push("--resume".to_owned());
        assert_eq!(operation_arguments(&trailing, 4), Some((&trailing[..4], DeliveryMode::Resume)));
        leading.push("--resume".to_owned());
        assert!(operation_arguments(&leading, 4).is_none());
        let mut misplaced = plain;
        misplaced.insert(2, "--resume".to_owned());
        assert!(operation_arguments(&misplaced, 4).is_none());
        assert!(operation_arguments(&[], 4).is_none());
    }

    #[test]
    fn resume_refuses_execution_and_has_one_restoration_transfer_deadline() {
        let (mut peer, _client) = pair_with_mode(Duration::from_secs(2), DeliveryMode::Resume);
        assert!(peer.send(&json!({"kind":"canonical-exec", "request_id":7})).is_err());
        peer.send(&json!({"kind":"result-resume", "request_id":7})).unwrap();
        let until = peer.until;
        assert!(until > Instant::now() + Duration::from_secs(60));
        peer.send(&json!({"kind":"output-read", "request_id":7})).unwrap();
        assert_eq!(peer.until, until);
        assert!(peer.send(&json!({"kind":"result-resume", "request_id":7})).is_err());
        assert!(peer.send(&json!({"kind":"canonical-exec", "request_id":7})).is_err());
        assert_eq!(peer.until, until);
    }

    #[test]
    fn resume_failures_before_connect_preserve_original_execution_uncertainty() {
        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("missing-request.json").to_string_lossy().into_owned();
        let destination = root.path().join("delivery").to_string_lossy().into_owned();
        let plain = vec!["127.0.0.1:0".to_owned(), "worker".to_owned(), missing.clone(), destination.clone()];
        let tls = vec!["127.0.0.1:0".to_owned(), "worker".to_owned(), "01".repeat(32), missing, destination];
        for mode in [DeliveryMode::Execute, DeliveryMode::Resume] {
            assert_eq!(run_once(&plain, mode).unwrap_err().execution_may_have_run, mode == DeliveryMode::Resume);
            assert_eq!(run_tls_once(&tls, mode).unwrap_err().execution_may_have_run, mode == DeliveryMode::Resume);
            let mut invalid_pin = tls.clone();
            invalid_pin[2] = "invalid".to_owned();
            assert_eq!(run_tls_once(&invalid_pin, mode).unwrap_err().execution_may_have_run, mode == DeliveryMode::Resume);
        }
        assert!(!root.path().join("delivery").exists());
    }
}
