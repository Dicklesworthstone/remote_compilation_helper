//! Explicit loopback operator lane for receiving one real worker execution.
//! This command neither starts a compiler locally nor installs received files
//! into a worktree. Authenticated fleet transport remains a separate entry point.

use rabsd::coord::worker_delivery::{
    Delivery, DeliveryFailure, MAX_FRAME_BYTES, WorkerPeer, receive_execution, validate_request,
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
    execution_started: bool,
}
impl TcpPeer {
    fn new(stream: TcpStream, handshake: Duration, execution_budget: Duration) -> io::Result<Self> {
        if !stream.peer_addr()?.ip().is_loopback() { return Err(invalid("non-loopback worker peer")); }
        stream.set_nonblocking(true)?;
        stream.set_nodelay(true)?;
        Ok(Self {stream,buffered:Vec::new(),until:deadline(handshake)?,execution_budget,execution_started:false})
    }
}
impl WorkerPeer for TcpPeer {
    fn send(&mut self, value: &Value) -> io::Result<()> {
        check_deadline(self.until)?;
        let mut bytes = serde_json::to_vec(value)?;
        if bytes.len() > MAX_FRAME_BYTES { return Err(invalid("outbound frame too large")); }
        if value.get("kind").and_then(Value::as_str) == Some("canonical-exec") {
            if self.execution_started { return Err(invalid("operator connection cannot execute twice")); }
            self.execution_started = true;
            self.until = deadline(self.execution_budget)?;
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

fn run_once(args: &[String]) -> Result<Delivery, DeliveryFailure> {
    let directory = PathBuf::from(&args[3]);
    let setup = (|| -> io::Result<_> {
        let address = loopback_address(&args[0])?;
        let request = read_request(Path::new(&args[2]))?;
        if args[1].is_empty() { return Err(invalid("expected worker must not be empty")); }
        if !directory.is_absolute() || directory.components().any(|c| matches!(c,std::path::Component::ParentDir)) {
            return Err(invalid("delivery directory must be absolute without traversal"));
        }
        match std::fs::symlink_metadata(&directory) {
            Ok(_) => return Err(io::Error::new(io::ErrorKind::AlreadyExists,"delivery directory already exists")),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let parent = directory.parent().ok_or_else(|| invalid("delivery directory needs an existing parent"))?;
        if !parent.is_dir() { return Err(invalid("delivery parent directory does not exist")); }
        let listener = TcpListener::bind(address)?;
        eprintln!("{}",json!({"kind":"worker-exec-listening","address":listener.local_addr()?.to_string(),
            "expected_worker":args[1],"request_id":request["request_id"],"transport_authenticated":false}));
        let stream = accept_one(&listener,ACCEPT_BUDGET)?;
        let budget = Duration::from_millis(request.get("timeout_ms").and_then(Value::as_u64)
            .unwrap_or(MAX_EXECUTION_MILLIS).min(MAX_EXECUTION_MILLIS)) + TRANSFER_ALLOWANCE;
        Ok((TcpPeer::new(stream,HANDSHAKE_BUDGET,budget)?,request))
    })();
    let (mut peer,request) = setup.map_err(|error| DeliveryFailure {
        directory:directory.clone(),execution_may_have_run:false,detail:error.to_string(),
    })?;
    receive_execution(&mut peer,&request,&args[1],&directory)
}

/// One explicit command, not a background service or an automatic retry loop.
pub fn run(args: &[String]) -> i32 {
    if args.len() != 4 {
        eprintln!("usage: rabsd --worker-exec-loopback <127.0.0.1:port> <expected-worker> <request.json> <new-absolute-directory>");
        return 2;
    }
    match run_once(args) {
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

#[cfg(test)]
mod tests {
    use super::*;
    fn pair(budget: Duration) -> (TcpPeer,TcpStream) {
        let listener=TcpListener::bind("127.0.0.1:0").unwrap();
        let client=TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let stream=accept_one(&listener,Duration::from_secs(2)).unwrap();
        (TcpPeer::new(stream,budget,budget).unwrap(),client)
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
    }
}
