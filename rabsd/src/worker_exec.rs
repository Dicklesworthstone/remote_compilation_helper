//! Explicit operator lanes for receiving one real worker execution.
//! Execution commands retain verified deliveries; prepared-build commands also
//! install complete successful outputs into a new operator-selected directory.
//! No command starts a compiler locally.
//! Plaintext loopback and mutually authenticated native ATP are separate modes;
//! an error in the secure path never selects the loopback path.
//! Repeating an exact command replays a verified durable delivery without dispatch.
//! --resume explicitly retrieves a sealed remote result into a NEW directory;
//! incomplete prior deliveries remain untouched and never trigger reexecution.
//! --resume-from selects local prefixes for that same recovery path, not execution.
//! --acknowledge explicitly reconciles an existing local delivery with the worker;
//! it sends no byte-range reads or compiler execution and never replaces files.
//! --source-root selects local capture for a request's explicit source_manifest;
//! it never infers upload permission from a checkout or rewrites the request.

use rabsd::coord::delivery_ack::PendingAcknowledgment;
use rabsd::coord::delivery_recovery::{DeliveryTrust, recover_existing_delivery};
use rabsd::coord::source_delivery::{SourcePeer, SourceUpload, request_manifest};
use rabsd::coord::worker_delivery::{
    Delivery, DeliveryFailure, DeliveryMode, MAX_FRAME_BYTES, ResumePeer, ResumeSource,
    WorkerPeer, receive_operation, validate_request,
};
use serde_json::{Value, json};
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

mod prepared_build;
pub use prepared_build::{run_build, run_build_tls};

const ACCEPT_BUDGET: Duration = Duration::from_secs(60);
const HANDSHAKE_BUDGET: Duration = Duration::from_secs(60);
const POLL_INTERVAL: Duration = Duration::from_millis(2);
const MAX_EXECUTION_MILLIS: u64 = 30 * 60 * 1000;
const TRANSFER_ALLOWANCE: Duration = Duration::from_secs(5 * 60);

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn deadline(budget: Duration) -> io::Result<Instant> {
    Instant::now()
        .checked_add(budget)
        .ok_or_else(|| invalid("deadline overflow"))
}
fn check_deadline(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "worker exchange deadline exceeded",
        ))
    } else {
        Ok(())
    }
}

/// Intent is a local flag, never a guess based on a failed response. Accept it
/// before or after the positional arguments, but never twice or in their midst.
/// --resume-from implies resume; it never changes the saved execution request.
fn operation_arguments(args: &[String], count: usize) -> Option<(&[String], DeliveryMode, Option<&Path>)> {
    let (positionals, mode, resume_from) = if args.len() == count {
        (args, DeliveryMode::Execute, None)
    } else if args.len() == count + 1 && args.first().is_some_and(|arg| arg == "--resume") {
        (&args[1..], DeliveryMode::Resume, None)
    } else if args.len() == count + 1 && args.last().is_some_and(|arg| arg == "--resume") {
        (&args[..count], DeliveryMode::Resume, None)
    } else if args.len() == count + 2 && args.first().is_some_and(|arg| arg == "--resume-from") {
        (&args[2..], DeliveryMode::Resume, Some(Path::new(&args[1])))
    } else if args.len() == count + 2 && args[count] == "--resume-from" {
        (&args[..count], DeliveryMode::Resume, Some(Path::new(&args[count + 1])))
    } else {
        return None;
    };
    if positionals.iter().any(|arg| matches!(arg.as_str(), "--resume" | "--resume-from" | "--acknowledge"))
        || resume_from.is_some_and(|root| !root.is_absolute())
    {
        return None;
    }
    Some((positionals, mode, resume_from))
}

/// Acceptance is independently selected, never an implicit network side effect
/// of ordinary offline receipt recovery. Source upload and resume flags conflict.
fn acknowledgment_arguments(args: &[String], count: usize) -> Option<&[String]> {
    if args.len() != count + 1 {
        return None;
    }
    let positionals = if args.first().is_some_and(|arg| arg == "--acknowledge") {
        &args[1..]
    } else if args.last().is_some_and(|arg| arg == "--acknowledge") {
        &args[..count]
    } else {
        return None;
    };
    if positionals
        .iter()
        .any(|arg| matches!(arg.as_str(), "--resume" | "--resume-from" | "--source-root" | "--acknowledge"))
    {
        return None;
    }
    Some(positionals)
}

/// Source capture is explicit and execution-only. Keep the existing resume
/// spelling/placement contract; do not interpret an absent upload as a retry.
fn execution_arguments(
    args: &[String],
    count: usize,
) -> Option<(&[String], DeliveryMode, Option<&Path>, Option<&Path>)> {
    let (args, source_root) = if args.first().is_some_and(|arg| arg == "--source-root") {
        (args.get(2..)?, Some(Path::new(args.get(1)?)))
    } else if args.len() >= 2 && args[args.len() - 2] == "--source-root" {
        (&args[..args.len() - 2], Some(Path::new(args.last()?)))
    } else {
        (args, None)
    };
    let (args, mode, resume_from) = operation_arguments(args, count)?;
    if args.iter().any(|arg| arg == "--source-root")
        || source_root.is_some_and(|root| !root.is_absolute())
        || (source_root.is_some() && mode == DeliveryMode::Resume)
    {
        return None;
    }
    Some((args, mode, source_root, resume_from))
}

/// Reuse the coherent sealed-capture boundary, then select ONLY the files whose
/// paths, bytes and executable bits the original request already authorizes.
/// Capturing a root does not authorize uploading its siblings. The snapshot's
/// paired scans each have the existing source-protocol byte bound.
fn capture_source(
    request: &Value,
    mode: DeliveryMode,
    root: Option<&Path>,
) -> io::Result<Option<SourceUpload>> {
    let manifest = request_manifest(request)?;
    if mode == DeliveryMode::Resume {
        if root.is_some() {
            return Err(invalid("--resume cannot upload source"));
        }
        return Ok(None);
    }
    let root = match (manifest, root) {
        (None, None) => return Ok(None),
        (None, Some(_)) => {
            return Err(invalid(
                "--source-root requires source_manifest, not workspace_backing",
            ));
        }
        (Some(_), None) => return Err(invalid("source_manifest execution requires --source-root")),
        (Some(_), Some(root)) => root,
    };
    if !root.is_absolute() {
        return Err(invalid("source root must be absolute"));
    }
    let image = rabs_sandbox::snapshot_capture::capture_sealed_source(
        &[("workspace".to_owned(), root.to_path_buf())],
        false,
        2,
        rabs_sandbox::source_transfer::MAX_SOURCE_BYTES,
    )
    .map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("source capture refused: {error:?}"),
        )
    })?;
    SourceUpload::for_request(std::sync::Arc::new(image), "workspace", request).map(Some)
}

/// A prefix source is local intent, not proof. Validate it before credentials,
/// listening, or worker contact, but only AFTER complete local receipt recovery.
fn prepare_resume_source(
    mode: DeliveryMode, root: Option<&Path>, destination: &Path,
) -> io::Result<Option<ResumeSource>> {
    let Some(root) = root else { return Ok(None); };
    if mode != DeliveryMode::Resume {
        return Err(invalid("--resume-from is result recovery only"));
    }
    let source = ResumeSource::open(root)?;
    source.validate_destination(destination)?;
    Ok(Some(source))
}

fn loopback_address(address: &str) -> io::Result<SocketAddr> {
    let address: SocketAddr = address
        .parse()
        .map_err(|_| invalid("listen must be a literal loopback IP:port"))?;
    if !address.ip().is_loopback() {
        return Err(invalid(
            "plaintext worker execution is restricted to literal loopback",
        ));
    }
    Ok(address)
}
fn read_request(path: &Path) -> io::Result<Value> {
    let file = File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(invalid("request must be an ordinary file"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_FRAME_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(invalid("request file exceeds frame limit"));
    }
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
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(POLL_INTERVAL)
            }
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
    source_started: bool,
}
impl TcpPeer {
    fn new(
        stream: TcpStream,
        handshake: Duration,
        execution_budget: Duration,
        mode: DeliveryMode,
    ) -> io::Result<Self> {
        if !stream.peer_addr()?.ip().is_loopback() {
            return Err(invalid("non-loopback worker peer"));
        }
        stream.set_nonblocking(true)?;
        stream.set_nodelay(true)?;
        Ok(Self {
            stream,
            buffered: Vec::new(),
            until: deadline(handshake)?,
            execution_budget,
            mode,
            operation_started: false,
            source_started: false,
        })
    }
}
impl WorkerPeer for TcpPeer {
    fn send(&mut self, value: &Value) -> io::Result<()> {
        check_deadline(self.until)?;
        let mut bytes = serde_json::to_vec(value)?;
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(invalid("outbound frame too large"));
        }
        match value.get("kind").and_then(Value::as_str) {
            Some("source-begin") => {
                if self.mode != DeliveryMode::Execute
                    || self.operation_started
                    || self.source_started
                {
                    return Err(invalid(
                        "source upload requires a fresh execution connection",
                    ));
                }
                self.source_started = true;
                self.until = deadline(TRANSFER_ALLOWANCE)?;
            }
            Some("source-chunk" | "source-seal") => {
                if self.mode != DeliveryMode::Execute
                    || !self.source_started
                    || self.operation_started
                {
                    return Err(invalid("source frame outside upload"));
                }
                // Chunk progress and the final seal never renew the budget.
            }
            _ => {}
        }
        if matches!(
            value.get("kind").and_then(Value::as_str),
            Some("canonical-exec" | "result-resume")
        ) {
            let expected = match self.mode {
                DeliveryMode::Execute => "canonical-exec",
                DeliveryMode::Resume => "result-resume",
            };
            if value["kind"] != expected {
                return Err(invalid("operation differs from local operator intent"));
            }
            if self.operation_started {
                return Err(invalid("operator connection cannot dispatch twice"));
            }
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
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "worker frame made no progress",
                    ));
                }
                Ok(n) => offset += n,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(POLL_INTERVAL)
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
    fn receive(&mut self) -> io::Result<Value> {
        let mut bytes = [0_u8; 4096];
        loop {
            check_deadline(self.until)?;
            if let Some(end) = self.buffered.iter().position(|byte| *byte == b'\n') {
                if end > MAX_FRAME_BYTES {
                    return Err(invalid("inbound frame too large"));
                }
                let line: Vec<_> = self.buffered.drain(..=end).collect();
                return serde_json::from_slice(&line[..end])
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error));
            }
            if self.buffered.len() > MAX_FRAME_BYTES {
                return Err(invalid("inbound frame too large"));
            }
            let capacity = bytes.len().min(MAX_FRAME_BYTES + 1 - self.buffered.len());
            match self.stream.read(&mut bytes[..capacity]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        if self.buffered.is_empty() {
                            "worker disconnected before response"
                        } else {
                            "truncated worker frame"
                        },
                    ));
                }
                Ok(n) => self.buffered.extend_from_slice(&bytes[..n]),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(POLL_INTERVAL)
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
    }
}

fn operation_failure(directory: &Path, mode: DeliveryMode, detail: String) -> DeliveryFailure {
    DeliveryFailure {
        directory: directory.to_path_buf(),
        execution_may_have_run: mode == DeliveryMode::Resume
            || !matches!(std::fs::symlink_metadata(directory),
                Err(error) if error.kind() == io::ErrorKind::NotFound),
        detail,
    }
}

/// Keep the parsed request fixed from preflight through dispatch and installation.
/// Prepared builds must not reopen a mutable request file between those phases.
struct WorkerOperation<'a> {
    address: &'a str,
    worker: &'a str,
    request: &'a Value,
    directory: &'a Path,
    mode: DeliveryMode,
    source_root: Option<&'a Path>,
    resume_from: Option<&'a Path>,
}

fn run_once(
    args: &[String],
    mode: DeliveryMode,
    source_root: Option<&Path>,
    resume_from: Option<&Path>,
) -> Result<Delivery, DeliveryFailure> {
    let directory = Path::new(&args[3]);
    let request = read_request(Path::new(&args[2]))
        .map_err(|error| operation_failure(directory, mode, error.to_string()))?;
    run_loopback_operation(WorkerOperation {
        address: &args[0],
        worker: &args[1],
        request: &request,
        directory,
        mode,
        source_root,
        resume_from,
    })
}

fn run_loopback_operation(operation: WorkerOperation<'_>) -> Result<Delivery, DeliveryFailure> {
    let WorkerOperation {
        address,
        worker,
        request,
        directory,
        mode,
        source_root,
        resume_from,
    } = operation;
    let failure = |error: io::Error| operation_failure(directory, mode, error.to_string());
    let address = loopback_address(address).map_err(&failure)?;
    // A durable result is independent of the worker still being connected.
    // Verify it BEFORE binding, and never turn an incomplete delivery into a
    // new execution. The receiver still atomically creates new destinations.
    if let Some(delivery) =
        recover_existing_delivery(request, worker, directory, DeliveryTrust::Loopback)?
    {
        return Ok(delivery);
    }
    // Offline receipt recovery above must not depend on a still-existing
    // checkout or old partial directory. New work preflights before listening.
    let upload = capture_source(request, mode, source_root).map_err(&failure)?;
    let reuse = prepare_resume_source(mode, resume_from, directory).map_err(&failure)?;
    let setup = (|| -> io::Result<_> {
        let parent = directory
            .parent()
            .ok_or_else(|| invalid("delivery directory needs an existing parent"))?;
        if !parent.is_dir() {
            return Err(invalid("delivery parent directory does not exist"));
        }
        let listener = TcpListener::bind(address)?;
        eprintln!(
            "{}",
            json!({"kind":"worker-exec-listening","address":listener.local_addr()?.to_string(),
            "expected_worker":worker,"request_id":request["request_id"],"transport_authenticated":false,
            "operation":if mode == DeliveryMode::Resume {"result-resume"} else {"canonical-exec"}})
        );
        let stream = accept_one(&listener, ACCEPT_BUDGET)?;
        let budget = Duration::from_millis(
            request
                .get("timeout_ms")
                .and_then(Value::as_u64)
                .unwrap_or(MAX_EXECUTION_MILLIS)
                .min(MAX_EXECUTION_MILLIS),
        ) + TRANSFER_ALLOWANCE;
        TcpPeer::new(stream, HANDSHAKE_BUDGET, budget, mode)
    })();
    let mut peer = setup.map_err(&failure)?;
    if let Some(reuse) = &reuse {
        return receive_operation(&mut ResumePeer::new(&mut peer, reuse), request, worker, directory, mode);
    }
    match upload.as_ref() {
        Some(upload) => {
            let mut peer = SourcePeer::new(&mut peer, upload, request).map_err(failure)?;
            receive_operation(&mut peer, request, worker, directory, mode)
        }
        None => receive_operation(&mut peer, request, worker, directory, mode),
    }
}

fn run_acknowledgment_once(args: &[String]) -> Result<Delivery, DeliveryFailure> {
    let directory = PathBuf::from(&args[3]);
    let failure = |error: io::Error| DeliveryFailure {
        directory: directory.clone(),
        execution_may_have_run: true,
        detail: error.to_string(),
    };
    let address = loopback_address(&args[0]).map_err(&failure)?;
    let request = read_request(Path::new(&args[2])).map_err(&failure)?;
    // No listener, source capture, or new directory can precede this proof.
    let pending =
        PendingAcknowledgment::verify(&request, &args[1], &directory, DeliveryTrust::Loopback)?;
    let listener = TcpListener::bind(address).map_err(&failure)?;
    let address = listener.local_addr().map_err(&failure)?;
    eprintln!(
        "{}",
        json!({"kind":"worker-exec-listening", "address":address.to_string(),
        "expected_worker":args[1], "request_id":request["request_id"],
        "transport_authenticated":false, "operation":"result-acknowledgment"})
    );
    let stream = accept_one(&listener, ACCEPT_BUDGET).map_err(&failure)?;
    let mut peer = TcpPeer::new(
        stream,
        HANDSHAKE_BUDGET,
        TRANSFER_ALLOWANCE,
        DeliveryMode::Resume,
    )
    .map_err(failure)?;
    pending.acknowledge(&mut peer)
}

/// One explicit command, not a background service or an automatic retry loop.
pub fn run(args: &[String]) -> i32 {
    if let Some(args) = acknowledgment_arguments(args, 4) {
        return report_acknowledgment(run_acknowledgment_once(args));
    }
    let Some((args, mode, source_root, resume_from)) = execution_arguments(args, 4) else {
        eprintln!(
            "usage: rabsd --worker-exec-loopback [--resume | --resume-from <absolute-old-delivery> | --acknowledge | --source-root <absolute-root>] <127.0.0.1:port> <expected-worker> <request.json> <absolute-delivery-directory>"
        );
        eprintln!(
            "--resume retrieves the original request into a new directory; --resume-from may reuse local prefixes after complete-file verification"
        );
        eprintln!(
            "--acknowledge requires an existing verified delivery and releases only its matching remote result"
        );
        eprintln!(
            "--source-root captures only for new source_manifest requests; only declared regular files are uploaded"
        );
        return 2;
    };
    report_result(run_once(args, mode, source_root, resume_from))
}

fn report_acknowledgment(result: Result<Delivery, DeliveryFailure>) -> i32 {
    match result {
        Ok(delivery) => {
            println!("{}", delivery.to_json());
            // This command reports receiver acceptance, not the historical
            // compiler exit. That original outcome remains in the receipt.
            0
        }
        Err(error) => report_result(Err(error)),
    }
}

fn report_result(result: Result<Delivery, DeliveryFailure>) -> i32 {
    match result {
        Ok(delivery) => {
            println!("{}", delivery.to_json());
            // Byte delivery success is distinct from compiler success. The
            // verified receipt retains a nonzero compiler/interruption status.
            delivery.receipt["exit_code"]
                .as_i64()
                .and_then(|code| i32::try_from(code).ok())
                .unwrap_or(1)
        }
        Err(error) => {
            eprintln!(
                "{}",
                json!({"kind":"worker-delivery-error","directory":error.directory,
                "execution_may_have_run":error.execution_may_have_run,"detail":error.detail,"reexecute":false})
            );
            1
        }
    }
}

fn coordinator_tls_files() -> io::Result<rabs_asupersync::worker_transport::TlsFiles> {
    let path = |name: &str| -> io::Result<PathBuf> {
        let value = std::env::var_os(name)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, format!("missing {name}"))
            })?;
        let path = PathBuf::from(value);
        if !path.is_absolute() {
            return Err(invalid("coordinator TLS files must use absolute paths"));
        }
        Ok(path)
    };
    Ok(rabs_asupersync::worker_transport::TlsFiles {
        ca: path("RABS_COORD_TLS_CA")?,
        certificate: path("RABS_COORD_TLS_CERT")?,
        private_key: path("RABS_COORD_TLS_KEY")?,
    })
}

/// All secure operator intents use this one native mutual-TLS listener. Local
/// proof/source preflight is the caller's responsibility and precedes this call.
fn accept_tls_worker(
    address: SocketAddr,
    worker: &str,
    pin: &str,
    request_id: &Value,
    operation: &str,
) -> Result<
    (
        asupersync::runtime::Runtime,
        rabs_asupersync::worker_transport::AuthenticatedPeer,
        rabsd::coord::secure_worker_delivery::PinnedWorkerAdmission,
    ),
    String,
> {
    use asupersync::runtime::RuntimeBuilder;
    use rabs_asupersync::worker_transport::accept_peer;
    use rabsd::coord::secure_worker_delivery::{PinnedWorkerAdmission, parse_worker_pin};
    let acceptor = coordinator_tls_files()
        .map_err(|error| error.to_string())?
        .acceptor()?;
    // A stable worker name owns its persistent pin and boot history. Hold its
    // exclusive admission capability before listening and through stream close.
    let state = std::env::var_os("RABS_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(crate::default_under_home(".cache/rch/rabs-state")));
    let admission = PinnedWorkerAdmission::open(
        &state,
        worker,
        parse_worker_pin(pin).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .map_err(|error| format!("worker delivery runtime: {error:?}"))?;
    let peer = runtime.block_on(async {
        let listener = asupersync::net::TcpListener::bind(address)
            .await
            .map_err(|error| format!("worker TLS listen: {error}"))?;
        eprintln!(
            "{}",
            json!({"kind":"worker-exec-listening",
            "address":listener.local_addr().map_err(|error| error.to_string())?.to_string(),
            "expected_worker":worker, "expected_worker_spki_sha256":pin,
            "request_id":request_id, "transport":"mutual-tls-atp",
            "operation":operation, "authentication_required":true})
        );
        let (stream, _) = asupersync::time::timeout(
            asupersync::time::wall_now(),
            ACCEPT_BUDGET,
            listener.accept(),
        )
        .await
        .map_err(|_| "worker TLS accept deadline exceeded")?
        .map_err(|error| format!("worker TLS accept: {error}"))?;
        accept_peer(&acceptor, stream).await
    })?;
    Ok((runtime, peer, admission))
}

fn run_tls_once(
    args: &[String],
    mode: DeliveryMode,
    source_root: Option<&Path>,
    resume_from: Option<&Path>,
) -> Result<Delivery, DeliveryFailure> {
    let directory = Path::new(&args[4]);
    let request = read_request(Path::new(&args[3]))
        .map_err(|error| operation_failure(directory, mode, error.to_string()))?;
    run_tls_operation(
        WorkerOperation {
            address: &args[0],
            worker: &args[1],
            request: &request,
            directory,
            mode,
            source_root,
            resume_from,
        },
        &args[2],
    )
}

fn run_tls_operation(
    operation: WorkerOperation<'_>,
    worker_pin: &str,
) -> Result<Delivery, DeliveryFailure> {
    use rabs_asupersync::worker_transport::MAX_JSON_RECORD;
    use rabsd::coord::secure_worker_delivery::{
        parse_worker_pin, receive_authenticated_operation, receive_authenticated_source,
    };

    let WorkerOperation {
        address,
        worker,
        request,
        directory,
        mode,
        source_root,
        resume_from,
    } = operation;
    let failure = |detail: String| operation_failure(directory, mode, detail);
    let (address, pin) = (|| -> Result<_, String> {
        let address: SocketAddr = address
            .parse()
            .map_err(|_| "listen must be a literal IP:port")?;
        if worker.is_empty() {
            return Err("expected worker must not be empty".to_owned());
        }
        let pin = parse_worker_pin(worker_pin).map_err(|error| error.to_string())?;
        if serde_json::to_vec(request)
            .map_err(|error| error.to_string())?
            .len()
            > MAX_JSON_RECORD
        {
            return Err("request exceeds native ATP record limit".to_owned());
        }
        Ok((address, pin))
    })()
    .map_err(&failure)?;
    // Local recovery checks the original authenticated SPKI and never falls
    // back to a plaintext receipt. It needs no live listener or new TLS session.
    if let Some(delivery) =
        recover_existing_delivery(request, worker, directory, DeliveryTrust::PinnedWorker(pin))?
    {
        return Ok(delivery);
    }
    let upload =
        capture_source(request, mode, source_root).map_err(|error| failure(error.to_string()))?;
    let reuse = prepare_resume_source(mode, resume_from, directory)
        .map_err(|error| failure(error.to_string()))?;
    if !directory.parent().is_some_and(Path::is_dir) {
        return Err(failure(
            "delivery parent directory does not exist".to_owned(),
        ));
    }
    let (runtime, peer, admission) = accept_tls_worker(
        address,
        worker,
        worker_pin,
        &request["request_id"],
        if mode == DeliveryMode::Resume {
            "result-resume"
        } else {
            "canonical-exec"
        },
    )
    .map_err(failure)?;
    match upload.as_ref() {
        Some(upload) => {
            receive_authenticated_source(&runtime, peer, admission, request, directory, upload)
        }
        None => {
            receive_authenticated_operation(&runtime, peer, admission, request, directory, mode, reuse.as_ref())
        }
    }
}

fn run_tls_acknowledgment_once(args: &[String]) -> Result<Delivery, DeliveryFailure> {
    use rabsd::coord::secure_worker_delivery::{acknowledge_authenticated, parse_worker_pin};
    let directory = PathBuf::from(&args[4]);
    let failure = |detail: String| DeliveryFailure {
        directory: directory.clone(),
        execution_may_have_run: true,
        detail,
    };
    let address: SocketAddr = args[0]
        .parse()
        .map_err(|_| failure("listen must be a literal IP:port".to_owned()))?;
    let pin = parse_worker_pin(&args[2]).map_err(|error| failure(error.to_string()))?;
    let request = read_request(Path::new(&args[3])).map_err(|error| failure(error.to_string()))?;
    // Verify the historical SPKI and every byte BEFORE reading credentials or
    // starting the listener. A loopback receipt cannot be upgraded to TLS.
    let pending = PendingAcknowledgment::verify(
        &request,
        &args[1],
        &directory,
        DeliveryTrust::PinnedWorker(pin),
    )?;
    let envelope =
        json!({"kind":"result-resume", "request_id":request["request_id"], "request":request});
    if serde_json::to_vec(&envelope)
        .map_err(|error| failure(error.to_string()))?
        .len()
        > rabs_asupersync::worker_transport::MAX_JSON_RECORD
    {
        return Err(failure(
            "acknowledgment request exceeds native ATP record limit".to_owned(),
        ));
    }
    let (runtime, peer, admission) = accept_tls_worker(
        address,
        &args[1],
        &args[2],
        &request["request_id"],
        "result-acknowledgment",
    )
    .map_err(failure)?;
    acknowledge_authenticated(&runtime, peer, admission, pending)
}

/// One explicitly pinned worker, authenticated transport, and one exact command.
/// TLS/admission failures terminate without dispatch or a plaintext retry.
/// Repeating the exact command revalidates an existing durable delivery offline.
/// --resume selects retrieval only; --acknowledge releases verified local results.
pub fn run_tls(args: &[String]) -> i32 {
    if let Some(args) = acknowledgment_arguments(args, 5) {
        return report_acknowledgment(run_tls_acknowledgment_once(args));
    }
    let Some((args, mode, source_root, resume_from)) = execution_arguments(args, 5) else {
        eprintln!(
            "usage: rabsd --worker-exec-tls [--resume | --resume-from <absolute-old-delivery> | --acknowledge | --source-root <absolute-root>] <IP:port> <expected-worker> <worker-spki-sha256> <request.json> <absolute-delivery-directory>"
        );
        eprintln!("required: RABS_COORD_TLS_CA, RABS_COORD_TLS_CERT, RABS_COORD_TLS_KEY");
        eprintln!(
            "--resume retrieves the original request into a new directory; --resume-from may reuse local prefixes after complete-file verification"
        );
        eprintln!(
            "--acknowledge requires an existing pinned delivery; it never downloads, executes or downgrades transport"
        );
        eprintln!(
            "--source-root captures only for new source_manifest requests; only declared regular files are uploaded"
        );
        return 2;
    };
    report_result(run_tls_once(args, mode, source_root, resume_from))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn pair_with_mode(budget: Duration, mode: DeliveryMode) -> (TcpPeer, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let stream = accept_one(&listener, Duration::from_secs(2)).unwrap();
        (TcpPeer::new(stream, budget, budget, mode).unwrap(), client)
    }
    fn pair(budget: Duration) -> (TcpPeer, TcpStream) {
        pair_with_mode(budget, DeliveryMode::Execute)
    }
    #[test]
    fn loopback_is_literal_and_never_a_public_fallback() {
        for good in ["127.0.0.1:7000", "[::1]:7000", "127.0.0.1:0"] {
            assert!(loopback_address(good).is_ok());
        }
        for bad in [
            "0.0.0.0:7000",
            "[::]:7000",
            "192.0.2.1:7000",
            "localhost:7000",
            "example.com:7000",
        ] {
            assert!(loopback_address(bad).is_err(), "{bad}");
        }
    }
    #[test]
    fn buffered_tcp_preserves_fragmented_and_coalesced_frames() {
        let (mut peer, mut client) = pair(Duration::from_secs(2));
        let writer = std::thread::spawn(move || {
            client.write_all(b"{\"kind\":").unwrap();
            std::thread::sleep(Duration::from_millis(5));
            client.write_all(b"\"one\"}\n{\"kind\":\"two\"}\n").unwrap();
        });
        assert_eq!(peer.receive().unwrap()["kind"], "one");
        assert_eq!(peer.receive().unwrap()["kind"], "two");
        writer.join().unwrap();
    }
    #[test]
    fn truncated_non_utf8_oversized_and_stalled_peers_refuse() {
        for bytes in [
            b"{\"x\":".to_vec(),
            vec![0xff, b'\n'],
            vec![b'x'; MAX_FRAME_BYTES + 1],
        ] {
            let (mut peer, mut client) = pair(Duration::from_secs(2));
            let writer = std::thread::spawn(move || {
                let _ = client.write_all(&bytes);
            });
            assert!(peer.receive().is_err());
            writer.join().unwrap();
        }
        let (mut peer, _client) = pair(Duration::from_millis(20));
        assert_eq!(peer.receive().unwrap_err().kind(), io::ErrorKind::TimedOut);
    }
    #[test]
    fn trickling_bytes_cannot_renew_the_absolute_deadline() {
        let (mut peer, mut client) = pair(Duration::from_millis(30));
        let writer = std::thread::spawn(move || {
            for _ in 0..20 {
                if client.write_all(b" ").is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        });
        assert_eq!(peer.receive().unwrap_err().kind(), io::ErrorKind::TimedOut);
        drop(peer);
        writer.join().unwrap();
    }
    #[test]
    fn operator_never_sends_a_second_execution_on_one_connection() {
        let (mut peer, _client) = pair(Duration::from_secs(2));
        peer.send(&json!({"kind":"canonical-exec","request_id":1}))
            .unwrap();
        assert!(
            peer.send(&json!({"kind":"canonical-exec","request_id":2}))
                .is_err()
        );
        assert!(
            peer.send(&json!({"kind":"result-resume","request_id":1}))
                .is_err()
        );
    }

    #[test]
    fn resume_intent_is_explicit_and_cannot_be_duplicated_or_misplaced() {
        let plain: Vec<String> = ["127.0.0.1:0", "worker", "request.json", "/delivery"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        assert_eq!(
            operation_arguments(&plain, 4),
            Some((plain.as_slice(), DeliveryMode::Execute, None))
        );
        let mut leading = vec!["--resume".to_owned()];
        leading.extend(plain.clone());
        assert_eq!(
            operation_arguments(&leading, 4),
            Some((&leading[1..], DeliveryMode::Resume, None))
        );
        let mut trailing = plain.clone();
        trailing.push("--resume".to_owned());
        assert_eq!(
            operation_arguments(&trailing, 4),
            Some((&trailing[..4], DeliveryMode::Resume, None))
        );
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
        assert!(
            peer.send(&json!({"kind":"canonical-exec", "request_id":7}))
                .is_err()
        );
        peer.send(&json!({"kind":"result-resume", "request_id":7}))
            .unwrap();
        let until = peer.until;
        assert!(until > Instant::now() + Duration::from_secs(60));
        peer.send(&json!({"kind":"output-read", "request_id":7}))
            .unwrap();
        assert_eq!(peer.until, until);
        assert!(
            peer.send(&json!({"kind":"result-resume", "request_id":7}))
                .is_err()
        );
        assert!(
            peer.send(&json!({"kind":"canonical-exec", "request_id":7}))
                .is_err()
        );
        assert_eq!(peer.until, until);
    }

    #[test]
    fn resume_failures_before_connect_preserve_original_execution_uncertainty() {
        let root = tempfile::tempdir().unwrap();
        let missing = root
            .path()
            .join("missing-request.json")
            .to_string_lossy()
            .into_owned();
        let destination = root.path().join("delivery").to_string_lossy().into_owned();
        let plain = vec![
            "127.0.0.1:0".to_owned(),
            "worker".to_owned(),
            missing.clone(),
            destination.clone(),
        ];
        let tls = vec![
            "127.0.0.1:0".to_owned(),
            "worker".to_owned(),
            "01".repeat(32),
            missing,
            destination,
        ];
        for mode in [DeliveryMode::Execute, DeliveryMode::Resume] {
            assert_eq!(
                run_once(&plain, mode, None, None)
                    .unwrap_err()
                    .execution_may_have_run,
                mode == DeliveryMode::Resume
            );
            assert_eq!(
                run_tls_once(&tls, mode, None, None)
                    .unwrap_err()
                    .execution_may_have_run,
                mode == DeliveryMode::Resume
            );
            let mut invalid_pin = tls.clone();
            invalid_pin[2] = "invalid".to_owned();
            assert_eq!(
                run_tls_once(&invalid_pin, mode, None, None)
                    .unwrap_err()
                    .execution_may_have_run,
                mode == DeliveryMode::Resume
            );
        }
        assert!(!root.path().join("delivery").exists());
    }

    #[cfg(unix)]
    fn source_request(root: &Path) -> Value {
        use rabs_sandbox::snapshot_capture::capture_sealed_source;
        std::fs::write(root.join("lib.rs"), b"pub fn value() -> u32 { 42 }\n").unwrap();
        std::fs::write(root.join("private.key"), b"never selected").unwrap();
        let image = capture_sealed_source(
            &[("workspace".into(), root.to_path_buf())],
            false,
            2,
            200_000,
        )
        .unwrap();
        let upload = SourceUpload::from_snapshot(
            std::sync::Arc::new(image),
            "workspace",
            &["lib.rs".into()],
        )
        .unwrap();
        json!({"kind":"canonical-exec", "request_id":7, "program":"rustc",
            "args":["lib.rs"], "toolchain_backing":"/tc", "source_manifest":upload.wire_manifest()})
    }

    #[cfg(unix)]
    #[test]
    fn source_root_is_explicit_execution_only_and_preserves_resume_parsing() {
        for count in [4, 5] {
            let plain: Vec<_> = (0..count).map(|index| format!("arg-{index}")).collect();
            assert_eq!(
                execution_arguments(&plain, count),
                Some((plain.as_slice(), DeliveryMode::Execute, None, None))
            );
            let mut leading = vec!["--source-root".to_owned(), "/source".to_owned()];
            leading.extend(plain.clone());
            assert_eq!(
                execution_arguments(&leading, count),
                Some((
                    &leading[2..],
                    DeliveryMode::Execute,
                    Some(Path::new("/source")),
                    None
                ))
            );
            let mut trailing = plain.clone();
            trailing.extend(["--source-root".to_owned(), "/source".to_owned()]);
            assert_eq!(
                execution_arguments(&trailing, count),
                Some((
                    &trailing[..count],
                    DeliveryMode::Execute,
                    Some(Path::new("/source")),
                    None
                ))
            );
            let mut resume = plain.clone();
            resume.push("--resume".to_owned());
            assert_eq!(
                execution_arguments(&resume, count),
                Some((&resume[..count], DeliveryMode::Resume, None, None))
            );
            for invalid in [
                [leading.clone(), vec!["--resume".to_owned()]].concat(),
                [vec!["--resume".to_owned()], trailing.clone()].concat(),
                [
                    leading.clone(),
                    vec!["--source-root".to_owned(), "/other".to_owned()],
                ]
                .concat(),
                [plain.clone(), vec!["--source-root".to_owned()]].concat(),
                [
                    vec!["--source-root".to_owned(), "relative".to_owned()],
                    plain.clone(),
                ]
                .concat(),
            ] {
                assert!(
                    execution_arguments(&invalid, count).is_none(),
                    "{invalid:?}"
                );
            }
            let mut misplaced = plain;
            misplaced.splice(1..1, ["--source-root".to_owned(), "/source".to_owned()]);
            assert!(execution_arguments(&misplaced, count).is_none());
        }
    }

    #[cfg(unix)]
    #[test]
    fn captured_source_must_match_saved_bytes_and_mode_without_rewriting_request() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let request = source_request(root.path());
        let original = serde_json::to_vec(&request).unwrap();
        let captured = capture_source(&request, DeliveryMode::Execute, Some(root.path()))
            .unwrap()
            .unwrap();
        assert_eq!(captured.wire_manifest(), request["source_manifest"]);
        assert_eq!(
            captured.wire_manifest()["files"].as_array().unwrap().len(),
            1
        );
        assert!(capture_source(&request, DeliveryMode::Execute, None).is_err());
        assert!(capture_source(&request, DeliveryMode::Resume, Some(root.path())).is_err());
        std::fs::set_permissions(
            root.path().join("lib.rs"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        assert!(capture_source(&request, DeliveryMode::Execute, Some(root.path())).is_err());
        std::fs::set_permissions(
            root.path().join("lib.rs"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        std::fs::write(root.path().join("lib.rs"), b"different content").unwrap();
        assert!(capture_source(&request, DeliveryMode::Execute, Some(root.path())).is_err());
        assert_eq!(
            captured.wire_manifest(),
            request["source_manifest"],
            "captured bytes remain immutable"
        );
        assert_eq!(serde_json::to_vec(&request).unwrap(), original);
        drop(root);
        assert!(
            capture_source(&request, DeliveryMode::Resume, None)
                .unwrap()
                .is_none()
        );
        let mut backing = request;
        backing.as_object_mut().unwrap().remove("source_manifest");
        backing["workspace_backing"] = json!("/worker/workspace");
        assert!(
            capture_source(&backing, DeliveryMode::Execute, None)
                .unwrap()
                .is_none()
        );
        assert!(
            capture_source(&backing, DeliveryMode::Execute, Some(Path::new("/unused"))).is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn source_preflight_refuses_before_listening_or_reading_tls_credentials() {
        let source = tempfile::tempdir().unwrap();
        let request = source_request(source.path());
        let parent = tempfile::tempdir().unwrap();
        let request_path = parent.path().join("request.json");
        std::fs::write(&request_path, serde_json::to_vec(&request).unwrap()).unwrap();
        std::fs::write(
            source.path().join("lib.rs"),
            b"does not match saved request",
        )
        .unwrap();
        // An accidental listen would fail for a different reason. Neither lane
        // may reach it before source intent and the captured image are checked.
        let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
        let destination = parent.path().join("delivery");
        let plain = vec![
            occupied.local_addr().unwrap().to_string(),
            "worker".into(),
            request_path.to_string_lossy().into_owned(),
            destination.to_string_lossy().into_owned(),
        ];
        let mut tls = plain.clone();
        tls.insert(2, "01".repeat(32));
        for root in [None, Some(Path::new("relative")), Some(source.path())] {
            let expected = capture_source(&request, DeliveryMode::Execute, root)
                .unwrap_err()
                .to_string();
            let loopback = run_once(&plain, DeliveryMode::Execute, root, None).unwrap_err();
            let secure = run_tls_once(&tls, DeliveryMode::Execute, root, None).unwrap_err();
            assert_eq!(loopback.detail, expected);
            assert_eq!(secure.detail, expected);
            assert!(!loopback.execution_may_have_run);
            assert!(!secure.execution_may_have_run);
            assert!(!destination.exists());
        }
    }

    #[test]
    fn loopback_source_upload_has_one_budget_and_cannot_reenter_after_dispatch() {
        let (mut peer, _client) = pair(Duration::from_secs(2));
        assert!(peer.send(&json!({"kind":"source-chunk"})).is_err());
        peer.send(&json!({"kind":"source-begin"})).unwrap();
        let until = peer.until;
        for kind in ["source-chunk", "source-chunk", "source-seal"] {
            peer.send(&json!({"kind":kind})).unwrap();
            assert_eq!(peer.until, until);
        }
        assert!(peer.send(&json!({"kind":"source-begin"})).is_err());
        peer.send(&json!({"kind":"canonical-exec", "request_id":7}))
            .unwrap();
        for kind in ["source-begin", "source-chunk", "source-seal"] {
            assert!(peer.send(&json!({"kind":kind})).is_err());
        }
        let (mut expired, _client) = pair(Duration::from_secs(2));
        expired.send(&json!({"kind":"source-begin"})).unwrap();
        expired.until = Instant::now() - Duration::from_secs(1);
        for kind in ["source-chunk", "source-seal", "canonical-exec"] {
            assert_eq!(
                expired.send(&json!({"kind":kind})).unwrap_err().kind(),
                io::ErrorKind::TimedOut
            );
        }
        assert!(!expired.operation_started);
        let (mut resume, _client) = pair_with_mode(Duration::from_secs(2), DeliveryMode::Resume);
        for kind in ["source-begin", "source-chunk", "source-seal"] {
            assert!(resume.send(&json!({"kind":kind})).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn completed_source_delivery_recovers_offline_without_recapture_or_reexecution() {
        use sha2::{Digest, Sha256};
        use std::collections::VecDeque;
        struct Responses(VecDeque<Value>);
        impl WorkerPeer for Responses {
            fn send(&mut self, _frame: &Value) -> io::Result<()> {
                Ok(())
            }
            fn receive(&mut self) -> io::Result<Value> {
                self.0
                    .pop_front()
                    .ok_or_else(|| invalid("missing scripted response"))
            }
        }
        let source = tempfile::tempdir().unwrap();
        let request = source_request(source.path());
        let upload = capture_source(&request, DeliveryMode::Execute, Some(source.path()))
            .unwrap()
            .unwrap();
        let digest = &request["source_manifest"]["manifest_sha256"];
        let empty: String = Sha256::digest([])
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let chunk = |stream: &str| {
            json!({"kind":"output-chunk", "request_id":7,
            "stream":stream, "offset":0, "next_offset":0, "total_bytes":0,
            "sha256":empty, "chunk_sha256":empty, "eof":true, "data_hex":""})
        };
        let mut peer = Responses(VecDeque::from([
            json!({"kind":"worker-hello", "worker_id":"worker", "canonical":true, "slots":1,
                "boot_generation":1, "incarnation":"00000000000000000000000000000001", "request_high_water":null,
                "source_transfers":["source-files-v1"], "output_transfers":["ranges-v1"], "recovery_protocols":["request-journal-v1"]}),
            json!({"kind":"source-ready", "request_id":7, "manifest_sha256":digest, "sealed":false}),
            json!({"kind":"source-chunk-accepted", "request_id":7, "manifest_sha256":digest,
                "path":"lib.rs", "next_offset":request["source_manifest"]["files"][0]["bytes"]}),
            json!({"kind":"source-ready", "request_id":7, "manifest_sha256":digest, "sealed":true}),
            json!({"kind":"exec-result", "request_id":7, "executed":true, "exit_code":0,
                "residual_group_members":0, "stop_reason":null, "output_transfer":"ranges-v1", "output_ack_required":true,
                "stdout_bytes":0, "stdout_sha256":empty, "stderr_bytes":0, "stderr_sha256":empty,
                "artifact_ack_required":false, "artifact_manifest":null}),
            chunk("stdout"),
            chunk("stderr"),
            json!({"kind":"output-acknowledged", "request_id":7, "already_released":false}),
        ]));
        let parent = tempfile::tempdir().unwrap();
        let destination = parent.path().join("delivery");
        receive_operation(
            &mut SourcePeer::new(&mut peer, &upload, &request).unwrap(),
            &request,
            "worker",
            &destination,
            DeliveryMode::Execute,
        )
        .unwrap();
        assert!(peer.0.is_empty());
        let source_path = source.path().to_path_buf();
        drop(upload);
        drop(source);
        let request_path = parent.path().join("request.json");
        std::fs::write(&request_path, serde_json::to_vec(&request).unwrap()).unwrap();
        let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
        let args = vec![
            occupied.local_addr().unwrap().to_string(),
            "worker".into(),
            request_path.to_string_lossy().into_owned(),
            destination.to_string_lossy().into_owned(),
        ];
        for mode in [DeliveryMode::Execute, DeliveryMode::Resume] {
            let delivery = run_once(&args, mode, None, None).unwrap();
            assert_eq!(delivery.receipt["request_id"], 7);
            assert_eq!(delivery.receipt["publication_authorized"], false);
        }
        assert!(run_once(&args, DeliveryMode::Execute, Some(&source_path), None).is_ok());
        assert!(run_once(&args, DeliveryMode::Resume, None, Some(&source_path)).is_ok(),
            "a complete local delivery no longer needs the old prefix source");
        let mut tls = args.clone();
        tls.insert(2, "01".repeat(32));
        assert!(
            run_tls_once(&tls, DeliveryMode::Resume, None, None).is_err(),
            "plaintext receipt cannot upgrade to TLS"
        );
        std::fs::write(destination.join("diagnostics/stdout"), b"corrupted").unwrap();
        assert!(
            run_once(&args, DeliveryMode::Execute, Some(&source_path), None)
                .unwrap_err()
                .execution_may_have_run
        );
    }

    #[test]
    fn acknowledgment_intent_is_explicit_exclusive_and_never_an_execution_positional() {
        for count in [4, 5] {
            let args: Vec<_> = (0..count).map(|index| format!("arg-{index}")).collect();
            let mut leading = vec!["--acknowledge".to_owned()];
            leading.extend(args.clone());
            assert_eq!(
                acknowledgment_arguments(&leading, count),
                Some(&leading[1..])
            );
            let mut trailing = args.clone();
            trailing.push("--acknowledge".into());
            assert_eq!(
                acknowledgment_arguments(&trailing, count),
                Some(&trailing[..count])
            );
            assert!(execution_arguments(&leading, count).is_none());
            assert!(execution_arguments(&trailing, count).is_none());
            assert!(acknowledgment_arguments(&args, count).is_none());
            for flag in ["--resume", "--resume-from", "--source-root", "--acknowledge"] {
                let mut wrong = leading.clone();
                wrong[2] = flag.into();
                assert!(acknowledgment_arguments(&wrong, count).is_none());
                assert!(execution_arguments(&wrong, count).is_none());
            }
            let mut misplaced = args;
            misplaced.insert(2, "--acknowledge".into());
            assert!(acknowledgment_arguments(&misplaced, count).is_none());
            assert!(execution_arguments(&misplaced, count).is_none());
        }
    }

    #[test]
    fn acknowledgment_requires_a_complete_local_delivery_before_binding() {
        let owner = tempfile::tempdir().unwrap();
        let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
        let request_path = owner.path().join("request.json");
        let request = json!({"kind":"canonical-exec", "request_id":7, "program":"rustc",
            "toolchain_backing":"/tc", "workspace_backing":"/ws"});
        std::fs::write(&request_path, serde_json::to_vec(&request).unwrap()).unwrap();
        let destination = owner.path().join("absent");
        let args = vec![
            occupied.local_addr().unwrap().to_string(),
            "worker".into(),
            request_path.to_string_lossy().into_owned(),
            destination.to_string_lossy().into_owned(),
        ];
        let failure = run_acknowledgment_once(&args).unwrap_err();
        assert!(failure.execution_may_have_run);
        assert!(failure.detail.contains("existing verified delivery"));
        let mut tls = args;
        tls.insert(2, "01".repeat(32));
        let failure = run_tls_acknowledgment_once(&tls).unwrap_err();
        assert!(failure.execution_may_have_run);
        assert!(failure.detail.contains("existing verified delivery"));
        assert!(!destination.exists());
    }

    #[test]
    fn resume_from_is_exclusive_absolute_and_always_selects_recovery() {
        for count in [4, 5, 6] {
            let plain: Vec<String> = (0..count).map(|index| format!("arg-{index}")).collect();
            let mut leading = vec!["--resume-from".to_owned(), "/old".to_owned()];
            leading.extend(plain.clone());
            assert_eq!(operation_arguments(&leading, count),
                Some((&leading[2..], DeliveryMode::Resume, Some(Path::new("/old")))));
            assert_eq!(execution_arguments(&leading, count),
                Some((&leading[2..], DeliveryMode::Resume, None, Some(Path::new("/old")))));
            let mut trailing = plain.clone();
            trailing.extend(["--resume-from".to_owned(), "/old".to_owned()]);
            assert_eq!(operation_arguments(&trailing, count),
                Some((&trailing[..count], DeliveryMode::Resume, Some(Path::new("/old")))));
            for bad in [
                [leading.clone(), vec!["--resume".into()]].concat(),
                [leading.clone(), vec!["--acknowledge".into()]].concat(),
                [leading.clone(), vec!["--source-root".into(), "/source".into()]].concat(),
                [leading.clone(), vec!["--resume-from".into(), "/other".into()]].concat(),
                [vec!["--resume-from".into(), "relative".into()], plain.clone()].concat(),
                [vec!["--resume-from".into()], plain.clone()].concat(),
            ] {
                assert!(execution_arguments(&bad, count).is_none(), "{bad:?}");
                assert!(acknowledgment_arguments(&bad, count).is_none());
            }
            let mut middle = plain;
            middle.splice(1..1, ["--resume-from".into(), "/old".into()]);
            assert!(operation_arguments(&middle, count).is_none());
        }
    }

    #[cfg(unix)]
    #[test]
    fn local_prefix_preflight_precedes_listening_and_tls_credentials() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let old = root.join("old");
        std::fs::create_dir(&old).unwrap();
        let alias = root.join("alias");
        std::os::unix::fs::symlink(&old, &alias).unwrap();
        let path = root.join("request.json");
        std::fs::write(&path, json!({"kind":"canonical-exec", "request_id":7,
            "program":"rustc", "toolchain_backing":"/tc", "workspace_backing":"/ws"}).to_string()).unwrap();
        let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
        for source in [root.join("missing"), alias, old.clone()] {
            let destination = if source == old { old.join("nested") } else { root.join("new") };
            let expected = prepare_resume_source(DeliveryMode::Resume, Some(&source), &destination)
                .unwrap_err().to_string();
            let plain = vec![occupied.local_addr().unwrap().to_string(), "worker".into(),
                path.to_string_lossy().into_owned(), destination.to_string_lossy().into_owned()];
            let mut tls = plain.clone();
            tls.insert(2, "01".repeat(32));
            for failure in [
                run_once(&plain, DeliveryMode::Resume, None, Some(&source)).unwrap_err(),
                run_tls_once(&tls, DeliveryMode::Resume, None, Some(&source)).unwrap_err(),
            ] {
                assert_eq!(failure.detail, expected);
                assert!(failure.execution_may_have_run);
            }
            assert!(!destination.exists());
        }
        assert!(prepare_resume_source(DeliveryMode::Execute, Some(&old), &root.join("new")).is_err());
    }
}
