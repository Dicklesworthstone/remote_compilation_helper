//! One-shot authenticated worker delivery over the existing native TLS/ATP lane.
//!
//! This composes the real session-admission policy with the SAME files-v1 and
//! ranges-v1 receiver used by the loopback operator. An operator-provided SPKI
//! expectation is checked against TLS evidence, never learned from a hello.
//! One exact operation may be sent, once, after admission. Explicit result
//! recovery retrieves sealed bytes; it cannot dispatch or retry execution.
//! Pinned identities and worker boot/incarnation fences persist across operator
//! processes. This is not a fleet scheduler, cache publication, key-rotation
//! service, or automatic reconnect loop.
//!
//! The synchronous entry point runs on a dedicated operator thread. It drives
//! native async I/O with a current-thread Runtime and performs filesystem work
//! outside that reactor. Do not call it from a running async task.

use super::delivery_ack::PendingAcknowledgment;
use super::source_delivery::SourceUpload;
use super::worker_delivery::{
    Delivery, DeliveryFailure, DeliveryMode, ResumePeer, ResumeSource,
    WorkerAuthentication, WorkerPeer, receive_operation, validate_request,
};
use asupersync::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use asupersync::runtime::Runtime;
use rabs_asupersync::worker_transport::{AuthenticatedPeer, MAX_JSON_RECORD};
use rabs_protocol::capability_tokens::{CapabilityKind, mint};
use rabs_protocol::envelope::DEFAULT_LIMITS;
use rabs_protocol::identity_store::{IdentityStore, TransportIdentity, TrustScope};
use rabs_protocol::version_negotiation::{VersionHello, VersionRange};
use rabs_protocol::worker_session::{CoordinatorSession, SessionPolicy, WorkerHelloClaims};
use serde_json::{Value, json};
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

mod admission;
mod interrupt;
pub use admission::PinnedWorkerAdmission;
use admission::AdmittedWorkerSession;

const ADMISSION_BUDGET: Duration = Duration::from_secs(10);
const TRANSFER_BUDGET: Duration = Duration::from_secs(5 * 60);
const ACK_BUDGET: Duration = Duration::from_secs(10);
const MAX_EXECUTION_MS: u64 = 30 * 60 * 1000;
const RECORD_READ_BYTES: usize = 4096;

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn require(condition: bool, message: &str) -> io::Result<()> {
    if condition {
        Ok(())
    } else {
        Err(invalid(message))
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Explicit public-key pin, not a worker label or a certificate serial number.
/// The all-zero sentinel and noncanonical encodings are rejected before listen.
pub fn parse_worker_pin(value: &str) -> io::Result<[u8; 32]> {
    require(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "expected 64 lowercase hex digits for worker SPKI SHA-256",
    )?;
    let mut pin = [0; 32];
    for (slot, pair) in pin.iter_mut().zip(value.as_bytes().as_chunks::<2>().0) {
        let digit = |byte: u8| {
            if byte <= b'9' {
                byte - b'0'
            } else {
                byte - b'a' + 10
            }
        };
        *slot = digit(pair[0]) * 16 + digit(pair[1]);
    }
    require(pin != [0; 32], "zero worker SPKI pin")?;
    Ok(pin)
}

fn versions(hello: &Value) -> io::Result<VersionHello> {
    let range = |field: &str| -> io::Result<VersionRange> {
        let read = |key: &str| -> io::Result<u32> {
            hello
                .get(field)
                .and_then(|value| value.get(key))
                .and_then(Value::as_u64)
                .and_then(|value| u32::try_from(value).ok())
                .filter(|value| *value > 0)
                .ok_or_else(|| invalid(format!("invalid {field}.{key}")))
        };
        let minimum_compatible = read("minimum_compatible")?;
        let current = read("current")?;
        require(minimum_compatible <= current, "inverted version range")?;
        Ok(VersionRange {
            minimum_compatible,
            current,
        })
    };
    Ok(VersionHello {
        transport: range("transport")?,
        application: range("application")?,
    })
}

fn challenge_ids() -> io::Result<[u64; 3]> {
    let mut bytes = [0; 24];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    let mut ids = [0; 3];
    for (id, chunk) in ids.iter_mut().zip(bytes.as_chunks::<8>().0) {
        // `as_chunks::<8>` proves the width without a fallible conversion.
        *id = u64::from_be_bytes(*chunk);
    }
    require(ids.iter().all(|id| *id != 0), "zero challenge identity")?;
    Ok(ids)
}

/// The adapter's identity evidence is supplied only by accept_peer. Tests inject
/// a trusted transport boundary; no deserializer can construct it from a frame.
struct AdmittedPeer<P> {
    session: Option<AdmittedWorkerSession>,
    admission: Arc<PinnedWorkerAdmission>,
    inner: P,
    identity: TransportIdentity,
    identities: IdentityStore,
    expected_operation: Value,
    mode: DeliveryMode,
    ids: [u64; 3],
    hello_read: bool,
    negotiation_started: bool,
    proof: Option<WorkerAuthentication>,
    operation_sent: bool,
    source: Option<SourceUpload>,
}

impl<P: WorkerPeer> AdmittedPeer<P> {
    fn new(
        inner: P,
        identity: TransportIdentity,
        expected: [u8; 32],
        request: &Value,
        ids: [u64; 3],
        mode: DeliveryMode,
        admission: Arc<PinnedWorkerAdmission>,
    ) -> io::Result<Self> {
        validate_request(request)?;
        let expected_operation = mode.frame(request);
        require(
            serde_json::to_vec(&expected_operation)?.len() <= MAX_JSON_RECORD,
            "operation exceeds ATP limit",
        )?;
        require(
            expected != [0; 32]
                && identity.peer_id == expected
                && identity.fingerprint == expected
                && admission.pin() == expected,
            "authenticated worker key does not match configured SPKI pin",
        )?;
        require(
            ids.iter().all(|id| *id != 0),
            "invalid session challenge identities",
        )?;
        // The persistent admission capability already checked the pinned key
        // against this worker name's history. Reconstruct its immutable role
        // binding; neither the TLS peer nor its hello can select another key.
        let mut identities = IdentityStore::default();
        identities
            .create(expected, expected, TrustScope::Worker, 1)
            .map_err(|error| invalid(format!("worker identity admission: {error:?}")))?;
        Ok(Self {
            session: None,
            admission,
            inner,
            identity,
            identities,
            expected_operation,
            mode,
            ids,
            hello_read: false,
            negotiation_started: false,
            proof: None,
            operation_sent: false,
            source: None,
        })
    }

    /// Upload permission is local intent bound to the complete saved request,
    /// not a capability that the worker can request by adding hello fields.
    fn with_source(mut self, upload: &SourceUpload) -> io::Result<Self> {
        require(
            self.mode == DeliveryMode::Execute
                && !self.hello_read
                && !self.negotiation_started
                && self.source.is_none(),
            "source upload requires a fresh execution session",
        )?;
        upload.validate_request(&self.expected_operation)?;
        self.source = Some(upload.clone());
        Ok(self)
    }
}

impl<P: WorkerPeer> WorkerPeer for AdmittedPeer<P> {
    fn negotiate(&mut self, hello: &Value, grant: &Value) -> io::Result<()> {
        require(
            self.hello_read && !self.negotiation_started,
            "session admission cannot be repeated",
        )?;
        self.negotiation_started = true; // a failed exchange never retries admission
        let peer = hex(&self.identity.peer_id);
        require(
            hello["kind"] == "worker-hello" && hello["peer_id"].as_str() == Some(peer.as_str()),
            "worker hello does not name the authenticated peer",
        )?;
        let slots = hello
            .get("slots")
            .and_then(Value::as_u64)
            .and_then(|slots| u32::try_from(slots).ok())
            .filter(|slots| *slots > 0)
            .ok_or_else(|| invalid("invalid worker slots"))?;
        require(
            grant["kind"] == "session-ok"
                && grant["output_transfer"] == "ranges-v1"
                && grant["recovery_protocol"] == "request-journal-v1",
            "invalid delivery session selection",
        )?;
        if self.mode == DeliveryMode::Resume {
            require(
                grant["result_retention"] == "durable-result-v1"
                    && hello["result_retentions"].as_array().is_some_and(|items| {
                        items.iter().any(|item| item == "durable-result-v1")
                    }),
                "resume requires negotiated durable result retention",
            )?;
        }
        // Decide source authority before sending the challenge. A source-backed
        // execution without captured bytes must not become a remote admission.
        // Resume retains the original manifest but never uploads it again.
        let mut grant = if let Some(upload) = &self.source {
            upload.grant(hello, grant)?
        } else {
            require(
                self.mode == DeliveryMode::Resume
                    || self.expected_operation.get("source_manifest").is_none(),
                "source-backed execution requires a captured source upload",
            )?;
            require(
                grant.get("source_transfer").is_none(),
                "source transfer was not authorized by this operator session",
            )?;
            grant.clone()
        };
        let [session_id, operation_id, token_id] = self.ids;
        // Retain the worker's existing S5 admission vocabulary. This is a
        // handshake token, not a steady-state execution lease. The adapter below
        // narrows ALL sends to the complete operator-selected operation. A
        // recovery session cannot use its handshake token to execute anything.
        let scope = format!("canonical-probes:{peer}");
        let token = mint(
            token_id,
            CapabilityKind::ExecuteAction,
            session_id,
            operation_id,
            &scope,
            2,
        )
        .map_err(|error| invalid(format!("session token: {error:?}")))?;
        let claims = WorkerHelloClaims {
            versions: versions(hello)?,
            claimed_peer: self.identity.peer_id,
            session_id,
            operation_id,
            token: token.clone(),
            canonical_namespace: hello.get("canonical").and_then(Value::as_bool) == Some(true),
            slots,
        };
        let ours = VersionHello {
            transport: VersionRange {
                minimum_compatible: 1,
                current: 1,
            },
            application: VersionRange {
                minimum_compatible: 1,
                current: 1,
            },
        };
        let admitted = CoordinatorSession::admit_hello(
            &self.identities,
            &self.identity,
            &claims,
            &SessionPolicy {
                ours,
                revoked_token_ids: &[],
                current_seq: 1,
                required_capability: CapabilityKind::ExecuteAction,
                require_canonical: true,
                limits: DEFAULT_LIMITS,
                max_sequence_buffer: 1,
            },
        )
        .map_err(|error| invalid(format!("worker session refused: {error:?}")))?;
        require(
            admitted.grant().scope == TrustScope::Worker,
            "identity lacks worker role",
        )?;
        self.inner.send(&json!({
            "kind":"session-challenge", "session_id":session_id, "operation_id":operation_id,
            "token_id":token_id, "capability":token.kind.tag(), "scope":scope,
            "expires_seq":token.expires_seq,
        }))?;
        let response = self.inner.receive()?;
        require(
            response["kind"] == "worker-auth"
                && response["peer_id"].as_str() == Some(peer.as_str())
                && response["session_id"].as_u64() == Some(session_id)
                && response["operation_id"].as_u64() == Some(operation_id)
                && response["token_id"].as_u64() == Some(token_id),
            "worker challenge response mismatch",
        )?;
        self.session = Some(self.admission.admit(&self.identity, hello)?);
        grant["session_id"] = json!(session_id);
        grant["transport"] = json!(admitted.grant().transport_version);
        grant["application"] = json!(admitted.grant().application_version);
        grant["publication"] = json!("disabled");
        // No arbitrary session continuation: sealed-result retrieval is the
        // separately negotiated result_retention protocol on a NEW session.
        grant["resume"] = json!("unsupported");
        self.inner.send(&grant)?;
        // Only now is the TLS-pinned identity's challenge complete. Keep source
        // frames inside this negotiation frontier: the public adapter never
        // allows arbitrary source writes, and a failed seal cannot dispatch.
        if let Some(upload) = &self.source {
            upload.transmit(&mut self.inner, &self.expected_operation)?;
        }
        self.proof = Some(WorkerAuthentication {
            spki_sha256: self.identity.fingerprint,
            session_id,
            identity_generation: admitted.grant().binding.generation,
        });
        Ok(())
    }

    fn authentication(&self) -> Option<WorkerAuthentication> {
        self.proof
    }

    fn send(&mut self, frame: &Value) -> io::Result<()> {
        require(
            self.proof.is_some(),
            "execution/delivery before authenticated admission",
        )?;
        match frame["kind"].as_str() {
            Some("canonical-exec" | "result-resume") => {
                require(
                    !self.operation_sent && frame == &self.expected_operation,
                    "only the exact selected operation may be sent, once",
                )?;
                self.operation_sent = true; // burn before any possibly partial write
            }
            Some("request-status") => {
                // Metadata-only confirmation after a lost final acceptance
                // response. Never query another admission or widen execution.
                require(self.mode == DeliveryMode::Resume && self.operation_sent
                    && frame == &json!({"kind":"request-status", "request_id":self.expected_operation["request_id"]}),
                    "status query does not own this recovery operation")?;
            }
            Some("output-read" | "artifact-read" | "output-ack" | "artifact-ack") => {
                require(
                    self.operation_sent
                        && frame["request_id"] == self.expected_operation["request_id"],
                    "delivery request does not own this operation",
                )?;
            }
            _ => {
                return Err(invalid(
                    "unsupported coordinator operation on delivery session",
                ));
            }
        }
        self.inner.send(frame)
    }

    fn receive(&mut self) -> io::Result<Value> {
        if self.proof.is_none() {
            require(!self.hello_read, "worker frame before session admission")?;
            self.hello_read = true;
            let hello = self.inner.receive()?;
            require(
                hello["kind"] == "worker-hello",
                "expected authenticated worker hello",
            )?;
            return Ok(hello);
        }
        require(self.operation_sent, "unsolicited worker result")?;
        let frame = self.inner.receive()?;
        require(
            matches!(
                frame["kind"].as_str(),
                Some(
                    "exec-result"
                        | "heartbeat"
                        | "error"
                        | "output-chunk"
                        | "artifact-chunk"
                        | "output-acknowledged"
                        | "artifact-acknowledged"
                )
            ) || (self.mode == DeliveryMode::Resume && frame["kind"] == "request-status"
                && frame["request_id"] == self.expected_operation["request_id"]),
            "worker frame forbidden on delivery session; publication is coordinator-only",
        )?;
        Ok(frame)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Admission,
    SourceUpload,
    Execution,
    Transfer,
    Acknowledgment,
}

/// Decode one record while retaining any coalesced tail on the connection.
/// Only the new bytes are scanned after each read; fragmented input cannot
/// force repeated scans of the whole prefix. The caller's timeout covers this
/// entire future, including cooperative yields and JSON decoding.
async fn read_record<S: AsyncRead + Unpin>(
    stream: &mut S,
    buffered: &mut Vec<u8>,
) -> io::Result<Value> {
    let mut scanned = 0;
    let mut reads = 0;
    let mut chunk = [0_u8; RECORD_READ_BYTES];
    loop {
        if let Some(offset) = buffered[scanned..].iter().position(|byte| *byte == b'\n') {
            let end = scanned + offset;
            require(end <= MAX_JSON_RECORD, "worker record exceeds ATP limit")?;
            let value = serde_json::from_slice(&buffered[..end])
                .map_err(|error| invalid(error.to_string()))?;
            buffered.drain(..=end);
            return Ok(value);
        }
        require(buffered.len() <= MAX_JSON_RECORD, "worker record exceeds ATP limit")?;
        scanned = buffered.len();
        // One extra byte admits the terminator at the exact record limit, not
        // an unbounded overshoot followed by a late size check.
        let capacity = chunk.len().min(MAX_JSON_RECORD + 1 - buffered.len());
        let count = stream.read(&mut chunk[..capacity]).await?;
        if count == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "worker record incomplete"));
        }
        buffered.extend_from_slice(&chunk[..count]);
        reads += 1;
        if reads == 32 {
            // An always-ready peer still yields to cancellation and timers.
            let mut yielded = false;
            std::future::poll_fn(|cx| {
                if yielded {
                    std::task::Poll::Ready(())
                } else {
                    yielded = true;
                    cx.waker().wake_by_ref();
                    std::task::Poll::Pending
                }
            }).await;
            reads = 0;
        }
    }
}

/// One operator owns this runtime and stream; block_on is never nested. Absolute
/// phase deadlines survive fragmented reads, telemetry and repeated range reads.
struct RecordPeer<'a, S> {
    runtime: &'a Runtime,
    stream: S,
    buffered: Vec<u8>,
    until: Instant,
    execution_budget: Duration,
    phase: Phase,
    failed: bool,
}

impl<'a, S> RecordPeer<'a, S> {
    fn new(runtime: &'a Runtime, stream: S, request: &Value) -> Self {
        let millis = request
            .get("timeout_ms")
            .and_then(Value::as_u64)
            .unwrap_or(MAX_EXECUTION_MS)
            .min(MAX_EXECUTION_MS);
        Self {
            runtime,
            stream,
            buffered: Vec::new(),
            until: Instant::now() + ADMISSION_BUDGET,
            execution_budget: Duration::from_millis(millis) + Duration::from_secs(60),
            phase: Phase::Admission,
            failed: false,
        }
    }

    fn remaining(&self) -> io::Result<Duration> {
        if self.failed {
            return Err(invalid("worker connection failed; no retry"));
        }
        self.until
            .checked_duration_since(Instant::now())
            .filter(|left| !left.is_zero())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::TimedOut, "worker phase deadline exceeded")
            })
    }

    fn begin_frame(&mut self, kind: Option<&str>) -> io::Result<()> {
        // Expiration is checked before a phase transition can grant new time.
        self.remaining()?;
        match kind {
            Some("source-begin") => {
                require(self.phase == Phase::Admission, "duplicate source upload")?;
                self.phase = Phase::SourceUpload;
                self.until = Instant::now() + TRANSFER_BUDGET;
            }
            Some("source-chunk" | "source-seal") => {
                require(self.phase == Phase::SourceUpload, "source frame outside upload")?;
                // Every chunk and the seal share the original upload budget.
            }
            Some("canonical-exec") => {
                require(
                    matches!(self.phase, Phase::Admission | Phase::SourceUpload),
                    "duplicate execution dispatch",
                )?;
                self.phase = Phase::Execution;
                self.until = Instant::now() + self.execution_budget;
            }
            Some("result-resume") => {
                require(self.phase == Phase::Admission, "duplicate recovery dispatch")?;
                // Restoring the spool and downloading it share one finite
                // budget. Receiving exec-result must NOT restart that budget.
                self.phase = Phase::Transfer;
                self.until = Instant::now() + TRANSFER_BUDGET;
            }
            Some("output-ack" | "artifact-ack") if self.phase == Phase::Transfer => {
                self.phase = Phase::Acknowledgment;
                self.until = Instant::now() + ACK_BUDGET;
            }
            _ => {}
        }
        Ok(())
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> WorkerPeer for RecordPeer<'_, S> {
    fn send(&mut self, frame: &Value) -> io::Result<()> {
        self.remaining()?;
        let mut bytes = serde_json::to_vec(frame)?;
        require(
            bytes.len() <= MAX_JSON_RECORD,
            "worker record exceeds ATP limit",
        )?;
        self.begin_frame(frame["kind"].as_str())?;
        bytes.push(b'\n');
        let budget = self.remaining()?;
        let stream = &mut self.stream;
        let result = self.runtime.block_on(async {
            asupersync::time::timeout(asupersync::time::wall_now(), budget, async {
                stream.write_all(&bytes).await?;
                stream.flush().await
            })
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "worker write deadline"))?
        });
        self.failed |= result.is_err();
        result
    }

    fn receive(&mut self) -> io::Result<Value> {
        let budget = self.remaining()?;
        let stream = &mut self.stream;
        let buffered = &mut self.buffered;
        let result = self.runtime.block_on(async {
            asupersync::time::timeout(
                asupersync::time::wall_now(), budget, read_record(stream, buffered),
            )
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "worker read deadline"))?
        });
        self.failed |= result.is_err();
        // JSON parsing and immediately-ready buffered reads must not let a late
        // result escape its absolute deadline and obtain a fresh transfer budget.
        if result.is_ok() && let Err(error) = self.remaining() {
            self.failed = true;
            return Err(error);
        }
        if let Ok(value) = &result
            && self.phase == Phase::Execution
            && value["kind"] == "exec-result"
        {
            self.phase = Phase::Transfer;
            self.until = Instant::now() + TRANSFER_BUDGET;
        }
        result
    }
}

/// Receive one exact new command over a stream returned by native mutual-TLS
/// admission. Recovery is never selected implicitly after an execution error.
pub fn receive_authenticated(
    runtime: &Runtime,
    peer: AuthenticatedPeer,
    admission: PinnedWorkerAdmission,
    request: &Value,
    destination: &Path,
) -> Result<Delivery, DeliveryFailure> {
    receive_authenticated_operation(
        runtime,
        peer,
        admission,
        request,
        destination,
        DeliveryMode::Execute,
        None,
    )
}

/// Perform one locally selected operation under a fresh mutually authenticated
/// session. Resume binds the COMPLETE original canonical-exec request, but only
/// sends result-resume. Pin/admission/retention failures never authorize execution
/// or plaintext fallback. In recovery mode even pre-admission errors preserve
/// uncertainty about the original run. Only the shared byte verifier can finalize
/// the new delivery directory and acknowledge remote captures.
/// Optional local prefixes are resume-only hints, not authentication or result
/// evidence. Every copied byte is hashed against the newly resumed result.
pub fn receive_authenticated_operation(
    runtime: &Runtime,
    peer: AuthenticatedPeer,
    admission: PinnedWorkerAdmission,
    request: &Value,
    destination: &Path,
    mode: DeliveryMode,
    resume_source: Option<&ResumeSource>,
) -> Result<Delivery, DeliveryFailure> {
    let failure = |error: io::Error| DeliveryFailure {
        directory: destination.to_path_buf(),
        execution_may_have_run: mode == DeliveryMode::Resume,
        detail: error.to_string(),
    };
    if asupersync::cx::Cx::current().is_some() {
        return Err(failure(invalid(
            "authenticated delivery requires an operator thread, not nested block_on",
        )));
    }
    if let Some(source) = resume_source {
        require(mode == DeliveryMode::Resume, "local output prefixes require explicit resume")
            .map_err(&failure)?;
        source.validate_destination(destination).map_err(&failure)?;
    }
    // Keep this private owner alive until the admitted peer and its transport
    // have both dropped. No caller can clone the consumed admission capability.
    let admission = Arc::new(admission);
    let expected_worker = admission.worker().to_owned();
    let raw = interrupt::OperatorPeer::new(RecordPeer::new(runtime, peer.stream, request))
        .map_err(&failure)?;
    let mut admitted = AdmittedPeer::new(
        raw,
        peer.identity,
        admission.pin(),
        request,
        challenge_ids().map_err(&failure)?,
        mode,
        Arc::clone(&admission),
    )
    .map_err(failure)?;
    match resume_source {
        Some(source) => receive_operation(
            &mut ResumePeer::new(&mut admitted, source), request, &expected_worker, destination, mode,
        ),
        None => receive_operation(&mut admitted, request, &expected_worker, destination, mode),
    }
}

/// Reconcile a previously verified local delivery through the same native TLS
/// key binding, session challenge and absolute-deadline adapter as result resume.
/// The proof carries the exact request and original trust policy. No ranges,
/// source bytes or compiler request are sent, and no local files are replaced.
pub fn acknowledge_authenticated(
    runtime: &Runtime,
    peer: AuthenticatedPeer,
    admission: PinnedWorkerAdmission,
    pending: PendingAcknowledgment,
) -> Result<Delivery, DeliveryFailure> {
    let directory = pending.directory().to_path_buf();
    let failure = |error: io::Error| DeliveryFailure {
        directory: directory.clone(), execution_may_have_run: true, detail: error.to_string(),
    };
    if asupersync::cx::Cx::current().is_some() {
        return Err(failure(invalid("authenticated acknowledgment requires an operator thread")));
    }
    let admission = Arc::new(admission);
    let raw = interrupt::OperatorPeer::new(RecordPeer::new(runtime, peer.stream, pending.request()))
        .map_err(&failure)?;
    let mut admitted = AdmittedPeer::new(
        raw, peer.identity, admission.pin(), pending.request(),
        challenge_ids().map_err(&failure)?, DeliveryMode::Resume,
        Arc::clone(&admission),
    ).map_err(failure)?;
    pending.acknowledge(&mut admitted)
}

/// Upload an explicitly approved immutable source projection after native TLS
/// admission, execute the exact request once, then verify the ordinary delivery.
/// A changed checkout cannot alter the retained snapshot or request identity.
/// This entry point never resumes, retries, publishes, or selects plaintext.
pub fn receive_authenticated_source(
    runtime: &Runtime,
    peer: AuthenticatedPeer,
    admission: PinnedWorkerAdmission,
    request: &Value,
    destination: &Path,
    upload: &SourceUpload,
) -> Result<Delivery, DeliveryFailure> {
    let failure = |error: io::Error| DeliveryFailure {
        directory: destination.to_path_buf(),
        execution_may_have_run: false,
        detail: error.to_string(),
    };
    if asupersync::cx::Cx::current().is_some() {
        return Err(failure(invalid(
            "authenticated delivery requires an operator thread, not nested block_on",
        )));
    }
    upload.validate_request(request).map_err(&failure)?;
    let admission = Arc::new(admission);
    let expected_worker = admission.worker().to_owned();
    let raw = interrupt::OperatorPeer::new(RecordPeer::new(runtime, peer.stream, request))
        .map_err(&failure)?;
    let mut admitted = AdmittedPeer::new(
        raw,
        peer.identity,
        admission.pin(),
        request,
        challenge_ids().map_err(&failure)?,
        DeliveryMode::Execute,
        Arc::clone(&admission),
    )
    .and_then(|admitted| admitted.with_source(upload))
    .map_err(failure)?;
    receive_operation(
        &mut admitted, request, &expected_worker, destination, DeliveryMode::Execute,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    #[derive(Default)]
    struct Script {
        state: Option<tempfile::TempDir>,
        replies: VecDeque<Value>,
        sent: Vec<Value>,
        fail_execution: bool,
    }
    impl WorkerPeer for Script {
        fn send(&mut self, frame: &Value) -> io::Result<()> {
            self.sent.push(frame.clone());
            if self.fail_execution
                && matches!(frame["kind"].as_str(), Some("canonical-exec" | "result-resume"))
            {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "partial operation write",
                ));
            }
            Ok(())
        }
        fn receive(&mut self) -> io::Result<Value> {
            self.replies
                .pop_front()
                .ok_or_else(|| invalid("missing scripted response"))
        }
    }
    fn request() -> Value {
        json!({"kind":"canonical-exec", "request_id":7, "program":"rustc", "args":["lib.rs"],
            "toolchain_backing":"/tc", "workspace_backing":"/ws", "artifacts":{"unit":"dep","files":["a"]}})
    }
    fn hello() -> Value {
        json!({"kind":"worker-hello", "worker_id":"worker", "peer_id":hex(&[1; 32]), "canonical":true, "slots":4,
            "boot_generation":1, "incarnation":"00000000000000000000000000000001",
            "transport":{"minimum_compatible":1,"current":1},
            "application":{"minimum_compatible":1,"current":1}})
    }
    fn response() -> Value {
        json!({"kind":"worker-auth", "session_id":10, "operation_id":20, "token_id":30, "peer_id":hex(&[1; 32])})
    }
    fn grant() -> Value {
        json!({"kind":"session-ok", "output_transfer":"ranges-v1",
            "artifact_transfer":"files-v1", "recovery_protocol":"request-journal-v1"})
    }
    fn with_admission(mut script: Script) -> (Script, Arc<PinnedWorkerAdmission>) {
        let root = script.state.take().unwrap_or_else(|| tempfile::tempdir().unwrap());
        let admission = Arc::new(PinnedWorkerAdmission::open(root.path(), "worker", [1; 32]).unwrap());
        script.state = Some(root);
        (script, admission)
    }
    fn peer_with_mode(hello: Value, response: Value, mode: DeliveryMode) -> AdmittedPeer<Script> {
        let inner = Script {
            replies: VecDeque::from([hello, response]),
            ..Script::default()
        };
        let (inner, admission) = with_admission(inner);
        AdmittedPeer::new(
            inner,
            TransportIdentity {
                peer_id: [1; 32],
                fingerprint: [1; 32],
            },
            [1; 32],
            &request(),
            [10, 20, 30],
            mode,
            admission,
        )
        .unwrap()
    }
    fn peer(hello: Value, response: Value) -> AdmittedPeer<Script> {
        peer_with_mode(hello, response, DeliveryMode::Execute)
    }

    #[test]
    fn pin_is_explicit_and_identity_must_be_transport_proven() {
        assert_eq!(parse_worker_pin(&"01".repeat(32)).unwrap(), [1; 32]);
        for value in [
            "00".repeat(32),
            "AA".repeat(32),
            "01".repeat(31),
            "xyz".to_owned(),
        ] {
            assert!(parse_worker_pin(&value).is_err());
        }
        for identity in [
            TransportIdentity {
                peer_id: [2; 32],
                fingerprint: [1; 32],
            },
            TransportIdentity {
                peer_id: [1; 32],
                fingerprint: [2; 32],
            },
        ] {
            let (inner, admission) = with_admission(Script::default());
            assert!(
                AdmittedPeer::new(
                    inner,
                    identity,
                    [1; 32],
                    &request(),
                    [10, 20, 30],
                    DeliveryMode::Execute,
                    admission,
                )
                .is_err()
            );
        }
        let mut forged = hello();
        forged["peer_id"] = json!(hex(&[2; 32]));
        forged["transport_authenticated"] = json!(true);
        let mut peer = peer(forged, response());
        let hello = peer.receive().unwrap();
        assert!(peer.negotiate(&hello, &grant()).is_err());
        assert!(peer.inner.sent.is_empty());
        assert!(peer.authentication().is_none());
        assert!(peer.send(&request()).is_err());
    }

    #[test]
    fn malformed_or_incompatible_versions_refuse_before_challenge() {
        for range in [
            json!({"minimum_compatible":2,"current":2}),
            json!({"minimum_compatible":2,"current":1}),
            json!({"minimum_compatible":1,"current":4294967296_u64}),
            json!({"minimum_compatible":0,"current":1}),
            Value::Null,
        ] {
            let mut hello = hello();
            hello["application"] = range;
            let mut peer = peer(hello, response());
            let hello = peer.receive().unwrap();
            assert!(peer.negotiate(&hello, &grant()).is_err());
            assert!(peer.inner.sent.is_empty());
        }
    }

    #[test]
    fn challenge_binds_session_operation_token_and_peer_before_any_execution() {
        for field in ["session_id", "operation_id", "token_id", "peer_id", "kind"] {
            let mut response = response();
            response[field] = json!(999);
            let mut peer = peer(hello(), response);
            let hello = peer.receive().unwrap();
            assert!(peer.negotiate(&hello, &grant()).is_err(), "{field}");
            assert_eq!(peer.inner.sent.len(), 1);
            assert_eq!(peer.inner.sent[0]["kind"], "session-challenge");
            assert!(peer.send(&request()).is_err());
            assert!(
                peer.negotiate(&hello, &grant()).is_err(),
                "no handshake retry"
            );
            assert!(peer.authentication().is_none());
        }
    }

    #[test]
    fn successful_admission_preserves_transfer_selection_and_limits_dispatch() {
        let mut peer = peer(hello(), response());
        assert!(peer.send(&request()).is_err());
        let hello = peer.receive().unwrap();
        peer.negotiate(&hello, &grant()).unwrap();
        let proof = peer.authentication().unwrap();
        assert_eq!(proof.spki_sha256, [1; 32]);
        assert_eq!(proof.session_id, 10);
        assert_eq!(proof.identity_generation, 1);
        assert_eq!(peer.inner.sent[1]["artifact_transfer"], "files-v1");
        assert_eq!(peer.inner.sent[1]["publication"], "disabled");
        assert_eq!(peer.inner.sent[1]["resume"], "unsupported");
        let mut wrong = request();
        wrong["artifacts"]["files"] = json!(["other"]);
        assert!(peer.send(&wrong).is_err());
        assert!(peer.send(&DeliveryMode::Resume.frame(&request())).is_err());
        peer.send(&request()).unwrap();
        assert!(peer.send(&request()).is_err());
        assert!(peer.send(&json!({"kind":"commit","request_id":7})).is_err());
        assert!(
            peer.send(&json!({"kind":"artifact-read","request_id":8}))
                .is_err()
        );
        assert_eq!(
            peer.inner
                .sent
                .iter()
                .filter(|frame| frame["kind"] == "canonical-exec")
                .count(),
            1
        );
        peer.inner
            .replies
            .push_back(json!({"kind":"commit","request_id":7}));
        assert!(peer.receive().is_err());
    }

    #[test]
    fn partial_execution_write_is_never_retried() {
        let mut peer = peer(hello(), response());
        let hello = peer.receive().unwrap();
        peer.negotiate(&hello, &grant()).unwrap();
        peer.inner.fail_execution = true;
        assert!(peer.send(&request()).is_err());
        peer.inner.fail_execution = false;
        assert!(peer.send(&request()).is_err());
        assert_eq!(
            peer.inner
                .sent
                .iter()
                .filter(|frame| frame["kind"] == "canonical-exec")
                .count(),
            1
        );
    }

    fn recovery_hello() -> Value {
        let mut hello = hello();
        hello["worker_id"] = json!("worker");
        hello["boot_generation"] = json!(2);
        hello["incarnation"] = json!("00000000000000000000000000000002");
        hello["request_high_water"] = json!(7);
        hello["recovery_protocols"] = json!(["request-journal-v1"]);
        hello["result_retentions"] = json!(["durable-result-v1"]);
        hello["output_transfers"] = json!(["ranges-v1"]);
        hello["artifact_transfers"] = json!(["files-v1"]);
        hello
    }

    #[test]
    fn resume_requires_retention_before_challenge_and_never_downgrades() {
        for missing_hello in [false, true] {
            let mut hello = recovery_hello();
            let mut grant = grant();
            if missing_hello {
                hello["result_retentions"] = json!([]);
                grant["result_retention"] = json!("durable-result-v1");
            }
            let mut peer = peer_with_mode(hello, response(), DeliveryMode::Resume);
            let hello = peer.receive().unwrap();
            assert!(peer.negotiate(&hello, &grant).is_err());
            assert!(peer.inner.sent.is_empty());
            assert!(peer.send(&request()).is_err());
            assert!(peer.send(&DeliveryMode::Resume.frame(&request())).is_err());
        }
    }

    #[test]
    fn resume_binds_complete_request_and_burns_dispatch_before_partial_write() {
        let mut peer = peer_with_mode(recovery_hello(), response(), DeliveryMode::Resume);
        let hello = peer.receive().unwrap();
        let mut grant = grant();
        grant["result_retention"] = json!("durable-result-v1");
        peer.negotiate(&hello, &grant).unwrap();
        assert!(peer.send(&request()).is_err());
        let dispatch = DeliveryMode::Resume.frame(&request());
        for field in ["program", "args", "artifacts", "workspace_backing", "toolchain_backing"] {
            let mut changed = dispatch.clone();
            changed["request"][field] = json!("different");
            assert!(peer.send(&changed).is_err(), "{field}");
        }
        let mut changed = dispatch.clone();
        changed["request_id"] = json!(8);
        assert!(peer.send(&changed).is_err());
        peer.inner.fail_execution = true;
        assert!(peer.send(&dispatch).is_err());
        peer.inner.fail_execution = false;
        assert!(peer.send(&dispatch).is_err());
        assert!(peer.send(&request()).is_err());
        assert_eq!(peer.inner.sent.iter().filter(|v| v["kind"] == "result-resume").count(), 1);
        assert!(!peer.inner.sent.iter().any(|v| v["kind"] == "canonical-exec"));
    }

    fn resumed_peer() -> (AdmittedPeer<Script>, Value) {
        use sha2::{Digest, Sha256};
        let hash = |bytes: &[u8]| hex(&Sha256::digest(bytes));
        let bytes = b"A\0\xffB";
        let mut request = request();
        request.as_object_mut().unwrap().remove("artifacts");
        let result = json!({"kind":"exec-result", "request_id":7, "executed":true,
            "resumed":true, "exit_code":0, "residual_group_members":0, "stop_reason":null,
            "result_retention":"durable-result-v1", "retained_result_sha256":"07".repeat(32),
            "output_transfer":"ranges-v1", "output_ack_required":true,
            "stdout_bytes":bytes.len(), "stdout_sha256":hash(bytes),
            "stderr_bytes":0, "stderr_sha256":hash(b""),
            "artifact_ack_required":false, "artifact_manifest":null});
        let chunk = |stream: &str, bytes: &[u8]| json!({"kind":"output-chunk", "request_id":7,
            "stream":stream, "offset":0, "next_offset":bytes.len(), "total_bytes":bytes.len(),
            "sha256":hash(bytes), "chunk_sha256":hash(bytes), "eof":true, "data_hex":hex(bytes)});
        let inner = Script {
            replies: VecDeque::from([
                recovery_hello(), response(), result,
                chunk("stdout", bytes), chunk("stderr", b""),
                json!({"kind":"output-acknowledged", "request_id":7, "already_released":false}),
            ]),
            ..Script::default()
        };
        let (inner, admission) = with_admission(inner);
        let peer = AdmittedPeer::new(
            inner,
            TransportIdentity { peer_id: [1; 32], fingerprint: [1; 32] },
            [1; 32], &request, [10, 20, 30], DeliveryMode::Resume, admission,
        ).unwrap();
        (peer, request)
    }

    #[test]
    fn authenticated_resume_uses_shared_byte_verifier_and_survives_ack_loss() {
        for lose_ack in [false, true] {
            let parent = tempfile::tempdir().unwrap();
            let destination = parent.path().join("recovered");
            let (mut peer, request) = resumed_peer();
            if lose_ack { peer.inner.replies.pop_back(); }
            let delivery = receive_operation(
                &mut peer, &request, "worker", &destination, DeliveryMode::Resume,
            ).unwrap();
            assert_eq!(delivery.acknowledgments_confirmed, !lose_ack);
            assert_eq!(delivery.receipt["resumed"], true);
            assert_eq!(delivery.receipt["transport_authenticated"], true);
            assert_eq!(delivery.receipt["worker_spki_sha256"], hex(&[1; 32]));
            assert_eq!(delivery.receipt["publication_authorized"], false);
            assert!(delivery.receipt["execution_boot_generation"].is_null());
            assert_eq!(std::fs::read(destination.join("diagnostics/stdout")).unwrap(), b"A\0\xffB");
            assert!(destination.join("delivery.json").is_file());
            assert!(!peer.inner.sent.iter().any(|v| v["kind"] == "canonical-exec"));
            assert_eq!(peer.inner.sent.iter().filter(|v| v["kind"] == "result-resume").count(), 1);
        }
    }

    #[test]
    fn unavailable_or_unresumed_result_never_authorizes_reexecution_or_ack() {
        for unavailable in [false, true] {
            let parent = tempfile::tempdir().unwrap();
            let destination = parent.path().join("refused");
            let (mut peer, request) = resumed_peer();
            if unavailable {
                peer.inner.replies[2] = json!({"kind":"error", "request_id":7, "error":"result unavailable"});
            } else {
                peer.inner.replies[2]["resumed"] = json!(false);
            }
            let failure = receive_operation(
                &mut peer, &request, "worker", &destination, DeliveryMode::Resume,
            ).unwrap_err();
            assert!(failure.execution_may_have_run);
            assert!(!destination.join("delivery.json").exists());
            assert_eq!(peer.inner.sent.len(), 3); // challenge, grant, retrieval only
            assert_eq!(peer.inner.sent[2]["kind"], "result-resume");
        }
    }

    #[cfg(unix)]
    fn source_fixture(
        root: &Path,
    ) -> (SourceUpload, Value, Script, Vec<u8>) {
        use rabs_sandbox::snapshot_capture::capture_sealed_source;
        use rabs_sandbox::source_transfer::MAX_SOURCE_CHUNK;
        use std::sync::Arc;

        let bytes: Vec<u8> = (0..MAX_SOURCE_CHUNK + 17).map(|i| (i % 251) as u8).collect();
        std::fs::write(root.join("lib.rs"), &bytes).unwrap();
        std::fs::write(root.join("private.key"), b"not approved for upload").unwrap();
        let image = capture_sealed_source(
            &[("workspace".into(), root.to_path_buf())], false, 2, 200_000,
        ).unwrap();
        let upload = SourceUpload::from_snapshot(
            Arc::new(image), "workspace", &["lib.rs".into()],
        ).unwrap();
        let (peer, mut request) = resumed_peer();
        request.as_object_mut().unwrap().remove("workspace_backing");
        request["source_manifest"] = upload.wire_manifest();
        let manifest = &request["source_manifest"]["manifest_sha256"];
        let mut script = peer.inner;
        script.replies[0]["request_high_water"] = Value::Null;
        script.replies[0]["source_transfers"] = json!(["source-files-v1"]);
        script.replies[2].as_object_mut().unwrap().remove("resumed");
        script.replies.insert(2, json!({"kind":"source-ready", "request_id":7,
            "manifest_sha256":manifest, "sealed":false}));
        for (index, next) in [MAX_SOURCE_CHUNK, bytes.len()].into_iter().enumerate() {
            script.replies.insert(3 + index, json!({"kind":"source-chunk-accepted",
                "request_id":7, "manifest_sha256":manifest, "path":"lib.rs", "next_offset":next}));
        }
        script.replies.insert(5, json!({"kind":"source-ready", "request_id":7,
            "manifest_sha256":manifest, "sealed":true}));
        (upload, request, script, bytes)
    }

    #[cfg(unix)]
    fn source_admission(script: Script, request: &Value) -> AdmittedPeer<Script> {
        let (script, admission) = with_admission(script);
        AdmittedPeer::new(
            script,
            TransportIdentity { peer_id: [1; 32], fingerprint: [1; 32] },
            [1; 32], request, [10, 20, 30], DeliveryMode::Execute, admission,
        ).unwrap()
    }

    #[cfg(unix)]
    #[test]
    fn authenticated_source_upload_precedes_execution_and_verified_delivery() {
        use rabs_sandbox::source_transfer::MAX_SOURCE_CHUNK;
        use sha2::{Digest, Sha256};

        let source = tempfile::tempdir().unwrap();
        let (upload, request, script, bytes) = source_fixture(source.path());
        std::fs::write(source.path().join("lib.rs"), b"changed after capture").unwrap();
        let parent = tempfile::tempdir().unwrap();
        let destination = parent.path().join("delivery");
        let mut peer = source_admission(script, &request).with_source(&upload).unwrap();
        let delivery = receive_operation(
            &mut peer, &request, "worker", &destination, DeliveryMode::Execute,
        ).unwrap();
        assert!(delivery.acknowledgments_confirmed);
        assert!(peer.inner.replies.is_empty());
        let sent = &peer.inner.sent;
        assert_eq!(sent[0]["kind"], "session-challenge");
        assert_eq!(sent[1]["kind"], "session-ok");
        assert_eq!(sent[1]["source_transfer"], "source-files-v1");
        assert_eq!(sent[1]["publication"], "disabled");
        assert_eq!(sent[2]["kind"], "source-begin");
        for (index, chunk) in bytes.chunks(MAX_SOURCE_CHUNK).enumerate() {
            assert_eq!(sent[3 + index]["kind"], "source-chunk");
            assert_eq!(sent[3 + index]["path"], "lib.rs");
            assert_eq!(sent[3 + index]["data_hex"], hex(chunk));
            assert_eq!(sent[3 + index]["chunk_sha256"], hex(&Sha256::digest(chunk)));
        }
        assert_eq!(sent[5]["kind"], "source-seal");
        assert_eq!(sent[6], request);
        assert_eq!(delivery.receipt["transport_authenticated"], true);
        assert_eq!(delivery.receipt["worker_spki_sha256"], hex(&[1; 32]));
        assert_eq!(delivery.receipt["publication_authorized"], false);
        assert_eq!(std::fs::read(destination.join("diagnostics/stdout")).unwrap(), b"A\0\xffB");
        assert!(peer.send(&request).is_err());
        assert!(peer.send(&json!({"kind":"source-begin", "request_id":7})).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn source_bytes_never_cross_failed_identity_capability_or_challenge_admission() {
        let source = tempfile::tempdir().unwrap();
        for case in 0..4 {
            let (upload, request, mut script, _) = source_fixture(source.path());
            match case {
                0 => script.replies[0]["peer_id"] = json!(hex(&[2; 32])),
                1 => script.replies[0]["source_transfers"] = json!([]),
                2 => script.replies[1]["token_id"] = json!(999),
                _ => script.replies[0]["application"] = json!({"minimum_compatible":2,"current":2}),
            }
            let mut peer = source_admission(script, &request).with_source(&upload).unwrap();
            let hello = peer.receive().unwrap();
            assert!(peer.negotiate(&hello, &grant()).is_err(), "case {case}");
            assert!(peer.authentication().is_none());
            assert!(peer.send(&request).is_err());
            assert!(peer.inner.sent.iter().all(|frame| frame["kind"] == "session-challenge"));
            assert!(peer.negotiate(&hello, &grant()).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn durable_refusal_prevents_grant_source_upload_and_execution() {
        let source = tempfile::tempdir().unwrap();
        let (upload, request, script, _) = source_fixture(source.path());
        let mut peer = source_admission(script, &request).with_source(&upload).unwrap();
        let mut newer = recovery_hello();
        newer["boot_generation"] = json!(4);
        newer["incarnation"] = json!("00000000000000000000000000000004");
        drop(peer.admission.admit(&peer.identity, &newer).unwrap());
        let offered = peer.receive().unwrap();
        let error = peer.negotiate(&offered, &grant()).unwrap_err();
        assert!(error.to_string().contains("RejectStaleBootGeneration"));
        assert!(peer.authentication().is_none());
        assert!(peer.send(&request).is_err());
        assert_eq!(peer.inner.sent.len(), 1);
        assert_eq!(peer.inner.sent[0]["kind"], "session-challenge");
    }

    #[cfg(unix)]
    #[test]
    fn corrupted_or_lost_source_acceptance_cannot_dispatch_or_retry() {
        let source = tempfile::tempdir().unwrap();
        for case in 0..7 {
            let (upload, request, mut script, _) = source_fixture(source.path());
            match case {
                0 => script.replies[2]["sealed"] = json!(true),
                1 => script.replies[2]["request_id"] = json!(8),
                2 => script.replies[3]["next_offset"] = json!(0),
                3 => script.replies[4]["path"] = json!("private.key"),
                4 => script.replies[5]["manifest_sha256"] = json!("00".repeat(32)),
                5 => script.replies[5]["sealed"] = json!(false),
                _ => script.replies.truncate(5),
            }
            let parent = tempfile::tempdir().unwrap();
            let destination = parent.path().join("delivery");
            let mut peer = source_admission(script, &request).with_source(&upload).unwrap();
            let failure = receive_operation(
                &mut peer, &request, "worker", &destination, DeliveryMode::Execute,
            ).unwrap_err();
            assert!(!failure.execution_may_have_run, "case {case}: {failure}");
            assert!(peer.authentication().is_none());
            assert!(!peer.inner.sent.iter().any(|frame| {
                matches!(frame["kind"].as_str(), Some("canonical-exec" | "output-ack" | "artifact-ack"))
            }));
            assert!(!destination.join("delivery.json").exists());
            assert!(peer.send(&request).is_err());
            assert!(peer.negotiate(&recovery_hello(), &grant()).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn source_upload_is_explicit_and_never_attached_to_recovery() {
        let source = tempfile::tempdir().unwrap();
        let (upload, request, script, _) = source_fixture(source.path());
        let mut peer = source_admission(script, &request);
        let hello = peer.receive().unwrap();
        assert!(peer.negotiate(&hello, &grant()).is_err());
        assert!(peer.inner.sent.is_empty());
        assert!(peer.send(&request).is_err());
        assert!(peer.with_source(&upload).is_err(), "no late upload authorization");
        let (resumed, _) = resumed_peer();
        assert!(resumed.with_source(&upload).is_err());
        assert!(source_admission(Script::default(), &self::request())
            .with_source(&upload).is_err(), "upload cannot replace the selected workspace");
    }

    #[test]
    fn upload_chunks_and_seal_share_one_absolute_deadline() {
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread().build().unwrap();
        let mut peer = RecordPeer::new(&runtime, (), &request());
        assert!(peer.begin_frame(Some("source-chunk")).is_err());
        peer.begin_frame(Some("source-begin")).unwrap();
        let until = peer.until;
        for kind in ["source-chunk", "source-chunk", "source-seal"] {
            peer.begin_frame(Some(kind)).unwrap();
            assert_eq!(peer.until, until, "{kind} must not renew the upload budget");
        }
        assert!(peer.begin_frame(Some("source-begin")).is_err());
        assert!(peer.begin_frame(Some("result-resume")).is_err());
        peer.begin_frame(Some("canonical-exec")).unwrap();
        assert!(peer.phase == Phase::Execution);
        assert!(peer.begin_frame(Some("source-chunk")).is_err());
        assert!(peer.begin_frame(Some("canonical-exec")).is_err());
    }

    #[test]
    fn expired_or_failed_upload_cannot_refresh_itself_into_execution() {
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread().build().unwrap();
        for failed in [false, true] {
            let mut peer = RecordPeer::new(&runtime, (), &request());
            peer.begin_frame(Some("source-begin")).unwrap();
            if failed {
                peer.failed = true;
            } else {
                peer.until = Instant::now() - Duration::from_secs(1);
            }
            let until = peer.until;
            for kind in ["source-begin", "source-chunk", "source-seal", "canonical-exec", "result-resume"] {
                assert!(peer.begin_frame(Some(kind)).is_err(), "{kind}");
                assert!(peer.phase == Phase::SourceUpload);
                assert_eq!(peer.until, until);
            }
        }
    }

    struct RecordWire {
        input: VecDeque<u8>,
        fragment: usize,
        reads: usize,
        written: Vec<u8>,
    }

    impl RecordWire {
        fn new(input: Vec<u8>, fragment: usize) -> Self {
            assert!(fragment > 0);
            Self { input: input.into(), fragment, reads: 0, written: Vec::new() }
        }
    }

    impl AsyncRead for RecordWire {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buffer: &mut asupersync::io::ReadBuf<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            let this = self.get_mut();
            this.reads += 1;
            let count = buffer.remaining().min(this.fragment).min(this.input.len());
            let bytes: Vec<_> = this.input.drain(..count).collect();
            buffer.put_slice(&bytes);
            std::task::Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for RecordWire {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            bytes: &[u8],
        ) -> std::task::Poll<io::Result<usize>> {
            self.get_mut().written.extend_from_slice(bytes);
            std::task::Poll::Ready(Ok(bytes.len()))
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn large_native_records_use_bounded_chunk_reads_not_one_poll_per_byte() {
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread().build().unwrap();
        let value = json!({"kind":"output-chunk", "data_hex":"ab".repeat(65_536)});
        let bytes = format!("{value}\n").into_bytes();
        let expected_reads = bytes.len().div_ceil(RECORD_READ_BYTES);
        let mut peer = RecordPeer::new(&runtime, RecordWire::new(bytes, RECORD_READ_BYTES), &request());
        assert_eq!(peer.receive().unwrap(), value);
        assert_eq!(peer.stream.reads, expected_reads);
        assert!(peer.buffered.is_empty());
        assert!(peer.stream.written.is_empty());
    }

    #[test]
    fn native_record_buffer_preserves_coalesced_frames_and_fragmented_utf8() {
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread().build().unwrap();
        let values = [json!({"kind":"heartbeat", "label":"雪🦀\nquoted"}), json!([1, 2]), json!({"ok":true})];
        let bytes = values.iter().map(|value| format!("{value}\n")).collect::<String>().into_bytes();
        for fragment in [1, 7, RECORD_READ_BYTES] {
            let mut peer = RecordPeer::new(&runtime, RecordWire::new(bytes.clone(), fragment), &request());
            for value in &values {
                assert_eq!(peer.receive().unwrap(), *value);
            }
            assert!(peer.buffered.is_empty());
            assert!(peer.stream.input.is_empty());
            if fragment == RECORD_READ_BYTES {
                assert_eq!(peer.stream.reads, 1, "coalesced tails should not cause another stream read");
            }
        }
    }

    #[test]
    fn invalid_or_truncated_native_record_poisons_buffered_continuation() {
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread().build().unwrap();
        for (bytes, expected) in [
            (b"{bad}\n{\"kind\":\"exec-result\"}\n".to_vec(), io::ErrorKind::InvalidData),
            (b"\xff\n{}\n".to_vec(), io::ErrorKind::InvalidData),
            (b"{\"kind\":".to_vec(), io::ErrorKind::UnexpectedEof),
            (Vec::new(), io::ErrorKind::UnexpectedEof),
        ] {
            let mut peer = RecordPeer::new(&runtime, RecordWire::new(bytes, RECORD_READ_BYTES), &request());
            assert_eq!(peer.receive().unwrap_err().kind(), expected);
            assert!(peer.failed);
            let reads = peer.stream.reads;
            assert!(peer.receive().unwrap_err().to_string().contains("no retry"));
            assert_eq!(peer.stream.reads, reads);
            assert!(peer.send(&request()).is_err());
            assert!(peer.stream.written.is_empty());
        }
    }

    #[test]
    fn native_record_exact_limit_is_accepted_and_oversize_is_terminal() {
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread().build().unwrap();
        for extra in [0, 1] {
            let value = "x".repeat(MAX_JSON_RECORD - 2 + extra);
            let bytes = format!("\"{value}\"\n").into_bytes();
            let mut peer = RecordPeer::new(&runtime, RecordWire::new(bytes, RECORD_READ_BYTES), &request());
            let result = peer.receive();
            if extra == 0 {
                assert_eq!(result.unwrap(), json!(value));
                assert!(peer.buffered.is_empty());
            } else {
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
                assert!(peer.failed);
                assert!(peer.buffered.len() <= MAX_JSON_RECORD + 1);
                assert!(peer.receive().is_err());
            }
        }
    }

    #[test]
    fn buffered_execution_result_cannot_refresh_an_expired_phase() {
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread().build().unwrap();
        let bytes = b"{\"kind\":\"heartbeat\"}\n{\"kind\":\"exec-result\"}\n".to_vec();
        let mut peer = RecordPeer::new(&runtime, RecordWire::new(bytes, RECORD_READ_BYTES), &request());
        peer.begin_frame(Some("canonical-exec")).unwrap();
        assert_eq!(peer.receive().unwrap()["kind"], "heartbeat");
        assert!(!peer.buffered.is_empty());
        let reads = peer.stream.reads;
        peer.until = Instant::now() - Duration::from_secs(1);
        let expired = peer.until;
        assert_eq!(peer.receive().unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert!(peer.phase == Phase::Execution);
        assert_eq!(peer.until, expired);
        assert_eq!(peer.stream.reads, reads);
        assert!(peer.begin_frame(Some("result-resume")).is_err());
    }

    #[test]
    fn buffered_results_preserve_recovery_and_shared_ack_deadlines() {
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread().build().unwrap();
        let bytes = b"{\"kind\":\"exec-result\",\"resumed\":true}\n{\"kind\":\"output-acknowledged\"}\n".to_vec();
        let mut peer = RecordPeer::new(&runtime, RecordWire::new(bytes, RECORD_READ_BYTES), &request());
        peer.begin_frame(Some("result-resume")).unwrap();
        let transfer_until = peer.until;
        assert_eq!(peer.receive().unwrap()["kind"], "exec-result");
        assert_eq!(peer.until, transfer_until, "resume cannot renew its transfer budget");
        assert!(peer.phase == Phase::Transfer);
        peer.begin_frame(Some("output-ack")).unwrap();
        let ack_until = peer.until;
        assert_eq!(peer.receive().unwrap()["kind"], "output-acknowledged");
        peer.begin_frame(Some("artifact-ack")).unwrap();
        assert_eq!(peer.until, ack_until);
        assert!(peer.phase == Phase::Acknowledgment);
        assert_eq!(peer.stream.reads, 1);
    }

    #[cfg(unix)]
    #[test]
    fn authenticated_acknowledgment_uses_the_same_pinned_challenge_without_range_reads() {
        use super::super::delivery_recovery::DeliveryTrust;
        let parent = tempfile::tempdir().unwrap();
        let destination = parent.path().join("delivery");
        let (mut original_peer, request) = resumed_peer();
        original_peer.inner.replies.pop_back(); // Lost original acceptance reply.
        let original = receive_operation(&mut original_peer, &request, "worker", &destination, DeliveryMode::Resume).unwrap();
        assert!(!original.acknowledgments_confirmed);
        let marker = std::fs::read(destination.join("delivery.json")).unwrap();
        let pending = PendingAcknowledgment::verify(&request, "worker", &destination, DeliveryTrust::PinnedWorker([1;32])).unwrap();
        let (mut peer, _) = resumed_peer();
        peer.inner.replies.remove(4); peer.inner.replies.remove(3); // No output chunks needed.
        let delivered = pending.acknowledge(&mut peer).unwrap();
        assert!(delivered.acknowledgments_confirmed);
        assert_eq!(delivered.receipt, original.receipt);
        assert_eq!(std::fs::read(destination.join("delivery.json")).unwrap(), marker);
        assert_eq!(peer.inner.sent.iter().map(|frame| frame["kind"].as_str().unwrap()).collect::<Vec<_>>(),
            ["session-challenge", "session-ok", "result-resume", "output-ack"]);
        assert!(peer.inner.replies.is_empty());
    }

    #[test]
    fn authenticated_status_queries_are_metadata_only_and_bound_to_selected_recovery() {
        let status = json!({"kind":"request-status", "request_id":7});
        for mode in [DeliveryMode::Execute, DeliveryMode::Resume] {
            let mut peer = peer_with_mode(recovery_hello(), response(), mode);
            assert!(peer.send(&status).is_err());
            let hello = peer.receive().unwrap();
            let mut grant = grant(); grant["result_retention"] = json!("durable-result-v1");
            peer.negotiate(&hello, &grant).unwrap();
            assert!(peer.send(&status).is_err());
            peer.send(&mode.frame(&request())).unwrap();
            assert_eq!(peer.send(&status).is_ok(), mode == DeliveryMode::Resume);
            for changed in [json!({"kind":"request-status", "request_id":8}),
                json!({"kind":"request-status", "request_id":7, "execute":true})] {
                assert!(peer.send(&changed).is_err());
            }
            if mode == DeliveryMode::Resume {
                peer.inner.replies.push_back(status.clone());
                assert_eq!(peer.receive().unwrap(), status);
                peer.inner.replies.push_back(json!({"kind":"request-status", "request_id":8}));
                assert!(peer.receive().is_err());
                assert!(peer.send(&request()).is_err());
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn authenticated_prefix_reuse_preserves_pinned_provenance_and_exact_recovery() {
        use std::os::unix::fs::MetadataExt;
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let old = root.join("old");
        std::fs::create_dir_all(old.join("diagnostics")).unwrap();
        std::fs::write(old.join("diagnostics/stdout"), b"A\0\xffB").unwrap();
        // A candidate marker is never parsed as provenance or completion proof.
        std::fs::write(old.join("delivery.json"), b"untrusted marker").unwrap();
        let original = std::fs::metadata(old.join("diagnostics/stdout")).unwrap();
        let source = ResumeSource::open(&old).unwrap();
        let destination = root.join("new");
        let (mut peer, request) = resumed_peer();
        peer.inner.replies.remove(3); // Complete local stdout must avoid its range request.
        let delivery = receive_operation(&mut ResumePeer::new(&mut peer, &source),
            &request, "worker", &destination, DeliveryMode::Resume).unwrap();
        assert!(delivery.acknowledgments_confirmed);
        assert_eq!(delivery.receipt["transport_authenticated"], true);
        assert_eq!(delivery.receipt["worker_spki_sha256"], hex(&[1;32]));
        assert_eq!(delivery.receipt["authenticated_session_id"], 10);
        assert_eq!(delivery.receipt["publication_authorized"], false);
        assert!(peer.inner.replies.is_empty());
        assert_eq!(peer.inner.sent[2], DeliveryMode::Resume.frame(&request));
        assert!(peer.inner.sent.iter().all(|frame| frame["kind"] != "canonical-exec"));
        assert!(peer.inner.sent.iter().all(|frame| !(frame["kind"] == "output-read" && frame["stream"] == "stdout")));
        assert_eq!(std::fs::read(old.join("delivery.json")).unwrap(), b"untrusted marker");
        assert_ne!(original.ino(), std::fs::metadata(destination.join("diagnostics/stdout")).unwrap().ino());
    }

    #[cfg(unix)]
    #[test]
    fn local_prefixes_cannot_bypass_authenticated_admission_or_complete_hashes() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let old = root.join("old");
        std::fs::create_dir_all(old.join("diagnostics")).unwrap();
        std::fs::write(old.join("diagnostics/stdout"), b"evil").unwrap();
        let source = ResumeSource::open(&old).unwrap();
        for wrong_identity in [false, true] {
            let destination = root.join(if wrong_identity {"foreign"} else {"corrupt"});
            let (mut peer, request) = resumed_peer();
            if wrong_identity { peer.inner.replies[0]["peer_id"] = json!(hex(&[2;32])); }
            let error = receive_operation(&mut ResumePeer::new(&mut peer, &source),
                &request, "worker", &destination, DeliveryMode::Resume).unwrap_err();
            assert!(error.execution_may_have_run);
            assert!(error.detail.contains(if wrong_identity {"authenticated peer"} else {"complete file digest"}));
            assert!(peer.inner.sent.iter().all(|frame| !matches!(frame["kind"].as_str(),
                Some("canonical-exec" | "output-ack" | "artifact-ack"))));
            if wrong_identity { assert!(peer.inner.sent.is_empty()); }
            assert!(!destination.join("delivery.json").exists());
        }
        assert_eq!(std::fs::read(old.join("diagnostics/stdout")).unwrap(), b"evil");
    }
}
