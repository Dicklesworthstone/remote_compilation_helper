//! One-shot authenticated worker delivery over the existing native TLS/ATP lane.
//!
//! This composes the real session-admission policy with the SAME files-v1 and
//! ranges-v1 receiver used by the loopback operator. An operator-provided SPKI
//! expectation is checked against TLS evidence, never learned from a hello.
//! One exact request may be sent, once, after admission. This is not a fleet
//! scheduler, durable enrollment service, cache publication, or reconnect loop.
//!
//! The synchronous entry point runs on a dedicated operator thread. It drives
//! native async I/O with a current-thread Runtime and performs filesystem work
//! outside that reactor. Do not call it from a running async task.

use super::worker_delivery::{
    Delivery, DeliveryFailure, WorkerAuthentication, WorkerPeer, receive_execution,
    validate_request,
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
use std::time::{Duration, Instant};

const ADMISSION_BUDGET: Duration = Duration::from_secs(10);
const TRANSFER_BUDGET: Duration = Duration::from_secs(5 * 60);
const ACK_BUDGET: Duration = Duration::from_secs(10);
const MAX_EXECUTION_MS: u64 = 30 * 60 * 1000;

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
        // `as_chunks::<8>` yields `[u8; 8]` directly, so the width is proven by
        // the type and the previous fallible conversion cannot fail.
        *id = u64::from_be_bytes(*chunk);
    }
    require(ids.iter().all(|id| *id != 0), "zero challenge identity")?;
    Ok(ids)
}

/// The adapter's identity evidence is supplied only by accept_peer. Tests inject
/// a trusted transport boundary; no deserializer can construct it from a frame.
struct AdmittedPeer<P> {
    inner: P,
    identity: TransportIdentity,
    identities: IdentityStore,
    expected_request: Value,
    ids: [u64; 3],
    hello_read: bool,
    negotiation_started: bool,
    proof: Option<WorkerAuthentication>,
    execution_sent: bool,
}

impl<P: WorkerPeer> AdmittedPeer<P> {
    fn new(
        inner: P,
        identity: TransportIdentity,
        expected: [u8; 32],
        request: &Value,
        ids: [u64; 3],
    ) -> io::Result<Self> {
        validate_request(request)?;
        require(
            serde_json::to_vec(request)?.len() <= MAX_JSON_RECORD,
            "request exceeds ATP limit",
        )?;
        require(
            expected != [0; 32] && identity.peer_id == expected && identity.fingerprint == expected,
            "authenticated worker key does not match configured SPKI pin",
        )?;
        require(
            ids.iter().all(|id| *id != 0),
            "invalid session challenge identities",
        )?;
        // Explicit per-invocation enrollment. Do not populate this store from the
        // key the peer just presented; the operator's expectation is its root.
        let mut identities = IdentityStore::default();
        identities
            .create(expected, expected, TrustScope::Worker, 1)
            .map_err(|error| invalid(format!("worker identity admission: {error:?}")))?;
        Ok(Self {
            inner,
            identity,
            identities,
            expected_request: request.clone(),
            ids,
            hello_read: false,
            negotiation_started: false,
            proof: None,
            execution_sent: false,
        })
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
        let [session_id, operation_id, token_id] = self.ids;
        // Retain the worker's existing S5 admission vocabulary. This is a
        // handshake token, not a steady-state execution lease. The adapter below
        // narrows all execution sends to the complete operator-selected request.
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
        let mut grant = grant.clone();
        grant["session_id"] = json!(session_id);
        grant["transport"] = json!(admitted.grant().transport_version);
        grant["application"] = json!(admitted.grant().application_version);
        grant["publication"] = json!("disabled");
        grant["resume"] = json!("unsupported");
        self.inner.send(&grant)?;
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
            Some("canonical-exec") => {
                require(
                    !self.execution_sent && frame == &self.expected_request,
                    "only the exact one-shot request may execute, once",
                )?;
                self.execution_sent = true; // burn before any possibly partial write
            }
            Some("output-read" | "artifact-read" | "output-ack" | "artifact-ack") => {
                require(
                    self.execution_sent
                        && frame["request_id"] == self.expected_request["request_id"],
                    "delivery request does not own this execution",
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
        require(self.execution_sent, "unsolicited worker result")?;
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
            ),
            "worker frame forbidden on delivery session; publication is coordinator-only",
        )?;
        Ok(frame)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Admission,
    Execution,
    Transfer,
    Acknowledgment,
}

/// One operator owns this runtime and stream; block_on is never nested. Absolute
/// phase deadlines survive fragmented reads, telemetry and repeated range reads.
struct RecordPeer<'a, S> {
    runtime: &'a Runtime,
    stream: S,
    until: Instant,
    execution_budget: Duration,
    phase: Phase,
    failed: bool,
}

impl<'a, S: AsyncRead + AsyncWrite + Unpin> RecordPeer<'a, S> {
    fn new(runtime: &'a Runtime, stream: S, request: &Value) -> Self {
        let millis = request
            .get("timeout_ms")
            .and_then(Value::as_u64)
            .unwrap_or(MAX_EXECUTION_MS)
            .min(MAX_EXECUTION_MS);
        Self {
            runtime,
            stream,
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
}

impl<S: AsyncRead + AsyncWrite + Unpin> WorkerPeer for RecordPeer<'_, S> {
    fn send(&mut self, frame: &Value) -> io::Result<()> {
        self.remaining()?;
        let mut bytes = serde_json::to_vec(frame)?;
        require(
            bytes.len() <= MAX_JSON_RECORD,
            "worker record exceeds ATP limit",
        )?;
        match frame["kind"].as_str() {
            Some("canonical-exec") => {
                require(
                    self.phase == Phase::Admission,
                    "duplicate execution dispatch",
                )?;
                self.phase = Phase::Execution;
                self.until = Instant::now() + self.execution_budget;
            }
            Some("output-ack" | "artifact-ack") if self.phase == Phase::Transfer => {
                self.phase = Phase::Acknowledgment;
                self.until = Instant::now() + ACK_BUDGET;
            }
            _ => {}
        }
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
        let result = self.runtime.block_on(async {
            asupersync::time::timeout(asupersync::time::wall_now(), budget, async {
                let mut bytes = Vec::new();
                let mut byte = [0];
                loop {
                    if stream.read(&mut byte).await? == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "worker record incomplete",
                        ));
                    }
                    if byte[0] == b'\n' {
                        return serde_json::from_slice::<Value>(&bytes)
                            .map_err(|error| invalid(error.to_string()));
                    }
                    require(
                        bytes.len() < MAX_JSON_RECORD,
                        "worker record exceeds ATP limit",
                    )?;
                    bytes.push(byte[0]);
                }
            })
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "worker read deadline"))?
        });
        self.failed |= result.is_err();
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

/// Receive one exact command over a stream returned by native mutual-TLS
/// admission. Pin mismatch refuses before application I/O. Only the existing
/// verifier may finalize delivery and release remote diagnostic/artifact owners.
pub fn receive_authenticated(
    runtime: &Runtime,
    peer: AuthenticatedPeer,
    expected_spki: [u8; 32],
    expected_worker: &str,
    request: &Value,
    destination: &Path,
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
    let raw = RecordPeer::new(runtime, peer.stream, request);
    let mut admitted = AdmittedPeer::new(
        raw,
        peer.identity,
        expected_spki,
        request,
        challenge_ids().map_err(&failure)?,
    )
    .map_err(failure)?;
    receive_execution(&mut admitted, request, expected_worker, destination)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    #[derive(Default)]
    struct Script {
        replies: VecDeque<Value>,
        sent: Vec<Value>,
        fail_execution: bool,
    }
    impl WorkerPeer for Script {
        fn send(&mut self, frame: &Value) -> io::Result<()> {
            self.sent.push(frame.clone());
            if self.fail_execution && frame["kind"] == "canonical-exec" {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "partial execution write",
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
        json!({"kind":"worker-hello", "peer_id":hex(&[1; 32]), "canonical":true, "slots":4,
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
    fn peer(hello: Value, response: Value) -> AdmittedPeer<Script> {
        let inner = Script {
            replies: VecDeque::from([hello, response]),
            ..Script::default()
        };
        AdmittedPeer::new(
            inner,
            TransportIdentity {
                peer_id: [1; 32],
                fingerprint: [1; 32],
            },
            [1; 32],
            &request(),
            [10, 20, 30],
        )
        .unwrap()
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
            assert!(
                AdmittedPeer::new(
                    Script::default(),
                    identity,
                    [1; 32],
                    &request(),
                    [10, 20, 30]
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
}
