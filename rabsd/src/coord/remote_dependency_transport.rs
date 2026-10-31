//! One bounded authenticated worker connection for a live dependency action.
//!
//! Workers reconnect outward to the configured listener. A caller reserves the
//! sole slot before offering remote execution, then moves the reservation to a
//! dedicated blocking lane. TLS identity, challenge and durable boot admission
//! precede its live-coordinator callback; a refused callback sends no inputs or
//! execution request. The ordinary receiver verifies private delivery bytes.
//! Publication, Cargo output installation and fallback remain with the caller.
//! Typed transport failures temporarily exclude this worker from NEW placement;
//! they never retry an execution or resolve its durable uncertainty. A still
//! reserved attempt may reconnect once to fetch its already observed sealed
//! result, with the original transfer deadline and authenticated incarnation.

use super::secure_worker_delivery::{
    OperationCancellation, PinnedWorkerAdmission, WorkerAdmissionHook, parse_worker_pin,
    receive_authenticated_continuation, receive_authenticated_with_admission,
};
use super::source_delivery::SourceUpload;
use super::worker_delivery::{
    Delivery, DeliveryFailure, DeliveryMode, SealedResult, toolchain_transfer,
    transport_interrupted, validate_request, worker_transport_error,
};
use asupersync::runtime::RuntimeBuilder;
use rabs_asupersync::worker_transport::{TlsFiles, accept_peer};
use rabs_protocol::worker_fence::WorkerSessionOffer;
use rabs_sandbox::dependency_context::{
    CANONICAL_DEPENDENCY_CONTEXT_VERSION, CANONICAL_WORKSPACE_CONTEXT_VERSION,
    DEPENDENCY_CONTEXT_VERSION,
};
use serde_json::Value;
use std::future::{Future, poll_fn};
use std::io;
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::pin::pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::{Duration, Instant};

/// Includes both the outward reconnect and TLS handshake. The established ATP
/// receiver separately bounds authentication, transfer, execution and cleanup.
const CONNECT_BUDGET: Duration = Duration::from_secs(60);

/// A bounded placement hint, not an execution lease or a result quarantine.
/// Failed workers otherwise consume another connection budget on every turn
/// through the live pool. The next ordinary request may probe after this delay;
/// no timer, background task or second dispatch is created here.
const FIRST_CONNECTION_COOLDOWN: Duration = Duration::from_secs(5);
const MAX_CONNECTION_COOLDOWN: Duration = Duration::from_secs(60);

#[derive(Debug, Default)]
struct ConnectionCooldown {
    failed_at: Option<Instant>,
    delay: Duration,
}

impl ConnectionCooldown {
    fn remaining(&self, now: Instant) -> Option<Duration> {
        let failed_at = self.failed_at?;
        // A regressed injected clock cannot make a failed worker available.
        let elapsed = now.checked_duration_since(failed_at).unwrap_or_default();
        let remaining = self.delay.saturating_sub(elapsed);
        (!remaining.is_zero()).then_some(remaining)
    }

    fn interrupted(&mut self, now: Instant) {
        self.delay = if self.failed_at.is_some() {
            self.delay.saturating_mul(2).min(MAX_CONNECTION_COOLDOWN)
        } else {
            FIRST_CONNECTION_COOLDOWN
        };
        self.failed_at = Some(now);
    }

    fn completed(&mut self) {
        *self = Self::default();
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn absolute_without_traversal(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
}

fn failure(destination: &Path, error: io::Error) -> DeliveryFailure {
    DeliveryFailure {
        directory: destination.to_path_buf(),
        execution_may_have_run: false,
        transport_interrupted: transport_interrupted(&error),
        detail: error.to_string(),
        sealed_result: None,
    }
}

enum ReservedOperation<'a> {
    Execute {
        upload: &'a SourceUpload,
        on_admitted: WorkerAdmissionHook,
    },
    Continue(SealedResult),
}

/// Explicit worker selection, with no worker-supplied name or learned key pin.
/// Keep one instance in an `Arc` for the lifetime of the live dependency lane.
/// The durable admission store also fences separate processes using this name.
#[derive(Debug)]
pub struct RemoteDependencyTransport {
    address: SocketAddr,
    worker: String,
    pin: [u8; 32],
    state: PathBuf,
    tls: TlsFiles,
    occupied: AtomicBool,
    cooldown: Mutex<ConnectionCooldown>,
}

impl RemoteDependencyTransport {
    pub fn new(
        address: SocketAddr,
        worker: String,
        pin: [u8; 32],
        state: PathBuf,
        tls: TlsFiles,
    ) -> io::Result<Self> {
        if address.port() == 0 {
            return Err(invalid(
                "remote dependency listener requires a fixed nonzero port",
            ));
        }
        if worker.is_empty() || worker.len() > 1024 || worker.chars().any(char::is_control) {
            return Err(invalid("remote dependency worker name is empty or invalid"));
        }
        if pin == [0; 32] {
            return Err(invalid(
                "remote dependency requires an explicit worker SPKI pin",
            ));
        }
        if !absolute_without_traversal(&state) {
            return Err(invalid(
                "remote dependency state must be absolute without traversal",
            ));
        }
        if [&tls.ca, &tls.certificate, &tls.private_key]
            .iter()
            .any(|path| !absolute_without_traversal(path))
        {
            return Err(invalid(
                "coordinator TLS files must be absolute without traversal",
            ));
        }
        Ok(Self {
            address,
            worker,
            pin,
            state,
            tls,
            occupied: AtomicBool::new(false),
            cooldown: Mutex::new(ConnectionCooldown::default()),
        })
    }

    /// Use the same explicit TLS credentials as the existing secure worker
    /// operator. Absence or invalid configuration cannot select plaintext.
    pub fn from_environment(
        address: SocketAddr,
        worker: &str,
        pin: &str,
        state: &Path,
    ) -> io::Result<Self> {
        let path = |name: &str| -> io::Result<PathBuf> {
            std::env::var_os(name)
                .filter(|value| !value.is_empty())
                .map(PathBuf::from)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, format!("missing {name}"))
                })
        };
        Self::new(
            address,
            worker.to_owned(),
            parse_worker_pin(pin)?,
            state.to_path_buf(),
            TlsFiles {
                ca: path("RABS_COORD_TLS_CA")?,
                certificate: path("RABS_COORD_TLS_CERT")?,
                private_key: path("RABS_COORD_TLS_KEY")?,
            },
        )
    }

    pub fn listen_address(&self) -> SocketAddr {
        self.address
    }

    pub fn worker(&self) -> &str {
        &self.worker
    }

    /// Reserve before telling Cargo's wrapper that remote work is admitted.
    /// There is no queue or sleeping waiter. The owned guard is `Send`, so the
    /// caller can hand it from the socket handler to a bounded blocking lane.
    /// Cooling workers return WouldBlock, so the existing pool tries its next
    /// candidate before admitting this invocation. Expiry grants no authority.
    pub fn try_reserve(self: &Arc<Self>) -> io::Result<RemoteDependencyReservation> {
        self.try_reserve_at(Instant::now())
    }

    /// Connectivity expiry as observed BEFORE a worker reservation probe. The
    /// pool retains this absolute wake even if it passes before a later wait.
    /// Occupancy release is signalled separately; this grants no slot, resets
    /// no cooldown history and cannot reconcile an uncertain execution.
    pub(crate) fn cooldown_deadline_at(&self, observed: Instant) -> io::Result<Option<Instant>> {
        // This mutex protects only a small local hint, never I/O or native
        // execution. Waiting for its current writer avoids losing an expiry
        // when the queue is about to sleep without any further release event.
        let cooldown = self
            .cooldown
            .lock()
            .map_err(|_| io::Error::other("remote connectivity state poisoned"))?;
        let Some(failed_at) = cooldown.failed_at else {
            return Ok(None);
        };
        let deadline = failed_at
            .checked_add(cooldown.delay)
            .ok_or_else(|| io::Error::other("remote cooldown deadline overflow"))?;
        Ok((observed < deadline).then_some(deadline))
    }

    fn try_reserve_at(self: &Arc<Self>, now: Instant) -> io::Result<RemoteDependencyReservation> {
        self.occupied
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "remote dependency worker is busy",
                )
            })?;
        // Own release immediately: every cooldown/state refusal below must
        // release the slot without opening a ledger or allocating a request ID.
        let reservation = RemoteDependencyReservation {
            transport: Arc::clone(self),
            admission: None,
            request_id: None,
            dispatch_attempted: false,
            continuation: None,
        };
        let cooldown = self.cooldown.try_lock().map_err(|_| {
            // Contended or poisoned local hints exclude only THIS candidate,
            // never strand the slot or abort selection of a healthy peer.
            io::Error::new(
                io::ErrorKind::WouldBlock,
                "remote dependency connectivity state unavailable",
            )
        })?;
        if let Some(remaining) = cooldown.remaining(now) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                format!(
                    "remote dependency worker cooling down ({} ms remaining)",
                    remaining.as_millis(),
                ),
            ));
        }
        drop(cooldown);
        Ok(reservation)
    }

    fn observe_delivery(
        &self,
        outcome: &Result<Delivery, DeliveryFailure>,
        caller_cancelled: bool,
        now: Instant,
    ) {
        // This runs before the reservation releases occupied. It must never
        // replace a verified result or change execution_may_have_run if local
        // bookkeeping fails. Only typed socket/deadline evidence penalizes a
        // worker; compiler failures, policy refusals and local I/O do not.
        let Ok(mut cooldown) = self.cooldown.lock() else {
            return;
        };
        match outcome {
            Ok(delivery) if delivery.acknowledgments_confirmed => cooldown.completed(),
            Ok(delivery) if delivery.acknowledgment_interrupted && !caller_cancelled => {
                cooldown.interrupted(now);
            }
            Err(failure) if failure.transport_interrupted && !caller_cancelled => {
                cooldown.interrupted(now);
            }
            _ => {}
        }
    }

    /// Convenience entry for callers that have not already offered remote work.
    /// Live wrapper admission should use `try_reserve` before its offer instead.
    pub fn execute(
        self: &Arc<Self>,
        request: &Value,
        upload: &SourceUpload,
        destination: &Path,
        cancellation: OperationCancellation,
        on_admitted: impl FnOnce(&WorkerSessionOffer) -> io::Result<()> + Send + 'static,
    ) -> Result<Delivery, DeliveryFailure> {
        self.try_reserve()
            .map_err(|error| failure(destination, error))?
            .execute(request, upload, destination, cancellation, on_admitted)
    }

    fn execute_reserved(
        &self,
        admission: Option<PinnedWorkerAdmission>,
        request: &Value,
        destination: &Path,
        cancellation: OperationCancellation,
        operation: ReservedOperation<'_>,
    ) -> Result<Delivery, DeliveryFailure> {
        let continuing = matches!(&operation, ReservedOperation::Continue(_));
        let before_dispatch = |error| {
            let mut failure = failure(destination, error);
            // A connection failure on this path can never erase the original
            // dispatch. In particular, it must not permit alternate execution.
            failure.execution_may_have_run = continuing;
            failure
        };
        let mut connection_deadline = Instant::now() + CONNECT_BUDGET;
        if let ReservedOperation::Continue(sealed) = &operation {
            connection_deadline = connection_deadline.min(sealed.deadline());
        }
        if asupersync::cx::Cx::current().is_some() {
            return Err(before_dispatch(invalid(
                "remote dependency delivery requires a dedicated blocking thread",
            )));
        }
        if cancellation.is_cancelled() {
            return Err(before_dispatch(cancelled()));
        }
        match &operation {
            ReservedOperation::Execute { upload, .. } => {
                preflight(request, upload, destination).map_err(&before_dispatch)?;
            }
            ReservedOperation::Continue(sealed) => {
                sealed.verify_request(request).map_err(&before_dispatch)?;
                if !absolute_without_traversal(destination) {
                    return Err(before_dispatch(invalid(
                        "remote dependency destination must be absolute without traversal",
                    )));
                }
            }
        }
        let acceptor = self
            .tls
            .acceptor()
            .map_err(io::Error::other)
            .map_err(&before_dispatch)?;
        // This exclusive store is transport identity fencing. The callback
        // below must separately admit the actual offer into the LIVE authority.
        let admission = match admission {
            Some(admission) => admission,
            None => PinnedWorkerAdmission::open(&self.state, &self.worker, self.pin)
                .map_err(&before_dispatch)?,
        };
        let runtime = RuntimeBuilder::current_thread().build().map_err(|error| {
            before_dispatch(io::Error::other(format!(
                "remote dependency runtime: {error:?}"
            )))
        })?;
        let peer = rabs_asupersync::daemon_runtime::block_on_top_level(&runtime, async {
            let exchange = async {
                let listener = asupersync::net::TcpListener::bind(self.address)
                    .await
                    .map_err(|error| {
                        io::Error::new(
                            error.kind(),
                            format!("remote dependency TLS listen: {error}"),
                        )
                    })?;
                let (stream, _) = listener.accept().await.map_err(worker_transport_error)?;
                // The TLS boundary exposes authentication failures as text.
                // Do not infer transport retry eligibility from that text.
                accept_peer(&acceptor, stream)
                    .await
                    .map_err(io::Error::other)
            };
            until_cancelled(&cancellation, async {
                let budget = connection_deadline
                    .checked_duration_since(Instant::now())
                    .filter(|remaining| !remaining.is_zero())
                    .ok_or_else(|| {
                        worker_transport_error(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "remote dependency worker connection deadline exceeded",
                        ))
                    })?;
                asupersync::time::timeout(asupersync::time::wall_now(), budget, exchange)
                    .await
                    .map_err(|_| {
                        worker_transport_error(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "remote dependency worker connection deadline exceeded",
                        ))
                    })?
            })
            .await
        })
        .map_err(&before_dispatch)?;

        match operation {
            ReservedOperation::Execute {
                upload,
                on_admitted,
            } => receive_authenticated_with_admission(
                &runtime,
                peer,
                admission,
                request,
                destination,
                DeliveryMode::Execute,
                Some(upload),
                None,
                cancellation,
                None,
                Some(on_admitted),
            ),
            ReservedOperation::Continue(sealed) => receive_authenticated_continuation(
                &runtime,
                peer,
                admission,
                request,
                destination,
                None,
                cancellation,
                sealed,
            ),
        }
    }
}

/// Exactly one caller owns this worker slot until it drops the reservation,
/// including any capture/publication after delivery. It cannot be cloned.
pub struct RemoteDependencyReservation {
    transport: Arc<RemoteDependencyTransport>,
    admission: Option<PinnedWorkerAdmission>,
    request_id: Option<u64>,
    dispatch_attempted: bool,
    /// Only this reservation's own interrupted receive can grant one reconnect.
    /// This is consumed without allocating an ID or another execution lease.
    continuation: Option<SealedResult>,
}

impl std::fmt::Debug for RemoteDependencyReservation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RemoteDependencyReservation")
            .field("transport", &self.transport)
            .field("request_id", &self.request_id)
            .field("admission_held", &self.admission.is_some())
            .field("dispatch_attempted", &self.dispatch_attempted)
            .field("continuation_available", &self.continuation.is_some())
            .finish()
    }
}

impl RemoteDependencyReservation {
    /// The configured identity held by this slot; transport admission still
    /// independently authenticates the worker's key and process incarnation.
    pub fn worker(&self) -> &str {
        self.transport.worker()
    }

    /// Persist only this selected worker's exact recovery context. A pool can
    /// change membership or order while an uncertain result remains retained;
    /// its aggregate status cannot identify the owner of this request.
    pub fn worker_configuration(&self, context_version: &str) -> Value {
        let pin: String = self
            .transport
            .pin
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        serde_json::json!({
            "remote_protocol":1, "dependency_context":context_version,
            "listen":self.transport.address.to_string(), "worker_id":self.transport.worker,
            "worker_spki_sha256":pin,
        })
    }

    /// Allocate after the wrapper accepts remote execution, before preparing
    /// the immutable request and uploads. This is blocking metadata work, never
    /// part of the decision lane. The persistent worker lock stays owned until
    /// execute finishes or this reservation is dropped.
    pub fn allocate_request_id(&mut self) -> io::Result<u64> {
        if self.dispatch_attempted {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "this remote dependency reservation already attempted execution",
            ));
        }
        if asupersync::cx::Cx::current().is_some() {
            return Err(invalid(
                "worker request allocation requires a dedicated blocking thread",
            ));
        }
        if self.request_id.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "this remote dependency reservation already owns a request ID",
            ));
        }
        if self.admission.is_none() {
            self.admission = Some(PinnedWorkerAdmission::open(
                &self.transport.state,
                &self.transport.worker,
                self.transport.pin,
            )?);
        }
        let admission = self
            .admission
            .as_ref()
            .ok_or_else(|| invalid("missing reserved worker admission"))?;
        let request_id = admission.allocate_request_id()?;
        self.request_id = Some(request_id);
        Ok(request_id)
    }

    /// Run once on a dedicated blocking thread. A transport error after the
    /// execution write may have run the compiler; preserve its uncertainty bit.
    /// The caller retains this capacity through result capture/publication so a
    /// new request cannot race a still-live coordinator worker session. Drop the
    /// reservation only after releasing that session. All delivered files stay
    /// private until the ordinary coordinator and wrapper paths install them.
    pub fn execute(
        &mut self,
        request: &Value,
        upload: &SourceUpload,
        destination: &Path,
        cancellation: OperationCancellation,
        on_admitted: impl FnOnce(&WorkerSessionOffer) -> io::Result<()> + Send + 'static,
    ) -> Result<Delivery, DeliveryFailure> {
        if std::mem::replace(&mut self.dispatch_attempted, true) {
            // A second call cannot prove the first compiler stopped. Even API
            // misuse must never turn an uncertain dispatch into safe fallback.
            return Err(DeliveryFailure {
                directory: destination.to_path_buf(),
                execution_may_have_run: true,
                transport_interrupted: false,
                detail: "remote dependency reservation cannot dispatch twice".into(),
                sealed_result: None,
            });
        }
        if self
            .request_id
            .is_some_and(|allocated| request["request_id"].as_u64() != Some(allocated))
        {
            return Err(failure(
                destination,
                invalid("execution request differs from its durable reserved worker ID"),
            ));
        }
        let outcome = self.transport.execute_reserved(
            self.admission.take(),
            request,
            destination,
            cancellation.clone(),
            ReservedOperation::Execute {
                upload,
                on_admitted: Box::new(on_admitted),
            },
        );
        self.continuation = outcome
            .as_ref()
            .err()
            .filter(|failure| failure.transport_interrupted && failure.execution_may_have_run)
            .and_then(|failure| failure.sealed_result.as_deref().cloned());
        self.transport
            .observe_delivery(&outcome, cancellation.is_cancelled(), Instant::now());
        outcome
    }

    /// Reconnect once for the exact result already observed by this reservation.
    /// No upload, admission callback, lease renewal or compiler dispatch exists
    /// on this path. The receiver rehashes every delivered byte; partial local
    /// files remain private recovery custody and are not copied without bounds.
    pub(crate) fn continue_result(
        &mut self,
        request: &Value,
        destination: &Path,
        cancellation: OperationCancellation,
    ) -> Result<Delivery, DeliveryFailure> {
        let refuse = |reason: &str| DeliveryFailure {
            directory: destination.to_path_buf(),
            execution_may_have_run: true,
            transport_interrupted: false,
            detail: reason.to_owned(),
            sealed_result: None,
        };
        let sealed = self
            .continuation
            .take()
            .ok_or_else(|| refuse("this reservation has no sealed result to continue"))?;
        if !self.dispatch_attempted
            || self.request_id.is_none()
            || self.request_id != request["request_id"].as_u64()
        {
            return Err(refuse(
                "result continuation differs from its original reserved request",
            ));
        }
        let outcome = self.transport.execute_reserved(
            None,
            request,
            destination,
            cancellation.clone(),
            ReservedOperation::Continue(sealed),
        );
        self.transport
            .observe_delivery(&outcome, cancellation.is_cancelled(), Instant::now());
        outcome
    }
}

impl Drop for RemoteDependencyReservation {
    fn drop(&mut self) {
        // Release persistent ownership before making the in-process slot
        // available; its next owner must never race a still-held store lock.
        drop(self.admission.take());
        self.transport.occupied.store(false, Ordering::Release);
    }
}

fn preflight(request: &Value, upload: &SourceUpload, destination: &Path) -> io::Result<()> {
    validate_request(request)?;
    upload.validate_request(request)?;
    if !absolute_without_traversal(destination) {
        return Err(invalid(
            "remote dependency destination must be absolute without traversal",
        ));
    }
    if !matches!(
        request["dependency_context"]["version"].as_str(),
        Some(
            DEPENDENCY_CONTEXT_VERSION
                | CANONICAL_DEPENDENCY_CONTEXT_VERSION
                | CANONICAL_WORKSPACE_CONTEXT_VERSION
        )
    ) || request.get("command_context").is_some()
        || request.get("artifacts").is_none()
        || !toolchain_transfer(request)?
        || request["program"].as_str().is_none()
        || request["program"] != request["dependency_context"]["compiler"]
    {
        return Err(invalid(
            "remote dependency requires its execution context, artifacts and captured toolchain",
        ));
    }
    Ok(())
}

fn cancelled() -> io::Error {
    io::Error::new(
        io::ErrorKind::Interrupted,
        "remote dependency cancelled before dispatch",
    )
}

async fn until_cancelled<T>(
    cancellation: &OperationCancellation,
    future: impl Future<Output = io::Result<T>>,
) -> io::Result<T> {
    let mut stopped = pin!(cancellation.cancelled());
    let mut pending = pin!(future);
    poll_fn(|cx| {
        if stopped.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(cancelled()));
        }
        pending.as_mut().poll(cx)
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transport() -> Arc<RemoteDependencyTransport> {
        transport_at(Path::new("/private/remote-state"))
    }

    fn transport_at(state: &Path) -> Arc<RemoteDependencyTransport> {
        Arc::new(
            RemoteDependencyTransport::new(
                "127.0.0.1:9123".parse().unwrap(),
                "worker".into(),
                [1; 32],
                state.to_path_buf(),
                TlsFiles {
                    ca: PathBuf::from("/private/ca.pem"),
                    certificate: PathBuf::from("/private/server.pem"),
                    private_key: PathBuf::from("/private/server.key"),
                },
            )
            .unwrap(),
        )
    }

    #[test]
    fn workspace_preflight_accepts_exact_retained_upload_without_losing_existing_versions() {
        use rabs_sandbox::snapshot_capture::capture_sealed_source;
        use rabs_sandbox::toolchain_dataset::{ToolchainLimits, capture_toolchain};
        use rabs_sandbox::toolchain_transfer::TOOLCHAIN_TRANSFER_VERSION;
        use serde_json::json;

        let state = crate::test_util::private_tempdir();
        let source = state.path().join("source");
        std::fs::create_dir_all(source.join("src")).unwrap();
        std::fs::create_dir(source.join("empty")).unwrap();
        std::fs::write(source.join("src/lib.rs"), b"pub fn unit() {}\n").unwrap();
        let snapshot = Arc::new(
            capture_sealed_source(&[("workspace".into(), source)], false, 1, 4096).unwrap(),
        );
        let upload = SourceUpload::from_snapshot(snapshot, "workspace", &["src/lib.rs".into()])
            .unwrap()
            .with_dependency_artifacts(Vec::new())
            .unwrap();
        let compiler = state.path().join("compiler");
        std::fs::create_dir_all(compiler.join("bin")).unwrap();
        // Dataset bytes only: this regression does not execute rustc or TLS.
        std::fs::write(compiler.join("bin/rustc"), b"fixture retained compiler").unwrap();
        let prepared = capture_toolchain(
            &compiler,
            &state.path().join("retained-toolchain"),
            None,
            &ToolchainLimits::default(),
            || false,
        )
        .unwrap();
        let mut request = json!({
            "kind":"canonical-exec", "request_id":7,
            "program":"/__rabs/toolchain/bin/rustc", "args":["src/lib.rs"],
            "source_manifest":upload.wire_manifest(),
            "toolchain_transfer":TOOLCHAIN_TRANSFER_VERSION,
            "toolchain_identity":crate::coord::worker_delivery::toolchain_identity_value(prepared.identity()),
            "artifacts":{"unit":"workspace-unit", "files":["libunit.rmeta","unit.d"]},
            "dependency_context":{
                "version":CANONICAL_WORKSPACE_CONTEXT_VERSION,
                "execution_mode":"metadata", "source_root":"/__rabs/workspace",
                "source_directories":["empty","src"],
                "generated_root":null, "generated_directories":[],
                "compiler":"/__rabs/toolchain/bin/rustc"
            }
        });
        let upload = upload.with_toolchain(prepared, &request).unwrap();
        let destination = state.path().join("delivery-not-created-by-preflight");
        for version in [
            DEPENDENCY_CONTEXT_VERSION,
            CANONICAL_DEPENDENCY_CONTEXT_VERSION,
            CANONICAL_WORKSPACE_CONTEXT_VERSION,
        ] {
            request["dependency_context"]["version"] = json!(version);
            assert!(
                preflight(&request, &upload, &destination).is_ok(),
                "{version}"
            );
        }
        request["dependency_context"]["version"] = json!("canonical-workspace-exec-future");
        assert!(preflight(&request, &upload, &destination).is_err());
        request["dependency_context"]["version"] = json!(CANONICAL_WORKSPACE_CONTEXT_VERSION);
        request["dependency_context"]["source_directories"] = json!(["src"]);
        assert!(preflight(&request, &upload, &destination).is_err());
        request["dependency_context"]["source_directories"] = json!(["empty", "src"]);
        request["program"] = json!("/__rabs/toolchain/bin/other");
        assert!(preflight(&request, &upload, &destination).is_err());
        assert!(!destination.exists());
    }

    #[test]
    fn a_reserved_worker_cannot_accept_another_offer_and_can_move_to_its_lane() {
        let transport = transport();
        let reservation = transport.try_reserve().unwrap();
        assert_eq!(
            transport.try_reserve().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        let (release, wait) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            wait.recv_timeout(Duration::from_secs(5)).unwrap();
            drop(reservation);
        });
        assert_eq!(
            transport.try_reserve().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        release.send(()).unwrap();
        thread.join().unwrap();
        drop(transport.try_reserve().unwrap());
        assert!(transport.try_reserve().is_ok());
    }

    #[test]
    fn allocation_keeps_the_persistent_worker_lock_until_reservation_release() {
        let state = tempfile::tempdir().unwrap();
        let transport = transport_at(state.path());
        let independent = transport_at(state.path());
        let mut reservation = transport.try_reserve().unwrap();
        let first = reservation.allocate_request_id().unwrap();
        assert!(first > 0);
        assert_eq!(
            reservation.allocate_request_id().unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        let mut competing = independent.try_reserve().unwrap();
        assert!(competing.allocate_request_id().is_err());
        drop(competing);
        drop(reservation);

        let mut next = independent.try_reserve().unwrap();
        assert!(next.allocate_request_id().unwrap() > first);
        assert!(transport.try_reserve().is_ok());
        drop(next);
        let mut reopened = transport.try_reserve().unwrap();
        assert!(reopened.allocate_request_id().unwrap() > first);
    }

    #[cfg(unix)]
    #[test]
    fn execution_keeps_capacity_until_drop_and_cannot_repeat_a_reserved_dispatch() {
        use rabs_sandbox::snapshot_capture::capture_sealed_source;
        use serde_json::json;

        let state = tempfile::tempdir().unwrap();
        let transport = transport_at(state.path());
        let mut reservation = transport.try_reserve().unwrap();
        let allocated = reservation.allocate_request_id().unwrap();
        let source = tempfile::tempdir().unwrap();
        std::fs::write(
            source.path().join("lib.rs"),
            b"pub fn answer() -> u8 { 42 }",
        )
        .unwrap();
        let snapshot = capture_sealed_source(
            &[("workspace".into(), source.path().to_path_buf())],
            false,
            1,
            1024,
        )
        .unwrap();
        let upload =
            SourceUpload::from_snapshot(Arc::new(snapshot), "workspace", &["lib.rs".into()])
                .unwrap();
        let destination = state.path().join("must-not-be-created");
        let error = reservation
            .execute(
                &json!({"request_id":allocated.checked_add(1).unwrap()}),
                &upload,
                &destination,
                OperationCancellation::new(),
                |_| panic!("mismatched request must not admit a live worker"),
            )
            .unwrap_err();
        assert!(!error.execution_may_have_run);
        assert!(!error.transport_interrupted);
        assert!(error.detail.contains("durable reserved worker ID"));
        assert!(!destination.exists());
        assert_eq!(
            transport.try_reserve().unwrap_err().kind(),
            io::ErrorKind::WouldBlock,
            "delivery must retain capacity until the caller releases its session"
        );
        let repeated = reservation
            .execute(
                &json!({"request_id":allocated}),
                &upload,
                &destination,
                OperationCancellation::new(),
                |_| panic!("a repeated reservation must never admit another worker"),
            )
            .unwrap_err();
        assert!(repeated.execution_may_have_run);
        assert!(!repeated.transport_interrupted);
        assert!(repeated.detail.contains("cannot dispatch twice"));
        assert!(!destination.exists());
        assert_eq!(
            reservation.allocate_request_id().unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        drop(reservation);
        let mut next = transport.try_reserve().unwrap();
        assert!(next.allocate_request_id().unwrap() > allocated);
    }

    #[test]
    fn configuration_requires_reachable_fixed_port_and_explicit_identity() {
        let configured = transport();
        for case in 0..5 {
            let mut address = configured.address;
            let mut worker = configured.worker.clone();
            let mut pin = configured.pin;
            let mut state = configured.state.clone();
            let mut tls = configured.tls.clone();
            match case {
                0 => address.set_port(0),
                1 => worker.push('\n'),
                2 => pin = [0; 32],
                3 => state = PathBuf::from("/private/../state"),
                _ => tls.private_key = PathBuf::from("relative.key"),
            }
            assert!(
                RemoteDependencyTransport::new(address, worker, pin, state, tls).is_err(),
                "case {case}"
            );
        }
    }

    fn disconnected(execution_may_have_run: bool) -> Result<Delivery, DeliveryFailure> {
        let mut failure = failure(
            Path::new("/private/retained-result"),
            worker_transport_error(io::Error::new(
                io::ErrorKind::TimedOut,
                "fixture socket deadline",
            )),
        );
        failure.execution_may_have_run = execution_may_have_run;
        Err(failure)
    }

    fn delivered(confirmed: bool, interrupted: bool) -> Result<Delivery, DeliveryFailure> {
        // Transport outcome fixture only, not claimed TLS/compiler execution.
        Ok(Delivery {
            directory: PathBuf::from("/private/retained-result"),
            receipt: serde_json::json!({"exit_code": 1, "publication_authorized": false}),
            acknowledgments_confirmed: confirmed,
            acknowledgment_error: (!confirmed).then(|| "fixture ACK failure".into()),
            acknowledgment_interrupted: interrupted,
        })
    }

    #[test]
    fn connectivity_failure_excludes_only_that_worker_without_allocating_work() {
        let failed = transport();
        let healthy = transport();
        let now = Instant::now();
        let owner = failed.try_reserve_at(now).unwrap();
        let outcome = disconnected(false);
        failed.observe_delivery(&outcome, false, now);
        drop(owner);
        for _ in 0..128 {
            let error = failed.try_reserve_at(now).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
            assert!(error.to_string().contains("cooling down"));
            assert!(!failed.occupied.load(Ordering::Acquire));
        }
        let owner = healthy.try_reserve_at(now).unwrap();
        assert!(owner.request_id.is_none());
        assert!(owner.admission.is_none());
        assert!(!owner.dispatch_attempted);
        assert_eq!(
            failed.cooldown.lock().unwrap().delay,
            FIRST_CONNECTION_COOLDOWN,
        );
        let error = outcome.unwrap_err();
        assert!(!error.execution_may_have_run);
        assert!(error.transport_interrupted);
        assert_eq!(error.directory, Path::new("/private/retained-result"));
    }

    #[test]
    fn cooldown_is_bounded_exponential_and_polling_does_not_renew_it() {
        let mut state = ConnectionCooldown::default();
        let start = Instant::now();
        assert_eq!(state.remaining(start), None);
        let mut now = start;
        for seconds in [5, 10, 20, 40, 60, 60, 60] {
            state.interrupted(now);
            let delay = Duration::from_secs(seconds);
            assert_eq!(state.remaining(now), Some(delay));
            for _ in 0..128 {
                assert_eq!(state.remaining(now + delay / 2), Some(delay / 2));
            }
            assert_eq!(state.remaining(now + delay), None);
            assert_eq!(state.remaining(start), Some(delay));
            now += delay;
        }
        for _ in 0..1000 {
            state.interrupted(now);
            assert_eq!(state.remaining(now), Some(MAX_CONNECTION_COOLDOWN));
        }
        state.completed();
        state.interrupted(now);
        assert_eq!(state.remaining(now), Some(FIRST_CONNECTION_COOLDOWN));
    }

    #[test]
    fn queue_cooldown_deadline_is_absolute_and_grants_no_reservation() {
        let transport = transport();
        let now = Instant::now();
        assert_eq!(transport.cooldown_deadline_at(now).unwrap(), None);
        transport.observe_delivery(&disconnected(false), false, now);
        let deadline = now + FIRST_CONNECTION_COOLDOWN;
        for elapsed in [
            Duration::ZERO,
            Duration::from_secs(1),
            Duration::from_secs(4),
        ] {
            assert_eq!(
                transport.cooldown_deadline_at(now + elapsed).unwrap(),
                Some(deadline)
            );
            assert!(!transport.occupied.load(Ordering::Acquire));
        }
        assert_eq!(transport.cooldown_deadline_at(deadline).unwrap(), None);
        let owner = transport.try_reserve_at(deadline).unwrap();
        assert!(owner.request_id.is_none());
        assert!(owner.admission.is_none());
        assert!(!owner.dispatch_attempted);
        assert_eq!(
            transport.cooldown.lock().unwrap().delay,
            FIRST_CONNECTION_COOLDOWN
        );
    }

    #[test]
    fn queue_cooldown_snapshot_waits_for_current_writer_and_reports_poison() {
        let transport = transport();
        let now = Instant::now();
        let mut state = transport.cooldown.lock().unwrap();
        let reader = Arc::clone(&transport);
        let (started, start) = std::sync::mpsc::sync_channel(1);
        let observer = std::thread::spawn(move || {
            started.send(()).unwrap();
            reader.cooldown_deadline_at(now)
        });
        start.recv_timeout(Duration::from_secs(5)).unwrap();
        state.interrupted(now);
        drop(state);
        assert_eq!(
            observer.join().unwrap().unwrap(),
            Some(now + FIRST_CONNECTION_COOLDOWN),
        );
        assert!(!transport.occupied.load(Ordering::Acquire));

        let writer = Arc::clone(&transport);
        assert!(
            std::thread::spawn(move || {
                let _state = writer.cooldown.lock().unwrap();
                panic!("poison only the local connectivity hint");
            })
            .join()
            .is_err()
        );
        assert_eq!(
            transport.cooldown_deadline_at(now).unwrap_err().kind(),
            io::ErrorKind::Other,
        );
        assert!(!transport.occupied.load(Ordering::Acquire));
    }

    #[test]
    fn cooldown_expiring_after_refused_probe_keeps_its_immediate_queue_wake() {
        let transport = transport();
        let failed_at = Instant::now();
        transport.observe_delivery(&disconnected(false), false, failed_at);
        let expires = failed_at + FIRST_CONNECTION_COOLDOWN;
        let observed = expires - Duration::from_nanos(1);
        assert_eq!(
            transport.try_reserve_at(observed).unwrap_err().kind(),
            io::ErrorKind::WouldBlock,
        );
        // Advance the injected observation past expiry before calculating the
        // queue wait. A fresh snapshot has no future deadline; retaining the
        // failed probe's observation preserves the already-due immediate wake.
        assert_eq!(transport.cooldown_deadline_at(expires).unwrap(), None);
        assert_eq!(
            transport.cooldown_deadline_at(observed).unwrap(),
            Some(expires),
        );
        let owner = transport.try_reserve_at(expires).unwrap();
        // Once a real owner has occupied the worker, the next probe waits for
        // its notifying release rather than spinning on an old expiry.
        assert_eq!(transport.cooldown_deadline_at(expires).unwrap(), None);
        assert_eq!(
            transport.try_reserve_at(expires).unwrap_err().kind(),
            io::ErrorKind::WouldBlock,
        );
        drop(owner);
        assert!(transport.try_reserve_at(expires).is_ok());
    }

    #[test]
    fn cooldown_expiry_allows_only_one_concurrent_probe_without_resetting_history() {
        let transport = transport();
        let now = Instant::now();
        transport.observe_delivery(&disconnected(false), false, now);
        let retry_at = now + FIRST_CONNECTION_COOLDOWN;
        assert!(
            transport
                .try_reserve_at(retry_at - Duration::from_nanos(1))
                .is_err(),
        );
        let all_reserved = Arc::new(std::sync::Barrier::new(16));
        let mut threads = Vec::new();
        for _ in 0..16 {
            let transport = Arc::clone(&transport);
            let all_reserved = Arc::clone(&all_reserved);
            threads.push(std::thread::spawn(move || {
                let owner = transport.try_reserve_at(retry_at);
                let admitted = owner.is_ok();
                if let Err(error) = &owner {
                    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
                }
                // Hold the sole successful guard until all contenders tried.
                all_reserved.wait();
                drop(owner);
                admitted
            }));
        }
        let winners = threads
            .into_iter()
            .map(|thread| usize::from(thread.join().unwrap()))
            .sum::<usize>();
        assert_eq!(winners, 1);
        assert!(!transport.occupied.load(Ordering::Acquire));
        // An offer that is abandoned before execution proves no recovery.
        drop(transport.try_reserve_at(retry_at).unwrap());
        transport.observe_delivery(&disconnected(false), false, retry_at);
        assert_eq!(
            transport.cooldown.lock().unwrap().remaining(retry_at),
            Some(FIRST_CONNECTION_COOLDOWN * 2),
        );
    }

    #[test]
    fn local_errors_and_caller_cancellation_neither_penalize_nor_rehabilitate() {
        let transport = transport();
        let now = Instant::now();
        transport.observe_delivery(&disconnected(false), false, now);
        let retry_at = now + FIRST_CONNECTION_COOLDOWN;
        for kind in [
            io::ErrorKind::TimedOut,
            io::ErrorKind::BrokenPipe,
            io::ErrorKind::Other,
        ] {
            // Identical ErrorKinds/messages from a filesystem or policy seam
            // have no typed transport provenance and cannot cool a worker.
            let outcome = Err(failure(
                Path::new("/private/retained-result"),
                io::Error::new(kind, "socket timeout: misleading nontransport text"),
            ));
            transport.observe_delivery(&outcome, false, retry_at);
        }
        transport.observe_delivery(&disconnected(true), true, retry_at);
        transport.observe_delivery(&delivered(false, true), true, retry_at);
        transport.observe_delivery(&delivered(false, false), false, retry_at);
        let state = transport.cooldown.lock().unwrap();
        assert_eq!(state.failed_at, Some(now));
        assert_eq!(state.delay, FIRST_CONNECTION_COOLDOWN);
        drop(state);
        assert!(transport.try_reserve_at(retry_at).is_ok());
    }

    #[test]
    fn a_verified_exchange_resets_connectivity_even_for_a_failed_compilation() {
        let transport = transport();
        let now = Instant::now();
        transport.observe_delivery(&disconnected(false), false, now);
        let owner = transport
            .try_reserve_at(now + FIRST_CONNECTION_COOLDOWN)
            .unwrap();
        let complete = delivered(true, false);
        transport.observe_delivery(&complete, false, now + FIRST_CONNECTION_COOLDOWN);
        assert!(transport.cooldown.lock().unwrap().failed_at.is_none());
        assert!(
            transport
                .try_reserve_at(now + FIRST_CONNECTION_COOLDOWN)
                .is_err()
        );
        drop(owner);
        assert!(
            transport
                .try_reserve_at(now + FIRST_CONNECTION_COOLDOWN)
                .is_ok()
        );
        assert_eq!(complete.as_ref().unwrap().receipt["exit_code"], 1);
        assert_eq!(
            complete.as_ref().unwrap().receipt["publication_authorized"],
            false,
        );
        transport.observe_delivery(&disconnected(false), false, now + FIRST_CONNECTION_COOLDOWN);
        assert_eq!(
            transport.cooldown.lock().unwrap().delay,
            FIRST_CONNECTION_COOLDOWN,
        );
    }

    #[test]
    fn lost_ack_cools_placement_without_discarding_verified_delivery() {
        let transport = transport();
        let now = Instant::now();
        let complete = delivered(false, true);
        transport.observe_delivery(&complete, false, now);
        assert!(transport.try_reserve_at(now).is_err());
        let delivery = complete.unwrap();
        assert!(!delivery.acknowledgments_confirmed);
        assert!(delivery.acknowledgment_interrupted);
        assert_eq!(delivery.directory, Path::new("/private/retained-result"));
        assert_eq!(
            delivery.acknowledgment_error.as_deref(),
            Some("fixture ACK failure"),
        );
    }

    #[test]
    fn uncertain_execution_remains_uncertain_after_cooldown_expires() {
        let transport = transport();
        let now = Instant::now();
        let outcome = disconnected(true);
        transport.observe_delivery(&outcome, false, now);
        assert!(transport.try_reserve_at(now).is_err());
        drop(
            transport
                .try_reserve_at(now + MAX_CONNECTION_COOLDOWN)
                .unwrap(),
        );
        // Availability is not drain proof, actor reconciliation or permission
        // to retry this same request. The original result is unchanged.
        let failure = outcome.unwrap_err();
        assert!(failure.execution_may_have_run);
        assert!(failure.transport_interrupted);
        assert_eq!(failure.detail, "fixture socket deadline");
    }

    #[test]
    fn contended_connectivity_state_never_strands_worker_capacity() {
        let transport = transport();
        let now = Instant::now();
        let state = transport.cooldown.lock().unwrap();
        assert_eq!(
            transport.try_reserve_at(now).unwrap_err().kind(),
            io::ErrorKind::WouldBlock,
        );
        assert!(!transport.occupied.load(Ordering::Acquire));
        drop(state);
        assert!(transport.try_reserve_at(now).is_ok());
    }

    #[test]
    fn cancellation_preempts_a_pending_connection_future() {
        let cancellation = OperationCancellation::new();
        cancellation.cancel();
        let runtime = RuntimeBuilder::current_thread().build().unwrap();
        let error = rabs_asupersync::daemon_runtime::block_on_top_level(&runtime, async {
            until_cancelled(&cancellation, std::future::pending::<io::Result<()>>()).await
        })
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert!(!transport_interrupted(&error));
    }
}
