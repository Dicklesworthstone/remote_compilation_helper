//! One bounded authenticated worker connection for a live dependency action.
//!
//! Workers reconnect outward to the configured listener. A caller reserves the
//! sole slot before offering remote execution, then moves the reservation to a
//! dedicated blocking lane. TLS identity, challenge and durable boot admission
//! precede its live-coordinator callback; a refused callback sends no inputs or
//! execution request. The ordinary receiver verifies private delivery bytes.
//! Publication, Cargo output installation and fallback remain with the caller.

use super::secure_worker_delivery::{
    DEPENDENCY_CONTEXT_VERSION, OperationCancellation, PinnedWorkerAdmission, WorkerAdmissionHook,
    parse_worker_pin, receive_authenticated_with_admission,
};
use super::source_delivery::SourceUpload;
use super::worker_delivery::{
    Delivery, DeliveryFailure, DeliveryMode, toolchain_transfer, transport_interrupted,
    validate_request, worker_transport_error,
};
use asupersync::runtime::RuntimeBuilder;
use rabs_asupersync::worker_transport::{TlsFiles, accept_peer};
use rabs_protocol::worker_fence::WorkerSessionOffer;
use serde_json::Value;
use std::future::{Future, poll_fn};
use std::io;
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;
use std::time::Duration;

/// Includes both the outward reconnect and TLS handshake. The established ATP
/// receiver separately bounds authentication, transfer, execution and cleanup.
const CONNECT_BUDGET: Duration = Duration::from_secs(60);

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
    }
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
    pub fn try_reserve(self: &Arc<Self>) -> io::Result<RemoteDependencyReservation> {
        self.occupied
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "remote dependency worker is busy",
                )
            })?;
        Ok(RemoteDependencyReservation {
            transport: Arc::clone(self),
            admission: None,
            request_id: None,
            dispatch_attempted: false,
        })
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

    #[allow(clippy::too_many_arguments)]
    fn execute_reserved(
        &self,
        admission: Option<PinnedWorkerAdmission>,
        request: &Value,
        upload: &SourceUpload,
        destination: &Path,
        cancellation: OperationCancellation,
        on_admitted: WorkerAdmissionHook,
    ) -> Result<Delivery, DeliveryFailure> {
        let before_dispatch = |error| failure(destination, error);
        if asupersync::cx::Cx::current().is_some() {
            return Err(before_dispatch(invalid(
                "remote dependency delivery requires a dedicated blocking thread",
            )));
        }
        if cancellation.is_cancelled() {
            return Err(before_dispatch(cancelled()));
        }
        preflight(request, upload, destination).map_err(&before_dispatch)?;
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
                asupersync::time::timeout(asupersync::time::wall_now(), CONNECT_BUDGET, exchange)
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

        receive_authenticated_with_admission(
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
        )
    }
}

/// Exactly one caller owns this worker slot until it drops the reservation,
/// including any capture/publication after delivery. It cannot be cloned.
pub struct RemoteDependencyReservation {
    transport: Arc<RemoteDependencyTransport>,
    admission: Option<PinnedWorkerAdmission>,
    request_id: Option<u64>,
    dispatch_attempted: bool,
}

impl std::fmt::Debug for RemoteDependencyReservation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RemoteDependencyReservation")
            .field("transport", &self.transport)
            .field("request_id", &self.request_id)
            .field("admission_held", &self.admission.is_some())
            .field("dispatch_attempted", &self.dispatch_attempted)
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
    pub fn worker_configuration(&self) -> Value {
        let pin: String = self
            .transport
            .pin
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        serde_json::json!({
            "remote_protocol":1, "dependency_context":DEPENDENCY_CONTEXT_VERSION,
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
        self.transport.execute_reserved(
            self.admission.take(),
            request,
            upload,
            destination,
            cancellation,
            Box::new(on_admitted),
        )
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
    if request["dependency_context"]["version"] != DEPENDENCY_CONTEXT_VERSION
        || request.get("command_context").is_some()
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
