//! One owned reactor for a worker's listener, authenticated standby and delivery.
//!
//! The mailbox carries at most one reserved operation. Only its owner thread
//! touches the listener or TLS stream, and shutdown joins that owner after the
//! existing delivery engine has processed cancellation and drained execution.

use super::{cancelled, failure, until_cancelled};
use crate::coord::secure_worker_delivery::{
    OperationCancellation, PinnedWorkerAdmission, StandbyPeer, WorkerAdmissionHook,
    prepare_standby, receive_standby_with_admission,
};
use crate::coord::source_delivery::SourceUpload;
use crate::coord::worker_delivery::{
    Delivery, DeliveryFailure, SealedResult, worker_transport_error,
};
use asupersync::net::{TcpListener, TcpStream};
use asupersync::runtime::{Runtime, RuntimeBuilder};
use asupersync::tls::TlsAcceptor;
use rabs_asupersync::daemon_runtime::block_on_top_level;
use rabs_asupersync::worker_transport::{TlsFiles, accept_peer};
use serde_json::{Value, json};
use std::future::{Future, poll_fn};
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::{Pin, pin};
use std::sync::{Arc, Mutex, mpsc};
use std::task::{Context, Poll, Waker};
use std::thread::JoinHandle;
use std::time::Instant;

/// Advisory evidence from the exact authenticated connection currently parked
/// on this owner. A generation is never reused, including across a disconnect.
/// It grants no request, execution lease, or durable worker admission.
#[derive(Debug)]
pub(super) struct Advertisement {
    pub generation: u64,
    pub hello: Value,
}

#[derive(Debug, Default)]
struct ReadinessState {
    next_generation: u64,
    current: Option<Arc<Advertisement>>,
    closed: bool,
}

#[derive(Debug, Default)]
pub(super) struct Readiness(Mutex<ReadinessState>);

impl Readiness {
    pub(super) fn snapshot(&self) -> Option<Arc<Advertisement>> {
        self.0
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .current
            .clone()
    }

    pub(super) fn is_current(&self, generation: u64) -> bool {
        self.snapshot()
            .is_some_and(|current| current.generation == generation)
    }

    fn publish(
        self: &Arc<Self>,
        hello: &Value,
        changed: Arc<dyn Fn() + Send + Sync>,
    ) -> io::Result<AdvertisementOwner> {
        let mut state = self.0.lock().unwrap_or_else(|error| error.into_inner());
        if state.closed {
            return Err(cancelled());
        }
        let generation = state
            .next_generation
            .checked_add(1)
            .ok_or_else(|| io::Error::other("standby readiness generation exhausted"))?;
        state.next_generation = generation;
        state.current = Some(Arc::new(Advertisement {
            generation,
            hello: hello.clone(),
        }));
        Ok(AdvertisementOwner {
            readiness: Arc::clone(self),
            generation,
            changed,
        })
    }

    pub(super) fn close(&self) {
        let mut state = self.0.lock().unwrap_or_else(|error| error.into_inner());
        state.closed = true;
        state.current = None;
    }

    fn is_closed(&self) -> bool {
        self.0
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .closed
    }

    #[cfg(test)]
    pub(super) fn publish_for_test(self: &Arc<Self>, hello: &Value) -> AdvertisementOwner {
        self.publish(hello, Arc::new(|| {})).unwrap()
    }
}

/// The socket owner alone retains this registration. Revocation precedes
/// dispatch and every peer drop; an old destructor cannot clear a newer peer.
pub(super) struct AdvertisementOwner {
    readiness: Arc<Readiness>,
    generation: u64,
    changed: Arc<dyn Fn() + Send + Sync>,
}

impl Drop for AdvertisementOwner {
    fn drop(&mut self) {
        let revoked = {
            let mut state = self
                .readiness
                .0
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if state
                .current
                .as_ref()
                .is_some_and(|current| current.generation == self.generation)
            {
                state.current = None;
                true
            } else {
                false
            }
        };
        if revoked {
            (self.changed)();
        }
    }
}

struct ParkedPeer {
    // Field order revokes the hint before closing the authenticated transport.
    advertisement: Option<AdvertisementOwner>,
    peer: StandbyPeer,
}

impl ParkedPeer {
    fn new(
        peer: StandbyPeer,
        readiness: &Arc<Readiness>,
        changed: &Arc<dyn Fn() + Send + Sync>,
    ) -> io::Result<Self> {
        let advertisement = peer
            .supported()
            .then(|| readiness.publish(peer.scheduling_hello(), Arc::clone(changed)))
            .transpose()?;
        Ok(Self {
            advertisement,
            peer,
        })
    }

    fn into_peer(self) -> StandbyPeer {
        let Self {
            advertisement,
            peer,
        } = self;
        drop(advertisement);
        peer
    }
}

pub(super) enum Operation {
    Execute {
        upload: Box<SourceUpload>,
        on_admitted: WorkerAdmissionHook,
    },
    Continue(Box<SealedResult>),
}

pub(super) struct Assignment {
    pub admission: PinnedWorkerAdmission,
    pub request: Value,
    pub destination: PathBuf,
    pub cancellation: OperationCancellation,
    pub connection_deadline: Instant,
    pub operation: Operation,
}

impl Assignment {
    fn before_dispatch(&self, error: io::Error) -> DeliveryFailure {
        let mut failure = failure(&self.destination, error);
        failure.execution_may_have_run = matches!(self.operation, Operation::Continue(_));
        failure
    }

    fn check_pending(&self) -> io::Result<()> {
        if self.cancellation.is_cancelled() {
            return Err(cancelled());
        }
        if Instant::now() >= self.connection_deadline {
            return Err(connection_timeout());
        }
        Ok(())
    }
}

struct Job {
    assignment: Assignment,
    result: mpsc::SyncSender<Result<Delivery, DeliveryFailure>>,
}

struct Waiter {
    registration: Arc<()>,
    waker: Waker,
}

#[derive(Default)]
struct MailboxState {
    pending: Option<Job>,
    active: Option<OperationCancellation>,
    closed: bool,
    waiter: Option<Waiter>,
}

#[derive(Default)]
struct Mailbox {
    state: Mutex<MailboxState>,
    shutdown: OperationCancellation,
}

impl Mailbox {
    fn submit(&self, job: Job) -> io::Result<()> {
        let wake = {
            let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            if state.closed {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "remote dependency listener has stopped",
                ));
            }
            if state.pending.is_some() || state.active.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "remote dependency listener already owns an operation",
                ));
            }
            state.pending = Some(job);
            state.waiter.take()
        };
        if let Some(waiter) = wake {
            waiter.waker.wake();
        }
        Ok(())
    }

    fn take(&self) -> Option<Job> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let job = state.pending.take()?;
        state.active = Some(job.assignment.cancellation.clone());
        Some(job)
    }

    fn finished(&self) {
        self.state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .active = None;
    }

    fn is_closed(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .closed
    }

    fn pending_boundary(&self) -> Option<(OperationCancellation, Instant)> {
        self.state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .pending
            .as_ref()
            .map(|job| {
                (
                    job.assignment.cancellation.clone(),
                    job.assignment.connection_deadline,
                )
            })
    }

    fn ready(&self) -> WorkReady<'_> {
        WorkReady {
            mailbox: self,
            registration: Arc::new(()),
        }
    }

    fn close(&self) {
        let (pending, active, waiter) = {
            let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            state.closed = true;
            (
                state.pending.take(),
                state.active.take(),
                state.waiter.take(),
            )
        };
        self.shutdown.cancel();
        if let Some(active) = active {
            active.cancel();
        }
        if let Some(job) = pending {
            job.assignment.cancellation.cancel();
            let result = job.assignment.before_dispatch(cancelled());
            let _ = job.result.send(Err(result));
        }
        if let Some(waiter) = waiter {
            waiter.waker.wake();
        }
    }
}

struct WorkReady<'a> {
    mailbox: &'a Mailbox,
    registration: Arc<()>,
}

impl Future for WorkReady<'_> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let replacement = Waiter {
            registration: Arc::clone(&self.registration),
            waker: cx.waker().clone(),
        };
        let mut state = self
            .mailbox
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if state.closed || state.pending.is_some() {
            return Poll::Ready(());
        }
        let previous = state.waiter.replace(replacement);
        drop(state);
        drop(previous);
        Poll::Pending
    }
}

impl Drop for WorkReady<'_> {
    fn drop(&mut self) {
        let removed = {
            let mut state = self
                .mailbox
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if state
                .waiter
                .as_ref()
                .is_some_and(|waiter| Arc::ptr_eq(&waiter.registration, &self.registration))
            {
                state.waiter.take()
            } else {
                None
            }
        };
        drop(removed);
    }
}

/// Seals pending senders even if the thread unwinds before returning a result.
/// An active sender then disconnects; its caller must retain run uncertainty.
struct OwnerExit {
    mailbox: Arc<Mailbox>,
    readiness: Arc<Readiness>,
    changed: Arc<dyn Fn() + Send + Sync>,
}

impl Drop for OwnerExit {
    fn drop(&mut self) {
        self.readiness.close();
        self.mailbox.close();
        (self.changed)();
    }
}

pub(super) struct Listener {
    mailbox: Arc<Mailbox>,
    readiness: Arc<Readiness>,
    owner: Mutex<Option<JoinHandle<io::Result<()>>>>,
}

impl std::fmt::Debug for Listener {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Listener")
            .field("stopped", &self.mailbox.shutdown.is_cancelled())
            .finish_non_exhaustive()
    }
}

impl Listener {
    pub(super) fn start(
        address: SocketAddr,
        worker: String,
        pin: [u8; 32],
        tls: TlsFiles,
        ready: Arc<dyn Fn() + Send + Sync>,
        readiness: Arc<Readiness>,
        changed: Arc<dyn Fn() + Send + Sync>,
    ) -> io::Result<Self> {
        let mailbox = Arc::new(Mailbox::default());
        let owned_mailbox = Arc::clone(&mailbox);
        let owned_readiness = Arc::clone(&readiness);
        let (started, startup) = mpsc::sync_channel(1);
        let owner = std::thread::Builder::new()
            .name("rabs-worker-listener".into())
            .spawn(move || {
                let setup = (|| {
                    let runtime = RuntimeBuilder::current_thread().build().map_err(|error| {
                        io::Error::other(format!("remote dependency runtime: {error:?}"))
                    })?;
                    let acceptor = tls.acceptor().map_err(io::Error::other)?;
                    let listener = block_on_top_level(&runtime, TcpListener::bind(address))
                        .map_err(|error| {
                            io::Error::new(
                                error.kind(),
                                format!("remote dependency TLS listen: {error}"),
                            )
                        })?;
                    Ok::<_, io::Error>((runtime, acceptor, listener))
                })();
                let (runtime, acceptor, listener) = match setup {
                    Ok(setup) => setup,
                    Err(error) => {
                        // No listener was published and no assignment could
                        // reach this mailbox. A corrected TLS/bind setup may
                        // retry with the same transport and readiness owner.
                        owned_mailbox.close();
                        let _ = started.send(Err(error));
                        return Ok(());
                    }
                };
                let _exit = OwnerExit {
                    mailbox: Arc::clone(&owned_mailbox),
                    readiness: Arc::clone(&owned_readiness),
                    changed: Arc::clone(&changed),
                };
                if started.send(Ok(())).is_err() {
                    return Ok(());
                }
                run_owner(
                    &runtime,
                    &listener,
                    &acceptor,
                    &worker,
                    pin,
                    &owned_mailbox,
                    &*ready,
                    &owned_readiness,
                    &changed,
                )
            })?;
        match startup.recv() {
            Ok(Ok(())) => Ok(Self {
                mailbox,
                readiness,
                owner: Mutex::new(Some(owner)),
            }),
            result => {
                mailbox.close();
                let _ = owner.join();
                Err(match result {
                    Ok(Err(error)) => error,
                    _ => io::Error::other("remote dependency listener stopped during startup"),
                })
            }
        }
    }

    pub(super) fn deliver(&self, assignment: Assignment) -> Result<Delivery, DeliveryFailure> {
        let destination = assignment.destination.clone();
        let continuing = matches!(assignment.operation, Operation::Continue(_));
        let (result, completed) = mpsc::sync_channel(1);
        self.mailbox
            .submit(Job { assignment, result })
            .map_err(|error| {
                let mut failure = failure(&destination, error);
                failure.execution_may_have_run = continuing;
                failure
            })?;
        // Cancellation is intent only. Wait for the owner to finish the real
        // protocol/drain; returning early would release a still-running slot.
        completed.recv().unwrap_or_else(|_| {
            let mut failure = failure(
                &destination,
                io::Error::other("remote dependency owner lost an accepted operation"),
            );
            failure.execution_may_have_run = true;
            Err(failure)
        })
    }

    pub(super) fn shutdown(&self) -> io::Result<()> {
        self.readiness.close();
        self.mailbox.close();
        // Hold the join lock through completion. Concurrent shutdown callers
        // must never observe success while another caller still drains it.
        let mut owner = self.owner.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(owner) = owner.take() {
            owner
                .join()
                .map_err(|_| io::Error::other("remote dependency listener owner panicked"))??;
        }
        Ok(())
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

enum Arrival {
    Work,
    Peer(Box<StandbyPeer>),
    Rejected,
}

async fn yield_to_owner() {
    let mut yielded = false;
    poll_fn(|cx| {
        if yielded {
            Poll::Ready(())
        } else {
            yielded = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    })
    .await;
}

async fn accept_connection(listener: &TcpListener) -> io::Result<(TcpStream, SocketAddr)> {
    loop {
        match listener.accept().await {
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted
                        | io::ErrorKind::ConnectionAborted
                        | io::ErrorKind::ConnectionReset
                ) =>
            {
                // A queued client disappearing must not retire the persistent
                // listener. Yield so work, cancellation and deadlines still win.
                yield_to_owner().await;
            }
            result => return result,
        }
    }
}

async fn authenticate(
    acceptor: &TlsAcceptor,
    stream: TcpStream,
    worker: &str,
    pin: [u8; 32],
) -> io::Result<StandbyPeer> {
    // The TLS boundary reports authentication failure as text. Do not infer
    // retry/run authority from those diagnostics; no request was sent here.
    let peer = accept_peer(acceptor, stream)
        .await
        .map_err(io::Error::other)?;
    prepare_standby(peer, worker, pin).await
}

/// Preserve an already-started idle exchange when work arrives, while making
/// the queued operation's cancellation and original deadline observable. It
/// remains pending until the synchronous owner takes it, so interrupted idle
/// authentication never becomes execution uncertainty or an admitted session.
async fn within_pending_boundary<T>(
    mailbox: &Mailbox,
    future: impl Future<Output = io::Result<T>>,
) -> io::Result<T> {
    until_cancelled(&mailbox.shutdown, async {
        let mut future = pin!(future);
        let completed = {
            let mut work = pin!(mailbox.ready());
            poll_fn(|cx| {
                if work.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(None);
                }
                future.as_mut().poll(cx).map(Some)
            })
            .await
        };
        if let Some(completed) = completed {
            return completed;
        }
        let Some((cancellation, deadline)) = mailbox.pending_boundary() else {
            return Err(cancelled());
        };
        until_cancelled(&cancellation, async {
            let budget = deadline
                .checked_duration_since(Instant::now())
                .filter(|remaining| !remaining.is_zero())
                .ok_or_else(connection_timeout)?;
            asupersync::time::timeout(asupersync::time::wall_now(), budget, future.as_mut())
                .await
                .map_err(|_| connection_timeout())?
        })
        .await
    })
    .await
}

async fn idle_arrival(
    listener: &TcpListener,
    acceptor: &TlsAcceptor,
    worker: &str,
    pin: [u8; 32],
    mailbox: &Mailbox,
) -> io::Result<Arrival> {
    until_cancelled(&mailbox.shutdown, async {
        let stream = {
            let mut work = pin!(mailbox.ready());
            let mut accepting = pin!(accept_connection(listener));
            poll_fn(|cx| {
                if work.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(Ok(None));
                }
                accepting
                    .as_mut()
                    .poll(cx)
                    .map(|result| result.map(|(stream, _)| Some(stream)))
            })
            .await?
        };
        let Some(stream) = stream else {
            return Ok(Arrival::Work);
        };
        // Work arrival preserves the accepted socket. Only its cancellation,
        // original connection deadline or a failed handshake may close it.
        Ok(
            match within_pending_boundary(mailbox, authenticate(acceptor, stream, worker, pin))
                .await
            {
                Ok(peer) => Arrival::Peer(Box::new(peer)),
                Err(_) => Arrival::Rejected,
            },
        )
    })
    .await
}

fn connection_timeout() -> io::Error {
    worker_transport_error(io::Error::new(
        io::ErrorKind::TimedOut,
        "remote dependency worker connection deadline exceeded",
    ))
}

async fn connect_assigned(
    listener: &TcpListener,
    acceptor: &TlsAcceptor,
    worker: &str,
    pin: [u8; 32],
    assignment: &Assignment,
    shutdown: &OperationCancellation,
) -> io::Result<StandbyPeer> {
    assignment.check_pending()?;
    let budget = assignment
        .connection_deadline
        .saturating_duration_since(Instant::now());
    until_cancelled(
        shutdown,
        until_cancelled(&assignment.cancellation, async {
            asupersync::time::timeout(asupersync::time::wall_now(), budget, async {
                loop {
                    let (stream, _) = accept_connection(listener)
                        .await
                        .map_err(worker_transport_error)?;
                    if let Ok(peer) = authenticate(acceptor, stream, worker, pin).await {
                        return Ok(peer);
                    }
                    // Even a flood of immediately rejected peers yields to the
                    // original connection deadline and cancellation wakeups.
                    yield_to_owner().await;
                }
            })
            .await
            .map_err(|_| connection_timeout())?
        }),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
fn deliver_assigned(
    runtime: &Runtime,
    listener: &TcpListener,
    acceptor: &TlsAcceptor,
    worker: &str,
    pin: [u8; 32],
    assignment: Assignment,
    shutdown: &OperationCancellation,
    parked: &mut Option<ParkedPeer>,
) -> Result<Delivery, DeliveryFailure> {
    assignment
        .check_pending()
        .map_err(|error| assignment.before_dispatch(error))?;
    let peer = if let Some(parked) = parked.take() {
        // Revocation happens before this connection leaves idle custody. A
        // reservation may race disconnect, but cannot retain readiness for a
        // handed-off connection or silently reuse it for another operation.
        parked.into_peer()
    } else {
        block_on_top_level(
            runtime,
            connect_assigned(listener, acceptor, worker, pin, &assignment, shutdown),
        )
        .map_err(|error| assignment.before_dispatch(error))?
    };
    assignment
        .check_pending()
        .map_err(|error| assignment.before_dispatch(error))?;
    if peer.supported() {
        eprintln!(
            "{}",
            json!({
                "kind":"rabsd-worker-standby-dispatch", "worker":worker,
                "request_id":assignment.request["request_id"],
                "completed_heartbeats":peer.completed_heartbeats(),
            })
        );
    }
    let (upload, admitted, continuation) = match assignment.operation {
        Operation::Execute {
            upload,
            on_admitted,
        } => (Some(upload), Some(on_admitted), None),
        Operation::Continue(sealed) => (None, None, Some(*sealed)),
    };
    receive_standby_with_admission(
        runtime,
        peer,
        assignment.admission,
        &assignment.request,
        &assignment.destination,
        upload.as_deref(),
        assignment.cancellation,
        admitted,
        continuation,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_owner(
    runtime: &Runtime,
    listener: &TcpListener,
    acceptor: &TlsAcceptor,
    worker: &str,
    pin: [u8; 32],
    mailbox: &Mailbox,
    ready: &dyn Fn(),
    readiness: &Arc<Readiness>,
    changed: &Arc<dyn Fn() + Send + Sync>,
) -> io::Result<()> {
    let mut parked: Option<ParkedPeer> = None;
    while !mailbox.is_closed() {
        if let Some(Job { assignment, result }) = mailbox.take() {
            let delivery = deliver_assigned(
                runtime,
                listener,
                acceptor,
                worker,
                pin,
                assignment,
                &mailbox.shutdown,
                &mut parked,
            );
            mailbox.finished();
            let _ = result.send(delivery);
            continue;
        }
        if let Some(parked_peer) = parked.as_mut() {
            let peer = &mut parked_peer.peer;
            // Old workers can be used for an already waiting request, but an
            // absent optional protocol cannot justify keeping them idle.
            if !peer.supported()
                || block_on_top_level(
                    runtime,
                    within_pending_boundary(
                        mailbox,
                        peer.wait_for_work(mailbox.ready(), mailbox.shutdown.clone()),
                    ),
                )
                .is_err()
            {
                parked = None;
            }
            continue;
        }
        match block_on_top_level(
            runtime,
            idle_arrival(listener, acceptor, worker, pin, mailbox),
        ) {
            Ok(Arrival::Peer(peer)) => {
                let peer = match ParkedPeer::new(*peer, readiness, changed) {
                    Ok(peer) => peer,
                    // Shutdown revokes readiness before closing the mailbox.
                    // An already-completed handshake in that narrow window
                    // must drain normally, not turn shutdown into an error.
                    Err(error)
                        if error.kind() == io::ErrorKind::Interrupted && readiness.is_closed() =>
                    {
                        break;
                    }
                    Err(error) => return Err(error),
                };
                if let Some(advertisement) = &peer.advertisement {
                    ready();
                    eprintln!(
                        "{}",
                        json!({
                            "kind":"rabsd-worker-standby-ready", "worker":worker,
                            "connection_generation":advertisement.generation,
                        })
                    );
                }
                parked = Some(peer);
            }
            Ok(Arrival::Work | Arrival::Rejected) => {}
            Err(_) if mailbox.is_closed() => break,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rabs_sandbox::snapshot_capture::capture_sealed_source;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::task::Wake;
    use std::time::Duration;

    #[test]
    fn readiness_revocation_is_connection_specific_and_notifies_after_releasing_its_lock() {
        let readiness = Arc::new(Readiness::default());
        let notifications = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&readiness);
        let counted = Arc::clone(&notifications);
        let changed: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
            assert!(observed.snapshot().is_none());
            counted.fetch_add(1, Ordering::Relaxed);
        });
        let earlier = readiness
            .publish(&json!({"incarnation":"earlier"}), Arc::clone(&changed))
            .unwrap();
        let old_snapshot = readiness.snapshot().unwrap();
        let current = readiness
            .publish(&json!({"incarnation":"current"}), changed)
            .unwrap();
        let generation = readiness.snapshot().unwrap().generation;
        assert!(generation > old_snapshot.generation);
        drop(earlier);
        assert!(readiness.is_current(generation));
        assert!(!readiness.is_current(old_snapshot.generation));
        assert_eq!(notifications.load(Ordering::Relaxed), 0);
        drop(current);
        assert!(readiness.snapshot().is_none());
        assert_eq!(notifications.load(Ordering::Relaxed), 1);
        // A cloned observation survives as data only, never as current
        // readiness or a way to resurrect the ended authenticated transport.
        assert!(!readiness.is_current(old_snapshot.generation));
    }

    #[test]
    fn closing_readiness_revokes_the_peer_and_refuses_republication() {
        let readiness = Arc::new(Readiness::default());
        let owner = readiness.publish_for_test(&json!({"incarnation":"worker"}));
        let snapshot = readiness.snapshot().unwrap();
        readiness.close();
        assert!(!readiness.is_current(snapshot.generation));
        assert!(readiness.snapshot().is_none());
        assert_eq!(
            readiness
                .publish(&json!({}), Arc::new(|| {}))
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::Interrupted
        );
        drop(owner);
        assert!(readiness.snapshot().is_none());
    }

    #[test]
    fn owner_exit_revokes_readiness_before_announcing_shutdown() {
        let readiness = Arc::new(Readiness::default());
        let advertisement = readiness.publish_for_test(&json!({"incarnation":"worker"}));
        let mailbox = Arc::new(Mailbox::default());
        let observed_readiness = Arc::clone(&readiness);
        let observed_mailbox = Arc::clone(&mailbox);
        let notified = Arc::new(AtomicBool::new(false));
        let notification = Arc::clone(&notified);
        let owner = OwnerExit {
            mailbox,
            readiness,
            changed: Arc::new(move || {
                assert!(observed_readiness.snapshot().is_none());
                assert!(observed_mailbox.is_closed());
                notification.store(true, Ordering::Release);
            }),
        };
        drop(owner);
        assert!(notified.load(Ordering::Acquire));
        drop(advertisement);
    }

    fn assignment() -> (tempfile::TempDir, Assignment) {
        let state = crate::test_util::private_tempdir();
        let source = state.path().join("source");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("lib.rs"), b"pub fn unit() {}\n").unwrap();
        let snapshot = Arc::new(
            capture_sealed_source(&[("workspace".into(), source)], false, 1, 4096).unwrap(),
        );
        let upload =
            SourceUpload::from_snapshot(snapshot, "workspace", &["lib.rs".into()]).unwrap();
        let assignment = Assignment {
            admission: PinnedWorkerAdmission::open(
                &state.path().join("admission"),
                "worker",
                [1; 32],
            )
            .unwrap(),
            request: json!({"request_id":1}),
            destination: state.path().join("delivery"),
            cancellation: OperationCancellation::new(),
            connection_deadline: Instant::now() + Duration::from_secs(60),
            operation: Operation::Execute {
                upload: Box::new(upload),
                on_admitted: Box::new(|_| panic!("mailbox tests must never admit execution")),
            },
        };
        (state, assignment)
    }

    struct Notify {
        mailbox: Arc<Mailbox>,
        wake: mpsc::Sender<()>,
    }

    impl Wake for Notify {
        fn wake(self: Arc<Self>) {
            assert!(
                self.mailbox.state.try_lock().is_ok(),
                "the reactor must be woken outside the mailbox lock"
            );
            let _ = self.wake.send(());
        }
    }

    fn wake_channel(mailbox: &Arc<Mailbox>) -> (Waker, mpsc::Receiver<()>) {
        let (wake, notified) = mpsc::channel();
        (
            Waker::from(Arc::new(Notify {
                mailbox: Arc::clone(mailbox),
                wake,
            })),
            notified,
        )
    }

    #[test]
    fn bounded_mailbox_wakes_idle_owner_and_closes_pending_work_before_dispatch() {
        let mailbox = Arc::new(Mailbox::default());
        let (waker, notified) = wake_channel(&mailbox);
        let mut waiting = Box::pin(mailbox.ready());
        assert!(
            waiting
                .as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
        let (_state, assignment) = assignment();
        let cancellation = assignment.cancellation.clone();
        let (result, completed) = mpsc::sync_channel(1);
        mailbox.submit(Job { assignment, result }).unwrap();
        notified.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(
            waiting
                .as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_ready()
        );
        let (_second_state, second) = self::assignment();
        let (result, rejected) = mpsc::sync_channel(1);
        assert_eq!(
            mailbox
                .submit(Job {
                    assignment: second,
                    result,
                })
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        assert!(matches!(
            rejected.try_recv(),
            Err(mpsc::TryRecvError::Disconnected)
        ));
        mailbox.close();
        let failure = completed
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap_err();
        assert!(!failure.execution_may_have_run);
        assert!(!failure.transport_interrupted);
        assert!(cancellation.is_cancelled());
        assert!(mailbox.take().is_none());
    }

    #[test]
    fn dropping_idle_wait_unregisters_reactor_and_shutdown_remains_sticky() {
        let mailbox = Arc::new(Mailbox::default());
        let (waker, notified) = wake_channel(&mailbox);
        let mut waiting = Box::pin(mailbox.ready());
        assert!(
            waiting
                .as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
        drop(waiting);
        assert!(mailbox.state.lock().unwrap().waiter.is_none());
        mailbox.close();
        assert!(matches!(
            notified.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        let mut late = Box::pin(mailbox.ready());
        assert!(
            late.as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_ready()
        );
        let (_state, assignment) = assignment();
        let (result, _) = mpsc::sync_channel(1);
        assert_eq!(
            mailbox
                .submit(Job { assignment, result })
                .unwrap_err()
                .kind(),
            io::ErrorKind::BrokenPipe
        );
    }

    #[test]
    fn accepted_owner_loss_preserves_uncertainty_and_cancellation_does_not_return_early() {
        // Exercise ownership/result channels, not a substitute TLS execution.
        let mailbox = Arc::new(Mailbox::default());
        let listener = Arc::new(Listener {
            mailbox: Arc::clone(&mailbox),
            readiness: Arc::new(Readiness::default()),
            owner: Mutex::new(None),
        });
        let (waker, notified) = wake_channel(&mailbox);
        let mut waiting = Box::pin(mailbox.ready());
        assert!(
            waiting
                .as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
        let (_state, assignment) = assignment();
        let cancellation = assignment.cancellation.clone();
        let (result, completed) = mpsc::channel();
        let caller = {
            let listener = Arc::clone(&listener);
            std::thread::spawn(move || result.send(listener.deliver(assignment)).unwrap())
        };
        notified.recv_timeout(Duration::from_secs(2)).unwrap();
        let accepted = mailbox.take().unwrap();
        mailbox.close();
        assert!(cancellation.is_cancelled());
        assert!(matches!(
            completed.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        // The owner disappearing after accepting a job cannot prove execution
        // stopped, even though this particular channel test never sends work.
        drop(accepted);
        let failure = completed
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap_err();
        assert!(failure.execution_may_have_run);
        assert!(!failure.transport_interrupted);
        caller.join().unwrap();
    }

    struct ExchangeDrop(Arc<AtomicBool>);

    impl Drop for ExchangeDrop {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    #[test]
    fn work_arrival_preserves_idle_exchange_but_pending_cancellation_interrupts_it() {
        // This tests the real reactor wake/deadline composition, with a held
        // future in place of network I/O. Native TLS/Cargo proof is separate.
        let runtime = RuntimeBuilder::current_thread().build().unwrap();
        let mailbox = Arc::new(Mailbox::default());
        let (_state, assignment) = assignment();
        let cancellation = assignment.cancellation.clone();
        let (result, completed) = mpsc::sync_channel(1);
        let (starting, started) = mpsc::channel();
        let (progress, progressed) = mpsc::channel();
        let submitted = Arc::new(AtomicBool::new(false));
        let dropped = Arc::new(AtomicBool::new(false));
        let producer = {
            let mailbox = Arc::clone(&mailbox);
            let submitted = Arc::clone(&submitted);
            let dropped = Arc::clone(&dropped);
            std::thread::spawn(move || {
                started.recv_timeout(Duration::from_secs(2)).unwrap();
                submitted.store(true, Ordering::Release);
                mailbox.submit(Job { assignment, result }).unwrap();
                progressed.recv_timeout(Duration::from_secs(2)).unwrap();
                assert!(!dropped.load(Ordering::Acquire));
                cancellation.cancel();
            })
        };
        let mut starting = Some(starting);
        let mut progress = Some(progress);
        let exchange = async {
            let _drop = ExchangeDrop(Arc::clone(&dropped));
            poll_fn(|_| {
                if let Some(starting) = starting.take() {
                    starting.send(()).unwrap();
                }
                if submitted.load(Ordering::Acquire)
                    && let Some(progress) = progress.take()
                {
                    progress.send(()).unwrap();
                }
                Poll::<io::Result<()>>::Pending
            })
            .await
        };
        let interrupted = block_on_top_level(
            &runtime,
            asupersync::time::timeout(
                asupersync::time::wall_now(),
                Duration::from_secs(3),
                within_pending_boundary(&mailbox, exchange),
            ),
        )
        .unwrap()
        .unwrap_err();
        assert_eq!(interrupted.kind(), io::ErrorKind::Interrupted);
        producer.join().unwrap();
        assert!(dropped.load(Ordering::Acquire));
        mailbox.close();
        let failure = completed.recv().unwrap().unwrap_err();
        assert!(!failure.execution_may_have_run);
        assert!(!failure.transport_interrupted);
    }

    #[test]
    fn pending_idle_exchange_keeps_original_connection_deadline() {
        let runtime = RuntimeBuilder::current_thread().build().unwrap();
        let mailbox = Mailbox::default();
        let (_state, mut assignment) = assignment();
        assignment.connection_deadline = Instant::now() + Duration::from_millis(20);
        let (result, completed) = mpsc::sync_channel(1);
        mailbox.submit(Job { assignment, result }).unwrap();
        let error = block_on_top_level(
            &runtime,
            within_pending_boundary(&mailbox, std::future::pending::<io::Result<()>>()),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(crate::coord::worker_delivery::transport_interrupted(&error));
        let pending = mailbox.take().unwrap();
        let error = pending.assignment.check_pending().unwrap_err();
        pending
            .result
            .send(Err(pending.assignment.before_dispatch(error)))
            .unwrap();
        mailbox.finished();
        let failure = completed.recv().unwrap().unwrap_err();
        assert!(!failure.execution_may_have_run);
        assert!(failure.transport_interrupted);
    }
}
