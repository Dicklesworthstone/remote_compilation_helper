//! The edge UDS server (bead S3 / bridge plan Phase S). Runs INSIDE the
//! S1 edge region as its [`SubsystemWork`]: every wrapper consult flows
//! through the REAL modules — `socket_admission` per connection,
//! `version_negotiation` per handshake — with bounded region-owned sessions.
//!
//! Slow peers have absolute frame-read/write budgets, and each connection has
//! a bounded request count. Shadow disk work and artifact materialization use
//! separate bounded blocking lanes, not the native control reactor. Cancellation
//! joins an admitted writer rather than detaching work that can still mutate a
//! subscriber's outputs. Filesystem shutdown itself is not claimed interruptible.
//!
//! Wire format: newline-delimited JSON, one request per line, 64 KiB bound.
//! Malformed input never grants execution, publication, or fallback authority.
//!
//! Endpoint ownership spans the listener AND every admitted session. A
//! permanent endpoint lock, private namespace and exact socket generation
//! fence takeover and teardown independently of the configured CAS root.
//! Only an unchanged socket whose bounded connect was refused is retired;
//! timeout, permissions, wrong type and replacement never prove death.

mod backpressure;
mod endpoint;
mod frame_read;
mod liveness;
mod metadata_delivery;
mod remote_dependency;
mod rustc_outputs;
mod rustc_request;

use asupersync::cx::Cx;
use asupersync::io::{AsyncWriteExt, BufReader};
#[cfg(test)]
use asupersync::net::unix::UnixListener;
use asupersync::net::unix::UnixStream;
use asupersync::signal::ShutdownReceiver;
use liveness::{Limit, WorkError};
use rabs_asupersync::daemon_runtime::SubsystemWork;
use rabs_protocol::socket_admission::{
    AdmissionPolicy, ConnectionEvidence, PeerCredentials, SocketMetadata, TokenContext, admit,
};
use rabs_protocol::version_negotiation::{Negotiation, VersionHello, VersionRange, negotiate};
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

/// Frame size bound (one JSON line).
pub const MAX_FRAME_BYTES: usize = 64 * 1024;
/// Bounds are per edge listener, shared by all of its connections.
pub const MAX_CONNECTIONS: usize = 128;
pub const MAX_REQUESTS_PER_CONNECTION: usize = 64;
const FRAME_IO_BUDGET: Duration = Duration::from_secs(5);
/// One buffer survives every phase, including completion and capture ACK.
/// The connection cap bounds total read-ahead storage to 2 MiB per listener.
const FRAME_READ_BUFFER_BYTES: usize = 16 * 1024;
type EdgeStream = BufReader<UnixStream>;
const CONTROL_WORKERS: usize = 2;
const SHADOW_WORKERS: usize = 4;
/// Artifact installs, including accepted live hits. Reserve before asking a
/// subscriber to wait, so fresh decisions cannot steal its installation slot.
/// Initial consent retains capacity without a thread. A negotiated metadata
/// prefix uses one finite ACK on the already-owned installer thread; control
/// work and all metadata-store locks remain independent of that wait.
const MATERIALIZATION_WORKERS: usize = 2;
const PREPARED_ADMISSION_WORKERS: usize = 2;
/// Live dependency decisions: a compiler is waiting on each. Saturation
/// before a decision may carry a bounded wrapper retry hint; no work is queued
/// or capacity retained while that wrapper backs off.
const LIVE_DECISION_WORKERS: usize = 8;
/// Live dependency completions (capture, durable uploads, publication).
/// Wrappers retain their outputs until capture is acknowledged, but do not
/// wait for publication. Keep this lane separate from decisions; no worker
/// permit is held while awaiting the subscriber's acknowledgment.
const LIVE_COMPLETION_WORKERS: usize = 8;
/// How long an admitted local execution may run before its completion
/// frame must arrive (the attempt lease is longer still).
const LOCAL_EXECUTION_BUDGET: Duration = Duration::from_secs(2 * 60 * 60);

#[derive(Clone)]
struct EdgeLimits {
    sessions: Limit,
    control: Limit,
    shadow: Limit,
    materialization: Limit,
    prepared_admission: Limit,
    live: Limit,
    live_completion: Limit,
    remote_execution: Limit,
}
impl EdgeLimits {
    fn new(remote_workers: usize) -> Self {
        Self {
            sessions: Limit::new(MAX_CONNECTIONS),
            control: Limit::new(CONTROL_WORKERS),
            shadow: Limit::new(SHADOW_WORKERS),
            materialization: Limit::new(MATERIALIZATION_WORKERS),
            prepared_admission: Limit::new(PREPARED_ADMISSION_WORKERS),
            live: Limit::new(LIVE_DECISION_WORKERS),
            live_completion: Limit::new(LIVE_COMPLETION_WORKERS),
            // One owned execution lane per configured worker. Long compiler
            // and transfer waits never occupy decisions or cache-hit installs.
            remote_execution: Limit::new(
                remote_workers.min(crate::coord::live_dependency::remote::MAX_DEPENDENCY_WORKERS),
            ),
        }
    }
}

#[derive(Clone)]
struct EdgeServices {
    shadow: std::sync::Arc<std::sync::Mutex<crate::edge::shadow::ShadowPlane>>,
    coord: crate::coord::live::EdgeSubscriber,
    prepared_operations:
        Option<std::sync::Arc<crate::coord::prepared_operation::PreparedOperationStore>>,
    live: Option<std::sync::Arc<rustc_request::LiveEdge>>,
    /// A prepared canonical Cargo operation can consult only its rustc lane.
    /// It never receives the normal daemon's status, prepared-job, or generic
    /// cache-serving capabilities.
    canonical_only: bool,
    canonical_activity: Option<Arc<CanonicalActivity>>,
}

/// Completion barrier for one prepared canonical Cargo operation. Cargo can
/// exit after its wrapper acknowledges captured outputs but before the edge
/// publishes them. Keep the coordinator alive until those sessions finish.
/// Admission is sealed only after Cargo's entire process group has stopped.
#[derive(Debug)]
pub(crate) struct CanonicalActivity {
    state: Mutex<CanonicalActivityState>,
    changed: Condvar,
}

#[derive(Debug)]
struct CanonicalActivityState {
    accepting: bool,
    active: usize,
}

impl CanonicalActivity {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(CanonicalActivityState {
                accepting: true,
                active: 0,
            }),
            changed: Condvar::new(),
        })
    }

    fn admit(self: &Arc<Self>) -> Option<CanonicalSession> {
        let mut state = self.state.lock().ok()?;
        if !state.accepting {
            return None;
        }
        state.active = state.active.checked_add(1)?;
        Some(CanonicalSession(Arc::clone(self)))
    }

    /// Seal before testing the counter: an accepted-but-not-yet-counted socket
    /// must be refused before hello or request handling rather than racing a
    /// transient zero. A live wrapper that already received a capture receipt
    /// necessarily owns a counted session, including a queued final ACK.
    pub(crate) fn seal_and_wait(
        &self,
        budget: Duration,
        stopped: impl Fn() -> bool,
    ) -> Result<(), String> {
        let deadline = std::time::Instant::now()
            .checked_add(budget)
            .ok_or("canonical publication drain deadline overflow")?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| "canonical activity lock poisoned")?;
        state.accepting = false;
        loop {
            if stopped() {
                return Err("canonical coordinator stopped before publication drain".into());
            }
            if state.active == 0 {
                return Ok(());
            }
            let now = std::time::Instant::now();
            if now >= deadline {
                return Err(format!(
                    "canonical publication drain timed out with {} active sessions",
                    state.active
                ));
            }
            let wait = deadline.duration_since(now).min(Duration::from_millis(50));
            (state, _) = self
                .changed
                .wait_timeout(state, wait)
                .map_err(|_| "canonical activity lock poisoned during drain")?;
        }
    }

    #[cfg(test)]
    pub(crate) fn active_sessions(&self) -> usize {
        self.state.lock().unwrap().active
    }
}

struct CanonicalSession(Arc<CanonicalActivity>);
impl Drop for CanonicalSession {
    fn drop(&mut self) {
        let mut state = self
            .0
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.active = state.active.saturating_sub(1);
        self.0.changed.notify_all();
    }
}

#[cfg(test)]
mod canonical_activity_tests {
    use super::*;

    #[test]
    fn sealing_covers_admitted_sessions_and_refuses_late_registration() {
        let activity = CanonicalActivity::new();
        let session = activity.admit().unwrap();
        assert_eq!(activity.active_sessions(), 1);
        // A zero budget is a deterministic deadline, not a sleep-based claim
        // that a captured-but-unpublished session has finished.
        let error = activity
            .seal_and_wait(Duration::ZERO, || false)
            .unwrap_err();
        assert!(error.contains("1 active sessions"), "{error}");
        assert!(
            activity.admit().is_none(),
            "late accepted sockets must not gain authority"
        );
        assert_eq!(activity.active_sessions(), 1);
        drop(session);
        assert!(activity.seal_and_wait(Duration::ZERO, || false).is_ok());
    }
}

/// The daemon's own hello (transport v1..=1, application v1..=1).
#[must_use]
pub fn our_hello() -> VersionHello {
    VersionHello {
        transport: VersionRange {
            minimum_compatible: 1,
            current: 1,
        },
        application: VersionRange {
            minimum_compatible: 1,
            current: 1,
        },
    }
}

/// Edge server configuration.
#[derive(Debug, Clone)]
pub struct EdgeServerConfig {
    /// Socket path.
    pub socket_path: PathBuf,
    /// Shadow-plane state directory (index + receipts).
    pub state_dir: PathBuf,
    /// Restricted subscriber capability; never a lease/publication owner.
    pub coord: crate::coord::live::EdgeSubscriber,
    /// Execution-only prepared jobs. No action-cache publication capability.
    pub prepared_operations:
        Option<std::sync::Arc<crate::coord::prepared_operation::PreparedOperationStore>>,
    /// The live registry/Git dependency lane (opt-in). `None` keeps every
    /// `rustc-request` in shadow mode.
    pub live_dependency: Option<crate::coord::live_dependency::LiveDependencyLane>,
}

/// One NDJSON event on stderr. Values are JSON-encoded, so a reason that
/// quotes a path or an OS error with backslashes or newlines stays one
/// parseable line instead of silently dropping out of the decision trail.
pub(crate) fn log_line(kind: &str, fields: &[(&str, &str)]) {
    eprintln!("{}", render_log_line(kind, fields));
}

/// Field order is preserved (a `Map` would sort it) for human readers.
fn render_log_line(kind: &str, fields: &[(&str, &str)]) -> String {
    let mut line = format!("{{\"v\":1,\"kind\":{}", serde_json::Value::from(kind));
    for (key, value) in fields {
        line.push_str(&format!(
            ",{}:{}",
            serde_json::Value::from(*key),
            serde_json::Value::from(*value)
        ));
    }
    line.push('}');
    line
}

/// Build the edge [`SubsystemWork`] for [`DaemonRunOptions`].
///
/// [`DaemonRunOptions`]: rabs_asupersync::daemon_runtime::DaemonRunOptions
pub fn edge_work(config: EdgeServerConfig) -> SubsystemWork {
    Box::new(move |cx, shutdown| Box::pin(serve(cx, shutdown, config, None)))
}

/// A build-scoped endpoint for a coordinator-owned canonical Cargo driver.
/// The retained path capability is constructed only after source/toolchain
/// capture and graph admission; request JSON cannot create or replace it.
pub(crate) fn canonical_edge_work(
    config: EdgeServerConfig,
    paths: std::sync::Arc<crate::coord::live_dependency::canonical::CanonicalPaths>,
    activity: Arc<CanonicalActivity>,
) -> SubsystemWork {
    let binding = CanonicalBinding {
        paths,
        activity,
        remote: CanonicalRemote::FromEnvironment,
    };
    Box::new(move |cx, shutdown| Box::pin(serve(cx, shutdown, config, Some(binding))))
}

/// Bind one canonical operation to the persistent service's immutable worker
/// pool. `None` is an explicit local-only choice made by that service, never a
/// request to read process environment again when this endpoint starts.
/// Sharing the exact pool preserves pending-action claims, worker occupancy,
/// cooldown and durable admission ownership across simultaneous operations.
pub(crate) fn canonical_edge_work_shared(
    config: EdgeServerConfig,
    paths: Arc<crate::coord::live_dependency::canonical::CanonicalPaths>,
    activity: Arc<CanonicalActivity>,
    remote: Option<Arc<crate::coord::live_dependency::remote::RemoteDependencies>>,
    executions: Option<Arc<crate::coord::live_dependency::remote::SharedRemoteExecutions>>,
) -> SubsystemWork {
    let binding = CanonicalBinding {
        paths,
        activity,
        remote: CanonicalRemote::Shared { remote, executions },
    };
    Box::new(move |cx, shutdown| Box::pin(serve(cx, shutdown, config, Some(binding))))
}

enum CanonicalRemote {
    FromEnvironment,
    Shared {
        remote: Option<Arc<crate::coord::live_dependency::remote::RemoteDependencies>>,
        executions: Option<Arc<crate::coord::live_dependency::remote::SharedRemoteExecutions>>,
    },
}

struct CanonicalBinding {
    paths: Arc<crate::coord::live_dependency::canonical::CanonicalPaths>,
    activity: Arc<CanonicalActivity>,
    remote: CanonicalRemote,
}

impl CanonicalBinding {
    fn live_edge(
        &self,
        lane: crate::coord::live_dependency::LiveDependencyLane,
        state: &std::path::Path,
    ) -> Result<rustc_request::LiveEdge, String> {
        match &self.remote {
            CanonicalRemote::FromEnvironment => {
                rustc_request::LiveEdge::canonical_configured(lane, Arc::clone(&self.paths), state)
            }
            CanonicalRemote::Shared { remote, executions } => {
                Ok(rustc_request::LiveEdge::canonical_shared(
                    lane,
                    Arc::clone(&self.paths),
                    remote.clone(),
                    executions.clone(),
                ))
            }
        }
    }
}

async fn serve(
    cx: Cx,
    mut shutdown: ShutdownReceiver,
    config: EdgeServerConfig,
    canonical: Option<CanonicalBinding>,
) -> Result<(), String> {
    let listener = endpoint::bind(&config.socket_path, FRAME_IO_BUDGET).await?;
    // The endpoint owner just checked the exact bound inode, kernel UID and
    // mode. Socket metadata never chooses a different user's admission policy.
    let expected_uid = listener.owner_uid();
    let policy = AdmissionPolicy {
        expected_uid,
        require_token_on_unix: false,
        tcp_enabled: false,
    };
    let socket_evidence = SocketMetadata {
        owner_uid: expected_uid,
        mode: 0o600,
    };
    log_line(
        "rabsd-edge-listening",
        &[("socket", &config.socket_path.display().to_string())],
    );

    // The shadow decision plane (S4): persisted index + receipts.
    let shadow = std::sync::Arc::new(std::sync::Mutex::new(
        crate::edge::shadow::ShadowPlane::open(&config.state_dir)
            .map_err(|e| format!("shadow plane open: {e}"))?,
    ));

    // Acceptor and connections remain region-owned. Each admitted blocking
    // operation also owns a join guard; abort cannot leave a detached writer.
    let acceptor_cx = cx.clone();
    let canonical_only = canonical.is_some();
    let services = EdgeServices {
        shadow,
        coord: config.coord.clone(),
        prepared_operations: config.prepared_operations.clone(),
        live: config
            .live_dependency
            .clone()
            .map(|lane| {
                match &canonical {
                    Some(binding) => binding.live_edge(lane, &config.state_dir),
                    None => rustc_request::LiveEdge::configured(lane, &config.state_dir),
                }
                .map(std::sync::Arc::new)
            })
            .transpose()?,
        canonical_only,
        canonical_activity: canonical
            .as_ref()
            .map(|binding| Arc::clone(&binding.activity)),
    };
    let limits = EdgeLimits::new(
        services
            .live
            .as_ref()
            .map_or(0, |live| live.remote_worker_count()),
    );
    let acceptor = cx
        .spawn(move |cx| accept_loop(cx, listener, policy, socket_evidence, services, limits))
        .map_err(|e| format!("acceptor spawn: {e:?}"))?;
    let _ = acceptor_cx.checkpoint();

    shutdown.wait().await;
    acceptor.abort();
    // The acceptor and its admitted sessions retain endpoint ownership.
    // Their final drop, after joined writers return, retires only the exact
    // bound generation. Never unlink here while a session may still own work.
    Ok(())
}

async fn accept_loop(
    cx: Cx,
    listener: endpoint::ListenerOwner,
    policy: AdmissionPolicy,
    socket_evidence: SocketMetadata,
    services: EdgeServices,
    limits: EdgeLimits,
) {
    let mut connection_id: u64 = 0;
    loop {
        match listener.listener.accept().await {
            Ok((stream, _addr)) => {
                // Refuse before task allocation. Do not attempt a potentially
                // blocking refusal write to a peer we have not admitted.
                let Some(permit) = limits.sessions.acquire() else {
                    log_line("rabsd-edge-capacity-refused", &[]);
                    drop(stream);
                    continue;
                };
                let Some(id) = connection_id.checked_add(1) else {
                    log_line("rabsd-edge-identity-exhausted", &[]);
                    return;
                };
                connection_id = id;
                let session = if let Some(activity) = &services.canonical_activity {
                    let Some(session) = activity.admit() else {
                        drop(stream);
                        continue;
                    };
                    Some(session)
                } else {
                    None
                };
                let services = services.clone();
                let limits = limits.clone();
                let endpoint_owner = std::sync::Arc::clone(&listener.owner);
                let spawned = cx.spawn(move |cx| async move {
                    // This guard is captured BEFORE spawn and outlives the
                    // complete connection future, including joined publication
                    // work on cancellation. No zero-counter scheduling gap.
                    let _canonical_session = session;
                    // Outlives handle_connection, including cancellation that
                    // drops its joined blocking-work owners. A replacement
                    // daemon cannot acquire this endpoint during that cleanup.
                    let _endpoint_owner = endpoint_owner;
                    if cx.checkpoint().is_ok() {
                        handle_connection(id, stream, policy, socket_evidence, services, limits)
                            .await;
                    }
                    drop(permit);
                });
                match spawned {
                    // Dropping the handle detaches WITHOUT aborting
                    // (abort-on-drop lives on JoinFuture, not the
                    // handle): the connection task stays region-owned
                    // and dies with the region at shutdown.
                    Ok(handle) => drop(handle),
                    Err(error) => log_line(
                        "rabsd-edge-conn-spawn-refused",
                        &[("error", &format!("{error:?}"))],
                    ),
                }
            }
            Err(error) => {
                log_line("rabsd-edge-accept-error", &[("error", &error.to_string())]);
                return;
            }
        }
    }
}

/// One absolute budget covers the ENTIRE frame, not each trickled byte.
async fn read_frame_with_budget(stream: &mut EdgeStream, budget: Duration) -> Option<Vec<u8>> {
    read_frame_bounded(stream, budget, MAX_FRAME_BYTES).await
}

/// [`read_frame_with_budget`] with an explicit frame bound, for the one
/// frame kind (a live completion carrying its transcript) that may exceed
/// the ordinary request bound. Retain read-ahead across every protocol phase.
async fn read_frame_bounded(
    stream: &mut EdgeStream,
    budget: Duration,
    max_bytes: usize,
) -> Option<Vec<u8>> {
    asupersync::time::timeout(
        asupersync::time::wall_now(),
        budget,
        frame_read::read_frame(stream, max_bytes),
    )
    .await
    .ok()
    .flatten()
}

/// None means EOF, a truncated/oversized frame, or an exhausted read budget.
async fn read_frame(stream: &mut EdgeStream) -> Option<Vec<u8>> {
    read_frame_with_budget(stream, FRAME_IO_BUDGET).await
}

async fn write_frame(stream: &mut EdgeStream, line: &str) -> bool {
    let mut bytes = line.as_bytes().to_vec();
    bytes.push(b'\n');
    asupersync::time::timeout(
        asupersync::time::wall_now(),
        FRAME_IO_BUDGET,
        stream.get_mut().write_all(&bytes),
    )
    .await
    .is_ok_and(|result| result.is_ok())
}

fn refusal(reason: &str, detail: &str) -> String {
    format!(
        "{{\"kind\":\"refusal\",\"reason\":\"{reason}\",\"detail\":\"{}\"}}",
        detail.replace('"', "'")
    )
}

/// Created at the same point as begin_flight, including on a blocking worker.
/// A cancelled future, failed reply, or panic cannot lose its matching release.
struct Flight {
    coord: crate::coord::live::EdgeSubscriber,
    key: String,
    label: &'static str,
}
impl Drop for Flight {
    fn drop(&mut self) {
        self.coord.end_flight(&self.key);
    }
}

async fn handle_connection(
    id: u64,
    stream: UnixStream,
    policy: AdmissionPolicy,
    socket_evidence: SocketMetadata,
    services: EdgeServices,
    limits: EdgeLimits,
) {
    let mut stream = EdgeStream::with_capacity(FRAME_READ_BUFFER_BYTES, stream);
    let EdgeServices {
        shadow,
        coord,
        prepared_operations,
        live,
        canonical_only,
        canonical_activity: _,
    } = services;
    let trace = format!("edge-conn-{id}");
    // Admission: kernel peer credentials against the policy.
    let (peer_uid, peer_gid) = match stream.get_ref().peer_cred() {
        Ok(cred) => (cred.uid, cred.gid),
        Err(error) => {
            log_line(
                "rabsd-edge-admission-refused",
                &[("trace", &trace), ("error", &error.to_string())],
            );
            let _ = write_frame(&mut stream, &refusal("peer-cred-unavailable", "")).await;
            return;
        }
    };
    let evidence = ConnectionEvidence::UnixSocket {
        peer: PeerCredentials {
            uid: peer_uid,
            gid: peer_gid,
        },
        socket: socket_evidence,
    };
    let token_context = TokenContext {
        revoked: &[],
        current_seq: 0,
        session_id: 0,
        operation_id: 0,
    };
    if let Err(refused) = admit(&policy, &evidence, None, &token_context) {
        log_line(
            "rabsd-edge-admission-refused",
            &[("trace", &trace), ("refusal", &format!("{refused:?}"))],
        );
        let _ = write_frame(&mut stream, &refusal("admission", &format!("{refused:?}"))).await;
        return;
    }

    // Handshake: hello frame -> negotiate -> reply.
    let Some(frame) = read_frame(&mut stream).await else {
        return;
    };
    let hello: VersionHello = match parse_hello(&frame) {
        Ok(hello) => hello,
        Err(detail) => {
            log_line(
                "rabsd-edge-malformed-hello",
                &[("trace", &trace), ("detail", &detail)],
            );
            let _ = write_frame(&mut stream, &refusal("malformed-hello", &detail)).await;
            return;
        }
    };
    match negotiate(&our_hello(), &hello) {
        Negotiation::Agreed {
            transport,
            application,
        } => {
            let reply = format!(
                "{{\"kind\":\"hello-ok\",\"transport\":{transport},\"application\":{application}}}"
            );
            if !write_frame(&mut stream, &reply).await {
                return;
            }
        }
        Negotiation::Refused(refused) => {
            let _ = write_frame(&mut stream, &refusal("version", &format!("{refused:?}"))).await;
            return;
        }
    }

    // Shadow-flight lifetime stays connection-scoped, including cancellation.
    // The request quota bounds both retained flight guards and per-peer work.
    let mut open_flights: Vec<Flight> = Vec::new();
    for _ in 0..MAX_REQUESTS_PER_CONNECTION {
        let Some(frame) = read_frame(&mut stream).await else {
            break;
        };
        let reply = match serde_json::from_slice::<serde_json::Value>(&frame) {
            Ok(value)
                if canonical_only
                    && value.get("kind").and_then(|kind| kind.as_str())
                        != Some("rustc-request") =>
            {
                refusal(
                    "canonical-build-socket",
                    "this operation grants only canonical rustc requests",
                )
            }
            Ok(value) if value.get("kind").and_then(|k| k.as_str()) == Some("status") => {
                let remote = live
                    .as_ref()
                    .and_then(|edge| edge.remote_configuration())
                    .cloned();
                status_on_lane(
                    &limits.control,
                    coord.clone(),
                    live.is_some(),
                    remote,
                    prepared_operations.clone(),
                )
                .await
            }
            Ok(value)
                if matches!(
                    value.get("kind").and_then(|k| k.as_str()),
                    Some(
                        "prepared-submit"
                            | "prepared-submit-allocated"
                            | "prepared-submit-pool"
                            | "prepared-status"
                            | "prepared-cancel"
                            | "prepared-resume"
                            | "prepared-acknowledge"
                            | "prepared-completion"
                            | "prepared-recover-local"
                            | "prepared-preview"
                    )
                ) =>
            {
                // Bundle admission and complete result verification perform
                // filesystem work. Neither may occupy the cancellation/status
                // lane or the reactor while hashing a large delivered tree.
                let lane = match value["kind"].as_str() {
                    Some(
                        "prepared-submit"
                        | "prepared-submit-allocated"
                        | "prepared-submit-pool"
                        | "prepared-resume",
                    ) => &limits.prepared_admission,
                    Some("prepared-completion" | "prepared-recover-local") => {
                        &limits.materialization
                    }
                    _ => &limits.control,
                };
                prepared_on_lane(lane, prepared_operations.clone(), value).await
            }
            Ok(value) if value.get("kind").and_then(|k| k.as_str()) == Some("consult") => {
                match parse_observation(&value) {
                    Some(observation) => {
                        let shadow = std::sync::Arc::clone(&shadow);
                        let coord = coord.clone();
                        let work_trace = trace.clone();
                        let result = match limits
                            .shadow
                            .spawn(move || shadow_reply(&work_trace, observation, shadow, coord))
                        {
                            Ok(mut work) => work.wait().await,
                            Err(error) => Err(error),
                        };
                        match result {
                            Ok((reply, flight)) => {
                                if let Some(flight) = flight {
                                    open_flights.push(flight);
                                }
                                reply
                            }
                            Err(error) => {
                                log_line(
                                    "rabsd-edge-shadow-error",
                                    &[("trace", &trace), ("error", &error.to_string())],
                                );
                                "{\"kind\":\"decision\",\"decision\":\"pass-through\",\"mode\":\"shadow-error\"}".to_owned()
                            }
                        }
                    }
                    None => "{\"kind\":\"decision\",\"decision\":\"pass-through\",\
                         \"mode\":\"unshadowed\"}"
                        .to_string(),
                }
            }
            Ok(value) if value.get("kind").and_then(|k| k.as_str()) == Some("serve") => {
                serve_on_lane(&limits.materialization, coord.clone(), value).await
            }
            Ok(value) if value.get("kind").and_then(|k| k.as_str()) == Some("rustc-request") => {
                let may_wait = value
                    .get("wait_for_inflight")
                    .and_then(serde_json::Value::as_bool)
                    == Some(true);
                let decided = match &live {
                    Some(live) => {
                        backpressure::decide(&limits.live, std::sync::Arc::clone(live), value).await
                    }
                    None => Ok(rustc_request::shadow_observation(&value).map_or_else(
                        || {
                            rustc_request::Decided::Reply(
                                "{\"kind\":\"decision\",\"decision\":\"pass-through\",\
                                 \"mode\":\"unshadowed\"}"
                                    .to_owned(),
                            )
                        },
                        rustc_request::Decided::Shadow,
                    )),
                };
                match decided {
                    Ok(rustc_request::Decided::Reply(reply)) => reply,
                    Ok(rustc_request::Decided::Shadow(observation)) => {
                        let shadow = std::sync::Arc::clone(&shadow);
                        let coord = coord.clone();
                        let work_trace = trace.clone();
                        let result = match limits
                            .shadow
                            .spawn(move || shadow_reply(&work_trace, observation, shadow, coord))
                        {
                            Ok(mut work) => work.wait().await,
                            Err(error) => Err(error),
                        };
                        match result {
                            Ok((reply, flight)) => {
                                if let Some(flight) = flight {
                                    open_flights.push(flight);
                                }
                                reply
                            }
                            Err(_) => "{\"kind\":\"decision\",\"decision\":\"pass-through\",\
                                       \"mode\":\"shadow-error\"}"
                                .to_owned(),
                        }
                    }
                    Ok(rustc_request::Decided::Remote { reply, pending }) => {
                        let Some(live) = live.clone() else {
                            break;
                        };
                        match remote_dependency::complete_on_connection(
                            &limits.remote_execution,
                            &limits.materialization,
                            live,
                            pending,
                            reply,
                            may_wait,
                            &mut stream,
                        )
                        .await
                        {
                            Some(reply) => reply,
                            None => break,
                        }
                    }
                    Ok(rustc_request::Decided::SharedRemote { reply, pending }) => {
                        let Some(live) = live.clone() else {
                            break;
                        };
                        match remote_dependency::complete_shared_on_connection(
                            &limits.materialization,
                            live,
                            pending,
                            reply,
                            &mut stream,
                        )
                        .await
                        {
                            Some(reply) => reply,
                            None => break,
                        }
                    }
                    Ok(rustc_request::Decided::Hit {
                        reply,
                        pending,
                        metadata,
                    }) => {
                        // Reserve the independent installation lane BEFORE
                        // offering a hit. Once Cargo accepts, a fresh decision
                        // burst cannot force a verified hit back to compilation.
                        let Some(installation) = limits.materialization.acquire() else {
                            // This preview owns no writer or compiler attempt.
                            // Drop it before advertising a non-owning retry.
                            drop(pending);
                            if !write_frame(
                                &mut stream,
                                &backpressure::capacity_reply(may_wait, "materialization"),
                            )
                            .await
                            {
                                break;
                            }
                            continue;
                        };
                        // Nothing is written unless the subscriber commits to
                        // waiting for the install. A subscriber that already
                        // gave up (timeout, crash) never sees a late writer.
                        let metadata = metadata.then(|| metadata_delivery::Identity {
                            action_key: rabs_cas::metadata_store::digest_key(pending.action_key()),
                            manifest_key: pending.manifest_key().to_owned(),
                        });
                        let accepted = write_frame(&mut stream, &reply).await
                            && read_frame(&mut stream).await.is_some_and(|frame| {
                                if let Some(identity) = &metadata {
                                    return identity.accepts(&frame);
                                }
                                serde_json::from_slice::<serde_json::Value>(&frame)
                                    .ok()
                                    .and_then(|value| {
                                        value
                                            .get("kind")
                                            .and_then(|k| k.as_str())
                                            .map(|kind| kind == "rustc-accept")
                                    })
                                    .unwrap_or(false)
                            });
                        if !accepted {
                            drop(pending);
                            break;
                        }
                        let Some(live) = live.clone() else {
                            break;
                        };
                        match metadata_delivery::install(
                            installation,
                            live,
                            pending,
                            metadata,
                            &mut stream,
                        )
                        .await
                        {
                            Some(reply) => reply,
                            None => break,
                        }
                    }
                    Ok(rustc_request::Decided::Execute { reply, attempt }) => {
                        // The subscriber now runs the compiler as this
                        // admitted attempt. Its completion arrives on THIS
                        // connection; losing the connection settles the
                        // attempt without publication.
                        let completion = if write_frame(&mut stream, &reply).await {
                            read_frame_bounded(
                                &mut stream,
                                LOCAL_EXECUTION_BUDGET,
                                rustc_request::MAX_COMPLETION_FRAME_BYTES,
                            )
                            .await
                        } else {
                            None
                        };
                        match (completion, live.clone()) {
                            (Some(frame), Some(live)) => {
                                rustc_request::complete_on_lane(
                                    &limits.live_completion,
                                    live,
                                    attempt,
                                    frame,
                                    &mut stream,
                                )
                                .await
                            }
                            _ => match limits.live_completion.spawn(move || {
                                drop(attempt);
                                refusal("completion-lost", "")
                            }) {
                                Ok(mut work) => work.wait().await.unwrap_or_else(|error| {
                                    refusal("completion", &error.to_string())
                                }),
                                Err(error) => refusal("completion", &error.to_string()),
                            },
                        }
                    }
                    Err(error) => {
                        log_line(
                            "rabsd-live-dependency-error",
                            &[("trace", &trace), ("error", &error.to_string())],
                        );
                        "{\"kind\":\"rustc-decision\",\"decision\":\"pass-through\",\
                         \"reason\":\"edge-capacity\"}"
                            .to_owned()
                    }
                }
            }
            Ok(other) => refusal(
                "unknown-frame",
                other.get("kind").and_then(|k| k.as_str()).unwrap_or("?"),
            ),
            Err(error) => {
                log_line(
                    "rabsd-edge-malformed-frame",
                    &[("trace", &trace), ("error", &error.to_string())],
                );
                refusal("malformed-json", &error.to_string())
            }
        };
        if !write_frame(&mut stream, &reply).await {
            break;
        }
    }
    drop(open_flights);
}

fn shadow_reply(
    trace: &str,
    observation: crate::edge::shadow::ConsultObservation,
    shadow: std::sync::Arc<std::sync::Mutex<crate::edge::shadow::ShadowPlane>>,
    coord: crate::coord::live::EdgeSubscriber,
) -> (String, Option<Flight>) {
    let mut joined: Option<Flight> = None;
    let decision = shadow.lock().map_err(|_| ()).and_then(|mut plane| {
        plane
            .on_consult(trace, &observation, |key| {
                let role = coord.begin_flight(key);
                if role != crate::coord::live::FlightRole::Degraded {
                    joined = Some(Flight {
                        coord: coord.clone(),
                        key: key.to_owned(),
                        label: role.label(),
                    });
                }
                role.label()
            })
            .map_err(|_| ())
    });
    let flight_label = joined.as_ref().map_or("degraded", |flight| flight.label);
    let reply = match decision {
        Ok(decision) => format!(
            "{{\"kind\":\"decision\",\"decision\":\"pass-through\",\
             \"mode\":\"{}\",\"key\":\"{}\",\
             \"hit_upper_bound\":{},\"class\":\"{}\",\
             \"flight\":\"{flight_label}\"}}",
            if coord.available() {
                "shadow"
            } else {
                "shadow-coord-degraded"
            },
            decision.key_hex,
            decision.would_have_hit_upper_bound,
            decision.class,
        ),
        Err(()) => {
            log_line(
                "rabsd-edge-shadow-error",
                &[("trace", trace), ("key_class", "unknown")],
            );
            "{\"kind\":\"decision\",\"decision\":\"pass-through\",\"mode\":\"shadow-error\"}"
                .to_owned()
        }
    };
    (reply, joined)
}

async fn status_on_lane(
    lane: &Limit,
    coord: crate::coord::live::EdgeSubscriber,
    live_dependency: bool,
    remote_dependency: Option<serde_json::Value>,
    prepared_operations: Option<
        std::sync::Arc<crate::coord::prepared_operation::PreparedOperationStore>,
    >,
) -> String {
    // Status can consult release-policy storage and coordinator locks too.
    // Its own lane prevents both inline I/O and bulk-work admission starvation.
    // Report the attached edge's actual capability, not the configuration a
    // new `rabsd --check-config` process would use. A healthy shadow daemon
    // shares this socket protocol but cannot serve Cargo dependency hits.
    let result = match lane.spawn(move || {
        match serde_json::from_str::<serde_json::Value>(&coord.status_json()) {
            Ok(serde_json::Value::Object(mut status)) => {
                status.insert("live_dependency".to_owned(), live_dependency.into());
                status.insert(
                    "remote_dependency".to_owned(),
                    remote_dependency.unwrap_or(serde_json::Value::Null),
                );
                status.insert(
                    "prepared_jobs".to_owned(),
                    prepared_operations.map_or(serde_json::Value::Null, |store| {
                        match store.capacity_status() {
                            Ok(capacity) => serde_json::json!({
                                "available":true,
                                "concurrency":capacity.concurrency,
                                "active":capacity.active,
                                "queued":capacity.queued,
                                "accepting":capacity.accepting,
                                "persistence_uncertain":capacity.persistence_uncertain,
                            }),
                            Err(error) => serde_json::json!({
                                "available":false,
                                "concurrency":store.concurrency().get(),
                                "detail":error.to_string(),
                            }),
                        }
                    }),
                );
                serde_json::Value::Object(status).to_string()
            }
            _ => refusal("status-unavailable", "invalid coordinator status"),
        }
    }) {
        Ok(mut work) => work.wait().await,
        Err(error) => Err(error),
    };
    match result {
        Ok(reply) => reply,
        Err(error) => refusal("status-unavailable", &error.to_string()),
    }
}

async fn prepared_on_lane(
    lane: &Limit,
    operations: Option<std::sync::Arc<crate::coord::prepared_operation::PreparedOperationStore>>,
    request: serde_json::Value,
) -> String {
    let operation_id = request
        .get("operation_id")
        .or_else(|| {
            request
                .get("operation")
                .and_then(|operation| operation.get("id"))
        })
        .cloned();
    let result = match lane.spawn(move || prepared_reply(operations.as_ref(), &request)) {
        Ok(mut work) => work.wait().await,
        Err(error) => Err(error),
    };
    match result {
        Ok(reply) => reply,
        Err(error) => serde_json::json!({
            "kind":"prepared-operation-error", "operation_id":operation_id,
            "detail":error.to_string(), "outcome_unconfirmed":true,
            "reexecute":false,
        })
        .to_string(),
    }
}

fn prepared_reply(
    operations: Option<&std::sync::Arc<crate::coord::prepared_operation::PreparedOperationStore>>,
    request: &serde_json::Value,
) -> String {
    use crate::coord::prepared_operation::{PreparedOperationSpec, PreparedPoolOperationSpec};
    use std::io;
    let operation_id = request.get("operation_id").or_else(|| {
        request
            .get("operation")
            .and_then(|operation| operation.get("id"))
    });
    let result = (|| -> io::Result<serde_json::Value> {
        let invalid = |detail: &str| io::Error::new(io::ErrorKind::InvalidInput, detail.to_owned());
        let operations =
            operations.ok_or_else(|| invalid("prepared job service is unavailable"))?;
        let kind = request["kind"]
            .as_str()
            .ok_or_else(|| invalid("missing request kind"))?;
        let fields: &[&str] = match kind {
            "prepared-submit" | "prepared-submit-allocated" | "prepared-submit-pool" => {
                &["kind", "operation"]
            }
            "prepared-status" | "prepared-cancel" => &["kind", "operation_id"],
            "prepared-completion" => &["kind", "operation_id", "request_sha256"],
            "prepared-preview" => &[
                "kind",
                "operation_id",
                "request_sha256",
                "attempt",
                "stdout_offset",
                "stderr_offset",
            ],
            "prepared-resume" => &["kind", "operation_id", "delivery", "resume_from"],
            "prepared-acknowledge" | "prepared-recover-local" => {
                &["kind", "operation_id", "delivery"]
            }
            _ => return Err(invalid("unknown prepared operation")),
        };
        if request
            .as_object()
            .is_none_or(|object| object.keys().any(|key| !fields.contains(&key.as_str())))
        {
            return Err(invalid("unexpected prepared operation field"));
        }
        if kind == "prepared-preview" {
            let id = request["operation_id"]
                .as_str()
                .ok_or_else(|| invalid("missing preview operation_id"))?;
            let fingerprint = request["request_sha256"]
                .as_str()
                .ok_or_else(|| invalid("missing preview request identity"))?;
            let number = |field: &str| {
                request[field]
                    .as_u64()
                    .ok_or_else(|| invalid("missing or invalid preview cursor or attempt"))
            };
            return operations.preview(
                id,
                fingerprint,
                number("attempt")?,
                number("stdout_offset")?,
                number("stderr_offset")?,
            );
        }
        if kind == "prepared-completion" {
            let id = request["operation_id"]
                .as_str()
                .ok_or_else(|| invalid("missing operation_id"))?;
            let fingerprint = request["request_sha256"]
                .as_str()
                .ok_or_else(|| invalid("missing completion request identity"))?;
            let completion = operations.completion(id, fingerprint)?;
            return Ok(serde_json::json!({
                "kind":"prepared-completion", "operation_id":id,
                "completion":completion, "publication_authorized":false,
                "reexecute":false,
            }));
        }
        let status = if kind == "prepared-submit-pool" {
            let spec: PreparedPoolOperationSpec =
                serde_json::from_value(request["operation"].clone())
                    .map_err(|error| invalid(&format!("invalid prepared worker pool: {error}")))?;
            operations.submit_allocated_pool(spec)?
        } else if matches!(kind, "prepared-submit" | "prepared-submit-allocated") {
            let spec: PreparedOperationSpec = serde_json::from_value(request["operation"].clone())
                .map_err(|error| invalid(&format!("invalid prepared operation: {error}")))?;
            if kind == "prepared-submit-allocated" {
                operations.submit_allocated(spec)?
            } else {
                operations.submit(spec)?
            }
        } else {
            let id = request["operation_id"]
                .as_str()
                .ok_or_else(|| invalid("missing operation_id"))?;
            match kind {
                "prepared-status" => operations.status(id)?.ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, "prepared operation not found")
                })?,
                "prepared-cancel" => operations.cancel(id)?,
                "prepared-resume" => {
                    let delivery = request["delivery"]
                        .as_str()
                        .ok_or_else(|| invalid("missing resume delivery directory"))?;
                    let resume_from = match request.get("resume_from") {
                        None | Some(serde_json::Value::Null) => None,
                        Some(serde_json::Value::String(path)) => Some(PathBuf::from(path)),
                        Some(_) => return Err(invalid("invalid resume prefix directory")),
                    };
                    operations.resume(id, PathBuf::from(delivery), resume_from)?
                }
                "prepared-acknowledge" => {
                    let delivery = request["delivery"]
                        .as_str()
                        .ok_or_else(|| invalid("missing owned delivery directory"))?;
                    operations.acknowledge(id, PathBuf::from(delivery))?
                }
                "prepared-recover-local" => {
                    let delivery = request["delivery"]
                        .as_str()
                        .ok_or_else(|| invalid("missing owned local delivery directory"))?;
                    operations.recover_local(id, PathBuf::from(delivery))?
                }
                _ => return Err(invalid("unknown prepared operation")),
            }
        };
        Ok(serde_json::json!({
            "kind":"prepared-operation", "operation":status,
            "publication_authorized":false, "reexecute":false,
        }))
    })();
    match result {
        Ok(reply) => reply.to_string(),
        Err(error) => serde_json::json!({
            "kind":"prepared-operation-error", "operation_id":operation_id,
            "detail":error.to_string(), "outcome_unconfirmed":true,
            "reexecute":false,
        })
        .to_string(),
    }
}

async fn serve_on_lane(
    lane: &Limit,
    coord: crate::coord::live::EdgeSubscriber,
    request: serde_json::Value,
) -> String {
    match lane.spawn(move || rustc_outputs::serve_reply(&coord, &request)) {
        Ok(mut work) => match work.wait().await {
            Ok(reply) => reply,
            Err(error) => serve_work_error(&error, true),
        },
        Err(error) => serve_work_error(&error, false),
    }
}

fn serve_work_error(error: &WorkError, started: bool) -> String {
    // A panic may occur after an output rename but before a receipt is returned.
    // Do not invent an empty installed prefix or authorize a local rerun.
    serde_json::json!({
        "kind":"serve-result", "outcome":"error", "reason":error.to_string(),
        "materialization_started":started,
        "installed": if started { serde_json::Value::Null } else { serde_json::json!([]) },
        "installed_path_bytes": if started { serde_json::Value::Null } else { serde_json::json!([]) },
        "compiler_skip_authorized":false, "reexecution_authorized":false,
    }).to_string()
}

/// Handle a `serve` frame: materialize a committed action's outputs
/// into a caller-named worktree (bd-1vf05 — the first way to reach
/// [`CoordLive::serve_action`] from outside the daemon process).
///
/// Every answer is typed and distinguishable: a miss, a quarantine, and
/// a fault are three different replies, because a caller that may skip
/// work on a hit must never confuse them. The destination must be an
/// ABSOLUTE path — a relative one would resolve against the daemon's
/// working directory, which is not the caller's.
///
/// [`CoordLive::serve_action`]: crate::coord::live::CoordLive::serve_action
fn serve_reply(coord: &crate::coord::live::EdgeSubscriber, value: &serde_json::Value) -> String {
    use crate::coord::live::{ExpectedOutputs, ServeOutcome};

    let Some(action_key) = value
        .get("action_key")
        .and_then(|k| k.as_str())
        .and_then(action_key_from_hex)
    else {
        return refusal("bad-action-key", "expected 64 hex characters");
    };
    let Some(destination) = value.get("destination_root").and_then(|d| d.as_str()) else {
        return refusal("missing-destination", "serve requires destination_root");
    };
    let destination = std::path::Path::new(destination);
    if !destination.is_absolute() {
        return refusal("relative-destination", "destination_root must be absolute");
    }
    // The caller's expectation. A frame that omits `expected_outputs`
    // is explicitly saying it is skipping no work (operator/diagnostic
    // use); a caller that IS skipping work states its derived set and
    // gets a refusal on any mismatch.
    let expected = match value.get("expected_outputs") {
        None => ExpectedOutputs::WhateverWasCommitted,
        Some(list) => {
            let Some(items) = list.as_array() else {
                return refusal("bad-expected-outputs", "expected_outputs must be an array");
            };
            let mut set = std::collections::BTreeSet::new();
            for item in items {
                let Some(text) = item.as_str() else {
                    return refusal("bad-expected-outputs", "entries must be strings");
                };
                set.insert(text.to_owned());
            }
            ExpectedOutputs::Exactly(set)
        }
    };
    let expected = match (expected, value.get("dep_info_mappings")) {
        (ExpectedOutputs::Exactly(paths), Some(value)) => {
            let Some(mappings) = parse_dep_info_mappings(value) else {
                return refusal(
                    "bad-dep-info-mappings",
                    "expected bounded [canonical-directory, subscriber-directory] pairs",
                );
            };
            ExpectedOutputs::WithDepInfo { paths, mappings }
        }
        (expected, None) => expected,
        _ => {
            return refusal(
                "bad-dep-info-mappings",
                "dep-info mappings require expected_outputs",
            );
        }
    };
    // The committed serving record carries clock epoch 0 (its column
    // default) until the coordinator populates a real clock epoch, so
    // the gate is asked at that epoch; the instant is the daemon's own.
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_micros()),
    )
    .unwrap_or(i64::MAX);
    match coord.serve_action(&action_key, destination, &expected, now, 0) {
        Ok(ServeOutcome::ExecutePrivately(reason)) => serde_json::json!({
            "kind": "serve-result",
            "outcome": "execute-privately",
            "reason": format!("{reason:?}"),
        })
        .to_string(),
        Ok(ServeOutcome::Served { files }) => {
            use std::os::unix::ffi::OsStrExt;
            serde_json::json!({
                "kind": "serve-result", "outcome": "served",
                "files": files.iter().map(|path| path.to_string_lossy()).collect::<Vec<_>>(),
                "file_path_bytes": files.iter().map(|path| path.as_os_str().as_bytes()).collect::<Vec<_>>(),
                "compiler_skip_authorized": false,
            }).to_string()
        }
        Ok(ServeOutcome::NotServable(decision)) => format!(
            "{{\"kind\":\"serve-result\",\"outcome\":\"not-servable\",\"reason\":\"{}\"}}",
            format!("{decision:?}").replace('"', "'")
        ),
        Ok(ServeOutcome::NoCommit) => {
            "{\"kind\":\"serve-result\",\"outcome\":\"no-commit\"}".to_string()
        }
        // The serve frame always installs; a preview answer here would mean
        // nothing was installed, which must never read as a hit.
        Ok(ServeOutcome::Servable) => {
            "{\"kind\":\"serve-result\",\"outcome\":\"error\",\"reason\":\"preview-only\",\
             \"compiler_skip_authorized\":false,\"reexecution_authorized\":false}"
                .to_string()
        }
        // T011: the running build is not release-authorized. The
        // standing token is reported rather than a bare refusal,
        // because "no verdict was ever recorded" and "the deployed
        // build is not the proven one" need different operator
        // responses.
        Ok(ServeOutcome::ReleaseUnauthorized { standing }) => format!(
            "{{\"kind\":\"serve-result\",\"outcome\":\"release-unauthorized\",\"standing\":\"{}\"}}",
            standing.token()
        ),
        Ok(ServeOutcome::ManifestUnavailable { key }) => format!(
            "{{\"kind\":\"serve-result\",\"outcome\":\"manifest-unavailable\",\"key\":\"{}\"}}",
            key.replace('"', "'")
        ),
        Ok(ServeOutcome::OutputSetMismatch {
            missing,
            unexpected,
        }) => {
            let quote = |items: &[String]| {
                items
                    .iter()
                    .map(|p| format!("\"{}\"", p.replace('"', "'")))
                    .collect::<Vec<_>>()
                    .join(",")
            };
            format!(
                "{{\"kind\":\"serve-result\",\"outcome\":\"output-set-mismatch\",\
                 \"missing\":[{}],\"unexpected\":[{}]}}",
                quote(&missing),
                quote(&unexpected)
            )
        }
        Err(error) => serve_error_reply(&error),
    }
}

fn parse_dep_info_mappings(value: &serde_json::Value) -> Option<Vec<(Vec<u8>, Vec<u8>)>> {
    let entries = value.as_array()?;
    if entries.len() > 64 {
        return None;
    }
    let path_bytes = |value: &serde_json::Value| -> Option<Vec<u8>> {
        if let Some(text) = value.as_str() {
            return (text.len() <= 4096).then(|| text.as_bytes().to_vec());
        }
        let bytes = value.as_array()?;
        if bytes.len() > 4096 {
            return None;
        }
        bytes
            .iter()
            .map(|byte| u8::try_from(byte.as_u64()?).ok())
            .collect()
    };
    entries
        .iter()
        .map(|entry| {
            let pair = entry.as_array()?;
            if pair.len() != 2 {
                return None;
            }
            Some((path_bytes(&pair[0])?, path_bytes(&pair[1])?))
        })
        .collect()
}

/// Error transport preserves the materializer's installed prefix. No response
/// from this file-only endpoint grants permission to rerun a compiler; in
/// particular a timeout or lost response is NOT evidence of an untouched tree.
fn serve_error_reply(error: &crate::coord::live::ServeError) -> String {
    use crate::coord::live::ServeError;
    use std::os::unix::ffi::OsStrExt;
    let (started, files) = match error {
        ServeError::Materialize(failure) => (
            true,
            failure
                .installed
                .iter()
                .map(|output| output.destination.as_path())
                .collect::<Vec<_>>(),
        ),
        ServeError::MetadataExposed { installed, .. } => (
            true,
            installed.iter().map(std::path::PathBuf::as_path).collect(),
        ),
        _ => (false, Vec::new()),
    };
    serde_json::json!({
        "kind": "serve-result", "outcome": "error", "reason": error.to_string(),
        "materialization_started": started,
        "installed": files.iter().map(|path| path.to_string_lossy()).collect::<Vec<_>>(),
        "installed_path_bytes": files.iter().map(|path| path.as_os_str().as_bytes()).collect::<Vec<_>>(),
        "compiler_skip_authorized": false, "reexecution_authorized": false,
    }).to_string()
}

#[cfg(test)]
mod complete_output_wire_tests {
    use super::{parse_dep_info_mappings, serve_error_reply};
    use crate::coord::live::ServeError;
    use rabs_cas::materialization::{
        ActionMaterializeFailure, MaterializeError, OutputMaterialized,
    };
    use rabs_protocol::raw_bytes::RawBytes;
    use rabs_protocol::result_identity::OutputRole;
    use std::os::unix::ffi::OsStringExt;
    use std::path::PathBuf;

    #[test]
    fn mapping_wire_preserves_unix_bytes_and_refuses_malformed_pairs() {
        let value = serde_json::json!([["/__rabs/workspace", [47, 116, 109, 112, 47, 255]]]);
        assert_eq!(
            parse_dep_info_mappings(&value).unwrap(),
            vec![(b"/__rabs/workspace".to_vec(), b"/tmp/\xff".to_vec())]
        );
        for value in [
            serde_json::json!([["/__rabs/workspace"]]),
            serde_json::json!([["/__rabs/workspace", [256]]]),
            serde_json::json!([["/__rabs/workspace", [-1]]]),
            serde_json::json!([["/__rabs/workspace", [1.5]]]),
            serde_json::json!({"not":"a list"}),
        ] {
            assert!(parse_dep_info_mappings(&value).is_none());
        }
    }

    #[test]
    fn mapping_wire_bounds_both_cardinality_and_path_size() {
        let pair = serde_json::json!(["/__rabs/workspace", "/subscriber"]);
        assert!(parse_dep_info_mappings(&serde_json::json!(vec![pair; 65])).is_none());
        assert!(
            parse_dep_info_mappings(&serde_json::json!([[
                "/__rabs/workspace",
                "x".repeat(4097)
            ]]))
            .is_none()
        );
        assert!(
            parse_dep_info_mappings(&serde_json::json!([["/__rabs/workspace", vec![1; 4097]]]))
                .is_none()
        );
    }

    #[test]
    fn partial_install_reply_never_loses_raw_paths_or_authorizes_reexecution() {
        let raw = b"/target/quote\"-\xff.rmeta".to_vec();
        let failure = ServeError::Materialize(ActionMaterializeFailure {
            installed: vec![OutputMaterialized {
                role: OutputRole::ProvisionalMetadata,
                virtual_path: RawBytes::from("out.rmeta"),
                destination: PathBuf::from(std::ffi::OsString::from_vec(raw.clone())),
                bytes: 42,
                nanos: 1,
            }],
            error: MaterializeError::Io {
                step: "prepare",
                error: "fault".to_owned(),
            },
        });
        let reply: serde_json::Value = serde_json::from_str(&serve_error_reply(&failure)).unwrap();
        assert_eq!(reply["outcome"], "error");
        assert_eq!(reply["materialization_started"], true);
        assert_eq!(reply["installed_path_bytes"], serde_json::json!([raw]));
        assert_eq!(reply["compiler_skip_authorized"], false);
        assert_eq!(reply["reexecution_authorized"], false);
        let before = ServeError::Preparation {
            path: "/target".into(),
            reason: "mapping".into(),
        };
        let reply: serde_json::Value = serde_json::from_str(&serve_error_reply(&before)).unwrap();
        assert_eq!(reply["materialization_started"], false);
        assert_eq!(reply["installed_path_bytes"], serde_json::json!([]));
        assert_eq!(reply["reexecution_authorized"], false);
    }
}

/// A 64-hex action key, typed under THIS build's action-key domain — the
/// domain is never taken from the wire (R121).
fn action_key_from_hex(hex: &str) -> Option<rabs_protocol::result_identity::TypedDigest> {
    use rabs_protocol::result_identity::{DigestAlgorithm, TypedDigest};
    if hex.len() != 64 {
        return None;
    }
    let mut bytes = [0_u8; 32];
    let (pairs, _) = hex.as_bytes().as_chunks::<2>();
    for (slot, pair) in bytes.iter_mut().zip(pairs) {
        *slot = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(TypedDigest {
        algorithm: DigestAlgorithm::Sha256V1,
        domain: rabs_key::typed_digest::DOMAIN_ACTION_KEY,
        bytes,
    })
}

/// Parse the full consult observation (argv + cwd + env names); None
/// when the frame carries only the legacy summary.
fn parse_observation(value: &serde_json::Value) -> Option<crate::edge::shadow::ConsultObservation> {
    let argv: Vec<String> = value
        .get("argv")?
        .as_array()?
        .iter()
        .filter_map(|item| item.as_str().map(str::to_string))
        .collect();
    if argv.is_empty() {
        return None;
    }
    Some(crate::edge::shadow::ConsultObservation {
        argv,
        cwd: value
            .get("cwd")
            .and_then(|c| c.as_str())
            .unwrap_or("")
            .to_string(),
        env_names: value
            .get("env_names")
            .and_then(|e| e.as_array())
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default(),
    })
}

fn parse_hello(frame: &[u8]) -> Result<VersionHello, String> {
    let value: serde_json::Value =
        serde_json::from_slice(frame).map_err(|e| format!("json: {e}"))?;
    if value.get("kind").and_then(|k| k.as_str()) != Some("hello") {
        return Err("first frame must be kind=hello".to_string());
    }
    let range = |key: &str| -> Result<VersionRange, String> {
        let node = value
            .get(key)
            .ok_or_else(|| format!("hello missing {key}"))?;
        Ok(VersionRange {
            minimum_compatible: node
                .get("minimum_compatible")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0) as u32,
            current: node
                .get("current")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0) as u32,
        })
    };
    Ok(VersionHello {
        transport: range("transport")?,
        application: range("application")?,
    })
}

#[cfg(test)]
mod live_serve_tests {
    use super::*;
    use rabs_cas::test_support::{
        install_admission_world, install_offer_closure, offer_under, sample_action_key,
        sample_expected_descriptor,
    };
    use std::sync::Arc;

    #[test]
    fn serve_frame_cannot_choose_its_own_risk_or_evidence_floor() {
        let dir = tempfile::tempdir().unwrap();
        let cas =
            Arc::new(crate::janitor::store::mount_and_reconcile(&dir.path().join("cas")).unwrap());
        let coord = Arc::new(crate::coord::live::CoordLive::with_cas(Arc::clone(&cas)));
        let authority = coord.acquire_boot_authority("serve-frame-fixture").unwrap();
        coord.mark_up();
        let offer = offer_under(&authority);
        {
            let mut store = cas.store().lock().unwrap();
            install_admission_world(&mut *store, &authority);
            install_offer_closure(&mut *store, &offer);
        }
        coord
            .commit_offer(&offer, &sample_expected_descriptor())
            .unwrap();
        let destination = dir.path().join("not-written");
        let key = sample_action_key()
            .bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let frame = serde_json::json!({
            "kind": "serve",
            "action_key": key,
            "destination_root": destination.to_str().unwrap(),
            "expected_outputs": ["out/lib.rlib"],
            "risk": "low-risk-registry",
            "min_samples": 0,
            "sample_rate_basis_points": 10_000,
            "verified": true,
        });
        let reply: serde_json::Value =
            serde_json::from_str(&serve_reply(&coord.edge_subscriber(), &frame)).unwrap();
        assert_eq!(reply["kind"], "serve-result");
        assert_eq!(reply["outcome"], "execute-privately");
        assert!(
            reply["reason"]
                .as_str()
                .unwrap()
                .contains("ElevatedClassRisk")
        );
        assert!(!destination.exists());

        // The absence of an output expectation is not an authorization bypass.
        let mut inspection_claim = frame;
        inspection_claim
            .as_object_mut()
            .unwrap()
            .remove("expected_outputs");
        let reply: serde_json::Value =
            serde_json::from_str(&serve_reply(&coord.edge_subscriber(), &inspection_claim))
                .unwrap();
        assert_eq!(reply["outcome"], "execute-privately");
        assert!(!destination.exists());
    }
}

#[cfg(test)]
mod edge_liveness_tests {
    use super::*;
    use asupersync::runtime::RuntimeBuilder;
    use std::future::Future;
    use std::sync::{Arc, mpsc};
    use std::task::{Context, Poll, Waker};
    use std::time::Instant;

    #[test]
    fn log_lines_stay_one_parseable_json_object_for_any_reason_text() {
        let reason = "facts-refused: \"C:\\tmp\\x\" line one\nline two\t\u{7}";
        let line = render_log_line(
            "rabsd-live-dependency",
            &[("decision", "pass-through"), ("reason", reason)],
        );
        assert!(!line.contains('\n'), "{line}");
        let value: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(value["v"], 1);
        assert_eq!(value["kind"], "rabsd-live-dependency");
        assert_eq!(value["decision"], "pass-through");
        assert_eq!(value["reason"], reason);
        // Field order is kept for people reading the raw stream.
        assert!(line.find("\"decision\"").unwrap() < line.find("\"reason\"").unwrap());
    }

    #[test]
    fn prepared_pool_admission_returns_one_saved_placement_and_rejects_changed_intent() {
        use crate::coord::prepared_operation::PreparedOperationStore;
        use crate::coord::source_delivery::prepare_source_template;
        use serde_json::{Value, json};

        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let source = root.join("source");
        let bundle = root.join("bundle");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("lib.rs"), b"pub fn value() {}\n").unwrap();
        prepare_source_template(
            &source,
            &json!({
                "kind":"canonical-exec", "request_id":"allocate",
                "program":"/__rabs/toolchain/bin/rustc",
                "toolchain_backing":"/opt/pool-edge-fixture",
                "toolchain_identity":{
                    "version":"toolchain-dataset-v1", "sha256":"ab".repeat(32),
                    "files":1, "bytes":4,
                },
                "source_files":["lib.rs"], "args":["lib.rs"],
                "artifacts":{"unit":"compile", "files":["libfixture.rmeta"]},
                "timeout_ms":10000,
            }),
            &bundle,
        )
        .unwrap();
        let store = PreparedOperationStore::open(&root.join("operations")).unwrap();
        let workers = json!([
            {"address":"127.0.0.1:31001", "worker":"one", "worker_spki_sha256":"ab".repeat(32)},
            {"address":"127.0.0.1:31002", "worker":"two", "worker_spki_sha256":"cd".repeat(32)},
        ]);
        let request = |sequence: u64| {
            json!({
                "kind":"prepared-submit-pool", "operation":{
                    "id":format!("{sequence:032x}"), "workers":workers,
                    "bundle":bundle, "delivery":root.join(format!("delivery-{sequence}")),
                    "output":root.join(format!("output-{sequence}")),
                },
            })
        };
        let query = |request: &Value| -> Value {
            serde_json::from_str(&prepared_reply(Some(&store), request)).unwrap()
        };
        let first = query(&request(1));
        assert_eq!(first["kind"], "prepared-operation");
        assert_eq!(first["operation"]["worker"], "one");
        assert_eq!(first["operation"]["request_id"], Value::Null);
        assert_eq!(first["publication_authorized"], false);
        assert_eq!(first["reexecute"], false);
        assert_eq!(query(&request(2))["operation"]["worker"], "two");
        assert_eq!(query(&request(1)), first);
        let mut changed = request(1);
        changed["operation"]["workers"]
            .as_array_mut()
            .unwrap()
            .reverse();
        assert_eq!(query(&changed)["kind"], "prepared-operation-error");
        let mut unknown = request(3);
        unknown["operation"]["workers"][0]["unapproved"] = json!(true);
        assert_eq!(query(&unknown)["kind"], "prepared-operation-error");
        assert!(store.status(&format!("{:032x}", 3)).unwrap().is_none());
    }

    #[test]
    fn prepared_preview_requires_exact_identity_attempt_and_cursor_fields() {
        use crate::coord::prepared_operation::PreparedOperationStore;
        use serde_json::{Value, json};

        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("operations");
        let store = PreparedOperationStore::open(&root).unwrap();
        let id = "0123456789abcdef0123456789abcdef";
        let request = json!({"kind":"prepared-preview", "operation_id":id,
            "request_sha256":"ab".repeat(32), "attempt":1,
            "stdout_offset":0, "stderr_offset":0});
        assert_eq!(request.as_object().unwrap().len(), 6);
        let query = |request: &Value| -> Value {
            serde_json::from_str(&prepared_reply(Some(&store), request)).unwrap()
        };
        assert_eq!(
            query(&request),
            json!({
                "kind":"prepared-preview", "operation_id":id, "request_sha256":"ab".repeat(32),
                "attempt":1, "available":false, "active":false, "reason":"unavailable",
                "segments":[], "complete":false, "publication_authorized":false,
            })
        );
        let refused = |request: &Value| {
            let reply = query(request);
            assert_eq!(reply["kind"], "prepared-operation-error", "{request}");
            assert_eq!(reply["outcome_unconfirmed"], true);
            assert_eq!(reply["reexecute"], false);
            assert!(reply.get("segments").is_none());
        };
        for field in ["attempt", "stdout_offset", "stderr_offset"] {
            for malformed in [Value::Null, json!(-1), json!(1.5), json!("0"), json!(false)] {
                let mut changed = request.clone();
                changed[field] = malformed;
                refused(&changed);
            }
        }
        for field in [
            "kind",
            "operation_id",
            "request_sha256",
            "attempt",
            "stdout_offset",
            "stderr_offset",
        ] {
            let mut changed = request.clone();
            changed.as_object_mut().unwrap().remove(field);
            refused(&changed);
        }
        let mut changed = request.clone();
        changed["execute"] = json!(true);
        refused(&changed);
        assert_eq!(query(&request)["available"], false);
        assert!(store.status(id).unwrap().is_none());
        assert!(!root.join(format!("{id}.json")).exists());
    }

    #[test]
    fn flight_guards_release_on_drop_and_unwind_without_borrowing_other_participants() {
        let coord = Arc::new(crate::coord::live::CoordLive::new());
        coord.mark_up();
        let edge = coord.edge_subscriber();
        assert_eq!(
            edge.begin_flight("key"),
            crate::coord::live::FlightRole::Leader
        );
        let guard = Flight {
            coord: edge.clone(),
            key: "key".into(),
            label: "leader",
        };
        assert_eq!(
            edge.begin_flight("key"),
            crate::coord::live::FlightRole::Follower
        );
        drop(guard);
        let status: serde_json::Value = serde_json::from_str(&edge.status_json()).unwrap();
        assert_eq!(status["open_flights"], 1);
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = Flight {
                coord: edge.clone(),
                key: "key".into(),
                label: "follower",
            };
            panic!("injected connection panic");
        }));
        assert!(panic.is_err());
        let status: serde_json::Value = serde_json::from_str(&edge.status_json()).unwrap();
        assert_eq!(status["open_flights"], 0);
    }

    #[test]
    fn saturated_materialization_refuses_without_writes_or_fallback_authority() {
        let lane = Limit::new(0);
        let coord = Arc::new(crate::coord::live::CoordLive::new());
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("untouched");
        let runtime = RuntimeBuilder::current_thread().build().unwrap();
        let reply = rabs_asupersync::daemon_runtime::block_on_top_level(
            &runtime,
            serve_on_lane(
                &lane,
                coord.edge_subscriber(),
                serde_json::json!({"kind":"serve", "action_key":"01".repeat(32),
                    "destination_root":destination.to_str().unwrap()}),
            ),
        );
        let reply: serde_json::Value = serde_json::from_str(&reply).unwrap();
        assert_eq!(reply["outcome"], "error");
        assert_eq!(reply["materialization_started"], false);
        assert_eq!(reply["installed"], serde_json::json!([]));
        assert_eq!(reply["compiler_skip_authorized"], false);
        assert_eq!(reply["reexecution_authorized"], false);
        assert!(!destination.exists());
        let panic: serde_json::Value =
            serde_json::from_str(&serve_work_error(&WorkError::Panicked, true)).unwrap();
        assert_eq!(panic["materialization_started"], true);
        assert!(
            panic["installed_path_bytes"].is_null(),
            "panic cannot prove no files installed"
        );
        assert_eq!(panic["reexecution_authorized"], false);
    }

    #[test]
    fn actual_serve_yields_while_cas_is_busy() {
        let dir = tempfile::tempdir().unwrap();
        let cas =
            Arc::new(crate::janitor::store::mount_and_reconcile(&dir.path().join("cas")).unwrap());
        let coord = Arc::new(crate::coord::live::CoordLive::with_cas(Arc::clone(&cas)));
        coord.acquire_boot_authority("busy-cas-fixture").unwrap();
        coord.mark_up();
        let lane = Limit::new(1);
        let (ready, ready_rx) = mpsc::channel();
        let (release, release_rx) = mpsc::channel();
        std::thread::scope(|scope| {
            let holder_cas = Arc::clone(&cas);
            let holder = scope.spawn(move || {
                let _store = holder_cas.store().lock().unwrap();
                ready.send(()).unwrap();
                // Bound even the failure case: an inline-I/O regression must
                // fail this test, not deadlock its process indefinitely.
                let _ = release_rx.recv_timeout(Duration::from_secs(3));
            });
            ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            let mut request = Box::pin(serve_on_lane(
                &lane,
                coord.edge_subscriber(),
                serde_json::json!({"kind":"serve", "action_key":"01".repeat(32),
                    "destination_root":dir.path().join("outputs").to_str().unwrap()}),
            ));
            let start = Instant::now();
            assert!(matches!(
                request
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop())),
                Poll::Pending
            ));
            assert!(coord.available());
            assert!(
                start.elapsed() < Duration::from_secs(1),
                "CAS I/O blocked the polling/control thread"
            );
            assert!(lane.acquire().is_none());
            release.send(()).unwrap();
            holder.join().unwrap();
            let runtime = RuntimeBuilder::current_thread().build().unwrap();
            let reply: serde_json::Value = serde_json::from_str(
                &rabs_asupersync::daemon_runtime::block_on_top_level(&runtime, request),
            )
            .unwrap();
            assert_eq!(reply["kind"], "serve-result");
            assert_ne!(reply["outcome"], "served");
            assert!(!dir.path().join("outputs").exists());
        });
    }

    #[test]
    fn live_frame_reader_expires_a_trickling_peer_without_resetting_its_budget() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("edge.sock");
        let runtime = RuntimeBuilder::current_thread().build().unwrap();
        rabs_asupersync::daemon_runtime::block_on_top_level(&runtime, async {
            let listener = UnixListener::bind(&path).await.unwrap();
            let path = path.clone();
            let writer = std::thread::spawn(move || {
                let mut stream = std::os::unix::net::UnixStream::connect(path).unwrap();
                for _ in 0..40 {
                    if stream.write_all(b" ").is_err() {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
            });
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = EdgeStream::with_capacity(FRAME_READ_BUFFER_BYTES, stream);
            let frame = read_frame_with_budget(&mut stream, Duration::from_millis(30)).await;
            assert!(frame.is_none());
            drop(stream);
            writer.join().unwrap();
        });
    }
}
