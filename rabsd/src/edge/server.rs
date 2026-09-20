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
//! Stale-socket takeover: never a blind unlink. If the socket path
//! exists, LIVENESS-PROBE it (connect): a live daemon means this boot
//! REFUSES (typed); only a probe-dead socket file (stale runtime state
//! from a dead incarnation) is removed and taken over, and the takeover
//! is logged.

mod liveness;

use asupersync::cx::Cx;
use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::net::unix::{UnixListener, UnixStream};
use asupersync::signal::ShutdownReceiver;
use liveness::{Limit, WorkError};
use rabs_asupersync::daemon_runtime::SubsystemWork;
use rabs_protocol::socket_admission::{
    AdmissionPolicy, ConnectionEvidence, PeerCredentials, SocketMetadata, TokenContext, admit,
};
use rabs_protocol::version_negotiation::{Negotiation, VersionHello, VersionRange, negotiate};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::time::Duration;

/// Frame size bound (one JSON line).
pub const MAX_FRAME_BYTES: usize = 64 * 1024;
/// Bounds are per edge listener, shared by all of its connections.
pub const MAX_CONNECTIONS: usize = 128;
pub const MAX_REQUESTS_PER_CONNECTION: usize = 64;
const FRAME_IO_BUDGET: Duration = Duration::from_secs(5);
const CONTROL_WORKERS: usize = 2;
const SHADOW_WORKERS: usize = 4;
const MATERIALIZATION_WORKERS: usize = 2;

#[derive(Clone)]
struct EdgeLimits {
    sessions: Limit,
    control: Limit,
    shadow: Limit,
    materialization: Limit,
}
impl EdgeLimits {
    fn new() -> Self {
        Self {
            sessions: Limit::new(MAX_CONNECTIONS),
            control: Limit::new(CONTROL_WORKERS),
            shadow: Limit::new(SHADOW_WORKERS),
            materialization: Limit::new(MATERIALIZATION_WORKERS),
        }
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
}

fn log_line(kind: &str, fields: &[(&str, &str)]) {
    let mut line = format!("{{\"v\":1,\"kind\":\"{kind}\"");
    for (key, value) in fields {
        line.push_str(&format!(",\"{}\":\"{}\"", key, value.replace('"', "'")));
    }
    line.push('}');
    eprintln!("{line}");
}

/// Build the edge [`SubsystemWork`] for [`DaemonRunOptions`].
///
/// [`DaemonRunOptions`]: rabs_asupersync::daemon_runtime::DaemonRunOptions
pub fn edge_work(config: EdgeServerConfig) -> SubsystemWork {
    Box::new(move |cx, shutdown| Box::pin(serve(cx, shutdown, config)))
}

async fn serve(
    cx: Cx,
    mut shutdown: ShutdownReceiver,
    config: EdgeServerConfig,
) -> Result<(), String> {
    // Stale-socket takeover: liveness probe, never blind unlink.
    if config.socket_path.exists() {
        match UnixStream::connect(&config.socket_path).await {
            Ok(_) => {
                return Err(format!(
                    "another rabsd is alive at {} — refusing to take over",
                    config.socket_path.display()
                ));
            }
            Err(_) => {
                log_line(
                    "rabsd-socket-takeover",
                    &[("stale", &config.socket_path.display().to_string())],
                );
                std::fs::remove_file(&config.socket_path)
                    .map_err(|e| format!("stale socket removal failed: {e}"))?;
            }
        }
    }
    if let Some(parent) = config.socket_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let listener = UnixListener::bind(&config.socket_path)
        .await
        .map_err(|e| format!("bind {}: {e}", config.socket_path.display()))?;
    std::fs::set_permissions(&config.socket_path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("socket chmod: {e}"))?;

    // Admission evidence baseline: the socket we just created. The
    // daemon's own uid is the socket owner's uid (we created it).
    let socket_meta = std::fs::metadata(&config.socket_path).map_err(|e| e.to_string())?;
    let expected_uid = socket_meta.uid();
    let policy = AdmissionPolicy {
        expected_uid,
        require_token_on_unix: false,
        tcp_enabled: false,
    };
    let socket_evidence = SocketMetadata {
        owner_uid: socket_meta.uid(),
        mode: socket_meta.mode() & 0o777,
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
    let coord = config.coord.clone();
    let limits = EdgeLimits::new();
    let acceptor = cx
        .spawn(move |cx| accept_loop(cx, listener, policy, socket_evidence, shadow, coord, limits))
        .map_err(|e| format!("acceptor spawn: {e:?}"))?;
    let _ = acceptor_cx.checkpoint();

    shutdown.wait().await;
    acceptor.abort();
    // The socket file is this incarnation's runtime state: remove it on
    // clean shutdown so the next boot needs no takeover.
    let _ = std::fs::remove_file(&config.socket_path);
    Ok(())
}

async fn accept_loop(
    cx: Cx,
    listener: UnixListener,
    policy: AdmissionPolicy,
    socket_evidence: SocketMetadata,
    shadow: std::sync::Arc<std::sync::Mutex<crate::edge::shadow::ShadowPlane>>,
    coord: crate::coord::live::EdgeSubscriber,
    limits: EdgeLimits,
) {
    let mut connection_id: u64 = 0;
    loop {
        match listener.accept().await {
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
                let shadow = std::sync::Arc::clone(&shadow);
                let coord = coord.clone();
                let limits = limits.clone();
                let spawned = cx.spawn(move |cx| async move {
                    if cx.checkpoint().is_ok() {
                        handle_connection(id, stream, policy, socket_evidence, shadow, coord, limits).await;
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
async fn read_frame_with_budget(stream: &mut UnixStream, budget: Duration) -> Option<Vec<u8>> {
    asupersync::time::timeout(asupersync::time::wall_now(), budget, async {
        let mut frame = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            match stream.read(&mut byte).await {
                Ok(0) => return None,
                Ok(_) => {
                    if byte[0] == b'\n' { return Some(frame); }
                    if frame.len() == MAX_FRAME_BYTES { return None; }
                    frame.push(byte[0]);
                }
                Err(_) => return None,
            }
        }
    }).await.ok().flatten()
}

/// None means EOF, a truncated/oversized frame, or an exhausted read budget.
async fn read_frame(stream: &mut UnixStream) -> Option<Vec<u8>> {
    read_frame_with_budget(stream, FRAME_IO_BUDGET).await
}

async fn write_frame(stream: &mut UnixStream, line: &str) -> bool {
    let mut bytes = line.as_bytes().to_vec();
    bytes.push(b'\n');
    asupersync::time::timeout(asupersync::time::wall_now(), FRAME_IO_BUDGET,
        stream.write_all(&bytes)).await.is_ok_and(|result| result.is_ok())
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
    fn drop(&mut self) { self.coord.end_flight(&self.key); }
}

async fn handle_connection(
    id: u64,
    mut stream: UnixStream,
    policy: AdmissionPolicy,
    socket_evidence: SocketMetadata,
    shadow: std::sync::Arc<std::sync::Mutex<crate::edge::shadow::ShadowPlane>>,
    coord: crate::coord::live::EdgeSubscriber,
    limits: EdgeLimits,
) {
    let trace = format!("edge-conn-{id}");
    // Admission: kernel peer credentials against the policy.
    let (peer_uid, peer_gid) = match stream.peer_cred() {
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
        let Some(frame) = read_frame(&mut stream).await else { break; };
        let reply = match serde_json::from_slice::<serde_json::Value>(&frame) {
            Ok(value) if value.get("kind").and_then(|k| k.as_str()) == Some("status") => {
                status_on_lane(&limits.control, coord.clone()).await
            }
            Ok(value) if value.get("kind").and_then(|k| k.as_str()) == Some("consult") => {
                match parse_observation(&value) {
                    Some(observation) => {
                        let shadow = std::sync::Arc::clone(&shadow);
                        let coord = coord.clone();
                        let work_trace = trace.clone();
                        let result = match limits.shadow.spawn(move || {
                            shadow_reply(&work_trace, observation, shadow, coord)
                        }) {
                            Ok(mut work) => work.wait().await,
                            Err(error) => Err(error),
                        };
                        match result {
                            Ok((reply, flight)) => {
                                if let Some(flight) = flight { open_flights.push(flight); }
                                reply
                            }
                            Err(error) => {
                                log_line("rabsd-edge-shadow-error", &[("trace", &trace), ("error", &error.to_string())]);
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
        plane.on_consult(trace, &observation, |key| {
            let role = coord.begin_flight(key);
            if role != crate::coord::live::FlightRole::Degraded {
                joined = Some(Flight { coord: coord.clone(), key: key.to_owned(), label: role.label() });
            }
            role.label()
        }).map_err(|_| ())
    });
    let flight_label = joined.as_ref().map_or("degraded", |flight| flight.label);
    let reply = match decision {
        Ok(decision) => format!(
            "{{\"kind\":\"decision\",\"decision\":\"pass-through\",\
             \"mode\":\"{}\",\"key\":\"{}\",\
             \"hit_upper_bound\":{},\"class\":\"{}\",\
             \"flight\":\"{flight_label}\"}}",
            if coord.available() { "shadow" } else { "shadow-coord-degraded" },
            decision.key_hex, decision.would_have_hit_upper_bound, decision.class,
        ),
        Err(()) => {
            log_line("rabsd-edge-shadow-error", &[("trace", trace), ("key_class", "unknown")]);
            "{\"kind\":\"decision\",\"decision\":\"pass-through\",\"mode\":\"shadow-error\"}".to_owned()
        }
    };
    (reply, joined)
}

async fn status_on_lane(lane: &Limit, coord: crate::coord::live::EdgeSubscriber) -> String {
    // Status can consult release-policy storage and coordinator locks too.
    // Its own lane prevents both inline I/O and bulk-work admission starvation.
    let result = match lane.spawn(move || coord.status_json()) {
        Ok(mut work) => work.wait().await,
        Err(error) => Err(error),
    };
    match result {
        Ok(reply) => reply,
        Err(error) => refusal("status-unavailable", &error.to_string()),
    }
}

async fn serve_on_lane(
    lane: &Limit,
    coord: crate::coord::live::EdgeSubscriber,
    request: serde_json::Value,
) -> String {
    match lane.spawn(move || serve_reply(&coord, &request)) {
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
    fn flight_guards_release_on_drop_and_unwind_without_borrowing_other_participants() {
        let coord = Arc::new(crate::coord::live::CoordLive::new());
        coord.mark_up();
        let edge = coord.edge_subscriber();
        assert_eq!(edge.begin_flight("key"), crate::coord::live::FlightRole::Leader);
        let guard = Flight { coord: edge.clone(), key: "key".into(), label: "leader" };
        assert_eq!(edge.begin_flight("key"), crate::coord::live::FlightRole::Follower);
        drop(guard);
        let status: serde_json::Value = serde_json::from_str(&edge.status_json()).unwrap();
        assert_eq!(status["open_flights"], 1);
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = Flight { coord: edge.clone(), key: "key".into(), label: "follower" };
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
        let reply = runtime.block_on(serve_on_lane(&lane, coord.edge_subscriber(),
            serde_json::json!({"kind":"serve", "action_key":"01".repeat(32),
                "destination_root":destination.to_str().unwrap()})));
        let reply: serde_json::Value = serde_json::from_str(&reply).unwrap();
        assert_eq!(reply["outcome"], "error");
        assert_eq!(reply["materialization_started"], false);
        assert_eq!(reply["installed"], serde_json::json!([]));
        assert_eq!(reply["compiler_skip_authorized"], false);
        assert_eq!(reply["reexecution_authorized"], false);
        assert!(!destination.exists());
        let panic: serde_json::Value = serde_json::from_str(
            &serve_work_error(&WorkError::Panicked, true)).unwrap();
        assert_eq!(panic["materialization_started"], true);
        assert!(panic["installed_path_bytes"].is_null(), "panic cannot prove no files installed");
        assert_eq!(panic["reexecution_authorized"], false);
    }

    #[test]
    fn actual_serve_yields_while_cas_is_busy() {
        let dir = tempfile::tempdir().unwrap();
        let cas = Arc::new(crate::janitor::store::mount_and_reconcile(&dir.path().join("cas")).unwrap());
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
            let mut request = Box::pin(serve_on_lane(&lane, coord.edge_subscriber(),
                serde_json::json!({"kind":"serve", "action_key":"01".repeat(32),
                    "destination_root":dir.path().join("outputs").to_str().unwrap()})));
            let start = Instant::now();
            assert!(matches!(request.as_mut().poll(&mut Context::from_waker(Waker::noop())), Poll::Pending));
            assert!(coord.available());
            assert!(start.elapsed() < Duration::from_secs(1), "CAS I/O blocked the polling/control thread");
            assert!(lane.acquire().is_none());
            release.send(()).unwrap();
            holder.join().unwrap();
            let runtime = RuntimeBuilder::current_thread().build().unwrap();
            let reply: serde_json::Value = serde_json::from_str(&runtime.block_on(request)).unwrap();
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
        runtime.block_on(async {
            let listener = UnixListener::bind(&path).await.unwrap();
            let path = path.clone();
            let writer = std::thread::spawn(move || {
                let mut stream = std::os::unix::net::UnixStream::connect(path).unwrap();
                for _ in 0..40 {
                    if stream.write_all(b" ").is_err() { break; }
                    std::thread::sleep(Duration::from_millis(5));
                }
            });
            let (mut stream, _) = listener.accept().await.unwrap();
            let frame = read_frame_with_budget(&mut stream, Duration::from_millis(30)).await;
            assert!(frame.is_none());
            drop(stream);
            writer.join().unwrap();
        });
    }
}
