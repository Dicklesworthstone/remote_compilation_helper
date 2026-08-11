//! The edge UDS server (bead S3 / bridge plan Phase S). Runs INSIDE the
//! S1 edge region as its [`SubsystemWork`]: every wrapper consult flows
//! through the REAL modules — `socket_admission` per connection,
//! `version_negotiation` per handshake — with one region-owned task per
//! connection (aborted on shutdown, so a hung client can never wedge the
//! daemon; verified by the kill-mid-frame test).
//!
//! Wire format (S3 skeleton; S4 enriches the consult): newline-delimited
//! JSON, one frame per line, 64 KiB bound. A malformed frame is a typed
//! refusal reply and a closed connection — never a panic (fuzzed against
//! the LIVE socket).
//!
//! Stale-socket takeover: never a blind unlink. If the socket path
//! exists, LIVENESS-PROBE it (connect): a live daemon means this boot
//! REFUSES (typed); only a probe-dead socket file (stale runtime state
//! from a dead incarnation) is removed and taken over, and the takeover
//! is logged.

use rabs_asupersync::asupersync::cx::Cx;
use rabs_asupersync::asupersync::io::{AsyncReadExt, AsyncWriteExt};
use rabs_asupersync::asupersync::net::unix::{UnixListener, UnixStream};
use rabs_asupersync::asupersync::signal::ShutdownReceiver;
use rabs_asupersync::daemon_runtime::SubsystemWork;
use rabs_protocol::socket_admission::{
    AdmissionPolicy, ConnectionEvidence, PeerCredentials, SocketMetadata, TokenContext, admit,
};
use rabs_protocol::version_negotiation::{Negotiation, VersionHello, VersionRange, negotiate};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;

/// Frame size bound (one JSON line).
pub const MAX_FRAME_BYTES: usize = 64 * 1024;

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
#[must_use]
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

    // Acceptor as a region-owned child task; aborted at shutdown so a
    // blocked accept (or a hung connection it spawned) cannot wedge us.
    let acceptor_cx = cx.clone();
    let acceptor = cx
        .spawn(move |cx| accept_loop(cx, listener, policy, socket_evidence, shadow))
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
) {
    let mut connection_id: u64 = 0;
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                connection_id += 1;
                let id = connection_id;
                let shadow = std::sync::Arc::clone(&shadow);
                let spawned = cx.spawn(move |cx| async move {
                    let _ = cx.checkpoint();
                    handle_connection(id, stream, policy, socket_evidence, shadow).await;
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

/// Read one newline-terminated frame (bounded). None = EOF/oversize.
async fn read_frame(stream: &mut UnixStream) -> Option<Vec<u8>> {
    let mut frame = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte).await {
            Ok(0) => return None,
            Ok(_) => {
                if byte[0] == b'\n' {
                    return Some(frame);
                }
                frame.push(byte[0]);
                if frame.len() > MAX_FRAME_BYTES {
                    return None;
                }
            }
            Err(_) => return None,
        }
    }
}

async fn write_frame(stream: &mut UnixStream, line: &str) -> bool {
    let mut bytes = line.as_bytes().to_vec();
    bytes.push(b'\n');
    stream.write_all(&bytes).await.is_ok()
}

fn refusal(reason: &str, detail: &str) -> String {
    format!(
        "{{\"kind\":\"refusal\",\"reason\":\"{reason}\",\"detail\":\"{}\"}}",
        detail.replace('"', "'")
    )
}

async fn handle_connection(
    id: u64,
    mut stream: UnixStream,
    policy: AdmissionPolicy,
    socket_evidence: SocketMetadata,
    shadow: std::sync::Arc<std::sync::Mutex<crate::edge::shadow::ShadowPlane>>,
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
        return; // EOF/oversize before hello: nothing to answer
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

    // Consult loop: the S4 shadow decision plane. Every consult with a
    // full observation computes a REAL Epic F key, records a receipt,
    // and answers pass-through; consults without argv (legacy/summary
    // frames) pass through unshadowed, loudly labeled.
    while let Some(frame) = read_frame(&mut stream).await {
        let reply = match serde_json::from_slice::<serde_json::Value>(&frame) {
            Ok(value) if value.get("kind").and_then(|k| k.as_str()) == Some("consult") => {
                match parse_observation(&value) {
                    Some(observation) => {
                        let decision = shadow.lock().map_err(|_| ()).and_then(|mut plane| {
                            plane.on_consult(&trace, &observation).map_err(|_| ())
                        });
                        match decision {
                            Ok(decision) => format!(
                                "{{\"kind\":\"decision\",\"decision\":\"pass-through\",\
                                 \"mode\":\"shadow\",\"key\":\"{}\",\
                                 \"hit_upper_bound\":{},\"class\":\"{}\"}}",
                                decision.key_hex,
                                decision.would_have_hit_upper_bound,
                                decision.class,
                            ),
                            Err(()) => "{\"kind\":\"decision\",\"decision\":\"pass-through\",\
                                 \"mode\":\"shadow-error\"}"
                                .to_string(),
                        }
                    }
                    None => "{\"kind\":\"decision\",\"decision\":\"pass-through\",\
                         \"mode\":\"unshadowed\"}"
                        .to_string(),
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
            return;
        }
    }
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
