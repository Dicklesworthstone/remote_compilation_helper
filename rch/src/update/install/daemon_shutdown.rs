//! Confirm daemon shutdown and restart during an update or rollback.
//!
//! This is deliberately not the interactive `daemon stop` path: an update never
//! authorizes killing a process, removing a socket, or interrupting a build.

use crate::commands::daemon::{DaemonProcess, MaintenanceFence, MaintenanceSignals};
use rch_common::RestartAdmissionResponse as Admission;
use rch_common::process_identity::OwnerPresence;
use serde::Deserialize;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::{Instant, sleep, timeout};

const MAX_REPLY_BYTES: u64 = 1024 * 1024;
const ADMISSION_STATUS: &str = "GET /restart-admission\n";
#[cfg(test)]
const CLOSE_ADMISSION: &str = "POST /restart-admission\n";
#[cfg(test)]
const SHUTDOWN: &str = "POST /shutdown\n";
#[cfg(test)]
const RELEASE_ADMISSION: &str = "POST /restart-admission/release\n";
#[cfg(test)]
const RENEW_ADMISSION: &str = "POST /restart-admission/renew\n";
const STATUS: &str = "GET /status\n";

#[derive(Clone, Copy)]
struct Timing {
    request: Duration,
    shutdown: Duration,
    poll: Duration,
    renew: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            request: Duration::from_secs(5),
            shutdown: Duration::from_secs(10),
            poll: Duration::from_millis(100),
            renew: Duration::from_secs(1),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SocketIdentity {
    device: u64,
    inode: u64,
}

async fn socket_identity(path: &Path) -> Result<Option<SocketIdentity>, String> {
    match tokio::fs::symlink_metadata(path).await {
        Ok(metadata) if metadata.file_type().is_socket() => Ok(Some(SocketIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        })),
        Ok(_) => Err(format!(
            "daemon endpoint is not a Unix socket: {}",
            path.display()
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!(
            "cannot inspect daemon endpoint {}: {error}",
            path.display()
        )),
    }
}

/// Every workload field is required. A partial or old response is not proof
/// that there are no builds or unacknowledged client leases. The nullable scan
/// error must be present; an explicit null confirms that the scan succeeded.
fn admission_idle(admission: &Admission) -> bool {
    admission.active_build_ids.is_empty()
        && admission.queued_build_ids.is_empty()
        && admission.client_lease_ids.is_empty()
        && admission.client_lease_scan_error.is_none()
        && !admission.ownership_failed
}

fn decode_reply<T: serde::de::DeserializeOwned>(reply: &[u8]) -> Result<T, String> {
    if reply.len() as u64 > MAX_REPLY_BYTES {
        return Err("oversized daemon reply; update refused".to_owned());
    }
    let reply = std::str::from_utf8(reply).map_err(|_| "non-UTF-8 daemon reply")?;
    let (header, body) = reply
        .split_once("\r\n\r\n")
        .or_else(|| reply.split_once("\n\n"))
        .ok_or("incomplete daemon reply")?;
    let mut status = header.lines().next().unwrap_or_default().split_whitespace();
    if !matches!(status.next(), Some("HTTP/1.0" | "HTTP/1.1")) || status.next() != Some("200") {
        return Err("daemon refused the update's lifecycle request".to_owned());
    }
    serde_json::from_str(body).map_err(|error| format!("invalid daemon reply: {error}"))
}

async fn request<T: serde::de::DeserializeOwned>(
    path: &Path,
    expected: SocketIdentity,
    command: &str,
    budget: Duration,
) -> Result<T, String> {
    request_capture(path, expected, command, budget, false)
        .await
        .map(|(reply, _)| reply)
}

async fn request_capture<T: serde::de::DeserializeOwned>(
    path: &Path,
    expected: SocketIdentity,
    command: &str,
    budget: Duration,
    require_peer: bool,
) -> Result<(T, Option<DaemonProcess>), String> {
    timeout(budget, async {
        if socket_identity(path).await? != Some(expected) {
            return Err("daemon endpoint changed; update refused".to_owned());
        }
        let mut stream = UnixStream::connect(path)
            .await
            .map_err(|error| format!("cannot connect to daemon: {error}"))?;
        // Do not send a mutation to a replacement endpoint found while connecting.
        if socket_identity(path).await? != Some(expected) {
            return Err("daemon endpoint changed during connection; update refused".to_owned());
        }
        let peer = if require_peer {
            Some(DaemonProcess::from_peer(&stream).map_err(|error| error.to_string())?)
        } else {
            None
        };
        stream
            .write_all(command.as_bytes())
            .await
            .map_err(|error| error.to_string())?;
        stream.shutdown().await.map_err(|error| error.to_string())?;
        let mut bytes = Vec::new();
        stream
            .take(MAX_REPLY_BYTES + 1)
            .read_to_end(&mut bytes)
            .await
            .map_err(|error| error.to_string())?;
        if let Some(peer) = &peer {
            peer.require_live().map_err(|error| error.to_string())?;
        }
        Ok((decode_reply(&bytes)?, peer))
    })
    .await
    .map_err(|_| "daemon lifecycle request timed out; update refused".to_owned())?
}

#[derive(Deserialize)]
struct ReadyStatus {
    daemon: ReadyDaemon,
}

#[derive(Deserialize)]
struct ReadyDaemon {
    pid: u32,
    version: String,
    socket_path: String,
}

/// Both replies must come from one kernel-identified peer at one socket inode.
/// Readiness means the installed version answers and admission is open, not
/// that the fleet is healthy or idle. New builds may already have arrived.
async fn probe_ready(
    path: &Path,
    identity: SocketIdentity,
    version: Option<&str>,
    budget: Duration,
) -> Result<u32, String> {
    let (status, peer): (ReadyStatus, _) =
        request_capture(path, identity, STATUS, budget, true).await?;
    if peer.as_ref().map(|peer| peer.pid) != Some(status.daemon.pid)
        || Path::new(&status.daemon.socket_path) != path
        || status.daemon.version.is_empty()
        || status.daemon.version.chars().any(char::is_control)
        || version.is_some_and(|expected| expected != status.daemon.version)
    {
        return Err("daemon identity, socket or installed version mismatch".to_owned());
    }
    let (admission, second_peer): (Admission, _) =
        request_capture(path, identity, ADMISSION_STATUS, budget, true).await?;
    if second_peer != peer || socket_identity(path).await? != Some(identity) {
        return Err("daemon endpoint changed while confirming readiness".to_owned());
    }
    if !admission.success
        || admission.admission_closed
        || admission.maintenance_closed
        || admission.shutdown_committed
        || admission.ownership_failed
        || admission.maintenance_owner.is_some()
        || admission.client_lease_scan_error.is_some()
        || uuid::Uuid::parse_str(&admission.daemon_incarnation).is_err()
    {
        return Err("daemon is responding but admission is unavailable".to_owned());
    }
    Ok(status.daemon.pid)
}

fn launcher_status(
    child: &mut Option<tokio::process::Child>,
) -> Result<Option<std::process::ExitStatus>, String> {
    let status = match child {
        Some(child) => child
            .try_wait()
            .map_err(|error| format!("cannot inspect daemon launcher: {error}"))?,
        None => None,
    };
    if let Some(status) = status
        && !status.success()
    {
        return Err(format!(
            "installed daemon launcher exited {status}; restart failed"
        ));
    }
    Ok(status)
}

pub(super) async fn start(
    command: std::process::Command,
    path: &Path,
    version: Option<&str>,
) -> Result<(), String> {
    start_with_timing(
        command,
        path,
        version,
        Duration::from_secs(30),
        Timing::default(),
    )
    .await
}

/// A service manager may already have respawned the installed daemon, or the
/// exact installed launcher may exit successfully after delegating to it. In
/// either case success still requires real, version-bound endpoint evidence.
/// No second spawn, process-name kill, socket unlink or admission mutation is
/// used as a fallback. A timeout may leave a live daemon; report uncertainty
/// rather than killing a process that could already have accepted new work.
async fn start_with_timing(
    mut command: std::process::Command,
    path: &Path,
    version: Option<&str>,
    startup: Duration,
    timing: Timing,
) -> Result<(), String> {
    if startup.is_zero() {
        return Err("daemon readiness budget must be nonzero".to_owned());
    }
    let mut last_error = "daemon endpoint has not appeared".to_owned();
    let result = timeout(startup, async {
        let executable = Path::new(command.get_program());
        if !executable.is_absolute() || !path.is_absolute() {
            return Err("daemon executable and socket must be absolute paths".to_owned());
        }
        let metadata = tokio::fs::symlink_metadata(executable)
            .await
            .map_err(|error| format!("cannot inspect installed daemon: {error}"))?;
        if !metadata.is_file() {
            return Err("installed daemon is not a regular file".to_owned());
        }
        let mut identity = socket_identity(path).await?;
        let mut child = if identity.is_none() {
            // Do not keep the updater's JSON/output pipes or terminal open in
            // a long-lived daemon. rchd maintains its own configured log files.
            command
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
            Some(
                tokio::process::Command::from(command)
                    .spawn()
                    .map_err(|error| format!("cannot launch installed daemon: {error}"))?,
            )
        } else {
            // Never spawn over even an unresponsive existing socket. It can
            // belong to a service manager that won the startup race.
            None
        };
        let launched_pid = child.as_ref().and_then(tokio::process::Child::id);
        loop {
            launcher_status(&mut child)?;
            let observed = socket_identity(path).await?;
            if identity.is_some() && observed != identity {
                return Err(
                    "daemon endpoint was replaced during startup; restart unconfirmed".to_owned(),
                );
            }
            if let Some(current) = observed {
                identity = Some(current);
                match probe_ready(path, current, version, timing.request).await {
                    Ok(peer) => {
                        let exited = launcher_status(&mut child)?;
                        match launched_pid {
                            Some(pid) if pid == peer && exited.is_some() => {
                                return Err(
                                    "daemon exited after replying; restart failed".to_owned()
                                );
                            }
                            Some(pid) if pid != peer && exited.is_none() => {
                                last_error =
                                    "daemon launcher has not confirmed service-manager handoff"
                                        .to_owned();
                            }
                            _ => return Ok(()),
                        }
                    }
                    Err(error) => last_error = error,
                }
            }
            sleep(timing.poll).await;
        }
    })
    .await;
    match result {
        Ok(result) => result,
        Err(_) => Err(format!(
            "daemon readiness timed out after {startup:?}: {last_error}; installed files and any running daemon retained"
        )),
    }
}

pub(super) async fn stop(
    path: &Path,
    drain_timeout: Duration,
    signals: &mut MaintenanceSignals,
) -> Result<bool, String> {
    stop_with_cancellation(path, drain_timeout, Timing::default(), signals.cancelled()).await
}

#[cfg(test)]
async fn stop_with_timing(
    path: &Path,
    drain_timeout: Duration,
    timing: Timing,
) -> Result<bool, String> {
    let mut signals = MaintenanceSignals::new().map_err(|error| error.to_string())?;
    stop_with_cancellation(path, drain_timeout, timing, signals.cancelled()).await
}

async fn stop_with_cancellation(
    path: &Path,
    drain_timeout: Duration,
    timing: Timing,
    cancellation: impl std::future::Future<Output = ()>,
) -> Result<bool, String> {
    tokio::pin!(cancellation);
    let Some(identity) = socket_identity(path).await? else {
        return Ok(false);
    };
    let (admission, process) = tokio::select! {
        biased;
        _ = &mut cancellation => return Err("update maintenance cancelled before admission changed".into()),
        result = prepare_admission(path, identity, timing) => result?,
    };
    let fence = MaintenanceFence::new(&admission).map_err(|error| error.to_string())?;
    let mut attempted = false;
    let result = tokio::select! {
        biased;
        _ = &mut cancellation => Err("update maintenance cancelled by signal; installation not started".into()),
        result = async {
            // Set before transport so a lost acquisition reply still has an
            // exact token to release. Neither error nor cancellation can
            // turn this token into authority over another operation.
            attempted = true;
            shutdown_owned(path, identity, &process, &fence, drain_timeout, timing).await
        } => result,
    };
    match result {
        Ok(stopped) => Ok(stopped),
        Err(error) if attempted => {
            let cleanup = release_owned(path, identity, &fence, timing).await;
            match cleanup {
                Ok(confirmed) => Err(format!("{error}; {confirmed}")),
                Err(cleanup) => Err(format!("{error}; {cleanup}")),
            }
        }
        Err(error) => Err(error),
    }
}

async fn prepare_admission(
    path: &Path,
    identity: SocketIdentity,
    timing: Timing,
) -> Result<(Admission, DaemonProcess), String> {
    let (admission, process): (Admission, _) =
        request_capture(path, identity, ADMISSION_STATUS, timing.request, true).await?;
    if admission.admission_closed {
        return Err("daemon admission is already closed; update will not take over another maintenance operation".to_owned());
    }
    if !admission.success
        || admission.ownership_failed
        || admission.client_lease_scan_error.is_some()
    {
        return Err(format!(
            "cannot prove daemon ownership: {admission:?}; update refused"
        ));
    }
    Ok((
        admission,
        process.ok_or("original daemon identity was not captured")?,
    ))
}

async fn shutdown_owned(
    path: &Path,
    identity: SocketIdentity,
    process: &DaemonProcess,
    fence: &MaintenanceFence,
    drain_timeout: Duration,
    timing: Timing,
) -> Result<bool, String> {
    let mut grant: Admission = request(
        path,
        identity,
        &fence.acquire_command("update"),
        timing.request,
    )
    .await
    .map_err(|error| {
        format!(
            "{error}; admission ownership is unconfirmed, no shutdown or installation attempted"
        )
    })?;
    let deadline = Instant::now()
        .checked_add(drain_timeout)
        .ok_or("update drain timeout is out of range")?;
    loop {
        fence
            .require_owned(&grant)
            .map_err(|error| error.to_string())?;
        if grant.client_lease_scan_error.is_some() || grant.ownership_failed {
            return Err(format!(
                "cannot prove daemon idle: {grant:?}; update refused"
            ));
        }
        if admission_idle(&grant) {
            if !grant.restart_permitted {
                return Err(format!(
                    "daemon did not grant an idle restart: {grant:?}; update refused"
                ));
            }
            break;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(format!(
                "update drain timed out with work still in flight: {grant:?}; daemon left running"
            ));
        }
        sleep(timing.renew.min(remaining)).await;
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(format!(
                "update drain timed out with work still in flight: {grant:?}; daemon left running"
            ));
        }
        grant = request(
            path,
            identity,
            &fence.command("/restart-admission/renew"),
            timing.request.min(remaining),
        )
        .await?;
    }
    let reply: Admission = request(path, identity, &fence.command("/shutdown"), timing.request)
        .await
        .map_err(|error| format!("{error}; shutdown is unconfirmed, installation not started"))?;
    fence
        .require_shutdown(&reply, false)
        .map_err(|error| format!("{error}; installation not started"))?;
    let deadline = Instant::now()
        .checked_add(timing.shutdown)
        .ok_or("update shutdown timeout is out of range")?;
    loop {
        let presence = process.presence();
        match socket_identity(path).await? {
            None if presence == OwnerPresence::Absent => return Ok(true),
            None => {}
            Some(current) if current != identity => {
                return Err("a replacement daemon endpoint appeared during shutdown; installation not started".to_owned());
            }
            Some(_) => {}
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(format!(
                "daemon acknowledged shutdown but original process exit and endpoint retirement are unconfirmed (PID {} is {presence:?}); installation not started, no process killed or socket removed",
                process.pid
            ));
        }
        sleep(timing.poll.min(remaining)).await;
    }
}

async fn release_owned(
    path: &Path,
    identity: SocketIdentity,
    fence: &MaintenanceFence,
    timing: Timing,
) -> Result<&'static str, String> {
    // Preserve the updater's inode boundary as well as the new daemon fence.
    // A replacement endpoint is never sent a mutation by this transaction.
    if socket_identity(path).await? != Some(identity) {
        return Err("admission release unconfirmed: original daemon endpoint retired or changed; replacement admission was not modified".into());
    }
    let released: Result<Admission, String> = request(
        path,
        identity,
        &fence.command("/restart-admission/release"),
        timing.request,
    )
    .await;
    let observed: Admission = request(path, identity, ADMISSION_STATUS, timing.request)
        .await
        .map_err(|error| format!("admission reopening unconfirmed: {error}; release acknowledgement: {released:?}; uncommitted maintenance expires without renewal; inspect `rch daemon admission status`"))?;
    fence.verify_open(&observed).map_err(|error| {
        format!("{error}; release acknowledgement: {released:?}; inspect `rch daemon admission status` and `rch daemon admission recover`")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    use tokio::net::UnixListener;

    fn timing() -> Timing {
        Timing {
            request: Duration::from_millis(200),
            shutdown: Duration::from_millis(100),
            poll: Duration::from_millis(2),
            renew: Duration::from_millis(2),
        }
    }

    fn admission(closed: bool, granted: bool) -> Value {
        json!({
            "success": true,
            "status": if closed { "maintenance_active" } else { "open" },
            "message": null,
            "daemon_incarnation": "a12ca740-4c39-4486-9872-1490f0b6c263",
            "admission_closed": closed,
            "maintenance_closed": closed,
            "ownership_failed": false,
            "ownership_error": null,
            "shutdown_committed": false,
            "maintenance_owner": if closed {
                json!({
                    "token": "d677a464-a969-49e7-b471-9580b7f6f6f7",
                    "pid": std::process::id(),
                    "process_identity": rch_common::process_identity::current_process_identity()
                        .expect("test process has a birth identity"),
                    "purpose": "update",
                    "generation": 1,
                    "acquired_unix_ms": 100,
                    "deadline_unix_ms": 30100,
                    "remaining_ms": 30000,
                    "owner_presence": "live"
                })
            } else { Value::Null },
            "last_recovery": null,
            "restart_permitted": granted,
            "active_build_ids": [],
            "queued_build_ids": [],
            "client_lease_ids": [],
            "client_lease_scan_error": null
        })
    }

    fn verify_command(command: &str, expected: &str) -> Option<String> {
        let command = command.trim_end();
        if expected.starts_with("POST ") {
            let (route, query) = command
                .split_once('?')
                .expect("mutation must carry a fence");
            assert_eq!(route, expected.trim_end());
            let fields: std::collections::HashMap<_, _> = query
                .split('&')
                .map(|field| field.split_once('=').unwrap())
                .collect();
            assert_eq!(
                fields.get("daemon_incarnation"),
                Some(&"a12ca740-4c39-4486-9872-1490f0b6c263")
            );
            let token = *fields.get("token").unwrap();
            uuid::Uuid::parse_str(token).expect("client-generated operation UUID");
            if expected == CLOSE_ADMISSION {
                let claim = *fields
                    .get("owner_identity")
                    .expect("acquisition requires the caller's process birth identity");
                let identity = rch_common::process_identity::current_process_identity().unwrap();
                assert_eq!(identity.to_record().as_deref(), Some(claim));
                assert_eq!(
                    rch_common::process_identity::ProcessIdentity::from_record(claim),
                    Some(identity)
                );
            } else {
                assert!(!fields.contains_key("owner_identity"));
            }
            Some(token.into())
        } else {
            assert_eq!(command, expected.trim_end());
            None
        }
    }

    async fn answer(listener: &UnixListener, expected: &str, mut value: Value) {
        let (mut stream, _) = timeout(Duration::from_secs(2), listener.accept())
            .await
            .unwrap()
            .unwrap();
        let mut command = String::new();
        stream.read_to_string(&mut command).await.unwrap();
        let token = verify_command(&command, expected);
        if expected == SHUTDOWN && value.get("admission_closed").is_none() {
            let mut complete = admission(true, true);
            for (name, field) in value.as_object().unwrap() {
                complete[name] = field.clone();
            }
            complete["shutdown_committed"] = json!(value["status"] == "shutting_down");
            value = complete;
        }
        if let Some(token) = token
            && value["maintenance_owner"].is_object()
        {
            value["maintenance_owner"]["token"] = token.into();
        }
        stream
            .write_all(format!("HTTP/1.1 200 OK\r\n\r\n{value}").as_bytes())
            .await
            .unwrap();
    }

    fn start_command(script: &str) -> std::process::Command {
        let mut command = std::process::Command::new(std::fs::canonicalize("/bin/sh").unwrap());
        command.args(["-c", script, "readiness-fixture"]);
        command
    }

    fn ready_status(socket: &Path) -> Value {
        json!({"daemon": {"pid": std::process::id(), "version": "9.1.2",
                          "socket_path": socket}})
    }

    async fn serve_readiness(listener: &UnixListener, status: Value, admission: Value) {
        let _ = timeout(Duration::from_millis(200), async {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut command = String::new();
                stream.read_to_string(&mut command).await.unwrap();
                let value = match command.as_str() {
                    STATUS => &status,
                    ADMISSION_STATUS => &admission,
                    // The client's deadline can drop a connection before it
                    // sends a request. An empty request mutates nothing.
                    "" => continue,
                    other => panic!("readiness must not mutate daemon state: {other}"),
                };
                // A deadline may drop the client's socket while this fixture
                // is replying. That is expected, not a fixture panic.
                let _ = stream
                    .write_all(format!("HTTP/1.1 200 OK\r\n\r\n{value}").as_bytes())
                    .await;
            }
        })
        .await;
    }

    #[tokio::test]
    async fn update_start_confirms_existing_ready_daemon_without_spawning_over_it() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("custom : daemon.sock");
        let marker = directory.path().join("must-not-spawn");
        let listener = UnixListener::bind(&socket).unwrap();
        let before = socket_identity(&socket).await.unwrap();
        let mut command = start_command("printf spawned > \"$1\"");
        command.arg(&marker);
        let server = async {
            answer(&listener, STATUS, ready_status(&socket)).await;
            let mut available = admission(false, false);
            // Ready does not mean idle: admitting work is the desired result.
            available["active_build_ids"] = json!([41]);
            answer(&listener, ADMISSION_STATUS, available).await;
        };
        let (result, ()) = tokio::join!(
            start_with_timing(
                command,
                &socket,
                Some("9.1.2"),
                Duration::from_secs(1),
                timing(),
            ),
            server,
        );
        result.unwrap();
        assert!(!marker.exists());
        assert_eq!(socket_identity(&socket).await.unwrap(), before);
    }

    #[tokio::test]
    async fn update_start_rejects_wrong_identity_version_path_and_unavailable_admission() {
        for case in 0..7 {
            let directory = tempfile::tempdir().unwrap();
            let socket = directory.path().join("daemon.sock");
            let marker = directory.path().join("must-not-spawn");
            let listener = UnixListener::bind(&socket).unwrap();
            let before = socket_identity(&socket).await.unwrap();
            let mut status = ready_status(&socket);
            let mut available = admission(false, false);
            match case {
                0 => status["daemon"]["pid"] = json!(u32::MAX),
                1 => status["daemon"]["version"] = json!("old-version"),
                2 => status["daemon"]["socket_path"] = json!("/another/socket"),
                3 => status["daemon"] = json!({"pid": std::process::id()}),
                4 => available["admission_closed"] = json!(true),
                5 => available["client_lease_scan_error"] = json!("permission denied"),
                6 => available = json!({"admission_closed": false}),
                _ => unreachable!(),
            }
            let mut command = start_command("printf spawned > \"$1\"");
            command.arg(&marker);
            let (result, ()) = tokio::join!(
                start_with_timing(
                    command,
                    &socket,
                    Some("9.1.2"),
                    Duration::from_millis(100),
                    timing(),
                ),
                serve_readiness(&listener, status, available),
            );
            assert!(result.is_err(), "case {case}");
            assert!(!marker.exists());
            assert_eq!(socket_identity(&socket).await.unwrap(), before);
        }
    }

    #[tokio::test]
    async fn update_start_refuses_failed_launcher_and_zero_exit_without_ready_api() {
        for script in ["exit 17", "exit 0"] {
            let directory = tempfile::tempdir().unwrap();
            let socket = directory.path().join("daemon.sock");
            let result = start_with_timing(
                start_command(script),
                &socket,
                Some("9.1.2"),
                Duration::from_millis(100),
                timing(),
            )
            .await
            .unwrap_err();
            if script == "exit 17" {
                assert!(result.contains("launcher exited"), "{result}");
            } else {
                assert!(result.contains("readiness timed out"), "{result}");
            }
            assert!(!socket.exists());
        }
    }

    #[tokio::test]
    async fn update_start_retains_unresponsive_and_non_socket_endpoints() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("daemon.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let before = socket_identity(&socket).await.unwrap();
        let began = Instant::now();
        let error = start_with_timing(
            start_command("exit 19"),
            &socket,
            Some("9.1.2"),
            Duration::from_millis(50),
            timing(),
        )
        .await
        .unwrap_err();
        assert!(error.contains("readiness timed out"), "{error}");
        assert!(began.elapsed() < Duration::from_secs(1));
        assert_eq!(socket_identity(&socket).await.unwrap(), before);
        drop(listener);
        let ordinary = directory.path().join("ordinary");
        std::fs::write(&ordinary, b"keep").unwrap();
        assert!(
            start_with_timing(
                start_command("exit 19"),
                &ordinary,
                Some("9.1.2"),
                Duration::from_millis(50),
                timing(),
            )
            .await
            .unwrap_err()
            .contains("not a Unix socket")
        );
        assert_eq!(std::fs::read(&ordinary).unwrap(), b"keep");
    }

    #[tokio::test]
    async fn update_start_does_not_adopt_replacement_endpoint() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("daemon.sock");
        let retained = directory.path().join("retained.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = async {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut command = String::new();
            stream.read_to_string(&mut command).await.unwrap();
            assert_eq!(command, STATUS);
            std::fs::rename(&socket, &retained).unwrap();
            let replacement = UnixListener::bind(&socket).unwrap();
            stream
                .write_all(format!("HTTP/1.1 200 OK\r\n\r\n{}", ready_status(&socket)).as_bytes())
                .await
                .unwrap();
            drop(stream);
            assert!(
                timeout(Duration::from_millis(100), replacement.accept())
                    .await
                    .is_err()
            );
        };
        let (result, ()) = tokio::join!(
            start_with_timing(
                start_command("exit 19"),
                &socket,
                Some("9.1.2"),
                Duration::from_secs(1),
                timing(),
            ),
            server,
        );
        assert!(result.unwrap_err().contains("replaced during startup"));
        assert!(socket.exists() && retained.exists());
    }

    #[tokio::test]
    async fn update_start_requires_absolute_executable_and_nonzero_budget_before_spawn() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("daemon.sock");
        let mut relative = std::process::Command::new("rchd");
        relative.arg("--socket").arg(&socket);
        assert!(
            start_with_timing(relative, &socket, None, Duration::from_secs(1), timing())
                .await
                .unwrap_err()
                .contains("absolute")
        );
        assert!(
            start_with_timing(
                start_command("exit 19"),
                &socket,
                None,
                Duration::ZERO,
                timing(),
            )
            .await
            .unwrap_err()
            .contains("nonzero")
        );
        assert!(!socket.exists());
    }

    /// A real child binds its socket and identifies itself using its own PID.
    /// It self-terminates after a bounded fixture lifetime; no real daemon,
    /// service manager, user configuration or shared socket is touched.
    const READY_CHILD: &str = r#"import json, os, socket, stat, sys, time
path, done, mode = sys.argv[1:]
null = os.stat(os.devnull)
for descriptor in (0, 1, 2):
    metadata = os.fstat(descriptor)
    assert stat.S_ISCHR(metadata.st_mode) and metadata.st_rdev == null.st_rdev
if mode == 'delegated' and os.fork() != 0:
    sys.exit(0)
if mode == 'delayed':
    time.sleep(0.05)
server = socket.socket(socket.AF_UNIX)
server.bind(path)
server.listen(4)
server.settimeout(0.05)
deadline = time.monotonic() + 1.0
while time.monotonic() < deadline:
    try:
        connection, _ = server.accept()
    except TimeoutError:
        continue
    with connection:
        connection.settimeout(0.2)
        data = b''
        while True:
            chunk = connection.recv(4096)
            if not chunk:
                break
            data += chunk
        if data == b'GET /status\n':
            value = {'daemon': {'pid': os.getpid(), 'version': '9.1.2', 'socket_path': path}}
        elif data == b'GET /restart-admission\n':
            value = {'admission_closed': False, 'restart_permitted': False,
                     'active_build_ids': [], 'queued_build_ids': [], 'client_lease_ids': [],
                     'client_lease_scan_error': None,
                     'success': True, 'status': 'open',
                     'daemon_incarnation': 'a12ca740-4c39-4486-9872-1490f0b6c263',
                     'maintenance_closed': False, 'ownership_failed': False,
                     'shutdown_committed': False, 'maintenance_owner': None}
        else:
            raise ValueError('unexpected mutation: ' + repr(data))
        connection.sendall(b'HTTP/1.1 200 OK\r\n\r\n' + json.dumps(value).encode())
server.close()
# Publish atomically: the test polls for `done` and reads it at once.
with open(done + '.tmp', 'w') as output:
    output.write('finished')
os.replace(done + '.tmp', done)
"#;

    #[tokio::test]
    async fn update_start_waits_for_real_child_and_detaches_output_pipes() {
        for mode in ["immediate", "delayed", "delegated"] {
            let directory = tempfile::tempdir().unwrap();
            let socket = directory.path().join("custom : daemon.sock");
            let fixture = directory.path().join("child.py");
            let done = directory.path().join("done");
            std::fs::write(&fixture, READY_CHILD).unwrap();
            let mut command = start_command("exec python3 -I -S \"$@\"");
            command.arg(&fixture).arg(&socket).arg(&done).arg(mode);
            // Even an explicitly piped caller command must not leave pipes
            // connected to a permanent daemon (or kill it when dropped).
            command
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());
            start_with_timing(
                command,
                &socket,
                Some("9.1.2"),
                Duration::from_secs(2),
                timing(),
            )
            .await
            .unwrap();
            timeout(Duration::from_secs(3), async {
                while !done.exists() {
                    sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            assert_eq!(std::fs::read(&done).unwrap(), b"finished");
        }
    }

    #[tokio::test]
    async fn update_shutdown_drains_work_but_refuses_socket_retirement_while_process_lives() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("daemon.sock");
        let unrelated = directory.path().join("other.sock");
        let peer = UnixListener::bind(&unrelated).unwrap();
        let listener = UnixListener::bind(&socket).unwrap();
        let mut busy = admission(false, false);
        busy["active_build_ids"] = json!([41]);
        busy["queued_build_ids"] = json!([42]);
        busy["client_lease_ids"] = json!(["rchw-owned"]);
        let server = async {
            answer(&listener, ADMISSION_STATUS, busy.clone()).await;
            let mut owned_busy = admission(true, false);
            for field in ["active_build_ids", "queued_build_ids", "client_lease_ids"] {
                owned_busy[field] = busy[field].clone();
            }
            answer(&listener, CLOSE_ADMISSION, owned_busy).await;
            let mut lease_only = admission(true, false);
            lease_only["client_lease_ids"] = json!(["rchw-owned"]);
            answer(&listener, RENEW_ADMISSION, lease_only).await;
            answer(&listener, RENEW_ADMISSION, admission(true, true)).await;
            answer(&listener, SHUTDOWN, json!({"status":"shutting_down"})).await;
            // The test-owned server performs its own socket retirement.
            drop(listener);
            tokio::fs::remove_file(&socket).await.unwrap();
        };
        let (result, ()) = tokio::join!(
            stop_with_timing(&socket, Duration::from_secs(1), timing()),
            server
        );
        let error = result.unwrap_err();
        assert!(error.contains("original process exit"), "{error}");
        assert!(error.contains("Live"), "{error}");
        assert!(unrelated.exists());
        drop(peer);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn update_shutdown_confirms_real_peer_exit_after_lease_only_drain() {
        use tokio::io::AsyncBufReadExt;

        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("daemon.sock");
        // A separate process is essential: retiring a listener owned by this
        // test thread cannot prove daemon process exit. The fixture also keeps
        // a client lease after its active/queued work has drained.
        let script = r#"
import json, os, socket, sys
from urllib.parse import parse_qs
path, opened, owned = sys.argv[1:]
opened, owned = json.loads(opened), json.loads(owned)
listener = socket.socket(socket.AF_UNIX)
listener.bind(path)
listener.listen(4)
print('ready', flush=True)
token = None
routes = ['/restart-admission', '/restart-admission', '/restart-admission/renew', '/restart-admission/renew', '/shutdown']
for step, expected in enumerate(routes):
    stream, _ = listener.accept()
    data = b''
    while True:
        chunk = stream.recv(4096)
        if not chunk:
            break
        data += chunk
    method, target = data.decode().strip().split()
    route, _, query = target.partition('?')
    assert route == expected
    value = json.loads(json.dumps(opened if step == 0 else owned))
    if step:
        fields = parse_qs(query)
        assert method == 'POST'
        assert fields['daemon_incarnation'] == [opened['daemon_incarnation']]
        if token is None:
            token = fields['token'][0]
        assert fields['token'] == [token]
        if step == 1:
            birth = owned['maintenance_owner']['process_identity']
            assert fields['owner_identity'] == [f"{birth['boot_id']}:{birth['start']['ticks']}"]
        else:
            assert 'owner_identity' not in fields
        value['maintenance_owner']['token'] = token
    if step < 2:
        value['active_build_ids'] = [41]
        value['queued_build_ids'] = [42]
    if step < 3:
        value['client_lease_ids'] = ['durable-wrapper']
    if step >= 3:
        value['restart_permitted'] = True
    if step == 4:
        value['status'] = 'shutting_down'
        value['shutdown_committed'] = True
    stream.sendall(b'HTTP/1.1 200 OK\r\n\r\n' + json.dumps(value).encode())
    stream.close()
listener.close()
os.rename(path, path + '.retired')
"#;
        let mut child = tokio::process::Command::new("python3")
            .args(["-I", "-S", "-c", script])
            .arg(&socket)
            .arg(admission(false, false).to_string())
            .arg(admission(true, false).to_string())
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut ready = tokio::io::BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        timeout(Duration::from_secs(2), ready.read_line(&mut line))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(line, "ready\n");
        let confirmed = stop_with_timing(
            &socket,
            Duration::from_secs(2),
            Timing {
                shutdown: Duration::from_secs(2),
                ..timing()
            },
        )
        .await
        .unwrap();
        assert!(confirmed);
        assert!(
            timeout(Duration::from_secs(2), child.wait())
                .await
                .unwrap()
                .unwrap()
                .success()
        );
        assert!(!socket.exists());
        assert!(socket.with_extension("sock.retired").exists());
    }

    #[tokio::test]
    async fn update_shutdown_zero_wait_refuses_work_and_verifies_owned_barrier_cleanup() {
        for field in [
            "active_build_ids",
            "queued_build_ids",
            "client_lease_ids",
            "client_lease_scan_error",
        ] {
            let directory = tempfile::tempdir().unwrap();
            let socket = directory.path().join("daemon.sock");
            let listener = UnixListener::bind(&socket).unwrap();
            let before = socket_identity(&socket).await.unwrap();
            let mut busy = admission(false, false);
            busy[field] = match field {
                "client_lease_ids" => json!(["rchw-unacknowledged"]),
                "client_lease_scan_error" => json!("permission denied"),
                _ => json!([41]),
            };
            let server = async {
                answer(&listener, ADMISSION_STATUS, busy.clone()).await;
                if field != "client_lease_scan_error" {
                    let mut owned_busy = admission(true, false);
                    owned_busy[field] = busy[field].clone();
                    answer(&listener, CLOSE_ADMISSION, owned_busy).await;
                    answer(&listener, RELEASE_ADMISSION, admission(false, false)).await;
                    answer(&listener, ADMISSION_STATUS, admission(false, false)).await;
                }
            };
            let (result, ()) =
                tokio::join!(stop_with_timing(&socket, Duration::ZERO, timing()), server);
            assert!(result.is_err(), "{field}");
            if field != "client_lease_scan_error" {
                assert!(
                    result
                        .unwrap_err()
                        .contains("admission reopened and verified")
                );
            }
            assert_eq!(socket_identity(&socket).await.unwrap(), before);
            assert!(
                timeout(Duration::from_millis(10), listener.accept())
                    .await
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn update_shutdown_does_not_take_over_or_reopen_an_existing_barrier() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("daemon.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let (result, ()) = tokio::join!(
            stop_with_timing(&socket, Duration::ZERO, timing()),
            answer(&listener, ADMISSION_STATUS, admission(true, false)),
        );
        assert!(result.unwrap_err().contains("already closed"));
        assert!(socket.exists());
        assert!(
            timeout(Duration::from_millis(10), listener.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn update_shutdown_requires_an_atomic_idle_grant_after_the_status_snapshot() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("daemon.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = async {
            answer(&listener, ADMISSION_STATUS, admission(false, false)).await;
            answer(&listener, CLOSE_ADMISSION, admission(true, false)).await;
            answer(&listener, RELEASE_ADMISSION, admission(false, false)).await;
            answer(&listener, ADMISSION_STATUS, admission(false, false)).await;
        };
        let (result, ()) =
            tokio::join!(stop_with_timing(&socket, Duration::ZERO, timing()), server);
        assert!(result.unwrap_err().contains("did not grant"));
        assert!(socket.exists());
        assert!(
            timeout(Duration::from_millis(10), listener.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn update_interrupted_acquisition_releases_its_original_token_and_verifies_admission() {
        for cancel_during_acquire in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let socket = directory.path().join("daemon.sock");
            let listener = UnixListener::bind(&socket).unwrap();
            let before = socket_identity(&socket).await.unwrap();
            let (cancel, cancelled) = tokio::sync::oneshot::channel::<()>();
            let server = async {
                answer(&listener, ADMISSION_STATUS, admission(false, false)).await;
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut command = String::new();
                stream.read_to_string(&mut command).await.unwrap();
                let acquired_token = verify_command(&command, CLOSE_ADMISSION).unwrap();
                // The daemon applied acquisition, but its response was lost
                // or the owner received cancellation at that exact boundary.
                if cancel_during_acquire {
                    cancel.send(()).unwrap();
                } else {
                    // Keep cancellation pending while returning invalid JSON.
                    stream
                        .write_all(b"HTTP/1.1 200 OK\r\n\r\n{}")
                        .await
                        .unwrap();
                }
                drop(stream);
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut command = String::new();
                stream.read_to_string(&mut command).await.unwrap();
                assert_eq!(
                    verify_command(&command, RELEASE_ADMISSION).as_deref(),
                    Some(acquired_token.as_str())
                );
                stream
                    .write_all(
                        format!("HTTP/1.1 200 OK\r\n\r\n{}", admission(false, false)).as_bytes(),
                    )
                    .await
                    .unwrap();
                drop(stream);
                answer(&listener, ADMISSION_STATUS, admission(false, false)).await;
            };
            let cancellation = async {
                if cancelled.await.is_err() {
                    std::future::pending::<()>().await;
                }
            };
            let (result, ()) = tokio::join!(
                stop_with_cancellation(&socket, Duration::ZERO, timing(), cancellation),
                server,
            );
            let error = result.unwrap_err();
            assert!(error.contains("admission reopened and verified"), "{error}");
            if cancel_during_acquire {
                assert!(error.contains("cancelled"), "{error}");
            } else {
                assert!(error.contains("invalid daemon reply"), "{error}");
            }
            assert_eq!(socket_identity(&socket).await.unwrap(), before);
        }
    }

    #[tokio::test]
    async fn update_release_requires_readback_even_when_the_acknowledgement_claims_success() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("daemon.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = async {
            answer(&listener, ADMISSION_STATUS, admission(false, false)).await;
            answer(&listener, CLOSE_ADMISSION, admission(true, false)).await;
            answer(&listener, RELEASE_ADMISSION, admission(false, false)).await;
            // Another operation closed admission before the verification.
            answer(&listener, ADMISSION_STATUS, admission(true, false)).await;
        };
        let (result, ()) =
            tokio::join!(stop_with_timing(&socket, Duration::ZERO, timing()), server);
        let error = result.unwrap_err();
        assert!(
            error.contains("admission reopening was not confirmed"),
            "{error}"
        );
        assert!(!error.contains("admission reopened and verified"));
    }

    #[tokio::test]
    async fn update_lost_release_acknowledgement_is_resolved_by_fresh_open_readback() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("daemon.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = async {
            answer(&listener, ADMISSION_STATUS, admission(false, false)).await;
            answer(&listener, CLOSE_ADMISSION, admission(true, false)).await;
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut command = String::new();
            stream.read_to_string(&mut command).await.unwrap();
            verify_command(&command, RELEASE_ADMISSION);
            drop(stream);
            answer(&listener, ADMISSION_STATUS, admission(false, false)).await;
        };
        let (result, ()) =
            tokio::join!(stop_with_timing(&socket, Duration::ZERO, timing()), server);
        let error = result.unwrap_err();
        assert!(error.contains("did not grant"));
        assert!(error.contains("admission reopened and verified"), "{error}");
    }

    #[tokio::test]
    async fn update_shutdown_success_cannot_hide_an_unacknowledged_client_lease() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("daemon.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = async {
            answer(&listener, ADMISSION_STATUS, admission(false, false)).await;
            answer(&listener, CLOSE_ADMISSION, admission(true, true)).await;
            answer(
                &listener,
                SHUTDOWN,
                json!({"status":"shutting_down", "client_lease_ids":["live-owner"]}),
            )
            .await;
            answer(&listener, RELEASE_ADMISSION, admission(false, false)).await;
            answer(&listener, ADMISSION_STATUS, admission(false, false)).await;
        };
        let (result, ()) =
            tokio::join!(stop_with_timing(&socket, Duration::ZERO, timing()), server);
        let error = result.unwrap_err();
        assert!(
            error.contains("did not acknowledge an owned shutdown commitment"),
            "{error}"
        );
        assert!(error.contains("live-owner"));
        assert!(socket.exists());
    }

    #[tokio::test]
    async fn update_shutdown_blocked_response_does_not_override_changed_admission() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("daemon.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = async {
            answer(&listener, ADMISSION_STATUS, admission(false, false)).await;
            answer(&listener, CLOSE_ADMISSION, admission(true, true)).await;
            answer(&listener, SHUTDOWN, json!({"status":"shutdown_blocked"})).await;
            // The client requests only its own fenced release; a surviving
            // concurrent owner cannot be treated as successful reopening.
            answer(&listener, RELEASE_ADMISSION, admission(true, false)).await;
            answer(&listener, ADMISSION_STATUS, admission(true, false)).await;
        };
        let (result, ()) =
            tokio::join!(stop_with_timing(&socket, Duration::ZERO, timing()), server);
        let error = result.unwrap_err();
        assert!(error.contains("admission reopening was not confirmed"));
        assert!(!error.contains("admission reopened and verified"));
        assert!(socket.exists());
        assert!(
            timeout(Duration::from_millis(10), listener.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn update_shutdown_acknowledgement_without_endpoint_retirement_is_not_success() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("daemon.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let before = socket_identity(&socket).await.unwrap();
        let server = async {
            answer(&listener, ADMISSION_STATUS, admission(false, false)).await;
            answer(&listener, CLOSE_ADMISSION, admission(true, true)).await;
            answer(&listener, SHUTDOWN, json!({"status":"shutting_down"})).await;
            let mut committed = admission(true, false);
            committed["shutdown_committed"] = json!(true);
            committed["success"] = json!(false);
            committed["status"] = json!("shutdown_committed");
            answer(&listener, RELEASE_ADMISSION, committed.clone()).await;
            answer(&listener, ADMISSION_STATUS, committed).await;
        };
        let (result, ()) =
            tokio::join!(stop_with_timing(&socket, Duration::ZERO, timing()), server);
        assert!(
            result
                .unwrap_err()
                .contains("process exit and endpoint retirement are unconfirmed")
        );
        assert_eq!(socket_identity(&socket).await.unwrap(), before);
    }

    #[tokio::test]
    async fn update_shutdown_lost_or_malformed_reply_never_authorizes_kill_or_unlink() {
        for reply in [
            b"".as_slice(),
            b"HTTP/1.1 200 OK\r\n\r\n{}",
            b"HTTP/1.1 500 Error\r\n\r\n{\"status\":\"shutting_down\"}",
        ] {
            let directory = tempfile::tempdir().unwrap();
            let socket = directory.path().join("daemon.sock");
            let listener = UnixListener::bind(&socket).unwrap();
            let server = async {
                answer(&listener, ADMISSION_STATUS, admission(false, false)).await;
                answer(&listener, CLOSE_ADMISSION, admission(true, true)).await;
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut command = String::new();
                stream.read_to_string(&mut command).await.unwrap();
                verify_command(&command, SHUTDOWN);
                stream.write_all(reply).await.unwrap();
                drop(stream);
                answer(&listener, RELEASE_ADMISSION, admission(false, false)).await;
                answer(&listener, ADMISSION_STATUS, admission(false, false)).await;
            };
            let (result, ()) =
                tokio::join!(stop_with_timing(&socket, Duration::ZERO, timing()), server);
            let error = result.unwrap_err();
            assert!(error.contains("admission reopened and verified"), "{error}");
            assert!(socket.exists());
            assert!(
                timeout(Duration::from_millis(10), listener.accept())
                    .await
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn update_shutdown_unresponsive_socket_has_a_deadline_and_is_left_intact() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("daemon.sock");
        let _listener = UnixListener::bind(&socket).unwrap();
        let result = timeout(
            Duration::from_secs(2),
            stop_with_timing(&socket, Duration::ZERO, timing()),
        )
        .await
        .unwrap();
        assert!(result.unwrap_err().contains("timed out"));
        assert!(socket.exists());
    }

    #[tokio::test]
    async fn update_shutdown_does_not_mistake_a_replacement_endpoint_for_the_old_daemon() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("daemon.sock");
        let retired = directory.path().join("old.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = async {
            answer(&listener, ADMISSION_STATUS, admission(false, false)).await;
            answer(&listener, CLOSE_ADMISSION, admission(true, true)).await;
            answer(&listener, SHUTDOWN, json!({"status":"shutting_down"})).await;
            // These are both fixture-owned endpoints, not user daemon files.
            // A synchronous rename/bind keeps the replacement transition in
            // one executor turn rather than exposing a deliberate absent gap.
            std::fs::rename(&socket, &retired).unwrap();
            UnixListener::bind(&socket).unwrap()
        };
        let (result, replacement) =
            tokio::join!(stop_with_timing(&socket, Duration::ZERO, timing()), server,);
        assert!(result.unwrap_err().contains("replacement daemon"));
        assert!(socket.exists());
        assert!(retired.exists());
        assert!(
            timeout(Duration::from_millis(10), replacement.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn update_shutdown_missing_endpoint_is_distinct_from_invalid_endpoint() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("daemon.sock");
        let mut signals = MaintenanceSignals::new().unwrap();
        assert!(!stop(&socket, Duration::ZERO, &mut signals).await.unwrap());
        tokio::fs::write(&socket, "not a socket").await.unwrap();
        assert!(stop(&socket, Duration::ZERO, &mut signals).await.is_err());
        assert_eq!(tokio::fs::read(&socket).await.unwrap(), b"not a socket");
    }

    #[test]
    fn update_shutdown_partial_or_invalid_evidence_cannot_prove_idle() {
        for body in [
            json!({}),
            json!({"admission_closed":false, "restart_permitted":true}),
            json!({"admission_closed":false, "restart_permitted":false, "active_build_ids":[], "queued_build_ids":[]}),
        ] {
            assert!(
                decode_reply::<Admission>(format!("HTTP/1.1 200 OK\r\n\r\n{body}").as_bytes())
                    .is_err()
            );
        }
        assert!(decode_reply::<Admission>(&vec![b' '; MAX_REPLY_BYTES as usize + 1]).is_err());
        assert!(decode_reply::<Admission>(b"HTTP/1.1 200 OK\r\n").is_err());
    }
}
