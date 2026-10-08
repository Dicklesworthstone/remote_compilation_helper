//! Confirm daemon shutdown and restart during an update or rollback.
//!
//! This is deliberately not the interactive `daemon stop` path: an update never
//! authorizes killing a process, removing a socket, or interrupting a build.

use serde::Deserialize;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::{Instant, sleep, timeout};

const MAX_REPLY_BYTES: u64 = 1024 * 1024;
const ADMISSION_STATUS: &str = "GET /restart-admission\n";
const CLOSE_ADMISSION: &str = "POST /restart-admission\n";
const SHUTDOWN: &str = "POST /shutdown\n";
const STATUS: &str = "GET /status\n";

#[derive(Clone, Copy)]
struct Timing {
    request: Duration,
    shutdown: Duration,
    poll: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            request: Duration::from_secs(5),
            shutdown: Duration::from_secs(10),
            poll: Duration::from_millis(100),
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
/// that there are no builds or unacknowledged client leases. The optional scan
/// error is omitted by the daemon only when its scan succeeded.
#[derive(Debug, Deserialize)]
struct Admission {
    admission_closed: bool,
    restart_permitted: bool,
    active_build_ids: Vec<u64>,
    queued_build_ids: Vec<u64>,
    client_lease_ids: Vec<String>,
    client_lease_scan_error: Option<String>,
}

impl Admission {
    fn idle(&self) -> bool {
        self.active_build_ids.is_empty()
            && self.queued_build_ids.is_empty()
            && self.client_lease_ids.is_empty()
            && self.client_lease_scan_error.is_none()
    }
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
) -> Result<(T, Option<u32>), String> {
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
            Some(
                stream
                    .peer_cred()
                    .map_err(|error| format!("cannot inspect daemon peer: {error}"))?
                    .pid()
                    .and_then(|pid| u32::try_from(pid).ok())
                    .filter(|pid| *pid > 0)
                    .ok_or("daemon peer PID is unavailable; readiness unconfirmed")?,
            )
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
    if peer != Some(status.daemon.pid)
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
    if admission.admission_closed || admission.client_lease_scan_error.is_some() {
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

pub(super) async fn stop(path: &Path, drain_timeout: Duration) -> Result<bool, String> {
    stop_with_timing(path, drain_timeout, Timing::default()).await
}

async fn stop_with_timing(
    path: &Path,
    drain_timeout: Duration,
    timing: Timing,
) -> Result<bool, String> {
    let Some(identity) = socket_identity(path).await? else {
        return Ok(false);
    };
    // Wait without changing admission. The existing boolean barrier has no
    // owner token: closing a busy barrier and later unconditionally reopening
    // it could clear another maintenance operation's gate. Instead acquire the
    // daemon's atomic, idle-only `restart_permitted` grant after this wait.
    let mut admission: Admission =
        request(path, identity, ADMISSION_STATUS, timing.request).await?;
    let deadline = Instant::now()
        .checked_add(drain_timeout)
        .ok_or("update drain timeout is out of range")?;
    loop {
        if admission.admission_closed {
            return Err("daemon admission is already closed; update will not take over another maintenance operation".to_owned());
        }
        if admission.client_lease_scan_error.is_some() {
            return Err(format!(
                "cannot prove daemon idle: {admission:?}; update refused"
            ));
        }
        if admission.idle() {
            break;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(format!(
                "update drain timed out with work still in flight: {admission:?}; daemon left running"
            ));
        }
        sleep(timing.poll.min(remaining)).await;
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(format!(
                "update drain timed out with work still in flight: {admission:?}; daemon left running"
            ));
        }
        admission = request(
            path,
            identity,
            ADMISSION_STATUS,
            timing.request.min(remaining),
        )
        .await?;
    }
    let grant: Admission = request(path, identity, CLOSE_ADMISSION, timing.request)
        .await
        .map_err(|error| {
            format!(
                "{error}; admission ownership is unconfirmed, no shutdown or installation attempted"
            )
        })?;
    if !grant.admission_closed || !grant.restart_permitted || !grant.idle() {
        // A concurrent maintenance request or new work won the race. No grant
        // means no authority to shut down OR to reopen the shared barrier.
        return Err(format!(
            "daemon did not grant an idle restart: {grant:?}; update refused, admission left unchanged by this client"
        ));
    }

    #[derive(Deserialize)]
    struct ShutdownReply {
        status: String,
    }
    let reply: ShutdownReply = match request(path, identity, SHUTDOWN, timing.request).await {
        Ok(reply) => reply,
        Err(error) => {
            // A lost shutdown reply cannot prove whether the daemon acted.
            // Retain the barrier and endpoint; never substitute pkill/unlink.
            return Err(format!(
                "{error}; shutdown is unconfirmed, installation not started; admission may remain closed"
            ));
        }
    };
    if reply.status != "shutting_down" {
        // Even a blocked reply after an idle grant means the shared admission
        // state changed. Without an owner token, reopening it could clear a
        // different operation's barrier. Leave that state intact for explicit
        // reconciliation rather than authorizing installation or force-stop.
        return Err(format!(
            "daemon did not acknowledge shutdown ({}); installation not started; admission may remain closed",
            reply.status
        ));
    }
    let deadline = Instant::now()
        .checked_add(timing.shutdown)
        .ok_or("update shutdown timeout is out of range")?;
    loop {
        match socket_identity(path).await? {
            None => return Ok(true),
            Some(current) if current != identity => {
                return Err("a replacement daemon endpoint appeared during shutdown; installation not started".to_owned());
            }
            Some(_) => {}
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("daemon acknowledged shutdown but its endpoint remains; installation not started, no process killed or socket removed".to_owned());
        }
        sleep(timing.poll.min(remaining)).await;
    }
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
        }
    }

    fn admission(closed: bool, granted: bool) -> Value {
        json!({"admission_closed": closed, "restart_permitted": granted,
               "active_build_ids": [], "queued_build_ids": [], "client_lease_ids": []})
    }

    async fn answer(listener: &UnixListener, expected: &str, value: Value) {
        let (mut stream, _) = timeout(Duration::from_secs(2), listener.accept())
            .await
            .unwrap()
            .unwrap();
        let mut command = String::new();
        stream.read_to_string(&mut command).await.unwrap();
        assert_eq!(command, expected);
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
                     'active_build_ids': [], 'queued_build_ids': [], 'client_lease_ids': []}
        else:
            raise ValueError('unexpected mutation: ' + repr(data))
        connection.sendall(b'HTTP/1.1 200 OK\r\n\r\n' + json.dumps(value).encode())
server.close()
with open(done, 'w') as output:
    output.write('finished')
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
    async fn update_shutdown_waits_for_work_then_grants_and_confirms_endpoint_retirement() {
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
            answer(&listener, ADMISSION_STATUS, busy).await;
            answer(&listener, ADMISSION_STATUS, admission(false, false)).await;
            answer(&listener, CLOSE_ADMISSION, admission(true, true)).await;
            answer(&listener, SHUTDOWN, json!({"status":"shutting_down"})).await;
            // The test-owned server performs its own socket retirement.
            drop(listener);
            tokio::fs::remove_file(&socket).await.unwrap();
        };
        let (result, ()) = tokio::join!(
            stop_with_timing(&socket, Duration::from_secs(1), timing()),
            server
        );
        assert!(result.unwrap());
        assert!(unrelated.exists());
        drop(peer);
    }

    #[tokio::test]
    async fn update_shutdown_zero_wait_and_each_kind_of_inflight_work_refuse_without_mutation() {
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
            let (result, ()) = tokio::join!(
                stop_with_timing(&socket, Duration::ZERO, timing()),
                answer(&listener, ADMISSION_STATUS, busy),
            );
            assert!(result.is_err(), "{field}");
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
    async fn update_shutdown_blocked_response_does_not_override_changed_admission() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("daemon.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = async {
            answer(&listener, ADMISSION_STATUS, admission(false, false)).await;
            answer(&listener, CLOSE_ADMISSION, admission(true, true)).await;
            answer(&listener, SHUTDOWN, json!({"status":"shutdown_blocked"})).await;
        };
        let (result, ()) =
            tokio::join!(stop_with_timing(&socket, Duration::ZERO, timing()), server);
        assert!(result.is_err());
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
        };
        let (result, ()) =
            tokio::join!(stop_with_timing(&socket, Duration::ZERO, timing()), server);
        assert!(result.unwrap_err().contains("endpoint remains"));
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
                assert_eq!(command, SHUTDOWN);
                stream.write_all(reply).await.unwrap();
            };
            let (result, ()) =
                tokio::join!(stop_with_timing(&socket, Duration::ZERO, timing()), server);
            assert!(result.is_err());
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
        assert!(!stop(&socket, Duration::ZERO).await.unwrap());
        tokio::fs::write(&socket, "not a socket").await.unwrap();
        assert!(stop(&socket, Duration::ZERO).await.is_err());
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
