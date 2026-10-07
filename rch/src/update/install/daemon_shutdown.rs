//! Confirm an idle daemon's shutdown before an update or rollback mutates files.
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
        decode_reply(&bytes)
    })
    .await
    .map_err(|_| "daemon lifecycle request timed out; update refused".to_owned())?
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
