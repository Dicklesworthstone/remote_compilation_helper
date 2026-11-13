//! Linux force-stop binds the configured peer to a stable kernel PID handle.
//!
//! A successful return requires the bound process to exit and its original
//! socket name to disappear. No numeric PID signal, KILL escalation or socket
//! removal is permitted, including after a deadline or task cancellation.

use anyhow::{Context, Result, ensure};
use rch_common::process_identity::{OwnerPresence, ProcessIdentity, ProcessStart, owner_presence};
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::fd::OwnedFd;
use rustix::process::{Pid, PidfdFlags, Signal};
use serde::Deserialize;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
use std::path::Path;
use std::time::Duration;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::time::Instant;

const MAX_REPLY: usize = 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const EXIT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Endpoint {
    device: u64,
    inode: u64,
    uid: u32,
}

async fn endpoint(path: &Path) -> Result<Option<Endpoint>> {
    let metadata = match tokio::fs::symlink_metadata(path).await {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("cannot observe daemon endpoint"),
    };
    ensure!(
        metadata.file_type().is_socket() && metadata.uid() == rustix::process::geteuid().as_raw(),
        "endpoint is not a socket owned by this user"
    );
    Ok(Some(Endpoint {
        device: metadata.dev(),
        inode: metadata.ino(),
        uid: metadata.uid(),
    }))
}

fn exited(handle: &OwnedFd, deadline: Instant) -> Result<bool> {
    let mut descriptors = [PollFd::new(handle, PollFlags::IN)];
    loop {
        ensure!(
            Instant::now() < deadline,
            "bound daemon observation deadline expired"
        );
        match poll(&mut descriptors, Some(&Timespec::default())) {
            Err(rustix::io::Errno::INTR) => continue,
            Err(error) => return Err(error).context("cannot observe bound daemon process"),
            Ok(0) => return Ok(false),
            Ok(_) => {
                let flags = descriptors[0].revents();
                ensure!(
                    !flags.intersects(PollFlags::ERR | PollFlags::NVAL)
                        && flags.intersects(PollFlags::IN | PollFlags::HUP),
                    "invalid bound daemon process readiness"
                );
                return Ok(true);
            }
        }
    }
}

/// Reject duplicate fields even in status sections we do not use for signal
/// authority. Serde's typed structures already reject duplicated known fields;
/// this bounded recursive walk also covers ignored nested objects.
struct UniqueJson;

impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = UniqueJson;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("JSON without duplicate object fields")
            }

            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueJson)
            }

            fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<Self::Value, E> {
                Ok(UniqueJson)
            }

            fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<Self::Value, E> {
                Ok(UniqueJson)
            }

            fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<Self::Value, E> {
                Ok(UniqueJson)
            }

            fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Self::Value, E> {
                Ok(UniqueJson)
            }

            fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<Self::Value, E> {
                Ok(UniqueJson)
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                while sequence.next_element::<UniqueJson>()?.is_some() {}
                Ok(UniqueJson)
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut object: A,
            ) -> Result<Self::Value, A::Error> {
                use serde::de::Error as _;
                let mut fields = std::collections::HashSet::new();
                while let Some(field) = object.next_key::<String>()? {
                    if !fields.insert(field) {
                        return Err(A::Error::custom("duplicate daemon response field"));
                    }
                    object.next_value::<UniqueJson>()?;
                }
                Ok(UniqueJson)
            }
        }

        deserializer.deserialize_any(Visitor)
    }
}

#[derive(Deserialize)]
struct Status {
    daemon: DaemonStatus,
    admission: AdmissionStatus,
}

#[derive(Deserialize)]
struct DaemonStatus {
    pid: u32,
    socket_path: String,
}

#[derive(Deserialize)]
struct AdmissionStatus {
    daemon_incarnation: String,
    success: bool,
    admission_closed: bool,
    shutdown_committed: bool,
}

fn verify_status(payload: &[u8], path: &str, pid: u32, incarnation: &str) -> Result<()> {
    let text = std::str::from_utf8(payload).context("daemon status is not UTF-8")?;
    let (header, body) = text
        .split_once("\r\n\r\n")
        .or_else(|| text.split_once("\n\n"))
        .context("daemon status is incomplete")?;
    let mut status_line = header.lines().next().unwrap_or_default().split_whitespace();
    ensure!(
        matches!(status_line.next(), Some("HTTP/1.0" | "HTTP/1.1"))
            && status_line.next() == Some("200"),
        "daemon status was not acknowledged"
    );
    // Deserializer errors can contain an entire wrong-typed status string.
    // Status bytes are untrusted; never attach them to CLI/log diagnostics.
    serde_json::from_str::<UniqueJson>(body)
        .map_err(|_| anyhow::anyhow!("daemon status is malformed or ambiguous"))?;
    let status: Status =
        serde_json::from_str(body).map_err(|_| anyhow::anyhow!("daemon status is malformed"))?;
    ensure!(
        status.daemon.pid == pid && status.daemon.socket_path == path,
        "daemon status does not match the bound peer and socket"
    );
    ensure!(
        status.admission.daemon_incarnation == incarnation
            && status.admission.success
            && status.admission.admission_closed
            && status.admission.shutdown_committed,
        "original daemon's terminal shutdown fence is unconfirmed"
    );
    Ok(())
}

pub(super) async fn stop(
    socket_path: &Path,
    pid: u32,
    identity: &ProcessIdentity,
    incarnation: &str,
) -> Result<()> {
    stop_with_timing(
        socket_path,
        pid,
        identity,
        incarnation,
        REQUEST_TIMEOUT,
        EXIT_TIMEOUT,
    )
    .await
}

pub(super) async fn stop_with_timing(
    socket_path: &Path,
    pid: u32,
    identity: &ProcessIdentity,
    incarnation: &str,
    request_timeout: Duration,
    exit_timeout: Duration,
) -> Result<()> {
    ensure!(
        pid > 1 && pid != std::process::id(),
        "refusing an unsafe daemon PID"
    );
    let kernel_pid = i32::try_from(pid)
        .ok()
        .and_then(Pid::from_raw)
        .context("invalid daemon PID")?;
    let path = socket_path
        .to_str()
        .context("daemon socket path is not UTF-8")?;
    ensure!(
        socket_path.is_absolute()
            && !path.bytes().any(|byte| byte < 32 || byte == 127)
            && !request_timeout.is_zero()
            && request_timeout <= REQUEST_TIMEOUT
            && !exit_timeout.is_zero()
            && exit_timeout <= EXIT_TIMEOUT,
        "invalid force-stop path or time budget"
    );
    ensure!(
        identity.is_valid()
            && matches!(identity.start, ProcessStart::Linux { .. })
            && uuid::Uuid::parse_str(incarnation).is_ok_and(|uuid| uuid.to_string() == incarnation),
        "invalid original daemon identity or incarnation"
    );
    let require_live = || {
        ensure!(
            owner_presence(pid, Some(identity)) == OwnerPresence::Live,
            "daemon birth identity changed or could not be confirmed; no signal sent"
        );
        Ok::<(), anyhow::Error>(())
    };

    let request_deadline = Instant::now() + request_timeout;
    let (handle, original_endpoint) = tokio::time::timeout_at(request_deadline, async {
        let original_endpoint = endpoint(socket_path)
            .await?
            .context("daemon endpoint disappeared before force-stop binding")?;
        // Bind before reconnecting. Recycled numeric PIDs cannot redirect TERM.
        let handle = rustix::process::pidfd_open(kernel_pid, PidfdFlags::empty())
            .context("Linux pidfd support is required for force-stop; use --drain")?;
        ensure!(
            !exited(&handle, request_deadline)?,
            "bound daemon already exited; no signal sent"
        );
        require_live()?;
        let mut peer = tokio::net::UnixStream::connect(socket_path)
            .await
            .context("cannot reconnect to configured daemon endpoint")?;
        let credentials = peer
            .peer_cred()
            .context("cannot inspect daemon socket peer")?;
        ensure!(
            credentials.pid() == Some(kernel_pid.as_raw_nonzero().get())
                && credentials.uid() == rustix::process::geteuid().as_raw(),
            "configured endpoint belongs to another process or user"
        );
        ensure!(
            endpoint(socket_path).await? == Some(original_endpoint),
            "endpoint changed during force-stop binding"
        );
        peer.write_all(b"GET /status\n").await?;
        peer.shutdown().await?;
        let mut payload = Vec::new();
        (&mut peer)
            .take(MAX_REPLY as u64 + 1)
            .read_to_end(&mut payload)
            .await?;
        ensure!(
            payload.len() <= MAX_REPLY,
            "oversized daemon status; no signal sent"
        );
        verify_status(&payload, path, pid, incarnation)?;
        ensure!(
            endpoint(socket_path).await? == Some(original_endpoint)
                && !exited(&handle, request_deadline)?,
            "daemon identity changed before TERM; no signal sent"
        );
        require_live()?;
        ensure!(
            Instant::now() < request_deadline,
            "daemon status deadline expired; no signal sent"
        );
        rustix::process::pidfd_send_signal(&handle, Signal::TERM)
            .context("cannot signal the bound daemon process")?;
        Ok::<_, anyhow::Error>((handle, original_endpoint))
    })
    .await
    .context("daemon status deadline expired; no signal sent")??;

    let exit_deadline = Instant::now() + exit_timeout;
    tokio::time::timeout_at(exit_deadline, async {
        loop {
            let current = endpoint(socket_path).await?;
            ensure!(
                current.is_none() || current == Some(original_endpoint),
                "replacement endpoint appeared; retained without modification"
            );
            if exited(&handle, exit_deadline)? && current.is_none() {
                return Ok(());
            }
            tokio::time::sleep_until(
                (Instant::now() + Duration::from_millis(50)).min(exit_deadline),
            )
            .await;
        }
    })
    .await
    .context("TERM sent but process exit and socket retirement unconfirmed; retained")?
}

#[cfg(test)]
mod tests {
    use super::{MAX_REPLY, verify_status};
    use serde_json::{Value, json};

    const PID: u32 = 42;
    const PATH: &str = "/tmp/rch-force-stop.sock";
    const INCARNATION: &str = "eac96767-51d6-41ee-9647-7d576d4d18de";

    fn committed_status() -> Value {
        json!({
            "daemon": {"pid": PID, "socket_path": PATH},
            "admission": {
                "daemon_incarnation": INCARNATION,
                "success": true,
                "admission_closed": true,
                "shutdown_committed": true
            }
        })
    }

    fn response(body: &str) -> Vec<u8> {
        format!("HTTP/1.1 200 OK\r\n\r\n{body}").into_bytes()
    }

    #[test]
    fn status_decoder_requires_exact_committed_authority_and_unique_fields() {
        let status = committed_status();
        verify_status(&response(&status.to_string()), PATH, PID, INCARNATION).unwrap();

        for (pointer, replacement, expected) in [
            (
                "/daemon/pid",
                json!(PID + 1),
                "daemon status does not match the bound peer and socket",
            ),
            (
                "/daemon/socket_path",
                json!("/tmp/another-daemon.sock"),
                "daemon status does not match the bound peer and socket",
            ),
            (
                "/admission/daemon_incarnation",
                json!("a1970ed9-c44b-41d6-a8ae-8ed327c22812"),
                "original daemon's terminal shutdown fence is unconfirmed",
            ),
        ] {
            let mut invalid = status.clone();
            *invalid.pointer_mut(pointer).unwrap() = replacement;
            let error = verify_status(&response(&invalid.to_string()), PATH, PID, INCARNATION)
                .expect_err(pointer);
            assert_eq!(error.to_string(), expected, "{pointer}");
        }

        for field in ["success", "admission_closed", "shutdown_committed"] {
            for replacement in [json!(false), json!(1), json!("true"), Value::Null] {
                let expected = if replacement == json!(false) {
                    "original daemon's terminal shutdown fence is unconfirmed"
                } else {
                    "daemon status is malformed"
                };
                let mut invalid = status.clone();
                invalid["admission"][field] = replacement;
                let error = verify_status(&response(&invalid.to_string()), PATH, PID, INCARNATION)
                    .expect_err(field);
                assert_eq!(error.to_string(), expected, "{field}");
            }
            let mut missing = status.clone();
            missing["admission"].as_object_mut().unwrap().remove(field);
            let error = verify_status(&response(&missing.to_string()), PATH, PID, INCARNATION)
                .expect_err(field);
            assert_eq!(error.to_string(), "daemon status is malformed", "{field}");
        }

        let daemon = &status["daemon"];
        let admission = &status["admission"];
        for body in [
            format!(r#"{{"daemon":{daemon},"daemon":{daemon},"admission":{admission}}}"#),
            format!(
                r#"{{"daemon":{{"pid":{PID},"pid":{PID},"socket_path":"{PATH}"}},"admission":{admission}}}"#
            ),
            format!(
                r#"{{"daemon":{daemon},"admission":{admission},"ignored":{{"nested":[{{"x":1,"x":2}}]}}}}"#
            ),
        ] {
            assert!(serde_json::from_str::<Value>(&body).is_ok());
            let error = verify_status(&response(&body), PATH, PID, INCARNATION).unwrap_err();
            assert_eq!(error.to_string(), "daemon status is malformed or ambiguous");
        }

        let refused = format!("HTTP/1.1 503 Unavailable\r\n\r\n{status}");
        assert_eq!(
            verify_status(refused.as_bytes(), PATH, PID, INCARNATION)
                .unwrap_err()
                .to_string(),
            "daemon status was not acknowledged"
        );
    }

    #[test]
    fn status_decoder_redacts_large_wrong_type_values() {
        const SENTINEL: &str = "private-status-sentinel-";
        let private_value = SENTINEL.repeat(32 * 1024);
        for pointer in [
            "/daemon/pid",
            "/admission/success",
            "/admission/admission_closed",
            "/admission/shutdown_committed",
        ] {
            let mut status = committed_status();
            *status.pointer_mut(pointer).unwrap() = json!(private_value);
            let payload = response(&status.to_string());
            assert!(payload.len() < MAX_REPLY);
            let error = verify_status(&payload, PATH, PID, INCARNATION).expect_err(pointer);
            let diagnostic = format!("{error:#}");
            assert_eq!(error.to_string(), "daemon status is malformed");
            assert!(
                diagnostic.len() <= 1024,
                "unbounded diagnostic for {pointer}"
            );
            assert!(!diagnostic.contains(SENTINEL));
            assert_eq!(error.chain().count(), 1, "untrusted error source retained");
        }
    }
}
