//! Borrow an admitted build's daemon-owned SSH connection without transferring
//! process ownership. The open local stream is the lease: no work starts before
//! a complete, identity-bound grant, and losing the stream revokes new channels.

use anyhow::{Context, Result, anyhow, ensure};
use rch_common::ssh_transport_lease::{
    MAX_SSH_TRANSPORT_LEASE_FRAME_BYTES, SSH_TRANSPORT_LEASE_ROUTE, SSH_TRANSPORT_LEASE_VERSION,
    SshTransportLeaseFinish, SshTransportLeaseRequest, SshTransportLeaseResponse,
    validate_transport_arguments,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::net::unix::OwnedWriteHalf;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::timeout;

const FINISH_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug)]
enum LeaseState {
    Active,
    Released,
    Lost(String),
}

/// Loss is monotonic, including an unexpectedly stopped monitor. Consumers
/// must distinguish this from having no lease: absence permits ordinary SSH,
/// whereas a lost lease must never select a fresh connection.
#[derive(Clone)]
pub(in crate::hook) struct LeaseWatch(watch::Receiver<LeaseState>);

impl LeaseWatch {
    pub(in crate::hook) fn lost_reason(&self) -> Option<String> {
        match &*self.0.borrow() {
            LeaseState::Lost(reason) => Some(reason.clone()),
            LeaseState::Released => Some("daemon SSH lease was already released".into()),
            LeaseState::Active => self
                .0
                .has_changed()
                .is_err()
                .then(|| "daemon SSH lease monitor stopped".into()),
        }
    }

    pub(in crate::hook) async fn lost(&self) -> String {
        let mut state = self.clone();
        loop {
            if let Some(reason) = state.lost_reason() {
                return reason;
            }
            if state.0.changed().await.is_err() {
                return "daemon SSH lease monitor stopped".into();
            }
        }
    }
}

/// Owns only the local lease connection and its read task. The daemon retains
/// the actual SSH process and the existing active-use guard. Dropping this
/// handle abandons reuse, without authorizing another build or connection.
pub(in crate::hook) struct DaemonSshLease {
    request: SshTransportLeaseRequest,
    arguments: Vec<String>,
    writer: OwnedWriteHalf,
    state: LeaseWatch,
    finishing: Arc<AtomicBool>,
    monitor: Option<JoinHandle<Result<()>>>,
}

impl DaemonSshLease {
    pub(in crate::hook) fn arguments(&self) -> &[String] {
        &self.arguments
    }

    pub(in crate::hook) fn watch(&self) -> LeaseWatch {
        self.state.clone()
    }

    /// A failed release acknowledgment only forfeits connection reuse. The
    /// caller already owns the verified operation outcome and must preserve it.
    pub(in crate::hook) async fn complete(mut self) -> Result<()> {
        ensure!(
            self.state.lost_reason().is_none(),
            "daemon SSH lease was lost before release"
        );
        let finish = SshTransportLeaseFinish {
            version: SSH_TRANSPORT_LEASE_VERSION,
            build_id: self.request.build_id,
            local_wrapper_id: self.request.local_wrapper_id.clone(),
        };
        let mut frame = serde_json::to_vec(&finish)?;
        frame.push(b'\n');
        ensure!(
            frame.len() <= MAX_SSH_TRANSPORT_LEASE_FRAME_BYTES,
            "daemon SSH lease release exceeds the frame limit"
        );
        self.finishing.store(true, Ordering::Release);
        timeout(FINISH_TIMEOUT, async {
            self.writer.write_all(&frame).await?;
            self.writer.flush().await?;
            let monitor = self
                .monitor
                .as_mut()
                .context("SSH lease monitor is absent")?;
            monitor.await.context("SSH lease monitor failed")??;
            Ok::<(), anyhow::Error>(())
        })
        .await
        .context("daemon SSH lease release timed out")??;
        self.monitor.take();
        Ok(())
    }
}

impl Drop for DaemonSshLease {
    fn drop(&mut self) {
        if let Some(monitor) = self.monitor.take() {
            // This task owns only a socket reader. Aborting it drops that half;
            // dropping our writer closes the lease and abandons the guard.
            monitor.abort();
        }
    }
}

fn request_line(request: &SshTransportLeaseRequest) -> Result<String> {
    request.validate().map_err(anyhow::Error::msg)?;
    let endpoint = &request.endpoint;
    let mut line = format!(
        "GET {SSH_TRANSPORT_LEASE_ROUTE}?build_id={}&local_wrapper_id={}&worker_id={}&host={}&user={}&identity_file={}&server_alive_interval_secs={}&idle_timeout_secs={}",
        request.build_id,
        super::urlencoding_encode(&request.local_wrapper_id),
        super::urlencoding_encode(endpoint.worker_id.as_str()),
        super::urlencoding_encode(&endpoint.host),
        super::urlencoding_encode(&endpoint.user),
        super::urlencoding_encode(&endpoint.identity_file),
        request.server_alive_interval_secs,
        request.idle_timeout_secs,
    );
    if let Some(os) = &endpoint.declared_os {
        line.push_str("&declared_os=");
        line.push_str(&super::urlencoding_encode(os));
    }
    line.push('\n');
    ensure!(
        line.len() <= MAX_SSH_TRANSPORT_LEASE_FRAME_BYTES,
        "daemon SSH lease request exceeds the frame limit"
    );
    Ok(line)
}

async fn read_frame<R: AsyncBufRead + Unpin>(reader: &mut R) -> Result<Option<Vec<u8>>> {
    let mut frame = Vec::new();
    let count = (&mut *reader)
        .take((MAX_SSH_TRANSPORT_LEASE_FRAME_BYTES + 1) as u64)
        .read_until(b'\n', &mut frame)
        .await?;
    if count == 0 {
        return Ok(None);
    }
    ensure!(
        frame.len() <= MAX_SSH_TRANSPORT_LEASE_FRAME_BYTES,
        "daemon SSH lease frame exceeds the byte limit"
    );
    ensure!(
        frame.last() == Some(&b'\n'),
        "daemon SSH lease frame is truncated"
    );
    Ok(Some(frame))
}

/// Acquire before the first remote mutation. Connection failure, timeout, an
/// older daemon closing its unknown route, or an explicit unavailable result
/// leave the existing per-dispatch transport available. A typed rejection or
/// malformed grant never degrades to a different transport.
pub(in crate::hook) async fn acquire(
    socket_path: &str,
    request: SshTransportLeaseRequest,
    budget: Duration,
) -> Result<Option<DaemonSshLease>> {
    acquire_with_connection(UnixStream::connect(socket_path), request, budget).await
}

/// Keep connection establishment and the complete grant under one budget.
/// The protocol itself needs an authenticated connected stream, not a named
/// listener, so local stream-pair tests exercise these same ownership checks.
async fn acquire_with_connection(
    connection: impl std::future::Future<Output = std::io::Result<UnixStream>>,
    request: SshTransportLeaseRequest,
    budget: Duration,
) -> Result<Option<DaemonSshLease>> {
    let line = request_line(&request)?;
    let acquire = async {
        let stream = match connection.await {
            Ok(stream) => stream,
            Err(error) => {
                tracing::debug!(%error, "Daemon SSH lease unavailable before dispatch");
                return Ok(None);
            }
        };
        acquire_stream(stream, request, line).await
    };
    match timeout(budget, acquire).await {
        Ok(result) => result,
        Err(_) => {
            tracing::debug!("Daemon SSH lease acquisition timed out before dispatch");
            Ok(None)
        }
    }
}

async fn acquire_stream(
    stream: UnixStream,
    request: SshTransportLeaseRequest,
    line: String,
) -> Result<Option<DaemonSshLease>> {
    let peer = stream
        .peer_cred()
        .context("cannot inspect daemon SSH lease peer")?;
    ensure!(
        peer.uid() == rustix::process::geteuid().as_raw(),
        "daemon SSH lease peer is not owned by this user"
    );
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    writer.write_all(line.as_bytes()).await?;
    writer.flush().await?;
    let Some(frame) = read_frame(&mut reader).await? else {
        // Older daemon parsers return an error and close an unknown route.
        // No remote command has started and no grant was consumed.
        return Ok(None);
    };
    let response: SshTransportLeaseResponse =
        serde_json::from_slice(&frame).context("invalid daemon SSH lease response")?;
    let arguments = match response {
        SshTransportLeaseResponse::Ready {
            request: echoed,
            arguments,
        } => {
            ensure!(
                echoed == request,
                "daemon SSH lease grant identity differs from admission"
            );
            validate_transport_arguments(&arguments).map_err(anyhow::Error::msg)?;
            arguments
        }
        SshTransportLeaseResponse::Unavailable { version, reason } => {
            ensure!(
                version == SSH_TRANSPORT_LEASE_VERSION,
                "unsupported daemon SSH lease version"
            );
            tracing::debug!(%reason, "Daemon SSH lease unavailable before dispatch");
            return Ok(None);
        }
        SshTransportLeaseResponse::Rejected { version, reason } => {
            ensure!(
                version == SSH_TRANSPORT_LEASE_VERSION,
                "unsupported daemon SSH lease version"
            );
            return Err(anyhow!("daemon refused SSH transport lease: {reason}"));
        }
        _ => return Err(anyhow!("unexpected daemon SSH lease acquisition response")),
    };
    let (updates, state) = watch::channel(LeaseState::Active);
    let finishing = Arc::new(AtomicBool::new(false));
    let expected = request.clone();
    let requested_finish = finishing.clone();
    let monitor = tokio::spawn(async move {
        let result = async {
            let frame = read_frame(&mut reader)
                .await?
                .context("daemon SSH lease connection closed")?;
            let response: SshTransportLeaseResponse = serde_json::from_slice(&frame)
                .context("invalid daemon SSH lease lifetime response")?;
            match response {
                SshTransportLeaseResponse::Released {
                    version,
                    build_id,
                    local_wrapper_id,
                } if requested_finish.load(Ordering::Acquire)
                    && version == SSH_TRANSPORT_LEASE_VERSION
                    && build_id == expected.build_id
                    && local_wrapper_id == expected.local_wrapper_id =>
                {
                    Ok(())
                }
                SshTransportLeaseResponse::Revoked { version, reason }
                    if version == SSH_TRANSPORT_LEASE_VERSION =>
                {
                    Err(anyhow!("daemon SSH lease revoked: {reason}"))
                }
                _ => Err(anyhow!("unexpected daemon SSH lease lifetime response")),
            }
        }
        .await;
        updates.send_replace(match &result {
            Ok(()) => LeaseState::Released,
            Err(error) => LeaseState::Lost(format!("{error:#}")),
        });
        result
    });
    Ok(Some(DaemonSshLease {
        request,
        arguments,
        writer,
        state: LeaseWatch(state),
        finishing,
        monitor: Some(monitor),
    }))
}

#[cfg(test)]
mod tests;
