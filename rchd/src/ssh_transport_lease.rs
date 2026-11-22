//! Connection-owned lending of the daemon's supervised SSH master.
//!
//! The active build remains the sole execution authority. This route grants
//! only an attachment to its already-admitted endpoint, and holds the exact
//! master owner until the wrapper finishes its channels or loses the lease.

use crate::DaemonContext;
use crate::restart_admission::MaintenancePeer;
use crate::workers::{AdminIntent, BackgroundProbe, WorkerEndpointSnapshot};
use anyhow::{Context, Result};
use rch_common::ssh::OwnedSshTransport;
use rch_common::ssh_transport_lease::{
    MAX_SSH_TRANSPORT_LEASE_FRAME_BYTES, SSH_TRANSPORT_LEASE_ACQUIRE_TIMEOUT_MS,
    SSH_TRANSPORT_LEASE_ROUTE, SSH_TRANSPORT_LEASE_VERSION, SshTransportEndpoint,
    SshTransportLeaseFinish, SshTransportLeaseRequest, SshTransportLeaseResponse,
    validate_transport_arguments,
};
use rch_common::{BuildLocation, WorkerId};
use std::collections::BTreeMap;
use std::time::Duration;
use tokio::io::{AsyncBufRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;

#[derive(Clone)]
struct LeaseAdmission {
    endpoint: WorkerEndpointSnapshot,
    network: BackgroundProbe,
}

enum Acquisition {
    Ready(Box<(OwnedSshTransport, LeaseAdmission)>),
    Unavailable(String),
    Rejected(String),
}

pub(super) fn is_request(line: &str) -> bool {
    line.split_whitespace()
        .nth(1)
        .is_some_and(|target| target.split('?').next() == Some(SSH_TRANSPORT_LEASE_ROUTE))
}

fn decode_parameter(value: &str) -> std::result::Result<String, String> {
    let mut decoded = Vec::with_capacity(value.len());
    let mut bytes = value.bytes();
    while let Some(byte) = bytes.next() {
        match byte {
            b'%' => {
                let high = bytes
                    .next()
                    .and_then(|value| char::from(value).to_digit(16));
                let low = bytes
                    .next()
                    .and_then(|value| char::from(value).to_digit(16));
                let (Some(high), Some(low)) = (high, low) else {
                    return Err("invalid SSH transport parameter encoding".into());
                };
                decoded.push((high * 16 + low) as u8);
            }
            b'+' => decoded.push(b' '),
            other => decoded.push(other),
        }
    }
    String::from_utf8(decoded).map_err(|_| "SSH transport parameter is not UTF-8".into())
}

fn parse_request(line: &str) -> std::result::Result<SshTransportLeaseRequest, String> {
    if line.len() > MAX_SSH_TRANSPORT_LEASE_FRAME_BYTES || !line.ends_with('\n') {
        return Err("SSH transport request must be one bounded complete line".into());
    }
    let mut parts = line.split_whitespace();
    let method = parts.next();
    let target = parts.next().unwrap_or_default();
    if method != Some("GET") || parts.next().is_some() {
        return Err("SSH transport leasing requires GET and one request target".into());
    }
    let Some((path, query)) = target.split_once('?') else {
        return Err("SSH transport request is missing its admitted identity".into());
    };
    if path != SSH_TRANSPORT_LEASE_ROUTE {
        return Err("unsupported SSH transport route".into());
    }
    let mut values = BTreeMap::new();
    for parameter in query.split('&') {
        let Some((key, value)) = parameter.split_once('=') else {
            return Err("invalid SSH transport query parameter".into());
        };
        if !matches!(
            key,
            "build_id"
                | "local_wrapper_id"
                | "worker_id"
                | "host"
                | "user"
                | "identity_file"
                | "declared_os"
                | "server_alive_interval_secs"
                | "idle_timeout_secs"
        ) || values.insert(key, decode_parameter(value)?).is_some()
        {
            return Err("unknown or repeated SSH transport query parameter".into());
        }
    }
    let mut required = |key| {
        values
            .remove(key)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("SSH transport request is missing {key}"))
    };
    let request = SshTransportLeaseRequest {
        version: SSH_TRANSPORT_LEASE_VERSION,
        build_id: required("build_id")?
            .parse()
            .map_err(|_| "invalid SSH transport build identity")?,
        local_wrapper_id: required("local_wrapper_id")?,
        endpoint: SshTransportEndpoint {
            worker_id: WorkerId::new(required("worker_id")?),
            host: required("host")?,
            user: required("user")?,
            identity_file: required("identity_file")?,
            declared_os: None,
        },
        server_alive_interval_secs: required("server_alive_interval_secs")?
            .parse()
            .map_err(|_| "invalid SSH transport keepalive policy")?,
        idle_timeout_secs: required("idle_timeout_secs")?
            .parse()
            .map_err(|_| "invalid SSH transport idle policy")?,
    };
    let request = SshTransportLeaseRequest {
        endpoint: SshTransportEndpoint {
            declared_os: values.remove("declared_os"),
            ..request.endpoint
        },
        ..request
    };
    request.validate()?;
    Ok(request)
}

/// Re-observe ownership after every acquisition await. The endpoint and
/// administrative epoch captured before authentication never change to a new
/// inventory entry, even after A -> B -> A or disable -> enable transitions.
async fn authorize(
    ctx: &DaemonContext,
    request: &SshTransportLeaseRequest,
    peer: Option<&MaintenancePeer>,
    admitted: Option<&LeaseAdmission>,
    acquiring: bool,
) -> std::result::Result<LeaseAdmission, String> {
    request.validate()?;
    if acquiring
        && (ctx.history.wrapper_cancelled(&request.local_wrapper_id)
            || ctx
                .cancellation
                .active_cancellations()
                .await
                .iter()
                .any(|record| record.build_id == request.build_id))
    {
        return Err("SSH transport build cancellation is already in progress".into());
    }
    let _release = ctx.history.lock_releases().await;
    let peer = peer
        .and_then(MaintenancePeer::revalidate)
        .ok_or("SSH transport peer process identity is unavailable or no longer live")?;
    if ctx.history.ownership_failed()
        || ctx.history.legacy_release_wrapper(
            request.build_id,
            request.endpoint.worker_id.as_str(),
            peer.pid,
            &peer.identity,
        ) != Some(request.local_wrapper_id.clone())
    {
        return Err("SSH transport request does not own the admitted build".into());
    }
    let build = ctx
        .history
        .active_build(request.build_id)
        .ok_or("SSH transport build is no longer active")?;
    if build.location != BuildLocation::Remote {
        return Err("SSH transport requires a remote build admission".into());
    }
    let endpoint = build
        .worker_endpoint
        .filter(WorkerEndpointSnapshot::has_runtime_identity)
        .ok_or("SSH transport requires the live admitted worker endpoint")?;
    if !request.endpoint.matches_worker(&endpoint.config) {
        return Err("SSH transport endpoint differs from the admitted build".into());
    }
    let worker = ctx
        .pool
        .get(&request.endpoint.worker_id)
        .await
        .ok_or("SSH transport worker was removed")?;
    let admission = admitted.cloned().unwrap_or_else(|| LeaseAdmission {
        endpoint: endpoint.clone(),
        network: worker.network_revision_guard(),
    });
    if endpoint.generation != admission.endpoint.generation {
        return Err("SSH transport admission endpoint changed".into());
    }
    let _endpoint = worker
        .lock_current_endpoint(&admission.endpoint)
        .await
        .ok_or("SSH transport worker endpoint was replaced")?;
    let _network = worker
        .lock_network_publication(&admission.network)
        .await
        .ok_or("SSH transport worker network admission was revoked")?;
    if matches!(
        worker.lifecycle().await.admin,
        AdminIntent::Disabled | AdminIntent::Drained
    ) {
        return Err("SSH transport worker is administratively unavailable".into());
    }
    // Revalidation after queued local locks never upgrades a recycled PID.
    peer.revalidate()
        .ok_or("SSH transport peer process no longer owns this connection")?;
    if acquiring
        && (ctx.history.wrapper_cancelled(&request.local_wrapper_id)
            || ctx
                .cancellation
                .active_cancellations()
                .await
                .iter()
                .any(|record| record.build_id == request.build_id))
    {
        return Err("SSH transport build cancellation is already in progress".into());
    }
    // Cancellation can finalize history without the legacy release gate.
    // Re-observe exact active ownership after every queued local lock too.
    if ctx.history.ownership_failed()
        || ctx.history.legacy_release_wrapper(
            request.build_id,
            request.endpoint.worker_id.as_str(),
            peer.pid,
            &peer.identity,
        ) != Some(request.local_wrapper_id.clone())
    {
        return Err("SSH transport build ownership ended while acquiring its lease".into());
    }
    Ok(admission)
}

async fn acquire(
    ctx: &DaemonContext,
    request: &SshTransportLeaseRequest,
    peer: Option<&MaintenancePeer>,
    deadline: Instant,
) -> Acquisition {
    let admitted = match authorize(ctx, request, peer, None, true).await {
        Ok(admitted) => admitted,
        Err(reason) => return Acquisition::Rejected(reason),
    };
    let Some(pool) = ctx.worker_selector.ssh_pool.as_ref() else {
        return Acquisition::Unavailable("daemon SSH pooling is disabled".into());
    };
    if request.endpoint.declared_os.as_deref() == Some("windows") {
        return Acquisition::Unavailable("worker requires independent SSH sessions".into());
    }
    if !pool.matches_transport_policy(
        request.server_alive_interval_secs,
        request.idle_timeout_secs,
    ) {
        return Acquisition::Unavailable("dispatch SSH policy differs from the daemon pool".into());
    }
    let transport = pool
        .try_external_transport_until(&admitted.endpoint.config, deadline)
        .await;
    // Absence or failure is optional only while the original owner and worker
    // still agree. A disable/retarget/cancellation must not become fallback.
    if let Err(reason) = authorize(ctx, request, peer, Some(&admitted), true).await {
        return Acquisition::Rejected(reason);
    }
    if Instant::now() >= deadline {
        return Acquisition::Rejected(
            "SSH transport acquisition exceeded its ownership deadline".into(),
        );
    }
    match transport {
        Ok(Some(transport)) => Acquisition::Ready(Box::new((transport, admitted))),
        Ok(None) => {
            Acquisition::Unavailable("another dispatch is using the pooled transport".into())
        }
        Err(error) => {
            Acquisition::Unavailable(format!("pooled SSH transport is unavailable: {error}"))
        }
    }
}

async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    response: &SshTransportLeaseResponse,
) -> Result<()> {
    let mut frame = serde_json::to_vec(response)?;
    frame.push(b'\n');
    anyhow::ensure!(
        frame.len() <= MAX_SSH_TRANSPORT_LEASE_FRAME_BYTES,
        "SSH transport response exceeds its frame limit"
    );
    tokio::time::timeout(
        rch_common::timing::scale_duration(Duration::from_secs(2)),
        writer.write_all(&frame),
    )
    .await
    .context("SSH transport response timed out")??;
    Ok(())
}

fn rejected(reason: String) -> SshTransportLeaseResponse {
    SshTransportLeaseResponse::Rejected {
        version: SSH_TRANSPORT_LEASE_VERSION,
        reason,
    }
}

fn revoked(reason: String) -> SshTransportLeaseResponse {
    SshTransportLeaseResponse::Revoked {
        version: SSH_TRANSPORT_LEASE_VERSION,
        reason,
    }
}

pub(super) async fn handle<R, W>(
    line: &str,
    ctx: &DaemonContext,
    peer: Option<&MaintenancePeer>,
    reader: &mut R,
    writer: &mut W,
) -> Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let request = match parse_request(line) {
        Ok(request) => request,
        Err(reason) => return write_frame(writer, &rejected(reason)).await,
    };
    let deadline = Instant::now()
        + rch_common::timing::scale_duration(Duration::from_millis(
            SSH_TRANSPORT_LEASE_ACQUIRE_TIMEOUT_MS,
        ));
    let acquired = tokio::select! {
        biased;
        early = reader.read_u8() => {
            return match early {
                Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => Ok(()),
                Err(error) => Err(error.into()),
                Ok(_) => write_frame(writer, &rejected("SSH transport received data before grant".into())).await,
            };
        }
        acquired = tokio::time::timeout_at(deadline, acquire(ctx, &request, peer, deadline)) => {
            acquired.unwrap_or_else(|_| Acquisition::Rejected("SSH transport acquisition exceeded its ownership deadline".into()))
        }
    };
    let (transport, admitted) = match acquired {
        Acquisition::Ready(ready) => *ready,
        Acquisition::Unavailable(reason) => {
            return write_frame(
                writer,
                &SshTransportLeaseResponse::Unavailable {
                    version: SSH_TRANSPORT_LEASE_VERSION,
                    reason,
                },
            )
            .await;
        }
        Acquisition::Rejected(reason) => return write_frame(writer, &rejected(reason)).await,
    };
    let arguments = transport
        .arguments()?
        .into_iter()
        .map(|argument| {
            argument
                .into_string()
                .map_err(|_| anyhow::anyhow!("SSH transport argument is not UTF-8"))
        })
        .collect::<Result<Vec<_>>>()?;
    validate_transport_arguments(&arguments).map_err(anyhow::Error::msg)?;
    if Instant::now() >= deadline {
        return write_frame(
            writer,
            &rejected("SSH transport grant exceeded its ownership deadline".into()),
        )
        .await;
    }
    write_frame(
        writer,
        &SshTransportLeaseResponse::Ready {
            request: request.clone(),
            arguments,
        },
    )
    .await?;

    let mut finish_line = String::new();
    let mut changes = ctx.pool.subscribe_endpoint_changes();
    let mut cadence =
        tokio::time::interval(rch_common::timing::scale_duration(Duration::from_secs(1)));
    cadence.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let finish = {
        // Pin one reader across the polling branches: cancelling and recreating
        // a line reader could discard a fragmented completion frame's prefix.
        let read_finish = super::read_line_with_limit(
            reader,
            &mut finish_line,
            MAX_SSH_TRANSPORT_LEASE_FRAME_BYTES,
        );
        tokio::pin!(read_finish);
        let closed = transport.closed();
        tokio::pin!(closed);
        let mut network = admitted.network.clone();
        let network_closed = network.run(std::future::pending::<()>());
        tokio::pin!(network_closed);
        loop {
            tokio::select! {
                biased;
                () = &mut closed => break Err("pooled SSH master closed or was revoked".into()),
                _ = &mut network_closed => break Err("worker network admission was revoked".into()),
                result = &mut read_finish => break result.map_err(|error| error.to_string()),
                _ = async { tokio::select! { _ = cadence.tick() => {}, _ = changes.changed() => {} } } => {
                    // Cancellation alone does not revoke an existing owner's
                    // cleanup transport. A new lease is refused by acquire().
                    match tokio::time::timeout(
                        rch_common::timing::scale_duration(Duration::from_secs(2)),
                        authorize(ctx, &request, peer, Some(&admitted), false),
                    ).await {
                        Ok(Ok(_)) => {},
                        Ok(Err(reason)) => break Err(reason),
                        Err(_) => break Err("SSH transport owner revalidation timed out".into()),
                    }
                }
            }
        }
    };
    let read = match finish {
        Ok(read) => read,
        Err(reason) => return write_frame(writer, &revoked(reason)).await,
    };
    if read == 0 {
        return Ok(()); // Abandonment drains after the master's other users.
    }
    let finish = serde_json::from_str::<SshTransportLeaseFinish>(&finish_line);
    if !finish_line.ends_with('\n') || !finish.is_ok_and(|finish| finish.matches_request(&request))
    {
        return write_frame(
            writer,
            &revoked("SSH transport completion does not match its lease".into()),
        )
        .await;
    }
    match tokio::time::timeout(
        rch_common::timing::scale_duration(Duration::from_secs(2)),
        authorize(ctx, &request, peer, Some(&admitted), false),
    )
    .await
    {
        Ok(Ok(_)) => {}
        Ok(Err(reason)) => return write_frame(writer, &revoked(reason)).await,
        Err(_) => {
            return write_frame(
                writer,
                &revoked("SSH transport completion revalidation timed out".into()),
            )
            .await;
        }
    }
    transport.complete();
    write_frame(
        writer,
        &SshTransportLeaseResponse::Released {
            version: SSH_TRANSPORT_LEASE_VERSION,
            build_id: request.build_id,
            local_wrapper_id: request.local_wrapper_id,
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disk_pressure::DiskHeadroomAdmission;
    use crate::workers::WorkerPool;
    use rch_common::{WorkerConfig, WorkerStatus};
    use std::sync::Arc;
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::net::UnixStream;

    async fn admitted_build() -> (DaemonContext, MaintenancePeer, SshTransportLeaseRequest) {
        let config = WorkerConfig {
            id: WorkerId::new("lease-worker"),
            host: "lease-worker.invalid".into(),
            user: "builder".into(),
            identity_file: "/tmp/rch-lease-key".into(),
            ..WorkerConfig::default()
        };
        let pool = WorkerPool::new();
        pool.add_worker(config.clone()).await;
        let worker = pool.get(&config.id).await.unwrap();
        let ctx = crate::test_daemon_context(pool);
        let peer = MaintenancePeer::capture(
            i32::try_from(crate::history::observable_test_process_id()).ok(),
        )
        .unwrap();
        let wrapper = rch_common::job_identity::JobIdentity::new_local().local_wrapper_id;
        let build = ctx
            .history
            .try_start_active_build_with_waiter(
                "lease-project".into(),
                config.id.to_string(),
                "cargo build".into(),
                peer.pid,
                Some(wrapper.clone()),
                1,
                BuildLocation::Remote,
                None,
                DiskHeadroomAdmission::default(),
                Some(worker.endpoint_snapshot().await),
            )
            .unwrap()
            .unwrap();
        let request = SshTransportLeaseRequest {
            version: SSH_TRANSPORT_LEASE_VERSION,
            build_id: build.id,
            local_wrapper_id: wrapper,
            endpoint: SshTransportEndpoint::from_worker(&config),
            server_alive_interval_secs: 15,
            idle_timeout_secs: 60,
        };
        (ctx, peer, request)
    }

    fn request_line(request: &SshTransportLeaseRequest) -> String {
        format!(
            "GET {SSH_TRANSPORT_LEASE_ROUTE}?build_id={}&local_wrapper_id={}&worker_id={}&host={}&user={}&identity_file={}&server_alive_interval_secs={}&idle_timeout_secs={}\n",
            request.build_id,
            request.local_wrapper_id,
            request.endpoint.worker_id,
            request.endpoint.host,
            request.endpoint.user,
            request.endpoint.identity_file,
            request.server_alive_interval_secs,
            request.idle_timeout_secs,
        )
    }

    #[tokio::test]
    async fn ssh_transport_lease_query_is_exact_bounded_and_decodes_literal_paths() {
        let (_, _, request) = admitted_build().await;
        let line = request_line(&request);
        assert_eq!(parse_request(&line).unwrap(), request);
        let encoded = line.replace("/tmp/rch-lease-key", "%2Ftmp%2Fa+key%26%23%25%3D%C3%A9");
        assert_eq!(
            parse_request(&encoded).unwrap().endpoint.identity_file,
            "/tmp/a key&#%=é"
        );
        for bad in [
            line.replace("GET ", "POST "),
            line.replace("idle_timeout_secs=60", "idle_timeout_secs=0"),
            line.replace("user=builder", "user="),
            line.replace("user=builder", "user=%FF"),
            line.replace("user=builder", "user=%2"),
            line.replace("user=builder", "user=%00"),
            line.replace("user=builder", "user=builder&user=other"),
            line.replace("user=builder", "user=builder&redial=true"),
            line.trim_end().to_owned(),
            format!("GET {SSH_TRANSPORT_LEASE_ROUTE}\n"),
            format!(
                "GET {SSH_TRANSPORT_LEASE_ROUTE}?user={}\n",
                "x".repeat(MAX_SSH_TRANSPORT_LEASE_FRAME_BYTES)
            ),
        ] {
            assert!(is_request(&bad), "{bad}");
            assert!(parse_request(&bad).is_err());
        }
        assert!(!is_request("GET /status\n"));
        assert!(!is_request("GET /ssh-transport-v10\n"));
    }

    #[tokio::test]
    async fn ssh_transport_lease_authority_requires_exact_live_owner_and_endpoint() {
        let (ctx, peer, request) = admitted_build().await;
        let admitted = authorize(&ctx, &request, Some(&peer), None, true)
            .await
            .unwrap();
        assert!(authorize(&ctx, &request, None, None, true).await.is_err());
        let mut wrong_peer = peer.clone();
        wrong_peer.pid += 1;
        assert!(
            authorize(&ctx, &request, Some(&wrong_peer), None, true)
                .await
                .is_err()
        );
        for field in ["build", "wrapper", "worker", "host", "user", "key", "os"] {
            let mut other = request.clone();
            match field {
                "build" => other.build_id += 100,
                "wrapper" => other.local_wrapper_id.push_str("-other"),
                "worker" => other.endpoint.worker_id = WorkerId::new("other-worker"),
                "host" => other.endpoint.host = "other.invalid".into(),
                "user" => other.endpoint.user = "other-user".into(),
                "key" => other.endpoint.identity_file = "/tmp/other-key".into(),
                "os" => other.endpoint.declared_os = Some("windows".into()),
                _ => unreachable!(),
            }
            assert!(
                authorize(&ctx, &other, Some(&peer), None, true)
                    .await
                    .is_err(),
                "{field}"
            );
        }
        ctx.history
            .finish_active_build(request.build_id, 0, None, None, None)
            .unwrap();
        assert!(
            authorize(&ctx, &request, Some(&peer), Some(&admitted), false)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn ssh_transport_lease_retains_endpoint_and_administrative_generations() {
        for transition in ["retarget", "replace", "disable_enable"] {
            let (ctx, peer, request) = admitted_build().await;
            let admitted = authorize(&ctx, &request, Some(&peer), None, true)
                .await
                .unwrap();
            let worker = ctx.pool.get(&request.endpoint.worker_id).await.unwrap();
            match transition {
                "retarget" => {
                    let mut changed = admitted.endpoint.config.clone();
                    changed.host = "other.invalid".into();
                    ctx.pool.add_worker(changed).await;
                    ctx.pool.add_worker(admitted.endpoint.config.clone()).await;
                }
                "replace" => {
                    assert!(ctx.pool.remove_worker(&request.endpoint.worker_id).await);
                    ctx.pool.add_worker(admitted.endpoint.config.clone()).await;
                }
                "disable_enable" => {
                    worker.disable(None).await;
                    worker.enable().await;
                }
                _ => unreachable!(),
            }
            assert!(
                authorize(&ctx, &request, Some(&peer), Some(&admitted), false)
                    .await
                    .is_err(),
                "{transition}"
            );
        }
    }

    #[tokio::test]
    async fn ssh_transport_lease_rechecks_owner_after_queued_publication_lock() {
        let (ctx, peer, request) = admitted_build().await;
        let admitted = authorize(&ctx, &request, Some(&peer), None, true)
            .await
            .unwrap();
        let worker = ctx.pool.get(&request.endpoint.worker_id).await.unwrap();
        let publication = worker
            .lock_network_publication(&admitted.network)
            .await
            .unwrap();
        let checking = authorize(&ctx, &request, Some(&peer), Some(&admitted), false);
        tokio::pin!(checking);
        std::future::poll_fn(|cx| {
            assert!(std::future::Future::poll(checking.as_mut(), cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        // This mirrors cancellation finalization, which owns durable history
        // directly rather than waiting for the legacy release gate.
        ctx.history
            .finish_active_build(request.build_id, 130, None, None, None)
            .unwrap();
        drop(publication);
        assert!(checking.await.is_err());
    }

    #[tokio::test]
    async fn ssh_transport_lease_draining_preserves_existing_build_but_drained_refuses() {
        let (ctx, peer, request) = admitted_build().await;
        let admitted = authorize(&ctx, &request, Some(&peer), None, true)
            .await
            .unwrap();
        let worker = ctx.pool.get(&request.endpoint.worker_id).await.unwrap();
        worker.set_status(WorkerStatus::Draining).await;
        assert!(
            authorize(&ctx, &request, Some(&peer), Some(&admitted), true)
                .await
                .is_ok()
        );
        assert!(
            authorize(&ctx, &request, Some(&peer), Some(&admitted), false)
                .await
                .is_ok()
        );
        worker.set_status(WorkerStatus::Drained).await;
        assert!(
            authorize(&ctx, &request, Some(&peer), Some(&admitted), false)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn ssh_transport_lease_unknown_runtime_endpoint_never_borrows_current_inventory() {
        let (ctx, peer, mut request) = admitted_build().await;
        let build = ctx.history.start_active_build_with_wrapper(
            "unknown-endpoint".into(),
            request.endpoint.worker_id.to_string(),
            "cargo build".into(),
            peer.pid,
            Some(request.local_wrapper_id.clone()),
            1,
            BuildLocation::Remote,
        );
        request.build_id = build.id;
        assert!(
            authorize(&ctx, &request, Some(&peer), None, true)
                .await
                .is_err()
        );
    }

    async fn exchange(ctx: DaemonContext, line: String) -> SshTransportLeaseResponse {
        let (mut client, server) = UnixStream::pair().unwrap();
        let (shutdown, _requests) = tokio::sync::mpsc::channel(1);
        let handler = tokio::spawn(super::super::handle_connection_with_metrics(
            server, ctx, shutdown, None,
        ));
        client.write_all(line.as_bytes()).await.unwrap();
        let mut reply = String::new();
        tokio::time::timeout(
            Duration::from_secs(3),
            BufReader::new(client).read_line(&mut reply),
        )
        .await
        .unwrap()
        .unwrap();
        handler.await.unwrap().unwrap();
        assert!(reply.ends_with('\n'));
        serde_json::from_str(&reply).unwrap()
    }

    #[tokio::test]
    async fn ssh_transport_lease_wire_distinguishes_unavailable_from_ownership_rejection() {
        let (mut ctx, _, request) = admitted_build().await;
        assert!(matches!(
            exchange(ctx.clone(), request_line(&request)).await,
            SshTransportLeaseResponse::Unavailable { .. }
        ));
        let mut wrong_owner = request.clone();
        wrong_owner.local_wrapper_id.push_str("-other");
        assert!(matches!(
            exchange(ctx.clone(), request_line(&wrong_owner)).await,
            SshTransportLeaseResponse::Rejected { .. }
        ));
        let pool = Arc::new(rch_common::SshPool::new(rch_common::SshOptions {
            control_master: true,
            control_persist_idle: Some(Duration::from_secs(30)),
            server_alive_interval: Some(Duration::from_secs(15)),
            ..Default::default()
        }));
        Arc::get_mut(&mut ctx.worker_selector)
            .unwrap()
            .set_ssh_pool(Some(pool));
        let response = exchange(ctx.clone(), request_line(&request)).await;
        assert!(
            matches!(response, SshTransportLeaseResponse::Unavailable { reason, .. } if reason.contains("policy"))
        );
        let response = exchange(ctx, request_line(&request).replace("GET ", "POST ")).await;
        assert!(matches!(
            response,
            SshTransportLeaseResponse::Rejected { .. }
        ));
    }
}
