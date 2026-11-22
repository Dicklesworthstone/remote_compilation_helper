use super::{DaemonSshLease, acquire_with_connection};
use crate::hook::ssh::{
    guard_offload_ssh_operation, offload_ssh_transport_arguments,
    offload_ssh_transport_shell_arguments, with_daemon_offload_ssh, with_owned_offload_ssh,
};
use rch_common::ssh_transport_lease::{
    MAX_SSH_TRANSPORT_LEASE_FRAME_BYTES, SSH_TRANSPORT_LEASE_VERSION, SshTransportEndpoint,
    SshTransportLeaseFinish, SshTransportLeaseRequest, SshTransportLeaseResponse,
};
use rch_common::{TransferConfig, WorkerConfig, WorkerId};
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::timeout;

const TEST_TIMEOUT: Duration = Duration::from_secs(5);

fn worker() -> WorkerConfig {
    WorkerConfig {
        id: WorkerId::new("worker-one"),
        host: "worker.example".into(),
        user: "builder".into(),
        identity_file: "/home/build user/.ssh/key&one".into(),
        total_slots: 4,
        priority: 100,
        tags: vec![rch_common::os_tag("linux")],
        tools: Vec::new(),
    }
}

fn request() -> SshTransportLeaseRequest {
    SshTransportLeaseRequest {
        version: SSH_TRANSPORT_LEASE_VERSION,
        build_id: 41,
        local_wrapper_id: "rchw-lease-owner".into(),
        endpoint: SshTransportEndpoint::from_worker(&worker()),
        server_alive_interval_secs: 15,
        idle_timeout_secs: 60,
    }
}

fn attachment_arguments() -> Vec<String> {
    [
        "-S",
        "/tmp/rch leased connection/master",
        "-o",
        "ControlMaster=no",
        "-o",
        "ControlPersist=no",
        "-o",
        "ProxyCommand=false",
        "-o",
        "ConnectionAttempts=1",
        "-o",
        "BatchMode=yes",
        "-T",
    ]
    .map(str::to_owned)
    .to_vec()
}

fn ready() -> SshTransportLeaseResponse {
    SshTransportLeaseResponse::Ready {
        request: request(),
        arguments: attachment_arguments(),
    }
}

fn released() -> SshTransportLeaseResponse {
    let expected = request();
    SshTransportLeaseResponse::Released {
        version: expected.version,
        build_id: expected.build_id,
        local_wrapper_id: expected.local_wrapper_id,
    }
}

struct Fixture {
    _directory: Option<tempfile::TempDir>,
    socket: String,
    connection: Mutex<Option<UnixStream>>,
    server: JoinHandle<()>,
}

impl Fixture {
    fn new<F, Fut>(operation: F) -> Self
    where
        F: FnOnce(UnixStream) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let (client, server) = UnixStream::pair().unwrap();
        Self {
            _directory: None,
            socket: String::new(),
            connection: Mutex::new(Some(client)),
            server: tokio::spawn(operation(server)),
        }
    }

    fn named<F, Fut>(operation: F) -> Self
    where
        F: FnOnce(UnixStream) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("lease.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = timeout(TEST_TIMEOUT, listener.accept())
                .await
                .expect("client must contact the fixture")
                .unwrap();
            operation(stream).await;
        });
        Self {
            _directory: Some(directory),
            socket: socket.to_str().unwrap().to_owned(),
            connection: Mutex::new(None),
            server,
        }
    }

    fn take_connection(&self) -> UnixStream {
        self.connection
            .lock()
            .unwrap()
            .take()
            .expect("fixture connection is consumed once")
    }

    async fn acquire_result(&self, budget: Duration) -> anyhow::Result<Option<DaemonSshLease>> {
        let connection = self.take_connection();
        acquire_with_connection(std::future::ready(Ok(connection)), request(), budget).await
    }

    async fn acquire(&self) -> DaemonSshLease {
        self.acquire_result(TEST_TIMEOUT)
            .await
            .expect("valid fixture grant")
            .expect("fixture granted a lease")
    }

    async fn finish(self) {
        timeout(TEST_TIMEOUT, self.server)
            .await
            .expect("fixture must finish")
            .expect("fixture must not panic");
    }
}

async fn read_request(stream: UnixStream) -> (BufReader<OwnedReadHalf>, OwnedWriteHalf) {
    let (reader, writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    timeout(TEST_TIMEOUT, reader.read_line(&mut line))
        .await
        .expect("request must be complete")
        .unwrap();
    assert_eq!(
        line,
        "GET /ssh-transport-v1?build_id=41&local_wrapper_id=rchw-lease-owner&worker_id=worker-one&host=worker.example&user=builder&identity_file=%2Fhome%2Fbuild%20user%2F.ssh%2Fkey%26one&server_alive_interval_secs=15&idle_timeout_secs=60&declared_os=linux\n"
    );
    (reader, writer)
}

async fn send_frame(writer: &mut OwnedWriteHalf, response: &SshTransportLeaseResponse) {
    let mut frame = serde_json::to_vec(response).unwrap();
    frame.push(b'\n');
    writer.write_all(&frame).await.unwrap();
    writer.flush().await.unwrap();
}

async fn read_finish(reader: &mut BufReader<OwnedReadHalf>) {
    let mut line = String::new();
    timeout(TEST_TIMEOUT, reader.read_line(&mut line))
        .await
        .expect("complete must send one finish frame")
        .unwrap();
    let finish: SshTransportLeaseFinish = serde_json::from_str(&line).unwrap();
    assert!(finish.matches_request(&request()));
}

#[tokio::test]
async fn daemon_ssh_lease_echoes_admission_and_confirms_explicit_release() {
    let fixture = Fixture::new(|stream| async move {
        let (mut reader, mut writer) = read_request(stream).await;
        send_frame(&mut writer, &ready()).await;
        read_finish(&mut reader).await;
        send_frame(&mut writer, &released()).await;
    });
    let lease = fixture.acquire().await;
    assert_eq!(lease.arguments(), attachment_arguments());
    assert!(lease.watch().lost_reason().is_none());
    lease.complete().await.unwrap();
    fixture.finish().await;
}

#[tokio::test]
async fn daemon_ssh_lease_drop_closes_both_stream_halves_without_completion() {
    let fixture = Fixture::new(|stream| async move {
        let (mut reader, mut writer) = read_request(stream).await;
        send_frame(&mut writer, &ready()).await;
        let mut remaining = Vec::new();
        timeout(TEST_TIMEOUT, reader.read_to_end(&mut remaining))
            .await
            .expect("dropping the lease must close its monitor and writer")
            .unwrap();
        assert!(
            remaining.is_empty(),
            "abandonment must not claim completion"
        );
    });
    let lease = fixture.acquire().await;
    let watch = lease.watch();
    drop(lease);
    assert!(
        !timeout(TEST_TIMEOUT, watch.lost())
            .await
            .unwrap()
            .is_empty()
    );
    fixture.finish().await;
}

#[tokio::test]
async fn daemon_ssh_lease_unavailable_or_legacy_eof_can_fall_back_before_work() {
    for reply in [
        Some(SshTransportLeaseResponse::Unavailable {
            version: SSH_TRANSPORT_LEASE_VERSION,
            reason: "pooling_disabled".into(),
        }),
        None,
    ] {
        let fixture = Fixture::new(move |stream| async move {
            let (_reader, mut writer) = read_request(stream).await;
            if let Some(reply) = reply {
                send_frame(&mut writer, &reply).await;
            }
        });
        assert!(
            fixture
                .acquire_result(TEST_TIMEOUT)
                .await
                .unwrap()
                .is_none()
        );
        fixture.finish().await;
    }
}

#[tokio::test]
async fn daemon_ssh_lease_partial_grant_cannot_hold_acquisition_past_its_budget() {
    let (release, released) = oneshot::channel();
    let (partial, observed) = oneshot::channel();
    let fixture = Fixture::new(move |stream| async move {
        let (_reader, mut writer) = read_request(stream).await;
        writer.write_all(b"{\"status\":\"ready\"").await.unwrap();
        partial.send(()).unwrap();
        // Keep the incomplete frame open until the client's own deadline wins.
        released.await.unwrap();
    });
    let connection = fixture.take_connection();
    let acquiring = tokio::spawn(async move {
        acquire_with_connection(
            std::future::ready(Ok(connection)),
            request(),
            Duration::from_secs(60),
        )
        .await
    });
    timeout(TEST_TIMEOUT, observed).await.unwrap().unwrap();
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(61)).await;
    let result = timeout(TEST_TIMEOUT, acquiring)
        .await
        .expect("a partial grant must not strand the caller")
        .unwrap()
        .unwrap();
    tokio::time::resume();
    assert!(
        result.is_none(),
        "no complete grant or remote work occurred"
    );
    release.send(()).unwrap();
    fixture.finish().await;
}

#[tokio::test]
async fn daemon_ssh_lease_rejection_or_changed_grant_never_selects_fallback() {
    let mut other_owner = request();
    other_owner.local_wrapper_id = "rchw-other-owner".into();
    let mut other_endpoint = request();
    other_endpoint.endpoint.host = "other.example".into();
    let mut unsafe_arguments = attachment_arguments();
    unsafe_arguments[7] = "ProxyCommand=ssh other.example".into();
    let replies = [
        SshTransportLeaseResponse::Rejected {
            version: SSH_TRANSPORT_LEASE_VERSION,
            reason: "admission_changed".into(),
        },
        SshTransportLeaseResponse::Ready {
            request: other_owner,
            arguments: attachment_arguments(),
        },
        SshTransportLeaseResponse::Ready {
            request: other_endpoint,
            arguments: attachment_arguments(),
        },
        SshTransportLeaseResponse::Ready {
            request: request(),
            arguments: unsafe_arguments,
        },
        SshTransportLeaseResponse::Unavailable {
            version: SSH_TRANSPORT_LEASE_VERSION + 1,
            reason: "future_protocol".into(),
        },
    ];
    for reply in replies {
        let fixture = Fixture::new(move |stream| async move {
            let (_reader, mut writer) = read_request(stream).await;
            send_frame(&mut writer, &reply).await;
        });
        assert!(fixture.acquire_result(TEST_TIMEOUT).await.is_err());
        fixture.finish().await;
    }
}

#[tokio::test]
async fn daemon_ssh_lease_rejection_stops_the_dispatch_route_before_work_or_retry() {
    struct ThreadMockOverride;
    impl Drop for ThreadMockOverride {
        fn drop(&mut self) {
            rch_common::mock::set_thread_mock_override(None);
        }
    }
    rch_common::mock::set_thread_mock_override(Some(false));
    let _mock = ThreadMockOverride;
    let fixture = Fixture::named(|stream| async move {
        let (_reader, mut writer) = read_request(stream).await;
        send_frame(
            &mut writer,
            &SshTransportLeaseResponse::Rejected {
                version: SSH_TRANSPORT_LEASE_VERSION,
                reason: "admitted_owner_was_cancelled".into(),
            },
        )
        .await;
    });
    let transfer = TransferConfig {
        ssh_control_persist_secs: Some(60),
        ssh_server_alive_interval_secs: Some(15),
        ..TransferConfig::default()
    };
    let polled = AtomicBool::new(false);
    let outcome = timeout(
        TEST_TIMEOUT,
        with_owned_offload_ssh(
            worker(),
            &transfer,
            &fixture.socket,
            Some(41),
            Some("rchw-lease-owner"),
            async {
                polled.store(true, Ordering::SeqCst);
                Ok(())
            },
        ),
    )
    .await
    .expect("rejection must stop before trying any SSH transport");
    assert!(
        outcome
            .unwrap_err()
            .is::<crate::transfer::RemoteExecutionUnconfirmed>()
    );
    assert!(!polled.load(Ordering::SeqCst));
    fixture.finish().await;
}

#[tokio::test]
async fn daemon_ssh_lease_lifetime_failures_are_monotonic_and_bounded() {
    let mut early_release = serde_json::to_vec(&released()).unwrap();
    early_release.push(b'\n');
    let frames = [
        Vec::new(),
        b"{\"status\":\"unrecognized\"}\n".to_vec(),
        b"{\"status\":\"revoked\"".to_vec(),
        early_release,
        vec![b'x'; MAX_SSH_TRANSPORT_LEASE_FRAME_BYTES + 1],
    ];
    for frame in frames {
        let fixture = Fixture::new(move |stream| async move {
            let (_reader, mut writer) = read_request(stream).await;
            send_frame(&mut writer, &ready()).await;
            // The over-bound case must be refused without waiting for newline.
            writer.write_all(&frame).await.unwrap();
        });
        let lease = fixture.acquire().await;
        let watch = lease.watch();
        let reason = timeout(TEST_TIMEOUT, watch.lost()).await.unwrap();
        assert!(!reason.is_empty());
        assert_eq!(watch.lost_reason().as_deref(), Some(reason.as_str()));
        assert_eq!(watch.clone().lost().await, reason);
        assert!(lease.complete().await.is_err());
        fixture.finish().await;
    }
}

#[tokio::test]
async fn daemon_ssh_lease_wrong_release_identity_is_not_acknowledged() {
    let fixture = Fixture::new(|stream| async move {
        let (mut reader, mut writer) = read_request(stream).await;
        send_frame(&mut writer, &ready()).await;
        read_finish(&mut reader).await;
        send_frame(
            &mut writer,
            &SshTransportLeaseResponse::Released {
                version: SSH_TRANSPORT_LEASE_VERSION,
                build_id: request().build_id + 1,
                local_wrapper_id: request().local_wrapper_id,
            },
        )
        .await;
    });
    assert!(fixture.acquire().await.complete().await.is_err());
    fixture.finish().await;
}

struct RecordDrop(Arc<AtomicBool>);

impl Drop for RecordDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn daemon_ssh_lease_loss_cancels_inner_work_but_keeps_settlement_and_blocks_redial() {
    let (started, entered) = oneshot::channel();
    let fixture = Fixture::new(move |stream| async move {
        let (_reader, mut writer) = read_request(stream).await;
        send_frame(&mut writer, &ready()).await;
        entered.await.unwrap();
        send_frame(
            &mut writer,
            &SshTransportLeaseResponse::Revoked {
                version: SSH_TRANSPORT_LEASE_VERSION,
                reason: "worker_disabled".into(),
            },
        )
        .await;
    });
    let lease = fixture.acquire().await;
    let dropped = Arc::new(AtomicBool::new(false));
    let settled = Arc::new(AtomicBool::new(false));
    let inner_dropped = dropped.clone();
    let settlement = settled.clone();
    let operation = with_daemon_offload_ssh(worker(), lease, async move {
        let outcome = guard_offload_ssh_operation(async move {
            let _lifetime = RecordDrop(inner_dropped);
            started.send(()).unwrap();
            std::future::pending::<anyhow::Result<()>>().await
        })
        .await;
        assert!(
            outcome
                .as_ref()
                .unwrap_err()
                .is::<crate::transfer::RemoteExecutionUnconfirmed>()
        );
        // This is the same outside-the-inner-future position as production's
        // source settlement. Losing transport must not drop this bookkeeping.
        settlement.store(true, Ordering::SeqCst);
        let arguments = offload_ssh_transport_arguments(&worker())
            .expect("revocation must retain an explicit transport");
        assert_eq!(arguments[0], "-S");
        assert_eq!(arguments[1], "none");
        assert!(
            arguments
                .windows(2)
                .any(|pair| pair == ["-o", "ProxyCommand=false"])
        );
        let shell = offload_ssh_transport_shell_arguments(&worker())
            .expect("rsync must not revert to ordinary SSH");
        assert!(shell.starts_with("-S none "), "{shell}");
        assert!(shell.contains("-o ProxyCommand=false"), "{shell}");
        outcome
    });
    let outcome: anyhow::Result<()> = timeout(TEST_TIMEOUT, operation)
        .await
        .expect("lease loss must wake and cancel the inner operation");
    assert!(
        outcome
            .unwrap_err()
            .is::<crate::transfer::RemoteExecutionUnconfirmed>()
    );
    assert!(dropped.load(Ordering::SeqCst));
    assert!(settled.load(Ordering::SeqCst));
    fixture.finish().await;
}

#[tokio::test]
async fn daemon_ssh_lease_already_lost_never_polls_a_new_operation() {
    let fixture = Fixture::new(|stream| async move {
        let (_reader, mut writer) = read_request(stream).await;
        send_frame(&mut writer, &ready()).await;
    });
    let lease = fixture.acquire().await;
    timeout(TEST_TIMEOUT, lease.watch().lost()).await.unwrap();
    let started = AtomicBool::new(false);
    let result = with_daemon_offload_ssh(worker(), lease, async {
        guard_offload_ssh_operation(async {
            started.store(true, Ordering::SeqCst);
            Ok(())
        })
        .await
    })
    .await;
    assert!(
        result
            .unwrap_err()
            .is::<crate::transfer::RemoteExecutionUnconfirmed>()
    );
    assert!(!started.load(Ordering::SeqCst));
    fixture.finish().await;
}

#[tokio::test]
async fn daemon_ssh_lease_finish_failure_preserves_a_verified_result() {
    let fixture = Fixture::new(|stream| async move {
        let (mut reader, mut writer) = read_request(stream).await;
        send_frame(&mut writer, &ready()).await;
        read_finish(&mut reader).await;
        // Completion reached the server, but its response was lost.
    });
    let lease = fixture.acquire().await;
    let result = with_daemon_offload_ssh(worker(), lease, async {
        guard_offload_ssh_operation(async { Ok(29) }).await
    })
    .await
    .unwrap();
    assert_eq!(result, 29);
    fixture.finish().await;
}
