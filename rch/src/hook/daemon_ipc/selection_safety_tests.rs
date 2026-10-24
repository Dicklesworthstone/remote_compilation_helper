//! Exercise the production dispatch boundary without changing process-wide env.
//! Socket peers script replies; they do not simulate actual worker execution.

use super::*;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::AsyncWrite;

const REQUEST: &[u8] = b"GET /select-worker?project=owner&cores=1\n";

async fn query_fixture(
    reply: &[u8],
    wait: bool,
    dry_run: bool,
) -> anyhow::Result<SelectionResponse> {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("selection.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let server = async {
        let (stream, _) = listener.accept().await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut request = String::new();
        BufReader::new(reader)
            .read_line(&mut request)
            .await
            .unwrap();
        assert!(request.starts_with("GET /select-worker?"), "{request}");
        assert_eq!(request.contains("&wait=1"), wait);
        assert_eq!(request.contains("&dry_run=1"), dry_run);
        assert!(request.contains("&local_wrapper_id=selection-test-owner"));
        // Oversized replies may be rejected before all bytes are written.
        let _ = writer.write_all(reply).await;
    };
    let client = query_daemon_with_mode(
        path.to_str().unwrap(),
        "owner",
        1,
        0,
        "cargo build",
        None,
        RequiredRuntime::None,
        CommandPriority::Normal,
        0,
        Some(std::process::id()),
        Some("selection-test-owner"),
        wait,
        &[],
        false,
        &[],
        dry_run,
    );
    let (result, ()) = timeout(Duration::from_secs(3), async {
        tokio::join!(client, server)
    })
    .await
    .expect("selection fixture must terminate");
    assert!(
        timeout(Duration::from_millis(20), listener.accept())
            .await
            .is_err(),
        "no automatic retry or compensating request after a lost result"
    );
    result
}

#[tokio::test]
async fn lost_invalid_and_oversized_replies_fence_both_queued_and_immediate_selection() {
    let _guard = rch_common::test_guard!();
    let mut oversized = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
    oversized.extend(vec![b'x'; MAX_DAEMON_BODY_BYTES + 1]);
    for reply in [
        Vec::new(),
        b"HTTP/1.1 200 OK\r\n".to_vec(),
        b"HTTP/1.1 503 Busy\r\n\r\n{}".to_vec(),
        b"HTTP/1.1 200 OK\r\n\r\n{".to_vec(),
        b"HTTP/1.1 200 OK\r\n\r\n{}".to_vec(),
        b"HTTP/1.1 200 OK\r\n\r\n\xff".to_vec(),
        oversized,
    ] {
        for wait in [false, true] {
            for dry_run in [false, true] {
                let error = query_fixture(&reply, wait, dry_run).await.unwrap_err();
                assert_eq!(
                    error
                        .downcast_ref::<SelectionOutcomeUnconfirmed>()
                        .is_some(),
                    !dry_run,
                    "wait={wait}, dry_run={dry_run}, reply={reply:?}: {error:#}"
                );
            }
        }
    }
}

#[tokio::test]
async fn confirmed_busy_and_cancellation_results_remain_ordinary_responses() {
    let _guard = rch_common::test_guard!();
    for reason in [
        SelectionReason::AllWorkersBusy,
        SelectionReason::NoWorkersConfigured,
        SelectionReason::SelectionError("job_cancelled_before_start".into()),
    ] {
        let reply = format!(
            "HTTP/1.1 200 OK\r\n\r\n{}",
            serde_json::to_string(&SelectionResponse {
                worker: None,
                reason: reason.clone(),
                build_id: None,
                diagnostics: None,
            })
            .unwrap()
        );
        for wait in [false, true] {
            let response = query_fixture(reply.as_bytes(), wait, false).await.unwrap();
            assert_eq!(response.reason, reason);
            assert!(response.worker.is_none() && response.build_id.is_none());
        }
    }
}

#[tokio::test]
async fn failures_before_connect_do_not_invent_unconfirmed_ownership() {
    let _guard = rch_common::test_guard!();
    let root = tempfile::tempdir().unwrap();
    let missing = root.path().join("missing.sock");
    let refused = root.path().join("refused.sock");
    // Dropping the listener leaves a socket path with nobody accepting it.
    drop(std::os::unix::net::UnixListener::bind(&refused).unwrap());
    for path in [&missing, &refused] {
        for wait in [false, true] {
            let error = query_daemon(
                path.to_str().unwrap(),
                "owner",
                1,
                0,
                "cargo build",
                None,
                RequiredRuntime::None,
                CommandPriority::Normal,
                0,
                None,
                Some("selection-test-owner"),
                wait,
                &[],
                false,
                &[],
            )
            .await
            .unwrap_err();
            assert!(
                error
                    .downcast_ref::<SelectionOutcomeUnconfirmed>()
                    .is_none()
            );
        }
    }
}

/// Models a transport accepting the complete request, then failing its flush.
/// Error means delivery is unconfirmed, not that the bytes were not delivered.
#[derive(Default)]
struct FailedFlush {
    received: Vec<u8>,
}

impl AsyncWrite for FailedFlush {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.received.extend_from_slice(bytes);
        Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Err(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "flush failed",
        )))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn fully_written_request_followed_by_failed_flush_remains_uncertain() {
    for dry_run in [false, true] {
        let mut writer = FailedFlush::default();
        let error = exchange_selection_request(
            tokio::io::empty(),
            &mut writer,
            REQUEST,
            Duration::from_secs(1),
            Duration::from_secs(1),
            dry_run,
        )
        .await
        .unwrap_err()
        .context("outer caller context");
        assert_eq!(writer.received, REQUEST);
        assert_eq!(
            error
                .downcast_ref::<SelectionOutcomeUnconfirmed>()
                .is_some(),
            !dry_run
        );
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::BrokenPipe
        );
    }
}

#[tokio::test]
async fn stalled_dispatch_and_silent_reply_keep_the_uncertainty_boundary() {
    let (mut writer, mut peer) = tokio::io::duplex(8);
    let error = exchange_selection_request(
        tokio::io::empty(),
        &mut writer,
        REQUEST,
        Duration::from_millis(20),
        Duration::from_secs(1),
        false,
    )
    .await
    .unwrap_err();
    assert!(
        error
            .downcast_ref::<SelectionOutcomeUnconfirmed>()
            .is_some()
    );
    assert!(format!("{error:#}").contains("request write timed out"));
    drop(writer);
    let mut bytes = Vec::new();
    peer.read_to_end(&mut bytes).await.unwrap();
    assert_eq!(bytes, REQUEST[..8]);

    let (reader, _silent_peer) = tokio::io::duplex(8);
    let mut writer = Vec::new();
    let error = exchange_selection_request(
        reader,
        &mut writer,
        REQUEST,
        Duration::from_secs(1),
        Duration::from_millis(20),
        false,
    )
    .await
    .unwrap_err();
    assert!(
        error
            .downcast_ref::<SelectionOutcomeUnconfirmed>()
            .is_some()
    );
    assert!(format!("{error:#}").contains("response timed out"));
    assert_eq!(writer, REQUEST);
}

/// The first reply names a worker outside the requested allow-set. Capture
/// every follow-up request so a preview cannot silently mutate daemon state.
async fn unrequested_fixture(
    dry_run: bool,
    build_id: Option<u64>,
    acknowledgement: &[u8],
) -> (anyhow::Result<SelectionResponse>, Vec<String>) {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("assignment.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let server = async {
        let (stream, _) = listener.accept().await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut first = String::new();
        BufReader::new(reader).read_line(&mut first).await.unwrap();
        assert!(first.contains("&worker=requested-worker"));
        assert_eq!(first.contains("&dry_run=1"), dry_run);
        let reply = serde_json::json!({
            "worker": {
                "id": "unrequested-worker", "host": "localhost", "user": "test",
                "identity_file": "/no-test-key", "slots_available": 2, "speed_score": 1.0
            },
            "reason": "success",
            "build_id": build_id,
        });
        writer
            .write_all(format!("HTTP/1.1 200 OK\r\n\r\n{reply}").as_bytes())
            .await
            .unwrap();
        drop(writer);
        let mut requests = vec![first];
        if let Ok(Ok((stream, _))) = timeout(Duration::from_millis(100), listener.accept()).await {
            let (reader, mut writer) = stream.into_split();
            let mut request = String::new();
            BufReader::new(reader)
                .read_line(&mut request)
                .await
                .unwrap();
            requests.push(request);
            let _ = writer.write_all(acknowledgement).await;
        }
        assert!(
            timeout(Duration::from_millis(20), listener.accept())
                .await
                .is_err()
        );
        requests
    };
    let requested = [WorkerId::new("requested-worker")];
    let client = query_daemon_with_mode(
        path.to_str().unwrap(),
        "owner",
        2,
        0,
        "cargo build",
        None,
        RequiredRuntime::None,
        CommandPriority::Normal,
        0,
        Some(std::process::id()),
        Some("selection-test-owner"),
        false,
        &requested,
        false,
        &[],
        dry_run,
    );
    timeout(Duration::from_secs(3), async {
        tokio::join!(client, server)
    })
    .await
    .expect("assignment refusal must terminate")
}

#[tokio::test]
async fn diagnostic_worker_mismatch_never_sends_a_release() {
    let _guard = rch_common::test_guard!();
    for build_id in [None, Some(42), Some(u64::MAX)] {
        let (result, requests) = unrequested_fixture(true, build_id, b"HTTP/1.1 200 OK\r\n").await;
        let response = result.unwrap();
        assert_eq!(response.reason, SelectionReason::NoMatchingWorkers);
        assert!(response.worker.is_none() && response.build_id.is_none());
        assert_eq!(
            requests.len(),
            1,
            "a preview must remain read-only: {requests:?}"
        );
    }
}

#[tokio::test]
async fn real_worker_mismatch_requires_an_identity_bound_acknowledged_release() {
    let _guard = rch_common::test_guard!();
    let (result, requests) = unrequested_fixture(false, Some(42), b"HTTP/1.1 200 OK\r\n").await;
    let response = result.unwrap();
    assert_eq!(response.reason, SelectionReason::NoMatchingWorkers);
    assert!(response.worker.is_none() && response.build_id.is_none());
    assert_eq!(requests.len(), 2);
    assert!(
        requests[1]
            .starts_with("POST /release-worker?worker=unrequested-worker&slots=2&build_id=42")
    );
    assert!(requests[1].contains("&local_wrapper_id=selection-test-owner"));
    assert!(requests[1].contains(&format!("&exit_code={EXIT_BUILD_ERROR}")));
}

#[tokio::test]
async fn unowned_mismatched_assignment_cannot_fall_back_or_release_by_slot_count() {
    let _guard = rch_common::test_guard!();
    for build_id in [None, Some(0), Some(1_u64 << 63), Some(u64::MAX)] {
        let (result, requests) = unrequested_fixture(false, build_id, b"HTTP/1.1 200 OK\r\n").await;
        let error = result.unwrap_err();
        assert!(
            error
                .downcast_ref::<SelectionOutcomeUnconfirmed>()
                .is_some()
        );
        assert!(format!("{error:#}").contains("no valid active build identity"));
        assert_eq!(
            requests.len(),
            1,
            "never guess which reservation to release"
        );
    }
}

#[tokio::test]
async fn unacknowledged_mismatch_release_preserves_uncertainty_and_correlation() {
    let _guard = rch_common::test_guard!();
    for ack in [
        b"".as_slice(),
        b"HTTP/1.1 500 Failed\r\n",
        b"HTTP/1.1 200 OK",
    ] {
        let (result, requests) = unrequested_fixture(false, Some(42), ack).await;
        let error = result.unwrap_err();
        assert!(
            error
                .downcast_ref::<SelectionOutcomeUnconfirmed>()
                .is_some()
        );
        let message = format!("{error:#}");
        assert!(message.contains("unrequested-worker build 42"), "{message}");
        assert!(message.contains("not acknowledged"), "{message}");
        assert_eq!(
            requests.len(),
            2,
            "one attempted release, no selection replay"
        );
    }
}

const RESUMING_WRAPPER: &str = "rchw-selection-resume-test";
const RESUMED_SELECTION_REPLY: &[u8] = concat!(
    "HTTP/1.1 200 OK\r\n\r\n",
    r#"{"worker":{"id":"worker-resume","host":"localhost","user":"test","identity_file":"/no-test-key","slots_available":2,"speed_score":1.0},"reason":"success","build_id":42}"#,
).as_bytes();

/// Script the transport boundary, retaining every dispatched request. The
/// caller supplies the daemon's replies; no worker command runs in this test.
async fn resuming_query_fixture(
    first_reply: &[u8],
    resume_reply: Option<&[u8]>,
    wait: bool,
    dry_run: bool,
    wrapper: Option<&str>,
    hook_pid: Option<u32>,
) -> (anyhow::Result<SelectionResponse>, Vec<String>) {
    let root = tempfile::tempdir().unwrap().keep();
    let path = root.join("resume.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let server = async {
        let mut requests = Vec::new();
        for reply in std::iter::once(first_reply).chain(resume_reply) {
            let (stream, _) = listener.accept().await.unwrap();
            let (reader, mut writer) = stream.into_split();
            let mut request = String::new();
            BufReader::new(reader)
                .read_line(&mut request)
                .await
                .unwrap();
            requests.push(request);
            // An empty first reply models a daemon connection disappearing
            // after it consumed the original selection request.
            let _ = writer.write_all(reply).await;
        }
        requests
    };
    let toolchain = ToolchainInfo::new(
        "nightly",
        Some("2026-09-01".into()),
        "fixture toolchain identity",
    );
    let workers = [
        WorkerId::new("worker-resume"),
        WorkerId::new("worker-alternate"),
    ];
    let tools = ["tool+one&check".into(), "tool-two".into()];
    let client = query_daemon_with_mode(
        path.to_str().unwrap(),
        "queued project&variant=one",
        4,
        0,
        "cargo +nightly-2026-09-01 test --features 'a&b'",
        Some(&toolchain),
        RequiredRuntime::Rust,
        CommandPriority::High,
        731,
        hook_pid,
        wrapper,
        wait,
        &workers,
        true,
        &tools,
        dry_run,
    );
    let result = timeout(Duration::from_secs(3), async {
        tokio::join!(client, server)
    })
    .await
    .expect("selection recovery must finish without another dispatch");
    assert!(
        timeout(Duration::from_millis(20), listener.accept())
            .await
            .is_err(),
        "selection recovery must not dispatch an extra request"
    );
    result
}

#[tokio::test]
async fn transport_loss_resumes_the_exact_original_queued_selection() {
    let _guard = rch_common::test_guard!();
    let (result, requests) = resuming_query_fixture(
        b"",
        Some(RESUMED_SELECTION_REPLY),
        true,
        false,
        Some(RESUMING_WRAPPER),
        Some(std::process::id()),
    )
    .await;
    let response = result.unwrap();
    assert_eq!(response.worker.unwrap().id.as_str(), "worker-resume");
    assert_eq!(response.build_id, Some(42));
    assert_eq!(requests.len(), 2);
    let original_query = requests[0].strip_prefix("GET /select-worker?").unwrap();
    assert_eq!(
        requests[1],
        format!("GET /select-worker/resume-queued?{original_query}"),
        "only the endpoint changes; identity, constraints and timeout stay exact"
    );
    for required in [
        "project=queued%20project%26variant%3Done&cores=4",
        "&command=cargo%20%2Bnightly-2026-09-01%20test%20--features%20%27a%26b%27",
        "&toolchain=",
        "&runtime=rust",
        "&priority=high",
        "&classification_us=731",
        "&worker=worker-resume&worker=worker-alternate",
        "&job_mode=1",
        "&require_tool=tool%2Bone%26check&require_tool=tool-two",
        "&wait=1&wait_timeout_secs=",
    ] {
        assert!(original_query.contains(required), "{original_query}");
    }
    assert!(original_query.contains(&format!("&local_wrapper_id={RESUMING_WRAPPER}")));
    assert!(original_query.contains(&format!("&hook_pid={}", std::process::id())));
    assert!(!original_query.contains("dry_run"));
}

#[tokio::test]
async fn refused_or_lost_resume_reply_never_dispatches_a_third_request() {
    let _guard = rch_common::test_guard!();
    for reply in [
        b"".as_slice(),
        b"HTTP/1.1 404 Not Found\r\n\r\n{\"error\":\"Unknown endpoint\"}",
        b"HTTP/1.1 409 Conflict\r\n\r\n{\"error\":\"queued owner missing\"}",
        b"HTTP/1.1 409 Conflict\r\n\r\n{\"error\":\"owner already active\"}",
        b"HTTP/1.1 403 Forbidden\r\n\r\n{\"error\":\"request contract mismatch\"}",
        b"HTTP/1.1 200 OK\r\n\r\n{",
    ] {
        let (result, requests) = resuming_query_fixture(
            b"",
            Some(reply),
            true,
            false,
            Some(RESUMING_WRAPPER),
            Some(std::process::id()),
        )
        .await;
        let error = result.unwrap_err().context("caller recovery context");
        assert!(
            error
                .downcast_ref::<SelectionOutcomeUnconfirmed>()
                .is_some(),
            "a refused or lost resume must retain uncertain ownership: {error:#}"
        );
        assert_eq!(requests.len(), 2);
        assert!(requests[0].starts_with("GET /select-worker?"));
        assert!(requests[1].starts_with("GET /select-worker/resume-queued?"));
    }
}

#[tokio::test]
async fn invalid_complete_reply_never_resumes_even_with_a_valid_waiting_wrapper() {
    let _guard = rch_common::test_guard!();
    for reply in [
        b"HTTP/1.1 200 OK\r\n".as_slice(),
        b"HTTP/1.1 503 Unavailable\r\n\r\n{}",
        b"HTTP/1.1 200 OK\r\n\r\n{",
        b"HTTP/1.1 200 OK\r\n\r\n{}",
        b"HTTP/1.1 200 OK\r\n\r\n\xff",
    ] {
        let (result, requests) = resuming_query_fixture(
            reply,
            None,
            true,
            false,
            Some(RESUMING_WRAPPER),
            Some(std::process::id()),
        )
        .await;
        let error = result.unwrap_err();
        assert!(
            error
                .downcast_ref::<SelectionOutcomeUnconfirmed>()
                .is_some(),
            "{error:#}"
        );
        assert_eq!(requests.len(), 1);
    }
}

#[tokio::test]
async fn resumption_requires_a_real_waiting_request_with_wrapper_and_process_identity() {
    let _guard = rch_common::test_guard!();
    let pid = Some(std::process::id());
    for (wait, dry_run, wrapper, hook_pid) in [
        (false, false, Some(RESUMING_WRAPPER), pid),
        (true, true, Some(RESUMING_WRAPPER), pid),
        (true, false, None, pid),
        (true, false, Some("selection-test-owner"), pid),
        (true, false, Some(RESUMING_WRAPPER), None),
        (true, false, Some(RESUMING_WRAPPER), Some(0)),
        (true, false, Some(RESUMING_WRAPPER), Some(1)),
    ] {
        let (result, requests) =
            resuming_query_fixture(b"", None, wait, dry_run, wrapper, hook_pid).await;
        let error = result.unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<SelectionOutcomeUnconfirmed>()
                .is_some(),
            !dry_run,
            "wait={wait}, dry_run={dry_run}, wrapper={wrapper:?}, pid={hook_pid:?}: {error:#}"
        );
        assert_eq!(requests.len(), 1);
    }
}

#[tokio::test]
async fn resume_connects_when_the_daemon_socket_reappears() {
    let root = tempfile::tempdir().unwrap().keep();
    let path = root.join("reappearing.sock");
    let query = "project=queued&cores=1&wait=1&local_wrapper_id=rchw-delayed&hook_pid=42";
    let server = async {
        tokio::time::sleep(Duration::from_millis(60)).await;
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut request = String::new();
        BufReader::new(reader)
            .read_line(&mut request)
            .await
            .unwrap();
        writer.write_all(RESUMED_SELECTION_REPLY).await.unwrap();
        (listener, request)
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let client = resume_queued_selection(path.to_str().unwrap(), query, deadline, 0);
    let (result, (listener, request)) = timeout(Duration::from_secs(3), async {
        tokio::join!(client, server)
    })
    .await
    .expect("a replacement listener must be discoverable within the same deadline");
    assert_eq!(result.unwrap().build_id, Some(42));
    assert_eq!(
        request,
        format!("GET /select-worker/resume-queued?{query}\n")
    );
    assert!(
        timeout(Duration::from_millis(20), listener.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn unavailable_resume_socket_exhausts_only_the_original_deadline() {
    let root = tempfile::tempdir().unwrap().keep();
    let missing = root.join("missing.sock");
    let refused = root.join("refused.sock");
    drop(std::os::unix::net::UnixListener::bind(&refused).unwrap());
    for path in [&missing, &refused] {
        let started = tokio::time::Instant::now();
        let budget = Duration::from_millis(160);
        let error = timeout(
            Duration::from_secs(2),
            resume_queued_selection(
                path.to_str().unwrap(),
                "project=queued",
                started + budget,
                0,
            ),
        )
        .await
        .expect("absent and refused sockets must not create a fresh response budget")
        .unwrap_err();
        assert!(
            error
                .downcast_ref::<SelectionOutcomeUnconfirmed>()
                .is_some(),
            "connect failure after original dispatch stays uncertain: {error:#}"
        );
        assert!(
            started.elapsed() >= budget,
            "allow the daemon to reappear until the deadline"
        );
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}

#[tokio::test]
async fn resumed_reply_wait_uses_time_left_after_reconnecting() {
    let root = tempfile::tempdir().unwrap().keep();
    let path = root.join("late-silent.sock");
    let (finished_tx, finished_rx) = tokio::sync::oneshot::channel();
    let server = async {
        tokio::time::sleep(Duration::from_millis(400)).await;
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        let (reader, writer) = stream.into_split();
        let mut request = String::new();
        BufReader::new(reader)
            .read_line(&mut request)
            .await
            .unwrap();
        // Keep the response open and silent until the client's deadline fires.
        finished_rx.await.unwrap();
        drop(writer);
        (listener, request)
    };
    let started = tokio::time::Instant::now();
    let deadline = started + Duration::from_millis(600);
    let client = async {
        let result =
            resume_queued_selection(path.to_str().unwrap(), "project=queued", deadline, 0).await;
        finished_tx.send(()).unwrap();
        result
    };
    let (result, (listener, request)) = timeout(Duration::from_secs(2), async {
        tokio::join!(client, server)
    })
    .await
    .expect("the original deadline includes reconnecting and reading the reply");
    let elapsed = started.elapsed();
    let error = result.unwrap_err();
    assert!(
        error
            .downcast_ref::<SelectionOutcomeUnconfirmed>()
            .is_some(),
        "{error:#}"
    );
    assert_eq!(request, "GET /select-worker/resume-queued?project=queued\n");
    assert!(elapsed >= Duration::from_millis(550), "elapsed={elapsed:?}");
    assert!(
        elapsed < Duration::from_millis(850),
        "reply wait reset the budget: elapsed={elapsed:?}"
    );
    assert!(
        timeout(Duration::from_millis(20), listener.accept())
            .await
            .is_err(),
        "a lost resumed reply must not trigger another request"
    );
}

#[tokio::test]
async fn expired_resume_deadline_does_not_dispatch() {
    let root = tempfile::tempdir().unwrap().keep();
    let path = root.join("expired.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let error = resume_queued_selection(
        path.to_str().unwrap(),
        "project=queued",
        tokio::time::Instant::now() - Duration::from_millis(1),
        0,
    )
    .await
    .unwrap_err();
    assert!(
        error
            .downcast_ref::<SelectionOutcomeUnconfirmed>()
            .is_some(),
        "{error:#}"
    );
    assert!(
        timeout(Duration::from_millis(20), listener.accept())
            .await
            .is_err(),
        "no connect or request is authorized after the original deadline"
    );
}
