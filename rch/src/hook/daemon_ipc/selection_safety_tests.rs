//! Exercise the production dispatch boundary without changing process-wide env.
//! Socket peers script replies; they do not simulate actual worker execution.

use super::*;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::AsyncWrite;

const REQUEST: &[u8] = b"GET /select-worker?project=owner&cores=1\n";

async fn query_fixture(reply: &[u8], wait: bool, dry_run: bool) -> anyhow::Result<SelectionResponse> {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("selection.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let server = async {
        let (stream, _) = listener.accept().await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut request = String::new();
        BufReader::new(reader).read_line(&mut request).await.unwrap();
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
    let (result, ()) = timeout(Duration::from_secs(3), async { tokio::join!(client, server) })
        .await
        .expect("selection fixture must terminate");
    assert!(
        timeout(Duration::from_millis(20), listener.accept()).await.is_err(),
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
                    error.downcast_ref::<SelectionOutcomeUnconfirmed>().is_some(),
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
            }).unwrap()
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
                path.to_str().unwrap(), "owner", 1, "cargo build", None,
                RequiredRuntime::None, CommandPriority::Normal, 0, None,
                Some("selection-test-owner"), wait, &[], false, &[],
            ).await.unwrap_err();
            assert!(error.downcast_ref::<SelectionOutcomeUnconfirmed>().is_none());
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
    fn poll_write(mut self: Pin<&mut Self>, _: &mut Context<'_>, bytes: &[u8])
        -> Poll<std::io::Result<usize>>
    {
        self.received.extend_from_slice(bytes);
        Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "flush failed")))
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
            tokio::io::empty(), &mut writer, REQUEST,
            Duration::from_secs(1), Duration::from_secs(1), dry_run,
        ).await.unwrap_err().context("outer caller context");
        assert_eq!(writer.received, REQUEST);
        assert_eq!(error.downcast_ref::<SelectionOutcomeUnconfirmed>().is_some(), !dry_run);
        assert_eq!(error.downcast_ref::<std::io::Error>().unwrap().kind(), std::io::ErrorKind::BrokenPipe);
    }
}

#[tokio::test]
async fn stalled_dispatch_and_silent_reply_keep_the_uncertainty_boundary() {
    let (mut writer, mut peer) = tokio::io::duplex(8);
    let error = exchange_selection_request(
        tokio::io::empty(), &mut writer, REQUEST,
        Duration::from_millis(20), Duration::from_secs(1), false,
    ).await.unwrap_err();
    assert!(error.downcast_ref::<SelectionOutcomeUnconfirmed>().is_some());
    assert!(format!("{error:#}").contains("request write timed out"));
    drop(writer);
    let mut bytes = Vec::new();
    peer.read_to_end(&mut bytes).await.unwrap();
    assert_eq!(bytes, REQUEST[..8]);

    let (reader, _silent_peer) = tokio::io::duplex(8);
    let mut writer = Vec::new();
    let error = exchange_selection_request(
        reader, &mut writer, REQUEST,
        Duration::from_secs(1), Duration::from_millis(20), false,
    ).await.unwrap_err();
    assert!(error.downcast_ref::<SelectionOutcomeUnconfirmed>().is_some());
    assert!(format!("{error:#}").contains("response timed out"));
    assert_eq!(writer, REQUEST);
}
