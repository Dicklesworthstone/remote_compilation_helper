// These use the native coordinator runtime and its real stream owner with a
// controlled transport. They do not claim a live worker or compiler execution.

use super::*;
use crate::coord::prepared_operation::PreviewObserver;

fn observer() -> PreviewObserver {
    PreviewObserver::new("0123456789abcdef0123456789abcdef", &"ab".repeat(32), 1)
}

fn selection(ttl_ms: u64) -> Value {
    let hello = json!({"execution_leases":["request-renewal-v1"],
        "boot_generation":1, "incarnation":format!("{:032x}", 2)});
    let mut grant =
        crate::coord::secure_worker_delivery::lease::grant(&hello, &request(), 11, 12).unwrap();
    grant["ttl_ms"] = json!(ttl_ms);
    json!({"kind":"session-ok", "execution_lease":grant, "output_preview":"tail-v1"})
}

fn renewal_ack(renewal: &Value) -> Value {
    let mut reply = renewal.clone();
    reply["kind"] = json!("execution-lease-renewed");
    reply["accepted"] = json!(true);
    reply
}

fn preview_reply(second: bool) -> Value {
    let segments = if second {
        json!([{"stream":"stdout", "offset":2, "data_hex":"0a", "skipped_bytes":0, "observed_bytes":3}])
    } else {
        json!([
            {"stream":"stdout", "offset":0, "data_hex":"00ff", "skipped_bytes":0, "observed_bytes":2},
            {"stream":"stderr", "offset":4, "data_hex":"fe", "skipped_bytes":4, "observed_bytes":5},
        ])
    };
    json!({"kind":"output-preview", "version":"tail-v1", "request_id":7,
        "active":true, "segments":segments, "complete":false, "publication_authorized":false})
}

fn heartbeat() -> Value {
    json!({"kind":"heartbeat", "request_id":7})
}

struct PreviewingWire {
    wire: Wire,
    queries: usize,
}

impl AsyncRead for PreviewingWire {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.wire).poll_read(cx, output)
    }
}

impl AsyncWrite for PreviewingWire {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let frame: Value = serde_json::from_slice(bytes).unwrap();
        let replies = match frame["kind"].as_str() {
            Some("output-preview") => {
                assert!(
                    self.queries < 2,
                    "more than one query per completed preview interval"
                );
                let reply = preview_reply(self.queries != 0);
                self.queries += 1;
                Some(format!("{reply}\n{}\n", heartbeat()))
            }
            Some("execution-lease-renew") => {
                let mut replies = format!("{}\n", renewal_ack(&frame));
                if frame["renewal_seq"] == 2 {
                    replies.push_str(&format!("{}\n", result()));
                }
                Some(replies)
            }
            _ => None,
        };
        if let Some(replies) = replies {
            self.wire.steps =
                VecDeque::from([Step::Bytes(replies.into_bytes().into()), Step::Pending]);
        }
        Pin::new(&mut self.wire).poll_write(cx, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.wire).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.wire).poll_shutdown(cx)
    }
}

#[test]
fn negotiated_previews_and_renewals_share_the_native_stream_without_changing_execution() {
    let runtime = runtime();
    let trigger = Trigger::default();
    let observer = observer();
    let mut wire = Wire::new(&trigger, &[]);
    wire.steps = VecDeque::from([Step::Pending]);
    let mut peer = OperatorPeer::with_interrupts(
        RecordPeer::new(&runtime, PreviewingWire { wire, queries: 0 }, &request()),
        trigger,
    )
    .with_preview_observer(Some(observer.clone()));
    let original = request();
    peer.send(&selection(1000)).unwrap();
    assert!(peer.preview.as_ref().unwrap().wake_at().is_none());
    peer.send(&original).unwrap();
    peer.inner.until = Instant::now() + Duration::from_secs(5);
    assert_eq!(peer.receive().unwrap(), heartbeat());
    let first = observer.snapshot(0, 0).unwrap();
    assert_eq!(first["available"], true);
    assert_eq!(first["segments"][0]["data_hex"], "00ff");
    assert_eq!(first["segments"][1]["skipped_bytes"], 4);
    assert_eq!(peer.receive().unwrap(), heartbeat());
    assert_eq!(peer.receive().unwrap(), result());
    assert!(peer.inner.phase == Phase::Transfer);
    assert!(peer.lease.as_ref().unwrap().stopped());
    assert!(peer.preview.as_ref().unwrap().wake_at().is_none());
    let snapshot = observer.snapshot(0, 0).unwrap();
    assert_eq!(snapshot["segments"][0]["data_hex"], "00ff0a");
    assert_eq!(snapshot["segments"][0]["next_offset"], 3);
    assert_eq!(snapshot["segments"][1]["data_hex"], "fe");
    assert_eq!(snapshot["complete"], false);
    assert_eq!(snapshot["publication_authorized"], false);
    let sent = peer.inner.stream.wire.sent();
    assert_eq!(sent[1], original);
    assert_eq!(
        sent.iter()
            .filter(|frame| frame["kind"] == "canonical-exec")
            .count(),
        1
    );
    assert_eq!(
        sent.iter()
            .filter(|frame| frame["kind"] == "output-preview")
            .count(),
        2
    );
    assert_eq!(
        sent.iter()
            .filter(|frame| frame["kind"] == "execution-lease-renew")
            .map(|frame| frame["renewal_seq"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        [1, 2]
    );
}

#[test]
fn pending_lease_ack_defers_due_preview_in_both_tick_and_receive_paths() {
    let runtime = runtime();
    let trigger = Trigger::default();
    let observer = observer();
    let mut peer = peer(&runtime, &trigger, &[]).with_preview_observer(Some(observer.clone()));
    peer.send(&selection(3000)).unwrap();
    peer.send(&request()).unwrap();
    peer.lease
        .as_mut()
        .unwrap()
        .arm(Instant::now() - Duration::from_millis(1100));
    peer.lease_tick().unwrap();
    assert!(peer.lease.as_ref().unwrap().renewal_pending());
    assert!(peer.preview.as_ref().unwrap().wake_at().unwrap() <= Instant::now());
    let sent = peer.inner.stream.sent();
    let ack = renewal_ack(sent.last().unwrap());
    peer.preview_tick().unwrap();
    assert_eq!(
        peer.inner.stream.sent(),
        sent,
        "direct optional tick must defer"
    );
    peer.inner.stream.steps = VecDeque::from([Step::Bytes(
        format!("{}\n", heartbeat()).into_bytes().into(),
    )]);
    peer.inner.until = Instant::now() + Duration::from_secs(1);
    assert_eq!(
        peer.receive().unwrap(),
        heartbeat(),
        "a suppressed preview timer cannot busy-loop over readable control data"
    );
    assert_eq!(peer.inner.stream.sent(), sent);
    assert_eq!(observer.snapshot(0, 0).unwrap()["available"], false);
    peer.inner.stream.steps = VecDeque::from([Step::Bytes(
        format!("{ack}\n{}\n{}\n", preview_reply(false), heartbeat())
            .into_bytes()
            .into(),
    )]);
    assert_eq!(peer.receive().unwrap(), heartbeat());
    assert!(!peer.lease.as_ref().unwrap().renewal_pending());
    assert_eq!(
        peer.inner.stream.sent().last().unwrap(),
        &json!({"kind":"output-preview", "request_id":7})
    );
    assert_eq!(observer.snapshot(0, 0).unwrap()["available"], true);
}

#[test]
fn terminal_result_drains_one_late_preview_without_cache_exposure_or_deadline_extension() {
    let runtime = runtime();
    let trigger = Trigger::default();
    let observer = observer();
    let before = observer.snapshot(0, 0).unwrap();
    let mut peer = peer(&runtime, &trigger, &[]).with_preview_observer(Some(observer.clone()));
    peer.send(&selection(30000)).unwrap();
    peer.send(&request()).unwrap();
    peer.preview_tick().unwrap();
    let first_query = peer.inner.stream.sent().last().unwrap().clone();
    assert_eq!(
        first_query,
        json!({"kind":"output-preview", "request_id":7})
    );
    peer.preview_tick().unwrap();
    assert_eq!(
        peer.inner
            .stream
            .sent()
            .iter()
            .filter(|frame| frame["kind"] == "output-preview")
            .count(),
        1
    );
    peer.lease
        .as_mut()
        .unwrap()
        .arm(Instant::now() - Duration::from_secs(11));
    peer.lease_tick().unwrap();
    let ack = renewal_ack(peer.inner.stream.sent().last().unwrap());
    let late = preview_reply(false);
    let chunk = json!({"kind":"output-chunk", "request_id":7});
    peer.inner.stream.steps = VecDeque::from([Step::Bytes(
        format!("{}\n{late}\n{ack}\n{chunk}\n{late}\n", result())
            .into_bytes()
            .into(),
    )]);
    assert_eq!(peer.receive().unwrap(), result());
    let deadline = peer.inner.until;
    assert!(peer.lease.as_ref().unwrap().stopped());
    assert!(peer.preview.as_ref().unwrap().wake_at().is_none());
    peer.send(&json!({"kind":"output-read", "request_id":7}))
        .unwrap();
    assert_eq!(peer.receive().unwrap(), chunk);
    assert_eq!(
        peer.inner.until, deadline,
        "late observational replies never reset transfer time"
    );
    assert_eq!(
        observer.snapshot(0, 0).unwrap(),
        before,
        "terminal preview cannot publish bytes to the job cache"
    );
    assert!(peer.lease.as_ref().unwrap().wake_at().is_none());
    assert!(peer.preview.as_ref().unwrap().wake_at().is_none());
    let sent = peer.inner.stream.sent();
    assert_eq!(
        sent.iter()
            .filter(|frame| frame["kind"] == "output-preview")
            .count(),
        1
    );
    assert_eq!(
        sent.iter()
            .filter(|frame| frame["kind"] == "execution-lease-renew")
            .count(),
        1
    );
    assert!(
        peer.receive().is_err(),
        "one pending preview cannot authorize duplicate replies"
    );
    assert!(peer.inner.failed);
    assert_eq!(peer.inner.stream.sent(), sent);
}

struct StalledPreview {
    wire: Wire,
    cancellation: crate::coord::secure_worker_delivery::OperationCancellation,
    partial: bool,
}

impl AsyncRead for StalledPreview {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.wire).poll_read(cx, output)
    }
}

impl AsyncWrite for StalledPreview {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.partial {
            self.cancellation.cancel();
            return Poll::Pending;
        }
        let frame: Value = serde_json::from_slice(bytes).unwrap();
        if frame["kind"] == "output-preview" {
            self.wire.sent.extend_from_slice(&bytes[..3]);
            self.partial = true;
            return Poll::Ready(Ok(3));
        }
        Pin::new(&mut self.wire).poll_write(cx, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.wire).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.wire).poll_shutdown(cx)
    }
}

#[test]
fn cancelled_partial_preview_write_poisons_without_appending_cancel_renewal_or_retry() {
    let runtime = runtime();
    let trigger = Trigger::default();
    let observer = observer();
    let cancellation = crate::coord::secure_worker_delivery::OperationCancellation::default();
    let mut wire = Wire::new(&trigger, &[]);
    wire.steps = VecDeque::from([Step::Pending]);
    let stream = StalledPreview {
        wire,
        cancellation: cancellation.clone(),
        partial: false,
    };
    let mut peer = OperatorPeer::with_interrupts(
        RecordPeer::new(&runtime, stream, &request()),
        OperationInterrupts::new(cancellation),
    )
    .with_preview_observer(Some(observer.clone()));
    peer.send(&selection(1000)).unwrap();
    peer.send(&request()).unwrap();
    let mut expected = peer.inner.stream.wire.sent.clone();
    let query = serde_json::to_vec(&json!({"kind":"output-preview", "request_id":7})).unwrap();
    expected.extend_from_slice(&query[..3]);
    assert_eq!(
        peer.receive().unwrap_err().kind(),
        io::ErrorKind::ConnectionAborted
    );
    assert!(peer.inner.failed);
    assert!(peer.inner.phase == Phase::Execution);
    assert!(
        !peer.cancel_sent,
        "cancel cannot be appended inside a partial preview frame"
    );
    assert_eq!(peer.inner.stream.wire.sent, expected);
    assert_eq!(observer.snapshot(0, 0).unwrap()["available"], false);
    assert!(peer.receive().is_err());
    assert!(peer.send(&request()).is_err());
    assert_eq!(
        peer.inner.stream.wire.sent, expected,
        "poisoned stream must never retry a control or dispatch"
    );
}
