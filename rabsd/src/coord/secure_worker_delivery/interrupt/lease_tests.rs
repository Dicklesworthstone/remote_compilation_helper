// Native runtime tests of the actual coordinator lease timer and stream owner.
// The controlled wire is a transport fixture, not a live worker or compiler.

use super::*;
use rabs_protocol::lease_semantics::REQUEST_EXECUTION_LEASE_VERSION;
use sha2::{Digest, Sha256};

fn selection(request: &Value) -> Value {
    json!({"kind":"session-ok", "execution_lease":{
        "version":REQUEST_EXECUTION_LEASE_VERSION, "session_id":11, "lease_id":12,
        "request_id":request["request_id"],
        "request_sha256":crate::coord::secure_worker_delivery::hex(
            &Sha256::digest(serde_json::to_vec(request).unwrap())),
        "boot_generation":1, "incarnation":format!("{:032x}", 2), "ttl_ms":1000,
    }})
}

fn renewal_ack(renewal: &Value) -> Value {
    let mut response = renewal.clone();
    response["kind"] = json!("execution-lease-renewed");
    response["accepted"] = json!(true);
    response
}

struct RenewingWire {
    wire: Wire,
    finish_at_sequence: u64,
}

impl AsyncRead for RenewingWire {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.wire).poll_read(cx, output)
    }
}

impl AsyncWrite for RenewingWire {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let frame: Value = serde_json::from_slice(bytes).unwrap();
        if frame["kind"] == "execution-lease-renew" {
            let sequence = frame["renewal_seq"].as_u64().unwrap();
            let mut replies = format!("{}\n", renewal_ack(&frame));
            if sequence == self.finish_at_sequence {
                replies.push_str(&format!("{}\n", result()));
            }
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
fn quiet_connection_gets_native_timer_renewals_without_incoming_heartbeats() {
    let runtime = runtime();
    let trigger = Trigger::default();
    let mut wire = Wire::new(&trigger, &[]);
    wire.steps = VecDeque::from([Step::Pending]);
    let stream = RenewingWire {
        wire,
        finish_at_sequence: 4,
    };
    let mut peer =
        OperatorPeer::with_interrupts(RecordPeer::new(&runtime, stream, &request()), trigger);
    let original = request();
    peer.send(&selection(&original)).unwrap();
    assert!(peer.lease.as_ref().unwrap().wake_at().is_none());
    peer.send(&original).unwrap();
    // Four actual timer wakes cross the original one-second TTL. The fixture
    // sends no bytes until the coordinator writes the respective renewal.
    peer.inner.until = Instant::now() + Duration::from_secs(5);
    assert_eq!(peer.receive().unwrap(), result());
    assert!(peer.inner.phase == Phase::Transfer);
    assert!(peer.lease.as_ref().unwrap().stopped());
    assert!(peer.lease.as_ref().unwrap().wake_at().is_none());
    let sent = peer.inner.stream.wire.sent();
    assert_eq!(
        sent[1], original,
        "lease negotiation cannot change request identity"
    );
    let sequences: Vec<_> = sent
        .iter()
        .filter(|frame| frame["kind"] == "execution-lease-renew")
        .map(|frame| frame["renewal_seq"].as_u64().unwrap())
        .collect();
    assert_eq!(sequences, [1, 2, 3, 4]);
}

struct StalledRenewal {
    wire: Wire,
    token: crate::coord::secure_worker_delivery::OperationCancellation,
    partial: bool,
}

impl AsyncRead for StalledRenewal {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.wire).poll_read(cx, output)
    }
}

impl AsyncWrite for StalledRenewal {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.partial {
            self.token.cancel();
            return Poll::Pending;
        }
        let frame: Value = serde_json::from_slice(bytes).unwrap();
        if frame["kind"] == "execution-lease-renew" {
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
fn cancellation_during_partial_renewal_poisons_without_appending_cancel_or_retry() {
    let runtime = runtime();
    let trigger = Trigger::default();
    let token = crate::coord::secure_worker_delivery::OperationCancellation::default();
    let mut wire = Wire::new(&trigger, &[]);
    wire.steps = VecDeque::from([Step::Pending]);
    let stream = StalledRenewal {
        wire,
        token: token.clone(),
        partial: false,
    };
    let mut peer = OperatorPeer::with_interrupts(
        RecordPeer::new(&runtime, stream, &request()),
        OperationInterrupts::new(token),
    );
    peer.send(&selection(&request())).unwrap();
    peer.send(&request()).unwrap();
    let complete_before = peer.inner.stream.wire.sent.clone();
    peer.inner.until = Instant::now() + Duration::from_secs(3);
    assert_eq!(
        peer.receive().unwrap_err().kind(),
        io::ErrorKind::ConnectionAborted
    );
    assert!(peer.inner.failed);
    assert!(
        !peer.cancel_sent,
        "cancel cannot be inserted into partial renewal JSON"
    );
    let sent = peer.inner.stream.wire.sent.clone();
    assert_eq!(sent.len(), complete_before.len() + 3);
    assert!(sent.starts_with(&complete_before));
    assert!(peer.receive().is_err());
    assert!(peer.send(&request()).is_err());
    assert_eq!(
        peer.inner.stream.wire.sent, sent,
        "uncertain writes are never retried"
    );
}

#[test]
fn result_before_pending_renewal_ack_stops_renewal_without_resetting_transfer_budget() {
    let runtime = runtime();
    let trigger = Trigger::default();
    let mut peer = peer(&runtime, &trigger, &[]);
    peer.send(&selection(&request())).unwrap();
    peer.send(&request()).unwrap();
    let sent_at = Instant::now() - Duration::from_millis(400);
    peer.lease.as_mut().unwrap().arm(sent_at);
    peer.lease_tick().unwrap();
    let renewal = peer.inner.stream.sent().last().unwrap().clone();
    assert_eq!(renewal["kind"], "execution-lease-renew");
    let ack = renewal_ack(&renewal);
    let chunk = json!({"kind":"output-chunk", "request_id":7});
    peer.inner.stream.steps = VecDeque::from([Step::Bytes(
        format!("{}\n{ack}\n{chunk}\n{ack}\n", result())
            .into_bytes()
            .into(),
    )]);
    assert_eq!(peer.receive().unwrap(), result());
    assert!(peer.lease.as_ref().unwrap().stopped());
    let deadline = peer.inner.until;
    peer.send(&json!({"kind":"output-read", "request_id":7}))
        .unwrap();
    assert_eq!(peer.receive().unwrap(), chunk);
    assert_eq!(
        peer.inner.until, deadline,
        "late ACK cannot renew transfer time"
    );
    assert!(peer.lease.as_ref().unwrap().wake_at().is_none());
    assert!(
        peer.receive().is_err(),
        "one pending ACK cannot authorize two replies"
    );
    assert!(peer.inner.failed);
}

#[test]
fn source_and_result_recovery_have_no_running_lease_or_renewal_authority() {
    let runtime = runtime();
    for mode in ["source", "resume"] {
        let trigger = Trigger::default();
        let mut peer = peer(&runtime, &trigger, &[]);
        if mode == "source" {
            peer.send(&selection(&request())).unwrap();
            peer.send(&json!({"kind":"source-begin", "request_id":7}))
                .unwrap();
        } else {
            peer.send(&json!({"kind":"session-ok"})).unwrap();
            peer.send(&json!({"kind":"result-resume", "request_id":7}))
                .unwrap();
        }
        assert!(peer.execution.is_none());
        assert!(
            peer.lease
                .as_ref()
                .and_then(ExecutionLease::wake_at)
                .is_none()
        );
        let before = peer.inner.stream.sent();
        peer.lease_tick().unwrap();
        assert_eq!(peer.inner.stream.sent(), before);
        assert!(
            !before
                .iter()
                .any(|frame| frame["kind"] == "execution-lease-renew")
        );
    }
}
