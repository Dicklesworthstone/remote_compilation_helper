//! Operator interruption on an already authenticated, request-scoped connection.
//!
//! Generated control messages renew or cancel the exact canonical-exec
//! that this connection actually sent. Recovery never acquires cancellation or
//! execution authority. A cancel acknowledgment is NOT completion: diagnostics,
//! artifacts, journal retention and release ACKs still use the ordinary receiver.
//! The native ATP stream and read_record retain partial input on the connection,
//! so dropping an interrupted read future neither loses bytes nor resets timers.

use super::{Phase, RecordPeer, TRANSFER_BUDGET, WorkerPeer, read_record, require};
use super::lease::{ExecutionLease, Tick};
use asupersync::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use asupersync::signal::{Signal, sigint, sigterm};
use serde_json::{Value, json};
use std::future::{Future, poll_fn};
use std::io;
use std::pin::pin;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

const CANCEL_DRAIN_BUDGET: Duration = Duration::from_secs(60);

pub(super) trait Interrupts {
    fn wait(&mut self) -> impl Future<Output = io::Result<()>>;

    fn finish_verified_delivery(&self) -> bool {
        false
    }
}

/// Cancellation belongs to one daemon operation. The sticky intent is consumed
/// once here; duplicate HTTP/socket requests cannot abort its cleanup drain.
pub(super) struct OperationInterrupts {
    cancellation: super::OperationCancellation,
    delivered: bool,
}

impl OperationInterrupts {
    pub(super) fn new(cancellation: super::OperationCancellation) -> Self {
        Self { cancellation, delivered: false }
    }
}

impl Interrupts for OperationInterrupts {
    async fn wait(&mut self) -> io::Result<()> {
        if self.delivered {
            std::future::pending::<()>().await;
        }
        self.cancellation.cancelled().await;
        self.delivered = true;
        Ok(())
    }

    fn finish_verified_delivery(&self) -> bool {
        true
    }
}

pub(super) struct ProcessSignals {
    interrupt: Signal,
    terminate: Signal,
}

impl ProcessSignals {
    fn new() -> io::Result<Self> {
        Ok(Self { interrupt: sigint()?, terminate: sigterm()? })
    }
}

impl Interrupts for ProcessSignals {
    async fn wait(&mut self) -> io::Result<()> {
        let mut interrupt = pin!(self.interrupt.recv());
        let mut terminate = pin!(self.terminate.recv());
        poll_fn(|cx| {
            let received = match interrupt.as_mut().poll(cx) {
                Poll::Ready(value) => Poll::Ready(value),
                Poll::Pending => terminate.as_mut().poll(cx),
            };
            received.map(|value| value.ok_or_else(|| {
                io::Error::new(io::ErrorKind::BrokenPipe, "operator signal listener closed")
            }))
        }).await
    }
}

enum Event {
    Record(Value),
    Interrupt,
    Lease,
}

async fn next_event<S: AsyncRead + Unpin, I: Interrupts>(
    stream: &mut S,
    buffered: &mut Vec<u8>,
    interrupts: &mut I,
    lease_wake: Option<Instant>,
) -> io::Result<Event> {
    let mut record = pin!(read_record(stream, buffered));
    let mut signal = pin!(interrupts.wait());
    let mut lease = pin!(async {
        if let Some(at) = lease_wake {
            asupersync::time::sleep(asupersync::time::wall_now(),
                at.saturating_duration_since(Instant::now())).await;
        } else {
            std::future::pending::<()>().await;
        }
    });
    poll_fn(|cx| {
        // A continuously readable peer cannot starve an operator's stop. Both
        // futures keep their owners outside the select; the signal stream's
        // receive is cancel-safe and decoded partial records remain buffered.
        if let Poll::Ready(result) = signal.as_mut().poll(cx) {
            return Poll::Ready(result.map(|()| Event::Interrupt));
        }
        // Ready heartbeats cannot starve renewal or local lease expiry. The
        // read future retains all partial bytes in the connection's buffer.
        if lease.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Ok(Event::Lease));
        }
        record.as_mut().poll(cx).map(|result| result.map(Event::Record))
    }).await
}

/// Private below AdmittedPeer: wire callers cannot manufacture an interruption
/// or use this to send arbitrary cancel frames. Signals are installed only for
/// the production operator entry points, not for library/test RecordPeers.
pub(super) struct OperatorPeer<'a, S, I = ProcessSignals> {
    inner: RecordPeer<'a, S>,
    interrupts: I,
    execution: Option<u64>,
    cancel_sent: bool,
    cancel_response_seen: bool,
    lease: Option<ExecutionLease>,
}

impl<'a, S> OperatorPeer<'a, S> {
    pub(super) fn new(inner: RecordPeer<'a, S>) -> io::Result<Self> {
        Ok(Self::with_interrupts(inner, ProcessSignals::new()?))
    }
}

impl<'a, S, I: Interrupts> OperatorPeer<'a, S, I> {
    pub(super) fn with_interrupts(inner: RecordPeer<'a, S>, interrupts: I) -> Self {
        Self { inner, interrupts, execution:None, cancel_sent:false, cancel_response_seen:false, lease:None }
    }

    fn pending_interrupt(&mut self) -> io::Result<bool> {
        // Nonblocking pre-write check. A pending notification is consumed only
        // when it is observed; a Pending future can safely be dropped here.
        let mut signal = pin!(self.interrupts.wait());
        match signal.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(result) => result.map(|()| true),
            Poll::Pending => Ok(false),
        }
    }

    fn abandon(&mut self) -> io::Error {
        self.inner.failed = true;
        io::Error::new(io::ErrorKind::ConnectionAborted,
            "operator interrupted delivery; retain the original request and reconcile, never reexecute")
    }

    fn consume_cancel_reply(&mut self, value: &Value) -> io::Result<bool> {
        let accepted = value["kind"] == "cancel-accepted";
        let already_finished = self.cancel_sent && value["kind"] == "error"
            && value["reason"] == "unknown-request";
        if !accepted && !already_finished { return Ok(false); }
        require(self.cancel_sent && !self.cancel_response_seen
            && value["request_id"].as_u64() == self.execution,
            "unsolicited, duplicate or foreign cancellation response")?;
        if accepted {
            require(value["accepted"].as_bool().is_some()
                && value["cleanup_pending"].as_bool() == Some(true)
                && value.get("stage").is_none(),
                "invalid execution cancellation acknowledgment")?;
        }
        // Completion may win the race, with its result preceding unknown-request
        // or cancel-accepted. Consume at most one such control response even when
        // it arrives during range transfer. It never stands in for exec-result.
        self.cancel_response_seen = true;
        Ok(true)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin, I: Interrupts> OperatorPeer<'_, S, I> {
    fn send_interruptibly(&mut self, frame: &Value, lease_deadline: Option<Instant>) -> io::Result<()> {
        let bytes = self.inner.outbound(frame)?;
        let mut budget = self.inner.remaining()?;
        if let Some(deadline) = lease_deadline {
            let remaining = deadline.checked_duration_since(Instant::now())
                .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "execution lease write deadline"))?;
            budget = budget.min(remaining);
        }
        let stream = &mut self.inner.stream;
        let interrupts = &mut self.interrupts;
        self.inner.runtime.block_on(async {
            asupersync::time::timeout(asupersync::time::wall_now(), budget, async {
                let mut stopped = pin!(interrupts.wait());
                let mut writing = pin!(async {
                    stream.write_all(&bytes).await?;
                    stream.flush().await
                });
                poll_fn(|cx| {
                    if let Poll::Ready(result) = stopped.as_mut().poll(cx) {
                        return Poll::Ready(result.and(Err(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            "operation cancelled during worker write; reconcile any uncertain dispatch",
                        ))));
                    }
                    writing.as_mut().poll(cx)
                }).await
            }).await.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "worker write deadline"))?
        })
    }

    fn interrupt(&mut self) -> io::Result<()> {
        self.inner.remaining()?;
        // A completed execution no longer owns a cancellable process. A daemon
        // stop racing the terminal result must still verify and retain its
        // bytes. The explicit operator's signal-based abandon behavior stays
        // unchanged.
        if self.execution.is_some() && self.inner.phase != Phase::Execution
            && self.interrupts.finish_verified_delivery()
        {
            return Ok(());
        }
        let Some(id) = self.execution.filter(|_| self.inner.phase == Phase::Execution) else {
            return Err(self.abandon());
        };
        if self.cancel_sent { return Err(self.abandon()); }
        if let Some(lease) = &mut self.lease { lease.stop(); }
        self.cancel_sent = true; // burn before any possibly partial control write
        self.inner.until = self.inner.until.min(Instant::now() + CANCEL_DRAIN_BUDGET);
        // Phase::Execution can only follow the authenticated adapter's exact
        // canonical dispatch. Result resume enters Transfer and never gets here.
        self.inner.send(&json!({"kind":"cancel", "request_id":id}))
    }

    fn lease_tick(&mut self) -> io::Result<()> {
        let Some(lease) = &mut self.lease else { return Ok(()); };
        match lease.tick(Instant::now())? {
            Tick::Idle => Ok(()),
            Tick::Expired => {
                // The worker owns process cleanup. Continue draining its typed
                // terminal result, but never grant more execution time.
                self.inner.until = self.inner.until.min(Instant::now() + CANCEL_DRAIN_BUDGET);
                Ok(())
            }
            Tick::Renew(frame) => {
                let deadline = lease.expires_at();
                // Any failed/partial renewal write poisons the connection. A
                // stop cannot append a cancel inside an incomplete JSON frame.
                self.send_interruptibly(&frame, deadline)
            }
        }
    }

    fn receive_inner(&mut self) -> io::Result<Value> {
        loop {
            let budget = self.inner.remaining()?;
            let lease_wake = self.lease.as_ref().and_then(ExecutionLease::wake_at);
            let event = self.inner.runtime.block_on(async {
                asupersync::time::timeout(asupersync::time::wall_now(), budget,
                    next_event(&mut self.inner.stream, &mut self.inner.buffered, &mut self.interrupts, lease_wake),
                ).await.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "worker read deadline"))?
            })?;
            // Decoding an immediately available frame is not permission to
            // cross a deadline or obtain a new transfer budget afterward.
            self.inner.remaining()?;
            match event {
                Event::Interrupt => self.interrupt()?,
                Event::Lease => self.lease_tick()?,
                Event::Record(value) => {
                    if self.consume_cancel_reply(&value)? { continue; }
                    if value["kind"] == "execution-lease-renewed" {
                        let lease = self.lease.as_mut().ok_or_else(|| {
                            super::invalid("execution lease acknowledgment without a negotiated lease")
                        })?;
                        lease.consume(&value, Instant::now())?;
                        if lease.stopped() && self.inner.phase == Phase::Execution {
                            self.inner.until = self.inner.until.min(Instant::now() + CANCEL_DRAIN_BUDGET);
                        }
                        continue;
                    }
                    if self.inner.phase == Phase::Execution && value["kind"] == "exec-result" {
                        require(value["request_id"].as_u64() == self.execution,
                            "execution result does not match the interrupted operation")?;
                        if let Some(lease) = &mut self.lease { lease.stop(); }
                        self.inner.phase = Phase::Transfer;
                        self.inner.until = Instant::now() + TRANSFER_BUDGET;
                    }
                    return Ok(value);
                }
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin, I: Interrupts> WorkerPeer for OperatorPeer<'_, S, I> {
    fn send(&mut self, frame: &Value) -> io::Result<()> {
        let result = (|| {
            self.inner.remaining()?;
            require(frame["kind"] != "cancel" && frame["kind"] != "execution-lease-renew",
                "execution controls are owned by this authenticated connection")?;
            if self.pending_interrupt()? { self.interrupt()?; }
            if frame["kind"] == "session-ok" {
                if let Some(grant) = frame.get("execution_lease") {
                    require(self.lease.is_none() && self.execution.is_none(),
                        "execution lease cannot be renegotiated")?;
                    self.lease = Some(ExecutionLease::parse(grant)?);
                }
            }
            if frame["kind"] == "canonical-exec" {
                if let Some(lease) = &self.lease { lease.validate_request(frame)?; }
            }
            let sent_at = Instant::now();
            // Before a complete dispatch, cancellation may abandon a partially
            // written frame. Poison this connection; never insert a cancel
            // record inside it or retry an uncertain canonical-exec. After a
            // completed dispatch, the read path owns cancellation and drain.
            if self.execution.is_none() && self.interrupts.finish_verified_delivery() {
                self.send_interruptibly(frame, None)?;
            } else {
                self.inner.send(frame)?;
            }
            if frame["kind"] == "canonical-exec" {
                self.execution = Some(frame["request_id"].as_u64()
                    .ok_or_else(|| super::invalid("missing execution identity"))?);
                if let Some(lease) = &mut self.lease { lease.arm(sent_at); }
            }
            Ok(())
        })();
        self.inner.failed |= result.is_err();
        result
    }

    fn receive(&mut self) -> io::Result<Value> {
        let result = self.receive_inner();
        self.inner.failed |= result.is_err();
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asupersync::io::ReadBuf;
    use asupersync::runtime::{Runtime, RuntimeBuilder};
    use std::collections::VecDeque;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};

    mod lease_tests {
        include!("interrupt/lease_tests.rs");
    }

    #[derive(Default)]
    struct Notification { pending:usize, waker:Option<Waker> }
    #[derive(Clone, Default)]
    struct Trigger(Arc<Mutex<Notification>>);
    impl Trigger {
        fn fire(&self) {
            let mut state = self.0.lock().unwrap();
            state.pending += 1;
            if let Some(waker) = state.waker.take() { waker.wake(); }
        }
    }
    impl Interrupts for Trigger {
        async fn wait(&mut self) -> io::Result<()> {
            poll_fn(|cx| {
                let mut state = self.0.lock().unwrap();
                if state.pending != 0 {
                    state.pending -= 1;
                    Poll::Ready(Ok(()))
                } else {
                    state.waker = Some(cx.waker().clone());
                    Poll::Pending
                }
            }).await
        }
    }

    enum Step { Bytes(VecDeque<u8>), Interrupt, Pending }
    struct Wire {
        steps: VecDeque<Step>,
        sent: Vec<u8>,
        trigger: Trigger,
        stop_on_dispatch: bool,
        fail_cancel: bool,
    }
    impl Wire {
        fn new(trigger: &Trigger, frames: &[Value]) -> Self {
            let bytes = frames.iter().map(|frame| format!("{frame}\n")).collect::<String>();
            Self { steps:VecDeque::from([Step::Bytes(bytes.into_bytes().into())]), sent:Vec::new(),
                trigger:trigger.clone(), stop_on_dispatch:false, fail_cancel:false }
        }
        fn sent(&self) -> Vec<Value> {
            self.sent.split(|byte| *byte == b'\n').filter(|line| !line.is_empty())
                .map(|line| serde_json::from_slice(line).unwrap()).collect()
        }
    }
    impl AsyncRead for Wire {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, output: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            loop {
                match this.steps.front_mut() {
                    Some(Step::Bytes(bytes)) if !bytes.is_empty() => {
                        let count = bytes.len().min(output.remaining());
                        output.put_slice(&bytes.drain(..count).collect::<Vec<_>>());
                        return Poll::Ready(Ok(()));
                    }
                    Some(Step::Bytes(_)) => { this.steps.pop_front(); }
                    Some(Step::Interrupt) => {
                        this.steps.pop_front();
                        this.trigger.fire();
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    Some(Step::Pending) => return Poll::Pending,
                    None => return Poll::Ready(Ok(())),
                }
            }
        }
    }
    impl AsyncWrite for Wire {
        fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            this.sent.extend_from_slice(bytes);
            let frame: Value = serde_json::from_slice(bytes).unwrap();
            if this.fail_cancel && frame["kind"] == "cancel" {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "uncertain cancel write")));
            }
            if this.stop_on_dispatch && frame["kind"] == "canonical-exec" { this.trigger.fire(); }
            Poll::Ready(Ok(bytes.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
    }
    fn runtime() -> Runtime { RuntimeBuilder::current_thread().build().unwrap() }
    fn request() -> Value { json!({"kind":"canonical-exec", "request_id":7, "program":"rustc",
        "args":[], "toolchain_backing":"/tc", "workspace_backing":"/ws"}) }
    fn accepted() -> Value { json!({"kind":"cancel-accepted", "request_id":7, "accepted":true, "cleanup_pending":true}) }
    fn result() -> Value { json!({"kind":"exec-result", "request_id":7, "exit_code":130, "stop_reason":"cancelled"}) }
    fn peer<'a>(runtime: &'a Runtime, trigger: &Trigger, frames: &[Value]) -> OperatorPeer<'a, Wire, Trigger> {
        OperatorPeer::with_interrupts(RecordPeer::new(runtime, Wire::new(trigger, frames), &request()), trigger.clone())
    }

    #[test]
    fn first_interrupt_sends_one_exact_cancel_and_waits_for_result_not_acceptance() {
        let runtime = runtime();
        let trigger = Trigger::default();
        let mut peer = peer(&runtime, &trigger, &[accepted(), result()]);
        peer.send(&request()).unwrap();
        let original_deadline = peer.inner.until;
        trigger.fire();
        assert_eq!(peer.receive().unwrap(), result());
        assert!(peer.cancel_response_seen);
        assert!(peer.inner.phase == Phase::Transfer);
        assert!(original_deadline > Instant::now() + CANCEL_DRAIN_BUDGET);
        assert_eq!(peer.inner.stream.sent(), vec![request(), json!({"kind":"cancel", "request_id":7})]);
        assert!(peer.send(&request()).is_err(), "never dispatch twice");
    }

    #[test]
    fn daemon_cancellation_is_idempotent_and_drains_the_terminal_result() {
        let runtime = runtime();
        let trigger = Trigger::default();
        let token = super::super::OperationCancellation::default();
        let wire = Wire::new(&trigger, &[accepted(), result()]);
        let mut peer = OperatorPeer::with_interrupts(
            RecordPeer::new(&runtime, wire, &request()), OperationInterrupts::new(token.clone()),
        );
        peer.send(&request()).unwrap();
        token.cancel();
        token.cancel();
        assert_eq!(peer.receive().unwrap(), result());
        token.cancel();
        peer.send(&json!({"kind":"output-read", "request_id":7})).unwrap();
        assert!(!peer.inner.failed);
        assert_eq!(peer.inner.stream.sent().iter().filter(|frame| frame["kind"] == "cancel").count(), 1);
        assert!(peer.cancel_response_seen);
    }

    #[test]
    fn daemon_stop_before_dispatch_sends_nothing_and_after_completion_preserves_delivery() {
        let runtime = runtime();
        let trigger = Trigger::default();
        for completed in [false, true] {
            let token = super::super::OperationCancellation::default();
            let success = json!({"kind":"exec-result", "request_id":7, "exit_code":0, "stop_reason":null});
            let chunk = json!({"kind":"output-chunk", "request_id":7});
            let wire = Wire::new(&trigger, &[success.clone(), chunk.clone()]);
            let mut peer = OperatorPeer::with_interrupts(
                RecordPeer::new(&runtime, wire, &request()), OperationInterrupts::new(token.clone()),
            );
            if completed {
                peer.send(&request()).unwrap();
                assert_eq!(peer.receive().unwrap(), success);
            }
            token.cancel();
            if completed {
                peer.send(&json!({"kind":"output-read", "request_id":7})).unwrap();
                assert_eq!(peer.receive().unwrap(), chunk);
                assert!(!peer.inner.failed);
                assert_eq!(peer.inner.stream.sent().len(), 2);
            } else {
                assert!(peer.send(&request()).is_err());
                assert!(peer.inner.stream.sent().is_empty());
            }
            assert!(!peer.cancel_sent);
        }
    }

    #[test]
    fn daemon_stop_interrupts_partial_dispatch_and_source_writes_without_inserting_cancel() {
        struct StalledWrite {
            token: super::super::OperationCancellation,
            stage: usize,
            sent: Vec<u8>,
        }
        impl AsyncRead for StalledWrite {
            fn poll_read(self: Pin<&mut Self>, _: &mut Context<'_>, _: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
                Poll::Pending
            }
        }
        impl AsyncWrite for StalledWrite {
            fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
                let this = self.get_mut();
                if this.stage == 2 {
                    this.sent.extend_from_slice(bytes);
                    return Poll::Ready(Ok(bytes.len()));
                }
                if this.stage == 1 && this.sent.is_empty() {
                    this.sent.extend_from_slice(&bytes[..3]);
                    return Poll::Ready(Ok(3));
                }
                this.token.cancel();
                Poll::Pending
            }
            fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                self.token.cancel();
                Poll::Pending
            }
            fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }
        let runtime = runtime();
        for frame in [request(), json!({"kind":"source-begin", "request_id":7})] {
            for stage in 0..3 {
                let token = super::super::OperationCancellation::default();
                let stream = StalledWrite { token:token.clone(), stage, sent:Vec::new() };
                let mut peer = OperatorPeer::with_interrupts(
                    RecordPeer::new(&runtime, stream, &request()), OperationInterrupts::new(token),
                );
                assert_eq!(peer.send(&frame).unwrap_err().kind(), io::ErrorKind::ConnectionAborted);
                assert!(peer.inner.failed);
                assert!(!peer.cancel_sent, "a cancel cannot be appended to an incomplete frame");
                assert!(peer.execution.is_none(), "a partial dispatch is never considered complete");
                let sent = peer.inner.stream.sent.clone();
                let expected = format!("{frame}\n").into_bytes();
                assert!(expected.starts_with(&sent));
                assert_eq!(sent.len(), match stage { 0 => 0, 1 => 3, _ => expected.len() });
                assert!(peer.send(&request()).is_err());
                assert_eq!(peer.inner.stream.sent, sent, "an interrupted write must never retry");
            }
        }
    }

    #[test]
    fn accepted_cancel_without_terminal_result_is_still_a_failure() {
        let runtime = runtime();
        let trigger = Trigger::default();
        let mut peer = peer(&runtime, &trigger, &[accepted()]);
        peer.send(&request()).unwrap();
        trigger.fire();
        assert_eq!(peer.receive().unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
        assert!(peer.inner.failed);
        assert!(peer.inner.phase == Phase::Execution);
        assert_eq!(peer.inner.stream.sent().len(), 2);
    }

    #[test]
    fn partial_record_is_preserved_when_interrupt_wins_a_pending_read() {
        let runtime = runtime();
        let trigger = Trigger::default();
        let mut peer = peer(&runtime, &trigger, &[]);
        peer.inner.stream.steps = VecDeque::from([
            Step::Bytes(b"{\"kind\":\"cancel-accepted\",\"request_id\":".to_vec().into()),
            Step::Interrupt,
            Step::Bytes(format!("7,\"accepted\":true,\"cleanup_pending\":true}}\n{}\n", result()).into_bytes().into()),
        ]);
        peer.send(&request()).unwrap();
        assert_eq!(peer.receive().unwrap(), result());
        assert!(peer.inner.buffered.is_empty());
        assert_eq!(peer.inner.stream.sent().len(), 2);
    }

    #[test]
    fn completion_race_preserves_success_and_consumes_only_one_late_control_reply() {
        let runtime = runtime();
        for control in [accepted(), json!({"kind":"error", "request_id":7, "reason":"unknown-request"})] {
            let trigger = Trigger::default();
            let success = json!({"kind":"exec-result", "request_id":7, "exit_code":0, "stop_reason":null});
            let chunk = json!({"kind":"output-chunk", "request_id":7});
            let mut peer = peer(&runtime, &trigger, &[success.clone(), control.clone(), chunk.clone(), control]);
            peer.send(&request()).unwrap();
            trigger.fire();
            assert_eq!(peer.receive().unwrap(), success);
            let deadline = peer.inner.until;
            peer.send(&json!({"kind":"output-read", "request_id":7})).unwrap();
            assert_eq!(peer.receive().unwrap(), chunk);
            assert_eq!(peer.inner.until, deadline);
            assert!(peer.receive().is_err(), "a second cancellation response cannot be hidden");
        }
    }

    #[test]
    fn malformed_foreign_and_unsolicited_cancel_responses_poison_the_session() {
        let runtime = runtime();
        for case in 0..6 {
            let trigger = Trigger::default();
            let mut reply = accepted();
            match case {
                0 => reply["request_id"] = json!(8),
                1 => reply["accepted"] = json!("true"),
                2 => reply["cleanup_pending"] = json!(false),
                3 => reply["stage"] = json!("source-upload"),
                4 => reply["request_id"] = Value::Null,
                _ => {}
            }
            let mut peer = peer(&runtime, &trigger, &[reply, result()]);
            peer.send(&request()).unwrap();
            if case != 5 { trigger.fire(); }
            assert!(peer.receive().is_err());
            assert!(peer.inner.failed);
            assert!(peer.inner.phase == Phase::Execution);
        }
    }

    #[test]
    fn pre_execution_and_recovery_interruptions_never_send_cancel_or_execute() {
        let runtime = runtime();
        for stage in ["admission", "source", "resume", "transfer"] {
            let trigger = Trigger::default();
            let mut peer = peer(&runtime, &trigger, &[]);
            match stage {
                "source" => peer.send(&json!({"kind":"source-begin", "request_id":7})).unwrap(),
                "resume" => peer.send(&json!({"kind":"result-resume", "request_id":7})).unwrap(),
                "transfer" => { peer.inner.phase = Phase::Transfer; }
                _ => {}
            }
            let before = peer.inner.stream.sent();
            trigger.fire();
            assert!(peer.send(&request()).is_err());
            assert!(peer.inner.failed);
            assert_eq!(peer.inner.stream.sent(), before);
            assert!(!peer.cancel_sent);
        }
    }

    #[test]
    fn lost_cancel_write_second_interrupt_and_deadline_never_retry_or_renew() {
        let runtime = runtime();
        for case in 0..3 {
            let trigger = Trigger::default();
            let mut peer = peer(&runtime, &trigger, &[accepted(), result()]);
            peer.send(&request()).unwrap();
            let until = Instant::now() + Duration::from_secs(2);
            peer.inner.until = until;
            if case == 0 { peer.inner.stream.fail_cancel = true; }
            if case == 1 { trigger.fire(); }
            if case == 2 { peer.inner.until = Instant::now() - Duration::from_secs(1); }
            trigger.fire();
            assert!(peer.receive().is_err());
            assert!(peer.inner.until <= until);
            let sent = peer.inner.stream.sent();
            assert!(sent.iter().filter(|frame| frame["kind"] == "cancel").count() <= 1);
            assert!(peer.receive().is_err());
            assert!(peer.send(&request()).is_err());
            assert_eq!(peer.inner.stream.sent(), sent);
        }
    }

    #[test]
    fn quiet_worker_still_has_a_finite_cancel_drain_deadline() {
        let runtime = runtime();
        let trigger = Trigger::default();
        let mut peer = peer(&runtime, &trigger, &[]);
        peer.inner.stream.steps = VecDeque::from([Step::Pending]);
        peer.send(&request()).unwrap();
        peer.inner.until = Instant::now() + Duration::from_millis(10);
        trigger.fire();
        assert_eq!(peer.receive().unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert!(peer.cancel_sent);
        assert!(peer.inner.failed);
    }

    #[test]
    fn cancelled_compilation_uses_complete_delivery_verification_before_release() {
        use sha2::{Digest, Sha256};
        use crate::coord::worker_delivery::receive_execution;
        let hash = |bytes: &[u8]| super::super::hex(&Sha256::digest(bytes));
        let runtime = runtime();
        let trigger = Trigger::default();
        let parent = tempfile::tempdir().unwrap();
        let destination = parent.path().join("delivery");
        let mut terminal = result();
        terminal["executed"] = json!(true);
        terminal["residual_group_members"] = json!(0);
        terminal["output_transfer"] = json!("ranges-v1");
        terminal["output_ack_required"] = json!(true);
        terminal["stdout_bytes"] = json!(0);
        terminal["stderr_bytes"] = json!(0);
        terminal["stdout_sha256"] = json!(hash(b""));
        terminal["stderr_sha256"] = json!(hash(b""));
        terminal["artifact_ack_required"] = json!(false);
        terminal["artifact_manifest"] = Value::Null;
        let chunk = |stream: &str| json!({"kind":"output-chunk", "request_id":7,
            "stream":stream, "offset":0, "next_offset":0, "total_bytes":0, "eof":true,
            "sha256":hash(b""), "chunk_sha256":hash(b""), "data_hex":""});
        let frames = [json!({"kind":"worker-hello", "worker_id":"worker", "canonical":true,
            "slots":1, "boot_generation":1, "incarnation":"00000000000000000000000000000001",
            "request_high_water":null, "recovery_protocols":["request-journal-v1"], "output_transfers":["ranges-v1"]}),
            accepted(), terminal, chunk("stdout"), chunk("stderr"),
            json!({"kind":"output-acknowledged", "request_id":7, "already_released":false})];
        let mut peer = peer(&runtime, &trigger, &frames);
        peer.inner.stream.stop_on_dispatch = true;
        let delivery = receive_execution(&mut peer, &request(), "worker", &destination).unwrap();
        assert!(delivery.acknowledgments_confirmed);
        assert_eq!(delivery.receipt["exit_code"], 130);
        assert_eq!(delivery.receipt["stop_reason"], "cancelled");
        assert_eq!(delivery.receipt["publication_authorized"], false);
        assert!(destination.join("delivery.json").is_file());
        let sent = peer.inner.stream.sent();
        assert_eq!(sent.iter().filter(|frame| frame["kind"] == "canonical-exec").count(), 1);
        assert_eq!(sent.iter().filter(|frame| frame["kind"] == "cancel").count(), 1);
        assert_eq!(sent.last().unwrap()["kind"], "output-ack");
    }
}
