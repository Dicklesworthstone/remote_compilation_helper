//! One bounded, acknowledged transcript prefix for an already committed result.
//!
//! This handshake grants no installation or execution authority. The caller
//! may offer a prefix only after the corresponding metadata is installed and
//! verified. A disconnect or abandoned session wakes the owned installer before
//! it is joined; the installer never waits on a metadata-store lock here.

use serde::Deserialize;
use serde_json::json;
use std::sync::{Condvar, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub(crate) struct Identity {
    pub(crate) action_key: String,
    pub(crate) manifest_key: String,
    remote: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Consent {
    kind: String,
    metadata_protocol: u32,
    action_key: String,
    manifest_key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Acknowledgment {
    kind: String,
    metadata_protocol: u32,
    action_key: String,
    manifest_key: String,
    sequence: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoteConsent {
    kind: String,
    capture: String,
    remote_protocol: u32,
    metadata_protocol: u32,
    action_key: String,
    manifest_key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoteAcknowledgment {
    kind: String,
    capture: String,
    remote_protocol: u32,
    metadata_protocol: u32,
    action_key: String,
    manifest_key: String,
    sequence: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CaptureConsent {
    kind: String,
    capture: String,
}

/// Only an unextended legacy consent can decline metadata negotiation. A
/// partial, duplicate or mismatched metadata identity must never downgrade.
pub(crate) fn accepts_capture(bytes: &[u8], capture: &str) -> bool {
    serde_json::from_slice::<CaptureConsent>(bytes)
        .is_ok_and(|value| value.kind == "rustc-accept" && value.capture == capture)
}

impl Identity {
    pub(crate) fn cached(action_key: String, manifest_key: String) -> Self {
        Self {
            action_key,
            manifest_key,
            remote: false,
        }
    }

    pub(crate) fn produced(action_key: String, capture: String) -> Self {
        Self {
            action_key,
            manifest_key: capture,
            remote: true,
        }
    }

    pub(super) fn is_remote(&self) -> bool {
        self.remote
    }

    pub(crate) fn accepts(&self, bytes: &[u8]) -> bool {
        if self.remote {
            return serde_json::from_slice::<RemoteConsent>(bytes).is_ok_and(|value| {
                value.kind == "rustc-accept"
                    && value.remote_protocol == 1
                    && value.metadata_protocol == 1
                    && value.action_key == self.action_key
                    && value.manifest_key == self.manifest_key
                    && value.capture == self.manifest_key
            });
        }
        serde_json::from_slice::<Consent>(bytes).is_ok_and(|value| {
            value.kind == "rustc-accept"
                && value.metadata_protocol == 1
                && value.action_key == self.action_key
                && value.manifest_key == self.manifest_key
        })
    }

    pub(super) fn acknowledges(&self, bytes: &[u8]) -> bool {
        if self.remote {
            return serde_json::from_slice::<RemoteAcknowledgment>(bytes).is_ok_and(|value| {
                value.kind == "rustc-metadata-ack"
                    && value.remote_protocol == 1
                    && value.metadata_protocol == 1
                    && value.action_key == self.action_key
                    && value.manifest_key == self.manifest_key
                    && value.capture == self.manifest_key
                    && value.sequence == 1
            });
        }
        serde_json::from_slice::<Acknowledgment>(bytes).is_ok_and(|value| {
            value.kind == "rustc-metadata-ack"
                && value.metadata_protocol == 1
                && value.action_key == self.action_key
                && value.manifest_key == self.manifest_key
                && value.sequence == 1
        })
    }

    pub(super) fn notice(&self, prefix: &[u8]) -> String {
        let bytes: String = prefix.iter().map(|byte| format!("{byte:02x}")).collect();
        let mut value = json!({
            "kind":"rustc-metadata", "metadata_protocol":1,
            "action_key":self.action_key, "manifest_key":self.manifest_key,
            "sequence":1, "stderr_hex":bytes,
        });
        if self.remote {
            value["remote_protocol"] = json!(1);
            value["capture"] = json!(self.manifest_key);
        }
        value.to_string()
    }
}

#[derive(Default)]
struct State {
    prefix: Option<Vec<u8>>,
    offered: bool,
    taken: bool,
    settled: bool,
    acknowledged: bool,
    waker: Option<Waker>,
}

pub(super) struct Exchange {
    state: Mutex<State>,
    changed: Condvar,
    maximum: usize,
    budget: Duration,
}

impl Exchange {
    pub(super) fn new(maximum: usize, budget: Duration) -> Self {
        Self {
            state: Mutex::new(State::default()),
            changed: Condvar::new(),
            maximum,
            budget,
        }
    }

    /// Called by the existing bounded installer thread, at most once. This
    /// waits only for one exact prefix ACK, under one absolute deadline.
    pub(super) fn offer(&self, prefix: &[u8]) -> Result<(), String> {
        if prefix.is_empty() || prefix.len() > self.maximum {
            return Err("metadata transcript prefix is outside its bound".into());
        }
        let deadline = Instant::now()
            .checked_add(self.budget)
            .ok_or("metadata acknowledgment deadline overflow")?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| "metadata handshake poisoned")?;
        if state.offered || state.settled {
            return Err("metadata handshake already used or abandoned".into());
        }
        state.offered = true;
        state.prefix = Some(prefix.to_vec());
        let wake = state.waker.take();
        drop(state);
        if let Some(waker) = wake {
            waker.wake();
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| "metadata handshake poisoned")?;
        while !state.settled {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                state.settled = true;
                state.prefix = None;
                return Err("metadata acknowledgment deadline exceeded".into());
            };
            state = self
                .changed
                .wait_timeout(state, remaining)
                .map_err(|_| "metadata handshake poisoned")?
                .0;
        }
        if state.acknowledged {
            Ok(())
        } else {
            Err("metadata transcript was not acknowledged".into())
        }
    }

    pub(super) fn poll_prefix(&self, cx: &mut Context<'_>) -> Poll<Option<Vec<u8>>> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(prefix) = state.prefix.take() {
            state.taken = true;
            return Poll::Ready(Some(prefix));
        }
        if state.settled || state.taken {
            return Poll::Ready(None);
        }
        state.waker = Some(cx.waker().clone());
        Poll::Pending
    }

    /// A positive resolution is accepted only after the one queued prefix was
    /// taken for delivery. Negative resolution is cancellation and is sticky.
    pub(super) fn resolve(&self, acknowledged: bool) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if state.settled {
            return;
        }
        state.settled = true;
        state.acknowledged = acknowledged && state.offered && state.taken;
        state.prefix = None;
        let wake = state.waker.take();
        drop(state);
        self.changed.notify_all();
        if let Some(waker) = wake {
            waker.wake();
        }
    }

    pub(super) fn offered(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .offered
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, mpsc};
    use std::task::Wake;

    struct WakeThread(std::thread::Thread);
    impl Wake for WakeThread {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }

    fn prefix(exchange: &Exchange) -> Vec<u8> {
        let waker = Waker::from(Arc::new(WakeThread(std::thread::current())));
        let mut cx = Context::from_waker(&waker);
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            match exchange.poll_prefix(&mut cx) {
                Poll::Ready(value) => return value.expect("one prefix must be offered"),
                Poll::Pending => {
                    assert!(Instant::now() < until, "metadata offer lost its wake");
                    std::thread::park_timeout(Duration::from_millis(10));
                }
            }
        }
    }

    #[test]
    fn real_owned_thread_waits_for_one_consumed_prefix_and_exact_resolution() {
        let exchange = Arc::new(Exchange::new(1024, Duration::from_secs(5)));
        let (finished, received) = mpsc::channel();
        let producer = Arc::clone(&exchange);
        let thread = std::thread::spawn(move || {
            finished
                .send(producer.offer(b"diagnostic\nmetadata\n"))
                .unwrap();
        });
        assert_eq!(prefix(&exchange), b"diagnostic\nmetadata\n");
        assert!(
            received.try_recv().is_err(),
            "no tail before acknowledgment"
        );
        exchange.resolve(true);
        assert_eq!(
            received.recv_timeout(Duration::from_secs(5)).unwrap(),
            Ok(())
        );
        thread.join().unwrap();
        assert!(exchange.offer(b"duplicate").is_err());
        assert!(exchange.offered());
    }

    #[test]
    fn cancellation_and_fixed_deadline_release_the_actual_waiting_thread() {
        for cancel in [false, true] {
            let budget = if cancel {
                Duration::from_secs(5)
            } else {
                Duration::from_millis(40)
            };
            let exchange = Arc::new(Exchange::new(1024, budget));
            let producer = Arc::clone(&exchange);
            let thread = std::thread::spawn(move || producer.offer(b"metadata\n"));
            if cancel {
                assert_eq!(prefix(&exchange), b"metadata\n");
                exchange.resolve(false);
            }
            assert!(thread.join().unwrap().is_err());
            exchange.resolve(true);
            assert!(exchange.offer(b"late retry").is_err());
        }
    }

    #[test]
    fn early_ack_cannot_authorize_an_unoffered_or_unconsumed_prefix() {
        let exchange = Exchange::new(1024, Duration::from_secs(5));
        exchange.resolve(true);
        assert!(exchange.offer(b"metadata\n").is_err());
        assert!(!exchange.offered());
        let exchange = Exchange::new(2, Duration::from_secs(5));
        assert!(exchange.offer(b"").is_err());
        assert!(exchange.offer(b"too large").is_err());
        assert!(!exchange.offered());
    }

    #[test]
    fn consent_and_ack_bind_version_action_manifest_sequence_and_unique_fields() {
        let identity = Identity::cached("action-a".into(), "manifest-a".into());
        let consent = json!({"kind":"rustc-accept","metadata_protocol":1,
            "action_key":"action-a","manifest_key":"manifest-a"});
        assert!(identity.accepts(consent.to_string().as_bytes()));
        let ack = json!({"kind":"rustc-metadata-ack","metadata_protocol":1,
            "action_key":"action-a","manifest_key":"manifest-a","sequence":1});
        assert!(identity.acknowledges(ack.to_string().as_bytes()));
        for (field, value) in [
            ("kind", json!("other")),
            ("metadata_protocol", json!(2)),
            ("action_key", json!("other")),
            ("manifest_key", json!("other")),
            ("sequence", json!(2)),
        ] {
            let mut changed = ack.clone();
            changed[field] = value;
            assert!(!identity.acknowledges(changed.to_string().as_bytes()));
        }
        let duplicate = br#"{"kind":"rustc-metadata-ack","metadata_protocol":1,"action_key":"wrong","action_key":"action-a","manifest_key":"manifest-a","sequence":1}"#;
        assert!(!identity.acknowledges(duplicate));
        let mut extra = ack;
        extra["writer_returned"] = json!(true);
        assert!(!identity.acknowledges(extra.to_string().as_bytes()));
        assert!(!identity.accepts(br#"{"kind":"rustc-accept"}"#));
        let notice: serde_json::Value =
            serde_json::from_str(&identity.notice(b"a\0\xff\n")).unwrap();
        assert_eq!(notice["stderr_hex"], "6100ff0a");
        assert_eq!(notice["manifest_key"], "manifest-a");
    }

    #[test]
    fn produced_consent_ack_and_notice_bind_the_exact_remote_capture() {
        let identity = Identity::produced("action-a".into(), "manifest-a".into());
        assert!(identity.is_remote());
        let consent = json!({"kind":"rustc-accept","capture":"manifest-a",
            "remote_protocol":1,"metadata_protocol":1,
            "action_key":"action-a","manifest_key":"manifest-a"});
        assert!(identity.accepts(consent.to_string().as_bytes()));
        let mut ack = consent.clone();
        ack["kind"] = json!("rustc-metadata-ack");
        ack["sequence"] = json!(1);
        assert!(identity.acknowledges(ack.to_string().as_bytes()));
        for (field, value) in [
            ("kind", json!("other")),
            ("capture", json!("other")),
            ("remote_protocol", json!(2)),
            ("metadata_protocol", json!(2)),
            ("action_key", json!("other")),
            ("manifest_key", json!("other")),
        ] {
            let mut changed = consent.clone();
            changed[field] = value.clone();
            assert!(!identity.accepts(changed.to_string().as_bytes()));
            let mut changed = ack.clone();
            changed[field] = value;
            assert!(!identity.acknowledges(changed.to_string().as_bytes()));
        }
        ack["sequence"] = json!(2);
        assert!(!identity.acknowledges(ack.to_string().as_bytes()));
        let duplicate = br#"{"kind":"rustc-metadata-ack","capture":"wrong","capture":"manifest-a","remote_protocol":1,"metadata_protocol":1,"action_key":"action-a","manifest_key":"manifest-a","sequence":1}"#;
        assert!(!identity.acknowledges(duplicate));
        let mut extra = consent.clone();
        extra["writer_returned"] = json!(true);
        assert!(!identity.accepts(extra.to_string().as_bytes()));
        let cached = Identity::cached("action-a".into(), "manifest-a".into());
        assert!(!cached.accepts(consent.to_string().as_bytes()));
        let notice: serde_json::Value =
            serde_json::from_str(&identity.notice(b"metadata\n")).unwrap();
        assert_eq!(notice.as_object().unwrap().len(), 8);
        assert_eq!(notice["remote_protocol"], 1);
        assert_eq!(notice["capture"], "manifest-a");
        assert_eq!(notice["manifest_key"], "manifest-a");
        assert_eq!(notice["stderr_hex"], "6d657461646174610a");
    }

    #[test]
    fn legacy_capture_consent_cannot_downgrade_a_partial_metadata_handshake() {
        let legacy = br#"{"kind":"rustc-accept","capture":"manifest-a"}"#;
        assert!(accepts_capture(legacy, "manifest-a"));
        assert!(!accepts_capture(legacy, "other"));
        let remote = Identity::produced("action-a".into(), "manifest-a".into());
        assert!(!remote.accepts(legacy));
        for invalid in [
            br#"{"kind":"rustc-accept","capture":"manifest-a","metadata_protocol":1}"#.as_slice(),
            br#"{"kind":"rustc-accept","capture":"wrong","capture":"manifest-a"}"#,
            br#"{"kind":"rustc-accept","capture":"manifest-a","action_key":"action-a"}"#,
        ] {
            assert!(!accepts_capture(invalid, "manifest-a"));
        }
    }
}
