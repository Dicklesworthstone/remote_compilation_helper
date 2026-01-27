//! Event broadcast utilities for daemon telemetry and benchmarking updates.

#![allow(dead_code)] // Events are wired for upcoming beads.

use chrono::Utc;
use serde::Serialize;
use serde_json::json;
use tokio::sync::broadcast;
use tracing::warn;

const DEFAULT_BUFFER: usize = 256;

/// Broadcast channel for daemon events (JSON lines).
#[derive(Clone)]
pub struct EventBus {
    sender: broadcast::Sender<String>,
}

impl EventBus {
    /// Create a new event bus with the provided buffer size.
    ///
    /// Note: the effective buffer is clamped to at least `DEFAULT_BUFFER` to
    /// avoid frequent lag/drop behavior for bursty event streams.
    pub fn new(buffer: usize) -> Self {
        let buffer = buffer.max(1).max(DEFAULT_BUFFER);
        let (sender, _) = broadcast::channel(buffer);
        Self { sender }
    }

    /// Subscribe to the event stream.
    pub fn subscribe(&self) -> broadcast::Receiver<String> {
        self.sender.subscribe()
    }

    /// Emit a structured event with payload.
    pub fn emit<T: Serialize>(&self, event: &str, data: &T) {
        let payload = json!({
            "event": event,
            "data": data,
            "timestamp": Utc::now().to_rfc3339(),
        });
        match serde_json::to_string(&payload) {
            Ok(serialized) => {
                let _ = self.sender.send(serialized);
            }
            Err(err) => warn!("Failed to serialize event {}: {}", event, err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn new_clamps_small_buffers_to_default_capacity() {
        let bus = EventBus::new(1);
        let mut rx = bus.subscribe();

        for idx in 0..DEFAULT_BUFFER {
            bus.sender.send(idx.to_string()).unwrap();
        }

        // With the default buffer (256), the receiver should not lag.
        let first = rx.recv().await.expect("recv should not lag");
        assert_eq!(first, "0");
    }

    #[tokio::test]
    async fn new_small_buffer_lags_after_default_plus_one_messages() {
        let bus = EventBus::new(1);
        let mut rx = bus.subscribe();

        for idx in 0..=DEFAULT_BUFFER {
            bus.sender.send(idx.to_string()).unwrap();
        }

        match rx.recv().await {
            Err(broadcast::error::RecvError::Lagged(skipped)) => assert_eq!(skipped, 1),
            other => panic!("expected Lagged(1), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn new_allows_larger_buffers_without_lag() {
        let bus = EventBus::new(DEFAULT_BUFFER + 1);
        let mut rx = bus.subscribe();

        for idx in 0..=DEFAULT_BUFFER {
            bus.sender.send(idx.to_string()).unwrap();
        }

        let first = rx.recv().await.expect("recv should not lag");
        assert_eq!(first, "0");
    }

    #[tokio::test]
    async fn emit_sends_json_with_event_data_and_timestamp() {
        let bus = EventBus::new(1);
        let mut rx = bus.subscribe();

        let data = json!({ "answer": 42 });
        bus.emit("test_event", &data);

        let msg = tokio::time::timeout(Duration::from_millis(50), rx.recv())
            .await
            .expect("timed out waiting for event")
            .expect("broadcast recv failed");

        let parsed: serde_json::Value = serde_json::from_str(&msg).expect("invalid json");
        assert_eq!(parsed["event"], "test_event");
        assert_eq!(parsed["data"]["answer"], 42);
        let ts = parsed["timestamp"]
            .as_str()
            .expect("timestamp should be string");
        chrono::DateTime::parse_from_rfc3339(ts).expect("timestamp should be RFC3339");
    }

    #[derive(Serialize)]
    struct NonFiniteData {
        value: f64,
    }

    #[tokio::test]
    async fn emit_does_not_send_when_serialization_fails() {
        let bus = EventBus::new(1);
        let mut rx = bus.subscribe();

        let bad = NonFiniteData { value: f64::NAN };
        bus.emit("bad_event", &bad);

        // Serialization should fail (serde_json rejects non-finite floats), so no message arrives.
        let result = tokio::time::timeout(Duration::from_millis(25), rx.recv()).await;
        assert!(result.is_err(), "unexpectedly received an event");
    }
}
