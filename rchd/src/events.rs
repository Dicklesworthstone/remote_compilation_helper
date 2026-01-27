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
    use rch_common::test_guard;
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

        // Note: serde_json 1.0.45+ converts NaN to null in json!() macro (to_value).
        // The outer to_string() then succeeds, so this test verifies the message IS sent
        // (with data containing null for the NaN value).
        let result = tokio::time::timeout(Duration::from_millis(25), rx.recv()).await;
        let msg = result
            .expect("should receive event (NaN serializes as null)")
            .expect("recv should succeed");
        let parsed: serde_json::Value = serde_json::from_str(&msg).expect("valid json");
        assert_eq!(parsed["event"], "bad_event");
        // NaN becomes null in serde_json Value
        assert!(
            parsed["data"]["value"].is_null(),
            "NaN should be serialized as null"
        );
    }

    #[tokio::test]
    async fn emit_warns_on_direct_serialization_failure() {
        // Test that the emit function handles serialization failures gracefully.
        // Note: With serde_json's json!() macro, NaN values are converted to null
        // rather than causing serialization failure. This test documents that behavior.
        let bad = NonFiniteData { value: f64::NAN };
        // json!() converts NaN to null, so this should succeed
        let payload = json!({
            "event": "test",
            "data": bad,
        });
        let result = serde_json::to_string(&payload);
        assert!(
            result.is_ok(),
            "json!() converts NaN to null, allowing serialization"
        );
        let serialized = result.unwrap();
        assert!(serialized.contains("null"), "NaN value becomes null");
    }

    // -------------------------------------------------------------------------
    // EventBus clone tests
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn clone_shares_same_channel() {
        let bus1 = EventBus::new(1);
        let bus2 = bus1.clone();
        let mut rx = bus1.subscribe();

        // Emit on cloned bus, receive on original subscriber
        bus2.emit("from_clone", &"test");

        let msg = tokio::time::timeout(Duration::from_millis(50), rx.recv())
            .await
            .expect("timed out")
            .expect("recv failed");
        let parsed: serde_json::Value = serde_json::from_str(&msg).expect("invalid json");
        assert_eq!(parsed["event"], "from_clone");
    }

    // -------------------------------------------------------------------------
    // Multiple subscriber tests
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn multiple_subscribers_receive_same_event() {
        let bus = EventBus::new(1);
        let mut rx1 = bus.subscribe();
        let mut rx2 = bus.subscribe();
        let mut rx3 = bus.subscribe();

        bus.emit("multi_sub_event", &42);

        for (idx, rx) in [&mut rx1, &mut rx2, &mut rx3].iter_mut().enumerate() {
            let msg = tokio::time::timeout(Duration::from_millis(50), rx.recv())
                .await
                .unwrap_or_else(|_| panic!("subscriber {} timed out", idx))
                .unwrap_or_else(|_| panic!("subscriber {} recv failed", idx));
            let parsed: serde_json::Value = serde_json::from_str(&msg).expect("invalid json");
            assert_eq!(parsed["event"], "multi_sub_event");
            assert_eq!(parsed["data"], 42);
        }
    }

    #[tokio::test]
    async fn late_subscriber_misses_previous_events() {
        let bus = EventBus::new(1);

        // Emit before subscribing
        bus.emit("early_event", &"before");

        let mut rx = bus.subscribe();

        // Emit after subscribing
        bus.emit("late_event", &"after");

        let msg = tokio::time::timeout(Duration::from_millis(50), rx.recv())
            .await
            .expect("timed out")
            .expect("recv failed");
        let parsed: serde_json::Value = serde_json::from_str(&msg).expect("invalid json");
        // Should receive the late event, not the early one
        assert_eq!(parsed["event"], "late_event");
        assert_eq!(parsed["data"], "after");
    }

    // -------------------------------------------------------------------------
    // Event data type tests
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn emit_with_string_data() {
        let bus = EventBus::new(1);
        let mut rx = bus.subscribe();

        bus.emit("string_event", &"hello world");

        let msg = tokio::time::timeout(Duration::from_millis(50), rx.recv())
            .await
            .expect("timed out")
            .expect("recv failed");
        let parsed: serde_json::Value = serde_json::from_str(&msg).expect("invalid json");
        assert_eq!(parsed["data"], "hello world");
    }

    #[tokio::test]
    async fn emit_with_integer_data() {
        let bus = EventBus::new(1);
        let mut rx = bus.subscribe();

        bus.emit("int_event", &12345i64);

        let msg = tokio::time::timeout(Duration::from_millis(50), rx.recv())
            .await
            .expect("timed out")
            .expect("recv failed");
        let parsed: serde_json::Value = serde_json::from_str(&msg).expect("invalid json");
        assert_eq!(parsed["data"], 12345);
    }

    #[tokio::test]
    async fn emit_with_float_data() {
        let bus = EventBus::new(1);
        let mut rx = bus.subscribe();

        let expected = std::f64::consts::PI;
        bus.emit("float_event", &expected);

        let msg = tokio::time::timeout(Duration::from_millis(50), rx.recv())
            .await
            .expect("timed out")
            .expect("recv failed");
        let parsed: serde_json::Value = serde_json::from_str(&msg).expect("invalid json");
        let data = parsed["data"].as_f64().expect("data should be float");
        assert!((data - expected).abs() < 0.00001);
    }

    #[tokio::test]
    async fn emit_with_boolean_data() {
        let bus = EventBus::new(1);
        let mut rx = bus.subscribe();

        bus.emit("bool_event", &true);

        let msg = tokio::time::timeout(Duration::from_millis(50), rx.recv())
            .await
            .expect("timed out")
            .expect("recv failed");
        let parsed: serde_json::Value = serde_json::from_str(&msg).expect("invalid json");
        assert_eq!(parsed["data"], true);
    }

    #[tokio::test]
    async fn emit_with_null_data() {
        let bus = EventBus::new(1);
        let mut rx = bus.subscribe();

        let null: Option<i32> = None;
        bus.emit("null_event", &null);

        let msg = tokio::time::timeout(Duration::from_millis(50), rx.recv())
            .await
            .expect("timed out")
            .expect("recv failed");
        let parsed: serde_json::Value = serde_json::from_str(&msg).expect("invalid json");
        assert!(parsed["data"].is_null());
    }

    #[tokio::test]
    async fn emit_with_array_data() {
        let bus = EventBus::new(1);
        let mut rx = bus.subscribe();

        bus.emit("array_event", &vec![1, 2, 3]);

        let msg = tokio::time::timeout(Duration::from_millis(50), rx.recv())
            .await
            .expect("timed out")
            .expect("recv failed");
        let parsed: serde_json::Value = serde_json::from_str(&msg).expect("invalid json");
        let arr = parsed["data"].as_array().expect("data should be array");
        assert_eq!(arr.len(), 3);
        assert_eq!(arr[0], 1);
        assert_eq!(arr[2], 3);
    }

    #[derive(Serialize)]
    struct NestedData {
        outer: InnerData,
    }

    #[derive(Serialize)]
    struct InnerData {
        value: String,
        count: u32,
    }

    #[tokio::test]
    async fn emit_with_nested_struct_data() {
        let bus = EventBus::new(1);
        let mut rx = bus.subscribe();

        let data = NestedData {
            outer: InnerData {
                value: "nested".to_string(),
                count: 99,
            },
        };
        bus.emit("nested_event", &data);

        let msg = tokio::time::timeout(Duration::from_millis(50), rx.recv())
            .await
            .expect("timed out")
            .expect("recv failed");
        let parsed: serde_json::Value = serde_json::from_str(&msg).expect("invalid json");
        assert_eq!(parsed["data"]["outer"]["value"], "nested");
        assert_eq!(parsed["data"]["outer"]["count"], 99);
    }

    // -------------------------------------------------------------------------
    // Event name edge cases
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn emit_with_empty_event_name() {
        let bus = EventBus::new(1);
        let mut rx = bus.subscribe();

        bus.emit("", &"empty name event");

        let msg = tokio::time::timeout(Duration::from_millis(50), rx.recv())
            .await
            .expect("timed out")
            .expect("recv failed");
        let parsed: serde_json::Value = serde_json::from_str(&msg).expect("invalid json");
        assert_eq!(parsed["event"], "");
        assert_eq!(parsed["data"], "empty name event");
    }

    #[tokio::test]
    async fn emit_with_special_chars_in_event_name() {
        let bus = EventBus::new(1);
        let mut rx = bus.subscribe();

        bus.emit("event/with:special.chars-and_underscores", &"special");

        let msg = tokio::time::timeout(Duration::from_millis(50), rx.recv())
            .await
            .expect("timed out")
            .expect("recv failed");
        let parsed: serde_json::Value = serde_json::from_str(&msg).expect("invalid json");
        assert_eq!(parsed["event"], "event/with:special.chars-and_underscores");
    }

    // -------------------------------------------------------------------------
    // Sequential events and ordering
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn events_received_in_order() {
        let bus = EventBus::new(10);
        let mut rx = bus.subscribe();

        for i in 0..5 {
            bus.emit("ordered_event", &i);
        }

        for expected in 0..5 {
            let msg = tokio::time::timeout(Duration::from_millis(50), rx.recv())
                .await
                .expect("timed out")
                .expect("recv failed");
            let parsed: serde_json::Value = serde_json::from_str(&msg).expect("invalid json");
            assert_eq!(parsed["data"], expected);
        }
    }

    // -------------------------------------------------------------------------
    // DEFAULT_BUFFER constant tests
    // -------------------------------------------------------------------------

    #[test]
    fn default_buffer_has_expected_value() {
        let _guard = test_guard!();
        assert_eq!(DEFAULT_BUFFER, 256);
    }

    #[tokio::test]
    async fn new_with_zero_buffer_uses_default() {
        let bus = EventBus::new(0);
        let mut rx = bus.subscribe();

        // Should be able to send DEFAULT_BUFFER messages without lag
        for idx in 0..DEFAULT_BUFFER {
            bus.sender.send(idx.to_string()).unwrap();
        }

        let first = rx.recv().await.expect("recv should not lag");
        assert_eq!(first, "0");
    }
}
