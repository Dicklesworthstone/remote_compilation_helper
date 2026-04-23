//! In-memory benchmark queue with rate limiting.

#![allow(dead_code)] // Used by SpeedScore API endpoints and future scheduler work.

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use rch_common::WorkerId;
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

/// Benchmark request queued by the API.
#[derive(Debug, Clone)]
pub struct BenchmarkRequest {
    pub request_id: String,
    pub worker_id: WorkerId,
    pub requested_at: DateTime<Utc>,
}

/// Rate limit information when benchmark trigger is rejected.
#[derive(Debug, Clone)]
pub struct RateLimitInfo {
    pub retry_after: ChronoDuration,
    pub last_triggered_at: DateTime<Utc>,
}

/// Simple FIFO queue for benchmark triggers.
pub struct BenchmarkQueue {
    min_interval: ChronoDuration,
    queue: Mutex<VecDeque<BenchmarkRequest>>,
    last_triggered: Mutex<HashMap<WorkerId, DateTime<Utc>>>,
}

impl BenchmarkQueue {
    /// Create a new queue with the specified per-worker minimum interval.
    pub fn new(min_interval: ChronoDuration) -> Self {
        Self {
            min_interval,
            queue: Mutex::new(VecDeque::new()),
            last_triggered: Mutex::new(HashMap::new()),
        }
    }

    /// Attempt to enqueue a benchmark request.
    pub fn enqueue(
        &self,
        worker_id: WorkerId,
        request_id: String,
    ) -> Result<BenchmarkRequest, RateLimitInfo> {
        let now = Utc::now();

        // Check-and-set under a single write lock: two concurrent callers
        // must not both pass the rate-limit check before either has
        // written its timestamp, or both requests would pass through and
        // the per-worker interval would be violated.
        {
            let mut last = self.last_triggered.lock().expect("benchmark rate lock");
            if let Some(last_at) = last.get(&worker_id) {
                let since = now - *last_at;
                if since < self.min_interval {
                    return Err(RateLimitInfo {
                        retry_after: self.min_interval - since,
                        last_triggered_at: *last_at,
                    });
                }
            }
            last.insert(worker_id.clone(), now);
        }

        let request = BenchmarkRequest {
            request_id,
            worker_id,
            requested_at: now,
        };

        let mut queue = self.queue.lock().expect("benchmark queue lock");
        queue.push_back(request.clone());
        Ok(request)
    }

    /// Current queued depth.
    pub fn len(&self) -> usize {
        let queue = self.queue.lock().expect("benchmark queue lock");
        queue.len()
    }

    /// Returns true if the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Pop the next benchmark request from the queue.
    pub fn pop(&self) -> Option<BenchmarkRequest> {
        let mut queue = self.queue.lock().expect("benchmark queue lock");
        queue.pop_front()
    }

    /// Clear all pending requests from the queue.
    pub fn clear(&self) {
        let mut queue = self.queue.lock().expect("benchmark queue lock");
        queue.clear();
    }

    /// Get the minimum interval between benchmarks for a single worker.
    pub fn min_interval(&self) -> ChronoDuration {
        self.min_interval
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rch_common::test_guard;
    use tracing::info;

    fn setup_tracing() {
        let _ = tracing_subscriber::fmt()
            .with_test_writer()
            .with_max_level(tracing::Level::INFO)
            .try_init();
    }

    #[test]
    fn test_queue_creation() {
        let _guard = test_guard!();
        setup_tracing();
        info!("TEST START: test_queue_creation");

        let interval = ChronoDuration::seconds(60);
        let queue = BenchmarkQueue::new(interval);

        info!("INPUT: Created queue with 60 second min_interval");
        assert_eq!(queue.min_interval().num_seconds(), 60);
        assert!(queue.is_empty());
        assert_eq!(queue.len(), 0);

        info!("VERIFY: Queue created with correct interval and empty state");
        info!("TEST PASS: test_queue_creation");
    }

    #[test]
    fn test_enqueue_success() {
        let _guard = test_guard!();
        setup_tracing();
        info!("TEST START: test_enqueue_success");

        let queue = BenchmarkQueue::new(ChronoDuration::seconds(0));
        let worker_id = WorkerId::new("worker-1".to_string());
        let request_id = "req-001".to_string();

        info!(
            "INPUT: Enqueuing benchmark for worker={}, request_id={}",
            worker_id, request_id
        );

        let result = queue.enqueue(worker_id.clone(), request_id.clone());

        assert!(result.is_ok());
        let request = result.unwrap();
        assert_eq!(request.worker_id, worker_id);
        assert_eq!(request.request_id, request_id);
        assert_eq!(queue.len(), 1);

        info!("VERIFY: Request enqueued successfully, queue length = 1");
        info!("TEST PASS: test_enqueue_success");
    }

    #[test]
    fn test_enqueue_rate_limited() {
        let _guard = test_guard!();
        setup_tracing();
        info!("TEST START: test_enqueue_rate_limited");

        let queue = BenchmarkQueue::new(ChronoDuration::seconds(60));
        let worker_id = WorkerId::new("worker-1".to_string());

        info!("INPUT: Enqueuing first request for worker-1");
        let result1 = queue.enqueue(worker_id.clone(), "req-001".to_string());
        assert!(result1.is_ok());

        info!("INPUT: Attempting second request immediately (should be rate limited)");
        let result2 = queue.enqueue(worker_id.clone(), "req-002".to_string());
        assert!(result2.is_err());

        let rate_limit_info = result2.unwrap_err();
        info!(
            "VERIFY: Rate limited - retry_after={}s, last_triggered={}",
            rate_limit_info.retry_after.num_seconds(),
            rate_limit_info.last_triggered_at
        );
        assert!(rate_limit_info.retry_after.num_seconds() > 0);

        // Queue should only have 1 request
        assert_eq!(queue.len(), 1);

        info!("TEST PASS: test_enqueue_rate_limited");
    }

    #[test]
    fn test_multiple_workers_not_rate_limited() {
        let _guard = test_guard!();
        setup_tracing();
        info!("TEST START: test_multiple_workers_not_rate_limited");

        let queue = BenchmarkQueue::new(ChronoDuration::seconds(60));
        let worker1 = WorkerId::new("worker-1".to_string());
        let worker2 = WorkerId::new("worker-2".to_string());
        let worker3 = WorkerId::new("worker-3".to_string());

        info!("INPUT: Enqueuing requests for 3 different workers");

        let result1 = queue.enqueue(worker1.clone(), "req-001".to_string());
        let result2 = queue.enqueue(worker2.clone(), "req-002".to_string());
        let result3 = queue.enqueue(worker3.clone(), "req-003".to_string());

        assert!(result1.is_ok());
        assert!(result2.is_ok());
        assert!(result3.is_ok());
        assert_eq!(queue.len(), 3);

        info!("VERIFY: All 3 requests enqueued successfully (different workers)");
        info!("TEST PASS: test_multiple_workers_not_rate_limited");
    }

    #[test]
    fn test_pop_fifo_order() {
        let _guard = test_guard!();
        setup_tracing();
        info!("TEST START: test_pop_fifo_order");

        let queue = BenchmarkQueue::new(ChronoDuration::seconds(0));
        let worker1 = WorkerId::new("worker-1".to_string());
        let worker2 = WorkerId::new("worker-2".to_string());

        info!("INPUT: Enqueuing worker-1 then worker-2");
        queue
            .enqueue(worker1.clone(), "req-001".to_string())
            .unwrap();
        queue
            .enqueue(worker2.clone(), "req-002".to_string())
            .unwrap();

        info!("VERIFY: Pop returns items in FIFO order");
        let first = queue.pop().expect("first pop should succeed");
        assert_eq!(first.worker_id, worker1);
        assert_eq!(first.request_id, "req-001");

        let second = queue.pop().expect("second pop should succeed");
        assert_eq!(second.worker_id, worker2);
        assert_eq!(second.request_id, "req-002");

        assert!(queue.pop().is_none());
        assert!(queue.is_empty());

        info!("TEST PASS: test_pop_fifo_order");
    }

    #[test]
    fn test_clear_queue() {
        let _guard = test_guard!();
        setup_tracing();
        info!("TEST START: test_clear_queue");

        let queue = BenchmarkQueue::new(ChronoDuration::seconds(0));

        info!("INPUT: Adding 5 requests then clearing");
        for i in 0..5 {
            let worker_id = WorkerId::new(format!("worker-{}", i));
            queue.enqueue(worker_id, format!("req-{:03}", i)).unwrap();
        }
        assert_eq!(queue.len(), 5);

        queue.clear();
        assert!(queue.is_empty());
        assert_eq!(queue.len(), 0);

        info!("VERIFY: Queue cleared successfully");
        info!("TEST PASS: test_clear_queue");
    }

    #[test]
    fn test_zero_interval_allows_rapid_enqueue() {
        let _guard = test_guard!();
        setup_tracing();
        info!("TEST START: test_zero_interval_allows_rapid_enqueue");

        let queue = BenchmarkQueue::new(ChronoDuration::seconds(0));
        let worker_id = WorkerId::new("worker-rapid".to_string());

        info!("INPUT: Enqueuing 10 requests rapidly with zero interval");
        for i in 0..10 {
            let result = queue.enqueue(worker_id.clone(), format!("req-{:03}", i));
            assert!(
                result.is_ok(),
                "Request {} should succeed with zero interval",
                i
            );
        }

        assert_eq!(queue.len(), 10);
        info!("VERIFY: All 10 rapid requests succeeded with zero interval");
        info!("TEST PASS: test_zero_interval_allows_rapid_enqueue");
    }

    #[test]
    fn test_request_contains_timestamp() {
        let _guard = test_guard!();
        setup_tracing();
        info!("TEST START: test_request_contains_timestamp");

        let queue = BenchmarkQueue::new(ChronoDuration::seconds(0));
        let worker_id = WorkerId::new("worker-ts".to_string());

        let before = Utc::now();
        let result = queue.enqueue(worker_id.clone(), "req-ts".to_string());
        let after = Utc::now();

        let request = result.unwrap();

        info!(
            "VERIFY: Request timestamp {} is between {} and {}",
            request.requested_at, before, after
        );
        assert!(request.requested_at >= before);
        assert!(request.requested_at <= after);

        info!("TEST PASS: test_request_contains_timestamp");
    }

    // ==================== Additional Coverage Tests ====================

    #[test]
    fn test_benchmark_request_clone() {
        let request = BenchmarkRequest {
            request_id: "req-clone".to_string(),
            worker_id: WorkerId::new("clone-worker"),
            requested_at: Utc::now(),
        };

        let cloned = request.clone();
        assert_eq!(cloned.request_id, request.request_id);
        assert_eq!(cloned.worker_id, request.worker_id);
        assert_eq!(cloned.requested_at, request.requested_at);
    }

    #[test]
    fn test_benchmark_request_debug() {
        let request = BenchmarkRequest {
            request_id: "req-debug".to_string(),
            worker_id: WorkerId::new("debug-worker"),
            requested_at: Utc::now(),
        };

        let debug_str = format!("{:?}", request);
        assert!(debug_str.contains("req-debug"));
        assert!(debug_str.contains("debug-worker"));
    }

    #[test]
    fn test_rate_limit_info_clone() {
        let info = RateLimitInfo {
            retry_after: ChronoDuration::seconds(30),
            last_triggered_at: Utc::now(),
        };

        let cloned = info.clone();
        assert_eq!(cloned.retry_after, info.retry_after);
        assert_eq!(cloned.last_triggered_at, info.last_triggered_at);
    }

    #[test]
    fn test_rate_limit_info_debug() {
        let info = RateLimitInfo {
            retry_after: ChronoDuration::seconds(45),
            last_triggered_at: Utc::now(),
        };

        let debug_str = format!("{:?}", info);
        assert!(debug_str.contains("retry_after"));
        assert!(debug_str.contains("last_triggered_at"));
    }

    #[test]
    fn test_pop_empty_queue() {
        let queue = BenchmarkQueue::new(ChronoDuration::seconds(10));
        assert!(queue.pop().is_none());
        assert!(queue.is_empty());
    }

    #[test]
    fn test_is_empty_after_pop_all() {
        let queue = BenchmarkQueue::new(ChronoDuration::seconds(0));

        // Add some requests
        for i in 0..3 {
            queue
                .enqueue(WorkerId::new(format!("w{}", i)), format!("r{}", i))
                .unwrap();
        }

        assert!(!queue.is_empty());
        assert_eq!(queue.len(), 3);

        // Pop all
        queue.pop();
        queue.pop();
        queue.pop();

        assert!(queue.is_empty());
        assert_eq!(queue.len(), 0);
    }

    #[test]
    fn test_len_accurate() {
        let queue = BenchmarkQueue::new(ChronoDuration::seconds(0));

        assert_eq!(queue.len(), 0);

        queue
            .enqueue(WorkerId::new("w1"), "r1".to_string())
            .unwrap();
        assert_eq!(queue.len(), 1);

        queue
            .enqueue(WorkerId::new("w2"), "r2".to_string())
            .unwrap();
        assert_eq!(queue.len(), 2);

        queue.pop();
        assert_eq!(queue.len(), 1);

        queue.pop();
        assert_eq!(queue.len(), 0);
    }

    #[test]
    fn test_clear_does_not_affect_rate_limits() {
        let queue = BenchmarkQueue::new(ChronoDuration::seconds(60));
        let worker_id = WorkerId::new("clear-test");

        // First enqueue should succeed
        queue.enqueue(worker_id.clone(), "r1".to_string()).unwrap();

        // Clear the queue
        queue.clear();
        assert!(queue.is_empty());

        // Second enqueue for same worker should still be rate limited
        let result = queue.enqueue(worker_id.clone(), "r2".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_rate_limit_info_fields() {
        let queue = BenchmarkQueue::new(ChronoDuration::seconds(100));
        let worker_id = WorkerId::new("rate-info-test");

        // First enqueue
        let before_first = Utc::now();
        queue.enqueue(worker_id.clone(), "r1".to_string()).unwrap();
        let after_first = Utc::now();

        // Second enqueue should fail with rate limit info
        let result = queue.enqueue(worker_id.clone(), "r2".to_string());
        let info = result.unwrap_err();

        // Verify retry_after is reasonable (close to 100 seconds)
        assert!(info.retry_after.num_seconds() > 90);
        assert!(info.retry_after.num_seconds() <= 100);

        // Verify last_triggered_at is from the first request
        assert!(info.last_triggered_at >= before_first);
        assert!(info.last_triggered_at <= after_first);
    }

    #[test]
    fn test_min_interval_accessor() {
        let interval = ChronoDuration::minutes(5);
        let queue = BenchmarkQueue::new(interval);

        assert_eq!(queue.min_interval().num_minutes(), 5);
        assert_eq!(queue.min_interval().num_seconds(), 300);
    }

    #[test]
    fn test_enqueue_pop_cycle() {
        let queue = BenchmarkQueue::new(ChronoDuration::seconds(0));

        // Cycle 1
        queue
            .enqueue(WorkerId::new("w1"), "r1".to_string())
            .unwrap();
        let popped = queue.pop().unwrap();
        assert_eq!(popped.request_id, "r1");
        assert!(queue.is_empty());

        // Cycle 2
        queue
            .enqueue(WorkerId::new("w2"), "r2".to_string())
            .unwrap();
        let popped = queue.pop().unwrap();
        assert_eq!(popped.request_id, "r2");
        assert!(queue.is_empty());

        // Cycle 3
        queue
            .enqueue(WorkerId::new("w3"), "r3".to_string())
            .unwrap();
        let popped = queue.pop().unwrap();
        assert_eq!(popped.request_id, "r3");
        assert!(queue.is_empty());
    }

    #[test]
    fn test_different_workers_different_rate_limits() {
        let queue = BenchmarkQueue::new(ChronoDuration::seconds(60));

        let w1 = WorkerId::new("w1");
        let w2 = WorkerId::new("w2");

        // Both first requests succeed
        assert!(queue.enqueue(w1.clone(), "r1".to_string()).is_ok());
        assert!(queue.enqueue(w2.clone(), "r2".to_string()).is_ok());

        // Both second requests fail (rate limited)
        assert!(queue.enqueue(w1.clone(), "r3".to_string()).is_err());
        assert!(queue.enqueue(w2.clone(), "r4".to_string()).is_err());

        // Queue should have 2 requests
        assert_eq!(queue.len(), 2);
    }

    #[test]
    fn test_very_long_interval() {
        let queue = BenchmarkQueue::new(ChronoDuration::hours(24));
        let worker_id = WorkerId::new("long-interval");

        // First request succeeds
        assert!(queue.enqueue(worker_id.clone(), "r1".to_string()).is_ok());

        // Second request fails with ~24 hour retry
        let result = queue.enqueue(worker_id.clone(), "r2".to_string());
        let info = result.unwrap_err();

        // retry_after should be close to 24 hours (allow some seconds tolerance)
        let retry_seconds = info.retry_after.num_seconds();
        assert!(
            retry_seconds > 86000,
            "Expected retry_after > 86000 seconds, got {}",
            retry_seconds
        );
        assert!(
            retry_seconds <= 86400,
            "Expected retry_after <= 86400 seconds, got {}",
            retry_seconds
        );
    }

    #[test]
    fn test_concurrent_access_simulation() {
        // This tests thread safety indirectly by accessing queue from main thread
        let queue = BenchmarkQueue::new(ChronoDuration::seconds(0));

        // Interleave enqueue and len checks
        for i in 0..100 {
            queue
                .enqueue(WorkerId::new(format!("w{}", i)), format!("r{}", i))
                .unwrap();
            assert_eq!(queue.len(), i + 1);
        }

        // Pop and verify
        for i in 0..100 {
            let item = queue.pop().unwrap();
            assert_eq!(item.request_id, format!("r{}", i));
        }

        assert!(queue.is_empty());
    }

    #[test]
    fn test_request_id_preserved() {
        let queue = BenchmarkQueue::new(ChronoDuration::seconds(0));
        let unique_id = "unique-request-id-12345-abcde";

        queue
            .enqueue(WorkerId::new("w1"), unique_id.to_string())
            .unwrap();

        let popped = queue.pop().unwrap();
        assert_eq!(popped.request_id, unique_id);
    }

    #[test]
    fn test_concurrent_enqueue_respects_rate_limit() {
        // Regression test for a check-then-set race: the rate-limit check
        // and the timestamp insert were performed under separate Mutex
        // acquisitions, which allowed two concurrent callers to both pass
        // the "not too recent" check before either had written.
        let _guard = test_guard!();
        let queue = std::sync::Arc::new(BenchmarkQueue::new(ChronoDuration::seconds(60)));
        let worker_id = WorkerId::new("hot-worker");

        let mut handles = Vec::new();
        for i in 0..16 {
            let q = queue.clone();
            let w = worker_id.clone();
            handles.push(std::thread::spawn(move || {
                q.enqueue(w, format!("req-{}", i))
            }));
        }

        let mut successes = 0;
        for h in handles {
            if h.join().expect("thread join").is_ok() {
                successes += 1;
            }
        }

        // Exactly one caller must succeed when the rate-limit window is
        // 60s and all callers arrive within microseconds of each other.
        assert_eq!(
            successes, 1,
            "rate-limit check must be atomic with insert; got {successes} successes"
        );
    }
}
