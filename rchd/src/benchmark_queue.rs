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
        {
            let last = self.last_triggered.lock().expect("benchmark rate lock");
            if let Some(last_at) = last.get(&worker_id) {
                let since = now - *last_at;
                if since < self.min_interval {
                    return Err(RateLimitInfo {
                        retry_after: self.min_interval - since,
                        last_triggered_at: *last_at,
                    });
                }
            }
        }

        {
            let mut last = self.last_triggered.lock().expect("benchmark rate lock");
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
    use tracing::info;

    fn setup_tracing() {
        let _ = tracing_subscriber::fmt()
            .with_test_writer()
            .with_max_level(tracing::Level::INFO)
            .try_init();
    }

    #[test]
    fn test_queue_creation() {
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
}
