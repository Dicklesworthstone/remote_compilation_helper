//! Benchmark scheduling and orchestration.
//!
//! This module provides intelligent scheduling for worker benchmarks, balancing
//! measurement freshness against system load impact.
//!
//! ## Scheduling Triggers
//! - New workers: benchmark immediately on detection
//! - Stale scores: re-benchmark when score exceeds max age
//! - Drift detection: re-benchmark if telemetry suggests performance change
//! - Manual triggers: user-initiated benchmarks via API

#![allow(dead_code)] // Scaffold code - will be wired into main.rs in future beads

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use rch_common::WorkerId;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, RwLock, mpsc};
use tracing::{debug, info, warn};

use crate::events::EventBus;
use crate::telemetry::TelemetryStore;
use crate::workers::{WorkerPool, WorkerState};

/// Priority levels for benchmark requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BenchmarkPriority {
    /// Low priority - drift detection, speculative re-benchmark.
    Low = 0,
    /// Normal priority - scheduled re-benchmark due to age.
    Normal = 1,
    /// High priority - new workers, manual triggers.
    High = 2,
}

impl Default for BenchmarkPriority {
    fn default() -> Self {
        Self::Normal
    }
}

/// Reason why a benchmark was scheduled.
#[derive(Debug, Clone)]
pub enum BenchmarkReason {
    /// New worker detected without any SpeedScore.
    NewWorker,
    /// Existing SpeedScore is older than the configured max age.
    StaleScore { age: ChronoDuration },
    /// User or API triggered manual benchmark.
    ManualTrigger { user: Option<String> },
    /// Telemetry suggests performance drift from last benchmark.
    DriftDetected { drift_pct: f64 },
    /// Scheduled periodic re-benchmark.
    Scheduled,
}

impl std::fmt::Display for BenchmarkReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BenchmarkReason::NewWorker => write!(f, "new_worker"),
            BenchmarkReason::StaleScore { age } => {
                write!(f, "stale_score({}h)", age.num_hours())
            }
            BenchmarkReason::ManualTrigger { user } => {
                write!(f, "manual({})", user.as_deref().unwrap_or("api"))
            }
            BenchmarkReason::DriftDetected { drift_pct } => {
                write!(f, "drift({:.1}%)", drift_pct)
            }
            BenchmarkReason::Scheduled => write!(f, "scheduled"),
        }
    }
}

/// A request to benchmark a specific worker.
#[derive(Debug, Clone)]
pub struct ScheduledBenchmarkRequest {
    /// Unique request identifier.
    pub request_id: String,
    /// Worker to benchmark.
    pub worker_id: WorkerId,
    /// Priority of this request.
    pub priority: BenchmarkPriority,
    /// When this request was created.
    pub requested_at: DateTime<Utc>,
    /// Reason for scheduling this benchmark.
    pub reason: BenchmarkReason,
}

impl ScheduledBenchmarkRequest {
    /// Create a new benchmark request.
    pub fn new(worker_id: WorkerId, priority: BenchmarkPriority, reason: BenchmarkReason) -> Self {
        Self {
            request_id: uuid::Uuid::new_v4().to_string(),
            worker_id,
            priority,
            requested_at: Utc::now(),
            reason,
        }
    }
}

/// Status of a benchmark execution.
#[derive(Debug, Clone)]
pub enum BenchmarkStatus {
    /// Waiting in queue.
    Queued,
    /// Worker is being reserved.
    Reserving,
    /// Benchmark is running.
    Running {
        started_at: DateTime<Utc>,
        worker_id: WorkerId,
    },
    /// Benchmark completed successfully.
    Completed { duration: Duration, new_score: f64 },
    /// Benchmark failed.
    Failed { error: String, retryable: bool },
}

/// Manual benchmark trigger from API.
#[derive(Debug)]
pub struct BenchmarkTrigger {
    /// Worker to benchmark.
    pub worker_id: WorkerId,
    /// User who triggered the benchmark (if known).
    pub user: Option<String>,
    /// Original request ID from API.
    pub request_id: String,
}

/// Configuration for the benchmark scheduler.
#[derive(Debug, Clone)]
pub struct SchedulerConfig {
    /// Minimum interval between benchmarks for the same worker.
    pub min_interval: Duration,
    /// Maximum age of a SpeedScore before requiring re-benchmark.
    pub max_age: Duration,
    /// CPU utilization threshold below which a worker is considered idle.
    pub idle_cpu_threshold: f64,
    /// Maximum number of concurrent benchmarks.
    pub max_concurrent: usize,
    /// Threshold percentage for drift detection.
    pub drift_threshold_pct: f64,
    /// Timeout for benchmark execution.
    pub benchmark_timeout: Duration,
    /// Interval for checking workers for scheduling.
    pub check_interval: Duration,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            min_interval: Duration::from_secs(6 * 3600), // 6 hours
            max_age: Duration::from_secs(24 * 3600),     // 24 hours
            idle_cpu_threshold: 20.0,                    // 20% CPU
            max_concurrent: 1,
            drift_threshold_pct: 20.0,                      // 20% drift
            benchmark_timeout: Duration::from_secs(5 * 60), // 5 minutes
            check_interval: Duration::from_secs(60),        // 1 minute
        }
    }
}

/// Benchmark scheduler that orchestrates when and how benchmarks run.
pub struct BenchmarkScheduler {
    /// Scheduler configuration.
    config: SchedulerConfig,

    /// Priority queue of pending benchmark requests.
    /// Ordered by priority (High > Normal > Low), then by requested_at.
    pending_queue: Mutex<VecDeque<ScheduledBenchmarkRequest>>,

    /// Currently running benchmarks.
    running: RwLock<HashMap<WorkerId, RunningBenchmark>>,

    /// Channel receiver for manual triggers.
    trigger_rx: Mutex<mpsc::Receiver<BenchmarkTrigger>>,

    /// Worker pool reference.
    pool: WorkerPool,

    /// Telemetry store for idle detection.
    telemetry: Arc<TelemetryStore>,

    /// Event bus for notifications.
    events: EventBus,
}

/// Internal tracking of a running benchmark.
#[derive(Debug, Clone)]
struct RunningBenchmark {
    request: ScheduledBenchmarkRequest,
    started_at: DateTime<Utc>,
}

/// Handle for sending manual benchmark triggers.
#[derive(Clone)]
pub struct BenchmarkTriggerHandle {
    tx: mpsc::Sender<BenchmarkTrigger>,
}

impl BenchmarkTriggerHandle {
    /// Send a manual benchmark trigger.
    pub async fn trigger(
        &self,
        worker_id: WorkerId,
        request_id: String,
        user: Option<String>,
    ) -> Result<(), mpsc::error::SendError<BenchmarkTrigger>> {
        self.tx
            .send(BenchmarkTrigger {
                worker_id,
                user,
                request_id,
            })
            .await
    }
}

impl BenchmarkScheduler {
    /// Create a new benchmark scheduler.
    ///
    /// Returns the scheduler and a handle for sending manual triggers.
    pub fn new(
        config: SchedulerConfig,
        pool: WorkerPool,
        telemetry: Arc<TelemetryStore>,
        events: EventBus,
    ) -> (Self, BenchmarkTriggerHandle) {
        let (tx, rx) = mpsc::channel(64);

        let scheduler = Self {
            config,
            pending_queue: Mutex::new(VecDeque::new()),
            running: RwLock::new(HashMap::new()),
            trigger_rx: Mutex::new(rx),
            pool,
            telemetry,
            events,
        };

        let handle = BenchmarkTriggerHandle { tx };
        (scheduler, handle)
    }

    /// Get the number of pending benchmarks.
    pub async fn pending_count(&self) -> usize {
        self.pending_queue.lock().await.len()
    }

    /// Get the number of running benchmarks.
    pub async fn running_count(&self) -> usize {
        self.running.read().await.len()
    }

    /// Check if a worker has a pending or running benchmark.
    pub async fn is_pending_or_running(&self, worker_id: &WorkerId) -> bool {
        // Check running
        if self.running.read().await.contains_key(worker_id) {
            return true;
        }

        // Check pending queue
        let queue = self.pending_queue.lock().await;
        queue.iter().any(|r| &r.worker_id == worker_id)
    }

    /// Enqueue a benchmark request with priority ordering.
    pub async fn enqueue(&self, request: ScheduledBenchmarkRequest) {
        let mut queue = self.pending_queue.lock().await;

        // Find insertion point to maintain priority order
        // Higher priority first, then earlier requested_at
        let insert_pos = queue
            .iter()
            .position(|r| {
                // Insert before items with lower priority
                if r.priority < request.priority {
                    return true;
                }
                // For same priority, insert before items with later timestamp
                if r.priority == request.priority && r.requested_at > request.requested_at {
                    return true;
                }
                false
            })
            .unwrap_or(queue.len());

        info!(
            worker_id = %request.worker_id,
            priority = ?request.priority,
            reason = %request.reason,
            position = insert_pos,
            queue_len = queue.len(),
            "Enqueued benchmark request"
        );

        queue.insert(insert_pos, request.clone());

        // Emit event
        self.events.emit(
            "benchmark:queued",
            &serde_json::json!({
                "request_id": request.request_id,
                "worker_id": request.worker_id.as_str(),
                "priority": format!("{:?}", request.priority),
                "reason": request.reason.to_string(),
            }),
        );
    }

    /// Check workers and schedule benchmarks as needed.
    pub async fn check_workers_for_scheduling(&self) {
        let workers = self.pool.all_workers().await;

        for worker in workers {
            if let Some(request) = self.should_benchmark(&worker).await {
                self.enqueue(request).await;
            }
        }
    }

    /// Determine if a worker should be benchmarked.
    pub async fn should_benchmark(
        &self,
        worker: &WorkerState,
    ) -> Option<ScheduledBenchmarkRequest> {
        let config = worker.config.read().await;
        let worker_id = config.id.clone();
        drop(config); // Drop lock early

        // Already pending or running?
        if self.is_pending_or_running(&worker_id).await {
            return None;
        }

        // Try to get current SpeedScore
        let speedscore = self.telemetry.latest_speedscore(worker_id.as_str()).ok()?;

        // New worker without score?
        if speedscore.is_none() {
            debug!(worker_id = %worker_id, "New worker without SpeedScore");
            return Some(ScheduledBenchmarkRequest::new(
                worker_id,
                BenchmarkPriority::High,
                BenchmarkReason::NewWorker,
            ));
        }

        let score = speedscore.unwrap();
        let age = Utc::now() - score.calculated_at;
        let age_duration = age.to_std().unwrap_or_default();

        // Score too old?
        if age_duration > self.config.max_age {
            debug!(
                worker_id = %worker_id,
                age_hours = age.num_hours(),
                "SpeedScore exceeds max age"
            );
            return Some(ScheduledBenchmarkRequest::new(
                worker_id,
                BenchmarkPriority::Normal,
                BenchmarkReason::StaleScore { age },
            ));
        }

        // Too recent for any re-benchmark?
        if age_duration < self.config.min_interval {
            return None;
        }

        // Check for drift
        if let Some(drift_pct) = self.detect_drift(worker, &score).await {
            debug!(
                worker_id = %worker_id,
                drift_pct = drift_pct,
                "Performance drift detected"
            );
            return Some(ScheduledBenchmarkRequest::new(
                worker_id,
                BenchmarkPriority::Low,
                BenchmarkReason::DriftDetected { drift_pct },
            ));
        }

        None
    }

    /// Detect performance drift by comparing current telemetry to benchmark-time conditions.
    async fn detect_drift(
        &self,
        worker: &WorkerState,
        _score: &rch_telemetry::speedscore::SpeedScore,
    ) -> Option<f64> {
        let config = worker.config.read().await;
        let worker_id = config.id.to_string(); // Clone ID
        let total_slots = config.total_slots;
        drop(config); // Release lock

        // Get current telemetry
        let telemetry = self.telemetry.latest(&worker_id)?;

        // Get the current load average (fifteen minute)
        let current_load = telemetry.telemetry.cpu.load_average.fifteen_min;

        // For now, use a simple heuristic:
        // If load average is significantly different from what we'd expect
        // for the number of cores, consider it drift.
        let expected_load = total_slots as f64 * 0.3; // ~30% baseline
        let drift = ((current_load - expected_load) / expected_load.max(0.1)).abs() * 100.0;

        if drift > self.config.drift_threshold_pct {
            return Some(drift);
        }

        None
    }

    /// Check if a worker is eligible for benchmarking (idle and healthy).
    pub async fn is_worker_eligible(&self, worker_id: &WorkerId) -> bool {
        // Get worker
        let Some(worker) = self.pool.get(worker_id).await else {
            return false;
        };

        // Check health status
        let status = worker.status().await;
        if !matches!(
            status,
            rch_common::WorkerStatus::Healthy | rch_common::WorkerStatus::Degraded
        ) {
            debug!(
                worker_id = %worker_id,
                status = ?status,
                "Worker not healthy for benchmark"
            );
            return false;
        }

        // Check if worker has available slots
        if worker.available_slots().await == 0 {
            debug!(worker_id = %worker_id, "Worker has no available slots");
            return false;
        }

        // Check idle state via telemetry
        if let Some(telemetry) = self.telemetry.latest(worker_id.as_str()) {
            let cpu_pct = telemetry.telemetry.cpu.overall_percent;
            if cpu_pct > self.config.idle_cpu_threshold {
                debug!(
                    worker_id = %worker_id,
                    cpu_pct = cpu_pct,
                    threshold = self.config.idle_cpu_threshold,
                    "Worker not idle enough for benchmark"
                );
                return false;
            }
        }

        true
    }

    /// Process the pending queue and start benchmarks.
    pub async fn process_pending_queue(&self) {
        // Check concurrent limit
        let running_count = self.running.read().await.len();
        if running_count >= self.config.max_concurrent {
            debug!(
                running = running_count,
                max = self.config.max_concurrent,
                "At max concurrent benchmarks"
            );
            return;
        }

        let slots_available = self.config.max_concurrent - running_count;

        for _ in 0..slots_available {
            // Get next request
            let request = {
                let mut queue = self.pending_queue.lock().await;
                if queue.is_empty() {
                    break;
                }

                // Find first eligible worker
                let mut eligible_idx = None;
                for (idx, req) in queue.iter().enumerate() {
                    if self.is_worker_eligible(&req.worker_id).await {
                        eligible_idx = Some(idx);
                        break;
                    }
                }

                match eligible_idx {
                    Some(idx) => queue.remove(idx),
                    None => break, // No eligible workers found
                }
            };

            if let Some(request) = request {
                self.start_benchmark(request).await;
            }
        }
    }

    /// Handle a manual benchmark trigger.
    pub async fn handle_manual_trigger(&self, trigger: BenchmarkTrigger) {
        info!(
            worker_id = %trigger.worker_id,
            user = ?trigger.user,
            request_id = %trigger.request_id,
            "Received manual benchmark trigger"
        );

        // Create high-priority request
        let mut request = ScheduledBenchmarkRequest::new(
            trigger.worker_id,
            BenchmarkPriority::High,
            BenchmarkReason::ManualTrigger { user: trigger.user },
        );
        request.request_id = trigger.request_id;

        // Skip if already pending/running
        if self.is_pending_or_running(&request.worker_id).await {
            warn!(
                worker_id = %request.worker_id,
                "Worker already has pending or running benchmark"
            );
            return;
        }

        self.enqueue(request).await;
    }

    /// Start a benchmark for a worker.
    async fn start_benchmark(&self, request: ScheduledBenchmarkRequest) {
        let worker_id = request.worker_id.clone();
        let request_id = request.request_id.clone();

        info!(
            worker_id = %worker_id,
            request_id = %request_id,
            reason = %request.reason,
            "Starting benchmark"
        );

        // Reserve a slot on the worker
        if let Some(worker) = self.pool.get(&worker_id).await {
            if !worker.reserve_slots(1).await {
                warn!(worker_id = %worker_id, "Failed to reserve slot for benchmark");
                // Re-queue the request
                self.enqueue(request).await;
                return;
            }
        }

        // Track as running
        let running = RunningBenchmark {
            request: request.clone(),
            started_at: Utc::now(),
        };
        self.running
            .write()
            .await
            .insert(worker_id.clone(), running);

        // Emit started event
        self.events.emit(
            "benchmark:started",
            &serde_json::json!({
                "request_id": request_id,
                "worker_id": worker_id.as_str(),
                "reason": request.reason.to_string(),
            }),
        );

        // TODO: Spawn actual benchmark execution task
        // For now, just mark as running - actual execution will be added
        // when rch-benchmark remote execution is implemented
        debug!(
            worker_id = %worker_id,
            "Benchmark execution placeholder - awaiting rch-benchmark integration"
        );
    }

    /// Mark a benchmark as completed.
    pub async fn mark_completed(&self, worker_id: &WorkerId, score: f64, duration: Duration) {
        let running = self.running.write().await.remove(worker_id);

        if let Some(running) = running {
            info!(
                worker_id = %worker_id,
                request_id = %running.request.request_id,
                score = score,
                duration_ms = duration.as_millis(),
                "Benchmark completed"
            );

            // Release slot
            self.pool.release_slots(worker_id, 1).await;

            // Emit completed event
            self.events.emit(
                "benchmark:completed",
                &serde_json::json!({
                    "request_id": running.request.request_id,
                    "worker_id": worker_id.as_str(),
                    "score": score,
                    "duration_ms": duration.as_millis(),
                }),
            );
        }
    }

    /// Mark a benchmark as failed.
    pub async fn mark_failed(&self, worker_id: &WorkerId, error: &str, retryable: bool) {
        let running = self.running.write().await.remove(worker_id);

        if let Some(running) = running {
            warn!(
                worker_id = %worker_id,
                request_id = %running.request.request_id,
                error = error,
                retryable = retryable,
                "Benchmark failed"
            );

            // Release slot
            self.pool.release_slots(worker_id, 1).await;

            // Emit failed event
            self.events.emit(
                "benchmark:failed",
                &serde_json::json!({
                    "request_id": running.request.request_id,
                    "worker_id": worker_id.as_str(),
                    "error": error,
                    "retryable": retryable,
                }),
            );

            // Re-queue if retryable (with lower priority)
            if retryable {
                let mut request = running.request;
                request.priority = BenchmarkPriority::Low;
                request.requested_at = Utc::now(); // Reset timestamp
                self.enqueue(request).await;
            }
        }
    }

    /// Run the scheduler loop.
    ///
    /// This should be spawned as a background task.
    pub async fn run(self: Arc<Self>) {
        let mut check_interval = tokio::time::interval(self.config.check_interval);

        loop {
            tokio::select! {
                _ = check_interval.tick() => {
                    self.check_workers_for_scheduling().await;
                    self.process_pending_queue().await;
                }
                Some(trigger) = async {
                    self.trigger_rx.lock().await.recv().await
                } => {
                    self.handle_manual_trigger(trigger).await;
                    self.process_pending_queue().await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::EventBus;
    use rch_common::WorkerConfig;

    fn make_test_config() -> SchedulerConfig {
        SchedulerConfig {
            min_interval: Duration::from_secs(60), // 1 minute for testing
            max_age: Duration::from_secs(120),     // 2 minutes for testing
            idle_cpu_threshold: 50.0,
            max_concurrent: 2,
            drift_threshold_pct: 20.0,
            benchmark_timeout: Duration::from_secs(30),
            check_interval: Duration::from_secs(1),
        }
    }

    fn make_worker_config(id: &str) -> WorkerConfig {
        WorkerConfig {
            id: WorkerId::new(id),
            host: "localhost".to_string(),
            user: "test".to_string(),
            identity_file: "~/.ssh/id_rsa".to_string(),
            total_slots: 4,
            priority: 100,
            tags: vec![],
        }
    }

    #[tokio::test]
    async fn test_enqueue_priority_ordering() {
        let pool = WorkerPool::new();
        let telemetry = Arc::new(TelemetryStore::new(Duration::from_secs(300), None));
        let events = EventBus::new(16);

        let (scheduler, _handle) =
            BenchmarkScheduler::new(make_test_config(), pool, telemetry, events);

        // Enqueue in wrong order (Low, High, Normal)
        scheduler
            .enqueue(ScheduledBenchmarkRequest::new(
                WorkerId::new("low"),
                BenchmarkPriority::Low,
                BenchmarkReason::Scheduled,
            ))
            .await;

        scheduler
            .enqueue(ScheduledBenchmarkRequest::new(
                WorkerId::new("high"),
                BenchmarkPriority::High,
                BenchmarkReason::NewWorker,
            ))
            .await;

        scheduler
            .enqueue(ScheduledBenchmarkRequest::new(
                WorkerId::new("normal"),
                BenchmarkPriority::Normal,
                BenchmarkReason::Scheduled,
            ))
            .await;

        // Check order: High > Normal > Low
        let queue = scheduler.pending_queue.lock().await;
        let ids: Vec<_> = queue.iter().map(|r| r.worker_id.as_str()).collect();
        assert_eq!(ids, vec!["high", "normal", "low"]);
    }

    #[tokio::test]
    async fn test_is_pending_or_running() {
        let pool = WorkerPool::new();
        let telemetry = Arc::new(TelemetryStore::new(Duration::from_secs(300), None));
        let events = EventBus::new(16);

        let (scheduler, _handle) =
            BenchmarkScheduler::new(make_test_config(), pool, telemetry, events);

        let worker_id = WorkerId::new("test-worker");

        // Initially not pending or running
        assert!(!scheduler.is_pending_or_running(&worker_id).await);

        // Enqueue
        scheduler
            .enqueue(ScheduledBenchmarkRequest::new(
                worker_id.clone(),
                BenchmarkPriority::Normal,
                BenchmarkReason::Scheduled,
            ))
            .await;

        // Now it's pending
        assert!(scheduler.is_pending_or_running(&worker_id).await);
    }

    #[tokio::test]
    async fn test_max_concurrent_limit() {
        let pool = WorkerPool::new();
        pool.add_worker(make_worker_config("w1")).await;
        pool.add_worker(make_worker_config("w2")).await;
        pool.add_worker(make_worker_config("w3")).await;

        let telemetry = Arc::new(TelemetryStore::new(Duration::from_secs(300), None));
        let events = EventBus::new(16);

        let mut config = make_test_config();
        config.max_concurrent = 2;

        let (scheduler, _handle) = BenchmarkScheduler::new(config, pool, telemetry, events);

        // Manually add two running benchmarks
        {
            let mut running = scheduler.running.write().await;
            running.insert(WorkerId::new("w1"), RunningBenchmark {
                request: ScheduledBenchmarkRequest::new(
                    WorkerId::new("w1"),
                    BenchmarkPriority::Normal,
                    BenchmarkReason::Scheduled,
                ),
                started_at: Utc::now(),
            });
            running.insert(WorkerId::new("w2"), RunningBenchmark {
                request: ScheduledBenchmarkRequest::new(
                    WorkerId::new("w2"),
                    BenchmarkPriority::Normal,
                    BenchmarkReason::Scheduled,
                ),
                started_at: Utc::now(),
            });
        }

        // Enqueue another
        scheduler
            .enqueue(ScheduledBenchmarkRequest::new(
                WorkerId::new("w3"),
                BenchmarkPriority::Normal,
                BenchmarkReason::Scheduled,
            ))
            .await;

        // Process should not start w3 (at max concurrent)
        let running_before = scheduler.running_count().await;
        scheduler.process_pending_queue().await;
        let running_after = scheduler.running_count().await;

        assert_eq!(running_before, 2);
        assert_eq!(running_after, 2);
        assert_eq!(scheduler.pending_count().await, 1);
    }

    #[tokio::test]
    async fn test_benchmark_reason_display() {
        assert_eq!(BenchmarkReason::NewWorker.to_string(), "new_worker");
        assert_eq!(
            BenchmarkReason::StaleScore {
                age: ChronoDuration::hours(25)
            }
            .to_string(),
            "stale_score(25h)"
        );
        assert_eq!(
            BenchmarkReason::ManualTrigger {
                user: Some("admin".to_string())
            }
            .to_string(),
            "manual(admin)"
        );
        assert_eq!(
            BenchmarkReason::ManualTrigger { user: None }.to_string(),
            "manual(api)"
        );
        assert_eq!(
            BenchmarkReason::DriftDetected { drift_pct: 25.5 }.to_string(),
            "drift(25.5%)"
        );
        assert_eq!(BenchmarkReason::Scheduled.to_string(), "scheduled");
    }

    #[tokio::test]
    async fn test_priority_ordering() {
        // Verify enum ordering
        assert!(BenchmarkPriority::High > BenchmarkPriority::Normal);
        assert!(BenchmarkPriority::Normal > BenchmarkPriority::Low);
    }

    #[tokio::test]
    async fn test_manual_trigger_creates_high_priority() {
        let pool = WorkerPool::new();
        pool.add_worker(make_worker_config("manual-test")).await;

        let telemetry = Arc::new(TelemetryStore::new(Duration::from_secs(300), None));
        let events = EventBus::new(16);

        let (scheduler, _handle) =
            BenchmarkScheduler::new(make_test_config(), pool, telemetry, events);

        scheduler
            .handle_manual_trigger(BenchmarkTrigger {
                worker_id: WorkerId::new("manual-test"),
                user: Some("test-user".to_string()),
                request_id: "manual-req-123".to_string(),
            })
            .await;

        let queue = scheduler.pending_queue.lock().await;
        assert_eq!(queue.len(), 1);
        assert_eq!(queue[0].priority, BenchmarkPriority::High);
        assert_eq!(queue[0].request_id, "manual-req-123");
        assert!(matches!(
            queue[0].reason,
            BenchmarkReason::ManualTrigger { .. }
        ));
    }

    #[tokio::test]
    async fn test_mark_completed_releases_slot() {
        let pool = WorkerPool::new();
        pool.add_worker(make_worker_config("complete-test")).await;

        let telemetry = Arc::new(TelemetryStore::new(Duration::from_secs(300), None));
        let events = EventBus::new(16);

        let (scheduler, _handle) =
            BenchmarkScheduler::new(make_test_config(), pool.clone(), telemetry, events);

        let worker_id = WorkerId::new("complete-test");

        // Simulate a running benchmark
        {
            let mut running = scheduler.running.write().await;
            running.insert(worker_id.clone(), RunningBenchmark {
                request: ScheduledBenchmarkRequest::new(
                    worker_id.clone(),
                    BenchmarkPriority::Normal,
                    BenchmarkReason::Scheduled,
                ),
                started_at: Utc::now(),
            });
        }

        // Reserve a slot on the worker
        if let Some(worker) = pool.get(&worker_id).await {
            worker.reserve_slots(1).await;
            assert_eq!(worker.available_slots().await, 3);
        }

        // Mark completed
        scheduler
            .mark_completed(&worker_id, 75.0, Duration::from_secs(30))
            .await;

        // Check running is empty
        assert_eq!(scheduler.running_count().await, 0);

        // Check slot was released
        if let Some(worker) = pool.get(&worker_id).await {
            assert_eq!(worker.available_slots().await, 4);
        }
    }

    #[tokio::test]
    async fn test_mark_failed_retryable_requeues() {
        let pool = WorkerPool::new();
        pool.add_worker(make_worker_config("fail-test")).await;

        let telemetry = Arc::new(TelemetryStore::new(Duration::from_secs(300), None));
        let events = EventBus::new(16);

        let (scheduler, _handle) =
            BenchmarkScheduler::new(make_test_config(), pool.clone(), telemetry, events);

        let worker_id = WorkerId::new("fail-test");

        // Simulate a running benchmark
        {
            let mut running = scheduler.running.write().await;
            running.insert(worker_id.clone(), RunningBenchmark {
                request: ScheduledBenchmarkRequest::new(
                    worker_id.clone(),
                    BenchmarkPriority::High, // Started as high priority
                    BenchmarkReason::NewWorker,
                ),
                started_at: Utc::now(),
            });
        }

        // Reserve a slot
        if let Some(worker) = pool.get(&worker_id).await {
            worker.reserve_slots(1).await;
        }

        // Mark failed with retryable
        scheduler
            .mark_failed(&worker_id, "SSH connection failed", true)
            .await;

        // Check it was re-queued with Low priority
        let queue = scheduler.pending_queue.lock().await;
        assert_eq!(queue.len(), 1);
        assert_eq!(queue[0].priority, BenchmarkPriority::Low); // Downgraded
    }

    #[tokio::test]
    async fn test_mark_failed_not_retryable() {
        let pool = WorkerPool::new();
        pool.add_worker(make_worker_config("fail-test-2")).await;

        let telemetry = Arc::new(TelemetryStore::new(Duration::from_secs(300), None));
        let events = EventBus::new(16);

        let (scheduler, _handle) =
            BenchmarkScheduler::new(make_test_config(), pool.clone(), telemetry, events);

        let worker_id = WorkerId::new("fail-test-2");

        // Simulate a running benchmark
        {
            let mut running = scheduler.running.write().await;
            running.insert(worker_id.clone(), RunningBenchmark {
                request: ScheduledBenchmarkRequest::new(
                    worker_id.clone(),
                    BenchmarkPriority::Normal,
                    BenchmarkReason::Scheduled,
                ),
                started_at: Utc::now(),
            });
        }

        // Reserve a slot
        if let Some(worker) = pool.get(&worker_id).await {
            worker.reserve_slots(1).await;
        }

        // Mark failed without retry
        scheduler
            .mark_failed(&worker_id, "Worker removed", false)
            .await;

        // Check it was NOT re-queued
        assert_eq!(scheduler.pending_count().await, 0);
    }
}
