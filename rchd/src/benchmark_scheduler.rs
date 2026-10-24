//! Benchmark scheduling and orchestration.
//!
//! This module provides intelligent scheduling for worker benchmarks, balancing
//! measurement freshness against system load impact.
//!
//! ## Scheduling Triggers
//! - New workers: queue on detection, run once fresh telemetry permits it
//! - Stale scores: re-benchmark if telemetry suggests performance change
//! - Drift detection: re-benchmark if telemetry suggests performance change
//! - Manual triggers: user-initiated benchmarks via API

#![allow(dead_code)] // Scaffold code - will be wired into main.rs in future beads

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use rch_common::{WorkerCapabilities, WorkerId};
use rch_telemetry::protocol::ReceivedTelemetry;
use rch_telemetry::speedscore::SpeedScore;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, RwLock, mpsc};
use tracing::{debug, info, warn};

use crate::disk_pressure::{DiskPressurePolicyConfig, PressureState, evaluate_pressure_policy};
use crate::events::EventBus;
use crate::telemetry::TelemetryStore;
use crate::workers::{WorkerPool, WorkerState};

/// Priority levels for benchmark requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum BenchmarkPriority {
    /// Low priority - drift detection, speculative re-benchmark.
    Low = 0,
    /// Normal priority - scheduled re-benchmark due to age.
    #[default]
    Normal = 1,
    /// High priority - new workers, manual triggers.
    High = 2,
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
    /// Number of consecutive failures before emitting an alert.
    pub consecutive_failure_alert_threshold: u32,
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
            consecutive_failure_alert_threshold: 3,         // Alert after 3 consecutive failures
        }
    }
}

fn benchmark_telemetry_allows_start(
    capabilities: &WorkerCapabilities,
    telemetry: Option<&ReceivedTelemetry>,
    idle_cpu_threshold: f64,
) -> bool {
    let Some(telemetry) = telemetry else {
        return false;
    };
    let cpu = telemetry.telemetry.cpu.overall_percent;
    let memory = telemetry.telemetry.memory.pressure_score;
    if !cpu.is_finite()
        || !(0.0..=idle_cpu_threshold).contains(&cpu)
        || !memory.is_finite()
        || !(0.0..=100.0).contains(&memory)
    {
        return false;
    }
    // Re-evaluate the existing pressure policy against the current receipt:
    // a cached healthy assessment can outlive its telemetry. Optional
    // benchmarks must wait when ordinary dispatch would report a telemetry gap.
    let pressure = evaluate_pressure_policy(
        capabilities,
        Some(telemetry),
        &DiskPressurePolicyConfig::configured(),
    );
    pressure.telemetry_fresh
        && matches!(
            pressure.state,
            PressureState::Healthy | PressureState::Warning
        )
}

fn normalized_event_score(score: f64) -> f64 {
    if score.is_finite() {
        score.clamp(0.0, 100.0)
    } else {
        0.0
    }
}

/// Only comparable, finite measurements may enter live worker selection.
/// Legacy values remain readable in history, but are not current calibration.
fn selection_speedscore(score: &SpeedScore) -> Option<f64> {
    let components = [
        score.total,
        score.cpu_score,
        score.memory_score,
        score.disk_score,
        score.network_score,
        score.compilation_score,
    ];
    (!score.is_outdated()
        && score.weights.is_valid()
        && components
            .iter()
            .all(|value| value.is_finite() && (0.0..=100.0).contains(value)))
    .then_some(score.total)
}

fn benchmark_score_view(score: &SpeedScore) -> serde_json::Value {
    serde_json::json!({
        "total": score.total,
        "cpu_score": score.cpu_score,
        "memory_score": score.memory_score,
        "disk_score": score.disk_score,
        "network_score": score.network_score,
        "compilation_score": score.compilation_score,
        "measured_at": score.calculated_at.to_rfc3339(),
        "version": score.version,
    })
}

/// Build a diagnostic [`SpeedScore`] from a bare total (legacy/scalar sources).
///
/// A scalar has no algorithm or measurement provenance. Never stamp it with
/// the daemon's current version: that would silently relabel an old worker's
/// saturated score as a newly calibrated result.
fn speedscore_from_total(score: f64, measured_at: DateTime<Utc>) -> SpeedScore {
    let score = normalized_event_score(score);
    SpeedScore {
        total: score,
        compilation_score: score,
        calculated_at: measured_at,
        version: 0,
        ..SpeedScore::default()
    }
}

/// Persist a completed benchmark's score and hydrate live selection state.
///
/// This is the single write path for benchmark results (issue #40): it stores
/// the score through `TelemetryStore::record_speedscore` so `should_benchmark`
/// stops classifying the worker as `NewWorker`, and pushes a comparable total
/// into live selection. Unknown calibration uses the normal neutral default.
/// Persistence failures are surfaced as warnings but never fail the benchmark.
async fn commit_benchmark_score(
    telemetry: &TelemetryStore,
    pool: &WorkerPool,
    worker_id: &WorkerId,
    score: &SpeedScore,
) {
    if let Some(worker) = pool.get(worker_id).await {
        worker.set_speed_score(selection_speedscore(score).unwrap_or(50.0));
    }
    if let Err(error) = telemetry
        .record_speedscore(worker_id.as_str(), score.clone())
        .await
    {
        warn!(
            worker_id = %worker_id,
            error = %error,
            "Benchmark succeeded but SpeedScore persistence failed; worker will re-benchmark"
        );
    }
}

fn benchmark_queued_event_data(request: &ScheduledBenchmarkRequest) -> serde_json::Value {
    serde_json::json!({
        "request_id": request.request_id.as_str(),
        "worker_id": request.worker_id.as_str(),
        "queued_at": request.requested_at.to_rfc3339(),
        "priority": format!("{:?}", request.priority),
        "reason": request.reason.to_string(),
    })
}

fn benchmark_started_event_data(request: &ScheduledBenchmarkRequest) -> serde_json::Value {
    serde_json::json!({
        "request_id": request.request_id.as_str(),
        "job_id": request.request_id.as_str(),
        "worker_id": request.worker_id.as_str(),
        "reason": request.reason.to_string(),
    })
}

fn benchmark_completed_event_data(
    request_id: &str,
    worker_id: &WorkerId,
    score: &SpeedScore,
    duration: Duration,
) -> serde_json::Value {
    serde_json::json!({
        "request_id": request_id,
        "job_id": request_id,
        "worker_id": worker_id.as_str(),
        "speedscore": benchmark_score_view(score),
        "duration_secs": duration.as_secs_f64(),
        "success": true,
    })
}

fn benchmark_failed_event_data(
    request_id: &str,
    worker_id: &WorkerId,
    error: &str,
    retryable: bool,
    consecutive_failures: u32,
) -> serde_json::Value {
    serde_json::json!({
        "request_id": request_id,
        "job_id": request_id,
        "worker_id": worker_id.as_str(),
        "error": error,
        "retryable": retryable,
        "consecutive_failures": consecutive_failures,
    })
}

/// Benchmark scheduler that orchestrates when and how benchmarks run.
pub struct BenchmarkScheduler {
    /// Scheduler configuration.
    config: SchedulerConfig,

    /// Priority queue of pending benchmark requests.
    /// Ordered by priority (High > Normal > Low), then by requested_at.
    pending_queue: Arc<Mutex<VecDeque<ScheduledBenchmarkRequest>>>,

    /// Currently running benchmarks.
    running: Arc<RwLock<HashMap<WorkerId, RunningBenchmark>>>,

    /// Channel receiver for manual triggers.
    trigger_rx: Mutex<mpsc::Receiver<BenchmarkTrigger>>,

    /// Worker pool reference.
    pool: WorkerPool,

    /// Telemetry store for idle detection.
    telemetry: Arc<TelemetryStore>,

    /// Event bus for notifications.
    events: EventBus,

    /// Consecutive failure count per worker for alerting.
    consecutive_failures: Arc<RwLock<HashMap<WorkerId, u32>>>,

    /// When each worker's latest consecutive failure happened (backoff).
    last_failure: Arc<RwLock<HashMap<WorkerId, std::time::Instant>>>,
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
            pending_queue: Arc::new(Mutex::new(VecDeque::new())),
            running: Arc::new(RwLock::new(HashMap::new())),
            trigger_rx: Mutex::new(rx),
            pool,
            telemetry,
            events,
            consecutive_failures: Arc::new(RwLock::new(HashMap::new())),
            last_failure: Arc::new(RwLock::new(HashMap::new())),
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
        self.events
            .emit("benchmark_queued", &benchmark_queued_event_data(&request));
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

    /// Time left before a worker at or past the failure threshold may be
    /// benchmarked again on schedule, or `None` when it is free to run.
    async fn failure_backoff_remaining(&self, worker_id: &WorkerId) -> Option<Duration> {
        let failures = *self.consecutive_failures.read().await.get(worker_id)?;
        let last = *self.last_failure.read().await.get(worker_id)?;
        failure_backoff(
            failures,
            self.config.consecutive_failure_alert_threshold,
            self.config.min_interval,
        )?
        .checked_sub(last.elapsed())
        .filter(|remaining| !remaining.is_zero())
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

        // A worker that keeps failing (a benchmark that always times out)
        // would otherwise be rescheduled as new/stale on every check.
        if let Some(remaining) = self.failure_backoff_remaining(&worker_id).await {
            debug!(worker_id = %worker_id, remaining_secs = remaining.as_secs(), "Benchmark in failure backoff");
            return None;
        }

        // Try to get current SpeedScore
        let speedscore = self
            .telemetry
            .latest_speedscore(worker_id.as_str())
            .await
            .ok()?;

        // New worker without score?
        let Some(score) = speedscore else {
            debug!(worker_id = %worker_id, "New worker without SpeedScore");
            return Some(ScheduledBenchmarkRequest::new(
                worker_id,
                BenchmarkPriority::High,
                BenchmarkReason::NewWorker,
            ));
        };

        let age = Utc::now() - score.calculated_at;
        let age_duration = age.to_std().unwrap_or_default();

        // Never hydrate a cached value from another calibration into placement.
        // A persisted, versioned old score gets one prompt upgrade benchmark.
        // Scalar-only reports are explicitly version 0 and must wait out the
        // minimum interval, otherwise an old worker would benchmark forever.
        let Some(comparable_total) = selection_speedscore(&score) else {
            worker.set_speed_score(50.0);
            if score.version == 0 && age_duration < self.config.min_interval {
                return None;
            }
            debug!(
                worker_id = %worker_id,
                version = score.version,
                "SpeedScore is not comparable; scheduling fresh measurements"
            );
            return Some(ScheduledBenchmarkRequest::new(
                worker_id,
                BenchmarkPriority::High,
                BenchmarkReason::StaleScore { age },
            ));
        };

        // After a daemon restart WorkerState boots with the default 50.0;
        // only a compatible persisted measurement is authoritative.
        worker.set_speed_score(comparable_total);

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
    ///
    /// Returns `Some(drift_pct)` if conditions have worsened enough since the benchmark
    /// was taken that the score may be too optimistic. Returns `None` if:
    /// - No benchmark conditions were recorded (legacy scores)
    /// - No current telemetry is available
    /// - Conditions have improved or stayed within the threshold
    ///
    /// Only flags drift when conditions have **worsened** (higher load now than at
    /// benchmark time). If the benchmark was taken under high load and conditions
    /// have since improved, the score is conservative — no re-benchmark needed.
    async fn detect_drift(
        &self,
        worker: &WorkerState,
        score: &rch_telemetry::speedscore::SpeedScore,
    ) -> Option<f64> {
        // Need recorded benchmark conditions to compare against
        let conditions = score.benchmark_conditions.as_ref()?;

        // Need current telemetry for the worker
        let endpoint = worker.endpoint_snapshot().await;
        let current = self.telemetry.latest_for_endpoint(&endpoint)?;
        let current_cpu = current.telemetry.cpu.overall_percent;
        let current_mem = current.telemetry.memory.used_percent;
        let current_load = current.telemetry.cpu.load_average.one_min;

        // Calculate per-metric drift (positive = conditions worsened)
        // CPU: higher utilization now means score may be too optimistic
        let cpu_drift = current_cpu - conditions.cpu_percent;
        // Memory: higher usage now means more pressure
        let mem_drift = current_mem - conditions.memory_used_percent;
        // Load: higher load average means more contention
        let load_drift = if conditions.load_1m > 0.01 {
            ((current_load - conditions.load_1m) / conditions.load_1m) * 100.0
        } else if current_load > 1.0 {
            // Benchmark was at ~zero load, now significant load — flag it
            100.0
        } else {
            // Both near zero — no drift
            0.0
        };

        // Weighted composite: CPU matters most for compilation workloads
        let composite_drift = cpu_drift * 0.5 + mem_drift * 0.2 + load_drift * 0.3;

        // Only trigger if conditions have WORSENED past the threshold.
        // Negative drift (conditions improved) is never flagged.
        if composite_drift >= self.config.drift_threshold_pct {
            debug!(
                worker_id = %endpoint.config.id,
                cpu_drift = format!("{:.1}", cpu_drift),
                mem_drift = format!("{:.1}", mem_drift),
                load_drift = format!("{:.1}", load_drift),
                composite = format!("{:.1}", composite_drift),
                threshold = self.config.drift_threshold_pct,
                "Drift detected: conditions worsened since benchmark"
            );
            Some(composite_drift)
        } else {
            None
        }
    }

    /// Check if a worker is eligible for benchmarking (idle and healthy).
    pub async fn is_worker_eligible(&self, worker_id: &WorkerId) -> bool {
        // Get worker
        let Some(worker) = self.pool.get(worker_id).await else {
            return false;
        };
        let endpoint = worker.endpoint_snapshot().await;

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

        let Some(_endpoint_guard) = worker.lock_current_endpoint(&endpoint).await else {
            return false;
        };
        let capabilities = worker.capabilities().await;
        let telemetry = self.telemetry.latest_for_endpoint(&endpoint);
        if !benchmark_telemetry_allows_start(
            &capabilities,
            telemetry.as_ref(),
            self.config.idle_cpu_threshold,
        ) {
            debug!(
                worker_id = %worker_id,
                "Benchmark waiting for fresh, idle telemetry and safe resource pressure"
            );
            return false;
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
            // Get candidate worker IDs to check without holding the lock during the check
            let candidates = {
                let queue = self.pending_queue.lock().await;
                if queue.is_empty() {
                    break;
                }
                queue
                    .iter()
                    .map(|req| req.worker_id.clone())
                    .collect::<Vec<_>>()
            };

            let mut eligible_worker_id = None;
            for worker_id in candidates {
                if self.is_worker_eligible(&worker_id).await {
                    eligible_worker_id = Some(worker_id);
                    break;
                }
            }

            // Get next request
            let request = {
                let mut queue = self.pending_queue.lock().await;
                if let Some(worker_id) = eligible_worker_id {
                    // Find it again, in case it moved or was removed
                    queue
                        .iter()
                        .position(|r| r.worker_id == worker_id)
                        .map(|idx| queue.remove(idx).unwrap())
                } else {
                    break; // No eligible workers found
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

        // Queue inspection can yield before dispatch. Keep a request pending
        // if its worker became busy, unhealthy, or stale in that interval.
        if !self.is_worker_eligible(&worker_id).await {
            self.enqueue(request).await;
            return;
        }

        info!(
            worker_id = %worker_id,
            request_id = %request_id,
            reason = %request.reason,
            "Starting benchmark"
        );

        // Reserve a slot on the worker
        let worker_opt = self.pool.get(&worker_id).await;
        let Some(worker) = worker_opt else {
            warn!(worker_id = %worker_id, "Worker not found for benchmark");
            return;
        };

        if !worker.reserve_slots(1).await {
            warn!(worker_id = %worker_id, "Failed to reserve slot for benchmark");
            // Re-queue the request
            self.enqueue(request).await;
            return;
        }

        // Get worker config for SSH connection
        let worker_config = worker.config.read().await.clone();

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
        self.events
            .emit("benchmark_started", &benchmark_started_event_data(&request));

        // Spawn benchmark execution task
        let pool = self.pool.clone();
        let events = self.events.clone();
        let timeout = self.config.benchmark_timeout;
        let consecutive_failures = self.consecutive_failures.clone();
        let last_failure = self.last_failure.clone();
        let running_map = self.running.clone();
        let pending_queue = self.pending_queue.clone();
        let alert_threshold = self.config.consecutive_failure_alert_threshold;
        let telemetry = self.telemetry.clone();

        tokio::spawn(async move {
            let start_time = std::time::Instant::now();
            let result = execute_benchmark_on_worker(&worker_config, timeout).await;
            let duration = start_time.elapsed();

            match result {
                Ok((score, _exec_duration)) => {
                    info!(
                        worker_id = %worker_id,
                        request_id = %request_id,
                        score = score.total,
                        duration_ms = duration.as_millis(),
                        "Benchmark completed successfully"
                    );

                    // Persist the score and hydrate live selection state BEFORE
                    // emitting completion, so the next scheduler pass observes
                    // the persisted score and does not re-enqueue the worker as
                    // NewWorker (issue #40).
                    commit_benchmark_score(&telemetry, &pool, &worker_id, &score).await;

                    // Remove from running
                    running_map.write().await.remove(&worker_id);

                    // Release slot
                    pool.release_slots(&worker_id, 1).await;

                    // Reset consecutive failure counter on success
                    consecutive_failures.write().await.remove(&worker_id);
                    last_failure.write().await.remove(&worker_id);

                    // Emit completed event
                    events.emit(
                        "benchmark_completed",
                        &benchmark_completed_event_data(&request_id, &worker_id, &score, duration),
                    );
                }
                Err(e) => {
                    let error_msg = e.to_string();
                    let retryable = is_retryable_error(&error_msg);

                    warn!(
                        worker_id = %worker_id,
                        request_id = %request_id,
                        error = %error_msg,
                        retryable = retryable,
                        "Benchmark failed"
                    );

                    // Remove from running
                    let running = running_map.write().await.remove(&worker_id);

                    // Release slot
                    pool.release_slots(&worker_id, 1).await;

                    // Track consecutive failures
                    let consecutive_count = {
                        let mut failures = consecutive_failures.write().await;
                        let count = failures.entry(worker_id.clone()).or_insert(0);
                        *count += 1;
                        *count
                    };
                    last_failure
                        .write()
                        .await
                        .insert(worker_id.clone(), std::time::Instant::now());

                    // Emit failed event
                    events.emit(
                        "benchmark_failed",
                        &benchmark_failed_event_data(
                            &request_id,
                            &worker_id,
                            &error_msg,
                            retryable,
                            consecutive_count,
                        ),
                    );

                    // Emit alert if threshold exceeded
                    if consecutive_count >= alert_threshold {
                        warn!(
                            worker_id = %worker_id,
                            consecutive_failures = consecutive_count,
                            threshold = alert_threshold,
                            "Worker benchmark repeatedly failing - alerting"
                        );
                        events.emit(
                            "benchmark_alert_repeated_failures",
                            &serde_json::json!({
                                "worker_id": worker_id.as_str(),
                                "consecutive_failures": consecutive_count,
                                "threshold": alert_threshold,
                                "last_error": error_msg,
                            }),
                        );
                    }

                    // Re-queue if retryable
                    if should_requeue_failed_benchmark(
                        retryable,
                        consecutive_count,
                        alert_threshold,
                    ) && let Some(running) = running
                    {
                        let mut req = running.request;
                        req.priority = BenchmarkPriority::Low;
                        req.requested_at = Utc::now();

                        let mut queue = pending_queue.lock().await;
                        queue.push_back(req);
                    }
                }
            }
        });
    }

    /// Mark a benchmark as completed.
    pub async fn mark_completed(&self, worker_id: &WorkerId, score: f64, duration: Duration) {
        let running = self.running.write().await.remove(worker_id);

        if let Some(running) = running {
            let score = speedscore_from_total(score, Utc::now());

            info!(
                worker_id = %worker_id,
                request_id = %running.request.request_id,
                score = score.total,
                duration_ms = duration.as_millis(),
                "Benchmark completed"
            );

            // Persist through the same single write path as the scheduler's
            // own execution task (issue #40).
            commit_benchmark_score(&self.telemetry, &self.pool, worker_id, &score).await;

            // Release slot
            self.pool.release_slots(worker_id, 1).await;

            // Credit the worker's circuit breaker: a completed benchmark is a
            // successful round-trip to the worker, so it should count toward
            // closing/keeping-closed the authoritative WorkerState.circuit that
            // selection reads (the circuit is otherwise only advanced by the
            // health monitor). Without this, benchmark success touched neither
            // circuit store — a documented gap in the unification.
            if let Some(worker) = self.pool.get(worker_id).await {
                worker.record_success().await;
            }

            // Reset consecutive failure counter on success
            self.consecutive_failures.write().await.remove(worker_id);
            self.last_failure.write().await.remove(worker_id);

            // Emit completed event
            self.events.emit(
                "benchmark_completed",
                &benchmark_completed_event_data(
                    &running.request.request_id,
                    worker_id,
                    &score,
                    duration,
                ),
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

            // Track consecutive failures and check for alert threshold
            let consecutive_count = {
                let mut failures = self.consecutive_failures.write().await;
                let count = failures.entry(worker_id.clone()).or_insert(0);
                *count += 1;
                *count
            };
            self.last_failure
                .write()
                .await
                .insert(worker_id.clone(), std::time::Instant::now());

            // Emit failed event
            self.events.emit(
                "benchmark_failed",
                &benchmark_failed_event_data(
                    &running.request.request_id,
                    worker_id,
                    error,
                    retryable,
                    consecutive_count,
                ),
            );

            // Emit alert if consecutive failure threshold exceeded
            if consecutive_count >= self.config.consecutive_failure_alert_threshold {
                warn!(
                    worker_id = %worker_id,
                    consecutive_failures = consecutive_count,
                    threshold = self.config.consecutive_failure_alert_threshold,
                    "Worker benchmark repeatedly failing - alerting"
                );
                self.events.emit(
                    "benchmark_alert_repeated_failures",
                    &serde_json::json!({
                        "worker_id": worker_id.as_str(),
                        "consecutive_failures": consecutive_count,
                        "threshold": self.config.consecutive_failure_alert_threshold,
                        "last_error": error,
                    }),
                );
            }

            // Re-queue if retryable (with lower priority)
            if should_requeue_failed_benchmark(
                retryable,
                consecutive_count,
                self.config.consecutive_failure_alert_threshold,
            ) {
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

/// Execute a benchmark on a remote worker via SSH.
///
/// Runs `~/.local/bin/rch-wkr benchmark` on the worker and parses the score.
async fn execute_benchmark_on_worker(
    worker: &rch_common::WorkerConfig,
    timeout: Duration,
) -> anyhow::Result<(SpeedScore, Duration)> {
    let (command, input) = benchmark_ssh_command(worker, timeout);
    debug!(
        worker_id = %worker.id,
        host = %worker.host,
        "Executing benchmark via SSH"
    );
    execute_benchmark_process(command, input, timeout).await
}

fn benchmark_ssh_command(
    worker: &rch_common::WorkerConfig,
    timeout: Duration,
) -> (tokio::process::Command, Option<String>) {
    use tokio::process::Command;

    // Expand tilde in identity file path
    let identity_file = if worker.identity_file.starts_with("~/") {
        if let Ok(home) = std::env::var("HOME") {
            format!("{}{}", home, &worker.identity_file[1..])
        } else {
            worker.identity_file.clone()
        }
    } else {
        worker.identity_file.clone()
    };

    // Build SSH command to run benchmark on worker
    let mut cmd = Command::new("ssh");
    cmd.arg("-o").arg("BatchMode=yes");
    cmd.arg("-o").arg("StrictHostKeyChecking=accept-new");
    cmd.arg("-o")
        .arg(format!("ConnectTimeout={}", timeout.as_secs().min(30)));
    cmd.arg("-i").arg(&identity_file);
    if let Some(opts) = rch_common::ssh_utils::identities_only_args(&identity_file) {
        cmd.args(opts);
    }
    cmd.arg(format!("{}@{}", worker.user, worker.host));
    // Windows workers keep the plain call, matching the build path, which also
    // skips `timeout` there: depending on which `sh` the session resolves,
    // `timeout` can be System32's pause utility, which rejects `-k 10 N`.
    let script = if rch_common::types::declared_os(&worker.tags).as_deref() == Some("windows") {
        "~/.local/bin/rch-wkr benchmark --json".to_string()
    } else {
        remote_benchmark_script(timeout.as_secs().max(1))
    };
    let remote = rch_common::ssh::remote_shell_command(worker, &script);
    cmd.arg(remote.command);
    (cmd, remote.stdin_script)
}

/// The worker-side benchmark command, bounded on the worker itself.
///
/// On timeout the dispatcher kills its local `ssh`, but a non-interactive
/// session delivers no hangup, so the remote `rch-wkr benchmark` (a release
/// build) kept running as an orphan on an already saturated worker (hz3,
/// 2026-09-26). The worker enforces the same deadline where `timeout` exists
/// and falls back to the unbounded call elsewhere (e.g. macOS without coreutils).
fn remote_benchmark_script(timeout_secs: u64) -> String {
    format!(
        "if command -v timeout >/dev/null 2>&1; then \
exec timeout -k 10 {timeout_secs} ~/.local/bin/rch-wkr benchmark --json; \
else exec ~/.local/bin/rch-wkr benchmark --json; fi"
    )
}

/// Read one complete bounded stream. Reaching a `take` limit is not EOF:
/// reserve one extra byte to distinguish exact-bound output from truncation.
/// Returning an error lets try_join stop the other stream and reap the child.
async fn read_benchmark_stream(
    reader: impl tokio::io::AsyncRead + Unpin,
    bytes: &mut Vec<u8>,
    limit: u64,
) -> std::io::Result<()> {
    use tokio::io::AsyncReadExt;
    let probe_limit = limit.checked_add(1).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid benchmark output limit",
        )
    })?;
    reader.take(probe_limit).read_to_end(bytes).await?;
    if bytes.len() as u64 > limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "benchmark output exceeds byte limit",
        ));
    }
    Ok(())
}

async fn execute_benchmark_process(
    mut cmd: tokio::process::Command,
    input: Option<String>,
    timeout: Duration,
) -> anyhow::Result<(SpeedScore, Duration)> {
    let start = std::time::Instant::now();
    cmd.stdin(if input.is_some() {
        std::process::Stdio::piped()
    } else {
        std::process::Stdio::null()
    });
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    // Defense in depth: if the surrounding task is dropped mid-flight (e.g.
    // a panic, scheduler shutdown, or a parent select! losing the race),
    // the spawned ssh process should not outlive us. The explicit
    // `child.kill().await` calls below cover the timeout/IO error paths;
    // `kill_on_drop` covers the panic-unwind/cancellation paths.
    cmd.kill_on_drop(true);

    let mut child = cmd
        .spawn()
        .map_err(|e| anyhow::anyhow!("Failed to spawn SSH command: {}", e))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("Failed to capture stdout from SSH command"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow::anyhow!("Failed to capture stderr from SSH command"))?;
    let stdin = child.stdin.take();

    let mut stdout_buf = Vec::new();
    let mut stderr_buf = Vec::new();

    // Read with 1MB limit
    const MAX_BENCHMARK_OUTPUT: u64 = 1024 * 1024; // 1MB

    let read_future = async {
        let t1 = read_benchmark_stream(stdout, &mut stdout_buf, MAX_BENCHMARK_OUTPUT);
        let t2 = read_benchmark_stream(stderr, &mut stderr_buf, MAX_BENCHMARK_OUTPUT);
        let write_input = async {
            if let (Some(stdin), Some(input)) = (stdin, input) {
                rch_common::ssh::write_ssh_command_stdin(stdin, &input).await?;
            }
            Ok::<(), std::io::Error>(())
        };
        tokio::try_join!(t1, t2, write_input)
    };

    // Wait for output or timeout
    match tokio::time::timeout(timeout, read_future).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            let _ = child.kill().await;
            let _ = child.wait().await; // Prevent zombie
            return Err(anyhow::anyhow!("Failed to read benchmark output: {}", e));
        }
        Err(_) => {
            let _ = child.kill().await;
            let _ = child.wait().await; // Prevent zombie
            return Err(anyhow::anyhow!("Benchmark timed out after {:?}", timeout));
        }
    }

    let status = match tokio::time::timeout(Duration::from_secs(5), child.wait()).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            return Err(anyhow::anyhow!(
                "Failed to wait for benchmark process: {}",
                e
            ));
        }
        Err(_) => {
            let _ = child.kill().await;
            let _ = child.wait().await; // Prevent zombie
            return Err(anyhow::anyhow!(
                "Benchmark process hung after closing output"
            ));
        }
    };

    let exec_duration = start.elapsed();

    if !status.success() {
        let stderr_str = String::from_utf8_lossy(&stderr_buf);
        return Err(anyhow::anyhow!(
            "Benchmark command failed with status {}: {}",
            status,
            stderr_str.trim()
        ));
    }

    let stdout_str = std::str::from_utf8(&stdout_buf)
        .map_err(|error| anyhow::anyhow!("Benchmark output is not UTF-8: {error}"))?;
    if let Some(score) = parse_benchmark_output(stdout_str) {
        return Ok((score, exec_duration));
    }

    Err(anyhow::anyhow!(
        "Failed to parse benchmark score from output: {}",
        stdout_str.chars().take(200).collect::<String>()
    ))
}

/// Structured output must pass structured validation. Do not salvage a
/// misleading `score` number from a malformed JSON or invalid raw report.
fn parse_benchmark_output(output: &str) -> Option<SpeedScore> {
    let trimmed = output.trim_start();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        parse_benchmark_json(trimmed)
    } else {
        parse_benchmark_score(output).map(|score| speedscore_from_total(score, Utc::now()))
    }
}

/// Recalibrate the raw measurement fields emitted by deployed workers.
///
/// Older flat reports omit memory latency and all network measurements. Only
/// use memory when BOTH measured inputs exist; never infer missing latency
/// from a clipped component score. Current complete reports take the typed path.
fn recalibrate_worker_raw(raw: &serde_json::Value) -> Option<SpeedScore> {
    use rch_telemetry::benchmarks::{
        CompilationBenchmarkResult, CpuBenchmarkResult, DiskBenchmarkResult, MemoryBenchmarkResult,
    };
    use rch_telemetry::speedscore::BenchmarkResults;

    raw.as_object()?;
    let positive = |name: &str| {
        raw.get(name)
            .and_then(serde_json::Value::as_f64)
            .filter(|value| value.is_finite() && *value > 0.0)
    };
    let mut results = BenchmarkResults::new();
    if let Some(ops_per_second) = positive("cpu_ops_per_second") {
        results.cpu = Some(CpuBenchmarkResult {
            ops_per_second,
            ..CpuBenchmarkResult::default()
        });
    }
    if let (Some(seq_bandwidth_gbps), Some(random_latency_ns)) = (
        positive("memory_seq_bandwidth_gbps"),
        positive("memory_random_latency_ns"),
    ) {
        results.memory = Some(MemoryBenchmarkResult {
            seq_bandwidth_gbps,
            random_latency_ns,
            ..MemoryBenchmarkResult::default()
        });
    }
    if let (Some(seq_read_mbps), Some(seq_write_mbps), Some(random_read_iops)) = (
        positive("disk_seq_read_mbps"),
        positive("disk_seq_write_mbps"),
        positive("disk_random_read_iops"),
    ) {
        results.disk = Some(DiskBenchmarkResult {
            seq_read_mbps,
            seq_write_mbps,
            random_read_iops,
            ..DiskBenchmarkResult::default()
        });
    }
    if let Some(release_build_ms) = raw
        .get("compilation_release_build_ms")
        .and_then(serde_json::Value::as_u64)
        .filter(|milliseconds| *milliseconds > 0)
    {
        results.compilation = Some(CompilationBenchmarkResult {
            release_build_ms,
            ..CompilationBenchmarkResult::default()
        });
    }
    let score = SpeedScore::calculate(&results);
    selection_speedscore(&score).map(|_| score)
}

/// Parse `rch-wkr benchmark --json` output into a typed [`SpeedScore`].
///
/// Complete reports are authoritative and recalibrated from the original JSON
/// so duplicate report/measurement fields cannot collapse into valid evidence.
/// Older flat raw and scalar reports keep their existing, narrower semantics.
fn parse_benchmark_json(output: &str) -> Option<SpeedScore> {
    let json = serde_json::from_str::<serde_json::Value>(output).ok()?;
    if json.get("benchmark_report").is_some() {
        // Presence commits this response to the complete evidence contract.
        // Null, malformed or unsupported reports must not fall back to a
        // convenient legacy score or partial raw object in the same response.
        return rch_telemetry::benchmarks::report::BenchmarkReport::from_worker_json(output)
            .ok()?
            .recalculate()
            .ok();
    }
    if let Some(raw) = json.get("raw") {
        return recalibrate_worker_raw(raw);
    }
    let total = json.get("score").and_then(serde_json::Value::as_f64)?;

    let mut score = speedscore_from_total(total, Utc::now());
    if let Some(components) = json.get("components") {
        let component = |name: &str| {
            components
                .get(name)
                .and_then(serde_json::Value::as_f64)
                .map(normalized_event_score)
        };
        if let Some(v) = component("cpu") {
            score.cpu_score = v;
        }
        if let Some(v) = component("memory") {
            score.memory_score = v;
        }
        if let Some(v) = component("disk") {
            score.disk_score = v;
        }
        if let Some(v) = component("network") {
            score.network_score = v;
        }
        if let Some(v) = component("compilation") {
            score.compilation_score = v;
        }
    }
    Some(score)
}

#[cfg(test)]
mod complete_benchmark_report_tests {
    use super::*;
    use rch_telemetry::benchmarks::report::BenchmarkReport;
    use rch_telemetry::benchmarks::{
        CompilationBenchmarkResult, CpuBenchmarkResult, MemoryBenchmarkResult,
    };
    use rch_telemetry::speedscore::BenchmarkResults;

    const VALID: &str = r#"{"benchmark_report":{"version":1,"cpu":{"ops_per_second":250000}}}"#;

    #[test]
    fn complete_report_reaches_selection_without_losing_memory_or_compilation() {
        let results = BenchmarkResults::new()
            .with_cpu(CpuBenchmarkResult {
                ops_per_second: 250_000.0,
                ..Default::default()
            })
            .with_memory(MemoryBenchmarkResult {
                seq_bandwidth_gbps: 4.0,
                random_latency_ns: 25.0,
                ..Default::default()
            })
            .with_compilation(CompilationBenchmarkResult {
                score: 1500.0,
                ..Default::default()
            });
        let expected = SpeedScore::calculate(&results);
        let wire = serde_json::json!({
            "score": 100,
            "components": {"memory": 0, "compilation": 0},
            "raw": {"cpu_ops_per_second": 1},
            "benchmark_report": BenchmarkReport::from_results(&results),
        })
        .to_string();
        let actual = parse_benchmark_output(&wire).unwrap();
        assert_eq!(actual.total, expected.total);
        assert_eq!(actual.weights, expected.weights);
        assert_eq!(actual.memory_score, expected.memory_score);
        assert_eq!(actual.compilation_score, expected.compilation_score);
        assert!(actual.weights.memory > 0.0);
        assert!(actual.weights.compilation > 0.0);
        assert_eq!(actual.weights.network, 0.0);
        assert_eq!(selection_speedscore(&actual), Some(expected.total));
    }

    #[test]
    fn invalid_advertised_reports_cannot_fall_back_to_legacy_evidence() {
        for report in [
            "null",
            "{}",
            r#"{"version":1}"#,
            r#"{"version":2,"cpu":{"ops_per_second":250000}}"#,
            r#"{"version":1,"cpu":{"ops_per_second":0}}"#,
            r#"{"version":1,"memory":{"seq_bandwidth_gbps":4}}"#,
            r#"{"version":1,"cpu":{"ops_per_second":250000},"memory":{"seq_bandwidth_gbps":4,"random_latency_ns":0}}"#,
            r#"{"version":1,"cpu":{"ops_per_second":1,"ops_per_second":250000}}"#,
        ] {
            let wire = format!(
                r#"{{"score":99,"raw":{{"cpu_ops_per_second":250000}},"benchmark_report":{report}}}"#
            );
            assert!(parse_benchmark_output(&wire).is_none(), "{wire}");
        }
    }

    #[test]
    fn duplicate_top_level_reports_are_rejected_before_placement() {
        let wire = r#"{"score":99,"benchmark_report":{"version":1,"cpu":{"ops_per_second":1}},"benchmark_report":{"version":1,"cpu":{"ops_per_second":250000}}}"#;
        assert!(parse_benchmark_output(wire).is_none());
    }

    #[test]
    fn flat_reports_need_both_memory_inputs_and_never_invent_network() {
        let missing = r#"{"raw":{"cpu_ops_per_second":250000,"memory_seq_bandwidth_gbps":4}}"#;
        let score = parse_benchmark_output(missing).unwrap();
        assert_eq!(score.weights.cpu, 1.0);
        assert_eq!(score.weights.memory, 0.0);
        let complete = r#"{"raw":{"cpu_ops_per_second":250000,"memory_seq_bandwidth_gbps":4,"memory_random_latency_ns":100}}"#;
        let score = parse_benchmark_output(complete).unwrap();
        assert!(score.weights.memory > 0.0);
        assert_eq!(score.memory_score, 50.0);
        assert_eq!(score.weights.network, 0.0);
    }

    #[test]
    fn legacy_scalar_remains_unversioned_not_current_placement() {
        let score = parse_benchmark_output(r#"{"score":99}"#).unwrap();
        assert_eq!(score.version, 0);
        assert!(selection_speedscore(&score).is_none());
    }

    #[tokio::test]
    async fn stream_bound_requires_eof_and_rejects_a_valid_prefix() {
        let mut output = Vec::new();
        read_benchmark_stream(VALID.as_bytes(), &mut output, VALID.len() as u64)
            .await
            .unwrap();
        assert_eq!(output, VALID.as_bytes());
        let mut oversized = VALID.as_bytes().to_vec();
        oversized.push(b' ');
        let mut output = Vec::new();
        let error = read_benchmark_stream(oversized.as_slice(), &mut output, VALID.len() as u64)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn process_rejects_oversized_stdout_or_stderr_even_with_valid_json() {
        let directory = tempfile::tempdir().unwrap();
        let payload = directory.path().join("oversized");
        let mut bytes = VALID.as_bytes().to_vec();
        bytes.resize(1024 * 1024 + 1, b' ');
        std::fs::write(&payload, &bytes).unwrap();
        for script in ["exec cat \"$1\"", "printf '%s' \"$2\"; exec cat \"$1\" >&2"] {
            let mut command = tokio::process::Command::new("sh");
            command
                .args(["-c", script, "benchmark-output-test"])
                .arg(&payload)
                .arg(VALID);
            let error = execute_benchmark_process(command, None, Duration::from_secs(5))
                .await
                .unwrap_err()
                .to_string();
            assert!(error.contains("exceeds byte limit"), "{error}");
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn process_does_not_repair_invalid_utf8_into_accepted_json() {
        let directory = tempfile::tempdir().unwrap();
        let payload = directory.path().join("invalid-utf8");
        let mut bytes = VALID.as_bytes()[..VALID.len() - 1].to_vec();
        bytes.extend_from_slice(b",\"note\":\"\xff\"}");
        std::fs::write(&payload, &bytes).unwrap();
        // Lossy conversion makes this syntactically valid with a usable score;
        // the production transport must instead reject the original bytes.
        assert!(parse_benchmark_output(&String::from_utf8_lossy(&bytes)).is_some());
        let mut command = tokio::process::Command::new("sh");
        command
            .args(["-c", "exec cat \"$1\"", "benchmark-output-test"])
            .arg(&payload);
        let error = execute_benchmark_process(command, None, Duration::from_secs(5))
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("not UTF-8"), "{error}");
    }
}

/// Parse benchmark score from text output.
///
/// Looks for patterns like "Score: 123.45" or "score: 123.45".
fn parse_benchmark_score(output: &str) -> Option<f64> {
    for line in output.lines() {
        // Try "Score: X" pattern (case insensitive)
        let line_lower = line.to_lowercase();
        if let Some(rest) = line_lower.strip_prefix("score:")
            && let Ok(score) = rest.trim().parse::<f64>()
        {
            return Some(score);
        }

        // Try "score = X" pattern
        if let Some(rest) = line_lower.strip_prefix("score =")
            && let Ok(score) = rest.trim().parse::<f64>()
        {
            return Some(score);
        }

        // Try extracting from JSON-like "score": 123.45
        if line.contains("\"score\"") {
            // Simple extraction: find number after "score":
            if let Some(idx) = line.find("\"score\"") {
                // "score" is 7 chars, skip one more to get past any immediate colon
                let skip_to = idx + 8;
                if skip_to <= line.len() {
                    let after_key = &line[skip_to..];
                    let trimmed =
                        after_key.trim_start_matches(|c: char| c == ':' || c.is_whitespace());
                    // Extract the number portion
                    let num_str: String = trimmed
                        .chars()
                        .take_while(|c| c.is_ascii_digit() || *c == '.' || *c == '-')
                        .collect();
                    if let Ok(score) = num_str.parse::<f64>() {
                        return Some(score);
                    }
                }
            }
        }
    }
    None
}

/// Scheduled-benchmark backoff after repeated failures: 10 minutes at the
/// threshold, doubling per further failure, capped at `cap`.
fn failure_backoff(failures: u32, threshold: u32, cap: Duration) -> Option<Duration> {
    const BASE: Duration = Duration::from_secs(10 * 60);
    let beyond = failures.checked_sub(threshold.max(1))?;
    Some(BASE.saturating_mul(1_u32 << beyond.min(16)).min(cap))
}

/// An immediate retry is for a transient blip. A worker that keeps failing
/// (a benchmark that always times out on an overloaded box) must not be
/// re-benchmarked back to back forever: past the alert threshold it waits
/// for the regular schedule.
fn should_requeue_failed_benchmark(
    retryable: bool,
    consecutive_failures: u32,
    threshold: u32,
) -> bool {
    retryable && consecutive_failures < threshold.max(1)
}

/// Determine if a benchmark error is retryable.
fn is_retryable_error(error: &str) -> bool {
    let retryable_patterns = [
        "timed out",
        "timeout",
        "connection refused",
        "connection reset",
        "no route to host",
        "network unreachable",
        "temporary failure",
        "resource temporarily unavailable",
        "broken pipe",
        "ssh_exchange_identification",
        "connection closed by remote host",
    ];

    let error_lower = error.to_lowercase();
    retryable_patterns
        .iter()
        .any(|pattern| error_lower.contains(pattern))
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
            consecutive_failure_alert_threshold: 3,
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
            tools: Vec::new(),
        }
    }

    #[test]
    fn test_benchmark_ssh_command_keeps_posix_command_out_of_windows_argv() {
        for os in ["linux", "Windows"] {
            let mut worker = make_worker_config("worker-1");
            worker.tags = vec![rch_common::types::os_tag(os)];
            worker.identity_file = "/private/key with spaces".into();
            let (command, input) = benchmark_ssh_command(&worker, Duration::from_secs(300));
            let argv: Vec<_> = command.as_std().get_args().collect();
            assert_eq!(command.as_std().get_program(), "ssh");
            assert!(argv.contains(&std::ffi::OsStr::new("ConnectTimeout=30")));
            assert!(argv.contains(&std::ffi::OsStr::new("/private/key with spaces")));
            assert_eq!(argv[argv.len() - 2], "test@localhost");
            if os == "linux" {
                assert_eq!(
                    argv.last().copied(),
                    Some(std::ffi::OsStr::new(&remote_benchmark_script(300)))
                );
                assert!(
                    remote_benchmark_script(300)
                        .contains("timeout -k 10 300 ~/.local/bin/rch-wkr benchmark --json")
                );
                assert!(input.is_none());
            } else {
                assert_eq!(argv.last().copied(), Some(std::ffi::OsStr::new("sh -s")));
                assert!(
                    input
                        .as_deref()
                        .unwrap()
                        .contains("rch-wkr benchmark --json")
                );
                // Windows keeps the plain call: `timeout` may be System32's.
                assert!(!input.as_deref().unwrap().contains("timeout"));
                assert!(
                    argv.iter()
                        .all(|arg| !arg.to_string_lossy().contains("rch-wkr"))
                );
            }
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_benchmark_process_executes_both_shell_transports_and_parses_components() {
        use std::os::unix::fs::PermissionsExt;

        // This is a real executable protocol fixture, not a worker performance
        // measurement. The separate native canary exercises Windows OpenSSH.
        let home = tempfile::Builder::new()
            .prefix("rch benchmark & ")
            .tempdir()
            .unwrap();
        let bin = home.path().join(".local/bin");
        std::fs::create_dir_all(&bin).unwrap();
        let worker_program = bin.join("rch-wkr");
        std::fs::write(
            &worker_program,
            "#!/bin/sh\n[ \"$*\" = 'benchmark --json' ] || exit 23\nif read -r value; then exit 24; fi\nprintf '%s\\n' '{\"score\":72.5,\"components\":{\"cpu\":81,\"memory\":64,\"disk\":57,\"network\":45,\"compilation\":79}}'\n",
        )
        .unwrap();
        std::fs::set_permissions(&worker_program, std::fs::Permissions::from_mode(0o755)).unwrap();

        for os in ["linux", "windows"] {
            let mut worker = make_worker_config("worker-1");
            worker.tags = vec![rch_common::types::os_tag(os)];
            let (ssh, input) = benchmark_ssh_command(&worker, Duration::from_secs(5));
            let mut shell = tokio::process::Command::new("sh");
            shell
                .arg("-c")
                .arg(ssh.as_std().get_args().last().unwrap())
                .env("HOME", home.path());
            let (score, _) = execute_benchmark_process(shell, input, Duration::from_secs(5))
                .await
                .unwrap();
            assert!((score.total - 72.5).abs() < f64::EPSILON);
            assert!((score.cpu_score - 81.0).abs() < f64::EPSILON);
            assert!((score.memory_score - 64.0).abs() < f64::EPSILON);
            assert!((score.disk_score - 57.0).abs() < f64::EPSILON);
            assert!((score.network_score - 45.0).abs() < f64::EPSILON);
            assert!((score.compilation_score - 79.0).abs() < f64::EPSILON);
        }
    }

    /// A hung worker benchmark must die on the worker at the deadline even
    /// when nothing on the dispatcher side kills it (dropped ssh session).
    #[cfg(target_os = "linux")]
    #[test]
    fn test_remote_benchmark_script_enforces_deadline_on_worker() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::Instant;

        let home = tempfile::tempdir().unwrap();
        let bin = home.path().join(".local/bin");
        let worker_program = bin.join("rch-wkr");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::write(&worker_program, "#!/bin/sh\nexec sleep 60\n").unwrap();
        std::fs::set_permissions(&worker_program, std::fs::Permissions::from_mode(0o755)).unwrap();

        let start = Instant::now();
        let status = std::process::Command::new("sh")
            .arg("-c")
            .arg(remote_benchmark_script(1))
            .env("HOME", home.path())
            .stdin(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(!status.success());
        assert!(
            start.elapsed() < Duration::from_secs(15),
            "worker-side deadline did not fire: {:?}",
            start.elapsed()
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_benchmark_process_preserves_early_exit_and_rejects_invalid_output() {
        let mut failure = tokio::process::Command::new("sh");
        failure.args(["-c", "printf '%s' 'worker diagnostic' >&2; exit 37"]);
        // More than a pipe buffer forces the writer to encounter a closed
        // stdin. The remote exit and diagnostic must still be returned.
        let error = execute_benchmark_process(
            failure,
            Some("x".repeat(1024 * 1024)),
            Duration::from_secs(5),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("37"), "{error}");
        assert!(error.contains("worker diagnostic"), "{error}");

        let mut invalid = tokio::process::Command::new("sh");
        invalid.args(["-c", "printf '%s' 'not a benchmark result'"]);
        let error = execute_benchmark_process(invalid, None, Duration::from_secs(5))
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("Failed to parse benchmark score"), "{error}");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_benchmark_process_timeout_and_cancellation_reap_owned_child() {
        for cancel in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let pid_file = directory.path().join("child.pid");
            let mut command = tokio::process::Command::new("sh");
            command
                .args([
                    "-c",
                    "printf '%s' \"$$\" > \"$1\"; exec sleep 30",
                    "benchmark-child",
                ])
                .arg(&pid_file);
            let timeout = if cancel {
                Duration::from_secs(30)
            } else {
                Duration::from_secs(1)
            };
            // The child never reads stdin: cancel while the new script writer
            // is blocked, as well as while both output readers are waiting.
            let task = tokio::spawn(execute_benchmark_process(
                command,
                Some("x".repeat(1024 * 1024)),
                timeout,
            ));
            let pid = tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    if let Ok(contents) = std::fs::read_to_string(&pid_file)
                        && let Ok(pid) = contents.parse::<u32>()
                    {
                        break pid;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("owned child must report its PID");
            if cancel {
                task.abort();
                assert!(task.await.unwrap_err().is_cancelled());
            } else {
                let error = task.await.unwrap().unwrap_err().to_string();
                assert!(error.contains("Benchmark timed out"), "{error}");
            }
            tokio::time::timeout(Duration::from_secs(5), async {
                while std::path::Path::new(&format!("/proc/{pid}")).exists() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("owned foreground child must be killed and reaped");
        }
    }

    #[test]
    fn test_benchmark_completed_event_matches_web_contract() {
        let worker_id = WorkerId::new("worker-1");
        let score = speedscore_from_total(87.5, Utc::now());
        let event = benchmark_completed_event_data(
            "req-1",
            &worker_id,
            &score,
            Duration::from_millis(1500),
        );
        let event = event.as_object().expect("event data should be an object");
        let speedscore = event
            .get("speedscore")
            .and_then(serde_json::Value::as_object)
            .expect("speedscore should be an object");

        assert_eq!(
            event.get("request_id").and_then(serde_json::Value::as_str),
            Some("req-1")
        );
        assert_eq!(
            event.get("job_id").and_then(serde_json::Value::as_str),
            Some("req-1")
        );
        assert_eq!(
            event.get("worker_id").and_then(serde_json::Value::as_str),
            Some("worker-1")
        );
        assert_eq!(
            event
                .get("duration_secs")
                .and_then(serde_json::Value::as_f64),
            Some(1.5)
        );
        assert_eq!(
            event.get("success").and_then(serde_json::Value::as_bool),
            Some(true)
        );
        assert_eq!(
            speedscore.get("total").and_then(serde_json::Value::as_f64),
            Some(87.5)
        );
        assert_eq!(
            speedscore
                .get("compilation_score")
                .and_then(serde_json::Value::as_f64),
            Some(87.5)
        );
        assert_eq!(
            speedscore
                .get("cpu_score")
                .and_then(serde_json::Value::as_f64),
            Some(0.0)
        );
        chrono::DateTime::parse_from_rfc3339(
            speedscore
                .get("measured_at")
                .and_then(serde_json::Value::as_str)
                .expect("measured_at should be string"),
        )
        .expect("measured_at should be RFC3339");
    }

    #[test]
    fn test_benchmark_failed_event_matches_web_contract() {
        let worker_id = WorkerId::new("worker-1");
        let event = benchmark_failed_event_data("req-1", &worker_id, "ssh timeout", true, 2);
        let event = event.as_object().expect("event data should be an object");

        assert_eq!(
            event.get("request_id").and_then(serde_json::Value::as_str),
            Some("req-1")
        );
        assert_eq!(
            event.get("job_id").and_then(serde_json::Value::as_str),
            Some("req-1")
        );
        assert_eq!(
            event.get("worker_id").and_then(serde_json::Value::as_str),
            Some("worker-1")
        );
        assert_eq!(
            event.get("error").and_then(serde_json::Value::as_str),
            Some("ssh timeout")
        );
        assert_eq!(
            event.get("retryable").and_then(serde_json::Value::as_bool),
            Some(true)
        );
        assert_eq!(
            event
                .get("consecutive_failures")
                .and_then(serde_json::Value::as_u64),
            Some(2)
        );
    }

    #[test]
    fn test_benchmark_event_score_is_finite_and_clamped() {
        assert_eq!(normalized_event_score(f64::NAN), 0.0);
        assert_eq!(normalized_event_score(f64::INFINITY), 0.0);
        assert_eq!(normalized_event_score(-12.0), 0.0);
        assert_eq!(normalized_event_score(125.0), 100.0);
        assert_eq!(normalized_event_score(42.5), 42.5);
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
            running.insert(
                WorkerId::new("w1"),
                RunningBenchmark {
                    request: ScheduledBenchmarkRequest::new(
                        WorkerId::new("w1"),
                        BenchmarkPriority::Normal,
                        BenchmarkReason::Scheduled,
                    ),
                    started_at: Utc::now(),
                },
            );
            running.insert(
                WorkerId::new("w2"),
                RunningBenchmark {
                    request: ScheduledBenchmarkRequest::new(
                        WorkerId::new("w2"),
                        BenchmarkPriority::Normal,
                        BenchmarkReason::Scheduled,
                    ),
                    started_at: Utc::now(),
                },
            );
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
        let mut rx = events.subscribe();

        let (scheduler, _handle) =
            BenchmarkScheduler::new(make_test_config(), pool.clone(), telemetry, events);

        let worker_id = WorkerId::new("complete-test");

        // Simulate a running benchmark
        {
            let mut running = scheduler.running.write().await;
            running.insert(
                worker_id.clone(),
                RunningBenchmark {
                    request: ScheduledBenchmarkRequest::new(
                        worker_id.clone(),
                        BenchmarkPriority::Normal,
                        BenchmarkReason::Scheduled,
                    ),
                    started_at: Utc::now(),
                },
            );
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

        let msg = tokio::time::timeout(Duration::from_millis(50), rx.recv())
            .await
            .expect("timed out waiting for completed event")
            .expect("event bus should receive completed event");
        let event: serde_json::Value = serde_json::from_str(&msg).expect("event should be JSON");
        assert_eq!(event["event"], "benchmark_completed");
        assert_eq!(event["data"]["job_id"], event["data"]["request_id"]);
        assert_eq!(event["data"]["speedscore"]["total"], 75.0);
    }

    /// Regression for issue #40: a successful legacy benchmark must persist its
    /// diagnostic score and not immediately loop as a NewWorker after restart.
    /// Its unknown calibration must not become a live selection measurement.
    #[tokio::test]
    async fn successful_benchmark_persistence_stops_new_worker_rescheduling() {
        use rch_telemetry::storage::TelemetryStorage;

        let storage = Arc::new(TelemetryStorage::new_in_memory().expect("telemetry storage"));

        let pool = WorkerPool::new();
        pool.add_worker(make_worker_config("persist-test")).await;
        let telemetry = Arc::new(TelemetryStore::new(
            Duration::from_secs(300),
            Some(storage.clone()),
        ));
        let events = EventBus::new(16);
        let (scheduler, _handle) =
            BenchmarkScheduler::new(make_test_config(), pool.clone(), telemetry.clone(), events);

        let worker_id = WorkerId::new("persist-test");
        let worker = pool.get(&worker_id).await.expect("worker should exist");

        // First pass: no persisted score, so the worker is a NewWorker.
        let first = scheduler
            .should_benchmark(&worker)
            .await
            .expect("worker without a score should be scheduled");
        assert!(matches!(first.reason, BenchmarkReason::NewWorker));

        // Simulate a running benchmark and complete it through the production
        // completion path (which must persist the score).
        {
            let mut running = scheduler.running.write().await;
            running.insert(
                worker_id.clone(),
                RunningBenchmark {
                    request: first,
                    started_at: Utc::now(),
                },
            );
        }
        worker.reserve_slots(1).await;
        scheduler
            .mark_completed(&worker_id, 75.0, Duration::from_secs(30))
            .await;

        // The next pass must NOT re-enqueue as NewWorker: the legacy result is
        // persisted and the minimum interval bounds any subsequent recheck.
        assert!(scheduler.should_benchmark(&worker).await.is_none());
        let persisted = telemetry
            .latest_speedscore(worker_id.as_str())
            .await
            .expect("persisted score should be readable")
            .expect("persisted score should exist");
        assert_eq!(persisted.total, 75.0);
        assert_eq!(persisted.compilation_score, 75.0);
        assert_eq!(persisted.version, 0);

        // Legacy diagnostics are not promoted into live calibrated selection.
        assert_eq!(worker.get_speed_score(), 50.0);

        // Simulated daemon restart: fresh pool/store/scheduler over the same
        // persistent storage. Legacy workers must neither hot-loop nor hydrate
        // an incompatible score into the new daemon's placement decisions.
        let restarted_pool = WorkerPool::new();
        restarted_pool
            .add_worker(make_worker_config("persist-test"))
            .await;
        let restarted_telemetry =
            Arc::new(TelemetryStore::new(Duration::from_secs(300), Some(storage)));
        let (restarted_scheduler, _handle) = BenchmarkScheduler::new(
            make_test_config(),
            restarted_pool.clone(),
            restarted_telemetry,
            EventBus::new(16),
        );
        let restarted_worker = restarted_pool
            .get(&worker_id)
            .await
            .expect("restarted worker should exist");
        assert_eq!(restarted_worker.get_speed_score(), 50.0);
        assert!(
            restarted_scheduler
                .should_benchmark(&restarted_worker)
                .await
                .is_none()
        );
        assert_eq!(restarted_worker.get_speed_score(), 50.0);
    }

    #[test]
    fn parse_benchmark_json_extracts_components() {
        let output = r#"{
            "score": 82.4,
            "elapsed_secs": 12.5,
            "cores": 16,
            "components": {
                "cpu": 91.0,
                "memory": 74.5,
                "disk": 63.2,
                "network": 0.0,
                "compilation": 88.8
            }
        }"#;
        let score = parse_benchmark_json(output).expect("should parse");
        assert_eq!(score.total, 82.4);
        assert_eq!(score.cpu_score, 91.0);
        assert_eq!(score.memory_score, 74.5);
        assert_eq!(score.disk_score, 63.2);
        assert_eq!(score.network_score, 0.0);
        assert_eq!(score.compilation_score, 88.8);
        assert_eq!(score.version, 0);
        assert!(selection_speedscore(&score).is_none());
    }

    #[test]
    fn parse_benchmark_json_scalar_only_is_compatible() {
        // Older workers emit only the scalar `score`.
        let score = parse_benchmark_json(r#"{"score": 66.0}"#).expect("should parse");
        assert_eq!(score.total, 66.0);
        assert_eq!(score.compilation_score, 66.0);
        assert_eq!(score.cpu_score, 0.0);

        // Non-JSON and score-less JSON are rejected.
        assert!(parse_benchmark_json("Score: 42.0").is_none());
        assert!(parse_benchmark_json(r#"{"elapsed_secs": 1.0}"#).is_none());
    }

    #[test]
    fn raw_worker_report_is_recalibrated_without_inventing_missing_measurements() {
        let report = r#"{
            "score": 99.9,
            "components": {"cpu": 100, "memory": 100, "disk": 100},
            "raw": {
                "cpu_ops_per_second": 250000,
                "memory_seq_bandwidth_gbps": 4.0,
                "disk_seq_read_mbps": 1000,
                "disk_seq_write_mbps": 1000,
                "disk_random_read_iops": 100000,
                "compilation_release_build_ms": 3000
            }
        }"#;
        let score = parse_benchmark_output(report).unwrap();
        assert!(!score.is_outdated());
        assert!((score.total - 50.0).abs() < 1e-9);
        assert_eq!(score.cpu_score, 50.0);
        assert_eq!(score.disk_score, 50.0);
        assert_eq!(score.compilation_score, 50.0);
        assert_eq!(score.weights.memory, 0.0);
        assert_eq!(score.weights.network, 0.0);
        assert!(score.weights.is_valid());
        assert!(selection_speedscore(&score).is_some());
    }

    #[test]
    fn malformed_structured_reports_cannot_fall_back_to_scalar_extraction() {
        for report in [
            r#"{"score":99,"raw":{}}"#,
            r#"{"score":99,"raw":null}"#,
            r#"{"score":99,"raw":{"cpu_ops_per_second":-5}}"#,
            r#"{"score":99,"raw":{"cpu_ops_per_second":"fast"}}"#,
            r#"{"score":99,"raw":{"compilation_release_build_ms":0}}"#,
            r#"{"score":99,"raw":[]}"#,
            r#"{"score":99,"raw":{"cpu_ops_per_second":250000}"#,
            r#"[{"score":99}]"#,
        ] {
            assert!(parse_benchmark_output(report).is_none(), "{report}");
        }
        let legacy = parse_benchmark_output("Score: 75.0").unwrap();
        assert_eq!(legacy.total, 75.0);
        assert!(selection_speedscore(&legacy).is_none());
    }

    #[tokio::test]
    async fn old_algorithm_score_is_not_hydrated_and_queues_an_upgrade_benchmark() {
        use rch_telemetry::storage::TelemetryStorage;

        let storage = Arc::new(TelemetryStorage::new_in_memory().unwrap());
        let telemetry = Arc::new(TelemetryStore::new(Duration::from_secs(300), Some(storage)));
        let pool = WorkerPool::new();
        let worker_id = WorkerId::new("upgrade-score");
        pool.add_worker(make_worker_config(worker_id.as_str()))
            .await;
        let worker = pool.get(&worker_id).await.unwrap();
        worker.set_speed_score(100.0);
        telemetry
            .record_speedscore(
                worker_id.as_str(),
                SpeedScore {
                    total: 100.0,
                    version: 1,
                    ..SpeedScore::default()
                },
            )
            .await
            .unwrap();
        let (scheduler, _) =
            BenchmarkScheduler::new(make_test_config(), pool, telemetry, EventBus::new(16));
        let request = scheduler.should_benchmark(&worker).await.unwrap();
        assert_eq!(worker.get_speed_score(), 50.0);
        assert_eq!(request.priority, BenchmarkPriority::High);
        assert!(matches!(request.reason, BenchmarkReason::StaleScore { .. }));
        scheduler.enqueue(request).await;
        scheduler.process_pending_queue().await;
        assert_eq!(scheduler.pending_count().await, 1);
        assert_eq!(scheduler.running_count().await, 0);
        assert_eq!(worker.available_slots().await, 4);
    }

    #[tokio::test]
    async fn recalibrated_raw_score_persists_and_hydrates_after_restart() {
        use rch_telemetry::storage::TelemetryStorage;

        let storage = Arc::new(TelemetryStorage::new_in_memory().unwrap());
        let telemetry = Arc::new(TelemetryStore::new(
            Duration::from_secs(300),
            Some(storage.clone()),
        ));
        let pool = WorkerPool::new();
        let worker_id = WorkerId::new("current-score");
        pool.add_worker(make_worker_config(worker_id.as_str()))
            .await;
        let worker = pool.get(&worker_id).await.unwrap();
        let score =
            parse_benchmark_output(r#"{"score":100,"raw":{"cpu_ops_per_second":750000}}"#).unwrap();
        commit_benchmark_score(&telemetry, &pool, &worker_id, &score).await;
        assert!((worker.get_speed_score() - 75.0).abs() < 1e-9);

        let restarted_pool = WorkerPool::new();
        restarted_pool
            .add_worker(make_worker_config(worker_id.as_str()))
            .await;
        let restarted_worker = restarted_pool.get(&worker_id).await.unwrap();
        let restarted_telemetry =
            Arc::new(TelemetryStore::new(Duration::from_secs(300), Some(storage)));
        let (scheduler, _) = BenchmarkScheduler::new(
            make_test_config(),
            restarted_pool,
            restarted_telemetry,
            EventBus::new(16),
        );
        assert_eq!(restarted_worker.get_speed_score(), 50.0);
        assert!(
            scheduler
                .should_benchmark(&restarted_worker)
                .await
                .is_none()
        );
        assert!((restarted_worker.get_speed_score() - 75.0).abs() < 1e-9);
    }

    #[test]
    fn incompatible_or_invalid_scores_are_diagnostic_only() {
        let current = SpeedScore {
            total: 75.0,
            ..SpeedScore::default()
        };
        assert_eq!(selection_speedscore(&current), Some(75.0));
        for version in [0, 1, u32::MAX] {
            let mut incompatible = current.clone();
            incompatible.version = version;
            assert!(selection_speedscore(&incompatible).is_none());
        }
        for total in [f64::NAN, f64::INFINITY, -1.0, 101.0] {
            let mut invalid = current.clone();
            invalid.total = total;
            assert!(selection_speedscore(&invalid).is_none());
        }
        let empty = SpeedScore::calculate(&rch_telemetry::speedscore::BenchmarkResults::new());
        assert!(selection_speedscore(&empty).is_none());
    }

    #[tokio::test]
    async fn test_mark_failed_retryable_requeues() {
        let pool = WorkerPool::new();
        pool.add_worker(make_worker_config("fail-test")).await;

        let telemetry = Arc::new(TelemetryStore::new(Duration::from_secs(300), None));
        let events = EventBus::new(16);
        let mut rx = events.subscribe();

        let (scheduler, _handle) =
            BenchmarkScheduler::new(make_test_config(), pool.clone(), telemetry, events);

        let worker_id = WorkerId::new("fail-test");

        // Simulate a running benchmark
        {
            let mut running = scheduler.running.write().await;
            running.insert(
                worker_id.clone(),
                RunningBenchmark {
                    request: ScheduledBenchmarkRequest::new(
                        worker_id.clone(),
                        BenchmarkPriority::High, // Started as high priority
                        BenchmarkReason::NewWorker,
                    ),
                    started_at: Utc::now(),
                },
            );
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

        let msg = tokio::time::timeout(Duration::from_millis(50), rx.recv())
            .await
            .expect("timed out waiting for failed event")
            .expect("event bus should receive failed event");
        let event: serde_json::Value = serde_json::from_str(&msg).expect("event should be JSON");
        assert_eq!(event["event"], "benchmark_failed");
        assert_eq!(event["data"]["job_id"], event["data"]["request_id"]);
        assert_eq!(event["data"]["error"], "SSH connection failed");
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
            running.insert(
                worker_id.clone(),
                RunningBenchmark {
                    request: ScheduledBenchmarkRequest::new(
                        worker_id.clone(),
                        BenchmarkPriority::Normal,
                        BenchmarkReason::Scheduled,
                    ),
                    started_at: Utc::now(),
                },
            );
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

    #[tokio::test]
    async fn repeatedly_failing_new_worker_is_not_rescheduled_during_backoff() {
        let pool = WorkerPool::new();
        pool.add_worker(make_worker_config("backoff-test")).await;
        let telemetry = Arc::new(TelemetryStore::new(Duration::from_secs(300), None));
        let mut config = make_test_config();
        config.consecutive_failure_alert_threshold = 1;
        let (scheduler, _handle) =
            BenchmarkScheduler::new(config, pool.clone(), telemetry, EventBus::new(16));
        let worker_id = WorkerId::new("backoff-test");
        let worker = pool.get(&worker_id).await.unwrap();
        assert!(
            scheduler.should_benchmark(&worker).await.is_some(),
            "a new worker is scheduled"
        );

        scheduler.running.write().await.insert(
            worker_id.clone(),
            RunningBenchmark {
                request: ScheduledBenchmarkRequest::new(
                    worker_id.clone(),
                    BenchmarkPriority::High,
                    BenchmarkReason::NewWorker,
                ),
                started_at: Utc::now(),
            },
        );
        worker.reserve_slots(1).await;
        scheduler
            .mark_failed(&worker_id, "Benchmark timed out after 300s", true)
            .await;
        scheduler.pending_queue.lock().await.clear();

        assert!(
            scheduler.should_benchmark(&worker).await.is_none(),
            "a worker past the failure threshold waits out its backoff"
        );
    }

    #[tokio::test]
    async fn test_consecutive_failures_tracked_and_reset() {
        // Create a scheduler with low threshold for testing
        let pool = WorkerPool::new();
        pool.add_worker(make_worker_config("alert-test")).await;

        let telemetry = Arc::new(TelemetryStore::new(Duration::from_secs(300), None));
        let events = EventBus::new(16);

        let mut config = make_test_config();
        config.consecutive_failure_alert_threshold = 2; // Alert after 2 consecutive failures

        let (scheduler, _handle) = BenchmarkScheduler::new(config, pool.clone(), telemetry, events);

        let worker_id = WorkerId::new("alert-test");

        // Helper to simulate a running benchmark
        async fn simulate_running_benchmark(
            scheduler: &BenchmarkScheduler,
            pool: &WorkerPool,
            worker_id: &WorkerId,
        ) {
            // Insert into running map
            {
                let mut running = scheduler.running.write().await;
                running.insert(
                    worker_id.clone(),
                    RunningBenchmark {
                        request: ScheduledBenchmarkRequest::new(
                            worker_id.clone(),
                            BenchmarkPriority::Normal,
                            BenchmarkReason::Scheduled,
                        ),
                        started_at: Utc::now(),
                    },
                );
            }
            // Reserve a slot
            if let Some(worker) = pool.get(worker_id).await {
                worker.reserve_slots(1).await;
            }
        }

        // Simulate first benchmark run and failure
        simulate_running_benchmark(&scheduler, &pool, &worker_id).await;
        scheduler
            .mark_failed(&worker_id, "Connection timeout", true)
            .await;

        // Check consecutive failure count is 1
        {
            let failures = scheduler.consecutive_failures.read().await;
            assert_eq!(*failures.get(&worker_id).unwrap(), 1);
        }

        // Simulate second benchmark run and failure (should trigger alert with threshold=2)
        simulate_running_benchmark(&scheduler, &pool, &worker_id).await;
        scheduler.mark_failed(&worker_id, "SSH error", true).await;

        // Check consecutive failure count incremented to 2
        {
            let failures = scheduler.consecutive_failures.read().await;
            assert_eq!(*failures.get(&worker_id).unwrap(), 2);
        }

        // Simulate third benchmark run and successful completion - should reset counter
        simulate_running_benchmark(&scheduler, &pool, &worker_id).await;
        scheduler
            .mark_completed(&worker_id, 75.0, Duration::from_secs(30))
            .await;

        // Check counter is reset (removed)
        {
            let failures = scheduler.consecutive_failures.read().await;
            assert!(failures.get(&worker_id).is_none());
        }
    }

    // ==================== Additional Coverage Tests ====================

    #[test]
    fn test_benchmark_priority_default() {
        let priority: BenchmarkPriority = Default::default();
        assert_eq!(priority, BenchmarkPriority::Normal);
    }

    #[test]
    fn test_benchmark_priority_ord() {
        assert!(BenchmarkPriority::High > BenchmarkPriority::Normal);
        assert!(BenchmarkPriority::Normal > BenchmarkPriority::Low);
        assert!(BenchmarkPriority::High > BenchmarkPriority::Low);

        // Equality
        assert_eq!(BenchmarkPriority::Low, BenchmarkPriority::Low);
        assert_eq!(BenchmarkPriority::Normal, BenchmarkPriority::Normal);
        assert_eq!(BenchmarkPriority::High, BenchmarkPriority::High);
    }

    #[test]
    fn test_benchmark_priority_clone_debug_hash() {
        let priority = BenchmarkPriority::High;
        let copied = priority; // BenchmarkPriority implements Copy
        assert_eq!(priority, copied);

        // Test Hash by inserting into HashMap
        let mut map = HashMap::new();
        map.insert(BenchmarkPriority::High, "high");
        map.insert(BenchmarkPriority::Normal, "normal");
        map.insert(BenchmarkPriority::Low, "low");
        assert_eq!(map.get(&BenchmarkPriority::High), Some(&"high"));

        // Debug format
        let debug_str = format!("{:?}", priority);
        assert!(debug_str.contains("High"));
    }

    #[test]
    fn test_benchmark_reason_clone_debug() {
        let reason = BenchmarkReason::NewWorker;
        let cloned = reason.clone();
        assert!(matches!(cloned, BenchmarkReason::NewWorker));

        let reason2 = BenchmarkReason::StaleScore {
            age: ChronoDuration::hours(48),
        };
        let cloned2 = reason2.clone();
        assert!(matches!(cloned2, BenchmarkReason::StaleScore { age } if age.num_hours() == 48));

        let reason3 = BenchmarkReason::DriftDetected { drift_pct: 15.5 };
        let cloned3 = reason3.clone();
        assert!(
            matches!(cloned3, BenchmarkReason::DriftDetected { drift_pct } if (drift_pct - 15.5).abs() < 0.01)
        );

        // Debug format
        let debug_str = format!("{:?}", reason);
        assert!(debug_str.contains("NewWorker"));
    }

    #[test]
    fn test_benchmark_reason_display_all_variants() {
        // NewWorker
        assert_eq!(BenchmarkReason::NewWorker.to_string(), "new_worker");

        // StaleScore with various ages
        assert_eq!(
            BenchmarkReason::StaleScore {
                age: ChronoDuration::hours(0)
            }
            .to_string(),
            "stale_score(0h)"
        );
        assert_eq!(
            BenchmarkReason::StaleScore {
                age: ChronoDuration::hours(168)
            }
            .to_string(),
            "stale_score(168h)"
        );

        // ManualTrigger with and without user
        assert_eq!(
            BenchmarkReason::ManualTrigger {
                user: Some("alice".to_string())
            }
            .to_string(),
            "manual(alice)"
        );
        assert_eq!(
            BenchmarkReason::ManualTrigger { user: None }.to_string(),
            "manual(api)"
        );

        // DriftDetected with various percentages
        assert_eq!(
            BenchmarkReason::DriftDetected { drift_pct: 0.0 }.to_string(),
            "drift(0.0%)"
        );
        assert_eq!(
            BenchmarkReason::DriftDetected { drift_pct: 99.99 }.to_string(),
            "drift(100.0%)"
        );

        // Scheduled
        assert_eq!(BenchmarkReason::Scheduled.to_string(), "scheduled");
    }

    #[test]
    fn test_scheduler_config_default() {
        let config = SchedulerConfig::default();

        assert_eq!(config.min_interval, Duration::from_secs(6 * 3600));
        assert_eq!(config.max_age, Duration::from_secs(24 * 3600));
        assert!((config.idle_cpu_threshold - 20.0).abs() < 0.01);
        assert_eq!(config.max_concurrent, 1);
        assert!((config.drift_threshold_pct - 20.0).abs() < 0.01);
        assert_eq!(config.benchmark_timeout, Duration::from_secs(5 * 60));
        assert_eq!(config.check_interval, Duration::from_secs(60));
        assert_eq!(config.consecutive_failure_alert_threshold, 3);
    }

    #[test]
    fn test_scheduler_config_clone() {
        let config = SchedulerConfig {
            min_interval: Duration::from_secs(100),
            max_age: Duration::from_secs(200),
            idle_cpu_threshold: 30.0,
            max_concurrent: 5,
            drift_threshold_pct: 15.0,
            benchmark_timeout: Duration::from_secs(300),
            check_interval: Duration::from_secs(10),
            consecutive_failure_alert_threshold: 5,
        };

        let cloned = config.clone();
        assert_eq!(cloned.min_interval, config.min_interval);
        assert_eq!(cloned.max_age, config.max_age);
        assert!((cloned.idle_cpu_threshold - config.idle_cpu_threshold).abs() < 0.01);
        assert_eq!(cloned.max_concurrent, config.max_concurrent);
        assert_eq!(cloned.consecutive_failure_alert_threshold, 5);
    }

    #[test]
    fn test_scheduled_benchmark_request_new() {
        let worker_id = WorkerId::new("test-worker");
        let request = ScheduledBenchmarkRequest::new(
            worker_id.clone(),
            BenchmarkPriority::High,
            BenchmarkReason::NewWorker,
        );

        assert_eq!(request.worker_id, worker_id);
        assert_eq!(request.priority, BenchmarkPriority::High);
        assert!(matches!(request.reason, BenchmarkReason::NewWorker));

        // Request ID should be UUID format (36 chars with hyphens)
        assert_eq!(request.request_id.len(), 36);
        assert!(request.request_id.contains('-'));

        // Requested_at should be recent
        let now = Utc::now();
        let diff = now - request.requested_at;
        assert!(diff.num_seconds() < 5);
    }

    #[test]
    fn test_scheduled_benchmark_request_clone() {
        let request = ScheduledBenchmarkRequest::new(
            WorkerId::new("clone-test"),
            BenchmarkPriority::Normal,
            BenchmarkReason::Scheduled,
        );

        let cloned = request.clone();
        assert_eq!(cloned.request_id, request.request_id);
        assert_eq!(cloned.worker_id, request.worker_id);
        assert_eq!(cloned.priority, request.priority);
        assert_eq!(cloned.requested_at, request.requested_at);
    }

    #[test]
    fn test_benchmark_status_variants() {
        // Queued
        let status1 = BenchmarkStatus::Queued;
        assert!(matches!(status1, BenchmarkStatus::Queued));

        // Reserving
        let status2 = BenchmarkStatus::Reserving;
        assert!(matches!(status2, BenchmarkStatus::Reserving));

        // Running
        let status3 = BenchmarkStatus::Running {
            started_at: Utc::now(),
            worker_id: WorkerId::new("running-worker"),
        };
        assert!(matches!(status3, BenchmarkStatus::Running { .. }));

        // Completed
        let status4 = BenchmarkStatus::Completed {
            duration: Duration::from_secs(60),
            new_score: 85.5,
        };
        assert!(matches!(status4, BenchmarkStatus::Completed { .. }));

        // Failed
        let status5 = BenchmarkStatus::Failed {
            error: "Connection timeout".to_string(),
            retryable: true,
        };
        assert!(matches!(
            status5,
            BenchmarkStatus::Failed {
                retryable: true,
                ..
            }
        ));

        let status6 = BenchmarkStatus::Failed {
            error: "Invalid worker".to_string(),
            retryable: false,
        };
        assert!(matches!(
            status6,
            BenchmarkStatus::Failed {
                retryable: false,
                ..
            }
        ));
    }

    #[test]
    fn test_benchmark_status_clone() {
        let status = BenchmarkStatus::Completed {
            duration: Duration::from_secs(120),
            new_score: 92.0,
        };
        let cloned = status.clone();
        assert!(matches!(
            cloned,
            BenchmarkStatus::Completed { duration, new_score }
            if duration == Duration::from_secs(120) && (new_score - 92.0).abs() < 0.01
        ));
    }

    #[test]
    fn test_benchmark_trigger_debug() {
        let trigger = BenchmarkTrigger {
            worker_id: WorkerId::new("debug-test"),
            user: Some("admin".to_string()),
            request_id: "req-123".to_string(),
        };

        let debug_str = format!("{:?}", trigger);
        assert!(debug_str.contains("debug-test"));
        assert!(debug_str.contains("admin"));
        assert!(debug_str.contains("req-123"));
    }

    #[tokio::test]
    async fn test_pending_count_empty() {
        let pool = WorkerPool::new();
        let telemetry = Arc::new(TelemetryStore::new(Duration::from_secs(300), None));
        let events = EventBus::new(16);

        let (scheduler, _handle) =
            BenchmarkScheduler::new(make_test_config(), pool, telemetry, events);

        assert_eq!(scheduler.pending_count().await, 0);
    }

    #[tokio::test]
    async fn test_running_count_empty() {
        let pool = WorkerPool::new();
        let telemetry = Arc::new(TelemetryStore::new(Duration::from_secs(300), None));
        let events = EventBus::new(16);

        let (scheduler, _handle) =
            BenchmarkScheduler::new(make_test_config(), pool, telemetry, events);

        assert_eq!(scheduler.running_count().await, 0);
    }

    #[tokio::test]
    async fn test_running_count_multiple() {
        let pool = WorkerPool::new();
        let telemetry = Arc::new(TelemetryStore::new(Duration::from_secs(300), None));
        let events = EventBus::new(16);

        let (scheduler, _handle) =
            BenchmarkScheduler::new(make_test_config(), pool, telemetry, events);

        // Add multiple running benchmarks
        {
            let mut running = scheduler.running.write().await;
            running.insert(
                WorkerId::new("w1"),
                RunningBenchmark {
                    request: ScheduledBenchmarkRequest::new(
                        WorkerId::new("w1"),
                        BenchmarkPriority::High,
                        BenchmarkReason::NewWorker,
                    ),
                    started_at: Utc::now(),
                },
            );
            running.insert(
                WorkerId::new("w2"),
                RunningBenchmark {
                    request: ScheduledBenchmarkRequest::new(
                        WorkerId::new("w2"),
                        BenchmarkPriority::Normal,
                        BenchmarkReason::Scheduled,
                    ),
                    started_at: Utc::now(),
                },
            );
        }

        assert_eq!(scheduler.running_count().await, 2);
    }

    #[tokio::test]
    async fn test_is_pending_or_running_in_running_map() {
        let pool = WorkerPool::new();
        let telemetry = Arc::new(TelemetryStore::new(Duration::from_secs(300), None));
        let events = EventBus::new(16);

        let (scheduler, _handle) =
            BenchmarkScheduler::new(make_test_config(), pool, telemetry, events);

        let worker_id = WorkerId::new("running-test");

        // Add to running map (not pending queue)
        {
            let mut running = scheduler.running.write().await;
            running.insert(
                worker_id.clone(),
                RunningBenchmark {
                    request: ScheduledBenchmarkRequest::new(
                        worker_id.clone(),
                        BenchmarkPriority::Normal,
                        BenchmarkReason::Scheduled,
                    ),
                    started_at: Utc::now(),
                },
            );
        }

        assert!(scheduler.is_pending_or_running(&worker_id).await);
        assert!(
            !scheduler
                .is_pending_or_running(&WorkerId::new("other"))
                .await
        );
    }

    #[tokio::test]
    async fn test_enqueue_same_priority_timestamp_ordering() {
        let pool = WorkerPool::new();
        let telemetry = Arc::new(TelemetryStore::new(Duration::from_secs(300), None));
        let events = EventBus::new(16);

        let (scheduler, _handle) =
            BenchmarkScheduler::new(make_test_config(), pool, telemetry, events);

        // Create requests with same priority but different timestamps
        let mut req1 = ScheduledBenchmarkRequest::new(
            WorkerId::new("first"),
            BenchmarkPriority::Normal,
            BenchmarkReason::Scheduled,
        );
        req1.requested_at = Utc::now() - ChronoDuration::seconds(10);

        let mut req2 = ScheduledBenchmarkRequest::new(
            WorkerId::new("second"),
            BenchmarkPriority::Normal,
            BenchmarkReason::Scheduled,
        );
        req2.requested_at = Utc::now();

        // Enqueue in reverse order (newer first)
        scheduler.enqueue(req2).await;
        scheduler.enqueue(req1).await;

        // Check order: earlier timestamp should be first
        let queue = scheduler.pending_queue.lock().await;
        let ids: Vec<_> = queue.iter().map(|r| r.worker_id.as_str()).collect();
        assert_eq!(ids, vec!["first", "second"]);
    }

    #[tokio::test]
    async fn test_enqueue_duplicate_worker_ids() {
        let pool = WorkerPool::new();
        let telemetry = Arc::new(TelemetryStore::new(Duration::from_secs(300), None));
        let events = EventBus::new(16);

        let (scheduler, _handle) =
            BenchmarkScheduler::new(make_test_config(), pool, telemetry, events);

        let worker_id = WorkerId::new("dupe-worker");

        // Enqueue same worker twice (different priorities)
        scheduler
            .enqueue(ScheduledBenchmarkRequest::new(
                worker_id.clone(),
                BenchmarkPriority::Low,
                BenchmarkReason::DriftDetected { drift_pct: 10.0 },
            ))
            .await;

        scheduler
            .enqueue(ScheduledBenchmarkRequest::new(
                worker_id.clone(),
                BenchmarkPriority::High,
                BenchmarkReason::ManualTrigger {
                    user: Some("test".to_string()),
                },
            ))
            .await;

        // Both should be in queue (no deduplication in enqueue)
        assert_eq!(scheduler.pending_count().await, 2);

        // High priority should be first
        let queue = scheduler.pending_queue.lock().await;
        assert_eq!(queue[0].priority, BenchmarkPriority::High);
        assert_eq!(queue[1].priority, BenchmarkPriority::Low);
    }

    #[tokio::test]
    async fn test_benchmark_trigger_handle_trigger() {
        let pool = WorkerPool::new();
        let telemetry = Arc::new(TelemetryStore::new(Duration::from_secs(300), None));
        let events = EventBus::new(16);

        let (scheduler, handle) =
            BenchmarkScheduler::new(make_test_config(), pool, telemetry, events);

        // Send a trigger through the handle
        let result = handle
            .trigger(
                WorkerId::new("trigger-test"),
                "req-456".to_string(),
                Some("bob".to_string()),
            )
            .await;

        assert!(result.is_ok());

        // Receive from the scheduler's rx channel
        let trigger = scheduler.trigger_rx.lock().await.recv().await.unwrap();
        assert_eq!(trigger.worker_id.as_str(), "trigger-test");
        assert_eq!(trigger.request_id, "req-456");
        assert_eq!(trigger.user, Some("bob".to_string()));
    }

    #[tokio::test]
    async fn test_benchmark_trigger_handle_clone() {
        let pool = WorkerPool::new();
        let telemetry = Arc::new(TelemetryStore::new(Duration::from_secs(300), None));
        let events = EventBus::new(16);

        let (_scheduler, handle) =
            BenchmarkScheduler::new(make_test_config(), pool, telemetry, events);

        // Clone the handle
        let handle2 = handle.clone();

        // Both handles should work
        let result1 = handle
            .trigger(WorkerId::new("h1"), "r1".to_string(), None)
            .await;
        let result2 = handle2
            .trigger(WorkerId::new("h2"), "r2".to_string(), None)
            .await;

        assert!(result1.is_ok());
        assert!(result2.is_ok());
    }

    #[tokio::test]
    async fn test_manual_trigger_skips_when_already_pending() {
        let pool = WorkerPool::new();
        pool.add_worker(make_worker_config("skip-test")).await;

        let telemetry = Arc::new(TelemetryStore::new(Duration::from_secs(300), None));
        let events = EventBus::new(16);

        let (scheduler, _handle) =
            BenchmarkScheduler::new(make_test_config(), pool, telemetry, events);

        let worker_id = WorkerId::new("skip-test");

        // Pre-enqueue the worker
        scheduler
            .enqueue(ScheduledBenchmarkRequest::new(
                worker_id.clone(),
                BenchmarkPriority::Normal,
                BenchmarkReason::Scheduled,
            ))
            .await;

        assert_eq!(scheduler.pending_count().await, 1);

        // Try manual trigger - should be skipped
        scheduler
            .handle_manual_trigger(BenchmarkTrigger {
                worker_id,
                user: Some("admin".to_string()),
                request_id: "should-be-skipped".to_string(),
            })
            .await;

        // Still just 1 in queue (not added)
        assert_eq!(scheduler.pending_count().await, 1);
    }

    #[tokio::test]
    async fn test_mark_completed_when_not_running() {
        let pool = WorkerPool::new();
        let telemetry = Arc::new(TelemetryStore::new(Duration::from_secs(300), None));
        let events = EventBus::new(16);

        let (scheduler, _handle) =
            BenchmarkScheduler::new(make_test_config(), pool, telemetry, events);

        // Mark completed on non-existent running benchmark
        // This should be a no-op, not panic
        scheduler
            .mark_completed(&WorkerId::new("ghost"), 50.0, Duration::from_secs(10))
            .await;

        assert_eq!(scheduler.running_count().await, 0);
    }

    #[tokio::test]
    async fn test_mark_failed_when_not_running() {
        let pool = WorkerPool::new();
        let telemetry = Arc::new(TelemetryStore::new(Duration::from_secs(300), None));
        let events = EventBus::new(16);

        let (scheduler, _handle) =
            BenchmarkScheduler::new(make_test_config(), pool, telemetry, events);

        // Mark failed on non-existent running benchmark
        // This should be a no-op, not panic
        scheduler
            .mark_failed(&WorkerId::new("ghost"), "error", true)
            .await;

        assert_eq!(scheduler.running_count().await, 0);
        assert_eq!(scheduler.pending_count().await, 0);
    }

    #[test]
    fn test_running_benchmark_clone() {
        let running = RunningBenchmark {
            request: ScheduledBenchmarkRequest::new(
                WorkerId::new("clone-running"),
                BenchmarkPriority::High,
                BenchmarkReason::NewWorker,
            ),
            started_at: Utc::now(),
        };

        let cloned = running.clone();
        assert_eq!(cloned.request.worker_id, running.request.worker_id);
        assert_eq!(cloned.started_at, running.started_at);
    }

    // ==================== Tests for Helper Functions ====================

    #[test]
    fn test_parse_benchmark_score_colon_format() {
        // "Score: 123.45" format
        assert_eq!(super::parse_benchmark_score("Score: 123.45"), Some(123.45));
        assert_eq!(super::parse_benchmark_score("score: 99.9"), Some(99.9));
        assert_eq!(super::parse_benchmark_score("SCORE: 0.5"), Some(0.5));
        assert_eq!(super::parse_benchmark_score("Score:   45.67"), Some(45.67));
    }

    #[test]
    fn test_parse_benchmark_score_equals_format() {
        // "score = 123.45" format
        assert_eq!(super::parse_benchmark_score("score = 75.0"), Some(75.0));
        assert_eq!(super::parse_benchmark_score("Score = 100"), Some(100.0));
    }

    #[test]
    fn test_parse_benchmark_score_json_format() {
        // JSON-like format
        assert_eq!(
            super::parse_benchmark_score(r#"{"score": 88.5}"#),
            Some(88.5)
        );
        assert_eq!(
            super::parse_benchmark_score(r#"  "score": 42.0,  "#),
            Some(42.0)
        );
    }

    #[test]
    fn test_parse_benchmark_score_multiline() {
        let output = r#"
Benchmark started
Running tests...
Score: 87.3
Benchmark complete
"#;
        assert_eq!(super::parse_benchmark_score(output), Some(87.3));
    }

    #[test]
    fn test_parse_benchmark_score_no_match() {
        assert_eq!(super::parse_benchmark_score("no score here"), None);
        assert_eq!(super::parse_benchmark_score(""), None);
        assert_eq!(super::parse_benchmark_score("points: 100"), None);
    }

    #[test]
    fn test_parse_benchmark_score_edge_cases() {
        // Line too short after "score" - should not panic
        assert_eq!(super::parse_benchmark_score(r#""score""#), None);
        assert_eq!(super::parse_benchmark_score(r#""score":"#), None);
        // Valid short format
        assert_eq!(super::parse_benchmark_score(r#""score":5"#), Some(5.0));
    }

    #[test]
    fn failed_benchmark_requeues_only_below_the_failure_threshold() {
        use super::should_requeue_failed_benchmark as requeue;
        assert!(requeue(true, 1, 3));
        assert!(requeue(true, 2, 3));
        assert!(
            !requeue(true, 3, 3),
            "a persistently failing worker must stop looping"
        );
        assert!(!requeue(false, 1, 3));
        assert!(
            !requeue(true, 1, 0),
            "a zero threshold still bounds retries"
        );
    }

    #[test]
    fn scheduled_benchmark_backoff_grows_and_is_capped() {
        use super::failure_backoff;
        let cap = Duration::from_secs(6 * 3600);
        let minutes = |m: u64| Some(Duration::from_secs(m * 60));
        assert_eq!(failure_backoff(2, 3, cap), None);
        assert_eq!(failure_backoff(3, 3, cap), minutes(10));
        assert_eq!(failure_backoff(4, 3, cap), minutes(20));
        assert_eq!(failure_backoff(40, 3, cap), Some(cap));
    }

    #[test]
    fn test_is_retryable_error_timeouts() {
        assert!(super::is_retryable_error("connection timed out"));
        assert!(super::is_retryable_error("Timeout waiting for response"));
        assert!(super::is_retryable_error("Operation timed out"));
    }

    #[test]
    fn test_is_retryable_error_network() {
        assert!(super::is_retryable_error("Connection refused by host"));
        assert!(super::is_retryable_error("connection reset by peer"));
        assert!(super::is_retryable_error("No route to host"));
        assert!(super::is_retryable_error("Network unreachable"));
        assert!(super::is_retryable_error("Broken pipe"));
    }

    #[test]
    fn test_is_retryable_error_ssh() {
        assert!(super::is_retryable_error(
            "ssh_exchange_identification failed"
        ));
        assert!(super::is_retryable_error(
            "Connection closed by remote host"
        ));
    }

    #[test]
    fn test_is_retryable_error_not_retryable() {
        assert!(!super::is_retryable_error("Permission denied"));
        assert!(!super::is_retryable_error("File not found"));
        assert!(!super::is_retryable_error("Invalid command"));
        assert!(!super::is_retryable_error("Authentication failed"));
    }

    // ==================== Drift Detection Tests ====================

    use rch_telemetry::collect::cpu::{CpuTelemetry, LoadAverage};
    use rch_telemetry::collect::memory::MemoryTelemetry;
    use rch_telemetry::protocol::{TelemetrySource, WorkerTelemetry};
    use rch_telemetry::speedscore::{BenchmarkConditions, SpeedScore};

    /// Build a WorkerTelemetry with specific CPU, memory, and load values.
    fn make_telemetry_with_load(
        worker_id: &str,
        cpu_pct: f64,
        mem_pct: f64,
        load_1m: f64,
    ) -> WorkerTelemetry {
        let cpu = CpuTelemetry {
            timestamp: Utc::now(),
            overall_percent: cpu_pct,
            per_core_percent: vec![cpu_pct],
            num_cores: 4,
            load_average: LoadAverage {
                one_min: load_1m,
                five_min: load_1m * 0.8,
                fifteen_min: load_1m * 0.6,
                running_processes: 2,
                total_processes: 200,
            },
            psi: None,
        };
        let memory = MemoryTelemetry {
            timestamp: Utc::now(),
            total_gb: 32.0,
            available_gb: 32.0 * (1.0 - mem_pct / 100.0),
            used_percent: mem_pct,
            pressure_score: mem_pct,
            swap_used_gb: 0.0,
            dirty_mb: 0.0,
            psi: None,
        };
        WorkerTelemetry::new(worker_id.to_string(), cpu, memory, None, None, 1)
    }

    #[test]
    fn test_benchmark_admission_requires_fresh_safe_telemetry() {
        let mut capabilities = WorkerCapabilities {
            disk_free_gb: Some(50.0),
            disk_total_gb: Some(100.0),
            ..WorkerCapabilities::default()
        };
        let fresh = ReceivedTelemetry::new(
            make_telemetry_with_load("admission", 10.0, 30.0, 0.5),
            TelemetrySource::SshPoll,
        );
        let threshold = SchedulerConfig::default().idle_cpu_threshold;
        assert!(benchmark_telemetry_allows_start(
            &capabilities,
            Some(&fresh),
            threshold
        ));
        assert!(!benchmark_telemetry_allows_start(
            &capabilities,
            None,
            threshold
        ));

        let mut stale = fresh.clone();
        stale.received_at = Utc::now() - ChronoDuration::seconds(91);
        assert!(!benchmark_telemetry_allows_start(
            &capabilities,
            Some(&stale),
            threshold
        ));
        for cpu in [21.0, f64::NAN, f64::INFINITY, -1.0] {
            let mut busy = fresh.clone();
            busy.telemetry.cpu.overall_percent = cpu;
            assert!(!benchmark_telemetry_allows_start(
                &capabilities,
                Some(&busy),
                threshold
            ));
        }
        for memory in [92.0, 100.0, f64::NAN, f64::INFINITY, -1.0] {
            let mut pressured = fresh.clone();
            pressured.telemetry.memory.pressure_score = memory;
            assert!(!benchmark_telemetry_allows_start(
                &capabilities,
                Some(&pressured),
                threshold
            ));
        }
        capabilities.disk_free_gb = Some(1.0);
        assert!(!benchmark_telemetry_allows_start(
            &capabilities,
            Some(&fresh),
            threshold
        ));
        capabilities.disk_free_gb = None;
        assert!(!benchmark_telemetry_allows_start(
            &capabilities,
            Some(&fresh),
            threshold
        ));
        capabilities.disk_free_gb = Some(20.0);
        assert!(
            benchmark_telemetry_allows_start(&capabilities, Some(&fresh), threshold),
            "noncritical warning pressure retains the existing admission threshold"
        );
    }

    #[tokio::test]
    async fn test_new_worker_benchmark_waits_for_telemetry() {
        let pool = WorkerPool::new();
        let worker_id = WorkerId::new("startup-admission");
        pool.add_worker(make_worker_config(worker_id.as_str()))
            .await;
        let worker = pool.get(&worker_id).await.unwrap();
        worker
            .set_capabilities(WorkerCapabilities {
                disk_free_gb: Some(50.0),
                disk_total_gb: Some(100.0),
                ..WorkerCapabilities::default()
            })
            .await;
        let telemetry = Arc::new(TelemetryStore::new(Duration::from_secs(300), None));
        let (scheduler, _handle) = BenchmarkScheduler::new(
            make_test_config(),
            pool,
            telemetry.clone(),
            EventBus::new(16),
        );
        let request = ScheduledBenchmarkRequest::new(
            worker_id.clone(),
            BenchmarkPriority::High,
            BenchmarkReason::NewWorker,
        );
        scheduler.enqueue(request.clone()).await;
        scheduler.process_pending_queue().await;
        assert_eq!(scheduler.pending_count().await, 1);
        assert_eq!(scheduler.running_count().await, 0);
        assert_eq!(worker.available_slots().await, 4);
        assert!(!scheduler.is_worker_eligible(&worker_id).await);

        telemetry.ingest(
            make_telemetry_with_load(worker_id.as_str(), 10.0, 30.0, 0.5),
            TelemetrySource::SshPoll,
        );
        assert!(scheduler.is_worker_eligible(&worker_id).await);
        assert!(worker.reserve_slots(4).await);
        assert!(!scheduler.is_worker_eligible(&worker_id).await);
        worker.release_slots(4).await;
        assert!(scheduler.is_worker_eligible(&worker_id).await);

        telemetry.ingest(
            make_telemetry_with_load(worker_id.as_str(), 10.0, 100.0, 0.5),
            TelemetrySource::SshPoll,
        );
        // The request was eligible at selection, then pressure worsened before
        // dispatch. The start boundary must requeue it without reserving a slot.
        scheduler.pending_queue.lock().await.clear();
        scheduler.start_benchmark(request).await;
        assert_eq!(scheduler.pending_count().await, 1);
        assert_eq!(scheduler.running_count().await, 0);
        assert_eq!(worker.available_slots().await, 4);
    }

    #[tokio::test]
    async fn replacement_benchmark_waits_for_its_own_telemetry() {
        let pool = WorkerPool::new();
        let worker_id = WorkerId::new("replacement-benchmark");
        pool.add_worker(make_worker_config(worker_id.as_str()))
            .await;
        let worker = pool.get(&worker_id).await.unwrap();
        let capabilities = WorkerCapabilities {
            disk_free_gb: Some(50.0),
            disk_total_gb: Some(100.0),
            ..WorkerCapabilities::default()
        };
        worker.set_capabilities(capabilities.clone()).await;
        let telemetry = Arc::new(TelemetryStore::new(Duration::from_secs(300), None));
        let (scheduler, _handle) = BenchmarkScheduler::new(
            make_test_config(),
            pool,
            telemetry.clone(),
            EventBus::new(16),
        );
        let sample = make_telemetry_with_load(worker_id.as_str(), 10.0, 30.0, 0.5);
        let before = worker.endpoint_snapshot().await;
        telemetry.ingest_for_endpoint(sample.clone(), TelemetrySource::SshPoll, &before);
        assert!(scheduler.is_worker_eligible(&worker_id).await);

        let mut replacement = before.config;
        replacement.host = "replacement.host".to_string();
        assert!(worker.update_config(replacement).await);
        worker
            .apply_health_status(rch_common::WorkerStatus::Healthy)
            .await;
        worker.set_capabilities(capabilities).await;
        assert!(!scheduler.is_worker_eligible(&worker_id).await);
        telemetry.ingest(sample.clone(), TelemetrySource::Piggyback);
        assert!(!scheduler.is_worker_eligible(&worker_id).await);

        let current = worker.endpoint_snapshot().await;
        telemetry.ingest_for_endpoint(sample, TelemetrySource::SshPoll, &current);
        assert!(scheduler.is_worker_eligible(&worker_id).await);
        telemetry.ingest(
            make_telemetry_with_load(worker_id.as_str(), 100.0, 100.0, 100.0),
            TelemetrySource::Piggyback,
        );
        assert!(
            scheduler.is_worker_eligible(&worker_id).await,
            "an unbound update cannot replace current endpoint evidence"
        );
    }

    /// Build a SpeedScore with attached BenchmarkConditions.
    fn make_score_with_conditions(cpu_pct: f64, mem_pct: f64, load_1m: f64) -> SpeedScore {
        SpeedScore::default().with_conditions(BenchmarkConditions {
            cpu_percent: cpu_pct,
            memory_used_percent: mem_pct,
            load_1m,
        })
    }

    #[tokio::test]
    async fn test_detect_drift_no_conditions_returns_none() {
        let pool = WorkerPool::new();
        pool.add_worker(make_worker_config("drift-none")).await;
        let telemetry = Arc::new(TelemetryStore::new(Duration::from_secs(300), None));
        let events = EventBus::new(16);

        // Ingest current telemetry
        telemetry.ingest(
            make_telemetry_with_load("drift-none", 80.0, 70.0, 4.0),
            TelemetrySource::SshPoll,
        );

        let (scheduler, _handle) =
            BenchmarkScheduler::new(make_test_config(), pool.clone(), telemetry, events);

        let worker = pool.get(&WorkerId::new("drift-none")).await.unwrap();
        let score = SpeedScore::default(); // No benchmark_conditions

        let result = scheduler.detect_drift(&worker, &score).await;
        assert!(
            result.is_none(),
            "Should return None when no conditions recorded"
        );
    }

    #[tokio::test]
    async fn test_detect_drift_no_telemetry_returns_none() {
        let pool = WorkerPool::new();
        pool.add_worker(make_worker_config("drift-notel")).await;
        let telemetry = Arc::new(TelemetryStore::new(Duration::from_secs(300), None));
        let events = EventBus::new(16);

        // No telemetry ingested

        let (scheduler, _handle) =
            BenchmarkScheduler::new(make_test_config(), pool.clone(), telemetry, events);

        let worker = pool.get(&WorkerId::new("drift-notel")).await.unwrap();
        let score = make_score_with_conditions(10.0, 30.0, 0.5);

        let result = scheduler.detect_drift(&worker, &score).await;
        assert!(
            result.is_none(),
            "Should return None when no current telemetry"
        );
    }

    #[tokio::test]
    async fn test_detect_drift_conditions_worsened() {
        let pool = WorkerPool::new();
        pool.add_worker(make_worker_config("drift-worse")).await;
        let telemetry = Arc::new(TelemetryStore::new(Duration::from_secs(300), None));
        let events = EventBus::new(16);

        // Benchmark was taken at low load; current load is much higher
        telemetry.ingest(
            make_telemetry_with_load("drift-worse", 80.0, 70.0, 6.0),
            TelemetrySource::SshPoll,
        );

        let mut config = make_test_config();
        config.drift_threshold_pct = 20.0;
        let (scheduler, _handle) = BenchmarkScheduler::new(config, pool.clone(), telemetry, events);

        let worker = pool.get(&WorkerId::new("drift-worse")).await.unwrap();
        // Benchmark was at CPU 10%, mem 30%, load 0.5
        let score = make_score_with_conditions(10.0, 30.0, 0.5);

        let result = scheduler.detect_drift(&worker, &score).await;
        assert!(
            result.is_some(),
            "Should detect drift when conditions worsened significantly"
        );
        let drift = result.unwrap();
        assert!(
            drift >= 20.0,
            "Drift should exceed threshold, got {}",
            drift
        );
    }

    #[tokio::test]
    async fn test_detect_drift_conditions_improved_returns_none() {
        let pool = WorkerPool::new();
        pool.add_worker(make_worker_config("drift-better")).await;
        let telemetry = Arc::new(TelemetryStore::new(Duration::from_secs(300), None));
        let events = EventBus::new(16);

        // Benchmark was taken at high load; current load is much lower
        telemetry.ingest(
            make_telemetry_with_load("drift-better", 10.0, 30.0, 0.5),
            TelemetrySource::SshPoll,
        );

        let (scheduler, _handle) =
            BenchmarkScheduler::new(make_test_config(), pool.clone(), telemetry, events);

        let worker = pool.get(&WorkerId::new("drift-better")).await.unwrap();
        // Benchmark was at CPU 80%, mem 70%, load 6.0
        let score = make_score_with_conditions(80.0, 70.0, 6.0);

        let result = scheduler.detect_drift(&worker, &score).await;
        assert!(
            result.is_none(),
            "Should not flag drift when conditions improved"
        );
    }

    #[tokio::test]
    async fn test_detect_drift_conditions_unchanged_returns_none() {
        let pool = WorkerPool::new();
        pool.add_worker(make_worker_config("drift-same")).await;
        let telemetry = Arc::new(TelemetryStore::new(Duration::from_secs(300), None));
        let events = EventBus::new(16);

        // Current conditions match benchmark-time conditions
        telemetry.ingest(
            make_telemetry_with_load("drift-same", 30.0, 40.0, 1.0),
            TelemetrySource::SshPoll,
        );

        let (scheduler, _handle) =
            BenchmarkScheduler::new(make_test_config(), pool.clone(), telemetry, events);

        let worker = pool.get(&WorkerId::new("drift-same")).await.unwrap();
        let score = make_score_with_conditions(30.0, 40.0, 1.0);

        let result = scheduler.detect_drift(&worker, &score).await;
        assert!(
            result.is_none(),
            "Should not flag drift when conditions are stable"
        );
    }

    #[tokio::test]
    async fn test_detect_drift_idle_benchmark_no_false_positive() {
        // This is the exact scenario that broke the old heuristic:
        // worker was idle during benchmark AND is still idle now.
        let pool = WorkerPool::new();
        pool.add_worker(make_worker_config("drift-idle")).await;
        let telemetry = Arc::new(TelemetryStore::new(Duration::from_secs(300), None));
        let events = EventBus::new(16);

        // Both benchmark and current: idle
        telemetry.ingest(
            make_telemetry_with_load("drift-idle", 0.5, 15.0, 0.01),
            TelemetrySource::SshPoll,
        );

        let (scheduler, _handle) =
            BenchmarkScheduler::new(make_test_config(), pool.clone(), telemetry, events);

        let worker = pool.get(&WorkerId::new("drift-idle")).await.unwrap();
        let score = make_score_with_conditions(0.5, 15.0, 0.01);

        let result = scheduler.detect_drift(&worker, &score).await;
        assert!(
            result.is_none(),
            "Must not re-benchmark idle workers (old bug)"
        );
    }

    #[tokio::test]
    async fn test_detect_drift_below_threshold_returns_none() {
        let pool = WorkerPool::new();
        pool.add_worker(make_worker_config("drift-small")).await;
        let telemetry = Arc::new(TelemetryStore::new(Duration::from_secs(300), None));
        let events = EventBus::new(16);

        // Small increase: CPU 10→15, mem 30→32, load 0.5→0.6
        // composite = (15-10)*0.5 + (32-30)*0.2 + ((0.6-0.5)/0.5*100)*0.3
        //           = 2.5 + 0.4 + 6.0 = 8.9 → below 20% threshold
        telemetry.ingest(
            make_telemetry_with_load("drift-small", 15.0, 32.0, 0.6),
            TelemetrySource::SshPoll,
        );

        let mut config = make_test_config();
        config.drift_threshold_pct = 20.0;
        let (scheduler, _handle) = BenchmarkScheduler::new(config, pool.clone(), telemetry, events);

        let worker = pool.get(&WorkerId::new("drift-small")).await.unwrap();
        let score = make_score_with_conditions(10.0, 30.0, 0.5);

        let result = scheduler.detect_drift(&worker, &score).await;
        assert!(
            result.is_none(),
            "Small drift below threshold should not trigger re-benchmark"
        );
    }

    #[test]
    fn test_benchmark_conditions_serialization() {
        let conditions = BenchmarkConditions {
            cpu_percent: 25.5,
            memory_used_percent: 45.0,
            load_1m: 1.2,
        };

        let json = serde_json::to_string(&conditions).unwrap();
        let deser: BenchmarkConditions = serde_json::from_str(&json).unwrap();

        assert!((deser.cpu_percent - 25.5).abs() < 0.01);
        assert!((deser.memory_used_percent - 45.0).abs() < 0.01);
        assert!((deser.load_1m - 1.2).abs() < 0.01);
    }

    #[test]
    fn test_speedscore_with_conditions_roundtrip() {
        let score = make_score_with_conditions(30.0, 50.0, 2.0);

        // Verify conditions attached
        assert!(score.benchmark_conditions.is_some());
        let cond = score.benchmark_conditions.as_ref().unwrap();
        assert!((cond.cpu_percent - 30.0).abs() < 0.01);

        // Serialize and deserialize
        let json = serde_json::to_string(&score).unwrap();
        let deser: SpeedScore = serde_json::from_str(&json).unwrap();
        assert!(deser.benchmark_conditions.is_some());
    }

    #[test]
    fn test_speedscore_without_conditions_backwards_compat() {
        // Simulate a legacy score JSON without benchmark_conditions field
        let legacy_json = r#"{
            "total": 75.0,
            "cpu_score": 80.0,
            "memory_score": 70.0,
            "disk_score": 65.0,
            "network_score": 60.0,
            "compilation_score": 75.0,
            "weights": {"cpu": 0.3, "memory": 0.15, "disk": 0.2, "network": 0.15, "compilation": 0.2},
            "calculated_at": "2026-01-15T12:00:00Z",
            "version": 1
        }"#;

        let score: SpeedScore = serde_json::from_str(legacy_json).unwrap();
        assert!(
            score.benchmark_conditions.is_none(),
            "Legacy scores without conditions should deserialize with None"
        );
    }
}
