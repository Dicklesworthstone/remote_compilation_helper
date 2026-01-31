//! Worker pool management.

#![allow(dead_code)] // Scaffold code - methods will be used in future beads

use rch_common::{
    CircuitBreakerConfig, CircuitState, CircuitStats, WorkerCapabilities, WorkerConfig, WorkerId,
    WorkerStatus,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use tokio::sync::RwLock;
use tracing::debug;

/// State of a single worker.
#[derive(Debug)]
pub struct WorkerState {
    /// Worker configuration.
    pub config: RwLock<WorkerConfig>,
    /// Current status (uses RwLock for interior mutability).
    status: RwLock<WorkerStatus>,
    /// Number of slots currently in use.
    used_slots: Arc<AtomicU32>,
    /// Speed score from benchmarking (0-100).
    ///
    /// **Why atomic:** Read on every worker selection decision (hot path). RwLock's
    /// ~25ns overhead per acquire multiplied by N workers is measurable; AtomicU64
    /// load compiles to a single MOV instruction (~1ns).
    ///
    /// **Bit-casting:** `f64` is stored as `u64` via `f64::to_bits`/`f64::from_bits`.
    /// This is a zero-cost transmute that preserves all IEEE 754 values including
    /// NaN, infinity, and negative zero.
    ///
    /// **Ordering:** `Relaxed` — speed_score is a statistical performance hint, not
    /// a correctness-critical flag. Stale reads produce slightly suboptimal worker
    /// selection, never incorrect behavior. No happens-before dependency with other
    /// fields (status transitions use RwLock which provides its own ordering).
    pub speed_score: AtomicU64,
    /// Last observed worker latency in milliseconds (from health checks).
    ///
    /// **Why atomic:** Same hot-path rationale as `speed_score`.
    ///
    /// **Sentinel:** `0` encodes `None` (latency of exactly 0ms is not meaningful
    /// in practice). Use `last_latency_ms()` accessor which returns `Option<u64>`.
    ///
    /// **Ordering:** `Relaxed` — advisory diagnostic value with no ordering
    /// dependency. See `speed_score` rationale.
    last_latency_ms: AtomicU64,
    /// Projects cached on this worker.
    pub cached_projects: RwLock<Vec<String>>,
    /// Circuit breaker statistics.
    circuit: RwLock<CircuitStats>,
    /// Last error message.
    last_error_msg: RwLock<Option<String>>,
    /// Runtime capabilities (Bun, Node, Rust versions).
    capabilities: RwLock<WorkerCapabilities>,
    /// Reason for disabling this worker (if disabled).
    disabled_reason: RwLock<Option<String>>,
    /// Unix timestamp (seconds since epoch) when worker was disabled.
    ///
    /// **Why atomic:** Queried during worker selection to skip disabled workers.
    ///
    /// **Sentinel:** `0` encodes `None` (no disable event). Use `disabled_at()`
    /// accessor which returns `Option<i64>`.
    ///
    /// **Ordering:** `Relaxed` — diagnostic timestamp set alongside `status`
    /// (RwLock) and `disabled_reason` (RwLock). The RwLock transitions provide
    /// happens-before ordering for the authoritative disabled state; this timestamp
    /// is supplementary. Briefly stale reads are acceptable for display purposes.
    disabled_at: AtomicI64,
}

impl WorkerState {
    /// Create a new worker state from configuration.
    pub fn new(config: WorkerConfig) -> Self {
        Self {
            config: RwLock::new(config),
            status: RwLock::new(WorkerStatus::Healthy),
            used_slots: Arc::new(AtomicU32::new(0)),
            speed_score: AtomicU64::new(50.0_f64.to_bits()), // Default mid-range score
            last_latency_ms: AtomicU64::new(0),
            cached_projects: RwLock::new(Vec::new()),
            circuit: RwLock::new(CircuitStats::new()),
            last_error_msg: RwLock::new(None),
            capabilities: RwLock::new(WorkerCapabilities::new()),
            disabled_reason: RwLock::new(None),
            disabled_at: AtomicI64::new(0),
        }
    }

    /// Update worker configuration.
    pub async fn update_config(&self, new_config: WorkerConfig) {
        let mut config = self.config.write().await;
        *config = new_config;
    }

    /// Get current worker status.
    pub async fn status(&self) -> WorkerStatus {
        *self.status.read().await
    }

    /// Set worker status.
    pub async fn set_status(&self, status: WorkerStatus) {
        *self.status.write().await = status;
    }

    /// Get the number of available slots.
    pub async fn available_slots(&self) -> u32 {
        let used = self.used_slots.load(Ordering::Relaxed);
        let total = self.config.read().await.total_slots;
        total.saturating_sub(used)
    }

    /// Reserve slots for a job. Returns true if successful.
    ///
    /// Re-reads total_slots on each CAS iteration to handle concurrent config changes.
    /// This prevents overallocation if total_slots is reduced while reserving.
    pub async fn reserve_slots(&self, count: u32) -> bool {
        let mut current = self.used_slots.load(Ordering::Relaxed);
        loop {
            // Re-read total_slots on each iteration to handle concurrent config changes.
            // This is safe because CAS loops typically succeed in 1-2 iterations.
            let total_slots = self.config.read().await.total_slots;
            if current + count > total_slots {
                return false;
            }
            match self.used_slots.compare_exchange(
                current,
                current + count,
                Ordering::SeqCst,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
    }

    /// Release slots after a job completes.
    ///
    /// If the worker is in `Draining` state and all slots are now free,
    /// automatically transitions to `Drained` state.
    pub async fn release_slots(&self, count: u32) {
        let mut current = self.used_slots.load(Ordering::Relaxed);
        loop {
            let new_val = current.saturating_sub(count);

            if count > current {
                let id = self.config.read().await.id.clone();
                tracing::warn!(
                    "Worker {}: attempted to release {} slots but only {} in use",
                    id,
                    count,
                    current
                );
            }

            match self.used_slots.compare_exchange(
                current,
                new_val,
                Ordering::SeqCst,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }

        // Check if draining worker should transition to drained
        self.check_drain_complete().await;
    }

    /// Check if this worker has a cached copy of a project.
    pub async fn has_cached_project(&self, project: &str) -> bool {
        self.cached_projects
            .read()
            .await
            .iter()
            .any(|p| p == project)
    }

    /// Add a project to the cache list.
    pub async fn add_cached_project(&self, project: String) {
        let mut cache = self.cached_projects.write().await;
        if !cache.contains(&project) {
            // Limit cache size to prevent unbounded growth
            if cache.len() >= 100 {
                cache.remove(0);
            }
            cache.push(project);
        }
    }

    /// Update the speed score.
    pub fn set_speed_score(&self, score: f64) {
        self.speed_score.store(score.to_bits(), Ordering::Relaxed);
    }

    /// Get the current speed score.
    pub fn get_speed_score(&self) -> f64 {
        f64::from_bits(self.speed_score.load(Ordering::Relaxed))
    }

    /// Update the last observed worker latency (ms).
    pub fn set_last_latency_ms(&self, latency_ms: Option<u64>) {
        self.last_latency_ms
            .store(latency_ms.unwrap_or(0), Ordering::Relaxed);
    }

    /// Get the last observed worker latency (ms).
    pub fn last_latency_ms(&self) -> Option<u64> {
        let v = self.last_latency_ms.load(Ordering::Relaxed);
        if v == 0 { None } else { Some(v) }
    }

    /// Get the current circuit breaker state.
    pub async fn circuit_state(&self) -> Option<CircuitState> {
        Some(self.circuit.read().await.state())
    }

    /// Get the circuit stats (for internal use).
    pub async fn circuit_stats(&self) -> CircuitStats {
        self.circuit.read().await.clone()
    }

    /// Record a successful operation for circuit breaker.
    pub async fn record_success(&self) {
        let mut circuit = self.circuit.write().await;
        circuit.record_success();
    }

    /// Record a failed operation for circuit breaker.
    pub async fn record_failure(&self, error_msg: Option<String>) {
        let mut circuit = self.circuit.write().await;
        circuit.record_failure();

        if let Some(msg) = error_msg {
            *self.last_error_msg.write().await = Some(msg);
        }
    }

    /// Check if circuit should open based on config.
    pub async fn should_open_circuit(&self, config: &CircuitBreakerConfig) -> bool {
        self.circuit.read().await.should_open(config)
    }

    /// Check if circuit should transition to half-open.
    pub async fn should_half_open(&self, config: &CircuitBreakerConfig) -> bool {
        self.circuit.read().await.should_half_open(config)
    }

    /// Check if circuit should close.
    pub async fn should_close_circuit(&self, config: &CircuitBreakerConfig) -> bool {
        self.circuit.read().await.should_close(config)
    }

    /// Check if we can send a probe request.
    pub async fn can_probe(&self, config: &CircuitBreakerConfig) -> bool {
        self.circuit.read().await.can_probe(config)
    }

    /// Start a probe request.
    pub async fn start_probe(&self, config: &CircuitBreakerConfig) -> bool {
        self.circuit.write().await.start_probe(config)
    }

    /// Open the circuit.
    pub async fn open_circuit(&self) {
        self.circuit.write().await.open();
    }

    /// Transition to half-open.
    pub async fn half_open_circuit(&self) {
        self.circuit.write().await.half_open();
    }

    /// Close the circuit.
    pub async fn close_circuit(&self) {
        self.circuit.write().await.close();
        // Clear last error on circuit close
        *self.last_error_msg.write().await = None;
    }

    /// Get the last error message.
    pub async fn last_error(&self) -> Option<String> {
        self.last_error_msg.read().await.clone()
    }

    /// Set an error message.
    pub async fn set_error(&self, msg: String) {
        *self.last_error_msg.write().await = Some(msg);
    }

    /// Update worker capabilities.
    pub async fn set_capabilities(&self, capabilities: WorkerCapabilities) {
        *self.capabilities.write().await = capabilities;
    }

    /// Get worker capabilities.
    pub async fn capabilities(&self) -> WorkerCapabilities {
        self.capabilities.read().await.clone()
    }

    /// Check if this worker has Bun installed.
    pub async fn has_bun(&self) -> bool {
        self.capabilities.read().await.has_bun()
    }

    /// Check if this worker has Node.js installed.
    pub async fn has_node(&self) -> bool {
        self.capabilities.read().await.has_node()
    }

    /// Check if this worker has Rust installed.
    pub async fn has_rust(&self) -> bool {
        self.capabilities.read().await.has_rust()
    }

    /// Disable the worker with an optional reason.
    /// Sets status to Disabled and records the timestamp and reason.
    pub async fn disable(&self, reason: Option<String>) {
        *self.status.write().await = WorkerStatus::Disabled;
        *self.disabled_reason.write().await = reason;
        self.disabled_at.store(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(1), // Use 1 instead of 0 to avoid None sentinel
            Ordering::Relaxed,
        );
    }

    /// Start draining the worker (no new jobs, but finish existing).
    pub async fn drain(&self) {
        *self.status.write().await = WorkerStatus::Draining;
    }

    /// Enable a previously disabled/draining worker.
    /// Clears disabled reason and timestamp, sets status to Healthy.
    pub async fn enable(&self) {
        *self.status.write().await = WorkerStatus::Healthy;
        *self.disabled_reason.write().await = None;
        self.disabled_at.store(0, Ordering::Relaxed);
    }

    /// Check if worker is disabled.
    pub async fn is_disabled(&self) -> bool {
        *self.status.read().await == WorkerStatus::Disabled
    }

    /// Check if worker is draining.
    pub async fn is_draining(&self) -> bool {
        *self.status.read().await == WorkerStatus::Draining
    }

    /// Check if worker is drained (drain complete, no active jobs).
    pub async fn is_drained(&self) -> bool {
        *self.status.read().await == WorkerStatus::Drained
    }

    /// Check if draining worker has completed all jobs and should transition to Drained.
    /// Called when a job completes; auto-transitions Draining → Drained when no jobs remain.
    /// Uses a single write lock to avoid TOCTOU race between read and write.
    pub async fn check_drain_complete(&self) {
        let mut status = self.status.write().await;
        if *status == WorkerStatus::Draining {
            // Use Acquire ordering to ensure we see any concurrent reserve_slots writes.
            // This prevents a race where we transition to Drained while another thread
            // has just reserved slots (their SeqCst write must happen-before our read).
            let used = self.used_slots.load(Ordering::Acquire);
            if used == 0 {
                *status = WorkerStatus::Drained;
            }
        }
    }

    /// Get the reason this worker was disabled (if any).
    pub async fn disabled_reason(&self) -> Option<String> {
        self.disabled_reason.read().await.clone()
    }

    /// Get the timestamp when this worker was disabled (Unix seconds).
    pub fn disabled_at(&self) -> Option<i64> {
        let v = self.disabled_at.load(Ordering::Relaxed);
        if v == 0 { None } else { Some(v) }
    }

    /// Get the number of slots currently in use.
    pub fn used_slots(&self) -> u32 {
        self.used_slots.load(Ordering::Relaxed)
    }
}

/// Pool of all workers.
#[derive(Clone)]
pub struct WorkerPool {
    workers: Arc<RwLock<HashMap<WorkerId, Arc<WorkerState>>>>,
    /// Track worker count atomically for sync access.
    worker_count: Arc<AtomicUsize>,
}

impl WorkerPool {
    /// Create a new empty worker pool.
    pub fn new() -> Self {
        Self {
            workers: Arc::new(RwLock::new(HashMap::new())),
            worker_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Add a worker to the pool.
    pub async fn add_worker(&self, config: WorkerConfig) {
        let id = config.id.clone();

        {
            let workers = self.workers.read().await;
            if let Some(existing) = workers.get(&id) {
                debug!("Updating existing worker: {}", id);
                existing.update_config(config).await;
                return;
            }
        }

        let state = Arc::new(WorkerState::new(config));
        let mut workers = self.workers.write().await;
        // Check again under write lock
        if let Some(existing) = workers.get(&id) {
            // Race condition: added between read and write lock
            // Just update config on the existing one, drop the new state
            let config = state.config.read().await.clone();
            existing.update_config(config).await;
        } else {
            workers.insert(id.clone(), state);
            self.worker_count.fetch_add(1, Ordering::SeqCst);
            debug!("Added worker: {}", id);
        }
    }

    /// Add a worker with a pre-configured state (for testing).
    #[cfg(test)]
    pub async fn add_worker_state(&self, state: WorkerState) {
        let id = state.config.read().await.id.clone();
        let mut workers = self.workers.write().await;
        if workers.insert(id.clone(), Arc::new(state)).is_none() {
            self.worker_count.fetch_add(1, Ordering::SeqCst);
        }
        debug!("Added worker: {}", id);
    }

    /// Remove a worker from the pool.
    pub async fn remove_worker(&self, id: &WorkerId) -> bool {
        let mut workers = self.workers.write().await;
        if workers.remove(id).is_some() {
            self.worker_count.fetch_sub(1, Ordering::SeqCst);
            debug!("Removed worker: {}", id);
            true
        } else {
            false
        }
    }

    /// Prune workers that are in Draining or Drained state and have no active slots.
    ///
    /// Returns the number of workers removed.
    pub async fn prune_drained(&self) -> usize {
        let mut workers = self.workers.write().await;
        let mut to_remove = Vec::new();

        for (id, worker) in workers.iter() {
            let status = worker.status().await;
            let is_draining_or_drained =
                status == WorkerStatus::Draining || status == WorkerStatus::Drained;

            if is_draining_or_drained && worker.used_slots() == 0 {
                to_remove.push(id.clone());
            }
        }

        let count = to_remove.len();
        for id in to_remove {
            workers.remove(&id);
            debug!("Pruned drained worker: {}", id);
        }

        if count > 0 {
            self.worker_count.fetch_sub(count, Ordering::SeqCst);
        }

        count
    }

    /// Get the number of workers in the pool.
    pub fn len(&self) -> usize {
        self.worker_count.load(Ordering::SeqCst)
    }

    /// Check if pool is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get all workers (regardless of status) for health monitoring.
    pub async fn all_workers(&self) -> Vec<Arc<WorkerState>> {
        let workers = self.workers.read().await;
        workers.values().cloned().collect()
    }

    /// Get all healthy workers (for job assignment).
    ///
    /// Includes workers with status Healthy or Degraded.
    pub async fn healthy_workers(&self) -> Vec<Arc<WorkerState>> {
        let workers = self.workers.read().await;
        let mut healthy = Vec::new();
        for worker in workers.values() {
            let status = worker.status().await;
            if status == WorkerStatus::Healthy || status == WorkerStatus::Degraded {
                healthy.push(worker.clone());
            }
        }
        healthy
    }

    /// Get a worker by ID.
    pub async fn get(&self, id: &WorkerId) -> Option<Arc<WorkerState>> {
        let workers = self.workers.read().await;
        workers.get(id).cloned()
    }

    /// Update worker status.
    pub async fn set_status(&self, id: &WorkerId, status: WorkerStatus) {
        let workers = self.workers.read().await;
        if let Some(worker) = workers.get(id) {
            worker.set_status(status).await;
            debug!("Set {} status to {:?}", id, status);
        }
    }

    /// Release reserved slots on a worker.
    pub async fn release_slots(&self, id: &WorkerId, slots: u32) {
        let workers = self.workers.read().await;
        if let Some(worker) = workers.get(id) {
            worker.release_slots(slots).await;
            debug!("Released {} slots on worker {}", slots, id);
        } else {
            debug!("Worker {} not found, cannot release slots", id);
        }
    }
}

impl Default for WorkerPool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a test worker config with given id.
    fn test_config(id: &str) -> WorkerConfig {
        WorkerConfig {
            id: WorkerId::new(id),
            host: "localhost".to_string(),
            user: "user".to_string(),
            identity_file: "~/.ssh/id_rsa".to_string(),
            total_slots: 8,
            priority: 100,
            tags: vec![],
        }
    }

    // ============== WorkerState Tests ==============

    #[tokio::test]
    async fn test_worker_state_new_defaults() {
        let state = WorkerState::new(test_config("test-worker"));

        // Check default values
        assert_eq!(state.status().await, WorkerStatus::Healthy);
        assert_eq!(state.available_slots().await, 8);
        assert_eq!(state.used_slots(), 0);
        assert_eq!(state.get_speed_score(), 50.0);
        assert!(state.last_latency_ms().is_none());
        assert!(state.last_error().await.is_none());
        assert!(!state.is_disabled().await);
        assert!(!state.is_draining().await);
        assert!(state.disabled_reason().await.is_none());
        assert!(state.disabled_at().is_none());
    }

    // =========================================================================
    // WS3.4: Unit tests for atomic field accessors (bd-1gyl)
    //
    // Verify that AtomicU64/AtomicI64 accessors for speed_score,
    // last_latency_ms, and disabled_at correctly roundtrip values including
    // edge cases (NaN, infinity, zero sentinels).
    // =========================================================================

    // --- speed_score (AtomicU64 via f64::to_bits/from_bits) ---

    #[test]
    fn test_speed_score_roundtrip_normal_values() {
        let state = WorkerState::new(test_config("test"));

        // Default should be 50.0
        assert_eq!(state.get_speed_score(), 50.0);

        // Set and get various normal values
        state.set_speed_score(0.0);
        assert_eq!(state.get_speed_score(), 0.0);

        state.set_speed_score(1.0);
        assert_eq!(state.get_speed_score(), 1.0);

        state.set_speed_score(100.0);
        assert_eq!(state.get_speed_score(), 100.0);

        state.set_speed_score(99.5);
        assert_eq!(state.get_speed_score(), 99.5);

        // Negative score (shouldn't happen in practice, but verify roundtrip)
        state.set_speed_score(-1.0);
        assert_eq!(state.get_speed_score(), -1.0);
    }

    #[test]
    fn test_speed_score_roundtrip_extremes() {
        let state = WorkerState::new(test_config("test"));

        // f64::MAX
        state.set_speed_score(f64::MAX);
        assert_eq!(state.get_speed_score(), f64::MAX);

        // f64::MIN (most negative)
        state.set_speed_score(f64::MIN);
        assert_eq!(state.get_speed_score(), f64::MIN);

        // f64::MIN_POSITIVE (smallest positive)
        state.set_speed_score(f64::MIN_POSITIVE);
        assert_eq!(state.get_speed_score(), f64::MIN_POSITIVE);

        // f64::EPSILON
        state.set_speed_score(f64::EPSILON);
        assert_eq!(state.get_speed_score(), f64::EPSILON);
    }

    #[test]
    fn test_speed_score_roundtrip_special_float_values() {
        let state = WorkerState::new(test_config("test"));

        // Positive infinity
        state.set_speed_score(f64::INFINITY);
        assert_eq!(state.get_speed_score(), f64::INFINITY);

        // Negative infinity
        state.set_speed_score(f64::NEG_INFINITY);
        assert_eq!(state.get_speed_score(), f64::NEG_INFINITY);

        // NaN roundtrips via to_bits/from_bits (NaN != NaN, so check bits)
        state.set_speed_score(f64::NAN);
        let retrieved = state.get_speed_score();
        assert!(
            retrieved.is_nan(),
            "NaN should roundtrip via to_bits/from_bits"
        );
        assert_eq!(
            f64::NAN.to_bits(),
            retrieved.to_bits(),
            "NaN bit pattern should be preserved"
        );

        // Negative zero
        state.set_speed_score(-0.0_f64);
        let retrieved = state.get_speed_score();
        assert_eq!(retrieved, 0.0); // -0.0 == 0.0 in f64
        // But bit pattern differs from +0.0
        assert_eq!((-0.0_f64).to_bits(), retrieved.to_bits());
    }

    // --- last_latency_ms (AtomicU64 with 0 as None sentinel) ---

    #[test]
    fn test_last_latency_ms_none_default() {
        let state = WorkerState::new(test_config("test"));
        assert_eq!(state.last_latency_ms(), None);
    }

    #[test]
    fn test_last_latency_ms_roundtrip() {
        let state = WorkerState::new(test_config("test"));

        // Set Some value
        state.set_last_latency_ms(Some(100));
        assert_eq!(state.last_latency_ms(), Some(100));

        // Update to different value
        state.set_last_latency_ms(Some(250));
        assert_eq!(state.last_latency_ms(), Some(250));

        // Large value
        state.set_last_latency_ms(Some(u64::MAX));
        assert_eq!(state.last_latency_ms(), Some(u64::MAX));

        // Set back to None
        state.set_last_latency_ms(None);
        assert_eq!(state.last_latency_ms(), None);
    }

    #[test]
    fn test_last_latency_ms_zero_sentinel_behavior() {
        let state = WorkerState::new(test_config("test"));

        // Some(0) maps to None because 0 is the sentinel value.
        // This is documented behavior: 0ms latency is not meaningful.
        state.set_last_latency_ms(Some(0));
        assert_eq!(
            state.last_latency_ms(),
            None,
            "Some(0) should map to None (0 is sentinel for None)"
        );

        // Some(1) should work fine
        state.set_last_latency_ms(Some(1));
        assert_eq!(state.last_latency_ms(), Some(1));
    }

    // --- disabled_at (AtomicI64 with 0 as None sentinel) ---

    #[test]
    fn test_disabled_at_none_default() {
        let state = WorkerState::new(test_config("test"));
        assert_eq!(state.disabled_at(), None);
    }

    #[tokio::test]
    async fn test_disabled_at_set_on_disable() {
        let state = WorkerState::new(test_config("test"));

        // Initially None
        assert!(state.disabled_at().is_none());

        // Disabling the worker should set disabled_at
        state.disable(Some("test reason".to_string())).await;
        let ts = state.disabled_at();
        assert!(ts.is_some(), "disabled_at should be set after disable()");
        assert!(ts.unwrap() > 0, "timestamp should be positive");
    }

    #[tokio::test]
    async fn test_disabled_at_cleared_on_enable() {
        let state = WorkerState::new(test_config("test"));

        // Disable then enable
        state.disable(Some("test".to_string())).await;
        assert!(state.disabled_at().is_some());

        state.enable().await;
        assert_eq!(
            state.disabled_at(),
            None,
            "disabled_at should be None after enable()"
        );
    }

    // --- Concurrent access tests ---

    #[tokio::test]
    async fn test_speed_score_concurrent_updates() {
        let state = Arc::new(WorkerState::new(test_config("test")));
        let mut handles = vec![];

        // Spawn 10 tasks that each set a different speed score
        for i in 0..10u64 {
            let s = Arc::clone(&state);
            handles.push(tokio::spawn(async move {
                s.set_speed_score(i as f64 * 10.0);
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        // The final value should be one of the set values (last-write-wins)
        let score = state.get_speed_score();
        assert!(
            (0.0..=90.0).contains(&score) && score % 10.0 == 0.0,
            "Final speed score {} should be one of the written values",
            score
        );
    }

    #[tokio::test]
    async fn test_latency_concurrent_updates() {
        let state = Arc::new(WorkerState::new(test_config("test")));
        let mut handles = vec![];

        // Spawn tasks that set latency and None concurrently
        for i in 0..10u64 {
            let s = Arc::clone(&state);
            handles.push(tokio::spawn(async move {
                if i % 2 == 0 {
                    s.set_last_latency_ms(Some(i * 100 + 1)); // Avoid 0
                } else {
                    s.set_last_latency_ms(None);
                }
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        // Result should be valid (either None or a reasonable value)
        let latency = state.last_latency_ms();
        match latency {
            None => {} // Valid
            Some(v) => assert!(v <= 901, "Latency {} out of expected range", v),
        }
    }

    #[tokio::test]
    async fn test_disabled_at_concurrent_disable_enable() {
        let state = Arc::new(WorkerState::new(test_config("test")));
        let mut handles = vec![];

        for i in 0..10u32 {
            let s = Arc::clone(&state);
            handles.push(tokio::spawn(async move {
                if i % 2 == 0 {
                    s.disable(Some(format!("reason {i}"))).await;
                } else {
                    s.enable().await;
                }
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        // State should be consistent: if disabled, disabled_at is Some; if not, None
        let is_disabled = state.is_disabled().await;
        let disabled_at = state.disabled_at();
        if is_disabled {
            assert!(
                disabled_at.is_some(),
                "disabled worker should have disabled_at set"
            );
        }
        // Note: disabled_at might not be None when !is_disabled due to race
        // between status and atomic checks, which is acceptable for diagnostic data
    }

    #[tokio::test]
    async fn test_slot_reservation() {
        let config = WorkerConfig {
            id: WorkerId::new("test"),
            host: "localhost".to_string(),
            user: "user".to_string(),
            identity_file: "~/.ssh/id_rsa".to_string(),
            total_slots: 8,
            priority: 100,
            tags: vec![],
        };

        let state = WorkerState::new(config);
        assert_eq!(state.available_slots().await, 8);

        assert!(state.reserve_slots(4).await);
        assert_eq!(state.available_slots().await, 4);

        assert!(state.reserve_slots(4).await);
        assert_eq!(state.available_slots().await, 0);

        assert!(!state.reserve_slots(1).await); // Should fail

        state.release_slots(4).await;
        assert_eq!(state.available_slots().await, 4);
    }

    #[tokio::test]
    async fn test_slot_reservation_exact_boundary() {
        let state = WorkerState::new(test_config("test"));

        // Reserve exactly all slots
        assert!(state.reserve_slots(8).await);
        assert_eq!(state.available_slots().await, 0);
        assert_eq!(state.used_slots(), 8);

        // Trying to reserve even 0 more fails when full
        assert!(!state.reserve_slots(1).await);

        // Release all
        state.release_slots(8).await;
        assert_eq!(state.available_slots().await, 8);
    }

    #[tokio::test]
    async fn test_release_slots_more_than_used() {
        let state = WorkerState::new(test_config("test"));

        // Reserve 2 slots
        assert!(state.reserve_slots(2).await);
        assert_eq!(state.used_slots(), 2);

        // Release more than reserved - should saturate to 0
        state.release_slots(10).await;
        assert_eq!(state.used_slots(), 0);
        assert_eq!(state.available_slots().await, 8);
    }

    #[tokio::test]
    async fn test_status_transitions() {
        let state = WorkerState::new(test_config("test"));

        assert_eq!(state.status().await, WorkerStatus::Healthy);

        state.set_status(WorkerStatus::Degraded).await;
        assert_eq!(state.status().await, WorkerStatus::Degraded);

        state.set_status(WorkerStatus::Unreachable).await;
        assert_eq!(state.status().await, WorkerStatus::Unreachable);

        state.set_status(WorkerStatus::Healthy).await;
        assert_eq!(state.status().await, WorkerStatus::Healthy);
    }

    #[tokio::test]
    async fn test_disable_enable_cycle() {
        let state = WorkerState::new(test_config("test"));

        // Disable with reason
        state.disable(Some("Maintenance".to_string())).await;
        assert!(state.is_disabled().await);
        assert_eq!(state.status().await, WorkerStatus::Disabled);
        assert_eq!(
            state.disabled_reason().await,
            Some("Maintenance".to_string())
        );
        assert!(state.disabled_at().is_some());

        // Enable again
        state.enable().await;
        assert!(!state.is_disabled().await);
        assert_eq!(state.status().await, WorkerStatus::Healthy);
        assert!(state.disabled_reason().await.is_none());
        assert!(state.disabled_at().is_none());
    }

    #[tokio::test]
    async fn test_disable_without_reason() {
        let state = WorkerState::new(test_config("test"));

        state.disable(None).await;
        assert!(state.is_disabled().await);
        assert!(state.disabled_reason().await.is_none());
        assert!(state.disabled_at().is_some());
    }

    #[tokio::test]
    async fn test_drain_state() {
        let state = WorkerState::new(test_config("test"));

        state.drain().await;
        assert!(state.is_draining().await);
        assert_eq!(state.status().await, WorkerStatus::Draining);
        assert!(!state.is_disabled().await);

        // Enable clears draining
        state.enable().await;
        assert!(!state.is_draining().await);
        assert_eq!(state.status().await, WorkerStatus::Healthy);
    }

    #[tokio::test]
    async fn test_drained_state() {
        let state = WorkerState::new(test_config("test"));

        // Drained is set automatically via check_drain_complete()
        state.drain().await;
        assert!(state.is_draining().await);
        assert!(!state.is_drained().await);

        // When no slots are used, draining should auto-transition to drained
        state.check_drain_complete().await;
        assert!(!state.is_draining().await);
        assert!(state.is_drained().await);
        assert_eq!(state.status().await, WorkerStatus::Drained);

        // Enable clears drained
        state.enable().await;
        assert!(!state.is_drained().await);
        assert_eq!(state.status().await, WorkerStatus::Healthy);
    }

    #[tokio::test]
    async fn test_drain_complete_with_active_jobs() {
        let state = WorkerState::new(test_config("test"));

        // Reserve a slot to simulate an active job
        assert!(state.reserve_slots(1).await);
        assert_eq!(state.used_slots(), 1);

        state.drain().await;
        assert!(state.is_draining().await);

        // With active jobs, calling check_drain_complete() should NOT transition to Drained
        state.check_drain_complete().await;
        assert!(state.is_draining().await);
        assert!(!state.is_drained().await);

        // Release the slot (job completes) - this automatically calls check_drain_complete()
        // and should transition to Drained since no jobs remain
        state.release_slots(1).await;
        assert_eq!(state.used_slots(), 0);

        // Worker should now be Drained (automatic transition via release_slots)
        assert!(!state.is_draining().await);
        assert!(state.is_drained().await);
        assert_eq!(state.status().await, WorkerStatus::Drained);
    }

    #[tokio::test]
    async fn test_cached_projects() {
        let state = WorkerState::new(test_config("test"));

        assert!(!state.has_cached_project("project-a").await);

        state.add_cached_project("project-a".to_string()).await;
        assert!(state.has_cached_project("project-a").await);
        assert!(!state.has_cached_project("project-b").await);

        // Adding same project again should not duplicate
        state.add_cached_project("project-a".to_string()).await;
        let projects = state.cached_projects.read().await;
        assert_eq!(projects.len(), 1);
        drop(projects);

        state.add_cached_project("project-b".to_string()).await;
        assert!(state.has_cached_project("project-b").await);
        let projects = state.cached_projects.read().await;
        assert_eq!(projects.len(), 2);
    }

    #[tokio::test]
    async fn test_speed_score() {
        let state = WorkerState::new(test_config("test"));

        // Default is 50.0
        assert_eq!(state.get_speed_score(), 50.0);

        state.set_speed_score(85.5);
        assert_eq!(state.get_speed_score(), 85.5);

        state.set_speed_score(0.0);
        assert_eq!(state.get_speed_score(), 0.0);

        state.set_speed_score(100.0);
        assert_eq!(state.get_speed_score(), 100.0);
    }

    #[tokio::test]
    async fn test_latency_tracking() {
        let state = WorkerState::new(test_config("test"));

        assert!(state.last_latency_ms().is_none());

        state.set_last_latency_ms(Some(42));
        assert_eq!(state.last_latency_ms(), Some(42));

        state.set_last_latency_ms(Some(100));
        assert_eq!(state.last_latency_ms(), Some(100));

        state.set_last_latency_ms(None);
        assert!(state.last_latency_ms().is_none());
    }

    #[tokio::test]
    async fn test_error_tracking() {
        let state = WorkerState::new(test_config("test"));

        assert!(state.last_error().await.is_none());

        state.set_error("Connection refused".to_string()).await;
        assert_eq!(
            state.last_error().await,
            Some("Connection refused".to_string())
        );

        // Recording failure with error message updates last_error
        state.record_failure(Some("Timeout".to_string())).await;
        assert_eq!(state.last_error().await, Some("Timeout".to_string()));

        // Recording failure without message keeps previous error
        state.record_failure(None).await;
        assert_eq!(state.last_error().await, Some("Timeout".to_string()));
    }

    #[tokio::test]
    async fn test_circuit_breaker_basic() {
        let state = WorkerState::new(test_config("test"));

        // Initial state is Closed
        assert_eq!(state.circuit_state().await, Some(CircuitState::Closed));

        // Record success
        state.record_success().await;
        assert_eq!(state.circuit_state().await, Some(CircuitState::Closed));

        // Open circuit
        state.open_circuit().await;
        assert_eq!(state.circuit_state().await, Some(CircuitState::Open));

        // Half-open
        state.half_open_circuit().await;
        assert_eq!(state.circuit_state().await, Some(CircuitState::HalfOpen));

        // Close circuit clears error
        state.set_error("Test error".to_string()).await;
        state.close_circuit().await;
        assert_eq!(state.circuit_state().await, Some(CircuitState::Closed));
        assert!(state.last_error().await.is_none());
    }

    #[tokio::test]
    async fn test_capabilities() {
        let state = WorkerState::new(test_config("test"));

        // Default capabilities: nothing installed
        assert!(!state.has_bun().await);
        assert!(!state.has_node().await);
        assert!(!state.has_rust().await);

        // Set capabilities with Rust
        let mut caps = WorkerCapabilities::new();
        caps.rustc_version = Some("1.87.0-nightly".to_string());
        state.set_capabilities(caps).await;

        assert!(state.has_rust().await);
        assert!(!state.has_bun().await);
        assert!(!state.has_node().await);

        // Set capabilities with all runtimes
        let mut caps = WorkerCapabilities::new();
        caps.rustc_version = Some("1.87.0".to_string());
        caps.bun_version = Some("1.2.0".to_string());
        caps.node_version = Some("22.0.0".to_string());
        state.set_capabilities(caps.clone()).await;

        assert!(state.has_rust().await);
        assert!(state.has_bun().await);
        assert!(state.has_node().await);

        // Verify capabilities retrieval
        let retrieved = state.capabilities().await;
        assert_eq!(retrieved.rustc_version, Some("1.87.0".to_string()));
        assert_eq!(retrieved.bun_version, Some("1.2.0".to_string()));
    }

    #[tokio::test]
    async fn test_update_config() {
        let state = WorkerState::new(test_config("test"));

        {
            let config = state.config.read().await;
            assert_eq!(config.total_slots, 8);
            assert_eq!(config.priority, 100);
        }

        // Update config
        let mut new_config = test_config("test");
        new_config.total_slots = 16;
        new_config.priority = 200;
        state.update_config(new_config).await;

        let config = state.config.read().await;
        assert_eq!(config.total_slots, 16);
        assert_eq!(config.priority, 200);
    }

    // ============== WorkerPool Tests ==============

    #[tokio::test]
    async fn test_pool_new_empty() {
        let pool = WorkerPool::new();
        assert!(pool.is_empty());
        assert_eq!(pool.len(), 0);
    }

    #[tokio::test]
    async fn test_pool_add_and_get() {
        let pool = WorkerPool::new();

        pool.add_worker(test_config("worker-1")).await;
        assert_eq!(pool.len(), 1);
        assert!(!pool.is_empty());

        let worker = pool.get(&WorkerId::new("worker-1")).await;
        assert!(worker.is_some());
        let worker = worker.unwrap();
        assert_eq!(worker.config.read().await.total_slots, 8);

        // Non-existent worker
        assert!(pool.get(&WorkerId::new("worker-2")).await.is_none());
    }

    #[tokio::test]
    async fn test_pool_add_duplicate_updates() {
        let pool = WorkerPool::new();

        pool.add_worker(test_config("worker-1")).await;
        assert_eq!(pool.len(), 1);

        // Adding same id again updates config, doesn't add new worker
        let mut updated_config = test_config("worker-1");
        updated_config.total_slots = 16;
        pool.add_worker(updated_config).await;

        assert_eq!(pool.len(), 1);

        let worker = pool.get(&WorkerId::new("worker-1")).await.unwrap();
        assert_eq!(worker.config.read().await.total_slots, 16);
    }

    #[tokio::test]
    async fn test_pool_remove_worker() {
        let pool = WorkerPool::new();

        pool.add_worker(test_config("worker-1")).await;
        pool.add_worker(test_config("worker-2")).await;
        assert_eq!(pool.len(), 2);

        // Remove existing
        assert!(pool.remove_worker(&WorkerId::new("worker-1")).await);
        assert_eq!(pool.len(), 1);
        assert!(pool.get(&WorkerId::new("worker-1")).await.is_none());
        assert!(pool.get(&WorkerId::new("worker-2")).await.is_some());

        // Remove non-existent
        assert!(!pool.remove_worker(&WorkerId::new("worker-1")).await);
        assert_eq!(pool.len(), 1);
    }

    #[tokio::test]
    async fn test_pool_all_workers() {
        let pool = WorkerPool::new();

        pool.add_worker(test_config("worker-1")).await;
        pool.add_worker(test_config("worker-2")).await;

        // Disable one
        pool.get(&WorkerId::new("worker-1"))
            .await
            .unwrap()
            .disable(None)
            .await;

        let all = pool.all_workers().await;
        assert_eq!(all.len(), 2);
    }

    #[tokio::test]
    async fn test_pool_healthy_workers() {
        let pool = WorkerPool::new();

        pool.add_worker(test_config("healthy")).await;
        pool.add_worker(test_config("degraded")).await;
        pool.add_worker(test_config("unreachable")).await;
        pool.add_worker(test_config("disabled")).await;
        pool.add_worker(test_config("draining")).await;

        // Set statuses
        pool.get(&WorkerId::new("degraded"))
            .await
            .unwrap()
            .set_status(WorkerStatus::Degraded)
            .await;
        pool.get(&WorkerId::new("unreachable"))
            .await
            .unwrap()
            .set_status(WorkerStatus::Unreachable)
            .await;
        pool.get(&WorkerId::new("disabled"))
            .await
            .unwrap()
            .disable(None)
            .await;
        pool.get(&WorkerId::new("draining"))
            .await
            .unwrap()
            .drain()
            .await;

        let healthy = pool.healthy_workers().await;

        // Should include Healthy and Degraded only
        assert_eq!(healthy.len(), 2);

        // Collect worker ids manually
        let mut ids = Vec::new();
        for w in &healthy {
            ids.push(w.config.read().await.id.clone());
        }

        assert!(ids.contains(&WorkerId::new("healthy")));
        assert!(ids.contains(&WorkerId::new("degraded")));
    }

    #[tokio::test]
    async fn test_pool_set_status() {
        let pool = WorkerPool::new();
        pool.add_worker(test_config("worker-1")).await;

        pool.set_status(&WorkerId::new("worker-1"), WorkerStatus::Unreachable)
            .await;

        let worker = pool.get(&WorkerId::new("worker-1")).await.unwrap();
        assert_eq!(worker.status().await, WorkerStatus::Unreachable);

        // Setting status on non-existent worker is a no-op
        pool.set_status(&WorkerId::new("nonexistent"), WorkerStatus::Healthy)
            .await;
    }

    #[tokio::test]
    async fn test_pool_release_slots() {
        let pool = WorkerPool::new();
        pool.add_worker(test_config("worker-1")).await;

        let worker = pool.get(&WorkerId::new("worker-1")).await.unwrap();
        worker.reserve_slots(4).await;
        assert_eq!(worker.available_slots().await, 4);

        pool.release_slots(&WorkerId::new("worker-1"), 2).await;
        assert_eq!(worker.available_slots().await, 6);

        // Release on non-existent worker is a no-op
        pool.release_slots(&WorkerId::new("nonexistent"), 10).await;
    }

    #[tokio::test]
    async fn test_prune_drained() {
        let pool = WorkerPool::new();

        // Active worker
        let active = WorkerState::new(WorkerConfig {
            id: WorkerId::new("active"),
            host: "localhost".to_string(),
            user: "u".to_string(),
            identity_file: "i".to_string(),
            total_slots: 8,
            priority: 100,
            tags: vec![],
        });
        pool.add_worker_state(active).await;

        // Drained worker with 0 slots used
        let drained_empty = WorkerState::new(WorkerConfig {
            id: WorkerId::new("drained_empty"),
            host: "localhost".to_string(),
            user: "u".to_string(),
            identity_file: "i".to_string(),
            total_slots: 8,
            priority: 100,
            tags: vec![],
        });
        drained_empty.drain().await;
        pool.add_worker_state(drained_empty).await;

        // Drained worker with slots in use (should NOT be pruned)
        let drained_busy = WorkerState::new(WorkerConfig {
            id: WorkerId::new("drained_busy"),
            host: "localhost".to_string(),
            user: "u".to_string(),
            identity_file: "i".to_string(),
            total_slots: 8,
            priority: 100,
            tags: vec![],
        });
        drained_busy.drain().await;
        drained_busy.reserve_slots(1).await;
        pool.add_worker_state(drained_busy).await;

        assert_eq!(pool.len(), 3);

        let pruned = pool.prune_drained().await;
        assert_eq!(pruned, 1);
        assert_eq!(pool.len(), 2);

        assert!(pool.get(&WorkerId::new("active")).await.is_some());
        assert!(pool.get(&WorkerId::new("drained_busy")).await.is_some());
        assert!(pool.get(&WorkerId::new("drained_empty")).await.is_none());
    }

    #[tokio::test]
    async fn test_prune_drained_empty_pool() {
        let pool = WorkerPool::new();
        let pruned = pool.prune_drained().await;
        assert_eq!(pruned, 0);
    }

    #[tokio::test]
    async fn test_prune_drained_no_draining_workers() {
        let pool = WorkerPool::new();
        pool.add_worker(test_config("worker-1")).await;
        pool.add_worker(test_config("worker-2")).await;

        let pruned = pool.prune_drained().await;
        assert_eq!(pruned, 0);
        assert_eq!(pool.len(), 2);
    }

    #[tokio::test]
    async fn test_pool_default() {
        let pool = WorkerPool::default();
        assert!(pool.is_empty());
    }
}
