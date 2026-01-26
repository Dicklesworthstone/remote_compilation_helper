//! Worker pool management.

#![allow(dead_code)] // Scaffold code - methods will be used in future beads

use rch_common::{
    CircuitBreakerConfig, CircuitState, CircuitStats, WorkerCapabilities, WorkerConfig, WorkerId,
    WorkerStatus,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
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
    pub speed_score: RwLock<f64>,
    /// Last observed worker latency in milliseconds (from health checks).
    last_latency_ms: RwLock<Option<u64>>,
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
    /// Unix timestamp when worker was disabled.
    disabled_at: RwLock<Option<i64>>,
}

impl WorkerState {
    /// Create a new worker state from configuration.
    pub fn new(config: WorkerConfig) -> Self {
        Self {
            config: RwLock::new(config),
            status: RwLock::new(WorkerStatus::Healthy),
            used_slots: Arc::new(AtomicU32::new(0)),
            speed_score: RwLock::new(50.0), // Default mid-range score
            last_latency_ms: RwLock::new(None),
            cached_projects: RwLock::new(Vec::new()),
            circuit: RwLock::new(CircuitStats::new()),
            last_error_msg: RwLock::new(None),
            capabilities: RwLock::new(WorkerCapabilities::new()),
            disabled_reason: RwLock::new(None),
            disabled_at: RwLock::new(None),
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
    pub async fn reserve_slots(&self, count: u32) -> bool {
        let total_slots = self.config.read().await.total_slots;
        let mut current = self.used_slots.load(Ordering::Relaxed);
        loop {
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
            cache.push(project);
        }
    }

    /// Update the speed score.
    pub async fn set_speed_score(&self, score: f64) {
        *self.speed_score.write().await = score;
    }

    /// Get the current speed score.
    pub async fn get_speed_score(&self) -> f64 {
        *self.speed_score.read().await
    }

    /// Update the last observed worker latency (ms).
    pub async fn set_last_latency_ms(&self, latency_ms: Option<u64>) {
        *self.last_latency_ms.write().await = latency_ms;
    }

    /// Get the last observed worker latency (ms).
    pub async fn last_latency_ms(&self) -> Option<u64> {
        *self.last_latency_ms.read().await
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
        *self.disabled_at.write().await = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
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
        *self.disabled_at.write().await = None;
    }

    /// Check if worker is disabled.
    pub async fn is_disabled(&self) -> bool {
        *self.status.read().await == WorkerStatus::Disabled
    }

    /// Check if worker is draining.
    pub async fn is_draining(&self) -> bool {
        *self.status.read().await == WorkerStatus::Draining
    }

    /// Get the reason this worker was disabled (if any).
    pub async fn disabled_reason(&self) -> Option<String> {
        self.disabled_reason.read().await.clone()
    }

    /// Get the timestamp when this worker was disabled (Unix seconds).
    pub async fn disabled_at(&self) -> Option<i64> {
        *self.disabled_at.read().await
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
}
