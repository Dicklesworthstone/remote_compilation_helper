//! Worker pool management.

#![allow(dead_code)] // Scaffold code - methods will be used in future beads

use rch_common::{
    CircuitBreakerConfig, CircuitState, CircuitStats, WorkerConfig, WorkerId, WorkerStatus,
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
    pub config: WorkerConfig,
    /// Current status (uses RwLock for interior mutability).
    status: RwLock<WorkerStatus>,
    /// Number of slots currently in use.
    used_slots: AtomicU32,
    /// Speed score from benchmarking (0-100).
    pub speed_score: f64,
    /// Projects cached on this worker.
    pub cached_projects: Vec<String>,
    /// Circuit breaker statistics.
    circuit: RwLock<CircuitStats>,
    /// Last error message.
    last_error_msg: RwLock<Option<String>>,
}

impl WorkerState {
    /// Create a new worker state from configuration.
    pub fn new(config: WorkerConfig) -> Self {
        Self {
            config,
            status: RwLock::new(WorkerStatus::Healthy),
            used_slots: AtomicU32::new(0),
            speed_score: 50.0, // Default mid-range score
            cached_projects: Vec::new(),
            circuit: RwLock::new(CircuitStats::new()),
            last_error_msg: RwLock::new(None),
        }
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
    pub fn available_slots(&self) -> u32 {
        let used = self.used_slots.load(Ordering::Relaxed);
        self.config.total_slots.saturating_sub(used)
    }

    /// Reserve slots for a job. Returns true if successful.
    pub fn reserve_slots(&self, count: u32) -> bool {
        let mut current = self.used_slots.load(Ordering::Relaxed);
        loop {
            if current + count > self.config.total_slots {
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
    pub fn release_slots(&self, count: u32) {
        self.used_slots.fetch_sub(count, Ordering::SeqCst);
    }

    /// Check if this worker has a cached copy of a project.
    pub fn has_cached_project(&self, project: &str) -> bool {
        self.cached_projects.iter().any(|p| p == project)
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
        let state = Arc::new(WorkerState::new(config));
        let mut workers = self.workers.write().await;
        if workers.insert(id.clone(), state).is_none() {
            // Only increment if this is a new worker
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
    pub async fn healthy_workers(&self) -> Vec<Arc<WorkerState>> {
        let workers = self.workers.read().await;
        let mut healthy = Vec::new();
        for worker in workers.values() {
            if worker.status().await == WorkerStatus::Healthy {
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
            worker.release_slots(slots);
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

    #[test]
    fn test_slot_reservation() {
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
        assert_eq!(state.available_slots(), 8);

        assert!(state.reserve_slots(4));
        assert_eq!(state.available_slots(), 4);

        assert!(state.reserve_slots(4));
        assert_eq!(state.available_slots(), 0);

        assert!(!state.reserve_slots(1)); // Should fail

        state.release_slots(4);
        assert_eq!(state.available_slots(), 4);
    }
}
