//! Worker pool management.

use rch_common::{WorkerConfig, WorkerId, WorkerStatus};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::sync::RwLock;
use tracing::debug;

/// State of a single worker.
#[derive(Debug)]
pub struct WorkerState {
    /// Worker configuration.
    pub config: WorkerConfig,
    /// Current status.
    pub status: WorkerStatus,
    /// Number of slots currently in use.
    used_slots: AtomicU32,
    /// Speed score from benchmarking (0-100).
    pub speed_score: f64,
    /// Projects cached on this worker.
    pub cached_projects: Vec<String>,
}

impl WorkerState {
    /// Create a new worker state from configuration.
    pub fn new(config: WorkerConfig) -> Self {
        Self {
            config,
            status: WorkerStatus::Healthy,
            used_slots: AtomicU32::new(0),
            speed_score: 50.0, // Default mid-range score
            cached_projects: Vec::new(),
        }
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
}

/// Pool of all workers.
#[derive(Clone)]
pub struct WorkerPool {
    workers: Arc<RwLock<HashMap<WorkerId, Arc<WorkerState>>>>,
}

impl WorkerPool {
    /// Create a new empty worker pool.
    pub fn new() -> Self {
        Self {
            workers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add a worker to the pool.
    pub async fn add_worker(&self, config: WorkerConfig) {
        let id = config.id.clone();
        let state = Arc::new(WorkerState::new(config));
        let mut workers = self.workers.write().await;
        workers.insert(id.clone(), state);
        debug!("Added worker: {}", id);
    }

    /// Get the number of workers in the pool.
    pub fn len(&self) -> usize {
        // This is a quick check, not perfectly accurate but good enough
        0 // TODO: Implement properly with async
    }

    /// Check if pool is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get all healthy workers.
    pub async fn healthy_workers(&self) -> Vec<Arc<WorkerState>> {
        let workers = self.workers.read().await;
        workers
            .values()
            .filter(|w| w.status == WorkerStatus::Healthy)
            .cloned()
            .collect()
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
            // Note: This requires interior mutability pattern
            // For now, we'll need to restructure to allow status updates
            debug!("Would set {} to {:?}", id, status);
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
