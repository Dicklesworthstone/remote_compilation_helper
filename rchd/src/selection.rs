//! Worker selection algorithm.

use crate::workers::{WorkerPool, WorkerState};
use rch_common::SelectionRequest;
use std::cmp::Ordering;
use std::sync::Arc;
use tracing::debug;

/// Weights for the selection scoring algorithm.
#[derive(Debug, Clone)]
pub struct SelectionWeights {
    /// Weight for available slots (0.0-1.0).
    pub slots: f64,
    /// Weight for speed score (0.0-1.0).
    pub speed: f64,
    /// Weight for project locality (0.0-1.0).
    pub locality: f64,
}

impl Default for SelectionWeights {
    fn default() -> Self {
        Self {
            slots: 0.4,
            speed: 0.5,
            locality: 0.1,
        }
    }
}

/// Select the best worker for a request.
pub async fn select_worker(
    pool: &WorkerPool,
    request: &SelectionRequest,
    weights: &SelectionWeights,
) -> Option<Arc<WorkerState>> {
    let workers = pool.healthy_workers().await;

    workers
        .into_iter()
        .filter(|w| w.available_slots() >= request.estimated_cores)
        .max_by(|a, b| {
            let score_a = compute_score(a, request, weights);
            let score_b = compute_score(b, request, weights);
            score_a.partial_cmp(&score_b).unwrap_or(Ordering::Equal)
        })
}

/// Compute a selection score for a worker.
fn compute_score(
    worker: &WorkerState,
    request: &SelectionRequest,
    weights: &SelectionWeights,
) -> f64 {
    // Slot availability score (0.0-1.0)
    let slot_score = worker.available_slots() as f64 / worker.config.total_slots as f64;

    // Speed score (already 0-100, normalize to 0-1)
    let speed_score = worker.speed_score / 100.0;

    // Locality score (1.0 if project is cached, 0.5 otherwise)
    let locality_score = if worker.has_cached_project(&request.project) {
        1.0
    } else {
        0.5
    };

    // Compute weighted score
    let score = weights.slots * slot_score
        + weights.speed * speed_score
        + weights.locality * locality_score;

    debug!(
        "Worker {} score: {:.3} (slots: {:.2}, speed: {:.2}, locality: {:.2})",
        worker.config.id, score, slot_score, speed_score, locality_score
    );

    score
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workers::WorkerState;
    use rch_common::WorkerStatus;
    use rch_common::{WorkerConfig, WorkerId};

    fn make_worker(id: &str, total_slots: u32, speed: f64) -> WorkerState {
        let config = WorkerConfig {
            id: WorkerId::new(id),
            host: "localhost".to_string(),
            user: "user".to_string(),
            identity_file: "~/.ssh/id_rsa".to_string(),
            total_slots,
            priority: 100,
            tags: vec![],
        };
        let mut state = WorkerState::new(config);
        state.speed_score = speed;
        state
    }

    #[test]
    fn test_selection_score() {
        let worker = make_worker("test", 16, 80.0);
        let request = SelectionRequest {
            project: "myproject".to_string(),
            estimated_cores: 4,
            preferred_workers: vec![],
        };
        let weights = SelectionWeights::default();

        let score = compute_score(&worker, &request, &weights);
        assert!(score > 0.0);
        assert!(score <= 1.0);
    }

    #[tokio::test]
    async fn test_select_worker_ignores_unhealthy() {
        let pool = WorkerPool::new();
        pool.add_worker(make_worker("healthy", 8, 50.0).config)
            .await;
        pool.add_worker(make_worker("unreachable", 16, 90.0).config)
            .await;

        // Mark the second worker unreachable
        pool.set_status(&WorkerId::new("unreachable"), WorkerStatus::Unreachable)
            .await;

        let request = SelectionRequest {
            project: "myproject".to_string(),
            estimated_cores: 2,
            preferred_workers: vec![],
        };
        let weights = SelectionWeights::default();

        let selected = select_worker(&pool, &request, &weights).await;
        let selected = selected.expect("Expected a healthy worker to be selected");
        assert_eq!(selected.config.id.as_str(), "healthy");
    }

    #[tokio::test]
    async fn test_select_worker_respects_slot_availability() {
        let pool = WorkerPool::new();
        pool.add_worker(make_worker("full", 4, 70.0).config).await;
        pool.add_worker(make_worker("available", 8, 50.0).config)
            .await;

        // Reserve all slots on the first worker
        let full_worker = pool.get(&WorkerId::new("full")).await.unwrap();
        assert!(full_worker.reserve_slots(4));
        assert_eq!(full_worker.available_slots(), 0);

        let request = SelectionRequest {
            project: "myproject".to_string(),
            estimated_cores: 2,
            preferred_workers: vec![],
        };
        let weights = SelectionWeights::default();

        let selected = select_worker(&pool, &request, &weights).await;
        let selected = selected.expect("Expected a worker with available slots");
        assert_eq!(selected.config.id.as_str(), "available");
    }
}
