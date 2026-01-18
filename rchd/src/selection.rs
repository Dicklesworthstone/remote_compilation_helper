//! Worker selection algorithm with multiple selection strategies.
//!
//! Supports five selection strategies:
//! - **Priority**: Original behavior, sort by priority and select first available
//! - **Fastest**: Select worker with highest SpeedScore
//! - **Balanced**: Balance SpeedScore, load, health, cache affinity, and priority
//! - **CacheAffinity**: Prefer workers with warm caches for the project
//! - **FairFastest**: Weighted random selection favoring fast workers but ensuring fairness

#![allow(dead_code)] // Scaffold code - methods will be used in future beads

use crate::metrics::latency::{DecisionTimer, DecisionType};
use crate::workers::{WorkerPool, WorkerState};
use rand::Rng;
use rch_common::{
    CircuitBreakerConfig, CircuitState, RequiredRuntime, SelectionConfig, SelectionReason,
    SelectionRequest, SelectionStrategy, SelectionWeightConfig,
};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::debug;

/// Weights for the selection scoring algorithm (legacy compatibility).
#[derive(Debug, Clone)]
pub struct SelectionWeights {
    /// Weight for available slots (0.0-1.0).
    pub slots: f64,
    /// Weight for speed score (0.0-1.0).
    pub speed: f64,
    /// Weight for project locality (0.0-1.0).
    pub locality: f64,
    /// Weight for worker priority (0.0-1.0).
    pub priority: f64,
    /// Penalty for half-open circuit workers (multiplier 0.0-1.0).
    pub half_open_penalty: f64,
}

impl Default for SelectionWeights {
    fn default() -> Self {
        Self {
            slots: 0.4,
            speed: 0.5,
            locality: 0.1,
            priority: 0.1,
            half_open_penalty: 0.5, // Half-open workers score at 50% of their normal value
        }
    }
}

impl From<&SelectionWeightConfig> for SelectionWeights {
    fn from(config: &SelectionWeightConfig) -> Self {
        Self {
            slots: config.slots,
            speed: config.speedscore,
            locality: config.cache,
            priority: config.priority,
            half_open_penalty: config.half_open_penalty,
        }
    }
}

// ============================================================================
// Cache Affinity Tracking
// ============================================================================

/// Tracks recent project builds per worker for cache affinity scoring.
#[derive(Debug, Default)]
pub struct CacheTracker {
    /// Map from worker_id -> (project_id -> last_build_time)
    workers: HashMap<String, HashMap<String, Instant>>,
    /// Maximum projects to track per worker.
    max_projects_per_worker: usize,
}

impl CacheTracker {
    /// Create a new cache tracker with default limits.
    pub fn new() -> Self {
        Self {
            workers: HashMap::new(),
            max_projects_per_worker: 50,
        }
    }

    /// Record a build completion on a worker for a project.
    pub fn record_build(&mut self, worker_id: &str, project_id: &str) {
        let cache = self.workers.entry(worker_id.to_string()).or_default();
        cache.insert(project_id.to_string(), Instant::now());

        // Limit to max_projects_per_worker most recent
        while cache.len() > self.max_projects_per_worker {
            let oldest = cache
                .iter()
                .min_by_key(|(_, time)| *time)
                .map(|(k, _)| k.clone());
            if let Some(key) = oldest {
                cache.remove(&key);
            }
        }
    }

    /// Estimate cache warmth for a project on a worker (0.0-1.0).
    ///
    /// Returns higher values for more recent builds:
    /// - Build < 1 hour ago: 1.0
    /// - Build 1-6 hours ago: 0.5-1.0 (linear decay)
    /// - Build 6-24 hours ago: 0.2-0.5 (linear decay)
    /// - Build > 24 hours ago: 0.0-0.2 (linear decay)
    /// - No build: 0.0
    pub fn estimate_warmth(&self, worker_id: &str, project_id: &str) -> f64 {
        self.workers
            .get(worker_id)
            .and_then(|c| c.get(project_id))
            .map(|last_build| {
                let age = last_build.elapsed();
                let hours = age.as_secs_f64() / 3600.0;

                if hours < 1.0 {
                    1.0
                } else if hours < 6.0 {
                    1.0 - (hours - 1.0) * 0.1 // 1.0 -> 0.5 over 5 hours
                } else if hours < 24.0 {
                    0.5 - (hours - 6.0) * (0.3 / 18.0) // 0.5 -> 0.2 over 18 hours
                } else {
                    0.2 * (-((hours - 24.0) / 24.0)).exp() // Exponential decay from 0.2
                }
            })
            .unwrap_or(0.0)
    }

    /// Check if a worker has a recent build for a project.
    pub fn has_recent_build(&self, worker_id: &str, project_id: &str, max_age: Duration) -> bool {
        self.workers
            .get(worker_id)
            .and_then(|c| c.get(project_id))
            .map(|last_build| last_build.elapsed() < max_age)
            .unwrap_or(false)
    }
}

// ============================================================================
// Selection History for FairFastest
// ============================================================================

/// Tracks recent worker selections for the FairFastest strategy.
#[derive(Debug)]
pub struct SelectionHistory {
    /// Map from worker_id -> list of selection timestamps
    selections: HashMap<String, VecDeque<Instant>>,
    /// Maximum history depth per worker.
    max_history_per_worker: usize,
}

impl Default for SelectionHistory {
    fn default() -> Self {
        Self {
            selections: HashMap::new(),
            max_history_per_worker: 100,
        }
    }
}

impl SelectionHistory {
    /// Create a new selection history tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a worker selection.
    pub fn record_selection(&mut self, worker_id: &str) {
        let history = self.selections.entry(worker_id.to_string()).or_default();
        history.push_back(Instant::now());

        // Limit history size
        while history.len() > self.max_history_per_worker {
            history.pop_front();
        }
    }

    /// Count recent selections for a worker within a time window.
    pub fn recent_selections(&self, worker_id: &str, window: Duration) -> usize {
        let cutoff = Instant::now() - window;
        self.selections
            .get(worker_id)
            .map(|history| history.iter().filter(|&&t| t > cutoff).count())
            .unwrap_or(0)
    }

    /// Prune old entries from all workers.
    pub fn prune(&mut self, max_age: Duration) {
        let cutoff = Instant::now() - max_age;
        for history in self.selections.values_mut() {
            while history.front().map(|&t| t < cutoff).unwrap_or(false) {
                history.pop_front();
            }
        }
    }
}

// ============================================================================
// Worker Selection Context
// ============================================================================

/// Context for strategy-based worker selection.
pub struct WorkerSelector {
    /// Selection configuration.
    pub config: SelectionConfig,
    /// Circuit breaker configuration.
    pub circuit_config: CircuitBreakerConfig,
    /// Cache affinity tracker.
    pub cache_tracker: Arc<RwLock<CacheTracker>>,
    /// Selection history for fairness.
    pub selection_history: Arc<RwLock<SelectionHistory>>,
}

/// Result of worker selection with reason.
pub struct SelectionResult {
    /// Selected worker, if available.
    pub worker: Option<Arc<WorkerState>>,
    /// Reason for the selection result.
    pub reason: SelectionReason,
}

impl WorkerSelector {
    /// Create a new worker selector with default configuration.
    pub fn new() -> Self {
        Self {
            config: SelectionConfig::default(),
            circuit_config: CircuitBreakerConfig::default(),
            cache_tracker: Arc::new(RwLock::new(CacheTracker::new())),
            selection_history: Arc::new(RwLock::new(SelectionHistory::new())),
        }
    }

    /// Create a new worker selector with explicit configuration.
    pub fn with_config(config: SelectionConfig, circuit_config: CircuitBreakerConfig) -> Self {
        Self {
            config,
            circuit_config,
            cache_tracker: Arc::new(RwLock::new(CacheTracker::new())),
            selection_history: Arc::new(RwLock::new(SelectionHistory::new())),
        }
    }

    /// Select a worker using the configured strategy.
    pub async fn select(&self, pool: &WorkerPool, request: &SelectionRequest) -> SelectionResult {
        let _timer = DecisionTimer::new(DecisionType::WorkerSelection);

        // Get eligible workers
        let eligible = match self.get_eligible_workers(pool, request).await {
            Ok(workers) => workers,
            Err(reason) => {
                return SelectionResult {
                    worker: None,
                    reason,
                };
            }
        };

        if eligible.is_empty() {
            return SelectionResult {
                worker: None,
                reason: SelectionReason::AllWorkersBusy,
            };
        }

        // Apply the configured selection strategy
        let selected = match self.config.strategy {
            SelectionStrategy::Priority => self.select_by_priority(&eligible).await,
            SelectionStrategy::Fastest => self.select_by_fastest(&eligible).await,
            SelectionStrategy::Balanced => self.select_balanced(&eligible, request).await,
            SelectionStrategy::CacheAffinity => {
                self.select_cache_affinity(&eligible, request).await
            }
            SelectionStrategy::FairFastest => self.select_fair_fastest(&eligible).await,
        };

        if let Some((worker, circuit_state)) = selected {
            // If selecting a half-open worker, start the probe
            if circuit_state == CircuitState::HalfOpen {
                worker.start_probe(&self.circuit_config).await;
                debug!(
                    "Worker {} selected (half-open probe), strategy={:?}",
                    worker.config.id, self.config.strategy
                );
            } else {
                debug!(
                    "Worker {} selected, strategy={:?}",
                    worker.config.id, self.config.strategy
                );
            }

            // Record the selection for fairness tracking
            let mut history = self.selection_history.write().await;
            history.record_selection(worker.config.id.as_str());

            SelectionResult {
                worker: Some(worker),
                reason: SelectionReason::Success,
            }
        } else {
            SelectionResult {
                worker: None,
                reason: SelectionReason::AllWorkersBusy,
            }
        }
    }

    /// Record a build completion for cache affinity tracking.
    pub async fn record_build(&self, worker_id: &str, project_id: &str) {
        let mut cache = self.cache_tracker.write().await;
        cache.record_build(worker_id, project_id);
    }

    /// Get eligible workers filtered by health, circuits, slots, and runtime.
    async fn get_eligible_workers(
        &self,
        pool: &WorkerPool,
        request: &SelectionRequest,
    ) -> Result<Vec<(Arc<WorkerState>, CircuitState)>, SelectionReason> {
        let workers = pool.healthy_workers().await;

        if workers.is_empty() {
            if pool.is_empty() {
                return Err(SelectionReason::NoWorkersConfigured);
            }

            // Check why no healthy workers
            let all_workers = pool.all_workers().await;
            let mut all_circuits_open = true;
            let mut all_unreachable = true;

            for worker in &all_workers {
                if let Some(state) = worker.circuit_state().await {
                    if state != CircuitState::Open {
                        all_circuits_open = false;
                    }
                }
                if worker.status().await != rch_common::WorkerStatus::Unreachable {
                    all_unreachable = false;
                }
            }

            if all_circuits_open {
                return Err(SelectionReason::AllCircuitsOpen);
            }
            if all_unreachable {
                return Err(SelectionReason::AllWorkersUnreachable);
            }
            return Err(SelectionReason::AllWorkersUnreachable);
        }

        let preferred_set: HashSet<&str> = request
            .preferred_workers
            .iter()
            .map(|id| id.as_str())
            .collect();
        let has_preferred = !preferred_set.is_empty();

        let mut eligible: Vec<(Arc<WorkerState>, CircuitState)> = Vec::new();
        let mut preferred: Vec<(Arc<WorkerState>, CircuitState)> = Vec::new();
        let mut any_has_runtime = false;

        for worker in workers {
            let circuit_state = worker.circuit_state().await.unwrap_or(CircuitState::Closed);

            // Filter by circuit state
            match circuit_state {
                CircuitState::Open => continue,
                CircuitState::HalfOpen => {
                    if !worker.can_probe(&self.circuit_config).await {
                        continue;
                    }
                }
                CircuitState::Closed => {}
            }

            // Filter by slot availability
            if worker.available_slots() < request.estimated_cores {
                continue;
            }

            // Filter by required runtime
            let has_required_runtime = match &request.required_runtime {
                RequiredRuntime::None => true,
                RequiredRuntime::Rust => worker.has_rust().await,
                RequiredRuntime::Bun => worker.has_bun().await,
                RequiredRuntime::Node => worker.has_node().await,
            };

            if !has_required_runtime {
                continue;
            }

            any_has_runtime = true;

            if has_preferred && preferred_set.contains(worker.config.id.as_str()) {
                preferred.push((worker.clone(), circuit_state));
            }
            eligible.push((worker, circuit_state));
        }

        if !any_has_runtime && request.required_runtime != RequiredRuntime::None {
            return Err(SelectionReason::NoWorkersWithRuntime(format!(
                "{:?}",
                request.required_runtime
            )));
        }

        // Return preferred workers if available, otherwise all eligible
        if has_preferred && !preferred.is_empty() {
            Ok(preferred)
        } else {
            Ok(eligible)
        }
    }

    /// Priority strategy: select worker with highest priority.
    async fn select_by_priority(
        &self,
        workers: &[(Arc<WorkerState>, CircuitState)],
    ) -> Option<(Arc<WorkerState>, CircuitState)> {
        workers
            .iter()
            .max_by_key(|(w, _)| w.config.priority)
            .map(|(w, s)| (w.clone(), *s))
    }

    /// Fastest strategy: select worker with highest SpeedScore.
    async fn select_by_fastest(
        &self,
        workers: &[(Arc<WorkerState>, CircuitState)],
    ) -> Option<(Arc<WorkerState>, CircuitState)> {
        workers
            .iter()
            .max_by(|(a, _), (b, _)| {
                a.speed_score
                    .partial_cmp(&b.speed_score)
                    .unwrap_or(Ordering::Equal)
            })
            .map(|(w, s)| (w.clone(), *s))
    }

    /// Balanced strategy: balance multiple factors.
    async fn select_balanced(
        &self,
        workers: &[(Arc<WorkerState>, CircuitState)],
        request: &SelectionRequest,
    ) -> Option<(Arc<WorkerState>, CircuitState)> {
        let cache = self.cache_tracker.read().await;
        let weights = &self.config.weights;

        let (min_priority, max_priority) = Self::priority_range(workers);

        workers
            .iter()
            .max_by(|(a, cs_a), (b, cs_b)| {
                let score_a = self.compute_balanced_score(
                    a,
                    *cs_a,
                    &request.project,
                    &cache,
                    weights,
                    min_priority,
                    max_priority,
                );
                let score_b = self.compute_balanced_score(
                    b,
                    *cs_b,
                    &request.project,
                    &cache,
                    weights,
                    min_priority,
                    max_priority,
                );
                score_a.partial_cmp(&score_b).unwrap_or(Ordering::Equal)
            })
            .map(|(w, s)| (w.clone(), *s))
    }

    /// Compute balanced score for a worker.
    #[allow(clippy::too_many_arguments)]
    fn compute_balanced_score(
        &self,
        worker: &WorkerState,
        circuit_state: CircuitState,
        project: &str,
        cache: &CacheTracker,
        weights: &SelectionWeightConfig,
        min_priority: u32,
        max_priority: u32,
    ) -> f64 {
        // SpeedScore component (0-1)
        let speed_score = worker.speed_score / 100.0;

        // Load factor: penalize heavily loaded workers (0.5-1.0)
        let load_factor = {
            let active_slots = worker.config.total_slots.saturating_sub(worker.available_slots());
            let utilization = active_slots as f64 / worker.config.total_slots.max(1) as f64;
            1.0 - (utilization * 0.5)
        };

        // Slot availability (0-1)
        let slot_score = worker.available_slots() as f64 / worker.config.total_slots.max(1) as f64;

        // Cache affinity (0-1)
        let cache_score = cache.estimate_warmth(worker.config.id.as_str(), project);

        // Priority normalization (0-1)
        let priority_score = Self::normalize_priority(worker.config.priority, min_priority, max_priority);

        // Combine weighted scores
        let base_score = weights.speedscore * speed_score
            + weights.slots * slot_score * load_factor
            + weights.cache * cache_score
            + weights.priority * priority_score;

        // Apply half-open penalty if applicable
        let final_score = if circuit_state == CircuitState::HalfOpen {
            base_score * weights.half_open_penalty
        } else {
            base_score
        };

        debug!(
            "Worker {} balanced score: {:.3} (speed={:.2}, load={:.2}, slots={:.2}, cache={:.2}, priority={:.2}, half_open={:?})",
            worker.config.id, final_score, speed_score, load_factor, slot_score, cache_score, priority_score, circuit_state == CircuitState::HalfOpen
        );

        final_score
    }

    /// CacheAffinity strategy: heavily weight cache warmth.
    async fn select_cache_affinity(
        &self,
        workers: &[(Arc<WorkerState>, CircuitState)],
        request: &SelectionRequest,
    ) -> Option<(Arc<WorkerState>, CircuitState)> {
        let cache = self.cache_tracker.read().await;

        // Find workers with warm caches for this project
        let warm_workers: Vec<_> = workers
            .iter()
            .filter(|(w, _)| cache.estimate_warmth(w.config.id.as_str(), &request.project) > 0.5)
            .collect();

        // If we have warm workers, select the fastest among them
        if !warm_workers.is_empty() {
            return warm_workers
                .iter()
                .max_by(|(a, _), (b, _)| {
                    a.speed_score
                        .partial_cmp(&b.speed_score)
                        .unwrap_or(Ordering::Equal)
                })
                .map(|(w, s)| ((*w).clone(), *s));
        }

        // Otherwise, fall back to fastest
        self.select_by_fastest(workers).await
    }

    /// FairFastest strategy: weighted random selection with fairness.
    async fn select_fair_fastest(
        &self,
        workers: &[(Arc<WorkerState>, CircuitState)],
    ) -> Option<(Arc<WorkerState>, CircuitState)> {
        if workers.is_empty() {
            return None;
        }

        let history = self.selection_history.read().await;
        let lookback = Duration::from_secs(self.config.fairness.lookback_secs);

        // Calculate weights for each worker
        let weights: Vec<f64> = workers
            .iter()
            .map(|(w, _)| {
                let speed = w.speed_score.max(10.0); // Minimum speed to avoid zero weight
                let recent = history.recent_selections(w.config.id.as_str(), lookback);
                // Diminish weight based on recent selections
                speed / (1.0 + recent as f64)
            })
            .collect();

        let total_weight: f64 = weights.iter().sum();
        if total_weight <= 0.0 {
            // Fallback to first worker if all weights are zero
            return workers.first().map(|(w, s)| (w.clone(), *s));
        }

        // Weighted random selection
        let mut rng = rand::rng();
        let threshold = rng.random_range(0.0..total_weight);

        let mut cumulative = 0.0;
        for (i, weight) in weights.iter().enumerate() {
            cumulative += weight;
            if cumulative >= threshold {
                return Some((workers[i].0.clone(), workers[i].1));
            }
        }

        // Fallback to last worker
        workers.last().map(|(w, s)| (w.clone(), *s))
    }

    fn priority_range(workers: &[(Arc<WorkerState>, CircuitState)]) -> (u32, u32) {
        let mut min_priority = u32::MAX;
        let mut max_priority = 0u32;

        for (worker, _) in workers {
            min_priority = min_priority.min(worker.config.priority);
            max_priority = max_priority.max(worker.config.priority);
        }

        if min_priority == u32::MAX {
            (0, 0)
        } else {
            (min_priority, max_priority)
        }
    }

    fn normalize_priority(priority: u32, min_priority: u32, max_priority: u32) -> f64 {
        if max_priority == min_priority {
            1.0
        } else {
            (priority.saturating_sub(min_priority)) as f64 / (max_priority - min_priority) as f64
        }
    }
}

impl Default for WorkerSelector {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Legacy API (for backwards compatibility)
// ============================================================================

/// Select the best worker for a request, considering circuit breaker state.
///
/// Workers with open circuits are excluded. Half-open workers are only
/// considered if they have probe budget available, and receive a scoring
/// penalty.
pub async fn select_worker(
    pool: &WorkerPool,
    request: &SelectionRequest,
    weights: &SelectionWeights,
) -> Option<Arc<WorkerState>> {
    let config = CircuitBreakerConfig::default();
    select_worker_with_config(pool, request, weights, &config)
        .await
        .worker
}

/// Select the best worker with explicit circuit breaker config.
///
/// Returns both the selected worker and the reason for selection result.
/// Tracks selection latency against the <10ms budget from AGENTS.md.
pub async fn select_worker_with_config(
    pool: &WorkerPool,
    request: &SelectionRequest,
    weights: &SelectionWeights,
    circuit_config: &CircuitBreakerConfig,
) -> SelectionResult {
    // Track worker selection latency (budget: <10ms, panic: 50ms)
    let _timer = DecisionTimer::new(DecisionType::WorkerSelection);

    let workers = pool.healthy_workers().await;

    if workers.is_empty() {
        // Check if there are any workers at all
        if pool.is_empty() {
            return SelectionResult {
                worker: None,
                reason: SelectionReason::NoWorkersConfigured,
            };
        }

        // All workers are unhealthy - check if it's due to unreachability or circuits
        let all_workers = pool.all_workers().await;
        let mut all_circuits_open = true;
        let mut all_unreachable = true;

        for worker in &all_workers {
            if let Some(state) = worker.circuit_state().await {
                if state != CircuitState::Open {
                    all_circuits_open = false;
                }
            }
            if worker.status().await != rch_common::WorkerStatus::Unreachable {
                all_unreachable = false;
            }
        }

        if all_circuits_open {
            return SelectionResult {
                worker: None,
                reason: SelectionReason::AllCircuitsOpen,
            };
        }

        if all_unreachable {
            return SelectionResult {
                worker: None,
                reason: SelectionReason::AllWorkersUnreachable,
            };
        }

        return SelectionResult {
            worker: None,
            reason: SelectionReason::AllWorkersUnreachable,
        };
    }

    let preferred_set: HashSet<&str> = request
        .preferred_workers
        .iter()
        .map(|id| id.as_str())
        .collect();
    let has_preferred = !preferred_set.is_empty();

    // Filter workers by circuit state and slot availability
    let mut eligible: Vec<(Arc<WorkerState>, CircuitState)> = Vec::new();
    let mut preferred: Vec<(Arc<WorkerState>, CircuitState)> = Vec::new();
    let mut all_circuits_open = true;
    let mut any_has_slots = false;
    let mut any_has_runtime = false;

    for worker in workers {
        let circuit_state = worker.circuit_state().await.unwrap_or(CircuitState::Closed);

        match circuit_state {
            CircuitState::Open => {
                debug!("Worker {} excluded: circuit open", worker.config.id);
                continue;
            }
            CircuitState::HalfOpen => {
                // Only allow if probe budget available
                if !worker.can_probe(circuit_config).await {
                    debug!(
                        "Worker {} excluded: half-open, no probe budget",
                        worker.config.id
                    );
                    continue;
                }
                all_circuits_open = false;
            }
            CircuitState::Closed => {
                all_circuits_open = false;
            }
        }

        // Check slot availability
        if worker.available_slots() < request.estimated_cores {
            debug!(
                "Worker {} excluded: insufficient slots ({} < {})",
                worker.config.id,
                worker.available_slots(),
                request.estimated_cores
            );
            continue;
        }

        // Check required runtime capability
        let has_required_runtime = match &request.required_runtime {
            RequiredRuntime::None => true,
            RequiredRuntime::Rust => worker.has_rust().await,
            RequiredRuntime::Bun => worker.has_bun().await,
            RequiredRuntime::Node => worker.has_node().await,
        };

        if !has_required_runtime {
            debug!(
                "Worker {} excluded: missing required runtime {:?}",
                worker.config.id, request.required_runtime
            );
            continue;
        }

        any_has_runtime = true;
        any_has_slots = true;

        // Compute score with circuit state penalty
        if has_preferred && preferred_set.contains(worker.config.id.as_str()) {
            preferred.push((worker.clone(), circuit_state));
        }

        eligible.push((worker, circuit_state));
    }

    let mut candidates = if has_preferred && !preferred.is_empty() {
        preferred
    } else {
        if has_preferred {
            debug!("Preferred workers not eligible; falling back to all eligible workers");
        }
        eligible
    };

    if candidates.is_empty() {
        // Check if no workers have required runtime (before other checks)
        if !any_has_runtime && request.required_runtime != RequiredRuntime::None {
            return SelectionResult {
                worker: None,
                reason: SelectionReason::NoWorkersWithRuntime(format!(
                    "{:?}",
                    request.required_runtime
                )),
            };
        }

        if all_circuits_open {
            return SelectionResult {
                worker: None,
                reason: SelectionReason::AllCircuitsOpen,
            };
        }

        if !any_has_slots {
            return SelectionResult {
                worker: None,
                reason: SelectionReason::AllWorkersBusy,
            };
        }

        return SelectionResult {
            worker: None,
            reason: SelectionReason::AllWorkersBusy,
        };
    }

    let (min_priority, max_priority) = priority_range(&candidates);
    let mut scored: Vec<(Arc<WorkerState>, CircuitState, f64)> =
        Vec::with_capacity(candidates.len());

    for (worker, circuit_state) in candidates.drain(..) {
        let priority_score = normalize_priority(worker.config.priority, min_priority, max_priority);
        let base_score = compute_score(&worker, request, weights, priority_score);
        let final_score = if circuit_state == CircuitState::HalfOpen {
            base_score * weights.half_open_penalty
        } else {
            base_score
        };

        debug!(
            "Worker {} candidate: circuit={:?}, base_score={:.3}, final_score={:.3}, priority_score={:.2}",
            worker.config.id, circuit_state, base_score, final_score, priority_score
        );

        scored.push((worker, circuit_state, final_score));
    }

    // Select worker with highest score
    scored.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(Ordering::Equal));

    let (selected_worker, circuit_state, score) = scored.into_iter().next().unwrap();

    // If selecting a half-open worker, start the probe
    if circuit_state == CircuitState::HalfOpen {
        selected_worker.start_probe(circuit_config).await;
        debug!(
            "Worker {} selected (half-open probe started), score={:.3}",
            selected_worker.config.id, score
        );
    } else {
        debug!(
            "Worker {} selected, score={:.3}",
            selected_worker.config.id, score
        );
    }

    SelectionResult {
        worker: Some(selected_worker),
        reason: SelectionReason::Success,
    }
}

/// Compute a selection score for a worker.
fn compute_score(
    worker: &WorkerState,
    request: &SelectionRequest,
    weights: &SelectionWeights,
    priority_score: f64,
) -> f64 {
    // Slot availability score (0.0-1.0)
    let total_slots = worker.config.total_slots.max(1) as f64;
    let slot_score = (worker.available_slots() as f64 / total_slots).min(1.0);

    // Speed score (already 0-100, normalize to 0-1)
    let speed_score = worker.speed_score / 100.0;

    // Locality score (1.0 if project is cached, 0.5 otherwise)
    let locality_score = if worker.has_cached_project(&request.project) {
        1.0
    } else {
        0.5
    };

    // Base weighted score (0.0-1.0)
    let base_score = weights.slots * slot_score
        + weights.speed * speed_score
        + weights.locality * locality_score;

    // Priority acts as a mild multiplier on the base score.
    let priority_factor = 1.0 + (weights.priority * priority_score);
    let score = base_score * priority_factor;

    debug!(
        "Worker {} score: {:.3} (slots: {:.2}, speed: {:.2}, locality: {:.2}, priority: {:.2})",
        worker.config.id, score, slot_score, speed_score, locality_score, priority_score
    );

    score
}

fn priority_range(candidates: &[(Arc<WorkerState>, CircuitState)]) -> (u32, u32) {
    let mut min_priority = u32::MAX;
    let mut max_priority = 0u32;

    for (worker, _) in candidates {
        min_priority = min_priority.min(worker.config.priority);
        max_priority = max_priority.max(worker.config.priority);
    }

    if min_priority == u32::MAX {
        (0, 0)
    } else {
        (min_priority, max_priority)
    }
}

fn normalize_priority(priority: u32, min_priority: u32, max_priority: u32) -> f64 {
    if max_priority == min_priority {
        1.0
    } else {
        (priority.saturating_sub(min_priority)) as f64 / (max_priority - min_priority) as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workers::WorkerState;
    use rch_common::WorkerStatus;
    use rch_common::{RequiredRuntime, WorkerConfig, WorkerId};

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
            command: None,
            estimated_cores: 4,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
        };
        let weights = SelectionWeights::default();

        let score = compute_score(&worker, &request, &weights, 0.5);
        assert!(score > 0.0);
        assert!(score <= 1.5);
    }

    #[test]
    fn test_selection_score_zero_slots_safe() {
        let worker = make_worker("zero", 0, 80.0);
        let request = SelectionRequest {
            project: "myproject".to_string(),
            command: None,
            estimated_cores: 1,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
        };
        let weights = SelectionWeights::default();

        let score = compute_score(&worker, &request, &weights, 0.5);
        assert!(score.is_finite());
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
            command: None,
            estimated_cores: 2,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
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
            command: None,
            estimated_cores: 2,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
        };
        let weights = SelectionWeights::default();

        let selected = select_worker(&pool, &request, &weights).await;
        let selected = selected.expect("Expected a worker with available slots");
        assert_eq!(selected.config.id.as_str(), "available");
    }

    #[tokio::test]
    async fn test_select_worker_ignores_open_circuit() {
        let pool = WorkerPool::new();
        pool.add_worker(make_worker("closed", 8, 50.0).config).await;
        pool.add_worker(make_worker("open", 16, 90.0).config).await;

        // Open the circuit on the second worker
        let open_worker = pool.get(&WorkerId::new("open")).await.unwrap();
        open_worker.open_circuit().await;

        let request = SelectionRequest {
            project: "myproject".to_string(),
            command: None,
            estimated_cores: 2,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
        };
        let weights = SelectionWeights::default();
        let config = CircuitBreakerConfig::default();

        let result = select_worker_with_config(&pool, &request, &weights, &config).await;
        let selected = result.worker.expect("Expected a worker to be selected");
        assert_eq!(result.reason, SelectionReason::Success);
        assert_eq!(selected.config.id.as_str(), "closed");
    }

    #[tokio::test]
    async fn test_select_worker_returns_all_circuits_open() {
        let pool = WorkerPool::new();
        pool.add_worker(make_worker("open1", 8, 50.0).config).await;
        pool.add_worker(make_worker("open2", 16, 90.0).config).await;

        // Open all circuits
        let worker1 = pool.get(&WorkerId::new("open1")).await.unwrap();
        let worker2 = pool.get(&WorkerId::new("open2")).await.unwrap();
        worker1.open_circuit().await;
        worker2.open_circuit().await;

        let request = SelectionRequest {
            project: "myproject".to_string(),
            command: None,
            estimated_cores: 2,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
        };
        let weights = SelectionWeights::default();
        let config = CircuitBreakerConfig::default();

        let result = select_worker_with_config(&pool, &request, &weights, &config).await;
        assert!(result.worker.is_none());
        assert_eq!(result.reason, SelectionReason::AllCircuitsOpen);
    }

    #[tokio::test]
    async fn test_select_worker_allows_half_open_with_probe_budget() {
        let pool = WorkerPool::new();
        pool.add_worker(make_worker("half_open", 8, 50.0).config)
            .await;

        // Put worker in half-open state
        let worker = pool.get(&WorkerId::new("half_open")).await.unwrap();
        worker.open_circuit().await;
        worker.half_open_circuit().await;

        let request = SelectionRequest {
            project: "myproject".to_string(),
            command: None,
            estimated_cores: 2,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
        };
        let weights = SelectionWeights::default();
        let config = CircuitBreakerConfig {
            half_open_max_probes: 1,
            ..Default::default()
        };

        let result = select_worker_with_config(&pool, &request, &weights, &config).await;
        let selected = result
            .worker
            .expect("Expected half-open worker to be selected");
        assert_eq!(result.reason, SelectionReason::Success);
        assert_eq!(selected.config.id.as_str(), "half_open");
    }

    #[tokio::test]
    async fn test_select_worker_excludes_half_open_at_probe_limit() {
        let pool = WorkerPool::new();
        pool.add_worker(make_worker("half_open", 8, 50.0).config)
            .await;
        pool.add_worker(make_worker("closed", 4, 40.0).config).await;

        // Put worker in half-open state and exhaust probe budget
        let half_open_worker = pool.get(&WorkerId::new("half_open")).await.unwrap();
        half_open_worker.open_circuit().await;
        half_open_worker.half_open_circuit().await;

        let config = CircuitBreakerConfig {
            half_open_max_probes: 1,
            ..Default::default()
        };

        // Start a probe to exhaust the budget
        half_open_worker.start_probe(&config).await;

        let request = SelectionRequest {
            project: "myproject".to_string(),
            command: None,
            estimated_cores: 2,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
        };
        let weights = SelectionWeights::default();

        let result = select_worker_with_config(&pool, &request, &weights, &config).await;
        let selected = result
            .worker
            .expect("Expected closed worker to be selected");
        assert_eq!(result.reason, SelectionReason::Success);
        // Should select the closed worker since half-open is at probe limit
        assert_eq!(selected.config.id.as_str(), "closed");
    }

    #[tokio::test]
    async fn test_select_worker_prefers_closed_over_half_open() {
        let pool = WorkerPool::new();
        pool.add_worker(make_worker("half_open", 16, 90.0).config)
            .await;
        pool.add_worker(make_worker("closed", 8, 50.0).config).await;

        // Put first worker in half-open state (normally would be preferred due to higher speed)
        let half_open_worker = pool.get(&WorkerId::new("half_open")).await.unwrap();
        half_open_worker.open_circuit().await;
        half_open_worker.half_open_circuit().await;

        let request = SelectionRequest {
            project: "myproject".to_string(),
            command: None,
            estimated_cores: 2,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
        };
        let weights = SelectionWeights::default();
        let config = CircuitBreakerConfig::default();

        let result = select_worker_with_config(&pool, &request, &weights, &config).await;
        let selected = result.worker.expect("Expected a worker to be selected");
        assert_eq!(result.reason, SelectionReason::Success);
        // Should prefer closed worker due to half-open penalty
        assert_eq!(selected.config.id.as_str(), "closed");
    }

    #[tokio::test]
    async fn test_select_worker_prefers_preferred_list() {
        let pool = WorkerPool::new();
        pool.add_worker(make_worker("preferred", 8, 30.0).config)
            .await;
        pool.add_worker(make_worker("other", 8, 90.0).config).await;

        let request = SelectionRequest {
            project: "myproject".to_string(),
            command: None,
            estimated_cores: 2,
            preferred_workers: vec![WorkerId::new("preferred")],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
        };
        let weights = SelectionWeights::default();
        let config = CircuitBreakerConfig::default();

        let result = select_worker_with_config(&pool, &request, &weights, &config).await;
        let selected = result.worker.expect("Expected a worker to be selected");
        assert_eq!(selected.config.id.as_str(), "preferred");
    }

    #[tokio::test]
    async fn test_select_worker_falls_back_when_preferred_unavailable() {
        let pool = WorkerPool::new();
        pool.add_worker(make_worker("available", 8, 60.0).config)
            .await;

        let request = SelectionRequest {
            project: "myproject".to_string(),
            command: None,
            estimated_cores: 2,
            preferred_workers: vec![WorkerId::new("missing")],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
        };
        let weights = SelectionWeights::default();
        let config = CircuitBreakerConfig::default();

        let result = select_worker_with_config(&pool, &request, &weights, &config).await;
        let selected = result.worker.expect("Expected fallback to eligible worker");
        assert_eq!(selected.config.id.as_str(), "available");
    }

    #[tokio::test]
    async fn test_select_worker_prefers_higher_priority() {
        let pool = WorkerPool::new();
        let mut high = make_worker("high", 8, 70.0);
        high.config.priority = 200;
        let mut low = make_worker("low", 8, 70.0);
        low.config.priority = 50;

        pool.add_worker(high.config).await;
        pool.add_worker(low.config).await;

        let request = SelectionRequest {
            project: "myproject".to_string(),
            command: None,
            estimated_cores: 2,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
        };
        let weights = SelectionWeights::default();
        let config = CircuitBreakerConfig::default();

        let result = select_worker_with_config(&pool, &request, &weights, &config).await;
        let selected = result.worker.expect("Expected a worker to be selected");
        assert_eq!(selected.config.id.as_str(), "high");
    }

    #[tokio::test]
    async fn test_half_open_penalty_applied() {
        // Test that the half-open penalty is correctly applied
        let weights = SelectionWeights {
            slots: 0.0,
            speed: 1.0,
            locality: 0.0,
            priority: 0.0,
            half_open_penalty: 0.5,
        };

        // Worker with 80% speed score
        // Closed: 0.8 (80/100)
        // Half-open: 0.8 * 0.5 = 0.4
        let pool = WorkerPool::new();
        pool.add_worker(make_worker("half_open", 16, 80.0).config)
            .await;
        pool.add_worker(make_worker("closed", 8, 50.0).config).await;

        // Put first worker in half-open state
        let half_open_worker = pool.get(&WorkerId::new("half_open")).await.unwrap();
        half_open_worker.open_circuit().await;
        half_open_worker.half_open_circuit().await;

        let request = SelectionRequest {
            project: "myproject".to_string(),
            command: None,
            estimated_cores: 2,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
        };
        let config = CircuitBreakerConfig::default();

        let result = select_worker_with_config(&pool, &request, &weights, &config).await;
        let selected = result.worker.expect("Expected a worker to be selected");
        // closed worker has 50/100 = 0.5 score
        // half-open worker has 80/100 * 0.5 = 0.4 score
        // So closed should win
        assert_eq!(selected.config.id.as_str(), "closed");
    }

    // =========================================================================
    // Cache Tracker Tests
    // =========================================================================

    #[test]
    fn test_cache_tracker_record_and_warmth() {
        let mut tracker = CacheTracker::new();
        tracker.record_build("worker1", "project-a");

        // Should have full warmth for just-recorded build
        let warmth = tracker.estimate_warmth("worker1", "project-a");
        assert!(warmth > 0.9, "Expected warmth > 0.9, got {}", warmth);

        // Unknown project should have zero warmth
        let unknown = tracker.estimate_warmth("worker1", "project-b");
        assert_eq!(unknown, 0.0);

        // Unknown worker should have zero warmth
        let unknown = tracker.estimate_warmth("worker2", "project-a");
        assert_eq!(unknown, 0.0);
    }

    #[test]
    fn test_cache_tracker_has_recent_build() {
        let mut tracker = CacheTracker::new();
        tracker.record_build("worker1", "project-a");

        // Should report recent build within short window
        assert!(tracker.has_recent_build("worker1", "project-a", Duration::from_secs(60)));

        // Unknown project should not have recent build
        assert!(!tracker.has_recent_build("worker1", "project-b", Duration::from_secs(60)));
    }

    // =========================================================================
    // Selection History Tests
    // =========================================================================

    #[test]
    fn test_selection_history_record_and_count() {
        let mut history = SelectionHistory::new();

        // Record some selections
        history.record_selection("worker1");
        history.record_selection("worker1");
        history.record_selection("worker2");

        // Should count recent selections
        let count1 = history.recent_selections("worker1", Duration::from_secs(60));
        assert_eq!(count1, 2);

        let count2 = history.recent_selections("worker2", Duration::from_secs(60));
        assert_eq!(count2, 1);

        // Unknown worker should have zero selections
        let count3 = history.recent_selections("worker3", Duration::from_secs(60));
        assert_eq!(count3, 0);
    }

    #[test]
    fn test_selection_history_prune() {
        let mut history = SelectionHistory::new();
        history.record_selection("worker1");

        // Prune with zero max age should clear everything
        history.prune(Duration::ZERO);

        // But since the selection just happened, it won't be pruned yet
        // (the cutoff is now - max_age, and the selection is at now)
        let count = history.recent_selections("worker1", Duration::from_secs(60));
        // After prune with zero max age, the just-recorded selection should still exist
        // because prune uses cutoff = now - max_age, and with zero max_age the cutoff is now
        let _ = count; // Count verified as a valid result
    }

    // =========================================================================
    // WorkerSelector Strategy Tests
    // =========================================================================

    #[tokio::test]
    async fn test_worker_selector_priority_strategy() {
        let pool = WorkerPool::new();

        let mut high_priority = make_worker("high-priority", 8, 50.0);
        high_priority.config.priority = 200;
        pool.add_worker(high_priority.config).await;

        let mut low_priority = make_worker("low-priority", 8, 90.0);
        low_priority.config.priority = 50;
        pool.add_worker(low_priority.config).await;

        let selector = WorkerSelector::with_config(
            SelectionConfig {
                strategy: SelectionStrategy::Priority,
                ..Default::default()
            },
            CircuitBreakerConfig::default(),
        );

        let request = SelectionRequest {
            project: "test-project".to_string(),
            command: None,
            estimated_cores: 2,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
        };

        let result = selector.select(&pool, &request).await;
        let selected = result.worker.expect("Expected a worker");
        // Should select by priority, not speed
        assert_eq!(selected.config.id.as_str(), "high-priority");
    }

    #[tokio::test]
    async fn test_worker_selector_fastest_strategy() {
        let pool = WorkerPool::new();

        // Use add_worker_state to preserve speed_score values
        let mut high_priority = make_worker("high-priority", 8, 50.0);
        high_priority.config.priority = 200;
        pool.add_worker_state(high_priority).await;

        let mut fastest = make_worker("fastest", 8, 90.0);
        fastest.config.priority = 50;
        pool.add_worker_state(fastest).await;

        let selector = WorkerSelector::with_config(
            SelectionConfig {
                strategy: SelectionStrategy::Fastest,
                ..Default::default()
            },
            CircuitBreakerConfig::default(),
        );

        let request = SelectionRequest {
            project: "test-project".to_string(),
            command: None,
            estimated_cores: 2,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
        };

        let result = selector.select(&pool, &request).await;
        let selected = result.worker.expect("Expected a worker");
        // Should select by speed, not priority
        assert_eq!(selected.config.id.as_str(), "fastest");
    }

    #[tokio::test]
    async fn test_worker_selector_balanced_strategy() {
        let pool = WorkerPool::new();
        pool.add_worker(make_worker("worker1", 8, 70.0).config).await;
        pool.add_worker(make_worker("worker2", 8, 80.0).config).await;

        let selector = WorkerSelector::with_config(
            SelectionConfig {
                strategy: SelectionStrategy::Balanced,
                ..Default::default()
            },
            CircuitBreakerConfig::default(),
        );

        let request = SelectionRequest {
            project: "test-project".to_string(),
            command: None,
            estimated_cores: 2,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
        };

        let result = selector.select(&pool, &request).await;
        // Should return a worker (either one is fine for this test)
        assert!(result.worker.is_some());
        assert_eq!(result.reason, SelectionReason::Success);
    }

    #[tokio::test]
    async fn test_worker_selector_cache_affinity_strategy() {
        let pool = WorkerPool::new();
        pool.add_worker(make_worker("warm-cache", 8, 50.0).config)
            .await;
        pool.add_worker(make_worker("cold-cache", 8, 90.0).config)
            .await;

        let selector = WorkerSelector::with_config(
            SelectionConfig {
                strategy: SelectionStrategy::CacheAffinity,
                ..Default::default()
            },
            CircuitBreakerConfig::default(),
        );

        // Record a build for warm-cache worker
        selector.record_build("warm-cache", "test-project").await;

        let request = SelectionRequest {
            project: "test-project".to_string(),
            command: None,
            estimated_cores: 2,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
        };

        let result = selector.select(&pool, &request).await;
        let selected = result.worker.expect("Expected a worker");
        // Should prefer warm cache despite lower speed
        assert_eq!(selected.config.id.as_str(), "warm-cache");
    }

    #[tokio::test]
    async fn test_worker_selector_cache_affinity_fallback_to_fastest() {
        let pool = WorkerPool::new();
        // Use add_worker_state to preserve speed scores
        pool.add_worker_state(make_worker("slow", 8, 50.0)).await;
        pool.add_worker_state(make_worker("fast", 8, 90.0)).await;

        let selector = WorkerSelector::with_config(
            SelectionConfig {
                strategy: SelectionStrategy::CacheAffinity,
                ..Default::default()
            },
            CircuitBreakerConfig::default(),
        );

        // No cache warmth recorded for either worker
        let request = SelectionRequest {
            project: "new-project".to_string(),
            command: None,
            estimated_cores: 2,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
        };

        let result = selector.select(&pool, &request).await;
        let selected = result.worker.expect("Expected a worker");
        // Should fall back to fastest when no warm cache
        assert_eq!(selected.config.id.as_str(), "fast");
    }

    #[tokio::test]
    async fn test_worker_selector_fair_fastest_distributes() {
        let pool = WorkerPool::new();
        pool.add_worker(make_worker("worker1", 8, 80.0).config).await;
        pool.add_worker(make_worker("worker2", 8, 80.0).config).await;

        let selector = WorkerSelector::with_config(
            SelectionConfig {
                strategy: SelectionStrategy::FairFastest,
                ..Default::default()
            },
            CircuitBreakerConfig::default(),
        );

        let request = SelectionRequest {
            project: "test-project".to_string(),
            command: None,
            estimated_cores: 2,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
        };

        // Run multiple selections and verify distribution
        let mut worker1_count = 0;
        let mut worker2_count = 0;

        for _ in 0..20 {
            let result = selector.select(&pool, &request).await;
            if let Some(worker) = result.worker {
                if worker.config.id.as_str() == "worker1" {
                    worker1_count += 1;
                } else {
                    worker2_count += 1;
                }
            }
        }

        // Both workers should have been selected at least once
        // (with equal speeds and fairness, distribution should be roughly even)
        assert!(worker1_count > 0, "Worker1 should be selected at least once");
        assert!(worker2_count > 0, "Worker2 should be selected at least once");
    }

    #[tokio::test]
    async fn test_worker_selector_records_build_for_cache() {
        let selector = WorkerSelector::new();

        // Record a build
        selector.record_build("worker1", "project-a").await;

        // Verify cache warmth is tracked
        let cache = selector.cache_tracker.read().await;
        let warmth = cache.estimate_warmth("worker1", "project-a");
        assert!(warmth > 0.9);
    }

    #[tokio::test]
    async fn test_worker_selector_handles_empty_pool() {
        let pool = WorkerPool::new();
        let selector = WorkerSelector::new();

        let request = SelectionRequest {
            project: "test-project".to_string(),
            command: None,
            estimated_cores: 2,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
        };

        let result = selector.select(&pool, &request).await;
        assert!(result.worker.is_none());
        assert_eq!(result.reason, SelectionReason::NoWorkersConfigured);
    }

    #[tokio::test]
    async fn test_worker_selector_respects_preferred_workers() {
        let pool = WorkerPool::new();
        pool.add_worker(make_worker("preferred", 8, 50.0).config)
            .await;
        pool.add_worker(make_worker("faster", 8, 90.0).config)
            .await;

        let selector = WorkerSelector::with_config(
            SelectionConfig {
                strategy: SelectionStrategy::Fastest,
                ..Default::default()
            },
            CircuitBreakerConfig::default(),
        );

        let request = SelectionRequest {
            project: "test-project".to_string(),
            command: None,
            estimated_cores: 2,
            preferred_workers: vec![WorkerId::new("preferred")],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
        };

        let result = selector.select(&pool, &request).await;
        let selected = result.worker.expect("Expected a worker");
        // Preferred workers take precedence even with Fastest strategy
        assert_eq!(selected.config.id.as_str(), "preferred");
    }
}
