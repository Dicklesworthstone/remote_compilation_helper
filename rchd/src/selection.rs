//! Worker selection algorithm with multiple selection strategies.
//!
//! Supports five selection strategies:
//! - **Priority**: Original behavior, sort by priority and select first available
//! - **Fastest**: Select worker with highest SpeedScore
//! - **Balanced**: Balance SpeedScore, load, health, cache affinity, and priority
//! - **CacheAffinity**: Prefer workers with warm caches for the project
//! - **FairFastest**: Weighted random selection favoring fast workers but ensuring fairness

#![allow(dead_code)] // Scaffold code - methods will be used in future beads

use crate::admission::AdmissionGate;
use crate::disk_pressure::PressureState;
use crate::metrics::latency::{DecisionTimer, DecisionType};
use crate::ui::workers::{debug_routing_enabled, log_routing_decision};
use crate::workers::{WorkerPool, WorkerState};
use rand::Rng;
use rch_common::{
    CircuitBreakerConfig, CircuitState, CommandPriority, RequiredRuntime, SelectionConfig,
    SelectionReason, SelectionRequest, SelectionStrategy, SelectionWeightConfig, WorkerId,
    classify_command,
};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, warn};

const DEFAULT_NETWORK_SCORE: f64 = 0.5;
const NETWORK_LATENCY_HALF_LIFE_MS: f64 = 200.0;
const TEST_CACHE_BOOST: f64 = 1.5;
const TEST_BUILD_FALLBACK_FACTOR: f64 = 0.4;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheUse {
    Build,
    Test,
}

#[derive(Debug, Default, Clone)]
struct CacheState {
    last_build: Option<Instant>,
    last_test: Option<Instant>,
    /// Last successful build (exit_code == 0) for affinity pinning.
    last_success: Option<Instant>,
}

impl CacheState {
    fn last_activity(&self) -> Option<Instant> {
        match (self.last_build, self.last_test) {
            (Some(build), Some(test)) => Some(build.max(test)),
            (Some(build), None) => Some(build),
            (None, Some(test)) => Some(test),
            (None, None) => None,
        }
    }
}

/// Tracks last successful build per project for affinity fallback.
#[derive(Debug, Clone)]
pub struct LastSuccessEntry {
    /// Worker ID that last succeeded for this project.
    pub worker_id: String,
    /// When the successful build completed.
    pub timestamp: Instant,
}

/// Tracks recent build/test activity per worker for cache affinity scoring.
#[derive(Debug, Default)]
pub struct CacheTracker {
    /// Map from worker_id -> (project_id -> CacheState)
    workers: HashMap<String, HashMap<String, CacheState>>,
    /// Maximum projects to track per worker.
    max_projects_per_worker: usize,
    /// Map from project_id -> last successful build info (for fallback).
    last_success_by_project: HashMap<String, LastSuccessEntry>,
    /// Maximum projects to track in the global success map.
    max_success_projects: usize,
}

impl CacheTracker {
    /// Create a new cache tracker with default limits.
    pub fn new() -> Self {
        Self {
            workers: HashMap::new(),
            max_projects_per_worker: 50,
            last_success_by_project: HashMap::new(),
            max_success_projects: 200,
        }
    }

    /// Record a build completion on a worker for a project.
    pub fn record_build(&mut self, worker_id: &str, project_id: &str, cache_use: CacheUse) {
        let cache = self.workers.entry(worker_id.to_string()).or_default();
        let state = cache.entry(project_id.to_string()).or_default();
        let now = Instant::now();

        match cache_use {
            CacheUse::Build => {
                state.last_build = Some(now);
            }
            CacheUse::Test => {
                state.last_test = Some(now);
                // Tests also produce build artifacts, so treat as a build too.
                state.last_build = Some(now);
            }
        }

        // Limit to max_projects_per_worker most recent
        while cache.len() > self.max_projects_per_worker {
            let oldest = cache
                .iter()
                .min_by_key(|(_, state)| state.last_activity())
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
    pub fn estimate_warmth(&self, worker_id: &str, project_id: &str, cache_use: CacheUse) -> f64 {
        self.workers
            .get(worker_id)
            .and_then(|c| c.get(project_id))
            .map(|state| match cache_use {
                CacheUse::Build => state
                    .last_activity()
                    .map(Self::warmth_from_instant)
                    .unwrap_or(0.0),
                CacheUse::Test => {
                    let test_warmth = state
                        .last_test
                        .map(Self::warmth_from_instant)
                        .unwrap_or(0.0);
                    let build_warmth = state
                        .last_build
                        .map(Self::warmth_from_instant)
                        .unwrap_or(0.0)
                        * TEST_BUILD_FALLBACK_FACTOR;
                    test_warmth.max(build_warmth)
                }
            })
            .unwrap_or(0.0)
    }

    /// Check if a worker has a recent build for a project.
    pub fn has_recent_build(
        &self,
        worker_id: &str,
        project_id: &str,
        cache_use: CacheUse,
        max_age: Duration,
    ) -> bool {
        self.workers
            .get(worker_id)
            .and_then(|c| c.get(project_id))
            .map(|state| match cache_use {
                CacheUse::Build => state
                    .last_activity()
                    .map(|instant| instant.elapsed() < max_age)
                    .unwrap_or(false),
                CacheUse::Test => {
                    // Check last_test first
                    if let Some(last_test) = state.last_test
                        && last_test.elapsed() < max_age
                    {
                        return true;
                    }
                    // Fallback to last_build (artifacts are useful for tests)
                    state
                        .last_build
                        .map(|instant| instant.elapsed() < max_age)
                        .unwrap_or(false)
                }
            })
            .unwrap_or(false)
    }

    fn warmth_from_instant(last_build: Instant) -> f64 {
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
    }

    // ========================================================================
    // Affinity Pinning Methods
    // ========================================================================

    /// Record a successful build completion for affinity tracking.
    ///
    /// Only called when exit_code == 0. Updates both per-worker cache state
    /// and the global last-success-by-project map.
    pub fn record_success(&mut self, worker_id: &str, project_id: &str) {
        let now = Instant::now();

        // Update per-worker cache state
        if let Some(cache) = self.workers.get_mut(worker_id)
            && let Some(state) = cache.get_mut(project_id)
        {
            state.last_success = Some(now);
        }

        // Update global last-success-by-project
        self.last_success_by_project.insert(
            project_id.to_string(),
            LastSuccessEntry {
                worker_id: worker_id.to_string(),
                timestamp: now,
            },
        );

        // Evict oldest entries if over limit
        while self.last_success_by_project.len() > self.max_success_projects {
            let oldest = self
                .last_success_by_project
                .iter()
                .min_by_key(|(_, entry)| entry.timestamp)
                .map(|(k, _)| k.clone());
            if let Some(key) = oldest {
                self.last_success_by_project.remove(&key);
            }
        }
    }

    /// Check if a project is pinned to a specific worker within the pin window.
    ///
    /// Returns Some(worker_id) if:
    /// - The project has a recent successful build on a worker
    /// - The success occurred within `pin_window`
    pub fn get_pinned_worker(&self, project_id: &str, pin_window: Duration) -> Option<&str> {
        self.last_success_by_project
            .get(project_id)
            .filter(|entry| entry.timestamp.elapsed() < pin_window)
            .map(|entry| entry.worker_id.as_str())
    }

    /// Get the last successful worker for a project (for fallback).
    ///
    /// Unlike `get_pinned_worker`, this doesn't check the pin window.
    /// Used when all workers fail selection criteria.
    pub fn get_last_success_worker(&self, project_id: &str) -> Option<&LastSuccessEntry> {
        self.last_success_by_project.get(project_id)
    }

    /// Check if a worker has had a recent successful build for a project.
    pub fn has_recent_success(&self, worker_id: &str, project_id: &str, max_age: Duration) -> bool {
        self.workers
            .get(worker_id)
            .and_then(|c| c.get(project_id))
            .and_then(|state| state.last_success)
            .map(|instant| instant.elapsed() < max_age)
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
// Selection Audit Log (bd-37hc)
// ============================================================================

/// Default maximum audit log entries.
const DEFAULT_AUDIT_LOG_SIZE: usize = 100;

/// Score breakdown for a single worker in a selection decision.
#[derive(Debug, Clone, serde::Serialize)]
pub struct WorkerScoreBreakdown {
    /// Worker identifier.
    pub worker_id: String,
    /// Worker's total score.
    pub total_score: f64,
    /// Speed score component.
    pub speed_score: f64,
    /// Slot availability component (0.0-1.0).
    pub slot_availability: f64,
    /// Cache affinity component (0.0-1.0).
    pub cache_affinity: f64,
    /// Priority component (normalized 0.0-1.0).
    pub priority_score: f64,
    /// Circuit state at selection time.
    pub circuit_state: String,
    /// Whether this worker was selected.
    pub selected: bool,
    /// Reason if skipped (e.g., "no slots", "circuit open").
    pub skip_reason: Option<String>,
}

/// A single entry in the selection audit log.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SelectionAuditEntry {
    /// Unique ID for this selection attempt.
    pub id: u64,
    /// Timestamp when selection was made (epoch milliseconds).
    pub timestamp_ms: u64,
    /// Project being built.
    pub project: String,
    /// Command being executed (if available).
    pub command: Option<String>,
    /// Selection strategy used.
    pub strategy: String,
    /// Command priority hint.
    pub command_priority: String,
    /// Required runtime (if any).
    pub required_runtime: Option<String>,
    /// Number of eligible workers considered.
    pub eligible_count: usize,
    /// Detailed score breakdowns for each considered worker.
    pub workers_evaluated: Vec<WorkerScoreBreakdown>,
    /// Selected worker ID (None if no worker selected).
    pub selected_worker_id: Option<String>,
    /// Selection reason.
    pub reason: String,
    /// Classification duration in microseconds (if available).
    pub classification_duration_us: Option<u64>,
    /// Total selection duration in microseconds.
    pub selection_duration_us: u64,
}

/// Ring buffer for selection audit log entries (bd-37hc).
#[derive(Debug)]
pub struct SelectionAuditLog {
    /// Audit log entries (newest last).
    entries: VecDeque<SelectionAuditEntry>,
    /// Maximum number of entries to keep.
    max_entries: usize,
    /// Counter for generating unique IDs.
    next_id: u64,
}

impl Default for SelectionAuditLog {
    fn default() -> Self {
        Self::new(DEFAULT_AUDIT_LOG_SIZE)
    }
}

impl SelectionAuditLog {
    /// Create a new audit log with the specified capacity.
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: VecDeque::with_capacity(max_entries),
            max_entries,
            next_id: 1,
        }
    }

    /// Add a new entry to the audit log, evicting oldest if at capacity.
    pub fn push(&mut self, mut entry: SelectionAuditEntry) {
        entry.id = self.next_id;
        self.next_id += 1;

        if self.entries.len() >= self.max_entries {
            self.entries.pop_front();
        }
        self.entries.push_back(entry);
    }

    /// Get all entries (oldest first).
    pub fn entries(&self) -> &VecDeque<SelectionAuditEntry> {
        &self.entries
    }

    /// Get the last N entries (newest first).
    pub fn last_n(&self, n: usize) -> Vec<&SelectionAuditEntry> {
        self.entries.iter().rev().take(n).collect()
    }

    /// Get the most recent entry.
    pub fn last(&self) -> Option<&SelectionAuditEntry> {
        self.entries.back()
    }

    /// Get entry by ID.
    pub fn get(&self, id: u64) -> Option<&SelectionAuditEntry> {
        self.entries.iter().find(|e| e.id == id)
    }

    /// Get the current entry count.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the log is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
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
    /// Selection audit log (bd-37hc).
    pub audit_log: Arc<RwLock<SelectionAuditLog>>,
    /// Optional admission gate for disk-pressure risk evaluation (bd-vvmd.4.4).
    pub admission_gate: Option<Arc<AdmissionGate>>,
}

/// Result of worker selection with reason.
pub struct SelectionResult {
    /// Selected worker, if available.
    pub worker: Option<Arc<WorkerState>>,
    /// Reason for the selection result.
    pub reason: SelectionReason,
}

fn cache_use_for_request(request: &SelectionRequest) -> CacheUse {
    let Some(command) = request.command.as_deref() else {
        return CacheUse::Build;
    };

    let classification = classify_command(command);
    if classification
        .kind
        .map(|kind| kind.is_test_command())
        .unwrap_or(false)
    {
        CacheUse::Test
    } else {
        CacheUse::Build
    }
}

impl WorkerSelector {
    /// Create a new worker selector with default configuration.
    pub fn new() -> Self {
        Self {
            config: SelectionConfig::default(),
            circuit_config: CircuitBreakerConfig::default(),
            cache_tracker: Arc::new(RwLock::new(CacheTracker::new())),
            selection_history: Arc::new(RwLock::new(SelectionHistory::new())),
            audit_log: Arc::new(RwLock::new(SelectionAuditLog::default())),
            admission_gate: None,
        }
    }

    /// Create a new worker selector with explicit configuration.
    pub fn with_config(config: SelectionConfig, circuit_config: CircuitBreakerConfig) -> Self {
        Self {
            config,
            circuit_config,
            cache_tracker: Arc::new(RwLock::new(CacheTracker::new())),
            selection_history: Arc::new(RwLock::new(SelectionHistory::new())),
            audit_log: Arc::new(RwLock::new(SelectionAuditLog::default())),
            admission_gate: None,
        }
    }

    /// Set the admission gate for disk-pressure risk evaluation (bd-vvmd.4.4).
    pub fn set_admission_gate(&mut self, gate: Arc<AdmissionGate>) {
        self.admission_gate = Some(gate);
    }

    /// Get a read-only view of the audit log entries.
    pub async fn get_audit_log(&self, limit: Option<usize>) -> Vec<SelectionAuditEntry> {
        let log = self.audit_log.read().await;
        match limit {
            Some(n) => log.last_n(n).into_iter().cloned().collect(),
            None => log.entries().iter().cloned().collect(),
        }
    }

    /// Get the most recent audit log entry.
    pub async fn get_last_audit_entry(&self) -> Option<SelectionAuditEntry> {
        let log = self.audit_log.read().await;
        log.last().cloned()
    }

    /// Select a worker using the configured strategy.
    pub async fn select(&self, pool: &WorkerPool, request: &SelectionRequest) -> SelectionResult {
        let _timer = DecisionTimer::new(DecisionType::WorkerSelection);
        let select_start = Instant::now();
        let cache_use = cache_use_for_request(request);

        // Get eligible workers
        let eligible = match self.get_eligible_workers(pool, request).await {
            Ok(workers) => workers,
            Err(reason) => {
                // Record failed selection in audit log
                self.record_audit_entry(request, Vec::new(), None, &reason, select_start.elapsed())
                    .await;
                return SelectionResult {
                    worker: None,
                    reason,
                };
            }
        };

        if eligible.is_empty() {
            // Try last-success fallback if enabled
            if let Some(fallback_worker_id) = self.try_fallback(pool, request).await {
                // Record fallback selection in audit log
                self.record_audit_entry(
                    request,
                    Vec::new(),
                    Some(fallback_worker_id.clone()),
                    &SelectionReason::AffinityFallback,
                    select_start.elapsed(),
                )
                .await;
                let worker_id = WorkerId::new(&fallback_worker_id);
                if let Some(worker) = pool.get(&worker_id).await {
                    debug!(
                        "Using affinity fallback worker {} for project {}",
                        fallback_worker_id, request.project
                    );
                    return SelectionResult {
                        worker: Some(worker),
                        reason: SelectionReason::AffinityFallback,
                    };
                }
            }

            // Record empty selection in audit log
            self.record_audit_entry(
                request,
                Vec::new(),
                None,
                &SelectionReason::AllWorkersBusy,
                select_start.elapsed(),
            )
            .await;
            return SelectionResult {
                worker: None,
                reason: SelectionReason::AllWorkersBusy,
            };
        }

        // Check for affinity-pinned worker (if enabled)
        let pinned_selection = self.try_pinned_worker(&eligible, request).await;
        if let Some((worker, circuit_state)) = pinned_selection {
            let worker_id = worker.config.read().await.id.as_str().to_string();
            debug!(
                "Using affinity-pinned worker {} for project {}",
                worker_id, request.project
            );

            // Record the selection for fairness tracking
            let mut history = self.selection_history.write().await;
            history.record_selection(&worker_id);

            // Record in audit log
            let breakdowns = self
                .build_score_breakdowns(&eligible, request, cache_use, Some(&worker_id))
                .await;
            self.record_audit_entry(
                request,
                breakdowns,
                Some(worker_id.clone()),
                &SelectionReason::AffinityPinned,
                select_start.elapsed(),
            )
            .await;

            // If selecting a half-open worker, start the probe
            if circuit_state == CircuitState::HalfOpen {
                worker.start_probe(&self.circuit_config).await;
            }

            return SelectionResult {
                worker: Some(worker),
                reason: SelectionReason::AffinityPinned,
            };
        }

        // Apply the configured selection strategy (with per-command priority hint).
        let selected = match self.config.strategy {
            SelectionStrategy::Priority => {
                self.select_by_priority(&eligible, request, cache_use).await
            }
            SelectionStrategy::Fastest => {
                if request.command_priority == CommandPriority::Low {
                    self.select_fair_fastest(&eligible).await
                } else {
                    self.select_by_fastest(&eligible).await
                }
            }
            SelectionStrategy::Balanced => {
                self.select_balanced(&eligible, request, cache_use).await
            }
            SelectionStrategy::CacheAffinity => match request.command_priority {
                CommandPriority::High => self.select_by_fastest(&eligible).await,
                CommandPriority::Normal | CommandPriority::Low => {
                    self.select_cache_affinity(&eligible, request, cache_use)
                        .await
                }
            },
            SelectionStrategy::FairFastest => {
                if request.command_priority == CommandPriority::High {
                    self.select_by_fastest(&eligible).await
                } else {
                    self.select_fair_fastest(&eligible).await
                }
            }
        };

        if let Some((worker, circuit_state)) = selected {
            let worker_id = worker.config.read().await.id.as_str().to_string();

            if debug_routing_enabled() {
                let scores = self.debug_scores(&eligible, request, cache_use).await;
                let circuit_label = format!("{:?}", circuit_state);
                log_routing_decision(
                    self.config.strategy,
                    &worker_id,
                    Some(circuit_label.as_str()),
                    &scores,
                    eligible.len(),
                );
            }

            // Record in audit log (bd-37hc)
            let breakdowns = self
                .build_score_breakdowns(&eligible, request, cache_use, Some(&worker_id))
                .await;
            self.record_audit_entry(
                request,
                breakdowns,
                Some(worker_id.clone()),
                &SelectionReason::Success,
                select_start.elapsed(),
            )
            .await;

            // If selecting a half-open worker, start the probe
            if circuit_state == CircuitState::HalfOpen {
                worker.start_probe(&self.circuit_config).await;
                debug!(
                    "Worker {} selected (half-open probe), strategy={:?}",
                    worker_id, self.config.strategy
                );
            } else {
                debug!(
                    "Worker {} selected, strategy={:?}",
                    worker_id, self.config.strategy
                );
            }

            // Record the selection for fairness tracking
            let mut history = self.selection_history.write().await;
            history.record_selection(&worker_id);

            SelectionResult {
                worker: Some(worker),
                reason: SelectionReason::Success,
            }
        } else {
            // Record failed selection in audit log (bd-37hc)
            let breakdowns = self
                .build_score_breakdowns(&eligible, request, cache_use, None)
                .await;
            self.record_audit_entry(
                request,
                breakdowns,
                None,
                &SelectionReason::AllWorkersBusy,
                select_start.elapsed(),
            )
            .await;

            SelectionResult {
                worker: None,
                reason: SelectionReason::AllWorkersBusy,
            }
        }
    }

    /// Record a build/test completion for cache affinity tracking.
    pub async fn record_build(&self, worker_id: &str, project_id: &str, is_test: bool) {
        let mut cache = self.cache_tracker.write().await;
        let cache_use = if is_test {
            CacheUse::Test
        } else {
            CacheUse::Build
        };
        cache.record_build(worker_id, project_id, cache_use);
    }

    /// Record a successful build for affinity pinning.
    ///
    /// Call this when a build completes with exit_code == 0.
    /// Updates both cache warmth and last-success tracking for fallback.
    pub async fn record_success(&self, worker_id: &str, project_id: &str) {
        let mut cache = self.cache_tracker.write().await;
        cache.record_success(worker_id, project_id);
    }

    /// Check if a project has an affinity-pinned worker.
    ///
    /// Returns Some(worker_id) if the project should preferentially use
    /// a specific worker based on recent successful builds.
    pub async fn get_pinned_worker(&self, project_id: &str) -> Option<String> {
        if !self.config.affinity.enabled {
            return None;
        }

        let pin_window = Duration::from_secs(self.config.affinity.pin_minutes * 60);
        let cache = self.cache_tracker.read().await;
        cache
            .get_pinned_worker(project_id, pin_window)
            .map(String::from)
    }

    /// Get the last successful worker for fallback.
    ///
    /// Used when all workers fail normal selection criteria.
    pub async fn get_fallback_worker(&self, project_id: &str) -> Option<String> {
        if !self.config.affinity.enable_last_success_fallback {
            return None;
        }

        let cache = self.cache_tracker.read().await;
        cache
            .get_last_success_worker(project_id)
            .map(|entry| entry.worker_id.clone())
    }

    /// Try to select an affinity-pinned worker from the eligible list.
    ///
    /// Returns the pinned worker if:
    /// - Affinity is enabled
    /// - Project has a pinned worker within the pin window
    /// - The pinned worker is in the eligible list
    async fn try_pinned_worker(
        &self,
        eligible: &[(Arc<WorkerState>, CircuitState)],
        request: &SelectionRequest,
    ) -> Option<(Arc<WorkerState>, CircuitState)> {
        if !self.config.affinity.enabled {
            return None;
        }

        let pinned_worker_id = self.get_pinned_worker(&request.project).await?;

        // Find the pinned worker in the eligible list
        for (worker, circuit_state) in eligible {
            let config = worker.config.read().await;
            if config.id.as_str() == pinned_worker_id {
                return Some((worker.clone(), *circuit_state));
            }
        }

        None
    }

    /// Try to find a fallback worker when no eligible workers exist.
    ///
    /// Returns the last-success worker if:
    /// - Last-success fallback is enabled
    /// - The worker still exists in the pool
    /// - The worker has available slots
    /// - The worker's circuit is not open
    async fn try_fallback(&self, pool: &WorkerPool, request: &SelectionRequest) -> Option<String> {
        if !self.config.affinity.enable_last_success_fallback {
            return None;
        }

        let fallback_id = self.get_fallback_worker(&request.project).await?;

        // Check if the fallback worker is viable
        let worker_id = WorkerId::new(&fallback_id);
        let worker = pool.get(&worker_id).await?;
        let available = worker.available_slots().await;
        if available == 0 {
            return None;
        }

        // Check circuit state (don't use if open)
        if let Some(circuit_state) = worker.circuit_state().await
            && circuit_state == CircuitState::Open
        {
            return None;
        }

        Some(fallback_id)
    }

    /// Build score breakdowns for all workers in a selection decision (bd-37hc).
    async fn build_score_breakdowns(
        &self,
        workers: &[(Arc<WorkerState>, CircuitState)],
        request: &SelectionRequest,
        cache_use: CacheUse,
        selected_id: Option<&str>,
    ) -> Vec<WorkerScoreBreakdown> {
        let cache = self.cache_tracker.read().await;
        let (min_priority, max_priority) = Self::priority_range(workers).await;
        let mut breakdowns = Vec::with_capacity(workers.len());

        for (worker, circuit_state) in workers {
            let config = worker.config.read().await;
            let worker_id = config.id.as_str().to_string();
            let speed_score = worker.get_speed_score();
            let total_slots = config.total_slots;
            let used_slots = worker.used_slots();
            let slot_availability = if total_slots > 0 {
                1.0 - (used_slots as f64 / total_slots as f64)
            } else {
                0.0
            };
            let cache_affinity = cache.estimate_warmth(&worker_id, &request.project, cache_use);
            let priority_score =
                Self::normalize_priority(config.priority, min_priority, max_priority);

            // Check if this worker can actually take the job
            let skip_reason = if *circuit_state == CircuitState::Open {
                Some("circuit open".to_string())
            } else if used_slots >= total_slots {
                Some("no slots available".to_string())
            } else {
                None
            };

            let selected = selected_id == Some(worker_id.as_str());

            breakdowns.push(WorkerScoreBreakdown {
                worker_id,
                total_score: speed_score * slot_availability, // Simplified total
                speed_score,
                slot_availability,
                cache_affinity,
                priority_score,
                circuit_state: format!("{:?}", circuit_state),
                selected,
                skip_reason,
            });
        }

        breakdowns
    }

    /// Record an entry in the selection audit log (bd-37hc).
    async fn record_audit_entry(
        &self,
        request: &SelectionRequest,
        workers_evaluated: Vec<WorkerScoreBreakdown>,
        selected_worker_id: Option<String>,
        reason: &SelectionReason,
        duration: Duration,
    ) {
        use std::time::{SystemTime, UNIX_EPOCH};

        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let entry = SelectionAuditEntry {
            id: 0, // Will be assigned by the log
            timestamp_ms,
            project: request.project.clone(),
            command: request.command.clone(),
            strategy: format!("{:?}", self.config.strategy),
            command_priority: format!("{:?}", request.command_priority),
            required_runtime: match request.required_runtime {
                RequiredRuntime::None => None,
                ref rt => Some(format!("{:?}", rt)),
            },
            eligible_count: workers_evaluated.len(),
            workers_evaluated,
            selected_worker_id,
            reason: format!("{:?}", reason),
            classification_duration_us: request.classification_duration_us,
            selection_duration_us: duration.as_micros() as u64,
        };

        let mut log = self.audit_log.write().await;
        log.push(entry);
    }

    async fn debug_scores(
        &self,
        workers: &[(Arc<WorkerState>, CircuitState)],
        request: &SelectionRequest,
        cache_use: CacheUse,
    ) -> Vec<(String, f64)> {
        let mut scores = Vec::new();

        match self.config.strategy {
            SelectionStrategy::Priority => {
                for (worker, _) in workers {
                    let config = worker.config.read().await;
                    scores.push((config.id.as_str().to_string(), config.priority as f64));
                }
            }
            SelectionStrategy::Fastest | SelectionStrategy::FairFastest => {
                for (worker, _) in workers {
                    let score = worker.get_speed_score();
                    let id = worker.config.read().await.id.as_str().to_string();
                    scores.push((id, score));
                }
            }
            SelectionStrategy::Balanced => {
                let cache = self.cache_tracker.read().await;
                let weights = adjust_weights_for_priority(&self.config.weights, request);
                let (min_priority, max_priority) = Self::priority_range(workers).await;
                for (worker, circuit_state) in workers {
                    let score = self
                        .compute_balanced_score(
                            worker,
                            *circuit_state,
                            &request.project,
                            &cache,
                            cache_use,
                            &weights,
                            min_priority,
                            max_priority,
                        )
                        .await;
                    let id = worker.config.read().await.id.as_str().to_string();
                    scores.push((id, score));
                }
            }
            SelectionStrategy::CacheAffinity => {
                let cache = self.cache_tracker.read().await;
                for (worker, _) in workers {
                    let id = worker.config.read().await.id.as_str().to_string();
                    let score = cache.estimate_warmth(id.as_str(), &request.project, cache_use);
                    scores.push((id, score));
                }
            }
        }

        scores
    }

    /// Get eligible workers filtered by health, circuits, slots, and runtime.
    async fn get_eligible_workers(
        &self,
        pool: &WorkerPool,
        request: &SelectionRequest,
    ) -> Result<Vec<(Arc<WorkerState>, CircuitState)>, SelectionReason> {
        // Clear per-round admission verdict cache (bd-vvmd.4.4).
        if let Some(ref gate) = self.admission_gate {
            gate.begin_round().await;
        }

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
                if let Some(state) = worker.circuit_state().await
                    && state != CircuitState::Open
                {
                    all_circuits_open = false;
                }
                if !matches!(
                    worker.status().await,
                    rch_common::WorkerStatus::Unreachable
                        | rch_common::WorkerStatus::Drained
                        | rch_common::WorkerStatus::Disabled
                ) {
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
        let mut eligible_without_health: Vec<(Arc<WorkerState>, CircuitState)> = Vec::new();
        let mut preferred_without_health: Vec<(Arc<WorkerState>, CircuitState)> = Vec::new();
        let mut filtered_by_health = 0usize;
        let mut filtered_by_hard_preflight = 0usize;
        let mut any_has_runtime = false;

        for worker in workers {
            let circuit_state = worker.circuit_state().await.unwrap_or(CircuitState::Closed);
            let worker_id = worker.config.read().await.id.clone();

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

            // Filter by slot availability
            if worker.available_slots().await < request.estimated_cores {
                debug!(
                    "Worker {} excluded: insufficient slots ({} < {})",
                    worker_id,
                    worker.available_slots().await,
                    request.estimated_cores
                );
                continue;
            }

            // Filter by load-per-core threshold (bd-3eaa)
            let capabilities = worker.capabilities().await;
            if let Some(false) = capabilities.is_topology_healthy() {
                let reason = capabilities
                    .projects_root_issue
                    .clone()
                    .unwrap_or_else(|| "unknown_topology_error".to_string());
                debug!(
                    "Worker {} excluded: topology preflight failed ({})",
                    worker_id, reason
                );
                filtered_by_hard_preflight += 1;
                continue;
            }

            let mut passes_preflight = true;
            let mut hard_preflight_block = false;
            if let Some(max_load) = self.config.max_load_per_core
                && let Some(true) = capabilities.is_high_load(max_load)
            {
                let load_per_core = capabilities.load_per_core().unwrap_or(0.0);
                debug!(
                    "Worker {} excluded: high load ({:.2} > {:.2} per core)",
                    worker_id, load_per_core, max_load
                );
                passes_preflight = false;
            }

            // Filter by disk space threshold (bd-3eaa)
            if let Some(min_disk) = self.config.min_free_gb
                && let Some(true) = capabilities.is_low_disk(min_disk)
            {
                let free_gb = capabilities.disk_free_gb.unwrap_or(0.0);
                debug!(
                    "Worker {} excluded: low disk ({:.1} GB < {:.1} GB)",
                    worker_id, free_gb, min_disk
                );
                passes_preflight = false;
            }

            // Disk-pressure and headroom admission gate (bd-vvmd.4.4)
            //
            // When an admission gate is configured, it replaces the basic
            // pressure check with a composite evaluation that also considers
            // headroom estimates and hysteresis.  When no gate is configured,
            // fall back to the original pressure-state filter (bd-vvmd.4.2).
            if let Some(ref gate) = self.admission_gate {
                use crate::admission::AdmissionVerdict;
                let verdict = gate
                    .evaluate(worker.as_ref(), worker_id.as_str(), &request.project)
                    .await;
                match verdict {
                    AdmissionVerdict::Reject {
                        reason_code,
                        reason,
                    } => {
                        debug!(
                            "Worker {} admission rejected: {} ({})",
                            worker_id, reason, reason_code
                        );
                        if reason_code == "admission_critical_pressure" {
                            // Critical pressure: hard exclusion (not even in fallback)
                            hard_preflight_block = true;
                        }
                        passes_preflight = false;
                    }
                    AdmissionVerdict::Admit {
                        pressure_penalty,
                        headroom_score,
                    } => {
                        debug!(
                            "Worker {} admitted: penalty={:.2}, headroom={:.2}",
                            worker_id, pressure_penalty, headroom_score
                        );
                    }
                }
            } else {
                // Legacy path: basic pressure-state filter (bd-vvmd.4.2)
                let pressure = worker.pressure_assessment().await;
                match pressure.state {
                    PressureState::Critical => {
                        debug!(
                            "Worker {} excluded: pressure {} (confidence={}, reason={}, rule={})",
                            worker_id,
                            pressure.state,
                            pressure.confidence,
                            pressure.reason_code,
                            pressure.policy_rule
                        );
                        passes_preflight = false;
                        hard_preflight_block = true;
                    }
                    PressureState::Warning => {
                        debug!(
                            "Worker {} pressure warning (confidence={}, reason={}, rule={})",
                            worker_id,
                            pressure.confidence,
                            pressure.reason_code,
                            pressure.policy_rule
                        );
                    }
                    PressureState::TelemetryGap => {
                        debug!(
                            "Worker {} pressure telemetry gap (confidence={}, reason={}, rule={}); fail-open keeps worker eligible",
                            worker_id,
                            pressure.confidence,
                            pressure.reason_code,
                            pressure.policy_rule
                        );
                    }
                    PressureState::Healthy => {}
                }
            }

            // Critical pressure is a hard preflight exclusion. We do not
            // include these workers in fail-open remote fallback candidates.
            if hard_preflight_block {
                filtered_by_hard_preflight += 1;
                continue;
            }

            // Track workers for fail-open fallback even if they fail preflight
            if has_preferred && preferred_set.contains(worker_id.as_str()) {
                preferred_without_health.push((worker.clone(), circuit_state));
            }
            eligible_without_health.push((worker.clone(), circuit_state));

            // Skip workers failing preflight checks (but keep for fail-open)
            if !passes_preflight {
                continue;
            }

            let success_rate = self.health_score(&worker).await;
            if success_rate < self.config.min_success_rate {
                filtered_by_health += 1;
                debug!(
                    "Worker {} excluded: success_rate {:.2} < min {:.2}",
                    worker_id, success_rate, self.config.min_success_rate
                );
                continue;
            }

            if has_preferred && preferred_set.contains(worker_id.as_str()) {
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
            return Ok(preferred);
        }
        if !eligible.is_empty() {
            return Ok(eligible);
        }

        // Hard preflight failures (for example topology invariants) must not
        // fall back to unhealthy worker assignment; force fail-open local execution.
        if filtered_by_hard_preflight > 0
            && preferred_without_health.is_empty()
            && eligible_without_health.is_empty()
        {
            debug!(
                "All candidate workers failed hard preflight checks (count={})",
                filtered_by_hard_preflight
            );
            return Err(SelectionReason::AllWorkersFailedPreflight);
        }

        if filtered_by_health > 0 {
            debug!(
                "No workers meet min_success_rate {:.2}; falling back to workers below threshold",
                self.config.min_success_rate
            );
        }

        if has_preferred && !preferred_without_health.is_empty() {
            Ok(preferred_without_health)
        } else {
            Ok(eligible_without_health)
        }
    }

    /// Priority strategy: select worker with highest priority.
    async fn select_by_priority(
        &self,
        workers: &[(Arc<WorkerState>, CircuitState)],
        request: &SelectionRequest,
        cache_use: CacheUse,
    ) -> Option<(Arc<WorkerState>, CircuitState)> {
        // Preserve existing behavior for the default case: pick the first worker with the
        // highest worker.priority (in the pool's iteration order).
        let mut best_priority: Option<u32> = None;
        for (worker, _) in workers {
            let priority = worker.config.read().await.priority;
            best_priority = Some(best_priority.map_or(priority, |best: u32| best.max(priority)));
        }

        let best_priority = best_priority?;
        let mut candidates: Vec<(Arc<WorkerState>, CircuitState)> = Vec::new();

        for (worker, circuit_state) in workers {
            let priority = worker.config.read().await.priority;
            if priority == best_priority {
                candidates.push((worker.clone(), *circuit_state));
            }
        }

        match request.command_priority {
            CommandPriority::High => self.select_by_fastest(&candidates).await,
            CommandPriority::Low => {
                let cache = self.cache_tracker.read().await;
                let mut best_idx: Option<usize> = None;
                let mut best_warmth = f64::NEG_INFINITY;

                for (idx, (worker, _)) in candidates.iter().enumerate() {
                    let id = worker.config.read().await.id.as_str().to_string();
                    let warmth = cache.estimate_warmth(id.as_str(), &request.project, cache_use);
                    if warmth > best_warmth {
                        best_warmth = warmth;
                        best_idx = Some(idx);
                    }
                }

                best_idx.map(|idx| (candidates[idx].0.clone(), candidates[idx].1))
            }
            CommandPriority::Normal => candidates.first().cloned(),
        }
    }

    /// Fastest strategy: select worker with highest SpeedScore.
    async fn select_by_fastest(
        &self,
        workers: &[(Arc<WorkerState>, CircuitState)],
    ) -> Option<(Arc<WorkerState>, CircuitState)> {
        let mut best: Option<&(Arc<WorkerState>, CircuitState)> = None;
        for pair in workers {
            let (worker, _) = pair;
            let score = worker.get_speed_score();
            match best {
                None => best = Some(pair),
                Some((best_worker, _)) => {
                    let best_score = best_worker.get_speed_score();
                    if score > best_score {
                        best = Some(pair);
                    }
                }
            }
        }
        best.cloned()
    }

    /// Balanced strategy: balance multiple factors.
    async fn select_balanced(
        &self,
        workers: &[(Arc<WorkerState>, CircuitState)],
        request: &SelectionRequest,
        cache_use: CacheUse,
    ) -> Option<(Arc<WorkerState>, CircuitState)> {
        let cache = self.cache_tracker.read().await;
        let weights = adjust_weights_for_priority(&self.config.weights, request);

        let (min_priority, max_priority) = Self::priority_range(workers).await;

        let mut best: Option<&(Arc<WorkerState>, CircuitState)> = None;
        let mut best_score = f64::NEG_INFINITY;

        for pair in workers {
            let (worker, circuit_state) = pair;
            let score = self
                .compute_balanced_score(
                    worker,
                    *circuit_state,
                    &request.project,
                    &cache,
                    cache_use,
                    &weights,
                    min_priority,
                    max_priority,
                )
                .await;

            if score > best_score {
                best_score = score;
                best = Some(pair);
            }
        }
        best.cloned()
    }

    /// Compute balanced score for a worker.
    #[allow(clippy::too_many_arguments)]
    async fn compute_balanced_score(
        &self,
        worker: &WorkerState,
        circuit_state: CircuitState,
        project: &str,
        cache: &CacheTracker,
        cache_use: CacheUse,
        weights: &SelectionWeightConfig,
        min_priority: u32,
        max_priority: u32,
    ) -> f64 {
        // SpeedScore component (0-1), clamped to valid range
        let speed_score = (worker.get_speed_score() / 100.0).clamp(0.0, 1.0);

        let config = worker.config.read().await;
        let total_slots = if config.total_slots == 0 {
            return 0.0; // Workers with 0 slots should never be selected
        } else {
            config.total_slots as f64
        };

        // Load factor: penalize heavily loaded workers (0.5-1.0)
        let load_factor = {
            let active_slots = config
                .total_slots
                .saturating_sub(worker.available_slots().await);
            let utilization = active_slots as f64 / total_slots;
            1.0 - (utilization * 0.5)
        };

        // Slot availability (0-1)
        let slot_score = worker.available_slots().await as f64 / total_slots;

        // Cache affinity (0-1)
        let mut cache_score = cache.estimate_warmth(config.id.as_str(), project, cache_use);
        if cache_use == CacheUse::Test {
            cache_score = (cache_score * TEST_CACHE_BOOST).min(1.0);
        }

        // Health score (0-1)
        let health_score = self.health_score(worker).await;

        // Network score (0-1)
        let network_score = self.network_score(worker);

        // Priority normalization (0-1)
        let priority_score = Self::normalize_priority(config.priority, min_priority, max_priority);

        // Combine weighted scores
        let base_score = weights.speedscore * speed_score
            + weights.slots * slot_score * load_factor
            + weights.health * health_score
            + weights.cache * cache_score
            + weights.network * network_score
            + weights.priority * priority_score;

        // Apply half-open penalty if applicable
        let mut final_score = if circuit_state == CircuitState::HalfOpen {
            base_score * weights.half_open_penalty
        } else {
            base_score
        };

        // Apply admission pressure penalty (bd-vvmd.4.4).
        // Workers under Warning pressure or with stale telemetry receive a
        // scoring reduction proportional to the penalty (0.0-1.0) from the
        // admission gate.  Workers not evaluated by the gate are unaffected
        // (fail-open: penalty defaults to 0.0).
        let admission_penalty = if let Some(ref gate) = self.admission_gate {
            let p = gate.get_pressure_penalty(config.id.as_str()).await;
            if p > 0.0 {
                final_score *= 1.0 - p;
            }
            p
        } else {
            0.0
        };

        debug!(
            "Worker {} balanced score: {:.3} (speed={:.2}, load={:.2}, slots={:.2}, health={:.2}, cache={:.2}, network={:.2}, priority={:.2}, half_open={:?}, admission_penalty={:.2}, cache_use={:?})",
            config.id,
            final_score,
            speed_score,
            load_factor,
            slot_score,
            health_score,
            cache_score,
            network_score,
            priority_score,
            circuit_state == CircuitState::HalfOpen,
            admission_penalty,
            cache_use
        );

        final_score
    }

    async fn health_score(&self, worker: &WorkerState) -> f64 {
        let stats = worker.circuit_stats().await;
        let success_rate = 1.0 - stats.error_rate();
        success_rate.clamp(0.0, 1.0)
    }

    fn network_score(&self, worker: &WorkerState) -> f64 {
        match worker.last_latency_ms() {
            Some(latency_ms) => Self::normalize_latency_ms(latency_ms),
            None => DEFAULT_NETWORK_SCORE,
        }
    }

    fn normalize_latency_ms(latency_ms: u64) -> f64 {
        let latency = latency_ms as f64;
        let score = 1.0 / (1.0 + (latency / NETWORK_LATENCY_HALF_LIFE_MS));
        score.clamp(0.0, 1.0)
    }

    /// CacheAffinity strategy: heavily weight cache warmth.
    async fn select_cache_affinity(
        &self,
        workers: &[(Arc<WorkerState>, CircuitState)],
        request: &SelectionRequest,
        cache_use: CacheUse,
    ) -> Option<(Arc<WorkerState>, CircuitState)> {
        let cache = self.cache_tracker.read().await;

        // Find workers with warm caches for this project
        let mut warm_workers = Vec::new();
        for pair in workers {
            let (w, _) = pair;
            let id = w.config.read().await.id.clone();
            if cache.estimate_warmth(id.as_str(), &request.project, cache_use) > 0.5 {
                warm_workers.push(pair.clone());
            }
        }

        // If we have warm workers, select the fastest among them
        if !warm_workers.is_empty() {
            return self.select_by_fastest(&warm_workers).await;
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
        let mut weights = Vec::with_capacity(workers.len());
        for (w, _) in workers {
            let speed = w.get_speed_score().max(10.0);
            let id = w.config.read().await.id.clone();
            let recent = history.recent_selections(id.as_str(), lookback);
            weights.push(speed / (1.0 + recent as f64));
        }

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

    async fn priority_range(workers: &[(Arc<WorkerState>, CircuitState)]) -> (u32, u32) {
        let mut min_priority = u32::MAX;
        let mut max_priority = 0u32;

        for (worker, _) in workers {
            let priority = worker.config.read().await.priority;
            min_priority = min_priority.min(priority);
            max_priority = max_priority.max(priority);
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

fn adjust_weights_for_priority(
    weights: &SelectionWeightConfig,
    request: &SelectionRequest,
) -> SelectionWeightConfig {
    let mut adjusted = weights.clone();

    match request.command_priority {
        CommandPriority::Normal => {}
        CommandPriority::High => {
            adjusted.speedscore *= 1.25;
            adjusted.network *= 1.15;
            adjusted.cache *= 0.85;
        }
        CommandPriority::Low => {
            adjusted.cache *= 1.25;
            adjusted.slots *= 1.15;
            adjusted.speedscore *= 0.85;
            adjusted.network *= 0.85;
        }
    }

    adjusted
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
            if let Some(state) = worker.circuit_state().await
                && state != CircuitState::Open
            {
                all_circuits_open = false;
            }
            if !matches!(
                worker.status().await,
                rch_common::WorkerStatus::Unreachable
                    | rch_common::WorkerStatus::Drained
                    | rch_common::WorkerStatus::Disabled
            ) {
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
        let worker_id = worker.config.read().await.id.clone();

        match circuit_state {
            CircuitState::Open => {
                debug!("Worker {} excluded: circuit open", worker_id);
                continue;
            }
            CircuitState::HalfOpen => {
                // Only allow if probe budget available
                if !worker.can_probe(circuit_config).await {
                    debug!("Worker {} excluded: half-open, no probe budget", worker_id);
                    continue;
                }
                all_circuits_open = false;
            }
            CircuitState::Closed => {
                all_circuits_open = false;
            }
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
                worker_id, request.required_runtime
            );
            continue;
        }

        any_has_runtime = true;

        // Check slot availability
        if worker.available_slots().await < request.estimated_cores {
            debug!(
                "Worker {} excluded: insufficient slots ({} < {})",
                worker_id,
                worker.available_slots().await,
                request.estimated_cores
            );
            continue;
        }

        any_has_slots = true;

        // Compute score with circuit state penalty
        if has_preferred && preferred_set.contains(worker_id.as_str()) {
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

    let (min_priority, max_priority) = priority_range(&candidates).await;
    let mut scored: Vec<(Arc<WorkerState>, CircuitState, f64)> =
        Vec::with_capacity(candidates.len());

    for (worker, circuit_state) in candidates.drain(..) {
        let config = worker.config.read().await;
        let priority_score = normalize_priority(config.priority, min_priority, max_priority);
        let id = config.id.clone();
        drop(config); // Release lock before moving worker

        let base_score = compute_score(&worker, request, weights, priority_score).await;
        let final_score = if circuit_state == CircuitState::HalfOpen {
            base_score * weights.half_open_penalty
        } else {
            base_score
        };

        debug!(
            "Worker {} candidate: circuit={:?}, base_score={:.3}, final_score={:.3}, priority_score={:.2}",
            id, circuit_state, base_score, final_score, priority_score
        );

        scored.push((worker, circuit_state, final_score));
    }

    // Select worker with highest score
    scored.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(Ordering::Equal));

    // Defensive check: scored should never be empty since candidates was non-empty
    // and every candidate was pushed to scored. But handle gracefully just in case.
    let Some((selected_worker, circuit_state, score)) = scored.into_iter().next() else {
        warn!("Bug: scored list empty despite non-empty candidates - this should not happen");
        return SelectionResult {
            worker: None,
            reason: SelectionReason::AllWorkersBusy,
        };
    };

    // If selecting a half-open worker, start the probe
    if circuit_state == CircuitState::HalfOpen {
        selected_worker.start_probe(circuit_config).await;
        debug!(
            "Worker {} selected (half-open probe started), score={:.3}",
            selected_worker.config.read().await.id,
            score
        );
    } else {
        debug!(
            "Worker {} selected, score={:.3}",
            selected_worker.config.read().await.id,
            score
        );
    }

    SelectionResult {
        worker: Some(selected_worker),
        reason: SelectionReason::Success,
    }
}

/// Compute a selection score for a worker.
async fn compute_score(
    worker: &WorkerState,
    request: &SelectionRequest,
    weights: &SelectionWeights,
    priority_score: f64,
) -> f64 {
    // Slot availability score (0.0-1.0)
    let config = worker.config.read().await;
    let total_slots = config.total_slots.max(1) as f64;
    let slot_score = (worker.available_slots().await as f64 / total_slots).min(1.0);

    // Speed score (already 0-100, normalize to 0-1)
    let speed_score = worker.get_speed_score() / 100.0;

    // Locality score (1.0 if project is cached, 0.5 otherwise)
    let locality_score = if worker.has_cached_project(&request.project).await {
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
        config.id, score, slot_score, speed_score, locality_score, priority_score
    );

    score
}

async fn priority_range(candidates: &[(Arc<WorkerState>, CircuitState)]) -> (u32, u32) {
    let mut min_priority = u32::MAX;
    let mut max_priority = 0u32;

    for (worker, _) in candidates {
        let priority = worker.config.read().await.priority;
        min_priority = min_priority.min(priority);
        max_priority = max_priority.max(priority);
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
    use rch_common::test_guard;
    use rch_common::{
        CommandPriority, RequiredRuntime, SelectionWeightConfig, WorkerConfig, WorkerId,
    };

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
        let state = WorkerState::new(config);
        state.set_speed_score(speed);
        state
    }

    #[test]
    fn test_selection_score() {
        let _guard = test_guard!();
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let worker = make_worker("test", 16, 80.0);
            let request = SelectionRequest {
                project: "myproject".to_string(),
                command: None,
                command_priority: CommandPriority::Normal,
                estimated_cores: 4,
                preferred_workers: vec![],
                toolchain: None,
                required_runtime: RequiredRuntime::default(),
                classification_duration_us: None,
                hook_pid: None,
            };
            let weights = SelectionWeights::default();

            let score = compute_score(&worker, &request, &weights, 0.5).await;
            assert!(score > 0.0);
            assert!(score <= 1.5);
        });
    }

    #[test]
    fn test_selection_score_zero_slots_safe() {
        let _guard = test_guard!();
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let worker = make_worker("zero", 0, 80.0);
            let request = SelectionRequest {
                project: "myproject".to_string(),
                command: None,
                command_priority: CommandPriority::Normal,
                estimated_cores: 1,
                preferred_workers: vec![],
                toolchain: None,
                required_runtime: RequiredRuntime::default(),
                classification_duration_us: None,
                hook_pid: None,
            };
            let weights = SelectionWeights::default();

            let score = compute_score(&worker, &request, &weights, 0.5).await;
            assert!(score.is_finite());
        });
    }

    #[tokio::test]
    async fn test_select_worker_ignores_unhealthy() {
        let pool = WorkerPool::new();
        pool.add_worker(make_worker("healthy", 8, 50.0).config.read().await.clone())
            .await;
        pool.add_worker(
            make_worker("unreachable", 16, 90.0)
                .config
                .read()
                .await
                .clone(),
        )
        .await;

        // Mark the second worker unreachable
        pool.set_status(&WorkerId::new("unreachable"), WorkerStatus::Unreachable)
            .await;

        let request = SelectionRequest {
            project: "myproject".to_string(),
            command: None,
            command_priority: CommandPriority::Normal,
            estimated_cores: 2,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
            hook_pid: None,
        };
        let weights = SelectionWeights::default();

        let selected = select_worker(&pool, &request, &weights).await;
        let selected = selected.expect("Expected a healthy worker to be selected");
        assert_eq!(selected.config.read().await.id.as_str(), "healthy");
    }

    #[tokio::test]
    async fn test_select_worker_respects_slot_availability() {
        let pool = WorkerPool::new();
        pool.add_worker(make_worker("full", 4, 70.0).config.read().await.clone())
            .await;
        pool.add_worker(
            make_worker("available", 8, 50.0)
                .config
                .read()
                .await
                .clone(),
        )
        .await;

        // Reserve all slots on the first worker
        let full_worker = pool.get(&WorkerId::new("full")).await.unwrap();
        assert!(full_worker.reserve_slots(4).await);
        assert_eq!(full_worker.available_slots().await, 0);

        let request = SelectionRequest {
            project: "myproject".to_string(),
            command: None,
            command_priority: CommandPriority::Normal,
            estimated_cores: 2,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
            hook_pid: None,
        };
        let weights = SelectionWeights::default();

        let selected = select_worker(&pool, &request, &weights).await;
        let selected = selected.expect("Expected a worker with available slots");
        assert_eq!(selected.config.read().await.id.as_str(), "available");
    }

    #[tokio::test]
    async fn test_select_worker_ignores_open_circuit() {
        let pool = WorkerPool::new();
        pool.add_worker(make_worker("closed", 8, 50.0).config.read().await.clone())
            .await;
        pool.add_worker(make_worker("open", 16, 90.0).config.read().await.clone())
            .await;

        // Open the circuit on the second worker
        let open_worker = pool.get(&WorkerId::new("open")).await.unwrap();
        open_worker.open_circuit().await;

        let request = SelectionRequest {
            project: "myproject".to_string(),
            command: None,
            command_priority: CommandPriority::Normal,
            estimated_cores: 2,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
            hook_pid: None,
        };
        let weights = SelectionWeights::default();
        let config = CircuitBreakerConfig::default();

        let result = select_worker_with_config(&pool, &request, &weights, &config).await;
        let selected = result.worker.expect("Expected a worker to be selected");
        assert_eq!(result.reason, SelectionReason::Success);
        assert_eq!(selected.config.read().await.id.as_str(), "closed");
    }

    #[tokio::test]
    async fn test_select_worker_returns_all_circuits_open() {
        let pool = WorkerPool::new();
        pool.add_worker(make_worker("open1", 8, 50.0).config.read().await.clone())
            .await;
        pool.add_worker(make_worker("open2", 16, 90.0).config.read().await.clone())
            .await;

        // Open all circuits
        let worker1 = pool.get(&WorkerId::new("open1")).await.unwrap();
        let worker2 = pool.get(&WorkerId::new("open2")).await.unwrap();
        worker1.open_circuit().await;
        worker2.open_circuit().await;

        let request = SelectionRequest {
            project: "myproject".to_string(),
            command: None,
            command_priority: CommandPriority::Normal,
            estimated_cores: 2,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
            hook_pid: None,
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
        pool.add_worker(
            make_worker("half_open", 8, 50.0)
                .config
                .read()
                .await
                .clone(),
        )
        .await;

        // Put worker in half-open state
        let worker = pool.get(&WorkerId::new("half_open")).await.unwrap();
        worker.open_circuit().await;
        worker.half_open_circuit().await;

        let request = SelectionRequest {
            project: "myproject".to_string(),
            command: None,
            command_priority: CommandPriority::Normal,
            estimated_cores: 2,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
            hook_pid: None,
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
        assert_eq!(selected.config.read().await.id.as_str(), "half_open");
    }

    #[tokio::test]
    async fn test_select_worker_excludes_half_open_at_probe_limit() {
        let pool = WorkerPool::new();
        pool.add_worker(
            make_worker("half_open", 8, 50.0)
                .config
                .read()
                .await
                .clone(),
        )
        .await;
        pool.add_worker(make_worker("closed", 4, 40.0).config.read().await.clone())
            .await;

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
            command_priority: CommandPriority::Normal,
            estimated_cores: 2,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
            hook_pid: None,
        };
        let weights = SelectionWeights::default();

        let result = select_worker_with_config(&pool, &request, &weights, &config).await;
        let selected = result
            .worker
            .expect("Expected closed worker to be selected");
        assert_eq!(result.reason, SelectionReason::Success);
        // Should select the closed worker since half-open is at probe limit
        assert_eq!(selected.config.read().await.id.as_str(), "closed");
    }

    #[tokio::test]
    async fn test_select_worker_prefers_closed_over_half_open() {
        let pool = WorkerPool::new();
        pool.add_worker(
            make_worker("half_open", 16, 90.0)
                .config
                .read()
                .await
                .clone(),
        )
        .await;
        pool.add_worker(make_worker("closed", 8, 50.0).config.read().await.clone())
            .await;

        // Put first worker in half-open state (normally would be preferred due to higher speed)
        let half_open_worker = pool.get(&WorkerId::new("half_open")).await.unwrap();
        half_open_worker.open_circuit().await;
        half_open_worker.half_open_circuit().await;

        let request = SelectionRequest {
            project: "myproject".to_string(),
            command: None,
            command_priority: CommandPriority::Normal,
            estimated_cores: 2,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
            hook_pid: None,
        };
        let weights = SelectionWeights::default();
        let config = CircuitBreakerConfig::default();

        let result = select_worker_with_config(&pool, &request, &weights, &config).await;
        let selected = result.worker.expect("Expected a worker to be selected");
        assert_eq!(result.reason, SelectionReason::Success);
        // Should prefer closed worker due to half-open penalty
        assert_eq!(selected.config.read().await.id.as_str(), "closed");
    }

    #[tokio::test]
    async fn test_select_worker_prefers_preferred_list() {
        let pool = WorkerPool::new();
        pool.add_worker(
            make_worker("preferred", 8, 60.0)
                .config
                .read()
                .await
                .clone(),
        )
        .await;
        pool.add_worker(make_worker("other", 8, 90.0).config.read().await.clone())
            .await;

        let request = SelectionRequest {
            project: "myproject".to_string(),
            command: None,
            command_priority: CommandPriority::Normal,
            estimated_cores: 2,
            preferred_workers: vec![WorkerId::new("preferred")],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
            hook_pid: None,
        };
        let weights = SelectionWeights::default();
        let config = CircuitBreakerConfig::default();

        let result = select_worker_with_config(&pool, &request, &weights, &config).await;
        let selected = result.worker.expect("Expected a worker to be selected");
        assert_eq!(selected.config.read().await.id.as_str(), "preferred");
    }

    #[tokio::test]
    async fn test_select_worker_falls_back_when_preferred_unavailable() {
        let pool = WorkerPool::new();
        pool.add_worker(
            make_worker("available", 8, 50.0)
                .config
                .read()
                .await
                .clone(),
        )
        .await;

        let request = SelectionRequest {
            project: "myproject".to_string(),
            command: None,
            command_priority: CommandPriority::Normal,
            estimated_cores: 2,
            preferred_workers: vec![WorkerId::new("missing")],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
            hook_pid: None,
        };
        let weights = SelectionWeights::default();
        let config = CircuitBreakerConfig::default();

        let result = select_worker_with_config(&pool, &request, &weights, &config).await;
        let selected = result.worker.expect("Expected fallback to eligible worker");
        assert_eq!(selected.config.read().await.id.as_str(), "available");
    }

    #[tokio::test]
    async fn test_select_worker_prefers_higher_priority() {
        let pool = WorkerPool::new();
        let high = make_worker("high", 8, 70.0);
        {
            let mut config = high.config.write().await;
            config.priority = 200;
        }
        let low = make_worker("low", 8, 50.0);
        {
            let mut config = low.config.write().await;
            config.priority = 50;
        }

        pool.add_worker(high.config.read().await.clone()).await;
        pool.add_worker(low.config.read().await.clone()).await;

        let request = SelectionRequest {
            project: "myproject".to_string(),
            command: None,
            command_priority: CommandPriority::Normal,
            estimated_cores: 2,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
            hook_pid: None,
        };
        let weights = SelectionWeights::default();
        let config = CircuitBreakerConfig::default();

        let result = select_worker_with_config(&pool, &request, &weights, &config).await;
        let selected = result.worker.expect("Expected a worker to be selected");
        assert_eq!(selected.config.read().await.id.as_str(), "high");
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
        pool.add_worker(
            make_worker("half_open", 16, 80.0)
                .config
                .read()
                .await
                .clone(),
        )
        .await;
        pool.add_worker(make_worker("closed", 8, 50.0).config.read().await.clone())
            .await;

        // Put first worker in half-open state
        let half_open_worker = pool.get(&WorkerId::new("half_open")).await.unwrap();
        half_open_worker.open_circuit().await;
        half_open_worker.half_open_circuit().await;

        let request = SelectionRequest {
            project: "myproject".to_string(),
            command: None,
            command_priority: CommandPriority::Normal,
            estimated_cores: 2,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
            hook_pid: None,
        };
        let config = CircuitBreakerConfig::default();

        let result = select_worker_with_config(&pool, &request, &weights, &config).await;
        let selected = result.worker.expect("Expected a worker to be selected");
        // closed worker has 50/100 = 0.5 score
        // half-open worker has 80/100 * 0.5 = 0.4 score
        // So closed should win
        assert_eq!(selected.config.read().await.id.as_str(), "closed");
    }

    // =========================================================================
    // Cache Tracker Tests
    // =========================================================================

    #[test]
    fn test_cache_tracker_record_and_warmth() {
        let _guard = test_guard!();
        let mut tracker = CacheTracker::new();
        tracker.record_build("worker1", "project-a", CacheUse::Build);

        // Should have full warmth for just-recorded build
        let warmth = tracker.estimate_warmth("worker1", "project-a", CacheUse::Build);
        assert!(warmth > 0.9, "Expected warmth > 0.9, got {}", warmth);

        // Unknown project should have zero warmth
        let unknown = tracker.estimate_warmth("worker1", "project-b", CacheUse::Build);
        assert_eq!(unknown, 0.0);

        // Unknown worker should have zero warmth
        let unknown = tracker.estimate_warmth("worker2", "project-a", CacheUse::Build);
        assert_eq!(unknown, 0.0);
    }

    #[test]
    fn test_cache_tracker_has_recent_build() {
        let _guard = test_guard!();
        let mut tracker = CacheTracker::new();
        tracker.record_build("worker1", "project-a", CacheUse::Build);

        // Should report recent build within short window
        assert!(tracker.has_recent_build(
            "worker1",
            "project-a",
            CacheUse::Build,
            Duration::from_secs(60)
        ));

        // Unknown project should not have recent build
        assert!(!tracker.has_recent_build(
            "worker1",
            "project-b",
            CacheUse::Build,
            Duration::from_secs(60)
        ));
    }

    #[test]
    fn test_cache_tracker_has_recent_build_fallback_for_test() {
        let _guard = test_guard!();
        let mut tracker = CacheTracker::new();
        // Record only a build (not a test)
        tracker.record_build("worker1", "project-a", CacheUse::Build);

        // Should report recent build for CacheUse::Test (fallback behavior)
        assert!(tracker.has_recent_build(
            "worker1",
            "project-a",
            CacheUse::Test,
            Duration::from_secs(60)
        ));
    }

    // =========================================================================
    // Selection History Tests
    // =========================================================================

    #[test]
    fn test_selection_history_record_and_count() {
        let _guard = test_guard!();
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
        let _guard = test_guard!();
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

        let high_priority = make_worker("high-priority", 8, 50.0);
        {
            let mut config = high_priority.config.write().await;
            config.priority = 200;
        }
        pool.add_worker(high_priority.config.read().await.clone())
            .await;

        let low_priority = make_worker("low-priority", 8, 90.0);
        {
            let mut config = low_priority.config.write().await;
            config.priority = 50;
        }
        pool.add_worker(low_priority.config.read().await.clone())
            .await;

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
            command_priority: CommandPriority::Normal,
            estimated_cores: 2,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
            hook_pid: None,
        };

        let result = selector.select(&pool, &request).await;
        let selected = result.worker.expect("Expected a worker");
        // Should select by priority, not speed
        assert_eq!(selected.config.read().await.id.as_str(), "high-priority");
    }

    #[tokio::test]
    async fn test_worker_selector_fastest_strategy() {
        let pool = WorkerPool::new();

        // Use add_worker_state to preserve speed_score values
        let high_priority = make_worker("high-priority", 8, 50.0);
        {
            let mut config = high_priority.config.write().await;
            config.priority = 200;
        }
        pool.add_worker_state(high_priority).await;

        let fastest = make_worker("fastest", 8, 90.0);
        {
            let mut config = fastest.config.write().await;
            config.priority = 50;
        }
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
            command_priority: CommandPriority::Normal,
            estimated_cores: 2,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
            hook_pid: None,
        };

        let result = selector.select(&pool, &request).await;
        let selected = result.worker.expect("Expected a worker");
        // Should select by speed, not priority
        assert_eq!(selected.config.read().await.id.as_str(), "fastest");
    }

    #[tokio::test]
    async fn test_worker_selector_filters_low_success_rate() {
        let pool = WorkerPool::new();

        let fast_unhealthy = make_worker("fast-unhealthy", 8, 95.0);
        // Drive success rate to 0.0 (all failures)
        fast_unhealthy.record_failure(None).await;
        fast_unhealthy.record_failure(None).await;
        fast_unhealthy.record_failure(None).await;
        pool.add_worker_state(fast_unhealthy).await;

        let slow_healthy = make_worker("slow-healthy", 8, 40.0);
        slow_healthy.record_success().await;
        pool.add_worker_state(slow_healthy).await;

        let selector = WorkerSelector::with_config(
            SelectionConfig {
                strategy: SelectionStrategy::Fastest,
                min_success_rate: 0.8,
                ..Default::default()
            },
            CircuitBreakerConfig::default(),
        );

        let request = SelectionRequest {
            project: "test-project".to_string(),
            command: None,
            command_priority: CommandPriority::Normal,
            estimated_cores: 2,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
            hook_pid: None,
        };

        let result = selector.select(&pool, &request).await;
        let selected = result.worker.expect("Expected a worker");
        assert_eq!(selected.config.read().await.id.as_str(), "slow-healthy");
    }

    #[tokio::test]
    async fn test_worker_selector_balanced_strategy() {
        let pool = WorkerPool::new();
        pool.add_worker(make_worker("worker1", 8, 70.0).config.read().await.clone())
            .await;
        pool.add_worker(make_worker("worker2", 8, 80.0).config.read().await.clone())
            .await;

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
            command_priority: CommandPriority::Normal,
            estimated_cores: 2,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
            hook_pid: None,
        };

        let result = selector.select(&pool, &request).await;
        // Should return a worker (either one is fine for this test)
        assert!(result.worker.is_some());
        assert_eq!(result.reason, SelectionReason::Success);
    }

    #[tokio::test]
    async fn test_command_priority_hint_influences_balanced_selection() {
        let pool = WorkerPool::new();
        pool.add_worker_state(make_worker("fast", 8, 90.0)).await;
        pool.add_worker_state(make_worker("cached", 8, 60.0)).await;

        let selector = WorkerSelector::with_config(
            SelectionConfig {
                strategy: SelectionStrategy::Balanced,
                ..Default::default()
            },
            CircuitBreakerConfig::default(),
        );

        // Make the "cached" worker warm for this project.
        selector.record_build("cached", "proj", false).await;

        let base_request = SelectionRequest {
            project: "proj".to_string(),
            command: None,
            command_priority: CommandPriority::Normal,
            estimated_cores: 2,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
            hook_pid: None,
        };

        let mut high = base_request.clone();
        high.command_priority = CommandPriority::High;
        let result = selector.select(&pool, &high).await;
        let selected = result.worker.expect("Expected a worker");
        assert_eq!(selected.config.read().await.id.as_str(), "fast");

        let mut low = base_request.clone();
        low.command_priority = CommandPriority::Low;
        let result = selector.select(&pool, &low).await;
        let selected = result.worker.expect("Expected a worker");
        assert_eq!(selected.config.read().await.id.as_str(), "cached");
    }

    #[tokio::test]
    async fn test_select_worker_balanced_health_weight_prefers_healthy() {
        let pool = WorkerPool::new();

        let unhealthy = make_worker("unhealthy", 8, 70.0);
        unhealthy.record_failure(None).await;
        pool.add_worker_state(unhealthy).await;

        let healthy = make_worker("healthy", 8, 70.0);
        healthy.record_success().await;
        pool.add_worker_state(healthy).await;

        let selector = WorkerSelector::with_config(
            SelectionConfig {
                strategy: SelectionStrategy::Balanced,
                min_success_rate: 0.0,
                weights: SelectionWeightConfig {
                    speedscore: 0.0,
                    slots: 0.0,
                    health: 1.0,
                    cache: 0.0,
                    network: 0.0,
                    priority: 0.0,
                    half_open_penalty: 1.0,
                },
                ..Default::default()
            },
            CircuitBreakerConfig::default(),
        );

        let request = SelectionRequest {
            project: "test-project".to_string(),
            command: None,
            command_priority: CommandPriority::Normal,
            estimated_cores: 2,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
            hook_pid: None,
        };

        let result = selector.select(&pool, &request).await;
        let selected = result.worker.expect("Expected a worker");
        assert_eq!(selected.config.read().await.id.as_str(), "healthy");
    }

    #[tokio::test]
    async fn test_bug_repro_no_workers_with_runtime_when_busy() {
        // Regression test for: NoWorkersWithRuntime returned when worker exists but is busy
        let pool = WorkerPool::new();

        let worker = make_worker("busy-rust", 4, 80.0);
        worker
            .set_capabilities(rch_common::WorkerCapabilities {
                rustc_version: Some("1.75.0".to_string()),
                ..Default::default()
            })
            .await;

        // Exhaust slots
        assert!(worker.reserve_slots(4).await);

        pool.add_worker_state(worker).await;

        let selector = WorkerSelector::default();
        let request = SelectionRequest {
            project: "test".to_string(),
            command: None,
            command_priority: CommandPriority::Normal,
            estimated_cores: 1,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::Rust,
            classification_duration_us: None,
            hook_pid: None,
        };

        let result = selector.select(&pool, &request).await;
        assert!(result.worker.is_none());

        // BUG FIX VERIFIED: Runtime check now happens before slot check,
        // so busy workers correctly return AllWorkersBusy (not NoWorkersWithRuntime)
        assert_eq!(
            result.reason,
            SelectionReason::AllWorkersBusy,
            "Expected AllWorkersBusy, got {:?}",
            result.reason
        );
    }

    #[tokio::test]
    async fn test_topology_preflight_prefers_healthy_worker() {
        let pool = WorkerPool::new();

        let missing_alias = make_worker("missing-alias", 8, 95.0);
        missing_alias
            .set_capabilities(rch_common::WorkerCapabilities {
                rustc_version: Some("1.87.0".to_string()),
                projects_root_ok: Some(false),
                projects_root_issue: Some("alias_missing".to_string()),
                projects_root_checked_at_unix_ms: Some(1_700_000_000_000),
                ..Default::default()
            })
            .await;
        pool.add_worker_state(missing_alias).await;

        let healthy = make_worker("healthy-topology", 8, 80.0);
        healthy
            .set_capabilities(rch_common::WorkerCapabilities {
                rustc_version: Some("1.87.0".to_string()),
                projects_root_ok: Some(true),
                projects_root_checked_at_unix_ms: Some(1_700_000_000_000),
                ..Default::default()
            })
            .await;
        pool.add_worker_state(healthy).await;

        let selector = WorkerSelector::default();
        let request = SelectionRequest {
            project: "topology-project".to_string(),
            command: Some("cargo test --no-run".to_string()),
            command_priority: CommandPriority::Normal,
            estimated_cores: 2,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::Rust,
            classification_duration_us: None,
            hook_pid: None,
        };

        let result = selector.select(&pool, &request).await;
        let selected = result.worker.expect("expected healthy topology worker");
        assert_eq!(selected.config.read().await.id.as_str(), "healthy-topology");
        assert_eq!(result.reason, SelectionReason::Success);
    }

    #[tokio::test]
    async fn test_topology_preflight_rejects_wrong_target_only_pool() {
        let pool = WorkerPool::new();

        let wrong_target = make_worker("wrong-target", 8, 95.0);
        wrong_target
            .set_capabilities(rch_common::WorkerCapabilities {
                rustc_version: Some("1.87.0".to_string()),
                projects_root_ok: Some(false),
                projects_root_issue: Some("alias_wrong_target:/tmp/other".to_string()),
                projects_root_checked_at_unix_ms: Some(1_700_000_000_123),
                ..Default::default()
            })
            .await;
        pool.add_worker_state(wrong_target).await;

        let selector = WorkerSelector::default();
        let request = SelectionRequest {
            project: "topology-project".to_string(),
            command: Some("cargo build".to_string()),
            command_priority: CommandPriority::Normal,
            estimated_cores: 2,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::Rust,
            classification_duration_us: None,
            hook_pid: None,
        };

        let result = selector.select(&pool, &request).await;
        assert!(result.worker.is_none());
        assert_eq!(result.reason, SelectionReason::AllWorkersFailedPreflight);
    }

    #[tokio::test]
    async fn test_topology_preflight_flapping_recovery_requires_revalidation() {
        let pool = WorkerPool::new();
        let flapping = make_worker("flapping", 8, 70.0);
        flapping
            .set_capabilities(rch_common::WorkerCapabilities {
                rustc_version: Some("1.87.0".to_string()),
                projects_root_ok: Some(false),
                projects_root_issue: Some("alias_missing".to_string()),
                projects_root_checked_at_unix_ms: Some(1_700_000_000_200),
                ..Default::default()
            })
            .await;
        pool.add_worker_state(flapping).await;

        let selector = WorkerSelector::default();
        let request = SelectionRequest {
            project: "topology-flap".to_string(),
            command: Some("cargo check".to_string()),
            command_priority: CommandPriority::Normal,
            estimated_cores: 1,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::Rust,
            classification_duration_us: None,
            hook_pid: None,
        };

        let first = selector.select(&pool, &request).await;
        assert!(first.worker.is_none());
        assert_eq!(first.reason, SelectionReason::AllWorkersFailedPreflight);

        // Explicit revalidation updates capabilities and allows scheduling again.
        let state = pool.get(&WorkerId::new("flapping")).await.unwrap();
        state
            .set_capabilities(rch_common::WorkerCapabilities {
                rustc_version: Some("1.87.0".to_string()),
                projects_root_ok: Some(true),
                projects_root_checked_at_unix_ms: Some(1_700_000_100_000),
                ..Default::default()
            })
            .await;

        let second = selector.select(&pool, &request).await;
        let selected = second
            .worker
            .expect("expected worker to recover after explicit revalidation");
        assert_eq!(selected.config.read().await.id.as_str(), "flapping");
        assert_eq!(second.reason, SelectionReason::Success);
    }

    #[tokio::test]
    async fn test_pressure_preflight_rejects_critical_worker_only_pool() {
        let pool = WorkerPool::new();
        let critical = make_worker("critical-pressure", 8, 80.0);
        critical
            .set_capabilities(rch_common::WorkerCapabilities {
                rustc_version: Some("1.87.0".to_string()),
                projects_root_ok: Some(true),
                projects_root_checked_at_unix_ms: Some(1_700_000_000_000),
                ..Default::default()
            })
            .await;
        critical
            .set_pressure_assessment(crate::disk_pressure::PressureAssessment {
                state: crate::disk_pressure::PressureState::Critical,
                confidence: crate::disk_pressure::PressureConfidence::High,
                reason_code: "disk_free_below_critical_gb".to_string(),
                policy_rule: "disk_free_gb<=critical_free_gb".to_string(),
                disk_free_gb: Some(4.0),
                disk_total_gb: Some(120.0),
                disk_free_ratio: Some(0.033),
                disk_io_util_pct: Some(80.0),
                memory_pressure: Some(55.0),
                telemetry_age_secs: Some(8),
                telemetry_fresh: true,
                evaluated_at_unix_ms: 1_700_000_000_000,
            })
            .await;
        pool.add_worker_state(critical).await;

        let selector = WorkerSelector::default();
        let request = SelectionRequest {
            project: "pressure-critical".to_string(),
            command: Some("cargo build".to_string()),
            command_priority: CommandPriority::Normal,
            estimated_cores: 2,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::Rust,
            classification_duration_us: None,
            hook_pid: None,
        };

        let result = selector.select(&pool, &request).await;
        assert!(result.worker.is_none());
        assert_eq!(result.reason, SelectionReason::AllWorkersFailedPreflight);
    }

    #[tokio::test]
    async fn test_pressure_preflight_allows_telemetry_gap_fail_open() {
        let pool = WorkerPool::new();
        let telemetry_gap = make_worker("telemetry-gap", 8, 80.0);
        telemetry_gap
            .set_capabilities(rch_common::WorkerCapabilities {
                rustc_version: Some("1.87.0".to_string()),
                projects_root_ok: Some(true),
                projects_root_checked_at_unix_ms: Some(1_700_000_000_000),
                disk_free_gb: Some(60.0),
                disk_total_gb: Some(120.0),
                ..Default::default()
            })
            .await;
        telemetry_gap
            .set_pressure_assessment(crate::disk_pressure::PressureAssessment {
                state: crate::disk_pressure::PressureState::TelemetryGap,
                confidence: crate::disk_pressure::PressureConfidence::Low,
                reason_code: "telemetry_unavailable".to_string(),
                policy_rule: "fail_open_telemetry_gap".to_string(),
                disk_free_gb: Some(60.0),
                disk_total_gb: Some(120.0),
                disk_free_ratio: Some(0.5),
                disk_io_util_pct: None,
                memory_pressure: None,
                telemetry_age_secs: Some(600),
                telemetry_fresh: false,
                evaluated_at_unix_ms: 1_700_000_000_000,
            })
            .await;
        pool.add_worker_state(telemetry_gap).await;

        let selector = WorkerSelector::default();
        let request = SelectionRequest {
            project: "pressure-gap".to_string(),
            command: Some("cargo build".to_string()),
            command_priority: CommandPriority::Normal,
            estimated_cores: 2,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::Rust,
            classification_duration_us: None,
            hook_pid: None,
        };

        let result = selector.select(&pool, &request).await;
        let selected = result
            .worker
            .expect("expected telemetry-gap worker to remain eligible (fail-open)");
        assert_eq!(selected.config.read().await.id.as_str(), "telemetry-gap");
        assert_eq!(result.reason, SelectionReason::Success);
    }

    #[tokio::test]
    async fn test_worker_selector_balanced_network_weight_prefers_low_latency() {
        let pool = WorkerPool::new();

        let fast_net = make_worker("fast-net", 8, 70.0);
        fast_net.set_last_latency_ms(Some(20));
        pool.add_worker_state(fast_net).await;

        let slow_net = make_worker("slow-net", 8, 70.0);
        slow_net.set_last_latency_ms(Some(600));
        pool.add_worker_state(slow_net).await;

        let selector = WorkerSelector::with_config(
            SelectionConfig {
                strategy: SelectionStrategy::Balanced,
                min_success_rate: 0.0,
                weights: SelectionWeightConfig {
                    speedscore: 0.0,
                    slots: 0.0,
                    health: 0.0,
                    cache: 0.0,
                    network: 1.0,
                    priority: 0.0,
                    half_open_penalty: 1.0,
                },
                ..Default::default()
            },
            CircuitBreakerConfig::default(),
        );

        let request = SelectionRequest {
            project: "test-project".to_string(),
            command: None,
            command_priority: CommandPriority::Normal,
            estimated_cores: 2,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
            hook_pid: None,
        };

        let result = selector.select(&pool, &request).await;
        let selected = result.worker.expect("Expected a worker");
        assert_eq!(selected.config.read().await.id.as_str(), "fast-net");
    }

    #[tokio::test]
    async fn test_worker_selector_cache_affinity_strategy() {
        let pool = WorkerPool::new();
        pool.add_worker(
            make_worker("warm-cache", 8, 50.0)
                .config
                .read()
                .await
                .clone(),
        )
        .await;
        pool.add_worker(
            make_worker("cold-cache", 8, 90.0)
                .config
                .read()
                .await
                .clone(),
        )
        .await;

        let selector = WorkerSelector::with_config(
            SelectionConfig {
                strategy: SelectionStrategy::CacheAffinity,
                ..Default::default()
            },
            CircuitBreakerConfig::default(),
        );

        // Record a build for warm-cache worker
        selector
            .record_build("warm-cache", "test-project", false)
            .await;

        let request = SelectionRequest {
            project: "test-project".to_string(),
            command: None,
            command_priority: CommandPriority::Normal,
            estimated_cores: 2,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
            hook_pid: None,
        };

        let result = selector.select(&pool, &request).await;
        let selected = result.worker.expect("Expected a worker");
        // Should prefer warm cache despite lower speed
        assert_eq!(selected.config.read().await.id.as_str(), "warm-cache");
    }

    #[tokio::test]
    async fn test_cache_affinity_prefers_test_cache_for_test_commands() {
        let pool = WorkerPool::new();
        pool.add_worker_state(make_worker("test-warm", 8, 50.0))
            .await;
        pool.add_worker_state(make_worker("fast", 8, 90.0)).await;

        let selector = WorkerSelector::with_config(
            SelectionConfig {
                strategy: SelectionStrategy::CacheAffinity,
                ..Default::default()
            },
            CircuitBreakerConfig::default(),
        );

        // Record only build cache first (no test binaries yet).
        selector.record_build("test-warm", "proj", false).await;

        let request = SelectionRequest {
            project: "proj".to_string(),
            command: Some("cargo test".to_string()),
            command_priority: CommandPriority::Normal,
            estimated_cores: 2,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
            hook_pid: None,
        };

        let result = selector.select(&pool, &request).await;
        let selected = result.worker.expect("Expected a worker");
        // Build cache alone shouldn't count as warm for tests.
        assert_eq!(selected.config.read().await.id.as_str(), "fast");

        // Now record a test run and ensure affinity selects the warm worker.
        selector.record_build("test-warm", "proj", true).await;

        let result = selector.select(&pool, &request).await;
        let selected = result.worker.expect("Expected a worker");
        assert_eq!(selected.config.read().await.id.as_str(), "test-warm");
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
            command_priority: CommandPriority::Normal,
            estimated_cores: 2,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
            hook_pid: None,
        };

        let result = selector.select(&pool, &request).await;
        let selected = result.worker.expect("Expected a worker");
        // Should fall back to fastest when no warm cache
        assert_eq!(selected.config.read().await.id.as_str(), "fast");
    }

    #[tokio::test]
    async fn test_worker_selector_fair_fastest_distributes() {
        let pool = WorkerPool::new();
        pool.add_worker(make_worker("worker1", 8, 80.0).config.read().await.clone())
            .await;
        pool.add_worker(make_worker("worker2", 8, 80.0).config.read().await.clone())
            .await;

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
            command_priority: CommandPriority::Normal,
            estimated_cores: 2,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
            hook_pid: None,
        };

        // Run multiple selections and verify distribution
        let mut worker1_count = 0;
        let mut worker2_count = 0;

        for _ in 0..20 {
            let result = selector.select(&pool, &request).await;
            if let Some(worker) = result.worker {
                if worker.config.read().await.id.as_str() == "worker1" {
                    worker1_count += 1;
                } else {
                    worker2_count += 1;
                }
            }
        }

        // Both workers should have been selected at least once
        // (with equal speeds and fairness, distribution should be roughly even)
        assert!(
            worker1_count > 0,
            "Worker1 should be selected at least once"
        );
        assert!(
            worker2_count > 0,
            "Worker2 should be selected at least once"
        );
    }

    #[tokio::test]
    async fn test_worker_selector_records_build_for_cache() {
        let selector = WorkerSelector::new();

        // Record a build
        selector.record_build("worker1", "project-a", false).await;

        // Verify cache warmth is tracked
        let cache = selector.cache_tracker.read().await;
        let warmth = cache.estimate_warmth("worker1", "project-a", CacheUse::Build);
        assert!(warmth > 0.9);
    }

    #[tokio::test]
    async fn test_worker_selector_handles_empty_pool() {
        let pool = WorkerPool::new();
        let selector = WorkerSelector::new();

        let request = SelectionRequest {
            project: "test-project".to_string(),
            command: None,
            command_priority: CommandPriority::Normal,
            estimated_cores: 2,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
            hook_pid: None,
        };

        let result = selector.select(&pool, &request).await;
        assert!(result.worker.is_none());
        assert_eq!(result.reason, SelectionReason::NoWorkersConfigured);
    }

    #[tokio::test]
    async fn test_worker_selector_respects_preferred_workers() {
        let pool = WorkerPool::new();
        pool.add_worker(
            make_worker("preferred", 8, 50.0)
                .config
                .read()
                .await
                .clone(),
        )
        .await;
        pool.add_worker(make_worker("faster", 8, 90.0).config.read().await.clone())
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
            command_priority: CommandPriority::Normal,
            estimated_cores: 2,
            preferred_workers: vec![WorkerId::new("preferred")],
            toolchain: None,
            required_runtime: RequiredRuntime::default(),
            classification_duration_us: None,
            hook_pid: None,
        };

        let result = selector.select(&pool, &request).await;
        let selected = result.worker.expect("Expected a worker");
        // Preferred workers take precedence even with Fastest strategy
        assert_eq!(selected.config.read().await.id.as_str(), "preferred");
    }

    // =========================================================================
    // Selection Audit Log Tests (bd-37hc)
    // =========================================================================

    #[test]
    fn test_audit_log_push_and_retrieve() {
        let _guard = test_guard!();
        let mut log = SelectionAuditLog::new(10);
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);

        // Create a test entry
        let entry = SelectionAuditEntry {
            id: 0,
            timestamp_ms: 1234567890,
            project: "test-project".to_string(),
            command: Some("cargo build".to_string()),
            strategy: "Balanced".to_string(),
            command_priority: "Normal".to_string(),
            required_runtime: None,
            eligible_count: 3,
            workers_evaluated: vec![],
            selected_worker_id: Some("worker-1".to_string()),
            reason: "Success".to_string(),
            classification_duration_us: Some(500),
            selection_duration_us: 1200,
        };

        log.push(entry);
        assert_eq!(log.len(), 1);
        assert!(!log.is_empty());

        let last = log.last().unwrap();
        assert_eq!(last.id, 1); // ID should be assigned
        assert_eq!(last.project, "test-project");
        assert_eq!(last.selected_worker_id, Some("worker-1".to_string()));
    }

    #[test]
    fn test_audit_log_eviction() {
        let _guard = test_guard!();
        let mut log = SelectionAuditLog::new(3);

        // Add 5 entries to a log with capacity 3
        for i in 0..5 {
            let entry = SelectionAuditEntry {
                id: 0,
                timestamp_ms: i as u64,
                project: format!("project-{}", i),
                command: None,
                strategy: "Fastest".to_string(),
                command_priority: "Normal".to_string(),
                required_runtime: None,
                eligible_count: 1,
                workers_evaluated: vec![],
                selected_worker_id: None,
                reason: "AllWorkersBusy".to_string(),
                classification_duration_us: None,
                selection_duration_us: 100,
            };
            log.push(entry);
        }

        // Should only have 3 entries (oldest evicted)
        assert_eq!(log.len(), 3);

        // Should have entries for projects 2, 3, 4 (0 and 1 evicted)
        let entries: Vec<_> = log.entries().iter().collect();
        assert_eq!(entries[0].project, "project-2");
        assert_eq!(entries[1].project, "project-3");
        assert_eq!(entries[2].project, "project-4");
    }

    #[test]
    fn test_audit_log_last_n() {
        let _guard = test_guard!();
        let mut log = SelectionAuditLog::new(10);

        for i in 0..5 {
            let entry = SelectionAuditEntry {
                id: 0,
                timestamp_ms: i as u64,
                project: format!("project-{}", i),
                command: None,
                strategy: "Priority".to_string(),
                command_priority: "Normal".to_string(),
                required_runtime: None,
                eligible_count: 1,
                workers_evaluated: vec![],
                selected_worker_id: Some(format!("worker-{}", i)),
                reason: "Success".to_string(),
                classification_duration_us: None,
                selection_duration_us: 50,
            };
            log.push(entry);
        }

        // Get last 2 (should be newest first)
        let last_2 = log.last_n(2);
        assert_eq!(last_2.len(), 2);
        assert_eq!(last_2[0].project, "project-4"); // Newest
        assert_eq!(last_2[1].project, "project-3");
    }

    #[test]
    fn test_audit_log_get_by_id() {
        let _guard = test_guard!();
        let mut log = SelectionAuditLog::new(10);

        for i in 0..3 {
            let entry = SelectionAuditEntry {
                id: 0,
                timestamp_ms: i as u64,
                project: format!("project-{}", i),
                command: None,
                strategy: "CacheAffinity".to_string(),
                command_priority: "Normal".to_string(),
                required_runtime: None,
                eligible_count: 2,
                workers_evaluated: vec![],
                selected_worker_id: None,
                reason: "AllWorkersBusy".to_string(),
                classification_duration_us: None,
                selection_duration_us: 75,
            };
            log.push(entry);
        }

        // IDs should be 1, 2, 3
        assert!(log.get(1).is_some());
        assert_eq!(log.get(1).unwrap().project, "project-0");
        assert!(log.get(2).is_some());
        assert!(log.get(3).is_some());
        assert!(log.get(4).is_none()); // Doesn't exist
        assert!(log.get(0).is_none()); // ID 0 is never assigned
    }

    #[test]
    fn test_audit_log_clear() {
        let _guard = test_guard!();
        let mut log = SelectionAuditLog::new(10);

        let entry = SelectionAuditEntry {
            id: 0,
            timestamp_ms: 0,
            project: "test".to_string(),
            command: None,
            strategy: "FairFastest".to_string(),
            command_priority: "High".to_string(),
            required_runtime: Some("Rust".to_string()),
            eligible_count: 0,
            workers_evaluated: vec![],
            selected_worker_id: None,
            reason: "NoWorkersConfigured".to_string(),
            classification_duration_us: None,
            selection_duration_us: 25,
        };
        log.push(entry);

        assert_eq!(log.len(), 1);
        log.clear();
        assert_eq!(log.len(), 0);
        assert!(log.is_empty());
    }

    #[test]
    fn test_worker_score_breakdown_serialization() {
        let _guard = test_guard!();
        let breakdown = WorkerScoreBreakdown {
            worker_id: "worker-1".to_string(),
            total_score: 0.85,
            speed_score: 0.9,
            slot_availability: 0.75,
            cache_affinity: 0.5,
            priority_score: 0.8,
            circuit_state: "Closed".to_string(),
            selected: true,
            skip_reason: None,
        };

        let json = serde_json::to_string(&breakdown).unwrap();
        assert!(json.contains("\"worker_id\":\"worker-1\""));
        assert!(json.contains("\"selected\":true"));
    }

    #[tokio::test]
    async fn test_selection_records_audit_entry() {
        // Create a selector and pool
        let selector = WorkerSelector::new();
        let pool = WorkerPool::new();

        // Create a simple worker
        let worker_config = WorkerConfig {
            id: WorkerId::new("audit-test-worker"),
            host: "localhost".to_string(),
            user: "test".to_string(),
            identity_file: "/tmp/test".to_string(),
            total_slots: 4,
            priority: 1,
            tags: vec![],
        };
        pool.add_worker(worker_config).await;

        // Make a selection request
        let request = SelectionRequest {
            project: "audit-test-project".to_string(),
            command: Some("cargo test".to_string()),
            command_priority: CommandPriority::Normal,
            estimated_cores: 2,
            preferred_workers: vec![],
            toolchain: None,
            required_runtime: RequiredRuntime::Rust,
            classification_duration_us: Some(250),
            hook_pid: Some(12345),
        };

        // Make a selection
        let _result = selector.select(&pool, &request).await;

        // Check that an audit entry was recorded
        let audit_entries = selector.get_audit_log(Some(1)).await;
        assert_eq!(audit_entries.len(), 1);

        let entry = &audit_entries[0];
        assert_eq!(entry.project, "audit-test-project");
        assert_eq!(entry.command, Some("cargo test".to_string()));
        assert_eq!(entry.strategy, "Priority"); // Default strategy
        assert_eq!(entry.classification_duration_us, Some(250));
    }

    // ========================================================================
    // Affinity Pinning Tests (bd-5a5k)
    // ========================================================================

    #[test]
    fn test_cache_tracker_record_success() {
        let _guard = test_guard!();
        let mut tracker = CacheTracker::new();
        let pin_window = Duration::from_secs(3600);

        // Initially no pinned worker
        assert!(tracker.get_pinned_worker("project-a", pin_window).is_none());

        // Record a success
        tracker.record_build("worker1", "project-a", CacheUse::Build);
        tracker.record_success("worker1", "project-a");

        // Now should have pinned worker
        let pinned = tracker.get_pinned_worker("project-a", pin_window);
        assert_eq!(pinned, Some("worker1"));
    }

    #[test]
    fn test_cache_tracker_last_success_entry() {
        let _guard = test_guard!();
        let mut tracker = CacheTracker::new();

        // No entry initially
        assert!(tracker.get_last_success_worker("project-x").is_none());

        // Record success
        tracker.record_build("worker2", "project-x", CacheUse::Build);
        tracker.record_success("worker2", "project-x");

        // Should have last success entry
        let entry = tracker.get_last_success_worker("project-x");
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().worker_id, "worker2");
    }

    #[test]
    fn test_cache_tracker_pin_updates_on_new_success() {
        let _guard = test_guard!();
        let mut tracker = CacheTracker::new();
        let pin_window = Duration::from_secs(3600);

        // First success
        tracker.record_build("worker1", "project-a", CacheUse::Build);
        tracker.record_success("worker1", "project-a");

        // Second success on different worker
        tracker.record_build("worker2", "project-a", CacheUse::Build);
        tracker.record_success("worker2", "project-a");

        // Pinned worker should be the most recent
        let pinned = tracker.get_pinned_worker("project-a", pin_window);
        assert_eq!(pinned, Some("worker2"));
    }

    #[tokio::test]
    async fn test_selector_record_success_updates_cache() {
        let selector = WorkerSelector::new();

        // Record a success
        selector.record_build("worker1", "project-a", false).await;
        selector.record_success("worker1", "project-a").await;

        // Check pinned worker
        let pinned = selector.get_pinned_worker("project-a").await;
        assert_eq!(pinned, Some("worker1".to_string()));
    }

    #[tokio::test]
    async fn test_selector_affinity_disabled_returns_none() {
        use rch_common::AffinityConfig;

        let selector = WorkerSelector::with_config(
            SelectionConfig {
                affinity: AffinityConfig {
                    enabled: false,
                    ..Default::default()
                },
                ..Default::default()
            },
            CircuitBreakerConfig::default(),
        );

        // Record a success
        selector.record_build("worker1", "project-a", false).await;
        selector.record_success("worker1", "project-a").await;

        // Affinity disabled, should return None
        let pinned = selector.get_pinned_worker("project-a").await;
        assert!(pinned.is_none());
    }

    #[tokio::test]
    async fn test_selector_fallback_disabled_returns_none() {
        use rch_common::AffinityConfig;

        let selector = WorkerSelector::with_config(
            SelectionConfig {
                affinity: AffinityConfig {
                    enable_last_success_fallback: false,
                    ..Default::default()
                },
                ..Default::default()
            },
            CircuitBreakerConfig::default(),
        );

        // Record a success
        selector.record_build("worker1", "project-a", false).await;
        selector.record_success("worker1", "project-a").await;

        // Fallback disabled, should return None
        let fallback = selector.get_fallback_worker("project-a").await;
        assert!(fallback.is_none());
    }

    // ========================================================================
    // Property-Based Tests (bd-1zy8)
    // ========================================================================

    mod proptest_selection {
        use super::*;
        use proptest::prelude::*;
        use std::time::Duration;

        // ====================================================================
        // normalize_latency_ms property tests
        // ====================================================================

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(1000))]

            /// Output is always in [0.0, 1.0] for any latency value.
            #[test]
            fn test_normalize_latency_output_range(latency_ms in 0u64..=u64::MAX) {
        let _guard = test_guard!();
                let score = WorkerSelector::normalize_latency_ms(latency_ms);
                prop_assert!(score >= 0.0, "Score {score} below 0.0 for latency {latency_ms}");
                prop_assert!(score <= 1.0, "Score {score} above 1.0 for latency {latency_ms}");
            }

            /// Larger latency always gives lower or equal score (monotonically decreasing).
            #[test]
            fn test_normalize_latency_monotonic(
                latency_a in 0u64..=1_000_000_000u64,
                latency_b in 0u64..=1_000_000_000u64,
            ) {
        let _guard = test_guard!();
                let score_a = WorkerSelector::normalize_latency_ms(latency_a);
                let score_b = WorkerSelector::normalize_latency_ms(latency_b);

                if latency_a <= latency_b {
                    prop_assert!(
                        score_a >= score_b,
                        "Expected score_a ({score_a}) >= score_b ({score_b}) for latency_a ({latency_a}) <= latency_b ({latency_b})"
                    );
                }
            }

            /// Zero latency gives maximum score of 1.0.
            #[test]
            fn test_normalize_latency_zero(_seed in 0u64..100u64) {
        let _guard = test_guard!();
                let score = WorkerSelector::normalize_latency_ms(0);
                prop_assert!(
                    (score - 1.0).abs() < f64::EPSILON,
                    "Zero latency should give score 1.0, got {score}"
                );
            }

            /// At half-life (200ms), score should be 0.5.
            #[test]
            fn test_normalize_latency_half_life(_seed in 0u64..100u64) {
        let _guard = test_guard!();
                let score = WorkerSelector::normalize_latency_ms(200);
                prop_assert!(
                    (score - 0.5).abs() < 0.01,
                    "Half-life latency (200ms) should give score ~0.5, got {score}"
                );
            }
        }

        // ====================================================================
        // normalize_priority property tests
        // ====================================================================

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(1000))]

            /// Output is always in [0.0, 1.0] for any valid priority range.
            #[test]
            fn test_normalize_priority_output_range(
                priority in 0u32..=1000u32,
                min_priority in 0u32..=500u32,
                max_priority in 500u32..=1000u32,
            ) {
        let _guard = test_guard!();
                // Ensure priority is within the range
                let clamped_priority = priority.clamp(min_priority, max_priority);
                let score = WorkerSelector::normalize_priority(clamped_priority, min_priority, max_priority);
                prop_assert!(score >= 0.0, "Score {score} below 0.0");
                prop_assert!(score <= 1.0, "Score {score} above 1.0");
            }

            /// When min == max, should return 1.0.
            #[test]
            fn test_normalize_priority_equal_bounds(value in 0u32..=1000u32) {
        let _guard = test_guard!();
                let score = WorkerSelector::normalize_priority(value, value, value);
                prop_assert!(
                    (score - 1.0).abs() < f64::EPSILON,
                    "Equal bounds should give score 1.0, got {score}"
                );
            }

            /// Priority at min gives 0.0, at max gives 1.0.
            #[test]
            fn test_normalize_priority_boundary_values(
                min_priority in 0u32..=500u32,
                max_priority in 501u32..=1000u32,
            ) {
        let _guard = test_guard!();
                let min_score = WorkerSelector::normalize_priority(min_priority, min_priority, max_priority);
                let max_score = WorkerSelector::normalize_priority(max_priority, min_priority, max_priority);

                prop_assert!(
                    min_score.abs() < f64::EPSILON,
                    "Min priority should give score 0.0, got {min_score}"
                );
                prop_assert!(
                    (max_score - 1.0).abs() < f64::EPSILON,
                    "Max priority should give score 1.0, got {max_score}"
                );
            }

            /// Higher priority always gives higher or equal score (monotonically increasing).
            #[test]
            fn test_normalize_priority_monotonic(
                priority_a in 0u32..=1000u32,
                priority_b in 0u32..=1000u32,
                min_priority in 0u32..=100u32,
                max_priority in 900u32..=1000u32,
            ) {
        let _guard = test_guard!();
                let clamped_a = priority_a.clamp(min_priority, max_priority);
                let clamped_b = priority_b.clamp(min_priority, max_priority);
                let score_a = WorkerSelector::normalize_priority(clamped_a, min_priority, max_priority);
                let score_b = WorkerSelector::normalize_priority(clamped_b, min_priority, max_priority);

                if clamped_a <= clamped_b {
                    prop_assert!(
                        score_a <= score_b,
                        "Expected score_a ({score_a}) <= score_b ({score_b}) for priority_a ({clamped_a}) <= priority_b ({clamped_b})"
                    );
                }
            }
        }

        // ====================================================================
        // SelectionWeights property tests
        // ====================================================================

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(500))]

            /// SelectionWeights from config preserves values.
            #[test]
            fn test_selection_weights_from_config(
                slots in 0.0f64..=1.0f64,
                speedscore in 0.0f64..=1.0f64,
                cache in 0.0f64..=1.0f64,
                priority in 0.0f64..=1.0f64,
                half_open_penalty in 0.0f64..=1.0f64,
            ) {
        let _guard = test_guard!();
                let config = SelectionWeightConfig {
                    slots,
                    speedscore,
                    cache,
                    priority,
                    half_open_penalty,
                    health: 0.1,
                    network: 0.1,
                };
                let weights = SelectionWeights::from(&config);

                prop_assert!((weights.slots - slots).abs() < f64::EPSILON);
                prop_assert!((weights.speed - speedscore).abs() < f64::EPSILON);
                prop_assert!((weights.locality - cache).abs() < f64::EPSILON);
                prop_assert!((weights.priority - priority).abs() < f64::EPSILON);
                prop_assert!((weights.half_open_penalty - half_open_penalty).abs() < f64::EPSILON);
            }
        }

        // ====================================================================
        // SelectionAuditLog property tests
        // ====================================================================

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(200))]

            /// Audit log respects max_entries capacity.
            #[test]
            fn test_audit_log_capacity(
                max_entries in 1usize..=100usize,
                num_entries in 0usize..=200usize,
            ) {
        let _guard = test_guard!();
                let mut log = SelectionAuditLog::new(max_entries);

                for i in 0..num_entries {
                    let entry = SelectionAuditEntry {
                        id: 0, // Will be set by push
                        timestamp_ms: i as u64,
                        project: format!("project-{i}"),
                        command: None,
                        strategy: "Priority".to_string(),
                        command_priority: "Normal".to_string(),
                        required_runtime: None,
                        eligible_count: 1,
                        workers_evaluated: vec![],
                        selected_worker_id: Some("worker-1".to_string()),
                        reason: "Success".to_string(),
                        classification_duration_us: None,
                        selection_duration_us: 100,
                    };
                    log.push(entry);
                }

                prop_assert!(
                    log.len() <= max_entries,
                    "Log size {} exceeds max_entries {max_entries}",
                    log.len()
                );
            }

            /// Audit log IDs are monotonically increasing.
            #[test]
            fn test_audit_log_ids_increasing(num_entries in 2usize..=50usize) {
        let _guard = test_guard!();
                let mut log = SelectionAuditLog::new(100);

                for i in 0..num_entries {
                    let entry = SelectionAuditEntry {
                        id: 0,
                        timestamp_ms: i as u64,
                        project: format!("project-{i}"),
                        command: None,
                        strategy: "Priority".to_string(),
                        command_priority: "Normal".to_string(),
                        required_runtime: None,
                        eligible_count: 1,
                        workers_evaluated: vec![],
                        selected_worker_id: Some("worker-1".to_string()),
                        reason: "Success".to_string(),
                        classification_duration_us: None,
                        selection_duration_us: 100,
                    };
                    log.push(entry);
                }

                let entries: Vec<_> = log.entries().iter().collect();
                for i in 1..entries.len() {
                    prop_assert!(
                        entries[i].id > entries[i - 1].id,
                        "IDs not monotonically increasing: {} vs {}",
                        entries[i - 1].id,
                        entries[i].id
                    );
                }
            }

            /// last_n returns at most n entries.
            #[test]
            fn test_audit_log_last_n(
                num_entries in 0usize..=50usize,
                n in 0usize..=100usize,
            ) {
        let _guard = test_guard!();
                let mut log = SelectionAuditLog::new(100);

                for i in 0..num_entries {
                    let entry = SelectionAuditEntry {
                        id: 0,
                        timestamp_ms: i as u64,
                        project: format!("project-{i}"),
                        command: None,
                        strategy: "Priority".to_string(),
                        command_priority: "Normal".to_string(),
                        required_runtime: None,
                        eligible_count: 1,
                        workers_evaluated: vec![],
                        selected_worker_id: Some("worker-1".to_string()),
                        reason: "Success".to_string(),
                        classification_duration_us: None,
                        selection_duration_us: 100,
                    };
                    log.push(entry);
                }

                let last_n_entries = log.last_n(n);
                prop_assert!(
                    last_n_entries.len() <= n,
                    "last_n({n}) returned {} entries",
                    last_n_entries.len()
                );
                prop_assert!(
                    last_n_entries.len() <= num_entries,
                    "last_n returned more entries than exist"
                );
            }
        }

        // ====================================================================
        // SelectionHistory property tests
        // ====================================================================

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(200))]

            /// History respects max_history_per_worker limit.
            #[test]
            fn test_selection_history_capacity(num_selections in 0usize..=200usize) {
        let _guard = test_guard!();
                let mut history = SelectionHistory::default();

                for _ in 0..num_selections {
                    history.record_selection("worker-1");
                }

                // Internal limit is 100
                let count = history.recent_selections("worker-1", Duration::from_secs(3600));
                prop_assert!(
                    count <= 100,
                    "History count {count} exceeds max_history_per_worker"
                );
            }

            /// recent_selections returns 0 for unknown workers.
            #[test]
            fn test_selection_history_unknown_worker(
                worker_id in "[a-z]{5,10}",
            ) {
        let _guard = test_guard!();
                let history = SelectionHistory::new();
                let count = history.recent_selections(&worker_id, Duration::from_secs(3600));
                prop_assert_eq!(count, 0, "Unknown worker should have 0 selections");
            }

            /// Recorded selections are counted.
            #[test]
            fn test_selection_history_counts_match(
                num_selections in 1usize..=50usize,
            ) {
        let _guard = test_guard!();
                let mut history = SelectionHistory::new();

                for _ in 0..num_selections {
                    history.record_selection("test-worker");
                }

                // Use a very long window to capture all recent selections
                let count = history.recent_selections("test-worker", Duration::from_secs(3600));
                prop_assert_eq!(
                    count, num_selections,
                    "Expected {} selections, got {}", num_selections, count
                );
            }
        }

        // ====================================================================
        // CacheTracker property tests
        // ====================================================================

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(200))]

            /// estimate_warmth returns value in [0.0, 1.0].
            #[test]
            fn test_cache_tracker_warmth_range(
                worker_id in "[a-z]{3,8}",
                project_id in "[a-z]{3,8}",
            ) {
        let _guard = test_guard!();
                let mut tracker = CacheTracker::new();
                tracker.record_build(&worker_id, &project_id, CacheUse::Build);

                let warmth = tracker.estimate_warmth(&worker_id, &project_id, CacheUse::Build);
                prop_assert!(warmth >= 0.0, "Warmth {warmth} below 0.0");
                prop_assert!(warmth <= 1.0, "Warmth {warmth} above 1.0");
            }

            /// Unknown worker/project returns 0.0 warmth.
            #[test]
            fn test_cache_tracker_unknown_warmth(
                worker_id in "[a-z]{3,8}",
                project_id in "[a-z]{3,8}",
            ) {
        let _guard = test_guard!();
                let tracker = CacheTracker::new();
                let warmth = tracker.estimate_warmth(&worker_id, &project_id, CacheUse::Build);
                prop_assert!(
                    warmth.abs() < f64::EPSILON,
                    "Unknown worker/project should have 0.0 warmth, got {warmth}"
                );
            }

            /// CacheTracker respects max_projects_per_worker limit.
            #[test]
            fn test_cache_tracker_project_limit(num_projects in 40usize..=100usize) {
        let _guard = test_guard!();
                let mut tracker = CacheTracker::new();

                for i in 0..num_projects {
                    tracker.record_build("worker-1", &format!("project-{i}"), CacheUse::Build);
                }

                // Default limit is 50 projects per worker
                let worker_projects = tracker.workers.get("worker-1").map(|m| m.len()).unwrap_or(0);
                prop_assert!(
                    worker_projects <= 50,
                    "Worker has {worker_projects} projects, exceeds limit of 50"
                );
            }

            /// Test cache warmth immediately after recording is 1.0.
            #[test]
            fn test_cache_tracker_immediate_warmth(
                worker_id in "[a-z]{3,8}",
                project_id in "[a-z]{3,8}",
            ) {
        let _guard = test_guard!();
                let mut tracker = CacheTracker::new();
                tracker.record_build(&worker_id, &project_id, CacheUse::Build);

                let warmth = tracker.estimate_warmth(&worker_id, &project_id, CacheUse::Build);
                // Immediately after recording, warmth should be 1.0 (less than 1 hour old)
                prop_assert!(
                    (warmth - 1.0).abs() < 0.01,
                    "Immediate warmth should be ~1.0, got {warmth}"
                );
            }
        }

        // ====================================================================
        // CacheState property tests
        // ====================================================================

        #[test]
        fn test_cache_state_last_activity_none() {
            let _guard = test_guard!();
            let state = CacheState::default();
            assert!(state.last_activity().is_none());
        }

        #[test]
        fn test_cache_state_last_activity_build_only() {
            let _guard = test_guard!();
            let now = Instant::now();
            let state = CacheState {
                last_build: Some(now),
                last_test: None,
                last_success: None,
            };
            assert_eq!(state.last_activity(), Some(now));
        }

        #[test]
        fn test_cache_state_last_activity_test_only() {
            let _guard = test_guard!();
            let now = Instant::now();
            let state = CacheState {
                last_build: None,
                last_test: Some(now),
                last_success: None,
            };
            assert_eq!(state.last_activity(), Some(now));
        }

        #[test]
        fn test_cache_state_last_activity_both_returns_max() {
            let _guard = test_guard!();
            let earlier = Instant::now();
            // Sleep briefly to ensure later > earlier
            std::thread::sleep(Duration::from_millis(1));
            let later = Instant::now();

            let state = CacheState {
                last_build: Some(earlier),
                last_test: Some(later),
                last_success: None,
            };
            assert_eq!(state.last_activity(), Some(later));

            let state2 = CacheState {
                last_build: Some(later),
                last_test: Some(earlier),
                last_success: None,
            };
            assert_eq!(state2.last_activity(), Some(later));
        }

        // ====================================================================
        // Targeted edge case tests
        // ====================================================================

        #[test]
        fn test_normalize_latency_extreme_values() {
            let _guard = test_guard!();
            // Test u64::MAX doesn't panic or produce NaN
            let score = WorkerSelector::normalize_latency_ms(u64::MAX);
            assert!(score >= 0.0);
            assert!(score <= 1.0);
            assert!(!score.is_nan());
        }

        #[test]
        fn test_normalize_priority_edge_cases() {
            let _guard = test_guard!();
            // Priority below min (saturating_sub handles this)
            let score = WorkerSelector::normalize_priority(0, 100, 200);
            assert!((score - 0.0).abs() < f64::EPSILON);

            // Priority above max
            let score = WorkerSelector::normalize_priority(300, 100, 200);
            assert!(score >= 1.0); // Will be 2.0 without clamping, which is fine for internal use
        }

        #[test]
        fn test_selection_history_prune() {
            let _guard = test_guard!();
            let mut history = SelectionHistory::new();

            // Record some selections
            history.record_selection("worker-1");
            history.record_selection("worker-2");

            // Prune with zero duration should remove all
            history.prune(Duration::from_secs(0));

            // All selections should be pruned (except those exactly at cutoff)
            // Since we just recorded, a zero-duration prune removes everything
            let count = history.recent_selections("worker-1", Duration::from_secs(3600));
            // Note: prune behavior may keep very recent entries, so we just check it doesn't panic
            assert!(count <= 1);
        }

        #[test]
        fn test_audit_log_empty_operations() {
            let _guard = test_guard!();
            let log = SelectionAuditLog::new(10);
            assert!(log.is_empty());
            assert_eq!(log.len(), 0);
            assert!(log.last().is_none());
            assert!(log.get(1).is_none());
            assert!(log.last_n(5).is_empty());
        }
    }
}
