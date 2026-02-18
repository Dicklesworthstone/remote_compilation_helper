//! Daemon-side RepoConvergence service for multi-repo dependency graphs.
//!
//! Computes required repo hull from active builds, tracks per-worker drift
//! states with deterministic transitions and hysteresis, and drives bounded
//! convergence through the repo_updater adapter contract.

use rch_common::WorkerId;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::events::EventBus;

// ── Constants ──────────────────────────────────────────────────────────────

/// Maximum convergence attempts per worker before entering Failed state.
const MAX_CONVERGENCE_ATTEMPTS: u32 = 3;

/// Maximum wall-clock time budget per convergence cycle (seconds).
const CONVERGENCE_TIME_BUDGET_SECS: u64 = 120;

/// Minimum dwell time in a state before allowing transition (hysteresis, ms).
const STATE_HYSTERESIS_MS: u64 = 5_000;

/// Maximum retained transition history entries per worker.
const MAX_TRANSITION_HISTORY: usize = 64;

/// Maximum retained convergence outcomes globally.
const MAX_OUTCOME_HISTORY: usize = 256;

/// Staleness threshold: if last status check is older than this, mark Stale.
const STALENESS_THRESHOLD_SECS: u64 = 300;

// ── Drift State ────────────────────────────────────────────────────────────

/// Deterministic drift states for per-worker repo convergence.
///
/// Transitions follow hysteresis rules to avoid flapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConvergenceDriftState {
    /// All required repos are present and fresh on the worker.
    Ready,
    /// Some required repos are missing or stale.
    Drifting,
    /// A sync operation is in progress.
    Converging,
    /// Sync failed after exhausting retry/time budgets.
    Failed,
    /// No convergence status available (timeout, adapter unavailable).
    Stale,
}

impl std::fmt::Display for ConvergenceDriftState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ready => write!(f, "ready"),
            Self::Drifting => write!(f, "drifting"),
            Self::Converging => write!(f, "converging"),
            Self::Failed => write!(f, "failed"),
            Self::Stale => write!(f, "stale"),
        }
    }
}

// ── State Transition ───────────────────────────────────────────────────────

/// Record of a drift state transition with reason code and timestamp.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftStateTransition {
    pub from_state: ConvergenceDriftState,
    pub to_state: ConvergenceDriftState,
    pub reason_code: String,
    pub transitioned_at_unix_ms: i64,
}

// ── Per-Worker Convergence State ───────────────────────────────────────────

/// Tracks the convergence posture for a single worker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerConvergenceState {
    pub worker_id: String,
    pub current_state: ConvergenceDriftState,
    pub required_repos: Vec<String>,
    pub synced_repos: Vec<String>,
    pub missing_repos: Vec<String>,
    pub last_status_check_unix_ms: i64,
    pub last_convergence_attempt_unix_ms: i64,
    pub convergence_attempts: u32,
    pub time_budget_remaining_ms: u64,
    pub attempt_budget_remaining: u32,
    /// Monotonic instant of last state transition (not serialized).
    #[serde(skip)]
    pub last_transition_at: Option<Instant>,
}

impl WorkerConvergenceState {
    fn new(worker_id: &str) -> Self {
        Self {
            worker_id: worker_id.to_string(),
            current_state: ConvergenceDriftState::Stale,
            required_repos: Vec::new(),
            synced_repos: Vec::new(),
            missing_repos: Vec::new(),
            last_status_check_unix_ms: 0,
            last_convergence_attempt_unix_ms: 0,
            convergence_attempts: 0,
            time_budget_remaining_ms: CONVERGENCE_TIME_BUDGET_SECS * 1000,
            attempt_budget_remaining: MAX_CONVERGENCE_ATTEMPTS,
            last_transition_at: None,
        }
    }

    /// Returns `true` if the hysteresis interval has elapsed since the last
    /// state transition, allowing a new transition.
    fn can_transition(&self) -> bool {
        match self.last_transition_at {
            Some(last) => last.elapsed() >= Duration::from_millis(STATE_HYSTERESIS_MS),
            None => true,
        }
    }

    /// Compute drift confidence score (0.0 = fully converged, 1.0 = fully drifted).
    pub(crate) fn drift_confidence(&self) -> f64 {
        if self.required_repos.is_empty() {
            return 0.0;
        }
        let missing = self.missing_repos.len() as f64;
        let total = self.required_repos.len() as f64;
        (missing / total).clamp(0.0, 1.0)
    }

    /// Reset budgets for a new convergence cycle.
    fn reset_budgets(&mut self) {
        self.convergence_attempts = 0;
        self.time_budget_remaining_ms = CONVERGENCE_TIME_BUDGET_SECS * 1000;
        self.attempt_budget_remaining = MAX_CONVERGENCE_ATTEMPTS;
    }
}

// ── Scheduling Context ─────────────────────────────────────────────────────

/// Represents the set of repos needed by currently-active builds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchedulingContext {
    pub context_id: String,
    pub active_build_count: u32,
    pub required_repos: Vec<String>,
    pub hull_computed_at_unix_ms: i64,
}

// ── Convergence Outcome ────────────────────────────────────────────────────

/// Structured outcome emitted after a convergence attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConvergenceOutcome {
    pub worker_id: String,
    pub drift_state_before: ConvergenceDriftState,
    pub drift_state_after: ConvergenceDriftState,
    pub synced_count: u32,
    pub failed_count: u32,
    pub skipped_count: u32,
    pub duration_ms: u64,
    pub reason_code: String,
    pub failure: Option<String>,
    pub emitted_at_unix_ms: i64,
}

// ── Error Types ────────────────────────────────────────────────────────────

/// Convergence operation errors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConvergenceError {
    /// The repo_updater adapter is not available.
    AdapterUnavailable,
    /// Time budget for convergence has been exceeded.
    TimeBudgetExceeded,
    /// Attempt budget for convergence has been exceeded.
    AttemptBudgetExceeded,
    /// Authentication/credential failure.
    AuthFailure(String),
    /// Partial failure during sync.
    PartialFailure { synced: u32, failed: u32 },
    /// Hysteresis guard prevents transition.
    HysteresisBlocked,
}

impl std::fmt::Display for ConvergenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AdapterUnavailable => write!(f, "repo_updater adapter unavailable"),
            Self::TimeBudgetExceeded => write!(f, "convergence time budget exceeded"),
            Self::AttemptBudgetExceeded => write!(f, "convergence attempt budget exceeded"),
            Self::AuthFailure(msg) => write!(f, "auth failure: {}", msg),
            Self::PartialFailure { synced, failed } => {
                write!(f, "partial failure: {} synced, {} failed", synced, failed)
            }
            Self::HysteresisBlocked => write!(f, "state transition blocked by hysteresis"),
        }
    }
}

// ── Service ────────────────────────────────────────────────────────────────

/// Core daemon service for tracking and driving repo convergence.
///
/// Maintains per-worker convergence state with deterministic transitions,
/// computes required repo hulls from active builds, and emits structured
/// events for observability.
pub struct RepoConvergenceService {
    events: EventBus,
    /// Per-worker convergence tracking.
    state: RwLock<HashMap<String, WorkerConvergenceState>>,
    /// Global convergence outcome log (bounded).
    outcomes: RwLock<VecDeque<ConvergenceOutcome>>,
    /// Per-worker transition history (bounded per worker).
    transitions: RwLock<HashMap<String, VecDeque<DriftStateTransition>>>,
}

impl RepoConvergenceService {
    /// Create a new service wired to the daemon event bus.
    pub fn new(events: EventBus) -> Self {
        Self {
            events,
            state: RwLock::new(HashMap::new()),
            outcomes: RwLock::new(VecDeque::new()),
            transitions: RwLock::new(HashMap::new()),
        }
    }

    // ── Hull Computation ───────────────────────────────────────────────

    /// Compute the convex hull of required repos from a set of project roots.
    ///
    /// The hull is the deduplicated, sorted set of all project paths that
    /// active builds depend on. This determines what repos must be present
    /// on each worker.
    pub fn compute_required_hull(project_roots: &[String]) -> SchedulingContext {
        let mut hull: Vec<String> = project_roots.to_vec();
        hull.sort();
        hull.dedup();

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or_default();

        SchedulingContext {
            context_id: format!("hull-{}", now_ms),
            active_build_count: project_roots.len() as u32,
            required_repos: hull,
            hull_computed_at_unix_ms: now_ms,
        }
    }

    // ── State Queries ──────────────────────────────────────────────────

    /// Get the current drift state for a worker.
    pub async fn get_drift_state(&self, worker_id: &WorkerId) -> ConvergenceDriftState {
        let state = self.state.read().await;
        state
            .get(worker_id.as_str())
            .map(|s| s.current_state)
            .unwrap_or(ConvergenceDriftState::Stale)
    }

    /// Get full convergence state for a worker.
    pub async fn get_worker_state(&self, worker_id: &WorkerId) -> Option<WorkerConvergenceState> {
        let state = self.state.read().await;
        state.get(worker_id.as_str()).cloned()
    }

    /// Get convergence state for all tracked workers.
    pub async fn get_all_worker_states(&self) -> Vec<WorkerConvergenceState> {
        let state = self.state.read().await;
        state.values().cloned().collect()
    }

    /// Get recent convergence outcomes (most recent first).
    pub async fn get_recent_outcomes(&self, limit: usize) -> Vec<ConvergenceOutcome> {
        let outcomes = self.outcomes.read().await;
        outcomes.iter().rev().take(limit).cloned().collect()
    }

    /// Get state transitions for a specific worker.
    pub async fn get_worker_transitions(&self, worker_id: &WorkerId) -> Vec<DriftStateTransition> {
        let transitions = self.transitions.read().await;
        transitions
            .get(worker_id.as_str())
            .map(|t| t.iter().cloned().collect())
            .unwrap_or_default()
    }

    // ── State Updates ──────────────────────────────────────────────────

    /// Update the required repo set for a worker and recompute drift.
    ///
    /// Called when the scheduling context changes (new builds started,
    /// builds completed, etc.).
    pub async fn update_required_repos(
        &self,
        worker_id: &WorkerId,
        required_repos: Vec<String>,
        synced_repos: Vec<String>,
    ) {
        let mut state = self.state.write().await;
        let entry = state
            .entry(worker_id.as_str().to_string())
            .or_insert_with(|| WorkerConvergenceState::new(worker_id.as_str()));

        entry.required_repos = required_repos;
        entry.synced_repos = synced_repos.clone();

        // Compute missing repos.
        let synced_set: std::collections::HashSet<&str> =
            synced_repos.iter().map(String::as_str).collect();
        entry.missing_repos = entry
            .required_repos
            .iter()
            .filter(|r| !synced_set.contains(r.as_str()))
            .cloned()
            .collect();

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or_default();
        entry.last_status_check_unix_ms = now_ms;

        // Determine new drift state.
        let new_state = if entry.missing_repos.is_empty() {
            ConvergenceDriftState::Ready
        } else {
            ConvergenceDriftState::Drifting
        };

        // Apply state transition with hysteresis.
        if new_state != entry.current_state && entry.can_transition() {
            let old_state = entry.current_state;
            let reason = if new_state == ConvergenceDriftState::Ready {
                "all_repos_present".to_string()
            } else {
                format!("missing_{}_repos", entry.missing_repos.len())
            };
            {
                let mut trans_guard = self.transitions.write().await;
                self.record_transition_locked(
                    &mut trans_guard,
                    worker_id.as_str(),
                    old_state,
                    new_state,
                    &reason,
                    now_ms,
                );
            }
            entry.current_state = new_state;
            entry.last_transition_at = Some(Instant::now());

            if new_state == ConvergenceDriftState::Ready {
                entry.reset_budgets();
            }
        }
    }

    /// Record a convergence attempt outcome.
    ///
    /// Drives state transitions based on the attempt result and remaining
    /// budgets.
    pub async fn record_convergence_attempt(
        &self,
        worker_id: &WorkerId,
        synced_count: u32,
        failed_count: u32,
        skipped_count: u32,
        duration_ms: u64,
        failure: Option<String>,
    ) -> Result<ConvergenceOutcome, ConvergenceError> {
        let mut state = self.state.write().await;
        let entry = state
            .entry(worker_id.as_str().to_string())
            .or_insert_with(|| WorkerConvergenceState::new(worker_id.as_str()));

        let drift_state_before = entry.current_state;

        // Consume budgets.
        entry.convergence_attempts += 1;
        entry.attempt_budget_remaining = entry.attempt_budget_remaining.saturating_sub(1);
        entry.time_budget_remaining_ms = entry.time_budget_remaining_ms.saturating_sub(duration_ms);

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or_default();
        entry.last_convergence_attempt_unix_ms = now_ms;

        // Determine new state based on outcome.
        let (new_state, reason_code) = if failure.is_some() {
            if entry.attempt_budget_remaining == 0 {
                (
                    ConvergenceDriftState::Failed,
                    "attempt_budget_exhausted".to_string(),
                )
            } else if entry.time_budget_remaining_ms == 0 {
                (
                    ConvergenceDriftState::Failed,
                    "time_budget_exhausted".to_string(),
                )
            } else {
                (
                    ConvergenceDriftState::Drifting,
                    "sync_failed_retryable".to_string(),
                )
            }
        } else if failed_count > 0 {
            (
                ConvergenceDriftState::Drifting,
                format!("partial_failure_{}_repos", failed_count),
            )
        } else {
            (ConvergenceDriftState::Ready, "sync_complete".to_string())
        };

        // Apply transition unconditionally — convergence attempts are
        // deliberate actions that bypass hysteresis (hysteresis only
        // guards the passive Ready ↔ Drifting observation path).
        if new_state != entry.current_state {
            {
                let mut trans_guard = self.transitions.write().await;
                self.record_transition_locked(
                    &mut trans_guard,
                    worker_id.as_str(),
                    entry.current_state,
                    new_state,
                    &reason_code,
                    now_ms,
                );
            }
            entry.current_state = new_state;
            entry.last_transition_at = Some(Instant::now());

            if new_state == ConvergenceDriftState::Ready {
                entry.reset_budgets();
            }
        }

        let outcome = ConvergenceOutcome {
            worker_id: worker_id.as_str().to_string(),
            drift_state_before,
            drift_state_after: entry.current_state,
            synced_count,
            failed_count,
            skipped_count,
            duration_ms,
            reason_code: reason_code.clone(),
            failure,
            emitted_at_unix_ms: now_ms,
        };

        // Emit event.
        self.events.emit("repo_convergence.outcome", &outcome);

        // Store outcome.
        let mut outcomes = self.outcomes.write().await;
        if outcomes.len() >= MAX_OUTCOME_HISTORY {
            outcomes.pop_front();
        }
        outcomes.push_back(outcome.clone());

        Ok(outcome)
    }

    /// Mark a worker as entering the Converging state (sync starting).
    pub async fn mark_converging(&self, worker_id: &WorkerId) {
        let mut state = self.state.write().await;
        let entry = state
            .entry(worker_id.as_str().to_string())
            .or_insert_with(|| WorkerConvergenceState::new(worker_id.as_str()));

        // No hysteresis — mark_converging is a deliberate action.
        if entry.current_state != ConvergenceDriftState::Converging {
            let now_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as i64)
                .unwrap_or_default();
            {
                let mut trans_guard = self.transitions.write().await;
                self.record_transition_locked(
                    &mut trans_guard,
                    worker_id.as_str(),
                    entry.current_state,
                    ConvergenceDriftState::Converging,
                    "sync_started",
                    now_ms,
                );
            }
            entry.current_state = ConvergenceDriftState::Converging;
            entry.last_transition_at = Some(Instant::now());
        }
    }

    /// Check and mark workers as Stale if their last status check is too old.
    pub async fn check_staleness(&self) {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or_default();
        let threshold_ms = (STALENESS_THRESHOLD_SECS * 1000) as i64;

        let mut state = self.state.write().await;
        let mut transitions = self.transitions.write().await;

        for entry in state.values_mut() {
            if entry.current_state != ConvergenceDriftState::Stale
                && entry.last_status_check_unix_ms > 0
                && (now_ms - entry.last_status_check_unix_ms) > threshold_ms
                && entry.can_transition()
            {
                let old_state = entry.current_state;
                self.record_transition_locked(
                    &mut transitions,
                    &entry.worker_id,
                    old_state,
                    ConvergenceDriftState::Stale,
                    "status_check_stale",
                    now_ms,
                );
                entry.current_state = ConvergenceDriftState::Stale;
                entry.last_transition_at = Some(Instant::now());
                warn!(
                    "Worker {} repo convergence marked stale (last check {}ms ago)",
                    entry.worker_id,
                    now_ms - entry.last_status_check_unix_ms
                );
            }
        }
    }

    /// Operator repair: force-reset a worker's convergence state to Drifting
    /// with fresh budgets. Bypasses hysteresis since this is a deliberate action.
    ///
    /// Returns the previous drift state, or `None` if the worker is not tracked.
    pub async fn repair_worker(&self, worker_id: &WorkerId) -> Option<ConvergenceDriftState> {
        let mut state = self.state.write().await;
        let entry = state.get_mut(worker_id.as_str())?;

        let old_state = entry.current_state;

        // Reset synced repos to force Drifting, reset budgets.
        entry.synced_repos.clear();
        entry.missing_repos = entry.required_repos.clone();
        entry.reset_budgets();

        let new_state = if entry.required_repos.is_empty() {
            ConvergenceDriftState::Ready
        } else {
            ConvergenceDriftState::Drifting
        };

        if new_state != old_state {
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as i64)
                .unwrap_or_default();

            let mut transitions = self.transitions.write().await;
            self.record_transition_locked(
                &mut transitions,
                worker_id.as_str(),
                old_state,
                new_state,
                "operator_repair",
                now_ms,
            );
            entry.current_state = new_state;
            entry.last_transition_at = Some(std::time::Instant::now());
        }

        Some(old_state)
    }

    /// Check if convergence budgets allow another attempt for a worker.
    pub async fn has_budget(&self, worker_id: &WorkerId) -> bool {
        let state = self.state.read().await;
        state
            .get(worker_id.as_str())
            .map(|s| s.attempt_budget_remaining > 0 && s.time_budget_remaining_ms > 0)
            .unwrap_or(true) // No state yet = budgets not consumed
    }

    // ── Test Helpers ──────────────────────────────────────────────────

    /// Allows tests to simulate staleness by backdating the last status check.
    #[cfg(test)]
    async fn set_last_status_check_unix_ms(&self, worker_id: &str, unix_ms: i64) {
        let mut state = self.state.write().await;
        if let Some(entry) = state.get_mut(worker_id) {
            entry.last_status_check_unix_ms = unix_ms;
        }
    }

    /// Allows tests to backdate `last_transition_at` to simulate hysteresis expiry.
    #[cfg(test)]
    async fn set_last_transition_at(&self, worker_id: &str, instant: Option<Instant>) {
        let mut state = self.state.write().await;
        if let Some(entry) = state.get_mut(worker_id) {
            entry.last_transition_at = instant;
        }
    }

    // ── Internal Helpers ───────────────────────────────────────────────

    fn record_transition_locked(
        &self,
        transitions: &mut HashMap<String, VecDeque<DriftStateTransition>>,
        worker_id: &str,
        from: ConvergenceDriftState,
        to: ConvergenceDriftState,
        reason: &str,
        now_ms: i64,
    ) {
        let transition = DriftStateTransition {
            from_state: from,
            to_state: to,
            reason_code: reason.to_string(),
            transitioned_at_unix_ms: now_ms,
        };

        info!(
            "Repo convergence transition: {} {} -> {} ({})",
            worker_id, from, to, reason
        );

        self.events
            .emit("repo_convergence.state_changed", &transition);

        let worker_transitions = transitions.entry(worker_id.to_string()).or_default();
        if worker_transitions.len() >= MAX_TRANSITION_HISTORY {
            worker_transitions.pop_front();
        }
        worker_transitions.push_back(transition);
    }
}

// ── Background Convergence Loop (bd-vvmd.3.4) ────────────────────────────

/// Default interval between convergence loop ticks.
const CONVERGENCE_LOOP_INTERVAL_SECS: u64 = 30;

/// Sustained drift alert threshold: alert if a worker stays Drifting for this
/// many consecutive ticks without improvement.
const SUSTAINED_DRIFT_ALERT_TICKS: u32 = 6;

/// Sustained failure alert threshold: alert if a worker stays Failed for this
/// many consecutive ticks.
const SUSTAINED_FAILURE_ALERT_TICKS: u32 = 2;

/// Alert debounce window: suppress repeat alerts for the same worker within
/// this many ticks after an alert fires.
const ALERT_DEBOUNCE_TICKS: u32 = 10;

/// Per-worker tracking for the convergence loop.
#[derive(Debug, Clone)]
struct LoopWorkerState {
    /// Consecutive ticks in Drifting state.
    drift_ticks: u32,
    /// Consecutive ticks in Failed state.
    failure_ticks: u32,
    /// Ticks remaining in alert suppression window.
    alert_cooldown: u32,
    /// Last drift state observed.
    last_state: ConvergenceDriftState,
}

impl LoopWorkerState {
    fn new() -> Self {
        Self {
            drift_ticks: 0,
            failure_ticks: 0,
            alert_cooldown: 0,
            last_state: ConvergenceDriftState::Stale,
        }
    }
}

/// Configuration for the background convergence loop.
#[derive(Debug, Clone)]
pub struct ConvergenceLoopConfig {
    /// Interval between convergence ticks.
    pub interval: Duration,
    /// After how many consecutive drift ticks to emit an alert.
    pub sustained_drift_ticks: u32,
    /// After how many consecutive failure ticks to emit an alert.
    pub sustained_failure_ticks: u32,
    /// Ticks to suppress repeat alerts after one fires.
    pub alert_debounce_ticks: u32,
}

impl Default for ConvergenceLoopConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(CONVERGENCE_LOOP_INTERVAL_SECS),
            sustained_drift_ticks: SUSTAINED_DRIFT_ALERT_TICKS,
            sustained_failure_ticks: SUSTAINED_FAILURE_ALERT_TICKS,
            alert_debounce_ticks: ALERT_DEBOUNCE_TICKS,
        }
    }
}

/// Alert emitted by the convergence loop for sustained drift or failure.
#[derive(Debug, Clone, Serialize)]
pub struct ConvergenceAlert {
    pub worker_id: String,
    pub alert_type: String,
    pub drift_state: String,
    pub consecutive_ticks: u32,
    pub missing_repos: Vec<String>,
    pub remediation: Vec<String>,
    pub emitted_at_unix_ms: i64,
}

/// Summary of a single convergence loop tick.
#[derive(Debug, Clone, Serialize)]
pub struct ConvergenceLoopTickSummary {
    pub tick_number: u64,
    pub workers_checked: usize,
    pub workers_skipped_busy: usize,
    pub staleness_checks: usize,
    pub alerts_emitted: usize,
    pub duration_ms: u64,
}

/// Background convergence loop that periodically checks worker drift states,
/// runs staleness checks, and emits alerts for sustained drift or failure.
///
/// Follows workload-aware throttling: workers with active builds (used_slots > 0)
/// are skipped to avoid interfering with in-flight compilations.
pub struct ConvergenceLoop {
    convergence: Arc<RepoConvergenceService>,
    pool: crate::workers::WorkerPool,
    events: EventBus,
    config: ConvergenceLoopConfig,
    tick_number: u64,
    tracker: HashMap<String, LoopWorkerState>,
}

impl ConvergenceLoop {
    /// Create a new convergence loop.
    pub fn new(
        convergence: Arc<RepoConvergenceService>,
        pool: crate::workers::WorkerPool,
        events: EventBus,
        config: ConvergenceLoopConfig,
    ) -> Self {
        Self {
            convergence,
            pool,
            events,
            config,
            tick_number: 0,
            tracker: HashMap::new(),
        }
    }

    /// Start the background convergence loop. Returns a JoinHandle.
    pub fn start(mut self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            use tokio::time::interval;

            let mut ticker = interval(self.config.interval);

            info!(
                interval_secs = self.config.interval.as_secs(),
                "Convergence loop started"
            );

            loop {
                ticker.tick().await;
                self.tick().await;
            }
        })
    }

    /// Execute a single convergence tick. Public for testability.
    pub async fn tick(&mut self) -> ConvergenceLoopTickSummary {
        self.tick_number += 1;

        let tick_start = Instant::now();
        let mut workers_checked: usize = 0;
        let mut workers_skipped_busy: usize = 0;
        let mut alerts_emitted: usize = 0;

        // 1. Run staleness checks for all tracked workers.
        self.convergence.check_staleness().await;

        // 2. Iterate over all pool workers and check convergence state.
        let pool_workers = self.pool.all_workers().await;

        for worker in &pool_workers {
            let worker_id = {
                let cfg = worker.config.read().await;
                cfg.id.clone()
            };

            // Workload-aware throttling: skip workers with active builds.
            if worker.used_slots() > 0 {
                workers_skipped_busy += 1;
                continue;
            }

            workers_checked += 1;
            let drift_state = self.convergence.get_drift_state(&worker_id).await;

            let entry = self
                .tracker
                .entry(worker_id.as_str().to_string())
                .or_insert_with(LoopWorkerState::new);

            // Decrement alert cooldown.
            if entry.alert_cooldown > 0 {
                entry.alert_cooldown -= 1;
            }

            // Track consecutive drift/failure ticks.
            match drift_state {
                ConvergenceDriftState::Drifting => {
                    entry.drift_ticks += 1;
                    entry.failure_ticks = 0;
                }
                ConvergenceDriftState::Failed => {
                    entry.failure_ticks += 1;
                    entry.drift_ticks = 0;
                }
                _ => {
                    // Ready, Converging, or Stale: reset counters.
                    entry.drift_ticks = 0;
                    entry.failure_ticks = 0;
                }
            }
            entry.last_state = drift_state;

            // Determine if alert should fire. Capture needed data before borrowing self.
            let alert_info = if entry.alert_cooldown == 0 {
                if entry.drift_ticks >= self.config.sustained_drift_ticks {
                    Some(("sustained_drift", entry.drift_ticks, entry.last_state))
                } else if entry.failure_ticks >= self.config.sustained_failure_ticks {
                    Some(("convergence_failure", entry.failure_ticks, entry.last_state))
                } else {
                    None
                }
            } else {
                None
            };

            if let Some((alert_type, ticks, _state)) = alert_info {
                let alert =
                    Self::build_alert_static(&self.convergence, &worker_id, alert_type, ticks)
                        .await;
                warn!(
                    worker_id = %alert.worker_id,
                    alert_type = %alert.alert_type,
                    consecutive_ticks = alert.consecutive_ticks,
                    "Convergence alert: {}",
                    alert.alert_type
                );
                self.events.emit("repo_convergence.alert", &alert);
                // Re-borrow entry to set cooldown.
                if let Some(entry) = self.tracker.get_mut(worker_id.as_str()) {
                    entry.alert_cooldown = self.config.alert_debounce_ticks;
                }
                alerts_emitted += 1;
            }
        }

        // Prune tracker entries for workers no longer in the pool.
        let pool_ids: std::collections::HashSet<String> = {
            let mut ids = std::collections::HashSet::new();
            for w in &pool_workers {
                let cfg = w.config.read().await;
                ids.insert(cfg.id.as_str().to_string());
            }
            ids
        };
        self.tracker.retain(|k, _| pool_ids.contains(k));

        let duration_ms = tick_start.elapsed().as_millis() as u64;

        let summary = ConvergenceLoopTickSummary {
            tick_number: self.tick_number,
            workers_checked,
            workers_skipped_busy,
            staleness_checks: pool_workers.len(),
            alerts_emitted,
            duration_ms,
        };

        self.events.emit("repo_convergence.loop_tick", &summary);

        if alerts_emitted > 0 || self.tick_number <= 1 {
            info!(
                tick = self.tick_number,
                checked = workers_checked,
                skipped_busy = workers_skipped_busy,
                alerts = alerts_emitted,
                duration_ms = duration_ms,
                "Convergence loop tick"
            );
        }

        summary
    }

    async fn build_alert_static(
        convergence: &RepoConvergenceService,
        worker_id: &WorkerId,
        alert_type: &str,
        ticks: u32,
    ) -> ConvergenceAlert {
        let (missing_repos, remediation) =
            if let Some(ws) = convergence.get_worker_state(worker_id).await {
                let missing = ws.missing_repos.clone();
                let mut hints = Vec::new();
                match ws.current_state {
                    ConvergenceDriftState::Drifting => {
                        if !missing.is_empty() {
                            hints.push(format!(
                                "Missing {} repo(s): {}",
                                missing.len(),
                                missing.join(", ")
                            ));
                        }
                        hints.push("Run convergence repair to sync missing repos.".into());
                    }
                    ConvergenceDriftState::Failed => {
                        hints.push("Convergence budgets exhausted.".into());
                        hints.push("Run repair to reset budgets and retry convergence.".into());
                    }
                    _ => {}
                }
                (missing, hints)
            } else {
                (vec![], vec!["No convergence data available.".into()])
            };

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        ConvergenceAlert {
            worker_id: worker_id.as_str().to_string(),
            alert_type: alert_type.to_string(),
            drift_state: convergence.get_drift_state(worker_id).await.to_string(),
            consecutive_ticks: ticks,
            missing_repos,
            remediation,
            emitted_at_unix_ms: now_ms,
        }
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rch_common::WorkerConfig;
    use rch_common::test_guard;

    fn test_events() -> EventBus {
        EventBus::new(64)
    }

    fn test_worker_id(name: &str) -> WorkerId {
        WorkerId::new(name)
    }

    #[test]
    fn test_convergence_drift_state_display() {
        let _guard = test_guard!();
        assert_eq!(ConvergenceDriftState::Ready.to_string(), "ready");
        assert_eq!(ConvergenceDriftState::Drifting.to_string(), "drifting");
        assert_eq!(ConvergenceDriftState::Converging.to_string(), "converging");
        assert_eq!(ConvergenceDriftState::Failed.to_string(), "failed");
        assert_eq!(ConvergenceDriftState::Stale.to_string(), "stale");
    }

    #[test]
    fn test_compute_required_hull_deduplicates_and_sorts() {
        let _guard = test_guard!();
        let roots = vec![
            "/data/projects/c".to_string(),
            "/data/projects/a".to_string(),
            "/data/projects/b".to_string(),
            "/data/projects/a".to_string(), // duplicate
        ];
        let ctx = RepoConvergenceService::compute_required_hull(&roots);
        assert_eq!(
            ctx.required_repos,
            vec!["/data/projects/a", "/data/projects/b", "/data/projects/c",]
        );
        assert_eq!(ctx.active_build_count, 4);
        assert!(ctx.hull_computed_at_unix_ms > 0);
    }

    #[test]
    fn test_compute_required_hull_empty() {
        let _guard = test_guard!();
        let ctx = RepoConvergenceService::compute_required_hull(&[]);
        assert!(ctx.required_repos.is_empty());
        assert_eq!(ctx.active_build_count, 0);
    }

    #[test]
    fn test_worker_convergence_state_drift_confidence() {
        let _guard = test_guard!();
        let mut ws = WorkerConvergenceState::new("w1");
        assert_eq!(ws.drift_confidence(), 0.0); // no required repos

        ws.required_repos = vec!["a".into(), "b".into(), "c".into(), "d".into()];
        ws.missing_repos = vec!["b".into(), "d".into()];
        assert!((ws.drift_confidence() - 0.5).abs() < f64::EPSILON);

        ws.missing_repos = vec![];
        assert_eq!(ws.drift_confidence(), 0.0);

        ws.missing_repos = ws.required_repos.clone();
        assert!((ws.drift_confidence() - 1.0).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_service_initial_state_is_stale() {
        let _guard = test_guard!();
        let svc = RepoConvergenceService::new(test_events());
        let wid = test_worker_id("fresh-worker");
        assert_eq!(
            svc.get_drift_state(&wid).await,
            ConvergenceDriftState::Stale
        );
    }

    #[tokio::test]
    async fn test_update_required_repos_transitions_to_ready() {
        let _guard = test_guard!();
        let svc = RepoConvergenceService::new(test_events());
        let wid = test_worker_id("w1");

        // All repos synced -> Ready
        svc.update_required_repos(
            &wid,
            vec!["repo_a".into(), "repo_b".into()],
            vec!["repo_a".into(), "repo_b".into()],
        )
        .await;

        assert_eq!(
            svc.get_drift_state(&wid).await,
            ConvergenceDriftState::Ready
        );
    }

    #[tokio::test]
    async fn test_update_required_repos_transitions_to_drifting() {
        let _guard = test_guard!();
        let svc = RepoConvergenceService::new(test_events());
        let wid = test_worker_id("w2");

        // Missing repo_b -> Drifting
        svc.update_required_repos(
            &wid,
            vec!["repo_a".into(), "repo_b".into()],
            vec!["repo_a".into()],
        )
        .await;

        assert_eq!(
            svc.get_drift_state(&wid).await,
            ConvergenceDriftState::Drifting
        );

        let ws = svc.get_worker_state(&wid).await.unwrap();
        assert_eq!(ws.missing_repos, vec!["repo_b"]);
    }

    #[tokio::test]
    async fn test_record_convergence_success_transitions_to_ready() {
        let _guard = test_guard!();
        let svc = RepoConvergenceService::new(test_events());
        let wid = test_worker_id("w3");

        // Start with drifting state.
        svc.update_required_repos(
            &wid,
            vec!["repo_a".into()],
            vec![], // missing repo_a
        )
        .await;
        assert_eq!(
            svc.get_drift_state(&wid).await,
            ConvergenceDriftState::Drifting
        );

        // Record successful convergence.
        let outcome = svc
            .record_convergence_attempt(&wid, 1, 0, 0, 500, None)
            .await
            .unwrap();
        assert_eq!(outcome.drift_state_before, ConvergenceDriftState::Drifting);
        assert_eq!(outcome.drift_state_after, ConvergenceDriftState::Ready);
        assert_eq!(outcome.synced_count, 1);
        assert!(outcome.failure.is_none());
    }

    #[tokio::test]
    async fn test_record_convergence_failure_stays_drifting_with_budget() {
        let _guard = test_guard!();
        let svc = RepoConvergenceService::new(test_events());
        let wid = test_worker_id("w4");

        svc.update_required_repos(&wid, vec!["r".into()], vec![])
            .await;

        let outcome = svc
            .record_convergence_attempt(&wid, 0, 1, 0, 100, Some("rsync timeout".to_string()))
            .await
            .unwrap();
        // Should stay Drifting (still has budget).
        assert_eq!(outcome.drift_state_after, ConvergenceDriftState::Drifting);
        assert!(svc.has_budget(&wid).await);
    }

    #[tokio::test]
    async fn test_convergence_attempt_budget_exhaustion_transitions_to_failed() {
        let _guard = test_guard!();
        let svc = RepoConvergenceService::new(test_events());
        let wid = test_worker_id("w5");

        svc.update_required_repos(&wid, vec!["r".into()], vec![])
            .await;

        // Exhaust attempt budget.
        for _ in 0..MAX_CONVERGENCE_ATTEMPTS {
            let _ = svc
                .record_convergence_attempt(&wid, 0, 1, 0, 100, Some("auth failure".to_string()))
                .await;
        }

        assert_eq!(
            svc.get_drift_state(&wid).await,
            ConvergenceDriftState::Failed
        );
        assert!(!svc.has_budget(&wid).await);
    }

    #[tokio::test]
    async fn test_mark_converging() {
        let _guard = test_guard!();
        let svc = RepoConvergenceService::new(test_events());
        let wid = test_worker_id("w6");

        svc.update_required_repos(&wid, vec!["r".into()], vec![])
            .await;
        svc.mark_converging(&wid).await;

        assert_eq!(
            svc.get_drift_state(&wid).await,
            ConvergenceDriftState::Converging
        );
    }

    #[tokio::test]
    async fn test_convergence_outcome_stored_and_retrievable() {
        let _guard = test_guard!();
        let svc = RepoConvergenceService::new(test_events());
        let wid = test_worker_id("w7");

        svc.update_required_repos(&wid, vec!["r".into()], vec![])
            .await;
        svc.record_convergence_attempt(&wid, 1, 0, 0, 200, None)
            .await
            .unwrap();

        let outcomes = svc.get_recent_outcomes(10).await;
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].worker_id, "w7");
        assert_eq!(outcomes[0].synced_count, 1);
    }

    #[tokio::test]
    async fn test_transitions_logged_per_worker() {
        let _guard = test_guard!();
        let svc = RepoConvergenceService::new(test_events());
        let wid = test_worker_id("w8");

        // Stale -> Drifting
        svc.update_required_repos(&wid, vec!["r".into()], vec![])
            .await;
        // Drifting -> Ready (via successful convergence)
        svc.record_convergence_attempt(&wid, 1, 0, 0, 100, None)
            .await
            .unwrap();

        let transitions = svc.get_worker_transitions(&wid).await;
        assert_eq!(transitions.len(), 2);
        assert_eq!(transitions[0].from_state, ConvergenceDriftState::Stale);
        assert_eq!(transitions[0].to_state, ConvergenceDriftState::Drifting);
        assert_eq!(transitions[1].from_state, ConvergenceDriftState::Drifting);
        assert_eq!(transitions[1].to_state, ConvergenceDriftState::Ready);
    }

    #[tokio::test]
    async fn test_partial_failure_keeps_drifting() {
        let _guard = test_guard!();
        let svc = RepoConvergenceService::new(test_events());
        let wid = test_worker_id("w9");

        svc.update_required_repos(&wid, vec!["a".into(), "b".into()], vec![])
            .await;

        // Partial: 1 synced, 1 failed, no fatal error
        let outcome = svc
            .record_convergence_attempt(&wid, 1, 1, 0, 300, None)
            .await
            .unwrap();
        assert_eq!(outcome.drift_state_after, ConvergenceDriftState::Drifting);
    }

    #[tokio::test]
    async fn test_get_all_worker_states() {
        let _guard = test_guard!();
        let svc = RepoConvergenceService::new(test_events());

        svc.update_required_repos(&test_worker_id("w10"), vec!["r".into()], vec!["r".into()])
            .await;
        svc.update_required_repos(&test_worker_id("w11"), vec!["r".into()], vec![])
            .await;

        let all = svc.get_all_worker_states().await;
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_convergence_error_display() {
        let _guard = test_guard!();
        assert_eq!(
            ConvergenceError::AdapterUnavailable.to_string(),
            "repo_updater adapter unavailable"
        );
        assert_eq!(
            ConvergenceError::TimeBudgetExceeded.to_string(),
            "convergence time budget exceeded"
        );
        assert_eq!(
            ConvergenceError::AttemptBudgetExceeded.to_string(),
            "convergence attempt budget exceeded"
        );
    }

    #[tokio::test]
    async fn test_convergence_events_emitted() {
        let _guard = test_guard!();
        let events = test_events();
        let mut rx = events.subscribe();
        let svc = RepoConvergenceService::new(events);
        let wid = test_worker_id("w12");

        // Trigger a state transition: Stale -> Drifting
        svc.update_required_repos(&wid, vec!["r".into()], vec![])
            .await;

        // Should have emitted a state_changed event.
        let event_json = tokio::time::timeout(Duration::from_millis(100), rx.recv())
            .await
            .expect("should receive event within timeout")
            .expect("recv should succeed");
        assert!(event_json.contains("repo_convergence.state_changed"));
    }

    #[tokio::test]
    async fn test_ready_resets_budgets() {
        let _guard = test_guard!();
        let svc = RepoConvergenceService::new(test_events());
        let wid = test_worker_id("w13");

        svc.update_required_repos(&wid, vec!["r".into()], vec![])
            .await;

        // Consume one attempt.
        svc.record_convergence_attempt(&wid, 0, 1, 0, 100, Some("fail".into()))
            .await
            .unwrap();

        // Now succeed.
        svc.record_convergence_attempt(&wid, 1, 0, 0, 100, None)
            .await
            .unwrap();

        let ws = svc.get_worker_state(&wid).await.unwrap();
        assert_eq!(ws.attempt_budget_remaining, MAX_CONVERGENCE_ATTEMPTS);
    }

    // ── bd-3jjc.1: Time-budget exhaustion transitions ────────────────

    #[tokio::test]
    async fn test_time_budget_exhaustion_transitions_to_failed() {
        let _guard = test_guard!();
        let svc = RepoConvergenceService::new(test_events());
        let wid = test_worker_id("tb1");

        svc.update_required_repos(&wid, vec!["r".into()], vec![])
            .await;

        // Single attempt consuming entire time budget.
        let outcome = svc
            .record_convergence_attempt(
                &wid,
                0,
                1,
                0,
                CONVERGENCE_TIME_BUDGET_SECS * 1000 + 1,
                Some("timeout".into()),
            )
            .await
            .unwrap();

        assert_eq!(outcome.drift_state_after, ConvergenceDriftState::Failed);
        assert_eq!(outcome.reason_code, "time_budget_exhausted");
    }

    #[tokio::test]
    async fn test_time_budget_cumulative_drain() {
        let _guard = test_guard!();
        let svc = RepoConvergenceService::new(test_events());
        let wid = test_worker_id("tb2");

        svc.update_required_repos(&wid, vec!["r".into()], vec![])
            .await;

        // First attempt: 50s
        svc.record_convergence_attempt(&wid, 0, 1, 0, 50_000, Some("fail".into()))
            .await
            .unwrap();
        let ws = svc.get_worker_state(&wid).await.unwrap();
        assert_eq!(ws.time_budget_remaining_ms, 70_000); // 120k - 50k

        // Second attempt: 50s
        svc.record_convergence_attempt(&wid, 0, 1, 0, 50_000, Some("fail".into()))
            .await
            .unwrap();
        let ws = svc.get_worker_state(&wid).await.unwrap();
        assert_eq!(ws.time_budget_remaining_ms, 20_000); // 70k - 50k

        // Third attempt: 30s — exceeds remaining
        let outcome = svc
            .record_convergence_attempt(&wid, 0, 1, 0, 30_000, Some("fail".into()))
            .await
            .unwrap();
        assert_eq!(outcome.drift_state_after, ConvergenceDriftState::Failed);
        assert_eq!(outcome.reason_code, "attempt_budget_exhausted");
        let ws = svc.get_worker_state(&wid).await.unwrap();
        assert_eq!(ws.time_budget_remaining_ms, 0); // saturated at 0
    }

    #[tokio::test]
    async fn test_time_and_attempt_budget_simultaneous_exhaustion() {
        let _guard = test_guard!();
        let svc = RepoConvergenceService::new(test_events());
        let wid = test_worker_id("tb3");

        svc.update_required_repos(&wid, vec!["r".into()], vec![])
            .await;

        // Consume 2 of 3 attempts with large durations.
        for _ in 0..2 {
            svc.record_convergence_attempt(&wid, 0, 1, 0, 55_000, Some("fail".into()))
                .await
                .unwrap();
        }

        // Third attempt exhausts both attempt budget and time budget.
        let outcome = svc
            .record_convergence_attempt(&wid, 0, 1, 0, 55_000, Some("fail".into()))
            .await
            .unwrap();
        assert_eq!(outcome.drift_state_after, ConvergenceDriftState::Failed);
        let ws = svc.get_worker_state(&wid).await.unwrap();
        assert_eq!(ws.attempt_budget_remaining, 0);
        assert_eq!(ws.time_budget_remaining_ms, 0);
    }

    #[tokio::test]
    async fn test_time_budget_exact_boundary() {
        let _guard = test_guard!();
        let svc = RepoConvergenceService::new(test_events());
        let wid = test_worker_id("tb4");

        svc.update_required_repos(&wid, vec!["r".into()], vec![])
            .await;

        // Consume exactly the full time budget in one attempt.
        let outcome = svc
            .record_convergence_attempt(
                &wid,
                0,
                1,
                0,
                CONVERGENCE_TIME_BUDGET_SECS * 1000,
                Some("timeout".into()),
            )
            .await
            .unwrap();
        let ws = svc.get_worker_state(&wid).await.unwrap();
        assert_eq!(ws.time_budget_remaining_ms, 0);
        // With time budget at 0 and failure, should transition to Failed.
        assert_eq!(outcome.drift_state_after, ConvergenceDriftState::Failed);
    }

    // ── bd-3jjc.2: History overflow boundaries ───────────────────────

    #[tokio::test]
    async fn test_outcome_history_overflow_evicts_oldest() {
        let _guard = test_guard!();
        let svc = RepoConvergenceService::new(test_events());

        // Store MAX_OUTCOME_HISTORY + 1 outcomes across different workers.
        for i in 0..=MAX_OUTCOME_HISTORY {
            let wid = test_worker_id(&format!("oh{i}"));
            svc.update_required_repos(&wid, vec!["r".into()], vec![])
                .await;
            svc.record_convergence_attempt(&wid, 1, 0, 0, 10, None)
                .await
                .unwrap();
        }

        let outcomes = svc.get_recent_outcomes(MAX_OUTCOME_HISTORY + 10).await;
        assert_eq!(outcomes.len(), MAX_OUTCOME_HISTORY);
        // get_recent_outcomes returns reverse-chronological (newest first).
        // Oldest (oh0) should have been evicted; newest should be oh256.
        assert_eq!(outcomes[0].worker_id, format!("oh{MAX_OUTCOME_HISTORY}"));
        // The oldest surviving entry (oh1) should be last.
        assert_eq!(outcomes[MAX_OUTCOME_HISTORY - 1].worker_id, "oh1");
    }

    #[tokio::test]
    async fn test_transition_history_overflow_evicts_oldest() {
        let _guard = test_guard!();
        let svc = RepoConvergenceService::new(test_events());
        let wid = test_worker_id("th_overflow");

        // Drive more transitions than MAX_TRANSITION_HISTORY by toggling
        // between Drifting and Ready states.
        for i in 0..MAX_TRANSITION_HISTORY + 2 {
            if i % 2 == 0 {
                svc.update_required_repos(
                    &wid,
                    vec!["r".into()],
                    vec![], // → Drifting
                )
                .await;
            } else {
                // Successful convergence → Ready (bypasses hysteresis).
                svc.record_convergence_attempt(&wid, 1, 0, 0, 10, None)
                    .await
                    .unwrap();
            }
        }

        let transitions = svc.get_worker_transitions(&wid).await;
        assert!(transitions.len() <= MAX_TRANSITION_HISTORY);
    }

    #[tokio::test]
    async fn test_outcome_history_fifo_ordering() {
        let _guard = test_guard!();
        let svc = RepoConvergenceService::new(test_events());

        for i in 0..5u32 {
            let wid = test_worker_id(&format!("fifo{i}"));
            svc.update_required_repos(&wid, vec!["r".into()], vec![])
                .await;
            svc.record_convergence_attempt(&wid, i + 1, 0, 0, 10, None)
                .await
                .unwrap();
        }

        let outcomes = svc.get_recent_outcomes(10).await;
        assert_eq!(outcomes.len(), 5);
        // get_recent_outcomes returns reverse-chronological (newest first).
        // synced_count should be 5,4,3,2,1.
        for (idx, o) in outcomes.iter().enumerate() {
            assert_eq!(o.synced_count, 5 - (idx as u32));
        }
    }

    #[tokio::test]
    async fn test_get_recent_outcomes_limit() {
        let _guard = test_guard!();
        let svc = RepoConvergenceService::new(test_events());

        for i in 0..20u32 {
            let wid = test_worker_id(&format!("lim{i}"));
            svc.update_required_repos(&wid, vec!["r".into()], vec![])
                .await;
            svc.record_convergence_attempt(&wid, 1, 0, 0, 10, None)
                .await
                .unwrap();
        }

        let outcomes = svc.get_recent_outcomes(5).await;
        assert_eq!(outcomes.len(), 5);
    }

    // ── bd-3jjc.17: Hull, drift confidence, and budget arithmetic ────

    #[test]
    fn test_hull_single_root() {
        let _guard = test_guard!();
        let ctx =
            RepoConvergenceService::compute_required_hull(&["/data/projects/solo".to_string()]);
        assert_eq!(ctx.required_repos, vec!["/data/projects/solo"]);
        assert_eq!(ctx.active_build_count, 1);
        // Context ID is timestamp-based, so just verify the format.
        assert!(
            ctx.context_id.starts_with("hull-"),
            "context_id should start with 'hull-'"
        );
        let ts_part = &ctx.context_id["hull-".len()..];
        assert!(
            ts_part.parse::<i64>().is_ok(),
            "context_id suffix should be a numeric timestamp"
        );
    }

    #[test]
    fn test_hull_unicode_repo_names() {
        let _guard = test_guard!();
        let roots = vec![
            "/data/projects/日本語".to_string(),
            "/data/projects/über-project".to_string(),
            "/data/projects/проект".to_string(),
        ];
        let ctx = RepoConvergenceService::compute_required_hull(&roots);
        assert_eq!(ctx.required_repos.len(), 3);
    }

    #[test]
    fn test_hull_very_large_set() {
        let _guard = test_guard!();
        let roots: Vec<String> = (0..500)
            .map(|i| format!("/data/projects/repo_{i:04}"))
            .collect();
        let start = Instant::now();
        let ctx = RepoConvergenceService::compute_required_hull(&roots);
        let elapsed = start.elapsed();
        assert_eq!(ctx.required_repos.len(), 500);
        assert!(
            elapsed.as_millis() < 10,
            "hull computation took {elapsed:?}"
        );
    }

    #[test]
    fn test_drift_confidence_all_missing() {
        let _guard = test_guard!();
        let mut ws = WorkerConvergenceState::new("dc1");
        ws.required_repos = vec!["a".into(), "b".into(), "c".into()];
        ws.missing_repos = vec!["a".into(), "b".into(), "c".into()];
        assert!((ws.drift_confidence() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_drift_confidence_none_missing() {
        let _guard = test_guard!();
        let mut ws = WorkerConvergenceState::new("dc2");
        ws.required_repos = vec!["a".into(), "b".into()];
        ws.missing_repos = vec![];
        assert_eq!(ws.drift_confidence(), 0.0);
    }

    #[test]
    fn test_drift_confidence_empty_required() {
        let _guard = test_guard!();
        let ws = WorkerConvergenceState::new("dc3");
        // empty required → 0.0, not NaN from division by zero.
        assert_eq!(ws.drift_confidence(), 0.0);
    }

    #[tokio::test]
    async fn test_budget_saturating_sub_no_underflow() {
        let _guard = test_guard!();
        let svc = RepoConvergenceService::new(test_events());
        let wid = test_worker_id("bsat1");

        svc.update_required_repos(&wid, vec!["r".into()], vec![])
            .await;

        // Consume 200000ms from 120000ms budget — should saturate at 0.
        svc.record_convergence_attempt(&wid, 0, 1, 0, 200_000, Some("fail".into()))
            .await
            .unwrap();
        let ws = svc.get_worker_state(&wid).await.unwrap();
        assert_eq!(ws.time_budget_remaining_ms, 0);
    }

    #[tokio::test]
    async fn test_budget_zero_duration_attempt() {
        let _guard = test_guard!();
        let svc = RepoConvergenceService::new(test_events());
        let wid = test_worker_id("bsat2");

        svc.update_required_repos(&wid, vec!["r".into()], vec![])
            .await;

        let initial_budget = CONVERGENCE_TIME_BUDGET_SECS * 1000;
        svc.record_convergence_attempt(&wid, 0, 1, 0, 0, Some("fail".into()))
            .await
            .unwrap();
        let ws = svc.get_worker_state(&wid).await.unwrap();
        assert_eq!(ws.time_budget_remaining_ms, initial_budget);
        assert_eq!(ws.attempt_budget_remaining, MAX_CONVERGENCE_ATTEMPTS - 1);
    }

    // ── bd-3jjc.18: EventBus emission content and JSON schema ────────

    #[tokio::test]
    async fn test_event_json_schema_valid() {
        let _guard = test_guard!();
        let events = test_events();
        let mut rx = events.subscribe();
        let svc = RepoConvergenceService::new(events);
        let wid = test_worker_id("ev1");

        svc.update_required_repos(&wid, vec!["r".into()], vec![])
            .await;

        let event_json = tokio::time::timeout(Duration::from_millis(100), rx.recv())
            .await
            .expect("should receive event")
            .expect("recv should succeed");

        let parsed: serde_json::Value =
            serde_json::from_str(&event_json).expect("event should be valid JSON");
        assert!(parsed.get("event").is_some(), "missing 'event' field");
        assert!(parsed.get("data").is_some(), "missing 'data' field");
        assert!(
            parsed.get("timestamp").is_some(),
            "missing 'timestamp' field"
        );
    }

    #[tokio::test]
    async fn test_event_field_values_match_transition() {
        let _guard = test_guard!();
        let events = test_events();
        let mut rx = events.subscribe();
        let svc = RepoConvergenceService::new(events);
        let wid = test_worker_id("ev2");

        // Stale -> Drifting
        svc.update_required_repos(&wid, vec!["r".into()], vec![])
            .await;

        let event_json = tokio::time::timeout(Duration::from_millis(100), rx.recv())
            .await
            .expect("should receive event")
            .expect("recv should succeed");

        let parsed: serde_json::Value = serde_json::from_str(&event_json).expect("valid JSON");
        let data = parsed.get("data").expect("data field");
        assert_eq!(
            data.get("from_state").and_then(|v| v.as_str()),
            Some("Stale")
        );
        assert_eq!(
            data.get("to_state").and_then(|v| v.as_str()),
            Some("Drifting")
        );
        assert!(data.get("reason_code").is_some());
    }

    #[tokio::test]
    async fn test_no_event_on_noop() {
        let _guard = test_guard!();
        let events = test_events();
        let mut rx = events.subscribe();
        let svc = RepoConvergenceService::new(events);
        let wid = test_worker_id("ev3");

        // First: Stale -> Ready (all synced) — emits event.
        svc.update_required_repos(&wid, vec!["r".into()], vec!["r".into()])
            .await;
        let _ = tokio::time::timeout(Duration::from_millis(50), rx.recv()).await;

        // Second: Ready -> Ready (same repos, no change) — should NOT emit.
        svc.update_required_repos(&wid, vec!["r".into()], vec!["r".into()])
            .await;

        let result = tokio::time::timeout(Duration::from_millis(50), rx.recv()).await;
        assert!(result.is_err(), "should NOT receive event on no-op");
    }

    #[tokio::test]
    async fn test_event_name_convention() {
        let _guard = test_guard!();
        let events = test_events();
        let mut rx = events.subscribe();
        let svc = RepoConvergenceService::new(events);
        let wid = test_worker_id("ev4");

        svc.update_required_repos(&wid, vec!["r".into()], vec![])
            .await;

        let event_json = tokio::time::timeout(Duration::from_millis(100), rx.recv())
            .await
            .expect("should receive event")
            .expect("recv should succeed");

        let parsed: serde_json::Value = serde_json::from_str(&event_json).expect("valid JSON");
        assert_eq!(
            parsed.get("event").and_then(|v| v.as_str()),
            Some("repo_convergence.state_changed")
        );
    }

    // ── bd-3jjc.3: Hysteresis edge cases ────────────────────────────────

    #[tokio::test]
    async fn test_hysteresis_blocks_rapid_ready_drifting_oscillation() {
        let _guard = test_guard!();
        let svc = RepoConvergenceService::new(test_events());
        let wid = test_worker_id("hyst1");

        // Stale → Drifting (first update, no hysteresis since last_transition_at=None).
        svc.update_required_repos(&wid, vec!["r".into()], vec![])
            .await;
        assert_eq!(
            svc.get_drift_state(&wid).await,
            ConvergenceDriftState::Drifting
        );

        // Immediately try Drifting → Ready (all synced). Should be BLOCKED
        // by hysteresis since <5s has elapsed since last transition.
        svc.update_required_repos(&wid, vec!["r".into()], vec!["r".into()])
            .await;
        // State should still be Drifting because hysteresis blocked it.
        assert_eq!(
            svc.get_drift_state(&wid).await,
            ConvergenceDriftState::Drifting,
            "hysteresis should block rapid Drifting→Ready via update_required_repos"
        );
    }

    #[tokio::test]
    async fn test_hysteresis_does_not_block_convergence_actions() {
        let _guard = test_guard!();
        let svc = RepoConvergenceService::new(test_events());
        let wid = test_worker_id("hyst2");

        // Stale → Drifting.
        svc.update_required_repos(&wid, vec!["r".into()], vec![])
            .await;
        assert_eq!(
            svc.get_drift_state(&wid).await,
            ConvergenceDriftState::Drifting
        );

        // Immediately record successful convergence — should bypass hysteresis.
        let outcome = svc
            .record_convergence_attempt(&wid, 1, 0, 0, 100, None)
            .await
            .unwrap();
        assert_eq!(
            outcome.drift_state_after,
            ConvergenceDriftState::Ready,
            "record_convergence_attempt should bypass hysteresis"
        );

        // Also verify mark_converging bypasses hysteresis immediately.
        // Ready → Converging should work even though we just transitioned.
        svc.mark_converging(&wid).await;
        assert_eq!(
            svc.get_drift_state(&wid).await,
            ConvergenceDriftState::Converging,
            "mark_converging should bypass hysteresis"
        );
    }

    #[tokio::test]
    async fn test_hysteresis_timer_resets_on_transition() {
        let _guard = test_guard!();
        let svc = RepoConvergenceService::new(test_events());
        let wid = test_worker_id("hyst3");

        // Stale → Drifting.
        svc.update_required_repos(&wid, vec!["r".into()], vec![])
            .await;

        // Verify last_transition_at is now set (recently).
        let ws = svc.get_worker_state(&wid).await.unwrap();
        assert!(ws.last_transition_at.is_some());
        let first_transition = ws.last_transition_at.unwrap();

        // Bypass hysteresis via deliberate action: Drifting → Ready.
        svc.record_convergence_attempt(&wid, 1, 0, 0, 10, None)
            .await
            .unwrap();

        // Verify last_transition_at was updated.
        let ws = svc.get_worker_state(&wid).await.unwrap();
        assert!(ws.last_transition_at.unwrap() >= first_transition);
    }

    #[tokio::test]
    async fn test_hysteresis_allows_after_expiry() {
        let _guard = test_guard!();
        let svc = RepoConvergenceService::new(test_events());
        let wid = test_worker_id("hyst4");

        // Stale → Drifting.
        svc.update_required_repos(&wid, vec!["r".into()], vec![])
            .await;
        assert_eq!(
            svc.get_drift_state(&wid).await,
            ConvergenceDriftState::Drifting
        );

        // Backdate last_transition_at to simulate hysteresis expiry.
        let expired = Instant::now() - Duration::from_millis(STATE_HYSTERESIS_MS + 100);
        svc.set_last_transition_at(wid.as_str(), Some(expired))
            .await;

        // Now update_required_repos should allow Drifting → Ready.
        svc.update_required_repos(&wid, vec!["r".into()], vec!["r".into()])
            .await;
        assert_eq!(
            svc.get_drift_state(&wid).await,
            ConvergenceDriftState::Ready,
            "should transition after hysteresis expiry"
        );
    }

    // ── bd-3jjc.4: Complete state-machine transition matrix ─────────────

    #[tokio::test]
    async fn test_state_transition_stale_to_drifting() {
        let _guard = test_guard!();
        let svc = RepoConvergenceService::new(test_events());
        let wid = test_worker_id("sm1");

        // Initial state is Stale; update with missing repos → Drifting.
        svc.update_required_repos(&wid, vec!["r".into()], vec![])
            .await;
        assert_eq!(
            svc.get_drift_state(&wid).await,
            ConvergenceDriftState::Drifting
        );

        let transitions = svc.get_worker_transitions(&wid).await;
        assert_eq!(transitions.len(), 1);
        assert_eq!(transitions[0].from_state, ConvergenceDriftState::Stale);
        assert_eq!(transitions[0].to_state, ConvergenceDriftState::Drifting);
    }

    #[tokio::test]
    async fn test_state_transition_stale_to_ready() {
        let _guard = test_guard!();
        let svc = RepoConvergenceService::new(test_events());
        let wid = test_worker_id("sm2");

        // Initial state is Stale; all repos synced → Ready.
        svc.update_required_repos(&wid, vec!["r".into()], vec!["r".into()])
            .await;
        assert_eq!(
            svc.get_drift_state(&wid).await,
            ConvergenceDriftState::Ready
        );

        let transitions = svc.get_worker_transitions(&wid).await;
        assert_eq!(transitions.len(), 1);
        assert_eq!(transitions[0].from_state, ConvergenceDriftState::Stale);
        assert_eq!(transitions[0].to_state, ConvergenceDriftState::Ready);
    }

    #[tokio::test]
    async fn test_state_transition_drifting_to_converging() {
        let _guard = test_guard!();
        let svc = RepoConvergenceService::new(test_events());
        let wid = test_worker_id("sm3");

        // Stale → Drifting.
        svc.update_required_repos(&wid, vec!["r".into()], vec![])
            .await;
        // Drifting → Converging via mark_converging.
        svc.mark_converging(&wid).await;
        assert_eq!(
            svc.get_drift_state(&wid).await,
            ConvergenceDriftState::Converging
        );

        let transitions = svc.get_worker_transitions(&wid).await;
        assert_eq!(transitions.len(), 2);
        assert_eq!(transitions[1].from_state, ConvergenceDriftState::Drifting);
        assert_eq!(transitions[1].to_state, ConvergenceDriftState::Converging);
    }

    #[tokio::test]
    async fn test_state_transition_drifting_to_ready() {
        let _guard = test_guard!();
        let svc = RepoConvergenceService::new(test_events());
        let wid = test_worker_id("sm4");

        // Stale → Drifting.
        svc.update_required_repos(&wid, vec!["r".into()], vec![])
            .await;
        // Drifting → Ready via successful convergence.
        svc.record_convergence_attempt(&wid, 1, 0, 0, 10, None)
            .await
            .unwrap();
        assert_eq!(
            svc.get_drift_state(&wid).await,
            ConvergenceDriftState::Ready
        );
    }

    #[tokio::test]
    async fn test_state_transition_drifting_to_failed() {
        let _guard = test_guard!();
        let svc = RepoConvergenceService::new(test_events());
        let wid = test_worker_id("sm5");

        // Stale → Drifting.
        svc.update_required_repos(&wid, vec!["r".into()], vec![])
            .await;
        // Exhaust attempt budget → Failed.
        for _ in 0..MAX_CONVERGENCE_ATTEMPTS {
            svc.record_convergence_attempt(&wid, 0, 1, 0, 10, Some("fail".into()))
                .await
                .unwrap();
        }
        assert_eq!(
            svc.get_drift_state(&wid).await,
            ConvergenceDriftState::Failed
        );
    }

    #[tokio::test]
    async fn test_state_transition_converging_to_ready() {
        let _guard = test_guard!();
        let svc = RepoConvergenceService::new(test_events());
        let wid = test_worker_id("sm6");

        // Stale → Drifting → Converging.
        svc.update_required_repos(&wid, vec!["r".into()], vec![])
            .await;
        svc.mark_converging(&wid).await;
        assert_eq!(
            svc.get_drift_state(&wid).await,
            ConvergenceDriftState::Converging
        );

        // Converging → Ready via success.
        svc.record_convergence_attempt(&wid, 1, 0, 0, 10, None)
            .await
            .unwrap();
        assert_eq!(
            svc.get_drift_state(&wid).await,
            ConvergenceDriftState::Ready
        );
    }

    #[tokio::test]
    async fn test_state_transition_converging_to_drifting() {
        let _guard = test_guard!();
        let svc = RepoConvergenceService::new(test_events());
        let wid = test_worker_id("sm7");

        // Stale → Drifting → Converging.
        svc.update_required_repos(&wid, vec!["r".into()], vec![])
            .await;
        svc.mark_converging(&wid).await;

        // Converging → Drifting via failure with budget remaining.
        let outcome = svc
            .record_convergence_attempt(&wid, 0, 1, 0, 10, Some("fail".into()))
            .await
            .unwrap();
        assert_eq!(
            outcome.drift_state_before,
            ConvergenceDriftState::Converging
        );
        assert_eq!(outcome.drift_state_after, ConvergenceDriftState::Drifting);
    }

    #[tokio::test]
    async fn test_state_transition_converging_to_failed() {
        let _guard = test_guard!();
        let svc = RepoConvergenceService::new(test_events());
        let wid = test_worker_id("sm8");

        // Stale → Drifting → Converging.
        svc.update_required_repos(&wid, vec!["r".into()], vec![])
            .await;
        svc.mark_converging(&wid).await;

        // Exhaust attempt budget from Converging → Failed.
        for _ in 0..MAX_CONVERGENCE_ATTEMPTS {
            svc.record_convergence_attempt(&wid, 0, 1, 0, 10, Some("fail".into()))
                .await
                .unwrap();
        }
        assert_eq!(
            svc.get_drift_state(&wid).await,
            ConvergenceDriftState::Failed
        );
    }

    #[tokio::test]
    async fn test_state_transition_ready_to_drifting() {
        let _guard = test_guard!();
        let svc = RepoConvergenceService::new(test_events());
        let wid = test_worker_id("sm9");

        // Stale → Ready.
        svc.update_required_repos(&wid, vec!["r".into()], vec!["r".into()])
            .await;
        assert_eq!(
            svc.get_drift_state(&wid).await,
            ConvergenceDriftState::Ready
        );

        // Expire hysteresis so update_required_repos can transition.
        let expired = Instant::now() - Duration::from_millis(STATE_HYSTERESIS_MS + 100);
        svc.set_last_transition_at(wid.as_str(), Some(expired))
            .await;

        // Ready → Drifting (new required repo missing).
        svc.update_required_repos(&wid, vec!["r".into(), "new_repo".into()], vec!["r".into()])
            .await;
        assert_eq!(
            svc.get_drift_state(&wid).await,
            ConvergenceDriftState::Drifting
        );
    }

    #[tokio::test]
    async fn test_state_no_op_ready_stays_ready() {
        let _guard = test_guard!();
        let events = test_events();
        let mut rx = events.subscribe();
        let svc = RepoConvergenceService::new(events);
        let wid = test_worker_id("sm10");

        // Stale → Ready.
        svc.update_required_repos(&wid, vec!["r".into()], vec!["r".into()])
            .await;
        // Drain the transition event.
        let _ = tokio::time::timeout(Duration::from_millis(50), rx.recv()).await;

        // Expire hysteresis.
        let expired = Instant::now() - Duration::from_millis(STATE_HYSTERESIS_MS + 100);
        svc.set_last_transition_at(wid.as_str(), Some(expired))
            .await;

        // Same repos, same state → no-op.
        svc.update_required_repos(&wid, vec!["r".into()], vec!["r".into()])
            .await;
        assert_eq!(
            svc.get_drift_state(&wid).await,
            ConvergenceDriftState::Ready
        );

        // Verify no event emitted for no-op.
        let result = tokio::time::timeout(Duration::from_millis(50), rx.recv()).await;
        assert!(
            result.is_err(),
            "no event should be emitted for Ready→Ready no-op"
        );
    }

    #[tokio::test]
    async fn test_state_transition_failed_recovery() {
        let _guard = test_guard!();
        let svc = RepoConvergenceService::new(test_events());
        let wid = test_worker_id("sm11");

        // Drive to Failed state.
        svc.update_required_repos(&wid, vec!["r".into()], vec![])
            .await;
        for _ in 0..MAX_CONVERGENCE_ATTEMPTS {
            svc.record_convergence_attempt(&wid, 0, 1, 0, 10, Some("fail".into()))
                .await
                .unwrap();
        }
        assert_eq!(
            svc.get_drift_state(&wid).await,
            ConvergenceDriftState::Failed
        );

        // Expire hysteresis.
        let expired = Instant::now() - Duration::from_millis(STATE_HYSTERESIS_MS + 100);
        svc.set_last_transition_at(wid.as_str(), Some(expired))
            .await;

        // New repo set updates can recover from Failed.
        // Failed → Drifting (has missing repos) or Failed → Ready (all synced).
        svc.update_required_repos(
            &wid,
            vec!["new_r".into()],
            vec![], // missing
        )
        .await;
        assert_eq!(
            svc.get_drift_state(&wid).await,
            ConvergenceDriftState::Drifting,
            "should recover from Failed to Drifting when repos change"
        );
    }

    #[tokio::test]
    async fn test_staleness_transitions_any_to_stale() {
        let _guard = test_guard!();
        let svc = RepoConvergenceService::new(test_events());
        let wid = test_worker_id("sm12");

        // Start Ready.
        svc.update_required_repos(&wid, vec!["r".into()], vec!["r".into()])
            .await;
        assert_eq!(
            svc.get_drift_state(&wid).await,
            ConvergenceDriftState::Ready
        );

        // Backdate status check to simulate staleness.
        let stale_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64
            - (STALENESS_THRESHOLD_SECS as i64 * 1000 + 1000);
        svc.set_last_status_check_unix_ms(wid.as_str(), stale_time)
            .await;

        // Expire hysteresis so check_staleness can transition.
        let expired = Instant::now() - Duration::from_millis(STATE_HYSTERESIS_MS + 100);
        svc.set_last_transition_at(wid.as_str(), Some(expired))
            .await;

        svc.check_staleness().await;
        assert_eq!(
            svc.get_drift_state(&wid).await,
            ConvergenceDriftState::Stale,
            "should transition to Stale after threshold exceeded"
        );
    }

    // ── bd-3jjc.5: Concurrent access safety ─────────────────────────────

    #[tokio::test(flavor = "multi_thread")]
    async fn test_concurrent_updates_different_workers() {
        let _guard = test_guard!();
        let svc = std::sync::Arc::new(RepoConvergenceService::new(test_events()));

        let mut handles = Vec::new();
        for i in 0..10u32 {
            let svc = svc.clone();
            handles.push(tokio::spawn(async move {
                let wid = WorkerId::new(format!("conc_w{i}"));
                svc.update_required_repos(
                    &wid,
                    vec!["r".into()],
                    vec![], // all drifting
                )
                .await;
                svc.record_convergence_attempt(&wid, 1, 0, 0, 10, None)
                    .await
                    .unwrap();
            }));
        }
        for h in handles {
            h.await.unwrap();
        }

        let all = svc.get_all_worker_states().await;
        assert_eq!(all.len(), 10, "all 10 workers should be tracked");
        for ws in &all {
            assert_eq!(
                ws.current_state,
                ConvergenceDriftState::Ready,
                "worker {} should be Ready",
                ws.worker_id
            );
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_concurrent_read_write_same_worker() {
        let _guard = test_guard!();
        let svc = std::sync::Arc::new(RepoConvergenceService::new(test_events()));
        let wid = test_worker_id("conc_rw");

        svc.update_required_repos(&wid, vec!["r".into()], vec![])
            .await;

        let mut handles = Vec::new();
        // Spawn concurrent readers and writers.
        for i in 0..20u32 {
            let svc = svc.clone();
            let wid = wid.clone();
            if i % 2 == 0 {
                // Writer.
                handles.push(tokio::spawn(async move {
                    svc.record_convergence_attempt(&wid, 1, 0, 0, 1, None)
                        .await
                        .ok();
                }));
            } else {
                // Reader.
                handles.push(tokio::spawn(async move {
                    let _ = svc.get_drift_state(&wid).await;
                    let _ = svc.get_worker_state(&wid).await;
                }));
            }
        }
        for h in handles {
            h.await.unwrap();
        }
        // No panics = success. Verify state is valid.
        let state = svc.get_drift_state(&wid).await;
        assert!(
            matches!(
                state,
                ConvergenceDriftState::Ready
                    | ConvergenceDriftState::Drifting
                    | ConvergenceDriftState::Stale
            ),
            "state should be valid after concurrent access"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_concurrent_state_snapshots() {
        let _guard = test_guard!();
        let svc = std::sync::Arc::new(RepoConvergenceService::new(test_events()));

        // Pre-populate 5 workers.
        for i in 0..5u32 {
            let wid = test_worker_id(&format!("snap{i}"));
            svc.update_required_repos(&wid, vec!["r".into()], vec![])
                .await;
        }

        let mut handles = Vec::new();
        // Concurrent mutations + snapshot reads.
        for i in 0..10u32 {
            let svc = svc.clone();
            handles.push(tokio::spawn(async move {
                if i < 5 {
                    // Mutate.
                    let wid = WorkerId::new(format!("snap{i}"));
                    svc.record_convergence_attempt(&wid, 1, 0, 0, 1, None)
                        .await
                        .ok();
                } else {
                    // Snapshot read.
                    let all = svc.get_all_worker_states().await;
                    // Snapshot should contain between 0 and 5 workers.
                    assert!(all.len() <= 5, "snapshot has too many workers");
                }
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_high_contention_outcome_storage() {
        let _guard = test_guard!();
        let svc = std::sync::Arc::new(RepoConvergenceService::new(test_events()));

        // Pre-create workers.
        for i in 0..50u32 {
            let wid = test_worker_id(&format!("hc{i}"));
            svc.update_required_repos(&wid, vec!["r".into()], vec![])
                .await;
        }

        let mut handles = Vec::new();
        for i in 0..50u32 {
            let svc = svc.clone();
            handles.push(tokio::spawn(async move {
                let wid = WorkerId::new(format!("hc{i}"));
                svc.record_convergence_attempt(&wid, 1, 0, 0, 1, None)
                    .await
                    .unwrap();
            }));
        }
        for h in handles {
            h.await.unwrap();
        }

        let outcomes = svc.get_recent_outcomes(100).await;
        assert_eq!(outcomes.len(), 50, "all 50 outcomes should be stored");
    }

    // ── bd-3jjc.11: E2E full lifecycle integration test ─────────────────

    #[tokio::test(flavor = "multi_thread")]
    async fn test_e2e_full_lifecycle() {
        let _guard = test_guard!();
        let events = test_events();
        let mut rx = events.subscribe();
        let svc = RepoConvergenceService::new(events);

        // Step 1-3: Register workers w1 (Ready), w2 (Drifting), w3 (Drifting).
        svc.update_required_repos(
            &test_worker_id("w1"),
            vec!["repo_a".into()],
            vec!["repo_a".into()], // all synced → Ready
        )
        .await;
        svc.update_required_repos(
            &test_worker_id("w2"),
            vec!["repo_a".into(), "repo_b".into()],
            vec!["repo_a".into()], // missing repo_b → Drifting
        )
        .await;
        svc.update_required_repos(
            &test_worker_id("w3"),
            vec!["repo_c".into()],
            vec![], // missing repo_c → Drifting
        )
        .await;

        // Step 4: Verify initial states.
        assert_eq!(
            svc.get_drift_state(&test_worker_id("w1")).await,
            ConvergenceDriftState::Ready
        );
        assert_eq!(
            svc.get_drift_state(&test_worker_id("w2")).await,
            ConvergenceDriftState::Drifting
        );
        assert_eq!(
            svc.get_drift_state(&test_worker_id("w3")).await,
            ConvergenceDriftState::Drifting
        );

        // Step 5: Mark drifting workers converging.
        svc.mark_converging(&test_worker_id("w2")).await;
        svc.mark_converging(&test_worker_id("w3")).await;
        assert_eq!(
            svc.get_drift_state(&test_worker_id("w2")).await,
            ConvergenceDriftState::Converging
        );
        assert_eq!(
            svc.get_drift_state(&test_worker_id("w3")).await,
            ConvergenceDriftState::Converging
        );

        // Step 6: w2 succeeds, w3 fails with budget remaining.
        let w2_outcome = svc
            .record_convergence_attempt(&test_worker_id("w2"), 2, 0, 0, 100, None)
            .await
            .unwrap();
        assert_eq!(w2_outcome.drift_state_after, ConvergenceDriftState::Ready);

        let w3_outcome = svc
            .record_convergence_attempt(
                &test_worker_id("w3"),
                0,
                1,
                0,
                50,
                Some("ssh timeout".into()),
            )
            .await
            .unwrap();
        assert_eq!(
            w3_outcome.drift_state_after,
            ConvergenceDriftState::Drifting
        );

        // Step 7: w3 second attempt succeeds.
        let w3_outcome_2 = svc
            .record_convergence_attempt(&test_worker_id("w3"), 1, 0, 0, 80, None)
            .await
            .unwrap();
        assert_eq!(w3_outcome_2.drift_state_after, ConvergenceDriftState::Ready);

        // Step 8: All Ready.
        let all_states = svc.get_all_worker_states().await;
        assert_eq!(all_states.len(), 3);
        for ws in &all_states {
            assert_eq!(
                ws.current_state,
                ConvergenceDriftState::Ready,
                "worker {} should be Ready",
                ws.worker_id
            );
        }

        // Step 9: Verify events were emitted (drain channel).
        let mut event_count = 0;
        while tokio::time::timeout(Duration::from_millis(50), rx.recv())
            .await
            .is_ok()
        {
            event_count += 1;
        }
        // Expected transitions: w1(Stale→Ready) + w2(Stale→Drifting, Drifting→Converging,
        // Converging→Ready) + w3(Stale→Drifting, Drifting→Converging, Converging→Drifting,
        // Drifting→Ready) = 8 state_changed events + 3 outcome events = 11 total minimum.
        assert!(
            event_count >= 8,
            "expected at least 8 events, got {event_count}"
        );

        // Step 10: Outcomes.
        let outcomes = svc.get_recent_outcomes(10).await;
        assert_eq!(outcomes.len(), 3, "3 convergence attempts recorded");

        // Step 11: Transition history for w3 (most complex path).
        let w3_transitions = svc.get_worker_transitions(&test_worker_id("w3")).await;
        assert!(
            w3_transitions.len() >= 4,
            "w3 should have at least 4 transitions: Stale→Drifting, Drifting→Converging, Converging→Drifting, Drifting→Ready"
        );
    }

    // ── bd-3jjc.16: E2E staleness detection and recovery ────────────────

    #[tokio::test]
    async fn test_e2e_staleness_detection_and_recovery() {
        let _guard = test_guard!();
        let svc = RepoConvergenceService::new(test_events());
        let wid = test_worker_id("stale_w1");

        // Step 1-2: Register Ready worker.
        svc.update_required_repos(&wid, vec!["repo_a".into()], vec!["repo_a".into()])
            .await;
        assert_eq!(
            svc.get_drift_state(&wid).await,
            ConvergenceDriftState::Ready
        );

        // Step 3: Backdate last_status_check_unix_ms to >300s ago.
        let stale_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64
            - (STALENESS_THRESHOLD_SECS as i64 * 1000 + 1000);
        svc.set_last_status_check_unix_ms(wid.as_str(), stale_ms)
            .await;

        // Also expire hysteresis so check_staleness can transition.
        let expired = Instant::now() - Duration::from_millis(STATE_HYSTERESIS_MS + 100);
        svc.set_last_transition_at(wid.as_str(), Some(expired))
            .await;

        // Step 4-5: check_staleness → Stale.
        svc.check_staleness().await;
        assert_eq!(
            svc.get_drift_state(&wid).await,
            ConvergenceDriftState::Stale,
            "worker should be Stale after staleness check"
        );

        // Step 6-7: Expire hysteresis again (check_staleness just set it).
        let expired2 = Instant::now() - Duration::from_millis(STATE_HYSTERESIS_MS + 100);
        svc.set_last_transition_at(wid.as_str(), Some(expired2))
            .await;

        // Refresh via update_required_repos → Ready (all synced).
        svc.update_required_repos(&wid, vec!["repo_a".into()], vec!["repo_a".into()])
            .await;
        assert_eq!(
            svc.get_drift_state(&wid).await,
            ConvergenceDriftState::Ready,
            "worker should recover to Ready after refresh"
        );

        // Step 8: Verify transition history: Ready → Stale → Ready.
        let transitions = svc.get_worker_transitions(&wid).await;
        assert!(transitions.len() >= 3);
        // Find the Ready→Stale→Ready sequence.
        let stale_idx = transitions
            .iter()
            .position(|t| t.to_state == ConvergenceDriftState::Stale)
            .expect("should have Stale transition");
        assert_eq!(
            transitions[stale_idx].from_state,
            ConvergenceDriftState::Ready
        );
        assert!(stale_idx + 1 < transitions.len());
        assert_eq!(
            transitions[stale_idx + 1].from_state,
            ConvergenceDriftState::Stale
        );
        assert_eq!(
            transitions[stale_idx + 1].to_state,
            ConvergenceDriftState::Ready
        );
    }

    // ── bd-3jjc.14: E2E concurrent convergence stress test ──────────────

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_e2e_concurrent_convergence_stress() {
        let _guard = test_guard!();
        let events = test_events();
        let mut rx = events.subscribe();
        let svc = std::sync::Arc::new(RepoConvergenceService::new(events));

        // Step 1-2: Spawn 20 tasks.
        let mut handles = Vec::new();
        for i in 0..20u32 {
            let svc = svc.clone();
            handles.push(tokio::spawn(async move {
                let wid = WorkerId::new(format!("stress_{i:02}"));
                // Register with missing repos.
                svc.update_required_repos(
                    &wid,
                    vec!["repo_a".into(), "repo_b".into()],
                    vec!["repo_a".into()], // missing repo_b
                )
                .await;

                // Mark converging.
                svc.mark_converging(&wid).await;

                // Even workers succeed, odd workers fail (with budget remaining).
                if i % 2 == 0 {
                    svc.record_convergence_attempt(&wid, 2, 0, 0, 10, None)
                        .await
                        .unwrap();
                } else {
                    svc.record_convergence_attempt(&wid, 0, 1, 0, 10, Some("fail".into()))
                        .await
                        .unwrap();
                }
            }));
        }

        // Step 3: Await all.
        for h in handles {
            h.await.expect("task should not panic");
        }

        // Step 4a-b: Verify 20 workers tracked.
        let all = svc.get_all_worker_states().await;
        assert_eq!(all.len(), 20, "all 20 workers should be tracked");

        // Step 4c: Even → Ready, Odd → Drifting.
        for ws in &all {
            let idx: u32 = ws
                .worker_id
                .strip_prefix("stress_")
                .unwrap()
                .parse()
                .unwrap();
            let expected = if idx.is_multiple_of(2) {
                ConvergenceDriftState::Ready
            } else {
                ConvergenceDriftState::Drifting
            };
            assert_eq!(
                ws.current_state, expected,
                "worker {} (idx={}) expected {:?}, got {:?}",
                ws.worker_id, idx, expected, ws.current_state
            );
        }

        // Step 4d: 20 outcomes.
        let outcomes = svc.get_recent_outcomes(50).await;
        assert_eq!(outcomes.len(), 20, "should have 20 outcomes");

        // Step 5: Verify events were emitted.
        let mut event_count = 0;
        while tokio::time::timeout(Duration::from_millis(50), rx.recv())
            .await
            .is_ok()
        {
            event_count += 1;
        }
        // Each worker has at least 3 transitions: Stale→Drifting, Drifting→Converging, then result.
        assert!(
            event_count >= 40,
            "expected at least 40 events (20 workers * 2+ transitions + 20 outcomes), got {event_count}"
        );
    }

    // ── bd-3jjc.12: E2E budget exhaustion and recovery ──────────────────

    #[tokio::test]
    async fn test_e2e_budget_exhaustion_and_recovery() {
        let _guard = test_guard!();
        let svc = RepoConvergenceService::new(test_events());
        let wid = test_worker_id("budget_e2e");

        // Step 1: Register with missing repos → Drifting.
        svc.update_required_repos(
            &wid,
            vec!["repo_a".into()],
            vec![], // missing
        )
        .await;
        assert_eq!(
            svc.get_drift_state(&wid).await,
            ConvergenceDriftState::Drifting
        );

        // Steps 2-7: Exhaust attempt budget via mark_converging + fail cycle.
        for attempt in 1..=MAX_CONVERGENCE_ATTEMPTS {
            svc.mark_converging(&wid).await;
            let outcome = svc
                .record_convergence_attempt(
                    &wid,
                    0,
                    1,
                    0,
                    40_000,
                    Some(format!("attempt {attempt} failed")),
                )
                .await
                .unwrap();

            if attempt < MAX_CONVERGENCE_ATTEMPTS {
                assert_eq!(
                    outcome.drift_state_after,
                    ConvergenceDriftState::Drifting,
                    "attempt {attempt}: should stay Drifting"
                );
            } else {
                assert_eq!(
                    outcome.drift_state_after,
                    ConvergenceDriftState::Failed,
                    "attempt {attempt}: should transition to Failed"
                );
            }
        }

        // Verify Failed + budgets exhausted.
        assert_eq!(
            svc.get_drift_state(&wid).await,
            ConvergenceDriftState::Failed
        );
        let ws = svc.get_worker_state(&wid).await.unwrap();
        assert_eq!(ws.attempt_budget_remaining, 0);

        // Step 8: Update with CHANGED repo set to recover.
        // Expire hysteresis first.
        let expired = Instant::now() - Duration::from_millis(STATE_HYSTERESIS_MS + 100);
        svc.set_last_transition_at(wid.as_str(), Some(expired))
            .await;

        svc.update_required_repos(
            &wid,
            vec!["new_repo".into()],
            vec![], // missing
        )
        .await;

        // Step 9: Should recover to Drifting (not stay Failed).
        assert_eq!(
            svc.get_drift_state(&wid).await,
            ConvergenceDriftState::Drifting,
            "should recover from Failed to Drifting with new repo set"
        );

        // Step 10: Converge successfully.
        svc.mark_converging(&wid).await;
        svc.record_convergence_attempt(&wid, 1, 0, 0, 10, None)
            .await
            .unwrap();

        // Step 11: Verify Ready + budgets reset.
        assert_eq!(
            svc.get_drift_state(&wid).await,
            ConvergenceDriftState::Ready
        );
        let ws = svc.get_worker_state(&wid).await.unwrap();
        assert_eq!(ws.attempt_budget_remaining, MAX_CONVERGENCE_ATTEMPTS);
    }

    // ── bd-vvmd.3.8 AC1: Adapter Failure Taxonomy Tests ───────────────

    /// AC1: Timeout scenario — adapter exceeds time budget across multiple
    /// attempts, driving the worker to Failed state.
    #[tokio::test]
    async fn test_adapter_timeout_exhausts_time_budget() {
        let _guard = test_guard!();
        let svc = RepoConvergenceService::new(test_events());
        let wid = test_worker_id("w-timeout");

        // Put worker into Drifting state.
        svc.update_required_repos(&wid, vec!["repo-a".into()], vec![])
            .await;
        assert_eq!(
            svc.get_drift_state(&wid).await,
            ConvergenceDriftState::Drifting
        );

        // Each attempt consumes a huge chunk of time budget (simulating slow timeouts).
        // Default budget = 120_000ms, we consume 50_000ms each attempt.
        for i in 0..3 {
            let result = svc
                .record_convergence_attempt(
                    &wid,
                    0,
                    1,
                    0,
                    50_000, // 50s per timeout
                    Some(format!("rsync_timeout_attempt_{}", i)),
                )
                .await;
            assert!(result.is_ok(), "Attempt should return Ok even on failure");
            let outcome = result.unwrap();
            assert_eq!(outcome.failed_count, 1);
            assert!(outcome.failure.is_some());
        }

        // After 3 attempts × 50s = 150s consumed (budget was 120s), should be Failed.
        assert_eq!(
            svc.get_drift_state(&wid).await,
            ConvergenceDriftState::Failed,
            "Worker should be Failed after time budget exhausted"
        );
        let ws = svc.get_worker_state(&wid).await.unwrap();
        assert_eq!(ws.time_budget_remaining_ms, 0);
    }

    /// AC1: Partial sync results — some repos succeed, some fail.
    /// Worker stays Drifting when budget remains.
    #[tokio::test]
    async fn test_adapter_partial_result_mixed_success_failure() {
        let _guard = test_guard!();
        let svc = RepoConvergenceService::new(test_events());
        let wid = test_worker_id("w-partial");

        svc.update_required_repos(
            &wid,
            vec!["repo-a".into(), "repo-b".into(), "repo-c".into()],
            vec![],
        )
        .await;
        assert_eq!(
            svc.get_drift_state(&wid).await,
            ConvergenceDriftState::Drifting
        );

        // Adapter returns: 2 synced, 1 auth denied.
        let outcome = svc
            .record_convergence_attempt(
                &wid, 2,     // synced
                1,     // failed
                0,     // skipped
                5_000, // 5s
                None,  // No error string → partial path based on failed_count > 0
            )
            .await
            .unwrap();

        assert_eq!(outcome.synced_count, 2);
        assert_eq!(outcome.failed_count, 1);
        assert_eq!(outcome.reason_code, "partial_failure_1_repos");
        assert_eq!(
            svc.get_drift_state(&wid).await,
            ConvergenceDriftState::Drifting,
            "Partial failure with budget remaining should stay Drifting"
        );

        // Budget should still be available.
        assert!(svc.has_budget(&wid).await);
    }

    /// AC1: Auth failure classification — failure string is preserved in outcome
    /// and worker transitions correctly.
    #[tokio::test]
    async fn test_adapter_auth_failure_classification() {
        let _guard = test_guard!();
        let svc = RepoConvergenceService::new(test_events());
        let wid = test_worker_id("w-auth");

        svc.update_required_repos(&wid, vec!["repo-a".into()], vec![])
            .await;

        let outcome = svc
            .record_convergence_attempt(
                &wid,
                0,
                1,
                0,
                2_000,
                Some("auth_credential_expired: token TTL exceeded".into()),
            )
            .await
            .unwrap();

        assert_eq!(
            outcome.failure.as_deref(),
            Some("auth_credential_expired: token TTL exceeded")
        );
        assert_eq!(outcome.reason_code, "sync_failed_retryable");
        assert_eq!(
            svc.get_drift_state(&wid).await,
            ConvergenceDriftState::Drifting,
            "Auth failure with remaining budget should stay Drifting"
        );
    }

    /// AC1: Network failure (SSH unreachable) — retryable failure, stays Drifting.
    #[tokio::test]
    async fn test_adapter_network_failure_ssh_unreachable() {
        let _guard = test_guard!();
        let svc = RepoConvergenceService::new(test_events());
        let wid = test_worker_id("w-net");

        svc.update_required_repos(&wid, vec!["repo-a".into()], vec![])
            .await;

        let outcome = svc
            .record_convergence_attempt(
                &wid,
                0,
                1,
                0,
                1_000,
                Some("connection_refused: ssh port 22 unreachable".into()),
            )
            .await
            .unwrap();

        assert!(outcome.failure.is_some());
        assert_eq!(outcome.reason_code, "sync_failed_retryable");
        assert_eq!(
            svc.get_drift_state(&wid).await,
            ConvergenceDriftState::Drifting
        );
        assert!(
            svc.has_budget(&wid).await,
            "Network failure is retryable, budget should remain"
        );
    }

    /// AC1: Adapter unavailable (binary not found) — repeated failures exhaust
    /// attempt budget, driving to Failed.
    #[tokio::test]
    async fn test_adapter_unavailable_exhausts_attempt_budget() {
        let _guard = test_guard!();
        let svc = RepoConvergenceService::new(test_events());
        let wid = test_worker_id("w-nobin");

        svc.update_required_repos(&wid, vec!["repo-a".into()], vec![])
            .await;

        // Exhaust all 3 attempts with "command not found" failures.
        for _ in 0..MAX_CONVERGENCE_ATTEMPTS {
            let _ = svc
                .record_convergence_attempt(
                    &wid,
                    0,
                    1,
                    0,
                    100,
                    Some("ru: command not found (exit 127)".into()),
                )
                .await;
        }

        assert_eq!(
            svc.get_drift_state(&wid).await,
            ConvergenceDriftState::Failed,
            "Should be Failed after exhausting attempt budget"
        );
        let ws = svc.get_worker_state(&wid).await.unwrap();
        assert_eq!(ws.attempt_budget_remaining, 0);
        assert!(!svc.has_budget(&wid).await, "Budget should be exhausted");
    }

    /// AC1: Exit code mapping — verify outcomes track failure reasons correctly
    /// when different failure strings indicate different root causes.
    #[tokio::test]
    async fn test_adapter_failure_reason_codes_differentiated() {
        let _guard = test_guard!();
        let svc = RepoConvergenceService::new(test_events());
        let wid = test_worker_id("w-codes");

        svc.update_required_repos(&wid, vec!["repo-a".into()], vec![])
            .await;

        // Attempt 1: auth failure.
        let o1 = svc
            .record_convergence_attempt(&wid, 0, 1, 0, 1_000, Some("auth_failure".into()))
            .await
            .unwrap();
        assert_eq!(o1.reason_code, "sync_failed_retryable");

        // Attempt 2: timeout.
        let o2 = svc
            .record_convergence_attempt(&wid, 0, 1, 0, 30_000, Some("timeout".into()))
            .await
            .unwrap();
        assert_eq!(o2.reason_code, "sync_failed_retryable");

        // Attempt 3: final failure (budget exhausted).
        let o3 = svc
            .record_convergence_attempt(&wid, 0, 1, 0, 1_000, Some("connection_refused".into()))
            .await
            .unwrap();
        assert_eq!(o3.reason_code, "attempt_budget_exhausted");

        // All outcomes are stored.
        let outcomes = svc.get_recent_outcomes(10).await;
        assert_eq!(outcomes.len(), 3);
        // Most recent first.
        assert_eq!(outcomes[0].failure.as_deref(), Some("connection_refused"));
        assert_eq!(outcomes[1].failure.as_deref(), Some("timeout"));
        assert_eq!(outcomes[2].failure.as_deref(), Some("auth_failure"));
    }

    /// AC1: Zero-duration timeout attempt shouldn't consume time budget but
    /// still consumes attempt budget.
    #[tokio::test]
    async fn test_adapter_zero_duration_failure_consumes_only_attempt_budget() {
        let _guard = test_guard!();
        let svc = RepoConvergenceService::new(test_events());
        let wid = test_worker_id("w-zero");

        svc.update_required_repos(&wid, vec!["repo-a".into()], vec![])
            .await;

        let ws_before = svc.get_worker_state(&wid).await.unwrap();
        let time_before = ws_before.time_budget_remaining_ms;

        let _ = svc
            .record_convergence_attempt(
                &wid,
                0,
                1,
                0,
                0, // zero duration
                Some("instant_reject".into()),
            )
            .await;

        let ws_after = svc.get_worker_state(&wid).await.unwrap();
        assert_eq!(
            ws_after.time_budget_remaining_ms, time_before,
            "Zero-duration attempt should not consume time budget"
        );
        assert_eq!(
            ws_after.attempt_budget_remaining,
            MAX_CONVERGENCE_ATTEMPTS - 1,
            "Should consume one attempt"
        );
    }

    /// AC1: Skipped repos are tracked correctly in outcome.
    #[tokio::test]
    async fn test_adapter_skipped_repos_tracked_in_outcome() {
        let _guard = test_guard!();
        let svc = RepoConvergenceService::new(test_events());
        let wid = test_worker_id("w-skip");

        svc.update_required_repos(&wid, vec!["repo-a".into(), "repo-b".into()], vec![])
            .await;

        let outcome = svc
            .record_convergence_attempt(&wid, 1, 0, 1, 3_000, None)
            .await
            .unwrap();

        assert_eq!(outcome.synced_count, 1);
        assert_eq!(outcome.skipped_count, 1);
        assert_eq!(outcome.failed_count, 0);
        assert_eq!(outcome.reason_code, "sync_complete");
        assert_eq!(
            svc.get_drift_state(&wid).await,
            ConvergenceDriftState::Ready,
            "No failures means Ready"
        );
    }

    // ── bd-vvmd.3.8 AC4: Fail-Open Semantics Tests ────────────────────

    /// AC4: Failed convergence does NOT prevent querying state — fail-open
    /// means callers can still check and decide.
    #[tokio::test]
    async fn test_fail_open_failed_state_still_queryable() {
        let _guard = test_guard!();
        let svc = RepoConvergenceService::new(test_events());
        let wid = test_worker_id("w-failq");

        svc.update_required_repos(&wid, vec!["repo-a".into()], vec![])
            .await;

        // Exhaust budgets.
        for _ in 0..MAX_CONVERGENCE_ATTEMPTS {
            let _ = svc
                .record_convergence_attempt(&wid, 0, 1, 0, 10_000, Some("fail".into()))
                .await;
        }

        assert_eq!(
            svc.get_drift_state(&wid).await,
            ConvergenceDriftState::Failed
        );

        // State is still fully queryable.
        let ws = svc.get_worker_state(&wid).await;
        assert!(ws.is_some(), "Failed worker state must still be queryable");
        let ws = ws.unwrap();
        assert_eq!(ws.current_state, ConvergenceDriftState::Failed);
        assert_eq!(ws.attempt_budget_remaining, 0);
        assert!(!ws.missing_repos.is_empty());
    }

    /// AC4: Stale worker (no convergence data) returns Stale, which callers
    /// interpret as fail-open.
    #[tokio::test]
    async fn test_fail_open_unknown_worker_returns_stale() {
        let _guard = test_guard!();
        let svc = RepoConvergenceService::new(test_events());
        let wid = test_worker_id("w-unknown");

        // Never registered — should return Stale.
        assert_eq!(
            svc.get_drift_state(&wid).await,
            ConvergenceDriftState::Stale,
            "Unknown worker should return Stale (fail-open)"
        );

        // get_worker_state returns None for unknown workers.
        assert!(svc.get_worker_state(&wid).await.is_none());

        // has_budget returns true for unknown workers (budgets not consumed).
        assert!(
            svc.has_budget(&wid).await,
            "Unknown worker should have budget (never consumed)"
        );
    }

    /// AC4: Failed worker can recover when repo set changes — budgets reset
    /// on transition to Ready.
    #[tokio::test]
    async fn test_fail_open_failed_worker_recovers_on_repo_change() {
        let _guard = test_guard!();
        let svc = RepoConvergenceService::new(test_events());
        let wid = test_worker_id("w-recover");

        svc.update_required_repos(&wid, vec!["repo-a".into()], vec![])
            .await;

        // Drive to Failed.
        for _ in 0..MAX_CONVERGENCE_ATTEMPTS {
            let _ = svc
                .record_convergence_attempt(&wid, 0, 1, 0, 1_000, Some("fail".into()))
                .await;
        }
        assert_eq!(
            svc.get_drift_state(&wid).await,
            ConvergenceDriftState::Failed
        );

        // Expire hysteresis.
        let expired = Instant::now() - Duration::from_millis(STATE_HYSTERESIS_MS + 100);
        svc.set_last_transition_at(wid.as_str(), Some(expired))
            .await;

        // Update with all repos synced → Ready.
        svc.update_required_repos(&wid, vec!["repo-b".into()], vec!["repo-b".into()])
            .await;

        assert_eq!(
            svc.get_drift_state(&wid).await,
            ConvergenceDriftState::Ready,
            "Failed worker should recover to Ready when repos change"
        );

        // Budgets should be reset.
        let ws = svc.get_worker_state(&wid).await.unwrap();
        assert_eq!(ws.attempt_budget_remaining, MAX_CONVERGENCE_ATTEMPTS);
        assert_eq!(
            ws.time_budget_remaining_ms,
            CONVERGENCE_TIME_BUDGET_SECS * 1000
        );
    }

    /// AC4: Stale detection + recovery — Ready worker goes Stale after
    /// staleness threshold, then recovers on status update.
    #[tokio::test]
    async fn test_fail_open_stale_detection_and_recovery() {
        let _guard = test_guard!();
        let svc = RepoConvergenceService::new(test_events());
        let wid = test_worker_id("w-stale-rec");

        // Set up Ready worker.
        svc.update_required_repos(&wid, vec!["repo-a".into()], vec!["repo-a".into()])
            .await;
        assert_eq!(
            svc.get_drift_state(&wid).await,
            ConvergenceDriftState::Ready
        );

        // Backdate last status check to trigger staleness.
        let old_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64
            - ((STALENESS_THRESHOLD_SECS as i64 + 60) * 1000);
        svc.set_last_status_check_unix_ms(wid.as_str(), old_ms)
            .await;

        // Expire hysteresis so check_staleness can transition.
        let expired = Instant::now() - Duration::from_millis(STATE_HYSTERESIS_MS + 100);
        svc.set_last_transition_at(wid.as_str(), Some(expired))
            .await;

        svc.check_staleness().await;
        assert_eq!(
            svc.get_drift_state(&wid).await,
            ConvergenceDriftState::Stale,
            "Worker should be Stale after staleness threshold"
        );

        // Expire hysteresis again for recovery.
        svc.set_last_transition_at(wid.as_str(), Some(expired))
            .await;

        // Refresh status → Ready.
        svc.update_required_repos(&wid, vec!["repo-a".into()], vec!["repo-a".into()])
            .await;
        assert_eq!(
            svc.get_drift_state(&wid).await,
            ConvergenceDriftState::Ready,
            "Stale worker should recover to Ready on fresh status update"
        );
    }

    // ── bd-vvmd.3.8 AC5: Structured Log / Event Verification Tests ────

    /// AC5: Verify transition events contain scenario-identifying fields.
    #[tokio::test]
    async fn test_structured_event_contains_scenario_fields() {
        let _guard = test_guard!();
        let events = test_events();
        let mut rx = events.subscribe();
        let svc = RepoConvergenceService::new(events);
        let wid = test_worker_id("w-log");

        // Trigger a state transition.
        svc.update_required_repos(&wid, vec!["repo-a".into()], vec![])
            .await;

        // Read emitted event.
        let msg = rx.try_recv().expect("Should receive state_changed event");
        let parsed: serde_json::Value =
            serde_json::from_str(&msg).expect("Event should be valid JSON");

        // Verify required structured fields.
        assert_eq!(parsed["event"], "repo_convergence.state_changed");
        let data = &parsed["data"];
        assert_eq!(data["from_state"], "Stale", "Must include from_state");
        assert_eq!(data["to_state"], "Drifting", "Must include to_state");
        assert!(data["reason_code"].is_string(), "Must include reason_code");
        assert!(
            data["transitioned_at_unix_ms"].is_number(),
            "Must include timestamp"
        );
    }

    /// AC5: Convergence outcome events include decision-relevant fields.
    #[tokio::test]
    async fn test_structured_outcome_event_contains_decision_fields() {
        let _guard = test_guard!();
        let events = test_events();
        let mut rx = events.subscribe();
        let svc = RepoConvergenceService::new(events);
        let wid = test_worker_id("w-outcome-log");

        svc.update_required_repos(&wid, vec!["repo-a".into()], vec![])
            .await;
        // Drain the state_changed event.
        let _ = rx.try_recv();

        // Record a convergence attempt.
        svc.record_convergence_attempt(&wid, 0, 1, 0, 5_000, Some("ssh_timeout".into()))
            .await
            .unwrap();

        // There should be a state_changed event (Drifting→Drifting is no-op, so
        // no transition event), but there IS an outcome event.
        let msg = rx.try_recv().expect("Should receive outcome event");
        let parsed: serde_json::Value =
            serde_json::from_str(&msg).expect("Event should be valid JSON");

        assert_eq!(parsed["event"], "repo_convergence.outcome");
        let data = &parsed["data"];
        assert_eq!(data["worker_id"], "w-outcome-log");
        assert_eq!(data["synced_count"], 0);
        assert_eq!(data["failed_count"], 1);
        assert_eq!(data["duration_ms"], 5_000);
        assert_eq!(data["reason_code"], "sync_failed_retryable");
        assert_eq!(data["failure"], "ssh_timeout");
        assert!(data["emitted_at_unix_ms"].is_number());
    }

    /// AC5: Verify transition history captures scenario-level audit trail.
    #[tokio::test]
    async fn test_structured_transition_history_audit_trail() {
        let _guard = test_guard!();
        let svc = RepoConvergenceService::new(test_events());
        let wid = test_worker_id("w-audit");

        // Drive through: Stale→Drifting→Converging→Ready.
        svc.update_required_repos(&wid, vec!["repo-a".into()], vec![])
            .await;
        svc.mark_converging(&wid).await;
        svc.record_convergence_attempt(&wid, 1, 0, 0, 1_000, None)
            .await
            .unwrap();

        let transitions = svc.get_worker_transitions(&wid).await;
        assert_eq!(transitions.len(), 3, "Should have 3 transitions");

        // Transition 1: Stale→Drifting.
        assert_eq!(transitions[0].from_state, ConvergenceDriftState::Stale);
        assert_eq!(transitions[0].to_state, ConvergenceDriftState::Drifting);
        assert_eq!(transitions[0].reason_code, "missing_1_repos");

        // Transition 2: Drifting→Converging.
        assert_eq!(transitions[1].from_state, ConvergenceDriftState::Drifting);
        assert_eq!(transitions[1].to_state, ConvergenceDriftState::Converging);
        assert_eq!(transitions[1].reason_code, "sync_started");

        // Transition 3: Converging→Ready.
        assert_eq!(transitions[2].from_state, ConvergenceDriftState::Converging);
        assert_eq!(transitions[2].to_state, ConvergenceDriftState::Ready);
        assert_eq!(transitions[2].reason_code, "sync_complete");

        // All transitions have valid timestamps.
        for t in &transitions {
            assert!(t.transitioned_at_unix_ms > 0, "Timestamp must be set");
        }
    }

    /// AC5: Failed convergence outcome includes remediation-relevant
    /// information (budget exhaustion reason).
    #[tokio::test]
    async fn test_structured_failed_outcome_includes_remediation_info() {
        let _guard = test_guard!();
        let events = test_events();
        let mut rx = events.subscribe();
        let svc = RepoConvergenceService::new(events);
        let wid = test_worker_id("w-remed");

        svc.update_required_repos(&wid, vec!["repo-a".into()], vec![])
            .await;
        // Drain state_changed event.
        let _ = rx.try_recv();

        // Exhaust attempt budget.
        for _ in 0..MAX_CONVERGENCE_ATTEMPTS {
            let _ = svc
                .record_convergence_attempt(&wid, 0, 1, 0, 1_000, Some("sync_error".into()))
                .await;
        }

        // The last outcome should indicate budget exhaustion.
        let outcomes = svc.get_recent_outcomes(1).await;
        assert_eq!(outcomes.len(), 1);
        let last = &outcomes[0];
        assert_eq!(last.reason_code, "attempt_budget_exhausted");
        assert_eq!(last.drift_state_after, ConvergenceDriftState::Failed);
        assert!(last.failure.is_some());

        // Verify the final outcome event is emitted with correct fields.
        // Drain all events to find the last outcome event.
        let mut last_outcome_event = None;
        while let Ok(msg) = rx.try_recv() {
            let parsed: serde_json::Value = serde_json::from_str(&msg).unwrap();
            if parsed["event"] == "repo_convergence.outcome" {
                last_outcome_event = Some(parsed);
            }
        }
        let evt = last_outcome_event.expect("Should have outcome event");
        assert_eq!(evt["data"]["reason_code"], "attempt_budget_exhausted");
        assert_eq!(evt["data"]["drift_state_after"], "Failed");
    }

    // ============================================================================
    // Convergence Loop Tests (bd-vvmd.3.4)
    // ============================================================================

    fn make_test_pool_and_loop(
        config: ConvergenceLoopConfig,
    ) -> (
        Arc<RepoConvergenceService>,
        crate::workers::WorkerPool,
        EventBus,
        ConvergenceLoop,
    ) {
        let events = EventBus::new(256);
        let svc = Arc::new(RepoConvergenceService::new(events.clone()));
        let pool = crate::workers::WorkerPool::new();

        let convergence_loop =
            ConvergenceLoop::new(svc.clone(), pool.clone(), events.clone(), config);

        (svc, pool, events, convergence_loop)
    }

    async fn add_test_worker(pool: &crate::workers::WorkerPool, id: &str) {
        pool.add_worker(WorkerConfig {
            id: WorkerId::new(id),
            ..Default::default()
        })
        .await;
    }

    #[tokio::test]
    async fn test_loop_steady_state_no_alerts() {
        // All workers Ready => no alerts emitted across many ticks.
        let config = ConvergenceLoopConfig {
            interval: Duration::from_millis(10),
            sustained_drift_ticks: 3,
            sustained_failure_ticks: 2,
            alert_debounce_ticks: 5,
        };
        let (svc, pool, events, mut cloop) = make_test_pool_and_loop(config);
        let mut rx = events.subscribe();

        add_test_worker(&pool, "w1").await;
        add_test_worker(&pool, "w2").await;

        // Mark both workers Ready.
        svc.update_required_repos(
            &WorkerId::new("w1"),
            vec!["repo-a".into()],
            vec!["repo-a".into()],
        )
        .await;
        svc.update_required_repos(
            &WorkerId::new("w2"),
            vec!["repo-b".into()],
            vec!["repo-b".into()],
        )
        .await;

        // Run 10 ticks.
        for _ in 0..10 {
            let summary = cloop.tick().await;
            assert_eq!(summary.alerts_emitted, 0);
            assert_eq!(summary.workers_checked, 2);
        }

        // Verify only loop_tick events, no alert events.
        let mut alert_count = 0;
        while let Ok(msg) = tokio::time::timeout(Duration::from_millis(5), rx.recv()).await {
            if let Ok(msg) = msg {
                let parsed: serde_json::Value = serde_json::from_str(&msg).unwrap();
                if parsed["event"] == "repo_convergence.alert" {
                    alert_count += 1;
                }
            }
        }
        assert_eq!(alert_count, 0);
    }

    #[tokio::test]
    async fn test_loop_sustained_drift_emits_alert() {
        let config = ConvergenceLoopConfig {
            interval: Duration::from_millis(10),
            sustained_drift_ticks: 3,
            sustained_failure_ticks: 2,
            alert_debounce_ticks: 5,
        };
        let (svc, pool, events, mut cloop) = make_test_pool_and_loop(config);
        let mut rx = events.subscribe();

        add_test_worker(&pool, "drift-w").await;

        // Set worker to Drifting (missing repos).
        svc.update_required_repos(
            &WorkerId::new("drift-w"),
            vec!["repo-x".into(), "repo-y".into()],
            vec![], // none synced
        )
        .await;

        // Tick 1-2: no alert (below threshold).
        for _ in 0..2 {
            let s = cloop.tick().await;
            assert_eq!(s.alerts_emitted, 0);
        }

        // Tick 3: alert should fire (sustained_drift_ticks = 3).
        let s = cloop.tick().await;
        assert_eq!(s.alerts_emitted, 1);

        // Find the alert event.
        let mut found_alert = false;
        while let Ok(msg) = tokio::time::timeout(Duration::from_millis(5), rx.recv()).await {
            if let Ok(msg) = msg {
                let parsed: serde_json::Value = serde_json::from_str(&msg).unwrap();
                if parsed["event"] == "repo_convergence.alert" {
                    assert_eq!(parsed["data"]["alert_type"], "sustained_drift");
                    assert_eq!(parsed["data"]["worker_id"], "drift-w");
                    assert_eq!(parsed["data"]["consecutive_ticks"], 3);
                    assert!(
                        !parsed["data"]["missing_repos"]
                            .as_array()
                            .unwrap()
                            .is_empty()
                    );
                    assert!(!parsed["data"]["remediation"].as_array().unwrap().is_empty());
                    found_alert = true;
                }
            }
        }
        assert!(found_alert, "Expected sustained_drift alert event");
    }

    #[tokio::test]
    async fn test_loop_failure_alert() {
        let config = ConvergenceLoopConfig {
            interval: Duration::from_millis(10),
            sustained_drift_ticks: 6,
            sustained_failure_ticks: 2,
            alert_debounce_ticks: 5,
        };
        let (svc, pool, _events, mut cloop) = make_test_pool_and_loop(config);

        add_test_worker(&pool, "fail-w").await;

        // Put worker into Failed state by exhausting budgets.
        let wid = WorkerId::new("fail-w");
        svc.update_required_repos(&wid, vec!["r1".into()], vec![])
            .await;
        svc.mark_converging(&wid).await;
        // Exhaust attempt budget (3 failures).
        for _ in 0..3 {
            let _ = svc
                .record_convergence_attempt(&wid, 0, 1, 0, 1000, Some("test".into()))
                .await;
            // Re-mark converging for next attempt (except when Failed).
            if svc.get_drift_state(&wid).await != ConvergenceDriftState::Failed {
                svc.mark_converging(&wid).await;
            }
        }
        assert_eq!(
            svc.get_drift_state(&wid).await,
            ConvergenceDriftState::Failed
        );

        // Tick 1: no alert.
        let s = cloop.tick().await;
        assert_eq!(s.alerts_emitted, 0);

        // Tick 2: alert fires (sustained_failure_ticks = 2).
        let s = cloop.tick().await;
        assert_eq!(s.alerts_emitted, 1);
    }

    #[tokio::test]
    async fn test_loop_alert_debounce_suppresses_repeats() {
        // debounce_ticks=4 means after alert fires, cooldown is set to 4.
        // Next ticks decrement: 4→3→2→1→0. Ticks with cooldown>0 are suppressed.
        // So 3 ticks suppressed (cooldown 3,2,1), 4th tick cooldown reaches 0 and fires.
        let config = ConvergenceLoopConfig {
            interval: Duration::from_millis(10),
            sustained_drift_ticks: 2,
            sustained_failure_ticks: 2,
            alert_debounce_ticks: 4,
        };
        let (svc, pool, _events, mut cloop) = make_test_pool_and_loop(config);

        add_test_worker(&pool, "bounce-w").await;
        svc.update_required_repos(&WorkerId::new("bounce-w"), vec!["r".into()], vec![])
            .await;

        // Tick 1: no alert (drift_ticks=1, below threshold=2).
        let s = cloop.tick().await;
        assert_eq!(s.alerts_emitted, 0);

        // Tick 2: alert fires (drift_ticks=2, meets threshold).
        let s = cloop.tick().await;
        assert_eq!(s.alerts_emitted, 1);

        // Ticks 3-5: debounce suppresses (cooldown 3,2,1).
        for i in 0..3 {
            let s = cloop.tick().await;
            assert_eq!(s.alerts_emitted, 0, "Tick {} should be debounced", i + 3);
        }

        // Tick 6: cooldown expired (0), alert fires again.
        let s = cloop.tick().await;
        assert_eq!(
            s.alerts_emitted, 1,
            "Alert should fire after debounce window"
        );
    }

    #[tokio::test]
    async fn test_loop_recovery_to_healthy_clears_counters() {
        let config = ConvergenceLoopConfig {
            interval: Duration::from_millis(10),
            sustained_drift_ticks: 3,
            sustained_failure_ticks: 2,
            alert_debounce_ticks: 5,
        };
        let (svc, pool, _events, mut cloop) = make_test_pool_and_loop(config);

        add_test_worker(&pool, "recover-w").await;
        let wid = WorkerId::new("recover-w");

        // Start Drifting.
        svc.update_required_repos(&wid, vec!["r1".into()], vec![])
            .await;

        // 2 drift ticks (below threshold).
        for _ in 0..2 {
            cloop.tick().await;
        }

        // Recover: sync the repos.
        // Need to wait for hysteresis before transitioning back.
        tokio::time::sleep(Duration::from_millis(5100)).await;
        svc.update_required_repos(&wid, vec!["r1".into()], vec!["r1".into()])
            .await;
        assert_eq!(
            svc.get_drift_state(&wid).await,
            ConvergenceDriftState::Ready
        );

        // Tick after recovery: no alert, counters reset.
        let s = cloop.tick().await;
        assert_eq!(s.alerts_emitted, 0);

        // Continue ticking many times: never alert (counters were reset).
        for _ in 0..10 {
            let s = cloop.tick().await;
            assert_eq!(s.alerts_emitted, 0);
        }
    }

    #[tokio::test]
    async fn test_loop_workload_aware_throttling_skips_busy_workers() {
        let config = ConvergenceLoopConfig {
            interval: Duration::from_millis(10),
            sustained_drift_ticks: 2,
            sustained_failure_ticks: 2,
            alert_debounce_ticks: 5,
        };
        let (svc, pool, _events, mut cloop) = make_test_pool_and_loop(config);

        add_test_worker(&pool, "busy-w").await;
        add_test_worker(&pool, "idle-w").await;

        // Put both into Drifting state.
        svc.update_required_repos(&WorkerId::new("busy-w"), vec!["r".into()], vec![])
            .await;
        svc.update_required_repos(&WorkerId::new("idle-w"), vec!["r".into()], vec![])
            .await;

        // Make busy-w have active builds.
        let workers = pool.all_workers().await;
        for w in &workers {
            let cfg = w.config.read().await;
            if cfg.id.as_str() == "busy-w" {
                w.reserve_slots(1).await;
            }
        }

        // First tick: busy-w skipped, idle-w checked.
        let s = cloop.tick().await;
        assert_eq!(s.workers_checked, 1);
        assert_eq!(s.workers_skipped_busy, 1);

        // Second tick: idle-w hits threshold, alert fires for idle-w only.
        let s = cloop.tick().await;
        assert_eq!(s.alerts_emitted, 1);
        assert_eq!(s.workers_skipped_busy, 1);
    }

    #[tokio::test]
    async fn test_loop_tick_summary_event_emitted() {
        let config = ConvergenceLoopConfig {
            interval: Duration::from_millis(10),
            sustained_drift_ticks: 100,
            sustained_failure_ticks: 100,
            alert_debounce_ticks: 100,
        };
        let (_svc, pool, events, mut cloop) = make_test_pool_and_loop(config);
        let mut rx = events.subscribe();

        add_test_worker(&pool, "w1").await;

        let summary = cloop.tick().await;
        assert_eq!(summary.tick_number, 1);
        assert_eq!(summary.workers_checked, 1);
        assert_eq!(summary.workers_skipped_busy, 0);
        assert_eq!(summary.staleness_checks, 1);

        // Find loop_tick event.
        let mut found_tick_event = false;
        while let Ok(msg) = tokio::time::timeout(Duration::from_millis(5), rx.recv()).await {
            if let Ok(msg) = msg {
                let parsed: serde_json::Value = serde_json::from_str(&msg).unwrap();
                if parsed["event"] == "repo_convergence.loop_tick" {
                    assert_eq!(parsed["data"]["tick_number"], 1);
                    assert_eq!(parsed["data"]["workers_checked"], 1);
                    found_tick_event = true;
                }
            }
        }
        assert!(found_tick_event, "Expected loop_tick event");
    }

    #[tokio::test]
    async fn test_loop_empty_pool_no_panic() {
        let config = ConvergenceLoopConfig {
            interval: Duration::from_millis(10),
            sustained_drift_ticks: 3,
            sustained_failure_ticks: 2,
            alert_debounce_ticks: 5,
        };
        let (_svc, _pool, _events, mut cloop) = make_test_pool_and_loop(config);

        // Empty pool should not panic and report 0 workers.
        let s = cloop.tick().await;
        assert_eq!(s.workers_checked, 0);
        assert_eq!(s.workers_skipped_busy, 0);
        assert_eq!(s.staleness_checks, 0);
        assert_eq!(s.alerts_emitted, 0);
    }

    #[tokio::test]
    async fn test_loop_config_default_values() {
        let config = ConvergenceLoopConfig::default();
        assert_eq!(config.interval, Duration::from_secs(30));
        assert_eq!(config.sustained_drift_ticks, SUSTAINED_DRIFT_ALERT_TICKS);
        assert_eq!(
            config.sustained_failure_ticks,
            SUSTAINED_FAILURE_ALERT_TICKS
        );
        assert_eq!(config.alert_debounce_ticks, ALERT_DEBOUNCE_TICKS);
    }

    #[tokio::test]
    async fn test_loop_drift_then_failure_switches_counter() {
        // Verify that transitioning from Drifting to Failed resets drift counter
        // and starts counting failure ticks.
        let config = ConvergenceLoopConfig {
            interval: Duration::from_millis(10),
            sustained_drift_ticks: 10,
            sustained_failure_ticks: 2,
            alert_debounce_ticks: 100,
        };
        let (svc, pool, _events, mut cloop) = make_test_pool_and_loop(config);

        add_test_worker(&pool, "df-w").await;
        let wid = WorkerId::new("df-w");

        // Start Drifting.
        svc.update_required_repos(&wid, vec!["r1".into()], vec![])
            .await;

        // 3 drift ticks.
        for _ in 0..3 {
            let s = cloop.tick().await;
            assert_eq!(s.alerts_emitted, 0);
        }

        // Transition to Failed by exhausting budgets.
        svc.mark_converging(&wid).await;
        for _ in 0..3 {
            let _ = svc
                .record_convergence_attempt(&wid, 0, 1, 0, 1000, Some("err".into()))
                .await;
            if svc.get_drift_state(&wid).await != ConvergenceDriftState::Failed {
                svc.mark_converging(&wid).await;
            }
        }
        assert_eq!(
            svc.get_drift_state(&wid).await,
            ConvergenceDriftState::Failed
        );

        // Tick 1 in Failed: no alert (need 2 failure ticks).
        let s = cloop.tick().await;
        assert_eq!(s.alerts_emitted, 0);

        // Tick 2 in Failed: alert fires.
        let s = cloop.tick().await;
        assert_eq!(s.alerts_emitted, 1);
    }
}
