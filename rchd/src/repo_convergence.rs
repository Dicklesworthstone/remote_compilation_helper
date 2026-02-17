//! Daemon-side RepoConvergence service for multi-repo dependency graphs.
//!
//! Computes required repo hull from active builds, tracks per-worker drift
//! states with deterministic transitions and hysteresis, and drives bounded
//! convergence through the repo_updater adapter contract.

use rch_common::WorkerId;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

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
    fn drift_confidence(&self) -> f64 {
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
    pub async fn get_worker_transitions(
        &self,
        worker_id: &WorkerId,
    ) -> Vec<DriftStateTransition> {
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
            self.record_transition_locked(
                &mut self.transitions.write().await,
                worker_id.as_str(),
                old_state,
                new_state,
                &reason,
                now_ms,
            );
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

        // Apply transition with hysteresis.
        if new_state != entry.current_state && entry.can_transition() {
            self.record_transition_locked(
                &mut self.transitions.write().await,
                worker_id.as_str(),
                entry.current_state,
                new_state,
                &reason_code,
                now_ms,
            );
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
        self.events
            .emit("repo_convergence.outcome", &outcome);

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

        if entry.current_state != ConvergenceDriftState::Converging && entry.can_transition() {
            let now_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as i64)
                .unwrap_or_default();
            self.record_transition_locked(
                &mut self.transitions.write().await,
                worker_id.as_str(),
                entry.current_state,
                ConvergenceDriftState::Converging,
                "sync_started",
                now_ms,
            );
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

    /// Check if convergence budgets allow another attempt for a worker.
    pub async fn has_budget(&self, worker_id: &WorkerId) -> bool {
        let state = self.state.read().await;
        state
            .get(worker_id.as_str())
            .map(|s| s.attempt_budget_remaining > 0 && s.time_budget_remaining_ms > 0)
            .unwrap_or(true) // No state yet = budgets not consumed
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

        let worker_transitions = transitions
            .entry(worker_id.to_string())
            .or_insert_with(VecDeque::new);
        if worker_transitions.len() >= MAX_TRANSITION_HISTORY {
            worker_transitions.pop_front();
        }
        worker_transitions.push_back(transition);
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
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
            vec![
                "/data/projects/a",
                "/data/projects/b",
                "/data/projects/c",
            ]
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
            .record_convergence_attempt(
                &wid,
                0,
                1,
                0,
                100,
                Some("rsync timeout".to_string()),
            )
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
                .record_convergence_attempt(
                    &wid,
                    0,
                    1,
                    0,
                    100,
                    Some("auth failure".to_string()),
                )
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

        svc.update_required_repos(
            &wid,
            vec!["a".into(), "b".into()],
            vec![],
        )
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

        svc.update_required_repos(
            &test_worker_id("w10"),
            vec!["r".into()],
            vec!["r".into()],
        )
        .await;
        svc.update_required_repos(
            &test_worker_id("w11"),
            vec!["r".into()],
            vec![],
        )
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
        svc.record_convergence_attempt(
            &wid,
            0,
            1,
            0,
            100,
            Some("fail".into()),
        )
        .await
        .unwrap();

        // Now succeed.
        svc.record_convergence_attempt(&wid, 1, 0, 0, 100, None)
            .await
            .unwrap();

        let ws = svc.get_worker_state(&wid).await.unwrap();
        assert_eq!(ws.attempt_budget_remaining, MAX_CONVERGENCE_ATTEMPTS);
    }
}
