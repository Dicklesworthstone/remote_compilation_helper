//! Deferred proof replay conveyor and state machine
//! (bd-session-history-remediation-ocv9i.5.3).
//!
//! When proof mode refuses ([`crate::proof_policy`]) it records a durable
//! [`ProofIntent`](crate::proof_intent::ProofIntent). Those intents are not
//! dead letters: when the fleet recovers, an eligible worker rejoins, or disk
//! pressure clears, the proof should run *automatically* — but only when doing
//! so is genuinely legal and safe.
//!
//! This module is that conveyor. It is built from the same pure, deterministic,
//! clock-free primitives as its siblings: [`decide`] is the single-intent state
//! transition over observable [`ConveyorSignals`], [`plan_scan`] folds a batch
//! of queued intents into a fair, starvation-bounded plan, and
//! [`ProofReplayStateStore`] persists each intent's current [`ProofState`] as an
//! append-only JSONL log (dedup-by-`intent_id`, latest-wins, corruption-tolerant)
//! mirroring [`crate::proof_intent::ProofIntentStore`].
//!
//! # Invariants the conveyor upholds
//!
//! 1. **Source is revalidated before every replay.** A stale intent (changed
//!    source, changed revision, or expired age — see
//!    [`validate_replay`](crate::proof_intent::validate_replay)) transitions to
//!    [`ProofState::Stale`] and is never replayed. A fresh proof must be
//!    recorded instead (which yields a new `intent_id`).
//! 2. **Replay never bypasses worker safety policy.** The conveyor only promotes
//!    an intent to [`ProofState::Replaying`] when the fleet readiness
//!    [`DecisiveBlocker`] is [`DecisiveBlocker::None`]. Critical pressure, an
//!    open circuit, a capability gap, a down daemon — every safety block holds
//!    the intent in [`ProofState::Queued`] or [`ProofState::Blocked`].
//! 3. **Replay never starves interactive work.** Promotion to `Replaying`
//!    additionally requires spare capacity ([`ConveyorSignals::replay_capacity_available`]),
//!    and [`plan_scan`] caps the number of concurrent replays per scan, choosing
//!    the oldest intents first (FIFO fairness).
//! 4. **Terminal states are final.** [`ProofState::Passed`], `Failed`, and
//!    `Stale` are terminal; the conveyor never resurrects them.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::disk_pressure_report::ExecFailureClass;
use crate::incident::IncidentReasonCode;
use crate::proof_intent::ReplayDecision;
use crate::readiness::DecisiveBlocker;
use crate::schema_versions::{SchemaComponent, current_version};

/// The published lifecycle state of a deferred proof intent.
///
/// Exactly the six states the bead requires. [`Queued`](ProofState::Queued) and
/// [`Blocked`](ProofState::Blocked) are both "not running yet" but differ in
/// *why*: a queued intent waits for a transient condition (capacity, health,
/// pressure) the conveyor retries automatically; a blocked intent waits for a
/// structural condition (a capability gap, an unhonored placement) that time
/// alone will not clear.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofState {
    /// Recorded and waiting on a *transient* recovery (capacity, fleet health,
    /// pressure). The conveyor re-evaluates it every scan.
    Queued,
    /// Waiting on a *structural* condition (no worker can run this command, or a
    /// requested placement cannot be honored). Held until the condition changes.
    Blocked,
    /// Cleared for genuine remote execution this scan.
    Replaying,
    /// Replayed remotely and the product succeeded. Terminal.
    Passed,
    /// Replayed remotely and the product failed (compile/test error). Terminal —
    /// re-running an unchanged proof cannot change the result; a fix yields a new
    /// intent.
    Failed,
    /// The recorded source/revision/age no longer matches; the intent can never
    /// be replayed as-is. Terminal.
    Stale,
}

impl ProofState {
    /// Every state, in stable declaration order (for coverage + iteration).
    pub const ALL: &'static [ProofState] = &[
        Self::Queued,
        Self::Blocked,
        Self::Replaying,
        Self::Passed,
        Self::Failed,
        Self::Stale,
    ];

    /// Stable lowercase token (matches the serde representation).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ProofState::Queued => "queued",
            ProofState::Blocked => "blocked",
            ProofState::Replaying => "replaying",
            ProofState::Passed => "passed",
            ProofState::Failed => "failed",
            ProofState::Stale => "stale",
        }
    }

    /// A terminal state never transitions to another state.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            ProofState::Passed | ProofState::Failed | ProofState::Stale
        )
    }

    /// Whether a transition from `self` to `next` is legal. Self-transitions are
    /// always legal (idempotent re-evaluation). Terminal states only transition
    /// to themselves.
    #[must_use]
    pub fn can_transition_to(self, next: ProofState) -> bool {
        if self == next {
            return true;
        }
        match self {
            // Non-terminal states freely interconvert and may reach any terminal.
            ProofState::Queued => matches!(
                next,
                ProofState::Blocked | ProofState::Replaying | ProofState::Stale
            ),
            ProofState::Blocked => matches!(
                next,
                ProofState::Queued | ProofState::Replaying | ProofState::Stale
            ),
            // A replay attempt resolves to passed/failed, or drops back to queued
            // on a transient (infrastructure) failure, or to stale if revalidation
            // failed mid-flight.
            ProofState::Replaying => matches!(
                next,
                ProofState::Passed | ProofState::Failed | ProofState::Queued | ProofState::Stale
            ),
            // Terminal: no transition other than the self-transition handled above.
            ProofState::Passed | ProofState::Failed | ProofState::Stale => false,
        }
    }
}

/// The outcome of a replay attempt that actually ran (or tried to) on a worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayOutcome {
    /// The command ran remotely and the product succeeded.
    Succeeded,
    /// The command ran remotely and the product failed (compile/test error).
    ProductFailed,
    /// A worker/transport/environment problem prevented a clean result; the
    /// proof itself is undecided and should be re-queued.
    InfrastructureFailed,
}

impl ReplayOutcome {
    /// Classify the result of an executed replay from its success flag and exec
    /// failure attribution. A success is [`Succeeded`](ReplayOutcome::Succeeded);
    /// a failure is a [`ProductFailed`](ReplayOutcome::ProductFailed) only when the
    /// failure is attributed to the product's own compilation, otherwise it is an
    /// [`InfrastructureFailed`](ReplayOutcome::InfrastructureFailed) (worker /
    /// environment / indeterminate), which is retriable.
    #[must_use]
    pub fn classify(success: bool, failure_class: ExecFailureClass) -> Self {
        if success {
            return ReplayOutcome::Succeeded;
        }
        match failure_class {
            ExecFailureClass::ProductCompile => ReplayOutcome::ProductFailed,
            ExecFailureClass::WorkerEnvironment | ExecFailureClass::Indeterminate => {
                ReplayOutcome::InfrastructureFailed
            }
        }
    }

    /// The terminal-or-retry state this outcome resolves a replay to.
    #[must_use]
    pub fn resolved_state(self) -> ProofState {
        match self {
            ReplayOutcome::Succeeded => ProofState::Passed,
            ReplayOutcome::ProductFailed => ProofState::Failed,
            ReplayOutcome::InfrastructureFailed => ProofState::Queued,
        }
    }
}

/// The observable world for a single intent's conveyor decision. Plain data so
/// the transition is pure and unit-testable.
#[derive(Debug, Clone)]
pub struct ConveyorSignals {
    /// The result of revalidating the intent's source/revision/age against the
    /// current checkout (see [`validate_replay`](crate::proof_intent::validate_replay)).
    pub replay: ReplayDecision,
    /// The decisive fleet-readiness blocker for the intent's command right now
    /// (see [`assess_readiness`](crate::readiness::assess_readiness)).
    pub blocker: DecisiveBlocker,
    /// There is spare capacity to run a replay without starving interactive work.
    pub replay_capacity_available: bool,
}

impl ConveyorSignals {
    /// Signals for an intent whose source is valid, the fleet is fully ready, and
    /// there is capacity to replay — i.e. it will be promoted to `Replaying`.
    #[must_use]
    pub fn ready() -> Self {
        Self {
            replay: ReplayDecision::Replayable,
            blocker: DecisiveBlocker::None,
            replay_capacity_available: true,
        }
    }
}

/// The conveyor's decision for one intent: the next state, whether to actually
/// attempt the replay now, and a durable reason/detail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConveyorDecision {
    /// The state to transition the intent to.
    pub next_state: ProofState,
    /// True iff the conveyor should execute the replay now (only ever true when
    /// `next_state == Replaying`).
    pub attempt_replay: bool,
    /// The decisive incident reason holding/advancing the intent. `None` when the
    /// intent is cleared to replay (there is no incident).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<IncidentReasonCode>,
    /// Operator/agent-facing detail.
    pub detail: String,
}

impl ConveyorDecision {
    fn new(
        next_state: ProofState,
        attempt_replay: bool,
        reason: Option<IncidentReasonCode>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            next_state,
            attempt_replay,
            reason,
            detail: detail.into(),
        }
    }
}

/// Decide the next state for a single non-terminal intent given the current
/// world. Pure and total.
///
/// Precedence (most fundamental first):
/// 1. A terminal `current` is final — the conveyor returns it unchanged.
/// 2. **Source revalidation wins over fleet state.** If the intent's source /
///    revision / age no longer validates, it is [`ProofState::Stale`] regardless
///    of how healthy the fleet is — replaying a stale proof would prove nothing.
/// 3. Otherwise the decisive fleet [`DecisiveBlocker`] maps to a state: a clean
///    fleet with spare capacity replays; a clean fleet *without* spare capacity
///    holds queued (protecting interactive work); a structural capability/
///    placement gap blocks; every transient block (daemon, health, pressure,
///    artifact miss) queues for automatic retry.
#[must_use]
pub fn decide(current: ProofState, signals: &ConveyorSignals) -> ConveyorDecision {
    if current.is_terminal() {
        return ConveyorDecision::new(
            current,
            false,
            None,
            format!("intent is in terminal state `{}`", current.as_str()),
        );
    }

    // (2) Source revalidation is decisive and beats any fleet readiness.
    if let ReplayDecision::Rejected { reason, detail } = &signals.replay {
        return ConveyorDecision::new(ProofState::Stale, false, Some(*reason), detail.clone());
    }

    // (3) Map the decisive fleet blocker.
    match signals.blocker {
        DecisiveBlocker::None => {
            if signals.replay_capacity_available {
                ConveyorDecision::new(
                    ProofState::Replaying,
                    true,
                    None,
                    "remote ready and replay capacity available; replaying",
                )
            } else {
                ConveyorDecision::new(
                    ProofState::Queued,
                    false,
                    Some(IncidentReasonCode::InsufficientSlots),
                    "remote ready but holding replay to avoid starving interactive work",
                )
            }
        }
        DecisiveBlocker::DaemonDown => ConveyorDecision::new(
            ProofState::Queued,
            false,
            Some(IncidentReasonCode::DaemonSocketRefused),
            "daemon socket unreachable; queued pending daemon recovery",
        ),
        DecisiveBlocker::NoDesiredFleet => ConveyorDecision::new(
            ProofState::Queued,
            false,
            Some(IncidentReasonCode::NoAdmissibleWorkers),
            "no workers configured/desired; queued pending fleet configuration",
        ),
        DecisiveBlocker::NoHealthyWorkers => ConveyorDecision::new(
            ProofState::Queued,
            false,
            Some(IncidentReasonCode::NoAdmissibleWorkers),
            "workers desired but none live/healthy; queued pending recovery/canary rejoin",
        ),
        DecisiveBlocker::PressureBlocked => ConveyorDecision::new(
            ProofState::Queued,
            false,
            Some(IncidentReasonCode::CriticalPressure),
            "admissibility blocked by critical pressure; queued pending pressure recovery",
        ),
        DecisiveBlocker::ArtifactMissed => ConveyorDecision::new(
            ProofState::Queued,
            false,
            Some(IncidentReasonCode::ArtifactMiss),
            "last attempt failed at artifact retrieval; queued to retry",
        ),
        DecisiveBlocker::NoCommandCapability => ConveyorDecision::new(
            ProofState::Blocked,
            false,
            Some(IncidentReasonCode::MissingRuntimeToolchainTarget),
            "no worker can run this command (capability gap); blocked pending capability",
        ),
        DecisiveBlocker::ProofRefused => ConveyorDecision::new(
            ProofState::Blocked,
            false,
            Some(IncidentReasonCode::ProofRefusal),
            "proof refused before execution (placement/policy); blocked pending operator",
        ),
    }
}

/// A durable record of one intent's conveyor state. Append-only history of these
/// in the [`ProofReplayStateStore`] makes `rch proof status` answerable without
/// recomputation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofReplayRecord {
    /// Schema version (`SchemaComponent::ProofReplayState`).
    pub schema_version: String,
    /// The proof intent this state belongs to (see [`crate::proof_intent`]).
    pub intent_id: String,
    /// When the intent was first recorded/queued (Unix epoch ms). Preserved
    /// across every transition so the conveyor can serve intents oldest-first and
    /// surface age in status.
    pub recorded_at_unix_ms: u64,
    /// The current published state.
    pub state: ProofState,
    /// How many replay attempts have been executed for this intent.
    #[serde(default)]
    pub attempts: u32,
    /// The decisive incident reason for the current state, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_reason: Option<IncidentReasonCode>,
    /// Operator/agent-facing detail for the current state.
    pub last_detail: String,
    /// Last transition time as Unix epoch milliseconds (caller-supplied →
    /// deterministic).
    pub updated_at_unix_ms: u64,
}

impl ProofReplayRecord {
    /// A freshly-queued record for a newly-recorded intent.
    #[must_use]
    pub fn queued(intent_id: impl Into<String>, recorded_at_unix_ms: u64) -> Self {
        Self {
            schema_version: proof_replay_schema_version().to_string(),
            intent_id: intent_id.into(),
            recorded_at_unix_ms,
            state: ProofState::Queued,
            attempts: 0,
            last_reason: None,
            last_detail: "recorded; queued for deferred replay".to_string(),
            updated_at_unix_ms: recorded_at_unix_ms,
        }
    }

    /// Apply a conveyor [`decide`] result, producing the next record. The
    /// attempt counter increments only when the decision actually replays. An
    /// illegal transition (e.g. from a terminal state) is a no-op except for the
    /// timestamp, preserving the state-machine invariant.
    #[must_use]
    pub fn apply(&self, decision: &ConveyorDecision, now_unix_ms: u64) -> Self {
        let mut next = self.clone();
        next.updated_at_unix_ms = now_unix_ms;
        if !self.state.can_transition_to(decision.next_state) {
            return next;
        }
        next.state = decision.next_state;
        next.last_reason = decision.reason;
        next.last_detail = decision.detail.clone();
        if decision.attempt_replay {
            next.attempts = next.attempts.saturating_add(1);
        }
        next
    }

    /// Resolve a `Replaying` record with the outcome of the executed replay.
    /// Succeeded → `Passed`, product failure → `Failed`, infrastructure failure
    /// → back to `Queued` for a later retry.
    #[must_use]
    pub fn resolve(&self, outcome: ReplayOutcome, now_unix_ms: u64) -> Self {
        let next_state = outcome.resolved_state();
        let mut next = self.clone();
        next.updated_at_unix_ms = now_unix_ms;
        if !self.state.can_transition_to(next_state) {
            return next;
        }
        next.state = next_state;
        next.last_detail = match outcome {
            ReplayOutcome::Succeeded => "replay succeeded remotely; proof passed".to_string(),
            ReplayOutcome::ProductFailed => {
                "replay ran remotely; product failed (compile/test)".to_string()
            }
            ReplayOutcome::InfrastructureFailed => {
                "replay hit an infrastructure failure; re-queued for retry".to_string()
            }
        };
        next.last_reason = match outcome {
            ReplayOutcome::Succeeded | ReplayOutcome::ProductFailed => None,
            ReplayOutcome::InfrastructureFailed => Some(IncidentReasonCode::ArtifactMiss),
        };
        next
    }
}

/// The current proof-replay-state schema version.
#[must_use]
pub fn proof_replay_schema_version() -> &'static str {
    current_version(SchemaComponent::ProofReplayState)
}

/// One item to evaluate in a conveyor scan: an intent, its current state, the
/// observed signals, and when it was recorded (for FIFO fairness).
#[derive(Debug, Clone)]
pub struct ConveyorScanItem {
    /// The intent's stable id.
    pub intent_id: String,
    /// The intent's current persisted state.
    pub current_state: ProofState,
    /// The observed world for this intent.
    pub signals: ConveyorSignals,
    /// When the intent was originally recorded (Unix epoch ms) — older first.
    pub recorded_at_unix_ms: u64,
}

/// The conveyor's decision for one scanned intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConveyorScanResult {
    /// The intent's stable id.
    pub intent_id: String,
    /// The decision for this intent.
    pub decision: ConveyorDecision,
}

/// Plan a full conveyor scan. Each item is evaluated with [`decide`], then the
/// set promoted to [`ProofState::Replaying`] is capped at `max_concurrent_replays`
/// — the **oldest** intents (smallest `recorded_at_unix_ms`, ties broken by
/// `intent_id`) win the available replay slots; the rest are held in
/// [`ProofState::Queued`]. This is the starvation guard: it bounds how much fleet
/// capacity deferred proofs may consume in one pass and serves intents fairly.
///
/// `max_concurrent_replays == 0` admits no replays this scan (e.g. interactive
/// demand is saturating the fleet). Results preserve input order.
#[must_use]
pub fn plan_scan(
    items: &[ConveyorScanItem],
    max_concurrent_replays: usize,
) -> Vec<ConveyorScanResult> {
    // First pass: the unconstrained per-intent decision.
    let mut decisions: Vec<ConveyorDecision> = items
        .iter()
        .map(|it| decide(it.current_state, &it.signals))
        .collect();

    // Identify would-be replays and rank them oldest-first for fair admission.
    let mut replay_candidates: Vec<usize> = decisions
        .iter()
        .enumerate()
        .filter(|(_, d)| d.next_state == ProofState::Replaying)
        .map(|(i, _)| i)
        .collect();
    replay_candidates.sort_by(|&a, &b| {
        items[a]
            .recorded_at_unix_ms
            .cmp(&items[b].recorded_at_unix_ms)
            .then_with(|| items[a].intent_id.cmp(&items[b].intent_id))
    });

    // Demote every replay beyond the concurrency cap back to Queued.
    for &idx in replay_candidates.iter().skip(max_concurrent_replays) {
        decisions[idx] = ConveyorDecision::new(
            ProofState::Queued,
            false,
            Some(IncidentReasonCode::InsufficientSlots),
            "replay deferred: concurrent replay cap reached (fairness/anti-starvation)",
        );
    }

    items
        .iter()
        .zip(decisions)
        .map(|(it, decision)| ConveyorScanResult {
            intent_id: it.intent_id.clone(),
            decision,
        })
        .collect()
}

/// Append-only, dedup-by-`intent_id`, corruption-tolerant proof-replay-state
/// store. Mirrors [`crate::proof_intent::ProofIntentStore`]: `put` is O(1) on the
/// hot path (latest-wins is resolved on read).
#[derive(Debug, Clone)]
pub struct ProofReplayStateStore {
    path: PathBuf,
}

impl ProofReplayStateStore {
    #[must_use]
    pub fn with_path(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append a state record. Duplicate `intent_id`s are tolerated on write
    /// (latest-wins resolved on read).
    pub fn put(&self, record: &ProofReplayRecord) -> std::io::Result<()> {
        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }
        let mut line = serde_json::to_string(record)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        line.push('\n');
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        file.write_all(line.as_bytes())?;
        file.flush()
    }

    /// All current records, deduplicated by `intent_id` (latest write wins), in
    /// first-seen order. Corrupt lines are skipped.
    #[must_use]
    pub fn all(&self) -> Vec<ProofReplayRecord> {
        let file = match fs::File::open(&self.path) {
            Ok(f) => f,
            Err(_) => return Vec::new(),
        };
        let mut order: Vec<String> = Vec::new();
        let mut latest: BTreeMap<String, ProofReplayRecord> = BTreeMap::new();
        for line in BufReader::new(file).lines() {
            let Ok(line) = line else { break };
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Ok(record) = serde_json::from_str::<ProofReplayRecord>(trimmed) {
                if !latest.contains_key(&record.intent_id) {
                    order.push(record.intent_id.clone());
                }
                latest.insert(record.intent_id.clone(), record);
            }
        }
        order
            .into_iter()
            .filter_map(|id| latest.remove(&id))
            .collect()
    }

    /// Fetch a single record by intent id (latest wins).
    #[must_use]
    pub fn get(&self, intent_id: &str) -> Option<ProofReplayRecord> {
        self.all().into_iter().find(|r| r.intent_id == intent_id)
    }

    /// Records currently in a given state.
    #[must_use]
    pub fn by_state(&self, state: ProofState) -> Vec<ProofReplayRecord> {
        self.all()
            .into_iter()
            .filter(|r| r.state == state)
            .collect()
    }

    /// A `state -> count` census of every tracked intent (for `rch proof status`).
    #[must_use]
    pub fn census(&self) -> BTreeMap<String, usize> {
        let mut census: BTreeMap<String, usize> = BTreeMap::new();
        for record in self.all() {
            *census.entry(record.state.as_str().to_string()).or_insert(0) += 1;
        }
        census
    }

    /// Run one conveyor scan over every tracked, **non-terminal** intent and
    /// persist the resulting transitions. This is the conveyor's loop body: the
    /// caller supplies the freshly-observed [`ConveyorSignals`] per intent (which
    /// require live state — readiness, source revalidation — and so are computed
    /// at the impure boundary), and this method handles the deterministic part:
    /// fair, starvation-bounded planning ([`plan_scan`]) and durable persistence.
    ///
    /// Intents with no entry in `signals_by_intent` are left untouched (the caller
    /// could not observe them this tick). Terminal intents are never revisited.
    /// Returns the per-intent scan results (for the intents that were evaluated).
    /// `now_unix_ms` stamps every transition deterministically.
    pub fn advance(
        &self,
        signals_by_intent: &BTreeMap<String, ConveyorSignals>,
        max_concurrent_replays: usize,
        now_unix_ms: u64,
    ) -> std::io::Result<Vec<ConveyorScanResult>> {
        let records: Vec<ProofReplayRecord> = self
            .all()
            .into_iter()
            .filter(|r| !r.state.is_terminal())
            .collect();

        let items: Vec<ConveyorScanItem> = records
            .iter()
            .filter_map(|r| {
                signals_by_intent
                    .get(&r.intent_id)
                    .map(|signals| ConveyorScanItem {
                        intent_id: r.intent_id.clone(),
                        current_state: r.state,
                        signals: signals.clone(),
                        recorded_at_unix_ms: r.recorded_at_unix_ms,
                    })
            })
            .collect();

        let results = plan_scan(&items, max_concurrent_replays);

        for result in &results {
            if let Some(record) = records.iter().find(|r| r.intent_id == result.intent_id) {
                let next = record.apply(&result.decision, now_unix_ms);
                self.put(&next)?;
            }
        }
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proof_intent::{
        ProofIntent, ReplayConstraints, ReplayContext, SourceFingerprint, StaleSourcePolicy,
        validate_replay,
    };

    fn rejected(detail: &str) -> ReplayDecision {
        ReplayDecision::Rejected {
            reason: IncidentReasonCode::ProofRefusal,
            detail: detail.to_string(),
        }
    }

    // --- ProofState machine -------------------------------------------------

    #[test]
    fn states_have_unique_stable_tokens() {
        assert_eq!(ProofState::ALL.len(), 6);
        let mut tokens: Vec<&str> = ProofState::ALL.iter().map(|s| s.as_str()).collect();
        let before = tokens.len();
        tokens.sort_unstable();
        tokens.dedup();
        assert_eq!(before, tokens.len(), "duplicate proof-state tokens");
    }

    #[test]
    fn terminal_states_are_final() {
        for terminal in [ProofState::Passed, ProofState::Failed, ProofState::Stale] {
            assert!(terminal.is_terminal());
            for &next in ProofState::ALL {
                let legal = terminal.can_transition_to(next);
                // Only the self-transition is legal from a terminal state.
                assert_eq!(legal, next == terminal, "{terminal:?} -> {next:?}");
            }
        }
    }

    #[test]
    fn non_terminal_states_can_reach_terminals() {
        for start in [
            ProofState::Queued,
            ProofState::Blocked,
            ProofState::Replaying,
        ] {
            assert!(!start.is_terminal());
            assert!(start.can_transition_to(ProofState::Stale));
        }
        assert!(ProofState::Replaying.can_transition_to(ProofState::Passed));
        assert!(ProofState::Replaying.can_transition_to(ProofState::Failed));
        // Queued cannot leap straight to Passed/Failed — it must replay first.
        assert!(!ProofState::Queued.can_transition_to(ProofState::Passed));
        assert!(!ProofState::Queued.can_transition_to(ProofState::Failed));
    }

    #[test]
    fn states_serialize_with_snake_case_tokens() {
        assert_eq!(
            serde_json::to_value(ProofState::Replaying).unwrap(),
            "replaying"
        );
        let back: ProofState = serde_json::from_str("\"stale\"").unwrap();
        assert_eq!(back, ProofState::Stale);
    }

    // --- ReplayOutcome ------------------------------------------------------

    #[test]
    fn outcome_classification_and_resolution() {
        assert_eq!(
            ReplayOutcome::classify(true, ExecFailureClass::Indeterminate),
            ReplayOutcome::Succeeded
        );
        assert_eq!(
            ReplayOutcome::classify(false, ExecFailureClass::ProductCompile),
            ReplayOutcome::ProductFailed
        );
        assert_eq!(
            ReplayOutcome::classify(false, ExecFailureClass::WorkerEnvironment),
            ReplayOutcome::InfrastructureFailed
        );
        assert_eq!(
            ReplayOutcome::classify(false, ExecFailureClass::Indeterminate),
            ReplayOutcome::InfrastructureFailed
        );
        assert_eq!(
            ReplayOutcome::Succeeded.resolved_state(),
            ProofState::Passed
        );
        assert_eq!(
            ReplayOutcome::ProductFailed.resolved_state(),
            ProofState::Failed
        );
        assert_eq!(
            ReplayOutcome::InfrastructureFailed.resolved_state(),
            ProofState::Queued
        );
    }

    // --- decide(): the four mandated scenarios + invariants -----------------

    #[test]
    fn decide_replays_when_ready_with_capacity() {
        let d = decide(ProofState::Queued, &ConveyorSignals::ready());
        assert_eq!(d.next_state, ProofState::Replaying);
        assert!(d.attempt_replay);
        assert!(d.reason.is_none());
    }

    #[test]
    fn decide_holds_queued_when_ready_but_no_capacity_protecting_interactive() {
        // Anti-starvation: a fully-ready fleet still defers when there is no spare
        // capacity for replay.
        let signals = ConveyorSignals {
            replay_capacity_available: false,
            ..ConveyorSignals::ready()
        };
        let d = decide(ProofState::Queued, &signals);
        assert_eq!(d.next_state, ProofState::Queued);
        assert!(!d.attempt_replay);
        assert_eq!(d.reason, Some(IncidentReasonCode::InsufficientSlots));
    }

    #[test]
    fn scenario_recovery_after_disk_pressure() {
        // While pressured: queued, never replayed.
        let pressured = ConveyorSignals {
            replay: ReplayDecision::Replayable,
            blocker: DecisiveBlocker::PressureBlocked,
            replay_capacity_available: true,
        };
        let d = decide(ProofState::Queued, &pressured);
        assert_eq!(d.next_state, ProofState::Queued);
        assert!(!d.attempt_replay);
        assert_eq!(d.reason, Some(IncidentReasonCode::CriticalPressure));

        // After pressure clears: replays.
        let d2 = decide(ProofState::Queued, &ConveyorSignals::ready());
        assert_eq!(d2.next_state, ProofState::Replaying);
        assert!(d2.attempt_replay);
    }

    #[test]
    fn scenario_source_changed_while_queued_goes_stale() {
        let signals = ConveyorSignals {
            replay: rejected("source fingerprint mismatch (source changed)"),
            // Even a perfectly healthy fleet must not replay a stale proof.
            blocker: DecisiveBlocker::None,
            replay_capacity_available: true,
        };
        let d = decide(ProofState::Queued, &signals);
        assert_eq!(d.next_state, ProofState::Stale);
        assert!(!d.attempt_replay);
        assert!(d.detail.contains("source changed"));
    }

    #[test]
    fn scenario_capability_still_missing_stays_blocked() {
        let signals = ConveyorSignals {
            replay: ReplayDecision::Replayable,
            blocker: DecisiveBlocker::NoCommandCapability,
            replay_capacity_available: true,
        };
        let d = decide(ProofState::Queued, &signals);
        assert_eq!(d.next_state, ProofState::Blocked);
        assert!(!d.attempt_replay);
        assert_eq!(
            d.reason,
            Some(IncidentReasonCode::MissingRuntimeToolchainTarget)
        );
    }

    #[test]
    fn scenario_worker_eligible_after_canary_rejoin() {
        // Before rejoin: workers desired but none healthy -> queued.
        let no_healthy = ConveyorSignals {
            replay: ReplayDecision::Replayable,
            blocker: DecisiveBlocker::NoHealthyWorkers,
            replay_capacity_available: true,
        };
        let d = decide(ProofState::Queued, &no_healthy);
        assert_eq!(d.next_state, ProofState::Queued);
        assert!(d.detail.contains("canary rejoin"));

        // After a canary rejoins and becomes admissible: replays.
        let d2 = decide(ProofState::Queued, &ConveyorSignals::ready());
        assert_eq!(d2.next_state, ProofState::Replaying);
        assert!(d2.attempt_replay);
    }

    #[test]
    fn decide_never_replays_under_any_safety_block() {
        // The cardinal safety invariant: no blocker except `None` may ever replay.
        for blocker in [
            DecisiveBlocker::DaemonDown,
            DecisiveBlocker::NoDesiredFleet,
            DecisiveBlocker::NoHealthyWorkers,
            DecisiveBlocker::NoCommandCapability,
            DecisiveBlocker::PressureBlocked,
            DecisiveBlocker::ArtifactMissed,
            DecisiveBlocker::ProofRefused,
        ] {
            let signals = ConveyorSignals {
                replay: ReplayDecision::Replayable,
                blocker,
                replay_capacity_available: true,
            };
            let d = decide(ProofState::Queued, &signals);
            assert!(!d.attempt_replay, "must not replay under {blocker:?}");
            assert_ne!(d.next_state, ProofState::Replaying);
        }
    }

    #[test]
    fn decide_is_noop_on_terminal_states() {
        for terminal in [ProofState::Passed, ProofState::Failed, ProofState::Stale] {
            let d = decide(terminal, &ConveyorSignals::ready());
            assert_eq!(d.next_state, terminal);
            assert!(!d.attempt_replay);
        }
    }

    #[test]
    fn decide_uses_real_validate_replay_for_staleness() {
        // Integration with the real proof-intent revalidation primitive.
        let intent = ProofIntent::new(
            "blake3:abc",
            "/data/projects/foo",
            Some("rev-1".to_string()),
            "pooled",
            IncidentReasonCode::ProofRefusal,
            StaleSourcePolicy::RejectIfChanged,
            ReplayConstraints {
                require_same_revision: true,
                require_unchanged_sources: true,
                max_age_secs: Some(3600),
            },
            1_700_000_000_000,
        )
        .with_source_fingerprints(vec![SourceFingerprint {
            path: "src/lib.rs".to_string(),
            blake3: "deadbeef".to_string(),
        }]);
        // Source changed since recording.
        let ctx = ReplayContext {
            current_revision: Some("rev-1".to_string()),
            current_fingerprints: vec![SourceFingerprint {
                path: "src/lib.rs".to_string(),
                blake3: "CHANGED".to_string(),
            }],
            age_secs: 10,
        };
        let signals = ConveyorSignals {
            replay: validate_replay(&intent, &ctx),
            blocker: DecisiveBlocker::None,
            replay_capacity_available: true,
        };
        // The intent carries no conveyor state of its own; the conveyor tracks
        // that separately. A queued intent whose source no longer validates is
        // stale regardless of fleet health.
        let _ = &intent;
        assert_eq!(
            decide(ProofState::Queued, &signals).next_state,
            ProofState::Stale
        );
    }

    // --- ProofReplayRecord transitions --------------------------------------

    #[test]
    fn record_apply_advances_and_counts_attempts() {
        let rec = ProofReplayRecord::queued("pi-1", 1_000);
        assert_eq!(rec.state, ProofState::Queued);
        assert_eq!(rec.attempts, 0);

        let d = decide(ProofState::Queued, &ConveyorSignals::ready());
        let replaying = rec.apply(&d, 2_000);
        assert_eq!(replaying.state, ProofState::Replaying);
        assert_eq!(replaying.attempts, 1, "attempt counted on replay");
        assert_eq!(replaying.updated_at_unix_ms, 2_000);

        let passed = replaying.resolve(ReplayOutcome::Succeeded, 3_000);
        assert_eq!(passed.state, ProofState::Passed);
        assert_eq!(passed.attempts, 1, "resolve does not re-count");
    }

    #[test]
    fn record_apply_rejects_illegal_transition_from_terminal() {
        let passed = ProofReplayRecord::queued("pi-1", 1)
            .apply(&decide(ProofState::Queued, &ConveyorSignals::ready()), 2)
            .resolve(ReplayOutcome::Succeeded, 3);
        assert_eq!(passed.state, ProofState::Passed);
        // A subsequent "queued" decision must NOT resurrect a passed proof.
        let illegal = ConveyorDecision {
            next_state: ProofState::Queued,
            attempt_replay: false,
            reason: None,
            detail: "spurious".to_string(),
        };
        let after = passed.apply(&illegal, 4);
        assert_eq!(after.state, ProofState::Passed, "terminal state preserved");
        assert_eq!(after.updated_at_unix_ms, 4);
    }

    #[test]
    fn record_resolve_infra_failure_requeues_for_retry() {
        let replaying = ProofReplayRecord::queued("pi-1", 1)
            .apply(&decide(ProofState::Queued, &ConveyorSignals::ready()), 2);
        let requeued = replaying.resolve(ReplayOutcome::InfrastructureFailed, 3);
        assert_eq!(requeued.state, ProofState::Queued);
        assert_eq!(requeued.attempts, 1);
        assert_eq!(requeued.last_reason, Some(IncidentReasonCode::ArtifactMiss));
    }

    #[test]
    fn record_roundtrips_and_stamps_schema_version() {
        let rec = ProofReplayRecord::queued("pi-xyz", 42);
        assert_eq!(rec.schema_version, proof_replay_schema_version());
        let back: ProofReplayRecord =
            serde_json::from_str(&serde_json::to_string(&rec).unwrap()).unwrap();
        assert_eq!(rec, back);
    }

    // --- plan_scan(): fairness + anti-starvation ----------------------------

    fn ready_item(id: &str, recorded: u64) -> ConveyorScanItem {
        ConveyorScanItem {
            intent_id: id.to_string(),
            current_state: ProofState::Queued,
            signals: ConveyorSignals::ready(),
            recorded_at_unix_ms: recorded,
        }
    }

    #[test]
    fn plan_scan_caps_concurrent_replays_oldest_first() {
        // Three ready intents, but capacity for only two replays this scan.
        let items = vec![
            ready_item("pi-new", 3_000),
            ready_item("pi-old", 1_000),
            ready_item("pi-mid", 2_000),
        ];
        let plan = plan_scan(&items, 2);
        let by_id = |id: &str| {
            plan.iter()
                .find(|r| r.intent_id == id)
                .unwrap()
                .decision
                .clone()
        };
        // The two oldest win the replay slots.
        assert_eq!(by_id("pi-old").next_state, ProofState::Replaying);
        assert_eq!(by_id("pi-mid").next_state, ProofState::Replaying);
        // The newest is held queued for fairness.
        let newest = by_id("pi-new");
        assert_eq!(newest.next_state, ProofState::Queued);
        assert!(!newest.attempt_replay);
        assert_eq!(newest.reason, Some(IncidentReasonCode::InsufficientSlots));
        // Output preserves input order.
        assert_eq!(plan[0].intent_id, "pi-new");
    }

    #[test]
    fn plan_scan_zero_cap_admits_no_replays() {
        let items = vec![ready_item("pi-1", 1), ready_item("pi-2", 2)];
        let plan = plan_scan(&items, 0);
        assert!(plan.iter().all(|r| !r.decision.attempt_replay));
        assert!(
            plan.iter()
                .all(|r| r.decision.next_state == ProofState::Queued)
        );
    }

    #[test]
    fn plan_scan_does_not_demote_non_replay_states() {
        // Blocked/stale items are unaffected by the replay cap.
        let mut blocked = ready_item("pi-blocked", 1);
        blocked.signals.blocker = DecisiveBlocker::NoCommandCapability;
        let mut stale = ready_item("pi-stale", 2);
        stale.signals.replay = rejected("source changed");
        let items = vec![blocked, stale, ready_item("pi-ready", 3)];
        let plan = plan_scan(&items, 0);
        let by_id = |id: &str| plan.iter().find(|r| r.intent_id == id).unwrap();
        assert_eq!(by_id("pi-blocked").decision.next_state, ProofState::Blocked);
        assert_eq!(by_id("pi-stale").decision.next_state, ProofState::Stale);
        // The genuinely-ready one is the only one the cap demotes.
        assert_eq!(by_id("pi-ready").decision.next_state, ProofState::Queued);
    }

    // --- ProofReplayStateStore ----------------------------------------------

    #[test]
    fn store_dedups_and_reports_latest_state() {
        let dir = tempfile::tempdir().unwrap();
        let store = ProofReplayStateStore::with_path(dir.path().join("replay.jsonl"));
        let rec = ProofReplayRecord::queued("pi-1", 1);
        store.put(&rec).unwrap();
        let replaying = rec.apply(&decide(ProofState::Queued, &ConveyorSignals::ready()), 2);
        store.put(&replaying).unwrap();
        let passed = replaying.resolve(ReplayOutcome::Succeeded, 3);
        store.put(&passed).unwrap();

        let all = store.all();
        assert_eq!(all.len(), 1, "dedup by intent_id");
        assert_eq!(all[0].state, ProofState::Passed, "latest wins");
        assert_eq!(store.get("pi-1").unwrap().state, ProofState::Passed);
        assert!(store.get("pi-missing").is_none());
    }

    #[test]
    fn store_by_state_and_census() {
        let dir = tempfile::tempdir().unwrap();
        let store = ProofReplayStateStore::with_path(dir.path().join("replay.jsonl"));
        store.put(&ProofReplayRecord::queued("pi-q1", 1)).unwrap();
        store.put(&ProofReplayRecord::queued("pi-q2", 2)).unwrap();
        let blocked = {
            let mut sig = ConveyorSignals::ready();
            sig.blocker = DecisiveBlocker::NoCommandCapability;
            ProofReplayRecord::queued("pi-b", 3).apply(&decide(ProofState::Queued, &sig), 4)
        };
        store.put(&blocked).unwrap();

        assert_eq!(store.by_state(ProofState::Queued).len(), 2);
        assert_eq!(store.by_state(ProofState::Blocked).len(), 1);
        let census = store.census();
        assert_eq!(census.get("queued"), Some(&2));
        assert_eq!(census.get("blocked"), Some(&1));
    }

    #[test]
    fn store_is_corruption_tolerant() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("replay.jsonl");
        let store = ProofReplayStateStore::with_path(&path);
        store.put(&ProofReplayRecord::queued("pi-1", 1)).unwrap();
        {
            let mut f = OpenOptions::new().append(true).open(&path).unwrap();
            writeln!(f, "{{ not json").unwrap();
        }
        store.put(&ProofReplayRecord::queued("pi-2", 2)).unwrap();
        assert_eq!(store.all().len(), 2, "corrupt line skipped, not fatal");
    }

    #[test]
    fn missing_store_reads_empty() {
        let dir = tempfile::tempdir().unwrap();
        let store = ProofReplayStateStore::with_path(dir.path().join("nope.jsonl"));
        assert!(store.all().is_empty());
        assert!(store.census().is_empty());
    }

    #[test]
    fn record_preserves_recorded_at_across_transitions() {
        let rec = ProofReplayRecord::queued("pi-1", 5_000);
        let replaying = rec.apply(
            &decide(ProofState::Queued, &ConveyorSignals::ready()),
            6_000,
        );
        let passed = replaying.resolve(ReplayOutcome::Succeeded, 7_000);
        assert_eq!(rec.recorded_at_unix_ms, 5_000);
        assert_eq!(replaying.recorded_at_unix_ms, 5_000, "preserved on apply");
        assert_eq!(passed.recorded_at_unix_ms, 5_000, "preserved on resolve");
        assert_eq!(passed.updated_at_unix_ms, 7_000);
    }

    // --- advance(): the conveyor loop body ----------------------------------

    #[test]
    fn advance_persists_transitions_and_honors_fairness_and_terminals() {
        let dir = tempfile::tempdir().unwrap();
        let store = ProofReplayStateStore::with_path(dir.path().join("replay.jsonl"));

        // Three queued intents (oldest first) and one already-passed terminal.
        store
            .put(&ProofReplayRecord::queued("pi-old", 1_000))
            .unwrap();
        store
            .put(&ProofReplayRecord::queued("pi-mid", 2_000))
            .unwrap();
        store
            .put(&ProofReplayRecord::queued("pi-new", 3_000))
            .unwrap();
        let passed = ProofReplayRecord::queued("pi-done", 500)
            .apply(&decide(ProofState::Queued, &ConveyorSignals::ready()), 600)
            .resolve(ReplayOutcome::Succeeded, 700);
        store.put(&passed).unwrap();

        // Signals: all three queued are ready; the terminal one is (wrongly) also
        // offered a signal to prove terminals are skipped.
        let mut signals: BTreeMap<String, ConveyorSignals> = BTreeMap::new();
        for id in ["pi-old", "pi-mid", "pi-new", "pi-done"] {
            signals.insert(id.to_string(), ConveyorSignals::ready());
        }

        // Capacity for only one replay this tick.
        let results = store.advance(&signals, 1, 10_000).unwrap();

        // The terminal intent is never evaluated.
        assert!(results.iter().all(|r| r.intent_id != "pi-done"));
        assert_eq!(results.len(), 3);

        // Exactly one replay, and it is the oldest.
        let replaying: Vec<&str> = results
            .iter()
            .filter(|r| r.decision.attempt_replay)
            .map(|r| r.intent_id.as_str())
            .collect();
        assert_eq!(replaying, vec!["pi-old"]);

        // Persistence reflects the plan: pi-old replaying, others queued, terminal intact.
        assert_eq!(store.get("pi-old").unwrap().state, ProofState::Replaying);
        assert_eq!(store.get("pi-old").unwrap().attempts, 1);
        assert_eq!(store.get("pi-mid").unwrap().state, ProofState::Queued);
        assert_eq!(store.get("pi-done").unwrap().state, ProofState::Passed);

        // A follow-up tick with more capacity advances the rest.
        let results2 = store.advance(&signals, 8, 11_000).unwrap();
        // pi-old is now Replaying (non-terminal), so it is re-evaluated too.
        assert!(
            results2
                .iter()
                .any(|r| r.intent_id == "pi-mid" && r.decision.attempt_replay)
        );
    }

    #[test]
    fn advance_skips_intents_without_signals() {
        let dir = tempfile::tempdir().unwrap();
        let store = ProofReplayStateStore::with_path(dir.path().join("replay.jsonl"));
        store.put(&ProofReplayRecord::queued("pi-seen", 1)).unwrap();
        store
            .put(&ProofReplayRecord::queued("pi-unseen", 2))
            .unwrap();

        let mut signals: BTreeMap<String, ConveyorSignals> = BTreeMap::new();
        signals.insert("pi-seen".to_string(), ConveyorSignals::ready());

        let results = store.advance(&signals, 8, 100).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].intent_id, "pi-seen");
        // The unobserved intent is untouched (still at its original queued state).
        assert_eq!(store.get("pi-unseen").unwrap().state, ProofState::Queued);
        assert_eq!(store.get("pi-unseen").unwrap().updated_at_unix_ms, 2);
    }
}
