//! Multi-agent load fairness and storm-control modeling
//! (bd-session-history-remediation-ocv9i.10.4).
//!
//! The core product promise is that many concurrent agents must not saturate the
//! local machine or leave work in an ambiguous queued/running state. Unit tests
//! for the individual queue/selection pieces are not enough: we need a scenario
//! that simulates a real swarm and proves the scheduler, admission, queue,
//! fallback policy, and observability stay coherent under contention.
//!
//! This module is the deterministic, CI-runnable heart of that proof. It does
//! **not** reimplement the scheduler's decision logic — it DRIVES the real
//! contract primitives so the mock-worker E2E exercises the same code the daemon
//! and CLI use:
//!   - [`crate::job_identity`] for the local-wrapper / remote-build identity and
//!     admission marking,
//!   - [`crate::queue_contract`] for the definite start-state contract and the
//!     attach/cancel guidance every not-started job must carry.
//!
//! What is *modeled* here (because it lives in the bin-only `rchd` crate and
//! cannot be imported) is the worker pool: slot accounting, the eligibility
//! gate (a worker that is temporarily bypassed / admin-disabled /
//! capability-inadmissible is never selected), the fairness weighting
//! (`speed / (1 + recent_selections)`, mirroring `selection::select_fair_fastest`),
//! the bounded FIFO queue with a wait timeout, and the fail-open / proof
//! fallback policy. The simulation is a deterministic discrete-event loop — no
//! threads, no wall clock, no randomness — so the same inputs always produce the
//! same [`StormRun`].
//!
//! The output is a stream of [`SmokeProfileEvent`] JSONL records (reusing the
//! smoke profile's event schema, extended with the load fields) plus a
//! [`StormSummary`] of regression statistics. The [invariant checkers](check_all_invariants)
//! analyze that event stream and are the actual regression guard: they run
//! against a SIMULATED storm in CI *and* against a REAL daemon's events from a
//! `--load` self-test run, so the same invariants gate both.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap, VecDeque};

use serde::{Deserialize, Serialize};

use crate::fleet_smoke_profile::{SmokeProfileEvent, SmokeScenario};
use crate::job_identity::{JobIdentity, RemoteBuildId};
use crate::queue_contract::{
    AdmissionState, QueueContractResponse, QueueOptions, WaitResult, resolve_queue_contract,
};

/// Stable placement/fallback decision tokens carried in
/// [`SmokeProfileEvent::fallback_decision`]. Append-only: the invariant checkers,
/// dashboards, and the validation matrix key off these exact strings.
pub mod decision {
    /// The job was admitted to a worker and ran remotely.
    pub const REMOTE: &str = "remote";
    /// The job was queued (not yet started) — an intermediate decision.
    pub const QUEUED: &str = "queued";
    /// No remote capacity (queue full or no eligible worker); a fail-open job ran
    /// locally instead.
    pub const LOCAL_FALLBACK: &str = "local_fallback";
    /// The job waited in the queue past the wait timeout and then ran locally.
    pub const QUEUE_TIMEOUT_FALLBACK: &str = "queue_timeout_fallback";
    /// A proof (strict-remote) job refused local fallback when no remote was
    /// available — the correct fail-closed behavior.
    pub const PROOF_REFUSED: &str = "proof_refused";
    /// The job was cancelled before it started.
    pub const CANCELLED: &str = "cancelled";
}

/// Stable lifecycle `event` tokens emitted for load/storm jobs (a superset of the
/// smoke profile's planned/started/passed/failed/skipped/refused vocabulary).
pub mod event {
    /// The job entered the queue.
    pub const QUEUED: &str = "queued";
    /// The job was admitted and began executing on a worker.
    pub const STARTED: &str = "started";
    /// The job completed remotely.
    pub const PASSED: &str = "passed";
    /// The job ran locally (fail-open fallback).
    pub const FELL_BACK: &str = "fell_back";
    /// The job refused local fallback (proof mode, fail-closed).
    pub const REFUSED: &str = "refused";
    /// The job was cancelled before it started.
    pub const CANCELLED: &str = "cancelled";
}

/// Reason code surfaced when a proof (strict-remote) job refuses local fallback.
/// Mirrors the proof-refusal taxonomy used by the smoke profile's proof-mode
/// scenario (`RCH-E301` family); kept as a token so the checker and dashboards
/// can recognise it without a hard dependency on the error catalog enum.
pub const PROOF_REFUSAL_REASON: &str = "RCH-E301";

/// Live scheduler eligibility of a worker, flattened from `rchd`'s two-axis
/// (admin-intent × eligibility) model. Only [`Self::Healthy`] and
/// [`Self::Degraded`] are schedulable — mirroring `WorkerState::is_schedulable`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerEligibility {
    /// Healthy and schedulable.
    Healthy,
    /// Degraded but still schedulable.
    Degraded,
    /// Transiently bypassed by the circuit breaker — not schedulable.
    TemporaryBypass,
    /// Operator-disabled (admin intent) — not schedulable.
    AdminDisabled,
    /// Missing a required capability/runtime — not schedulable.
    CapabilityInadmissible,
}

impl WorkerEligibility {
    /// Whether a worker in this state may receive new work.
    #[must_use]
    pub const fn is_schedulable(self) -> bool {
        matches!(self, Self::Healthy | Self::Degraded)
    }

    /// Stable token for diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::TemporaryBypass => "temporary_bypass",
            Self::AdminDisabled => "admin_disabled",
            Self::CapabilityInadmissible => "capability_inadmissible",
        }
    }
}

/// A worker in the simulated fleet.
#[derive(Debug, Clone, PartialEq)]
pub struct StormWorker {
    /// Stable worker id.
    pub id: String,
    /// Total concurrent slots.
    pub total_slots: u32,
    /// SpeedScore used in fairness weighting (higher = faster).
    pub speed: f64,
    /// Live eligibility.
    pub eligibility: WorkerEligibility,
}

impl StormWorker {
    /// A healthy worker with the given id, slots, and speed.
    #[must_use]
    pub fn healthy(id: impl Into<String>, total_slots: u32, speed: f64) -> Self {
        Self {
            id: id.into(),
            total_slots,
            speed,
            eligibility: WorkerEligibility::Healthy,
        }
    }

    /// The same worker with a different eligibility (for building adversarial
    /// fleets where some workers must never receive work).
    #[must_use]
    pub fn with_eligibility(mut self, eligibility: WorkerEligibility) -> Self {
        self.eligibility = eligibility;
        self
    }
}

/// Per-job fallback policy, mirroring the placement controls
/// (`RCH_REQUIRE_REMOTE` / `RCH_FORCE_REMOTE` / default fail-open).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobPolicy {
    /// Default: attempt remote, fall back to local when remote is unavailable.
    FailOpen,
    /// Always attempt remote but still fall back to local (distinct from proof).
    ForceRemote,
    /// Strict remote (proof): refuse local fallback — fail closed.
    Proof,
}

impl JobPolicy {
    /// Whether this policy permits a local fallback.
    #[must_use]
    pub const fn allows_local_fallback(self) -> bool {
        matches!(self, Self::FailOpen | Self::ForceRemote)
    }
}

/// The kind of compilation command (only affects the `command_fingerprint`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobKind {
    /// `cargo build`-like.
    Build,
    /// `cargo test`-like.
    Test,
    /// `cargo check`-like.
    Check,
}

impl JobKind {
    /// Redacted command fingerprint for the JSONL event.
    #[must_use]
    pub const fn fingerprint(self) -> &'static str {
        match self {
            Self::Build => "cargo build",
            Self::Test => "cargo test",
            Self::Check => "cargo check",
        }
    }
}

/// One agent's compilation job submitted into the storm.
#[derive(Debug, Clone, PartialEq)]
pub struct StormJob {
    /// Virtual remote runtime in milliseconds.
    pub runtime_ms: u64,
    /// Slots the job needs.
    pub slots: u32,
    /// Project root (used for cache/affinity attribution and varied fixtures).
    pub project_root: String,
    /// Fallback policy.
    pub policy: JobPolicy,
    /// Command kind.
    pub kind: JobKind,
    /// If the job ends up queued, cancel it before it starts (exercises the
    /// cancel-before-start path) instead of waiting for a slot.
    pub cancel_when_queued: bool,
}

impl StormJob {
    /// A fail-open build job needing `slots` slots for `runtime_ms`.
    #[must_use]
    pub fn build(runtime_ms: u64, slots: u32, project_root: impl Into<String>) -> Self {
        Self {
            runtime_ms,
            slots,
            project_root: project_root.into(),
            policy: JobPolicy::FailOpen,
            kind: JobKind::Build,
            cancel_when_queued: false,
        }
    }

    /// Override the policy.
    #[must_use]
    pub fn with_policy(mut self, policy: JobPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Override the kind.
    #[must_use]
    pub fn with_kind(mut self, kind: JobKind) -> Self {
        self.kind = kind;
        self
    }

    /// Mark the job to cancel-when-queued.
    #[must_use]
    pub fn cancelling(mut self) -> Self {
        self.cancel_when_queued = true;
        self
    }
}

/// Tunables for the storm run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StormConfig {
    /// Correlates every event of this run.
    pub run_id: String,
    /// Owning bead id.
    pub bead_id: String,
    /// Maximum queued jobs before a fail-open job falls back to local.
    pub max_queue_depth: usize,
    /// Maximum milliseconds a job waits in the queue before timing out.
    pub queue_timeout_ms: u64,
    /// Fairness lookback window: how many recent placements count toward a
    /// worker's recent-selection penalty.
    pub fairness_window: usize,
    /// Delay before a `cancel_when_queued` job is cancelled, once queued.
    pub cancel_delay_ms: u64,
}

impl StormConfig {
    /// A reasonable default storm config for the given run/bead ids.
    #[must_use]
    pub fn new(run_id: impl Into<String>, bead_id: impl Into<String>) -> Self {
        Self {
            run_id: run_id.into(),
            bead_id: bead_id.into(),
            max_queue_depth: 64,
            queue_timeout_ms: 30_000,
            fairness_window: 16,
            cancel_delay_ms: 5,
        }
    }
}

/// Regression statistics for one storm run — enough to detect future scheduler
/// regressions without re-deriving them from the raw event stream.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StormSummary {
    /// Total jobs submitted.
    pub total_jobs: u32,
    /// Jobs that ran remotely to completion.
    pub remote_successes: u32,
    /// Jobs that fell back to local execution (fail-open).
    pub local_fallbacks: u32,
    /// Proof jobs that refused local fallback (fail-closed).
    pub proof_refusals: u32,
    /// Jobs whose queue wait exceeded the timeout.
    pub queue_timeouts: u32,
    /// Jobs cancelled before they started.
    pub cancellations: u32,
    /// 95th-percentile queue wait, milliseconds.
    pub p95_queue_wait_ms: u64,
    /// 95th-percentile end-to-end time, milliseconds.
    pub p95_end_to_end_ms: u64,
    /// Per-worker slot utilization fraction over the run's makespan, by id.
    pub per_worker_slot_utilization: BTreeMap<String, f64>,
}

/// The full result of a simulated storm: the JSONL event stream and the summary.
#[derive(Debug, Clone)]
pub struct StormRun {
    /// Every emitted JSONL event, in chronological (then submission) order.
    pub events: Vec<SmokeProfileEvent>,
    /// Aggregate statistics.
    pub summary: StormSummary,
}

impl StormRun {
    /// Serialize the event stream as one JSON object per line (JSONL).
    ///
    /// # Errors
    /// Returns a [`serde_json::Error`] if any event fails to serialize.
    pub fn to_jsonl(&self) -> Result<String, serde_json::Error> {
        let mut out = String::new();
        for ev in &self.events {
            out.push_str(&serde_json::to_string(ev)?);
            out.push('\n');
        }
        Ok(out)
    }
}

// ===========================================================================
// Discrete-event simulator
// ===========================================================================

#[derive(Debug, Clone, Copy)]
enum Disposition {
    Remote { remote_id: RemoteBuildId },
    LocalFallback,
    QueueTimeoutFallback,
    ProofRefused,
    Cancelled,
}

#[derive(Debug)]
struct JobState {
    local_id: String,
    enqueued_at: Option<u64>,
    queue_wait_ms: u64,
    started_at: Option<u64>,
    disposition: Option<Disposition>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EvKind {
    Arrival(usize),
    Completion {
        worker: usize,
        slots: u32,
        job: usize,
    },
    Timeout(usize),
    Cancel(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Ev {
    time: u64,
    seq: u64,
    kind: EvKind,
}

// Min-heap ordering by (time, seq): earliest event first, deterministic ties.
impl Ord for Ev {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.time.cmp(&other.time).then(self.seq.cmp(&other.seq))
    }
}
impl PartialOrd for Ev {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Run a deterministic, virtual-time simulation of a multi-agent storm.
///
/// Jobs all arrive at virtual time 0 (a true storm). Each attempts placement on
/// the fairest eligible worker with capacity; if none, it queues (bounded) or
/// falls back per its policy. Completions free slots and admit queued jobs FIFO;
/// queued jobs honor the wait timeout and cancellation. Every job reaches exactly
/// one terminal disposition — there is no "stuck wrapper".
#[must_use]
pub fn simulate_storm(workers: &[StormWorker], jobs: &[StormJob], cfg: &StormConfig) -> StormRun {
    let mut sim = Sim::new(workers, jobs, cfg);
    sim.run();
    sim.finish()
}

struct Sim<'a> {
    workers: &'a [StormWorker],
    jobs: &'a [StormJob],
    cfg: &'a StormConfig,
    used: Vec<u32>,
    busy_slot_ms: Vec<u128>,
    selection_log: VecDeque<usize>,
    state: Vec<JobState>,
    queue: VecDeque<usize>,
    heap: BinaryHeap<Reverse<Ev>>,
    events: Vec<SmokeProfileEvent>,
    next_remote_id: RemoteBuildId,
    next_seq: u64,
    clock: u64,
    makespan: u64,
    queue_timeouts: u32,
}

impl<'a> Sim<'a> {
    fn new(workers: &'a [StormWorker], jobs: &'a [StormJob], cfg: &'a StormConfig) -> Self {
        // Deterministic local ids by index (not the uuid-based mint) so the run
        // is reproducible; they keep the real `rchw-` prefix.
        let state = (0..jobs.len())
            .map(|i| JobState {
                local_id: format!("{}{i:04}", crate::job_identity::LOCAL_WRAPPER_ID_PREFIX),
                enqueued_at: None,
                queue_wait_ms: 0,
                started_at: None,
                disposition: None,
            })
            .collect();
        let mut heap = BinaryHeap::new();
        // Arrivals at t=0, sequenced by submission order.
        for (i, _) in jobs.iter().enumerate() {
            heap.push(Reverse(Ev {
                time: 0,
                seq: i as u64,
                kind: EvKind::Arrival(i),
            }));
        }
        Self {
            workers,
            jobs,
            cfg,
            used: vec![0; workers.len()],
            busy_slot_ms: vec![0; workers.len()],
            selection_log: VecDeque::new(),
            state,
            queue: VecDeque::new(),
            heap,
            events: Vec::new(),
            next_remote_id: 1,
            next_seq: jobs.len() as u64,
            clock: 0,
            makespan: 0,
            queue_timeouts: 0,
        }
    }

    fn seq(&mut self) -> u64 {
        let s = self.next_seq;
        self.next_seq += 1;
        s
    }

    fn run(&mut self) {
        while let Some(Reverse(ev)) = self.heap.pop() {
            self.clock = ev.time;
            match ev.kind {
                EvKind::Arrival(job) => self.on_arrival(job),
                EvKind::Completion { worker, slots, job } => self.on_completion(worker, slots, job),
                EvKind::Timeout(job) => self.on_timeout(job),
                EvKind::Cancel(job) => self.on_cancel(job),
            }
        }
        // Safety net: any straggler still queued (e.g. head-of-line never fit)
        // is resolved as a timeout fallback so no wrapper is ever left dangling.
        let stragglers: Vec<usize> = self.queue.drain(..).collect();
        for job in stragglers {
            if self.state[job].disposition.is_none() {
                self.dispose_timeout(job);
            }
        }
    }

    /// Fairest eligible worker with capacity for `slots`, or `None`.
    /// Weight = speed / (1 + recent_selections), highest wins; ties by index.
    fn try_select(&self, slots: u32) -> Option<usize> {
        let mut best: Option<(usize, f64)> = None;
        for (i, w) in self.workers.iter().enumerate() {
            if !w.eligibility.is_schedulable() {
                continue;
            }
            if w.total_slots < slots {
                continue; // capacity-impossible on this worker
            }
            if w.total_slots - self.used[i] < slots {
                continue; // busy right now
            }
            let recent = self.selection_log.iter().filter(|&&x| x == i).count();
            let weight = w.speed / (1.0 + recent as f64);
            match best {
                Some((_, bw)) if weight <= bw => {}
                _ => best = Some((i, weight)),
            }
        }
        best.map(|(i, _)| i)
    }

    /// Whether ANY eligible worker could ever fit `slots` (capacity feasibility).
    fn ever_feasible(&self, slots: u32) -> bool {
        self.workers
            .iter()
            .any(|w| w.eligibility.is_schedulable() && w.total_slots >= slots)
    }

    fn queue_depth_u32(&self) -> u32 {
        u32::try_from(self.queue.len()).unwrap_or(u32::MAX)
    }

    fn on_arrival(&mut self, job: usize) {
        let spec = &self.jobs[job];
        if !self.ever_feasible(spec.slots) {
            // No eligible worker can ever hold this job: rejected before
            // admission. Fail-open runs local; proof refuses.
            if spec.policy.allows_local_fallback() {
                self.dispose_local_fallback(job, decision::LOCAL_FALLBACK);
            } else {
                self.dispose_proof_refused(job);
            }
            return;
        }
        if let Some(w) = self.try_select(spec.slots) {
            self.place(job, w);
            return;
        }
        // Busy fleet: consult the real queue contract for proof refusal vs queue.
        if !spec.policy.allows_local_fallback() {
            // Strict (proof) refuses to queue — fail closed.
            self.dispose_proof_refused(job);
            return;
        }
        if self.queue.len() >= self.cfg.max_queue_depth {
            // Bounded queue is full: fail open to local rather than grow
            // unboundedly — the storm-control backpressure guarantee.
            self.dispose_local_fallback(job, decision::LOCAL_FALLBACK);
            return;
        }
        self.enqueue(job);
    }

    fn enqueue(&mut self, job: usize) {
        self.state[job].enqueued_at = Some(self.clock);
        self.queue.push_back(job);
        let depth = self.queue_depth_u32();
        // The real queue contract: a busy fleet with no wait yields a definite,
        // reattachable not-started job carrying attach/cancel guidance.
        let guidance = queued_guidance(&self.state[job].local_id);
        self.emit(
            job,
            event::QUEUED,
            "queued",
            decision::QUEUED,
            None,
            None,
            Some(depth),
            0,
            Some(guidance),
            None,
        );
        // Schedule timeout and (if applicable) cancellation.
        let timeout_at = self.clock + self.cfg.queue_timeout_ms;
        let s = self.seq();
        self.heap.push(Reverse(Ev {
            time: timeout_at,
            seq: s,
            kind: EvKind::Timeout(job),
        }));
        if self.jobs[job].cancel_when_queued {
            let cancel_at = self.clock + self.cfg.cancel_delay_ms;
            let s = self.seq();
            self.heap.push(Reverse(Ev {
                time: cancel_at,
                seq: s,
                kind: EvKind::Cancel(job),
            }));
        }
    }

    fn place(&mut self, job: usize, worker: usize) {
        let spec = &self.jobs[job];
        let slots = spec.slots;
        let runtime = spec.runtime_ms;
        self.used[worker] += slots;
        self.busy_slot_ms[worker] += u128::from(slots) * u128::from(runtime);
        self.selection_log.push_back(worker);
        while self.selection_log.len() > self.cfg.fairness_window {
            self.selection_log.pop_front();
        }
        let wait = self.state[job]
            .enqueued_at
            .map_or(0, |e| self.clock.saturating_sub(e));
        self.state[job].queue_wait_ms = wait;
        self.state[job].started_at = Some(self.clock);

        let remote_id = self.next_remote_id;
        self.next_remote_id += 1;
        let mut identity = JobIdentity::new_local();
        identity.local_wrapper_id = self.state[job].local_id.clone();
        identity.admit(remote_id);
        self.state[job].disposition = Some(Disposition::Remote { remote_id });

        let worker_id = self.workers[worker].id.clone();
        let depth = self.queue_depth_u32();
        // `started` event: selected worker, both job ids, queue depth.
        self.emit(
            job,
            event::STARTED,
            "run",
            decision::REMOTE,
            Some(worker_id.clone()),
            Some(worker_id.clone()),
            Some(depth),
            0,
            Some("admitted and running".to_string()),
            Some(remote_id),
        );
        let finish = self.clock + runtime;
        self.makespan = self.makespan.max(finish);
        let s = self.seq();
        self.heap.push(Reverse(Ev {
            time: finish,
            seq: s,
            kind: EvKind::Completion { worker, slots, job },
        }));
    }

    fn on_completion(&mut self, worker: usize, slots: u32, job: usize) {
        self.used[worker] = self.used[worker].saturating_sub(slots);
        let runtime = self.jobs[job].runtime_ms;
        let worker_id = self.workers[worker].id.clone();
        let remote_id = match self.state[job].disposition {
            Some(Disposition::Remote { remote_id }) => Some(remote_id),
            _ => None,
        };
        // Terminal remote success.
        self.emit(
            job,
            event::PASSED,
            "ok",
            decision::REMOTE,
            Some(worker_id.clone()),
            Some(worker_id),
            None,
            runtime,
            Some("completed remotely".to_string()),
            remote_id,
        );
        // Freed capacity: admit queued jobs FIFO until the head cannot fit.
        self.drain_queue();
    }

    fn drain_queue(&mut self) {
        while let Some(&job) = self.queue.front() {
            // Already disposed (timed out / cancelled at this same instant)?
            if self.state[job].disposition.is_some() {
                self.queue.pop_front();
                continue;
            }
            let slots = self.jobs[job].slots;
            if let Some(w) = self.try_select(slots) {
                self.queue.pop_front();
                self.place(job, w);
            } else {
                break; // head-of-line: nothing fits yet
            }
        }
    }

    fn on_timeout(&mut self, job: usize) {
        if self.state[job].disposition.is_some() || self.state[job].started_at.is_some() {
            return; // already resolved
        }
        // Remove from queue if still present.
        self.remove_from_queue(job);
        self.dispose_timeout(job);
    }

    fn on_cancel(&mut self, job: usize) {
        if self.state[job].disposition.is_some() || self.state[job].started_at.is_some() {
            return;
        }
        self.remove_from_queue(job);
        self.dispose_cancelled(job);
    }

    fn remove_from_queue(&mut self, job: usize) {
        if let Some(pos) = self.queue.iter().position(|&j| j == job) {
            self.queue.remove(pos);
        }
    }

    fn dispose_timeout(&mut self, job: usize) {
        self.queue_timeouts += 1;
        let wait = self.state[job]
            .enqueued_at
            .map_or(self.cfg.queue_timeout_ms, |e| {
                (self.clock.saturating_sub(e)).min(self.cfg.queue_timeout_ms)
            });
        self.state[job].queue_wait_ms = wait;
        self.state[job].disposition = Some(Disposition::QueueTimeoutFallback);
        let guidance = queue_timeout_guidance(&self.state[job].local_id, self.cfg.queue_timeout_ms);
        self.emit(
            job,
            event::FELL_BACK,
            "local",
            decision::QUEUE_TIMEOUT_FALLBACK,
            None,
            None,
            None,
            self.jobs[job].runtime_ms,
            Some(guidance),
            None,
        );
    }

    fn dispose_local_fallback(&mut self, job: usize, decision_tok: &str) {
        self.state[job].disposition = Some(Disposition::LocalFallback);
        let guidance = local_fallback_guidance();
        self.emit(
            job,
            event::FELL_BACK,
            "local",
            decision_tok,
            None,
            None,
            None,
            self.jobs[job].runtime_ms,
            Some(guidance),
            None,
        );
    }

    fn dispose_proof_refused(&mut self, job: usize) {
        self.state[job].disposition = Some(Disposition::ProofRefused);
        self.emit(
            job,
            event::REFUSED,
            "refused",
            decision::PROOF_REFUSED,
            None,
            None,
            None,
            0,
            Some(
                "proof mode requires immediate remote admission; refused local fallback"
                    .to_string(),
            ),
            None,
        );
        // Tag the refusal reason code on the just-emitted event.
        if let Some(ev) = self.events.last_mut() {
            ev.reason_code = Some(PROOF_REFUSAL_REASON.to_string());
        }
    }

    fn dispose_cancelled(&mut self, job: usize) {
        let wait = self.state[job]
            .enqueued_at
            .map_or(0, |e| self.clock.saturating_sub(e));
        self.state[job].queue_wait_ms = wait;
        self.state[job].disposition = Some(Disposition::Cancelled);
        let guidance = cancel_guidance(&self.state[job].local_id);
        self.emit(
            job,
            event::CANCELLED,
            "cancelled",
            decision::CANCELLED,
            None,
            None,
            None,
            0,
            Some(guidance),
            None,
        );
    }

    #[allow(clippy::too_many_arguments)] // one param per JSONL field the event carries
    fn emit(
        &mut self,
        job: usize,
        event_tok: &str,
        status_tok: &str,
        decision_tok: &str,
        worker_id: Option<String>,
        selected_worker: Option<String>,
        queue_depth: Option<u32>,
        duration_ms: u64,
        detail: Option<String>,
        remote_id: Option<RemoteBuildId>,
    ) {
        let ev = make_load_event(
            &self.cfg.run_id,
            &self.cfg.bead_id,
            self.jobs[job].kind,
            &self.state[job].local_id,
            event_tok,
            status_tok,
            decision_tok,
            worker_id,
            selected_worker,
            queue_depth,
            duration_ms,
            detail,
            remote_id,
        );
        self.events.push(ev);
    }

    fn finish(self) -> StormRun {
        let mut remote_successes = 0u32;
        let mut local_fallbacks = 0u32;
        let mut proof_refusals = 0u32;
        let mut cancellations = 0u32;
        let mut queue_waits = Vec::new();
        let mut end_to_ends = Vec::new();

        for (i, st) in self.state.iter().enumerate() {
            let runtime = self.jobs[i].runtime_ms;
            queue_waits.push(st.queue_wait_ms);
            match st.disposition {
                Some(Disposition::Remote { .. }) => {
                    remote_successes += 1;
                    end_to_ends.push(st.queue_wait_ms + runtime);
                }
                Some(Disposition::LocalFallback) => {
                    local_fallbacks += 1;
                    end_to_ends.push(st.queue_wait_ms + runtime);
                }
                Some(Disposition::QueueTimeoutFallback) => {
                    local_fallbacks += 1;
                    end_to_ends.push(st.queue_wait_ms + runtime);
                }
                Some(Disposition::ProofRefused) => {
                    proof_refusals += 1;
                    end_to_ends.push(st.queue_wait_ms);
                }
                Some(Disposition::Cancelled) => {
                    cancellations += 1;
                    end_to_ends.push(st.queue_wait_ms);
                }
                None => {
                    // Should be impossible (the safety net resolves stragglers),
                    // but count an end-to-end so the percentiles stay sane.
                    end_to_ends.push(st.queue_wait_ms);
                }
            }
        }

        let makespan = self.makespan.max(1);
        let mut per_worker_slot_utilization = BTreeMap::new();
        for (i, w) in self.workers.iter().enumerate() {
            let capacity = u128::from(w.total_slots) * u128::from(makespan);
            #[allow(clippy::cast_precision_loss)]
            let util = if capacity == 0 {
                0.0
            } else {
                self.busy_slot_ms[i] as f64 / capacity as f64
            };
            per_worker_slot_utilization.insert(w.id.clone(), util);
        }

        let summary = StormSummary {
            total_jobs: u32::try_from(self.jobs.len()).unwrap_or(u32::MAX),
            remote_successes,
            local_fallbacks,
            proof_refusals,
            queue_timeouts: self.queue_timeouts,
            cancellations,
            p95_queue_wait_ms: percentile(&mut queue_waits, 95),
            p95_end_to_end_ms: percentile(&mut end_to_ends, 95),
            per_worker_slot_utilization,
        };
        StormRun {
            events: self.events,
            summary,
        }
    }
}

/// The `p`-th percentile of `values` (nearest-rank), 0 if empty. Sorts in place.
#[must_use]
fn percentile(values: &mut [u64], p: u64) -> u64 {
    if values.is_empty() {
        return 0;
    }
    values.sort_unstable();
    // nearest-rank: rank = ceil(p/100 * n), 1-based.
    let n = values.len() as u64;
    let rank = (p * n).div_ceil(100).max(1);
    let idx = (rank - 1).min(n - 1) as usize;
    values[idx]
}

// ===========================================================================
// Shared event / guidance construction (used by BOTH the discrete-event
// simulator and the live recorder so the two emit byte-identical event shapes
// for the same logical disposition — that is what lets the same invariant
// checkers gate a SIMULATED storm in CI and a REAL `--load` self-test run).
// ===========================================================================

/// Build one [`SmokeProfileEvent`] for a load/storm job, carrying every load
/// field. Shared by the simulator's `Sim::emit` and [`build_live_storm_run`].
#[allow(clippy::too_many_arguments)] // one param per JSONL field the event carries
fn make_load_event(
    run_id: &str,
    bead_id: &str,
    kind: JobKind,
    local_id: &str,
    event_tok: &str,
    status_tok: &str,
    decision_tok: &str,
    worker_id: Option<String>,
    selected_worker: Option<String>,
    queue_depth: Option<u32>,
    duration_ms: u64,
    detail: Option<String>,
    remote_id: Option<RemoteBuildId>,
) -> SmokeProfileEvent {
    let mut ev = SmokeProfileEvent::started(
        run_id.to_string(),
        bead_id.to_string(),
        worker_id,
        SmokeScenario::LoadStormControl,
    );
    ev.event = event_tok.to_string();
    ev.status = status_tok.to_string();
    ev.duration_ms = duration_ms;
    ev.command_fingerprint = Some(kind.fingerprint().to_string());
    ev = ev
        .with_job_ids(Some(local_id.to_string()), remote_id)
        .with_selected_worker(selected_worker)
        .with_fallback_decision(decision_tok);
    if let Some(d) = queue_depth {
        ev = ev.with_queue_depth(d);
    }
    if let Some(d) = detail {
        ev = ev.with_detail(d);
    }
    ev
}

/// Attach/cancel guidance for a job that is queued and not yet started — the
/// real busy-fleet queue contract (definite, reattachable not-started job).
fn queued_guidance(local_id: &str) -> String {
    QueueContractResponse::build(
        &resolve_queue_contract(&AdmissionState::Queued, &QueueOptions::default(), None),
        Some(local_id.to_string()),
    )
    .render()
}

/// Guidance for a fail-open job that never reached a worker (fleet at capacity)
/// and ran locally instead.
fn local_fallback_guidance() -> String {
    QueueContractResponse::build(
        &resolve_queue_contract(
            &AdmissionState::RejectedBeforeAdmission(
                "fleet at capacity; ran locally (fail-open)".to_string(),
            ),
            &QueueOptions::default(),
            None,
        ),
        None,
    )
    .detail
}

/// Guidance for a job that waited past the queue wait-timeout and fell back.
fn queue_timeout_guidance(local_id: &str, queue_timeout_ms: u64) -> String {
    QueueContractResponse::build(
        &resolve_queue_contract(
            &AdmissionState::Queued,
            &QueueOptions {
                wait: true,
                wait_timeout_secs: Some(queue_timeout_ms / 1000),
                ..QueueOptions::default()
            },
            Some(WaitResult::TimedOut),
        ),
        Some(local_id.to_string()),
    )
    .render()
}

/// Guidance for a job cancelled before it started.
fn cancel_guidance(local_id: &str) -> String {
    QueueContractResponse::build(
        &resolve_queue_contract(
            &AdmissionState::Queued,
            &QueueOptions {
                wait: true,
                ..QueueOptions::default()
            },
            Some(WaitResult::CancelledBeforeStart),
        ),
        Some(local_id.to_string()),
    )
    .render()
}

// ===========================================================================
// Live recorder: real canary outcomes -> StormRun
// ===========================================================================
//
// The deterministic simulator above proves the SCHEDULER LOGIC in CI. The
// `rch self-test --smoke --load` consumer instead launches a bounded swarm of
// REAL tiny canary builds on a deployed fleet, observes how each one actually
// resolved, and feeds those observations here. [`build_live_storm_run`] turns
// the observed outcomes into the exact same [`StormRun`] shape (JSONL event
// stream + [`StormSummary`]) the simulator produces, so the *same five*
// [`check_all_invariants`] gate a live run. The recorder owns the event
// vocabulary and summary accounting; the consumer owns only the real execution.

/// The terminal disposition of one observed live canary job. Mirrors the
/// simulator's internal `Disposition` but is the public input the live consumer
/// reports for each real build.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveDisposition {
    /// The job was admitted to a worker and ran remotely to completion.
    Remote,
    /// No remote capacity; a fail-open job ran locally instead.
    LocalFallback,
    /// The job waited past the queue wait-timeout and then ran locally.
    QueueTimeoutFallback,
    /// A proof (strict-remote) job refused local fallback (fail-closed).
    ProofRefused,
    /// The job was cancelled before it started.
    Cancelled,
}

impl LiveDisposition {
    /// Whether this disposition admitted the job to a worker.
    #[must_use]
    pub const fn is_remote(self) -> bool {
        matches!(self, Self::Remote)
    }

    /// Whether this disposition counts as a local fallback in the summary.
    #[must_use]
    pub const fn is_local_fallback(self) -> bool {
        matches!(self, Self::LocalFallback | Self::QueueTimeoutFallback)
    }
}

/// One observed REAL canary outcome from a live `--load` self-test run.
///
/// The consumer populates one of these per concurrent canary build it launched,
/// recording how the build actually resolved (which worker the daemon selected,
/// the remote build id it was assigned, whether it queued/fell back/was
/// refused/cancelled, and the measured timings).
#[derive(Debug, Clone, PartialEq)]
pub struct LiveJobOutcome {
    /// Local wrapper id (`rchw-…`) the hook minted for this job.
    pub local_job_id: String,
    /// Remote build id the daemon assigned once admitted; `None` if the job
    /// never reached a worker.
    pub remote_job_id: Option<RemoteBuildId>,
    /// The worker the scheduler selected; `None` for fallback/refusal/cancel.
    pub selected_worker: Option<String>,
    /// Slots the job requested (for slot-utilization accounting).
    pub slots: u32,
    /// Command kind (only affects the redacted command fingerprint).
    pub kind: JobKind,
    /// How the job actually resolved.
    pub disposition: LiveDisposition,
    /// Whether the job spent time in the queue before resolving (drives an
    /// intermediate `queued` event carrying attach/cancel guidance).
    pub queued: bool,
    /// Measured queue wait, milliseconds.
    pub queue_wait_ms: u64,
    /// Measured remote/local runtime, milliseconds.
    pub runtime_ms: u64,
    /// Queue depth observed when the job resolved, if known.
    pub queue_depth: Option<u32>,
}

impl LiveJobOutcome {
    /// A remote-success outcome: admitted to `worker` with `remote_id`, ran for
    /// `runtime_ms`.
    #[must_use]
    pub fn remote(
        local_job_id: impl Into<String>,
        worker: impl Into<String>,
        remote_id: RemoteBuildId,
        slots: u32,
        runtime_ms: u64,
    ) -> Self {
        Self {
            local_job_id: local_job_id.into(),
            remote_job_id: Some(remote_id),
            selected_worker: Some(worker.into()),
            slots,
            kind: JobKind::Check,
            disposition: LiveDisposition::Remote,
            queued: false,
            queue_wait_ms: 0,
            runtime_ms,
            queue_depth: None,
        }
    }

    /// A local-fallback outcome: no remote capacity, ran locally for `runtime_ms`.
    #[must_use]
    pub fn local_fallback(local_job_id: impl Into<String>, slots: u32, runtime_ms: u64) -> Self {
        Self {
            local_job_id: local_job_id.into(),
            remote_job_id: None,
            selected_worker: None,
            slots,
            kind: JobKind::Check,
            disposition: LiveDisposition::LocalFallback,
            queued: false,
            queue_wait_ms: 0,
            runtime_ms,
            queue_depth: None,
        }
    }

    /// Override the command kind.
    #[must_use]
    pub fn with_kind(mut self, kind: JobKind) -> Self {
        self.kind = kind;
        self
    }

    /// Mark the job as having queued, with the measured wait and depth.
    #[must_use]
    pub fn queued_for(mut self, wait_ms: u64, depth: Option<u32>) -> Self {
        self.queued = true;
        self.queue_wait_ms = wait_ms;
        self.queue_depth = depth;
        self
    }

    /// Override the disposition (for fallback/refusal/cancel outcomes).
    #[must_use]
    pub fn with_disposition(mut self, disposition: LiveDisposition) -> Self {
        self.disposition = disposition;
        self
    }
}

/// Build a [`StormRun`] (JSONL event stream + [`StormSummary`]) from a set of
/// observed REAL canary outcomes, using the exact event vocabulary and summary
/// accounting as the simulator. The resulting run can be fed straight into
/// [`check_all_invariants`].
///
/// `workers` is the live fleet description (ids, slots, eligibility) so the
/// fairness and ineligible-selection invariants — and per-worker slot
/// utilization — can be computed against the real fleet shape.
#[must_use]
pub fn build_live_storm_run(
    cfg: &StormConfig,
    workers: &[StormWorker],
    outcomes: &[LiveJobOutcome],
) -> StormRun {
    let mut events = Vec::new();
    for o in outcomes {
        // A job that waited emits an intermediate `queued` event carrying the
        // real attach/cancel guidance, so the no-stuck-wrapper invariant has a
        // definite, reattachable record even before the terminal event.
        if o.queued {
            events.push(make_load_event(
                &cfg.run_id,
                &cfg.bead_id,
                o.kind,
                &o.local_job_id,
                event::QUEUED,
                "queued",
                decision::QUEUED,
                None,
                None,
                o.queue_depth,
                0,
                Some(queued_guidance(&o.local_job_id)),
                None,
            ));
        }
        match o.disposition {
            LiveDisposition::Remote => {
                events.push(make_load_event(
                    &cfg.run_id,
                    &cfg.bead_id,
                    o.kind,
                    &o.local_job_id,
                    event::STARTED,
                    "run",
                    decision::REMOTE,
                    o.selected_worker.clone(),
                    o.selected_worker.clone(),
                    o.queue_depth,
                    0,
                    Some("admitted and running".to_string()),
                    o.remote_job_id,
                ));
                events.push(make_load_event(
                    &cfg.run_id,
                    &cfg.bead_id,
                    o.kind,
                    &o.local_job_id,
                    event::PASSED,
                    "ok",
                    decision::REMOTE,
                    o.selected_worker.clone(),
                    o.selected_worker.clone(),
                    None,
                    o.runtime_ms,
                    Some("completed remotely".to_string()),
                    o.remote_job_id,
                ));
            }
            LiveDisposition::LocalFallback => {
                events.push(make_load_event(
                    &cfg.run_id,
                    &cfg.bead_id,
                    o.kind,
                    &o.local_job_id,
                    event::FELL_BACK,
                    "local",
                    decision::LOCAL_FALLBACK,
                    None,
                    None,
                    None,
                    o.runtime_ms,
                    Some(local_fallback_guidance()),
                    None,
                ));
            }
            LiveDisposition::QueueTimeoutFallback => {
                events.push(make_load_event(
                    &cfg.run_id,
                    &cfg.bead_id,
                    o.kind,
                    &o.local_job_id,
                    event::FELL_BACK,
                    "local",
                    decision::QUEUE_TIMEOUT_FALLBACK,
                    None,
                    None,
                    None,
                    o.runtime_ms,
                    Some(queue_timeout_guidance(
                        &o.local_job_id,
                        cfg.queue_timeout_ms,
                    )),
                    None,
                ));
            }
            LiveDisposition::ProofRefused => {
                let mut ev = make_load_event(
                    &cfg.run_id,
                    &cfg.bead_id,
                    o.kind,
                    &o.local_job_id,
                    event::REFUSED,
                    "refused",
                    decision::PROOF_REFUSED,
                    None,
                    None,
                    None,
                    0,
                    Some(
                        "proof mode requires immediate remote admission; refused local fallback"
                            .to_string(),
                    ),
                    None,
                );
                ev.reason_code = Some(PROOF_REFUSAL_REASON.to_string());
                events.push(ev);
            }
            LiveDisposition::Cancelled => {
                events.push(make_load_event(
                    &cfg.run_id,
                    &cfg.bead_id,
                    o.kind,
                    &o.local_job_id,
                    event::CANCELLED,
                    "cancelled",
                    decision::CANCELLED,
                    None,
                    None,
                    None,
                    0,
                    Some(cancel_guidance(&o.local_job_id)),
                    None,
                ));
            }
        }
    }
    let summary = summarize_live(workers, outcomes);
    StormRun { events, summary }
}

/// Compute the [`StormSummary`] for a live run, mirroring the simulator's
/// `Sim::finish` accounting.
fn summarize_live(workers: &[StormWorker], outcomes: &[LiveJobOutcome]) -> StormSummary {
    let mut remote_successes = 0u32;
    let mut local_fallbacks = 0u32;
    let mut proof_refusals = 0u32;
    let mut queue_timeouts = 0u32;
    let mut cancellations = 0u32;
    let mut queue_waits = Vec::with_capacity(outcomes.len());
    let mut end_to_ends = Vec::with_capacity(outcomes.len());
    let mut busy_slot_ms: BTreeMap<&str, u128> = BTreeMap::new();
    let mut makespan = 0u64;

    for o in outcomes {
        queue_waits.push(o.queue_wait_ms);
        let end_to_end = o.queue_wait_ms.saturating_add(o.runtime_ms);
        match o.disposition {
            LiveDisposition::Remote => {
                remote_successes += 1;
                end_to_ends.push(end_to_end);
                makespan = makespan.max(end_to_end);
                if let Some(w) = o.selected_worker.as_deref() {
                    *busy_slot_ms.entry(w).or_default() +=
                        u128::from(o.slots) * u128::from(o.runtime_ms);
                }
            }
            LiveDisposition::LocalFallback => {
                local_fallbacks += 1;
                end_to_ends.push(end_to_end);
                makespan = makespan.max(end_to_end);
            }
            LiveDisposition::QueueTimeoutFallback => {
                local_fallbacks += 1;
                queue_timeouts += 1;
                end_to_ends.push(end_to_end);
                makespan = makespan.max(end_to_end);
            }
            LiveDisposition::ProofRefused => {
                proof_refusals += 1;
                end_to_ends.push(o.queue_wait_ms);
            }
            LiveDisposition::Cancelled => {
                cancellations += 1;
                end_to_ends.push(o.queue_wait_ms);
            }
        }
    }

    let makespan = makespan.max(1);
    let mut per_worker_slot_utilization = BTreeMap::new();
    for w in workers {
        let capacity = u128::from(w.total_slots) * u128::from(makespan);
        let busy = busy_slot_ms.get(w.id.as_str()).copied().unwrap_or(0);
        #[allow(clippy::cast_precision_loss)]
        let util = if capacity == 0 {
            0.0
        } else {
            busy as f64 / capacity as f64
        };
        per_worker_slot_utilization.insert(w.id.clone(), util);
    }

    StormSummary {
        total_jobs: u32::try_from(outcomes.len()).unwrap_or(u32::MAX),
        remote_successes,
        local_fallbacks,
        proof_refusals,
        queue_timeouts,
        cancellations,
        p95_queue_wait_ms: percentile(&mut queue_waits, 95),
        p95_end_to_end_ms: percentile(&mut end_to_ends, 95),
        per_worker_slot_utilization,
    }
}

// ===========================================================================
// Invariant checkers
// ===========================================================================

/// The verdict of a single storm-control invariant check.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InvariantReport {
    /// Stable invariant name/token.
    pub name: String,
    /// Whether the invariant held.
    pub passed: bool,
    /// Human/agent-facing summary.
    pub detail: String,
    /// Specific violations (empty when `passed`).
    pub violations: Vec<String>,
}

impl InvariantReport {
    fn pass(name: &str, detail: impl Into<String>) -> Self {
        Self {
            name: name.to_string(),
            passed: true,
            detail: detail.into(),
            violations: Vec::new(),
        }
    }
    fn fail(name: &str, detail: impl Into<String>, violations: Vec<String>) -> Self {
        Self {
            name: name.to_string(),
            passed: false,
            detail: detail.into(),
            violations,
        }
    }
}

/// Invariant: no eligible worker should sit idle while another is overloaded —
/// the busiest worker's share of remote placements must not exceed `tolerance`×
/// its fair share (1/n of schedulable workers). Single-worker fleets trivially
/// pass.
#[must_use]
pub fn check_load_fairness(
    events: &[SmokeProfileEvent],
    workers: &[StormWorker],
    tolerance: f64,
) -> InvariantReport {
    const NAME: &str = "load_fairness";
    let schedulable: Vec<&StormWorker> = workers
        .iter()
        .filter(|w| w.eligibility.is_schedulable())
        .collect();
    if schedulable.len() <= 1 {
        return InvariantReport::pass(NAME, "single schedulable worker; fairness trivial");
    }
    let mut counts: BTreeMap<&str, u32> = BTreeMap::new();
    for w in &schedulable {
        counts.insert(w.id.as_str(), 0);
    }
    let mut total = 0u32;
    for ev in events {
        if ev.event == event::STARTED
            && let Some(sel) = ev.selected_worker.as_deref()
            && let Some(c) = counts.get_mut(sel)
        {
            *c += 1;
            total += 1;
        }
    }
    if total == 0 {
        return InvariantReport::pass(NAME, "no remote placements to spread");
    }
    let fair_share = f64::from(total) / schedulable.len() as f64;
    let cap = fair_share * tolerance;
    let mut violations = Vec::new();
    for (id, c) in &counts {
        if f64::from(*c) > cap {
            violations.push(format!(
                "worker {id} took {c} of {total} placements (cap {cap:.1}, fair share {fair_share:.1})"
            ));
        }
    }
    if violations.is_empty() {
        InvariantReport::pass(
            NAME,
            format!("{total} placements spread within {tolerance:.2}× fair share"),
        )
    } else {
        InvariantReport::fail(NAME, "load not spread fairly", violations)
    }
}

/// Invariant: every admitted job gets a UNIQUE remote build id (no two jobs share
/// a remote job id across the run).
#[must_use]
pub fn check_no_duplicate_remote_job_ids(events: &[SmokeProfileEvent]) -> InvariantReport {
    const NAME: &str = "no_duplicate_remote_job_ids";
    // Map remote_job_id -> set of distinct local_job_ids that claimed it.
    let mut owners: BTreeMap<u64, std::collections::BTreeSet<String>> = BTreeMap::new();
    for ev in events {
        if let Some(rid) = ev.remote_job_id {
            let local = ev.local_job_id.clone().unwrap_or_default();
            owners.entry(rid).or_default().insert(local);
        }
    }
    let mut violations = Vec::new();
    for (rid, locals) in &owners {
        if locals.len() > 1 {
            violations.push(format!(
                "remote job id {rid} shared by local jobs {locals:?}"
            ));
        }
    }
    if violations.is_empty() {
        InvariantReport::pass(
            NAME,
            format!("{} distinct remote job ids, none shared", owners.len()),
        )
    } else {
        InvariantReport::fail(NAME, "remote job id collision", violations)
    }
}

/// Invariant: the fleet must not degenerate into an unbounded local-fallback
/// storm. The fraction of jobs that fell back to local must not exceed
/// `max_fallback_ratio`. Proof refusals and cancellations are not fallbacks.
#[must_use]
pub fn check_no_unbounded_local_fallback_storm(
    events: &[SmokeProfileEvent],
    summary: &StormSummary,
    max_fallback_ratio: f64,
) -> InvariantReport {
    const NAME: &str = "no_unbounded_local_fallback_storm";
    let _ = events;
    if summary.total_jobs == 0 {
        return InvariantReport::pass(NAME, "no jobs");
    }
    let ratio = f64::from(summary.local_fallbacks) / f64::from(summary.total_jobs);
    if ratio <= max_fallback_ratio {
        InvariantReport::pass(
            NAME,
            format!(
                "{}/{} jobs fell back to local ({:.1}% <= {:.1}% cap)",
                summary.local_fallbacks,
                summary.total_jobs,
                ratio * 100.0,
                max_fallback_ratio * 100.0
            ),
        )
    } else {
        InvariantReport::fail(
            NAME,
            "local fallback storm: too many jobs bypassed the fleet",
            vec![format!(
                "{}/{} fell back ({:.1}% > {:.1}% cap)",
                summary.local_fallbacks,
                summary.total_jobs,
                ratio * 100.0,
                max_fallback_ratio * 100.0
            )],
        )
    }
}

/// Invariant: no agent is left with a "maybe running somewhere" wrapper. Every
/// job that did not start remotely (fell back, timed out, was cancelled, or
/// queued-not-started) must carry non-empty attach/cancel guidance in `detail`,
/// and every job must reach a definite terminal event.
#[must_use]
pub fn check_attach_cancel_guidance(events: &[SmokeProfileEvent]) -> InvariantReport {
    const NAME: &str = "attach_cancel_guidance";
    use std::collections::BTreeSet;
    let terminal = [
        event::PASSED,
        event::FELL_BACK,
        event::REFUSED,
        event::CANCELLED,
    ];
    let not_started_terminal = [event::FELL_BACK, event::CANCELLED];
    let mut all_jobs: BTreeSet<String> = BTreeSet::new();
    let mut terminated: BTreeSet<String> = BTreeSet::new();
    let mut violations = Vec::new();
    for ev in events {
        let Some(local) = ev.local_job_id.clone() else {
            continue;
        };
        all_jobs.insert(local.clone());
        if terminal.contains(&ev.event.as_str()) {
            terminated.insert(local.clone());
        }
        // Any not-started terminal (and the intermediate queued event) must
        // carry guidance.
        if not_started_terminal.contains(&ev.event.as_str()) || ev.event == event::QUEUED {
            let has_guidance = ev.detail.as_deref().is_some_and(|d| !d.trim().is_empty());
            if !has_guidance {
                violations.push(format!(
                    "job {local} event '{}' lacks attach/cancel guidance",
                    ev.event
                ));
            }
        }
    }
    for job in all_jobs.difference(&terminated) {
        violations.push(format!(
            "job {job} never reached a terminal event (stuck wrapper)"
        ));
    }
    if violations.is_empty() {
        InvariantReport::pass(
            NAME,
            format!("{} jobs all terminated with guidance", terminated.len()),
        )
    } else {
        InvariantReport::fail(NAME, "stuck wrapper or missing guidance", violations)
    }
}

/// Invariant: a worker that is temporarily bypassed, admin-disabled, or
/// capability-inadmissible must NEVER be selected for work.
#[must_use]
pub fn check_no_ineligible_worker_selected(
    events: &[SmokeProfileEvent],
    workers: &[StormWorker],
) -> InvariantReport {
    const NAME: &str = "no_ineligible_worker_selected";
    let ineligible: BTreeMap<&str, WorkerEligibility> = workers
        .iter()
        .filter(|w| !w.eligibility.is_schedulable())
        .map(|w| (w.id.as_str(), w.eligibility))
        .collect();
    let mut violations = Vec::new();
    for ev in events {
        // A worker is "given work" if it is selected or the job started on it.
        for candidate in [ev.selected_worker.as_deref(), ev.worker_id.as_deref()]
            .into_iter()
            .flatten()
        {
            if let Some(elig) = ineligible.get(candidate)
                && (ev.event == event::STARTED || ev.event == event::PASSED)
            {
                violations.push(format!(
                    "ineligible worker {candidate} ({}) received work on event '{}' (job {:?})",
                    elig.as_str(),
                    ev.event,
                    ev.local_job_id
                ));
            }
        }
    }
    if violations.is_empty() {
        InvariantReport::pass(
            NAME,
            format!("{} ineligible worker(s) received no work", ineligible.len()),
        )
    } else {
        InvariantReport::fail(NAME, "ineligible worker received work", violations)
    }
}

/// Run all five storm-control invariants with the given tolerances.
#[must_use]
pub fn check_all_invariants(
    run: &StormRun,
    workers: &[StormWorker],
    fairness_tolerance: f64,
    max_fallback_ratio: f64,
) -> Vec<InvariantReport> {
    vec![
        check_load_fairness(&run.events, workers, fairness_tolerance),
        check_no_duplicate_remote_job_ids(&run.events),
        check_no_unbounded_local_fallback_storm(&run.events, &run.summary, max_fallback_ratio),
        check_attach_cancel_guidance(&run.events),
        check_no_ineligible_worker_selected(&run.events, workers),
    ]
}

/// Whether every invariant in a report set held.
#[must_use]
pub fn all_passed(reports: &[InvariantReport]) -> bool {
    reports.iter().all(|r| r.passed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> StormConfig {
        StormConfig::new("storm-run-1", "bd-session-history-remediation-ocv9i.10.4")
    }

    fn healthy_fleet() -> Vec<StormWorker> {
        vec![
            StormWorker::healthy("w1", 4, 100.0),
            StormWorker::healthy("w2", 4, 100.0),
            StormWorker::healthy("w3", 4, 100.0),
        ]
    }

    fn build_jobs(n: usize, runtime: u64, slots: u32) -> Vec<StormJob> {
        (0..n)
            .map(|i| StormJob::build(runtime, slots, format!("/data/projects/p{}", i % 4)))
            .collect()
    }

    #[test]
    fn percentile_nearest_rank() {
        let mut v = vec![10, 20, 30, 40, 50, 60, 70, 80, 90, 100];
        assert_eq!(percentile(&mut v, 95), 100);
        let mut v2 = vec![5];
        assert_eq!(percentile(&mut v2, 95), 5);
        let mut empty: Vec<u64> = vec![];
        assert_eq!(percentile(&mut empty, 95), 0);
        let mut v3 = vec![1, 2, 3, 4];
        assert_eq!(percentile(&mut v3, 50), 2); // ceil(0.5*4)=2 -> idx 1
    }

    #[test]
    fn healthy_storm_upholds_all_invariants() {
        let workers = healthy_fleet();
        // 24 jobs, fleet capacity 12 slots: guaranteed contention + queueing.
        let jobs = build_jobs(24, 1000, 1);
        let run = simulate_storm(&workers, &jobs, &cfg());
        let reports = check_all_invariants(&run, &workers, 1.5, 0.25);
        for r in &reports {
            assert!(r.passed, "invariant {} failed: {:?}", r.name, r.violations);
        }
        assert_eq!(run.summary.total_jobs, 24);
        // Every job completed remotely (capacity recycles via the queue).
        assert_eq!(run.summary.remote_successes, 24);
        assert_eq!(run.summary.local_fallbacks, 0);
    }

    #[test]
    fn fairness_spreads_load_across_homogeneous_fleet() {
        let workers = healthy_fleet();
        let jobs = build_jobs(30, 500, 1);
        let run = simulate_storm(&workers, &jobs, &cfg());
        let report = check_load_fairness(&run.events, &workers, 1.4);
        assert!(report.passed, "fairness: {:?}", report.violations);
        // Each worker should get a meaningful share (none starved).
        for w in &workers {
            let util = run.summary.per_worker_slot_utilization[&w.id];
            assert!(util > 0.0, "worker {} starved (util 0)", w.id);
        }
    }

    #[test]
    fn unique_remote_job_ids_under_storm() {
        let workers = healthy_fleet();
        let jobs = build_jobs(50, 300, 1);
        let run = simulate_storm(&workers, &jobs, &cfg());
        let report = check_no_duplicate_remote_job_ids(&run.events);
        assert!(report.passed, "{:?}", report.violations);
    }

    #[test]
    fn queue_full_falls_back_locally_but_not_unboundedly() {
        let workers = vec![StormWorker::healthy("only", 1, 100.0)];
        // Tiny queue: most jobs must fall back, but fail-open keeps the wrapper
        // definite. The storm-control bound is the *cap*, which we set high here
        // to assert the fallbacks happen and are accounted, then assert the bound
        // catches an over-fallback configuration below.
        let mut c = cfg();
        c.max_queue_depth = 2;
        c.queue_timeout_ms = 10; // short so queued jobs time out fast
        let jobs = build_jobs(20, 1000, 1);
        let run = simulate_storm(&workers, &jobs, &c);
        assert_eq!(run.summary.total_jobs, 20);
        // Some ran remotely, the rest fell back; nothing is stuck.
        let guidance = check_attach_cancel_guidance(&run.events);
        assert!(guidance.passed, "{:?}", guidance.violations);
        let total_resolved = run.summary.remote_successes
            + run.summary.local_fallbacks
            + run.summary.proof_refusals
            + run.summary.cancellations;
        assert_eq!(total_resolved, 20, "every job must resolve");
        // With a deliberately low cap the storm check must FAIL (detects the
        // over-fallback condition) — proving the checker is not vacuous.
        let strict = check_no_unbounded_local_fallback_storm(&run.events, &run.summary, 0.10);
        assert!(!strict.passed, "low cap should flag the fallback storm");
    }

    #[test]
    fn proof_jobs_refuse_rather_than_fall_back() {
        // Single slot, many proof jobs: all but the first few must refuse, never
        // fall back to local.
        let workers = vec![StormWorker::healthy("only", 1, 100.0)];
        let jobs: Vec<StormJob> = (0..10)
            .map(|i| StormJob::build(1000, 1, format!("/p{i}")).with_policy(JobPolicy::Proof))
            .collect();
        let run = simulate_storm(&workers, &jobs, &cfg());
        assert_eq!(run.summary.local_fallbacks, 0, "proof must never fall back");
        assert!(run.summary.proof_refusals >= 9, "most proof jobs refuse");
        // Refusals carry the proof reason code.
        let refused: Vec<_> = run
            .events
            .iter()
            .filter(|e| e.event == event::REFUSED)
            .collect();
        assert!(!refused.is_empty());
        assert!(
            refused
                .iter()
                .all(|e| e.reason_code.as_deref() == Some(PROOF_REFUSAL_REASON))
        );
        assert!(check_no_unbounded_local_fallback_storm(&run.events, &run.summary, 0.0).passed);
    }

    #[test]
    fn ineligible_workers_never_receive_work() {
        let workers = vec![
            StormWorker::healthy("good", 2, 100.0),
            StormWorker::healthy("bypassed", 8, 200.0)
                .with_eligibility(WorkerEligibility::TemporaryBypass),
            StormWorker::healthy("disabled", 8, 200.0)
                .with_eligibility(WorkerEligibility::AdminDisabled),
            StormWorker::healthy("incapable", 8, 200.0)
                .with_eligibility(WorkerEligibility::CapabilityInadmissible),
        ];
        let jobs = build_jobs(20, 500, 1);
        let run = simulate_storm(&workers, &jobs, &cfg());
        let report = check_no_ineligible_worker_selected(&run.events, &workers);
        assert!(report.passed, "{:?}", report.violations);
        // Confirm only "good" ever appears as a selected worker.
        for ev in &run.events {
            if let Some(sel) = &ev.selected_worker {
                assert_eq!(sel, "good", "only the eligible worker may be selected");
            }
        }
        // All work landed on the one eligible worker.
        assert_eq!(run.summary.per_worker_slot_utilization["bypassed"], 0.0);
        assert_eq!(run.summary.per_worker_slot_utilization["disabled"], 0.0);
        assert_eq!(run.summary.per_worker_slot_utilization["incapable"], 0.0);
    }

    #[test]
    fn cancellation_before_start_is_clean() {
        let workers = vec![StormWorker::healthy("only", 1, 100.0)];
        let mut jobs = build_jobs(6, 1000, 1);
        // Mark the later (necessarily-queued) jobs to cancel.
        for j in jobs.iter_mut().skip(2) {
            j.cancel_when_queued = true;
        }
        let mut c = cfg();
        c.cancel_delay_ms = 5;
        c.queue_timeout_ms = 100_000;
        let run = simulate_storm(&workers, &jobs, &c);
        assert!(run.summary.cancellations >= 1, "some jobs cancel");
        let guidance = check_attach_cancel_guidance(&run.events);
        assert!(guidance.passed, "{:?}", guidance.violations);
        // Cancelled events carry guidance.
        let cancelled: Vec<_> = run
            .events
            .iter()
            .filter(|e| e.event == event::CANCELLED)
            .collect();
        assert!(!cancelled.is_empty());
        assert!(
            cancelled
                .iter()
                .all(|e| e.detail.as_deref().is_some_and(|d| !d.is_empty()))
        );
    }

    #[test]
    fn jsonl_carries_every_required_field() {
        let workers = healthy_fleet();
        let jobs = build_jobs(12, 500, 1);
        let run = simulate_storm(&workers, &jobs, &cfg());
        let jsonl = run.to_jsonl().expect("serialize");
        assert!(!jsonl.is_empty());
        // The started events must expose the load fields.
        let started: Vec<&SmokeProfileEvent> = run
            .events
            .iter()
            .filter(|e| e.event == event::STARTED)
            .collect();
        assert!(!started.is_empty());
        for ev in &started {
            assert!(ev.local_job_id.is_some(), "local_job_id present");
            assert!(ev.remote_job_id.is_some(), "remote_job_id present");
            assert!(ev.selected_worker.is_some(), "selected_worker present");
            assert!(ev.queue_depth.is_some(), "queue_depth present");
            assert!(ev.fallback_decision.is_some(), "fallback_decision present");
            assert_eq!(ev.bead_id, "bd-session-history-remediation-ocv9i.10.4");
        }
        // Each JSONL line is a valid object with run_id + scenario.
        for line in jsonl.lines() {
            let v: serde_json::Value = serde_json::from_str(line).expect("valid json line");
            assert_eq!(v["run_id"], "storm-run-1");
            assert_eq!(v["scenario"], "load_storm_control");
        }
    }

    #[test]
    fn detector_catches_duplicate_remote_ids() {
        // Hand-craft an event stream with a duplicated remote id.
        let mk = |local: &str, rid: u64| {
            SmokeProfileEvent::started("r", "b", Some("w".into()), SmokeScenario::LoadStormControl)
                .with_job_ids(Some(local.into()), Some(rid))
        };
        let events = vec![mk("rchw-0", 7), mk("rchw-1", 7)];
        let report = check_no_duplicate_remote_job_ids(&events);
        assert!(!report.passed);
        assert_eq!(report.violations.len(), 1);
    }

    #[test]
    fn detector_catches_ineligible_selection() {
        let workers = vec![
            StormWorker::healthy("good", 2, 100.0),
            StormWorker::healthy("disabled", 2, 100.0)
                .with_eligibility(WorkerEligibility::AdminDisabled),
        ];
        // A forged event that selected the disabled worker.
        let mut bad = SmokeProfileEvent::started(
            "r",
            "b",
            Some("disabled".into()),
            SmokeScenario::LoadStormControl,
        );
        bad.event = event::STARTED.to_string();
        let bad = bad.with_selected_worker(Some("disabled".into()));
        let report = check_no_ineligible_worker_selected(&[bad], &workers);
        assert!(!report.passed);
    }

    #[test]
    fn detector_catches_stuck_wrapper() {
        // A started event with no terminal event => stuck wrapper.
        let ev =
            SmokeProfileEvent::started("r", "b", Some("w".into()), SmokeScenario::LoadStormControl)
                .with_job_ids(Some("rchw-stuck".into()), Some(1));
        let report = check_attach_cancel_guidance(&[ev]);
        assert!(!report.passed);
        assert!(
            report
                .violations
                .iter()
                .any(|v| v.contains("stuck wrapper"))
        );
    }

    #[test]
    fn deterministic_runs_are_identical() {
        let workers = healthy_fleet();
        let jobs = build_jobs(40, 700, 1);
        let a = simulate_storm(&workers, &jobs, &cfg());
        let b = simulate_storm(&workers, &jobs, &cfg());
        assert_eq!(a.to_jsonl().unwrap(), b.to_jsonl().unwrap());
        assert_eq!(a.summary, b.summary);
    }

    #[test]
    fn summary_serde_roundtrip() {
        let workers = healthy_fleet();
        let jobs = build_jobs(10, 500, 1);
        let run = simulate_storm(&workers, &jobs, &cfg());
        let json = serde_json::to_string(&run.summary).unwrap();
        let back: StormSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(run.summary, back);
    }

    #[test]
    fn varied_jobs_mixed_policies_kinds_slots() {
        // Heterogeneous storm: varied runtimes, slot requests, project roots,
        // kinds, and proof/fail-open policies (the bead's varied-job criterion).
        let workers = healthy_fleet();
        let mut jobs = Vec::new();
        for i in 0..18 {
            let kind = match i % 3 {
                0 => JobKind::Build,
                1 => JobKind::Test,
                _ => JobKind::Check,
            };
            let policy = if i % 5 == 0 {
                JobPolicy::ForceRemote
            } else {
                JobPolicy::FailOpen
            };
            jobs.push(
                StormJob::build(
                    300 + (i as u64 % 4) * 250,
                    1 + (i as u32 % 3),
                    format!("/r{}", i % 4),
                )
                .with_kind(kind)
                .with_policy(policy),
            );
        }
        let run = simulate_storm(&workers, &jobs, &cfg());
        let reports = check_all_invariants(&run, &workers, 1.6, 0.30);
        for r in &reports {
            assert!(r.passed, "invariant {} failed: {:?}", r.name, r.violations);
        }
    }

    // -----------------------------------------------------------------------
    // Live recorder (real-canary outcomes -> StormRun) tests
    // -----------------------------------------------------------------------

    /// A healthy live run: 30 remote successes spread evenly over a 3-worker
    /// fleet, each with a unique remote id, upholds all five invariants — the
    /// SAME checkers that gate the simulated storm.
    #[test]
    fn live_healthy_run_upholds_all_invariants() {
        let workers = healthy_fleet();
        let outcomes: Vec<LiveJobOutcome> = (0..30)
            .map(|i| {
                let w = &workers[i % workers.len()].id;
                LiveJobOutcome::remote(format!("rchw-{i:04}"), w.clone(), (i + 1) as u64, 1, 500)
            })
            .collect();
        let run = build_live_storm_run(&cfg(), &workers, &outcomes);
        let reports = check_all_invariants(&run, &workers, 1.5, 0.25);
        for r in &reports {
            assert!(r.passed, "invariant {} failed: {:?}", r.name, r.violations);
        }
        assert_eq!(run.summary.total_jobs, 30);
        assert_eq!(run.summary.remote_successes, 30);
        assert_eq!(run.summary.local_fallbacks, 0);
        // Every schedulable worker carried real work.
        for w in &workers {
            assert!(
                run.summary.per_worker_slot_utilization[&w.id] > 0.0,
                "worker {} starved",
                w.id
            );
        }
    }

    /// A live run with a bounded mix of remote successes and fail-open local
    /// fallbacks (under the cap) still passes — including the fallback-storm
    /// invariant — and every fallback carries attach/cancel guidance.
    #[test]
    fn live_mixed_run_with_bounded_fallback_passes() {
        let workers = healthy_fleet();
        let mut outcomes = Vec::new();
        for i in 0..24 {
            let w = &workers[i % workers.len()].id;
            outcomes.push(LiveJobOutcome::remote(
                format!("rchw-{i:04}"),
                w.clone(),
                (i + 1) as u64,
                1,
                400,
            ));
        }
        // 4 of 28 (~14%) fell back to local — within a 25% cap.
        for i in 24..28 {
            outcomes.push(LiveJobOutcome::local_fallback(
                format!("rchw-{i:04}"),
                1,
                400,
            ));
        }
        let run = build_live_storm_run(&cfg(), &workers, &outcomes);
        let reports = check_all_invariants(&run, &workers, 1.5, 0.25);
        for r in &reports {
            assert!(r.passed, "invariant {} failed: {:?}", r.name, r.violations);
        }
        assert_eq!(run.summary.remote_successes, 24);
        assert_eq!(run.summary.local_fallbacks, 4);
        // A deliberately strict cap flags the same run (checker is not vacuous).
        let strict = check_no_unbounded_local_fallback_storm(&run.events, &run.summary, 0.10);
        assert!(!strict.passed, "10% cap must flag a 14% fallback rate");
    }

    /// The summary faithfully accounts every disposition kind a live run can
    /// observe, matching the simulator's `finish()` accounting.
    #[test]
    fn live_summary_accounts_every_disposition() {
        let workers = healthy_fleet();
        let outcomes = vec![
            LiveJobOutcome::remote("rchw-0000", "w1", 1, 1, 300),
            LiveJobOutcome::remote("rchw-0001", "w2", 2, 1, 300),
            LiveJobOutcome::local_fallback("rchw-0002", 1, 300),
            LiveJobOutcome::local_fallback("rchw-0003", 1, 300)
                .queued_for(40, Some(2))
                .with_disposition(LiveDisposition::QueueTimeoutFallback),
            LiveJobOutcome::local_fallback("rchw-0004", 1, 0)
                .with_disposition(LiveDisposition::ProofRefused),
            LiveJobOutcome::local_fallback("rchw-0005", 1, 0)
                .queued_for(10, Some(1))
                .with_disposition(LiveDisposition::Cancelled),
        ];
        let run = build_live_storm_run(&cfg(), &workers, &outcomes);
        assert_eq!(run.summary.total_jobs, 6);
        assert_eq!(run.summary.remote_successes, 2);
        // LocalFallback + QueueTimeoutFallback both count as local fallbacks.
        assert_eq!(run.summary.local_fallbacks, 2);
        assert_eq!(run.summary.queue_timeouts, 1);
        assert_eq!(run.summary.proof_refusals, 1);
        assert_eq!(run.summary.cancellations, 1);
        // Guidance + terminal invariants still hold for the mixed bag.
        assert!(check_attach_cancel_guidance(&run.events).passed);
    }

    /// The live JSONL carries every load field on the started events and each
    /// line is a valid `load_storm_control` record.
    #[test]
    fn live_jsonl_carries_load_fields() {
        let workers = healthy_fleet();
        let outcomes: Vec<LiveJobOutcome> = (0..6)
            .map(|i| {
                LiveJobOutcome::remote(
                    format!("rchw-{i:04}"),
                    workers[i % workers.len()].id.clone(),
                    (i + 1) as u64,
                    1,
                    250,
                )
                .queued_for(5, Some(1))
            })
            .collect();
        let run = build_live_storm_run(&cfg(), &workers, &outcomes);
        let jsonl = run.to_jsonl().expect("serialize");
        assert!(!jsonl.is_empty());
        let started: Vec<&SmokeProfileEvent> = run
            .events
            .iter()
            .filter(|e| e.event == event::STARTED)
            .collect();
        assert_eq!(started.len(), 6);
        for ev in &started {
            assert!(ev.local_job_id.is_some());
            assert!(ev.remote_job_id.is_some());
            assert!(ev.selected_worker.is_some());
            assert!(ev.queue_depth.is_some());
            assert_eq!(ev.fallback_decision.as_deref(), Some(decision::REMOTE));
        }
        for line in jsonl.lines() {
            let v: serde_json::Value = serde_json::from_str(line).expect("valid json line");
            assert_eq!(v["scenario"], "load_storm_control");
        }
    }

    /// A live run that (incorrectly) reports work on an ineligible worker is
    /// caught — the live path is held to the same eligibility invariant.
    #[test]
    fn live_detector_catches_ineligible_selection() {
        let workers = vec![
            StormWorker::healthy("good", 4, 100.0),
            StormWorker::healthy("disabled", 4, 100.0)
                .with_eligibility(WorkerEligibility::AdminDisabled),
        ];
        // A forged outcome that landed on the admin-disabled worker.
        let outcomes = vec![
            LiveJobOutcome::remote("rchw-0000", "good", 1, 1, 300),
            LiveJobOutcome::remote("rchw-0001", "disabled", 2, 1, 300),
        ];
        let run = build_live_storm_run(&cfg(), &workers, &outcomes);
        let report = check_no_ineligible_worker_selected(&run.events, &workers);
        assert!(!report.passed);
        assert!(report.violations.iter().any(|v| v.contains("disabled")));
    }

    /// Two live outcomes that claim the same remote build id are caught.
    #[test]
    fn live_detector_catches_duplicate_remote_ids() {
        let workers = healthy_fleet();
        let outcomes = vec![
            LiveJobOutcome::remote("rchw-0000", "w1", 7, 1, 300),
            LiveJobOutcome::remote("rchw-0001", "w2", 7, 1, 300),
        ];
        let run = build_live_storm_run(&cfg(), &workers, &outcomes);
        let report = check_no_duplicate_remote_job_ids(&run.events);
        assert!(!report.passed);
    }

    /// A live proof-refusal outcome carries the proof reason code and refuses
    /// rather than counting as a fallback.
    #[test]
    fn live_proof_refusal_carries_reason_code() {
        let workers = healthy_fleet();
        let outcomes = vec![
            LiveJobOutcome::local_fallback("rchw-0000", 1, 0)
                .with_disposition(LiveDisposition::ProofRefused),
        ];
        let run = build_live_storm_run(&cfg(), &workers, &outcomes);
        assert_eq!(run.summary.proof_refusals, 1);
        assert_eq!(run.summary.local_fallbacks, 0);
        let refused: Vec<&SmokeProfileEvent> = run
            .events
            .iter()
            .filter(|e| e.event == event::REFUSED)
            .collect();
        assert_eq!(refused.len(), 1);
        assert_eq!(
            refused[0].reason_code.as_deref(),
            Some(PROOF_REFUSAL_REASON)
        );
        // Fallback-storm invariant holds even at a zero cap (no fallbacks).
        assert!(check_no_unbounded_local_fallback_storm(&run.events, &run.summary, 0.0).passed);
    }

    /// The live builder and the simulator emit the SAME event shape for a single
    /// remote success (started + passed), proving the two paths are in lockstep.
    #[test]
    fn live_builder_matches_simulator_remote_event_shape() {
        let workers = vec![StormWorker::healthy("w1", 4, 100.0)];
        // Simulator: one job placed remotely.
        let jobs = vec![StormJob::build(500, 1, "/p0").with_kind(JobKind::Check)];
        let sim = simulate_storm(&workers, &jobs, &cfg());
        let sim_started = sim
            .events
            .iter()
            .find(|e| e.event == event::STARTED)
            .expect("sim started");
        // Live: the same logical outcome.
        let outcomes = vec![LiveJobOutcome::remote(
            sim.events
                .iter()
                .find_map(|e| e.local_job_id.clone())
                .unwrap(),
            "w1",
            1,
            1,
            500,
        )];
        let live = build_live_storm_run(&cfg(), &workers, &outcomes);
        let live_started = live
            .events
            .iter()
            .find(|e| e.event == event::STARTED)
            .expect("live started");
        // Same scenario token, decision, status, fingerprint, selected worker.
        assert_eq!(sim_started.scenario, live_started.scenario);
        assert_eq!(sim_started.status, live_started.status);
        assert_eq!(
            sim_started.fallback_decision,
            live_started.fallback_decision
        );
        assert_eq!(
            sim_started.command_fingerprint,
            live_started.command_fingerprint
        );
        assert_eq!(sim_started.selected_worker, live_started.selected_worker);
        assert_eq!(sim_started.detail, live_started.detail);
    }
}
